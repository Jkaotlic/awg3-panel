package bootstrap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/store"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const (
	ServerPath      = "/etc/amnezia/amneziawg/awgtop.conf"
	PanelPath       = "/etc/awg3panel/config.yaml"
	DefaultsPath    = "/var/lib/awg3panel/awgtop/defaults.json"
	EnvironmentPath = "/etc/awg3panel/bootstrap.env"
	CredentialsPath = "/root/awg3panel-access.txt"
	ManifestPath    = "/var/lib/awg3panel-bootstrap/manifest.json"
	CompletePath    = "/var/lib/awg3panel-bootstrap/prepared.complete"
)

var paths = []string{ServerPath, PanelPath, DefaultsPath, EnvironmentPath, CredentialsPath}

type Options struct {
	Root, Endpoint, Subnet, Egress, DNS string
	DryRun                              bool
	AfterWrite                          func(string) error // fault-injection boundary, never set by the CLI
}
type Result struct{ Listen, Config, Credentials string }
type entry struct {
	SHA256 string `json:"sha256"`
	Stage  string `json:"stage"`
}
type manifest struct {
	Version  int              `json:"version"`
	Preset   string           `json:"preset"`
	Endpoint string           `json:"endpoint"`
	Subnet   string           `json:"subnet"`
	Egress   string           `json:"egress"`
	DNS      string           `json:"dns"`
	Files    map[string]entry `json:"files"`
}

func target(root, path string) string {
	return filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(path, "/")))
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func normalize(o Options) (Options, netip.Prefix, error) {
	if o.Root == "" {
		o.Root = string(filepath.Separator)
	}
	r, err := filepath.Abs(o.Root)
	if err != nil {
		return o, netip.Prefix{}, errors.New("invalid installation root")
	}
	o.Root = r
	ip, err := netip.ParseAddr(o.Endpoint)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return o, netip.Prefix{}, errors.New("endpoint must be an explicit IPv4 address")
	}
	if o.Subnet == "" {
		o.Subnet = "10.66.0.1/24"
	}
	p, err := netip.ParsePrefix(o.Subnet)
	if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() < 16 || p.Bits() > 30 || p.Addr() != p.Masked().Addr().Next() {
		return o, p, errors.New("subnet must use the first host of a private IPv4 /16../30 network")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(o.Egress) {
		return o, p, errors.New("invalid egress interface")
	}
	if o.DNS != "" {
		for _, s := range strings.Split(o.DNS, ",") {
			if net.ParseIP(strings.TrimSpace(s)) == nil {
				return o, p, errors.New("DNS must contain IP addresses separated by commas")
			}
		}
	}
	return o, p, nil
}

// safePath rejects symlinks and writable ancestors before privileged writes.
// Paths are confined under an explicit root, used by the isolated test harness.
func safePath(root, path string) error {
	full := target(root, path)
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("path escaped installation root")
	}
	cur := root
	parts := append([]string{""}, strings.Split(rel, string(filepath.Separator))...)
	for _, part := range parts {
		if part != "" {
			cur = filepath.Join(cur, part)
		}
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return errors.New("cannot inspect installation path")
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink in installation path")
		}
		if err := trustedOwner(st); err != nil {
			return err
		}
		if runtime.GOOS != "windows" && st.Mode().Perm()&0022 != 0 {
			return errors.New("installation path is writable by other users")
		}
	}
	return nil
}

func ensureParent(root, path string) error {
	if err := safePath(root, path); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Dir(target(root, path)), 0700)
}

// newFile atomically publishes a complete 0600 file without replacing a path.
// Hard-link creation is exclusive; a crash before publication leaves no partial
// target and a private temporary file can never be interpreted as completed work.
func newFile(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".awg3setup-")
	if err != nil {
		return errors.New("cannot create private staging file")
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("cannot write private staging file")
	}
	if err = os.Link(name, path); err != nil {
		return errors.New("cannot exclusively create installation file")
	}
	return nil
}

func loadManifest(root string) (manifest, error) {
	var m manifest
	if err := safePath(root, ManifestPath); err != nil {
		return m, err
	}
	b, err := os.ReadFile(target(root, ManifestPath))
	if err != nil {
		return m, err
	}
	if err = json.Unmarshal(b, &m); err != nil {
		return m, errors.New("invalid installation manifest")
	}
	if m.Version != 1 || m.Preset != PresetName || len(m.Files) != len(paths) {
		return m, errors.New("unsupported installation manifest")
	}
	for _, p := range paths {
		e, ok := m.Files[p]
		if !ok || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(e.SHA256) || !regexp.MustCompile(`^\.stage-[a-zA-Z0-9]+/[0-4]$`).MatchString(e.Stage) {
			return m, errors.New("invalid installation manifest entry")
		}
	}
	return m, nil
}

func checkContent(path string, b []byte, e entry, completed bool) error {
	if completed && path == ServerPath {
		if i := strings.Index(string(b), "\n[Peer]"); i >= 0 {
			b = b[:i+1]
		}
	}
	if completed && path == DefaultsPath {
		var d store.Defaults
		if json.Unmarshal(b, &d) != nil || d.Version != store.DefaultsVersion || d.Endpoint == "" {
			return errors.New("invalid managed client defaults")
		}
		return nil // operator changes through the panel are legitimate
	}
	if digest(b) != e.SHA256 {
		return errors.New("managed file changed; refusing to overwrite")
	}
	return nil
}

func privateFile(root, path string) error {
	st, err := os.Lstat(target(root, path))
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return errors.New("managed secret file must be regular with mode 0600")
	}
	return nil
}

// Verify reads installed configuration, never writes files or prints secrets.
func Verify(root string) error {
	if root == "" {
		root = string(filepath.Separator)
	}
	m, err := loadManifest(root)
	if err != nil {
		return err
	}
	if err := auxiliaryPaths(root); err != nil {
		return err
	}
	completed, err := preparationComplete(root)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if err := safePath(root, p); err != nil {
			return err
		}
		if err := privateFile(root, p); err != nil {
			return err
		}
		b, err := os.ReadFile(target(root, p))
		if err != nil {
			return fmt.Errorf("missing managed file: %s", p)
		}
		if err := checkContent(p, b, m.Files[p], completed); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

// Prepare creates only files named by a previously persisted ownership manifest.
// The manifest records hashes and staged paths, never credentials or key values.
func Prepare(o Options, rnd io.Reader) (Result, error) {
	o, p, err := normalize(o)
	if err != nil {
		return Result{}, err
	}
	result := Result{Listen: net.JoinHostPort(p.Addr().String(), "8081"), Config: PanelPath, Credentials: CredentialsPath}
	if err := auxiliaryPaths(o.Root); err != nil {
		return result, err
	}
	for _, path := range append(append([]string{}, paths...), ManifestPath, CompletePath) {
		if err := safePath(o.Root, path); err != nil {
			return result, err
		}
	}
	m, err := loadManifest(o.Root)
	if os.IsNotExist(err) {
		for _, path := range append(append([]string{}, paths...), CompletePath, "/var/lib/awg3panel/awgtop", AdminPath, AdminRecordPath) {
			if _, e := os.Lstat(target(o.Root, path)); e == nil {
				return result, fmt.Errorf("existing unmanaged file: %s", path)
			} else if !os.IsNotExist(e) {
				return result, e
			}
		}
		if o.DryRun {
			return result, nil
		}
		files, err := render(o, p, rnd)
		if err != nil {
			return result, err
		}
		if err := ensureParent(o.Root, ManifestPath); err != nil {
			return result, err
		}
		stateDir := filepath.Dir(target(o.Root, ManifestPath))
		stage, err := os.MkdirTemp(stateDir, ".stage-")
		if err != nil {
			return result, errors.New("cannot create installation staging directory")
		}
		m = manifest{Version: 1, Preset: PresetName, Endpoint: o.Endpoint, Subnet: o.Subnet, Egress: o.Egress, DNS: o.DNS, Files: map[string]entry{}}
		for i, path := range paths {
			name := fmt.Sprint(i)
			if err := newFile(filepath.Join(stage, name), files[path]); err != nil {
				return result, err
			}
			m.Files[path] = entry{SHA256: digest(files[path]), Stage: filepath.ToSlash(filepath.Join(filepath.Base(stage), name))}
		}
		data, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return result, err
		}
		if err := newFile(target(o.Root, ManifestPath), data); err != nil {
			return result, err
		}
	} else if err != nil {
		return result, err
	}
	if m.Endpoint != o.Endpoint || m.Subnet != o.Subnet || m.Egress != o.Egress || m.DNS != o.DNS {
		return result, errors.New("installation arguments differ from ownership manifest")
	}
	completed, err := preparationComplete(o.Root)
	if err != nil {
		return result, err
	}
	// Validate every existing target before completing any missing one.
	for _, path := range paths {
		b, e := os.ReadFile(target(o.Root, path))
		if os.IsNotExist(e) {
			if completed {
				return result, fmt.Errorf("completed installation lost %s; restore a current backup instead of stale staging data", path)
			}
			continue
		}
		if e != nil {
			return result, e
		}
		if err := checkContent(path, b, m.Files[path], completed); err != nil {
			return result, fmt.Errorf("%s: %w", path, err)
		}
	}
	if o.DryRun {
		return result, nil
	}
	ordered := append([]string{}, paths...)
	sort.Strings(ordered)
	for _, path := range ordered {
		if _, err := os.Lstat(target(o.Root, path)); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return result, err
		}
		e := m.Files[path]
		stagePath := filepath.ToSlash(filepath.Join(filepath.Dir(ManifestPath), e.Stage))
		if err := safePath(o.Root, stagePath); err != nil {
			return result, err
		}
		b, err := os.ReadFile(target(o.Root, stagePath))
		if err != nil || digest(b) != e.SHA256 {
			return result, errors.New("installation staging data missing or changed")
		}
		if err := ensureParent(o.Root, path); err != nil {
			return result, err
		}
		if err := newFile(target(o.Root, path), b); err != nil {
			return result, err
		}
		if o.AfterWrite != nil {
			if err := o.AfterWrite(path); err != nil {
				return result, err
			}
		}
	}
	if err := Verify(o.Root); err != nil {
		return result, err
	}
	if !completed {
		if err := newFile(target(o.Root, CompletePath), []byte("prepared-v1\n")); err != nil {
			return result, err
		}
	}
	return result, nil
}

func render(o Options, p netip.Prefix, rnd io.Reader) (map[string][]byte, error) {
	preset, err := Generate(rnd)
	if err != nil {
		return nil, err
	}
	priv := make([]byte, 32)
	if _, err := io.ReadFull(rnd, priv); err != nil {
		return nil, errors.New("key entropy unavailable")
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pw := make([]byte, 24)
	if _, err := io.ReadFull(rnd, pw); err != nil {
		return nil, errors.New("password entropy unavailable")
	}
	password := base64.RawURLEncoding.EncodeToString(pw)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return nil, errors.New("cannot hash panel password")
	}
	state := "/var/lib/awg3panel/awgtop"
	endpoint := net.JoinHostPort(o.Endpoint, "3478")
	c := config.Config{Listen: net.JoinHostPort(p.Addr().String(), "8081"), Auth: config.Auth{User: "admin", Bcrypt: string(hash)}, Interfaces: []config.Interface{{ID: "awgtop", Title: "Personal AWG 3.1", Interface: "awgtop", Config: ServerPath, BinDir: "/opt/awgtop/bin", Client: config.Client{Endpoint: endpoint, AllowedIPs: "0.0.0.0/0", PersistentKeepalive: "22-30", DNS: o.DNS, Jc: 6, Jmin: 48, Jmax: 160}, Storage: config.Storage{State: state + "/peers.json", Backups: state + "/backups", Keys: state + "/keys"}}}}
	if err := c.Validate(); err != nil {
		return nil, errors.New("generated panel configuration failed validation")
	}
	panel, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	d := preset.Defaults(endpoint)
	d.DNS = o.DNS
	defaults, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	env := fmt.Sprintf("AWG_IFACE=awgtop\nAWG_ADDRESS='%s'\nAWG_NETWORK='%s'\nAWG_EGRESS='%s'\nAWG_PANEL='%s'\nAWG_ENDPOINT='%s'\n", p.String(), p.Masked().String(), o.Egress, p.Addr(), o.Endpoint)
	credentials := fmt.Sprintf("Panel: http://%s\nUser: admin\nPassword: %s\nPreset: %s\nIPv4 full tunnel; DNS omitted unless selected. Check IPv6/KillSwitch in the client.\n", c.Listen, password, PresetName)
	return map[string][]byte{ServerPath: []byte(preset.ServerConfig(base64.StdEncoding.EncodeToString(priv), p.String())), PanelPath: panel, DefaultsPath: defaults, EnvironmentPath: []byte(env), CredentialsPath: []byte(credentials)}, nil
}
