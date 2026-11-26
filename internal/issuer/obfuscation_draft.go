package issuer

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/warpsignature"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

type DraftOptions struct {
	Profile        string  `json:"profile"`
	HostPreset     string  `json:"host_preset,omitempty"`
	Domains        string  `json:"domains,omitempty"`
	TimingJitter   bool    `json:"timing_jitter"`
	ContentPadding *string `json:"content_padding"`
	RandomTrailers *bool   `json:"random_trailers"`
	DisableCookies *bool   `json:"disable_cookies"`
	Jitter         *Jitter `json:"jitter,omitempty"`
}

type ObfuscationDraft struct {
	ServerBlock string    `json:"server_block"`
	ClientBlock string    `json:"client_block"`
	Keepalive   string    `json:"keepalive"`
	Profile     string    `json:"profile"`
	Domain      string    `json:"domain"`
	ListenPort  int       `json:"listen_port"`
	CPS         [5]string `json:"cps"`
	Jitter      Jitter    `json:"jitter"`
}

// GenerateObfuscationDraft generates a pair of snippets for a new standalone
// AWG interface and the related client. Both blocks belong in [Interface].
// Keepalive is the separate PersistentKeepalive value for the client's [Peer].
func GenerateObfuscationDraft(rnd io.Reader, opts DraftOptions) (ObfuscationDraft, error) {
	if j := opts.Jitter; j != nil {
		if err := validateEffectiveJitter(j.Jc, j.Jmin, j.Jmax, "1280"); err != nil {
			return ObfuscationDraft{}, err
		}
	}
	var rawPadding string
	if opts.ContentPadding != nil {
		rawPadding = *opts.ContentPadding
	}
	padding, err := normalizeDraftPadding(rawPadding)
	if err != nil {
		return ObfuscationDraft{}, err
	}
	signature, err := warpsignature.GenerateWithOptions(opts.Profile, warpsignature.GenerateOptions{
		HostPreset: opts.HostPreset,
		Domain:     opts.Domains,
	})
	if err != nil {
		return ObfuscationDraft{}, fmt.Errorf("%w: параметры сигнатуры: %w", ErrInvalidInput, err)
	}
	port, err := draftListenPort(signature.Profile)
	if err != nil {
		return ObfuscationDraft{}, err
	}

	base, err := GenerateInterfaceParams(rnd, MimicryQUIC)
	if err != nil {
		return ObfuscationDraft{}, err
	}
	trailers := opts.RandomTrailers != nil && *opts.RandomTrailers
	cookies := opts.DisableCookies != nil && *opts.DisableCookies
	extensions := generatedDraftExtensions(padding, opts.TimingJitter, trailers, cookies)
	draft := ObfuscationDraft{
		Keepalive:  "25",
		Profile:    signature.Profile,
		Domain:     signature.Domain,
		ListenPort: port,
		CPS:        [5]string{signature.Packets.I1, signature.Packets.I2, signature.Packets.I3, signature.Packets.I4, signature.Packets.I5},
		Jitter:     base.Jitter,
	}
	if opts.TimingJitter {
		draft.Keepalive = "25-35"
	}
	if opts.Jitter != nil {
		draft.Jitter = *opts.Jitter
	}
	return renderObfuscationDraft(base, extensions, draft, maxRandomTagLen)
}

// GenerateDraftFromPeer reuses settings from a single exported client .conf.
// The address, credentials and routing stay with the source profile.
func GenerateDraftFromPeer(rnd io.Reader, profile string) (ObfuscationDraft, error) {
	config, err := wgconf.Parse(profile)
	if err != nil || len(config.Peers) != 1 {
		return ObfuscationDraft{}, fmt.Errorf("%w: ожидается экспортированный конфиг с одним пиром", ErrInvalidInput)
	}
	iface, peer := config.Interface, config.Peers[0]
	host, rawPort, err := net.SplitHostPort(peer.Get("Endpoint"))
	if err != nil || host == "" {
		return ObfuscationDraft{}, fmt.Errorf("%w: некорректный Endpoint исходного пира", ErrInvalidInput)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return ObfuscationDraft{}, fmt.Errorf("%w: некорректный порт исходного пира", ErrInvalidInput)
	}
	draft := ObfuscationDraft{ListenPort: int(port), Keepalive: peer.Get("PersistentKeepalive")}
	if err := validateKeepalive(draft.Keepalive); err != nil {
		return ObfuscationDraft{}, fmt.Errorf("%w: некорректный PersistentKeepalive исходного пира", ErrInvalidInput)
	}
	if err := readDraftJunk(iface, &draft); err != nil {
		return ObfuscationDraft{}, err
	}
	extensions, err := copiedDraftExtensions(iface)
	if err != nil {
		return ObfuscationDraft{}, err
	}
	base, err := GenerateInterfaceParams(rnd, MimicryQUIC)
	if err != nil {
		return ObfuscationDraft{}, err
	}
	if base.HeaderProtectionKey == iface.Get("HeaderProtectionKey") {
		return ObfuscationDraft{}, fmt.Errorf("не удалось получить новый ключ защиты заголовка")
	}
	return renderObfuscationDraft(base, extensions, draft, 0)
}

func readDraftJunk(iface *wgconf.Section, draft *ObfuscationDraft) error {
	for _, field := range []struct {
		name string
		n    *int
	}{{"Jc", &draft.Jitter.Jc}, {"Jmin", &draft.Jitter.Jmin}, {"Jmax", &draft.Jitter.Jmax}} {
		if raw := iface.Get(field.name); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil {
				return fmt.Errorf("%w: некорректный %s исходного пира", ErrInvalidInput, field.name)
			}
			*field.n = n
		}
	}
	mtu := iface.Get("MTU")
	if mtu != "" && validateMTU(mtu) != nil {
		return fmt.Errorf("%w: некорректный MTU исходного пира", ErrInvalidInput)
	}
	j := draft.Jitter
	if err := validateEffectiveJitter(j.Jc, j.Jmin, j.Jmax, mtu); err != nil {
		return fmt.Errorf("%w: некорректный набор J исходного пира", ErrInvalidInput)
	}

	draft.Profile = warpsignature.ProfileNone
	for i := range draft.CPS {
		draft.CPS[i] = iface.Get(cpsKeys[i])
		if draft.CPS[i] != "" {
			draft.Profile = "custom"
		}
	}
	if detection, ok := DetectProfile(draft.CPS[0]); ok {
		draft.Profile = string(detection)
		if detection == MimicryQUIC {
			draft.Profile = "quic_initial"
		}
	}
	return nil
}

func renderObfuscationDraft(p InterfaceParams, extensions string, draft ObfuscationDraft, maxCPSRandom int) (ObfuscationDraft, error) {
	shared := draftSharedBlock(p) + extensions
	draft.ServerBlock = fmt.Sprintf("ListenPort = %d\n", draft.ListenPort) + shared
	var client strings.Builder
	client.WriteString(shared)
	if j := draft.Jitter; j != (Jitter{}) {
		fmt.Fprintf(&client, "Jc = %d\nJmin = %d\nJmax = %d\n", j.Jc, j.Jmin, j.Jmax)
	}
	extra := make(map[string]string)
	for i, packet := range draft.CPS {
		if packet != "" {
			// Older exports allow text between tags. A value without any
			// token does not produce a packet and is not safe to copy.
			if !strings.Contains(packet, "<") {
				return ObfuscationDraft{}, fmt.Errorf("%w: некорректные параметры CPS", ErrInvalidInput)
			}
			key := cpsKeys[i]
			extra[key] = packet
			fmt.Fprintf(&client, "%s = %s\n", key, packet)
		}
	}
	if err := validateExtra(extra, maxCPSRandom); err != nil {
		return ObfuscationDraft{}, fmt.Errorf("%w: некорректные параметры CPS", ErrInvalidInput)
	}
	draft.ClientBlock = client.String()
	return draft, nil
}

func draftListenPort(profile string) (int, error) {
	switch profile {
	case warpsignature.ProfileNone:
		return 51820, nil
	case "quic_initial":
		profile = string(MimicryQUIC)
	}
	if port, ok := PortForProfile(MimicryProfile(profile)); ok {
		return port, nil
	}
	return 0, fmt.Errorf("нет порта для профиля %q", profile)
}

func draftSharedBlock(p InterfaceParams) string {
	var block strings.Builder
	for i, value := range [4]int{p.S1, p.S2, p.S3, p.S4} {
		fmt.Fprintf(&block, "S%d = %d\n", i+1, value)
	}
	for i, value := range [4]HRange{p.H1, p.H2, p.H3, p.H4} {
		fmt.Fprintf(&block, "H%d = %s\n", i+1, value.String())
	}
	fmt.Fprintf(&block, "HeaderProtectionKey = %s\n", p.HeaderProtectionKey)
	return block.String()
}

func generatedDraftExtensions(padding string, timing, trailers, cookies bool) string {
	var block strings.Builder
	if padding == "" && !trailers {
		padding = "0" // ExtractObfuscation requires an explicit CPA in AWG 3.0.
	}
	if padding != "" {
		fmt.Fprintf(&block, "ContentPaddingAddition = %s\n", padding)
	}
	// Timing ranges match AWG Manager v2.20.6 internal/warpscout/conf.go.
	if timing {
		block.WriteString("RekeyAfterTime = 100-120\nRekeyTimeout = 3-7\nRejectAfterTime = 150-180\n" +
			"KeepaliveTimeout = 5-15\nMaxHandshakeAttempts = 15-20\n")
	}
	if trailers {
		block.WriteString("RandomTrailers = on\n")
	}
	if cookies {
		block.WriteString("DisableCookies = on\n")
	}
	return block.String()
}

func copiedDraftExtensions(iface *wgconf.Section) (string, error) {
	var block strings.Builder
	padding := iface.Get("ContentPaddingAddition")
	if padding == "" && !isOn(iface.Get("RandomTrailers")) {
		padding = "0"
	}
	if padding != "" {
		if _, err := normalizeDraftPadding(padding); err != nil {
			return "", fmt.Errorf("%w: некорректный ContentPaddingAddition исходного пира", ErrInvalidInput)
		}
		fmt.Fprintf(&block, "ContentPaddingAddition = %s\n", padding)
	}
	for _, key := range TimingKeys {
		if value := iface.Get(key); value != "" {
			if _, err := normalizeDraftPadding(value); err != nil {
				return "", fmt.Errorf("%w: некорректный %s исходного пира", ErrInvalidInput, key)
			}
			fmt.Fprintf(&block, "%s = %s\n", key, value)
		}
	}
	for _, key := range TrailerKeys {
		value := iface.Get(key)
		switch strings.ToLower(value) {
		case "":
		case "on", "off", "true", "false", "1", "0":
			fmt.Fprintf(&block, "%s = %s\n", key, value)
		default:
			return "", fmt.Errorf("%w: некорректный %s исходного пира", ErrInvalidInput, key)
		}
	}
	return block.String(), nil
}

func normalizeDraftPadding(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	lo, hi, ranged := strings.Cut(raw, "-")
	minimum, err := parseDraftPaddingNumber(lo)
	if err != nil {
		return "", err
	}
	if !ranged {
		return strconv.Itoa(minimum), nil
	}
	maximum, err := parseDraftPaddingNumber(hi)
	if err != nil {
		return "", err
	}
	if minimum > maximum {
		return "", fmt.Errorf("%w: нижняя граница ContentPaddingAddition больше верхней", ErrInvalidInput)
	}
	return fmt.Sprintf("%d-%d", minimum, maximum), nil
}

func parseDraftPaddingNumber(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) <= 5 && raw != "" && strings.Trim(raw, "0123456789") == "" {
		if n, err := strconv.ParseUint(raw, 10, 16); err == nil {
			return int(n), nil
		}
	}
	return 0, fmt.Errorf("%w: ContentPaddingAddition — число 0..65535 или диапазон min-max", ErrInvalidInput)
}
