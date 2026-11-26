package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// These roots match ReadWritePaths in deploy/awg3panel.service.
const (
	serviceConfigRoot  = "/etc/amnezia/amneziawg"
	serviceStorageRoot = "/var/lib/awg3panel"
)

var bcryptPattern = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{21}[.Oeu][./A-Za-z0-9]{30}[.CGKOSWaeimquy26]$`)

func validBcrypt(hash string) bool {
	if !bcryptPattern.MatchString(hash) {
		return false
	}
	_, err := bcrypt.Cost([]byte(hash))
	return err == nil
}

// ValidateBcrypt checks the configured hash without requiring a running host.
func (c *Config) ValidateBcrypt() error {
	if !validBcrypt(c.Auth.Bcrypt) {
		return fmt.Errorf("auth.bcrypt: некорректный bcrypt-хеш")
	}
	return nil
}

// validateService checks host-dependent requirements before the daemon recovers
// pending operations. Parse is also used by offline tools and remains portable.
func (c *Config) validateService() error {
	if err := c.ValidateBcrypt(); err != nil {
		return err
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("listen: чтение локальных адресов: %w", err)
	}
	host, _, _ := net.SplitHostPort(c.Listen)
	if !hasLocalAddress(net.ParseIP(host), addrs) {
		return fmt.Errorf("listen %q: IP-адрес не назначен локальному интерфейсу", c.Listen)
	}

	for _, iface := range c.Interfaces {
		// bin_dir is read-only in the unit. Check it as seen from the
		// service namespace (ProtectHome and PrivateTmp can hide it).
		if err := checkBinDir(iface.BinDir); err != nil {
			return fmt.Errorf("interfaces[%s].bin_dir: %w", iface.ID, err)
		}
		for _, field := range []struct {
			name, value, root string
			directory         bool
		}{
			{"config", iface.Config, serviceConfigRoot, false},
			{"storage.state", iface.Storage.State, serviceStorageRoot, false},
			{"storage.backups", iface.Storage.Backups, serviceStorageRoot, true},
			{"storage.keys", iface.Storage.Keys, serviceStorageRoot, true},
			{"storage.client_configs", iface.Storage.ClientConfigs, serviceStorageRoot, true},
		} {
			if field.name == "storage.client_configs" && field.value == "" {
				continue
			}
			if err := checkServicePath(field.value, field.root, field.directory); err != nil {
				return fmt.Errorf("interfaces[%s].%s: %w", iface.ID, field.name, err)
			}
		}
	}
	return nil
}

func checkBinDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0100 == 0 {
		return fmt.Errorf("%q: требуется каталог с правом владельца на обход", dir)
	}
	return nil
}

func hasLocalAddress(ip net.IP, addrs []net.Addr) bool {
	for _, addr := range addrs {
		switch a := addr.(type) {
		case *net.IPNet:
			if ip.Equal(a.IP) {
				return true
			}
		case *net.IPAddr:
			if ip.Equal(a.IP) {
				return true
			}
		}
	}
	return false
}

func hasParentSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func withinServiceRoot(candidate, root string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && filepath.IsLocal(rel)
}

// checkServicePath allows missing descendants, whose directories are created
// on demand. Each existing ancestor below the sandbox root must stay inside it.
func checkServicePath(value, root string, directory bool) error {
	if !filepath.IsAbs(value) || !withinServiceRoot(value, root) || hasParentSegment(value) {
		return fmt.Errorf("путь %q должен находиться внутри %s", value, root)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("каталог службы %q: %w", root, err)
	}

	value = filepath.Clean(value)
	needWrite := true
	for current := value; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return err
			}
			if !withinServiceRoot(resolved, resolvedRoot) {
				return fmt.Errorf("путь %q через символическую ссылку выходит за %s", current, root)
			}
			info, err = os.Stat(resolved)
			if err != nil {
				return err
			}
			if current == value && !directory {
				if !info.Mode().IsRegular() {
					return fmt.Errorf("%q: требуется обычный файл", current)
				}
			} else {
				if !info.IsDir() || info.Mode().Perm()&0100 == 0 {
					return fmt.Errorf("%q: требуется каталог с правом владельца на обход", current)
				}
				if needWrite && info.Mode().Perm()&0200 == 0 {
					return fmt.Errorf("%q: каталог без права владельца на запись", current)
				}
				needWrite = false
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}

		if current == root {
			return nil
		}
	}
}
