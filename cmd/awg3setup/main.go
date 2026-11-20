// awg3setup is a root-only installer helper, never part of the web daemon.
package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Jkaotlic/awg3-panel/internal/bootstrap"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: awg3setup prepare|verify|version [options]")
	}
	if args[0] == "version" {
		fmt.Fprintf(out, "awg3setup %s\n", version)
		return nil
	}
	if args[0] != "prepare" && args[0] != "verify" && args[0] != "admin-record" && args[0] != "admin-verify" {
		return errors.New("unknown setup command")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(out)
	o := bootstrap.Options{}
	f.StringVar(&o.Root, "root", string(filepath.Separator), "installation root (isolated tests only)")
	f.StringVar(&o.Endpoint, "endpoint", "", "public IPv4 address")
	f.StringVar(&o.Subnet, "subnet", "10.66.0.1/24", "private IPv4 subnet, first host")
	f.StringVar(&o.Egress, "egress", "", "WAN interface")
	f.StringVar(&o.DNS, "dns", "", "optional client DNS IP addresses, comma separated")
	f.BoolVar(&o.DryRun, "dry-run", false, "inspect only; do not create files or keys")
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errors.New("invalid setup arguments")
	}
	if f.NArg() != 0 {
		return errors.New("unexpected setup arguments")
	}
	if o.Root == string(filepath.Separator) && !o.DryRun && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
		return errors.New("a real installation requires Linux root")
	}
	if args[0] == "admin-record" || args[0] == "admin-verify" {
		_, err := bootstrap.AdminProfile(o.Root, args[0] == "admin-record")
		return err
	}
	if args[0] == "verify" {
		if err := bootstrap.Verify(o.Root); err != nil {
			return err
		}
		fmt.Fprintln(out, "configuration ownership: OK")
		return nil
	}
	r, err := bootstrap.Prepare(o, rand.Reader)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "preset: %s\npanel: http://%s (VPN only)\ncredentials file: %s\n", bootstrap.PresetName, r.Listen, r.Credentials)
	return nil
}
