package issuer_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/store"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

func TestPreviewMeasuredObfuscationPreservesPeerAndChangesOnlyTuningFields(t *testing.T) {
	e := newServiceEnv(t)
	p, err := e.svc.Add("preview lab")
	if err != nil {
		t.Fatal(err)
	}
	dns := "203.0.113.53"
	if err := e.svc.Update(p.ID, issuer.PeerPatch{Overrides: &store.Overrides{
		DNS: &dns, Extra: map[string]string{"i1": "<r 10>", "I4": "<r 20>", "TestField": "keep"},
	}}); err != nil {
		t.Fatal(err)
	}
	name, current, err := e.svc.ConfigFor(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	state := readConf(t, e.iface.Storage.State)
	server := readConf(t, e.iface.Config)
	beforeCalls := len(e.fake.Calls)

	tuning := issuer.Jitter{Jc: 7, Jmin: 64, Jmax: 400}
	replacement := [5]string{"<r 35>", "<r 45>"}
	empty := [5]string{}
	for _, test := range []struct {
		name    string
		cps     *[5]string
		wantCPS [5]string
	}{
		{"legacy-jitter-only", nil, [5]string{"<r 10>", "", "", "<r 20>"}},
		{"replacement-CPS", &replacement, replacement},
		{"clear-CPS", &empty, empty},
	} {
		t.Run(test.name, func(t *testing.T) {
			checked := false
			previewName, body, err := e.svc.PreviewMeasuredObfuscation(p.ID, tuning, test.cps, func(profile string) error {
				checked = true
				if profile != current {
					t.Error("measurement check must receive the current peer profile")
				}
				return nil
			})
			if err != nil || !checked || previewName != strings.TrimSuffix(name, ".conf")+"-measured.conf" {
				t.Fatalf("unexpected preview outcome %q, check called %t, error %v", previewName, checked, err)
			}
			if stripTuningLines(body) != stripTuningLines(current) {
				t.Fatal("preview modified non-tunable fields")
			}
			parsed, err := wgconf.Parse(body)
			if err != nil {
				t.Fatal("unusable preview profile")
			}
			for key, want := range map[string]string{"Jc": "7", "Jmin": "64", "Jmax": "400"} {
				if parsed.Interface.Get(key) != want {
					t.Errorf("preview omitted measured %s", key)
				}
			}
			for index, want := range test.wantCPS {
				if parsed.Interface.Get(fmt.Sprintf("I%d", index+1)) != want {
					t.Errorf("wrong CPS field I%d", index+1)
				}
			}
		})
	}
	if _, after, err := e.svc.ConfigFor(p.ID); err != nil || after != current {
		t.Fatal("preview modified the issued profile")
	}
	if readConf(t, e.iface.Storage.State) != state || readConf(t, e.iface.Config) != server {
		t.Fatal("preview wrote peer state or server configuration")
	}
	for _, call := range e.fake.Calls[beforeCalls:] {
		if strings.HasPrefix(call, "syncconf ") {
			t.Fatal("preview applied server configuration")
		}
	}
}

func stripTuningLines(body string) string {
	var keep []string
	for _, line := range strings.Split(body, "\n") {
		key, _, _ := strings.Cut(strings.ToLower(line), " = ")
		switch key {
		case "jc", "jmin", "jmax", "i1", "i2", "i3", "i4", "i5":
		default:
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

func TestPreviewMeasuredObfuscationRejectsUnverifiedOrInvalidProfiles(t *testing.T) {
	e := newServiceEnv(t)
	p, err := e.svc.Add("preview lab")
	if err != nil {
		t.Fatal(err)
	}
	jitter := issuer.Jitter{Jc: 7, Jmin: 64, Jmax: 400}
	const secret = "preview-secret-marker"
	check := func(string) error { return nil }
	markerCPS := [5]string{"<" + secret + ">"}
	for _, test := range []struct {
		name   string
		jitter issuer.Jitter
		cps    *[5]string
		check  func(string) error
		want   error
	}{
		{"missing-check", jitter, nil, nil, issuer.ErrInvalidInput},
		{"changed-profile", jitter, nil, func(string) error { return fmt.Errorf("%w: %s", issuer.ErrStateConflict, secret) }, issuer.ErrStateConflict},
		{"partial-jitter", issuer.Jitter{Jc: 7}, nil, check, issuer.ErrInvalidInput},
		{"invalid-CPS", jitter, &markerCPS, check, issuer.ErrInvalidInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			name, body, err := e.svc.PreviewMeasuredObfuscation(p.ID, test.jitter, test.cps, test.check)
			if !errors.Is(err, test.want) || name != "" || body != "" || strings.Contains(err.Error(), secret) {
				t.Fatal("preview exposed content or returned an unexpected error class")
			}
		})
	}
	if err := e.svc.Disable(p.ID); err != nil {
		t.Fatal(err)
	}
	if name, body, err := e.svc.PreviewMeasuredObfuscation(p.ID, jitter, nil, func(string) error {
		t.Error("disabled peer must not be passed to measurement check")
		return nil
	}); !errors.Is(err, issuer.ErrStateConflict) || name != "" || body != "" {
		t.Fatal("disabled peer was exported or caused an incorrect error class")
	}
}
