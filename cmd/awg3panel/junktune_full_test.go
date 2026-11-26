//go:build !readonly

package main

import (
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/junktune"
)

func TestTuneProfileVersionChecksBindingAndTracksEditedFields(t *testing.T) {
	const conf = `[Interface]
Address = 198.51.100.10/32
MTU = 1280
Jc = 4
S1 = 15
S2 = 16
S3 = 17
S4 = 18
H1 = 20-29
H2 = 30-39
H3 = 40-49
H4 = 50-59
I1 = <r 3>

[Peer]
PublicKey = test-public-key
Endpoint = 203.0.113.10:3478
`
	router := junktune.Snapshot{
		Endpoint: "203.0.113.10:3478", LocalAddress: "198.51.100.10/32",
		MTU: 1280, ServerPublicKey: "test-public-key", Mimicry: [5]string{"<r 3>"},
		Headers: [4]string{"20-29", "30-39", "40-49", "50-59"}, Padding: [4]int{15, 16, 17, 18},
	}
	baseline, err := tuneProfileVersion(conf, router, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tuneProfileVersion(strings.Replace(conf, "Jc = 4", "Jc = 7", 1), router, false)
	if err != nil || baseline.Fingerprint != got.Fingerprint || baseline == got || got.Parameters.Jitter.Jc != 7 {
		t.Fatalf("junk edit must change the saved parameters and preserve the fixed fields: %v", err)
	}
	full, err := tuneProfileVersion(conf, router, true)
	if err != nil {
		t.Fatal(err)
	}
	cpsEdit := strings.Replace(conf, "I1 = <r 3>", "I2 = <r 29>", 1)
	got, err = tuneProfileVersion(cpsEdit, router, true)
	if err != nil || got.Fingerprint != full.Fingerprint || got == full || got.Parameters.CPS[1] != "<r 29>" {
		t.Fatalf("CPS edit must change the saved parameters and preserve the fixed fields: %v", err)
	}
	for _, edit := range []func(*junktune.Snapshot){
		func(s *junktune.Snapshot) { s.Mimicry[0] = "" },
		func(s *junktune.Snapshot) { s.Headers[3] = "60-69" },
		func(s *junktune.Snapshot) { s.Padding[0]++ },
		func(s *junktune.Snapshot) { s.MTU++ },
		func(s *junktune.Snapshot) { s.LocalAddress = "198.51.100.11/32" },
	} {
		changed := router
		edit(&changed)
		if _, err := tuneProfileVersion(conf, changed, false); err == nil {
			t.Fatal("accepted the wrong router profile")
		}
	}
	router.WireFingerprint[0]++
	if changed, err := tuneProfileVersion(conf, router, false); err != nil || changed.Fingerprint == baseline.Fingerprint {
		t.Fatalf("router settings did not invalidate the measurement: %v", err)
	}
}
