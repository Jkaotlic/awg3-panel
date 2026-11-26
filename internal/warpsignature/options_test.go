package warpsignature

import (
	"errors"
	"slices"
	"testing"
)

func TestNormalizeProfileAndDomainOptions(t *testing.T) {
	profile, opts, err := Normalize(" QUIC ", GenerateOptions{Domain: "a.example.com; https://b.example.com:443/x a.example.com"})
	if err != nil || profile != "quic_initial" || opts.HostPreset != HostPresetCustom ||
		!slices.Equal(opts.Domains, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("Normalize returned %q, %+v, %v", profile, opts, err)
	}
	profile, opts, err = Normalize("", GenerateOptions{HostPreset: "whitelist"})
	if err != nil || profile != "random" || opts.HostPreset != HostPresetRU {
		t.Fatalf("Normalize returned %q, %+v, %v", profile, opts, err)
	}
	for _, test := range []struct {
		profile string
		options GenerateOptions
		want    error
	}{
		{"tls", GenerateOptions{}, ErrUnknownProtocol},
		{"quic", GenerateOptions{HostPreset: "typo"}, ErrInvalidDomainPreset},
		{"dns", GenerateOptions{HostPreset: "custom"}, ErrInvalidDomain},
		{"dns", GenerateOptions{Domain: "a.example.com, b.example.com$"}, ErrInvalidDomain},
	} {
		if _, _, err := Normalize(test.profile, test.options); !errors.Is(err, test.want) {
			t.Errorf("Normalize(%q, %+v) = %v, want %v", test.profile, test.options, err, test.want)
		}
	}
}

func TestGenerateSpecialProfiles(t *testing.T) {
	none, err := GenerateWithOptions("none", GenerateOptions{HostPreset: "custom"})
	if err != nil || none.Profile != "none" || none.Domain != "" ||
		none.Packets != (GeneratedPackets{}) || none.ByteSize != 0 {
		t.Fatalf("none: %+v, %v", none, err)
	}
	result, err := GenerateWithOptions("random", GenerateOptions{Domain: "example.com"})
	if err != nil || !slices.Contains(Profiles, result.Profile) || result.Domain != "example.com" || result.Packets.I1 == "" {
		t.Fatalf("random: %s, %s, %v", result.Profile, result.Domain, err)
	}
}

func TestProfilesMatchUpstreamPacketCountsAndSizes(t *testing.T) {
	for _, profile := range Profiles {
		t.Run(profile, func(t *testing.T) {
			result, err := GenerateWithOptions(profile, GenerateOptions{Domain: "example.com"})
			if err != nil || result.Domain != "example.com" || result.Packets.I1 == "" {
				t.Fatalf("generated %q, error %v", result.Domain, err)
			}
			if (result.Packets.I2 != "") != (profile == "sip") ||
				result.Packets.I3 != "" || result.Packets.I4 != "" || result.Packets.I5 != "" {
				t.Fatal("unexpected CPS packet count")
			}
			if profile == "quic_initial" && (ByteSize(result.Packets.I1) != 1200 || result.ByteSize != 1200) {
				t.Errorf("wrong QUIC Initial size: %d", result.ByteSize)
			}
		})
	}
}
