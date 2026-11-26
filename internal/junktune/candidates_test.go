package junktune

import (
	"errors"
	"slices"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/warpsignature"
)

func TestNormalizeOptions(t *testing.T) {
	opts, err := NormalizeOptions(Options{})
	if err != nil || opts != (Options{Profile: "random", HostPreset: "default", MaxAttempts: 10, ThresholdPct: 95}) {
		t.Fatalf("default options: %+v, %v", opts, err)
	}
	opts, err = NormalizeOptions(Options{
		Profile: "QUIC", HostPreset: "ru", Domains: "one.example.com; https://two.example.com/info, one.example.com",
		MaxAttempts: 42, ThresholdPct: 20,
	})
	if err != nil || opts.Profile != "quic_initial" || opts.HostPreset != "ru_whitelist" ||
		opts.Domains != "one.example.com, two.example.com" || opts.MaxAttempts != 30 || opts.ThresholdPct != 50 {
		t.Fatalf("normalized options: %+v, %v", opts, err)
	}
	if _, err := NormalizeOptions(Options{Profile: "dns", HostPreset: "custom"}); !errors.Is(err, issuer.ErrInvalidInput) {
		t.Fatalf("empty custom list: %v", err)
	}
}

func TestFindJunkCandidatesKeepControlAndRotateDomains(t *testing.T) {
	initial := Snapshot{
		MTU: 1280, Jitter: issuer.Jitter{Jc: 7, Jmin: 80, Jmax: 480},
		Mimicry: [5]string{"<r 32>", "", "<r 20>"},
	}
	opts := Options{Profile: "dns", HostPreset: "custom", Domains: "a.example.com, b.example.com", MaxAttempts: 6}
	candidates, err := generateFindJunkCandidates(opts, initial)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != opts.MaxAttempts+1 ||
		candidates[0] != (Candidate{Parameters: Parameters{Jitter: initial.Jitter, CPS: initial.Mimicry}, Profile: "current"}) {
		t.Fatalf("unexpected control or count: %d, %+v", len(candidates), candidates[0])
	}
	seen := map[Parameters]bool{candidates[0].Parameters: true}
	for index, candidate := range candidates[1:] {
		want := []string{"a.example.com", "b.example.com"}[index%2]
		if candidate.Domain != want || candidate.Profile != "dns" || candidate.CPS[0] == "" ||
			seen[candidate.Parameters] {
			t.Fatalf("candidate %d: profile %q, domain %q, duplicate %v", index, candidate.Profile,
				candidate.Domain, seen[candidate.Parameters])
		}
		seen[candidate.Parameters] = true
		j := candidate.Jitter
		if j.Jc < 4 || j.Jc > 6 || j.Jmin < 10 || j.Jmin > 50 || j.Jmax-j.Jmin < 20 || j.Jmax-j.Jmin > 100 {
			t.Errorf("jitter out of the upstream ranges: %+v", j)
		}
	}
}

func TestFindJunkRejectsOversizedCPSAndRandomUsesSupportedProfiles(t *testing.T) {
	initial := Snapshot{MTU: 1247}
	if _, err := generateFindJunkCandidates(Options{Profile: "quic_initial", MaxAttempts: 1}, initial); !errors.Is(err, issuer.ErrInvalidInput) {
		t.Fatalf("QUIC datagram does not fit: %v", err)
	}
	candidates, err := generateFindJunkCandidates(Options{Profile: "random", MaxAttempts: 30}, initial)
	if err != nil || len(candidates) != 31 {
		t.Fatalf("random: %d candidates, error %v", len(candidates), err)
	}
	for _, candidate := range candidates[1:] {
		if !slices.Contains(warpsignature.Profiles, candidate.Profile) || candidate.Profile == "quic_initial" {
			t.Fatalf("unsupported or oversized profile: %q", candidate.Profile)
		}
	}
}

func TestFindJunkNoneClearsEveryCPSPacket(t *testing.T) {
	initial := Snapshot{MTU: 1280, Mimicry: [5]string{"<r 16>", "<r 32>", "<r 64>", "<r 128>", "<r 256>"}}
	got, err := generateFindJunkCandidates(Options{Profile: "none", MaxAttempts: 1}, initial)
	if err != nil || len(got) != 2 || got[1].Profile != "none" || got[1].CPS != [5]string{} {
		t.Fatalf("none generated %d candidates, error %v", len(got), err)
	}
}
