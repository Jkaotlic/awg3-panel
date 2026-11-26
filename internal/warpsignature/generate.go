// Package warpsignature generates CPS payloads entirely in memory.
//
// The protocol encoders and host pools are adapted from AWG Manager v2.20.6
// (https://github.com/hoaxisr/awg-manager/tree/v2.20.6/internal/signature),
// which adapted byte layouts from https://github.com/Sketchystan1/payloadGen.
package warpsignature

import (
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// MaxSignatureChars is the combined CPS text limit used by AWG Manager to
// leave room in the AWG tools' netlink message for the other tunnel fields.
const MaxSignatureChars = 3500

const (
	ProfileRandom = "random"
	ProfileNone   = "none"
)

// Profiles lists the protocols available to random selection in upstream order.
var Profiles = []string{"quic_initial", "stun", "dns", "dtls", "sip"}

var (
	ErrUnknownProtocol = errors.New("unknown protocol")
	ErrPacketsTooLarge = errors.New("signature packets exceed size limit")
)

type GeneratedPackets struct{ I1, I2, I3, I4, I5 string }

type Result struct {
	Profile  string
	Domain   string
	Packets  GeneratedPackets
	ByteSize int
}

type GenerateOptions struct {
	Domain     string
	HostPreset string
	Domains    []string
}

var builders = map[string]func(*mrand.Rand, string) (GeneratedPackets, string, error){
	"quic_initial": buildQUICProfileWithHost,
	"stun":         buildSTUNWithHost,
	"dns":          buildDNSWithHost,
	"dtls":         buildDTLSWithHost,
	"sip":          buildSIPWithHost,
}

// Normalize validates a profile and makes its options reusable across attempts.
// Domain can be an explicit name or list. When provided, it takes precedence
// over Domains, and either explicit input takes precedence over the host pool.
func Normalize(profile string, opts GenerateOptions) (string, GenerateOptions, error) {
	switch profile = strings.ToLower(strings.TrimSpace(profile)); profile {
	case "":
		profile = ProfileRandom
	case "quic":
		profile = "quic_initial"
	case ProfileNone, ProfileRandom:
	default:
		if _, exists := builders[profile]; !exists {
			return "", GenerateOptions{}, ErrUnknownProtocol
		}
	}
	preset := CanonicalHostPreset(opts.HostPreset)
	if preset == "" {
		return "", GenerateOptions{}, ErrInvalidDomainPreset
	}
	var domains []string
	if strings.TrimSpace(opts.Domain) != "" {
		list, err := ParseDomainList(opts.Domain)
		if err != nil {
			return "", GenerateOptions{}, err
		}
		domains = list
	} else {
		if len(opts.Domains) > MaxDomainListLen {
			return "", GenerateOptions{}, fmt.Errorf("%w: too many domains (max %d)", ErrInvalidDomain, MaxDomainListLen)
		}
		for _, raw := range opts.Domains {
			domain, err := ValidateDomain(raw)
			if err != nil {
				return "", GenerateOptions{}, err
			}
			if !slices.Contains(domains, domain) {
				domains = append(domains, domain)
			}
		}
	}
	if preset == HostPresetDefault && len(domains) > 0 {
		preset = HostPresetCustom
	}
	if profile != ProfileNone && preset == HostPresetCustom && len(domains) == 0 {
		return "", GenerateOptions{}, fmt.Errorf("%w: empty custom domain", ErrInvalidDomain)
	}
	return profile, GenerateOptions{HostPreset: preset, Domains: domains}, nil
}

// GenerateWithOptions creates a fresh CPS pattern. A random selection returns
// the selected protocol, while none returns an empty set of packets.
func GenerateWithOptions(profile string, opts GenerateOptions) (Result, error) {
	profile, opts, err := Normalize(profile, opts)
	if err != nil {
		return Result{}, err
	}
	if profile == ProfileNone {
		return Result{Profile: profile}, nil
	}
	random := mrand.New(mrand.NewSource(int64(binary.LittleEndian.Uint64(randBytes(8)))))
	if profile == ProfileRandom {
		profile = Profiles[random.Intn(len(Profiles))]
	}
	var host string
	switch {
	case len(opts.Domains) > 0:
		host = opts.Domains[random.Intn(len(opts.Domains))]
	case opts.HostPreset == HostPresetRU:
		host = ruWhitelistPool[random.Intn(len(ruWhitelistPool))]
	case opts.HostPreset == HostPresetCDN:
		host = cdnHostPool[random.Intn(len(cdnHostPool))]
	}
	packets, usedHost, err := builders[profile](random, host)
	if err != nil {
		return Result{}, err
	}
	if err := CheckSize(packets); err != nil {
		return Result{}, err
	}
	return Result{Profile: profile, Domain: usedHost, Packets: packets, ByteSize: TotalByteSize(packets)}, nil
}

var cpsTagRe = regexp.MustCompile(`<(\w+)(?:\s+([^>]*))?>`)
var hexArgRe = regexp.MustCompile(`0x([0-9a-fA-F]*)`)

// ByteSize is the UDP payload size of a generated CPS pattern on the wire.
func ByteSize(pattern string) int {
	total := 0
	for _, match := range cpsTagRe.FindAllStringSubmatch(pattern, -1) {
		tag, arg := match[1], match[2]
		switch tag {
		case "b":
			if hex := hexArgRe.FindStringSubmatch(arg); hex != nil {
				total += len(hex[1]) / 2
			}
		case "r", "rc", "rd":
			if n, err := strconv.Atoi(arg); err == nil && n > 0 {
				total += n
			}
		case "t":
			total += 4
		}
	}
	return total
}

func TotalByteSize(p GeneratedPackets) int {
	return ByteSize(p.I1) + ByteSize(p.I2) + ByteSize(p.I3) + ByteSize(p.I4) + ByteSize(p.I5)
}

func CheckSize(p GeneratedPackets) error {
	if size := len(p.I1) + len(p.I2) + len(p.I3) + len(p.I4) + len(p.I5); size > MaxSignatureChars {
		return fmt.Errorf("%w: %d > %d characters", ErrPacketsTooLarge, size, MaxSignatureChars)
	}
	return nil
}
