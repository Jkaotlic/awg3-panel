package issuer

import (
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// Эталон 3.1: равные S, узкие непересекающиеся H1..H3, широкий H4, HPK, CPA, хвосты.
const etalonIface = `[Interface]
PrivateKey = c2VydmVyLXByaXZhdGUta2V5LWZha2UtMDAwMDAwMDAwMDA9
ListenPort = 3478
S1 = 27
S2 = 27
S3 = 27
S4 = 27
H1 = 686000000-686024999
H2 = 1949000000-1949024999
H3 = 1956000000-1956024999
H4 = 2839000000-2839024999
HeaderProtectionKey = aGVhZGVyLXByb3RlY3Rpb24ta2V5LWZha2UtMDAwMDAwMD0=
ContentPaddingAddition = 10-100
RandomTrailers = on
DisableCookies = on
`

func warningsFor(t *testing.T, conf string) []string {
	t.Helper()
	c, err := wgconf.Parse(conf)
	if err != nil {
		t.Fatal(err)
	}
	return interfaceWarnings(c.Interface)
}

func TestInterfaceWarnings(t *testing.T) {
	cases := []struct {
		name, from, to string
		n              int      // точное число предупреждений
		want           []string // подстроки, каждая обязана встретиться в каком-то предупреждении
	}{
		{"эталон чист", "", "", 0, nil},
		// Разные S при хвостах дают второе предупреждение — о равенстве.
		{"S меньше 12 при HPK", "S2 = 27", "S2 = 11", 2, []string{"S2", "12", "равн"}},
		{"S4 больше 32", "S4 = 27", "S4 = 33", 2, []string{"S4", "32", "равн"}},
		{"H пересекаются", "H2 = 1949000000-1949024999", "H2 = 686000100-686000200", 1, []string{"пересека"}},
		{"хвосты без CPA", "ContentPaddingAddition = 10-100\n", "", 1, []string{"ContentPaddingAddition"}},
		{"неразбираемый H", "H1 = 686000000-686024999", "H1 = abc", 1, []string{"H1", "разобрать"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := warningsFor(t, strings.Replace(etalonIface, c.from, c.to, 1))
			if len(got) != c.n {
				t.Fatalf("ожидалось %d предупреждений, получено %q", c.n, got)
			}
			all := strings.Join(got, "\n")
			for _, w := range c.want {
				if !strings.Contains(all, w) {
					t.Errorf("предупреждения %q не содержат %q", got, w)
				}
			}
		})
	}
}

// Разные S при хвостах: и S≥12 соблюдены, и S4 ≤ 32, — одно предупреждение о равенстве.
func TestInterfaceWarningsХвостыТребуютРавныхS(t *testing.T) {
	got := warningsFor(t, strings.Replace(etalonIface, "S1 = 27", "S1 = 30", 1))
	if len(got) != 1 || !strings.Contains(got[0], "равн") {
		t.Fatalf("ожидалось одно предупреждение о равенстве S, получено %q", got)
	}
}

// AWG 3.0 (хвостов нет): разные S и отсутствие CPA при хвостах не касаются.
func TestInterfaceWarningsБезХвостовНетТребованийКS(t *testing.T) {
	conf := strings.NewReplacer("RandomTrailers = on\n", "", "S1 = 27", "S1 = 30").Replace(etalonIface)
	if got := warningsFor(t, conf); len(got) != 0 {
		t.Fatalf("без хвостов разные S законны, получено %q", got)
	}
}
