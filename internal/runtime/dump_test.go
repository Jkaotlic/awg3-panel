package runtime_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// Реальный формат: первая строка — устройство, дальше по строке на пира,
// поля разделены табуляцией.
const sampleDump = "c2VydmVyLXByaXY=\tc2VydmVyLXB1Yg==\t51772\toff\n" +
	"bWUtcHVi\tbWUtcHNr\t198.51.100.10:59487\t10.11.0.2/32\t1754049600\t11400000\t2300000\toff\n" +
	"cGFwYS1wdWI=\tcGFwYS1wc2s=\t(none)\t10.11.0.3/32\t0\t0\t0\t25\n"

func TestParseDumpSkipsDeviceLine(t *testing.T) {
	peers, err := runtime.ParseDump(sampleDump)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("пиров %d, ожидалось 2", len(peers))
	}
}

func TestParseDumpFields(t *testing.T) {
	peers, _ := runtime.ParseDump(sampleDump)
	p := peers[0]
	if p.PublicKey != "bWUtcHVi" {
		t.Errorf("PublicKey = %q", p.PublicKey)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.11.0.2/32" {
		t.Errorf("AllowedIPs = %v", p.AllowedIPs)
	}
	if p.LatestHandshake != 1754049600 {
		t.Errorf("LatestHandshake = %d", p.LatestHandshake)
	}
	if p.RxBytes != 11400000 || p.TxBytes != 2300000 {
		t.Errorf("счётчики = %d/%d", p.RxBytes, p.TxBytes)
	}
	if peers[1].LatestHandshake != 0 {
		t.Errorf("второй пир: LatestHandshake = %d, ожидался 0", peers[1].LatestHandshake)
	}
}

func TestParseDumpMultipleAllowedIPs(t *testing.T) {
	line := "cHVi\t(none)\t(none)\t10.11.0.5/32,192.168.9.0/24\t0\t0\t0\toff\n"
	peers, err := runtime.ParseDump("dev\tdev\t1\toff\n" + line)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers[0].AllowedIPs) != 2 {
		t.Errorf("AllowedIPs = %v, ожидалось 2 элемента", peers[0].AllowedIPs)
	}
}

// Формат dump может обрасти полями в новых версиях amneziawg-tools —
// лишние поля не должны ломать разбор.
func TestParseDumpToleratesExtraTrailingFields(t *testing.T) {
	line := "cHVi\t(none)\t(none)\t10.11.0.5/32\t0\t0\t0\toff\textra\n"
	if _, err := runtime.ParseDump("dev\tdev\t1\toff\n" + line); err != nil {
		t.Fatalf("лишнее поле сломало разбор: %v", err)
	}
}

func TestParseDumpRejectsShortPeerLine(t *testing.T) {
	if _, err := runtime.ParseDump("dev\tdev\t1\toff\nmalo\tpoley\n"); err == nil {
		t.Fatal("ожидалась ошибка на укороченную строку пира")
	}
}

func TestParseDumpEmpty(t *testing.T) {
	peers, err := runtime.ParseDump("dev\tdev\t51772\toff\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Errorf("пиров %d, ожидалось 0", len(peers))
	}
	if _, err := runtime.ParseDump(""); err == nil {
		t.Fatal("ожидалась ошибка на пустой вывод")
	}
}

func TestParseDumpDevice(t *testing.T) {
	const line = "aPRIVATEkey=\tPL3d0QYzTLtbU7A/fZBsQk7diXIcv4ro5XkU/GO7Yg8=\t51772\toff\n" +
		"peerkey=\t(none)\t1.2.3.4:1111\t10.11.0.2/32\t1756000000\t10\t20\toff\n"
	d, err := runtime.ParseDumpDevice(line)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if d.PublicKey != "PL3d0QYzTLtbU7A/fZBsQk7diXIcv4ro5XkU/GO7Yg8=" {
		t.Errorf("PublicKey = %q", d.PublicKey)
	}
	if d.ListenPort != 51772 {
		t.Errorf("ListenPort = %d, ожидалось 51772", d.ListenPort)
	}
	if d.FWMark != "off" {
		t.Errorf("FWMark = %q", d.FWMark)
	}
}

// Приватный ключ устройства не должен доезжать ни до одного поля результата:
// структура, в которую его некуда положить, — это и есть гарантия.
func TestParseDumpDeviceДержитПриватныйКлючПриСебе(t *testing.T) {
	const priv = "SECRETSECRETSECRETSECRETSECRETSECRETSECRET="
	d, err := runtime.ParseDumpDevice(priv + "\tPUB=\t51772\toff\n")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", d), priv) {
		t.Fatalf("приватный ключ утёк в структуру: %+v", d)
	}
}

func TestParseDumpDeviceОшибки(t *testing.T) {
	cases := map[string]string{
		"пустой ввод":    "",
		"только пробелы": "   \n",
		"мало полей":     "priv=\tpub=\t51772\n",
		"порт не число":  "priv=\tpub=\tабв\toff\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := runtime.ParseDumpDevice(in); err == nil {
				t.Fatal("ожидалась ошибка, её нет")
			}
		})
	}
}
