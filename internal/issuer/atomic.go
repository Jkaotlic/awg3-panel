package issuer

import (
	"github.com/Jkaotlic/awg3-panel/internal/atomicfile"
)

// writeFileAtomic0600 пишет body в path через временный файл в том же
// каталоге и rename: читатель никогда не увидит частично записанный файл.
// Временный файл получает права 0600 до переименования, так что итоговый
// файл ни на мгновение не оказывается доступен шире, чем 0600 — это важно
// и для конфига (apply.go), и для приватных ключей клиентов (KeyStore).
func writeFileAtomic0600(path, body string) error {
	return atomicfile.Write(path, []byte(body), 0o600)
}
