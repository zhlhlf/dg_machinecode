package main

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const secret = "datagrand_license_copyright_9s^994f@)E"
const licensePassword = "DataGrand@123"

var licenseSalt = []byte{0xCE, 0xFB, 0xDE, 0xAC, 0x05, 0x02, 0x19, 0x71}

const licenseIterations = 2005

const certificateData = `
-----BEGIN CERTIFICATE-----
MIIFpjCCA44CCQDv9EJp51LS7DANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC
Q04xETAPBgNVBAgMCFNoYW5naGFpMREwDwYDVQQHDAhTaGFuZ2hhaTESMBAGA1UE
CgwJRGF0YUdyYW5kMQ0wCwYDVQQLDARUZWNoMRYwFAYDVQQDDA1kYXRhZ3JhbmQu
Y29tMSQwIgYJKoZIhvcNAQkBFhVjb250YWN0LmRhdGFncmFuZC5jb20wHhcNMTgx
MDI1MTI0MTA1WhcNMjgxMDIyMTI0MTA1WjCBlDELMAkGA1UEBhMCQ04xETAPBgNV
BAgMCFNoYW5naGFpMREwDwYDVQQHDAhTaGFuZ2hhaTESMBAGA1UECgwJRGF0YUdy
YW5kMQ0wCwYDVQQLDARUZWNoMRYwFAYDVQQDDA1kYXRhZ3JhbmQuY29tMSQwIgYJ
KoZIhvcNAQkBFhVjb250YWN0LmRhdGFncmFuZC5jb20wggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQC6x1YgHHYd3mUcOcQ34P82FHpJAdY+Xbz30dncCkh3
DKulY6dH7eSY5L2NIMUYbVEgTJE5kwMXTsVLtVlAcyuK7qUYyHhsUEKOpOQhoMly
AJq48/zIqAegbt4CWSqFOvntaqxU6rOZGAUPAKoxh/CQoqJHtK+Rjv9Yut5l7eco
omsTzeK25NdEhNxMu59twp3xW8U4cV5yV5i/6KsxniC4mrPc1sR+qygMBwDfLPQw
F+zH5TO2fYmIJX3/7UciYHjuVzomnXjxEJe12rntmRoU5cxai1WJ2MtZFGVmwDY5
GPMKuyzO51F+UYmV49zhugKhzHEK8NDBZz3dbo1MV7V61s8oreg9hRbOdcG7vaoR
SEFrY9SBAmw2UF2/eC8Cz7vLl4YdLF3fstvIHXWt51386/l4YVCyFtaTCV4jKtp3
KxKtysI4qmvGPVWw7WBXSrNwdyOdT3+Npta7iwfybDNNZh32ah9qUMUU6QLtzwr9
nnmIn/kTNJs9UZcnDq5SOvutb5gSAzvgDXo+6q/B9lJNY73YRo6WelbBlUEG7UdE
Mtkp1jmGTqAVSqAGRhNtubCmlL5K1uz/xQt0Jwbw4xTfqjxoHiK6WJDhl+LRKPYU
mm1aql77/P6ZZMdilPk8KwaTrl18qO0+gg9v18/hW5sk8mwN9FBtiw5ka+PTa4U7
VQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAO3siJnqtZQav2Wa8346rqn9Ax89jJ
c4LfuFTbJLM6h7Qb7t/lYDcUHECVhtl5KjG7uMWw12zz88OwrYxyAfPWl2MRzvOj
6hBdEvn7cA8er47vhxlRmTGiyF5qdMN7culf1j16RYH+5XB2nMlDeUD9a2B/4zo2
cO0IHNHyIMH3c8nACzfXmj19jKSRMcxjW1/86Cg/rEW7J1hECdUwIs+igyv3PRpN
gpCe0tsvBSWtPBmTycW0OLrT2y8E0HxflJ1Ty+y4qaHb4U4eCJ6e+tVAaF6qH6qv
Gr7qoF+3l7uyVsT23IYPu18eQfUbaD7WWcdpfXt8aQNTF+ZWKXpV+ZLaqJC18o9C
tmplCN4Kh5OOuBqZU3ocI1OfaFsnxfpYDv/HFlWnwjLEhP7QXsCVAWVEZbx3cB5u
f99kYeU4YNrGIBgX9B0rCZuArvDKTk82DM9DHqOVedfXuffAXXqq1MqQlDkPhki8
s0H1b+xJ2BMyRvhDT9d3SamMJWja/hbPXtf/xyGLYxPmo8prQkiSYS0oM8369utm
QPatlG4OvtVJadGkDXdJfJFs9Ees0odzit9X4wjFbKrtQTm7OuwOo9Z0Ij03r26p
7Nx1897gD+y8t2euCX0hmryqg+HR+bOSquluLJOuqBBLxUqLQQy/CiVN+nZP1JXi
YnQbyy8ekjbm3w==
-----END CERTIFICATE-----
`

type xmlJava struct {
	XMLName xml.Name  `xml:"java"`
	Object  xmlObject `xml:"object"`
}

type xmlObject struct {
	Class string    `xml:"class,attr"`
	Voids []xmlVoid `xml:"void"`
}

type xmlVoid struct {
	Property string      `xml:"property,attr"`
	String   *xmlString  `xml:"string"`
	Object   *xmlContent `xml:"object"`
	Long     *xmlString  `xml:"long"`
}

type xmlString struct {
	Text string `xml:",chardata"`
}

type xmlContent struct {
	Class  string     `xml:"class,attr"`
	String *xmlString `xml:"string"`
	Long   *xmlString `xml:"long"`
}

type licenseData struct {
	notBefore time.Time
	notAfter  time.Time
	extra     string
}

type extraData struct {
	MachineCodes    []string `json:"machine_codes"`
	SupportProducts []string `json:"support_products"`
}

// ---- machine code ----

func getUUID() string {
	if uuid := getLinuxUUID(); uuid != "" {
		return uuid
	}
	if uuid := getMachineID(); uuid != "" {
		return uuid
	}
	if uuid := getMacUUID(); uuid != "" {
		return uuid
	}
	return ""
}

func getLinuxUUID() string {
	var uuid_code string
	// try DMI product UUID
	data, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		uuid_code = strings.ToLower(strings.Join(strings.Split(strings.TrimSpace(string(data)), "-"), ""))
	} else {
		// fallback with sudo
		out, err := exec.Command("sh", "-c", `sudo cat /sys/class/dmi/id/product_uuid`).Output()
		if err == nil {
			uuid_code = strings.ToLower(strings.Join(strings.Split(strings.TrimSpace(string(out)), "-"), ""))
		}
	}
	return uuid_code
}

func getMachineID() string {
	var uuid_code string
	data, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		uuid_code = strings.ToLower(strings.Join(strings.Split(strings.TrimSpace(string(data)), "-"), ""))
	} else {
		out, err := exec.Command("sh", "-c", `sudo cat /etc/machine-id`).Output()
		if err == nil {
			uuid_code = strings.ToLower(strings.Join(strings.Split(strings.TrimSpace(string(out)), "-"), ""))
		}
	}
	return uuid_code
}

func getMacUUID() string {
	cmd := `sudo ioreg -rd1 -c IOPlatformExpertDevice | grep -E '(UUID)'`
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err == nil {
		s := strings.TrimSpace(string(out))
		if s != "" {
			parts := strings.Split(s, `"`)
			if len(parts) >= 2 {
				uuid := parts[len(parts)-2]
				uuid = strings.ToLower(strings.Join(strings.Split(uuid, "-"), ""))
				return uuid
			}
		}
	}
	return ""
}
// ---- license ----

func deriveKeyIV(password string) ([]byte, []byte) {
	keyiv := append([]byte(password), licenseSalt...)
	for i := 0; i < licenseIterations; i++ {
		h := md5.Sum(keyiv)
		keyiv = h[:]
	}
	return keyiv[:8], keyiv[8:16]
}

func unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty decrypted data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > 8 || padLen > len(data) {
		return nil, errors.New("invalid PKCS#5 padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid PKCS#5 padding")
		}
	}
	return data[:len(data)-padLen], nil
}

func decryptLicense(data []byte) ([]byte, error) {
	key, iv := deriveKeyIV(licensePassword)
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%block.BlockSize() != 0 {
		return nil, errors.New("encrypted data length is not a multiple of block size")
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data)
	return unpad(plain)
}

func gunzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

func parseProperties(o *xmlObject) map[string]*xmlVoid {
	props := make(map[string]*xmlVoid)
	for i := range o.Voids {
		v := &o.Voids[i]
		props[v.Property] = v
	}
	return props
}

func parseDate(v *xmlVoid) (time.Time, error) {
	if v.Object == nil || v.Object.Class != "java.util.Date" {
		return time.Time{}, errors.New("not a java.util.Date")
	}
	ms, err := strconv.ParseInt(strings.TrimSpace(v.Object.Long.Text), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(ms).UTC(), nil
}

func parseExtra(v *xmlVoid) (string, error) {
	if v.String == nil {
		return "", errors.New("extra is not a string")
	}
	return strings.TrimSpace(v.String.Text), nil
}

func verifyLicenseSignature(encoded, signature, sigAlg string) error {
	block, _ := pem.Decode([]byte(certificateData))
	if block == nil {
		return errors.New("invalid certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("certificate key is not RSA")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	digestName := strings.ToUpper(strings.SplitN(sigAlg, "with", 2)[0])
	var hash crypto.Hash
	switch digestName {
	case "SHA1":
		hash = crypto.SHA1
	case "SHA256":
		hash = crypto.SHA256
	case "SHA384":
		hash = crypto.SHA384
	case "SHA512":
		hash = crypto.SHA512
	default:
		return errors.New("unsupported signature algorithm: " + sigAlg)
	}
	if !hash.Available() {
		return errors.New("hash not available")
	}
	h := hash.New()
	h.Write([]byte(encoded))
	if err := rsa.VerifyPKCS1v15(pub, hash, h.Sum(nil), sig); err != nil {
		return errors.New("license is illegal, contact DataGrand")
	}
	return nil
}

func loadLicense(path string) (*licenseData, *extraData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	decrypted, err := decryptLicense(raw)
	if err != nil {
		return nil, nil, err
	}
	xmlData, err := gunzip(decrypted)
	if err != nil {
		return nil, nil, err
	}

	var doc xmlJava
	if err := xml.Unmarshal(xmlData, &doc); err != nil {
		return nil, nil, err
	}
	beanProps := parseProperties(&doc.Object)

	encoded := ""
	signature := ""
	sigAlg := ""
	if v := beanProps["encoded"]; v != nil && v.String != nil {
		encoded = strings.TrimSpace(v.String.Text)
	}
	if v := beanProps["signature"]; v != nil && v.String != nil {
		signature = strings.TrimSpace(v.String.Text)
	}
	if v := beanProps["signatureAlgorithm"]; v != nil && v.String != nil {
		sigAlg = strings.TrimSpace(v.String.Text)
	}
	if encoded == "" || signature == "" {
		return nil, nil, errors.New("invalid license bean")
	}
	if sigAlg == "" {
		sigAlg = "SHA1withRSA"
	}
	if err := verifyLicenseSignature(encoded, signature, sigAlg); err != nil {
		return nil, nil, err
	}

	var inner xmlJava
	if err := xml.Unmarshal([]byte(encoded), &inner); err != nil {
		return nil, nil, err
	}
	contentProps := parseProperties(&inner.Object)

	ld := &licenseData{}
	if v := contentProps["notBefore"]; v != nil {
		ld.notBefore, err = parseDate(v)
		if err != nil {
			return nil, nil, err
		}
	}
	if v := contentProps["notAfter"]; v != nil {
		ld.notAfter, err = parseDate(v)
		if err != nil {
			return nil, nil, err
		}
	}
	if v := contentProps["extra"]; v != nil {
		ld.extra, err = parseExtra(v)
		if err != nil {
			return nil, nil, err
		}
	}

	ex := &extraData{}
	if ld.extra != "" {
		if err := json.Unmarshal([]byte(ld.extra), ex); err != nil {
			return nil, nil, err
		}
	}
	return ld, ex, nil
}

func pyDateTime(t time.Time) string {
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02 15:04:05")
	}
	return t.Format("2006-01-02 15:04:05.000000")
}

func pyList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = "'" + s + "'"
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func printLicenseInfo(ld *licenseData, ex *extraData) {
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("%s - %s\n", pyDateTime(ld.notBefore), pyDateTime(ld.notAfter))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println(strings.Join(ex.MachineCodes, ","))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println(pyList(ex.MachineCodes))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println(strings.Join(ex.SupportProducts, ","))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println(pyList(ex.SupportProducts))
	fmt.Println(strings.Repeat("=", 50))
}

func printLicense(path string) error {
	ld, ex, err := loadLicense(path)
	if err != nil {
		return err
	}
	printLicenseInfo(ld, ex)
	return nil
}

func main() {
	if len(os.Args) > 1 {
		if err := printLicense(os.Args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	uuid := getUUID()
	if uuid == "" {
		os.Exit(1)
	}
	h := md5.Sum([]byte(uuid + secret))
	os.Stdout.WriteString(hex.EncodeToString(h[:]))
}
