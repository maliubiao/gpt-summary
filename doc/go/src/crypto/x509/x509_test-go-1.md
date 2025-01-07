Response:
The user has provided a Go code snippet from `go/src/crypto/x509/x509_test.go` and wants to understand its functionality. This is part 2 of a 6-part series, and the goal is to summarize the functionality of this specific part.

Based on the code, this section primarily focuses on testing the correct copying of various fields from a certificate template to a newly created certificate. It also includes tests for parsing certificates with different signature algorithms (ECDSA, DSA, RSAPSS, Ed25519) and verifying their signatures. Furthermore, it contains tests related to Certificate Revocation Lists (CRLs), including their creation and parsing.

Therefore, the functionality of this part can be summarized as: **Testing the correct copying of certificate template fields, parsing of certificates with various signature algorithms, signature verification, and CRL creation and parsing.**
这是 Go 语言 `crypto/x509` 包的测试文件 `x509_test.go` 的一部分，主要功能是 **测试证书创建过程中模板字段的正确复制**。

**功能归纳：**

这个代码片段主要测试了使用 `CreateCertificate` 函数创建证书时，能否正确地将模板（`template`）中的各种字段复制到新创建的证书（`cert`）中。它针对 `BasicConstraints`、`SignatureAlgorithm`、`ExtKeyUsage`、`UnknownExtKeyUsage`、`OCSPServer`、`IssuingCertificateURL`、`DNSNames`、`EmailAddresses`、`URIs`、`IPAddresses`、`CRLDistributionPoints` 等字段进行了逐一的对比验证。 此外，它还测试了 `ExtraExtensions` 是否能覆盖某些默认字段，以及生成的 DER 编码中是否包含预期的额外扩展。最后，它还测试了自签名证书的签名验证功能。

**代码推理举例：**

以下代码展示了如何使用 `CreateCertificate` 函数并验证字段是否正确复制。

```go
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"time"
)

func main() {
	// 假设我们有一个用于签名的私钥
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("生成私钥失败:", err)
		return
	}

	// 假设我们有一个证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://cacerts.example.com/ca.crt"},
		DNSNames:              []string{"example.com", "www.example.com"},
		EmailAddresses:        []string{"test@example.com"},
		URIs:                  []*url.URL{&url.URL{Scheme: "https", Host: "example.com", Path: "/resource"}},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
		CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
	}

	// 假设我们有一个用于签名的父证书（自签名场景）
	parent := template

	// 创建证书
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, priv)
	if err != nil {
		fmt.Println("创建证书失败:", err)
		return
	}

	// 解析创建的证书
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		fmt.Println("解析证书失败:", err)
		return
	}

	// 验证字段是否被正确复制
	if cert.SignatureAlgorithm != template.SignatureAlgorithm {
		fmt.Printf("SignatureAlgorithm 不匹配: Got %v, Want %v\n", cert.SignatureAlgorithm, template.SignatureAlgorithm)
	}
	if !slices.Equal(cert.DNSNames, template.DNSNames) {
		fmt.Printf("DNSNames 不匹配: Got %v, Want %v\n", cert.DNSNames, template.DNSNames)
	}
	// ... 可以添加更多字段的对比
	fmt.Println("证书字段复制验证完成")
}
```

**假设的输入与输出：**

**输入：** 一个包含各种字段的 `x509.Certificate` 类型的 `template` 变量，以及一个用于签名的私钥。

**输出：**  `x509.CreateCertificate` 函数会返回一个包含证书 DER 编码的字节切片。经过 `x509.ParseCertificate` 解析后，得到的 `*x509.Certificate` 类型的 `cert` 变量中的各个字段值应该与 `template` 中的对应字段值相同。如果字段复制不正确，测试代码中的 `t.Errorf` 会报告错误。

**使用者易犯错的点：**

使用者在使用 `CreateCertificate` 函数时，容易犯的错误是 **没有正确设置模板中的字段**。如果模板中的某些字段为空或者设置了不期望的值，那么生成的证书也会包含这些不正确的值。 例如：

```go
// 错误的示例：忘记设置 DNSNames
template := &x509.Certificate{
    // ... 其他字段
}

// 创建的证书的 DNSNames 也会为空
certBytes, _ := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, priv)
cert, _ := x509.ParseCertificate(certBytes)
if len(cert.DNSNames) != 0 { // 这是一个错误
    fmt.Println("DNSNames 不应该存在")
}
```

这个代码片段的主要目的是确保 `crypto/x509` 包中的证书创建功能能够按照预期工作，正确地从提供的模板中复制所需的证书属性。

Prompt: 
```
这是路径为go/src/crypto/x509/x509_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共6部分，请归纳一下它的功能

"""
		t.Errorf("%s: SignatureAlgorithm wasn't copied from template. Got %v, want %v", test.name, cert.SignatureAlgorithm, test.sigAlgo)
		}

		if !slices.Equal(cert.ExtKeyUsage, testExtKeyUsage) {
			t.Errorf("%s: extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.ExtKeyUsage, testExtKeyUsage)
		}

		if !slices.EqualFunc(cert.UnknownExtKeyUsage, testUnknownExtKeyUsage, asn1.ObjectIdentifier.Equal) {
			t.Errorf("%s: unknown extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.UnknownExtKeyUsage, testUnknownExtKeyUsage)
		}

		if !slices.Equal(cert.OCSPServer, template.OCSPServer) {
			t.Errorf("%s: OCSP servers differ from template. Got %v, want %v", test.name, cert.OCSPServer, template.OCSPServer)
		}

		if !slices.Equal(cert.IssuingCertificateURL, template.IssuingCertificateURL) {
			t.Errorf("%s: Issuing certificate URLs differ from template. Got %v, want %v", test.name, cert.IssuingCertificateURL, template.IssuingCertificateURL)
		}

		if !slices.Equal(cert.DNSNames, template.DNSNames) {
			t.Errorf("%s: SAN DNS names differ from template. Got %v, want %v", test.name, cert.DNSNames, template.DNSNames)
		}

		if !slices.Equal(cert.EmailAddresses, template.EmailAddresses) {
			t.Errorf("%s: SAN emails differ from template. Got %v, want %v", test.name, cert.EmailAddresses, template.EmailAddresses)
		}

		if len(cert.URIs) != 1 || cert.URIs[0].String() != "https://foo.com/wibble#foo" {
			t.Errorf("%s: URIs differ from template. Got %v, want %v", test.name, cert.URIs, template.URIs)
		}

		if !slices.EqualFunc(cert.IPAddresses, template.IPAddresses, net.IP.Equal) {
			t.Errorf("%s: SAN IPs differ from template. Got %v, want %v", test.name, cert.IPAddresses, template.IPAddresses)
		}

		if !slices.Equal(cert.CRLDistributionPoints, template.CRLDistributionPoints) {
			t.Errorf("%s: CRL distribution points differ from template. Got %v, want %v", test.name, cert.CRLDistributionPoints, template.CRLDistributionPoints)
		}

		if !bytes.Equal(cert.SubjectKeyId, []byte{4, 3, 2, 1}) {
			t.Errorf("%s: ExtraExtensions didn't override SubjectKeyId", test.name)
		}

		if !bytes.Contains(derBytes, extraExtensionData) {
			t.Errorf("%s: didn't find extra extension in DER output", test.name)
		}

		if test.checkSig {
			err = cert.CheckSignatureFrom(cert)
			if err != nil {
				t.Errorf("%s: signature verification failed: %s", test.name, err)
			}
		}
	}
}

// Self-signed certificate using ECDSA with SHA1 & secp256r1
var ecdsaSHA1CertPem = `
-----BEGIN CERTIFICATE-----
MIICDjCCAbUCCQDF6SfN0nsnrjAJBgcqhkjOPQQBMIGPMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMG
A1UECgwMR29vZ2xlLCBJbmMuMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIwMjAyMDUw
WhcNMjIwNTE4MjAyMDUwWjCBjzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwg
SW5jLjEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20xIzAhBgkqhkiG9w0BCQEWFGdv
bGFuZy1kZXZAZ21haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/Wgn
WQDo5+bz71T0327ERgd5SDDXFbXLpzIZDXTkjpe8QTEbsF+ezsQfrekrpDPC4Cd3
P9LY0tG+aI8IyVKdUjAJBgcqhkjOPQQBA0gAMEUCIGlsqMcRqWVIWTD6wXwe6Jk2
DKxL46r/FLgJYnzBEH99AiEA3fBouObsvV1R3oVkb4BQYnD4/4LeId6lAT43YvyV
a/A=
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA256 & secp256r1
var ecdsaSHA256p256CertPem = `
-----BEGIN CERTIFICATE-----
MIICDzCCAbYCCQDlsuMWvgQzhTAKBggqhkjOPQQDAjCBjzELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20xIzAh
BgkqhkiG9w0BCQEWFGdvbGFuZy1kZXZAZ21haWwuY29tMB4XDTEyMDUyMTAwMTkx
NloXDTIyMDUxOTAwMTkxNlowgY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxp
Zm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUs
IEluYy4xFzAVBgNVBAMMDnd3dy5nb29nbGUuY29tMSMwIQYJKoZIhvcNAQkBFhRn
b2xhbmctZGV2QGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPMt
2ErhxAty5EJRu9yM+MTy+hUXm3pdW1ensAv382KoGExSXAFWP7pjJnNtHO+XSwVm
YNtqjcAGFKpweoN//kQwCgYIKoZIzj0EAwIDRwAwRAIgIYSaUA/IB81gjbIw/hUV
70twxJr5EcgOo0hLp3Jm+EYCIFDO3NNcgmURbJ1kfoS3N/0O+irUtoPw38YoNkqJ
h5wi
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA256 & secp384r1
var ecdsaSHA256p384CertPem = `
-----BEGIN CERTIFICATE-----
MIICSjCCAdECCQDje/no7mXkVzAKBggqhkjOPQQDAjCBjjELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDAS
BgNVBAoMC0dvb2dsZSwgSW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIxMDYxMDM0
WhcNMjIwNTE5MDYxMDM0WjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDASBgNVBAoMC0dvb2dsZSwg
SW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEGCSqGSIb3DQEJARYUZ29s
YW5nLWRldkBnbWFpbC5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARRuzRNIKRK
jIktEmXanNmrTR/q/FaHXLhWRZ6nHWe26Fw7Rsrbk+VjGy4vfWtNn7xSFKrOu5ze
qxKnmE0h5E480MNgrUiRkaGO2GMJJVmxx20aqkXOk59U8yGA4CghE6MwCgYIKoZI
zj0EAwIDZwAwZAIwBZEN8gvmRmfeP/9C1PRLzODIY4JqWub2PLRT4mv9GU+yw3Gr
PU9A3CHMdEcdw/MEAjBBO1lId8KOCh9UZunsSMfqXiVurpzmhWd6VYZ/32G+M+Mh
3yILeYQzllt/g0rKVRk=
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA384 & secp521r1
var ecdsaSHA384p521CertPem = `
-----BEGIN CERTIFICATE-----
MIICljCCAfcCCQDhp1AFD/ahKjAKBggqhkjOPQQDAzCBjjELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDAS
BgNVBAoMC0dvb2dsZSwgSW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIxMTUwNDI5
WhcNMjIwNTE5MTUwNDI5WjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDASBgNVBAoMC0dvb2dsZSwg
SW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEGCSqGSIb3DQEJARYUZ29s
YW5nLWRldkBnbWFpbC5jb20wgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABACqx9Rv
IssRs1LWYcNN+WffwlHw4Tv3y8/LIAA9MF1ZScIonU9nRMxt4a2uGJVCPDw6JHpz
PaYc0E9puLoE9AfKpwFr59Jkot7dBg55SKPEFkddoip/rvmN7NPAWjMBirOwjOkm
8FPthvPhGPqsu9AvgVuHu3PosWiHGNrhh379pva8MzAKBggqhkjOPQQDAwOBjAAw
gYgCQgEHNmswkUdPpHqrVxp9PvLVl+xxPuHBkT+75z9JizyxtqykHQo9Uh6SWCYH
BF9KLolo01wMt8DjoYP5Fb3j5MH7xwJCAbWZzTOp4l4DPkIvAh4LeC4VWbwPPyqh
kBg71w/iEcSY3wUKgHGcJJrObZw7wys91I5kENljqw/Samdr3ka+jBJa
-----END CERTIFICATE-----
`

var ecdsaTests = []struct {
	sigAlgo SignatureAlgorithm
	pemCert string
}{
	{ECDSAWithSHA256, ecdsaSHA256p256CertPem},
	{ECDSAWithSHA256, ecdsaSHA256p384CertPem},
	{ECDSAWithSHA384, ecdsaSHA384p521CertPem},
}

func TestECDSA(t *testing.T) {
	for i, test := range ecdsaTests {
		pemBlock, _ := pem.Decode([]byte(test.pemCert))
		cert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		if sa := cert.SignatureAlgorithm; sa != test.sigAlgo {
			t.Errorf("%d: signature algorithm is %v, want %v", i, sa, test.sigAlgo)
		}
		if parsedKey, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			t.Errorf("%d: wanted an ECDSA public key but found: %#v", i, parsedKey)
		}
		if pka := cert.PublicKeyAlgorithm; pka != ECDSA {
			t.Errorf("%d: public key algorithm is %v, want ECDSA", i, pka)
		}
		if err = cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("%d: certificate verification failed: %s", i, err)
		}
	}
}

// Self-signed certificate using DSA with SHA1
var dsaCertPem = `-----BEGIN CERTIFICATE-----
MIIEDTCCA82gAwIBAgIJALHPghaoxeDhMAkGByqGSM44BAMweTELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAk5DMQ8wDQYDVQQHEwZOZXd0b24xFDASBgNVBAoTC0dvb2ds
ZSwgSW5jMRIwEAYDVQQDEwlKb24gQWxsaWUxIjAgBgkqhkiG9w0BCQEWE2pvbmFs
bGllQGdvb2dsZS5jb20wHhcNMTEwNTE0MDMwMTQ1WhcNMTEwNjEzMDMwMTQ1WjB5
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCTkMxDzANBgNVBAcTBk5ld3RvbjEUMBIG
A1UEChMLR29vZ2xlLCBJbmMxEjAQBgNVBAMTCUpvbiBBbGxpZTEiMCAGCSqGSIb3
DQEJARYTam9uYWxsaWVAZ29vZ2xlLmNvbTCCAbcwggEsBgcqhkjOOAQBMIIBHwKB
gQC8hLUnQ7FpFYu4WXTj6DKvXvz8QrJkNJCVMTpKAT7uBpobk32S5RrPKXocd4gN
8lyGB9ggS03EVlEwXvSmO0DH2MQtke2jl9j1HLydClMf4sbx5V6TV9IFw505U1iW
jL7awRMgxge+FsudtJK254FjMFo03ZnOQ8ZJJ9E6AEDrlwIVAJpnBn9moyP11Ox5
Asc/5dnjb6dPAoGBAJFHd4KVv1iTVCvEG6gGiYop5DJh28hUQcN9kul+2A0yPUSC
X93oN00P8Vh3eYgSaCWZsha7zDG53MrVJ0Zf6v/X/CoZNhLldeNOepivTRAzn+Rz
kKUYy5l1sxYLHQKF0UGNCXfFKZT0PCmgU+PWhYNBBMn6/cIh44vp85ideo5CA4GE
AAKBgFmifCafzeRaohYKXJgMGSEaggCVCRq5xdyDCat+wbOkjC4mfG01/um3G8u5
LxasjlWRKTR/tcAL7t0QuokVyQaYdVypZXNaMtx1db7YBuHjj3aP+8JOQRI9xz8c
bp5NDJ5pISiFOv4p3GZfqZPcqckDt78AtkQrmnal2txhhjF6o4HeMIHbMB0GA1Ud
DgQWBBQVyyr7hO11ZFFpWX50298Sa3V+rzCBqwYDVR0jBIGjMIGggBQVyyr7hO11
ZFFpWX50298Sa3V+r6F9pHsweTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk5DMQ8w
DQYDVQQHEwZOZXd0b24xFDASBgNVBAoTC0dvb2dsZSwgSW5jMRIwEAYDVQQDEwlK
b24gQWxsaWUxIjAgBgkqhkiG9w0BCQEWE2pvbmFsbGllQGdvb2dsZS5jb22CCQCx
z4IWqMXg4TAMBgNVHRMEBTADAQH/MAkGByqGSM44BAMDLwAwLAIUPtn/5j8Q1jJI
7ggOIsgrhgUdjGQCFCsmDq1H11q9+9Wp9IMeGrTSKHIM
-----END CERTIFICATE-----
`

func TestParseCertificateWithDsaPublicKey(t *testing.T) {
	expectedKey := &dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: bigFromHexString("00BC84B52743B169158BB85974E3E832AF5EFCFC42B264349095313A4A013EEE069A1B937D92E51ACF297A1C77880DF25C8607D8204B4DC45651305EF4A63B40C7D8C42D91EDA397D8F51CBC9D0A531FE2C6F1E55E9357D205C39D395358968CBEDAC11320C607BE16CB9DB492B6E78163305A34DD99CE43C64927D13A0040EB97"),
			Q: bigFromHexString("009A67067F66A323F5D4EC7902C73FE5D9E36FA74F"),
			G: bigFromHexString("009147778295BF5893542BC41BA806898A29E43261DBC85441C37D92E97ED80D323D44825FDDE8374D0FF15877798812682599B216BBCC31B9DCCAD527465FEAFFD7FC2A193612E575E34E7A98AF4D10339FE47390A518CB9975B3160B1D0285D1418D0977C52994F43C29A053E3D685834104C9FAFDC221E38BE9F3989D7A8E42"),
		},
		Y: bigFromHexString("59A27C269FCDE45AA2160A5C980C19211A820095091AB9C5DC8309AB7EC1B3A48C2E267C6D35FEE9B71BCBB92F16AC8E559129347FB5C00BEEDD10BA8915C90698755CA965735A32DC7575BED806E1E38F768FFBC24E41123DC73F1C6E9E4D0C9E692128853AFE29DC665FA993DCA9C903B7BF00B6442B9A76A5DADC6186317A"),
	}
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	if cert.PublicKeyAlgorithm != DSA {
		t.Errorf("Parsed key algorithm was not DSA")
	}
	parsedKey, ok := cert.PublicKey.(*dsa.PublicKey)
	if !ok {
		t.Fatalf("Parsed key was not a DSA key: %s", err)
	}
	if expectedKey.Y.Cmp(parsedKey.Y) != 0 ||
		expectedKey.P.Cmp(parsedKey.P) != 0 ||
		expectedKey.Q.Cmp(parsedKey.Q) != 0 ||
		expectedKey.G.Cmp(parsedKey.G) != 0 {
		t.Fatal("Parsed key differs from expected key")
	}
}

func TestParseCertificateWithDSASignatureAlgorithm(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	if cert.SignatureAlgorithm != DSAWithSHA1 {
		t.Errorf("Parsed signature algorithm was not DSAWithSHA1")
	}
}

func TestVerifyCertificateWithDSASignature(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	// test cert is self-signed
	if err = cert.CheckSignatureFrom(cert); err == nil {
		t.Fatalf("Expected error verifying DSA certificate")
	}
}

var rsaPSSSelfSignedPEM = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

// openssl req -newkey rsa:2048 -keyout test.key -sha256 -sigopt \
// rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 \
// -x509 -days 3650 -nodes -subj '/C=US/ST=CA/L=SF/O=Test/CN=Test' -out \
// test.pem
var rsaPSSSelfSignedOpenSSL110PEM = `-----BEGIN CERTIFICATE-----
MIIDwDCCAnigAwIBAgIJAM9LAMHTE5xpMD0GCSqGSIb3DQEBCjAwoA0wCwYJYIZI
AWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIDAgEgMEUxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTELMAkGA1UEBwwCU0YxDTALBgNVBAoMBFRlc3Qx
DTALBgNVBAMMBFRlc3QwHhcNMTgwMjIyMjIxMzE4WhcNMjgwMjIwMjIxMzE4WjBF
MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExCzAJBgNVBAcMAlNGMQ0wCwYDVQQK
DARUZXN0MQ0wCwYDVQQDDARUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA4Zrsydod+GoTAJLLutWNF87qhhVPBsK1zB1Gj+NAAe4+VbrZ1E41H1wp
qITx7DA8DRtJEf+NqrTAnAdZWBG/tAOA5LfXVax0ZSQtLnYLSeylLoMtDyY3eFAj
TmuTOoyVy6raktowCnHCh01NsstqqTfrx6SbmzOmDmKTkq/I+7K0MCVsn41xRDVM
+ShD0WGFGioEGoiWnFSWupxJDA3Q6jIDEygVwNKHwnhv/2NgG2kqZzrZSQA67en0
iKAXtoDNPpmyD5oS9YbEJ+2Nbm7oLeON30i6kZvXKIzJXx+UWViazHZqnsi5rQ8G
RHF+iVFXsqd0MzDKmkKOT5FDhrsbKQIDAQABo1MwUTAdBgNVHQ4EFgQU9uFY/nlg
gLH00NBnr/o7QvpN9ugwHwYDVR0jBBgwFoAU9uFY/nlggLH00NBnr/o7QvpN9ugw
DwYDVR0TAQH/BAUwAwEB/zA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAaEa
MBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgGiAwIBIAOCAQEAhJzpwxBNGKvzKWDe
WLqv6RMrl/q4GcH3b7M9wjxe0yOm4F+Tb2zJ7re4h+D39YkJf8cX1NV9UQVu6z4s
Fvo2kmlR0qZOXAg5augmCQ1xS0WHFoF6B52anNzHkZQbAIYJ3kGoFsUHzs7Sz7F/
656FsRpHA9UzJQ3avPPMrA4Y4aoJ7ANJ6XIwTrdWrhULOVuvYRLCl4CdTVztVFX6
wxX8nS1ISYd8jXPUMgsBKVbWufvLoIymMJW8CZbpprVZel5zFn0bmPrON8IHS30w
Gs+ITJjKEnZgXmAQ25SLKVzkZkBcGANs2GsdHNJ370Puisy0FIPD2NXR5uASAf7J
+w9fjQ==
-----END CERTIFICATE-----`

func TestRSAPSSSelfSigned(t *testing.T) {
	for i, pemBlock := range []string{rsaPSSSelfSignedPEM, rsaPSSSelfSignedOpenSSL110PEM} {
		der, _ := pem.Decode([]byte(pemBlock))
		if der == nil {
			t.Errorf("#%d: failed to find PEM block", i)
			continue
		}

		cert, err := ParseCertificate(der.Bytes)
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		if err = cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("#%d: signature check failed: %s", i, err)
			continue
		}
	}
}

const ed25519Certificate = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0c:83:d8:21:2b:82:cb:23:98:23:63:e2:f7:97:8a:43:5b:f3:bd:92
        Signature Algorithm: ED25519
        Issuer: CN = Ed25519 test certificate
        Validity
            Not Before: May  6 17:27:16 2019 GMT
            Not After : Jun  5 17:27:16 2019 GMT
        Subject: CN = Ed25519 test certificate
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    36:29:c5:6c:0d:4f:14:6c:81:d0:ff:75:d3:6a:70:
                    5f:69:cd:0f:4d:66:d5:da:98:7e:82:49:89:a3:8a:
                    3c:fa
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                09:3B:3A:9D:4A:29:D8:95:FF:68:BE:7B:43:54:72:E0:AD:A2:E3:AE
            X509v3 Authority Key Identifier:
                keyid:09:3B:3A:9D:4A:29:D8:95:FF:68:BE:7B:43:54:72:E0:AD:A2:E3:AE

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: ED25519
         53:a5:58:1c:2c:3b:2a:9e:ac:9d:4e:a5:1d:5f:5d:6d:a6:b5:
         08:de:12:82:f3:97:20:ae:fa:d8:98:f4:1a:83:32:6b:91:f5:
         24:1d:c4:20:7f:2c:e2:4d:da:13:3b:6d:54:1a:d2:a8:28:dc:
         60:b9:d4:f4:78:4b:3c:1c:91:00
-----BEGIN CERTIFICATE-----
MIIBWzCCAQ2gAwIBAgIUDIPYISuCyyOYI2Pi95eKQ1vzvZIwBQYDK2VwMCMxITAf
BgNVBAMMGEVkMjU1MTkgdGVzdCBjZXJ0aWZpY2F0ZTAeFw0xOTA1MDYxNzI3MTZa
Fw0xOTA2MDUxNzI3MTZaMCMxITAfBgNVBAMMGEVkMjU1MTkgdGVzdCBjZXJ0aWZp
Y2F0ZTAqMAUGAytlcAMhADYpxWwNTxRsgdD/ddNqcF9pzQ9NZtXamH6CSYmjijz6
o1MwUTAdBgNVHQ4EFgQUCTs6nUop2JX/aL57Q1Ry4K2i464wHwYDVR0jBBgwFoAU
CTs6nUop2JX/aL57Q1Ry4K2i464wDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQBT
pVgcLDsqnqydTqUdX11tprUI3hKC85cgrvrYmPQagzJrkfUkHcQgfyziTdoTO21U
GtKoKNxgudT0eEs8HJEA
-----END CERTIFICATE-----`

func TestEd25519SelfSigned(t *testing.T) {
	der, _ := pem.Decode([]byte(ed25519Certificate))
	if der == nil {
		t.Fatalf("Failed to find PEM block")
	}

	cert, err := ParseCertificate(der.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse: %s", err)
	}

	if cert.PublicKeyAlgorithm != Ed25519 {
		t.Fatalf("Parsed key algorithm was not Ed25519")
	}
	parsedKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("Parsed key was not an Ed25519 key: %s", err)
	}
	if len(parsedKey) != ed25519.PublicKeySize {
		t.Fatalf("Invalid Ed25519 key")
	}

	if err = cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("Signature check failed: %s", err)
	}
}

const pemCertificate = `-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIRAKQkkrFx1T/dgB/Go/xBM5swDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjA4MTcyMDM2MDdaFw0xNzA4MTcyMDM2
MDdaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDAoJtjG7M6InsWwIo+l3qq9u+g2rKFXNu9/mZ24XQ8XhV6PUR+5HQ4
jUFWC58ExYhottqK5zQtKGkw5NuhjowFUgWB/VlNGAUBHtJcWR/062wYrHBYRxJH
qVXOpYKbIWwFKoXu3hcpg/CkdOlDWGKoZKBCwQwUBhWE7MDhpVdQ+ZljUJWL+FlK
yQK5iRsJd5TGJ6VUzLzdT4fmN2DzeK6GLeyMpVpU3sWV90JJbxWQ4YrzkKzYhMmB
EcpXTG2wm+ujiHU/k2p8zlf8Sm7VBM/scmnMFt0ynNXop4FWvJzEm1G0xD2t+e2I
5Utr04dOZPCgkm++QJgYhtZvgW7ZZiGTAgMBAAGjUjBQMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBsGA1UdEQQUMBKC
EHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBADpqKQxrthH5InC7
X96UP0OJCu/lLEMkrjoEWYIQaFl7uLPxKH5AmQPH4lYwF7u7gksR7owVG9QU9fs6
1fK7II9CVgCd/4tZ0zm98FmU4D0lHGtPARrrzoZaqVZcAvRnFTlPX5pFkPhVjjai
/mkxX9LpD8oK1445DFHxK5UjLMmPIIWd8EOi+v5a+hgGwnJpoW7hntSl8kHMtTmy
fnnktsblSUV4lRCit0ymC7Ojhe+gzCCwkgs5kDzVVag+tnl/0e2DloIjASwOhpbH
KVcg7fBd484ht/sS+l0dsB4KDOSpd8JzVDMF8OZqlaydizoJO0yWr9GbCN1+OKq5
EhLrEqU=
-----END CERTIFICATE-----`

const ed25519CRLCertificate = `
Certificate:
Data:
	Version: 3 (0x2)
	Serial Number:
		7a:07:a0:9d:14:04:16:fc:1f:d8:e5:fe:d1:1d:1f:8d
	Signature Algorithm: ED25519
	Issuer: CN = Ed25519 CRL Test CA
	Validity
		Not Before: Oct 30 01:20:20 2019 GMT
		Not After : Dec 31 23:59:59 9999 GMT
	Subject: CN = Ed25519 CRL Test CA
	Subject Public Key Info:
		Public Key Algorithm: ED25519
			ED25519 Public-Key:
			pub:
				95:73:3b:b0:06:2a:31:5a:b6:a7:a6:6e:ef:71:df:
				ac:6f:6b:39:03:85:5e:63:4b:f8:a6:0f:68:c6:6f:
				75:21
	X509v3 extensions:
		X509v3 Key Usage: critical
			Digital Signature, Certificate Sign, CRL Sign
		X509v3 Extended Key Usage:
			TLS Web Client Authentication, TLS Web Server Authentication, OCSP Signing
		X509v3 Basic Constraints: critical
			CA:TRUE
		X509v3 Subject Key Identifier:
			B7:17:DA:16:EA:C5:ED:1F:18:49:44:D3:D2:E3:A0:35:0A:81:93:60
		X509v3 Authority Key Identifier:
			keyid:B7:17:DA:16:EA:C5:ED:1F:18:49:44:D3:D2:E3:A0:35:0A:81:93:60

Signature Algorithm: ED25519
	 fc:3e:14:ea:bb:70:c2:6f:38:34:70:bc:c8:a7:f4:7c:0d:1e:
	 28:d7:2a:9f:22:8a:45:e8:02:76:84:1e:2d:64:2d:1e:09:b5:
	 29:71:1f:95:8a:4e:79:87:51:60:9a:e7:86:40:f6:60:c7:d1:
	 ee:68:76:17:1d:90:cc:92:93:07
-----BEGIN CERTIFICATE-----
MIIBijCCATygAwIBAgIQegegnRQEFvwf2OX+0R0fjTAFBgMrZXAwHjEcMBoGA1UE
AxMTRWQyNTUxOSBDUkwgVGVzdCBDQTAgFw0xOTEwMzAwMTIwMjBaGA85OTk5MTIz
MTIzNTk1OVowHjEcMBoGA1UEAxMTRWQyNTUxOSBDUkwgVGVzdCBDQTAqMAUGAytl
cAMhAJVzO7AGKjFatqembu9x36xvazkDhV5jS/imD2jGb3Uho4GNMIGKMA4GA1Ud
DwEB/wQEAwIBhjAnBgNVHSUEIDAeBggrBgEFBQcDAgYIKwYBBQUHAwEGCCsGAQUF
BwMJMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLcX2hbqxe0fGElE09LjoDUK
gZNgMB8GA1UdIwQYMBaAFLcX2hbqxe0fGElE09LjoDUKgZNgMAUGAytlcANBAPw+
FOq7cMJvODRwvMin9HwNHijXKp8iikXoAnaEHi1kLR4JtSlxH5WKTnmHUWCa54ZA
9mDH0e5odhcdkMySkwc=
-----END CERTIFICATE-----`

var ed25519CRLKey = testingKey(`-----BEGIN TEST KEY-----
MC4CAQAwBQYDK2VwBCIEINdKh2096vUBYu4EIFpjShsUSh3vimKya1sQ1YTT4RZG
-----END TEST KEY-----`)

func TestCRLCreation(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	privRSA, _ := ParsePKCS1PrivateKey(block.Bytes)
	block, _ = pem.Decode([]byte(pemCertificate))
	certRSA, _ := ParseCertificate(block.Bytes)

	block, _ = pem.Decode([]byte(ed25519CRLKey))
	privEd25519, _ := ParsePKCS8PrivateKey(block.Bytes)
	block, _ = pem.Decode([]byte(ed25519CRLCertificate))
	certEd25519, _ := ParseCertificate(block.Bytes)

	tests := []struct {
		name string
		priv any
		cert *Certificate
	}{
		{"RSA CA", privRSA, certRSA},
		{"Ed25519 CA", privEd25519, certEd25519},
	}

	loc := time.FixedZone("Oz/Atlantis", int((2 * time.Hour).Seconds()))

	now := time.Unix(1000, 0).In(loc)
	nowUTC := now.UTC()
	expiry := time.Unix(10000, 0)

	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: nowUTC,
		},
		{
			SerialNumber: big.NewInt(42),
			// RevocationTime should be converted to UTC before marshaling.
			RevocationTime: now,
		},
	}
	expectedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: nowUTC,
		},
		{
			SerialNumber:   big.NewInt(42),
			RevocationTime: nowUTC,
		},
	}

	for _, test := range tests {
		crlBytes, err := test.cert.CreateCRL(rand.Reader, test.priv, revokedCerts, now, expiry)
		if err != nil {
			t.Errorf("%s: error creating CRL: %s", test.name, err)
			continue
		}

		parsedCRL, err := ParseDERCRL(crlBytes)
		if err != nil {
			t.Errorf("%s: error reparsing CRL: %s", test.name, err)
			continue
		}
		if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, expectedCerts) {
			t.Errorf("%s: RevokedCertificates mismatch: got %v; want %v.", test.name,
				parsedCRL.TBSCertList.RevokedCertificates, expectedCerts)
		}
	}
}

func fromBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		panic("failed to base64 decode")
	}
	return out[:n]
}

func TestParseDERCRL(t *testing.T) {
	derBytes := fromBase64(derCRLBase64)
	certList, err := ParseDERCRL(derBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expected := 88
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}

	if certList.HasExpired(time.Unix(1302517272, 0)) {
		t.Errorf("CRL has expired (but shouldn't have)")
	}

	// Can't check the signature here without a package cycle.
}

func TestCRLWithoutExpiry(t *testing.T) {
	derBytes := fromBase64("MIHYMIGZMAkGByqGSM44BAMwEjEQMA4GA1UEAxMHQ2FybERTUxcNOTkwODI3MDcwMDAwWjBpMBMCAgDIFw05OTA4MjIwNzAwMDBaMBMCAgDJFw05OTA4MjIwNzAwMDBaMBMCAgDTFw05OTA4MjIwNzAwMDBaMBMCAgDSFw05OTA4MjIwNzAwMDBaMBMCAgDUFw05OTA4MjQwNzAwMDBaMAkGByqGSM44BAMDLwAwLAIUfmVSdjP+NHMX0feW+aDU2G1cfT0CFAJ6W7fVWxjBz4fvftok8yqDnDWh")
	certList, err := ParseDERCRL(derBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certList.TBSCertList.NextUpdate.IsZero() {
		t.Errorf("NextUpdate is not the zero value")
	}
}

func TestParsePEMCRL(t *testing.T) {
	pemBytes := fromBase64(pemCRLBase64)
	certList, err := ParseCRL(pemBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expected := 2
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}

	if certList.HasExpired(time.Unix(1302517272, 0)) {
		t.Errorf("CRL has expired (but shouldn't have)")
	}

	// Can't check the signature here without a package cycle.
}

func TestImports(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	testenv.MustHaveGoRun(t)

	if out, err := exec.Command(testenv.GoToolPath(t), "run", "x509_test_import.go").CombinedOutput(); err != nil {
		t.Errorf("failed to run x509_test_import.go: %s\n%s", err, out)
	}
}

const derCRLBase64 = "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"

const pemCRLBase64 = "LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0tDQpNSUlCOWpDQ0FWOENBUUV3RFFZSktvWklodmNOQVFFRkJRQXdiREVhTUJnR0ExVUVDaE1SVWxOQklGTmxZM1Z5DQphWFI1SUVsdVl5NHhIakFjQmdOVkJBTVRGVkpUUVNCUWRXSnNhV01nVW05dmRDQkRRU0IyTVRFdU1Dd0dDU3FHDQpTSWIzRFFFSkFSWWZjbk5oYTJWdmJuSnZiM1J6YVdkdVFISnpZWE5sWTNWeWFYUjVMbU52YlJjTk1URXdNakl6DQpNVGt5T0RNd1doY05NVEV3T0RJeU1Ua3lPRE13V2pDQmpEQktBaEVBckRxb2g5RkhKSFhUN09QZ3V1bjQrQmNODQpNRGt4TVRBeU1UUXlOekE1V2pBbU1Bb0dBMVVkRlFRRENnRUpNQmdHQTFVZEdBUVJHQTh5TURBNU1URXdNakUwDQpNalExTlZvd1BnSVJBTEd6blowOTVQQjVhQU9MUGc1N2ZNTVhEVEF5TVRBeU16RTBOVEF4TkZvd0dqQVlCZ05WDQpIUmdFRVJnUE1qQXdNakV3TWpNeE5EVXdNVFJhb0RBd0xqQWZCZ05WSFNNRUdEQVdnQlQxVERGNlVRTS9MTmVMDQpsNWx2cUhHUXEzZzltekFMQmdOVkhSUUVCQUlDQUlRd0RRWUpLb1pJaHZjTkFRRUZCUUFEZ1lFQUZVNUFzNk16DQpxNVBSc2lmYW9iUVBHaDFhSkx5QytNczVBZ2MwYld5QTNHQWR4dXI1U3BQWmVSV0NCamlQL01FSEJXSkNsQkhQDQpHUmNxNXlJZDNFakRrYUV5eFJhK2k2N0x6dmhJNmMyOUVlNks5cFNZd2ppLzdSVWhtbW5Qclh0VHhsTDBsckxyDQptUVFKNnhoRFJhNUczUUE0Q21VZHNITnZicnpnbUNZcHZWRT0NCi0tLS0tRU5EIFg1MDkgQ1JMLS0tLS0NCg0K"

func TestCreateCertificateRequest(t *testing.T) {
	random := rand.Reader

	ecdsa256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa521Priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	_, ed25519Priv, err := ed25519.GenerateKey(random)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}

	tests := []struct {
		name    string
		priv    any
		sigAlgo SignatureAlgorithm
	}{
		{"RSA", testPrivateKey, SHA256WithRSA},
		{"RSA-PSS-SHA256", testPrivateKey, SHA256WithRSAPSS},
		{"ECDSA-256", ecdsa256Priv, ECDSAWithSHA256},
		{"ECDSA-384", ecdsa384Priv, ECDSAWithSHA256},
		{"ECDSA-521", ecdsa521Priv, ECDSAWithSHA256},
		{"Ed25519", ed25519Priv, PureEd25519},
	}

	for _, test := range tests {
		template := CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Σ Acme Co"},
			},
			SignatureAlgorithm: test.sigAlgo,
			DNSNames:           []string{"test.example.com"},
			EmailAddresses:     []string{"gopher@golang.org"},
			IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		}

		derBytes, err := CreateCertificateRequest(random, &template, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		out, err := ParseCertificateRequest(derBytes)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		err = out.CheckSignature()
		if err != nil {
			t.Errorf("%s: failed to check certificate request signature: %s", test.name, err)
			continue
		}

		if out.Subject.CommonName != template.Subject.CommonName {
			t.Errorf("%s: output subject common name and template subject common name don't match", test.name)
		} else if len(out.Subject.Or
"""




```