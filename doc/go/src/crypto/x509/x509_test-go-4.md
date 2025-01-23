Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keywords:**

The first step is to quickly scan the code for recognizable keywords and structures. Things that jump out are:

* `package x509` and the import path `go/src/crypto/x509/x509_test.go`: This immediately tells us we're dealing with tests for the `crypto/x509` package in Go, which handles X.509 certificates.
* Function names like `Test...`, `Benchmark...`, `CreateCertificate`, `ParseCertificate`, `ParseCertificateRequest`, `ParseRevocationList`, `CheckSignatureFrom`. These suggest the code is testing various functionalities related to creating, parsing, and validating X.509 artifacts.
* Data structures like `Certificate`, `CertificateRequest`, `CertPool`, `RevocationList`. These are the core types being tested.
* Cryptographic primitives like `rsa`, `ecdsa`, `elliptic`. This confirms the code is involved with cryptographic operations related to certificates.
* `pem.Decode`: This indicates the code handles PEM-encoded certificates and related data.
* `t.Errorf`, `t.Fatalf`, `b.Run`, `b.N`:  These are standard Go testing and benchmarking utilities.

**2. Grouping by Functionality:**

Next, I would mentally (or physically, if the snippet were much larger) group the code sections based on the primary functionality they seem to be testing.

* **`TestCreateCertificateWithError` and `BenchmarkCreateCertificate`:** These are clearly testing the `CreateCertificate` function, one for error handling and the other for performance.
* **`TestCreateCertificateBrokenSigner` and `TestCreateCertificateLegacy`:** These are also related to `CreateCertificate`, specifically testing error conditions (broken signer, legacy signature algorithm).
* **`TestCertificateRequestRoundtripFields`:** This tests the serialization and deserialization of `CertificateRequest` structures.
* **`BenchmarkParseCertificate`, `TestParseCertificateRawEquals`, `TestSigAlgMismatch`, `TestAuthKeyIdOptional`, `TestLargeOID`, `TestParseUniqueID`, `TestDisableSHA1ForCertOnly`, `TestParseNegativeSerial`, `TestCreateNegativeSerial`, `TestDuplicateExtensionsCert`, `TestDuplicateExtensionsCSR`, `TestDupAttCSR`:** These all seem to be testing the `ParseCertificate` and `ParseCertificateRequest` functions, focusing on various edge cases and specific scenarios (raw data integrity, signature algorithm mismatches, optional fields, large OIDs, unique IDs, negative serial numbers, duplicate extensions/attributes).
* **`TestParseRevocationList` and `TestRevocationListCheckSignatureFrom`:**  These are testing the `ParseRevocationList` function and the signature verification of revocation lists.
* **Functions related to `CertPool` (`mustCert`, `allCerts`, `certPoolEqual`):** These test the functionality of the `CertPool` type, likely used for managing and verifying certificate chains.
* **`TestOmitEmptyExtensions`:** This tests how certificate extensions are handled during creation.

**3. Inferring Go Features and Providing Examples:**

Based on the identified functionalities, I can infer the Go features being tested and provide illustrative examples:

* **Certificate Creation:**  The code clearly tests the creation of X.509 certificates. The examples of `rsa.GenerateKey` and `ecdsa.GenerateKey` show the use of Go's crypto library for generating keys. The `CreateCertificate` function itself is the target.
* **Certificate Parsing:**  Several tests focus on parsing PEM-encoded certificates. The `pem.Decode` function and `ParseCertificate` are the key elements here. The different test cases with various PEM strings illustrate this.
* **Certificate Request Handling:** The `TestCertificateRequestRoundtripFields` function demonstrates the marshaling and unmarshaling of certificate requests. `ParseCertificateRequest` is the relevant function.
* **Certificate Pool Management:** The `CertPool` related functions indicate testing of a mechanism for storing and comparing collections of certificates.
* **Revocation List Handling:**  The tests around `ParseRevocationList` and `CheckSignatureFrom` show the package's ability to handle and verify Certificate Revocation Lists (CRLs).
* **Error Handling:** Several test cases are explicitly designed to check error conditions (e.g., broken signer, legacy algorithms, negative serials, duplicate extensions).
* **Benchmarking:** The `BenchmarkCreateCertificate` and `BenchmarkParseCertificate` functions utilize Go's benchmarking framework to measure the performance of these core operations.

**4. Code Inference and Assumptions:**

For code inference (like how `CreateCertificate` works), the provided snippet is insufficient to show the *implementation*. However, the *tests* reveal its intended behavior: it takes a template, subject public key, and signing key as input and produces a signed certificate. The tests for broken signers and legacy algorithms give clues about the signing process and supported algorithms. My assumptions would be based on standard X.509 certificate generation practices.

**5. Command-Line Arguments (If Applicable):**

In this specific snippet, there are no direct command-line argument processing being tested. If there were, I would look for flags or parsing logic using packages like `flag`.

**6. Common Mistakes:**

Identifying potential user errors involves thinking about how developers might misuse the API. For instance:

* Incorrect key usage flags when creating certificates.
* Using deprecated or insecure signature algorithms.
* Not handling errors returned by parsing or creation functions.
* Misunderstanding the purpose of different certificate fields.

**7. Summarization of Functionality (Part 5 of 6):**

Finally, for the summarization, I would synthesize the key functionalities observed in this specific part of the code, building upon the previous analysis. Since this is part 5 of 6, I'd emphasize the functionalities most prevalent in this section, such as:

* In-depth testing of `ParseCertificate` with diverse certificate structures and potential error conditions.
* Testing of `ParseCertificateRequest`.
* Testing of `ParseRevocationList`.
* Performance benchmarking of certificate creation and parsing.
* Specific error handling scenarios related to certificate creation and parsing (broken signers, legacy algorithms, etc.).

By following these steps, I can systematically analyze the Go code snippet, infer its purpose, provide relevant examples, and highlight key aspects and potential pitfalls.
这段Go语言代码是 `go/src/crypto/x509/x509_test.go` 文件的一部分，主要专注于测试 X.509 证书和证书请求的创建和解析功能，以及证书吊销列表（CRL）的处理。

**功能归纳 (针对提供的代码片段):**

总的来说，这段代码主要测试了以下 `crypto/x509` 包的功能：

1. **证书创建 (`CreateCertificate`):**
   - 测试使用不同的密钥类型（RSA 和 ECDSA）创建自签名证书的性能。
   - 测试当签名者出现错误时 (`brokenSigner`)，`CreateCertificate` 是否能正确返回错误。
   - 测试当尝试使用过时的签名算法（如 MD5WithRSA）时，`CreateCertificate` 是否会失败。
   - 测试创建证书时，如果序列号为负数，是否会返回错误。
   - 测试创建证书时，如果扩展字段为空，是否会被省略。

2. **证书解析 (`ParseCertificate`):**
   - 基准测试不同类型的证书（ECDSA 和 RSA）的解析性能。
   - 验证解析后的证书的原始字节 (`Raw`) 是否与原始 PEM 编码的字节一致。
   - 测试解析证书时，如果证书内部和外部的签名算法标识符或参数不匹配，是否会返回错误。
   - 测试解析包含可选 Authority Key Identifier 字段的证书是否成功。
   - 测试解析包含非常大的 OID 的证书是否成功。
   - 测试解析包含 Unique Identifier 扩展的证书是否成功。
   - 测试在禁用 SHA-1 的情况下，解析使用 SHA-1 签名的证书是否会失败。
   - 测试解析带有负序列号的证书是否会失败。
   - 测试解析包含重复扩展字段的证书是否会失败。

3. **证书请求解析 (`ParseCertificateRequest`):**
   - 测试证书请求中不同字段（DNS 名称、邮箱地址、IP 地址、URI）的编解码是否正确。
   - 测试解析包含重复扩展字段的证书请求是否会失败。
   - 测试解析包含重复属性的证书请求是否会失败。

4. **证书池 (`CertPool`) 的功能:**
   - 提供了用于比较两个证书池是否相等的辅助函数 `certPoolEqual`。
   - 提供了从证书池中获取证书的辅助函数 `mustCert` 和 `allCerts`。

5. **证书吊销列表 (CRL) 的处理:**
   - 测试解析 CRL (`ParseRevocationList`) 的功能。
   - 测试验证 CRL 签名 (`CheckSignatureFrom`) 的功能，包括各种有效和无效的发行者证书场景。

**Go 语言功能实现示例:**

**1. 证书创建:**

假设我们想创建一个 RSA 自签名证书：

```go
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	// 生成 RSA 私钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}

	// 创建证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Org"},
			CommonName:   "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 使用私钥创建自签名证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		fmt.Println("Error creating certificate:", err)
		return
	}

	// 将证书编码为 PEM 格式
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	// 打印 PEM 编码的证书
	if err := pem.Encode(os.Stdout, certPEM); err != nil {
		fmt.Println("Error encoding certificate to PEM:", err)
		return
	}
}
```

**假设的输入与输出:**

上面的代码会生成并输出一个 PEM 格式的自签名证书到标准输出。输出类似于：

```
-----BEGIN CERTIFICATE-----
MIIChjCCAeICCQD/h9J8lKx4mjANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDEwZl
eGFtcGxlLmNvbTAeFw0yMzEwMjYwNzQ1MzNaFw0yNDEwMjMwNzQ1MzNaMB8xETAP
BgNVBAMM example.comMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
... (一大串 base64 编码的字符) ...
-----END CERTIFICATE-----
```

**命令行参数处理:**

这段代码片段本身没有涉及命令行参数的处理。`x509` 包的主要功能是处理证书数据，而不是命令行交互。如果涉及到命令行工具，通常会使用 `flag` 或其他库来处理参数。

**使用者易犯错的点:**

基于这段测试代码，使用者在 `crypto/x509` 包中容易犯的错误包括：

1. **密钥用途 (`KeyUsage`) 设置不正确:** 例如，创建用于签名代码的证书时，没有设置 `x509.KeyUsageDigitalSignature`。
2. **基本约束 (`BasicConstraints`) 设置错误:** 例如，将非 CA 证书标记为 CA 证书，或者反之。
3. **签名算法选择不当:**  使用已被认为不安全的签名算法，如 MD5 或 SHA-1 (在某些上下文中)。
4. **序列号为负数:**  在创建证书时，序列号必须是正数。
5. **尝试解析无效或损坏的证书/CSR/CRL 数据:** 这会导致解析错误。
6. **扩展字段重复:** X.509 标准通常不允许重复的关键扩展字段。

**总结这段代码的功能:**

这段代码是 `go/src/crypto/x509/x509_test.go` 的一部分，着重测试了 `crypto/x509` 包中关于 **创建和解析 X.509 证书、证书请求以及处理证书吊销列表（CRL）** 的核心功能。它通过各种测试用例，包括性能测试、错误场景测试以及特定字段和扩展的处理测试，来确保这些功能的正确性和健壮性。

### 提示词
```
这是路径为go/src/crypto/x509/x509_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```go
edError {
			t.Errorf("unexpected error: got %q, want %q", err.Error(), tc.expectedError)
		}
	}
}

func BenchmarkCreateCertificate(b *testing.B) {
	template := &Certificate{
		SerialNumber: big.NewInt(10),
		DNSNames:     []string{"example.com"},
	}
	tests := []struct {
		name string
		gen  func() crypto.Signer
	}{
		{
			name: "RSA 2048",
			gen: func() crypto.Signer {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					b.Fatalf("failed to generate test key: %s", err)
				}
				return k
			},
		},
		{
			name: "ECDSA P256",
			gen: func() crypto.Signer {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					b.Fatalf("failed to generate test key: %s", err)
				}
				return k
			},
		},
	}

	for _, tc := range tests {
		k := tc.gen()
		b.ResetTimer()
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := CreateCertificate(rand.Reader, template, template, k.Public(), k)
				if err != nil {
					b.Fatalf("failed to create certificate: %s", err)
				}
			}
		})
	}
}

type brokenSigner struct {
	pub crypto.PublicKey
}

func (bs *brokenSigner) Public() crypto.PublicKey {
	return bs.pub
}

func (bs *brokenSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return []byte{1, 2, 3}, nil
}

func TestCreateCertificateBrokenSigner(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(10),
		DNSNames:     []string{"example.com"},
	}
	expectedErr := "signature returned by signer is invalid"
	_, err := CreateCertificate(rand.Reader, template, template, testPrivateKey.Public(), &brokenSigner{testPrivateKey.Public()})
	if err == nil {
		t.Fatal("expected CreateCertificate to fail with a broken signer")
	} else if !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("CreateCertificate returned an unexpected error: got %q, want %q", err, expectedErr)
	}
}

func TestCreateCertificateLegacy(t *testing.T) {
	sigAlg := MD5WithRSA
	template := &Certificate{
		SerialNumber:       big.NewInt(10),
		DNSNames:           []string{"example.com"},
		SignatureAlgorithm: sigAlg,
	}
	_, err := CreateCertificate(rand.Reader, template, template, testPrivateKey.Public(), &brokenSigner{testPrivateKey.Public()})
	if err == nil {
		t.Fatal("CreateCertificate didn't fail when SignatureAlgorithm = MD5WithRSA")
	}
}

func (s *CertPool) mustCert(t *testing.T, n int) *Certificate {
	c, err := s.lazyCerts[n].getCert()
	if err != nil {
		t.Fatalf("failed to load cert %d: %v", n, err)
	}
	return c
}

func allCerts(t *testing.T, p *CertPool) []*Certificate {
	all := make([]*Certificate, p.len())
	for i := range all {
		all[i] = p.mustCert(t, i)
	}
	return all
}

// certPoolEqual reports whether a and b are equal, except for the
// function pointers.
func certPoolEqual(a, b *CertPool) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	if a == nil {
		return true
	}
	if !reflect.DeepEqual(a.byName, b.byName) ||
		len(a.lazyCerts) != len(b.lazyCerts) {
		return false
	}
	for i := range a.lazyCerts {
		la, lb := a.lazyCerts[i], b.lazyCerts[i]
		if !bytes.Equal(la.rawSubject, lb.rawSubject) {
			return false
		}
		ca, err := la.getCert()
		if err != nil {
			panic(err)
		}
		cb, err := la.getCert()
		if err != nil {
			panic(err)
		}
		if !ca.Equal(cb) {
			return false
		}
	}

	return true
}

func TestCertificateRequestRoundtripFields(t *testing.T) {
	urlA, err := url.Parse("https://example.com/_")
	if err != nil {
		t.Fatal(err)
	}
	urlB, err := url.Parse("https://example.org/_")
	if err != nil {
		t.Fatal(err)
	}
	in := &CertificateRequest{
		DNSNames:       []string{"example.com", "example.org"},
		EmailAddresses: []string{"a@example.com", "b@example.com"},
		IPAddresses:    []net.IP{net.IPv4(192, 0, 2, 0), net.IPv6loopback},
		URIs:           []*url.URL{urlA, urlB},
	}
	out := marshalAndParseCSR(t, in)

	if !slices.Equal(in.DNSNames, out.DNSNames) {
		t.Fatalf("Unexpected DNSNames: got %v, want %v", out.DNSNames, in.DNSNames)
	}
	if !slices.Equal(in.EmailAddresses, out.EmailAddresses) {
		t.Fatalf("Unexpected EmailAddresses: got %v, want %v", out.EmailAddresses, in.EmailAddresses)
	}
	if len(in.IPAddresses) != len(out.IPAddresses) ||
		!in.IPAddresses[0].Equal(out.IPAddresses[0]) ||
		!in.IPAddresses[1].Equal(out.IPAddresses[1]) {
		t.Fatalf("Unexpected IPAddresses: got %v, want %v", out.IPAddresses, in.IPAddresses)
	}
	if !reflect.DeepEqual(in.URIs, out.URIs) {
		t.Fatalf("Unexpected URIs: got %v, want %v", out.URIs, in.URIs)
	}
}

func BenchmarkParseCertificate(b *testing.B) {
	cases := []struct {
		name string
		pem  string
	}{
		{
			name: "ecdsa leaf",
			pem: `-----BEGIN CERTIFICATE-----
MIIINjCCBx6gAwIBAgIQHdQ6oBMoe/MJAAAAAEHzmTANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMDEyMDgwOTExMzZaFw0yMTAzMDIw
OTExMzVaMBcxFTATBgNVBAMMDCouZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABEFYegyHh1AHRS1nar5+zYJgMACcsIQMtg0YMyK/59ml8ERIt/JF
kXM3XIvQuCJhghUawZrrAcAs8djZF1U9M4mjggYYMIIGFDAOBgNVHQ8BAf8EBAMC
B4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU
6SWWF36XBsmXJ6iV0EHPXUFoMbwwHwYDVR0jBBgwFoAUinR/r4XN7pXNPZzQ4kYU
83E1HScwagYIKwYBBQUHAQEEXjBcMCcGCCsGAQUFBzABhhtodHRwOi8vb2NzcC5w
a2kuZ29vZy9ndHMxYzMwMQYIKwYBBQUHMAKGJWh0dHA6Ly9wa2kuZ29vZy9yZXBv
L2NlcnRzL2d0czFjMy5kZXIwggTCBgNVHREEggS5MIIEtYIMKi5nb29nbGUuY29t
gg0qLmFuZHJvaWQuY29tghYqLmFwcGVuZ2luZS5nb29nbGUuY29tggkqLmJkbi5k
ZXaCEiouY2xvdWQuZ29vZ2xlLmNvbYIYKi5jcm93ZHNvdXJjZS5nb29nbGUuY29t
ghgqLmRhdGFjb21wdXRlLmdvb2dsZS5jb22CBiouZy5jb4IOKi5nY3AuZ3Z0Mi5j
b22CESouZ2NwY2RuLmd2dDEuY29tggoqLmdncGh0LmNugg4qLmdrZWNuYXBwcy5j
boIWKi5nb29nbGUtYW5hbHl0aWNzLmNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xl
LmNsgg4qLmdvb2dsZS5jby5pboIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNv
LnVrgg8qLmdvb2dsZS5jb20uYXKCDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUu
Y29tLmJygg8qLmdvb2dsZS5jb20uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29n
bGUuY29tLnRygg8qLmdvb2dsZS5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2ds
ZS5lc4ILKi5nb29nbGUuZnKCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5n
b29nbGUubmyCCyouZ29vZ2xlLnBsggsqLmdvb2dsZS5wdIISKi5nb29nbGVhZGFw
aXMuY29tgg8qLmdvb2dsZWFwaXMuY26CESouZ29vZ2xlY25hcHBzLmNughQqLmdv
b2dsZWNvbW1lcmNlLmNvbYIRKi5nb29nbGV2aWRlby5jb22CDCouZ3N0YXRpYy5j
boINKi5nc3RhdGljLmNvbYISKi5nc3RhdGljY25hcHBzLmNuggoqLmd2dDEuY29t
ggoqLmd2dDIuY29tghQqLm1ldHJpYy5nc3RhdGljLmNvbYIMKi51cmNoaW4uY29t
ghAqLnVybC5nb29nbGUuY29tghMqLndlYXIuZ2tlY25hcHBzLmNughYqLnlvdXR1
YmUtbm9jb29raWUuY29tgg0qLnlvdXR1YmUuY29tghYqLnlvdXR1YmVlZHVjYXRp
b24uY29tghEqLnlvdXR1YmVraWRzLmNvbYIHKi55dC5iZYILKi55dGltZy5jb22C
GmFuZHJvaWQuY2xpZW50cy5nb29nbGUuY29tggthbmRyb2lkLmNvbYIbZGV2ZWxv
cGVyLmFuZHJvaWQuZ29vZ2xlLmNughxkZXZlbG9wZXJzLmFuZHJvaWQuZ29vZ2xl
LmNuggRnLmNvgghnZ3BodC5jboIMZ2tlY25hcHBzLmNuggZnb28uZ2yCFGdvb2ds
ZS1hbmFseXRpY3MuY29tggpnb29nbGUuY29tgg9nb29nbGVjbmFwcHMuY26CEmdv
b2dsZWNvbW1lcmNlLmNvbYIYc291cmNlLmFuZHJvaWQuZ29vZ2xlLmNuggp1cmNo
aW4uY29tggp3d3cuZ29vLmdsggh5b3V0dS5iZYILeW91dHViZS5jb22CFHlvdXR1
YmVlZHVjYXRpb24uY29tgg95b3V0dWJla2lkcy5jb22CBXl0LmJlMCEGA1UdIAQa
MBgwCAYGZ4EMAQIBMAwGCisGAQQB1nkCBQMwNQYDVR0fBC4wLDAqoCigJoYkaHR0
cDovL2NybC5wa2kuZ29vZy9ndHNyMS9ndHMxYzMuY3JsMBMGCisGAQQB1nkCBAMB
Af8EAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQAlDQm5zY7JcPxcJ9ulfTGsWV/m6Pro
gLYmAlBUPGKy313aetT4Zjz44ZseVtUOKsXVHh4avPA9O+ta1FgkASlbkgJ05ivb
j/+MMqkrLemdMv9Svvx3CNaAq2jJ2E+8GdrA1RzMkiNthJCiRafaPnXnN6hOHGNr
GtqYfMHsvrRHW8J2IPHW0/MUHmJ/NDu/vNchxke2OEfCPLtseo3hJt8l8HbH+yE8
DFrt8YVRi1CLomEyuPJDF4og3O3ZsoXuxcPd9UPxULOCxycdolRw8Iv/Xgr082j3
svXC3HUd3apM2Yy3xJAlk/mUkzVXfdJZ+Zy1huNsUoJ+gM8rmpyGhYyx
-----END CERTIFICATE-----`,
		},
		{
			name: "rsa leaf",
			pem: `-----BEGIN CERTIFICATE-----
MIIJXjCCCEagAwIBAgIRAPYaTUsjP4iRBQAAAACHSSgwDQYJKoZIhvcNAQELBQAw
QjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET
MBEGA1UEAxMKR1RTIENBIDFPMTAeFw0yMTAxMjYwODQ2MzRaFw0yMTA0MjAwODQ2
MzNaMGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQDDAwq
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC76xx0
UdZ36/41rZNPfQ/yQ05vsBLUO0d+3uMOhvDlpst+XvIsG6L+vLDgf3RiQRFlei0h
KqqLOtWLDc/y0+OmaaC+8ft1zljBYdvQlAYoZrT79Cc5pAIDq7G1OZ7cC4ahDno/
n46FHjT/UTUAMYa8cKWBaMPneMIsKvn8nMdZzHkfO2nUd6OEecn90XweMvNmx8De
6h5AlIgG3m66hkD/UCSdxn7yJHBQVdHgkfTqzv3sz2YyBQGNi288F1bn541f6khE
fYti1MvXRtkky7yLCQNUG6PtvuSU4cKaNvRklHigf5i1nVdGEuH61gAElZIklSia
OVK46UyU4DGtbdWNAgMBAAGjggYpMIIGJTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU8zCvllLd3jhB
k//+Wdjo40Q+T3gwHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswaAYI
KwYBBQUHAQEEXDBaMCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC5wa2kuZ29vZy9n
dHMxbzFjb3JlMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2cvZ3NyMi9HVFMx
TzEuY3J0MIIE1wYDVR0RBIIEzjCCBMqCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lk
LmNvbYIWKi5hcHBlbmdpbmUuZ29vZ2xlLmNvbYIJKi5iZG4uZGV2ghIqLmNsb3Vk
Lmdvb2dsZS5jb22CGCouY3Jvd2Rzb3VyY2UuZ29vZ2xlLmNvbYIYKi5kYXRhY29t
cHV0ZS5nb29nbGUuY29tghMqLmZsYXNoLmFuZHJvaWQuY29tggYqLmcuY2+CDiou
Z2NwLmd2dDIuY29tghEqLmdjcGNkbi5ndnQxLmNvbYIKKi5nZ3BodC5jboIOKi5n
a2VjbmFwcHMuY26CFiouZ29vZ2xlLWFuYWx5dGljcy5jb22CCyouZ29vZ2xlLmNh
ggsqLmdvb2dsZS5jbIIOKi5nb29nbGUuY28uaW6CDiouZ29vZ2xlLmNvLmpwgg4q
Lmdvb2dsZS5jby51a4IPKi5nb29nbGUuY29tLmFygg8qLmdvb2dsZS5jb20uYXWC
DyouZ29vZ2xlLmNvbS5icoIPKi5nb29nbGUuY29tLmNvgg8qLmdvb2dsZS5jb20u
bXiCDyouZ29vZ2xlLmNvbS50coIPKi5nb29nbGUuY29tLnZuggsqLmdvb2dsZS5k
ZYILKi5nb29nbGUuZXOCCyouZ29vZ2xlLmZyggsqLmdvb2dsZS5odYILKi5nb29n
bGUuaXSCCyouZ29vZ2xlLm5sggsqLmdvb2dsZS5wbIILKi5nb29nbGUucHSCEiou
Z29vZ2xlYWRhcGlzLmNvbYIPKi5nb29nbGVhcGlzLmNughEqLmdvb2dsZWNuYXBw
cy5jboIUKi5nb29nbGVjb21tZXJjZS5jb22CESouZ29vZ2xldmlkZW8uY29tggwq
LmdzdGF0aWMuY26CDSouZ3N0YXRpYy5jb22CEiouZ3N0YXRpY2NuYXBwcy5jboIK
Ki5ndnQxLmNvbYIKKi5ndnQyLmNvbYIUKi5tZXRyaWMuZ3N0YXRpYy5jb22CDCou
dXJjaGluLmNvbYIQKi51cmwuZ29vZ2xlLmNvbYITKi53ZWFyLmdrZWNuYXBwcy5j
boIWKi55b3V0dWJlLW5vY29va2llLmNvbYINKi55b3V0dWJlLmNvbYIWKi55b3V0
dWJlZWR1Y2F0aW9uLmNvbYIRKi55b3V0dWJla2lkcy5jb22CByoueXQuYmWCCyou
eXRpbWcuY29tghphbmRyb2lkLmNsaWVudHMuZ29vZ2xlLmNvbYILYW5kcm9pZC5j
b22CG2RldmVsb3Blci5hbmRyb2lkLmdvb2dsZS5jboIcZGV2ZWxvcGVycy5hbmRy
b2lkLmdvb2dsZS5jboIEZy5jb4IIZ2dwaHQuY26CDGdrZWNuYXBwcy5jboIGZ29v
LmdsghRnb29nbGUtYW5hbHl0aWNzLmNvbYIKZ29vZ2xlLmNvbYIPZ29vZ2xlY25h
cHBzLmNughJnb29nbGVjb21tZXJjZS5jb22CGHNvdXJjZS5hbmRyb2lkLmdvb2ds
ZS5jboIKdXJjaGluLmNvbYIKd3d3Lmdvby5nbIIIeW91dHUuYmWCC3lvdXR1YmUu
Y29tghR5b3V0dWJlZWR1Y2F0aW9uLmNvbYIPeW91dHViZWtpZHMuY29tggV5dC5i
ZTAhBgNVHSAEGjAYMAgGBmeBDAECAjAMBgorBgEEAdZ5AgUDMDMGA1UdHwQsMCow
KKAmoCSGImh0dHA6Ly9jcmwucGtpLmdvb2cvR1RTMU8xY29yZS5jcmwwEwYKKwYB
BAHWeQIEAwEB/wQCBQAwDQYJKoZIhvcNAQELBQADggEBAHh9/ozYUGRd+W5akWlM
4WvX808TK2oUISnagbxCCFZ2trpg2oi03CJf4o4o3Je5Qzzz10s22oQY6gPHAR0B
QHzrpqAveQw9D5vd8xjgtQ/SAujPzPKNQee5511rS7/EKW9I83ccd5XhhoEyx8A1
/65RTS+2hKpJKTMkr0yHBPJV7kUW+n/KIef5YaSOA9VYK7hyH0niDpvm9EmoqvWS
U5xAFAe/Xrrq3sxTuDJPQA8alk6h/ql5Klkw6dL53csiPka/MevDqdifWkzuT/6n
YK/ePeJzPD17FA9V+N1rcuF3Wk29AZvCOSasdIkIuE82vGr3dfNrsrn9E9lWIbCr
Qc4=
-----END CERTIFICATE-----`,
		},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			pemBlock, _ := pem.Decode([]byte(c.pem))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := ParseCertificate(pemBlock.Bytes)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestParseCertificateRawEquals(t *testing.T) {
	p, _ := pem.Decode([]byte(pemCertificate))
	cert, err := ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
	if !bytes.Equal(p.Bytes, cert.Raw) {
		t.Fatalf("unexpected Certificate.Raw\ngot: %x\nwant: %x\n", cert.Raw, p.Bytes)
	}
}

// mismatchingSigAlgIDPEM contains a certificate where the Certificate
// signatureAlgorithm and the TBSCertificate signature contain
// mismatching OIDs
const mismatchingSigAlgIDPEM = `-----BEGIN CERTIFICATE-----
MIIBBzCBrqADAgECAgEAMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA8wMDAxMDEwMTAwMDAwMFowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOqV
EDuVXxwZgIU3+dOwv1SsMu0xuV48hf7xmK8n7sAMYgllB+96DnPqBeboJj4snYnx
0AcE0PDVQ1l4Z3YXsQWjFTATMBEGA1UdEQEB/wQHMAWCA2FzZDAKBggqhkjOPQQD
AwNIADBFAiBi1jz/T2HT5nAfrD7zsgR+68qh7Erc6Q4qlxYBOgKG4QIhAOtjIn+Q
tA+bq+55P3ntxTOVRq0nv1mwnkjwt9cQR9Fn
-----END CERTIFICATE-----`

// mismatchingSigAlgParamPEM contains a certificate where the Certificate
// signatureAlgorithm and the TBSCertificate signature contain
// mismatching parameters
const mismatchingSigAlgParamPEM = `-----BEGIN CERTIFICATE-----
MIIBCTCBrqADAgECAgEAMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA8wMDAxMDEwMTAwMDAwMFowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOqV
EDuVXxwZgIU3+dOwv1SsMu0xuV48hf7xmK8n7sAMYgllB+96DnPqBeboJj4snYnx
0AcE0PDVQ1l4Z3YXsQWjFTATMBEGA1UdEQEB/wQHMAWCA2FzZDAMBggqhkjOPQQD
AgUAA0gAMEUCIGLWPP9PYdPmcB+sPvOyBH7ryqHsStzpDiqXFgE6AobhAiEA62Mi
f5C0D5ur7nk/ee3FM5VGrSe/WbCeSPC31xBH0Wc=
-----END CERTIFICATE-----`

func TestSigAlgMismatch(t *testing.T) {
	for _, certPEM := range []string{mismatchingSigAlgIDPEM, mismatchingSigAlgParamPEM} {
		b, _ := pem.Decode([]byte(certPEM))
		if b == nil {
			t.Fatalf("couldn't decode test certificate")
		}
		_, err := ParseCertificate(b.Bytes)
		if err == nil {
			t.Fatalf("expected ParseCertificate to fail")
		}
		expected := "x509: inner and outer signature algorithm identifiers don't match"
		if err.Error() != expected {
			t.Errorf("unexpected error from ParseCertificate: got %q, want %q", err.Error(), expected)
		}
	}
}

const optionalAuthKeyIDPEM = `-----BEGIN CERTIFICATE-----
MIIFEjCCBHugAwIBAgICAQwwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1Zh
bGlDZXJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIElu
Yy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24g
QXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAe
BgkqhkiG9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTA0MDYyOTE3MzkxNloX
DTI0MDYyOTE3MzkxNlowaDELMAkGA1UEBhMCVVMxJTAjBgNVBAoTHFN0YXJmaWVs
ZCBUZWNobm9sb2dpZXMsIEluYy4xMjAwBgNVBAsTKVN0YXJmaWVsZCBDbGFzcyAy
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0A
MIIBCAKCAQEAtzLI/ulxpgSFrQwRZN/OTe/IAxiHP6Gr+zymn/DDodrU2G4rU5D7
JKQ+hPCe6F/s5SdE9SimP3ve4CrwyK9TL57KBQGTHo9mHDmnTfpatnMEJWbrd3/n
WcZKmSUUVOsmx/N/GdUwcI+vsEYq/63rKe3Xn6oEh6PU+YmlNF/bQ5GCNtlmPLG4
uYL9nDo+EMg77wZlZnqbGRg9/3FRPDAuX749d3OyXQZswyNWmiuFJpIcpwKz5D8N
rwh5grg2Peqc0zWzvGnK9cyd6P1kjReAM25eSl2ZyR6HtJ0awNVuEzUjXt+bXz3v
1vd2wuo+u3gNHEJnawTY+Nbab4vyRKABqwIBA6OCAfMwggHvMB0GA1UdDgQWBBS/
X7fRzt0fhvRbVazc1xDCDqmI5zCB0gYDVR0jBIHKMIHHoYHBpIG+MIG7MSQwIgYD
VQQHExtWYWxpQ2VydCBWYWxpZGF0aW9uIE5ldHdvcmsxFzAVBgNVBAoTDlZhbGlD
ZXJ0LCBJbmMuMTUwMwYDVQQLEyxWYWxpQ2VydCBDbGFzcyAyIFBvbGljeSBWYWxp
ZGF0aW9uIEF1dGhvcml0eTEhMB8GA1UEAxMYaHR0cDovL3d3dy52YWxpY2VydC5j
b20vMSAwHgYJKoZIhvcNAQkBFhFpbmZvQHZhbGljZXJ0LmNvbYIBATAPBgNVHRMB
Af8EBTADAQH/MDkGCCsGAQUFBwEBBC0wKzApBggrBgEFBQcwAYYdaHR0cDovL29j
c3Auc3RhcmZpZWxkdGVjaC5jb20wSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2Nl
cnRpZmljYXRlcy5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5L3Jvb3QuY3Js
MFEGA1UdIARKMEgwRgYEVR0gADA+MDwGCCsGAQUFBwIBFjBodHRwOi8vY2VydGlm
aWNhdGVzLnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkwDgYDVR0PAQH/BAQD
AgEGMA0GCSqGSIb3DQEBBQUAA4GBAKVi8afCXSWlcD284ipxs33kDTcdVWptobCr
mADkhWBKIMuh8D1195TaQ39oXCUIuNJ9MxB73HZn8bjhU3zhxoNbKXuNSm8uf0So
GkVrMgfHeMpkksK0hAzc3S1fTbvdiuo43NlmouxBulVtWmQ9twPMHOKRUJ7jCUSV
FxdzPcwl
-----END CERTIFICATE-----`

func TestAuthKeyIdOptional(t *testing.T) {
	b, _ := pem.Decode([]byte(optionalAuthKeyIDPEM))
	if b == nil {
		t.Fatalf("couldn't decode test certificate")
	}
	_, err := ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate to failed to parse certificate with optional authority key identifier fields: %s", err)
	}
}

const largeOIDPEM = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            da:ba:53:19:1b:09:4b:82:b2:89:26:7d:c7:6f:a0:02
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: O = Acme Co
        Validity
            Not Before: Dec 21 16:59:27 2021 GMT
            Not After : Dec 21 16:59:27 2022 GMT
        Subject: O = Acme Co
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:bf:17:16:d8:bc:29:9c:16:e5:76:b4:93:15:78:
                    ad:6e:45:c5:4a:63:46:a1:b2:76:71:65:51:9c:14:
                    c4:ea:74:13:e4:34:df:2f:2c:65:11:e8:56:52:69:
                    11:f9:0e:fc:77:bb:63:a8:7c:1a:c6:a1:7b:6e:6c:
                    e7:18:25:25:c9:e8:fb:06:7f:a2:a9:98:fe:2a:bc:
                    8a:b3:75:b6:b8:7d:b6:c9:6b:29:08:32:22:10:cb:
                    8d:d6:60:c8:83:ad:f5:58:91:d6:11:e8:55:56:fb:
                    8f:a3:a2:9f:48:cb:79:e4:65:4a:8c:a6:52:64:9f:
                    99:38:35:d4:d5:ac:6f:cf:a0:cb:42:8c:07:eb:21:
                    17:31:3a:eb:91:7b:62:43:a4:75:5f:ef:a7:2f:94:
                    f8:69:0b:d4:ec:09:e6:00:c0:8c:dd:07:63:0b:e4:
                    77:aa:60:18:3c:a0:e0:ae:0a:ea:0e:52:3b:b4:fa:
                    6a:30:1b:50:62:21:73:53:33:01:60:a1:6b:99:58:
                    00:f3:77:c6:0f:46:19:ca:c2:5d:cd:f5:e2:52:4d:
                    84:94:23:d3:32:2f:ae:5f:da:43:a1:19:95:d2:17:
                    dd:49:14:b4:d9:48:1c:08:13:93:8e:d5:09:43:21:
                    b6:ce:52:e8:87:bb:d2:60:0d:c6:4e:bf:c5:93:6a:
                    c6:bf
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Alternative Name:
                DNS:longOID.example
            X509v3 Certificate Policies:
                Policy: 1.3.6.1.4.1.311.21.8.1492336001

    Signature Algorithm: sha256WithRSAEncryption
         72:77:8b:de:48:fb:6d:9a:94:b1:be:d4:90:7d:4c:e6:d3:79:
         fa:fb:fc:3e:d5:3d:e9:a0:ce:28:2b:2f:94:77:3f:87:f8:9c:
         9f:91:1c:f3:f6:58:91:15:6b:24:b9:ca:ae:9f:ee:ca:c8:31:
         db:1a:3d:bb:6b:83:6d:bc:81:8b:a1:79:d5:3e:bb:dd:93:fe:
         35:3e:b7:99:e0:d6:eb:58:0c:fd:42:73:dc:49:da:e2:b7:ae:
         15:ee:e6:cc:aa:ef:91:41:9a:18:46:8d:4a:39:65:a2:85:3c:
         7f:0c:41:f8:0b:9c:e8:1f:35:36:60:8d:8c:e0:8e:18:b1:06:
         57:d0:4e:c4:c3:cd:8f:6f:e7:76:02:52:da:03:43:61:2b:b3:
         bf:19:fd:73:0d:6a:0b:b4:b6:cb:a9:6f:70:4e:53:2a:54:07:
         b3:74:fd:85:49:57:5b:23:8d:8c:6b:53:2b:09:e8:41:a5:80:
         3f:69:1b:11:d1:6b:13:35:2e:f9:d6:50:15:d9:91:38:42:43:
         e9:17:af:67:d9:96:a4:d1:6a:4f:cc:b4:a7:8e:48:1f:00:72:
         69:de:4d:f1:73:a4:47:12:67:e9:f9:07:3e:79:75:90:42:b8:
         d4:b5:fd:d1:7e:35:04:f7:00:04:cf:f1:36:be:0f:27:81:1f:
         a6:ba:88:6c
-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIRANq6UxkbCUuCsokmfcdvoAIwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0yMTEyMjExNjU5MjdaFw0yMjEyMjExNjU5
MjdaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQC/FxbYvCmcFuV2tJMVeK1uRcVKY0ahsnZxZVGcFMTqdBPkNN8vLGUR
6FZSaRH5Dvx3u2OofBrGoXtubOcYJSXJ6PsGf6KpmP4qvIqzdba4fbbJaykIMiIQ
y43WYMiDrfVYkdYR6FVW+4+jop9Iy3nkZUqMplJkn5k4NdTVrG/PoMtCjAfrIRcx
OuuRe2JDpHVf76cvlPhpC9TsCeYAwIzdB2ML5HeqYBg8oOCuCuoOUju0+mowG1Bi
IXNTMwFgoWuZWADzd8YPRhnKwl3N9eJSTYSUI9MyL65f2kOhGZXSF91JFLTZSBwI
E5OO1QlDIbbOUuiHu9JgDcZOv8WTasa/AgMBAAGjbjBsMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBoGA1UdEQQTMBGC
D2xvbmdPSUQuZXhhbXBsZTAbBgNVHSAEFDASMBAGDisGAQQBgjcVCIXHzPsBMA0G
CSqGSIb3DQEBCwUAA4IBAQByd4veSPttmpSxvtSQfUzm03n6+/w+1T3poM4oKy+U
dz+H+JyfkRzz9liRFWskucqun+7KyDHbGj27a4NtvIGLoXnVPrvdk/41PreZ4Nbr
WAz9QnPcSdrit64V7ubMqu+RQZoYRo1KOWWihTx/DEH4C5zoHzU2YI2M4I4YsQZX
0E7Ew82Pb+d2AlLaA0NhK7O/Gf1zDWoLtLbLqW9wTlMqVAezdP2FSVdbI42Ma1Mr
CehBpYA/aRsR0WsTNS751lAV2ZE4QkPpF69n2Zak0WpPzLSnjkgfAHJp3k3xc6RH
Emfp+Qc+eXWQQrjUtf3RfjUE9wAEz/E2vg8ngR+muohs
-----END CERTIFICATE-----`

func TestLargeOID(t *testing.T) {
	// See Issue 49678.
	b, _ := pem.Decode([]byte(largeOIDPEM))
	if b == nil {
		t.Fatalf("couldn't decode test certificate")
	}
	_, err := ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate to failed to parse certificate with large OID: %s", err)
	}
}

const uniqueIDPEM = `-----BEGIN CERTIFICATE-----
MIIFsDCCBJigAwIBAgIILOyC1ydafZMwDQYJKoZIhvcNAQEFBQAwgY4xgYswgYgG
A1UEAx6BgABNAGkAYwByAG8AcwBvAGYAdAAgAEYAbwByAGUAZgByAG8AbgB0ACAA
VABNAEcAIABIAFQAVABQAFMAIABJAG4AcwBwAGUAYwB0AGkAbwBuACAAQwBlAHIA
dABpAGYAaQBjAGEAdABpAG8AbgAgAEEAdQB0AGgAbwByAGkAdAB5MB4XDTE0MDEx
ODAwNDEwMFoXDTE1MTExNTA5Mzc1NlowgZYxCzAJBgNVBAYTAklEMRAwDgYDVQQI
EwdqYWthcnRhMRIwEAYDVQQHEwlJbmRvbmVzaWExHDAaBgNVBAoTE3N0aG9ub3Jl
aG90ZWxyZXNvcnQxHDAaBgNVBAsTE3N0aG9ub3JlaG90ZWxyZXNvcnQxJTAjBgNV
BAMTHG1haWwuc3Rob25vcmVob3RlbHJlc29ydC5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCvuu0qpI+Ko2X84Twkf84cRD/rgp6vpgc5Ebejx/D4
PEVON5edZkazrMGocK/oQqIlRxx/lefponN/chlGcllcVVPWTuFjs8k+Aat6T1qp
4iXxZekAqX+U4XZMIGJD3PckPL6G2RQSlF7/LhGCsRNRdKpMWSTbou2Ma39g52Kf
gsl3SK/GwLiWpxpcSkNQD1hugguEIsQYLxbeNwpcheXZtxbBGguPzQ7rH8c5vuKU
BkMOzaiNKLzHbBdFSrua8KWwCJg76Vdq/q36O9GlW6YgG3i+A4pCJjXWerI1lWwX
Ktk5V+SvUHGey1bkDuZKJ6myMk2pGrrPWCT7jP7WskChAgMBAAGBCQBCr1dgEleo
cKOCAfswggH3MIHDBgNVHREEgbswgbiCHG1haWwuc3Rob25vcmVob3RlbHJlc29y
dC5jb22CIGFzaGNoc3ZyLnN0aG9ub3JlaG90ZWxyZXNvcnQuY29tgiRBdXRvRGlz
Y292ZXIuc3Rob25vcmVob3RlbHJlc29ydC5jb22CHEF1dG9EaXNjb3Zlci5ob3Rl
bHJlc29ydC5jb22CCEFTSENIU1ZSghdzdGhvbm9yZWhvdGVscmVzb3J0LmNvbYIP
aG90ZWxyZXNvcnQuY29tMCEGCSsGAQQBgjcUAgQUHhIAVwBlAGIAUwBlAHIAdgBl
AHIwHQYDVR0OBBYEFMAC3UR4FwAdGekbhMgnd6lMejtbMAsGA1UdDwQEAwIFoDAT
BgNVHSUEDDAKBggrBgEFBQcDATAJBgNVHRMEAjAAMIG/BgNVHQEEgbcwgbSAFGfF
6xihk+gJJ5TfwvtWe1UFnHLQoYGRMIGOMYGLMIGIBgNVBAMegYAATQBpAGMAcgBv
AHMAbwBmAHQAIABGAG8AcgBlAGYAcgBvAG4AdAAgAFQATQBHACAASABUAFQAUABT
ACAASQBuAHMAcABlAGMAdABpAG8AbgAgAEMAZQByAHQAaQBmAGkAYwBhAHQAaQBv
AG4AIABBAHUAdABoAG8AcgBpAHQAeYIIcKhXEmBXr0IwDQYJKoZIhvcNAQEFBQAD
ggEBABlSxyCMr3+ANr+WmPSjyN5YCJBgnS0IFCwJAzIYP87bcTye/U8eQ2+E6PqG
Q7Huj7nfHEw9qnGo+HNyPp1ad3KORzXDb54c6xEoi+DeuPzYHPbn4c3hlH49I0aQ
eWW2w4RslSWpLvO6Y7Lboyz2/Thk/s2kd4RHxkkWpH2ltPqJuYYg3X6oM5+gIFHJ
WGnh+ojZ5clKvS5yXh3Wkj78M6sb32KfcBk0Hx6NkCYPt60ODYmWtvqwtw6r73u5
TnTYWRNvo2svX69TriL+CkHY9O1Hkwf2It5zHl3gNiKTJVaak8AuEz/CKWZneovt
yYLwhUhg3PX5Co1VKYE+9TxloiE=
-----END CERTIFICATE-----`

func TestParseUniqueID(t *testing.T) {
	b, _ := pem.Decode([]byte(uniqueIDPEM))
	if b == nil {
		t.Fatalf("couldn't decode test certificate")
	}
	cert, err := ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate to failed to parse certificate with unique identifier id: %s", err)
	}
	if len(cert.Extensions) != 7 {
		t.Fatalf("unexpected number of extensions (probably because the extension section was not parsed): got %d, want 7", len(cert.Extensions))
	}
}

func TestDisableSHA1ForCertOnly(t *testing.T) {
	t.Setenv("GODEBUG", "")

	tmpl := &Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		SignatureAlgorithm:    SHA1WithRSA,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              KeyUsageCertSign | KeyUsageCRLSign,
	}
	certDER, err := CreateCertificate(rand.Reader, tmpl, tmpl, rsaPrivateKey.Public(), rsaPrivateKey)
	if err != nil {
		t.Fatalf("failed to generate test cert: %s", err)
	}
	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse test cert: %s", err)
	}

	err = cert.CheckSignatureFrom(cert)
	if err == nil {
		t.Error("expected CheckSignatureFrom to fail")
	} else if _, ok := err.(InsecureAlgorithmError); !ok {
		t.Errorf("expected InsecureAlgorithmError error, got %T", err)
	}

	crlDER, err := CreateRevocationList(rand.Reader, &RevocationList{
		SignatureAlgorithm: SHA1WithRSA,
		Number:             big.NewInt(1),
		ThisUpdate:         time.Now().Add(-time.Hour),
		NextUpdate:         time.Now().Add(time.Hour),
	}, cert, rsaPrivateKey)
	if err != nil {
		t.Fatalf("failed to generate test CRL: %s", err)
	}
	crl, err := ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("failed to parse test CRL: %s", err)
	}

	if err = crl.CheckSignatureFrom(cert); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// This is an unrelated OCSP response, which will fail signature verification
	// but shouldn't return an InsecureAlgorithmError, since SHA1 should be allowed
	// for OCSP.
	ocspTBSHex := "30819fa2160414884451ff502a695e2d88f421bad90cf2cecbea7c180f32303133303631383037323434335a30743072304a300906052b0e03021a0500041448b60d38238df8456e4ee5843ea394111802979f0414884451ff502a695e2d88f421bad90cf2cecbea7c021100f78b13b946fc9635d8ab49de9d2148218000180f32303133303631383037323434335aa011180f32303133303632323037323434335a"
	ocspTBS, err := hex.DecodeString(ocspTBSHex)
	if err != nil {
		t.Fatalf("failed to decode OCSP response TBS hex: %s", err)
	}

	err = cert.CheckSignature(SHA1WithRSA, ocspTBS, nil)
	if err != rsa.ErrVerification {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestParseRevocationList(t *testing.T) {
	derBytes := fromBase64(derCRLBase64)
	certList, err := ParseRevocationList(derBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.RevokedCertificateEntries)
	numCertsDeprecated := len(certList.RevokedCertificateEntries)
	expected := 88
	if numCerts != expected || numCertsDeprecated != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}
}

func TestRevocationListCheckSignatureFrom(t *testing.T) {
	goodKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %s", err)
	}
	badKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %s", err)
	}
	tests := []struct {
		name   string
		issuer *Certificate
		err    string
	}{
		{
			name: "valid",
			issuer: &Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    ECDSA,
				PublicKey:             goodKey.Public(),
			},
		},
		{
			name: "valid, key usage set",
			issuer: &Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    ECDSA,
				PublicKey:             goodKey.Public(),
				KeyUsage:              KeyUsageCRLSign,
			},
		},
		{
			name: "invalid issuer, wrong key usage",
			issuer: &Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    ECDSA,
				PublicKey:             goodKey.Public(),
				KeyUsage:              KeyUsageCertSign,
			},
			err: "x509: invalid signature: parent certificate cannot sign this kind of certificate",
		},
		{
			name: "invalid issuer, no basic constraints/ca",
			issuer: &Certificate{
				Version:            3,
				PublicKeyAlgorithm: ECDSA,
				PublicKey:          goodKey.Public(),
			},
			err: "x509: invalid signature: parent certificate cannot sign this kind of certificate",
		},
		{
			name: "invalid issuer, unsupported public key type",
			issuer: &Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    UnknownPublicKeyAlgorithm,
				PublicKey:             goodKey.Public(),
			},
			err: "x509: cannot verify signature: algorithm unimplemented",
		},
		{
			name: "wrong key",
			issuer: &Certificate{
				Version:               3,
				BasicConstraintsValid: true,
				IsCA:                  true,
				PublicKeyAlgorithm:    ECDSA,
				PublicKey:             badKey.Public(),
			},
			err: "x509: ECDSA verification failure",
		},
	}

	crlIssuer := &Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKeyAlgorithm:    ECDSA,
		PublicKey:             goodKey.Public(),
		KeyUsage:              KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crlDER, err := CreateRevocationList(rand.Reader, &RevocationList{Number: big.NewInt(1)}, crlIssuer, goodKey)
			if err != nil {
				t.Fatalf("failed to generate CRL: %s", err)
			}
			crl, err := ParseRevocationList(crlDER)
			if err != nil {
				t.Fatalf("failed to parse test CRL: %s", err)
			}
			err = crl.CheckSignatureFrom(tc.issuer)
			if err != nil && err.Error() != tc.err {
				t.Errorf("unexpected error: got %s, want %s", err, tc.err)
			} else if err == nil && tc.err != "" {
				t.Errorf("CheckSignatureFrom did not fail: want %s", tc.err)
			}
		})
	}
}

func TestOmitEmptyExtensions(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: ":)",
		},
		NotAfter:  time.Now().Add(time.Hour),
		NotBefore: time.Now().Add(-time.Hour),
	}
	der, err := CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}

	emptyExtSeq := []byte{0xA3, 0x02, 0x30, 0x00}
	if bytes.Contains(der, emptyExtSeq) {
		t.Error("DER encoding contains the an empty extensions SEQUENCE")
	}
}

var negativeSerialCert = `-----BEGIN CERTIFICATE-----
MIIBBTCBraADAgECAgH/MAoGCCqGSM49BAMCMA0xCzAJBgNVBAMTAjopMB4XDTIy
MDQxNDIzNTYwNFoXDTIyMDQxNTAxNTYwNFowDTELMAkGA1UEAxMCOikwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ9ezsIsj+q17K87z/PXE/rfGRN72P/Wyn5d6oo
5M0ZbSatuntMvfKdX79CQxXAxN4oXk3Aov4jVSG12AcDI8ShMAoGCCqGSM49BAMC
A0cAMEQCIBzfBU5eMPT6m5lsR6cXaJILpAaiD9YxOl4v6dT3rzEjAiBHmjnHmAss
RqUAyJKFzqZxOlK2q4j2IYnuj5+LrLGbQA==
-----END CERTIFICATE-----`

func TestParseNegativeSerial(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(negativeSerialCert))
	_, err := ParseCertificate(pemBlock.Bytes)
	if err == nil {
		t.Fatal("parsed certificate with negative serial")
	}
}

func TestCreateNegativeSerial(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &Certificate{
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName: ":)",
		},
		NotAfter:  time.Now().Add(time.Hour),
		NotBefore: time.Now().Add(-time.Hour),
	}
	expectedErr := "x509: serial number must be positive"
	_, err = CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("CreateCertificate returned unexpected error: want %q, got %q", expectedErr, err)
	}
}

const dupExtCert = `-----BEGIN CERTIFICATE-----
MIIBrjCCARegAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwR0ZXN0
MCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMA8xDTALBgNVBAMT
BHRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMiFchnHms9l9NninAIz
SkY9acwl9Bk2AtmJrNCenFpiA17AcOO5q8DJYwdXi6WPKlVgcyH+ysW8XMWkq+CP
yhtF/+LMzl9odaUF2iUy3vgTC5gxGLWH5URVssx21Und2Pm2f4xyou5IVxbS9dxy
jLvV9PEY9BIb0H+zFthjhihDAgMBAAGjFjAUMAgGAioDBAIFADAIBgIqAwQCBQAw
DQYJKoZIhvcNAQELBQADgYEAlhQ4TQQKIQ8GUyzGiN/75TCtQtjhMGemxc0cNgre
d9rmm4DjydH0t7/sMCB56lQrfhJNplguzsbjFW4l245KbNKHfLiqwEGUgZjBNKur
ot6qX/skahLtt0CNOaFIge75HVKe/69OrWQGdp18dkay/KS4Glu8YMKIjOhfrUi1
NZA=
-----END CERTIFICATE-----`

func TestDuplicateExtensionsCert(t *testing.T) {
	b, _ := pem.Decode([]byte(dupExtCert))
	if b == nil {
		t.Fatalf("couldn't decode test certificate")
	}
	_, err := ParseCertificate(b.Bytes)
	if err == nil {
		t.Fatal("ParseCertificate should fail when parsing certificate with duplicate extensions")
	}
}

const dupExtCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIIBczCB3QIBADAPMQ0wCwYDVQQDEwR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQC5PbxMGVJ8aLF9lq/EvGObXTRMB7ieiZL9N+DJZg1n/ECCnZLIvYrr
ZmmDV7YZsClgxKGfjJB0RQFFyZElFM9EfHEs8NJdidDKCRdIhDXQWRyhXKevHvdm
CQNKzUeoxvdHpU/uscSkw6BgUzPyLyTx9A6ye2ix94z8Y9hGOBO2DQIDAQABoCUw
IwYJKoZIhvcNAQkOMRYwFDAIBgIqAwQCBQAwCAYCKgMEAgUAMA0GCSqGSIb3DQEB
CwUAA4GBAHROEsE7URk1knXmBnQtIHwoq663vlMcX3Hes58pUy020rWP8QkocA+X
VF18/phg3p5ILlS4fcbbP2bEeV0pePo2k00FDPsJEKCBAX2LKxbU7Vp2OuV2HM2+
VLOVx0i+/Q7fikp3hbN1JwuMTU0v2KL/IKoUcZc02+5xiYrnOIt5
-----END CERTIFICATE REQUEST-----`

func TestDuplicateExtensionsCSR(t *testing.T) {
	b, _ := pem.Decode([]byte(dupExtCSR))
	if b == nil {
		t.Fatalf("couldn't decode test CSR")
	}
	_, err := ParseCertificateRequest(b.Bytes)
	if err == nil {
		t.Fatal("ParseCertificateRequest should fail when parsing CSR with duplicate extensions")
	}
}

const dupAttCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIIBbDCB1gIBADAPMQ0wCwYDVQQDEwR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQCj5Po3PKO/JNuxr+B+WNfMIzqqYztdlv+mTQhT0jOR5rTkUvxeeHH8
YclryES2dOISjaUOTmOAr5GQIIdQl4Ql33Cp7ZR/VWcRn+qvTak0Yow+xVsDo0n4
7IcvvP6CJ7FRoYBUakVczeXLxCjLwdyK16VGJM06eRzDLykPxpPwLQIDAQABoB4w
DQYCKgMxBwwFdGVzdDEwDQYCKgMxBwwFdGVzdDIwDQYJKoZIhvcNAQELBQADgYEA
UJ8hsHxtnIeqb2ufHnQFJO+wEJhx2Uxm/BTuzHOeffuQkwATez4skZ7SlX9exgb7
6jRMRilqb4F7f8w+uDoqxRrA9zc8mwY16zPsyBhRet+ZGbj/ilgvGmtZ21qZZ/FU
0pJFJIVLM3l49Onr5uIt5+hCWKwHlgE0nGpjKLR3cMg=
-----END CERTIFICATE
```