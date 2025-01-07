Response:
The user wants to understand the functionality of the provided Go code snippet, which is a part of the `x509_test.go` file in the `crypto/x509` package. I need to analyze the code and identify its purpose, providing examples if possible. The request specifically asks for a summary of the functionality as this is part 3 of 6.

Based on the code, it seems to be focused on testing the creation and parsing of Certificate Signing Requests (CSRs) and X.509 certificates.

Here's a breakdown of the code sections and their apparent functions:

1. **`TestCertificateRequestEquality`**: This function tests the equality of fields between a template `CertificateRequest` and the parsed `CertificateRequest` after marshalling and unmarshalling. It checks `Subject`, `DNSNames`, `EmailAddresses`, and `IPAddresses`.

2. **`marshalAndParseCSR`**: This is a helper function that takes a `CertificateRequest` template, creates a CSR from it, and then parses the resulting DER-encoded CSR back into a `CertificateRequest`.

3. **`TestCertificateRequestOverrides`**: This function checks how extensions in a `CertificateRequest` override the template values. It tests scenarios where:
    - An explicit Subject Alternative Name (SAN) extension overrides the `DNSNames` in the template.
    - Adding extensions to existing `Attributes` works correctly.
    - Extensions in `Attributes` override those in `ExtraExtensions`.

4. **`TestParseCertificateRequest`**: This function parses pre-generated base64 encoded CSRs and verifies if the extracted fields like `EmailAddresses`, `DNSNames`, `Subject`, and presence of specific extensions are correct.

5. **`TestCriticalFlagInCSRRequestedExtensions`**: This test focuses on parsing a CSR that contains extensions with the `critical` flag set and ensures these extensions are correctly parsed.

6. **`serialiseAndParse`**:  Another helper function, this one creates a self-signed certificate from a `Certificate` template and parses it back.

7. **`TestMaxPathLenNotCA`**: This function tests the behavior of `MaxPathLen` in certificates when `IsCA` is false. It checks that `MaxPathLen` defaults to -1, setting it explicitly to -1 also results in -1, and attempting to set it to a positive value or setting `MaxPathLenZero` fails when `IsCA` is false.

8. **`TestMaxPathLen`**:  This function tests the behavior of `MaxPathLen` when `IsCA` is true. It verifies that omitting `MaxPathLen` results in -1, setting it to a positive integer works, and setting `MaxPathLenZero` to true sets `MaxPathLen` to 0.

9. **`TestNoAuthorityKeyIdInSelfSignedCert`**:  This test checks if the Authority Key Identifier is correctly handled in self-signed certificates. It ensures that it's not included by default but is present if explicitly set.

10. **`TestNoSubjectKeyIdInCert`**: This function tests the generation of the Subject Key Identifier in certificates. It verifies that it's generated for CA certificates, not for non-CA certificates by default, and is present if explicitly set.

11. **`TestASN1BitLength`**: This function tests a utility function `asn1BitLength` which calculates the bit length of a byte slice.

12. **`TestVerifyEmptyCertificate`**: This test checks the error returned when trying to verify an empty certificate.

13. **`TestInsecureAlgorithmErrorString`**: This function tests the string representation of the `InsecureAlgorithmError`.

14. **`csrBase64Array`**: This variable holds an array of base64 encoded CSR strings used for testing.

15. **`md5cert`**: This variable holds a base64 encoded certificate using the MD5WithRSA signature algorithm.

16. **`TestMD5`**: This function parses the `md5cert` and verifies that its signature algorithm is correctly identified as `MD5WithRSA` and that verification fails with an `InsecureAlgorithmError`.

17. **`TestSHA1`**: Similar to `TestMD5`, this function tests a certificate signed with SHA1.

18. **`certMissingRSANULL`**:  A base64 encoded certificate with a missing NULL parameter in the RSA public key.

19. **`TestRSAMissingNULLParameters`**: This function attempts to parse `certMissingRSANULL` and checks if the expected error about the missing NULL parameter is returned.

20. **`certISOOID`**: A base64 encoded certificate containing an ISO OID.

21. **`TestISOOIDInCertificate`**: This function parses `certISOOID` and verifies that the signature algorithm is correctly identified (not `UnknownSignatureAlgorithm`).

22. **`certMultipleRDN`**: A base64 encoded certificate with multiple Relative Distinguished Names (RDNs).

23. **`TestMultipleRDN`**: This function parses `certMultipleRDN` and verifies that the subject's common name and serial number are extracted correctly.

24. **`TestSystemCertPool`**: This test focuses on the `SystemCertPool` function, ensuring that multiple calls return the same pool and that modifying one pool doesn't affect others (on supported platforms).

25. **`emptyNameConstraintsPEM`**: A base64 encoded certificate with empty name constraints.

26. **`TestEmptyNameConstraints`**: This function attempts to parse `emptyNameConstraintsPEM` and verifies that it fails with an error indicating empty name constraints.

27. **`TestPKIXNameString`**: This function tests the string representation of `pkix.Name`, including handling of non-standard attributes and cases with both `ExtraNames` and `Names`.

28. **`TestRDNSequenceString`**: This function tests the string representation of `pkix.RDNSequence`, specifically focusing on multi-valued attributes.

29. **`criticalNameConstraintWithUnknownTypePEM`**: A base64 encoded certificate with a critical name constraint of an unknown type.

30. **`TestCriticalNameConstraintWithUnknownType`**: This function parses the certificate with the unknown critical name constraint and verifies that it's correctly identified as an unhandled critical extension.

31. **`badIPMaskPEM`**: A base64 encoded certificate with an invalid IP mask in the name constraints.

32. **`TestBadIPMask`**: This function attempts to parse the certificate with the bad IP mask and checks if the expected error about the invalid mask is returned.

33. **`additionalGeneralSubtreePEM`**: A partially shown PEM-encoded certificate, likely used for testing name constraints or related features in other parts of the file.

**Summary of Functionality (Part 3):**

This section of the `x509_test.go` file primarily focuses on **testing the creation, parsing, and specific aspects of X.509 Certificate Signing Requests (CSRs) and X.509 certificates.**  It verifies the correct handling of various certificate fields (like Subject, DNS names, email addresses, IP addresses), extensions (including Subject Alternative Names and critical extensions), and attributes within CSRs. It also includes tests for specific certificate features like `MaxPathLen` for CA and non-CA certificates, the presence of key identifiers, and the behavior when encountering certificates with insecure signature algorithms or malformed data.

这是 `go/src/crypto/x509/x509_test.go` 文件的第三部分，主要功能是**测试证书签名请求（CSR）和证书的创建、解析以及一些特定的属性和错误处理**。

具体来说，这部分代码测试了以下几个方面：

1. **证书签名请求（CSR）的创建和解析**:
   - 验证创建的 CSR 与模板中的信息是否一致 (例如：组织、DNS 名称、邮箱地址、IP 地址)。
   - 测试了当 CSR 中包含扩展时，扩展信息是否能正确覆盖模板中的信息。
   - 测试了包含属性的 CSR 的创建和解析，以及当属性中包含扩展时，是否能正确合并或覆盖 `ExtraExtensions` 中的信息。
   - 通过解析预定义的 Base64 编码的 CSR 字符串，来验证解析功能是否正确，例如提取邮箱地址、DNS 名称、主题信息和特定的扩展。
   - 专门测试了解析包含关键（critical）标志的扩展的 CSR 的能力。

2. **证书的创建和解析，以及特定属性的测试**:
   - 创建自签名证书并解析，用于测试某些属性的默认行为。
   - 测试了 `MaxPathLen` 属性在 CA 证书和非 CA 证书中的处理逻辑。
   - 测试了自签名证书中 Authority Key Identifier 和 Subject Key Identifier 的生成规则。

3. **错误处理和安全特性测试**:
   - 测试了对空证书进行验证时是否返回预期的错误。
   - 测试了 `InsecureAlgorithmError` 类型的字符串表示是否正确，这涉及到对使用不安全算法签名的证书进行验证时产生的错误。
   - 测试了解析使用 MD5 和 SHA1 等不安全算法签名的证书，验证是否能正确识别算法并返回相应的错误。
   - 测试了解析包含格式错误（例如 RSA 公钥中缺少 NULL 参数）的证书时，是否会返回预期的错误。
   - 测试了解析包含 ISO OID 的证书时，是否能正确识别签名算法。

4. **其他辅助功能测试**:
   - 测试了一个计算 ASN.1 位长度的辅助函数 `asn1BitLength`。
   - 测试了获取系统证书池的功能，以及对证书池进行修改是否会影响其他证书池的实例。
   - 测试了解析包含空名称约束的证书时是否会报错。
   - 测试了 `pkix.Name` 结构体的字符串表示，包括对非标准属性的处理。
   - 测试了 `pkix.RDNSequence` 结构体的字符串表示，尤其关注包含多个属性值的 RDN。
   - 测试了解析包含未知类型但标记为关键的名称约束的证书，是否能正确识别为未处理的关键扩展。
   - 测试了解析包含错误 IP 掩码的证书时是否会报错。

**代码举例说明 (证书签名请求的创建和解析)**:

假设我们有一个创建证书签名请求的模板，并希望验证解析后的 CSR 与模板是否一致。

```go
package x509_test

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
)

func TestCreateAndParseCSR(t *testing.T) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
			Organization: []string{"Example Org"},
		},
		DNSNames: []string{"example.com", "www.example.com"},
		EmailAddresses: []string{"test@example.com"},
	}

	privKey, _ := generateTestKey(t) // 假设存在这个生成私钥的函数

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	if parsedCSR.Subject.CommonName != template.Subject.CommonName {
		t.Errorf("Parsed CSR CommonName does not match template")
	}
	if len(parsedCSR.Subject.Organization) != len(template.Subject.Organization) || parsedCSR.Subject.Organization[0] != template.Subject.Organization[0] {
		t.Errorf("Parsed CSR Organization does not match template")
	}
	if len(parsedCSR.DNSNames) != len(template.DNSNames) || parsedCSR.DNSNames[0] != template.DNSNames[0] || parsedCSR.DNSNames[1] != template.DNSNames[1] {
		t.Errorf("Parsed CSR DNSNames do not match template")
	}
	if len(parsedCSR.EmailAddresses) != len(template.EmailAddresses) || parsedCSR.EmailAddresses[0] != template.EmailAddresses[0] {
		t.Errorf("Parsed CSR EmailAddresses do not match template")
	}

	fmt.Println("CSR created and parsed successfully!")
}
```

**假设的输入与输出:**

- **输入:** `template` 变量定义了一个包含 CommonName, Organization, DNSNames 和 EmailAddresses 的 `CertificateRequest` 结构体。
- **输出:** 如果创建和解析成功，并且解析后的 `parsedCSR` 的字段与 `template` 的字段一致，则测试通过，并打印 "CSR created and parsed successfully!"。如果任何一个环节失败，`t.Fatalf` 会终止测试并输出错误信息。

**使用者易犯错的点 (以证书签名请求为例):**

一个常见的错误是在创建 CSR 时，提供的私钥与后续签名证书请求使用的私钥不一致。这会导致证书颁发机构无法正确验证请求的签名。

```go
// 错误示例
func TestIncorrectPrivateKeyForCSR(t *testing.T) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
	}

	privKey1, _ := generateTestKey(t)
	privKey2, _ := generateTestKey(t) // 使用了不同的私钥

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privKey1)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// 假设后续使用 privKey2 来尝试创建证书，这会导致签名验证失败
	// ...
}
```

**命令行参数的具体处理:**

这部分代码主要关注单元测试，并不直接处理命令行参数。`x509` 包本身在创建和解析证书或 CSR 时，接收的是结构体参数（如 `CertificateRequest` 和 `Certificate`）或字节流，而不是命令行参数。命令行参数的处理通常发生在调用 `x509` 包的更上层应用中，例如使用 `crypto/tls` 包配置 TLS 连接时读取证书文件路径等。

**归纳一下它的功能:**

这部分测试代码的核心功能是**全面地验证 Go 语言 `crypto/x509` 包中关于证书签名请求（CSR）和 X.509 证书的创建、解析以及关键属性处理的正确性**。它通过构造不同的测试用例，包括成功场景和各种错误场景，来确保该包的稳定性和可靠性。

Prompt: 
```
这是路径为go/src/crypto/x509/x509_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共6部分，请归纳一下它的功能

"""
ganization) != len(template.Subject.Organization) {
			t.Errorf("%s: output subject organisation and template subject organisation don't match", test.name)
		} else if len(out.DNSNames) != len(template.DNSNames) {
			t.Errorf("%s: output DNS names and template DNS names don't match", test.name)
		} else if len(out.EmailAddresses) != len(template.EmailAddresses) {
			t.Errorf("%s: output email addresses and template email addresses don't match", test.name)
		} else if len(out.IPAddresses) != len(template.IPAddresses) {
			t.Errorf("%s: output IP addresses and template IP addresses names don't match", test.name)
		}
	}
}

func marshalAndParseCSR(t *testing.T, template *CertificateRequest) *CertificateRequest {
	t.Helper()
	derBytes, err := CreateCertificateRequest(rand.Reader, template, testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParseCertificateRequest(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func TestCertificateRequestOverrides(t *testing.T) {
	sanContents, err := marshalSANs([]string{"foo.example.com"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	template := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Σ Acme Co"},
		},
		DNSNames: []string{"test.example.com"},

		// An explicit extension should override the DNSNames from the
		// template.
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidExtensionSubjectAltName,
				Value:    sanContents,
				Critical: true,
			},
		},
	}

	csr := marshalAndParseCSR(t, &template)

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "foo.example.com" {
		t.Errorf("Extension did not override template. Got %v\n", csr.DNSNames)
	}

	if len(csr.Extensions) != 1 || !csr.Extensions[0].Id.Equal(oidExtensionSubjectAltName) || !csr.Extensions[0].Critical {
		t.Errorf("SAN extension was not faithfully copied, got %#v", csr.Extensions)
	}

	// If there is already an attribute with X.509 extensions then the
	// extra extensions should be added to it rather than creating a CSR
	// with two extension attributes.

	template.Attributes = []pkix.AttributeTypeAndValueSET{
		{
			Type: oidExtensionRequest,
			Value: [][]pkix.AttributeTypeAndValue{
				{
					{
						Type:  oidExtensionAuthorityInfoAccess,
						Value: []byte("foo"),
					},
				},
			},
		},
	}

	csr = marshalAndParseCSR(t, &template)
	if l := len(csr.Attributes); l != 1 {
		t.Errorf("incorrect number of attributes: %d\n", l)
	}

	if !csr.Attributes[0].Type.Equal(oidExtensionRequest) ||
		len(csr.Attributes[0].Value) != 1 ||
		len(csr.Attributes[0].Value[0]) != 2 {
		t.Errorf("bad attributes: %#v\n", csr.Attributes)
	}

	sanContents2, err := marshalSANs([]string{"foo2.example.com"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Extensions in Attributes should override those in ExtraExtensions.
	template.Attributes[0].Value[0] = append(template.Attributes[0].Value[0], pkix.AttributeTypeAndValue{
		Type:  oidExtensionSubjectAltName,
		Value: sanContents2,
	})

	csr = marshalAndParseCSR(t, &template)

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "foo2.example.com" {
		t.Errorf("Attributes did not override ExtraExtensions. Got %v\n", csr.DNSNames)
	}
}

func TestParseCertificateRequest(t *testing.T) {
	for _, csrBase64 := range csrBase64Array {
		csrBytes := fromBase64(csrBase64)
		csr, err := ParseCertificateRequest(csrBytes)
		if err != nil {
			t.Fatalf("failed to parse CSR: %s", err)
		}

		if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "gopher@golang.org" {
			t.Errorf("incorrect email addresses found: %v", csr.EmailAddresses)
		}

		if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "test.example.com" {
			t.Errorf("incorrect DNS names found: %v", csr.DNSNames)
		}

		if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "AU" {
			t.Errorf("incorrect Subject name: %v", csr.Subject)
		}

		found := false
		for _, e := range csr.Extensions {
			if e.Id.Equal(oidExtensionBasicConstraints) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("basic constraints extension not found in CSR")
		}
	}
}

func TestCriticalFlagInCSRRequestedExtensions(t *testing.T) {
	// This CSR contains an extension request where the extensions have a
	// critical flag in them. In the past we failed to handle this.
	const csrBase64 = "MIICrTCCAZUCAQIwMzEgMB4GA1UEAwwXU0NFUCBDQSBmb3IgRGV2ZWxlciBTcmwxDzANBgNVBAsMBjQzNTk3MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALFMAJ7Zy9YyfgbNlbUWAW0LalNRMPs7aXmLANsCpjhnw3lLlfDPaLeWyKh1nK5I5ojaJOW6KIOSAcJkDUe3rrE0wR0RVt3UxArqs0R/ND3u5Q+bDQY2X1HAFUHzUzcdm5JRAIA355v90teMckaWAIlkRQjDE22Lzc6NAl64KOd1rqOUNj8+PfX6fSo20jm94Pp1+a6mfk3G/RUWVuSm7owO5DZI/Fsi2ijdmb4NUar6K/bDKYTrDFkzcqAyMfP3TitUtBp19Mp3B1yAlHjlbp/r5fSSXfOGHZdgIvp0WkLuK2u5eQrX5l7HMB/5epgUs3HQxKY6ljhh5wAjDwz//LsCAwEAAaA1MDMGCSqGSIb3DQEJDjEmMCQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQEFBQADggEBAAMq3bxJSPQEgzLYR/yaVvgjCDrc3zUbIwdOis6Go06Q4RnjH5yRaSZAqZQTDsPurQcnz2I39VMGEiSkFJFavf4QHIZ7QFLkyXadMtALc87tm17Ej719SbHcBSSZayR9VYJUNXRLayI6HvyUrmqcMKh+iX3WY3ICr59/wlM0tYa8DYN4yzmOa2Onb29gy3YlaF5A2AKAMmk003cRT9gY26mjpv7d21czOSSeNyVIoZ04IR9ee71vWTMdv0hu/af5kSjQ+ZG5/Qgc0+mnECLz/1gtxt1srLYbtYQ/qAY8oX1DCSGFS61tN/vl+4cxGMD/VGcGzADRLRHSlVqy2Qgss6Q="

	csrBytes := fromBase64(csrBase64)
	csr, err := ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %s", err)
	}

	expected := []struct {
		Id    asn1.ObjectIdentifier
		Value []byte
	}{
		{oidExtensionBasicConstraints, fromBase64("MAYBAf8CAQA=")},
		{oidExtensionKeyUsage, fromBase64("AwIChA==")},
	}

	if n := len(csr.Extensions); n != len(expected) {
		t.Fatalf("expected to find %d extensions but found %d", len(expected), n)
	}

	for i, extension := range csr.Extensions {
		if !extension.Id.Equal(expected[i].Id) {
			t.Fatalf("extension #%d has unexpected type %v (expected %v)", i, extension.Id, expected[i].Id)
		}

		if !bytes.Equal(extension.Value, expected[i].Value) {
			t.Fatalf("extension #%d has unexpected contents %x (expected %x)", i, extension.Value, expected[i].Value)
		}
	}
}

// serialiseAndParse generates a self-signed certificate from template and
// returns a parsed version of it.
func serialiseAndParse(t *testing.T, template *Certificate) *Certificate {
	t.Helper()
	derBytes, err := CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
		return nil
	}

	cert, err := ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
		return nil
	}

	return cert
}

func TestMaxPathLenNotCA(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if m := serialiseAndParse(t, template).MaxPathLen; m != -1 {
		t.Errorf("MaxPathLen should be -1 when IsCa is false, got %d", m)
	}

	template.MaxPathLen = -1
	if m := serialiseAndParse(t, template).MaxPathLen; m != -1 {
		t.Errorf("MaxPathLen should be -1 when IsCa is false and MaxPathLen set to -1, got %d", m)
	}

	template.MaxPathLen = 5
	if _, err := CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey); err == nil {
		t.Error("specifying a MaxPathLen when IsCA is false should fail")
	}

	template.MaxPathLen = 0
	template.MaxPathLenZero = true
	if _, err := CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey); err == nil {
		t.Error("setting MaxPathLenZero when IsCA is false should fail")
	}

	template.BasicConstraintsValid = false
	if m := serialiseAndParse(t, template).MaxPathLen; m != 0 {
		t.Errorf("Bad MaxPathLen should be ignored if BasicConstraintsValid is false, got %d", m)
	}
}

func TestMaxPathLen(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert1 := serialiseAndParse(t, template)
	if m := cert1.MaxPathLen; m != -1 {
		t.Errorf("Omitting MaxPathLen didn't turn into -1, got %d", m)
	}
	if cert1.MaxPathLenZero {
		t.Errorf("Omitting MaxPathLen resulted in MaxPathLenZero")
	}

	template.MaxPathLen = 1
	cert2 := serialiseAndParse(t, template)
	if m := cert2.MaxPathLen; m != 1 {
		t.Errorf("Setting MaxPathLen didn't work. Got %d but set 1", m)
	}
	if cert2.MaxPathLenZero {
		t.Errorf("Setting MaxPathLen resulted in MaxPathLenZero")
	}

	template.MaxPathLen = 0
	template.MaxPathLenZero = true
	cert3 := serialiseAndParse(t, template)
	if m := cert3.MaxPathLen; m != 0 {
		t.Errorf("Setting MaxPathLenZero didn't work, got %d", m)
	}
	if !cert3.MaxPathLenZero {
		t.Errorf("Setting MaxPathLen to zero didn't result in MaxPathLenZero")
	}
}

func TestNoAuthorityKeyIdInSelfSignedCert(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	if cert := serialiseAndParse(t, template); len(cert.AuthorityKeyId) != 0 {
		t.Fatalf("self-signed certificate contained default authority key id")
	}

	template.AuthorityKeyId = []byte{1, 2, 3, 4}
	if cert := serialiseAndParse(t, template); len(cert.AuthorityKeyId) == 0 {
		t.Fatalf("self-signed certificate erased explicit authority key id")
	}
}

func TestNoSubjectKeyIdInCert(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if cert := serialiseAndParse(t, template); len(cert.SubjectKeyId) == 0 {
		t.Fatalf("self-signed certificate did not generate subject key id using the public key")
	}

	template.IsCA = false
	if cert := serialiseAndParse(t, template); len(cert.SubjectKeyId) != 0 {
		t.Fatalf("self-signed certificate generated subject key id when it isn't a CA")
	}

	template.SubjectKeyId = []byte{1, 2, 3, 4}
	if cert := serialiseAndParse(t, template); len(cert.SubjectKeyId) == 0 {
		t.Fatalf("self-signed certificate erased explicit subject key id")
	}
}

func TestASN1BitLength(t *testing.T) {
	tests := []struct {
		bytes  []byte
		bitLen int
	}{
		{nil, 0},
		{[]byte{0x00}, 0},
		{[]byte{0x00, 0x00}, 0},
		{[]byte{0xf0}, 4},
		{[]byte{0x88}, 5},
		{[]byte{0xff}, 8},
		{[]byte{0xff, 0x80}, 9},
		{[]byte{0xff, 0x81}, 16},
	}

	for i, test := range tests {
		if got := asn1BitLength(test.bytes); got != test.bitLen {
			t.Errorf("#%d: calculated bit-length of %d for %x, wanted %d", i, got, test.bytes, test.bitLen)
		}
	}
}

func TestVerifyEmptyCertificate(t *testing.T) {
	if _, err := new(Certificate).Verify(VerifyOptions{}); err != errNotParsed {
		t.Errorf("Verifying empty certificate resulted in unexpected error: %q (wanted %q)", err, errNotParsed)
	}
}

func TestInsecureAlgorithmErrorString(t *testing.T) {
	tests := []struct {
		sa   SignatureAlgorithm
		want string
	}{
		{MD5WithRSA, "x509: cannot verify signature: insecure algorithm MD5-RSA"},
		{SHA1WithRSA, "x509: cannot verify signature: insecure algorithm SHA1-RSA"},
		{ECDSAWithSHA1, "x509: cannot verify signature: insecure algorithm ECDSA-SHA1"},
		{MD2WithRSA, "x509: cannot verify signature: insecure algorithm 1"},
		{-1, "x509: cannot verify signature: insecure algorithm -1"},
		{0, "x509: cannot verify signature: insecure algorithm 0"},
		{9999, "x509: cannot verify signature: insecure algorithm 9999"},
	}
	for i, tt := range tests {
		if got := fmt.Sprint(InsecureAlgorithmError(tt.sa)); got != tt.want {
			t.Errorf("%d. mismatch.\n got: %s\nwant: %s\n", i, got, tt.want)
		}
	}
}

// These CSR was generated with OpenSSL:
//
//	openssl req -out CSR.csr -new -sha256 -nodes -keyout privateKey.key -config openssl.cnf
//
// With openssl.cnf containing the following sections:
//
//	[ v3_req ]
//	basicConstraints = CA:FALSE
//	keyUsage = nonRepudiation, digitalSignature, keyEncipherment
//	subjectAltName = email:gopher@golang.org,DNS:test.example.com
//	[ req_attributes ]
//	challengePassword = ignored challenge
//	unstructuredName  = ignored unstructured name
var csrBase64Array = [...]string{
	// Just [ v3_req ]
	"MIIDHDCCAgQCAQAwfjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLQ29tbW9uIE5hbWUxITAfBgkqhkiG9w0BCQEWEnRlc3RAZW1haWwuYWRkcmVzczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1GY4YFx2ujlZEOJxQVYmsjUnLsd5nFVnNpLE4cV+77sgv9NPNlB8uhn3MXt5leD34rm/2BisCHOifPucYlSrszo2beuKhvwn4+2FxDmWtBEMu/QA16L5IvoOfYZm/gJTsPwKDqvaR0tTU67a9OtxwNTBMI56YKtmwd/o8d3hYv9cg+9ZGAZ/gKONcg/OWYx/XRh6bd0g8DMbCikpWgXKDsvvK1Nk+VtkDO1JxuBaj4Lz/p/MifTfnHoqHxWOWl4EaTs4Ychxsv34/rSj1KD1tJqorIv5Xv2aqv4sjxfbrYzX4kvS5SC1goIovLnhj5UjmQ3Qy8u65eow/LLWw+YFcCAwEAAaBZMFcGCSqGSIb3DQEJDjFKMEgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwLgYDVR0RBCcwJYERZ29waGVyQGdvbGFuZy5vcmeCEHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAB6VPMRrchvNW61Tokyq3ZvO6/NoGIbuwUn54q6l5VZW0Ep5Nq8juhegSSnaJ0jrovmUgKDN9vEo2KxuAtwG6udS6Ami3zP+hRd4k9Q8djJPb78nrjzWiindLK5Fps9U5mMoi1ER8ViveyAOTfnZt/jsKUaRsscY2FzE9t9/o5moE6LTcHUS4Ap1eheR+J72WOnQYn3cifYaemsA9MJuLko+kQ6xseqttbh9zjqd9fiCSh/LNkzos9c+mg2yMADitaZinAh+HZi50ooEbjaT3erNq9O6RqwJlgD00g6MQdoz9bTAryCUhCQfkIaepmQ7BxS0pqWNW3MMwfDwx/Snz6g=",
	// Both [ v3_req ] and [ req_attributes ]
	"MIIDaTCCAlECAQAwfjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLQ29tbW9uIE5hbWUxITAfBgkqhkiG9w0BCQEWEnRlc3RAZW1haWwuYWRkcmVzczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1GY4YFx2ujlZEOJxQVYmsjUnLsd5nFVnNpLE4cV+77sgv9NPNlB8uhn3MXt5leD34rm/2BisCHOifPucYlSrszo2beuKhvwn4+2FxDmWtBEMu/QA16L5IvoOfYZm/gJTsPwKDqvaR0tTU67a9OtxwNTBMI56YKtmwd/o8d3hYv9cg+9ZGAZ/gKONcg/OWYx/XRh6bd0g8DMbCikpWgXKDsvvK1Nk+VtkDO1JxuBaj4Lz/p/MifTfnHoqHxWOWl4EaTs4Ychxsv34/rSj1KD1tJqorIv5Xv2aqv4sjxfbrYzX4kvS5SC1goIovLnhj5UjmQ3Qy8u65eow/LLWw+YFcCAwEAAaCBpTAgBgkqhkiG9w0BCQcxEwwRaWdub3JlZCBjaGFsbGVuZ2UwKAYJKoZIhvcNAQkCMRsMGWlnbm9yZWQgdW5zdHJ1Y3R1cmVkIG5hbWUwVwYJKoZIhvcNAQkOMUowSDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAuBgNVHREEJzAlgRFnb3BoZXJAZ29sYW5nLm9yZ4IQdGVzdC5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAgxe2N5O48EMsYE7o0rZBB0wi3Ov5/yYfnmmVI22Y3sP6VXbLDW0+UWIeSccOhzUCcZ/G4qcrfhhx6gTZTeA01nP7TdTJURvWAH5iFqj9sQ0qnLq6nEcVHij3sG6M5+BxAIVClQBk6lTCzgphc835Fjj6qSLuJ20XHdL5UfUbiJxx299CHgyBRL+hBUIPfz8p+ZgamyAuDLfnj54zzcRVyLlrmMLNPZNll1Q70RxoU6uWvLH8wB8vQe3Q/guSGubLyLRTUQVPh+dw1L4t8MKFWfX/48jwRM4gIRHFHPeAAE9D9YAoqdIvj/iFm/eQ++7DP8MDwOZWsXeB6jjwHuLmkQ==",
}

var md5cert = `
-----BEGIN CERTIFICATE-----
MIIB4TCCAUoCCQCfmw3vMgPS5TANBgkqhkiG9w0BAQQFADA1MQswCQYDVQQGEwJB
VTETMBEGA1UECBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wHhcNMTUx
MjAzMTkyOTMyWhcNMjkwODEyMTkyOTMyWjA1MQswCQYDVQQGEwJBVTETMBEGA1UE
CBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBANrq2nhLQj5mlXbpVX3QUPhfEm/vdEqPkoWtR/jRZIWm4WGf
Wpq/LKHJx2Pqwn+t117syN8l4U5unyAi1BJSXjBwPZNd7dXjcuJ+bRLV7FZ/iuvs
cfYyQQFTxan4TaJMd0x1HoNDbNbjHa02IyjjYE/r3mb/PIg+J2t5AZEh80lPAgMB
AAEwDQYJKoZIhvcNAQEEBQADgYEAjGzp3K3ey/YfKHohf33yHHWd695HQxDAP+wY
cs9/TAyLR+gJzJP7d18EcDDLJWVi7bhfa4EAD86di05azOh9kWSn4b3o9QYRGCSw
GNnI3Zk0cwNKA49hZntKKiy22DhRk7JAHF01d6Bu3KkHkmENrtJ+zj/+159WAnUa
qViorq4=
-----END CERTIFICATE-----
`

func TestMD5(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(md5cert))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
	if sa := cert.SignatureAlgorithm; sa != MD5WithRSA {
		t.Errorf("signature algorithm is %v, want %v", sa, MD5WithRSA)
	}
	if err = cert.CheckSignatureFrom(cert); err == nil {
		t.Fatalf("certificate verification succeeded incorrectly")
	}
	if _, ok := err.(InsecureAlgorithmError); !ok {
		t.Fatalf("certificate verification returned %v (%T), wanted InsecureAlgorithmError", err, err)
	}
}

func TestSHA1(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(ecdsaSHA1CertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
	if sa := cert.SignatureAlgorithm; sa != ECDSAWithSHA1 {
		t.Errorf("signature algorithm is %v, want %v", sa, ECDSAWithSHA1)
	}
	if err = cert.CheckSignatureFrom(cert); err == nil {
		t.Fatalf("certificate verification succeeded incorrectly")
	}
	if _, ok := err.(InsecureAlgorithmError); !ok {
		t.Fatalf("certificate verification returned %v (%T), wanted InsecureAlgorithmError", err, err)
	}
}

// certMissingRSANULL contains an RSA public key where the AlgorithmIdentifier
// parameters are omitted rather than being an ASN.1 NULL.
const certMissingRSANULL = `
-----BEGIN CERTIFICATE-----
MIIB7TCCAVigAwIBAgIBADALBgkqhkiG9w0BAQUwJjEQMA4GA1UEChMHQWNtZSBD
bzESMBAGA1UEAxMJMTI3LjAuMC4xMB4XDTExMTIwODA3NTUxMloXDTEyMTIwNzA4
MDAxMlowJjEQMA4GA1UEChMHQWNtZSBDbzESMBAGA1UEAxMJMTI3LjAuMC4xMIGc
MAsGCSqGSIb3DQEBAQOBjAAwgYgCgYBO0Hsx44Jk2VnAwoekXh6LczPHY1PfZpIG
hPZk1Y/kNqcdK+izIDZFI7Xjla7t4PUgnI2V339aEu+H5Fto5OkOdOwEin/ekyfE
ARl6vfLcPRSr0FTKIQzQTW6HLlzF0rtNS0/Otiz3fojsfNcCkXSmHgwa2uNKWi7e
E5xMQIhZkwIDAQABozIwMDAOBgNVHQ8BAf8EBAMCAKAwDQYDVR0OBAYEBAECAwQw
DwYDVR0jBAgwBoAEAQIDBDALBgkqhkiG9w0BAQUDgYEANh+zegx1yW43RmEr1b3A
p0vMRpqBWHyFeSnIyMZn3TJWRSt1tukkqVCavh9a+hoV2cxVlXIWg7nCto/9iIw4
hB2rXZIxE0/9gzvGnfERYraL7KtnvshksBFQRlgXa5kc0x38BvEO5ZaoDPl4ILdE
GFGNEH5PlGffo05wc46QkYU=
-----END CERTIFICATE-----`

func TestRSAMissingNULLParameters(t *testing.T) {
	block, _ := pem.Decode([]byte(certMissingRSANULL))
	if _, err := ParseCertificate(block.Bytes); err == nil {
		t.Error("unexpected success when parsing certificate with missing RSA NULL parameter")
	} else if !strings.Contains(err.Error(), "missing NULL") {
		t.Errorf("unrecognised error when parsing certificate with missing RSA NULL parameter: %s", err)
	}
}

const certISOOID = `-----BEGIN CERTIFICATE-----
MIIB5TCCAVKgAwIBAgIQNwyL3RPWV7dJQp34HwZG9DAJBgUrDgMCHQUAMBExDzAN
BgNVBAMTBm15dGVzdDAeFw0xNjA4MDkyMjExMDVaFw0zOTEyMzEyMzU5NTlaMBEx
DzANBgNVBAMTBm15dGVzdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArzIH
GsyDB3ohIGkkvijF2PTRUX1bvOtY1eUUpjwHyu0twpAKSuaQv2Ha+/63+aHe8O86
BT+98wjXFX6RFSagtAujo80rIF2dSm33BGt18pDN8v6zp93dnAm0jRaSQrHJ75xw
5O+S1oEYR1LtUoFJy6qB104j6aINBAgOiLIKiMkCAwEAAaNGMEQwQgYDVR0BBDsw
OYAQVuYVQ/WDjdGSkZRlTtJDNKETMBExDzANBgNVBAMTBm15dGVzdIIQtwyL3RPW
V7dJQp34HwZG9DAJBgUrDgMCHQUAA4GBABngrSkH7vG5lY4sa4AZF59lAAXqBVJE
J4TBiKC62hCdZv18rBleP6ETfhbPg7pTs8p4ebQbpmtNxRS9Lw3MzQ8Ya5Ybwzj2
NwBSyCtCQl7mrEg4nJqJl4A2EUhnET/oVxU0oTV/SZ3ziGXcY1oG1s6vidV7TZTu
MCRtdSdaM7g3
-----END CERTIFICATE-----`

func TestISOOIDInCertificate(t *testing.T) {
	block, _ := pem.Decode([]byte(certISOOID))
	if cert, err := ParseCertificate(block.Bytes); err != nil {
		t.Errorf("certificate with ISO OID failed to parse: %s", err)
	} else if cert.SignatureAlgorithm == UnknownSignatureAlgorithm {
		t.Errorf("ISO OID not recognised in certificate")
	}
}

// certMultipleRDN contains a RelativeDistinguishedName with two elements (the
// common name and serial number). This particular certificate was the first
// such certificate in the “Pilot” Certificate Transparency log.
const certMultipleRDN = `
-----BEGIN CERTIFICATE-----
MIIFRzCCBC+gAwIBAgIEOl59NTANBgkqhkiG9w0BAQUFADA9MQswCQYDVQQGEwJz
aTEbMBkGA1UEChMSc3RhdGUtaW5zdGl0dXRpb25zMREwDwYDVQQLEwhzaWdvdi1j
YTAeFw0xMjExMTYxMDUyNTdaFw0xNzExMTYxMjQ5MDVaMIGLMQswCQYDVQQGEwJz
aTEbMBkGA1UEChMSc3RhdGUtaW5zdGl0dXRpb25zMRkwFwYDVQQLExB3ZWItY2Vy
dGlmaWNhdGVzMRAwDgYDVQQLEwdTZXJ2ZXJzMTIwFAYDVQQFEw0xMjM2NDg0MDEw
MDEwMBoGA1UEAxMTZXBvcnRhbC5tc3MuZWR1cy5zaTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMrNkZH9MPuBTjMGNk3sJX8V+CkFx/4ru7RTlLS6dlYM
098dtSfJ3s2w0p/1NB9UmR8j0yS0Kg6yoZ3ShsSO4DWBtcQD8820a6BYwqxxQTNf
HSRZOc+N/4TQrvmK6t4k9Aw+YEYTMrWOU4UTeyhDeCcUsBdh7HjfWsVaqNky+2sv
oic3zP5gF+2QfPkvOoHT3FLR8olNhViIE6Kk3eFIEs4dkq/ZzlYdLb8pHQoj/sGI
zFmA5AFvm1HURqOmJriFjBwaCtn8AVEYOtQrnUCzJYu1ex8azyS2ZgYMX0u8A5Z/
y2aMS/B2W+H79WcgLpK28vPwe7vam0oFrVytAd+u65ECAwEAAaOCAf4wggH6MA4G
A1UdDwEB/wQEAwIFoDBABgNVHSAEOTA3MDUGCisGAQQBr1kBAwMwJzAlBggrBgEF
BQcCARYZaHR0cDovL3d3dy5jYS5nb3Yuc2kvY3BzLzAfBgNVHREEGDAWgRRwb2Rw
b3JhLm1pemtzQGdvdi5zaTCB8QYDVR0fBIHpMIHmMFWgU6BRpE8wTTELMAkGA1UE
BhMCc2kxGzAZBgNVBAoTEnN0YXRlLWluc3RpdHV0aW9uczERMA8GA1UECxMIc2ln
b3YtY2ExDjAMBgNVBAMTBUNSTDM5MIGMoIGJoIGGhldsZGFwOi8veDUwMC5nb3Yu
c2kvb3U9c2lnb3YtY2Esbz1zdGF0ZS1pbnN0aXR1dGlvbnMsYz1zaT9jZXJ0aWZp
Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2WGK2h0dHA6Ly93d3cuc2lnb3YtY2EuZ292
LnNpL2NybC9zaWdvdi1jYS5jcmwwKwYDVR0QBCQwIoAPMjAxMjExMTYxMDUyNTda
gQ8yMDE3MTExNjEyNDkwNVowHwYDVR0jBBgwFoAUHvjUU2uzgwbpBAZXAvmlv8ZY
PHIwHQYDVR0OBBYEFGI1Duuu+wTGDZka/xHNbwcbM69ZMAkGA1UdEwQCMAAwGQYJ
KoZIhvZ9B0EABAwwChsEVjcuMQMCA6gwDQYJKoZIhvcNAQEFBQADggEBAHny0K1y
BQznrzDu3DDpBcGYguKU0dvU9rqsV1ua4nxkriSMWjgsX6XJFDdDW60I3P4VWab5
ag5fZzbGqi8kva/CzGgZh+CES0aWCPy+4Gb8lwOTt+854/laaJvd6kgKTER7z7U9
9C86Ch2y4sXNwwwPJ1A9dmrZJZOcJjS/WYZgwaafY2Hdxub5jqPE5nehwYUPVu9R
uH6/skk4OEKcfOtN0hCnISOVuKYyS4ANARWRG5VGHIH06z3lGUVARFRJ61gtAprd
La+fgSS+LVZ+kU2TkeoWAKvGq8MAgDq4D4Xqwekg7WKFeuyusi/NI5rm40XgjBMF
DF72IUofoVt7wo0=
-----END CERTIFICATE-----`

func TestMultipleRDN(t *testing.T) {
	block, _ := pem.Decode([]byte(certMultipleRDN))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("certificate with two elements in an RDN failed to parse: %v", err)
	}

	if want := "eportal.mss.edus.si"; cert.Subject.CommonName != want {
		t.Errorf("got common name of %q, but want %q", cert.Subject.CommonName, want)
	}

	if want := "1236484010010"; cert.Subject.SerialNumber != want {
		t.Errorf("got serial number of %q, but want %q", cert.Subject.SerialNumber, want)
	}
}

func TestSystemCertPool(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		t.Skip("not implemented on Windows (Issue 16736, 18609) or darwin (Issue 46287)")
	}
	a, err := SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	b, err := SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	if !certPoolEqual(a, b) {
		t.Fatal("two calls to SystemCertPool had different results")
	}
	if ok := b.AppendCertsFromPEM([]byte(`
-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIRANXM5I3gjuqDfTp/PYrs+u8wDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xODAzMjcxOTU2MjFaFw0xOTAzMjcxOTU2
MjFaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDK+9m3rjsO2Djes6bIYQZ3eV29JF09ZrjOrEHLtaKrD6/acsoSoTsf
cQr+rzzztdB5ijWXCS64zo/0OiqBeZUNZ67jVdToa9qW5UYe2H0Y+ZNdfA5GYMFD
yk/l3/uBu3suTZPfXiW2TjEi27Q8ruNUIZ54DpTcs6y2rBRFzadPWwn/VQMlvRXM
jrzl8Y08dgnYmaAHprxVzwMXcQ/Brol+v9GvjaH1DooHqkn8O178wsPQNhdtvN01
IXL46cYdcUwWrE/GX5u+9DaSi+0KWxAPQ+NVD5qUI0CKl4714yGGh7feXMjJdHgl
VG4QJZlJvC4FsURgCHJT6uHGIelnSwhbAgMBAAGjVzBVMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMCAGA1UdEQQZMBeC
FVRlc3RTeXN0ZW1DZXJ0UG9vbC5nbzANBgkqhkiG9w0BAQsFAAOCAQEAwuSRx/VR
BKh2ICxZjL6jBwk/7UlU1XKbhQD96RqkidDNGEc6eLZ90Z5XXTurEsXqdm5jQYPs
1cdcSW+fOSMl7MfW9e5tM66FaIPZl9rKZ1r7GkOfgn93xdLAWe8XHd19xRfDreub
YC8DVqgLASOEYFupVSl76ktPfxkU5KCvmUf3P2PrRybk1qLGFytGxfyice2gHSNI
gify3K/+H/7wCkyFW4xYvzl7WW4mXxoqPRPjQt1J423DhnnQ4G1P8V/vhUpXNXOq
N9IEPnWuihC09cyx/WMQIUlWnaQLHdfpPS04Iez3yy2PdfXJzwfPrja7rNE+skK6
pa/O1nF0AfWOpw==
-----END CERTIFICATE-----
	`)); !ok {
		t.Fatal("AppendCertsFromPEM failed")
	}
	if reflect.DeepEqual(a, b) {
		t.Fatal("changing one pool modified the other")
	}
}

const emptyNameConstraintsPEM = `
-----BEGIN CERTIFICATE-----
MIIC1jCCAb6gAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRW1w
dHkgbmFtZSBjb25zdHJhaW50cyBpc3N1ZXIwHhcNMTMwMjAxMDAwMDAwWhcNMjAw
NTMwMTA0ODM4WjAhMR8wHQYDVQQDExZFbXB0eSBuYW1lIGNvbnN0cmFpbnRzMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwriElUIt3LCqmJObs+yDoWPD
F5IqgWk6moIobYjPfextZiYU6I3EfvAwoNxPDkN2WowcocUZMJbEeEq5ebBksFnx
f12gBxlIViIYwZAzu7aFvhDMyPKQI3C8CG0ZSC9ABZ1E3umdA3CEueNOmP/TChNq
Cl23+BG1Qb/PJkpAO+GfpWSVhTcV53Mf/cKvFHcjGNrxzdSoq9fyW7a6gfcGEQY0
LVkmwFWUfJ0wT8kaeLr0E0tozkIfo01KNWNzv6NcYP80QOBRDlApWu9ODmEVJHPD
blx4jzTQ3JLa+4DvBNOjVUOp+mgRmjiW0rLdrxwOxIqIOwNjweMCp/hgxX/hTQID
AQABoxEwDzANBgNVHR4EBjAEoAChADANBgkqhkiG9w0BAQsFAAOCAQEAWG+/zUMH
QhP8uNCtgSHyim/vh7wminwAvWgMKxlkLBFns6nZeQqsOV1lABY7U0Zuoqa1Z5nb
6L+iJa4ElREJOi/erLc9uLwBdDCAR0hUTKD7a6i4ooS39DTle87cUnj0MW1CUa6H
v5SsvpYW+1XleYJk/axQOOTcy4Es53dvnZsjXH0EA/QHnn7UV+JmlE3rtVxcYp6M
LYPmRhTioROA/drghicRkiu9hxdPyxkYS16M5g3Zj30jdm+k/6C6PeNtN9YmOOga
nCOSyFYfGhqOANYzpmuV+oIedAsPpIbfIzN8njYUs1zio+1IoI4o8ddM9sCbtPU8
o+WoY6IsCKXV/g==
-----END CERTIFICATE-----`

func TestEmptyNameConstraints(t *testing.T) {
	block, _ := pem.Decode([]byte(emptyNameConstraintsPEM))
	_, err := ParseCertificate(block.Bytes)
	if err == nil {
		t.Fatal("unexpected success")
	}

	const expected = "empty name constraints"
	if str := err.Error(); !strings.Contains(str, expected) {
		t.Errorf("expected %q in error but got %q", expected, str)
	}
}

func TestPKIXNameString(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParseCertificates(der)
	if err != nil {
		t.Fatal(err)
	}

	// Check that parsed non-standard attributes are printed.
	rdns := pkix.Name{
		Locality: []string{"Gophertown"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
	}.ToRDNSequence()
	nn := pkix.Name{}
	nn.FillFromRDNSequence(&rdns)

	// Check that zero-length non-nil ExtraNames hide Names.
	extra := []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "backing array"}}
	extraNotNil := pkix.Name{
		Locality:   []string{"Gophertown"},
		ExtraNames: extra[:0],
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
	}

	tests := []struct {
		dn   pkix.Name
		want string
	}{
		{nn, "L=Gophertown,1.2.3.4.5=#130a676f6c616e672e6f7267"},
		{extraNotNil, "L=Gophertown"},
		{pkix.Name{
			CommonName:         "Steve Kille",
			Organization:       []string{"Isode Limited"},
			OrganizationalUnit: []string{"RFCs"},
			Locality:           []string{"Richmond"},
			Province:           []string{"Surrey"},
			StreetAddress:      []string{"The Square"},
			PostalCode:         []string{"TW9 1DT"},
			SerialNumber:       "RFC 2253",
			Country:            []string{"GB"},
		}, "SERIALNUMBER=RFC 2253,CN=Steve Kille,OU=RFCs,O=Isode Limited,POSTALCODE=TW9 1DT,STREET=The Square,L=Richmond,ST=Surrey,C=GB"},
		{certs[0].Subject,
			"CN=mail.google.com,O=Google LLC,L=Mountain View,ST=California,C=US"},
		{pkix.Name{
			Organization: []string{"#Google, Inc. \n-> 'Alphabet\" "},
			Country:      []string{"US"},
		}, "O=\\#Google\\, Inc. \n-\\> 'Alphabet\\\"\\ ,C=US"},
		{pkix.Name{
			CommonName:   "foo.com",
			Organization: []string{"Gopher Industries"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{2, 5, 4, 3}), Value: "bar.com"}},
		}, "CN=bar.com,O=Gopher Industries"},
		{pkix.Name{
			Locality: []string{"Gophertown"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
		}, "1.2.3.4.5=#130a676f6c616e672e6f7267,L=Gophertown"},
		// If there are no ExtraNames, the Names are printed instead.
		{pkix.Name{
			Locality: []string{"Gophertown"},
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
		}, "L=Gophertown,1.2.3.4.5=#130a676f6c616e672e6f7267"},
		// If there are both, print only the ExtraNames.
		{pkix.Name{
			Locality: []string{"Gophertown"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 6}), Value: "example.com"}},
		}, "1.2.3.4.5=#130a676f6c616e672e6f7267,L=Gophertown"},
	}

	for i, test := range tests {
		if got := test.dn.String(); got != test.want {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, got, test.want)
		}
	}

	if extra[0].Value != "backing array" {
		t.Errorf("the backing array of an empty ExtraNames got modified by String")
	}
}

func TestRDNSequenceString(t *testing.T) {
	// Test some extra cases that get lost in pkix.Name conversions such as
	// multi-valued attributes.

	var (
		oidCountry            = []int{2, 5, 4, 6}
		oidOrganization       = []int{2, 5, 4, 10}
		oidOrganizationalUnit = []int{2, 5, 4, 11}
		oidCommonName         = []int{2, 5, 4, 3}
	)

	tests := []struct {
		seq  pkix.RDNSequence
		want string
	}{
		{
			seq: pkix.RDNSequence{
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidCountry, Value: "US"},
				},
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidOrganization, Value: "Widget Inc."},
				},
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidOrganizationalUnit, Value: "Sales"},
					pkix.AttributeTypeAndValue{Type: oidCommonName, Value: "J. Smith"},
				},
			},
			want: "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US",
		},
	}

	for i, test := range tests {
		if got := test.seq.String(); got != test.want {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, got, test.want)
		}
	}
}

const criticalNameConstraintWithUnknownTypePEM = `
-----BEGIN CERTIFICATE-----
MIIC/TCCAeWgAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRW1w
dHkgbmFtZSBjb25zdHJhaW50cyBpc3N1ZXIwHhcNMTMwMjAxMDAwMDAwWhcNMjAw
NTMwMTA0ODM4WjAhMR8wHQYDVQQDExZFbXB0eSBuYW1lIGNvbnN0cmFpbnRzMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwriElUIt3LCqmJObs+yDoWPD
F5IqgWk6moIobYjPfextZiYU6I3EfvAwoNxPDkN2WowcocUZMJbEeEq5ebBksFnx
f12gBxlIViIYwZAzu7aFvhDMyPKQI3C8CG0ZSC9ABZ1E3umdA3CEueNOmP/TChNq
Cl23+BG1Qb/PJkpAO+GfpWSVhTcV53Mf/cKvFHcjGNrxzdSoq9fyW7a6gfcGEQY0
LVkmwFWUfJ0wT8kaeLr0E0tozkIfo01KNWNzv6NcYP80QOBRDlApWu9ODmEVJHPD
blx4jzTQ3JLa+4DvBNOjVUOp+mgRmjiW0rLdrxwOxIqIOwNjweMCp/hgxX/hTQID
AQABozgwNjA0BgNVHR4BAf8EKjAooCQwIokgIACrzQAAAAAAAAAAAAAAAP////8A
AAAAAAAAAAAAAAChADANBgkqhkiG9w0BAQsFAAOCAQEAWG+/zUMHQhP8uNCtgSHy
im/vh7wminwAvWgMKxlkLBFns6nZeQqsOV1lABY7U0Zuoqa1Z5nb6L+iJa4ElREJ
Oi/erLc9uLwBdDCAR0hUTKD7a6i4ooS39DTle87cUnj0MW1CUa6Hv5SsvpYW+1Xl
eYJk/axQOOTcy4Es53dvnZsjXH0EA/QHnn7UV+JmlE3rtVxcYp6MLYPmRhTioROA
/drghicRkiu9hxdPyxkYS16M5g3Zj30jdm+k/6C6PeNtN9YmOOganCOSyFYfGhqO
ANYzpmuV+oIedAsPpIbfIzN8njYUs1zio+1IoI4o8ddM9sCbtPU8o+WoY6IsCKXV
/g==
-----END CERTIFICATE-----`

func TestCriticalNameConstraintWithUnknownType(t *testing.T) {
	block, _ := pem.Decode([]byte(criticalNameConstraintWithUnknownTypePEM))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("unexpected parsing failure: %s", err)
	}

	if l := len(cert.UnhandledCriticalExtensions); l != 1 {
		t.Fatalf("expected one unhandled critical extension, but found %d", l)
	}
}

const badIPMaskPEM = `
-----BEGIN CERTIFICATE-----
MIICzzCCAbegAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAxMSQmFk
IElQIG1hc2sgaXNzdWVyMB4XDTEzMDIwMTAwMDAwMFoXDTIwMDUzMDEwNDgzOFow
FjEUMBIGA1UEAxMLQmFkIElQIG1hc2swggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDCuISVQi3csKqYk5uz7IOhY8MXkiqBaTqagihtiM997G1mJhTojcR+
8DCg3E8OQ3ZajByhxRkwlsR4Srl5sGSwWfF/XaAHGUhWIhjBkDO7toW+EMzI8pAj
cLwIbRlIL0AFnUTe6Z0DcIS5406Y/9MKE2oKXbf4EbVBv88mSkA74Z+lZJWFNxXn
cx/9wq8UdyMY2vHN1Kir1/JbtrqB9wYRBjQtWSbAVZR8nTBPyRp4uvQTS2jOQh+j
TUo1Y3O/o1xg/zRA4FEOUCla704OYRUkc8NuXHiPNNDcktr7gO8E06NVQ6n6aBGa
OJbSst2vHA7Eiog7A2PB4wKn+GDFf+FNAgMBAAGjIDAeMBwGA1UdHgEB/wQSMBCg
DDAKhwgBAgME//8BAKEAMA0GCSqGSIb3DQEBCwUAA4IBAQBYb7/NQwdCE/y40K2B
IfKKb++HvCaKfAC9aAwrGWQsEWezqdl5Cqw5XWUAFjtTRm6iprVnmdvov6IlrgSV
EQk6L96stz24vAF0MIBHSFRMoPtrqLiihLf0NOV7ztxSePQxbUJRroe/lKy+lhb7
VeV5gmT9rFA45NzLgSznd2+dmyNcfQQD9AeeftRX4maUTeu1XFxinowtg+ZGFOKh
E4D92uCGJxGSK72HF0/LGRhLXozmDdmPfSN2b6T/oLo942031iY46BqcI5LIVh8a
Go4A1jOma5X6gh50Cw+kht8jM3yeNhSzXOKj7Uigjijx10z2wJu09Tyj5ahjoiwI
pdX+
-----END CERTIFICATE-----`

func TestBadIPMask(t *testing.T) {
	block, _ := pem.Decode([]byte(badIPMaskPEM))
	_, err := ParseCertificate(block.Bytes)
	if err == nil {
		t.Fatalf("unexpected success")
	}

	const expected = "contained invalid mask"
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected %q in error but got: %s", expected, err)
	}
}

const additionalGeneralSubtreePEM = `
-----BEGIN CERTIFICATE-----
MIIG4TCCBMmgAwIBAgIRALss+4rLw2Ia7tFFhxE8g5cwDQYJKoZIhvcNAQELBQAw
bjELMAkGA1UEBhMCTkwxIDAeBgNVBAoMF01pbmlzdGVyaWUgdmFuIERlZmVuc2ll
MT0wOwYDVQQDDDRNaW5pc3RlcmllIHZhbiBEZWZlbnNpZSBDZXJ0aWZpY2F0aWUg
QXV0b3JpdGVpdCAtIEcyMB4XDTEzMDMwNjEyMDM0OVoXDTEzMTEzMDEyMDM1MFow
bDELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUNlcnRpUGF0aCBMTEMxIjAgBgNVBAsT
GUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXM
"""




```