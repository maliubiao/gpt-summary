Response:
The user has provided the second part of a Go source code file (`tls_test.go`) and is asking for its functionality and related information. This is part 2 of 3, so I need to summarize the functionality covered in this specific section.

**Breakdown of the code:**

1. **`TestHandshakeComplete` function:** Checks the `HandshakeState` information after a successful handshake with ALPN. It verifies fields like `HandshakeComplete`, `DidResume`, `CipherSuite`, `NegotiatedProtocol`, `ServerName`, `PeerCertificates`, `VerifiedChains`, `SignedCertificateTimestamps`, `OCSPResponse`, and `TLSUnique`. It runs for different TLS versions.

2. **`TestBuildNameToCertificate_doesntModifyCertificates` function:**  Tests that calling `BuildNameToCertificate` on a `Config` doesn't modify the original `Certificates` slice.

3. **`TestClientHelloInfo_SupportsCertificate` function:** Tests the `SupportsCertificate` method of `ClientHelloInfo`. This method determines if a given certificate is suitable for the provided client hello information based on factors like server name, supported signature algorithms, supported versions, cipher suites, and supported curves.

4. **`TestCipherSuites` function:**  Tests the functionality and properties of cipher suites, including their ordering, security status, supported versions, and names. It checks both secure and insecure cipher suites. It also validates the preference order of cipher suites.

5. **`TestVersionName` function:**  Tests the `VersionName` function, which returns a human-readable name for a TLS version number.

6. **`http2isBadCipher` function:** (Copied from `net/http`) Determines if a given cipher suite is considered bad for HTTP/2.

7. **`TestPKCS1OnlyCert` function:** Tests the scenario where a client certificate only supports PKCS #1 v1.5 signatures and ensures the handshake fails with RSA-PSS (TLS 1.3) but succeeds when supported algorithms are restricted (TLS 1.2).

8. **`TestVerifyCertificates` and `testVerifyCertificates` functions:** Tests different client authentication modes and verifies that the `VerifyPeerCertificate` and `VerifyConnection` hooks are called correctly during handshakes and resumptions.

9. **`TestHandshakeMLKEM` function:** Tests the handshake process when using ML-KEM (hybrid key exchange). It verifies client support, successful ML-KEM negotiation, and fallback to HRR (HelloRetryRequest). It also includes tests for different configurations and the `GODEBUG` setting for disabling ML-KEM.

10. **`TestX509KeyPairPopulateCertificate` function:** Tests the behavior of `X509KeyPair` regarding populating the `Leaf` field of the returned `Certificate`. It checks the effect of the `x509keypairleaf` `GODEBUG` setting.

11. **`TestEarlyLargeCertMsg` function:** Tests the handling of early handshake messages (specifically Certificate) that exceed the maximum allowed length.

12. **`TestLargeCertMsg` function:** Tests the handling of large certificate messages during the handshake. It creates a certificate with extra extensions to exceed the typical record size.

13. **`TestECH` function:** Starts testing Encrypted ClientHello (ECH) functionality. It includes helper functions to marshal ECH configurations.

**Summary of Functionality:**

This section of `tls_test.go` primarily focuses on testing various aspects of the TLS handshake process and the configuration options that influence it. It covers:

*   **Verifying handshake state after a successful connection.**
*   **Ensuring immutability of certificate lists in the `Config`.**
*   **Validating the certificate selection logic based on the `ClientHelloInfo`.**
*   **Testing the properties and ordering of different TLS cipher suites.**
*   **Testing the retrieval of TLS version names.**
*   **Handling client certificates with limited signature algorithm support.**
*   **Testing different client authentication modes and the `VerifyConnection`/`VerifyPeerCertificate` hooks.**
*   **Testing the negotiation of ML-KEM (hybrid key exchange) during the handshake.**
*   **Testing the population of the `Leaf` field in `Certificate` created with `X509KeyPair`.**
*   **Testing the handling of oversized certificate messages during the handshake.**
*   **Initial testing of the Encrypted ClientHello (ECH) feature.**
这是 `go/src/crypto/tls/tls_test.go` 文件的第二部分，它主要包含以下功能的测试：

1. **验证握手完成后的连接状态信息:**  `TestHandshakeComplete` 函数测试在 TLS 握手成功后，`ConnectionState` 结构体中的信息是否正确。它检查了诸如握手是否完成、是否是会话恢复、选择的密码套件、协商的 ALPN 协议、服务器名称、对等证书、验证链、签名证书时间戳 (SCTs)、OCSP 响应以及 `TLSUnique` 等信息。这个测试覆盖了不同的 TLS 版本。

2. **验证 `BuildNameToCertificate` 方法不会修改原始证书列表:** `TestBuildNameToCertificate_doesntModifyCertificates` 函数确保在 `Config` 结构体上调用 `BuildNameToCertificate` 方法后，其原始的 `Certificates` 列表不会被修改。这对于保证配置的不可变性很重要。

3. **测试 `ClientHelloInfo` 的 `SupportsCertificate` 方法:** `TestClientHelloInfo_SupportsCertificate` 函数测试了 `ClientHelloInfo` 结构体的 `SupportsCertificate` 方法。该方法用于判断一个给定的证书是否适用于当前的客户端 Hello 信息，它会根据服务器名称、支持的签名算法、支持的 TLS 版本、客户端提供的密码套件以及支持的曲线等信息进行判断。

4. **测试密码套件的相关功能:** `TestCipherSuites` 函数测试了密码套件的各种属性和功能，包括其排序、是否安全、支持的 TLS 版本以及名称等。它还区分了安全和不安全的密码套件，并验证了密码套件的偏好顺序。

5. **测试 TLS 版本名称的获取:** `TestVersionName` 函数测试了 `VersionName` 函数，该函数可以将 TLS 版本号转换为可读的字符串名称。

6. **判断密码套件是否对 HTTP/2 不友好:** `http2isBadCipher` 函数（从 `net/http` 包复制而来）用于判断一个给定的密码套件是否被认为是 HTTP/2 的不良密码套件。

7. **测试仅支持 PKCS#1 v1.5 签名的客户端证书:** `TestPKCS1OnlyCert` 函数模拟了一个客户端证书只支持 PKCS #1 v1.5 签名的情况，并验证在启用 RSA-PSS 的 TLS 1.3 下握手会失败，而在限制签名算法的 TLS 1.2 下握手会成功。

8. **测试证书验证过程:** `TestVerifyCertificates` 和 `testVerifyCertificates` 函数测试了不同的客户端认证模式，并验证了在握手和会话恢复过程中 `VerifyPeerCertificate` 和 `VerifyConnection` 回调函数是否被正确调用。

9. **测试基于 ML-KEM 的握手:** `TestHandshakeMLKEM` 函数测试了在使用 ML-KEM (Memory-Locked Key Exchange Mechanism) 时的握手过程。它验证了客户端是否支持 ML-KEM，是否成功协商了 ML-KEM，以及是否会回退到 HelloRetryRequest (HRR)。它还包含了针对不同配置以及通过 `GODEBUG` 设置禁用 ML-KEM 的测试。

10. **测试 `X509KeyPair` 函数填充证书的 `Leaf` 字段:** `TestX509KeyPairPopulateCertificate` 函数测试了 `X509KeyPair` 函数在创建 `Certificate` 对象时，是否会根据 `x509keypairleaf` 这个 `GODEBUG` 环境变量来决定是否填充 `Leaf` 字段。

11. **测试过早收到过大的证书消息:** `TestEarlyLargeCertMsg` 函数测试了在握手早期阶段（例如收到客户端发送的过大的 Certificate 消息）时，程序是否能正确处理并报错。

12. **测试接收到过大的证书消息:** `TestLargeCertMsg` 函数测试了在 TLS 握手过程中接收到大小超过常规记录大小的证书消息时的情况。它创建了一个包含额外扩展的证书来模拟这种情况。

13. **初步测试 ECH (Encrypted ClientHello):** `TestECH` 函数开始测试加密客户端 Hello (ECH) 功能。它包含了一个用于编组 ECH 配置的辅助函数。

**归纳一下它的功能:**

这部分 `tls_test.go` 的主要功能是 **全面测试 Go 语言 `crypto/tls` 包中关于 TLS 握手过程、连接状态、证书处理、密码套件选择、客户端认证机制以及一些高级特性 (如 ML-KEM 和 ECH) 的实现是否正确**。它通过构造不同的场景和配置，验证 TLS 协议的各个细节是否符合预期。

Prompt: 
```
这是路径为go/src/crypto/tls/tls_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
andshakeComplete %v (server) and %v (client), expected true", ss.HandshakeComplete, cs.HandshakeComplete)
			}

			if ss.DidResume || cs.DidResume {
				t.Errorf("Got DidResume %v (server) and %v (client), expected false", ss.DidResume, cs.DidResume)
			}

			if ss.CipherSuite == 0 || cs.CipherSuite == 0 {
				t.Errorf("Got invalid cipher suite: %v (server) and %v (client)", ss.CipherSuite, cs.CipherSuite)
			}

			if ss.NegotiatedProtocol != alpnProtocol || cs.NegotiatedProtocol != alpnProtocol {
				t.Errorf("Got negotiated protocol %q (server) and %q (client), expected %q", ss.NegotiatedProtocol, cs.NegotiatedProtocol, alpnProtocol)
			}

			if !cs.NegotiatedProtocolIsMutual {
				t.Errorf("Got false NegotiatedProtocolIsMutual on the client side")
			}
			// NegotiatedProtocolIsMutual on the server side is unspecified.

			if ss.ServerName != serverName {
				t.Errorf("Got server name %q, expected %q", ss.ServerName, serverName)
			}
			if cs.ServerName != serverName {
				t.Errorf("Got server name on client connection %q, expected %q", cs.ServerName, serverName)
			}

			if len(ss.PeerCertificates) != 1 || len(cs.PeerCertificates) != 1 {
				t.Errorf("Got %d (server) and %d (client) peer certificates, expected %d", len(ss.PeerCertificates), len(cs.PeerCertificates), 1)
			}

			if len(ss.VerifiedChains) != 1 || len(cs.VerifiedChains) != 1 {
				t.Errorf("Got %d (server) and %d (client) verified chains, expected %d", len(ss.VerifiedChains), len(cs.VerifiedChains), 1)
			} else if len(ss.VerifiedChains[0]) != 2 || len(cs.VerifiedChains[0]) != 2 {
				t.Errorf("Got %d (server) and %d (client) long verified chain, expected %d", len(ss.VerifiedChains[0]), len(cs.VerifiedChains[0]), 2)
			}

			if len(cs.SignedCertificateTimestamps) != 2 {
				t.Errorf("Got %d SCTs, expected %d", len(cs.SignedCertificateTimestamps), 2)
			}
			if !bytes.Equal(cs.OCSPResponse, ocsp) {
				t.Errorf("Got OCSPs %x, expected %x", cs.OCSPResponse, ocsp)
			}
			// Only TLS 1.3 supports OCSP and SCTs on client certs.
			if v == VersionTLS13 {
				if len(ss.SignedCertificateTimestamps) != 2 {
					t.Errorf("Got %d client SCTs, expected %d", len(ss.SignedCertificateTimestamps), 2)
				}
				if !bytes.Equal(ss.OCSPResponse, ocsp) {
					t.Errorf("Got client OCSPs %x, expected %x", ss.OCSPResponse, ocsp)
				}
			}

			if v == VersionTLS13 {
				if ss.TLSUnique != nil || cs.TLSUnique != nil {
					t.Errorf("Got TLSUnique %x (server) and %x (client), expected nil in TLS 1.3", ss.TLSUnique, cs.TLSUnique)
				}
			} else {
				if ss.TLSUnique == nil || cs.TLSUnique == nil {
					t.Errorf("Got TLSUnique %x (server) and %x (client), expected non-nil", ss.TLSUnique, cs.TLSUnique)
				}
			}
		})
	}
}

// Issue 28744: Ensure that we don't modify memory
// that Config doesn't own such as Certificates.
func TestBuildNameToCertificate_doesntModifyCertificates(t *testing.T) {
	c0 := Certificate{
		Certificate: [][]byte{testRSACertificate},
		PrivateKey:  testRSAPrivateKey,
	}
	c1 := Certificate{
		Certificate: [][]byte{testSNICertificate},
		PrivateKey:  testRSAPrivateKey,
	}
	config := testConfig.Clone()
	config.Certificates = []Certificate{c0, c1}

	config.BuildNameToCertificate()
	got := config.Certificates
	want := []Certificate{c0, c1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Certificates were mutated by BuildNameToCertificate\nGot: %#v\nWant: %#v\n", got, want)
	}
}

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

func TestClientHelloInfo_SupportsCertificate(t *testing.T) {
	skipFIPS(t) // Test certificates not FIPS compatible.

	rsaCert := &Certificate{
		Certificate: [][]byte{testRSACertificate},
		PrivateKey:  testRSAPrivateKey,
	}
	pkcs1Cert := &Certificate{
		Certificate:                  [][]byte{testRSACertificate},
		PrivateKey:                   testRSAPrivateKey,
		SupportedSignatureAlgorithms: []SignatureScheme{PKCS1WithSHA1, PKCS1WithSHA256},
	}
	ecdsaCert := &Certificate{
		// ECDSA P-256 certificate
		Certificate: [][]byte{testP256Certificate},
		PrivateKey:  testP256PrivateKey,
	}
	ed25519Cert := &Certificate{
		Certificate: [][]byte{testEd25519Certificate},
		PrivateKey:  testEd25519PrivateKey,
	}

	tests := []struct {
		c       *Certificate
		chi     *ClientHelloInfo
		wantErr string
	}{
		{rsaCert, &ClientHelloInfo{
			ServerName:        "example.golang",
			SignatureSchemes:  []SignatureScheme{PSSWithSHA256},
			SupportedVersions: []uint16{VersionTLS13},
		}, ""},
		{ecdsaCert, &ClientHelloInfo{
			SignatureSchemes:  []SignatureScheme{PSSWithSHA256, ECDSAWithP256AndSHA256},
			SupportedVersions: []uint16{VersionTLS13, VersionTLS12},
		}, ""},
		{rsaCert, &ClientHelloInfo{
			ServerName:        "example.com",
			SignatureSchemes:  []SignatureScheme{PSSWithSHA256},
			SupportedVersions: []uint16{VersionTLS13},
		}, "not valid for requested server name"},
		{ecdsaCert, &ClientHelloInfo{
			SignatureSchemes:  []SignatureScheme{ECDSAWithP384AndSHA384},
			SupportedVersions: []uint16{VersionTLS13},
		}, "signature algorithms"},
		{pkcs1Cert, &ClientHelloInfo{
			SignatureSchemes:  []SignatureScheme{PSSWithSHA256, ECDSAWithP256AndSHA256},
			SupportedVersions: []uint16{VersionTLS13},
		}, "signature algorithms"},

		{rsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			SignatureSchemes:  []SignatureScheme{PKCS1WithSHA1},
			SupportedVersions: []uint16{VersionTLS13, VersionTLS12},
		}, "signature algorithms"},
		{rsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			SignatureSchemes:  []SignatureScheme{PKCS1WithSHA1},
			SupportedVersions: []uint16{VersionTLS13, VersionTLS12},
			config: &Config{
				CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
				MaxVersion:   VersionTLS12,
			},
		}, ""}, // Check that mutual version selection works.

		{ecdsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256},
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
			SupportedVersions: []uint16{VersionTLS12},
		}, ""},
		{ecdsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256},
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{ECDSAWithP384AndSHA384},
			SupportedVersions: []uint16{VersionTLS12},
		}, ""}, // TLS 1.2 does not restrict curves based on the SignatureScheme.
		{ecdsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256},
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  nil,
			SupportedVersions: []uint16{VersionTLS12},
		}, ""}, // TLS 1.2 comes with default signature schemes.
		{ecdsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256},
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
			SupportedVersions: []uint16{VersionTLS12},
		}, "cipher suite"},
		{ecdsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256},
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
			SupportedVersions: []uint16{VersionTLS12},
			config: &Config{
				CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			},
		}, "cipher suite"},
		{ecdsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP384},
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
			SupportedVersions: []uint16{VersionTLS12},
		}, "certificate curve"},
		{ecdsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256},
			SupportedPoints:   []uint8{1},
			SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
			SupportedVersions: []uint16{VersionTLS12},
		}, "doesn't support ECDHE"},
		{ecdsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256},
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{PSSWithSHA256},
			SupportedVersions: []uint16{VersionTLS12},
		}, "signature algorithms"},

		{ed25519Cert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256}, // only relevant for ECDHE support
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{Ed25519},
			SupportedVersions: []uint16{VersionTLS12},
		}, ""},
		{ed25519Cert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256}, // only relevant for ECDHE support
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{Ed25519},
			SupportedVersions: []uint16{VersionTLS10},
			config:            &Config{MinVersion: VersionTLS10},
		}, "doesn't support Ed25519"},
		{ed25519Cert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{},
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{Ed25519},
			SupportedVersions: []uint16{VersionTLS12},
		}, "doesn't support ECDHE"},

		{rsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			SupportedCurves:   []CurveID{CurveP256}, // only relevant for ECDHE support
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SupportedVersions: []uint16{VersionTLS10},
			config:            &Config{MinVersion: VersionTLS10},
		}, ""},
		{rsaCert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			SupportedVersions: []uint16{VersionTLS12},
			config: &Config{
				CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			},
		}, ""}, // static RSA fallback
	}
	for i, tt := range tests {
		err := tt.chi.SupportsCertificate(tt.c)
		switch {
		case tt.wantErr == "" && err != nil:
			t.Errorf("%d: unexpected error: %v", i, err)
		case tt.wantErr != "" && err == nil:
			t.Errorf("%d: unexpected success", i)
		case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
			t.Errorf("%d: got error %q, expected %q", i, err, tt.wantErr)
		}
	}
}

func TestCipherSuites(t *testing.T) {
	var lastID uint16
	for _, c := range CipherSuites() {
		if lastID > c.ID {
			t.Errorf("CipherSuites are not ordered by ID: got %#04x after %#04x", c.ID, lastID)
		} else {
			lastID = c.ID
		}

		if c.Insecure {
			t.Errorf("%#04x: Insecure CipherSuite returned by CipherSuites()", c.ID)
		}
	}
	lastID = 0
	for _, c := range InsecureCipherSuites() {
		if lastID > c.ID {
			t.Errorf("InsecureCipherSuites are not ordered by ID: got %#04x after %#04x", c.ID, lastID)
		} else {
			lastID = c.ID
		}

		if !c.Insecure {
			t.Errorf("%#04x: not Insecure CipherSuite returned by InsecureCipherSuites()", c.ID)
		}
	}

	CipherSuiteByID := func(id uint16) *CipherSuite {
		for _, c := range CipherSuites() {
			if c.ID == id {
				return c
			}
		}
		for _, c := range InsecureCipherSuites() {
			if c.ID == id {
				return c
			}
		}
		return nil
	}

	for _, c := range cipherSuites {
		cc := CipherSuiteByID(c.id)
		if cc == nil {
			t.Errorf("%#04x: no CipherSuite entry", c.id)
			continue
		}

		if tls12Only := c.flags&suiteTLS12 != 0; tls12Only && len(cc.SupportedVersions) != 1 {
			t.Errorf("%#04x: suite is TLS 1.2 only, but SupportedVersions is %v", c.id, cc.SupportedVersions)
		} else if !tls12Only && len(cc.SupportedVersions) != 3 {
			t.Errorf("%#04x: suite TLS 1.0-1.2, but SupportedVersions is %v", c.id, cc.SupportedVersions)
		}

		if cc.Insecure {
			if slices.Contains(defaultCipherSuites(), c.id) {
				t.Errorf("%#04x: insecure suite in default list", c.id)
			}
		} else {
			if !slices.Contains(defaultCipherSuites(), c.id) {
				t.Errorf("%#04x: secure suite not in default list", c.id)
			}
		}

		if got := CipherSuiteName(c.id); got != cc.Name {
			t.Errorf("%#04x: unexpected CipherSuiteName: got %q, expected %q", c.id, got, cc.Name)
		}
	}
	for _, c := range cipherSuitesTLS13 {
		cc := CipherSuiteByID(c.id)
		if cc == nil {
			t.Errorf("%#04x: no CipherSuite entry", c.id)
			continue
		}

		if cc.Insecure {
			t.Errorf("%#04x: Insecure %v, expected false", c.id, cc.Insecure)
		}
		if len(cc.SupportedVersions) != 1 || cc.SupportedVersions[0] != VersionTLS13 {
			t.Errorf("%#04x: suite is TLS 1.3 only, but SupportedVersions is %v", c.id, cc.SupportedVersions)
		}

		if got := CipherSuiteName(c.id); got != cc.Name {
			t.Errorf("%#04x: unexpected CipherSuiteName: got %q, expected %q", c.id, got, cc.Name)
		}
	}

	if got := CipherSuiteName(0xabc); got != "0x0ABC" {
		t.Errorf("unexpected fallback CipherSuiteName: got %q, expected 0x0ABC", got)
	}

	if len(cipherSuitesPreferenceOrder) != len(cipherSuites) {
		t.Errorf("cipherSuitesPreferenceOrder is not the same size as cipherSuites")
	}
	if len(cipherSuitesPreferenceOrderNoAES) != len(cipherSuitesPreferenceOrder) {
		t.Errorf("cipherSuitesPreferenceOrderNoAES is not the same size as cipherSuitesPreferenceOrder")
	}

	// Check that disabled suites are marked insecure.
	for _, badSuites := range []map[uint16]bool{disabledCipherSuites, rsaKexCiphers} {
		for id := range badSuites {
			c := CipherSuiteByID(id)
			if c == nil {
				t.Errorf("%#04x: no CipherSuite entry", id)
				continue
			}
			if !c.Insecure {
				t.Errorf("%#04x: disabled by default but not marked insecure", id)
			}
		}
	}

	for i, prefOrder := range [][]uint16{cipherSuitesPreferenceOrder, cipherSuitesPreferenceOrderNoAES} {
		// Check that insecure and HTTP/2 bad cipher suites are at the end of
		// the preference lists.
		var sawInsecure, sawBad bool
		for _, id := range prefOrder {
			c := CipherSuiteByID(id)
			if c == nil {
				t.Errorf("%#04x: no CipherSuite entry", id)
				continue
			}

			if c.Insecure {
				sawInsecure = true
			} else if sawInsecure {
				t.Errorf("%#04x: secure suite after insecure one(s)", id)
			}

			if http2isBadCipher(id) {
				sawBad = true
			} else if sawBad {
				t.Errorf("%#04x: non-bad suite after bad HTTP/2 one(s)", id)
			}
		}

		// Check that the list is sorted according to the documented criteria.
		isBetter := func(a, b uint16) int {
			aSuite, bSuite := cipherSuiteByID(a), cipherSuiteByID(b)
			aName, bName := CipherSuiteName(a), CipherSuiteName(b)
			// * < RC4
			if !strings.Contains(aName, "RC4") && strings.Contains(bName, "RC4") {
				return -1
			} else if strings.Contains(aName, "RC4") && !strings.Contains(bName, "RC4") {
				return +1
			}
			// * < CBC_SHA256
			if !strings.Contains(aName, "CBC_SHA256") && strings.Contains(bName, "CBC_SHA256") {
				return -1
			} else if strings.Contains(aName, "CBC_SHA256") && !strings.Contains(bName, "CBC_SHA256") {
				return +1
			}
			// * < 3DES
			if !strings.Contains(aName, "3DES") && strings.Contains(bName, "3DES") {
				return -1
			} else if strings.Contains(aName, "3DES") && !strings.Contains(bName, "3DES") {
				return +1
			}
			// ECDHE < *
			if aSuite.flags&suiteECDHE != 0 && bSuite.flags&suiteECDHE == 0 {
				return -1
			} else if aSuite.flags&suiteECDHE == 0 && bSuite.flags&suiteECDHE != 0 {
				return +1
			}
			// AEAD < CBC
			if aSuite.aead != nil && bSuite.aead == nil {
				return -1
			} else if aSuite.aead == nil && bSuite.aead != nil {
				return +1
			}
			// AES < ChaCha20
			if strings.Contains(aName, "AES") && strings.Contains(bName, "CHACHA20") {
				// negative for cipherSuitesPreferenceOrder
				if i == 0 {
					return -1
				} else {
					return +1
				}
			} else if strings.Contains(aName, "CHACHA20") && strings.Contains(bName, "AES") {
				// negative for cipherSuitesPreferenceOrderNoAES
				if i != 0 {
					return -1
				} else {
					return +1
				}
			}
			// AES-128 < AES-256
			if strings.Contains(aName, "AES_128") && strings.Contains(bName, "AES_256") {
				return -1
			} else if strings.Contains(aName, "AES_256") && strings.Contains(bName, "AES_128") {
				return +1
			}
			// ECDSA < RSA
			if aSuite.flags&suiteECSign != 0 && bSuite.flags&suiteECSign == 0 {
				return -1
			} else if aSuite.flags&suiteECSign == 0 && bSuite.flags&suiteECSign != 0 {
				return +1
			}
			t.Fatalf("two ciphersuites are equal by all criteria: %v and %v", aName, bName)
			panic("unreachable")
		}
		if !slices.IsSortedFunc(prefOrder, isBetter) {
			t.Error("preference order is not sorted according to the rules")
		}
	}
}

func TestVersionName(t *testing.T) {
	if got, exp := VersionName(VersionTLS13), "TLS 1.3"; got != exp {
		t.Errorf("unexpected VersionName: got %q, expected %q", got, exp)
	}
	if got, exp := VersionName(0x12a), "0x012A"; got != exp {
		t.Errorf("unexpected fallback VersionName: got %q, expected %q", got, exp)
	}
}

// http2isBadCipher is copied from net/http.
// TODO: if it ends up exposed somewhere, use that instead.
func http2isBadCipher(cipher uint16) bool {
	switch cipher {
	case TLS_RSA_WITH_RC4_128_SHA,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA256,
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return true
	default:
		return false
	}
}

type brokenSigner struct{ crypto.Signer }

func (s brokenSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// Replace opts with opts.HashFunc(), so rsa.PSSOptions are discarded.
	return s.Signer.Sign(rand, digest, opts.HashFunc())
}

// TestPKCS1OnlyCert uses a client certificate with a broken crypto.Signer that
// always makes PKCS #1 v1.5 signatures, so can't be used with RSA-PSS.
func TestPKCS1OnlyCert(t *testing.T) {
	clientConfig := testConfig.Clone()
	clientConfig.Certificates = []Certificate{{
		Certificate: [][]byte{testRSACertificate},
		PrivateKey:  brokenSigner{testRSAPrivateKey},
	}}
	serverConfig := testConfig.Clone()
	serverConfig.MaxVersion = VersionTLS12 // TLS 1.3 doesn't support PKCS #1 v1.5
	serverConfig.ClientAuth = RequireAnyClientCert

	// If RSA-PSS is selected, the handshake should fail.
	if _, _, err := testHandshake(t, clientConfig, serverConfig); err == nil {
		t.Fatal("expected broken certificate to cause connection to fail")
	}

	clientConfig.Certificates[0].SupportedSignatureAlgorithms =
		[]SignatureScheme{PKCS1WithSHA1, PKCS1WithSHA256}

	// But if the certificate restricts supported algorithms, RSA-PSS should not
	// be selected, and the handshake should succeed.
	if _, _, err := testHandshake(t, clientConfig, serverConfig); err != nil {
		t.Error(err)
	}
}

func TestVerifyCertificates(t *testing.T) {
	skipFIPS(t) // Test certificates not FIPS compatible.

	// See https://go.dev/issue/31641.
	t.Run("TLSv12", func(t *testing.T) { testVerifyCertificates(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testVerifyCertificates(t, VersionTLS13) })
}

func testVerifyCertificates(t *testing.T, version uint16) {
	tests := []struct {
		name string

		InsecureSkipVerify bool
		ClientAuth         ClientAuthType
		ClientCertificates bool
	}{
		{
			name: "defaults",
		},
		{
			name:               "InsecureSkipVerify",
			InsecureSkipVerify: true,
		},
		{
			name:       "RequestClientCert with no certs",
			ClientAuth: RequestClientCert,
		},
		{
			name:               "RequestClientCert with certs",
			ClientAuth:         RequestClientCert,
			ClientCertificates: true,
		},
		{
			name:               "RequireAnyClientCert",
			ClientAuth:         RequireAnyClientCert,
			ClientCertificates: true,
		},
		{
			name:       "VerifyClientCertIfGiven with no certs",
			ClientAuth: VerifyClientCertIfGiven,
		},
		{
			name:               "VerifyClientCertIfGiven with certs",
			ClientAuth:         VerifyClientCertIfGiven,
			ClientCertificates: true,
		},
		{
			name:               "RequireAndVerifyClientCert",
			ClientAuth:         RequireAndVerifyClientCert,
			ClientCertificates: true,
		},
	}

	issuer, err := x509.ParseCertificate(testRSACertificateIssuer)
	if err != nil {
		t.Fatal(err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(issuer)

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var serverVerifyConnection, clientVerifyConnection bool
			var serverVerifyPeerCertificates, clientVerifyPeerCertificates bool

			clientConfig := testConfig.Clone()
			clientConfig.Time = func() time.Time { return time.Unix(1476984729, 0) }
			clientConfig.MaxVersion = version
			clientConfig.MinVersion = version
			clientConfig.RootCAs = rootCAs
			clientConfig.ServerName = "example.golang"
			clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
			serverConfig := clientConfig.Clone()
			serverConfig.ClientCAs = rootCAs

			clientConfig.VerifyConnection = func(cs ConnectionState) error {
				clientVerifyConnection = true
				return nil
			}
			clientConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				clientVerifyPeerCertificates = true
				return nil
			}
			serverConfig.VerifyConnection = func(cs ConnectionState) error {
				serverVerifyConnection = true
				return nil
			}
			serverConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				serverVerifyPeerCertificates = true
				return nil
			}

			clientConfig.InsecureSkipVerify = test.InsecureSkipVerify
			serverConfig.ClientAuth = test.ClientAuth
			if !test.ClientCertificates {
				clientConfig.Certificates = nil
			}

			if _, _, err := testHandshake(t, clientConfig, serverConfig); err != nil {
				t.Fatal(err)
			}

			want := serverConfig.ClientAuth != NoClientCert
			if serverVerifyPeerCertificates != want {
				t.Errorf("VerifyPeerCertificates on the server: got %v, want %v",
					serverVerifyPeerCertificates, want)
			}
			if !clientVerifyPeerCertificates {
				t.Errorf("VerifyPeerCertificates not called on the client")
			}
			if !serverVerifyConnection {
				t.Error("VerifyConnection did not get called on the server")
			}
			if !clientVerifyConnection {
				t.Error("VerifyConnection did not get called on the client")
			}

			serverVerifyPeerCertificates, clientVerifyPeerCertificates = false, false
			serverVerifyConnection, clientVerifyConnection = false, false
			cs, _, err := testHandshake(t, clientConfig, serverConfig)
			if err != nil {
				t.Fatal(err)
			}
			if !cs.DidResume {
				t.Error("expected resumption")
			}

			if serverVerifyPeerCertificates {
				t.Error("VerifyPeerCertificates got called on the server on resumption")
			}
			if clientVerifyPeerCertificates {
				t.Error("VerifyPeerCertificates got called on the client on resumption")
			}
			if !serverVerifyConnection {
				t.Error("VerifyConnection did not get called on the server on resumption")
			}
			if !clientVerifyConnection {
				t.Error("VerifyConnection did not get called on the client on resumption")
			}
		})
	}
}

func TestHandshakeMLKEM(t *testing.T) {
	skipFIPS(t) // No X25519MLKEM768 in FIPS
	var tests = []struct {
		name                string
		clientConfig        func(*Config)
		serverConfig        func(*Config)
		preparation         func(*testing.T)
		expectClientSupport bool
		expectMLKEM         bool
		expectHRR           bool
	}{
		{
			name:                "Default",
			expectClientSupport: true,
			expectMLKEM:         true,
			expectHRR:           false,
		},
		{
			name: "ClientCurvePreferences",
			clientConfig: func(config *Config) {
				config.CurvePreferences = []CurveID{X25519}
			},
			expectClientSupport: false,
		},
		{
			name: "ServerCurvePreferencesX25519",
			serverConfig: func(config *Config) {
				config.CurvePreferences = []CurveID{X25519}
			},
			expectClientSupport: true,
			expectMLKEM:         false,
			expectHRR:           false,
		},
		{
			name: "ServerCurvePreferencesHRR",
			serverConfig: func(config *Config) {
				config.CurvePreferences = []CurveID{CurveP256}
			},
			expectClientSupport: true,
			expectMLKEM:         false,
			expectHRR:           true,
		},
		{
			name: "ClientMLKEMOnly",
			clientConfig: func(config *Config) {
				config.CurvePreferences = []CurveID{X25519MLKEM768}
			},
			expectClientSupport: true,
			expectMLKEM:         true,
		},
		{
			name: "ClientSortedCurvePreferences",
			clientConfig: func(config *Config) {
				config.CurvePreferences = []CurveID{CurveP256, X25519MLKEM768}
			},
			expectClientSupport: true,
			expectMLKEM:         true,
		},
		{
			name: "ClientTLSv12",
			clientConfig: func(config *Config) {
				config.MaxVersion = VersionTLS12
			},
			expectClientSupport: false,
		},
		{
			name: "ServerTLSv12",
			serverConfig: func(config *Config) {
				config.MaxVersion = VersionTLS12
			},
			expectClientSupport: true,
			expectMLKEM:         false,
		},
		{
			name: "GODEBUG",
			preparation: func(t *testing.T) {
				t.Setenv("GODEBUG", "tlsmlkem=0")
			},
			expectClientSupport: false,
		},
	}

	baseConfig := testConfig.Clone()
	baseConfig.CurvePreferences = nil
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.preparation != nil {
				test.preparation(t)
			} else {
				t.Parallel()
			}
			serverConfig := baseConfig.Clone()
			if test.serverConfig != nil {
				test.serverConfig(serverConfig)
			}
			serverConfig.GetConfigForClient = func(hello *ClientHelloInfo) (*Config, error) {
				if !test.expectClientSupport && slices.Contains(hello.SupportedCurves, X25519MLKEM768) {
					return nil, errors.New("client supports X25519MLKEM768")
				} else if test.expectClientSupport && !slices.Contains(hello.SupportedCurves, X25519MLKEM768) {
					return nil, errors.New("client does not support X25519MLKEM768")
				}
				return nil, nil
			}
			clientConfig := baseConfig.Clone()
			if test.clientConfig != nil {
				test.clientConfig(clientConfig)
			}
			ss, cs, err := testHandshake(t, clientConfig, serverConfig)
			if err != nil {
				t.Fatal(err)
			}
			if test.expectMLKEM {
				if ss.testingOnlyCurveID != X25519MLKEM768 {
					t.Errorf("got CurveID %v (server), expected %v", ss.testingOnlyCurveID, X25519MLKEM768)
				}
				if cs.testingOnlyCurveID != X25519MLKEM768 {
					t.Errorf("got CurveID %v (client), expected %v", cs.testingOnlyCurveID, X25519MLKEM768)
				}
			} else {
				if ss.testingOnlyCurveID == X25519MLKEM768 {
					t.Errorf("got CurveID %v (server), expected not X25519MLKEM768", ss.testingOnlyCurveID)
				}
				if cs.testingOnlyCurveID == X25519MLKEM768 {
					t.Errorf("got CurveID %v (client), expected not X25519MLKEM768", cs.testingOnlyCurveID)
				}
			}
			if test.expectHRR {
				if !ss.testingOnlyDidHRR {
					t.Error("server did not use HRR")
				}
				if !cs.testingOnlyDidHRR {
					t.Error("client did not use HRR")
				}
			} else {
				if ss.testingOnlyDidHRR {
					t.Error("server used HRR")
				}
				if cs.testingOnlyDidHRR {
					t.Error("client used HRR")
				}
			}
		})
	}
}

func TestX509KeyPairPopulateCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	t.Run("x509keypairleaf=0", func(t *testing.T) {
		t.Setenv("GODEBUG", "x509keypairleaf=0")
		cert, err := X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		if cert.Leaf != nil {
			t.Fatal("Leaf should not be populated")
		}
	})
	t.Run("x509keypairleaf=1", func(t *testing.T) {
		t.Setenv("GODEBUG", "x509keypairleaf=1")
		cert, err := X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		if cert.Leaf == nil {
			t.Fatal("Leaf should be populated")
		}
	})
	t.Run("GODEBUG unset", func(t *testing.T) {
		cert, err := X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		if cert.Leaf == nil {
			t.Fatal("Leaf should be populated")
		}
	})
}

func TestEarlyLargeCertMsg(t *testing.T) {
	client, server := localPipe(t)

	go func() {
		if _, err := client.Write([]byte{byte(recordTypeHandshake), 3, 4, 0, 4, typeCertificate, 1, 255, 255}); err != nil {
			t.Log(err)
		}
	}()

	expectedErr := "tls: handshake message of length 131071 bytes exceeds maximum of 65536 bytes"
	servConn := Server(server, testConfig)
	err := servConn.Handshake()
	if err == nil {
		t.Fatal("unexpected success")
	}
	if err.Error() != expectedErr {
		t.Fatalf("unexpected error: got %q, want %q", err, expectedErr)
	}
}

func TestLargeCertMsg(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		ExtraExtensions: []pkix.Extension{
			{
				Id: asn1.ObjectIdentifier{1, 2, 3},
				// Ballast to inflate the certificate beyond the
				// regular handshake record size.
				Value: make([]byte, 65536),
			},
		},
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}

	clientConfig, serverConfig := testConfig.Clone(), testConfig.Clone()
	clientConfig.InsecureSkipVerify = true
	serverConfig.Certificates = []Certificate{
		{
			Certificate: [][]byte{cert},
			PrivateKey:  k,
		},
	}
	if _, _, err := testHandshake(t, clientConfig, serverConfig); err != nil {
		t.Fatalf("unexpected failure: %s", err)
	}
}

func TestECH(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"public.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	publicCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	publicCert, err := x509.ParseCertificate(publicCertDER)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.DNSNames[0] = "secret.example"
	secretCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	secretCert, err := x509.ParseCertificate(secretCertDER)
	if err != nil {
		t.Fatal(err)
	}

	marshalECHConfig := func(id uint8, pubKey []byte, publicName string, maxNameLen uint8) []byte {
		builder := cryptobyte.NewBuilder(nil)
		builder.AddUint16(extensionEncryptedClientHello)
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddUint8(id)
			builder.AddUint16(hpke.DHKEM_X25519_HKDF_SHA256) // The only DHKEM we support
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddBytes(pubKey)
			})
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				for _, aeadID := range sortedSupportedAEADs {
					builder.AddUint16(hpke.KDF_HKDF_SHA256) // The only KDF we support
					builder.AddUint16(aeadID)
				}
			})
			builder.AddUint8(maxNameLen)
			builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddBytes([]byte(publicName))
			})
			builder.AddUint16(0) // extensions
		})

		return builder.BytesOrPanic()
	}

	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	echConfig := marshalECHConfig(123, echKey.PublicKey().Bytes(), "public.example", 32)

	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(echConfig)
	})
	echConfigList := builder.BytesOrPanic()

	clientConfig, serverConfig := testConfig.Clone(), testConfig.Clone()
	clientConfig.InsecureSkipVerify = false
	clientConfig.Rand = ran
"""




```