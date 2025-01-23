Response:
Let's break down the thought process for summarizing the provided Go code snippet.

1. **Understand the Goal:** The primary goal is to summarize the functionality of the provided Go code, which is a part of the `handshake_client_test.go` file within the `crypto/tls` package. This means focusing on what aspects of the TLS client handshake are being tested.

2. **Initial Scan for Key Functions and Test Names:** Quickly scan the code for function names starting with `Test`. These are the core units of functionality being examined. List them out:

   * `TestBrokenServerKey`
   * `TestHandshakeRace`
   * `TestGetClientCertificate` (and the helper `testGetClientCertificate`)
   * `TestRSAPSSKeyError`
   * `TestCloseClientConnectionOnIdleServer`
   * `TestDowngradeCanary` (and the helper `testDowngradeCanary`)
   * `TestResumptionKeepsOCSPAndSCT` (and the helper `testResumptionKeepsOCSPAndSCT`)
   * `TestClientHandshakeContextCancellation`
   * `TestTLS13OnlyClientHelloCipherSuite` (and the helper `testTLS13OnlyClientHelloCipherSuite`)
   * `TestHandshakeRSATooBig`
   * `TestTLS13ECHRejectionCallbacks`
   * `TestECHTLS12Server`

3. **Analyze Each Test Function (Iterative Process):**  Go through each test function and identify its purpose. Look for the following patterns:

   * **Setup:** What configuration is being established for the client and server (e.g., certificates, versions, custom functions)?
   * **Action:** What is the core action being tested (e.g., calling `Client(…).Handshake()`, reading/writing)?
   * **Assertion:** What is the expected outcome? Is an error expected?  Are specific values in the `ConnectionState` being checked?

4. **Group Similar Functionality:**  Notice that some tests have related themes. For example, several tests deal with specific TLS versions (`TestGetClientCertificate` with `TLSv12` and `TLSv13`, `TestResumptionKeepsOCSPAndSCT` with `TLSv12` and `TLSv13`). Group these related tests in the summary.

5. **Identify Specific TLS Features Being Tested:** As you analyze the tests, note down the specific TLS features being targeted:

   * Handshake with a broken server key
   * Race conditions in the handshake
   * Client certificate handling (`GetClientCertificate`)
   * Handling of RSASSA-PSS certificates
   * Closing connections on idle servers
   * Downgrade attack detection (canary values)
   * Session resumption and preservation of OCSP and SCT data
   * Context cancellation during handshake
   * Advertising correct cipher suites for TLS 1.3 only clients
   * Handling of large RSA keys
   * Encrypted Client Hello (ECH) and rejection callbacks
   * ECH with TLS 1.2 servers

6. **Synthesize High-Level Functionality:**  Based on the individual test analyses, synthesize a high-level description of the code's overall function. This code is clearly focused on testing the *client-side* of the TLS handshake in various scenarios.

7. **Formulate the Summary:** Write a concise summary that captures the essence of the code. Use clear and descriptive language. Avoid overly technical jargon where possible. Highlight the major areas of testing.

8. **Refine and Organize:** Review the summary for clarity, accuracy, and completeness. Organize the points logically. For example, group tests related to specific TLS features or error conditions.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This code tests the TLS handshake."  **Refinement:** "This code *specifically* tests the *client side* of the TLS handshake."
* **Realizing a pattern:**  "Many tests involve setting up server and client configurations and then calling `Client(…).Handshake()`."  **Refinement:**  Focus on the *differences* in these setups and the *specific assertions* being made in each test.
* **Overly detailed summary:**  Listing every single assertion in every test. **Refinement:**  Focus on the *general purpose* of each test function rather than getting bogged down in implementation details.
* **Missing key concepts:** Forgetting to explicitly mention features like session resumption or ECH. **Refinement:** Review the identified TLS features and ensure they are included in the summary.

By following these steps, we can systematically analyze the code and generate a comprehensive and accurate summary of its functionality. The iterative process and self-correction help to refine the understanding and improve the quality of the summary.
这是对Go语言 `crypto/tls` 包中客户端握手功能的测试代码的第三部分，延续了之前对各种客户端握手场景的测试。

**归纳一下它的功能：**

这部分代码主要专注于测试 `crypto/tls` 包中客户端在 TLS 握手过程中的各种复杂情况和特定功能，包括：

* **处理服务端返回的错误私钥:** 测试客户端在与配置了错误私钥的服务端进行握手时能否正确捕获并报告错误。
* **并发握手测试:**  通过并发读写操作模拟高并发场景，验证握手过程中的锁机制是否正确，避免死锁和竞态条件。
* **客户端证书获取 (`GetClientCertificate`):**  测试客户端通过 `GetClientCertificate` 回调函数获取证书的各种情况，例如：
    * 返回空证书。
    * 在 TLS 1.1 下 `SignatureSchemes` 的生成。
    * 返回错误导致握手失败。
    * 返回有效证书并进行验证。
* **处理 RSASSA-PSS 密钥的错误:**  验证代码能否正确处理或拒绝使用 RSASSA-PSS 算法的证书，避免潜在的误用。
* **处理服务端空闲时的客户端连接关闭:** 测试当服务端处于空闲状态时，客户端能否正确关闭连接并处理可能出现的超时错误。
* **降级攻击检测 (Downgrade Canary):** 测试客户端是否能够检测到服务端尝试降级 TLS 版本，并采取相应的安全措施。
* **会话恢复与 OCSP 和 SCT 信息保留:** 测试在 TLS 会话恢复后，客户端是否能够正确保留和使用之前的 OCSP Staple 和 Signed Certificate Timestamps 信息。
* **客户端握手上下文取消:** 测试使用 `HandshakeContext` 方法时，如果上下文被取消，客户端握手是否能被正确中断。
* **TLS 1.3 专属客户端 Hello 消息的 Cipher Suites:** 测试当客户端声明只支持 TLS 1.3 时，发送的 ClientHello 消息中是否只包含 TLS 1.3 支持的密码套件。
* **处理过大的 RSA 密钥:** 测试客户端和服务端在遇到包含过大 RSA 密钥的证书时是否会报错。
* **TLS 1.3 ECH 拒绝回调:** 测试 TLS 1.3 的 Encrypted Client Hello (ECH) 功能被服务端拒绝时的回调函数 (`VerifyConnection`, `VerifyPeerCertificate`, `EncryptedClientHelloRejectionVerify`) 的行为。
* **TLS 1.2 服务端处理 ECH:** 测试当客户端尝试与仅支持 TLS 1.2 的服务端使用 ECH 时，是否会产生预期的错误。

总而言之，这部分代码深入测试了 TLS 客户端握手过程中的各种边界情况、错误处理、安全特性和协议细节，确保 `crypto/tls` 包的客户端实现是健壮和安全的。

### 提示词
```
这是路径为go/src/crypto/tls/handshake_client_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
rsa.PrivateKey{PublicKey: testRSAPrivateKey.PublicKey}
	brokenKey.D = big.NewInt(42)
	serverConfig.Certificates = []Certificate{{
		Certificate: [][]byte{testRSACertificate},
		PrivateKey:  &brokenKey,
	}}

	go func() {
		Server(serverWCC, serverConfig).Handshake()
		serverWCC.Close()
		done <- true
	}()

	err := Client(clientWCC, testConfig).Handshake()
	if err == nil {
		t.Fatal("client unexpectedly returned no error")
	}

	const expectedError = "remote error: tls: internal error"
	if e := err.Error(); !strings.Contains(e, expectedError) {
		t.Fatalf("expected to find %q in error but error was %q", expectedError, e)
	}
	clientWCC.Close()
	<-done

	if n := serverWCC.numWrites; n != 1 {
		t.Errorf("expected server handshake to complete with one write, but saw %d", n)
	}
}

func TestHandshakeRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	t.Parallel()
	// This test races a Read and Write to try and complete a handshake in
	// order to provide some evidence that there are no races or deadlocks
	// in the handshake locking.
	for i := 0; i < 32; i++ {
		c, s := localPipe(t)

		go func() {
			server := Server(s, testConfig)
			if err := server.Handshake(); err != nil {
				panic(err)
			}

			var request [1]byte
			if n, err := server.Read(request[:]); err != nil || n != 1 {
				panic(err)
			}

			server.Write(request[:])
			server.Close()
		}()

		startWrite := make(chan struct{})
		startRead := make(chan struct{})
		readDone := make(chan struct{}, 1)

		client := Client(c, testConfig)
		go func() {
			<-startWrite
			var request [1]byte
			client.Write(request[:])
		}()

		go func() {
			<-startRead
			var reply [1]byte
			if _, err := io.ReadFull(client, reply[:]); err != nil {
				panic(err)
			}
			c.Close()
			readDone <- struct{}{}
		}()

		if i&1 == 1 {
			startWrite <- struct{}{}
			startRead <- struct{}{}
		} else {
			startRead <- struct{}{}
			startWrite <- struct{}{}
		}
		<-readDone
	}
}

var getClientCertificateTests = []struct {
	setup               func(*Config, *Config)
	expectedClientError string
	verify              func(*testing.T, int, *ConnectionState)
}{
	{
		func(clientConfig, serverConfig *Config) {
			// Returning a Certificate with no certificate data
			// should result in an empty message being sent to the
			// server.
			serverConfig.ClientCAs = nil
			clientConfig.GetClientCertificate = func(cri *CertificateRequestInfo) (*Certificate, error) {
				if len(cri.SignatureSchemes) == 0 {
					panic("empty SignatureSchemes")
				}
				if len(cri.AcceptableCAs) != 0 {
					panic("AcceptableCAs should have been empty")
				}
				return new(Certificate), nil
			}
		},
		"",
		func(t *testing.T, testNum int, cs *ConnectionState) {
			if l := len(cs.PeerCertificates); l != 0 {
				t.Errorf("#%d: expected no certificates but got %d", testNum, l)
			}
		},
	},
	{
		func(clientConfig, serverConfig *Config) {
			// With TLS 1.1, the SignatureSchemes should be
			// synthesised from the supported certificate types.
			clientConfig.MaxVersion = VersionTLS11
			clientConfig.GetClientCertificate = func(cri *CertificateRequestInfo) (*Certificate, error) {
				if len(cri.SignatureSchemes) == 0 {
					panic("empty SignatureSchemes")
				}
				return new(Certificate), nil
			}
		},
		"",
		func(t *testing.T, testNum int, cs *ConnectionState) {
			if l := len(cs.PeerCertificates); l != 0 {
				t.Errorf("#%d: expected no certificates but got %d", testNum, l)
			}
		},
	},
	{
		func(clientConfig, serverConfig *Config) {
			// Returning an error should abort the handshake with
			// that error.
			clientConfig.GetClientCertificate = func(cri *CertificateRequestInfo) (*Certificate, error) {
				return nil, errors.New("GetClientCertificate")
			}
		},
		"GetClientCertificate",
		func(t *testing.T, testNum int, cs *ConnectionState) {
		},
	},
	{
		func(clientConfig, serverConfig *Config) {
			clientConfig.GetClientCertificate = func(cri *CertificateRequestInfo) (*Certificate, error) {
				if len(cri.AcceptableCAs) == 0 {
					panic("empty AcceptableCAs")
				}
				cert := &Certificate{
					Certificate: [][]byte{testRSA2048Certificate},
					PrivateKey:  testRSA2048PrivateKey,
				}
				return cert, nil
			}
		},
		"",
		func(t *testing.T, testNum int, cs *ConnectionState) {
			if len(cs.VerifiedChains) == 0 {
				t.Errorf("#%d: expected some verified chains, but found none", testNum)
			}
		},
	},
}

func TestGetClientCertificate(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testGetClientCertificate(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testGetClientCertificate(t, VersionTLS13) })
}

func testGetClientCertificate(t *testing.T, version uint16) {
	// Note: using RSA 2048 test certificates because they are compatible with FIPS mode.
	issuer, err := x509.ParseCertificate(testRSA2048CertificateIssuer)
	if err != nil {
		panic(err)
	}

	for i, test := range getClientCertificateTests {
		serverConfig := testConfig.Clone()
		serverConfig.Certificates = []Certificate{{Certificate: [][]byte{testRSA2048Certificate}, PrivateKey: testRSA2048PrivateKey}}
		serverConfig.ClientAuth = VerifyClientCertIfGiven
		serverConfig.RootCAs = x509.NewCertPool()
		serverConfig.RootCAs.AddCert(issuer)
		serverConfig.ClientCAs = serverConfig.RootCAs
		serverConfig.Time = func() time.Time { return time.Unix(1476984729, 0) }
		serverConfig.MaxVersion = version

		clientConfig := testConfig.Clone()
		clientConfig.Certificates = []Certificate{{Certificate: [][]byte{testRSA2048Certificate}, PrivateKey: testRSA2048PrivateKey}}
		clientConfig.MaxVersion = version

		test.setup(clientConfig, serverConfig)

		// TLS 1.1 isn't available for FIPS required
		if fips140tls.Required() && clientConfig.MaxVersion == VersionTLS11 {
			t.Logf("skipping test %d for FIPS mode", i)
			continue
		}

		type serverResult struct {
			cs  ConnectionState
			err error
		}

		c, s := localPipe(t)
		done := make(chan serverResult)

		go func() {
			defer s.Close()
			server := Server(s, serverConfig)
			err := server.Handshake()

			var cs ConnectionState
			if err == nil {
				cs = server.ConnectionState()
			}
			done <- serverResult{cs, err}
		}()

		clientErr := Client(c, clientConfig).Handshake()
		c.Close()

		result := <-done

		if clientErr != nil {
			if len(test.expectedClientError) == 0 {
				t.Errorf("#%d: client error: %v", i, clientErr)
			} else if got := clientErr.Error(); got != test.expectedClientError {
				t.Errorf("#%d: expected client error %q, but got %q", i, test.expectedClientError, got)
			} else {
				test.verify(t, i, &result.cs)
			}
		} else if len(test.expectedClientError) > 0 {
			t.Errorf("#%d: expected client error %q, but got no error", i, test.expectedClientError)
		} else if err := result.err; err != nil {
			t.Errorf("#%d: server error: %v", i, err)
		} else {
			test.verify(t, i, &result.cs)
		}
	}
}

func TestRSAPSSKeyError(t *testing.T) {
	// crypto/tls does not support the rsa_pss_pss_* SignatureSchemes. If support for
	// public keys with OID RSASSA-PSS is added to crypto/x509, they will be misused with
	// the rsa_pss_rsae_* SignatureSchemes. Assert that RSASSA-PSS certificates don't
	// parse, or that they don't carry *rsa.PublicKey keys.
	b, _ := pem.Decode([]byte(`
-----BEGIN CERTIFICATE-----
MIIDZTCCAhygAwIBAgIUCF2x0FyTgZG0CC9QTDjGWkB5vgEwPgYJKoZIhvcNAQEK
MDGgDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBogQC
AgDeMBIxEDAOBgNVBAMMB1JTQS1QU1MwHhcNMTgwNjI3MjI0NDM2WhcNMTgwNzI3
MjI0NDM2WjASMRAwDgYDVQQDDAdSU0EtUFNTMIIBIDALBgkqhkiG9w0BAQoDggEP
ADCCAQoCggEBANxDm0f76JdI06YzsjB3AmmjIYkwUEGxePlafmIASFjDZl/elD0Z
/a7xLX468b0qGxLS5al7XCcEprSdsDR6DF5L520+pCbpfLyPOjuOvGmk9KzVX4x5
b05YXYuXdsQ0Kjxcx2i3jjCday6scIhMJVgBZxTEyMj1thPQM14SHzKCd/m6HmCL
QmswpH2yMAAcBRWzRpp/vdH5DeOJEB3aelq7094no731mrLUCHRiZ1htq8BDB3ou
czwqgwspbqZ4dnMXl2MvfySQ5wJUxQwILbiuAKO2lVVPUbFXHE9pgtznNoPvKwQT
JNcX8ee8WIZc2SEGzofjk3NpjR+2ADB2u3sCAwEAAaNTMFEwHQYDVR0OBBYEFNEz
AdyJ2f+fU+vSCS6QzohnOnprMB8GA1UdIwQYMBaAFNEzAdyJ2f+fU+vSCS6Qzohn
OnprMA8GA1UdEwEB/wQFMAMBAf8wPgYJKoZIhvcNAQEKMDGgDTALBglghkgBZQME
AgGhGjAYBgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBogQCAgDeA4IBAQCjEdrR5aab
sZmCwrMeKidXgfkmWvfuLDE+TCbaqDZp7BMWcMQXT9O0UoUT5kqgKj2ARm2pEW0Z
H3Z1vj3bbds72qcDIJXp+l0fekyLGeCrX/CbgnMZXEP7+/+P416p34ChR1Wz4dU1
KD3gdsUuTKKeMUog3plxlxQDhRQmiL25ygH1LmjLd6dtIt0GVRGr8lj3euVeprqZ
bZ3Uq5eLfsn8oPgfC57gpO6yiN+UURRTlK3bgYvLh4VWB3XXk9UaQZ7Mq1tpXjoD
HYFybkWzibkZp4WRo+Fa28rirH+/wHt0vfeN7UCceURZEx4JaxIIfe4ku7uDRhJi
RwBA9Xk1KBNF
-----END CERTIFICATE-----`))
	if b == nil {
		t.Fatal("Failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		t.Error("A RSASSA-PSS certificate was parsed like a PKCS#1 v1.5 one, and it will be mistakenly used with rsa_pss_rsae_* signature algorithms")
	}
}

func TestCloseClientConnectionOnIdleServer(t *testing.T) {
	clientConn, serverConn := localPipe(t)
	client := Client(clientConn, testConfig.Clone())
	go func() {
		var b [1]byte
		serverConn.Read(b[:])
		client.Close()
	}()
	client.SetWriteDeadline(time.Now().Add(time.Minute))
	err := client.Handshake()
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			t.Errorf("Expected a closed network connection error but got '%s'", err.Error())
		}
	} else {
		t.Errorf("Error expected, but no error returned")
	}
}

func testDowngradeCanary(t *testing.T, clientVersion, serverVersion uint16) error {
	defer func() { testingOnlyForceDowngradeCanary = false }()
	testingOnlyForceDowngradeCanary = true

	clientConfig := testConfig.Clone()
	clientConfig.MaxVersion = clientVersion
	serverConfig := testConfig.Clone()
	serverConfig.MaxVersion = serverVersion
	_, _, err := testHandshake(t, clientConfig, serverConfig)
	return err
}

func TestDowngradeCanary(t *testing.T) {
	if err := testDowngradeCanary(t, VersionTLS13, VersionTLS12); err == nil {
		t.Errorf("downgrade from TLS 1.3 to TLS 1.2 was not detected")
	}
	if testing.Short() {
		t.Skip("skipping the rest of the checks in short mode")
	}
	if err := testDowngradeCanary(t, VersionTLS13, VersionTLS11); err == nil {
		t.Errorf("downgrade from TLS 1.3 to TLS 1.1 was not detected")
	}
	if err := testDowngradeCanary(t, VersionTLS13, VersionTLS10); err == nil {
		t.Errorf("downgrade from TLS 1.3 to TLS 1.0 was not detected")
	}
	if err := testDowngradeCanary(t, VersionTLS12, VersionTLS11); err == nil {
		t.Errorf("downgrade from TLS 1.2 to TLS 1.1 was not detected")
	}
	if err := testDowngradeCanary(t, VersionTLS12, VersionTLS10); err == nil {
		t.Errorf("downgrade from TLS 1.2 to TLS 1.0 was not detected")
	}
	if err := testDowngradeCanary(t, VersionTLS13, VersionTLS13); err != nil {
		t.Errorf("server unexpectedly sent downgrade canary for TLS 1.3")
	}
	if err := testDowngradeCanary(t, VersionTLS12, VersionTLS12); err != nil {
		t.Errorf("client didn't ignore expected TLS 1.2 canary")
	}
	if !fips140tls.Required() {
		if err := testDowngradeCanary(t, VersionTLS11, VersionTLS11); err != nil {
			t.Errorf("client unexpectedly reacted to a canary in TLS 1.1")
		}
		if err := testDowngradeCanary(t, VersionTLS10, VersionTLS10); err != nil {
			t.Errorf("client unexpectedly reacted to a canary in TLS 1.0")
		}
	} else {
		t.Logf("skiping TLS 1.1 and TLS 1.0 downgrade canary checks in FIPS mode")
	}
}

func TestResumptionKeepsOCSPAndSCT(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testResumptionKeepsOCSPAndSCT(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testResumptionKeepsOCSPAndSCT(t, VersionTLS13) })
}

func testResumptionKeepsOCSPAndSCT(t *testing.T, ver uint16) {
	// Note: using RSA 2048 test certificates because they are compatible with FIPS mode.
	issuer, err := x509.ParseCertificate(testRSA2048CertificateIssuer)
	if err != nil {
		t.Fatalf("failed to parse test issuer")
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	clientConfig := &Config{
		MaxVersion:         ver,
		ClientSessionCache: NewLRUClientSessionCache(32),
		ServerName:         "example.golang",
		RootCAs:            roots,
	}
	serverConfig := testConfig.Clone()
	serverConfig.Certificates = []Certificate{{Certificate: [][]byte{testRSA2048Certificate}, PrivateKey: testRSA2048PrivateKey}}
	serverConfig.MaxVersion = ver
	serverConfig.Certificates[0].OCSPStaple = []byte{1, 2, 3}
	serverConfig.Certificates[0].SignedCertificateTimestamps = [][]byte{{4, 5, 6}}

	_, ccs, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
	// after a new session we expect to see OCSPResponse and
	// SignedCertificateTimestamps populated as usual
	if !bytes.Equal(ccs.OCSPResponse, serverConfig.Certificates[0].OCSPStaple) {
		t.Errorf("client ConnectionState contained unexpected OCSPResponse: wanted %v, got %v",
			serverConfig.Certificates[0].OCSPStaple, ccs.OCSPResponse)
	}
	if !reflect.DeepEqual(ccs.SignedCertificateTimestamps, serverConfig.Certificates[0].SignedCertificateTimestamps) {
		t.Errorf("client ConnectionState contained unexpected SignedCertificateTimestamps: wanted %v, got %v",
			serverConfig.Certificates[0].SignedCertificateTimestamps, ccs.SignedCertificateTimestamps)
	}

	// if the server doesn't send any SCTs, repopulate the old SCTs
	oldSCTs := serverConfig.Certificates[0].SignedCertificateTimestamps
	serverConfig.Certificates[0].SignedCertificateTimestamps = nil
	_, ccs, err = testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
	if !ccs.DidResume {
		t.Fatalf("expected session to be resumed")
	}
	// after a resumed session we also expect to see OCSPResponse
	// and SignedCertificateTimestamps populated
	if !bytes.Equal(ccs.OCSPResponse, serverConfig.Certificates[0].OCSPStaple) {
		t.Errorf("client ConnectionState contained unexpected OCSPResponse after resumption: wanted %v, got %v",
			serverConfig.Certificates[0].OCSPStaple, ccs.OCSPResponse)
	}
	if !reflect.DeepEqual(ccs.SignedCertificateTimestamps, oldSCTs) {
		t.Errorf("client ConnectionState contained unexpected SignedCertificateTimestamps after resumption: wanted %v, got %v",
			oldSCTs, ccs.SignedCertificateTimestamps)
	}

	//  Only test overriding the SCTs for TLS 1.2, since in 1.3
	// the server won't send the message containing them
	if ver == VersionTLS13 {
		return
	}

	// if the server changes the SCTs it sends, they should override the saved SCTs
	serverConfig.Certificates[0].SignedCertificateTimestamps = [][]byte{{7, 8, 9}}
	_, ccs, err = testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
	if !ccs.DidResume {
		t.Fatalf("expected session to be resumed")
	}
	if !reflect.DeepEqual(ccs.SignedCertificateTimestamps, serverConfig.Certificates[0].SignedCertificateTimestamps) {
		t.Errorf("client ConnectionState contained unexpected SignedCertificateTimestamps after resumption: wanted %v, got %v",
			serverConfig.Certificates[0].SignedCertificateTimestamps, ccs.SignedCertificateTimestamps)
	}
}

// TestClientHandshakeContextCancellation tests that canceling
// the context given to the client side conn.HandshakeContext
// interrupts the in-progress handshake.
func TestClientHandshakeContextCancellation(t *testing.T) {
	c, s := localPipe(t)
	ctx, cancel := context.WithCancel(context.Background())
	unblockServer := make(chan struct{})
	defer close(unblockServer)
	go func() {
		cancel()
		<-unblockServer
		_ = s.Close()
	}()
	cli := Client(c, testConfig)
	// Initiates client side handshake, which will block until the client hello is read
	// by the server, unless the cancellation works.
	err := cli.HandshakeContext(ctx)
	if err == nil {
		t.Fatal("Client handshake did not error when the context was canceled")
	}
	if err != context.Canceled {
		t.Errorf("Unexpected client handshake error: %v", err)
	}
	if runtime.GOARCH == "wasm" {
		t.Skip("conn.Close does not error as expected when called multiple times on WASM")
	}
	err = cli.Close()
	if err == nil {
		t.Error("Client connection was not closed when the context was canceled")
	}
}

// TestTLS13OnlyClientHelloCipherSuite tests that when a client states that
// it only supports TLS 1.3, it correctly advertises only TLS 1.3 ciphers.
func TestTLS13OnlyClientHelloCipherSuite(t *testing.T) {
	tls13Tests := []struct {
		name    string
		ciphers []uint16
	}{
		{
			name:    "nil",
			ciphers: nil,
		},
		{
			name:    "empty",
			ciphers: []uint16{},
		},
		{
			name:    "some TLS 1.2 cipher",
			ciphers: []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		},
		{
			name:    "some TLS 1.3 cipher",
			ciphers: []uint16{TLS_AES_128_GCM_SHA256},
		},
		{
			name:    "some TLS 1.2 and 1.3 ciphers",
			ciphers: []uint16{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_AES_256_GCM_SHA384},
		},
	}
	for _, tt := range tls13Tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testTLS13OnlyClientHelloCipherSuite(t, tt.ciphers)
		})
	}
}

func testTLS13OnlyClientHelloCipherSuite(t *testing.T, ciphers []uint16) {
	serverConfig := &Config{
		Certificates: testConfig.Certificates,
		GetConfigForClient: func(chi *ClientHelloInfo) (*Config, error) {
			expectedCiphersuites := defaultCipherSuitesTLS13NoAES
			if fips140tls.Required() {
				expectedCiphersuites = defaultCipherSuitesTLS13FIPS
			}
			if len(chi.CipherSuites) != len(expectedCiphersuites) {
				t.Errorf("only TLS 1.3 suites should be advertised, got=%x", chi.CipherSuites)
			} else {
				for i := range expectedCiphersuites {
					if want, got := expectedCiphersuites[i], chi.CipherSuites[i]; want != got {
						t.Errorf("cipher at index %d does not match, want=%x, got=%x", i, want, got)
					}
				}
			}
			return nil, nil
		},
	}
	clientConfig := &Config{
		MinVersion:         VersionTLS13, // client only supports TLS 1.3
		CipherSuites:       ciphers,
		InsecureSkipVerify: true,
	}
	if _, _, err := testHandshake(t, clientConfig, serverConfig); err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
}

// discardConn wraps a net.Conn but discards all writes, but reports that they happened.
type discardConn struct {
	net.Conn
}

func (dc *discardConn) Write(data []byte) (int, error) {
	return len(data), nil
}

// largeRSAKeyCertPEM contains a 8193 bit RSA key
const largeRSAKeyCertPEM = `-----BEGIN CERTIFICATE-----
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
u58=
-----END CERTIFICATE-----`

func TestHandshakeRSATooBig(t *testing.T) {
	testCert, _ := pem.Decode([]byte(largeRSAKeyCertPEM))

	c := &Conn{conn: &discardConn{}, config: testConfig.Clone()}

	expectedErr := "tls: server sent certificate containing RSA key larger than 8192 bits"
	err := c.verifyServerCertificate([][]byte{testCert.Bytes})
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Conn.verifyServerCertificate unexpected error: want %q, got %q", expectedErr, err)
	}

	expectedErr = "tls: client sent certificate containing RSA key larger than 8192 bits"
	err = c.processCertsFromClient(Certificate{Certificate: [][]byte{testCert.Bytes}})
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Conn.processCertsFromClient unexpected error: want %q, got %q", expectedErr, err)
	}
}

func TestTLS13ECHRejectionCallbacks(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		DNSNames:     []string{"example.golang"},
		NotBefore:    testConfig.Time().Add(-time.Hour),
		NotAfter:     testConfig.Time().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	clientConfig, serverConfig := testConfig.Clone(), testConfig.Clone()
	serverConfig.Certificates = []Certificate{
		{
			Certificate: [][]byte{certDER},
			PrivateKey:  k,
		},
	}
	serverConfig.MinVersion = VersionTLS13
	clientConfig.RootCAs = x509.NewCertPool()
	clientConfig.RootCAs.AddCert(cert)
	clientConfig.MinVersion = VersionTLS13
	clientConfig.EncryptedClientHelloConfigList, _ = hex.DecodeString("0041fe0d003d0100200020204bed0a11fc0dde595a9b78d966b0011128eb83f65d3c91c1cc5ac786cd246f000400010001ff0e6578616d706c652e676f6c616e670000")
	clientConfig.ServerName = "example.golang"

	for _, tc := range []struct {
		name        string
		expectedErr string

		verifyConnection                    func(ConnectionState) error
		verifyPeerCertificate               func([][]byte, [][]*x509.Certificate) error
		encryptedClientHelloRejectionVerify func(ConnectionState) error
	}{
		{
			name:        "no callbacks",
			expectedErr: "tls: server rejected ECH",
		},
		{
			name: "EncryptedClientHelloRejectionVerify, no err",
			encryptedClientHelloRejectionVerify: func(ConnectionState) error {
				return nil
			},
			expectedErr: "tls: server rejected ECH",
		},
		{
			name: "EncryptedClientHelloRejectionVerify, err",
			encryptedClientHelloRejectionVerify: func(ConnectionState) error {
				return errors.New("callback err")
			},
			// testHandshake returns the server side error, so we just need to
			// check alertBadCertificate was sent
			expectedErr: "callback err",
		},
		{
			name: "VerifyConnection, err",
			verifyConnection: func(ConnectionState) error {
				return errors.New("callback err")
			},
			expectedErr: "tls: server rejected ECH",
		},
		{
			name: "VerifyPeerCertificate, err",
			verifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
				return errors.New("callback err")
			},
			expectedErr: "tls: server rejected ECH",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := localPipe(t)
			done := make(chan error)

			go func() {
				serverErr := Server(s, serverConfig).Handshake()
				s.Close()
				done <- serverErr
			}()

			cConfig := clientConfig.Clone()
			cConfig.VerifyConnection = tc.verifyConnection
			cConfig.VerifyPeerCertificate = tc.verifyPeerCertificate
			cConfig.EncryptedClientHelloRejectionVerify = tc.encryptedClientHelloRejectionVerify

			clientErr := Client(c, cConfig).Handshake()
			c.Close()

			if tc.expectedErr == "" && clientErr != nil {
				t.Fatalf("unexpected err: %s", clientErr)
			} else if clientErr != nil && tc.expectedErr != clientErr.Error() {
				t.Fatalf("unexpected err: got %q, want %q", clientErr, tc.expectedErr)
			}
		})
	}
}

func TestECHTLS12Server(t *testing.T) {
	clientConfig, serverConfig := testConfig.Clone(), testConfig.Clone()

	serverConfig.MaxVersion = VersionTLS12
	clientConfig.MinVersion = 0

	clientConfig.EncryptedClientHelloConfigList, _ = hex.DecodeString("0041fe0d003d0100200020204bed0a11fc0dde595a9b78d966b0011128eb83f65d3c91c1cc5ac786cd246f000400010001ff0e6578616d706c652e676f6c616e670000")

	expectedErr := "server: tls: client offered only unsupported versions: [304]\nclient: remote error: tls: protocol version not supported"
	_, _, err := testHandshake(t, clientConfig, serverConfig)
	if err == nil || err.Error() != expectedErr {
		t.Fatalf("unexpected handshake error: got %q, want %q", err, expectedErr)
	}
}
```