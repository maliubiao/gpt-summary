Response:
Let's break down the thought process for summarizing the Go code snippet.

1. **Understand the Goal:** The primary goal is to summarize the functionality of the provided Go code, which is a part of the `handshake_server_test.go` file in the `crypto/tls` package. This means focusing on what aspects of the TLS server handshake are being tested.

2. **Identify Key Functions and Test Cases:**  The code is organized into several test functions, each with a descriptive name. These names are the first clue to understanding the tested functionality. I'd scan for function names starting with `TestHandshakeServer`, `TestServerResumption`, `TestClientAuth`, etc.

3. **Categorize Test Scenarios:**  As I identify the test functions, I'd group them thematically. For instance:
    * **Certificate Selection:**  Tests involving `GetCertificate`, SNI (`ServerName`), and scenarios where certificates are present or absent.
    * **Client Authentication:** Tests with `ClientAuth`, verifying client certificates.
    * **Session Resumption:** Tests using session tickets (`-sess_out`, `-sess_in`).
    * **Protocol Versions and Cipher Suites:** Tests related to specific TLS versions (TLS 1.2, TLS 1.3), cipher suite negotiation, and fallback mechanisms.
    * **Error Handling:** Tests checking how the server reacts to errors during handshake (e.g., `GetCertificate` errors).
    * **Performance:** Benchmarks (`BenchmarkHandshakeServer`).
    * **Context Management:**  Tests involving context cancellation (`HandshakeContext`).

4. **Analyze Individual Test Functions (Focus on Purpose and Method):** For each test function, I'd ask:
    * **What is being tested?** (Read the function name and potentially the comments within).
    * **How is it being tested?** (Look for the setup: `config` modifications, `clientHello` creation, the `serverTest` struct with `command`). The `command` often uses `openssl s_client`, which is a key indicator of what the external client is doing to trigger the server's behavior.
    * **What are the key assertions or checks?** (Look for `t.Run`, `t.Error`, `validate` functions in `serverTest`, expected error messages).

5. **Synthesize and Generalize:** After analyzing the individual tests, I'd synthesize the information into broader functional categories. Avoid getting bogged down in the minute details of each test case; focus on the overarching concepts being validated. For example, instead of listing every specific SNI test, summarize the functionality as testing SNI and the `GetCertificate` callback.

6. **Identify Key Go Features Demonstrated:** While summarizing the functionality, I'd also note which Go language features are being used or tested:
    * **Server Name Indication (SNI):**  Clearly present in tests with `-servername`.
    * **`GetCertificate` callback:** Explicitly used in several tests.
    * **Session Resumption (Session Tickets):**  Evident in tests with `-sess_out` and `-sess_in`.
    * **Client Authentication:**  Used with `config.ClientAuth`.
    * **TLS Versions (TLS 1.2, TLS 1.3):**  Mentioned in test names and sometimes within the test logic.
    * **Cipher Suite Negotiation:**  Shown in the `command` strings and the logic for selecting cipher suites.
    * **`GetConfigForClient` callback:**  Tested explicitly.
    * **Context Management:**  Demonstrated by `HandshakeContext`.

7. **Formulate the Summary:** Based on the categorized functionalities and identified Go features, I'd construct the summary using clear and concise language. Use action verbs to describe the functionality.

8. **Review and Refine:**  Read through the summary to ensure accuracy, completeness (at a high level), and clarity. Remove any jargon that might not be immediately understandable. Make sure the summary aligns with the provided "part 2 of 3" indication, implying it's an intermediate chunk of a larger test suite.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  List every single test case. **Correction:** Group similar tests into functional categories for a more concise summary.
* **Initial thought:** Focus too much on the `openssl` commands. **Correction:** While important for *how* the tests are done, the summary should focus on the *what* (the TLS functionality being tested).
* **Initial thought:**  Use technical terms without explanation. **Correction:**  Explain key terms like SNI or session resumption briefly within the summary.
* **Initial thought:**  Miss the overarching purpose of the file. **Correction:**  Remember that this is a *test* file, so the ultimate goal is to verify the correct behavior of the TLS server handshake.

By following this structured approach, I can systematically analyze the code and generate a comprehensive and informative summary of its functionality.
这段代码是 Go 语言 `crypto/tls` 包中 `handshake_server_test.go` 文件的一部分，它主要用于测试 TLS 服务器握手过程中的各种场景和功能。

**功能归纳：**

这段代码主要测试了 TLS 服务器在握手阶段处理不同情况的能力，特别是关于证书选择、会话恢复、客户端认证、协议降级保护以及性能测试等方面。

**具体功能点：**

1. **SNI (Server Name Indication) 支持与 `GetCertificate` 回调测试:**
   - 测试服务器如何根据客户端提供的 ServerName 来选择合适的证书。
   - 测试了 `Config.GetCertificate` 回调函数的功能，包括正确返回证书、找不到证书以及返回错误时的处理。
   - 验证了传递给 `GetCertificate` 回调的 `ClientHelloInfo` 结构体中 `Extensions` 字段是否包含了预期的扩展信息。

2. **会话恢复 (Session Resumption) 测试:**
   - 测试了 TLS 1.2 和 TLS 1.3 中的会话恢复机制，包括使用 Session Tickets 的情况。
   - 测试了通过 HelloRetryRequest (HRR) 进行会话恢复的场景。
   - 测试了禁用 Session Tickets 功能时的行为。

3. **协议降级保护 (Fallback SCSV) 测试:**
   - 测试了服务器如何处理客户端发送的 `TLS_FALLBACK_SCSV` 信号，以防止协议降级攻击。

4. **导出密钥材料 (Export Keying Material) 测试:**
   - 测试了 `ConnectionState.ExportKeyingMaterial` 方法，用于导出用于其他用途的密钥材料。

5. **签名算法协商测试:**
   - 测试了服务器支持和处理不同的签名算法，包括 RSA PKCS#1 v1.5 和 RSASSA-PSS。
   - 测试了当服务器不支持客户端首选的签名算法时的处理情况。
   - 测试了使用 Ed25519 证书的情况。

6. **性能基准测试 (Benchmark):**
   - 提供了不同密钥类型 (RSA, ECDHE) 和 TLS 版本下的服务器握手性能基准测试。

7. **客户端认证 (Client Authentication) 测试:**
   - 测试了服务器请求客户端证书 ( `RequestClientCert` ) 的场景。
   - 测试了客户端提供和不提供证书的情况，以及使用不同类型的客户端证书 (RSA, ECDSA, Ed25519) 的情况。
   - 测试了客户端提供不同签名算法的证书时的兼容性。

8. **握手失败时 SNI 信息的保留:**
   - 测试了即使握手失败，服务器也能正确记录客户端提供的 SNI 信息。

9. **`GetConfigForClient` 回调测试:**
   - 测试了 `Config.GetConfigForClient` 回调函数的功能，允许服务器根据客户端的 ClientHello 信息动态返回不同的配置。
   - 验证了 `GetConfigForClient` 中返回错误或者修改配置时的行为。

10. **处理空闲客户端连接:**
    - 测试了服务器在等待客户端操作时，如果客户端空闲，服务器可以正确关闭连接。

11. **内部工具函数测试:**
    - 测试了 `cloneHash` 函数，用于复制哈希对象。

12. **密钥大小限制测试:**
    - 测试了当 RSA 密钥大小不足以支持 RSASSA-PSS 签名算法时的处理。

13. **多证书配置测试:**
    - 测试了服务器配置多个证书时，客户端能够正确完成握手并选择合适的证书。

14. **AES 密码套件重排序测试:**
    - 测试了服务器在选择密码套件时，是否会根据硬件加速 (AES-GCM) 的可用性进行优化。

15. **`HandshakeContext` 上下文取消测试:**
    - 测试了使用 `HandshakeContext` 方法时，如果提供的上下文被取消，服务器握手能够正确中断。

**Go 语言功能示例 (基于代码推理):**

**1. `GetCertificate` 回调函数：**

```go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
)

func main() {
	config := &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			fmt.Println("收到客户端的 ServerName:", clientHello.ServerName)
			// 这里可以根据 clientHello.ServerName 返回不同的证书
			if clientHello.ServerName == "example.com" {
				// 假设 nameToCert 存储了域名到证书的映射
				cert, ok := nameToCert["example.com"]
				if ok {
					return cert, nil
				}
			}
			return nil, nil // 返回 nil 表示使用默认证书或后续处理
		},
		// ... 其他配置
	}

	// ... 使用 config 创建并运行 TLS 服务器
}

// 假设的证书映射
var nameToCert map[string]*tls.Certificate

// ... 初始化 nameToCert
```

**假设的输入与输出：**

* **输入 (客户端 ClientHello):** 包含 `ServerName` 扩展，例如 "example.com"。
* **输出 (服务器 `GetCertificate`):** 如果 `clientHello.ServerName` 是 "example.com"，则返回与 "example.com" 关联的 `tls.Certificate`。否则，可能返回 `nil, nil`。

**2. `GetConfigForClient` 回调函数：**

```go
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
)

func main() {
	serverConfig := &tls.Config{
		GetConfigForClient: func(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
			fmt.Println("客户端请求连接，版本:", clientHello.SupportedVersions)
			if contains(clientHello.SupportedVersions, tls.VersionTLS13) {
				cfg := testConfig.Clone() // 复制一个基础配置
				cfg.MinVersion = tls.VersionTLS13 // 强制使用 TLS 1.3
				return cfg, nil
			}
			return nil, errors.New("不支持的 TLS 版本")
		},
		Certificates: []tls.Certificate{testCert}, // 假设 testCert 已经定义
	}

	listener, err := net.Listen("tcp", "localhost:8443")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		tlsConn := tls.Server(conn, serverConfig)
		go func() {
			err := tlsConn.Handshake()
			if err != nil {
				log.Println("握手失败:", err)
			} else {
				log.Println("握手成功")
			}
			tlsConn.Close()
		}()
	}
}

func contains(s []uint16, e uint16) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// 假设的 testConfig 和 testCert
var testConfig = &tls.Config{}
var testCert tls.Certificate
```

**假设的输入与输出：**

* **输入 (客户端 ClientHello):** 包含 `SupportedVersions` 扩展，例如 `[]uint16{tls.VersionTLS12, tls.VersionTLS13}`。
* **输出 (服务器 `GetConfigForClient`):** 如果客户端支持 TLS 1.3，则返回一个新的 `tls.Config`，其 `MinVersion` 被设置为 `tls.VersionTLS13`。否则，返回一个错误。

**命令行参数处理：**

这段代码本身是测试代码，主要通过 Go 的 `testing` 包来运行。它并没有直接处理命令行参数。然而，在测试中，它使用了 `openssl s_client` 命令来模拟客户端行为。

例如，在测试 SNI 时，使用了 `-servername` 参数：

```
command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "AES128-SHA", "-servername", "snitest.com"}
```

这里的 `-servername snitest.com` 就是 `openssl s_client` 工具的命令行参数，用于指定客户端在握手时发送的服务器名称。

其他的 `openssl s_client` 命令行参数包括：

* `-cipher <密码套件>`:  指定使用的密码套件。
* `-ciphersuites <密码套件列表>`:  指定使用的 TLS 1.3 密码套件列表。
* `-no_ticket`:  禁用会话票据。
* `-sess_out <文件>`:  将会话信息保存到文件。
* `-sess_in <文件>`:  从文件读取会话信息进行恢复。
* `-fallback_scsv`:  发送 TLS_FALLBACK_SCSV 信号。
* `-cert <证书文件>`:  指定客户端证书文件。
* `-key <密钥文件>`:  指定客户端密钥文件。
* `-client_sigalgs <签名算法列表>`: 指定客户端支持的签名算法。
* `-curves <曲线列表>`: 指定客户端支持的椭圆曲线。

**使用者易犯错的点 (基于代码推理):**

虽然这段代码是测试代码，但可以推断出在实际使用 `crypto/tls` 包时，开发者可能犯的错误：

1. **`GetCertificate` 回调函数实现不正确:**
   - 没有处理 `clientHello.ServerName` 为空的情况。
   - 在查找证书时出现错误，但没有返回合适的错误信息。
   - 返回的证书与请求的 `ServerName` 不匹配。

2. **配置 `Config.Certificates` 和 `Config.GetCertificate` 的混淆:**
   - 同时设置了 `Config.Certificates` 和 `Config.GetCertificate`，可能导致非预期的证书选择行为。通常，如果需要动态选择证书，应该使用 `GetCertificate`。

3. **会话恢复配置不当:**
   - `SessionTicketsDisabled` 设置不正确，导致会话无法恢复或意外恢复。
   - 在集群环境中没有正确同步 Session Ticket 密钥。

4. **客户端认证配置错误:**
   - `Config.ClientAuth` 设置不当，例如设置为 `RequireClientCert` 但没有提供合适的 CA 证书 (`Config.ClientCAs`) 来验证客户端证书。

5. **密码套件和 TLS 版本配置不兼容:**
   - 配置了客户端和服务器都不支持的密码套件或 TLS 版本。

6. **不理解 `GetConfigForClient` 的使用场景:**
   - 错误地认为 `GetConfigForClient` 可以用于所有连接的通用配置，而它的目的是根据客户端的特性返回特定的配置。

这段代码通过大量的测试用例，覆盖了 TLS 服务器握手过程中各种可能的情况，帮助确保 `crypto/tls` 包的稳定性和可靠性。作为开发者，理解这些测试用例所覆盖的场景，能够更好地使用 Go 语言的 TLS 功能。

### 提示词
```
这是路径为go/src/crypto/tls/handshake_server_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
{
		cert := nameToCert[clientHello.ServerName]
		return cert, nil
	}
	test := &serverTest{
		name:    "SNI-GetCertificate",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "AES128-SHA", "-servername", "snitest.com"},
		config:  config,
	}
	runServerTestTLS12(t, test)
}

// TestHandshakeServerSNIGetCertificateNotFound is similar to
// TestHandshakeServerSNICertForName, but tests to make sure that when the
// GetCertificate method doesn't return a cert, we fall back to what's in
// the NameToCertificate map.
func TestHandshakeServerSNIGetCertificateNotFound(t *testing.T) {
	config := testConfig.Clone()

	config.GetCertificate = func(clientHello *ClientHelloInfo) (*Certificate, error) {
		return nil, nil
	}
	test := &serverTest{
		name:    "SNI-GetCertificateNotFound",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "AES128-SHA", "-servername", "snitest.com"},
		config:  config,
	}
	runServerTestTLS12(t, test)
}

// TestHandshakeServerGetCertificateExtensions tests to make sure that the
// Extensions passed to GetCertificate match what we expect based on the
// clientHelloMsg
func TestHandshakeServerGetCertificateExtensions(t *testing.T) {
	const errMsg = "TestHandshakeServerGetCertificateExtensions error"
	// ensure the test condition inside our GetCertificate callback
	// is actually invoked
	var called atomic.Int32

	testVersions := []uint16{VersionTLS12, VersionTLS13}
	for _, vers := range testVersions {
		t.Run(fmt.Sprintf("TLS version %04x", vers), func(t *testing.T) {
			pk, _ := ecdh.P256().GenerateKey(rand.Reader)
			clientHello := &clientHelloMsg{
				vers:                         vers,
				random:                       make([]byte, 32),
				cipherSuites:                 []uint16{TLS_AES_128_GCM_SHA256},
				compressionMethods:           []uint8{compressionNone},
				serverName:                   "test",
				keyShares:                    []keyShare{{group: CurveP256, data: pk.PublicKey().Bytes()}},
				supportedCurves:              []CurveID{CurveP256},
				supportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256},
			}

			// the clientHelloMsg initialized just above is serialized with
			// two extensions: server_name(0) and application_layer_protocol_negotiation(16)
			expectedExtensions := []uint16{
				extensionServerName,
				extensionSupportedCurves,
				extensionSignatureAlgorithms,
				extensionKeyShare,
			}

			if vers == VersionTLS13 {
				clientHello.supportedVersions = []uint16{VersionTLS13}
				expectedExtensions = append(expectedExtensions, extensionSupportedVersions)
			}

			// Go's TLS client presents extensions in the ClientHello sorted by extension ID
			slices.Sort(expectedExtensions)

			serverConfig := testConfig.Clone()
			serverConfig.GetCertificate = func(clientHello *ClientHelloInfo) (*Certificate, error) {
				if !slices.Equal(expectedExtensions, clientHello.Extensions) {
					t.Errorf("expected extensions on ClientHelloInfo (%v) to match clientHelloMsg (%v)", expectedExtensions, clientHello.Extensions)
				}
				called.Add(1)

				return nil, errors.New(errMsg)
			}
			testClientHelloFailure(t, serverConfig, clientHello, errMsg)
		})
	}

	if int(called.Load()) != len(testVersions) {
		t.Error("expected our GetCertificate test to be called twice")
	}
}

// TestHandshakeServerSNIGetCertificateError tests to make sure that errors in
// GetCertificate result in a tls alert.
func TestHandshakeServerSNIGetCertificateError(t *testing.T) {
	const errMsg = "TestHandshakeServerSNIGetCertificateError error"

	serverConfig := testConfig.Clone()
	serverConfig.GetCertificate = func(clientHello *ClientHelloInfo) (*Certificate, error) {
		return nil, errors.New(errMsg)
	}

	clientHello := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
		serverName:         "test",
	}
	testClientHelloFailure(t, serverConfig, clientHello, errMsg)
}

// TestHandshakeServerEmptyCertificates tests that GetCertificates is called in
// the case that Certificates is empty, even without SNI.
func TestHandshakeServerEmptyCertificates(t *testing.T) {
	const errMsg = "TestHandshakeServerEmptyCertificates error"

	serverConfig := testConfig.Clone()
	serverConfig.GetCertificate = func(clientHello *ClientHelloInfo) (*Certificate, error) {
		return nil, errors.New(errMsg)
	}
	serverConfig.Certificates = nil

	clientHello := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
	}
	testClientHelloFailure(t, serverConfig, clientHello, errMsg)

	// With an empty Certificates and a nil GetCertificate, the server
	// should always return a “no certificates” error.
	serverConfig.GetCertificate = nil

	clientHello = &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
	}
	testClientHelloFailure(t, serverConfig, clientHello, "no certificates")
}

func TestServerResumption(t *testing.T) {
	sessionFilePath := tempFile("")
	defer os.Remove(sessionFilePath)

	testIssue := &serverTest{
		name:    "IssueTicket",
		command: []string{"openssl", "s_client", "-cipher", "AES128-SHA", "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-sess_out", sessionFilePath},
		wait:    true,
	}
	testResume := &serverTest{
		name:    "Resume",
		command: []string{"openssl", "s_client", "-cipher", "AES128-SHA", "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-sess_in", sessionFilePath},
		validate: func(state ConnectionState) error {
			if !state.DidResume {
				return errors.New("did not resume")
			}
			return nil
		},
	}

	runServerTestTLS12(t, testIssue)
	runServerTestTLS12(t, testResume)

	runServerTestTLS13(t, testIssue)
	runServerTestTLS13(t, testResume)

	config := testConfig.Clone()
	config.CurvePreferences = []CurveID{CurveP256}

	testResumeHRR := &serverTest{
		name: "Resume-HelloRetryRequest",
		command: []string{"openssl", "s_client", "-curves", "X25519:P-256", "-cipher", "AES128-SHA", "-ciphersuites",
			"TLS_AES_128_GCM_SHA256", "-sess_in", sessionFilePath},
		config: config,
		validate: func(state ConnectionState) error {
			if !state.DidResume {
				return errors.New("did not resume")
			}
			return nil
		},
	}

	runServerTestTLS13(t, testResumeHRR)
}

func TestServerResumptionDisabled(t *testing.T) {
	sessionFilePath := tempFile("")
	defer os.Remove(sessionFilePath)

	config := testConfig.Clone()

	testIssue := &serverTest{
		name:    "IssueTicketPreDisable",
		command: []string{"openssl", "s_client", "-cipher", "AES128-SHA", "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-sess_out", sessionFilePath},
		config:  config,
		wait:    true,
	}
	testResume := &serverTest{
		name:    "ResumeDisabled",
		command: []string{"openssl", "s_client", "-cipher", "AES128-SHA", "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-sess_in", sessionFilePath},
		config:  config,
		validate: func(state ConnectionState) error {
			if state.DidResume {
				return errors.New("resumed with SessionTicketsDisabled")
			}
			return nil
		},
	}

	config.SessionTicketsDisabled = false
	runServerTestTLS12(t, testIssue)
	config.SessionTicketsDisabled = true
	runServerTestTLS12(t, testResume)

	config.SessionTicketsDisabled = false
	runServerTestTLS13(t, testIssue)
	config.SessionTicketsDisabled = true
	runServerTestTLS13(t, testResume)
}

func TestFallbackSCSV(t *testing.T) {
	serverConfig := Config{
		Certificates: testConfig.Certificates,
		MinVersion:   VersionTLS11,
	}
	test := &serverTest{
		name:   "FallbackSCSV",
		config: &serverConfig,
		// OpenSSL 1.0.1j is needed for the -fallback_scsv option.
		command:                       []string{"openssl", "s_client", "-fallback_scsv"},
		expectHandshakeErrorIncluding: "inappropriate protocol fallback",
	}
	runServerTestTLS11(t, test)
}

func TestHandshakeServerExportKeyingMaterial(t *testing.T) {
	test := &serverTest{
		name:    "ExportKeyingMaterial",
		command: []string{"openssl", "s_client", "-cipher", "ECDHE-RSA-AES256-SHA", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"},
		config:  testConfig.Clone(),
		validate: func(state ConnectionState) error {
			if km, err := state.ExportKeyingMaterial("test", nil, 42); err != nil {
				return fmt.Errorf("ExportKeyingMaterial failed: %v", err)
			} else if len(km) != 42 {
				return fmt.Errorf("Got %d bytes from ExportKeyingMaterial, wanted %d", len(km), 42)
			}
			return nil
		},
	}
	runServerTestTLS10(t, test)
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)
}

func TestHandshakeServerRSAPKCS1v15(t *testing.T) {
	test := &serverTest{
		name:    "RSA-RSAPKCS1v15",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305", "-sigalgs", "rsa_pkcs1_sha256"},
	}
	runServerTestTLS12(t, test)
}

func TestHandshakeServerRSAPSS(t *testing.T) {
	// We send rsa_pss_rsae_sha512 first, as the test key won't fit, and we
	// verify the server implementation will disregard the client preference in
	// that case. See Issue 29793.
	test := &serverTest{
		name:    "RSA-RSAPSS",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256", "-sigalgs", "rsa_pss_rsae_sha512:rsa_pss_rsae_sha256"},
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)

	test = &serverTest{
		name:                          "RSA-RSAPSS-TooSmall",
		command:                       []string{"openssl", "s_client", "-no_ticket", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256", "-sigalgs", "rsa_pss_rsae_sha512"},
		expectHandshakeErrorIncluding: "peer doesn't support any of the certificate's signature algorithms",
	}
	runServerTestTLS13(t, test)
}

func TestHandshakeServerEd25519(t *testing.T) {
	config := testConfig.Clone()
	config.Certificates = make([]Certificate, 1)
	config.Certificates[0].Certificate = [][]byte{testEd25519Certificate}
	config.Certificates[0].PrivateKey = testEd25519PrivateKey
	config.BuildNameToCertificate()

	test := &serverTest{
		name:    "Ed25519",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "ECDHE-ECDSA-CHACHA20-POLY1305", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"},
		config:  config,
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)
}

func benchmarkHandshakeServer(b *testing.B, version uint16, cipherSuite uint16, curve CurveID, cert []byte, key crypto.PrivateKey) {
	config := testConfig.Clone()
	config.CipherSuites = []uint16{cipherSuite}
	config.CurvePreferences = []CurveID{curve}
	config.Certificates = make([]Certificate, 1)
	config.Certificates[0].Certificate = [][]byte{cert}
	config.Certificates[0].PrivateKey = key
	config.BuildNameToCertificate()

	clientConn, serverConn := localPipe(b)
	serverConn = &recordingConn{Conn: serverConn}
	go func() {
		config := testConfig.Clone()
		config.MaxVersion = version
		config.CurvePreferences = []CurveID{curve}
		client := Client(clientConn, config)
		client.Handshake()
	}()
	server := Server(serverConn, config)
	if err := server.Handshake(); err != nil {
		b.Fatalf("handshake failed: %v", err)
	}
	serverConn.Close()
	flows := serverConn.(*recordingConn).flows

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		replay := &replayingConn{t: b, flows: slices.Clone(flows), reading: true}
		server := Server(replay, config)
		if err := server.Handshake(); err != nil {
			b.Fatalf("handshake failed: %v", err)
		}
	}
}

func BenchmarkHandshakeServer(b *testing.B) {
	b.Run("RSA", func(b *testing.B) {
		benchmarkHandshakeServer(b, VersionTLS12, TLS_RSA_WITH_AES_128_GCM_SHA256,
			0, testRSACertificate, testRSAPrivateKey)
	})
	b.Run("ECDHE-P256-RSA", func(b *testing.B) {
		b.Run("TLSv13", func(b *testing.B) {
			benchmarkHandshakeServer(b, VersionTLS13, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				CurveP256, testRSACertificate, testRSAPrivateKey)
		})
		b.Run("TLSv12", func(b *testing.B) {
			benchmarkHandshakeServer(b, VersionTLS12, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				CurveP256, testRSACertificate, testRSAPrivateKey)
		})
	})
	b.Run("ECDHE-P256-ECDSA-P256", func(b *testing.B) {
		b.Run("TLSv13", func(b *testing.B) {
			benchmarkHandshakeServer(b, VersionTLS13, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				CurveP256, testP256Certificate, testP256PrivateKey)
		})
		b.Run("TLSv12", func(b *testing.B) {
			benchmarkHandshakeServer(b, VersionTLS12, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				CurveP256, testP256Certificate, testP256PrivateKey)
		})
	})
	b.Run("ECDHE-X25519-ECDSA-P256", func(b *testing.B) {
		b.Run("TLSv13", func(b *testing.B) {
			benchmarkHandshakeServer(b, VersionTLS13, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				X25519, testP256Certificate, testP256PrivateKey)
		})
		b.Run("TLSv12", func(b *testing.B) {
			benchmarkHandshakeServer(b, VersionTLS12, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				X25519, testP256Certificate, testP256PrivateKey)
		})
	})
	b.Run("ECDHE-P521-ECDSA-P521", func(b *testing.B) {
		if testECDSAPrivateKey.PublicKey.Curve != elliptic.P521() {
			b.Fatal("test ECDSA key doesn't use curve P-521")
		}
		b.Run("TLSv13", func(b *testing.B) {
			benchmarkHandshakeServer(b, VersionTLS13, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				CurveP521, testECDSACertificate, testECDSAPrivateKey)
		})
		b.Run("TLSv12", func(b *testing.B) {
			benchmarkHandshakeServer(b, VersionTLS12, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				CurveP521, testECDSACertificate, testECDSAPrivateKey)
		})
	})
}

func TestClientAuth(t *testing.T) {
	var certPath, keyPath, ecdsaCertPath, ecdsaKeyPath, ed25519CertPath, ed25519KeyPath string

	if *update {
		certPath = tempFile(clientCertificatePEM)
		defer os.Remove(certPath)
		keyPath = tempFile(clientKeyPEM)
		defer os.Remove(keyPath)
		ecdsaCertPath = tempFile(clientECDSACertificatePEM)
		defer os.Remove(ecdsaCertPath)
		ecdsaKeyPath = tempFile(clientECDSAKeyPEM)
		defer os.Remove(ecdsaKeyPath)
		ed25519CertPath = tempFile(clientEd25519CertificatePEM)
		defer os.Remove(ed25519CertPath)
		ed25519KeyPath = tempFile(clientEd25519KeyPEM)
		defer os.Remove(ed25519KeyPath)
	} else {
		t.Parallel()
	}

	config := testConfig.Clone()
	config.ClientAuth = RequestClientCert

	test := &serverTest{
		name:    "ClientAuthRequestedNotGiven",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "AES128-SHA", "-ciphersuites", "TLS_AES_128_GCM_SHA256"},
		config:  config,
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)

	test = &serverTest{
		name: "ClientAuthRequestedAndGiven",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "AES128-SHA", "-ciphersuites", "TLS_AES_128_GCM_SHA256",
			"-cert", certPath, "-key", keyPath, "-client_sigalgs", "rsa_pss_rsae_sha256"},
		config:            config,
		expectedPeerCerts: []string{clientCertificatePEM},
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)

	test = &serverTest{
		name: "ClientAuthRequestedAndECDSAGiven",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "AES128-SHA", "-ciphersuites", "TLS_AES_128_GCM_SHA256",
			"-cert", ecdsaCertPath, "-key", ecdsaKeyPath},
		config:            config,
		expectedPeerCerts: []string{clientECDSACertificatePEM},
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)

	test = &serverTest{
		name: "ClientAuthRequestedAndEd25519Given",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "AES128-SHA", "-ciphersuites", "TLS_AES_128_GCM_SHA256",
			"-cert", ed25519CertPath, "-key", ed25519KeyPath},
		config:            config,
		expectedPeerCerts: []string{clientEd25519CertificatePEM},
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)

	test = &serverTest{
		name: "ClientAuthRequestedAndPKCS1v15Given",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "AES128-SHA",
			"-cert", certPath, "-key", keyPath, "-client_sigalgs", "rsa_pkcs1_sha256"},
		config:            config,
		expectedPeerCerts: []string{clientCertificatePEM},
	}
	runServerTestTLS12(t, test)
}

func TestSNIGivenOnFailure(t *testing.T) {
	const expectedServerName = "test.testing"

	clientHello := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
		serverName:         expectedServerName,
	}

	serverConfig := testConfig.Clone()
	// Erase the server's cipher suites to ensure the handshake fails.
	serverConfig.CipherSuites = nil

	c, s := localPipe(t)
	go func() {
		cli := Client(c, testConfig)
		cli.vers = clientHello.vers
		if _, err := cli.writeHandshakeRecord(clientHello, nil); err != nil {
			testFatal(t, err)
		}
		c.Close()
	}()
	conn := Server(s, serverConfig)
	ctx := context.Background()
	ch, _, err := conn.readClientHello(ctx)
	hs := serverHandshakeState{
		c:           conn,
		ctx:         ctx,
		clientHello: ch,
	}
	if err == nil {
		err = hs.processClientHello()
	}
	if err == nil {
		err = hs.pickCipherSuite()
	}
	defer s.Close()

	if err == nil {
		t.Error("No error reported from server")
	}

	cs := hs.c.ConnectionState()
	if cs.HandshakeComplete {
		t.Error("Handshake registered as complete")
	}

	if cs.ServerName != expectedServerName {
		t.Errorf("Expected ServerName of %q, but got %q", expectedServerName, cs.ServerName)
	}
}

var getConfigForClientTests = []struct {
	setup          func(config *Config)
	callback       func(clientHello *ClientHelloInfo) (*Config, error)
	errorSubstring string
	verify         func(config *Config) error
}{
	{
		nil,
		func(clientHello *ClientHelloInfo) (*Config, error) {
			return nil, nil
		},
		"",
		nil,
	},
	{
		nil,
		func(clientHello *ClientHelloInfo) (*Config, error) {
			return nil, errors.New("should bubble up")
		},
		"should bubble up",
		nil,
	},
	{
		nil,
		func(clientHello *ClientHelloInfo) (*Config, error) {
			config := testConfig.Clone()
			// Setting a maximum version of TLS 1.1 should cause
			// the handshake to fail, as the client MinVersion is TLS 1.2.
			config.MaxVersion = VersionTLS11
			return config, nil
		},
		"client offered only unsupported versions",
		nil,
	},
	{
		func(config *Config) {
			for i := range config.SessionTicketKey {
				config.SessionTicketKey[i] = byte(i)
			}
			config.sessionTicketKeys = nil
		},
		func(clientHello *ClientHelloInfo) (*Config, error) {
			config := testConfig.Clone()
			for i := range config.SessionTicketKey {
				config.SessionTicketKey[i] = 0
			}
			config.sessionTicketKeys = nil
			return config, nil
		},
		"",
		func(config *Config) error {
			if config.SessionTicketKey == [32]byte{} {
				return fmt.Errorf("expected SessionTicketKey to be set")
			}
			return nil
		},
	},
	{
		func(config *Config) {
			var dummyKey [32]byte
			for i := range dummyKey {
				dummyKey[i] = byte(i)
			}

			config.SetSessionTicketKeys([][32]byte{dummyKey})
		},
		func(clientHello *ClientHelloInfo) (*Config, error) {
			config := testConfig.Clone()
			config.sessionTicketKeys = nil
			return config, nil
		},
		"",
		func(config *Config) error {
			if config.SessionTicketKey == [32]byte{} {
				return fmt.Errorf("expected SessionTicketKey to be set")
			}
			return nil
		},
	},
}

func TestGetConfigForClient(t *testing.T) {
	serverConfig := testConfig.Clone()
	clientConfig := testConfig.Clone()
	clientConfig.MinVersion = VersionTLS12

	for i, test := range getConfigForClientTests {
		if test.setup != nil {
			test.setup(serverConfig)
		}

		var configReturned *Config
		serverConfig.GetConfigForClient = func(clientHello *ClientHelloInfo) (*Config, error) {
			config, err := test.callback(clientHello)
			configReturned = config
			return config, err
		}
		c, s := localPipe(t)
		done := make(chan error)

		go func() {
			defer s.Close()
			done <- Server(s, serverConfig).Handshake()
		}()

		clientErr := Client(c, clientConfig).Handshake()
		c.Close()

		serverErr := <-done

		if len(test.errorSubstring) == 0 {
			if serverErr != nil || clientErr != nil {
				t.Errorf("test[%d]: expected no error but got serverErr: %q, clientErr: %q", i, serverErr, clientErr)
			}
			if test.verify != nil {
				if err := test.verify(configReturned); err != nil {
					t.Errorf("test[%d]: verify returned error: %v", i, err)
				}
			}
		} else {
			if serverErr == nil {
				t.Errorf("test[%d]: expected error containing %q but got no error", i, test.errorSubstring)
			} else if !strings.Contains(serverErr.Error(), test.errorSubstring) {
				t.Errorf("test[%d]: expected error to contain %q but it was %q", i, test.errorSubstring, serverErr)
			}
		}
	}
}

func TestCloseServerConnectionOnIdleClient(t *testing.T) {
	clientConn, serverConn := localPipe(t)
	server := Server(serverConn, testConfig.Clone())
	go func() {
		clientConn.Write([]byte{'0'})
		server.Close()
	}()
	server.SetReadDeadline(time.Now().Add(time.Minute))
	err := server.Handshake()
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			t.Errorf("Expected a closed network connection error but got '%s'", err.Error())
		}
	} else {
		t.Errorf("Error expected, but no error returned")
	}
}

func TestCloneHash(t *testing.T) {
	h1 := crypto.SHA256.New()
	h1.Write([]byte("test"))
	s1 := h1.Sum(nil)
	h2 := cloneHash(h1, crypto.SHA256)
	s2 := h2.Sum(nil)
	if !bytes.Equal(s1, s2) {
		t.Error("cloned hash generated a different sum")
	}
}

func expectError(t *testing.T, err error, sub string) {
	if err == nil {
		t.Errorf(`expected error %q, got nil`, sub)
	} else if !strings.Contains(err.Error(), sub) {
		t.Errorf(`expected error %q, got %q`, sub, err)
	}
}

func TestKeyTooSmallForRSAPSS(t *testing.T) {
	cert, err := X509KeyPair([]byte(`-----BEGIN CERTIFICATE-----
MIIBcTCCARugAwIBAgIQGjQnkCFlUqaFlt6ixyz/tDANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMB4XDTE5MDExODIzMjMyOFoXDTIwMDExODIzMjMy
OFowEjEQMA4GA1UEChMHQWNtZSBDbzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDd
ez1rFUDwax2HTxbcnFUP9AhcgEGMHVV2nn4VVEWFJB6I8C/Nkx0XyyQlrmFYBzEQ
nIPhKls4T0hFoLvjJnXpAgMBAAGjTTBLMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE
DDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBYGA1UdEQQPMA2CC2V4YW1wbGUu
Y29tMA0GCSqGSIb3DQEBCwUAA0EAxDuUS+BrrS3c+h+k+fQPOmOScy6yTX9mHw0Q
KbucGamXYEy0URIwOdO0tQ3LHPc1YGvYSPwkDjkjqECs2Vm/AA==
-----END CERTIFICATE-----`), []byte(testingKey(`-----BEGIN RSA TESTING KEY-----
MIIBOgIBAAJBAN17PWsVQPBrHYdPFtycVQ/0CFyAQYwdVXaefhVURYUkHojwL82T
HRfLJCWuYVgHMRCcg+EqWzhPSEWgu+MmdekCAwEAAQJBALjQYNTdXF4CFBbXwUz/
yt9QFDYT9B5WT/12jeGAe653gtYS6OOi/+eAkGmzg1GlRnw6fOfn+HYNFDORST7z
4j0CIQDn2xz9hVWQEu9ee3vecNT3f60huDGTNoRhtqgweQGX0wIhAPSLj1VcRZEz
nKpbtU22+PbIMSJ+e80fmY9LIPx5N4HTAiAthGSimMR9bloz0EY3GyuUEyqoDgMd
hXxjuno2WesoJQIgemilbcALXpxsLmZLgcQ2KSmaVr7jb5ECx9R+hYKTw1sCIG4s
T+E0J8wlH24pgwQHzy7Ko2qLwn1b5PW8ecrlvP1g
-----END RSA TESTING KEY-----`)))
	if err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := localPipe(t)
	client := Client(clientConn, testConfig)
	done := make(chan struct{})
	go func() {
		config := testConfig.Clone()
		config.Certificates = []Certificate{cert}
		config.MinVersion = VersionTLS13
		server := Server(serverConn, config)
		err := server.Handshake()
		expectError(t, err, "key size too small")
		close(done)
	}()
	err = client.Handshake()
	expectError(t, err, "handshake failure")
	<-done
}

func TestMultipleCertificates(t *testing.T) {
	clientConfig := testConfig.Clone()
	clientConfig.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	clientConfig.MaxVersion = VersionTLS12

	serverConfig := testConfig.Clone()
	serverConfig.Certificates = []Certificate{{
		Certificate: [][]byte{testECDSACertificate},
		PrivateKey:  testECDSAPrivateKey,
	}, {
		Certificate: [][]byte{testRSACertificate},
		PrivateKey:  testRSAPrivateKey,
	}}

	_, clientState, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got := clientState.PeerCertificates[0].PublicKeyAlgorithm; got != x509.RSA {
		t.Errorf("expected RSA certificate, got %v", got)
	}
}

func TestAESCipherReordering(t *testing.T) {
	skipFIPS(t) // No CHACHA20_POLY1305 for FIPS.

	currentAESSupport := hasAESGCMHardwareSupport
	defer func() { hasAESGCMHardwareSupport = currentAESSupport }()

	tests := []struct {
		name            string
		clientCiphers   []uint16
		serverHasAESGCM bool
		serverCiphers   []uint16
		expectedCipher  uint16
	}{
		{
			name: "server has hardware AES, client doesn't (pick ChaCha)",
			clientCiphers: []uint16{
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			serverHasAESGCM: true,
			expectedCipher:  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		{
			name: "client prefers AES-GCM, server doesn't have hardware AES (pick ChaCha)",
			clientCiphers: []uint16{
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			serverHasAESGCM: false,
			expectedCipher:  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		{
			name: "client prefers AES-GCM, server has hardware AES (pick AES-GCM)",
			clientCiphers: []uint16{
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			serverHasAESGCM: true,
			expectedCipher:  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		{
			name: "client prefers AES-GCM and sends GREASE, server has hardware AES (pick AES-GCM)",
			clientCiphers: []uint16{
				0x0A0A, // GREASE value
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			serverHasAESGCM: true,
			expectedCipher:  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		{
			name: "client prefers AES-GCM and doesn't support ChaCha, server doesn't have hardware AES (pick AES-GCM)",
			clientCiphers: []uint16{
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			serverHasAESGCM: false,
			expectedCipher:  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		{
			name: "client prefers AES-GCM and AES-CBC over ChaCha, server doesn't have hardware AES (pick ChaCha)",
			clientCiphers: []uint16{
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			serverHasAESGCM: false,
			expectedCipher:  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		{
			name: "client prefers AES-GCM over ChaCha and sends GREASE, server doesn't have hardware AES (pick ChaCha)",
			clientCiphers: []uint16{
				0x0A0A, // GREASE value
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			serverHasAESGCM: false,
			expectedCipher:  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		{
			name: "client supports multiple AES-GCM, server doesn't have hardware AES and doesn't support ChaCha (AES-GCM)",
			clientCiphers: []uint16{
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			serverHasAESGCM: false,
			serverCiphers: []uint16{
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			expectedCipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		{
			name: "client prefers AES-GCM, server has hardware but doesn't support AES (pick ChaCha)",
			clientCiphers: []uint16{
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			serverHasAESGCM: true,
			serverCiphers: []uint16{
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			expectedCipher: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hasAESGCMHardwareSupport = tc.serverHasAESGCM
			hs := &serverHandshakeState{
				c: &Conn{
					config: &Config{
						CipherSuites: tc.serverCiphers,
					},
					vers: VersionTLS12,
				},
				clientHello: &clientHelloMsg{
					cipherSuites: tc.clientCiphers,
					vers:         VersionTLS12,
				},
				ecdheOk:      true,
				rsaSignOk:    true,
				rsaDecryptOk: true,
			}

			err := hs.pickCipherSuite()
			if err != nil {
				t.Errorf("pickCipherSuite failed: %s", err)
			}

			if tc.expectedCipher != hs.suite.id {
				t.Errorf("unexpected cipher chosen: want %d, got %d", tc.expectedCipher, hs.suite.id)
			}
		})
	}
}

func TestAESCipherReorderingTLS13(t *testing.T) {
	skipFIPS(t) // No CHACHA20_POLY1305 for FIPS.

	currentAESSupport := hasAESGCMHardwareSupport
	defer func() { hasAESGCMHardwareSupport = currentAESSupport }()

	tests := []struct {
		name            string
		clientCiphers   []uint16
		serverHasAESGCM bool
		expectedCipher  uint16
	}{
		{
			name: "server has hardware AES, client doesn't (pick ChaCha)",
			clientCiphers: []uint16{
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_128_GCM_SHA256,
			},
			serverHasAESGCM: true,
			expectedCipher:  TLS_CHACHA20_POLY1305_SHA256,
		},
		{
			name: "neither server nor client have hardware AES (pick ChaCha)",
			clientCiphers: []uint16{
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_128_GCM_SHA256,
			},
			serverHasAESGCM: false,
			expectedCipher:  TLS_CHACHA20_POLY1305_SHA256,
		},
		{
			name: "client prefers AES, server doesn't have hardware (pick ChaCha)",
			clientCiphers: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
			},
			serverHasAESGCM: false,
			expectedCipher:  TLS_CHACHA20_POLY1305_SHA256,
		},
		{
			name: "client prefers AES and sends GREASE, server doesn't have hardware (pick ChaCha)",
			clientCiphers: []uint16{
				0x0A0A, // GREASE value
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
			},
			serverHasAESGCM: false,
			expectedCipher:  TLS_CHACHA20_POLY1305_SHA256,
		},
		{
			name: "client prefers AES, server has hardware AES (pick AES)",
			clientCiphers: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
			},
			serverHasAESGCM: true,
			expectedCipher:  TLS_AES_128_GCM_SHA256,
		},
		{
			name: "client prefers AES and sends GREASE, server has hardware AES (pick AES)",
			clientCiphers: []uint16{
				0x0A0A, // GREASE value
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
			},
			serverHasAESGCM: true,
			expectedCipher:  TLS_AES_128_GCM_SHA256,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hasAESGCMHardwareSupport = tc.serverHasAESGCM
			pk, _ := ecdh.X25519().GenerateKey(rand.Reader)
			hs := &serverHandshakeStateTLS13{
				c: &Conn{
					config: &Config{},
					vers:   VersionTLS13,
				},
				clientHello: &clientHelloMsg{
					cipherSuites:       tc.clientCiphers,
					supportedVersions:  []uint16{VersionTLS13},
					compressionMethods: []uint8{compressionNone},
					keyShares:          []keyShare{{group: X25519, data: pk.PublicKey().Bytes()}},
					supportedCurves:    []CurveID{X25519},
				},
			}

			err := hs.processClientHello()
			if err != nil {
				t.Errorf("pickCipherSuite failed: %s", err)
			}

			if tc.expectedCipher != hs.suite.id {
				t.Errorf("unexpected cipher chosen: want %d, got %d", tc.expectedCipher, hs.suite.id)
			}
		})
	}
}

// TestServerHandshakeContextCancellation tests that canceling
// the context given to the server side conn.HandshakeContext
// interrupts the in-progress handshake.
func TestServerHandshakeContextCancellation(t *testing.T) {
	c, s := localPipe(t)
	ctx, cancel := context.WithCancel(context.Background())
	unblockClient := make(chan struct{})
	defer close(unblockClient)
	go func() {
		cancel()
		<-unblockClient
		_ = c.Close()
	}()
	conn := Server(s, testConfig)
	// Initiates server side handshake, which will block until a client hello is read
	// unless the cancellation works.
	err := conn.HandshakeContext(ctx)
	if err == nil {
		t.Fatal("Server handshake did not error when the context was canceled")
	}
	if err != context.Canceled {
		t.Errorf("Unexpected server handshake error: %v", err)
	}
	if runtime.GOARCH == "wasm" {
		t.Skip("conn.Close does not error as expected when called multiple times on WASM")
	}
	err = conn.Close()
	if err == nil {
		t.Error("Server connection was not closed when the context was canceled")
	}
}

// TestHandshakeContextHierarchy tests whether the contexts
// available to GetClientCertificate and GetCertificate are
// derived from the context provided to HandshakeContext, and
// that those contexts are canceled after HandshakeContext has
// returned.
func TestHandshakeContextHierarchy(t *testing.T) {
	c, s := localPipe(t)
	clientErr := make(chan error, 1)
	clientConfig := testConfig.Clone()
	serverCo
```