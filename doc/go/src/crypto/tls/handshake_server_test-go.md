Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding and Goal:**

The primary goal is to understand the *purpose* of this Go code. The filename `handshake_server_test.go` and the `tls` package strongly suggest it's involved in testing the server-side TLS handshake process. The request asks for the functionality, possible Go features used, code examples (with assumptions), command-line argument handling, common mistakes, and a summary.

**2. High-Level Structure and Key Functions:**

I start by scanning the code for top-level function definitions. Immediately, I see functions like `testClientHello`, `testClientHelloFailure`, and several `Test...` functions. This confirms the testing nature. The presence of `localPipe` hints at in-memory testing without actual network connections.

**3. Analyzing Core Testing Functions (`testClientHello`, `testClientHelloFailure`):**

These seem central to the testing. `testClientHello` simply calls `testClientHelloFailure`, suggesting the latter is the core logic. `testClientHelloFailure` does the following:

* **Sets up a pipe:** `localPipe(t)` creates an in-memory network connection. This is a common pattern for isolated testing.
* **Simulates a client:** A goroutine is launched to act as a client, writing a `handshakeMessage`. This involves creating a `Client` and using its methods.
* **Simulates a server:** The main goroutine acts as the server, creating a `Server` and calling `readClientHello`.
* **Processes the ClientHello:** Depending on the TLS version, it calls either `serverHandshakeStateTLS13.processClientHello` or `serverHandshakeState.processClientHello`, along with other version-specific steps like `checkForResumption`, `pickCertificate`, and `pickCipherSuite`.
* **Error Checking:** It checks if the expected error occurred (or didn't occur).

**4. Identifying Test Cases (Functions starting with `Test`):**

I then look at the `Test...` functions. These clearly represent individual test scenarios:

* `TestSimpleError`: Tests handling of an unexpected handshake message.
* `TestRejectBadProtocolVersion`: Tests rejecting clients with invalid TLS versions.
* `TestNoSuiteOverlap`: Tests when the client and server have no common cipher suites.
* ... and so on. Each test focuses on a specific aspect of the handshake process, often simulating different client configurations or messages.

**5. Inferring Go Features Used:**

Based on the code structure and functions, I can identify several Go features:

* **`testing` package:** The presence of `testing.T` and functions like `t.Helper()`, `t.Fatal()`, and `t.Errorf()` clearly indicates the use of Go's built-in testing framework.
* **Goroutines and Channels:** The use of `go func()` and channels (`bufChan`, `replyChan`) demonstrates concurrent programming for simulating client and server interactions.
* **Interfaces:** The `handshakeMessage` interface is used to represent different types of handshake messages.
* **Structs and Methods:** The code uses structs like `clientHelloMsg`, `serverHelloMsg`, `Config`, `Certificate`, and defines methods on them (e.g., `unmarshal` on `serverHelloMsg`).
* **Error Handling:** The code extensively uses the `error` interface and `errors` package for managing errors.
* **`net` package:** The `net.Listen`, `net.Dial`, `net.Conn` are used for simulating network connections.
* **`crypto` packages:** The imports `crypto`, `crypto/ecdh`, `crypto/elliptic`, `crypto/rand`, `crypto/tls`, `crypto/x509` indicate heavy use of cryptography-related functionalities.
* **`io` package:** Used for basic input/output operations, particularly with the pipe connections.
* **`os/exec` package:** Used for running external commands (like `openssl`) in the `serverTest` structure.
* **Slices and Maps:** Used for storing lists of cipher suites, certificates, etc.

**6. Developing Code Examples (with Assumptions):**

For the code examples, I focus on illustrating the *core* functionalities being tested. This involves:

* **Simulating `testClientHelloFailure`:** Showing how a server might reject a client with an unsupported TLS version.
* **Simulating `TestRejectBadProtocolVersion`:** Specifically demonstrating the scenario where a client offers a bad protocol version.

Crucially, I include assumptions because the provided snippet is incomplete. Assumptions help clarify the context of the example.

**7. Analyzing Command-Line Arguments (for `serverTest`):**

The `serverTest` structure and its `connFromCommand` method reveal the use of external commands, particularly `openssl s_client`. I examine how the `command` slice is built, noting the `-connect`, `-tls1`, `-cipher`, `-servername`, `-alpn`, `-ciphersuites`, and `-curves` flags. I explain the purpose of these flags in the context of TLS testing.

**8. Identifying Common Mistakes:**

I think about potential pitfalls for users interacting with TLS configurations, drawing inspiration from the tests themselves:

* **Mismatched TLS versions:** Clients and servers not supporting the same versions.
* **No shared cipher suites:** Clients and servers not having any compatible encryption algorithms.
* **Incorrect certificate configuration:** Problems with the server's certificate and private key.
* **SNI configuration issues:** Incorrectly configuring or expecting SNI behavior.
* **ALPN mismatches:** Not handling application-level protocol negotiation correctly.

**9. Summarizing Functionality (the final request):**

Finally, I synthesize the information gathered to provide a concise summary of the code's purpose: testing the server-side TLS handshake in various scenarios, including error handling, protocol version negotiation, cipher suite selection, and extension handling.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the code is *implementing* a TLS server. **Correction:**  The presence of `testing` and test functions strongly indicates it's for *testing* an existing implementation.
* **Detail level:** At first, I might try to understand every single line of code. **Refinement:** For this request, focusing on the high-level functionality and the purpose of key functions is more efficient. Deep dives into specific handshake message structures can be saved for later if needed.
* **Code example relevance:** Ensure the code examples directly relate to the tested functionalities and are easy to understand, even with the necessary assumptions.

By following this structured approach, I can effectively analyze the Go code snippet and address all the points in the request.
这是 `go/src/crypto/tls/handshake_server_test.go` 文件的一部分，它主要用于测试 Go 语言 `crypto/tls` 包中 **TLS 服务器握手** 的实现。

**功能归纳:**

这段代码定义了一系列测试用例，用于验证 TLS 服务器在握手过程中的各种行为，包括：

* **处理客户端的 `ClientHello` 消息：**  测试服务器如何解析和响应客户端发送的初始握手消息，包括协议版本、支持的密码套件、压缩方法等。
* **协商 TLS 版本：** 验证服务器能否正确地根据自身配置和客户端请求协商合适的 TLS 版本。
* **选择密码套件：** 测试服务器如何根据客户端提供的密码套件列表和自身配置选择合适的加密算法。
* **处理错误情况：** 验证服务器在遇到错误的客户端请求（例如，不支持的协议版本、没有共同的密码套件）时是否能够正确处理并返回错误。
* **处理 TLS 扩展：** 测试服务器对各种 TLS 扩展的支持，例如服务器名称指示 (SNI)、安全重协商、应用层协议协商 (ALPN)、椭圆曲线密码学 (ECC) 等。
* **会话恢复：** 验证服务器是否能正确处理和恢复之前的 TLS 会话。
* **证书处理：** 测试服务器在握手过程中选择和发送证书的能力，包括使用 `GetCertificate` 函数动态选择证书。
* **与外部 TLS 实现的互操作性：** 通过与 `openssl s_client` 命令交互，验证 Go 语言的 TLS 服务器实现与其他 TLS 实现的兼容性。

**Go 语言功能实现举例 (会话恢复):**

这段代码中 `TestCrossVersionResume` 函数展示了如何测试会话恢复功能。会话恢复允许客户端和服务器重用之前的加密密钥，从而加速后续的连接建立过程。

```go
func TestCrossVersionResume(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testCrossVersionResume(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testCrossVersionResume(t, VersionTLS13) })
}

func testCrossVersionResume(t *testing.T, version uint16) {
	serverConfig := &Config{
		CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: testConfig.Certificates,
	}
	clientConfig := &Config{
		CipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		InsecureSkipVerify: true,
		ClientSessionCache: NewLRUClientSessionCache(1), // 使用客户端会话缓存
		ServerName:         "servername",
		MinVersion:         VersionTLS12,
	}

	// 建立一个 TLS 1.3 会话
	clientConfig.MaxVersion = VersionTLS13
	_, _, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("握手失败: %s", err)
	}

	// 客户端会话缓存现在包含一个 TLS 1.3 会话
	state, _, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("握手失败: %s", err)
	}
	if !state.DidResume {
		t.Fatalf("握手没有在相同版本恢复")
	}

	// ... (后续测试用例，测试在不同 TLS 版本之间的恢复)
}
```

**假设的输入与输出:**

在 `TestCrossVersionResume` 中：

* **首次握手 (TLS 1.3):**
    * **输入 (客户端):**  `clientConfig` 配置为 `MaxVersion: VersionTLS13`，并设置了 `ClientSessionCache` 和 `ServerName`。
    * **输出 (服务器):**  成功建立 TLS 1.3 连接，并将会话信息存储在服务器端（本例中是模拟的）。
    * **输出 (客户端):**  成功建立 TLS 1.3 连接，并将会话信息存储在 `ClientSessionCache` 中。
* **第二次握手 (尝试恢复 TLS 1.3 会话):**
    * **输入 (客户端):**  `clientConfig` 配置不变，客户端发送包含会话 ID 的 `ClientHello` 消息。
    * **输出 (服务器):**  识别出会话 ID 并恢复之前的 TLS 1.3 会话，无需完整握手。`state.DidResume` 为 `true`。
* **第三次握手 (尝试恢复为 TLS 1.2):**
    * **输入 (客户端):** `clientConfig` 配置为 `MaxVersion: VersionTLS12`，客户端发送包含会话 ID 的 `ClientHello` 消息。
    * **输出 (服务器):**  可能拒绝在较低版本恢复会话，执行完整握手。`state.DidResume` 可能为 `false`。

**命令行参数的具体处理 (针对 `serverTest` 结构体):**

`serverTest` 结构体用于与外部的 `openssl s_client` 命令进行交互测试。

* **`command` 字段:**  存储了要执行的 `openssl s_client` 命令及其参数。例如：
    * `[]string{"openssl", "s_client", "-no_ticket", "-cipher", "RC4-SHA"}`
* **参数解释:**
    * `openssl s_client`:  调用 OpenSSL 的客户端工具。
    * `-no_ticket`:  禁用 TLS 会话票据，避免票据相关的干扰。
    * `-cipher <cipher>`:  指定客户端希望使用的密码套件，例如 `RC4-SHA`。
    * `-connect <host:port>`:  指定连接的服务器地址和端口，由测试代码动态生成。
    * `-tls1`, `-tls1_1`, `-tls1_2`, `-tls1_3`:  指定客户端希望使用的 TLS 版本。
    * `-servername <hostname>`:  发送服务器名称指示 (SNI) 扩展。
    * `-alpn <protocols>`:  发送应用层协议协商 (ALPN) 扩展，指定客户端支持的协议列表。
    * `-ciphersuites <ciphersuites>`:  指定 TLS 1.3 的密码套件列表。
    * `-curves <curves>`: 指定客户端支持的椭圆曲线。

测试代码会动态地生成一个本地监听地址和端口，并将这些信息添加到 `openssl s_client` 的 `-connect` 参数中，从而启动 `openssl s_client` 连接到测试服务器。

**使用者易犯错的点 (基于代码推断):**

虽然这段代码是测试代码，但可以从中推断出使用 `crypto/tls` 包时的一些常见错误：

* **配置不匹配的 TLS 版本:**  客户端和服务器配置的 `MinVersion` 和 `MaxVersion` 可能不兼容，导致握手失败。例如，服务器只支持 TLS 1.3，但客户端只支持 TLS 1.2。
* **没有交集的密码套件:**  客户端和服务器没有共同支持的密码套件，导致无法协商加密算法。这通常发生在配置了自定义的 `CipherSuites` 但没有包含客户端支持的套件时。
* **证书配置错误:**  服务器没有正确配置证书和私钥，或者证书与请求的服务器名称 (SNI) 不匹配。
* **ALPN 配置错误:**  服务器配置的 `NextProtos` 与客户端请求的不匹配，或者服务器没有配置 ALPN 但客户端请求了 ALPN。
* **错误地假设会话恢复的条件:**  没有理解会话恢复的条件 (例如，相同的密码套件、服务器名称等)，导致期望会话恢复但实际上进行了完整握手。
* **在不需要的地方禁用加密:**  过度使用 `InsecureSkipVerify` 可能会导致安全风险。

**总结:**

这段 `handshake_server_test.go` 代码是 `crypto/tls` 包中至关重要的部分，它通过大量的测试用例验证了 TLS 服务器握手实现的正确性和健壮性，涵盖了协议协商、密码套件选择、扩展处理、错误处理以及与外部 TLS 实现的互操作性等多个方面。这些测试用例也间接地反映了在使用 Go 语言进行 TLS 服务器开发时需要注意的一些配置和潜在的错误点。

Prompt: 
```
这是路径为go/src/crypto/tls/handshake_server_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls/internal/fips140tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClientHello(t *testing.T, serverConfig *Config, m handshakeMessage) {
	t.Helper()
	testClientHelloFailure(t, serverConfig, m, "")
}

// testFatal is a hack to prevent the compiler from complaining that there is a
// call to t.Fatal from a non-test goroutine
func testFatal(t *testing.T, err error) {
	t.Helper()
	t.Fatal(err)
}

func testClientHelloFailure(t *testing.T, serverConfig *Config, m handshakeMessage, expectedSubStr string) {
	c, s := localPipe(t)
	go func() {
		cli := Client(c, testConfig)
		if ch, ok := m.(*clientHelloMsg); ok {
			cli.vers = ch.vers
		}
		if _, err := cli.writeHandshakeRecord(m, nil); err != nil {
			testFatal(t, err)
		}
		c.Close()
	}()
	ctx := context.Background()
	conn := Server(s, serverConfig)
	ch, ech, err := conn.readClientHello(ctx)
	if conn.vers == VersionTLS13 {
		hs := serverHandshakeStateTLS13{
			c:           conn,
			ctx:         ctx,
			clientHello: ch,
			echContext:  ech,
		}
		if err == nil {
			err = hs.processClientHello()
		}
		if err == nil {
			err = hs.checkForResumption()
		}
		if err == nil {
			err = hs.pickCertificate()
		}
	} else {
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
	}
	s.Close()
	t.Helper()
	if len(expectedSubStr) == 0 {
		if err != nil && err != io.EOF {
			t.Errorf("Got error: %s; expected to succeed", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), expectedSubStr) {
		t.Errorf("Got error: %v; expected to match substring '%s'", err, expectedSubStr)
	}
}

func TestSimpleError(t *testing.T) {
	testClientHelloFailure(t, testConfig, &serverHelloDoneMsg{}, "unexpected handshake message")
}

var badProtocolVersions = []uint16{0x0000, 0x0005, 0x0100, 0x0105, 0x0200, 0x0205, VersionSSL30}

func TestRejectBadProtocolVersion(t *testing.T) {
	config := testConfig.Clone()
	config.MinVersion = VersionSSL30
	for _, v := range badProtocolVersions {
		testClientHelloFailure(t, config, &clientHelloMsg{
			vers:   v,
			random: make([]byte, 32),
		}, "unsupported versions")
	}
	testClientHelloFailure(t, config, &clientHelloMsg{
		vers:              VersionTLS12,
		supportedVersions: badProtocolVersions,
		random:            make([]byte, 32),
	}, "unsupported versions")
}

func TestNoSuiteOverlap(t *testing.T) {
	clientHello := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{0xff00},
		compressionMethods: []uint8{compressionNone},
	}
	testClientHelloFailure(t, testConfig, clientHello, "no cipher suite supported by both client and server")
}

func TestNoCompressionOverlap(t *testing.T) {
	clientHello := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		compressionMethods: []uint8{0xff},
	}
	testClientHelloFailure(t, testConfig, clientHello, "client does not support uncompressed connections")
}

func TestNoRC4ByDefault(t *testing.T) {
	clientHello := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{TLS_RSA_WITH_RC4_128_SHA},
		compressionMethods: []uint8{compressionNone},
	}
	serverConfig := testConfig.Clone()
	// Reset the enabled cipher suites to nil in order to test the
	// defaults.
	serverConfig.CipherSuites = nil
	testClientHelloFailure(t, serverConfig, clientHello, "no cipher suite supported by both client and server")
}

func TestRejectSNIWithTrailingDot(t *testing.T) {
	testClientHelloFailure(t, testConfig, &clientHelloMsg{
		vers:       VersionTLS12,
		random:     make([]byte, 32),
		serverName: "foo.com.",
	}, "unexpected message")
}

func TestDontSelectECDSAWithRSAKey(t *testing.T) {
	// Test that, even when both sides support an ECDSA cipher suite, it
	// won't be selected if the server's private key doesn't support it.
	clientHello := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		compressionMethods: []uint8{compressionNone},
		supportedCurves:    []CurveID{CurveP256},
		supportedPoints:    []uint8{pointFormatUncompressed},
	}
	serverConfig := testConfig.Clone()
	serverConfig.CipherSuites = clientHello.cipherSuites
	serverConfig.Certificates = make([]Certificate, 1)
	serverConfig.Certificates[0].Certificate = [][]byte{testECDSACertificate}
	serverConfig.Certificates[0].PrivateKey = testECDSAPrivateKey
	serverConfig.BuildNameToCertificate()
	// First test that it *does* work when the server's key is ECDSA.
	testClientHello(t, serverConfig, clientHello)

	// Now test that switching to an RSA key causes the expected error (and
	// not an internal error about a signing failure).
	serverConfig.Certificates = testConfig.Certificates
	testClientHelloFailure(t, serverConfig, clientHello, "no cipher suite supported by both client and server")
}

func TestDontSelectRSAWithECDSAKey(t *testing.T) {
	// Test that, even when both sides support an RSA cipher suite, it
	// won't be selected if the server's private key doesn't support it.
	clientHello := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
		supportedCurves:    []CurveID{CurveP256},
		supportedPoints:    []uint8{pointFormatUncompressed},
	}
	serverConfig := testConfig.Clone()
	serverConfig.CipherSuites = clientHello.cipherSuites
	// First test that it *does* work when the server's key is RSA.
	testClientHello(t, serverConfig, clientHello)

	// Now test that switching to an ECDSA key causes the expected error
	// (and not an internal error about a signing failure).
	serverConfig.Certificates = make([]Certificate, 1)
	serverConfig.Certificates[0].Certificate = [][]byte{testECDSACertificate}
	serverConfig.Certificates[0].PrivateKey = testECDSAPrivateKey
	serverConfig.BuildNameToCertificate()
	testClientHelloFailure(t, serverConfig, clientHello, "no cipher suite supported by both client and server")
}

func TestRenegotiationExtension(t *testing.T) {
	skipFIPS(t) // #70505

	clientHello := &clientHelloMsg{
		vers:                         VersionTLS12,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		secureRenegotiationSupported: true,
		cipherSuites:                 []uint16{TLS_RSA_WITH_RC4_128_SHA},
	}

	bufChan := make(chan []byte, 1)
	c, s := localPipe(t)

	go func() {
		cli := Client(c, testConfig)
		cli.vers = clientHello.vers
		if _, err := cli.writeHandshakeRecord(clientHello, nil); err != nil {
			testFatal(t, err)
		}

		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			t.Errorf("Server read returned error: %s", err)
			return
		}
		c.Close()
		bufChan <- buf[:n]
	}()

	Server(s, testConfig).Handshake()
	buf := <-bufChan

	if len(buf) < 5+4 {
		t.Fatalf("Server returned short message of length %d", len(buf))
	}
	// buf contains a TLS record, with a 5 byte record header and a 4 byte
	// handshake header. The length of the ServerHello is taken from the
	// handshake header.
	serverHelloLen := int(buf[6])<<16 | int(buf[7])<<8 | int(buf[8])

	var serverHello serverHelloMsg
	// unmarshal expects to be given the handshake header, but
	// serverHelloLen doesn't include it.
	if !serverHello.unmarshal(buf[5 : 9+serverHelloLen]) {
		t.Fatalf("Failed to parse ServerHello")
	}

	if !serverHello.secureRenegotiationSupported {
		t.Errorf("Secure renegotiation extension was not echoed.")
	}
}

func TestTLS12OnlyCipherSuites(t *testing.T) {
	skipFIPS(t) // No TLS 1.1 in FIPS mode.

	// Test that a Server doesn't select a TLS 1.2-only cipher suite when
	// the client negotiates TLS 1.1.
	clientHello := &clientHelloMsg{
		vers:   VersionTLS11,
		random: make([]byte, 32),
		cipherSuites: []uint16{
			// The Server, by default, will use the client's
			// preference order. So the GCM cipher suite
			// will be selected unless it's excluded because
			// of the version in this ClientHello.
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_RSA_WITH_RC4_128_SHA,
		},
		compressionMethods: []uint8{compressionNone},
		supportedCurves:    []CurveID{CurveP256, CurveP384, CurveP521},
		supportedPoints:    []uint8{pointFormatUncompressed},
	}

	c, s := localPipe(t)
	replyChan := make(chan any)
	go func() {
		cli := Client(c, testConfig)
		cli.vers = clientHello.vers
		if _, err := cli.writeHandshakeRecord(clientHello, nil); err != nil {
			testFatal(t, err)
		}
		reply, err := cli.readHandshake(nil)
		c.Close()
		if err != nil {
			replyChan <- err
		} else {
			replyChan <- reply
		}
	}()
	config := testConfig.Clone()
	config.CipherSuites = clientHello.cipherSuites
	Server(s, config).Handshake()
	s.Close()
	reply := <-replyChan
	if err, ok := reply.(error); ok {
		t.Fatal(err)
	}
	serverHello, ok := reply.(*serverHelloMsg)
	if !ok {
		t.Fatalf("didn't get ServerHello message in reply. Got %v\n", reply)
	}
	if s := serverHello.cipherSuite; s != TLS_RSA_WITH_RC4_128_SHA {
		t.Fatalf("bad cipher suite from server: %x", s)
	}
}

func TestTLSPointFormats(t *testing.T) {
	// Test that a Server returns the ec_point_format extension when ECC is
	// negotiated, and not on a RSA handshake or if ec_point_format is missing.
	tests := []struct {
		name                string
		cipherSuites        []uint16
		supportedCurves     []CurveID
		supportedPoints     []uint8
		wantSupportedPoints bool
	}{
		{"ECC", []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, []CurveID{CurveP256}, []uint8{pointFormatUncompressed}, true},
		{"ECC without ec_point_format", []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, []CurveID{CurveP256}, nil, false},
		{"ECC with extra values", []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, []CurveID{CurveP256}, []uint8{13, 37, pointFormatUncompressed, 42}, true},
		{"RSA", []uint16{TLS_RSA_WITH_AES_256_GCM_SHA384}, nil, nil, false},
		{"RSA with ec_point_format", []uint16{TLS_RSA_WITH_AES_256_GCM_SHA384}, nil, []uint8{pointFormatUncompressed}, false},
	}
	for _, tt := range tests {
		// The RSA subtests should be enabled for FIPS 140 required mode: #70505
		if strings.HasPrefix(tt.name, "RSA") && fips140tls.Required() {
			t.Logf("skipping in FIPS mode.")
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			clientHello := &clientHelloMsg{
				vers:               VersionTLS12,
				random:             make([]byte, 32),
				cipherSuites:       tt.cipherSuites,
				compressionMethods: []uint8{compressionNone},
				supportedCurves:    tt.supportedCurves,
				supportedPoints:    tt.supportedPoints,
			}

			c, s := localPipe(t)
			replyChan := make(chan any)
			go func() {
				clientConfig := testConfig.Clone()
				clientConfig.Certificates = []Certificate{{Certificate: [][]byte{testRSA2048Certificate}, PrivateKey: testRSA2048PrivateKey}}
				cli := Client(c, clientConfig)
				cli.vers = clientHello.vers
				if _, err := cli.writeHandshakeRecord(clientHello, nil); err != nil {
					testFatal(t, err)
				}
				reply, err := cli.readHandshake(nil)
				c.Close()
				if err != nil {
					replyChan <- err
				} else {
					replyChan <- reply
				}
			}()
			serverConfig := testConfig.Clone()
			serverConfig.Certificates = []Certificate{{Certificate: [][]byte{testRSA2048Certificate}, PrivateKey: testRSA2048PrivateKey}}
			serverConfig.CipherSuites = clientHello.cipherSuites
			Server(s, serverConfig).Handshake()
			s.Close()
			reply := <-replyChan
			if err, ok := reply.(error); ok {
				t.Fatal(err)
			}
			serverHello, ok := reply.(*serverHelloMsg)
			if !ok {
				t.Fatalf("didn't get ServerHello message in reply. Got %v\n", reply)
			}
			if tt.wantSupportedPoints {
				if !bytes.Equal(serverHello.supportedPoints, []uint8{pointFormatUncompressed}) {
					t.Fatal("incorrect ec_point_format extension from server")
				}
			} else {
				if len(serverHello.supportedPoints) != 0 {
					t.Fatalf("unexpected ec_point_format extension from server: %v", serverHello.supportedPoints)
				}
			}
		})
	}
}

func TestAlertForwarding(t *testing.T) {
	c, s := localPipe(t)
	go func() {
		Client(c, testConfig).sendAlert(alertUnknownCA)
		c.Close()
	}()

	err := Server(s, testConfig).Handshake()
	s.Close()
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Err != error(alertUnknownCA) {
		t.Errorf("Got error: %s; expected: %s", err, error(alertUnknownCA))
	}
}

func TestClose(t *testing.T) {
	c, s := localPipe(t)
	go c.Close()

	err := Server(s, testConfig).Handshake()
	s.Close()
	if err != io.EOF {
		t.Errorf("Got error: %s; expected: %s", err, io.EOF)
	}
}

func TestVersion(t *testing.T) {
	serverConfig := &Config{
		Certificates: testConfig.Certificates,
		MaxVersion:   VersionTLS13,
	}
	clientConfig := &Config{
		InsecureSkipVerify: true,
		MinVersion:         VersionTLS12,
	}
	state, _, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
	if state.Version != VersionTLS13 {
		t.Fatalf("incorrect version %x, should be %x", state.Version, VersionTLS11)
	}

	clientConfig.MinVersion = 0
	serverConfig.MaxVersion = VersionTLS11
	_, _, err = testHandshake(t, clientConfig, serverConfig)
	if err == nil {
		t.Fatalf("expected failure to connect with TLS 1.0/1.1")
	}
}

func TestCipherSuitePreference(t *testing.T) {
	skipFIPS(t) // No RC4 or CHACHA20_POLY1305 in FIPS mode.

	serverConfig := &Config{
		CipherSuites: []uint16{TLS_RSA_WITH_RC4_128_SHA, TLS_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
		Certificates: testConfig.Certificates,
		MaxVersion:   VersionTLS12,
		GetConfigForClient: func(chi *ClientHelloInfo) (*Config, error) {
			if chi.CipherSuites[0] != TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 {
				t.Error("the advertised order should not depend on Config.CipherSuites")
			}
			if len(chi.CipherSuites) != 2+len(defaultCipherSuitesTLS13) {
				t.Error("the advertised TLS 1.2 suites should be filtered by Config.CipherSuites")
			}
			return nil, nil
		},
	}
	clientConfig := &Config{
		CipherSuites:       []uint16{TLS_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
		InsecureSkipVerify: true,
	}
	state, _, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
	if state.CipherSuite != TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 {
		t.Error("the preference order should not depend on Config.CipherSuites")
	}
}

func TestSCTHandshake(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testSCTHandshake(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testSCTHandshake(t, VersionTLS13) })
}

func testSCTHandshake(t *testing.T, version uint16) {
	expected := [][]byte{[]byte("certificate"), []byte("transparency")}
	serverConfig := &Config{
		Certificates: []Certificate{{
			Certificate:                 [][]byte{testRSACertificate},
			PrivateKey:                  testRSAPrivateKey,
			SignedCertificateTimestamps: expected,
		}},
		MaxVersion: version,
	}
	clientConfig := &Config{
		InsecureSkipVerify: true,
	}
	_, state, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
	actual := state.SignedCertificateTimestamps
	if len(actual) != len(expected) {
		t.Fatalf("got %d scts, want %d", len(actual), len(expected))
	}
	for i, sct := range expected {
		if !bytes.Equal(sct, actual[i]) {
			t.Fatalf("SCT #%d was %x, but expected %x", i, actual[i], sct)
		}
	}
}

func TestCrossVersionResume(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testCrossVersionResume(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testCrossVersionResume(t, VersionTLS13) })
}

func testCrossVersionResume(t *testing.T, version uint16) {
	serverConfig := &Config{
		CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: testConfig.Certificates,
	}
	clientConfig := &Config{
		CipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		InsecureSkipVerify: true,
		ClientSessionCache: NewLRUClientSessionCache(1),
		ServerName:         "servername",
		MinVersion:         VersionTLS12,
	}

	// Establish a session at TLS 1.3.
	clientConfig.MaxVersion = VersionTLS13
	_, _, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}

	// The client session cache now contains a TLS 1.3 session.
	state, _, err := testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
	if !state.DidResume {
		t.Fatalf("handshake did not resume at the same version")
	}

	// Test that the server will decline to resume at a lower version.
	clientConfig.MaxVersion = VersionTLS12
	state, _, err = testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
	if state.DidResume {
		t.Fatalf("handshake resumed at a lower version")
	}

	// The client session cache now contains a TLS 1.2 session.
	state, _, err = testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
	if !state.DidResume {
		t.Fatalf("handshake did not resume at the same version")
	}

	// Test that the server will decline to resume at a higher version.
	clientConfig.MaxVersion = VersionTLS13
	state, _, err = testHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}
	if state.DidResume {
		t.Fatalf("handshake resumed at a higher version")
	}
}

// Note: see comment in handshake_test.go for details of how the reference
// tests work.

// serverTest represents a test of the TLS server handshake against a reference
// implementation.
type serverTest struct {
	// name is a freeform string identifying the test and the file in which
	// the expected results will be stored.
	name string
	// command, if not empty, contains a series of arguments for the
	// command to run for the reference server.
	command []string
	// expectedPeerCerts contains a list of PEM blocks of expected
	// certificates from the client.
	expectedPeerCerts []string
	// config, if not nil, contains a custom Config to use for this test.
	config *Config
	// expectHandshakeErrorIncluding, when not empty, contains a string
	// that must be a substring of the error resulting from the handshake.
	expectHandshakeErrorIncluding string
	// validate, if not nil, is a function that will be called with the
	// ConnectionState of the resulting connection. It returns false if the
	// ConnectionState is unacceptable.
	validate func(ConnectionState) error
	// wait, if true, prevents this subtest from calling t.Parallel.
	// If false, runServerTest* returns immediately.
	wait bool
}

var defaultClientCommand = []string{"openssl", "s_client", "-no_ticket"}

// connFromCommand starts opens a listening socket and starts the reference
// client to connect to it. It returns a recordingConn that wraps the resulting
// connection.
func (test *serverTest) connFromCommand() (conn *recordingConn, child *exec.Cmd, err error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	if err != nil {
		return nil, nil, err
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	var command []string
	command = append(command, test.command...)
	if len(command) == 0 {
		command = defaultClientCommand
	}
	command = append(command, "-connect")
	command = append(command, fmt.Sprintf("127.0.0.1:%d", port))
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = nil
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	connChan := make(chan any, 1)
	go func() {
		tcpConn, err := l.Accept()
		if err != nil {
			connChan <- err
			return
		}
		connChan <- tcpConn
	}()

	var tcpConn net.Conn
	select {
	case connOrError := <-connChan:
		if err, ok := connOrError.(error); ok {
			return nil, nil, err
		}
		tcpConn = connOrError.(net.Conn)
	case <-time.After(2 * time.Second):
		return nil, nil, errors.New("timed out waiting for connection from child process")
	}

	record := &recordingConn{
		Conn: tcpConn,
	}

	return record, cmd, nil
}

func (test *serverTest) dataPath() string {
	return filepath.Join("testdata", "Server-"+test.name)
}

func (test *serverTest) loadData() (flows [][]byte, err error) {
	in, err := os.Open(test.dataPath())
	if err != nil {
		return nil, err
	}
	defer in.Close()
	return parseTestData(in)
}

func (test *serverTest) run(t *testing.T, write bool) {
	var serverConn net.Conn
	var recordingConn *recordingConn
	var childProcess *exec.Cmd

	if write {
		var err error
		recordingConn, childProcess, err = test.connFromCommand()
		if err != nil {
			t.Fatalf("Failed to start subcommand: %s", err)
		}
		serverConn = recordingConn
		defer func() {
			if t.Failed() {
				t.Logf("OpenSSL output:\n\n%s", childProcess.Stdout)
			}
		}()
	} else {
		flows, err := test.loadData()
		if err != nil {
			t.Fatalf("Failed to load data from %s", test.dataPath())
		}
		serverConn = &replayingConn{t: t, flows: flows, reading: true}
	}
	config := test.config
	if config == nil {
		config = testConfig
	}
	server := Server(serverConn, config)

	_, err := server.Write([]byte("hello, world\n"))
	if len(test.expectHandshakeErrorIncluding) > 0 {
		if err == nil {
			t.Errorf("Error expected, but no error returned")
		} else if s := err.Error(); !strings.Contains(s, test.expectHandshakeErrorIncluding) {
			t.Errorf("Error expected containing '%s' but got '%s'", test.expectHandshakeErrorIncluding, s)
		}
	} else {
		if err != nil {
			t.Logf("Error from Server.Write: '%s'", err)
		}
	}
	server.Close()

	connState := server.ConnectionState()
	peerCerts := connState.PeerCertificates
	if len(peerCerts) == len(test.expectedPeerCerts) {
		for i, peerCert := range peerCerts {
			block, _ := pem.Decode([]byte(test.expectedPeerCerts[i]))
			if !bytes.Equal(block.Bytes, peerCert.Raw) {
				t.Fatalf("%s: mismatch on peer cert %d", test.name, i+1)
			}
		}
	} else {
		t.Fatalf("%s: mismatch on peer list length: %d (wanted) != %d (got)", test.name, len(test.expectedPeerCerts), len(peerCerts))
	}

	if test.validate != nil {
		if err := test.validate(connState); err != nil {
			t.Fatalf("validate callback returned error: %s", err)
		}
	}

	if write {
		serverConn.Close()
		path := test.dataPath()
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			t.Fatalf("Failed to create output file: %s", err)
		}
		defer out.Close()
		recordingConn.Close()
		if len(recordingConn.flows) < 3 {
			if len(test.expectHandshakeErrorIncluding) == 0 {
				t.Fatalf("Handshake failed")
			}
		}
		recordingConn.WriteTo(out)
		t.Logf("Wrote %s\n", path)
		childProcess.Wait()
	}
}

func runServerTestForVersion(t *testing.T, template *serverTest, version, option string) {
	// Make a deep copy of the template before going parallel.
	test := *template
	if template.config != nil {
		test.config = template.config.Clone()
	}
	test.name = version + "-" + test.name
	if len(test.command) == 0 {
		test.command = defaultClientCommand
	}
	test.command = append([]string(nil), test.command...)
	test.command = append(test.command, option)

	runTestAndUpdateIfNeeded(t, version, test.run, test.wait)
}

func runServerTestTLS10(t *testing.T, template *serverTest) {
	runServerTestForVersion(t, template, "TLSv10", "-tls1")
}

func runServerTestTLS11(t *testing.T, template *serverTest) {
	runServerTestForVersion(t, template, "TLSv11", "-tls1_1")
}

func runServerTestTLS12(t *testing.T, template *serverTest) {
	runServerTestForVersion(t, template, "TLSv12", "-tls1_2")
}

func runServerTestTLS13(t *testing.T, template *serverTest) {
	runServerTestForVersion(t, template, "TLSv13", "-tls1_3")
}

func TestHandshakeServerRSARC4(t *testing.T) {
	test := &serverTest{
		name:    "RSA-RC4",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "RC4-SHA"},
	}
	runServerTestTLS10(t, test)
	runServerTestTLS11(t, test)
	runServerTestTLS12(t, test)
}

func TestHandshakeServerRSA3DES(t *testing.T) {
	test := &serverTest{
		name:    "RSA-3DES",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "DES-CBC3-SHA"},
	}
	runServerTestTLS10(t, test)
	runServerTestTLS12(t, test)
}

func TestHandshakeServerRSAAES(t *testing.T) {
	test := &serverTest{
		name:    "RSA-AES",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "AES128-SHA"},
	}
	runServerTestTLS10(t, test)
	runServerTestTLS12(t, test)
}

func TestHandshakeServerAESGCM(t *testing.T) {
	test := &serverTest{
		name:    "RSA-AES-GCM",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"},
	}
	runServerTestTLS12(t, test)
}

func TestHandshakeServerAES256GCMSHA384(t *testing.T) {
	test := &serverTest{
		name:    "RSA-AES256-GCM-SHA384",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "ECDHE-RSA-AES256-GCM-SHA384"},
	}
	runServerTestTLS12(t, test)
}

func TestHandshakeServerAES128SHA256(t *testing.T) {
	test := &serverTest{
		name:    "AES128-SHA256",
		command: []string{"openssl", "s_client", "-no_ticket", "-ciphersuites", "TLS_AES_128_GCM_SHA256"},
	}
	runServerTestTLS13(t, test)
}
func TestHandshakeServerAES256SHA384(t *testing.T) {
	test := &serverTest{
		name:    "AES256-SHA384",
		command: []string{"openssl", "s_client", "-no_ticket", "-ciphersuites", "TLS_AES_256_GCM_SHA384"},
	}
	runServerTestTLS13(t, test)
}
func TestHandshakeServerCHACHA20SHA256(t *testing.T) {
	test := &serverTest{
		name:    "CHACHA20-SHA256",
		command: []string{"openssl", "s_client", "-no_ticket", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"},
	}
	runServerTestTLS13(t, test)
}

func TestHandshakeServerECDHEECDSAAES(t *testing.T) {
	config := testConfig.Clone()
	config.Certificates = make([]Certificate, 1)
	config.Certificates[0].Certificate = [][]byte{testECDSACertificate}
	config.Certificates[0].PrivateKey = testECDSAPrivateKey
	config.BuildNameToCertificate()

	test := &serverTest{
		name:    "ECDHE-ECDSA-AES",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "ECDHE-ECDSA-AES256-SHA", "-ciphersuites", "TLS_AES_128_GCM_SHA256"},
		config:  config,
	}
	runServerTestTLS10(t, test)
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)
}

func TestHandshakeServerX25519(t *testing.T) {
	config := testConfig.Clone()
	config.CurvePreferences = []CurveID{X25519}

	test := &serverTest{
		name:    "X25519",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256", "-curves", "X25519"},
		config:  config,
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)
}

func TestHandshakeServerP256(t *testing.T) {
	config := testConfig.Clone()
	config.CurvePreferences = []CurveID{CurveP256}

	test := &serverTest{
		name:    "P256",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256", "-curves", "P-256"},
		config:  config,
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)
}

func TestHandshakeServerHelloRetryRequest(t *testing.T) {
	config := testConfig.Clone()
	config.CurvePreferences = []CurveID{CurveP256}

	test := &serverTest{
		name:    "HelloRetryRequest",
		command: []string{"openssl", "s_client", "-no_ticket", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256", "-curves", "X25519:P-256"},
		config:  config,
		validate: func(cs ConnectionState) error {
			if !cs.testingOnlyDidHRR {
				return errors.New("expected HelloRetryRequest")
			}
			return nil
		},
	}
	runServerTestTLS13(t, test)
}

// TestHandshakeServerKeySharePreference checks that we prefer a key share even
// if it's later in the CurvePreferences order.
func TestHandshakeServerKeySharePreference(t *testing.T) {
	config := testConfig.Clone()
	config.CurvePreferences = []CurveID{X25519, CurveP256}

	test := &serverTest{
		name:    "KeySharePreference",
		command: []string{"openssl", "s_client", "-no_ticket", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256", "-curves", "P-256:X25519"},
		config:  config,
		validate: func(cs ConnectionState) error {
			if cs.testingOnlyDidHRR {
				return errors.New("unexpected HelloRetryRequest")
			}
			return nil
		},
	}
	runServerTestTLS13(t, test)
}

func TestHandshakeServerALPN(t *testing.T) {
	config := testConfig.Clone()
	config.NextProtos = []string{"proto1", "proto2"}

	test := &serverTest{
		name: "ALPN",
		// Note that this needs OpenSSL 1.0.2 because that is the first
		// version that supports the -alpn flag.
		command: []string{"openssl", "s_client", "-alpn", "proto2,proto1", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"},
		config:  config,
		validate: func(state ConnectionState) error {
			// The server's preferences should override the client.
			if state.NegotiatedProtocol != "proto1" {
				return fmt.Errorf("Got protocol %q, wanted proto1", state.NegotiatedProtocol)
			}
			return nil
		},
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)
}

func TestHandshakeServerALPNNoMatch(t *testing.T) {
	config := testConfig.Clone()
	config.NextProtos = []string{"proto3"}

	test := &serverTest{
		name: "ALPN-NoMatch",
		// Note that this needs OpenSSL 1.0.2 because that is the first
		// version that supports the -alpn flag.
		command:                       []string{"openssl", "s_client", "-alpn", "proto2,proto1", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"},
		config:                        config,
		expectHandshakeErrorIncluding: "client requested unsupported application protocol",
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)
}

func TestHandshakeServerALPNNotConfigured(t *testing.T) {
	config := testConfig.Clone()
	config.NextProtos = nil

	test := &serverTest{
		name: "ALPN-NotConfigured",
		// Note that this needs OpenSSL 1.0.2 because that is the first
		// version that supports the -alpn flag.
		command: []string{"openssl", "s_client", "-alpn", "proto2,proto1", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"},
		config:  config,
		validate: func(state ConnectionState) error {
			if state.NegotiatedProtocol != "" {
				return fmt.Errorf("Got protocol %q, wanted nothing", state.NegotiatedProtocol)
			}
			return nil
		},
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)
}

func TestHandshakeServerALPNFallback(t *testing.T) {
	config := testConfig.Clone()
	config.NextProtos = []string{"proto1", "h2", "proto2"}

	test := &serverTest{
		name: "ALPN-Fallback",
		// Note that this needs OpenSSL 1.0.2 because that is the first
		// version that supports the -alpn flag.
		command: []string{"openssl", "s_client", "-alpn", "proto3,http/1.1,proto4", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"},
		config:  config,
		validate: func(state ConnectionState) error {
			if state.NegotiatedProtocol != "" {
				return fmt.Errorf("Got protocol %q, wanted nothing", state.NegotiatedProtocol)
			}
			return nil
		},
	}
	runServerTestTLS12(t, test)
	runServerTestTLS13(t, test)
}

// TestHandshakeServerSNI involves a client sending an SNI extension of
// "snitest.com", which happens to match the CN of testSNICertificate. The test
// verifies that the server correctly selects that certificate.
func TestHandshakeServerSNI(t *testing.T) {
	test := &serverTest{
		name:    "SNI",
		command: []string{"openssl", "s_client", "-no_ticket", "-cipher", "AES128-SHA", "-servername", "snitest.com"},
	}
	runServerTestTLS12(t, test)
}

// TestHandshakeServerSNIGetCertificate is similar to TestHandshakeServerSNI, but
// tests the dynamic GetCertificate method
func TestHandshakeServerSNIGetCertificate(t *testing.T) {
	config := testConfig.Clone()

	// Replace the NameToCertificate map with a GetCertificate function
	nameToCert := config.NameToCertificate
	config.NameToCertificate = nil
	config.GetCertificate = func(clientHello *ClientHelloInfo) (*Certificate, error) 
"""




```