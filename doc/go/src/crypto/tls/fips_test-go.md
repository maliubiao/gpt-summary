Response:
The user wants to understand the functionality of the provided Go code snippet, which is a test file (`fips_test.go`) for the `crypto/tls` package in Go. The file seems to focus on testing the behavior of the TLS implementation when FIPS mode is enabled or disabled.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Purpose:** The filename `fips_test.go` and the presence of functions like `runWithFIPSEnabled` and `runWithFIPSDisabled` strongly suggest the main goal is to test TLS functionality under FIPS (Federal Information Processing Standard) compliance.

2. **Analyze Key Functions:**
   - `allCipherSuitesIncludingTLS13()`:  This function gathers all supported cipher suites, including those for TLS 1.3. This is relevant for testing different encryption algorithms.
   - `isTLS13CipherSuite(id uint16)`:  Determines if a given cipher suite ID belongs to TLS 1.3. This indicates a focus on supporting and testing the latest TLS version.
   - `generateKeyShare(group CurveID)`:  Generates key shares for a specific elliptic curve. This is related to the ECDHE key exchange mechanism.
   - `TestFIPSServerProtocolVersion(t *testing.T)`:  This function tests how the server behaves with different TLS protocol versions when FIPS mode is enabled or disabled. It specifically checks if non-FIPS versions are rejected in FIPS mode.
   - `isFIPSVersion(v uint16)`:  Checks if a TLS version is considered FIPS-compliant (TLS 1.2 and 1.3).
   - `isFIPSCipherSuite(id uint16)`:  Identifies if a cipher suite is FIPS-approved. It lists specific GCM-based cipher suites.
   - `isFIPSCurve(id CurveID)`:  Checks if an elliptic curve is FIPS-approved (P-256 and P-384).
   - `isECDSA(id uint16)`:  Determines if a cipher suite uses ECDSA for signing.
   - `isFIPSSignatureScheme(alg SignatureScheme)`:  Checks if a signature scheme is FIPS-compliant.
   - `TestFIPSServerCipherSuites(t *testing.T)`:  Tests server behavior with various cipher suites under FIPS mode. It verifies that only FIPS-approved cipher suites are allowed.
   - `TestFIPSServerCurves(t *testing.T)`:  Tests server behavior with different elliptic curves in FIPS mode, ensuring only FIPS-approved curves are accepted.
   - `fipsHandshake(t *testing.T, clientConfig, serverConfig *Config)`:  A helper function to perform a TLS handshake for testing.
   - `TestFIPSServerSignatureAndHash(t *testing.T)`:  Tests how the server handles different signature and hash algorithms in FIPS mode.
   - `TestFIPSClientHello(t *testing.T)` and `testFIPSClientHello(t *testing.T)`: These functions verify that the client, when in FIPS mode, only offers FIPS-compliant protocol versions, cipher suites, curves, and signature schemes.
   - `TestFIPSCertAlgs(t *testing.T)`:  A comprehensive test that examines certificate verification under FIPS mode. It covers various certificate chains involving different key types (RSA, ECDSA) and sizes.
   - `fipsCert`, `fipsRSAKey`, `fipsECDSAKey`, `fipsCertificate`: Helper functions and struct to create and manage test certificates with FIPS compliance flags.

3. **Infer High-Level Functionality:** Based on the analysis, the code's primary function is to ensure the `crypto/tls` package correctly implements FIPS 140-2 requirements when operating in FIPS mode. This involves restricting the allowed TLS protocol versions, cipher suites, elliptic curves, and signature algorithms to those approved by FIPS. It also includes testing certificate verification with FIPS constraints.

4. **Provide Go Code Examples:** The user requested examples. The most straightforward examples would be related to how FIPS mode affects the configuration of TLS clients and servers. Illustrate setting `MinVersion`, `MaxVersion`, `CipherSuites`, and `CurvePreferences`, and explain how FIPS mode would influence the actual choices made during a handshake.

5. **Address Code Reasoning (with Assumptions):** The code heavily relies on helper functions like `runWithFIPSEnabled` and `runWithFIPSDisabled`. Since the implementation of these functions isn't provided in the snippet, a reasonable assumption is that they manipulate a global setting or environment variable to enable or disable FIPS mode for the duration of the test. Demonstrate how these functions are used to execute the same test under both FIPS and non-FIPS conditions and how the expected outcomes differ.

6. **Explain Command-Line Parameters (if applicable):** In this specific code snippet, there are no directly visible command-line parameters being processed. However, it's crucial to mention that the underlying mechanism for enabling/disabling FIPS mode might involve a command-line flag when running the tests or when building the Go application with specific FIPS-related build tags.

7. **Identify Potential Pitfalls:** A common mistake users might make is assuming that simply setting FIPS mode will automatically handle all compliance aspects. It's important to emphasize that developers still need to choose FIPS-approved configurations (e.g., cipher suites, curves) even when FIPS mode is enabled.

8. **Structure the Answer:** Organize the information logically, starting with a high-level overview and then delving into specifics. Use clear headings and formatting to improve readability. Use code blocks for examples and be precise with terminology.

By following these steps, the resulting answer should comprehensively address the user's request, providing a clear understanding of the Go code's functionality and its role in testing FIPS compliance in the `crypto/tls` package.
这段Go语言代码是 `crypto/tls` 包的一部分，专门用于测试在启用和禁用 FIPS (Federal Information Processing Standard) 模式下 TLS 的行为。它主要关注以下功能：

**1. 测试 FIPS 模式下支持的协议版本：**

   - `TestFIPSServerProtocolVersion` 函数测试了当 FIPS 模式启用和禁用时，服务器对不同 TLS 协议版本的支持情况。
   - 在 FIPS 禁用时，服务器应该接受 TLS 1.0, TLS 1.1, TLS 1.2 和 TLS 1.3。
   - 在 FIPS 启用时，服务器应该只接受 TLS 1.2 和 TLS 1.3，拒绝 TLS 1.0 和 TLS 1.1。

   **Go 代码示例：**

   ```go
   func runWithFIPSEnabled(t *testing.T, f func(t *testing.T)) {
       // 假设此函数会设置某种全局或环境变量来启用 FIPS 模式
       // 实际实现可能有所不同
       t.Log("启用 FIPS 模式")
       f(t)
       t.Log("禁用 FIPS 模式")
   }

   func TestFIPSServerProtocolVersionExample(t *testing.T) {
       test := func(t *testing.T, name string, v uint16, msg string) {
           t.Run(name, func(t *testing.T) {
               serverConfig := &Config{MinVersion: VersionSSL30}
               clientConfig := &Config{MinVersion: v, MaxVersion: v}
               // 模拟握手过程，这里只是为了演示概念
               err := simulateHandshake(clientConfig, serverConfig) // 假设有这样一个模拟握手函数
               if msg == "" {
                   if err != nil {
                       t.Fatalf("期望成功，但得到错误: %v", err)
                   }
               } else {
                   if err == nil {
                       t.Fatalf("期望错误，但得到成功")
                   }
                   if !strings.Contains(err.Error(), msg) {
                       t.Fatalf("得到错误 %v, 期望包含 %q", err, msg)
                   }
               }
           })
       }

       runWithFIPSEnabled(t, func(t *testing.T) {
           test(t, "VersionTLS10", VersionTLS10, "不支持的版本") // 假设错误信息包含 "不支持的版本"
       })
   }

   // 假设的模拟握手函数
   func simulateHandshake(clientConfig, serverConfig *Config) error {
       if isFIPSModeEnabled() { // 假设有函数检查 FIPS 模式是否启用
           if clientConfig.MaxVersion < VersionTLS12 {
               return fmt.Errorf("不支持的版本")
           }
       }
       return nil
   }

   // 假设的检查 FIPS 模式是否启用的函数
   func isFIPSModeEnabled() bool {
       // 在实际的 crypto/tls 包中，FIPS 模式的启用可能通过构建标签或其他机制实现
       return true // 这里只是为了演示
   }
   ```

   **假设的输入与输出：**

   - **输入 (在 `runWithFIPSEnabled` 中执行):**  `clientConfig` 设置 `MaxVersion` 为 `VersionTLS10`。
   - **输出:** `simulateHandshake` 函数返回包含 "不支持的版本" 的错误，因为在 FIPS 模式下不允许 TLS 1.0。

**2. 测试 FIPS 模式下支持的密码套件：**

   - `TestFIPSServerCipherSuites` 函数测试了服务器在 FIPS 模式下是否只接受 FIPS 批准的密码套件。
   - 它遍历所有可能的密码套件，并测试当客户端只提供一个密码套件时，服务器在 FIPS 模式下的反应。
   - 如果客户端提供的密码套件不是 FIPS 批准的，服务器应该拒绝连接。

   **Go 代码示例：**

   ```go
   func TestFIPSServerCipherSuitesExample(t *testing.T) {
       serverConfig := &Config{
           Certificates: []Certificate{{Certificate: [][]byte{testRSACertificate}, PrivateKey: testRSAPrivateKey}},
       }
       serverConfig.BuildNameToCertificate()

       runWithFIPSEnabled(t, func(t *testing.T) {
           clientHello := &clientHelloMsg{
               vers:                         VersionTLS12,
               random:                       make([]byte, 32),
               cipherSuites:                 []uint16{TLS_RSA_WITH_RC4_128_SHA}, // 假设这是一个非 FIPS 的密码套件
               compressionMethods:           []uint8{compressionNone},
               supportedCurves:              defaultCurvePreferences(),
               keyShares:                    []keyShare{generateKeyShare(CurveP256)},
               supportedPoints:              []uint8{pointFormatUncompressed},
               supportedVersions:            []uint16{VersionTLS12},
               supportedSignatureAlgorithms: defaultSupportedSignatureAlgorithmsFIPS,
           }
           err := simulateServerHandshakeWithClientHello(serverConfig, clientHello) // 假设有这样一个模拟函数
           if err == nil || !strings.Contains(err.Error(), "没有客户端和服务端都支持的密码套件") {
               t.Fatalf("在 FIPS 模式下，期望因不支持的密码套件而失败，但结果不符合预期: %v", err)
           }
       })
   }

   // 假设的模拟服务端处理 ClientHello 的函数
   func simulateServerHandshakeWithClientHello(serverConfig *Config, clientHello *clientHelloMsg) error {
       if isFIPSModeEnabled() {
           isFIPSSupported := false
           for _, suite := range clientHello.cipherSuites {
               if isFIPSCipherSuite(suite) {
                   isFIPSSupported = true
                   break
               }
           }
           if !isFIPSSupported {
               return fmt.Errorf("没有客户端和服务端都支持的密码套件")
           }
       }
       return nil
   }
   ```

   **假设的输入与输出：**

   - **输入 (在 `runWithFIPSEnabled` 中执行):** `clientHello` 消息包含一个非 FIPS 的密码套件 `TLS_RSA_WITH_RC4_128_SHA`。
   - **输出:** `simulateServerHandshakeWithClientHello` 函数返回包含 "没有客户端和服务端都支持的密码套件" 的错误。

**3. 测试 FIPS 模式下支持的椭圆曲线：**

   - `TestFIPSServerCurves` 函数测试了服务器在 FIPS 模式下是否只接受 FIPS 批准的椭圆曲线。
   - 它遍历默认的椭圆曲线偏好，并测试当客户端只提供一个椭圆曲线时，服务器在 FIPS 模式下的反应。
   - 如果客户端提供的椭圆曲线不是 FIPS 批准的，服务器在 FIPS 模式下应该拒绝连接。

**4. 测试 FIPS 模式下的签名和哈希算法：**

   - `TestFIPSServerSignatureAndHash` 函数测试了服务器在 FIPS 模式下对签名和哈希算法的处理。
   - 它模拟客户端发送包含特定签名算法的 ClientHello 消息，并验证在 FIPS 模式下服务器是否只接受 FIPS 批准的签名算法。

**5. 测试 FIPS 模式下客户端的 ClientHello 消息：**

   - `TestFIPSClientHello` 和 `testFIPSClientHello` 函数验证了在 FIPS 模式下，客户端发送的 ClientHello 消息是否只包含 FIPS 批准的协议版本、密码套件、椭圆曲线和签名算法。
   - 即使客户端配置了非 FIPS 的选项，在 FIPS 模式下，客户端也应该强制使用 FIPS 兼容的设置。

**6. 测试 FIPS 模式下的证书算法：**

   - `TestFIPSCertAlgs` 函数是一个更全面的测试，用于验证在 FIPS 模式下证书链的验证是否正确。
   - 它创建了不同类型的证书（RSA 和 ECDSA，不同密钥长度），并测试了在 FIPS 模式下，使用 FIPS 批准的算法签名的证书是否被接受，而使用非 FIPS 批准的算法签名的证书是否被拒绝。

**代码推理：**

这段代码的核心是通过模拟 TLS 握手过程，并在启用和禁用 FIPS 模式下进行测试，来验证 `crypto/tls` 包的 FIPS 合规性。它通过以下方式进行推理：

- **基于配置的测试：**  它设置客户端和服务器的配置 (例如，支持的协议版本、密码套件、椭圆曲线)，然后观察在不同 FIPS 模式下握手的结果（成功或失败，以及失败的原因）。
- **基于消息的测试：** 它构造特定的 ClientHello 消息，包含特定的协议版本、密码套件等，然后观察服务器在不同 FIPS 模式下的反应。
- **基于证书的测试：** 它创建不同类型的证书，并测试在 FIPS 模式下证书链的验证是否符合预期。

**命令行参数的具体处理：**

这段代码本身是测试代码，通常不会直接处理命令行参数。但是，`runWithFIPSEnabled` 和 `runWithFIPSDisabled` 这两个函数（虽然代码中没有给出具体实现）很可能依赖于某种机制来控制 FIPS 模式的启用和禁用。这可能涉及到：

- **构建标签 (Build Tags):** Go 允许使用构建标签来条件编译代码。可能会有一个类似于 `fips` 的构建标签，当编译时加上这个标签，就会启用 FIPS 相关的逻辑。测试代码可能会在不同的构建环境下运行，以模拟 FIPS 模式。
- **环境变量:**  可能会设置一个环境变量（例如 `GOFIPS=1`）来指示启用 FIPS 模式。`runWithFIPSEnabled` 函数可能会读取这个环境变量。
- **全局变量或函数:**  可能会有一个全局变量或函数来控制 FIPS 模式的状态。

由于代码中没有给出 `runWithFIPSEnabled` 和 `runWithFIPSDisabled` 的具体实现，这里只能进行推测。在实际的 `crypto/tls` 包中，FIPS 模式的启用和禁用机制可能更加复杂。

**使用者易犯错的点：**

虽然这段代码是测试代码，但可以推断出使用者在使用 `crypto/tls` 包时可能犯的错误：

1. **错误地认为启用 FIPS 模式会自动处理一切：** 即使启用了 FIPS 模式，用户仍然需要确保他们配置的 TLS 连接使用 FIPS 批准的协议版本、密码套件和椭圆曲线。FIPS 模式主要是强制执行这些限制，而不是自动选择。
   - **例如：**  即使启用了 FIPS 模式，如果客户端仍然配置了允许 TLS 1.0 的 `MaxVersion`，并且服务器也支持 TLS 1.0（在非 FIPS 模式下），那么连接仍然可能建立在非 FIPS 批准的协议上。真正的 FIPS 模式实现会阻止这种情况。

2. **混淆 FIPS 模式的启用方式：**  用户可能会不清楚如何正确地启用 Go 语言的 FIPS 模式。这通常涉及到特定的构建步骤或环境变量设置，而不仅仅是在代码中设置某个配置项。

总而言之，这段测试代码是 `crypto/tls` 包中至关重要的一部分，它确保了该包在 FIPS 模式下的行为符合安全标准，并且能够正确地限制使用的加密算法和协议。

### 提示词
```
这是路径为go/src/crypto/tls/fips_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"internal/obscuretestdata"
	"internal/testenv"
	"math/big"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func allCipherSuitesIncludingTLS13() []uint16 {
	s := allCipherSuites()
	for _, suite := range cipherSuitesTLS13 {
		s = append(s, suite.id)
	}
	return s
}

func isTLS13CipherSuite(id uint16) bool {
	for _, suite := range cipherSuitesTLS13 {
		if id == suite.id {
			return true
		}
	}
	return false
}

func generateKeyShare(group CurveID) keyShare {
	key, err := generateECDHEKey(rand.Reader, group)
	if err != nil {
		panic(err)
	}
	return keyShare{group: group, data: key.PublicKey().Bytes()}
}

func TestFIPSServerProtocolVersion(t *testing.T) {
	test := func(t *testing.T, name string, v uint16, msg string) {
		t.Run(name, func(t *testing.T) {
			serverConfig := testConfig.Clone()
			serverConfig.MinVersion = VersionSSL30
			clientConfig := testConfig.Clone()
			clientConfig.MinVersion = v
			clientConfig.MaxVersion = v
			_, _, err := testHandshake(t, clientConfig, serverConfig)
			if msg == "" {
				if err != nil {
					t.Fatalf("got error: %v, expected success", err)
				}
			} else {
				if err == nil {
					t.Fatalf("got success, expected error")
				}
				if !strings.Contains(err.Error(), msg) {
					t.Fatalf("got error %v, expected %q", err, msg)
				}
			}
		})
	}

	runWithFIPSDisabled(t, func(t *testing.T) {
		test(t, "VersionTLS10", VersionTLS10, "")
		test(t, "VersionTLS11", VersionTLS11, "")
		test(t, "VersionTLS12", VersionTLS12, "")
		test(t, "VersionTLS13", VersionTLS13, "")
	})

	runWithFIPSEnabled(t, func(t *testing.T) {
		test(t, "VersionTLS10", VersionTLS10, "supported versions")
		test(t, "VersionTLS11", VersionTLS11, "supported versions")
		test(t, "VersionTLS12", VersionTLS12, "")
		test(t, "VersionTLS13", VersionTLS13, "")
	})
}

func isFIPSVersion(v uint16) bool {
	return v == VersionTLS12 || v == VersionTLS13
}

func isFIPSCipherSuite(id uint16) bool {
	switch id {
	case TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return true
	}
	return false
}

func isFIPSCurve(id CurveID) bool {
	switch id {
	case CurveP256, CurveP384:
		return true
	}
	return false
}

func isECDSA(id uint16) bool {
	for _, suite := range cipherSuites {
		if suite.id == id {
			return suite.flags&suiteECSign == suiteECSign
		}
	}
	return false // TLS 1.3 cipher suites are not tied to the signature algorithm.
}

func isFIPSSignatureScheme(alg SignatureScheme) bool {
	switch alg {
	default:
		return false
	case PKCS1WithSHA256,
		ECDSAWithP256AndSHA256,
		PKCS1WithSHA384,
		ECDSAWithP384AndSHA384,
		PKCS1WithSHA512,
		PSSWithSHA256,
		PSSWithSHA384,
		PSSWithSHA512:
		// ok
	}
	return true
}

func TestFIPSServerCipherSuites(t *testing.T) {
	serverConfig := testConfig.Clone()
	serverConfig.Certificates = make([]Certificate, 1)

	for _, id := range allCipherSuitesIncludingTLS13() {
		if isECDSA(id) {
			serverConfig.Certificates[0].Certificate = [][]byte{testECDSACertificate}
			serverConfig.Certificates[0].PrivateKey = testECDSAPrivateKey
		} else {
			serverConfig.Certificates[0].Certificate = [][]byte{testRSACertificate}
			serverConfig.Certificates[0].PrivateKey = testRSAPrivateKey
		}
		serverConfig.BuildNameToCertificate()
		t.Run(fmt.Sprintf("suite=%s", CipherSuiteName(id)), func(t *testing.T) {
			clientHello := &clientHelloMsg{
				vers:                         VersionTLS12,
				random:                       make([]byte, 32),
				cipherSuites:                 []uint16{id},
				compressionMethods:           []uint8{compressionNone},
				supportedCurves:              defaultCurvePreferences(),
				keyShares:                    []keyShare{generateKeyShare(CurveP256)},
				supportedPoints:              []uint8{pointFormatUncompressed},
				supportedVersions:            []uint16{VersionTLS12},
				supportedSignatureAlgorithms: defaultSupportedSignatureAlgorithmsFIPS,
			}
			if isTLS13CipherSuite(id) {
				clientHello.supportedVersions = []uint16{VersionTLS13}
			}

			runWithFIPSDisabled(t, func(t *testing.T) {
				testClientHello(t, serverConfig, clientHello)
			})

			runWithFIPSEnabled(t, func(t *testing.T) {
				msg := ""
				if !isFIPSCipherSuite(id) {
					msg = "no cipher suite supported by both client and server"
				}
				testClientHelloFailure(t, serverConfig, clientHello, msg)
			})
		})
	}
}

func TestFIPSServerCurves(t *testing.T) {
	serverConfig := testConfig.Clone()
	serverConfig.CurvePreferences = nil
	serverConfig.BuildNameToCertificate()

	for _, curveid := range defaultCurvePreferences() {
		t.Run(fmt.Sprintf("curve=%d", curveid), func(t *testing.T) {
			clientConfig := testConfig.Clone()
			clientConfig.CurvePreferences = []CurveID{curveid}

			runWithFIPSDisabled(t, func(t *testing.T) {
				if _, _, err := testHandshake(t, clientConfig, serverConfig); err != nil {
					t.Fatalf("got error: %v, expected success", err)
				}
			})

			// With fipstls forced, bad curves should be rejected.
			runWithFIPSEnabled(t, func(t *testing.T) {
				_, _, err := testHandshake(t, clientConfig, serverConfig)
				if err != nil && isFIPSCurve(curveid) {
					t.Fatalf("got error: %v, expected success", err)
				} else if err == nil && !isFIPSCurve(curveid) {
					t.Fatalf("got success, expected error")
				}
			})
		})
	}
}

func fipsHandshake(t *testing.T, clientConfig, serverConfig *Config) (clientErr, serverErr error) {
	c, s := localPipe(t)
	client := Client(c, clientConfig)
	server := Server(s, serverConfig)
	done := make(chan error, 1)
	go func() {
		done <- client.Handshake()
		c.Close()
	}()
	serverErr = server.Handshake()
	s.Close()
	clientErr = <-done
	return
}

func TestFIPSServerSignatureAndHash(t *testing.T) {
	defer func() {
		testingOnlyForceClientHelloSignatureAlgorithms = nil
	}()

	for _, sigHash := range defaultSupportedSignatureAlgorithms {
		t.Run(fmt.Sprintf("%v", sigHash), func(t *testing.T) {
			serverConfig := testConfig.Clone()
			serverConfig.Certificates = make([]Certificate, 1)

			testingOnlyForceClientHelloSignatureAlgorithms = []SignatureScheme{sigHash}

			sigType, _, _ := typeAndHashFromSignatureScheme(sigHash)
			switch sigType {
			case signaturePKCS1v15, signatureRSAPSS:
				serverConfig.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
				serverConfig.Certificates[0].Certificate = [][]byte{testRSAPSS2048Certificate}
				serverConfig.Certificates[0].PrivateKey = testRSAPSS2048PrivateKey
			case signatureEd25519:
				serverConfig.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
				serverConfig.Certificates[0].Certificate = [][]byte{testEd25519Certificate}
				serverConfig.Certificates[0].PrivateKey = testEd25519PrivateKey
			case signatureECDSA:
				serverConfig.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
				serverConfig.Certificates[0].Certificate = [][]byte{testECDSACertificate}
				serverConfig.Certificates[0].PrivateKey = testECDSAPrivateKey
			}
			serverConfig.BuildNameToCertificate()
			// PKCS#1 v1.5 signature algorithms can't be used standalone in TLS
			// 1.3, and the ECDSA ones bind to the curve used.
			serverConfig.MaxVersion = VersionTLS12

			runWithFIPSDisabled(t, func(t *testing.T) {
				clientErr, serverErr := fipsHandshake(t, testConfig, serverConfig)
				if clientErr != nil {
					t.Fatalf("expected handshake with %#x to succeed; client error: %v; server error: %v", sigHash, clientErr, serverErr)
				}
			})

			// With fipstls forced, bad curves should be rejected.
			runWithFIPSEnabled(t, func(t *testing.T) {
				clientErr, _ := fipsHandshake(t, testConfig, serverConfig)
				if isFIPSSignatureScheme(sigHash) {
					if clientErr != nil {
						t.Fatalf("expected handshake with %#x to succeed; err=%v", sigHash, clientErr)
					}
				} else {
					if clientErr == nil {
						t.Fatalf("expected handshake with %#x to fail, but it succeeded", sigHash)
					}
				}
			})
		})
	}
}

func TestFIPSClientHello(t *testing.T) {
	runWithFIPSEnabled(t, testFIPSClientHello)
}

func testFIPSClientHello(t *testing.T) {
	// Test that no matter what we put in the client config,
	// the client does not offer non-FIPS configurations.

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	clientConfig := testConfig.Clone()
	// All sorts of traps for the client to avoid.
	clientConfig.MinVersion = VersionSSL30
	clientConfig.MaxVersion = VersionTLS13
	clientConfig.CipherSuites = allCipherSuites()
	clientConfig.CurvePreferences = defaultCurvePreferences()

	go Client(c, clientConfig).Handshake()
	srv := Server(s, testConfig)
	msg, err := srv.readHandshake(nil)
	if err != nil {
		t.Fatal(err)
	}
	hello, ok := msg.(*clientHelloMsg)
	if !ok {
		t.Fatalf("unexpected message type %T", msg)
	}

	if !isFIPSVersion(hello.vers) {
		t.Errorf("client vers=%#x", hello.vers)
	}
	for _, v := range hello.supportedVersions {
		if !isFIPSVersion(v) {
			t.Errorf("client offered disallowed version %#x", v)
		}
	}
	for _, id := range hello.cipherSuites {
		if !isFIPSCipherSuite(id) {
			t.Errorf("client offered disallowed suite %#x", id)
		}
	}
	for _, id := range hello.supportedCurves {
		if !isFIPSCurve(id) {
			t.Errorf("client offered disallowed curve %d", id)
		}
	}
	for _, sigHash := range hello.supportedSignatureAlgorithms {
		if !isFIPSSignatureScheme(sigHash) {
			t.Errorf("client offered disallowed signature-and-hash %v", sigHash)
		}
	}
}

func TestFIPSCertAlgs(t *testing.T) {
	// arm and wasm time out generating keys. Nothing in this test is
	// architecture-specific, so just don't bother on those.
	if testenv.CPUIsSlow() {
		t.Skipf("skipping on %s/%s because key generation takes too long", runtime.GOOS, runtime.GOARCH)
	}

	// Set up some roots, intermediate CAs, and leaf certs with various algorithms.
	// X_Y is X signed by Y.
	R1 := fipsCert(t, "R1", fipsRSAKey(t, 2048), nil, fipsCertCA|fipsCertFIPSOK)
	R2 := fipsCert(t, "R2", fipsRSAKey(t, 1024), nil, fipsCertCA)
	R3 := fipsCert(t, "R3", fipsRSAKey(t, 4096), nil, fipsCertCA|fipsCertFIPSOK)

	M1_R1 := fipsCert(t, "M1_R1", fipsECDSAKey(t, elliptic.P256()), R1, fipsCertCA|fipsCertFIPSOK)
	M2_R1 := fipsCert(t, "M2_R1", fipsECDSAKey(t, elliptic.P224()), R1, fipsCertCA)

	I_R1 := fipsCert(t, "I_R1", fipsRSAKey(t, 3072), R1, fipsCertCA|fipsCertFIPSOK)
	I_R2 := fipsCert(t, "I_R2", I_R1.key, R2, fipsCertCA|fipsCertFIPSOK)
	I_M1 := fipsCert(t, "I_M1", I_R1.key, M1_R1, fipsCertCA|fipsCertFIPSOK)
	I_M2 := fipsCert(t, "I_M2", I_R1.key, M2_R1, fipsCertCA|fipsCertFIPSOK)

	I_R3 := fipsCert(t, "I_R3", fipsRSAKey(t, 3072), R3, fipsCertCA|fipsCertFIPSOK)
	fipsCert(t, "I_R3", I_R3.key, R3, fipsCertCA|fipsCertFIPSOK)

	L1_I := fipsCert(t, "L1_I", fipsECDSAKey(t, elliptic.P384()), I_R1, fipsCertLeaf|fipsCertFIPSOK)
	L2_I := fipsCert(t, "L2_I", fipsRSAKey(t, 1024), I_R1, fipsCertLeaf)

	// client verifying server cert
	testServerCert := func(t *testing.T, desc string, pool *x509.CertPool, key interface{}, list [][]byte, ok bool) {
		clientConfig := testConfig.Clone()
		clientConfig.RootCAs = pool
		clientConfig.InsecureSkipVerify = false
		clientConfig.ServerName = "example.com"

		serverConfig := testConfig.Clone()
		serverConfig.Certificates = []Certificate{{Certificate: list, PrivateKey: key}}
		serverConfig.BuildNameToCertificate()

		clientErr, _ := fipsHandshake(t, clientConfig, serverConfig)

		if (clientErr == nil) == ok {
			if ok {
				t.Logf("%s: accept", desc)
			} else {
				t.Logf("%s: reject", desc)
			}
		} else {
			if ok {
				t.Errorf("%s: BAD reject (%v)", desc, clientErr)
			} else {
				t.Errorf("%s: BAD accept", desc)
			}
		}
	}

	// server verifying client cert
	testClientCert := func(t *testing.T, desc string, pool *x509.CertPool, key interface{}, list [][]byte, ok bool) {
		clientConfig := testConfig.Clone()
		clientConfig.ServerName = "example.com"
		clientConfig.Certificates = []Certificate{{Certificate: list, PrivateKey: key}}

		serverConfig := testConfig.Clone()
		serverConfig.ClientCAs = pool
		serverConfig.ClientAuth = RequireAndVerifyClientCert

		_, serverErr := fipsHandshake(t, clientConfig, serverConfig)

		if (serverErr == nil) == ok {
			if ok {
				t.Logf("%s: accept", desc)
			} else {
				t.Logf("%s: reject", desc)
			}
		} else {
			if ok {
				t.Errorf("%s: BAD reject (%v)", desc, serverErr)
			} else {
				t.Errorf("%s: BAD accept", desc)
			}
		}
	}

	// Run simple basic test with known answers before proceeding to
	// exhaustive test with computed answers.
	r1pool := x509.NewCertPool()
	r1pool.AddCert(R1.cert)

	runWithFIPSDisabled(t, func(t *testing.T) {
		testServerCert(t, "basic", r1pool, L2_I.key, [][]byte{L2_I.der, I_R1.der}, true)
		testClientCert(t, "basic (client cert)", r1pool, L2_I.key, [][]byte{L2_I.der, I_R1.der}, true)
	})

	runWithFIPSEnabled(t, func(t *testing.T) {
		testServerCert(t, "basic (fips)", r1pool, L2_I.key, [][]byte{L2_I.der, I_R1.der}, false)
		testClientCert(t, "basic (fips, client cert)", r1pool, L2_I.key, [][]byte{L2_I.der, I_R1.der}, false)
	})

	if t.Failed() {
		t.Fatal("basic test failed, skipping exhaustive test")
	}

	if testing.Short() {
		t.Logf("basic test passed; skipping exhaustive test in -short mode")
		return
	}

	for l := 1; l <= 2; l++ {
		leaf := L1_I
		if l == 2 {
			leaf = L2_I
		}
		for i := 0; i < 64; i++ {
			reachable := map[string]bool{leaf.parentOrg: true}
			reachableFIPS := map[string]bool{leaf.parentOrg: leaf.fipsOK}
			list := [][]byte{leaf.der}
			listName := leaf.name
			addList := func(cond int, c *fipsCertificate) {
				if cond != 0 {
					list = append(list, c.der)
					listName += "," + c.name
					if reachable[c.org] {
						reachable[c.parentOrg] = true
					}
					if reachableFIPS[c.org] && c.fipsOK {
						reachableFIPS[c.parentOrg] = true
					}
				}
			}
			addList(i&1, I_R1)
			addList(i&2, I_R2)
			addList(i&4, I_M1)
			addList(i&8, I_M2)
			addList(i&16, M1_R1)
			addList(i&32, M2_R1)

			for r := 1; r <= 3; r++ {
				pool := x509.NewCertPool()
				rootName := ","
				shouldVerify := false
				shouldVerifyFIPS := false
				addRoot := func(cond int, c *fipsCertificate) {
					if cond != 0 {
						rootName += "," + c.name
						pool.AddCert(c.cert)
						if reachable[c.org] {
							shouldVerify = true
						}
						if reachableFIPS[c.org] && c.fipsOK {
							shouldVerifyFIPS = true
						}
					}
				}
				addRoot(r&1, R1)
				addRoot(r&2, R2)
				rootName = rootName[1:] // strip leading comma

				runWithFIPSDisabled(t, func(t *testing.T) {
					testServerCert(t, listName+"->"+rootName[1:], pool, leaf.key, list, shouldVerify)
					testClientCert(t, listName+"->"+rootName[1:]+"(client cert)", pool, leaf.key, list, shouldVerify)
				})

				runWithFIPSEnabled(t, func(t *testing.T) {
					testServerCert(t, listName+"->"+rootName[1:]+" (fips)", pool, leaf.key, list, shouldVerifyFIPS)
					testClientCert(t, listName+"->"+rootName[1:]+" (fips, client cert)", pool, leaf.key, list, shouldVerifyFIPS)
				})
			}
		}
	}
}

const (
	fipsCertCA = iota
	fipsCertLeaf
	fipsCertFIPSOK = 0x80
)

func fipsRSAKey(t *testing.T, size int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fipsECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type fipsCertificate struct {
	name      string
	org       string
	parentOrg string
	der       []byte
	cert      *x509.Certificate
	key       interface{}
	fipsOK    bool
}

func fipsCert(t *testing.T, name string, key interface{}, parent *fipsCertificate, mode int) *fipsCertificate {
	org := name
	parentOrg := ""
	if i := strings.Index(org, "_"); i >= 0 {
		org = org[:i]
		parentOrg = name[i+1:]
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore: time.Unix(0, 0),
		NotAfter:  time.Unix(0, 0),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if mode&^fipsCertFIPSOK == fipsCertLeaf {
		tmpl.DNSNames = []string{"example.com"}
	} else {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}

	var pcert *x509.Certificate
	var pkey interface{}
	if parent != nil {
		pcert = parent.cert
		pkey = parent.key
	} else {
		pcert = tmpl
		pkey = key
	}

	var pub interface{}
	var desc string
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
		desc = fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
		desc = "ECDSA-" + k.Curve.Params().Name
	default:
		t.Fatalf("invalid key %T", key)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, pcert, pub, pkey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	fipsOK := mode&fipsCertFIPSOK != 0
	runWithFIPSEnabled(t, func(t *testing.T) {
		if fipsAllowCert(cert) != fipsOK {
			t.Errorf("fipsAllowCert(cert with %s key) = %v, want %v", desc, !fipsOK, fipsOK)
		}
	})

	return &fipsCertificate{name, org, parentOrg, der, cert, key, fipsOK}
}

// A self-signed test certificate with an RSA key of size 2048, for testing
// RSA-PSS with SHA512. SAN of example.golang.
var (
	testRSAPSS2048Certificate []byte
	testRSAPSS2048PrivateKey  *rsa.PrivateKey
)

func init() {
	block, _ := pem.Decode(obscuretestdata.Rot13([]byte(`
-----ORTVA PREGVSVPNGR-----
ZVVP/mPPNrrtNjVONtVENYUUK/xu4+4mZH9QnemORpDjQDLWXbMVuipANDRYODNj
RwRDZN4TN1HRPuZUDJAgMFOQomNrSj0kZGNkZQRkAGN0ZQInSj0lZQRlZwxkAGN0
ZQInZOVkRQNBOtAIONbGO0SwoJHtD28jttRvZN0TPFdTFVo3QDRONDHNN4VOQjNj
ttRXNbVONDPs8sx0A6vrPOK4VBIVsXvgg4xTpBDYrvzPsfwddUplfZVITRgSFZ6R
4Nl141s/7VdqJ0HgVdAo4CKuEBVQ7lQkE284kY6KoPhi/g5uC3HpruLp3uzYvlIq
ZxMDvMJgsHHWs/1dBgZ+buAt59YEJc4q+6vK0yn1WY3RjPVpxxAwW9uDoS7Co2PF
+RF9Lb55XNnc8XBoycpE8ZOFA38odajwsDqPKiBRBwnz2UHkXmRSK5ZN+sN0zr4P
vbPpPEYJXy+TbA9S8sNOsbM+G+2rny4QYhB95eKE8FeBVIOu3KSBe/EIuwgKpAIS
MXpiQg6q68I6wNXNLXz5ayw9TCcq4i+eNtZONNTwHQOBZN4TN1HqQjRO/jDRNjVS
bQNGOtAIUFHRQQNXOtteOtRSODpQNGNZOtAIUEZONs8RNwNNZOxTN1HqRDDFZOPP
QzI4LJ1joTHhM29fLJ5aZN0TPFdTFVo3QDROPjHNN4VONDPBbLfIpSPOuobdr3JU
qP6I7KKKRPzawu01e8u80li0AE379aFQ3pj2Z+UXinKlfJdey5uwTIXj0igjQ81e
I4WmQh7VsVbt5z8+DAP+7YdQMfm88iQXBefblFIBzHPtzPXSKrj+YN+rB/vDRWGe
7rafqqBrKWRc27Rq5iJ+xzJJ3Dztyp2Tjl8jSeZQVdaeaBmON4bPaQRtgKWg0mbt
aEjosRZNJv1nDEl5qG9XN3FC9zb5FrGSFmTTUvR4f4tUHr7wifNSS2dtgQ6+jU6f
m9o6fukaP7t5VyOXuV7FIO/Hdg2lqW+xU1LowZpVd6ANZ5rAZXtMhWe3+mjfFtju
TAnR
-----RAQ PREGVSVPNGR-----`)))
	testRSAPSS2048Certificate = block.Bytes

	block, _ = pem.Decode(obscuretestdata.Rot13([]byte(`
-----ORTVA EFN CEVINGR XRL-----
ZVVRcNVONNXPNDRNa/U5AQrbattI+PQyFUlbeorWOaQxP3bcta7V6du3ZeQPSEuY
EHwBuBNZgrAK/+lXaIgSYFXwJ+Q14HGvN+8t8HqiBZF+y2jee/7rLG91UUbJUA4M
v4fyKGWTHVzIeK1SPK/9nweGCdVGLBsF0IdrUshby9WJgFF9kZNvUWWQLlsLHTkr
m29txiuRiJXBrFtTdsPwz5nKRsQNHwq/T6c8V30UDy7muQb2cgu1ZFfkOI+GNCaj
AWahNbdNaNxF1vcsudQsEsUjNK6Tsx/gazcrNl7wirn10sRdmvSDLq1kGd/0ILL7
I3QIEJFaYj7rariSrbjPtTPchM5L/Ew6KrY/djVQNDNONbVONDPAcZMvsq/it42u
UqPiYhMnLF0E7FhaSycbKRfygTqYSfac0VsbWM/htSDOFNVVsYjZhzH6bKN1m7Hi
98nVLI61QrCeGPQIQSOfUoAzC8WNb8JgohfRojq5mlbO7YLT2+pyxWxyJR73XdHd
ezV+HWrlFpy2Tva7MGkOKm1JCOx9IjpajxrnKctNFVOJ23suRPZ9taLRRjnOrm5G
6Zr8q1gUgLDi7ifXr7eb9j9/UXeEKrwdLXX1YkxusSevlI+z8YMWMa2aKBn6T3tS
Ao8Dx1Hx5CHORAOzlZSWuG4Z/hhFd4LgZeeB2tv8D+sCuhTmp5FfuLXEOc0J4C5e
zgIPgRSENbTONZRAOVSYeI2+UfTw0kLSnfXbi/DCr6UFGE1Uu2VMBAc+bX4bfmJR
wOG4IpaVGzcy6gP1Jl4TpekwAtXVSMNw+1k1YHHYqbeKxhT8le0gNuT9mAlsJfFl
CeFbiP0HIome8Wkkyn+xDIkRDDdJDkCyRIhY8xKnVQN6Ylg1Uchn2YiCNbTONADM
p6Yd2G7+OkYkAqv2z8xMmrw5xtmOc/KqIfoSJEyroVK2XeSUfeUmG9CHx3QR1iMX
Z6cmGg94aDuJFxQtPnj1FbuRyW3USVSjphfS1FWNp3cDrcq8ht6VLqycQZYgOw/C
/5C6OIHgtb05R4+V/G3vLngztyDkGgyM0ExFI2yyNbTONYBKxXSK7nuCis0JxfQu
hGshSBGCbbjtDT0RctJ0jEqPkrt/WYvp3yFQ0tfggDI2JfErpelJpknryEt10EzB
38OobtzunS4kitfFihwBsvMGR8bX1G43Z+6AXfVyZY3LVYocH/9nWkCJl0f2QdQe
pDWuMeyx+cmwON7Oas/HEqjkNbTNXE/PAj14Q+zeY3LYoovPKvlqdkIjki5cqMqm
8guv3GApfJP4vTHEqpIdosHvaICqWvKr/Xnp3JTPrEWnSItoXNBkYgv1EO5ZxVut
Q8rlhcOdx4J1Y1txekdfqw4GSykxjZljwy2R2F4LlD8COg6I04QbIEMfVXmdm+CS
HvbaCd0PtLOPLKidvbWuCrjxBd/L5jeQOrMJ1SDX5DQ9J5Z8/5mkq4eqiWgwuoWc
bBegiZqey6hcl9Um4OWQ3SKjISvCSR7wdrAdv0S21ivYkOCZZQ3HBQS6YY5RlYvE
9I4kIZF8XKkit7ekfhdmZCfpIvnJHY6JAIOufQ2+92qUkFKmm5RWXD==
-----RAQ EFN CEVINGR XRL-----`)))
	var err error
	testRSAPSS2048PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
}
```