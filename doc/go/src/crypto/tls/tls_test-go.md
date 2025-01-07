Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Goal:**

The request asks for an analysis of a Go file (`tls_test.go`) focusing on its functionality and potential connections to broader Go TLS features. The "part 1 of 3" indicates a larger context, but we should focus solely on the provided snippet for now.

**2. High-Level Overview of the Code:**

A quick scan reveals:

* **Package Declaration:** `package tls` - This immediately tells us it's part of the Go standard library's `crypto/tls` package, specifically for testing.
* **Imports:** A good number of standard library packages are imported, particularly those related to cryptography (`crypto`, `crypto/x509`), networking (`net`), and testing (`testing`). This reinforces the idea that it's a testing file.
* **Variable Declarations:** Several string variables are defined, appearing to hold PEM-encoded certificates and keys for both RSA and ECDSA. The naming (`rsaCertPEM`, `rsaKeyPEM`, `ecdsaCertPEM`, `ecdsaKeyPEM`) makes their purpose clear. The `testingKey` function suggests these might be specially crafted for testing scenarios.
* **`keyPairTests` Slice:** This slice groups the certificate and key PEM strings together, likely for iterating through different key pair types in tests.
* **Test Functions:** Functions starting with `Test...` are the core of a Go testing file. We see tests for:
    * `TestX509KeyPair`:  Loading key pairs.
    * `TestX509KeyPairErrors`: Handling errors during key pair loading.
    * `TestX509MixedKeyPair`:  Testing the failure cases of mismatched key pairs.
    * `TestDialTimeout`: Testing TLS connection timeouts.
    * `TestDeadlineOnWrite`: Testing deadlines on write operations.
    * `TestDialer`: Testing the `Dialer` functionality with context cancellation.
    * `TestConnReadNonzeroAndEOF`: Testing specific `Read` behavior at the end of a connection.
    * `TestTLSUniqueMatches`: Testing the uniqueness of TLS channel bindings.
    * `TestVerifyHostname`: Testing hostname verification.
    * `TestConnCloseBreakingWrite`: Testing connection closure during writes.
    * `TestConnCloseWrite`: Testing the `CloseWrite` functionality.
    * `TestWarningAlertFlood`: Testing how the library handles excessive warning alerts.
    * `TestCloneFuncFields` and `TestCloneNonFuncFields`:  Testing the `Clone` method of the `Config` struct.
    * `TestCloneNilConfig`: Testing `Clone` with a nil config.
    * `BenchmarkThroughput` and `BenchmarkLatency`: Performance benchmarks for TLS.
    * `TestConnectionStateMarshal`: Testing JSON marshaling of `ConnectionState`.
    * `TestConnectionState`: A more comprehensive test for `ConnectionState`.
* **Helper Functions:** Functions like `newLocalListener`, `runWithFIPSEnabled`, `runWithFIPSDisabled`, `skipFIPS`, `isTimeoutError`, `testingKey`, `readerFunc`, `changeImplConn`, `throughput`, `latency`. These assist the test functions.

**3. Identifying Core Functionality:**

Based on the test names and the content of the variables, the primary focus of this code snippet is testing various aspects of TLS functionality, specifically:

* **Loading and handling X.509 key pairs (certificates and private keys).**
* **Establishing TLS connections, including handling timeouts and deadlines.**
* **Specific connection behaviors like `CloseWrite` and handling of connection closure during write operations.**
* **The uniqueness of TLS channel bindings (`TLSUnique`).**
* **Hostname verification.**
* **Handling of TLS alerts.**
* **The `Config` struct and its `Clone` method.**
* **Performance characteristics (throughput and latency).**
* **The `ConnectionState` struct.**

**4. Connecting to Go TLS Features (and the prompt's request for "what Go language feature is being implemented"):**

The code *tests* the `crypto/tls` package. It doesn't *implement* a new core TLS feature itself. However, by observing *what* it tests, we can infer the features it's exercising:

* **`crypto/x509` package:**  The tests extensively use `x509.ParseCertificate`, `x509.X509KeyPair`, suggesting the file tests the integration of X.509 certificate handling within the `tls` package.
* **`net` package and `net/ Dial`, `net.Listen`:** The tests create network listeners and establish connections, indicating testing of the TLS client and server connection establishment process.
* **`crypto/tls.Config`:**  Many tests create and manipulate `tls.Config` instances, showcasing the testing of various configuration options for TLS connections.
* **`crypto/tls.Conn`:** The tests interact with `tls.Conn` methods like `Handshake`, `Write`, `Read`, `Close`, `CloseWrite`, `ConnectionState`, demonstrating tests for the core TLS connection object.
* **TLS Protocol Concepts:**  The tests implicitly cover TLS concepts like handshakes, session resumption, alerts, and secure communication.

**5. Considering the "Go code example" request:**

The `TestX509KeyPair` function itself provides a good example of how to use `tls.X509KeyPair`. We can extract and simplify it.

**6. Addressing other prompt points (assumptions, input/output, command-line arguments, common mistakes):**

* **Assumptions/Input/Output:** For `TestX509KeyPair`, the input is PEM-encoded data, and the output is either a `tls.Certificate` object or an error.
* **Command-line arguments:** This specific test file doesn't process command-line arguments directly. That's usually handled by the `testing` package itself (e.g., `-test.v` for verbose output).
* **Common mistakes:**  The `TestX509KeyPairErrors` function highlights a common mistake: switching the order of certificate and key when calling `X509KeyPair`.

**7. Structuring the Answer (Chinese, as requested):**

Organize the findings logically:

* Start with a concise summary of the file's purpose.
* Elaborate on the specific functionalities tested, grouping related tests.
* Provide the Go code example.
* Discuss assumptions, input/output for the example.
* Explain the lack of direct command-line argument handling in this file.
* Highlight the common mistake.
* Finally, summarize the overall functionality for the "part 1" requirement.

This thought process combines a top-down approach (understanding the overall goal and structure) with a bottom-up approach (examining individual functions and variables) to arrive at a comprehensive analysis of the code snippet. The iterative refinement of understanding and the specific focus on the prompt's requirements are key to producing a relevant and accurate answer.
这是一个Go语言实现的测试文件，路径为 `go/src/crypto/tls/tls_test.go`。它主要用于测试 `crypto/tls` 包中的 TLS (Transport Layer Security) 功能的各种方面。

**功能归纳：**

这个代码片段的功能是测试 Go 语言 `crypto/tls` 包中关于以下功能的实现：

1. **X.509 密钥对的加载和处理:**  测试 `tls.X509KeyPair` 函数，该函数用于从 PEM 编码的证书和私钥中加载密钥对。包括成功加载 RSA 和 ECDSA 密钥对，以及处理各种错误情况（例如参数顺序错误，提供非 PEM 数据等）。
2. **TLS 连接的建立和超时控制:**  测试使用 `tls.Dial` 和 `tls.DialWithDialer` 建立 TLS 连接时的超时机制。
3. **TLS 连接的读写截止时间:**  测试在 TLS 连接上设置读写操作的截止时间，以及超时后的错误处理。
4. **`tls.Dialer` 的上下文取消功能:** 测试使用 `tls.Dialer` 并结合 `context.Context` 在握手过程中取消连接的能力。
5. **TLS 连接读取行为的特殊情况:** 测试当接收到 `close_notify` 警报时，`Conn.Read` 方法是否能正确返回 `io.EOF`。
6. **TLS 通道绑定的唯一性:** 测试 TLS 连接的客户端和服务器端 `ConnectionState().TLSUnique` 值是否匹配，包括会话恢复的情况。
7. **TLS 主机名验证:** 测试 `Conn.VerifyHostname` 方法是否能正确验证服务器证书中的主机名。
8. **TLS 连接关闭时的行为:** 测试在进行写操作时关闭连接是否会正确返回错误，以及测试 `CloseWrite` 方法的功能。
9. **TLS 警告警报的洪水攻击防御:** 测试当收到过多的警告警报时，服务器是否会断开连接。
10. **`tls.Config` 结构的克隆功能:**  测试 `tls.Config` 结构的 `Clone` 方法是否能正确复制配置项，包括函数类型的字段。
11. **TLS 连接的吞吐量和延迟基准测试:**  提供 `BenchmarkThroughput` 和 `BenchmarkLatency` 函数用于衡量 TLS 连接的性能。
12. **`tls.ConnectionState` 结构的序列化:** 测试 `tls.ConnectionState` 结构是否可以被序列化为 JSON 格式。
13. **`tls.ConnectionState` 结构的状态信息:** 测试 `tls.ConnectionState` 结构中各种状态信息的正确性，例如协议版本、握手是否完成、使用的加密套件等。

**Go 语言功能实现示例 (基于 `tls.X509KeyPair`):**

这个代码片段主要测试的是 `crypto/tls` 包的功能，它本身不直接实现一个新的 Go 语言核心功能。但是，它大量使用了 Go 语言的标准库，特别是 `crypto` 和 `net` 包的功能。

我们可以举例说明 `tls.X509KeyPair` 是如何使用 `crypto/x509` 包来解析证书和私钥的：

```go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
)

func main() {
	certPEM := `-----BEGIN CERTIFICATE-----
MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDEwZUZXN0
IENBMB4XDTIzMTAyNjA3MjkxOVoXDTI0MTAyNzA3MjkxOVowETEPMA0GA1UEAxMG
VGVzdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDMjHwWu+r/89hR9tP9v
w1mD1/h0l5YpG24tV0/0vJt/1qL9pZ/64Z3aVqJk25wWwXQW6/jU6mNfP85Wn1C
PjcwDQYJKoZIhvcNAQELBQADggEBAGlY2+50d/bQ54+pL/71zK2fR/eB9V9lXmJp
... (剩余部分省略)
-----END CERTIFICATE-----
`

	keyPEM := `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAg4iY76F+hC3vD/t+I
... (剩余部分省略)
-----END PRIVATE KEY-----
`

	// 假设的输入：PEM 编码的证书和私钥字符串
	certificate, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		log.Fatalf("加载密钥对失败: %v", err)
	}

	// 假设的输出：一个 tls.Certificate 结构体，包含解析后的证书和私钥
	fmt.Printf("证书主题: %v\n", certificate.Leaf.Subject)
	fmt.Printf("私钥类型: %T\n", certificate.PrivateKey)
}
```

**代码推理 (关于 `TestConnReadNonzeroAndEOF`):**

这个测试用例旨在验证当 TLS 连接的缓冲区中既有应用数据，又有表示连接关闭的 `close_notify` 警报时，`Conn.Read` 方法的行为。

**假设的输入：**

1. 客户端和服务器成功建立 TLS 1.2 连接。
2. 服务器先向客户端发送一些应用数据（例如 "foobar"）。
3. 然后，服务器再次发送一些应用数据（例如 "abcdef"）。
4. 紧接着，服务器调用 `srv.Close()`，这会发送一个 `close_notify` 警报。

**假设的输出：**

1. 客户端第一次调用 `conn.Read` 时，会读取到 "foobar"，返回 `n = 6, err = nil`。
2. 客户端第二次调用 `conn.Read` 时，会先读取到 "abcdef"，返回 `n = 6, err = nil`。
3. 客户端第三次调用 `conn.Read` 时，由于缓冲区中还有 `close_notify` 警报，并且没有更多应用数据，会返回 `n = 0, err = io.EOF`。 **（测试的目标是验证即使缓冲区中还有数据，但在 `close_notify` 之后也应该返回 `io.EOF`）**。  但是，根据代码逻辑，它会先读取完 "abcdef"，然后在下一次 `Read` 时返回 `io.EOF`。

**命令行参数的具体处理：**

这个代码片段本身是一个测试文件，它不直接处理命令行参数。Go 语言的 `testing` 包会处理一些标准的测试相关的命令行参数，例如：

* `-test.run <regexp>`:  运行匹配正则表达式的测试用例。
* `-test.bench <regexp>`: 运行匹配正则表达式的性能测试用例。
* `-test.v`:  显示详细的测试输出。
* `-test.timeout <duration>`: 设置测试用例的超时时间。

这些参数在使用 `go test` 命令运行测试时可以传递，例如：

```bash
go test -test.v ./crypto/tls
go test -test.run TestX509KeyPair ./crypto/tls
go test -test.bench BenchmarkThroughput ./crypto/tls
```

**使用者易犯错的点 (基于 `X509KeyPair` 的错误处理测试):**

* **证书和私钥参数顺序错误:**  `TestX509KeyPairErrors` 测试了当 `X509KeyPair` 函数的第一个参数传入私钥，第二个参数传入证书时，是否会返回包含 "been switched" 的错误信息。这是一个常见的错误，因为使用者可能会混淆参数的顺序。

  **错误示例：**
  ```go
  _, err := tls.X509KeyPair([]byte(rsaKeyPEM), []byte(rsaCertPEM))
  if err == nil {
      // 应该会报错
  }
  ```

* **提供相同的内容作为证书和私钥:** `TestX509KeyPairErrors` 还测试了当两个参数都传入证书内容时，是否会返回包含 "certificate" 的错误信息。使用者可能会错误地将证书内容同时作为证书和私钥提供。

  **错误示例：**
  ```go
  _, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaCertPEM))
  if err == nil {
      // 应该会报错
  }
  ```

* **提供无效的 PEM 数据:**  `TestX509KeyPairErrors` 也测试了当提供非 PEM 格式的数据时，是否会返回包含 "NONSENSE" 的错误信息。

  **错误示例：**
  ```go
  nonsensePEM := `-----BEGIN NONSENSE-----
  Zm9vZm9vZm9v
  -----END NONSENSE-----
  `
  _, err := tls.X509KeyPair([]byte(nonsensePEM), []byte(nonsensePEM))
  if err == nil {
      // 应该会报错
  }
  ```

总而言之，这个代码片段是一个综合性的测试文件，用于验证 Go 语言 `crypto/tls` 包中多个关键功能的正确性和鲁棒性。它涵盖了密钥对加载、连接管理、错误处理、性能测试等多个方面。

Prompt: 
```
这是路径为go/src/crypto/tls/tls_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/internal/hpke"
	"crypto/rand"
	"crypto/tls/internal/fips140tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"internal/testenv"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

var rsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB0zCCAX2gAwIBAgIJAI/M7BYjwB+uMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTIwOTEyMjE1MjAyWhcNMTUwOTEyMjE1MjAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANLJ
hPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wok/4xIA+ui35/MmNa
rtNuC+BdZ1tMuVCPFZcCAwEAAaNQME4wHQYDVR0OBBYEFJvKs8RfJaXTH08W+SGv
zQyKn0H8MB8GA1UdIwQYMBaAFJvKs8RfJaXTH08W+SGvzQyKn0H8MAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADQQBJlffJHybjDGxRMqaRmDhX0+6v02TUKZsW
r5QuVbpQhH6u+0UgcW0jp9QwpxoPTLTWGXEWBBBurxFwiCBhkQ+V
-----END CERTIFICATE-----
`

var rsaKeyPEM = testingKey(`-----BEGIN RSA TESTING KEY-----
MIIBOwIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo
k/4xIA+ui35/MmNartNuC+BdZ1tMuVCPFZcCAwEAAQJAEJ2N+zsR0Xn8/Q6twa4G
6OB1M1WO+k+ztnX/1SvNeWu8D6GImtupLTYgjZcHufykj09jiHmjHx8u8ZZB/o1N
MQIhAPW+eyZo7ay3lMz1V01WVjNKK9QSn1MJlb06h/LuYv9FAiEA25WPedKgVyCW
SmUwbPw8fnTcpqDWE3yTO3vKcebqMSsCIBF3UmVue8YU3jybC3NxuXq3wNm34R8T
xVLHwDXh/6NJAiEAl2oHGGLz64BuAfjKrqwz7qMYr9HCLIe/YsoWq/olzScCIQDi
D2lWusoe2/nEqfDVVWGWlyJ7yOmqaVm/iNUN9B2N2g==
-----END RSA TESTING KEY-----
`)

// keyPEM is the same as rsaKeyPEM, but declares itself as just
// "PRIVATE KEY", not "RSA PRIVATE KEY".  https://golang.org/issue/4477
var keyPEM = testingKey(`-----BEGIN TESTING KEY-----
MIIBOwIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo
k/4xIA+ui35/MmNartNuC+BdZ1tMuVCPFZcCAwEAAQJAEJ2N+zsR0Xn8/Q6twa4G
6OB1M1WO+k+ztnX/1SvNeWu8D6GImtupLTYgjZcHufykj09jiHmjHx8u8ZZB/o1N
MQIhAPW+eyZo7ay3lMz1V01WVjNKK9QSn1MJlb06h/LuYv9FAiEA25WPedKgVyCW
SmUwbPw8fnTcpqDWE3yTO3vKcebqMSsCIBF3UmVue8YU3jybC3NxuXq3wNm34R8T
xVLHwDXh/6NJAiEAl2oHGGLz64BuAfjKrqwz7qMYr9HCLIe/YsoWq/olzScCIQDi
D2lWusoe2/nEqfDVVWGWlyJ7yOmqaVm/iNUN9B2N2g==
-----END TESTING KEY-----
`)

var ecdsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB/jCCAWICCQDscdUxw16XFDAJBgcqhkjOPQQBMEUxCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQwHhcNMTIxMTE0MTI0MDQ4WhcNMTUxMTE0MTI0MDQ4WjBFMQswCQYDVQQG
EwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lk
Z2l0cyBQdHkgTHRkMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBY9+my9OoeSUR
lDQdV/x8LsOuLilthhiS1Tz4aGDHIPwC1mlvnf7fg5lecYpMCrLLhauAc1UJXcgl
01xoLuzgtAEAgv2P/jgytzRSpUYvgLBt1UA0leLYBy6mQQbrNEuqT3INapKIcUv8
XxYP0xMEUksLPq6Ca+CRSqTtrd/23uTnapkwCQYHKoZIzj0EAQOBigAwgYYCQXJo
A7Sl2nLVf+4Iu/tAX/IF4MavARKC4PPHK3zfuGfPR3oCCcsAoz3kAzOeijvd0iXb
H5jBImIxPL4WxQNiBTexAkF8D1EtpYuWdlVQ80/h/f4pBcGiXPqX5h2PQSQY7hP1
+jwM1FGS4fREIOvlBYr/SzzQRtwrvrzGYxDEDbsC0ZGRnA==
-----END CERTIFICATE-----
`

var ecdsaKeyPEM = testingKey(`-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC TESTING KEY-----
MIHcAgEBBEIBrsoKp0oqcv6/JovJJDoDVSGWdirrkgCWxrprGlzB9o0X8fV675X0
NwuBenXFfeZvVcwluO7/Q9wkYoPd/t3jGImgBwYFK4EEACOhgYkDgYYABAFj36bL
06h5JRGUNB1X/Hwuw64uKW2GGJLVPPhoYMcg/ALWaW+d/t+DmV5xikwKssuFq4Bz
VQldyCXTXGgu7OC0AQCC/Y/+ODK3NFKlRi+AsG3VQDSV4tgHLqZBBus0S6pPcg1q
kohxS/xfFg/TEwRSSws+roJr4JFKpO2t3/be5OdqmQ==
-----END EC TESTING KEY-----
`)

var keyPairTests = []struct {
	algo string
	cert string
	key  string
}{
	{"ECDSA", ecdsaCertPEM, ecdsaKeyPEM},
	{"RSA", rsaCertPEM, rsaKeyPEM},
	{"RSA-untyped", rsaCertPEM, keyPEM}, // golang.org/issue/4477
}

func TestX509KeyPair(t *testing.T) {
	t.Parallel()
	var pem []byte
	for _, test := range keyPairTests {
		pem = []byte(test.cert + test.key)
		if _, err := X509KeyPair(pem, pem); err != nil {
			t.Errorf("Failed to load %s cert followed by %s key: %s", test.algo, test.algo, err)
		}
		pem = []byte(test.key + test.cert)
		if _, err := X509KeyPair(pem, pem); err != nil {
			t.Errorf("Failed to load %s key followed by %s cert: %s", test.algo, test.algo, err)
		}
	}
}

func TestX509KeyPairErrors(t *testing.T) {
	_, err := X509KeyPair([]byte(rsaKeyPEM), []byte(rsaCertPEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when arguments were switched")
	}
	if subStr := "been switched"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when switching arguments to X509KeyPair, but the error was %q", subStr, err)
	}

	_, err = X509KeyPair([]byte(rsaCertPEM), []byte(rsaCertPEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when both arguments were certificates")
	}
	if subStr := "certificate"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when both arguments to X509KeyPair were certificates, but the error was %q", subStr, err)
	}

	const nonsensePEM = `
-----BEGIN NONSENSE-----
Zm9vZm9vZm9v
-----END NONSENSE-----
`

	_, err = X509KeyPair([]byte(nonsensePEM), []byte(nonsensePEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when both arguments were nonsense")
	}
	if subStr := "NONSENSE"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when both arguments to X509KeyPair were nonsense, but the error was %q", subStr, err)
	}
}

func TestX509MixedKeyPair(t *testing.T) {
	if _, err := X509KeyPair([]byte(rsaCertPEM), []byte(ecdsaKeyPEM)); err == nil {
		t.Error("Load of RSA certificate succeeded with ECDSA private key")
	}
	if _, err := X509KeyPair([]byte(ecdsaCertPEM), []byte(rsaKeyPEM)); err == nil {
		t.Error("Load of ECDSA certificate succeeded with RSA private key")
	}
}

func newLocalListener(t testing.TB) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func runWithFIPSEnabled(t *testing.T, testFunc func(t *testing.T)) {
	originalFIPS := fips140tls.Required()
	defer func() {
		if originalFIPS {
			fips140tls.Force()
		} else {
			fips140tls.TestingOnlyAbandon()
		}
	}()

	fips140tls.Force()
	t.Run("fips140tls", testFunc)
}

func runWithFIPSDisabled(t *testing.T, testFunc func(t *testing.T)) {
	originalFIPS := fips140tls.Required()
	defer func() {
		if originalFIPS {
			fips140tls.Force()
		} else {
			fips140tls.TestingOnlyAbandon()
		}
	}()

	fips140tls.TestingOnlyAbandon()
	t.Run("no-fips140tls", testFunc)
}

func skipFIPS(t *testing.T) {
	if fips140tls.Required() {
		t.Skip("skipping test in FIPS mode")
	}
}

func TestDialTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	timeout := 100 * time.Microsecond
	for !t.Failed() {
		acceptc := make(chan net.Conn)
		listener := newLocalListener(t)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					close(acceptc)
					return
				}
				acceptc <- conn
			}
		}()

		addr := listener.Addr().String()
		dialer := &net.Dialer{
			Timeout: timeout,
		}
		if conn, err := DialWithDialer(dialer, "tcp", addr, nil); err == nil {
			conn.Close()
			t.Errorf("DialWithTimeout unexpectedly completed successfully")
		} else if !isTimeoutError(err) {
			t.Errorf("resulting error not a timeout: %v\nType %T: %#v", err, err, err)
		}

		listener.Close()

		// We're looking for a timeout during the handshake, so check that the
		// Listener actually accepted the connection to initiate it. (If the server
		// takes too long to accept the connection, we might cancel before the
		// underlying net.Conn is ever dialed — without ever attempting a
		// handshake.)
		lconn, ok := <-acceptc
		if ok {
			// The Listener accepted a connection, so assume that it was from our
			// Dial: we triggered the timeout at the point where we wanted it!
			t.Logf("Listener accepted a connection from %s", lconn.RemoteAddr())
			lconn.Close()
		}
		// Close any spurious extra connections from the listener. (This is
		// possible if there are, for example, stray Dial calls from other tests.)
		for extraConn := range acceptc {
			t.Logf("spurious extra connection from %s", extraConn.RemoteAddr())
			extraConn.Close()
		}
		if ok {
			break
		}

		t.Logf("with timeout %v, DialWithDialer returned before listener accepted any connections; retrying", timeout)
		timeout *= 2
	}
}

func TestDeadlineOnWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ln := newLocalListener(t)
	defer ln.Close()

	srvCh := make(chan *Conn, 1)

	go func() {
		sconn, err := ln.Accept()
		if err != nil {
			srvCh <- nil
			return
		}
		srv := Server(sconn, testConfig.Clone())
		if err := srv.Handshake(); err != nil {
			srvCh <- nil
			return
		}
		srvCh <- srv
	}()

	clientConfig := testConfig.Clone()
	clientConfig.MaxVersion = VersionTLS12
	conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	srv := <-srvCh
	if srv == nil {
		t.Error(err)
	}

	// Make sure the client/server is setup correctly and is able to do a typical Write/Read
	buf := make([]byte, 6)
	if _, err := srv.Write([]byte("foobar")); err != nil {
		t.Errorf("Write err: %v", err)
	}
	if n, err := conn.Read(buf); n != 6 || err != nil || string(buf) != "foobar" {
		t.Errorf("Read = %d, %v, data %q; want 6, nil, foobar", n, err, buf)
	}

	// Set a deadline which should cause Write to timeout
	if err = srv.SetDeadline(time.Now()); err != nil {
		t.Fatalf("SetDeadline(time.Now()) err: %v", err)
	}
	if _, err = srv.Write([]byte("should fail")); err == nil {
		t.Fatal("Write should have timed out")
	}

	// Clear deadline and make sure it still times out
	if err = srv.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline(time.Time{}) err: %v", err)
	}
	if _, err = srv.Write([]byte("This connection is permanently broken")); err == nil {
		t.Fatal("Write which previously failed should still time out")
	}

	// Verify the error
	if ne := err.(net.Error); ne.Temporary() != false {
		t.Error("Write timed out but incorrectly classified the error as Temporary")
	}
	if !isTimeoutError(err) {
		t.Error("Write timed out but did not classify the error as a Timeout")
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) { return f(b) }

// TestDialer tests that tls.Dialer.DialContext can abort in the middle of a handshake.
// (The other cases are all handled by the existing dial tests in this package, which
// all also flow through the same code shared code paths)
func TestDialer(t *testing.T) {
	ln := newLocalListener(t)
	defer ln.Close()

	unblockServer := make(chan struct{}) // close-only
	defer close(unblockServer)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-unblockServer
	}()

	ctx, cancel := context.WithCancel(context.Background())
	d := Dialer{Config: &Config{
		Rand: readerFunc(func(b []byte) (n int, err error) {
			// By the time crypto/tls wants randomness, that means it has a TCP
			// connection, so we're past the Dialer's dial and now blocked
			// in a handshake. Cancel our context and see if we get unstuck.
			// (Our TCP listener above never reads or writes, so the Handshake
			// would otherwise be stuck forever)
			cancel()
			return len(b), nil
		}),
		ServerName: "foo",
	}}
	_, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != context.Canceled {
		t.Errorf("err = %v; want context.Canceled", err)
	}
}

func isTimeoutError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// tests that Conn.Read returns (non-zero, io.EOF) instead of
// (non-zero, nil) when a Close (alertCloseNotify) is sitting right
// behind the application data in the buffer.
func TestConnReadNonzeroAndEOF(t *testing.T) {
	// This test is racy: it assumes that after a write to a
	// localhost TCP connection, the peer TCP connection can
	// immediately read it. Because it's racy, we skip this test
	// in short mode, and then retry it several times with an
	// increasing sleep in between our final write (via srv.Close
	// below) and the following read.
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	var err error
	for delay := time.Millisecond; delay <= 64*time.Millisecond; delay *= 2 {
		if err = testConnReadNonzeroAndEOF(t, delay); err == nil {
			return
		}
	}
	t.Error(err)
}

func testConnReadNonzeroAndEOF(t *testing.T, delay time.Duration) error {
	ln := newLocalListener(t)
	defer ln.Close()

	srvCh := make(chan *Conn, 1)
	var serr error
	go func() {
		sconn, err := ln.Accept()
		if err != nil {
			serr = err
			srvCh <- nil
			return
		}
		serverConfig := testConfig.Clone()
		srv := Server(sconn, serverConfig)
		if err := srv.Handshake(); err != nil {
			serr = fmt.Errorf("handshake: %v", err)
			srvCh <- nil
			return
		}
		srvCh <- srv
	}()

	clientConfig := testConfig.Clone()
	// In TLS 1.3, alerts are encrypted and disguised as application data, so
	// the opportunistic peek won't work.
	clientConfig.MaxVersion = VersionTLS12
	conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	srv := <-srvCh
	if srv == nil {
		return serr
	}

	buf := make([]byte, 6)

	srv.Write([]byte("foobar"))
	n, err := conn.Read(buf)
	if n != 6 || err != nil || string(buf) != "foobar" {
		return fmt.Errorf("Read = %d, %v, data %q; want 6, nil, foobar", n, err, buf)
	}

	srv.Write([]byte("abcdef"))
	srv.Close()
	time.Sleep(delay)
	n, err = conn.Read(buf)
	if n != 6 || string(buf) != "abcdef" {
		return fmt.Errorf("Read = %d, buf= %q; want 6, abcdef", n, buf)
	}
	if err != io.EOF {
		return fmt.Errorf("Second Read error = %v; want io.EOF", err)
	}
	return nil
}

func TestTLSUniqueMatches(t *testing.T) {
	ln := newLocalListener(t)
	defer ln.Close()

	serverTLSUniques := make(chan []byte)
	parentDone := make(chan struct{})
	childDone := make(chan struct{})
	defer close(parentDone)
	go func() {
		defer close(childDone)
		for i := 0; i < 2; i++ {
			sconn, err := ln.Accept()
			if err != nil {
				t.Error(err)
				return
			}
			serverConfig := testConfig.Clone()
			serverConfig.MaxVersion = VersionTLS12 // TLSUnique is not defined in TLS 1.3
			srv := Server(sconn, serverConfig)
			if err := srv.Handshake(); err != nil {
				t.Error(err)
				return
			}
			select {
			case <-parentDone:
				return
			case serverTLSUniques <- srv.ConnectionState().TLSUnique:
			}
		}
	}()

	clientConfig := testConfig.Clone()
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}

	var serverTLSUniquesValue []byte
	select {
	case <-childDone:
		return
	case serverTLSUniquesValue = <-serverTLSUniques:
	}

	if !bytes.Equal(conn.ConnectionState().TLSUnique, serverTLSUniquesValue) {
		t.Error("client and server channel bindings differ")
	}
	if serverTLSUniquesValue == nil || bytes.Equal(serverTLSUniquesValue, make([]byte, 12)) {
		t.Error("tls-unique is empty or zero")
	}
	conn.Close()

	conn, err = Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !conn.ConnectionState().DidResume {
		t.Error("second session did not use resumption")
	}

	select {
	case <-childDone:
		return
	case serverTLSUniquesValue = <-serverTLSUniques:
	}

	if !bytes.Equal(conn.ConnectionState().TLSUnique, serverTLSUniquesValue) {
		t.Error("client and server channel bindings differ when session resumption is used")
	}
	if serverTLSUniquesValue == nil || bytes.Equal(serverTLSUniquesValue, make([]byte, 12)) {
		t.Error("resumption tls-unique is empty or zero")
	}
}

func TestVerifyHostname(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	c, err := Dial("tcp", "www.google.com:https", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyHostname("www.google.com"); err != nil {
		t.Fatalf("verify www.google.com: %v", err)
	}
	if err := c.VerifyHostname("www.yahoo.com"); err == nil {
		t.Fatalf("verify www.yahoo.com succeeded")
	}

	c, err = Dial("tcp", "www.google.com:https", &Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyHostname("www.google.com"); err == nil {
		t.Fatalf("verify www.google.com succeeded with InsecureSkipVerify=true")
	}
}

func TestConnCloseBreakingWrite(t *testing.T) {
	ln := newLocalListener(t)
	defer ln.Close()

	srvCh := make(chan *Conn, 1)
	var serr error
	var sconn net.Conn
	go func() {
		var err error
		sconn, err = ln.Accept()
		if err != nil {
			serr = err
			srvCh <- nil
			return
		}
		serverConfig := testConfig.Clone()
		srv := Server(sconn, serverConfig)
		if err := srv.Handshake(); err != nil {
			serr = fmt.Errorf("handshake: %v", err)
			srvCh <- nil
			return
		}
		srvCh <- srv
	}()

	cconn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cconn.Close()

	conn := &changeImplConn{
		Conn: cconn,
	}

	clientConfig := testConfig.Clone()
	tconn := Client(conn, clientConfig)
	if err := tconn.Handshake(); err != nil {
		t.Fatal(err)
	}

	srv := <-srvCh
	if srv == nil {
		t.Fatal(serr)
	}
	defer sconn.Close()

	connClosed := make(chan struct{})
	conn.closeFunc = func() error {
		close(connClosed)
		return nil
	}

	inWrite := make(chan bool, 1)
	var errConnClosed = errors.New("conn closed for test")
	conn.writeFunc = func(p []byte) (n int, err error) {
		inWrite <- true
		<-connClosed
		return 0, errConnClosed
	}

	closeReturned := make(chan bool, 1)
	go func() {
		<-inWrite
		tconn.Close() // test that this doesn't block forever.
		closeReturned <- true
	}()

	_, err = tconn.Write([]byte("foo"))
	if err != errConnClosed {
		t.Errorf("Write error = %v; want errConnClosed", err)
	}

	<-closeReturned
	if err := tconn.Close(); err != net.ErrClosed {
		t.Errorf("Close error = %v; want net.ErrClosed", err)
	}
}

func TestConnCloseWrite(t *testing.T) {
	ln := newLocalListener(t)
	defer ln.Close()

	clientDoneChan := make(chan struct{})

	serverCloseWrite := func() error {
		sconn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %v", err)
		}
		defer sconn.Close()

		serverConfig := testConfig.Clone()
		srv := Server(sconn, serverConfig)
		if err := srv.Handshake(); err != nil {
			return fmt.Errorf("handshake: %v", err)
		}
		defer srv.Close()

		data, err := io.ReadAll(srv)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			return fmt.Errorf("Read data = %q; want nothing", data)
		}

		if err := srv.CloseWrite(); err != nil {
			return fmt.Errorf("server CloseWrite: %v", err)
		}

		// Wait for clientCloseWrite to finish, so we know we
		// tested the CloseWrite before we defer the
		// sconn.Close above, which would also cause the
		// client to unblock like CloseWrite.
		<-clientDoneChan
		return nil
	}

	clientCloseWrite := func() error {
		defer close(clientDoneChan)

		clientConfig := testConfig.Clone()
		conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
		if err != nil {
			return err
		}
		if err := conn.Handshake(); err != nil {
			return err
		}
		defer conn.Close()

		if err := conn.CloseWrite(); err != nil {
			return fmt.Errorf("client CloseWrite: %v", err)
		}

		if _, err := conn.Write([]byte{0}); err != errShutdown {
			return fmt.Errorf("CloseWrite error = %v; want errShutdown", err)
		}

		data, err := io.ReadAll(conn)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			return fmt.Errorf("Read data = %q; want nothing", data)
		}
		return nil
	}

	errChan := make(chan error, 2)

	go func() { errChan <- serverCloseWrite() }()
	go func() { errChan <- clientCloseWrite() }()

	for i := 0; i < 2; i++ {
		select {
		case err := <-errChan:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("deadlock")
		}
	}

	// Also test CloseWrite being called before the handshake is
	// finished:
	{
		ln2 := newLocalListener(t)
		defer ln2.Close()

		netConn, err := net.Dial("tcp", ln2.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer netConn.Close()
		conn := Client(netConn, testConfig.Clone())

		if err := conn.CloseWrite(); err != errEarlyCloseWrite {
			t.Errorf("CloseWrite error = %v; want errEarlyCloseWrite", err)
		}
	}
}

func TestWarningAlertFlood(t *testing.T) {
	ln := newLocalListener(t)
	defer ln.Close()

	server := func() error {
		sconn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %v", err)
		}
		defer sconn.Close()

		serverConfig := testConfig.Clone()
		srv := Server(sconn, serverConfig)
		if err := srv.Handshake(); err != nil {
			return fmt.Errorf("handshake: %v", err)
		}
		defer srv.Close()

		_, err = io.ReadAll(srv)
		if err == nil {
			return errors.New("unexpected lack of error from server")
		}
		const expected = "too many ignored"
		if str := err.Error(); !strings.Contains(str, expected) {
			return fmt.Errorf("expected error containing %q, but saw: %s", expected, str)
		}

		return nil
	}

	errChan := make(chan error, 1)
	go func() { errChan <- server() }()

	clientConfig := testConfig.Clone()
	clientConfig.MaxVersion = VersionTLS12 // there are no warning alerts in TLS 1.3
	conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < maxUselessRecords+1; i++ {
		conn.sendAlert(alertNoRenegotiation)
	}

	if err := <-errChan; err != nil {
		t.Fatal(err)
	}
}

func TestCloneFuncFields(t *testing.T) {
	const expectedCount = 9
	called := 0

	c1 := Config{
		Time: func() time.Time {
			called |= 1 << 0
			return time.Time{}
		},
		GetCertificate: func(*ClientHelloInfo) (*Certificate, error) {
			called |= 1 << 1
			return nil, nil
		},
		GetClientCertificate: func(*CertificateRequestInfo) (*Certificate, error) {
			called |= 1 << 2
			return nil, nil
		},
		GetConfigForClient: func(*ClientHelloInfo) (*Config, error) {
			called |= 1 << 3
			return nil, nil
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			called |= 1 << 4
			return nil
		},
		VerifyConnection: func(ConnectionState) error {
			called |= 1 << 5
			return nil
		},
		UnwrapSession: func(identity []byte, cs ConnectionState) (*SessionState, error) {
			called |= 1 << 6
			return nil, nil
		},
		WrapSession: func(cs ConnectionState, ss *SessionState) ([]byte, error) {
			called |= 1 << 7
			return nil, nil
		},
		EncryptedClientHelloRejectionVerify: func(ConnectionState) error {
			called |= 1 << 8
			return nil
		},
	}

	c2 := c1.Clone()

	c2.Time()
	c2.GetCertificate(nil)
	c2.GetClientCertificate(nil)
	c2.GetConfigForClient(nil)
	c2.VerifyPeerCertificate(nil, nil)
	c2.VerifyConnection(ConnectionState{})
	c2.UnwrapSession(nil, ConnectionState{})
	c2.WrapSession(ConnectionState{}, nil)
	c2.EncryptedClientHelloRejectionVerify(ConnectionState{})

	if called != (1<<expectedCount)-1 {
		t.Fatalf("expected %d calls but saw calls %b", expectedCount, called)
	}
}

func TestCloneNonFuncFields(t *testing.T) {
	var c1 Config
	v := reflect.ValueOf(&c1).Elem()

	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := v.Field(i)
		// testing/quick can't handle functions or interfaces and so
		// isn't used here.
		switch fn := typ.Field(i).Name; fn {
		case "Rand":
			f.Set(reflect.ValueOf(io.Reader(os.Stdin)))
		case "Time", "GetCertificate", "GetConfigForClient", "VerifyPeerCertificate", "VerifyConnection", "GetClientCertificate", "WrapSession", "UnwrapSession", "EncryptedClientHelloRejectionVerify":
			// DeepEqual can't compare functions. If you add a
			// function field to this list, you must also change
			// TestCloneFuncFields to ensure that the func field is
			// cloned.
		case "Certificates":
			f.Set(reflect.ValueOf([]Certificate{
				{Certificate: [][]byte{{'b'}}},
			}))
		case "NameToCertificate":
			f.Set(reflect.ValueOf(map[string]*Certificate{"a": nil}))
		case "RootCAs", "ClientCAs":
			f.Set(reflect.ValueOf(x509.NewCertPool()))
		case "ClientSessionCache":
			f.Set(reflect.ValueOf(NewLRUClientSessionCache(10)))
		case "KeyLogWriter":
			f.Set(reflect.ValueOf(io.Writer(os.Stdout)))
		case "NextProtos":
			f.Set(reflect.ValueOf([]string{"a", "b"}))
		case "ServerName":
			f.Set(reflect.ValueOf("b"))
		case "ClientAuth":
			f.Set(reflect.ValueOf(VerifyClientCertIfGiven))
		case "InsecureSkipVerify", "SessionTicketsDisabled", "DynamicRecordSizingDisabled", "PreferServerCipherSuites":
			f.Set(reflect.ValueOf(true))
		case "MinVersion", "MaxVersion":
			f.Set(reflect.ValueOf(uint16(VersionTLS12)))
		case "SessionTicketKey":
			f.Set(reflect.ValueOf([32]byte{}))
		case "CipherSuites":
			f.Set(reflect.ValueOf([]uint16{1, 2}))
		case "CurvePreferences":
			f.Set(reflect.ValueOf([]CurveID{CurveP256}))
		case "Renegotiation":
			f.Set(reflect.ValueOf(RenegotiateOnceAsClient))
		case "EncryptedClientHelloConfigList":
			f.Set(reflect.ValueOf([]byte{'x'}))
		case "EncryptedClientHelloKeys":
			f.Set(reflect.ValueOf([]EncryptedClientHelloKey{
				{Config: []byte{1}, PrivateKey: []byte{1}},
			}))
		case "mutex", "autoSessionTicketKeys", "sessionTicketKeys":
			continue // these are unexported fields that are handled separately
		default:
			t.Errorf("all fields must be accounted for, but saw unknown field %q", fn)
		}
	}
	// Set the unexported fields related to session ticket keys, which are copied with Clone().
	c1.autoSessionTicketKeys = []ticketKey{c1.ticketKeyFromBytes(c1.SessionTicketKey)}
	c1.sessionTicketKeys = []ticketKey{c1.ticketKeyFromBytes(c1.SessionTicketKey)}

	c2 := c1.Clone()
	if !reflect.DeepEqual(&c1, c2) {
		t.Errorf("clone failed to copy a field")
	}
}

func TestCloneNilConfig(t *testing.T) {
	var config *Config
	if cc := config.Clone(); cc != nil {
		t.Fatalf("Clone with nil should return nil, got: %+v", cc)
	}
}

// changeImplConn is a net.Conn which can change its Write and Close
// methods.
type changeImplConn struct {
	net.Conn
	writeFunc func([]byte) (int, error)
	closeFunc func() error
}

func (w *changeImplConn) Write(p []byte) (n int, err error) {
	if w.writeFunc != nil {
		return w.writeFunc(p)
	}
	return w.Conn.Write(p)
}

func (w *changeImplConn) Close() error {
	if w.closeFunc != nil {
		return w.closeFunc()
	}
	return w.Conn.Close()
}

func throughput(b *testing.B, version uint16, totalBytes int64, dynamicRecordSizingDisabled bool) {
	ln := newLocalListener(b)
	defer ln.Close()

	N := b.N

	// Less than 64KB because Windows appears to use a TCP rwin < 64KB.
	// See Issue #15899.
	const bufsize = 32 << 10

	go func() {
		buf := make([]byte, bufsize)
		for i := 0; i < N; i++ {
			sconn, err := ln.Accept()
			if err != nil {
				// panic rather than synchronize to avoid benchmark overhead
				// (cannot call b.Fatal in goroutine)
				panic(fmt.Errorf("accept: %v", err))
			}
			serverConfig := testConfig.Clone()
			serverConfig.CipherSuites = nil // the defaults may prefer faster ciphers
			serverConfig.DynamicRecordSizingDisabled = dynamicRecordSizingDisabled
			srv := Server(sconn, serverConfig)
			if err := srv.Handshake(); err != nil {
				panic(fmt.Errorf("handshake: %v", err))
			}
			if _, err := io.CopyBuffer(srv, srv, buf); err != nil {
				panic(fmt.Errorf("copy buffer: %v", err))
			}
		}
	}()

	b.SetBytes(totalBytes)
	clientConfig := testConfig.Clone()
	clientConfig.CipherSuites = nil // the defaults may prefer faster ciphers
	clientConfig.DynamicRecordSizingDisabled = dynamicRecordSizingDisabled
	clientConfig.MaxVersion = version

	buf := make([]byte, bufsize)
	chunks := int(math.Ceil(float64(totalBytes) / float64(len(buf))))
	for i := 0; i < N; i++ {
		conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
		if err != nil {
			b.Fatal(err)
		}
		for j := 0; j < chunks; j++ {
			_, err := conn.Write(buf)
			if err != nil {
				b.Fatal(err)
			}
			_, err = io.ReadFull(conn, buf)
			if err != nil {
				b.Fatal(err)
			}
		}
		conn.Close()
	}
}

func BenchmarkThroughput(b *testing.B) {
	for _, mode := range []string{"Max", "Dynamic"} {
		for size := 1; size <= 64; size <<= 1 {
			name := fmt.Sprintf("%sPacket/%dMB", mode, size)
			b.Run(name, func(b *testing.B) {
				b.Run("TLSv12", func(b *testing.B) {
					throughput(b, VersionTLS12, int64(size<<20), mode == "Max")
				})
				b.Run("TLSv13", func(b *testing.B) {
					throughput(b, VersionTLS13, int64(size<<20), mode == "Max")
				})
			})
		}
	}
}

type slowConn struct {
	net.Conn
	bps int
}

func (c *slowConn) Write(p []byte) (int, error) {
	if c.bps == 0 {
		panic("too slow")
	}
	t0 := time.Now()
	wrote := 0
	for wrote < len(p) {
		time.Sleep(100 * time.Microsecond)
		allowed := int(time.Since(t0).Seconds()*float64(c.bps)) / 8
		if allowed > len(p) {
			allowed = len(p)
		}
		if wrote < allowed {
			n, err := c.Conn.Write(p[wrote:allowed])
			wrote += n
			if err != nil {
				return wrote, err
			}
		}
	}
	return len(p), nil
}

func latency(b *testing.B, version uint16, bps int, dynamicRecordSizingDisabled bool) {
	ln := newLocalListener(b)
	defer ln.Close()

	N := b.N

	go func() {
		for i := 0; i < N; i++ {
			sconn, err := ln.Accept()
			if err != nil {
				// panic rather than synchronize to avoid benchmark overhead
				// (cannot call b.Fatal in goroutine)
				panic(fmt.Errorf("accept: %v", err))
			}
			serverConfig := testConfig.Clone()
			serverConfig.DynamicRecordSizingDisabled = dynamicRecordSizingDisabled
			srv := Server(&slowConn{sconn, bps}, serverConfig)
			if err := srv.Handshake(); err != nil {
				panic(fmt.Errorf("handshake: %v", err))
			}
			io.Copy(srv, srv)
		}
	}()

	clientConfig := testConfig.Clone()
	clientConfig.DynamicRecordSizingDisabled = dynamicRecordSizingDisabled
	clientConfig.MaxVersion = version

	buf := make([]byte, 16384)
	peek := make([]byte, 1)

	for i := 0; i < N; i++ {
		conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
		if err != nil {
			b.Fatal(err)
		}
		// make sure we're connected and previous connection has stopped
		if _, err := conn.Write(buf[:1]); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, peek); err != nil {
			b.Fatal(err)
		}
		if _, err := conn.Write(buf); err != nil {
			b.Fatal(err)
		}
		if _, err = io.ReadFull(conn, peek); err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}

func BenchmarkLatency(b *testing.B) {
	for _, mode := range []string{"Max", "Dynamic"} {
		for _, kbps := range []int{200, 500, 1000, 2000, 5000} {
			name := fmt.Sprintf("%sPacket/%dkbps", mode, kbps)
			b.Run(name, func(b *testing.B) {
				b.Run("TLSv12", func(b *testing.B) {
					latency(b, VersionTLS12, kbps*1000, mode == "Max")
				})
				b.Run("TLSv13", func(b *testing.B) {
					latency(b, VersionTLS13, kbps*1000, mode == "Max")
				})
			})
		}
	}
}

func TestConnectionStateMarshal(t *testing.T) {
	cs := &ConnectionState{}
	_, err := json.Marshal(cs)
	if err != nil {
		t.Errorf("json.Marshal failed on ConnectionState: %v", err)
	}
}

func TestConnectionState(t *testing.T) {
	skipFIPS(t) // Test certificates not FIPS compatible.

	issuer, err := x509.ParseCertificate(testRSACertificateIssuer)
	if err != nil {
		panic(err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(issuer)

	now := func() time.Time { return time.Unix(1476984729, 0) }

	const alpnProtocol = "golang"
	const serverName = "example.golang"
	var scts = [][]byte{[]byte("dummy sct 1"), []byte("dummy sct 2")}
	var ocsp = []byte("dummy ocsp")

	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		var name string
		switch v {
		case VersionTLS12:
			name = "TLSv12"
		case VersionTLS13:
			name = "TLSv13"
		}
		t.Run(name, func(t *testing.T) {
			config := &Config{
				Time:         now,
				Rand:         zeroSource{},
				Certificates: make([]Certificate, 1),
				MaxVersion:   v,
				RootCAs:      rootCAs,
				ClientCAs:    rootCAs,
				ClientAuth:   RequireAndVerifyClientCert,
				NextProtos:   []string{alpnProtocol},
				ServerName:   serverName,
			}
			config.Certificates[0].Certificate = [][]byte{testRSACertificate}
			config.Certificates[0].PrivateKey = testRSAPrivateKey
			config.Certificates[0].SignedCertificateTimestamps = scts
			config.Certificates[0].OCSPStaple = ocsp

			ss, cs, err := testHandshake(t, config, config)
			if err != nil {
				t.Fatalf("Handshake failed: %v", err)
			}

			if ss.Version != v || cs.Version != v {
				t.Errorf("Got versions %x (server) and %x (client), expected %x", ss.Version, cs.Version, v)
			}

			if !ss.HandshakeComplete || !cs.HandshakeComplete {
				t.Errorf("Got H
"""




```