Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding and Goal:**

The first step is to recognize the context: a Go test file within the `crypto/x509` package. The name `example_test.go` immediately suggests that it contains examples demonstrating the usage of the `x509` package. The goal is to understand what functionalities are showcased in this snippet.

**2. Examining Individual Functions:**

The next logical step is to analyze each function defined within the file. In this case, there are two functions: `ExampleCertificate_Verify` and `ExampleParsePKIXPublicKey`. The naming convention `Example` followed by the type or function being demonstrated is a standard Go practice for creating runnable examples in documentation.

**3. `ExampleCertificate_Verify` Function Analysis:**

* **PEM Decoding:** The presence of `pem.Decode` and the string literals starting with `-----BEGIN CERTIFICATE-----` strongly indicate that this function deals with X.509 certificates in PEM format.
* **Certificate Parsing:**  The calls to `x509.NewCertPool()` and `roots.AppendCertsFromPEM()` suggest the creation and population of a certificate pool, likely for trust validation. `x509.ParseCertificate()` confirms the parsing of a single certificate.
* **Verification:** The core of the function seems to be the `cert.Verify(opts)` call. The `x509.VerifyOptions` struct, including `DNSName` and `Roots`, points directly to certificate path validation, checking if the given certificate is valid for a specific domain using a provided set of trusted root certificates.
* **Hypothesizing Functionality:** Based on these observations, the primary function of `ExampleCertificate_Verify` is to demonstrate how to verify an X.509 certificate against a custom set of root certificates.

**4. `ExampleParsePKIXPublicKey` Function Analysis:**

* **PEM Decoding (Again):** Similar to the previous function, `pem.Decode` and the `-----BEGIN PUBLIC KEY-----` marker indicate handling of public keys in PEM format.
* **Public Key Parsing:** The function `x509.ParsePKIXPublicKey()` is the central point. This function name clearly suggests the parsing of a public key in PKIX (Public Key Infrastructure X.509) format.
* **Type Switching:** The `switch pub := pub.(type)` statement is crucial. It indicates that `ParsePKIXPublicKey` can return different types of public keys depending on the key's algorithm (RSA, DSA, ECDSA, Ed25519).
* **Hypothesizing Functionality:** The primary function of `ExampleParsePKIXPublicKey` is to demonstrate how to parse a public key from its PEM-encoded form and identify its underlying algorithm.

**5. Inferring Go Language Features:**

Based on the code, the following Go features are in play:

* **Packages:** `crypto/x509`, `encoding/pem`, `fmt`, and various sub-packages within `crypto` demonstrate the use of Go's package system for modularity.
* **Functions:** The definition and calling of functions (`ExampleCertificate_Verify`, `ExampleParsePKIXPublicKey`, etc.).
* **Data Types:**  Structs (`x509.Certificate`, `x509.CertPool`, `x509.VerifyOptions`), pointers, slices (`[]byte`), and interfaces (`crypto.PublicKey` implicitly).
* **Control Flow:** `if` statements for error handling, `switch` statement for type checking.
* **String Literals:**  Multi-line string literals for embedding PEM-encoded data.
* **Error Handling:** The use of `err != nil` to check for errors after function calls.
* **Panic:** The use of `panic` for unrecoverable errors in the examples.
* **Type Assertion:**  The `pub.(type)` syntax for checking the concrete type of an interface value.

**6. Code Examples and Reasoning:**

For each function, creating simplified code examples helps solidify understanding. The key is to isolate the core functionality and demonstrate it with minimal surrounding context. The thought process here is: "How would I use this function in a real scenario?" and then constructing a basic example. Inputs and outputs are essential to illustrate the function's effect.

**7. Command-Line Arguments and Error Handling (If Applicable):**

In this specific snippet, there's no explicit handling of command-line arguments. This observation is important to note in the analysis. However, focusing on potential errors the *user* might make is relevant, such as providing incorrect PEM data or not understanding the role of the root certificate pool.

**8. Structuring the Answer:**

Finally, organize the findings in a clear and logical manner. Use headings, bullet points, and code formatting to improve readability. The requested format was Chinese, so all explanations and code examples needed to be in Chinese.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Perhaps the `ExampleCertificate_Verify` function also shows how to *create* certificates.
* **Correction:**  Looking closely, the example only *loads* existing certificates from PEM and verifies them. Creation would involve different `x509` package functions.

* **Initial Thought:**  Maybe the `ExampleParsePKIXPublicKey` function demonstrates key generation.
* **Correction:**  The function is specifically about *parsing* an existing public key, not generating a new one.

By continually analyzing the code, referring to Go documentation (if needed), and testing assumptions, a comprehensive understanding of the code snippet can be achieved.
这段代码是 Go 语言 `crypto/x509` 包的一部分，它包含两个示例函数，用于演示 `x509` 包的两个主要功能：**证书验证**和**解析公钥**。

下面详细列举每个示例的功能，并用 Go 代码举例说明：

**1. `ExampleCertificate_Verify()` 函数**

* **功能:**  演示如何使用自定义的根证书列表来验证一个 X.509 证书的有效性。它模拟了客户端验证服务器证书的过程。

* **Go 代码示例:**

```go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

func main() {
	// 模拟根证书（通常由受信任的 CA 机构颁发）
	rootPEM := `
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIkludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`

	// 模拟待验证的证书
	certPEM := `
-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIIE31FZVaPXTUwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTMyNzQzWhcNMTQwNTI5MDAwMDAw
WjBpMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEYMBYGA1UEAwwPbWFp
bC5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfRrObuSW5T7q
5CnSEqefEmtH4CCv6+5EckuriNr1CjfVvqzwfAhopXkLrq45EQm8vkmf7W96XJhC
7ZM0dYi1/qOCAU8wggFLMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAa
BgNVHREEEzARgg9tYWlsLmdvb2dsZS5jb20wCwYDVR0PBAQDAgeAMGgGCCsGAQUF
BwEBBFwwWjArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJQUcy
LmNydDArBggrBgEFBQcwAYYfaHR0cDovL2NsaWVudHMxLmdvb2dsZS5jb20vb2Nz
cDAdBgNVHQ4EFgQUiJxtimAuTfwb+aUtBn5UYKreKvMwDAYDVR0TAQH/BAIwADAf
BgNVHSMEGDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzAXBgNVHSAEEDAOMAwGCisG
AQQB1nkCBQEwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29t
L0dJQUcyLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAH6RYHxHdcGpMpFE3oxDoFnP+
gtuBCHan2yE2GRbJ2Cw8Lw0MmuKqHlf9RSeYfd3BXeKkj1qO6TVKwCh+0HdZk283
TZZyzmEOyclm3UGFYe82P/iDFt+CeQ3NpmBg+GoaVCuWAARJN/KfglbLyyYygcQq
0SgeDh8dRKUiaW3HQSoYvTvdTuqzwK4CXsr3b5/dAOY8uMuG/IAR3FgwTbZ1dtoW
RvOTa8hYiU6A475WuZKyEHcwnGYe57u2I2KbMgcKjPniocj4QzgYsVAVKW3IwaOh
yE+vPxsiUkvQHdO2fojCkY8jg70jxM+gu59tPDNbw3Uh/2Ij310FgTHsnGQMyA==
-----END CERTIFICATE-----`

	// 创建根证书池并添加根证书
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		log.Fatal("解析根证书失败")
	}

	// 解析待验证的证书
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		log.Fatal("解析证书 PEM 失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("解析证书失败: %v", err)
	}

	// 设置验证选项，包括期望的 DNS 名称和根证书池
	opts := x509.VerifyOptions{
		DNSName: "mail.google.com",
		Roots:   roots,
	}

	// 执行证书验证
	if _, err := cert.Verify(opts); err != nil {
		log.Fatalf("证书验证失败: %v", err)
	}

	fmt.Println("证书验证成功!")
}
```

* **假设的输入与输出:**
    * **输入:**  `rootPEM` 包含根证书的 PEM 编码，`certPEM` 包含待验证证书的 PEM 编码。
    * **输出:** 如果证书验证成功，则输出 "证书验证成功!"。如果验证失败，则会 `panic` 并输出错误信息。

**2. `ExampleParsePKIXPublicKey()` 函数**

* **功能:** 演示如何解析一个 PEM 编码的 PKIX (Public Key Infrastructure X.509) 格式的公钥，并判断其类型 (RSA, DSA, ECDSA, Ed25519)。

* **Go 代码示例:**

```go
package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

func main() {
	// 模拟 PEM 编码的公钥
	pubPEM := `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----`

	// 解码 PEM 编码的公钥
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		log.Fatal("解析公钥 PEM 失败")
	}

	// 解析 PKIX 格式的公钥
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("解析 DER 编码的公钥失败: %v", err)
	}

	// 判断公钥类型
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("公钥类型: RSA", pub)
	case *dsa.PublicKey:
		fmt.Println("公钥类型: DSA", pub)
	case *ecdsa.PublicKey:
		fmt.Println("公钥类型: ECDSA", pub)
	case ed25519.PublicKey:
		fmt.Println("公钥类型: Ed25519", pub)
	default:
		log.Fatal("未知的公钥类型")
	}
}
```

* **假设的输入与输出:**
    * **输入:** `pubPEM` 包含公钥的 PEM 编码。
    * **输出:** 根据公钥的实际类型，输出相应的类型信息，例如 "公钥类型: RSA &{N:[...] E:65537]}"。

**涉及的 Go 语言功能实现:**

* **`crypto/x509` 包:**  用于 X.509 证书、密钥的解析和验证。
* **`encoding/pem` 包:** 用于处理 PEM (Privacy Enhanced Mail) 编码的数据，PEM 是一种常用的证书和密钥的编码格式。
* **`crypto/rsa`, `crypto/dsa`, `crypto/ecdsa`, `crypto/ed25519` 包:** 提供了各种公钥密码算法的实现。
* **类型断言 (Type Assertion):**  `switch pub := pub.(type)` 用于判断接口变量的实际类型。

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。它主要是作为示例代码存在，通常在测试或者作为库的一部分被调用。如果需要在命令行中使用证书验证或公钥解析的功能，你需要编写额外的代码来读取命令行参数，例如使用 `os.Args` 或者 `flag` 包。

**使用者易犯错的点:**

* **`ExampleCertificate_Verify()`:**
    * **忘记提供正确的根证书:** 如果提供的 `roots` 不包含用于签发 `certPEM` 中证书的根证书或中间证书，验证将会失败。
    * **DNSName 设置不正确:** `VerifyOptions` 中的 `DNSName` 应该与待验证证书的 Subject Alternative Name (SAN) 或 Common Name (CN) 匹配，否则验证会失败。
    * **PEM 格式错误:**  如果 `rootPEM` 或 `certPEM` 的 PEM 格式不正确（例如，缺少 BEGIN/END 标记，或者内容错误），解析会失败。

    **举例说明:** 假设 `certPEM` 是 `mail.example.com` 的证书，但 `opts.DNSName` 设置为 `mail.google.com`，则验证会失败。

* **`ExampleParsePKIXPublicKey()`:**
    * **提供非 PEM 格式的数据:**  `pem.Decode` 只能处理 PEM 编码的数据，如果提供的是 DER 编码或其他格式的数据，解析会失败。
    * **PEM 格式错误:**  与证书验证类似，公钥 PEM 数据的格式必须正确。

    **举例说明:**  如果 `pubPEM` 的内容是 DER 编码的公钥，而不是 PEM 编码，那么 `pem.Decode` 将返回 `nil`。

总而言之，这段代码片段展示了 Go 语言 `crypto/x509` 包中用于证书验证和公钥解析的核心功能。通过这两个示例，开发者可以学习如何在自己的程序中使用这些功能来保障通信安全和处理加密密钥。

Prompt: 
```
这是路径为go/src/crypto/x509/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509_test

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ExampleCertificate_Verify() {
	// Verifying with a custom list of root certificates.

	const rootPEM = `
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`

	const certPEM = `
-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIIE31FZVaPXTUwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTMyNzQzWhcNMTQwNTI5MDAwMDAw
WjBpMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEYMBYGA1UEAwwPbWFp
bC5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfRrObuSW5T7q
5CnSEqefEmtH4CCv6+5EckuriNr1CjfVvqzwfAhopXkLrq45EQm8vkmf7W96XJhC
7ZM0dYi1/qOCAU8wggFLMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAa
BgNVHREEEzARgg9tYWlsLmdvb2dsZS5jb20wCwYDVR0PBAQDAgeAMGgGCCsGAQUF
BwEBBFwwWjArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJQUcy
LmNydDArBggrBgEFBQcwAYYfaHR0cDovL2NsaWVudHMxLmdvb2dsZS5jb20vb2Nz
cDAdBgNVHQ4EFgQUiJxtimAuTfwb+aUtBn5UYKreKvMwDAYDVR0TAQH/BAIwADAf
BgNVHSMEGDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzAXBgNVHSAEEDAOMAwGCisG
AQQB1nkCBQEwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29t
L0dJQUcyLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAH6RYHxHdcGpMpFE3oxDoFnP+
gtuBCHan2yE2GRbJ2Cw8Lw0MmuKqHlf9RSeYfd3BXeKkj1qO6TVKwCh+0HdZk283
TZZyzmEOyclm3UGFYe82P/iDFt+CeQ3NpmBg+GoaVCuWAARJN/KfglbLyyYygcQq
0SgeDh8dRKUiaW3HQSoYvTvdTuqzwK4CXsr3b5/dAOY8uMuG/IAR3FgwTbZ1dtoW
RvOTa8hYiU6A475WuZKyEHcwnGYe57u2I2KbMgcKjPniocj4QzgYsVAVKW3IwaOh
yE+vPxsiUkvQHdO2fojCkY8jg70jxM+gu59tPDNbw3Uh/2Ij310FgTHsnGQMyA==
-----END CERTIFICATE-----`

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		DNSName: "mail.google.com",
		Roots:   roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
}

func ExampleParsePKIXPublicKey() {
	const pubPEM = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----`

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("pub is of type RSA:", pub)
	case *dsa.PublicKey:
		fmt.Println("pub is of type DSA:", pub)
	case *ecdsa.PublicKey:
		fmt.Println("pub is of type ECDSA:", pub)
	case ed25519.PublicKey:
		fmt.Println("pub is of type Ed25519:", pub)
	default:
		panic("unknown type of public key")
	}
}

"""



```