Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Goal:**

The primary goal is to analyze a Go test file (`example_test.go`) within the `crypto/tls` package and describe its functionalities, infer its purpose, provide illustrative Go code examples, explain command-line arguments (if applicable), and highlight potential pitfalls for users.

**2. Initial Code Scan and Structure Identification:**

The first step is to scan through the code and identify the major components. Key elements immediately stand out:

* **`package tls_test`:** This indicates it's a test file for the `crypto/tls` package. The `_test` suffix is standard Go convention.
* **`import` statements:** These reveal the dependencies: `crypto/tls`, `crypto/x509`, `log`, `net/http`, `net/http/httptest`, `os`, and `time`. This immediately tells us the code is dealing with TLS, X.509 certificates, HTTP, testing, operating system interactions, and time management.
* **`zeroSource` struct:** This looks like a custom `io.Reader` used for generating zero bytes. Its usage will likely be related to testing or reproducible examples.
* **`ExampleDial()` function:** The `Example` prefix suggests this is a documented example that will be shown in Go documentation. It demonstrates how to establish a TLS connection with a custom root certificate.
* **`ExampleConfig_keyLogWriter()` function:**  Another documented example, this one focuses on the `KeyLogWriter` functionality for debugging TLS connections by logging secrets.
* **`ExampleLoadX509KeyPair()` function:**  This demonstrates loading certificate and key files from disk.
* **`ExampleX509KeyPair()` function:** This shows how to create a `tls.Certificate` directly from PEM-encoded data.
* **`ExampleX509KeyPair_httpServer()` function:**  Combines certificate loading with setting up an HTTPS server.
* **`ExampleConfig_verifyConnection()` function:** This example illustrates how to customize the TLS connection verification process.

**3. Analyzing Individual Examples:**

For each `Example` function, the approach is similar:

* **Identify the Core TLS Feature:** What specific `tls` functionality is being demonstrated? (e.g., `tls.Dial`, `tls.Config.KeyLogWriter`, `tls.LoadX509KeyPair`, `tls.X509KeyPair`, `tls.Listen`, `tls.Config.VerifyConnection`).
* **Understand the Code Logic:**  Trace the execution flow. What are the key steps involved? What data is being used?
* **Infer the Purpose:** Why would someone use this particular feature? What problem does it solve?
* **Formulate an Explanation:**  Describe the functionality in clear, concise Chinese.
* **Construct an Illustrative Code Example:**  If the example is self-contained, it can often be used directly. If it's more conceptual, create a simplified example to showcase the core behavior.
* **Identify Potential Pitfalls:** Are there any common mistakes users might make when using this feature?  (e.g., security implications of `KeyLogWriter`, incorrect file paths, neglecting error handling).

**4. Specific Example Walkthrough (ExampleDial):**

* **Feature:** `tls.Dial` with a custom `RootCAs`.
* **Logic:**  Reads a PEM-encoded root certificate, creates a `x509.CertPool`, appends the certificate, and then uses this pool in the `tls.Config` when dialing.
* **Purpose:** To connect to a server whose certificate is signed by a CA not trusted by the system's default root certificates.
* **Explanation:** Explains how to establish a TLS connection using a specific trusted root certificate.
* **Illustrative Code:** The provided `ExampleDial` function itself is a good illustration.
* **Pitfalls:**  Incorrect PEM format, issues with file paths if reading from a file (not in this example, but a general concern with certificate handling).

**5. Specific Example Walkthrough (ExampleConfig_keyLogWriter):**

* **Feature:** `tls.Config.KeyLogWriter`.
* **Logic:** Creates a dummy HTTPS server, sets the `KeyLogWriter` in the client's `tls.Config` to `os.Stdout`, and makes a request.
* **Purpose:** To log the TLS secrets needed to decrypt the connection traffic for debugging purposes.
* **Explanation:** Describes how to use `KeyLogWriter` to output TLS secrets.
* **Illustrative Code:** The provided example is illustrative.
* **Pitfalls:** **Crucially, the security warning about the danger of using `KeyLogWriter` in production needs to be emphasized.**

**6. Identifying Common Themes and Overall Functionality:**

After analyzing each example, common themes emerge:

* **Customizing TLS Configuration:** The examples demonstrate various ways to configure TLS connections, including specifying root CAs, certificates, key log writers, and verification logic.
* **Certificate Handling:**  Loading certificates from files and creating them from PEM data are key operations.
* **Client and Server Roles:**  Some examples focus on client-side configuration (e.g., `Dial`), while others address server-side setup (e.g., `Listen`, `ListenAndServeTLS`).
* **Debugging:** The `KeyLogWriter` example explicitly addresses debugging TLS issues.

**7. Inferring the Overall Purpose of the File:**

Given that it's a `_test.go` file containing `Example` functions within the `crypto/tls` package, the overall purpose is clearly to:

* **Document Usage:** Provide clear and executable examples of how to use various `crypto/tls` functionalities.
* **Test Functionality:** While not explicitly shown in this snippet, `_test.go` files also contain unit tests to verify the correctness of the code. The examples themselves can serve as integration tests to some extent.

**8. Addressing Specific Requirements of the Prompt:**

* **Listing Functionalities:** This involves summarizing the purpose of each `Example` function.
* **Inferring Go Language Feature:** This requires identifying the core `crypto/tls` features being demonstrated.
* **Go Code Examples:** The `Example` functions themselves serve as examples.
* **Assumptions, Inputs, and Outputs:**  For code inference, think about the expected input (e.g., PEM data, server address) and the resulting output/behavior (e.g., a TLS connection, log output).
* **Command-Line Arguments:**  In this specific snippet, there are no direct command-line arguments being processed. This needs to be stated explicitly.
* **User Mistakes:** Identify common errors, particularly security-related ones.
* **Chinese Answers:**  Translate all explanations and descriptions into Chinese.

**Self-Correction/Refinement:**

During the process, it's important to review and refine the explanations. For example, initially, I might have simply listed the functions. However, the prompt asks for *functionalities*, which requires a higher level of understanding and explanation of *what* each function achieves. Similarly, clearly distinguishing between client-side and server-side configurations adds clarity. Emphasizing the security implications of `KeyLogWriter` is crucial and should be highlighted.
这段代码是 Go 语言标准库 `crypto/tls` 包的一部分，具体来说是其测试文件 `example_test.go` 中的一些示例代码片段。这些示例旨在演示如何使用 `crypto/tls` 包中的各种功能。

以下是代码中各个 `Example` 函数的功能：

1. **`ExampleDial()`**:
    *   **功能:** 演示如何使用自定义的根证书集 (Root CAs) 来建立 TLS 连接。
    *   **Go 语言功能实现:**  展示了 `tls.Dial` 函数的使用，并配置了 `tls.Config` 结构体中的 `RootCAs` 字段。
    *   **代码举例说明:**
        ```go
        package main

        import (
            "crypto/tls"
            "crypto/x509"
            "fmt"
            "log"
        )

        func main() {
            const rootPEM = `-----BEGIN CERTIFICATE-----
        MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G
        A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gRjIxEzARBgNVBAoTCkdsb2JhbFNp
        Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1
        MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBKMjETMBEG
        A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
        hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL
        v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8
        eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq
        tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd
        C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa
        zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB
        mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH
        V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n
        bG9iYWxzaWduLm5ldC9yb290LXJyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG
        3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs
        J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO
        291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS
        ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd
        AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7
        TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==
        -----END CERTIFICATE-----`

            roots := x509.NewCertPool()
            ok := roots.AppendCertsFromPEM([]byte(rootPEM))
            if !ok {
                log.Fatal("failed to parse root certificate")
            }

            conf := &tls.Config{
                RootCAs: roots,
            }
            conn, err := tls.Dial("tcp", "example.com:443", conf)
            if err != nil {
                log.Fatalf("failed to connect: %v", err)
            }
            defer conn.Close()
            fmt.Println("TLS connection established successfully!")
        }
        ```
        **假设输入:**  `example.com:443` 是一个需要使用特定根证书才能验证的 HTTPS 服务器地址。`rootPEM` 变量包含该服务器证书链中根证书的 PEM 编码。
        **输出:** 如果连接成功，将打印 "TLS connection established successfully!"，否则会打印错误信息。

2. **`ExampleConfig_keyLogWriter()`**:
    *   **功能:** 演示如何使用 `KeyLogWriter` 来记录 TLS 连接的密钥信息，用于调试（例如使用 Wireshark 解密 TLS 流量）。
    *   **Go 语言功能实现:** 展示了在 `tls.Config` 中设置 `KeyLogWriter` 字段，并将其指向一个 `io.Writer` (例如 `os.Stdout` 或一个文件)。
    *   **代码举例说明:**  代码片段本身就是一个很好的例子。它创建了一个临时的 HTTP 服务器，并在客户端的 `tls.Config` 中设置了 `KeyLogWriter`。
    *   **使用者易犯错的点:**  **非常重要：**  `KeyLogWriter` 输出的密钥信息可以用于解密 TLS 通信，因此**绝对不能在生产环境中使用**。这是一个仅用于调试的工具，如果密钥信息泄露，会严重威胁安全性。

3. **`ExampleLoadX509KeyPair()`**:
    *   **功能:** 演示如何从 PEM 编码的文件中加载 X.509 密钥对（证书和私钥）。
    *   **Go 语言功能实现:**  展示了 `tls.LoadX509KeyPair` 函数的使用。
    *   **代码举例说明:** 代码片段本身就是一个很好的例子。它假设存在 `testdata/example-cert.pem` 和 `testdata/example-key.pem` 两个文件。
    *   **假设输入:**  `testdata/example-cert.pem` 文件包含 PEM 编码的证书，`testdata/example-key.pem` 文件包含对应的 PEM 编码的私钥。
    *   **输出:**  如果加载成功，会创建一个 `tls.Config`，其中包含加载的证书。如果加载失败，会打印错误信息并退出。

4. **`ExampleX509KeyPair()`**:
    *   **功能:** 演示如何直接使用 PEM 编码的字符串来创建 X.509 密钥对。
    *   **Go 语言功能实现:** 展示了 `tls.X509KeyPair` 函数的使用。
    *   **代码举例说明:** 代码片段本身就是一个很好的例子。它直接定义了 `certPem` 和 `keyPem` 两个包含 PEM 编码的字符串变量。
    *   **假设输入:** `certPem` 包含 PEM 编码的证书内容，`keyPem` 包含对应的 PEM 编码的私钥内容。
    *   **输出:**  如果创建成功，会创建一个 `tls.Config`，其中包含创建的证书。如果创建失败，会打印错误信息并退出。

5. **`ExampleX509KeyPair_httpServer()`**:
    *   **功能:** 演示如何使用 `tls.X509KeyPair` 加载的密钥对来配置一个 HTTPS 服务器。
    *   **Go 语言功能实现:**  结合了 `tls.X509KeyPair` 和 `net/http` 包中的 `http.Server` 以及 `ListenAndServeTLS` 函数。
    *   **代码举例说明:** 代码片段本身就是一个很好的例子。它使用了与 `ExampleX509KeyPair` 相同的 PEM 编码的字符串。
    *   **假设输入:**  与 `ExampleX509KeyPair` 相同，`certPem` 和 `keyPem` 包含有效的证书和私钥。
    *   **输出:**  如果配置成功，会启动一个监听在默认 TLS 端口（通常是 443，但这里 `ListenAndServeTLS("", "")` 表示不指定具体地址和端口，可能会使用一些默认行为或报错）的 HTTPS 服务器。如果配置失败，会打印错误信息并退出。

6. **`ExampleConfig_verifyConnection()`**:
    *   **功能:** 演示如何自定义 TLS 连接的验证过程，通过设置 `tls.Config` 中的 `VerifyConnection` 字段。
    *   **Go 语言功能实现:** 展示了如何定义一个函数并将其赋值给 `VerifyConnection`，该函数接收一个 `tls.ConnectionState` 参数，并返回一个 `error`。
    *   **代码举例说明:** 代码片段展示了客户端和服务端两种配置。客户端通过 `InsecureSkipVerify: true` 跳过默认验证，并使用自定义的 `VerifyConnection` 来执行类似默认的证书验证。服务端则要求客户端证书 (`ClientAuth: tls.RequireAnyClientCert`)，并使用自定义的 `VerifyConnection` 来验证客户端证书。
    *   **使用者易犯错的点:**
        *   如果设置了 `InsecureSkipVerify: true` 但没有提供自定义的 `VerifyConnection`，则会跳过所有证书验证，这会带来安全风险。
        *   在自定义的 `VerifyConnection` 函数中，需要谨慎处理 `cs.PeerCertificates`，确保索引的有效性，例如在服务端示例中，如果客户端没有提供证书，访问 `cs.PeerCertificates[0]` 可能会导致 panic。

**关于命令行参数:**

这段代码主要用于演示 `crypto/tls` 包的 API 使用，并没有直接处理命令行参数。它更侧重于展示如何在代码中配置和使用 TLS 功能。如果在实际的应用中需要处理命令行参数来配置 TLS 相关选项（例如证书路径、监听地址等），通常会使用 `flag` 包或其他命令行参数解析库。

**总结:**

总而言之，这段 `example_test.go` 代码片段提供了 `crypto/tls` 包关键功能的示例，涵盖了 TLS 连接的建立、证书加载、服务器配置以及连接验证的自定义。这些示例对于理解和使用 Go 语言的 TLS 功能非常有帮助。

Prompt: 
```
这是路径为go/src/crypto/tls/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls_test

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
)

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	clear(b)
	return len(b), nil
}

func ExampleDial() {
	// Connecting with a custom root-certificate set.

	const rootPEM = `
-- GlobalSign Root R2, valid until Dec 15, 2021
-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1
MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL
v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8
eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq
tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd
C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa
zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB
mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH
V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n
bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG
3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs
J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO
291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS
ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd
AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7
TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==
-----END CERTIFICATE-----`

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}

	conn, err := tls.Dial("tcp", "mail.google.com:443", &tls.Config{
		RootCAs: roots,
	})
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	conn.Close()
}

func ExampleConfig_keyLogWriter() {
	// Debugging TLS applications by decrypting a network traffic capture.

	// WARNING: Use of KeyLogWriter compromises security and should only be
	// used for debugging.

	// Dummy test HTTP server for the example with insecure random so output is
	// reproducible.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{
		Rand: zeroSource{}, // for example only; don't do this.
	}
	server.StartTLS()
	defer server.Close()

	// Typically the log would go to an open file:
	// w, err := os.OpenFile("tls-secrets.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	w := os.Stdout

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				KeyLogWriter: w,

				Rand:               zeroSource{}, // for reproducible output; don't do this.
				InsecureSkipVerify: true,         // test server certificate is not trusted.
			},
		},
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		log.Fatalf("Failed to get URL: %v", err)
	}
	resp.Body.Close()

	// The resulting file can be used with Wireshark to decrypt the TLS
	// connection by setting (Pre)-Master-Secret log filename in SSL Protocol
	// preferences.
}

func ExampleLoadX509KeyPair() {
	cert, err := tls.LoadX509KeyPair("testdata/example-cert.pem", "testdata/example-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", ":2000", cfg)
	if err != nil {
		log.Fatal(err)
	}
	_ = listener
}

func ExampleX509KeyPair() {
	certPem := []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", ":2000", cfg)
	if err != nil {
		log.Fatal(err)
	}
	_ = listener
}

func ExampleX509KeyPair_httpServer() {
	certPem := []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	srv := &http.Server{
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func ExampleConfig_verifyConnection() {
	// VerifyConnection can be used to replace and customize connection
	// verification. This example shows a VerifyConnection implementation that
	// will be approximately equivalent to what crypto/tls does normally to
	// verify the peer's certificate.

	// Client side configuration.
	_ = &tls.Config{
		// Set InsecureSkipVerify to skip the default validation we are
		// replacing. This will not disable VerifyConnection.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				DNSName:       cs.ServerName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}

	// Server side configuration.
	_ = &tls.Config{
		// Require client certificates (or VerifyConnection will run anyway and
		// panic accessing cs.PeerCertificates[0]) but don't verify them with the
		// default verifier. This will not disable VerifyConnection.
		ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				DNSName:       cs.ServerName,
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}

	// Note that when certificates are not handled by the default verifier
	// ConnectionState.VerifiedChains will be nil.
}

"""



```