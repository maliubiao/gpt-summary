Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the TLS handshake process on the server side.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The code is within the `crypto/tls` package and the filename `handshake_server.go` strongly suggests this code is responsible for handling the server-side of the TLS handshake. The functions `serverHandshake` and the `serverHandshakeState` struct confirm this.

2. **Deconstruct the `serverHandshake` function:** This function is the entry point. It checks the TLS version and then calls either `serverHandshakeStateTLS13.handshake()` (not in the provided snippet) for TLS 1.3 or `serverHandshakeState.handshake()` for earlier versions.

3. **Analyze the `serverHandshakeState` struct:** This struct holds the state of the handshake, including the connection, context, client hello message, server hello message, chosen cipher suite, session state, and cryptographic keys. It gives clues about the data being processed during the handshake.

4. **Examine the `serverHandshakeState.handshake()` method:** This is the heart of the logic for TLS < 1.3. It performs a series of steps:
    * `processClientHello()`: Processes the client's initial message.
    * `checkForResumption()`: Checks if the server can resume a previous session.
    * If resuming: `doResumeHandshake()`, `establishKeys()`, `sendSessionTicket()`, `sendFinished()`, `readFinished()`.
    * If not resuming: `pickCipherSuite()`, `doFullHandshake()`, `establishKeys()`, `readFinished()`, `sendSessionTicket()`, `sendFinished()`.

5. **Delve into the helper methods within `serverHandshakeState`:**  Each of these methods performs a specific part of the handshake. Understanding their roles is key:
    * `processClientHello()`: Parses the `ClientHello` message, selects the TLS version, handles ECH, gets the server certificate, and negotiates ALPN.
    * `negotiateALPN()`: Selects an application-level protocol.
    * `supportsECDHE()`: Checks if Elliptic Curve Diffie-Hellman Ephemeral key exchange is supported.
    * `pickCipherSuite()`: Chooses a mutually supported cipher suite.
    * `cipherSuiteOk()`: Checks if a cipher suite is compatible with the server's capabilities.
    * `checkForResumption()`: Checks for session ticket and decides whether to resume a session.
    * `doResumeHandshake()`: Handles the abbreviated handshake for session resumption.
    * `doFullHandshake()`: Handles the full handshake.
    * `establishKeys()`: Derives the encryption keys based on the negotiated parameters.
    * `readFinished()`: Reads and verifies the client's `Finished` message.
    * `sendSessionTicket()`: Sends a new session ticket to the client.
    * `sendFinished()`: Sends the server's `Finished` message.

6. **Analyze the `Conn` methods called within `serverHandshake` and `serverHandshakeState`:** These provide further context:
    * `readClientHello()`: Reads and parses the `ClientHello`.
    * `readHandshake()`: Reads a handshake message.
    * `sendAlert()`: Sends a TLS alert.
    * `flush()`: Flushes buffered data.
    * `writeHandshakeRecord()`: Writes a handshake message.
    * `readChangeCipherSpec()`: Reads the Change Cipher Spec message.
    * `writeChangeCipherRecord()`: Writes the Change Cipher Spec message.
    * `processCertsFromClient()`: Processes and verifies client certificates.
    * `clientHelloInfo()`: Creates a struct containing information from the `ClientHello`.

7. **Identify Go Language Features:** The code uses several core Go features:
    * **Structs:** `serverHandshakeState` to hold handshake state.
    * **Methods:** Functions associated with structs (e.g., `hs.handshake()`).
    * **Interfaces:** `crypto.Signer`, `crypto.Decrypter`, `hash.Hash`.
    * **Error Handling:** Returning `error` values.
    * **Context:** Using `context.Context` for cancellation and timeouts.
    * **Slices and Maps:** Used for storing lists of cipher suites, certificates, etc.
    * **Type Assertions:**  `msg.(*clientHelloMsg)` to check the message type.

8. **Construct Example Go Code:**  Illustrate a simple server setup using the `net/http` package with TLS configuration. This highlights how this low-level handshake code is used in a higher-level context. Include hypothetical client and server behavior.

9. **Identify Potential Pitfalls:** Think about common errors developers might make when configuring TLS servers:
    * Incorrect certificate/key paths.
    * Mismatched client and server TLS configurations (e.g., incompatible cipher suites or minimum TLS versions).
    * Forgetting to handle `ListenAndServeTLS` correctly.

10. **Structure the Answer:** Organize the information logically with clear headings and concise explanations. Use bullet points for listing functionalities and potential pitfalls. Provide the example code within code blocks.

11. **Refine and Review:** Read through the answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have focused too much on individual functions without highlighting the overall handshake flow. Reviewing helps to correct such oversights.
这段Go语言代码实现了TLS协议服务端握手过程的一部分。更具体地说，它处理了TLS 1.2及更早版本的握手流程。以下是其主要功能：

**核心功能:**

1. **处理客户端的Hello消息 (`readClientHello`):**
   - 读取并解析客户端发送的 `ClientHello` 消息，该消息包含了客户端支持的协议版本、密码套件、扩展等信息。
   - 进行加密客户端Hello (ECH) 的处理，如果客户端使用了 ECH。
   - 根据客户端的 `ClientHello` 信息和服务器配置，选择双方都支持的TLS协议版本 (`mutualVersion`)。
   - 如果配置了 `GetConfigForClient` 回调函数，则根据客户端信息动态选择服务器配置。
   - 检查客户端提供的TLS版本是否受支持，如果不支持则发送 `alertProtocolVersion` 警报。
   - 检查客户端是否在TLS 1.3之前的版本使用了 ECH，如果使用则发送 `alertIllegalParameter` 警报。

2. **处理客户端Hello消息的后续步骤 (`processClientHello`):**
   - 创建并初始化 `ServerHello` 消息，设置服务器选择的TLS版本。
   - 检查客户端是否支持无压缩连接。
   - 生成 32 字节的随机数作为服务器随机数，并可能包含降级保护的标记。
   - 检查客户端的 `ClientHello` 是否包含不安全的重新协商扩展，如果包含则发送 `alertHandshakeFailure` 警报。
   - 设置 `ServerHello` 中的扩展主密钥支持和安全重新协商支持标记。
   - 设置 `ServerHello` 中的压缩方法为无压缩。
   - 如果客户端提供了服务器名称指示 (SNI)，则记录该名称。
   - 调用 `negotiateALPN` 函数协商应用层协议。
   - 根据客户端信息获取服务器证书。
   - 如果客户端请求了签名证书时间戳 (SCTs)，则将服务器证书中的 SCTs 包含在 `ServerHello` 中。
   - 检查客户端是否支持椭圆曲线 Diffie-Hellman 密钥交换 (ECDHE)。

3. **协商应用层协议 (`negotiateALPN`):**
   - 比较服务器和客户端支持的应用层协议列表 (ALPN)，选择一个双方都支持的协议。
   - 如果未找到共同支持的协议，则返回错误。
   - 特殊处理了 "h2" 和 "http/1.1" 的情况，允许 "http/1.1" 客户端连接到只支持 "h2" 的服务器。

4. **判断是否支持ECDHE (`supportsECDHE`):**
   - 检查客户端是否支持服务器配置中指定的椭圆曲线。
   - 检查客户端是否支持未压缩的椭圆曲线点格式。

5. **选择密码套件 (`pickCipherSuite`):**
   - 根据服务器配置和客户端提供的密码套件列表，选择一个双方都支持的密码套件。
   - 考虑硬件加速的 AES-GCM 的偏好。
   - 如果未找到共同支持的密码套件，则发送 `alertHandshakeFailure` 警报。
   - 检查客户端是否发送了 `TLS_FALLBACK_SCSV` 信号，以检测潜在的协议降级攻击。

6. **判断密码套件是否可用 (`cipherSuiteOk`):**
   - 检查密码套件所需的密钥交换算法和签名算法是否被服务器支持（例如 ECDHE、RSA 加密/签名，ECDSA 签名）。

7. **检查是否可以恢复会话 (`checkForResumption`):**
   - 检查服务器是否禁用了会话票据。
   - 尝试解密客户端提供的会话票据。
   - 验证会话票据的有效性，包括过期时间、TLS版本、密码套件、客户端证书信息等。
   - 检查扩展主密钥 (Extended Master Secret) 的支持情况。

8. **执行会话恢复握手 (`doResumeHandshake`):**
   - 当可以恢复会话时，创建 `ServerHello` 消息，包含协商的密码套件和客户端提供的会话ID。
   - 计算握手消息的哈希值。
   - 发送 `ServerHello` 消息。
   - 如果配置了 `VerifyConnection` 回调函数，则进行连接验证。
   - 使用会话票据中保存的密钥作为主密钥。

9. **执行完整握手 (`doFullHandshake`):**
   - 当无法恢复会话时，进行完整的握手流程。
   - 设置 `ServerHello` 中的 OCSP 装订支持和会话票据支持标记。
   - 计算握手消息的哈希值。
   - 发送 `ServerHello` 消息。
   - 发送服务器证书消息 (`Certificate`)。
   - 如果支持 OCSP 装订，则发送证书状态消息 (`CertificateStatus`)，包含 OCSP Staple。
   - 根据选择的密钥交换算法，生成并发送服务器密钥交换消息 (`ServerKeyExchange`)。
   - 如果配置了客户端认证，则发送证书请求消息 (`CertificateRequest`)。
   - 发送服务器Hello完成消息 (`ServerHelloDone`)。
   - 等待并读取客户端发送的消息，包括证书消息 (`Certificate`)（如果请求了客户端证书）和客户端密钥交换消息 (`ClientKeyExchange`).
   - 处理客户端证书，进行验证。
   - 处理客户端密钥交换消息，计算预主密钥和主密钥。
   - 如果收到了客户端证书，则验证客户端发送的证书验证消息 (`CertificateVerify`)。

10. **建立密钥 (`establishKeys`):**
    - 根据协商的密码套件、主密钥以及客户端和服务器的随机数，派生出用于加密和认证的密钥和初始化向量。
    - 配置连接的输入和输出方向的密码规范。

11. **读取客户端的Finished消息 (`readFinished`):**
    - 读取客户端发送的 `ChangeCipherSpec` 消息。
    - 读取客户端发送的 `Finished` 消息。
    - 验证 `Finished` 消息中的验证数据是否与根据主密钥和握手消息计算出的哈希值一致。

12. **发送会话票据 (`sendSessionTicket`):**
    - 如果支持会话票据，则创建并发送 `NewSessionTicket` 消息，其中包含加密的会话状态信息。

13. **发送服务器的Finished消息 (`sendFinished`):**
    - 发送 `ChangeCipherSpec` 消息，通知客户端启用加密。
    - 创建并发送服务器的 `Finished` 消息，其中包含根据主密钥和握手消息计算出的哈希值。

14. **处理客户端证书 (`processCertsFromClient`):**
    - 解析客户端发送的证书链。
    - 检查证书的有效性，包括解析、密钥大小等。
    - 如果配置了客户端认证，并且客户端没有提供证书，则发送 `alertBadCertificate` 或 `alertCertificateRequired` 警报。
    - 如果配置了 `VerifyClientCertIfGiven` 或更高的客户端认证级别，则验证客户端证书链的有效性。
    - 如果配置了 `VerifyPeerCertificate` 回调函数，则调用该函数进行额外的证书验证。

15. **创建 ClientHelloInfo (`clientHelloInfo`):**
    - 创建一个包含 `ClientHello` 消息中相关信息的结构体，用于在 `GetConfigForClient` 等回调函数中使用。

**可以推理出它是什么Go语言功能的实现:**

这段代码是 `crypto/tls` 包中实现 **TLS 服务端握手** 功能的核心部分。它处理了接收客户端的连接请求，协商加密参数，进行身份验证（可选），并最终建立安全连接的过程。

**Go代码示例:**

以下是一个简化的使用这段代码功能的示例，展示了如何创建一个简单的HTTPS服务器：

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

func main() {
	// 1. 生成自签名证书（生产环境不应这样做）
	cert, key, err := generateSelfSignedCertKey()
	if err != nil {
		log.Fatalf("Error generating self-signed cert: %v", err)
	}

	// 2. 创建 TLS 证书
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("Error creating TLS cert: %v", err)
	}

	// 3. 配置 TLS
	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		// 可选：配置客户端认证
		// ClientAuth: tls.RequireAndVerifyClientCert,
		// ClientCAs:  caCertPool, // 如果需要验证客户端证书
		MinVersion: tls.VersionTLS12, // 设置最低TLS版本
	}

	// 4. 创建 HTTP 服务器
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, TLS!")
	})

	server := &http.Server{
		Addr:    ":8443",
		Handler: mux,
		TLSConfig: config,
	}

	// 5. 启动 HTTPS 服务器
	log.Println("Starting HTTPS server on :8443")
	err = server.ListenAndServeTLS("", "") // 证书和密钥由 TLSConfig 提供
	if err != nil {
		log.Fatalf("ListenAndServeTLS error: %v", err)
	}
}

// generateSelfSignedCertKey 生成自签名证书和密钥 (仅用于示例)
func generateSelfSignedCertKey() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"My Company"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return certPEM, keyPEM, nil
}
```

**假设的输入与输出 (针对 `readClientHello` 函数):**

**假设输入:**

- `c`: 一个已经建立的网络连接 (`net.Conn`)。
- 上下文 (`context.Context`)。
- 客户端发送的原始 TLS `ClientHello` 消息字节流。

**假设输出:**

- `clientHello`: 一个解析后的 `clientHelloMsg` 结构体，包含了客户端的 TLS 版本、支持的密码套件、扩展等信息。
- `ech`:  如果客户端使用了 ECH，则包含 `echServerContext`，否则为 `nil`。
- `err`: 如果读取或解析过程中发生错误，则返回错误，否则返回 `nil`。

**代码推理:**

在 `readClientHello` 函数中，`c.readHandshake(nil)` 会从连接中读取握手消息。假设客户端发送了一个包含以下信息的 `ClientHello` 消息（简化表示）：

```
ClientHello {
  Version: TLS 1.2 (0x0303)
  Random: ... (32 bytes)
  SessionId: ...
  CipherSuites: [TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ...]
  Extensions: {
    ServerName: "example.com"
    SupportedVersions: [TLS 1.2, TLS 1.3]
    // ... 其他扩展
  }
}
```

`readClientHello` 函数会将其解析成 `clientHelloMsg` 结构体。输出的 `clientHello` 将会包含类似以下的信息：

```go
&tls.clientHelloMsg{
	vers:         0x303,
	random:       ... ,
	sessionId:    ... ,
	cipherSuites: []uint16{0xc02f, ...}, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	extensions: []extension{
		{Type: 0, Data: []byte{...}}, // ServerName extension
		{Type: 43, Data: []byte{...}}, // SupportedVersions extension
		// ...
	},
	serverName: "example.com",
	supportedVersions: []uint16{0x303, 0x304}, // TLS 1.2, TLS 1.3
	// ...
}
```

如果服务器配置支持 TLS 1.2，那么 `c.vers` 将会被设置为 `tls.VersionTLS12`。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。TLS 服务器的配置通常是在代码中完成的，例如通过 `tls.Config` 结构体。

然而，一些与 TLS 相关的工具（如 `openssl s_server`）会使用命令行参数来指定证书、密钥、监听端口等。这些工具的实现会涉及到 `crypto/tls` 包的使用，但参数处理逻辑在工具本身的代码中。

**使用者易犯错的点:**

1. **证书和密钥配置错误:**
   - **错误示例:** 未正确指定证书文件路径或密钥文件路径，或者证书和密钥不匹配。
   ```go
   config := &tls.Config{
       Certificates: make([]tls.Certificate, 1),
   }
   cert, err := tls.LoadX509KeyPair("wrong_cert.pem", "wrong_key.pem")
   if err != nil {
       log.Fatal(err)
   }
   config.Certificates[0] = cert
   ```
   - **正确做法:** 确保 `tls.LoadX509KeyPair` 函数加载的是正确的、匹配的证书和私钥文件。

2. **TLS 版本配置不当:**
   - **错误示例:**  将最低 TLS 版本设置为过低，导致安全风险。
   ```go
   config := &tls.Config{
       MinVersion: tls.VersionTLS10, // 非常不安全，应该避免
   }
   ```
   - **正确做法:**  根据安全要求，设置合适的最低 TLS 版本，通常建议设置为 `tls.VersionTLS12` 或更高。

3. **密码套件配置不当:**
   - **错误示例:**  不小心启用了不安全的或过时的密码套件。
   ```go
   config := &tls.Config{
       CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}, // RC4 有安全漏洞，应避免使用
   }
   ```
   - **正确做法:**  依赖 Go 语言的默认密码套件选择，或者只显式指定安全的、推荐的密码套件。

4. **客户端认证配置错误:**
   - **错误示例:**  在需要客户端认证的情况下，未配置 `ClientCAs`，导致无法验证客户端证书。
   ```go
   config := &tls.Config{
       ClientAuth: tls.RequireAndVerifyClientCert,
       // ClientCAs 未配置
   }
   ```
   - **正确做法:**  如果需要客户端认证，需要加载信任的客户端证书颁发机构 (CA) 证书，并将其设置为 `ClientCAs`。

5. **ALPN 配置错误:**
   - **错误示例:**  服务器配置的 ALPN 协议与客户端请求的不匹配，导致连接失败。
   ```go
   config := &tls.Config{
       NextProtos: []string{"h2"}, // 服务器只支持 HTTP/2
   }
   // 客户端只发送 "http/1.1"
   ```
   - **正确做法:**  确保服务器和客户端配置的 ALPN 协议能够匹配上。

理解这些细节可以帮助开发者更安全、更有效地配置和使用 Go 语言的 TLS 功能。

Prompt: 
```
这是路径为go/src/crypto/tls/handshake_server.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls/internal/fips140tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"internal/byteorder"
	"io"
	"time"
)

// serverHandshakeState contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
type serverHandshakeState struct {
	c            *Conn
	ctx          context.Context
	clientHello  *clientHelloMsg
	hello        *serverHelloMsg
	suite        *cipherSuite
	ecdheOk      bool
	ecSignOk     bool
	rsaDecryptOk bool
	rsaSignOk    bool
	sessionState *SessionState
	finishedHash finishedHash
	masterSecret []byte
	cert         *Certificate
}

// serverHandshake performs a TLS handshake as a server.
func (c *Conn) serverHandshake(ctx context.Context) error {
	clientHello, ech, err := c.readClientHello(ctx)
	if err != nil {
		return err
	}

	if c.vers == VersionTLS13 {
		hs := serverHandshakeStateTLS13{
			c:           c,
			ctx:         ctx,
			clientHello: clientHello,
			echContext:  ech,
		}
		return hs.handshake()
	}

	hs := serverHandshakeState{
		c:           c,
		ctx:         ctx,
		clientHello: clientHello,
	}
	return hs.handshake()
}

func (hs *serverHandshakeState) handshake() error {
	c := hs.c

	if err := hs.processClientHello(); err != nil {
		return err
	}

	// For an overview of TLS handshaking, see RFC 5246, Section 7.3.
	c.buffering = true
	if err := hs.checkForResumption(); err != nil {
		return err
	}
	if hs.sessionState != nil {
		// The client has included a session ticket and so we do an abbreviated handshake.
		if err := hs.doResumeHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendSessionTicket(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.serverFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.readFinished(nil); err != nil {
			return err
		}
	} else {
		// The client didn't include a session ticket, or it wasn't
		// valid so we do a full handshake.
		if err := hs.pickCipherSuite(); err != nil {
			return err
		}
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readFinished(c.clientFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		c.buffering = true
		if err := hs.sendSessionTicket(); err != nil {
			return err
		}
		if err := hs.sendFinished(nil); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random)
	c.isHandshakeComplete.Store(true)

	return nil
}

// readClientHello reads a ClientHello message and selects the protocol version.
func (c *Conn) readClientHello(ctx context.Context) (*clientHelloMsg, *echServerContext, error) {
	// clientHelloMsg is included in the transcript, but we haven't initialized
	// it yet. The respective handshake functions will record it themselves.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return nil, nil, err
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, nil, unexpectedMessageError(clientHello, msg)
	}

	// ECH processing has to be done before we do any other negotiation based on
	// the contents of the client hello, since we may swap it out completely.
	var ech *echServerContext
	if len(clientHello.encryptedClientHello) != 0 {
		clientHello, ech, err = c.processECHClientHello(clientHello)
		if err != nil {
			return nil, nil, err
		}
	}

	var configForClient *Config
	originalConfig := c.config
	if c.config.GetConfigForClient != nil {
		chi := clientHelloInfo(ctx, c, clientHello)
		if configForClient, err = c.config.GetConfigForClient(chi); err != nil {
			c.sendAlert(alertInternalError)
			return nil, nil, err
		} else if configForClient != nil {
			c.config = configForClient
		}
	}
	c.ticketKeys = originalConfig.ticketKeys(configForClient)

	clientVersions := clientHello.supportedVersions
	if len(clientHello.supportedVersions) == 0 {
		clientVersions = supportedVersionsFromMax(clientHello.vers)
	}
	c.vers, ok = c.config.mutualVersion(roleServer, clientVersions)
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return nil, nil, fmt.Errorf("tls: client offered only unsupported versions: %x", clientVersions)
	}
	c.haveVers = true
	c.in.version = c.vers
	c.out.version = c.vers

	// This check reflects some odd specification implied behavior. Client-facing servers
	// are supposed to reject hellos with outer ECH and inner ECH that offers 1.2, but
	// backend servers are allowed to accept hellos with inner ECH that offer 1.2, since
	// they cannot expect client-facing servers to behave properly. Since we act as both
	// a client-facing and backend server, we only enforce 1.3 being negotiated if we
	// saw a hello with outer ECH first. The spec probably should've made this an error,
	// but it didn't, and this matches the boringssl behavior.
	if c.vers != VersionTLS13 && (ech != nil && !ech.inner) {
		c.sendAlert(alertIllegalParameter)
		return nil, nil, errors.New("tls: Encrypted Client Hello cannot be used pre-TLS 1.3")
	}

	if c.config.MinVersion == 0 && c.vers < VersionTLS12 {
		tls10server.Value() // ensure godebug is initialized
		tls10server.IncNonDefault()
	}

	return clientHello, ech, nil
}

func (hs *serverHandshakeState) processClientHello() error {
	c := hs.c

	hs.hello = new(serverHelloMsg)
	hs.hello.vers = c.vers

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	if !foundCompression {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client does not support uncompressed connections")
	}

	hs.hello.random = make([]byte, 32)
	serverRandom := hs.hello.random
	// Downgrade protection canaries. See RFC 8446, Section 4.1.3.
	maxVers := c.config.maxSupportedVersion(roleServer)
	if maxVers >= VersionTLS12 && c.vers < maxVers || testingOnlyForceDowngradeCanary {
		if c.vers == VersionTLS12 {
			copy(serverRandom[24:], downgradeCanaryTLS12)
		} else {
			copy(serverRandom[24:], downgradeCanaryTLS11)
		}
		serverRandom = serverRandom[:24]
	}
	_, err := io.ReadFull(c.config.rand(), serverRandom)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	hs.hello.extendedMasterSecret = hs.clientHello.extendedMasterSecret
	hs.hello.secureRenegotiationSupported = hs.clientHello.secureRenegotiationSupported
	hs.hello.compressionMethod = compressionNone
	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}

	selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols, false)
	if err != nil {
		c.sendAlert(alertNoApplicationProtocol)
		return err
	}
	hs.hello.alpnProtocol = selectedProto
	c.clientProtocol = selectedProto

	hs.cert, err = c.config.getCertificate(clientHelloInfo(hs.ctx, c, hs.clientHello))
	if err != nil {
		if err == errNoCertificates {
			c.sendAlert(alertUnrecognizedName)
		} else {
			c.sendAlert(alertInternalError)
		}
		return err
	}
	if hs.clientHello.scts {
		hs.hello.scts = hs.cert.SignedCertificateTimestamps
	}

	hs.ecdheOk = supportsECDHE(c.config, c.vers, hs.clientHello.supportedCurves, hs.clientHello.supportedPoints)

	if hs.ecdheOk && len(hs.clientHello.supportedPoints) > 0 {
		// Although omitting the ec_point_formats extension is permitted, some
		// old OpenSSL version will refuse to handshake if not present.
		//
		// Per RFC 4492, section 5.1.2, implementations MUST support the
		// uncompressed point format. See golang.org/issue/31943.
		hs.hello.supportedPoints = []uint8{pointFormatUncompressed}
	}

	if priv, ok := hs.cert.PrivateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecSignOk = true
		case ed25519.PublicKey:
			hs.ecSignOk = true
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: unsupported signing key type (%T)", priv.Public())
		}
	}
	if priv, ok := hs.cert.PrivateKey.(crypto.Decrypter); ok {
		switch priv.Public().(type) {
		case *rsa.PublicKey:
			hs.rsaDecryptOk = true
		default:
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: unsupported decryption key type (%T)", priv.Public())
		}
	}

	return nil
}

// negotiateALPN picks a shared ALPN protocol that both sides support in server
// preference order. If ALPN is not configured or the peer doesn't support it,
// it returns "" and no error.
func negotiateALPN(serverProtos, clientProtos []string, quic bool) (string, error) {
	if len(serverProtos) == 0 || len(clientProtos) == 0 {
		if quic && len(serverProtos) != 0 {
			// RFC 9001, Section 8.1
			return "", fmt.Errorf("tls: client did not request an application protocol")
		}
		return "", nil
	}
	var http11fallback bool
	for _, s := range serverProtos {
		for _, c := range clientProtos {
			if s == c {
				return s, nil
			}
			if s == "h2" && c == "http/1.1" {
				http11fallback = true
			}
		}
	}
	// As a special case, let http/1.1 clients connect to h2 servers as if they
	// didn't support ALPN. We used not to enforce protocol overlap, so over
	// time a number of HTTP servers were configured with only "h2", but
	// expected to accept connections from "http/1.1" clients. See Issue 46310.
	if http11fallback {
		return "", nil
	}
	return "", fmt.Errorf("tls: client requested unsupported application protocols (%s)", clientProtos)
}

// supportsECDHE returns whether ECDHE key exchanges can be used with this
// pre-TLS 1.3 client.
func supportsECDHE(c *Config, version uint16, supportedCurves []CurveID, supportedPoints []uint8) bool {
	supportsCurve := false
	for _, curve := range supportedCurves {
		if c.supportsCurve(version, curve) {
			supportsCurve = true
			break
		}
	}

	supportsPointFormat := false
	for _, pointFormat := range supportedPoints {
		if pointFormat == pointFormatUncompressed {
			supportsPointFormat = true
			break
		}
	}
	// Per RFC 8422, Section 5.1.2, if the Supported Point Formats extension is
	// missing, uncompressed points are supported. If supportedPoints is empty,
	// the extension must be missing, as an empty extension body is rejected by
	// the parser. See https://go.dev/issue/49126.
	if len(supportedPoints) == 0 {
		supportsPointFormat = true
	}

	return supportsCurve && supportsPointFormat
}

func (hs *serverHandshakeState) pickCipherSuite() error {
	c := hs.c

	preferenceOrder := cipherSuitesPreferenceOrder
	if !hasAESGCMHardwareSupport || !aesgcmPreferred(hs.clientHello.cipherSuites) {
		preferenceOrder = cipherSuitesPreferenceOrderNoAES
	}

	configCipherSuites := c.config.cipherSuites()
	preferenceList := make([]uint16, 0, len(configCipherSuites))
	for _, suiteID := range preferenceOrder {
		for _, id := range configCipherSuites {
			if id == suiteID {
				preferenceList = append(preferenceList, id)
				break
			}
		}
	}

	hs.suite = selectCipherSuite(preferenceList, hs.clientHello.cipherSuites, hs.cipherSuiteOk)
	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: no cipher suite supported by both client and server")
	}
	c.cipherSuite = hs.suite.id

	if c.config.CipherSuites == nil && !fips140tls.Required() && rsaKexCiphers[hs.suite.id] {
		tlsrsakex.Value() // ensure godebug is initialized
		tlsrsakex.IncNonDefault()
	}
	if c.config.CipherSuites == nil && !fips140tls.Required() && tdesCiphers[hs.suite.id] {
		tls3des.Value() // ensure godebug is initialized
		tls3des.IncNonDefault()
	}

	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// The client is doing a fallback connection. See RFC 7507.
			if hs.clientHello.vers < c.config.maxSupportedVersion(roleServer) {
				c.sendAlert(alertInappropriateFallback)
				return errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	return nil
}

func (hs *serverHandshakeState) cipherSuiteOk(c *cipherSuite) bool {
	if c.flags&suiteECDHE != 0 {
		if !hs.ecdheOk {
			return false
		}
		if c.flags&suiteECSign != 0 {
			if !hs.ecSignOk {
				return false
			}
		} else if !hs.rsaSignOk {
			return false
		}
	} else if !hs.rsaDecryptOk {
		return false
	}
	if hs.c.vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
		return false
	}
	return true
}

// checkForResumption reports whether we should perform resumption on this connection.
func (hs *serverHandshakeState) checkForResumption() error {
	c := hs.c

	if c.config.SessionTicketsDisabled {
		return nil
	}

	var sessionState *SessionState
	if c.config.UnwrapSession != nil {
		ss, err := c.config.UnwrapSession(hs.clientHello.sessionTicket, c.connectionStateLocked())
		if err != nil {
			return err
		}
		if ss == nil {
			return nil
		}
		sessionState = ss
	} else {
		plaintext := c.config.decryptTicket(hs.clientHello.sessionTicket, c.ticketKeys)
		if plaintext == nil {
			return nil
		}
		ss, err := ParseSessionState(plaintext)
		if err != nil {
			return nil
		}
		sessionState = ss
	}

	// TLS 1.2 tickets don't natively have a lifetime, but we want to avoid
	// re-wrapping the same master secret in different tickets over and over for
	// too long, weakening forward secrecy.
	createdAt := time.Unix(int64(sessionState.createdAt), 0)
	if c.config.time().Sub(createdAt) > maxSessionTicketLifetime {
		return nil
	}

	// Never resume a session for a different TLS version.
	if c.vers != sessionState.version {
		return nil
	}

	cipherSuiteOk := false
	// Check that the client is still offering the ciphersuite in the session.
	for _, id := range hs.clientHello.cipherSuites {
		if id == sessionState.cipherSuite {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return nil
	}

	// Check that we also support the ciphersuite from the session.
	suite := selectCipherSuite([]uint16{sessionState.cipherSuite},
		c.config.cipherSuites(), hs.cipherSuiteOk)
	if suite == nil {
		return nil
	}

	sessionHasClientCerts := len(sessionState.peerCertificates) != 0
	needClientCerts := requiresClientCert(c.config.ClientAuth)
	if needClientCerts && !sessionHasClientCerts {
		return nil
	}
	if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
		return nil
	}
	if sessionHasClientCerts && c.config.time().After(sessionState.peerCertificates[0].NotAfter) {
		return nil
	}
	if sessionHasClientCerts && c.config.ClientAuth >= VerifyClientCertIfGiven &&
		len(sessionState.verifiedChains) == 0 {
		return nil
	}

	// RFC 7627, Section 5.3
	if !sessionState.extMasterSecret && hs.clientHello.extendedMasterSecret {
		return nil
	}
	if sessionState.extMasterSecret && !hs.clientHello.extendedMasterSecret {
		// Aborting is somewhat harsh, but it's a MUST and it would indicate a
		// weird downgrade in client capabilities.
		return errors.New("tls: session supported extended_master_secret but client does not")
	}

	c.peerCertificates = sessionState.peerCertificates
	c.ocspResponse = sessionState.ocspResponse
	c.scts = sessionState.scts
	c.verifiedChains = sessionState.verifiedChains
	c.extMasterSecret = sessionState.extMasterSecret
	hs.sessionState = sessionState
	hs.suite = suite
	c.didResume = true
	return nil
}

func (hs *serverHandshakeState) doResumeHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	c.cipherSuite = hs.suite.id
	// We echo the client's session ID in the ServerHello to let it know
	// that we're doing a resumption.
	hs.hello.sessionId = hs.clientHello.sessionId
	// We always send a new session ticket, even if it wraps the same master
	// secret and it's potentially encrypted with the same key, to help the
	// client avoid cross-connection tracking from a network observer.
	hs.hello.ticketSupported = true
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil {
		return err
	}
	if _, err := hs.c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil {
		return err
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	hs.masterSecret = hs.sessionState.secret

	return nil
}

func (hs *serverHandshakeState) doFullHandshake() error {
	c := hs.c

	if hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0 {
		hs.hello.ocspStapling = true
	}

	hs.hello.ticketSupported = hs.clientHello.ticketSupported && !c.config.SessionTicketsDisabled
	hs.hello.cipherSuite = hs.suite.id

	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	if c.config.ClientAuth == NoClientCert {
		// No need to keep a full record of the handshake if client
		// certificates won't be used.
		hs.finishedHash.discardHandshakeBuffer()
	}
	if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil {
		return err
	}
	if _, err := hs.c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil {
		return err
	}

	certMsg := new(certificateMsg)
	certMsg.certificates = hs.cert.Certificate
	if _, err := hs.c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
		return err
	}

	if hs.hello.ocspStapling {
		certStatus := new(certificateStatusMsg)
		certStatus.response = hs.cert.OCSPStaple
		if _, err := hs.c.writeHandshakeRecord(certStatus, &hs.finishedHash); err != nil {
			return err
		}
	}

	keyAgreement := hs.suite.ka(c.vers)
	skx, err := keyAgreement.generateServerKeyExchange(c.config, hs.cert, hs.clientHello, hs.hello)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	if skx != nil {
		if len(skx.key) >= 3 && skx.key[0] == 3 /* named curve */ {
			c.curveID = CurveID(byteorder.BEUint16(skx.key[1:]))
		}
		if _, err := hs.c.writeHandshakeRecord(skx, &hs.finishedHash); err != nil {
			return err
		}
	}

	var certReq *certificateRequestMsg
	if c.config.ClientAuth >= RequestClientCert {
		// Request a client certificate
		certReq = new(certificateRequestMsg)
		certReq.certificateTypes = []byte{
			byte(certTypeRSASign),
			byte(certTypeECDSASign),
		}
		if c.vers >= VersionTLS12 {
			certReq.hasSignatureAlgorithm = true
			certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
		}

		// An empty list of certificateAuthorities signals to
		// the client that it may send any certificate in response
		// to our request. When we know the CAs we trust, then
		// we can send them down, so that the client can choose
		// an appropriate certificate to give to us.
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		if _, err := hs.c.writeHandshakeRecord(certReq, &hs.finishedHash); err != nil {
			return err
		}
	}

	helloDone := new(serverHelloDoneMsg)
	if _, err := hs.c.writeHandshakeRecord(helloDone, &hs.finishedHash); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	var pub crypto.PublicKey // public key for client auth, if any

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}

	// If we requested a client certificate, then the client must send a
	// certificate message, even if it's empty.
	if c.config.ClientAuth >= RequestClientCert {
		certMsg, ok := msg.(*certificateMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certMsg, msg)
		}

		if err := c.processCertsFromClient(Certificate{
			Certificate: certMsg.certificates,
		}); err != nil {
			return err
		}
		if len(certMsg.certificates) != 0 {
			pub = c.peerCertificates[0].PublicKey
		}

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	// Get client key exchange
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}

	preMasterSecret, err := keyAgreement.processClientKeyExchange(c.config, hs.cert, ckx, c.vers)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return err
	}
	if hs.hello.extendedMasterSecret {
		c.extMasterSecret = true
		hs.masterSecret = extMasterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret,
			hs.finishedHash.Sum())
	} else {
		hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret,
			hs.clientHello.random, hs.hello.random)
	}
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.clientHello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	// If we received a client cert in response to our certificate request message,
	// the client will send us a certificateVerifyMsg immediately after the
	// clientKeyExchangeMsg. This message is a digest of all preceding
	// handshake-layer messages that is signed using the private key corresponding
	// to the client's certificate. This allows us to verify that the client is in
	// possession of the private key of the certificate.
	if len(c.peerCertificates) > 0 {
		// certificateVerifyMsg is included in the transcript, but not until
		// after we verify the handshake signature, since the state before
		// this message was sent is used.
		msg, err = c.readHandshake(nil)
		if err != nil {
			return err
		}
		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}

		var sigType uint8
		var sigHash crypto.Hash
		if c.vers >= VersionTLS12 {
			if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, certReq.supportedSignatureAlgorithms) {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tls: client certificate used with invalid signature algorithm")
			}
			sigType, sigHash, err = typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
			if err != nil {
				return c.sendAlert(alertInternalError)
			}
		} else {
			sigType, sigHash, err = legacyTypeAndHashFromPublicKey(pub)
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
		}

		signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash)
		if err := verifyHandshakeSignature(sigType, pub, sigHash, signed, certVerify.signature); err != nil {
			c.sendAlert(alertDecryptError)
			return errors.New("tls: invalid signature by the client certificate: " + err.Error())
		}

		if err := transcriptMsg(certVerify, &hs.finishedHash); err != nil {
			return err
		}
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	var clientCipher, serverCipher any
	var clientHash, serverHash hash.Hash

	if hs.suite.aead == nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

func (hs *serverHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	// finishedMsg is included in the transcript, but not until after we
	// check the client version, since the state before this message was
	// sent is used during verification.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client's Finished message is incorrect")
	}

	if err := transcriptMsg(clientFinished, &hs.finishedHash); err != nil {
		return err
	}

	copy(out, verify)
	return nil
}

func (hs *serverHandshakeState) sendSessionTicket() error {
	if !hs.hello.ticketSupported {
		return nil
	}

	c := hs.c
	m := new(newSessionTicketMsg)

	state := c.sessionState()
	state.secret = hs.masterSecret
	if hs.sessionState != nil {
		// If this is re-wrapping an old key, then keep
		// the original time it was created.
		state.createdAt = hs.sessionState.createdAt
	}
	if c.config.WrapSession != nil {
		var err error
		m.ticket, err = c.config.WrapSession(c.connectionStateLocked(), state)
		if err != nil {
			return err
		}
	} else {
		stateBytes, err := state.Bytes()
		if err != nil {
			return err
		}
		m.ticket, err = c.config.encryptTicket(stateBytes, c.ticketKeys)
		if err != nil {
			return err
		}
	}

	if _, err := hs.c.writeHandshakeRecord(m, &hs.finishedHash); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	if _, err := hs.c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}

	copy(out, finished.verifyData)

	return nil
}

// processCertsFromClient takes a chain of client certificates either from a
// Certificates message and verifies them.
func (c *Conn) processCertsFromClient(certificate Certificate) error {
	certificates := certificate.Certificate
	certs := make([]*x509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to parse client certificate: " + err.Error())
		}
		if certs[i].PublicKeyAlgorithm == x509.RSA {
			n := certs[i].PublicKey.(*rsa.PublicKey).N.BitLen()
			if max, ok := checkKeySize(n); !ok {
				c.sendAlert(alertBadCertificate)
				return fmt.Errorf("tls: client sent certificate containing RSA key larger than %d bits", max)
			}
		}
	}

	if len(certs) == 0 && requiresClientCert(c.config.ClientAuth) {
		if c.vers == VersionTLS13 {
			c.sendAlert(alertCertificateRequired)
		} else {
			c.sendAlert(alertBadCertificate)
		}
		return errors.New("tls: client didn't provide a certificate")
	}

	if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
		opts := x509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}

		chains, err := certs[0].Verify(opts)
		if err != nil {
			var errCertificateInvalid x509.CertificateInvalidError
			if errors.As(err, &x509.UnknownAuthorityError{}) {
				c.sendAlert(alertUnknownCA)
			} else if errors.As(err, &errCertificateInvalid) && errCertificateInvalid.Reason == x509.Expired {
				c.sendAlert(alertCertificateExpired)
			} else {
				c.sendAlert(alertBadCertificate)
			}
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}

		c.verifiedChains, err = fipsAllowedChains(chains)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
	}

	c.peerCertificates = certs
	c.ocspResponse = certificate.OCSPStaple
	c.scts = certificate.SignedCertificateTimestamps

	if len(certs) > 0 {
		switch certs[0].PublicKey.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		default:
			c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("tls: client certificate contains an unsupported public key of type %T", certs[0].PublicKey)
		}
	}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	return nil
}

func clientHelloInfo(ctx context.Context, c *Conn, clientHello *clientHelloMsg) *ClientHelloInfo {
	supportedVersions := clientHello.supportedVersions
	if len(clientHello.supportedVersions) == 0 {
		supportedVersions = supportedVersionsFromMax(clientHello.vers)
	}

	return &ClientHelloInfo{
		CipherSuites:      clientHello.cipherSuites,
		ServerName:        clientHello.serverName,
		SupportedCurves:   clientHello.supportedCurves,
		SupportedPoints:   clientHello.supportedPoints,
		SignatureSchemes:  clientHello.supportedSignatureAlgorithms,
		SupportedProtos:   clientHello.alpnProtocols,
		SupportedVersions: supportedVersions,
		Extensions:        clientHello.extensions,
		Conn:              c.conn,
		config:            c.config,
		ctx:               ctx,
	}
}

"""



```