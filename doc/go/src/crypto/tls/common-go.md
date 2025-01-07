Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze the provided Go code snippet from `go/src/crypto/tls/common.go` and summarize its functionalities. The request also asks for specific examples related to Go features, code inference with input/output, command-line arguments, and common mistakes.

2. **Initial Code Scan and Keyword Spotting:**  I'll first skim the code, looking for keywords and patterns that suggest specific TLS functionalities. I notice constants like `VersionTLS10`, `VersionTLS13`, `maxPlaintext`, `recordTypeHandshake`, `typeClientHello`, `extensionServerName`,  `CurveP256`, data structures like `ConnectionState`, `ClientHelloInfo`, and `Config`, and interface definitions like `ClientSessionCache`. These immediately point to core TLS concepts: versions, record structures, handshake messages, extensions, elliptic curves, connection state management, and session handling.

3. **Categorize Functionality:** Based on the keywords and the overall structure, I can start grouping the code into logical functional areas:

    * **TLS Versions:** Constants defining supported TLS versions (SSLv3, TLS 1.0, 1.1, 1.2, 1.3) and a function to get the version name.
    * **Record Layer:** Constants related to record sizes and types.
    * **Handshake Protocol:** Constants defining handshake message types.
    * **Extensions:** Constants defining various TLS extensions.
    * **Cryptography:** Definitions related to elliptic curves (`CurveID`), signature schemes (`SignatureScheme`), and related helpers.
    * **Connection State:** The `ConnectionState` struct, encapsulating information about an established TLS connection.
    * **Client Authentication:**  `ClientAuthType` and related constants.
    * **Session Management:** `ClientSessionCache` interface and related structures like `pskIdentity`.
    * **Configuration:** The `Config` struct, which is central to customizing TLS behavior.
    * **Callbacks:**  Function types like `GetCertificate`, `VerifyPeerCertificate`, `GetConfigForClient`, etc., which allow users to customize TLS behavior.
    * **Renegotiation:** `RenegotiationSupport` and related constants.

4. **Detailed Analysis of Key Structures and Functions:** Now I'll delve deeper into the most important parts:

    * **`ConnectionState`:**  This struct is crucial. I'll list all its fields and explain what each represents (version, handshake status, cipher suite, certificates, etc.). I'll pay attention to the comments explaining when each field is populated.
    * **`Config`:**  This is the configuration hub. I'll list its important fields, focusing on how they influence TLS behavior (certificates, client authentication, root CAs, cipher suites, version control, session management, callbacks).
    * **`ClientHelloInfo` and `CertificateRequestInfo`:** These structures pass information to callback functions, so understanding what data they contain is important.
    * **Version Handling:**  The `VersionName` function is straightforward, but the constants themselves are essential.

5. **Address Specific Requirements:**

    * **Go Feature Examples:** I'll look for specific Go language features demonstrated in the code, such as:
        * Constants (`const`)
        * Data structures (`struct`)
        * Interfaces (`interface`)
        * Type definitions (`type recordType uint8`)
        * Comments (`//`)
        * Import statements (`import`)
        * Built-in types (`uint16`, `uint8`, `string`, `[]byte`)

    * **Code Inference with Input/Output:**  This requires imagining how some of the functions might work. For example, `VersionName` is simple to demonstrate. For more complex scenarios, I might need to make assumptions about the flow.

    * **Command-Line Arguments:**  Based on the code alone, there are no *direct* command-line arguments being processed within this file. However, I can mention the `GODEBUG` environment variable mentioned in the comments as an indirect way to affect behavior.

    * **Common Mistakes:** I'll look at areas where users might easily make errors, especially when configuring TLS. For example, misconfiguring client authentication or misunderstanding `InsecureSkipVerify`.

6. **Structure the Answer:** I'll organize the information logically, following the structure of the request. I'll start with the overall functionality summary, then go into more detail about specific aspects, providing code examples and explanations where requested.

7. **Refine and Review:** I'll read through my answer, ensuring clarity, accuracy, and completeness. I'll double-check that I've addressed all parts of the request. I'll ensure the Go code examples are valid and easy to understand.

**Self-Correction Example During the Process:**

Initially, I might focus heavily on the constants and enums. Then, I'd realize the request also emphasizes the *flow* and *purpose*. I would then shift my focus to the `ConnectionState` and `Config` structs, as these are central to the TLS handshake and connection management. I would also ensure to explain the purpose of the callback functions, as they represent customization points. I'd also notice the comments about `GODEBUG` and incorporate that into the "command-line arguments" section (even though it's an environment variable). I'd also realize that directly interpreting command-line arguments isn't the primary function of this *specific* file, but configuration and the effect of environment variables are relevant.
这段Go语言代码是 `crypto/tls` 包的核心组成部分，定义了TLS协议中使用的各种常量、数据结构和类型。它主要负责以下功能：

**1. 定义了TLS协议的版本:**

*   声明了支持的TLS协议版本常量，例如 `VersionTLS10`, `VersionTLS11`, `VersionTLS12`, `VersionTLS13`。
*   提供了一个函数 `VersionName` 用于将版本号转换为易读的字符串表示，例如将 `VersionTLS13` 转换为 "TLS 1.3"。

**2. 定义了TLS记录层相关的常量:**

*   定义了最大明文数据长度 `maxPlaintext` 和最大密文数据长度 `maxCiphertext`。
*   定义了记录头长度 `recordHeaderLen`。
*   定义了最大握手消息大小 `maxHandshake` 和最大证书消息大小 `maxHandshakeCertificateMsg`。

**3. 定义了TLS记录类型和握手消息类型:**

*   使用 `recordType` 类型定义了TLS记录的类型，例如 `recordTypeChangeCipherSpec`, `recordTypeAlert`, `recordTypeHandshake`, `recordTypeApplicationData`。
*   定义了TLS握手消息的类型常量，例如 `typeHelloRequest`, `typeClientHello`, `typeServerHello`, `typeCertificate`, `typeFinished` 等。

**4. 定义了TLS压缩类型:**

*   目前只定义了 `compressionNone` 表示不支持压缩。

**5. 定义了TLS扩展类型:**

*   定义了各种TLS扩展的编号常量，例如 `extensionServerName` (SNI), `extensionSupportedCurves`, `extensionSignatureAlgorithms`, `extensionALPN`, `extensionPreSharedKey` 等。

**6. 定义了椭圆曲线和密钥交换机制相关的常量和类型:**

*   定义了 `CurveID` 类型表示椭圆曲线的ID，例如 `CurveP256`, `CurveP384`, `CurveP521`, `X25519`。
*   提供了一些辅助函数，例如 `isTLS13OnlyKeyExchange` 和 `isPQKeyExchange` 用于判断特定的曲线是否只在TLS 1.3中使用或是否是后量子密钥交换算法。
*   定义了 `keyShare` 结构体用于表示TLS 1.3的密钥共享信息。

**7. 定义了TLS 1.3 PSK相关的常量和类型:**

*   定义了PSK密钥交换模式常量 `pskModePlain` 和 `pskModeDHE`。
*   定义了 `pskIdentity` 结构体用于表示PSK身份信息。

**8. 定义了TLS证书状态类型:**

*   定义了 `statusTypeOCSP` 表示使用OCSP协议获取证书状态。

**9. 定义了证书类型:**

*   定义了 `certTypeRSASign` 和 `certTypeECDSASign` 表示证书的签名算法类型。

**10. 定义了签名算法相关的常量:**

*   定义了 `signaturePKCS1v15`, `signatureRSAPSS`, `signatureECDSA`, `signatureEd25519` 等常量用于内部表示签名算法。
*   定义了 `directSigning` 变量，用于表示Ed25519签名算法不需要预哈希。

**11. 定义了特殊用途的随机数:**

*   定义了 `helloRetryRequestRandom` 用于表示ServerHello消息是HelloRetryRequest。
*   定义了降级保护的随机数 `downgradeCanaryTLS12` 和 `downgradeCanaryTLS11`。

**12. 定义了 `ConnectionState` 结构体:**

*   `ConnectionState` 结构体用于存储TLS连接的状态信息，包括使用的TLS版本、握手是否完成、是否是会话恢复、使用的密码套件、协商的协议、服务器名称、对端证书、验证后的证书链、SCT、OCSP响应、TLSUnique通道绑定值、是否接受ECH等信息。
*   提供了一个方法 `ExportKeyingMaterial` 用于导出密钥材料。

**13. 定义了客户端认证类型 `ClientAuthType`:**

*   定义了客户端认证的策略，例如 `NoClientCert`, `RequestClientCert`, `RequireAnyClientCert`, `VerifyClientCertIfGiven`, `RequireAndVerifyClientCert`。
*   提供了一个辅助函数 `requiresClientCert` 用于判断是否需要客户端证书。

**14. 定义了客户端会话缓存接口 `ClientSessionCache`:**

*   定义了客户端会话缓存的接口，包含 `Get` 和 `Put` 方法，用于存储和检索会话信息，以便进行会话恢复。

**15. 定义了签名方案类型 `SignatureScheme`:**

*   定义了 TLS 支持的签名方案常量，例如 `PKCS1WithSHA256`, `PSSWithSHA256`, `ECDSAWithP256AndSHA256`, `Ed25519` 等。

**16. 定义了 `ClientHelloInfo` 结构体:**

*   `ClientHelloInfo` 结构体用于在服务器处理 `ClientHello` 消息时，向 `GetCertificate` 和 `GetConfigForClient` 回调函数传递客户端的信息，包括支持的密码套件、服务器名称、支持的曲线、支持的Point格式、支持的签名方案、支持的应用层协议、支持的TLS版本和扩展等。

**17. 定义了 `CertificateRequestInfo` 结构体:**

*   `CertificateRequestInfo` 结构体用于在客户端处理服务器发送的 `CertificateRequest` 消息时，向 `GetClientCertificate` 回调函数传递服务器的信息，包括可接受的CA列表和支持的签名方案等。

**18. 定义了重协商支持类型 `RenegotiationSupport`:**

*   定义了对TLS重协商的支持程度，例如 `RenegotiateNever`, `RenegotiateOnceAsClient`, `RenegotiateFreelyAsClient`。

**19. 定义了核心的配置结构体 `Config`:**

*   `Config` 结构体包含了配置TLS客户端或服务器所需的各种选项，例如随机数生成器、时间函数、证书链、获取证书的回调函数、客户端认证配置、根CA证书池、支持的应用层协议列表、服务器名称、是否跳过证书校验、支持的密码套件、是否禁用会话票据、会话票据密钥、客户端会话缓存、会话包装和解包函数、最小和最大TLS版本、支持的曲线偏好、是否禁用动态记录大小、重协商控制、密钥日志写入器、加密客户端 Hello 配置列表等。

**归纳一下它的功能：**

这段代码是 `crypto/tls` 包的基础，它定义了 TLS 协议中用到的各种常量、数据结构和类型，为实现 TLS 协议的握手、记录层处理、连接状态管理、会话管理和配置提供了必要的抽象和基础类型。它定义了协议的基本元素，使得 Go 语言可以实现安全可靠的网络通信。

由于你没有提供具体的代码片段，我只能根据文件路径 `go/src/crypto/tls/common.go` 来推断其功能。  如果提供具体的代码片段，我可以给出更精确的分析。

**关于 Go 语言功能的实现：**

这段代码主要使用了 Go 语言的以下功能：

*   **常量 (const):** 用于定义各种协议相关的固定值，例如版本号、消息类型、扩展编号等。
*   **类型定义 (type):** 用于为基本类型创建别名，提高代码可读性，例如 `recordType`, `CurveID`, `SignatureScheme`。
*   **结构体 (struct):** 用于组织相关的数据，例如 `ConnectionState`, `ClientHelloInfo`, `Config`。
*   **接口 (interface):** 用于定义行为规范，例如 `ClientSessionCache`。
*   **函数 (func):** 用于实现特定的逻辑，例如 `VersionName`, `requiresClientCert`, `ExportKeyingMaterial`。
*   **导入 (import):** 导入其他标准库或内部库的包，例如 `crypto`, `net`, `time`。

**代码推理举例 (假设分析 `VersionName` 函数):**

```go
// VersionName returns the name for the provided TLS version number
// (e.g. "TLS 1.3"), or a fallback representation of the value if the
// version is not implemented by this package.
func VersionName(version uint16) string {
	switch version {
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}
```

**假设输入:** `version = 0x0304`

**代码推理:**  `switch` 语句会匹配 `case VersionTLS13:`, 因为 `VersionTLS13` 的常量值是 `0x0304`。因此，函数会返回字符串 `"TLS 1.3"`。

**假设输入:** `version = 0x1234`

**代码推理:**  `switch` 语句中没有匹配的 `case`，因此会执行 `default:` 分支。函数会使用 `fmt.Sprintf` 格式化输出，将 `0x1234` 转换为 "0x1234" 字符串并返回。

**输出 (对应以上输入):**

*   输入 `0x0304` -> 输出 `"TLS 1.3"`
*   输入 `0x1234` -> 输出 `"0x1234"`

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。命令行参数的处理通常发生在程序的入口点 `main` 函数中。但是，`crypto/tls` 包的配置，特别是 `Config` 结构体中的字段，可能会受到命令行参数的影响。例如，你可能会通过命令行参数指定证书文件的路径，然后在代码中读取这些文件并配置到 `Config.Certificates` 中。

**易犯错的点举例：**

*   **不理解 `InsecureSkipVerify` 的含义:**  开发者可能会为了方便测试而将 `Config.InsecureSkipVerify` 设置为 `true`，但这会禁用对服务器证书的校验，使得连接容易受到中间人攻击。在生产环境中必须谨慎使用。

    ```go
    // 错误示例，在生产环境禁用证书校验
    config := &tls.Config{
        InsecureSkipVerify: true,
    }
    ```

*   **错误配置 `ClientAuth`:**  服务端可能错误地配置了 `ClientAuth`，例如设置为 `RequireAndVerifyClientCert` 但没有正确配置 `ClientCAs`，导致客户端无法连接。

    ```go
    // 错误示例，需要客户端证书但未配置可信CA
    config := &tls.Config{
        ClientAuth: tls.RequireAndVerifyClientCert,
        // ClientCAs 未设置
    }
    ```

*   **混淆 `Certificates` 和 `GetCertificate`:**  开发者可能同时设置了 `Config.Certificates` 和 `Config.GetCertificate`，但没有理解它们的调用时机和优先级，导致证书选择出现意外。通常，如果需要动态选择证书，应该使用 `GetCertificate`。

**由于这是第1部分，其主要功能是定义了TLS协议的基础元素，为后续的握手、加密、数据传输等功能的实现提供了必要的数据结构和常量。**

Prompt: 
```
这是路径为go/src/crypto/tls/common.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"container/list"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls/internal/fips140tls"
	"crypto/x509"
	"errors"
	"fmt"
	"internal/godebug"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
	_ "unsafe" // for linkname
)

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	// Deprecated: SSLv3 is cryptographically broken, and is no longer
	// supported by this package. See golang.org/issue/32716.
	VersionSSL30 = 0x0300
)

// VersionName returns the name for the provided TLS version number
// (e.g. "TLS 1.3"), or a fallback representation of the value if the
// version is not implemented by this package.
func VersionName(version uint16) string {
	switch version {
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}

const (
	maxPlaintext               = 16384        // maximum plaintext payload length
	maxCiphertext              = 16384 + 2048 // maximum ciphertext payload length
	maxCiphertextTLS13         = 16384 + 256  // maximum ciphertext length in TLS 1.3
	recordHeaderLen            = 5            // record header length
	maxHandshake               = 65536        // maximum handshake we support (protocol max is 16 MB)
	maxHandshakeCertificateMsg = 262144       // maximum certificate message size (256 KiB)
	maxUselessRecords          = 16           // maximum number of consecutive non-advancing records
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
	typeMessageHash         uint8 = 254 // synthetic message
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionExtendedMasterSecret    uint16 = 23
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionQUICTransportParameters uint16 = 57
	extensionRenegotiationInfo       uint16 = 0xff01
	extensionECHOuterExtensions      uint16 = 0xfd00
	extensionEncryptedClientHello    uint16 = 0xfe0d
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// CurveID is the type of a TLS identifier for a key exchange mechanism. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
//
// In TLS 1.2, this registry used to support only elliptic curves. In TLS 1.3,
// it was extended to other groups and renamed NamedGroup. See RFC 8446, Section
// 4.2.7. It was then also extended to other mechanisms, such as hybrid
// post-quantum KEMs.
type CurveID uint16

const (
	CurveP256      CurveID = 23
	CurveP384      CurveID = 24
	CurveP521      CurveID = 25
	X25519         CurveID = 29
	X25519MLKEM768 CurveID = 4588
)

func isTLS13OnlyKeyExchange(curve CurveID) bool {
	return curve == X25519MLKEM768
}

func isPQKeyExchange(curve CurveID) bool {
	return curve == X25519MLKEM768
}

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type keyShare struct {
	group CurveID
	data  []byte
}

// TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
const (
	pskModePlain uint8 = 0
	pskModeDHE   uint8 = 1
)

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type pskIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}

// TLS Elliptic Curve Point Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
	pointFormatUncompressed uint8 = 0
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// Certificate types (for certificateRequestMsg)
const (
	certTypeRSASign   = 1
	certTypeECDSASign = 64 // ECDSA or EdDSA keys, see RFC 8422, Section 3.
)

// Signature algorithms (for internal signaling use). Starting at 225 to avoid overlap with
// TLS 1.2 codepoints (RFC 5246, Appendix A.4.1), with which these have nothing to do.
const (
	signaturePKCS1v15 uint8 = iota + 225
	signatureRSAPSS
	signatureECDSA
	signatureEd25519
)

// directSigning is a standard Hash value that signals that no pre-hashing
// should be performed, and that the input should be signed directly. It is the
// hash function associated with the Ed25519 signature scheme.
var directSigning crypto.Hash = 0

// helloRetryRequestRandom is set as the Random value of a ServerHello
// to signal that the message is actually a HelloRetryRequest.
var helloRetryRequestRandom = []byte{ // See RFC 8446, Section 4.1.3.
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

const (
	// downgradeCanaryTLS12 or downgradeCanaryTLS11 is embedded in the server
	// random as a downgrade protection if the server would be capable of
	// negotiating a higher version. See RFC 8446, Section 4.1.3.
	downgradeCanaryTLS12 = "DOWNGRD\x01"
	downgradeCanaryTLS11 = "DOWNGRD\x00"
)

// testingOnlyForceDowngradeCanary is set in tests to force the server side to
// include downgrade canaries even if it's using its highers supported version.
var testingOnlyForceDowngradeCanary bool

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	// Version is the TLS version used by the connection (e.g. VersionTLS12).
	Version uint16

	// HandshakeComplete is true if the handshake has concluded.
	HandshakeComplete bool

	// DidResume is true if this connection was successfully resumed from a
	// previous session with a session ticket or similar mechanism.
	DidResume bool

	// CipherSuite is the cipher suite negotiated for the connection (e.g.
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256).
	CipherSuite uint16

	// NegotiatedProtocol is the application protocol negotiated with ALPN.
	NegotiatedProtocol string

	// NegotiatedProtocolIsMutual used to indicate a mutual NPN negotiation.
	//
	// Deprecated: this value is always true.
	NegotiatedProtocolIsMutual bool

	// ServerName is the value of the Server Name Indication extension sent by
	// the client. It's available both on the server and on the client side.
	ServerName string

	// PeerCertificates are the parsed certificates sent by the peer, in the
	// order in which they were sent. The first element is the leaf certificate
	// that the connection is verified against.
	//
	// On the client side, it can't be empty. On the server side, it can be
	// empty if Config.ClientAuth is not RequireAnyClientCert or
	// RequireAndVerifyClientCert.
	//
	// PeerCertificates and its contents should not be modified.
	PeerCertificates []*x509.Certificate

	// VerifiedChains is a list of one or more chains where the first element is
	// PeerCertificates[0] and the last element is from Config.RootCAs (on the
	// client side) or Config.ClientCAs (on the server side).
	//
	// On the client side, it's set if Config.InsecureSkipVerify is false. On
	// the server side, it's set if Config.ClientAuth is VerifyClientCertIfGiven
	// (and the peer provided a certificate) or RequireAndVerifyClientCert.
	//
	// VerifiedChains and its contents should not be modified.
	VerifiedChains [][]*x509.Certificate

	// SignedCertificateTimestamps is a list of SCTs provided by the peer
	// through the TLS handshake for the leaf certificate, if any.
	SignedCertificateTimestamps [][]byte

	// OCSPResponse is a stapled Online Certificate Status Protocol (OCSP)
	// response provided by the peer for the leaf certificate, if any.
	OCSPResponse []byte

	// TLSUnique contains the "tls-unique" channel binding value (see RFC 5929,
	// Section 3). This value will be nil for TLS 1.3 connections and for
	// resumed connections that don't support Extended Master Secret (RFC 7627).
	TLSUnique []byte

	// ECHAccepted indicates if Encrypted Client Hello was offered by the client
	// and accepted by the server. Currently, ECH is supported only on the
	// client side.
	ECHAccepted bool

	// ekm is a closure exposed via ExportKeyingMaterial.
	ekm func(label string, context []byte, length int) ([]byte, error)

	// testingOnlyDidHRR is true if a HelloRetryRequest was sent/received.
	testingOnlyDidHRR bool

	// testingOnlyCurveID is the selected CurveID, or zero if an RSA exchanges
	// is performed.
	testingOnlyCurveID CurveID
}

// ExportKeyingMaterial returns length bytes of exported key material in a new
// slice as defined in RFC 5705. If context is nil, it is not used as part of
// the seed. If the connection was set to allow renegotiation via
// Config.Renegotiation, or if the connections supports neither TLS 1.3 nor
// Extended Master Secret, this function will return an error.
//
// Exporting key material without Extended Master Secret or TLS 1.3 was disabled
// in Go 1.22 due to security issues (see the Security Considerations sections
// of RFC 5705 and RFC 7627), but can be re-enabled with the GODEBUG setting
// tlsunsafeekm=1.
func (cs *ConnectionState) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	return cs.ekm(label, context, length)
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

const (
	// NoClientCert indicates that no client certificate should be requested
	// during the handshake, and if any certificates are sent they will not
	// be verified.
	NoClientCert ClientAuthType = iota
	// RequestClientCert indicates that a client certificate should be requested
	// during the handshake, but does not require that the client send any
	// certificates.
	RequestClientCert
	// RequireAnyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one certificate is required to be
	// sent by the client, but that certificate is not required to be valid.
	RequireAnyClientCert
	// VerifyClientCertIfGiven indicates that a client certificate should be requested
	// during the handshake, but does not require that the client sends a
	// certificate. If the client does send a certificate it is required to be
	// valid.
	VerifyClientCertIfGiven
	// RequireAndVerifyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one valid certificate is required
	// to be sent by the client.
	RequireAndVerifyClientCert
)

// requiresClientCert reports whether the ClientAuthType requires a client
// certificate to be provided.
func requiresClientCert(c ClientAuthType) bool {
	switch c {
	case RequireAnyClientCert, RequireAndVerifyClientCert:
		return true
	default:
		return false
	}
}

// ClientSessionCache is a cache of ClientSessionState objects that can be used
// by a client to resume a TLS session with a given server. ClientSessionCache
// implementations should expect to be called concurrently from different
// goroutines. Up to TLS 1.2, only ticket-based resumption is supported, not
// SessionID-based resumption. In TLS 1.3 they were merged into PSK modes, which
// are supported via this interface.
type ClientSessionCache interface {
	// Get searches for a ClientSessionState associated with the given key.
	// On return, ok is true if one was found.
	Get(sessionKey string) (session *ClientSessionState, ok bool)

	// Put adds the ClientSessionState to the cache with the given key. It might
	// get called multiple times in a connection if a TLS 1.3 server provides
	// more than one session ticket. If called with a nil *ClientSessionState,
	// it should remove the cache entry.
	Put(sessionKey string, cs *ClientSessionState)
}

//go:generate stringer -linecomment -type=SignatureScheme,CurveID,ClientAuthType -output=common_string.go

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
type SignatureScheme uint16

const (
	// RSASSA-PKCS1-v1_5 algorithms.
	PKCS1WithSHA256 SignatureScheme = 0x0401
	PKCS1WithSHA384 SignatureScheme = 0x0501
	PKCS1WithSHA512 SignatureScheme = 0x0601

	// RSASSA-PSS algorithms with public key OID rsaEncryption.
	PSSWithSHA256 SignatureScheme = 0x0804
	PSSWithSHA384 SignatureScheme = 0x0805
	PSSWithSHA512 SignatureScheme = 0x0806

	// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603

	// EdDSA algorithms.
	Ed25519 SignatureScheme = 0x0807

	// Legacy signature and hash algorithms for TLS 1.2.
	PKCS1WithSHA1 SignatureScheme = 0x0201
	ECDSAWithSHA1 SignatureScheme = 0x0203
)

// ClientHelloInfo contains information from a ClientHello message in order to
// guide application logic in the GetCertificate and GetConfigForClient callbacks.
type ClientHelloInfo struct {
	// CipherSuites lists the CipherSuites supported by the client (e.g.
	// TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).
	CipherSuites []uint16

	// ServerName indicates the name of the server requested by the client
	// in order to support virtual hosting. ServerName is only set if the
	// client is using SNI (see RFC 4366, Section 3.1).
	ServerName string

	// SupportedCurves lists the key exchange mechanisms supported by the
	// client. It was renamed to "supported groups" in TLS 1.3, see RFC 8446,
	// Section 4.2.7 and [CurveID].
	//
	// SupportedCurves may be nil in TLS 1.2 and lower if the Supported Elliptic
	// Curves Extension is not being used (see RFC 4492, Section 5.1.1).
	SupportedCurves []CurveID

	// SupportedPoints lists the point formats supported by the client.
	// SupportedPoints is set only if the Supported Point Formats Extension
	// is being used (see RFC 4492, Section 5.1.2).
	SupportedPoints []uint8

	// SignatureSchemes lists the signature and hash schemes that the client
	// is willing to verify. SignatureSchemes is set only if the Signature
	// Algorithms Extension is being used (see RFC 5246, Section 7.4.1.4.1).
	SignatureSchemes []SignatureScheme

	// SupportedProtos lists the application protocols supported by the client.
	// SupportedProtos is set only if the Application-Layer Protocol
	// Negotiation Extension is being used (see RFC 7301, Section 3.1).
	//
	// Servers can select a protocol by setting Config.NextProtos in a
	// GetConfigForClient return value.
	SupportedProtos []string

	// SupportedVersions lists the TLS versions supported by the client.
	// For TLS versions less than 1.3, this is extrapolated from the max
	// version advertised by the client, so values other than the greatest
	// might be rejected if used.
	SupportedVersions []uint16

	// Extensions lists the IDs of the extensions presented by the client
	// in the ClientHello.
	Extensions []uint16

	// Conn is the underlying net.Conn for the connection. Do not read
	// from, or write to, this connection; that will cause the TLS
	// connection to fail.
	Conn net.Conn

	// config is embedded by the GetCertificate or GetConfigForClient caller,
	// for use with SupportsCertificate.
	config *Config

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// Context returns the context of the handshake that is in progress.
// This context is a child of the context passed to HandshakeContext,
// if any, and is canceled when the handshake concludes.
func (c *ClientHelloInfo) Context() context.Context {
	return c.ctx
}

// CertificateRequestInfo contains information from a server's
// CertificateRequest message, which is used to demand a certificate and proof
// of control from a client.
type CertificateRequestInfo struct {
	// AcceptableCAs contains zero or more, DER-encoded, X.501
	// Distinguished Names. These are the names of root or intermediate CAs
	// that the server wishes the returned certificate to be signed by. An
	// empty slice indicates that the server has no preference.
	AcceptableCAs [][]byte

	// SignatureSchemes lists the signature schemes that the server is
	// willing to verify.
	SignatureSchemes []SignatureScheme

	// Version is the TLS version that was negotiated for this connection.
	Version uint16

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// Context returns the context of the handshake that is in progress.
// This context is a child of the context passed to HandshakeContext,
// if any, and is canceled when the handshake concludes.
func (c *CertificateRequestInfo) Context() context.Context {
	return c.ctx
}

// RenegotiationSupport enumerates the different levels of support for TLS
// renegotiation. TLS renegotiation is the act of performing subsequent
// handshakes on a connection after the first. This significantly complicates
// the state machine and has been the source of numerous, subtle security
// issues. Initiating a renegotiation is not supported, but support for
// accepting renegotiation requests may be enabled.
//
// Even when enabled, the server may not change its identity between handshakes
// (i.e. the leaf certificate must be the same). Additionally, concurrent
// handshake and application data flow is not permitted so renegotiation can
// only be used with protocols that synchronise with the renegotiation, such as
// HTTPS.
//
// Renegotiation is not defined in TLS 1.3.
type RenegotiationSupport int

const (
	// RenegotiateNever disables renegotiation.
	RenegotiateNever RenegotiationSupport = iota

	// RenegotiateOnceAsClient allows a remote server to request
	// renegotiation once per connection.
	RenegotiateOnceAsClient

	// RenegotiateFreelyAsClient allows a remote server to repeatedly
	// request renegotiation.
	RenegotiateFreelyAsClient
)

// A Config structure is used to configure a TLS client or server.
// After one has been passed to a TLS function it must not be
// modified. A Config may be reused; the tls package will also not
// modify it.
type Config struct {
	// Rand provides the source of entropy for nonces and RSA blinding.
	// If Rand is nil, TLS uses the cryptographic random reader in package
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	Rand io.Reader

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time

	// Certificates contains one or more certificate chains to present to the
	// other side of the connection. The first certificate compatible with the
	// peer's requirements is selected automatically.
	//
	// Server configurations must set one of Certificates, GetCertificate or
	// GetConfigForClient. Clients doing client-authentication may set either
	// Certificates or GetClientCertificate.
	//
	// Note: if there are multiple Certificates, and they don't have the
	// optional field Leaf set, certificate selection will incur a significant
	// per-handshake performance cost.
	Certificates []Certificate

	// NameToCertificate maps from a certificate name to an element of
	// Certificates. Note that a certificate name can be of the form
	// '*.example.com' and so doesn't have to be a domain name as such.
	//
	// Deprecated: NameToCertificate only allows associating a single
	// certificate with a given name. Leave this field nil to let the library
	// select the first compatible chain from Certificates.
	NameToCertificate map[string]*Certificate

	// GetCertificate returns a Certificate based on the given
	// ClientHelloInfo. It will only be called if the client supplies SNI
	// information or if Certificates is empty.
	//
	// If GetCertificate is nil or returns nil, then the certificate is
	// retrieved from NameToCertificate. If NameToCertificate is nil, the
	// best element of Certificates will be used.
	//
	// Once a Certificate is returned it should not be modified.
	GetCertificate func(*ClientHelloInfo) (*Certificate, error)

	// GetClientCertificate, if not nil, is called when a server requests a
	// certificate from a client. If set, the contents of Certificates will
	// be ignored.
	//
	// If GetClientCertificate returns an error, the handshake will be
	// aborted and that error will be returned. Otherwise
	// GetClientCertificate must return a non-nil Certificate. If
	// Certificate.Certificate is empty then no certificate will be sent to
	// the server. If this is unacceptable to the server then it may abort
	// the handshake.
	//
	// GetClientCertificate may be called multiple times for the same
	// connection if renegotiation occurs or if TLS 1.3 is in use.
	//
	// Once a Certificate is returned it should not be modified.
	GetClientCertificate func(*CertificateRequestInfo) (*Certificate, error)

	// GetConfigForClient, if not nil, is called after a ClientHello is
	// received from a client. It may return a non-nil Config in order to
	// change the Config that will be used to handle this connection. If
	// the returned Config is nil, the original Config will be used. The
	// Config returned by this callback may not be subsequently modified.
	//
	// If GetConfigForClient is nil, the Config passed to Server() will be
	// used for all connections.
	//
	// If SessionTicketKey was explicitly set on the returned Config, or if
	// SetSessionTicketKeys was called on the returned Config, those keys will
	// be used. Otherwise, the original Config keys will be used (and possibly
	// rotated if they are automatically managed).
	GetConfigForClient func(*ClientHelloInfo) (*Config, error)

	// VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a TLS client or server. It
	// receives the raw ASN.1 certificates provided by the peer and also
	// any verified chains that normal processing found. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled (on the
	// client when InsecureSkipVerify is set, or on a server when ClientAuth is
	// RequestClientCert or RequireAnyClientCert), then this callback will be
	// considered but the verifiedChains argument will always be nil. When
	// ClientAuth is NoClientCert, this callback is not called on the server.
	// rawCerts may be empty on the server if ClientAuth is RequestClientCert or
	// VerifyClientCertIfGiven.
	//
	// This callback is not invoked on resumed connections, as certificates are
	// not re-verified on resumption.
	//
	// verifiedChains and its contents should not be modified.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection, if not nil, is called after normal certificate
	// verification and after VerifyPeerCertificate by either a TLS client
	// or server. If it returns a non-nil error, the handshake is aborted
	// and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. This callback will run for all connections,
	// including resumptions, regardless of InsecureSkipVerify or ClientAuth
	// settings.
	VerifyConnection func(ConnectionState) error

	// RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool

	// NextProtos is a list of supported application level protocols, in
	// order of preference. If both peers support ALPN, the selected
	// protocol will be one from this list, and the connection will fail
	// if there is no mutually supported protocol. If NextProtos is empty
	// or the peer doesn't support ALPN, the connection will succeed and
	// ConnectionState.NegotiatedProtocol will be empty.
	NextProtos []string

	// ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given. It is also included
	// in the client's handshake to support virtual hosting unless it is
	// an IP address.
	ServerName string

	// ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	ClientAuth ClientAuthType

	// ClientCAs defines the set of root certificate authorities
	// that servers use if required to verify a client certificate
	// by the policy in ClientAuth.
	ClientCAs *x509.CertPool

	// InsecureSkipVerify controls whether a client verifies the server's
	// certificate chain and host name. If InsecureSkipVerify is true, crypto/tls
	// accepts any certificate presented by the server and any host name in that
	// certificate. In this mode, TLS is susceptible to machine-in-the-middle
	// attacks unless custom verification is used. This should be used only for
	// testing or in combination with VerifyConnection or VerifyPeerCertificate.
	InsecureSkipVerify bool

	// CipherSuites is a list of enabled TLS 1.0–1.2 cipher suites. The order of
	// the list is ignored. Note that TLS 1.3 ciphersuites are not configurable.
	//
	// If CipherSuites is nil, a safe default list is used. The default cipher
	// suites might change over time. In Go 1.22 RSA key exchange based cipher
	// suites were removed from the default list, but can be re-added with the
	// GODEBUG setting tlsrsakex=1. In Go 1.23 3DES cipher suites were removed
	// from the default list, but can be re-added with the GODEBUG setting
	// tls3des=1.
	CipherSuites []uint16

	// PreferServerCipherSuites is a legacy field and has no effect.
	//
	// It used to control whether the server would follow the client's or the
	// server's preference. Servers now select the best mutually supported
	// cipher suite based on logic that takes into account inferred client
	// hardware, server hardware, and security.
	//
	// Deprecated: PreferServerCipherSuites is ignored.
	PreferServerCipherSuites bool

	// SessionTicketsDisabled may be set to true to disable session ticket and
	// PSK (resumption) support. Note that on clients, session ticket support is
	// also disabled if ClientSessionCache is nil.
	SessionTicketsDisabled bool

	// SessionTicketKey is used by TLS servers to provide session resumption.
	// See RFC 5077 and the PSK mode of RFC 8446. If zero, it will be filled
	// with random data before the first server handshake.
	//
	// Deprecated: if this field is left at zero, session ticket keys will be
	// automatically rotated every day and dropped after seven days. For
	// customizing the rotation schedule or synchronizing servers that are
	// terminating connections for the same host, use SetSessionTicketKeys.
	SessionTicketKey [32]byte

	// ClientSessionCache is a cache of ClientSessionState entries for TLS
	// session resumption. It is only used by clients.
	ClientSessionCache ClientSessionCache

	// UnwrapSession is called on the server to turn a ticket/identity
	// previously produced by [WrapSession] into a usable session.
	//
	// UnwrapSession will usually either decrypt a session state in the ticket
	// (for example with [Config.EncryptTicket]), or use the ticket as a handle
	// to recover a previously stored state. It must use [ParseSessionState] to
	// deserialize the session state.
	//
	// If UnwrapSession returns an error, the connection is terminated. If it
	// returns (nil, nil), the session is ignored. crypto/tls may still choose
	// not to resume the returned session.
	UnwrapSession func(identity []byte, cs ConnectionState) (*SessionState, error)

	// WrapSession is called on the server to produce a session ticket/identity.
	//
	// WrapSession must serialize the session state with [SessionState.Bytes].
	// It may then encrypt the serialized state (for example with
	// [Config.DecryptTicket]) and use it as the ticket, or store the state and
	// return a handle for it.
	//
	// If WrapSession returns an error, the connection is terminated.
	//
	// Warning: the return value will be exposed on the wire and to clients in
	// plaintext. The application is in charge of encrypting and authenticating
	// it (and rotating keys) or returning high-entropy identifiers. Failing to
	// do so correctly can compromise current, previous, and future connections
	// depending on the protocol version.
	WrapSession func(ConnectionState, *SessionState) ([]byte, error)

	// MinVersion contains the minimum TLS version that is acceptable.
	//
	// By default, TLS 1.2 is currently used as the minimum. TLS 1.0 is the
	// minimum supported by this package.
	//
	// The server-side default can be reverted to TLS 1.0 by including the value
	// "tls10server=1" in the GODEBUG environment variable.
	MinVersion uint16

	// MaxVersion contains the maximum TLS version that is acceptable.
	//
	// By default, the maximum version supported by this package is used,
	// which is currently TLS 1.3.
	MaxVersion uint16

	// CurvePreferences contains a set of supported key exchange mechanisms.
	// The name refers to elliptic curves for legacy reasons, see [CurveID].
	// The order of the list is ignored, and key exchange mechanisms are chosen
	// from this list using an internal preference order. If empty, the default
	// will be used.
	//
	// From Go 1.24, the default includes the [X25519MLKEM768] hybrid
	// post-quantum key exchange. To disable it, set CurvePreferences explicitly
	// or use the GODEBUG=tlsmlkem=0 environment variable.
	CurvePreferences []CurveID

	// DynamicRecordSizingDisabled disables adaptive sizing of TLS records.
	// When true, the largest possible TLS record size is always used. When
	// false, the size of TLS records may be adjusted in an attempt to
	// improve latency.
	DynamicRecordSizingDisabled bool

	// Renegotiation controls what types of renegotiation are supported.
	// The default, none, is correct for the vast majority of applications.
	Renegotiation RenegotiationSupport

	// KeyLogWriter optionally specifies a destination for TLS master secrets
	// in NSS key log format that can be used to allow external programs
	// such as Wireshark to decrypt TLS connections.
	// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
	// Use of KeyLogWriter compromises security and should only be
	// used for debugging.
	KeyLogWriter io.Writer

	// EncryptedClientHelloConfigList is a serialized ECHConfigList. If
	// provided, clients will attempt to connect to servers using Encrypted
	// Client Hello (ECH) using one of the provided ECHConfigs.
	//
	// Servers do not use this field. In order to configure ECH for servers, see
	// the EncryptedClientHelloKeys field.
	//
	// If the list contains no valid ECH configs, the handshake will fail
	// and return an error.
	//
	// If EncryptedClientHelloConfigList is set, MinVersion, if set, must
	// be VersionTLS13.
	//
	// When EncryptedClientHelloConfigList is set, the handshake will only
	// succeed if ECH is successfully negotiated. If the server rejects ECH,
	// an ECHRejectionError error will be returned, which may contain a new
	// ECHConfigList that the server suggests using.
	//
	// How this field is parsed may change in future Go versions, if the
	// encoding d
"""




```