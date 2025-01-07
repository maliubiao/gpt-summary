Response:
The user has provided a snippet of Go code from `go/src/crypto/tls/handshake_client.go` and asked for a summary of its functionality.

Here's a breakdown of the thought process to generate the answer:

1. **Understand the context:** The file name `handshake_client.go` strongly suggests this code handles the client-side of the TLS handshake process. The `package tls` confirms this.

2. **Identify key data structures:**  Scan the code for prominent types. `clientHandshakeState`, `Conn`, and various message types (`clientHelloMsg`, `serverHelloMsg`, etc.) stand out. These will be central to the functionality.

3. **Trace the main functions:** Look for functions that appear to be entry points or high-level control flow. `makeClientHello` and `clientHandshake` are immediately apparent.

4. **Analyze `makeClientHello`:**
    * Note the purpose: creating the `clientHelloMsg`.
    * Identify the various fields being set: version, cipher suites, extensions (server name, supported curves, ALPN, etc.).
    * Observe the TLS 1.3 specific logic involving key shares and the potential inclusion of ML-KEM.
    * Notice the handling of Encrypted Client Hello (ECH).
    * Recognize that this function prepares the initial handshake message from the client.

5. **Analyze `clientHandshake`:**
    * Recognize this as the core function driving the client-side handshake.
    * See the call to `makeClientHello`.
    * Understand the session resumption logic (`loadSession`).
    * Observe the handling of ECH, splitting the hello message into inner and outer parts.
    * Identify the interaction with the server (reading `serverHelloMsg`).
    * Distinguish between TLS 1.3 and earlier versions based on `c.vers`.
    * Note the creation of `clientHandshakeState` or `clientHandshakeStateTLS13` based on the negotiated version.
    * Infer that the subsequent handshake steps are handled by the `handshake` method of these state structs.

6. **Analyze the `clientHandshakeState` and `clientHandshakeStateTLS13` structs:** While the provided snippet doesn't fully detail these, note their purpose in managing the handshake state. The presence of `finishedHash`, `masterSecret`, and `session` in `clientHandshakeState` suggests they manage cryptographic context and session information.

7. **Identify key concepts:** As you analyze the code, note the underlying TLS concepts being implemented:
    * Client Hello message construction.
    * Cipher suite negotiation.
    * Session resumption (tickets and PSK).
    * TLS versions (especially TLS 1.3).
    * Extensions (SNI, ALPN, ECH, etc.).
    * Key exchange (through the presence of `keySharePrivateKeys`).

8. **Synthesize the functionality:** Combine the observations from the previous steps into a concise summary of the code's role. Emphasize the client-side handshake process and the key steps involved.

9. **Address the "go语言功能的实现" question:**  The core Go language features used here are:
    * Structs for data organization (`clientHandshakeState`, message types).
    * Methods on structs to encapsulate behavior.
    * Interfaces for cryptography (`crypto.Signer`, `hash.Hash`).
    * Standard library packages (`bytes`, `context`, `errors`, `io`, `net`).

10. **Provide a code example (as requested):** Create a simple example demonstrating how a `tls.Config` is used to initiate a TLS connection as a client. Include setting `ServerName` and potentially `InsecureSkipVerify` to illustrate the check in `makeClientHello`.

11. **Consider error-prone areas:**  Think about common mistakes developers might make when using this functionality, such as forgetting to set `ServerName` or using `InsecureSkipVerify` in production.

12. **Structure the answer:** Organize the information logically, using headings and bullet points for clarity. Follow the order of the user's questions.

13. **Review and refine:** Read through the generated answer to ensure accuracy, completeness, and clarity. Correct any errors or omissions. For example, initially, I might have overlooked mentioning the `loadSession` function, but a closer look at `clientHandshake` reveals its importance. Similarly, emphasizing the different handling for TLS 1.3 and earlier versions is crucial.
这段Go语言代码是 `crypto/tls` 包中处理 TLS 客户端握手过程的一部分。它主要负责生成并发送客户端的 `ClientHello` 消息，以及处理一些与会话恢复相关的逻辑。

**功能归纳:**

这段代码的主要功能可以归纳为：

1. **构建和发送 ClientHello 消息:**  它根据 `tls.Config` 中的配置信息，创建一个 `clientHelloMsg` 结构体，并将其写入网络连接。`ClientHello` 消息包含了客户端支持的 TLS 版本、密码套件、扩展等信息，用于与服务器协商加密参数。
2. **处理会话恢复:**  代码尝试从客户端会话缓存中加载之前的会话信息（session ticket 或 session ID）。如果找到有效的会话，它会将相关信息添加到 `ClientHello` 消息中，尝试与服务器恢复之前的会话。这可以缩短握手时间并提高性能。
3. **支持多种 TLS 协议版本和扩展:**  代码考虑了不同 TLS 版本（包括 TLS 1.3）的差异，并处理了各种 TLS 扩展，如 SNI (Server Name Indication)、ALPN (Application-Layer Protocol Negotiation)、安全重协商、加密客户端Hello (ECH) 等。
4. **密钥共享:** 对于 TLS 1.3，代码负责生成和包含密钥共享信息 (`keyShare`)，用于建立共享密钥。
5. **处理加密客户端Hello (ECH):** 如果配置了 ECH，代码会将 `ClientHello` 分成内部和外部两部分，并使用服务器的公钥加密内部的 `ClientHello`。
6. **QUIC 集成:**  代码也考虑了 QUIC 协议的集成，可以添加 QUIC 传输参数到 `ClientHello` 消息中。

**它是什么go语言功能的实现，请用go代码举例说明:**

这段代码主要实现了 TLS 协议客户端握手的第一步，即发送 `ClientHello` 消息。这涉及到以下 Go 语言功能：

* **结构体 (Structs):**  使用 `clientHandshakeState` 和 `clientHelloMsg` 等结构体来组织握手状态和消息数据。
* **方法 (Methods):**  为 `Conn` 和 `clientHandshakeState` 定义方法，如 `makeClientHello` 和 `clientHandshake`，封装了握手过程的逻辑。
* **切片 (Slices):** 使用切片来存储支持的密码套件、协议版本、扩展等信息。
* **错误处理 (Error Handling):** 使用 `error` 类型来处理握手过程中可能出现的各种错误。
* **随机数生成:** 使用 `crypto/rand` 包生成随机数，用于 `ClientHello` 消息的随机数部分和会话 ID。
* **网络操作:**  通过 `Conn` 类型进行网络读写操作，发送 `ClientHello` 消息。
* **条件语句 (if/else):** 根据配置和协议版本执行不同的握手逻辑。

**Go 代码举例说明:**

以下代码示例展示了如何使用 `crypto/tls` 包创建一个 TLS 客户端连接，这会触发 `handshake_client.go` 中的代码执行：

```go
package main

import (
	"crypto/tls"
	"fmt"
	"net"
)

func main() {
	conn, err := tls.Dial("tcp", "example.com:443", &tls.Config{
		ServerName: "example.com", // 必须设置 ServerName
		// InsecureSkipVerify: true, // 在生产环境中不要使用
	})
	if err != nil {
		fmt.Println("连接失败:", err)
		return
	}
	defer conn.Close()

	fmt.Println("TLS 连接已建立")
	fmt.Println("协商的协议版本:", conn.ConnectionState().Version)
	fmt.Println("协商的密码套件:", conn.ConnectionState().CipherSuite)
}
```

**假设的输入与输出:**

**假设输入:**

* `tls.Config`:  `ServerName` 设置为 "example.com"。
* 网络连接正常。

**预期输出:**

* 如果握手成功，程序会打印 "TLS 连接已建立"。
* 可能会打印协商的协议版本和密码套件。
* 如果握手失败，程序会打印 "连接失败:" 和具体的错误信息。

**代码推理:**

1. `tls.Dial` 函数会被调用，并创建一个 `tls.Conn` 实例。
2. 在 `tls.Dial` 内部，会调用 `clientHandshake` 方法。
3. `makeClientHello` 方法会被调用，根据 `tls.Config` 生成 `clientHelloMsg`。 由于 `ServerName` 设置了，不会返回关于 `ServerName` 或 `InsecureSkipVerify` 的错误。
4. 如果客户端有可用的会话缓存，`loadSession` 可能会尝试加载之前的会话信息。
5. `clientHelloMsg` 会被写入网络连接发送给服务器。
6. 服务器会返回 `ServerHello` 消息，后续的握手过程会继续。

**使用者易犯错的点:**

一个常见的错误是在创建 `tls.Config` 时 **忘记设置 `ServerName`**，或者在不需要进行主机名校验的情况下错误地设置了 `InsecureSkipVerify` 为 `true`。

**示例:**

```go
package main

import (
	"crypto/tls"
	"fmt"
	"net"
)

func main() {
	// 错误示例 1: 忘记设置 ServerName
	conn1, err1 := tls.Dial("tcp", "example.com:443", &tls.Config{})
	if err1 != nil {
		fmt.Println("连接失败 (错误 1):", err1) // 会输出 "tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config"
	} else {
		conn1.Close()
	}

	// 错误示例 2: 在生产环境中使用 InsecureSkipVerify
	conn2, err2 := tls.Dial("tcp", "example.com:443", &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true, // 潜在的安全风险
	})
	if err2 != nil {
		fmt.Println("连接失败 (错误 2):", err2)
	} else {
		fmt.Println("TLS 连接已建立 (错误 2，不安全的配置)")
		conn2.Close()
	}
}
```

**总结这段代码的功能：**

这段代码的核心功能是实现 TLS 客户端握手的第一阶段，即生成并发送 `ClientHello` 消息，并处理与会话恢复相关的逻辑。它负责根据客户端配置构建初始的握手消息，以便与服务器协商加密参数并建立安全连接。

Prompt: 
```
这是路径为go/src/crypto/tls/handshake_client.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/internal/fips140/mlkem"
	"crypto/internal/fips140/tls13"
	"crypto/internal/hpke"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls/internal/fips140tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"internal/byteorder"
	"internal/godebug"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

type clientHandshakeState struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *SessionState // the session being resumed
	ticket       []byte        // a fresh ticket received during this handshake
}

var testingOnlyForceClientHelloSignatureAlgorithms []SignatureScheme

func (c *Conn) makeClientHello() (*clientHelloMsg, *keySharePrivateKeys, *echClientContext, error) {
	config := c.config
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, nil, nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return nil, nil, nil, errors.New("tls: NextProtos values too large")
	}

	supportedVersions := config.supportedVersions(roleClient)
	if len(supportedVersions) == 0 {
		return nil, nil, nil, errors.New("tls: no supported versions satisfy MinVersion and MaxVersion")
	}
	maxVersion := config.maxSupportedVersion(roleClient)

	hello := &clientHelloMsg{
		vers:                         maxVersion,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		extendedMasterSecret:         true,
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName),
		supportedCurves:              config.curvePreferences(maxVersion),
		supportedPoints:              []uint8{pointFormatUncompressed},
		secureRenegotiationSupported: true,
		alpnProtocols:                config.NextProtos,
		supportedVersions:            supportedVersions,
	}

	// The version at the beginning of the ClientHello was capped at TLS 1.2
	// for compatibility reasons. The supported_versions extension is used
	// to negotiate versions now. See RFC 8446, Section 4.2.1.
	if hello.vers > VersionTLS12 {
		hello.vers = VersionTLS12
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	preferenceOrder := cipherSuitesPreferenceOrder
	if !hasAESGCMHardwareSupport {
		preferenceOrder = cipherSuitesPreferenceOrderNoAES
	}
	configCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))

	for _, suiteId := range preferenceOrder {
		suite := mutualCipherSuite(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		// Don't advertise TLS 1.2-only cipher suites unless
		// we're attempting TLS 1.2.
		if maxVersion < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	//
	// The session ID is not set for QUIC connections (see RFC 9001, Section 8.4).
	if c.quic == nil {
		hello.sessionId = make([]byte, 32)
		if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
			return nil, nil, nil, errors.New("tls: short read from Rand: " + err.Error())
		}
	}

	if maxVersion >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
	}
	if testingOnlyForceClientHelloSignatureAlgorithms != nil {
		hello.supportedSignatureAlgorithms = testingOnlyForceClientHelloSignatureAlgorithms
	}

	var keyShareKeys *keySharePrivateKeys
	if hello.supportedVersions[0] == VersionTLS13 {
		// Reset the list of ciphers when the client only supports TLS 1.3.
		if len(hello.supportedVersions) == 1 {
			hello.cipherSuites = nil
		}
		if fips140tls.Required() {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13FIPS...)
		} else if hasAESGCMHardwareSupport {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13...)
		} else {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13NoAES...)
		}

		if len(hello.supportedCurves) == 0 {
			return nil, nil, nil, errors.New("tls: no supported elliptic curves for ECDHE")
		}
		curveID := hello.supportedCurves[0]
		keyShareKeys = &keySharePrivateKeys{curveID: curveID}
		// Note that if X25519MLKEM768 is supported, it will be first because
		// the preference order is fixed.
		if curveID == X25519MLKEM768 {
			keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), X25519)
			if err != nil {
				return nil, nil, nil, err
			}
			seed := make([]byte, mlkem.SeedSize)
			if _, err := io.ReadFull(config.rand(), seed); err != nil {
				return nil, nil, nil, err
			}
			keyShareKeys.mlkem, err = mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				return nil, nil, nil, err
			}
			mlkemEncapsulationKey := keyShareKeys.mlkem.EncapsulationKey().Bytes()
			x25519EphemeralKey := keyShareKeys.ecdhe.PublicKey().Bytes()
			hello.keyShares = []keyShare{
				{group: X25519MLKEM768, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)},
			}
			// If both X25519MLKEM768 and X25519 are supported, we send both key
			// shares (as a fallback) and we reuse the same X25519 ephemeral
			// key, as allowed by draft-ietf-tls-hybrid-design-09, Section 3.2.
			if slices.Contains(hello.supportedCurves, X25519) {
				hello.keyShares = append(hello.keyShares, keyShare{group: X25519, data: x25519EphemeralKey})
			}
		} else {
			if _, ok := curveForCurveID(curveID); !ok {
				return nil, nil, nil, errors.New("tls: CurvePreferences includes unsupported curve")
			}
			keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), curveID)
			if err != nil {
				return nil, nil, nil, err
			}
			hello.keyShares = []keyShare{{group: curveID, data: keyShareKeys.ecdhe.PublicKey().Bytes()}}
		}
	}

	if c.quic != nil {
		p, err := c.quicGetTransportParameters()
		if err != nil {
			return nil, nil, nil, err
		}
		if p == nil {
			p = []byte{}
		}
		hello.quicTransportParameters = p
	}

	var ech *echClientContext
	if c.config.EncryptedClientHelloConfigList != nil {
		if c.config.MinVersion != 0 && c.config.MinVersion < VersionTLS13 {
			return nil, nil, nil, errors.New("tls: MinVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated")
		}
		if c.config.MaxVersion != 0 && c.config.MaxVersion <= VersionTLS12 {
			return nil, nil, nil, errors.New("tls: MaxVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated")
		}
		echConfigs, err := parseECHConfigList(c.config.EncryptedClientHelloConfigList)
		if err != nil {
			return nil, nil, nil, err
		}
		echConfig := pickECHConfig(echConfigs)
		if echConfig == nil {
			return nil, nil, nil, errors.New("tls: EncryptedClientHelloConfigList contains no valid configs")
		}
		ech = &echClientContext{config: echConfig}
		hello.encryptedClientHello = []byte{1} // indicate inner hello
		// We need to explicitly set these 1.2 fields to nil, as we do not
		// marshal them when encoding the inner hello, otherwise transcripts
		// will later mismatch.
		hello.supportedPoints = nil
		hello.ticketSupported = false
		hello.secureRenegotiationSupported = false
		hello.extendedMasterSecret = false

		echPK, err := hpke.ParseHPKEPublicKey(ech.config.KemID, ech.config.PublicKey)
		if err != nil {
			return nil, nil, nil, err
		}
		suite, err := pickECHCipherSuite(ech.config.SymmetricCipherSuite)
		if err != nil {
			return nil, nil, nil, err
		}
		ech.kdfID, ech.aeadID = suite.KDFID, suite.AEADID
		info := append([]byte("tls ech\x00"), ech.config.raw...)
		ech.encapsulatedKey, ech.hpkeContext, err = hpke.SetupSender(ech.config.KemID, suite.KDFID, suite.AEADID, echPK, info)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	return hello, keyShareKeys, ech, nil
}

type echClientContext struct {
	config          *echConfig
	hpkeContext     *hpke.Sender
	encapsulatedKey []byte
	innerHello      *clientHelloMsg
	innerTranscript hash.Hash
	kdfID           uint16
	aeadID          uint16
	echRejected     bool
}

func (c *Conn) clientHandshake(ctx context.Context) (err error) {
	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	hello, keyShareKeys, ech, err := c.makeClientHello()
	if err != nil {
		return err
	}

	session, earlySecret, binderKey, err := c.loadSession(hello)
	if err != nil {
		return err
	}
	if session != nil {
		defer func() {
			// If we got a handshake failure when resuming a session, throw away
			// the session ticket. See RFC 5077, Section 3.2.
			//
			// RFC 8446 makes no mention of dropping tickets on failure, but it
			// does require servers to abort on invalid binders, so we need to
			// delete tickets to recover from a corrupted PSK.
			if err != nil {
				if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
					c.config.ClientSessionCache.Put(cacheKey, nil)
				}
			}
		}()
	}

	if ech != nil {
		// Split hello into inner and outer
		ech.innerHello = hello.clone()

		// Overwrite the server name in the outer hello with the public facing
		// name.
		hello.serverName = string(ech.config.PublicName)
		// Generate a new random for the outer hello.
		hello.random = make([]byte, 32)
		_, err = io.ReadFull(c.config.rand(), hello.random)
		if err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}

		// NOTE: we don't do PSK GREASE, in line with boringssl, it's meant to
		// work around _possibly_ broken middleboxes, but there is little-to-no
		// evidence that this is actually a problem.

		if err := computeAndUpdateOuterECHExtension(hello, ech.innerHello, ech, true); err != nil {
			return err
		}
	}

	c.serverName = hello.serverName

	if _, err := c.writeHandshakeRecord(hello, nil); err != nil {
		return err
	}

	if hello.earlyData {
		suite := cipherSuiteTLS13ByID(session.cipherSuite)
		transcript := suite.hash.New()
		if err := transcriptMsg(hello, transcript); err != nil {
			return err
		}
		earlyTrafficSecret := earlySecret.ClientEarlyTrafficSecret(transcript)
		c.quicSetWriteSecret(QUICEncryptionLevelEarly, suite.id, earlyTrafficSecret)
	}

	// serverHelloMsg is not included in the transcript
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	if err := c.pickTLSVersion(serverHello); err != nil {
		return err
	}

	// If we are negotiating a protocol version that's lower than what we
	// support, check for the server downgrade canaries.
	// See RFC 8446, Section 4.1.3.
	maxVers := c.config.maxSupportedVersion(roleClient)
	tls12Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS12
	tls11Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS11
	if maxVers == VersionTLS13 && c.vers <= VersionTLS12 && (tls12Downgrade || tls11Downgrade) ||
		maxVers == VersionTLS12 && c.vers <= VersionTLS11 && tls11Downgrade {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox")
	}

	if c.vers == VersionTLS13 {
		hs := &clientHandshakeStateTLS13{
			c:            c,
			ctx:          ctx,
			serverHello:  serverHello,
			hello:        hello,
			keyShareKeys: keyShareKeys,
			session:      session,
			earlySecret:  earlySecret,
			binderKey:    binderKey,
			echContext:   ech,
		}
		return hs.handshake()
	}

	hs := &clientHandshakeState{
		c:           c,
		ctx:         ctx,
		serverHello: serverHello,
		hello:       hello,
		session:     session,
	}
	return hs.handshake()
}

func (c *Conn) loadSession(hello *clientHelloMsg) (
	session *SessionState, earlySecret *tls13.EarlySecret, binderKey []byte, err error) {
	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return nil, nil, nil, nil
	}

	echInner := bytes.Equal(hello.encryptedClientHello, []byte{1})

	// ticketSupported is a TLS 1.2 extension (as TLS 1.3 replaced tickets with PSK
	// identities) and ECH requires and forces TLS 1.3.
	hello.ticketSupported = true && !echInner

	if hello.supportedVersions[0] == VersionTLS13 {
		// Require DHE on resumption as it guarantees forward secrecy against
		// compromise of the session ticket key. See RFC 8446, Section 4.2.9.
		hello.pskModes = []uint8{pskModeDHE}
	}

	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	if c.handshakes != 0 {
		return nil, nil, nil, nil
	}

	// Try to resume a previously negotiated TLS session, if available.
	cacheKey := c.clientSessionCacheKey()
	if cacheKey == "" {
		return nil, nil, nil, nil
	}
	cs, ok := c.config.ClientSessionCache.Get(cacheKey)
	if !ok || cs == nil {
		return nil, nil, nil, nil
	}
	session = cs.session

	// Check that version used for the previous session is still valid.
	versOk := false
	for _, v := range hello.supportedVersions {
		if v == session.version {
			versOk = true
			break
		}
	}
	if !versOk {
		return nil, nil, nil, nil
	}

	// Check that the cached server certificate is not expired, and that it's
	// valid for the ServerName. This should be ensured by the cache key, but
	// protect the application from a faulty ClientSessionCache implementation.
	if c.config.time().After(session.peerCertificates[0].NotAfter) {
		// Expired certificate, delete the entry.
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return nil, nil, nil, nil
	}
	if !c.config.InsecureSkipVerify {
		if len(session.verifiedChains) == 0 {
			// The original connection had InsecureSkipVerify, while this doesn't.
			return nil, nil, nil, nil
		}
		if err := session.peerCertificates[0].VerifyHostname(c.config.ServerName); err != nil {
			return nil, nil, nil, nil
		}
	}

	if session.version != VersionTLS13 {
		// In TLS 1.2 the cipher suite must match the resumed session. Ensure we
		// are still offering it.
		if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil {
			return nil, nil, nil, nil
		}

		hello.sessionTicket = session.ticket
		return
	}

	// Check that the session ticket is not expired.
	if c.config.time().After(time.Unix(int64(session.useBy), 0)) {
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return nil, nil, nil, nil
	}

	// In TLS 1.3 the KDF hash must match the resumed session. Ensure we
	// offer at least one cipher suite with that hash.
	cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
	if cipherSuite == nil {
		return nil, nil, nil, nil
	}
	cipherSuiteOk := false
	for _, offeredID := range hello.cipherSuites {
		offeredSuite := cipherSuiteTLS13ByID(offeredID)
		if offeredSuite != nil && offeredSuite.hash == cipherSuite.hash {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return nil, nil, nil, nil
	}

	if c.quic != nil {
		if c.quic.enableSessionEvents {
			c.quicResumeSession(session)
		}

		// For 0-RTT, the cipher suite has to match exactly, and we need to be
		// offering the same ALPN.
		if session.EarlyData && mutualCipherSuiteTLS13(hello.cipherSuites, session.cipherSuite) != nil {
			for _, alpn := range hello.alpnProtocols {
				if alpn == session.alpnProtocol {
					hello.earlyData = true
					break
				}
			}
		}
	}

	// Set the pre_shared_key extension. See RFC 8446, Section 4.2.11.1.
	ticketAge := c.config.time().Sub(time.Unix(int64(session.createdAt), 0))
	identity := pskIdentity{
		label:               session.ticket,
		obfuscatedTicketAge: uint32(ticketAge/time.Millisecond) + session.ageAdd,
	}
	hello.pskIdentities = []pskIdentity{identity}
	hello.pskBinders = [][]byte{make([]byte, cipherSuite.hash.Size())}

	// Compute the PSK binders. See RFC 8446, Section 4.2.11.2.
	earlySecret = tls13.NewEarlySecret(cipherSuite.hash.New, session.secret)
	binderKey = earlySecret.ResumptionBinderKey()
	transcript := cipherSuite.hash.New()
	if err := computeAndUpdatePSK(hello, binderKey, transcript, cipherSuite.finishedHash); err != nil {
		return nil, nil, nil, err
	}

	return
}

func (c *Conn) pickTLSVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers
	if serverHello.supportedVersion != 0 {
		peerVersion = serverHello.supportedVersion
	}

	vers, ok := c.config.mutualVersion(roleClient, []uint16{peerVersion})
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", peerVersion)
	}

	c.vers = vers
	c.haveVers = true
	c.in.version = vers
	c.out.version = vers

	return nil
}

// Does the handshake, either a full one or resumes old session. Requires hs.c,
// hs.hello, hs.serverHello, and, optionally, hs.session to be set.
func (hs *clientHandshakeState) handshake() error {
	c := hs.c

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	if err := transcriptMsg(hs.hello, &hs.finishedHash); err != nil {
		return err
	}
	if err := transcriptMsg(hs.serverHello, &hs.finishedHash); err != nil {
		return err
	}

	c.buffering = true
	c.didResume = isResume
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}
	if err := hs.saveSessionTicket(); err != nil {
		return err
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	c.isHandshakeComplete.Store(true)

	return nil
}

func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	if hs.c.config.CipherSuites == nil && !fips140tls.Required() && rsaKexCiphers[hs.suite.id] {
		tlsrsakex.Value() // ensure godebug is initialized
		tlsrsakex.IncNonDefault()
	}
	if hs.c.config.CipherSuites == nil && !fips140tls.Required() && tdesCiphers[hs.suite.id] {
		tls3des.Value() // ensure godebug is initialized
		tls3des.IncNonDefault()
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}

	msg, err = c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}

	cs, ok := msg.(*certificateStatusMsg)
	if ok {
		// RFC4366 on Certificate Status Request:
		// The server MAY return a "certificate_status" message.

		if !hs.serverHello.ocspStapling {
			// If a server returns a "CertificateStatus" message, then the
			// server MUST have included an extension of type "status_request"
			// with empty "extension_data" in the extended server hello.

			c.sendAlert(alertUnexpectedMessage)
			return errors.New("tls: received unexpected CertificateStatus message")
		}

		c.ocspResponse = cs.response

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	if c.handshakes == 0 {
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		if err := c.verifyServerCertificate(certMsg.certificates); err != nil {
			return err
		}
	} else {
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: server's identity changed during renegotiation")
		}
	}

	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return err
		}
		if len(skx.key) >= 3 && skx.key[0] == 3 /* named curve */ {
			c.curveID = CurveID(byteorder.BEUint16(skx.key[1:]))
		}

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true

		cri := certificateRequestInfoFromMsg(hs.ctx, c.vers, certReq)
		if chainToSend, err = c.getClientCertificate(cri); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		if _, err := hs.c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
			return err
		}
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[0])
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		if _, err := hs.c.writeHandshakeRecord(ckx, &hs.finishedHash); err != nil {
			return err
		}
	}

	if hs.serverHello.extendedMasterSecret {
		c.extMasterSecret = true
		hs.masterSecret = extMasterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret,
			hs.finishedHash.Sum())
	} else {
		hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret,
			hs.hello.random, hs.serverHello.random)
	}
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to write to key log: " + err.Error())
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		var sigType uint8
		var sigHash crypto.Hash
		if c.vers >= VersionTLS12 {
			signatureAlgorithm, err := selectSignatureScheme(c.vers, chainToSend, certReq.supportedSignatureAlgorithms)
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
			sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
			if err != nil {
				return c.sendAlert(alertInternalError)
			}
			certVerify.hasSignatureAlgorithm = true
			certVerify.signatureAlgorithm = signatureAlgorithm
		} else {
			sigType, sigHash, err = legacyTypeAndHashFromPublicKey(key.Public())
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
		}

		signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash)
		signOpts := crypto.SignerOpts(sigHash)
		if sigType == signatureRSAPSS {
			signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
		}
		certVerify.signature, err = key.Sign(c.config.rand(), signed, signOpts)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		if _, err := hs.c.writeHandshakeRecord(certVerify, &hs.finishedHash); err != nil {
			return err
		}
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher any
	var clientHash, serverHash hash.Hash
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: incorrect renegotiation extension contents")
		}
	}

	if err := checkALPN(hs.hello.alpnProtocols, hs.serverHello.alpnProtocol, false); err != nil {
		c.sendAlert(alertUnsupportedExtension)
		return false, err
	}
	c.clientProtocol = hs.serverHello.alpnProtocol

	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.version != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	// RFC 7627, Section 5.3
	if hs.session.extMasterSecret != hs.serverHello.extendedMasterSecret {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different EMS extension")
	}

	// Restore master secret and certificates from previous state
	hs.masterSecret = hs.session.secret
	c.extMasterSecret = hs.session.extMasterSecret
	c.peerCertificates = hs.session.peerCertificates
	c.activeCertHandles = hs.c.activeCertHandles
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	// Let the ServerHello SCTs override the session SCTs from the original
	// connection, if any are provided
	if len(c.scts) == 0 && len(hs.session.scts) != 0 {
		c.scts = hs.session.scts
	}

	return true, nil
}

// checkALPN ensure that the server's choice of ALPN protocol is compatible with
// the protocols that we advertised in the ClientHello.
func checkALPN(clientProtos []string, serverProto string, quic bool) error {
	if serverProto == "" {
		if quic && len(clientProtos) > 0 {
			// RFC 9001, Section 8.1
			return errors.New("tls: server did not select an ALPN protocol")
		}
		return nil
	}
	if len(clientProtos) == 0 {
		return errors.New("tls: server advertised unrequested ALPN extension")
	}
	for _, proto := range clientProtos {
		if proto == serverProto {
			return nil
		}
	}
	return errors.New("tls: server selected unadvertised ALPN protocol")
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
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
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}

	if err := transcriptMsg(serverFinished, &hs.finishedHash); err != nil {
		return err
	}

	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}
	c := hs.c

	if !hs.hello.ticketSupported {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent unrequested session ticket")
	}

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}

	hs.ticket = sessionTicketMsg.ticket
	return nil
}

func (hs *clientHandshakeState) saveSessionTicket() error {
	if hs.ticket == nil {
		return nil
	}
	c := hs.c

	cacheKey := c.clientSessionCacheKey()
	if cacheKey == "" {
		return nil
	}

	session := c.sessionState()
	session.secret = hs.masterSecret
	session.ticket = hs.ticket

	cs := &ClientSessionState{session: session}
	c.config.ClientSessionCache.Put(cacheKey, cs)
	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	if _, err := hs.c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

// defaultMaxRSAKeySize is the maximum RSA key size in bits that we 
"""




```