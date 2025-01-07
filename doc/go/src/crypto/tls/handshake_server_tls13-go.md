Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the TLS 1.3 server-side handshake implementation. I need to analyze the code and provide a summary of its purpose. Specifically, the user asked for:

1. **Overall Functionality:** A description of what this code does.
2. **Go Language Feature:** If applicable, identify and explain the Go feature this code implements with an example.
3. **Code Reasoning:** If the analysis involves deducing functionality, provide examples with hypothetical inputs and outputs.
4. **Command-Line Arguments:** Explain how command-line arguments are handled, if at all.
5. **Common Mistakes:** Point out potential pitfalls for users.
6. **Summary:**  A concise summary of the code's purpose as the first part of a two-part explanation.

Based on the code, it primarily handles the server-side logic for the TLS 1.3 handshake, starting from processing the client's initial `ClientHello` message and proceeding through various stages like selecting ciphersuites, key exchange, certificate handling, and optionally handling session resumption with PSK. It manages the handshake state and uses various cryptographic primitives.

**Plan:**

1. **Identify Key Functions:** Look for functions that represent distinct stages of the TLS 1.3 handshake.
2. **Trace the Handshake Flow:**  Follow the execution path, starting with the `handshake()` function.
3. **Describe Major Responsibilities:**  Summarize what each key function does in the handshake process.
4. **Address Specific User Requests:**
    - Go Language Features: This code implements the TLS 1.3 protocol, a network protocol, and utilizes Go's standard library for cryptography and networking. It doesn't seem to be a specific language feature demo.
    - Code Reasoning:  The logic flow itself is the reasoning. I'll point out key steps and their purpose.
    - Command-Line Arguments: This part of the code doesn't directly handle command-line arguments. TLS configuration is usually done programmatically.
    - Common Mistakes:  Potential issues could involve incorrect TLS configurations or misunderstanding the TLS 1.3 handshake flow.
5. **Formulate the Summary:**  Write a concise overview of the code's purpose.
这段Go语言代码是 `crypto/tls` 包的一部分，专门负责实现 **TLS 1.3 服务器端的握手过程**。

更具体地说，这段代码定义了服务器端 TLS 1.3 握手所需的状态和处理逻辑，从接收客户端的 `ClientHello` 消息开始，到建立安全连接并准备好传输应用数据为止。

以下是这段代码的主要功能归纳：

1. **定义握手状态:**  定义了 `serverHandshakeStateTLS13` 结构体，用于存储服务器端握手过程中的各种状态信息，例如：
    - 连接对象 (`Conn`)
    - 上下文 (`context.Context`)
    - 客户端 `ClientHello` 消息 (`clientHelloMsg`)
    - 服务器 `ServerHello` 消息 (`hello`)
    - 是否已发送伪造的 `ChangeCipherSpec` 消息
    - 是否使用 PSK (预共享密钥)
    - 是否允许早期数据 (Early Data)
    - 选择的密码套件 (`cipherSuiteTLS13`)
    - 服务器证书 (`Certificate`)
    - 签名算法 (`SignatureScheme`)
    - 各种密钥 (早期密钥、握手密钥、主密钥、流量密钥)
    - 握手消息的哈希值 (`hash.Hash`)
    - 客户端 `Finished` 消息
    - ECH (加密客户端 Hello) 上下文

2. **实现握手主流程:** `handshake()` 函数是服务器端 TLS 1.3 握手的核心流程控制，它按照 TLS 1.3 协议的规范逐步执行以下步骤：
    - 处理客户端的 `ClientHello` 消息 (`processClientHello()`)
    - 检查是否可以进行会话恢复 (`checkForResumption()`)
    - 选择服务器证书 (`pickCertificate()`)
    - 发送服务器参数 (`sendServerParameters()`)，包括 `ServerHello` 消息
    - 发送服务器证书相关的消息 (`sendServerCertificate()`)
    - 发送服务器 `Finished` 消息 (`sendServerFinished()`)
    - 读取客户端证书 (如果需要) (`readClientCertificate()`)
    - 读取客户端 `Finished` 消息 (`readClientFinished()`)

3. **处理客户端的 `ClientHello` 消息:** `processClientHello()` 函数负责解析客户端发送的 `ClientHello` 消息，并进行以下处理：
    - 验证客户端支持的 TLS 版本
    - 处理降级保护 (`TLS_FALLBACK_SCSV`)
    - 验证压缩方法 (TLS 1.3 必须为 `compressionNone`)
    - 生成 `ServerHello` 消息的随机数
    - 检查安全重协商扩展
    - 处理早期数据指示
    - 选择密码套件
    - 选择密钥交换算法 (包括处理 `HelloRetryRequest` 的情况)
    - 协商 ALPN (应用层协议协商)
    - 处理 QUIC 传输参数 (如果使用 QUIC)
    - 记录客户端提供的服务器名称 (SNI)

4. **处理会话恢复 (PSK):** `checkForResumption()` 函数检查客户端是否提供了会话票据 (Session Ticket) 或 PSK 身份标识，并尝试恢复之前的会话，如果成功恢复，则可以跳过证书交换等步骤。

5. **选择服务器证书:** `pickCertificate()` 函数根据客户端提供的 SNI 和服务器配置选择合适的证书。

6. **发送服务器参数:** `sendServerParameters()` 函数发送 `ServerHello` 消息，并根据握手状态派生出握手密钥。

7. **处理 `HelloRetryRequest`:** `doHelloRetryRequest()` 函数处理客户端收到服务器的 `HelloRetryRequest` 后的重试逻辑。

8. **发送服务器证书相关消息:** `sendServerCertificate()` 函数发送服务器证书、证书链以及相关的 `CertificateVerify` 消息，用于向客户端证明服务器的身份。

9. **发送服务器 `Finished` 消息:** `sendServerFinished()` 函数发送服务器的 `Finished` 消息，用于验证握手过程中消息的完整性，并派生出用于加密应用数据的密钥。

10. **处理客户端证书请求:** `requestClientCert()` 函数判断服务器是否需要客户端提供证书。`readClientCertificate()` 函数则负责读取和验证客户端发送的证书。

11. **发送和处理会话票据:** `sendSessionTickets()` 和 `sendSessionTicket()` 函数负责生成和发送新的会话票据，用于后续的会话恢复。

总而言之，这段代码是 Go 语言 `crypto/tls` 包中实现 TLS 1.3 服务器端握手的核心组成部分，它负责处理客户端的握手请求，协商安全参数，验证身份，并建立安全的加密连接。

Prompt: 
```
这是路径为go/src/crypto/tls/handshake_server_tls13.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/internal/fips140/hkdf"
	"crypto/internal/fips140/mlkem"
	"crypto/internal/fips140/tls13"
	"crypto/internal/hpke"
	"crypto/rsa"
	"crypto/tls/internal/fips140tls"
	"errors"
	"hash"
	"internal/byteorder"
	"io"
	"slices"
	"sort"
	"time"
)

// maxClientPSKIdentities is the number of client PSK identities the server will
// attempt to validate. It will ignore the rest not to let cheap ClientHello
// messages cause too much work in session ticket decryption attempts.
const maxClientPSKIdentities = 5

type echServerContext struct {
	hpkeContext *hpke.Receipient
	configID    uint8
	ciphersuite echCipher
	transcript  hash.Hash
	// inner indicates that the initial client_hello we recieved contained an
	// encrypted_client_hello extension that indicated it was an "inner" hello.
	// We don't do any additional processing of the hello in this case, so all
	// fields above are unset.
	inner bool
}

type serverHandshakeStateTLS13 struct {
	c               *Conn
	ctx             context.Context
	clientHello     *clientHelloMsg
	hello           *serverHelloMsg
	sentDummyCCS    bool
	usingPSK        bool
	earlyData       bool
	suite           *cipherSuiteTLS13
	cert            *Certificate
	sigAlg          SignatureScheme
	earlySecret     *tls13.EarlySecret
	sharedKey       []byte
	handshakeSecret *tls13.HandshakeSecret
	masterSecret    *tls13.MasterSecret
	trafficSecret   []byte // client_application_traffic_secret_0
	transcript      hash.Hash
	clientFinished  []byte
	echContext      *echServerContext
}

func (hs *serverHandshakeStateTLS13) handshake() error {
	c := hs.c

	// For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.
	if err := hs.processClientHello(); err != nil {
		return err
	}
	if err := hs.checkForResumption(); err != nil {
		return err
	}
	if err := hs.pickCertificate(); err != nil {
		return err
	}
	c.buffering = true
	if err := hs.sendServerParameters(); err != nil {
		return err
	}
	if err := hs.sendServerCertificate(); err != nil {
		return err
	}
	if err := hs.sendServerFinished(); err != nil {
		return err
	}
	// Note that at this point we could start sending application data without
	// waiting for the client's second flight, but the application might not
	// expect the lack of replay protection of the ClientHello parameters.
	if _, err := c.flush(); err != nil {
		return err
	}
	if err := hs.readClientCertificate(); err != nil {
		return err
	}
	if err := hs.readClientFinished(); err != nil {
		return err
	}

	c.isHandshakeComplete.Store(true)

	return nil
}

func (hs *serverHandshakeStateTLS13) processClientHello() error {
	c := hs.c

	hs.hello = new(serverHelloMsg)

	// TLS 1.3 froze the ServerHello.legacy_version field, and uses
	// supported_versions instead. See RFC 8446, sections 4.1.3 and 4.2.1.
	hs.hello.vers = VersionTLS12
	hs.hello.supportedVersion = c.vers

	if len(hs.clientHello.supportedVersions) == 0 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client used the legacy version field to negotiate TLS 1.3")
	}

	// Abort if the client is doing a fallback and landing lower than what we
	// support. See RFC 7507, which however does not specify the interaction
	// with supported_versions. The only difference is that with
	// supported_versions a client has a chance to attempt a [TLS 1.2, TLS 1.4]
	// handshake in case TLS 1.3 is broken but 1.2 is not. Alas, in that case,
	// it will have to drop the TLS_FALLBACK_SCSV protection if it falls back to
	// TLS 1.2, because a TLS 1.3 server would abort here. The situation before
	// supported_versions was not better because there was just no way to do a
	// TLS 1.4 handshake without risking the server selecting TLS 1.3.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// Use c.vers instead of max(supported_versions) because an attacker
			// could defeat this by adding an arbitrary high version otherwise.
			if c.vers < c.config.maxSupportedVersion(roleServer) {
				c.sendAlert(alertInappropriateFallback)
				return errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	if len(hs.clientHello.compressionMethods) != 1 ||
		hs.clientHello.compressionMethods[0] != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: TLS 1.3 client supports illegal compression methods")
	}

	hs.hello.random = make([]byte, 32)
	if _, err := io.ReadFull(c.config.rand(), hs.hello.random); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	if hs.clientHello.earlyData && c.quic != nil {
		if len(hs.clientHello.pskIdentities) == 0 {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: early_data without pre_shared_key")
		}
	} else if hs.clientHello.earlyData {
		// See RFC 8446, Section 4.2.10 for the complicated behavior required
		// here. The scenario is that a different server at our address offered
		// to accept early data in the past, which we can't handle. For now, all
		// 0-RTT enabled session tickets need to expire before a Go server can
		// replace a server or join a pool. That's the same requirement that
		// applies to mixing or replacing with any TLS 1.2 server.
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: client sent unexpected early data")
	}

	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.compressionMethod = compressionNone

	preferenceList := defaultCipherSuitesTLS13
	if !hasAESGCMHardwareSupport || !aesgcmPreferred(hs.clientHello.cipherSuites) {
		preferenceList = defaultCipherSuitesTLS13NoAES
	}
	if fips140tls.Required() {
		preferenceList = defaultCipherSuitesTLS13FIPS
	}
	for _, suiteID := range preferenceList {
		hs.suite = mutualCipherSuiteTLS13(hs.clientHello.cipherSuites, suiteID)
		if hs.suite != nil {
			break
		}
	}
	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: no cipher suite supported by both client and server")
	}
	c.cipherSuite = hs.suite.id
	hs.hello.cipherSuite = hs.suite.id
	hs.transcript = hs.suite.hash.New()

	// First, if a post-quantum key exchange is available, use one. See
	// draft-ietf-tls-key-share-prediction-01, Section 4 for why this must be
	// first.
	//
	// Second, if the client sent a key share for a group we support, use that,
	// to avoid a HelloRetryRequest round-trip.
	//
	// Finally, pick in our fixed preference order.
	preferredGroups := c.config.curvePreferences(c.vers)
	preferredGroups = slices.DeleteFunc(preferredGroups, func(group CurveID) bool {
		return !slices.Contains(hs.clientHello.supportedCurves, group)
	})
	if len(preferredGroups) == 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: no key exchanges supported by both client and server")
	}
	hasKeyShare := func(group CurveID) bool {
		for _, ks := range hs.clientHello.keyShares {
			if ks.group == group {
				return true
			}
		}
		return false
	}
	sort.SliceStable(preferredGroups, func(i, j int) bool {
		return hasKeyShare(preferredGroups[i]) && !hasKeyShare(preferredGroups[j])
	})
	sort.SliceStable(preferredGroups, func(i, j int) bool {
		return isPQKeyExchange(preferredGroups[i]) && !isPQKeyExchange(preferredGroups[j])
	})
	selectedGroup := preferredGroups[0]

	var clientKeyShare *keyShare
	for _, ks := range hs.clientHello.keyShares {
		if ks.group == selectedGroup {
			clientKeyShare = &ks
			break
		}
	}
	if clientKeyShare == nil {
		ks, err := hs.doHelloRetryRequest(selectedGroup)
		if err != nil {
			return err
		}
		clientKeyShare = ks
	}
	c.curveID = selectedGroup

	ecdhGroup := selectedGroup
	ecdhData := clientKeyShare.data
	if selectedGroup == X25519MLKEM768 {
		ecdhGroup = X25519
		if len(ecdhData) != mlkem.EncapsulationKeySize768+x25519PublicKeySize {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid X25519MLKEM768 client key share")
		}
		ecdhData = ecdhData[mlkem.EncapsulationKeySize768:]
	}
	if _, ok := curveForCurveID(ecdhGroup); !ok {
		c.sendAlert(alertInternalError)
		return errors.New("tls: CurvePreferences includes unsupported curve")
	}
	key, err := generateECDHEKey(c.config.rand(), ecdhGroup)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}
	peerKey, err := key.Curve().NewPublicKey(ecdhData)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid client key share")
	}
	hs.sharedKey, err = key.ECDH(peerKey)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid client key share")
	}
	if selectedGroup == X25519MLKEM768 {
		k, err := mlkem.NewEncapsulationKey768(clientKeyShare.data[:mlkem.EncapsulationKeySize768])
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid X25519MLKEM768 client key share")
		}
		ciphertext, mlkemSharedSecret := k.Encapsulate()
		// draft-kwiatkowski-tls-ecdhe-mlkem-02, Section 3.1.3: "For
		// X25519MLKEM768, the shared secret is the concatenation of the ML-KEM
		// shared secret and the X25519 shared secret. The shared secret is 64
		// bytes (32 bytes for each part)."
		hs.sharedKey = append(mlkemSharedSecret, hs.sharedKey...)
		// draft-kwiatkowski-tls-ecdhe-mlkem-02, Section 3.1.2: "When the
		// X25519MLKEM768 group is negotiated, the server's key exchange value
		// is the concatenation of an ML-KEM ciphertext returned from
		// encapsulation to the client's encapsulation key, and the server's
		// ephemeral X25519 share."
		hs.hello.serverShare.data = append(ciphertext, hs.hello.serverShare.data...)
	}

	selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols, c.quic != nil)
	if err != nil {
		c.sendAlert(alertNoApplicationProtocol)
		return err
	}
	c.clientProtocol = selectedProto

	if c.quic != nil {
		// RFC 9001 Section 4.2: Clients MUST NOT offer TLS versions older than 1.3.
		for _, v := range hs.clientHello.supportedVersions {
			if v < VersionTLS13 {
				c.sendAlert(alertProtocolVersion)
				return errors.New("tls: client offered TLS version older than TLS 1.3")
			}
		}
		// RFC 9001 Section 8.2.
		if hs.clientHello.quicTransportParameters == nil {
			c.sendAlert(alertMissingExtension)
			return errors.New("tls: client did not send a quic_transport_parameters extension")
		}
		c.quicSetTransportParameters(hs.clientHello.quicTransportParameters)
	} else {
		if hs.clientHello.quicTransportParameters != nil {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: client sent an unexpected quic_transport_parameters extension")
		}
	}

	c.serverName = hs.clientHello.serverName
	return nil
}

func (hs *serverHandshakeStateTLS13) checkForResumption() error {
	c := hs.c

	if c.config.SessionTicketsDisabled {
		return nil
	}

	modeOK := false
	for _, mode := range hs.clientHello.pskModes {
		if mode == pskModeDHE {
			modeOK = true
			break
		}
	}
	if !modeOK {
		return nil
	}

	if len(hs.clientHello.pskIdentities) != len(hs.clientHello.pskBinders) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid or missing PSK binders")
	}
	if len(hs.clientHello.pskIdentities) == 0 {
		return nil
	}

	for i, identity := range hs.clientHello.pskIdentities {
		if i >= maxClientPSKIdentities {
			break
		}

		var sessionState *SessionState
		if c.config.UnwrapSession != nil {
			var err error
			sessionState, err = c.config.UnwrapSession(identity.label, c.connectionStateLocked())
			if err != nil {
				return err
			}
			if sessionState == nil {
				continue
			}
		} else {
			plaintext := c.config.decryptTicket(identity.label, c.ticketKeys)
			if plaintext == nil {
				continue
			}
			var err error
			sessionState, err = ParseSessionState(plaintext)
			if err != nil {
				continue
			}
		}

		if sessionState.version != VersionTLS13 {
			continue
		}

		createdAt := time.Unix(int64(sessionState.createdAt), 0)
		if c.config.time().Sub(createdAt) > maxSessionTicketLifetime {
			continue
		}

		pskSuite := cipherSuiteTLS13ByID(sessionState.cipherSuite)
		if pskSuite == nil || pskSuite.hash != hs.suite.hash {
			continue
		}

		// PSK connections don't re-establish client certificates, but carry
		// them over in the session ticket. Ensure the presence of client certs
		// in the ticket is consistent with the configured requirements.
		sessionHasClientCerts := len(sessionState.peerCertificates) != 0
		needClientCerts := requiresClientCert(c.config.ClientAuth)
		if needClientCerts && !sessionHasClientCerts {
			continue
		}
		if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
			continue
		}
		if sessionHasClientCerts && c.config.time().After(sessionState.peerCertificates[0].NotAfter) {
			continue
		}
		if sessionHasClientCerts && c.config.ClientAuth >= VerifyClientCertIfGiven &&
			len(sessionState.verifiedChains) == 0 {
			continue
		}

		if c.quic != nil && c.quic.enableSessionEvents {
			if err := c.quicResumeSession(sessionState); err != nil {
				return err
			}
		}

		hs.earlySecret = tls13.NewEarlySecret(hs.suite.hash.New, sessionState.secret)
		binderKey := hs.earlySecret.ResumptionBinderKey()
		// Clone the transcript in case a HelloRetryRequest was recorded.
		transcript := cloneHash(hs.transcript, hs.suite.hash)
		if transcript == nil {
			c.sendAlert(alertInternalError)
			return errors.New("tls: internal error: failed to clone hash")
		}
		clientHelloBytes, err := hs.clientHello.marshalWithoutBinders()
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		transcript.Write(clientHelloBytes)
		pskBinder := hs.suite.finishedHash(binderKey, transcript)
		if !hmac.Equal(hs.clientHello.pskBinders[i], pskBinder) {
			c.sendAlert(alertDecryptError)
			return errors.New("tls: invalid PSK binder")
		}

		if c.quic != nil && hs.clientHello.earlyData && i == 0 &&
			sessionState.EarlyData && sessionState.cipherSuite == hs.suite.id &&
			sessionState.alpnProtocol == c.clientProtocol {
			hs.earlyData = true

			transcript := hs.suite.hash.New()
			if err := transcriptMsg(hs.clientHello, transcript); err != nil {
				return err
			}
			earlyTrafficSecret := hs.earlySecret.ClientEarlyTrafficSecret(transcript)
			c.quicSetReadSecret(QUICEncryptionLevelEarly, hs.suite.id, earlyTrafficSecret)
		}

		c.didResume = true
		c.peerCertificates = sessionState.peerCertificates
		c.ocspResponse = sessionState.ocspResponse
		c.scts = sessionState.scts
		c.verifiedChains = sessionState.verifiedChains

		hs.hello.selectedIdentityPresent = true
		hs.hello.selectedIdentity = uint16(i)
		hs.usingPSK = true
		return nil
	}

	return nil
}

// cloneHash uses the encoding.BinaryMarshaler and encoding.BinaryUnmarshaler
// interfaces implemented by standard library hashes to clone the state of in
// to a new instance of h. It returns nil if the operation fails.
func cloneHash(in hash.Hash, h crypto.Hash) hash.Hash {
	// Recreate the interface to avoid importing encoding.
	type binaryMarshaler interface {
		MarshalBinary() (data []byte, err error)
		UnmarshalBinary(data []byte) error
	}
	marshaler, ok := in.(binaryMarshaler)
	if !ok {
		return nil
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		return nil
	}
	out := h.New()
	unmarshaler, ok := out.(binaryMarshaler)
	if !ok {
		return nil
	}
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		return nil
	}
	return out
}

func (hs *serverHandshakeStateTLS13) pickCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	// signature_algorithms is required in TLS 1.3. See RFC 8446, Section 4.2.3.
	if len(hs.clientHello.supportedSignatureAlgorithms) == 0 {
		return c.sendAlert(alertMissingExtension)
	}

	certificate, err := c.config.getCertificate(clientHelloInfo(hs.ctx, c, hs.clientHello))
	if err != nil {
		if err == errNoCertificates {
			c.sendAlert(alertUnrecognizedName)
		} else {
			c.sendAlert(alertInternalError)
		}
		return err
	}
	hs.sigAlg, err = selectSignatureScheme(c.vers, certificate, hs.clientHello.supportedSignatureAlgorithms)
	if err != nil {
		// getCertificate returned a certificate that is unsupported or
		// incompatible with the client's signature algorithms.
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	hs.cert = certificate

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *serverHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.c.quic != nil {
		return nil
	}
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	return hs.c.writeChangeCipherRecord()
}

func (hs *serverHandshakeStateTLS13) doHelloRetryRequest(selectedGroup CurveID) (*keyShare, error) {
	c := hs.c

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. See RFC 8446, Section 4.4.1.
	if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil {
		return nil, err
	}
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)

	helloRetryRequest := &serverHelloMsg{
		vers:              hs.hello.vers,
		random:            helloRetryRequestRandom,
		sessionId:         hs.hello.sessionId,
		cipherSuite:       hs.hello.cipherSuite,
		compressionMethod: hs.hello.compressionMethod,
		supportedVersion:  hs.hello.supportedVersion,
		selectedGroup:     selectedGroup,
	}

	if hs.echContext != nil {
		// Compute the acceptance message.
		helloRetryRequest.encryptedClientHello = make([]byte, 8)
		confTranscript := cloneHash(hs.transcript, hs.suite.hash)
		if err := transcriptMsg(helloRetryRequest, confTranscript); err != nil {
			return nil, err
		}
		acceptConfirmation := tls13.ExpandLabel(hs.suite.hash.New,
			hkdf.Extract(hs.suite.hash.New, hs.clientHello.random, nil),
			"hrr ech accept confirmation",
			confTranscript.Sum(nil),
			8,
		)
		helloRetryRequest.encryptedClientHello = acceptConfirmation
	}

	if _, err := hs.c.writeHandshakeRecord(helloRetryRequest, hs.transcript); err != nil {
		return nil, err
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return nil, err
	}

	// clientHelloMsg is not included in the transcript.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return nil, err
	}

	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(clientHello, msg)
	}

	if hs.echContext != nil {
		if len(clientHello.encryptedClientHello) == 0 {
			c.sendAlert(alertMissingExtension)
			return nil, errors.New("tls: second client hello missing encrypted client hello extension")
		}

		echType, echCiphersuite, configID, encap, payload, err := parseECHExt(clientHello.encryptedClientHello)
		if err != nil {
			c.sendAlert(alertDecodeError)
			return nil, errors.New("tls: client sent invalid encrypted client hello extension")
		}

		if echType == outerECHExt && hs.echContext.inner || echType == innerECHExt && !hs.echContext.inner {
			c.sendAlert(alertDecodeError)
			return nil, errors.New("tls: unexpected switch in encrypted client hello extension type")
		}

		if echType == outerECHExt {
			if echCiphersuite != hs.echContext.ciphersuite || configID != hs.echContext.configID || len(encap) != 0 {
				c.sendAlert(alertIllegalParameter)
				return nil, errors.New("tls: second client hello encrypted client hello extension does not match")
			}

			encodedInner, err := decryptECHPayload(hs.echContext.hpkeContext, clientHello.original, payload)
			if err != nil {
				c.sendAlert(alertDecryptError)
				return nil, errors.New("tls: failed to decrypt second client hello encrypted client hello extension payload")
			}

			echInner, err := decodeInnerClientHello(clientHello, encodedInner)
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return nil, errors.New("tls: client sent invalid encrypted client hello extension")
			}

			clientHello = echInner
		}
	}

	if len(clientHello.keyShares) != 1 {
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("tls: client didn't send one key share in second ClientHello")
	}
	ks := &clientHello.keyShares[0]

	if ks.group != selectedGroup {
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("tls: client sent unexpected key share in second ClientHello")
	}

	if clientHello.earlyData {
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("tls: client indicated early data in second ClientHello")
	}

	if illegalClientHelloChange(clientHello, hs.clientHello) {
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("tls: client illegally modified second ClientHello")
	}

	c.didHRR = true
	hs.clientHello = clientHello
	return ks, nil
}

// illegalClientHelloChange reports whether the two ClientHello messages are
// different, with the exception of the changes allowed before and after a
// HelloRetryRequest. See RFC 8446, Section 4.1.2.
func illegalClientHelloChange(ch, ch1 *clientHelloMsg) bool {
	if len(ch.supportedVersions) != len(ch1.supportedVersions) ||
		len(ch.cipherSuites) != len(ch1.cipherSuites) ||
		len(ch.supportedCurves) != len(ch1.supportedCurves) ||
		len(ch.supportedSignatureAlgorithms) != len(ch1.supportedSignatureAlgorithms) ||
		len(ch.supportedSignatureAlgorithmsCert) != len(ch1.supportedSignatureAlgorithmsCert) ||
		len(ch.alpnProtocols) != len(ch1.alpnProtocols) {
		return true
	}
	for i := range ch.supportedVersions {
		if ch.supportedVersions[i] != ch1.supportedVersions[i] {
			return true
		}
	}
	for i := range ch.cipherSuites {
		if ch.cipherSuites[i] != ch1.cipherSuites[i] {
			return true
		}
	}
	for i := range ch.supportedCurves {
		if ch.supportedCurves[i] != ch1.supportedCurves[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithms {
		if ch.supportedSignatureAlgorithms[i] != ch1.supportedSignatureAlgorithms[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithmsCert {
		if ch.supportedSignatureAlgorithmsCert[i] != ch1.supportedSignatureAlgorithmsCert[i] {
			return true
		}
	}
	for i := range ch.alpnProtocols {
		if ch.alpnProtocols[i] != ch1.alpnProtocols[i] {
			return true
		}
	}
	return ch.vers != ch1.vers ||
		!bytes.Equal(ch.random, ch1.random) ||
		!bytes.Equal(ch.sessionId, ch1.sessionId) ||
		!bytes.Equal(ch.compressionMethods, ch1.compressionMethods) ||
		ch.serverName != ch1.serverName ||
		ch.ocspStapling != ch1.ocspStapling ||
		!bytes.Equal(ch.supportedPoints, ch1.supportedPoints) ||
		ch.ticketSupported != ch1.ticketSupported ||
		!bytes.Equal(ch.sessionTicket, ch1.sessionTicket) ||
		ch.secureRenegotiationSupported != ch1.secureRenegotiationSupported ||
		!bytes.Equal(ch.secureRenegotiation, ch1.secureRenegotiation) ||
		ch.scts != ch1.scts ||
		!bytes.Equal(ch.cookie, ch1.cookie) ||
		!bytes.Equal(ch.pskModes, ch1.pskModes)
}

func (hs *serverHandshakeStateTLS13) sendServerParameters() error {
	c := hs.c

	if hs.echContext != nil {
		copy(hs.hello.random[32-8:], make([]byte, 8))
		echTranscript := cloneHash(hs.transcript, hs.suite.hash)
		echTranscript.Write(hs.clientHello.original)
		if err := transcriptMsg(hs.hello, echTranscript); err != nil {
			return err
		}
		// compute the acceptance message
		acceptConfirmation := tls13.ExpandLabel(hs.suite.hash.New,
			hkdf.Extract(hs.suite.hash.New, hs.clientHello.random, nil),
			"ech accept confirmation",
			echTranscript.Sum(nil),
			8,
		)
		copy(hs.hello.random[32-8:], acceptConfirmation)
	}

	if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil {
		return err
	}

	if _, err := hs.c.writeHandshakeRecord(hs.hello, hs.transcript); err != nil {
		return err
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}

	earlySecret := hs.earlySecret
	if earlySecret == nil {
		earlySecret = tls13.NewEarlySecret(hs.suite.hash.New, nil)
	}
	hs.handshakeSecret = earlySecret.HandshakeSecret(hs.sharedKey)

	clientSecret := hs.handshakeSecret.ClientHandshakeTrafficSecret(hs.transcript)
	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, clientSecret)
	serverSecret := hs.handshakeSecret.ServerHandshakeTrafficSecret(hs.transcript)
	c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, serverSecret)

	if c.quic != nil {
		if c.hand.Len() != 0 {
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelHandshake, hs.suite.id, serverSecret)
		c.quicSetReadSecret(QUICEncryptionLevelHandshake, hs.suite.id, clientSecret)
	}

	err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.clientHello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	encryptedExtensions := new(encryptedExtensionsMsg)
	encryptedExtensions.alpnProtocol = c.clientProtocol

	if c.quic != nil {
		p, err := c.quicGetTransportParameters()
		if err != nil {
			return err
		}
		encryptedExtensions.quicTransportParameters = p
		encryptedExtensions.earlyData = hs.earlyData
	}

	// If client sent ECH extension, but we didn't accept it,
	// send retry configs, if available.
	if len(hs.c.config.EncryptedClientHelloKeys) > 0 && len(hs.clientHello.encryptedClientHello) > 0 && hs.echContext == nil {
		encryptedExtensions.echRetryConfigs, err = buildRetryConfigList(hs.c.config.EncryptedClientHelloKeys)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}

	if _, err := hs.c.writeHandshakeRecord(encryptedExtensions, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) requestClientCert() bool {
	return hs.c.config.ClientAuth >= RequestClientCert && !hs.usingPSK
}

func (hs *serverHandshakeStateTLS13) sendServerCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	if hs.requestClientCert() {
		// Request a client certificate
		certReq := new(certificateRequestMsgTLS13)
		certReq.ocspStapling = true
		certReq.scts = true
		certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}

		if _, err := hs.c.writeHandshakeRecord(certReq, hs.transcript); err != nil {
			return err
		}
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *hs.cert
	certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0

	if _, err := hs.c.writeHandshakeRecord(certMsg, hs.transcript); err != nil {
		return err
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true
	certVerifyMsg.signatureAlgorithm = hs.sigAlg

	sigType, sigHash, err := typeAndHashFromSignatureScheme(hs.sigAlg)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := hs.cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		public := hs.cert.PrivateKey.(crypto.Signer).Public()
		if rsaKey, ok := public.(*rsa.PublicKey); ok && sigType == signatureRSAPSS &&
			rsaKey.N.BitLen()/8 < sigHash.Size()*2+2 { // key too small for RSA-PSS
			c.sendAlert(alertHandshakeFailure)
		} else {
			c.sendAlert(alertInternalError)
		}
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	if _, err := hs.c.writeHandshakeRecord(certVerifyMsg, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) sendServerFinished() error {
	c := hs.c

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}

	if _, err := hs.c.writeHandshakeRecord(finished, hs.transcript); err != nil {
		return err
	}

	// Derive secrets that take context through the server Finished.

	hs.masterSecret = hs.handshakeSecret.MasterSecret()

	hs.trafficSecret = hs.masterSecret.ClientApplicationTrafficSecret(hs.transcript)
	serverSecret := hs.masterSecret.ServerApplicationTrafficSecret(hs.transcript)
	c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, serverSecret)

	if c.quic != nil {
		if c.hand.Len() != 0 {
			// TODO: Handle this in setTrafficSecret?
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelApplication, hs.suite.id, serverSecret)
	}

	err := c.config.writeKeyLog(keyLogLabelClientTraffic, hs.clientHello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	// If we did not request client certificates, at this point we can
	// precompute the client finished and roll the transcript forward to send
	// session tickets in our first flight.
	if !hs.requestClientCert() {
		if err := hs.sendSessionTickets(); err != nil {
			return err
		}
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) shouldSendSessionTickets() bool {
	if hs.c.config.SessionTicketsDisabled {
		return false
	}

	// QUIC tickets are sent by QUICConn.SendSessionTicket, not automatically.
	if hs.c.quic != nil {
		return false
	}

	// Don't send tickets the client wouldn't use. See RFC 8446, Section 4.2.9.
	for _, pskMode := range hs.clientHello.pskModes {
		if pskMode == pskModeDHE {
			return true
		}
	}
	return false
}

func (hs *serverHandshakeStateTLS13) sendSessionTickets() error {
	c := hs.c

	hs.clientFinished = hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	finishedMsg := &finishedMsg{
		verifyData: hs.clientFinished,
	}
	if err := transcriptMsg(finishedMsg, hs.transcript); err != nil {
		return err
	}

	c.resumptionSecret = hs.masterSecret.ResumptionMasterSecret(hs.transcript)

	if !hs.shouldSendSessionTickets() {
		return nil
	}
	return c.sendSessionTicket(false, nil)
}

func (c *Conn) sendSessionTicket(earlyData bool, extra [][]byte) error {
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	if suite == nil {
		return errors.New("tls: internal error: unknown cipher suite")
	}
	// ticket_nonce, which must be unique per connection, is always left at
	// zero because we only ever send one ticket per connection.
	psk := tls13.ExpandLabel(suite.hash.New, c.resumptionSecret, "resumption",
		nil, suite.hash.Size())

	m := new(newSessionTicketMsgTLS13)

	state := c.sessionState()
	state.secret = psk
	state.EarlyData = earlyData
	state.Extra = extra
	if c.config.WrapSession != nil {
		var err error
		m.label, err = c.config.WrapSession(c.connectionStateLocked(), state)
		if err != nil {
			return err
		}
	} else {
		stateBytes, err := state.Bytes()
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		m.label, err = c.config.encryptTicket(stateBytes, c.ticketKeys)
		if err != nil {
			return err
		}
	}
	m.lifetime = uint32(maxSessionTicketLifetime / time.Second)

	// ticket_age_add is a random 32-bit value. See RFC 8446, section 4.6.1
	// The value is not stored anywhere; we never need to check the ticket age
	// because 0-RTT is not supported.
	ageAdd := make([]byte, 4)
	if _, err := c.config.rand().Read(ageAdd); err != nil {
		return err
	}
	m.ageAdd = byteorder.LEUint32(ageAdd)

	if earlyData {
		// RFC 9001, Section 4.6.1
		m.maxEarlyData = 0xffffffff
	}

	if _, err := c.writeHandshakeRecord(m, nil); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) readClientCertificate() error {
	c := hs.c

	if !hs.requestClientCert() {
		// Make sure the connection is still being verified whether or not
		// the server requested a client certificate.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	// If we requested a client certificate, then the client must send a
	// certificate message. I
"""




```