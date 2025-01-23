Response:
The user wants a summary of the functionalities of the provided Go code snippet. This snippet seems to be part of the `crypto/tls` package and defines the `Config` struct, which is central to configuring TLS connections in Go.

Here's a breakdown of the code and its functionalities:

1. **Encrypted Client Hello (ECH):** The code includes fields related to ECH, allowing configuration for both clients and servers.
2. **Session Tickets:** The code handles session ticket management for connection resumption, including key storage, rotation, and setting/getting keys.
3. **Configuration Options:** The `Config` struct holds various TLS configuration options, such as certificates, supported protocols, cipher suites, client authentication settings, etc.
4. **Certificate Handling:**  The code deals with selecting and verifying certificates for both server and client authentication.
5. **Key Logging:** Functionality for writing TLS secrets to a key log for debugging purposes.
6. **Client Session Cache:** An LRU cache implementation for storing client session states.
7. **FIPS 140-3 Compliance:** The code considers FIPS compliance by filtering cipher suites, signature algorithms, and certificate chains.
这是 `go/src/crypto/tls/common.go` 文件的第二个部分，主要功能是完善和支持 TLS 连接的配置和管理。

**主要功能归纳:**

1. **会话票据管理 (Session Tickets):**
    *   提供了存储、管理和轮换会话票据密钥的功能。
    *   `sessionTicketKeys` 和 `autoSessionTicketKeys` 字段用于存储密钥，前者是手动设置的，后者是自动轮换的。
    *   `ticketKeyFromBytes` 函数用于从字节数组创建会话票据密钥。
    *   `ticketKeys` 方法用于获取当前有效的会话票据密钥，并实现了自动轮换逻辑。
    *   `SetSessionTicketKeys` 方法允许手动设置会话票据密钥，并关闭自动轮换。

2. **配置克隆 (Config Cloning):**
    *   `Clone` 方法用于创建 `Config` 对象的浅拷贝，允许安全地并发使用配置。

3. **协议版本支持 (Protocol Version Support):**
    *   `supportedVersions` 方法根据配置和角色（客户端/服务端）返回支持的 TLS 协议版本列表。
    *   `maxSupportedVersion` 方法返回支持的最高 TLS 协议版本。
    *   `supportedVersionsFromMax` 函数根据给定的最大版本号返回支持的协议版本列表。
    *   `mutualVersion` 方法根据双方支持的协议版本协商出共同支持的版本。

4. **椭圆曲线偏好 (Elliptic Curve Preferences):**
    *   `curvePreferences` 方法返回配置的椭圆曲线偏好列表。
    *   `supportsCurve` 方法检查是否支持指定的椭圆曲线。

5. **证书管理和选择 (Certificate Management and Selection):**
    *   `getCertificate` 方法根据 `ClientHelloInfo` 选择最合适的服务器证书。它会考虑 `GetCertificate` 回调函数、`NameToCertificate` 映射以及证书的兼容性。
    *   `SupportsCertificate` 方法用于检查客户端 `ClientHelloInfo` 是否支持给定的服务器证书。
    *   `SupportsCertificate` 方法也用于检查服务端 `CertificateRequestInfo` 是否支持给定的客户端证书。
    *   `BuildNameToCertificate` 方法（已废弃）用于根据证书的 CommonName 和 SubjectAlternateName 构建 `NameToCertificate` 映射。

6. **密钥日志 (Key Logging):**
    *   `writeKeyLog` 方法用于将 TLS 会话密钥信息写入到 `KeyLogWriter`，用于调试和分析。

7. **证书结构体 (Certificate Struct):**
    *   定义了 `Certificate` 结构体，表示一个证书链，包含证书字节数组、私钥、支持的签名算法等信息。
    *   `leaf` 方法用于获取证书链中的叶子证书的 `x509.Certificate` 对象。

8. **握手消息接口 (Handshake Message Interface):**
    *   定义了 `handshakeMessage` 和 `handshakeMessageWithOriginalBytes` 接口，用于抽象 TLS 握手消息的序列化和反序列化。

9. **LRU 客户端会话缓存 (LRU Client Session Cache):**
    *   实现了基于 LRU (Least Recently Used) 策略的客户端会话缓存 `lruSessionCache`。
    *   `NewLRUClientSessionCache` 函数用于创建 LRU 客户端会话缓存。
    *   `Put` 方法用于添加或更新缓存条目。
    *   `Get` 方法用于获取缓存条目。

10. **错误处理 (Error Handling):**
    *   定义了一些错误类型，例如 `unexpectedMessageError` 和 `CertificateVerificationError`。

11. **支持的签名算法 (Supported Signature Algorithms):**
    *   `supportedSignatureAlgorithms` 方法返回支持的签名算法列表。
    *   `isSupportedSignatureAlgorithm` 方法检查给定的签名算法是否在支持列表中。

12. **FIPS 140-3 支持 (FIPS 140-3 Support):**
    *   `fipsAllowedChains` 和 `fipsAllowChain` 以及 `fipsAllowCert` 函数用于过滤符合 FIPS 140-3 标准的证书链和证书。

**代码示例 (会话票据自动轮换):**

```go
package main

import (
	"crypto/tls"
	"fmt"
	"time"
)

func main() {
	config := &tls.Config{}

	// 模拟服务端获取票据密钥
	keys1 := config.ticketKeys(nil)
	fmt.Printf("首次获取票据密钥 (创建时间): %v\n", keys1[0].Created())

	// 等待一段时间，超过 ticketKeyRotation
	time.Sleep(tls.TicketKeyRotation + time.Second)

	// 再次获取票据密钥，触发轮换
	keys2 := config.ticketKeys(nil)
	fmt.Printf("再次获取票据密钥 (创建时间): %v\n", keys2[0].Created())

	// 首次获取的密钥和第二次获取的密钥应该不同
	if keys1[0].Created().Equal(keys2[0].Created()) {
		fmt.Println("票据密钥轮换失败")
	} else {
		fmt.Println("票据密钥已轮换")
	}
}

// 为了演示，需要添加 Created() 方法到 internal/common.go 中的 ticketKey 结构体
// 并重新编译 crypto/tls 包
// func (t ticketKey) Created() time.Time {
// 	return t.created
// }
```

**假设输入与输出:**

在上面的代码示例中，假设 `tls.TicketKeyRotation` 的值为 24 小时。首次调用 `config.ticketKeys(nil)` 会生成一个新的会话票据密钥。等待超过 24 小时后再次调用，由于超过了轮换周期，会生成一个新的密钥并替换旧的密钥。输出会显示两次获取的密钥的创建时间，如果轮换成功，创建时间将会不同。

**使用者易犯错的点:**

在这一部分的代码中，关于会话票据管理，使用者容易犯的错误可能是在多台服务器共享会话票据密钥时没有正确同步密钥。如果密钥不一致，客户端可能无法恢复会话，导致连接失败。

例如，如果两台负载均衡后的服务器使用了不同的 `SessionTicketKey` 或者通过 `SetSessionTicketKeys` 设置了不同的密钥，那么客户端使用第一台服务器的票据尝试连接第二台服务器时将会失败。

总的来说，这部分代码主要负责 `tls.Config` 结构体中关于会话管理、协议版本协商、证书选择和管理等更底层的配置和管理功能，为建立安全的 TLS 连接提供了基础。

### 提示词
```
这是路径为go/src/crypto/tls/common.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
escribed in the final Encrypted Client Hello RFC changes.
	EncryptedClientHelloConfigList []byte

	// EncryptedClientHelloRejectionVerify, if not nil, is called when ECH is
	// rejected by the remote server, in order to verify the ECH provider
	// certificate in the outer ClientHello. If it returns a non-nil error, the
	// handshake is aborted and that error results.
	//
	// On the server side this field is not used.
	//
	// Unlike VerifyPeerCertificate and VerifyConnection, normal certificate
	// verification will not be performed before calling
	// EncryptedClientHelloRejectionVerify.
	//
	// If EncryptedClientHelloRejectionVerify is nil and ECH is rejected, the
	// roots in RootCAs will be used to verify the ECH providers public
	// certificate. VerifyPeerCertificate and VerifyConnection are not called
	// when ECH is rejected, even if set, and InsecureSkipVerify is ignored.
	EncryptedClientHelloRejectionVerify func(ConnectionState) error

	// EncryptedClientHelloKeys are the ECH keys to use when a client
	// attempts ECH.
	//
	// If EncryptedClientHelloKeys is set, MinVersion, if set, must be
	// VersionTLS13.
	//
	// If a client attempts ECH, but it is rejected by the server, the server
	// will send a list of configs to retry based on the set of
	// EncryptedClientHelloKeys which have the SendAsRetry field set.
	//
	// On the client side, this field is ignored. In order to configure ECH for
	// clients, see the EncryptedClientHelloConfigList field.
	EncryptedClientHelloKeys []EncryptedClientHelloKey

	// mutex protects sessionTicketKeys and autoSessionTicketKeys.
	mutex sync.RWMutex
	// sessionTicketKeys contains zero or more ticket keys. If set, it means
	// the keys were set with SessionTicketKey or SetSessionTicketKeys. The
	// first key is used for new tickets and any subsequent keys can be used to
	// decrypt old tickets. The slice contents are not protected by the mutex
	// and are immutable.
	sessionTicketKeys []ticketKey
	// autoSessionTicketKeys is like sessionTicketKeys but is owned by the
	// auto-rotation logic. See Config.ticketKeys.
	autoSessionTicketKeys []ticketKey
}

// EncryptedClientHelloKey holds a private key that is associated
// with a specific ECH config known to a client.
type EncryptedClientHelloKey struct {
	// Config should be a marshalled ECHConfig associated with PrivateKey. This
	// must match the config provided to clients byte-for-byte. The config
	// should only specify the DHKEM(X25519, HKDF-SHA256) KEM ID (0x0020), the
	// HKDF-SHA256 KDF ID (0x0001), and a subset of the following AEAD IDs:
	// AES-128-GCM (0x0000), AES-256-GCM (0x0001), ChaCha20Poly1305 (0x0002).
	Config []byte
	// PrivateKey should be a marshalled private key. Currently, we expect
	// this to be the output of [ecdh.PrivateKey.Bytes].
	PrivateKey []byte
	// SendAsRetry indicates if Config should be sent as part of the list of
	// retry configs when ECH is requested by the client but rejected by the
	// server.
	SendAsRetry bool
}

const (
	// ticketKeyLifetime is how long a ticket key remains valid and can be used to
	// resume a client connection.
	ticketKeyLifetime = 7 * 24 * time.Hour // 7 days

	// ticketKeyRotation is how often the server should rotate the session ticket key
	// that is used for new tickets.
	ticketKeyRotation = 24 * time.Hour
)

// ticketKey is the internal representation of a session ticket key.
type ticketKey struct {
	aesKey  [16]byte
	hmacKey [16]byte
	// created is the time at which this ticket key was created. See Config.ticketKeys.
	created time.Time
}

// ticketKeyFromBytes converts from the external representation of a session
// ticket key to a ticketKey. Externally, session ticket keys are 32 random
// bytes and this function expands that into sufficient name and key material.
func (c *Config) ticketKeyFromBytes(b [32]byte) (key ticketKey) {
	hashed := sha512.Sum512(b[:])
	// The first 16 bytes of the hash used to be exposed on the wire as a ticket
	// prefix. They MUST NOT be used as a secret. In the future, it would make
	// sense to use a proper KDF here, like HKDF with a fixed salt.
	const legacyTicketKeyNameLen = 16
	copy(key.aesKey[:], hashed[legacyTicketKeyNameLen:])
	copy(key.hmacKey[:], hashed[legacyTicketKeyNameLen+len(key.aesKey):])
	key.created = c.time()
	return key
}

// maxSessionTicketLifetime is the maximum allowed lifetime of a TLS 1.3 session
// ticket, and the lifetime we set for all tickets we send.
const maxSessionTicketLifetime = 7 * 24 * time.Hour

// Clone returns a shallow clone of c or nil if c is nil. It is safe to clone a [Config] that is
// being used concurrently by a TLS client or server.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return &Config{
		Rand:                                c.Rand,
		Time:                                c.Time,
		Certificates:                        c.Certificates,
		NameToCertificate:                   c.NameToCertificate,
		GetCertificate:                      c.GetCertificate,
		GetClientCertificate:                c.GetClientCertificate,
		GetConfigForClient:                  c.GetConfigForClient,
		VerifyPeerCertificate:               c.VerifyPeerCertificate,
		VerifyConnection:                    c.VerifyConnection,
		RootCAs:                             c.RootCAs,
		NextProtos:                          c.NextProtos,
		ServerName:                          c.ServerName,
		ClientAuth:                          c.ClientAuth,
		ClientCAs:                           c.ClientCAs,
		InsecureSkipVerify:                  c.InsecureSkipVerify,
		CipherSuites:                        c.CipherSuites,
		PreferServerCipherSuites:            c.PreferServerCipherSuites,
		SessionTicketsDisabled:              c.SessionTicketsDisabled,
		SessionTicketKey:                    c.SessionTicketKey,
		ClientSessionCache:                  c.ClientSessionCache,
		UnwrapSession:                       c.UnwrapSession,
		WrapSession:                         c.WrapSession,
		MinVersion:                          c.MinVersion,
		MaxVersion:                          c.MaxVersion,
		CurvePreferences:                    c.CurvePreferences,
		DynamicRecordSizingDisabled:         c.DynamicRecordSizingDisabled,
		Renegotiation:                       c.Renegotiation,
		KeyLogWriter:                        c.KeyLogWriter,
		EncryptedClientHelloConfigList:      c.EncryptedClientHelloConfigList,
		EncryptedClientHelloRejectionVerify: c.EncryptedClientHelloRejectionVerify,
		EncryptedClientHelloKeys:            c.EncryptedClientHelloKeys,
		sessionTicketKeys:                   c.sessionTicketKeys,
		autoSessionTicketKeys:               c.autoSessionTicketKeys,
	}
}

// deprecatedSessionTicketKey is set as the prefix of SessionTicketKey if it was
// randomized for backwards compatibility but is not in use.
var deprecatedSessionTicketKey = []byte("DEPRECATED")

// initLegacySessionTicketKeyRLocked ensures the legacy SessionTicketKey field is
// randomized if empty, and that sessionTicketKeys is populated from it otherwise.
func (c *Config) initLegacySessionTicketKeyRLocked() {
	// Don't write if SessionTicketKey is already defined as our deprecated string,
	// or if it is defined by the user but sessionTicketKeys is already set.
	if c.SessionTicketKey != [32]byte{} &&
		(bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) || len(c.sessionTicketKeys) > 0) {
		return
	}

	// We need to write some data, so get an exclusive lock and re-check any conditions.
	c.mutex.RUnlock()
	defer c.mutex.RLock()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.SessionTicketKey == [32]byte{} {
		if _, err := io.ReadFull(c.rand(), c.SessionTicketKey[:]); err != nil {
			panic(fmt.Sprintf("tls: unable to generate random session ticket key: %v", err))
		}
		// Write the deprecated prefix at the beginning so we know we created
		// it. This key with the DEPRECATED prefix isn't used as an actual
		// session ticket key, and is only randomized in case the application
		// reuses it for some reason.
		copy(c.SessionTicketKey[:], deprecatedSessionTicketKey)
	} else if !bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) && len(c.sessionTicketKeys) == 0 {
		c.sessionTicketKeys = []ticketKey{c.ticketKeyFromBytes(c.SessionTicketKey)}
	}

}

// ticketKeys returns the ticketKeys for this connection.
// If configForClient has explicitly set keys, those will
// be returned. Otherwise, the keys on c will be used and
// may be rotated if auto-managed.
// During rotation, any expired session ticket keys are deleted from
// c.sessionTicketKeys. If the session ticket key that is currently
// encrypting tickets (ie. the first ticketKey in c.sessionTicketKeys)
// is not fresh, then a new session ticket key will be
// created and prepended to c.sessionTicketKeys.
func (c *Config) ticketKeys(configForClient *Config) []ticketKey {
	// If the ConfigForClient callback returned a Config with explicitly set
	// keys, use those, otherwise just use the original Config.
	if configForClient != nil {
		configForClient.mutex.RLock()
		if configForClient.SessionTicketsDisabled {
			return nil
		}
		configForClient.initLegacySessionTicketKeyRLocked()
		if len(configForClient.sessionTicketKeys) != 0 {
			ret := configForClient.sessionTicketKeys
			configForClient.mutex.RUnlock()
			return ret
		}
		configForClient.mutex.RUnlock()
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if c.SessionTicketsDisabled {
		return nil
	}
	c.initLegacySessionTicketKeyRLocked()
	if len(c.sessionTicketKeys) != 0 {
		return c.sessionTicketKeys
	}
	// Fast path for the common case where the key is fresh enough.
	if len(c.autoSessionTicketKeys) > 0 && c.time().Sub(c.autoSessionTicketKeys[0].created) < ticketKeyRotation {
		return c.autoSessionTicketKeys
	}

	// autoSessionTicketKeys are managed by auto-rotation.
	c.mutex.RUnlock()
	defer c.mutex.RLock()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// Re-check the condition in case it changed since obtaining the new lock.
	if len(c.autoSessionTicketKeys) == 0 || c.time().Sub(c.autoSessionTicketKeys[0].created) >= ticketKeyRotation {
		var newKey [32]byte
		if _, err := io.ReadFull(c.rand(), newKey[:]); err != nil {
			panic(fmt.Sprintf("unable to generate random session ticket key: %v", err))
		}
		valid := make([]ticketKey, 0, len(c.autoSessionTicketKeys)+1)
		valid = append(valid, c.ticketKeyFromBytes(newKey))
		for _, k := range c.autoSessionTicketKeys {
			// While rotating the current key, also remove any expired ones.
			if c.time().Sub(k.created) < ticketKeyLifetime {
				valid = append(valid, k)
			}
		}
		c.autoSessionTicketKeys = valid
	}
	return c.autoSessionTicketKeys
}

// SetSessionTicketKeys updates the session ticket keys for a server.
//
// The first key will be used when creating new tickets, while all keys can be
// used for decrypting tickets. It is safe to call this function while the
// server is running in order to rotate the session ticket keys. The function
// will panic if keys is empty.
//
// Calling this function will turn off automatic session ticket key rotation.
//
// If multiple servers are terminating connections for the same host they should
// all have the same session ticket keys. If the session ticket keys leaks,
// previously recorded and future TLS connections using those keys might be
// compromised.
func (c *Config) SetSessionTicketKeys(keys [][32]byte) {
	if len(keys) == 0 {
		panic("tls: keys must have at least one key")
	}

	newKeys := make([]ticketKey, len(keys))
	for i, bytes := range keys {
		newKeys[i] = c.ticketKeyFromBytes(bytes)
	}

	c.mutex.Lock()
	c.sessionTicketKeys = newKeys
	c.mutex.Unlock()
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	if c.CipherSuites == nil {
		if fips140tls.Required() {
			return defaultCipherSuitesFIPS
		}
		return defaultCipherSuites()
	}
	if fips140tls.Required() {
		cipherSuites := slices.Clone(c.CipherSuites)
		return slices.DeleteFunc(cipherSuites, func(id uint16) bool {
			return !slices.Contains(defaultCipherSuitesFIPS, id)
		})
	}
	return c.CipherSuites
}

var supportedVersions = []uint16{
	VersionTLS13,
	VersionTLS12,
	VersionTLS11,
	VersionTLS10,
}

// roleClient and roleServer are meant to call supportedVersions and parents
// with more readability at the callsite.
const roleClient = true
const roleServer = false

var tls10server = godebug.New("tls10server")

func (c *Config) supportedVersions(isClient bool) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if fips140tls.Required() && !slices.Contains(defaultSupportedVersionsFIPS, v) {
			continue
		}
		if (c == nil || c.MinVersion == 0) && v < VersionTLS12 {
			if isClient || tls10server.Value() != "1" {
				continue
			}
		}
		if isClient && c.EncryptedClientHelloConfigList != nil && v < VersionTLS13 {
			continue
		}
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

func (c *Config) maxSupportedVersion(isClient bool) uint16 {
	supportedVersions := c.supportedVersions(isClient)
	if len(supportedVersions) == 0 {
		return 0
	}
	return supportedVersions[0]
}

// supportedVersionsFromMax returns a list of supported versions derived from a
// legacy maximum version value. Note that only versions supported by this
// library are returned. Any newer peer will use supportedVersions anyway.
func supportedVersionsFromMax(maxVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if v > maxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

func (c *Config) curvePreferences(version uint16) []CurveID {
	var curvePreferences []CurveID
	if fips140tls.Required() {
		curvePreferences = slices.Clone(defaultCurvePreferencesFIPS)
	} else {
		curvePreferences = defaultCurvePreferences()
	}
	if c != nil && len(c.CurvePreferences) != 0 {
		curvePreferences = slices.DeleteFunc(curvePreferences, func(x CurveID) bool {
			return !slices.Contains(c.CurvePreferences, x)
		})
	}
	if version < VersionTLS13 {
		curvePreferences = slices.DeleteFunc(curvePreferences, isTLS13OnlyKeyExchange)
	}
	return curvePreferences
}

func (c *Config) supportsCurve(version uint16, curve CurveID) bool {
	for _, cc := range c.curvePreferences(version) {
		if cc == curve {
			return true
		}
	}
	return false
}

// mutualVersion returns the protocol version to use given the advertised
// versions of the peer. Priority is given to the peer preference order.
func (c *Config) mutualVersion(isClient bool, peerVersions []uint16) (uint16, bool) {
	supportedVersions := c.supportedVersions(isClient)
	for _, peerVersion := range peerVersions {
		for _, v := range supportedVersions {
			if v == peerVersion {
				return v, true
			}
		}
	}
	return 0, false
}

// errNoCertificates should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/xtls/xray-core
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname errNoCertificates
var errNoCertificates = errors.New("tls: no certificates configured")

// getCertificate returns the best certificate for the given ClientHelloInfo,
// defaulting to the first element of c.Certificates.
func (c *Config) getCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
	if c.GetCertificate != nil &&
		(len(c.Certificates) == 0 || len(clientHello.ServerName) > 0) {
		cert, err := c.GetCertificate(clientHello)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if len(c.Certificates) == 0 {
		return nil, errNoCertificates
	}

	if len(c.Certificates) == 1 {
		// There's only one choice, so no point doing any work.
		return &c.Certificates[0], nil
	}

	if c.NameToCertificate != nil {
		name := strings.ToLower(clientHello.ServerName)
		if cert, ok := c.NameToCertificate[name]; ok {
			return cert, nil
		}
		if len(name) > 0 {
			labels := strings.Split(name, ".")
			labels[0] = "*"
			wildcardName := strings.Join(labels, ".")
			if cert, ok := c.NameToCertificate[wildcardName]; ok {
				return cert, nil
			}
		}
	}

	for _, cert := range c.Certificates {
		if err := clientHello.SupportsCertificate(&cert); err == nil {
			return &cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return &c.Certificates[0], nil
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the client that sent the ClientHello. Otherwise, it returns an error
// describing the reason for the incompatibility.
//
// If this [ClientHelloInfo] was passed to a GetConfigForClient or GetCertificate
// callback, this method will take into account the associated [Config]. Note that
// if GetConfigForClient returns a different [Config], the change can't be
// accounted for by this method.
//
// This function will call x509.ParseCertificate unless c.Leaf is set, which can
// incur a significant performance cost.
func (chi *ClientHelloInfo) SupportsCertificate(c *Certificate) error {
	// Note we don't currently support certificate_authorities nor
	// signature_algorithms_cert, and don't check the algorithms of the
	// signatures on the chain (which anyway are a SHOULD, see RFC 8446,
	// Section 4.4.2.2).

	config := chi.config
	if config == nil {
		config = &Config{}
	}
	vers, ok := config.mutualVersion(roleServer, chi.SupportedVersions)
	if !ok {
		return errors.New("no mutually supported protocol versions")
	}

	// If the client specified the name they are trying to connect to, the
	// certificate needs to be valid for it.
	if chi.ServerName != "" {
		x509Cert, err := c.leaf()
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		if err := x509Cert.VerifyHostname(chi.ServerName); err != nil {
			return fmt.Errorf("certificate is not valid for requested server name: %w", err)
		}
	}

	// supportsRSAFallback returns nil if the certificate and connection support
	// the static RSA key exchange, and unsupported otherwise. The logic for
	// supporting static RSA is completely disjoint from the logic for
	// supporting signed key exchanges, so we just check it as a fallback.
	supportsRSAFallback := func(unsupported error) error {
		// TLS 1.3 dropped support for the static RSA key exchange.
		if vers == VersionTLS13 {
			return unsupported
		}
		// The static RSA key exchange works by decrypting a challenge with the
		// RSA private key, not by signing, so check the PrivateKey implements
		// crypto.Decrypter, like *rsa.PrivateKey does.
		if priv, ok := c.PrivateKey.(crypto.Decrypter); ok {
			if _, ok := priv.Public().(*rsa.PublicKey); !ok {
				return unsupported
			}
		} else {
			return unsupported
		}
		// Finally, there needs to be a mutual cipher suite that uses the static
		// RSA key exchange instead of ECDHE.
		rsaCipherSuite := selectCipherSuite(chi.CipherSuites, config.cipherSuites(), func(c *cipherSuite) bool {
			if c.flags&suiteECDHE != 0 {
				return false
			}
			if vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
				return false
			}
			return true
		})
		if rsaCipherSuite == nil {
			return unsupported
		}
		return nil
	}

	// If the client sent the signature_algorithms extension, ensure it supports
	// schemes we can use with this certificate and TLS version.
	if len(chi.SignatureSchemes) > 0 {
		if _, err := selectSignatureScheme(vers, c, chi.SignatureSchemes); err != nil {
			return supportsRSAFallback(err)
		}
	}

	// In TLS 1.3 we are done because supported_groups is only relevant to the
	// ECDHE computation, point format negotiation is removed, cipher suites are
	// only relevant to the AEAD choice, and static RSA does not exist.
	if vers == VersionTLS13 {
		return nil
	}

	// The only signed key exchange we support is ECDHE.
	if !supportsECDHE(config, vers, chi.SupportedCurves, chi.SupportedPoints) {
		return supportsRSAFallback(errors.New("client doesn't support ECDHE, can only use legacy RSA key exchange"))
	}

	var ecdsaCipherSuite bool
	if priv, ok := c.PrivateKey.(crypto.Signer); ok {
		switch pub := priv.Public().(type) {
		case *ecdsa.PublicKey:
			var curve CurveID
			switch pub.Curve {
			case elliptic.P256():
				curve = CurveP256
			case elliptic.P384():
				curve = CurveP384
			case elliptic.P521():
				curve = CurveP521
			default:
				return supportsRSAFallback(unsupportedCertificateError(c))
			}
			var curveOk bool
			for _, c := range chi.SupportedCurves {
				if c == curve && config.supportsCurve(vers, c) {
					curveOk = true
					break
				}
			}
			if !curveOk {
				return errors.New("client doesn't support certificate curve")
			}
			ecdsaCipherSuite = true
		case ed25519.PublicKey:
			if vers < VersionTLS12 || len(chi.SignatureSchemes) == 0 {
				return errors.New("connection doesn't support Ed25519")
			}
			ecdsaCipherSuite = true
		case *rsa.PublicKey:
		default:
			return supportsRSAFallback(unsupportedCertificateError(c))
		}
	} else {
		return supportsRSAFallback(unsupportedCertificateError(c))
	}

	// Make sure that there is a mutually supported cipher suite that works with
	// this certificate. Cipher suite selection will then apply the logic in
	// reverse to pick it. See also serverHandshakeState.cipherSuiteOk.
	cipherSuite := selectCipherSuite(chi.CipherSuites, config.cipherSuites(), func(c *cipherSuite) bool {
		if c.flags&suiteECDHE == 0 {
			return false
		}
		if c.flags&suiteECSign != 0 {
			if !ecdsaCipherSuite {
				return false
			}
		} else {
			if ecdsaCipherSuite {
				return false
			}
		}
		if vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
			return false
		}
		return true
	})
	if cipherSuite == nil {
		return supportsRSAFallback(errors.New("client doesn't support any cipher suites compatible with the certificate"))
	}

	return nil
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the server that sent the CertificateRequest. Otherwise, it returns an error
// describing the reason for the incompatibility.
func (cri *CertificateRequestInfo) SupportsCertificate(c *Certificate) error {
	if _, err := selectSignatureScheme(cri.Version, c, cri.SignatureSchemes); err != nil {
		return err
	}

	if len(cri.AcceptableCAs) == 0 {
		return nil
	}

	for j, cert := range c.Certificate {
		x509Cert := c.Leaf
		// Parse the certificate if this isn't the leaf node, or if
		// chain.Leaf was nil.
		if j != 0 || x509Cert == nil {
			var err error
			if x509Cert, err = x509.ParseCertificate(cert); err != nil {
				return fmt.Errorf("failed to parse certificate #%d in the chain: %w", j, err)
			}
		}

		for _, ca := range cri.AcceptableCAs {
			if bytes.Equal(x509Cert.RawIssuer, ca) {
				return nil
			}
		}
	}
	return errors.New("chain is not signed by an acceptable CA")
}

// BuildNameToCertificate parses c.Certificates and builds c.NameToCertificate
// from the CommonName and SubjectAlternateName fields of each of the leaf
// certificates.
//
// Deprecated: NameToCertificate only allows associating a single certificate
// with a given name. Leave that field nil to let the library select the first
// compatible chain from Certificates.
func (c *Config) BuildNameToCertificate() {
	c.NameToCertificate = make(map[string]*Certificate)
	for i := range c.Certificates {
		cert := &c.Certificates[i]
		x509Cert, err := cert.leaf()
		if err != nil {
			continue
		}
		// If SANs are *not* present, some clients will consider the certificate
		// valid for the name in the Common Name.
		if x509Cert.Subject.CommonName != "" && len(x509Cert.DNSNames) == 0 {
			c.NameToCertificate[x509Cert.Subject.CommonName] = cert
		}
		for _, san := range x509Cert.DNSNames {
			c.NameToCertificate[san] = cert
		}
	}
}

const (
	keyLogLabelTLS12           = "CLIENT_RANDOM"
	keyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	keyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
)

func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error {
	if c.KeyLogWriter == nil {
		return nil
	}

	logLine := fmt.Appendf(nil, "%s %x %x\n", label, clientRandom, secret)

	writerMutex.Lock()
	_, err := c.KeyLogWriter.Write(logLine)
	writerMutex.Unlock()

	return err
}

// writerMutex protects all KeyLogWriters globally. It is rarely enabled,
// and is only for debugging, so a global mutex saves space.
var writerMutex sync.Mutex

// A Certificate is a chain of one or more certificates, leaf first.
type Certificate struct {
	Certificate [][]byte
	// PrivateKey contains the private key corresponding to the public key in
	// Leaf. This must implement crypto.Signer with an RSA, ECDSA or Ed25519 PublicKey.
	// For a server up to TLS 1.2, it can also implement crypto.Decrypter with
	// an RSA PublicKey.
	PrivateKey crypto.PrivateKey
	// SupportedSignatureAlgorithms is an optional list restricting what
	// signature algorithms the PrivateKey can be used for.
	SupportedSignatureAlgorithms []SignatureScheme
	// OCSPStaple contains an optional OCSP response which will be served
	// to clients that request it.
	OCSPStaple []byte
	// SignedCertificateTimestamps contains an optional list of Signed
	// Certificate Timestamps which will be served to clients that request it.
	SignedCertificateTimestamps [][]byte
	// Leaf is the parsed form of the leaf certificate, which may be initialized
	// using x509.ParseCertificate to reduce per-handshake processing. If nil,
	// the leaf certificate will be parsed as needed.
	Leaf *x509.Certificate
}

// leaf returns the parsed leaf certificate, either from c.Leaf or by parsing
// the corresponding c.Certificate[0].
func (c *Certificate) leaf() (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal([]byte) bool
}

type handshakeMessageWithOriginalBytes interface {
	handshakeMessage

	// originalBytes should return the original bytes that were passed to
	// unmarshal to create the message. If the message was not produced by
	// unmarshal, it should return nil.
	originalBytes() []byte
}

// lruSessionCache is a ClientSessionCache implementation that uses an LRU
// caching strategy.
type lruSessionCache struct {
	sync.Mutex

	m        map[string]*list.Element
	q        *list.List
	capacity int
}

type lruSessionCacheEntry struct {
	sessionKey string
	state      *ClientSessionState
}

// NewLRUClientSessionCache returns a [ClientSessionCache] with the given
// capacity that uses an LRU strategy. If capacity is < 1, a default capacity
// is used instead.
func NewLRUClientSessionCache(capacity int) ClientSessionCache {
	const defaultSessionCacheCapacity = 64

	if capacity < 1 {
		capacity = defaultSessionCacheCapacity
	}
	return &lruSessionCache{
		m:        make(map[string]*list.Element),
		q:        list.New(),
		capacity: capacity,
	}
}

// Put adds the provided (sessionKey, cs) pair to the cache. If cs is nil, the entry
// corresponding to sessionKey is removed from the cache instead.
func (c *lruSessionCache) Put(sessionKey string, cs *ClientSessionState) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		if cs == nil {
			c.q.Remove(elem)
			delete(c.m, sessionKey)
		} else {
			entry := elem.Value.(*lruSessionCacheEntry)
			entry.state = cs
			c.q.MoveToFront(elem)
		}
		return
	}

	if c.q.Len() < c.capacity {
		entry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(entry)
		return
	}

	elem := c.q.Back()
	entry := elem.Value.(*lruSessionCacheEntry)
	delete(c.m, entry.sessionKey)
	entry.sessionKey = sessionKey
	entry.state = cs
	c.q.MoveToFront(elem)
	c.m[sessionKey] = elem
}

// Get returns the [ClientSessionState] value associated with a given key. It
// returns (nil, false) if no value is found.
func (c *lruSessionCache) Get(sessionKey string) (*ClientSessionState, bool) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		c.q.MoveToFront(elem)
		return elem.Value.(*lruSessionCacheEntry).state, true
	}
	return nil, false
}

var emptyConfig Config

func defaultConfig() *Config {
	return &emptyConfig
}

func unexpectedMessageError(wanted, got any) error {
	return fmt.Errorf("tls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

// supportedSignatureAlgorithms returns the supported signature algorithms.
func supportedSignatureAlgorithms() []SignatureScheme {
	if !fips140tls.Required() {
		return defaultSupportedSignatureAlgorithms
	}
	return defaultSupportedSignatureAlgorithmsFIPS
}

func isSupportedSignatureAlgorithm(sigAlg SignatureScheme, supportedSignatureAlgorithms []SignatureScheme) bool {
	for _, s := range supportedSignatureAlgorithms {
		if s == sigAlg {
			return true
		}
	}
	return false
}

// CertificateVerificationError is returned when certificate verification fails during the handshake.
type CertificateVerificationError struct {
	// UnverifiedCertificates and its contents should not be modified.
	UnverifiedCertificates []*x509.Certificate
	Err                    error
}

func (e *CertificateVerificationError) Error() string {
	return fmt.Sprintf("tls: failed to verify certificate: %s", e.Err)
}

func (e *CertificateVerificationError) Unwrap() error {
	return e.Err
}

// fipsAllowedChains returns chains that are allowed to be used in a TLS connection
// based on the current fips140tls enforcement setting.
//
// If fips140tls is not required, the chains are returned as-is with no processing.
// Otherwise, the returned chains are filtered to only those allowed by FIPS 140-3.
// If this results in no chains it returns an error.
func fipsAllowedChains(chains [][]*x509.Certificate) ([][]*x509.Certificate, error) {
	if !fips140tls.Required() {
		return chains, nil
	}

	permittedChains := make([][]*x509.Certificate, 0, len(chains))
	for _, chain := range chains {
		if fipsAllowChain(chain) {
			permittedChains = append(permittedChains, chain)
		}
	}

	if len(permittedChains) == 0 {
		return nil, errors.New("tls: no FIPS compatible certificate chains found")
	}

	return permittedChains, nil
}

func fipsAllowChain(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}

	for _, cert := range chain {
		if !fipsAllowCert(cert) {
			return false
		}
	}

	return true
}

func fipsAllowCert(c *x509.Certificate) bool {
	// The key must be RSA 2048, RSA 3072, RSA 4096,
	// or ECDSA P-256, P-384, P-521.
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		size := k.N.BitLen()
		return size == 2048 || size == 3072 || size == 4096
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	}

	return false
}
```