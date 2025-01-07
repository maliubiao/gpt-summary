Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The initial comment "// TLS low level connection and record layer" immediately tells us this code deals with the fundamental aspects of TLS communication, specifically the "record layer." This layer is responsible for framing, encrypting, and decrypting data.

2. **Scan for Key Data Structures:**  The `Conn` struct is central. We need to understand its fields:
    * `net.Conn`: The underlying network connection. This confirms it's about TLS over a regular network connection.
    * `isClient`:  Indicates client or server mode.
    * `handshakeFn`:  Pointers to handshake functions (client/server).
    * `quic`:  A pointer related to QUIC, indicating support for that protocol.
    * Various fields related to handshake state (`isHandshakeComplete`, `handshakeMutex`, `handshakeErr`, `vers`, `config`, etc.). These are crucial for understanding the TLS negotiation process.
    * Cipher suite and keying material related fields (`cipherSuite`, `curveID`, `ekm`, `resumptionSecret`, `ticketKeys`). These point to the cryptographic operations.
    * Input/output buffers (`in`, `out`, `rawInput`, `input`, `hand`, `buffering`, `sendBuf`). These are vital for understanding how data is processed.
    * Counters (`bytesSent`, `packetsSent`).
    * Error tracking (`closeNotifyErr`).

3. **Analyze Key Methods:**  Focus on the methods associated with the `Conn` struct:
    * Methods implementing `net.Conn` (`LocalAddr`, `RemoteAddr`, `SetDeadline`, etc.): These show the `Conn` adheres to standard network connection behavior.
    * `NetConn()`: Allows access to the underlying connection, but warns against direct manipulation.
    * `readRecord`, `readRecordOrCCS`, `writeRecordLocked`: These are clearly the core functions for reading and writing TLS records. The "CCS" part hints at "Change Cipher Spec."
    * `decrypt`, `encrypt`: These are the cryptographic heart of the record layer.
    * `sendAlert`, `sendAlertLocked`:  Methods for sending TLS alerts.
    * `maxPayloadSizeForWrite`:  Deals with optimizing record size.

4. **Dive into the `halfConn` Struct:**  This struct is used within `Conn` for the input (`in`) and output (`out`). Its fields are essential for understanding the encryption/decryption process:
    * `sync.Mutex`:  Indicates thread-safety.
    * `err`:  Stores errors.
    * `version`, `cipher`, `mac`, `seq`: These are the cryptographic parameters for a particular direction of the connection.
    * `nextCipher`, `nextMac`:  Used during the "Change Cipher Spec" process.
    * `level`, `trafficSecret`:  Fields related to TLS 1.3 and QUIC.

5. **Trace the Data Flow (Mentally or with Simple Diagrams):** Imagine the journey of data:
    * Network connection -> `rawInput` -> `decrypt` -> `input` (for reading)
    * Data to write -> `encrypt` -> formatted record -> network connection (via `writeRecordLocked`)

6. **Identify Key Concepts and Functionalities:** Based on the structures and methods, we can deduce:
    * **TLS Record Processing:**  The code handles the reading, decryption, encryption, and writing of TLS records.
    * **Handshake Management:** The `Conn` struct and related methods manage the TLS handshake process (though the specific handshake logic isn't in this snippet).
    * **Cipher Suite Negotiation:**  Fields like `cipherSuite` and methods related to encryption/decryption point to the selection and use of encryption algorithms.
    * **Authentication:** The presence of MAC (Message Authentication Code) and AEAD (Authenticated Encryption with Associated Data) indicates mechanisms for data integrity and authenticity.
    * **Version Negotiation:** The `vers` field and checks in `readRecord` show that the code handles different TLS versions.
    * **Error Handling:**  The code uses specific alert types for signaling errors.
    * **Record Size Optimization:** The `maxPayloadSizeForWrite` function addresses performance considerations related to record sizing.
    * **QUIC Support:** The `quic` field indicates support for the QUIC protocol as an alternative transport.

7. **Consider Potential Issues (Based on the Code):**
    * **Incorrect `net.Conn` Usage:** The warning in `NetConn()` highlights a common pitfall.
    * **Handshake Errors:** The `handshakeErr` field suggests that errors can occur during the TLS handshake.
    * **Record Overflow:** Checks in `readRecord` prevent overly large records.
    * **Unexpected Messages:**  The code validates record types to prevent unexpected data.
    * **Sequence Number Handling:** The `incSeq` method and its panic condition suggest the importance of sequence numbers in preventing replay attacks.

8. **Structure the Summary:** Organize the findings into logical categories, such as core functionalities, data flow, error handling, etc. Use clear and concise language. Since this is part 1, focus on the overall responsibilities.

9. **Refine and Iterate:**  Review the summary and ensure it accurately reflects the code's purpose and functionality. Look for areas that could be clearer or more detailed.

By following this systematic approach, we can effectively analyze and understand the functionality of a complex code snippet like this. The key is to start with the big picture and gradually drill down into the details, while constantly relating the parts back to the overall goal.
这段Go语言代码是 `crypto/tls` 包中 `conn.go` 文件的一部分，它实现了 **TLS 连接的底层处理和记录层** 的核心功能。 简单来说，它负责 TLS 连接建立后，对实际传输的应用数据进行加密、解密，以及处理 TLS 协议的控制消息（如握手消息、告警消息等）。

**功能归纳：**

1. **TLS 连接管理:**  `Conn` 结构体代表一个 TLS 连接，包含了底层网络连接 (`net.Conn`)、连接状态（如是否是客户端、握手是否完成）、配置信息 (`Config`) 等。
2. **记录层处理:** 负责将应用数据分割成 TLS 记录，并对这些记录进行加密、添加 MAC (Message Authentication Code) 或 AEAD (Authenticated Encryption with Associated Data)，以及在接收时进行解密和验证。
3. **加密与解密:**  `halfConn` 结构体负责单方向（发送或接收）的加密和解密操作。 它维护了加密算法 (`cipher`)、MAC 算法 (`mac`)、序列号 (`seq`) 等状态。
4. **TLS 握手支持:** 虽然这段代码本身不包含完整的握手逻辑，但它提供了支持握手的机制，例如存储握手数据 (`hand`)，以及在握手过程中管理加密状态的切换 (`prepareCipherSpec`, `changeCipherSpec`)。
5. **TLS 协议支持:**  代码中涉及到 TLS 版本号 (`vers`) 的处理，以及对不同 TLS 版本特性的支持，例如 TLS 1.3 的处理。
6. **告警处理:**  可以发送和接收 TLS 告警消息 (`sendAlert`, `readRecordOrCCS` 中对 `recordTypeAlert` 的处理)。
7. **数据缓冲:**  可以进行数据缓冲 (`buffering`, `sendBuf`)，用于批量发送数据。
8. **错误处理:**  定义了 `permanentError` 和 `RecordHeaderError` 等错误类型，用于处理连接过程中出现的错误。
9. **性能优化:**  `maxPayloadSizeForWrite` 函数尝试根据网络状况动态调整发送记录的最大载荷大小，以优化性能。

**Go 代码举例说明 (记录层加解密)：**

假设我们已经建立了一个 TLS 连接 `conn`，并且协商好了加密算法和密钥。以下代码演示了如何使用 `halfConn` (conn.out 代表发送方向，conn.in 代表接收方向) 进行数据加密和解密。

**加密示例 (发送数据):**

```go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/rand"
	"fmt"
	"hash"
	"io"
	"log"
)

func main() {
	// 假设 conn 是一个已经建立的 *tls.Conn
	// 这里为了演示，手动创建一个 halfConn 并设置加密参数
	block, err := aes.NewCipher([]byte("thisis32bitlongkeyforAES256"))
	if err != nil {
		log.Fatal(err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	var conn tls.Conn
	conn.out.cipher = aesGCM
	conn.out.version = tls.VersionTLS12 // 假设是 TLS 1.2

	payload := []byte("Hello, TLS!")
	recordHeader := []byte{tls.RecordTypeApplicationData, 0x03, 0x03, 0x00, 0x00} // 假设是 TLS 1.2 应用数据

	encryptedRecord, err := conn.out.Encrypt(recordHeader, payload, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("加密后的记录: %x\n", encryptedRecord)
}
```

**假设输入与输出 (加密):**

* **假设输入:**
    * `payload`: `[]byte("Hello, TLS!")`
    * 加密算法为 AES-GCM
    * TLS 版本为 1.2

* **可能的输出:**  (输出会因为随机 nonce 而不同)
    * `加密后的记录`:  例如 `1703030019...` (开头的 `17` 是 `tls.RecordTypeApplicationData`，`0303` 是 TLS 版本，后面的长度和加密数据)

**解密示例 (接收数据):**

```go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"hash"
	"log"
)

func main() {
	// 假设 conn 是一个已经建立的 *tls.Conn
	// 这里为了演示，手动创建一个 halfConn 并设置解密参数
	block, err := aes.NewCipher([]byte("thisis32bitlongkeyforAES256"))
	if err != nil {
		log.Fatal(err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	var conn tls.Conn
	conn.in.cipher = aesGCM
	conn.in.version = tls.VersionTLS12 // 假设是 TLS 1.2

	encryptedRecord := []byte{0x17, 0x03, 0x03, 0x00, 0x19, /* 加密数据 */ } // 假设接收到的加密记录，省略具体加密数据
	// 为了演示，手动构造一个包含加密数据的 record 切片
	// 注意：实际使用中，encryptedRecord 的内容会由网络读取得到
	record := make([]byte, len(encryptedRecord))
	copy(record, encryptedRecord)

	plaintext, recordType, err := conn.in.Decrypt(record)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("解密后的数据: %s\n", plaintext)
	fmt.Printf("记录类型: %v\n", recordType)
}
```

**假设输入与输出 (解密):**

* **假设输入:**
    * `encryptedRecord`:  一个包含 TLS 加密数据的字节切片，例如 `[]byte{0x17, 0x03, 0x03, 0x00, 0x19, /* ... 加密后的数据 ... */}`
    * 解密算法为 AES-GCM
    * TLS 版本为 1.2

* **可能的输出:**
    * `解密后的数据: Hello, TLS!`
    * `记录类型: applicationData`

**命令行参数处理：**

这段代码本身不直接处理命令行参数。TLS 连接的配置通常在创建 `tls.Config` 结构体时进行设置，例如指定支持的协议版本、密码套件、证书等。这些配置信息会在创建 `tls.Conn` 时传入。

**使用者易犯错的点：**

1. **直接操作 `NetConn()` 返回的连接:**  代码中明确注释了 "Note that writing to or reading from this connection directly will corrupt the TLS session."  使用者容易忽略这一点，直接使用底层连接进行读写，导致 TLS 状态混乱。
2. **不正确的并发访问:**  `Conn` 结构体中的一些字段需要通过互斥锁 (`sync.Mutex`) 保护，例如 `in` 和 `out` 中的状态。如果多个 goroutine 不正确地并发访问和修改这些状态，会导致数据竞争和不可预测的行为。
3. **忽略错误处理:**  TLS 操作可能会返回错误，例如握手失败、解密失败等。使用者必须正确处理这些错误，否则可能导致连接异常或安全漏洞。
4. **对 `halfConn` 的状态理解不足:**  `halfConn` 维护了加密状态，使用者需要理解在 TLS 握手的不同阶段，`halfConn` 的状态是如何变化的，以及如何正确使用 `prepareCipherSpec` 和 `changeCipherSpec`。

这就是 `go/src/crypto/tls/conn.go` 文件一部分的功能概述。它专注于 TLS 连接的底层细节，为上层提供可靠的安全通信基础。

Prompt: 
```
这是路径为go/src/crypto/tls/conn.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TLS low level connection and record layer

package tls

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"internal/godebug"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// A Conn represents a secured connection.
// It implements the net.Conn interface.
type Conn struct {
	// constant
	conn        net.Conn
	isClient    bool
	handshakeFn func(context.Context) error // (*Conn).clientHandshake or serverHandshake
	quic        *quicState                  // nil for non-QUIC connections

	// isHandshakeComplete is true if the connection is currently transferring
	// application data (i.e. is not currently processing a handshake).
	// isHandshakeComplete is true implies handshakeErr == nil.
	isHandshakeComplete atomic.Bool
	// constant after handshake; protected by handshakeMutex
	handshakeMutex sync.Mutex
	handshakeErr   error   // error resulting from handshake
	vers           uint16  // TLS version
	haveVers       bool    // version has been negotiated
	config         *Config // configuration passed to constructor
	// handshakes counts the number of handshakes performed on the
	// connection so far. If renegotiation is disabled then this is either
	// zero or one.
	handshakes       int
	extMasterSecret  bool
	didResume        bool // whether this connection was a session resumption
	didHRR           bool // whether a HelloRetryRequest was sent/received
	cipherSuite      uint16
	curveID          CurveID
	ocspResponse     []byte   // stapled OCSP response
	scts             [][]byte // signed certificate timestamps from server
	peerCertificates []*x509.Certificate
	// activeCertHandles contains the cache handles to certificates in
	// peerCertificates that are used to track active references.
	activeCertHandles []*activeCert
	// verifiedChains contains the certificate chains that we built, as
	// opposed to the ones presented by the server.
	verifiedChains [][]*x509.Certificate
	// serverName contains the server name indicated by the client, if any.
	serverName string
	// secureRenegotiation is true if the server echoed the secure
	// renegotiation extension. (This is meaningless as a server because
	// renegotiation is not supported in that case.)
	secureRenegotiation bool
	// ekm is a closure for exporting keying material.
	ekm func(label string, context []byte, length int) ([]byte, error)
	// resumptionSecret is the resumption_master_secret for handling
	// or sending NewSessionTicket messages.
	resumptionSecret []byte
	echAccepted      bool

	// ticketKeys is the set of active session ticket keys for this
	// connection. The first one is used to encrypt new tickets and
	// all are tried to decrypt tickets.
	ticketKeys []ticketKey

	// clientFinishedIsFirst is true if the client sent the first Finished
	// message during the most recent handshake. This is recorded because
	// the first transmitted Finished message is the tls-unique
	// channel-binding value.
	clientFinishedIsFirst bool

	// closeNotifyErr is any error from sending the alertCloseNotify record.
	closeNotifyErr error
	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent bool

	// clientFinished and serverFinished contain the Finished message sent
	// by the client or server in the most recent handshake. This is
	// retained to support the renegotiation extension and tls-unique
	// channel-binding.
	clientFinished [12]byte
	serverFinished [12]byte

	// clientProtocol is the negotiated ALPN protocol.
	clientProtocol string

	// input/output
	in, out   halfConn
	rawInput  bytes.Buffer // raw input, starting with a record header
	input     bytes.Reader // application data waiting to be read, from rawInput.Next
	hand      bytes.Buffer // handshake data waiting to be read
	buffering bool         // whether records are buffered in sendBuf
	sendBuf   []byte       // a buffer of records waiting to be sent

	// bytesSent counts the bytes of application data sent.
	// packetsSent counts packets.
	bytesSent   int64
	packetsSent int64

	// retryCount counts the number of consecutive non-advancing records
	// received by Conn.readRecord. That is, records that neither advance the
	// handshake, nor deliver application data. Protected by in.Mutex.
	retryCount int

	// activeCall indicates whether Close has been call in the low bit.
	// the rest of the bits are the number of goroutines in Conn.Write.
	activeCall atomic.Int32

	tmp [16]byte
}

// Access to net.Conn methods.
// Cannot just embed net.Conn because that would
// export the struct field too.

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means [Conn.Read] and [Conn.Write] will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means [Conn.Read] will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means [Conn.Write] will not time out.
// After a [Conn.Write] has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// NetConn returns the underlying connection that is wrapped by c.
// Note that writing to or reading from this connection directly will corrupt the
// TLS session.
func (c *Conn) NetConn() net.Conn {
	return c.conn
}

// A halfConn represents one direction of the record layer
// connection, either sending or receiving.
type halfConn struct {
	sync.Mutex

	err     error  // first permanent error
	version uint16 // protocol version
	cipher  any    // cipher algorithm
	mac     hash.Hash
	seq     [8]byte // 64-bit sequence number

	scratchBuf [13]byte // to avoid allocs; interface method args escape

	nextCipher any       // next encryption state
	nextMac    hash.Hash // next MAC algorithm

	level         QUICEncryptionLevel // current QUIC encryption level
	trafficSecret []byte              // current TLS 1.3 traffic secret
}

type permanentError struct {
	err net.Error
}

func (e *permanentError) Error() string   { return e.err.Error() }
func (e *permanentError) Unwrap() error   { return e.err }
func (e *permanentError) Timeout() bool   { return e.err.Timeout() }
func (e *permanentError) Temporary() bool { return false }

func (hc *halfConn) setErrorLocked(err error) error {
	if e, ok := err.(net.Error); ok {
		hc.err = &permanentError{err: e}
	} else {
		hc.err = err
	}
	return hc.err
}

// prepareCipherSpec sets the encryption and MAC states
// that a subsequent changeCipherSpec will use.
func (hc *halfConn) prepareCipherSpec(version uint16, cipher any, mac hash.Hash) {
	hc.version = version
	hc.nextCipher = cipher
	hc.nextMac = mac
}

// changeCipherSpec changes the encryption and MAC states
// to the ones previously passed to prepareCipherSpec.
func (hc *halfConn) changeCipherSpec() error {
	if hc.nextCipher == nil || hc.version == VersionTLS13 {
		return alertInternalError
	}
	hc.cipher = hc.nextCipher
	hc.mac = hc.nextMac
	hc.nextCipher = nil
	hc.nextMac = nil
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	return nil
}

func (hc *halfConn) setTrafficSecret(suite *cipherSuiteTLS13, level QUICEncryptionLevel, secret []byte) {
	hc.trafficSecret = secret
	hc.level = level
	key, iv := suite.trafficKey(secret)
	hc.cipher = suite.aead(key, iv)
	for i := range hc.seq {
		hc.seq[i] = 0
	}
}

// incSeq increments the sequence number.
func (hc *halfConn) incSeq() {
	for i := 7; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("TLS: sequence number wraparound")
}

// explicitNonceLen returns the number of bytes of explicit nonce or IV included
// in each record. Explicit nonces are present only in CBC modes after TLS 1.0
// and in certain AEAD modes in TLS 1.2.
func (hc *halfConn) explicitNonceLen() int {
	if hc.cipher == nil {
		return 0
	}

	switch c := hc.cipher.(type) {
	case cipher.Stream:
		return 0
	case aead:
		return c.explicitNonceLen()
	case cbcMode:
		// TLS 1.1 introduced a per-record explicit IV to fix the BEAST attack.
		if hc.version >= VersionTLS11 {
			return c.BlockSize()
		}
		return 0
	default:
		panic("unknown cipher type")
	}
}

// extractPadding returns, in constant time, the length of the padding to remove
// from the end of payload. It also returns a byte which is equal to 255 if the
// padding was valid and 0 otherwise. See RFC 2246, Section 6.2.3.2.
func extractPadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	// if len(payload) >= (paddingLen - 1) then the MSB of t is zero
	good = byte(int32(^t) >> 31)

	// The maximum possible padding length plus the actual length field
	toCheck := 256
	// The length of the padded data is public, so we can use an if here
	if toCheck > len(payload) {
		toCheck = len(payload)
	}

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		// if i <= paddingLen then the MSB of t is zero
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	// We AND together the bits of good and replicate the result across
	// all the bits.
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	// Zero the padding length on error. This ensures any unchecked bytes
	// are included in the MAC. Otherwise, an attacker that could
	// distinguish MAC failures from padding failures could mount an attack
	// similar to POODLE in SSL 3.0: given a good ciphertext that uses a
	// full block's worth of padding, replace the final block with another
	// block. If the MAC check passed but the padding check failed, the
	// last byte of that block decrypted to the block size.
	//
	// See also macAndPaddingGood logic below.
	paddingLen &= good

	toRemove = int(paddingLen) + 1
	return
}

func roundUp(a, b int) int {
	return a + (b-a%b)%b
}

// cbcMode is an interface for block ciphers using cipher block chaining.
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

// decrypt authenticates and decrypts the record if protection is active at
// this stage. The returned plaintext might overlap with the input.
func (hc *halfConn) decrypt(record []byte) ([]byte, recordType, error) {
	var plaintext []byte
	typ := recordType(record[0])
	payload := record[recordHeaderLen:]

	// In TLS 1.3, change_cipher_spec messages are to be ignored without being
	// decrypted. See RFC 8446, Appendix D.4.
	if hc.version == VersionTLS13 && typ == recordTypeChangeCipherSpec {
		return payload, typ, nil
	}

	paddingGood := byte(255)
	paddingLen := 0

	explicitNonceLen := hc.explicitNonceLen()

	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		case cipher.Stream:
			c.XORKeyStream(payload, payload)
		case aead:
			if len(payload) < explicitNonceLen {
				return nil, 0, alertBadRecordMAC
			}
			nonce := payload[:explicitNonceLen]
			if len(nonce) == 0 {
				nonce = hc.seq[:]
			}
			payload = payload[explicitNonceLen:]

			var additionalData []byte
			if hc.version == VersionTLS13 {
				additionalData = record[:recordHeaderLen]
			} else {
				additionalData = append(hc.scratchBuf[:0], hc.seq[:]...)
				additionalData = append(additionalData, record[:3]...)
				n := len(payload) - c.Overhead()
				additionalData = append(additionalData, byte(n>>8), byte(n))
			}

			var err error
			plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
			if err != nil {
				return nil, 0, alertBadRecordMAC
			}
		case cbcMode:
			blockSize := c.BlockSize()
			minPayload := explicitNonceLen + roundUp(hc.mac.Size()+1, blockSize)
			if len(payload)%blockSize != 0 || len(payload) < minPayload {
				return nil, 0, alertBadRecordMAC
			}

			if explicitNonceLen > 0 {
				c.SetIV(payload[:explicitNonceLen])
				payload = payload[explicitNonceLen:]
			}
			c.CryptBlocks(payload, payload)

			// In a limited attempt to protect against CBC padding oracles like
			// Lucky13, the data past paddingLen (which is secret) is passed to
			// the MAC function as extra data, to be fed into the HMAC after
			// computing the digest. This makes the MAC roughly constant time as
			// long as the digest computation is constant time and does not
			// affect the subsequent write, modulo cache effects.
			paddingLen, paddingGood = extractPadding(payload)
		default:
			panic("unknown cipher type")
		}

		if hc.version == VersionTLS13 {
			if typ != recordTypeApplicationData {
				return nil, 0, alertUnexpectedMessage
			}
			if len(plaintext) > maxPlaintext+1 {
				return nil, 0, alertRecordOverflow
			}
			// Remove padding and find the ContentType scanning from the end.
			for i := len(plaintext) - 1; i >= 0; i-- {
				if plaintext[i] != 0 {
					typ = recordType(plaintext[i])
					plaintext = plaintext[:i]
					break
				}
				if i == 0 {
					return nil, 0, alertUnexpectedMessage
				}
			}
		}
	} else {
		plaintext = payload
	}

	if hc.mac != nil {
		macSize := hc.mac.Size()
		if len(payload) < macSize {
			return nil, 0, alertBadRecordMAC
		}

		n := len(payload) - macSize - paddingLen
		n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n) // if n < 0 { n = 0 }
		record[3] = byte(n >> 8)
		record[4] = byte(n)
		remoteMAC := payload[n : n+macSize]
		localMAC := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload[:n], payload[n+macSize:])

		// This is equivalent to checking the MACs and paddingGood
		// separately, but in constant-time to prevent distinguishing
		// padding failures from MAC failures. Depending on what value
		// of paddingLen was returned on bad padding, distinguishing
		// bad MAC from bad padding can lead to an attack.
		//
		// See also the logic at the end of extractPadding.
		macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
		if macAndPaddingGood != 1 {
			return nil, 0, alertBadRecordMAC
		}

		plaintext = payload[:n]
	}

	hc.incSeq()
	return plaintext, typ, nil
}

// sliceForAppend extends the input slice by n bytes. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// encrypt encrypts payload, adding the appropriate nonce and/or MAC, and
// appends it to record, which must already contain the record header.
func (hc *halfConn) encrypt(record, payload []byte, rand io.Reader) ([]byte, error) {
	if hc.cipher == nil {
		return append(record, payload...), nil
	}

	var explicitNonce []byte
	if explicitNonceLen := hc.explicitNonceLen(); explicitNonceLen > 0 {
		record, explicitNonce = sliceForAppend(record, explicitNonceLen)
		if _, isCBC := hc.cipher.(cbcMode); !isCBC && explicitNonceLen < 16 {
			// The AES-GCM construction in TLS has an explicit nonce so that the
			// nonce can be random. However, the nonce is only 8 bytes which is
			// too small for a secure, random nonce. Therefore we use the
			// sequence number as the nonce. The 3DES-CBC construction also has
			// an 8 bytes nonce but its nonces must be unpredictable (see RFC
			// 5246, Appendix F.3), forcing us to use randomness. That's not
			// 3DES' biggest problem anyway because the birthday bound on block
			// collision is reached first due to its similarly small block size
			// (see the Sweet32 attack).
			copy(explicitNonce, hc.seq[:])
		} else {
			if _, err := io.ReadFull(rand, explicitNonce); err != nil {
				return nil, err
			}
		}
	}

	var dst []byte
	switch c := hc.cipher.(type) {
	case cipher.Stream:
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
		record, dst = sliceForAppend(record, len(payload)+len(mac))
		c.XORKeyStream(dst[:len(payload)], payload)
		c.XORKeyStream(dst[len(payload):], mac)
	case aead:
		nonce := explicitNonce
		if len(nonce) == 0 {
			nonce = hc.seq[:]
		}

		if hc.version == VersionTLS13 {
			record = append(record, payload...)

			// Encrypt the actual ContentType and replace the plaintext one.
			record = append(record, record[0])
			record[0] = byte(recordTypeApplicationData)

			n := len(payload) + 1 + c.Overhead()
			record[3] = byte(n >> 8)
			record[4] = byte(n)

			record = c.Seal(record[:recordHeaderLen],
				nonce, record[recordHeaderLen:], record[:recordHeaderLen])
		} else {
			additionalData := append(hc.scratchBuf[:0], hc.seq[:]...)
			additionalData = append(additionalData, record[:recordHeaderLen]...)
			record = c.Seal(record, nonce, payload, additionalData)
		}
	case cbcMode:
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
		blockSize := c.BlockSize()
		plaintextLen := len(payload) + len(mac)
		paddingLen := blockSize - plaintextLen%blockSize
		record, dst = sliceForAppend(record, plaintextLen+paddingLen)
		copy(dst, payload)
		copy(dst[len(payload):], mac)
		for i := plaintextLen; i < len(dst); i++ {
			dst[i] = byte(paddingLen - 1)
		}
		if len(explicitNonce) > 0 {
			c.SetIV(explicitNonce)
		}
		c.CryptBlocks(dst, dst)
	default:
		panic("unknown cipher type")
	}

	// Update length to include nonce, MAC and any block padding needed.
	n := len(record) - recordHeaderLen
	record[3] = byte(n >> 8)
	record[4] = byte(n)
	hc.incSeq()

	return record, nil
}

// RecordHeaderError is returned when a TLS record header is invalid.
type RecordHeaderError struct {
	// Msg contains a human readable string that describes the error.
	Msg string
	// RecordHeader contains the five bytes of TLS record header that
	// triggered the error.
	RecordHeader [5]byte
	// Conn provides the underlying net.Conn in the case that a client
	// sent an initial handshake that didn't look like TLS.
	// It is nil if there's already been a handshake or a TLS alert has
	// been written to the connection.
	Conn net.Conn
}

func (e RecordHeaderError) Error() string { return "tls: " + e.Msg }

func (c *Conn) newRecordHeaderError(conn net.Conn, msg string) (err RecordHeaderError) {
	err.Msg = msg
	err.Conn = conn
	copy(err.RecordHeader[:], c.rawInput.Bytes())
	return err
}

func (c *Conn) readRecord() error {
	return c.readRecordOrCCS(false)
}

func (c *Conn) readChangeCipherSpec() error {
	return c.readRecordOrCCS(true)
}

// readRecordOrCCS reads one or more TLS records from the connection and
// updates the record layer state. Some invariants:
//   - c.in must be locked
//   - c.input must be empty
//
// During the handshake one and only one of the following will happen:
//   - c.hand grows
//   - c.in.changeCipherSpec is called
//   - an error is returned
//
// After the handshake one and only one of the following will happen:
//   - c.hand grows
//   - c.input is set
//   - an error is returned
func (c *Conn) readRecordOrCCS(expectChangeCipherSpec bool) error {
	if c.in.err != nil {
		return c.in.err
	}
	handshakeComplete := c.isHandshakeComplete.Load()

	// This function modifies c.rawInput, which owns the c.input memory.
	if c.input.Len() != 0 {
		return c.in.setErrorLocked(errors.New("tls: internal error: attempted to read record with pending application data"))
	}
	c.input.Reset(nil)

	if c.quic != nil {
		return c.in.setErrorLocked(errors.New("tls: internal error: attempted to read record with QUIC transport"))
	}

	// Read header, payload.
	if err := c.readFromUntil(c.conn, recordHeaderLen); err != nil {
		// RFC 8446, Section 6.1 suggests that EOF without an alertCloseNotify
		// is an error, but popular web sites seem to do this, so we accept it
		// if and only if at the record boundary.
		if err == io.ErrUnexpectedEOF && c.rawInput.Len() == 0 {
			err = io.EOF
		}
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}
	hdr := c.rawInput.Bytes()[:recordHeaderLen]
	typ := recordType(hdr[0])

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if !handshakeComplete && typ == 0x80 {
		c.sendAlert(alertProtocolVersion)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, "unsupported SSLv2 handshake received"))
	}

	vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	expectedVers := c.vers
	if expectedVers == VersionTLS13 {
		// All TLS 1.3 records are expected to have 0x0303 (1.2) after
		// the initial hello (RFC 8446 Section 5.1).
		expectedVers = VersionTLS12
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if c.haveVers && vers != expectedVers {
		c.sendAlert(alertProtocolVersion)
		msg := fmt.Sprintf("received record with version %x when expecting version %x", vers, expectedVers)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if !c.haveVers {
		// First message, be extra suspicious: this might not be a TLS
		// client. Bail out before reading a full 'body', if possible.
		// The current max version is 3.3 so if the version is >= 16.0,
		// it's probably not real.
		if (typ != recordTypeAlert && typ != recordTypeHandshake) || vers >= 0x1000 {
			return c.in.setErrorLocked(c.newRecordHeaderError(c.conn, "first record does not look like a TLS handshake"))
		}
	}
	if c.vers == VersionTLS13 && n > maxCiphertextTLS13 || n > maxCiphertext {
		c.sendAlert(alertRecordOverflow)
		msg := fmt.Sprintf("oversized record received with length %d", n)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if err := c.readFromUntil(c.conn, recordHeaderLen+n); err != nil {
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}

	// Process message.
	record := c.rawInput.Next(recordHeaderLen + n)
	data, typ, err := c.in.decrypt(record)
	if err != nil {
		return c.in.setErrorLocked(c.sendAlert(err.(alert)))
	}
	if len(data) > maxPlaintext {
		return c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
	}

	// Application Data messages are always protected.
	if c.in.cipher == nil && typ == recordTypeApplicationData {
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	if typ != recordTypeAlert && typ != recordTypeChangeCipherSpec && len(data) > 0 {
		// This is a state-advancing message: reset the retry count.
		c.retryCount = 0
	}

	// Handshake messages MUST NOT be interleaved with other record types in TLS 1.3.
	if c.vers == VersionTLS13 && typ != recordTypeHandshake && c.hand.Len() > 0 {
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	switch typ {
	default:
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))

	case recordTypeAlert:
		if c.quic != nil {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if len(data) != 2 {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if alert(data[1]) == alertCloseNotify {
			return c.in.setErrorLocked(io.EOF)
		}
		if c.vers == VersionTLS13 {
			return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
		}
		switch data[0] {
		case alertLevelWarning:
			// Drop the record on the floor and retry.
			return c.retryReadRecord(expectChangeCipherSpec)
		case alertLevelError:
			return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
		default:
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}

	case recordTypeChangeCipherSpec:
		if len(data) != 1 || data[0] != 1 {
			return c.in.setErrorLocked(c.sendAlert(alertDecodeError))
		}
		// Handshake messages are not allowed to fragment across the CCS.
		if c.hand.Len() > 0 {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		// In TLS 1.3, change_cipher_spec records are ignored until the
		// Finished. See RFC 8446, Appendix D.4. Note that according to Section
		// 5, a server can send a ChangeCipherSpec before its ServerHello, when
		// c.vers is still unset. That's not useful though and suspicious if the
		// server then selects a lower protocol version, so don't allow that.
		if c.vers == VersionTLS13 {
			return c.retryReadRecord(expectChangeCipherSpec)
		}
		if !expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if err := c.in.changeCipherSpec(); err != nil {
			return c.in.setErrorLocked(c.sendAlert(err.(alert)))
		}

	case recordTypeApplicationData:
		if !handshakeComplete || expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		// Some OpenSSL servers send empty records in order to randomize the
		// CBC IV. Ignore a limited number of empty records.
		if len(data) == 0 {
			return c.retryReadRecord(expectChangeCipherSpec)
		}
		// Note that data is owned by c.rawInput, following the Next call above,
		// to avoid copying the plaintext. This is safe because c.rawInput is
		// not read from or written to until c.input is drained.
		c.input.Reset(data)

	case recordTypeHandshake:
		if len(data) == 0 || expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		c.hand.Write(data)
	}

	return nil
}

// retryReadRecord recurs into readRecordOrCCS to drop a non-advancing record, like
// a warning alert, empty application_data, or a change_cipher_spec in TLS 1.3.
func (c *Conn) retryReadRecord(expectChangeCipherSpec bool) error {
	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tls: too many ignored records"))
	}
	return c.readRecordOrCCS(expectChangeCipherSpec)
}

// atLeastReader reads from R, stopping with EOF once at least N bytes have been
// read. It is different from an io.LimitedReader in that it doesn't cut short
// the last Read call, and in that it considers an early EOF an error.
type atLeastReader struct {
	R io.Reader
	N int64
}

func (r *atLeastReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err := r.R.Read(p)
	r.N -= int64(n) // won't underflow unless len(p) >= n > 9223372036854775809
	if r.N > 0 && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	if r.N <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

// readFromUntil reads from r into c.rawInput until c.rawInput contains
// at least n bytes or else returns an error.
func (c *Conn) readFromUntil(r io.Reader, n int) error {
	if c.rawInput.Len() >= n {
		return nil
	}
	needs := n - c.rawInput.Len()
	// There might be extra input waiting on the wire. Make a best effort
	// attempt to fetch it so that it can be used in (*Conn).Read to
	// "predict" closeNotify alerts.
	c.rawInput.Grow(needs + bytes.MinRead)
	_, err := c.rawInput.ReadFrom(&atLeastReader{r, int64(needs)})
	return err
}

// sendAlertLocked sends a TLS alert message.
func (c *Conn) sendAlertLocked(err alert) error {
	if c.quic != nil {
		return c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
	}

	switch err {
	case alertNoRenegotiation, alertCloseNotify:
		c.tmp[0] = alertLevelWarning
	default:
		c.tmp[0] = alertLevelError
	}
	c.tmp[1] = byte(err)

	_, writeErr := c.writeRecordLocked(recordTypeAlert, c.tmp[0:2])
	if err == alertCloseNotify {
		// closeNotify is a special case in that it isn't an error.
		return writeErr
	}

	return c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
}

// sendAlert sends a TLS alert message.
func (c *Conn) sendAlert(err alert) error {
	c.out.Lock()
	defer c.out.Unlock()
	return c.sendAlertLocked(err)
}

const (
	// tcpMSSEstimate is a conservative estimate of the TCP maximum segment
	// size (MSS). A constant is used, rather than querying the kernel for
	// the actual MSS, to avoid complexity. The value here is the IPv6
	// minimum MTU (1280 bytes) minus the overhead of an IPv6 header (40
	// bytes) and a TCP header with timestamps (32 bytes).
	tcpMSSEstimate = 1208

	// recordSizeBoostThreshold is the number of bytes of application data
	// sent after which the TLS record size will be increased to the
	// maximum.
	recordSizeBoostThreshold = 128 * 1024
)

// maxPayloadSizeForWrite returns the maximum TLS payload size to use for the
// next application data record. There is the following trade-off:
//
//   - For latency-sensitive applications, such as web browsing, each TLS
//     record should fit in one TCP segment.
//   - For throughput-sensitive applications, such as large file transfers,
//     larger TLS records better amortize framing and encryption overheads.
//
// A simple heuristic that works well in practice is to use small records for
// the first 1MB of data, then use larger records for subsequent data, and
// reset back to smaller records after the connection becomes idle. See "High
// Performance Web Networking", Chapter 4, or:
// https://www.igvita.com/2013/10/24/optimizing-tls-record-size-and-buffering-latency/
//
// In the interests of simplicity and determinism, this code does not attempt
// to reset the record size once the connection is idle, however.
func (c *Conn) maxPayloadSizeForWrite(typ recordType) int {
	if c.config.DynamicRecordSizingDisabled || typ != recordTypeApplicationData {
		return maxPlaintext
	}

	if c.bytesSent >= recordSizeBoostThreshold {
		return maxPlaintext
	}

	// Subtract TLS overheads to get the maximum payload size.
	payloadBytes := tcpMSSEstimate - recordHeaderLen - c.out.explicitNonceLen()
	if c.out.cipher != nil {
		switch ciph := c.out.cipher.(type) {
		case cipher.Stream:
			payloadBytes -= c.out.mac.Size()
		case cipher.AEAD:
			payloadBytes -= ciph.Overhead()
		case cbcMode:
			blockSize := ciph.BlockSize()
			// The payload must fit in a multiple of blockSize, with
			// room for at least one padding byte.
			payloadBytes = (payloadBytes & ^(blockSize - 1)) - 1
			// The MAC is appended before padding so affects the
			// payload size directly.
			payloadBytes -= c.out.mac.Size()
		default:
			panic("unknown cipher type")
		}
	}
	if c.vers == VersionTLS13 {
		payloadBytes-- // encrypted ContentType
	}

	// Allow packet growth in arithmetic progression up to max.
	pkt := c.packetsSent
	c.packetsSent++
	if pkt > 1000 {
		return maxPlaintext // avoid overflow in multiply below
	}

	n := payloadBytes * int(pkt+1)
	if n > maxPlaintext {
		n = maxPlaintext
	}
	return n
}

func (c *Conn) write(data []byte) (int, error) {
	if c.buffering {
		c.sendBuf = append(c.sendBuf, data...)
		return len(data), nil
	}

	n, err := c.conn.Write(data)
	c.bytesSent += int64(n)
	return n, err
}

func (c *Conn) flush() (int, error) {
	if len(c.sendBuf) == 0 {
		return 0, nil
	}

	n, err := c.conn.Write(c.sendBuf)
	c.bytesSent += int64(n)
	c.sendBuf = nil
	c.buffering = false
	return n, err
}

// outBufPool pools the record-sized scratch buffers used by writeRecordLocked.
var outBufPool = sync.Pool{
	New: func() any {
		return new([]byte)
	},
}

// writeRecordLocked writes a TLS record with the given type and payload to the
// connection and updates the record layer state.
func (c *Conn) writeRecordLocked(typ recordType, data []byte) (int, error) {
	if c.quic != nil {
		if typ != recordTypeHandshake {
			return 0, errors.New("tls: internal error: sending non-handshake message to QUIC transport")
		}
		c.quicWriteCryptoData(c.out.level, data)
		if !c.buffering {
			if _, err := c.flush(); err != nil {
				return 0, err
			}
		}
		return len(data), nil
	}

	outBufPtr := outBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer func() {
		// You might be tempted to simplify this by just passing &outBuf to Put,
		// but that would make the local copy of the outBuf slice header escape
		// to the heap, causing an allocation. Instead, we keep around the
		// pointer to the slice header returned by Get, which is already on the
		// heap, and overwrite and return that.
		*outBufPtr = outBuf
		outBufPool.Put(outBufPt
"""




```