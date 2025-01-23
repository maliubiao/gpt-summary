Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `crypto/tls` package, specifically the `conn.go` file. This is the second part of the code.

Here's a breakdown of the code's responsibilities:

1. **Writing TLS Records:**  The `writeRecordLocked` function handles the low-level process of packaging data into TLS records, including adding headers, encrypting the payload, and sending it.
2. **Writing Handshake Messages:**  The `writeHandshakeRecord` function takes a handshake message, marshals it into bytes, and then uses `writeRecordLocked` to send it within a handshake record.
3. **Writing Change Cipher Spec:** The `writeChangeCipherRecord` function sends a ChangeCipherSpec message, signaling a change in encryption parameters.
4. **Reading Handshake Messages:**
    - `readHandshakeBytes`: Reads raw bytes from the connection until a certain number of bytes for a handshake message are available.
    - `readHandshake`: Reads the complete handshake message from the buffered data, checking its length and then unmarshaling it.
    - `unmarshalHandshakeMessage`: Converts the raw byte representation of a handshake message into a specific Go struct.
5. **Writing Application Data:** The `Write` method is the primary way to send application data over the TLS connection. It handles the handshake if necessary, encrypts the data, and sends it in application data records. It also includes a workaround for the TLS 1.0 BEAST attack.
6. **Handling Renegotiation (TLS <= 1.2):** The `handleRenegotiation` function processes `HelloRequest` messages, which can trigger TLS renegotiation.
7. **Handling Post-Handshake Messages (TLS >= 1.3):** The `handlePostHandshakeMessage` function deals with messages received after the initial handshake, like `NewSessionTicket` and `KeyUpdate`.
8. **Handling Key Updates (TLS >= 1.3):** The `handleKeyUpdate` function manages the process of updating encryption keys during the lifetime of a TLS 1.3 connection.
9. **Reading Application Data:** The `Read` method is the primary way to receive application data. It handles the handshake if necessary, reads TLS records, decrypts the data, and buffers it for the user. It also handles post-handshake messages that might arrive during reads.
10. **Closing the Connection:** The `Close` method gracefully closes the TLS connection, sending a `close_notify` alert if the handshake is complete.
11. **Closing the Write Side:** The `CloseWrite` method shuts down the writing side of the connection after the handshake is complete.
12. **Initiating the Handshake:**
    - `Handshake`: Starts the TLS handshake process.
    - `HandshakeContext`: Starts the handshake with context support for cancellation and timeouts.
    - `handshakeContext`: The internal implementation of the handshake process.
13. **Retrieving Connection State:** The `ConnectionState` method provides details about the current state of the TLS connection, including negotiated parameters, certificates, and whether the handshake is complete.
14. **Retrieving OCSP Response:** The `OCSPResponse` method returns the stapled OCSP response from the server.
15. **Verifying Hostname:** The `VerifyHostname` method checks if the server's certificate is valid for a given hostname.

Essentially, this part of `conn.go` focuses on the core data transfer and handshake management aspects of a TLS connection, both for sending and receiving data.
这是 `go/src/crypto/tls/conn.go` 文件中关于 TLS 连接功能实现的第二部分代码，主要负责以下功能：

**核心功能归纳：数据收发、握手处理与连接管理**

1. **写入 TLS 记录 (Writing TLS Records):**  `writeRecordLocked` 函数负责将数据封装成 TLS 记录，包括添加类型、版本、长度等头部信息，并调用底层加密方法进行加密。
2. **写入握手记录 (Writing Handshake Records):** `writeHandshakeRecord` 函数用于发送握手消息。它首先将握手消息序列化成字节流，然后调用 `writeRecordLocked` 将其封装成握手类型的 TLS 记录发送出去。
3. **写入密码变更记录 (Writing Change Cipher Spec Record):** `writeChangeCipherRecord` 函数发送一个 ChangeCipherSpec 消息，用于通知对方接下来将使用新的加密套件。
4. **读取握手消息 (Reading Handshake Messages):**
    *   `readHandshakeBytes`： 从连接中读取指定长度的字节，用于接收完整的握手消息头和内容。
    *   `readHandshake`： 读取并解析下一个握手消息。它首先读取消息头获取消息长度，然后读取消息体，最后根据消息类型反序列化成对应的握手消息结构体。
    *   `unmarshalHandshakeMessage`： 根据握手消息的类型，将字节流反序列化成对应的 Go 结构体。
5. **写入应用数据 (Writing Application Data):** `Write` 方法是向 TLS 连接写入应用数据的入口。它会首先确保握手已完成，然后将数据分割成合适的块，并调用 `writeRecordLocked` 将其封装成应用数据类型的 TLS 记录发送出去。为了规避 TLS 1.0 的 BEAST 攻击，会对某些情况下的数据进行特殊处理。
6. **处理重新协商 (Handling Renegotiation - TLS 1.2 及以下):** `handleRenegotiation` 函数处理服务端发起的重新协商请求 (`HelloRequest` 消息)。
7. **处理握手后消息 (Handling Post-Handshake Messages - TLS 1.3 及以上):** `handlePostHandshakeMessage` 函数处理握手完成后收到的消息，例如 `NewSessionTicket` (用于会话恢复) 和 `KeyUpdate` (用于密钥更新)。
8. **处理密钥更新 (Handling Key Updates - TLS 1.3):** `handleKeyUpdate` 函数处理 TLS 1.3 中的密钥更新请求。
9. **读取应用数据 (Reading Application Data):** `Read` 方法是从 TLS 连接读取应用数据的入口。它会首先确保握手已完成，然后读取 TLS 记录，解密数据，并将解密后的应用数据存入缓冲区供用户读取。同时，也会处理在读取过程中可能收到的握手后消息。
10. **关闭连接 (Closing the Connection):** `Close` 方法关闭 TLS 连接。如果握手已完成，它会尝试发送 `close_notify` 警报通知对方。
11. **关闭写入端 (Closing the Write Side):** `CloseWrite` 方法只关闭连接的写入端，用于优雅地结束数据发送。
12. **执行握手 (Performing Handshake):**
    *   `Handshake`:  启动 TLS 握手过程。这个方法会被 `Read` 或 `Write` 隐式调用，确保在数据传输前完成握手。
    *   `HandshakeContext`:  与 `Handshake` 功能相同，但允许传入 `context.Context`，以便支持超时和取消操作。
    *   `handshakeContext`:  `HandshakeContext` 的实际实现。
13. **获取连接状态 (Getting Connection State):** `ConnectionState` 方法返回当前 TLS 连接的状态信息，包括协议版本、加密套件、证书信息等。
14. **获取 OCSP 响应 (Getting OCSP Response):** `OCSPResponse` 方法返回服务端提供的 OCSP 状态查询协议的响应，用于客户端验证服务端证书的有效性。
15. **校验主机名 (Verifying Hostname):** `VerifyHostname` 方法用于客户端校验服务端证书的主机名是否与目标主机匹配。

**功能代码举例 (使用 `Write` 方法发送数据):**

假设我们已经建立了一个 TLS 连接 `conn`。

```go
package main

import (
	"crypto/tls"
	"fmt"
	"net"
)

func main() {
	// 假设 listener 已经创建并监听
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	config := &tls.Config{
		Certificates: nil, // 这里需要配置服务端证书
	}
	tlsListener := tls.NewListener(listener, config)
	defer tlsListener.Close()

	conn, err := tlsListener.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// 假设握手已完成

	data := []byte("Hello, TLS!")
	n, err := conn.Write(data) // 调用 Write 方法发送数据
	if err != nil {
		fmt.Println("写入数据失败:", err)
		return
	}
	fmt.Printf("成功写入 %d 字节\n", n)

	// ... 其他操作
}
```

**假设的输入与输出 (基于 `writeRecordLocked` 函数):**

**假设输入:**

*   `typ`: `recordTypeApplicationData` (假设要发送应用数据)
*   `data`: `[]byte{72, 101, 108, 108, 111}` (要发送的数据 "Hello")
*   `c.vers`: `VersionTLS12` (假设 TLS 版本为 1.2)
*   `c.out.cipher`: 一个实现了加密接口的 cipher 对象

**推理过程:**

1. 确定最大有效载荷大小 `maxPayload`。
2. 分配输出缓冲区 `outBuf`，预留头部空间。
3. 设置头部信息：类型 (应用数据)、版本 (TLS 1.2)、长度 (5)。
4. 调用 `c.out.encrypt` 对数据进行加密，假设加密后的结果为 `encryptedData`。
5. 将加密后的数据追加到 `outBuf`。
6. 调用底层的 `c.write` 方法发送 `outBuf`。

**假设输出:**

*   如果写入成功，返回写入的字节数 (包括头部和加密后的数据长度)。
*   如果发生错误 (例如加密失败或底层写入失败)，返回错误信息。

**使用者易犯错的点 (基于 `Write` 方法):**

*   **在握手完成前调用 `Write` 而没有设置 Deadline:** 如果在 TLS 握手完成之前调用 `Write`，并且没有通过 `SetDeadline`、`SetReadDeadline` 或 `SetWriteDeadline` 设置超时时间，`Write` 方法会阻塞等待握手完成，如果握手过程中出现问题，可能会导致程序永久阻塞。

    ```go
    package main

    import (
        "crypto/tls"
        "fmt"
        "net"
    )

    func main() {
        conn, err := tls.Dial("tcp", "example.com:443", &tls.Config{InsecureSkipVerify: true})
        if err != nil {
            fmt.Println("连接失败:", err)
            return
        }
        defer conn.Close()

        data := []byte("Hello")
        _, err = conn.Write(data) // 如果握手卡住，这里会一直阻塞
        if err != nil {
            fmt.Println("写入失败:", err)
        }
    }
    ```

**总结：**

这部分代码是 Go TLS 实现的核心组成部分，负责 TLS 连接的建立、数据传输和关闭流程。它实现了 TLS 协议中关于记录层和握手消息的处理，确保了通信的安全性和可靠性。开发者在使用 `crypto/tls` 包时，通常不需要直接操作这些底层的细节，而是通过 `Conn` 提供的 `Read` 和 `Write` 方法进行数据交互，并依赖其内部的握手机制来建立安全连接。理解这部分代码的功能有助于更深入地理解 TLS 协议的工作原理。

### 提示词
```
这是路径为go/src/crypto/tls/conn.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
r)
	}()

	var n int
	for len(data) > 0 {
		m := len(data)
		if maxPayload := c.maxPayloadSizeForWrite(typ); m > maxPayload {
			m = maxPayload
		}

		_, outBuf = sliceForAppend(outBuf[:0], recordHeaderLen)
		outBuf[0] = byte(typ)
		vers := c.vers
		if vers == 0 {
			// Some TLS servers fail if the record version is
			// greater than TLS 1.0 for the initial ClientHello.
			vers = VersionTLS10
		} else if vers == VersionTLS13 {
			// TLS 1.3 froze the record layer version to 1.2.
			// See RFC 8446, Section 5.1.
			vers = VersionTLS12
		}
		outBuf[1] = byte(vers >> 8)
		outBuf[2] = byte(vers)
		outBuf[3] = byte(m >> 8)
		outBuf[4] = byte(m)

		var err error
		outBuf, err = c.out.encrypt(outBuf, data[:m], c.config.rand())
		if err != nil {
			return n, err
		}
		if _, err := c.write(outBuf); err != nil {
			return n, err
		}
		n += m
		data = data[m:]
	}

	if typ == recordTypeChangeCipherSpec && c.vers != VersionTLS13 {
		if err := c.out.changeCipherSpec(); err != nil {
			return n, c.sendAlertLocked(err.(alert))
		}
	}

	return n, nil
}

// writeHandshakeRecord writes a handshake message to the connection and updates
// the record layer state. If transcript is non-nil the marshaled message is
// written to it.
func (c *Conn) writeHandshakeRecord(msg handshakeMessage, transcript transcriptHash) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	data, err := msg.marshal()
	if err != nil {
		return 0, err
	}
	if transcript != nil {
		transcript.Write(data)
	}

	return c.writeRecordLocked(recordTypeHandshake, data)
}

// writeChangeCipherRecord writes a ChangeCipherSpec message to the connection and
// updates the record layer state.
func (c *Conn) writeChangeCipherRecord() error {
	c.out.Lock()
	defer c.out.Unlock()
	_, err := c.writeRecordLocked(recordTypeChangeCipherSpec, []byte{1})
	return err
}

// readHandshakeBytes reads handshake data until c.hand contains at least n bytes.
func (c *Conn) readHandshakeBytes(n int) error {
	if c.quic != nil {
		return c.quicReadHandshakeBytes(n)
	}
	for c.hand.Len() < n {
		if err := c.readRecord(); err != nil {
			return err
		}
	}
	return nil
}

// readHandshake reads the next handshake message from
// the record layer. If transcript is non-nil, the message
// is written to the passed transcriptHash.
func (c *Conn) readHandshake(transcript transcriptHash) (any, error) {
	if err := c.readHandshakeBytes(4); err != nil {
		return nil, err
	}
	data := c.hand.Bytes()

	maxHandshakeSize := maxHandshake
	// hasVers indicates we're past the first message, forcing someone trying to
	// make us just allocate a large buffer to at least do the initial part of
	// the handshake first.
	if c.haveVers && data[0] == typeCertificate {
		// Since certificate messages are likely to be the only messages that
		// can be larger than maxHandshake, we use a special limit for just
		// those messages.
		maxHandshakeSize = maxHandshakeCertificateMsg
	}

	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshakeSize {
		c.sendAlertLocked(alertInternalError)
		return nil, c.in.setErrorLocked(fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshakeSize))
	}
	if err := c.readHandshakeBytes(4 + n); err != nil {
		return nil, err
	}
	data = c.hand.Next(4 + n)
	return c.unmarshalHandshakeMessage(data, transcript)
}

func (c *Conn) unmarshalHandshakeMessage(data []byte, transcript transcriptHash) (handshakeMessage, error) {
	var m handshakeMessage
	switch data[0] {
	case typeHelloRequest:
		m = new(helloRequestMsg)
	case typeClientHello:
		m = new(clientHelloMsg)
	case typeServerHello:
		m = new(serverHelloMsg)
	case typeNewSessionTicket:
		if c.vers == VersionTLS13 {
			m = new(newSessionTicketMsgTLS13)
		} else {
			m = new(newSessionTicketMsg)
		}
	case typeCertificate:
		if c.vers == VersionTLS13 {
			m = new(certificateMsgTLS13)
		} else {
			m = new(certificateMsg)
		}
	case typeCertificateRequest:
		if c.vers == VersionTLS13 {
			m = new(certificateRequestMsgTLS13)
		} else {
			m = &certificateRequestMsg{
				hasSignatureAlgorithm: c.vers >= VersionTLS12,
			}
		}
	case typeCertificateStatus:
		m = new(certificateStatusMsg)
	case typeServerKeyExchange:
		m = new(serverKeyExchangeMsg)
	case typeServerHelloDone:
		m = new(serverHelloDoneMsg)
	case typeClientKeyExchange:
		m = new(clientKeyExchangeMsg)
	case typeCertificateVerify:
		m = &certificateVerifyMsg{
			hasSignatureAlgorithm: c.vers >= VersionTLS12,
		}
	case typeFinished:
		m = new(finishedMsg)
	case typeEncryptedExtensions:
		m = new(encryptedExtensionsMsg)
	case typeEndOfEarlyData:
		m = new(endOfEarlyDataMsg)
	case typeKeyUpdate:
		m = new(keyUpdateMsg)
	default:
		return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	// The handshake message unmarshalers
	// expect to be able to keep references to data,
	// so pass in a fresh copy that won't be overwritten.
	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	if transcript != nil {
		transcript.Write(data)
	}

	return m, nil
}

var (
	errShutdown = errors.New("tls: protocol is shutdown")
)

// Write writes data to the connection.
//
// As Write calls [Conn.Handshake], in order to prevent indefinite blocking a deadline
// must be set for both [Conn.Read] and Write before Write is called when the handshake
// has not yet completed. See [Conn.SetDeadline], [Conn.SetReadDeadline], and
// [Conn.SetWriteDeadline].
func (c *Conn) Write(b []byte) (int, error) {
	// interlock with Close below
	for {
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			break
		}
	}
	defer c.activeCall.Add(-2)

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.out.Lock()
	defer c.out.Unlock()

	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.isHandshakeComplete.Load() {
		return 0, alertInternalError
	}

	if c.closeNotifySent {
		return 0, errShutdown
	}

	// TLS 1.0 is susceptible to a chosen-plaintext
	// attack when using block mode ciphers due to predictable IVs.
	// This can be prevented by splitting each Application Data
	// record into two records, effectively randomizing the IV.
	//
	// https://www.openssl.org/~bodo/tls-cbc.txt
	// https://bugzilla.mozilla.org/show_bug.cgi?id=665814
	// https://www.imperialviolet.org/2012/01/15/beastfollowup.html

	var m int
	if len(b) > 1 && c.vers == VersionTLS10 {
		if _, ok := c.out.cipher.(cipher.BlockMode); ok {
			n, err := c.writeRecordLocked(recordTypeApplicationData, b[:1])
			if err != nil {
				return n, c.out.setErrorLocked(err)
			}
			m, b = 1, b[1:]
		}
	}

	n, err := c.writeRecordLocked(recordTypeApplicationData, b)
	return n + m, c.out.setErrorLocked(err)
}

// handleRenegotiation processes a HelloRequest handshake message.
func (c *Conn) handleRenegotiation() error {
	if c.vers == VersionTLS13 {
		return errors.New("tls: internal error: unexpected renegotiation")
	}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	helloReq, ok := msg.(*helloRequestMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(helloReq, msg)
	}

	if !c.isClient {
		return c.sendAlert(alertNoRenegotiation)
	}

	switch c.config.Renegotiation {
	case RenegotiateNever:
		return c.sendAlert(alertNoRenegotiation)
	case RenegotiateOnceAsClient:
		if c.handshakes > 1 {
			return c.sendAlert(alertNoRenegotiation)
		}
	case RenegotiateFreelyAsClient:
		// Ok.
	default:
		c.sendAlert(alertInternalError)
		return errors.New("tls: unknown Renegotiation value")
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	c.isHandshakeComplete.Store(false)
	if c.handshakeErr = c.clientHandshake(context.Background()); c.handshakeErr == nil {
		c.handshakes++
	}
	return c.handshakeErr
}

// handlePostHandshakeMessage processes a handshake message arrived after the
// handshake is complete. Up to TLS 1.2, it indicates the start of a renegotiation.
func (c *Conn) handlePostHandshakeMessage() error {
	if c.vers != VersionTLS13 {
		return c.handleRenegotiation()
	}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tls: too many non-advancing records"))
	}

	switch msg := msg.(type) {
	case *newSessionTicketMsgTLS13:
		return c.handleNewSessionTicket(msg)
	case *keyUpdateMsg:
		return c.handleKeyUpdate(msg)
	}
	// The QUIC layer is supposed to treat an unexpected post-handshake CertificateRequest
	// as a QUIC-level PROTOCOL_VIOLATION error (RFC 9001, Section 4.4). Returning an
	// unexpected_message alert here doesn't provide it with enough information to distinguish
	// this condition from other unexpected messages. This is probably fine.
	c.sendAlert(alertUnexpectedMessage)
	return fmt.Errorf("tls: received unexpected handshake message of type %T", msg)
}

func (c *Conn) handleKeyUpdate(keyUpdate *keyUpdateMsg) error {
	if c.quic != nil {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tls: received unexpected key update message"))
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil {
		return c.in.setErrorLocked(c.sendAlert(alertInternalError))
	}

	newSecret := cipherSuite.nextTrafficSecret(c.in.trafficSecret)
	c.in.setTrafficSecret(cipherSuite, QUICEncryptionLevelInitial, newSecret)

	if keyUpdate.updateRequested {
		c.out.Lock()
		defer c.out.Unlock()

		msg := &keyUpdateMsg{}
		msgBytes, err := msg.marshal()
		if err != nil {
			return err
		}
		_, err = c.writeRecordLocked(recordTypeHandshake, msgBytes)
		if err != nil {
			// Surface the error at the next write.
			c.out.setErrorLocked(err)
			return nil
		}

		newSecret := cipherSuite.nextTrafficSecret(c.out.trafficSecret)
		c.out.setTrafficSecret(cipherSuite, QUICEncryptionLevelInitial, newSecret)
	}

	return nil
}

// Read reads data from the connection.
//
// As Read calls [Conn.Handshake], in order to prevent indefinite blocking a deadline
// must be set for both Read and [Conn.Write] before Read is called when the handshake
// has not yet completed. See [Conn.SetDeadline], [Conn.SetReadDeadline], and
// [Conn.SetWriteDeadline].
func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return 0, nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	for c.input.Len() == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
		for c.hand.Len() > 0 {
			if err := c.handlePostHandshakeMessage(); err != nil {
				return 0, err
			}
		}
	}

	n, _ := c.input.Read(b)

	// If a close-notify alert is waiting, read it so that we can return (n,
	// EOF) instead of (n, nil), to signal to the HTTP response reading
	// goroutine that the connection is now closed. This eliminates a race
	// where the HTTP response reading goroutine would otherwise not observe
	// the EOF until its next read, by which time a client goroutine might
	// have already tried to reuse the HTTP connection for a new request.
	// See https://golang.org/cl/76400046 and https://golang.org/issue/3514
	if n != 0 && c.input.Len() == 0 && c.rawInput.Len() > 0 &&
		recordType(c.rawInput.Bytes()[0]) == recordTypeAlert {
		if err := c.readRecord(); err != nil {
			return n, err // will be io.EOF on closeNotify
		}
	}

	return n, nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	// Interlock with Conn.Write above.
	var x int32
	for {
		x = c.activeCall.Load()
		if x&1 != 0 {
			return net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x|1) {
			break
		}
	}
	if x != 0 {
		// io.Writer and io.Closer should not be used concurrently.
		// If Close is called while a Write is currently in-flight,
		// interpret that as a sign that this Close is really just
		// being used to break the Write and/or clean up resources and
		// avoid sending the alertCloseNotify, which may block
		// waiting on handshakeMutex or the c.out mutex.
		return c.conn.Close()
	}

	var alertErr error
	if c.isHandshakeComplete.Load() {
		if err := c.closeNotify(); err != nil {
			alertErr = fmt.Errorf("tls: failed to send closeNotify alert (but connection was closed anyway): %w", err)
		}
	}

	if err := c.conn.Close(); err != nil {
		return err
	}
	return alertErr
}

var errEarlyCloseWrite = errors.New("tls: CloseWrite called before handshake complete")

// CloseWrite shuts down the writing side of the connection. It should only be
// called once the handshake has completed and does not call CloseWrite on the
// underlying connection. Most callers should just use [Conn.Close].
func (c *Conn) CloseWrite() error {
	if !c.isHandshakeComplete.Load() {
		return errEarlyCloseWrite
	}

	return c.closeNotify()
}

func (c *Conn) closeNotify() error {
	c.out.Lock()
	defer c.out.Unlock()

	if !c.closeNotifySent {
		// Set a Write Deadline to prevent possibly blocking forever.
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		c.closeNotifyErr = c.sendAlertLocked(alertCloseNotify)
		c.closeNotifySent = true
		// Any subsequent writes will fail.
		c.SetWriteDeadline(time.Now())
	}
	return c.closeNotifyErr
}

// Handshake runs the client or server handshake
// protocol if it has not yet been run.
//
// Most uses of this package need not call Handshake explicitly: the
// first [Conn.Read] or [Conn.Write] will call it automatically.
//
// For control over canceling or setting a timeout on a handshake, use
// [Conn.HandshakeContext] or the [Dialer]'s DialContext method instead.
//
// In order to avoid denial of service attacks, the maximum RSA key size allowed
// in certificates sent by either the TLS server or client is limited to 8192
// bits. This limit can be overridden by setting tlsmaxrsasize in the GODEBUG
// environment variable (e.g. GODEBUG=tlsmaxrsasize=4096).
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext runs the client or server handshake
// protocol if it has not yet been run.
//
// The provided Context must be non-nil. If the context is canceled before
// the handshake is complete, the handshake is interrupted and an error is returned.
// Once the handshake has completed, cancellation of the context will not affect the
// connection.
//
// Most uses of this package need not call HandshakeContext explicitly: the
// first [Conn.Read] or [Conn.Write] will call it automatically.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	// Delegate to unexported method for named return
	// without confusing documented signature.
	return c.handshakeContext(ctx)
}

func (c *Conn) handshakeContext(ctx context.Context) (ret error) {
	// Fast sync/atomic-based exit if there is no handshake in flight and the
	// last one succeeded without an error. Avoids the expensive context setup
	// and mutex for most Read and Write calls.
	if c.isHandshakeComplete.Load() {
		return nil
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	// Note: defer this before starting the "interrupter" goroutine
	// so that we can tell the difference between the input being canceled and
	// this cancellation. In the former case, we need to close the connection.
	defer cancel()

	if c.quic != nil {
		c.quic.cancelc = handshakeCtx.Done()
		c.quic.cancel = cancel
	} else if ctx.Done() != nil {
		// Start the "interrupter" goroutine, if this context might be canceled.
		// (The background context cannot).
		//
		// The interrupter goroutine waits for the input context to be done and
		// closes the connection if this happens before the function returns.
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				// Return context error to user.
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-handshakeCtx.Done():
				// Close the connection, discarding the error
				_ = c.conn.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.isHandshakeComplete.Load() {
		return nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	c.handshakeErr = c.handshakeFn(handshakeCtx)
	if c.handshakeErr == nil {
		c.handshakes++
	} else {
		// If an error occurred during the handshake try to flush the
		// alert that might be left in the buffer.
		c.flush()
	}

	if c.handshakeErr == nil && !c.isHandshakeComplete.Load() {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}
	if c.handshakeErr != nil && c.isHandshakeComplete.Load() {
		panic("tls: internal error: handshake returned an error but is marked successful")
	}

	if c.quic != nil {
		if c.handshakeErr == nil {
			c.quicHandshakeComplete()
			// Provide the 1-RTT read secret now that the handshake is complete.
			// The QUIC layer MUST NOT decrypt 1-RTT packets prior to completing
			// the handshake (RFC 9001, Section 5.7).
			c.quicSetReadSecret(QUICEncryptionLevelApplication, c.cipherSuite, c.in.trafficSecret)
		} else {
			var a alert
			c.out.Lock()
			if !errors.As(c.out.err, &a) {
				a = alertInternalError
			}
			c.out.Unlock()
			// Return an error which wraps both the handshake error and
			// any alert error we may have sent, or alertInternalError
			// if we didn't send an alert.
			// Truncate the text of the alert to 0 characters.
			c.handshakeErr = fmt.Errorf("%w%.0w", c.handshakeErr, AlertError(a))
		}
		close(c.quic.blockedc)
		close(c.quic.signalc)
	}

	return c.handshakeErr
}

// ConnectionState returns basic TLS details about the connection.
func (c *Conn) ConnectionState() ConnectionState {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	return c.connectionStateLocked()
}

var tlsunsafeekm = godebug.New("tlsunsafeekm")

func (c *Conn) connectionStateLocked() ConnectionState {
	var state ConnectionState
	state.HandshakeComplete = c.isHandshakeComplete.Load()
	state.Version = c.vers
	state.NegotiatedProtocol = c.clientProtocol
	state.DidResume = c.didResume
	state.testingOnlyDidHRR = c.didHRR
	// c.curveID is not set on TLS 1.0–1.2 resumptions. Fix that before exposing it.
	state.testingOnlyCurveID = c.curveID
	state.NegotiatedProtocolIsMutual = true
	state.ServerName = c.serverName
	state.CipherSuite = c.cipherSuite
	state.PeerCertificates = c.peerCertificates
	state.VerifiedChains = c.verifiedChains
	state.SignedCertificateTimestamps = c.scts
	state.OCSPResponse = c.ocspResponse
	if (!c.didResume || c.extMasterSecret) && c.vers != VersionTLS13 {
		if c.clientFinishedIsFirst {
			state.TLSUnique = c.clientFinished[:]
		} else {
			state.TLSUnique = c.serverFinished[:]
		}
	}
	if c.config.Renegotiation != RenegotiateNever {
		state.ekm = noEKMBecauseRenegotiation
	} else if c.vers != VersionTLS13 && !c.extMasterSecret {
		state.ekm = func(label string, context []byte, length int) ([]byte, error) {
			if tlsunsafeekm.Value() == "1" {
				tlsunsafeekm.IncNonDefault()
				return c.ekm(label, context, length)
			}
			return noEKMBecauseNoEMS(label, context, length)
		}
	} else {
		state.ekm = c.ekm
	}
	state.ECHAccepted = c.echAccepted
	return state
}

// OCSPResponse returns the stapled OCSP response from the TLS server, if
// any. (Only valid for client connections.)
func (c *Conn) OCSPResponse() []byte {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	return c.ocspResponse
}

// VerifyHostname checks that the peer certificate chain is valid for
// connecting to host. If so, it returns nil; if not, it returns an error
// describing the problem.
func (c *Conn) VerifyHostname(host string) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if !c.isClient {
		return errors.New("tls: VerifyHostname called on TLS server connection")
	}
	if !c.isHandshakeComplete.Load() {
		return errors.New("tls: handshake has not yet been performed")
	}
	if len(c.verifiedChains) == 0 {
		return errors.New("tls: handshake did not verify certificate chain")
	}
	return c.peerCertificates[0].VerifyHostname(host)
}
```