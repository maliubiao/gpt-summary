Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - What is this about?**

The code resides in `go/src/crypto/tls/quic.go`. The package name is `tls`, and the filename mentions `quic`. This immediately suggests this code is about integrating QUIC (Quick UDP Internet Connections) with the Go `crypto/tls` package, which handles TLS (Transport Layer Security). The copyright notice further confirms this is part of the standard Go library.

**2. Identifying Core Data Structures:**

I start by looking for the main types and their relationships. The key structures are:

* `QUICEncryptionLevel`:  An enum representing different stages of QUIC's encryption handshake. The `String()` method is a giveaway for an enum.
* `QUICConn`: Represents a QUIC connection. It holds a standard `tls.Conn` and a flag for session tickets. The comment explicitly states it's for RFC 9001.
* `QUICConfig`: Configuration options for a `QUICConn`, including the standard TLS config and a flag for enabling session events.
* `QUICEventKind`: An enum defining different events that can occur during the QUIC handshake. The `iota` keyword strongly suggests an enum.
* `QUICEvent`:  Represents a specific event, holding the `Kind` and additional data depending on the event type.
* `quicState`:  Internal state associated with a QUIC connection, managing event queues, synchronization, and handshake buffers.

**3. Tracing the Flow and Purpose of Key Functions:**

Next, I examine the functions and how they interact with the data structures:

* **Constructors (`QUICClient`, `QUICServer`, `newQUICConn`):** These functions create `QUICConn` instances, linking them to underlying `tls.Conn` objects. They initialize the internal `quicState`. The client and server functions take a `QUICConfig`.
* **`Start()`:**  This function initiates the QUIC handshake. It checks for minimum TLS version (1.3) and launches a goroutine for the handshake. The use of channels (`blockedc`) suggests synchronization.
* **`NextEvent()`:** This is crucial. It retrieves the next event from the internal queue (`qs.events`). The logic for clearing the `Data` field hints at ownership management of the event data.
* **`Close()`:**  Handles closing the connection, including canceling the handshake goroutine. The loop waiting on `blockedc` is important for ensuring the handshake goroutine finishes.
* **`HandleData()`:**  Processes incoming handshake data. It checks the encryption level and uses channels (`signalc`, `blockedc`) for communication with the handshake goroutine. The logic to handle fragmented handshake messages is visible.
* **`SendSessionTicket()`:** Sends a session ticket (for session resumption). It has checks to ensure it's called at the right time and on the correct side (server).
* **`StoreSession()`:** Allows the application to store a received session ticket. This is primarily for clients.
* **`ConnectionState()`:**  Delegates to the underlying `tls.Conn` for basic TLS information.
* **`SetTransportParameters()`:** Sets the QUIC transport parameters. The use of channels suggests synchronization if called after `Start`.
* **Helper functions (`quicError`, `quicReadHandshakeBytes`, `quicSetReadSecret`, etc.):** These functions manage internal state and event generation within the `tls.Conn`. The prefixes (`quic`) are a clear indication of their purpose.

**4. Identifying the "Go Language Feature" (the core question):**

Based on the structures and functions, the core Go language feature being implemented is **integration of a custom transport protocol (QUIC) with the existing TLS framework**. This involves:

* **Defining specific events and states for the QUIC handshake.** This is done through the `QUICEncryptionLevel`, `QUICEventKind`, and `QUICEvent` types.
* **Using goroutines and channels for asynchronous communication** between the main QUIC connection management and the underlying TLS handshake. This is evident in `Start()`, `HandleData()`, and the `quicState`.
* **Extending the existing `tls.Conn` with QUIC-specific logic.** The `conn.quic` field and the `quic*` prefixed functions show this extension.

**5. Constructing the Code Example:**

To illustrate this, I thought about a simplified client-side scenario. The key actions would be:

* Creating a `QUICConfig`.
* Creating a `QUICClient`.
* Starting the handshake.
* Handling events using `NextEvent()`.
* Specifically looking for `QUICSetReadSecret`, `QUICSetWriteSecret`, and `QUICHandshakeDone` as these are fundamental to the handshake process.
* Potentially handling transport parameters if the server requires them.

**6. Identifying Potential Pitfalls:**

I looked for areas where a developer might make mistakes:

* **Calling `Start()` multiple times:** The code explicitly checks for this.
* **Incorrect TLS version:**  The minimum version check in `Start()` is important.
* **Not handling events from `NextEvent()`:**  The handshake won't progress if events aren't processed. The `QUICNoEvent` return is crucial to understand.
* **Calling `SendSessionTicket()` at the wrong time or on the wrong side.** The checks in `SendSessionTicket()` highlight these errors.
* **Forgetting to call `StoreSession()` when `EnableSessionEvents` is true.**  The comment for `EnableSessionEvents` clearly states this.

**7. Structuring the Answer (Chinese):**

Finally, I organized the information into a clear and concise Chinese answer, addressing each part of the prompt:

* **功能列表 (List of Functions):**  A straightforward bulleted list of the identified functionalities.
* **实现的Go语言功能 (Implemented Go Language Feature):**  A clear explanation of the integration of QUIC with TLS.
* **Go代码举例说明 (Go Code Example):**  Providing a working client-side example with clear steps and comments. I considered a server example too, but a client is often simpler to illustrate the event-driven nature.
* **代码推理 (Code Reasoning):**  Explaining the assumptions made for the code example and the expected input/output.
* **命令行参数 (Command-line Arguments):** Noting that this specific code doesn't directly handle command-line arguments, as it's a library component.
* **使用者易犯错的点 (Common Mistakes):**  Listing the identified pitfalls with explanations.

Throughout the process, I focused on understanding the *purpose* of the code and how the different parts interact to achieve that purpose. The naming conventions in Go (`QUIC`, prefixes like `quic*`) are very helpful in understanding the code's organization and intent.
这段代码是 Go 语言 `crypto/tls` 包中关于 QUIC (Quick UDP Internet Connections) 协议支持的一部分实现。它定义了用于管理 QUIC 连接和处理 QUIC 特有事件的结构体和方法。

**它的主要功能包括:**

1. **定义 QUIC 加密级别 (`QUICEncryptionLevel`)**:  它定义了 QUIC 握手过程中不同的加密级别，例如 `Initial`、`Early`、`Handshake` 和 `Application`。这有助于区分在不同握手阶段发送的消息。

2. **表示 QUIC 连接 (`QUICConn`)**:  `QUICConn` 结构体封装了一个标准的 `tls.Conn`，并添加了 QUIC 特有的状态，例如 `sessionTicketSent`，用于跟踪会话票据的发送状态。

3. **配置 QUIC 连接 (`QUICConfig`)**:  `QUICConfig` 结构体允许用户配置 QUIC 连接，例如指定底层的 TLS 配置 (`TLSConfig`) 以及是否启用会话事件 (`EnableSessionEvents`)。启用会话事件后，客户端的会话将不会自动存储在会话缓存中，需要应用手动管理。

4. **定义 QUIC 事件类型 (`QUICEventKind`)**:  `QUICEventKind` 枚举定义了 QUIC 连接上可能发生的各种事件，例如设置读写密钥、写入数据、接收传输参数、握手完成、会话恢复和会话存储等。

5. **表示 QUIC 事件 (`QUICEvent`)**:  `QUICEvent` 结构体用于表示一个具体的 QUIC 事件，包含事件类型 (`Kind`) 以及与该事件相关的数据，例如加密级别 (`Level`)、数据 (`Data`)、加密套件 (`Suite`) 和会话状态 (`SessionState`)。

6. **管理 QUIC 连接状态 (`quicState`)**:  `quicState` 结构体维护了 QUIC 连接的内部状态，包括事件队列、同步 channel、握手 buffer 和传输参数等。

7. **创建 QUIC 客户端和服务器连接 (`QUICClient`, `QUICServer`)**:  这两个函数分别用于创建使用 QUIC 作为底层传输的 TLS 客户端和服务器连接。它们接收一个 `QUICConfig` 作为参数。

8. **启动 QUIC 握手 (`Start`)**:  `Start` 方法用于启动 QUIC 的握手协议。它会执行一些检查，例如最小 TLS 版本，并启动一个 goroutine 来执行握手。

9. **获取下一个 QUIC 事件 (`NextEvent`)**:  `NextEvent` 方法用于从内部事件队列中获取下一个发生的 QUIC 事件。如果没有事件可用，则返回 `QUICNoEvent`。

10. **关闭 QUIC 连接 (`Close`)**:  `Close` 方法用于关闭 QUIC 连接，并停止任何正在进行的握手。

11. **处理接收到的握手数据 (`HandleData`)**:  `HandleData` 方法用于处理从对端接收到的握手数据。它根据加密级别将数据传递给底层的 TLS 连接进行处理。

12. **发送会话票据 (`SendSessionTicket`)**:  `SendSessionTicket` 方法用于向客户端发送会话票据，以便客户端在后续连接中恢复会话。

13. **存储会话 (`StoreSession`)**:  `StoreSession` 方法允许应用程序手动存储接收到的会话，通常在 `QUICStoreSession` 事件发生时调用。

14. **获取连接状态 (`ConnectionState`)**:  `ConnectionState` 方法返回底层的 TLS 连接状态。

15. **设置传输参数 (`SetTransportParameters`)**:  `SetTransportParameters` 方法用于设置要发送给对端的 QUIC 传输参数。

16. **内部辅助函数**: 代码中还包含一些内部辅助函数，例如 `quicError` 用于确保错误类型是 `AlertError`，以及一些以 `quic` 开头的函数用于在 TLS 连接内部管理 QUIC 特有的状态和事件。

**它是什么Go语言功能的实现？**

这段代码实现了 **将 QUIC 协议集成到 Go 语言的 `crypto/tls` 包中** 的功能。它允许 Go 程序使用 QUIC 作为 TLS 连接的底层传输协议。这涉及到定义 QUIC 特有的连接状态、事件类型以及处理 QUIC 握手流程的方法。

**Go代码举例说明:**

以下是一个简化的客户端使用这段代码的例子：

```go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
)

func main() {
	config := &tls.QUICConfig{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // 仅用于演示
			NextProtos:         []string{"h3"}, // 声明支持的 ALPN
		},
	}

	conn, err := net.Dial("udp", "localhost:1234")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// 假设我们已经建立了一个底层的 UDP 连接

	// 使用底层的 UDP 连接创建 QUIC 连接
	tlsConn := tls.QUICClient(config)

	// 启动握手
	if err := tlsConn.Start(context.Background()); err != nil {
		log.Fatal(err)
	}

	fmt.Println("QUIC handshake started")

	// 循环处理事件
	for {
		event := tlsConn.NextEvent()
		switch event.Kind {
		case tls.QUICNoEvent:
			fmt.Println("No more events")
			return
		case tls.QUICSetReadSecret:
			fmt.Printf("Received read secret for level: %s, suite: %d\n", event.Level, event.Suite)
			// 这里应该使用 event.Data 中的密钥来解密接收到的数据
		case tls.QUICSetWriteSecret:
			fmt.Printf("Received write secret for level: %s, suite: %d\n", event.Level, event.Suite)
			// 这里应该使用 event.Data 中的密钥来加密要发送的数据
		case tls.QUICWriteData:
			fmt.Printf("Need to send data at level: %s, length: %d\n", event.Level, len(event.Data))
			// 假设我们有一个函数 sendDataOverUDP(level, data) 来发送数据
			// sendDataOverUDP(event.Level, event.Data)
		case tls.QUICTransportParameters:
			fmt.Println("Received transport parameters:", event.Data)
		case tls.QUICHandshakeDone:
			fmt.Println("QUIC handshake completed!")
			return
		case tls.QUICTransportParametersRequired:
			fmt.Println("Transport parameters required, setting them...")
			// 实际应用中需要根据需求设置合适的传输参数
			tlsConn.SetTransportParameters([]byte{ /* 你的传输参数 */ })
		case tls.QUICRejectedEarlyData:
			fmt.Println("Server rejected early data")
		case tls.QUICResumeSession:
			fmt.Println("Attempting to resume session")
			// 可以根据需要设置 event.SessionState.EarlyData
		case tls.QUICStoreSession:
			fmt.Println("Received session to store")
			// 应用应该调用 tlsConn.StoreSession(event.SessionState) 来存储会话
			tlsConn.StoreSession(event.SessionState)
		default:
			fmt.Printf("Received unknown event: %v\n", event)
		}
	}
}
```

**假设的输入与输出:**

在这个例子中，假设我们已经建立了一个连接到 `localhost:1234` 的 UDP 连接。

**可能的输出:**

```
QUIC handshake started
Received read secret for level: Initial, suite: 0
Received write secret for level: Initial, suite: 0
Need to send data at level: Initial, length: ...
Received transport parameters: ...
Received read secret for level: Handshake, suite: ...
Received write secret for level: Handshake, suite: ...
Need to send data at level: Handshake, length: ...
Received read secret for level: Application, suite: ...
Received write secret for level: Application, suite: ...
QUIC handshake completed!
No more events
```

输出的具体内容会根据实际的网络交互和服务器的响应而变化。关键在于 `NextEvent` 方法返回的不同类型的事件，以及在不同阶段需要执行的操作（例如，使用密钥加密/解密数据，发送握手消息）。

**命令行参数的具体处理:**

这段代码本身是库代码，并不直接处理命令行参数。 命令行参数的处理通常发生在调用此库的应用程序中。 例如，一个使用此库的 QUIC 客户端程序可能会使用 `flag` 包来解析命令行参数，例如服务器地址、端口号等，然后将这些参数传递给 `net.Dial` 或配置 `tls.QUICConfig`。

**使用者易犯错的点:**

1. **未调用 `NextEvent` 处理事件:** QUIC 的握手是事件驱动的。如果使用者在调用 `Start` 后没有循环调用 `NextEvent` 来处理返回的事件，握手将无法完成。例如，如果服务器需要客户端提供传输参数（`QUICTransportParametersRequired` 事件），而客户端没有处理这个事件并调用 `SetTransportParameters`，连接将会卡住。

   ```go
   // 错误示例：启动握手后没有处理事件
   if err := tlsConn.Start(context.Background()); err != nil {
       log.Fatal(err)
   }
   // ... 这里缺少循环调用 NextEvent 的代码 ...
   ```

2. **在握手完成前尝试发送应用数据:** 在 `QUICHandshakeDone` 事件发生之前，连接可能还没有建立好安全的加密通道。尝试过早发送应用数据可能会失败或导致安全问题。使用者应该监听 `QUICHandshakeDone` 事件后再开始发送应用数据。

3. **错误地管理会话 (`EnableSessionEvents` 为 true 的情况):** 如果 `QUICConfig.EnableSessionEvents` 设置为 `true`，客户端不会自动缓存会话。使用者必须处理 `QUICStoreSession` 事件，并调用 `QUICConn.StoreSession` 来手动存储会话，以便后续的连接可以恢复会话。忘记这样做会导致无法利用会话恢复的优势。

   ```go
   // 假设 EnableSessionEvents 为 true
   for {
       event := tlsConn.NextEvent()
       switch event.Kind {
       case tls.QUICStoreSession:
           // 正确的做法是存储会话
           tlsConn.StoreSession(event.SessionState)
       // ... 其他事件处理 ...
       }
   }

   // 错误的做法是忽略 QUICStoreSession 事件
   ```

4. **在错误的时机调用 `SendSessionTicket`:**  `SendSessionTicket` 只能在服务器端且握手完成后调用一次。在客户端调用或者在握手完成前多次调用会导致错误。

   ```go
   // 错误示例 (客户端调用)
   if !isServer {
       err := tlsConn.SendSessionTicket(tls.QUICSessionTicketOptions{}) // 错误！
       if err != nil {
           log.Println("Error sending session ticket:", err)
       }
   }
   ```

理解这些功能和潜在的错误点，可以帮助开发者正确地使用 Go 语言的 `crypto/tls` 包来实现基于 QUIC 的安全连接。

Prompt: 
```
这是路径为go/src/crypto/tls/quic.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"errors"
	"fmt"
)

// QUICEncryptionLevel represents a QUIC encryption level used to transmit
// handshake messages.
type QUICEncryptionLevel int

const (
	QUICEncryptionLevelInitial = QUICEncryptionLevel(iota)
	QUICEncryptionLevelEarly
	QUICEncryptionLevelHandshake
	QUICEncryptionLevelApplication
)

func (l QUICEncryptionLevel) String() string {
	switch l {
	case QUICEncryptionLevelInitial:
		return "Initial"
	case QUICEncryptionLevelEarly:
		return "Early"
	case QUICEncryptionLevelHandshake:
		return "Handshake"
	case QUICEncryptionLevelApplication:
		return "Application"
	default:
		return fmt.Sprintf("QUICEncryptionLevel(%v)", int(l))
	}
}

// A QUICConn represents a connection which uses a QUIC implementation as the underlying
// transport as described in RFC 9001.
//
// Methods of QUICConn are not safe for concurrent use.
type QUICConn struct {
	conn *Conn

	sessionTicketSent bool
}

// A QUICConfig configures a [QUICConn].
type QUICConfig struct {
	TLSConfig *Config

	// EnableSessionEvents may be set to true to enable the
	// [QUICStoreSession] and [QUICResumeSession] events for client connections.
	// When this event is enabled, sessions are not automatically
	// stored in the client session cache.
	// The application should use [QUICConn.StoreSession] to store sessions.
	EnableSessionEvents bool
}

// A QUICEventKind is a type of operation on a QUIC connection.
type QUICEventKind int

const (
	// QUICNoEvent indicates that there are no events available.
	QUICNoEvent QUICEventKind = iota

	// QUICSetReadSecret and QUICSetWriteSecret provide the read and write
	// secrets for a given encryption level.
	// QUICEvent.Level, QUICEvent.Data, and QUICEvent.Suite are set.
	//
	// Secrets for the Initial encryption level are derived from the initial
	// destination connection ID, and are not provided by the QUICConn.
	QUICSetReadSecret
	QUICSetWriteSecret

	// QUICWriteData provides data to send to the peer in CRYPTO frames.
	// QUICEvent.Data is set.
	QUICWriteData

	// QUICTransportParameters provides the peer's QUIC transport parameters.
	// QUICEvent.Data is set.
	QUICTransportParameters

	// QUICTransportParametersRequired indicates that the caller must provide
	// QUIC transport parameters to send to the peer. The caller should set
	// the transport parameters with QUICConn.SetTransportParameters and call
	// QUICConn.NextEvent again.
	//
	// If transport parameters are set before calling QUICConn.Start, the
	// connection will never generate a QUICTransportParametersRequired event.
	QUICTransportParametersRequired

	// QUICRejectedEarlyData indicates that the server rejected 0-RTT data even
	// if we offered it. It's returned before QUICEncryptionLevelApplication
	// keys are returned.
	// This event only occurs on client connections.
	QUICRejectedEarlyData

	// QUICHandshakeDone indicates that the TLS handshake has completed.
	QUICHandshakeDone

	// QUICResumeSession indicates that a client is attempting to resume a previous session.
	// [QUICEvent.SessionState] is set.
	//
	// For client connections, this event occurs when the session ticket is selected.
	// For server connections, this event occurs when receiving the client's session ticket.
	//
	// The application may set [QUICEvent.SessionState.EarlyData] to false before the
	// next call to [QUICConn.NextEvent] to decline 0-RTT even if the session supports it.
	QUICResumeSession

	// QUICStoreSession indicates that the server has provided state permitting
	// the client to resume the session.
	// [QUICEvent.SessionState] is set.
	// The application should use [QUICConn.StoreSession] session to store the [SessionState].
	// The application may modify the [SessionState] before storing it.
	// This event only occurs on client connections.
	QUICStoreSession
)

// A QUICEvent is an event occurring on a QUIC connection.
//
// The type of event is specified by the Kind field.
// The contents of the other fields are kind-specific.
type QUICEvent struct {
	Kind QUICEventKind

	// Set for QUICSetReadSecret, QUICSetWriteSecret, and QUICWriteData.
	Level QUICEncryptionLevel

	// Set for QUICTransportParameters, QUICSetReadSecret, QUICSetWriteSecret, and QUICWriteData.
	// The contents are owned by crypto/tls, and are valid until the next NextEvent call.
	Data []byte

	// Set for QUICSetReadSecret and QUICSetWriteSecret.
	Suite uint16

	// Set for QUICResumeSession and QUICStoreSession.
	SessionState *SessionState
}

type quicState struct {
	events    []QUICEvent
	nextEvent int

	// eventArr is a statically allocated event array, large enough to handle
	// the usual maximum number of events resulting from a single call: transport
	// parameters, Initial data, Early read secret, Handshake write and read
	// secrets, Handshake data, Application write secret, Application data.
	eventArr [8]QUICEvent

	started  bool
	signalc  chan struct{}   // handshake data is available to be read
	blockedc chan struct{}   // handshake is waiting for data, closed when done
	cancelc  <-chan struct{} // handshake has been canceled
	cancel   context.CancelFunc

	waitingForDrain bool

	// readbuf is shared between HandleData and the handshake goroutine.
	// HandshakeCryptoData passes ownership to the handshake goroutine by
	// reading from signalc, and reclaims ownership by reading from blockedc.
	readbuf []byte

	transportParams []byte // to send to the peer

	enableSessionEvents bool
}

// QUICClient returns a new TLS client side connection using QUICTransport as the
// underlying transport. The config cannot be nil.
//
// The config's MinVersion must be at least TLS 1.3.
func QUICClient(config *QUICConfig) *QUICConn {
	return newQUICConn(Client(nil, config.TLSConfig), config)
}

// QUICServer returns a new TLS server side connection using QUICTransport as the
// underlying transport. The config cannot be nil.
//
// The config's MinVersion must be at least TLS 1.3.
func QUICServer(config *QUICConfig) *QUICConn {
	return newQUICConn(Server(nil, config.TLSConfig), config)
}

func newQUICConn(conn *Conn, config *QUICConfig) *QUICConn {
	conn.quic = &quicState{
		signalc:             make(chan struct{}),
		blockedc:            make(chan struct{}),
		enableSessionEvents: config.EnableSessionEvents,
	}
	conn.quic.events = conn.quic.eventArr[:0]
	return &QUICConn{
		conn: conn,
	}
}

// Start starts the client or server handshake protocol.
// It may produce connection events, which may be read with [QUICConn.NextEvent].
//
// Start must be called at most once.
func (q *QUICConn) Start(ctx context.Context) error {
	if q.conn.quic.started {
		return quicError(errors.New("tls: Start called more than once"))
	}
	q.conn.quic.started = true
	if q.conn.config.MinVersion < VersionTLS13 {
		return quicError(errors.New("tls: Config MinVersion must be at least TLS 1.3"))
	}
	go q.conn.HandshakeContext(ctx)
	if _, ok := <-q.conn.quic.blockedc; !ok {
		return q.conn.handshakeErr
	}
	return nil
}

// NextEvent returns the next event occurring on the connection.
// It returns an event with a Kind of [QUICNoEvent] when no events are available.
func (q *QUICConn) NextEvent() QUICEvent {
	qs := q.conn.quic
	if last := qs.nextEvent - 1; last >= 0 && len(qs.events[last].Data) > 0 {
		// Write over some of the previous event's data,
		// to catch callers erroniously retaining it.
		qs.events[last].Data[0] = 0
	}
	if qs.nextEvent >= len(qs.events) && qs.waitingForDrain {
		qs.waitingForDrain = false
		<-qs.signalc
		<-qs.blockedc
	}
	if qs.nextEvent >= len(qs.events) {
		qs.events = qs.events[:0]
		qs.nextEvent = 0
		return QUICEvent{Kind: QUICNoEvent}
	}
	e := qs.events[qs.nextEvent]
	qs.events[qs.nextEvent] = QUICEvent{} // zero out references to data
	qs.nextEvent++
	return e
}

// Close closes the connection and stops any in-progress handshake.
func (q *QUICConn) Close() error {
	if q.conn.quic.cancel == nil {
		return nil // never started
	}
	q.conn.quic.cancel()
	for range q.conn.quic.blockedc {
		// Wait for the handshake goroutine to return.
	}
	return q.conn.handshakeErr
}

// HandleData handles handshake bytes received from the peer.
// It may produce connection events, which may be read with [QUICConn.NextEvent].
func (q *QUICConn) HandleData(level QUICEncryptionLevel, data []byte) error {
	c := q.conn
	if c.in.level != level {
		return quicError(c.in.setErrorLocked(errors.New("tls: handshake data received at wrong level")))
	}
	c.quic.readbuf = data
	<-c.quic.signalc
	_, ok := <-c.quic.blockedc
	if ok {
		// The handshake goroutine is waiting for more data.
		return nil
	}
	// The handshake goroutine has exited.
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	c.hand.Write(c.quic.readbuf)
	c.quic.readbuf = nil
	for q.conn.hand.Len() >= 4 && q.conn.handshakeErr == nil {
		b := q.conn.hand.Bytes()
		n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if n > maxHandshake {
			q.conn.handshakeErr = fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshake)
			break
		}
		if len(b) < 4+n {
			return nil
		}
		if err := q.conn.handlePostHandshakeMessage(); err != nil {
			q.conn.handshakeErr = err
		}
	}
	if q.conn.handshakeErr != nil {
		return quicError(q.conn.handshakeErr)
	}
	return nil
}

type QUICSessionTicketOptions struct {
	// EarlyData specifies whether the ticket may be used for 0-RTT.
	EarlyData bool
	Extra     [][]byte
}

// SendSessionTicket sends a session ticket to the client.
// It produces connection events, which may be read with [QUICConn.NextEvent].
// Currently, it can only be called once.
func (q *QUICConn) SendSessionTicket(opts QUICSessionTicketOptions) error {
	c := q.conn
	if !c.isHandshakeComplete.Load() {
		return quicError(errors.New("tls: SendSessionTicket called before handshake completed"))
	}
	if c.isClient {
		return quicError(errors.New("tls: SendSessionTicket called on the client"))
	}
	if q.sessionTicketSent {
		return quicError(errors.New("tls: SendSessionTicket called multiple times"))
	}
	q.sessionTicketSent = true
	return quicError(c.sendSessionTicket(opts.EarlyData, opts.Extra))
}

// StoreSession stores a session previously received in a QUICStoreSession event
// in the ClientSessionCache.
// The application may process additional events or modify the SessionState
// before storing the session.
func (q *QUICConn) StoreSession(session *SessionState) error {
	c := q.conn
	if !c.isClient {
		return quicError(errors.New("tls: StoreSessionTicket called on the server"))
	}
	cacheKey := c.clientSessionCacheKey()
	if cacheKey == "" {
		return nil
	}
	cs := &ClientSessionState{session: session}
	c.config.ClientSessionCache.Put(cacheKey, cs)
	return nil
}

// ConnectionState returns basic TLS details about the connection.
func (q *QUICConn) ConnectionState() ConnectionState {
	return q.conn.ConnectionState()
}

// SetTransportParameters sets the transport parameters to send to the peer.
//
// Server connections may delay setting the transport parameters until after
// receiving the client's transport parameters. See [QUICTransportParametersRequired].
func (q *QUICConn) SetTransportParameters(params []byte) {
	if params == nil {
		params = []byte{}
	}
	q.conn.quic.transportParams = params
	if q.conn.quic.started {
		<-q.conn.quic.signalc
		<-q.conn.quic.blockedc
	}
}

// quicError ensures err is an AlertError.
// If err is not already, quicError wraps it with alertInternalError.
func quicError(err error) error {
	if err == nil {
		return nil
	}
	var ae AlertError
	if errors.As(err, &ae) {
		return err
	}
	var a alert
	if !errors.As(err, &a) {
		a = alertInternalError
	}
	// Return an error wrapping the original error and an AlertError.
	// Truncate the text of the alert to 0 characters.
	return fmt.Errorf("%w%.0w", err, AlertError(a))
}

func (c *Conn) quicReadHandshakeBytes(n int) error {
	for c.hand.Len() < n {
		if err := c.quicWaitForSignal(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) quicSetReadSecret(level QUICEncryptionLevel, suite uint16, secret []byte) {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind:  QUICSetReadSecret,
		Level: level,
		Suite: suite,
		Data:  secret,
	})
}

func (c *Conn) quicSetWriteSecret(level QUICEncryptionLevel, suite uint16, secret []byte) {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind:  QUICSetWriteSecret,
		Level: level,
		Suite: suite,
		Data:  secret,
	})
}

func (c *Conn) quicWriteCryptoData(level QUICEncryptionLevel, data []byte) {
	var last *QUICEvent
	if len(c.quic.events) > 0 {
		last = &c.quic.events[len(c.quic.events)-1]
	}
	if last == nil || last.Kind != QUICWriteData || last.Level != level {
		c.quic.events = append(c.quic.events, QUICEvent{
			Kind:  QUICWriteData,
			Level: level,
		})
		last = &c.quic.events[len(c.quic.events)-1]
	}
	last.Data = append(last.Data, data...)
}

func (c *Conn) quicResumeSession(session *SessionState) error {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind:         QUICResumeSession,
		SessionState: session,
	})
	c.quic.waitingForDrain = true
	for c.quic.waitingForDrain {
		if err := c.quicWaitForSignal(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) quicStoreSession(session *SessionState) {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind:         QUICStoreSession,
		SessionState: session,
	})
}

func (c *Conn) quicSetTransportParameters(params []byte) {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind: QUICTransportParameters,
		Data: params,
	})
}

func (c *Conn) quicGetTransportParameters() ([]byte, error) {
	if c.quic.transportParams == nil {
		c.quic.events = append(c.quic.events, QUICEvent{
			Kind: QUICTransportParametersRequired,
		})
	}
	for c.quic.transportParams == nil {
		if err := c.quicWaitForSignal(); err != nil {
			return nil, err
		}
	}
	return c.quic.transportParams, nil
}

func (c *Conn) quicHandshakeComplete() {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind: QUICHandshakeDone,
	})
}

func (c *Conn) quicRejectedEarlyData() {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind: QUICRejectedEarlyData,
	})
}

// quicWaitForSignal notifies the QUICConn that handshake progress is blocked,
// and waits for a signal that the handshake should proceed.
//
// The handshake may become blocked waiting for handshake bytes
// or for the user to provide transport parameters.
func (c *Conn) quicWaitForSignal() error {
	// Drop the handshake mutex while blocked to allow the user
	// to call ConnectionState before the handshake completes.
	c.handshakeMutex.Unlock()
	defer c.handshakeMutex.Lock()
	// Send on blockedc to notify the QUICConn that the handshake is blocked.
	// Exported methods of QUICConn wait for the handshake to become blocked
	// before returning to the user.
	select {
	case c.quic.blockedc <- struct{}{}:
	case <-c.quic.cancelc:
		return c.sendAlertLocked(alertCloseNotify)
	}
	// The QUICConn reads from signalc to notify us that the handshake may
	// be able to proceed. (The QUICConn reads, because we close signalc to
	// indicate that the handshake has completed.)
	select {
	case c.quic.signalc <- struct{}{}:
		c.hand.Write(c.quic.readbuf)
		c.quic.readbuf = nil
	case <-c.quic.cancelc:
		return c.sendAlertLocked(alertCloseNotify)
	}
	return nil
}

"""



```