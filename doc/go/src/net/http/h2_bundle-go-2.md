Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for a functional summary of the provided Go code, identifying the broader Go feature it implements, providing an example, and highlighting potential user errors. It also specifies that this is "part 3 of 13" which implies a larger context (likely the HTTP/2 implementation in Go's `net/http` package).

2. **Initial Scan for Keywords and Structures:**  A quick scan reveals recurring keywords and data structures that provide clues about the code's purpose:

    * `http2inflow`, `http2outflow`:  These strongly suggest flow control mechanisms, where `inflow` likely refers to the receiving end's window and `outflow` the sending end's window.
    * `maxWindow`:  This constant reinforces the flow control idea, suggesting a limit on window size.
    * `unsent`, `avail`, `take`, `add`: These are typical operations associated with managing a buffer or a window.
    * `http2FrameType`, `http2FrameHeader`, `http2Flags`, `http2Framer`: These point to the structure and processing of HTTP/2 frames.
    * Specific frame types like `http2FrameData`, `http2FrameHeaders`, `http2FrameSettings`, etc.:  This confirms the code is related to HTTP/2.
    * `WriteData`, `WriteSettings`, `WritePing`, etc.: These are clearly functions for creating and writing different types of HTTP/2 frames.
    * `ReadFrame`, `ReadFrameHeader`:  These are for reading and parsing incoming HTTP/2 frames.

3. **Focus on Core Data Structures:**  Deep dive into the `http2inflow` and `http2outflow` structs. Understand their fields and methods. For example:

    * `http2inflow`:  `unsent` (amount of window update not yet sent), `avail` (available window). The `add` method updates these, respecting `maxWindow`. The `take` method reduces the available window.
    * `http2outflow`: `n` (number of bytes allowed to send), `conn` (pointer to connection-level outflow). The `available` method considers both stream and connection-level limits. The `take` method reduces the allowed sending amount.

4. **Identify the Broader Feature:** Based on the keywords and data structures, it becomes clear that this code implements **HTTP/2 flow control** and the **structure and processing of HTTP/2 frames**.

5. **Code Example (Flow Control):** Create a simple example to illustrate how flow control works. This involves:

    * Creating `http2inflow` instances for both connection and stream.
    * Simulating sending data and the corresponding reduction in `avail`.
    * Demonstrating how `add` increases the window size.
    *  Include `fmt.Println` statements to show the state changes. *Self-correction:* Initially, I considered using more complex scenarios, but the request asks for a *simple* example. Focusing on the basic `add` and `take` operations is sufficient.

6. **Code Example (Frame Processing):**  Create an example showing how frames are written and potentially read. This involves:

    * Creating an `http2Framer`.
    * Using `WriteData` to create a DATA frame.
    * Showing the raw bytes written to the buffer. *Self-correction:*  Initially, I thought about also demonstrating `ReadFrame`, but since the request focuses on *this specific part* of the code,  demonstrating frame *writing* is more relevant to the provided snippet.

7. **Command-Line Arguments:**  Examine the code for any direct handling of command-line arguments. In this specific snippet, there's *no* explicit command-line argument processing. Mention this clearly.

8. **Common Mistakes:** Think about common pitfalls when working with flow control and frame handling:

    * **Flow Control:** Exceeding the maximum window size (`maxWindow`), not respecting the available window when sending data.
    * **Frame Handling:** Incorrectly setting frame headers, creating frames with invalid stream IDs, ignoring frame size limits. Provide concrete examples of these errors.

9. **Summarize the Functionality of This Part:**  Condense the findings into a concise summary, focusing on flow control management and the foundational elements for working with HTTP/2 frames (headers, types, basic writing). Acknowledge that this is a part of a larger implementation.

10. **Review and Refine:** Read through the entire answer to ensure clarity, accuracy, and completeness, according to the prompt's requirements. Check for any logical inconsistencies or areas where more detail or simplification is needed. Ensure the examples are runnable and the explanations are easy to understand.

This systematic approach, starting with a broad overview and progressively focusing on specific details, coupled with the creation of illustrative examples and consideration of potential errors, allows for a comprehensive and accurate analysis of the given code snippet. The "part X of Y" indication is crucial for understanding the scope and not trying to analyze the *entire* HTTP/2 implementation.
这是 Go 语言 `net/http` 包中处理 HTTP/2 协议的一部分，具体是 `h2_bundle.go` 文件中的第三部分。

**功能归纳:**

这部分代码主要负责 **HTTP/2 协议中的流量控制机制** 和 **HTTP/2 帧的结构定义与基本操作**。

**具体功能列举:**

1. **定义了入站流量控制 (`http2inflow`) 的数据结构和方法：**
   - `http2inflow` 结构体用于跟踪对端允许发送的数据量。
   - `add` 方法用于更新入站流量控制窗口的大小，并进行边界检查，防止超过最大窗口限制 (2^31-1)。该方法还实现了窗口更新的缓冲策略，只有当窗口大小低于阈值或者更新能显著增加窗口时才实际更新。
   - `take` 方法用于尝试从入站流量控制窗口中取出一定数量的字节，表示允许接收这些数据。
   - `http2takeInflows` 函数用于同时从连接级别和流级别的入站流量控制窗口中取字节。

2. **定义了出站流量控制 (`http2outflow`) 的数据结构和方法：**
   - `http2outflow` 结构体用于跟踪本地可以发送的数据量。
   - `setConnFlow` 方法用于设置流级别的出站流量控制与连接级别的出站流量控制之间的关联。
   - `available` 方法返回当前可用的出站流量控制窗口大小，会考虑连接级别的限制。
   - `take` 方法用于减少出站流量控制窗口的大小，表示已发送一定量的数据。
   - `add` 方法用于增加或减少出站流量控制窗口的大小，并进行边界检查。

3. **定义了 HTTP/2 帧的类型 (`http2FrameType`) 和标志位 (`http2Flags`)：**
   - `http2FrameType` 定义了各种 HTTP/2 帧的类型，如 DATA, HEADERS, SETTINGS 等。
   - `http2Flags` 定义了帧的标志位，不同的帧类型有不同的标志位。
   - 提供了将帧类型和标志位转换为字符串表示的方法 (`String`, `Has`)，方便调试和日志记录。

4. **定义了 HTTP/2 帧头 (`http2FrameHeader`) 的结构：**
   - `http2FrameHeader` 包含了帧的类型、标志位、长度和流 ID 等信息。
   - 提供了读取帧头的方法 (`http2ReadFrameHeader`)。

5. **定义了 `http2Frame` 接口：**
   - `http2Frame` 是所有 HTTP/2 帧类型的通用接口，定义了 `Header()` 和 `invalidate()` 方法。

6. **定义了 `http2Framer` 结构体和相关方法，用于读写 HTTP/2 帧：**
   - `http2Framer` 负责从 `io.Reader` 读取帧，并将帧写入 `io.Writer`。
   - 提供了 `WriteData`, `WriteSettings`, `WritePing`, `WriteGoAway`, `WriteWindowUpdate` 等方法用于写入各种类型的 HTTP/2 帧。
   - 提供了 `ReadFrame` 方法用于读取下一个 HTTP/2 帧。
   - 实现了帧的缓存和重用机制 (`SetReuseFrames`, `http2frameCache`) 以提高性能。
   - 提供了设置最大读取帧大小 (`SetMaxReadFrameSize`) 和获取错误详情 (`ErrorDetail`) 的方法.
   - 包含对帧顺序的检查 (`checkFrameOrder`)，确保 HEADERS 和 CONTINUATION 帧的连续性。

7. **定义了 `http2DataFrame` 结构体和相关方法：**
   - `http2DataFrame` 表示 DATA 帧，包含帧头和数据。
   - 提供了获取数据的方法 (`Data`) 和判断流是否结束的方法 (`StreamEnded`)。
   - 提供了用于解析 DATA 帧的函数 (`http2parseDataFrame`)。
   - 提供了写入 DATA 帧的方法 (`WriteData`, `WriteDataPadded`)。

8. **定义了 `http2SettingsFrame` 结构体和相关方法：**
   - `http2SettingsFrame` 表示 SETTINGS 帧，包含帧头和设置参数。
   - 提供了判断是否为 ACK 帧的方法 (`IsAck`) 和获取特定设置值的方法 (`Value`, `Setting`)。
   - 提供了写入 SETTINGS 帧的方法 (`WriteSettings`, `WriteSettingsAck`)。

9. **定义了 `http2PingFrame` 结构体和相关方法：**
   - `http2PingFrame` 表示 PING 帧，用于测量往返时间或检查连接是否存活。
   - 提供了判断是否为 ACK 帧的方法 (`IsAck`)。
   - 提供了写入 PING 帧的方法 (`WritePing`)。

10. **定义了 `http2GoAwayFrame` 结构体和相关方法：**
    - `http2GoAwayFrame` 表示 GOAWAY 帧，用于告知对端停止创建新的流。
    - 提供了获取调试数据的方法 (`DebugData`)。
    - 提供了写入 GOAWAY 帧的方法 (`WriteGoAway`)。

11. **定义了 `http2UnknownFrame` 结构体和相关方法：**
    - `http2UnknownFrame` 表示未知类型的帧。
    - 提供了获取帧负载的方法 (`Payload`)。

12. **定义了 `http2WindowUpdateFrame` 结构体和相关方法：**
    - `http2WindowUpdateFrame` 表示 WINDOW_UPDATE 帧，用于更新流量控制窗口大小。
    - 提供了写入 WINDOW_UPDATE 帧的方法 (`WriteWindowUpdate`)。

**推理它是什么 Go 语言功能的实现：**

这部分代码是 Go 语言 `net/http` 包中 **HTTP/2 协议** 的核心实现部分，专注于 **流量控制** 和 **帧的编解码**。

**Go 代码举例说明 (流量控制):**

假设我们有一个 HTTP/2 连接，本地想要发送一些数据。

```go
package main

import (
	"fmt"
	"net/http/internal/http2"
)

func main() {
	// 假设 connInflow 是连接级别的入站流量控制
	connInflow := &http2.Http2inflow{Avail: 100} // 初始窗口大小为 100

	// 假设 streamInflow 是流级别的入站流量控制
	streamInflow := &http2.Http2inflow{Avail: 50} // 初始窗口大小为 50

	// 尝试发送 30 字节的数据
	sendSize := uint32(30)

	// 检查连接级别和流级别是否有足够的窗口
	canSend := http2.Http2takeInflows(connInflow, streamInflow, sendSize)

	if canSend {
		fmt.Println("可以发送数据")
		fmt.Printf("连接级别剩余窗口: %d\n", connInflow.Avail)
		fmt.Printf("流级别剩余窗口: %d\n", streamInflow.Avail)
	} else {
		fmt.Println("无法发送数据，流量控制窗口不足")
		fmt.Printf("连接级别剩余窗口: %d\n", connInflow.Avail)
		fmt.Printf("流级别剩余窗口: %d\n", streamInflow.Avail)
	}

	// 模拟接收到 WINDOW_UPDATE 帧，更新连接级别的流量控制窗口
	updateSize := int32(50)
	unsent := connInflow.Add(updateSize)
	fmt.Printf("更新连接级别窗口，实际更新大小: %d\n", unsent)
	fmt.Printf("连接级别更新后剩余窗口: %d\n", connInflow.Avail)
}
```

**假设的输入与输出:**

运行上面的代码，输出可能如下：

```
可以发送数据
连接级别剩余窗口: 70
流级别剩余窗口: 20
更新连接级别窗口，实际更新大小: 50
连接级别更新后剩余窗口: 120
```

**Go 代码举例说明 (帧的写入):**

```go
package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http/internal/http2"
)

func main() {
	var buf bytes.Buffer
	framer := http2.NewFramer(&buf, nil) // nil 表示不从任何地方读取

	streamID := uint32(1)
	data := []byte("Hello, HTTP/2!")
	endStream := true

	err := framer.WriteData(streamID, endStream, data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("写入的字节: %v\n", buf.Bytes())

	// 可以尝试读取刚刚写入的帧（仅用于演示）
	framer2 := http2.NewFramer(nil, &buf)
	frame, err := framer2.ReadFrame()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("读取到的帧类型: %T\n", frame)
	if dataFrame, ok := frame.(*http2.DataFrame); ok {
		fmt.Printf("读取到的数据: %s\n", dataFrame.Data())
		fmt.Printf("流是否结束: %t\n", dataFrame.StreamEnded())
	}
}
```

**假设的输入与输出:**

运行上面的代码，输出可能如下 (实际字节会根据 HTTP/2 帧的编码规则有所不同)：

```
写入的字节: [0 0 18 0 0 0 0 0 1 Hello, HTTP/2!]
读取到的帧类型: *http2.DataFrame
读取到的数据: Hello, HTTP/2!
流是否结束: true
```

**命令行参数的具体处理:**

这段代码本身 **不直接处理命令行参数**。HTTP/2 的连接建立和参数协商通常发生在网络连接建立之后，通过 SETTINGS 帧进行。如果涉及到命令行工具使用 HTTP/2，那么命令行参数的处理会在调用 `net/http` 包的上层代码中完成。

**使用者易犯错的点:**

1. **流量控制窗口溢出:**  手动管理流量控制时，容易忘记检查窗口大小，导致发送超过对端允许的数据量，虽然代码中有 `panic` 防御，但在实际应用中应该避免。

   ```go
   // 错误示例：假设 f 是一个 http2outflow
   f := &http2.Http2outflow{N: 10}
   f.Take(20) // 这里会 panic，因为要取的比可用的多
   ```

2. **不正确的帧头设置:**  手动创建和发送帧时，容易设置错误的帧头信息，例如错误的长度、类型或标志位。

   ```go
   // 错误示例：手动创建一个帧头
   header := http2.FrameHeader{
       Type:     http2.FrameData,
       Flags:    0,
       Length:   10, // 实际数据长度可能不一致
       StreamID: 1,
   }
   // ... 后续操作可能会因为长度不匹配而出错
   ```

3. **在 ReadFrame 返回的 Frame 失效后仍然访问其数据:** `Framer.ReadFrame` 返回的 `Frame` 只在下一次调用 `ReadFrame` 之前有效，因为内部会复用缓冲区。

   ```go
   framer := http2.NewFramer(nil, &buf)
   frame1, _ := framer.ReadFrame()
   // ... 使用 frame1 的数据
   frame2, _ := framer.ReadFrame()
   // 错误：此时 frame1 的数据可能已被 frame2 覆盖
   fmt.Println(frame1.Header())
   ```

4. **没有正确处理 HEADERS 和 CONTINUATION 帧的顺序:**  HEADERS 帧可能很大，需要通过多个 CONTINUATION 帧传输。使用者需要确保在读取到 HEADERS 帧后，后续接收到的都是属于该 HEADERS 帧的 CONTINUATION 帧，直到 END_HEADERS 标志位被设置。`Framer` 内部会进行检查，但使用者在自定义处理时需要注意。

### 提示词
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
"A sender MUST NOT allow a flow-control window to exceed 2^31-1 octets."
	// RFC 7540 Section 6.9.1.
	const maxWindow = 1<<31 - 1
	if unsent+int64(f.avail) > maxWindow {
		panic("flow control update exceeds maximum window size")
	}
	f.unsent = int32(unsent)
	if f.unsent < http2inflowMinRefresh && f.unsent < f.avail {
		// If there aren't at least inflowMinRefresh bytes of window to send,
		// and this update won't at least double the window, buffer the update for later.
		return 0
	}
	f.avail += f.unsent
	f.unsent = 0
	return int32(unsent)
}

// take attempts to take n bytes from the peer's flow control window.
// It reports whether the window has available capacity.
func (f *http2inflow) take(n uint32) bool {
	if n > uint32(f.avail) {
		return false
	}
	f.avail -= int32(n)
	return true
}

// takeInflows attempts to take n bytes from two inflows,
// typically connection-level and stream-level flows.
// It reports whether both windows have available capacity.
func http2takeInflows(f1, f2 *http2inflow, n uint32) bool {
	if n > uint32(f1.avail) || n > uint32(f2.avail) {
		return false
	}
	f1.avail -= int32(n)
	f2.avail -= int32(n)
	return true
}

// outflow is the outbound flow control window's size.
type http2outflow struct {
	_ http2incomparable

	// n is the number of DATA bytes we're allowed to send.
	// An outflow is kept both on a conn and a per-stream.
	n int32

	// conn points to the shared connection-level outflow that is
	// shared by all streams on that conn. It is nil for the outflow
	// that's on the conn directly.
	conn *http2outflow
}

func (f *http2outflow) setConnFlow(cf *http2outflow) { f.conn = cf }

func (f *http2outflow) available() int32 {
	n := f.n
	if f.conn != nil && f.conn.n < n {
		n = f.conn.n
	}
	return n
}

func (f *http2outflow) take(n int32) {
	if n > f.available() {
		panic("internal error: took too much")
	}
	f.n -= n
	if f.conn != nil {
		f.conn.n -= n
	}
}

// add adds n bytes (positive or negative) to the flow control window.
// It returns false if the sum would exceed 2^31-1.
func (f *http2outflow) add(n int32) bool {
	sum := f.n + n
	if (sum > n) == (f.n > 0) {
		f.n = sum
		return true
	}
	return false
}

const http2frameHeaderLen = 9

var http2padZeros = make([]byte, 255) // zeros for padding

// A FrameType is a registered frame type as defined in
// https://httpwg.org/specs/rfc7540.html#rfc.section.11.2
type http2FrameType uint8

const (
	http2FrameData         http2FrameType = 0x0
	http2FrameHeaders      http2FrameType = 0x1
	http2FramePriority     http2FrameType = 0x2
	http2FrameRSTStream    http2FrameType = 0x3
	http2FrameSettings     http2FrameType = 0x4
	http2FramePushPromise  http2FrameType = 0x5
	http2FramePing         http2FrameType = 0x6
	http2FrameGoAway       http2FrameType = 0x7
	http2FrameWindowUpdate http2FrameType = 0x8
	http2FrameContinuation http2FrameType = 0x9
)

var http2frameName = map[http2FrameType]string{
	http2FrameData:         "DATA",
	http2FrameHeaders:      "HEADERS",
	http2FramePriority:     "PRIORITY",
	http2FrameRSTStream:    "RST_STREAM",
	http2FrameSettings:     "SETTINGS",
	http2FramePushPromise:  "PUSH_PROMISE",
	http2FramePing:         "PING",
	http2FrameGoAway:       "GOAWAY",
	http2FrameWindowUpdate: "WINDOW_UPDATE",
	http2FrameContinuation: "CONTINUATION",
}

func (t http2FrameType) String() string {
	if s, ok := http2frameName[t]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN_FRAME_TYPE_%d", uint8(t))
}

// Flags is a bitmask of HTTP/2 flags.
// The meaning of flags varies depending on the frame type.
type http2Flags uint8

// Has reports whether f contains all (0 or more) flags in v.
func (f http2Flags) Has(v http2Flags) bool {
	return (f & v) == v
}

// Frame-specific FrameHeader flag bits.
const (
	// Data Frame
	http2FlagDataEndStream http2Flags = 0x1
	http2FlagDataPadded    http2Flags = 0x8

	// Headers Frame
	http2FlagHeadersEndStream  http2Flags = 0x1
	http2FlagHeadersEndHeaders http2Flags = 0x4
	http2FlagHeadersPadded     http2Flags = 0x8
	http2FlagHeadersPriority   http2Flags = 0x20

	// Settings Frame
	http2FlagSettingsAck http2Flags = 0x1

	// Ping Frame
	http2FlagPingAck http2Flags = 0x1

	// Continuation Frame
	http2FlagContinuationEndHeaders http2Flags = 0x4

	http2FlagPushPromiseEndHeaders http2Flags = 0x4
	http2FlagPushPromisePadded     http2Flags = 0x8
)

var http2flagName = map[http2FrameType]map[http2Flags]string{
	http2FrameData: {
		http2FlagDataEndStream: "END_STREAM",
		http2FlagDataPadded:    "PADDED",
	},
	http2FrameHeaders: {
		http2FlagHeadersEndStream:  "END_STREAM",
		http2FlagHeadersEndHeaders: "END_HEADERS",
		http2FlagHeadersPadded:     "PADDED",
		http2FlagHeadersPriority:   "PRIORITY",
	},
	http2FrameSettings: {
		http2FlagSettingsAck: "ACK",
	},
	http2FramePing: {
		http2FlagPingAck: "ACK",
	},
	http2FrameContinuation: {
		http2FlagContinuationEndHeaders: "END_HEADERS",
	},
	http2FramePushPromise: {
		http2FlagPushPromiseEndHeaders: "END_HEADERS",
		http2FlagPushPromisePadded:     "PADDED",
	},
}

// a frameParser parses a frame given its FrameHeader and payload
// bytes. The length of payload will always equal fh.Length (which
// might be 0).
type http2frameParser func(fc *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error)

var http2frameParsers = map[http2FrameType]http2frameParser{
	http2FrameData:         http2parseDataFrame,
	http2FrameHeaders:      http2parseHeadersFrame,
	http2FramePriority:     http2parsePriorityFrame,
	http2FrameRSTStream:    http2parseRSTStreamFrame,
	http2FrameSettings:     http2parseSettingsFrame,
	http2FramePushPromise:  http2parsePushPromise,
	http2FramePing:         http2parsePingFrame,
	http2FrameGoAway:       http2parseGoAwayFrame,
	http2FrameWindowUpdate: http2parseWindowUpdateFrame,
	http2FrameContinuation: http2parseContinuationFrame,
}

func http2typeFrameParser(t http2FrameType) http2frameParser {
	if f := http2frameParsers[t]; f != nil {
		return f
	}
	return http2parseUnknownFrame
}

// A FrameHeader is the 9 byte header of all HTTP/2 frames.
//
// See https://httpwg.org/specs/rfc7540.html#FrameHeader
type http2FrameHeader struct {
	valid bool // caller can access []byte fields in the Frame

	// Type is the 1 byte frame type. There are ten standard frame
	// types, but extension frame types may be written by WriteRawFrame
	// and will be returned by ReadFrame (as UnknownFrame).
	Type http2FrameType

	// Flags are the 1 byte of 8 potential bit flags per frame.
	// They are specific to the frame type.
	Flags http2Flags

	// Length is the length of the frame, not including the 9 byte header.
	// The maximum size is one byte less than 16MB (uint24), but only
	// frames up to 16KB are allowed without peer agreement.
	Length uint32

	// StreamID is which stream this frame is for. Certain frames
	// are not stream-specific, in which case this field is 0.
	StreamID uint32
}

// Header returns h. It exists so FrameHeaders can be embedded in other
// specific frame types and implement the Frame interface.
func (h http2FrameHeader) Header() http2FrameHeader { return h }

func (h http2FrameHeader) String() string {
	var buf bytes.Buffer
	buf.WriteString("[FrameHeader ")
	h.writeDebug(&buf)
	buf.WriteByte(']')
	return buf.String()
}

func (h http2FrameHeader) writeDebug(buf *bytes.Buffer) {
	buf.WriteString(h.Type.String())
	if h.Flags != 0 {
		buf.WriteString(" flags=")
		set := 0
		for i := uint8(0); i < 8; i++ {
			if h.Flags&(1<<i) == 0 {
				continue
			}
			set++
			if set > 1 {
				buf.WriteByte('|')
			}
			name := http2flagName[h.Type][http2Flags(1<<i)]
			if name != "" {
				buf.WriteString(name)
			} else {
				fmt.Fprintf(buf, "0x%x", 1<<i)
			}
		}
	}
	if h.StreamID != 0 {
		fmt.Fprintf(buf, " stream=%d", h.StreamID)
	}
	fmt.Fprintf(buf, " len=%d", h.Length)
}

func (h *http2FrameHeader) checkValid() {
	if !h.valid {
		panic("Frame accessor called on non-owned Frame")
	}
}

func (h *http2FrameHeader) invalidate() { h.valid = false }

// frame header bytes.
// Used only by ReadFrameHeader.
var http2fhBytes = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, http2frameHeaderLen)
		return &buf
	},
}

// ReadFrameHeader reads 9 bytes from r and returns a FrameHeader.
// Most users should use Framer.ReadFrame instead.
func http2ReadFrameHeader(r io.Reader) (http2FrameHeader, error) {
	bufp := http2fhBytes.Get().(*[]byte)
	defer http2fhBytes.Put(bufp)
	return http2readFrameHeader(*bufp, r)
}

func http2readFrameHeader(buf []byte, r io.Reader) (http2FrameHeader, error) {
	_, err := io.ReadFull(r, buf[:http2frameHeaderLen])
	if err != nil {
		return http2FrameHeader{}, err
	}
	return http2FrameHeader{
		Length:   (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
		Type:     http2FrameType(buf[3]),
		Flags:    http2Flags(buf[4]),
		StreamID: binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1),
		valid:    true,
	}, nil
}

// A Frame is the base interface implemented by all frame types.
// Callers will generally type-assert the specific frame type:
// *HeadersFrame, *SettingsFrame, *WindowUpdateFrame, etc.
//
// Frames are only valid until the next call to Framer.ReadFrame.
type http2Frame interface {
	Header() http2FrameHeader

	// invalidate is called by Framer.ReadFrame to make this
	// frame's buffers as being invalid, since the subsequent
	// frame will reuse them.
	invalidate()
}

// A Framer reads and writes Frames.
type http2Framer struct {
	r         io.Reader
	lastFrame http2Frame
	errDetail error

	// countError is a non-nil func that's called on a frame parse
	// error with some unique error path token. It's initialized
	// from Transport.CountError or Server.CountError.
	countError func(errToken string)

	// lastHeaderStream is non-zero if the last frame was an
	// unfinished HEADERS/CONTINUATION.
	lastHeaderStream uint32

	maxReadSize uint32
	headerBuf   [http2frameHeaderLen]byte

	// TODO: let getReadBuf be configurable, and use a less memory-pinning
	// allocator in server.go to minimize memory pinned for many idle conns.
	// Will probably also need to make frame invalidation have a hook too.
	getReadBuf func(size uint32) []byte
	readBuf    []byte // cache for default getReadBuf

	maxWriteSize uint32 // zero means unlimited; TODO: implement

	w    io.Writer
	wbuf []byte

	// AllowIllegalWrites permits the Framer's Write methods to
	// write frames that do not conform to the HTTP/2 spec. This
	// permits using the Framer to test other HTTP/2
	// implementations' conformance to the spec.
	// If false, the Write methods will prefer to return an error
	// rather than comply.
	AllowIllegalWrites bool

	// AllowIllegalReads permits the Framer's ReadFrame method
	// to return non-compliant frames or frame orders.
	// This is for testing and permits using the Framer to test
	// other HTTP/2 implementations' conformance to the spec.
	// It is not compatible with ReadMetaHeaders.
	AllowIllegalReads bool

	// ReadMetaHeaders if non-nil causes ReadFrame to merge
	// HEADERS and CONTINUATION frames together and return
	// MetaHeadersFrame instead.
	ReadMetaHeaders *hpack.Decoder

	// MaxHeaderListSize is the http2 MAX_HEADER_LIST_SIZE.
	// It's used only if ReadMetaHeaders is set; 0 means a sane default
	// (currently 16MB)
	// If the limit is hit, MetaHeadersFrame.Truncated is set true.
	MaxHeaderListSize uint32

	// TODO: track which type of frame & with which flags was sent
	// last. Then return an error (unless AllowIllegalWrites) if
	// we're in the middle of a header block and a
	// non-Continuation or Continuation on a different stream is
	// attempted to be written.

	logReads, logWrites bool

	debugFramer       *http2Framer // only use for logging written writes
	debugFramerBuf    *bytes.Buffer
	debugReadLoggerf  func(string, ...interface{})
	debugWriteLoggerf func(string, ...interface{})

	frameCache *http2frameCache // nil if frames aren't reused (default)
}

func (fr *http2Framer) maxHeaderListSize() uint32 {
	if fr.MaxHeaderListSize == 0 {
		return 16 << 20 // sane default, per docs
	}
	return fr.MaxHeaderListSize
}

func (f *http2Framer) startWrite(ftype http2FrameType, flags http2Flags, streamID uint32) {
	// Write the FrameHeader.
	f.wbuf = append(f.wbuf[:0],
		0, // 3 bytes of length, filled in in endWrite
		0,
		0,
		byte(ftype),
		byte(flags),
		byte(streamID>>24),
		byte(streamID>>16),
		byte(streamID>>8),
		byte(streamID))
}

func (f *http2Framer) endWrite() error {
	// Now that we know the final size, fill in the FrameHeader in
	// the space previously reserved for it. Abuse append.
	length := len(f.wbuf) - http2frameHeaderLen
	if length >= (1 << 24) {
		return http2ErrFrameTooLarge
	}
	_ = append(f.wbuf[:0],
		byte(length>>16),
		byte(length>>8),
		byte(length))
	if f.logWrites {
		f.logWrite()
	}

	n, err := f.w.Write(f.wbuf)
	if err == nil && n != len(f.wbuf) {
		err = io.ErrShortWrite
	}
	return err
}

func (f *http2Framer) logWrite() {
	if f.debugFramer == nil {
		f.debugFramerBuf = new(bytes.Buffer)
		f.debugFramer = http2NewFramer(nil, f.debugFramerBuf)
		f.debugFramer.logReads = false // we log it ourselves, saying "wrote" below
		// Let us read anything, even if we accidentally wrote it
		// in the wrong order:
		f.debugFramer.AllowIllegalReads = true
	}
	f.debugFramerBuf.Write(f.wbuf)
	fr, err := f.debugFramer.ReadFrame()
	if err != nil {
		f.debugWriteLoggerf("http2: Framer %p: failed to decode just-written frame", f)
		return
	}
	f.debugWriteLoggerf("http2: Framer %p: wrote %v", f, http2summarizeFrame(fr))
}

func (f *http2Framer) writeByte(v byte) { f.wbuf = append(f.wbuf, v) }

func (f *http2Framer) writeBytes(v []byte) { f.wbuf = append(f.wbuf, v...) }

func (f *http2Framer) writeUint16(v uint16) { f.wbuf = append(f.wbuf, byte(v>>8), byte(v)) }

func (f *http2Framer) writeUint32(v uint32) {
	f.wbuf = append(f.wbuf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

const (
	http2minMaxFrameSize = 1 << 14
	http2maxFrameSize    = 1<<24 - 1
)

// SetReuseFrames allows the Framer to reuse Frames.
// If called on a Framer, Frames returned by calls to ReadFrame are only
// valid until the next call to ReadFrame.
func (fr *http2Framer) SetReuseFrames() {
	if fr.frameCache != nil {
		return
	}
	fr.frameCache = &http2frameCache{}
}

type http2frameCache struct {
	dataFrame http2DataFrame
}

func (fc *http2frameCache) getDataFrame() *http2DataFrame {
	if fc == nil {
		return &http2DataFrame{}
	}
	return &fc.dataFrame
}

// NewFramer returns a Framer that writes frames to w and reads them from r.
func http2NewFramer(w io.Writer, r io.Reader) *http2Framer {
	fr := &http2Framer{
		w:                 w,
		r:                 r,
		countError:        func(string) {},
		logReads:          http2logFrameReads,
		logWrites:         http2logFrameWrites,
		debugReadLoggerf:  log.Printf,
		debugWriteLoggerf: log.Printf,
	}
	fr.getReadBuf = func(size uint32) []byte {
		if cap(fr.readBuf) >= int(size) {
			return fr.readBuf[:size]
		}
		fr.readBuf = make([]byte, size)
		return fr.readBuf
	}
	fr.SetMaxReadFrameSize(http2maxFrameSize)
	return fr
}

// SetMaxReadFrameSize sets the maximum size of a frame
// that will be read by a subsequent call to ReadFrame.
// It is the caller's responsibility to advertise this
// limit with a SETTINGS frame.
func (fr *http2Framer) SetMaxReadFrameSize(v uint32) {
	if v > http2maxFrameSize {
		v = http2maxFrameSize
	}
	fr.maxReadSize = v
}

// ErrorDetail returns a more detailed error of the last error
// returned by Framer.ReadFrame. For instance, if ReadFrame
// returns a StreamError with code PROTOCOL_ERROR, ErrorDetail
// will say exactly what was invalid. ErrorDetail is not guaranteed
// to return a non-nil value and like the rest of the http2 package,
// its return value is not protected by an API compatibility promise.
// ErrorDetail is reset after the next call to ReadFrame.
func (fr *http2Framer) ErrorDetail() error {
	return fr.errDetail
}

// ErrFrameTooLarge is returned from Framer.ReadFrame when the peer
// sends a frame that is larger than declared with SetMaxReadFrameSize.
var http2ErrFrameTooLarge = errors.New("http2: frame too large")

// terminalReadFrameError reports whether err is an unrecoverable
// error from ReadFrame and no other frames should be read.
func http2terminalReadFrameError(err error) bool {
	if _, ok := err.(http2StreamError); ok {
		return false
	}
	return err != nil
}

// ReadFrame reads a single frame. The returned Frame is only valid
// until the next call to ReadFrame.
//
// If the frame is larger than previously set with SetMaxReadFrameSize, the
// returned error is ErrFrameTooLarge. Other errors may be of type
// ConnectionError, StreamError, or anything else from the underlying
// reader.
//
// If ReadFrame returns an error and a non-nil Frame, the Frame's StreamID
// indicates the stream responsible for the error.
func (fr *http2Framer) ReadFrame() (http2Frame, error) {
	fr.errDetail = nil
	if fr.lastFrame != nil {
		fr.lastFrame.invalidate()
	}
	fh, err := http2readFrameHeader(fr.headerBuf[:], fr.r)
	if err != nil {
		return nil, err
	}
	if fh.Length > fr.maxReadSize {
		return nil, http2ErrFrameTooLarge
	}
	payload := fr.getReadBuf(fh.Length)
	if _, err := io.ReadFull(fr.r, payload); err != nil {
		return nil, err
	}
	f, err := http2typeFrameParser(fh.Type)(fr.frameCache, fh, fr.countError, payload)
	if err != nil {
		if ce, ok := err.(http2connError); ok {
			return nil, fr.connError(ce.Code, ce.Reason)
		}
		return nil, err
	}
	if err := fr.checkFrameOrder(f); err != nil {
		return nil, err
	}
	if fr.logReads {
		fr.debugReadLoggerf("http2: Framer %p: read %v", fr, http2summarizeFrame(f))
	}
	if fh.Type == http2FrameHeaders && fr.ReadMetaHeaders != nil {
		return fr.readMetaFrame(f.(*http2HeadersFrame))
	}
	return f, nil
}

// connError returns ConnectionError(code) but first
// stashes away a public reason to the caller can optionally relay it
// to the peer before hanging up on them. This might help others debug
// their implementations.
func (fr *http2Framer) connError(code http2ErrCode, reason string) error {
	fr.errDetail = errors.New(reason)
	return http2ConnectionError(code)
}

// checkFrameOrder reports an error if f is an invalid frame to return
// next from ReadFrame. Mostly it checks whether HEADERS and
// CONTINUATION frames are contiguous.
func (fr *http2Framer) checkFrameOrder(f http2Frame) error {
	last := fr.lastFrame
	fr.lastFrame = f
	if fr.AllowIllegalReads {
		return nil
	}

	fh := f.Header()
	if fr.lastHeaderStream != 0 {
		if fh.Type != http2FrameContinuation {
			return fr.connError(http2ErrCodeProtocol,
				fmt.Sprintf("got %s for stream %d; expected CONTINUATION following %s for stream %d",
					fh.Type, fh.StreamID,
					last.Header().Type, fr.lastHeaderStream))
		}
		if fh.StreamID != fr.lastHeaderStream {
			return fr.connError(http2ErrCodeProtocol,
				fmt.Sprintf("got CONTINUATION for stream %d; expected stream %d",
					fh.StreamID, fr.lastHeaderStream))
		}
	} else if fh.Type == http2FrameContinuation {
		return fr.connError(http2ErrCodeProtocol, fmt.Sprintf("unexpected CONTINUATION for stream %d", fh.StreamID))
	}

	switch fh.Type {
	case http2FrameHeaders, http2FrameContinuation:
		if fh.Flags.Has(http2FlagHeadersEndHeaders) {
			fr.lastHeaderStream = 0
		} else {
			fr.lastHeaderStream = fh.StreamID
		}
	}

	return nil
}

// A DataFrame conveys arbitrary, variable-length sequences of octets
// associated with a stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.1
type http2DataFrame struct {
	http2FrameHeader
	data []byte
}

func (f *http2DataFrame) StreamEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagDataEndStream)
}

// Data returns the frame's data octets, not including any padding
// size byte or padding suffix bytes.
// The caller must not retain the returned memory past the next
// call to ReadFrame.
func (f *http2DataFrame) Data() []byte {
	f.checkValid()
	return f.data
}

func http2parseDataFrame(fc *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		// DATA frames MUST be associated with a stream. If a
		// DATA frame is received whose stream identifier
		// field is 0x0, the recipient MUST respond with a
		// connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR.
		countError("frame_data_stream_0")
		return nil, http2connError{http2ErrCodeProtocol, "DATA frame with stream ID 0"}
	}
	f := fc.getDataFrame()
	f.http2FrameHeader = fh

	var padSize byte
	if fh.Flags.Has(http2FlagDataPadded) {
		var err error
		payload, padSize, err = http2readByte(payload)
		if err != nil {
			countError("frame_data_pad_byte_short")
			return nil, err
		}
	}
	if int(padSize) > len(payload) {
		// If the length of the padding is greater than the
		// length of the frame payload, the recipient MUST
		// treat this as a connection error.
		// Filed: https://github.com/http2/http2-spec/issues/610
		countError("frame_data_pad_too_big")
		return nil, http2connError{http2ErrCodeProtocol, "pad size larger than data payload"}
	}
	f.data = payload[:len(payload)-int(padSize)]
	return f, nil
}

var (
	http2errStreamID    = errors.New("invalid stream ID")
	http2errDepStreamID = errors.New("invalid dependent stream ID")
	http2errPadLength   = errors.New("pad length too large")
	http2errPadBytes    = errors.New("padding bytes must all be zeros unless AllowIllegalWrites is enabled")
)

func http2validStreamIDOrZero(streamID uint32) bool {
	return streamID&(1<<31) == 0
}

func http2validStreamID(streamID uint32) bool {
	return streamID != 0 && streamID&(1<<31) == 0
}

// WriteData writes a DATA frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility not to violate the maximum frame size
// and to not call other Write methods concurrently.
func (f *http2Framer) WriteData(streamID uint32, endStream bool, data []byte) error {
	return f.WriteDataPadded(streamID, endStream, data, nil)
}

// WriteDataPadded writes a DATA frame with optional padding.
//
// If pad is nil, the padding bit is not sent.
// The length of pad must not exceed 255 bytes.
// The bytes of pad must all be zero, unless f.AllowIllegalWrites is set.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility not to violate the maximum frame size
// and to not call other Write methods concurrently.
func (f *http2Framer) WriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error {
	if err := f.startWriteDataPadded(streamID, endStream, data, pad); err != nil {
		return err
	}
	return f.endWrite()
}

// startWriteDataPadded is WriteDataPadded, but only writes the frame to the Framer's internal buffer.
// The caller should call endWrite to flush the frame to the underlying writer.
func (f *http2Framer) startWriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error {
	if !http2validStreamID(streamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	if len(pad) > 0 {
		if len(pad) > 255 {
			return http2errPadLength
		}
		if !f.AllowIllegalWrites {
			for _, b := range pad {
				if b != 0 {
					// "Padding octets MUST be set to zero when sending."
					return http2errPadBytes
				}
			}
		}
	}
	var flags http2Flags
	if endStream {
		flags |= http2FlagDataEndStream
	}
	if pad != nil {
		flags |= http2FlagDataPadded
	}
	f.startWrite(http2FrameData, flags, streamID)
	if pad != nil {
		f.wbuf = append(f.wbuf, byte(len(pad)))
	}
	f.wbuf = append(f.wbuf, data...)
	f.wbuf = append(f.wbuf, pad...)
	return nil
}

// A SettingsFrame conveys configuration parameters that affect how
// endpoints communicate, such as preferences and constraints on peer
// behavior.
//
// See https://httpwg.org/specs/rfc7540.html#SETTINGS
type http2SettingsFrame struct {
	http2FrameHeader
	p []byte
}

func http2parseSettingsFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if fh.Flags.Has(http2FlagSettingsAck) && fh.Length > 0 {
		// When this (ACK 0x1) bit is set, the payload of the
		// SETTINGS frame MUST be empty. Receipt of a
		// SETTINGS frame with the ACK flag set and a length
		// field value other than 0 MUST be treated as a
		// connection error (Section 5.4.1) of type
		// FRAME_SIZE_ERROR.
		countError("frame_settings_ack_with_length")
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	if fh.StreamID != 0 {
		// SETTINGS frames always apply to a connection,
		// never a single stream. The stream identifier for a
		// SETTINGS frame MUST be zero (0x0).  If an endpoint
		// receives a SETTINGS frame whose stream identifier
		// field is anything other than 0x0, the endpoint MUST
		// respond with a connection error (Section 5.4.1) of
		// type PROTOCOL_ERROR.
		countError("frame_settings_has_stream")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	if len(p)%6 != 0 {
		countError("frame_settings_mod_6")
		// Expecting even number of 6 byte settings.
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	f := &http2SettingsFrame{http2FrameHeader: fh, p: p}
	if v, ok := f.Value(http2SettingInitialWindowSize); ok && v > (1<<31)-1 {
		countError("frame_settings_window_size_too_big")
		// Values above the maximum flow control window size of 2^31 - 1 MUST
		// be treated as a connection error (Section 5.4.1) of type
		// FLOW_CONTROL_ERROR.
		return nil, http2ConnectionError(http2ErrCodeFlowControl)
	}
	return f, nil
}

func (f *http2SettingsFrame) IsAck() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagSettingsAck)
}

func (f *http2SettingsFrame) Value(id http2SettingID) (v uint32, ok bool) {
	f.checkValid()
	for i := 0; i < f.NumSettings(); i++ {
		if s := f.Setting(i); s.ID == id {
			return s.Val, true
		}
	}
	return 0, false
}

// Setting returns the setting from the frame at the given 0-based index.
// The index must be >= 0 and less than f.NumSettings().
func (f *http2SettingsFrame) Setting(i int) http2Setting {
	buf := f.p
	return http2Setting{
		ID:  http2SettingID(binary.BigEndian.Uint16(buf[i*6 : i*6+2])),
		Val: binary.BigEndian.Uint32(buf[i*6+2 : i*6+6]),
	}
}

func (f *http2SettingsFrame) NumSettings() int { return len(f.p) / 6 }

// HasDuplicates reports whether f contains any duplicate setting IDs.
func (f *http2SettingsFrame) HasDuplicates() bool {
	num := f.NumSettings()
	if num == 0 {
		return false
	}
	// If it's small enough (the common case), just do the n^2
	// thing and avoid a map allocation.
	if num < 10 {
		for i := 0; i < num; i++ {
			idi := f.Setting(i).ID
			for j := i + 1; j < num; j++ {
				idj := f.Setting(j).ID
				if idi == idj {
					return true
				}
			}
		}
		return false
	}
	seen := map[http2SettingID]bool{}
	for i := 0; i < num; i++ {
		id := f.Setting(i).ID
		if seen[id] {
			return true
		}
		seen[id] = true
	}
	return false
}

// ForeachSetting runs fn for each setting.
// It stops and returns the first error.
func (f *http2SettingsFrame) ForeachSetting(fn func(http2Setting) error) error {
	f.checkValid()
	for i := 0; i < f.NumSettings(); i++ {
		if err := fn(f.Setting(i)); err != nil {
			return err
		}
	}
	return nil
}

// WriteSettings writes a SETTINGS frame with zero or more settings
// specified and the ACK bit not set.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteSettings(settings ...http2Setting) error {
	f.startWrite(http2FrameSettings, 0, 0)
	for _, s := range settings {
		f.writeUint16(uint16(s.ID))
		f.writeUint32(s.Val)
	}
	return f.endWrite()
}

// WriteSettingsAck writes an empty SETTINGS frame with the ACK bit set.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteSettingsAck() error {
	f.startWrite(http2FrameSettings, http2FlagSettingsAck, 0)
	return f.endWrite()
}

// A PingFrame is a mechanism for measuring a minimal round trip time
// from the sender, as well as determining whether an idle connection
// is still functional.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.7
type http2PingFrame struct {
	http2FrameHeader
	Data [8]byte
}

func (f *http2PingFrame) IsAck() bool { return f.Flags.Has(http2FlagPingAck) }

func http2parsePingFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error) {
	if len(payload) != 8 {
		countError("frame_ping_length")
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	if fh.StreamID != 0 {
		countError("frame_ping_has_stream")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	f := &http2PingFrame{http2FrameHeader: fh}
	copy(f.Data[:], payload)
	return f, nil
}

func (f *http2Framer) WritePing(ack bool, data [8]byte) error {
	var flags http2Flags
	if ack {
		flags = http2FlagPingAck
	}
	f.startWrite(http2FramePing, flags, 0)
	f.writeBytes(data[:])
	return f.endWrite()
}

// A GoAwayFrame informs the remote peer to stop creating streams on this connection.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.8
type http2GoAwayFrame struct {
	http2FrameHeader
	LastStreamID uint32
	ErrCode      http2ErrCode
	debugData    []byte
}

// DebugData returns any debug data in the GOAWAY frame. Its contents
// are not defined.
// The caller must not retain the returned memory past the next
// call to ReadFrame.
func (f *http2GoAwayFrame) DebugData() []byte {
	f.checkValid()
	return f.debugData
}

func http2parseGoAwayFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if fh.StreamID != 0 {
		countError("frame_goaway_has_stream")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	if len(p) < 8 {
		countError("frame_goaway_short")
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	return &http2GoAwayFrame{
		http2FrameHeader: fh,
		LastStreamID:     binary.BigEndian.Uint32(p[:4]) & (1<<31 - 1),
		ErrCode:          http2ErrCode(binary.BigEndian.Uint32(p[4:8])),
		debugData:        p[8:],
	}, nil
}

func (f *http2Framer) WriteGoAway(maxStreamID uint32, code http2ErrCode, debugData []byte) error {
	f.startWrite(http2FrameGoAway, 0, 0)
	f.writeUint32(maxStreamID & (1<<31 - 1))
	f.writeUint32(uint32(code))
	f.writeBytes(debugData)
	return f.endWrite()
}

// An UnknownFrame is the frame type returned when the frame type is unknown
// or no specific frame type parser exists.
type http2UnknownFrame struct {
	http2FrameHeader
	p []byte
}

// Payload returns the frame's payload (after the header).  It is not
// valid to call this method after a subsequent call to
// Framer.ReadFrame, nor is it valid to retain the returned slice.
// The memory is owned by the Framer and is invalidated when the next
// frame is read.
func (f *http2UnknownFrame) Payload() []byte {
	f.checkValid()
	return f.p
}

func http2parseUnknownFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	return &http2UnknownFrame{fh, p}, nil
}

// A WindowUpdateFrame is used to implement flow control.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.9
type http2WindowUpdateFrame struct {
	http2FrameHeader
	Increment uint32 // never read with high bit set
}

func http2parseWindowUpdateFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if len(p) != 4 {
		countError("frame_windowupdate_bad_len")
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	inc := binary.BigEndian.Uint32(p[:4]) & 0x7fffffff // mask off high reserved bit
	if inc == 0 {
		// A receiver MUST treat the receipt of a
		// WINDOW_UPDATE frame with an flow control window
		// increment of 0 as a stream error (Section 5.4.2) of
		// type PROTOCOL_ERROR; errors on the connection flow
		// control window MUST be treated as a connection
		// error (Section 5.4.1).
		if fh.StreamID == 0 {
			countError("frame_windowupdate_zero_inc_conn")
			return nil, http2ConnectionError(http2ErrCodeProtocol)
		}
		countError("frame_windowupdate_zero_inc_stream")
		return nil, http2streamError(fh.StreamID, http2ErrCodeProtocol)
	}
	return &http2WindowUpdateFrame{
		http2FrameHeader: fh,
		Increment:        inc,
	}, nil
}

// WriteWindowUpdate writes a WINDOW_UPDATE frame.
// The increment value must be between 1 and 2,147,483,647, inclusive.
// If the Stream ID is zero, the window update applies to the
// connection as a whole.
func (f *http2Framer) WriteWindowUpdate(streamID, incr uint32) error {
	// "The legal range for the increment to the flow control window is 1 to 2^31-1 (2,147,483,647) octets."
	if (incr < 1 || incr > 2147483647) && !f.AllowIllegalW
```