Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part 4 of 13 of the `h2_bundle.go` file in the `net/http` package.

I need to identify the key data structures and functions defined in this part of the code and describe their purpose within the context of HTTP/2.

Based on the code, the main components are:

1. **`http2WindowUpdateFrame` and its associated functions:** Deals with flow control by allowing a receiver to inform the sender of available space in its receive window.
2. **`http2HeadersFrame` and its associated functions:** Represents the HEADERS frame used to open streams and send header blocks.
3. **`http2HeadersFrameParam`:**  A struct to encapsulate parameters for writing a HEADERS frame.
4. **`http2PriorityFrame` and its associated functions:** Represents the PRIORITY frame used to signal the sender-advised priority of a stream.
5. **`http2PriorityParam`:** A struct to hold the stream prioritization parameters.
6. **`http2RSTStreamFrame` and its associated functions:** Represents the RST_STREAM frame for abnormal termination of a stream.
7. **`http2ContinuationFrame` and its associated functions:** Represents the CONTINUATION frame used to send header blocks that are too large for a single HEADERS frame.
8. **`http2PushPromiseFrame` and its associated functions:** Represents the PUSH_PROMISE frame used by servers to initiate a server push.
9. **`http2PushPromiseParam`:** A struct to encapsulate parameters for writing a PUSH_PROMISE frame.
10. **`WriteRawFrame`:** A function to write arbitrary HTTP/2 frames.
11. **Helper functions `http2readByte` and `http2readUint32`:** For reading data from byte slices.
12. **`http2MetaHeadersFrame` and its associated functions:** Represents a HEADERS frame combined with its subsequent CONTINUATION frames, along with decoded HPACK headers.
13. **`http2summarizeFrame`:** A debugging function to provide a string representation of an HTTP/2 frame.
14. **Goroutine locking mechanisms (`http2goroutineLock` and associated functions):** For ensuring code is executed on the correct goroutine.
15. **Helper functions for parsing unsigned integers from byte slices (`http2parseUintBytes`, `http2cutoff64`).**
16. **Helper functions and data structures for managing common HTTP headers (`http2commonBuildOnce`, `http2commonLowerHeader`, `http2commonCanonHeader`, `http2buildCommonHeaderMapsOnce`, `http2buildCommonHeaderMaps`, `http2lowerHeader`, `http2canonicalHeader`).**
17. **Global variables related to debugging and feature flags (`http2VerboseLogs`, `http2logFrameWrites`, `http2logFrameReads`, `http2inTests`, `http2disableExtendedConnectProtocol`).**
18. **Constants related to HTTP/2 protocol (`http2ClientPreface`, `http2initialMaxFrameSize`, `http2NextProtoTLS`, `http2initialHeaderTableSize`, `http2initialWindowSize`, `http2defaultMaxReadFrameSize`).**
19. **`http2streamState` and associated constants and functions:** Defines the possible states of an HTTP/2 stream.
20. **`http2Setting` and `http2SettingID` and their associated functions and constants:** Represent HTTP/2 settings parameters.
21. **`http2validWireHeaderFieldName`:** Function to validate HTTP/2 header field names.
22. **`http2httpCodeString`:**  A helper function to get the string representation of an HTTP status code.
23. **`http2stringWriter` interface:** Defines an interface for string writers.
24. **`http2closeWaiter` and its associated functions:** A synchronization primitive for waiting for closure.
25. **`http2bufferedWriter` and its associated functions:** A buffered writer for network connections.
这是`go/src/net/http/h2_bundle.go`文件的第四部分，主要负责定义和处理多种HTTP/2帧的结构体和相关操作。以下是这部分代码功能的归纳：

**功能归纳：**

这部分代码定义了用于表示和操作以下HTTP/2帧的结构体和方法：

*   **WINDOW_UPDATE帧:**  用于进行流量控制，允许接收方告知发送方它可以接收更多数据。
*   **HEADERS帧:** 用于打开新的HTTP/2流，并携带一部分或全部的HTTP头部信息。它还包含了处理优先级的功能。
*   **PRIORITY帧:**  用于指定HTTP/2流的优先级。
*   **RST_STREAM帧:**  用于异常终止一个HTTP/2流。
*   **CONTINUATION帧:**  用于续传 HEADERS 帧中未完成的头部信息，当头部信息过大时会被拆分成多个 CONTINUATION 帧发送。
*   **PUSH_PROMISE帧:**  用于服务器向客户端推送资源（Server Push）。

此外，这部分代码还包含了：

*   **帧的解析函数 (`http2parse...Frame`)**:  用于将接收到的字节流解析成对应的帧结构体。
*   **帧的写入函数 (`Write...`)**: 用于将帧结构体序列化成字节流并写入到网络连接中。
*   **辅助结构体 (`http2HeadersFrameParam`, `http2PriorityParam`, `http2PushPromiseParam`)**: 用于封装创建和写入帧所需的参数。
*   **元数据头部帧 (`http2MetaHeadersFrame`)**:  一个逻辑上的帧，它将 HEADERS 帧和其后续的 CONTINUATION 帧组合在一起，并包含了解码后的头部信息。
*   **调试和日志功能 (`http2summarizeFrame`)**: 用于将帧信息格式化为易于阅读的字符串。
*   **内部辅助函数**:  例如 `http2readByte`, `http2readUint32` 用于读取字节流中的数据。
*   **goroutine 锁机制**: 用于确保某些操作在特定的 goroutine 上执行。
*   **HTTP头部相关的辅助功能**: 例如 HTTP 头部字段的规范化和常见头部信息的缓存。
*   **HTTP/2 协议相关的常量和类型定义**: 例如帧类型，流状态，设置参数等。
*   **bufferedWriter**:  一个带缓冲的 writer，用于提高网络写入效率。

总而言之，这部分代码是 `net/http` 包中处理 HTTP/2 协议帧的核心部分，它定义了各种帧的结构、解析和序列化方法，为构建 HTTP/2 客户端和服务器提供了基础。

**代码示例（HEADERS 帧的创建和写入）：**

```go
package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/internal/http2"
)

func main() {
	// 假设我们已经建立了一个 net.Conn 连接 conn

	// 模拟一个 net.Conn (实际应用中需要替换为真实的连接)
	conn, _ := net.Pipe()
	defer conn.Close()

	framer := http2.NewFramer(conn, conn)

	// 构造 HEADERS 帧的参数
	headersParam := http2.HeadersFrameParam{
		StreamID:      1, // 流ID
		BlockFragment: []byte("\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67"), // 示例头部，经过HPACK编码
		EndStream:     false,
		EndHeaders:    true,
	}

	// 写入 HEADERS 帧
	err := framer.WriteHeaders(headersParam)
	if err != nil {
		fmt.Println("写入 HEADERS 帧失败:", err)
		return
	}

	fmt.Println("成功写入 HEADERS 帧")

	// --- 假设的输入和输出 ---
	// 输入: headersParam 包含了流ID 1 和经过 HPACK 编码的头部信息
	// 输出:  conn 上会写入一个 HTTP/2 HEADERS 帧的二进制数据，
	//       该帧的头部信息对应 headersParam 中的设置。
}
```

**代码示例（读取 HEADERS 帧）：**

```go
package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/internal/http2"
)

func main() {
	// 假设我们已经从连接 conn 读取到了一个 HEADERS 帧的字节流 frameBytes

	// 模拟接收到的 HEADERS 帧字节流
	frameBytes := bytes.NewReader([]byte("\x00\x00\x17\x01\x04\x00\x00\x00\x01\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67"))

	// 创建一个 Framer 用于读取帧
	conn, _ := net.Pipe()
	defer conn.Close()
	framer := http2.NewFramer(conn, frameBytes)

	// 读取帧
	frame, err := framer.ReadFrame()
	if err != nil {
		fmt.Println("读取帧失败:", err)
		return
	}

	// 断言读取到的帧是 HEADERS 帧
	headersFrame, ok := frame.(*http2.HeadersFrame)
	if !ok {
		fmt.Println("读取到的帧不是 HEADERS 帧")
		return
	}

	fmt.Printf("读取到 HEADERS 帧，流ID: %d, 头部片段: %v\n", headersFrame.StreamID, headersFrame.HeaderBlockFragment())

	// --- 假设的输入和输出 ---
	// 输入: frameBytes 包含了 HEADERS 帧的二进制数据
	// 输出:  成功解析出一个 http2.HeadersFrame 结构体，其 StreamID 为 1，
	//       HeaderBlockFragment 包含了经过 HPACK 编码的头部信息。
}
```

**易犯错的点（以 WINDOW_UPDATE 帧为例）：**

在使用 `WriteWindowUpdate` 时，一个常见的错误是设置了非法的窗口增量值。HTTP/2 规范要求窗口增量值必须大于 0。

```go
package main

import (
	"fmt"
	"net"
	"net/http/internal/http2"
)

func main() {
	conn, _ := net.Pipe()
	defer conn.Close()
	framer := http2.NewFramer(conn, conn)

	// 错误示例：设置窗口增量为 0
	err := framer.WriteWindowUpdate(1, 0)
	if err != nil {
		fmt.Println("写入 WINDOW_UPDATE 帧失败:", err) // 输出：illegal window increment value
	}

	// 正确示例：设置窗口增量为正数
	err = framer.WriteWindowUpdate(1, 1000)
	if err != nil {
		fmt.Println("写入 WINDOW_UPDATE 帧失败:", err)
	} else {
		fmt.Println("成功写入 WINDOW_UPDATE 帧")
	}
}
```

总结来说，这部分代码是 `net/http` 包中关于 HTTP/2 协议帧处理的核心实现，定义了各种帧的结构、解析和写入逻辑，并提供了一些辅助功能来简化操作。理解这部分代码对于深入学习和使用 Go 语言的 HTTP/2 功能至关重要。

Prompt: 
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共13部分，请归纳一下它的功能

"""
rites {
		return errors.New("illegal window increment value")
	}
	f.startWrite(http2FrameWindowUpdate, 0, streamID)
	f.writeUint32(incr)
	return f.endWrite()
}

// A HeadersFrame is used to open a stream and additionally carries a
// header block fragment.
type http2HeadersFrame struct {
	http2FrameHeader

	// Priority is set if FlagHeadersPriority is set in the FrameHeader.
	Priority http2PriorityParam

	headerFragBuf []byte // not owned
}

func (f *http2HeadersFrame) HeaderBlockFragment() []byte {
	f.checkValid()
	return f.headerFragBuf
}

func (f *http2HeadersFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersEndHeaders)
}

func (f *http2HeadersFrame) StreamEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersEndStream)
}

func (f *http2HeadersFrame) HasPriority() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersPriority)
}

func http2parseHeadersFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (_ http2Frame, err error) {
	hf := &http2HeadersFrame{
		http2FrameHeader: fh,
	}
	if fh.StreamID == 0 {
		// HEADERS frames MUST be associated with a stream. If a HEADERS frame
		// is received whose stream identifier field is 0x0, the recipient MUST
		// respond with a connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR.
		countError("frame_headers_zero_stream")
		return nil, http2connError{http2ErrCodeProtocol, "HEADERS frame with stream ID 0"}
	}
	var padLength uint8
	if fh.Flags.Has(http2FlagHeadersPadded) {
		if p, padLength, err = http2readByte(p); err != nil {
			countError("frame_headers_pad_short")
			return
		}
	}
	if fh.Flags.Has(http2FlagHeadersPriority) {
		var v uint32
		p, v, err = http2readUint32(p)
		if err != nil {
			countError("frame_headers_prio_short")
			return nil, err
		}
		hf.Priority.StreamDep = v & 0x7fffffff
		hf.Priority.Exclusive = (v != hf.Priority.StreamDep) // high bit was set
		p, hf.Priority.Weight, err = http2readByte(p)
		if err != nil {
			countError("frame_headers_prio_weight_short")
			return nil, err
		}
	}
	if len(p)-int(padLength) < 0 {
		countError("frame_headers_pad_too_big")
		return nil, http2streamError(fh.StreamID, http2ErrCodeProtocol)
	}
	hf.headerFragBuf = p[:len(p)-int(padLength)]
	return hf, nil
}

// HeadersFrameParam are the parameters for writing a HEADERS frame.
type http2HeadersFrameParam struct {
	// StreamID is the required Stream ID to initiate.
	StreamID uint32
	// BlockFragment is part (or all) of a Header Block.
	BlockFragment []byte

	// EndStream indicates that the header block is the last that
	// the endpoint will send for the identified stream. Setting
	// this flag causes the stream to enter one of "half closed"
	// states.
	EndStream bool

	// EndHeaders indicates that this frame contains an entire
	// header block and is not followed by any
	// CONTINUATION frames.
	EndHeaders bool

	// PadLength is the optional number of bytes of zeros to add
	// to this frame.
	PadLength uint8

	// Priority, if non-zero, includes stream priority information
	// in the HEADER frame.
	Priority http2PriorityParam
}

// WriteHeaders writes a single HEADERS frame.
//
// This is a low-level header writing method. Encoding headers and
// splitting them into any necessary CONTINUATION frames is handled
// elsewhere.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteHeaders(p http2HeadersFrameParam) error {
	if !http2validStreamID(p.StreamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	var flags http2Flags
	if p.PadLength != 0 {
		flags |= http2FlagHeadersPadded
	}
	if p.EndStream {
		flags |= http2FlagHeadersEndStream
	}
	if p.EndHeaders {
		flags |= http2FlagHeadersEndHeaders
	}
	if !p.Priority.IsZero() {
		flags |= http2FlagHeadersPriority
	}
	f.startWrite(http2FrameHeaders, flags, p.StreamID)
	if p.PadLength != 0 {
		f.writeByte(p.PadLength)
	}
	if !p.Priority.IsZero() {
		v := p.Priority.StreamDep
		if !http2validStreamIDOrZero(v) && !f.AllowIllegalWrites {
			return http2errDepStreamID
		}
		if p.Priority.Exclusive {
			v |= 1 << 31
		}
		f.writeUint32(v)
		f.writeByte(p.Priority.Weight)
	}
	f.wbuf = append(f.wbuf, p.BlockFragment...)
	f.wbuf = append(f.wbuf, http2padZeros[:p.PadLength]...)
	return f.endWrite()
}

// A PriorityFrame specifies the sender-advised priority of a stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.3
type http2PriorityFrame struct {
	http2FrameHeader
	http2PriorityParam
}

// PriorityParam are the stream prioritzation parameters.
type http2PriorityParam struct {
	// StreamDep is a 31-bit stream identifier for the
	// stream that this stream depends on. Zero means no
	// dependency.
	StreamDep uint32

	// Exclusive is whether the dependency is exclusive.
	Exclusive bool

	// Weight is the stream's zero-indexed weight. It should be
	// set together with StreamDep, or neither should be set. Per
	// the spec, "Add one to the value to obtain a weight between
	// 1 and 256."
	Weight uint8
}

func (p http2PriorityParam) IsZero() bool {
	return p == http2PriorityParam{}
}

func http2parsePriorityFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		countError("frame_priority_zero_stream")
		return nil, http2connError{http2ErrCodeProtocol, "PRIORITY frame with stream ID 0"}
	}
	if len(payload) != 5 {
		countError("frame_priority_bad_length")
		return nil, http2connError{http2ErrCodeFrameSize, fmt.Sprintf("PRIORITY frame payload size was %d; want 5", len(payload))}
	}
	v := binary.BigEndian.Uint32(payload[:4])
	streamID := v & 0x7fffffff // mask off high bit
	return &http2PriorityFrame{
		http2FrameHeader: fh,
		http2PriorityParam: http2PriorityParam{
			Weight:    payload[4],
			StreamDep: streamID,
			Exclusive: streamID != v, // was high bit set?
		},
	}, nil
}

// WritePriority writes a PRIORITY frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WritePriority(streamID uint32, p http2PriorityParam) error {
	if !http2validStreamID(streamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	if !http2validStreamIDOrZero(p.StreamDep) {
		return http2errDepStreamID
	}
	f.startWrite(http2FramePriority, 0, streamID)
	v := p.StreamDep
	if p.Exclusive {
		v |= 1 << 31
	}
	f.writeUint32(v)
	f.writeByte(p.Weight)
	return f.endWrite()
}

// A RSTStreamFrame allows for abnormal termination of a stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.4
type http2RSTStreamFrame struct {
	http2FrameHeader
	ErrCode http2ErrCode
}

func http2parseRSTStreamFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if len(p) != 4 {
		countError("frame_rststream_bad_len")
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	if fh.StreamID == 0 {
		countError("frame_rststream_zero_stream")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	return &http2RSTStreamFrame{fh, http2ErrCode(binary.BigEndian.Uint32(p[:4]))}, nil
}

// WriteRSTStream writes a RST_STREAM frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteRSTStream(streamID uint32, code http2ErrCode) error {
	if !http2validStreamID(streamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	f.startWrite(http2FrameRSTStream, 0, streamID)
	f.writeUint32(uint32(code))
	return f.endWrite()
}

// A ContinuationFrame is used to continue a sequence of header block fragments.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.10
type http2ContinuationFrame struct {
	http2FrameHeader
	headerFragBuf []byte
}

func http2parseContinuationFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		countError("frame_continuation_zero_stream")
		return nil, http2connError{http2ErrCodeProtocol, "CONTINUATION frame with stream ID 0"}
	}
	return &http2ContinuationFrame{fh, p}, nil
}

func (f *http2ContinuationFrame) HeaderBlockFragment() []byte {
	f.checkValid()
	return f.headerFragBuf
}

func (f *http2ContinuationFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagContinuationEndHeaders)
}

// WriteContinuation writes a CONTINUATION frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteContinuation(streamID uint32, endHeaders bool, headerBlockFragment []byte) error {
	if !http2validStreamID(streamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	var flags http2Flags
	if endHeaders {
		flags |= http2FlagContinuationEndHeaders
	}
	f.startWrite(http2FrameContinuation, flags, streamID)
	f.wbuf = append(f.wbuf, headerBlockFragment...)
	return f.endWrite()
}

// A PushPromiseFrame is used to initiate a server stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.6
type http2PushPromiseFrame struct {
	http2FrameHeader
	PromiseID     uint32
	headerFragBuf []byte // not owned
}

func (f *http2PushPromiseFrame) HeaderBlockFragment() []byte {
	f.checkValid()
	return f.headerFragBuf
}

func (f *http2PushPromiseFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagPushPromiseEndHeaders)
}

func http2parsePushPromise(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (_ http2Frame, err error) {
	pp := &http2PushPromiseFrame{
		http2FrameHeader: fh,
	}
	if pp.StreamID == 0 {
		// PUSH_PROMISE frames MUST be associated with an existing,
		// peer-initiated stream. The stream identifier of a
		// PUSH_PROMISE frame indicates the stream it is associated
		// with. If the stream identifier field specifies the value
		// 0x0, a recipient MUST respond with a connection error
		// (Section 5.4.1) of type PROTOCOL_ERROR.
		countError("frame_pushpromise_zero_stream")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	// The PUSH_PROMISE frame includes optional padding.
	// Padding fields and flags are identical to those defined for DATA frames
	var padLength uint8
	if fh.Flags.Has(http2FlagPushPromisePadded) {
		if p, padLength, err = http2readByte(p); err != nil {
			countError("frame_pushpromise_pad_short")
			return
		}
	}

	p, pp.PromiseID, err = http2readUint32(p)
	if err != nil {
		countError("frame_pushpromise_promiseid_short")
		return
	}
	pp.PromiseID = pp.PromiseID & (1<<31 - 1)

	if int(padLength) > len(p) {
		// like the DATA frame, error out if padding is longer than the body.
		countError("frame_pushpromise_pad_too_big")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	pp.headerFragBuf = p[:len(p)-int(padLength)]
	return pp, nil
}

// PushPromiseParam are the parameters for writing a PUSH_PROMISE frame.
type http2PushPromiseParam struct {
	// StreamID is the required Stream ID to initiate.
	StreamID uint32

	// PromiseID is the required Stream ID which this
	// Push Promises
	PromiseID uint32

	// BlockFragment is part (or all) of a Header Block.
	BlockFragment []byte

	// EndHeaders indicates that this frame contains an entire
	// header block and is not followed by any
	// CONTINUATION frames.
	EndHeaders bool

	// PadLength is the optional number of bytes of zeros to add
	// to this frame.
	PadLength uint8
}

// WritePushPromise writes a single PushPromise Frame.
//
// As with Header Frames, This is the low level call for writing
// individual frames. Continuation frames are handled elsewhere.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WritePushPromise(p http2PushPromiseParam) error {
	if !http2validStreamID(p.StreamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	var flags http2Flags
	if p.PadLength != 0 {
		flags |= http2FlagPushPromisePadded
	}
	if p.EndHeaders {
		flags |= http2FlagPushPromiseEndHeaders
	}
	f.startWrite(http2FramePushPromise, flags, p.StreamID)
	if p.PadLength != 0 {
		f.writeByte(p.PadLength)
	}
	if !http2validStreamID(p.PromiseID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	f.writeUint32(p.PromiseID)
	f.wbuf = append(f.wbuf, p.BlockFragment...)
	f.wbuf = append(f.wbuf, http2padZeros[:p.PadLength]...)
	return f.endWrite()
}

// WriteRawFrame writes a raw frame. This can be used to write
// extension frames unknown to this package.
func (f *http2Framer) WriteRawFrame(t http2FrameType, flags http2Flags, streamID uint32, payload []byte) error {
	f.startWrite(t, flags, streamID)
	f.writeBytes(payload)
	return f.endWrite()
}

func http2readByte(p []byte) (remain []byte, b byte, err error) {
	if len(p) == 0 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return p[1:], p[0], nil
}

func http2readUint32(p []byte) (remain []byte, v uint32, err error) {
	if len(p) < 4 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return p[4:], binary.BigEndian.Uint32(p[:4]), nil
}

type http2streamEnder interface {
	StreamEnded() bool
}

type http2headersEnder interface {
	HeadersEnded() bool
}

type http2headersOrContinuation interface {
	http2headersEnder
	HeaderBlockFragment() []byte
}

// A MetaHeadersFrame is the representation of one HEADERS frame and
// zero or more contiguous CONTINUATION frames and the decoding of
// their HPACK-encoded contents.
//
// This type of frame does not appear on the wire and is only returned
// by the Framer when Framer.ReadMetaHeaders is set.
type http2MetaHeadersFrame struct {
	*http2HeadersFrame

	// Fields are the fields contained in the HEADERS and
	// CONTINUATION frames. The underlying slice is owned by the
	// Framer and must not be retained after the next call to
	// ReadFrame.
	//
	// Fields are guaranteed to be in the correct http2 order and
	// not have unknown pseudo header fields or invalid header
	// field names or values. Required pseudo header fields may be
	// missing, however. Use the MetaHeadersFrame.Pseudo accessor
	// method access pseudo headers.
	Fields []hpack.HeaderField

	// Truncated is whether the max header list size limit was hit
	// and Fields is incomplete. The hpack decoder state is still
	// valid, however.
	Truncated bool
}

// PseudoValue returns the given pseudo header field's value.
// The provided pseudo field should not contain the leading colon.
func (mh *http2MetaHeadersFrame) PseudoValue(pseudo string) string {
	for _, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return ""
		}
		if hf.Name[1:] == pseudo {
			return hf.Value
		}
	}
	return ""
}

// RegularFields returns the regular (non-pseudo) header fields of mh.
// The caller does not own the returned slice.
func (mh *http2MetaHeadersFrame) RegularFields() []hpack.HeaderField {
	for i, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return mh.Fields[i:]
		}
	}
	return nil
}

// PseudoFields returns the pseudo header fields of mh.
// The caller does not own the returned slice.
func (mh *http2MetaHeadersFrame) PseudoFields() []hpack.HeaderField {
	for i, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return mh.Fields[:i]
		}
	}
	return mh.Fields
}

func (mh *http2MetaHeadersFrame) checkPseudos() error {
	var isRequest, isResponse bool
	pf := mh.PseudoFields()
	for i, hf := range pf {
		switch hf.Name {
		case ":method", ":path", ":scheme", ":authority", ":protocol":
			isRequest = true
		case ":status":
			isResponse = true
		default:
			return http2pseudoHeaderError(hf.Name)
		}
		// Check for duplicates.
		// This would be a bad algorithm, but N is 5.
		// And this doesn't allocate.
		for _, hf2 := range pf[:i] {
			if hf.Name == hf2.Name {
				return http2duplicatePseudoHeaderError(hf.Name)
			}
		}
	}
	if isRequest && isResponse {
		return http2errMixPseudoHeaderTypes
	}
	return nil
}

func (fr *http2Framer) maxHeaderStringLen() int {
	v := int(fr.maxHeaderListSize())
	if v < 0 {
		// If maxHeaderListSize overflows an int, use no limit (0).
		return 0
	}
	return v
}

// readMetaFrame returns 0 or more CONTINUATION frames from fr and
// merge them into the provided hf and returns a MetaHeadersFrame
// with the decoded hpack values.
func (fr *http2Framer) readMetaFrame(hf *http2HeadersFrame) (http2Frame, error) {
	if fr.AllowIllegalReads {
		return nil, errors.New("illegal use of AllowIllegalReads with ReadMetaHeaders")
	}
	mh := &http2MetaHeadersFrame{
		http2HeadersFrame: hf,
	}
	var remainSize = fr.maxHeaderListSize()
	var sawRegular bool

	var invalid error // pseudo header field errors
	hdec := fr.ReadMetaHeaders
	hdec.SetEmitEnabled(true)
	hdec.SetMaxStringLength(fr.maxHeaderStringLen())
	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		if http2VerboseLogs && fr.logReads {
			fr.debugReadLoggerf("http2: decoded hpack field %+v", hf)
		}
		if !httpguts.ValidHeaderFieldValue(hf.Value) {
			// Don't include the value in the error, because it may be sensitive.
			invalid = http2headerFieldValueError(hf.Name)
		}
		isPseudo := strings.HasPrefix(hf.Name, ":")
		if isPseudo {
			if sawRegular {
				invalid = http2errPseudoAfterRegular
			}
		} else {
			sawRegular = true
			if !http2validWireHeaderFieldName(hf.Name) {
				invalid = http2headerFieldNameError(hf.Name)
			}
		}

		if invalid != nil {
			hdec.SetEmitEnabled(false)
			return
		}

		size := hf.Size()
		if size > remainSize {
			hdec.SetEmitEnabled(false)
			mh.Truncated = true
			remainSize = 0
			return
		}
		remainSize -= size

		mh.Fields = append(mh.Fields, hf)
	})
	// Lose reference to MetaHeadersFrame:
	defer hdec.SetEmitFunc(func(hf hpack.HeaderField) {})

	var hc http2headersOrContinuation = hf
	for {
		frag := hc.HeaderBlockFragment()

		// Avoid parsing large amounts of headers that we will then discard.
		// If the sender exceeds the max header list size by too much,
		// skip parsing the fragment and close the connection.
		//
		// "Too much" is either any CONTINUATION frame after we've already
		// exceeded the max header list size (in which case remainSize is 0),
		// or a frame whose encoded size is more than twice the remaining
		// header list bytes we're willing to accept.
		if int64(len(frag)) > int64(2*remainSize) {
			if http2VerboseLogs {
				log.Printf("http2: header list too large")
			}
			// It would be nice to send a RST_STREAM before sending the GOAWAY,
			// but the structure of the server's frame writer makes this difficult.
			return mh, http2ConnectionError(http2ErrCodeProtocol)
		}

		// Also close the connection after any CONTINUATION frame following an
		// invalid header, since we stop tracking the size of the headers after
		// an invalid one.
		if invalid != nil {
			if http2VerboseLogs {
				log.Printf("http2: invalid header: %v", invalid)
			}
			// It would be nice to send a RST_STREAM before sending the GOAWAY,
			// but the structure of the server's frame writer makes this difficult.
			return mh, http2ConnectionError(http2ErrCodeProtocol)
		}

		if _, err := hdec.Write(frag); err != nil {
			return mh, http2ConnectionError(http2ErrCodeCompression)
		}

		if hc.HeadersEnded() {
			break
		}
		if f, err := fr.ReadFrame(); err != nil {
			return nil, err
		} else {
			hc = f.(*http2ContinuationFrame) // guaranteed by checkFrameOrder
		}
	}

	mh.http2HeadersFrame.headerFragBuf = nil
	mh.http2HeadersFrame.invalidate()

	if err := hdec.Close(); err != nil {
		return mh, http2ConnectionError(http2ErrCodeCompression)
	}
	if invalid != nil {
		fr.errDetail = invalid
		if http2VerboseLogs {
			log.Printf("http2: invalid header: %v", invalid)
		}
		return nil, http2StreamError{mh.StreamID, http2ErrCodeProtocol, invalid}
	}
	if err := mh.checkPseudos(); err != nil {
		fr.errDetail = err
		if http2VerboseLogs {
			log.Printf("http2: invalid pseudo headers: %v", err)
		}
		return nil, http2StreamError{mh.StreamID, http2ErrCodeProtocol, err}
	}
	return mh, nil
}

func http2summarizeFrame(f http2Frame) string {
	var buf bytes.Buffer
	f.Header().writeDebug(&buf)
	switch f := f.(type) {
	case *http2SettingsFrame:
		n := 0
		f.ForeachSetting(func(s http2Setting) error {
			n++
			if n == 1 {
				buf.WriteString(", settings:")
			}
			fmt.Fprintf(&buf, " %v=%v,", s.ID, s.Val)
			return nil
		})
		if n > 0 {
			buf.Truncate(buf.Len() - 1) // remove trailing comma
		}
	case *http2DataFrame:
		data := f.Data()
		const max = 256
		if len(data) > max {
			data = data[:max]
		}
		fmt.Fprintf(&buf, " data=%q", data)
		if len(f.Data()) > max {
			fmt.Fprintf(&buf, " (%d bytes omitted)", len(f.Data())-max)
		}
	case *http2WindowUpdateFrame:
		if f.StreamID == 0 {
			buf.WriteString(" (conn)")
		}
		fmt.Fprintf(&buf, " incr=%v", f.Increment)
	case *http2PingFrame:
		fmt.Fprintf(&buf, " ping=%q", f.Data[:])
	case *http2GoAwayFrame:
		fmt.Fprintf(&buf, " LastStreamID=%v ErrCode=%v Debug=%q",
			f.LastStreamID, f.ErrCode, f.debugData)
	case *http2RSTStreamFrame:
		fmt.Fprintf(&buf, " ErrCode=%v", f.ErrCode)
	}
	return buf.String()
}

var http2DebugGoroutines = os.Getenv("DEBUG_HTTP2_GOROUTINES") == "1"

type http2goroutineLock uint64

func http2newGoroutineLock() http2goroutineLock {
	if !http2DebugGoroutines {
		return 0
	}
	return http2goroutineLock(http2curGoroutineID())
}

func (g http2goroutineLock) check() {
	if !http2DebugGoroutines {
		return
	}
	if http2curGoroutineID() != uint64(g) {
		panic("running on the wrong goroutine")
	}
}

func (g http2goroutineLock) checkNotOn() {
	if !http2DebugGoroutines {
		return
	}
	if http2curGoroutineID() == uint64(g) {
		panic("running on the wrong goroutine")
	}
}

var http2goroutineSpace = []byte("goroutine ")

func http2curGoroutineID() uint64 {
	bp := http2littleBuf.Get().(*[]byte)
	defer http2littleBuf.Put(bp)
	b := *bp
	b = b[:runtime.Stack(b, false)]
	// Parse the 4707 out of "goroutine 4707 ["
	b = bytes.TrimPrefix(b, http2goroutineSpace)
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		panic(fmt.Sprintf("No space found in %q", b))
	}
	b = b[:i]
	n, err := http2parseUintBytes(b, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse goroutine ID out of %q: %v", b, err))
	}
	return n
}

var http2littleBuf = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64)
		return &buf
	},
}

// parseUintBytes is like strconv.ParseUint, but using a []byte.
func http2parseUintBytes(s []byte, base int, bitSize int) (n uint64, err error) {
	var cutoff, maxVal uint64

	if bitSize == 0 {
		bitSize = int(strconv.IntSize)
	}

	s0 := s
	switch {
	case len(s) < 1:
		err = strconv.ErrSyntax
		goto Error

	case 2 <= base && base <= 36:
		// valid base; nothing to do

	case base == 0:
		// Look for octal, hex prefix.
		switch {
		case s[0] == '0' && len(s) > 1 && (s[1] == 'x' || s[1] == 'X'):
			base = 16
			s = s[2:]
			if len(s) < 1 {
				err = strconv.ErrSyntax
				goto Error
			}
		case s[0] == '0':
			base = 8
		default:
			base = 10
		}

	default:
		err = errors.New("invalid base " + strconv.Itoa(base))
		goto Error
	}

	n = 0
	cutoff = http2cutoff64(base)
	maxVal = 1<<uint(bitSize) - 1

	for i := 0; i < len(s); i++ {
		var v byte
		d := s[i]
		switch {
		case '0' <= d && d <= '9':
			v = d - '0'
		case 'a' <= d && d <= 'z':
			v = d - 'a' + 10
		case 'A' <= d && d <= 'Z':
			v = d - 'A' + 10
		default:
			n = 0
			err = strconv.ErrSyntax
			goto Error
		}
		if int(v) >= base {
			n = 0
			err = strconv.ErrSyntax
			goto Error
		}

		if n >= cutoff {
			// n*base overflows
			n = 1<<64 - 1
			err = strconv.ErrRange
			goto Error
		}
		n *= uint64(base)

		n1 := n + uint64(v)
		if n1 < n || n1 > maxVal {
			// n+v overflows
			n = 1<<64 - 1
			err = strconv.ErrRange
			goto Error
		}
		n = n1
	}

	return n, nil

Error:
	return n, &strconv.NumError{Func: "ParseUint", Num: string(s0), Err: err}
}

// Return the first number n such that n*base >= 1<<64.
func http2cutoff64(base int) uint64 {
	if base < 2 {
		return 0
	}
	return (1<<64-1)/uint64(base) + 1
}

var (
	http2commonBuildOnce   sync.Once
	http2commonLowerHeader map[string]string // Go-Canonical-Case -> lower-case
	http2commonCanonHeader map[string]string // lower-case -> Go-Canonical-Case
)

func http2buildCommonHeaderMapsOnce() {
	http2commonBuildOnce.Do(http2buildCommonHeaderMaps)
}

func http2buildCommonHeaderMaps() {
	common := []string{
		"accept",
		"accept-charset",
		"accept-encoding",
		"accept-language",
		"accept-ranges",
		"age",
		"access-control-allow-credentials",
		"access-control-allow-headers",
		"access-control-allow-methods",
		"access-control-allow-origin",
		"access-control-expose-headers",
		"access-control-max-age",
		"access-control-request-headers",
		"access-control-request-method",
		"allow",
		"authorization",
		"cache-control",
		"content-disposition",
		"content-encoding",
		"content-language",
		"content-length",
		"content-location",
		"content-range",
		"content-type",
		"cookie",
		"date",
		"etag",
		"expect",
		"expires",
		"from",
		"host",
		"if-match",
		"if-modified-since",
		"if-none-match",
		"if-unmodified-since",
		"last-modified",
		"link",
		"location",
		"max-forwards",
		"origin",
		"proxy-authenticate",
		"proxy-authorization",
		"range",
		"referer",
		"refresh",
		"retry-after",
		"server",
		"set-cookie",
		"strict-transport-security",
		"trailer",
		"transfer-encoding",
		"user-agent",
		"vary",
		"via",
		"www-authenticate",
		"x-forwarded-for",
		"x-forwarded-proto",
	}
	http2commonLowerHeader = make(map[string]string, len(common))
	http2commonCanonHeader = make(map[string]string, len(common))
	for _, v := range common {
		chk := CanonicalHeaderKey(v)
		http2commonLowerHeader[chk] = v
		http2commonCanonHeader[v] = chk
	}
}

func http2lowerHeader(v string) (lower string, ascii bool) {
	http2buildCommonHeaderMapsOnce()
	if s, ok := http2commonLowerHeader[v]; ok {
		return s, true
	}
	return http2asciiToLower(v)
}

func http2canonicalHeader(v string) string {
	http2buildCommonHeaderMapsOnce()
	if s, ok := http2commonCanonHeader[v]; ok {
		return s
	}
	return CanonicalHeaderKey(v)
}

var (
	http2VerboseLogs                    bool
	http2logFrameWrites                 bool
	http2logFrameReads                  bool
	http2inTests                        bool
	http2disableExtendedConnectProtocol bool
)

func init() {
	e := os.Getenv("GODEBUG")
	if strings.Contains(e, "http2debug=1") {
		http2VerboseLogs = true
	}
	if strings.Contains(e, "http2debug=2") {
		http2VerboseLogs = true
		http2logFrameWrites = true
		http2logFrameReads = true
	}
	if strings.Contains(e, "http2xconnect=0") {
		http2disableExtendedConnectProtocol = true
	}
}

const (
	// ClientPreface is the string that must be sent by new
	// connections from clients.
	http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	// SETTINGS_MAX_FRAME_SIZE default
	// https://httpwg.org/specs/rfc7540.html#rfc.section.6.5.2
	http2initialMaxFrameSize = 16384

	// NextProtoTLS is the NPN/ALPN protocol negotiated during
	// HTTP/2's TLS setup.
	http2NextProtoTLS = "h2"

	// https://httpwg.org/specs/rfc7540.html#SettingValues
	http2initialHeaderTableSize = 4096

	http2initialWindowSize = 65535 // 6.9.2 Initial Flow Control Window Size

	http2defaultMaxReadFrameSize = 1 << 20
)

var (
	http2clientPreface = []byte(http2ClientPreface)
)

type http2streamState int

// HTTP/2 stream states.
//
// See http://tools.ietf.org/html/rfc7540#section-5.1.
//
// For simplicity, the server code merges "reserved (local)" into
// "half-closed (remote)". This is one less state transition to track.
// The only downside is that we send PUSH_PROMISEs slightly less
// liberally than allowable. More discussion here:
// https://lists.w3.org/Archives/Public/ietf-http-wg/2016JulSep/0599.html
//
// "reserved (remote)" is omitted since the client code does not
// support server push.
const (
	http2stateIdle http2streamState = iota
	http2stateOpen
	http2stateHalfClosedLocal
	http2stateHalfClosedRemote
	http2stateClosed
)

var http2stateName = [...]string{
	http2stateIdle:             "Idle",
	http2stateOpen:             "Open",
	http2stateHalfClosedLocal:  "HalfClosedLocal",
	http2stateHalfClosedRemote: "HalfClosedRemote",
	http2stateClosed:           "Closed",
}

func (st http2streamState) String() string {
	return http2stateName[st]
}

// Setting is a setting parameter: which setting it is, and its value.
type http2Setting struct {
	// ID is which setting is being set.
	// See https://httpwg.org/specs/rfc7540.html#SettingFormat
	ID http2SettingID

	// Val is the value.
	Val uint32
}

func (s http2Setting) String() string {
	return fmt.Sprintf("[%v = %d]", s.ID, s.Val)
}

// Valid reports whether the setting is valid.
func (s http2Setting) Valid() error {
	// Limits and error codes from 6.5.2 Defined SETTINGS Parameters
	switch s.ID {
	case http2SettingEnablePush:
		if s.Val != 1 && s.Val != 0 {
			return http2ConnectionError(http2ErrCodeProtocol)
		}
	case http2SettingInitialWindowSize:
		if s.Val > 1<<31-1 {
			return http2ConnectionError(http2ErrCodeFlowControl)
		}
	case http2SettingMaxFrameSize:
		if s.Val < 16384 || s.Val > 1<<24-1 {
			return http2ConnectionError(http2ErrCodeProtocol)
		}
	case http2SettingEnableConnectProtocol:
		if s.Val != 1 && s.Val != 0 {
			return http2ConnectionError(http2ErrCodeProtocol)
		}
	}
	return nil
}

// A SettingID is an HTTP/2 setting as defined in
// https://httpwg.org/specs/rfc7540.html#iana-settings
type http2SettingID uint16

const (
	http2SettingHeaderTableSize       http2SettingID = 0x1
	http2SettingEnablePush            http2SettingID = 0x2
	http2SettingMaxConcurrentStreams  http2SettingID = 0x3
	http2SettingInitialWindowSize     http2SettingID = 0x4
	http2SettingMaxFrameSize          http2SettingID = 0x5
	http2SettingMaxHeaderListSize     http2SettingID = 0x6
	http2SettingEnableConnectProtocol http2SettingID = 0x8
)

var http2settingName = map[http2SettingID]string{
	http2SettingHeaderTableSize:       "HEADER_TABLE_SIZE",
	http2SettingEnablePush:            "ENABLE_PUSH",
	http2SettingMaxConcurrentStreams:  "MAX_CONCURRENT_STREAMS",
	http2SettingInitialWindowSize:     "INITIAL_WINDOW_SIZE",
	http2SettingMaxFrameSize:          "MAX_FRAME_SIZE",
	http2SettingMaxHeaderListSize:     "MAX_HEADER_LIST_SIZE",
	http2SettingEnableConnectProtocol: "ENABLE_CONNECT_PROTOCOL",
}

func (s http2SettingID) String() string {
	if v, ok := http2settingName[s]; ok {
		return v
	}
	return fmt.Sprintf("UNKNOWN_SETTING_%d", uint16(s))
}

// validWireHeaderFieldName reports whether v is a valid header field
// name (key). See httpguts.ValidHeaderName for the base rules.
//
// Further, http2 says:
//
//	"Just as in HTTP/1.x, header field names are strings of ASCII
//	characters that are compared in a case-insensitive
//	fashion. However, header field names MUST be converted to
//	lowercase prior to their encoding in HTTP/2. "
func http2validWireHeaderFieldName(v string) bool {
	if len(v) == 0 {
		return false
	}
	for _, r := range v {
		if !httpguts.IsTokenRune(r) {
			return false
		}
		if 'A' <= r && r <= 'Z' {
			return false
		}
	}
	return true
}

func http2httpCodeString(code int) string {
	switch code {
	case 200:
		return "200"
	case 404:
		return "404"
	}
	return strconv.Itoa(code)
}

// from pkg io
type http2stringWriter interface {
	WriteString(s string) (n int, err error)
}

// A closeWaiter is like a sync.WaitGroup but only goes 1 to 0 (open to closed).
type http2closeWaiter chan struct{}

// Init makes a closeWaiter usable.
// It exists because so a closeWaiter value can be placed inside a
// larger struct and have the Mutex and Cond's memory in the same
// allocation.
func (cw *http2closeWaiter) Init() {
	*cw = make(chan struct{})
}

// Close marks the closeWaiter as closed and unblocks any waiters.
func (cw http2closeWaiter) Close() {
	close(cw)
}

// Wait waits for the closeWaiter to become closed.
func (cw http2closeWaiter) Wait() {
	<-cw
}

// bufferedWriter is a buffered writer that writes to w.
// Its buffered writer is lazily allocated as needed, to minimize
// idle memory usage with many connections.
type http2bufferedWriter struct {
	_           http2incomparable
	group       http2synctestGroupInterface // immutable
	conn        net.Conn                    // immutable
	bw          *bufio.Writer               // non-nil when data is buffered
	byteTimeout time.Duration               // immutable, WriteByteTimeout
}

func http2newBufferedWriter(group http2synctestGroupInterface, conn net.Conn, timeout time.Duration) *http2bufferedWriter {
	return &http2bufferedWriter{
		group:       group,
		conn:        conn,
		byteTimeout: timeout,
	}
}

// bufWriterPoolBufferSize is the size of bufio.Writer's
// buffers cre
"""




```