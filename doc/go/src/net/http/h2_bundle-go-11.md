Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Goal:** The code resides in `go/src/net/http/h2_bundle.go`. The `h2` suggests it's related to HTTP/2. The file name implies it bundles related functionalities. Looking at the function and type names (e.g., `http2splitHeaderBlock`, `http2writeResHeaders`, `http2WriteScheduler`), it's clear we're dealing with how HTTP/2 frames are constructed and scheduled for writing.

2. **Deconstruct by Functionality:**  Instead of trying to understand everything at once, break it down into logical units. Look for clearly defined functions and structs.

    * **Header Splitting (`http2splitHeaderBlock`):**  This function's name and comments are quite explicit. It takes a header block and splits it into fragments according to `MAX_FRAME_SIZE`. This immediately suggests the concept of HTTP/2's frame size limitation and the need for CONTINUATION frames.

    * **Response Headers (`http2writeResHeaders`):** The struct name and fields ( `streamID`, `httpResCode`, `h`, `trailers`, `endStream`) clearly point to the creation of HTTP response header frames. The `writeFrame` and `writeHeaderBlock` methods show the process of encoding and writing these headers.

    * **Push Promise (`http2writePushPromise`):** Similar to response headers, this struct and its methods manage the creation of PUSH_PROMISE frames, a key feature of HTTP/2 server push.

    * **100 Continue (`http2write100ContinueHeadersFrame`):** This is a specific, simpler case for the 100 Continue status.

    * **Window Update (`http2writeWindowUpdate`):**  This directly relates to HTTP/2 flow control.

    * **Header Encoding (`http2encodeHeaders`, `http2encKV`):**  These functions handle the actual encoding of header key-value pairs using HPACK.

    * **Write Scheduling (Interfaces and Implementations):** This is a significant part. The `http2WriteScheduler` interface and its implementations (`http2priorityWriteScheduler`, `http2randomWriteScheduler`, `http2roundRobinWriteScheduler`) clearly demonstrate different strategies for deciding which frames to send next. Focus on the methods of the interface (`OpenStream`, `CloseStream`, `AdjustStream`, `Push`, `Pop`).

    * **Frame Write Request (`http2FrameWriteRequest`):** This struct encapsulates a frame to be written and related metadata. The `Consume` method is crucial for understanding flow control interaction.

    * **Write Queue (`http2writeQueue`):** A basic data structure used by the schedulers to hold frames.

    * **Priority Tree (`http2priorityNode` and `http2priorityWriteScheduler`):**  This is the most complex scheduler. The `http2priorityNode` represents a node in the priority tree, and the scheduler manages this tree to respect HTTP/2 priority rules.

3. **Identify Key HTTP/2 Concepts:** As you go through the code, actively connect the code elements to core HTTP/2 concepts:

    * **Frames:**  The fundamental unit of communication in HTTP/2. Many structs represent different frame types (HEADERS, CONTINUATION, PUSH_PROMISE, WINDOW_UPDATE, DATA).
    * **Streams:**  The concept of multiplexing multiple requests/responses over a single TCP connection. `streamID` is a key field.
    * **Headers and CONTINUATION frames:**  Headers can be larger than a single frame, requiring splitting.
    * **Server Push:**  The `PUSH_PROMISE` functionality.
    * **Flow Control:** The `http2writeWindowUpdate` struct and the `Consume` method in `http2FrameWriteRequest`.
    * **Prioritization:** The `http2WriteScheduler` interface and its priority-based implementation.
    * **HPACK:** The `hpack.Encoder` is used for header compression.

4. **Infer Functionality from Names and Types:**  Even without deep knowledge of HTTP/2, you can infer a lot from the naming conventions. "writeResHeaders" suggests writing response headers, "splitHeaderBlock" suggests splitting a header block, and so on.

5. **Look for Examples and Logic:**  The code includes internal logic (like the header splitting loop) and calls to other parts of the `net/http` package (like `hpack.Encoder`). This helps understand the workflow.

6. **Pay Attention to Comments:** The comments are valuable. They often explain the "why" behind the code and reference relevant RFC sections.

7. **Synthesize and Summarize:**  After analyzing the individual parts, synthesize the findings into a coherent summary of the file's overall purpose and the specific functions it provides.

8. **Address the Prompt's Specific Questions:** Go back to the prompt and ensure you've addressed all the requested points:
    * Listing functionalities.
    * Inferring Go features and providing examples (structs, methods, interfaces, concurrency primitives - although less prominent in this snippet).
    * Explaining code reasoning (especially for the header splitting and scheduling).
    * Detailing command-line arguments (not present in this snippet).
    * Identifying potential user errors (though this section was empty in this case).
    * Providing a concise summary.

9. **Iterative Refinement:**  The first pass might not be perfect. Review your analysis, clarify any ambiguities, and ensure the language is clear and accurate. For instance, initially, you might just say "handles headers," but refining it to "handles splitting large header blocks into multiple frames" is more precise.

By following these steps, you can systematically analyze even complex code snippets and extract meaningful information. The key is to break down the problem, connect code elements to underlying concepts, and use the available information (names, types, comments, logic) to infer functionality.
这是 `go/src/net/http/h2_bundle.go` 文件的第 12 部分，主要关注 **HTTP/2 帧的写入调度和管理**。它定义了不同的写入调度器，负责决定在连接上发送哪些帧以及发送的顺序，并处理帧的分割、排队和消费等操作。

以下是该部分代码的主要功能归纳：

1. **定义了 `http2WriteScheduler` 接口:**  这是一个核心接口，定义了 HTTP/2 写入调度器的通用行为，包括打开/关闭流、调整流优先级、推送帧、弹出帧等。这为实现不同的调度策略提供了抽象。

2. **实现了多种 `http2WriteScheduler`:**
   - **`http2priorityWriteScheduler` (优先级调度器):**  这是根据 HTTP/2 优先级规则（RFC 7540 Section 5.3）进行帧调度的实现。它维护一个优先级树，并根据流的依赖关系和权重来决定发送顺序。它还实现了流量控制的感知，在消费帧时会考虑流的可用窗口大小。
   - **`http2randomWriteScheduler` (随机调度器):**  一个简单的调度器，忽略 HTTP/2 优先级。它优先发送控制帧，然后随机选择一个有待发送帧的流。
   - **`http2roundRobinWriteScheduler` (轮询调度器):**  另一个不考虑优先级的调度器，它轮流从每个有待发送帧的流中选择帧进行发送。

3. **定义了 `http2FrameWriteRequest` 结构体:**  这个结构体封装了一个待写入的 HTTP/2 帧的信息，包括实际的写入器 (`http2writeFramer`)、所属的流 (`*http2stream`) 以及一个用于通知写入完成的 channel (`done`)。它还包含了与流量控制相关的方法，如 `DataSize()` 和 `Consume()`。

4. **定义了 `http2writeQueue` 结构体:**  这是一个简单的 FIFO 队列，用于存储待写入的 `http2FrameWriteRequest`。不同的调度器使用这种队列来管理每个流或全局的待发送帧。

5. **定义了 `http2OpenStreamOptions` 结构体:**  用于在打开流时传递额外选项，例如推送流的父流 ID。

**它可以被认为是 Go 语言中实现 HTTP/2 连接管理的核心部分，负责控制帧的发送顺序，确保符合 HTTP/2 协议规范，并提供不同的调度策略来满足不同的应用场景。**

**Go 代码示例说明 (优先级调度器):**

假设我们有两个 HTTP/2 流，stream ID 为 1 和 3。Stream 3 依赖于 stream 1，意味着 stream 1 的优先级更高。

```go
package main

import (
	"fmt"
	"math"
	"net/url"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func main() {
	// 模拟 Framer 和 HeaderEncoder
	framer := &mockFramer{}
	headerEncoder := hpack.NewEncoder(&mockHpackWriter{})

	// 创建优先级写入调度器
	scheduler := http2.NewPriorityWriteScheduler(nil)

	// 打开两个流
	scheduler.OpenStream(1, http2.OpenStreamOptions{})
	scheduler.OpenStream(3, http2.OpenStreamOptions{})

	// 设置流 3 依赖于流 1
	scheduler.AdjustStream(3, http2.PriorityParam{StreamDep: 1, Exclusive: false, Weight: 15})

	// 创建一些待发送的帧
	req1 := http2.FrameWriteRequest{
		stream: &http2.Stream{id: 1, flow: &mockFlow{}},
		write: &http2.DataFrame{
			StreamID: 1,
			Data:     []byte("data for stream 1"),
		},
	}
	req3 := http2.FrameWriteRequest{
		stream: &http2.Stream{id: 3, flow: &mockFlow{}},
		write: &http2.DataFrame{
			StreamID: 3,
			Data:     []byte("data for stream 3"),
		},
	}

	// 将帧推送到调度器
	scheduler.Push(req3) // 先推送 stream 3 的帧
	scheduler.Push(req1) // 再推送 stream 1 的帧

	// 模拟写入上下文
	ctx := mockWriteContext{f: framer, enc: headerEncoder}

	// 弹出并发送帧，优先级调度器会优先发送 stream 1 的帧
	for i := 0; i < 2; i++ {
		wr, ok := scheduler.Pop()
		if ok {
			fmt.Printf("发送帧到流 %d\n", wr.StreamID())
			wr.write.WriteFrame(ctx) // 实际写入操作被模拟
		} else {
			fmt.Println("没有更多帧可发送")
		}
	}
}

// 模拟 Framer
type mockFramer struct{}

func (m *mockFramer) WriteData(sid uint32, endStream bool, data []byte) error {
	fmt.Printf("模拟写入 DATA 帧到流 %d，数据: %s，EndStream: %v\n", sid, data, endStream)
	return nil
}
func (m *mockFramer) WriteHeaders(p http2.HeadersFrameParam) error { return nil }
func (m *mockFramer) WriteContinuation(streamID uint32, endHeaders bool, headerBlockFragment []byte) error {
	return nil
}
func (m *mockFramer) WritePushPromise(p http2.PushPromiseParam) error { return nil }
func (m *mockFramer) WriteSettings(settings ...http2.Setting) error        { return nil }
func (m *mockFramer) WriteWindowUpdate(streamID, inc uint32) error          { return nil }

// 模拟 HPACK Writer
type mockHpackWriter struct{}

func (m *mockHpackWriter) Write(p []byte) (n int, err error) { return len(p), nil }

// 模拟 WriteContext
type mockWriteContext struct {
	f   *mockFramer
	enc *hpack.Encoder
}

func (m mockWriteContext) HeaderEncoder() (*hpack.Encoder, *hpack.Buffer) {
	buf := hpack.NewBuffer(make([]byte, 0, 256))
	return m.enc, buf
}
func (m mockWriteContext) Framer() *mockFramer { return m.f }

// 模拟 Flow
type mockFlow struct {
	current int32
}

func (f *mockFlow) available() int32 {
	return math.MaxInt32 // 假设初始可用窗口很大
}
func (f *mockFlow) take(n int32) {
	f.current += n
}
```

**假设的输出:**

```
发送帧到流 1
模拟写入 DATA 帧到流 1，数据: data for stream 1，EndStream: false
发送帧到流 3
模拟写入 DATA 帧到流 3，数据: data for stream 3，EndStream: false
```

尽管我们先将 `req3` 推入调度器，但由于优先级调度器的作用，`req1` (stream 1) 的帧会先被弹出并“发送”，因为 stream 1 具有更高的优先级。

**使用者易犯错的点:**

在使用写入调度器时，一个常见的错误是**在流关闭后仍然尝试向该流推送数据帧**。HTTP/2 协议规定，在流关闭后，不应再发送新的数据帧。

**示例:**

```go
// ... (假设已经创建了调度器和流)

scheduler.CloseStream(1)

// 错误的做法：在流 1 关闭后尝试推送数据帧
req := http2.FrameWriteRequest{
	stream: &http2.Stream{id: 1}, // 指向已关闭的流
	write: &http2.DataFrame{
		StreamID: 1,
		Data:     []byte("data after close"),
	},
}
scheduler.Push(req) // 这可能会导致 panic 或其他未定义的行为
```

优先级调度器在 `Push` 方法中会进行一定的检查，如果发现尝试向非打开状态的流推送 `DATA` 帧，会触发 `panic`。

**总结第 12 部分的功能:**

第 12 部分专注于 **HTTP/2 写入调度器的实现**，它定义了调度器的接口和多种不同的调度策略（优先级、随机、轮询）。它还定义了表示待写入帧的结构体以及用于管理帧队列的结构体。这部分代码是 HTTP/2 连接管理的关键组成部分，负责决定哪些帧应该被发送以及发送的顺序，并处理与流量控制的交互。

Prompt: 
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第12部分，共13部分，请归纳一下它的功能

"""
 each fragment. firstFrag/lastFrag are true
// for the first/last fragment, respectively.
func http2splitHeaderBlock(ctx http2writeContext, headerBlock []byte, fn func(ctx http2writeContext, frag []byte, firstFrag, lastFrag bool) error) error {
	// For now we're lazy and just pick the minimum MAX_FRAME_SIZE
	// that all peers must support (16KB). Later we could care
	// more and send larger frames if the peer advertised it, but
	// there's little point. Most headers are small anyway (so we
	// generally won't have CONTINUATION frames), and extra frames
	// only waste 9 bytes anyway.
	const maxFrameSize = 16384

	first := true
	for len(headerBlock) > 0 {
		frag := headerBlock
		if len(frag) > maxFrameSize {
			frag = frag[:maxFrameSize]
		}
		headerBlock = headerBlock[len(frag):]
		if err := fn(ctx, frag, first, len(headerBlock) == 0); err != nil {
			return err
		}
		first = false
	}
	return nil
}

// writeResHeaders is a request to write a HEADERS and 0+ CONTINUATION frames
// for HTTP response headers or trailers from a server handler.
type http2writeResHeaders struct {
	streamID    uint32
	httpResCode int      // 0 means no ":status" line
	h           Header   // may be nil
	trailers    []string // if non-nil, which keys of h to write. nil means all.
	endStream   bool

	date          string
	contentType   string
	contentLength string
}

func http2encKV(enc *hpack.Encoder, k, v string) {
	if http2VerboseLogs {
		log.Printf("http2: server encoding header %q = %q", k, v)
	}
	enc.WriteField(hpack.HeaderField{Name: k, Value: v})
}

func (w *http2writeResHeaders) staysWithinBuffer(max int) bool {
	// TODO: this is a common one. It'd be nice to return true
	// here and get into the fast path if we could be clever and
	// calculate the size fast enough, or at least a conservative
	// upper bound that usually fires. (Maybe if w.h and
	// w.trailers are nil, so we don't need to enumerate it.)
	// Otherwise I'm afraid that just calculating the length to
	// answer this question would be slower than the ~2µs benefit.
	return false
}

func (w *http2writeResHeaders) writeFrame(ctx http2writeContext) error {
	enc, buf := ctx.HeaderEncoder()
	buf.Reset()

	if w.httpResCode != 0 {
		http2encKV(enc, ":status", http2httpCodeString(w.httpResCode))
	}

	http2encodeHeaders(enc, w.h, w.trailers)

	if w.contentType != "" {
		http2encKV(enc, "content-type", w.contentType)
	}
	if w.contentLength != "" {
		http2encKV(enc, "content-length", w.contentLength)
	}
	if w.date != "" {
		http2encKV(enc, "date", w.date)
	}

	headerBlock := buf.Bytes()
	if len(headerBlock) == 0 && w.trailers == nil {
		panic("unexpected empty hpack")
	}

	return http2splitHeaderBlock(ctx, headerBlock, w.writeHeaderBlock)
}

func (w *http2writeResHeaders) writeHeaderBlock(ctx http2writeContext, frag []byte, firstFrag, lastFrag bool) error {
	if firstFrag {
		return ctx.Framer().WriteHeaders(http2HeadersFrameParam{
			StreamID:      w.streamID,
			BlockFragment: frag,
			EndStream:     w.endStream,
			EndHeaders:    lastFrag,
		})
	} else {
		return ctx.Framer().WriteContinuation(w.streamID, lastFrag, frag)
	}
}

// writePushPromise is a request to write a PUSH_PROMISE and 0+ CONTINUATION frames.
type http2writePushPromise struct {
	streamID uint32   // pusher stream
	method   string   // for :method
	url      *url.URL // for :scheme, :authority, :path
	h        Header

	// Creates an ID for a pushed stream. This runs on serveG just before
	// the frame is written. The returned ID is copied to promisedID.
	allocatePromisedID func() (uint32, error)
	promisedID         uint32
}

func (w *http2writePushPromise) staysWithinBuffer(max int) bool {
	// TODO: see writeResHeaders.staysWithinBuffer
	return false
}

func (w *http2writePushPromise) writeFrame(ctx http2writeContext) error {
	enc, buf := ctx.HeaderEncoder()
	buf.Reset()

	http2encKV(enc, ":method", w.method)
	http2encKV(enc, ":scheme", w.url.Scheme)
	http2encKV(enc, ":authority", w.url.Host)
	http2encKV(enc, ":path", w.url.RequestURI())
	http2encodeHeaders(enc, w.h, nil)

	headerBlock := buf.Bytes()
	if len(headerBlock) == 0 {
		panic("unexpected empty hpack")
	}

	return http2splitHeaderBlock(ctx, headerBlock, w.writeHeaderBlock)
}

func (w *http2writePushPromise) writeHeaderBlock(ctx http2writeContext, frag []byte, firstFrag, lastFrag bool) error {
	if firstFrag {
		return ctx.Framer().WritePushPromise(http2PushPromiseParam{
			StreamID:      w.streamID,
			PromiseID:     w.promisedID,
			BlockFragment: frag,
			EndHeaders:    lastFrag,
		})
	} else {
		return ctx.Framer().WriteContinuation(w.streamID, lastFrag, frag)
	}
}

type http2write100ContinueHeadersFrame struct {
	streamID uint32
}

func (w http2write100ContinueHeadersFrame) writeFrame(ctx http2writeContext) error {
	enc, buf := ctx.HeaderEncoder()
	buf.Reset()
	http2encKV(enc, ":status", "100")
	return ctx.Framer().WriteHeaders(http2HeadersFrameParam{
		StreamID:      w.streamID,
		BlockFragment: buf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
}

func (w http2write100ContinueHeadersFrame) staysWithinBuffer(max int) bool {
	// Sloppy but conservative:
	return 9+2*(len(":status")+len("100")) <= max
}

type http2writeWindowUpdate struct {
	streamID uint32 // or 0 for conn-level
	n        uint32
}

func (wu http2writeWindowUpdate) staysWithinBuffer(max int) bool { return http2frameHeaderLen+4 <= max }

func (wu http2writeWindowUpdate) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteWindowUpdate(wu.streamID, wu.n)
}

// encodeHeaders encodes an http.Header. If keys is not nil, then (k, h[k])
// is encoded only if k is in keys.
func http2encodeHeaders(enc *hpack.Encoder, h Header, keys []string) {
	if keys == nil {
		sorter := http2sorterPool.Get().(*http2sorter)
		// Using defer here, since the returned keys from the
		// sorter.Keys method is only valid until the sorter
		// is returned:
		defer http2sorterPool.Put(sorter)
		keys = sorter.Keys(h)
	}
	for _, k := range keys {
		vv := h[k]
		k, ascii := http2lowerHeader(k)
		if !ascii {
			// Skip writing invalid headers. Per RFC 7540, Section 8.1.2, header
			// field names have to be ASCII characters (just as in HTTP/1.x).
			continue
		}
		if !http2validWireHeaderFieldName(k) {
			// Skip it as backup paranoia. Per
			// golang.org/issue/14048, these should
			// already be rejected at a higher level.
			continue
		}
		isTE := k == "transfer-encoding"
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				// TODO: return an error? golang.org/issue/14048
				// For now just omit it.
				continue
			}
			// TODO: more of "8.1.2.2 Connection-Specific Header Fields"
			if isTE && v != "trailers" {
				continue
			}
			http2encKV(enc, k, v)
		}
	}
}

// WriteScheduler is the interface implemented by HTTP/2 write schedulers.
// Methods are never called concurrently.
type http2WriteScheduler interface {
	// OpenStream opens a new stream in the write scheduler.
	// It is illegal to call this with streamID=0 or with a streamID that is
	// already open -- the call may panic.
	OpenStream(streamID uint32, options http2OpenStreamOptions)

	// CloseStream closes a stream in the write scheduler. Any frames queued on
	// this stream should be discarded. It is illegal to call this on a stream
	// that is not open -- the call may panic.
	CloseStream(streamID uint32)

	// AdjustStream adjusts the priority of the given stream. This may be called
	// on a stream that has not yet been opened or has been closed. Note that
	// RFC 7540 allows PRIORITY frames to be sent on streams in any state. See:
	// https://tools.ietf.org/html/rfc7540#section-5.1
	AdjustStream(streamID uint32, priority http2PriorityParam)

	// Push queues a frame in the scheduler. In most cases, this will not be
	// called with wr.StreamID()!=0 unless that stream is currently open. The one
	// exception is RST_STREAM frames, which may be sent on idle or closed streams.
	Push(wr http2FrameWriteRequest)

	// Pop dequeues the next frame to write. Returns false if no frames can
	// be written. Frames with a given wr.StreamID() are Pop'd in the same
	// order they are Push'd, except RST_STREAM frames. No frames should be
	// discarded except by CloseStream.
	Pop() (wr http2FrameWriteRequest, ok bool)
}

// OpenStreamOptions specifies extra options for WriteScheduler.OpenStream.
type http2OpenStreamOptions struct {
	// PusherID is zero if the stream was initiated by the client. Otherwise,
	// PusherID names the stream that pushed the newly opened stream.
	PusherID uint32
}

// FrameWriteRequest is a request to write a frame.
type http2FrameWriteRequest struct {
	// write is the interface value that does the writing, once the
	// WriteScheduler has selected this frame to write. The write
	// functions are all defined in write.go.
	write http2writeFramer

	// stream is the stream on which this frame will be written.
	// nil for non-stream frames like PING and SETTINGS.
	// nil for RST_STREAM streams, which use the StreamError.StreamID field instead.
	stream *http2stream

	// done, if non-nil, must be a buffered channel with space for
	// 1 message and is sent the return value from write (or an
	// earlier error) when the frame has been written.
	done chan error
}

// StreamID returns the id of the stream this frame will be written to.
// 0 is used for non-stream frames such as PING and SETTINGS.
func (wr http2FrameWriteRequest) StreamID() uint32 {
	if wr.stream == nil {
		if se, ok := wr.write.(http2StreamError); ok {
			// (*serverConn).resetStream doesn't set
			// stream because it doesn't necessarily have
			// one. So special case this type of write
			// message.
			return se.StreamID
		}
		return 0
	}
	return wr.stream.id
}

// isControl reports whether wr is a control frame for MaxQueuedControlFrames
// purposes. That includes non-stream frames and RST_STREAM frames.
func (wr http2FrameWriteRequest) isControl() bool {
	return wr.stream == nil
}

// DataSize returns the number of flow control bytes that must be consumed
// to write this entire frame. This is 0 for non-DATA frames.
func (wr http2FrameWriteRequest) DataSize() int {
	if wd, ok := wr.write.(*http2writeData); ok {
		return len(wd.p)
	}
	return 0
}

// Consume consumes min(n, available) bytes from this frame, where available
// is the number of flow control bytes available on the stream. Consume returns
// 0, 1, or 2 frames, where the integer return value gives the number of frames
// returned.
//
// If flow control prevents consuming any bytes, this returns (_, _, 0). If
// the entire frame was consumed, this returns (wr, _, 1). Otherwise, this
// returns (consumed, rest, 2), where 'consumed' contains the consumed bytes and
// 'rest' contains the remaining bytes. The consumed bytes are deducted from the
// underlying stream's flow control budget.
func (wr http2FrameWriteRequest) Consume(n int32) (http2FrameWriteRequest, http2FrameWriteRequest, int) {
	var empty http2FrameWriteRequest

	// Non-DATA frames are always consumed whole.
	wd, ok := wr.write.(*http2writeData)
	if !ok || len(wd.p) == 0 {
		return wr, empty, 1
	}

	// Might need to split after applying limits.
	allowed := wr.stream.flow.available()
	if n < allowed {
		allowed = n
	}
	if wr.stream.sc.maxFrameSize < allowed {
		allowed = wr.stream.sc.maxFrameSize
	}
	if allowed <= 0 {
		return empty, empty, 0
	}
	if len(wd.p) > int(allowed) {
		wr.stream.flow.take(allowed)
		consumed := http2FrameWriteRequest{
			stream: wr.stream,
			write: &http2writeData{
				streamID: wd.streamID,
				p:        wd.p[:allowed],
				// Even if the original had endStream set, there
				// are bytes remaining because len(wd.p) > allowed,
				// so we know endStream is false.
				endStream: false,
			},
			// Our caller is blocking on the final DATA frame, not
			// this intermediate frame, so no need to wait.
			done: nil,
		}
		rest := http2FrameWriteRequest{
			stream: wr.stream,
			write: &http2writeData{
				streamID:  wd.streamID,
				p:         wd.p[allowed:],
				endStream: wd.endStream,
			},
			done: wr.done,
		}
		return consumed, rest, 2
	}

	// The frame is consumed whole.
	// NB: This cast cannot overflow because allowed is <= math.MaxInt32.
	wr.stream.flow.take(int32(len(wd.p)))
	return wr, empty, 1
}

// String is for debugging only.
func (wr http2FrameWriteRequest) String() string {
	var des string
	if s, ok := wr.write.(fmt.Stringer); ok {
		des = s.String()
	} else {
		des = fmt.Sprintf("%T", wr.write)
	}
	return fmt.Sprintf("[FrameWriteRequest stream=%d, ch=%v, writer=%v]", wr.StreamID(), wr.done != nil, des)
}

// replyToWriter sends err to wr.done and panics if the send must block
// This does nothing if wr.done is nil.
func (wr *http2FrameWriteRequest) replyToWriter(err error) {
	if wr.done == nil {
		return
	}
	select {
	case wr.done <- err:
	default:
		panic(fmt.Sprintf("unbuffered done channel passed in for type %T", wr.write))
	}
	wr.write = nil // prevent use (assume it's tainted after wr.done send)
}

// writeQueue is used by implementations of WriteScheduler.
type http2writeQueue struct {
	s          []http2FrameWriteRequest
	prev, next *http2writeQueue
}

func (q *http2writeQueue) empty() bool { return len(q.s) == 0 }

func (q *http2writeQueue) push(wr http2FrameWriteRequest) {
	q.s = append(q.s, wr)
}

func (q *http2writeQueue) shift() http2FrameWriteRequest {
	if len(q.s) == 0 {
		panic("invalid use of queue")
	}
	wr := q.s[0]
	// TODO: less copy-happy queue.
	copy(q.s, q.s[1:])
	q.s[len(q.s)-1] = http2FrameWriteRequest{}
	q.s = q.s[:len(q.s)-1]
	return wr
}

// consume consumes up to n bytes from q.s[0]. If the frame is
// entirely consumed, it is removed from the queue. If the frame
// is partially consumed, the frame is kept with the consumed
// bytes removed. Returns true iff any bytes were consumed.
func (q *http2writeQueue) consume(n int32) (http2FrameWriteRequest, bool) {
	if len(q.s) == 0 {
		return http2FrameWriteRequest{}, false
	}
	consumed, rest, numresult := q.s[0].Consume(n)
	switch numresult {
	case 0:
		return http2FrameWriteRequest{}, false
	case 1:
		q.shift()
	case 2:
		q.s[0] = rest
	}
	return consumed, true
}

type http2writeQueuePool []*http2writeQueue

// put inserts an unused writeQueue into the pool.

// put inserts an unused writeQueue into the pool.
func (p *http2writeQueuePool) put(q *http2writeQueue) {
	for i := range q.s {
		q.s[i] = http2FrameWriteRequest{}
	}
	q.s = q.s[:0]
	*p = append(*p, q)
}

// get returns an empty writeQueue.
func (p *http2writeQueuePool) get() *http2writeQueue {
	ln := len(*p)
	if ln == 0 {
		return new(http2writeQueue)
	}
	x := ln - 1
	q := (*p)[x]
	(*p)[x] = nil
	*p = (*p)[:x]
	return q
}

// RFC 7540, Section 5.3.5: the default weight is 16.
const http2priorityDefaultWeight = 15 // 16 = 15 + 1

// PriorityWriteSchedulerConfig configures a priorityWriteScheduler.
type http2PriorityWriteSchedulerConfig struct {
	// MaxClosedNodesInTree controls the maximum number of closed streams to
	// retain in the priority tree. Setting this to zero saves a small amount
	// of memory at the cost of performance.
	//
	// See RFC 7540, Section 5.3.4:
	//   "It is possible for a stream to become closed while prioritization
	//   information ... is in transit. ... This potentially creates suboptimal
	//   prioritization, since the stream could be given a priority that is
	//   different from what is intended. To avoid these problems, an endpoint
	//   SHOULD retain stream prioritization state for a period after streams
	//   become closed. The longer state is retained, the lower the chance that
	//   streams are assigned incorrect or default priority values."
	MaxClosedNodesInTree int

	// MaxIdleNodesInTree controls the maximum number of idle streams to
	// retain in the priority tree. Setting this to zero saves a small amount
	// of memory at the cost of performance.
	//
	// See RFC 7540, Section 5.3.4:
	//   Similarly, streams that are in the "idle" state can be assigned
	//   priority or become a parent of other streams. This allows for the
	//   creation of a grouping node in the dependency tree, which enables
	//   more flexible expressions of priority. Idle streams begin with a
	//   default priority (Section 5.3.5).
	MaxIdleNodesInTree int

	// ThrottleOutOfOrderWrites enables write throttling to help ensure that
	// data is delivered in priority order. This works around a race where
	// stream B depends on stream A and both streams are about to call Write
	// to queue DATA frames. If B wins the race, a naive scheduler would eagerly
	// write as much data from B as possible, but this is suboptimal because A
	// is a higher-priority stream. With throttling enabled, we write a small
	// amount of data from B to minimize the amount of bandwidth that B can
	// steal from A.
	ThrottleOutOfOrderWrites bool
}

// NewPriorityWriteScheduler constructs a WriteScheduler that schedules
// frames by following HTTP/2 priorities as described in RFC 7540 Section 5.3.
// If cfg is nil, default options are used.
func http2NewPriorityWriteScheduler(cfg *http2PriorityWriteSchedulerConfig) http2WriteScheduler {
	if cfg == nil {
		// For justification of these defaults, see:
		// https://docs.google.com/document/d/1oLhNg1skaWD4_DtaoCxdSRN5erEXrH-KnLrMwEpOtFY
		cfg = &http2PriorityWriteSchedulerConfig{
			MaxClosedNodesInTree:     10,
			MaxIdleNodesInTree:       10,
			ThrottleOutOfOrderWrites: false,
		}
	}

	ws := &http2priorityWriteScheduler{
		nodes:                make(map[uint32]*http2priorityNode),
		maxClosedNodesInTree: cfg.MaxClosedNodesInTree,
		maxIdleNodesInTree:   cfg.MaxIdleNodesInTree,
		enableWriteThrottle:  cfg.ThrottleOutOfOrderWrites,
	}
	ws.nodes[0] = &ws.root
	if cfg.ThrottleOutOfOrderWrites {
		ws.writeThrottleLimit = 1024
	} else {
		ws.writeThrottleLimit = math.MaxInt32
	}
	return ws
}

type http2priorityNodeState int

const (
	http2priorityNodeOpen http2priorityNodeState = iota
	http2priorityNodeClosed
	http2priorityNodeIdle
)

// priorityNode is a node in an HTTP/2 priority tree.
// Each node is associated with a single stream ID.
// See RFC 7540, Section 5.3.
type http2priorityNode struct {
	q            http2writeQueue        // queue of pending frames to write
	id           uint32                 // id of the stream, or 0 for the root of the tree
	weight       uint8                  // the actual weight is weight+1, so the value is in [1,256]
	state        http2priorityNodeState // open | closed | idle
	bytes        int64                  // number of bytes written by this node, or 0 if closed
	subtreeBytes int64                  // sum(node.bytes) of all nodes in this subtree

	// These links form the priority tree.
	parent     *http2priorityNode
	kids       *http2priorityNode // start of the kids list
	prev, next *http2priorityNode // doubly-linked list of siblings
}

func (n *http2priorityNode) setParent(parent *http2priorityNode) {
	if n == parent {
		panic("setParent to self")
	}
	if n.parent == parent {
		return
	}
	// Unlink from current parent.
	if parent := n.parent; parent != nil {
		if n.prev == nil {
			parent.kids = n.next
		} else {
			n.prev.next = n.next
		}
		if n.next != nil {
			n.next.prev = n.prev
		}
	}
	// Link to new parent.
	// If parent=nil, remove n from the tree.
	// Always insert at the head of parent.kids (this is assumed by walkReadyInOrder).
	n.parent = parent
	if parent == nil {
		n.next = nil
		n.prev = nil
	} else {
		n.next = parent.kids
		n.prev = nil
		if n.next != nil {
			n.next.prev = n
		}
		parent.kids = n
	}
}

func (n *http2priorityNode) addBytes(b int64) {
	n.bytes += b
	for ; n != nil; n = n.parent {
		n.subtreeBytes += b
	}
}

// walkReadyInOrder iterates over the tree in priority order, calling f for each node
// with a non-empty write queue. When f returns true, this function returns true and the
// walk halts. tmp is used as scratch space for sorting.
//
// f(n, openParent) takes two arguments: the node to visit, n, and a bool that is true
// if any ancestor p of n is still open (ignoring the root node).
func (n *http2priorityNode) walkReadyInOrder(openParent bool, tmp *[]*http2priorityNode, f func(*http2priorityNode, bool) bool) bool {
	if !n.q.empty() && f(n, openParent) {
		return true
	}
	if n.kids == nil {
		return false
	}

	// Don't consider the root "open" when updating openParent since
	// we can't send data frames on the root stream (only control frames).
	if n.id != 0 {
		openParent = openParent || (n.state == http2priorityNodeOpen)
	}

	// Common case: only one kid or all kids have the same weight.
	// Some clients don't use weights; other clients (like web browsers)
	// use mostly-linear priority trees.
	w := n.kids.weight
	needSort := false
	for k := n.kids.next; k != nil; k = k.next {
		if k.weight != w {
			needSort = true
			break
		}
	}
	if !needSort {
		for k := n.kids; k != nil; k = k.next {
			if k.walkReadyInOrder(openParent, tmp, f) {
				return true
			}
		}
		return false
	}

	// Uncommon case: sort the child nodes. We remove the kids from the parent,
	// then re-insert after sorting so we can reuse tmp for future sort calls.
	*tmp = (*tmp)[:0]
	for n.kids != nil {
		*tmp = append(*tmp, n.kids)
		n.kids.setParent(nil)
	}
	sort.Sort(http2sortPriorityNodeSiblings(*tmp))
	for i := len(*tmp) - 1; i >= 0; i-- {
		(*tmp)[i].setParent(n) // setParent inserts at the head of n.kids
	}
	for k := n.kids; k != nil; k = k.next {
		if k.walkReadyInOrder(openParent, tmp, f) {
			return true
		}
	}
	return false
}

type http2sortPriorityNodeSiblings []*http2priorityNode

func (z http2sortPriorityNodeSiblings) Len() int { return len(z) }

func (z http2sortPriorityNodeSiblings) Swap(i, k int) { z[i], z[k] = z[k], z[i] }

func (z http2sortPriorityNodeSiblings) Less(i, k int) bool {
	// Prefer the subtree that has sent fewer bytes relative to its weight.
	// See sections 5.3.2 and 5.3.4.
	wi, bi := float64(z[i].weight+1), float64(z[i].subtreeBytes)
	wk, bk := float64(z[k].weight+1), float64(z[k].subtreeBytes)
	if bi == 0 && bk == 0 {
		return wi >= wk
	}
	if bk == 0 {
		return false
	}
	return bi/bk <= wi/wk
}

type http2priorityWriteScheduler struct {
	// root is the root of the priority tree, where root.id = 0.
	// The root queues control frames that are not associated with any stream.
	root http2priorityNode

	// nodes maps stream ids to priority tree nodes.
	nodes map[uint32]*http2priorityNode

	// maxID is the maximum stream id in nodes.
	maxID uint32

	// lists of nodes that have been closed or are idle, but are kept in
	// the tree for improved prioritization. When the lengths exceed either
	// maxClosedNodesInTree or maxIdleNodesInTree, old nodes are discarded.
	closedNodes, idleNodes []*http2priorityNode

	// From the config.
	maxClosedNodesInTree int
	maxIdleNodesInTree   int
	writeThrottleLimit   int32
	enableWriteThrottle  bool

	// tmp is scratch space for priorityNode.walkReadyInOrder to reduce allocations.
	tmp []*http2priorityNode

	// pool of empty queues for reuse.
	queuePool http2writeQueuePool
}

func (ws *http2priorityWriteScheduler) OpenStream(streamID uint32, options http2OpenStreamOptions) {
	// The stream may be currently idle but cannot be opened or closed.
	if curr := ws.nodes[streamID]; curr != nil {
		if curr.state != http2priorityNodeIdle {
			panic(fmt.Sprintf("stream %d already opened", streamID))
		}
		curr.state = http2priorityNodeOpen
		return
	}

	// RFC 7540, Section 5.3.5:
	//  "All streams are initially assigned a non-exclusive dependency on stream 0x0.
	//  Pushed streams initially depend on their associated stream. In both cases,
	//  streams are assigned a default weight of 16."
	parent := ws.nodes[options.PusherID]
	if parent == nil {
		parent = &ws.root
	}
	n := &http2priorityNode{
		q:      *ws.queuePool.get(),
		id:     streamID,
		weight: http2priorityDefaultWeight,
		state:  http2priorityNodeOpen,
	}
	n.setParent(parent)
	ws.nodes[streamID] = n
	if streamID > ws.maxID {
		ws.maxID = streamID
	}
}

func (ws *http2priorityWriteScheduler) CloseStream(streamID uint32) {
	if streamID == 0 {
		panic("violation of WriteScheduler interface: cannot close stream 0")
	}
	if ws.nodes[streamID] == nil {
		panic(fmt.Sprintf("violation of WriteScheduler interface: unknown stream %d", streamID))
	}
	if ws.nodes[streamID].state != http2priorityNodeOpen {
		panic(fmt.Sprintf("violation of WriteScheduler interface: stream %d already closed", streamID))
	}

	n := ws.nodes[streamID]
	n.state = http2priorityNodeClosed
	n.addBytes(-n.bytes)

	q := n.q
	ws.queuePool.put(&q)
	n.q.s = nil
	if ws.maxClosedNodesInTree > 0 {
		ws.addClosedOrIdleNode(&ws.closedNodes, ws.maxClosedNodesInTree, n)
	} else {
		ws.removeNode(n)
	}
}

func (ws *http2priorityWriteScheduler) AdjustStream(streamID uint32, priority http2PriorityParam) {
	if streamID == 0 {
		panic("adjustPriority on root")
	}

	// If streamID does not exist, there are two cases:
	// - A closed stream that has been removed (this will have ID <= maxID)
	// - An idle stream that is being used for "grouping" (this will have ID > maxID)
	n := ws.nodes[streamID]
	if n == nil {
		if streamID <= ws.maxID || ws.maxIdleNodesInTree == 0 {
			return
		}
		ws.maxID = streamID
		n = &http2priorityNode{
			q:      *ws.queuePool.get(),
			id:     streamID,
			weight: http2priorityDefaultWeight,
			state:  http2priorityNodeIdle,
		}
		n.setParent(&ws.root)
		ws.nodes[streamID] = n
		ws.addClosedOrIdleNode(&ws.idleNodes, ws.maxIdleNodesInTree, n)
	}

	// Section 5.3.1: A dependency on a stream that is not currently in the tree
	// results in that stream being given a default priority (Section 5.3.5).
	parent := ws.nodes[priority.StreamDep]
	if parent == nil {
		n.setParent(&ws.root)
		n.weight = http2priorityDefaultWeight
		return
	}

	// Ignore if the client tries to make a node its own parent.
	if n == parent {
		return
	}

	// Section 5.3.3:
	//   "If a stream is made dependent on one of its own dependencies, the
	//   formerly dependent stream is first moved to be dependent on the
	//   reprioritized stream's previous parent. The moved dependency retains
	//   its weight."
	//
	// That is: if parent depends on n, move parent to depend on n.parent.
	for x := parent.parent; x != nil; x = x.parent {
		if x == n {
			parent.setParent(n.parent)
			break
		}
	}

	// Section 5.3.3: The exclusive flag causes the stream to become the sole
	// dependency of its parent stream, causing other dependencies to become
	// dependent on the exclusive stream.
	if priority.Exclusive {
		k := parent.kids
		for k != nil {
			next := k.next
			if k != n {
				k.setParent(n)
			}
			k = next
		}
	}

	n.setParent(parent)
	n.weight = priority.Weight
}

func (ws *http2priorityWriteScheduler) Push(wr http2FrameWriteRequest) {
	var n *http2priorityNode
	if wr.isControl() {
		n = &ws.root
	} else {
		id := wr.StreamID()
		n = ws.nodes[id]
		if n == nil {
			// id is an idle or closed stream. wr should not be a HEADERS or
			// DATA frame. In other case, we push wr onto the root, rather
			// than creating a new priorityNode.
			if wr.DataSize() > 0 {
				panic("add DATA on non-open stream")
			}
			n = &ws.root
		}
	}
	n.q.push(wr)
}

func (ws *http2priorityWriteScheduler) Pop() (wr http2FrameWriteRequest, ok bool) {
	ws.root.walkReadyInOrder(false, &ws.tmp, func(n *http2priorityNode, openParent bool) bool {
		limit := int32(math.MaxInt32)
		if openParent {
			limit = ws.writeThrottleLimit
		}
		wr, ok = n.q.consume(limit)
		if !ok {
			return false
		}
		n.addBytes(int64(wr.DataSize()))
		// If B depends on A and B continuously has data available but A
		// does not, gradually increase the throttling limit to allow B to
		// steal more and more bandwidth from A.
		if openParent {
			ws.writeThrottleLimit += 1024
			if ws.writeThrottleLimit < 0 {
				ws.writeThrottleLimit = math.MaxInt32
			}
		} else if ws.enableWriteThrottle {
			ws.writeThrottleLimit = 1024
		}
		return true
	})
	return wr, ok
}

func (ws *http2priorityWriteScheduler) addClosedOrIdleNode(list *[]*http2priorityNode, maxSize int, n *http2priorityNode) {
	if maxSize == 0 {
		return
	}
	if len(*list) == maxSize {
		// Remove the oldest node, then shift left.
		ws.removeNode((*list)[0])
		x := (*list)[1:]
		copy(*list, x)
		*list = (*list)[:len(x)]
	}
	*list = append(*list, n)
}

func (ws *http2priorityWriteScheduler) removeNode(n *http2priorityNode) {
	for n.kids != nil {
		n.kids.setParent(n.parent)
	}
	n.setParent(nil)
	delete(ws.nodes, n.id)
}

// NewRandomWriteScheduler constructs a WriteScheduler that ignores HTTP/2
// priorities. Control frames like SETTINGS and PING are written before DATA
// frames, but if no control frames are queued and multiple streams have queued
// HEADERS or DATA frames, Pop selects a ready stream arbitrarily.
func http2NewRandomWriteScheduler() http2WriteScheduler {
	return &http2randomWriteScheduler{sq: make(map[uint32]*http2writeQueue)}
}

type http2randomWriteScheduler struct {
	// zero are frames not associated with a specific stream.
	zero http2writeQueue

	// sq contains the stream-specific queues, keyed by stream ID.
	// When a stream is idle, closed, or emptied, it's deleted
	// from the map.
	sq map[uint32]*http2writeQueue

	// pool of empty queues for reuse.
	queuePool http2writeQueuePool
}

func (ws *http2randomWriteScheduler) OpenStream(streamID uint32, options http2OpenStreamOptions) {
	// no-op: idle streams are not tracked
}

func (ws *http2randomWriteScheduler) CloseStream(streamID uint32) {
	q, ok := ws.sq[streamID]
	if !ok {
		return
	}
	delete(ws.sq, streamID)
	ws.queuePool.put(q)
}

func (ws *http2randomWriteScheduler) AdjustStream(streamID uint32, priority http2PriorityParam) {
	// no-op: priorities are ignored
}

func (ws *http2randomWriteScheduler) Push(wr http2FrameWriteRequest) {
	if wr.isControl() {
		ws.zero.push(wr)
		return
	}
	id := wr.StreamID()
	q, ok := ws.sq[id]
	if !ok {
		q = ws.queuePool.get()
		ws.sq[id] = q
	}
	q.push(wr)
}

func (ws *http2randomWriteScheduler) Pop() (http2FrameWriteRequest, bool) {
	// Control and RST_STREAM frames first.
	if !ws.zero.empty() {
		return ws.zero.shift(), true
	}
	// Iterate over all non-idle streams until finding one that can be consumed.
	for streamID, q := range ws.sq {
		if wr, ok := q.consume(math.MaxInt32); ok {
			if q.empty() {
				delete(ws.sq, streamID)
				ws.queuePool.put(q)
			}
			return wr, true
		}
	}
	return http2FrameWriteRequest{}, false
}

type http2roundRobinWriteScheduler struct {
	// control contains control frames (SETTINGS, PING, etc.).
	control http2writeQueue

	// streams maps stream ID to a queue.
	streams map[uint32]*http2writeQueue

	// stream queues are stored in a circular linked list.
	// head is the next stream to write, or nil if there are no streams open.
	head *http2writeQueue

	// pool of empty queues for reuse.
	queuePool http2writeQueuePool
}

// newRoundRobinWriteScheduler constructs a new write scheduler.
// The round robin scheduler priorizes control frames
// like SETTINGS and PING over DATA frames.
// When there are no control frames to send, it performs a round-robin
// selection from the ready streams.
func http2newRoundRobinWriteScheduler() http2WriteScheduler {
	ws := &http2roundRobinWriteScheduler{
		streams: make(map[uint32]*http2writeQueue),
	}
	return ws
}

func (ws *http2roundRobinWriteScheduler) OpenStream(streamID uint32, options http2OpenStreamOptions) {
	if ws.streams[streamID] != nil {
		panic(fmt.Errorf("stream %d already opened", streamID))
	}
	q := ws.queuePool.get()
	ws.streams[streamID] = q
	if ws.head == nil {
		ws.head = q
		q.next = q
		q.prev = q
	} else {
		// Queues are stored in a ring.
		// Insert the new stream before ws.head, putting it at the end of the list.
		q.prev = ws.head.prev
		q.next = ws.head
		q.prev.next = q
		q.next.prev = q
	}
}

func (ws *http2roundRobinWriteScheduler) CloseStream(streamID uint32) {
	q := ws.streams[streamID]
	if q == nil {
		return
	}
	if q.next == q {
		// This was the only open stream.
		ws.head = nil
	} else {
		q.prev.next = q.next
		q.next.prev = q.prev
		if ws.head == q {
			ws.head = q.next
		}
	}
	delete(ws.streams, streamID)
	ws.queuePool.put(q)
}

func (ws *http2roundRobinWriteScheduler) AdjustStream(streamID uint32, priority http2PriorityParam) {}

func (ws *http2roundRobinWriteScheduler) Push(wr http2FrameWriteRequest) {
	if wr.isControl() {
		ws.control.push(wr)
		return
	}
	q := ws.streams[wr.StreamID()]
	if q == nil {
		// This is a closed stream.
		// wr should not be a HEADERS or DATA frame.
		// We push the request onto the control queue.
		if wr.DataSize() > 0 {
			panic("add DATA on non-open stream")
		}
		ws.control.push(wr)
		return
	}
	q.push(wr)
}

func (ws *http2roundRobinWriteScheduler) Pop() (http2FrameWriteRequest, bool) {
	// Control and RST_STREAM fra
"""




```