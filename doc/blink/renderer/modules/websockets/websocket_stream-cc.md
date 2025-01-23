Response:
Let's break down the thought process for analyzing this `websocket_stream.cc` file.

1. **Initial Understanding - The Big Picture:**  The file name `websocket_stream.cc` immediately suggests it's related to the WebSockets API within the Blink rendering engine. The `stream` part hints at the Streams API integration. The copyright notice confirms it's part of Chromium.

2. **Core Functionality - What does it *do*?:** The primary goal is to implement the `WebSocketStream` interface. This interface likely provides a way to interact with WebSockets using the WHATWG Streams API (ReadableStream and WritableStream). This means it needs to handle sending and receiving data, opening, closing, and error handling.

3. **Key Components - Identifying the Building Blocks:**  A quick scan reveals important classes:
    * `WebSocketStream`: The main class.
    * `UnderlyingSource`:  Provides data *from* the WebSocket to the ReadableStream.
    * `UnderlyingSink`:  Sends data *to* the WebSocket from the WritableStream.
    * `WebSocketChannelImpl`: Likely the lower-level communication channel.
    *  Promises (`ScriptPromise`, `ScriptPromiseResolver`): Used for asynchronous operations.
    *  Various data structures (`DOMArrayBuffer`, `DOMArrayBufferView`, `String`).

4. **Data Flow - How does information move?:**  The Streams API implies a producer-consumer relationship.
    * **Receiving:**  `WebSocketChannelImpl` receives data from the network. This data is then passed to `UnderlyingSource`'s `DidReceiveTextMessage` or `DidReceiveBinaryMessage` methods. These methods enqueue the data into the ReadableStream's controller. JavaScript can then read from this ReadableStream.
    * **Sending:** JavaScript writes data to the WritableStream. This triggers `UnderlyingSink`'s `write` method. This method takes the data and sends it to `WebSocketChannelImpl`.

5. **Connections to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** This is the primary interface. The `WebSocketStream` class will be exposed to JavaScript. The example usage demonstrates the instantiation and interaction with the `opened` and `closed` promises, as well as the readable and writable streams.
    * **HTML:** While this specific file doesn't *directly* interact with HTML, the WebSocket API itself is used within HTML documents via JavaScript. The `<script>` tag is where the relevant JavaScript code would reside.
    * **CSS:** No direct relationship with CSS. WebSockets are about data transfer, not presentation.

6. **Logic and Reasoning -  Following the Code Paths:**
    * **Opening:** `CreateInternal` sets up the `WebSocketChannelImpl` and calls `Connect`. The `DidConnect` method handles the successful connection, creates the Readable and Writable Streams, and resolves the `opened` promise.
    * **Sending Data:** The `UnderlyingSink::write` method handles both string and binary data. It uses `WebSocketChannelImpl::Send`. The use of promises ensures asynchronous handling of sends.
    * **Receiving Data:**  The `UnderlyingSource::DidReceiveTextMessage` and `DidReceiveBinaryMessage` methods enqueue data into the ReadableStream.
    * **Closing:** The `close` method in `WebSocketStream` triggers the closing handshake. The `DidClose` method in both `UnderlyingSource` and `UnderlyingSink` handles the stream closure. The `closed` promise is resolved or rejected based on whether the closure was clean.
    * **Error Handling:**  Methods like `CloseWithError` are used to signal errors to the streams. The `closed` promise can be rejected in error scenarios.

7. **User and Programming Errors:**  Think about common mistakes developers make when using WebSockets:
    * Not waiting for the `opened` promise before sending.
    * Trying to send data after the socket is closed.
    * Not handling the `closed` promise rejection (for unclean closures).
    * Aborting the connection prematurely.

8. **Debugging Clues - Tracing User Actions:** Imagine a user clicking a button that initiates a WebSocket connection:
    1. User interacts with the UI (e.g., clicks a button).
    2. JavaScript event handler is triggered.
    3. JavaScript code creates a `WebSocketStream` object. This will call `WebSocketStream::Create`.
    4. `WebSocketStream::CreateInternal` is invoked, creating the `WebSocketChannelImpl`.
    5. `WebSocketStream::Connect` is called, initiating the connection handshake.
    6. Network communication happens via `WebSocketChannelImpl`.
    7. If the connection succeeds, `WebSocketStream::DidConnect` is called.
    8. If data is received, `WebSocketStream::DidReceiveTextMessage` or `DidReceiveBinaryMessage` are called.
    9. If the user (or server) closes the connection, `WebSocketStream::DidClose` is called.

9. **Refinement and Organization:**  Structure the analysis logically, starting with the high-level overview and then diving into specifics. Use clear headings and examples. Ensure all parts of the prompt are addressed.

Self-Correction/Refinement during the thought process:

* **Initial thought:** Maybe the file directly handles network sockets. **Correction:**  It seems to delegate the low-level socket handling to `WebSocketChannelImpl`. This makes sense for separation of concerns.
* **Initial thought:**  The Streams API might be complex to integrate. **Realization:** The `UnderlyingSource` and `UnderlyingSink` classes abstract away much of the Streams API complexity from the main `WebSocketStream` logic.
* **Double-checking:**  Ensure each requirement of the prompt is explicitly addressed (functionality, JavaScript/HTML/CSS relation, logic/reasoning, errors, debugging).

By following these steps, we can systematically analyze the code and provide a comprehensive and accurate explanation of its functionality.
好的，让我们详细分析一下 `blink/renderer/modules/websockets/websocket_stream.cc` 这个文件。

**文件功能概述**

`websocket_stream.cc` 文件实现了 Chromium Blink 引擎中 `WebSocketStream` 接口的功能。 `WebSocketStream` 是一个 JavaScript API，它提供了一种使用 WHATWG Streams API (ReadableStream 和 WritableStream) 来操作 WebSocket 连接的方式。 简单来说，它将传统的基于事件的 WebSocket API 转换为了基于流的 API，允许开发者以更灵活的方式处理 WebSocket 的数据流。

**与 JavaScript, HTML, CSS 的关系及举例说明**

* **JavaScript:**  `WebSocketStream` 是一个 JavaScript 可访问的 API。开发者可以使用 JavaScript 代码来创建、操作 `WebSocketStream` 对象，并利用其提供的 `readable` 和 `writable` 属性访问底层的流。

   **举例:**

   ```javascript
   const socketStream = new WebSocketStream('wss://example.com');

   socketStream.opened.then(async ({ readable, writable }) => {
     console.log('WebSocket connection opened!');

     // 从 readable 流读取数据
     const reader = readable.getReader();
     while (true) {
       const { done, value } = await reader.read();
       if (done) {
         break;
       }
       console.log('Received:', new TextDecoder().decode(value));
     }

     // 向 writable 流写入数据
     const writer = writable.getWriter();
     const encoder = new TextEncoder();
     await writer.write(encoder.encode('Hello from WebSocketStream!'));
     await writer.close();
   });

   socketStream.closed.then(({ code, reason }) => {
     console.log('WebSocket connection closed:', code, reason);
   });

   socketStream.closed.catch((error) => {
       console.error('WebSocket connection closed with an error:', error);
   });
   ```

* **HTML:** HTML 文件通过 `<script>` 标签引入 JavaScript 代码，从而可以使用 `WebSocketStream` API。

   **举例:**

   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <title>WebSocketStream Example</title>
   </head>
   <body>
     <script>
       // 上面的 JavaScript 代码可以放在这里
     </script>
   </body>
   </html>
   ```

* **CSS:** CSS 与 `WebSocketStream` 没有直接的功能关系。CSS 负责页面的样式和布局，而 `WebSocketStream` 负责网络通信。

**逻辑推理及假设输入与输出**

假设我们有以下 JavaScript 代码：

```javascript
const socketStream = new WebSocketStream('wss://echo.websocket.events');
const encoder = new TextEncoder();
const decoder = new TextDecoder();

socketStream.opened.then(async ({ readable, writable }) => {
  const writer = writable.getWriter();
  writer.write(encoder.encode('Hello'));
  writer.close();

  const reader = readable.getReader();
  const { value, done } = await reader.read();
  if (!done) {
    console.log('Received:', decoder.decode(value));
  }
});
```

**假设输入:**

1. 用户在浏览器中打开包含上述 JavaScript 代码的 HTML 页面。
2. WebSocket 服务器 `wss://echo.websocket.events` 运行正常，能够接收并回显消息。

**逻辑推理过程 (对应 `websocket_stream.cc` 中的部分功能):**

1. **`WebSocketStream::Create` 或 `WebSocketStream::CreateInternal`:**  当 JavaScript 创建 `new WebSocketStream(...)` 时，Blink 会调用 `WebSocketStream::Create` 或 `WebSocketStream::CreateInternal` 来创建 C++ 层的 `WebSocketStream` 对象，并建立与服务器的连接。
2. **`WebSocketStream::Connect`:**  此方法会处理连接握手，并监听连接结果。如果 `options` 中有 `signal` 属性 (用于 `AbortSignal`)，也会设置相应的取消操作。
3. **`WebSocketStream::DidConnect`:** 当连接成功建立后，`WebSocketChannelImpl` 会回调 `WebSocketStream::DidConnect`。此方法会创建 `UnderlyingSource` 和 `UnderlyingSink` 对象，以及对应的 `ReadableStream` 和 `WritableStream`，并将它们通过 `WebSocketOpenInfo` 传递给 JavaScript 的 `opened` promise。
4. **`WebSocketStream::UnderlyingSink::write` 和 `WebSocketChannelImpl::Send`:** 当 JavaScript 调用 `writer.write(...)` 时，数据会传递到 `UnderlyingSink::write` 方法。该方法会将数据（可能是 `ArrayBuffer` 或字符串）通过 `WebSocketChannelImpl::Send` 发送到 WebSocket 服务器。
5. **`WebSocketStream::UnderlyingSource::DidReceiveTextMessage` 或 `WebSocketStream::UnderlyingSource::DidReceiveBinaryMessage`:** 当服务器发送消息时，`WebSocketChannelImpl` 会根据消息类型调用 `UnderlyingSource` 相应的 `DidReceive...` 方法。这些方法会将接收到的数据放入 `ReadableStream` 的队列中。
6. **`WebSocketStream::UnderlyingSource::Pull`:**  当 JavaScript 调用 `reader.read()` 时，`ReadableStream` 可能会调用 `UnderlyingSource::Pull` 来请求更多数据。
7. **`WebSocketStream::DidClose`:** 当连接关闭时（无论是客户端发起还是服务器发起），`WebSocketChannelImpl` 会回调 `WebSocketStream::DidClose`，并根据关闭状态（是否干净关闭）来处理 `closed` promise 的 resolve 或 reject。

**假设输出:**

如果一切顺利，控制台会输出：

```
Received: Hello
```

**用户或编程常见的使用错误及举例说明**

1. **尝试在连接打开之前发送数据:**

   ```javascript
   const socketStream = new WebSocketStream('wss://example.com');
   const writer = socketStream.writable.getWriter(); // 错误：writable 在 opened promise resolve 后才可用
   writer.write(new TextEncoder().encode('Hello'));
   ```

   **错误说明:**  `writable` 属性在 `opened` promise resolve 之前是不可用的。用户应该等待连接建立成功后再操作 `readable` 和 `writable` 流。

2. **没有正确处理 `closed` promise 的 rejection:**

   ```javascript
   const socketStream = new WebSocketStream('wss://example.com');
   socketStream.closed.then(({ code, reason }) => {
     console.log('Closed:', code, reason);
   });
   // 如果连接因错误关闭，这里没有处理 rejection，可能会导致 unhandled promise rejection 警告。
   ```

   **错误说明:** WebSocket 连接可能因各种原因非正常关闭。开发者应该使用 `.catch()` 或在 `.then()` 中提供第二个回调函数来处理 `closed` promise 的 rejection，以便了解错误原因并进行相应的处理。

3. **在流关闭后尝试写入数据:**

   ```javascript
   const socketStream = new WebSocketStream('wss://example.com');
   socketStream.opened.then(async ({ writable }) => {
     const writer = writable.getWriter();
     await writer.close();
     await writer.write(new TextEncoder().encode('Trying to write after close')); // 错误
   });
   ```

   **错误说明:**  一旦 `WritableStream` 关闭，尝试向其写入数据会抛出异常。

**用户操作如何一步步到达这里 (作为调试线索)**

假设用户在浏览器中访问了一个网页，该网页使用 `WebSocketStream` 与服务器进行通信。以下是用户操作可能触发 `websocket_stream.cc` 中代码执行的步骤：

1. **用户在网页中执行了 JavaScript 代码，创建了一个 `WebSocketStream` 对象:**  例如 `const socketStream = new WebSocketStream('wss://example.com');` 这会导致调用 `WebSocketStream::Create` 或 `WebSocketStream::CreateInternal`。
2. **如果构造函数中提供了 `AbortSignal`，并且该信号已触发:**  `WebSocketStream::Connect` 中会检查 `AbortSignal` 的状态，如果已中止，会立即 reject `opened` 和 `closed` promises。
3. **Blink 引擎开始尝试建立 WebSocket 连接:**  `WebSocketStream::Connect` 方法会调用底层的 `WebSocketChannelImpl` 来发起连接。
4. **连接成功建立:**  服务器响应握手请求，`WebSocketChannelImpl` 会回调 `WebSocketStream::DidConnect`。
5. **网页 JavaScript 代码通过 `writable` 流发送数据:**  例如 `writer.write(...)` 会最终调用到 `WebSocketStream::UnderlyingSink::write`，然后通过 `WebSocketChannelImpl::Send` 发送数据。
6. **服务器向客户端发送数据:**  `WebSocketChannelImpl` 接收到数据后，会根据数据类型调用 `WebSocketStream::UnderlyingSource::DidReceiveTextMessage` 或 `DidReceiveBinaryMessage`。
7. **网页 JavaScript 代码通过 `readable` 流读取数据:**  例如 `reader.read()` 可能会触发 `WebSocketStream::UnderlyingSource::Pull` 来请求更多数据。
8. **网页 JavaScript 代码调用 `socketStream.close()` 或服务器主动关闭连接:**  这会导致 `WebSocketStream::close` 或 `WebSocketStream::DidClose` 被调用，开始关闭握手过程。
9. **如果连接过程中发生错误:**  例如网络错误、服务器拒绝连接等，`WebSocketChannelImpl` 会回调 `WebSocketStream::DidError` (虽然此方法在 `WebSocketStream` 中目前是空的，但底层可能会有相关处理) 和 `WebSocketStream::DidClose` 并传递错误信息。

**总结**

`blink/renderer/modules/websockets/websocket_stream.cc` 是 Chromium Blink 引擎中实现 `WebSocketStream` API 的核心文件。它负责管理 WebSocket 连接的生命周期，处理数据的发送和接收，并与 JavaScript 的 Streams API 进行集成。理解这个文件的功能对于深入了解浏览器如何处理 WebSocket 连接以及如何调试相关的 Web 应用至关重要。

### 提示词
```
这是目录为blink/renderer/modules/websockets/websocket_stream.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/websockets/websocket_stream.h"

#include <memory>
#include <string>
#include <utility>

#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_websocket_close_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_websocket_error.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_websocket_open_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_websocket_stream_options.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/core/streams/underlying_sink_base.h"
#include "third_party/blink/renderer/core/streams/underlying_source_base.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/modules/websockets/websocket_channel_impl.h"
#include "third_party/blink/renderer/modules/websockets/websocket_error.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

// This is used in several places, so use a constant to avoid typos.
constexpr char kWebSocketNotCleanlyClosedErrorMessage[] =
    "WebSocket was not cleanly closed.";

}  // namespace

class WebSocketStream::UnderlyingSource final : public UnderlyingSourceBase {
 public:
  UnderlyingSource(ScriptState* script_state, WebSocketStream* creator)
      : UnderlyingSourceBase(script_state), creator_(creator) {}

  // UnderlyingSourceBase implementation.
  ScriptPromise<IDLUndefined> Pull(ScriptState*, ExceptionState&) override;
  ScriptPromise<IDLUndefined> Cancel(ScriptState*,
                                     ScriptValue reason,
                                     ExceptionState&) override;

  // API for WebSocketStream.
  void DidReceiveTextMessage(const String&);
  void DidReceiveBinaryMessage(const Vector<base::span<const char>>&);
  void DidStartClosingHandshake();
  void DidCloseCleanly(uint16_t code, const String& reason);
  void CloseWithError(v8::Local<v8::Value> error);

  void Trace(Visitor* visitor) const override {
    visitor->Trace(creator_);
    UnderlyingSourceBase::Trace(visitor);
  }

 private:
  Member<WebSocketStream> creator_;
  bool closed_ = false;
};

class WebSocketStream::UnderlyingSink final : public UnderlyingSinkBase {
 public:
  explicit UnderlyingSink(WebSocketStream* creator) : creator_(creator) {}

  // UnderlyingSinkBase implementation.
  ScriptPromise<IDLUndefined> start(ScriptState*,
                                    WritableStreamDefaultController*,
                                    ExceptionState&) override;
  ScriptPromise<IDLUndefined> write(ScriptState*,
                                    ScriptValue chunk,
                                    WritableStreamDefaultController*,
                                    ExceptionState&) override;
  ScriptPromise<IDLUndefined> close(ScriptState*, ExceptionState&) override;
  ScriptPromise<IDLUndefined> abort(ScriptState*,
                                    ScriptValue reason,
                                    ExceptionState&) override;

  // API for WebSocketStream.
  void DidStartClosingHandshake();
  void DidCloseCleanly(uint16_t code, const String& reason);
  void CloseWithError(v8::Local<v8::Value> error);
  bool AllDataHasBeenConsumed() { return !is_writing_; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(creator_);
    visitor->Trace(close_resolver_);
    UnderlyingSinkBase::Trace(visitor);
  }

 private:
  void ErrorControllerBecauseClosed();
  void FinishWriteCallback(ScriptPromiseResolver<IDLUndefined>*);
  void ResolveClose(bool was_clean);
  void SendArrayBuffer(ScriptState*,
                       DOMArrayBuffer*,
                       size_t offset,
                       size_t length,
                       ScriptPromiseResolver<IDLUndefined>*,
                       base::OnceClosure callback);
  void SendString(ScriptState*,
                  v8::Local<v8::Value> v8chunk,
                  ScriptPromiseResolver<IDLUndefined>*,
                  base::OnceClosure callback);

  Member<WebSocketStream> creator_;
  Member<ScriptPromiseResolver<IDLUndefined>> close_resolver_;
  bool closed_ = false;
  bool is_writing_ = false;
};

ScriptPromise<IDLUndefined> WebSocketStream::UnderlyingSource::Pull(
    ScriptState* script_state,
    ExceptionState&) {
  DVLOG(1) << "WebSocketStream::UnderlyingSource " << this << " Pull()";
  creator_->channel_->RemoveBackpressure();
  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<IDLUndefined> WebSocketStream::UnderlyingSource::Cancel(
    ScriptState* script_state,
    ScriptValue reason,
    ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream::UnderlyingSource " << this << " Cancel()";
  closed_ = true;
  creator_->CloseMaybeWithReason(reason, exception_state);
  return ToResolvedUndefinedPromise(script_state);
}

void WebSocketStream::UnderlyingSource::DidReceiveTextMessage(
    const String& string) {
  DVLOG(1) << "WebSocketStream::UnderlyingSource " << this
           << " DidReceiveTextMessage() string=" << string;

  DCHECK(!closed_);
  Controller()->Enqueue(
      V8String(creator_->script_state_->GetIsolate(), string));
  creator_->channel_->ApplyBackpressure();
}

void WebSocketStream::UnderlyingSource::DidReceiveBinaryMessage(
    const Vector<base::span<const char>>& data) {
  DVLOG(1) << "WebSocketStream::UnderlyingSource " << this
           << " DidReceiveBinaryMessage()";

  DCHECK(!closed_);
  auto* buffer = DOMArrayBuffer::Create(data);
  Controller()->Enqueue(buffer);
  creator_->channel_->ApplyBackpressure();
}

void WebSocketStream::UnderlyingSource::DidStartClosingHandshake() {
  DVLOG(1) << "WebSocketStream::UnderlyingSource " << this
           << " DidStartClosingHandshake()";

  DCHECK(!closed_);
  Controller()->Close();
  closed_ = true;
}

void WebSocketStream::UnderlyingSource::DidCloseCleanly(uint16_t code,
                                                        const String& reason) {
  DVLOG(1) << "WebSocketStream::UnderlyingSource " << this
           << " DidCloseCleanly() code=" << code << " reason=" << reason;

  if (closed_)
    return;

  closed_ = true;
  Controller()->Close();
}

void WebSocketStream::UnderlyingSource::CloseWithError(
    v8::Local<v8::Value> error) {
  DVLOG(1) << "WebSocketStream::UnderlyingSource::CloseWithError";
  if (closed_) {
    return;
  }

  closed_ = true;

  Controller()->Error(error);
}

ScriptPromise<IDLUndefined> WebSocketStream::UnderlyingSink::start(
    ScriptState* script_state,
    WritableStreamDefaultController*,
    ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream::UnderlyingSink " << this << " start()";
  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<IDLUndefined> WebSocketStream::UnderlyingSink::write(
    ScriptState* script_state,
    ScriptValue chunk,
    WritableStreamDefaultController*,
    ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream::UnderlyingSink " << this << " write()";
  is_writing_ = true;

  v8::Local<v8::Value> v8chunk = chunk.V8Value();
  auto* isolate = script_state->GetIsolate();
  DOMArrayBuffer* data = nullptr;
  size_t offset = 0;
  size_t length = 0;
  if (v8chunk->IsArrayBuffer()) {
    data = NativeValueTraits<DOMArrayBuffer>::NativeValue(isolate, v8chunk,
                                                          exception_state);
    if (exception_state.HadException()) {
      closed_ = true;
      is_writing_ = false;
      return EmptyPromise();
    }
    length = data->ByteLength();
  } else if (v8chunk->IsArrayBufferView()) {
    NotShared<DOMArrayBufferView> data_view =
        NativeValueTraits<NotShared<DOMArrayBufferView>>::NativeValue(
            isolate, v8chunk, exception_state);
    if (exception_state.HadException()) {
      closed_ = true;
      is_writing_ = false;
      return EmptyPromise();
    }
    data = data_view->buffer();
    offset = data_view->byteOffset();
    length = data_view->byteLength();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();
  base::OnceClosure callback =
      WTF::BindOnce(&UnderlyingSink::FinishWriteCallback,
                    WrapWeakPersistent(this), WrapPersistent(resolver));
  if (data) {
    SendArrayBuffer(script_state, data, offset, length, resolver,
                    std::move(callback));
  } else {
    SendString(script_state, v8chunk, resolver, std::move(callback));
  }
  return result;
}

ScriptPromise<IDLUndefined> WebSocketStream::UnderlyingSink::close(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream::UnderlyingSink " << this << " close()";
  closed_ = true;
  creator_->CloseWithUnspecifiedCode(exception_state);
  DCHECK(!close_resolver_);
  close_resolver_ = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  return close_resolver_->Promise();
}

ScriptPromise<IDLUndefined> WebSocketStream::UnderlyingSink::abort(
    ScriptState* script_state,
    ScriptValue reason,
    ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream::UnderlyingSink " << this << " abort()";

  closed_ = true;
  creator_->CloseMaybeWithReason(reason, exception_state);
  return ToResolvedUndefinedPromise(script_state);
}

void WebSocketStream::UnderlyingSink::DidStartClosingHandshake() {
  DVLOG(1) << "WebSocketStream::UnderlyingSink " << this
           << " DidStartClosingHandshake()";

  if (closed_)
    return;
  closed_ = true;

  ErrorControllerBecauseClosed();
}

void WebSocketStream::UnderlyingSink::DidCloseCleanly(uint16_t code,
                                                      const String& reason) {
  DVLOG(1) << "WebSocketStream::UnderlyingSink " << this
           << " DidCloseCleanly() code=" << code << " reason=" << reason;

  if (close_resolver_) {
    ResolveClose(/*was_clean=*/true);
  }

  if (closed_)
    return;
  closed_ = true;

  ErrorControllerBecauseClosed();
}

void WebSocketStream::UnderlyingSink::CloseWithError(
    v8::Local<v8::Value> error) {
  if (close_resolver_) {
    ResolveClose(/*was_clean=*/false);
  }

  if (closed_) {
    return;
  }
  closed_ = true;

  ScriptState* script_state = creator_->script_state_;
  Controller()->error(script_state,
                      ScriptValue(script_state->GetIsolate(), error));
}

void WebSocketStream::UnderlyingSink::ErrorControllerBecauseClosed() {
  ScriptState* script_state = creator_->script_state_;
  Controller()->error(
      script_state,
      ScriptValue(
          script_state->GetIsolate(),
          V8ThrowDOMException::CreateOrEmpty(
              script_state->GetIsolate(), DOMExceptionCode::kInvalidStateError,
              "Cannot write to a closed WebSocketStream")));
}

void WebSocketStream::UnderlyingSink::FinishWriteCallback(
    ScriptPromiseResolver<IDLUndefined>* resolver) {
  DVLOG(1) << "WebSocketStream::UnderlyingSink " << this
           << " FinishWriteCallback()";

  resolver->Resolve();
  is_writing_ = false;
}

void WebSocketStream::UnderlyingSink::ResolveClose(bool was_clean) {
  DCHECK(close_resolver_);

  if (was_clean) {
    close_resolver_->Resolve();
    return;
  }

  close_resolver_->Reject(
      creator_->CreateWebSocketError(kWebSocketNotCleanlyClosedErrorMessage));
}

void WebSocketStream::UnderlyingSink::SendArrayBuffer(
    ScriptState* script_state,
    DOMArrayBuffer* buffer,
    size_t offset,
    size_t length,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    base::OnceClosure callback) {
  DVLOG(1) << "WebSocketStream::UnderlyingSink " << this
           << " SendArrayBuffer() buffer = " << buffer << " offset = " << offset
           << " length = " << length;

  if (creator_->channel_->Send(*buffer, offset, length, std::move(callback)) ==
      WebSocketChannel::SendResult::kSentSynchronously) {
    is_writing_ = false;
    resolver->Resolve();
  }
}

void WebSocketStream::UnderlyingSink::SendString(
    ScriptState* script_state,
    v8::Local<v8::Value> v8chunk,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    base::OnceClosure callback) {
  DVLOG(1) << "WebSocketStream::UnderlyingSink " << this << " SendString()";
  auto* isolate = script_state->GetIsolate();
  v8::TryCatch try_catch(isolate);
  v8::Local<v8::String> string_chunk;
  if (!v8chunk->ToString(script_state->GetContext()).ToLocal(&string_chunk)) {
    closed_ = true;
    resolver->Reject(try_catch.Exception());
    is_writing_ = false;
    return;
  }
  // Skip one string copy by using v8::String UTF8 conversion instead of going
  // via WTF::String.
  size_t utf8_length = string_chunk->Utf8LengthV2(isolate);
  std::string message(utf8_length, '\0');
  size_t written_length =
      string_chunk->WriteUtf8V2(isolate, message.data(), utf8_length,
                                v8::String::WriteFlags::kReplaceInvalidUtf8);
  DCHECK_EQ(utf8_length, written_length);
  if (creator_->channel_->Send(message, std::move(callback)) ==
      WebSocketChannel::SendResult::kSentSynchronously) {
    is_writing_ = false;
    resolver->Resolve();
  }
}

WebSocketStream* WebSocketStream::Create(ScriptState* script_state,
                                         const String& url,
                                         WebSocketStreamOptions* options,
                                         ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream Create() url=" << url << " options=" << options;
  return CreateInternal(script_state, url, options, nullptr, exception_state);
}

WebSocketStream* WebSocketStream::CreateForTesting(
    ScriptState* script_state,
    const String& url,
    WebSocketStreamOptions* options,
    WebSocketChannel* channel,
    ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream CreateForTesting() url=" << url
           << " options=" << options << " channel=" << channel;

  DCHECK(channel) << "Don't use a real channel when testing";
  return CreateInternal(script_state, url, options, channel, exception_state);
}

WebSocketStream* WebSocketStream::CreateInternal(
    ScriptState* script_state,
    const String& url,
    WebSocketStreamOptions* options,
    WebSocketChannel* channel,
    ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream CreateInternal() url=" << url
           << " options=" << options << " channel=" << channel;

  auto* execution_context = ExecutionContext::From(script_state);
  auto* stream =
      MakeGarbageCollected<WebSocketStream>(execution_context, script_state);
  if (channel) {
    stream->channel_ = channel;
  } else {
    stream->channel_ = WebSocketChannelImpl::Create(
        execution_context, stream, CaptureSourceLocation(execution_context));
  }
  stream->Connect(script_state, url, options, exception_state);
  if (exception_state.HadException())
    return nullptr;

  return stream;
}

WebSocketStream::WebSocketStream(ExecutionContext* execution_context,
                                 ScriptState* script_state)
    : ActiveScriptWrappable<WebSocketStream>({}),
      ExecutionContextLifecycleObserver(execution_context),
      script_state_(script_state),
      opened_(MakeGarbageCollected<
              ScriptPromiseProperty<WebSocketOpenInfo, IDLAny>>(
          GetExecutionContext())),
      closed_(MakeGarbageCollected<
              ScriptPromiseProperty<WebSocketCloseInfo, IDLAny>>(
          GetExecutionContext())) {}

WebSocketStream::~WebSocketStream() = default;

ScriptPromise<WebSocketOpenInfo> WebSocketStream::opened(
    ScriptState* script_state) const {
  return opened_->Promise(script_state->World());
}

ScriptPromise<WebSocketCloseInfo> WebSocketStream::closed(
    ScriptState* script_state) const {
  return closed_->Promise(script_state->World());
}

void WebSocketStream::close(WebSocketCloseInfo* info,
                            ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream " << this << " close() info=" << info;
  CloseInternal(info->hasCloseCode() ? std::make_optional(info->closeCode())
                                     : std::nullopt,
                info->reason(), exception_state);
}

void WebSocketStream::DidConnect(const String& subprotocol,
                                 const String& extensions) {
  DVLOG(1) << "WebSocketStream " << this
           << " DidConnect() subprotocol=" << subprotocol
           << " extensions=" << extensions;

  if (!channel_)
    return;

  ScriptState::Scope scope(script_state_);
  if (common_.GetState() != WebSocketCommon::kConnecting)
    return;
  common_.SetState(WebSocketCommon::kOpen);
  was_ever_connected_ = true;
  auto* open_info = MakeGarbageCollected<WebSocketOpenInfo>();
  open_info->setProtocol(subprotocol);
  open_info->setExtensions(extensions);
  source_ = MakeGarbageCollected<UnderlyingSource>(script_state_, this);
  auto* readable = ReadableStream::CreateWithCountQueueingStrategy(
      script_state_, source_, 1);
  sink_ = MakeGarbageCollected<UnderlyingSink>(this);
  auto* writable =
      WritableStream::CreateWithCountQueueingStrategy(script_state_, sink_, 1);
  open_info->setReadable(readable);
  open_info->setWritable(writable);
  opened_->Resolve(open_info);
  abort_handle_.Clear();
}

void WebSocketStream::DidReceiveTextMessage(const String& string) {
  DVLOG(1) << "WebSocketStream " << this
           << " DidReceiveTextMessage() string=" << string;

  if (!channel_)
    return;

  ScriptState::Scope scope(script_state_);
  source_->DidReceiveTextMessage(string);
}

void WebSocketStream::DidReceiveBinaryMessage(
    const Vector<base::span<const char>>& data) {
  DVLOG(1) << "WebSocketStream " << this << " DidReceiveBinaryMessage()";
  if (!channel_)
    return;

  ScriptState::Scope scope(script_state_);
  source_->DidReceiveBinaryMessage(data);
}

void WebSocketStream::DidError() {
  // This is not useful as it is always followed by a call to DidClose().
}

void WebSocketStream::DidConsumeBufferedAmount(uint64_t consumed) {
  // This is only relevant to DOMWebSocket.
}

void WebSocketStream::DidStartClosingHandshake() {
  DVLOG(1) << "WebSocketStream " << this << " DidStartClosingHandshake()";
  if (!channel_)
    return;

  ScriptState::Scope scope(script_state_);
  common_.SetState(WebSocketCommon::kClosing);
  source_->DidStartClosingHandshake();
  sink_->DidStartClosingHandshake();
}

void WebSocketStream::DidClose(
    ClosingHandshakeCompletionStatus closing_handshake_completion,
    uint16_t code,
    const String& reason) {
  DVLOG(1) << "WebSocketStream " << this
           << " DidClose() closing_handshake_completion="
           << closing_handshake_completion << " code=" << code
           << " reason=" << reason;

  if (!channel_)
    return;

  ScriptState::Scope scope(script_state_);
  if (!was_ever_connected_) {
    opened_->Reject(ScriptValue(
        script_state_->GetIsolate(),
        CreateWebSocketError("WebSocket closed before handshake complete.")));
  }
  bool all_data_was_consumed = sink_ ? sink_->AllDataHasBeenConsumed() : true;
  bool was_clean = common_.GetState() == WebSocketCommon::kClosing &&
                   all_data_was_consumed &&
                   closing_handshake_completion == kClosingHandshakeComplete &&
                   code != WebSocketChannel::kCloseEventCodeAbnormalClosure;
  common_.SetState(WebSocketCommon::kClosed);

  channel_->Disconnect();
  channel_ = nullptr;
  abort_handle_.Clear();
  if (was_clean) {
    if (source_) {
      source_->DidCloseCleanly(code, reason);
    }
    if (sink_) {
      sink_->DidCloseCleanly(code, reason);
    }
    closed_->Resolve(MakeCloseInfo(code, reason));
  } else {
    auto error = CreateWebSocketError(kWebSocketNotCleanlyClosedErrorMessage,
                                      code, reason);
    if (source_) {
      source_->CloseWithError(error);
    }
    if (sink_) {
      sink_->CloseWithError(error);
    }
    closed_->Reject(ScriptValue(script_state_->GetIsolate(), error));
  }
}

void WebSocketStream::ContextDestroyed() {
  DVLOG(1) << "WebSocketStream " << this << " ContextDestroyed()";
  if (channel_) {
    channel_ = nullptr;
  }
  if (common_.GetState() != WebSocketCommon::kClosed) {
    common_.SetState(WebSocketCommon::kClosed);
  }
  abort_handle_.Clear();
}

bool WebSocketStream::HasPendingActivity() const {
  return channel_ != nullptr;
}

void WebSocketStream::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  visitor->Trace(opened_);
  visitor->Trace(closed_);
  visitor->Trace(channel_);
  visitor->Trace(source_);
  visitor->Trace(sink_);
  visitor->Trace(abort_handle_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  WebSocketChannelClient::Trace(visitor);
}

void WebSocketStream::Connect(ScriptState* script_state,
                              const String& url,
                              WebSocketStreamOptions* options,
                              ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream " << this << " Connect() url=" << url
           << " options=" << options;

  // Don't read all of a huge initial message before read() has been called.
  channel_->ApplyBackpressure();

  if (options->hasSignal()) {
    auto* signal = options->signal();
    if (signal->aborted()) {
      auto exception = V8ThrowDOMException::CreateOrEmpty(
          script_state->GetIsolate(), DOMExceptionCode::kAbortError,
          "WebSocket handshake was aborted");
      opened_->Reject(ScriptValue(script_state_->GetIsolate(), exception));
      closed_->Reject(ScriptValue(script_state_->GetIsolate(), exception));
      return;
    }

    abort_handle_ = signal->AddAlgorithm(
        WTF::BindOnce(&WebSocketStream::OnAbort, WrapWeakPersistent(this)));
  }

  auto result = common_.Connect(
      ExecutionContext::From(script_state), url,
      options->hasProtocols() ? options->protocols() : Vector<String>(),
      channel_, exception_state);

  switch (result) {
    case WebSocketCommon::ConnectResult::kSuccess:
      DCHECK(!exception_state.HadException());
      return;

    case WebSocketCommon::ConnectResult::kException:
      DCHECK(exception_state.HadException());
      channel_ = nullptr;
      return;

    case WebSocketCommon::ConnectResult::kAsyncError:
      DCHECK(!exception_state.HadException());
      auto exception = V8ThrowDOMException::CreateOrEmpty(
          script_state->GetIsolate(), DOMExceptionCode::kSecurityError,
          "An attempt was made to break through the security policy of the "
          "user agent.",
          "WebSocket mixed content check failed.");
      opened_->Reject(ScriptValue(script_state_->GetIsolate(), exception));
      closed_->Reject(ScriptValue(script_state_->GetIsolate(), exception));
      return;
  }
}

// If |maybe_reason| contains a valid code and reason, then closes with it,
// otherwise closes with unspecified code and reason.
void WebSocketStream::CloseMaybeWithReason(ScriptValue maybe_reason,
                                           ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream " << this << " CloseMaybeWithReason()";
  WebSocketError* info = V8WebSocketError::ToWrappable(
      script_state_->GetIsolate(), maybe_reason.V8Value());
  if (info) {
    CloseInternal(info->closeCode(), info->reason(), exception_state);
  } else {
    CloseWithUnspecifiedCode(exception_state);
  }
}

void WebSocketStream::CloseWithUnspecifiedCode(
    ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream " << this << " CloseWithUnspecifiedCode()";
  CloseInternal(std::nullopt, String(), exception_state);
  DCHECK(!exception_state.HadException());
}

void WebSocketStream::CloseInternal(std::optional<uint16_t> code,
                                    const String& reason,
                                    ExceptionState& exception_state) {
  DVLOG(1) << "WebSocketStream " << this
           << " CloseInternal() code=" << (code ? code.value() : uint16_t{0})
           << " reason=" << reason;

  common_.CloseInternal(code, reason, channel_, exception_state);
}

v8::Local<v8::Value> WebSocketStream::CreateWebSocketError(
    String message,
    std::optional<uint16_t> close_code,
    String reason) {
  return WebSocketError::Create(script_state_->GetIsolate(), std::move(message),
                                close_code, std::move(reason));
}

void WebSocketStream::OnAbort() {
  DVLOG(1) << "WebSocketStream " << this << " OnAbort()";

  if (was_ever_connected_ || !channel_)
    return;

  channel_->CancelHandshake();
  channel_ = nullptr;

  auto exception = V8ThrowDOMException::CreateOrEmpty(
      script_state_->GetIsolate(), DOMExceptionCode::kAbortError,
      "WebSocket handshake was aborted");
  opened_->Reject(ScriptValue(script_state_->GetIsolate(), exception));
  closed_->Reject(ScriptValue(script_state_->GetIsolate(), exception));
  abort_handle_.Clear();
}

WebSocketCloseInfo* WebSocketStream::MakeCloseInfo(uint16_t close_code,
                                                   const String& reason) {
  DVLOG(1) << "WebSocketStream MakeCloseInfo() code=" << close_code
           << " reason=" << reason;

  auto* info = MakeGarbageCollected<WebSocketCloseInfo>();
  info->setCloseCode(close_code);
  info->setReason(reason);
  return info;
}

}  // namespace blink
```