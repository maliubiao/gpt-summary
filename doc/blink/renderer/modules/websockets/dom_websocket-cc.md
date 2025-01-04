Response:
My thought process to answer the request about `dom_websocket.cc` goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of this Chromium Blink file, its relation to web technologies (JavaScript, HTML, CSS), logical reasoning, common usage errors, and how a user's action might lead to this code being executed.

2. **High-Level Analysis of the Code:**  I first scan the code for key elements:
    * **Includes:** These tell me what other parts of the system this file interacts with. I see things like `v8`, `dom`, `events`, `fileapi`, `frame`, `websockets`, `platform`, indicating this file is central to the WebSocket implementation in the browser.
    * **Class Definition (`DOMWebSocket`):** This is the main actor. It inherits from `ActiveScriptWrappable`, `ExecutionContextLifecycleStateObserver`, and `WebSocketChannelClient`. This suggests it's exposed to JavaScript, tied to the lifecycle of a document/frame, and interacts with a lower-level WebSocket implementation.
    * **Methods:** I quickly scan the public methods like `create`, `connect`, `send`, `close`, and event handlers like `DidConnect`, `DidReceiveTextMessage`, `DidError`, etc. These are strong indicators of the class's responsibilities.
    * **State Management:**  The `readyState` property and the `kConnecting`, `kOpen`, `kClosing`, `kClosed` constants suggest this class manages the connection state.
    * **Event Handling (`EventQueue`):**  The nested `EventQueue` class and the dispatching of events like `open`, `message`, `error`, and `close` are crucial.

3. **Break Down Functionality:** Based on the above, I start listing the core functions:
    * **Creating WebSocket Objects:** The `Create` methods clearly handle the instantiation of WebSocket objects from JavaScript.
    * **Establishing Connections:** The `Connect` method and interaction with `WebSocketCommon` and `CreateChannel` manage the initial handshake.
    * **Sending Data:** The overloaded `send` methods for strings, ArrayBuffers, ArrayBufferViews, and Blobs handle sending data over the socket.
    * **Closing Connections:** The `close` methods (with and without codes/reasons) manage the closing handshake.
    * **Receiving Data:** The `DidReceiveTextMessage` and `DidReceiveBinaryMessage` methods handle incoming data and dispatch `message` events.
    * **Handling Connection Events:**  `DidConnect`, `DidError`, `DidClose` manage state transitions and dispatch corresponding events.
    * **Buffering:** The `bufferedAmount` and related logic indicate handling of data waiting to be sent.
    * **Event Queuing:** The `EventQueue` manages the order and delivery of events, especially during state transitions.

4. **Relate to Web Technologies:**
    * **JavaScript:** The `DOMWebSocket` class *is* the JavaScript `WebSocket` API. The `create`, `send`, `close` methods directly correspond to JavaScript methods. Events like `open`, `message`, `error`, `close` are the JavaScript events dispatched by this class.
    * **HTML:** The `<script>` tag is the primary way JavaScript (and thus WebSocket creation) is embedded in HTML. The `document` object (mentioned in includes) is the entry point for many DOM operations, including creating `WebSocket` objects.
    * **CSS:** CSS doesn't directly interact with the *functionality* of WebSockets. However, CSS might be used to style elements based on the state of a WebSocket connection (e.g., disabling a "send" button while connecting). It's a more indirect relationship.

5. **Logical Reasoning (Hypothetical Input/Output):** I think about simple scenarios:
    * **Successful Connection:**  Input: `new WebSocket("ws://example.com")`. Output: Eventually, the `open` event is fired.
    * **Sending Text:** Input: `socket.send("hello")`. Output: The `channel_->Send` method will be called with the string "hello".
    * **Receiving Data:** Input:  The server sends a message "world". Output: The `DidReceiveTextMessage` method is called, and a `message` event with data "world" is dispatched.
    * **Error:** Input: The server rejects the connection. Output: The `DidError` method is called, and an `error` event is dispatched.

6. **Common User/Programming Errors:** I consider common mistakes when using the WebSocket API:
    * **Sending in the `CONNECTING` state:** This is explicitly checked and throws an error.
    * **Not handling errors:**  Users might forget to add an `onerror` handler.
    * **Incorrect URL:** This can lead to connection failures.
    * **Server-side issues:** While not the fault of the JavaScript code, understanding that server problems manifest as errors on the client is important.

7. **User Steps to Reach the Code (Debugging Clues):** I trace back from the JavaScript API:
    1. **User writes JavaScript:** `const socket = new WebSocket("ws://example.com");`
    2. **Browser parses and executes:** The JavaScript engine calls the `DOMWebSocket::Create` method in the Blink renderer.
    3. **Connection attempt:** `DOMWebSocket::Connect` is called, initiating the connection.
    4. **Network interaction:** Lower-level networking code (outside this file) handles the actual TCP/IP and WebSocket handshake.
    5. **Callbacks:**  When the connection succeeds or fails, methods in `DOMWebSocket` (like `DidConnect`, `DidError`) are called by the `WebSocketChannel`.
    6. **Data transfer:**  `socket.send()` calls `DOMWebSocket::send`. Incoming data triggers `DidReceiveTextMessage` or `DidReceiveBinaryMessage`.
    7. **Closure:** `socket.close()` calls `DOMWebSocket::close`.

8. **Structure and Refine:** I organize the information into the requested categories, providing clear explanations and examples. I use the code snippets and comments as supporting evidence. I also pay attention to the level of detail required for each section.

By following this process, I can effectively analyze the provided C++ code and generate a comprehensive and informative answer that addresses all aspects of the user's request. The key is to move from a high-level understanding to specific details, connecting the C++ implementation to the user-facing JavaScript API.
好的，让我们来分析一下 `blink/renderer/modules/websockets/dom_websocket.cc` 这个 Chromium Blink 引擎源代码文件。

**文件功能概览**

`dom_websocket.cc` 文件是 Chromium Blink 引擎中实现 **WebSocket API** 的核心部分。它负责处理 JavaScript 中 `WebSocket` 对象的创建、连接、数据发送与接收、关闭连接等操作。  简单来说，它桥接了 JavaScript WebSocket API 和底层的网络通信机制。

**与 JavaScript, HTML, CSS 的关系**

这个文件与 JavaScript 的关系最为密切，因为它直接实现了 JavaScript 的 `WebSocket` 接口。

* **JavaScript:**
    * **创建 WebSocket 对象:** 当 JavaScript 代码执行 `new WebSocket(url, [protocols])` 时，最终会调用到 `DOMWebSocket::Create` 方法。
        ```javascript
        // JavaScript 代码
        const websocket = new WebSocket("ws://example.com/socket", ["chat", "superchat"]);
        ```
        在这个例子中，`DOMWebSocket::Create` 会被调用，`url` 参数会是 `"ws://example.com/socket"`，`protocols` 参数会是包含 `"chat"` 和 `"superchat"` 的数组。
    * **发送数据:** JavaScript 代码调用 `websocket.send(data)` 时，会调用 `DOMWebSocket` 的 `send` 方法。`data` 可以是字符串、`ArrayBuffer`、`ArrayBufferView` 或 `Blob`。
        ```javascript
        // JavaScript 代码
        websocket.send("Hello, WebSocket!"); // 调用 DOMWebSocket::send(const String& message, ...)
        websocket.send(new ArrayBuffer(8)); // 调用 DOMWebSocket::send(DOMArrayBuffer* binary_data, ...)
        ```
    * **关闭连接:** JavaScript 代码调用 `websocket.close([code], [reason])` 时，会调用 `DOMWebSocket` 的 `close` 方法。
        ```javascript
        // JavaScript 代码
        websocket.close(1000, "Normal closure"); // 调用 DOMWebSocket::close(uint16_t code, const String& reason, ...)
        websocket.close(); // 调用 DOMWebSocket::close(ExceptionState& exception_state)
        ```
    * **事件处理:**  `DOMWebSocket` 负责触发 WebSocket 相关的事件 (如 `open`, `message`, `error`, `close`)，这些事件可以在 JavaScript 中监听和处理。例如，当连接成功建立时，`DOMWebSocket::DidConnect` 会被调用，并触发 `open` 事件。当接收到消息时，`DOMWebSocket::DidReceiveTextMessage` 或 `DOMWebSocket::DidReceiveBinaryMessage` 会被调用，并触发 `message` 事件。

* **HTML:**
    * HTML 文件通过 `<script>` 标签引入 JavaScript 代码，而这些 JavaScript 代码可能包含创建和使用 `WebSocket` 对象的逻辑。HTML 结构本身不直接与 `dom_websocket.cc` 交互，但它承载了执行 WebSocket 操作的 JavaScript 代码。

* **CSS:**
    * CSS 与 `dom_websocket.cc` 没有直接的功能关系。CSS 负责页面的样式，而 WebSocket 负责网络通信。尽管 CSS 可以用来根据 WebSocket 的状态（例如，通过 JavaScript 修改元素的 class）来改变页面元素的视觉表现，但 `dom_websocket.cc` 的核心职责与 CSS 无关。

**逻辑推理 (假设输入与输出)**

假设输入 JavaScript 代码如下：

```javascript
const ws = new WebSocket("ws://echo.websocket.events");

ws.onopen = () => {
  console.log("WebSocket connection opened");
  ws.send("Hello from client");
};

ws.onmessage = (event) => {
  console.log("Received message:", event.data);
};

ws.onerror = (error) => {
  console.error("WebSocket error:", error);
};

ws.onclose = (event) => {
  console.log("WebSocket connection closed", event);
};

// 假设一段时间后
ws.close();
```

对应的 `dom_websocket.cc` 中的函数调用与行为：

1. **`new WebSocket(...)`:**
   * **输入:** URL `"ws://echo.websocket.events"`
   * **输出:** 创建 `DOMWebSocket` 对象，调用 `DOMWebSocket::Create`，然后调用 `DOMWebSocket::Connect` 尝试建立连接。

2. **连接成功 (假设服务器响应):**
   * **输入:** 服务器响应表示连接建立成功。
   * **输出:** `DOMWebSocket::DidConnect` 被调用，设置 WebSocket 状态为 `OPEN`，触发 JavaScript 的 `onopen` 事件。

3. **`ws.send("Hello from client")`:**
   * **输入:** 字符串 `"Hello from client"`
   * **输出:** `DOMWebSocket::send(const String& message, ...)` 被调用，将消息传递给底层的 WebSocket 通道进行发送。`buffered_amount_` 会增加。

4. **接收到服务器消息 (假设服务器回显消息):**
   * **输入:** 服务器发送的消息 `"Hello from client"`。
   * **输出:** `DOMWebSocket::DidReceiveTextMessage` 被调用，创建一个 `MessageEvent` 对象，并触发 JavaScript 的 `onmessage` 事件，`event.data` 将是 `"Hello from client"`。

5. **`ws.close()`:**
   * **输入:** 无参数调用 `close()`。
   * **输出:** `DOMWebSocket::close(ExceptionState& exception_state)` 或 `DOMWebSocket::CloseInternal` 被调用，开始关闭 WebSocket 连接的握手过程。`DOMWebSocket::DidStartClosingHandshake` 可能会被调用。

6. **连接关闭:**
   * **输入:**  WebSocket 连接关闭完成。
   * **输出:** `DOMWebSocket::DidClose` 被调用，设置 WebSocket 状态为 `CLOSED`，创建一个 `CloseEvent` 对象，并触发 JavaScript 的 `onclose` 事件。

**用户或编程常见的使用错误**

1. **在 `CONNECTING` 状态下发送数据:**
   * **错误示例:**
     ```javascript
     const ws = new WebSocket("ws://example.com");
     ws.send("This might fail"); // 如果连接尚未建立完成
     ```
   * **`dom_websocket.cc` 的处理:** `send` 方法会检查 `common_.GetState()`，如果状态是 `kConnecting`，则会调用 `SetInvalidStateErrorForSendMethod` 抛出一个 JavaScript 异常。

2. **忘记添加错误处理:**
   * **错误示例:**  没有监听 `onerror` 事件，导致 WebSocket 错误发生时没有适当的处理。
   * **`dom_websocket.cc` 的处理:** 当底层 WebSocket 通道发生错误时，`DOMWebSocket::DidError` 会被调用，并触发 `error` 事件。如果没有 JavaScript 代码监听这个事件，错误信息可能不会被用户捕获。

3. **尝试在连接关闭后发送数据:**
   * **错误示例:**
     ```javascript
     const ws = new WebSocket("ws://example.com");
     ws.onclose = () => {
       ws.send("This will likely fail");
     };
     ws.close();
     ```
   * **`dom_websocket.cc` 的处理:** `send` 方法会检查 `common_.GetState()`，如果状态是 `kClosing` 或 `kClosed`，数据将不会被发送，并且 `buffered_amount_after_close_` 会增加。

4. **URL 格式错误:**
   * **错误示例:** `new WebSocket("invalid-url")`
   * **`dom_websocket.cc` 的处理:** `DOMWebSocket::Create` 会检查 URL 的有效性，如果无效会抛出 `SyntaxError` 异常。

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户在浏览一个网页，这个网页使用了 WebSocket 来进行实时通信：

1. **用户打开网页:** 浏览器加载 HTML、CSS 和 JavaScript 代码。
2. **JavaScript 执行:** 网页的 JavaScript 代码被执行，其中包含了创建 `WebSocket` 对象的代码：
   ```javascript
   const socket = new WebSocket("wss://realtime-service.com/updates");
   ```
   这会触发 `dom_websocket.cc` 中的 `DOMWebSocket::Create` 方法。
3. **连接尝试:** `DOMWebSocket::Connect` 方法被调用，开始与 `"wss://realtime-service.com/updates"` 服务器建立连接。
4. **连接建立成功:** 如果连接成功，底层的网络通信模块会通知 `DOMWebSocket` 对象，`DOMWebSocket::DidConnect` 被调用，触发 JavaScript 的 `onopen` 事件。
5. **用户触发发送消息的操作:**  用户在网页上点击一个发送按钮或者输入文本并提交，JavaScript 代码调用 `socket.send()` 发送数据。这会触发 `dom_websocket.cc` 中的 `send` 方法。
6. **服务器发送消息:** 服务器向客户端发送数据，底层的网络模块接收到数据后，会调用 `DOMWebSocket::DidReceiveTextMessage` 或 `DOMWebSocket::DidReceiveBinaryMessage`，触发 JavaScript 的 `onmessage` 事件。
7. **用户关闭页面或触发关闭连接:** 用户关闭浏览器标签页或点击网页上的断开连接按钮，JavaScript 代码调用 `socket.close()`，这会触发 `dom_websocket.cc` 中的 `close` 方法，开始关闭连接的过程。
8. **连接关闭:**  `DOMWebSocket::DidClose` 被调用，触发 JavaScript 的 `onclose` 事件。

**调试线索:**

* **断点:** 在 `DOMWebSocket::Create`, `DOMWebSocket::Connect`, `DOMWebSocket::send`, `DOMWebSocket::DidReceiveTextMessage` 等关键方法上设置断点，可以观察 WebSocket 连接的生命周期和数据流。
* **日志:**  查看控制台输出的 WebSocket 相关日志 (例如，使用 `DVLOG(1)` 打印的日志)。
* **网络面板:**  浏览器的开发者工具中的 "Network" (或 "网络") 面板可以查看 WebSocket 连接的握手过程、发送和接收的消息。
* **JavaScript 调试器:**  在 JavaScript 代码中设置断点，可以查看 `WebSocket` 对象的状态和事件处理函数的执行情况。

总而言之，`dom_websocket.cc` 是 Blink 引擎中实现 WebSocket API 的关键组件，它负责将 JavaScript 的 WebSocket 操作转化为底层的网络通信，并管理 WebSocket 连接的状态和事件。理解这个文件的功能对于理解浏览器如何处理 WebSocket 连接至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/websockets/dom_websocket.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2011 Google Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/websockets/dom_websocket.h"

#include <optional>
#include <string>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_stringsequence.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/modules/websockets/close_event.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/weborigin/known_ports.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

DOMWebSocket::EventQueue::EventQueue(EventTarget* target)
    : state_(kActive), target_(target) {}

void DOMWebSocket::EventQueue::Dispatch(Event* event) {
  switch (state_) {
    case kActive:
      DCHECK(events_.empty());
      target_->DispatchEvent(*event);
      break;
    case kPaused:
    case kUnpausePosted:
      events_.push_back(event);
      break;
    case kStopped:
      DCHECK(events_.empty());
      // Do nothing.
      break;
  }
}

bool DOMWebSocket::EventQueue::IsEmpty() const {
  return events_.empty();
}

void DOMWebSocket::EventQueue::Pause() {
  if (state_ == kStopped || state_ == kPaused)
    return;

  state_ = kPaused;
}

void DOMWebSocket::EventQueue::Unpause() {
  if (state_ != kPaused || state_ == kUnpausePosted)
    return;

  state_ = kUnpausePosted;
  target_->GetExecutionContext()
      ->GetTaskRunner(TaskType::kWebSocket)
      ->PostTask(FROM_HERE, WTF::BindOnce(&EventQueue::UnpauseTask,
                                          WrapWeakPersistent(this)));
}

void DOMWebSocket::EventQueue::ContextDestroyed() {
  if (state_ == kStopped)
    return;

  state_ = kStopped;
  events_.clear();
}

bool DOMWebSocket::EventQueue::IsPaused() {
  return state_ == kPaused || state_ == kUnpausePosted;
}

void DOMWebSocket::EventQueue::DispatchQueuedEvents() {
  if (state_ != kActive)
    return;

  HeapDeque<Member<Event>> events;
  events.Swap(events_);
  while (!events.empty()) {
    if (state_ == kStopped || state_ == kPaused || state_ == kUnpausePosted)
      break;
    DCHECK_EQ(state_, kActive);
    target_->DispatchEvent(*events.TakeFirst());
    // |this| can be stopped here.
  }
  if (state_ == kPaused || state_ == kUnpausePosted) {
    while (!events_.empty())
      events.push_back(events_.TakeFirst());
    events.Swap(events_);
  }
}

void DOMWebSocket::EventQueue::UnpauseTask() {
  if (state_ != kUnpausePosted)
    return;
  state_ = kActive;
  DispatchQueuedEvents();
}

void DOMWebSocket::EventQueue::Trace(Visitor* visitor) const {
  visitor->Trace(target_);
  visitor->Trace(events_);
}

static void SetInvalidStateErrorForSendMethod(ExceptionState& exception_state) {
  exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                    "Still in CONNECTING state.");
}

constexpr WebSocketCommon::State DOMWebSocket::kConnecting;
constexpr WebSocketCommon::State DOMWebSocket::kOpen;
constexpr WebSocketCommon::State DOMWebSocket::kClosing;
constexpr WebSocketCommon::State DOMWebSocket::kClosed;

DOMWebSocket::DOMWebSocket(ExecutionContext* context)
    : ActiveScriptWrappable<DOMWebSocket>({}),
      ExecutionContextLifecycleStateObserver(context),
      buffered_amount_(0),
      consumed_buffered_amount_(0),
      buffered_amount_after_close_(0),
      subprotocol_(""),
      extensions_(""),
      event_queue_(MakeGarbageCollected<EventQueue>(this)),
      buffered_amount_update_task_pending_(false) {
  DVLOG(1) << "DOMWebSocket " << this << " created";
}

DOMWebSocket::~DOMWebSocket() {
  DVLOG(1) << "DOMWebSocket " << this << " destroyed";
  DCHECK(!channel_);
}

void DOMWebSocket::LogError(const String& message) {
  if (GetExecutionContext()) {
    GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kJavaScript,
            mojom::ConsoleMessageLevel::kError, message));
  }
}

DOMWebSocket* DOMWebSocket::Create(ExecutionContext* context,
                                   const String& url,
                                   ExceptionState& exception_state) {
  return Create(
      context, url,
      MakeGarbageCollected<V8UnionStringOrStringSequence>(Vector<String>()),
      exception_state);
}

DOMWebSocket* DOMWebSocket::Create(
    ExecutionContext* context,
    const String& url,
    const V8UnionStringOrStringSequence* protocols,
    ExceptionState& exception_state) {
  if (url.IsNull()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Failed to create a WebSocket: the provided URL is invalid.");
    return nullptr;
  }

  DOMWebSocket* websocket = MakeGarbageCollected<DOMWebSocket>(context);
  websocket->UpdateStateIfNeeded();

  DCHECK(protocols);
  switch (protocols->GetContentType()) {
    case V8UnionStringOrStringSequence::ContentType::kString: {
      Vector<String> protocols_vector;
      protocols_vector.push_back(protocols->GetAsString());
      websocket->Connect(url, protocols_vector, exception_state);
      break;
    }
    case V8UnionStringOrStringSequence::ContentType::kStringSequence:
      websocket->Connect(url, protocols->GetAsStringSequence(),
                         exception_state);
      break;
  }

  if (exception_state.HadException())
    return nullptr;

  return websocket;
}

void DOMWebSocket::Connect(const String& url,
                           const Vector<String>& protocols,
                           ExceptionState& exception_state) {
  UseCounter::Count(GetExecutionContext(), WebFeature::kWebSocket);

  DVLOG(1) << "WebSocket " << this << " connect() url=" << url;

  channel_ = CreateChannel(GetExecutionContext(), this);
  auto result = common_.Connect(GetExecutionContext(), url, protocols, channel_,
                                exception_state);

  switch (result) {
    case WebSocketCommon::ConnectResult::kSuccess:
      DCHECK(!exception_state.HadException());
      origin_string_ = SecurityOrigin::Create(common_.Url())->ToString();
      return;

    case WebSocketCommon::ConnectResult::kException:
      DCHECK(exception_state.HadException());
      channel_ = nullptr;
      return;

    case WebSocketCommon::ConnectResult::kAsyncError:
      DCHECK(!exception_state.HadException());
      // Delay the event dispatch until after the current task by suspending and
      // resuming the queue. If we don't do this, the event is fired
      // synchronously with the constructor, meaning that it's impossible to
      // listen for.
      event_queue_->Pause();
      event_queue_->Dispatch(Event::Create(event_type_names::kError));
      event_queue_->Unpause();
      return;
  }
}

void DOMWebSocket::UpdateBufferedAmountAfterClose(uint64_t payload_size) {
  buffered_amount_after_close_ += payload_size;

  LogError("WebSocket is already in CLOSING or CLOSED state.");
}

void DOMWebSocket::PostBufferedAmountUpdateTask() {
  if (buffered_amount_update_task_pending_)
    return;
  buffered_amount_update_task_pending_ = true;
  GetExecutionContext()
      ->GetTaskRunner(TaskType::kWebSocket)
      ->PostTask(FROM_HERE,
                 WTF::BindOnce(&DOMWebSocket::BufferedAmountUpdateTask,
                               WrapWeakPersistent(this)));
}

void DOMWebSocket::BufferedAmountUpdateTask() {
  buffered_amount_update_task_pending_ = false;
  ReflectBufferedAmountConsumption();
}

void DOMWebSocket::ReflectBufferedAmountConsumption() {
  if (event_queue_->IsPaused())
    return;
  DCHECK_GE(buffered_amount_, consumed_buffered_amount_);
  DVLOG(1) << "WebSocket " << this << " reflectBufferedAmountConsumption() "
           << buffered_amount_ << " => "
           << (buffered_amount_ - consumed_buffered_amount_);

  buffered_amount_ -= consumed_buffered_amount_;
  consumed_buffered_amount_ = 0;
}

void DOMWebSocket::ReleaseChannel() {
  DCHECK(channel_);
  channel_->Disconnect();
  channel_ = nullptr;
}

void DOMWebSocket::send(const String& message,
                        ExceptionState& exception_state) {
  DVLOG(1) << "WebSocket " << this << " send() Sending String " << message;
  if (common_.GetState() == kConnecting) {
    SetInvalidStateErrorForSendMethod(exception_state);
    return;
  }
  // No exception is raised if the connection was once established but has
  // subsequently been closed.
  std::string encoded_message = message.Utf8();
  if (common_.GetState() == kClosing || common_.GetState() == kClosed) {
    UpdateBufferedAmountAfterClose(encoded_message.length());
    return;
  }

  DCHECK(channel_);
  buffered_amount_ += encoded_message.length();
  channel_->Send(encoded_message, base::OnceClosure());
  NotifyWebSocketActivity();
}

void DOMWebSocket::send(DOMArrayBuffer* binary_data,
                        ExceptionState& exception_state) {
  DVLOG(1) << "WebSocket " << this << " send() Sending ArrayBuffer "
           << binary_data;
  DCHECK(binary_data);
  if (common_.GetState() == kConnecting) {
    SetInvalidStateErrorForSendMethod(exception_state);
    return;
  }
  if (common_.GetState() == kClosing || common_.GetState() == kClosed) {
    UpdateBufferedAmountAfterClose(binary_data->ByteLength());
    return;
  }
  DCHECK(channel_);
  buffered_amount_ += binary_data->ByteLength();
  channel_->Send(*binary_data, 0, binary_data->ByteLength(),
                 base::OnceClosure());
  NotifyWebSocketActivity();
}

void DOMWebSocket::send(NotShared<DOMArrayBufferView> array_buffer_view,
                        ExceptionState& exception_state) {
  DVLOG(1) << "WebSocket " << this << " send() Sending ArrayBufferView "
           << array_buffer_view.Get();
  DCHECK(array_buffer_view);
  if (common_.GetState() == kConnecting) {
    SetInvalidStateErrorForSendMethod(exception_state);
    return;
  }
  if (common_.GetState() == kClosing || common_.GetState() == kClosed) {
    UpdateBufferedAmountAfterClose(array_buffer_view->byteLength());
    return;
  }
  DCHECK(channel_);
  buffered_amount_ += array_buffer_view->byteLength();
  channel_->Send(*array_buffer_view->buffer(), array_buffer_view->byteOffset(),
                 array_buffer_view->byteLength(), base::OnceClosure());
  NotifyWebSocketActivity();
}

void DOMWebSocket::send(Blob* binary_data, ExceptionState& exception_state) {
  DVLOG(1) << "WebSocket " << this << " send() Sending Blob "
           << binary_data->Uuid();
  DCHECK(binary_data);
  if (common_.GetState() == kConnecting) {
    SetInvalidStateErrorForSendMethod(exception_state);
    return;
  }
  if (common_.GetState() == kClosing || common_.GetState() == kClosed) {
    UpdateBufferedAmountAfterClose(binary_data->size());
    return;
  }
  uint64_t size = binary_data->size();
  buffered_amount_ += size;
  DCHECK(channel_);

  // When the runtime type of |binary_data| is File,
  // binary_data->GetBlobDataHandle()->size() returns -1. However, in order to
  // maintain the value of |buffered_amount_| correctly, the WebSocket code
  // needs to fix the size of the File at this point. For this reason,
  // construct a new BlobDataHandle here with the size that this method
  // observed.
  channel_->Send(BlobDataHandle::Create(binary_data->Uuid(),
                                        binary_data->type(), size,
                                        binary_data->AsMojoBlob()));
  NotifyWebSocketActivity();
}

void DOMWebSocket::close(uint16_t code,
                         const String& reason,
                         ExceptionState& exception_state) {
  CloseInternal(code, reason, exception_state);
}

void DOMWebSocket::close(ExceptionState& exception_state) {
  CloseInternal(std::nullopt, String(), exception_state);
}

void DOMWebSocket::close(uint16_t code, ExceptionState& exception_state) {
  CloseInternal(code, String(), exception_state);
}

void DOMWebSocket::CloseInternal(std::optional<uint16_t> code,
                                 const String& reason,
                                 ExceptionState& exception_state) {
  common_.CloseInternal(code, reason, channel_, exception_state);
}

const KURL& DOMWebSocket::url() const {
  return common_.Url();
}

WebSocketCommon::State DOMWebSocket::readyState() const {
  return common_.GetState();
}

uint64_t DOMWebSocket::bufferedAmount() const {
  // TODO(ricea): Check for overflow once machines with exabytes of RAM become
  // commonplace.
  return buffered_amount_after_close_ + buffered_amount_;
}

String DOMWebSocket::protocol() const {
  return subprotocol_;
}

String DOMWebSocket::extensions() const {
  return extensions_;
}

V8BinaryType DOMWebSocket::binaryType() const {
  return V8BinaryType(binary_type_);
}

void DOMWebSocket::setBinaryType(const V8BinaryType& binary_type) {
  binary_type_ = binary_type.AsEnum();
}

const AtomicString& DOMWebSocket::InterfaceName() const {
  return event_target_names::kWebSocket;
}

ExecutionContext* DOMWebSocket::GetExecutionContext() const {
  return ExecutionContextLifecycleStateObserver::GetExecutionContext();
}

void DOMWebSocket::ContextDestroyed() {
  DVLOG(1) << "WebSocket " << this << " contextDestroyed()";
  event_queue_->ContextDestroyed();
  if (channel_) {
    ReleaseChannel();
  }
  if (common_.GetState() != kClosed) {
    common_.SetState(kClosed);
  }
}

bool DOMWebSocket::HasPendingActivity() const {
  return channel_ || !event_queue_->IsEmpty();
}

void DOMWebSocket::ContextLifecycleStateChanged(
    mojom::FrameLifecycleState state) {
  if (state == mojom::FrameLifecycleState::kRunning) {
    event_queue_->Unpause();

    // If |consumed_buffered_amount_| was updated while the object was paused
    // then the changes to |buffered_amount_| will not yet have been applied.
    // Post another task to update it.
    PostBufferedAmountUpdateTask();
  } else {
    event_queue_->Pause();
  }
}

void DOMWebSocket::DidConnect(const String& subprotocol,
                              const String& extensions) {
  DVLOG(1) << "WebSocket " << this << " DidConnect()";
  if (common_.GetState() != kConnecting)
    return;
  common_.SetState(kOpen);
  subprotocol_ = subprotocol;
  extensions_ = extensions;
  event_queue_->Dispatch(Event::Create(event_type_names::kOpen));
  NotifyWebSocketActivity();
}

void DOMWebSocket::DidReceiveTextMessage(const String& msg) {
  DVLOG(1) << "WebSocket " << this << " DidReceiveTextMessage() Text message "
           << msg;
  ReflectBufferedAmountConsumption();
  DCHECK_NE(common_.GetState(), kConnecting);
  if (common_.GetState() != kOpen)
    return;

  DCHECK(!origin_string_.IsNull());
  event_queue_->Dispatch(MessageEvent::Create(msg, origin_string_));
  NotifyWebSocketActivity();
}

void DOMWebSocket::DidReceiveBinaryMessage(
    const Vector<base::span<const char>>& data) {
  size_t size = 0;
  for (const auto& span : data) {
    size += span.size();
  }
  DVLOG(1) << "WebSocket " << this << " DidReceiveBinaryMessage() " << size
           << " byte binary message";
  ReflectBufferedAmountConsumption();
  DCHECK(!origin_string_.IsNull());

  DCHECK_NE(common_.GetState(), kConnecting);
  if (common_.GetState() != kOpen)
    return;

  switch (binary_type_) {
    case V8BinaryType::Enum::kBlob: {
      auto blob_data = std::make_unique<BlobData>();
      for (const auto& span : data) {
        blob_data->AppendBytes(base::as_bytes(span));
      }
      auto* blob = MakeGarbageCollected<Blob>(
          BlobDataHandle::Create(std::move(blob_data), size));
      event_queue_->Dispatch(MessageEvent::Create(blob, origin_string_));
      break;
    }

    case V8BinaryType::Enum::kArraybuffer:
      DOMArrayBuffer* array_buffer = DOMArrayBuffer::Create(data);
      event_queue_->Dispatch(
          MessageEvent::Create(array_buffer, origin_string_));
      break;
  }
  NotifyWebSocketActivity();
}

void DOMWebSocket::DidError() {
  DVLOG(1) << "WebSocket " << this << " DidError()";
  ReflectBufferedAmountConsumption();
  common_.SetState(kClosed);
  event_queue_->Dispatch(Event::Create(event_type_names::kError));
}

void DOMWebSocket::DidConsumeBufferedAmount(uint64_t consumed) {
  DCHECK_GE(buffered_amount_, consumed + consumed_buffered_amount_);
  DVLOG(1) << "WebSocket " << this << " DidConsumeBufferedAmount(" << consumed
           << ")";
  if (common_.GetState() == kClosed)
    return;
  consumed_buffered_amount_ += consumed;
  PostBufferedAmountUpdateTask();
}

void DOMWebSocket::DidStartClosingHandshake() {
  DVLOG(1) << "WebSocket " << this << " DidStartClosingHandshake()";
  ReflectBufferedAmountConsumption();
  common_.SetState(kClosing);
}

void DOMWebSocket::DidClose(
    ClosingHandshakeCompletionStatus closing_handshake_completion,
    uint16_t code,
    const String& reason) {
  DVLOG(1) << "WebSocket " << this << " DidClose()";
  ReflectBufferedAmountConsumption();
  if (!channel_)
    return;
  bool all_data_has_been_consumed =
      buffered_amount_ == consumed_buffered_amount_;
  bool was_clean = common_.GetState() == kClosing &&
                   all_data_has_been_consumed &&
                   closing_handshake_completion == kClosingHandshakeComplete &&
                   code != WebSocketChannel::kCloseEventCodeAbnormalClosure;
  common_.SetState(kClosed);

  ReleaseChannel();

  event_queue_->Dispatch(
      MakeGarbageCollected<CloseEvent>(was_clean, code, reason));
}

void DOMWebSocket::NotifyWebSocketActivity() {
  ExecutionContext* context = GetExecutionContext();
  if (context) {
    context->NotifyWebSocketActivity();
  }
}

void DOMWebSocket::Trace(Visitor* visitor) const {
  visitor->Trace(channel_);
  visitor->Trace(event_queue_);
  WebSocketChannelClient::Trace(visitor);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleStateObserver::Trace(visitor);
}

}  // namespace blink

"""

```