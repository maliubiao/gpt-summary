Response:
Let's break down the thought process for analyzing the `event_source.cc` file.

1. **Understand the Goal:** The core request is to understand the functionality of this specific Chromium Blink file (`event_source.cc`). This includes its purpose, how it relates to web technologies (JavaScript, HTML, CSS), potential issues, and how a user's actions lead to its involvement.

2. **Initial Skim for High-Level Purpose:**  Reading the initial comments and included headers gives a strong clue. The copyright mentions "EventSource," and headers like `third_party/blink/renderer/modules/eventsource/event_source.h` and `third_party/blink/renderer/core/events/message_event.h` clearly indicate this file is about the *EventSource API*.

3. **Identify Key Classes and Methods:**  Look for class definitions (`class EventSource`) and prominent methods like `Create`, `Connect`, `close`, and event handlers (`DidReceiveResponse`, `DidReceiveData`, `DidFail`). These are the building blocks of the functionality.

4. **Analyze Core Functionality - The EventSource Lifecycle:**  Trace the logical flow of an EventSource's life:
    * **Creation:**  The `Create` method is the entry point. It takes a URL and potentially initialization options. It performs URL validation and starts the initial connection.
    * **Connection:** The `Connect` method constructs a `ResourceRequest` with specific headers (`Accept: text/event-stream`, `Cache-Control: no-cache`, `Last-Event-ID`). It uses a `ThreadableLoader` to make the network request.
    * **Receiving Data:**  `DidReceiveResponse` handles the HTTP response, validating the status code and MIME type. `DidReceiveData` processes the incoming data using an `EventSourceParser`.
    * **Message Handling:** The `OnMessageEvent` method is where parsed data is converted into `MessageEvent` objects and dispatched to JavaScript.
    * **Error Handling and Reconnection:** `DidFail` handles network errors and triggers reconnection attempts (`ScheduleReconnect`). The `reconnect_delay_` and `connect_timer_` are important here.
    * **Closing:** The `close` method stops the connection and prevents further reconnection attempts.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  The `EventSource` object is created and manipulated in JavaScript. Events (`open`, `message`, `error`) are dispatched to JavaScript event handlers attached to the `EventSource` object. The `withCredentials` option is set from JavaScript.
    * **HTML:**  The `EventSource` object is typically created via JavaScript, but its URL originates from an HTML context (e.g., an attribute or a script).
    * **CSS:**  While CSS doesn't directly interact with `EventSource`, the *results* of the server-sent events might influence the content or styling of the page, which CSS would then handle.

6. **Identify Logic and Assumptions:**
    * **Reconnection Logic:** The file implements a reconnection mechanism with a delay. The delay is configurable and defaults to 3 seconds.
    * **Error Handling:** Different error conditions (cancellation, access check, etc.) are handled differently, influencing whether a reconnect is attempted.
    * **Last-Event-ID:** The `Last-Event-ID` header is used for resuming a stream after a disconnection.
    * **CORS:** The code explicitly sets CORS-related request parameters.

7. **Consider User/Programming Errors:** Think about common mistakes developers might make when using EventSource:
    * **Invalid URL:** Providing an incorrect URL.
    * **Incorrect MIME type on the server:** The server not sending `text/event-stream`.
    * **Network issues:** Server being unavailable.
    * **CORS problems:** Server not configured to allow cross-origin requests.
    * **Not handling errors:** Forgetting to add `onerror` handlers.

8. **Trace User Actions to Code:** Think about the sequence of events that leads to this code being executed:
    1. User opens a web page.
    2. JavaScript code on the page creates a new `EventSource` object.
    3. Blink's JavaScript engine calls the `EventSource::Create` method in C++.
    4. The connection process begins, potentially triggering various methods in `event_source.cc` depending on the network response.

9. **Debugging Clues:**  Focus on the states, timers, and network interactions as key areas for debugging:
    * **State transitions:** Track the `state_` variable (kConnecting, kOpen, kClosed).
    * **Timer:** The `connect_timer_` is crucial for reconnection.
    * **Loader:** The `loader_` object manages the network request.
    * **Console messages:** The code logs errors to the console.

10. **Structure the Answer:** Organize the information logically with clear headings and examples. Address each part of the prompt systematically. Use bullet points or numbered lists for clarity. Provide concrete examples for JavaScript, HTML, and common errors.

11. **Review and Refine:** Read through the answer to ensure accuracy, completeness, and clarity. Check if all parts of the prompt have been addressed.

**Self-Correction Example During Thought Process:**

Initially, I might focus too heavily on the network request aspect. Then, realizing the prompt asks about the *functionality*, I'd broaden the scope to include the JavaScript API interaction, event dispatching, and the overall state management of the `EventSource` object. I'd also double-check that I've provided *specific examples* for each of the requested areas (JavaScript, HTML, errors, etc.). Similarly, I'd ensure the debugging clues are actionable and directly related to the code's behavior.
这是 Chromium Blink 引擎中负责实现 **EventSource API** 的源代码文件 `event_source.cc`。EventSource API (也称为 Server-Sent Events, SSE) 允许服务器向客户端推送实时数据更新。

**它的主要功能包括:**

1. **建立与服务器的连接:**
   - 创建一个到指定 URL 的 HTTP 连接，用于接收服务器发送的事件流。
   - 设置请求头，例如 `Accept: text/event-stream`，告知服务器客户端期望接收的是事件流数据。
   - 处理跨域请求 (CORS)，根据 `withCredentials` 属性设置 `CredentialsMode`。
   - 如果之前有连接，并且服务器发送了 `Last-Event-ID`，会在新的请求中带上这个头，以便服务器知道客户端期望从哪个事件开始接收。

2. **管理连接状态:**
   - 维护连接的不同状态：`kConnecting` (连接中), `kOpen` (已连接), `kClosed` (已关闭)。
   - 提供 `readyState()` 方法来获取当前连接状态。

3. **处理服务器发送的数据:**
   - 使用 `EventSourceParser` 解析服务器发送的事件流数据。
   - 解析出的事件数据包括 `event` (事件类型), `data` (事件数据), `id` (事件 ID), 和 `retry` (重连时间)。

4. **分发事件到 JavaScript:**
   - 当接收到新的完整事件时，创建一个 `MessageEvent` 对象，并将服务器发送的 `data` 作为事件数据。
   - 如果服务器指定了 `event` 字段，则使用该值作为事件类型，否则默认类型为 `message`。
   - `lastEventId` 属性会记录最新的事件 ID。
   - 分发 `open` 事件，当连接成功建立时触发。
   - 分发 `message` 事件，当接收到服务器发送的事件消息时触发。
   - 分发 `error` 事件，当连接发生错误或被关闭时触发。

5. **处理连接错误和重连:**
   - 当连接失败时 (例如网络错误、HTTP 状态码错误)，会尝试重新连接。
   - 使用 `reconnect_delay_` 来控制重连的时间间隔，该值可以由服务器通过 `retry` 字段指定。
   - 使用定时器 `connect_timer_` 来延迟重连尝试。

6. **提供 `close()` 方法:**
   - 允许 JavaScript 代码显式关闭 EventSource 连接。
   - 关闭连接后，不会再尝试重新连接。

7. **集成到 Blink 渲染引擎:**
   - 使用 Blink 的网络库 (`ThreadableLoader`) 进行网络请求。
   - 与 V8 JavaScript 引擎集成，将事件分发到 JavaScript 环境。
   - 利用 Blink 的事件系统 (`EventTarget`) 来管理事件监听器和分发事件。
   - 使用 Blink 的控制台 (`ConsoleMessage`) 输出错误信息。
   - 使用 `UseCounter` 记录 EventSource 的使用情况。

**与 JavaScript, HTML, CSS 的关系以及举例说明:**

* **JavaScript:**  EventSource 的主要使用方式是通过 JavaScript 代码创建和操作 `EventSource` 对象。
   ```javascript
   // JavaScript 代码
   const eventSource = new EventSource('/my-event-stream');

   eventSource.onopen = function() {
     console.log("连接已打开");
   };

   eventSource.onmessage = function(event) {
     console.log("接收到消息:", event.data);
   };

   eventSource.onerror = function(error) {
     console.error("连接发生错误:", error);
   };

   // 关闭连接
   // eventSource.close();
   ```
   在这个例子中，JavaScript 代码创建了一个连接到 `/my-event-stream` 的 EventSource 对象，并定义了 `onopen`, `onmessage`, 和 `onerror` 事件处理函数。

* **HTML:**  HTML 页面通常会包含引用上述 JavaScript 代码的 `<script>` 标签。HTML 本身不直接涉及 EventSource 的实现细节，但它提供了运行 JavaScript 代码的环境。

* **CSS:** CSS 本身与 EventSource 的功能没有直接关系。然而，通过 EventSource 接收到的数据可能会导致 JavaScript 修改 DOM 结构或元素的样式，从而间接地影响页面的 CSS 呈现。例如，服务器推送了新的通知数量，JavaScript 接收到后可以更新页面上通知图标的数字，这个数字的样式由 CSS 定义。

**逻辑推理 (假设输入与输出):**

假设输入:

1. **用户在浏览器中打开一个包含以下 JavaScript 代码的 HTML 页面:**
   ```javascript
   const source = new EventSource('/stream');
   source.onmessage = function(event) {
     console.log("Data received:", event.data);
   };
   ```
2. **服务器 `/stream` 返回以下内容 (text/event-stream):**
   ```
   data: Hello from server!

   data: Another message
   event: custom_event
   data: This is a custom event
   id: message-123

   retry: 5000
   ```

输出:

1. **浏览器控制台输出:**
   ```
   Data received: Hello from server!
   Data received: Another message
   Data received: This is a custom event
   ```
2. **EventSource 对象的 `lastEventId` 属性将被设置为 `"message-123"`。**
3. **如果连接中断，浏览器会在 5000 毫秒后尝试重新连接 (因为服务器发送了 `retry: 5000`)。**

**用户或编程常见的使用错误举例说明:**

1. **服务器未设置正确的 MIME 类型:**
   - **错误:** 服务器返回的内容类型不是 `text/event-stream`，而是 `text/plain` 或 `application/json` 等。
   - **结果:** `EventSource::DidReceiveResponse` 中的 `response_is_valid` 将为 `false`，连接将被中止，并可能在控制台输出错误信息："EventSource's response has a MIME type ("text/plain") that is not "text/event-stream". Aborting the connection."
   - **调试线索:** 检查浏览器的网络面板，查看服务器响应的 `Content-Type` 头是否正确。

2. **URL 不存在或服务器错误:**
   - **错误:** `EventSource` 构造函数中指定的 URL 指向一个不存在的资源或返回 404 或 500 等错误状态码。
   - **结果:** `EventSource::DidReceiveResponse` 中的 `response_is_valid` 将为 `false`，连接将被中止，并触发 `onerror` 事件。
   - **调试线索:** 检查浏览器的网络面板，查看请求的状态码。确保服务器端处理该 URL 的逻辑正常。

3. **CORS 配置错误:**
   - **错误:** 如果尝试从不同的源 (域名、协议或端口) 连接到 EventSource，但服务器没有设置正确的 CORS 头 (例如 `Access-Control-Allow-Origin`)。
   - **结果:** 浏览器会阻止跨域请求，`EventSource::DidFail` 会收到一个 `ResourceError`，并且 `error.IsAccessCheck()` 将返回 `true`，导致连接尝试被中止，并触发 `onerror` 事件。
   - **调试线索:** 检查浏览器的控制台，可能会有 CORS 相关的错误信息。检查服务器的 CORS 配置。

4. **在不支持 EventSource 的旧浏览器中使用:**
   - **错误:**  在一些较旧的浏览器中，`EventSource` API 可能未实现。
   - **结果:**  尝试创建 `EventSource` 对象可能会导致 JavaScript 错误。
   - **调试线索:** 检查目标浏览器的兼容性。可以使用特性检测来判断浏览器是否支持 EventSource。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入网址或点击链接，导航到一个包含 EventSource 使用的网页。**
2. **浏览器加载 HTML 页面，并解析 HTML 内容。**
3. **浏览器执行 HTML 中包含的 JavaScript 代码。**
4. **JavaScript 代码中创建了一个 `EventSource` 对象，例如 `const source = new EventSource('/updates');`。**  这一步会调用 `EventSource::Create` 函数。
5. **`EventSource::Create` 函数会进行 URL 校验，并创建 `EventSource` 对象，然后调用 `ScheduleInitialConnect`。**
6. **`ScheduleInitialConnect` 函数会启动一个定时器 `connect_timer_`，用于延迟连接。**
7. **定时器触发，调用 `EventSource::Connect` 函数。**
8. **`EventSource::Connect` 函数创建 `ResourceRequest` 对象，设置请求头，并使用 `ThreadableLoader` 发起网络请求。**
9. **浏览器网络层处理请求，连接到服务器。**
10. **服务器响应后，Blink 的网络层会调用 `EventSource::DidReceiveResponse` 函数，处理响应头。**
11. **如果响应成功 (状态码 200，MIME 类型为 `text/event-stream`)，状态变为 `kOpen`，并分发 `open` 事件。**
12. **服务器后续发送数据时，Blink 的网络层会调用 `EventSource::DidReceiveData` 函数，将数据传递给 `EventSourceParser` 进行解析。**
13. **`EventSourceParser` 解析出完整的事件后，会调用 `EventSource::OnMessageEvent` 函数。**
14. **`EventSource::OnMessageEvent` 函数创建 `MessageEvent` 对象，并分发到 JavaScript 环境。**
15. **如果连接过程中发生错误，Blink 的网络层会调用 `EventSource::DidFail` 函数，处理错误情况并尝试重连或分发 `error` 事件。**
16. **如果 JavaScript 代码调用了 `source.close()`，则会调用 `EventSource::close()` 函数，关闭连接并停止重连。**

**调试线索:**

* **浏览器的开发者工具 (Network 面板):**  可以查看 EventSource 连接的网络请求和响应头，确认 URL、状态码、MIME 类型、CORS 头等信息。
* **浏览器的开发者工具 (Console 面板):**  查看是否有 JavaScript 错误或 `console.log` 输出的信息。`EventSource` 类中也会输出一些错误信息到控制台。
* **Blink 调试工具:**  如果需要深入调试 Blink 引擎本身的行为，可以使用 Blink 提供的调试工具，设置断点在 `event_source.cc` 的相关函数中，例如 `Connect`, `DidReceiveResponse`, `DidReceiveData`, `DidFail` 等，来跟踪代码执行流程和变量状态。
* **抓包工具 (如 Wireshark):**  可以捕获网络数据包，查看客户端和服务器之间的详细通信内容，包括 HTTP 请求和响应的原始数据。
* **日志记录:**  在服务器端记录 EventSource 请求的处理过程，可以帮助排查服务器端的问题。

总而言之，`event_source.cc` 文件是 Chromium Blink 引擎中实现 EventSource API 的核心组件，负责管理连接、处理数据、分发事件以及处理错误和重连逻辑，使得 Web 开发者能够利用 Server-Sent Events 技术构建实时的 Web 应用。

### 提示词
```
这是目录为blink/renderer/modules/eventsource/event_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2009, 2012 Ericsson AB. All rights reserved.
 * Copyright (C) 2010 Apple Inc. All rights reserved.
 * Copyright (C) 2011, Code Aurora Forum. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of Ericsson nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
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

#include "third_party/blink/renderer/modules/eventsource/event_source.h"

#include <memory>

#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value_factory.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_event_source_init.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/threadable_loader.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {
namespace {
// https://fetch.spec.whatwg.org/#cors-unsafe-request-header-byte
bool IsCorsUnsafeRequestHeaderByte(char c) {
  const auto u = static_cast<uint8_t>(c);
  return (u < 0x20 && u != 0x09) || u == 0x22 || u == 0x28 || u == 0x29 ||
         u == 0x3a || u == 0x3c || u == 0x3e || u == 0x3f || u == 0x40 ||
         u == 0x5b || u == 0x5c || u == 0x5d || u == 0x7b || u == 0x7d ||
         u == 0x7f;
}

void ReportUMA(ExecutionContext& context,
               const std::string& value,
               network::mojom::FetchResponseType response_type) {
  if (response_type == network::mojom::FetchResponseType::kCors &&
      (value.size() > 128 ||
       base::ranges::any_of(value, IsCorsUnsafeRequestHeaderByte))) {
    UseCounter::Count(context,
                      WebFeature::kFetchEventSourceLastEventIdCorsUnSafe);
  }
}

}  // anonymous namespace

const uint64_t EventSource::kDefaultReconnectDelay = 3000;

inline EventSource::EventSource(ExecutionContext* context,
                                const KURL& url,
                                const EventSourceInit* event_source_init)
    : ActiveScriptWrappable<EventSource>({}),
      ExecutionContextLifecycleObserver(context),
      url_(url),
      current_url_(url),
      with_credentials_(event_source_init->withCredentials()),
      state_(kConnecting),
      connect_timer_(context->GetTaskRunner(TaskType::kRemoteEvent),
                     this,
                     &EventSource::ConnectTimerFired),
      reconnect_delay_(kDefaultReconnectDelay),
      world_(context->GetCurrentWorld()) {}

EventSource* EventSource::Create(ExecutionContext* context,
                                 const String& url,
                                 const EventSourceInit* event_source_init,
                                 ExceptionState& exception_state) {
  UseCounter::Count(context, context->IsWindow()
                                 ? WebFeature::kEventSourceDocument
                                 : WebFeature::kEventSourceWorker);

  KURL full_url = context->CompleteURL(url);
  if (!full_url.IsValid()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Cannot open an EventSource to '" + url + "'. The URL is invalid.");
    return nullptr;
  }

  EventSource* source =
      MakeGarbageCollected<EventSource>(context, full_url, event_source_init);

  source->ScheduleInitialConnect();
  return source;
}

EventSource::~EventSource() {
  DCHECK_EQ(kClosed, state_);
  DCHECK(!loader_);
}

void EventSource::ScheduleInitialConnect() {
  DCHECK_EQ(kConnecting, state_);
  DCHECK(!loader_);

  connect_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void EventSource::Connect() {
  DCHECK_EQ(kConnecting, state_);
  DCHECK(!loader_);
  DCHECK(GetExecutionContext());

  ExecutionContext& execution_context = *GetExecutionContext();
  ResourceRequest request(current_url_);
  request.SetHttpMethod(http_names::kGET);
  request.SetHttpHeaderField(http_names::kAccept,
                             AtomicString("text/event-stream"));
  request.SetHttpHeaderField(http_names::kCacheControl,
                             AtomicString("no-cache"));
  request.SetRequestContext(mojom::blink::RequestContextType::EVENT_SOURCE);
  request.SetFetchLikeAPI(true);
  request.SetMode(network::mojom::RequestMode::kCors);
  request.SetTargetAddressSpace(network::mojom::IPAddressSpace::kUnknown);
  request.SetCredentialsMode(
      with_credentials_ ? network::mojom::CredentialsMode::kInclude
                        : network::mojom::CredentialsMode::kSameOrigin);
  request.SetCacheMode(blink::mojom::FetchCacheMode::kNoStore);
  request.SetCorsPreflightPolicy(
      network::mojom::CorsPreflightPolicy::kPreventPreflight);
  if (parser_ && !parser_->LastEventId().empty()) {
    // HTTP headers are Latin-1 byte strings, but the Last-Event-ID header is
    // encoded as UTF-8.
    // TODO(davidben): This should be captured in the type of
    // setHTTPHeaderField's arguments.
    std::string last_event_id_utf8 = parser_->LastEventId().Utf8();
    request.SetHttpHeaderField(
        http_names::kLastEventID,
        AtomicString(base::as_byte_span(last_event_id_utf8)));
  }

  ResourceLoaderOptions resource_loader_options(world_);
  resource_loader_options.data_buffering_policy = kDoNotBufferData;

  probe::WillSendEventSourceRequest(&execution_context);
  loader_ = MakeGarbageCollected<ThreadableLoader>(execution_context, this,
                                                   resource_loader_options);
  loader_->Start(std::move(request));
}

void EventSource::NetworkRequestEnded() {
  loader_ = nullptr;

  if (state_ != kClosed)
    ScheduleReconnect();
}

void EventSource::ScheduleReconnect() {
  state_ = kConnecting;
  connect_timer_.StartOneShot(base::Milliseconds(reconnect_delay_), FROM_HERE);
  DispatchEvent(*Event::Create(event_type_names::kError));
}

void EventSource::ConnectTimerFired(TimerBase*) {
  Connect();
}

String EventSource::url() const {
  return url_.GetString();
}

bool EventSource::withCredentials() const {
  return with_credentials_;
}

EventSource::State EventSource::readyState() const {
  return state_;
}

void EventSource::close() {
  if (state_ == kClosed) {
    DCHECK(!loader_);
    return;
  }
  if (parser_)
    parser_->Stop();

  // Stop trying to reconnect if EventSource was explicitly closed or if
  // contextDestroyed() was called.
  if (connect_timer_.IsActive()) {
    connect_timer_.Stop();
  }

  state_ = kClosed;

  if (loader_) {
    loader_->Cancel();
    loader_ = nullptr;
  }

}

const AtomicString& EventSource::InterfaceName() const {
  return event_target_names::kEventSource;
}

ExecutionContext* EventSource::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

void EventSource::DidReceiveResponse(uint64_t identifier,
                                     const ResourceResponse& response) {
  DCHECK_EQ(kConnecting, state_);
  DCHECK(loader_);

  resource_identifier_ = identifier;
  current_url_ = response.CurrentRequestUrl();
  event_stream_origin_ =
      SecurityOrigin::Create(response.CurrentRequestUrl())->ToString();
  int status_code = response.HttpStatusCode();
  bool mime_type_is_valid = response.MimeType() == "text/event-stream";
  bool response_is_valid = status_code == 200 && mime_type_is_valid;
  if (response_is_valid) {
    const String& charset = response.TextEncodingName();
    // If we have a charset, the only allowed value is UTF-8 (case-insensitive).
    response_is_valid =
        charset.empty() || EqualIgnoringASCIICase(charset, "UTF-8");
    if (!response_is_valid) {
      StringBuilder message;
      message.Append("EventSource's response has a charset (\"");
      message.Append(charset);
      message.Append("\") that is not UTF-8. Aborting the connection.");
      // FIXME: We are missing the source line.
      GetExecutionContext()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::ConsoleMessageSource::kJavaScript,
              mojom::ConsoleMessageLevel::kError, message.ToString()));
    }
  } else {
    // To keep the signal-to-noise ratio low, we only log 200-response with an
    // invalid MIME type.
    if (status_code == 200 && !mime_type_is_valid) {
      StringBuilder message;
      message.Append("EventSource's response has a MIME type (\"");
      message.Append(response.MimeType());
      message.Append(
          "\") that is not \"text/event-stream\". Aborting the connection.");
      // FIXME: We are missing the source line.
      GetExecutionContext()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::ConsoleMessageSource::kJavaScript,
              mojom::ConsoleMessageLevel::kError, message.ToString()));
    }
  }

  if (response_is_valid) {
    state_ = kOpen;
    AtomicString last_event_id;
    if (parser_) {
      // The new parser takes over the event ID.
      last_event_id = parser_->LastEventId();
      DCHECK(GetExecutionContext());
      ReportUMA(*GetExecutionContext(), last_event_id.Utf8(),
                response.GetType());
    }
    parser_ = MakeGarbageCollected<EventSourceParser>(last_event_id, this);
    DispatchEvent(*Event::Create(event_type_names::kOpen));
  } else {
    loader_->Cancel();
  }
}

void EventSource::DidReceiveData(base::span<const char> data) {
  DCHECK_EQ(kOpen, state_);
  DCHECK(loader_);
  DCHECK(parser_);

  parser_->AddBytes(data);
}

void EventSource::DidFinishLoading(uint64_t) {
  DCHECK_EQ(kOpen, state_);
  DCHECK(loader_);

  NetworkRequestEnded();
}

void EventSource::DidFail(uint64_t, const ResourceError& error) {
  DCHECK(loader_);
  if (error.IsCancellation() && state_ == kClosed) {
    NetworkRequestEnded();
    return;
  }

  DCHECK_NE(kClosed, state_);

  if (error.IsAccessCheck()) {
    AbortConnectionAttempt();
    return;
  }

  if (error.IsCancellation()) {
    // When the loading is cancelled for an external reason (e.g.,
    // window.stop()), dispatch an error event and do not reconnect.
    AbortConnectionAttempt();
    return;
  }
  NetworkRequestEnded();
}

void EventSource::DidFailRedirectCheck(uint64_t) {
  DCHECK(loader_);

  AbortConnectionAttempt();
}

void EventSource::OnMessageEvent(const AtomicString& event_type,
                                 const String& data,
                                 const AtomicString& last_event_id) {
  MessageEvent* e = MessageEvent::Create();
  e->initMessageEvent(event_type, false, false, data, event_stream_origin_,
                      last_event_id, nullptr, nullptr);

  probe::WillDispatchEventSourceEvent(GetExecutionContext(),
                                      resource_identifier_, event_type,
                                      last_event_id, data);
  DispatchEvent(*e);
}

void EventSource::OnReconnectionTimeSet(uint64_t reconnection_time) {
  reconnect_delay_ = reconnection_time;
}

void EventSource::AbortConnectionAttempt() {
  DCHECK_NE(kClosed, state_);

  loader_ = nullptr;
  state_ = kClosed;
  NetworkRequestEnded();

  DispatchEvent(*Event::Create(event_type_names::kError));
}

void EventSource::ContextDestroyed() {
  close();
}

bool EventSource::HasPendingActivity() const {
  return state_ != kClosed;
}

void EventSource::Trace(Visitor* visitor) const {
  visitor->Trace(parser_);
  visitor->Trace(loader_);
  visitor->Trace(connect_timer_);
  visitor->Trace(world_);
  EventTarget::Trace(visitor);
  ThreadableLoaderClient::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  EventSourceParser::Client::Trace(visitor);
}

}  // namespace blink
```