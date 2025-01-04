Response:
Let's break down the thought process for analyzing this `BroadcastChannel.cc` file.

1. **Understand the Goal:** The primary request is to understand the functionality of this C++ file within the Chromium Blink rendering engine. This involves identifying its purpose, how it interacts with web technologies (JavaScript, HTML, CSS), its logic, potential errors, and debugging information.

2. **Initial Scan for Keywords:**  Quickly scan the code for obvious keywords and structures:
    * `BroadcastChannel`: This is the central concept.
    * `#include`: Identifies dependencies. Pay attention to includes like `third_party/blink/renderer/modules/broadcastchannel/broadcast_channel.h` (the header file), `third_party/blink/renderer/core/...` (core rendering engine components), `mojo/...` (inter-process communication), and platform-level includes.
    * `postMessage`, `close`, `OnMessage`, `OnError`: These look like methods related to the lifecycle and communication of the `BroadcastChannel`.
    * `ExecutionContext`, `LocalDOMWindow`, `WorkerGlobalScope`: These indicate the contexts in which the `BroadcastChannel` can exist.
    * `MessageEvent`:  This is a key DOM event associated with messaging.
    * `UseCounter`, `WebFeature`: Suggests tracking of feature usage.
    * `Prerendering`, `BackForwardCache`: Hints at interactions with browser optimizations.

3. **Identify Core Functionality (High-Level):** From the keywords and structure, the core functionality appears to be implementing the browser's `BroadcastChannel` API. This API allows different browsing contexts (tabs, iframes, workers) from the *same origin* to communicate.

4. **Analyze Key Methods:**  Focus on the most important methods:
    * **`Create()`:**  This is the entry point for creating a `BroadcastChannel` object in JavaScript. Notice the check for cross-site iframes and the `UseCounter`.
    * **`postMessage()`:** This method sends a message. Pay attention to:
        * Error handling (`!receiver_.is_bound()`, `explicitly_closed_`).
        * Worker closing check.
        * Serialization of the message (`SerializedScriptValue`).
        * Prerendering handling (`AddPostPrerenderingActivationStep`).
        * Calling `PostMessageInternal()`.
    * **`PostMessageInternal()`:** The actual sending logic using Mojo (`remote_client_->OnMessage()`).
    * **`close()`:** Marks the channel as explicitly closed and calls `CloseInternal()`.
    * **`CloseInternal()`:**  Releases Mojo resources.
    * **`OnMessage()`:**  Handles incoming messages. Crucially, it deserializes the message and dispatches a `MessageEvent`. Note the Back/Forward Cache eviction logic.
    * **`OnError()`:** Handles disconnection from the browser process.

5. **Trace the Message Flow:** Visualize how a message travels:
    * JavaScript calls `broadcastChannel.postMessage(data)`.
    * `BroadcastChannel::postMessage()` serializes the data.
    * `BroadcastChannel::PostMessageInternal()` sends the serialized data via Mojo to the browser process.
    * The browser process routes the message to other `BroadcastChannel` instances with the same name and origin.
    * The receiving `BroadcastChannel::OnMessage()` deserializes the data and dispatches a `MessageEvent`.
    * JavaScript event listeners on the receiving `BroadcastChannel` handle the message.

6. **Identify Interactions with Web Technologies:**
    * **JavaScript:** The entire purpose is to implement the JavaScript `BroadcastChannel` API. The `Create()`, `postMessage()`, and `close()` methods are directly called from JavaScript. The `MessageEvent` is dispatched to JavaScript.
    * **HTML:**  The origin of the page determines which `BroadcastChannel`s can communicate. Iframes introduce complexities (cross-site restrictions).
    * **CSS:**  No direct interaction with CSS functionality.

7. **Consider Edge Cases and Potential Errors:**
    * **Closed Channel:** Calling `postMessage()` after `close()` throws an error.
    * **Detached Iframes/Closing Workers:**  `postMessage()` calls are ignored.
    * **Serialization Errors:** If the message can't be serialized, an exception is thrown.
    * **Cross-Origin Communication:** `BroadcastChannel` only works for the same origin.
    * **Back/Forward Cache:** Receiving a message while in the BFCache can trigger eviction.

8. **Analyze Logic and Assumptions:**
    * **Mojo for IPC:**  The code heavily relies on Mojo for inter-process communication between the renderer and the browser process.
    * **Message Ordering:** The comments explain how Mojo associated interfaces are used to ensure message ordering, especially in worker threads.
    * **Security Origins:**  Security origins are crucial for determining which channels can communicate.

9. **Think about Debugging:**
    * **User Actions:** Opening multiple tabs or iframes with the same origin and using the `BroadcastChannel` API.
    * **Breakpoints:** Setting breakpoints in `postMessage()`, `PostMessageInternal()`, `OnMessage()` to track message flow.
    * **Mojo Inspection Tools:** Tools to inspect Mojo message traffic.
    * **Browser Developer Tools:**  Console logging and event listener inspection.

10. **Structure the Explanation:** Organize the findings into clear sections like "Functionality," "Relationship to Web Technologies," "Logic and Assumptions," "User/Programming Errors," and "Debugging." Use examples to illustrate the concepts.

11. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or missing information. For instance, initially, I might have overlooked the significance of the `GetWorkerThreadSpecificProvider` and then realized its importance for message ordering in workers.

By following this structured approach, systematically analyzing the code, and connecting the low-level implementation details to the high-level web API, we can effectively understand the purpose and behavior of the `BroadcastChannel.cc` file.
这个文件 `blink/renderer/modules/broadcastchannel/broadcast_channel.cc` 是 Chromium Blink 渲染引擎中实现 **Broadcast Channel API** 的核心代码。Broadcast Channel API 允许同源的浏览器上下文（例如，不同的标签页、iframe 或 worker）之间进行基本的单向消息传递。

以下是该文件的功能列表，并附带与 JavaScript、HTML、CSS 关系的说明，逻辑推理，常见错误以及调试线索：

**功能列表:**

1. **创建 BroadcastChannel 对象:**
   - 提供 `BroadcastChannel::Create` 静态方法，用于在 JavaScript 中实例化 `BroadcastChannel` 对象。
   - 根据执行上下文（例如，主窗口或 worker）和指定的名称创建一个新的广播频道实例。
   - 记录跨域 iframe 中使用 Broadcast Channel 的情况 (通过 `UseCounter`)。

2. **发送消息 (postMessage):**
   - 实现 `BroadcastChannel::postMessage` 方法，允许 JavaScript 将数据发送到同一频道的其他监听器。
   - 对要发送的消息进行序列化 (`SerializedScriptValue::Serialize`)。
   - 处理在预渲染页面中发送消息的情况，将消息发送推迟到页面激活。
   - 调用内部方法 `PostMessageInternal` 执行实际发送。

3. **内部消息发送 (PostMessageInternal):**
   - 实现 `BroadcastChannel::PostMessageInternal` 方法，负责通过 Mojo 将序列化后的消息发送到浏览器进程。
   - 消息包含实际的数据、发送者的源（`SecurityOrigin`）和代理集群 ID (`AgentClusterID`)。
   - 考虑消息是否绑定到发送者的代理集群。

4. **关闭频道 (close):**
   - 提供 `BroadcastChannel::close` 方法，允许 JavaScript 手动关闭广播频道。
   - 设置 `explicitly_closed_` 标记。
   - 调用内部方法 `CloseInternal` 清理资源。

5. **内部关闭频道 (CloseInternal):**
   - 实现 `BroadcastChannel::CloseInternal` 方法，负责断开与浏览器进程的 Mojo 连接，释放相关资源。

6. **接收消息 (OnMessage):**
   - 实现 `BroadcastChannel::OnMessage` 方法，当从浏览器进程接收到消息时被调用。
   - 对接收到的消息进行反序列化 (`MessageEvent::Create`)。
   - 创建 `MessageEvent` 对象，并将其派发到该 `BroadcastChannel` 对象上，以便 JavaScript 监听器可以接收到。
   - 处理消息发送者和接收者是否在同一个代理集群的情况。
   - 在 Back/Forward Cache 启用时，如果页面在 BFCache 中收到广播消息，则会触发页面从 BFCache 中移除。

7. **处理错误 (OnError):**
   - 实现 `BroadcastChannel::OnError` 方法，当与浏览器进程的连接断开时被调用，通常用于清理资源。

8. **生命周期管理:**
   - 实现 `Dispose` 方法，用于在对象被垃圾回收时清理资源。
   - 实现 `ContextDestroyed` 方法，在执行上下文销毁时调用，用于清理资源。
   - 实现 `HasPendingActivity` 方法，判断频道是否处于活动状态（已连接且有消息监听器）。

9. **Mojo 集成:**
   - 使用 Mojo 进行进程间通信，与浏览器进程中的 `BroadcastChannelServiceImpl` 进行交互。
   - 使用 `mojo::Remote` 和 `mojo::PendingAssociatedReceiver`/`mojo::PendingAssociatedRemote` 来建立和管理连接。
   - 根据执行上下文（主窗口或 worker），采用不同的方式建立 Mojo 连接，以确保消息的顺序性和目标正确性。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    - 该文件实现了 JavaScript `BroadcastChannel` API 的底层逻辑。
    - JavaScript 代码通过 `new BroadcastChannel('channel-name')` 创建 `BroadcastChannel` 对象，这会调用 `BroadcastChannel::Create`。
    - JavaScript 代码调用 `broadcastChannel.postMessage('hello')` 发送消息，这会调用 `BroadcastChannel::postMessage`。
    - JavaScript 代码通过监听 `message` 事件来接收消息，例如 `broadcastChannel.onmessage = event => { ... }`，当 `BroadcastChannel::OnMessage` 处理完接收到的消息并派发 `MessageEvent` 后，该回调函数会被执行。
    - JavaScript 代码调用 `broadcastChannel.close()` 关闭频道，这会调用 `BroadcastChannel::close`。

    **举例说明 (JavaScript):**

    ```javascript
    // 页面 A
    const bc = new BroadcastChannel('my-channel');
    bc.postMessage('Hello from page A!');

    bc.onmessage = event => {
      console.log('Received message:', event.data);
    };

    // 页面 B (同一个源)
    const bc2 = new BroadcastChannel('my-channel');
    bc2.onmessage = event => {
      console.log('Received message:', event.data);
    };
    ```

* **HTML:**
    - HTML 中通过 `<script>` 标签引入的 JavaScript 代码可以使用 Broadcast Channel API。
    - `BroadcastChannel` 的通信范围是同源的，这意味着只有在相同协议、域名和端口下的页面和 worker 才能通过同一个频道通信。
    - 如果在 cross-site 的 iframe 中使用 `BroadcastChannel`，会记录使用情况，但这并不意味着可以跨域通信。

    **举例说明 (HTML):**

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Page A</title>
    </head>
    <body>
      <script>
        const bc = new BroadcastChannel('my-channel');
        bc.postMessage('Hello from page A!');

        bc.onmessage = event => {
          console.log('Page A received:', event.data);
        };
      </script>
      <iframe src="page_b.html"></iframe>
    </body>
    </html>

    <!-- page_b.html (假设与 Page A 同源) -->
    <!DOCTYPE html>
    <html>
    <head>
      <title>Page B</title>
    </head>
    <body>
      <script>
        const bc = new BroadcastChannel('my-channel');
        bc.onmessage = event => {
          console.log('Page B received:', event.data);
        };
      </script>
    </body>
    </html>
    ```

* **CSS:**
    - CSS 与 Broadcast Channel API 没有直接的功能关系。CSS 负责页面的样式和布局，而 Broadcast Channel 用于 JavaScript 之间的消息传递。

**逻辑推理与假设输入/输出:**

**假设输入:**

1. **JavaScript 调用 `postMessage`:**
    ```javascript
    const bc = new BroadcastChannel('test-channel');
    bc.postMessage({ message: 'Some data' });
    ```
2. **假设存在另一个同源的页面或 worker 监听 'test-channel'。**

**逻辑推理过程:**

1. `BroadcastChannel::postMessage` 被调用。
2. 消息 `{ message: 'Some data' }` 被序列化为 `SerializedScriptValue`。
3. `BroadcastChannel::PostMessageInternal` 被调用，通过 Mojo 将序列化的消息发送到浏览器进程。
4. 浏览器进程将消息路由到所有监听 'test-channel' 的同源 `BroadcastChannel` 实例。
5. 在接收端的 `BroadcastChannel` 实例中，`BroadcastChannel::OnMessage` 被调用。
6. 接收到的 `SerializedScriptValue` 被反序列化。
7. 一个 `MessageEvent` 被创建，其 `data` 属性包含反序列化后的 `{ message: 'Some data' }`。
8. 该 `MessageEvent` 被派发到接收端的 `BroadcastChannel` 对象。

**假设输出:**

在监听 'test-channel' 的另一个页面或 worker 的 JavaScript 控制台中，会输出：

```
Received message: {message: 'Some data'}
```

**用户或编程常见的使用错误:**

1. **跨域通信:** 尝试在不同源的页面之间使用 `BroadcastChannel` 通信，消息不会传递。
    * **错误示例 (JavaScript):**
      ```javascript
      // 页面 A (origin: http://example.com)
      const bc = new BroadcastChannel('my-channel');
      bc.postMessage('Hello');

      // 页面 B (origin: http://different-example.com)
      const bc2 = new BroadcastChannel('my-channel');
      bc2.onmessage = event => {
        console.log('Received:', event.data); // 这不会被执行
      };
      ```

2. **在 `close()` 后调用 `postMessage()`:**  会导致抛出 `InvalidStateError` 异常。
    * **错误示例 (JavaScript):**
      ```javascript
      const bc = new BroadcastChannel('my-channel');
      bc.close();
      bc.postMessage('This will throw an error'); // 抛出 InvalidStateError
      ```

3. **忘记添加 `message` 事件监听器:**  即使发送了消息，如果没有监听器，消息也会被丢弃。
    * **错误示例 (JavaScript):**
      ```javascript
      const bc = new BroadcastChannel('my-channel');
      bc.postMessage('Message sent, but no listener!');
      ```

4. **序列化失败的数据:**  如果尝试发送无法序列化的数据（例如包含循环引用的对象），`postMessage` 会抛出异常。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开多个标签页或 iframe，并且这些页面都加载了包含 `BroadcastChannel` API 使用的 JavaScript 代码。**
2. **在其中一个页面或 worker 的 JavaScript 代码中，创建了一个 `BroadcastChannel` 对象，例如 `const bc = new BroadcastChannel('my-channel');`。** 这会最终调用 `BroadcastChannel::Create`。
3. **用户在其中一个页面上执行了某些操作，触发了调用 `bc.postMessage(data)` 的代码。** 这会将执行流引导到 `BroadcastChannel::postMessage`。
4. **如果需要在预渲染页面中发送消息，则会进入预渲染处理逻辑。**
5. **`postMessage` 会调用 `PostMessageInternal`，涉及到 Mojo 接口的调用。**  可以使用 Mojo 的调试工具来跟踪这些跨进程的调用。
6. **在接收消息的页面或 worker 中，浏览器进程会将消息传递给对应的 `BroadcastChannel` 实例，最终调用 `BroadcastChannel::OnMessage`。**
7. **可以在 `BroadcastChannel::postMessage`, `BroadcastChannel::PostMessageInternal`, `BroadcastChannel::OnMessage` 等关键方法中设置断点进行调试。**
8. **检查 Mojo 连接状态 (`receiver_.is_bound()`, `remote_client_.is_connected()`) 可以帮助诊断连接问题。**
9. **利用浏览器开发者工具的 "Sources" 面板，可以查看 JavaScript 代码的执行流程，以及 `BroadcastChannel` 对象的状态。**
10. **使用 `chrome://webrtc-internals/` 可以查看更底层的进程间通信信息，虽然 Broadcast Channel 不直接涉及 WebRTC，但可以帮助理解跨进程消息传递的机制。**

总而言之，`broadcast_channel.cc` 文件是 Blink 引擎中 Broadcast Channel API 的核心实现，负责处理 JavaScript 的调用、消息的序列化和反序列化、通过 Mojo 与浏览器进程通信以及事件的派发。理解这个文件对于调试 Broadcast Channel 相关的问题至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/broadcastchannel/broadcast_channel.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/broadcastchannel/broadcast_channel.h"

#include "base/metrics/histogram_functions.h"
#include "base/notreached.h"
#include "mojo/public/cpp/bindings/pending_associated_receiver.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/navigation/renderer_eviction_reason.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

// To ensure proper ordering of messages sent to/from multiple BroadcastChannel
// instances in the same thread, this uses one BroadcastChannelProvider
// connection as basis for all connections to channels from the same thread. The
// actual connections used to send/receive messages are then created using
// associated interfaces, ensuring proper message ordering. Note that this
// approach only works in the case of workers, since each worker has it's own
// thread.
mojo::Remote<mojom::blink::BroadcastChannelProvider>&
GetWorkerThreadSpecificProvider(WorkerGlobalScope& worker_global_scope) {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      ThreadSpecific<mojo::Remote<mojom::blink::BroadcastChannelProvider>>,
      provider, ());
  if (!provider.IsSet()) {
    worker_global_scope.GetBrowserInterfaceBroker().GetInterface(
        provider->BindNewPipeAndPassReceiver());
  }
  return *provider;
}

}  // namespace

// static
BroadcastChannel* BroadcastChannel::Create(ExecutionContext* execution_context,
                                           const String& name,
                                           ExceptionState& exception_state) {
  LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(execution_context);
  if (window && window->IsCrossSiteSubframe())
    UseCounter::Count(window, WebFeature::kThirdPartyBroadcastChannel);

  return MakeGarbageCollected<BroadcastChannel>(execution_context, name);
}

BroadcastChannel::~BroadcastChannel() = default;

void BroadcastChannel::Dispose() {
  CloseInternal();
}

void BroadcastChannel::postMessage(const ScriptValue& message,
                                   ExceptionState& exception_state) {
  // If the receiver is not bound because `close` was called on this
  // BroadcastChannel instance, raise an exception per the spec. Otherwise,
  // in cases like the instance being created in an iframe that is now detached,
  // just ignore the postMessage call.
  if (!receiver_.is_bound()) {
    if (explicitly_closed_) {
      exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                        "Channel is closed");
    }
    return;
  }

  // Silently ignore the postMessage call if this BroadcastChannel instance is
  // associated with a closing worker. This case needs to be handled explicitly
  // because the mojo connection to the worker won't be torn down until the
  // worker actually goes away.
  ExecutionContext* execution_context = GetExecutionContext();
  if (execution_context->IsWorkerGlobalScope()) {
    WorkerGlobalScope* worker_global_scope =
        DynamicTo<WorkerGlobalScope>(execution_context);
    DCHECK(worker_global_scope);
    if (worker_global_scope->IsClosing()) {
      return;
    }
  }

  scoped_refptr<SerializedScriptValue> value = SerializedScriptValue::Serialize(
      message.GetIsolate(), message.V8Value(),
      SerializedScriptValue::SerializeOptions(), exception_state);
  if (exception_state.HadException())
    return;

  // Defer postMessage() from a prerendered page until page activation.
  // https://wicg.github.io/nav-speculation/prerendering.html#patch-broadcast-channel
  if (execution_context->IsWindow()) {
    Document* document = To<LocalDOMWindow>(execution_context)->document();
    if (document->IsPrerendering()) {
      document->AddPostPrerenderingActivationStep(
          WTF::BindOnce(&BroadcastChannel::PostMessageInternal,
                        WrapWeakPersistent(this), std::move(value),
                        execution_context->GetSecurityOrigin()->IsolatedCopy(),
                        execution_context->GetAgentClusterID()));
      return;
    }
  }

  PostMessageInternal(std::move(value),
                      execution_context->GetSecurityOrigin()->IsolatedCopy(),
                      execution_context->GetAgentClusterID());
}

void BroadcastChannel::PostMessageInternal(
    scoped_refptr<SerializedScriptValue> value,
    scoped_refptr<SecurityOrigin> sender_origin,
    const base::UnguessableToken sender_agent_cluster_id) {
  if (!receiver_.is_bound())
    return;
  BlinkCloneableMessage msg;
  msg.message = std::move(value);
  msg.sender_origin = std::move(sender_origin);
  msg.sender_agent_cluster_id = sender_agent_cluster_id;
  msg.locked_to_sender_agent_cluster = msg.message->IsLockedToAgentCluster();
  remote_client_->OnMessage(std::move(msg));
}

void BroadcastChannel::close() {
  explicitly_closed_ = true;
  CloseInternal();
}

void BroadcastChannel::CloseInternal() {
  remote_client_.reset();
  if (receiver_.is_bound())
    receiver_.reset();
  if (associated_remote_.is_bound())
    associated_remote_.reset();
  feature_handle_for_scheduler_.reset();
}

const AtomicString& BroadcastChannel::InterfaceName() const {
  return event_target_names::kBroadcastChannel;
}

bool BroadcastChannel::HasPendingActivity() const {
  return receiver_.is_bound() && HasEventListeners(event_type_names::kMessage);
}

void BroadcastChannel::ContextDestroyed() {
  CloseInternal();
}

void BroadcastChannel::Trace(Visitor* visitor) const {
  ExecutionContextLifecycleObserver::Trace(visitor);
  EventTarget::Trace(visitor);
  visitor->Trace(receiver_);
  visitor->Trace(remote_client_);
  visitor->Trace(associated_remote_);
}

void BroadcastChannel::OnMessage(BlinkCloneableMessage message) {
  auto* context = GetExecutionContext();

  // Queue a task to dispatch the event.
  MessageEvent* event;
  if ((!message.locked_to_sender_agent_cluster ||
       context->IsSameAgentCluster(message.sender_agent_cluster_id)) &&
      message.message->CanDeserializeIn(context)) {
    event = MessageEvent::Create(nullptr, std::move(message.message),
                                 context->GetSecurityOrigin()->ToString());
  } else {
    event = MessageEvent::CreateError(context->GetSecurityOrigin()->ToString());
  }

  if (base::FeatureList::IsEnabled(features::kBFCacheOpenBroadcastChannel) &&
      context->is_in_back_forward_cache()) {
    LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(context);
    CHECK(window);
    if (LocalFrame* frame = window->GetFrame()) {
      base::UmaHistogramEnumeration(
          "BackForwardCache.Eviction.Renderer",
          mojom::blink::RendererEvictionReason::kBroadcastChannelOnMessage);
      // We don't need to report the source location of a broadcast channel.
      frame->GetBackForwardCacheControllerHostRemote()
          .EvictFromBackForwardCache(
              mojom::blink::RendererEvictionReason::kBroadcastChannelOnMessage,
              /*source=*/nullptr);
    }
    return;
  }
  // <specdef
  // href="https://html.spec.whatwg.org/multipage/web-messaging.html#dom-broadcastchannel-postmessage">
  // <spec>The tasks must use the DOM manipulation task source, and, for
  // those where the event loop specified by the target BroadcastChannel
  // object's BroadcastChannel settings object is a window event loop,
  // must be associated with the responsible document specified by that
  // target BroadcastChannel object's BroadcastChannel settings object.
  // </spec>
  DispatchEvent(*event);
}

void BroadcastChannel::OnError() {
  CloseInternal();
}

BroadcastChannel::BroadcastChannel(ExecutionContext* execution_context,
                                   const String& name)
    : BroadcastChannel(execution_context,
                       name,
                       mojo::NullAssociatedReceiver(),
                       mojo::NullAssociatedRemote()) {}

BroadcastChannel::BroadcastChannel(
    base::PassKey<StorageAccessHandle>,
    ExecutionContext* execution_context,
    const String& name,
    mojom::blink::BroadcastChannelProvider* provider)
    : ActiveScriptWrappable<BroadcastChannel>({}),
      ExecutionContextLifecycleObserver(execution_context),
      name_(name),
      receiver_(this, execution_context),
      remote_client_(execution_context),
      associated_remote_(execution_context) {
  if (!base::FeatureList::IsEnabled(features::kBFCacheOpenBroadcastChannel)) {
    feature_handle_for_scheduler_ =
        execution_context->GetScheduler()->RegisterFeature(
            SchedulingPolicy::Feature::kBroadcastChannel,
            {SchedulingPolicy::DisableBackForwardCache()});
  }
  provider->ConnectToChannel(
      name_,
      receiver_.BindNewEndpointAndPassRemote(
          execution_context->GetTaskRunner(TaskType::kInternalDefault)),
      remote_client_.BindNewEndpointAndPassReceiver(
          execution_context->GetTaskRunner(TaskType::kInternalDefault)));
  SetupDisconnectHandlers();
}

BroadcastChannel::BroadcastChannel(
    base::PassKey<BroadcastChannelTester>,
    ExecutionContext* execution_context,
    const String& name,
    mojo::PendingAssociatedReceiver<mojom::blink::BroadcastChannelClient>
        receiver,
    mojo::PendingAssociatedRemote<mojom::blink::BroadcastChannelClient> remote)
    : BroadcastChannel(execution_context,
                       name,
                       std::move(receiver),
                       std::move(remote)) {}

BroadcastChannel::BroadcastChannel(
    ExecutionContext* execution_context,
    const String& name,
    mojo::PendingAssociatedReceiver<mojom::blink::BroadcastChannelClient>
        receiver,
    mojo::PendingAssociatedRemote<mojom::blink::BroadcastChannelClient> remote)
    : ActiveScriptWrappable<BroadcastChannel>({}),
      ExecutionContextLifecycleObserver(execution_context),
      name_(name),
      receiver_(this, execution_context),
      remote_client_(execution_context),
      associated_remote_(execution_context) {
  if (!base::FeatureList::IsEnabled(features::kBFCacheOpenBroadcastChannel)) {
    feature_handle_for_scheduler_ =
        execution_context->GetScheduler()->RegisterFeature(
            SchedulingPolicy::Feature::kBroadcastChannel,
            {SchedulingPolicy::DisableBackForwardCache()});
  }
  // Note: We cannot associate per-frame task runner here, but postTask
  //       to it manually via EnqueueEvent, since the current expectation
  //       is to receive messages even after close for which queued before
  //       close.
  //       https://github.com/whatwg/html/issues/1319
  //       Relying on Mojo binding will cancel the enqueued messages
  //       at close().

  // The BroadcastChannel spec indicates that messages should be delivered to
  // BroadcastChannel objects in the order in which they were created, so it's
  // important that the ordering of ConnectToChannel messages (used to create
  // the corresponding state in the browser process) is preserved. We accomplish
  // this using two approaches, depending on the context:
  //
  //  - In the frame case, we create a new navigation associated remote for each
  //    BroadcastChannel instance and leverage it to ensure in-order delivery
  //    and delivery to the RenderFrameHostImpl object that corresponds to the
  //    current frame.
  //
  //  - In the worker case, since each worker runs in its own thread, we use a
  //    shared remote for all BroadcastChannel objects created on that thread to
  //    ensure in-order delivery of messages to the appropriate *WorkerHost
  //    object.
  auto receiver_task_runner =
      execution_context->GetTaskRunner(TaskType::kInternalDefault);
  auto client_task_runner =
      execution_context->GetTaskRunner(TaskType::kInternalDefault);
  if (receiver.is_valid() && remote.is_valid()) {
    receiver_.Bind(std::move(receiver), receiver_task_runner);
    remote_client_.Bind(std::move(remote), client_task_runner);
  } else if (auto* window = DynamicTo<LocalDOMWindow>(execution_context)) {
    LocalFrame* frame = window->GetFrame();
    if (!frame)
      return;

    frame->GetRemoteNavigationAssociatedInterfaces()->GetInterface(
        associated_remote_.BindNewEndpointAndPassReceiver(
            execution_context->GetTaskRunner(TaskType::kInternalDefault)));
    associated_remote_->ConnectToChannel(
        name_, receiver_.BindNewEndpointAndPassRemote(receiver_task_runner),
        remote_client_.BindNewEndpointAndPassReceiver(client_task_runner));
  } else if (auto* worker_global_scope =
                 DynamicTo<WorkerGlobalScope>(execution_context)) {
    if (worker_global_scope->IsClosing())
      return;

    mojo::Remote<mojom::blink::BroadcastChannelProvider>& provider =
        GetWorkerThreadSpecificProvider(*worker_global_scope);
    provider->ConnectToChannel(
        name_, receiver_.BindNewEndpointAndPassRemote(receiver_task_runner),
        remote_client_.BindNewEndpointAndPassReceiver(client_task_runner));
  } else {
    NOTREACHED();
  }

  SetupDisconnectHandlers();
}

void BroadcastChannel::SetupDisconnectHandlers() {
  receiver_.set_disconnect_handler(
      WTF::BindOnce(&BroadcastChannel::OnError, WrapWeakPersistent(this)));
  remote_client_.set_disconnect_handler(
      WTF::BindOnce(&BroadcastChannel::OnError, WrapWeakPersistent(this)));
}

bool BroadcastChannel::IsRemoteClientConnectedForTesting() const {
  return remote_client_.is_connected();
}

}  // namespace blink

"""

```