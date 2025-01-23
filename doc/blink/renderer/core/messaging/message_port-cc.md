Response:
Let's break down the thought process for analyzing the `message_port.cc` file.

**1. Understanding the Core Purpose:**

The first step is to identify the central entity. The file name `message_port.cc` immediately suggests it deals with message ports. Prior knowledge of web development reveals that message ports are a mechanism for inter-process or inter-thread communication, particularly between different browsing contexts (iframes, workers, etc.).

**2. Examining Key Imports:**

The `#include` directives are crucial for understanding dependencies and functionality. I'd scan these for hints about the file's role:

* **`third_party/blink/...`:**  This tells us it's part of the Blink rendering engine.
* **`.h` files (especially those mirroring the file name):**  `message_port.h` will contain the class declaration, giving a high-level overview of its members and methods.
* **`mojom` files:**  These indicate interaction with the Mojo IPC system, confirming the inter-process communication aspect. The specific `transferable_message.mojom-blink.h` is a strong indicator of how messages are structured.
* **`bindings/core/v8/...`:** This highlights the integration with JavaScript via V8, especially serialization and deserialization of messages.
* **`core/events/message_event.h`:**  This shows that the file is responsible for creating and dispatching message events.
* **`core/frame/...` and `core/workers/...`:** These namespaces confirm the involvement of message ports in communication between frames and workers.
* **`platform/bindings/...`:**  Related to binding with the underlying platform.
* **`platform/scheduler/...`:** Indicates involvement in task scheduling and attribution.

**3. Analyzing the `MessagePort` Class:**

Next, I'd focus on the `MessagePort` class definition within the file:

* **Constructor:**  How is a `MessagePort` created?  It takes an `ExecutionContext`. This is a fundamental concept in Blink, representing the context in which JavaScript executes (e.g., a window, worker). The constructor also initializes its state (closed, task runner).
* **`postMessage()`:** The most prominent method. This is the core action of sending a message. I'd look at its parameters: the message itself, transferables (like `MessagePort`s, `ArrayBuffer`s), and options. The internal steps involving serialization, disentangling ports, and Mojo communication are important.
* **`start()`:**  This suggests the port needs to be explicitly activated to receive messages.
* **`close()`:**  Shuts down the port.
* **`Disentangle()` and `Entangle()`:** These are crucial for understanding how message ports are passed between different contexts. "Disentangle" likely breaks the connection, while "Entangle" establishes it. The involvement of `MessagePortDescriptor` and Mojo pipes is key.
* **`Accept()`:** This is the receiving end. It deserializes the message and dispatches a `MessageEvent`.
* **`CreateMessageEvent()`:**  Responsible for constructing the `MessageEvent` object, including handling security checks and transferring ports.
* **`OnConnectionError()`:** Handles the scenario where the underlying communication channel breaks.
* **`HasPendingActivity()`:** Determines if the port should keep the execution context alive.

**4. Identifying Functionality and Relationships:**

Based on the above, I'd start listing the functions:

* **Core Functionality:** Inter-context communication, message sending/receiving, transfer of ownership.
* **JavaScript/HTML/CSS Relationships:**  Directly interacts with JavaScript's `postMessage()` API on `MessagePort` objects. This can be used by scripts in iframes, web workers, and service workers. HTML triggers the creation of new browsing contexts where these ports operate. CSS is less directly related, but layout changes might trigger communication between iframes.

**5. Logic Reasoning (Hypothetical Input/Output):**

For `postMessage()`, I'd imagine a simple case:

* **Input (JavaScript):** `port1.postMessage("hello", [port2]);`
* **Output (within `message_port.cc`):**  The `postMessage()` function would serialize "hello", disentangle `port2`, wrap everything into a Mojo message, and send it through the `connector_`. On the receiving end (in another `message_port.cc` instance), `Accept()` would receive the Mojo message, deserialize "hello" and the entangled version of `port2`, and dispatch a `MessageEvent`.

**6. Common Usage Errors:**

Thinking about how developers might misuse message ports helps identify potential pitfalls:

* **Forgetting to `start()`:**  The port won't receive messages if it's not started.
* **Trying to `postMessage()` to a closed port:**  Nothing happens.
* **Transferring the same port being used to send:** Leads to an error.
* **Incorrectly handling transferred ports:**  The original sender loses access to transferred ports.

**7. Debugging Scenario:**

To trace the execution, I'd think about the user actions that lead to a message being sent:

1. **User Interaction/Script Execution:** Something triggers JavaScript code to call `postMessage()` on a `MessagePort`.
2. **Blink Processing:** The browser engine calls the Blink implementation of `postMessage()` (in `message_port.cc`).
3. **Serialization & Transfer:** The message and transferables are serialized.
4. **Mojo Communication:** The serialized message is sent via Mojo to the target context.
5. **Receiving End:** The `Accept()` method in the target context's `message_port.cc` receives the message.
6. **Event Dispatch:** A `MessageEvent` is created and dispatched.
7. **JavaScript Handling:** The `onmessage` handler in the target context is executed.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the Mojo details. It's important to step back and connect the C++ code to the higher-level JavaScript API.
*  Realizing the significance of `ExecutionContext` and how it ties everything together is key.
*  Understanding the transfer mechanism and the implications of disentangling and entangling ports is crucial for accurate explanations.
*  Double-checking the purpose of each method and how they contribute to the overall goal of inter-context communication.

By following this structured approach, starting with the big picture and progressively diving into the details,  I can effectively analyze the functionality and relationships of the `message_port.cc` file.
好的，让我们来详细分析一下 `blink/renderer/core/messaging/message_port.cc` 这个文件。

**文件功能概述:**

`message_port.cc` 文件实现了 Chromium Blink 引擎中 `MessagePort` 接口的核心逻辑。 `MessagePort` 是 Web API 的一部分，它允许在不同的浏览上下文（例如，同一个页面内的 iframe，不同的窗口，或者 Web Worker）之间进行异步通信。

**核心功能点:**

1. **消息发送与接收:**  `MessagePort` 对象可以用来发送和接收消息。该文件定义了 `postMessage` 方法用于发送消息，以及通过 Mojo 接口接收消息并在目标上下文中触发 `message` 事件的机制。

2. **消息序列化与反序列化:**  发送的消息需要被序列化才能跨越不同的执行上下文或进程边界。该文件使用了 `PostMessageHelper` 来处理 JavaScript 值的序列化，并将其转换为可以通过 Mojo 传递的格式。接收端会进行反序列化。

3. **可转移对象 (Transferable Objects):**  `MessagePort` 支持转移某些类型的对象（例如 `ArrayBuffer`，`MessagePort`自身），而不是复制它们。这提高了性能，尤其对于大型数据。该文件处理了可转移对象的剥离（disentangle）和重新连接（entangle）过程。

4. **端口纠缠 (Port Entanglement):**  `MessagePort` 对象需要与另一个 `MessagePort` 对象 "纠缠" 在一起才能进行通信。该文件实现了 `Entangle` 和 `Disentangle` 方法来管理这种连接。

5. **生命周期管理:**  该文件负责管理 `MessagePort` 对象的生命周期，包括创建、启动 (`start`)、关闭 (`close`) 和销毁 (`Dispose`)。

6. **Mojo 集成:**  Chromium 使用 Mojo 作为其跨进程通信 (IPC) 机制。 `MessagePort` 的实现大量依赖 Mojo 来传递消息。

7. **安全性处理:**  该文件包含了处理跨域消息的逻辑，例如检查消息的来源 (`sender_origin`)，并可能阻止不符合安全策略的消息传递。

8. **任务调度与追踪:**  使用了 `scheduler::TaskAttributionTracker` 来追踪 `postMessage` 产生的任务，以便进行性能分析和调试。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  `MessagePort` 是一个可以直接在 JavaScript 中使用的 API。开发者可以通过 `window.postMessage` 或 `MessageChannel` 等 API 获得 `MessagePort` 对象，并调用其 `postMessage()` 方法发送消息。

   **举例:**

   ```javascript
   // 在父窗口中创建一个 iframe
   const iframe = document.createElement('iframe');
   iframe.src = 'child.html';
   document.body.appendChild(iframe);

   iframe.onload = () => {
     // 获取 iframe 的 MessagePort
     const childPort = iframe.contentWindow.postMessage; // 这是一个简化的理解，实际更复杂

     // 创建一个 MessageChannel
     const channel = new MessageChannel();
     const port1 = channel.port1;
     const port2 = channel.port2;

     // 将 port2 转移给 iframe
     iframe.contentWindow.postMessage('准备好了', '*', [port2]);

     // 监听来自 iframe 的消息
     port1.onmessage = (event) => {
       console.log('来自 iframe 的消息:', event.data);
     };

     // 启动接收消息
     port1.start();
   };
   ```

* **HTML:** HTML 用于创建包含不同浏览上下文的元素，例如 `<iframe>` 和 `<object>`，这些上下文可以使用 `MessagePort` 进行通信。

   **举例:** 上面的 JavaScript 代码片段中，`<iframe>` 元素的创建就为跨上下文消息传递提供了基础。

* **CSS:** CSS 本身与 `MessagePort` 的功能没有直接关系。然而，CSS 可能会影响页面的布局和渲染，从而间接地影响到 JavaScript 代码的执行，进而可能触发消息的发送和接收。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **JavaScript 调用:** 在一个 Web Worker 中，调用 `port.postMessage({type: 'data', payload: [1, 2, 3]}, [transferable]);`，其中 `port` 是一个 `MessagePort` 对象，`transferable` 是一个 `ArrayBuffer`。
2. **Blink 处理:**  `MessagePort::postMessage` 被调用。

**处理流程 (核心逻辑):**

1. **检查端口状态:** 检查端口是否已纠缠 (`IsEntangled`)。
2. **序列化消息:** 使用 `PostMessageHelper::SerializeMessageByMove` 将 JavaScript 对象 `{type: 'data', payload: [1, 2, 3]}` 序列化为内部表示。
3. **处理可转移对象:**  `ArrayBuffer` 被标记为可转移，并从发送方的上下文中剥离 (`DisentanglePorts`)。
4. **创建 Mojo 消息:**  创建一个包含序列化后的消息和剥离后的端口的 Mojo 消息 (`mojom::blink::TransferableMessage::WrapAsMessage`)。
5. **发送 Mojo 消息:**  通过 `connector_->Accept()` 将 Mojo 消息发送到与该端口连接的另一端。

**假设输出 (在接收端):**

1. **接收 Mojo 消息:**  接收端的 `MessagePort::Accept` 方法接收到 Mojo 消息。
2. **反序列化消息:**  `mojom::blink::TransferableMessage::DeserializeFromMessage` 将 Mojo 消息反序列化为 `BlinkTransferableMessage` 结构。
3. **重新连接端口:**  如果消息中包含转移的端口，会在接收端重新创建 `MessagePort` 对象并连接 (`EntanglePorts`)。
4. **创建 MessageEvent:**  `MessagePort::CreateMessageEvent` 创建一个 `MessageEvent` 对象，其中包含了反序列化的数据和重新连接的端口。
5. **触发 message 事件:**  接收端的 `MessagePort` 对象上触发 `message` 事件，相关的事件监听器会处理该消息。

**用户或编程常见的使用错误:**

1. **忘记调用 `start()`:**  在创建 `MessageChannel` 后，或者在接收到转移的端口后，必须调用 `port.start()` 才能开始接收消息。忘记调用会导致消息被缓存，直到调用 `start()` 或端口被垃圾回收。

   **举例:**

   ```javascript
   const channel = new MessageChannel();
   const port1 = channel.port1;
   const port2 = channel.port2;

   port1.onmessage = (event) => {
     console.log('收到消息:', event.data);
   };

   // 忘记调用 port1.start();

   port2.postMessage('你好'); // 这条消息可能不会被立即处理
   ```

2. **在已关闭的端口上发送消息:**  如果一个端口已经被关闭 (`close()` 被调用)，尝试在其上发送消息将不会有任何效果。

   **举例:**

   ```javascript
   const channel = new MessageChannel();
   const port1 = channel.port1;
   const port2 = channel.port2;

   port1.close();
   port2.postMessage('这条消息不会被发送');
   ```

3. **尝试转移发送端口自身:**  一个 `MessagePort` 不能被转移到它正在发送消息的目标。这会导致 `DataCloneError` 异常。

   **举例:**

   ```javascript
   const channel = new MessageChannel();
   const port1 = channel.port1;
   const port2 = channel.port2;

   try {
     port1.postMessage('消息', [port1]); // 尝试转移 port1 自身
   } catch (e) {
     console.error(e); // 输出 DataCloneError
   }
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在一个网页上进行了一些操作，导致一个消息被发送到另一个 iframe：

1. **用户操作:** 用户点击了页面上的一个按钮。
2. **事件监听器触发:**  与按钮关联的 JavaScript 事件监听器被触发。
3. **JavaScript 代码执行:**  事件监听器中的代码获取了目标 iframe 的 `contentWindow`，并调用了 `postMessage` 方法，或者通过一个已经建立的 `MessageChannel` 发送消息。
4. **Blink 处理 (renderer 进程):**  浏览器渲染进程中的 JavaScript 引擎执行 `postMessage` 调用，最终会调用到 `blink/renderer/core/messaging/message_port.cc` 中的 `MessagePort::postMessage` 方法。
5. **消息序列化和传递:**  如前面所述，消息被序列化，可转移对象被处理，并通过 Mojo 发送到目标 iframe 所在的渲染进程。
6. **目标进程接收:** 目标渲染进程中的 `MessagePort::Accept` 方法接收到消息。
7. **`message` 事件触发:**  目标 iframe 的 `window` 对象上会触发 `message` 事件，相关的事件处理函数会被调用。

**调试线索:**

* **断点:** 在 `MessagePort::postMessage` 和 `MessagePort::Accept` 方法中设置断点，可以观察消息的发送和接收过程。
* **Mojo 追踪:**  使用 Chromium 的 Mojo 追踪工具可以查看 Mojo 消息的传递过程，包括消息的内容和传递方向。
* **控制台输出:**  在 JavaScript 代码中使用 `console.log` 输出消息的内容和端口的状态，以便排查问题。
* **网络面板:**  虽然 `MessagePort` 不是通过网络发送消息，但在某些涉及 Service Worker 的场景下，消息可能会涉及到网络请求，可以通过网络面板查看相关信息。
* **审查元素:**  查看页面结构，确认 iframe 的存在和 URL 是否正确。

希望以上分析能够帮助你理解 `blink/renderer/core/messaging/message_port.cc` 文件的功能和它在 Chromium Blink 引擎中的作用。

### 提示词
```
这是目录为blink/renderer/core/messaging/message_port.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2008 Apple Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "third_party/blink/renderer/core/messaging/message_port.h"

#include <memory>
#include <optional>

#include "base/numerics/safe_conversions.h"
#include "base/trace_event/trace_event.h"
#include "mojo/public/cpp/base/big_buffer_mojom_traits.h"
#include "third_party/blink/public/mojom/blob/blob.mojom-blink.h"
#include "third_party/blink/public/mojom/messaging/transferable_message.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/post_message_helper.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_post_message_options.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/user_activation.h"
#include "third_party/blink/renderer/core/messaging/blink_transferable_message_mojom_traits.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_or_worklet_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_thread.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/thread_debugger.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

MessagePort::MessagePort(ExecutionContext& execution_context)
    : ActiveScriptWrappable<MessagePort>({}),
      ExecutionContextLifecycleObserver(execution_context.IsContextDestroyed()
                                            ? nullptr
                                            : &execution_context),
      // Ports in a destroyed context start out in a closed state.
      closed_(execution_context.IsContextDestroyed()),
      task_runner_(execution_context.GetTaskRunner(TaskType::kPostedMessage)),
      post_message_task_container_(
          MakeGarbageCollected<PostMessageTaskContainer>()) {}

void MessagePort::Dispose() {
  DCHECK(!started_ || !IsEntangled());
  if (!IsNeutered()) {
    // Disentangle before teardown. The MessagePortDescriptor will blow up if it
    // hasn't had its underlying handle returned to it before teardown.
    Disentangle();
  }
}

void MessagePort::postMessage(ScriptState* script_state,
                              const ScriptValue& message,
                              HeapVector<ScriptValue> transfer,
                              ExceptionState& exception_state) {
  PostMessageOptions* options = PostMessageOptions::Create();
  if (!transfer.empty())
    options->setTransfer(std::move(transfer));
  postMessage(script_state, message, options, exception_state);
}

void MessagePort::postMessage(ScriptState* script_state,
                              const ScriptValue& message,
                              const PostMessageOptions* options,
                              ExceptionState& exception_state) {
  if (!IsEntangled())
    return;
  DCHECK(GetExecutionContext());
  DCHECK(!IsNeutered());

  BlinkTransferableMessage msg;
  Transferables transferables;
  msg.message = PostMessageHelper::SerializeMessageByMove(
      script_state->GetIsolate(), message, options, transferables,
      exception_state);
  if (exception_state.HadException())
    return;
  DCHECK(msg.message);

  // Make sure we aren't connected to any of the passed-in ports.
  for (unsigned i = 0; i < transferables.message_ports.size(); ++i) {
    if (transferables.message_ports[i] == this) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Port at index " + String::Number(i) + " contains the source port.");
      return;
    }
  }
  msg.ports = MessagePort::DisentanglePorts(
      ExecutionContext::From(script_state), transferables.message_ports,
      exception_state);
  if (exception_state.HadException())
    return;
  msg.user_activation = PostMessageHelper::CreateUserActivationSnapshot(
      GetExecutionContext(), options);

  msg.sender_origin =
      GetExecutionContext()->GetSecurityOrigin()->IsolatedCopy();

  ThreadDebugger* debugger = ThreadDebugger::From(script_state->GetIsolate());
  if (debugger)
    msg.sender_stack_trace_id = debugger->StoreCurrentStackTrace("postMessage");

  msg.sender_agent_cluster_id = GetExecutionContext()->GetAgentClusterID();
  msg.locked_to_sender_agent_cluster = msg.message->IsLockedToAgentCluster();

  // Only pass the parent task ID if we're in the main world, as isolated world
  // task tracking is not yet supported. Also, only pass the parent task if the
  // port is still entangled to its initially entangled port.
  if (auto* tracker =
          scheduler::TaskAttributionTracker::From(script_state->GetIsolate());
      initially_entangled_port_ && tracker &&
      script_state->World().IsMainWorld()) {
    if (scheduler::TaskAttributionInfo* task = tracker->RunningTask()) {
      // Since `initially_entangled_port_` is not nullptr, neither should be
      // `post_message_task_container_`.
      CHECK(post_message_task_container_);
      post_message_task_container_->AddPostMessageTask(task);
      msg.parent_task_id =
          std::optional<scheduler::TaskAttributionId>(task->Id());
    } else {
      msg.parent_task_id = std::nullopt;
    }
  }

  mojo::Message mojo_message =
      mojom::blink::TransferableMessage::WrapAsMessage(std::move(msg));
  connector_->Accept(&mojo_message);
}

MessagePortChannel MessagePort::Disentangle() {
  DCHECK(!IsNeutered());
  port_descriptor_.GiveDisentangledHandle(connector_->PassMessagePipe());
  connector_ = nullptr;
  // Using a variable here places the WeakMember pointer on the stack, ensuring
  // it doesn't get GCed while it's being used.
  if (auto* entangled_port = initially_entangled_port_.Get()) {
    entangled_port->OnEntangledPortDisconnected();
  }
  OnEntangledPortDisconnected();
  return MessagePortChannel(std::move(port_descriptor_));
}

void MessagePort::start() {
  // Do nothing if we've been cloned or closed.
  if (!IsEntangled())
    return;

  DCHECK(GetExecutionContext());
  if (started_)
    return;

  started_ = true;
  connector_->StartReceiving(task_runner_);
}

void MessagePort::close() {
  if (closed_)
    return;
  // A closed port should not be neutered, so rather than merely disconnecting
  // from the mojo message pipe, also entangle with a new dangling message pipe.
  if (!IsNeutered()) {
    Disentangle().ReleaseHandle();
    MessagePortDescriptorPair pipe;
    Entangle(pipe.TakePort0(), nullptr);
  }
  closed_ = true;
}

void MessagePort::OnConnectionError() {
  close();
  // When the entangled port is disconnected, this error handler is executed,
  // so in this error handler, we dispatch the close event if close event is
  // enabled.
  if (RuntimeEnabledFeatures::MessagePortCloseEventEnabled()) {
    DispatchEvent(*Event::Create(event_type_names::kClose));
  }
}

void MessagePort::Entangle(MessagePortDescriptor port_descriptor,
                           MessagePort* port) {
  DCHECK(port_descriptor.IsValid());
  DCHECK(!connector_);

  // If the context was already destroyed, there is no reason to actually
  // entangle the port and create a Connector. No messages will ever be able to
  // be sent or received anyway, as StartReceiving will never be called.
  if (!GetExecutionContext())
    return;

  port_descriptor_ = std::move(port_descriptor);
  initially_entangled_port_ = port;
  connector_ = std::make_unique<mojo::Connector>(
      port_descriptor_.TakeHandleToEntangle(GetExecutionContext()),
      mojo::Connector::SINGLE_THREADED_SEND);
  // The raw `this` is safe despite `this` being a garbage collected object
  // because we make sure that:
  // 1. This object will not be garbage collected while it is connected and
  //    the execution context is not destroyed, and
  // 2. when the execution context is destroyed, the connector_ is reset.
  connector_->set_incoming_receiver(this);
  connector_->set_connection_error_handler(
      WTF::BindOnce(&MessagePort::OnConnectionError, WrapWeakPersistent(this)));
}

void MessagePort::Entangle(MessagePortChannel channel) {
  // We're not passing a MessagePort* for TaskAttribution purposes here, as this
  // method is only used for plugin support.
  Entangle(channel.ReleaseHandle(), nullptr);
}

const AtomicString& MessagePort::InterfaceName() const {
  return event_target_names::kMessagePort;
}

bool MessagePort::HasPendingActivity() const {
  // The spec says that entangled message ports should always be treated as if
  // they have a strong reference.
  // We'll also stipulate that the queue needs to be open (if the app drops its
  // reference to the port before start()-ing it, then it's not really entangled
  // as it's unreachable).
  // Between close() and dispatching a close event, IsEntangled() starts
  // returning false, but it is not garbage collected because a function on the
  // MessagePort is running, and the MessagePort is retained on the stack at
  // that time.
  return started_ && IsEntangled();
}

Vector<MessagePortChannel> MessagePort::DisentanglePorts(
    ExecutionContext* context,
    const MessagePortArray& ports,
    ExceptionState& exception_state) {
  if (!ports.size())
    return Vector<MessagePortChannel>();

  HeapHashSet<Member<MessagePort>> visited;
  bool has_closed_ports = false;

  // Walk the incoming array - if there are any duplicate ports, or null ports
  // or cloned ports, throw an error (per section 8.3.3 of the HTML5 spec).
  for (unsigned i = 0; i < ports.size(); ++i) {
    MessagePort* port = ports[i];
    if (!port || port->IsNeutered() || visited.Contains(port)) {
      String type;
      if (!port)
        type = "null";
      else if (port->IsNeutered())
        type = "already neutered";
      else
        type = "a duplicate";
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Port at index " + String::Number(i) + " is " + type + ".");
      return Vector<MessagePortChannel>();
    }
    if (port->closed_)
      has_closed_ports = true;
    visited.insert(port);
  }

  UseCounter::Count(context, WebFeature::kMessagePortsTransferred);
  if (has_closed_ports)
    UseCounter::Count(context, WebFeature::kMessagePortTransferClosedPort);

  // Passed-in ports passed validity checks, so we can disentangle them.
  Vector<MessagePortChannel> channels;
  channels.ReserveInitialCapacity(ports.size());
  for (unsigned i = 0; i < ports.size(); ++i)
    channels.push_back(ports[i]->Disentangle());
  return channels;
}

MessagePortArray* MessagePort::EntanglePorts(
    ExecutionContext& context,
    Vector<MessagePortChannel> channels) {
  return EntanglePorts(context,
                       WebVector<MessagePortChannel>(std::move(channels)));
}

MessagePortArray* MessagePort::EntanglePorts(
    ExecutionContext& context,
    WebVector<MessagePortChannel> channels) {
  // https://html.spec.whatwg.org/C/#message-ports
  // |ports| should be an empty array, not null even when there is no ports.
  wtf_size_t count = base::checked_cast<wtf_size_t>(channels.size());
  MessagePortArray* port_array = MakeGarbageCollected<MessagePortArray>(count);
  for (wtf_size_t i = 0; i < count; ++i) {
    auto* port = MakeGarbageCollected<MessagePort>(context);
    port->Entangle(std::move(channels[i]));
    (*port_array)[i] = port;
  }
  return port_array;
}

::MojoHandle MessagePort::EntangledHandleForTesting() const {
  return connector_->handle().value();
}

void MessagePort::Trace(Visitor* visitor) const {
  ExecutionContextLifecycleObserver::Trace(visitor);
  EventTarget::Trace(visitor);
  visitor->Trace(initially_entangled_port_);
  visitor->Trace(post_message_task_container_);
}

bool MessagePort::Accept(mojo::Message* mojo_message) {
  TRACE_EVENT0("blink", "MessagePort::Accept");

  BlinkTransferableMessage message;
  if (!mojom::blink::TransferableMessage::DeserializeFromMessage(
          std::move(*mojo_message), &message)) {
    return false;
  }

  ExecutionContext* context = GetExecutionContext();
  // WorkerGlobalScope::close() in Worker onmessage handler should prevent
  // the next message from dispatching.
  if (auto* scope = DynamicTo<WorkerGlobalScope>(context)) {
    if (scope->IsClosing())
      return true;
  }

  Event* evt = CreateMessageEvent(message);
  std::optional<scheduler::TaskAttributionTracker::TaskScope>
      task_attribution_scope;
  // Using a variable here places the WeakMember pointer on the stack, ensuring
  // it doesn't get GCed while it's being used.
  auto* entangled_port = initially_entangled_port_.Get();
  if (entangled_port && message.sender_origin &&
      message.sender_origin->IsSameOriginWith(context->GetSecurityOrigin()) &&
      context->IsSameAgentCluster(message.sender_agent_cluster_id) &&
      context->IsWindow()) {
    // TODO(crbug.com/1351643): It is not correct to assume we're running in the
    // main world here. Even though we're in Window, this could be running in an
    // isolated world context. At the same time, even if we are running in such
    // a context, the TaskScope creation here will not leak any meaningful
    // information to that world. At worst, TaskAttributionTracking will return
    // the wrong ancestor for tasks initiated by MessagePort::PostMessage inside
    // of extensions. TaskScope is using the v8::Context in order to store the
    // current TaskAttributionId in the context's
    // EmbedderPreservedContinuationData, and it's only used later for
    // attributing continuations to that original task.
    // We cannot check `content->GetCurrentWorld()->IsMainWorld()` here, as the
    // v8::Context may still be empty (and hence
    // ExecutionContext::GetCurrentWorld returns null).
    if (ScriptState* script_state = ToScriptStateForMainWorld(context)) {
      if (auto* tracker = scheduler::TaskAttributionTracker::From(
              script_state->GetIsolate())) {
        // Since `initially_entangled_port_` is not nullptr, neither should be
        // its `post_message_task_container_`.
        CHECK(entangled_port->post_message_task_container_);
        scheduler::TaskAttributionInfo* parent_task =
            entangled_port->post_message_task_container_
                ->GetAndDecrementPostMessageTask(message.parent_task_id);
        task_attribution_scope = tracker->CreateTaskScope(
            script_state, parent_task,
            scheduler::TaskAttributionTracker::TaskScopeType::kPostMessage);
      }
    }
  }

  v8::Isolate* isolate = context->GetIsolate();
  ThreadDebugger* debugger = ThreadDebugger::From(isolate);
  if (debugger)
    debugger->ExternalAsyncTaskStarted(message.sender_stack_trace_id);
  DispatchEvent(*evt);
  if (debugger)
    debugger->ExternalAsyncTaskFinished(message.sender_stack_trace_id);
  return true;
}

Event* MessagePort::CreateMessageEvent(BlinkTransferableMessage& message) {
  ExecutionContext* context = GetExecutionContext();
  // Dispatch a messageerror event when the target is a remote origin that is
  // not allowed to access the message's data.
  if (message.message->IsOriginCheckRequired()) {
    const SecurityOrigin* target_origin = context->GetSecurityOrigin();
    if (!message.sender_origin ||
        !message.sender_origin->IsSameOriginWith(target_origin)) {
      return MessageEvent::CreateError();
    }
  }

  if (message.locked_to_sender_agent_cluster) {
    DCHECK(message.sender_agent_cluster_id);
    if (!context->IsSameAgentCluster(message.sender_agent_cluster_id)) {
      UseCounter::Count(
          context,
          WebFeature::kMessageEventSharedArrayBufferDifferentAgentCluster);
      return MessageEvent::CreateError();
    }
    const SecurityOrigin* target_origin = context->GetSecurityOrigin();
    if (!message.sender_origin ||
        !message.sender_origin->IsSameOriginWith(target_origin)) {
      UseCounter::Count(
          context, WebFeature::kMessageEventSharedArrayBufferSameAgentCluster);
    } else {
      UseCounter::Count(context,
                        WebFeature::kMessageEventSharedArrayBufferSameOrigin);
    }
  }

  if (!message.message->CanDeserializeIn(context))
    return MessageEvent::CreateError();

  MessagePortArray* ports = MessagePort::EntanglePorts(
      *GetExecutionContext(), std::move(message.ports));
  UserActivation* user_activation = nullptr;
  if (message.user_activation) {
    user_activation = MakeGarbageCollected<UserActivation>(
        message.user_activation->has_been_active,
        message.user_activation->was_active);
  }

  return MessageEvent::Create(ports, std::move(message.message),
                              user_activation);
}

void MessagePort::OnEntangledPortDisconnected() {
  initially_entangled_port_ = nullptr;
  post_message_task_container_ = nullptr;
}

// PostMessageTaskContainer's implementation
//////////////////////////////////////
void MessagePort::PostMessageTaskContainer::AddPostMessageTask(
    scheduler::TaskAttributionInfo* task) {
  CHECK(task);
  auto it = post_message_tasks_.find(task->Id().value());
  if (it == post_message_tasks_.end()) {
    post_message_tasks_.insert(task->Id().value(),
                               MakeGarbageCollected<PostMessageTask>(task));
  } else {
    it->value->IncrementCounter();
  }
}

scheduler::TaskAttributionInfo*
MessagePort::PostMessageTaskContainer::GetAndDecrementPostMessageTask(
    std::optional<scheduler::TaskAttributionId> id) {
  if (!id) {
    return nullptr;
  }
  auto it = post_message_tasks_.find(id.value().value());
  CHECK(it != post_message_tasks_.end());
  CHECK(it->value);
  scheduler::TaskAttributionInfo* task = it->value->GetTask();
  if (!it->value->DecrementAndReturnCounter()) {
    post_message_tasks_.erase(it);
  }
  return task;
}

}  // namespace blink
```