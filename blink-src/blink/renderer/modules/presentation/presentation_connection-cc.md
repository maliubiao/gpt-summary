Response:
Let's break down the thought process for analyzing the `presentation_connection.cc` file.

1. **Understanding the Goal:** The request asks for a functional breakdown of the code, including its relation to web technologies, logic, potential errors, and how a user might trigger its execution.

2. **Initial Scan and Keywords:**  A quick skim reveals important terms: "Presentation API," "connection," "message," "send," "receive," "close," "terminate," "JavaScript," "Event."  This immediately points to the file being a core part of the Presentation API implementation within Blink.

3. **Core Class Identification:** The central class is `PresentationConnection`. The file also defines subclasses `ControllerPresentationConnection` and `ReceiverPresentationConnection`. This suggests a distinction between the connecting (controlling) end and the receiving end of a presentation session.

4. **Functionality Decomposition (Per Class/Major Section):**

   * **`PresentationConnection` (Base Class):**
      * **State Management:** Look for member variables and methods related to `state_` and methods like `DidChangeState`, `DidClose`. Recognize the `mojom::blink::PresentationConnectionState` enum.
      * **Message Handling:** Identify `send` methods for different data types (string, ArrayBuffer, Blob), `OnMessage`, `DidReceiveTextMessage`, `DidReceiveBinaryMessage`. Notice the message queue (`messages_`) and the blob loader (`blob_loader_`).
      * **Event Handling:** Spot the `EnqueueEvent` calls and the `AddedEventListener` method, connecting to JavaScript event listeners.
      * **Lifecycle Management:**  See `ContextDestroyed`, `ContextLifecycleStateChanged`, `CloseConnection`, `TearDown`. These relate to how the connection behaves when the page or frame is unloaded or frozen.
      * **Initialization and Destruction:**  The constructor and destructor provide clues about object creation and cleanup.
      * **Utility Methods:**  `Matches`, `CanSendMessage`, `HandleMessageQueue`.

   * **`ControllerPresentationConnection`:**
      * **Inheritance:** Note that it inherits from `PresentationConnection`.
      * **Controller Role:** The name suggests it's on the initiating side. Look for interaction with `PresentationController`.
      * **Initialization:** The `Init` method, taking `connection_remote` and `connection_receiver`, is crucial for setting up the Mojo communication channels.
      * **Control Actions:** `CloseInternal`, `TerminateInternal` – these methods seem to delegate actions to the `PresentationService`.
      * **Static `Take` methods:** These are important for how the controller connection is created and handed off, particularly in conjunction with `PresentationRequest`.

   * **`ReceiverPresentationConnection`:**
      * **Inheritance:**  Also inherits from `PresentationConnection`.
      * **Receiver Role:**  The name and interaction with `PresentationReceiver` confirm its role on the receiving end.
      * **Initialization:**  Similar to the controller, `Init` sets up Mojo communication.
      * **State Updates:** Notice the explicit state updates in `Init`.
      * **Lifecycle:**  `DidClose` removes the connection from the receiver. `TerminateInternal` seems to trigger the receiver window's termination.

5. **Relating to Web Technologies (JavaScript, HTML, CSS):**

   * **JavaScript API:**  Think about the corresponding JavaScript API. The `PresentationConnection` class directly maps to the JavaScript `PresentationConnection` object. The `send` methods, event types (`connect`, `message`, `close`, `terminate`), and the `state` property are key links.
   * **HTML:**  Consider how a presentation might be initiated. The `navigator.presentation.requestPresent()` method (though not directly in *this* file) is the starting point. The URLs involved in the connection can come from HTML.
   * **CSS:**  CSS is less directly involved but could influence the presentation's appearance on the receiving screen. It's a more indirect relationship.

6. **Logical Reasoning and Assumptions:**

   * **Input/Output of Key Methods:** Consider methods like `send`. Input: a string, ArrayBuffer, or Blob. Output: a message being sent over the Mojo connection. For state changes, input: a `mojom::blink::PresentationConnectionState`. Output: a corresponding event being fired.
   * **Assumptions:**  Assume a basic understanding of the Presentation API's goals (allowing a web page to present content on a secondary screen).

7. **Common Errors:**

   * **Invalid State:**  Trying to send data when the connection is closed is a classic error. The `CanSendMessage` method and the `ThrowPresentationDisconnectedError` function are indicators.
   * **Large ArrayBuffers:** The size checks in the `send` methods point to potential issues with sending excessively large data.
   * **Unbound Connection:** Trying to send or close when the underlying Mojo connection isn't established.

8. **User Steps and Debugging:**

   * **User Actions:**  Start from the user initiating a presentation (`requestPresent`), selecting a display, and then the sending/receiving of data.
   * **Debugging:**  Think about where breakpoints could be placed in this code to trace the connection lifecycle, message flow, and state changes.

9. **Review and Refine:**  Go back through the analysis to ensure accuracy and completeness. Check for any missing pieces or areas that could be explained more clearly. For example, initially, I might not have explicitly mentioned the role of Mojo, but recognizing the `mojom::blink` namespace and the `PendingRemote`/`PendingReceiver` types highlights its importance.

By following these steps, combining code analysis with an understanding of the underlying web technologies and the Presentation API's purpose, we can arrive at a comprehensive explanation of the `presentation_connection.cc` file's functionality.
这个文件 `blink/renderer/modules/presentation/presentation_connection.cc` 是 Chromium Blink 渲染引擎中负责实现 **Presentation API** 的关键部分。 它定义了 `PresentationConnection` 类及其子类，用于在 presenting 页面和 receiver 页面之间建立和管理连接。

以下是它的主要功能：

**1. 建立和管理 Presentation 连接:**

*   **`PresentationConnection` 类:**  这是核心类，代表一个活动的 Presentation 连接。它维护了连接的状态（connecting, connected, closed, terminated）、连接的 ID 和 URL，以及用于通信的 Mojo 接口。
*   **子类 `ControllerPresentationConnection`:**  代表由 presenting 页面创建的连接。它负责发起连接、关闭连接和终止会话。
*   **子类 `ReceiverPresentationConnection`:** 代表由 receiver 页面接收的连接。它处理接收到的消息和关闭/终止请求。
*   **连接状态管理:**  跟踪连接的不同状态，并在状态改变时触发相应的事件（例如，`connect`, `close`, `terminate`）。
*   **Mojo 接口:** 使用 Mojo IPC 框架在 presenting 和 receiver 页面之间建立通信通道。

**2. 消息传递:**

*   **`send()` 方法:**  允许 presenting 页面向 receiver 页面发送消息。支持发送文本消息、`ArrayBuffer`（二进制数据）和 `Blob` 对象。
*   **消息队列 (`messages_`)**:  当连接尚未建立或正在处理之前的消息时，会将待发送的消息放入队列中。
*   **`OnMessage()` 方法:**  处理接收到的来自另一端的消息。
*   **`DidReceiveTextMessage()` 和 `DidReceiveBinaryMessage()` 方法:**  将接收到的 Mojo 消息转换为 JavaScript 的 `MessageEvent` 并分发。
*   **Blob 处理:**  对于发送 `Blob` 对象，会使用 `BlobLoader` 类异步读取 Blob 的内容并将其作为二进制数据发送。

**3. 事件处理:**

*   **事件分发:**  继承自 `EventTarget`，能够分发各种 Presentation API 相关的事件，例如：
    *   `connect`:  连接成功建立时触发。
    *   `message`:  收到消息时触发。
    *   `close`:  连接关闭时触发。
    *   `terminate`:  连接被终止时触发。
    *   `connectionavailable` (在 `ControllerPresentationConnection` 中): 当找到可用的 presentation 显示器并建立连接后触发。

**4. 连接生命周期管理:**

*   **`close()` 方法:**  允许任一端主动关闭连接。
*   **`terminate()` 方法:**  允许 presenting 页面终止整个 presentation 会话。
*   **`DidClose()` 方法:**  处理连接关闭事件，并分发 `close` 事件。
*   **`DidChangeState()` 方法:**  处理连接状态的变化，并分发相应的事件。
*   **页面生命周期集成:**  监听页面的生命周期事件（例如，页面被冻结），并在适当的时候关闭连接。

**与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:** 这个文件是 Presentation API 的底层实现，JavaScript 代码通过全局对象 `navigator.presentation` 来访问这些功能。
    *   **举例:**  在 JavaScript 中，你可以创建一个 `PresentationConnection` 对象并监听其 `message` 事件来接收消息：
        ```javascript
        navigator.presentation.requestSession()
          .then(session => {
            const connection = session.connection;
            connection.addEventListener('message', event => {
              console.log('Received message:', event.data);
            });
            connection.send('Hello from presenting page!');
          });
        ```
    *   `send()` 方法对应 JavaScript 中 `PresentationConnection.send()`。
    *   `connect`, `message`, `close`, `terminate` 事件对应 JavaScript 中 `PresentationConnection` 对象的同名事件。
    *   `state` 属性对应 JavaScript 中 `PresentationConnection.state`。
*   **HTML:**  HTML 用于结构化 presenting 和 receiver 页面。  Receiver 页面通常会监听 `PresentationReceiver` 相关的事件来接收连接请求。
    *   **举例:**  Receiver 页面可能会有如下 JavaScript 代码：
        ```javascript
        navigator.presentation.receiver.addEventListener('connectionavailable', event => {
          const connection = event.connection;
          console.log('Connection available from:', connection.url);
          connection.addEventListener('message', event => {
            // 处理接收到的消息
          });
        });
        ```
*   **CSS:** CSS 主要用于样式化 presenting 和 receiver 页面的外观，与 `PresentationConnection` 的核心功能没有直接关系，但可以影响用户体验。

**逻辑推理 (假设输入与输出):**

*   **假设输入 (presenting 页面 JavaScript):**
    ```javascript
    let connection;
    navigator.presentation.requestSession({ url: 'https://example.com/receiver.html' })
      .then(session => {
        connection = session.connection;
        connection.send('Initial message');
      });
    ```
*   **假设输出 (`PresentationConnection::send` 方法):**
    1. `CanSendMessage` 会检查当前连接状态是否为 `CONNECTED`。
    2. 如果连接已建立，一个 `Message` 对象会被创建并添加到 `messages_` 队列中。
    3. `HandleMessageQueue` 会被调用。
    4. 由于消息类型是文本，`SendMessageToTargetConnection` 会被调用，将消息封装成 `mojom::blink::PresentationConnectionMessagePtr` 并通过 Mojo 发送。
*   **假设输入 (receiver 页面 JavaScript):**
    ```javascript
    navigator.presentation.receiver.addEventListener('connectionavailable', event => {
      const connection = event.connection;
      connection.addEventListener('message', event => {
        console.log('Receiver got:', event.data);
      });
    });
    ```
*   **假设输出 (`PresentationConnection::OnMessage` 方法在 receiver 端):**
    1. 接收到来自 presenting 端的 Mojo 消息。
    2. `OnMessage` 判断消息类型是文本。
    3. `DidReceiveTextMessage` 被调用，创建一个 `MessageEvent` 对象。
    4. 该事件被分发到 receiver 页面的 JavaScript 代码，触发 `message` 事件监听器，控制台输出 "Receiver got: Initial message"。

**用户或编程常见的使用错误:**

*   **在连接未建立时发送消息:**
    *   **错误:**  在 `PresentationConnection` 的状态不是 `CONNECTED` 时调用 `send()` 方法。
    *   **结果:**  会抛出一个 `InvalidStateError` 异常，因为 `CanSendMessage` 会检查连接状态。
    *   **代码示例:**
        ```javascript
        let connection;
        navigator.presentation.requestSession({ url: 'https://example.com/receiver.html' })
          .then(session => {
            connection = session.connection;
            // 错误：可能在连接成功建立之前就尝试发送
            connection.send('This might fail');
          });
        ```
*   **发送过大的 `ArrayBuffer`:**
    *   **错误:** 尝试发送大小超过限制的 `ArrayBuffer`。
    *   **结果:**  会抛出一个 `RangeError` 异常，因为 `send(DOMArrayBuffer*)` 会检查 `ArrayBuffer` 的大小。
    *   **代码示例:**
        ```javascript
        const largeBuffer = new ArrayBuffer(Number.MAX_SAFE_INTEGER); // 非常大的 buffer
        connection.send(largeBuffer); // 可能抛出 RangeError
        ```
*   **忘记添加事件监听器:**
    *   **错误:**  在发送或接收消息之前没有添加 `message` 事件监听器。
    *   **结果:**  消息会被发送/接收，但 JavaScript 代码无法处理这些消息，导致功能失效。
    *   **代码示例 (receiver 端缺少监听器):**
        ```javascript
        navigator.presentation.receiver.addEventListener('connectionavailable', event => {
          const connection = event.connection;
          // 错误：没有监听 'message' 事件
        });
        ```
*   **在页面卸载或冻结后尝试操作连接:**
    *   **错误:**  在 presenting 或 receiver 页面被卸载或冻结后，尝试调用 `send()`, `close()` 或 `terminate()`。
    *   **结果:**  这些操作可能会失败，因为 `PresentationConnection` 对象可能已经失效。Blink 会监听页面生命周期事件并在必要时关闭连接。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 presenting 页面触发一个需要进行 Presentation 的操作:** 例如，点击一个 "投屏" 按钮。
2. **JavaScript 代码调用 `navigator.presentation.requestSession(options)`:** 这会创建一个 `PresentationRequest` 对象，并尝试发现可用的 presentation 显示器。
3. **浏览器找到可用的显示器并提示用户选择:** 用户选择一个显示器。
4. **Blink 创建 `ControllerPresentationConnection` 对象:** 当连接成功建立后，Blink 会在 presenting 页面创建一个 `ControllerPresentationConnection` 对象，并将其传递给 JavaScript。
5. **JavaScript 代码调用 `connection.send(message)`:**  用户的操作触发了 JavaScript 代码调用 `PresentationConnection` 对象的 `send()` 方法。
6. **`PresentationConnection::send` 方法被调用:**  这是我们分析的这个文件中的代码。
7. **消息通过 Mojo 发送给 receiver 页面:**  Blink 使用 Mojo 将消息传递到 receiver 页面。
8. **Blink 在 receiver 页面创建 `ReceiverPresentationConnection` 对象 (如果尚未存在):**  并关联接收到的连接。
9. **`PresentationConnection::OnMessage` 方法在 receiver 端被调用:** 处理接收到的消息。
10. **`DidReceiveTextMessage` 或 `DidReceiveBinaryMessage` 被调用:**  将消息转换为 JavaScript 事件并分发。
11. **Receiver 页面的 JavaScript 代码处理 `message` 事件:**  用户看到 presentation 的内容或状态发生变化。

**调试线索:**

*   **在 `PresentationConnection` 的构造函数和析构函数中设置断点:**  可以了解连接何时被创建和销毁。
*   **在 `send()` 和 `OnMessage()` 方法中设置断点:**  可以跟踪消息的发送和接收过程，查看消息内容和连接状态。
*   **在 `DidChangeState()` 和 `DidClose()` 方法中设置断点:**  可以监控连接状态的变化和关闭原因。
*   **查看 Mojo 通信日志:**  可以检查底层 Mojo 消息的传递情况，帮助诊断连接问题。
*   **使用 Chrome 的开发者工具的 "审查元素" -> "Application" -> "Presentation" 面板:** 可以查看当前的 Presentation 会话和连接信息。

总而言之，`presentation_connection.cc` 文件是 Blink 引擎中实现 Web Presentation API 的核心组件，负责建立、管理和维护 presenting 页面和 receiver 页面之间的双向通信连接，并处理相关的事件和消息传递。 它与 JavaScript API 紧密关联，使得 Web 开发者能够构建跨设备的 presentation 应用。

Prompt: 
```
这是目录为blink/renderer/modules/presentation/presentation_connection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/presentation/presentation_connection.h"

#include <memory>

#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_presentation_connection_state.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/fileapi/file_error.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_client.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/presentation/presentation.h"
#include "third_party/blink/renderer/modules/presentation/presentation_connection_available_event.h"
#include "third_party/blink/renderer/modules/presentation/presentation_connection_close_event.h"
#include "third_party/blink/renderer/modules/presentation/presentation_controller.h"
#include "third_party/blink/renderer/modules/presentation/presentation_receiver.h"
#include "third_party/blink/renderer/modules/presentation/presentation_request.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

namespace {

mojom::blink::PresentationConnectionMessagePtr MakeBinaryMessage(
    const DOMArrayBuffer* buffer) {
  // Mutating the data field on the message instead of passing in an already
  // populated Vector into message constructor is more efficient since the
  // latter does not support moves.
  auto message =
      mojom::blink::PresentationConnectionMessage::NewData(Vector<uint8_t>());
  Vector<uint8_t>& data = message->get_data();
  data.AppendSpan(buffer->ByteSpan());
  return message;
}

mojom::blink::PresentationConnectionMessagePtr MakeTextMessage(
    const String& text) {
  return mojom::blink::PresentationConnectionMessage::NewMessage(text);
}

V8PresentationConnectionState::Enum ConnectionStateToEnum(
    mojom::blink::PresentationConnectionState state) {
  switch (state) {
    case mojom::blink::PresentationConnectionState::CONNECTING:
      return V8PresentationConnectionState::Enum::kConnecting;
    case mojom::blink::PresentationConnectionState::CONNECTED:
      return V8PresentationConnectionState::Enum::kConnected;
    case mojom::blink::PresentationConnectionState::CLOSED:
      return V8PresentationConnectionState::Enum::kClosed;
    case mojom::blink::PresentationConnectionState::TERMINATED:
      return V8PresentationConnectionState::Enum::kTerminated;
  }
  NOTREACHED();
}

V8PresentationConnectionCloseReason::Enum ConnectionCloseReasonToEnum(
    mojom::blink::PresentationConnectionCloseReason reason) {
  switch (reason) {
    case mojom::blink::PresentationConnectionCloseReason::CONNECTION_ERROR:
      return V8PresentationConnectionCloseReason::Enum::kError;
    case mojom::blink::PresentationConnectionCloseReason::CLOSED:
      return V8PresentationConnectionCloseReason::Enum::kClosed;
    case mojom::blink::PresentationConnectionCloseReason::WENT_AWAY:
      return V8PresentationConnectionCloseReason::Enum::kWentaway;
  }
  NOTREACHED();
}

void ThrowPresentationDisconnectedError(ExceptionState& exception_state) {
  exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                    "Presentation connection is disconnected.");
}

}  // namespace

class PresentationConnection::Message final
    : public GarbageCollected<PresentationConnection::Message> {
 public:
  Message(const String& text) : type(kMessageTypeText), text(text) {}

  Message(DOMArrayBuffer* array_buffer)
      : type(kMessageTypeArrayBuffer), array_buffer(array_buffer) {}

  Message(scoped_refptr<BlobDataHandle> blob_data_handle)
      : type(kMessageTypeBlob), blob_data_handle(std::move(blob_data_handle)) {}

  void Trace(Visitor* visitor) const { visitor->Trace(array_buffer); }

  MessageType type;
  String text;
  Member<DOMArrayBuffer> array_buffer;
  scoped_refptr<BlobDataHandle> blob_data_handle;
};

class PresentationConnection::BlobLoader final
    : public GarbageCollected<PresentationConnection::BlobLoader>,
      public FileReaderAccumulator {
 public:
  BlobLoader(scoped_refptr<BlobDataHandle> blob_data_handle,
             PresentationConnection* presentation_connection,
             scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : presentation_connection_(presentation_connection),
        loader_(
            MakeGarbageCollected<FileReaderLoader>(this,
                                                   std::move(task_runner))) {
    loader_->Start(std::move(blob_data_handle));
  }
  ~BlobLoader() override = default;

  // FileReaderAccumulator functions.
  void DidFinishLoading(FileReaderData contents) override {
    auto* buffer = std::move(contents).AsDOMArrayBuffer();
    presentation_connection_->DidFinishLoadingBlob(buffer);
  }
  void DidFail(FileErrorCode error_code) override {
    FileReaderAccumulator::DidFail(error_code);
    presentation_connection_->DidFailLoadingBlob(error_code);
  }

  void Cancel() { loader_->Cancel(); }

  void Trace(Visitor* visitor) const override {
    FileReaderAccumulator::Trace(visitor);
    visitor->Trace(presentation_connection_);
    visitor->Trace(loader_);
  }

 private:
  Member<PresentationConnection> presentation_connection_;
  Member<FileReaderLoader> loader_;
};

PresentationConnection::PresentationConnection(LocalDOMWindow& window,
                                               const String& id,
                                               const KURL& url)
    : ExecutionContextLifecycleStateObserver(&window),
      id_(id),
      url_(url),
      state_(mojom::blink::PresentationConnectionState::CONNECTING),
      connection_receiver_(this, &window),
      target_connection_(&window),
      file_reading_task_runner_(window.GetTaskRunner(TaskType::kFileReading)) {
  UpdateStateIfNeeded();
}

PresentationConnection::~PresentationConnection() {
  DCHECK(!blob_loader_);
}

void PresentationConnection::OnMessage(
    mojom::blink::PresentationConnectionMessagePtr message) {
  if (message->is_data()) {
    DidReceiveBinaryMessage(message->get_data());
  } else {
    DidReceiveTextMessage(message->get_message());
  }
}

void PresentationConnection::DidChangeState(
    mojom::blink::PresentationConnectionState state) {
  // Closed state is handled in |DidClose()|.
  DCHECK_NE(mojom::blink::PresentationConnectionState::CLOSED, state);

  if (state_ == state)
    return;

  state_ = state;

  switch (state_) {
    case mojom::blink::PresentationConnectionState::CONNECTING:
      return;
    case mojom::blink::PresentationConnectionState::CONNECTED:
      EnqueueEvent(*Event::Create(event_type_names::kConnect),
                   TaskType::kPresentation);
      return;
    case mojom::blink::PresentationConnectionState::CLOSED:
      return;
    case mojom::blink::PresentationConnectionState::TERMINATED:
      EnqueueEvent(*Event::Create(event_type_names::kTerminate),
                   TaskType::kPresentation);
      return;
  }
  NOTREACHED();
}

void PresentationConnection::DidClose(
    mojom::blink::PresentationConnectionCloseReason reason) {
  DidClose(reason, /* message */ String());
}

// static
ControllerPresentationConnection* ControllerPresentationConnection::Take(
    ScriptPromiseResolverBase* resolver,
    const mojom::blink::PresentationInfo& presentation_info,
    PresentationRequest* request) {
  DCHECK(resolver);
  DCHECK(request);

  PresentationController* controller =
      PresentationController::FromContext(resolver->GetExecutionContext());
  if (!controller)
    return nullptr;

  return Take(controller, presentation_info, request);
}

// static
ControllerPresentationConnection* ControllerPresentationConnection::Take(
    PresentationController* controller,
    const mojom::blink::PresentationInfo& presentation_info,
    PresentationRequest* request) {
  DCHECK(controller);
  DCHECK(request);

  auto* connection = MakeGarbageCollected<ControllerPresentationConnection>(
      *controller->GetSupplementable(), controller, presentation_info.id,
      presentation_info.url);
  controller->RegisterConnection(connection);

  // Fire onconnectionavailable event asynchronously.
  request->EnqueueEvent(*PresentationConnectionAvailableEvent::Create(
                            event_type_names::kConnectionavailable, connection),
                        TaskType::kPresentation);
  return connection;
}

ControllerPresentationConnection::ControllerPresentationConnection(
    LocalDOMWindow& window,
    PresentationController* controller,
    const String& id,
    const KURL& url)
    : PresentationConnection(window, id, url), controller_(controller) {}

ControllerPresentationConnection::~ControllerPresentationConnection() {}

void ControllerPresentationConnection::Trace(Visitor* visitor) const {
  visitor->Trace(controller_);
  PresentationConnection::Trace(visitor);
}

void ControllerPresentationConnection::Init(
    mojo::PendingRemote<mojom::blink::PresentationConnection> connection_remote,
    mojo::PendingReceiver<mojom::blink::PresentationConnection>
        connection_receiver) {
  // Note that it is possible for the binding to be already bound here, because
  // the ControllerPresentationConnection object could be reused when
  // reconnecting in the same frame. In this case the existing connections are
  // discarded.
  if (connection_receiver_.is_bound()) {
    connection_receiver_.reset();
    target_connection_.reset();
  }

  DidChangeState(mojom::blink::PresentationConnectionState::CONNECTING);
  target_connection_.Bind(
      std::move(connection_remote),
      GetExecutionContext()->GetTaskRunner(blink::TaskType::kPresentation));
  connection_receiver_.Bind(
      std::move(connection_receiver),
      GetExecutionContext()->GetTaskRunner(blink::TaskType::kPresentation));
}

void ControllerPresentationConnection::CloseInternal() {
  auto& service = controller_->GetPresentationService();
  if (service)
    service->CloseConnection(url_, id_);
}

void ControllerPresentationConnection::TerminateInternal() {
  auto& service = controller_->GetPresentationService();
  if (service)
    service->Terminate(url_, id_);
}

// static
ReceiverPresentationConnection* ReceiverPresentationConnection::Take(
    PresentationReceiver* receiver,
    const mojom::blink::PresentationInfo& presentation_info,
    mojo::PendingRemote<mojom::blink::PresentationConnection>
        controller_connection,
    mojo::PendingReceiver<mojom::blink::PresentationConnection>
        receiver_connection_receiver) {
  DCHECK(receiver);

  ReceiverPresentationConnection* connection =
      MakeGarbageCollected<ReceiverPresentationConnection>(
          *receiver->GetWindow(), receiver, presentation_info.id,
          presentation_info.url);
  connection->Init(std::move(controller_connection),
                   std::move(receiver_connection_receiver));

  receiver->RegisterConnection(connection);
  return connection;
}

ReceiverPresentationConnection::ReceiverPresentationConnection(
    LocalDOMWindow& window,
    PresentationReceiver* receiver,
    const String& id,
    const KURL& url)
    : PresentationConnection(window, id, url), receiver_(receiver) {}

ReceiverPresentationConnection::~ReceiverPresentationConnection() = default;

void ReceiverPresentationConnection::Init(
    mojo::PendingRemote<mojom::blink::PresentationConnection>
        controller_connection_remote,
    mojo::PendingReceiver<mojom::blink::PresentationConnection>
        receiver_connection_receiver) {
  target_connection_.Bind(
      std::move(controller_connection_remote),
      GetExecutionContext()->GetTaskRunner(blink::TaskType::kPresentation));
  connection_receiver_.Bind(
      std::move(receiver_connection_receiver),
      GetExecutionContext()->GetTaskRunner(blink::TaskType::kPresentation));

  target_connection_->DidChangeState(
      mojom::blink::PresentationConnectionState::CONNECTED);
  DidChangeState(mojom::blink::PresentationConnectionState::CONNECTED);
}

void ReceiverPresentationConnection::DidChangeState(
    mojom::blink::PresentationConnectionState state) {
  PresentationConnection::DidChangeState(state);
}

void ReceiverPresentationConnection::DidClose(
    mojom::blink::PresentationConnectionCloseReason reason) {
  PresentationConnection::DidClose(reason);
  receiver_->RemoveConnection(this);
}

void ReceiverPresentationConnection::CloseInternal() {
  // No-op
}

void ReceiverPresentationConnection::TerminateInternal() {
  // This will close the receiver window. Change the state to TERMINATED now
  // since ReceiverPresentationConnection won't get a state change notification.
  if (state_ == mojom::blink::PresentationConnectionState::TERMINATED)
    return;

  receiver_->Terminate();

  state_ = mojom::blink::PresentationConnectionState::TERMINATED;
  if (target_connection_.is_bound())
    target_connection_->DidChangeState(state_);
}

void ReceiverPresentationConnection::Trace(Visitor* visitor) const {
  visitor->Trace(receiver_);
  PresentationConnection::Trace(visitor);
}

const AtomicString& PresentationConnection::InterfaceName() const {
  return event_target_names::kPresentationConnection;
}

ExecutionContext* PresentationConnection::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

void PresentationConnection::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  EventTarget::AddedEventListener(event_type, registered_listener);
  if (event_type == event_type_names::kConnect) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kPresentationConnectionConnectEventListener);
  } else if (event_type == event_type_names::kClose) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kPresentationConnectionCloseEventListener);
  } else if (event_type == event_type_names::kTerminate) {
    UseCounter::Count(
        GetExecutionContext(),
        WebFeature::kPresentationConnectionTerminateEventListener);
  } else if (event_type == event_type_names::kMessage) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kPresentationConnectionMessageEventListener);
  }
}

void PresentationConnection::ContextDestroyed() {
  CloseConnection();
}

void PresentationConnection::ContextLifecycleStateChanged(
    mojom::FrameLifecycleState state) {
  if (state == mojom::FrameLifecycleState::kFrozen ||
      state == mojom::FrameLifecycleState::kFrozenAutoResumeMedia) {
    CloseConnection();
  }
}

void PresentationConnection::CloseConnection() {
  DoClose(mojom::blink::PresentationConnectionCloseReason::WENT_AWAY);
  target_connection_.reset();
  connection_receiver_.reset();
}

void PresentationConnection::Trace(Visitor* visitor) const {
  visitor->Trace(connection_receiver_);
  visitor->Trace(target_connection_);
  visitor->Trace(blob_loader_);
  visitor->Trace(messages_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleStateObserver::Trace(visitor);
}

V8PresentationConnectionState PresentationConnection::state() const {
  return V8PresentationConnectionState(ConnectionStateToEnum(state_));
}

void PresentationConnection::send(const String& message,
                                  ExceptionState& exception_state) {
  if (!CanSendMessage(exception_state))
    return;

  messages_.push_back(MakeGarbageCollected<Message>(message));
  HandleMessageQueue();
}

void PresentationConnection::send(DOMArrayBuffer* array_buffer,
                                  ExceptionState& exception_state) {
  DCHECK(array_buffer);
  if (!CanSendMessage(exception_state))
    return;
  if (!base::CheckedNumeric<wtf_size_t>(array_buffer->ByteLength()).IsValid()) {
    static_assert(
        4294967295 == std::numeric_limits<wtf_size_t>::max(),
        "Change the error message below if this static_assert fails.");
    exception_state.ThrowRangeError(
        "ArrayBuffer size exceeds the maximum supported size (4294967295)");
    return;
  }

  messages_.push_back(MakeGarbageCollected<Message>(array_buffer));
  HandleMessageQueue();
}

void PresentationConnection::send(
    NotShared<DOMArrayBufferView> array_buffer_view,
    ExceptionState& exception_state) {
  DCHECK(array_buffer_view);
  if (!CanSendMessage(exception_state))
    return;
  if (!base::CheckedNumeric<wtf_size_t>(array_buffer_view->byteLength())
           .IsValid()) {
    static_assert(
        4294967295 == std::numeric_limits<wtf_size_t>::max(),
        "Change the error message below if this static_assert fails.");
    exception_state.ThrowRangeError(
        "ArrayBuffer size exceeds the maximum supported size (4294967295)");
    return;
  }

  messages_.push_back(
      MakeGarbageCollected<Message>(array_buffer_view->buffer()));
  HandleMessageQueue();
}

void PresentationConnection::send(Blob* data, ExceptionState& exception_state) {
  DCHECK(data);
  if (!CanSendMessage(exception_state))
    return;

  messages_.push_back(MakeGarbageCollected<Message>(data->GetBlobDataHandle()));
  HandleMessageQueue();
}

void PresentationConnection::DoClose(
    mojom::blink::PresentationConnectionCloseReason reason) {
  if (state_ != mojom::blink::PresentationConnectionState::CONNECTING &&
      state_ != mojom::blink::PresentationConnectionState::CONNECTED) {
    return;
  }

  if (target_connection_.is_bound())
    target_connection_->DidClose(reason);

  DidClose(reason);
  CloseInternal();
  TearDown();
}

bool PresentationConnection::CanSendMessage(ExceptionState& exception_state) {
  if (state_ != mojom::blink::PresentationConnectionState::CONNECTED) {
    ThrowPresentationDisconnectedError(exception_state);
    return false;
  }

  return !!target_connection_.is_bound();
}

void PresentationConnection::HandleMessageQueue() {
  if (!target_connection_.is_bound())
    return;

  while (!messages_.empty() && !blob_loader_) {
    Message* message = messages_.front().Get();
    switch (message->type) {
      case kMessageTypeText:
        SendMessageToTargetConnection(MakeTextMessage(message->text));
        messages_.pop_front();
        break;
      case kMessageTypeArrayBuffer:
        SendMessageToTargetConnection(MakeBinaryMessage(message->array_buffer));
        messages_.pop_front();
        break;
      case kMessageTypeBlob:
        DCHECK(!blob_loader_);
        blob_loader_ = MakeGarbageCollected<BlobLoader>(
            message->blob_data_handle, this, file_reading_task_runner_);
        break;
    }
  }
}

V8BinaryType PresentationConnection::binaryType() const {
  return V8BinaryType(binary_type_);
}

void PresentationConnection::setBinaryType(const V8BinaryType& binary_type) {
  binary_type_ = binary_type.AsEnum();
}

void PresentationConnection::SendMessageToTargetConnection(
    mojom::blink::PresentationConnectionMessagePtr message) {
  if (target_connection_.is_bound())
    target_connection_->OnMessage(std::move(message));
}

void PresentationConnection::DidReceiveTextMessage(const WebString& message) {
  if (state_ != mojom::blink::PresentationConnectionState::CONNECTED)
    return;

  DispatchEvent(*MessageEvent::Create(message));
}

void PresentationConnection::DidReceiveBinaryMessage(
    base::span<const uint8_t> data) {
  if (state_ != mojom::blink::PresentationConnectionState::CONNECTED)
    return;

  switch (binary_type_) {
    case V8BinaryType::Enum::kBlob: {
      auto blob_data = std::make_unique<BlobData>();
      blob_data->AppendBytes(data);
      auto* blob = MakeGarbageCollected<Blob>(
          BlobDataHandle::Create(std::move(blob_data), data.size()));
      DispatchEvent(*MessageEvent::Create(blob));
      return;
    }
    case V8BinaryType::Enum::kArraybuffer:
      DOMArrayBuffer* buffer = DOMArrayBuffer::Create(data);
      DispatchEvent(*MessageEvent::Create(buffer));
      return;
  }
  NOTREACHED();
}

mojom::blink::PresentationConnectionState PresentationConnection::GetState()
    const {
  return state_;
}

void PresentationConnection::close() {
  DoClose(mojom::blink::PresentationConnectionCloseReason::CLOSED);
}

void PresentationConnection::terminate() {
  if (state_ != mojom::blink::PresentationConnectionState::CONNECTED)
    return;

  TerminateInternal();
  TearDown();
}

bool PresentationConnection::Matches(const String& id, const KURL& url) const {
  return url_ == url && id_ == id;
}

void PresentationConnection::DidClose(
    mojom::blink::PresentationConnectionCloseReason reason,
    const String& message) {
  if (state_ == mojom::blink::PresentationConnectionState::CLOSED ||
      state_ == mojom::blink::PresentationConnectionState::TERMINATED) {
    return;
  }

  state_ = mojom::blink::PresentationConnectionState::CLOSED;
  EnqueueEvent(*PresentationConnectionCloseEvent::Create(
                   event_type_names::kClose,
                   ConnectionCloseReasonToEnum(reason), message),
               TaskType::kPresentation);
}

void PresentationConnection::DidFinishLoadingBlob(DOMArrayBuffer* buffer) {
  DCHECK(!messages_.empty());
  DCHECK_EQ(messages_.front()->type, kMessageTypeBlob);
  DCHECK(buffer);
  if (!base::CheckedNumeric<wtf_size_t>(buffer->ByteLength()).IsValid()) {
    // TODO(crbug.com/1036565): generate error message? The problem is that the
    // content of {buffer} is copied into a WTF::Vector, but a DOMArrayBuffer
    // has a bigger maximum size than a WTF::Vector. Ignore the current failed
    // blob item and continue with next items.
    messages_.pop_front();
    blob_loader_.Clear();
    HandleMessageQueue();
  }
  // Send the loaded blob immediately here and continue processing the queue.
  SendMessageToTargetConnection(MakeBinaryMessage(buffer));

  messages_.pop_front();
  blob_loader_.Clear();
  HandleMessageQueue();
}

void PresentationConnection::DidFailLoadingBlob(FileErrorCode error_code) {
  DCHECK(!messages_.empty());
  DCHECK_EQ(messages_.front()->type, kMessageTypeBlob);
  // TODO(crbug.com/1036565): generate error message?
  // Ignore the current failed blob item and continue with next items.
  messages_.pop_front();
  blob_loader_.Clear();
  HandleMessageQueue();
}

void PresentationConnection::TearDown() {
  // Cancel current Blob loading if any.
  if (blob_loader_) {
    blob_loader_->Cancel();
    blob_loader_.Clear();
  }
  messages_.clear();
}

}  // namespace blink

"""

```