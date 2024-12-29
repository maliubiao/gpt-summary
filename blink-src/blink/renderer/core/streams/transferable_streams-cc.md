Response:
The user wants a summary of the provided C++ code for `transferable_streams.cc`. I need to identify the main functionalities of this file within the Chromium Blink engine. Since this is part 1 of 2, I should focus on the features implemented in this specific part.

Based on the code, it seems to be implementing the logic for **transferable streams**, allowing streams of data to be transferred between different execution contexts (realms), likely using `MessagePort` for communication.

Key aspects to cover:
- Core functionality: Handling messages for data transfer (chunks), closing, and errors.
- Relationship with Javascript/HTML/CSS:  This code implements Web API features, specifically the Streams API. Examples could involve using `postMessage` with transferable streams.
- Logical reasoning:  The code handles different message types. I can outline the flow for handling a 'chunk' message as an example.
- Common user errors:  Misusing the Streams API or issues with the transfer process.
- Debugging hints: How user actions might lead to this code being executed.
- Part 1 summary: A concise overview of the file's purpose based on the implemented features in this section.
```
功能列表：

1. **实现可转移流的核心逻辑:** 该文件实现了在不同的 JavaScript 执行上下文（ realms ）之间转移数据流的功能。这允许将 `ReadableStream` 和 `WritableStream` 对象从一个上下文传递到另一个，而无需复制底层数据。

2. **定义跨 Realm 转换机制:**  文件中定义了 `CrossRealmTransformWritable` 和 `CrossRealmTransformReadable` 两个类，分别用于管理可写流和可读流在跨 Realm 传输时的状态和行为。

3. **处理消息端口通信:**  使用 `MessagePort` 作为跨 Realm 通信的通道。定义了 `MessageType` 枚举来区分不同类型的消息（拉取数据、数据块、关闭、错误）。

4. **封装和解包消息:**  提供了 `PackAndPostMessage` 和 `UnpackKeyValueObject` 函数，用于在 `MessagePort` 上发送和接收结构化的消息。消息包含类型和值两个部分。

5. **处理背压 (Backpressure):**  `CrossRealmTransformWritable` 类使用 `backpressure_promise_` 来管理背压。当接收端需要更多数据时，发送端会收到 "pull" 消息并继续发送。

6. **处理错误和关闭:** 定义了处理跨 Realm 传输中出现的错误和流关闭的逻辑。

7. **实现流算法:**  为可写流 (`CrossRealmTransformWritable`) 和可读流 (`CrossRealmTransformReadable`) 定义了 `WriteAlgorithm`, `CloseAlgorithm`, `AbortAlgorithm`, 和 `PullAlgorithm`, `CancelAlgorithm` 等流操作相关的算法。

8. **创建可转移的流:** `CrossRealmTransformWritable::CreateWritableStream` 和 `CrossRealmTransformReadable::CreateReadableStream` 方法用于创建与跨 Realm 转换相关的 `WritableStream` 和 `ReadableStream` 对象。

9. **处理 MessagePort 事件:**  使用 `CrossRealmTransformMessageListener` 和 `CrossRealmTransformErrorListener` 处理来自 `MessagePort` 的 `message` 和 `messageerror` 事件。

与 javascript, html, css 的功能关系及举例说明：

* **JavaScript (Streams API):** 该文件是 Chromium 中实现 JavaScript Streams API 中可转移流特性的核心部分。JavaScript 代码可以使用 `pipeTo()` 或 `postMessage()` 等方法来触发可转移流的创建和传输。

    **举例:**
    ```javascript
    // 在一个 worker 中创建 ReadableStream
    const readableStream = new ReadableStream({
      start(controller) {
        controller.enqueue("Hello from worker!");
        controller.close();
      }
    });

    // 获取 worker 自身的 MessagePort
    const [port1, port2] = new MessageChannel();
    navigator.serviceWorker.controller.postMessage({ type: 'port' }, [port1]);

    // 将 ReadableStream 转移到主线程
    port2.postMessage({ stream: readableStream }, [readableStream]);
    ```

* **HTML (Web Workers, MessageChannel):**  可转移流通常与 Web Workers 和 `MessageChannel` API 一起使用，以便在主线程和 worker 线程之间，或者不同的 worker 之间高效地传输数据。

    **举例:** 上面的 JavaScript 例子中使用了 `MessageChannel` 来建立通信通道，并且隐含了 Web Worker 的使用场景。

* **CSS:**  该文件直接与 CSS 功能没有直接关系。CSS 依赖于数据（例如图像、字体），这些数据可能通过 Streams API 加载，但 `transferable_streams.cc` 本身不涉及 CSS 的解析或渲染。

逻辑推理，假设输入与输出:

**假设输入:**  在 JavaScript 中，一个 `ReadableStream` 对象 `streamA` 被传递到另一个 Realm（例如通过 `postMessage`）。

**处理流程 (基于代码推断):**

1. **`postMessage` 调用:** JavaScript 调用 `postMessage(streamA, [streamA])`，其中 `streamA` 被指定为可转移对象。
2. **内部处理:** Blink 引擎识别出 `streamA` 是一个可转移的流。
3. **创建跨 Realm 转换对象:**  在发送 Realm 和接收 Realm 中分别创建 `CrossRealmTransformWritable` 和 `CrossRealmTransformReadable` 的实例，或者相反，取决于流的方向。
4. **建立消息通道:**  `MessagePort` 用于这两个 Realm 之间的通信。
5. **拉取数据 (Pull):**  接收端的 `CrossRealmTransformReadable` 会通过 `MessagePort` 发送一个 `MessageType::kPull` 消息给发送端。
6. **发送数据块 (Chunk):** 发送端的 `CrossRealmTransformWritable` 接收到 "pull" 消息后，会从原始流中读取数据块，并将其封装成 `MessageType::kChunk` 消息通过 `MessagePort` 发送出去。
7. **接收数据块:** 接收端的 `CrossRealmTransformReadable` 接收到 "chunk" 消息，并将数据添加到其关联的 `ReadableStreamDefaultController` 中，使得数据可以被下游消费者读取。
8. **关闭/错误处理:**  当发送端或原始流关闭或发生错误时，会发送 `MessageType::kClose` 或 `MessageType::kError` 消息，接收端会相应地关闭或错误其关联的流。

**假设输入:** 在 JavaScript 中，一个 `WritableStream` 对象 `streamB` 需要接收来自另一个 Realm 的数据。

**处理流程 (基于代码推断):**

1. **传递 WritableStream:** JavaScript 调用 `postMessage(streamB, [streamB])` 将 `streamB` 传递到另一个 Realm。
2. **创建跨 Realm 转换对象:**  类似地，创建 `CrossRealmTransformWritable` 和 `CrossRealmTransformReadable` 的实例。
3. **写入数据 (Write):**  在发送 Realm 中，当向跨 Realm 的 `WritableStream` 写入数据时，`CrossRealmTransformWritable::WriteAlgorithm::Run` 会被调用。
4. **发送数据块:**  `WriteAlgorithm::DoWrite` 将数据块封装成 `MessageType::kChunk` 消息并通过 `MessagePort` 发送。
5. **背压处理:**  如果接收端处理数据的速度较慢，它不会发送 "pull" 消息，发送端会进入背压状态，直到收到 "pull" 消息。
6. **接收数据块:** 接收端的 `CrossRealmTransformReadable` 接收到 "chunk" 消息，并将数据写入其内部的流。
7. **关闭/错误处理:**  类似可读流，也会处理关闭和错误消息。

用户或编程常见的使用错误：

1. **尝试多次转移同一个流:**  可转移对象只能被转移一次。如果尝试再次转移，会导致错误。

    **举例:**
    ```javascript
    const [port1, port2] = new MessageChannel();
    const stream = new ReadableStream({...});
    port2.postMessage({ stream }, [stream]);
    // 稍后尝试再次转移
    try {
      port2.postMessage({ stream }, [stream]); // 错误：流已被转移
    } catch (e) {
      console.error(e);
    }
    ```

2. **在错误的 Realm 中操作已转移的流:**  一旦流被转移，原始 Realm 中的流对象将变为不可用状态。尝试在其上调用方法会导致错误。

    **举例:**
    ```javascript
    // 在 worker 中发送流
    const [port1, port2] = new MessageChannel();
    const stream = new ReadableStream({...});
    port2.postMessage({ stream }, [stream]);

    // 在 worker 中尝试使用已转移的流
    stream.getReader().read().then(...); // 错误：流已被转移
    ```

3. **没有正确处理背压:**  如果接收端无法及时处理数据，发送端没有正确实现背压控制，可能导致内存问题或性能下降。虽然代码中实现了背压处理，但在用户 JavaScript 代码中也需要注意避免过度生产数据。

4. **传输非可序列化的数据块 (如果 `allow_per_chunk_transferring` 为 false):** 默认情况下，数据块需要可序列化才能通过 `postMessage` 传输。如果尝试传输不可序列化的对象，会导致数据克隆错误。启用 `allow_per_chunk_transferring` 后，可以直接转移数据块，但需要谨慎使用，确保接收端能够正确处理。

用户操作是如何一步步的到达这里，作为调试线索：

假设用户在网页上进行以下操作，可能触发到 `transferable_streams.cc` 中的代码执行：

1. **网页脚本创建了一个 `ReadableStream` 或 `WritableStream` 对象。**  这会涉及到 `ReadableStream` 和 `WritableStream` 相关的 C++ 代码。

2. **网页脚本获取了一个 Web Worker。**

3. **网页脚本创建了一个 `MessageChannel` 对象，并获取了两个端口。**

4. **网页脚本将一个流对象作为可转移对象通过 `postMessage` 发送给 Web Worker。**  例如：`worker.postMessage({ stream: myReadableStream }, [myReadableStream]);`  或者通过 `MessageChannel` 发送： `port2.postMessage({ stream: myReadableStream }, [myReadableStream]);`

5. **在接收端的 Web Worker 中，当接收到包含可转移流的消息时，Blink 引擎会开始处理该消息。**

6. **在消息处理过程中，Blink 引擎会识别出消息中包含可转移的 `ReadableStream` 或 `WritableStream`。**

7. **Blink 引擎会调用 `transferable_streams.cc` 中相应的代码来建立跨 Realm 的流连接。**  这涉及到创建 `CrossRealmTransformWritable` 或 `CrossRealmTransformReadable` 对象，并设置 `MessagePort` 的消息监听器。

8. **当数据开始在流中流动时，或者当需要进行背压控制、关闭或错误处理时，`transferable_streams.cc` 中的 `HandleMessage` 等方法会被调用。**

**调试线索:**

* 如果在控制台看到与 `ReadableStream` 或 `WritableStream` 相关的错误，并且涉及到跨域或跨 worker 通信，那么很可能涉及到 `transferable_streams.cc` 中的代码。
* 可以使用 Chrome 的开发者工具中的 Performance 面板或 Memory 面板来观察流的传输和内存使用情况。
* 可以设置断点在 `transferable_streams.cc` 中的关键函数，例如 `PackAndPostMessage`, `HandleMessage`, `WriteAlgorithm::Run` 等，来跟踪流的传输过程。
* 使用 `--vmodule=transferable_streams=3` 命令行参数可以启用更详细的日志输出，帮助调试可转移流的问题。

归纳一下它的功能 (第1部分):

这个 blink 引擎源代码文件的主要功能是 **实现了 JavaScript Streams API 中可转移流的跨 Realm 传输机制**。它定义了用于管理可读流和可写流在不同 JavaScript 执行上下文之间转移状态和数据的核心逻辑，包括消息的封装与解包、背压控制、错误处理和流的关闭。该文件依赖于 `MessagePort` 进行跨 Realm 通信，并为可转移的流定义了底层的算法实现。这部分代码主要关注建立连接、数据传输的基础框架和可写流的具体实现。
```
Prompt: 
```
这是目录为blink/renderer/core/streams/transferable_streams.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Functions for transferable streams. See design doc
// https://docs.google.com/document/d/1_KuZzg5c3pncLJPFa8SuVm23AP4tft6mzPCL5at3I9M/edit

#include "third_party/blink/renderer/core/streams/transferable_streams.h"

#include "third_party/blink/renderer/bindings/core/v8/promise_all.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_post_message_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_default_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/read_request.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/core/streams/readable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/core/streams/underlying_source_base.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/writable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "v8/include/v8.h"

// See the design doc at
// https://docs.google.com/document/d/1_KuZzg5c3pncLJPFa8SuVm23AP4tft6mzPCL5at3I9M/edit
// for explanation of how transferable streams are constructed from the "cross
// realm identity transform" implemented in this file.

// The peer (the other end of the MessagePort) is untrusted as it may be
// compromised. This means we have to be very careful in unpacking the messages
// from the peer. LOG(WARNING) is used for cases where a message from the peer
// appears to be invalid. If this appears during ordinary testing it indicates a
// bug.
//
// The -vmodule=transferable_streams=3 command-line argument can be used for
// debugging of the protocol.

namespace blink {

namespace {

// These are the types of messages that are sent between peers.
enum class MessageType { kPull, kChunk, kClose, kError };

// Creates a JavaScript object with a null prototype structured like {key1:
// value2, key2: value2}. This is used to create objects to be serialized by
// postMessage.
v8::Local<v8::Object> CreateKeyValueObject(v8::Isolate* isolate,
                                           const char* key1,
                                           v8::Local<v8::Value> value1,
                                           const char* key2,
                                           v8::Local<v8::Value> value2) {
  v8::Local<v8::Name> names[] = {V8AtomicString(isolate, key1),
                                 V8AtomicString(isolate, key2)};
  v8::Local<v8::Value> values[] = {value1, value2};
  static_assert(std::size(names) == std::size(values),
                "names and values arrays must be the same size");
  return v8::Object::New(isolate, v8::Null(isolate), names, values,
                         std::size(names));
}

// Unpacks an object created by CreateKeyValueObject(). |value1| and |value2|
// are out parameters. Returns false on failure.
bool UnpackKeyValueObject(ScriptState* script_state,
                          v8::Local<v8::Object> object,
                          const char* key1,
                          v8::Local<v8::Value>* value1,
                          const char* key2,
                          v8::Local<v8::Value>* value2) {
  auto* isolate = script_state->GetIsolate();
  v8::TryCatch try_catch(isolate);
  auto context = script_state->GetContext();
  if (!object->Get(context, V8AtomicString(isolate, key1)).ToLocal(value1)) {
    DLOG(WARNING) << "Error reading key: '" << key1 << "'";
    return false;
  }
  if (!object->Get(context, V8AtomicString(isolate, key2)).ToLocal(value2)) {
    DLOG(WARNING) << "Error reading key: '" << key2 << "'";
    return false;
  }
  return true;
}

// Sends a message with type |type| and contents |value| over |port|. The type
// is packed as a number with key "t", and the value is packed with key "v".
void PackAndPostMessage(ScriptState* script_state,
                        MessagePort* port,
                        MessageType type,
                        v8::Local<v8::Value> value,
                        AllowPerChunkTransferring allow_per_chunk_transferring,
                        ExceptionState& exception_state) {
  DVLOG(3) << "PackAndPostMessage sending message type "
           << static_cast<int>(type);
  v8::Context::Scope v8_context_scope(script_state->GetContext());
  auto* isolate = script_state->GetIsolate();

  // https://streams.spec.whatwg.org/#abstract-opdef-packandpostmessage
  // 1. Let message be OrdinaryObjectCreate(null).
  // 2. Perform ! CreateDataProperty(message, "type", type).
  // 3. Perform ! CreateDataProperty(message, "value", value).
  v8::Local<v8::Object> packed = CreateKeyValueObject(
      isolate, "t", v8::Number::New(isolate, static_cast<int>(type)), "v",
      value);

  // 5. Let options be «[ "transfer" → « » ]».
  PostMessageOptions* options = PostMessageOptions::Create();
  if (allow_per_chunk_transferring && type == MessageType::kChunk) {
    // Here we set a non-empty transfer list: This is a non-standardized and
    // non-default behavior, and the one who set `allow_per_chunk_transferring`
    // to true must guarantee the validity.
    HeapVector<ScriptValue> transfer;
    transfer.push_back(ScriptValue(isolate, value));
    options->setTransfer(transfer);
  }

  // 4. Let targetPort be the port with which port is entangled, if any;
  //    otherwise let it be null.
  // 6. Run the message port post message steps providing targetPort, message,
  //    and options.
  port->postMessage(script_state, ScriptValue(isolate, packed), options,
                    exception_state);
}

// Sends a kError message to the remote side, disregarding failure.
void CrossRealmTransformSendError(ScriptState* script_state,
                                  MessagePort* port,
                                  v8::Local<v8::Value> error) {
  v8::TryCatch try_catch(script_state->GetIsolate());

  // https://streams.spec.whatwg.org/#abstract-opdef-crossrealmtransformsenderror
  // 1. Perform PackAndPostMessage(port, "error", error), discarding the result.
  PackAndPostMessage(script_state, port, MessageType::kError, error,
                     AllowPerChunkTransferring(false),
                     PassThroughException(script_state->GetIsolate()));
  if (try_catch.HasCaught()) {
    DLOG(WARNING) << "Disregarding exception while sending error";
  }
}

// Same as PackAndPostMessage(), except that it attempts to handle exceptions by
// sending a kError message to the remote side. Any error from sending the
// kError message is ignored.
//
// The calling convention differs slightly from the standard to minimize
// verbosity at the calling sites. The function returns true for a normal
// completion and false for an abrupt completion.When there's an abrupt
// completion result.[[Value]] is stored into |error|.
bool PackAndPostMessageHandlingError(
    ScriptState* script_state,
    MessagePort* port,
    MessageType type,
    v8::Local<v8::Value> value,
    AllowPerChunkTransferring allow_per_chunk_transferring,
    v8::Local<v8::Value>* error) {
  v8::TryCatch try_catch(script_state->GetIsolate());
  // https://streams.spec.whatwg.org/#abstract-opdef-packandpostmessagehandlingerror
  // 1. Let result be PackAndPostMessage(port, type, value).
  PackAndPostMessage(script_state, port, type, value,
                     allow_per_chunk_transferring,
                     PassThroughException(script_state->GetIsolate()));

  // 2. If result is an abrupt completion,
  if (try_catch.HasCaught()) {
    //   1. Perform ! CrossRealmTransformSendError(port, result.[[Value]]).
    // 3. Return result as a completion record.
    *error = try_catch.Exception();
    CrossRealmTransformSendError(script_state, port, try_catch.Exception());
    return false;
  }

  return true;
}

bool PackAndPostMessageHandlingError(ScriptState* script_state,
                                     MessagePort* port,
                                     MessageType type,
                                     v8::Local<v8::Value> value,
                                     v8::Local<v8::Value>* error) {
  return PackAndPostMessageHandlingError(
      script_state, port, type, value, AllowPerChunkTransferring(false), error);
}

// Base class for CrossRealmTransformWritable and CrossRealmTransformReadable.
// Contains common methods that are used when handling MessagePort events.
class CrossRealmTransformStream
    : public GarbageCollected<CrossRealmTransformStream> {
 public:
  // Neither of the subclasses require finalization, so no destructor.

  virtual ScriptState* GetScriptState() const = 0;
  virtual MessagePort* GetMessagePort() const = 0;

  // HandleMessage() is called by CrossRealmTransformMessageListener to handle
  // an incoming message from the MessagePort.
  virtual void HandleMessage(MessageType type, v8::Local<v8::Value> value) = 0;

  // HandleError() is called by CrossRealmTransformErrorListener when an error
  // event is fired on the message port. It should error the stream.
  virtual void HandleError(v8::Local<v8::Value> error) = 0;

  virtual void Trace(Visitor*) const {}
};

// Handles MessageEvents from the MessagePort.
class CrossRealmTransformMessageListener final : public NativeEventListener {
 public:
  explicit CrossRealmTransformMessageListener(CrossRealmTransformStream* target)
      : target_(target) {}

  void Invoke(ExecutionContext*, Event* event) override {
    // TODO(ricea): Find a way to guarantee this cast is safe.
    MessageEvent* message = static_cast<MessageEvent*>(event);
    ScriptState* script_state = target_->GetScriptState();
    // The deserializer code called by message->data() looks up the ScriptState
    // from the current context, so we need to make sure it is set.
    ScriptState::Scope scope(script_state);

    // Common to
    // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformreadable
    // and
    // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformwritable.

    // 1. Let data be the data of the message.
    v8::Local<v8::Value> data = message->data(script_state).V8Value();

    // 2. Assert: Type(data) is Object.
    // In the world of the standard, this is guaranteed to be true. In the real
    // world, the data could come from a compromised renderer and be malicious.
    if (!data->IsObject()) {
      DLOG(WARNING) << "Invalid message from peer ignored (not object)";
      return;
    }

    // 3. Let type be ! Get(data, "type").
    // 4. Let value be ! Get(data, "value").
    v8::Local<v8::Value> type;
    v8::Local<v8::Value> value;
    if (!UnpackKeyValueObject(script_state, data.As<v8::Object>(), "t", &type,
                              "v", &value)) {
      DLOG(WARNING) << "Invalid message from peer ignored";
      return;
    }

    // 5. Assert: Type(type) is String
    // This implementation uses numbers for types rather than strings.
    if (!type->IsNumber()) {
      DLOG(WARNING) << "Invalid message from peer ignored (type is not number)";
      return;
    }

    int type_value = type.As<v8::Number>()->Value();
    DVLOG(3) << "MessageListener saw message type " << type_value;
    target_->HandleMessage(static_cast<MessageType>(type_value), value);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(target_);
    NativeEventListener::Trace(visitor);
  }

 private:
  const Member<CrossRealmTransformStream> target_;
};

// Handles "error" events from the MessagePort.
class CrossRealmTransformErrorListener final : public NativeEventListener {
 public:
  explicit CrossRealmTransformErrorListener(CrossRealmTransformStream* target)
      : target_(target) {}

  void Invoke(ExecutionContext*, Event*) override {
    ScriptState* script_state = target_->GetScriptState();

    // Need to enter a script scope to manipulate JavaScript objects.
    ScriptState::Scope scope(script_state);

    // Common to
    // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformreadable
    // and
    // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformwritable.

    // 1. Let error be a new "DataCloneError" DOMException.
    v8::Local<v8::Value> error = V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kDataCloneError,
        "chunk could not be cloned");

    // 2. Perform ! CrossRealmTransformSendError(port, error).
    auto* message_port = target_->GetMessagePort();
    CrossRealmTransformSendError(script_state, message_port, error);

    // 4. Disentangle port.
    message_port->close();

    DVLOG(3) << "ErrorListener saw messageerror";
    target_->HandleError(error);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(target_);
    NativeEventListener::Trace(visitor);
  }

 private:
  const Member<CrossRealmTransformStream> target_;
};

// Class for data associated with the writable side of the cross realm transform
// stream.
class CrossRealmTransformWritable final : public CrossRealmTransformStream {
 public:
  CrossRealmTransformWritable(
      ScriptState* script_state,
      MessagePort* port,
      AllowPerChunkTransferring allow_per_chunk_transferring)
      : script_state_(script_state),
        message_port_(port),
        backpressure_promise_(
            MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
                script_state)),
        allow_per_chunk_transferring_(allow_per_chunk_transferring) {}

  WritableStream* CreateWritableStream(ExceptionState&);

  ScriptState* GetScriptState() const override { return script_state_.Get(); }
  MessagePort* GetMessagePort() const override { return message_port_.Get(); }
  void HandleMessage(MessageType type, v8::Local<v8::Value> value) override;
  void HandleError(v8::Local<v8::Value> error) override;

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    visitor->Trace(message_port_);
    visitor->Trace(backpressure_promise_);
    visitor->Trace(controller_);
    CrossRealmTransformStream::Trace(visitor);
  }

 private:
  class WriteAlgorithm;
  class CloseAlgorithm;
  class AbortAlgorithm;

  const Member<ScriptState> script_state_;
  const Member<MessagePort> message_port_;
  Member<ScriptPromiseResolver<IDLUndefined>> backpressure_promise_;
  Member<WritableStreamDefaultController> controller_;
  const AllowPerChunkTransferring allow_per_chunk_transferring_;
};

class CrossRealmTransformWritable::WriteAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit WriteAlgorithm(CrossRealmTransformWritable* writable)
      : writable_(writable) {}

  // Sends the chunk to the readable side, possibly after waiting for
  // backpressure.
  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformwritable
    // 8. Let writeAlgorithm be the following steps, taking a chunk argument:
    DCHECK_EQ(argc, 1);
    auto chunk = argv[0];

    // 1. If backpressurePromise is undefined, set backpressurePromise to a
    //    promise resolved with undefined.

    // As an optimization for the common case, we call DoWrite() synchronously
    // instead. The difference is not observable because the result is only
    // visible asynchronously anyway. This avoids doing an extra allocation and
    // creating a TraceWrappertV8Reference.
    if (!writable_->backpressure_promise_) {
      return DoWrite(script_state, chunk);
    }

    // 2. Return the result of reacting to backpressurePromise with the
    //    following fulfillment steps:
    return writable_->backpressure_promise_->Promise().Then(
        script_state,
        MakeGarbageCollected<DoWriteOnResolve>(script_state, chunk, this));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(writable_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  // A promise handler which calls DoWrite() when the promise resolves.
  class DoWriteOnResolve final : public ThenCallable<IDLUndefined,
                                                     DoWriteOnResolve,
                                                     IDLPromise<IDLUndefined>> {
   public:
    DoWriteOnResolve(ScriptState* script_state,
                     v8::Local<v8::Value> chunk,
                     WriteAlgorithm* target)
        : chunk_(script_state->GetIsolate(), chunk), target_(target) {}

    ScriptPromise<IDLUndefined> React(ScriptState* script_state) {
      return target_->DoWrite(script_state,
                              chunk_.Get(script_state->GetIsolate()));
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(chunk_);
      visitor->Trace(target_);
      ThenCallable<IDLUndefined, DoWriteOnResolve,
                   IDLPromise<IDLUndefined>>::Trace(visitor);
    }

   private:
    const TraceWrapperV8Reference<v8::Value> chunk_;
    const Member<WriteAlgorithm> target_;
  };

  // Sends a chunk over the message port to the readable side.
  ScriptPromise<IDLUndefined> DoWrite(ScriptState* script_state,
                                      v8::Local<v8::Value> chunk) {
    // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformwritable
    // 8. Let writeAlgorithm be the following steps, taking a chunk argument:
    //   2. Return the result of reacting to backpressurePromise with the
    //      following fulfillment steps:
    //     1. Set backpressurePromise to a new promise.
    writable_->backpressure_promise_ =
        MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

    v8::Local<v8::Value> error;

    //     2. Let result be PackAndPostMessageHandlingError(port, "chunk",
    //        chunk).
    bool success = PackAndPostMessageHandlingError(
        script_state, writable_->message_port_, MessageType::kChunk, chunk,
        writable_->allow_per_chunk_transferring_, &error);
    //     3. If result is an abrupt completion,
    if (!success) {
      //     1. Disentangle port.
      writable_->message_port_->close();

      //     2. Return a promise rejected with result.[[Value]].
      return ScriptPromise<IDLUndefined>::Reject(script_state, error);
    }

    //     4. Otherwise, return a promise resolved with undefined.
    return ToResolvedUndefinedPromise(script_state);
  }

  const Member<CrossRealmTransformWritable> writable_;
};

class CrossRealmTransformWritable::CloseAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit CloseAlgorithm(CrossRealmTransformWritable* writable)
      : writable_(writable) {}

  // Sends a close message to the readable side and closes the message port.
  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 0);

    // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformwritable
    // 9. Let closeAlgorithm be the folowing steps:
    v8::Local<v8::Value> error;
    //   1. Perform ! PackAndPostMessage(port, "close", undefined).
    // In the standard, this can't fail. However, in the implementation failure
    // is possible, so we have to handle it.
    bool success = PackAndPostMessageHandlingError(
        script_state, writable_->message_port_, MessageType::kClose,
        v8::Undefined(script_state->GetIsolate()), &error);

    //   2. Disentangle port.
    writable_->message_port_->close();

    // Error the stream if an error occurred.
    if (!success) {
      return ScriptPromise<IDLUndefined>::Reject(script_state, error);
    }

    //   3. Return a promise resolved with undefined.
    return ToResolvedUndefinedPromise(script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(writable_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  const Member<CrossRealmTransformWritable> writable_;
};

class CrossRealmTransformWritable::AbortAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit AbortAlgorithm(CrossRealmTransformWritable* writable)
      : writable_(writable) {}

  // Sends an abort message to the readable side and closes the message port.
  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformwritable
    // 10. Let abortAlgorithm be the following steps, taking a reason argument:
    DCHECK_EQ(argc, 1);
    auto reason = argv[0];

    v8::Local<v8::Value> error;

    //   1. Let result be PackAndPostMessageHandlingError(port, "error",
    //      reason).
    bool success =
        PackAndPostMessageHandlingError(script_state, writable_->message_port_,
                                        MessageType::kError, reason, &error);

    //   2. Disentangle port.
    writable_->message_port_->close();

    //   3. If result is an abrupt completion, return a promise rejected with
    //      result.[[Value]].
    if (!success) {
      return ScriptPromise<IDLUndefined>::Reject(script_state, error);
    }

    //   4. Otherwise, return a promise resolved with undefined.
    return ToResolvedUndefinedPromise(script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(writable_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  const Member<CrossRealmTransformWritable> writable_;
};

WritableStream* CrossRealmTransformWritable::CreateWritableStream(
    ExceptionState& exception_state) {
  DCHECK(!controller_) << "CreateWritableStream() can only be called once";

  // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformwritable
  // The order of operations is significantly different from the standard, but
  // functionally equivalent.

  //  3. Let backpressurePromise be a new promise.
  // |backpressure_promise_| is initialized by the constructor.

  //  4. Add a handler for port’s message event with the following steps:
  //  6. Enable port’s port message queue.
  message_port_->setOnmessage(
      MakeGarbageCollected<CrossRealmTransformMessageListener>(this));

  //  5. Add a handler for port’s messageerror event with the following steps:
  message_port_->setOnmessageerror(
      MakeGarbageCollected<CrossRealmTransformErrorListener>(this));

  //  1. Perform ! InitializeWritableStream(stream).
  //  2. Let controller be a new WritableStreamDefaultController.
  //  7. Let startAlgorithm be an algorithm that returns undefined.
  // 11. Let sizeAlgorithm be an algorithm that returns 1.
  // 12. Perform ! SetUpWritableStreamDefaultController(stream, controller,
  //     startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, 1,
  //     sizeAlgorithm).
  auto* stream =
      WritableStream::Create(script_state_, CreateTrivialStartAlgorithm(),
                             MakeGarbageCollected<WriteAlgorithm>(this),
                             MakeGarbageCollected<CloseAlgorithm>(this),
                             MakeGarbageCollected<AbortAlgorithm>(this), 1,
                             CreateDefaultSizeAlgorithm(), exception_state);

  if (exception_state.HadException()) {
    return nullptr;
  }

  controller_ = stream->Controller();
  return stream;
}

void CrossRealmTransformWritable::HandleMessage(MessageType type,
                                                v8::Local<v8::Value> value) {
  // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformwritable
  // 4. Add a handler for port’s message event with the following steps:
  // The initial steps are done by CrossRealmTransformMessageListener
  switch (type) {
    // 6. If type is "pull",
    case MessageType::kPull:
      // 1. If backpressurePromise is not undefined,
      if (backpressure_promise_) {
        // 1. Resolve backpressurePromise with undefined.
        backpressure_promise_->Resolve();
        // 2. Set backpressurePromise to undefined.
        backpressure_promise_ = nullptr;
      }
      return;

    // 7. Otherwise if type is "error",
    case MessageType::kError:
      // 1. Perform ! WritableStreamDefaultControllerErrorIfNeeded(controller,
      //    value).
      WritableStreamDefaultController::ErrorIfNeeded(script_state_, controller_,
                                                     value);
      // 2. If backpressurePromise is not undefined,
      if (backpressure_promise_) {
        // 1. Resolve backpressurePromise with undefined.
        // 2. Set backpressurePromise to undefined.
        backpressure_promise_->Resolve();
        backpressure_promise_ = nullptr;
      }
      return;

    default:
      DLOG(WARNING) << "Invalid message from peer ignored (invalid type): "
                    << static_cast<int>(type);
      return;
  }
}

void CrossRealmTransformWritable::HandleError(v8::Local<v8::Value> error) {
  // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformwritable
  // 5. Add a handler for port’s messageerror event with the following steps:
  // The first two steps, and the last step, are performed by
  // CrossRealmTransformErrorListener.

  //   3. Perform ! WritableStreamDefaultControllerError(controller, error).
  // TODO(ricea): Fix the standard to say ErrorIfNeeded and update the above
  // line once that is done.
  WritableStreamDefaultController::ErrorIfNeeded(script_state_, controller_,
                                                 error);
}

// Class for data associated with the readable side of the cross realm transform
// stream.
class CrossRealmTransformReadable final : public CrossRealmTransformStream {
 public:
  CrossRealmTransformReadable(ScriptState* script_state, MessagePort* port)
      : script_state_(script_state), message_port_(port) {}

  ReadableStream* CreateReadableStream(ExceptionState&);

  ScriptState* GetScriptState() const override { return script_state_.Get(); }
  MessagePort* GetMessagePort() const override { return message_port_.Get(); }
  void HandleMessage(MessageType type, v8::Local<v8::Value> value) override;
  void HandleError(v8::Local<v8::Value> error) override;

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    visitor->Trace(message_port_);
    visitor->Trace(controller_);
    CrossRealmTransformStream::Trace(visitor);
  }

 private:
  class PullAlgorithm;
  class CancelAlgorithm;

  const Member<ScriptState> script_state_;
  const Member<MessagePort> message_port_;
  Member<ReadableStreamDefaultController> controller_;
};

class CrossRealmTransformReadable::PullAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit PullAlgorithm(CrossRealmTransformReadable* readable)
      : readable_(readable) {}

  // Sends a pull message to the writable side and then waits for backpressure
  // to clear.
  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 0);
    auto* isolate = script_state->GetIsolate();

    // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformreadable
    // 7. Let pullAlgorithm be the following steps:

    v8::Local<v8::Value> error;

    //   1. Perform ! PackAndPostMessage(port, "pull", undefined).
    // In the standard this can't throw an exception, but in the implementation
    // it can, so we need to be able to handle it.
    bool success = PackAndPostMessageHandlingError(
        script_state, readable_->message_port_, MessageType::kPull,
        v8::Undefined(isolate), &error);

    if (!success) {
      readable_->message_port_->close();
      return ScriptPromise<IDLUndefined>::Reject(script_state, error);
    }

    //   2. Return a promise resolved with undefined.
    // The Streams Standard guarantees that PullAlgorithm won't be called again
    // until Enqueue() is called.
    return ToResolvedUndefinedPromise(script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(readable_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  const Member<CrossRealmTransformReadable> readable_;
};

class CrossRealmTransformReadable::CancelAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit CancelAlgorithm(CrossRealmTransformReadable* readable)
      : readable_(readable) {}

  // Sends a cancel message to the writable side and closes the message port.
  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformreadable
    // 8. Let cancelAlgorithm be the following steps, taking a reason argument:
    DCHECK_EQ(argc, 1);
    auto reason = argv[0];

    v8::Local<v8::Value> error;

    //   1. Let result be PackAndPostMessageHandlingError(port, "error",
    //      reason).
    bool success =
        PackAndPostMessageHandlingError(script_state, readable_->message_port_,
                                        MessageType::kError, reason, &error);

    //   2. Disentangle port.
    readable_->message_port_->close();

    //   3. If result is an abrupt completion, return a promise rejected with
    //      result.[[Value]].
    if (!success) {
      return ScriptPromise<IDLUndefined>::Reject(script_state, error);
    }

    //   4. Otherwise, return a promise resolved with undefined.
    return ToResolvedUndefinedPromise(script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(readable_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  const Member<CrossRealmTransformReadable> readable_;
};

class ConcatenatingUnderlyingSource final : public UnderlyingSourceBase {
 public:
  class PullSource2 final : public ThenCallable<IDLUndefined,
                                                PullSource2,
                                                IDLPromise<IDLUndefined>> {
   public:
    explicit PullSource2(ConcatenatingUnderlyingSource* source)
        : source_(source) {}

    ScriptPromise<IDLUndefined> React(ScriptState* script_state) {
      return source_->source2_->Pull(
          script_state, PassThroughException(script_state->GetIsolate()));
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(source_);
      ThenCallable<IDLUndefined, PullSource2, IDLPromise<IDLUndefined>>::Trace(
          visitor);
    }

   private:
    const Member<ConcatenatingUnderlyingSource> source_;
  };

  class ConcatenatingUnderlyingSourceReadRequest final : public ReadRequest {
   public:
    explicit ConcatenatingUnderlyingSourceReadRequest(
        ConcatenatingUnderlyingSource* source,
        ScriptPromiseResolver<IDLUndefined>* resolver)
        : source_(source), resolver_(resolver) {}

    void ChunkSteps(ScriptState* script_state,
                    v8::Local<v8::Value> chunk,
                    ExceptionState&) const override {
      source_->Controller()->Enqueue(chunk);
      resolver_->Resolve();
    }

    void CloseSteps(Sc
"""


```