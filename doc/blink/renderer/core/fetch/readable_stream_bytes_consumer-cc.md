Response:
Let's break down the thought process for analyzing this code and generating the detailed explanation.

1. **Understand the Core Purpose:** The filename `readable_stream_bytes_consumer.cc` and the class name `ReadableStreamBytesConsumer` immediately suggest its function: consuming byte data from a ReadableStream. The "consumer" part indicates it's actively taking data, not providing it.

2. **Identify Key Dependencies:**  Scan the `#include` statements. This reveals:
    * `<string.h>` and `<algorithm>`: Standard C++ utilities, likely for memory manipulation or data handling.
    * `third_party/blink/renderer/bindings/...`:  Interaction with JavaScript through V8 bindings. This is a strong indicator of JS/Web API involvement.
    * `third_party/blink/renderer/core/execution_context/...`:  Relates to the execution environment of JavaScript, including event loops.
    * `third_party/blink/renderer/core/streams/...`: This is a direct link to the Streams API, confirming the core purpose.
    * `third_party/blink/renderer/platform/bindings/...`: Further V8 binding support.
    * `third_party/blink/renderer/platform/scheduler/...`: Indicates asynchronous operations and event handling.
    * `third_party/blink/renderer/platform/wtf/...`:  Blink-specific utilities, including string handling (`WTFString`).
    * `v8/include/v8.h`: The V8 JavaScript engine itself.

3. **Analyze the Class Structure:**  Look at the class definition and its members:
    * `script_state_`:  Clearly ties this class to a JavaScript execution context.
    * `reader_`:  A `ReadableStreamDefaultReader`, the primary interface for reading from a ReadableStream.
    * `client_`: A `Client` interface, suggesting a callback mechanism for notifying other parts of the system.
    * `pending_buffer_`:  Stores the currently being processed chunk of data.
    * `pending_offset_`: Tracks the current position within `pending_buffer_`.
    * `state_`:  An enum (`PublicState`) likely representing the current status of the consumer (readable, closed, errored).
    * `is_reading_`, `is_inside_read_`: Flags to manage the asynchronous read process.
    * The inner class `BytesConsumerReadRequest`:  Implements the `ReadRequest` interface, which is how the `ReadableStreamDefaultReader` provides data.

4. **Examine Key Methods:**
    * **Constructor (`ReadableStreamBytesConsumer`)**: Takes a `ScriptState` and a `ReadableStream`, acquiring a reader. This is the initialization point.
    * **Destructor (`~ReadableStreamBytesConsumer`)**:  No explicit deallocation, likely relying on RAII and garbage collection.
    * **`BeginRead`**:  The core method for initiating a read. It checks the current state, returns data from the `pending_buffer_` if available, or starts an asynchronous read operation. The `base::span<const char>& buffer` argument strongly suggests it's providing raw byte access.
    * **`EndRead`**: Called after `BeginRead` has provided a buffer, indicating how many bytes were consumed. It updates the `pending_offset_` and handles the case where the entire chunk has been read. The check for `IsDetached()` is crucial and highlights a potential edge case with transferable objects.
    * **`SetClient` / `ClearClient`**:  Manages the `client_` callback.
    * **`Cancel`**:  Attempts to cancel the underlying ReadableStream. The check for `ScriptForbiddenScope` is important for understanding scenarios where cancellation might not be possible.
    * **`GetPublicState` / `GetError`**:  Provide status information.
    * **`OnRead`**: Called when a new chunk of data is available from the ReadableStream. It handles potential re-entrancy by using `EnqueueMicrotask`.
    * **`OnReadDone`**: Called when the ReadableStream is closed.
    * **`OnRejected`**: Called when an error occurs on the ReadableStream.
    * **`SetErrored`**:  Sets the consumer's state to error.

5. **Connect to JavaScript/Web APIs:** Based on the identified dependencies and method names, it's clear this code is part of the implementation of the JavaScript Streams API. Specifically, it handles reading byte streams.

6. **Infer Relationships and Examples:**
    * **`fetch()`**:  A prime example of how this code is used. The response body can be a ReadableStream.
    * **`FileReader`**: Another API that deals with streams of data.
    * **`<video>`/`<audio>`**: While less direct, the media source extensions (MSE) also involve streaming data.
    * **WebSockets**:  Can also use streams for data transfer.

7. **Consider Error Scenarios:** The `IsDetached()` check in `BeginRead` and `EndRead` is a key point for user errors. Transferring an `ArrayBuffer` (underlying a `Uint8Array`) while it's being processed can lead to unexpected errors.

8. **Trace User Actions (Debugging Clues):**  Think about the sequence of events that would lead to this code being executed. A user initiates a fetch, the browser receives data, and the `ReadableStreamBytesConsumer` is created to process the response body.

9. **Structure the Explanation:** Organize the findings into logical sections: functionality, relationship to web technologies, logical reasoning, common errors, and debugging.

10. **Refine and Elaborate:**  Review the generated explanation for clarity, completeness, and accuracy. Add details and examples to make it more understandable. For instance, explicitly explain the role of the `BytesConsumerReadRequest` inner class.

Self-Correction/Refinement during the process:

* **Initial Thought:**  Maybe it's just about reading files.
* **Correction:** The inclusion of `ReadableStream`, `fetch`, and V8 bindings strongly suggests it's a more general-purpose stream consumer for web APIs, not just local files.

* **Initial Thought:** Focus only on the direct methods called by JS.
* **Correction:**  It's important to understand the underlying mechanisms, like the `ReadRequest` interface and how asynchronous operations are handled with `EnqueueMicrotask`.

* **Initial Thought:**  Just list the errors.
* **Correction:** Provide a concrete example of *how* a user might encounter the `IsDetached()` error (transferring an ArrayBuffer).

By following these steps, iteratively analyzing the code, and connecting the dots between different parts of the Chromium/Blink architecture, we can arrive at a comprehensive and accurate explanation of the `ReadableStreamBytesConsumer`.
这个文件 `readable_stream_bytes_consumer.cc` 定义了 `blink::ReadableStreamBytesConsumer` 类，它是 Chromium Blink 渲染引擎中用于从 JavaScript 的 `ReadableStream` 中读取 **字节数据** 的一个消费者。更具体地说，它允许 C++ 代码以同步的方式（对于调用者而言）从一个异步的 JavaScript `ReadableStream` 中获取字节数据块。

以下是它的主要功能：

**核心功能：**

1. **从 `ReadableStream` 中消费字节:**  `ReadableStreamBytesConsumer` 封装了从 JavaScript `ReadableStream` 读取数据的复杂性。它使用 `ReadableStreamDefaultReader` 与 JavaScript 端的流进行交互。
2. **提供同步的字节访问接口:**  尽管 `ReadableStream` 本身是异步的，但 `ReadableStreamBytesConsumer` 提供了 `BeginRead` 和 `EndRead` 方法，使得 C++ 调用者可以像处理同步数据一样进行操作。`BeginRead` 会尝试返回一个指向可用字节的 `base::span`，如果数据尚未准备好，则返回一个指示需要等待的信号。
3. **处理异步读取:** 当 `BeginRead` 被调用且没有可用数据时，它会启动一个异步的读取操作。当 JavaScript 端提供数据时，会通过回调（`OnRead`）通知 `ReadableStreamBytesConsumer`。
4. **管理读取状态:**  它维护了内部状态（例如，是否正在读取，是否已关闭或出错）来跟踪流的当前状态。
5. **处理流的结束和错误:** 它能正确处理 `ReadableStream` 的关闭 (`OnReadDone`) 和错误 (`OnRejected`)，并通知其客户端。
6. **管理 `Uint8Array` 数据块:**  它接收来自 JavaScript 的 `Uint8Array` 作为数据块，并将其提供给 C++ 客户端。
7. **处理 `ArrayBuffer` 分离:**  它考虑到了 `Uint8Array` 底层的 `ArrayBuffer` 可能被分离的情况（例如，通过 `postMessage` 传输），并在这种情况下处理错误。
8. **与事件循环集成:**  为了处理异步操作，它使用了 Blink 的事件循环 (`scheduler::EventLoop`)，例如在 `OnRead` 等回调中，如果当前正处于读取操作的中间，会将任务添加到微任务队列中。

**与 JavaScript, HTML, CSS 的关系：**

`ReadableStreamBytesConsumer` 直接与 JavaScript 的 `ReadableStream` API 相关，而 `ReadableStream` 是 Web API 的一部分，因此它与 JavaScript 有着直接的联系。

**举例说明：**

* **`fetch()` API:**  当你在 JavaScript 中使用 `fetch()` API 发起网络请求时，响应的 `body` 属性可能是一个 `ReadableStream`。浏览器内部的 C++ 网络层会使用 `ReadableStreamBytesConsumer` 来读取这个流中的字节数据，然后将这些数据传递给其他 Blink 组件进行处理，例如渲染引擎解析 HTML 或 CSS，或者 JavaScript 代码通过 `response.body.getReader().read()` 方法读取数据。

   **假设输入与输出（针对 `fetch()`）：**

   * **假设输入 (用户操作):** 用户在浏览器中访问一个页面，该页面执行了以下 JavaScript 代码：
     ```javascript
     fetch('https://example.com/data.bin')
       .then(response => response.body.getReader().read())
       .then(result => {
         if (result.done) {
           console.log('读取完成');
         } else {
           console.log('读取到数据:', result.value); // result.value 是一个 Uint8Array
         }
       });
     ```
   * **内部流程:** 当 `response.body.getReader().read()` 被调用时，JavaScript 会与底层的 C++ 代码交互。Blink 的网络层会创建一个 `ReadableStreamBytesConsumer` 来读取响应体 `ReadableStream` 中的字节数据。
   * **`ReadableStreamBytesConsumer` 的假设输入:** 来自网络层的 `ReadableStream` 对象。
   * **`ReadableStreamBytesConsumer` 的假设输出:** 当 `BeginRead` 被调用时，它会返回一个 `base::span<const char>`，指向从网络接收到的部分字节数据。`EndRead` 会告知消费了多少字节。当数据可用时，`OnRead` 回调会被调用，参数是一个包含数据块的 `DOMUint8Array`。

* **`FileReader` API:**  当 JavaScript 使用 `FileReader` API 读取本地文件时，`FileReader` 内部也会使用 `ReadableStream` 来表示文件内容。`ReadableStreamBytesConsumer` 可以用来从这个 `ReadableStream` 中读取文件内容。

   **假设输入与输出（针对 `FileReader`）：**

   * **假设输入 (用户操作):** 用户使用 `<input type="file">` 元素选择了一个本地文件，并且 JavaScript 代码如下：
     ```javascript
     const fileInput = document.querySelector('input[type="file"]');
     fileInput.addEventListener('change', () => {
       const file = fileInput.files[0];
       const reader = new FileReader();
       reader.onload = () => {
         // reader.result 可能是 ArrayBuffer
       };
       reader.readAsArrayBuffer(file);
     });
     ```
   * **内部流程:**  当 `reader.readAsArrayBuffer(file)` 被调用时，Blink 会创建一个表示文件内容的 `ReadableStream`。
   * **`ReadableStreamBytesConsumer` 的假设输入:**  表示文件内容的 `ReadableStream` 对象。
   * **`ReadableStreamBytesConsumer` 的假设输出:** 类似于 `fetch()` 的例子，通过 `BeginRead` 和 `EndRead` 提供字节数据，并通过 `OnRead` 回调提供 `DOMUint8Array`。

**与 HTML 和 CSS 的关系较为间接。** 当浏览器下载 HTML、CSS 或其他资源时，这些资源的内容通常会通过 `ReadableStream` 进行传输和处理。`ReadableStreamBytesConsumer` 在这个过程中扮演着读取字节数据的角色，这些字节数据最终会被 HTML 解析器、CSS 解析器等组件消费。

**用户或编程常见的使用错误：**

1. **在错误的线程或上下文中使用:**  `ReadableStreamBytesConsumer` 依赖于特定的 Blink 线程和上下文。在不合适的线程调用其方法可能会导致崩溃或未定义的行为。
2. **未正确处理异步性:**  虽然 `ReadableStreamBytesConsumer` 提供了类似同步的接口，但其底层操作是异步的。调用者需要理解 `BeginRead` 可能会返回 `kShouldWait`，并适当地处理这种情况，例如通过事件循环等待通知。
3. **在 JavaScript 端过早关闭或取消流:**  如果在 C++ 代码还在尝试读取数据时，JavaScript 代码关闭或取消了 `ReadableStream`，`ReadableStreamBytesConsumer` 需要能够正确处理这种情况，避免出现 use-after-free 或其他错误。
4. **`Uint8Array` 被分离:**  一个常见的错误场景是，JavaScript 代码持有的 `Uint8Array` 的底层 `ArrayBuffer` 被转移（例如，通过 `postMessage`），导致 `ReadableStreamBytesConsumer` 尝试访问已分离的内存。

   **举例说明（`Uint8Array` 分离）：**

   * **假设输入:**  一个 `ReadableStream` 产生一个 `Uint8Array` 作为数据块。
   * **用户操作 (错误操作):** JavaScript 代码在将这个 `Uint8Array` 的数据提供给 C++ 的 `ReadableStreamBytesConsumer` 之前，就将其转移给另一个 Worker 或窗口：
     ```javascript
     let reader = response.body.getReader();
     reader.read().then(({ value, done }) => {
       if (value) {
         postMessage(value.buffer, [value.buffer]); // Transfer the underlying ArrayBuffer
         // ... 稍后，C++ 的 ReadableStreamBytesConsumer 尝试读取 value 中的数据
       }
     });
     ```
   * **结果:** 当 `ReadableStreamBytesConsumer` 的 `BeginRead` 或 `EndRead` 尝试访问 `pending_buffer_` 的数据时，如果 `pending_buffer_` 的底层 `ArrayBuffer` 已经被分离，则会触发 `IsDetached()` 的检查，并导致错误状态。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户发起网络请求:** 用户在浏览器中输入网址或点击链接，导致浏览器发起一个 HTTP 请求。
2. **服务器返回响应:** 服务器返回响应头和响应体。
3. **Blink 创建 `ReadableStream`:**  Blink 的网络层接收到响应体，并将其包装成一个 JavaScript `ReadableStream` 对象。这个 `ReadableStream` 对象可以在 JavaScript 中通过 `response.body` 访问。
4. **C++ 代码需要读取流数据:**  Blink 内部的某个 C++ 组件（例如，HTML 解析器、CSS 解析器、JavaScript 代码通过 `getReader()` 获取读取器后）需要读取这个 `ReadableStream` 中的字节数据。
5. **创建 `ReadableStreamBytesConsumer`:**  为了从 `ReadableStream` 中读取字节数据，Blink 会创建一个 `ReadableStreamBytesConsumer` 对象，并将其与该 `ReadableStream` 关联起来。
6. **调用 `BeginRead`:** C++ 代码调用 `ReadableStreamBytesConsumer` 的 `BeginRead` 方法尝试获取可用的字节数据。
7. **异步读取和回调:** 如果数据尚未准备好，`ReadableStreamBytesConsumer` 会启动异步读取操作。当 JavaScript 端的 `ReadableStream` 产生数据块时，会调用 `ReadableStreamBytesConsumer` 的 `OnRead` 方法，并将包含数据的 `DOMUint8Array` 传递给它。
8. **提供数据给 C++ 客户端:** `ReadableStreamBytesConsumer` 将读取到的数据通过 `base::span` 提供给其 C++ 客户端。
9. **调用 `EndRead`:** C++ 客户端处理完一部分数据后，会调用 `EndRead` 方法，告知 `ReadableStreamBytesConsumer` 消费了多少字节。
10. **流结束或出错:** 这个过程会一直持续到流结束（`OnReadDone` 被调用）或发生错误（`OnRejected` 被调用）。

**调试线索:**

* **检查 JavaScript 代码中对 `ReadableStream` 的操作:**  查看 JavaScript 代码是否正确地处理了 `ReadableStream`，是否过早地关闭或取消了流，或者是否在 C++ 代码还在读取时转移了 `ArrayBuffer`。
* **断点调试 C++ 代码:** 在 `ReadableStreamBytesConsumer` 的关键方法（例如 `BeginRead`, `EndRead`, `OnRead`, `OnRejected`）设置断点，查看其状态和数据流。
* **查看 Blink 的日志:**  Blink 可能会有相关的日志输出，指示流的状态和错误信息。
* **检查网络请求:**  确认网络请求是否成功，响应头是否正确，以及响应体的内容是否符合预期。
* **使用 Chrome 的开发者工具:**  可以使用 Chrome 的开发者工具查看网络请求的详细信息，以及 JavaScript 中 `ReadableStream` 的状态。

总而言之，`blink::ReadableStreamBytesConsumer` 是 Blink 引擎中一个关键的组件，它弥合了 JavaScript 异步 `ReadableStream` 和 C++ 同步数据处理之间的差距，使得 C++ 代码能够方便地消费来自 Web API 的字节数据流。

Prompt: 
```
这是目录为blink/renderer/core/fetch/readable_stream_bytes_consumer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/readable_stream_bytes_consumer.h"

#include <string.h>

#include <algorithm>

#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/read_request.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/scoped_persistent.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding_macros.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "v8/include/v8.h"

namespace blink {

class ReadableStreamBytesConsumer::BytesConsumerReadRequest final
    : public ReadRequest {
 public:
  explicit BytesConsumerReadRequest(ReadableStreamBytesConsumer* consumer)
      : consumer_(consumer) {}

  void ChunkSteps(ScriptState* script_state,
                  v8::Local<v8::Value> chunk,
                  ExceptionState& exception_state) const override {
    if (!chunk->IsUint8Array()) {
      consumer_->OnRejected();
      return;
    }
    ScriptState::Scope scope(script_state);
    consumer_->OnRead(
        NativeValueTraits<MaybeShared<DOMUint8Array>>::NativeValue(
            script_state->GetIsolate(), chunk, exception_state)
            .Get());
    DCHECK(!exception_state.HadException());
  }

  void CloseSteps(ScriptState* script_state) const override {
    consumer_->OnReadDone();
  }

  void ErrorSteps(ScriptState* script_state,
                  v8::Local<v8::Value> e) const override {
    consumer_->OnRejected();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(consumer_);
    ReadRequest::Trace(visitor);
  }

 private:
  Member<ReadableStreamBytesConsumer> consumer_;
};

ReadableStreamBytesConsumer::ReadableStreamBytesConsumer(
    ScriptState* script_state,
    ReadableStream* stream)
    : script_state_(script_state) {
  DCHECK(!ReadableStream::IsLocked(stream));

  // Since the stream is not locked, AcquireDefaultReader cannot fail.
  NonThrowableExceptionState exception_state(__FILE__, __LINE__);
  reader_ = ReadableStream::AcquireDefaultReader(script_state, stream,
                                                 exception_state);
}

ReadableStreamBytesConsumer::~ReadableStreamBytesConsumer() {}

BytesConsumer::Result ReadableStreamBytesConsumer::BeginRead(
    base::span<const char>& buffer) {
  buffer = {};
  if (state_ == PublicState::kErrored)
    return Result::kError;
  if (state_ == PublicState::kClosed)
    return Result::kDone;

  if (pending_buffer_) {
    // The UInt8Array has become detached due to, for example, the site
    // transferring it away via postMessage().  Since we were in the middle
    // of reading the array we must error out.
    if (pending_buffer_->IsDetached()) {
      SetErrored();
      return Result::kError;
    }

    DCHECK_LE(pending_offset_, pending_buffer_->length());
    buffer =
        base::as_chars(pending_buffer_->ByteSpan().subspan(pending_offset_));
    return Result::kOk;
  }
  if (!is_reading_) {
    is_reading_ = true;
    is_inside_read_ = true;
    ScriptState::Scope scope(script_state_);
    DCHECK(reader_);

    ExceptionState exception_state(script_state_->GetIsolate(),
                                   v8::ExceptionContext::kUnknown, "", "");
    auto* read_request = MakeGarbageCollected<BytesConsumerReadRequest>(this);
    ReadableStreamDefaultReader::Read(script_state_, reader_, read_request,
                                      exception_state);
    is_inside_read_ = false;
  }
  return Result::kShouldWait;
}

BytesConsumer::Result ReadableStreamBytesConsumer::EndRead(size_t read_size) {
  DCHECK(pending_buffer_);

  // While the buffer size is immutable once constructed, the buffer can be
  // detached if the site does something like transfer it away using
  // postMessage().  Since we were in the middle of a read we must error out.
  if (pending_buffer_->IsDetached()) {
    SetErrored();
    return Result::kError;
  }

  DCHECK_LE(pending_offset_ + read_size, pending_buffer_->length());
  pending_offset_ += read_size;
  if (pending_offset_ >= pending_buffer_->length()) {
    pending_buffer_ = nullptr;
    pending_offset_ = 0;
  }
  return Result::kOk;
}

void ReadableStreamBytesConsumer::SetClient(Client* client) {
  DCHECK(!client_);
  DCHECK(client);
  client_ = client;
}

void ReadableStreamBytesConsumer::ClearClient() {
  client_ = nullptr;
}

void ReadableStreamBytesConsumer::Cancel() {
  if (state_ == PublicState::kClosed || state_ == PublicState::kErrored)
    return;
  // BytesConsumer::Cancel can be called with ScriptForbiddenScope (e.g.,
  // in ExecutionContextLifecycleObserver::ContextDestroyed()). We don't run
  // ReadableStreamDefaultReader::cancel in such a case.
  if (!ScriptForbiddenScope::IsScriptForbidden()) {
    ScriptState::Scope scope(script_state_);
    ExceptionState exception_state(script_state_->GetIsolate(),
                                   v8::ExceptionContext::kUnknown, "", "");
    reader_->cancel(script_state_, exception_state);
    // We ignore exceptions as we can do nothing here.
  }
  state_ = PublicState::kClosed;
  ClearClient();
  reader_ = nullptr;
}

BytesConsumer::PublicState ReadableStreamBytesConsumer::GetPublicState() const {
  return state_;
}

BytesConsumer::Error ReadableStreamBytesConsumer::GetError() const {
  return Error("Failed to read from a ReadableStream.");
}

void ReadableStreamBytesConsumer::Trace(Visitor* visitor) const {
  visitor->Trace(reader_);
  visitor->Trace(client_);
  visitor->Trace(pending_buffer_);
  visitor->Trace(script_state_);
  BytesConsumer::Trace(visitor);
}

void ReadableStreamBytesConsumer::OnRead(DOMUint8Array* buffer) {
  DCHECK(is_reading_);
  DCHECK(buffer);
  DCHECK(!pending_buffer_);
  DCHECK(!pending_offset_);
  if (is_inside_read_) {
    scoped_refptr<scheduler::EventLoop> event_loop =
        ExecutionContext::From(script_state_)->GetAgent()->event_loop();
    event_loop->EnqueueMicrotask(
        WTF::BindOnce(&ReadableStreamBytesConsumer::OnRead,
                      WrapPersistent(this), WrapPersistent(buffer)));
    return;
  }
  is_reading_ = false;
  if (state_ == PublicState::kClosed)
    return;
  DCHECK_EQ(state_, PublicState::kReadableOrWaiting);
  pending_buffer_ = buffer;
  if (client_)
    client_->OnStateChange();
}

void ReadableStreamBytesConsumer::OnReadDone() {
  DCHECK(is_reading_);
  DCHECK(!pending_buffer_);
  if (is_inside_read_) {
    scoped_refptr<scheduler::EventLoop> event_loop =
        ExecutionContext::From(script_state_)->GetAgent()->event_loop();
    event_loop->EnqueueMicrotask(WTF::BindOnce(
        &ReadableStreamBytesConsumer::OnReadDone, WrapPersistent(this)));
    return;
  }
  is_reading_ = false;
  if (state_ == PublicState::kClosed)
    return;
  DCHECK_EQ(state_, PublicState::kReadableOrWaiting);
  state_ = PublicState::kClosed;
  reader_ = nullptr;
  Client* client = client_;
  ClearClient();
  if (client)
    client->OnStateChange();
}

void ReadableStreamBytesConsumer::OnRejected() {
  DCHECK(is_reading_);
  DCHECK(!pending_buffer_);
  if (is_inside_read_) {
    scoped_refptr<scheduler::EventLoop> event_loop =
        ExecutionContext::From(script_state_)->GetAgent()->event_loop();
    event_loop->EnqueueMicrotask(WTF::BindOnce(
        &ReadableStreamBytesConsumer::OnRejected, WrapPersistent(this)));
    return;
  }
  is_reading_ = false;
  if (state_ == PublicState::kClosed)
    return;
  DCHECK_EQ(state_, PublicState::kReadableOrWaiting);
  Client* client = client_;
  SetErrored();
  if (client)
    client->OnStateChange();
}

void ReadableStreamBytesConsumer::SetErrored() {
  DCHECK_NE(state_, PublicState::kClosed);
  DCHECK_NE(state_, PublicState::kErrored);
  state_ = PublicState::kErrored;
  ClearClient();
  reader_ = nullptr;
}

}  // namespace blink

"""

```