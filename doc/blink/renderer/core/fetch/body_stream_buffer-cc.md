Response:
Let's break down the thought process for analyzing this code and generating the explanation.

1. **Understand the Goal:** The request asks for a functional breakdown of `body_stream_buffer.cc`, its relation to web technologies, potential errors, and debugging tips.

2. **Initial Skim and Keyword Spotting:**  Quickly read through the code, looking for keywords and class names. Things that jump out: `BodyStreamBuffer`, `ReadableStream`, `BytesConsumer`, `FetchDataLoader`, `BlobDataHandle`, `FormData`, `AbortSignal`, `ScriptState`, `ExceptionState`. These immediately suggest involvement in data fetching, stream processing, and interactions with JavaScript APIs.

3. **Core Class Identification:** The central class is clearly `BodyStreamBuffer`. The comments and the `Create` method emphasize its role in managing a stream of data.

4. **Identify Key Dependencies and Relationships:**
    * **`BytesConsumer`:**  This likely handles the low-level consumption of data. Different types of consumers are probably used for different data formats.
    * **`ReadableStream`:** This is a fundamental web API for handling asynchronous data streams. The code explicitly creates and interacts with `ReadableByteStreamController`.
    * **`FetchDataLoader`:** This class is responsible for fetching data from the network. The `StartLoading` method confirms this.
    * **`AbortSignal`:**  This allows for cancelling ongoing operations, important for resource management and user interaction.
    * **`ScriptState`:**  Indicates interaction with the JavaScript environment.
    * **`BlobDataHandle`, `FormData`:**  Represent specific data formats that can be handled by the buffer.

5. **Analyze Key Methods:**  Go through the public methods of `BodyStreamBuffer` and understand their purpose:
    * **`Create`:**  Sets up a `BodyStreamBuffer` connected to a `BytesConsumer`.
    * **Constructors:** Handle different initialization scenarios (from a `BytesConsumer` or an existing `ReadableStream`).
    * **`DrainAsBlobDataHandle`, `DrainAsFormData`:** Methods to extract the buffered data in specific formats.
    * **`DrainAsChunkedDataPipeGetter`:**  Deals with streaming data using Mojo data pipes.
    * **`StartLoading`:** Initiates the data fetching process.
    * **`Tee`:**  Implements the `tee()` method of `ReadableStream`, allowing duplication of the stream.
    * **`Pull`:**  Part of the `ReadableStream` pull mechanism, requesting more data.
    * **`Cancel`:**  Stops the stream and any ongoing operations.
    * **`OnStateChange`:**  Reacts to state changes in the `BytesConsumer`.
    * **`Abort`, `Close`, `GetError`, `RaiseOOMError`:** Methods for handling different stream termination scenarios.
    * **`ReleaseHandle`:**  Obtains the underlying `BytesConsumer` (or a wrapper) for use by other components.

6. **Trace Data Flow:**  Consider how data moves through the system:
    * Network -> `FetchDataLoader` -> `BytesConsumer` -> `BodyStreamBuffer` -> `ReadableStream` -> JavaScript.
    * The `LoaderClient` acts as an intermediary between `FetchDataLoader` and `BodyStreamBuffer`.

7. **Identify Connections to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The core connection is through the `ReadableStream` API. The `BodyStreamBuffer` provides the underlying data source for these streams, which are directly accessible in JavaScript. Methods like `tee()`, `cancel()`, and the pull mechanism are all part of the JavaScript `ReadableStream` API.
    * **HTML:**  The `fetch()` API, used to initiate network requests, returns a `Response` object whose `body` property is a `ReadableStream` backed by a `BodyStreamBuffer`. Form submissions also involve this mechanism.
    * **CSS:**  While not directly involved in *fetching* CSS, the same underlying mechanisms could be used if CSS resources were streamed in a non-standard way. However, the primary use cases are for fetching document content, images, and other data.

8. **Consider Logic and Potential Issues:**
    * **State Management:** The code carefully manages the state of the stream (readable, closed, errored, locked, disturbed). Incorrect state transitions can lead to errors.
    * **Error Handling:** The code includes mechanisms for handling aborts, network errors, and out-of-memory conditions.
    * **Concurrency:** Asynchronous operations and interactions with different threads (network, worker) require careful synchronization.
    * **Resource Management:**  The use of `scoped_refptr` and garbage collection indicates attention to memory management.

9. **Formulate Examples and Scenarios:**  Think of concrete examples to illustrate the concepts:
    * **JavaScript `fetch()`:**  Show how the `response.body` stream is connected to the C++ code.
    * **`tee()`:** Demonstrate how cloning a stream works.
    * **Common Errors:**  Illustrate scenarios where the stream is locked or disturbed, leading to exceptions.
    * **Debugging:** Explain how to track the data flow by setting breakpoints in the C++ code.

10. **Structure the Explanation:** Organize the information logically with clear headings and bullet points. Start with a high-level overview and then delve into specifics.

11. **Review and Refine:**  Read through the explanation to ensure clarity, accuracy, and completeness. Check for any ambiguities or missing information. For example, ensure the connection between `BytesConsumer` and different data types (Blob, FormData) is clear. Also, make sure the explanation of the debugging process is practical.

By following these steps, one can systematically analyze the code and generate a comprehensive and informative explanation that addresses all aspects of the original request. The key is to move from general understanding to specific details, always keeping the connection to the user-facing web technologies in mind.
好的，让我们来分析一下 `blink/renderer/core/fetch/body_stream_buffer.cc` 这个 Blink 引擎源代码文件的功能。

**功能概述:**

`BodyStreamBuffer` 的核心功能是作为 HTTP 响应体（或请求体，尽管此文件主要处理响应）数据流的缓冲区和管理者。它在底层 `BytesConsumer` 和上层 JavaScript 可读流 (`ReadableStream`) 之间架起桥梁。 它的主要职责包括：

1. **接收和缓冲数据:** 从底层的 `BytesConsumer` 接收来自网络或其他来源的字节数据。
2. **转换为可读流:** 将接收到的数据组织成符合 JavaScript `ReadableStream` API 的格式，使其能够在 JavaScript 中异步读取。
3. **支持不同的数据读取方式:**  提供将数据以不同形式（如 `Blob`, `FormData`, `ArrayBuffer`）提供给上层的功能。
4. **处理流的状态:**  跟踪和管理数据流的状态，例如是否已读取完毕、是否发生错误、是否被取消等。
5. **支持流的 `tee()` 操作:** 允许创建两个独立的流分支，用于并行处理同一份数据。
6. **处理流的取消和中止:**  响应用户的取消操作或网络错误，中止数据流的处理。
7. **与 `FetchDataLoader` 协同工作:**  在网络请求过程中与 `FetchDataLoader` 交互，管理数据加载的生命周期。
8. **处理背压 (Backpressure):** 当 JavaScript 侧读取速度慢于数据到达速度时，能够暂停数据的读取，防止内存溢出。

**与 JavaScript, HTML, CSS 的关系及举例:**

`BodyStreamBuffer` 是实现 Web 标准 Fetch API 中 `Response.body` 属性的关键组成部分。`Response.body` 返回一个 `ReadableStream` 对象，该对象允许 JavaScript 代码异步地读取响应体的数据。

* **JavaScript `fetch()` API:**
  当 JavaScript 代码使用 `fetch()` 发起一个网络请求时，浏览器会创建一个 `BodyStreamBuffer` 来处理服务器返回的响应体数据。

  ```javascript
  fetch('https://example.com/data.json')
    .then(response => {
      const reader = response.body.getReader(); // response.body 是一个 ReadableStream
      return new ReadableStream({
        start(controller) {
          function push() {
            reader.read().then(({ done, value }) => {
              if (done) {
                controller.close();
                return;
              }
              controller.enqueue(value); // 将数据块添加到可读流
              push();
            });
          }
          push();
        }
      });
    })
    .then(stream => new Response(stream))
    .then(response => response.json())
    .then(data => console.log(data));
  ```
  在这个例子中，`response.body` 背后的 C++ 实现就涉及到了 `BodyStreamBuffer`。`BodyStreamBuffer` 负责从网络接收数据，并将其转换成 `ReadableStream` 能够处理的数据块。

* **HTML `<video>` 或 `<img>` 标签的流式加载:**
  虽然通常 `<video>` 和 `<img>` 标签的资源加载对开发者来说是透明的，但在底层，浏览器也可能使用类似流的方式处理大型媒体文件的加载。`BodyStreamBuffer` 可以参与到这种流式加载的过程中，将网络数据逐步提供给解码器进行渲染。

* **Service Workers 拦截请求并返回自定义响应:**
  Service Worker 可以拦截浏览器的网络请求，并返回自定义的 `Response` 对象。这个自定义的 `Response` 的 `body` 也可以是一个 `ReadableStream`，而这个 `ReadableStream` 的底层同样可能由 `BodyStreamBuffer` 来管理。

  ```javascript
  // Service Worker 代码
  self.addEventListener('fetch', event => {
    if (event.request.url.endsWith('.custom')) {
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('自定义数据块 1'));
          setTimeout(() => {
            controller.enqueue(new TextEncoder().encode('自定义数据块 2'));
            controller.close();
          }, 1000);
        }
      });
      event.respondWith(new Response(stream));
    }
  });
  ```
  在这个 Service Worker 的例子中，虽然 `ReadableStream` 是直接在 JavaScript 中创建的，但 Blink 引擎内部仍然需要将其与底层的网络处理机制连接起来，而 `BodyStreamBuffer` 提供了创建这种与底层连接的 `ReadableStream` 的机制 (通过 `BodyStreamBuffer::BodyStreamBuffer(ScriptState* script_state, ReadableStream* stream, ...)` 构造函数)。

* **CSS 资源加载 (较间接):**
  虽然 CSS 文件通常不是以流的方式逐块处理的，但如果存在一些特殊的场景，例如服务端推送 CSS 数据或者通过某些 JavaScript 库动态生成和注入 CSS，那么 `BodyStreamBuffer` 也可能参与到加载 CSS 数据的过程中。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **网络响应到达了一些数据块:** 例如，服务器发送了 HTTP chunked 编码的响应，`BytesConsumer` 接收到了若干个数据块 (例如，两个数据块："Hello, " 和 "World!")。
2. **JavaScript 代码正在读取 `response.body`:**  `ReadableStream` 的读取器被调用，请求读取数据。

**逻辑推理过程 (简化):**

* `BodyStreamBuffer` 的 `ProcessData` 方法被调用。
* `consumer_->BeginRead()` 返回可用的数据块。
* `ReadableByteStreamController::Enqueue()` 被调用，将数据块 (例如，Uint8Array 形式的 "Hello, ") 添加到 `ReadableStream` 的内部队列中。
* JavaScript 侧的 `reader.read()` promise resolve，返回包含 "Hello, " 的数据块。
* 当 JavaScript 再次请求读取时，如果 `BytesConsumer` 还有更多数据，则重复上述过程，将 "World!" 也添加到 `ReadableStream`。
* 当所有数据读取完毕，`consumer_->EndRead()` 返回 `BytesConsumer::Result::kDone`，`BodyStreamBuffer::Close()` 被调用，关闭 `ReadableStream`。
* JavaScript 侧的 `reader.read()` 最终会返回 `{ done: true, value: undefined }`。

**用户或编程常见的使用错误及举例:**

1. **在流被锁定时尝试读取或操作:**  一旦 `ReadableStream` 被一个读取器锁定（例如，通过 `getReader()` 获取读取器后），就不能再对其进行某些操作，例如调用 `tee()`。

   ```javascript
   fetch('https://example.com/data.txt')
     .then(response => {
       const reader = response.body.getReader();
       response.body.tee(); // 错误: 流已被锁定
     });
   ```
   `BodyStreamBuffer::Tee` 方法会检查 `IsStreamLocked()`，如果返回 `true` 则会抛出 `InvalidStateError` 异常。

2. **多次调用 `getReader()`:**  只能有一个读取器与 `ReadableStream` 关联。

   ```javascript
   fetch('https://example.com/data.txt')
     .then(response => {
       response.body.getReader();
       response.body.getReader(); // 错误: 流已被锁定
     });
   ```

3. **在流已经读取完毕后尝试读取:** 当 `ReadableStream` 已经关闭 (`done: true`) 后，再次调用 `reader.read()` 会返回一个已经 resolved 的 promise，其 `done` 属性为 `true`，`value` 为 `undefined`，不会报错，但也没有意义。

4. **错误处理不当:**  网络请求可能失败，导致 `ReadableStream` 进入错误状态。开发者需要正确地处理这种情况，例如通过检查 `response.ok` 或在读取流的过程中捕获异常。

**用户操作如何一步步地到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个网页:** 例如，输入 URL 并按下回车键。
2. **网页中的 JavaScript 代码发起一个 `fetch()` 请求:**  例如，请求一个 JSON 文件。
3. **Blink 引擎的网络模块开始处理该请求:**  这涉及到 DNS 解析、TCP 连接建立、TLS 握手等。
4. **服务器返回 HTTP 响应头和响应体数据:**  响应体数据可能以 chunked 编码或其他方式传输。
5. **Blink 引擎的 `FetchDataLoader` 接收到响应数据:**  `FetchDataLoader` 负责处理网络数据的接收和初步处理。
6. **`FetchDataLoader` 将接收到的数据传递给 `BodyStreamBuffer` 关联的 `BytesConsumer`。**
7. **JavaScript 代码尝试读取 `response.body` 的数据:** 例如，调用 `response.body.getReader()` 获取读取器，然后调用 `reader.read()`。
8. **`BodyStreamBuffer` 的 `Pull` 方法被调用 (当使用字节流控制器时):**  这表明 JavaScript 侧需要更多数据。
9. **`BodyStreamBuffer::ProcessData` 被调用:**  此方法尝试从 `BytesConsumer` 读取数据，并将其放入 `ReadableStream` 的队列中。
10. **如果在 `ProcessData` 中发生错误 (例如，`BytesConsumer` 返回错误状态):** `BodyStreamBuffer::GetError` 会被调用，将 `ReadableStream` 置于错误状态。
11. **如果在 `Tee` 操作时流已被锁定:** 当 JavaScript 调用 `response.body.tee()` 时，会最终调用 `BodyStreamBuffer::Tee`，如果此时流的状态不允许 `tee` 操作，则会抛出异常。

**调试线索:**

* **在 `BodyStreamBuffer` 的关键方法 (例如 `ProcessData`, `Pull`, `Tee`, `Abort`, `Close`) 设置断点:**  可以观察数据的流动和状态的变化。
* **检查 `BytesConsumer` 的状态:**  了解底层数据接收的情况。
* **查看 `ReadableStream` 的状态:**  使用浏览器的开发者工具或在 C++ 代码中打印 `stream_->IsReadable()`, `stream_->IsClosed()`, `stream_->IsErrored()` 等状态。
* **跟踪 `AbortSignal` 的状态:**  确定流是否因为用户取消或其他原因被中止。
* **检查相关的 Mojo 接口调用:**  如果涉及到进程间通信，可以查看 Mojo 接口的调用情况。

总而言之，`BodyStreamBuffer` 是 Blink 引擎中一个至关重要的组件，它负责有效地管理和转换 HTTP 响应体数据，使其能够以异步流的方式在 JavaScript 中被使用，是实现现代 Web 标准 Fetch API 的核心部分。

### 提示词
```
这是目录为blink/renderer/core/fetch/body_stream_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"

#include <memory>

#include "base/auto_reset.h"
#include "base/compiler_specific.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/body.h"
#include "third_party/blink/renderer/core/fetch/bytes_consumer_tee.h"
#include "third_party/blink/renderer/core/fetch/bytes_uploader.h"
#include "third_party/blink/renderer/core/fetch/readable_stream_bytes_consumer.h"
#include "third_party/blink/renderer/core/streams/readable_byte_stream_controller.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_request.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_or_worker_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "v8/include/v8.h"

namespace blink {

class BodyStreamBuffer::LoaderClient final
    : public GarbageCollected<LoaderClient>,
      public ExecutionContextLifecycleObserver,
      public FetchDataLoader::Client {
 public:
  LoaderClient(ExecutionContext* execution_context,
               BodyStreamBuffer* buffer,
               FetchDataLoader::Client* client)
      : ExecutionContextLifecycleObserver(execution_context),
        buffer_(buffer),
        client_(client) {}
  LoaderClient(const LoaderClient&) = delete;
  LoaderClient& operator=(const LoaderClient&) = delete;

  void DidFetchDataLoadedBlobHandle(
      scoped_refptr<BlobDataHandle> blob_data_handle) override {
    buffer_->EndLoading();
    client_->DidFetchDataLoadedBlobHandle(std::move(blob_data_handle));
  }

  void DidFetchDataLoadedArrayBuffer(DOMArrayBuffer* array_buffer) override {
    buffer_->EndLoading();
    client_->DidFetchDataLoadedArrayBuffer(array_buffer);
  }

  void DidFetchDataLoadedFormData(FormData* form_data) override {
    buffer_->EndLoading();
    client_->DidFetchDataLoadedFormData(form_data);
  }

  void DidFetchDataLoadedString(const String& string) override {
    buffer_->EndLoading();
    client_->DidFetchDataLoadedString(string);
  }

  void DidFetchDataStartedDataPipe(
      mojo::ScopedDataPipeConsumerHandle data_pipe) override {
    client_->DidFetchDataStartedDataPipe(std::move(data_pipe));
  }

  void DidFetchDataLoadedDataPipe() override {
    buffer_->EndLoading();
    client_->DidFetchDataLoadedDataPipe();
  }

  void DidFetchDataLoadedCustomFormat() override {
    buffer_->EndLoading();
    client_->DidFetchDataLoadedCustomFormat();
  }

  void DidFetchDataLoadFailed() override {
    buffer_->EndLoading();
    client_->DidFetchDataLoadFailed();
  }

  void Abort() override { NOTREACHED(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(buffer_);
    visitor->Trace(client_);
    ExecutionContextLifecycleObserver::Trace(visitor);
    FetchDataLoader::Client::Trace(visitor);
  }

 private:
  void ContextDestroyed() override { buffer_->StopLoading(); }

  Member<BodyStreamBuffer> buffer_;
  Member<FetchDataLoader::Client> client_;
};

// Use a Create() method to split construction from initialisation.
// Initialisation may result in nested calls to ContextDestroyed() and so is not
// safe to do during construction.

// static
BodyStreamBuffer* BodyStreamBuffer::Create(
    ScriptState* script_state,
    BytesConsumer* consumer,
    AbortSignal* signal,
    ScriptCachedMetadataHandler* cached_metadata_handler,
    scoped_refptr<BlobDataHandle> side_data_blob) {
  auto* buffer = MakeGarbageCollected<BodyStreamBuffer>(
      PassKey(), script_state, consumer, signal, cached_metadata_handler,
      std::move(side_data_blob));
  buffer->Init();
  return buffer;
}

BodyStreamBuffer::BodyStreamBuffer(
    PassKey,
    ScriptState* script_state,
    BytesConsumer* consumer,
    AbortSignal* signal,
    ScriptCachedMetadataHandler* cached_metadata_handler,
    scoped_refptr<BlobDataHandle> side_data_blob)
    : ExecutionContextLifecycleObserver(ExecutionContext::From(script_state)),
      script_state_(script_state),
      consumer_(consumer),
      signal_(signal),
      cached_metadata_handler_(cached_metadata_handler),
      side_data_blob_(std::move(side_data_blob)),
      made_from_readable_stream_(false) {}

void BodyStreamBuffer::Init() {
  DCHECK(consumer_);

  stream_ = ReadableStream::CreateByteStream(script_state_, this);
  stream_broken_ = !stream_;

  // ContextDestroyed() can be called inside the ReadableStream constructor when
  // a worker thread is being terminated. See https://crbug.com/1007162 for
  // details. If consumer_ is null, assume that this happened and this object
  // will never actually be used, and so it is fine to skip the rest of
  // initialisation.
  if (!consumer_)
    return;

  consumer_->SetClient(this);
  if (signal_) {
    if (signal_->aborted()) {
      Abort();
    } else {
      stream_buffer_abort_handle_ = signal_->AddAlgorithm(
          WTF::BindOnce(&BodyStreamBuffer::Abort, WrapWeakPersistent(this)));
    }
  }
  OnStateChange();
}

BodyStreamBuffer::BodyStreamBuffer(
    ScriptState* script_state,
    ReadableStream* stream,
    ScriptCachedMetadataHandler* cached_metadata_handler,
    scoped_refptr<BlobDataHandle> side_data_blob)
    : ExecutionContextLifecycleObserver(ExecutionContext::From(script_state)),
      script_state_(script_state),
      stream_(stream),
      signal_(nullptr),
      cached_metadata_handler_(cached_metadata_handler),
      side_data_blob_(std::move(side_data_blob)),
      made_from_readable_stream_(true) {
  DCHECK(stream_);
}

scoped_refptr<BlobDataHandle> BodyStreamBuffer::DrainAsBlobDataHandle(
    BytesConsumer::BlobSizePolicy policy,
    ExceptionState& exception_state) {
  DCHECK(!IsStreamLocked());
  DCHECK(!IsStreamDisturbed());
  if (IsStreamClosed() || IsStreamErrored() || stream_broken_)
    return nullptr;

  if (made_from_readable_stream_)
    return nullptr;

  scoped_refptr<BlobDataHandle> blob_data_handle =
      consumer_->DrainAsBlobDataHandle(policy);
  if (blob_data_handle) {
    CloseAndLockAndDisturb(exception_state);
    return blob_data_handle;
  }
  return nullptr;
}

scoped_refptr<EncodedFormData> BodyStreamBuffer::DrainAsFormData(
    ExceptionState& exception_state) {
  DCHECK(!IsStreamLocked());
  DCHECK(!IsStreamDisturbed());
  if (IsStreamClosed() || IsStreamErrored() || stream_broken_)
    return nullptr;

  if (made_from_readable_stream_)
    return nullptr;

  scoped_refptr<EncodedFormData> form_data = consumer_->DrainAsFormData();
  if (form_data) {
    CloseAndLockAndDisturb(exception_state);
    return form_data;
  }
  return nullptr;
}

void BodyStreamBuffer::DrainAsChunkedDataPipeGetter(
    ScriptState* script_state,
    mojo::PendingReceiver<network::mojom::blink::ChunkedDataPipeGetter>
        pending_receiver,
    BytesUploader::Client* client) {
  DCHECK(!IsStreamLocked());
  auto* consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream_);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  stream_uploader_ = MakeGarbageCollected<BytesUploader>(
      execution_context, consumer, std::move(pending_receiver),
      execution_context->GetTaskRunner(TaskType::kNetworking), client);
}

void BodyStreamBuffer::StartLoading(FetchDataLoader* loader,
                                    FetchDataLoader::Client* client,
                                    ExceptionState& exception_state) {
  DCHECK(!loader_);
  DCHECK(!keep_alive_);

  if (!script_state_->ContextIsValid()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot load body from a frame or worker than has been detached");
    return;
  }

  if (signal_) {
    if (signal_->aborted()) {
      client->Abort();
      return;
    }
    loader_client_abort_handle_ = signal_->AddAlgorithm(WTF::BindOnce(
        &FetchDataLoader::Client::Abort, WrapWeakPersistent(client)));
  }
  loader_ = loader;
  auto* handle = ReleaseHandle(exception_state);
  if (exception_state.HadException())
    return;
  keep_alive_ = this;

  auto* execution_context = GetExecutionContext();
  if (execution_context) {
    virtual_time_pauser_ =
        execution_context->GetScheduler()->CreateWebScopedVirtualTimePauser(
            "ResponseBody",
            WebScopedVirtualTimePauser::VirtualTaskDuration::kInstant);
    virtual_time_pauser_.PauseVirtualTime();
  }
  loader->Start(handle, MakeGarbageCollected<LoaderClient>(execution_context,
                                                           this, client));
}

void BodyStreamBuffer::Tee(BodyStreamBuffer** branch1,
                           BodyStreamBuffer** branch2,
                           ExceptionState& exception_state) {
  DCHECK(!IsStreamLocked());
  DCHECK(!IsStreamDisturbed());
  *branch1 = nullptr;
  *branch2 = nullptr;
  auto* cached_metadata_handler = cached_metadata_handler_.Get();
  scoped_refptr<BlobDataHandle> side_data_blob = TakeSideDataBlob();

  if (made_from_readable_stream_) {
    if (stream_broken_) {
      // We don't really know what state the stream is in, so throw an exception
      // rather than making things worse.
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "Unsafe to tee stream in unknown state");
      return;
    }
    ReadableStream* stream1 = nullptr;
    ReadableStream* stream2 = nullptr;

    // IsByteStreamController() can be false if the stream was constructed from
    // a user-defined stream.
    if (stream_->GetController()->IsByteStreamController()) {
      stream_->ByteStreamTee(script_state_, &stream1, &stream2,
                             exception_state);
    } else {
      DCHECK(stream_->GetController()->IsDefaultController());
      stream_->Tee(script_state_, &stream1, &stream2, true, exception_state);
    }
    if (exception_state.HadException()) {
      stream_broken_ = true;
      return;
    }

    *branch1 = MakeGarbageCollected<BodyStreamBuffer>(
        script_state_, stream1, cached_metadata_handler, side_data_blob);
    *branch2 = MakeGarbageCollected<BodyStreamBuffer>(
        script_state_, stream2, cached_metadata_handler, side_data_blob);
    return;
  }
  BytesConsumer* dest1 = nullptr;
  BytesConsumer* dest2 = nullptr;
  auto* handle = ReleaseHandle(exception_state);
  if (exception_state.HadException()) {
    stream_broken_ = true;
    return;
  }
  BytesConsumerTee(ExecutionContext::From(script_state_), handle, &dest1,
                   &dest2);
  *branch1 = BodyStreamBuffer::Create(script_state_, dest1, signal_,
                                      cached_metadata_handler, side_data_blob);
  *branch2 = BodyStreamBuffer::Create(script_state_, dest2, signal_,
                                      cached_metadata_handler, side_data_blob);
}

ScriptPromise<IDLUndefined> BodyStreamBuffer::Pull(
    ReadableByteStreamController* controller,
    ExceptionState& exception_state) {
  if (!consumer_) {
    // This is a speculative workaround for a crash. See
    // https://crbug.com/773525.
    // TODO(yhirano): Remove this branch or have a better comment.
    return ToResolvedUndefinedPromise(GetScriptState());
  }

  if (stream_needs_more_) {
    return ToResolvedUndefinedPromise(GetScriptState());
  }
  stream_needs_more_ = true;
  if (!in_process_data_) {
    ProcessData(exception_state);
  }
  return ToResolvedUndefinedPromise(GetScriptState());
}

ScriptPromise<IDLUndefined> BodyStreamBuffer::Cancel() {
  return Cancel(v8::Undefined(GetScriptState()->GetIsolate()));
}

ScriptPromise<IDLUndefined> BodyStreamBuffer::Cancel(
    v8::Local<v8::Value> reason) {
  ReadableStreamController* controller = Stream()->GetController();
  DCHECK(controller->IsByteStreamController());
  ReadableByteStreamController* byte_controller =
      To<ReadableByteStreamController>(controller);
  byte_controller->Close(GetScriptState(), byte_controller);
  CancelConsumer();
  return ToResolvedUndefinedPromise(GetScriptState());
}

ScriptState* BodyStreamBuffer::GetScriptState() {
  return script_state_.Get();
}

void BodyStreamBuffer::OnStateChange() {
  if (!consumer_ || !GetExecutionContext() ||
      GetExecutionContext()->IsContextDestroyed()) {
    return;
  }
  ExceptionState exception_state(script_state_->GetIsolate(),
                                 v8::ExceptionContext::kUnknown, "", "");

  switch (consumer_->GetPublicState()) {
    case BytesConsumer::PublicState::kReadableOrWaiting:
      break;
    case BytesConsumer::PublicState::kClosed:
      Close(exception_state);
      return;
    case BytesConsumer::PublicState::kErrored:
      GetError();
      return;
  }
  ProcessData(exception_state);
}

void BodyStreamBuffer::ContextDestroyed() {
  CancelConsumer();
  keep_alive_.Clear();
}

bool BodyStreamBuffer::IsStreamReadable() const {
  return stream_->IsReadable();
}

bool BodyStreamBuffer::IsStreamClosed() const {
  return stream_->IsClosed();
}

bool BodyStreamBuffer::IsStreamErrored() const {
  return stream_->IsErrored();
}

bool BodyStreamBuffer::IsStreamLocked() const {
  return stream_->IsLocked();
}

bool BodyStreamBuffer::IsStreamDisturbed() const {
  return stream_->IsDisturbed();
}

void BodyStreamBuffer::CloseAndLockAndDisturb(ExceptionState& exception_state) {
  DCHECK(!stream_broken_);

  cached_metadata_handler_ = nullptr;

  if (IsStreamReadable()) {
    // Note that the stream cannot be "draining", because it doesn't have
    // the internal buffer.
    Close(exception_state);
  }

  stream_->LockAndDisturb(script_state_);
}

bool BodyStreamBuffer::IsAborted() {
  if (!signal_)
    return false;
  return signal_->aborted();
}

scoped_refptr<BlobDataHandle> BodyStreamBuffer::TakeSideDataBlob() {
  return std::move(side_data_blob_);
}

void BodyStreamBuffer::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  visitor->Trace(stream_);
  visitor->Trace(stream_uploader_);
  visitor->Trace(consumer_);
  visitor->Trace(loader_);
  visitor->Trace(signal_);
  visitor->Trace(stream_buffer_abort_handle_);
  visitor->Trace(loader_client_abort_handle_);
  visitor->Trace(cached_metadata_handler_);
  UnderlyingByteSourceBase::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void BodyStreamBuffer::Abort() {
  if (!GetExecutionContext()) {
    DCHECK(!consumer_);
    return;
  }
  auto* byte_controller =
      To<ReadableByteStreamController>(stream_->GetController());
  v8::Local<v8::Value> dom_exception = V8ThrowDOMException::CreateOrEmpty(
      script_state_->GetIsolate(), DOMExceptionCode::kAbortError,
      "BodyStreamBuffer was aborted");
  CHECK(!dom_exception.IsEmpty());
  ReadableByteStreamController::Error(script_state_, byte_controller,
                                      dom_exception);
  CancelConsumer();
}

void BodyStreamBuffer::Close(ExceptionState& exception_state) {
  // Close() can be called during construction, in which case `stream_`
  // will not be set yet.
  if (stream_) {
    v8::Isolate* isolate = script_state_->GetIsolate();
    v8::TryCatch try_catch(isolate);
    if (script_state_->ContextIsValid()) {
      ScriptState::Scope scope(script_state_);
      stream_->CloseStream(script_state_, PassThroughException(isolate));
    } else {
      // If the context is not valid then Close() will not try to resolve the
      // promises, and that is not a problem.
      stream_->CloseStream(script_state_, PassThroughException(isolate));
    }
    if (try_catch.HasCaught()) {
      return;
    }
  }
  CancelConsumer();
}

void BodyStreamBuffer::GetError() {
  {
    ScriptState::Scope scope(script_state_);
    auto* byte_controller =
        To<ReadableByteStreamController>(stream_->GetController());
    ReadableByteStreamController::Error(
        script_state_, byte_controller,
        V8ThrowException::CreateTypeError(script_state_->GetIsolate(),
                                          "network error"));
  }
  CancelConsumer();
}

void BodyStreamBuffer::RaiseOOMError() {
  {
    ScriptState::Scope scope(script_state_);
    auto* byte_controller =
        To<ReadableByteStreamController>(stream_->GetController());
    ReadableByteStreamController::Error(
        script_state_, byte_controller,
        V8ThrowException::CreateRangeError(script_state_->GetIsolate(),
                                           "Array buffer allocation failed"));
  }
  CancelConsumer();
}

void BodyStreamBuffer::CancelConsumer() {
  side_data_blob_.reset();
  virtual_time_pauser_.UnpauseVirtualTime();
  if (consumer_) {
    consumer_->Cancel();
    consumer_ = nullptr;
  }
}

void BodyStreamBuffer::ProcessData(ExceptionState& exception_state) {
  DCHECK(consumer_);
  DCHECK(!in_process_data_);

  base::AutoReset<bool> auto_reset(&in_process_data_, true);
  while (stream_needs_more_) {
    base::span<const char> buffer;
    auto result = consumer_->BeginRead(buffer);
    if (result == BytesConsumer::Result::kShouldWait)
      return;
    DOMUint8Array* array = nullptr;
    DOMArrayBufferView* byob_view = nullptr;
    if (result == BytesConsumer::Result::kOk) {
      if (stream_->GetController()->IsByteStreamController()) {
        auto* byte_controller =
            To<ReadableByteStreamController>(stream_->GetController());
        if (ReadableStreamBYOBRequest* request =
                byte_controller->byobRequest()) {
          DOMArrayBufferView* view = request->view().Get();
          auto view_span = view->ByteSpan();
          buffer = buffer.first(std::min(view_span.size(), buffer.size()));
          view_span.copy_prefix_from(base::as_bytes(buffer));
          byob_view = view;
        }
      }
      if (!byob_view) {
        CHECK(!array);
        array = DOMUint8Array::CreateOrNull(base::as_bytes(buffer));
      }
      result = consumer_->EndRead(buffer.size());
      if (!array && !byob_view) {
        RaiseOOMError();
        return;
      }
    }
    switch (result) {
      case BytesConsumer::Result::kOk:
      case BytesConsumer::Result::kDone:
        if (array || byob_view) {
          // Clear |stream_needs_more_| in order to detect a pull call.
          stream_needs_more_ = false;
          ScriptState::Scope scope(script_state_);
          v8::TryCatch try_catch(script_state_->GetIsolate());
          auto* byte_controller =
              To<ReadableByteStreamController>(stream_->GetController());
          if (byob_view) {
            ReadableByteStreamController::Respond(
                script_state_, byte_controller, buffer.size(),
                PassThroughException(script_state_->GetIsolate()));
          } else {
            CHECK(array);
            ReadableByteStreamController::Enqueue(
                script_state_, byte_controller, NotShared(array),
                PassThroughException(script_state_->GetIsolate()));
          }
          if (try_catch.HasCaught()) {
            return;
          }
        }
        if (result == BytesConsumer::Result::kDone) {
          Close(exception_state);
          return;
        }
        // If |stream_needs_more_| is true, it means that pull is called and
        // the stream needs more data even if the desired size is not
        // positive.
        if (!stream_needs_more_) {
          auto* byte_controller =
              To<ReadableByteStreamController>(stream_->GetController());
          std::optional<double> desired_size =
              ReadableByteStreamController::GetDesiredSize(byte_controller);
          DCHECK(desired_size.has_value());
          stream_needs_more_ = desired_size.value() > 0;
        }
        break;
      case BytesConsumer::Result::kShouldWait:
        NOTREACHED();
      case BytesConsumer::Result::kError:
        GetError();
        return;
    }
  }
}

void BodyStreamBuffer::EndLoading() {
  if (!loader_) {
    DCHECK(!keep_alive_);
    return;
  }
  virtual_time_pauser_.UnpauseVirtualTime();
  keep_alive_.Clear();
  loader_ = nullptr;
}

void BodyStreamBuffer::StopLoading() {
  if (!loader_) {
    DCHECK(!keep_alive_);
    return;
  }
  loader_->Cancel();
  EndLoading();
}

BytesConsumer* BodyStreamBuffer::ReleaseHandle(
    ExceptionState& exception_state) {
  DCHECK(!IsStreamLocked());
  DCHECK(!IsStreamDisturbed());

  if (stream_broken_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Body stream has suffered a fatal error and cannot be inspected");
    return nullptr;
  }

  if (!GetExecutionContext()) {
    // Avoid crashing if ContextDestroyed() has been called.
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot release body in a window or worker that has been detached");
    return nullptr;
  }

  // Do this after state checks to avoid side-effects when the method does
  // nothing.
  side_data_blob_.reset();

  if (made_from_readable_stream_) {
    DCHECK(script_state_->ContextIsValid());
    ScriptState::Scope scope(script_state_);
    return MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state_,
                                                             stream_);
  }
  // We need to call these before calling CloseAndLockAndDisturb.
  const bool is_closed = IsStreamClosed();
  const bool is_errored = IsStreamErrored();

  BytesConsumer* consumer = consumer_.Release();

  CloseAndLockAndDisturb(exception_state);

  if (is_closed) {
    // Note that the stream cannot be "draining", because it doesn't have
    // the internal buffer.
    return BytesConsumer::CreateClosed();
  }
  if (is_errored)
    return BytesConsumer::CreateErrored(BytesConsumer::Error("error"));

  DCHECK(consumer);
  consumer->ClearClient();
  return consumer;
}

}  // namespace blink
```