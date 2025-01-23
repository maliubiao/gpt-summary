Response:
Let's break down the thought process for analyzing the `bytes_consumer_tee.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the code, its relation to web technologies (JavaScript, HTML, CSS), potential logic, common errors, and debugging context.

2. **Identify the Core Class:** The filename `bytes_consumer_tee.cc` and the function `BytesConsumerTee` strongly suggest that the primary purpose is to "tee" or duplicate a `BytesConsumer`. This is a common pattern in data processing where you need to process the same data in multiple ways.

3. **Analyze the `BytesConsumerTee` Function:**
    * **Input:** It takes an `ExecutionContext`, a source `BytesConsumer`, and two output `BytesConsumer**`. This confirms the "teeing" idea.
    * **Early Exits:** It checks if the source can be drained as a `BlobDataHandle` or a `FormData`. This indicates optimizations or special handling for these common types of data.
    * **`NoopClient`:** The use of `NoopClient` suggests that when the data is drained directly, a client still needs to be set on the original consumer, even if it does nothing. This maintains internal consistency.
    * **`TeeHelper`:**  If the early exits don't apply, a `TeeHelper` is created. This strongly hints that the core logic of the teeing mechanism resides within this helper class.

4. **Dive into the `TeeHelper` Class:**
    * **Constructor:** Takes the `ExecutionContext` and the source `BytesConsumer`. Crucially, it creates two `Destination` objects and sets itself as the client of the source.
    * **`OnStateChange()`:** This is the heart of the teeing logic. It reads data from the source `BytesConsumer` and enqueues it into both `Destination` objects. The logic handles `kShouldWait`, `kOk`, `kDone`, and `kError` states, ensuring proper synchronization. The `has_enqueued` variable suggests optimization for notifying destinations only when new data is actually available.
    * **`DebugName()`:** Helpful for debugging.
    * **`GetPublicState()` and `GetError()`:** Simply delegate to the source.
    * **`Cancel()`:**  Cancels the source only if both destinations are already cancelled. This prevents prematurely cancelling the source if one destination is still active.
    * **`Destination1()` and `Destination2()`:** Provide access to the duplicated consumers.
    * **`Trace()`:**  For Blink's garbage collection mechanism.

5. **Examine the `TeeHelper::Chunk` Class:**
    * **Purpose:** Represents a chunk of data read from the source.
    * **Memory Management:** Uses `Vector<char>` and `V8ExternalMemoryAccounterBase` to manage memory and inform the V8 garbage collector about the memory usage of the chunks.

6. **Investigate the `TeeHelper::Destination` Class:**
    * **Purpose:** Represents one of the duplicated `BytesConsumer` outputs.
    * **Constructor:**  Takes `ExecutionContext` and a pointer to the `TeeHelper`.
    * **`BeginRead()`:** Attempts to provide a chunk of data to the consumer. It handles waiting if no data is available or if the source is still readable.
    * **`EndRead()`:** Updates the internal offset and removes consumed chunks. It also handles the case where the source is closed and all data has been consumed. The asynchronous `Close()` call is interesting.
    * **`SetClient()` and `ClearClient()`:** Manage the client that wants to consume data from this destination.
    * **`Cancel()`:** Cancels this destination, clears its internal buffers, and potentially cancels the source (via `TeeHelper`).
    * **`GetPublicState()`:**  Reports the state, considering both its own state (`is_cancelled_`, `is_closed_`) and the source's state.
    * **`GetError()`:** Delegates to the `TeeHelper`.
    * **`Enqueue()`:**  Adds a chunk of data to the destination's queue.
    * **`IsEmpty()`:** Checks if the destination has any pending data.
    * **`ClearChunks()`:** Discards buffered data.
    * **`Notify()`:**  Informs the client that new data is available. It also handles closing the destination if the source is closed and all data is consumed.
    * **`IsCancelled()`:** Checks if the destination has been cancelled.
    * **`Close()`:**  Marks the destination as closed and notifies the client. The asynchronous nature is important to note.

7. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript `tee()` method on `ReadableStream`:** This is the most direct connection. The `BytesConsumerTee` likely implements the underlying logic for this JavaScript API.
    * **`fetch()` API:**  The `fetch()` API returns a `Response` object, which has a `body` property that's a `ReadableStream`. The teeing mechanism would be relevant when the user wants to consume the response body multiple times.
    * **Service Workers:** Service workers can intercept `fetch` requests and create modified responses. Teeing could be used to both return a response to the browser and cache the response content.

8. **Consider Logic and Examples:**
    * **Assumptions:**  Focus on the core function of duplicating data.
    * **Input/Output:**  Demonstrate the flow of data from the source to both destinations.

9. **Think About Common Errors:**
    * **Canceling one stream but not the other:**  This could lead to resource leaks or unexpected behavior if the source continues to produce data.
    * **Not handling errors:** If the source stream errors, both destinations should also reflect this.

10. **Trace User Actions (Debugging):**
    * **Start with the JavaScript API:** How does a user invoke `tee()`?
    * **Follow the call stack:**  Trace how the JavaScript call leads to the C++ code.

11. **Review and Refine:**  Ensure the explanation is clear, concise, and addresses all aspects of the prompt. Use the code itself as the primary source of truth. Pay attention to details like memory management, error handling, and asynchronous operations. For example, the asynchronous `Close()` in `Destination` is a crucial detail to highlight.
好的，让我们详细分析一下 `blink/renderer/core/fetch/bytes_consumer_tee.cc` 文件的功能和相关性。

**文件功能概要**

`bytes_consumer_tee.cc` 文件的核心功能是实现 **字节流的复制 (Tee)**。更具体地说，它提供了一种机制，可以将一个 `BytesConsumer`（字节流的消费者）产生的数据同时分发给两个不同的 `BytesConsumer`。这类似于一个水管上的三通阀，允许水流同时流向两个出口。

**核心组件：**

* **`BytesConsumerTee()` 函数:** 这是该文件的入口点，负责创建和连接必要的对象来实现 tee 功能。
* **`TeeHelper` 类:**  这是一个关键的辅助类，负责从源 `BytesConsumer` 读取数据，并将数据分发到两个目标 `BytesConsumer`。它充当中间人，协调数据的流动。
* **`TeeHelper::Destination` 类:**  表示 tee 操作的目标 `BytesConsumer`。每个 `TeeHelper` 都有两个 `Destination` 实例。它们接收来自源的数据并将其缓冲，直到有客户端来读取。
* **`TeeHelper::Chunk` 类:**  表示从源 `BytesConsumer` 读取的一小块数据。

**功能详细解释：**

1. **接收源 `BytesConsumer`:** `BytesConsumerTee()` 函数接收一个指向源 `BytesConsumer` 的指针。这个源 `BytesConsumer` 可以是来自网络请求、文件读取或其他数据源的字节流。

2. **处理特殊情况 (Blob 和 FormData):**  在创建 `TeeHelper` 之前，`BytesConsumerTee()` 会尝试将源 `BytesConsumer` 的数据 "排空" (Drain) 为 `BlobDataHandle` 或 `FormData`。
   * **如果可以排空为 Blob:**  它会创建两个新的 `BlobBytesConsumer`，它们共享相同的 `BlobDataHandle`。这意味着两个消费者将读取相同的 Blob 数据，而不需要实际复制字节。
   * **如果可以排空为 FormData:** 它会创建两个新的 `FormDataBytesConsumer`，它们共享相同的 `FormData` 对象。同样，数据不会被复制，而是共享访问。
   * **这样做是为了优化性能，避免不必要的内存复制，特别是对于大型 Blob 或 FormData。**

3. **创建 `TeeHelper` (如果不是 Blob 或 FormData):** 如果源 `BytesConsumer` 不能直接排空为 Blob 或 FormData，则会创建一个 `TeeHelper` 对象。

4. **`TeeHelper` 的工作原理:**
   * `TeeHelper` 实现了 `BytesConsumer::Client` 接口，以便接收源 `BytesConsumer` 的状态变化通知。
   * `TeeHelper` 维护着两个 `Destination` 对象。
   * 当源 `BytesConsumer` 有新数据可用时，`TeeHelper::OnStateChange()` 方法会被调用。
   * `OnStateChange()` 方法会循环读取源 `BytesConsumer` 的数据，并将每个数据块 (Chunk) 分发到两个 `Destination` 对象的内部队列中。
   * `TeeHelper` 负责处理源 `BytesConsumer` 的各种状态，例如数据可用、读取完成、发生错误等，并将这些状态传递给两个 `Destination`。

5. **`Destination` 的工作原理:**
   * 每个 `Destination` 也是一个 `BytesConsumer`。
   * 它内部维护一个数据块 (Chunk) 的队列。
   * 当有客户端 (例如 JavaScript 代码) 调用 `BeginRead()` 时，`Destination` 会尝试从其内部队列中提供数据。
   * 如果队列为空，并且源 `BytesConsumer` 仍然可读，则 `BeginRead()` 返回 `Result::kShouldWait`，表示需要等待更多数据。
   * 当客户端调用 `EndRead()` 时，`Destination` 会更新其内部状态，并可能从队列中移除已读取的数据块。
   * `Destination` 负责处理取消 (Cancel) 操作，并将其传递给 `TeeHelper` 以取消源 `BytesConsumer` (只有当两个 Destination 都被取消时才会真正取消源)。
   * `Destination` 也负责处理错误状态，并将其传递给其客户端。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`BytesConsumerTee` 的主要应用场景是 Web APIs 中处理响应体 (Response Body) 的情况，特别是当需要多次读取或处理响应体的内容时。

* **JavaScript `tee()` 方法:**  `bytes_consumer_tee.cc` 中实现的功能直接对应于 JavaScript `ReadableStream` 接口上的 `tee()` 方法。
    ```javascript
    fetch('https://example.com/data.json')
      .then(response => {
        const [body1, body2] = response.body.tee();

        // body1 和 body2 是两个独立的 ReadableStream，
        // 它们将接收相同的响应体数据。

        const reader1 = body1.getReader();
        const reader2 = body2.getReader();

        // 可以分别读取 body1 和 body2 的内容
        reader1.read().then(result => console.log('Body 1 chunk:', result));
        reader2.read().then(result => console.log('Body 2 chunk:', result));
      });
    ```
    在这个例子中，`response.body.tee()` 会调用 Blink 引擎中相应的 C++ 代码，最终会调用到 `BytesConsumerTee()` 函数，将 `response.body` 这个 `BytesConsumer` 分割成两个独立的 `BytesConsumer`。

* **Service Workers 的缓存:** 在 Service Worker 中，你可能需要将 `fetch` 请求的响应缓存起来，同时也需要将响应返回给浏览器。`tee()` 方法就非常有用：
    ```javascript
    self.addEventListener('fetch', event => {
      event.respondWith(
        caches.match(event.request).then(cachedResponse => {
          if (cachedResponse) {
            return cachedResponse;
          }

          return fetch(event.request).then(fetchResponse => {
            const responseToCache = fetchResponse.clone(); // 克隆 Response 对象
            const [body1, body2] = fetchResponse.body.tee(); // 分割响应体

            caches.open('my-cache').then(cache => {
              // 使用 body1 存储响应到缓存
              cache.put(event.request, new Response(body1, fetchResponse));
            });

            // 使用 body2 将响应返回给浏览器
            return new Response(body2, fetchResponse);
          });
        })
      );
    });
    ```
    这里，`fetchResponse.body.tee()` 确保了响应体可以同时用于存储到缓存和返回给浏览器。

* **HTML `<video>` 或 `<img>` 标签的流式加载:** 虽然不是直接使用 `tee()`, 但 `BytesConsumer` 的概念与 HTML 中流式加载资源有关。例如，当浏览器逐步下载视频或图片时，它会使用 `BytesConsumer` 来处理接收到的数据块，并逐步渲染内容。`tee` 的思想可以用于在下载过程中同时进行其他处理，例如分析视频的元数据。

**逻辑推理的假设输入与输出**

假设我们有一个简单的字符串 "Hello, World!" 需要通过 `BytesConsumerTee` 进行复制。

**假设输入:**

* 源 `BytesConsumer`:  一个能够产生 "Hello, World!" 字符串的 `BytesConsumer`。为了简化，我们可以假设它一次性产生整个字符串。
* `ExecutionContext`:  一个有效的执行上下文。

**处理过程 (简化):**

1. `BytesConsumerTee()` 被调用，传入源 `BytesConsumer`。
2. 由于源数据不是 Blob 或 FormData，`TeeHelper` 被创建。
3. `TeeHelper` 的 `OnStateChange()` 被调用。
4. `TeeHelper` 从源 `BytesConsumer` 读取到 "Hello, World!" 这个数据块。
5. `TeeHelper` 创建两个 `Chunk` 对象，分别包含 "Hello, World!"。
6. 这两个 `Chunk` 对象被添加到 `destination1_` 和 `destination2_` 的内部队列中。

**预期输出:**

* `dest1`: 指向一个 `TeeHelper::Destination` 对象，当客户端从其读取数据时，将返回 "Hello, World!" 字符串。
* `dest2`: 指向另一个 `TeeHelper::Destination` 对象，同样地，当客户端从其读取数据时，将返回 "Hello, World!" 字符串。

**用户或编程常见的使用错误及举例说明**

1. **过早取消其中一个消费者:**
   ```javascript
   fetch('https://example.com/large-file')
     .then(response => {
       const [body1, body2] = response.body.tee();
       const reader1 = body1.getReader();
       const reader2 = body2.getReader();

       reader1.read().then(result => console.log('Body 1 chunk:', result));

       // 假设我们只需要第一个消费者的一部分数据，然后就取消它
       reader2.cancel('不再需要 body2 的数据');
     });
   ```
   在这个例子中，虽然取消了 `body2` 的读取，但底层的源 `BytesConsumer` 可能仍在继续下载数据，直到 `body1` 也被完全读取或取消。这可能会导致不必要的网络资源消耗。正确的方式是在不再需要任何一个消费者的数据时，显式地取消它们。

2. **假设两个消费者完全独立，忽略错误传递:**
   ```javascript
   fetch('https://example.com/error')
     .then(response => {
       const [body1, body2] = response.body.tee();
       const reader1 = body1.getReader();
       const reader2 = body2.getReader();

       reader1.read().catch(error => console.error('Body 1 error:', error));
       reader2.read().catch(error => console.error('Body 2 error:', error));
     });
   ```
   如果源 `BytesConsumer` 发生错误 (例如，网络请求失败)，这个错误会被传递到两个 `Destination`。开发者需要正确处理两个消费者可能出现的相同错误。

3. **不正确地处理异步操作和背压 (Backpressure):**
   如果一个消费者读取数据的速度比另一个慢很多，可能会导致 `TeeHelper` 内部的队列无限增长，最终导致内存问题。`BytesConsumer` 和 `ReadableStream` 都有背压机制来处理这种情况，开发者需要理解并正确使用这些机制。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户发起网络请求:** 用户在浏览器中访问一个网页，网页上的 JavaScript 代码使用 `fetch()` API 发起一个网络请求。
2. **`fetch()` API 调用:** JavaScript `fetch()` API 会调用 Blink 渲染引擎中的相应 C++ 代码。
3. **响应接收和 `Response` 对象创建:**  当服务器返回响应头时，Blink 会创建一个 `Response` 对象，并将响应体封装在一个 `ReadableStream` 中。这个 `ReadableStream` 的底层实现通常会使用一个 `BytesConsumer` 来处理接收到的字节流。
4. **调用 `response.body.tee()`:** JavaScript 代码调用 `response.body.tee()` 方法。
5. **`ReadableStreamTee()` 调用:**  `ReadableStream` 的 `tee()` 方法的 JavaScript 实现会调用 Blink 中对应的 C++ 方法，通常在 `third_party/blink/renderer/modules/streams/readable_stream.cc` 或类似的文件中。
6. **`BytesConsumerTee()` 调用:**  `ReadableStreamTee()` 的 C++ 实现会最终调用 `blink/renderer/core/fetch/bytes_consumer_tee.cc` 文件中的 `BytesConsumerTee()` 函数，将 `Response` 对象的底层 `BytesConsumer` 作为输入。
7. **数据流处理:**  之后，当 JavaScript 代码通过 `getReader()` 获取 `ReadableStream` 的读取器并开始读取数据时，数据会通过 `TeeHelper` 从源 `BytesConsumer` 流向两个目标 `Destination`，最终到达 JavaScript 代码。

**调试线索:**

* **断点:** 在 `BytesConsumerTee()` 函数入口处设置断点，可以观察到何时以及哪个 `BytesConsumer` 被 tee。
* **追踪 `TeeHelper` 的创建:**  查看 `TeeHelper` 的构造函数和 `OnStateChange()` 方法，可以了解数据是如何被读取和分发的。
* **检查 `Destination` 的状态:**  观察 `Destination` 的内部队列、读取偏移量以及是否被取消或关闭，可以帮助理解数据消费的情况。
* **日志输出:** 在关键路径上添加日志输出，例如在读取数据、添加数据到队列、通知客户端等地方，可以帮助跟踪数据流。
* **使用 Chrome 的开发者工具:**  在 "Network" 标签中查看网络请求的详细信息，在 "Performance" 标签中分析内存使用情况，可以辅助理解 `tee` 操作对资源的影响。

希望以上详细的解释能够帮助你理解 `blink/renderer/core/fetch/bytes_consumer_tee.cc` 文件的功能和相关性。

### 提示词
```
这是目录为blink/renderer/core/fetch/bytes_consumer_tee.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/fetch/bytes_consumer_tee.h"

#include <string.h>

#include <algorithm>

#include "base/memory/scoped_refptr.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/blob_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"
#include "third_party/blink/renderer/platform/bindings/v8_external_memory_accounter.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_deque.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/loader/fetch/bytes_consumer.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

class NoopClient final : public GarbageCollected<NoopClient>,
                         public BytesConsumer::Client {
 public:
  void OnStateChange() override {}
  String DebugName() const override { return "NoopClient"; }
};

class TeeHelper final : public GarbageCollected<TeeHelper>,
                        public BytesConsumer::Client {
 public:
  TeeHelper(ExecutionContext* execution_context, BytesConsumer* consumer)
      : src_(consumer),
        destination1_(
            MakeGarbageCollected<Destination>(execution_context, this)),
        destination2_(
            MakeGarbageCollected<Destination>(execution_context, this)) {
    consumer->SetClient(this);
    // As no client is set to either destinations, Destination::notify() is
    // no-op in this function.
    OnStateChange();
  }

  void OnStateChange() override {
    bool destination1_was_empty = destination1_->IsEmpty();
    bool destination2_was_empty = destination2_->IsEmpty();
    bool has_enqueued = false;

    while (true) {
      base::span<const char> buffer;
      auto result = src_->BeginRead(buffer);
      if (result == Result::kShouldWait) {
        if (has_enqueued && destination1_was_empty)
          destination1_->Notify();
        if (has_enqueued && destination2_was_empty)
          destination2_->Notify();
        return;
      }
      Chunk* chunk = nullptr;
      if (result == Result::kOk) {
        chunk = MakeGarbageCollected<Chunk>(buffer);
        result = src_->EndRead(buffer.size());
      }
      switch (result) {
        case Result::kOk:
          DCHECK(chunk);
          destination1_->Enqueue(chunk);
          destination2_->Enqueue(chunk);
          has_enqueued = true;
          break;
        case Result::kShouldWait:
          NOTREACHED();
        case Result::kDone:
          if (chunk) {
            destination1_->Enqueue(chunk);
            destination2_->Enqueue(chunk);
          }
          if (destination1_was_empty)
            destination1_->Notify();
          if (destination2_was_empty)
            destination2_->Notify();
          return;
        case Result::kError:
          ClearAndNotify();
          return;
      }
    }
  }
  String DebugName() const override { return "TeeHelper"; }

  BytesConsumer::PublicState GetPublicState() const {
    return src_->GetPublicState();
  }

  BytesConsumer::Error GetError() const { return src_->GetError(); }

  void Cancel() {
    if (!destination1_->IsCancelled() || !destination2_->IsCancelled())
      return;
    src_->Cancel();
  }

  BytesConsumer* Destination1() const { return destination1_.Get(); }
  BytesConsumer* Destination2() const { return destination2_.Get(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(src_);
    visitor->Trace(destination1_);
    visitor->Trace(destination2_);
    BytesConsumer::Client::Trace(visitor);
  }

 private:
  using Result = BytesConsumer::Result;
  class Chunk final : public GarbageCollected<Chunk> {
   public:
    explicit Chunk(base::span<const char> data) {
      buffer_.ReserveInitialCapacity(
          base::checked_cast<wtf_size_t>(data.size()));
      buffer_.AppendSpan(data);
      // Report buffer size to V8 so GC can be triggered appropriately.
      external_memory_accounter_.Increase(v8::Isolate::GetCurrent(),
                                          static_cast<int64_t>(buffer_.size()));
    }
    ~Chunk() {
      external_memory_accounter_.Decrease(v8::Isolate::GetCurrent(),
                                          static_cast<int64_t>(buffer_.size()));
    }
    const char* data() const { return buffer_.data(); }
    wtf_size_t size() const { return buffer_.size(); }

    // Iterators, so this type meets the requirements of
    // `std::ranges::contiguous_range`.
    auto begin() const { return buffer_.begin(); }
    auto end() const { return buffer_.end(); }

    void Trace(Visitor* visitor) const {}

   private:
    Vector<char> buffer_;
    NO_UNIQUE_ADDRESS V8ExternalMemoryAccounterBase external_memory_accounter_;
  };

  class Destination final : public BytesConsumer {
   public:
    Destination(ExecutionContext* execution_context, TeeHelper* tee)
        : execution_context_(execution_context), tee_(tee) {}

    Result BeginRead(base::span<const char>& buffer) override {
      DCHECK(!chunk_in_use_);
      buffer = {};
      if (is_cancelled_ || is_closed_)
        return Result::kDone;
      if (!chunks_.empty()) {
        Chunk* chunk = chunks_[0];
        DCHECK_LE(offset_, chunk->size());
        buffer = base::span(*chunk).subspan(offset_);
        chunk_in_use_ = chunk;
        return Result::kOk;
      }
      switch (tee_->GetPublicState()) {
        case PublicState::kReadableOrWaiting:
          return Result::kShouldWait;
        case PublicState::kClosed:
          is_closed_ = true;
          ClearClient();
          return Result::kDone;
        case PublicState::kErrored:
          ClearClient();
          return Result::kError;
      }
      NOTREACHED();
    }

    Result EndRead(size_t read) override {
      DCHECK(chunk_in_use_);
      DCHECK(chunks_.empty() || chunk_in_use_ == chunks_[0]);
      chunk_in_use_ = nullptr;
      if (chunks_.empty()) {
        // This object becomes errored during the two-phase read.
        DCHECK_EQ(PublicState::kErrored, GetPublicState());
        return Result::kOk;
      }
      Chunk* chunk = chunks_[0];
      DCHECK_LE(offset_ + read, chunk->size());
      offset_ += read;
      if (chunk->size() == offset_) {
        offset_ = 0;
        chunks_.pop_front();
      }
      if (chunks_.empty() && tee_->GetPublicState() == PublicState::kClosed) {
        // All data has been consumed.
        execution_context_->GetTaskRunner(TaskType::kNetworking)
            ->PostTask(FROM_HERE, WTF::BindOnce(&Destination::Close,
                                                WrapPersistent(this)));
      }
      return Result::kOk;
    }

    void SetClient(BytesConsumer::Client* client) override {
      DCHECK(!client_);
      DCHECK(client);
      auto state = GetPublicState();
      if (state == PublicState::kClosed || state == PublicState::kErrored)
        return;
      client_ = client;
    }

    void ClearClient() override { client_ = nullptr; }

    void Cancel() override {
      DCHECK(!chunk_in_use_);
      auto state = GetPublicState();
      if (state == PublicState::kClosed || state == PublicState::kErrored)
        return;
      is_cancelled_ = true;
      ClearChunks();
      ClearClient();
      tee_->Cancel();
    }

    PublicState GetPublicState() const override {
      if (is_cancelled_ || is_closed_)
        return PublicState::kClosed;
      auto state = tee_->GetPublicState();
      // We don't say this object is closed unless m_isCancelled or
      // m_isClosed is set.
      return state == PublicState::kClosed ? PublicState::kReadableOrWaiting
                                           : state;
    }

    Error GetError() const override { return tee_->GetError(); }

    String DebugName() const override { return "TeeHelper::Destination"; }

    void Enqueue(Chunk* chunk) {
      if (is_cancelled_)
        return;
      chunks_.push_back(chunk);
    }

    bool IsEmpty() const { return chunks_.empty(); }

    void ClearChunks() {
      chunks_.clear();
      offset_ = 0;
    }

    void Notify() {
      if (is_cancelled_ || is_closed_)
        return;
      if (chunks_.empty() && tee_->GetPublicState() == PublicState::kClosed) {
        Close();
        return;
      }
      if (client_) {
        client_->OnStateChange();
        if (GetPublicState() == PublicState::kErrored)
          ClearClient();
      }
    }

    bool IsCancelled() const { return is_cancelled_; }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(execution_context_);
      visitor->Trace(tee_);
      visitor->Trace(client_);
      visitor->Trace(chunks_);
      visitor->Trace(chunk_in_use_);
      BytesConsumer::Trace(visitor);
    }

   private:
    void Close() {
      DCHECK_EQ(PublicState::kClosed, tee_->GetPublicState());
      DCHECK(chunks_.empty());
      if (is_closed_ || is_cancelled_) {
        // It's possible to reach here because this function can be
        // called asynchronously.
        return;
      }
      DCHECK_EQ(PublicState::kReadableOrWaiting, GetPublicState());
      is_closed_ = true;
      if (client_) {
        client_->OnStateChange();
        ClearClient();
      }
    }

    Member<ExecutionContext> execution_context_;
    Member<TeeHelper> tee_;
    Member<BytesConsumer::Client> client_;
    HeapDeque<Member<Chunk>> chunks_;
    Member<Chunk> chunk_in_use_;
    size_t offset_ = 0;
    bool is_cancelled_ = false;
    bool is_closed_ = false;
  };

  void ClearAndNotify() {
    destination1_->ClearChunks();
    destination2_->ClearChunks();
    destination1_->Notify();
    destination2_->Notify();
  }

  Member<BytesConsumer> src_;
  Member<Destination> destination1_;
  Member<Destination> destination2_;
};

}  // namespace

void BytesConsumerTee(ExecutionContext* execution_context,
                      BytesConsumer* src,
                      BytesConsumer** dest1,
                      BytesConsumer** dest2) {
  scoped_refptr<BlobDataHandle> blob_data_handle = src->DrainAsBlobDataHandle(
      BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize);
  if (blob_data_handle) {
    // Register a client in order to be consistent.
    src->SetClient(MakeGarbageCollected<NoopClient>());
    *dest1 = MakeGarbageCollected<BlobBytesConsumer>(execution_context,
                                                     blob_data_handle);
    *dest2 = MakeGarbageCollected<BlobBytesConsumer>(execution_context,
                                                     blob_data_handle);
    return;
  }

  auto form_data = src->DrainAsFormData();
  if (form_data) {
    // Register a client in order to be consistent.
    src->SetClient(MakeGarbageCollected<NoopClient>());
    *dest1 = MakeGarbageCollected<FormDataBytesConsumer>(execution_context,
                                                         form_data);
    *dest2 = MakeGarbageCollected<FormDataBytesConsumer>(execution_context,
                                                         form_data);
    return;
  }

  TeeHelper* tee = MakeGarbageCollected<TeeHelper>(execution_context, src);
  *dest1 = tee->Destination1();
  *dest2 = tee->Destination2();
}

}  // namespace blink
```