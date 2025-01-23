Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The primary goal is to explain the functionality of `readable_stream_byob_reader.cc`, its relationships to web technologies, provide examples, and discuss common errors and debugging.

2. **Initial Code Scan (High-Level):** First, I skim the code to get a general idea of its structure and included headers. I see:
    * Headers related to Blink's binding system (`bindings/core/v8`, `platform/bindings`). This strongly suggests interaction with JavaScript.
    * Headers related to streams (`core/streams`). This is the core domain.
    * Typed arrays (`core/typed_arrays`). This points to handling binary data.
    * A nested class `BYOBReaderReadIntoRequest`. This likely represents a pending read operation.
    * Methods like `Create`, `read`, `releaseLock`, `SetUpBYOBReader`. These hint at the lifecycle and operations of the reader.

3. **Focus on the Class Name:** `ReadableStreamBYOBReader` is a key term. "BYOB" likely stands for "Bring Your Own Buffer."  This immediately suggests a reader that allows the user to provide the memory buffer where the data will be read.

4. **Analyze Key Methods:** I examine the main methods to understand their purpose:
    * `Create`:  Standard factory pattern for creating instances.
    * `read`:  The central method for reading data. The arguments `ScriptState`, `DOMArrayBufferView`, and `ExceptionState` clearly indicate it's interacting with JavaScript's typed arrays and error handling. The internal logic involving `ReadableStreamBYOBReaderRead` and `ReadableByteStreamControllerPullInto` shows the core stream processing.
    * `releaseLock`:  Releasing the reader's lock on the stream.
    * `SetUpBYOBReader`:  Initialization logic, including checks for locked streams and the correct controller type.
    * `ErrorReadIntoRequests`: Handling errors for pending read requests.

5. **Connect to Web Concepts:** Based on the class name and methods, I start connecting it to the Web Streams API:
    * **ReadableStream:** This C++ class directly corresponds to the JavaScript `ReadableStream` object.
    * **BYOB (Bring Your Own Buffer):** This confirms the purpose – reading directly into user-provided `ArrayBuffer` or `TypedArray`.
    * **Reader:**  The `ReadableStreamBYOBReader` is a specific type of reader for a `ReadableStream`.
    * **`read()` method:**  This directly maps to the `read()` method on a BYOB reader in JavaScript.

6. **Examine the Nested Class:** `BYOBReaderReadIntoRequest` is a crucial piece. Its methods (`ChunkSteps`, `CloseSteps`, `ErrorSteps`) correspond to different outcomes of the read operation. The use of `ScriptPromiseResolver` confirms that asynchronous operations and promises are involved, mirroring the JavaScript API.

7. **Infer Relationships with JavaScript, HTML, CSS:**
    * **JavaScript:** The strong ties through the binding layer are evident. The `read` method takes `DOMArrayBufferView`, a JavaScript object. The return type is a `ScriptPromise`. Error handling uses `ExceptionState`. This all points to direct interaction.
    * **HTML:**  HTML itself doesn't directly interact with this low-level stream reader. However, JavaScript code running within an HTML page *does*. Examples like downloading files or processing network responses demonstrate this.
    * **CSS:** CSS has no direct relationship with this code, which deals with data streams.

8. **Construct Examples and Scenarios:**  Now, I can create concrete examples based on the understanding gained:
    * **JavaScript Example:** Demonstrating how to get a BYOB reader, create a `Uint8Array`, and call `read()`.
    * **Error Scenarios:**  Focusing on the checks within the `read()` method: zero-length buffers, detached buffers, and using a released reader.

9. **Consider Logic and Assumptions (Input/Output):**
    * **Input:** A `ReadableStream`, a `DOMArrayBufferView`.
    * **Output:** A `Promise` that resolves with a `{ value: TypedArray, done: boolean }` object.
    * **Assumptions:** The underlying stream provides data, the provided buffer is valid.

10. **Think About User/Programming Errors:** This involves identifying common mistakes developers might make when using BYOB readers, such as incorrect buffer sizes or using the reader after it's been released.

11. **Trace User Actions (Debugging Clues):** I consider how a user's interaction might lead to this code being executed:
    * Fetch API with `response.body.getReader({ mode: 'byob' })`.
    * `new ReadableStream({ ... }, { strategy: 'bytes' })`.
    * `pipeTo` with a BYOB reader on the destination.

12. **Refine and Structure the Explanation:** Finally, I organize the information logically, using headings and bullet points for clarity. I make sure to explain the purpose of the code, its relationships, provide examples, and address potential issues. I ensure the language is clear and accessible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "Maybe this is related to file system access?"  *Correction:* The presence of `ReadableStream` strongly suggests network or in-memory streams. The "BYOB" aspect confirms it's not strictly file-based.
* **Realization:** The `ChunkSteps`, `CloseSteps`, `ErrorSteps` pattern is a classic way to handle asynchronous results, aligning perfectly with Promises.
* **Emphasis:**  Highlighting the "zero-copy" nature of BYOB readers as a performance benefit.
* **Clarity:** Ensuring the explanation distinguishes between the C++ code and the corresponding JavaScript API.

By following these steps, blending code analysis with knowledge of web technologies and common programming practices, I can generate a comprehensive and helpful explanation like the example provided.
好的，让我们来详细分析一下 `blink/renderer/core/streams/readable_stream_byob_reader.cc` 这个文件。

**功能概述**

`ReadableStreamBYOBReader.cc` 文件定义了 Chromium Blink 引擎中用于实现 **Readable Streams API** 的 **BYOB (Bring Your Own Buffer) 读取器** 的核心逻辑。

简单来说，BYOB 读取器允许 JavaScript 代码提供一个预先分配的 `ArrayBuffer` 或 `TypedArray`，并将从流中读取的数据直接写入到这个提供的缓冲区中。这种方式可以减少内存分配和拷贝，提高性能，尤其是在处理大量二进制数据时。

**核心功能点:**

1. **创建 BYOB 读取器 (`Create`, 构造函数):**  负责创建 `ReadableStreamBYOBReader` 对象，并进行必要的初始化，例如检查流是否已锁定以及是否是字节流。
2. **发起读取操作 (`read`):**  这是 BYOB 读取器的主要方法，允许 JavaScript 代码请求从流中读取数据到提供的 `DOMArrayBufferView` (本质上是 `ArrayBuffer` 或 `TypedArray` 的视图)。
3. **处理读取结果 (`BYOBReaderReadIntoRequest`):**  定义了一个内部类 `BYOBReaderReadIntoRequest`，用于封装一次读取请求。它包含成功读取到数据 (`ChunkSteps`)、流结束 (`CloseSteps`) 或发生错误 (`ErrorSteps`) 时的处理逻辑。这些步骤会解析相应的 Promise。
4. **底层读取 (`Read`):**  实际执行从 `ReadableByteStreamController` 中拉取数据并写入到提供的缓冲区中的操作。
5. **处理错误的读取请求 (`ErrorReadIntoRequests`):** 当流发生错误时，会遍历所有挂起的读取请求，并用错误信息拒绝对应的 Promise。
6. **释放读取器 (`releaseLock`, `Release`):**  允许释放读取器对流的锁定。释放后，读取器将不再可用。
7. **设置 BYOB 读取器 (`SetUpBYOBReader`):**  执行 BYOB 读取器特定的初始化检查。

**与 JavaScript, HTML, CSS 的关系及举例**

这个文件直接关联到 **JavaScript 的 Streams API**。

* **JavaScript:**  `ReadableStreamBYOBReader` 是 JavaScript 中 `ReadableStream` 对象的一个特定类型的读取器 (`getReader({ mode: 'byob' })`) 在 Blink 引擎中的 C++ 实现。

   **举例:**

   ```javascript
   const response = await fetch('large-binary-file');
   const readableStream = response.body;
   const reader = readableStream.getReader({ mode: 'byob' });

   const buffer = new Uint8Array(new ArrayBuffer(1024)); // 提供一个缓冲区

   try {
     while (true) {
       const { done, value } = await reader.read(buffer); // 调用 read 方法，传入缓冲区
       if (done) {
         console.log('读取完成');
         break;
       }
       // 'value' 是传入的 'buffer' 的子集，包含了读取到的数据
       console.log(`读取到 ${value.byteLength} 字节`);
       // 处理读取到的数据
     }
   } catch (error) {
     console.error('读取出错:', error);
   } finally {
     reader.releaseLock();
   }
   ```

   在这个例子中，`getReader({ mode: 'byob' })` 会在 Blink 引擎内部创建 `ReadableStreamBYOBReader` 的实例。随后调用 `reader.read(buffer)` 会触发 `ReadableStreamBYOBReader::read` 方法，并将 JavaScript 的 `Uint8Array` (对应 C++ 的 `DOMArrayBufferView`) 传递给 C++ 代码。

* **HTML:** HTML 本身不直接涉及流的底层操作，但 HTML 中嵌入的 JavaScript 代码可以使用 Streams API。

   **举例:**  考虑一个使用 `<video>` 标签进行流媒体播放的场景。虽然 `<video>` 元素自身处理流的细节，但底层的实现可能涉及使用 `ReadableStream` 来处理媒体数据的传输。开发者可以通过 JavaScript 获取 `ReadableStream` 并使用 BYOB 读取器进行更底层的控制（尽管这种情况相对高级）。

* **CSS:** CSS 与此文件没有任何直接关系。CSS 负责页面的样式和布局，而 `ReadableStreamBYOBReader` 专注于数据流的读取和处理。

**逻辑推理、假设输入与输出**

假设我们有一个已经创建并处于活动状态的 `ReadableStreamBYOBReader` 实例，以及一个 JavaScript 创建的 `Uint8Array` 作为输入缓冲区。

**假设输入:**

* `script_state`: 当前 JavaScript 执行上下文。
* `view`: 一个 `DOMArrayBufferView` 对象，例如 `Uint8Array(new ArrayBuffer(100))`，长度为 100 字节。

**`ReadableStreamBYOBReader::read` 方法的逻辑推理:**

1. **检查输入缓冲区:**
   - 如果 `view` 的 `byteLength` 为 0，抛出 `TypeError` 并返回一个 rejected 的 Promise。
   - 如果 `view` 关联的 `ArrayBuffer` 的 `ByteLength` 为 0，抛出 `TypeError` 并返回一个 rejected 的 Promise。
   - 如果 `view` 关联的 `ArrayBuffer` 已经分离 (detached)，抛出 `TypeError` 并返回一个 rejected 的 Promise。
2. **检查读取器状态:**
   - 如果读取器的 `owner_readable_stream_` 为空 (undefined)，表示读取器已被释放，抛出 `TypeError` 并返回一个 rejected 的 Promise。
3. **创建 Promise 和读取请求:**
   - 创建一个新的 JavaScript `Promise` 对象。
   - 创建一个 `BYOBReaderReadIntoRequest` 对象，用于处理读取操作的结果 (成功、结束、错误)。
4. **调用底层读取:**
   - 调用 `Read` 方法，将读取器、输入缓冲区和读取请求对象传递下去。

**`ReadableStreamBYOBReader::Read` 方法的逻辑推理:**

1. **获取流:** 从读取器中获取关联的 `ReadableStream`。
2. **设置流为已扰乱:**  设置 `stream->is_disturbed_ = true;`，表示流已被读取过。
3. **检查流状态:**
   - 如果流的状态是 "errored"，调用 `read_into_request` 的 `ErrorSteps` 方法，用存储的错误信息拒绝 Promise。
   - 否则，调用 `ReadableByteStreamController::PullInto`，尝试从流的控制器中拉取数据到提供的缓冲区。

**假设输出 (成功读取):**

* `read` 方法返回一个 `Promise`，该 `Promise` 将会 resolve，并带有一个 `ReadableStreamReadResult` 对象，其结构类似于：
  ```javascript
  {
    value: Uint8Array(n), //  n 是实际读取到的字节数 (0 <= n <= 100)
    done: false          //  表示流尚未结束
  }
  ```
  这里的 `Uint8Array(n)` 是传入的 `view` 的一个子集 (view)。数据会被直接写入到 `view` 的底层 `ArrayBuffer` 中。

**假设输出 (流结束):**

* `read` 方法返回的 `Promise` 会 resolve，并带有一个 `ReadableStreamReadResult` 对象：
  ```javascript
  {
    value: Uint8Array(n) 或 undefined, // 如果在结束前读取到数据，则包含数据，否则为 undefined
    done: true                     // 表示流已结束
  }
  ```

**假设输出 (发生错误):**

* `read` 方法返回的 `Promise` 会 reject，并带有一个表示错误的 JavaScript 值 (通常是一个 `Error` 对象)。

**用户或编程常见的使用错误及举例**

1. **提供的缓冲区长度为 0:**

   ```javascript
   const reader = readableStream.getReader({ mode: 'byob' });
   const buffer = new Uint8Array(0); // 错误：缓冲区长度为 0
   reader.read(buffer); // 将抛出 TypeError
   ```
   **错误信息:** "This readable stream reader cannot be used to read as the view has byte length equal to 0"

2. **提供的缓冲区的 ArrayBuffer 长度为 0:**

   ```javascript
   const reader = readableStream.getReader({ mode: 'byob' });
   const buffer = new Uint8Array(new ArrayBuffer(0)); // 错误：ArrayBuffer 长度为 0
   reader.read(buffer); // 将抛出 TypeError
   ```
   **错误信息:** "This readable stream reader cannot be used to read as the viewed array buffer has 0 byte length"

3. **提供的缓冲区的 ArrayBuffer 已分离:**

   ```javascript
   const reader = readableStream.getReader({ mode: 'byob' });
   const arrayBuffer = new ArrayBuffer(100);
   const buffer = new Uint8Array(arrayBuffer);
   arrayBuffer.detach(); // 分离 ArrayBuffer
   reader.read(buffer); // 将抛出 TypeError
   ```
   **错误信息:** "This readable stream reader cannot be used to read as the viewed array buffer is detached"

4. **在读取器被释放后尝试读取:**

   ```javascript
   const reader = readableStream.getReader({ mode: 'byob' });
   reader.releaseLock();
   const buffer = new Uint8Array(100);
   reader.read(buffer); // 将抛出 TypeError
   ```
   **错误信息:** "This readable stream reader has been released and cannot be used to read from its previous owner stream"

5. **对非字节流使用 BYOB 读取器:**

   ```javascript
   const readableStream = new ReadableStream(); // 非字节流
   readableStream.getReader({ mode: 'byob' }); // 将抛出 TypeError
   ```
   **错误信息:** "Cannot use a BYOB reader with a non-byte stream" (通常在创建读取器时抛出，在 `SetUpBYOBReader` 中检查)

**用户操作如何一步步到达这里，作为调试线索**

当用户在网页上执行某些操作，导致 JavaScript 代码使用了 Fetch API 或 `ReadableStream` API 并获取了 BYOB 读取器时，代码执行流程最终会触及 `readable_stream_byob_reader.cc` 中的逻辑。以下是一些可能的场景：

1. **下载大文件:** 用户点击下载链接，JavaScript 使用 `fetch` API 获取响应，并调用 `response.body.getReader({ mode: 'byob' })` 来高效地读取响应体到预分配的缓冲区中。调试时，如果发现读取操作异常，可以检查 `ReadableStreamBYOBReader::read` 的参数，例如提供的缓冲区是否有效。

2. **处理来自 WebSocket 的二进制数据:** 用户连接到 WebSocket 服务，接收到二进制消息。JavaScript 代码可能会创建一个 `ReadableStream` 来处理 WebSocket 数据，并使用 BYOB 读取器来避免不必要的内存拷贝。调试时，可以追踪数据是如何写入缓冲区的，以及是否发生了错误。

3. **使用 Service Worker 拦截请求:** Service Worker 可以拦截网络请求，并返回自定义的 `Response` 对象，其 `body` 可以是一个 `ReadableStream`。如果 Service Worker 使用 BYOB 读取器来处理请求体，那么相关的逻辑就会在 `readable_stream_byob_reader.cc` 中执行。调试时，可以检查 Service Worker 的实现，看是否有不正确的缓冲区操作。

4. **使用 `pipeTo` 将一个可读流管道到一个可写流:** 如果一个可读流的读取器是 BYOB 读取器，那么在 `pipeTo` 操作过程中，会涉及到 `readable_stream_byob_reader.cc` 中的读取逻辑。调试时，可以检查管道的配置和流的状态。

**调试线索:**

* **断点:** 在 `ReadableStreamBYOBReader::read` 和 `ReadableStreamBYOBReader::Read` 等关键方法设置断点，查看传入的参数 (特别是 `view`)，以及流的状态。
* **日志输出:** 在关键路径添加日志输出，记录缓冲区的长度、ArrayBuffer 的状态以及读取操作的结果。
* **Chrome 开发者工具:** 使用 Chrome 开发者工具的 "Sources" 面板，可以单步调试 JavaScript 代码，查看 `getReader({ mode: 'byob' })` 的调用以及后续的 `read` 操作。
* **`chrome://inspect/#devices`:** 对于 Service Worker 相关的调试，可以使用 Chrome 的 `chrome://inspect/#devices` 页面来检查 Service Worker 的状态和日志。
* **Web Streams API 的错误处理:**  确保 JavaScript 代码正确处理了 `reader.read()` 返回的 Promise 的 rejected 状态，并输出了有意义的错误信息。

总而言之，`readable_stream_byob_reader.cc` 是 Blink 引擎中实现高性能数据读取的关键组件，它与 JavaScript 的 Streams API 紧密相连，允许开发者进行更底层的、更高效的数据流处理。理解其功能和常见错误，有助于调试涉及 BYOB 读取器的 Web 应用。

### 提示词
```
这是目录为blink/renderer/core/streams/readable_stream_byob_reader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/readable_stream_byob_reader.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/core/streams/read_into_request.h"
#include "third_party/blink/renderer/core/streams/readable_byte_stream_controller.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_controller.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"

namespace blink {

class ReadableStreamBYOBReader::BYOBReaderReadIntoRequest final
    : public ReadIntoRequest {
 public:
  explicit BYOBReaderReadIntoRequest(
      ScriptPromiseResolver<ReadableStreamReadResult>* resolver)
      : resolver_(resolver) {}

  void ChunkSteps(ScriptState* script_state,
                  DOMArrayBufferView* chunk,
                  ExceptionState& exception_state) const override {
    auto* read_result = ReadableStreamReadResult::Create();
    read_result->setValue(
        ScriptValue(script_state->GetIsolate(),
                    ToV8Traits<DOMArrayBufferView>::ToV8(script_state, chunk)));
    read_result->setDone(false);
    resolver_->Resolve(read_result);
  }

  void CloseSteps(ScriptState* script_state,
                  DOMArrayBufferView* chunk) const override {
    auto* read_result = ReadableStreamReadResult::Create();
    read_result->setValue(ScriptValue(
        script_state->GetIsolate(),
        chunk ? ToV8Traits<DOMArrayBufferView>::ToV8(script_state, chunk)
              : static_cast<v8::Local<v8::Value>>(
                    v8::Undefined(script_state->GetIsolate()))));
    read_result->setDone(true);
    resolver_->Resolve(read_result);
  }

  void ErrorSteps(ScriptState*, v8::Local<v8::Value> e) const override {
    resolver_->Reject(e);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(resolver_);
    ReadIntoRequest::Trace(visitor);
  }

 private:
  Member<ScriptPromiseResolver<ReadableStreamReadResult>> resolver_;
};

ReadableStreamBYOBReader* ReadableStreamBYOBReader::Create(
    ScriptState* script_state,
    ReadableStream* stream,
    ExceptionState& exception_state) {
  auto* reader = MakeGarbageCollected<ReadableStreamBYOBReader>(
      script_state, stream, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return reader;
}

ReadableStreamBYOBReader::ReadableStreamBYOBReader(
    ScriptState* script_state,
    ReadableStream* stream,
    ExceptionState& exception_state) {
  SetUpBYOBReader(script_state, this, stream, exception_state);
}

ReadableStreamBYOBReader::~ReadableStreamBYOBReader() = default;

ScriptPromise<ReadableStreamReadResult> ReadableStreamBYOBReader::read(
    ScriptState* script_state,
    NotShared<DOMArrayBufferView> view,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#byob-reader-read
  // 1. If view.[[ByteLength]] is 0, return a promise rejected with a TypeError
  // exception.
  if (view->byteLength() == 0) {
    exception_state.ThrowTypeError(
        "This readable stream reader cannot be used to read as the view has "
        "byte length equal to 0");
    return EmptyPromise();
  }

  // 2. If view.[[ViewedArrayBuffer]].[[ArrayBufferByteLength]] is 0, return a
  // promise rejected with a TypeError exception.
  if (view->buffer()->ByteLength() == 0) {
    exception_state.ThrowTypeError(
        "This readable stream reader cannot be used to read as the viewed "
        "array buffer has 0 byte length");
    return EmptyPromise();
  }

  // 3. If ! IsDetachedBuffer(view.[[ViewedArrayBuffer]]) is true, return a
  // promise rejected with a TypeError exception.
  if (view->buffer()->IsDetached()) {
    exception_state.ThrowTypeError(
        "This readable stream reader cannot be used to read as the viewed "
        "array buffer is detached");
    return EmptyPromise();
  }

  // 4. If this.[[stream]] is undefined, return a promise rejected with a
  // TypeError exception.
  if (!owner_readable_stream_) {
    exception_state.ThrowTypeError(
        "This readable stream reader has been released and cannot be used to "
        "read from its previous owner stream");
    return EmptyPromise();
  }

  // 5. Let promise be a new promise.
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<ReadableStreamReadResult>>(
          script_state, exception_state.GetContext());

  // 6. Let readIntoRequest be a new read-into request with the following items:
  //    chunk steps, given chunk
  //      1. Resolve promise with «[ "value" → chunk, "done" → false ]».
  //    close steps, given chunk
  //      1. Resolve promise with «[ "value" → chunk, "done" → true ]».
  //    error steps, given e
  //      1. Reject promise with e.
  auto* read_into_request =
      MakeGarbageCollected<BYOBReaderReadIntoRequest>(resolver);

  // 7. Perform ! ReadableStreamBYOBReaderRead(this, view, readIntoRequest).
  Read(script_state, this, view, read_into_request, exception_state);
  // 8. Return promise.
  return resolver->Promise();
}

void ReadableStreamBYOBReader::Read(ScriptState* script_state,
                                    ReadableStreamBYOBReader* reader,
                                    NotShared<DOMArrayBufferView> view,
                                    ReadIntoRequest* read_into_request,
                                    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-stream-byob-reader-read
  // 1. Let stream be reader.[[stream]].
  ReadableStream* stream = reader->owner_readable_stream_;

  // 2. Assert: stream is not undefined.
  DCHECK(stream);

  // 3. Set stream.[[disturbed]] to true.
  stream->is_disturbed_ = true;

  // 4. If stream.[[state]] is "errored", perform readIntoRequest's error steps
  // given stream.[[storedError]].
  if (stream->state_ == ReadableStream::kErrored) {
    read_into_request->ErrorSteps(
        script_state, stream->GetStoredError(script_state->GetIsolate()));
  } else {
    // 5. Otherwise, perform !
    // ReadableByteStreamControllerPullInto(stream.[[controller]], view,
    // readIntoRequest).
    ReadableStreamController* controller = stream->readable_stream_controller_;
    ReadableByteStreamController::PullInto(
        script_state, To<ReadableByteStreamController>(controller), view,
        read_into_request, exception_state);
  }
}

void ReadableStreamBYOBReader::ErrorReadIntoRequests(
    ScriptState* script_state,
    ReadableStreamBYOBReader* reader,
    v8::Local<v8::Value> e) {
  // https://streams.spec.whatwg.org/#abstract-opdef-readablestreambyobreadererrorreadintorequests
  // 1. Let readIntoRequests be reader.[[readIntoRequests]].
  // 2. Set reader.[[readIntoRequests]] to a new empty list.
  HeapDeque<Member<ReadIntoRequest>> read_into_requests;
  read_into_requests.Swap(reader->read_into_requests_);
  // 3. For each readIntoRequest of readIntoRequests,
  for (ReadIntoRequest* request : read_into_requests) {
    //   a. Perform readIntoRequest’s error steps, given e.
    request->ErrorSteps(script_state, e);
  }
}

void ReadableStreamBYOBReader::Release(ScriptState* script_state,
                                       ReadableStreamBYOBReader* reader) {
  // https://streams.spec.whatwg.org/#abstract-opdef-readablestreambyobreaderrelease
  // 1. Perform ! ReadableStreamReaderGenericRelease(reader).
  ReadableStreamGenericReader::GenericRelease(script_state, reader);

  // 2. Let e be a new TypeError exception.
  v8::Local<v8::Value> e = V8ThrowException::CreateTypeError(
      script_state->GetIsolate(), "Releasing BYOB reader");

  // 3. Perform ! ReadableStreamBYOBReaderErrorReadIntoRequests(reader, e).
  ErrorReadIntoRequests(script_state, reader, e);
}

void ReadableStreamBYOBReader::releaseLock(ScriptState* script_state,
                                           ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#byob-reader-release-lock
  // 1. If this.[[stream]] is undefined, return.
  if (!owner_readable_stream_) {
    return;
  }

  // 2. Perform ! ReadableStreamBYOBReaderRelease(this).
  Release(script_state, this);
}

void ReadableStreamBYOBReader::SetUpBYOBReader(
    ScriptState* script_state,
    ReadableStreamBYOBReader* reader,
    ReadableStream* stream,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#set-up-readable-stream-byob-reader
  // If ! IsReadableStreamLocked(stream) is true, throw a TypeError exception.
  if (ReadableStream::IsLocked(stream)) {
    exception_state.ThrowTypeError(
        "ReadableStreamBYOBReader constructor can only accept readable streams "
        "that are not yet locked to a reader");
    return;
  }

  // If stream.[[controller]] does not implement ReadableByteStreamController,
  // throw a TypeError exception.
  if (!stream->readable_stream_controller_->IsByteStreamController()) {
    exception_state.ThrowTypeError(
        "Cannot use a BYOB reader with a non-byte stream");
    return;
  }

  // Perform ! ReadableStreamReaderGenericInitialize(reader, stream).
  ReadableStreamGenericReader::GenericInitialize(script_state, reader, stream);

  // Set reader.[[readIntoRequests]] to a new empty list.
  DCHECK_EQ(reader->read_into_requests_.size(), 0u);
}

void ReadableStreamBYOBReader::Trace(Visitor* visitor) const {
  visitor->Trace(read_into_requests_);
  ReadableStreamGenericReader::Trace(visitor);
}

}  // namespace blink
```