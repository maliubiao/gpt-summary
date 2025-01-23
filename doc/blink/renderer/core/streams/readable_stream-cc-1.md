Response:
My thought process to analyze the provided code snippet and generate the description involves the following steps:

1. **Understand the Goal:** The primary goal is to understand the functionality of the `readable_stream.cc` file within the Chromium Blink engine, particularly the code provided in the snippet. This includes identifying its purpose, relationships to web standards (JavaScript, HTML, CSS), logical flow, potential errors, and debugging context.

2. **High-Level Overview:** I first read through the code to get a general sense of what it's doing. Keywords like `Tee`, `ByteStreamTee`, `LockAndDisturb`, `CloseStream`, `Serialize`, `Deserialize`, `PipeTo`, `Cancel`, `Close`, `Error`, and `FulfillRead*Request` immediately suggest this code is about managing the lifecycle and operations of readable streams, a key component of the Streams API.

3. **Decomposition by Function:**  I then break down the code function by function. For each function, I ask:
    * **What is its purpose?** The comments in the code, especially those referencing the WHATWG Streams standard, are invaluable here. I look for phrases like "https://streams.spec.whatwg.org/#...".
    * **What are its inputs and outputs?** This involves identifying the function arguments and what it returns (or modifies). `ScriptState*`, exception states, and pointers to other stream objects are common.
    * **Does it interact with other objects or functions?**  I look for calls to other methods within the `ReadableStream` class or related classes like `ReadableStreamController`, `ReadableStreamReader`, `WritableStream`, `PipeToEngine`, etc.
    * **Are there any assertions or checks (`CHECK`, `DCHECK`)?** These often indicate preconditions or invariants that should hold.
    * **Does it involve asynchronous operations (promises)?**  The presence of `ScriptPromise` suggests asynchronous behavior.

4. **Connecting to Web Standards:**  A crucial part of the request is to link the code to JavaScript, HTML, and CSS.
    * **JavaScript:** The Streams API is directly exposed to JavaScript. I look for functions that correspond to JavaScript methods on `ReadableStream` objects (e.g., `tee()`, `pipeTo()`, `cancel()`, `getReader()`). I also consider how JavaScript code would *use* these functionalities.
    * **HTML:** While the code itself doesn't directly manipulate HTML, I consider scenarios where readable streams are used in HTML contexts, such as fetching data (`fetch API`) or handling media streams.
    * **CSS:**  Readable streams are less directly related to CSS. However, I consider potential indirect links, such as using streams to load CSS resources or manipulate canvas elements where CSS styling might be involved.

5. **Logical Reasoning and Examples:** For functions that involve more complex logic, I try to trace the execution flow. I consider hypothetical input scenarios and predict the outputs. For example, for the `Tee` function, if a readable stream is given, it should produce two new, independent readable streams.

6. **Identifying Common Errors:** Based on my understanding of the Streams API and the code, I consider common mistakes developers might make. For example, trying to operate on a locked stream will lead to an error. Incorrect usage of BYOB readers is another potential source of errors.

7. **Tracing User Interaction:** I think about the user actions that could lead to this specific code being executed. This often involves thinking about JavaScript code that creates and manipulates readable streams, triggered by user events or network requests. The examples I provide are simplified but illustrate the path.

8. **Debugging Clues:** I look for information that would be helpful for a developer debugging issues related to readable streams. This includes understanding the states of the stream, the roles of different reader types, and how errors are handled.

9. **Focus on Part 2:** Since this is specifically "Part 2," I focus on the functionalities present in *this* code snippet. I avoid repeating details extensively covered in "Part 1" (even though I don't have access to Part 1). The request asks to summarize the *current* code.

10. **Structure and Clarity:**  Finally, I organize my analysis into logical sections with clear headings and explanations. I use examples and concise language to make the information accessible. I try to match the format requested in the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file is only about basic stream creation.
* **Correction:** The presence of `Tee`, `PipeTo`, and serialization suggests more advanced stream manipulation.

* **Initial thought:** Focus only on the C++ implementation details.
* **Correction:** The prompt explicitly asks about the relationship to JavaScript, HTML, and CSS, so I need to connect the C++ code to the web platform APIs.

* **Initial thought:** Provide very detailed, low-level explanations of each function.
* **Correction:**  Balance technical detail with higher-level explanations of the purpose and usage of each function, keeping in mind the audience might be web developers using the Streams API in JavaScript.

By following these steps iteratively, I can develop a comprehensive understanding of the code and generate the detailed response provided in the example. The process involves understanding the code itself, its relationship to the web platform, and how developers would interact with it.
好的，让我们继续分析 `blink/renderer/core/streams/readable_stream.cc` 文件的剩余部分，并归纳其功能。

**剩余代码的功能分解：**

这部分代码主要包含以下几个方面的功能：

1. **与 Reader 相关的抽象操作：**
   - `AddReadIntoRequest`:  用于向 BYOB (Bring Your Own Buffer) 读取器添加读取请求。
   - `AddReadRequest`: 用于向默认读取器添加读取请求。
   - `FulfillReadIntoRequest`: 当 BYOB 读取请求成功完成时调用，处理读取到的数据。
   - `FulfillReadRequest`: 当默认读取请求成功完成时调用，处理读取到的数据。
   - `GetNumReadIntoRequests`: 获取 BYOB 读取器中待处理的读取请求数量。
   - `GetNumReadRequests`: 获取默认读取器中待处理的读取请求数量。
   - `HasBYOBReader`: 检查流是否具有 BYOB 读取器。
   - `HasDefaultReader`: 检查流是否具有默认读取器。

2. **流的取消操作：**
   - `Cancel`:  取消可读流的读取。这会触发流的 `disturbed` 状态，如果流未关闭或出错，则关闭流并取消底层数据源。

3. **流的关闭操作：**
   - `Close`: 关闭可读流。这会更新流的状态为 "closed"，并通知相关的读取器。

4. **流的错误处理操作：**
   - `Error`:  使可读流进入错误状态。这会更新流的状态为 "errored"，存储错误信息，并通知相关的读取器。

5. **Tee 操作辅助函数：**
   - `CallTeeAndReturnBranchArray`:  封装了 `Tee` 或 `ByteStreamTee` 的调用，并返回包含两个分支流的数组。

6. **创建迭代器源：**
   - `CreateIterationSource`:  为可读流创建一个迭代器源，用于支持 `for await...of` 循环。

**与 JavaScript, HTML, CSS 的关系举例：**

* **JavaScript:**
    * 当 JavaScript 代码调用 `readableStream.getReader()` 并获取一个默认读取器时，`AddReadRequest` 会被调用来添加读取请求。当数据准备好时，`FulfillReadRequest` 会被调用，并将数据传递给 JavaScript 的 `reader.read()` 返回的 Promise。
    * 当 JavaScript 代码调用 `readableStream.getReader({ mode: 'byob' })` 并获取一个 BYOB 读取器时，`AddReadIntoRequest` 会被调用。当数据被读取到提供的缓冲区后，`FulfillReadIntoRequest` 会被调用。
    * 当 JavaScript 代码调用 `readableStream.cancel(reason)` 时，会触发 C++ 层的 `Cancel` 函数。
    * 当 JavaScript 代码调用 `readableStream.close()` 时，会触发 C++ 层的 `Close` 函数。
    * 当可读流在底层数据源发生错误时（例如网络请求失败），会调用 C++ 层的 `Error` 函数，最终导致 JavaScript 中读取操作的 Promise 被拒绝。
    * JavaScript 的 `readableStream.tee()` 方法会调用 C++ 层的 `CallTeeAndReturnBranchArray`，进而根据流的控制器类型调用 `Tee` 或 `ByteStreamTee`。
    * JavaScript 的 `for await...of` 循环在可读流上使用时，会调用 `CreateIterationSource` 来创建迭代器。

* **HTML:**
    * `<img>` 标签的 `src` 属性可以指向一个返回可读流的资源（例如使用 `fetch` API 获取的响应体）。浏览器内部会使用这些 C++ 代码来处理流式加载的图像数据。
    * `<video>` 和 `<audio>` 标签在流式播放媒体时也会涉及到可读流的处理。

* **CSS:**
    * 虽然不太常见，但如果 CSS 资源也以流的形式提供（理论上可能），那么这部分代码也可能参与其处理过程。例如，通过 JavaScript 使用 `fetch` 获取 CSS 文本并手动解析。

**逻辑推理示例：**

**假设输入：**

* 一个处于 "readable" 状态的 `ReadableStream` 对象 `stream`。
* 一个已经获取了该 `stream` 的默认读取器 `reader`。
* JavaScript 调用了 `reader.read()`，创建了一个待处理的读取请求。
* 底层数据源准备好了一块数据 `chunk`。

**输出：**

1. 控制器（未在代码片段中直接展示，但与 `readable_stream_controller_` 关联）会调用 `ReadableStream::FulfillReadRequest(script_state, stream, chunk, false, exception_state)`。
2. `FulfillReadRequest` 函数会：
   - 断言流具有默认读取器。
   - 获取 `reader`。
   - 断言 `reader` 的读取请求队列不为空。
   - 从 `reader` 的读取请求队列中取出第一个请求。
   - 调用该请求的 `ChunkSteps` 方法，将 `chunk` 数据传递给 JavaScript 的 `reader.read()` 返回的 Promise 的 `resolve` 回调。

**用户或编程常见使用错误举例：**

* **在流被锁定后尝试取消或关闭：**  如果一个流已经被读取器锁定（例如通过 `getReader()` 获取了读取器），用户尝试调用 `stream.cancel()` 或 `stream.close()` 可能会导致意外行为或错误。规范中对此有明确规定，并在某些情况下会抛出异常。
* **BYOB 读取器使用不当：**  使用 BYOB 读取器时，用户需要提供一个预先分配的缓冲区。如果提供的缓冲区太小，会导致数据截断或错误。如果缓冲区在读取操作完成前被修改，可能会导致数据损坏。
* **忘记处理 Promise 的拒绝：**  可读流的读取操作返回 Promise。如果底层数据源发生错误，Promise 将被拒绝。如果用户没有正确处理拒绝的情况，可能会导致程序出现未捕获的异常。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中打开一个网页。**
2. **网页的 JavaScript 代码发起一个网络请求，使用 `fetch` API 并获取响应。**
   ```javascript
   fetch('https://example.com/data.txt')
     .then(response => {
       const reader = response.body.getReader();
       return reader.read();
     })
     .then(({ done, value }) => {
       if (done) {
         console.log('读取完成');
       } else {
         console.log('读取到数据:', value);
       }
     });
   ```
3. **`response.body` 返回一个 `ReadableStream` 对象。**
4. **`response.body.getReader()`  会在 C++ 层创建相应的读取器对象。**
5. **当 `reader.read()` 被调用时，C++ 层的 `AddReadRequest` 函数会被调用，将读取请求添加到读取器的队列中。**
6. **浏览器接收到来自服务器的数据块。**
7. **可读流的控制器接收到数据，并调用 `FulfillReadRequest` 将数据传递给等待的读取请求。**
8. **如果网络请求失败，控制器可能会调用 `Error` 函数，导致读取操作的 Promise 被拒绝。**
9. **如果用户在读取过程中关闭了标签页或导航到其他页面，可能会触发 `Cancel` 函数。**

**总结 `readable_stream.cc` (第2部分) 的功能：**

这部分代码主要负责处理 `ReadableStream` 的核心操作，特别是与 **读取器 (Readers)** 交互相关的部分。它定义了如何添加和完成读取请求（无论是默认读取器还是 BYOB 读取器），以及如何处理流的取消、关闭和错误状态。这些功能是实现 WHATWG Streams 标准中可读流 API 的关键组成部分，使得 JavaScript 能够以高效且可控的方式处理流式数据。此外，它还包含了创建可读流迭代器以及支持 `tee()` 操作的辅助功能。 总体来说，这部分代码专注于 **管理可读流的生命周期和数据流动**，确保数据能够正确地从底层数据源传递给 JavaScript 代码。

### 提示词
```
这是目录为blink/renderer/core/streams/readable_stream.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// initialised correctly.
  // https://streams.spec.whatwg.org/#initialize-readable-stream
  // 1. Set stream.[[state]] to "readable".
  CHECK_EQ(stream->state_, kReadable);
  // 2. Set stream.[[reader]] and stream.[[storedError]] to undefined.
  DCHECK(!stream->reader_);
  DCHECK(stream->stored_error_.IsEmpty());
  // 3. Set stream.[[disturbed]] to false.
  DCHECK(!stream->is_disturbed_);
}

void ReadableStream::Tee(ScriptState* script_state,
                         ReadableStream** branch1,
                         ReadableStream** branch2,
                         bool clone_for_branch2,
                         ExceptionState& exception_state) {
  auto* engine = MakeGarbageCollected<TeeEngine>();
  engine->Start(script_state, this, clone_for_branch2, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // Instead of returning a List like ReadableStreamTee in the standard, the
  // branches are returned via output parameters.
  *branch1 = engine->Branch1();
  *branch2 = engine->Branch2();
}

void ReadableStream::ByteStreamTee(ScriptState* script_state,
                                   ReadableStream** branch1,
                                   ReadableStream** branch2,
                                   ExceptionState& exception_state) {
  auto* engine = MakeGarbageCollected<ByteStreamTeeEngine>();
  engine->Start(script_state, this, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // Instead of returning a List like ReadableByteStreamTee in the standard, the
  // branches are returned via output parameters.
  *branch1 = engine->Branch1();
  *branch2 = engine->Branch2();
}

void ReadableStream::LockAndDisturb(ScriptState* script_state) {
  if (reader_) {
    return;
  }

  DCHECK(!IsLocked(this));

  // Since the stream is not locked, AcquireDefaultReader cannot fail.
  NonThrowableExceptionState exception_state(__FILE__, __LINE__);
  ReadableStreamGenericReader* reader =
      AcquireDefaultReader(script_state, this, exception_state);
  DCHECK(reader);

  is_disturbed_ = true;
}

void ReadableStream::CloseStream(ScriptState* script_state,
                                 ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readablestream-close
  // 1. If stream.[[controller]] implements ReadableByteStreamController,
  if (auto* readable_byte_stream_controller =
          DynamicTo<ReadableByteStreamController>(
              readable_stream_controller_.Get())) {
    // 1. Perform ! ReadableByteStreamControllerClose(stream.[[controller]]).
    TryRethrowScope rethrow_scope(script_state->GetIsolate(), exception_state);
    readable_byte_stream_controller->Close(script_state,
                                           readable_byte_stream_controller);
    if (rethrow_scope.HasCaught()) {
      return;
    }

    // 2. If stream.[[controller]].[[pendingPullIntos]] is not empty, perform !
    // ReadableByteStreamControllerRespond(stream.[[controller]], 0).
    if (readable_byte_stream_controller->pending_pull_intos_.size() > 0) {
      readable_byte_stream_controller->Respond(
          script_state, readable_byte_stream_controller, 0, exception_state);
    }
    if (exception_state.HadException()) {
      return;
    }
  }

  // 2. Otherwise, perform !
  // ReadableStreamDefaultControllerClose(stream.[[controller]]).
  else {
    auto* readable_stream_default_controller =
        To<ReadableStreamDefaultController>(readable_stream_controller_.Get());
    ReadableStreamDefaultController::Close(script_state,
                                           readable_stream_default_controller);
  }
}

void ReadableStream::Serialize(ScriptState* script_state,
                               MessagePort* port,
                               ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rs-transfer
  // 1. If ! IsReadableStreamLocked(value) is true, throw a "DataCloneError"
  //    DOMException.
  if (IsLocked(this)) {
    exception_state.ThrowTypeError("Cannot transfer a locked stream");
    return;
  }

  // Done by SerializedScriptValue::TransferReadableStream():
  // 2. Let port1 be a new MessagePort in the current Realm.
  // 3. Let port2 be a new MessagePort in the current Realm.
  // 4. Entangle port1 and port2.

  // 5. Let writable be a new WritableStream in the current Realm.
  // 6. Perform ! SetUpCrossRealmTransformWritable(writable, port1).
  auto* writable = CreateCrossRealmTransformWritable(
      script_state, port, allow_per_chunk_transferring_, /*optimizer=*/nullptr,
      exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 7. Let promise be ! ReadableStreamPipeTo(value, writable, false, false,
  //    false).
  auto promise = PipeTo(script_state, this, writable,
                        MakeGarbageCollected<PipeOptions>(), exception_state);

  // 8. Set promise.[[PromiseIsHandled]] to true.
  promise.MarkAsHandled();

  // This step is done in a roundabout way by the caller:
  // 9. Set dataHolder.[[port]] to ! StructuredSerializeWithTransfer(port2,
  //    « port2 »).
}

ReadableStream* ReadableStream::Deserialize(
    ScriptState* script_state,
    MessagePort* port,
    std::unique_ptr<ReadableStreamTransferringOptimizer> optimizer,
    ExceptionState& exception_state) {
  // We need to execute JavaScript to call "Then" on v8::Promises. We will not
  // run author code.
  v8::Isolate::AllowJavascriptExecutionScope allow_js(
      script_state->GetIsolate());

  // https://streams.spec.whatwg.org/#rs-transfer
  // These steps are done by V8ScriptValueDeserializer::ReadDOMObject().
  // 1. Let deserializedRecord be !
  //    StructuredDeserializeWithTransfer(dataHolder.[[port]], the current
  //    Realm).
  // 2. Let port be deserializedRecord.[[Deserialized]].

  // 3. Perform ! SetUpCrossRealmTransformReadable(value, port).
  // In the standard |value| contains an uninitialized ReadableStream. In the
  // implementation, we create the stream here.
  auto* readable = CreateCrossRealmTransformReadable(
      script_state, port, std::move(optimizer), exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return readable;
}

ScriptPromise<IDLUndefined> ReadableStream::PipeTo(
    ScriptState* script_state,
    ReadableStream* readable,
    WritableStream* destination,
    PipeOptions* pipe_options,
    ExceptionState& exception_state) {
  auto* engine = MakeGarbageCollected<PipeToEngine>(script_state, pipe_options);
  return engine->Start(readable, destination, exception_state);
}

v8::Local<v8::Value> ReadableStream::GetStoredError(
    v8::Isolate* isolate) const {
  return stored_error_.Get(isolate);
}

std::unique_ptr<ReadableStreamTransferringOptimizer>
ReadableStream::TakeTransferringOptimizer() {
  return std::move(transferring_optimizer_);
}

void ReadableStream::Trace(Visitor* visitor) const {
  visitor->Trace(readable_stream_controller_);
  visitor->Trace(reader_);
  visitor->Trace(stored_error_);
  ScriptWrappable::Trace(visitor);
}

//
// Abstract Operations Used By Controllers
//

void ReadableStream::AddReadIntoRequest(ScriptState* script_state,
                                        ReadableStream* stream,
                                        ReadIntoRequest* readRequest) {
  // https://streams.spec.whatwg.org/#readable-stream-add-read-into-request
  // 1. Assert: stream.[[reader]] implements ReadableStreamBYOBReader.
  DCHECK(stream->reader_->IsBYOBReader());
  // 2. Assert: stream.[[state]] is "readable" or "closed".
  DCHECK(stream->state_ == kReadable || stream->state_ == kClosed);
  // 3. Append readRequest to stream.[[reader]].[[readIntoRequests]].
  ReadableStreamGenericReader* reader = stream->reader_;
  ReadableStreamBYOBReader* byob_reader = To<ReadableStreamBYOBReader>(reader);
  byob_reader->read_into_requests_.push_back(readRequest);
}

void ReadableStream::AddReadRequest(ScriptState* script_state,
                                    ReadableStream* stream,
                                    ReadRequest* read_request) {
  // https://streams.spec.whatwg.org/#readable-stream-add-read-request
  // 1. Assert: ! IsReadableStreamDefaultReader(stream.[[reader]]) is true.
  DCHECK(stream->reader_->IsDefaultReader());

  // 2. Assert: stream.[[state]] is "readable".
  CHECK_EQ(stream->state_, kReadable);

  // 3. Append readRequest to stream.[[reader]].[[readRequests]].
  ReadableStreamGenericReader* reader = stream->reader_;
  ReadableStreamDefaultReader* default_reader =
      To<ReadableStreamDefaultReader>(reader);
  default_reader->read_requests_.push_back(read_request);
}

ScriptPromise<IDLUndefined> ReadableStream::Cancel(
    ScriptState* script_state,
    ReadableStream* stream,
    v8::Local<v8::Value> reason) {
  // https://streams.spec.whatwg.org/#readable-stream-cancel
  // 1. Set stream.[[disturbed]] to true.
  stream->is_disturbed_ = true;

  // 2. If stream.[[state]] is "closed", return a promise resolved with
  //    undefined.
  const auto state = stream->state_;
  if (state == kClosed) {
    return ToResolvedUndefinedPromise(script_state);
  }

  // 3. If stream.[[state]] is "errored", return a promise rejected with stream.
  //    [[storedError]].
  if (state == kErrored) {
    return ScriptPromise<IDLUndefined>::Reject(
        script_state, stream->GetStoredError(script_state->GetIsolate()));
  }

  // 4. Perform ! ReadableStreamClose(stream).
  Close(script_state, stream);

  // 5. Let reader be stream.[[reader]].
  ReadableStreamGenericReader* reader = stream->reader_;

  // 6. If reader is not undefined and reader implements
  // ReadableStreamBYOBReader,
  if (reader && reader->IsBYOBReader()) {
    //   a. Let readIntoRequests be reader.[[readIntoRequests]].
    ReadableStreamBYOBReader* byob_reader =
        To<ReadableStreamBYOBReader>(reader);
    HeapDeque<Member<ReadIntoRequest>> read_into_requests;
    read_into_requests.Swap(byob_reader->read_into_requests_);

    //   b. Set reader.[[readIntoRequests]] to an empty list.
    //      This is not required since we've already called Swap().

    //   c. For each readIntoRequest of readIntoRequests,
    for (ReadIntoRequest* request : read_into_requests) {
      //     i. Perform readIntoRequest's close steps, given undefined.
      request->CloseSteps(script_state, nullptr);
    }
  }

  // 7. Let sourceCancelPromise be !
  // stream.[[controller]].[[CancelSteps]](reason).
  ScriptPromise<IDLUndefined> source_cancel_promise =
      stream->readable_stream_controller_->CancelSteps(script_state, reason);

  class ResolveUndefinedFunction final
      : public ThenCallable<IDLUndefined, ResolveUndefinedFunction> {
   public:
    // Dummy callable to insert a reaction step.
    void React(ScriptState*) {}
  };

  // 8. Return the result of reacting to sourceCancelPromise with a
  //    fulfillment step that returns undefined.
  return source_cancel_promise.Then(
      script_state, MakeGarbageCollected<ResolveUndefinedFunction>());
}

void ReadableStream::Close(ScriptState* script_state, ReadableStream* stream) {
  // https://streams.spec.whatwg.org/#readable-stream-close
  // 1. Assert: stream.[[state]] is "readable".
  CHECK_EQ(stream->state_, kReadable);

  // 2. Set stream.[[state]] to "closed".
  stream->state_ = kClosed;

  // 3. Let reader be stream.[[reader]].
  ReadableStreamGenericReader* reader = stream->reader_;

  // 4. If reader is undefined, return.
  if (!reader) {
    return;
  }

  // Don't resolve promises if the context has been destroyed.
  if (ExecutionContext::From(script_state)->IsContextDestroyed())
    return;

  // 5. Resolve reader.[[closedPromise]] with undefined.
  reader->ClosedResolver()->Resolve();

  // 6. If reader implements ReadableStreamDefaultReader,
  if (reader->IsDefaultReader()) {
    //   a. Let readRequests be reader.[[readRequests]].
    HeapDeque<Member<ReadRequest>> requests;
    requests.Swap(To<ReadableStreamDefaultReader>(reader)->read_requests_);
    //   b. Set reader.[[readRequests]] to an empty list.`
    //      This is not required since we've already called Swap()

    //   c. For each readRequest of readRequests,
    for (ReadRequest* request : requests) {
      //     i. Perform readRequest’s close steps.
      request->CloseSteps(script_state);
    }
  }
}

void ReadableStream::Error(ScriptState* script_state,
                           ReadableStream* stream,
                           v8::Local<v8::Value> e) {
  // https://streams.spec.whatwg.org/#readable-stream-error
  // 1. Assert: stream.[[state]] is "readable".
  CHECK_EQ(stream->state_, kReadable);
  auto* isolate = script_state->GetIsolate();

  // 2. Set stream.[[state]] to "errored".
  stream->state_ = kErrored;

  // 3. Set stream.[[storedError]] to e.
  stream->stored_error_.Reset(isolate, e);

  // 4. Let reader be stream.[[reader]].
  ReadableStreamGenericReader* reader = stream->reader_;

  // 5. If reader is undefined, return.
  if (!reader) {
    return;
  }

  // 6. Reject reader.[[closedPromise]] with e.
  reader->ClosedResolver()->Reject(ScriptValue(isolate, e));

  // 7. Set reader.[[closedPromise]].[[PromiseIsHandled]] to true.
  reader->closed(script_state).MarkAsHandled();

  // 8. If reader implements ReadableStreamDefaultReader,
  if (reader->IsDefaultReader()) {
    //   a. Perform ! ReadableStreamDefaultReaderErrorReadRequests(reader, e).
    ReadableStreamDefaultReader* default_reader =
        To<ReadableStreamDefaultReader>(reader);
    ReadableStreamDefaultReader::ErrorReadRequests(script_state, default_reader,
                                                   e);
  } else {
    // 9. Otherwise,
    // a. Assert: reader implements ReadableStreamBYOBReader.
    DCHECK(reader->IsBYOBReader());
    // b. Perform ! ReadableStreamBYOBReaderErrorReadIntoRequests(reader, e).
    ReadableStreamBYOBReader* byob_reader =
        To<ReadableStreamBYOBReader>(reader);
    ReadableStreamBYOBReader::ErrorReadIntoRequests(script_state, byob_reader,
                                                    e);
  }
}

void ReadableStream::FulfillReadIntoRequest(ScriptState* script_state,
                                            ReadableStream* stream,
                                            DOMArrayBufferView* chunk,
                                            bool done,
                                            ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-stream-fulfill-read-into-request
  // 1. Assert: ! ReadableStreamHasBYOBReader(stream) is true.
  DCHECK(HasBYOBReader(stream));
  // 2. Let reader be stream.[[reader]].
  ReadableStreamGenericReader* reader = stream->reader_;
  ReadableStreamBYOBReader* byob_reader = To<ReadableStreamBYOBReader>(reader);
  // 3. Assert: reader.[[readIntoRequests]] is not empty.
  DCHECK(!byob_reader->read_into_requests_.empty());
  // 4. Let readIntoRequest be reader.[[readIntoRequests]][0].
  ReadIntoRequest* read_into_request = byob_reader->read_into_requests_[0];
  // 5. Remove readIntoRequest from reader.[[readIntoRequests]].
  byob_reader->read_into_requests_.pop_front();
  // 6. If done is true, perform readIntoRequest’s close steps, given chunk.
  if (done) {
    read_into_request->CloseSteps(script_state, chunk);
  } else {
    // 7. Otherwise, perform readIntoRequest’s chunk steps, given chunk.
    read_into_request->ChunkSteps(script_state, chunk, exception_state);
  }
}

void ReadableStream::FulfillReadRequest(ScriptState* script_state,
                                        ReadableStream* stream,
                                        v8::Local<v8::Value> chunk,
                                        bool done,
                                        ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-stream-fulfill-read-request
  // 1. Assert: ! ReadableStreamHasDefaultReader(stream) is true.
  DCHECK(HasDefaultReader(stream));

  // 2. Let reader be stream.[[reader]].
  ReadableStreamGenericReader* reader = stream->reader_;
  ReadableStreamDefaultReader* default_reader =
      To<ReadableStreamDefaultReader>(reader);

  // 3. Assert: reader.[[readRequests]] is not empty.
  DCHECK(!default_reader->read_requests_.empty());

  // 4. Let readRequest be reader.[[readRequests]][0].
  ReadRequest* read_request = default_reader->read_requests_[0];

  // 5. Remove readRequest from reader.[[readRequests]].
  default_reader->read_requests_.pop_front();

  // 6. If done is true, perform readRequest’s close steps.
  if (done) {
    read_request->CloseSteps(script_state);
  } else {
    // 7. Otherwise, perform readRequest’s chunk steps, given chunk.
    read_request->ChunkSteps(script_state, chunk, exception_state);
  }
}

int ReadableStream::GetNumReadIntoRequests(const ReadableStream* stream) {
  // https://streams.spec.whatwg.org/#readable-stream-get-num-read-into-requests
  // 1. Assert: ! ReadableStreamHasBYOBReader(stream) is true.
  DCHECK(HasBYOBReader(stream));
  // 2. Return stream.[[reader]].[[readIntoRequests]]'s size.
  ReadableStreamGenericReader* reader = stream->reader_;
  return To<ReadableStreamBYOBReader>(reader)->read_into_requests_.size();
}

int ReadableStream::GetNumReadRequests(const ReadableStream* stream) {
  // https://streams.spec.whatwg.org/#readable-stream-get-num-read-requests
  // 1. Assert: ! ReadableStreamHasDefaultReader(stream) is true.
  DCHECK(HasDefaultReader(stream));
  // 2. Return the number of elements in stream.[[reader]].[[readRequests]].
  ReadableStreamGenericReader* reader = stream->reader_;
  return To<ReadableStreamDefaultReader>(reader)->read_requests_.size();
}

bool ReadableStream::HasBYOBReader(const ReadableStream* stream) {
  // https://streams.spec.whatwg.org/#readable-stream-has-byob-reader
  // 1. Let reader be stream.[[reader]].
  ReadableStreamGenericReader* reader = stream->reader_;

  // 2. If reader is undefined, return false.
  if (!reader) {
    return false;
  }

  // 3. If reader implements ReadableStreamBYOBReader, return true.
  // 4. Return false.
  return reader->IsBYOBReader();
}

bool ReadableStream::HasDefaultReader(const ReadableStream* stream) {
  // https://streams.spec.whatwg.org/#readable-stream-has-default-reader
  // 1. Let reader be stream.[[reader]].
  ReadableStreamGenericReader* reader = stream->reader_;

  // 2. If reader is undefined, return false.
  if (!reader) {
    return false;
  }

  // 3. If reader implements ReadableStreamDefaultReader, return true.
  // 4. Return false.
  return reader->IsDefaultReader();
}

HeapVector<Member<ReadableStream>> ReadableStream::CallTeeAndReturnBranchArray(
    ScriptState* script_state,
    ReadableStream* readable,
    bool clone_for_branch2,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rs-tee
  ReadableStream* branch1 = nullptr;
  ReadableStream* branch2 = nullptr;

  // 2. Let branches be ? ReadableStreamTee(this, false).
  if (readable->readable_stream_controller_->IsByteStreamController()) {
    readable->ByteStreamTee(script_state, &branch1, &branch2, exception_state);
  } else {
    DCHECK(readable->readable_stream_controller_->IsDefaultController());
    readable->Tee(script_state, &branch1, &branch2, clone_for_branch2,
                  exception_state);
  }

  if (!branch1 || !branch2)
    return HeapVector<Member<ReadableStream>>();

  DCHECK(!exception_state.HadException());

  // 3. Return ! CreateArrayFromList(branches).
  return HeapVector<Member<ReadableStream>>({branch1, branch2});
}

ReadableStream::IterationSourceBase* ReadableStream::CreateIterationSource(
    ScriptState* script_state,
    ReadableStream::IterationSourceBase::Kind kind,
    ReadableStreamIteratorOptions* options,
    ExceptionState& exception_state) {
  // 1. Let reader be ? AcquireReadableStreamDefaultReader(stream).
  ReadableStreamDefaultReader* reader =
      AcquireDefaultReader(script_state, this, exception_state);
  if (!reader) {
    return nullptr;
  }
  // 3. Let preventCancel be args[0]["preventCancel"].
  bool prevent_cancel = options->preventCancel();
  return MakeGarbageCollected<IterationSource>(script_state, kind, reader,
                                               prevent_cancel);
}

}  // namespace blink
```