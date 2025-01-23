Response:
The user wants to understand the functionality of the provided C++ code snippet from `writable_stream.cc`. This is the second part of the file. I need to:

1. **Summarize the functionality** of the given code.
2. **Identify connections to JavaScript, HTML, and CSS**, providing examples if any exist. Since this is backend code, direct connections might be limited, but I need to think about how the concepts are exposed in the web platform.
3. **Illustrate logical reasoning** with input and output examples. This will likely involve the internal state transitions of the `WritableStream`.
4. **Point out common user or programming errors** related to the code's functionality.
5. **Explain how user actions can lead to this code being executed**, providing a debugging context.
6. **Since this is part 2, I need to synthesize the information with the understanding from part 1** to provide a complete picture.

**Part 1 Recap (Inferred from the file name and common knowledge about streams):** The first part likely dealt with the basic structure and initial setup of the `WritableStream`, potentially including methods for writing data.

**Analyzing the current code snippet:**

- **`SetCloseRequest`, `SetController`, `SetWriter`, `TakeTransferringOptimizer`**: These are setter and getter-like methods for internal state management.
- **`CreateCannotActionOnStateStreamMessage`, `CreateCannotActionOnStateStreamException`**: These static methods are for creating error messages and exceptions related to the stream's state (closed or errored). This strongly indicates the code handles state management and error reporting.
- **`Trace`**: This method is part of Blink's tracing infrastructure for debugging and garbage collection. It lists the internal members of the `WritableStream` that need to be tracked.
- **`InitInternal`**: This method initializes the `WritableStream` based on JavaScript parameters (`raw_underlying_sink`, `raw_strategy`). It handles the conversion of JavaScript objects to C++ representations and validation of the input. It sets up the `WritableStreamDefaultController`.
- **`HasOperationMarkedInFlight`**: This method checks if there's an ongoing write or close operation.
- **`RejectCloseAndClosedPromiseIfNeeded`**: This method handles the rejection of promises associated with closing the stream when the stream has entered an error state.
- **`RejectPromises`**: A utility function to reject a queue of promises with a given error.

**Connecting to web technologies:**

- **JavaScript:** The `WritableStream` API is directly exposed to JavaScript. The `InitInternal` method directly interacts with JavaScript values. The error messages generated are likely used in JavaScript exceptions. Promises are a core JavaScript concept used for asynchronous operations.
- **HTML:**  While not directly related to HTML rendering, the `WritableStream` can be used in conjunction with technologies like `<canvas>` or file downloads initiated from the browser.
- **CSS:** No direct relation to CSS.

**Logical Reasoning:** The state transitions of the `WritableStream` are central here. Methods like `RejectCloseAndClosedPromiseIfNeeded` are triggered based on the stream's state.

**User/Programming Errors:** Trying to write to or close a stream that is already closed or errored is a common mistake.

**User Actions:**  Calling methods like `WritableStream.getWriter().write()`, `WritableStream.close()`, or encountering errors during underlying sink operations can lead to this code being executed.
好的，这是 `blink/renderer/core/streams/writable_stream.cc` 文件第二部分的分析。结合你提供的代码片段，我们可以归纳出以下功能：

**核心功能归纳:**

1. **管理 WritableStream 的状态和关联对象:** 这部分代码主要负责管理 `WritableStream` 对象的内部状态，例如 `close_request_`（关闭请求）、`writable_stream_controller_`（控制器）、`writer_`（写入器）等。它提供了设置和获取这些关联对象的方法。

2. **处理关闭操作和错误状态:**  代码中包含处理流关闭请求和错误状态的逻辑。例如，`SetCloseRequest` 用于设置关闭请求的 Promise 解析器。`CreateCannotActionOnStateStreamMessage` 和 `CreateCannotActionOnStateStreamException` 用于创建特定状态下（例如已关闭或已出错）无法执行操作的错误消息和异常。`RejectCloseAndClosedPromiseIfNeeded` 函数则在流进入错误状态时，拒绝与关闭操作相关的 Promise。

3. **实现 WritableStream 的初始化:** `InitInternal` 方法负责 `WritableStream` 对象的初始化，该初始化过程会处理 JavaScript 传递过来的底层 sink 和策略 (strategy) 参数。这包括验证参数，创建和配置 `WritableStreamDefaultController`。

4. **追踪进行中的操作:** `HasOperationMarkedInFlight` 用于判断流是否有正在进行的写入或关闭操作。

5. **提供调试和内存管理支持:** `Trace` 方法用于 Blink 的垃圾回收和调试机制，它标记了 `WritableStream` 对象中需要追踪的成员变量，以防止过早释放。

6. **提供拒绝 Promise 的工具函数:** `RejectPromises` 是一个通用的工具函数，用于拒绝一个 Promise 队列中的所有 Promise，通常用于处理错误情况。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**
    * **关联性:**  `WritableStream` API 是 JavaScript Streams API 的一部分，直接暴露给 JavaScript 代码使用。 这部分 C++ 代码实现了 JavaScript 中 `WritableStream` 对象在 Blink 渲染引擎中的底层逻辑。
    * **举例:**
        * JavaScript 代码调用 `new WritableStream(underlyingSink, strategy)` 时，会最终调用到 C++ 的 `WritableStream::InitInternal` 方法来完成初始化。
        * 当 JavaScript 代码调用 `writableStream.getWriter().close()` 时，会创建一个关闭请求，并可能通过 `SetCloseRequest` 设置 `close_request_`。
        * 如果在 JavaScript 中对一个已经关闭或出错的 `WritableStream` 执行操作（例如 `write()`），会抛出 `TypeError` 异常，这个异常的创建可能使用了 `CreateCannotActionOnStateStreamException`。

* **HTML:**
    * **关联性:** `WritableStream` 可以用于处理来自 HTML 元素（如 `<form>` 或通过 Fetch API 获取的响应体）的数据。 例如，可以将通过 Fetch API 获取的响应体 `body` 的 `readable` 流，通过管道连接到一个 `WritableStream` 来处理接收到的数据。
    * **举例:**  假设一个网页使用 JavaScript 获取一个大的文件：
        ```javascript
        fetch('/large-file')
          .then(response => {
            const reader = response.body.getReader();
            const writableStream = new WritableStream({
              write(chunk) {
                // 处理接收到的数据块
                console.log('Received chunk:', chunk);
              }
            });
            return reader.pipeTo(writableStream);
          });
        ```
        在这个例子中，`writableStream` 的创建和操作会涉及到 `writable_stream.cc` 中的代码执行。

* **CSS:**
    * **关联性:**  `WritableStream` 与 CSS 没有直接的关联。CSS 主要负责页面的样式和布局。

**逻辑推理、假设输入与输出:**

假设输入：

1. JavaScript 代码创建了一个 `WritableStream` 实例，并提供了一个 `underlyingSink` 对象，其中包含一个 `close` 方法。
2. JavaScript 代码调用了 `writer.close()` 方法。

逻辑推理和输出：

1. `writer.close()` 的调用会触发 Blink 内部创建关闭请求。
2. `SetCloseRequest` 方法会被调用，将与关闭操作关联的 Promise 解析器存储到 `close_request_` 成员变量中。
3. 在适当的时机（例如所有挂起的写入操作完成），`WritableStream` 的状态会变为 `kClosed`。
4. 如果在此过程中发生错误，`WritableStream` 的状态可能变为 `kErrored`，并且 `RejectCloseAndClosedPromiseIfNeeded` 会被调用，使用 `stored_error_` 拒绝 `close_request_` 对应的 Promise。
5. `HasOperationMarkedInFlight` 会在有正在进行的写入或关闭操作时返回 `true`，否则返回 `false`。

**用户或编程常见的使用错误及举例:**

1. **在流已关闭或出错后尝试写入:**
    ```javascript
    const writer = writableStream.getWriter();
    writableStream.close();
    writer.write('some data'); // 错误：无法对已关闭的流执行操作
    ```
    这会触发类似 `CreateCannotActionOnStateStreamException` 创建的异常。

2. **没有正确处理关闭或错误状态下的 Promise:**
    ```javascript
    writableStream.closed.then(() => {
      console.log('Stream closed');
    }).catch(error => {
      console.error('Stream error:', error); // 没有 catch 错误可能导致未处理的 Promise 拒绝
    });
    ```
    如果流在关闭过程中出错，并且没有 `.catch()` 处理，可能会导致意外的行为。

3. **在底层 sink 的 `close` 方法中抛出错误:**
    ```javascript
    const writableStream = new WritableStream({
      close() {
        throw new Error('Failed to close');
      },
      write(chunk) {}
    });
    writableStream.close(); // 这将导致流进入错误状态，并拒绝相关的 Promise
    ```
    这会触发 `RejectCloseAndClosedPromiseIfNeeded`，并将错误传递给 JavaScript 的 Promise。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在网页上触发了一个需要写入数据的操作:** 例如，用户点击了“保存”按钮，导致浏览器需要将数据写入到某个目的地（例如，通过 Service Worker 下载文件）。
2. **JavaScript 代码创建了一个 `WritableStream`:** 可能是为了对接一个不支持直接写入的底层 API，或者为了自定义数据处理流程。
3. **JavaScript 代码获取了 `WritableStream` 的 `writer`:** 通过 `writableStream.getWriter()` 获取。
4. **JavaScript 代码调用 `writer.write(chunk)` 多次写入数据:** 这些调用会触发 Blink 内部的写入逻辑。
5. **用户触发了关闭流的操作:** 例如，下载完成，或者用户主动取消了操作，JavaScript 代码调用 `writer.close()` 或 `writableStream.close()`。
6. **在关闭过程中或之前发生错误:** 例如，网络连接中断，底层 sink 写入失败，或者 sink 的 `close` 方法抛出异常。
7. **Blink 引擎执行 `writable_stream.cc` 中的代码:**
    * `SetCloseRequest` 可能被调用来记录关闭请求。
    * 如果发生错误，`RejectCloseAndClosedPromiseIfNeeded` 会被调用来拒绝相关的 Promise。
    * `CreateCannotActionOnStateStreamException` 会在尝试对已关闭或出错的流执行操作时被调用。

**总结 (结合第 1 部分):**

结合推测的第 1 部分内容（可能包含 `WritableStream` 的构造、基本写入操作等），这第二部分的代码主要关注于 `WritableStream` 的状态管理、关闭流程、错误处理以及与 JavaScript Promise 的集成。`WritableStream` 作为 Streams API 的一部分，在 Blink 引擎中扮演着数据接收和处理的关键角色。它通过与 `WritableStreamDefaultController` 和 `WritableStreamDefaultWriter` 等组件的协作，实现了 JavaScript 中 `WritableStream` 对象的完整功能。这部分代码确保了在各种状态下（包括正常关闭和发生错误时） `WritableStream` 能够正确地响应和通知 JavaScript 代码，并通过 Blink 的追踪机制进行有效的内存管理和调试。

### 提示词
```
这是目录为blink/renderer/core/streams/writable_stream.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
equest(
    ScriptPromiseResolver<IDLUndefined>* close_request) {
  close_request_ = close_request;
}

void WritableStream::SetController(
    WritableStreamDefaultController* controller) {
  writable_stream_controller_ = controller;
}

void WritableStream::SetWriter(WritableStreamDefaultWriter* writer) {
  writer_ = writer;
}

std::unique_ptr<WritableStreamTransferringOptimizer>
WritableStream::TakeTransferringOptimizer() {
  return std::move(transferring_optimizer_);
}

// static
v8::Local<v8::String> WritableStream::CreateCannotActionOnStateStreamMessage(
    v8::Isolate* isolate,
    const char* action,
    const char* state_name) {
  return V8String(isolate, String::Format("Cannot %s a %s writable stream",
                                          action, state_name));
}

// static
v8::Local<v8::Value> WritableStream::CreateCannotActionOnStateStreamException(
    v8::Isolate* isolate,
    const char* action,
    State state) {
  const char* state_name = nullptr;
  switch (state) {
    case WritableStream::kClosed:
      state_name = "CLOSED";
      break;

    case WritableStream::kErrored:
      state_name = "ERRORED";
      break;

    default:
      NOTREACHED();
  }
  return v8::Exception::TypeError(
      CreateCannotActionOnStateStreamMessage(isolate, action, state_name));
}

void WritableStream::Trace(Visitor* visitor) const {
  visitor->Trace(close_request_);
  visitor->Trace(in_flight_write_request_);
  visitor->Trace(in_flight_close_request_);
  visitor->Trace(pending_abort_request_);
  visitor->Trace(stored_error_);
  visitor->Trace(writable_stream_controller_);
  visitor->Trace(writer_);
  visitor->Trace(write_requests_);
  ScriptWrappable::Trace(visitor);
}

// This is not implemented inside the constructor in C++, because calling into
// JavaScript from the constructor can cause GC problems.
void WritableStream::InitInternal(ScriptState* script_state,
                                  ScriptValue raw_underlying_sink,
                                  ScriptValue raw_strategy,
                                  ExceptionState& exception_state) {
  // The first parts of this constructor implementation correspond to the object
  // conversions that are implicit in the definition in the standard:
  // https://streams.spec.whatwg.org/#ws-constructor
  DCHECK(!raw_underlying_sink.IsEmpty());
  DCHECK(!raw_strategy.IsEmpty());

  auto context = script_state->GetContext();
  auto* isolate = script_state->GetIsolate();

  v8::Local<v8::Object> underlying_sink;
  ScriptValueToObject(script_state, raw_underlying_sink, &underlying_sink,
                      exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 2. Let size be ? GetV(strategy, "size").
  // 3. Let highWaterMark be ? GetV(strategy, "highWaterMark").
  StrategyUnpacker strategy_unpacker(script_state, raw_strategy,
                                     exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 4. Let type be ? GetV(underlyingSink, "type").
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::Local<v8::Value> type;
  if (!underlying_sink->Get(context, V8AtomicString(isolate, "type"))
           .ToLocal(&type)) {
    return;
  }

  // 5. If type is not undefined, throw a RangeError exception.
  if (!type->IsUndefined()) {
    exception_state.ThrowRangeError("Invalid type is specified");
    return;
  }

  // 6. Let sizeAlgorithm be ? MakeSizeAlgorithmFromSizeFunction(size).
  auto* size_algorithm =
      strategy_unpacker.MakeSizeAlgorithm(script_state, exception_state);
  if (exception_state.HadException()) {
    return;
  }
  DCHECK(size_algorithm);

  // 7. If highWaterMark is undefined, let highWaterMark be 1.
  // 8. Set highWaterMark to ? ValidateAndNormalizeHighWaterMark(highWaterMark).
  double high_water_mark =
      strategy_unpacker.GetHighWaterMark(script_state, 1, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 9. Perform ? SetUpWritableStreamDefaultControllerFromUnderlyingSink(this,
  //    underlyingSink, highWaterMark, sizeAlgorithm).
  WritableStreamDefaultController::SetUpFromUnderlyingSink(
      script_state, this, underlying_sink, high_water_mark, size_algorithm,
      exception_state);
}

bool WritableStream::HasOperationMarkedInFlight(const WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-has-operation-marked-in-flight
  //  1. If stream.[[inFlightWriteRequest]] is undefined and
  //     controller.[[inFlightCloseRequest]] is undefined, return false.
  //  2. Return true.
  return stream->in_flight_write_request_ || stream->in_flight_close_request_;
}

void WritableStream::RejectCloseAndClosedPromiseIfNeeded(
    ScriptState* script_state,
    WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-reject-close-and-closed-promise-if-needed
  // //  1. Assert: stream.[[state]] is "errored".
  CHECK_EQ(stream->state_, kErrored);

  auto* isolate = script_state->GetIsolate();

  //  2. If stream.[[closeRequest]] is not undefined,
  if (stream->close_request_) {
    //      a. Assert: stream.[[inFlightCloseRequest]] is undefined.
    DCHECK(!stream->in_flight_close_request_);

    //      b. Reject stream.[[closeRequest]] with stream.[[storedError]].
    stream->close_request_->Reject(stream->stored_error_.Get(isolate));

    //      c. Set stream.[[closeRequest]] to undefined.
    stream->close_request_ = nullptr;
  }

  //  3. Let writer be stream.[[writer]].
  const auto writer = stream->writer_;

  //  4. If writer is not undefined,
  if (writer) {
    //      a. Reject writer.[[closedPromise]] with stream.[[storedError]].
    writer->ClosedResolver()->Reject(
        ScriptValue(isolate, stream->stored_error_.Get(isolate)));

    //      b. Set writer.[[closedPromise]].[[PromiseIsHandled]] to true.
    writer->closed(script_state).MarkAsHandled();
  }
}

// TODO(ricea): Functions for transferable streams.

// Utility functions (not from the standard).

void WritableStream::RejectPromises(ScriptState* script_state,
                                    PromiseQueue* queue,
                                    v8::Local<v8::Value> e) {
  for (auto promise : *queue) {
    promise->Reject(e);
  }
}

}  // namespace blink
```