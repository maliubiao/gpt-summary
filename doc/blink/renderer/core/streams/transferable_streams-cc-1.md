Response:
Let's break down the thought process for analyzing this code snippet.

**1. Understanding the Request:**

The request asks for a functional summary of the given C++ code from `transferable_streams.cc`, focusing on its relationship with JavaScript, HTML, and CSS, providing examples, and explaining potential user errors and debugging paths. Crucially, it specifies that this is part 2 of 2, meaning we should summarize the functionality present in *this specific snippet*.

**2. Initial Code Scan and Keyword Identification:**

I quickly scanned the code, looking for keywords and class names that hint at the functionality. The key elements that jumped out were:

* **`ConcatenatingUnderlyingSource`**:  The name itself is very descriptive. It suggests combining two data sources.
* **`ReadableStream`**:  This is a core Web API related to handling asynchronous data.
* **`WritableStream`**: Another core Web API for writing asynchronous data.
* **`MessagePort`**: This immediately suggests inter-process communication or communication between different browsing contexts (like iframes or workers).
* **`CrossRealmTransformReadable` and `CrossRealmTransformWritable`**:  "CrossRealm" reinforces the idea of communication across different security origins. "Transform" indicates some manipulation or forwarding of data.
* **`UnderlyingSourceBase` and `UnderlyingSinkBase`**: These are likely base classes for implementing the actual data handling logic for readable and writable streams, respectively.
* **`ScriptState`**:  This is a Blink-specific concept, but the name suggests interaction with the JavaScript engine.
* **`Promise`**:  A fundamental JavaScript construct for handling asynchronous operations.
* **`Enqueue`, `Close`, `Error`, `Pull`, `Cancel`**: These are standard methods associated with readable and writable streams.

**3. Focusing on the Main Classes and their Interactions:**

I then focused on understanding how the key classes interact:

* **`ConcatenatingUnderlyingSource`**:  This class seems to be the central piece of this snippet. It takes two `ReadableStream` sources and appears to chain them together. The `Pull` method logic confirms this, as it switches to the second source once the first is exhausted. The `Cancel` method also shows it needs to handle cancellation of both underlying streams.

* **`CrossRealmTransformReadable` and `CrossRealmTransformWritable`**: These classes clearly manage communication through `MessagePort`. The `HandleMessage` function in `CrossRealmTransformReadable` reveals how data, close, and error signals are received and propagated to the associated `ReadableStream`. The `CreateWritableStream` and `CreateReadableStream` functions set up the necessary event listeners on the `MessagePort`.

**4. Mapping to Web APIs:**

Knowing the class names and methods, I could start connecting them to their corresponding JavaScript Web APIs:

* `ReadableStream` and `WritableStream` directly correspond to the JavaScript `ReadableStream` and `WritableStream` objects.
* `MessagePort` corresponds to the JavaScript `MessagePort` API used for postMessage communication.

**5. Analyzing Functionality within Each Class:**

I then looked at the specific methods within each class to understand their purpose:

* **`ConcatenatingUnderlyingSource::Start`, `Pull`, `Cancel`**: These are the core methods required for a custom readable stream source, implementing the logic for starting the data flow, fetching data chunks, and handling cancellation.
* **`ConcatenatingUnderlyingSourceReadRequest::OnFulfilled`, `OnError`**: These are callbacks triggered by the underlying reader when data is available or an error occurs.
* **`CrossRealmTransformReadable::CreateReadableStream`**: Sets up the `MessagePort` listeners and creates the `ReadableStream`.
* **`CrossRealmTransformReadable::HandleMessage`, `HandleError`**: Processes messages received on the `MessagePort` and enqueues data, closes, or errors the associated `ReadableStream`.
* **`CreateCrossRealmTransformWritable`, `CreateCrossRealmTransformReadable`, `CreateConcatenatedReadableStream`**: These are factory functions that create instances of the relevant stream types.

**6. Identifying Relationships with JavaScript, HTML, and CSS:**

Based on the understanding of the core functionality and its mapping to Web APIs, I could deduce the relationships with JavaScript and HTML:

* **JavaScript:**  The entire code snippet is about implementing the underlying mechanisms for JavaScript Stream APIs. The examples of `pipeTo`, `tee`, and manual reading/writing clearly demonstrate this connection.
* **HTML:**  The `MessagePort` usage suggests scenarios involving `<iframe>` elements, web workers, or service workers, which are all part of the HTML environment.

CSS is not directly related to this code, as it deals with the presentation of web pages, not data streaming.

**7. Developing Examples and Hypothetical Scenarios:**

To illustrate the functionality, I created simple JavaScript examples demonstrating how a developer might use the `ReadableStream` and `WritableStream` objects created by this C++ code. For `ConcatenatingUnderlyingSource`, the concatenation of two file streams is a natural example. For the cross-realm streams, communication between an iframe and its parent is a classic use case.

**8. Considering User Errors and Debugging:**

I thought about common mistakes developers might make when using streams, such as using a closed stream or mismanaging backpressure. The code itself provides some clues for debugging, such as the `DCHECK` statements and the handling of `try_catch` blocks. The explanation of how a user action might lead to this code (e.g., using `pipeTo`) helps in tracing the execution flow.

**9. Structuring the Answer and Refining Language:**

Finally, I organized the information logically, starting with the core functionality, then moving to the relationships with web technologies, examples, error scenarios, and debugging. I aimed for clear and concise language, explaining technical terms where necessary. The "Assumptions and Outputs" sections are designed to demonstrate concrete input/output behavior, even if hypothetical.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** I initially focused heavily on the `ConcatenatingUnderlyingSource`. I then realized the `CrossRealmTransform*` classes were equally important and represented a distinct use case.
* **Example selection:** I considered more complex examples but opted for simpler ones that clearly illustrated the core concepts.
* **Debugging explanation:** I initially focused on low-level debugging but broadened it to include higher-level user actions that trigger the code.
* **Part 2 focus:**  I constantly reminded myself that the request was for *this specific part* of the code, avoiding bringing in concepts or code from a hypothetical "part 1." This was crucial for accurately summarizing the functionality present.

By following this structured approach, I was able to analyze the code effectively and provide a comprehensive and accurate answer to the request.
这是提供的 `blink/renderer/core/streams/transferable_streams.cc` 文件的第二部分代码。考虑到这是第二部分，我们需要结合第一部分的知识来归纳它的功能。

**基于第一部分和这部分代码，可以归纳出 `transferable_streams.cc` 文件的主要功能是：**

该文件实现了 Chromium Blink 引擎中与**可转移 Streams API** 相关的核心逻辑，特别是针对以下两种关键场景：

1. **连接（Concatenating）两个 ReadableStream：**  `ConcatenatingUnderlyingSource` 类及其相关逻辑允许将两个独立的 `ReadableStream` 串联成一个新的 `ReadableStream`。当第一个 stream 的数据读取完毕后，会自动开始读取第二个 stream 的数据。

2. **跨 Realm 传输 Streams (Cross-Realm Transferable Streams)：**  `CrossRealmTransformReadable` 和 `CrossRealmTransformWritable` 类及其相关逻辑支持在不同的 JavaScript Realms (例如，iframe, worker) 之间安全高效地传输 ReadableStream 和 WritableStream。这通过 `MessagePort` 进行通信，允许将 stream 的数据块、关闭和错误信号在不同的上下文中传递。

**具体到这部分代码的功能归纳：**

* **`ConcatenatingUnderlyingSource` 类：**
    * **核心功能：** 实现了将两个 `ReadableStream` (`stream1_` 和 `source2_` 表示) 连接起来的底层逻辑。
    * **`Start` 方法：**  获取第一个 `ReadableStream` 的默认读取器。
    * **`Pull` 方法：**  控制数据的读取。如果第一个 stream 还没有读取完，则从第一个 stream 读取；否则，调用第二个 stream 的 `Pull` 方法开始读取第二个 stream 的数据。
    * **`Cancel` 方法：**  处理取消操作。如果第一个 stream 还没有读取完，则取消第一个 stream 的读取，并尝试取消第二个 stream。
    * **`ConcatenatingUnderlyingSourceReadRequest` 内部类：**  用于处理从第一个 stream 读取数据的请求完成或出错时的回调。当第一个 stream 读取完成后，它会启动读取第二个 stream 的操作。
    * **目的：**  允许开发者创建一个看起来像是单个 stream，但实际上是由两个 sequential 的 stream 组成的数据流。

* **`CrossRealmTransformReadable` 类：**
    * **核心功能：**  实现跨 Realm 可读流的接收端。
    * **`CreateReadableStream` 方法：**  创建并配置用于接收跨 Realm 数据的 `ReadableStream`。它会设置 `MessagePort` 的消息和错误事件监听器。
    * **`HandleMessage` 方法：**  处理从 `MessagePort` 收到的消息。根据消息类型（"chunk"、"close"、"error"），将数据块添加到可读流的队列，或关闭或报错该可读流。
    * **`HandleError` 方法：**  处理 `MessagePort` 上的错误事件，并向可读流控制器报告错误。
    * **目的：**  接收来自另一个 Realm 的数据，并将这些数据作为本地的 `ReadableStream` 提供。

* **`CreateCrossRealmTransformWritable` 和 `CreateCrossRealmTransformReadable` 函数：**
    * **功能：**  提供创建跨 Realm 可写流和可读流的工厂函数。
    * **优化：**  在创建跨 Realm 流时，可以应用优化器 (`WritableStreamTransferringOptimizer` 和 `ReadableStreamTransferringOptimizer`)，例如，在同进程的情况下直接传递底层 sink 或 source，避免不必要的跨进程通信开销。
    * **目的：**  简化跨 Realm 流的创建过程，并允许进行性能优化。

* **`CreateConcatenatedReadableStream` 函数：**
    * **功能：**  提供创建连接的 `ReadableStream` 的便利函数，它使用了 `ConcatenatingUnderlyingSource`。
    * **目的：**  简化连接两个可读流的操作。

**总结来说，这部分代码主要关注于实现两种高级的 `ReadableStream` 操作：串联和跨 Realm 传输。**  它提供了底层的 C++ 逻辑来支持 JavaScript 中对这些功能的使用。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    * **连接 Streams:**  JavaScript 代码可以使用 `ReadableStream.pipeTo()` 或手动读取数据块的方式来消费由 `CreateConcatenatedReadableStream` 创建的连接的 stream。
        ```javascript
        const stream1 = new ReadableStream({ ... });
        const stream2 = new ReadableStream({ ... });

        // 假设在 C++ 端创建了连接的 stream
        const concatenatedStream = createConcatenatedReadableStreamFromCpp(stream1, stream2);

        concatenatedStream.pipeTo(someWritableStream);
        ```
    * **跨 Realm 传输 Streams:**  JavaScript 代码可以使用 `postMessage` API 将 `MessagePort` 对象传递到另一个 Realm，然后在两个 Realm 中分别调用 `createCrossRealmTransformReadable` 和 `createCrossRealmTransformWritable` 创建可读写流。
        ```javascript
        // Realm A
        const channel = new MessageChannel();
        const readableStream = createCrossRealmTransformReadableFromCpp(channel.port1);
        iframe.contentWindow.postMessage({ port: channel.port2 }, '*', [channel.port2]);

        // Realm B (iframe)
        window.addEventListener('message', event => {
          if (event.data.port) {
            const writableStream = createCrossRealmTransformWritableFromCpp(event.data.port);
            // ... 使用 writableStream 接收数据
          }
        });
        ```

* **HTML:**  `MessagePort` 的使用通常涉及到 `<iframe>` 元素、Web Workers 或 Service Workers，这些都是 HTML 的一部分，用于创建不同的浏览上下文。

* **CSS:**  这个文件中的代码与 CSS 没有直接关系，因为它处理的是数据流的逻辑，而不是页面的样式和布局。

**逻辑推理的假设输入与输出：**

**假设输入 (针对 `ConcatenatingUnderlyingSource`):**

* `stream1`: 一个包含数据 "Hello" 的 `ReadableStream`.
* `source2`: 一个包含数据 " World!" 的 `UnderlyingSourceBase` 实现。

**输出:**

当从由 `ConcatenatingUnderlyingSource` 创建的连接 stream 中读取数据时，会先得到 "Hello"，然后得到 " World!"。  当第一个 stream 完成时，`has_finished_reading_stream1_` 会变为 `true`，后续的 `Pull` 操作会转向 `source2_`。

**假设输入 (针对 `CrossRealmTransformReadable`):**

* `MessagePort` 接收到来自另一个 Realm 的消息：
    * 类型 "chunk"，值 "Data chunk 1"
    * 类型 "chunk"，值 "Data chunk 2"
    * 类型 "close"

**输出:**

由 `CrossRealmTransformReadable` 创建的 `ReadableStream` 会先产出 "Data chunk 1"，然后产出 "Data chunk 2"，最后 stream 会被关闭。

**用户或编程常见的使用错误举例说明：**

* **在 `ConcatenatingUnderlyingSource` 中，如果 `stream1` 在被连接之前就已经报错，**  那么 `ConcatenatingUnderlyingSource` 的 `Pull` 方法在尝试读取 `stream1` 时会遇到错误，可能导致整个连接的 stream 提前报错。
* **在 `CrossRealmTransformReadable` 中，如果发送端发送了格式错误的消息（例如，未知的消息类型），**  `HandleMessage` 方法会忽略该消息，可能导致接收端无法正常接收数据或关闭信号。开发者需要确保跨 Realm 通信的消息格式正确。
* **在跨 Realm 传输 stream 时，如果 `MessagePort` 在 stream 完全传输之前被意外关闭或解耦，**  可能会导致数据传输中断或出现错误。开发者需要妥善管理 `MessagePort` 的生命周期。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在网页中发起了一个操作，例如，下载一个由多个部分组成的大文件。**
2. **JavaScript 代码使用 `fetch()` API 获取文件的各个部分，并将每个部分的数据源创建为 `ReadableStream`。**
3. **为了方便处理，开发者可能希望将这些独立的 `ReadableStream` 连接成一个单一的逻辑 stream。**
4. **JavaScript 代码可能会调用一个自定义的函数或使用 Streams API 的方法（如果浏览器原生支持连接），最终在 Blink 引擎的 C++ 层会创建 `ConcatenatingUnderlyingSource` 对象来管理这个连接过程。**
5. **或者，用户可能正在与一个嵌入的 `<iframe>` 元素或 Web Worker 进行交互。**
6. **JavaScript 代码可能需要将一个本地的 `ReadableStream` 或 `WritableStream` 传递到 `<iframe>` 或 Worker 中进行处理。**
7. **JavaScript 代码会创建一个 `MessageChannel`，并通过 `postMessage` 将 `MessagePort` 传递到目标 Realm。**
8. **在 Blink 引擎的 C++ 层，`CreateCrossRealmTransformReadable` 或 `CreateCrossRealmTransformWritable` 函数会被调用，根据 `MessagePort` 创建相应的跨 Realm stream 对象。**
9. **当数据在 streams 中流动或发生错误时，会触发 `ConcatenatingUnderlyingSource` 或 `CrossRealmTransformReadable/Writable` 类中的方法，例如 `Pull`、`Enqueue`、`Close`、`Error` 等。**

因此，当你在调试涉及到连接多个数据源或者跨不同浏览上下文传输 stream 的问题时，你可以检查是否创建了 `ConcatenatingUnderlyingSource` 或 `CrossRealmTransformReadable/Writable` 对象，并跟踪这些对象的方法调用和状态变化，以理解数据流的走向和可能出现的问题。例如，你可以断点在 `Pull` 方法中查看数据是否正确地从第一个 stream 过渡到第二个 stream，或者在 `HandleMessage` 方法中查看是否收到了预期的跨 Realm 消息。

### 提示词
```
这是目录为blink/renderer/core/streams/transferable_streams.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
riptState* script_state) const override {
      // We've finished reading `source1_`. Let's start reading `source2_`.
      source_->has_finished_reading_stream1_ = true;
      ReadableStreamDefaultController* controller =
          source_->Controller()->GetOriginalController();
      auto* isolate = script_state->GetIsolate();
      if (controller) {
        resolver_->Resolve(
            source_->source2_->StartWrapper(script_state, controller)
                .Then(script_state,
                      MakeGarbageCollected<PullSource2>(source_)));
      } else {
        // TODO(crbug.com/1418910): Investigate how to handle cases when the
        // controller is cleared.
        resolver_->Reject(v8::Exception::TypeError(
            V8String(isolate,
                     "The readable stream controller has been cleared "
                     "and cannot be used to start reading the second "
                     "stream.")));
      }
    }

    void ErrorSteps(ScriptState* script_state,
                    v8::Local<v8::Value> e) const override {
      ReadableStream* dummy_stream =
          ReadableStream::CreateWithCountQueueingStrategy(
              script_state, source_->source2_,
              /*high_water_mark=*/0);

      v8::Isolate* isolate = script_state->GetIsolate();
      // We don't care about the result of the cancellation, including
      // exceptions.
      dummy_stream->cancel(script_state,
                           ScriptValue(isolate, v8::Undefined(isolate)),
                           IGNORE_EXCEPTION);
      resolver_->Reject(e);
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(source_);
      visitor->Trace(resolver_);
      ReadRequest::Trace(visitor);
    }

   private:
    Member<ConcatenatingUnderlyingSource> source_;
    Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  };

  ConcatenatingUnderlyingSource(ScriptState* script_state,
                                ReadableStream* stream1,
                                UnderlyingSourceBase* source2)
      : UnderlyingSourceBase(script_state),
        stream1_(stream1),
        source2_(source2) {}

  ScriptPromise<IDLUndefined> Start(ScriptState* script_state) override {
    v8::TryCatch try_catch(script_state->GetIsolate());
    reader_for_stream1_ = ReadableStream::AcquireDefaultReader(
        script_state, stream1_,
        PassThroughException(script_state->GetIsolate()));
    if (try_catch.HasCaught()) {
      return ScriptPromise<IDLUndefined>::Reject(script_state,
                                                 try_catch.Exception());
    }
    DCHECK(reader_for_stream1_);
    return ToResolvedUndefinedPromise(script_state);
  }

  ScriptPromise<IDLUndefined> Pull(ScriptState* script_state,
                                   ExceptionState& exception_state) override {
    if (has_finished_reading_stream1_) {
      return source2_->Pull(script_state, exception_state);
    }
    auto* promise =
        MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
    auto* read_request =
        MakeGarbageCollected<ConcatenatingUnderlyingSourceReadRequest>(this,
                                                                       promise);
    ReadableStreamDefaultReader::Read(script_state, reader_for_stream1_,
                                      read_request, exception_state);
    return promise->Promise();
  }

  ScriptPromise<IDLUndefined> Cancel(ScriptState* script_state,
                                     ScriptValue reason,
                                     ExceptionState& exception_state) override {
    if (has_finished_reading_stream1_) {
      return source2_->Cancel(script_state, reason, exception_state);
    }
    v8::TryCatch try_catch(script_state->GetIsolate());
    ScriptPromise<IDLUndefined> cancel_promise1 = reader_for_stream1_->cancel(
        script_state, reason, PassThroughException(script_state->GetIsolate()));
    if (try_catch.HasCaught()) {
      cancel_promise1 = ScriptPromise<IDLUndefined>::Reject(
          script_state, try_catch.Exception());
    }

    ReadableStream* dummy_stream =
        ReadableStream::CreateWithCountQueueingStrategy(script_state, source2_,
                                                        /*high_water_mark=*/0);
    ScriptPromise<IDLUndefined> cancel_promise2 = dummy_stream->cancel(
        script_state, reason, PassThroughException(script_state->GetIsolate()));
    if (try_catch.HasCaught()) {
      cancel_promise2 = ScriptPromise<IDLUndefined>::Reject(
          script_state, try_catch.Exception());
    }

    return PromiseAll<IDLUndefined>::Create(script_state,
                                            {cancel_promise1, cancel_promise2});
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(stream1_);
    visitor->Trace(reader_for_stream1_);
    visitor->Trace(source2_);
    UnderlyingSourceBase::Trace(visitor);
  }

 private:
  Member<ReadableStream> stream1_;
  Member<ReadableStreamDefaultReader> reader_for_stream1_;
  bool has_finished_reading_stream1_ = false;
  Member<UnderlyingSourceBase> source2_;
};

ReadableStream* CrossRealmTransformReadable::CreateReadableStream(
    ExceptionState& exception_state) {
  DCHECK(!controller_) << "CreateReadableStream can only be called once";

  // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformreadable
  // The order of operations is significantly different from the standard, but
  // functionally equivalent.

  //  3. Add a handler for port’s message event with the following steps:
  //  5. Enable port’s port message queue.
  message_port_->setOnmessage(
      MakeGarbageCollected<CrossRealmTransformMessageListener>(this));

  //  4. Add a handler for port’s messageerror event with the following steps:
  message_port_->setOnmessageerror(
      MakeGarbageCollected<CrossRealmTransformErrorListener>(this));

  //  6. Let startAlgorithm be an algorithm that returns undefined.
  //  7. Let pullAlgorithm be the following steps:
  //  8. Let cancelAlgorithm be the following steps, taking a reason argument:
  //  9. Let sizeAlgorithm be an algorithm that returns 1.
  // 10. Perform ! SetUpReadableStreamDefaultController(stream, controller,
  //     startAlgorithm, pullAlgorithm, cancelAlgorithm, 0, sizeAlgorithm).
  auto* stream = ReadableStream::Create(
      script_state_, CreateTrivialStartAlgorithm(),
      MakeGarbageCollected<PullAlgorithm>(this),
      MakeGarbageCollected<CancelAlgorithm>(this),
      /* highWaterMark = */ 0, CreateDefaultSizeAlgorithm(), exception_state);

  if (exception_state.HadException()) {
    return nullptr;
  }

  // The stream is created right above, and the type of the source is not given,
  // hence it is guaranteed that the controller is a
  // ReadableStreamDefaultController.
  controller_ = To<ReadableStreamDefaultController>(stream->GetController());
  return stream;
}

void CrossRealmTransformReadable::HandleMessage(MessageType type,
                                                v8::Local<v8::Value> value) {
  // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformreadable
  // 3. Add a handler for port’s message event with the following steps:
  // The first 5 steps are handled by CrossRealmTransformMessageListener.
  switch (type) {
    // 6. If type is "chunk",
    case MessageType::kChunk:
      // 1. Perform ! ReadableStreamDefaultControllerEnqueue(controller,
      //    value).
      // TODO(ricea): Update ReadableStreamDefaultController::Enqueue() to match
      // the standard so this extra check is not needed.
      if (ReadableStreamDefaultController::CanCloseOrEnqueue(controller_)) {
        // This can't throw because we always use the default strategy size
        // algorithm, which doesn't throw, and always returns a valid value of
        // 1.0.
        ReadableStreamDefaultController::Enqueue(script_state_, controller_,
                                                 value, ASSERT_NO_EXCEPTION);
      }
      return;

    // 7. Otherwise, if type is "close",
    case MessageType::kClose:
      // 1. Perform ! ReadableStreamDefaultControllerClose(controller).
      // TODO(ricea): Update ReadableStreamDefaultController::Close() to match
      // the standard so this extra check is not needed.
      if (ReadableStreamDefaultController::CanCloseOrEnqueue(controller_)) {
        ReadableStreamDefaultController::Close(script_state_, controller_);
      }

      // Disentangle port.
      message_port_->close();
      return;

    // 8. Otherwise, if type is "error",
    case MessageType::kError:
      // 1. Perform ! ReadableStreamDefaultControllerError(controller, value).
      ReadableStreamDefaultController::Error(script_state_, controller_, value);

      // 2. Disentangle port.
      message_port_->close();
      return;

    default:
      DLOG(WARNING) << "Invalid message from peer ignored (invalid type): "
                    << static_cast<int>(type);
      return;
  }
}

void CrossRealmTransformReadable::HandleError(v8::Local<v8::Value> error) {
  // https://streams.spec.whatwg.org/#abstract-opdef-setupcrossrealmtransformreadable
  // 4. Add a handler for port’s messageerror event with the following steps:
  // The first two steps, and the last step, are performed by
  // CrossRealmTransformErrorListener.

  //   3. Perform ! ReadableStreamDefaultControllerError(controller, error).
  ReadableStreamDefaultController::Error(script_state_, controller_, error);
}

}  // namespace

CORE_EXPORT WritableStream* CreateCrossRealmTransformWritable(
    ScriptState* script_state,
    MessagePort* port,
    AllowPerChunkTransferring allow_per_chunk_transferring,
    std::unique_ptr<WritableStreamTransferringOptimizer> optimizer,
    ExceptionState& exception_state) {
  WritableStream* stream = MakeGarbageCollected<CrossRealmTransformWritable>(
                               script_state, port, allow_per_chunk_transferring)
                               ->CreateWritableStream(exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  if (!optimizer) {
    return stream;
  }
  UnderlyingSinkBase* sink =
      optimizer->PerformInProcessOptimization(script_state);
  if (!sink) {
    return stream;
  }
  stream->close(script_state, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  return WritableStream::CreateWithCountQueueingStrategy(script_state, sink,
                                                         /*high_water_mark=*/1);
}

CORE_EXPORT ReadableStream* CreateCrossRealmTransformReadable(
    ScriptState* script_state,
    MessagePort* port,
    std::unique_ptr<ReadableStreamTransferringOptimizer> optimizer,
    ExceptionState& exception_state) {
  ReadableStream* stream =
      MakeGarbageCollected<CrossRealmTransformReadable>(script_state, port)
          ->CreateReadableStream(exception_state);
  if (!optimizer) {
    return stream;
  }
  UnderlyingSourceBase* source2 =
      optimizer->PerformInProcessOptimization(script_state);
  if (!source2) {
    return stream;
  }

  return ReadableStream::CreateWithCountQueueingStrategy(
      script_state,
      MakeGarbageCollected<ConcatenatingUnderlyingSource>(script_state, stream,
                                                          source2),
      /*high_water_mark=*/0);
}

ReadableStream* CreateConcatenatedReadableStream(
    ScriptState* script_state,
    UnderlyingSourceBase* source1,
    UnderlyingSourceBase* source2) {
  auto* const stream1 =
      ReadableStream::CreateWithCountQueueingStrategy(script_state, source1,
                                                      /*high_water_mark=*/0);
  return ReadableStream::CreateWithCountQueueingStrategy(
      script_state,
      MakeGarbageCollected<ConcatenatingUnderlyingSource>(script_state, stream1,
                                                          source2),
      /*high_water_mark=*/0);
}

}  // namespace blink
```