Response:
The user wants a summary of the functionality of the `transform_stream.cc` file in the Chromium Blink engine. They are particularly interested in:

1. **Core Functionality:** What does this file do?
2. **Relationship to Web Standards:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and Data Flow:**  If there's any internal logic, they want examples of inputs and outputs.
4. **Common Usage Errors:** What mistakes do developers often make when using this functionality?
5. **Debugging Information:** How can a user's actions lead to this code being executed?
6. **Concise Summary (for Part 1):**  A brief overview of the file's purpose.

Let's break down the code to address these points.

**1. Core Functionality:**

*   The file implements the `TransformStream` API defined in the Streams Standard.
*   It manages the transformation of data as it flows between a writable stream and a readable stream.
*   It uses a `TransformStreamTransformer` (defined elsewhere) to perform the actual transformation.
*   It handles the lifecycle of the stream, including starting, transforming data chunks, flushing any remaining data, and handling errors.

**2. Relationship to Web Standards:**

*   **JavaScript:** This code directly implements the JavaScript `TransformStream` API. Developers interact with `TransformStream` objects in JavaScript.
*   **HTML:**  While not directly manipulating HTML elements, `TransformStream` is often used in conjunction with APIs that handle data from network requests (`fetch`), WebSockets, or the File API, which are all integrated into the browser environment and can be triggered by user interactions within HTML pages.
*   **CSS:**  Less direct relation to CSS. However, if data processing within a `TransformStream` affects the structure or content of a page, it *indirectly* influences what CSS styles.

**3. Logic and Data Flow:**

*   The code defines internal algorithms (`TransformAlgorithm`, `FlushAlgorithm`) that encapsulate the core logic of data transformation. These algorithms delegate to the user-provided transformer.
*   It manages the backpressure mechanism, which ensures that the data flow is controlled and doesn't overwhelm either the readable or writable side.
*   Promises are used extensively to handle asynchronous operations, such as waiting for the transformer to process a chunk or for flushing to complete.

**4. Common Usage Errors:**

*   **Incorrect Transformer Implementation:**  The most common errors likely occur in the user-provided JavaScript transformer (not directly in this C++ file, but this file handles its execution). For example, the `transform` method might not correctly process the input chunk, or the `flush` method might not clean up resources.
*   **Ignoring Backpressure:**  While the browser handles backpressure internally, understanding it is crucial. If the readable side is slow, the writable side should be throttled. Misunderstanding this can lead to performance issues or unexpected behavior.
*   **Error Handling:**  Not properly handling errors in the transformer's `transform` or `flush` methods can lead to stream failures.

**5. Debugging Information:**

*   User actions (e.g., initiating a fetch request, sending data through a WebSocket) can lead to the creation and use of `TransformStream` if the associated JavaScript code utilizes it.
*   Breakpoints within this C++ code can be hit when the JavaScript `TransformStream` API is used.
*   Looking at the call stack can trace back the execution flow to the JavaScript that initiated the stream.

**6. Concise Summary (for Part 1):**

This file implements the core logic of the `TransformStream` API in Chromium's Blink rendering engine. It manages the flow of data through a transformation process defined by a user-provided JavaScript transformer, handling asynchronous operations and backpressure to ensure efficient and correct data processing between readable and writable streams.

Now, let's generate the detailed response.
这是 `blink/renderer/core/streams/transform_stream.cc` 文件的第一部分，它主要负责实现 Web Streams API 中的 `TransformStream` 接口的核心功能。以下是其功能的详细归纳：

**核心功能:**

1. **`TransformStream` 类的实现:**  该文件定义了 `TransformStream` 类，这是 Web Streams API 的一个关键组成部分，允许开发者以声明式的方式处理数据流的转换。
2. **数据转换流程管理:** `TransformStream` 充当一个管道，数据从一个可写流 (`WritableStream`) 流入，经过转换处理，然后从一个可读流 (`ReadableStream`) 流出。这个文件中的代码负责协调这个过程。
3. **与 JavaScript 的交互:**  `TransformStream` 是一个可以在 JavaScript 中使用的 API。此 C++ 文件实现了与 JavaScript 层的绑定，使得 JavaScript 代码能够创建、配置和操作 `TransformStream` 对象。
4. **生命周期管理:**  文件中的代码处理 `TransformStream` 的初始化、启动、数据转换、刷新（flush）以及关闭/错误处理等生命周期阶段。
5. **内部算法的实现:**  定义了内部的 `TransformAlgorithm` 和 `FlushAlgorithm` 类，这些类封装了实际的数据转换和刷新操作，并委托给用户提供的 `TransformStreamTransformer` 对象。
6. **背压 (Backpressure) 处理:**  实现了背压机制，当读取端消费数据的速度慢于写入端产生数据的速度时，能够暂停写入，防止内存溢出。
7. **错误处理:**  定义了如何处理 `TransformStream` 过程中出现的错误，并将错误传递到相关的可读流和可写流。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **JavaScript:** `TransformStream` 是一个 JavaScript API。开发者在 JavaScript 中创建和使用 `TransformStream` 对象来处理数据流。

    **举例:**
    ```javascript
    const transformStream = new TransformStream({
      transform(chunk, controller) {
        // 将数据块转换为大写
        controller.enqueue(chunk.toUpperCase());
      }
    });

    fetch('data.txt')
      .then(response => response.body.pipeThrough(transformStream).getReader())
      .then(reader => {
        const read = () => {
          reader.read().then(({ done, value }) => {
            if (done) {
              console.log('转换完成');
              return;
            }
            console.log('转换后的数据:', value);
            read();
          });
        };
        read();
      });
    ```
    在这个例子中，`TransformStream` 的 `transform` 方法被 JavaScript 定义，用于将从 `data.txt` 读取的数据转换为大写。

*   **HTML:** `TransformStream` 通常与处理网页上的数据相关联，例如通过 `fetch` API 获取的数据，或者通过 `<video>` 或 `<audio>` 元素流式传输的媒体数据。

    **举例:**  一个处理从服务器流式传输的 JSON 数据的场景。HTML 页面可以通过 JavaScript 使用 `fetch` API 获取数据，并使用 `TransformStream` 对 JSON 数据进行解析或预处理，然后再显示在页面上。

*   **CSS:**  `TransformStream` 本身与 CSS 没有直接的功能关系。但是，经过 `TransformStream` 处理的数据可能会影响 HTML 结构或内容，从而间接地影响 CSS 的应用效果。

**逻辑推理与假设输入输出:**

假设我们有一个简单的 `TransformStream`，其转换函数将输入的字符串转换为大写。

*   **假设输入 (JavaScript 中写入 `WritableStream` 的数据):**  `"hello"`
*   **`TransformAlgorithm` 的处理:**  `TransformAlgorithm` 会调用用户提供的 JavaScript `transform` 函数，该函数会将 `"hello"` 转换为 `"HELLO"`.
*   **假设输出 (从 `ReadableStream` 读取的数据):** `"HELLO"`

**常见的使用错误及举例说明:**

*   **错误地实现 `transform` 或 `flush` 方法:** 用户提供的 JavaScript `transform` 函数可能会抛出异常，或者没有正确地将处理后的数据 `enqueue` 到控制器的可读队列中。

    **举例:**
    ```javascript
    const transformStream = new TransformStream({
      transform(chunk, controller) {
        if (typeof chunk !== 'string') {
          throw new Error('输入必须是字符串'); // 错误：没有检查数据类型
        }
        controller.enqueue(chunk.toUpperCase());
      }
    });
    ```
    如果写入 `transformStream.writable` 的数据不是字符串，上面的代码会抛出错误，导致流进入错误状态。正确的做法是在 `transform` 方法中进行必要的类型检查和错误处理。

*   **没有正确处理背压:** 虽然浏览器会自动处理背压，但如果用户自定义了更复杂的转换逻辑，可能会因为同步执行了大量耗时操作而阻塞事件循环，间接导致背压问题。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在网页上执行操作:** 例如，点击一个按钮触发了一个使用 `fetch` API 发起网络请求的 JavaScript 函数。
2. **JavaScript 代码创建并使用了 `TransformStream`:**  在 `fetch` 请求的响应处理中，JavaScript 代码可能创建了一个 `TransformStream` 来处理响应的 `body`。
3. **数据通过管道传输:**  响应的 `ReadableStream` 被 `pipeThrough()` 方法连接到 `TransformStream` 的 `writable` 端。
4. **Blink 引擎执行 C++ 代码:** 当数据开始流入 `TransformStream` 时，Blink 引擎会执行 `transform_stream.cc` 中实现的 C++ 代码来管理数据的转换流程。
5. **触发 `TransformAlgorithm`:**  当有数据块写入 `TransformStream` 的可写端时，会触发内部的 `TransformAlgorithm`，该算法会调用用户定义的 JavaScript `transform` 函数。

**本部分功能归纳:**

这部分 `transform_stream.cc` 代码主要负责 `TransformStream` 的**创建、初始化和核心数据转换流程的管理**。它定义了 `TransformStream` 类，实现了与 JavaScript 的接口，并封装了数据转换和刷新的内部逻辑，包括如何调用用户提供的 JavaScript transformer 函数。此外，它还涉及了背压的初步管理和错误处理机制的建立。这部分代码是 `TransformStream` 功能的基础，为后续的数据处理和流的生命周期管理奠定了基础。

### 提示词
```
这是目录为blink/renderer/core/streams/transform_stream.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/transform_stream.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/core/streams/transform_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/transform_stream_transformer.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"

namespace blink {

// Implements a flush algorithm that delegates to a TransformStreamTransformer.
// This is used when creating a TransformStream from C++.
class TransformStream::FlushAlgorithm final : public StreamAlgorithm {
 public:
  explicit FlushAlgorithm(TransformStreamTransformer* transformer)
      : transformer_(transformer) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 0);
    DCHECK(controller_);
    v8::Isolate* isolate = script_state->GetIsolate();
    auto* transformer_script_state = transformer_->GetScriptState();
    if (!transformer_script_state->ContextIsValid()) {
      return ScriptPromise<IDLUndefined>::Reject(
          script_state,
          V8ThrowException::CreateTypeError(isolate, "invalid realm"));
    }
    v8::TryCatch try_catch(isolate);
    ScriptPromise<IDLUndefined> promise;
    {
      // This is needed because the realm of the transformer can be different
      // from the realm of the transform stream.
      ScriptState::Scope scope(transformer_script_state);
      promise = transformer_->Flush(controller_, PassThroughException(isolate));
    }
    if (try_catch.HasCaught()) {
      return ScriptPromise<IDLUndefined>::Reject(script_state,
                                                 try_catch.Exception());
    }

    return promise;
  }

  // SetController() must be called before Run() is.
  void SetController(TransformStreamDefaultController* controller) {
    controller_ = controller;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(transformer_);
    visitor->Trace(controller_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<TransformStreamTransformer> transformer_;
  Member<TransformStreamDefaultController> controller_;
};

// Implements a transform algorithm that delegates to a
// TransformStreamTransformer.
class TransformStream::TransformAlgorithm final : public StreamAlgorithm {
 public:
  explicit TransformAlgorithm(TransformStreamTransformer* transformer)
      : transformer_(transformer) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 1);
    DCHECK(controller_);
    v8::Isolate* isolate = script_state->GetIsolate();
    auto* transformer_script_state = transformer_->GetScriptState();
    if (!transformer_script_state->ContextIsValid()) {
      return ScriptPromise<IDLUndefined>::Reject(
          script_state,
          V8ThrowException::CreateTypeError(isolate, "invalid realm"));
    }
    v8::TryCatch try_catch(isolate);
    auto promise = transformer_->Transform(argv[0], controller_,
                                           PassThroughException(isolate));
    if (try_catch.HasCaught()) {
      return ScriptPromise<IDLUndefined>::Reject(script_state,
                                                 try_catch.Exception());
    }

    return promise;
  }

  // SetController() must be called before Run() is.
  void SetController(TransformStreamDefaultController* controller) {
    controller_ = controller;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(transformer_);
    visitor->Trace(controller_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<TransformStreamTransformer> transformer_;
  Member<TransformStreamDefaultController> controller_;
};

TransformStream* TransformStream::Create(ScriptState* script_state,
                                         ExceptionState& exception_state) {
  ScriptValue undefined(script_state->GetIsolate(),
                        v8::Undefined(script_state->GetIsolate()));
  return Create(script_state, undefined, undefined, undefined, exception_state);
}

TransformStream* TransformStream::Create(
    ScriptState* script_state,
    ScriptValue transform_stream_transformer,
    ExceptionState& exception_state) {
  ScriptValue undefined(script_state->GetIsolate(),
                        v8::Undefined(script_state->GetIsolate()));
  return Create(script_state, transform_stream_transformer, undefined,
                undefined, exception_state);
}

TransformStream* TransformStream::Create(
    ScriptState* script_state,
    ScriptValue transform_stream_transformer,
    ScriptValue writable_strategy,
    ExceptionState& exception_state) {
  ScriptValue undefined(script_state->GetIsolate(),
                        v8::Undefined(script_state->GetIsolate()));
  return Create(script_state, transform_stream_transformer, writable_strategy,
                undefined, exception_state);
}

TransformStream* TransformStream::Create(ScriptState* script_state,
                                         ScriptValue transformer,
                                         ScriptValue writable_strategy,
                                         ScriptValue readable_strategy,
                                         ExceptionState& exception_state) {
  auto* ts = MakeGarbageCollected<TransformStream>();

  ts->InitInternal(script_state, transformer, writable_strategy,
                   readable_strategy, exception_state);

  if (exception_state.HadException()) {
    return nullptr;
  }

  return ts;
}

// static
TransformStream* TransformStream::Create(
    ScriptState* script_state,
    TransformStreamTransformer* transformer,
    ExceptionState& exception_state) {
  auto* transform_algorithm =
      MakeGarbageCollected<TransformAlgorithm>(transformer);
  auto* flush_algorithm = MakeGarbageCollected<FlushAlgorithm>(transformer);
  auto* size_algorithm = CreateDefaultSizeAlgorithm();
  auto* stream = Create(script_state, CreateTrivialStartAlgorithm(),
                        transform_algorithm, flush_algorithm, 1, size_algorithm,
                        0, size_algorithm, exception_state);
  DCHECK(stream);
  DCHECK(!exception_state.HadException());
  TransformStreamDefaultController* controller =
      stream->transform_stream_controller_;
  transform_algorithm->SetController(controller);
  flush_algorithm->SetController(controller);
  return stream;
}

TransformStream* TransformStream::Create(
    ScriptState* script_state,
    StreamStartAlgorithm* start_algorithm,
    StreamAlgorithm* transform_algorithm,
    StreamAlgorithm* flush_algorithm,
    double writable_high_water_mark,
    StrategySizeAlgorithm* writable_size_algorithm,
    double readable_high_water_mark,
    StrategySizeAlgorithm* readable_size_algorithm,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#create-transform-stream
  //
  // In this implementation, all the arguments are compulsory, so the following
  // steps aren't performed:
  // 1. If writableHighWaterMark was not passed, set it to 1.
  // 2. If writableSizeAlgorithm was not passed, set it to an algorithm that
  //    returns 1.
  // 3. If readableHighWaterMark was not passed, set it to 0.
  // 4. If readableSizeAlgorithm was not passed, set it to an algorithm that
  //    returns 1.

  // 5. Assert: ! IsNonNegativeNumber(writableHighWaterMark) is true.
  DCHECK_GE(writable_high_water_mark, 0);

  // 6. Assert: ! IsNonNegativeNumber(readableHighWaterMark) is true.
  DCHECK_GE(readable_high_water_mark, 0);

  // 7. Let stream be ObjectCreate(the original value of TransformStream's
  //    prototype property).
  auto* stream = MakeGarbageCollected<TransformStream>();

  // 8. Let startPromise be a new promise.
  auto* start_promise =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  // 9. Perform ! InitializeTransformStream(stream, startPromise,
  //    writableHighWaterMark, writableSizeAlgorithm, readableHighWaterMark,
  //    readableSizeAlgorithm).
  Initialize(script_state, stream, start_promise, writable_high_water_mark,
             writable_size_algorithm, readable_high_water_mark,
             readable_size_algorithm, exception_state);

  // 10. Let controller be ObjectCreate(the original value of
  //     TransformStreamDefaultController's prototype property).
  auto* controller = MakeGarbageCollected<TransformStreamDefaultController>();

  // 11. Perform ! SetUpTransformStreamDefaultController(stream, controller,
  //     transformAlgorithm, flushAlgorithm).
  TransformStreamDefaultController::SetUp(script_state, stream, controller,
                                          transform_algorithm, flush_algorithm);

  // 12. Let startResult be the result of performing startAlgorithm. (This may
  //     throw an exception.)
  TryRethrowScope rethrow_scope(script_state->GetIsolate(), exception_state);
  auto start_result = start_algorithm->Run(script_state);
  if (start_result.IsEmpty()) {
    CHECK(rethrow_scope.HasCaught());
    return nullptr;
  }

  // 13. Resolve startPromise with startResult.
  start_promise->Resolve(start_result);

  // 14. Return stream.
  return stream;
}

// This constructor is only used internally.
TransformStream::TransformStream() = default;

TransformStream::TransformStream(ReadableStream* readable,
                                 WritableStream* writable)
    : readable_(readable), writable_(writable) {}

ReadableStreamDefaultController* TransformStream::GetReadableController() {
  // The type of source is not given when constructing the readable stream in
  // TranformStream, so it is guaranteed that the controller is a
  // ReadableStreamDefaultController.
  return To<ReadableStreamDefaultController>(readable_->GetController());
}

void TransformStream::Trace(Visitor* visitor) const {
  visitor->Trace(backpressure_change_promise_);
  visitor->Trace(readable_);
  visitor->Trace(transform_stream_controller_);
  visitor->Trace(writable_);
  ScriptWrappable::Trace(visitor);
}

// Implements the "an algorithm that returns startPromise" step from
// InitializeTransformStream():
// https://streams.spec.whatwg.org/#initialize-transform-stream.
class TransformStream::ReturnStartPromiseAlgorithm final
    : public StreamStartAlgorithm {
 public:
  explicit ReturnStartPromiseAlgorithm(
      ScriptPromiseResolver<IDLUndefined>* start_promise)
      : start_promise_(start_promise) {}

  ScriptPromise<IDLUndefined> Run(ScriptState*) override {
    return start_promise_->Promise();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(start_promise_);
    StreamStartAlgorithm::Trace(visitor);
  }

 private:
  Member<ScriptPromiseResolver<IDLUndefined>> start_promise_;
};

//
// The following algorithms are described as abstract operations in the
// standard, but need to be implemented as classes in C++ so that the data they
// store can be traced by the garbage collector correctly.
//
class TransformStream::DefaultSinkWriteAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit DefaultSinkWriteAlgorithm(TransformStream* stream)
      : stream_(stream) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 1);
    const auto chunk = argv[0];

    // https://streams.spec.whatwg.org/#transform-stream-default-sink-write-algorithm
    // 1. Assert: stream.[[writable]].[[state]] is "writable".
    DCHECK(stream_->writable_->IsWritable());

    // 2. Let controller be stream.[[transformStreamController]].
    TransformStreamDefaultController* controller =
        stream_->transform_stream_controller_;

    // 3. If stream.[[backpressure]] is true,
    if (stream_->had_backpressure_) {
      // a. Let backpressureChangePromise be
      //    stream.[[backpressureChangePromise]].
      auto* backpressure_change_promise =
          stream_->backpressure_change_promise_.Get();

      // b. Assert: backpressureChangePromise is not undefined.
      DCHECK(backpressure_change_promise);

      class ResponseFunction final
          : public ThenCallable<IDLUndefined, ResponseFunction,
                                IDLPromise<IDLUndefined>> {
       public:
        ResponseFunction(ScriptState* script_state,
                         TransformStream* stream,
                         v8::Local<v8::Value> chunk)
            : stream_(stream), chunk_(script_state->GetIsolate(), chunk) {}

        ScriptPromise<IDLUndefined> React(ScriptState* script_state) {
          auto* isolate = script_state->GetIsolate();

          // c. Return the result of transforming backpressureChangePromise with
          //    a fulfillment handler which performs the following steps:
          //    i. Let writable be stream.[[writable]].
          WritableStream* writable = stream_->writable_;

          //   ii. Let state be writable.[[state]].
          //  iii. If state is "erroring", throw writable.[[storedError]].
          if (writable->IsErroring()) {
            return ScriptPromise<IDLUndefined>::Reject(
                script_state, writable->GetStoredError(isolate));
          }

          // 4. Assert: state is "writable".
          CHECK(writable->IsWritable());

          // 5. Return ! TransformStreamDefaultControllerPerformTransform(
          //    controller, chunk).
          return TransformStreamDefaultController::PerformTransform(
              script_state, stream_->transform_stream_controller_,
              chunk_.Get(isolate));
        }

        void Trace(Visitor* visitor) const override {
          visitor->Trace(stream_);
          visitor->Trace(chunk_);
          ThenCallable<IDLUndefined, ResponseFunction,
                       IDLPromise<IDLUndefined>>::Trace(visitor);
        }

       private:
        Member<TransformStream> stream_;
        TraceWrapperV8Reference<v8::Value> chunk_;
      };

      // c. Return the result of transforming backpressureChangePromise ...
      return backpressure_change_promise->Promise().Then(
          script_state,
          MakeGarbageCollected<ResponseFunction>(script_state, stream_, chunk));
    }

    //  4. Return ! TransformStreamDefaultControllerPerformTransform(controller,
    //     chunk).
    return TransformStreamDefaultController::PerformTransform(
        script_state, controller, chunk);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(stream_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<TransformStream> stream_;
};

class TransformStream::DefaultSinkAbortAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit DefaultSinkAbortAlgorithm(TransformStream* stream)
      : stream_(stream) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 1);
    const auto reason = argv[0];

    // https://streams.spec.whatwg.org/#transform-stream-default-sink-abort-algorithm
    // 1. Perform ! TransformStreamError(stream, reason).
    Error(script_state, stream_, reason);

    // 2. Return a promise resolved with undefined.
    return ToResolvedUndefinedPromise(script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(stream_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<TransformStream> stream_;
};

class TransformStream::DefaultSinkCloseAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit DefaultSinkCloseAlgorithm(TransformStream* stream)
      : stream_(stream) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 0);
    // https://streams.spec.whatwg.org/#transform-stream-default-sink-close-algorithm
    // 1. Let readable be stream.[[readable]].

    // 2. Let controller be stream.[[transformStreamController]].
    TransformStreamDefaultController* controller =
        stream_->transform_stream_controller_;

    // 3. Let flushPromise be the result of performing
    //    controller.[[flushAlgorithm]].
    auto flush_promise =
        controller->flush_algorithm_->Run(script_state, 0, nullptr);

    // 4. Perform ! TransformStreamDefaultControllerClearAlgorithms(controller).
    TransformStreamDefaultController::ClearAlgorithms(controller);

    class ResolveFunction final
        : public ThenCallable<IDLUndefined, ResolveFunction> {
     public:
      explicit ResolveFunction(TransformStream* stream) : stream_(stream) {}

      void React(ScriptState* script_state) {
        // 5. Return the result of transforming flushPromise with:
        //    a. A fulfillment handler that performs the following steps:
        //       i. If readable.[[state]] is "errored", throw
        //          readable.[[storedError]].
        if (ReadableStream::IsErrored(stream_->readable_)) {
          V8ThrowException::ThrowException(
              script_state->GetIsolate(),
              stream_->readable_->GetStoredError(script_state->GetIsolate()));
          return;
        }

        //      ii. Let readableController be
        //          readable.[[readableStreamController]].
        auto* readable_controller = stream_->GetReadableController();

        //     iii. If ! ReadableStreamDefaultControllerCanCloseOrEnqueue(
        //          readableController) is true, perform !
        //          ReadableStreamDefaultControllerClose(readableController).
        if (ReadableStreamDefaultController::CanCloseOrEnqueue(
                readable_controller)) {
          ReadableStreamDefaultController::Close(script_state,
                                                 readable_controller);
        }
      }

      void Trace(Visitor* visitor) const override {
        visitor->Trace(stream_);
        ThenCallable<IDLUndefined, ResolveFunction>::Trace(visitor);
      }

     private:
      Member<TransformStream> stream_;
    };

    class RejectFunction final : public ThenCallable<IDLAny, RejectFunction> {
     public:
      explicit RejectFunction(TransformStream* stream) : stream_(stream) {}

      void React(ScriptState* script_state, ScriptValue r) {
        // b. A rejection handler that, when called with argument r, performs
        //    the following steps:
        //    i. Perform ! TransformStreamError(stream, r).
        Error(script_state, stream_, r.V8Value());

        //   ii. Throw readable.[[storedError]].
        V8ThrowException::ThrowException(
            script_state->GetIsolate(),
            stream_->readable_->GetStoredError(script_state->GetIsolate()));
        return;
      }

      void Trace(Visitor* visitor) const override {
        visitor->Trace(stream_);
        ThenCallable<IDLAny, RejectFunction>::Trace(visitor);
      }

     private:
      Member<TransformStream> stream_;
    };

    // 5. Return the result of transforming flushPromise ...
    return flush_promise.Then(script_state,
                              MakeGarbageCollected<ResolveFunction>(stream_),
                              MakeGarbageCollected<RejectFunction>(stream_));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(stream_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<TransformStream> stream_;
};

class TransformStream::DefaultSourcePullAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit DefaultSourcePullAlgorithm(TransformStream* stream)
      : stream_(stream) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 0);

    // https://streams.spec.whatwg.org/#transform-stream-default-source-pull
    // 1. Assert: stream.[[backpressure]] is true.
    DCHECK(stream_->had_backpressure_);

    // 2. Assert: stream.[[backpressureChangePromise]] is not undefined.
    DCHECK(stream_->backpressure_change_promise_);

    // 3. Perform ! TransformStreamSetBackpressure(stream, false).
    SetBackpressure(script_state, stream_, false);

    // 4. Return stream.[[backpressureChangePromise]].
    return stream_->backpressure_change_promise_->Promise();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(stream_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<TransformStream> stream_;
};

// This algorithm isn't explicitly named in the standard, but instead is
// described by a step in InitializeTransformStream.
class TransformStream::DefaultSourceCancelAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit DefaultSourceCancelAlgorithm(TransformStream* stream)
      : stream_(stream) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 1);

    // https://streams.spec.whatwg.org/#initialize-transform-stream
    // 7. Let cancelAlgorithm be the following steps, taking a reason argument:
    //    a. Perform ! TransformStreamErrorWritableAndUnblockWrite(stream,
    //       reason).
    ErrorWritableAndUnblockWrite(script_state, stream_, argv[0]);

    //    b. Return a promise resolved with undefined.
    return ToResolvedUndefinedPromise(script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(stream_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<TransformStream> stream_;
};

// This is split out from the constructor in this implementation as calling
// JavaScript from inside a C++ constructor can cause GC problems.
void TransformStream::InitInternal(ScriptState* script_state,
                                   ScriptValue raw_transformer,
                                   ScriptValue raw_writable_strategy,
                                   ScriptValue raw_readable_strategy,
                                   ExceptionState& exception_state) {
  // TODO(ricea): Move this to IDL.
  UseCounter::Count(ExecutionContext::From(script_state),
                    WebFeature::kTransformStreamConstructor);

  DCHECK(!raw_transformer.IsEmpty());
  DCHECK(!raw_writable_strategy.IsEmpty());
  DCHECK(!raw_readable_strategy.IsEmpty());

  auto context = script_state->GetContext();
  auto* isolate = script_state->GetIsolate();

  // https://streams.spec.whatwg.org/#ts-constructor
  // Perform the "transformer = {}" step from the function signature.
  v8::Local<v8::Object> transformer;
  ScriptValueToObject(script_state, raw_transformer, &transformer,
                      exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // Perform the "writableStrategy = {}" step from the function signature, and
  // 1. Let writableSizeFunction be ? GetV(writableStrategy, "size").
  // 2. Let writableHighWaterMark be ? GetV(writableStrategy, "highWaterMark").
  StrategyUnpacker writable_strategy_unpacker(
      script_state, raw_writable_strategy, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // Perform the "readableStrategy = {}" step from the function signature, and
  // 3. Let readableSizeFunction be ? GetV(readableStrategy, "size").
  // 4. Let readableHighWaterMark be ? GetV(readableStrategy, "highWaterMark").
  StrategyUnpacker readable_strategy_unpacker(
      script_state, raw_readable_strategy, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  TryRethrowScope rethrow_scope(isolate, exception_state);

  // 5. Let writableType be ? GetV(transformer, "writableType").
  v8::Local<v8::Value> writable_type;
  if (!transformer->Get(context, V8AtomicString(isolate, "writableType"))
           .ToLocal(&writable_type)) {
    return;
  }

  // 6. If writableType is not undefined, throw a RangeError exception.
  if (!writable_type->IsUndefined()) {
    exception_state.ThrowRangeError("Invalid writableType was specified");
    return;
  }

  // 7. Let writableSizeAlgorithm be ? MakeSizeAlgorithmFromSizeFunction(
  //    writableSizeFunction).
  auto* writable_size_algorithm = writable_strategy_unpacker.MakeSizeAlgorithm(
      script_state, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 8. If writableHighWaterMark is undefined, set writableHighWaterMark to 1.
  // 9. Set writableHighWaterMark to ? ValidateAndNormalizeHighWaterMark(
  //    writableHighWaterMark).
  double writable_high_water_mark = writable_strategy_unpacker.GetHighWaterMark(
      script_state, 1, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 10. Let readableType be ? GetV(transformer, "readableType").
  v8::Local<v8::Value> readable_type;
  if (!transformer->Get(context, V8AtomicString(isolate, "readableType"))
           .ToLocal(&readable_type)) {
    return;
  }

  // 11. If readableType is not undefined, throw a RangeError exception.
  if (!readable_type->IsUndefined()) {
    exception_state.ThrowRangeError("Invalid readableType was specified");
    return;
  }

  // 12. Let readableSizeAlgorithm be ? MakeSizeAlgorithmFromSizeFunction(
  //     readableSizeFunction).
  auto* readable_size_algorithm = readable_strategy_unpacker.MakeSizeAlgorithm(
      script_state, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 13. If readableHighWaterMark is undefined, set readableHighWaterMark to 0.
  // 14. Set readableHighWaterMark be ? ValidateAndNormalizeHighWaterMark(
  //     readableHighWaterMark).
  double readable_high_water_mark = readable_strategy_unpacker.GetHighWaterMark(
      script_state, 0, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 15. Let startPromise be a new promise.
  auto* start_promise =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  // 16. Perform ! InitializeTransformStream(this, startPromise,
  //     writableHighWaterMark, writableSizeAlgorithm, readableHighWaterMark,
  //     readableSizeAlgorithm).
  Initialize(script_state, this, start_promise, writable_high_water_mark,
             writable_size_algorithm, readable_high_water_mark,
             readable_size_algorithm, exception_state);

  // 17. Perform ? SetUpTransformStreamDefaultControllerFromTransformer(this,
  //     transformer).
  const auto controller_value =
      TransformStreamDefaultController::SetUpFromTransformer(
          script_state, this, transformer, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 18. Let startResult be ? InvokeOrNoop(transformer, "start", « this.
  //     [[transformStreamController]] »).
  v8::MaybeLocal<v8::Value> start_result_maybe =
      CallOrNoop1(script_state, transformer, "start", "transformer.start",
                  controller_value, exception_state);
  v8::Local<v8::Value> start_result;
  if (!start_result_maybe.ToLocal(&start_result)) {
    CHECK(exception_state.HadException());
    return;
  }
  DCHECK(!exception_state.HadException());

  // 19. Resolve startPromise with startResult.
  start_promise->Resolve(
      ScriptPromise<IDLUndefined>::FromV8Value(script_state, start_result));
}

void TransformStream::Initialize(
    ScriptState* script_state,
    TransformStream* stream,
    ScriptPromiseResolver<IDLUndefined>* start_promise,
    double writable_high_water_mark,
    StrategySizeAlgorithm* writable_size_algorithm,
    double readable_high_water_mark,
    StrategySizeAlgorithm* readable_size_algorithm,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#initialize-transform-stream
  // 1. Let startAlgorithm be an algorithm that returns startPromise.
  auto* start_algorithm =
      MakeGarbageCollected<ReturnStartPromiseAlgorithm>(start_promise);

  // 2. Let writeAlgorithm be the following steps, taking a chunk argument:
  //    a. Return ! TransformStreamDefaultSinkWriteAlgorithm(stream, chunk).
  auto* write_algorithm =
      MakeGarbageCollected<DefaultSinkWriteAlgorithm>(stream);

  // 3. Let abortAlgorithm be the following steps, taking a reason argument:
  //    a. Return ! TransformStreamDefaultSinkAbortAlgorithm(stream, reason).
  auto* abort_algorithm =
      MakeGarbageCollected<DefaultSinkAbortAlgorithm>(stream);

  // 4. Let closeAlgorithm be the following steps:
  //    a. Return ! TransformStreamDefaultSinkCloseAlgorithm(stream).
  auto* close_algorithm =
      MakeGarbageCollected<DefaultSinkCloseAlgorithm>(stream);

  // 5. Set stream.[[writable]] to ! CreateWritableStream(startAlgorithm,
  //    writeAlgorithm, closeAlgorithm, abortAlgorithm, writableHighWaterMark,
  //    writableSizeAlgorithm).
  stream->writable_ = WritableStream::Create(
      script_state, start_algorithm, write_algorithm, close_algorithm,
      abort_algorithm, writable_high_water_mark, writable_size_algorithm,
      exception_state);
  DCHECK(!exception_state.HadException());

  // 6. Let pullAlgorithm be the following steps:
  //    a. Return ! TransformStreamDefaultSourcePullAlgorithm(stream).
  auto* pull_algorithm =
      MakeGarbageCollected<DefaultSourcePullAlgorithm>(stream);

  // 7. Let cancelAlgorithm be the following steps, taking a reason argument:
  //    a. Perform ! TransformStreamErrorWritableAndUnblockWrite(stream,
  //       reason).
  //    b. Return a promise resolved with undefined.
  auto* cancel_algorithm =
      MakeGarbageCollected<DefaultSourceCancelAlgorithm>(stream);

  // 8. Set stream.[[readable]] to ! CreateReadableStream(startAlgorithm,
  //    pullAlgorithm, cancelAlgorithm, readableHighWaterMark,
  //    readableSizeAlgorithm).
  stream->readable_ = ReadableStream::Create(
      script_state, start_algorithm, pull_algorithm, cancel_algorithm,
      readable_high_water_mark, readable_size_algorithm, exception_state);
  DCHECK(!exception_state.HadException());

  //  9. Set stream.[[backpressure]] and stream.[[backpressureChangePromise]] to
  //     undefined.
  // 10. Perform ! TransformStreamSetBackpressure(stream, true).
  // |had_backpressure_| is bool and so can't be set to undefined; instead we
  // take the equivalent steps to achieve the final result here.
  DCHECK(stream->had_backpressure_);
  DCHECK(!stream->backpressure_change_promise_);
  stream->backpressure_change_promise_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  stream->backpressure_change_promise_->SuppressDetachCheck();

  // 11. Set stream.[[transformStreamController]] to undefined.
  // (This is set by the constructor; just verify the value here).
  DCHECK_EQ(stream->transform_stream_controller_, nullptr);
}

void TransformStream::Error(ScriptState* script_state,
                            TransformStream* stream,
                            v8::Local<v8::Value> e) {
  // https://streams.spec.whatwg.org/#transform-stream-error
  // 1. Perform ! ReadableStreamDefaultControllerError(stream.[[readable]].
  //    [[readableStreamController]], e).
  ReadableStreamDefaultController::Error(script_state,
                                         stream->GetReadableController(), e);

  // 2. Perform ! TransformStreamErrorWritableAndUnblockWrite(stream, e).
  ErrorWritableAndUnblockWrite(script_state, stream, e);
}

void TransformStream::ErrorWritableAndUnblockWrite(Script
```