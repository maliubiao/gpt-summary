Response:
The user wants a summary of the `readable_stream.cc` file in the Chromium Blink engine. I need to identify the key functionalities implemented in this file related to readable streams. I should also look for connections to JavaScript, HTML, and CSS, along with examples. The prompt also requests hypothetical inputs and outputs, common user errors, and debugging steps leading to this code. Finally, I need to provide an overall summary of the file's purpose, as this is part 1 of 2.

Here's a breakdown of the file's content and how to address each point:

1. **File Functionality:** The code defines the `ReadableStream` class and related algorithms for handling readable streams. This involves managing stream states, controllers (default and byte), readers (default and BYOB), and operations like reading, canceling, teeing, and piping.

2. **Relationship to JavaScript, HTML, CSS:** Readable streams are a JavaScript API. The C++ code implements the underlying logic for these APIs. Examples would involve JavaScript code using the `ReadableStream` constructor or methods like `getReader()`, `pipeTo()`, etc. HTML and CSS are less directly related, but data fetched via streams might be used to populate HTML elements or style them with CSS.

3. **Logical Reasoning, Input/Output:**  Consider specific functions like `PullAlgorithm` or `CancelAlgorithm`. For `PullAlgorithm`, the input could be a request for more data, and the output would be a promise resolving with the next chunk of data. For `CancelAlgorithm`, the input is a cancellation reason, and the output is a promise indicating the cancellation status.

4. **User/Programming Errors:** Common errors include attempting to operate on a locked stream or providing incorrect arguments to stream methods.

5. **User Steps to Reach the Code:** A user interacts with a web page that uses the Streams API in JavaScript. For example, fetching data using `fetch()` which returns a readable stream, or using the `ReadableStream` constructor directly.

6. **File Summary:** This file is the core implementation of the Readable Streams API within the Blink rendering engine. It handles the internal state management and logic for stream operations, bridging the gap between the JavaScript API and the underlying data sources.
这是 `blink/renderer/core/streams/readable_stream.cc` 文件的第一部分，该文件是 Chromium Blink 引擎中实现可读流（Readable Streams）功能的核心代码。从提供的代码片段来看，其主要功能可以归纳为：

**核心功能：实现 Web Streams API 中的 ReadableStream 及其相关操作。**

更具体地说，这部分代码负责：

1. **`ReadableStream` 类的定义和创建:**
    *   提供了多种创建 `ReadableStream` 对象的方法，包括从 JavaScript 代码创建，以及在 C++ 内部创建特定类型的可读流（例如字节流）。
    *   支持使用不同的策略（strategy）来控制流的行为，例如基于计数或自定义大小算法的高水位线控制。
    *   实现了构造函数 `ReadableStream::Create`，该函数接收底层源（underlying source）和策略作为参数，并初始化可读流对象。

2. **实现可读流的底层算法 (Algorithms):**
    *   定义了用于执行“pull”和“cancel”操作的算法类 (`PullAlgorithm`, `CancelAlgorithm`)，这些算法通常会委托给底层的源对象 (`UnderlyingByteSourceBase`).
    *   实现了迭代器相关的逻辑 (`IterationSource`, `IterationReadRequest`)，使得可读流可以被用作异步迭代器。

3. **处理可读流的各种操作:**
    *   实现了 `cancel()` 方法，允许取消可读流。
    *   实现了 `getReader()` 方法，用于获取不同类型的读取器 (`ReadableStreamDefaultReader`, `ReadableStreamBYOBReader`)，以便从流中读取数据。
    *   实现了 `pipeThrough()` 和 `pipeTo()` 方法，用于将可读流的数据管道传输到可写流。
    *   实现了 `tee()` 方法，用于创建一个可读流的两个分支。

4. **管理可读流的状态和控制器:**
    *   涉及到 `ReadableStreamDefaultController` 和 `ReadableByteStreamController` 的创建和设置，这些控制器负责管理流的内部状态和与底层源的交互。

5. **与 JavaScript 的绑定:**
    *   代码中大量使用了 Blink 的绑定机制，例如 `ScriptState`，`ScriptPromise`，`ScriptValue` 等，用于在 C++ 代码和 JavaScript 代码之间传递数据和控制。
    *   包含了与 V8 引擎相关的代码，例如 `v8::Local<v8::Value>`。

**与 JavaScript, HTML, CSS 的关系：**

`readable_stream.cc` 文件直接实现了 Web Streams API 的一部分，该 API 是 JavaScript 中用于处理流式数据的标准。

*   **JavaScript:**  JavaScript 代码可以直接使用 `ReadableStream` 构造函数创建可读流，并调用其上的方法，例如 `
Prompt: 
```
这是目录为blink/renderer/core/streams/readable_stream.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/readable_stream.h"

#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_get_reader_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_writable_pair.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_stream_pipe_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_underlying_source.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_readablestreambyobreader_readablestreamdefaultreader.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/streams/byte_stream_tee_engine.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/pipe_options.h"
#include "third_party/blink/renderer/core/streams/pipe_to_engine.h"
#include "third_party/blink/renderer/core/streams/read_into_request.h"
#include "third_party/blink/renderer/core/streams/read_request.h"
#include "third_party/blink/renderer/core/streams/readable_byte_stream_controller.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_reader.h"
#include "third_party/blink/renderer/core/streams/readable_stream_controller.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/readable_stream_generic_reader.h"
#include "third_party/blink/renderer/core/streams/readable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/core/streams/tee_engine.h"
#include "third_party/blink/renderer/core/streams/transferable_streams.h"
#include "third_party/blink/renderer/core/streams/underlying_byte_source_base.h"
#include "third_party/blink/renderer/core/streams/underlying_source_base.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/streams/writable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

// Implements a pull algorithm that delegates to an UnderlyingByteSourceBase.
// This is used when creating a ReadableByteStream from C++.
class ReadableStream::PullAlgorithm final : public StreamAlgorithm {
 public:
  explicit PullAlgorithm(UnderlyingByteSourceBase* underlying_byte_source)
      : underlying_byte_source_(underlying_byte_source) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 0);
    DCHECK(controller_);
    ScriptPromise<IDLUndefined> promise;
    if (script_state->ContextIsValid()) {
      v8::TryCatch try_catch(script_state->GetIsolate());
      {
        // This is needed because the realm of the underlying source can be
        // different from the realm of the readable stream.
        ScriptState::Scope scope(underlying_byte_source_->GetScriptState());
        promise = underlying_byte_source_->Pull(
            controller_, PassThroughException(script_state->GetIsolate()));
      }
      if (try_catch.HasCaught()) {
        return ScriptPromise<IDLUndefined>::Reject(script_state,
                                                   try_catch.Exception());
      }
    } else {
      return ScriptPromise<IDLUndefined>::Reject(
          script_state, V8ThrowException::CreateTypeError(
                            script_state->GetIsolate(), "invalid realm"));
    }

    return promise;
  }

  // SetController() must be called before Run() is.
  void SetController(ReadableByteStreamController* controller) {
    controller_ = controller;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(underlying_byte_source_);
    visitor->Trace(controller_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<UnderlyingByteSourceBase> underlying_byte_source_;
  Member<ReadableByteStreamController> controller_;
};

// Implements a cancel algorithm that delegates to an UnderlyingByteSourceBase.
class ReadableStream::CancelAlgorithm final : public StreamAlgorithm {
 public:
  explicit CancelAlgorithm(UnderlyingByteSourceBase* underlying_byte_source)
      : underlying_byte_source_(underlying_byte_source) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 1);
    ScriptPromise<IDLUndefined> promise;
    if (script_state->ContextIsValid()) {
      v8::TryCatch try_catch(script_state->GetIsolate());
      {
        // This is needed because the realm of the underlying source can be
        // different from the realm of the readable stream.
        ScriptState::Scope scope(underlying_byte_source_->GetScriptState());
        promise = underlying_byte_source_->Cancel(argv[0]);
      }
      if (try_catch.HasCaught()) {
        return ScriptPromise<IDLUndefined>::Reject(script_state,
                                                   try_catch.Exception());
      }
    } else {
      return ScriptPromise<IDLUndefined>::Reject(
          script_state, V8ThrowException::CreateTypeError(
                            script_state->GetIsolate(), "invalid realm"));
    }

    return promise;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(underlying_byte_source_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<UnderlyingByteSourceBase> underlying_byte_source_;
};

class ReadableStream::IterationSource final
    : public ReadableStream::IterationSourceBase {
 public:
  IterationSource(ScriptState* script_state,
                  Kind kind,
                  ReadableStreamDefaultReader* reader,
                  bool prevent_cancel)
      : ReadableStream::IterationSourceBase(script_state, kind),
        reader_(reader),
        prevent_cancel_(prevent_cancel) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(reader_);
    ReadableStream::IterationSourceBase::Trace(visitor);
  }

 protected:
  void GetNextIterationResult() override;
  void AsyncIteratorReturn(ScriptValue arg) override;

 private:
  friend class IterationReadRequest;

  void TryResolvePromise();

  Member<ReadableStreamDefaultReader> reader_;
  bool prevent_cancel_;
};

class ReadableStream::IterationReadRequest final : public ReadRequest {
 public:
  explicit IterationReadRequest(IterationSource* iteration_source)
      : iteration_source_(iteration_source) {}

  void ChunkSteps(ScriptState* script_state,
                  v8::Local<v8::Value> chunk,
                  ExceptionState& exception_state) const override {
    // 1. Resolve promise with chunk.
    iteration_source_->TakePendingPromiseResolver()->Resolve(
        iteration_source_->MakeIterationResult(
            ScriptValue(script_state->GetIsolate(), chunk)));
  }

  void CloseSteps(ScriptState* script_state) const override {
    // 1. Perform ! ReadableStreamDefaultReaderRelease(reader).
    ReadableStreamDefaultReader::Release(script_state,
                                         iteration_source_->reader_);
    // 2. Resolve promise with end of iteration.
    iteration_source_->TakePendingPromiseResolver()->Resolve(
        iteration_source_->MakeEndOfIteration());
  }

  void ErrorSteps(ScriptState* script_state,
                  v8::Local<v8::Value> e) const override {
    // 1. Perform ! ReadableStreamDefaultReaderRelease(reader).
    ReadableStreamDefaultReader::Release(script_state,
                                         iteration_source_->reader_);
    // 2. Reject promise with e.
    iteration_source_->TakePendingPromiseResolver()->Reject(e);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(iteration_source_);
    ReadRequest::Trace(visitor);
  }

 private:
  Member<IterationSource> iteration_source_;
};

void ReadableStream::IterationSource::GetNextIterationResult() {
  DCHECK(HasPendingPromise());

  // https://streams.spec.whatwg.org/#ref-for-dfn-get-the-next-iteration-result
  // 2. Assert: reader.[[stream]] is not undefined.
  DCHECK(reader_->owner_readable_stream_);

  // 4. Let readRequest be a new read request.
  auto* read_request = MakeGarbageCollected<IterationReadRequest>(this);

  // 5. Perform ! ReadableStreamDefaultReaderRead(this, readRequest).
  ScriptState* script_state = GetScriptState();
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kUnknown, "", "");
  ReadableStreamDefaultReader::Read(script_state, reader_, read_request,
                                    exception_state);
}

void ReadableStream::IterationSource::AsyncIteratorReturn(ScriptValue arg) {
  DCHECK(HasPendingPromise());

  // https://streams.spec.whatwg.org/#ref-for-asynchronous-iterator-return
  // 2. Assert: reader.[[stream]] is not undefined.
  DCHECK(reader_->owner_readable_stream_);
  // 3. Assert: reader.[[readRequests]] is empty, as the async iterator
  //    machinery guarantees that any previous calls to next() have settled
  //    before this is called.
  DCHECK(reader_->read_requests_.empty());

  ScriptState* script_state = GetScriptState();
  // 4. If iterator's prevent cancel is false:
  if (!prevent_cancel_) {
    // 4.1. Let result be ! ReadableStreamReaderGenericCancel(reader, arg).
    auto result = ReadableStreamGenericReader::GenericCancel(
        script_state, reader_, arg.V8Value());
    // 4.2. Perform ! ReadableStreamDefaultReaderRelease(reader).
    ReadableStreamDefaultReader::Release(script_state, reader_);
    // 4.3. Return result.
    TakePendingPromiseResolver()->Resolve(result.V8Promise());
    return;
  }

  // 5. Perform ! ReadableStreamDefaultReaderRelease(reader).
  ReadableStreamDefaultReader::Release(script_state, reader_);

  // 6. Return a promise resolved with undefined.
  TakePendingPromiseResolver()->Resolve(
      v8::Undefined(script_state->GetIsolate()));
}

ReadableStream* ReadableStream::Create(ScriptState* script_state,
                                       ExceptionState& exception_state) {
  return Create(script_state,
                ScriptValue(script_state->GetIsolate(),
                            v8::Undefined(script_state->GetIsolate())),
                ScriptValue(script_state->GetIsolate(),
                            v8::Undefined(script_state->GetIsolate())),
                exception_state);
}

ReadableStream* ReadableStream::Create(ScriptState* script_state,
                                       ScriptValue underlying_source,
                                       ExceptionState& exception_state) {
  return Create(script_state, underlying_source,
                ScriptValue(script_state->GetIsolate(),
                            v8::Undefined(script_state->GetIsolate())),
                exception_state);
}

ReadableStream* ReadableStream::Create(ScriptState* script_state,
                                       ScriptValue underlying_source,
                                       ScriptValue strategy,
                                       ExceptionState& exception_state) {
  auto* stream = MakeGarbageCollected<ReadableStream>();
  stream->InitInternal(script_state, underlying_source, strategy, false,
                       exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  return stream;
}

ReadableStream* ReadableStream::CreateWithCountQueueingStrategy(
    ScriptState* script_state,
    UnderlyingSourceBase* underlying_source,
    size_t high_water_mark) {
  return CreateWithCountQueueingStrategy(script_state, underlying_source,
                                         high_water_mark,
                                         AllowPerChunkTransferring(false),
                                         /*optimizer=*/nullptr);
}

ReadableStream* ReadableStream::CreateWithCountQueueingStrategy(
    ScriptState* script_state,
    UnderlyingSourceBase* underlying_source,
    size_t high_water_mark,
    AllowPerChunkTransferring allow_per_chunk_transferring,
    std::unique_ptr<ReadableStreamTransferringOptimizer> optimizer) {
  auto* isolate = script_state->GetIsolate();
  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state),
      v8::MicrotasksScope::kDoNotRunMicrotasks);

  auto* stream = MakeGarbageCollected<ReadableStream>();
  stream->InitWithCountQueueingStrategy(
      script_state, underlying_source, high_water_mark,
      allow_per_chunk_transferring, std::move(optimizer), IGNORE_EXCEPTION);
  return stream;
}

void ReadableStream::InitWithCountQueueingStrategy(
    ScriptState* script_state,
    UnderlyingSourceBase* underlying_source,
    size_t high_water_mark,
    AllowPerChunkTransferring allow_per_chunk_transferring,
    std::unique_ptr<ReadableStreamTransferringOptimizer> optimizer,
    ExceptionState& exception_state) {
  Initialize(this);
  auto* controller =
      MakeGarbageCollected<ReadableStreamDefaultController>(script_state);

  ReadableStreamDefaultController::SetUp(
      script_state, this, controller,
      MakeGarbageCollected<UnderlyingStartAlgorithm>(underlying_source,
                                                     controller),
      MakeGarbageCollected<UnderlyingPullAlgorithm>(underlying_source),
      MakeGarbageCollected<UnderlyingCancelAlgorithm>(underlying_source),
      high_water_mark, CreateDefaultSizeAlgorithm(), exception_state);

  allow_per_chunk_transferring_ = allow_per_chunk_transferring;
  transferring_optimizer_ = std::move(optimizer);
}

ReadableStream* ReadableStream::Create(ScriptState* script_state,
                                       StreamStartAlgorithm* start_algorithm,
                                       StreamAlgorithm* pull_algorithm,
                                       StreamAlgorithm* cancel_algorithm,
                                       double high_water_mark,
                                       StrategySizeAlgorithm* size_algorithm,
                                       ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#create-readable-stream
  // All arguments are compulsory in this implementation, so the first two steps
  // are skipped:
  // 1. If highWaterMark was not passed, set it to 1.
  // 2. If sizeAlgorithm was not passed, set it to an algorithm that returns 1.

  // 3. Assert: ! IsNonNegativeNumber(highWaterMark) is true.
  DCHECK_GE(high_water_mark, 0);

  // 4. Let stream be a new ReadableStream.
  auto* stream = MakeGarbageCollected<ReadableStream>();

  // 5. Perform ! InitializeReadableStream(stream).
  Initialize(stream);

  // 6. Let controller be a new ReadableStreamDefaultController.
  auto* controller =
      MakeGarbageCollected<ReadableStreamDefaultController>(script_state);

  // 7. Perform ? SetUpReadableStreamDefaultController(stream, controller,
  //    startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark,
  //    sizeAlgorithm).
  ReadableStreamDefaultController::SetUp(
      script_state, stream, controller, start_algorithm, pull_algorithm,
      cancel_algorithm, high_water_mark, size_algorithm, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  // 8. Return stream.
  return stream;
}

ReadableStream* ReadableStream::CreateByteStream(
    ScriptState* script_state,
    StreamStartAlgorithm* start_algorithm,
    StreamAlgorithm* pull_algorithm,
    StreamAlgorithm* cancel_algorithm,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#abstract-opdef-createreadablebytestream
  // 1. Let stream be a new ReadableStream.
  auto* stream = MakeGarbageCollected<ReadableStream>();

  // 2. Perform ! InitializeReadableStream(stream).
  Initialize(stream);

  // 3. Let controller be a new ReadableByteStreamController.
  auto* controller = MakeGarbageCollected<ReadableByteStreamController>();

  // 4. Perform ? SetUpReadableByteStreamController(stream, controller,
  //    startAlgorithm, pullAlgorithm, cancelAlgorithm, 0, undefined).
  ReadableByteStreamController::SetUp(script_state, stream, controller,
                                      start_algorithm, pull_algorithm,
                                      cancel_algorithm, 0, 0, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  // 5. Return stream.
  return stream;
}

// static
ReadableStream* ReadableStream::CreateByteStream(
    ScriptState* script_state,
    UnderlyingByteSourceBase* underlying_byte_source) {
  // https://streams.spec.whatwg.org/#abstract-opdef-createreadablebytestream
  // 1. Let stream be a new ReadableStream.
  auto* stream = MakeGarbageCollected<ReadableStream>();

  // Construction of the byte stream cannot fail because the trivial start
  // algorithm will not throw.
  NonThrowableExceptionState exception_state;
  InitByteStream(script_state, stream, underlying_byte_source, exception_state);

  // 5. Return stream.
  return stream;
}

void ReadableStream::InitByteStream(
    ScriptState* script_state,
    ReadableStream* stream,
    UnderlyingByteSourceBase* underlying_byte_source,
    ExceptionState& exception_state) {
  auto* pull_algorithm =
      MakeGarbageCollected<PullAlgorithm>(underlying_byte_source);
  auto* cancel_algorithm =
      MakeGarbageCollected<CancelAlgorithm>(underlying_byte_source);

  // Step 3 of
  // https://streams.spec.whatwg.org/#abstract-opdef-createreadablebytestream
  // 3. Let controller be a new ReadableByteStreamController.
  auto* controller = MakeGarbageCollected<ReadableByteStreamController>();

  InitByteStream(script_state, stream, controller,
                 CreateTrivialStartAlgorithm(), pull_algorithm,
                 cancel_algorithm, exception_state);
  DCHECK(!exception_state.HadException());

  pull_algorithm->SetController(controller);
}

void ReadableStream::InitByteStream(ScriptState* script_state,
                                    ReadableStream* stream,
                                    ReadableByteStreamController* controller,
                                    StreamStartAlgorithm* start_algorithm,
                                    StreamAlgorithm* pull_algorithm,
                                    StreamAlgorithm* cancel_algorithm,
                                    ExceptionState& exception_state) {
  // Step 2 and 4 of
  // https://streams.spec.whatwg.org/#abstract-opdef-createreadablebytestream
  // 2. Perform ! InitializeReadableStream(stream).
  Initialize(stream);

  // 4. Perform ? SetUpReadableByteStreamController(stream, controller,
  // startAlgorithm, pullAlgorithm, cancelAlgorithm, 0, undefined).
  ReadableByteStreamController::SetUp(script_state, stream, controller,
                                      start_algorithm, pull_algorithm,
                                      cancel_algorithm, 0, 0, exception_state);
  if (exception_state.HadException()) {
    return;
  }
}

ReadableStream::ReadableStream() = default;

ReadableStream::~ReadableStream() = default;

bool ReadableStream::locked() const {
  // https://streams.spec.whatwg.org/#rs-locked
  // 2. Return ! IsReadableStreamLocked(this).
  return IsLocked(this);
}

ScriptPromise<IDLUndefined> ReadableStream::cancel(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  return cancel(script_state,
                ScriptValue(script_state->GetIsolate(),
                            v8::Undefined(script_state->GetIsolate())),
                exception_state);
}

ScriptPromise<IDLUndefined> ReadableStream::cancel(
    ScriptState* script_state,
    ScriptValue reason,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rs-cancel
  // 2. If ! IsReadableStreamLocked(this) is true, return a promise rejected
  //    with a TypeError exception.
  if (IsLocked(this)) {
    exception_state.ThrowTypeError("Cannot cancel a locked stream");
    return EmptyPromise();
  }

  // 3. Return ! ReadableStreamCancel(this, reason).
  return Cancel(script_state, this, reason.V8Value());
}

V8ReadableStreamReader* ReadableStream::getReader(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rs-get-reader
  // 1. If options["mode"] does not exist, return ?
  // AcquireReadableStreamDefaultReader(this).
  ReadableStreamDefaultReader* reader =
      AcquireDefaultReader(script_state, this, exception_state);
  if (!reader)
    return nullptr;
  return MakeGarbageCollected<V8ReadableStreamReader>(reader);
}

V8ReadableStreamReader* ReadableStream::getReader(
    ScriptState* script_state,
    const ReadableStreamGetReaderOptions* options,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rs-get-reader
  if (options->hasMode()) {
    DCHECK_EQ(options->mode(), "byob");

    UseCounter::Count(ExecutionContext::From(script_state),
                      WebFeature::kReadableStreamBYOBReader);

    ReadableStreamBYOBReader* reader =
        AcquireBYOBReader(script_state, this, exception_state);
    if (!reader)
      return nullptr;
    return MakeGarbageCollected<V8ReadableStreamReader>(reader);
  }

  return getReader(script_state, exception_state);
}

ReadableStreamDefaultReader* ReadableStream::GetDefaultReaderForTesting(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  auto* result = getReader(script_state, exception_state);
  if (!result)
    return nullptr;
  return result->GetAsReadableStreamDefaultReader();
}

ReadableStreamBYOBReader* ReadableStream::GetBYOBReaderForTesting(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  auto* options = ReadableStreamGetReaderOptions::Create();
  options->setMode("byob");
  auto* result = getReader(script_state, options, exception_state);
  if (!result)
    return nullptr;
  return result->GetAsReadableStreamBYOBReader();
}

ReadableStream* ReadableStream::pipeThrough(ScriptState* script_state,
                                            ReadableWritablePair* transform,
                                            ExceptionState& exception_state) {
  return pipeThrough(script_state, transform, StreamPipeOptions::Create(),
                     exception_state);
}

// https://streams.spec.whatwg.org/#rs-pipe-through
ReadableStream* ReadableStream::pipeThrough(ScriptState* script_state,
                                            ReadableWritablePair* transform,
                                            const StreamPipeOptions* options,
                                            ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rs-pipe-through
  DCHECK(transform->hasReadable());
  ReadableStream* readable_stream = transform->readable();

  DCHECK(transform->hasWritable());
  WritableStream* writable_stream = transform->writable();

  // 1. If ! IsReadableStreamLocked(this) is true, throw a TypeError exception.
  if (IsLocked(this)) {
    exception_state.ThrowTypeError("Cannot pipe a locked stream");
    return nullptr;
  }

  // 2. If ! IsWritableStreamLocked(transform["writable"]) is true, throw a
  //    TypeError exception.
  if (WritableStream::IsLocked(writable_stream)) {
    exception_state.ThrowTypeError("parameter 1's 'writable' is locked");
    return nullptr;
  }

  // 3. Let signal be options["signal"] if it exists, or undefined otherwise.
  auto* pipe_options = MakeGarbageCollected<PipeOptions>(options);

  // 4. Let promise be ! ReadableStreamPipeTo(this, transform["writable"],
  //    options["preventClose"], options["preventAbort"],
  //    options["preventCancel"], signal).
  auto promise = PipeTo(script_state, this, writable_stream, pipe_options,
                        exception_state);

  // 5. Set promise.[[PromiseIsHandled]] to true.
  promise.MarkAsHandled();

  // 6. Return transform["readable"].
  return readable_stream;
}

ScriptPromise<IDLUndefined> ReadableStream::pipeTo(
    ScriptState* script_state,
    WritableStream* destination,
    ExceptionState& exception_state) {
  return pipeTo(script_state, destination, StreamPipeOptions::Create(),
                exception_state);
}

ScriptPromise<IDLUndefined> ReadableStream::pipeTo(
    ScriptState* script_state,
    WritableStream* destination,
    const StreamPipeOptions* options,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rs-pipe-to
  // 1. If ! IsReadableStreamLocked(this) is true, return a promise rejected
  //    with a TypeError exception.
  if (IsLocked(this)) {
    exception_state.ThrowTypeError("Cannot pipe a locked stream");
    return EmptyPromise();
  }

  // 2. If ! IsWritableStreamLocked(destination) is true, return a promise
  //    rejected with a TypeError exception.
  if (WritableStream::IsLocked(destination)) {
    exception_state.ThrowTypeError("Cannot pipe to a locked stream");
    return EmptyPromise();
  }

  // 3. Let signal be options["signal"] if it exists, or undefined otherwise.
  auto* pipe_options = MakeGarbageCollected<PipeOptions>(options);

  // 4. Return ! ReadableStreamPipeTo(this, destination,
  //    options["preventClose"], options["preventAbort"],
  //    options["preventCancel"], signal).
  return PipeTo(script_state, this, destination, pipe_options, exception_state);
}

HeapVector<Member<ReadableStream>> ReadableStream::tee(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  return CallTeeAndReturnBranchArray(script_state, this, false,
                                     exception_state);
}

// Unlike in the standard, this is defined as a separate method from the
// constructor. This prevents problems when garbage collection happens
// re-entrantly during construction.
void ReadableStream::InitInternal(ScriptState* script_state,
                                  ScriptValue raw_underlying_source,
                                  ScriptValue raw_strategy,
                                  bool created_by_ua,
                                  ExceptionState& exception_state) {
  if (!created_by_ua) {
    // TODO(ricea): Move this to IDL once blink::ReadableStreamOperations is
    // no longer using the public constructor.
    UseCounter::Count(ExecutionContext::From(script_state),
                      WebFeature::kReadableStreamConstructor);
  }

  // https://streams.spec.whatwg.org/#rs-constructor
  //  1. Perform ! InitializeReadableStream(this).
  Initialize(this);

  // The next part of this constructor corresponds to the object conversions
  // that are implicit in the definition in the standard.
  DCHECK(!raw_underlying_source.IsEmpty());
  DCHECK(!raw_strategy.IsEmpty());

  auto context = script_state->GetContext();
  auto* isolate = script_state->GetIsolate();

  v8::Local<v8::Object> underlying_source;
  ScriptValueToObject(script_state, raw_underlying_source, &underlying_source,
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

  // 4. Let type be ? GetV(underlyingSource, "type").
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::Local<v8::Value> type;
  if (!underlying_source->Get(context, V8AtomicString(isolate, "type"))
           .ToLocal(&type)) {
    return;
  }

  if (!type->IsUndefined()) {
    // 5. Let typeString be ? ToString(type).
    v8::Local<v8::String> type_string;
    if (!type->ToString(context).ToLocal(&type_string)) {
      return;
    }

    // 6. If typeString is "bytes",
    if (type_string->StringEquals(V8AtomicString(isolate, "bytes"))) {
      UseCounter::Count(ExecutionContext::From(script_state),
                        WebFeature::kReadableStreamWithByteSource);

      UnderlyingSource* underlying_source_dict =
          NativeValueTraits<UnderlyingSource>::NativeValue(
              script_state->GetIsolate(), raw_underlying_source.V8Value(),
              exception_state);
      if (!strategy_unpacker.IsSizeUndefined()) {
        exception_state.ThrowRangeError(
            "Cannot create byte stream with size() defined on the strategy");
        return;
      }
      double high_water_mark =
          strategy_unpacker.GetHighWaterMark(script_state, 0, exception_state);
      if (exception_state.HadException()) {
        return;
      }
      ReadableByteStreamController::SetUpFromUnderlyingSource(
          script_state, this, underlying_source, underlying_source_dict,
          high_water_mark, exception_state);
      return;
    }

    // 8. Otherwise, throw a RangeError exception.
    else {
      exception_state.ThrowRangeError("Invalid type is specified");
      return;
    }
  }

  // 7. Otherwise, if type is undefined,
  //   a. Let sizeAlgorithm be ? MakeSizeAlgorithmFromSizeFunction(size).
  auto* size_algorithm =
      strategy_unpacker.MakeSizeAlgorithm(script_state, exception_state);
  if (exception_state.HadException()) {
    return;
  }
  DCHECK(size_algorithm);

  //   b. If highWaterMark is undefined, let highWaterMark be 1.
  //   c. Set highWaterMark to ? ValidateAndNormalizeHighWaterMark(
  //      highWaterMark).
  double high_water_mark =
      strategy_unpacker.GetHighWaterMark(script_state, 1, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 4. Perform ? SetUpReadableStreamDefaultControllerFromUnderlyingSource
  //  (this, underlyingSource, highWaterMark, sizeAlgorithm).
  ReadableStreamDefaultController::SetUpFromUnderlyingSource(
      script_state, this, underlying_source, high_water_mark, size_algorithm,
      exception_state);
}

//
// Readable stream abstract operations
//
ReadableStreamDefaultReader* ReadableStream::AcquireDefaultReader(
    ScriptState* script_state,
    ReadableStream* stream,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#acquire-readable-stream-reader
  // 1. Let reader by a new ReadableStreamDefaultReader.
  // 2. Perform ? SetUpReadableStreamReader(reader, stream).
  auto* reader = MakeGarbageCollected<ReadableStreamDefaultReader>(
      script_state, stream, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  // 3. Return reader.
  return reader;
}

ReadableStreamBYOBReader* ReadableStream::AcquireBYOBReader(
    ScriptState* script_state,
    ReadableStream* stream,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#acquire-readable-stream-byob-reader
  // 1. Let reader be a new ReadableStreamBYOBReader.
  // 2. Perform ? SetUpBYOBReader(reader, stream).
  auto* reader = MakeGarbageCollected<ReadableStreamBYOBReader>(
      script_state, stream, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  // 3. Return reader.
  return reader;
}

void ReadableStream::Initialize(ReadableStream* stream) {
  // Fields are initialised by the constructor, so we only check that they were
"""


```