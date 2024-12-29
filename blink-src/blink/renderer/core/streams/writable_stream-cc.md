Response:
The user wants a summary of the `WritableStream` class in Blink, based on the provided C++ source code.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The filename and the initial comment clearly state this file implements the `WritableStream` API in Blink. This API is part of the Streams standard, allowing data to be written to a destination in chunks.

2. **Analyze Key Members and Methods:** Scan the code for important member variables (like `state_`, `controller_`, `writer_`, promises related to closing and aborting) and methods. Pay attention to methods that match the Streams standard (like `abort`, `close`, `getWriter`).

3. **Group Functionality:**  Organize the observed functionalities into logical categories. The code itself is structured somewhat according to the spec, making this easier. Potential categories include:
    * Creation and Initialization
    * Writing Data (though the core logic seems to be in the controller)
    * Closing the Stream
    * Aborting the Stream
    * Locking the Stream (via the writer)
    * Error Handling
    * Backpressure Management
    * Transferring Streams
    * Internal Management (related to promises and state)

4. **Connect to Web APIs:**  Consider how `WritableStream` relates to JavaScript, HTML, and CSS. `WritableStream` is directly exposed as a JavaScript API. Think about typical use cases:
    * Downloading files (using `fetch` and piping to a `WritableStream`).
    * Writing to a file system (using the File System Access API).
    * Sending data over a WebSocket.
    * The connection to CSS and HTML is less direct but exists through APIs that interact with streams.

5. **Infer Logic and Examples:**  For key operations like `abort` and `close`, try to understand the steps involved based on the code. This includes handling different stream states and the use of promises. Formulate simple examples to illustrate the input and output of these operations.

6. **Identify Potential Errors:** Look for checks and error handling in the code. Common errors involve trying to operate on a locked or closed stream. Think about how a user might trigger these errors in JavaScript.

7. **Trace User Actions:** Consider how a user's interaction with a web page might lead to the execution of code within this `WritableStream` implementation. Start with a high-level user action and drill down.

8. **Structure the Summary:** Organize the information clearly, using headings and bullet points. Start with a concise overview and then elaborate on specific functionalities. Address each of the user's requests (functionality, relationship to web APIs, logic, errors, user actions).

9. **Refine and Review:** Ensure the summary is accurate, comprehensive (within the scope of the first part of the file), and easy to understand. Check for any inconsistencies or missing information. For instance, the initial thought might be to explain writing in detail, but the code suggests the *controller* handles the core writing logic. Adjust the summary to reflect this. Also, ensure the summary explicitly states it's based on the *first part* of the file.

**Self-Correction Example during the process:**

Initial thought: "This file handles the actual writing of data to the underlying sink."

Reviewing the code: Notice the `WritableStreamDefaultController` and methods like `WritableStreamDefaultController::Close`. The `WritableStream` class seems to manage the state and high-level operations, while the controller interacts more directly with the underlying sink.

Correction:  Adjust the description to highlight that `WritableStream` manages the overall lifecycle and state, and delegates the actual writing logic to the controller.
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/writable_stream.h"

#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_queuing_strategy_init.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/streams/count_queuing_strategy.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/pipe_options.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/core/streams/transferable_streams.h"
#include "third_party/blink/renderer/core/streams/underlying_sink_base.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/streams/writable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"

// Implementation of WritableStream for Blink. See
// https://streams.spec.whatwg.org/#ws. The implementation closely follows the
// standard, except where required for performance or integration with Blink.
// In particular, classes, methods and abstract operations are implemented in
// the same order as in the standard, to simplify side-by-side reading.

namespace blink {

// The PendingAbortRequest type corresponds to the Record {[[promise]],
// [[reason]], [[wasAlreadyErroring]]} from the standard.
class WritableStream::PendingAbortRequest final
    : public GarbageCollected<PendingAbortRequest> {
 public:
  PendingAbortRequest(v8::Isolate* isolate,
                      ScriptPromiseResolver<IDLUndefined>* resolver,
                      v8::Local<v8::Value> reason,
                      bool was_already_erroring)
      : resolver_(resolver),
        reason_(isolate, reason),
        was_already_erroring_(was_already_erroring) {}
  PendingAbortRequest(const PendingAbortRequest&) = delete;
  PendingAbortRequest& operator=(const PendingAbortRequest&) = delete;

  ScriptPromiseResolver<IDLUndefined>* GetResolver() { return resolver_.Get(); }
  v8::Local<v8::Value> Reason(v8::Isolate* isolate) {
    return reason_.Get(isolate);
  }

  bool WasAlreadyErroring() { return was_already_erroring_; }

  void Trace(Visitor* visitor) const {
    visitor->Trace(resolver_);
    visitor->Trace(reason_);
  }

 private:
  Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  TraceWrapperV8Reference<v8::Value> reason_;
  const bool was_already_erroring_;
};

WritableStream* WritableStream::Create(ScriptState* script_state,
                                       ExceptionState& exception_state) {
  return Create(script_state,
                ScriptValue(script_state->GetIsolate(),
                            v8::Undefined(script_state->GetIsolate())),
                ScriptValue(script_state->GetIsolate(),
                            v8::Undefined(script_state->GetIsolate())),
                exception_state);
}

WritableStream* WritableStream::Create(ScriptState* script_state,
                                       ScriptValue underlying_sink,
                                       ExceptionState& exception_state) {
  return Create(script_state, underlying_sink,
                ScriptValue(script_state->GetIsolate(),
                            v8::Undefined(script_state->GetIsolate())),
                exception_state);
}

WritableStream* WritableStream::Create(ScriptState* script_state,
                                       ScriptValue raw_underlying_sink,
                                       ScriptValue raw_strategy,
                                       ExceptionState& exception_state) {
  auto* stream = MakeGarbageCollected<WritableStream>();
  stream->InitInternal(script_state, raw_underlying_sink, raw_strategy,
                       exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return stream;
}

WritableStream::WritableStream() = default;
WritableStream::~WritableStream() = default;

ScriptPromise<IDLUndefined> WritableStream::abort(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  return abort(script_state,
               ScriptValue(script_state->GetIsolate(),
                           v8::Undefined(script_state->GetIsolate())),
               exception_state);
}

ScriptPromise<IDLUndefined> WritableStream::abort(
    ScriptState* script_state,
    ScriptValue reason,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#ws-abort
  //  2. If ! IsWritableStreamLocked(this) is true, return a promise rejected
  //     with a TypeError exception.
  if (IsLocked(this)) {
    exception_state.ThrowTypeError("Cannot abort a locked stream");
    return EmptyPromise();
  }

  //  3. Return ! WritableStreamAbort(this, reason).
  return Abort(script_state, this, reason.V8Value());
}

ScriptPromise<IDLUndefined> WritableStream::close(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#ws-close
  // 2. If ! IsWritableStreamLocked(this) is true, return a promise rejected
  // with a TypeError exception.
  if (IsLocked(this)) {
    exception_state.ThrowTypeError("Cannot close a locked stream");
    return EmptyPromise();
  }

  // 3. If ! WritableStreamCloseQueuedOrInFlight(this) is true, return a promise
  // rejected with a TypeError exception.
  if (CloseQueuedOrInFlight(this)) {
    exception_state.ThrowTypeError("Cannot close a closed or closing stream");
    return EmptyPromise();
  }

  if (!script_state->ContextIsValid()) {
    exception_state.ThrowTypeError("invalid realm");
    return EmptyPromise();
  }

  return Close(script_state, this);
}

WritableStreamDefaultWriter* WritableStream::getWriter(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#ws-get-writer
  //  2. Return ? AcquireWritableStreamDefaultWriter(this).

  auto* writer = AcquireDefaultWriter(script_state, this, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return writer;
}

// General Writable Stream Abstract Operations

WritableStream* WritableStream::Create(ScriptState* script_state,
                                       StreamStartAlgorithm* start_algorithm,
                                       StreamAlgorithm* write_algorithm,
                                       StreamAlgorithm* close_algorithm,
                                       StreamAlgorithm* abort_algorithm,
                                       double high_water_mark,
                                       StrategySizeAlgorithm* size_algorithm,
                                       ExceptionState& exception_state) {
  DCHECK(size_algorithm);

  // https://streams.spec.whatwg.org/#create-writable-stream
  //  3. Assert: ! IsNonNegativeNumber(highWaterMark) is true.
  DCHECK_GE(high_water_mark, 0);

  //  4. Let stream be ObjectCreate(the original value of WritableStream's
  //     prototype property).
  //  5. Perform ! InitializeWritableStream(stream).
  auto* stream = MakeGarbageCollected<WritableStream>();

  //  6. Let controller be ObjectCreate(the original value of
  //     WritableStreamDefaultController's prototype property).
  auto* controller = MakeGarbageCollected<WritableStreamDefaultController>();

  //  7. Perform ? SetUpWritableStreamDefaultController(stream, controller,
  //     startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm,
  //     highWaterMark, sizeAlgorithm).
  WritableStreamDefaultController::SetUp(
      script_state, stream, controller, start_algorithm, write_algorithm,
      close_algorithm, abort_algorithm, high_water_mark, size_algorithm,
      exception_state);

  //  8. Return stream.
  return stream;
}

// static
WritableStream* WritableStream::CreateWithCountQueueingStrategy(
    ScriptState* script_state,
    UnderlyingSinkBase* underlying_sink,
    size_t high_water_mark) {
  return CreateWithCountQueueingStrategy(script_state, underlying_sink,
                                         high_water_mark,
                                         /*optimizer=*/nullptr);
}

WritableStream* WritableStream::CreateWithCountQueueingStrategy(
    ScriptState* script_state,
    UnderlyingSinkBase* underlying_sink,
    size_t high_water_mark,
    std::unique_ptr<WritableStreamTransferringOptimizer> optimizer) {
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  auto* stream = MakeGarbageCollected<WritableStream>();
  stream->InitWithCountQueueingStrategy(script_state, underlying_sink,
                                        high_water_mark, std::move(optimizer),
                                        PassThroughException(isolate));
  if (isolate->HasPendingException()) {
    return nullptr;
  }

  return stream;
}

void WritableStream::InitWithCountQueueingStrategy(
    ScriptState* script_state,
    UnderlyingSinkBase* underlying_sink,
    size_t high_water_mark,
    std::unique_ptr<WritableStreamTransferringOptimizer> optimizer,
    ExceptionState& exception_state) {
  ScriptValue strategy_value =
      CreateTrivialQueuingStrategy(script_state->GetIsolate(), high_water_mark);

  auto underlying_sink_value = ScriptValue::From(script_state, underlying_sink);

  // TODO(crbug.com/902633): This method of constructing a WritableStream
  // introduces unnecessary trips through V8. Implement algorithms based on an
  // UnderlyingSinkBase.
  InitInternal(script_state, underlying_sink_value, strategy_value,
               exception_state);

  transferring_optimizer_ = std::move(optimizer);
}

void WritableStream::Serialize(ScriptState* script_state,
                               MessagePort* port,
                               ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#ws-transfer
  // 1. If ! IsWritableStreamLocked(value) is true, throw a "DataCloneError"
  //    DOMException.
  if (IsLocked(this)) {
    exception_state.ThrowTypeError("Cannot transfer a locked stream");
    return;
  }

  // Done by SerializedScriptValue::TransferWritableStream():
  // 2. Let port1 be a new MessagePort in the current Realm.
  // 3. Let port2 be a new MessagePort in the current Realm.
  // 4. Entangle port1 and port2.

  // 5. Let readable be a new ReadableStream in the current Realm.
  // 6. Perform ! SetUpCrossRealmTransformReadable(readable, port1).
  auto* readable = CreateCrossRealmTransformReadable(
      script_state, port, /*optimizer=*/nullptr, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 7. Let promise be ! ReadableStreamPipeTo(readable, value, false, false,
  //    false).
  auto promise = ReadableStream::PipeTo(script_state, readable, this,
                                        MakeGarbageCollected<PipeOptions>(),
                                        exception_state);

  // 8. Set promise.[[PromiseIsHandled]] to true.
  promise.MarkAsHandled();

  // This step is done in a roundabout way by the caller:
  // 9. Set dataHolder.[[port]] to ! StructuredSerializeWithTransfer(port2, «
  //    port2 »).
}

WritableStream* WritableStream::Deserialize(
    ScriptState* script_state,
    MessagePort* port,
    std::unique_ptr<WritableStreamTransferringOptimizer> optimizer,
    ExceptionState& exception_state) {
  // We need to execute JavaScript to call "Then" on v8::Promises. We will not
  // run author code.
  v8::Isolate::AllowJavascriptExecutionScope allow_js(
      script_state->GetIsolate());

  // https://streams.spec.whatwg.org/#ws-transfer
  // These step is done by V8ScriptValueDeserializer::ReadDOMObject().
  // 1. Let deserializedRecord be !
  //    StructuredDeserializeWithTransfer(dataHolder.[[port]], the current
  //    Realm).
  // 2. Let port be deserializedRecord.[[Deserialized]].

  // 3. Perform ! SetUpCrossRealmTransformWritable(value, port).
  // In the standard |value| contains an unitialized WritableStream. In the
  // implementation, we create the stream here.
  auto* writable = CreateCrossRealmTransformWritable(
      script_state, port, AllowPerChunkTransferring(false),
      std::move(optimizer), exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return writable;
}

WritableStreamDefaultWriter* WritableStream::AcquireDefaultWriter(
    ScriptState* script_state,
    WritableStream* stream,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#acquire-writable-stream-default-writer
  //  1. Return ? Construct(WritableStreamDefaultWriter, « stream »).
  auto* writer = MakeGarbageCollected<WritableStreamDefaultWriter>(
      script_state, stream, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return writer;
}

ScriptPromise<IDLUndefined> WritableStream::Abort(ScriptState* script_state,
                                                  WritableStream* stream,
                                                  v8::Local<v8::Value> reason) {
  // https://streams.spec.whatwg.org/#writable-stream-abort
  //  1. If stream.[[state]] is "closed" or "errored", return a promise resolved
  //     with undefined.
  if (stream->state_ == kClosed || stream->state_ == kErrored) {
    return ToResolvedUndefinedPromise(script_state);
  }

  //  2. Signal abort on stream.[[controller]].[[abortController]] with reason.
  auto* isolate = script_state->GetIsolate();
  stream->Controller()->Abort(script_state, ScriptValue(isolate, reason));

  //  3. Let state be stream.[[state]].
  const auto state = stream->state_;

  //  4. If state is "closed" or "errored", return a promise resolved with
  //     undefined.
  if (state == kClosed || state == kErrored) {
    return ToResolvedUndefinedPromise(script_state);
  }

  //  5. If stream.[[pendingAbortRequest]] is not undefined, return
  //     stream.[[pendingAbortRequest]]'s promise.
  if (stream->pending_abort_request_) {
    return stream->pending_abort_request_->GetResolver()->Promise();
  }

  //  6. Assert: state is "writable" or "erroring".
  CHECK(state == kWritable || state == kErroring);

  //  7. Let wasAlreadyErroring be false.
  //  8. If state is "erroring",
  //      a. Set wasAlreadyErroring to true.
  //      b. Set reason to undefined.
  const bool was_already_erroring = state == kErroring;
  if (was_already_erroring) {
    reason = v8::Undefined(isolate);
  }

  //  9. Let promise be a new promise.
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  // 10. Set stream.[[pendingAbortRequest]] to a new pending abort request
  //     whose promise is promise, reason is reason, and was already erroring is
  //     wasAlreadyErroring.
  stream->pending_abort_request_ = MakeGarbageCollected<PendingAbortRequest>(
      isolate, resolver, reason, was_already_erroring);

  // 11. If wasAlreadyErroring is false, perform ! WritableStreamStartErroring(
  //     stream, reason).
  if (!was_already_erroring) {
    StartErroring(script_state, stream, reason);
  }

  // 12. Return promise.
  return resolver->Promise();
}

// Writable Stream Abstract Operations Used by Controllers

void WritableStream::AddWriteRequest(
    WritableStream* stream,
    ScriptPromiseResolver<IDLUndefined>* resolver) {
  // https://streams.spec.whatwg.org/#writable-stream-add-write-request
  //  1. Assert: ! IsWritableStreamLocked(stream) is true.
  DCHECK(IsLocked(stream));

  //  2. Assert: stream.[[state]] is "writable".
  CHECK_EQ(stream->state_, kWritable);

  //  3. Let promise be a new promise.
  //  4. Append promise as the last element of stream.[[writeRequests]]
  //  5. Return promise.
  stream->write_requests_.push_back(resolver);
}

ScriptPromise<IDLUndefined> WritableStream::Close(ScriptState* script_state,
                                                  WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-close
  //  1. Let state be stream.[[state]].
  const auto state = stream->GetState();

  //  2. If state is "closed" or "errored", return a promise rejected with a
  //     TypeError exception.
  if (state == kClosed || state == kErrored) {
    return ScriptPromise<IDLUndefined>::Reject(
        script_state, CreateCannotActionOnStateStreamException(
                          script_state->GetIsolate(), "close", state));
  }

  //  3. Assert: state is "writable" or "erroring".
  CHECK(state == kWritable || state == kErroring);

  //  4. Assert: ! WritableStreamCloseQueuedOrInFlight(stream) is false.
  CHECK(!CloseQueuedOrInFlight(stream));

  //  5. Let promise be a new promise.
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  //  6. Set stream.[[closeRequest]] to promise.
  stream->SetCloseRequest(resolver);

  //  7. Let writer be stream.[[writer]].
  WritableStreamDefaultWriter* writer = stream->writer_;

  //  8. If writer is not undefined, and stream.[[backpressure]] is true, and
  //  state is "writable", resolve writer.[[readyPromise]] with undefined.
  if (writer && stream->HasBackpressure() && state == kWritable) {
    writer->ReadyResolver()->Resolve();
  }

  //  9. Perform ! WritableStreamDefaultControllerClose(
  //     stream.[[writableStreamController]]).
  WritableStreamDefaultController::Close(script_state, stream->Controller());

  // 10. Return promise.
  return resolver->Promise();
}

bool WritableStream::CloseQueuedOrInFlight(const WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-close-queued-or-in-flight
  //  1. If stream.[[closeRequest]] is undefined and
  //     stream.[[inFlightCloseRequest]] is undefined, return false.
  //  2. Return true.
  return stream->close_request_ || stream->in_flight_close_request_;
}

void WritableStream::DealWithRejection(ScriptState* script_state,
                                       WritableStream* stream,
                                       v8::Local<v8::Value> error) {
  // https://streams.spec.whatwg.org/#writable-stream-deal-with-rejection
  //  1. Let state be stream.[[state]].
  const auto state = stream->state_;

  //  2. If state is "writable",
  if (state == kWritable) {
    //      a. Perform ! WritableStreamStartErroring(stream, error).
    StartErroring(script_state, stream, error);

    //      b. Return.
    return;
  }

  //  3. Assert: state is "erroring".
  CHECK_EQ(state, kErroring);

  //  4. Perform ! WritableStreamFinishErroring(stream).
  FinishErroring(script_state, stream);
}

void WritableStream::StartErroring(ScriptState* script_state,
                                   WritableStream* stream,
                                   v8::Local<v8::Value> reason) {
  // https://streams.spec.whatwg.org/#writable-stream-start-erroring
  //  1. Assert: stream.[[storedError]] is undefined.
  DCHECK(stream->stored_error_.IsEmpty());

  //  2. Assert: stream.[[state]] is "writable".
  CHECK_EQ(stream->state_, kWritable);

  //  3. Let controller be stream.[[writableStreamController]].
  WritableStreamDefaultController* controller =
      stream->writable_stream_controller_;

  //  4. Assert: controller is not undefined.
  DCHECK(controller);

  //  5. Set stream.[[state]] to "erroring".
  stream->state_ = kErroring;

  //  6. Set stream.[[storedError]] to reason.
  stream->stored_error_.Reset(script_state->GetIsolate(), reason);

  //  7. Let writer be stream.[[writer]].
  WritableStreamDefaultWriter* writer = stream->writer_;

  //  8. If writer is not undefined, perform !
  //     WritableStreamDefaultWriterEnsureReadyPromiseRejected(writer, reason).
  if (writer) {
    WritableStreamDefaultWriter::EnsureReadyPromiseRejected(script_state,
                                                            writer, reason);
  }

  //  9. If ! WritableStreamHasOperationMarkedInFlight(stream) is false and
  //     controller.[[started]] is true, perform !
  //     WritableStreamFinishErroring(stream).
  if (!HasOperationMarkedInFlight(stream) && controller->Started()) {
    FinishErroring(script_state, stream);
  }
}

void WritableStream::FinishErroring(ScriptState* script_state,
                                    WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-finish-erroring
  //  1. Assert: stream.[[state]] is "erroring".
  CHECK_EQ(stream->state_, kErroring);

  //  2. Assert: ! WritableStreamHasOperationMarkedInFlight(stream) is false.
  DCHECK(!HasOperationMarkedInFlight(stream));

  //  3. Set stream.[[state]] to "errored".
  stream->state_ = kErrored;

  //  4. Perform ! stream.[[writableStreamController]].[[ErrorSteps]]().
  stream->writable_stream_controller_->ErrorSteps();

  //  5. Let storedError be stream.[[storedError]].
  auto* isolate = script_state->GetIsolate();
  const auto stored_error = stream->stored_error_.Get(isolate);

  //  6. Repeat for each writeRequest that is an element of
  //     stream.[[writeRequests]],
  //      a. Reject writeRequest with storedError.
  RejectPromises(script_state, &stream->write_requests_, stored_error);

  //  7. Set stream.[[writeRequests]] to an empty List.
  stream->write_requests_.clear();

  //  8. If stream.[[pendingAbortRequest]] is undefined,
  if (!stream->pending_abort_request_) {
    //      a. Perform !
    //         WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream).
    RejectCloseAndClosedPromiseIfNeeded(script_state, stream);

    //      b. Return.
    return;
  }

  //  9. Let abortRequest be stream.[[pendingAbortRequest]].
  auto* abort_request = stream->pending_abort_request_.Get();

  // 10. Set stream.[[pendingAbortRequest]] to undefined.
  stream->pending_abort_request_ = nullptr;

  // 11. If abortRequest.[[wasAlreadyErroring]] is true,
  if (abort_request->WasAlreadyErroring()) {
    //      a. Reject abortRequest.[[promise]] with storedError.
    abort_request->GetResolver()->Reject(stored_error);

    //      b. Perform !
    //         WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream)
    RejectCloseAndClosedPromiseIfNeeded(script_state, stream);

    //      c. Return.
    return;
  }

  // 12. Let promise be ! stream.[[writableStreamController]].[[AbortSteps]](
  //     abortRequest.[[reason]]).
  auto promise = stream->writable_stream_controller_->AbortSteps(
      script_state, abort_request->Reason(isolate));

  class ResolvePromiseFunction final
      : public ThenCallable<IDLUndefined, ResolvePromiseFunction> {
   public:
    ResolvePromiseFunction(WritableStream* stream,
                           ScriptPromiseResolver<IDLUndefined>* resolver)
        : stream_(stream), resolver_(resolver) {}

    void React(ScriptState* script_state) {
      // 13. Upon fulfillment of promise,
      //      a. Resolve abortRequest.[[promise]] with undefined.
      resolver_->Resolve();

      //      b. Perform !
      //         WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream).
      RejectCloseAndClosedPromiseIfNeeded(script_state, stream_);
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(stream_);
      visitor->Trace(resolver_);
      ThenCallable<IDLUndefined, ResolvePromiseFunction>::Trace(visitor);
    }

   private:
    Member<WritableStream> stream_;
    Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  };

  class RejectPromiseFunction final
      : public ThenCallable<IDLAny, RejectPromiseFunction> {
   public:
    RejectPromiseFunction(WritableStream* stream,
                          ScriptPromiseResolver<IDLUndefined>* resolver)
        : stream_(stream), resolver_(resolver) {}

    void React(ScriptState* script_state, ScriptValue reason) {
      // 14. Upon rejection of promise with reason reason,
      //      a. Reject abortRequest.[[promise]] with reason.
      resolver_->Reject(reason);

      //      b. Perform !
      //         WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream).
      RejectCloseAndClosedPromiseIfNeeded(script_state, stream_);
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(stream_);
      visitor->Trace(resolver_);
      ThenCallable<IDLAny, RejectPromiseFunction>::Trace(visitor);
    }

   private:
    Member<WritableStream> stream_;
    Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  };

  promise.Then(script_state,
               MakeGarbageCollected<ResolvePromiseFunction>(
                   stream, abort_request->GetResolver()),
               MakeGarbageCollected<RejectPromiseFunction>(
                   stream, abort_request->GetResolver()));
}
```

## 功能归纳 (第1部分)

`blink/renderer/core/streams/writable_stream.cc` 文件的主要功能是**实现了 Web Streams API 中的 `WritableStream` 接口**。这个接口允许 JavaScript 代码向一个目标（"sink"）写入数据。

**具体功能点包括：**

1. **`WritableStream` 对象的创建和初始化:**
   - 提供了多种静态 `Create` 方法，允许基于不同的参数创建 `WritableStream` 对象，例如：
     - 不带任何参数的简单创建。
     - 使用用户自定义的 underlying sink 对象。
     - 使用 underlying sink 和 queuing strategy 对象。
     - 基于更底层的算法（start, write, close, abort）。
   - `InitInternal` 方法用于执行通用的初始化流程。
   - `InitWithCountQueueingStrategy` 方法使用简单的计数策略初始化流。

2. **处理流的 `abort` 操作:**
   - `abort(ScriptState*, ExceptionState&)` 和 `abort(ScriptState*, ScriptValue, ExceptionState&)` 方法对应 JavaScript 中调用 `writableStream.abort(reason)`。
   - 检查流是否已被锁定，如果锁定则抛出 `TypeError` 异常。
   - 调用内部的 `Abort` 抽象操作来执行中止逻辑。
   - 涉及到 `PendingAbortRequest` 类的使用，用于管理待处理的中止请求及其相关的 promise 和原因。

3. **处理流的 `close` 操作:**
   - `close(ScriptState*, ExceptionState&)` 方法对应 JavaScript 中调用 `writableStream.close()`。
   - 检查流是否已被锁定或已经处于关闭/正在关闭的状态，如果是则抛出 `TypeError` 异常。
   - 调用内部的 `Close` 抽象操作来执行关闭逻辑。

4. **获取 `WritableStreamDefaultWriter` 对象:**
   - `getWriter(ScriptState*, ExceptionState&)` 方法对应 JavaScript 中调用 `writableStream.getWriter()`。
   - 调用内部的 `AcquireDefaultWriter` 抽象操作来创建和获取默认的 writer。

5. **实现 `WritableStream` 相关的抽象操作 (按照 Streams 标准组织):**
   - `Create(ScriptState*, StreamStartAlgorithm*, ...)`:  更底层的创建方法。
   - `CreateWithCountQueueingStrategy`:  使用计数策略创建流。
   - `Abort(ScriptState*, WritableStream*, v8::Local<v8::Value>)`:  执行中止操作的核心逻辑，处理流的不同状态，管理 `PendingAbortRequest`。
   - `Close(ScriptState*, WritableStream*)`: 执行关闭操作的核心逻辑，管理关闭请求。
   - `CloseQueuedOrInFlight`: 检查是否有待处理或正在处理的关闭请求。
   - `AddWriteRequest`:  向流中添加写请求 (与 controller 交互)。

Prompt: 
```
这是目录为blink/renderer/core/streams/writable_stream.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/writable_stream.h"

#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_queuing_strategy_init.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/streams/count_queuing_strategy.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/pipe_options.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/core/streams/transferable_streams.h"
#include "third_party/blink/renderer/core/streams/underlying_sink_base.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/streams/writable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"

// Implementation of WritableStream for Blink.  See
// https://streams.spec.whatwg.org/#ws. The implementation closely follows the
// standard, except where required for performance or integration with Blink.
// In particular, classes, methods and abstract operations are implemented in
// the same order as in the standard, to simplify side-by-side reading.

namespace blink {

// The PendingAbortRequest type corresponds to the Record {[[promise]],
// [[reason]], [[wasAlreadyErroring]]} from the standard.
class WritableStream::PendingAbortRequest final
    : public GarbageCollected<PendingAbortRequest> {
 public:
  PendingAbortRequest(v8::Isolate* isolate,
                      ScriptPromiseResolver<IDLUndefined>* resolver,
                      v8::Local<v8::Value> reason,
                      bool was_already_erroring)
      : resolver_(resolver),
        reason_(isolate, reason),
        was_already_erroring_(was_already_erroring) {}
  PendingAbortRequest(const PendingAbortRequest&) = delete;
  PendingAbortRequest& operator=(const PendingAbortRequest&) = delete;

  ScriptPromiseResolver<IDLUndefined>* GetResolver() { return resolver_.Get(); }
  v8::Local<v8::Value> Reason(v8::Isolate* isolate) {
    return reason_.Get(isolate);
  }

  bool WasAlreadyErroring() { return was_already_erroring_; }

  void Trace(Visitor* visitor) const {
    visitor->Trace(resolver_);
    visitor->Trace(reason_);
  }

 private:
  Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  TraceWrapperV8Reference<v8::Value> reason_;
  const bool was_already_erroring_;
};

WritableStream* WritableStream::Create(ScriptState* script_state,
                                       ExceptionState& exception_state) {
  return Create(script_state,
                ScriptValue(script_state->GetIsolate(),
                            v8::Undefined(script_state->GetIsolate())),
                ScriptValue(script_state->GetIsolate(),
                            v8::Undefined(script_state->GetIsolate())),
                exception_state);
}

WritableStream* WritableStream::Create(ScriptState* script_state,
                                       ScriptValue underlying_sink,
                                       ExceptionState& exception_state) {
  return Create(script_state, underlying_sink,
                ScriptValue(script_state->GetIsolate(),
                            v8::Undefined(script_state->GetIsolate())),
                exception_state);
}

WritableStream* WritableStream::Create(ScriptState* script_state,
                                       ScriptValue raw_underlying_sink,
                                       ScriptValue raw_strategy,
                                       ExceptionState& exception_state) {
  auto* stream = MakeGarbageCollected<WritableStream>();
  stream->InitInternal(script_state, raw_underlying_sink, raw_strategy,
                       exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return stream;
}

WritableStream::WritableStream() = default;
WritableStream::~WritableStream() = default;

ScriptPromise<IDLUndefined> WritableStream::abort(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  return abort(script_state,
               ScriptValue(script_state->GetIsolate(),
                           v8::Undefined(script_state->GetIsolate())),
               exception_state);
}

ScriptPromise<IDLUndefined> WritableStream::abort(
    ScriptState* script_state,
    ScriptValue reason,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#ws-abort
  //  2. If ! IsWritableStreamLocked(this) is true, return a promise rejected
  //     with a TypeError exception.
  if (IsLocked(this)) {
    exception_state.ThrowTypeError("Cannot abort a locked stream");
    return EmptyPromise();
  }

  //  3. Return ! WritableStreamAbort(this, reason).
  return Abort(script_state, this, reason.V8Value());
}

ScriptPromise<IDLUndefined> WritableStream::close(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#ws-close
  // 2. If ! IsWritableStreamLocked(this) is true, return a promise rejected
  // with a TypeError exception.
  if (IsLocked(this)) {
    exception_state.ThrowTypeError("Cannot close a locked stream");
    return EmptyPromise();
  }

  // 3. If ! WritableStreamCloseQueuedOrInFlight(this) is true, return a promise
  // rejected with a TypeError exception.
  if (CloseQueuedOrInFlight(this)) {
    exception_state.ThrowTypeError("Cannot close a closed or closing stream");
    return EmptyPromise();
  }

  if (!script_state->ContextIsValid()) {
    exception_state.ThrowTypeError("invalid realm");
    return EmptyPromise();
  }

  return Close(script_state, this);
}

WritableStreamDefaultWriter* WritableStream::getWriter(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#ws-get-writer
  //  2. Return ? AcquireWritableStreamDefaultWriter(this).

  auto* writer = AcquireDefaultWriter(script_state, this, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return writer;
}

// General Writable Stream Abstract Operations

WritableStream* WritableStream::Create(ScriptState* script_state,
                                       StreamStartAlgorithm* start_algorithm,
                                       StreamAlgorithm* write_algorithm,
                                       StreamAlgorithm* close_algorithm,
                                       StreamAlgorithm* abort_algorithm,
                                       double high_water_mark,
                                       StrategySizeAlgorithm* size_algorithm,
                                       ExceptionState& exception_state) {
  DCHECK(size_algorithm);

  // https://streams.spec.whatwg.org/#create-writable-stream
  //  3. Assert: ! IsNonNegativeNumber(highWaterMark) is true.
  DCHECK_GE(high_water_mark, 0);

  //  4. Let stream be ObjectCreate(the original value of WritableStream's
  //     prototype property).
  //  5. Perform ! InitializeWritableStream(stream).
  auto* stream = MakeGarbageCollected<WritableStream>();

  //  6. Let controller be ObjectCreate(the original value of
  //     WritableStreamDefaultController's prototype property).
  auto* controller = MakeGarbageCollected<WritableStreamDefaultController>();

  //  7. Perform ? SetUpWritableStreamDefaultController(stream, controller,
  //     startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm,
  //     highWaterMark, sizeAlgorithm).
  WritableStreamDefaultController::SetUp(
      script_state, stream, controller, start_algorithm, write_algorithm,
      close_algorithm, abort_algorithm, high_water_mark, size_algorithm,
      exception_state);

  //  8. Return stream.
  return stream;
}

// static
WritableStream* WritableStream::CreateWithCountQueueingStrategy(
    ScriptState* script_state,
    UnderlyingSinkBase* underlying_sink,
    size_t high_water_mark) {
  return CreateWithCountQueueingStrategy(script_state, underlying_sink,
                                         high_water_mark,
                                         /*optimizer=*/nullptr);
}

WritableStream* WritableStream::CreateWithCountQueueingStrategy(
    ScriptState* script_state,
    UnderlyingSinkBase* underlying_sink,
    size_t high_water_mark,
    std::unique_ptr<WritableStreamTransferringOptimizer> optimizer) {
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  auto* stream = MakeGarbageCollected<WritableStream>();
  stream->InitWithCountQueueingStrategy(script_state, underlying_sink,
                                        high_water_mark, std::move(optimizer),
                                        PassThroughException(isolate));
  if (isolate->HasPendingException()) {
    return nullptr;
  }

  return stream;
}

void WritableStream::InitWithCountQueueingStrategy(
    ScriptState* script_state,
    UnderlyingSinkBase* underlying_sink,
    size_t high_water_mark,
    std::unique_ptr<WritableStreamTransferringOptimizer> optimizer,
    ExceptionState& exception_state) {
  ScriptValue strategy_value =
      CreateTrivialQueuingStrategy(script_state->GetIsolate(), high_water_mark);

  auto underlying_sink_value = ScriptValue::From(script_state, underlying_sink);

  // TODO(crbug.com/902633): This method of constructing a WritableStream
  // introduces unnecessary trips through V8. Implement algorithms based on an
  // UnderlyingSinkBase.
  InitInternal(script_state, underlying_sink_value, strategy_value,
               exception_state);

  transferring_optimizer_ = std::move(optimizer);
}

void WritableStream::Serialize(ScriptState* script_state,
                               MessagePort* port,
                               ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#ws-transfer
  // 1. If ! IsWritableStreamLocked(value) is true, throw a "DataCloneError"
  //    DOMException.
  if (IsLocked(this)) {
    exception_state.ThrowTypeError("Cannot transfer a locked stream");
    return;
  }

  // Done by SerializedScriptValue::TransferWritableStream():
  // 2. Let port1 be a new MessagePort in the current Realm.
  // 3. Let port2 be a new MessagePort in the current Realm.
  // 4. Entangle port1 and port2.

  // 5. Let readable be a new ReadableStream in the current Realm.
  // 6. Perform ! SetUpCrossRealmTransformReadable(readable, port1).
  auto* readable = CreateCrossRealmTransformReadable(
      script_state, port, /*optimizer=*/nullptr, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 7. Let promise be ! ReadableStreamPipeTo(readable, value, false, false,
  //    false).
  auto promise = ReadableStream::PipeTo(script_state, readable, this,
                                        MakeGarbageCollected<PipeOptions>(),
                                        exception_state);

  // 8. Set promise.[[PromiseIsHandled]] to true.
  promise.MarkAsHandled();

  // This step is done in a roundabout way by the caller:
  // 9. Set dataHolder.[[port]] to ! StructuredSerializeWithTransfer(port2, «
  //    port2 »).
}

WritableStream* WritableStream::Deserialize(
    ScriptState* script_state,
    MessagePort* port,
    std::unique_ptr<WritableStreamTransferringOptimizer> optimizer,
    ExceptionState& exception_state) {
  // We need to execute JavaScript to call "Then" on v8::Promises. We will not
  // run author code.
  v8::Isolate::AllowJavascriptExecutionScope allow_js(
      script_state->GetIsolate());

  // https://streams.spec.whatwg.org/#ws-transfer
  // These step is done by V8ScriptValueDeserializer::ReadDOMObject().
  // 1. Let deserializedRecord be !
  //    StructuredDeserializeWithTransfer(dataHolder.[[port]], the current
  //    Realm).
  // 2. Let port be deserializedRecord.[[Deserialized]].

  // 3. Perform ! SetUpCrossRealmTransformWritable(value, port).
  // In the standard |value| contains an unitialized WritableStream. In the
  // implementation, we create the stream here.
  auto* writable = CreateCrossRealmTransformWritable(
      script_state, port, AllowPerChunkTransferring(false),
      std::move(optimizer), exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return writable;
}

WritableStreamDefaultWriter* WritableStream::AcquireDefaultWriter(
    ScriptState* script_state,
    WritableStream* stream,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#acquire-writable-stream-default-writer
  //  1. Return ? Construct(WritableStreamDefaultWriter, « stream »).
  auto* writer = MakeGarbageCollected<WritableStreamDefaultWriter>(
      script_state, stream, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return writer;
}

ScriptPromise<IDLUndefined> WritableStream::Abort(ScriptState* script_state,
                                                  WritableStream* stream,
                                                  v8::Local<v8::Value> reason) {
  // https://streams.spec.whatwg.org/#writable-stream-abort
  //  1. If stream.[[state]] is "closed" or "errored", return a promise resolved
  //     with undefined.
  if (stream->state_ == kClosed || stream->state_ == kErrored) {
    return ToResolvedUndefinedPromise(script_state);
  }

  //  2. Signal abort on stream.[[controller]].[[abortController]] with reason.
  auto* isolate = script_state->GetIsolate();
  stream->Controller()->Abort(script_state, ScriptValue(isolate, reason));

  //  3. Let state be stream.[[state]].
  const auto state = stream->state_;

  //  4. If state is "closed" or "errored", return a promise resolved with
  //     undefined.
  if (state == kClosed || state == kErrored) {
    return ToResolvedUndefinedPromise(script_state);
  }

  //  5. If stream.[[pendingAbortRequest]] is not undefined, return
  //     stream.[[pendingAbortRequest]]'s promise.
  if (stream->pending_abort_request_) {
    return stream->pending_abort_request_->GetResolver()->Promise();
  }

  //  6. Assert: state is "writable" or "erroring".
  CHECK(state == kWritable || state == kErroring);

  //  7. Let wasAlreadyErroring be false.
  //  8. If state is "erroring",
  //      a. Set wasAlreadyErroring to true.
  //      b. Set reason to undefined.
  const bool was_already_erroring = state == kErroring;
  if (was_already_erroring) {
    reason = v8::Undefined(isolate);
  }

  //  9. Let promise be a new promise.
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  // 10. Set stream.[[pendingAbortRequest]] to a new pending abort request
  //     whose promise is promise, reason is reason, and was already erroring is
  //     wasAlreadyErroring.
  stream->pending_abort_request_ = MakeGarbageCollected<PendingAbortRequest>(
      isolate, resolver, reason, was_already_erroring);

  // 11. If wasAlreadyErroring is false, perform ! WritableStreamStartErroring(
  //     stream, reason).
  if (!was_already_erroring) {
    StartErroring(script_state, stream, reason);
  }

  // 12. Return promise.
  return resolver->Promise();
}

// Writable Stream Abstract Operations Used by Controllers

void WritableStream::AddWriteRequest(
    WritableStream* stream,
    ScriptPromiseResolver<IDLUndefined>* resolver) {
  // https://streams.spec.whatwg.org/#writable-stream-add-write-request
  //  1. Assert: ! IsWritableStreamLocked(stream) is true.
  DCHECK(IsLocked(stream));

  //  2. Assert: stream.[[state]] is "writable".
  CHECK_EQ(stream->state_, kWritable);

  //  3. Let promise be a new promise.
  //  4. Append promise as the last element of stream.[[writeRequests]]
  //  5. Return promise.
  stream->write_requests_.push_back(resolver);
}

ScriptPromise<IDLUndefined> WritableStream::Close(ScriptState* script_state,
                                                  WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-close
  //  1. Let state be stream.[[state]].
  const auto state = stream->GetState();

  //  2. If state is "closed" or "errored", return a promise rejected with a
  //     TypeError exception.
  if (state == kClosed || state == kErrored) {
    return ScriptPromise<IDLUndefined>::Reject(
        script_state, CreateCannotActionOnStateStreamException(
                          script_state->GetIsolate(), "close", state));
  }

  //  3. Assert: state is "writable" or "erroring".
  CHECK(state == kWritable || state == kErroring);

  //  4. Assert: ! WritableStreamCloseQueuedOrInFlight(stream) is false.
  CHECK(!CloseQueuedOrInFlight(stream));

  //  5. Let promise be a new promise.
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  //  6. Set stream.[[closeRequest]] to promise.
  stream->SetCloseRequest(resolver);

  //  7. Let writer be stream.[[writer]].
  WritableStreamDefaultWriter* writer = stream->writer_;

  //  8. If writer is not undefined, and stream.[[backpressure]] is true, and
  //  state is "writable", resolve writer.[[readyPromise]] with undefined.
  if (writer && stream->HasBackpressure() && state == kWritable) {
    writer->ReadyResolver()->Resolve();
  }

  //  9. Perform ! WritableStreamDefaultControllerClose(
  //     stream.[[writableStreamController]]).
  WritableStreamDefaultController::Close(script_state, stream->Controller());

  // 10. Return promise.
  return resolver->Promise();
}

bool WritableStream::CloseQueuedOrInFlight(const WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-close-queued-or-in-flight
  //  1. If stream.[[closeRequest]] is undefined and
  //     stream.[[inFlightCloseRequest]] is undefined, return false.
  //  2. Return true.
  return stream->close_request_ || stream->in_flight_close_request_;
}

void WritableStream::DealWithRejection(ScriptState* script_state,
                                       WritableStream* stream,
                                       v8::Local<v8::Value> error) {
  // https://streams.spec.whatwg.org/#writable-stream-deal-with-rejection
  //  1. Let state be stream.[[state]].
  const auto state = stream->state_;

  //  2. If state is "writable",
  if (state == kWritable) {
    //      a. Perform ! WritableStreamStartErroring(stream, error).
    StartErroring(script_state, stream, error);

    //      b. Return.
    return;
  }

  //  3. Assert: state is "erroring".
  CHECK_EQ(state, kErroring);

  //  4. Perform ! WritableStreamFinishErroring(stream).
  FinishErroring(script_state, stream);
}

void WritableStream::StartErroring(ScriptState* script_state,
                                   WritableStream* stream,
                                   v8::Local<v8::Value> reason) {
  // https://streams.spec.whatwg.org/#writable-stream-start-erroring
  //  1. Assert: stream.[[storedError]] is undefined.
  DCHECK(stream->stored_error_.IsEmpty());

  //  2. Assert: stream.[[state]] is "writable".
  CHECK_EQ(stream->state_, kWritable);

  //  3. Let controller be stream.[[writableStreamController]].
  WritableStreamDefaultController* controller =
      stream->writable_stream_controller_;

  //  4. Assert: controller is not undefined.
  DCHECK(controller);

  //  5. Set stream.[[state]] to "erroring".
  stream->state_ = kErroring;

  //  6. Set stream.[[storedError]] to reason.
  stream->stored_error_.Reset(script_state->GetIsolate(), reason);

  //  7. Let writer be stream.[[writer]].
  WritableStreamDefaultWriter* writer = stream->writer_;

  //  8. If writer is not undefined, perform !
  //     WritableStreamDefaultWriterEnsureReadyPromiseRejected(writer, reason).
  if (writer) {
    WritableStreamDefaultWriter::EnsureReadyPromiseRejected(script_state,
                                                            writer, reason);
  }

  //  9. If ! WritableStreamHasOperationMarkedInFlight(stream) is false and
  //     controller.[[started]] is true, perform !
  //     WritableStreamFinishErroring(stream).
  if (!HasOperationMarkedInFlight(stream) && controller->Started()) {
    FinishErroring(script_state, stream);
  }
}

void WritableStream::FinishErroring(ScriptState* script_state,
                                    WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-finish-erroring
  //  1. Assert: stream.[[state]] is "erroring".
  CHECK_EQ(stream->state_, kErroring);

  //  2. Assert: ! WritableStreamHasOperationMarkedInFlight(stream) is false.
  DCHECK(!HasOperationMarkedInFlight(stream));

  //  3. Set stream.[[state]] to "errored".
  stream->state_ = kErrored;

  //  4. Perform ! stream.[[writableStreamController]].[[ErrorSteps]]().
  stream->writable_stream_controller_->ErrorSteps();

  //  5. Let storedError be stream.[[storedError]].
  auto* isolate = script_state->GetIsolate();
  const auto stored_error = stream->stored_error_.Get(isolate);

  //  6. Repeat for each writeRequest that is an element of
  //     stream.[[writeRequests]],
  //      a. Reject writeRequest with storedError.
  RejectPromises(script_state, &stream->write_requests_, stored_error);

  //  7. Set stream.[[writeRequests]] to an empty List.
  stream->write_requests_.clear();

  //  8. If stream.[[pendingAbortRequest]] is undefined,
  if (!stream->pending_abort_request_) {
    //      a. Perform !
    //         WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream).
    RejectCloseAndClosedPromiseIfNeeded(script_state, stream);

    //      b. Return.
    return;
  }

  //  9. Let abortRequest be stream.[[pendingAbortRequest]].
  auto* abort_request = stream->pending_abort_request_.Get();

  // 10. Set stream.[[pendingAbortRequest]] to undefined.
  stream->pending_abort_request_ = nullptr;

  // 11. If abortRequest.[[wasAlreadyErroring]] is true,
  if (abort_request->WasAlreadyErroring()) {
    //      a. Reject abortRequest.[[promise]] with storedError.
    abort_request->GetResolver()->Reject(stored_error);

    //      b. Perform !
    //         WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream)
    RejectCloseAndClosedPromiseIfNeeded(script_state, stream);

    //      c. Return.
    return;
  }

  // 12. Let promise be ! stream.[[writableStreamController]].[[AbortSteps]](
  //     abortRequest.[[reason]]).
  auto promise = stream->writable_stream_controller_->AbortSteps(
      script_state, abort_request->Reason(isolate));

  class ResolvePromiseFunction final
      : public ThenCallable<IDLUndefined, ResolvePromiseFunction> {
   public:
    ResolvePromiseFunction(WritableStream* stream,
                           ScriptPromiseResolver<IDLUndefined>* resolver)
        : stream_(stream), resolver_(resolver) {}

    void React(ScriptState* script_state) {
      // 13. Upon fulfillment of promise,
      //      a. Resolve abortRequest.[[promise]] with undefined.
      resolver_->Resolve();

      //      b. Perform !
      //         WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream).
      RejectCloseAndClosedPromiseIfNeeded(script_state, stream_);
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(stream_);
      visitor->Trace(resolver_);
      ThenCallable<IDLUndefined, ResolvePromiseFunction>::Trace(visitor);
    }

   private:
    Member<WritableStream> stream_;
    Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  };

  class RejectPromiseFunction final
      : public ThenCallable<IDLAny, RejectPromiseFunction> {
   public:
    RejectPromiseFunction(WritableStream* stream,
                          ScriptPromiseResolver<IDLUndefined>* resolver)
        : stream_(stream), resolver_(resolver) {}

    void React(ScriptState* script_state, ScriptValue reason) {
      // 14. Upon rejection of promise with reason reason,
      //      a. Reject abortRequest.[[promise]] with reason.
      resolver_->Reject(reason);

      //      b. Perform !
      //         WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream).
      RejectCloseAndClosedPromiseIfNeeded(script_state, stream_);
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(stream_);
      visitor->Trace(resolver_);
      ThenCallable<IDLAny, RejectPromiseFunction>::Trace(visitor);
    }

   private:
    Member<WritableStream> stream_;
    Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  };

  promise.Then(script_state,
               MakeGarbageCollected<ResolvePromiseFunction>(
                   stream, abort_request->GetResolver()),
               MakeGarbageCollected<RejectPromiseFunction>(
                   stream, abort_request->GetResolver()));
}

void WritableStream::FinishInFlightWrite(ScriptState* script_state,
                                         WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-finish-in-flight-write
  //  1. Assert: stream.[[inFlightWriteRequest]] is not undefined.
  DCHECK(stream->in_flight_write_request_);

  //  2. Resolve stream.[[inFlightWriteRequest]] with undefined.
  stream->in_flight_write_request_->Resolve();

  //  3. Set stream.[[inFlightWriteRequest]] to undefined.
  stream->in_flight_write_request_ = nullptr;
}

void WritableStream::FinishInFlightWriteWithError(ScriptState* script_state,
                                                  WritableStream* stream,
                                                  v8::Local<v8::Value> error) {
  // https://streams.spec.whatwg.org/#writable-stream-finish-in-flight-write-with-error
  //  1. Assert: stream.[[inFlightWriteRequest]] is not undefined.
  DCHECK(stream->in_flight_write_request_);

  //  2. Reject stream.[[inFlightWriteRequest]] with error.
  stream->in_flight_write_request_->Reject(error);

  //  3. Set stream.[[inFlightWriteRequest]] to undefined.
  stream->in_flight_write_request_ = nullptr;

  //  4. Assert: stream.[[state]] is "writable" or "erroring".
  const auto state = stream->state_;
  CHECK(state == kWritable || state == kErroring);

  //  5. Perform ! WritableStreamDealWithRejection(stream, error).
  DealWithRejection(script_state, stream, error);
}

void WritableStream::FinishInFlightClose(ScriptState* script_state,
                                         WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-finish-in-flight-close
  //  1. Assert: stream.[[inFlightCloseRequest]] is not undefined.
  DCHECK(stream->in_flight_close_request_);

  //  2. Resolve stream.[[inFlightCloseRequest]] with undefined.
  stream->in_flight_close_request_->Resolve();

  //  3. Set stream.[[inFlightCloseRequest]] to undefined.
  stream->in_flight_close_request_ = nullptr;

  //  4. Let state be stream.[[state]].
  const auto state = stream->state_;

  //  5. Assert: stream.[[state]] is "writable" or "erroring".
  CHECK(state == kWritable || state == kErroring);

  //  6. If state is "erroring",
  if (state == kErroring) {
    //      a. Set stream.[[storedError]] to undefined.
    stream->stored_error_.Reset();

    //      b. If stream.[[pendingAbortRequest]] is not undefined,
    if (stream->pending_abort_request_) {
      //          i. Resolve stream.[[pendingAbortRequest]].[[promise]] with
      //             undefined.
      stream->pending_abort_request_->GetResolver()->Resolve();

      //         ii. Set stream.[[pendingAbortRequest]] to undefined.
      stream->pending_abort_request_ = nullptr;
    }
  }

  //  7. Set stream.[[state]] to "closed".
  stream->state_ = kClosed;

  //  8. Let writer be stream.[[writer]].
  const auto writer = stream->writer_;

  //  9. If writer is not undefined, resolve writer.[[closedPromise]] with
  //     undefined.
  if (writer) {
    writer->ClosedResolver()->Resolve();
  }

  // 10. Assert: stream.[[pendingAbortRequest]] is undefined.
  DCHECK(!stream->pending_abort_request_);

  // 11. Assert: stream.[[storedError]] is undefined.
  DCHECK(stream->stored_error_.IsEmpty());
}

void WritableStream::FinishInFlightCloseWithError(ScriptState* script_state,
                                                  WritableStream* stream,
                                                  v8::Local<v8::Value> error) {
  // https://streams.spec.whatwg.org/#writable-stream-finish-in-flight-close-with-error
  //  1. Assert: stream.[[inFlightCloseRequest]] is not undefined.
  DCHECK(stream->in_flight_close_request_);

  //  2. Reject stream.[[inFlightCloseRequest]] with error.
  stream->in_flight_close_request_->Reject(error);

  //  3. Set stream.[[inFlightCloseRequest]] to undefined.
  stream->in_flight_close_request_ = nullptr;

  //  4. Assert: stream.[[state]] is "writable" or "erroring".
  const auto state = stream->state_;
  CHECK(state == kWritable || state == kErroring);

  //  5. If stream.[[pendingAbortRequest]] is not undefined,
  if (stream->pending_abort_request_) {
    //      a. Reject stream.[[pendingAbortRequest]].[[promise]] with error.
    stream->pending_abort_request_->GetResolver()->Reject(error);

    //      b. Set stream.[[pendingAbortRequest]] to undefined.
    stream->pending_abort_request_ = nullptr;
  }

  //  6. Perform ! WritableStreamDealWithRejection(stream, error).
  DealWithRejection(script_state, stream, error);
}

void WritableStream::MarkCloseRequestInFlight(WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-mark-close-request-in-flight
  //  1. Assert: stream.[[inFlightCloseRequest]] is undefined.
  DCHECK(!stream->in_flight_close_request_);

  //  2. Assert: stream.[[closeRequest]] is not undefined.
  DCHECK(stream->close_request_);

  //  3. Set stream.[[inFlightCloseRequest]] to stream.[[closeRequest]].
  stream->in_flight_close_request_ = stream->close_request_;

  //  4. Set stream.[[closeRequest]] to undefined.
  stream->close_request_ = nullptr;
}

void WritableStream::MarkFirstWriteRequestInFlight(WritableStream* stream) {
  // https://streams.spec.whatwg.org/#writable-stream-mark-first-write-request-in-flight
  //  1. Assert: stream.[[inFlightWriteRequest]] is undefined.
  DCHECK(!stream->in_flight_write_request_);

  //  2. Assert: stream.[[writeRequests]] is not empty.
  DCHECK(!stream->write_requests_.empty());

  //  3. Let writeRequest be the first element of stream.[[writeRequests]].
  ScriptPromiseResolver<IDLUndefined>* write_request =
      stream->write_requests_.front();

  //  4. Remove writeRequest from stream.[[writeRequests]], shifting all other
  //     elements downward (so that the second becomes the first, and so on).
  stream->write_requests_.pop_front();

  //  5. Set stream.[[inFlightWriteRequest]] to writeRequest.
  stream->in_flight_write_request_ = write_request;
}

void WritableStream::UpdateBackpressure(ScriptState* script_state,
                                        WritableStream* stream,
                                        bool backpressure) {
  // https://streams.spec.whatwg.org/#writable-stream-update-backpressure
  //  1. Assert: stream.[[state]] is "writable".
  CHECK_EQ(stream->state_, kWritable);

  //  2. Assert: ! WritableStreamCloseQueuedOrInFlight(stream) is false.
  CHECK(!CloseQueuedOrInFlight(stream));

  //  3. Let writer be stream.[[writer]].
  WritableStreamDefaultWriter* writer = stream->writer_;

  //  4. If writer is not undefined and backpressure is not
  //     stream.[[backpressure]],
  if (writer && backpressure != stream->has_backpressure_) {
    //      a. If backpressure is true, set writer.[[readyPromise]] to a new
    //         promise.
    if (backpressure) {
      writer->ResetReadyPromise(script_state);
    } else {
      //      b. Otherwise,
      //          i. Assert: backpressure is false.
      DCHECK(!backpressure);

      //         ii. Resolve writer.[[readyPromise]] with undefined.
      writer->ReadyResolver()->Resolve();
    }
  }

  //  5. Set stream.[[backpressure]] to backpressure.
  stream->has_backpressure_ = backpressure;
}

v8::Local<v8::Value> WritableStream::GetStoredError(
    v8::Isolate* isolate) const {
  return stored_error_.Get(isolate);
}

void WritableStream::SetCloseR
"""


```