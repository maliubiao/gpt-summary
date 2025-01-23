Response:
The user wants a summary of the functionality of the provided C++ code snippet from `observable.cc`. I need to analyze the code and identify its core purpose and how it relates to web technologies like JavaScript, HTML, and CSS. I should also consider potential usage errors and how a user might trigger this code.

**Plan:**

1. Identify the main class or structure being implemented. It seems to be related to `Observable`.
2. Analyze the included headers to understand the dependencies and related functionalities. Pay attention to headers like `v8/...`, `bindings/...`, and `dom/...`.
3. Examine the defined classes like `ScriptValueHolder`, `RejectPromiseAbortAlgorithm`, and the various `*InternalObserver` classes. These seem to represent different behaviors and states within the Observable mechanism.
4. Look for relationships between these C++ classes and corresponding JavaScript APIs or concepts, like Promises, callbacks (`next`, `error`, `complete`), and operators like `reduce`, `find`, `every`, `some`, `last`, `first`, `forEach`, `catch`, and `inspect`.
5. Infer the functionality of the code based on the class names and the operations they perform.
6. Consider how user interactions in a web browser (JavaScript, HTML, CSS) might lead to the execution of this C++ code.
7. Identify potential common programming errors based on the logic and API usage.
8. Formulate a concise summary of the file's functionality.
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/observable.h"

#include "base/types/pass_key.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_catch_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mapper.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observable_inspector.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observable_inspector_abort_handler.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observer_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observer_complete_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_predicate.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_reducer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_subscribe_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_subscribe_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_observableinspector_observercallback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_observer_observercallback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_visitor.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_void_function.h"
#include "third_party/blink/renderer/core/dom/abort_controller.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/observable_internal_observer.h"
#include "third_party/blink/renderer/core/dom/subscriber.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

// A helper wrapper since we cannot hold `Member<ScriptValue>` directly.
class ScriptValueHolder final : public GarbageCollected<ScriptValueHolder> {
 public:
  explicit ScriptValueHolder(ScriptValue value) : value_(value) {}
  const ScriptValue& Value() const { return value_; }
  void Trace(Visitor* visitor) const { visitor->Trace(value_); }

 private:
  ScriptValue value_;
};

class RejectPromiseAbortAlgorithm final : public AbortSignal::Algorithm {
 public:
  RejectPromiseAbortAlgorithm(ScriptPromiseResolverBase* resolver,
                              AbortSignal* signal)
      : resolver_(resolver), signal_(signal) {
    CHECK(resolver);
    CHECK(signal);
  }

  void Run() override {
    resolver_->Reject(signal_->reason(resolver_->GetScriptState()));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(resolver_);
    visitor->Trace(signal_);

    Algorithm::Trace(visitor);
  }

 private:
  // The `ScriptPromiseResolverBase` that `this` must reject when `signal_` is
  // aborted (as notified by `Run()` above).
  Member<ScriptPromiseResolverBase> resolver_;
  // Never null. We have to store the `signal_` that `this` is associated with
  // in order to get the abort reason.
  Member<AbortSignal> signal_;
};

class ScriptCallbackInternalObserver final : public ObservableInternalObserver {
 public:
  ScriptCallbackInternalObserver(V8ObserverCallback* next_callback,
                                 V8ObserverCallback* error_callback,
                                 V8ObserverCompleteCallback* complete_callback)
      : next_callback_(next_callback),
        error_callback_(error_callback),
        complete_callback_(complete_callback) {}

  void Next(ScriptValue value) override {
    if (next_callback_) {
      next_callback_->InvokeAndReportException(nullptr, value);
    }
  }
  void Error(ScriptState* script_state, ScriptValue error_value) override {
    if (error_callback_) {
      error_callback_->InvokeAndReportException(nullptr, error_value);
    } else {
      // This is the "default error algorithm" [1] that must be invoked in the
      // case where `error_callback_` was not provided.
      //
      // [1]: https://wicg.github.io/observable/#default-error-algorithm
      ObservableInternalObserver::Error(script_state, error_value);
    }
  }
  void Complete() override {
    if (complete_callback_) {
      complete_callback_->InvokeAndReportException(nullptr);
    }
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(next_callback_);
    visitor->Trace(error_callback_);
    visitor->Trace(complete_callback_);
  }

 private:
  Member<V8ObserverCallback> next_callback_;
  Member<V8ObserverCallback> error_callback_;
  Member<V8ObserverCompleteCallback> complete_callback_;
};

class ToArrayInternalObserver final : public ObservableInternalObserver {
 public:
  ToArrayInternalObserver(ScriptPromiseResolver<IDLSequence<IDLAny>>* resolver,
                          AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver), abort_algorithm_handle_(handle) {}

  void Next(ScriptValue value) override {
    // "Append the passed in value to values."
    values_.push_back(value);
  }
  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with values."
    resolver_->Resolve(values_);
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(values_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  Member<ScriptPromiseResolver<IDLSequence<IDLAny>>> resolver_;
  HeapVector<ScriptValue> values_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This is the internal observer associated with the `reduce()` operator. See
// https://wicg.github.io/observable/#dom-observable-reduce for its definition
// and spec prose.
class OperatorReduceInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorReduceInternalObserver(ScriptPromiseResolver<IDLAny>* resolver,
                                 AbortController* controller,
                                 V8Reducer* reducer,
                                 std::optional<ScriptValue> initial_value,
                                 AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        reducer_(reducer),
        abort_algorithm_handle_(handle) {
    CHECK(resolver_);
    CHECK(controller_);
    CHECK(reducer_);
    CHECK(abort_algorithm_handle_);
    if (initial_value) {
      accumulator_ = MakeGarbageCollected<ScriptValueHolder>(*initial_value);
    }
  }

  void Next(ScriptValue value) override {
    if (!accumulator_) [[unlikely]] {
      // For all subsequent values, we will take the path where `accumulator_`
      // is *not* null, and we invoke `reducer_` with it.
      accumulator_ = MakeGarbageCollected<ScriptValueHolder>(value);
      // Adjust the index, so that when we first call `reducer_` on the *second*
      // value, the index is adjusted accordingly.
      idx_++;
      return;
    }

    // `ScriptState::Scope` can only be created in a valid context, so
    // early-return if we're in a detached one.
    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      return;
    }

    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    const v8::Maybe<ScriptValue> result = reducer_->Invoke(
        /*thisArg=*/nullptr, /*accumulator=*/accumulator_->Value(),
        /*currentValue=*/value, /*index=*/idx_++);
    if (try_catch.HasCaught()) {
      abort_algorithm_handle_.Clear();
      ScriptValue exception(script_state->GetIsolate(), try_catch.Exception());
      resolver_->Reject(exception);
      controller_->abort(script_state, exception);
      return;
    }

    // Since we handled the exception case above, `result` must not be
    // `v8::Nothing`.
    accumulator_ = MakeGarbageCollected<ScriptValueHolder>(result.ToChecked());
  }

  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    if (accumulator_) {
      resolver_->Resolve(accumulator_->Value());
    } else {
      v8::Isolate* isolate = resolver_->GetScriptState()->GetIsolate();
      resolver_->Reject(V8ThrowException::CreateTypeError(
          isolate, "Reduce of empty array with no initial value"));
    }
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(reducer_);
    visitor->Trace(accumulator_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  uint64_t idx_ = 0;
  Member<ScriptPromiseResolver<IDLAny>> resolver_;
  Member<AbortController> controller_;
  Member<V8Reducer> reducer_;
  // `accumulator_` is initually null unless `initialValue` is passed into the
  // constructor of `this`. When `accumulator_` is initially null, we eventually
  // set it to the first value that `this` encounters in `Next()`. Then, for all
  // subsequent values, we use `accumulator_` as the "accumulator" argument for
  // `reducer_` callback above.
  Member<ScriptValueHolder> accumulator_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This is the internal observer associated with the `find()` operator. See
// https://wicg.github.io/observable/#dom-observable-find for its definition
// and spec prose quoted below.
class OperatorFindInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorFindInternalObserver(ScriptPromiseResolver<IDLAny>* resolver,
                               AbortController* controller,
                               V8Predicate* predicate,
                               AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        predicate_(predicate),
        abort_algorithm_handle_(handle) {
    CHECK(resolver_);
    CHECK(controller_);
    CHECK(predicate_);
    CHECK(abort_algorithm_handle_);
  }

  void Next(ScriptValue value) override {
    // `ScriptState::Scope` can only be created in a valid context, so
    // early-return if we're in a detached one.
    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      return;
    }

    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    const v8::Maybe<bool> maybe_matches =
        predicate_->Invoke(nullptr, value, idx_++);
    if (try_catch.HasCaught()) {
      abort_algorithm_handle_.Clear();
      ScriptValue exception(script_state->GetIsolate(), try_catch.Exception());
      resolver_->Reject(exception);
      controller_->abort(script_state, exception);
      return;
    }

    // Since we handled the exception case above, `maybe_matches` must not be
    // `v8::Nothing`.
    const bool matches = maybe_matches.ToChecked();
    if (matches) {
      abort_algorithm_handle_.Clear();
      resolver_->Resolve(value);
      controller_->abort(resolver_->GetScriptState());
    }
  }

  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with undefined."
    resolver_->Resolve(
        v8::Undefined(resolver_->GetScriptState()->GetIsolate()));
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(predicate_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  uint64_t idx_ = 0;
  Member<ScriptPromiseResolver<IDLAny>> resolver_;
  Member<AbortController> controller_;
  Member<V8Predicate> predicate_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This is the internal observer associated with the `every()` operator. See
// https://wicg.github.io/observable/#dom-observable-every for its definition
// and spec prose quoted below.
class OperatorEveryInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorEveryInternalObserver(ScriptPromiseResolver<IDLBoolean>* resolver,
                                AbortController* controller,
                                V8Predicate* predicate,
                                AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        predicate_(predicate),
        abort_algorithm_handle_(handle) {
    CHECK(resolver_);
    CHECK(controller_);
    CHECK(predicate_);
    CHECK(abort_algorithm_handle_);
  }

  void Next(ScriptValue value) override {
    // `ScriptState::Scope` can only be created in a valid context, so
    // early-return if we're in a detached one.
    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      return;
    }

    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    const v8::Maybe<bool> maybe_matches =
        predicate_->Invoke(nullptr, value, idx_++);
    if (try_catch.HasCaught()) {
      abort_algorithm_handle_.Clear();
      ScriptValue exception(script_state->GetIsolate(), try_catch.Exception());
      resolver_->Reject(exception);
      controller_->abort(script_state, exception);
      return;
    }

    // Since we handled the exception case above, `maybe_matches` must not be
    // `v8::Nothing`.
    const bool matches = maybe_matches.ToChecked();
    if (!matches) {
      abort_algorithm_handle_.Clear();
      resolver_->Resolve(false);
      controller_->abort(resolver_->GetScriptState());
    }
  }

  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with true."
    resolver_->Resolve(true);
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(predicate_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  uint64_t idx_ = 0;
  Member<ScriptPromiseResolver<IDLBoolean>> resolver_;
  Member<AbortController> controller_;
  Member<V8Predicate> predicate_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This is the internal observer associated with the `some()` operator. See
// https://wicg.github.io/observable/#dom-observable-some for its definition
// and spec prose quoted below.
class OperatorSomeInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorSomeInternalObserver(ScriptPromiseResolver<IDLBoolean>* resolver,
                               AbortController* controller,
                               V8Predicate* predicate,
                               AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        predicate_(predicate),
        abort_algorithm_handle_(handle) {
    CHECK(resolver_);
    CHECK(controller_);
    CHECK(predicate_);
    CHECK(abort_algorithm_handle_);
  }

  void Next(ScriptValue value) override {
    // `ScriptState::Scope` can only be created in a valid context, so
    // early-return if we're in a detached one.
    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      return;
    }

    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    const v8::Maybe<bool> maybe_matches =
        predicate_->Invoke(nullptr, value, idx_++);
    if (try_catch.HasCaught()) {
      abort_algorithm_handle_.Clear();
      ScriptValue exception(script_state->GetIsolate(), try_catch.Exception());
      resolver_->Reject(exception);
      controller_->abort(script_state, exception);
      return;
    }

    // Since we handled the exception case above, `maybe_matches` must not be
    // `v8::Nothing`.
    const bool matches = maybe_matches.ToChecked();
    if (matches) {
      abort_algorithm_handle_.Clear();
      resolver_->Resolve(true);
      controller_->abort(resolver_->GetScriptState());
    }
  }

  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with false".
    resolver_->Resolve(false);
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(predicate_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  uint64_t idx_ = 0;
  Member<ScriptPromiseResolver<IDLBoolean>> resolver_;
  Member<AbortController> controller_;
  Member<V8Predicate> predicate_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This is the internal observer associated with the `last()` operator. See
// https://wicg.github.io/observable/#dom-observable-last for its definition
// and spec prose quoted below.
class OperatorLastInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorLastInternalObserver(ScriptPromiseResolver<IDLAny>* resolver,
                               AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver), abort_algorithm_handle_(handle) {}

  void Next(ScriptValue value) override {
    last_value_ = MakeGarbageCollected<ScriptValueHolder>(value);
  }
  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "If lastValue is not null, resolve p with lastValue."
    if (last_value_) {
      resolver_->Resolve(last_value_->Value());
      return;
    }

    // "Otherwise, reject p with a new RangeError."
    v8::Isolate* isolate = resolver_->GetScriptState()->GetIsolate();
    resolver_->Reject(
        ScriptValue(isolate, V8ThrowException::CreateRangeError(
                                 isolate, "No values in Observable")));
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(abort_algorithm_handle_);
    visitor->Trace(last_value_);
  }

 private:
  Member<ScriptPromiseResolver<IDLAny>> resolver_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
  Member<ScriptValueHolder> last_value_;
};

// This is the internal observer associated with the `first()` operator. See
// https://wicg.github.io/observable/#dom-observable-first for its definition
// and spec prose quoted below.
class OperatorFirstInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorFirstInternalObserver(ScriptPromiseResolver<IDLAny>* resolver,
                                AbortController* controller,
                                AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        abort_algorithm_handle_(handle) {}

  void Next(ScriptValue value) override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with the passed in value."
    resolver_->Resolve(value);
    // "Signal abort controller".
    controller_->abort(resolver_->GetScriptState());
  }
  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Reject p with a new RangeError."
    v8::Isolate* isolate = resolver_->GetScriptState()->GetIsolate();
    resolver_->Reject(
        ScriptValue(isolate, V8ThrowException::CreateRangeError(
                                 isolate, "No values in Observable")));
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  Member<ScriptPromiseResolver<IDLAny>> resolver_;
  Member<AbortController> controller_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

class OperatorForEachInternalObserver final
    : public ObservableInternalObserver {
 public:
  OperatorForEachInternalObserver(ScriptPromiseResolver<IDLUndefined>* resolver,
                                  AbortController* controller,
                                  V8Visitor* callback,
                                  AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        callback_(callback),
        abort_algorithm_handle_(handle) {}

  void Next(ScriptValue value) override {
    // Invoke callback with the passed in value.
    //
    // If an exception |E| was thrown, then reject |p| with |E| and signal
    // abort |visitor callback controller| with |E|.

    // `ScriptState::Scope` can only be created in a valid context, so
    // early-return if we're in a detached one.
    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      return;
    }

    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    // Invoking `callback_` can detach the context, but that's OK, nothing below
    // this invocation relies on an attached/valid context.
    std::ignore = callback_->Invoke(nullptr, value, idx_++);
    if (try_catch.HasCaught()) {
      ScriptValue exception(script_state->GetIsolate(), try_catch.Exception());
      resolver_->Reject(exception);
      controller_->abort(script_state, exception);
    }
  }
  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with undefined."
    resolver_->Resolve();
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(callback_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  uint64_t idx_ = 0;
  Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  Member<AbortController> controller_;
  Member<V8Visitor> callback_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This delegate is used by the `Observer#from()` operator, in the case where
// the given `any` value is a `Promise`. It simply utilizes the promise's
// then/catch handlers to pipe the corresponding fulfilled/rejection value to
// the Observable in a one-shot manner.
class OperatorFromPromiseSubscribeDelegate final
    : public Observable::SubscribeDelegate {
 public:
  explicit OperatorFromPromiseSubscribeDelegate(ScriptPromise<IDLAny> promise)
      : promise_(promise) {}

  void OnSubscribe(Subscriber* subscriber, ScriptState* script_state) override {
    promise_.Unwrap().Then(
        script_state,
        MakeGarbageCollected<ObservablePromiseResolverFunction>(
            subscriber,
            ObservablePromiseResolverFunction::ResolveType::kFulfill),
        MakeGarbageCollected<ObservablePromiseResolverFunction>(
            subscriber,
            ObservablePromiseResolverFunction::ResolveType::kReject));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(promise_);

    Observable::SubscribeDelegate::Trace(visitor);
  }

 private:
  class ObservablePromiseResolverFunction final
      : public ThenCallable<IDLAny, ObservablePromiseResolverFunction> {
   public:
    enum class ResolveType { kFulfill, kReject };

    ObservablePromiseResolverFunction(Subscriber* subscriber, ResolveType type)
        : subscriber_(subscriber), type_(type) {
      CHECK(subscriber_);
    }

    void React(ScriptState* script_state, ScriptValue value) {
      if (type_ == ResolveType::kFulfill) {
        subscriber_->next(value);
        subscriber_->complete(script_state);
      } else {
        subscriber_->error(script_state, value);
      }
    }

    void Trace(Visitor* visitor) const final {
      visitor->Trace(subscriber_);

      ThenCallable<IDLAny, ObservablePromiseResolverFunction>::Trace(visitor);
    }

   private:
    Member<Subscriber> subscriber_;
    ResolveType type_;
  };

  MemberScriptPromise<IDLAny> promise_;
};

// This is the subscribe delegate for the `catch()` operator. It allows one to
// "catch" errors pushed from upstream Observables, and handle them by returning
// a new Observable derived from that error. The Observable returned from the
// catch handler is immediately subscribed to, and its values are plumbed
// downstream. See https://wicg.github.io/observable/#dom-observable-catch.
class OperatorCatchSubscribeDelegate final
    : public Observable::SubscribeDelegate {
 public:
  OperatorCatchSubscribeDelegate(Observable* source_observable,
                                 V8CatchCallback* catch_callback)
      : source_observable_(source_observable),
        catch_callback_(catch_callback) {}
  void OnSubscribe(Subscriber* subscriber, ScriptState* script_state) override {
    SubscribeOptions* options = MakeGarbageCollected<SubscribeOptions>();
    options->setSignal(subscriber->signal());

    source_observable_->SubscribeWithNativeObserver(
        script_state,
        MakeGarbageCollected<SourceInternalObserver>(subscriber, script_state,
                                                     catch_callback_),
        options);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(source_observable_);
    visitor->Trace(catch_callback_);

    Observable::SubscribeDelegate::Trace(visitor);
  }

 private:
  class SourceInternalObserver final : public ObservableInternalObserver {
   public:
    SourceInternalObserver(Subscriber* outer_subscriber,
                           ScriptState* script_state,
                           V8CatchCallback* catch_callback)
        : outer_subscriber_(outer_subscriber),
          script_state_(script_state),
          catch_callback_(catch_callback) {
      CHECK(outer_subscriber_);
      CHECK(script_state_);
      CHECK(catch_callback_);
    }

    void Next(ScriptValue value) override { outer_subscriber_->next(value); }
    void Error(ScriptState*, ScriptValue error) override {
      // `ScriptState::Scope` can only be created in a valid context, so
      // early-return if we're in a detached one.
      if (!script_state_->ContextIsValid()) {
        return;
      }

      ScriptState::Scope scope(script_state_);
      v8::TryCatch try_catch(script_state_->GetIsolate());
      // This is the return value of the `catch_callback_`, which must be
      // convertible to an `Observable` object.
      v8::Maybe<ScriptValue> mapped_value =
          catch_callback_->Invoke(nullptr, error);
      if (try_catch.HasCaught()) {
        outer_subscriber_->error(
            script_state_,
            ScriptValue(script_state_->GetIsolate(), try_catch.Exception()));
        return;
      }

      // Since we handled the exception case above, `mapped_value` must not be
      // `v8::Nothing`.
      Observable* inner_observable =
          Observable::from(script_state_, mapped_value.ToChecked(),
                           PassThroughException(script_state_->GetIsolate()));
      if (try_catch.HasCaught()) {
        ApplyContextToException(
            script_state_, try_catch.Exception(),
            ExceptionContext(v8::ExceptionContext::kOperation, "Observable",
                             "catch"));
        outer_subscriber_->error(
            script_state_,
            ScriptValue(script_state_->GetIsolate(), try_catch.Exception()));
        return;
      }

      SubscribeOptions* options = MakeGarbageCollected<SubscribeOptions>();
      options->setSignal(outer_subscriber_->signal());

      inner_observable->SubscribeWithNativeObserver(
          script_state_,
          MakeGarbageCollected<InnerCatchHandlerObserver>(outer_subscriber_,
                                                          script_state_),
          options);
    }
    void Complete() override { outer_subscriber_->complete(script_state_); }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(outer_subscriber_);
      visitor->Trace(script_state_);
      visitor->Trace(catch_callback_);

      ObservableInternalObserver::Trace(visitor);
    }

   private:
    // This is the internal observer that manages the subscription for the
    // Observable returned by the catch handler. It's a trivial pass-through.
    //
    // TODO(crbug.com/40282760): Deduplicate this with
    // `OperatorTakeUntilSubscribeDelegate::SourceInternalObserver`, which is an
    // exact copy of this, by factoring this out into a more common class.
    class InnerCatchHandlerObserver final : public ObservableInternalObserver {
     public:
      InnerCatchHandlerObserver(Subscriber* outer_subscriber,
                                ScriptState* script_state)
          : outer_subscriber_(outer_subscriber), script_state_(script_state) {}

      void Next(ScriptValue value) override { outer_subscriber_->next(value); }
      void Error(ScriptState* script_state, ScriptValue value) override {
        outer_subscriber_->error(script_state, value);
      }
      void Complete() override { outer_subscriber_->complete(script_state_); }

      void
### 提示词
```
这是目录为blink/renderer/core/dom/observable.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/observable.h"

#include "base/types/pass_key.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_catch_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mapper.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observable_inspector.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observable_inspector_abort_handler.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observer_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observer_complete_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_predicate.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_reducer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_subscribe_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_subscribe_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_observableinspector_observercallback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_observer_observercallback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_visitor.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_void_function.h"
#include "third_party/blink/renderer/core/dom/abort_controller.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/observable_internal_observer.h"
#include "third_party/blink/renderer/core/dom/subscriber.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

// A helper wrapper since we cannot hold `Member<ScriptValue>` directly.
class ScriptValueHolder final : public GarbageCollected<ScriptValueHolder> {
 public:
  explicit ScriptValueHolder(ScriptValue value) : value_(value) {}
  const ScriptValue& Value() const { return value_; }
  void Trace(Visitor* visitor) const { visitor->Trace(value_); }

 private:
  ScriptValue value_;
};

class RejectPromiseAbortAlgorithm final : public AbortSignal::Algorithm {
 public:
  RejectPromiseAbortAlgorithm(ScriptPromiseResolverBase* resolver,
                              AbortSignal* signal)
      : resolver_(resolver), signal_(signal) {
    CHECK(resolver);
    CHECK(signal);
  }

  void Run() override {
    resolver_->Reject(signal_->reason(resolver_->GetScriptState()));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(resolver_);
    visitor->Trace(signal_);

    Algorithm::Trace(visitor);
  }

 private:
  // The `ScriptPromiseResolverBase` that `this` must reject when `signal_` is
  // aborted (as notified by `Run()` above).
  Member<ScriptPromiseResolverBase> resolver_;
  // Never null. We have to store the `signal_` that `this` is associated with
  // in order to get the abort reason.
  Member<AbortSignal> signal_;
};

class ScriptCallbackInternalObserver final : public ObservableInternalObserver {
 public:
  ScriptCallbackInternalObserver(V8ObserverCallback* next_callback,
                                 V8ObserverCallback* error_callback,
                                 V8ObserverCompleteCallback* complete_callback)
      : next_callback_(next_callback),
        error_callback_(error_callback),
        complete_callback_(complete_callback) {}

  void Next(ScriptValue value) override {
    if (next_callback_) {
      next_callback_->InvokeAndReportException(nullptr, value);
    }
  }
  void Error(ScriptState* script_state, ScriptValue error_value) override {
    if (error_callback_) {
      error_callback_->InvokeAndReportException(nullptr, error_value);
    } else {
      // This is the "default error algorithm" [1] that must be invoked in the
      // case where `error_callback_` was not provided.
      //
      // [1]: https://wicg.github.io/observable/#default-error-algorithm
      ObservableInternalObserver::Error(script_state, error_value);
    }
  }
  void Complete() override {
    if (complete_callback_) {
      complete_callback_->InvokeAndReportException(nullptr);
    }
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(next_callback_);
    visitor->Trace(error_callback_);
    visitor->Trace(complete_callback_);
  }

 private:
  Member<V8ObserverCallback> next_callback_;
  Member<V8ObserverCallback> error_callback_;
  Member<V8ObserverCompleteCallback> complete_callback_;
};

class ToArrayInternalObserver final : public ObservableInternalObserver {
 public:
  ToArrayInternalObserver(ScriptPromiseResolver<IDLSequence<IDLAny>>* resolver,
                          AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver), abort_algorithm_handle_(handle) {}

  void Next(ScriptValue value) override {
    // "Append the passed in value to values."
    values_.push_back(value);
  }
  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with values."
    resolver_->Resolve(values_);
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(values_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  Member<ScriptPromiseResolver<IDLSequence<IDLAny>>> resolver_;
  HeapVector<ScriptValue> values_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This is the internal observer associated with the `reduce()` operator. See
// https://wicg.github.io/observable/#dom-observable-reduce for its definition
// and spec prose.
class OperatorReduceInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorReduceInternalObserver(ScriptPromiseResolver<IDLAny>* resolver,
                                 AbortController* controller,
                                 V8Reducer* reducer,
                                 std::optional<ScriptValue> initial_value,
                                 AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        reducer_(reducer),
        abort_algorithm_handle_(handle) {
    CHECK(resolver_);
    CHECK(controller_);
    CHECK(reducer_);
    CHECK(abort_algorithm_handle_);
    if (initial_value) {
      accumulator_ = MakeGarbageCollected<ScriptValueHolder>(*initial_value);
    }
  }

  void Next(ScriptValue value) override {
    if (!accumulator_) [[unlikely]] {
      // For all subsequent values, we will take the path where `accumulator_`
      // is *not* null, and we invoke `reducer_` with it.
      accumulator_ = MakeGarbageCollected<ScriptValueHolder>(value);
      // Adjust the index, so that when we first call `reducer_` on the *second*
      // value, the index is adjusted accordingly.
      idx_++;
      return;
    }

    // `ScriptState::Scope` can only be created in a valid context, so
    // early-return if we're in a detached one.
    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      return;
    }

    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    const v8::Maybe<ScriptValue> result = reducer_->Invoke(
        /*thisArg=*/nullptr, /*accumulator=*/accumulator_->Value(),
        /*currentValue=*/value, /*index=*/idx_++);
    if (try_catch.HasCaught()) {
      abort_algorithm_handle_.Clear();
      ScriptValue exception(script_state->GetIsolate(), try_catch.Exception());
      resolver_->Reject(exception);
      controller_->abort(script_state, exception);
      return;
    }

    // Since we handled the exception case above, `result` must not be
    // `v8::Nothing`.
    accumulator_ = MakeGarbageCollected<ScriptValueHolder>(result.ToChecked());
  }

  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    if (accumulator_) {
      resolver_->Resolve(accumulator_->Value());
    } else {
      v8::Isolate* isolate = resolver_->GetScriptState()->GetIsolate();
      resolver_->Reject(V8ThrowException::CreateTypeError(
          isolate, "Reduce of empty array with no initial value"));
    }
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(reducer_);
    visitor->Trace(accumulator_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  uint64_t idx_ = 0;
  Member<ScriptPromiseResolver<IDLAny>> resolver_;
  Member<AbortController> controller_;
  Member<V8Reducer> reducer_;
  // `accumulator_` is initually null unless `initialValue` is passed into the
  // constructor of `this`. When `accumulator_` is initially null, we eventually
  // set it to the first value that `this` encounters in `Next()`. Then, for all
  // subsequent values, we use `accumulator_` as the "accumulator" argument for
  // `reducer_` callback above.
  Member<ScriptValueHolder> accumulator_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This is the internal observer associated with the `find()` operator. See
// https://wicg.github.io/observable/#dom-observable-find for its definition
// and spec prose quoted below.
class OperatorFindInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorFindInternalObserver(ScriptPromiseResolver<IDLAny>* resolver,
                               AbortController* controller,
                               V8Predicate* predicate,
                               AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        predicate_(predicate),
        abort_algorithm_handle_(handle) {
    CHECK(resolver_);
    CHECK(controller_);
    CHECK(predicate_);
    CHECK(abort_algorithm_handle_);
  }

  void Next(ScriptValue value) override {
    // `ScriptState::Scope` can only be created in a valid context, so
    // early-return if we're in a detached one.
    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      return;
    }

    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    const v8::Maybe<bool> maybe_matches =
        predicate_->Invoke(nullptr, value, idx_++);
    if (try_catch.HasCaught()) {
      abort_algorithm_handle_.Clear();
      ScriptValue exception(script_state->GetIsolate(), try_catch.Exception());
      resolver_->Reject(exception);
      controller_->abort(script_state, exception);
      return;
    }

    // Since we handled the exception case above, `maybe_matches` must not be
    // `v8::Nothing`.
    const bool matches = maybe_matches.ToChecked();
    if (matches) {
      abort_algorithm_handle_.Clear();
      resolver_->Resolve(value);
      controller_->abort(resolver_->GetScriptState());
    }
  }

  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with undefined."
    resolver_->Resolve(
        v8::Undefined(resolver_->GetScriptState()->GetIsolate()));
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(predicate_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  uint64_t idx_ = 0;
  Member<ScriptPromiseResolver<IDLAny>> resolver_;
  Member<AbortController> controller_;
  Member<V8Predicate> predicate_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This is the internal observer associated with the `every()` operator. See
// https://wicg.github.io/observable/#dom-observable-every for its definition
// and spec prose quoted below.
class OperatorEveryInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorEveryInternalObserver(ScriptPromiseResolver<IDLBoolean>* resolver,
                                AbortController* controller,
                                V8Predicate* predicate,
                                AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        predicate_(predicate),
        abort_algorithm_handle_(handle) {
    CHECK(resolver_);
    CHECK(controller_);
    CHECK(predicate_);
    CHECK(abort_algorithm_handle_);
  }

  void Next(ScriptValue value) override {
    // `ScriptState::Scope` can only be created in a valid context, so
    // early-return if we're in a detached one.
    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      return;
    }

    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    const v8::Maybe<bool> maybe_matches =
        predicate_->Invoke(nullptr, value, idx_++);
    if (try_catch.HasCaught()) {
      abort_algorithm_handle_.Clear();
      ScriptValue exception(script_state->GetIsolate(), try_catch.Exception());
      resolver_->Reject(exception);
      controller_->abort(script_state, exception);
      return;
    }

    // Since we handled the exception case above, `maybe_matches` must not be
    // `v8::Nothing`.
    const bool matches = maybe_matches.ToChecked();
    if (!matches) {
      abort_algorithm_handle_.Clear();
      resolver_->Resolve(false);
      controller_->abort(resolver_->GetScriptState());
    }
  }

  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with true."
    resolver_->Resolve(true);
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(predicate_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  uint64_t idx_ = 0;
  Member<ScriptPromiseResolver<IDLBoolean>> resolver_;
  Member<AbortController> controller_;
  Member<V8Predicate> predicate_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This is the internal observer associated with the `some()` operator. See
// https://wicg.github.io/observable/#dom-observable-some for its definition
// and spec prose quoted below.
class OperatorSomeInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorSomeInternalObserver(ScriptPromiseResolver<IDLBoolean>* resolver,
                               AbortController* controller,
                               V8Predicate* predicate,
                               AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        predicate_(predicate),
        abort_algorithm_handle_(handle) {
    CHECK(resolver_);
    CHECK(controller_);
    CHECK(predicate_);
    CHECK(abort_algorithm_handle_);
  }

  void Next(ScriptValue value) override {
    // `ScriptState::Scope` can only be created in a valid context, so
    // early-return if we're in a detached one.
    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      return;
    }

    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    const v8::Maybe<bool> maybe_matches =
        predicate_->Invoke(nullptr, value, idx_++);
    if (try_catch.HasCaught()) {
      abort_algorithm_handle_.Clear();
      ScriptValue exception(script_state->GetIsolate(), try_catch.Exception());
      resolver_->Reject(exception);
      controller_->abort(script_state, exception);
      return;
    }

    // Since we handled the exception case above, `maybe_matches` must not be
    // `v8::Nothing`.
    const bool matches = maybe_matches.ToChecked();
    if (matches) {
      abort_algorithm_handle_.Clear();
      resolver_->Resolve(true);
      controller_->abort(resolver_->GetScriptState());
    }
  }

  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with false".
    resolver_->Resolve(false);
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(predicate_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  uint64_t idx_ = 0;
  Member<ScriptPromiseResolver<IDLBoolean>> resolver_;
  Member<AbortController> controller_;
  Member<V8Predicate> predicate_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This is the internal observer associated with the `last()` operator. See
// https://wicg.github.io/observable/#dom-observable-last for its definition
// and spec prose quoted below.
class OperatorLastInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorLastInternalObserver(ScriptPromiseResolver<IDLAny>* resolver,
                               AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver), abort_algorithm_handle_(handle) {}

  void Next(ScriptValue value) override {
    last_value_ = MakeGarbageCollected<ScriptValueHolder>(value);
  }
  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "If lastValue is not null, resolve p with lastValue."
    if (last_value_) {
      resolver_->Resolve(last_value_->Value());
      return;
    }

    // "Otherwise, reject p with a new RangeError."
    v8::Isolate* isolate = resolver_->GetScriptState()->GetIsolate();
    resolver_->Reject(
        ScriptValue(isolate, V8ThrowException::CreateRangeError(
                                 isolate, "No values in Observable")));
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(abort_algorithm_handle_);
    visitor->Trace(last_value_);
  }

 private:
  Member<ScriptPromiseResolver<IDLAny>> resolver_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
  Member<ScriptValueHolder> last_value_;
};

// This is the internal observer associated with the `first()` operator. See
// https://wicg.github.io/observable/#dom-observable-first for its definition
// and spec prose quoted below.
class OperatorFirstInternalObserver final : public ObservableInternalObserver {
 public:
  OperatorFirstInternalObserver(ScriptPromiseResolver<IDLAny>* resolver,
                                AbortController* controller,
                                AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        abort_algorithm_handle_(handle) {}

  void Next(ScriptValue value) override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with the passed in value."
    resolver_->Resolve(value);
    // "Signal abort controller".
    controller_->abort(resolver_->GetScriptState());
  }
  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Reject p with a new RangeError."
    v8::Isolate* isolate = resolver_->GetScriptState()->GetIsolate();
    resolver_->Reject(
        ScriptValue(isolate, V8ThrowException::CreateRangeError(
                                 isolate, "No values in Observable")));
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  Member<ScriptPromiseResolver<IDLAny>> resolver_;
  Member<AbortController> controller_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

class OperatorForEachInternalObserver final
    : public ObservableInternalObserver {
 public:
  OperatorForEachInternalObserver(ScriptPromiseResolver<IDLUndefined>* resolver,
                                  AbortController* controller,
                                  V8Visitor* callback,
                                  AbortSignal::AlgorithmHandle* handle)
      : resolver_(resolver),
        controller_(controller),
        callback_(callback),
        abort_algorithm_handle_(handle) {}

  void Next(ScriptValue value) override {
    // Invoke callback with the passed in value.
    //
    // If an exception |E| was thrown, then reject |p| with |E| and signal
    // abort |visitor callback controller| with |E|.

    // `ScriptState::Scope` can only be created in a valid context, so
    // early-return if we're in a detached one.
    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      return;
    }

    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    // Invoking `callback_` can detach the context, but that's OK, nothing below
    // this invocation relies on an attached/valid context.
    std::ignore = callback_->Invoke(nullptr, value, idx_++);
    if (try_catch.HasCaught()) {
      ScriptValue exception(script_state->GetIsolate(), try_catch.Exception());
      resolver_->Reject(exception);
      controller_->abort(script_state, exception);
    }
  }
  void Error(ScriptState* script_state, ScriptValue error_value) override {
    abort_algorithm_handle_.Clear();

    // "Reject p with the passed in error."
    resolver_->Reject(error_value);
  }
  void Complete() override {
    abort_algorithm_handle_.Clear();

    // "Resolve p with undefined."
    resolver_->Resolve();
  }

  void Trace(Visitor* visitor) const override {
    ObservableInternalObserver::Trace(visitor);

    visitor->Trace(resolver_);
    visitor->Trace(controller_);
    visitor->Trace(callback_);
    visitor->Trace(abort_algorithm_handle_);
  }

 private:
  uint64_t idx_ = 0;
  Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  Member<AbortController> controller_;
  Member<V8Visitor> callback_;
  Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;
};

// This delegate is used by the `Observer#from()` operator, in the case where
// the given `any` value is a `Promise`. It simply utilizes the promise's
// then/catch handlers to pipe the corresponding fulfilled/rejection value to
// the Observable in a one-shot manner.
class OperatorFromPromiseSubscribeDelegate final
    : public Observable::SubscribeDelegate {
 public:
  explicit OperatorFromPromiseSubscribeDelegate(ScriptPromise<IDLAny> promise)
      : promise_(promise) {}

  void OnSubscribe(Subscriber* subscriber, ScriptState* script_state) override {
    promise_.Unwrap().Then(
        script_state,
        MakeGarbageCollected<ObservablePromiseResolverFunction>(
            subscriber,
            ObservablePromiseResolverFunction::ResolveType::kFulfill),
        MakeGarbageCollected<ObservablePromiseResolverFunction>(
            subscriber,
            ObservablePromiseResolverFunction::ResolveType::kReject));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(promise_);

    Observable::SubscribeDelegate::Trace(visitor);
  }

 private:
  class ObservablePromiseResolverFunction final
      : public ThenCallable<IDLAny, ObservablePromiseResolverFunction> {
   public:
    enum class ResolveType { kFulfill, kReject };

    ObservablePromiseResolverFunction(Subscriber* subscriber, ResolveType type)
        : subscriber_(subscriber), type_(type) {
      CHECK(subscriber_);
    }

    void React(ScriptState* script_state, ScriptValue value) {
      if (type_ == ResolveType::kFulfill) {
        subscriber_->next(value);
        subscriber_->complete(script_state);
      } else {
        subscriber_->error(script_state, value);
      }
    }

    void Trace(Visitor* visitor) const final {
      visitor->Trace(subscriber_);

      ThenCallable<IDLAny, ObservablePromiseResolverFunction>::Trace(visitor);
    }

   private:
    Member<Subscriber> subscriber_;
    ResolveType type_;
  };

  MemberScriptPromise<IDLAny> promise_;
};

// This is the subscribe delegate for the `catch()` operator. It allows one to
// "catch" errors pushed from upstream Observables, and handle them by returning
// a new Observable derived from that error. The Observable returned from the
// catch handler is immediately subscribed to, and its values are plumbed
// downstream. See https://wicg.github.io/observable/#dom-observable-catch.
class OperatorCatchSubscribeDelegate final
    : public Observable::SubscribeDelegate {
 public:
  OperatorCatchSubscribeDelegate(Observable* source_observable,
                                 V8CatchCallback* catch_callback)
      : source_observable_(source_observable),
        catch_callback_(catch_callback) {}
  void OnSubscribe(Subscriber* subscriber, ScriptState* script_state) override {
    SubscribeOptions* options = MakeGarbageCollected<SubscribeOptions>();
    options->setSignal(subscriber->signal());

    source_observable_->SubscribeWithNativeObserver(
        script_state,
        MakeGarbageCollected<SourceInternalObserver>(subscriber, script_state,
                                                     catch_callback_),
        options);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(source_observable_);
    visitor->Trace(catch_callback_);

    Observable::SubscribeDelegate::Trace(visitor);
  }

 private:
  class SourceInternalObserver final : public ObservableInternalObserver {
   public:
    SourceInternalObserver(Subscriber* outer_subscriber,
                           ScriptState* script_state,
                           V8CatchCallback* catch_callback)
        : outer_subscriber_(outer_subscriber),
          script_state_(script_state),
          catch_callback_(catch_callback) {
      CHECK(outer_subscriber_);
      CHECK(script_state_);
      CHECK(catch_callback_);
    }

    void Next(ScriptValue value) override { outer_subscriber_->next(value); }
    void Error(ScriptState*, ScriptValue error) override {
      // `ScriptState::Scope` can only be created in a valid context, so
      // early-return if we're in a detached one.
      if (!script_state_->ContextIsValid()) {
        return;
      }

      ScriptState::Scope scope(script_state_);
      v8::TryCatch try_catch(script_state_->GetIsolate());
      // This is the return value of the `catch_callback_`, which must be
      // convertible to an `Observable` object.
      v8::Maybe<ScriptValue> mapped_value =
          catch_callback_->Invoke(nullptr, error);
      if (try_catch.HasCaught()) {
        outer_subscriber_->error(
            script_state_,
            ScriptValue(script_state_->GetIsolate(), try_catch.Exception()));
        return;
      }

      // Since we handled the exception case above, `mapped_value` must not be
      // `v8::Nothing`.
      Observable* inner_observable =
          Observable::from(script_state_, mapped_value.ToChecked(),
                           PassThroughException(script_state_->GetIsolate()));
      if (try_catch.HasCaught()) {
        ApplyContextToException(
            script_state_, try_catch.Exception(),
            ExceptionContext(v8::ExceptionContext::kOperation, "Observable",
                             "catch"));
        outer_subscriber_->error(
            script_state_,
            ScriptValue(script_state_->GetIsolate(), try_catch.Exception()));
        return;
      }

      SubscribeOptions* options = MakeGarbageCollected<SubscribeOptions>();
      options->setSignal(outer_subscriber_->signal());

      inner_observable->SubscribeWithNativeObserver(
          script_state_,
          MakeGarbageCollected<InnerCatchHandlerObserver>(outer_subscriber_,
                                                          script_state_),
          options);
    }
    void Complete() override { outer_subscriber_->complete(script_state_); }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(outer_subscriber_);
      visitor->Trace(script_state_);
      visitor->Trace(catch_callback_);

      ObservableInternalObserver::Trace(visitor);
    }

   private:
    // This is the internal observer that manages the subscription for the
    // Observable returned by the catch handler. It's a trivial pass-through.
    //
    // TODO(crbug.com/40282760): Deduplicate this with
    // `OperatorTakeUntilSubscribeDelegate::SourceInternalObserver`, which is an
    // exact copy of this, by factoring this out into a more common class.
    class InnerCatchHandlerObserver final : public ObservableInternalObserver {
     public:
      InnerCatchHandlerObserver(Subscriber* outer_subscriber,
                                ScriptState* script_state)
          : outer_subscriber_(outer_subscriber), script_state_(script_state) {}

      void Next(ScriptValue value) override { outer_subscriber_->next(value); }
      void Error(ScriptState* script_state, ScriptValue value) override {
        outer_subscriber_->error(script_state, value);
      }
      void Complete() override { outer_subscriber_->complete(script_state_); }

      void Trace(Visitor* visitor) const override {
        visitor->Trace(outer_subscriber_);
        visitor->Trace(script_state_);

        ObservableInternalObserver::Trace(visitor);
      }

     private:
      Member<Subscriber> outer_subscriber_;
      Member<ScriptState> script_state_;
    };

    Member<Subscriber> outer_subscriber_;
    Member<ScriptState> script_state_;
    Member<V8CatchCallback> catch_callback_;
  };

  // The `Observable` which `this` will mirror, when `this` is subscribed to.
  //
  // All of these members are essentially state-less, and are just held here so
  // that we can pass them into the `SourceInternalObserver` above, which gets
  // created for each new subscription.
  Member<Observable> source_observable_;
  Member<V8CatchCallback> catch_callback_;
};

// This is the subscribe delegate for the `inspect()` operator. It allows one to
// supply a pseudo "Observer" dictionary, specifically an `ObservableInspector`,
// which can tap into the direct outputs of a source Observable. It mirrors its
// `next()`, `error()`, and `complete()` handlers, as well as letting you pass
// in two supplemental callbacks:
//   1. A `subscribe()` callback, which runs immediately when the
//      `Observable`-returned-from-`inspect()` is subscribed to, and just before
//      *it* subscribes to its source Observable. Errors from this callback are
//      piped to the consumer Subscriber's `error()` handler, and the
//      subscription is promptly closed.
//   2. An `abort()` callback, which is run specifically for consumer-initiated
//      unsubscriptions/aborts, NOT producer (source-Observable-initiated)
//      unsubscriptions (via `complete()` or `error()`). See the documentation
//      in `OperatorInspectSubscribeDelegate::SourceInternalObserver::Error()`.
class OperatorInspectSubscribeDelegate final
    : public Observable::SubscribeDelegate {
 public:
  OperatorInspectSubscribeDelegate(
      Observable* source_observable,
      V8ObserverCallback* next_callback,
      V8Observe
```