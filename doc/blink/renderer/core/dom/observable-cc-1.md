Response:
The user wants me to analyze the provided C++ code snippet from Chromium's Blink rendering engine. This is the second part of a four-part analysis. I need to focus on the functionality implemented in this section and its relation to web technologies (JavaScript, HTML, CSS).

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:**  The code defines several classes that inherit from `Observable::SubscribeDelegate`. This strongly suggests this code deals with the *subscription logic* for different types of Observables. The prefixes `Operator...SubscribeDelegate` reinforce this idea, indicating these delegates implement specific operators on Observables.

2. **Analyze Individual Delegates:**

   * **`OperatorObserveOnSubscribeDelegate`:** This looks like it intercepts the subscription process. It calls a `subscribe_callback_` before subscribing to the underlying observable. It also manages an `abort_callback_`. This likely relates to how side effects or setup/teardown logic are handled during subscription and unsubscription.

   * **`OperatorSwitchMapSubscribeDelegate`:**  The name "switchMap" is a strong indicator of its function. SwitchMap is a common reactive programming operator. It cancels the previous "inner" observable when a new value arrives from the "outer" observable. The code confirms this with the logic in `Next()` where it aborts the `active_inner_abort_controller_`.

   * **`OperatorFlatMapSubscribeDelegate`:**  "FlatMap" is another standard reactive operator. Unlike switchMap, it *merges* the values from all inner observables. The code uses a `queue_` to manage new values from the outer observable while an inner subscription is active.

   * **`OperatorFromAsyncIterableSubscribeDelegate`:** This delegate handles the creation of Observables from JavaScript Async Iterables. The `SubscriptionRunner` class is crucial here, as it manages the iteration and pushing of values to the subscriber.

3. **Connect to Web Technologies:**

   * **JavaScript:**  The presence of `V8ObserverCallback`, `V8Mapper`, `ScriptState`, and `ScriptValue` strongly links this code to JavaScript interaction. Observables are a feature exposed to JavaScript. The callbacks are JavaScript functions invoked from the C++ side. The operators (switchMap, flatMap, from) are JavaScript concepts being implemented in C++.
   * **HTML/CSS:** While this specific code doesn't directly manipulate HTML or CSS, Observables are used in Blink for managing asynchronous operations, which can be triggered by user interactions with the DOM (HTML) or style changes (CSS). For instance, an Observable could be used to handle a stream of events from a button click or to react to changes in CSS properties.

4. **Logical Reasoning and Examples:**

   * For each delegate, I'll consider what kind of input triggers it and what the expected output would be in terms of the subscriber's `next`, `error`, and `complete` methods.

5. **Common Usage Errors:**

   * Focus on potential issues arising from the interaction between JavaScript and the C++ implementation. Incorrectly implemented JavaScript callbacks that throw errors are a key area. Also, understanding the behavior of `switchMap` and `flatMap` is important for JavaScript developers using these operators.

6. **User Operations and Debugging:**

   * Think about the sequence of user actions in a web page that could lead to this code being executed. This involves interactions that trigger asynchronous behavior or the use of the JavaScript `Observable` API. Debugging would involve tracing the flow of execution from JavaScript calls into the Blink engine.

7. **Synthesize Part 2 Functionality:** Combine the individual functionalities of the delegates into a concise summary for Part 2.

**(Self-Correction/Refinement):** Initially, I might focus too much on the low-level C++ details. I need to constantly remind myself to link the functionality back to its purpose in the browser and its connection to the web platform APIs. The callbacks involving `V8` are the most crucial links to JavaScript. The operator names (`switchMap`, `flatMap`) provide significant clues about the high-level behavior. It's also important to remember that this is *part 2* of the analysis, so the summary should build upon the general understanding of Observables established in part 1 (even though I haven't seen part 1).
这是 `blink/renderer/core/dom/observable.cc` 文件的一部分，主要负责实现 `Observable` 接口的不同订阅策略，特别关注了几个常见的响应式编程操作符的实现。

**功能归纳 (针对提供的代码片段):**

这段代码主要实现了以下几种 `Observable` 的订阅行为，这些行为对应了不同的操作符：

1. **`OperatorObserveOnSubscribeDelegate`:**
   - **功能:**  它作为一个订阅委托，允许在实际订阅源 `Observable` 之前和之后执行自定义的 JavaScript 回调函数。
   - **与 JavaScript 的关系:**
     - `subscribe_callback_`:  这是一个 JavaScript 函数，在订阅开始时被调用。
     - `next_callback_`, `error_callback_`, `complete_callback_`: 这些是 JavaScript 函数，分别对应 `Observable` 发出新值、错误和完成信号时被调用。
     - `abort_callback_`: 这是一个 JavaScript 函数，当订阅被取消时调用，通常与 `AbortSignal` 关联。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个通过 `Observable` 的 `pipe` 方法连接了 `observeOn` 操作符的 `Observable` 实例，以及 `observeOn` 提供的 `next`, `error`, `complete`, `subscribe`, `abort` 回调函数。
     - **输出:** 当订阅发生时，`subscribe_callback_` 会被调用。然后，源 `Observable` 会被订阅，并且当源 `Observable` 发出值、错误或完成信号时，相应的 `next_callback_`, `error_callback_`, `complete_callback_` 会被调用。如果订阅被中止，`abort_callback_` 会被调用。
   - **用户或编程常见的使用错误:**
     - 在 `subscribe_callback_` 中抛出异常会导致订阅失败，并且错误会被传递给订阅者的 `error` 处理函数。
     - `abort_callback_` 的目的是处理用户主动取消订阅的情况，如果在 `error` 或 `complete` 回调中错误地调用与用户取消相关的逻辑，可能会导致意外行为。
   - **用户操作如何到达这里 (调试线索):**
     1. JavaScript 代码创建了一个 `Observable` 实例。
     2. 使用 `pipe` 方法链式调用了 `observeOn` 操作符，并传入了相应的回调函数。例如：`observable.pipe(observeOn({ next: ..., error: ..., complete: ..., subscribe: ..., abort: ... }))`.
     3. 调用 `subscribe()` 方法开始订阅这个经过 `observeOn` 处理的 `Observable`。

2. **`OperatorSwitchMapSubscribeDelegate`:**
   - **功能:** 实现 `switchMap` 操作符，该操作符会将源 `Observable` 发出的每个值映射为一个新的 `Observable`（内部 `Observable`），并只订阅最新的内部 `Observable`。当源 `Observable` 发出新值时，它会取消订阅前一个内部 `Observable`。
   - **与 JavaScript 的关系:**
     - `V8Mapper* mapper_`:  这是一个 JavaScript 函数，用于将源 `Observable` 发出的值转换为新的 `Observable`。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个源 `Observable` 和一个映射函数。源 `Observable` 发出值 A，映射函数将 A 转换为 `Observable B`。然后源 `Observable` 发出值 C，映射函数将 C 转换为 `Observable D`。
     - **输出:** 首先订阅 `Observable B`。当源 `Observable` 发出 C 时，会取消订阅 `Observable B`，然后订阅 `Observable D`。只有来自最新的内部 `Observable` (这里是 `Observable D`) 的值会被传递给最终的订阅者。
   - **用户或编程常见的使用错误:**
     - 忘记 `switchMap` 会取消之前的内部订阅，可能导致某些预期执行的代码被跳过。
     - 提供的映射函数没有返回一个合法的 `Observable` 对象。
   - **用户操作如何到达这里 (调试线索):**
     1. JavaScript 代码创建了一个 `Observable` 实例。
     2. 使用 `pipe` 方法调用了 `switchMap` 操作符，并传入一个映射函数。例如：`observable.pipe(switchMap(value => anotherObservableFn(value)))`.
     3. 调用 `subscribe()` 方法开始订阅这个经过 `switchMap` 处理的 `Observable`。

3. **`OperatorFlatMapSubscribeDelegate`:**
   - **功能:** 实现 `flatMap`（或 `mergeMap`）操作符，该操作符会将源 `Observable` 发出的每个值映射为一个新的 `Observable`（内部 `Observable`），并将所有内部 `Observable` 发出的值合并（merge）到最终的 `Observable` 中。
   - **与 JavaScript 的关系:**
     - `V8Mapper* mapper_`: 这是一个 JavaScript 函数，用于将源 `Observable` 发出的值转换为新的 `Observable`。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个源 `Observable` 和一个映射函数。源 `Observable` 发出值 A，映射函数将 A 转换为 `Observable B`。然后源 `Observable` 发出值 C，映射函数将 C 转换为 `Observable D`。
     - **输出:** 同时订阅 `Observable B` 和 `Observable D`。来自 `Observable B` 和 `Observable D` 的所有值都会被传递给最终的订阅者，顺序可能交错。只有当源 `Observable` 完成并且所有内部 `Observable` 都完成时，最终的 `Observable` 才会完成。
   - **用户或编程常见的使用错误:**
     -  不理解 `flatMap` 会并发处理多个内部 `Observable`，可能导致副作用的执行顺序不可预测。
     -  提供的映射函数没有返回一个合法的 `Observable` 对象。
   - **用户操作如何到达这里 (调试线索):**
     1. JavaScript 代码创建了一个 `Observable` 实例。
     2. 使用 `pipe` 方法调用了 `flatMap` 操作符，并传入一个映射函数。例如：`observable.pipe(flatMap(value => anotherObservableFn(value)))`.
     3. 调用 `subscribe()` 方法开始订阅这个经过 `flatMap` 处理的 `Observable`。

4. **`OperatorFromAsyncIterableSubscribeDelegate`:**
   - **功能:**  允许从 JavaScript 的异步可迭代对象（Async Iterable）创建 `Observable`。它会迭代异步可迭代对象，并将产生的值推送到 `Observable` 的订阅者。
   - **与 JavaScript 的关系:**
     - `ScriptValue async_iterable_`:  存储了 JavaScript 的异步可迭代对象。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个 JavaScript 的 `AsyncIterable` 对象，例如一个异步生成器函数返回的对象。
     - **输出:**  当订阅发生时，代码会迭代该异步可迭代对象。每次异步迭代产生一个值时，该值会被传递给 `Observable` 的订阅者。当异步迭代完成时，`Observable` 也会发出完成信号。
   - **用户或编程常见的使用错误:**
     - 传入的 JavaScript 对象不是一个有效的异步可迭代对象。
     - 异步迭代过程中抛出异常没有被正确处理。
   - **用户操作如何到达这里 (调试线索):**
     1. JavaScript 代码调用了 `Observable.from()` 方法，并传入一个异步可迭代对象作为参数。例如：`Observable.from(asyncIterable)`.
     2. 调用 `subscribe()` 方法开始订阅这个从异步可迭代对象创建的 `Observable`。

**第 2 部分功能归纳:**

总而言之，这段代码的第二部分专注于实现 `Observable` 的不同操作符的订阅逻辑。它提供了处理订阅生命周期事件的机制 (通过 `OperatorObserveOnSubscribeDelegate`)，以及实现了两种常见的转换操作符 (`switchMap` 和 `flatMap`)，它们允许将 `Observable` 发出的值映射为新的 `Observable` 并以不同的方式处理这些内部 `Observable` 的值。此外，它还提供了从 JavaScript 异步可迭代对象创建 `Observable` 的能力。这些功能都是构建复杂异步数据流和响应式编程模式的基础。

### 提示词
```
这是目录为blink/renderer/core/dom/observable.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
rCallback* error_callback,
      V8ObserverCompleteCallback* complete_callback,
      V8VoidFunction* subscribe_callback,
      V8ObservableInspectorAbortHandler* abort_callback)
      : source_observable_(source_observable),
        next_callback_(next_callback),
        error_callback_(error_callback),
        complete_callback_(complete_callback),
        subscribe_callback_(subscribe_callback),
        abort_callback_(abort_callback) {}
  void OnSubscribe(Subscriber* subscriber, ScriptState* script_state) override {
    if (subscribe_callback_) {
      // `ScriptState::Scope` can only be created in a valid context, so
      // early-return if we're in a detached one.
      if (!script_state->ContextIsValid()) {
        return;
      }

      ScriptState::Scope scope(script_state);
      v8::TryCatch try_catch(script_state->GetIsolate());
      std::ignore = subscribe_callback_->Invoke(nullptr);
      if (try_catch.HasCaught()) {
        ScriptValue exception(script_state->GetIsolate(),
                              try_catch.Exception());
        subscriber->error(script_state, exception);
        return;
      }
    }

    AbortSignal::AlgorithmHandle* abort_algorithm_handle = nullptr;
    if (abort_callback_) {
      abort_algorithm_handle = subscriber->signal()->AddAlgorithm(
          MakeGarbageCollected<InspectorAbortHandlerAlgorithm>(
              abort_callback_, subscriber->signal(), script_state));
    }

    // At this point, the `subscribe_callback_` has been called and has not
    // thrown an exception, so we proceed to *actually* subscribe to the
    // underlying Observable, invoking *its* callback through the normal flow
    // and so on.
    SubscribeOptions* options = MakeGarbageCollected<SubscribeOptions>();
    options->setSignal(subscriber->signal());

    source_observable_->SubscribeWithNativeObserver(
        script_state,
        MakeGarbageCollected<SourceInternalObserver>(
            subscriber, script_state, abort_algorithm_handle, next_callback_,
            error_callback_, complete_callback_),
        options);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(source_observable_);

    visitor->Trace(next_callback_);
    visitor->Trace(error_callback_);
    visitor->Trace(complete_callback_);
    visitor->Trace(abort_callback_);
    visitor->Trace(subscribe_callback_);

    Observable::SubscribeDelegate::Trace(visitor);
  }

 private:
  class InspectorAbortHandlerAlgorithm final : public AbortSignal::Algorithm {
   public:
    InspectorAbortHandlerAlgorithm(
        V8ObservableInspectorAbortHandler* abort_handler,
        AbortSignal* signal,
        ScriptState* script_state)
        : abort_handler_(abort_handler),
          signal_(signal),
          script_state_(script_state) {
      CHECK(abort_handler_);
      CHECK(signal_);
      CHECK(script_state_);
    }

    void Run() override {
      abort_handler_->InvokeAndReportException(nullptr,
                                               signal_->reason(script_state_));
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(abort_handler_);
      visitor->Trace(signal_);
      visitor->Trace(script_state_);

      Algorithm::Trace(visitor);
    }

   private:
    // Never null. The JS callback that `this` runs when `signal_ is aborted.
    Member<V8ObservableInspectorAbortHandler> abort_handler_;
    // Never null. We have to store the `signal_` that `this` is associated with
    // in order to get the abort reason.
    Member<AbortSignal> signal_;
    Member<ScriptState> script_state_;
  };

  class SourceInternalObserver final : public ObservableInternalObserver {
   public:
    SourceInternalObserver(Subscriber* subscriber,
                           ScriptState* script_state,
                           AbortSignal::AlgorithmHandle* abort_algorithm_handle,
                           V8ObserverCallback* next_callback,
                           V8ObserverCallback* error_callback,
                           V8ObserverCompleteCallback* complete_callback)
        : subscriber_(subscriber),
          script_state_(script_state),
          abort_algorithm_handle_(abort_algorithm_handle),
          next_callback_(next_callback),
          error_callback_(error_callback),
          complete_callback_(complete_callback) {
      CHECK(subscriber_);
      CHECK(script_state_);
      // All of `next_callback_`, `error_callback_`, `complete_callback_`,
      // `abort_callback`, can all be null, because script may not have provided
      // any of them.
    }

    void ResetAbortAlgorithm() {
      if (!abort_algorithm_handle_) {
        return;
      }

      subscriber_->signal()->RemoveAlgorithm(abort_algorithm_handle_);
      abort_algorithm_handle_ = nullptr;
    }

    void Next(ScriptValue value) override {
      if (!next_callback_) {
        subscriber_->next(value);
        return;
      }

      // `ScriptState::Scope` can only be created in a valid context, so
      // early-return if we're in a detached one.
      if (!script_state_->ContextIsValid()) {
        return;
      }

      ScriptState::Scope scope(script_state_);
      v8::TryCatch try_catch(script_state_->GetIsolate());
      // Invoking `callback_` can detach the context, but that's OK, nothing
      // below this invocation relies on an attached/valid context.
      std::ignore = next_callback_->Invoke(nullptr, value);
      if (try_catch.HasCaught()) {
        ScriptValue exception(script_state_->GetIsolate(),
                              try_catch.Exception());
        // See the documentation in `Error()` for what this does.
        ResetAbortAlgorithm();
        subscriber_->error(script_state_, exception);
      }

      subscriber_->next(value);
    }
    void Error(ScriptState*, ScriptValue error) override {
      // The algorithm represented by `abort_algorithm_handle_` invokes the
      // `ObservableInspector` dictionary's `ObservableInspectorAbortHandler`
      // callback. However, that callback must only be invoked for
      // consumer-initiated aborts, NOT producer-initiated aborts. This means,
      // when the source Observable calls `Error()` or `Complete()` on `this`,
      // we must remove the algorithm from `subscriber_`'s signal, because said
      // signal is about to be aborted for producer-initiated reasons.
      ResetAbortAlgorithm();

      if (!error_callback_) {
        subscriber_->error(script_state_, error);
        return;
      }

      if (!script_state_->ContextIsValid()) {
        return;
      }

      ScriptState::Scope scope(script_state_);
      v8::TryCatch try_catch(script_state_->GetIsolate());
      std::ignore = error_callback_->Invoke(nullptr, error);
      if (try_catch.HasCaught()) {
        ScriptValue exception(script_state_->GetIsolate(),
                              try_catch.Exception());
        subscriber_->error(script_state_, exception);
      }

      subscriber_->error(script_state_, error);
    }
    void Complete() override {
      // See the documentation in `Error()` for what this does.
      ResetAbortAlgorithm();

      if (!complete_callback_) {
        subscriber_->complete(script_state_);
        return;
      }

      if (!script_state_->ContextIsValid()) {
        return;
      }

      ScriptState::Scope scope(script_state_);
      v8::TryCatch try_catch(script_state_->GetIsolate());
      std::ignore = complete_callback_->Invoke(nullptr);
      if (try_catch.HasCaught()) {
        ScriptValue exception(script_state_->GetIsolate(),
                              try_catch.Exception());
        subscriber_->error(script_state_, exception);
      }

      subscriber_->complete(script_state_);
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(subscriber_);
      visitor->Trace(script_state_);
      visitor->Trace(abort_algorithm_handle_);

      visitor->Trace(next_callback_);
      visitor->Trace(error_callback_);
      visitor->Trace(complete_callback_);

      ObservableInternalObserver::Trace(visitor);
    }

   private:
    Member<Subscriber> subscriber_;
    Member<ScriptState> script_state_;
    Member<AbortSignal::AlgorithmHandle> abort_algorithm_handle_;

    Member<V8ObserverCallback> next_callback_;
    Member<V8ObserverCallback> error_callback_;
    Member<V8ObserverCompleteCallback> complete_callback_;
  };
  // The `Observable` which `this` will mirror, when `this` is subscribed to.
  Member<Observable> source_observable_;

  Member<V8ObserverCallback> next_callback_;
  Member<V8ObserverCallback> error_callback_;
  Member<V8ObserverCompleteCallback> complete_callback_;
  Member<V8VoidFunction> subscribe_callback_;
  Member<V8ObservableInspectorAbortHandler> abort_callback_;
};

class OperatorSwitchMapSubscribeDelegate final
    : public Observable::SubscribeDelegate {
 public:
  OperatorSwitchMapSubscribeDelegate(Observable* source_observable,
                                     V8Mapper* mapper)
      : source_observable_(source_observable), mapper_(mapper) {}
  void OnSubscribe(Subscriber* subscriber, ScriptState* script_state) override {
    SubscribeOptions* options = MakeGarbageCollected<SubscribeOptions>();
    options->setSignal(subscriber->signal());

    source_observable_->SubscribeWithNativeObserver(
        script_state,
        MakeGarbageCollected<SourceInternalObserver>(subscriber, script_state,
                                                     mapper_),
        options);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(source_observable_);
    visitor->Trace(mapper_);

    Observable::SubscribeDelegate::Trace(visitor);
  }

 private:
  class SourceInternalObserver final : public ObservableInternalObserver {
   public:
    SourceInternalObserver(Subscriber* outer_subscriber,
                           ScriptState* script_state,
                           V8Mapper* mapper)
        : outer_subscriber_(outer_subscriber),
          script_state_(script_state),
          mapper_(mapper) {
      CHECK(outer_subscriber_);
      CHECK(script_state_);
      CHECK(mapper_);
    }

    // https://wicg.github.io/observable/#switchmap-next-steps.
    void Next(ScriptValue value) override {
      if (active_inner_abort_controller_) {
        active_inner_abort_controller_->abort(script_state_);
      }

      active_inner_abort_controller_ = AbortController::Create(script_state_);

      SwitchMapProcessNextValueSteps(value);
    }
    void Error(ScriptState*, ScriptValue error) override {
      outer_subscriber_->error(script_state_, error);
    }
    // https://wicg.github.io/observable/#switchmap-complete-steps.
    void Complete() override {
      outer_subscription_has_completed_ = true;

      if (!active_inner_abort_controller_) {
        outer_subscriber_->complete(script_state_);
      }
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(outer_subscriber_);
      visitor->Trace(script_state_);
      visitor->Trace(mapper_);
      visitor->Trace(active_inner_abort_controller_);

      ObservableInternalObserver::Trace(visitor);
    }

    // https://wicg.github.io/observable/#switchmap-process-next-value-steps.
    void SwitchMapProcessNextValueSteps(ScriptValue value) {
      // `ScriptState::Scope` can only be created in a valid context, so
      // early-return if we're in a detached one.
      if (!script_state_->ContextIsValid()) {
        return;
      }

      ScriptState::Scope scope(script_state_);
      v8::TryCatch try_catch(script_state_->GetIsolate());
      v8::Maybe<ScriptValue> mapped_value =
          mapper_->Invoke(nullptr, value, ++idx_);
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
                             "map"));
        outer_subscriber_->error(
            script_state_,
            ScriptValue(script_state_->GetIsolate(), try_catch.Exception()));
        return;
      }

      // The `AbortSignal` with which we subscribe to the "inner" Observable is
      // dependent on two signals:
      //   1. The outer subscriber's signal; this one is no surprise, so that we
      //      can unsubscribe from the inner Observable when the outer source
      //      Observable gets torn down.
      HeapVector<Member<AbortSignal>> signals;
      signals.push_back(outer_subscriber_->signal());
      //   2. A more narrowly-scoped signal: the one derived from
      //      `active_inner_abort_controller_`. This signal allows `this` to
      //      abort the inner Observable when the outer source Observable emits
      //      new values.
      DCHECK(active_inner_abort_controller_);
      signals.push_back(active_inner_abort_controller_->signal());

      SubscribeOptions* options = MakeGarbageCollected<SubscribeOptions>();
      options->setSignal(
          MakeGarbageCollected<AbortSignal>(script_state_, signals));

      inner_observable->SubscribeWithNativeObserver(
          script_state_,
          MakeGarbageCollected<InnerSwitchMapObserver>(outer_subscriber_, this),
          options);
    }

    void InnerObservableCompleted() {
      if (outer_subscription_has_completed_) {
        outer_subscriber_->complete(script_state_);
        return;
      }

      active_inner_abort_controller_ = nullptr;
    }

   private:
    // This is the internal observer that manages the subscription for each
    // "inner" Observable, that is derived from each `any` value that the
    // `V8Mapper` omits for each value that the source Observable. So the flow
    // looks like this:
    //   1. "source observable" emits `any` values, which get processed by
    //      `SourceInternalObserver::Next()`.
    //   2. It then goes through
    //      `SourceInternalObserver::SwitchMapProcessNextValueSteps()`, which
    //      calls `V8Mapper` on the `any` value, transforming it into an
    //      `Observable` (via `Observable::from()` semantics).
    //   3. That `Observable` gets subscribed to, via this
    //      `InnerSwitchMapObserver`. `InnerSwitchMapObserver` subscribes to the
    //      given "inner" Observable, piping values/errors it omits to
    //      `outer_subscriber_`, and upon completion, letting calling back to
    //      `SourceInternalObserver` to let it know of the most recent "inner"
    //      subscription completion, so it can process any subsequent ones.
    class InnerSwitchMapObserver final : public ObservableInternalObserver {
     public:
      InnerSwitchMapObserver(Subscriber* outer_subscriber,
                             SourceInternalObserver* source_observer)
          : outer_subscriber_(outer_subscriber),
            source_observer_(source_observer) {}

      void Next(ScriptValue value) override { outer_subscriber_->next(value); }
      void Error(ScriptState* script_state, ScriptValue value) override {
        outer_subscriber_->error(script_state, value);
      }
      void Complete() override { source_observer_->InnerObservableCompleted(); }

      void Trace(Visitor* visitor) const override {
        visitor->Trace(source_observer_);
        visitor->Trace(outer_subscriber_);

        ObservableInternalObserver::Trace(visitor);
      }

     private:
      Member<Subscriber> outer_subscriber_;
      Member<SourceInternalObserver> source_observer_;
    };

    uint64_t idx_ = 0;
    Member<Subscriber> outer_subscriber_;
    Member<ScriptState> script_state_;
    Member<V8Mapper> mapper_;

    Member<AbortController> active_inner_abort_controller_ = nullptr;

    // This member keeps track of whether the "outer" subscription has
    // completed. This is relevant because while we're currently processing
    // "inner" observable subscriptions (i.e., the subscriptions associated with
    // individual Observable values that the "outer" subscriber produces), the
    // "outer" subscription may very well complete. This member helps us keep
    // track of that so we know to complete our subscription once all "inner"
    // values are done being processed.
    bool outer_subscription_has_completed_ = false;
  };

  // The `Observable` which `this` will mirror, when `this` is subscribed to.
  //
  // All of these members are essentially state-less, and are just held here so
  // that we can pass them into the `SourceInternalObserver` above, which gets
  // created for each new subscription.
  Member<Observable> source_observable_;
  Member<V8Mapper> mapper_;
};

// This class is the subscriber delegate for Observables returned by
// `flatMap()`. Flat map is a tricky operator, so here's how the flow works.
// Upon subscription, `this` subscribes to the "source" Observable, that had its
// `flatMap()` method called. All values that the source Observable emits, get
// piped to its subscription's internal observer, which is
// `OperatorFlatMapSubscribeDelegate::SourceInternalObserver`. It is that class
// that is responsible for mapping each of the individual source Observable, via
// `mapper`, to an Observable (that we call the "inner" Observable), which then
// gets subscribed to. Through the remainder the "inner" Observable's lifetime,
// its values are exclusively piped to the "outer" Subscriber — this allows the
// IDL `Observer` handlers associated with the Observable returned from
// `flatMap()` to observe the inner Observable's values.
//
// Once the inner Observable completes, the focus is transferred to the *next*
// value that the outer Observable has emitted, if one such exists. That value
// too gets mapped and converted to an Observable, and subscribed to, and so on.
// See also, the documentation above
// `OperatorFlatMapSubscribeDelegate::SourceInternalObserver::InnerFlatMapObserver`.
class OperatorFlatMapSubscribeDelegate final
    : public Observable::SubscribeDelegate {
 public:
  OperatorFlatMapSubscribeDelegate(Observable* source_observable,
                                   V8Mapper* mapper)
      : source_observable_(source_observable), mapper_(mapper) {}
  void OnSubscribe(Subscriber* subscriber, ScriptState* script_state) override {
    SubscribeOptions* options = MakeGarbageCollected<SubscribeOptions>();
    options->setSignal(subscriber->signal());

    source_observable_->SubscribeWithNativeObserver(
        script_state,
        MakeGarbageCollected<SourceInternalObserver>(subscriber, script_state,
                                                     mapper_),
        options);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(source_observable_);
    visitor->Trace(mapper_);

    Observable::SubscribeDelegate::Trace(visitor);
  }

 private:
  class SourceInternalObserver final : public ObservableInternalObserver {
   public:
    SourceInternalObserver(Subscriber* outer_subscriber,
                           ScriptState* script_state,
                           V8Mapper* mapper)
        : outer_subscriber_(outer_subscriber),
          script_state_(script_state),
          mapper_(mapper) {
      CHECK(outer_subscriber_);
      CHECK(script_state_);
      CHECK(mapper_);
    }

    void Next(ScriptValue value) override {
      if (active_inner_subscription_) {
        queue_.push_back(std::move(value));
        return;
      }

      active_inner_subscription_ = true;

      FlatMapProcessNextValueSteps(value);
    }
    void Error(ScriptState*, ScriptValue error) override {
      outer_subscriber_->error(script_state_, error);
    }
    void Complete() override {
      outer_subscription_has_completed_ = true;

      if (!active_inner_subscription_ && queue_.empty()) {
        outer_subscriber_->complete(script_state_);
      }
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(outer_subscriber_);
      visitor->Trace(script_state_);
      visitor->Trace(mapper_);
      visitor->Trace(queue_);

      ObservableInternalObserver::Trace(visitor);
    }

    // Analogous to
    // https://wicg.github.io/observable/#flatmap-process-next-value-steps.
    //
    // This method can be called re-entrantly. Imagine the following:
    //   1. The source Observable emits a value that gets passed to this method
    //      (`value` below).
    //   2. `this` derives an Observable from that value, and immediately
    //      subscribes to it.
    //   3. Upon subscription, the Observable synchronously `complete()`s.
    //   4. Upon completion, `InnerObservableCompleted()` gets called, which has
    //      to synchronously process the next value in `queue_`, restarting
    //      these steps from the top.
    void FlatMapProcessNextValueSteps(ScriptValue value) {
      // `ScriptState::Scope` can only be created in a valid context, so
      // early-return if we're in a detached one.
      if (!script_state_->ContextIsValid()) {
        return;
      }

      ScriptState::Scope scope(script_state_);
      v8::TryCatch try_catch(script_state_->GetIsolate());
      v8::Maybe<ScriptValue> mapped_value =
          mapper_->Invoke(nullptr, value, ++idx_);
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
                             "flatMap"));
        outer_subscriber_->error(
            script_state_,
            ScriptValue(script_state_->GetIsolate(), try_catch.Exception()));
        return;
      }

      SubscribeOptions* options = MakeGarbageCollected<SubscribeOptions>();
      options->setSignal(outer_subscriber_->signal());

      inner_observable->SubscribeWithNativeObserver(
          script_state_,
          MakeGarbageCollected<InnerFlatMapObserver>(outer_subscriber_, this),
          options);
    }

    // This method can be called re-entrantly. See the documentation above
    // `FlatMapProcessNextValueSteps()`.
    void InnerObservableCompleted() {
      if (!queue_.empty()) {
        ScriptValue value = queue_.front();
        // This is inefficient! See the documentation above `queue_` for more.
        queue_.EraseAt(0);
        FlatMapProcessNextValueSteps(value);
        return;
      }

      // When the `queue_` is empty and the last "inner" Observable has
      // completed, we can finally complete `outer_subscriber_`.
      active_inner_subscription_ = false;
      if (outer_subscription_has_completed_) {
        outer_subscriber_->complete(script_state_);
      }
    }

   private:
    // This is the internal observer that manages the subscription for each
    // "inner" Observable, that is derived from each `any` value that the
    // `V8Mapper` omits for each value that the source Observable. So the flow
    // looks like this:
    //   1. "source observable" emits `any` values, which get processed by
    //      `SourceInternalObserver::Next()`.
    //   2. It then goes through
    //      `SourceInternalObserver::FlatMapProcessNextValueSteps()`, which
    //      calls `V8Mapper` on the `any` value, transforming it into an
    //      `Observable` (via `Observable::from()` semantics).
    //   3. That `Observable` gets subscribed to, via this
    //      `InnerFlatMapObserver`. `InnerFlatMapObserver` subscribes to the
    //      given "inner" Observable, piping values/errors it omits to
    //      `outer_subscriber_`, and upon completion, letting calling back to
    //      `SourceInternalObserver` to let it know of the most recent "inner"
    //      subscription completion, so it can process any subsequent ones.
    class InnerFlatMapObserver final : public ObservableInternalObserver {
     public:
      InnerFlatMapObserver(Subscriber* outer_subscriber,
                           SourceInternalObserver* source_observer)
          : outer_subscriber_(outer_subscriber),
            source_observer_(source_observer) {}

      void Next(ScriptValue value) override { outer_subscriber_->next(value); }
      void Error(ScriptState* script_state, ScriptValue value) override {
        outer_subscriber_->error(script_state, value);
      }
      void Complete() override { source_observer_->InnerObservableCompleted(); }

      void Trace(Visitor* visitor) const override {
        visitor->Trace(source_observer_);
        visitor->Trace(outer_subscriber_);

        ObservableInternalObserver::Trace(visitor);
      }

     private:
      Member<Subscriber> outer_subscriber_;
      Member<SourceInternalObserver> source_observer_;
    };

    uint64_t idx_ = 0;
    Member<Subscriber> outer_subscriber_;
    Member<ScriptState> script_state_;
    Member<V8Mapper> mapper_;

    // This queue stores all of the values that the "outer" subscription emits
    // while there is an active inner subscription (captured by the member below
    // this). These values are queued and processed one-by-one; they each get
    // passed into `mapper_`.
    //
    // TODO(crbug.com/40282760): This should be a `WTF::Deque` or `HeapDeque`,
    // but neither support holding a `ScriptValue` type at the moment. This
    // needs some investigation, so we can avoid using `HeapVector` here, which
    // has O(n) performance when removing values from the front.
    HeapVector<ScriptValue> queue_;

    bool active_inner_subscription_ = false;

    // This member keeps track of whether the "outer" subscription has
    // completed. This is relevant because while we're currently processing
    // "inner" observable subscriptions (i.e., the subscriptions associated with
    // individual Observable values that the "outer" subscriber produces), the
    // "outer" subscription may very well complete. This member helps us keep
    // track of that so we know to complete our subscription once all "inner"
    // values are done being processed.
    bool outer_subscription_has_completed_ = false;
  };

  // The `Observable` which `this` will mirror, when `this` is subscribed to.
  //
  // All of these members are essentially state-less, and are just held here so
  // that we can pass them into the `SourceInternalObserver` above, which gets
  // created for each new subscription.
  Member<Observable> source_observable_;
  Member<V8Mapper> mapper_;
};

// This delegate is used by the `Observer#from()` operator, in the case where
// the given `any` value is an async iterable. In that case, we store the async
// iterable in `this` delegate, and upon subscription, push to the subscriber
// all of the async iterable's resolved values, once the internal promises are
// reacted to.
class OperatorFromAsyncIterableSubscribeDelegate final
    : public Observable::SubscribeDelegate {
 public:
  // Upon construction of `this`, we know that `async_iterable` is a valid
  // object that implements the async iterable prototcol, however:
  //   1. We don't assert that here, because it has script-observable
  //      consequences that shouldn't be invoked just for assertion/sanity
  //      purposes.
  //   2. In `OnSubscribe()` we still have to confirm that fact, because in
  //      between the constructor and `OnSubscribe()` running, that could have
  //      changed.
  explicit OperatorFromAsyncIterableSubscribeDelegate(
      ScriptValue async_iterable)
      : async_iterable_(async_iterable) {}

  // "Return a new Observable whose subscribe callback is an algorithm that
  // takes a Subscriber |subscriber| and does the following:"
  void OnSubscribe(Subscriber* subscriber, ScriptState* script_state) override {
    if (subscriber->signal()->aborted()) {
      return;
    }

    // `Observable::from()` already checks that `async_iterable_` is a JS
    // object, so we can safely convert it here.
    //
    // The runner is never owned by `this`, since the lifetime of `this` is too
    // long. Instead, we just create it now and leave it alone. This ties the
    // ownership to the underlying iterator that produces values. Specifically,
    // `SubscriptionRunner::next_promise_` is kept alive by the script that owns
    // the resolver.
    MakeGarbageCollected<SubscriptionRunner>(
        async_iterable_.V8Value().As<v8::Object>(), subscriber, script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(async_iterable_);

    Observable::SubscribeDelegate::Trace(visitor);
  }

 private:
  // An instance of this class gets created for every single call of
  // `OperatorFromAsyncIterableSubscribeDelegate::OnSubscribe()`, and is
  // responsible for managing each subscription. That's because each
  // subscription must grab a brand new iterator off of `async_iterable_` and
  // run it to completion, which `SubscriptionRunner` is responsible for.
  //
  // See documentation above its instantiation for ownership details.
  class SubscriptionRunner final : public AbortSignal::Algorithm {
   public:
    SubscriptionRunner(v8::Local<v8::Object> v8_async_iterable,
                       Subscriber* subscriber,
                       ScriptState* script_state)
        : subscriber_(subscriber), script_state_(script_state) {
      v8::TryCatch try_catch(script_state->GetIsolate());

      // "Let |iteratorRecord| be GetIterator(value, async)."
      //
      // This invokes script, so we have to check if there was an exception. In
      // all of the exception-throwing cases in this method, we always catch the
      // exception, clear it, and report it properly through `subscriber`.
      iterator_ = ScriptIterator::FromIterable(
          script_state->GetIsolate(), v8_async_iterable,
          PassThroughException(script_state_->GetIsolate()),
          ScriptIterator::Kind::kAsync);

      // "If |iteratorRecord| is a throw completion, then run |subscriber|'s
      // error() method, given |iteratorRecord|'s [[Value]]."
      if (try_catch.HasCaught()) {
        // Don't ApplyContextToException(), because FromIterable() might return
        // a user-defined exception, which we shouldn't modify.
        subscriber->error(script_state, ScriptValue(script_state->GetIsolate(),
                                                    try_catch.Exception()));
        return;
      }

      // This happens if `ScriptIterator::FromIterable()`, which runs script,
      // aborts the subscription. In that case, we respect the abort and leave
      // the iterator alone.
      if (subscriber_->signal()->aborted()) {
        return;
      }

      abort_algorithm_handle_ = subscriber->signal()->AddAlgorithm(this);

      // Note that it's possible for `iterator_.IsNull()` to be true here, and
      // we have to handle it appropriately. Here's why:
      //
      // ECMAScript's `GetIterator(value, async)` [1] throws a TypeError when it
      // fails to find both a %Symbol.asyncIterator% or fallback
      // %Symbol.iterator% implementation on the object to convert. However,
      // Blink's implementation of this does not throw an exception in this
      // case, to allow for Blink to specify alternate behavior in the case
      // where the object simply doesn't implement the protocols. However,
      // Observables have no alternate behavior, so we treat the `IsNull()` case
      // the same as the error-throwing case.
      //
      // [1]: https://tc39.es/ecma262/#sec-getiterator
      if (iterator_.IsNull()) {
        DCHECK(!try_catch.HasCaught());
        // The object failed to convert to an async or sync iterable.
        v8::Local<v8::Value> type_error = V8ThrowException::CreateTypeError(
            script_state->GetIsolate(), "Object must be iterable");
        ClearAbortAlgorithm();
        subscriber->error(script_state,
                          ScriptValue(script_state->GetIsolate(), type_error));
        return;
      }

      // "Run |nextAlgorithm| given |subscriber| and |iteratorRecord|."
      GetNextValue(subscr
```