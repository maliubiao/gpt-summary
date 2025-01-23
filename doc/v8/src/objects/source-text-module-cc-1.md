Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/source-text-module.cc`. The request also includes several specific constraints:

1. **List Functionality:** Provide a list of what the code does.
2. **Torque Source:** Check if the filename ends with `.tq` and state if it's Torque code.
3. **JavaScript Relation:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:** If there's code logic, provide an example with input and output.
5. **Common Programming Errors:** If the code touches upon common programming errors, provide examples.
6. **Overall Functionality (Part 2):**  Summarize the functionality of this specific code part.

Let's break down the code and address each point:

* **Code Overview:** This code snippet seems to handle the evaluation of JavaScript modules, specifically `SourceTextModule` which represents modules loaded from source text. It deals with synchronous and asynchronous evaluation, error handling, and dependency management.

* **Functionality Listing:** I can go through the methods in the snippet and describe their purpose.

* **`.tq` Check:** The filename is `source-text-module.cc`, so it's not a Torque file.

* **JavaScript Relation:** Module evaluation is directly tied to JavaScript's `import` and module execution semantics. I can craft a simple JavaScript module example to illustrate this.

* **Code Logic Inference:**  The `InnerModuleEvaluation` function with its DFS-like traversal for dependency resolution and handling of synchronous/asynchronous dependencies seems like a good candidate for illustrating logic with input and output. I'll need to define a simple module dependency graph.

* **Common Programming Errors:**  The error handling parts of the code, especially around asynchronous module execution, could relate to common errors like unhandled promise rejections or circular dependencies in modules.

* **Overall Functionality (Part 2):** This part seems to focus on the later stages of module evaluation, specifically handling successful and failed asynchronous module executions and dealing with potential stalls due to top-level await.

**Plan:**

1. **Functionality List:**  Iterate through the methods like `MaybeHandleEvaluationException`, `Evaluate`, `AsyncModuleExecutionFulfilled`, `AsyncModuleExecutionRejected`, `ExecuteAsyncModule`, `InnerExecuteAsyncModule`, `ExecuteModule`, `InnerModuleEvaluation`, `Reset`, and `GetStalledTopLevelAwaitMessages` and describe their purpose.
2. **Torque:** State that the file is not a Torque file.
3. **JavaScript Example:** Create a simple JavaScript example with `import` to show the relevance.
4. **Code Logic Example:**  Focus on `InnerModuleEvaluation`. Define a simple module dependency graph (e.g., A imports B). Trace the execution with some assumptions about module states.
5. **Common Errors:** Provide examples of unhandled promise rejections in modules leading to `AsyncModuleExecutionRejected` and potential circular dependencies causing issues in `InnerModuleEvaluation`.
6. **Part 2 Summary:**  Summarize the key responsibilities of the code, focusing on asynchronous module completion, error propagation, and detecting stalled top-level awaits.

Planning complete. I will now generate the response.
这是 `v8/src/objects/source-text-module.cc` 源代码的第二部分，主要负责处理模块的 **评估 (Evaluation)** 阶段，包括同步和异步模块的执行、错误处理以及与 Promise 的交互。

**功能列举:**

* **`MaybeHandleEvaluationException`**:  处理模块评估过程中可能出现的异常。它会根据异常类型更新模块的状态，并将错误记录到模块中。对于非终止异常，它会将错误传播到依赖的模块。
* **`Evaluate`**:  启动模块的评估过程。它会创建一个 Promise Capability 来跟踪评估结果，并调用 `InnerModuleEvaluation` 来执行实际的评估。根据 `InnerModuleEvaluation` 的结果，它会 resolve 或 reject 该 Promise。
* **`AsyncModuleExecutionFulfilled`**: 当一个异步模块成功执行完毕时被调用。它会更新模块的状态为 `EVALUATED`，并触发依赖该模块的其他异步模块的执行。如果模块有 Top-Level Await，它会 resolve 与之关联的 Promise。
* **`AsyncModuleExecutionRejected`**: 当一个异步模块执行失败时被调用。它会将错误记录到模块中，并将错误传播到依赖该模块的其他异步模块。如果模块有 Top-Level Await，它会 reject 与之关联的 Promise。
* **`ExecuteAsyncModule`**:  用于执行包含 Top-Level Await 的异步模块。它会创建一个新的 Promise Capability，并调用 `InnerExecuteAsyncModule` 来实际执行异步函数。成功或失败的回调函数会被注册到该 Promise 上。
* **`InnerExecuteAsyncModule`**:  实际执行异步模块的代码。它会获取模块关联的 `JSAsyncFunctionObject`，并使用传入的 Promise Capability 来驱动其执行。
* **`ExecuteModule`**:  用于执行同步模块的代码。它会获取模块关联的 `JSGeneratorObject`，并调用其 `next` 方法来执行模块代码。
* **`InnerModuleEvaluation`**:  模块评估的核心递归函数。它负责深度优先遍历模块的依赖图，并根据模块的状态进行不同的操作。它会处理循环依赖、同步和异步依赖，并启动模块的执行。
* **`Reset`**:  重置模块的状态，用于重新加载或重新评估模块。
* **`GetStalledTopLevelAwaitMessages`**:  用于检测由于循环依赖而导致 Top-Level Await 停滞的模块，并生成相应的错误消息。
* **`InnerGetStalledTopLevelAwaitModule`**:  `GetStalledTopLevelAwaitMessages` 的辅助函数，用于递归遍历模块依赖图以查找停滞的模块。

**是否为 Torque 源代码:**

`v8/src/objects/source-text-module.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件的扩展名通常是 `.tq`）。

**与 JavaScript 的关系及示例:**

这段代码直接关联到 JavaScript 的模块系统（ES Modules）。它实现了 JavaScript 模块的加载、链接和评估过程。

**JavaScript 示例:**

```javascript
// moduleA.js
import { valueB } from './moduleB.js';
console.log('Module A is evaluating, valueB:', valueB);
export const valueA = 1;
```

```javascript
// moduleB.js
console.log('Module B is evaluating');
export const valueB = 2;
```

当 JavaScript 引擎执行 `import` 语句时，V8 内部就会创建 `SourceTextModule` 对象来表示这些模块。`InnerModuleEvaluation` 函数会按照依赖关系（moduleA 依赖 moduleB）的顺序评估这些模块。

对于包含 Top-Level Await 的模块：

```javascript
// asyncModule.js
console.log('Async module starting');
const data = await fetch('/data');
console.log('Async module fetched data:', await data.json());
export const result = 'done';
```

`ExecuteAsyncModule` 和相关的函数会处理这种异步模块的评估，确保 `await` 表达式完成后再继续执行。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

有一个模块 `moduleA`，它同步依赖于 `moduleB`。

* `moduleA` 的状态是 `kLinked`。
* `moduleB` 的状态是 `kLinked`。

**执行 `InnerModuleEvaluation(isolate, moduleA, &stack, &dfs_index)`:**

1. `moduleA` 的状态变为 `kEvaluating`。
2. `moduleA` 被添加到 `stack`。
3. 遍历 `moduleA` 的依赖，发现 `moduleB`。
4. 调用 `InnerModuleEvaluation(isolate, moduleB, &stack, &dfs_index)`。
5. `moduleB` 的状态变为 `kEvaluating`。
6. `moduleB` 被添加到 `stack`。
7. `moduleB` 没有依赖，执行 `moduleB` 的代码 (`ExecuteModule`)。
8. `moduleB` 的状态变为 `kEvaluated`。
9. 从 `stack` 中移除 `moduleB`。
10. 返回到 `moduleA` 的评估。
11. 执行 `moduleA` 的代码 (`ExecuteModule`)。
12. `moduleA` 的状态变为 `kEvaluated`。
13. 从 `stack` 中移除 `moduleA`。

**假设输出:**

* `moduleA` 的状态是 `kEvaluated`。
* `moduleB` 的状态是 `kEvaluated`。

**涉及用户常见的编程错误:**

* **循环依赖:** 如果 `moduleA` 导入 `moduleB`，而 `moduleB` 也导入 `moduleA`，就会形成循环依赖。`InnerModuleEvaluation` 中会检测到这种情况，并妥善处理，但可能会导致一些模块在初始化时值未定义。

   ```javascript
   // moduleA.js
   import { valueB } from './moduleB.js';
   export const valueA = valueB + 1; // 可能在 moduleB 初始化完成前访问

   // moduleB.js
   import { valueA } from './moduleA.js';
   export const valueB = valueA + 1;
   ```

* **未处理的 Promise rejection (在异步模块中):** 如果一个异步模块的 Top-Level Await 中有未处理的 Promise rejection，`AsyncModuleExecutionRejected` 会被调用，并且这个错误可能会传播，阻止模块的正常评估。

   ```javascript
   // asyncModuleWithError.js
   await Promise.reject('Something went wrong!'); // 未被 try...catch 包裹
   export const result = 'done';
   ```

**归纳一下它的功能 (第 2 部分):**

`v8/src/objects/source-text-module.cc` 的这一部分主要负责 **执行和管理 JavaScript 模块的评估过程**。它处理了同步和异步模块的不同执行路径，包括：

* **启动评估:**  `Evaluate` 函数负责开始模块的评估，并管理与评估结果相关的 Promise。
* **递归评估依赖:** `InnerModuleEvaluation` 实现了深度优先搜索，用于按照正确的顺序评估模块及其依赖。它能够处理循环依赖和区分同步/异步依赖。
* **同步模块执行:** `ExecuteModule` 函数负责执行同步模块的代码。
* **异步模块执行:** `ExecuteAsyncModule` 和 `InnerExecuteAsyncModule` 负责执行包含 Top-Level Await 的异步模块，并与 Promise 集成。
* **处理评估结果:** `AsyncModuleExecutionFulfilled` 和 `AsyncModuleExecutionRejected` 函数处理异步模块执行的成功和失败情况，并更新模块状态和传播结果。
* **错误处理:** `MaybeHandleEvaluationException` 负责捕获和记录模块评估过程中发生的错误。
* **状态管理:** 代码维护了模块在不同评估阶段的状态 (例如 `kEvaluating`, `kEvaluated`, `kErrored`)。
* **检测停滞的 Top-Level Await:** 提供了机制来检测由于循环依赖而卡住的异步模块。

总而言之，这部分代码是 V8 引擎实现 JavaScript 模块评估逻辑的关键组成部分，确保模块能够按照规范正确地加载、链接和执行，并处理各种可能的执行结果和错误情况。

### 提示词
```
这是目录为v8/src/objects/source-text-module.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/source-text-module.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ption)) {
    // a. For each Cyclic Module Record m in stack, do
    for (DirectHandle<SourceTextModule> descendant : *stack) {
      //   i. Assert: m.[[Status]] is EVALUATING.
      CHECK_EQ(descendant->status(), kEvaluating);
      //  ii. Set m.[[Status]] to EVALUATED.
      // iii. Set m.[[EvaluationError]] to result.
      descendant->RecordError(isolate, exception);
    }
    return true;
  }
  // If the exception was a termination exception, rejecting the promise
  // would resume execution, and our API contract is to return an empty
  // handle. The module's status should be set to kErrored and the
  // exception field should be set to `null`.
  RecordError(isolate, exception);
  for (DirectHandle<SourceTextModule> descendant : *stack) {
    descendant->RecordError(isolate, exception);
  }
  CHECK_EQ(status(), kErrored);
  CHECK_EQ(this->exception(), *isolate->factory()->null_value());
  return false;
}

// ES#sec-moduleevaluation
MaybeHandle<Object> SourceTextModule::Evaluate(
    Isolate* isolate, Handle<SourceTextModule> module) {
  CHECK(module->status() == kLinked || module->status() == kEvaluatingAsync ||
        module->status() == kEvaluated);

  // 5. Let stack be a new empty List.
  Zone zone(isolate->allocator(), ZONE_NAME);
  ZoneForwardList<Handle<SourceTextModule>> stack(&zone);
  unsigned dfs_index = 0;

  // 6. Let capability be ! NewPromiseCapability(%Promise%).
  Handle<JSPromise> capability = isolate->factory()->NewJSPromise();

  // 7. Set module.[[TopLevelCapability]] to capability.
  module->set_top_level_capability(*capability);
  DCHECK(IsJSPromise(module->top_level_capability()));

  // 8. Let result be InnerModuleEvaluation(module, stack, 0).
  // 9. If result is an abrupt completion, then
  v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
  try_catch.SetVerbose(false);
  try_catch.SetCaptureMessage(false);
  // TODO(verwaest): Return a bool from InnerModuleEvaluation instead?
  if (InnerModuleEvaluation(isolate, module, &stack, &dfs_index).is_null()) {
    if (!module->MaybeHandleEvaluationException(isolate, &stack)) return {};
    CHECK(try_catch.HasCaught());
    // d. Perform ! Call(capability.[[Reject]], undefined,
    //                   «result.[[Value]]»).
    JSPromise::Reject(capability, handle(module->exception(), isolate));
  } else {  // 10. Else,
    // a. Assert: module.[[Status]] is either EVALUATING-ASYNC or EVALUATED.
    CHECK_GE(module->status(), kEvaluatingAsync);

    // c. If module.[[AsyncEvaluation]] is false, then
    if (!module->HasAsyncEvaluationOrdinal()) {
      // i. Assert: module.[[Status]] is EVALUATED.
      DCHECK_EQ(module->status(), kEvaluated);

      // ii. Perform ! Call(capability.[[Resolve]], undefined,
      //                    «undefined»).
      JSPromise::Resolve(capability, isolate->factory()->undefined_value())
          .ToHandleChecked();
    }

    // d. Assert: stack is empty.
    DCHECK(stack.empty());
  }

  // 11. Return capability.[[Promise]].
  return capability;
}

// ES#sec-async-module-execution-fulfilled
Maybe<bool> SourceTextModule::AsyncModuleExecutionFulfilled(
    Isolate* isolate, Handle<SourceTextModule> module) {
  // 1. If module.[[Status]] is EVALUATED, then
  if (module->status() == kErrored) {
    // a. Assert: module.[[EvaluationError]] is not EMPTY.
    DCHECK(!IsTheHole(module->exception(), isolate));
    // b. Return UNUSED.
    return Just(true);
  }

  // 2. Assert: module.[[Status]] is EVALUATING-ASYNC.
  DCHECK_EQ(module->status(), kEvaluatingAsync);

  // 3. Assert: module.[[AsyncEvaluation]] is true.
  DCHECK(module->HasAsyncEvaluationOrdinal());

  // 4. Assert: module.[[EvaluationError]] is EMPTY.
  // (Done by step 2.)

  // 5. Set module.[[AsyncEvaluation]] to false.
  module->set_async_evaluation_ordinal(kAsyncEvaluateDidFinish);

  // 6. Set module.[[Status]] to EVALUATED.
  module->SetStatus(kEvaluated);

  // 7. If module.[[TopLevelCapability]] is not EMPTY, then
  if (!IsUndefined(module->top_level_capability(), isolate)) {
    //  a. Assert: module.[[CycleRoot]] is equal to module.
    DCHECK_EQ(*module->GetCycleRoot(isolate), *module);

    //   i. Perform ! Call(module.[[TopLevelCapability]].[[Resolve]], undefined,
    //                     «undefined»).
    Handle<JSPromise> capability(
        Cast<JSPromise>(module->top_level_capability()), isolate);
    JSPromise::Resolve(capability, isolate->factory()->undefined_value())
        .ToHandleChecked();
  }

  // 8. Let execList be a new empty List.
  Zone zone(isolate->allocator(), ZONE_NAME);
  AvailableAncestorsSet exec_list(&zone);

  // 9. Perform GatherAvailableAncestors(module, execList).
  GatherAvailableAncestors(isolate, &zone, module, &exec_list);

  // 10. Let sortedExecList be a List of elements that are the elements of
  //    execList, in the order in which they had their [[AsyncEvaluation]]
  //    fields set to true in InnerModuleEvaluation.
  //
  // This step is implemented by AvailableAncestorsSet, which is a set
  // ordered on async_evaluation_ordinal.

  // 11. Assert: All elements of sortedExecList have their [[AsyncEvaluation]]
  //    field set to true, [[PendingAsyncDependencies]] field set to 0 and
  //    [[EvaluationError]] field set to undefined.
#ifdef DEBUG
  for (DirectHandle<SourceTextModule> m : exec_list) {
    DCHECK(m->HasAsyncEvaluationOrdinal());
    DCHECK(!m->HasPendingAsyncDependencies());
    DCHECK_NE(m->status(), kErrored);
  }
#endif

  // 12. For each Module m of sortedExecList, do
  for (DirectHandle<SourceTextModule> m : exec_list) {
    if (m->status() == kErrored) {  // a. If m.[[Status]] is EVALUATED, then
      // i. Assert: m.[[EvaluationError]] is not EMPTY.
      DCHECK(!IsTheHole(m->exception(), isolate));
    } else if (m->has_toplevel_await()) {  // b. Else if m.[[HasTLA]] is true,
                                           // then
      // i. Perform ExecuteAsyncModule(m).
      //
      // The execution may have been terminated and can not be resumed, so just
      // raise the exception.
      MAYBE_RETURN(ExecuteAsyncModule(isolate, m), Nothing<bool>());
    } else {  // c. Else,
      // i. Let result be m.ExecuteModule().
      Handle<Object> unused_result;
      MaybeHandle<Object> exception;
      // ii. If result is an abrupt completion, then
      if (!ExecuteModule(isolate, m, &exception).ToHandle(&unused_result)) {
        // 1. Perform AsyncModuleExecutionRejected(m, result.[[Value]]).
        AsyncModuleExecutionRejected(isolate, m, exception.ToHandleChecked());
      } else {  // iii. Else,
        // 1. Set m.[[AsyncEvaluation]] to false.
        m->set_async_evaluation_ordinal(kAsyncEvaluateDidFinish);

        // 2. Set m.[[Status]] to EVALUATED.
        m->SetStatus(kEvaluated);

        // 3. If m.[[TopLevelCapability]] is not EMPTY, then
        if (!IsUndefined(m->top_level_capability(), isolate)) {
          // a. Assert: m.[[CycleRoot]] and m are the same Module Record.
          DCHECK_EQ(*m->GetCycleRoot(isolate), *m);

          // b. Perform ! Call(m.[[TopLevelCapability]].[[Resolve]], undefined,
          //    « undefined »).
          Handle<JSPromise> capability(
              Cast<JSPromise>(m->top_level_capability()), isolate);
          JSPromise::Resolve(capability, isolate->factory()->undefined_value())
              .ToHandleChecked();
        }
      }
    }
  }

  // Return UNUSED.
  return Just(true);
}

// ES#sec-async-module-execution-rejected
void SourceTextModule::AsyncModuleExecutionRejected(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    Handle<Object> exception) {
  // 1. If module.[[Status]] is EVALUATED, then
  if (module->status() == kErrored) {
    // a. Assert: module.[[EvaluationError]] is not empty.
    DCHECK(!IsTheHole(module->exception(), isolate));
    // b. Return UNUSED.
    return;
  }

  DCHECK(isolate->is_catchable_by_javascript(*exception));
  // 2. Assert: module.[[Status]] is EVALUATING-ASYNC.
  CHECK_EQ(module->status(), kEvaluatingAsync);
  // 3. Assert: module.[[AsyncEvaluation]] is true.
  DCHECK(module->HasAsyncEvaluationOrdinal());
  // 4. Assert: module.[[EvaluationError]] is EMPTY.
  DCHECK(IsTheHole(module->exception(), isolate));

  // 5. Set module.[[EvaluationError]] to ThrowCompletion(error).
  module->RecordError(isolate, *exception);

  // 6. Set module.[[Status]] to EVALUATED.
  // (We have a status for kErrored, so don't set to kEvaluated.)
  module->set_async_evaluation_ordinal(kAsyncEvaluateDidFinish);

  // 7. For each Cyclic Module Record m of module.[[AsyncParentModules]], do
  for (int i = 0; i < module->AsyncParentModuleCount(); i++) {
    // a. Perform AsyncModuleExecutionRejected(m, error).
    DirectHandle<SourceTextModule> m = module->GetAsyncParentModule(isolate, i);
    AsyncModuleExecutionRejected(isolate, m, exception);
  }

  // 8. If module.[[TopLevelCapability]] is not EMPTY, then
  if (!IsUndefined(module->top_level_capability(), isolate)) {
    // a. Assert: module.[[CycleRoot]] and module are the same Module Record.
    DCHECK_EQ(*module->GetCycleRoot(isolate), *module);

    //  b. Perform ! Call(module.[[TopLevelCapability]].[[Reject]],
    //                    undefined, «error»).
    Handle<JSPromise> capability(
        Cast<JSPromise>(module->top_level_capability()), isolate);
    JSPromise::Reject(capability, exception);
  }

  // 9. Return UNUSED.
}

// static
Maybe<bool> SourceTextModule::ExecuteAsyncModule(
    Isolate* isolate, DirectHandle<SourceTextModule> module) {
  // 1. Assert: module.[[Status]] is either EVALUATING or EVALUATING-ASYNC.
  CHECK(module->status() == kEvaluating ||
        module->status() == kEvaluatingAsync);

  // 2. Assert: module.[[HasTLA]] is true.
  DCHECK(module->has_toplevel_await());

  // 3. Let capability be ! NewPromiseCapability(%Promise%).
  Handle<JSPromise> capability = isolate->factory()->NewJSPromise();

  Handle<Context> execute_async_module_context =
      isolate->factory()->NewBuiltinContext(
          isolate->native_context(),
          ExecuteAsyncModuleContextSlots::kContextLength);
  execute_async_module_context->set(ExecuteAsyncModuleContextSlots::kModule,
                                    *module);

  // 4. Let fulfilledClosure be a new Abstract Closure with no parameters that
  //    captures module and performs the following steps when called:
  //   a. Perform AsyncModuleExecutionFulfilled(module).
  //   b. Return undefined.
  // 5. Let onFulfilled be CreateBuiltinFunction(fulfilledClosure, 0, "", « »).
  Handle<JSFunction> on_fulfilled =
      Factory::JSFunctionBuilder{
          isolate,
          isolate->factory()
              ->source_text_module_execute_async_module_fulfilled_sfi(),
          execute_async_module_context}
          .Build();

  // 6. Let rejectedClosure be a new Abstract Closure with parameters (error)
  //    that captures module and performs the following steps when called:
  //   a. Perform AsyncModuleExecutionRejected(module, error).
  //   b. Return undefined.
  // 7. Let onRejected be CreateBuiltinFunction(rejectedClosure, 0, "", « »).
  Handle<JSFunction> on_rejected =
      Factory::JSFunctionBuilder{
          isolate,
          isolate->factory()
              ->source_text_module_execute_async_module_rejected_sfi(),
          execute_async_module_context}
          .Build();

  // 8. Perform ! PerformPromiseThen(capability.[[Promise]],
  //                                 onFulfilled, onRejected).
  Handle<Object> argv[] = {on_fulfilled, on_rejected};
  if (V8_UNLIKELY(Execution::CallBuiltin(isolate, isolate->promise_then(),
                                         capability, arraysize(argv), argv)
                      .is_null())) {
    // TODO(349961173): We assume the builtin call can only fail with a
    // termination exception. If this check fails in the wild investigate why
    // the call fails. Otherwise turn this into a DCHECK in the future.
    CHECK(isolate->is_execution_terminating());
    return Nothing<bool>();
  }

  // 9. Perform ! module.ExecuteModule(capability).
  // Note: In V8 we have broken module.ExecuteModule into
  // ExecuteModule for synchronous module execution and
  // InnerExecuteAsyncModule for asynchronous execution.
  MaybeHandle<Object> ret =
      InnerExecuteAsyncModule(isolate, module, capability);
  if (ret.is_null()) {
    // The evaluation of async module cannot throw a JavaScript observable
    // exception.
    DCHECK_IMPLIES(v8_flags.strict_termination_checks,
                   isolate->is_execution_terminating());
    return Nothing<bool>();
  }

  // 10. Return UNUSED.
  return Just<bool>(true);
}

MaybeHandle<Object> SourceTextModule::InnerExecuteAsyncModule(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    DirectHandle<JSPromise> capability) {
  // If we have an async module, then it has an associated
  // JSAsyncFunctionObject, which we then evaluate with the passed in promise
  // capability.
  Handle<JSAsyncFunctionObject> async_function_object(
      Cast<JSAsyncFunctionObject>(module->code()), isolate);
  async_function_object->set_promise(*capability);
  Handle<JSFunction> resume(
      isolate->native_context()->async_module_evaluate_internal(), isolate);
  return Execution::TryCall(isolate, resume, async_function_object, 0, nullptr,
                            Execution::MessageHandling::kKeepPending, nullptr);
}

MaybeHandle<Object> SourceTextModule::ExecuteModule(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    MaybeHandle<Object>* exception_out) {
  // Synchronous modules have an associated JSGeneratorObject.
  Handle<JSGeneratorObject> generator(Cast<JSGeneratorObject>(module->code()),
                                      isolate);
  Handle<JSFunction> resume(
      isolate->native_context()->generator_next_internal(), isolate);
  Handle<Object> result;

  if (!Execution::TryCall(isolate, resume, generator, 0, nullptr,
                          Execution::MessageHandling::kKeepPending,
                          exception_out)
           .ToHandle(&result)) {
    return {};
  }
  DCHECK(
      Object::BooleanValue(Cast<JSIteratorResult>(*result)->done(), isolate));
  return handle(Cast<JSIteratorResult>(*result)->value(), isolate);
}

MaybeHandle<Object> SourceTextModule::InnerModuleEvaluation(
    Isolate* isolate, Handle<SourceTextModule> module,
    ZoneForwardList<Handle<SourceTextModule>>* stack, unsigned* dfs_index) {
  STACK_CHECK(isolate, MaybeHandle<Object>());
  int module_status = module->status();
  // InnerModuleEvaluation(module, stack, index)

  // 2. If module.[[Status]] is either EVALUATING-ASYNC or EVALUATED, then
  if (module_status == kEvaluatingAsync || module_status == kEvaluating ||
      module_status == kEvaluated) {
    // a. If module.[[EvaluationError]] is undefined, return index.
    // (We return undefined instead)
    //
    // 3. If module.[[Status]] is EVALUATING, return index.
    // (Out of order)
    return isolate->factory()->undefined_value();
  } else if (module_status == kErrored) {
    // b. Otherwise return module.[[EvaluationError]].
    // (We throw on isolate and return a MaybeHandle<Object> instead)
    isolate->Throw(module->exception());
    return MaybeHandle<Object>();
  }

  // 4. Assert: module.[[Status]] is LINKED.
  CHECK_EQ(module_status, kLinked);

  DirectHandle<FixedArray> module_requests;
  DirectHandle<FixedArray> requested_modules;

  {
    DisallowGarbageCollection no_gc;
    Tagged<SourceTextModule> raw_module = *module;
    // 5. Set module.[[Status]] to EVALUATING.
    raw_module->SetStatus(kEvaluating);

    // 6. Set module.[[DFSIndex]] to index.
    raw_module->set_dfs_index(*dfs_index);

    // 7. Set module.[[DFSAncestorIndex]] to index.
    raw_module->set_dfs_ancestor_index(*dfs_index);

    // 8. Set module.[[PendingAsyncDependencies]] to 0.
    DCHECK(!raw_module->HasPendingAsyncDependencies());

    // 9. Set index to index + 1.
    (*dfs_index)++;

    // 10. Append module to stack.
    stack->push_front(module);

    // Recursion.
    module_requests =
        direct_handle(raw_module->info()->module_requests(), isolate);
    requested_modules = direct_handle(raw_module->requested_modules(), isolate);
  }

  // 11. For each ModuleRequest Record required of module.[[RequestedModules]],
  for (int i = 0, length = requested_modules->length(); i < length; ++i) {
    DirectHandle<ModuleRequest> module_request(
        Cast<ModuleRequest>(module_requests->get(i)), isolate);
    if (module_request->phase() != ModuleImportPhase::kEvaluation) {
      continue;
    }
    // b. If requiredModule.[[Phase]] is evaluation, then
    Handle<Module> requested_module(Cast<Module>(requested_modules->get(i)),
                                    isolate);
    // c. If requiredModule is a Cyclic Module Record, then
    if (IsSourceTextModule(*requested_module)) {
      // b. Set index to ? InnerModuleEvaluation(requiredModule, stack, index).
      // (Out of order because InnerModuleEvaluation is type-driven.)
      Handle<SourceTextModule> required_module(
          Cast<SourceTextModule>(*requested_module), isolate);
      RETURN_ON_EXCEPTION(
          isolate,
          InnerModuleEvaluation(isolate, required_module, stack, dfs_index));
      int required_module_status = required_module->status();

      // i. Assert: requiredModule.[[Status]] is one of EVALUATING,
      //    EVALUATING-ASYNC, or EVALUATED.
      // (We also assert the module cannot be errored, because if it was
      //  we would have already returned from InnerModuleEvaluation)
      CHECK_GE(required_module_status, kEvaluating);
      CHECK_NE(required_module_status, kErrored);

      // ii. Assert: requiredModule.[[Status]] is EVALUATING if and only if
      //     requiredModule is in stack.
      SLOW_DCHECK((requested_module->status() == kEvaluating) ==
                  std::count_if(stack->begin(), stack->end(),
                                [&](DirectHandle<Module> m) {
                                  return *m == *requested_module;
                                }));

      // iii. If requiredModule.[[Status]] is EVALUATING, then
      if (required_module_status == kEvaluating) {
        // 1. Set module.[[DFSAncestorIndex]] to
        //    min(module.[[DFSAncestorIndex]],
        //        requiredModule.[[DFSAncestorIndex]]).
        module->set_dfs_ancestor_index(
            std::min(module->dfs_ancestor_index(),
                     required_module->dfs_ancestor_index()));
      } else {  // iv. Else,
        // 1. Set requiredModule to requiredModule.[[CycleRoot]].
        required_module = required_module->GetCycleRoot(isolate);
        required_module_status = required_module->status();

        // 2. Assert: requiredModule.[[Status]] is either EVALUATING-ASYNC or
        //    EVALUATED.
        CHECK_GE(required_module_status, kEvaluatingAsync);

        // 3. If requiredModule.[[EvaluationError]] is not EMPTY,
        //    return ? module.[[EvaluationError]].

        // (If there was an exception on the original required module we would
        // have already returned. This check handles the case where the
        // AsyncCycleRoot has an error. Instead of returning the exception, we
        // throw on isolate and return a MaybeHandle<Object>.)
        if (required_module_status == kErrored) {
          isolate->Throw(required_module->exception());
          return MaybeHandle<Object>();
        }
      }
      // v. If requiredModule.[[AsyncEvaluation]] is true, then
      if (required_module->HasAsyncEvaluationOrdinal()) {
        // 1. Set module.[[PendingAsyncDependencies]] to
        //    module.[[PendingAsyncDependencies]] + 1.
        module->IncrementPendingAsyncDependencies();

        // 2. Append module to requiredModule.[[AsyncParentModules]].
        AddAsyncParentModule(isolate, required_module, module);
      }
    } else {
      // b. Set index to ? InnerModuleEvaluation(requiredModule, stack, index).
      // (Out of order because InnerModuleEvaluation is type-driven.)
      RETURN_ON_EXCEPTION(isolate, Module::Evaluate(isolate, requested_module));
    }
  }

  // The spec returns the module index for proper numbering of dependencies.
  // However, we pass the module index by pointer instead.
  //
  // Before async modules v8 returned the value result from calling next
  // on the module's implicit iterator. We preserve this behavior for
  // synchronous modules, but return undefined for AsyncModules.
  Handle<Object> result = isolate->factory()->undefined_value();

  // 12. If module.[[PendingAsyncDependencies]] > 0 or module.[[HasTLA]] is
  //     true, then
  if (module->HasPendingAsyncDependencies() || module->has_toplevel_await()) {
    // a. Assert: module.[[AsyncEvaluation]] is false and was never previously
    //    set to true.
    DCHECK_EQ(module->async_evaluation_ordinal(), kNotAsyncEvaluated);

    // b. Set module.[[AsyncEvaluation]] to true.
    // c. NOTE: The order in which module records have their [[AsyncEvaluation]]
    //    fields transition to true is significant.
    module->set_async_evaluation_ordinal(
        isolate->NextModuleAsyncEvaluationOrdinal());

    // c. If module.[[PendingAsyncDependencies]] = 0, perform
    //    ExecuteAsyncModule(module).
    // The execution may have been terminated and can not be resumed, so just
    // raise the exception.
    if (!module->HasPendingAsyncDependencies()) {
      MAYBE_RETURN(SourceTextModule::ExecuteAsyncModule(isolate, module),
                   MaybeHandle<Object>());
    }
  } else {  // 13. Else,
    // a. Perform ? module.ExecuteModule().
    MaybeHandle<Object> exception;
    Handle<Object> result;
    if (!ExecuteModule(isolate, module, &exception).ToHandle(&result)) {
      if (!isolate->is_execution_terminating()) {
        isolate->Throw(*exception.ToHandleChecked());
      }
      return result;
    }
  }

  CHECK(MaybeTransitionComponent(isolate, module, stack, kEvaluated));
  return result;
}

void SourceTextModule::Reset(Isolate* isolate,
                             DirectHandle<SourceTextModule> module) {
  Factory* factory = isolate->factory();

  DCHECK(IsTheHole(module->import_meta(kAcquireLoad), isolate));

  DirectHandle<FixedArray> regular_exports =
      factory->NewFixedArray(module->regular_exports()->length());
  DirectHandle<FixedArray> regular_imports =
      factory->NewFixedArray(module->regular_imports()->length());
  DirectHandle<FixedArray> requested_modules =
      factory->NewFixedArray(module->requested_modules()->length());

  DisallowGarbageCollection no_gc;
  Tagged<SourceTextModule> raw_module = *module;
  if (raw_module->status() == kLinking) {
    raw_module->set_code(Cast<JSFunction>(raw_module->code())->shared());
  }
  raw_module->set_regular_exports(*regular_exports);
  raw_module->set_regular_imports(*regular_imports);
  raw_module->set_requested_modules(*requested_modules);
  raw_module->set_dfs_index(-1);
  raw_module->set_dfs_ancestor_index(-1);
}

std::vector<std::tuple<Handle<SourceTextModule>, Handle<JSMessageObject>>>
SourceTextModule::GetStalledTopLevelAwaitMessages(Isolate* isolate) {
  Zone zone(isolate->allocator(), ZONE_NAME);
  UnorderedModuleSet visited(&zone);
  std::vector<std::tuple<Handle<SourceTextModule>, Handle<JSMessageObject>>>
      result;
  std::vector<Handle<SourceTextModule>> stalled_modules;
  InnerGetStalledTopLevelAwaitModule(isolate, &visited, &stalled_modules);
  size_t stalled_modules_size = stalled_modules.size();
  if (stalled_modules_size == 0) return result;

  result.reserve(stalled_modules_size);
  for (size_t i = 0; i < stalled_modules_size; ++i) {
    Handle<SourceTextModule> found = stalled_modules[i];
    CHECK(IsJSGeneratorObject(found->code()));
    DirectHandle<JSGeneratorObject> code(Cast<JSGeneratorObject>(found->code()),
                                         isolate);
    Handle<SharedFunctionInfo> shared(found->GetSharedFunctionInfo(), isolate);
    Handle<Object> script(shared->script(), isolate);
    MessageLocation location =
        MessageLocation(Cast<Script>(script), shared, code->code_offset());
    Handle<JSMessageObject> message = MessageHandler::MakeMessageObject(
        isolate, MessageTemplate::kTopLevelAwaitStalled, &location,
        isolate->factory()->null_value());
    result.push_back(std::make_tuple(found, message));
  }
  return result;
}

void SourceTextModule::InnerGetStalledTopLevelAwaitModule(
    Isolate* isolate, UnorderedModuleSet* visited,
    std::vector<Handle<SourceTextModule>>* result) {
  DisallowGarbageCollection no_gc;
  // If it's a module that is waiting for no other modules but itself,
  // it's what we are looking for. Add it to the results.
  if (!HasPendingAsyncDependencies() && HasAsyncEvaluationOrdinal()) {
    DCHECK(HasAsyncEvaluationOrdinal());
    result->push_back(handle(*this, isolate));
    return;
  }
  // The module isn't what we are looking for, continue looking in the graph.
  Tagged<FixedArray> requests = info()->module_requests();
  Tagged<FixedArray> requested = requested_modules();
  int length = requested->length();
  for (int i = 0; i < length; ++i) {
    Tagged<ModuleRequest> request = Cast<ModuleRequest>(requests->get(i));
    if (request->phase() != ModuleImportPhase::kEvaluation) {
      continue;
    }
    Tagged<Module> requested_module = Cast<Module>(requested->get(i));
    if (IsSourceTextModule(requested_module) &&
        visited->insert(handle(requested_module, isolate)).second) {
      Tagged<SourceTextModule> source_text_module =
          Cast<SourceTextModule>(requested_module);
      source_text_module->InnerGetStalledTopLevelAwaitModule(isolate, visited,
                                                             result);
    }
  }
}

}  // namespace internal
}  // namespace v8
```