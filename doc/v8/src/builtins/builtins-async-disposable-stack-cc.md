Response:
Let's break down the thought process for analyzing this V8 source code.

**1. Initial Scan and Keyword Recognition:**

* The first thing I notice is the file name: `builtins-async-disposable-stack.cc`. Keywords like "builtins," "async," and "disposable stack" immediately tell me this code is part of V8's implementation of a language feature related to asynchronous resource management. The `.cc` extension confirms it's C++ code.
* I then scan the `#include` directives. These point to various V8 internal headers related to API interaction (`api.h`), logging (`base/logging.h`), macros (`base/macros.h`), built-in function utilities (`builtins-utils-inl.h`), the builtins framework itself (`builtins.h`), execution context (`execution/isolate.h`), object handling (`handles/maybe-handles.h`, `objects/*`), and roots (`roots/roots.h`). This reinforces that it's core V8 functionality.

**2. Namespace Analysis:**

* The code is within the `v8::internal` namespace, indicating it's part of V8's internal implementation details, not exposed directly to JavaScript developers.

**3. BUILTIN Macro Analysis:**

* The repeated use of the `BUILTIN` macro is a strong indicator that these are implementations of built-in JavaScript functions or internal operations. Each `BUILTIN` block represents a distinct function exposed to the JavaScript engine.

**4. Function-by-Function Breakdown (Iterative Process):**

For each `BUILTIN` function, I follow a similar pattern:

* **Name Recognition:** The name of the `BUILTIN` often gives a strong hint about its purpose (e.g., `AsyncDisposableStackOnFulfilled`, `AsyncDisposableStackConstructor`, `AsyncDisposableStackPrototypeUse`).
* **Context Access:**  Notice the recurring pattern of accessing the `isolate->context()`. This suggests that these builtins operate within a specific execution context and likely interact with context-local data. The use of `JSDisposableStackBase::AsyncDisposableStackContextSlots` further confirms this.
* **Object Handling:**  Look for the creation, casting, and manipulation of V8's internal object types like `JSDisposableStackBase`, `JSPromise`, `JSAsyncDisposableStack`, `JSFunction`, `Map`, etc. This reveals the data structures involved.
* **Core Logic Identification:**  Focus on the key operations within each function. For example:
    * `AsyncDisposableStackOnFulfilled` and `AsyncDisposableStackOnRejected`:  These seem to handle the resolution or rejection of promises associated with asynchronous disposal. The call to `JSAsyncDisposableStack::NextDisposeAsyncIteration` is significant.
    * `AsyncDisposeFromSyncDispose`: This deals with adapting synchronous `dispose` methods for asynchronous disposal. The `TryCatch` block hints at error handling.
    * `AsyncDisposableStackConstructor`: This is the constructor for the `AsyncDisposableStack` object, involving map creation and initialization of internal slots.
    * Prototype methods (`Use`, `DisposeAsync`, `GetDisposed`, `Adopt`, `Defer`, `Move`): These implement the core API of the `AsyncDisposableStack` as proposed by the explicit resource management proposal. I look for specific operations like adding resources (`AddDisposableResource`), checking the disposal state, and moving resources between stacks.
* **Error Handling:** Pay attention to `THROW_NEW_ERROR_RETURN_FAILURE`, `NewTypeError`, `NewReferenceError`, and the `DCHECK` macros. These indicate how the code handles invalid inputs or unexpected states.
* **ECMAScript Specification References:** The comments frequently mention specific sections of the "explicit resource management" TC39 proposal. This is crucial for understanding the intended behavior and linking the C++ code to the JavaScript specification.

**5. Connecting to JavaScript:**

* Based on the function names and the operations, I start forming a mental model of how these builtins relate to JavaScript code. For instance, the constructor clearly corresponds to `new AsyncDisposableStack()`. The prototype methods map directly to methods on the `AsyncDisposableStack.prototype`.
* I use the specification references to confirm the mapping and understand the intended semantics.
* I then formulate JavaScript examples that would trigger these builtins. This involves understanding the syntax and behavior of `using` declarations and the `AsyncDisposableStack` class.

**6. Identifying Potential Errors and Logic:**

* I consider scenarios where the JavaScript code might misuse the API. For example, calling methods after the stack has been disposed leads to `ReferenceError`. Providing non-callable arguments to `adopt` or `defer` results in `TypeError`.
* I analyze the control flow within the C++ code to understand the logic. For example, the `AsyncDisposeFromSyncDispose` function demonstrates how a synchronous `dispose` method is wrapped in a promise.

**7. Structuring the Output:**

Finally, I organize the findings into the requested categories:

* **Functionality:** A high-level summary of the file's purpose.
* **Torque:** Checking for `.tq` extension (in this case, it's `.cc`).
* **JavaScript Relation:** Providing clear JavaScript examples.
* **Logic Inference:**  Explaining the flow of specific functions with hypothetical inputs and outputs.
* **Common Errors:**  Illustrating typical programming mistakes.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:** I might initially misunderstand the purpose of a function. Reading the comments and the specification links helps correct these misunderstandings.
* **Missing Connections:** Sometimes, the connection between a C++ builtin and its JavaScript counterpart isn't immediately obvious. Looking at the specification and the names of the builtins helps bridge this gap.
* **Overlooking Details:**  On a first pass, I might miss subtle aspects of the code, like the specific error types being thrown. A second, more careful reading helps catch these details.

By following this structured and iterative approach, combining code analysis with knowledge of JavaScript and the relevant specifications, I can effectively analyze and explain the functionality of this V8 source code.
好的，让我们来分析一下 `v8/src/builtins/builtins-async-disposable-stack.cc` 这个 V8 源代码文件的功能。

**功能概览**

这个 C++ 文件定义了 V8 引擎中用于实现 ECMAScript 提议的“显式资源管理”（Explicit Resource Management）中的 `AsyncDisposableStack` 功能的内置函数（builtins）。 `AsyncDisposableStack` 允许开发者以异步的方式管理资源的生命周期，确保在不再需要时释放这些资源，即使在异步操作中也能可靠地执行清理操作。

**详细功能分解**

文件中定义了多个 `BUILTIN` 宏，每个宏对应一个 JavaScript 可访问的 `AsyncDisposableStack` 的方法或内部操作。以下是这些内置函数的功能列表：

* **`AsyncDisposableStackOnFulfilled` 和 `AsyncDisposableStackOnRejected`:** 这两个内置函数是内部的回调函数，用于处理 `AsyncDisposableStack` 中异步 dispose 过程的 Promise 的完成（fulfilled）和拒绝（rejected）状态。它们负责驱动异步清理过程的下一步。

* **`AsyncDisposeFromSyncDispose`:**  这个内置函数用于处理当一个对象只有同步的 `dispose` 方法，但在 `AsyncDisposableStack` 中被要求进行异步 dispose 时的情况。它会将同步的 `dispose` 调用包装在一个 Promise 中，使其可以被异步地处理。

* **`AsyncDisposableStackConstructor`:** 这是 `AsyncDisposableStack` 类的构造函数。它负责创建 `AsyncDisposableStack` 的实例，并初始化其内部状态，包括 `AsyncDisposableState` 和 `DisposeCapability`。

* **`AsyncDisposableStackPrototypeUse`:**  实现了 `AsyncDisposableStack.prototype.use` 方法。这个方法用于向 `AsyncDisposableStack` 添加需要被异步清理的资源。它会检查资源是否具有异步的 `[Symbol.asyncDispose]` 方法，或者同步的 `[Symbol.dispose]` 方法，并将其添加到内部的资源列表中。

* **`AsyncDisposableStackPrototypeDisposeAsync`:** 实现了 `AsyncDisposableStack.prototype.disposeAsync` 方法。这个方法会触发 `AsyncDisposableStack` 中所有已添加资源的异步清理过程。它会返回一个 Promise，该 Promise 在所有资源的清理完成后 resolve。

* **`AsyncDisposableStackPrototypeGetDisposed`:** 实现了 `AsyncDisposableStack.prototype` 的 `disposed` getter 属性。它返回一个布尔值，指示 `AsyncDisposableStack` 是否已经被 dispose。

* **`AsyncDisposableStackPrototypeAdopt`:** 实现了 `AsyncDisposableStack.prototype.adopt` 方法。这个方法允许开发者接管一个外部资源的异步清理责任，并将其纳入 `AsyncDisposableStack` 的管理。它接收一个值和一个异步的 dispose 回调函数。

* **`AsyncDisposableStackPrototypeDefer`:** 实现了 `AsyncDisposableStack.prototype.defer` 方法。这个方法允许开发者注册一个在 `AsyncDisposableStack` 被 dispose 时执行的异步回调函数，而不需要关联特定的资源。

* **`AsyncDisposableStackPrototypeMove`:** 实现了 `AsyncDisposableStack.prototype.move` 方法。这个方法允许开发者将一个 `AsyncDisposableStack` 的资源管理权转移到另一个新的 `AsyncDisposableStack` 实例。

**关于文件后缀 `.cc` 和 Torque**

文件后缀是 `.cc`，这表明它是一个标准的 C++ 源代码文件。如果文件以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内置函数的领域特定语言。

**与 JavaScript 功能的关系及示例**

这个文件中的 C++ 代码直接实现了 JavaScript 中的 `AsyncDisposableStack` 类的行为。以下是一些 JavaScript 示例，展示了这些内置函数在幕后是如何工作的：

```javascript
// 创建一个 AsyncDisposableStack 实例
const stack = new AsyncDisposableStack();

// 定义一个需要异步清理的资源
const resource = {
  async [Symbol.asyncDispose]() {
    console.log('异步清理资源');
    await new Promise(resolve => setTimeout(resolve, 100));
  }
};

// 使用 use 方法添加资源
stack.use(resource);

// 定义一个只有同步 dispose 方法的资源
const syncResource = {
  [Symbol.dispose]() {
    console.log('同步清理资源');
  }
};

// 使用 use 方法添加同步资源，V8 会自动处理
stack.use(syncResource);

// 使用 adopt 方法接管外部资源的清理
let externalState = { isCleaned: false };
stack.adopt(externalState, async (state) => {
  console.log('异步清理外部状态');
  await new Promise(resolve => setTimeout(resolve, 50));
  state.isCleaned = true;
});

// 使用 defer 方法注册一个异步清理回调
stack.defer(async () => {
  console.log('异步执行 deferred 清理');
  await new Promise(resolve => setTimeout(resolve, 25));
});

// 异步 dispose stack
async function disposeStack() {
  console.log('开始 dispose stack');
  await stack.disposeAsync();
  console.log('stack 已 dispose，外部状态是否清理:', externalState.isCleaned);
  console.log('stack.disposed 状态:', stack.disposed);
}

disposeStack();

// 使用 move 方法转移资源管理权
async function moveStack() {
  const stack1 = new AsyncDisposableStack();
  const resource1 = { async [Symbol.asyncDispose]() { console.log('清理资源 1'); } };
  stack1.use(resource1);

  const stack2 = stack1.move();
  console.log('资源已转移到 stack2');
  await stack2.disposeAsync(); // 只会清理 resource1
  console.log('stack2 已 dispose');
  console.log('stack1.disposed 状态:', stack1.disposed); // stack1 已经被 dispose 了
}

moveStack();
```

**代码逻辑推理 (假设输入与输出)**

假设我们有以下 JavaScript 代码：

```javascript
async function testDispose() {
  const stack = new AsyncDisposableStack();
  let isDisposed = false;
  const resource = {
    async [Symbol.asyncDispose]() {
      console.log('资源正在被清理');
      await new Promise(resolve => setTimeout(resolve, 50));
      isDisposed = true;
      return '清理完成';
    }
  };
  stack.use(resource);
  console.log('开始 dispose');
  const result = await stack.disposeAsync();
  console.log('dispose 完成, 结果:', result);
  console.log('资源是否被清理:', isDisposed);
}

testDispose();
```

**推断的输入与输出：**

* **输入:**  执行 `testDispose()` 函数。
* **在 `AsyncDisposableStackPrototypeDisposeAsync` 内置函数中:**
    * `asyncDisposableStack` 指向 `stack` 实例。
    * `promise` 是为 `disposeAsync` 操作创建的新的 Promise。
* **在 `JSAsyncDisposableStack::NextDisposeAsyncIteration` (被 `AsyncDisposableStackPrototypeDisposeAsync` 调用) 中:**
    * V8 会检查 `stack` 中是否有待清理的资源。
    * 它会找到 `resource` 对象及其 `[Symbol.asyncDispose]` 方法。
    * V8 会调用 `resource[Symbol.asyncDispose]()`。
* **在 `AsyncDisposableStackOnFulfilled` 内置函数中 (当 `resource[Symbol.asyncDispose]()` 的 Promise 完成时):**
    *  `stack` 指向 `stack` 实例。
    *  `promise` 指向 `disposeAsync` 返回的 Promise。
    *  `args` 中包含 `resource[Symbol.asyncDispose]()` 的返回值 `'清理完成'`。
    *  V8 会将 `'清理完成'` 作为 `disposeAsync` Promise 的 resolve 值。
* **输出:**
    ```
    开始 dispose
    资源正在被清理
    dispose 完成, 结果: 清理完成
    资源是否被清理: true
    ```

**用户常见的编程错误**

1. **在 `AsyncDisposableStack` 已经 dispose 后尝试使用 `use`、`adopt` 或 `defer`:** 这会导致抛出 `ReferenceError`，因为堆栈的状态已经变为已释放，不再接受新的资源或回调。

   ```javascript
   const stack = new AsyncDisposableStack();
   await stack.disposeAsync();
   stack.use({}); // 抛出 ReferenceError
   ```

2. **向 `adopt` 方法传递不可调用的 `onDisposeAsync` 参数:** 这会导致抛出 `TypeError`。

   ```javascript
   const stack = new AsyncDisposableStack();
   stack.adopt({}, 'not a function'); // 抛出 TypeError
   ```

3. **假设同步的 `dispose` 方法会自动变为异步:**  `AsyncDisposableStack` 能够处理同步的 `dispose` 方法，但开发者需要理解这仍然会在一个微任务中执行，而不是真正的并发异步操作。

4. **在 `disposeAsync` 完成之前就假设资源已经被清理:**  `disposeAsync` 返回一个 Promise，资源清理是异步发生的。必须等待 Promise resolve 后才能确保所有资源都已清理完毕。

5. **忘记处理 `disposeAsync` 返回的 Promise 的 rejection:** 如果资源的异步 dispose 方法抛出错误，`disposeAsync` 返回的 Promise 会被 reject。开发者应该使用 `.catch()` 或 `try...catch` 来处理这些错误。

通过理解这些内置函数的功能和潜在的错误，开发者可以更好地利用 `AsyncDisposableStack` 来管理异步环境中的资源，避免资源泄漏和提高代码的可靠性。

Prompt: 
```
这是目录为v8/src/builtins/builtins-async-disposable-stack.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-async-disposable-stack.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/execution/isolate.h"
#include "src/handles/maybe-handles.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-disposable-stack-inl.h"
#include "src/objects/js-disposable-stack.h"
#include "src/objects/js-objects.h"
#include "src/objects/js-promise-inl.h"
#include "src/objects/js-promise.h"
#include "src/objects/objects.h"
#include "src/roots/roots.h"

namespace v8 {
namespace internal {

BUILTIN(AsyncDisposableStackOnFulfilled) {
  HandleScope scope(isolate);

  DirectHandle<JSDisposableStackBase> stack(
      Cast<JSDisposableStackBase>(isolate->context()->get(static_cast<int>(
          JSDisposableStackBase::AsyncDisposableStackContextSlots::kStack))),
      isolate);
  Handle<JSPromise> promise(
      Cast<JSPromise>(isolate->context()->get(static_cast<int>(
          JSDisposableStackBase::AsyncDisposableStackContextSlots::
              kOuterPromise))),
      isolate);

  MAYBE_RETURN(JSAsyncDisposableStack::NextDisposeAsyncIteration(isolate, stack,
                                                                 promise),
               ReadOnlyRoots(isolate).exception());
  return ReadOnlyRoots(isolate).undefined_value();
}

BUILTIN(AsyncDisposableStackOnRejected) {
  HandleScope scope(isolate);

  Handle<JSDisposableStackBase> stack(
      Cast<JSDisposableStackBase>(isolate->context()->get(static_cast<int>(
          JSDisposableStackBase::AsyncDisposableStackContextSlots::kStack))),
      isolate);
  Handle<JSPromise> promise(
      Cast<JSPromise>(isolate->context()->get(static_cast<int>(
          JSDisposableStackBase::AsyncDisposableStackContextSlots::
              kOuterPromise))),
      isolate);

  Handle<Object> rejection_error = args.at(1);
  // (TODO:rezvan): Pass the correct pending message.
  Handle<Object> message(isolate->pending_message(), isolate);
  DCHECK(isolate->is_catchable_by_javascript(*rejection_error));
  JSDisposableStackBase::HandleErrorInDisposal(isolate, stack, rejection_error,
                                               message);

  MAYBE_RETURN(JSAsyncDisposableStack::NextDisposeAsyncIteration(isolate, stack,
                                                                 promise),
               ReadOnlyRoots(isolate).exception());
  return ReadOnlyRoots(isolate).undefined_value();
}

// Part of
// https://tc39.es/proposal-explicit-resource-management/#sec-getdisposemethod
BUILTIN(AsyncDisposeFromSyncDispose) {
  HandleScope scope(isolate);
  // 1. If hint is async-dispose
  //   b. If GetMethod(V, @@asyncDispose) is undefined,
  //    i. If GetMethod(V, @@dispose) is not undefined, then
  //      1. Let closure be a new Abstract Closure with no parameters that
  //      captures method and performs the following steps when called:
  //        a. Let O be the this value.
  //        b. Let promiseCapability be ! NewPromiseCapability(%Promise%).
  Handle<JSPromise> promise = isolate->factory()->NewJSPromise();

  //        c. Let result be Completion(Call(method, O)).
  Handle<JSFunction> sync_method = Handle<JSFunction>(
      Cast<JSFunction>(isolate->context()->get(static_cast<int>(
          JSDisposableStackBase::AsyncDisposeFromSyncDisposeContextSlots::
              kMethod))),
      isolate);

  v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
  try_catch.SetVerbose(false);
  try_catch.SetCaptureMessage(false);

  MaybeHandle<Object> result = Execution::Call(
      isolate, sync_method, ReadOnlyRoots(isolate).undefined_value_handle(), 0,
      nullptr);

  Handle<Object> result_handle;

  if (result.ToHandle(&result_handle)) {
    //        e. Perform ? Call(promiseCapability.[[Resolve]], undefined, «
    //        undefined »).
    JSPromise::Resolve(promise, result_handle).ToHandleChecked();
  } else {
    Tagged<Object> exception = isolate->exception();
    if (!isolate->is_catchable_by_javascript(exception)) {
      return {};
    }
    //        d. IfAbruptRejectPromise(result, promiseCapability).
    DCHECK(try_catch.HasCaught());
    JSPromise::Reject(promise, handle(exception, isolate));
  }

  //        f. Return promiseCapability.[[Promise]].
  return *promise;
}

// https://tc39.es/proposal-explicit-resource-management/#sec-asyncdisposablestack
BUILTIN(AsyncDisposableStackConstructor) {
  const char kMethodName[] = "AsyncDisposableStack";
  HandleScope scope(isolate);

  // 1. If NewTarget is undefined, throw a TypeError exception.
  if (!IsJSReceiver(*args.new_target(), isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kConstructorNotFunction,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  kMethodName)));
  }

  // 2. Let asyncDisposableStack be ? OrdinaryCreateFromConstructor(NewTarget,
  //    "%AsyncDisposableStack.prototype%", « [[AsyncDisposableState]],
  //    [[DisposeCapability]] »).
  DirectHandle<Map> map;
  Handle<JSFunction> target = args.target();
  Handle<JSReceiver> new_target = Cast<JSReceiver>(args.new_target());

  DCHECK_EQ(*target,
            target->native_context()->js_async_disposable_stack_function());

  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, map, JSFunction::GetDerivedMap(isolate, target, new_target));

  DirectHandle<JSAsyncDisposableStack> async_disposable_stack =
      isolate->factory()->NewJSAsyncDisposableStack(map);
  // 3. Set asyncDisposableStack.[[AsyncDisposableState]] to pending.
  // 4. Set asyncDisposableStack.[[DisposeCapability]] to
  // NewDisposeCapability().
  JSDisposableStackBase::InitializeJSDisposableStackBase(
      isolate, async_disposable_stack);
  // 5. Return asyncDisposableStack.
  return *async_disposable_stack;
}

// https://tc39.es/proposal-explicit-resource-management/#sec-asyncdisposablestack.prototype.use
BUILTIN(AsyncDisposableStackPrototypeUse) {
  const char kMethodName[] = "AsyncDisposableStack.prototype.use";
  HandleScope scope(isolate);

  // 1. Let asyncDisposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(asyncDisposableStack,
  // [[AsyncDisposableState]]).
  CHECK_RECEIVER(JSAsyncDisposableStack, async_disposable_stack, kMethodName);
  Handle<JSAny> value = args.at<JSAny>(1);

  // 3. If asyncDisposableStack.[[AsyncDisposableState]] is disposed, throw a
  //    ReferenceError exception.
  if (async_disposable_stack->state() == DisposableStackState::kDisposed) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewReferenceError(
            MessageTemplate::kDisposableStackIsDisposed,
            isolate->factory()->NewStringFromAsciiChecked(kMethodName)));
  }

  // 4. Perform ?
  // AddDisposableResource(asyncDisposableStack.[[DisposeCapability]],
  // value, async-dispose).
  Handle<Object> method;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, method,
      JSDisposableStackBase::CheckValueAndGetDisposeMethod(
          isolate, value, DisposeMethodHint::kAsyncDispose));

  JSDisposableStackBase::Add(
      isolate, async_disposable_stack,
      (IsNullOrUndefined(*value)
           ? ReadOnlyRoots(isolate).undefined_value_handle()
           : value),
      method, DisposeMethodCallType::kValueIsReceiver,
      DisposeMethodHint::kAsyncDispose);

  // 5. Return value.
  return *value;
}

// https://tc39.es/proposal-explicit-resource-management/#sec-asyncdisposablestack.prototype.disposeAsync
BUILTIN(AsyncDisposableStackPrototypeDisposeAsync) {
  HandleScope scope(isolate);

  // 1. Let asyncDisposableStack be the this value.
  Handle<Object> receiver = args.receiver();

  // 2. Let promiseCapability be ! NewPromiseCapability(%Promise%).
  Handle<JSPromise> promise = isolate->factory()->NewJSPromise();

  // 3. If asyncDisposableStack does not have an [[AsyncDisposableState]]
  // internal slot, then
  if (!IsJSAsyncDisposableStack(*receiver)) {
    //    a. Perform ! Call(promiseCapability.[[Reject]], undefined, « a newly
    //    created TypeError object »).
    JSPromise::Reject(promise,
                      isolate->factory()->NewTypeError(
                          MessageTemplate::kNotAnAsyncDisposableStack));
    //   b. Return promiseCapability.[[Promise]].
    return *promise;
  }

  Handle<JSAsyncDisposableStack> async_disposable_stack =
      Cast<JSAsyncDisposableStack>(receiver);

  // 4. If asyncDisposableStack.[[AsyncDisposableState]] is disposed, then
  if (async_disposable_stack->state() == DisposableStackState::kDisposed) {
    //    a. Perform ! Call(promiseCapability.[[Resolve]], undefined, «
    //    undefined »).
    JSPromise::Resolve(
        promise, handle(ReadOnlyRoots(isolate).undefined_value(), isolate))
        .ToHandleChecked();
    //    b. Return promiseCapability.[[Promise]].
    return *promise;
  }

  // 5. Set asyncDisposableStack.[[AsyncDisposableState]] to disposed.
  async_disposable_stack->set_state(DisposableStackState::kDisposed);

  // 6. Let result be
  //   DisposeResources(asyncDisposableStack.[[DisposeCapability]],
  //   NormalCompletion(undefined)).
  // 7. IfAbruptRejectPromise(result, promiseCapability).
  // 8. Perform ! Call(promiseCapability.[[Resolve]], undefined, « result
  // »).
  // 9. Return promiseCapability.[[Promise]].
  MAYBE_RETURN(JSAsyncDisposableStack::NextDisposeAsyncIteration(
                   isolate, async_disposable_stack, promise),
               ReadOnlyRoots(isolate).exception());
  return *promise;
}

// https://tc39.es/proposal-explicit-resource-management/#sec-get-asyncdisposablestack.prototype.disposed
BUILTIN(AsyncDisposableStackPrototypeGetDisposed) {
  const char kMethodName[] = "get AsyncDisposableStack.prototype.disposed";
  HandleScope scope(isolate);

  // 1. Let AsyncdisposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(asyncDisposableStack,
  // [[AsyncDisposableState]]).
  CHECK_RECEIVER(JSAsyncDisposableStack, async_disposable_stack, kMethodName);

  // 3. If AsyncdisposableStack.[[AsyncDisposableState]] is disposed, return
  // true.
  // 4. Otherwise, return false.
  return *(isolate->factory()->ToBoolean(async_disposable_stack->state() ==
                                         DisposableStackState::kDisposed));
}

// https://tc39.es/proposal-explicit-resource-management/#sec-asyncdisposablestack.prototype.adopt
BUILTIN(AsyncDisposableStackPrototypeAdopt) {
  const char kMethodName[] = "AsyncDisposableStack.prototype.adopt";
  HandleScope scope(isolate);
  Handle<Object> value = args.at(1);
  Handle<Object> on_dispose_async = args.at(2);

  // 1. Let asyncDisposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(asyncDisposableStack,
  // [[AsyncDisposableState]]).
  CHECK_RECEIVER(JSAsyncDisposableStack, async_disposable_stack, kMethodName);

  // 3. If asyncDisposableStack.[[AsyncDisposableState]] is disposed, throw a
  //    ReferenceError exception.
  if (async_disposable_stack->state() == DisposableStackState::kDisposed) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewReferenceError(
            MessageTemplate::kDisposableStackIsDisposed,
            isolate->factory()->NewStringFromAsciiChecked(kMethodName)));
  }

  // 4. If IsCallable(onDisposeAsync) is false, throw a TypeError exception.
  if (!IsCallable(*on_dispose_async)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNotCallable, on_dispose_async));
  }

  // 5. Let closure be a new Abstract Closure with no parameters that captures
  //    value and onDisposeAsync and performs the following steps when called:
  //      a. Return ? Call(onDisposeAsync, undefined, « value »).
  // 6. Let F be CreateBuiltinFunction(closure, 0, "", « »).
  // 7. Perform ?
  // AddDisposableResource(asyncDisposableStack.[[DisposeCapability]],
  //    undefined, async-dispose, F).
  // Instead of creating an abstract closure and a function, we pass
  // DisposeMethodCallType::kArgument so at the time of disposal, the value will
  // be passed as the argument to the method.
  JSDisposableStackBase::Add(isolate, async_disposable_stack, value,
                             on_dispose_async,
                             DisposeMethodCallType::kValueIsArgument,
                             DisposeMethodHint::kAsyncDispose);

  // 8. Return value.
  return *value;
}

// https://tc39.es/proposal-explicit-resource-management/#sec-asyncdisposablestack.prototype.defer
BUILTIN(AsyncDisposableStackPrototypeDefer) {
  const char kMethodName[] = "AsyncDisposableStack.prototype.defer";
  HandleScope scope(isolate);
  Handle<Object> on_dispose_async = args.at(1);

  // 1. Let asyncDisposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(asyncDisposableStack,
  // [[AsyncDisposableState]]).
  CHECK_RECEIVER(JSAsyncDisposableStack, async_disposable_stack, kMethodName);

  // 3. If asyncDisposableStack.[[AsyncDisposableState]] is disposed, throw a
  // ReferenceError exception.
  if (async_disposable_stack->state() == DisposableStackState::kDisposed) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewReferenceError(
            MessageTemplate::kDisposableStackIsDisposed,
            isolate->factory()->NewStringFromAsciiChecked(kMethodName)));
  }

  // 4. If IsCallable(onDisposeAsync) is false, throw a TypeError exception.
  if (!IsCallable(*on_dispose_async)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNotCallable, on_dispose_async));
  }

  // 5. Perform ?
  // AddDisposableResource(asyncDisposableStack.[[DisposeCapability]],
  // undefined, async-dispose, onDisposeAsync).
  JSDisposableStackBase::Add(isolate, async_disposable_stack,
                             ReadOnlyRoots(isolate).undefined_value_handle(),
                             on_dispose_async,
                             DisposeMethodCallType::kValueIsReceiver,
                             DisposeMethodHint::kAsyncDispose);

  // 6. Return undefined.
  return ReadOnlyRoots(isolate).undefined_value();
}

// https://tc39.es/proposal-explicit-resource-management/#sec-asyncdisposablestack.prototype.move
BUILTIN(AsyncDisposableStackPrototypeMove) {
  const char kMethodName[] = "AsyncDisposableStack.prototype.move";
  HandleScope scope(isolate);

  // 1. Let asyncDisposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(asyncDisposableStack,
  // [[AsyncDisposableState]]).
  CHECK_RECEIVER(JSAsyncDisposableStack, async_disposable_stack, kMethodName);

  // 3. If asyncDisposableStack.[[AsyncDisposableState]] is disposed, throw a
  //    ReferenceError exception.
  if (async_disposable_stack->state() == DisposableStackState::kDisposed) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewReferenceError(
            MessageTemplate::kDisposableStackIsDisposed,
            isolate->factory()->NewStringFromAsciiChecked(kMethodName)));
  }

  // 4. Let newAsyncDisposableStack be ?
  //    OrdinaryCreateFromConstructor(%AsyncDisposableStack%,
  //    "%AsyncDisposableStack.prototype%", « [[AsyncDisposableState]],
  //     [[DisposeCapability]] »).
  // 5. Set newAsyncDisposableStack.[[AsyncDisposableState]] to pending.

  Tagged<JSFunction> constructor_function =
      Cast<JSFunction>(isolate->native_context()->get(
          Context::JS_ASYNC_DISPOSABLE_STACK_FUNCTION_INDEX));
  DirectHandle<Map> map(constructor_function->initial_map(), isolate);

  DirectHandle<JSAsyncDisposableStack> new_async_disposable_stack =
      isolate->factory()->NewJSAsyncDisposableStack(map);

  // 6. Set newAsyncDisposableStack.[[DisposeCapability]] to
  //    asyncDisposableStack.[[DisposeCapability]].
  new_async_disposable_stack->set_stack(async_disposable_stack->stack());
  new_async_disposable_stack->set_length(async_disposable_stack->length());
  new_async_disposable_stack->set_state(DisposableStackState::kPending);
  new_async_disposable_stack->set_error(
      *(isolate->factory()->uninitialized_value()));

  // 7. Set asyncDisposableStack.[[DisposeCapability]] to
  // NewDisposeCapability().
  async_disposable_stack->set_stack(ReadOnlyRoots(isolate).empty_fixed_array());
  async_disposable_stack->set_length(0);
  async_disposable_stack->set_error(
      *(isolate->factory()->uninitialized_value()));

  // 8. Set disposableStack.[[DisposableState]] to disposed.
  async_disposable_stack->set_state(DisposableStackState::kDisposed);

  // 9. Return newDisposableStack.
  return *new_async_disposable_stack;
}

}  // namespace internal
}  // namespace v8

"""

```