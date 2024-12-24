Response: My thinking process to analyze the Torque code and generate the summary went through these stages:

1. **Initial Scan and Keyword Recognition:** I first scanned the code for familiar keywords and structures related to Promises. I noticed:
    * `JSPromise`, `PromiseCapability`, `PromiseReaction`, `PromiseState`
    * `PromiseFulfillReactionJobTask`, `PromiseRejectReactionJobTask`, `PromiseResolveThenableJobTask`
    * `PromiseHook`, `RunContextPromiseHook`, `RunAnyPromiseHookInit`
    * `PromiseInit`, `NewJSPromise`, `PromiseHasHandler`
    * `then` (related to `InvokeThen`)
    * `@export`, `macro`, `transitioning` (Torque specific syntax)
    * `V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA`, `V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS` (Conditional compilation flags)

2. **Grouping by Functionality:** I started mentally grouping the code blocks based on the keywords and their apparent purpose:
    * **Promise Creation and Initialization:**  `PromiseInit`, `InnerNewJSPromise`, `NewJSPromise`
    * **Promise Reaction Handling:** `NewPromiseFulfillReactionJobTask`, `NewPromiseRejectReactionJobTask`, `NewPromiseReaction`
    * **Promise Resolution with Thenables:** `NewPromiseResolveThenableJobTask`, `InvokeThen`
    * **Promise Hooks:** `RunContextPromiseHookInit`, `RunContextPromiseHookResolve`, `RunContextPromiseHookBefore`, `RunContextPromiseHookAfter`, `RunAnyPromiseHookInit`
    * **Utility Functions:** `PromiseHasHandler`
    * **Embedder Data Handling:** `GetContinuationPreservedEmbedderData`, `SetContinuationPreservedEmbedderData`
    * **Internal Functions/Macros:**  Functions prefixed with `promise_internal::`, and macros for checking hook flags.

3. **Understanding Core Concepts:** I recalled the fundamental concepts of Promises in JavaScript: states (pending, fulfilled, rejected), reactions (`then`, `catch`, `finally`), and the microtask queue for asynchronous operations. I then tried to map the Torque code to these concepts. For instance, the "JobTask" related macros clearly point to the microtask queue and how reactions are scheduled.

4. **Analyzing Individual Macros/Functions:**  I started dissecting the more important macros and functions:
    * **`PromiseInit`:**  Clearly sets the initial state of a Promise.
    * **`NewJSPromise`:**  Shows different ways to create a Promise, including with a parent for hook purposes and with a pre-determined state.
    * **`NewPromiseReaction`:** Represents how `then`, `catch`, and `finally` create reaction objects.
    * **`NewPromise...JobTask`:**  Demonstrates the creation of microtasks for handling fulfillment, rejection, and thenable resolution.
    * **`InvokeThen`:**  Crucial for understanding how the `then` method is invoked, including optimizations for the common case.
    * **Promise Hook functions:**  Illustrate the mechanism for intercepting Promise lifecycle events, useful for debugging and monitoring.

5. **Connecting to JavaScript:**  As I understood the Torque code's purpose, I started thinking about how these operations translate to JavaScript. For example:
    * `NewJSPromise()` maps to `new Promise(...)`.
    * `PromiseHasHandler()` relates to whether a `then` or `catch` has been attached.
    * The JobTask macros are the internal machinery behind the asynchronous nature of Promises.
    * Promise hooks are less directly accessible in standard JavaScript but are used by debugging tools.

6. **Identifying Logic and Potential Errors:** I looked for conditional logic and potential error scenarios:
    * The `BranchIfAccessCheckFailed` macro addresses a security concern when dealing with Promise executors from different contexts.
    * The handling of `Undefined` in some function arguments indicates optional parameters or default behavior.
    * The conditional compilation (`@if`) highlights different build configurations and potentially different behavior.

7. **Structuring the Output:**  I organized my findings into the requested sections: Functionality Summary, JavaScript Examples, Logic and I/O, and Common Errors.

8. **Refining and Adding Detail:** I reviewed my initial draft and added more specific details and examples. For instance, I elaborated on the purpose of the different JobTask types and provided more concrete JavaScript examples. I also made sure to explain the conditional compilation flags.

9. **Considering Edge Cases and Assumptions:** I thought about potential edge cases (like revoked Proxies in `NewPromiseResolveThenableJobTask`) and made sure to note any assumptions made during the analysis.

This iterative process of scanning, grouping, understanding, connecting, and refining allowed me to build a comprehensive summary of the provided V8 Torque code. The key was to combine my knowledge of JavaScript Promises with careful analysis of the Torque syntax and the specific functions and macros defined in the code.
这个V8 Torque源代码文件 `v8/src/builtins/promise-misc.tq` 主要定义了一些用于 Promise 操作的基础宏和内建函数，这些操作是构建 JavaScript Promise 功能的核心组成部分。它涵盖了 Promise 的创建、初始化、状态管理、reaction 的创建和调度，以及 Promise Hook 的相关功能。

以下是对其功能的归纳：

**主要功能:**

1. **Promise 的创建和初始化:**
   - 定义了 `InnerNewJSPromise` 宏用于创建未初始化的 `JSPromise` 对象。
   - 定义了 `PromiseInit` 宏用于初始化 `JSPromise` 对象，设置其初始状态为 `pending`，并清空 embedder data 的偏移量。
   - 提供了多个 `NewJSPromise` 宏的重载，用于创建不同状态（pending, fulfilled, rejected）的 Promise 对象，并支持在创建时指定父 Promise 用于 Promise Hook。

2. **Promise 状态管理:**
   - 提供了 `PromiseHasHandler` 宏用于检查 Promise 是否有 handler (即是否调用过 `then` 或 `catch`)。

3. **Promise Reaction 的创建:**
   - 定义了 `NewPromiseReaction` 宏用于创建 `PromiseReaction` 对象，该对象存储了 Promise 的 fulfill 和 reject 回调以及关联的 Promise 或 PromiseCapability。
   - 定义了 `NewPromiseFulfillReactionJobTask` 和 `NewPromiseRejectReactionJobTask` 宏用于创建微任务，这些微任务会在 Promise 状态变为 fulfilled 或 rejected 时被调度执行，用于执行相应的 reaction。

4. **Promise 的 thenable 处理:**
   - 定义了 `NewPromiseResolveThenableJobTask` 宏用于创建处理 thenable 对象的微任务。当一个 Promise 被一个 thenable 对象 resolve 时，这个微任务会被调度，用于递归地 resolve 该 thenable 对象。
   - 定义了 `InvokeThen` 宏，用于安全地调用 thenable 对象的 `then` 方法，其中包含对 `Promise.prototype.then` 的优化检查。

5. **Promise Hook 功能:**
   - 定义了多个 `RunContextPromiseHook...` 宏，用于在 Promise 的生命周期中的特定时刻（例如初始化、resolve 前后）执行用户或 embedder 定义的 hook 函数。这些 hook 函数可以用于监控和调试 Promise 的行为。
   - 定义了 `RunAnyPromiseHookInit` 宏，用于根据配置同时执行 context-specific 和 isolate-specific 的 Promise 初始化 hook。
   - 提供了检查 Promise Hook 是否启用的宏 `IsContextPromiseHookEnabled` 和 `IsIsolatePromiseHookEnabled` 以及获取 Promise Hook 标志的宏 `PromiseHookFlags`。

6. **其他辅助功能:**
   - 提供了 `GetContinuationPreservedEmbedderData` 和 `SetContinuationPreservedEmbedderData` 内建函数（在特定编译条件下），用于获取和设置与 Promise 相关的 embedder data。
   - 提供了 `BranchIfAccessCheckFailed` 宏，用于在创建 Promise 时检查 executor 函数的访问权限，防止跨 context 的非法访问。

**与 Javascript 功能的关系及举例:**

这个 Torque 文件中的代码直接对应于 JavaScript 中 Promise 的核心行为。

* **Promise 创建:** JavaScript 中的 `new Promise((resolve, reject) => { ... })` 最终会调用到类似 `NewJSPromise` 的宏来创建 Promise 对象。

   ```javascript
   const promise = new Promise((resolve, reject) => {
     setTimeout(() => {
       resolve('成功');
     }, 1000);
   });
   ```

* **Promise 的 `then` 和 `catch`:**  JavaScript 中的 `promise.then(onFulfilled, onRejected)` 和 `promise.catch(onRejected)` 操作会创建 `PromiseReaction` 对象，并将其添加到 Promise 的 reactions 队列中。`NewPromiseFulfillReactionJobTask` 和 `NewPromiseRejectReactionJobTask` 则会在 Promise 状态改变时被调度，执行相应的回调。

   ```javascript
   promise.then(
     (result) => { console.log('fulfilled:', result); },
     (error) => { console.log('rejected:', error); }
   );

   promise.catch((error) => {
     console.error('caught error:', error);
   });
   ```

* **Promise 的 resolve thenable:** 当一个 Promise 被另一个 Promise 或一个拥有 `then` 方法的对象（thenable） resolve 时，会触发 `NewPromiseResolveThenableJobTask`。

   ```javascript
   const anotherPromise = new Promise(resolve => setTimeout(() => resolve(Promise.resolve(10)), 500));
   anotherPromise.then(value => console.log(value)); // 输出 10
   ```

* **Promise Hook:** 虽然 JavaScript 标准没有直接暴露 Promise Hook API，但一些调试工具或 embedder 可以利用这些 hook 来监控 Promise 的行为。

**代码逻辑推理及假设输入与输出:**

**宏: `PromiseInit(promise: JSPromise)`**

* **假设输入:** 一个新创建的 `JSPromise` 对象 `promise`。
* **输出:**
    * `promise.reactions_or_result` 被设置为 `kZero` (表示初始状态没有结果或 reactions)。
    * `promise.flags` 被设置为一个包含以下信息的 Smi 标记：
        * `status`: `PromiseState::kPending` (Promise 的状态为等待中)。
        * `has_handler`: `false` (初始状态没有 handler)。
        * `is_silent`: `false` (通常用于表示 unhandled rejection 是否需要报告，初始为 false)。
        * `async_task_id`: `kInvalidAsyncTaskId` (初始状态没有关联的异步任务 ID)。
    * Embedder 相关的偏移量被清零。

**宏: `NewPromiseFulfillReactionJobTask(...)`**

* **假设输入:**
    * `handlerContext`: 执行 handler 的上下文。
    * `argument`: Promise resolve 的值。
    * `handler`: fulfill 回调函数。
    * `promiseOrCapability`: 关联的 Promise 或 PromiseCapability。
* **输出:** 创建一个新的 `PromiseFulfillReactionJobTask` 对象，该对象包含了执行 fulfill reaction 所需的信息，例如回调函数、参数和上下文。这个 JobTask 会被放入微任务队列等待执行。

**宏: `InvokeThen(nativeContext: NativeContext, receiver: JSAny, arg: JSAny)`**

* **假设输入:**
    * `nativeContext`: 当前的 NativeContext。
    * `receiver`:  一个可能拥有 `then` 方法的对象（通常是 Promise）。
    * `arg`: 传递给 `then` 方法的参数。
* **输出:**
    * 如果 `receiver` 是一个 Promise 且 Promise 的 `then` lookup chain 没有被破坏，则直接从 NativeContext 中获取缓存的 `Promise.prototype.then` 并调用。
    * 否则，会先获取 `receiver` 对象的 `then` 属性，然后调用该 `then` 方法，并将 `arg` 作为参数传递。
    * 返回 `then` 方法的执行结果。

**涉及用户常见的编程错误:**

1. **忘记处理 Promise 的 rejection:** 如果一个 Promise 被 reject 且没有提供 rejection handler (`.catch` 或 `.then` 的第二个参数)，在某些环境下（如浏览器控制台或 Node.js）会产生 unhandled rejection 错误。Promise Hook 机制可以帮助 embedder 捕获这类错误。

   ```javascript
   const promise = new Promise((resolve, reject) => {
     setTimeout(() => {
       reject('出错了！');
     }, 500);
   });

   // 错误：没有提供 rejection handler
   // promise.then((result) => { console.log(result); });

   // 正确：提供 rejection handler
   promise.catch((error) => { console.error('Promise rejected:', error); });
   ```

2. **在 Promise executor 中抛出错误但没有捕获:** 如果 Promise 的 executor 函数中抛出了错误，且没有被 `try...catch` 捕获，该 Promise 会被 reject，但如果没有相应的 rejection handler，同样会导致 unhandled rejection。

   ```javascript
   const promise = new Promise((resolve, reject) => {
     throw new Error('Executor 中发生错误');
   });

   promise.catch((error) => {
     console.error('Caught error from executor:', error);
   });
   ```

3. **误解 Promise 的异步性:** 新手可能会误以为 Promise 的 executor 是同步执行的，或者 `.then` 的回调会立即执行。理解微任务队列和事件循环是正确使用 Promise 的关键。

   ```javascript
   console.log('开始');
   const promise = new Promise((resolve) => {
     console.log('Executor 执行');
     resolve('完成');
   });
   promise.then((result) => {
     console.log('Then 回调:', result);
   });
   console.log('结束');

   // 输出顺序:
   // 开始
   // Executor 执行
   // 结束
   // Then 回调: 完成
   ```

4. **在不需要 Promise 的地方过度使用 Promise:** 虽然 Promise 对于处理异步操作很有用，但在同步场景下使用 Promise 会增加不必要的复杂性。

总而言之，这个 Torque 文件是 V8 引擎中实现 JavaScript Promise 机制的关键组成部分，它定义了 Promise 的内部结构、状态管理、reaction 处理和异步调度的核心逻辑。理解这些底层的实现有助于更深入地理解和使用 JavaScript Promise。

Prompt: 
```
这是目录为v8/src/builtins/promise-misc.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-promise.h'
#include 'src/builtins/builtins-promise-gen.h'

namespace runtime {
extern transitioning runtime AllowDynamicFunction(
    implicit context: Context)(JSAny): JSAny;

extern transitioning runtime ThrowNoAccess(implicit context: Context)(): never;

extern transitioning runtime ReportMessageFromMicrotask(
    implicit context: Context)(JSAny): JSAny;
}

// Unsafe functions that should be used very carefully.
namespace promise_internal {
extern macro PromiseBuiltinsAssembler::ZeroOutEmbedderOffsets(JSPromise): void;

extern macro PromiseBuiltinsAssembler::AllocateJSPromise(Context): HeapObject;
}

extern macro PromiseBuiltinsAssembler::IsContextPromiseHookEnabled(uint32):
    bool;

extern macro PromiseBuiltinsAssembler::IsIsolatePromiseHookEnabled(uint32):
    bool;

extern macro PromiseBuiltinsAssembler::PromiseHookFlags(): uint32;

namespace macros {
extern macro GetContinuationPreservedEmbedderData(): Object;
extern macro SetContinuationPreservedEmbedderData(Object): void;
}

namespace promise {
const kInvalidAsyncTaskId:
    constexpr uint32 generates 'JSPromise::kInvalidAsyncTaskId';

extern macro IsFunctionWithPrototypeSlotMap(Map): bool;

@export
macro PromiseHasHandler(promise: JSPromise): bool {
  return promise.HasHandler();
}

@export
macro PromiseInit(promise: JSPromise): void {
  promise.reactions_or_result = kZero;
  promise.flags = SmiTag(JSPromiseFlags{
    status: PromiseState::kPending,
    has_handler: false,
    is_silent: false,
    async_task_id: kInvalidAsyncTaskId
  });
  promise_internal::ZeroOutEmbedderOffsets(promise);
}

macro InnerNewJSPromise(implicit context: Context)(): JSPromise {
  const promiseFun = *NativeContextSlot(ContextSlot::PROMISE_FUNCTION_INDEX);
  dcheck(IsFunctionWithPrototypeSlotMap(promiseFun.map));
  const promiseMap = UnsafeCast<Map>(promiseFun.prototype_or_initial_map);
  const promiseHeapObject = promise_internal::AllocateJSPromise(context);
  *UnsafeConstCast(&promiseHeapObject.map) = promiseMap;
  const promise = UnsafeCast<JSPromise>(promiseHeapObject);
  promise.properties_or_hash = kEmptyFixedArray;
  promise.elements = kEmptyFixedArray;
  promise.reactions_or_result = kZero;
  promise.flags = SmiTag(JSPromiseFlags{
    status: PromiseState::kPending,
    has_handler: false,
    is_silent: false,
    async_task_id: kInvalidAsyncTaskId
  });
  return promise;
}

macro NewPromiseFulfillReactionJobTask(
    implicit context: Context)(handlerContext: Context, argument: Object,
    handler: Callable|Undefined,
    promiseOrCapability: JSPromise|PromiseCapability|
    Undefined): PromiseFulfillReactionJobTask {
  @if(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA) {
    return new PromiseFulfillReactionJobTask{
      map: PromiseFulfillReactionJobTaskMapConstant(),
      continuation_preserved_embedder_data:
          macros::GetContinuationPreservedEmbedderData(),
      argument,
      context: handlerContext,
      handler,
      promise_or_capability: promiseOrCapability
    };
  }

  @ifnot(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA) {
    return new PromiseFulfillReactionJobTask{
      map: PromiseFulfillReactionJobTaskMapConstant(),
      argument,
      context: handlerContext,
      handler,
      promise_or_capability: promiseOrCapability
    };
  }
}

macro NewPromiseRejectReactionJobTask(
    implicit context: Context)(handlerContext: Context, argument: Object,
    handler: Callable|Undefined,
    promiseOrCapability: JSPromise|PromiseCapability|
    Undefined): PromiseRejectReactionJobTask {
  @if(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA) {
    return new PromiseRejectReactionJobTask{
      map: PromiseRejectReactionJobTaskMapConstant(),
      continuation_preserved_embedder_data:
          macros::GetContinuationPreservedEmbedderData(),
      argument,
      context: handlerContext,
      handler,
      promise_or_capability: promiseOrCapability
    };
  }

  @ifnot(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA) {
    return new PromiseRejectReactionJobTask{
      map: PromiseRejectReactionJobTaskMapConstant(),
      argument,
      context: handlerContext,
      handler,
      promise_or_capability: promiseOrCapability
    };
  }
}

@export
transitioning macro RunContextPromiseHookInit(
    implicit context: Context)(promise: JSPromise, parent: Object): void {
  const maybeHook = *NativeContextSlot(
      ContextSlot::PROMISE_HOOK_INIT_FUNCTION_INDEX);
  const hook = Cast<Callable>(maybeHook) otherwise return;
  const parentObject = Is<JSPromise>(parent) ? Cast<JSPromise>(parent)
      otherwise unreachable: Undefined;

  try {
    Call(context, hook, Undefined, promise, parentObject);
  } catch (e, _message) {
    runtime::ReportMessageFromMicrotask(e);
  }
}

@export
transitioning macro RunContextPromiseHookResolve(
    implicit context: Context)(promise: JSPromise): void {
  // Use potentially unused variables.
  const _unusedPromise = promise;
  @if(V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS) {
    RunContextPromiseHook(
        ContextSlot::PROMISE_HOOK_RESOLVE_FUNCTION_INDEX, promise,
        PromiseHookFlags());
  }
}

@export
transitioning macro RunContextPromiseHookResolve(
    implicit context: Context)(promise: JSPromise, flags: uint32): void {
  RunContextPromiseHook(
      ContextSlot::PROMISE_HOOK_RESOLVE_FUNCTION_INDEX, promise, flags);
}

@export
transitioning macro RunContextPromiseHookBefore(
    implicit context: Context)(
    promiseOrCapability: JSPromise|PromiseCapability|Undefined): void {
  // Use potentially unused variables.
  const _unusedPromiseOrCapability = promiseOrCapability;
  @if(V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS) {
    RunContextPromiseHook(
        ContextSlot::PROMISE_HOOK_BEFORE_FUNCTION_INDEX, promiseOrCapability,
        PromiseHookFlags());
  }
}

@export
transitioning macro RunContextPromiseHookBefore(
    implicit context: Context)(
    promiseOrCapability: JSPromise|PromiseCapability|Undefined,
    flags: uint32): void {
  RunContextPromiseHook(
      ContextSlot::PROMISE_HOOK_BEFORE_FUNCTION_INDEX, promiseOrCapability,
      flags);
}

@export
transitioning macro RunContextPromiseHookAfter(
    implicit context: Context)(
    promiseOrCapability: JSPromise|PromiseCapability|Undefined): void {
  // Use potentially unused variables.
  const _unusedPromiseOrCapability = promiseOrCapability;
  @if(V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS) {
    RunContextPromiseHook(
        ContextSlot::PROMISE_HOOK_AFTER_FUNCTION_INDEX, promiseOrCapability,
        PromiseHookFlags());
  }
}

@export
transitioning macro RunContextPromiseHookAfter(
    implicit context: Context)(
    promiseOrCapability: JSPromise|PromiseCapability|Undefined,
    flags: uint32): void {
  RunContextPromiseHook(
      ContextSlot::PROMISE_HOOK_AFTER_FUNCTION_INDEX, promiseOrCapability,
      flags);
}

transitioning macro RunContextPromiseHook(
    implicit context: Context)(slot: Slot<NativeContext, Undefined|Callable>,
    promiseOrCapability: JSPromise|PromiseCapability|Undefined,
    flags: uint32): void {
  // Use potentially unused variables.
  const _unusedSlot = slot;
  const _unusedPromiseOrCapability = promiseOrCapability;
  const _unusedFlags = flags;
  @if(V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS) {
    if (!IsContextPromiseHookEnabled(flags)) return;
    const maybeHook = *NativeContextSlot(slot);
    const hook = Cast<Callable>(maybeHook) otherwise return;

    let promise: JSPromise;
    typeswitch (promiseOrCapability) {
      case (jspromise: JSPromise): {
        promise = jspromise;
      }
      case (capability: PromiseCapability): {
        promise = Cast<JSPromise>(capability.promise) otherwise return;
      }
      case (Undefined): {
        return;
      }
    }

    try {
      Call(context, hook, Undefined, promise);
    } catch (e, _message) {
      runtime::ReportMessageFromMicrotask(e);
    }
  }
}

transitioning macro RunAnyPromiseHookInit(
    implicit context: Context)(promise: JSPromise, parent: Object): void {
  const promiseHookFlags = PromiseHookFlags();
  // Fast return if no hooks are set.
  if (promiseHookFlags == 0) return;
  @if(V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS) {
    if (IsContextPromiseHookEnabled(promiseHookFlags)) {
      RunContextPromiseHookInit(promise, parent);
    }
  }
  if (IsIsolatePromiseHookEnabled(promiseHookFlags)) {
    runtime::PromiseHookInit(promise, parent);
  }
}

// These allocate and initialize a promise with pending state and
// undefined fields.
//
// This uses the given parent as the parent promise for the promise
// init hook.
@export
transitioning macro NewJSPromise(implicit context: Context)(parent: Object):
    JSPromise {
  const instance = InnerNewJSPromise();
  PromiseInit(instance);
  RunAnyPromiseHookInit(instance, parent);
  return instance;
}

// This uses undefined as the parent promise for the promise init
// hook.
@export
transitioning macro NewJSPromise(implicit context: Context)(): JSPromise {
  return NewJSPromise(Undefined);
}

// This allocates and initializes a promise with the given state and
// fields.
@export
transitioning macro NewJSPromise(
    implicit context: Context)(status: constexpr PromiseState,
    result: JSAny): JSPromise {
  dcheck(status != PromiseState::kPending);

  const instance = InnerNewJSPromise();
  instance.reactions_or_result = result;
  instance.SetStatus(status);
  promise_internal::ZeroOutEmbedderOffsets(instance);
  RunAnyPromiseHookInit(instance, Undefined);
  return instance;
}

macro NewPromiseReaction(
    implicit context: Context)(next: Zero|PromiseReaction,
    promiseOrCapability: JSPromise|PromiseCapability|Undefined,
    fulfillHandler: Callable|Undefined,
    rejectHandler: Callable|Undefined): PromiseReaction {
  @if(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA) {
    return new PromiseReaction{
      map: PromiseReactionMapConstant(),
      continuation_preserved_embedder_data:
          macros::GetContinuationPreservedEmbedderData(),
      next: next,
      reject_handler: rejectHandler,
      fulfill_handler: fulfillHandler,
      promise_or_capability: promiseOrCapability
    };
  }

  @ifnot(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA) {
    return new PromiseReaction{
      map: PromiseReactionMapConstant(),
      next: next,
      reject_handler: rejectHandler,
      fulfill_handler: fulfillHandler,
      promise_or_capability: promiseOrCapability
    };
  }
}

extern macro PromiseResolveThenableJobTaskMapConstant(): Map;

// https://tc39.es/ecma262/#sec-newpromiseresolvethenablejob
macro NewPromiseResolveThenableJobTask(
    implicit context: Context)(promiseToResolve: JSPromise,
    thenable: JSReceiver, then: Callable): PromiseResolveThenableJobTask {
  // 2. Let getThenRealmResult be GetFunctionRealm(then).
  // 3. If getThenRealmResult is a normal completion, then let thenRealm be
  //    getThenRealmResult.[[Value]].
  // 4. Otherwise, let thenRealm be null.
  //
  // The only cases where |thenRealm| can be null is when |then| is a revoked
  // Proxy object, which would throw when it is called anyway. So instead of
  // setting the context to null as the spec does, we just use the current
  // realm.
  const thenContext: Context = ExtractHandlerContext(then);
  const nativeContext = LoadNativeContext(thenContext);

  // 1. Let job be a new Job abstract closure with no parameters that
  //    captures promiseToResolve, thenable, and then...
  // 5. Return { [[Job]]: job, [[Realm]]: thenRealm }.
  @if(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA) {
    return new PromiseResolveThenableJobTask{
      map: PromiseResolveThenableJobTaskMapConstant(),
      continuation_preserved_embedder_data:
          macros::GetContinuationPreservedEmbedderData(),
      context: nativeContext,
      promise_to_resolve: promiseToResolve,
      thenable,
      then
    };
  }

  @ifnot(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA) {
    return new PromiseResolveThenableJobTask{
      map: PromiseResolveThenableJobTaskMapConstant(),
      context: nativeContext,
      promise_to_resolve: promiseToResolve,
      thenable,
      then
    };
  }
}

struct InvokeThenOneArgFunctor {
  transitioning macro Call(
      nativeContext: NativeContext, then: JSAny, receiver: JSAny, arg1: JSAny,
      _arg2: JSAny): JSAny {
    return Call(nativeContext, then, receiver, arg1);
  }
}

struct InvokeThenTwoArgFunctor {
  transitioning macro Call(
      nativeContext: NativeContext, then: JSAny, receiver: JSAny, arg1: JSAny,
      arg2: JSAny): JSAny {
    return Call(nativeContext, then, receiver, arg1, arg2);
  }
}

transitioning macro InvokeThen<F: type>(
    implicit context: Context)(nativeContext: NativeContext, receiver: JSAny,
    arg1: JSAny, arg2: JSAny, callFunctor: F): JSAny {
  // We can skip the "then" lookup on {receiver} if it's [[Prototype]]
  // is the (initial) Promise.prototype and the Promise#then protector
  // is intact, as that guards the lookup path for the "then" property
  // on JSPromise instances which have the (initial) %PromisePrototype%.
  if (!Is<Smi>(receiver) &&
      IsPromiseThenLookupChainIntact(
          nativeContext, UnsafeCast<HeapObject>(receiver).map)) {
    const then =
        *NativeContextSlot(nativeContext, ContextSlot::PROMISE_THEN_INDEX);
    return callFunctor.Call(nativeContext, then, receiver, arg1, arg2);
  } else
    deferred {
      const then = UnsafeCast<JSAny>(GetProperty(receiver, kThenString));
      return callFunctor.Call(nativeContext, then, receiver, arg1, arg2);
    }
}

transitioning macro InvokeThen(
    implicit context: Context)(nativeContext: NativeContext, receiver: JSAny,
    arg: JSAny): JSAny {
  return InvokeThen(
      nativeContext, receiver, arg, Undefined, InvokeThenOneArgFunctor{});
}

transitioning macro InvokeThen(
    implicit context: Context)(nativeContext: NativeContext, receiver: JSAny,
    arg1: JSAny, arg2: JSAny): JSAny {
  return InvokeThen(
      nativeContext, receiver, arg1, arg2, InvokeThenTwoArgFunctor{});
}

transitioning macro BranchIfAccessCheckFailed(
    implicit context: Context)(nativeContext: NativeContext,
    promiseConstructor: JSAny, executor: JSAny): void labels IfNoAccess {
  try {
    // If executor is a bound function, load the bound function until we've
    // reached an actual function.
    let foundExecutor = executor;
    while (true) {
      typeswitch (foundExecutor) {
        case (f: JSFunction): {
          // Load the context from the function and compare it to the Promise
          // constructor's context. If they match, everything is fine,
          // otherwise, bail out to the runtime.
          const functionContext = f.context;
          const nativeFunctionContext = LoadNativeContext(functionContext);
          if (TaggedEqual(nativeContext, nativeFunctionContext)) {
            goto HasAccess;
          } else {
            goto CallRuntime;
          }
        }
        case (b: JSBoundFunction): {
          foundExecutor = b.bound_target_function;
        }
        case (Object): {
          goto CallRuntime;
        }
      }
    }
  } label CallRuntime deferred {
    const result = runtime::AllowDynamicFunction(promiseConstructor);
    if (result != True) {
      goto IfNoAccess;
    }
  } label HasAccess {}
}

@if(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA)
transitioning javascript builtin GetContinuationPreservedEmbedderData(
    js-implicit context: Context, receiver: JSAny)(): JSAny {
  return UnsafeCast<JSAny>(macros::GetContinuationPreservedEmbedderData());
}

@if(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA)
transitioning javascript builtin SetContinuationPreservedEmbedderData(
    js-implicit context: Context, receiver: JSAny)(data: Object): Undefined {
  macros::SetContinuationPreservedEmbedderData(data);
  return Undefined;
}

}

"""

```