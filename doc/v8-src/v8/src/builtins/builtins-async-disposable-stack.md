Response: Let's break down the thought process for analyzing this C++ code for V8.

**1. Understanding the Goal:** The primary goal is to figure out what this C++ file does within the V8 JavaScript engine and how it relates to JavaScript. The filename "builtins-async-disposable-stack.cc" and the inclusion of terms like "AsyncDisposableStack" strongly suggest a connection to a specific JavaScript feature.

**2. Initial Scan for Keywords:**  I'd start by quickly scanning the code for prominent keywords and patterns:

* **`BUILTIN`:** This is a significant indicator. In V8, `BUILTIN` defines functions that are exposed to JavaScript. Each `BUILTIN` block represents a specific JavaScript method or constructor.
* **`AsyncDisposableStack`:**  This appears repeatedly, both in function names and comments. It's clearly the central concept.
* **`JSPromise`:** Promises are fundamental to asynchronous JavaScript. Their presence suggests this feature is about managing asynchronous operations.
* **`Dispose` / `Disposable`:** These terms suggest a mechanism for cleaning up resources.
* **`use`, `disposeAsync`, `adopt`, `defer`, `move`, `disposed`:** These look like method names that might be exposed on the `AsyncDisposableStack` object in JavaScript.
* **`tc39.es/proposal-explicit-resource-management`:** This is a crucial clue. It directly links the code to a specific ECMAScript proposal (Explicit Resource Management). This immediately provides context.

**3. Analyzing Individual `BUILTIN` Functions:**  Now, I'd go through each `BUILTIN` function, trying to understand its purpose:

* **`AsyncDisposableStackOnFulfilled` & `AsyncDisposableStackOnRejected`:** These look like callback functions associated with a promise. The names suggest they are executed when a promise related to disposal is fulfilled or rejected. They manipulate the `JSDisposableStackBase`.

* **`AsyncDisposeFromSyncDispose`:**  The name is a bit more complex. The comments and code within indicate a scenario where a synchronous `dispose` method needs to be adapted for asynchronous disposal. It involves creating a promise and calling the synchronous method. This is important for interoperability.

* **`AsyncDisposableStackConstructor`:** This is clearly the constructor for the `AsyncDisposableStack` object. It sets up internal state. The check for `NewTarget` is standard for constructors.

* **`AsyncDisposableStackPrototypeUse`:** The name suggests using the stack. The code checks if the stack is disposed and then adds a resource to be disposed of later. The `AddDisposableResource` function (implied by the code) is key.

* **`AsyncDisposableStackPrototypeDisposeAsync`:** This looks like the core method for triggering the asynchronous disposal process. It iterates through the resources to be disposed of.

* **`AsyncDisposableStackPrototypeGetDisposed`:**  A simple getter to check if the stack has been disposed.

* **`AsyncDisposableStackPrototypeAdopt`:** This seems to allow adopting an existing object with an asynchronous disposal method. It takes the object and the disposal function as arguments.

* **`AsyncDisposableStackPrototypeDefer`:** Similar to `adopt`, but it registers a disposal function without associating it with a specific value.

* **`AsyncDisposableStackPrototypeMove`:** This is an interesting one. It creates a *new* `AsyncDisposableStack` and moves the disposal resources from the original stack to the new one. This is likely for transferring ownership of resources.

**4. Connecting to JavaScript:**  With an understanding of each `BUILTIN`, I would start thinking about how this translates to JavaScript:

* **Constructor:** The `AsyncDisposableStackConstructor` maps directly to the `AsyncDisposableStack` class/constructor in JavaScript.
* **Prototype Methods:** The other `BUILTIN` functions with "Prototype" in their names become methods on the `AsyncDisposableStack.prototype`.
* **Asynchronous Nature:** The use of `JSPromise` strongly implies that the disposal process is asynchronous, which is confirmed by the `disposeAsync` method.

**5. Formulating the Summary:** Based on the analysis, I would synthesize a summary like the one provided in the initial prompt. Key elements of the summary would include:

* **Purpose:** Managing asynchronous disposal of resources.
* **Relationship to Explicit Resource Management Proposal:**  Highlighting the standard it implements.
* **Core Functionality:**  Creating, using, and disposing of resources asynchronously.
* **Key Methods:** Listing the important methods like `use`, `disposeAsync`, `adopt`, `defer`, and `move`.
* **Internal State:** Mentioning the "disposed" state.

**6. Creating the JavaScript Example:**  To illustrate the JavaScript usage, I would create a simple example that demonstrates the core functionality:

* **Creating an `AsyncDisposableStack`:** Using the `new` keyword.
* **Using `use`:**  Demonstrating adding a resource with an asynchronous `[Symbol.asyncDispose]` method.
* **Using `disposeAsync`:** Showing how to trigger the disposal process.
* **Illustrating the asynchronous nature:**  Using `async`/`await`.

**Self-Correction/Refinement:**

* **Initial thought:** Maybe this is about garbage collection. *Correction:* The explicit mention of `dispose` and the proposal link point to manual resource management, not automatic garbage collection.
* **Initial thought:**  The `OnFulfilled` and `OnRejected` might be about general promise handling. *Correction:*  They specifically operate on the `JSDisposableStackBase` and are triggered *during* the disposal process, not just any promise.
* **JavaScript Example Clarity:**  Ensure the JavaScript example is concise and clearly demonstrates the key features. Add comments to explain each step.

By following this methodical process of keyword scanning, function analysis, and connecting to JavaScript concepts, I can arrive at a comprehensive understanding of the C++ code and its role in the V8 engine.
这个C++源代码文件 `builtins-async-disposable-stack.cc` 是 V8 JavaScript 引擎的一部分，它实现了 **AsyncDisposableStack** 这一 JavaScript 内置对象的相关功能。  `AsyncDisposableStack` 是 ECMAScript 提案 "Explicit Resource Management" 中引入的一个用于管理异步资源清理的对象。

**功能归纳:**

该文件主要负责以下功能：

1. **实现 `AsyncDisposableStack` 构造函数：**  `AsyncDisposableStackConstructor` 函数实现了 JavaScript 中 `new AsyncDisposableStack()` 的行为，创建并初始化一个新的异步可清理堆栈对象。

2. **实现 `AsyncDisposableStack.prototype.use` 方法：** `AsyncDisposableStackPrototypeUse` 函数允许将需要异步清理的资源添加到 `AsyncDisposableStack` 中。 它会检查资源是否具有 `Symbol.asyncDispose` 方法，并将其添加到内部管理队列中。

3. **实现 `AsyncDisposableStack.prototype.disposeAsync` 方法：** `AsyncDisposableStackPrototypeDisposeAsync` 函数触发异步清理过程。 它会遍历堆栈中添加的资源，并依次调用它们的 `Symbol.asyncDispose` 方法。  这个方法返回一个 Promise，确保清理操作是异步的。

4. **实现 `AsyncDisposableStack.prototype.disposed` getter：** `AsyncDisposableStackPrototypeGetDisposed` 函数提供了一个只读属性，用于检查 `AsyncDisposableStack` 是否已经被清理（即 `disposeAsync` 已完成）。

5. **实现 `AsyncDisposableStack.prototype.adopt` 方法：** `AsyncDisposableStackPrototypeAdopt` 函数允许将一个已有的对象及其异步清理函数添加到 `AsyncDisposableStack` 中。 它接收一个值和一个异步清理函数作为参数。

6. **实现 `AsyncDisposableStack.prototype.defer` 方法：** `AsyncDisposableStackPrototypeDefer` 函数允许延迟执行一个异步清理函数，而不需要关联特定的资源值。

7. **实现 `AsyncDisposableStack.prototype.move` 方法：** `AsyncDisposableStackPrototypeMove` 函数允许将一个 `AsyncDisposableStack` 中的资源转移到另一个新的 `AsyncDisposableStack` 中。

8. **处理异步清理过程中的成功和失败：** `AsyncDisposableStackOnFulfilled` 和 `AsyncDisposableStackOnRejected` 函数是内部的回调函数，用于处理 `Symbol.asyncDispose` 方法返回的 Promise 的成功和失败情况。

9. **处理同步 `dispose` 到异步 `dispose` 的转换：** `AsyncDisposeFromSyncDispose` 函数处理当资源只有同步的 `Symbol.dispose` 方法时，如何将其转换为异步清理过程。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件直接实现了 JavaScript 中的 `AsyncDisposableStack` 及其原型方法。  `AsyncDisposableStack` 允许开发者在异步操作完成后，确保某些资源得到清理，类似于 `try...finally` 块，但更加专注于异步资源的生命周期管理。

**JavaScript 示例：**

```javascript
async function example() {
  const stack = new AsyncDisposableStack();

  // 假设我们有一个需要异步清理的资源，例如一个文件句柄
  class AsyncResource {
    constructor(name) {
      this.name = name;
      console.log(`资源 ${this.name} 已分配.`);
    }

    async [Symbol.asyncDispose]() {
      console.log(`正在异步清理资源 ${this.name}...`);
      await new Promise(resolve => setTimeout(resolve, 100)); // 模拟异步清理操作
      console.log(`资源 ${this.name} 已清理.`);
    }
  }

  const resource1 = new AsyncResource("Resource 1");
  const resource2 = new AsyncResource("Resource 2");

  // 使用 stack.use 添加需要清理的资源
  stack.use(resource1);
  stack.use(resource2);

  console.log("开始执行主要异步操作...");
  await new Promise(resolve => setTimeout(resolve, 500));
  console.log("主要异步操作完成.");

  // 当 example 函数执行完毕时，或者显式调用 disposeAsync，
  // stack 中添加的资源会被异步清理
  await stack.disposeAsync();
  console.log(`AsyncDisposableStack 是否已清理: ${stack.disposed}`);
}

example();

// 使用 adopt 的例子
async function adoptExample() {
  const stack = new AsyncDisposableStack();

  class AnotherAsyncResource {
    constructor(name) {
      this.name = name;
      console.log(`另一个资源 ${this.name} 已创建.`);
    }

    async disposeResource() {
      console.log(`异步清理另一个资源 ${this.name}...`);
      await new Promise(resolve => setTimeout(resolve, 100));
      console.log(`另一个资源 ${this.name} 已清理.`);
    }
  }

  const anotherResource = new AnotherAsyncResource("Another Resource");
  stack.adopt(anotherResource, anotherResource.disposeResource);

  console.log("开始执行采用资源的异步操作...");
  await new Promise(resolve => setTimeout(resolve, 300));
  console.log("采用资源的异步操作完成.");

  await stack.disposeAsync();
}

adoptExample();

// 使用 defer 的例子
async function deferExample() {
  const stack = new AsyncDisposableStack();

  async function deferredCleanup() {
    console.log("执行延迟清理操作...");
    await new Promise(resolve => setTimeout(resolve, 200));
    console.log("延迟清理操作完成.");
  }

  stack.defer(deferredCleanup);

  console.log("执行其他异步操作...");
  await new Promise(resolve => setTimeout(resolve, 400));
  console.log("其他异步操作完成.");

  await stack.disposeAsync();
}

deferExample();

// 使用 move 的例子
async function moveExample() {
  const stack1 = new AsyncDisposableStack();
  const stack2 = new AsyncDisposableStack();

  class DisposableItem {
    async [Symbol.asyncDispose]() {
      console.log("清理可移动的资源");
      await new Promise(resolve => setTimeout(resolve, 50));
      console.log("可移动的资源已清理");
    }
  }

  stack1.use(new DisposableItem());
  console.log("资源添加到 stack1");

  const stack3 = stack1.move();
  console.log("资源从 stack1 移动到 stack3");

  console.log(`stack1 是否已清理: ${stack1.disposed}`);
  console.log(`stack3 是否已清理: ${stack3.disposed}`);

  await stack3.disposeAsync();
  console.log(`stack3 完成清理`);

  await stack1.disposeAsync(); // stack1 本身也需要清理，虽然它内部的资源已经移动走了
  console.log(`stack1 完成清理`);
}

moveExample();
```

**总结:**

`builtins-async-disposable-stack.cc` 文件是 V8 引擎中实现 JavaScript `AsyncDisposableStack` 功能的关键部分。它定义了与创建、使用和异步清理资源相关的内置函数，使得 JavaScript 开发者能够更好地管理异步资源的生命周期，避免资源泄漏。 这个特性是 "Explicit Resource Management" 提案的核心组成部分，旨在提供更精细的资源控制能力。

Prompt: 
```
这是目录为v8/src/builtins/builtins-async-disposable-stack.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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