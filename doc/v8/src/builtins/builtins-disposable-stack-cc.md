Response:
Let's break down the thought process for analyzing this V8 source code.

1. **Identify the Core Subject:** The file name `builtins-disposable-stack.cc` immediately points to the `DisposableStack` feature in JavaScript. The `.cc` extension confirms it's C++ source code for V8 built-in functions.

2. **High-Level Understanding of `DisposableStack`:** Even without reading the code, the name suggests a mechanism for managing resources that need to be cleaned up (disposed of) when no longer needed. This likely relates to RAII (Resource Acquisition Is Initialization) principles, but in a JavaScript context. The "stack" part suggests a last-in, first-out order of disposal.

3. **Scan for Key Terms and Concepts:** Look for recurring keywords and phrases. In this code, we see:
    * `DisposableStack`, `JSSyncDisposableStack`:  These are central to the functionality.
    * `Dispose`, `DisposableState`, `DisposeCapability`:  These clearly relate to the lifecycle and control of disposal.
    * `use`, `adopt`, `defer`, `dispose`, `move`, `disposed`: These are the methods of the `DisposableStack` object.
    * `NewTarget`, `this value`:  Common in constructor and method implementations.
    * `TypeError`, `ReferenceError`:  Indicate error conditions.
    * `IsCallable`, `IsNullOrUndefined`:  Type checking.
    * `AddDisposableResource`, `DisposeResources`: Internal operations for managing disposal.
    * `pending`, `disposed`: States of the `DisposableStack`.

4. **Analyze Each Built-in Function:** Go through each `BUILTIN` function individually:

    * **`DisposableStackConstructor`:**
        * **Purpose:**  The name strongly suggests this is the constructor for the `DisposableStack` object.
        * **Key Operations:**  Checks `new.target` (ensuring it's called with `new`), creates a `JSSyncDisposableStack` object, initializes its state to `pending`.
        * **JavaScript Connection:** Corresponds to the `new DisposableStack()` call in JavaScript.

    * **`DisposableStackPrototypeUse`:**
        * **Purpose:**  Likely for registering a resource that needs to be disposed of. The name "use" suggests actively employing a resource managed by the stack.
        * **Key Operations:** Checks if the stack is disposed, checks if the value is null/undefined, gets the `dispose` method of the value, and adds the value and its dispose method to the stack.
        * **JavaScript Connection:**  `stack.use(resource)`.

    * **`DisposableStackPrototypeDispose`:**
        * **Purpose:**  To explicitly trigger the disposal of resources held by the stack.
        * **Key Operations:** Checks if already disposed, sets the state to disposed, and calls an internal `DisposeResources` function.
        * **JavaScript Connection:** `stack.dispose()`.

    * **`DisposableStackPrototypeGetDisposed`:**
        * **Purpose:** A getter to check the disposal state.
        * **Key Operations:**  Simply checks the `DisposableState` and returns `true` or `false`.
        * **JavaScript Connection:** `stack.disposed` (accessing the property).

    * **`DisposableStackPrototypeAdopt`:**
        * **Purpose:** Seems like registering a resource with a *custom* disposal function. "Adopt" implies taking responsibility for something already existing.
        * **Key Operations:** Checks disposal state, checks if the `onDispose` argument is a function, and registers the `value` and `onDispose` function for later execution.
        * **JavaScript Connection:** `stack.adopt(resource, () => { /* cleanup */ })`.

    * **`DisposableStackPrototypeDefer`:**
        * **Purpose:**  Similar to `adopt`, but the resource itself isn't directly managed. "Defer" suggests delaying an action.
        * **Key Operations:** Checks disposal state, checks if `onDispose` is a function, and registers the `onDispose` function to be called later.
        * **JavaScript Connection:** `stack.defer(() => { /* cleanup */ })`.

    * **`DisposableStackPrototypeMove`:**
        * **Purpose:**  To transfer the ownership of the resources from one `DisposableStack` to another.
        * **Key Operations:** Checks disposal state, creates a new `DisposableStack`, transfers the internal state (resources), and marks the original stack as disposed.
        * **JavaScript Connection:** `stack1.move()`.

5. **Infer Functionality and Relationships:** Based on the analysis of individual functions, we can infer the overall functionality:

    * `DisposableStack` provides a way to manage resources and ensure they are disposed of, even if errors occur.
    * It follows a LIFO (stack-like) order for disposal.
    * It offers different ways to register resources for disposal: using their built-in `dispose` method (`use`), providing a custom disposal function (`adopt`), or simply registering a cleanup function (`defer`).
    * `move` allows transferring the responsibility of disposal.

6. **Connect to JavaScript Concepts:**  Relate the code to common JavaScript patterns and potential use cases. Think about scenarios where manual resource management is necessary (e.g., file handles, database connections, event listeners).

7. **Consider Potential Errors:** Analyze the error handling within the code (`TypeError`, `ReferenceError`). Think about what mistakes a developer might make that would trigger these errors.

8. **Formulate Examples and Assumptions:**  Create simple JavaScript examples to illustrate the usage of each method and to demonstrate the error conditions. Define clear input and expected output for the examples.

9. **Structure the Explanation:** Organize the findings into a coherent explanation covering the requested aspects (functionality, Torque, JavaScript examples, code logic, common errors). Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe `use` is only for objects with a `dispose` method. **Correction:** The code explicitly handles null/undefined and uses `CheckValueAndGetDisposeMethod`, suggesting flexibility.
* **Initial thought:**  `move` just renames the stack. **Correction:** It creates a *new* stack and transfers the resources, effectively invalidating the original.
* **Double-check terminology:** Ensure consistent use of terms like "resource," "disposal function," etc.

By following this structured approach, combining code analysis with logical reasoning and JavaScript knowledge, we can effectively understand and explain the functionality of this V8 source code.
这个 C++ 源代码文件 `v8/src/builtins/builtins-disposable-stack.cc` 实现了 JavaScript 中 `DisposableStack` 构造函数及其原型方法的功能。

以下是它的功能列表：

1. **`DisposableStack` 构造函数 (`DisposableStackConstructor`)**:
   - 创建一个新的 `DisposableStack` 实例。
   - 检查是否通过 `new` 关键字调用，如果不是则抛出 `TypeError`。
   - 初始化 `DisposableStack` 实例的内部状态，包括 `[[DisposableState]]` (设置为 `pending`) 和 `[[DisposeCapability]]` (用于管理需要释放的资源)。

2. **`DisposableStack.prototype.use` 方法 (`DisposableStackPrototypeUse`)**:
   - 用于注册一个需要被 `DisposableStack` 管理释放的资源。
   - 接收一个值作为参数。
   - 如果 `DisposableStack` 的状态已经是 `disposed`，则抛出 `ReferenceError`。
   - 如果传入的值是 `null` 或 `undefined`，则直接返回该值，不做任何处理。
   - 检查传入的值是否具有可调用的 `dispose` 方法。
   - 将该值及其 `dispose` 方法添加到 `DisposableStack` 的资源管理中。

3. **`DisposableStack.prototype.dispose` 方法 (`DisposableStackPrototypeDispose`)**:
   - 显式地释放 `DisposableStack` 管理的所有资源。
   - 如果 `DisposableStack` 的状态已经是 `disposed`，则直接返回 `undefined`。
   - 将 `DisposableStack` 的状态设置为 `disposed`。
   - 按照注册的相反顺序调用资源的 `dispose` 方法。

4. **`get DisposableStack.prototype.disposed` 属性 (`DisposableStackPrototypeGetDisposed`)**:
   - 一个 getter 属性，用于获取 `DisposableStack` 当前的释放状态。
   - 如果 `DisposableStack` 的状态是 `disposed`，则返回 `true`，否则返回 `false`。

5. **`DisposableStack.prototype.adopt` 方法 (`DisposableStackPrototypeAdopt`)**:
   - 用于注册一个资源，并提供一个自定义的释放函数。
   - 接收一个值和一个释放函数作为参数。
   - 如果 `DisposableStack` 的状态已经是 `disposed`，则抛出 `ReferenceError`。
   - 检查传入的释放函数是否可调用，如果不是则抛出 `TypeError`。
   - 将该值和释放函数添加到 `DisposableStack` 的资源管理中，在释放时会调用该释放函数，并将该值作为参数传递给它。

6. **`DisposableStack.prototype.defer` 方法 (`DisposableStackPrototypeDefer`)**:
   - 用于注册一个在 `DisposableStack` 被释放时需要执行的回调函数。
   - 接收一个回调函数作为参数。
   - 如果 `DisposableStack` 的状态已经是 `disposed`，则抛出 `ReferenceError`。
   - 检查传入的回调函数是否可调用，如果不是则抛出 `TypeError`。
   - 将该回调函数添加到 `DisposableStack` 的资源管理中，在释放时会调用该回调函数。

7. **`DisposableStack.prototype.move` 方法 (`DisposableStackPrototypeMove`)**:
   - 将当前 `DisposableStack` 管理的所有资源转移到一个新的 `DisposableStack` 实例。
   - 如果当前 `DisposableStack` 的状态已经是 `disposed`，则抛出 `ReferenceError`。
   - 创建一个新的 `DisposableStack` 实例。
   - 将当前 `DisposableStack` 的资源管理能力转移到新的 `DisposableStack` 实例。
   - 将当前 `DisposableStack` 的状态设置为 `disposed`。
   - 返回新的 `DisposableStack` 实例。

**关于文件扩展名 `.tq`：**

你提到的 `.tq` 结尾的文件是 V8 的 Torque 语言编写的源代码。这个 `.cc` 文件不是 Torque 文件。Torque 是一种用于定义 V8 built-in 函数的类型化的中间语言，它可以生成 C++ 代码。通常，核心的、性能敏感的 built-ins 会用 Torque 编写，而一些辅助或较简单的 built-ins 可能直接用 C++ 编写。

**与 JavaScript 的关系和示例：**

`v8/src/builtins/builtins-disposable-stack.cc` 中实现的功能直接对应于 JavaScript 中的 `DisposableStack` API。这个 API 旨在提供一种结构化的方式来管理需要清理的资源，例如文件句柄、网络连接或者任何需要在不再使用时执行特定清理操作的对象。

**JavaScript 示例：**

```javascript
// 创建一个 DisposableStack 实例
const stack = new DisposableStack();

// 定义一个需要被释放的资源 (假设它有一个 dispose 方法)
const resource = {
  value: 10,
  dispose() {
    console.log('资源被释放了，值为:', this.value);
  }
};

// 使用 use 方法注册资源
stack.use(resource);

// 定义另一个需要被释放的资源
const anotherResource = {
  close() {
    console.log('另一个资源被关闭了');
  }
};

// 使用 adopt 方法注册资源，并提供自定义的释放函数
stack.adopt(anotherResource, (res) => {
  res.close();
});

// 使用 defer 方法注册一个清理函数
stack.defer(() => {
  console.log('最后执行的清理操作');
});

console.log('代码执行中...');

// 手动释放所有资源
stack.dispose();

// 或者，如果 DisposableStack 超出作用域，它的 dispose 方法也会被调用 (如果引擎实现了相应的机制，
// 但通常需要显式调用 dispose 或者依赖 try...finally 等结构)。
```

**代码逻辑推理、假设输入与输出：**

**示例 1：`use` 方法**

**假设输入：**

```javascript
const stack = new DisposableStack();
const resource = { dispose: () => '资源已释放' };
```

**执行：** `stack.use(resource);`

**输出：** `resource` 对象本身会被返回。内部状态是 `resource` 及其 `dispose` 方法被添加到 `stack` 的资源列表中。

**之后执行：** `stack.dispose();`

**输出：** 控制台会输出 "资源已释放"。

**示例 2：`dispose` 方法**

**假设输入：**

```javascript
const stack = new DisposableStack();
let disposed = false;
stack.defer(() => { disposed = true; });
```

**执行：** `stack.dispose();`

**输出：** `undefined` 被返回。 `disposed` 变量的值变为 `true`。

**示例 3：`adopt` 方法**

**假设输入：**

```javascript
const stack = new DisposableStack();
let adoptedValue = null;
const obj = { data: 5 };
stack.adopt(obj, (val) => { adoptedValue = val.data * 2; });
```

**执行：** `stack.dispose();`

**输出：** `undefined` 被返回。 `adoptedValue` 的值变为 `10`。

**示例 4：`move` 方法**

**假设输入：**

```javascript
const stack1 = new DisposableStack();
let disposed = false;
stack1.defer(() => { disposed = true; });
```

**执行：** `const stack2 = stack1.move();`

**输出：** `stack2` 是一个新的 `DisposableStack` 实例，它拥有了原来 `stack1` 中的资源（defer 的回调）。 `stack1` 的状态变为 `disposed`，不再管理任何资源。

**之后执行：** `stack2.dispose();`

**输出：** `disposed` 变量的值变为 `true`。

**涉及用户常见的编程错误：**

1. **忘记调用 `dispose()`：** 如果创建了 `DisposableStack` 实例，但忘记在不再需要时调用 `dispose()`，则注册的资源可能不会被及时释放，导致资源泄漏。

   ```javascript
   function processData() {
     const stack = new DisposableStack();
     // ... 使用 stack.use, stack.adopt, stack.defer 注册资源 ...
     // 忘记调用 stack.dispose();
   }
   // 如果 processData 被频繁调用，可能会导致资源泄漏。
   ```

2. **在 `DisposableStack` 已经释放后尝试使用它：**  在调用 `dispose()` 后，或者在 `move()` 操作后，原始的 `DisposableStack` 实例的状态变为 `disposed`。如果尝试在其上调用 `use`、`adopt` 或 `defer`，会抛出 `ReferenceError`。

   ```javascript
   const stack = new DisposableStack();
   stack.use({ dispose: () => console.log('释放') });
   stack.dispose();
   try {
     stack.use({ dispose: () => {} }); // 抛出 ReferenceError
   } catch (e) {
     console.error(e);
   }
   ```

3. **假设 `DisposableStack` 会自动管理所有类型的资源：** `DisposableStack` 需要注册需要管理的资源。对于没有 `dispose` 方法的对象，需要使用 `adopt` 提供自定义的释放逻辑。

   ```javascript
   const stack = new DisposableStack();
   const fileHandle = openFile('data.txt');
   // 错误：直接使用，没有注册，不会自动关闭文件
   // 正确做法：stack.adopt(fileHandle, (handle) => closeFile(handle));
   ```

4. **在 `adopt` 中提供的释放函数不正确：** 如果 `adopt` 方法提供的释放函数无法正确释放资源，也会导致问题。

   ```javascript
   const stack = new DisposableStack();
   let resourceValue = 100;
   stack.adopt({}, () => {
     resourceValue = 0; // 假设这里应该释放与某个 resourceValue 相关的外部资源，但实际没有做。
   });
   stack.dispose();
   // 外部资源可能没有被正确释放。
   ```

了解 `DisposableStack` 的工作原理和正确的使用方式对于编写健壮和资源高效的 JavaScript 代码非常重要。V8 的源代码实现细节有助于我们深入理解其行为和限制。

Prompt: 
```
这是目录为v8/src/builtins/builtins-disposable-stack.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-disposable-stack.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/common/globals.h"
#include "src/handles/maybe-handles.h"
#include "src/objects/casting.h"
#include "src/objects/contexts.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-disposable-stack-inl.h"
#include "src/objects/js-disposable-stack.h"
#include "src/objects/js-function.h"

namespace v8 {
namespace internal {

// https://arai-a.github.io/ecma262-compare/?pr=3000&id=sec-disposablestack
BUILTIN(DisposableStackConstructor) {
  const char* const kMethodName = "DisposableStack";
  HandleScope scope(isolate);

  // 1. If NewTarget is undefined, throw a TypeError exception.
  if (IsUndefined(*args.new_target(), isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kConstructorNotFunction,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  kMethodName)));
  }

  // 2. Let disposableStack be ? OrdinaryCreateFromConstructor(NewTarget,
  //    "%DisposableStack.prototype%", « [[DisposableState]],
  //    [[DisposeCapability]] »).
  DirectHandle<Map> map;
  Handle<JSFunction> target = args.target();
  Handle<JSReceiver> new_target = Cast<JSReceiver>(args.new_target());

  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, map, JSFunction::GetDerivedMap(isolate, target, new_target));

  DirectHandle<JSSyncDisposableStack> disposable_stack =
      isolate->factory()->NewJSSyncDisposableStack(map);
  // 3. Set disposableStack.[[DisposableState]] to pending.
  // 4. Set disposableStack.[[DisposeCapability]] to NewDisposeCapability().
  JSDisposableStackBase::InitializeJSDisposableStackBase(isolate,
                                                         disposable_stack);
  // 5. Return disposableStack.
  return *disposable_stack;
}

// https://arai-a.github.io/ecma262-compare/?pr=3000&id=sec-disposablestack.prototype.use
BUILTIN(DisposableStackPrototypeUse) {
  const char* const kMethodName = "DisposableStack.prototype.use";
  HandleScope scope(isolate);

  // 1. Let disposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(disposableStack, [[DisposableState]]).
  CHECK_RECEIVER(JSSyncDisposableStack, disposable_stack, kMethodName);
  Handle<JSAny> value = args.at<JSAny>(1);

  // use(value) does nothing when the value is null or undefined, so return
  // early.
  if (IsNullOrUndefined(*value)) {
    return *value;
  }

  // 3. If disposableStack.[[DisposableState]] is disposed, throw a
  //    ReferenceError exception.
  if (disposable_stack->state() == DisposableStackState::kDisposed) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewReferenceError(
            MessageTemplate::kDisposableStackIsDisposed,
            isolate->factory()->NewStringFromAsciiChecked(kMethodName)));
  }

  Handle<Object> method;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, method,
      JSDisposableStackBase::CheckValueAndGetDisposeMethod(
          isolate, value, DisposeMethodHint::kSyncDispose));

  // 4. Perform ? AddDisposableResource(disposableStack.[[DisposeCapability]],
  //    value, sync-dispose).
  JSDisposableStackBase::Add(isolate, disposable_stack, value, method,
                             DisposeMethodCallType::kValueIsReceiver,
                             DisposeMethodHint::kSyncDispose);

  // 5. Return value.
  return *value;
}

BUILTIN(DisposableStackPrototypeDispose) {
  const char* const kMethodName = "DisposableStack.prototype.dispose";
  HandleScope scope(isolate);

  // 1. Let disposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(disposableStack, [[DisposableState]]).
  CHECK_RECEIVER(JSSyncDisposableStack, disposable_stack, kMethodName);

  // 3. If disposableStack.[[DisposableState]] is disposed, return undefined.
  if (disposable_stack->state() == DisposableStackState::kDisposed) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // 4. Set disposableStack.[[DisposableState]] to disposed.
  // Will be done in DisposeResources call.

  // 5. Return ? DisposeResources(disposableStack.[[DisposeCapability]],
  //    NormalCompletion(undefined)).
  Handle<Object> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, result,
      JSDisposableStackBase::DisposeResources(
          isolate, disposable_stack, MaybeHandle<Object>(),
          DisposableStackResourcesType::kAllSync));

  return *result;
}

BUILTIN(DisposableStackPrototypeGetDisposed) {
  const char* const kMethodName = "get DisposableStack.prototype.disposed";
  HandleScope scope(isolate);

  // 1. Let disposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(disposableStack, [[DisposableState]]).
  CHECK_RECEIVER(JSSyncDisposableStack, disposable_stack, kMethodName);

  // 3. If disposableStack.[[DisposableState]] is disposed, return true.
  if (disposable_stack->state() == DisposableStackState::kDisposed) {
    return ReadOnlyRoots(isolate).true_value();
  }
  // 4. Otherwise, return false.
  return ReadOnlyRoots(isolate).false_value();
}

// https://arai-a.github.io/ecma262-compare/?pr=3000&id=sec-disposablestack.prototype.adopt
BUILTIN(DisposableStackPrototypeAdopt) {
  const char* const kMethodName = "DisposableStack.prototype.adopt";
  HandleScope scope(isolate);
  DirectHandle<Object> value = args.at(1);
  Handle<Object> on_dispose = args.at(2);

  // 1. Let disposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(disposableStack, [[DisposableState]]).
  CHECK_RECEIVER(JSSyncDisposableStack, disposable_stack, kMethodName);

  // 3. If disposableStack.[[DisposableState]] is disposed, throw a
  //    ReferenceError exception.
  if (disposable_stack->state() == DisposableStackState::kDisposed) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewReferenceError(
            MessageTemplate::kDisposableStackIsDisposed,
            isolate->factory()->NewStringFromAsciiChecked(kMethodName)));
  }

  // 4. If IsCallable(onDispose) is false, throw a TypeError exception.
  if (!IsCallable(*on_dispose)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNotCallable, on_dispose));
  }

  // 5. Let closure be a new Abstract Closure with no parameters that captures
  //    value and onDispose and performs the following steps when called:
  //      a. Return ? Call(onDispose, undefined, « value »).
  // 6. Let F be CreateBuiltinFunction(closure, 0, "", « »).
  // 7. Perform ? AddDisposableResource(disposableStack.[[DisposeCapability]],
  //    undefined, sync-dispose, F).
  // Instead of creating an abstract closure and a function, we pass
  // DisposeMethodCallType::kArgument so at the time of disposal, the value will
  // be passed as the argument to the method.
  JSDisposableStackBase::Add(isolate, disposable_stack, value, on_dispose,
                             DisposeMethodCallType::kValueIsArgument,
                             DisposeMethodHint::kSyncDispose);

  // 8. Return value.
  return *value;
}

// https://arai-a.github.io/ecma262-compare/?pr=3000&id=sec-disposablestack.prototype.defer
BUILTIN(DisposableStackPrototypeDefer) {
  const char* const kMethodName = "DisposableStack.prototype.defer";
  HandleScope scope(isolate);
  Handle<Object> on_dispose = args.at(1);

  // 1. Let disposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(disposableStack, [[DisposableState]]).
  CHECK_RECEIVER(JSSyncDisposableStack, disposable_stack, kMethodName);

  // 3. If disposableStack.[[DisposableState]] is disposed, throw a
  // ReferenceError exception.
  if (disposable_stack->state() == DisposableStackState::kDisposed) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewReferenceError(
            MessageTemplate::kDisposableStackIsDisposed,
            isolate->factory()->NewStringFromAsciiChecked(kMethodName)));
  }

  // 4. If IsCallable(onDispose) is false, throw a TypeError exception.
  if (!IsCallable(*on_dispose)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNotCallable, on_dispose));
  }

  // 5. Perform ? AddDisposableResource(disposableStack.[[DisposeCapability]],
  // undefined, sync-dispose, onDispose).
  JSDisposableStackBase::Add(
      isolate, disposable_stack,
      ReadOnlyRoots(isolate).undefined_value_handle(), on_dispose,
      DisposeMethodCallType::kValueIsReceiver, DisposeMethodHint::kSyncDispose);

  // 6. Return undefined.
  return ReadOnlyRoots(isolate).undefined_value();
}

BUILTIN(DisposableStackPrototypeMove) {
  const char* const kMethodName = "DisposableStack.prototype.move";
  HandleScope scope(isolate);

  // 1. Let disposableStack be the this value.
  // 2. Perform ? RequireInternalSlot(disposableStack, [[DisposableState]]).
  CHECK_RECEIVER(JSSyncDisposableStack, disposable_stack, kMethodName);

  // 3. If disposableStack.[[DisposableState]] is disposed, throw a
  //    ReferenceError exception.
  if (disposable_stack->state() == DisposableStackState::kDisposed) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewReferenceError(
            MessageTemplate::kDisposableStackIsDisposed,
            isolate->factory()->NewStringFromAsciiChecked(kMethodName)));
  }

  // 4. Let newDisposableStack be ?
  //    OrdinaryCreateFromConstructor(%DisposableStack%,
  //    "%DisposableStack.prototype%", « [[DisposableState]],
  //     [[DisposeCapability]] »).
  // 5. Set newDisposableStack.[[DisposableState]] to pending.

  Tagged<JSFunction> constructor_function =
      Cast<JSFunction>(isolate->native_context()->get(
          Context::JS_DISPOSABLE_STACK_FUNCTION_INDEX));
  DirectHandle<Map> map(constructor_function->initial_map(), isolate);

  DirectHandle<JSSyncDisposableStack> new_disposable_stack =
      isolate->factory()->NewJSSyncDisposableStack(map);

  // 6. Set newDisposableStack.[[DisposeCapability]] to
  //    disposableStack.[[DisposeCapability]].
  new_disposable_stack->set_stack(disposable_stack->stack());
  new_disposable_stack->set_length(disposable_stack->length());
  new_disposable_stack->set_state(DisposableStackState::kPending);
  new_disposable_stack->set_error(*(isolate->factory()->uninitialized_value()));
  new_disposable_stack->set_error_message(
      *(isolate->factory()->uninitialized_value()));

  // 7. Set disposableStack.[[DisposeCapability]] to NewDisposeCapability().
  disposable_stack->set_stack(ReadOnlyRoots(isolate).empty_fixed_array());
  disposable_stack->set_length(0);
  disposable_stack->set_error(*(isolate->factory()->uninitialized_value()));
  disposable_stack->set_error_message(
      *(isolate->factory()->uninitialized_value()));

  // 8. Set disposableStack.[[DisposableState]] to disposed.
  disposable_stack->set_state(DisposableStackState::kDisposed);

  // 9. Return newDisposableStack.
  return *new_disposable_stack;
}

}  // namespace internal
}  // namespace v8

"""

```