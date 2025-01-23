Response:
My thinking process to answer the request goes like this:

1. **Understand the Request:** The core request is to analyze the provided C++ header file (`isolate-inl.h`) from the V8 JavaScript engine and describe its functionality. Specific points to address are:
    * General functionality.
    * If it were a `.tq` file, what that would imply.
    * Its relationship to JavaScript, with examples.
    * Code logic with hypothetical inputs/outputs.
    * Common programming errors related to its functionality.

2. **Initial Analysis of the Header File:**
    * **File Name:** `isolate-inl.h` strongly suggests this file defines inline functions related to the `Isolate` class in V8. The `-inl.h` convention is common for inline implementations.
    * **Includes:** The included headers (`isolate.h`, various `objects-inl.h`, etc.) hint at core V8 concepts like isolates, contexts, functions, objects, and exception handling.
    * **Namespace:** It's within the `v8::internal` namespace, indicating internal V8 implementation details.
    * **Key Class:** The presence of `class Isolate` and methods directly within its definition confirms this file is extending the `Isolate` class.
    * **Inline Functions:** The `V8_INLINE` macro marks many functions, confirming the inline nature.
    * **Focus Areas:**  Scanning the method names reveals a focus on:
        * Current isolate access (`Current`, `TryGetCurrent`, `IsCurrent`).
        * Context management (`set_context`, `native_context`, `GetIncumbentContext`).
        * Exception handling (`set_exception`, `clear_exception`, `has_exception`).
        * Message handling (`set_pending_message`, `pending_message`).
        * Global objects (`global_object`, `global_proxy`).
        * Internal state (`InFastCCall`, `is_execution_terminating`).
        * Debugging and verification (`VerifyBuiltinsResult`).
        * Native context fields (macros for accessing).

3. **Break Down Functionality:**  I start grouping the identified methods into logical functional areas:
    * **Isolate Access and Management:** Functions to get the current isolate, check if it's the current one.
    * **Context Management:** Setting, getting, and managing different types of contexts (current, native, script-having). Understanding the concept of a context is crucial here – it's the execution environment for JavaScript code.
    * **Exception Handling:**  The core mechanism for dealing with errors in V8. This involves setting, clearing, and checking for exceptions. The idea of "internal exceptions" is worth noting.
    * **Message Handling:**  A way to store and retrieve pending messages, likely related to error reporting or asynchronous operations.
    * **Global Object Access:**  Provides access to the global object and its proxy, essential for executing JavaScript.
    * **Internal State Tracking:**  Flags and methods to track the internal state of the isolate (e.g., within a C++ call).
    * **Debugging:** Methods used in debug builds for validating results.

4. **Address Specific Points in the Request:**

    * **`.tq` Extension:** I know `.tq` files are used for Torque, V8's type-safe TypeScript-like language for implementing builtins. So, if the file had that extension, it would contain Torque code for implementing some of the functionality related to the `Isolate`.
    * **JavaScript Relationship:** This is key. I need to connect the C++ concepts to how they manifest in JavaScript. Contexts relate to global scope. Exceptions are the errors JavaScript developers see. The global object is `window` (in browsers) or the global object in Node.js. I need to provide concrete JavaScript examples to illustrate these connections. For example, throwing and catching exceptions, accessing global variables, etc.
    * **Code Logic/Inference:**  I look for methods where a simple logic flow can be illustrated. `has_exception` is a good example: if `thread_local_top()->exception_` is not the "hole" value, then there's an exception. I can create a simple input/output scenario where an exception is set and then checked.
    * **Common Programming Errors:**  Think about how developers might misuse or misunderstand the concepts exposed by these functions. Common errors related to `Isolate` would likely involve:
        * Not handling exceptions properly (leading to unhandled promise rejections, for example).
        * Incorrectly assuming the current context.
        * Memory leaks if context/isolate lifecycles are not managed.
        * Trying to access isolate-specific data from the wrong isolate in a multi-isolate environment (less common for typical JS developers but relevant in V8 embedding scenarios).

5. **Structure the Answer:** I organize the information logically, following the points in the request. Using headings and bullet points improves readability. I make sure the JavaScript examples are clear and relevant.

6. **Refine and Review:** I reread my answer to ensure accuracy, clarity, and completeness. I check if the JavaScript examples are correct and if the explanations are easy to understand for someone who might not be a V8 expert. I double-check for any technical inaccuracies. For example, ensuring I correctly explain the concept of "the hole" value.

By following these steps, I can systematically analyze the C++ header file and generate a comprehensive and informative answer that addresses all aspects of the user's request. The key is to connect the low-level C++ details to the higher-level concepts that JavaScript developers interact with.
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_EXECUTION_ISOLATE_INL_H_
#define V8_EXECUTION_ISOLATE_INL_H_

#include "src/execution/isolate.h"
#include "src/objects/contexts-inl.h"
#include "src/objects/js-function.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/property-cell.h"
#include "src/objects/regexp-match-info.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/source-text-module-inl.h"

#ifdef DEBUG
#include "src/common/ptr-compr-inl.h"
#include "src/runtime/runtime-utils.h"
#endif

namespace v8 {
namespace internal {

// static
V8_INLINE Isolate::PerIsolateThreadData*
Isolate::CurrentPerIsolateThreadData() {
  return g_current_per_isolate_thread_data_;
}

// static
V8_INLINE Isolate* Isolate::Current() {
  Isolate* isolate = TryGetCurrent();
  DCHECK_NOT_NULL(isolate);
  return isolate;
}

bool Isolate::IsCurrent() const { return this == TryGetCurrent(); }

void Isolate::set_context(Tagged<Context> context) {
  DCHECK(context.is_null() || IsContext(context));
  thread_local_top()->context_ = context;
}

Handle<NativeContext> Isolate::native_context() {
  DCHECK(!context().is_null());
  return handle(context()->native_context(), this);
}

Tagged<NativeContext> Isolate::raw_native_context() {
  DCHECK(!context().is_null());
  return context()->native_context();
}

void Isolate::set_topmost_script_having_context(Tagged<Context> context) {
  DCHECK(context.is_null() || IsContext(context));
  thread_local_top()->topmost_script_having_context_ = context;
}

void Isolate::clear_topmost_script_having_context() {
  static_assert(Context::kNoContext == 0);
  thread_local_top()->topmost_script_having_context_ = Context();
}

Handle<NativeContext> Isolate::GetIncumbentContext() {
  Tagged<Context> maybe_topmost_script_having_context =
      topmost_script_having_context();
  if (V8_LIKELY(!maybe_topmost_script_having_context.is_null())) {
    // The topmost script-having context value is guaranteed to be valid only
    // inside the Api callback however direct calls of Api callbacks from
    // builtins or optimized code do not change the current VM state, so we
    // allow JS VM state too.
    DCHECK(current_vm_state() == EXTERNAL ||  // called from C++ code
           current_vm_state() == JS);         // called from JS code directly

    Tagged<NativeContext> incumbent_context =
        maybe_topmost_script_having_context->native_context();
    DCHECK_EQ(incumbent_context, *GetIncumbentContextSlow());
    return handle(incumbent_context, this);
  }
  return GetIncumbentContextSlow();
}

void Isolate::set_pending_message(Tagged<Object> message_obj) {
  DCHECK(IsTheHole(message_obj, this) || IsJSMessageObject(message_obj));
  thread_local_top()->pending_message_ = message_obj;
}

Tagged<Object> Isolate::pending_message() {
  return thread_local_top()->pending_message_;
}

void Isolate::clear_pending_message() {
  set_pending_message(ReadOnlyRoots(this).the_hole_value());
}

bool Isolate::has_pending_message() {
  return !IsTheHole(pending_message(), this);
}

Tagged<Object> Isolate::exception() {
  CHECK(has_exception());
  DCHECK(!IsException(thread_local_top()->exception_, this));
  return thread_local_top()->exception_;
}

void Isolate::set_exception(Tagged<Object> exception_obj) {
  DCHECK(!IsException(exception_obj, this));
  thread_local_top()->exception_ = exception_obj;
}

void Isolate::clear_internal_exception() {
  DCHECK(!IsException(thread_local_top()->exception_, this));
  thread_local_top()->exception_ = ReadOnlyRoots(this).the_hole_value();
}

void Isolate::clear_exception() {
  clear_internal_exception();
  if (try_catch_handler()) try_catch_handler()->Reset();
}

bool Isolate::has_exception() {
  ThreadLocalTop* top = thread_local_top();
  DCHECK(!IsException(top->exception_, this));
  return !IsTheHole(top->exception_, this);
}

bool Isolate::is_execution_terminating() {
  return thread_local_top()->exception_ ==
         i::ReadOnlyRoots(this).termination_exception();
}

#ifdef DEBUG
Tagged<Object> Isolate::VerifyBuiltinsResult(Tagged<Object> result) {
  if (is_execution_terminating() && !v8_flags.strict_termination_checks) {
    // We may be missing places where termination checks are handled properly.
    // If that's the case, it's likely that we'll have one sitting around when
    // we return from a builtin. If we're not looking to find such bugs
    // (strict_termination_checks is false), simply return the exception marker.
    return ReadOnlyRoots(this).exception();
  }

  // Here we use full pointer comparison as the result might be an object
  // outside of the main pointer compression heap (e.g. in trusted space).
  DCHECK_EQ(has_exception(),
            result.SafeEquals(ReadOnlyRoots(this).exception()));

#ifdef V8_COMPRESS_POINTERS
  // Check that the returned pointer is actually part of the current isolate (or
  // the shared isolate), because that's the assumption in generated code (which
  // might call this builtin).
  Isolate* isolate;
  if (!IsSmi(result) &&
      GetIsolateFromHeapObject(Cast<HeapObject>(result), &isolate)) {
    DCHECK(isolate == this || isolate == shared_space_isolate());
  }
#endif

  return result;
}

ObjectPair Isolate::VerifyBuiltinsResult(ObjectPair pair) {
#ifdef V8_HOST_ARCH_64_BIT
  Tagged<Object> x(pair.x), y(pair.y);

  // Here we use full pointer comparison as the result might be an object
  // outside of the main pointer compression heap (e.g. in trusted space).
  DCHECK_EQ(has_exception(), x.SafeEquals(ReadOnlyRoots(this).exception()));

#ifdef V8_COMPRESS_POINTERS
  // Check that the returned pointer is actually part of the current isolate (or
  // the shared isolate), because that's the assumption in generated code (which
  // might call this builtin).
  Isolate* isolate;
  if (!IsSmi(x) && GetIsolateFromHeapObject(Cast<HeapObject>(x), &isolate)) {
    DCHECK(isolate == this || isolate == shared_space_isolate());
  }
  if (!IsSmi(y) && GetIsolateFromHeapObject(Cast<HeapObject>(y), &isolate)) {
    DCHECK(isolate == this || isolate == shared_space_isolate());
  }
#endif
#endif  // V8_HOST_ARCH_64_BIT
  return pair;
}
#endif  // DEBUG

bool Isolate::is_catchable_by_javascript(Tagged<Object> exception) {
  return exception != ReadOnlyRoots(heap()).termination_exception();
}

bool Isolate::InFastCCall() const {
  return isolate_data()->fast_c_call_caller_fp() != kNullAddress;
}

bool Isolate::is_catchable_by_wasm(Tagged<Object> exception) {
  if (!is_catchable_by_javascript(exception)) return false;
  if (!IsJSObject(exception)) return true;
  return !LookupIterator::HasInternalMarkerProperty(
      this, Cast<JSReceiver>(exception), factory()->wasm_uncatchable_symbol());
}

void Isolate::FireBeforeCallEnteredCallback() {
  for (auto& callback : before_call_entered_callbacks_) {
    callback(reinterpret_cast<v8::Isolate*>(this));
  }
}

Handle<JSGlobalObject> Isolate::global_object() {
  return handle(context()->global_object(), this);
}

Handle<JSGlobalProxy> Isolate::global_proxy() {
  return handle(context()->global_proxy(), this);
}

Isolate::ExceptionScope::ExceptionScope(Isolate* isolate)
    : isolate_(isolate), exception_(isolate_->exception(), isolate_) {
  isolate_->clear_internal_exception();
}

Isolate::ExceptionScope::~ExceptionScope() {
  isolate_->set_exception(*exception_);
}

bool Isolate::IsInitialArrayPrototype(Tagged<JSArray> array) {
  DisallowGarbageCollection no_gc;
  return IsInCreationContext(array, Context::INITIAL_ARRAY_PROTOTYPE_INDEX);
}

#define NATIVE_CONTEXT_FIELD_ACCESSOR(index, type, name)              \
  Handle<UNPAREN(type)> Isolate::name() {                             \
    return Handle<UNPAREN(type)>(raw_native_context()->name(), this); \
  }                                                                   \
  bool Isolate::is_##name(Tagged<UNPAREN(type)> value) {              \
    return raw_native_context()->is_##name(value);                    \
  }
NATIVE_CONTEXT_FIELDS(NATIVE_CONTEXT_FIELD_ACCESSOR)
#undef NATIVE_CONTEXT_FIELD_ACCESSOR

}  // namespace internal
}  // namespace v8

#endif  // V8_EXECUTION_ISOLATE_INL_H_
```

### `v8/src/execution/isolate-inl.h` 的功能

`v8/src/execution/isolate-inl.h` 是 V8 引擎中 `Isolate` 类的内联函数定义文件。 `Isolate` 是 V8 中一个非常核心的概念，可以将其理解为一个独立的 JavaScript 虚拟机实例。  这个文件中的函数提供了对 `Isolate` 对象状态和功能的快速访问和操作。

其主要功能包括：

1. **获取当前 Isolate:** 提供静态方法 `Current()` 来获取当前线程正在运行的 `Isolate` 实例。
2. **管理 Context:**  Context 可以理解为 JavaScript 代码的执行环境，包含了全局对象等信息。该文件提供了设置和获取当前 `Isolate` 的 Context（`set_context`, `context`, `native_context`, `raw_native_context`）以及与脚本相关的 Context 信息 (`set_topmost_script_having_context`, `clear_topmost_script_having_context`, `GetIncumbentContext`)。
3. **处理消息:**  允许设置和获取待处理的消息 (`set_pending_message`, `pending_message`, `clear_pending_message`, `has_pending_message`)，这些消息可能与错误报告或其他异步操作有关。
4. **异常处理:** 提供了设置、清除和检查异常状态的功能 (`set_exception`, `clear_internal_exception`, `clear_exception`, `has_exception`, `is_execution_terminating`)。
5. **内置函数结果验证 (Debug 模式):** 在调试模式下，包含用于验证内置函数返回结果的函数 (`VerifyBuiltinsResult`)，确保返回的对象属于正确的堆。
6. **判断异常是否可捕获:** 提供方法判断异常是否可以被 JavaScript 或 WebAssembly 代码捕获 (`is_catchable_by_javascript`, `is_catchable_by_wasm`).
7. **回调管理:** 提供了在进入函数调用前后触发回调的机制 (`FireBeforeCallEnteredCallback`).
8. **访问全局对象:** 提供便捷的方法来获取当前 Context 的全局对象和全局代理 (`global_object`, `global_proxy`).
9. **异常作用域管理:**  通过 `ExceptionScope` 类，可以方便地管理异常状态，确保在作用域结束时恢复之前的异常状态。
10. **访问 Native Context 字段:**  通过宏 `NATIVE_CONTEXT_FIELDS` 定义了一系列访问 Native Context 特定字段的内联函数。
11. **判断是否处于快速 C 调用中:**  `InFastCCall()` 用于检查当前是否正处于一个快速 C 函数调用中。
12. **判断是否是初始 Array 原型:** `IsInitialArrayPrototype` 用于检查给定的数组是否是初始的 Array 原型对象。

**为什么是 `.inl.h`:**  `.inl.h` 后缀通常用于存放内联函数的定义。将这些函数的定义放在头文件中，允许编译器在调用点直接将函数代码展开，从而提高性能，尤其对于频繁调用的底层函数。

### 如果 `v8/src/execution/isolate-inl.h` 以 `.tq` 结尾

如果 `v8/src/execution/isolate-inl.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。

**V8 Torque** 是 V8 使用的一种领域特定语言，它类似于 TypeScript，用于编写高效且类型安全的 V8 内置函数（builtins）。 Torque 代码会被编译成 C++ 代码，然后被 V8 引擎使用。

在这种情况下，该文件将包含使用 Torque 语法编写的 `Isolate` 类相关功能的实现。例如，用 Torque 实现获取当前 Isolate、设置 Context 或处理异常的逻辑。

### 与 JavaScript 的功能关系

`v8/src/execution/isolate-inl.h` 中定义的功能与 JavaScript 的执行息息相关。`Isolate` 是 JavaScript 代码运行的沙箱环境，Context 则是代码执行的上下文。

**JavaScript 示例：**

1. **Context 的概念:**

   ```javascript
   // 全局变量属于全局 Context
   var globalVar = 10;

   function myFunction() {
     // 函数内部可以访问全局 Context 的变量
     console.log(globalVar);
   }

   myFunction();
   ```

   在 V8 内部，`Isolate` 的 `context()` 方法会返回当前的 JavaScript 上下文，其中包含了 `globalVar`。

2. **异常处理:**

   ```javascript
   try {
     throw new Error("Something went wrong!");
   } catch (e) {
     console.error("Caught an error:", e.message);
   }
   ```

   当 JavaScript 代码抛出异常时，V8 内部会使用 `Isolate::set_exception()` 来记录这个异常对象。 `Isolate::has_exception()` 会返回 `true`。`catch` 语句能够捕获这个异常，这与 V8 内部的异常处理机制紧密相关。

3. **全局对象:**

   ```javascript
   // 在浏览器中
   console.log(window);

   // 在 Node.js 中
   console.log(global);
   ```

   `Isolate::global_object()` 返回的是 `window` (在浏览器环境) 或 `global` (在 Node.js 环境) 这样的全局对象。

4. **消息处理 (例如，错误消息):**

   ```javascript
   try {
     undefinedFunction(); // 触发一个 ReferenceError
   } catch (e) {
     // V8 内部会将错误信息作为消息进行处理
     console.error(e.message);
   }
   ```

   当 JavaScript 代码运行时发生错误，V8 可能会使用 `Isolate::set_pending_message()` 来存储相关的错误消息，以便后续处理或报告。

### 代码逻辑推理

**假设输入：**

1. 在某个 JavaScript 函数执行过程中抛出了一个 `TypeError` 异常。
2. 当前 `Isolate` 的 `thread_local_top()->exception_` 为 "the_hole" (表示没有异常)。

**代码逻辑推理（基于 `has_exception()` 和 `set_exception()`）：**

1. 当 JavaScript 引擎执行到 `throw new TypeError(...)` 时，V8 内部的异常处理机制会被触发。
2. V8 会创建一个表示该 `TypeError` 的对象。
3. 调用 `Isolate::set_exception(exception_object)`，其中 `exception_object` 是新创建的 `TypeError` 对象。
4. 在 `set_exception()` 内部，`thread_local_top()->exception_` 的值会被更新为 `exception_object`。
5. 如果之后调用 `Isolate::has_exception()`，由于 `thread_local_top()->exception_` 不再是 "the_hole"，该方法将返回 `true`。

**输出：**

* 调用 `Isolate::has_exception()` 将返回 `true`。
* 调用 `Isolate::exception()` 将返回表示该 `TypeError` 的对象。

### 用户常见的编程错误

1. **未处理的异常:**

   ```javascript
   function riskyOperation() {
     throw new Error("Something went wrong");
   }

   riskyOperation(); // 没有 try...catch 包裹，导致程序崩溃或异常传播
   ```

   V8 内部会记录这个未处理的异常，但如果用户没有使用 `try...catch` 或其他机制来捕获它，可能会导致程序非预期终止或进入错误状态。 这与 `Isolate` 的异常处理机制相关。

2. **访问错误的 Context 中的变量:**

   虽然 JavaScript 开发者通常不需要直接管理 Context，但在一些高级场景（例如，使用 `vm` 模块或嵌入 V8）中，错误地假设当前代码运行的 Context 可能导致问题。

   ```javascript
   const vm = require('vm');
   const context = vm.createContext({ value: 10 });
   const script = new vm.Script('console.log(value)');

   script.runInThisContext(); // 错误：在当前的全局 Context 中查找 value
   script.runInContext(context); // 正确：在创建的 context 中执行
   ```

   在 V8 内部，这涉及到 `Isolate` 对不同 Context 的管理。错误的 Context 会导致找不到预期的变量或函数。

3. **在异步操作中假设 Context:**

   ```javascript
   let myValue = 5;

   setTimeout(() => {
     console.log(myValue); // 依赖于闭包，而非执行时的 Context
   }, 1000);
   ```

   虽然这个例子不会直接导致 `Isolate` 级别的错误，但在更复杂的异步场景中，尤其是在涉及多个 `Isolate` 或 Context 的情况下，理解代码执行时的 Context 非常重要。

总而言之，`v8/src/execution/isolate-inl.h` 定义了 V8 引擎核心组件 `Isolate` 的一些关键操作，这些操作直接支撑着 JavaScript 代码的执行、异常处理和上下文管理。 理解这些底层机制有助于更深入地理解 JavaScript 运行时的行为。

### 提示词
```
这是目录为v8/src/execution/isolate-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_EXECUTION_ISOLATE_INL_H_
#define V8_EXECUTION_ISOLATE_INL_H_

#include "src/execution/isolate.h"
#include "src/objects/contexts-inl.h"
#include "src/objects/js-function.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/property-cell.h"
#include "src/objects/regexp-match-info.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/source-text-module-inl.h"

#ifdef DEBUG
#include "src/common/ptr-compr-inl.h"
#include "src/runtime/runtime-utils.h"
#endif

namespace v8 {
namespace internal {

// static
V8_INLINE Isolate::PerIsolateThreadData*
Isolate::CurrentPerIsolateThreadData() {
  return g_current_per_isolate_thread_data_;
}

// static
V8_INLINE Isolate* Isolate::Current() {
  Isolate* isolate = TryGetCurrent();
  DCHECK_NOT_NULL(isolate);
  return isolate;
}

bool Isolate::IsCurrent() const { return this == TryGetCurrent(); }

void Isolate::set_context(Tagged<Context> context) {
  DCHECK(context.is_null() || IsContext(context));
  thread_local_top()->context_ = context;
}

Handle<NativeContext> Isolate::native_context() {
  DCHECK(!context().is_null());
  return handle(context()->native_context(), this);
}

Tagged<NativeContext> Isolate::raw_native_context() {
  DCHECK(!context().is_null());
  return context()->native_context();
}

void Isolate::set_topmost_script_having_context(Tagged<Context> context) {
  DCHECK(context.is_null() || IsContext(context));
  thread_local_top()->topmost_script_having_context_ = context;
}

void Isolate::clear_topmost_script_having_context() {
  static_assert(Context::kNoContext == 0);
  thread_local_top()->topmost_script_having_context_ = Context();
}

Handle<NativeContext> Isolate::GetIncumbentContext() {
  Tagged<Context> maybe_topmost_script_having_context =
      topmost_script_having_context();
  if (V8_LIKELY(!maybe_topmost_script_having_context.is_null())) {
    // The topmost script-having context value is guaranteed to be valid only
    // inside the Api callback however direct calls of Api callbacks from
    // builtins or optimized code do not change the current VM state, so we
    // allow JS VM state too.
    DCHECK(current_vm_state() == EXTERNAL ||  // called from C++ code
           current_vm_state() == JS);         // called from JS code directly

    Tagged<NativeContext> incumbent_context =
        maybe_topmost_script_having_context->native_context();
    DCHECK_EQ(incumbent_context, *GetIncumbentContextSlow());
    return handle(incumbent_context, this);
  }
  return GetIncumbentContextSlow();
}

void Isolate::set_pending_message(Tagged<Object> message_obj) {
  DCHECK(IsTheHole(message_obj, this) || IsJSMessageObject(message_obj));
  thread_local_top()->pending_message_ = message_obj;
}

Tagged<Object> Isolate::pending_message() {
  return thread_local_top()->pending_message_;
}

void Isolate::clear_pending_message() {
  set_pending_message(ReadOnlyRoots(this).the_hole_value());
}

bool Isolate::has_pending_message() {
  return !IsTheHole(pending_message(), this);
}

Tagged<Object> Isolate::exception() {
  CHECK(has_exception());
  DCHECK(!IsException(thread_local_top()->exception_, this));
  return thread_local_top()->exception_;
}

void Isolate::set_exception(Tagged<Object> exception_obj) {
  DCHECK(!IsException(exception_obj, this));
  thread_local_top()->exception_ = exception_obj;
}

void Isolate::clear_internal_exception() {
  DCHECK(!IsException(thread_local_top()->exception_, this));
  thread_local_top()->exception_ = ReadOnlyRoots(this).the_hole_value();
}

void Isolate::clear_exception() {
  clear_internal_exception();
  if (try_catch_handler()) try_catch_handler()->Reset();
}

bool Isolate::has_exception() {
  ThreadLocalTop* top = thread_local_top();
  DCHECK(!IsException(top->exception_, this));
  return !IsTheHole(top->exception_, this);
}

bool Isolate::is_execution_terminating() {
  return thread_local_top()->exception_ ==
         i::ReadOnlyRoots(this).termination_exception();
}

#ifdef DEBUG
Tagged<Object> Isolate::VerifyBuiltinsResult(Tagged<Object> result) {
  if (is_execution_terminating() && !v8_flags.strict_termination_checks) {
    // We may be missing places where termination checks are handled properly.
    // If that's the case, it's likely that we'll have one sitting around when
    // we return from a builtin. If we're not looking to find such bugs
    // (strict_termination_checks is false), simply return the exception marker.
    return ReadOnlyRoots(this).exception();
  }

  // Here we use full pointer comparison as the result might be an object
  // outside of the main pointer compression heap (e.g. in trusted space).
  DCHECK_EQ(has_exception(),
            result.SafeEquals(ReadOnlyRoots(this).exception()));

#ifdef V8_COMPRESS_POINTERS
  // Check that the returned pointer is actually part of the current isolate (or
  // the shared isolate), because that's the assumption in generated code (which
  // might call this builtin).
  Isolate* isolate;
  if (!IsSmi(result) &&
      GetIsolateFromHeapObject(Cast<HeapObject>(result), &isolate)) {
    DCHECK(isolate == this || isolate == shared_space_isolate());
  }
#endif

  return result;
}

ObjectPair Isolate::VerifyBuiltinsResult(ObjectPair pair) {
#ifdef V8_HOST_ARCH_64_BIT
  Tagged<Object> x(pair.x), y(pair.y);

  // Here we use full pointer comparison as the result might be an object
  // outside of the main pointer compression heap (e.g. in trusted space).
  DCHECK_EQ(has_exception(), x.SafeEquals(ReadOnlyRoots(this).exception()));

#ifdef V8_COMPRESS_POINTERS
  // Check that the returned pointer is actually part of the current isolate (or
  // the shared isolate), because that's the assumption in generated code (which
  // might call this builtin).
  Isolate* isolate;
  if (!IsSmi(x) && GetIsolateFromHeapObject(Cast<HeapObject>(x), &isolate)) {
    DCHECK(isolate == this || isolate == shared_space_isolate());
  }
  if (!IsSmi(y) && GetIsolateFromHeapObject(Cast<HeapObject>(y), &isolate)) {
    DCHECK(isolate == this || isolate == shared_space_isolate());
  }
#endif
#endif  // V8_HOST_ARCH_64_BIT
  return pair;
}
#endif  // DEBUG

bool Isolate::is_catchable_by_javascript(Tagged<Object> exception) {
  return exception != ReadOnlyRoots(heap()).termination_exception();
}

bool Isolate::InFastCCall() const {
  return isolate_data()->fast_c_call_caller_fp() != kNullAddress;
}

bool Isolate::is_catchable_by_wasm(Tagged<Object> exception) {
  if (!is_catchable_by_javascript(exception)) return false;
  if (!IsJSObject(exception)) return true;
  return !LookupIterator::HasInternalMarkerProperty(
      this, Cast<JSReceiver>(exception), factory()->wasm_uncatchable_symbol());
}

void Isolate::FireBeforeCallEnteredCallback() {
  for (auto& callback : before_call_entered_callbacks_) {
    callback(reinterpret_cast<v8::Isolate*>(this));
  }
}

Handle<JSGlobalObject> Isolate::global_object() {
  return handle(context()->global_object(), this);
}

Handle<JSGlobalProxy> Isolate::global_proxy() {
  return handle(context()->global_proxy(), this);
}

Isolate::ExceptionScope::ExceptionScope(Isolate* isolate)
    : isolate_(isolate), exception_(isolate_->exception(), isolate_) {
  isolate_->clear_internal_exception();
}

Isolate::ExceptionScope::~ExceptionScope() {
  isolate_->set_exception(*exception_);
}

bool Isolate::IsInitialArrayPrototype(Tagged<JSArray> array) {
  DisallowGarbageCollection no_gc;
  return IsInCreationContext(array, Context::INITIAL_ARRAY_PROTOTYPE_INDEX);
}

#define NATIVE_CONTEXT_FIELD_ACCESSOR(index, type, name)              \
  Handle<UNPAREN(type)> Isolate::name() {                             \
    return Handle<UNPAREN(type)>(raw_native_context()->name(), this); \
  }                                                                   \
  bool Isolate::is_##name(Tagged<UNPAREN(type)> value) {              \
    return raw_native_context()->is_##name(value);                    \
  }
NATIVE_CONTEXT_FIELDS(NATIVE_CONTEXT_FIELD_ACCESSOR)
#undef NATIVE_CONTEXT_FIELD_ACCESSOR

}  // namespace internal
}  // namespace v8

#endif  // V8_EXECUTION_ISOLATE_INL_H_
```