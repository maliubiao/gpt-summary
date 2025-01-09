Response:
Let's break down the thought process for analyzing the `runtime-internal.cc` file.

1. **Understanding the Request:** The request asks for the functionality of the C++ code, specifically focusing on its relation to JavaScript, potential Torque origins, code logic, common errors, and examples.

2. **Initial Scan and Structure Recognition:**  The first step is to quickly scan the code to get a high-level understanding. I see:
    * Copyright and license information.
    * Includes of various V8 headers (`api-inl.h`, `builtins.h`, etc.). This immediately tells me it's part of the V8 engine's implementation.
    * A namespace `v8::internal`. This confirms it's internal V8 code.
    * A series of functions prefixed with `RUNTIME_FUNCTION`. This is a strong indicator of runtime functions callable from within the V8 JavaScript engine.

3. **Identifying Key Functionality Areas:**  As I read through the `RUNTIME_FUNCTION` definitions, patterns emerge:
    * **Error Handling:** Functions like `Runtime_Throw`, `Runtime_ReThrow`, `Runtime_ThrowTypeError`, `Runtime_ThrowReferenceError`, etc., clearly deal with throwing and managing errors.
    * **Memory Management (Indirectly):**  Functions like `Runtime_FatalProcessOutOfMemoryInAllocateRaw`, `Runtime_AllocateInYoungGeneration`, and `Runtime_AllocateInOldGeneration` suggest interaction with the V8 heap, although the immediate actions are often about reporting fatal errors or allocating raw memory.
    * **Stack Management:**  Functions such as `Runtime_ThrowStackOverflow`, `Runtime_StackGuard`, and `Runtime_StackGuardWithGap` are related to stack overflow detection and handling interrupts.
    * **Type Checking and Conversion:** `Runtime_Typeof`, `Runtime_DoubleToStringWithRadix` fall into this category.
    * **Iterator Support:** `Runtime_ThrowIteratorResultNotAnObject`, `Runtime_CreateAsyncFromSyncIterator` point to functionality supporting JavaScript iterators.
    * **Profiling and Debugging:** `Runtime_GetAndResetTurboProfilingData` and `Runtime_GetAndResetRuntimeCallStats` are related to collecting performance data.
    * **Internal Operations:**  Functions like `Runtime_AccessCheck`, `Runtime_TerminateExecution`, `Runtime_CreateListFromArrayLike` appear to be lower-level operations needed by the engine.

4. **Connecting to JavaScript:**  This is a crucial part. For each identified area, I think about how these internal functions relate to JavaScript concepts:
    * **Errors:** The `Runtime_Throw...` functions directly correspond to JavaScript `throw` statements and different error types (TypeError, ReferenceError, etc.).
    * **Memory:** While JavaScript has garbage collection, these functions are invoked internally when memory allocation fails or when specific allocation strategies are needed. Users don't directly call these but trigger them indirectly.
    * **Stack:** Stack overflow errors in JavaScript are related to `Runtime_ThrowStackOverflow`. `Runtime_StackGuard` is part of V8's mechanism to prevent infinite recursion or long-running computations from crashing the engine.
    * **Typeof:** `Runtime_Typeof` implements the JavaScript `typeof` operator.
    * **Iterators:** The iterator-related runtime functions are invoked when JavaScript code uses `for...of`, spread syntax on iterables, or asynchronous iterators.
    * **Profiling:**  While not directly exposed in standard JavaScript, these functions are used by V8's profiling tools.

5. **Considering Torque:** The prompt explicitly mentions `.tq` files. I scanned the code for any mentions of Torque-specific syntax or constructs. Since there were none, I concluded it's likely not a Torque file.

6. **Code Logic and Examples:** For a few representative functions, I tried to illustrate the logic with simple examples:
    * `Runtime_ThrowTypeError`: A basic JavaScript `throw new TypeError(...)`.
    * `Runtime_AccessCheck`: An example using proxies and a handler to demonstrate access control.
    * `Runtime_CreateListFromArrayLike`:  Showing how it's related to spreading iterable objects.
    * `Runtime_Typeof`: Simple examples of JavaScript's `typeof` operator.

7. **Common Programming Errors:** I considered the user-facing implications of these internal functions and linked them to common JavaScript mistakes:
    * Incorrect function calls leading to `TypeError`.
    * Accessing undeclared variables leading to `ReferenceError`.
    * Exceeding recursion depth causing stack overflow.
    * Using `new` on non-constructor functions.
    * Issues with iterators (e.g., returning non-objects from `next`).

8. **Hypothetical Inputs and Outputs:** For a few functions, I provided simple input scenarios and the expected outcome:
    * `Runtime_Throw`:  Throwing a string.
    * `Runtime_AccessCheck`: Accessing an object with a failing access check.
    * `Runtime_CreateListFromArrayLike`: Spreading an array.
    * `Runtime_Typeof`: Checking the type of a number.

9. **Structuring the Output:**  Finally, I organized the information into clear sections based on the prompt's requirements: functionality, Torque, JavaScript relationship, code logic, and common errors. Using bullet points and code blocks enhances readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is every `RUNTIME_FUNCTION` directly callable by JavaScript?"  **Correction:** No, these are internal functions called *by* the JavaScript engine in response to JavaScript code execution. The connection is often indirect.
* **Considering Edge Cases:**  For example, with `Runtime_AccessCheck`, I initially only thought about basic object access. Then, I considered the proxy example, which is a more explicit use case for access control.
* **Balancing Detail:** I aimed for a balance between providing enough technical detail to be accurate and keeping the explanations understandable to someone who might not be a V8 internals expert. Avoiding overly specific V8 data structure details where possible.

By following these steps, I could systematically analyze the C++ code and generate a comprehensive answer addressing all aspects of the request.
好的，让我们来分析一下 `v8/src/runtime/runtime-internal.cc` 这个 V8 源代码文件的功能。

**功能概览**

`v8/src/runtime/runtime-internal.cc` 文件定义了 V8 JavaScript 引擎的**内部运行时函数 (Internal Runtime Functions)**。 这些函数是 V8 引擎实现 JavaScript 语言特性的核心组成部分，它们通常由 V8 的内置代码 (Builtins) 或者由编译器生成的代码直接调用。

简单来说，这些函数执行着各种底层操作，例如：

* **错误处理和异常抛出:**  定义了各种抛出不同类型错误的函数，例如 `Runtime_ThrowTypeError`, `Runtime_ThrowReferenceError`, `Runtime_ThrowStackOverflow` 等。
* **内存管理 (间接):**  虽然不直接进行内存分配，但包含一些与内存相关的错误处理函数，如 `Runtime_FatalProcessOutOfMemoryInAllocateRaw`。 还包含直接分配内存的函数，例如 `Runtime_AllocateInYoungGeneration` 和 `Runtime_AllocateInOldGeneration`。
* **类型检查和转换:**  例如 `Runtime_Typeof` 实现了 JavaScript 的 `typeof` 操作符。 `Runtime_DoubleToStringWithRadix` 用于将数字转换为指定进制的字符串。
* **对象和属性访问控制:** `Runtime_AccessCheck` 用于执行对象访问权限的检查。
* **迭代器支持:**  例如 `Runtime_ThrowIteratorResultNotAnObject` 用于在迭代器返回非对象时抛出错误。 `Runtime_CreateAsyncFromSyncIterator` 用于创建异步迭代器。
* **性能监控和调试:** 包含一些用于性能分析的函数，例如 `Runtime_GetAndResetTurboProfilingData` 和 `Runtime_GetAndResetRuntimeCallStats`。
* **栈管理:**  例如 `Runtime_StackGuard` 用于处理栈溢出和中断。
* **内部工具函数:**  例如 `Runtime_CreateListFromArrayLike` 用于根据类数组对象创建列表。

**关于 Torque (.tq) 文件**

如果 `v8/src/runtime/runtime-internal.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。 Torque 是 V8 开发的一种领域特定语言 (DSL)，用于更安全、更高效地编写 V8 的内置函数和运行时函数。

**检查当前文件:**  从您提供的代码片段来看，该文件以 `.cc` 结尾，因此它是一个 C++ 源文件，而不是 Torque 文件。  V8 中许多早期的运行时函数是用 C++ 编写的，而新的或重构的函数更多地倾向于使用 Torque。

**与 JavaScript 功能的关系及示例**

这个文件中的函数与 JavaScript 的功能有着非常紧密的联系。 许多 JavaScript 的核心特性和语法糖都依赖于这些底层的运行时函数来实现。

以下是一些 JavaScript 功能与 `runtime-internal.cc` 中函数的对应示例：

1. **错误处理:**

   ```javascript
   try {
     throw new TypeError("Something went wrong!");
   } catch (e) {
     console.error(e);
   }
   ```

   当 JavaScript 引擎执行 `throw new TypeError(...)` 时，内部会调用 `Runtime_ThrowTypeError` 这个运行时函数来创建并抛出 `TypeError` 对象。

2. **`typeof` 运算符:**

   ```javascript
   console.log(typeof 10);      // 输出 "number"
   console.log(typeof "hello"); // 输出 "string"
   ```

   JavaScript 的 `typeof` 运算符在底层会调用 `Runtime_Typeof` 函数来确定给定值的类型并返回相应的字符串。

3. **栈溢出:**

   ```javascript
   function recursiveFunction() {
     recursiveFunction();
   }
   try {
     recursiveFunction(); // 这将导致栈溢出
   } catch (e) {
     console.error(e); // 可能捕获 RangeError: Maximum call stack size exceeded
   }
   ```

   当 JavaScript 代码执行导致栈溢出时，V8 的栈保护机制会检测到，并调用 `Runtime_ThrowStackOverflow` 函数来抛出一个栈溢出错误。

4. **`Array.from()` 或展开语法 (Spread Syntax) 用于类数组对象:**

   ```javascript
   function foo() {
     console.log(Array.from(arguments)); // 将 arguments 对象转换为数组
     console.log([...arguments]);       // 使用展开语法将 arguments 对象转换为数组
   }
   foo(1, 2, 3);
   ```

   在底层，`Array.from()` 和展开语法在处理类数组对象 (如 `arguments`) 时，可能会调用 `Runtime_CreateListFromArrayLike` 来创建一个新的数组。

5. **访问对象属性的权限检查 (通过 Proxy):**

   ```javascript
   const target = {};
   const handler = {
     get(obj, prop) {
       if (prop === 'secret') {
         throw new Error("Cannot access secret property!");
       }
       return obj[prop];
     }
   };
   const proxy = new Proxy(target, handler);

   try {
     console.log(proxy.secret); // 这将触发 Proxy 的 get trap
   } catch (e) {
     console.error(e);
   }
   ```

   虽然这个例子主要展示了 Proxy 的 `get` trap，但在更底层的场景中，如果存在更细粒度的访问控制，`Runtime_AccessCheck` 可能会参与到属性访问的权限检查中。

**代码逻辑推理及假设输入输出**

让我们看一个简单的例子： `Runtime_ThrowTypeError`

**假设输入:**  一个表示错误消息的 `Smi` (小整数) 或字符串。

**代码逻辑:**

```c++
RUNTIME_FUNCTION(Runtime_ThrowTypeError) {
  return ThrowError(isolate, args, &Isolate::type_error_function);
}
```

内部 `ThrowError` 函数会根据传入的参数创建一个 `TypeError` 对象，并使用 `isolate->Throw()` 抛出该异常。

**假设输入:**  假设 JavaScript 代码执行 `throw new TypeError('Invalid argument');`。  在 V8 内部，可能会将消息 'Invalid argument' 转换为一个内部的 `MessageTemplate` 的 ID。 假设这个 ID 是 `123`。

**预期输出:**  V8 引擎会抛出一个 `TypeError` 异常，其消息为 "Invalid argument"。  在 JavaScript 环境中，这个异常可以被 `try...catch` 捕获。

**用户常见的编程错误**

`runtime-internal.cc` 中定义的功能直接关系到用户在编写 JavaScript 代码时容易犯的错误：

1. **调用非函数类型的变量:**

   ```javascript
   let notAFunction = 10;
   notAFunction(); // TypeError: notAFunction is not a function
   ```

   当尝试调用一个非函数的值时，V8 会检查其类型，如果不是函数，则会调用类似 `Runtime_ThrowTypeError` 的函数抛出一个 `TypeError`。

2. **访问未声明的变量:**

   ```javascript
   console.log(undeclaredVariable); // ReferenceError: undeclaredVariable is not defined
   ```

   当访问一个未声明的变量时，V8 会抛出一个 `ReferenceError`，这涉及到 `Runtime_ThrowReferenceError` 的调用。

3. **栈溢出 (无限递归):**

   ```javascript
   function foo() {
     foo();
   }
   foo(); // RangeError: Maximum call stack size exceeded
   ```

   无限递归会导致调用栈超出限制，V8 会通过 `Runtime_ThrowStackOverflow` 抛出错误。

4. **对 `null` 或 `undefined` 进行属性访问或调用方法:**

   ```javascript
   let obj = null;
   console.log(obj.toString()); // TypeError: Cannot read properties of null (reading 'toString')

   let undef;
   console.log(undef.length);  // TypeError: Cannot read properties of undefined (reading 'length')
   ```

   这些操作会触发 `TypeError`，`runtime-internal.cc` 中可能存在处理这类错误的函数。

5. **尝试 `new` 一个非构造函数:**

   ```javascript
   function notAConstructor() {
     return 10;
   }
   let instance = new notAConstructor(); // TypeError: notAConstructor is not a constructor
   ```

   V8 会检查被 `new` 调用的对象是否是构造函数，如果不是，则会通过类似 `Runtime_ThrowTypeError` 的函数抛出错误。

**总结**

`v8/src/runtime/runtime-internal.cc` 是 V8 引擎中一个至关重要的文件，它定义了大量的内部运行时函数，这些函数是实现 JavaScript 语言特性的基础。  虽然开发者通常不会直接调用这些函数，但他们的 JavaScript 代码的执行会间接地依赖于这些底层的操作。理解这个文件中的功能有助于更深入地理解 V8 引擎的工作原理以及 JavaScript 的底层实现。

Prompt: 
```
这是目录为v8/src/runtime/runtime-internal.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-internal.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "src/api/api-inl.h"
#include "src/api/api.h"
#include "src/builtins/builtins.h"
#include "src/common/message-template.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/messages.h"
#include "src/execution/tiering-manager.h"
#include "src/handles/maybe-handles.h"
#include "src/logging/counters.h"
#include "src/numbers/conversions.h"
#include "src/objects/template-objects-inl.h"
#include "src/runtime/runtime-utils.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

RUNTIME_FUNCTION(Runtime_AccessCheck) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSObject> object = args.at<JSObject>(0);
  if (!isolate->MayAccess(isolate->native_context(), object)) {
    RETURN_FAILURE_ON_EXCEPTION(isolate,
                                isolate->ReportFailedAccessCheck(object));
    UNREACHABLE();
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_FatalProcessOutOfMemoryInAllocateRaw) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  isolate->heap()->FatalProcessOutOfMemory("CodeStubAssembler::AllocateRaw");
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_FatalProcessOutOfMemoryInvalidArrayLength) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  isolate->heap()->FatalProcessOutOfMemory("invalid array length");
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_FatalInvalidSize) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  FATAL("Invalid size");
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_Throw) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  return isolate->Throw(args[0]);
}

RUNTIME_FUNCTION(Runtime_ReThrow) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  return isolate->ReThrow(args[0]);
}

RUNTIME_FUNCTION(Runtime_ReThrowWithMessage) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  return isolate->ReThrow(args[0], args[1]);
}

RUNTIME_FUNCTION(Runtime_ThrowStackOverflow) {
  SealHandleScope shs(isolate);
  DCHECK_LE(0, args.length());
  return isolate->StackOverflow();
}

RUNTIME_FUNCTION(Runtime_ThrowSymbolAsyncIteratorInvalid) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kSymbolAsyncIteratorInvalid));
}

RUNTIME_FUNCTION(Runtime_TerminateExecution) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  return isolate->TerminateExecution();
}

namespace {

Tagged<Object> NewError(Isolate* isolate, RuntimeArguments args,
                        Handle<JSFunction> (Isolate::*constructor_fn)()) {
  HandleScope scope(isolate);
  DCHECK_LE(1, args.length());
  int message_id_smi = args.smi_value_at(0);

  constexpr int kMaxMessageArgs = 3;
  DirectHandle<Object> message_args[kMaxMessageArgs];
  int num_message_args = 0;
  while (num_message_args < kMaxMessageArgs &&
         args.length() > num_message_args + 1) {
    message_args[num_message_args] = args.at(num_message_args + 1);
    ++num_message_args;
  }

  MessageTemplate message_id = MessageTemplateFromInt(message_id_smi);

  return *isolate->factory()->NewError(
      (isolate->*constructor_fn)(), message_id,
      base::VectorOf(message_args, num_message_args));
}

Tagged<Object> ThrowError(Isolate* isolate, RuntimeArguments args,
                          Handle<JSFunction> (Isolate::*constructor_fn)()) {
  return isolate->Throw(NewError(isolate, args, constructor_fn));
}

}  // namespace

RUNTIME_FUNCTION(Runtime_ThrowRangeError) {
  if (v8_flags.correctness_fuzzer_suppressions) {
    DCHECK_LE(1, args.length());
    int message_id_smi = args.smi_value_at(0);

    // If the result of a BigInt computation is truncated to 64 bit, Turbofan
    // can sometimes truncate intermediate results already, which can prevent
    // those from exceeding the maximum length, effectively preventing a
    // RangeError from being thrown. As this is a performance optimization, this
    // behavior is accepted. To prevent the correctness fuzzer from detecting
    // this difference, we crash the program.
    if (MessageTemplateFromInt(message_id_smi) ==
        MessageTemplate::kBigIntTooBig) {
      FATAL("Aborting on invalid BigInt length");
    }
  }

  return ThrowError(isolate, args, &Isolate::range_error_function);
}

RUNTIME_FUNCTION(Runtime_ThrowTypeError) {
  return ThrowError(isolate, args, &Isolate::type_error_function);
}

RUNTIME_FUNCTION(Runtime_ThrowTypeErrorIfStrict) {
  if (GetShouldThrow(isolate, Nothing<ShouldThrow>()) ==
      ShouldThrow::kDontThrow) {
    return ReadOnlyRoots(isolate).undefined_value();
  }
  return ThrowError(isolate, args, &Isolate::type_error_function);
}

namespace {

const char* ElementsKindToType(ElementsKind fixed_elements_kind) {
  switch (fixed_elements_kind) {
#define ELEMENTS_KIND_CASE(Type, type, TYPE, ctype) \
  case TYPE##_ELEMENTS:                             \
    return #Type "Array";

    TYPED_ARRAYS(ELEMENTS_KIND_CASE)
    RAB_GSAB_TYPED_ARRAYS_WITH_TYPED_ARRAY_TYPE(ELEMENTS_KIND_CASE)
#undef ELEMENTS_KIND_CASE

    default:
      UNREACHABLE();
  }
}

}  // namespace

RUNTIME_FUNCTION(Runtime_ThrowInvalidTypedArrayAlignment) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  DirectHandle<Map> map = args.at<Map>(0);
  Handle<String> problem_string = args.at<String>(1);

  ElementsKind kind = map->elements_kind();

  Handle<String> type =
      isolate->factory()->NewStringFromAsciiChecked(ElementsKindToType(kind));

  ExternalArrayType external_type;
  size_t size;
  Factory::TypeAndSizeForElementsKind(kind, &external_type, &size);
  Handle<Object> element_size =
      handle(Smi::FromInt(static_cast<int>(size)), isolate);

  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewRangeError(MessageTemplate::kInvalidTypedArrayAlignment,
                             problem_string, type, element_size));
}

RUNTIME_FUNCTION(Runtime_UnwindAndFindExceptionHandler) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(0, args.length());
  return isolate->UnwindAndFindHandler();
}

RUNTIME_FUNCTION(Runtime_PropagateException) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(0, args.length());
  DCHECK(isolate->has_exception());
  return ReadOnlyRoots(isolate).exception();
}

RUNTIME_FUNCTION(Runtime_ThrowReferenceError) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> name = args.at(0);
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewReferenceError(MessageTemplate::kNotDefined, name));
}

RUNTIME_FUNCTION(Runtime_ThrowAccessedUninitializedVariable) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> name = args.at(0);
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate,
      NewReferenceError(MessageTemplate::kAccessedUninitializedVariable, name));
}

RUNTIME_FUNCTION(Runtime_NewError) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  int template_index = args.smi_value_at(0);
  Handle<Object> arg0 = args.at(1);
  MessageTemplate message_template = MessageTemplateFromInt(template_index);
  return *isolate->factory()->NewError(message_template, arg0);
}

RUNTIME_FUNCTION(Runtime_NewTypeError) {
  return NewError(isolate, args, &Isolate::type_error_function);
}

RUNTIME_FUNCTION(Runtime_NewReferenceError) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  int template_index = args.smi_value_at(0);
  Handle<Object> arg0 = args.at(1);
  MessageTemplate message_template = MessageTemplateFromInt(template_index);
  return *isolate->factory()->NewReferenceError(message_template, arg0);
}

RUNTIME_FUNCTION(Runtime_ThrowInvalidStringLength) {
  HandleScope scope(isolate);
  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewInvalidStringLengthError());
}

RUNTIME_FUNCTION(Runtime_ThrowIteratorResultNotAnObject) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> value = args.at(0);
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate,
      NewTypeError(MessageTemplate::kIteratorResultNotAnObject, value));
}

RUNTIME_FUNCTION(Runtime_ThrowThrowMethodMissing) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kThrowMethodMissing));
}

RUNTIME_FUNCTION(Runtime_ThrowSymbolIteratorInvalid) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kSymbolIteratorInvalid));
}

RUNTIME_FUNCTION(Runtime_ThrowNoAccess) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());

  // TODO(verwaest): We would like to throw using the calling context instead
  // of the entered context but we don't currently have access to that.
  HandleScopeImplementer* impl = isolate->handle_scope_implementer();
  SaveAndSwitchContext save(isolate,
                            impl->LastEnteredContext()->native_context());
  THROW_NEW_ERROR_RETURN_FAILURE(isolate,
                                 NewTypeError(MessageTemplate::kNoAccess));
}

RUNTIME_FUNCTION(Runtime_ThrowNotConstructor) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> object = args.at(0);
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kNotConstructor, object));
}

RUNTIME_FUNCTION(Runtime_ThrowApplyNonFunction) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> object = args.at(0);
  Handle<String> type = Object::TypeOf(isolate, object);
  Handle<String> msg;
  if (IsNull(*object)) {
    // "which is null"
    msg = isolate->factory()->NewStringFromAsciiChecked("null");
  } else if (isolate->factory()->object_string()->Equals(*type)) {
    // "which is an object"
    msg = isolate->factory()->NewStringFromAsciiChecked("an object");
  } else {
    // "which is a typeof arg"
    msg = isolate->factory()
              ->NewConsString(
                  isolate->factory()->NewStringFromAsciiChecked("a "), type)
              .ToHandleChecked();
  }
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kApplyNonFunction, object, msg));
}

RUNTIME_FUNCTION(Runtime_StackGuard) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(0, args.length());
  TRACE_EVENT0("v8.execute", "V8.StackGuard");

  // First check if this is a real stack overflow.
  StackLimitCheck check(isolate);
  if (check.JsHasOverflowed()) {
    return isolate->StackOverflow();
  }

  return isolate->stack_guard()->HandleInterrupts(
      StackGuard::InterruptLevel::kAnyEffect);
}

RUNTIME_FUNCTION(Runtime_HandleNoHeapWritesInterrupts) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(0, args.length());
  TRACE_EVENT0("v8.execute", "V8.StackGuard");

  // First check if this is a real stack overflow.
  StackLimitCheck check(isolate);
  if (check.JsHasOverflowed()) {
    return isolate->StackOverflow();
  }

  return isolate->stack_guard()->HandleInterrupts(
      StackGuard::InterruptLevel::kNoHeapWrites);
}

RUNTIME_FUNCTION(Runtime_StackGuardWithGap) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(args.length(), 1);
  uint32_t gap = args.positive_smi_value_at(0);
  TRACE_EVENT0("v8.execute", "V8.StackGuard");

  // First check if this is a real stack overflow.
  StackLimitCheck check(isolate);
  if (check.JsHasOverflowed(gap)) {
    return isolate->StackOverflow();
  }

  return isolate->stack_guard()->HandleInterrupts(
      StackGuard::InterruptLevel::kAnyEffect);
}

namespace {

Tagged<Object> BytecodeBudgetInterruptWithStackCheck(Isolate* isolate,
                                                     RuntimeArguments& args,
                                                     CodeKind code_kind) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  TRACE_EVENT0("v8.execute", "V8.BytecodeBudgetInterruptWithStackCheck");

  // Check for stack interrupts here so that we can fold the interrupt check
  // into bytecode budget interrupts.
  StackLimitCheck check(isolate);
  if (check.JsHasOverflowed()) {
    // We ideally wouldn't actually get StackOverflows here, since we stack
    // check on bytecode entry, but it's possible that this check fires due to
    // the runtime function call being what overflows the stack.
    return isolate->StackOverflow();
  } else if (check.InterruptRequested()) {
    Tagged<Object> return_value = isolate->stack_guard()->HandleInterrupts();
    if (!IsUndefined(return_value, isolate)) {
      return return_value;
    }
  }

  isolate->tiering_manager()->OnInterruptTick(function, code_kind);
  return ReadOnlyRoots(isolate).undefined_value();
}

Tagged<Object> BytecodeBudgetInterrupt(Isolate* isolate, RuntimeArguments& args,
                                       CodeKind code_kind) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  TRACE_EVENT0("v8.execute", "V8.BytecodeBudgetInterrupt");

  isolate->tiering_manager()->OnInterruptTick(function, code_kind);
  return ReadOnlyRoots(isolate).undefined_value();
}

}  // namespace

RUNTIME_FUNCTION(Runtime_BytecodeBudgetInterruptWithStackCheck_Ignition) {
  return BytecodeBudgetInterruptWithStackCheck(isolate, args,
                                               CodeKind::INTERPRETED_FUNCTION);
}

RUNTIME_FUNCTION(Runtime_BytecodeBudgetInterrupt_Ignition) {
  return BytecodeBudgetInterrupt(isolate, args, CodeKind::INTERPRETED_FUNCTION);
}

RUNTIME_FUNCTION(Runtime_BytecodeBudgetInterruptWithStackCheck_Sparkplug) {
  return BytecodeBudgetInterruptWithStackCheck(isolate, args,
                                               CodeKind::BASELINE);
}

RUNTIME_FUNCTION(Runtime_BytecodeBudgetInterrupt_Sparkplug) {
  return BytecodeBudgetInterrupt(isolate, args, CodeKind::BASELINE);
}

RUNTIME_FUNCTION(Runtime_BytecodeBudgetInterrupt_Maglev) {
  return BytecodeBudgetInterrupt(isolate, args, CodeKind::MAGLEV);
}

RUNTIME_FUNCTION(Runtime_BytecodeBudgetInterruptWithStackCheck_Maglev) {
  return BytecodeBudgetInterruptWithStackCheck(isolate, args, CodeKind::MAGLEV);
}

RUNTIME_FUNCTION(Runtime_AllocateInYoungGeneration) {
  HandleScope scope(isolate);
  DCHECK(isolate->IsOnCentralStack());
  DCHECK_EQ(2, args.length());
  // TODO(v8:13070): Align allocations in the builtins that call this.
  int size = ALIGN_TO_ALLOCATION_ALIGNMENT(args.smi_value_at(0));
  int flags = args.smi_value_at(1);
  AllocationAlignment alignment =
      AllocateDoubleAlignFlag::decode(flags) ? kDoubleAligned : kTaggedAligned;
  CHECK(IsAligned(size, kTaggedSize));
  CHECK_GT(size, 0);

  // When this is called from WasmGC code, clear the "thread in wasm" flag,
  // which is important in case any GC needs to happen.
  // TODO(chromium:1236668): Find a better fix, likely by replacing the global
  // flag.
  SaveAndClearThreadInWasmFlag clear_wasm_flag(isolate);

  // TODO(v8:9472): Until double-aligned allocation is fixed for new-space
  // allocations, don't request it.
  alignment = kTaggedAligned;

  return *isolate->factory()->NewFillerObject(size, alignment,
                                              AllocationType::kYoung,
                                              AllocationOrigin::kGeneratedCode);
}

RUNTIME_FUNCTION(Runtime_AllocateInOldGeneration) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  // TODO(v8:13070): Align allocations in the builtins that call this.
  int size = ALIGN_TO_ALLOCATION_ALIGNMENT(args.smi_value_at(0));
  int flags = args.smi_value_at(1);
  AllocationAlignment alignment =
      AllocateDoubleAlignFlag::decode(flags) ? kDoubleAligned : kTaggedAligned;
  CHECK(IsAligned(size, kTaggedSize));
  CHECK_GT(size, 0);
  return *isolate->factory()->NewFillerObject(
      size, alignment, AllocationType::kOld, AllocationOrigin::kGeneratedCode);
}

RUNTIME_FUNCTION(Runtime_AllocateByteArray) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  int length = args.smi_value_at(0);
  DCHECK_LT(0, length);
  return *isolate->factory()->NewByteArray(length);
}

RUNTIME_FUNCTION(Runtime_ThrowIteratorError) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> object = args.at(0);
  return isolate->Throw(*ErrorUtils::NewIteratorError(isolate, object));
}

RUNTIME_FUNCTION(Runtime_ThrowSpreadArgError) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  int message_id_smi = args.smi_value_at(0);
  MessageTemplate message_id = MessageTemplateFromInt(message_id_smi);
  Handle<Object> object = args.at(1);
  return ErrorUtils::ThrowSpreadArgError(isolate, message_id, object);
}

RUNTIME_FUNCTION(Runtime_ThrowCalledNonCallable) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> object = args.at(0);
  return isolate->Throw(
      *ErrorUtils::NewCalledNonCallableError(isolate, object));
}

RUNTIME_FUNCTION(Runtime_ThrowConstructedNonConstructable) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> object = args.at(0);
  return isolate->Throw(
      *ErrorUtils::NewConstructedNonConstructable(isolate, object));
}

RUNTIME_FUNCTION(Runtime_ThrowPatternAssignmentNonCoercible) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> object = args.at(0);
  return ErrorUtils::ThrowLoadFromNullOrUndefined(isolate, object,
                                                  MaybeHandle<Object>());
}

RUNTIME_FUNCTION(Runtime_ThrowConstructorReturnedNonObject) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());

  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate,
      NewTypeError(MessageTemplate::kDerivedConstructorReturnedNonObject));
}

// ES6 section 7.3.17 CreateListFromArrayLike (obj)
RUNTIME_FUNCTION(Runtime_CreateListFromArrayLike) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> object = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::CreateListFromArrayLike(
                                        isolate, object, ElementTypes::kAll));
}

RUNTIME_FUNCTION(Runtime_IncrementUseCounter) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  int counter = args.smi_value_at(0);
  isolate->CountUsage(static_cast<v8::Isolate::UseCounterFeature>(counter));
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_GetAndResetTurboProfilingData) {
  HandleScope scope(isolate);
  DCHECK_LE(args.length(), 2);
  if (!BasicBlockProfiler::Get()->HasData(isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(
            MessageTemplate::kInvalid,
            isolate->factory()->NewStringFromAsciiChecked("Runtime Call"),
            isolate->factory()->NewStringFromAsciiChecked(
                "V8 was not built with v8_enable_builtins_profiling=true")));
  }

  std::stringstream stats_stream;
  BasicBlockProfiler::Get()->Log(isolate, stats_stream);
  DirectHandle<String> result =
      isolate->factory()->NewStringFromAsciiChecked(stats_stream.str().c_str());
  BasicBlockProfiler::Get()->ResetCounts(isolate);
  return *result;
}

RUNTIME_FUNCTION(Runtime_GetAndResetRuntimeCallStats) {
  HandleScope scope(isolate);
  DCHECK_LE(args.length(), 2);
#ifdef V8_RUNTIME_CALL_STATS
  if (!v8_flags.runtime_call_stats) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kInvalid,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  "Runtime Call"),
                              isolate->factory()->NewStringFromAsciiChecked(
                                  "--runtime-call-stats is not set")));
  }
  // Append any worker thread runtime call stats to the main table before
  // printing.
  isolate->counters()->worker_thread_runtime_call_stats()->AddToMainTable(
      isolate->counters()->runtime_call_stats());

  if (args.length() == 0) {
    // Without arguments, the result is returned as a string.
    std::stringstream stats_stream;
    isolate->counters()->runtime_call_stats()->Print(stats_stream);
    DirectHandle<String> result = isolate->factory()->NewStringFromAsciiChecked(
        stats_stream.str().c_str());
    isolate->counters()->runtime_call_stats()->Reset();
    return *result;
  }

  std::FILE* f;
  if (IsString(args[0])) {
    // With a string argument, the results are appended to that file.
    DirectHandle<String> filename = args.at<String>(0);
    f = std::fopen(filename->ToCString().get(), "a");
    DCHECK_NOT_NULL(f);
  } else {
    // With an integer argument, the results are written to stdout/stderr.
    int fd = args.smi_value_at(0);
    DCHECK(fd == 1 || fd == 2);
    f = fd == 1 ? stdout : stderr;
  }
  // The second argument (if any) is a message header to be printed.
  if (args.length() >= 2) {
    DirectHandle<String> message = args.at<String>(1);
    message->PrintOn(f);
    std::fputc('\n', f);
    std::fflush(f);
  }
  OFStream stats_stream(f);
  isolate->counters()->runtime_call_stats()->Print(stats_stream);
  isolate->counters()->runtime_call_stats()->Reset();
  if (IsString(args[0])) {
    std::fclose(f);
  } else {
    std::fflush(f);
  }
  return ReadOnlyRoots(isolate).undefined_value();
#else   // V8_RUNTIME_CALL_STATS
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kInvalid,
                            isolate->factory()->NewStringFromAsciiChecked(
                                "Runtime Call"),
                            isolate->factory()->NewStringFromAsciiChecked(
                                "RCS was disabled at compile-time")));
#endif  // V8_RUNTIME_CALL_STATS
}

RUNTIME_FUNCTION(Runtime_OrdinaryHasInstance) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSAny> callable = args.at<JSAny>(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  RETURN_RESULT_OR_FAILURE(
      isolate, Object::OrdinaryHasInstance(isolate, callable, object));
}

RUNTIME_FUNCTION(Runtime_Typeof) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<Object> object = args.at(0);
  return *Object::TypeOf(isolate, object);
}

RUNTIME_FUNCTION(Runtime_AllowDynamicFunction) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> target = args.at<JSFunction>(0);
  Handle<JSObject> global_proxy(target->global_proxy(), isolate);
  return *isolate->factory()->ToBoolean(
      Builtins::AllowDynamicFunction(isolate, target, global_proxy));
}

RUNTIME_FUNCTION(Runtime_CreateAsyncFromSyncIterator) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  Handle<JSAny> sync_iterator_any = args.at<JSAny>(0);
  Handle<JSReceiver> sync_iterator;
  if (!TryCast<JSReceiver>(sync_iterator_any, &sync_iterator)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kSymbolIteratorInvalid));
  }

  Handle<Object> next;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, next,
      Object::GetProperty(isolate, sync_iterator,
                          isolate->factory()->next_string()));

  return *isolate->factory()->NewJSAsyncFromSyncIterator(sync_iterator, next);
}

RUNTIME_FUNCTION(Runtime_GetTemplateObject) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  DirectHandle<TemplateObjectDescription> description =
      args.at<TemplateObjectDescription>(0);
  DirectHandle<SharedFunctionInfo> shared_info = args.at<SharedFunctionInfo>(1);
  int slot_id = args.smi_value_at(2);

  DirectHandle<NativeContext> native_context(
      isolate->context()->native_context(), isolate);
  return *TemplateObjectDescription::GetTemplateObject(
      isolate, native_context, description, shared_info, slot_id);
}

RUNTIME_FUNCTION(Runtime_ReportMessageFromMicrotask) {
  // Helper to report messages and continue JS execution. This is intended to
  // behave similarly to reporting exceptions which reach the top-level, but
  // allow the JS code to continue.
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  Handle<Object> exception = args.at(0);

  DCHECK(!isolate->has_exception());
  isolate->set_exception(*exception);
  MessageLocation* no_location = nullptr;
  DirectHandle<JSMessageObject> message =
      isolate->CreateMessageOrAbort(exception, no_location);
  MessageHandler::ReportMessage(isolate, no_location, message);
  isolate->clear_exception();
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_GetInitializerFunction) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  Handle<JSReceiver> constructor = args.at<JSReceiver>(0);
  Handle<Symbol> key = isolate->factory()->class_fields_symbol();
  DirectHandle<Object> initializer =
      JSReceiver::GetDataProperty(isolate, constructor, key);
  return *initializer;
}

RUNTIME_FUNCTION(Runtime_DoubleToStringWithRadix) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  double number = args.number_value_at(0);
  int32_t radix = 0;
  CHECK(Object::ToInt32(args[1], &radix));

  char* const str = DoubleToRadixCString(number, radix);
  DirectHandle<String> result =
      isolate->factory()->NewStringFromAsciiChecked(str);
  DeleteArray(str);
  return *result;
}

RUNTIME_FUNCTION(Runtime_SharedValueBarrierSlow) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<HeapObject> value = args.at<HeapObject>(0);
  Handle<Object> shared_value;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, shared_value, Object::ShareSlow(isolate, value, kThrowOnError));
  return *shared_value;
}

RUNTIME_FUNCTION(Runtime_InvalidateDependentCodeForScriptContextSlot) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  auto const_tracking_let_cell =
      Cast<ContextSidePropertyCell>(args.at<HeapObject>(0));
  DependentCode::DeoptimizeDependencyGroups(
      isolate, *const_tracking_let_cell,
      DependentCode::kScriptContextSlotPropertyChangedGroup);
  return ReadOnlyRoots(isolate).undefined_value();
}

}  // namespace internal
}  // namespace v8

"""

```