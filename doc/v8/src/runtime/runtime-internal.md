Response: The user wants to understand the functionality of the C++ file `v8/src/runtime/runtime-internal.cc`. I need to analyze the code and summarize its purpose. Since the user also asked about its relation to JavaScript, I should identify parts of the code that directly implement or support JavaScript features and provide illustrative JavaScript examples.

**Plan:**

1. **Identify the core purpose of the file:** Look for common themes and keywords in the function names and the included headers. The `RUNTIME_FUNCTION` macro is a strong indicator of the file's role.
2. **Categorize the functionalities:** Group the runtime functions based on their apparent purpose (e.g., error handling, memory management, type checking, etc.).
3. **Explain the connection to JavaScript:**  For each category, explain how these internal runtime functions are related to JavaScript behavior.
4. **Provide JavaScript examples:** For relevant functionalities, create simple JavaScript code snippets that would likely trigger the corresponding runtime functions. Focus on illustrating the conceptual link.
这个C++文件 `v8/src/runtime/runtime-internal.cc` 定义了V8 JavaScript引擎的**内部运行时（Internal Runtime）函数**。 这些函数是V8引擎内部使用的，通常不直接暴露给JavaScript开发者，但它们是实现JavaScript语言特性的基础。

**功能归纳：**

这个文件主要负责以下几个方面的功能：

1. **错误处理和异常抛出:**
   - 提供了各种抛出不同类型错误的运行时函数，例如 `Runtime_ThrowTypeError`, `Runtime_ThrowRangeError`, `Runtime_ThrowReferenceError` 等。
   - 包括处理栈溢出的函数 `Runtime_ThrowStackOverflow`。
   - 提供了重新抛出异常的函数 `Runtime_ReThrow` 和 `Runtime_ReThrowWithMessage`。
   - 用于处理访问权限检查失败的函数 `Runtime_AccessCheck`。

2. **内存管理相关的操作:**
   - 提供了在年轻代和老年代分配内存的函数 `Runtime_AllocateInYoungGeneration` 和 `Runtime_AllocateInOldGeneration`。
   - 用于分配字节数组的函数 `Runtime_AllocateByteArray`。
   - 处理内存不足错误的函数 `Runtime_FatalProcessOutOfMemoryInAllocateRaw` 和 `Runtime_FatalProcessOutOfMemoryInvalidArrayLength`。

3. **类型检查和类型转换:**
   - 提供了判断对象类型的函数，例如内部使用的 `Runtime_Typeof`。
   - 提供了创建类似数组的列表的函数 `Runtime_CreateListFromArrayLike`。

4. **迭代器相关的操作:**
   - 提供了抛出迭代器相关错误的函数，例如 `Runtime_ThrowIteratorResultNotAnObject` 和 `Runtime_ThrowSymbolIteratorInvalid`。
   - 提供了将同步迭代器转换为异步迭代器的函数 `Runtime_CreateAsyncFromSyncIterator`。

5. **调用栈和中断处理:**
   - 提供了栈保护机制相关的函数 `Runtime_StackGuard`, `Runtime_HandleNoHeapWritesInterrupts`, `Runtime_StackGuardWithGap`。
   - 提供了处理字节码预算中断的函数，用于实现代码分层优化 `Runtime_BytecodeBudgetInterrupt*`。
   - 提供了展开调用栈并查找异常处理器的函数 `Runtime_UnwindAndFindExceptionHandler`。
   - 提供了传播异常的函数 `Runtime_PropagateException`。

6. **模板对象:**
   - 提供了获取模板对象的函数 `Runtime_GetTemplateObject`，这与模板字面量相关。

7. **调试和性能分析:**
   - 提供了获取和重置 TurboFan 性能分析数据的函数 `Runtime_GetAndResetTurboProfilingData`。
   - 提供了获取和重置运行时调用统计信息的函数 `Runtime_GetAndResetRuntimeCallStats`。

8. **其他内部操作:**
   - 提供了终止执行的函数 `Runtime_TerminateExecution`。
   - 提供了创建新的错误对象的函数 `Runtime_NewError`, `Runtime_NewTypeError`, `Runtime_NewReferenceError`。
   - 提供了增加使用计数器的函数 `Runtime_IncrementUseCounter`，用于统计语言特性的使用情况。
   - 提供了普通对象 `instanceof` 操作的实现 `Runtime_OrdinaryHasInstance`。
   - 提供了允许动态函数创建的检查 `Runtime_AllowDynamicFunction`。
   - 提供了报告来自微任务的消息的函数 `Runtime_ReportMessageFromMicrotask`。
   - 提供了获取类字段初始化函数的函数 `Runtime_GetInitializerFunction`。
   - 提供了将数字转换为指定进制字符串的函数 `Runtime_DoubleToStringWithRadix`。
   - 提供了共享值屏障的慢速路径函数 `Runtime_SharedValueBarrierSlow`。
   - 提供了使脚本上下文槽的依赖代码失效的函数 `Runtime_InvalidateDependentCodeForScriptContextSlot`。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这些内部运行时函数是 JavaScript 引擎实现各种语言特性的幕后功臣。当 JavaScript 代码执行时，引擎会根据需要调用这些底层的运行时函数。

以下是一些与 JavaScript 功能相关的示例：

1. **错误处理 (Error Handling):**

   ```javascript
   try {
     throw new TypeError("Something went wrong!");
   } catch (e) {
     console.error(e);
   }
   ```

   当执行 `throw new TypeError(...)` 时，V8 引擎内部会调用类似于 `Runtime_ThrowTypeError` 的函数来创建并抛出错误对象。

2. **类型错误 (TypeError):**

   ```javascript
   let obj = null;
   obj.property; // TypeError: Cannot read properties of null (reading 'property')

   function nonConstructor() {}
   new nonConstructor(); // TypeError: nonConstructor is not a constructor
   ```

   当尝试访问 `null` 或 `undefined` 的属性，或者尝试 `new` 一个非构造函数时，V8 会调用 `Runtime_ThrowTypeError` 并传入相应的错误消息模板。

3. **范围错误 (RangeError):**

   ```javascript
   const arr = new Array(-1); // RangeError: Invalid array length
   ```

   创建长度为负数的数组时，V8 会检测到这个非法长度，并调用 `Runtime_ThrowRangeError`。

4. **引用错误 (ReferenceError):**

   ```javascript
   console.log(unknownVariable); // ReferenceError: unknownVariable is not defined
   ```

   当尝试访问未声明的变量时，V8 会调用 `Runtime_ThrowReferenceError`。

5. **`instanceof` 操作符:**

   ```javascript
   class MyClass {}
   const obj = new MyClass();
   console.log(obj instanceof MyClass); // true
   ```

   `instanceof` 操作符的内部实现涉及到调用 `Runtime_OrdinaryHasInstance` 来进行原型链的检查。

6. **迭代器 (Iterators):**

   ```javascript
   const iterable = [1, 2, 3];
   const iterator = iterable[Symbol.iterator]();
   console.log(iterator.next()); // { value: 1, done: false }
   ```

   当使用 `Symbol.iterator` 获取迭代器时，如果对象没有提供迭代器方法，或者迭代器的 `next()` 方法返回的不是对象时，可能会触发 `Runtime_ThrowSymbolIteratorInvalid` 或 `Runtime_ThrowIteratorResultNotAnObject`。

7. **模板字面量 (Template Literals):**

   ```javascript
   const name = "World";
   const greeting = `Hello, ${name}!`;
   ```

   模板字面量的处理过程中，V8 引擎可能会调用 `Runtime_GetTemplateObject` 来获取或创建与模板相关的对象。

总而言之，`v8/src/runtime/runtime-internal.cc` 文件是 V8 引擎的核心组成部分，它定义了许多底层的操作，这些操作支撑着 JavaScript 语言的各种功能和特性。虽然开发者通常不会直接调用这些函数，但理解它们的存在和作用有助于更深入地理解 JavaScript 引擎的工作原理。

### 提示词
```
这是目录为v8/src/runtime/runtime-internal.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
```