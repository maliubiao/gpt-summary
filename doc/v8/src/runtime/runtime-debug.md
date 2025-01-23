Response: The user wants to understand the functionality of the C++ source code file `v8/src/runtime/runtime-debug.cc`. I need to analyze the code and identify its main purpose. The file name and the included headers strongly suggest that it's related to debugging functionalities within the V8 JavaScript engine.

Specifically, I need to:

1. **Summarize the overall function of the file.**  This will likely involve interacting with the V8 debugger and providing runtime support for debugging features.
2. **Identify any connections to JavaScript functionality.** Many of the functions seem to be runtime implementations called from JavaScript or influencing JavaScript execution.
3. **Provide concrete JavaScript examples** to illustrate the identified connections.

Let's break down the code section by section to understand the functionalities:

- **Includes:**  Headers like `debug/debug.h`, `debug/debug-scopes.h`, `debug/liveedit.h` clearly point to debugging features. Headers related to `interpreter`, `objects`, and `runtime` indicate interactions with the core JavaScript execution.
- **`Runtime_DebugBreakOnBytecode`:** This function is triggered when a debug break occurs at a specific bytecode instruction. It allows inspecting and modifying the return value and performs side-effect checks.
- **`Runtime_DebugBreakAtEntry`:** This function is invoked when a function with a "break at entry" breakpoint is called.
- **`Runtime_HandleDebuggerStatement`:**  This seems to handle the `debugger;` statement in JavaScript code.
- **`Runtime_ScheduleBreak`:**  This allows scheduling a breakpoint asynchronously.
- **`Runtime::GetInternalProperties`:** This function retrieves internal properties of JavaScript objects, often used by debuggers for inspection.
- **`Runtime_GetGeneratorScopeCount` and `Runtime_GetGeneratorScopeDetails`:** These functions are designed for inspecting the scope of suspended generator functions.
- **`Runtime_SetGeneratorScopeVariableValue`:** Allows modifying variables within the scope of a suspended generator.
- **`Runtime_GetBreakLocations`:**  Retrieves the locations of potential breakpoints within a function.
- **`Runtime_IsBreakOnException`:**  Checks the status of break-on-exception settings.
- **`Runtime_ClearStepping`:**  Clears any active stepping configurations.
- **`Runtime_DebugGetLoadedScriptIds`:**  Returns the IDs of loaded JavaScript scripts.
- **`Runtime_FunctionGetInferredName`:**  Retrieves the inferred name of a function.
- **`Runtime_CollectGarbage`:**  Forces a garbage collection.
- **`Runtime_ScriptLocationFromLine2`:**  Converts a line and column number in a script to an absolute position.
- **`Runtime_DebugOnFunctionCall`:**  This function is executed when a function is called, allowing for stepping and side-effect checks before the actual call.
- **`Runtime_DebugPrepareStepInSuspendedGenerator`:** Sets up breakpoints for stepping into a suspended generator.
- **`Runtime_DebugCollectCoverage`:** Collects code coverage information.
- **`Runtime_DebugTogglePreciseCoverage` and `Runtime_DebugToggleBlockCoverage`:**  Control the granularity of code coverage.
- **`Runtime_IncBlockCounter`:**  Related to block-level code coverage (but marked as unreachable in this file, implying it's handled elsewhere).
- **`Runtime_DebugAsyncFunctionSuspended`:**  Handles the suspension of asynchronous functions for debugging purposes.
- **`Runtime_DebugPromiseThen`:**  Hook called when a promise's `then` method is invoked, likely for tracking promise execution.
- **`Runtime_LiveEditPatchScript`:** Implements the "live edit" functionality, allowing modification of running code.
- **`Runtime_ProfileCreateSnapshotDataBlob`:**  A function related to creating snapshot data, likely for performance analysis and testing.

**Overall Function:** The file provides the runtime implementations of various debugging-related functionalities in V8. These functions are often called by the V8 debugger or other internal components to facilitate debugging JavaScript code.

**Connections to JavaScript:** Many of these functions directly correspond to debugging features accessible in JavaScript development tools.

Now, I need to create JavaScript examples to illustrate some of these connections.
这个 C++ 源代码文件 `v8/src/runtime/runtime-debug.cc` 的主要功能是**提供 V8 JavaScript 引擎在运行时进行调试支持的底层实现**。它包含了许多 V8 内部的 runtime 函数，这些函数被 V8 的调试器或者其他需要运行时调试信息的功能所调用。

具体来说，这个文件实现了以下一些关键的调试功能：

* **断点控制:**  例如 `Runtime_DebugBreakOnBytecode` 和 `Runtime_DebugBreakAtEntry`，分别用于在特定的字节码位置和函数入口处设置断点，当程序执行到这些位置时会暂停。
* **单步执行:**  虽然这个文件没有直接实现单步执行的逻辑，但它提供的 `Runtime_DebugOnFunctionCall` 等函数可以配合调试器实现单步进入等功能。
* **异常断点:** `Runtime_IsBreakOnException` 用于控制在抛出异常时是否中断程序执行。
* **作用域检查和修改:**  `Runtime_GetGeneratorScopeCount`, `Runtime_GetGeneratorScopeDetails`, 和 `Runtime_SetGeneratorScopeVariableValue` 专门用于处理生成器函数的调试，允许检查和修改生成器函数暂停时的作用域变量。
* **查看内部属性:** `Runtime::GetInternalProperties` 允许查看 JavaScript 对象的内部属性，这些属性在普通的 JavaScript 代码中无法直接访问，但对于调试非常有用。
* **代码覆盖率:** `Runtime_DebugCollectCoverage`, `Runtime_DebugTogglePreciseCoverage`, 和 `Runtime_DebugToggleBlockCoverage` 实现了代码覆盖率的收集和控制功能。
* **热重载 (LiveEdit):** `Runtime_LiveEditPatchScript` 实现了在程序运行时修改代码的功能。
* **异步函数调试:**  `Runtime_DebugAsyncFunctionSuspended` 和 `Runtime_DebugPromiseThen` 提供了对异步函数和 Promise 进行调试的支持。
* **获取脚本信息:** `Runtime_DebugGetLoadedScriptIds` 和 `Runtime_ScriptLocationFromLine2` 用于获取加载的脚本信息和定位代码位置。
* **`debugger` 语句:** `Runtime_HandleDebuggerStatement` 负责处理 JavaScript 代码中的 `debugger;` 语句，当执行到该语句时会触发断点。

**它与 JavaScript 的功能有密切关系，因为它实现了 JavaScript 调试器的底层机制。**  开发者在 JavaScript 代码中使用调试工具或者 `debugger;` 语句时，最终会触发这个文件中的 C++ 函数的执行。

**JavaScript 举例说明:**

1. **`debugger;` 语句:**

   ```javascript
   function myFunction(x) {
     console.log("Before debugger");
     debugger; // 执行到这里会暂停，允许开发者检查变量和执行流程
     console.log("After debugger");
     return x * 2;
   }

   myFunction(5);
   ```

   当 JavaScript 引擎执行到 `debugger;` 语句时，会调用 `Runtime_HandleDebuggerStatement` 函数，从而中断程序执行，并将控制权交给调试器。

2. **设置断点 (通过开发者工具):**

   如果你在 Chrome 开发者工具的代码面板中，在某一行点击设置了一个断点，当代码执行到该行时，V8 引擎内部会触发类似于 `Runtime_DebugBreakOnBytecode` 或者 `Runtime_DebugBreakAtEntry` 的函数，取决于断点设置的位置和类型。

3. **查看对象内部属性 (通过开发者工具):**

   在 Chrome 开发者工具的控制台或者 Sources 面板的 Scope 视图中，你可以查看对象的属性。对于一些特殊的内部属性（例如 Promise 的状态），开发者工具可能会调用 `Runtime::GetInternalProperties` 来获取这些信息并展示出来。

   例如，在控制台中输入以下代码并查看 promise 的属性：

   ```javascript
   let myPromise = new Promise((resolve, reject) => {
     setTimeout(() => resolve("done"), 1000);
   });

   // 在开发者工具中查看 myPromise 的属性，
   // 可能会看到类似 [[PromiseState]] 和 [[PromiseResult]] 这样的内部属性。
   ```

4. **单步执行 (通过开发者工具):**

   当你在调试器中点击 "Step Over" 或 "Step Into" 时，V8 引擎会设置一些内部状态，并且在函数调用等关键节点，可能会执行像 `Runtime_DebugOnFunctionCall` 这样的函数，以决定是否需要暂停或者进行其他调试操作。

5. **代码覆盖率 (通过开发者工具或测试框架):**

   一些代码覆盖率工具会利用 V8 提供的接口，当开启代码覆盖率收集时，V8 会调用 `Runtime_DebugCollectCoverage` 等函数来记录代码的执行情况。

   例如，使用 Istanbul.js 等工具生成代码覆盖率报告时，底层会利用 V8 的机制来跟踪代码的执行。

总而言之，`v8/src/runtime/runtime-debug.cc` 文件是 V8 引擎调试功能的基石，它提供的 runtime 函数是 JavaScript 调试器和相关工具与 V8 引擎交互的关键桥梁。开发者在 JavaScript 层面上使用的各种调试功能，背后都有这个文件中的 C++ 代码在默默地工作。

### 提示词
```
这是目录为v8/src/runtime/runtime-debug.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "src/common/globals.h"
#include "src/debug/debug-coverage.h"
#include "src/debug/debug-scopes.h"
#include "src/debug/debug.h"
#include "src/debug/liveedit.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/interpreter/bytecodes.h"
#include "src/interpreter/interpreter.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-promise-inl.h"
#include "src/objects/js-weak-refs-inl.h"
#include "src/runtime/runtime-utils.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/snapshot/snapshot.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/debug/debug-wasm-objects.h"
#include "src/wasm/wasm-objects-inl.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

RUNTIME_FUNCTION_RETURN_PAIR(Runtime_DebugBreakOnBytecode) {
  using interpreter::Bytecode;
  using interpreter::Bytecodes;
  using interpreter::OperandScale;

  SealHandleScope shs(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<Object> value = args.at(0);
  HandleScope scope(isolate);

  // Return value can be changed by debugger. Last set value will be used as
  // return value.
  ReturnValueScope result_scope(isolate->debug());
  isolate->debug()->set_return_value(*value);

  // Get the top-most JavaScript frame.
  JavaScriptStackFrameIterator it(isolate);
  if (isolate->debug_execution_mode() == DebugInfo::kBreakpoints) {
    isolate->debug()->Break(it.frame(),
                            handle(it.frame()->function(), isolate));
  }

  // If the user requested to restart a frame, there is no need
  // to get the return value or check the bytecode for side-effects.
  if (isolate->debug()->IsRestartFrameScheduled()) {
    Tagged<Object> exception = isolate->TerminateExecution();
    return MakePair(exception,
                    Smi::FromInt(static_cast<uint8_t>(Bytecode::kIllegal)));
  }

  // Return the handler from the original bytecode array.
  DCHECK(it.frame()->is_interpreted());
  InterpretedFrame* interpreted_frame =
      reinterpret_cast<InterpretedFrame*>(it.frame());

  bool side_effect_check_failed = false;
  if (isolate->debug_execution_mode() == DebugInfo::kSideEffects) {
    side_effect_check_failed =
        !isolate->debug()->PerformSideEffectCheckAtBytecode(interpreted_frame);
  }

  // Make sure to only access these objects after the side effect check, as the
  // check can allocate on failure.
  Tagged<SharedFunctionInfo> shared = interpreted_frame->function()->shared();
  Tagged<BytecodeArray> bytecode_array = shared->GetBytecodeArray(isolate);
  int bytecode_offset = interpreted_frame->GetBytecodeOffset();
  Bytecode bytecode = Bytecodes::FromByte(bytecode_array->get(bytecode_offset));

  if (Bytecodes::Returns(bytecode)) {
    // If we are returning (or suspending), reset the bytecode array on the
    // interpreted stack frame to the non-debug variant so that the interpreter
    // entry trampoline sees the return/suspend bytecode rather than the
    // DebugBreak.
    interpreted_frame->PatchBytecodeArray(bytecode_array);
  }

  // We do not have to deal with operand scale here. If the bytecode at the
  // break is prefixed by operand scaling, we would have patched over the
  // scaling prefix. We now simply dispatch to the handler for the prefix.
  // We need to deserialize now to ensure we don't hit the debug break again
  // after deserializing.
  OperandScale operand_scale = OperandScale::kSingle;
  isolate->interpreter()->GetBytecodeHandler(bytecode, operand_scale);

  if (side_effect_check_failed) {
    return MakePair(ReadOnlyRoots(isolate).exception(),
                    Smi::FromInt(static_cast<uint8_t>(bytecode)));
  }
  Tagged<Object> interrupt_object = isolate->stack_guard()->HandleInterrupts();
  if (IsException(interrupt_object, isolate)) {
    return MakePair(interrupt_object,
                    Smi::FromInt(static_cast<uint8_t>(bytecode)));
  }
  return MakePair(isolate->debug()->return_value(),
                  Smi::FromInt(static_cast<uint8_t>(bytecode)));
}

RUNTIME_FUNCTION(Runtime_DebugBreakAtEntry) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);

  DCHECK(function->shared()->BreakAtEntry(isolate));

  // Get the top-most JavaScript frame. This is the debug target function.
  JavaScriptStackFrameIterator it(isolate);
  DCHECK_EQ(*function, it.frame()->function());
  // Check whether the next JS frame is closer than the last API entry.
  // if yes, then the call to the debug target came from JavaScript. Otherwise,
  // the call to the debug target came from API. Do not break for the latter.
  it.Advance();
  if (!it.done() &&
      it.frame()->fp() < isolate->thread_local_top()->last_api_entry_) {
    isolate->debug()->Break(it.frame(), function);
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_HandleDebuggerStatement) {
  // SealHandleScope shs(isolate);
  // DCHECK_EQ(0, args.length());
  // if (isolate->debug()->break_points_active()) {
  //   isolate->debug()->HandleDebugBreak(
  //       kIgnoreIfTopFrameBlackboxed,
  //       v8::debug::BreakReasons({v8::debug::BreakReason::kDebuggerStatement}));
  //   if (isolate->debug()->IsRestartFrameScheduled()) {
  //     return isolate->TerminateExecution();
  //   }
  // }
  // return isolate->stack_guard()->HandleInterrupts();
  
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_ScheduleBreak) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(0, args.length());
  isolate->RequestInterrupt(
      [](v8::Isolate* isolate, void*) {
        v8::debug::BreakRightNow(
            isolate,
            v8::debug::BreakReasons({v8::debug::BreakReason::kScheduled}));
      },
      nullptr);
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

template <class IteratorType>
static Handle<ArrayList> AddIteratorInternalProperties(
    Isolate* isolate, Handle<ArrayList> result, Handle<IteratorType> iterator) {
  const char* kind = nullptr;
  switch (iterator->map()->instance_type()) {
    case JS_MAP_KEY_ITERATOR_TYPE:
      kind = "keys";
      break;
    case JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case JS_SET_KEY_VALUE_ITERATOR_TYPE:
      kind = "entries";
      break;
    case JS_MAP_VALUE_ITERATOR_TYPE:
    case JS_SET_VALUE_ITERATOR_TYPE:
      kind = "values";
      break;
    default:
      UNREACHABLE();
  }

  result = ArrayList::Add(
      isolate, result,
      isolate->factory()->NewStringFromAsciiChecked("[[IteratorHasMore]]"),
      isolate->factory()->ToBoolean(iterator->HasMore()));
  result = ArrayList::Add(
      isolate, result,
      isolate->factory()->NewStringFromAsciiChecked("[[IteratorIndex]]"),
      handle(iterator->index(), isolate));
  result = ArrayList::Add(
      isolate, result,
      isolate->factory()->NewStringFromAsciiChecked("[[IteratorKind]]"),
      isolate->factory()->NewStringFromAsciiChecked(kind));
  return result;
}

}  // namespace

MaybeHandle<JSArray> Runtime::GetInternalProperties(Isolate* isolate,
                                                    Handle<Object> object) {
  Handle<ArrayList> result = ArrayList::New(isolate, 8 * 2);
  if (IsJSObject(*object)) {
    PrototypeIterator iter(isolate, Cast<JSObject>(object), kStartAtReceiver);
    if (iter.HasAccess()) {
      iter.Advance();
      DirectHandle<Object> prototype = PrototypeIterator::GetCurrent(iter);
      if (!iter.IsAtEnd() && iter.HasAccess() && IsJSGlobalProxy(*object)) {
        // Skip JSGlobalObject as the [[Prototype]].
        DCHECK(IsJSGlobalObject(*prototype));
        iter.Advance();
        prototype = PrototypeIterator::GetCurrent(iter);
      }
      if (!IsNull(*prototype, isolate)) {
        result = ArrayList::Add(
            isolate, result,
            isolate->factory()->NewStringFromStaticChars("[[Prototype]]"),
            prototype);
      }
    }
  }
  if (IsJSBoundFunction(*object)) {
    auto function = Cast<JSBoundFunction>(object);

    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[TargetFunction]]"),
        handle(function->bound_target_function(), isolate));
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[BoundThis]]"),
        handle(function->bound_this(), isolate));
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[BoundArgs]]"),
        isolate->factory()->NewJSArrayWithElements(
            isolate->factory()->CopyFixedArray(
                handle(function->bound_arguments(), isolate))));
  } else if (IsJSMapIterator(*object)) {
    Handle<JSMapIterator> iterator = Cast<JSMapIterator>(object);
    result = AddIteratorInternalProperties(isolate, result, iterator);
  } else if (IsJSSetIterator(*object)) {
    Handle<JSSetIterator> iterator = Cast<JSSetIterator>(object);
    result = AddIteratorInternalProperties(isolate, result, iterator);
  } else if (IsJSGeneratorObject(*object)) {
    auto generator = Cast<JSGeneratorObject>(object);

    const char* status = "suspended";
    if (generator->is_closed()) {
      status = "closed";
    } else if (generator->is_executing()) {
      status = "running";
    } else {
      DCHECK(generator->is_suspended());
    }

    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[GeneratorState]]"),
        isolate->factory()->NewStringFromAsciiChecked(status));
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[GeneratorFunction]]"),
        handle(generator->function(), isolate));
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[GeneratorReceiver]]"),
        handle(generator->receiver(), isolate));
  } else if (IsJSPromise(*object)) {
    auto promise = Cast<JSPromise>(object);

    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[PromiseState]]"),
        isolate->factory()->NewStringFromAsciiChecked(
            JSPromise::Status(promise->status())));
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[PromiseResult]]"),
        promise->status() == Promise::kPending
            ? isolate->factory()->undefined_value()
            : handle(promise->result(), isolate));
  } else if (IsJSProxy(*object)) {
    auto js_proxy = Cast<JSProxy>(object);

    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[Handler]]"),
        handle(js_proxy->handler(), isolate));
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[Target]]"),
        handle(js_proxy->target(), isolate));
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[IsRevoked]]"),
        isolate->factory()->ToBoolean(js_proxy->IsRevoked()));
  } else if (IsJSPrimitiveWrapper(*object)) {
    auto js_value = Cast<JSPrimitiveWrapper>(object);

    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[PrimitiveValue]]"),
        handle(js_value->value(), isolate));
  } else if (IsJSWeakRef(*object)) {
    auto js_weak_ref = Cast<JSWeakRef>(object);

    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[WeakRefTarget]]"),
        handle(js_weak_ref->target(), isolate));
  } else if (IsJSArrayBuffer(*object)) {
    Handle<JSArrayBuffer> js_array_buffer = Cast<JSArrayBuffer>(object);
    if (js_array_buffer->was_detached()) {
      // Mark a detached JSArrayBuffer and such and don't even try to
      // create views for it, since the TypedArray constructors will
      // throw a TypeError when the underlying buffer is detached.
      result = ArrayList::Add(
          isolate, result,
          isolate->factory()->NewStringFromAsciiChecked("[[IsDetached]]"),
          isolate->factory()->true_value());
    } else {
      const size_t byte_length = js_array_buffer->byte_length();
      static_assert(JSTypedArray::kMaxByteLength ==
                    JSArrayBuffer::kMaxByteLength);
      using DataView = std::tuple<const char*, ExternalArrayType, size_t>;
      for (auto [name, type, elem_size] :
           {DataView{"[[Int8Array]]", kExternalInt8Array, 1},
            DataView{"[[Uint8Array]]", kExternalUint8Array, 1},
            DataView{"[[Int16Array]]", kExternalInt16Array, 2},
            DataView{"[[Int32Array]]", kExternalInt32Array, 4}}) {
        if ((byte_length % elem_size) != 0) continue;
        size_t length = byte_length / elem_size;
        result =
            ArrayList::Add(isolate, result,
                           isolate->factory()->NewStringFromAsciiChecked(name),
                           isolate->factory()->NewJSTypedArray(
                               type, js_array_buffer, 0, length));
      }
      result =
          ArrayList::Add(isolate, result,
                         isolate->factory()->NewStringFromAsciiChecked(
                             "[[ArrayBufferByteLength]]"),
                         isolate->factory()->NewNumberFromSize(byte_length));

      auto backing_store = js_array_buffer->GetBackingStore();
      DirectHandle<Object> array_buffer_data;
      if (backing_store) {
        array_buffer_data =
            isolate->factory()->NewNumberFromUint(backing_store->id());
      } else {
        array_buffer_data = isolate->factory()->null_value();
      }
      result = ArrayList::Add(
          isolate, result,
          isolate->factory()->NewStringFromAsciiChecked("[[ArrayBufferData]]"),
          array_buffer_data);

      Handle<Symbol> memory_symbol =
          isolate->factory()->array_buffer_wasm_memory_symbol();
      DirectHandle<Object> memory_object =
          JSObject::GetDataProperty(isolate, js_array_buffer, memory_symbol);
      if (!IsUndefined(*memory_object, isolate)) {
        result = ArrayList::Add(isolate, result,
                                isolate->factory()->NewStringFromAsciiChecked(
                                    "[[WebAssemblyMemory]]"),
                                memory_object);
      }
    }
#if V8_ENABLE_WEBASSEMBLY
  } else if (IsWasmInstanceObject(*object)) {
    result = AddWasmInstanceObjectInternalProperties(
        isolate, result, Cast<WasmInstanceObject>(object));
  } else if (IsWasmModuleObject(*object)) {
    result = AddWasmModuleObjectInternalProperties(
        isolate, result, Cast<WasmModuleObject>(object));
  } else if (IsWasmTableObject(*object)) {
    result = AddWasmTableObjectInternalProperties(
        isolate, result, Cast<WasmTableObject>(object));
#endif  // V8_ENABLE_WEBASSEMBLY
  }
  return isolate->factory()->NewJSArrayWithElements(
      ArrayList::ToFixedArray(isolate, result), PACKED_ELEMENTS);
}

RUNTIME_FUNCTION(Runtime_GetGeneratorScopeCount) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  if (!IsJSGeneratorObject(args[0])) return Smi::zero();

  // Check arguments.
  Handle<JSGeneratorObject> gen = args.at<JSGeneratorObject>(0);

  // Only inspect suspended generator scopes.
  if (!gen->is_suspended()) {
    return Smi::zero();
  }

  // Count the visible scopes.
  int n = 0;
  for (ScopeIterator it(isolate, gen); !it.Done(); it.Next()) {
    n++;
  }

  return Smi::FromInt(n);
}

RUNTIME_FUNCTION(Runtime_GetGeneratorScopeDetails) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  if (!IsJSGeneratorObject(args[0])) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // Check arguments.
  Handle<JSGeneratorObject> gen = args.at<JSGeneratorObject>(0);
  int index = NumberToInt32(args[1]);

  // Only inspect suspended generator scopes.
  if (!gen->is_suspended()) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // Find the requested scope.
  int n = 0;
  ScopeIterator it(isolate, gen);
  for (; !it.Done() && n < index; it.Next()) {
    n++;
  }
  if (it.Done()) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  return *it.MaterializeScopeDetails();
}

static bool SetScopeVariableValue(ScopeIterator* it, int index,
                                  Handle<String> variable_name,
                                  Handle<Object> new_value) {
  for (int n = 0; !it->Done() && n < index; it->Next()) {
    n++;
  }
  if (it->Done()) {
    return false;
  }
  return it->SetVariableValue(variable_name, new_value);
}

// Change variable value in closure or local scope
// args[0]: number or JsFunction: break id or function
// args[1]: number: scope index
// args[2]: string: variable name
// args[3]: object: new value
//
// Return true if success and false otherwise
RUNTIME_FUNCTION(Runtime_SetGeneratorScopeVariableValue) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSGeneratorObject> gen = args.at<JSGeneratorObject>(0);
  int index = NumberToInt32(args[1]);
  Handle<String> variable_name = args.at<String>(2);
  Handle<Object> new_value = args.at(3);
  ScopeIterator it(isolate, gen);
  bool res = SetScopeVariableValue(&it, index, variable_name, new_value);
  return isolate->heap()->ToBoolean(res);
}

RUNTIME_FUNCTION(Runtime_GetBreakLocations) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  CHECK(isolate->debug()->is_active());
  DirectHandle<JSFunction> fun = args.at<JSFunction>(0);

  DirectHandle<SharedFunctionInfo> shared(fun->shared(), isolate);
  // Find the number of break points
  Handle<Object> break_locations =
      Debug::GetSourceBreakLocations(isolate, shared);
  if (IsUndefined(*break_locations, isolate)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }
  // Return array as JS array
  return *isolate->factory()->NewJSArrayWithElements(
      Cast<FixedArray>(break_locations));
}

// Returns the state of break on exceptions
// args[0]: boolean indicating uncaught exceptions
RUNTIME_FUNCTION(Runtime_IsBreakOnException) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  uint32_t type_arg = NumberToUint32(args[0]);

  ExceptionBreakType type = static_cast<ExceptionBreakType>(type_arg);
  bool result = isolate->debug()->IsBreakOnException(type);
  return Smi::FromInt(result);
}

// Clear all stepping set by PrepareStep.
RUNTIME_FUNCTION(Runtime_ClearStepping) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  CHECK(isolate->debug()->is_active());
  isolate->debug()->ClearStepping();
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_DebugGetLoadedScriptIds) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());

  DirectHandle<FixedArray> instances;
  {
    DebugScope debug_scope(isolate->debug());
    // Fill the script objects.
    instances = isolate->debug()->GetLoadedScripts();
  }

  // Convert the script objects to proper JS objects.
  for (int i = 0; i < instances->length(); i++) {
    DirectHandle<Script> script(Cast<Script>(instances->get(i)), isolate);
    instances->set(i, Smi::FromInt(script->id()));
  }

  // Return result as a JS array.
  return *isolate->factory()->NewJSArrayWithElements(instances);
}

RUNTIME_FUNCTION(Runtime_FunctionGetInferredName) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(1, args.length());

  Tagged<Object> f = args[0];
  if (IsJSFunction(f)) {
    return Cast<JSFunction>(f)->shared()->inferred_name();
  }
  return ReadOnlyRoots(isolate).empty_string();
}

// Performs a GC.
// Presently, it only does a full GC.
RUNTIME_FUNCTION(Runtime_CollectGarbage) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(1, args.length());
  isolate->heap()->PreciseCollectAllGarbage(GCFlag::kNoFlags,
                                            GarbageCollectionReason::kRuntime);
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

int ScriptLinePosition(DirectHandle<Script> script, int line) {
  if (line < 0) return -1;

#if V8_ENABLE_WEBASSEMBLY
  if (script->type() == Script::Type::kWasm) {
    // Wasm positions are relative to the start of the module.
    return 0;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  Script::InitLineEnds(script->GetIsolate(), script);

  Tagged<FixedArray> line_ends_array = Cast<FixedArray>(script->line_ends());
  const int line_count = line_ends_array->length();
  DCHECK_LT(0, line_count);

  if (line == 0) return 0;
  // If line == line_count, we return the first position beyond the last line.
  if (line > line_count) return -1;
  return Smi::ToInt(line_ends_array->get(line - 1)) + 1;
}

int ScriptLinePositionWithOffset(DirectHandle<Script> script, int line,
                                 int offset) {
  if (line < 0 || offset < 0) return -1;

  if (line == 0 || offset == 0)
    return ScriptLinePosition(script, line) + offset;

  Script::PositionInfo info;
  if (!Script::GetPositionInfo(script, offset, &info,
                               Script::OffsetFlag::kNoOffset)) {
    return -1;
  }

  const int total_line = info.line + line;
  return ScriptLinePosition(script, total_line);
}

Handle<Object> GetJSPositionInfo(DirectHandle<Script> script, int position,
                                 Script::OffsetFlag offset_flag,
                                 Isolate* isolate) {
  Script::PositionInfo info;
  if (!Script::GetPositionInfo(script, position, &info, offset_flag)) {
    return isolate->factory()->null_value();
  }

#if V8_ENABLE_WEBASSEMBLY
  const bool is_wasm_script = script->type() == Script::Type::kWasm;
#else
  const bool is_wasm_script = false;
#endif  // V8_ENABLE_WEBASSEMBLY
  DirectHandle<String> sourceText =
      is_wasm_script ? isolate->factory()->empty_string()
                     : isolate->factory()->NewSubString(
                           handle(Cast<String>(script->source()), isolate),
                           info.line_start, info.line_end);

  Handle<JSObject> jsinfo =
      isolate->factory()->NewJSObject(isolate->object_function());

  JSObject::AddProperty(isolate, jsinfo, isolate->factory()->script_string(),
                        script, NONE);
  JSObject::AddProperty(isolate, jsinfo, isolate->factory()->position_string(),
                        handle(Smi::FromInt(position), isolate), NONE);
  JSObject::AddProperty(isolate, jsinfo, isolate->factory()->line_string(),
                        handle(Smi::FromInt(info.line), isolate), NONE);
  JSObject::AddProperty(isolate, jsinfo, isolate->factory()->column_string(),
                        handle(Smi::FromInt(info.column), isolate), NONE);
  JSObject::AddProperty(isolate, jsinfo,
                        isolate->factory()->sourceText_string(), sourceText,
                        NONE);

  return jsinfo;
}

Handle<Object> ScriptLocationFromLine(Isolate* isolate,
                                      DirectHandle<Script> script,
                                      DirectHandle<Object> opt_line,
                                      DirectHandle<Object> opt_column,
                                      int32_t offset) {
  // Line and column are possibly undefined and we need to handle these cases,
  // additionally subtracting corresponding offsets.

  int32_t line = 0;
  if (!IsNullOrUndefined(*opt_line, isolate)) {
    CHECK(IsNumber(*opt_line));
    line = NumberToInt32(*opt_line) - script->line_offset();
  }

  int32_t column = 0;
  if (!IsNullOrUndefined(*opt_column, isolate)) {
    CHECK(IsNumber(*opt_column));
    column = NumberToInt32(*opt_column);
    if (line == 0) column -= script->column_offset();
  }

  int line_position = ScriptLinePositionWithOffset(script, line, offset);
  if (line_position < 0 || column < 0) return isolate->factory()->null_value();

  return GetJSPositionInfo(script, line_position + column,
                           Script::OffsetFlag::kNoOffset, isolate);
}

// Slow traversal over all scripts on the heap.
bool GetScriptById(Isolate* isolate, int needle, Handle<Script>* result) {
  Script::Iterator iterator(isolate);
  for (Tagged<Script> script = iterator.Next(); !script.is_null();
       script = iterator.Next()) {
    if (script->id() == needle) {
      *result = handle(script, isolate);
      return true;
    }
  }

  return false;
}

}  // namespace

// TODO(5530): Rename once conflicting function has been deleted.
RUNTIME_FUNCTION(Runtime_ScriptLocationFromLine2) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  int32_t scriptid = NumberToInt32(args[0]);
  DirectHandle<Object> opt_line = args.at(1);
  DirectHandle<Object> opt_column = args.at(2);
  int32_t offset = NumberToInt32(args[3]);

  Handle<Script> script;
  CHECK(GetScriptById(isolate, scriptid, &script));

  return *ScriptLocationFromLine(isolate, script, opt_line, opt_column, offset);
}

// On function call, depending on circumstances, prepare for stepping in,
// or perform a side effect check.
RUNTIME_FUNCTION(Runtime_DebugOnFunctionCall) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSFunction> fun = args.at<JSFunction>(0);
  Handle<Object> receiver = args.at(1);
  if (isolate->debug()->needs_check_on_function_call()) {
    // Ensure that the callee will perform debug check on function call too.
    DirectHandle<SharedFunctionInfo> shared(fun->shared(), isolate);
    isolate->debug()->DeoptimizeFunction(shared);
    if (isolate->debug()->last_step_action() >= StepInto ||
        isolate->debug()->break_on_next_function_call()) {
      DCHECK_EQ(isolate->debug_execution_mode(), DebugInfo::kBreakpoints);
      isolate->debug()->PrepareStepIn(fun);
    }
    if (isolate->debug_execution_mode() == DebugInfo::kSideEffects &&
        !isolate->debug()->PerformSideEffectCheck(fun, receiver)) {
      return ReadOnlyRoots(isolate).exception();
    }
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

// Set one shot breakpoints for the suspended generator object.
RUNTIME_FUNCTION(Runtime_DebugPrepareStepInSuspendedGenerator) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  isolate->debug()->PrepareStepInSuspendedGenerator();
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {
Handle<JSObject> MakeRangeObject(Isolate* isolate, const CoverageBlock& range) {
  Factory* factory = isolate->factory();

  Handle<String> start_string = factory->InternalizeUtf8String("start");
  Handle<String> end_string = factory->InternalizeUtf8String("end");
  Handle<String> count_string = factory->InternalizeUtf8String("count");

  Handle<JSObject> range_obj = factory->NewJSObjectWithNullProto();
  JSObject::AddProperty(isolate, range_obj, start_string,
                        factory->NewNumberFromInt(range.start), NONE);
  JSObject::AddProperty(isolate, range_obj, end_string,
                        factory->NewNumberFromInt(range.end), NONE);
  JSObject::AddProperty(isolate, range_obj, count_string,
                        factory->NewNumberFromUint(range.count), NONE);

  return range_obj;
}
}  // namespace

RUNTIME_FUNCTION(Runtime_DebugCollectCoverage) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  // Collect coverage data.
  std::unique_ptr<Coverage> coverage;
  if (isolate->is_best_effort_code_coverage()) {
    coverage = Coverage::CollectBestEffort(isolate);
  } else {
    coverage = Coverage::CollectPrecise(isolate);
  }
  Factory* factory = isolate->factory();
  // Turn the returned data structure into JavaScript.
  // Create an array of scripts.
  int num_scripts = static_cast<int>(coverage->size());
  // Prepare property keys.
  DirectHandle<FixedArray> scripts_array = factory->NewFixedArray(num_scripts);
  Handle<String> script_string = factory->script_string();
  for (int i = 0; i < num_scripts; i++) {
    const auto& script_data = coverage->at(i);
    HandleScope inner_scope(isolate);

    std::vector<CoverageBlock> ranges;
    int num_functions = static_cast<int>(script_data.functions.size());
    for (int j = 0; j < num_functions; j++) {
      const auto& function_data = script_data.functions[j];
      ranges.emplace_back(function_data.start, function_data.end,
                          function_data.count);
      for (size_t k = 0; k < function_data.blocks.size(); k++) {
        const auto& block_data = function_data.blocks[k];
        ranges.emplace_back(block_data.start, block_data.end, block_data.count);
      }
    }

    int num_ranges = static_cast<int>(ranges.size());
    DirectHandle<FixedArray> ranges_array = factory->NewFixedArray(num_ranges);
    for (int j = 0; j < num_ranges; j++) {
      DirectHandle<JSObject> range_object = MakeRangeObject(isolate, ranges[j]);
      ranges_array->set(j, *range_object);
    }

    Handle<JSArray> script_obj =
        factory->NewJSArrayWithElements(ranges_array, PACKED_ELEMENTS);
    JSObject::AddProperty(isolate, script_obj, script_string,
                          handle(script_data.script->source(), isolate), NONE);
    scripts_array->set(i, *script_obj);
  }
  return *factory->NewJSArrayWithElements(scripts_array, PACKED_ELEMENTS);
}

RUNTIME_FUNCTION(Runtime_DebugTogglePreciseCoverage) {
  SealHandleScope shs(isolate);
  bool enable = Cast<Boolean>(args[0])->ToBool(isolate);
  Coverage::SelectMode(isolate, enable ? debug::CoverageMode::kPreciseCount
                                       : debug::CoverageMode::kBestEffort);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_DebugToggleBlockCoverage) {
  SealHandleScope shs(isolate);
  bool enable = Cast<Boolean>(args[0])->ToBool(isolate);
  Coverage::SelectMode(isolate, enable ? debug::CoverageMode::kBlockCount
                                       : debug::CoverageMode::kBestEffort);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_IncBlockCounter) {
  UNREACHABLE();  // Never called. See the IncBlockCounter builtin instead.
}

RUNTIME_FUNCTION(Runtime_DebugAsyncFunctionSuspended) {
  DCHECK_EQ(4, args.length());
  HandleScope scope(isolate);
  Handle<JSPromise> promise = args.at<JSPromise>(0);
  Handle<JSPromise> outer_promise = args.at<JSPromise>(1);
  Handle<JSFunction> reject_handler = args.at<JSFunction>(2);
  DirectHandle<JSGeneratorObject> generator = args.at<JSGeneratorObject>(3);

  // Allocate the throwaway promise and fire the appropriate init
  // hook for the throwaway promise (passing the {promise} as its
  // parent).
  Handle<JSPromise> throwaway = isolate->factory()->NewJSPromiseWithoutHook();
  isolate->OnAsyncFunctionSuspended(throwaway, promise);

  // The Promise will be thrown away and not handled, but it
  // shouldn't trigger unhandled reject events as its work is done
  throwaway->set_has_handler(true);

  // Enable proper debug support for promises.
  if (isolate->debug()->is_active()) {
    Object::SetProperty(isolate, reject_handler,
                        isolate->factory()->promise_forwarding_handler_symbol(),
                        isolate->factory()->true_value(),
                        StoreOrigin::kMaybeKeyed,
                        Just(ShouldThrow::kThrowOnError))
        .Check();

    // Mark the dependency to {outer_promise} in case the {throwaway}
    // Promise is found on the Promise stack
    Object::SetProperty(isolate, throwaway,
                        isolate->factory()->promise_handled_by_symbol(),
                        outer_promise, StoreOrigin::kMaybeKeyed,
                        Just(ShouldThrow::kThrowOnError))
        .Check();

    Handle<WeakFixedArray> awaited_by_holder(
        isolate->factory()->NewWeakFixedArray(1));
    awaited_by_holder->set(0, MakeWeak(*generator));
    Object::SetProperty(isolate, promise,
                        isolate->factory()->promise_awaited_by_symbol(),
                        awaited_by_holder, StoreOrigin::kMaybeKeyed,
                        Just(ShouldThrow::kThrowOnError))
        .Check();
  }

  return *throwaway;
}

RUNTIME_FUNCTION(Runtime_DebugPromiseThen) {
  DCHECK_EQ(1, args.length());
  HandleScope scope(isolate);
  Handle<JSReceiver> promise = args.at<JSReceiver>(0);
  if (IsJSPromise(*promise)) {
    isolate->OnPromiseThen(Cast<JSPromise>(promise));
  }
  return *promise;
}

RUNTIME_FUNCTION(Runtime_LiveEditPatchScript) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  DirectHandle<JSFunction> script_function = args.at<JSFunction>(0);
  Handle<String> new_source = args.at<String>(1);

  Handle<Script> script(Cast<Script>(script_function->shared()->script()),
                        isolate);
  v8::debug::LiveEditResult result;
  LiveEdit::PatchScript(isolate, script, new_source, /* preview */ false,
                        /* allow_top_frame_live_editing */ false, &result);
  switch (result.status) {
    case v8::debug::LiveEditResult::COMPILE_ERROR:
      return isolate->Throw(*isolate->factory()->NewStringFromAsciiChecked(
          "LiveEdit failed: COMPILE_ERROR"));
    case v8::debug::LiveEditResult::BLOCKED_BY_RUNNING_GENERATOR:
      return isolate->Throw(*isolate->factory()->NewStringFromAsciiChecked(
          "LiveEdit failed: BLOCKED_BY_RUNNING_GENERATOR"));
    case v8::debug::LiveEditResult::BLOCKED_BY_ACTIVE_FUNCTION:
      return isolate->Throw(*isolate->factory()->NewStringFromAsciiChecked(
          "LiveEdit failed: BLOCKED_BY_ACTIVE_FUNCTION"));
    case v8::debug::LiveEditResult::BLOCKED_BY_TOP_LEVEL_ES_MODULE_CHANGE:
      return isolate->Throw(*isolate->factory()->NewStringFromAsciiChecked(
          "LiveEdit failed: BLOCKED_BY_TOP_LEVEL_ES_MODULE_CHANGE"));
    case v8::debug::LiveEditResult::OK:
      return ReadOnlyRoots(isolate).undefined_value();
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_ProfileCreateSnapshotDataBlob) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());

  // Used only by the test/memory/Memory.json benchmark. This creates a snapshot
  // blob and outputs various statistics around it.

  DCHECK(v8_flags.profile_deserialization && v8_flags.serialization_statistics);

  DisableEmbeddedBlobRefcounting();

  static constexpr char* kNoEmbeddedSource = nullptr;
  // We use this flag to tell the serializer not to finalize/seal RO space -
  // this already happened after deserializing the main Isolate.
  static constexpr Snapshot::SerializerFlags kSerializerFlags =
      Snapshot::SerializerFlag::kAllowActiveIsolateForTesting;
  v8::StartupData blob = CreateSnapshotDataBlobInternal(
      v8::SnapshotCreator::FunctionCodeHandling::kClear, kNoEmbeddedSource,
      kSerializerFlags);
  delete[] blob.data;

  // Track the embedded blob size as well.
  {
    i::EmbeddedData d = i::EmbeddedData::FromBlob(isolate);
    PrintF("Embedded blob is %d bytes\n",
           static_cast<int>(d.code_size() + d.data_size()));
  }

  FreeCurrentEmbeddedBlob();

  return ReadOnlyRoots(isolate).undefined_value();
}

}  // namespace internal
}  // namespace v8
```