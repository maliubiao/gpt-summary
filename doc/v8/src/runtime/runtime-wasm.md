Response: The user wants a summary of the C++ source code file `v8/src/runtime/runtime-wasm.cc`.
The user also wants to know how this file relates to JavaScript and wants an example if a relationship exists.
This is part 1 of 2, so I should focus on the functionality present in this part.

Based on the included headers and the function names, this file seems to implement runtime functions that are called from WebAssembly code. These functions handle various interactions between WebAssembly and the JavaScript environment, such as:

- **Type conversions:** Converting between JS and Wasm values.
- **Memory management:** Growing Wasm memory.
- **Error handling:** Throwing Wasm-specific errors and handling JS exceptions.
- **Stack management:** Handling stack overflows and stack guards.
- **Lazy compilation:** Compiling Wasm functions on demand.
- **Deoptimization:** Handling deoptimization of Liftoff-compiled Wasm code.
- **Function calls:** Handling calls between JS and Wasm, including tier-up optimizations.
- **Debugging:** Supporting breakpoints and stepping in Wasm code.
- **Atomic operations:** Implementing atomic wait operations on shared memory.
- **Table operations:** Getting, setting, initializing, copying, growing, and filling Wasm tables.
- **Suspenders:** Implementing support for Wasm continuations and stack switching.
- **String operations:** Creating Wasm strings from memory or arrays.
- **Array operations:** Copying and initializing Wasm arrays.

Relationship with JavaScript: WebAssembly is designed to run alongside JavaScript in the browser. This file contains the C++ implementation of runtime functions that facilitate this interoperability. When Wasm code needs to interact with the JavaScript environment (e.g., call a JavaScript function, access a global variable, throw a JavaScript error), it calls one of these runtime functions.

JavaScript Example: Imagine a WebAssembly module that needs to log a message to the browser's console. The Wasm code would likely call a JavaScript function like `console.log`. This call would go through a Wasm-to-JS wrapper, and during the execution of that wrapper or a related runtime function in this file, the necessary steps to call the JavaScript `console.log` function would be performed. For instance, the `Runtime_WasmGenericWasmToJSObject` function is involved in converting Wasm function references to JavaScript function objects.
这个C++源代码文件 `v8/src/runtime/runtime-wasm.cc` 的主要功能是 **实现 V8 引擎中 WebAssembly 虚拟机与 JavaScript 运行时环境交互的各种运行时函数**。

更具体地说，这个文件定义了许多名为 `Runtime_XXX` 的 C++ 函数，这些函数是在 WebAssembly 代码执行过程中，需要调用 V8 引擎的底层功能时被调用的。 这些功能涵盖了 WebAssembly 与 JavaScript 交互的各个方面，包括：

**主要功能归纳：**

1. **类型转换 (Type Conversion):**
   - 在 WebAssembly 和 JavaScript 对象之间进行类型转换，例如 `Runtime_WasmGenericWasmToJSObject` 和 `Runtime_WasmGenericJSToWasmObject`， 用于将 WebAssembly 的函数引用转换为 JavaScript 函数对象，或将 JavaScript 对象转换为 WebAssembly 的表示形式。

2. **内存管理 (Memory Management):**
   - 提供 WebAssembly 线性内存操作的支持，例如 `Runtime_WasmMemoryGrow` 用于扩展 WebAssembly 实例的内存。

3. **错误处理 (Error Handling):**
   - 实现 WebAssembly 运行时错误的处理和抛出，例如 `Runtime_TrapHandlerThrowWasmError` 和 `Runtime_ThrowWasmError` 用于抛出特定的 WebAssembly 错误。
   - 处理 WebAssembly 调用 JavaScript 时可能发生的类型错误，例如 `Runtime_WasmThrowJSTypeError`。

4. **栈管理 (Stack Management):**
   - 管理 WebAssembly 代码执行的栈，例如 `Runtime_ThrowWasmStackOverflow` 用于处理栈溢出， `Runtime_WasmStackGuard` 用于栈保护和中断处理。

5. **懒编译 (Lazy Compilation):**
   - 支持 WebAssembly 函数的按需编译，例如 `Runtime_WasmCompileLazy` 用于在首次调用时编译 WebAssembly 函数。

6. **去优化 (Deoptimization):**
   -  处理 Liftoff 编译的 WebAssembly 代码的去优化过程，例如 `Runtime_WasmLiftoffDeoptFinish`。

7. **函数调用 (Function Calls):**
   - 处理 WebAssembly 与 JavaScript 之间的函数调用，包括对调用目标进行优化的机制，例如 `Runtime_TierUpJSToWasmWrapper` 和 `Runtime_TierUpWasmToJSWrapper` 用于提升跨语言调用的性能。

8. **调试 (Debugging):**
   - 提供 WebAssembly 代码调试的支持，例如 `Runtime_WasmDebugBreak` 用于在 WebAssembly 代码中设置断点。

9. **原子操作 (Atomic Operations):**
   - 实现 WebAssembly 的原子操作，例如 `Runtime_WasmI32AtomicWait` 和 `Runtime_WasmI64AtomicWait` 用于实现原子等待操作。

10. **表操作 (Table Operations):**
    - 提供对 WebAssembly 函数表进行操作的支持，例如 `Runtime_WasmFunctionTableGet`， `Runtime_WasmFunctionTableSet`， `Runtime_WasmTableInit`， `Runtime_WasmTableCopy`， `Runtime_WasmTableGrow` 和 `Runtime_WasmTableFill`，用于获取、设置、初始化、复制、增长和填充函数表。

11. **异常处理 (Exception Handling):**
    - 支持 WebAssembly 的异常处理机制，例如 `Runtime_WasmThrow` 和 `Runtime_WasmReThrow` 用于抛出和重新抛出 WebAssembly 异常。

12. **异步操作 (Asynchronous Operations):**
    - 包含用于支持 WebAssembly 异步操作的运行时函数，例如 `Runtime_WasmAllocateSuspender` 用于分配一个 `WasmSuspenderObject`，这是实现 WebAssembly 协程的关键部分。

13. **数组操作 (Array Operations):**
    - 提供对 WebAssembly 数组进行操作的支持，例如 `Runtime_WasmArrayCopy` 用于复制数组内容， `Runtime_WasmArrayNewSegment` 和 `Runtime_WasmArrayInitSegment` 用于创建和初始化数组段。

14. **字符串操作 (String Operations):**
    -  支持 WebAssembly 字符串的创建，例如 `Runtime_WasmStringNewWtf8` 和 `Runtime_WasmStringNewWtf8Array` 用于从内存或数组创建 UTF-8 字符串。

**与 JavaScript 的关系：**

此文件中的运行时函数是 WebAssembly 与 JavaScript 交互的桥梁。当 WebAssembly 代码需要执行以下操作时，它会调用这些运行时函数：

* **调用 JavaScript 函数:** WebAssembly 可以导入并在内部调用 JavaScript 函数。
* **访问 JavaScript 对象:** WebAssembly 可以通过导入的接口与 JavaScript 对象进行交互。
* **抛出 JavaScript 异常:** WebAssembly 代码可以抛出 JavaScript 异常。
* **使用 JavaScript 提供的功能:** 例如，使用 JavaScript 的 `console.log` 进行日志输出。

**JavaScript 示例:**

假设有一个简单的 WebAssembly 模块，它需要调用 JavaScript 的 `console.log` 函数来打印一条消息。

**WebAssembly 代码 (示例):**

```wat
(module
  (import "env" "log" (func $log (param i32)))
  (func (export "main")
    i32.const 123
    call $log
  )
)
```

**JavaScript 代码:**

```javascript
const wasmModule = new WebAssembly.Module( /* ... wasm bytecode ... */ );
const wasmInstance = new WebAssembly.Instance(wasmModule, {
  env: {
    log: function(message) {
      console.log("Wasm says:", message);
    }
  }
});

wasmInstance.exports.main();
```

在这个例子中，当 WebAssembly 代码执行 `call $log` 时，实际上是调用了 JavaScript 中导入的 `log` 函数。  在 V8 引擎的内部实现中，当 WebAssembly 执行 `call` 指令调用导入的函数时，会涉及到 `v8/src/runtime/runtime-wasm.cc` 中相关的运行时函数，以便正确地将 WebAssembly 的调用转换为 JavaScript 的函数调用，并处理参数的传递和返回值的转换。 例如，`Runtime_TierUpWasmToJSWrapper` 就可能在这个过程中被调用，用于优化 WebAssembly 到 JavaScript 的调用性能。 此外，如果 JavaScript 函数抛出一个异常，`Runtime_WasmThrowJSTypeError` 等函数可能会参与处理这个异常，并将其传递回 WebAssembly 环境。

总而言之，`v8/src/runtime/runtime-wasm.cc` 是 V8 引擎中 WebAssembly 功能的核心组成部分，它实现了 WebAssembly 与 JavaScript 运行时环境无缝集成所需的关键底层功能。

### 提示词
```
这是目录为v8/src/runtime/runtime-wasm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/builtins/builtins-inl.h"
#include "src/builtins/data-view-ops.h"
#include "src/common/assert-scope.h"
#include "src/common/message-template.h"
#include "src/compiler/wasm-compiler.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/frames.h"
#include "src/heap/factory.h"
#include "src/numbers/conversions.h"
#include "src/objects/objects-inl.h"
#include "src/runtime/runtime-utils.h"
#include "src/strings/unicode-inl.h"
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-subtyping.h"
#include "src/wasm/wasm-value.h"

#if V8_ENABLE_WEBASSEMBLY && V8_ENABLE_DRUMBRAKE
#include "src/wasm/interpreter/wasm-interpreter.h"
#endif  // V8_ENABLE_WEBASSEMBLY && V8_ENABLE_DRUMBRAKE

namespace v8::internal {

// TODO(13036): See if we can find a way to have the stack walker visit
// tagged values being passed from Wasm to runtime functions. In the meantime,
// disallow access to safe-looking-but-actually-unsafe stack-backed handles
// and thereby force manual creation of safe handles (backed by HandleScope).
class RuntimeArgumentsWithoutHandles : public RuntimeArguments {
 public:
  RuntimeArgumentsWithoutHandles(int length, Address* arguments)
      : RuntimeArguments(length, arguments) {}

 private:
  // Disallowing the superclass method.
  template <class S = Object>
  V8_INLINE Handle<S> at(int index) const;
};

#define RuntimeArguments RuntimeArgumentsWithoutHandles

// (End of TODO(13036)-related hackery.)

namespace {

template <typename FrameType>
class FrameFinder {
 public:
  explicit FrameFinder(Isolate* isolate,
                       std::initializer_list<StackFrame::Type>
                           skipped_frame_types = {StackFrame::EXIT})
      : frame_iterator_(isolate, isolate->thread_local_top(),
                        StackFrameIterator::FirstStackOnly{}) {
    // We skip at least one frame.
    DCHECK_LT(0, skipped_frame_types.size());

    for (auto type : skipped_frame_types) {
      DCHECK_EQ(type, frame_iterator_.frame()->type());
      USE(type);
      frame_iterator_.Advance();
    }
    // Type check the frame where the iterator stopped now.
    DCHECK_NOT_NULL(frame());
  }

  FrameType* frame() { return FrameType::cast(frame_iterator_.frame()); }

 private:
  StackFrameIterator frame_iterator_;
};

Tagged<WasmTrustedInstanceData> GetWasmInstanceDataOnStackTop(
    Isolate* isolate) {
  Address fp = Isolate::c_entry_fp(isolate->thread_local_top());
  fp = Memory<Address>(fp + ExitFrameConstants::kCallerFPOffset);
#ifdef DEBUG
  intptr_t marker =
      Memory<intptr_t>(fp + CommonFrameConstants::kContextOrFrameTypeOffset);
  DCHECK(StackFrame::MarkerToType(marker) == StackFrame::WASM ||
         StackFrame::MarkerToType(marker) == StackFrame::WASM_SEGMENT_START);
#endif
  Tagged<Object> trusted_instance_data(
      Memory<Address>(fp + WasmFrameConstants::kWasmInstanceDataOffset));
  return Cast<WasmTrustedInstanceData>(trusted_instance_data);
}

Tagged<Context> GetNativeContextFromWasmInstanceOnStackTop(Isolate* isolate) {
  return GetWasmInstanceDataOnStackTop(isolate)->native_context();
}

// TODO(jkummerow): Merge this with {SaveAndClearThreadInWasmFlag} from
// runtime-utils.h.
class V8_NODISCARD ClearThreadInWasmScope {
 public:
  explicit ClearThreadInWasmScope(Isolate* isolate)
      : isolate_(isolate), is_thread_in_wasm_(trap_handler::IsThreadInWasm()) {
    // In some cases we call this from Wasm code inlined into JavaScript
    // so the flag might not be set.
    if (is_thread_in_wasm_) {
      trap_handler::ClearThreadInWasm();
    }

#if V8_ENABLE_DRUMBRAKE
    if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms &&
        !v8_flags.wasm_jitless) {
      isolate->wasm_execution_timer()->Stop();
    }
#endif  // V8_ENABLE_DRUMBRAKE
  }
  ~ClearThreadInWasmScope() {
    DCHECK_IMPLIES(trap_handler::IsTrapHandlerEnabled(),
                   !trap_handler::IsThreadInWasm());
    if (!isolate_->has_exception() && is_thread_in_wasm_) {
      trap_handler::SetThreadInWasm();

#if V8_ENABLE_DRUMBRAKE
      if (v8_flags.wasm_enable_exec_time_histograms &&
          v8_flags.slow_histograms && !v8_flags.wasm_jitless) {
        isolate_->wasm_execution_timer()->Start();
      }
#endif  // V8_ENABLE_DRUMBRAKE
    }
    // Otherwise we only want to set the flag if the exception is caught in
    // wasm. This is handled by the unwinder.
  }

 private:
  Isolate* isolate_;
  const bool is_thread_in_wasm_;
};

Tagged<Object> ThrowWasmError(
    Isolate* isolate, MessageTemplate message,
    std::initializer_list<DirectHandle<Object>> args = {}) {
#if V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    // Store the trap reason to be retrieved later when the interpreter will
    // trap while detecting the thrown exception.
    wasm::WasmInterpreterThread::SetRuntimeLastWasmError(isolate, message);
  }
#endif  // V8_ENABLE_DRUMBRAKE

  Handle<JSObject> error_obj =
      isolate->factory()->NewWasmRuntimeError(message, base::VectorOf(args));
  JSObject::AddProperty(isolate, error_obj,
                        isolate->factory()->wasm_uncatchable_symbol(),
                        isolate->factory()->true_value(), NONE);
  return isolate->Throw(*error_obj);
}
}  // namespace

RUNTIME_FUNCTION(Runtime_WasmGenericWasmToJSObject) {
  SealHandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Tagged<Object> value = args[0];
  if (IsWasmFuncRef(value)) {
    Tagged<WasmInternalFunction> internal =
        Cast<WasmFuncRef>(value)->internal(isolate);
    Tagged<JSFunction> external;
    if (internal->try_get_external(&external)) return external;
    // Slow path:
    HandleScope scope(isolate);
    return *WasmInternalFunction::GetOrCreateExternal(
        handle(internal, isolate));
  }
  if (IsWasmNull(value)) return ReadOnlyRoots(isolate).null_value();
  return value;
}

// Takes a JS object and a wasm type as Smi. Type checks the object against the
// type; if the check succeeds, returns the object in its wasm representation;
// otherwise throws a type error.
RUNTIME_FUNCTION(Runtime_WasmGenericJSToWasmObject) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<Object> value(args[1], isolate);
  // Make sure CanonicalValueType fits properly in a Smi.
  static_assert(wasm::CanonicalValueType::kLastUsedBit + 1 <= kSmiValueSize);
  int raw_type = args.smi_value_at(2);

  wasm::CanonicalValueType type =
      wasm::CanonicalValueType::FromRawBitField(raw_type);
  const char* error_message;
  Handle<Object> result;
  if (!JSToWasmObject(isolate, value, type, &error_message).ToHandle(&result)) {
    return isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kWasmTrapJSTypeError));
  }
  return *result;
}

// Parameters:
// args[0]: the object, any JS value.
// args[1]: the expected canonicalized ValueType, Smi-tagged.
// Type checks the object against the type; if the check succeeds, returns the
// object in its wasm representation; otherwise throws a type error.
RUNTIME_FUNCTION(Runtime_WasmJSToWasmObject) {
  SaveAndClearThreadInWasmFlag non_wasm_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<Object> value(args[0], isolate);
  // Make sure ValueType fits properly in a Smi.
  static_assert(wasm::CanonicalValueType::kLastUsedBit + 1 <= kSmiValueSize);
  int raw_type = args.smi_value_at(1);

  wasm::CanonicalValueType expected =
      wasm::CanonicalValueType::FromRawBitField(raw_type);
  const char* error_message;
  Handle<Object> result;
  bool success = JSToWasmObject(isolate, value, expected, &error_message)
                     .ToHandle(&result);
  Tagged<Object> ret = success
                           ? *result
                           : isolate->Throw(*isolate->factory()->NewTypeError(
                                 MessageTemplate::kWasmTrapJSTypeError));
  return ret;
}

RUNTIME_FUNCTION(Runtime_WasmMemoryGrow) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  // {memory_index} and {delta_pages} are checked to be positive Smis in the
  // WasmMemoryGrow builtin which calls this runtime function.
  uint32_t memory_index = args.positive_smi_value_at(1);
  uint32_t delta_pages = args.positive_smi_value_at(2);

  Handle<WasmMemoryObject> memory_object{
      trusted_instance_data->memory_object(memory_index), isolate};
  int ret = WasmMemoryObject::Grow(isolate, memory_object, delta_pages);
  // The WasmMemoryGrow builtin which calls this runtime function expects us to
  // always return a Smi.
  DCHECK(!isolate->has_exception());
  return Smi::FromInt(ret);
}

RUNTIME_FUNCTION(Runtime_TrapHandlerThrowWasmError) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  std::vector<FrameSummary> summary;
  FrameFinder<WasmFrame> frame_finder(isolate, {StackFrame::EXIT});
  WasmFrame* frame = frame_finder.frame();
  // TODO(ahaas): We cannot use frame->position() here because for inlined
  // function it does not return the correct source position. We should remove
  // frame->position() to avoid problems in the future.
  frame->Summarize(&summary);
  DCHECK(summary.back().IsWasm());
  int pos = summary.back().AsWasm().SourcePosition();

  wasm::WasmCodeRefScope code_ref_scope;
  auto wire_bytes = frame->wasm_code()->native_module()->wire_bytes();
  wasm::WasmOpcode op = static_cast<wasm::WasmOpcode>(wire_bytes.at(pos));
  MessageTemplate message = MessageTemplate::kWasmTrapMemOutOfBounds;
  if (op == wasm::kGCPrefix || op == wasm::kExprRefAsNonNull ||
      op == wasm::kExprCallRef || op == wasm::kExprReturnCallRef ||
      // Calling imported string function with null can trigger a signal.
      op == wasm::kExprCallFunction || op == wasm::kExprReturnCall) {
    message = MessageTemplate::kWasmTrapNullDereference;
#if DEBUG
  } else {
    if (wasm::WasmOpcodes::IsPrefixOpcode(op)) {
      op = wasm::Decoder{wire_bytes}
               .read_prefixed_opcode<wasm::Decoder::NoValidationTag>(
                   &wire_bytes.begin()[pos])
               .first;
    }
#endif  // DEBUG
  }
  return ThrowWasmError(isolate, message);
}

RUNTIME_FUNCTION(Runtime_ThrowWasmError) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  int message_id = args.smi_value_at(0);
  return ThrowWasmError(isolate, MessageTemplateFromInt(message_id));
}

RUNTIME_FUNCTION(Runtime_ThrowWasmStackOverflow) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  SealHandleScope shs(isolate);
  DCHECK_LE(0, args.length());
  return isolate->StackOverflow();
}

RUNTIME_FUNCTION(Runtime_WasmThrowJSTypeError) {
  // The caller may be wasm or JS. Only clear the thread_in_wasm flag if the
  // caller is wasm, and let the unwinder set it back depending on the handler.
  if (trap_handler::IsTrapHandlerEnabled() && trap_handler::IsThreadInWasm()) {
#if V8_ENABLE_DRUMBRAKE
    // Transitioning from Wasm To JS.
    if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms &&
        !v8_flags.wasm_jitless) {
      // Stop measuring the time spent running jitted Wasm.
      isolate->wasm_execution_timer()->Stop();
    }
#endif  // V8_ENABLE_DRUMBRAKE

    trap_handler::ClearThreadInWasm();
  }
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kWasmTrapJSTypeError));
}

// This error is thrown from a wasm-to-JS wrapper, so unlike
// Runtime_ThrowWasmError, this function does not check or unset the
// thread-in-wasm flag.
RUNTIME_FUNCTION(Runtime_ThrowBadSuspenderError) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  return ThrowWasmError(isolate, MessageTemplate::kWasmTrapBadSuspender);
}

RUNTIME_FUNCTION(Runtime_WasmThrowRangeError) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  MessageTemplate message_id = MessageTemplateFromInt(args.smi_value_at(0));
  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewRangeError(message_id));
}

RUNTIME_FUNCTION(Runtime_WasmThrowDataViewTypeError) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  MessageTemplate message_id = MessageTemplateFromInt(args.smi_value_at(0));
  DataViewOp op = static_cast<DataViewOp>(isolate->error_message_param());
  Handle<String> op_name =
      isolate->factory()->NewStringFromAsciiChecked(ToString(op));
  Handle<Object> value(args[1], isolate);

  THROW_NEW_ERROR_RETURN_FAILURE(isolate,
                                 NewTypeError(message_id, op_name, value));
}

RUNTIME_FUNCTION(Runtime_WasmThrowDataViewDetachedError) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  MessageTemplate message_id = MessageTemplateFromInt(args.smi_value_at(0));
  DataViewOp op = static_cast<DataViewOp>(isolate->error_message_param());
  Handle<String> op_name =
      isolate->factory()->NewStringFromAsciiChecked(ToString(op));

  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(message_id, op_name));
}

RUNTIME_FUNCTION(Runtime_WasmThrowTypeError) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  MessageTemplate message_id = MessageTemplateFromInt(args.smi_value_at(0));
  Handle<Object> arg(args[1], isolate);
  if (IsSmi(*arg)) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(message_id));
  } else {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(message_id, arg));
  }
}

RUNTIME_FUNCTION(Runtime_WasmThrow) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Tagged<Context> context = GetNativeContextFromWasmInstanceOnStackTop(isolate);
  isolate->set_context(context);
  DirectHandle<WasmExceptionTag> tag(Cast<WasmExceptionTag>(args[0]), isolate);
  DirectHandle<FixedArray> values(Cast<FixedArray>(args[1]), isolate);
  auto js_tag = Cast<WasmTagObject>(context->wasm_js_tag());
  if (*tag == js_tag->tag()) {
    return isolate->Throw(values->get(0));
  } else {
    DirectHandle<WasmExceptionPackage> exception =
        WasmExceptionPackage::New(isolate, tag, values);
    return isolate->Throw(*exception);
  }
}

RUNTIME_FUNCTION(Runtime_WasmReThrow) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  return isolate->ReThrow(args[0]);
}

RUNTIME_FUNCTION(Runtime_WasmStackGuard) {
  ClearThreadInWasmScope wasm_flag(isolate);
  SealHandleScope shs(isolate);
  DCHECK_EQ(1, args.length());

  uint32_t gap = args.positive_smi_value_at(0);

  // Check if this is a real stack overflow.
  StackLimitCheck check(isolate);
  if (check.WasmHasOverflowed(gap)) return isolate->StackOverflow();

  return isolate->stack_guard()->HandleInterrupts(
      StackGuard::InterruptLevel::kAnyEffect);
}

RUNTIME_FUNCTION(Runtime_WasmCompileLazy) {
  ClearThreadInWasmScope wasm_flag(isolate);
  DCHECK_EQ(2, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  int func_index = args.smi_value_at(1);

  TRACE_EVENT1("v8.wasm", "wasm.CompileLazy", "func_index", func_index);
  DisallowHeapAllocation no_gc;
  SealHandleScope scope(isolate);

  DCHECK(isolate->context().is_null());
  isolate->set_context(trusted_instance_data->native_context());
  bool success = wasm::CompileLazy(isolate, trusted_instance_data, func_index);
  if (!success) {
    DCHECK(v8_flags.wasm_lazy_validation);
    AllowHeapAllocation throwing_unwinds_the_stack;
    wasm::ThrowLazyCompilationError(
        isolate, trusted_instance_data->native_module(), func_index);
    DCHECK(isolate->has_exception());
    return ReadOnlyRoots{isolate}.exception();
  }

  return Smi::FromInt(
      wasm::JumpTableOffset(trusted_instance_data->module(), func_index));
}

namespace {
Tagged<FixedArray> AllocateFeedbackVector(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int declared_func_index) {
  DCHECK(isolate->context().is_null());
  isolate->set_context(trusted_instance_data->native_context());
  const wasm::WasmModule* module =
      trusted_instance_data->native_module()->module();

  int func_index = declared_func_index + module->num_imported_functions;
  int num_slots = NumFeedbackSlots(module, func_index);
  DirectHandle<FixedArray> vector =
      isolate->factory()->NewFixedArrayWithZeroes(num_slots);
  DCHECK_EQ(trusted_instance_data->feedback_vectors()->get(declared_func_index),
            Smi::zero());
  trusted_instance_data->feedback_vectors()->set(declared_func_index, *vector);
  isolate->set_context(Tagged<Context>());
  return *vector;
}
}  // namespace

RUNTIME_FUNCTION(Runtime_WasmAllocateFeedbackVector) {
  ClearThreadInWasmScope wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  DCHECK(v8_flags.wasm_inlining);
  DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  int declared_func_index = args.smi_value_at(1);
  wasm::NativeModule** native_module_stack_slot =
      reinterpret_cast<wasm::NativeModule**>(args.address_of_arg_at(2));
  wasm::NativeModule* native_module = trusted_instance_data->native_module();
  // We have to save the native_module on the stack, in case the allocation
  // triggers a GC and we need the module to scan LiftoffSetupFrame stack frame.
  *native_module_stack_slot = native_module;
  return AllocateFeedbackVector(isolate, trusted_instance_data,
                                declared_func_index);
}

RUNTIME_FUNCTION(Runtime_WasmLiftoffDeoptFinish) {
  ClearThreadInWasmScope wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  // Destroy the Deoptimizer object stored on the isolate.
  size_t deopt_frame_count = Deoptimizer::DeleteForWasm(isolate);
  size_t i = 0;

  // For each liftoff frame, check if the feedback vector is already present.
  // If it is not, allocate a new feedback vector for it.
  for (StackFrameIterator it(isolate); !it.done(); it.Advance()) {
    StackFrame* frame = it.frame();
    if (frame->is_wasm() && WasmFrame::cast(frame)->wasm_code()->is_liftoff()) {
      Address vector_address =
          frame->fp() - WasmLiftoffFrameConstants::kFeedbackVectorOffset;
      Tagged<Object> vector_or_smi(Memory<intptr_t>(vector_address));
      if (vector_or_smi.IsSmi()) {
        int declared_func_index = Cast<Smi>(vector_or_smi).value();
        Tagged<Object> vector =
            trusted_instance_data->feedback_vectors()->get(declared_func_index);
        // The vector can already exist if the same function appears multiple
        // times in the deopted frames (i.e. it was inlined recursively).
        if (vector == Smi::zero()) {
          vector = AllocateFeedbackVector(isolate, trusted_instance_data,
                                          declared_func_index);
        }
        memcpy(reinterpret_cast<void*>(vector_address), &vector,
               sizeof(intptr_t));
      }
      if (++i == deopt_frame_count) {
        break;  // All deopt frames have been visited.
      }
    }
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {
void ReplaceJSToWasmWrapper(
    Isolate* isolate, Tagged<WasmTrustedInstanceData> trusted_instance_data,
    int function_index, Tagged<Code> wrapper_code) {
  Tagged<WasmFuncRef> func_ref;
  // Always expect a func_ref. If this fails, we are maybe compiling a wrapper
  // for the start function. This function is only called once, so this should
  // not happen.
  CHECK(trusted_instance_data->try_get_func_ref(function_index, &func_ref));
  Tagged<JSFunction> external_function;
  CHECK(func_ref->internal(isolate)->try_get_external(&external_function));
  if (external_function->shared()->HasWasmJSFunctionData()) return;
  CHECK(external_function->shared()->HasWasmExportedFunctionData());
  external_function->UpdateCode(wrapper_code);
  Tagged<WasmExportedFunctionData> function_data =
      external_function->shared()->wasm_exported_function_data();
  function_data->set_wrapper_code(wrapper_code);
}
}  // namespace

RUNTIME_FUNCTION(Runtime_TierUpJSToWasmWrapper) {
  DCHECK_EQ(1, args.length());

  // Avoid allocating a HandleScope and handles on the fast path.
  Tagged<WasmExportedFunctionData> function_data =
      Cast<WasmExportedFunctionData>(args[0]);
  Tagged<WasmTrustedInstanceData> trusted_data = function_data->instance_data();

  const wasm::WasmModule* module = trusted_data->module();
  const int function_index = function_data->function_index();
  const wasm::WasmFunction& function = module->functions[function_index];
  const wasm::CanonicalTypeIndex sig_id =
      module->canonical_sig_id(function.sig_index);
  const wasm::CanonicalSig* sig =
      wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_id);

  Tagged<MaybeObject> maybe_cached_wrapper =
      isolate->heap()->js_to_wasm_wrappers()->get(sig_id.index);
  Tagged<Code> wrapper_code;
  DCHECK(maybe_cached_wrapper.IsWeakOrCleared());
  if (!maybe_cached_wrapper.IsCleared()) {
    wrapper_code =
        Cast<CodeWrapper>(maybe_cached_wrapper.GetHeapObjectAssumeWeak())
            ->code(isolate);
  } else {
    // Set the context on the isolate and open a handle scope for allocation of
    // new objects. Wrap {trusted_data} in a handle so it survives GCs.
    DCHECK(isolate->context().is_null());
    isolate->set_context(trusted_data->native_context());
    HandleScope scope(isolate);
    Handle<WasmTrustedInstanceData> trusted_data_handle{trusted_data, isolate};
    DirectHandle<Code> new_wrapper_code =
        wasm::JSToWasmWrapperCompilationUnit::CompileJSToWasmWrapper(
            isolate, sig, sig_id);

    // Compilation must have installed the wrapper into the cache.
    DCHECK_EQ(MakeWeak(new_wrapper_code->wrapper()),
              isolate->heap()->js_to_wasm_wrappers()->get(sig_id.index));

    // Reset raw pointers still needed outside the slow path.
    wrapper_code = *new_wrapper_code;
    trusted_data = *trusted_data_handle;
    function_data = {};
  }

  // Replace the wrapper for the function that triggered the tier-up.
  // This is to ensure that the wrapper is replaced, even if the function
  // is implicitly exported and is not part of the export_table.
  ReplaceJSToWasmWrapper(isolate, trusted_data, function_index, wrapper_code);

  // Iterate over all exports to replace eagerly the wrapper for all functions
  // that share the signature of the function that tiered up.
  for (wasm::WasmExport exp : module->export_table) {
    if (exp.kind != wasm::kExternalFunction) continue;
    int index = static_cast<int>(exp.index);
    if (index == function_index) continue;  // Already replaced.
    const wasm::WasmFunction& exp_function = module->functions[index];
    if (module->canonical_sig_id(exp_function.sig_index) != sig_id) {
      continue;  // Different signature.
    }
    ReplaceJSToWasmWrapper(isolate, trusted_data, index, wrapper_code);
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_IsWasmExternalFunction) {
  DCHECK_EQ(1, args.length());
  return isolate->heap()->ToBoolean(
      WasmExternalFunction::IsWasmExternalFunction(args[0]));
}

RUNTIME_FUNCTION(Runtime_TierUpWasmToJSWrapper) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<WasmImportData> import_data(Cast<WasmImportData>(args[0]),
                                           isolate);

  DCHECK(isolate->context().is_null());
  isolate->set_context(import_data->native_context());

  const wasm::CanonicalSig* sig = import_data->sig();
  DirectHandle<Object> origin(import_data->call_origin(), isolate);
  wasm::WasmCodeRefScope code_ref_scope;

  if (IsWasmFuncRef(*origin)) {
    // The tierup for `WasmFuncRef` is special, as there may not be an instance.
    size_t expected_arity = sig->parameter_count();
    wasm::ImportCallKind kind;
    if (IsJSFunction(import_data->callable())) {
      Tagged<SharedFunctionInfo> shared =
          Cast<JSFunction>(import_data->callable())->shared();
      expected_arity =
          shared->internal_formal_parameter_count_without_receiver();
      if (expected_arity == sig->parameter_count()) {
        kind = wasm::ImportCallKind::kJSFunctionArityMatch;
      } else {
        kind = wasm::ImportCallKind::kJSFunctionArityMismatch;
      }
    } else {
      kind = wasm::ImportCallKind::kUseCallBuiltin;
    }
    wasm::WasmImportWrapperCache* cache = wasm::GetWasmImportWrapperCache();
    wasm::CanonicalTypeIndex canonical_sig_index =
        wasm::GetTypeCanonicalizer()->FindIndex_Slow(sig);
    int arity = static_cast<int>(expected_arity);
    wasm::Suspend suspend = static_cast<wasm::Suspend>(import_data->suspend());
    wasm::WasmCode* wrapper =
        cache->MaybeGet(kind, canonical_sig_index, arity, suspend);
    bool source_positions = false;
    if (!wrapper) {
      wrapper = cache->CompileWasmImportCallWrapper(
          isolate, kind, sig, canonical_sig_index, source_positions, arity,
          suspend);
    }
    Tagged<WasmInternalFunction> internal =
        Cast<WasmFuncRef>(origin)->internal(isolate);
    internal->set_call_target(wrapper->code_pointer());

    Tagged<JSFunction> existing_external;
    Tagged<WasmTrustedInstanceData> instance_data;
    if (internal->try_get_external(&existing_external)) {
      Tagged<Object> func_data = existing_external->shared()->GetTrustedData();
      // WasmJSFunctions set their external function at creation.
      if (IsWasmJSFunctionData(func_data)) {
        Cast<WasmJSFunctionData>(func_data)->offheap_data()->set_wrapper(
            wrapper);
        return ReadOnlyRoots(isolate).undefined_value();
      }
      // Other functions could have had their external JSFunction created
      // lazily before.
      DCHECK(IsWasmExportedFunctionData(func_data));
      instance_data =
          Cast<WasmExportedFunctionData>(func_data)->instance_data();
      // Fall through.
    } else {
      // We're tiering up a WasmToJS wrapper, so the function must be an
      // imported JS function.
      DCHECK(IsWasmImportData(internal->implicit_arg()));
      instance_data =
          Cast<WasmImportData>(internal->implicit_arg())->instance_data();
    }
    // For imported JS functions, we don't really care about updating the call
    // target in the table, but we do need the table to manage the lifetime
    // of the wrapper we just compiled.
    Tagged<WasmDispatchTable> table =
        instance_data->dispatch_table_for_imports();
    table->InstallCompiledWrapper(internal->function_index(), wrapper);
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // The trusted data of the instance which originally imported the non-wasm
  // target.
  Handle<WasmTrustedInstanceData> defining_instance_data(
      import_data->instance_data(), isolate);
  Handle<WasmTrustedInstanceData> call_origin_instance_data =
      defining_instance_data;
  if (IsTuple2(*origin)) {
    auto tuple = Cast<Tuple2>(origin);
    // Note: This link is unsafe (via the untrusted WasmInstanceObject). We only
    // use it to find places to patch after tier-up, after additional checks.
    call_origin_instance_data =
        handle(Cast<WasmInstanceObject>(tuple->value1())->trusted_data(isolate),
               isolate);
    origin = direct_handle(tuple->value2(), isolate);
  }
  CHECK(IsSmi(*origin));
  Tagged<Smi> call_origin_index = Cast<Smi>(*origin);

  // Get the function's canonical signature index.
  // TODO(clemensb): Just get the sig_index based on WasmImportData::sig.
  wasm::CanonicalTypeIndex sig_index = wasm::CanonicalTypeIndex::Invalid();

  if (WasmImportData::CallOriginIsImportIndex(call_origin_index)) {
    int func_index = WasmImportData::CallOriginAsIndex(call_origin_index);
    const wasm::WasmModule* call_origin_module =
        call_origin_instance_data->module();
    sig_index = call_origin_module->canonical_sig_id(
        call_origin_module->functions[func_index].sig_index);
  } else {
    // Indirect function table index.
    int entry_index = WasmImportData::CallOriginAsIndex(call_origin_index);
    int table_count = call_origin_instance_data->dispatch_tables()->length();
    const wasm::WasmModule* call_origin_module =
        call_origin_instance_data->module();
    // We have to find the table which contains the correct entry.
    for (int table_index = 0; table_index < table_count; ++table_index) {
      bool table_is_shared = call_origin_module->tables[table_index].shared;
      DirectHandle<WasmTrustedInstanceData> maybe_shared_data =
          table_is_shared
              ? direct_handle(call_origin_instance_data->shared_part(), isolate)
              : call_origin_instance_data;
      if (!maybe_shared_data->has_dispatch_table(table_index)) continue;
      Tagged<WasmDispatchTable> table =
          maybe_shared_data->dispatch_table(table_index);
      if (entry_index < table->length() &&
          table->implicit_arg(entry_index) == *import_data) {
        sig_index = table->sig(entry_index);
        break;
      }
    }
  }
  // Do not trust the `Tuple2` stored in `call_origin`. If we failed to find the
  // signature, crash early.
  SBXCHECK(sig_index.valid());

  // Compile a wrapper for the target callable.
  Handle<JSReceiver> callable(Cast<JSReceiver>(import_data->callable()),
                              isolate);
  wasm::Suspend suspend = static_cast<wasm::Suspend>(import_data->suspend());

  wasm::ResolvedWasmImport resolved({}, -1, callable, sig, sig_index,
                                    wasm::WellKnownImport::kUninstantiated);
  wasm::ImportCallKind kind = resolved.kind();
  callable = resolved.callable();  // Update to ultimate target.
  DCHECK_NE(wasm::ImportCallKind::kLinkError, kind);
  // {expected_arity} should only be used if kind != kJSFunctionArityMismatch.
  int expected_arity = static_cast<int>(sig->parameter_count());
  if (kind == wasm::ImportCallKind ::kJSFunctionArityMismatch) {
    expected_arity = Cast<JSFunction>(callable)
                         ->shared()
                         ->internal_formal_parameter_count_without_receiver();
  }

  wasm::WasmImportWrapperCache* cache = wasm::GetWasmImportWrapperCache();
  wasm::WasmCode* wasm_code =
      cache->MaybeGet(kind, sig_index, expected_arity, suspend);
  if (!wasm_code) {
    wasm_code = cache->CompileWasmImportCallWrapper(
        isolate, kind, sig, sig_index, false, expected_arity, suspend);
  }
  // Note: we don't need to decrement any refcounts here, because tier-up
  // doesn't overwrite an existing compiled wrapper, and the generic wrapper
  // isn't refcounted.

  if (WasmImportData::CallOriginIsImportIndex(call_origin_index)) {
    int func_index = WasmImportData::CallOriginAsIndex(call_origin_index);
    call_origin_instance_data->dispatch_table_for_imports()
        ->InstallCompiledWrapper(func_index, wasm_code);
  } else {
    // Indirect function table index.
    int entry_index = WasmImportData::CallOriginAsIndex(call_origin_index);
    int table_count = call_origin_instance_data->dispatch_tables()->length();
    // We have to find the table which contains the correct entry.
    for (int table_index = 0; table_index < table_count; ++table_index) {
      if (!call_origin_instance_data->has_dispatch_table(table_index)) continue;
      Tagged<WasmDispatchTable> table =
          call_origin_instance_data->dispatch_table(table_index);
      if (entry_index < table->length() &&
          table->implicit_arg(entry_index) == *import_data) {
        table->InstallCompiledWrapper(entry_index, wasm_code);
        // {ref} is used in at most one table.
        break;
      }
    }
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTriggerTierUp) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  SealHandleScope shs(isolate);

  {
    DisallowGarbageCollection no_gc;
    DCHECK_EQ(1, args.length());
    Tagged<WasmTrustedInstanceData> trusted_data =
        Cast<WasmTrustedInstanceData>(args[0]);

    FrameFinder<WasmFrame> frame_finder(isolate);
    int func_index = frame_finder.frame()->function_index();
    DCHECK_EQ(trusted_data, frame_finder.frame()->trusted_instance_data());

    if (V8_UNLIKELY(v8_flags.wasm_sync_tier_up)) {
      if (!trusted_data->native_module()->HasCodeWithTier(
              func_index, wasm::ExecutionTier::kTurbofan)) {
        wasm::TierUpNowForTesting(isolate, trusted_data, func_index);
      }
      // We call this function when the tiering budget runs out, so reset that
      // budget to appropriately delay the next call.
      int array_index =
          wasm::declared_function_index(trusted_data->module(), func_index);
      trusted_data->tiering_budget_array()[array_index].store(
          v8_flags.wasm_tiering_budget, std::memory_order_relaxed);
    } else {
      wasm::TriggerTierUp(isolate, trusted_data, func_index);
    }
  }

  // We're reusing this interrupt mechanism to interrupt long-running loops.
  StackLimitCheck check(isolate);
  // We don't need to handle stack overflows here, because the function that
  // performed this runtime call did its own stack check at its beginning.
  // However, we can't DCHECK(!check.JsHasOverflowed()) here, because the
  // additional stack space used by the CEntryStub and this runtime function
  // itself might have pushed us above the limit where a stack check would
  // fail.
  if (check.InterruptRequested()) {
    // Note: This might trigger a GC, which invalidates the {args} object (see
    // https://crbug.com/v8/13036#2).
    Tagged<Object> result = isolate->stack_guard()->HandleInterrupts();
    if (IsException(result)) return result;
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmI32AtomicWait) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  int memory_index = args.smi_value_at(1);
  double offset_double = args.number_value_at(2);
  uintptr_t offset = static_cast<uintptr_t>(offset_double);
  int32_t expected_value = NumberToInt32(args[3]);
  Tagged<BigInt> timeout_ns = Cast<BigInt>(args[4]);

  Handle<JSArrayBuffer> array_buffer{
      trusted_instance_data->memory_object(memory_index)->array_buffer(),
      isolate};
  // Should have trapped if address was OOB.
  DCHECK_LT(offset, array_buffer->byte_length());

  // Trap if memory is not shared, or wait is not allowed on the isolate
  if (!array_buffer->is_shared() || !isolate->allow_atomics_wait()) {
    return ThrowWasmError(
        isolate, MessageTemplate::kAtomicsOperationNotAllowed,
        {isolate->factory()->NewStringFromAsciiChecked("Atomics.wait")});
  }
  return FutexEmulation::WaitWasm32(isolate, array_buffer, offset,
                                    expected_value, timeout_ns->AsInt64());
}

RUNTIME_FUNCTION(Runtime_WasmI64AtomicWait) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  int memory_index = args.smi_value_at(1);
  double offset_double = args.number_value_at(2);
  uintptr_t offset = static_cast<uintptr_t>(offset_double);
  Tagged<BigInt> expected_value = Cast<BigInt>(args[3]);
  Tagged<BigInt> timeout_ns = Cast<BigInt>(args[4]);

  Handle<JSArrayBuffer> array_buffer{
      trusted_instance_data->memory_object(memory_index)->array_buffer(),
      isolate};
  // Should have trapped if address was OOB.
  DCHECK_LT(offset, array_buffer->byte_length());

  // Trap if memory is not shared, or if wait is not allowed on the isolate
  if (!array_buffer->is_shared() || !isolate->allow_atomics_wait()) {
    return ThrowWasmError(
        isolate, MessageTemplate::kAtomicsOperationNotAllowed,
        {isolate->factory()->NewStringFromAsciiChecked("Atomics.wait")});
  }
  return FutexEmulation::WaitWasm64(isolate, array_buffer, offset,
                                    expected_value->AsInt64(),
                                    timeout_ns->AsInt64());
}

namespace {
Tagged<Object> ThrowTableOutOfBounds(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data) {
  // Handle out-of-bounds access here in the runtime call, rather
  // than having the lower-level layers deal with JS exceptions.
  if (isolate->context().is_null()) {
    isolate->set_context(trusted_instance_data->native_context());
  }
  return ThrowWasmError(isolate, MessageTemplate::kWasmTrapTableOutOfBounds);
}
}  // namespace

RUNTIME_FUNCTION(Runtime_WasmRefFunc) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t function_index = args.positive_smi_value_at(1);

  return *WasmTrustedInstanceData::GetOrCreateFuncRef(
      isolate, trusted_instance_data, function_index);
}

RUNTIME_FUNCTION(Runtime_WasmInternalFunctionCreateExternal) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  // TODO(14564): Pass WasmFuncRef here instead of WasmInternalFunction.
  DirectHandle<WasmInternalFunction> internal(
      Cast<WasmInternalFunction>(args[0]), isolate);
  return *WasmInternalFunction::GetOrCreateExternal(internal);
}

RUNTIME_FUNCTION(Runtime_WasmFunctionTableGet) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t table_index = args.positive_smi_value_at(1);
  uint32_t entry_index = args.positive_smi_value_at(2);
  DCHECK_LT(table_index, trusted_instance_data->tables()->length());
  auto table = handle(
      Cast<WasmTableObject>(trusted_instance_data->tables()->get(table_index)),
      isolate);
  // We only use the runtime call for lazily initialized function references.
  DCHECK(
      !table->has_trusted_data()
          ? table->type() == wasm::kWasmFuncRef
          : (IsSubtypeOf(table->type(), wasm::kWasmFuncRef,
                         table->trusted_data(isolate)->module()) ||
             IsSubtypeOf(table->type(),
                         wasm::ValueType::RefNull(wasm::HeapType::kFuncShared),
                         table->trusted_data(isolate)->module())));

  if (!table->is_in_bounds(entry_index)) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapTableOutOfBounds);
  }

  return *WasmTableObject::Get(isolate, table, entry_index);
}

RUNTIME_FUNCTION(Runtime_WasmFunctionTableSet) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t table_index = args.positive_smi_value_at(1);
  uint32_t entry_index = args.positive_smi_value_at(2);
  DirectHandle<Object> element(args[3], isolate);
  DCHECK_LT(table_index, trusted_instance_data->tables()->length());
  auto table = handle(
      Cast<WasmTableObject>(trusted_instance_data->tables()->get(table_index)),
      isolate);
  // We only use the runtime call for lazily initialized function references.
  DCHECK(
      !table->has_trusted_data()
          ? table->type() == wasm::kWasmFuncRef
          : (IsSubtypeOf(table->type(), wasm::kWasmFuncRef,
                         table->trusted_data(isolate)->module()) ||
             IsSubtypeOf(table->type(),
                         wasm::ValueType::RefNull(wasm::HeapType::kFuncShared),
                         table->trusted_data(isolate)->module())));

  if (!table->is_in_bounds(entry_index)) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapTableOutOfBounds);
  }
  WasmTableObject::Set(isolate, table, entry_index, element);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTableInit) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());
  Handle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t table_index = args.positive_smi_value_at(1);
  uint32_t elem_segment_index = args.positive_smi_value_at(2);
  static_assert(
      wasm::kV8MaxWasmTableSize < kSmiMaxValue,
      "Make sure clamping to Smi range doesn't make an invalid call valid");
  uint32_t dst = args.positive_smi_value_at(3);
  uint32_t src = args.positive_smi_value_at(4);
  uint32_t count = args.positive_smi_value_at(5);

  DCHECK(!isolate->context().is_null());

  // TODO(14616): Pass the correct instance data.
  std::optional<MessageTemplate> opt_error =
      WasmTrustedInstanceData::InitTableEntries(
          isolate, trusted_instance_data, trusted_instance_data, table_index,
          elem_segment_index, dst, src, count);
  if (opt_error.has_value()) {
    return ThrowWasmError(isolate, opt_error.value());
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTableCopy) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());
  DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t table_dst_index = args.positive_smi_value_at(1);
  uint32_t table_src_index = args.positive_smi_value_at(2);
  static_assert(
      wasm::kV8MaxWasmTableSize < kSmiMaxValue,
      "Make sure clamping to Smi range doesn't make an invalid call valid");
  uint32_t dst = args.positive_smi_value_at(3);
  uint32_t src = args.positive_smi_value_at(4);
  uint32_t count = args.positive_smi_value_at(5);

  DCHECK(!isolate->context().is_null());

  bool oob = !WasmTrustedInstanceData::CopyTableEntries(
      isolate, trusted_instance_data, table_dst_index, table_src_index, dst,
      src, count);
  if (oob) return ThrowTableOutOfBounds(isolate, trusted_instance_data);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTableGrow) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK(isolate->IsOnCentralStack());
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t table_index = args.positive_smi_value_at(1);
  DirectHandle<Object> value(args[2], isolate);
  uint32_t delta = args.positive_smi_value_at(3);

  DirectHandle<WasmTableObject> table(
      Cast<WasmTableObject>(trusted_instance_data->tables()->get(table_index)),
      isolate);
  int result = WasmTableObject::Grow(isolate, table, delta, value);

  return Smi::FromInt(result);
}

RUNTIME_FUNCTION(Runtime_WasmTableFill) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t table_index = args.positive_smi_value_at(1);
  uint32_t start = args.positive_smi_value_at(2);
  DirectHandle<Object> value(args[3], isolate);
  uint32_t count = args.positive_smi_value_at(4);

  DirectHandle<WasmTableObject> table(
      Cast<WasmTableObject>(trusted_instance_data->tables()->get(table_index)),
      isolate);

  uint32_t table_size = table->current_length();

  if (start > table_size) {
    return ThrowTableOutOfBounds(isolate, trusted_instance_data);
  }

  // Even when table.fill goes out-of-bounds, as many entries as possible are
  // put into the table. Only afterwards we trap.
  uint32_t fill_count = std::min(count, table_size - start);
  if (fill_count < count) {
    return ThrowTableOutOfBounds(isolate, trusted_instance_data);
  }
  WasmTableObject::Fill(isolate, table, start, value, fill_count);

  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {
// Returns true if any breakpoint was hit, false otherwise.
bool ExecuteWasmDebugBreaks(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    WasmFrame* frame) {
  DirectHandle<Script> script{trusted_instance_data->module_object()->script(),
                              isolate};
  auto* debug_info = trusted_instance_data->native_module()->GetDebugInfo();

  // Enter the debugger.
  DebugScope debug_scope(isolate->debug());

  // Check for instrumentation breakpoints first, but still execute regular
  // breakpoints afterwards.
  bool paused_on_instrumentation = false;
  DCHECK_EQ(script->break_on_entry(),
            !!trusted_instance_data->break_on_entry());
  if (script->break_on_entry()) {
    MaybeHandle<FixedArray> maybe_on_entry_breakpoints =
        WasmScript::CheckBreakPoints(isolate, script,
                                     WasmScript::kOnEntryBreakpointPosition,
                                     frame->id());
    script->set_break_on_entry(false);
    // Update the "break_on_entry" flag on all live instances.
    i::Tagged<i::WeakArrayList> weak_instance_list =
        script->wasm_weak_instance_list();
    for (int i = 0; i < weak_instance_list->length(); ++i) {
      if (weak_instance_list->Get(i).IsCleared()) continue;
      i::Cast<i::WasmInstanceObject>(weak_instance_list->Get(i).GetHeapObject())
          ->trusted_data(isolate)
          ->set_break_on_entry(false);
    }
    DCHECK(!trusted_instance_data->break_on_entry());
    if (!maybe_on_entry_breakpoints.is_null()) {
      isolate->debug()->OnInstrumentationBreak();
      paused_on_instrumentation = true;
    }
  }

  if (debug_info->IsStepping(frame) && !debug_info->IsFrameBlackboxed(frame)) {
    debug_info->ClearStepping(isolate);
    StepAction step_action = isolate->debug()->last_step_action();
    isolate->debug()->ClearStepping();
    isolate->debug()->OnDebugBreak(isolate->factory()->empty_fixed_array(),
                                   step_action);
    return true;
  }

  // Check whether we hit a breakpoint.
  Handle<FixedArray> breakpoints;
  if (WasmScript::CheckBreakPoints(isolate, script, frame->position(),
                                   frame->id())
          .ToHandle(&breakpoints)) {
    debug_info->ClearStepping(isolate);
    StepAction step_action = isolate->debug()->last_step_action();
    isolate->debug()->ClearStepping();
    if (isolate->debug()->break_points_active()) {
      // We hit one or several breakpoints. Notify the debug listeners.
      isolate->debug()->OnDebugBreak(breakpoints, step_action);
    }
    return true;
  }

  return paused_on_instrumentation;
}
}  // namespace

RUNTIME_FUNCTION(Runtime_WasmDebugBreak) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  FrameFinder<WasmFrame> frame_finder(
      isolate, {StackFrame::EXIT, StackFrame::WASM_DEBUG_BREAK});
  WasmFrame* frame = frame_finder.frame();
  DirectHandle<WasmTrustedInstanceData> trusted_data{
      frame->trusted_instance_data(), isolate};
  isolate->set_context(trusted_data->native_context());

  if (!ExecuteWasmDebugBreaks(isolate, trusted_data, frame)) {
    // We did not hit a breakpoint. If we are in stepping code, but the user did
    // not request stepping, clear this (to save further calls into this runtime
    // function).
    auto* debug_info = trusted_data->native_module()->GetDebugInfo();
    debug_info->ClearStepping(frame);
  }

  // Execute a stack check before leaving this function. This is to handle any
  // interrupts set by the debugger (e.g. termination), but also to execute Wasm
  // code GC to get rid of temporarily created Wasm code.
  StackLimitCheck check(isolate);
  if (check.InterruptRequested()) {
    Tagged<Object> interrupt_object =
        isolate->stack_guard()->HandleInterrupts();
    // Interrupt handling can create an exception, including the
    // termination exception.
    if (IsException(interrupt_object, isolate)) return interrupt_object;
    DCHECK(IsUndefined(interrupt_object, isolate));
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

// Assumes copy ranges are in-bounds and copy length > 0.
// TODO(manoskouk): Unify part of this with the implementation in
// wasm-extern-refs.cc
RUNTIME_FUNCTION(Runtime_WasmArrayCopy) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  DCHECK_EQ(5, args.length());
  Tagged<WasmArray> dst_array = Cast<WasmArray>(args[0]);
  uint32_t dst_index = args.positive_smi_value_at(1);
  Tagged<WasmArray> src_array = Cast<WasmArray>(args[2]);
  uint32_t src_index = args.positive_smi_value_at(3);
  uint32_t length = args.positive_smi_value_at(4);
  DCHECK_GT(length, 0);
  bool overlapping_ranges =
      dst_array.ptr() == src_array.ptr() &&
      (dst_index < src_index ? dst_index + length > src_index
                             : src_index + length > dst_index);
  wasm::ValueType element_type = src_array->type()->element_type();
  if (element_type.is_reference()) {
    ObjectSlot dst_slot = dst_array->ElementSlot(dst_index);
    ObjectSlot src_slot = src_array->ElementSlot(src_index);
    if (overlapping_ranges) {
      isolate->heap()->MoveRange(dst_array, dst_slot, src_slot, length,
                                 UPDATE_WRITE_BARRIER);
    } else {
      isolate->heap()->CopyRange(dst_array, dst_slot, src_slot, length,
                                 UPDATE_WRITE_BARRIER);
    }
  } else {
    void* dst = reinterpret_cast<void*>(dst_array->ElementAddress(dst_index));
    void* src = reinterpret_cast<void*>(src_array->ElementAddress(src_index));
    size_t copy_size = length * element_type.value_kind_size();
    if (overlapping_ranges) {
      MemMove(dst, src, copy_size);
    } else {
      MemCopy(dst, src, copy_size);
    }
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmArrayNewSegment) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  Handle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t segment_index = args.positive_smi_value_at(1);
  uint32_t offset = args.positive_smi_value_at(2);
  uint32_t length = args.positive_smi_value_at(3);
  DirectHandle<Map> rtt(Cast<Map>(args[4]), isolate);

  wasm::ArrayType* type =
      reinterpret_cast<wasm::ArrayType*>(rtt->wasm_type_info()->native_type());

  uint32_t element_size = type->element_type().value_kind_size();
  // This check also implies no overflow.
  if (length > static_cast<uint32_t>(WasmArray::MaxLength(element_size))) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapArrayTooLarge);
  }

  if (type->element_type().is_numeric()) {
    // No chance of overflow due to the check above.
    uint32_t length_in_bytes = length * element_size;

    if (!base::IsInBounds<uint32_t>(
            offset, length_in_bytes,
            trusted_instance_data->data_segment_sizes()->get(segment_index))) {
      return ThrowWasmError(isolate,
                            MessageTemplate::kWasmTrapDataSegmentOutOfBounds);
    }

    Address source =
        trusted_instance_data->data_segment_starts()->get(segment_index) +
        offset;
    return *isolate->factory()->NewWasmArrayFromMemory(length, rtt, source);
  } else {
    Handle<Object> elem_segment_raw = handle(
        trusted_instance_data->element_segments()->get(segment_index), isolate);
    const wasm::WasmElemSegment* module_elem_segment =
        &trusted_instance_data->module()->elem_segments[segment_index];
    // If the segment is initialized in the instance, we have to get its length
    // from there, as it might have been dropped. If the segment is
    // uninitialized, we need to fetch its length from the module.
    int segment_length = IsFixedArray(*elem_segment_raw)
                             ? Cast<FixedArray>(elem_segment_raw)->length()
                             : module_elem_segment->element_count;
    if (!base::IsInBounds<size_t>(offset, length, segment_length)) {
      return ThrowWasmError(
          isolate, MessageTemplate::kWasmTrapElementSegmentOutOfBounds);
    }
    // TODO(14616): Pass the correct instance data.
    DirectHandle<Object> result =
        isolate->factory()->NewWasmArrayFromElementSegment(
            trusted_instance_data, trusted_instance_data, segment_index, offset,
            length, rtt);
    if (IsSmi(*result)) {
      return ThrowWasmError(
          isolate, static_cast<MessageTemplate>(Cast<Smi>(*result).value()));
    } else {
      return *result;
    }
  }
}

RUNTIME_FUNCTION(Runtime_WasmArrayInitSegment) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());
  Handle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t segment_index = args.positive_smi_value_at(1);
  DirectHandle<WasmArray> array(Cast<WasmArray>(args[2]), isolate);
  uint32_t array_index = args.positive_smi_value_at(3);
  uint32_t segment_offset = args.positive_smi_value_at(4);
  uint32_t length = args.positive_smi_value_at(5);

  wasm::ArrayType* type = reinterpret_cast<wasm::ArrayType*>(
      array->map()->wasm_type_info()->native_type());

  uint32_t element_size = type->element_type().value_kind_size();

  if (type->element_type().is_numeric()) {
    if (!base::IsInBounds<uint32_t>(array_index, length, array->length())) {
      return ThrowWasmError(isolate,
                            MessageTemplate::kWasmTrapArrayOutOfBounds);
    }

    // No chance of overflow, due to the check above and the limit in array
    // length.
    uint32_t length_in_bytes = length * element_size;

    if (!base::IsInBounds<uint32_t>(
            segment_offset, length_in_bytes,
            trusted_instance_data->data_segment_sizes()->get(segment_index))) {
      return ThrowWasmError(isolate,
                            MessageTemplate::kWasmTrapDataSegmentOutOfBounds);
    }

    Address source =
        trusted_instance_data->data_segment_starts()->get(segment_index) +
        segment_offset;
    Address dest = array->ElementAddress(array_index);
#if V8_TARGET_BIG_ENDIAN
    MemCopyAndSwitchEndianness(reinterpret_cast<void*>(dest),
                               reinterpret_cast<void*>(source), length,
                               element_size);
#else
    MemCopy(reinterpret_cast<void*>(dest), reinterpret_cast<void*>(source),
            length_in_bytes);
#endif
    return *isolate->factory()->undefined_value();
  } else {
    Handle<Object> elem_segment_raw = handle(
        trusted_instance_data->element_segments()->get(segment_index), isolate);
    const wasm::WasmElemSegment* module_elem_segment =
        &trusted_instance_data->module()->elem_segments[segment_index];
    // If the segment is initialized in the instance, we have to get its length
    // from there, as it might have been dropped. If the segment is
    // uninitialized, we need to fetch its length from the module.
    int segment_length = IsFixedArray(*elem_segment_raw)
                             ? Cast<FixedArray>(elem_segment_raw)->length()
                             : module_elem_segment->element_count;
    if (!base::IsInBounds<size_t>(segment_offset, length, segment_length)) {
      return ThrowWasmError(
          isolate, MessageTemplate::kWasmTrapElementSegmentOutOfBounds);
    }
    if (!base::IsInBounds(array_index, length, array->length())) {
      return ThrowWasmError(isolate,
                            MessageTemplate::kWasmTrapArrayOutOfBounds);
    }

    // If the element segment has not been initialized yet, lazily initialize it
    // now.
    AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    // TODO(14616): Fix the instance data.
    std::optional<MessageTemplate> opt_error =
        wasm::InitializeElementSegment(&zone, isolate, trusted_instance_data,
                                       trusted_instance_data, segment_index);
    if (opt_error.has_value()) {
      return ThrowWasmError(isolate, opt_error.value());
    }

    auto elements = handle(
        Cast<FixedArray>(
            trusted_instance_data->element_segments()->get(segment_index)),
        isolate);
    if (length > 0) {
      isolate->heap()->CopyRange(*array, array->ElementSlot(array_index),
                                 elements->RawFieldOfElementAt(segment_offset),
                                 length, UPDATE_WRITE_BARRIER);
    }
    return *isolate->factory()->undefined_value();
  }
}

// Allocate a new suspender, and prepare for stack switching by updating the
// active continuation, active suspender and stack limit.
RUNTIME_FUNCTION(Runtime_WasmAllocateSuspender) {
  HandleScope scope(isolate);
  DirectHandle<WasmSuspenderObject> suspender =
      isolate->factory()->NewWasmSuspenderObject();

  // Update the continuation state.
  auto parent = handle(Cast<WasmContinuationObject>(
                           isolate->root(RootIndex::kActiveContinuation)),
                       isolate);
  std::unique_ptr<wasm::StackMemory> target_stack =
      isolate->stack_pool().GetOrAllocate();
  DirectHandle<WasmContinuationObject> target = WasmContinuationObject::New(
      isolate, target_stack.get(), wasm::JumpBuffer::Suspended, parent);
  target_stack->set_index(isolate->wasm_stacks().size());
  isolate->wasm_stacks().emplace_back(std::move(target_stack));
  for (size_t i = 0; i < isolate->wasm_stacks().size(); ++i) {
    SLOW_DCHECK(isolate->wasm_stacks()[i]->index() == i);
  }
  isolate->roots_table().slot(RootIndex::kActiveContinuation).store(*target);

  // Update the suspender state.
  FullObjectSlot active_suspender_slot =
      isolate->roots_table().slot(RootIndex::kActiveSuspender);
  suspender->set_parent(
      Cast<UnionOf<Undefined, WasmSuspenderObject>>(*active_suspender_slot));
  suspender->set_state(WasmSuspenderObject::kActive);
  suspender->set_continuation(*target);
  active_suspender_slot.store(*suspender);

  // Stack limit will be updated in WasmReturnPromiseOnSuspendAsm builtin.
  wasm::JumpBuffer* jmpbuf = reinterpret_cast<wasm::JumpBuffer*>(
      parent->ReadExternalPointerField<kWasmContinuationJmpbufTag>(
          WasmContinuationObject::kJmpbufOffset, isolate));
  DCHECK_EQ(jmpbuf->state, wasm::JumpBuffer::Active);
  jmpbuf->state = wasm::JumpBuffer::Inactive;
  return *suspender;
}

#define RETURN_RESULT_OR_TRAP(call)                                            \
  do {                                                                         \
    Handle<Object> result;                                                     \
    if (!(call).ToHandle(&result)) {                                           \
      DCHECK(isolate->has_exception());                                        \
      /* Mark any exception as uncatchable by Wasm. */                         \
      Handle<JSObject> exception(Cast<JSObject>(isolate->exception()),         \
                                 isolate);                                     \
      Handle<Name> uncatchable =                                               \
          isolate->factory()->wasm_uncatchable_symbol();                       \
      LookupIterator it(isolate, exception, uncatchable, LookupIterator::OWN); \
      if (!JSReceiver::HasProperty(&it).FromJust()) {                          \
        JSObject::AddProperty(isolate, exception, uncatchable,                 \
                              isolate->factory()->true_value(), NONE);         \
      }                                                                        \
      return ReadOnlyRoots(isolate).exception();                               \
    }                                                                          \
    DCHECK(!isolate->has_exception());                                         \
    return *result;                                                            \
  } while (false)

// "Special" because the type must be in a recgroup of its own.
// Used by "JS String Builtins".
RUNTIME_FUNCTION(Runtime_WasmCastToSpecialPrimitiveArray) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  int bits = args.smi_value_at(1);
  DCHECK(bits == 8 || bits == 16);

  if (args[0] == ReadOnlyRoots(isolate).null_value()) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapNullDereference);
  }
  MessageTemplate illegal_cast = MessageTemplate::kWasmTrapIllegalCast;
  if (!IsWasmArray(args[0])) return ThrowWasmError(isolate, illegal_cast);
  Tagged<WasmArray> obj = Cast<WasmArray>(args[0]);
  Tagged<WasmTypeInfo> wti = obj->map()->wasm_type_info();
  const wasm::WasmModule* module = wti->trusted_data(isolate)->module();
  wasm::ModuleTypeIndex type_index = wti->type_index();
  DCHECK(module->has_array(type_index));
  wasm::CanonicalTypeIndex expected =
      bits == 8 ? wasm::TypeCanonicalizer::kPredefinedArrayI8Index
                : wasm::TypeCanonicalizer::kPredefinedArrayI16Index;
  if (module->canonical_type_id(type_index) != expected) {
    return ThrowWasmError(isolate, illegal_cast);
  }
  return obj;
}

// Returns the new string if the operation succeeds.  Otherwise throws an
// exception and returns an empty result.
RUNTIME_FUNCTION(Runtime_WasmStringNewWtf8) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(5, args.length());
  HandleScope scope(isolate);
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t memory = args.positive_smi_value_at(1);
  uint32_t utf8_variant_value = args.positive_smi_value_at(2);
  double offset_double = args.number_value_at(3);
  uintptr_t offset = static_cast<uintptr_t>(offset_double);
  uint32_t size = NumberToUint32(args[4]);

  DCHECK(utf8_variant_value <=
         static_cast<uint32_t>(unibrow::Utf8Variant::kLastUtf8Variant));

  auto utf8_variant = static_cast<unibrow::Utf8Variant>(utf8_variant_value);

  uint64_t mem_size = trusted_instance_data->memory_size(memory);
  if (!base::IsInBounds<uint64_t>(offset, size, mem_size)) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapMemOutOfBounds);
  }

  const base::Vector<const uint8_t> bytes{
      trusted_instance_data->memory_base(memory) + offset, size};
  MaybeHandle<v8::internal::String> result_string =
      isolate->factory()->NewStringFromUtf8(bytes, utf8_variant);
  if (utf8_variant == unibrow::Utf8Variant::kUtf8NoTrap) {
    DCHECK(!isolate->has_exception());
    if (result_string.is_null()) {
      return *isolate->factory()->wasm_null();
    }
    return *result_string.ToHandleChecked();
  }
  RETURN_RESULT_OR_TRAP(result_string);
}

RUNTIME_FUNCTION(Runtime_WasmStringNewWtf8Array) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(4, args.length());
  HandleScope scope(isolate);
  uint32_t utf8_variant_value = args.positive_smi_value_at(0);
  DirectHandle<WasmArray> array(Cast<WasmArray>(args[1]), isolate);
  uint32_t start = NumberToUint32(args[2]);
  uint32_t end = NumberToUint32(args[3]);

  DCHECK(utf8_variant_value <=
         static_cast<uint32_t>(unibrow::Utf8Variant::kLastUtf8Variant));
  auto utf8_variant = static_cast<unibrow::Utf8Variant>(utf8_variant_value);

  MaybeHandle<v8::internal::String> result_string =
      isolate->factory()->NewStringFromUtf8(array, start, end, utf8_variant);
  if (utf8_variant == unibrow::Utf8Variant::kUtf8NoTrap) {
    DCHECK(!isolate->has_exception());
    if (result_string.is_null()) {
      return *isolate->factory()->wasm_null();
    }
    return *result_string.ToHandleChecked();
  }
  RETURN_RESULT_OR_TRAP(result_string);
}

RUNTIME_FUNCTION(Runtime_WasmStringNewWtf16) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(4, args.length());
  HandleScope scope(isolate);
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t memory = args.positive_smi_value_at(1);
  double offset_double = args.number_value_at(2);
  uintptr_t offset = static_cast<uintptr_t>(offset_double);
  uint32_t size_in_codeunits = NumberToUint32(args[3]);

  uint64_t mem_size = trusted_instance_data->memory_size(memory);
  if (size_in_codeunits > kMaxUInt32 / 2 ||
      !base::IsInBounds<uint64_t>(offset, size_in_co
```