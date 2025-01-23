Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/runtime/runtime-wasm.cc`. They also have several specific questions related to its nature and potential interactions with JavaScript.

Here's a breakdown of the thinking process to address the user's request:

1. **Identify the core purpose:** The filename `runtime-wasm.cc` and the included headers (`src/wasm/...`) strongly suggest this file implements runtime functions specifically for WebAssembly within the V8 JavaScript engine.

2. **Scan for keywords and concepts:** Look for recurring patterns and important terms like:
    * `RUNTIME_FUNCTION`: This macro likely defines functions callable from the V8 runtime system, often triggered by built-in JavaScript functions or during execution.
    * `Wasm...`:  Prefixes like `WasmMemoryGrow`, `ThrowWasmError`, `WasmCompileLazy` clearly indicate WebAssembly-related functionality.
    * `JSObject`, `JSFunction`, `TypeError`:  These suggest interaction with JavaScript objects and the handling of JavaScript errors.
    * `isolate`: This is a core V8 concept representing an isolated JavaScript execution environment.
    * `HandleScope`, `SealHandleScope`: These are V8 mechanisms for managing memory and object lifetimes, often used when interacting with the V8 heap.
    * `trap_handler`:  Points to handling WebAssembly traps (runtime errors).
    * `JSToWasmObject`, `WasmToJSObject`: Indicate conversion between JavaScript and WebAssembly representations.
    * `TierUp...`: Suggest optimization or transitioning to more optimized code.
    * `FeedbackVector`: Hints at performance optimization through feedback collection.

3. **Group related functions:**  Observe that several functions deal with specific aspects of WebAssembly execution:
    * **Object Conversion:** `Runtime_WasmGenericWasmToJSObject`, `Runtime_WasmGenericJSToWasmObject`, `Runtime_WasmJSToWasmObject`.
    * **Memory Management:** `Runtime_WasmMemoryGrow`.
    * **Error Handling:** `Runtime_TrapHandlerThrowWasmError`, `Runtime_ThrowWasmError`, `Runtime_WasmThrowJSTypeError`, `Runtime_ThrowBadSuspenderError`, `Runtime_WasmThrowRangeError`, `Runtime_WasmThrowDataViewTypeError`, `Runtime_WasmThrowDataViewDetachedError`, `Runtime_WasmThrowTypeError`, `Runtime_WasmThrow`, `Runtime_WasmReThrow`.
    * **Stack Management:** `Runtime_ThrowWasmStackOverflow`, `Runtime_WasmStackGuard`.
    * **Lazy Compilation:** `Runtime_WasmCompileLazy`.
    * **Optimization/Tiering:** `Runtime_WasmAllocateFeedbackVector`, `Runtime_WasmLiftoffDeoptFinish`, `Runtime_TierUpJSToWasmWrapper`, `Runtime_TierUpWasmToJSWrapper`.
    * **Function Type Checking:** `Runtime_IsWasmExternalFunction`.

4. **Address specific questions:**

    * **`.tq` extension:** The code is clearly C++, not Torque. Note this explicitly.
    * **Relationship to JavaScript:** The presence of functions like `JSToWasmObject` and `WasmToJSObject`, and the error handling involving `TypeError`, demonstrate a strong relationship. Construct simple JavaScript examples to illustrate the conversions and potential errors.
    * **Code logic推理 (Logic Inference):** Choose a relatively straightforward function, like `Runtime_WasmMemoryGrow`, and provide an example with clear inputs (instance data, memory index, delta pages) and the expected output (the new number of pages or -1 on failure). Explain the underlying assumptions (valid inputs, memory bounds).
    * **User Programming Errors:**  Focus on common errors related to WebAssembly's typed nature and memory access. Examples include passing incorrect types to WebAssembly functions and accessing memory out of bounds.

5. **Summarize the functionality:** Based on the identified purpose and the grouped functions, create a concise summary highlighting the key responsibilities of `runtime-wasm.cc`.

6. **Structure the answer:** Organize the information logically, starting with the main function, then addressing the specific questions, and finally providing the summary. Use clear headings and formatting to improve readability.

7. **Review and refine:** Ensure the explanation is accurate, easy to understand, and directly addresses all aspects of the user's request. Double-check the JavaScript examples and logic inferences. Make sure the language is precise and avoids jargon where possible, or explains it when necessary.
这是V8源代码文件 `v8/src/runtime/runtime-wasm.cc` 的第一部分。根据您提供的信息，我们可以归纳一下它的功能如下：

**主要功能：提供 WebAssembly 运行时环境的关键支持函数。**

这个文件定义了一系列以 `RUNTIME_FUNCTION` 宏声明的 C++ 函数，这些函数是 V8 引擎在执行 WebAssembly 代码时调用的底层运行时支持。  它们连接了 WebAssembly 执行环境和 V8 的 JavaScript 引擎的其他部分。

**具体功能点（基于代码片段）：**

* **WebAssembly 和 JavaScript 对象之间的转换:**
    * `Runtime_WasmGenericWasmToJSObject`: 将 WebAssembly 的值（例如 `funcref` 或 `nullref`）转换为相应的 JavaScript 对象。
    * `Runtime_WasmGenericJSToWasmObject` 和 `Runtime_WasmJSToWasmObject`: 将 JavaScript 对象转换为 WebAssembly 的表示形式，并进行类型检查。

* **WebAssembly 内存操作:**
    * `Runtime_WasmMemoryGrow`:  实现 WebAssembly 内存的增长操作。

* **WebAssembly 错误和异常处理:**
    * `Runtime_TrapHandlerThrowWasmError`: 处理 WebAssembly 陷阱 (trap)，并抛出相应的 JavaScript 错误。
    * `Runtime_ThrowWasmError`:  根据错误 ID 抛出特定的 WebAssembly 错误。
    * `Runtime_ThrowWasmStackOverflow`: 处理 WebAssembly 栈溢出。
    * `Runtime_WasmThrowJSTypeError`, `Runtime_ThrowBadSuspenderError`, `Runtime_WasmThrowRangeError`, `Runtime_WasmThrowDataViewTypeError`, `Runtime_WasmThrowDataViewDetachedError`, `Runtime_WasmThrowTypeError`: 抛出各种与 WebAssembly 相关的 JavaScript `TypeError` 和 `RangeError`。
    * `Runtime_WasmThrow` 和 `Runtime_WasmReThrow`:  支持 WebAssembly 异常的抛出和重新抛出机制。

* **WebAssembly 栈管理:**
    * `Runtime_WasmStackGuard`:  用于检查 WebAssembly 栈是否溢出，并处理中断。

* **WebAssembly 代码的延迟编译:**
    * `Runtime_WasmCompileLazy`:  实现 WebAssembly 函数的延迟编译。

* **WebAssembly 代码优化和内联:**
    * `Runtime_WasmAllocateFeedbackVector`:  为 WebAssembly 函数分配反馈向量，用于优化。
    * `Runtime_WasmLiftoffDeoptFinish`:  在 Liftoff 反优化后完成相关操作，例如分配反馈向量。
    * `Runtime_TierUpJSToWasmWrapper` 和 `Runtime_TierUpWasmToJSWrapper`:  支持 JavaScript 到 WebAssembly 和 WebAssembly 到 JavaScript 调用的优化（例如，切换到更快的调用包装器）。

* **WebAssembly 函数类型检查:**
    * `Runtime_IsWasmExternalFunction`: 检查给定的对象是否是 WebAssembly 外部函数。

**关于源代码类型和 JavaScript 关系：**

* **源代码类型:**  根据您提供的信息，该文件以 `.cc` 结尾，因此是 **C++ 源代码**，而不是 Torque 源代码（Torque 源代码以 `.tq` 结尾）。

* **与 JavaScript 的关系:**  这个文件中的函数直接影响着 JavaScript 如何与 WebAssembly 代码交互。例如：
    * 当 JavaScript 调用 WebAssembly 函数时，可能会触发 `Runtime_WasmGenericJSToWasmObject` 进行参数转换。
    * 当 WebAssembly 代码抛出错误时，会通过 `Runtime_TrapHandlerThrowWasmError` 或其他 `Runtime_ThrowWasm...` 函数转换为 JavaScript 异常，JavaScript 可以捕获这些异常。
    * `Runtime_WasmMemoryGrow` 允许 WebAssembly 模块在运行时扩展其内存，这会影响 JavaScript 中 `WebAssembly.Memory` 对象的状态。

**JavaScript 示例（与转换功能相关）：**

```javascript
// 假设有一个 WebAssembly 模块的实例叫 'instance'

// 从 WebAssembly 获取一个 funcref (假设导出一个返回 funcref 的函数 getFuncRef)
const funcRef = instance.exports.getFuncRef();

// 将 WebAssembly funcref 转换为 JavaScript 函数
const jsFunction = funcRef; // V8 会在内部处理转换

// 现在可以像调用普通 JavaScript 函数一样调用 jsFunction
// jsFunction(...args);

// 假设有一个 JavaScript 函数 jsFunc
function jsFunc(x) { return x * 2; }

// 将 JavaScript 函数传递给需要 funcref 的 WebAssembly 函数 (假设导出一个接收 funcref 的函数 callWithFuncRef)
// instance.exports.callWithFuncRef(jsFunc); // V8 会在内部处理转换

// WebAssembly nullref 转换为 JavaScript null
const nullRef = instance.exports.getNullRef(); // 假设导出一个返回 nullref 的函数
console.log(nullRef === null); // 输出 true

// 将 JavaScript null 转换为 WebAssembly nullref
instance.exports.takeNullRef(null); // 假设导出一个接收 nullref 的函数
```

**代码逻辑推理 (以 `Runtime_WasmMemoryGrow` 为例):**

**假设输入：**

* `trusted_instance_data`:  指向 WebAssembly 实例数据的指针。
* `memory_index`:  表示要增长的内存对象的索引 (假设为 `0`，表示第一个内存)。
* `delta_pages`:  表示要增长的页数 (假设为 `2`)。

**预期输出：**

* 如果内存增长成功，则返回增长后的总页数（Smi 格式）。
* 如果内存增长失败（例如，超过最大限制），则返回 `-1`（Smi 格式）。

**推理过程:**

`Runtime_WasmMemoryGrow` 函数会获取指定索引的 `WasmMemoryObject`，并调用其 `Grow` 方法，尝试增加指定的页数。 `WasmMemoryObject::Grow` 内部会处理内存分配和边界检查。最终，`Runtime_WasmMemoryGrow` 将 `Grow` 方法的返回值（成功增长后的总页数或失败时的 -1）转换为 Smi 并返回。

**用户常见的编程错误（与类型转换和内存访问相关）：**

1. **在 JavaScript 中传递错误类型的值给 WebAssembly 函数:**
   ```javascript
   // 假设 WebAssembly 函数 'add' 接收两个 i32 类型的参数
   instance.exports.add("hello", 5); // 错误：传递了字符串
   ```
   这将可能导致 `Runtime_WasmJSToWasmObject` 中的类型检查失败，并抛出 `TypeError`。

2. **尝试访问超出 WebAssembly 内存边界的地址:**
   ```javascript
   const memory = instance.exports.memory;
   const buffer = new Uint8Array(memory.buffer);
   buffer[65536 * 100]; // 假设 WebAssembly 内存大小不足以访问这个地址
   ```
   在 WebAssembly 代码内部，这种越界访问会导致陷阱 (trap)，并被 `Runtime_TrapHandlerThrowWasmError` 等函数捕获并转换为 JavaScript 错误。

**总结：**

`v8/src/runtime/runtime-wasm.cc` 的第一部分主要负责实现 V8 引擎中支持 WebAssembly 运行时环境的关键底层函数，包括 WebAssembly 和 JavaScript 对象之间的转换、内存管理、错误处理、栈管理、延迟编译和代码优化等功能。它在 JavaScript 与 WebAssembly 代码的互操作中扮演着至关重要的角色。

### 提示词
```
这是目录为v8/src/runtime/runtime-wasm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-wasm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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

RUNTIME_FUNCTION(Runtime_WasmT
```