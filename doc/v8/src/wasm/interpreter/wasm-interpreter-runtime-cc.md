Response:
Let's break down the thought process for analyzing the provided C++ code snippet and fulfilling the user's request.

**1. Initial Understanding and Goal Definition:**

The core request is to understand the *functionality* of the provided C++ source code file (`wasm-interpreter-runtime.cc`) within the context of V8's WebAssembly interpreter. The prompt also contains specific instructions about potential Torque files, JavaScript relationships, code logic, common errors, and a final summarization for this "part 1" of a larger set.

**2. High-Level Code Scan and Structure Identification:**

The first step is to skim through the code to get a general sense of its structure. Key observations:

* **Includes:** The `#include` directives point to various V8 components related to execution, objects, runtime, and WebAssembly. This confirms the file's purpose within V8's WASM interpreter.
* **Namespaces:**  The code is within `v8::internal::wasm`, clearly indicating its location within the V8 project.
* **Macros:** The `WASM_STACK_CHECK` macro suggests stack management and error handling.
* **Classes:**  The `ValueTypes` class seems to define sizes for different WebAssembly value types. The `IndirectFunctionTableEntry` class appears to handle entries in function tables. The main functionality seems to reside within `WasmInterpreterRuntime`.
* **Runtime Functions:** The `RUNTIME_FUNCTION(Runtime_WasmRunInterpreter)` block is a strong indicator of a function exposed to the V8 runtime system (potentially callable from JavaScript).
* **Helper Functions:** Functions like `GetInterpreterHandle`, `GetOrCreateInterpreterHandle`, `FindInterpreterEntryFramePointer` suggest internal management and utility functions.
* **Methods within `WasmInterpreterRuntime`:**  Methods like `MemoryGrow`, `TableGet`, `TableSet`, `ThrowException`, `HandleException` clearly indicate core interpreter functionalities.

**3. Deeper Dive into Key Sections:**

Now, focus on the most significant parts:

* **`RUNTIME_FUNCTION(Runtime_WasmRunInterpreter)`:**  This is crucial. Analyze its purpose:
    * It takes arguments related to a Wasm instance, function index, and an argument buffer.
    * It retrieves function signature information.
    * It interacts with `InterpreterHandle` and `WasmInterpreterObject`.
    * It copies arguments from a raw memory buffer into `WasmValue` objects.
    * It calls `WasmInterpreterObject::RunInterpreter`.
    * It copies return values back to the buffer.
    * **Inference:** This function is the entry point from the V8 runtime to execute a Wasm function using the interpreter. It handles argument passing and result retrieval.

* **`class WasmInterpreterRuntime`:** This is the heart of the interpreter runtime. Examine its members and methods:
    * **Members:**  `module_`, `instance_object_`, `codemap_`, `reference_stack_`, etc., indicate the runtime's state and context.
    * **`Init...` methods:** `InitGlobalAddressCache`, `InitMemoryAddresses`, `InitIndirectFunctionTables` suggest initialization processes.
    * **`Memory...` methods:** `MemoryGrow`, `MemoryInit`, `MemoryCopy`, `MemoryFill` point to memory management functionalities within the interpreter.
    * **`Table...` methods:** `TableGet`, `TableSet`, `TableInit`, `TableCopy`, `TableGrow`, `TableSize`, `TableFill` indicate handling of WebAssembly tables.
    * **`ThrowException` and `HandleException`:** These are clearly for exception handling within the interpreter.

* **`class IndirectFunctionTableEntry`:** Understand its purpose. It seems to represent an entry in an indirect function table, storing information needed for indirect calls.

**4. Answering Specific Questions and Instructions:**

* **Functionality Listing:** Based on the deep dive, create a list of the core responsibilities and features exposed by the code.
* **Torque File Check:** The prompt explicitly mentions checking for `.tq`. A quick visual scan confirms the file ends in `.cc`, so it's C++, not Torque.
* **JavaScript Relationship:** The `Runtime_WasmRunInterpreter` function being exposed to the runtime strongly suggests a connection to JavaScript. Formulate a JavaScript example that would trigger this runtime function (calling a WebAssembly function).
* **Code Logic and Assumptions:**  Focus on sections with clear logic, such as argument and return value handling in `Runtime_WasmRunInterpreter`. Create a simple scenario with input arguments and expected output, making clear assumptions.
* **Common Programming Errors:** Think about typical errors related to WebAssembly execution, such as out-of-bounds memory or table access. Relate these to the checks within the code (e.g., checks in `TableGet`, `TableSet`, `MemoryInit`).
* **Summarization:**  Synthesize the key findings into a concise summary of the file's purpose.

**5. Iteration and Refinement:**

Review the answers. Are they clear, accurate, and address all aspects of the prompt?  For instance, the initial explanation of `Runtime_WasmRunInterpreter` might be too technical. Refine it to be more accessible. Ensure the JavaScript example is correct and illustrative. Double-check the assumptions in the code logic example.

**Self-Correction Example During the Process:**

Initially, I might have focused too heavily on the low-level details of memory management within `WasmInterpreterRuntime`. However, realizing the prompt asks for a high-level overview of functionality, I'd shift my focus to the *purpose* of these memory management functions within the broader context of the interpreter. Similarly, while the `WASM_STACK_CHECK` macro is interesting, its core functionality (preventing stack overflow) is more important for a general understanding than the intricate details of its implementation.

By following this structured approach, moving from a high-level understanding to detailed analysis and then synthesizing the information, one can effectively analyze complex source code and address the user's request comprehensively.
好的，让我们来分析一下 `v8/src/wasm/interpreter/wasm-interpreter-runtime.cc` 这个文件的功能。

**文件功能归纳:**

`v8/src/wasm/interpreter/wasm-interpreter-runtime.cc` 文件是 V8 JavaScript 引擎中 WebAssembly (Wasm) 解释器的运行时支持代码。它主要负责以下功能：

1. **提供从 V8 运行时调用 Wasm 解释器的接口:**  `Runtime_WasmRunInterpreter` 是一个 V8 的运行时函数，它允许 V8 的其他部分（包括 JavaScript 调用 Wasm）启动 Wasm 解释器来执行特定的 Wasm 函数。它负责设置解释器运行所需的环境，包括参数传递和返回值处理。

2. **管理 Wasm 解释器的状态:**  `WasmInterpreterRuntime` 类维护了 Wasm 解释器实例的运行时状态，例如内存、全局变量、表、当前的执行帧等。

3. **实现 Wasm 指令的运行时行为:**  虽然具体的指令执行逻辑在 `wasm-interpreter.cc` 中，但 `wasm-interpreter-runtime.cc` 提供了许多辅助函数，用于实现 Wasm 指令在运行时需要的操作，例如：
    * **内存操作:**  `MemoryGrow`, `MemoryInit`, `MemoryCopy`, `MemoryFill` 等函数用于管理和操作 Wasm 实例的线性内存。
    * **表操作:** `TableGet`, `TableSet`, `TableInit`, `TableCopy`, `TableGrow`, `TableSize`, `TableFill` 等函数用于管理和操作 Wasm 实例的表。
    * **全局变量操作:**  虽然没有显式的全局变量操作函数，但 `InitGlobalAddressCache` 负责初始化全局变量的地址缓存。
    * **异常处理:** `ThrowException`, `RethrowException`, `HandleException`, `UnpackException` 等函数用于支持 Wasm 的异常处理机制。
    * **间接调用:**  `IndirectFunctionTableEntry` 类和相关的初始化逻辑用于支持通过函数表进行间接调用。

4. **处理 Wasm 与 JavaScript 之间的互操作:** `Runtime_WasmRunInterpreter` 函数负责将 JavaScript 的参数转换为 Wasm 解释器可以使用的格式，并将 Wasm 的返回值转换回 JavaScript。 `JSToWasmObject` 函数（虽然在这个文件中没有定义，但被使用）负责将 JavaScript 对象转换为 Wasm 的引用类型。

5. **提供工具函数:**  例如 `GetInterpreterHandle`, `GetOrCreateInterpreterHandle` 用于获取和创建与 Wasm 实例关联的解释器句柄。 `ValueTypes::ElementSizeInBytes` 提供了不同 Wasm 值类型的大小信息。

**关于文件类型和 JavaScript 关系:**

* **文件类型:**  `v8/src/wasm/interpreter/wasm-interpreter-runtime.cc` 以 `.cc` 结尾，这意味着它是一个 **C++** 源文件，而不是 Torque 源文件。

* **JavaScript 关系:**  此文件与 JavaScript 的功能有密切关系。 `Runtime_WasmRunInterpreter` 就是一个明显的例子，它充当了 JavaScript 调用 Wasm 代码的桥梁。

**JavaScript 示例 (与 `Runtime_WasmRunInterpreter` 相关):**

假设你有一个编译好的 WebAssembly 模块 `wasmModule`，其中包含一个导出的函数 `add`，它接受两个 i32 类型的参数并返回一个 i32 类型的结果。

```javascript
async function runWasm() {
  const response = await fetch('your_wasm_module.wasm'); // 假设你的 wasm 文件名为 your_wasm_module.wasm
  const buffer = await response.arrayBuffer();
  const wasmModule = await WebAssembly.instantiate(buffer);
  const result = wasmModule.instance.exports.add(5, 10);
  console.log("Wasm 函数的返回值:", result);
}

runWasm();
```

当 JavaScript 调用 `wasmModule.instance.exports.add(5, 10)` 时，如果 V8 决定使用解释器来执行这个 Wasm 函数（例如，在某些调试或优化场景下），那么 V8 内部会调用 `Runtime_WasmRunInterpreter` 函数。

`Runtime_WasmRunInterpreter` 会接收：

* `instance`:  代表 `wasmModule.instance` 的 `WasmInstanceObject`。
* `func_index`:  `add` 函数在 Wasm 模块中的索引。
* `arg_buffer`:  包含参数 `5` 和 `10` 的内存地址。

`Runtime_WasmRunInterpreter` 负责将 JavaScript 的数字 `5` 和 `10` 放入 `arg_buffer` 中，然后调用 Wasm 解释器执行 `add` 函数。执行完成后，它会将 Wasm 函数的返回值从解释器的状态复制回 `arg_buffer`，最终返回给 JavaScript。

**代码逻辑推理示例:**

**假设输入:**

* 一个 Wasm 实例 `instance`，其中包含一个线性内存。
* Wasm 解释器正在执行 `memory.fill i32.const 10, i32.const 0, i32.const 4` 指令。
* `current_code` 指向 `memory.fill` 指令的操作码。
* `dst` (目标地址) 为 10。
* `value` (填充值) 为 0。
* `size` (填充大小) 为 4。
* 内存的起始地址 `memory_start_` 是有效的。
* 内存的大小足以容纳填充操作。

**输出:**

* `WasmInterpreterRuntime::MemoryFill` 函数将被调用。
* 在 `WasmInterpreterRuntime::MemoryFill` 函数中，`BoundsCheckMemRange` 会检查 `dst` 和 `size` 是否在内存范围内。假设检查通过。
* `std::memset` 将被调用，从内存地址 `memory_start_ + 10` 开始，填充 4 个字节的值 `0`。
* 函数返回 `true`。

**用户常见的编程错误示例:**

一个与此文件相关的常见编程错误是在 Wasm 代码中进行 **越界内存访问** 或 **越界表访问**。

**越界内存访问 (导致 `kTrapMemOutOfBounds`):**

假设 Wasm 代码尝试执行 `i32.load offset=1000`，但 Wasm 实例的内存大小只有 500 字节。在解释器执行 `i32.load` 指令时，相关的运行时函数（可能在其他文件中，但涉及到这里的内存管理逻辑）会检查访问地址是否有效，并最终调用 `SetTrap(TrapReason::kTrapMemOutOfBounds, current_code)` 来指示发生了内存越界错误。

**越界表访问 (导致 `kTrapTableOutOfBounds`):**

假设 Wasm 代码尝试调用一个函数表的索引超出表的大小的函数。例如，如果一个表的长度为 10，而 Wasm 代码尝试通过索引 15 调用函数，`WasmInterpreterRuntime::TableGet` 或类似函数会检测到索引越界，并调用 `SetTrap(TrapReason::kTrapTableOutOfBounds, current_code)`。

**总结 (第 1 部分功能):**

总的来说，`v8/src/wasm/interpreter/wasm-interpreter-runtime.cc` 构成了 V8 中 Wasm 解释器运行时的核心基础设施。它提供了连接 V8 运行时和 Wasm 解释器的桥梁，管理解释器的状态，并实现了 Wasm 指令执行所需的关键运行时支持功能，包括内存管理、表操作、异常处理以及与 JavaScript 的互操作。 这个文件是 Wasm 解释器能够正确、安全地执行 Wasm 代码的关键组成部分。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter-runtime.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter-runtime.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/interpreter/wasm-interpreter-runtime.h"

#include <optional>

#include "src/execution/frames-inl.h"
#include "src/execution/isolate.h"
#include "src/objects/managed-inl.h"
#include "src/runtime/runtime-utils.h"
#include "src/wasm/interpreter/wasm-interpreter-objects-inl.h"
#include "src/wasm/interpreter/wasm-interpreter-runtime-inl.h"
#include "src/wasm/wasm-arguments.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8 {
namespace internal {

namespace wasm {

// Similar to STACK_CHECK in isolate.h.
#define WASM_STACK_CHECK(isolate, code)                      \
  do {                                                       \
    StackLimitCheck stack_check(isolate);                    \
    if (stack_check.InterruptRequested()) {                  \
      if (stack_check.HasOverflowed()) {                     \
        ClearThreadInWasmScope clear_wasm_flag(isolate);     \
        SealHandleScope shs(isolate);                        \
        current_frame_.current_function_ = nullptr;          \
        SetTrap(TrapReason::kTrapUnreachable, code);         \
        isolate->StackOverflow();                            \
        return;                                              \
      }                                                      \
      if (isolate->stack_guard()->HasTerminationRequest()) { \
        ClearThreadInWasmScope clear_wasm_flag(isolate);     \
        SealHandleScope shs(isolate);                        \
        current_frame_.current_function_ = nullptr;          \
        SetTrap(TrapReason::kTrapUnreachable, code);         \
        isolate->TerminateExecution();                       \
        return;                                              \
      }                                                      \
    }                                                        \
  } while (false)

class V8_EXPORT_PRIVATE ValueTypes {
 public:
  static inline int ElementSizeInBytes(ValueType type) {
    switch (type.kind()) {
      case kI32:
      case kF32:
        return 4;
      case kI64:
      case kF64:
        return 8;
      case kS128:
        return 16;
      case kRef:
      case kRefNull:
        return kSystemPointerSize;
      default:
        UNREACHABLE();
    }
  }
};

}  // namespace wasm

namespace {

// Find the frame pointer of the interpreter frame on the stack.
Address FindInterpreterEntryFramePointer(Isolate* isolate) {
  StackFrameIterator it(isolate, isolate->thread_local_top());
  // On top: C entry stub.
  DCHECK_EQ(StackFrame::EXIT, it.frame()->type());
  it.Advance();
  // Next: the wasm interpreter entry.
  DCHECK_EQ(StackFrame::WASM_INTERPRETER_ENTRY, it.frame()->type());
  return it.frame()->fp();
}

}  // namespace

RUNTIME_FUNCTION(Runtime_WasmRunInterpreter) {
  DCHECK_EQ(3, args.length());
  HandleScope scope(isolate);
  Handle<WasmInstanceObject> instance = args.at<WasmInstanceObject>(0);
  Handle<WasmTrustedInstanceData> trusted_data(instance->trusted_data(isolate),
                                               isolate);
  int32_t func_index = NumberToInt32(args[1]);
  Handle<Object> arg_buffer_obj = args.at(2);

  // The arg buffer is the raw pointer to the caller's stack. It looks like a
  // Smi (lowest bit not set, as checked by IsSmi), but is no valid Smi. We just
  // cast it back to the raw pointer.
  CHECK(!IsHeapObject(*arg_buffer_obj));
  CHECK(IsSmi(*arg_buffer_obj));
  Address arg_buffer = (*arg_buffer_obj).ptr();

  // Reserve buffers for argument and return values.
  DCHECK_GT(trusted_data->module()->functions.size(), func_index);
  const wasm::FunctionSig* sig =
      trusted_data->module()->functions[func_index].sig;
  DCHECK_GE(kMaxInt, sig->parameter_count());
  int num_params = static_cast<int>(sig->parameter_count());
  std::vector<wasm::WasmValue> wasm_args(num_params);
  DCHECK_GE(kMaxInt, sig->return_count());
  int num_returns = static_cast<int>(sig->return_count());
  std::vector<wasm::WasmValue> wasm_rets(num_returns);

  // Set the current isolate's context.
  isolate->set_context(trusted_data->native_context());

  // Make sure the WasmInterpreterObject and InterpreterHandle for this instance
  // exist.
  Handle<Tuple2> interpreter_object =
      WasmTrustedInstanceData::GetOrCreateInterpreterObject(instance);
  wasm::InterpreterHandle* interpreter_handle =
      wasm::GetOrCreateInterpreterHandle(isolate, interpreter_object);

  if (wasm::WasmBytecode::ContainsSimd(sig)) {
    wasm::ClearThreadInWasmScope clear_wasm_flag(isolate);

    interpreter_handle->SetTrapFunctionIndex(func_index);
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kWasmTrapJSTypeError));
    return ReadOnlyRoots(isolate).exception();
  }

  Address frame_pointer = FindInterpreterEntryFramePointer(isolate);

  // If there are Ref arguments or return values, we store their pointers into
  // an array of bytes so we need to disable GC until they are unpacked by the
  // callee.
  {
    DisallowHeapAllocation no_gc;

    // Copy the arguments for the {arg_buffer} into a vector of {WasmValue}.
    // This also boxes reference types into handles, which needs to happen
    // before any methods that could trigger a GC are being called.
    Address arg_buf_ptr = arg_buffer;
    for (int i = 0; i < num_params; ++i) {
#define CASE_ARG_TYPE(type, ctype)                                     \
  case wasm::type:                                                     \
    DCHECK_EQ(wasm::ValueTypes::ElementSizeInBytes(sig->GetParam(i)),  \
              sizeof(ctype));                                          \
    wasm_args[i] =                                                     \
        wasm::WasmValue(base::ReadUnalignedValue<ctype>(arg_buf_ptr)); \
    arg_buf_ptr += sizeof(ctype);                                      \
    break;

      wasm::ValueType value_type = sig->GetParam(i);
      wasm::ValueKind kind = value_type.kind();
      switch (kind) {
        CASE_ARG_TYPE(kWasmI32.kind(), uint32_t)
        CASE_ARG_TYPE(kWasmI64.kind(), uint64_t)
        CASE_ARG_TYPE(kWasmF32.kind(), float)
        CASE_ARG_TYPE(kWasmF64.kind(), double)
#undef CASE_ARG_TYPE
        case wasm::kWasmRefString.kind():
        case wasm::kWasmAnyRef.kind(): {
          const bool anyref = (kind == wasm::kWasmAnyRef.kind());
          DCHECK_EQ(wasm::ValueTypes::ElementSizeInBytes(sig->GetParam(i)),
                    kSystemPointerSize);
          // MarkCompactCollector::RootMarkingVisitor requires ref slots to be
          // 64-bit aligned.
          arg_buf_ptr += (arg_buf_ptr & 0x04);

          Handle<Object> ref(
              base::ReadUnalignedValue<Tagged<Object>>(arg_buf_ptr), isolate);

          const wasm::WasmInterpreterRuntime* wasm_runtime =
              interpreter_handle->interpreter()->GetWasmRuntime();
          ref = wasm_runtime->JSToWasmObject(ref, value_type);
          if (isolate->has_exception()) {
            interpreter_handle->SetTrapFunctionIndex(func_index);
            return ReadOnlyRoots(isolate).exception();
          }

          if ((value_type != wasm::kWasmExternRef &&
               value_type != wasm::kWasmNullExternRef) &&
              IsNull(*ref, isolate)) {
            ref = isolate->factory()->wasm_null();
          }

          wasm_args[i] = wasm::WasmValue(
              ref, anyref ? wasm::kWasmAnyRef : wasm::kWasmRefString);
          arg_buf_ptr += kSystemPointerSize;
          break;
        }
        case wasm::kWasmS128.kind():
        default:
          UNREACHABLE();
      }
    }

    // Run the function in the interpreter. Note that neither the
    // {WasmInterpreterObject} nor the {InterpreterHandle} have to exist,
    // because interpretation might have been triggered by another Isolate
    // sharing the same WasmEngine.
    bool success = WasmInterpreterObject::RunInterpreter(
        isolate, frame_pointer, instance, func_index, wasm_args, wasm_rets);

    // Early return on failure.
    if (!success) {
      DCHECK(isolate->has_exception());
      return ReadOnlyRoots(isolate).exception();
    }

    // Copy return values from the vector of {WasmValue} into {arg_buffer}. This
    // also un-boxes reference types from handles into raw pointers.
    arg_buf_ptr = arg_buffer;

    for (int i = 0; i < num_returns; ++i) {
#define CASE_RET_TYPE(type, ctype)                                           \
  case wasm::type:                                                           \
    DCHECK_EQ(wasm::ValueTypes::ElementSizeInBytes(sig->GetReturn(i)),       \
              sizeof(ctype));                                                \
    base::WriteUnalignedValue<ctype>(arg_buf_ptr, wasm_rets[i].to<ctype>()); \
    arg_buf_ptr += sizeof(ctype);                                            \
    break;

      switch (sig->GetReturn(i).kind()) {
        CASE_RET_TYPE(kWasmI32.kind(), uint32_t)
        CASE_RET_TYPE(kWasmI64.kind(), uint64_t)
        CASE_RET_TYPE(kWasmF32.kind(), float)
        CASE_RET_TYPE(kWasmF64.kind(), double)
#undef CASE_RET_TYPE
        case wasm::kWasmRefString.kind():
        case wasm::kWasmAnyRef.kind(): {
          DCHECK_EQ(wasm::ValueTypes::ElementSizeInBytes(sig->GetReturn(i)),
                    kSystemPointerSize);
          Handle<Object> ref = wasm_rets[i].to_ref();
          // Note: WasmToJSObject(ref) already called in ContinueExecution or
          // CallExternalJSFunction.

          // Make sure ref slots are 64-bit aligned.
          arg_buf_ptr += (arg_buf_ptr & 0x04);
          base::WriteUnalignedValue<Tagged<Object>>(arg_buf_ptr, *ref);
          arg_buf_ptr += kSystemPointerSize;
          break;
        }
        case wasm::kWasmS128.kind():
        default:
          UNREACHABLE();
      }
    }

    return ReadOnlyRoots(isolate).undefined_value();
  }
}

namespace wasm {

V8_EXPORT_PRIVATE InterpreterHandle* GetInterpreterHandle(
    Isolate* isolate, Handle<Tuple2> interpreter_object) {
  Handle<Object> handle(
      WasmInterpreterObject::get_interpreter_handle(*interpreter_object),
      isolate);
  CHECK(!IsUndefined(*handle, isolate));
  return Cast<Managed<InterpreterHandle>>(handle)->raw();
}

V8_EXPORT_PRIVATE InterpreterHandle* GetOrCreateInterpreterHandle(
    Isolate* isolate, Handle<Tuple2> interpreter_object) {
  Handle<Object> handle(
      WasmInterpreterObject::get_interpreter_handle(*interpreter_object),
      isolate);
  if (IsUndefined(*handle, isolate)) {
    // Use the maximum stack size to estimate the maximum size of the
    // interpreter. The interpreter keeps its own stack internally, and the size
    // of the stack should dominate the overall size of the interpreter. We
    // multiply by '2' to account for the growing strategy for the backing store
    // of the stack.
    size_t interpreter_size = v8_flags.stack_size * KB * 2;
    handle = Managed<InterpreterHandle>::From(
        isolate, interpreter_size,
        std::make_shared<InterpreterHandle>(isolate, interpreter_object));
    WasmInterpreterObject::set_interpreter_handle(*interpreter_object, *handle);
  }

  return Cast<Managed<InterpreterHandle>>(handle)->raw();
}

// A helper for an entry in an indirect function table (IFT).
// The underlying storage in the instance is used by generated code to
// call functions indirectly at runtime.
// Each entry has the following fields:
// - implicit_arg = A WasmTrustedInstanceData or a WasmImportData.
// - sig_id = signature id of function.
// - target = entrypoint to Wasm code or import wrapper code.
// - function_index = function index, if a Wasm function, or
// WasmDispatchTable::kInvalidFunctionIndex otherwise.
class IndirectFunctionTableEntry {
 public:
  inline IndirectFunctionTableEntry(Handle<WasmInstanceObject>, int table_index,
                                    int entry_index);

  inline Tagged<Object> implicit_arg() const {
    return table_->implicit_arg(index_);
  }
  inline int sig_id() const { return table_->sig(index_); }
  inline Address target() const { return table_->target(index_); }
  inline uint32_t function_index() const {
    return table_->function_index(index_);
  }

 private:
  Handle<WasmDispatchTable> const table_;
  int const index_;
};

IndirectFunctionTableEntry::IndirectFunctionTableEntry(
    Handle<WasmInstanceObject> instance, int table_index, int entry_index)
    : table_(table_index != 0
                 ? handle(Cast<WasmDispatchTable>(
                              instance->trusted_data(instance->GetIsolate())
                                  ->dispatch_tables()
                                  ->get(table_index)),
                          instance->GetIsolate())
                 : handle(Cast<WasmDispatchTable>(
                              instance->trusted_data(instance->GetIsolate())
                                  ->dispatch_table0()),
                          instance->GetIsolate())),
      index_(entry_index) {
  DCHECK_GE(entry_index, 0);
  DCHECK_LT(entry_index, table_->length());
}

WasmInterpreterRuntime::WasmInterpreterRuntime(
    const WasmModule* module, Isolate* isolate,
    Handle<WasmInstanceObject> instance_object,
    WasmInterpreter::CodeMap* codemap)
    : isolate_(isolate),
      module_(module),
      instance_object_(instance_object),
      codemap_(codemap),
      start_function_index_(UINT_MAX),
      trap_function_index_(-1),
      trap_pc_(0),

      // The old Wasm interpreter used a {ReferenceStackScope} and stated in a
      // comment that a global handle was not an option because it can lead to a
      // memory leak if a reference to the {WasmInstanceObject} is put onto the
      // reference stack and thereby transitively keeps the interpreter alive.
      // The current Wasm interpreter (located under test/common/wasm) instead
      // uses a global handle. TODO(paolosev@microsoft.com): verify if this
      // works.
      reference_stack_(isolate_->global_handles()->Create(
          ReadOnlyRoots(isolate_).empty_fixed_array())),
      current_ref_stack_size_(0),
      current_thread_(nullptr),

      memory_start_(nullptr),
      instruction_table_(kInstructionTable),
      generic_wasm_to_js_interpreter_wrapper_fn_(
          GeneratedCode<WasmToJSCallSig>::FromAddress(isolate, {}))
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      ,
      shadow_stack_(nullptr)
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
{
  DCHECK(v8_flags.wasm_jitless);

  InitGlobalAddressCache();
  InitMemoryAddresses();
  InitIndirectFunctionTables();

  // Initialize address of GenericWasmToJSInterpreterWrapper builtin.
  Address wasm_to_js_code_addr_addr =
      isolate->isolate_root() +
      IsolateData::BuiltinEntrySlotOffset(Builtin::kWasmInterpreterCWasmEntry);
  Address wasm_to_js_code_addr =
      *reinterpret_cast<Address*>(wasm_to_js_code_addr_addr);
  generic_wasm_to_js_interpreter_wrapper_fn_ =
      GeneratedCode<WasmToJSCallSig>::FromAddress(isolate,
                                                  wasm_to_js_code_addr);
}

WasmInterpreterRuntime::~WasmInterpreterRuntime() {
  GlobalHandles::Destroy(reference_stack_.location());
}

void WasmInterpreterRuntime::Reset() {
  start_function_index_ = UINT_MAX;
  current_frame_ = {};
  function_result_ = {};
  trap_function_index_ = -1;
  trap_pc_ = 0;

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  shadow_stack_ = nullptr;
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
}

void WasmInterpreterRuntime::InitGlobalAddressCache() {
  global_addresses_.resize(module_->globals.size());
  for (size_t index = 0; index < module_->globals.size(); index++) {
    const WasmGlobal& global = module_->globals[index];
    if (!global.type.is_reference()) {
      global_addresses_[index] =
          wasm_trusted_instance_data()->GetGlobalStorage(global);
    }
  }
}

// static
void WasmInterpreterRuntime::UpdateMemoryAddress(
    Handle<WasmInstanceObject> instance) {
  Isolate* isolate = instance->GetIsolate();
  Handle<Tuple2> interpreter_object =
      WasmTrustedInstanceData::GetOrCreateInterpreterObject(instance);
  InterpreterHandle* handle =
      GetOrCreateInterpreterHandle(isolate, interpreter_object);
  WasmInterpreterRuntime* wasm_runtime =
      handle->interpreter()->GetWasmRuntime();
  wasm_runtime->InitMemoryAddresses();
}

int32_t WasmInterpreterRuntime::MemoryGrow(uint32_t delta_pages) {
  HandleScope handle_scope(isolate_);  // Avoid leaking handles.
  // TODO(paolosev@microsoft.com): Support multiple memories.
  uint32_t memory_index = 0;
  Handle<WasmMemoryObject> memory(
      wasm_trusted_instance_data()->memory_object(memory_index), isolate_);
  int32_t result = WasmMemoryObject::Grow(isolate_, memory, delta_pages);
  InitMemoryAddresses();
  return result;
}

void WasmInterpreterRuntime::InitIndirectFunctionTables() {
  int table_count = static_cast<int>(module_->tables.size());
  indirect_call_tables_.resize(table_count);
  for (int table_index = 0; table_index < table_count; ++table_index) {
    PurgeIndirectCallCache(table_index);
  }
}

bool WasmInterpreterRuntime::TableGet(const uint8_t*& current_code,
                                      uint32_t table_index,
                                      uint32_t entry_index,
                                      Handle<Object>* result) {
  // This function assumes that it is executed in a HandleScope.

  auto table =
      handle(Cast<WasmTableObject>(
                 wasm_trusted_instance_data()->tables()->get(table_index)),
             isolate_);
  uint32_t table_size = table->current_length();
  if (entry_index >= table_size) {
    SetTrap(TrapReason::kTrapTableOutOfBounds, current_code);
    return false;
  }

  *result = WasmTableObject::Get(isolate_, table, entry_index);
  return true;
}

void WasmInterpreterRuntime::TableSet(const uint8_t*& current_code,
                                      uint32_t table_index,
                                      uint32_t entry_index,
                                      Handle<Object> ref) {
  // This function assumes that it is executed in a HandleScope.

  auto table =
      handle(Cast<WasmTableObject>(
                 wasm_trusted_instance_data()->tables()->get(table_index)),
             isolate_);
  uint32_t table_size = table->current_length();
  if (entry_index >= table_size) {
    SetTrap(TrapReason::kTrapTableOutOfBounds, current_code);
  } else {
    WasmTableObject::Set(isolate_, table, entry_index, ref);
  }
}

void WasmInterpreterRuntime::TableInit(const uint8_t*& current_code,
                                       uint32_t table_index,
                                       uint32_t element_segment_index,
                                       uint32_t dst, uint32_t src,
                                       uint32_t size) {
  HandleScope scope(isolate_);  // Avoid leaking handles.

  Handle<WasmTrustedInstanceData> trusted_data = wasm_trusted_instance_data();
  auto table =
      handle(Cast<WasmTableObject>(trusted_data->tables()->get(table_index)),
             isolate_);
  if (IsSubtypeOf(table->type(), kWasmFuncRef, module_)) {
    PurgeIndirectCallCache(table_index);
  }

  std::optional<MessageTemplate> msg_template =
      WasmTrustedInstanceData::InitTableEntries(
          instance_object_->GetIsolate(), trusted_data, trusted_data,
          table_index, element_segment_index, dst, src, size);
  // See WasmInstanceObject::InitTableEntries.
  if (msg_template == MessageTemplate::kWasmTrapTableOutOfBounds) {
    SetTrap(TrapReason::kTrapTableOutOfBounds, current_code);
  } else if (msg_template ==
             MessageTemplate::kWasmTrapElementSegmentOutOfBounds) {
    SetTrap(TrapReason::kTrapElementSegmentOutOfBounds, current_code);
  }
}

void WasmInterpreterRuntime::TableCopy(const uint8_t*& current_code,
                                       uint32_t dst_table_index,
                                       uint32_t src_table_index, uint32_t dst,
                                       uint32_t src, uint32_t size) {
  HandleScope scope(isolate_);  // Avoid leaking handles.

  Handle<WasmTrustedInstanceData> trusted_data = wasm_trusted_instance_data();
  auto table_dst = handle(
      Cast<WasmTableObject>(trusted_data->tables()->get(dst_table_index)),
      isolate_);
  if (IsSubtypeOf(table_dst->type(), kWasmFuncRef, module_)) {
    PurgeIndirectCallCache(dst_table_index);
  }

  if (!WasmTrustedInstanceData::CopyTableEntries(
          isolate_, trusted_data, dst_table_index, src_table_index, dst, src,
          size)) {
    SetTrap(TrapReason::kTrapTableOutOfBounds, current_code);
  }
}

uint32_t WasmInterpreterRuntime::TableGrow(uint32_t table_index, uint32_t delta,
                                           Handle<Object> value) {
  // This function assumes that it is executed in a HandleScope.

  auto table =
      handle(Cast<WasmTableObject>(
                 wasm_trusted_instance_data()->tables()->get(table_index)),
             isolate_);
  return WasmTableObject::Grow(isolate_, table, delta, value);
}

uint32_t WasmInterpreterRuntime::TableSize(uint32_t table_index) {
  HandleScope handle_scope(isolate_);  // Avoid leaking handles.
  auto table =
      handle(Cast<WasmTableObject>(
                 wasm_trusted_instance_data()->tables()->get(table_index)),
             isolate_);
  return table->current_length();
}

void WasmInterpreterRuntime::TableFill(const uint8_t*& current_code,
                                       uint32_t table_index, uint32_t count,
                                       Handle<Object> value, uint32_t start) {
  // This function assumes that it is executed in a HandleScope.

  auto table =
      handle(Cast<WasmTableObject>(
                 wasm_trusted_instance_data()->tables()->get(table_index)),
             isolate_);
  uint32_t table_size = table->current_length();
  if (start + count < start ||  // Check for overflow.
      start + count > table_size) {
    SetTrap(TrapReason::kTrapTableOutOfBounds, current_code);
    return;
  }

  if (count == 0) {
    return;
  }

  WasmTableObject::Fill(isolate_, table, start, value, count);
}

bool WasmInterpreterRuntime::MemoryInit(const uint8_t*& current_code,
                                        uint32_t data_segment_index,
                                        uint64_t dst, uint64_t src,
                                        uint64_t size) {
  Handle<WasmTrustedInstanceData> trusted_data = wasm_trusted_instance_data();
  Address dst_addr;
  uint64_t src_max =
      trusted_data->data_segment_sizes()->get(data_segment_index);
  if (!BoundsCheckMemRange(dst, &size, &dst_addr) ||
      !base::IsInBounds(src, size, src_max)) {
    SetTrap(TrapReason::kTrapMemOutOfBounds, current_code);
    return false;
  }

  Address src_addr =
      trusted_data->data_segment_starts()->get(data_segment_index) + src;
  std::memmove(reinterpret_cast<void*>(dst_addr),
               reinterpret_cast<void*>(src_addr), size);
  return true;
}

bool WasmInterpreterRuntime::MemoryCopy(const uint8_t*& current_code,
                                        uint64_t dst, uint64_t src,
                                        uint64_t size) {
  Address dst_addr;
  Address src_addr;
  if (!BoundsCheckMemRange(dst, &size, &dst_addr) ||
      !BoundsCheckMemRange(src, &size, &src_addr)) {
    SetTrap(TrapReason::kTrapMemOutOfBounds, current_code);
    return false;
  }

  std::memmove(reinterpret_cast<void*>(dst_addr),
               reinterpret_cast<void*>(src_addr), size);
  return true;
}

bool WasmInterpreterRuntime::MemoryFill(const uint8_t*& current_code,
                                        uint64_t dst, uint32_t value,
                                        uint64_t size) {
  Address dst_addr;
  if (!BoundsCheckMemRange(dst, &size, &dst_addr)) {
    SetTrap(TrapReason::kTrapMemOutOfBounds, current_code);
    return false;
  }

  std::memset(reinterpret_cast<void*>(dst_addr), value, size);
  return true;
}

// Unpack the values encoded in the given exception. The exception values are
// pushed onto the operand stack.
void WasmInterpreterRuntime::UnpackException(
    uint32_t* sp, const WasmTag& tag, Handle<Object> exception_object,
    uint32_t first_param_slot_index, uint32_t first_param_ref_stack_index) {
  Handle<FixedArray> encoded_values =
      Cast<FixedArray>(WasmExceptionPackage::GetExceptionValues(
          isolate_, Cast<WasmExceptionPackage>(exception_object)));
  // Decode the exception values from the given exception package and push
  // them onto the operand stack. This encoding has to be in sync with other
  // backends so that exceptions can be passed between them.
  const WasmTagSig* sig = tag.sig;
  uint32_t encoded_index = 0;
  uint32_t* p = sp + first_param_slot_index;
  for (size_t i = 0; i < sig->parameter_count(); ++i) {
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    if (v8_flags.trace_drumbrake_execution) {
      TracePush(sig->GetParam(i).kind(), static_cast<uint32_t>(p - sp));
    }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

    WasmValue value;
    switch (sig->GetParam(i).kind()) {
      case kI32: {
        uint32_t u32 = 0;
        DecodeI32ExceptionValue(encoded_values, &encoded_index, &u32);
        base::WriteUnalignedValue<uint32_t>(reinterpret_cast<Address>(p), u32);
        p += sizeof(uint32_t) / kSlotSize;
        break;
      }
      case kF32: {
        uint32_t f32_bits = 0;
        DecodeI32ExceptionValue(encoded_values, &encoded_index, &f32_bits);
        float f32 = Float32::FromBits(f32_bits).get_scalar();
        base::WriteUnalignedValue<float>(reinterpret_cast<Address>(p), f32);
        p += sizeof(float) / kSlotSize;
        break;
      }
      case kI64: {
        uint64_t u64 = 0;
        DecodeI64ExceptionValue(encoded_values, &encoded_index, &u64);
        base::WriteUnalignedValue<uint64_t>(reinterpret_cast<Address>(p), u64);
        p += sizeof(uint64_t) / kSlotSize;
        break;
      }
      case kF64: {
        uint64_t f64_bits = 0;
        DecodeI64ExceptionValue(encoded_values, &encoded_index, &f64_bits);
        float f64 = Float64::FromBits(f64_bits).get_scalar();
        base::WriteUnalignedValue<double>(reinterpret_cast<Address>(p), f64);
        p += sizeof(double) / kSlotSize;
        break;
      }
      case kS128: {
        int32x4 s128 = {0, 0, 0, 0};
        uint32_t* vals = reinterpret_cast<uint32_t*>(s128.val);
        DecodeI32ExceptionValue(encoded_values, &encoded_index, &vals[0]);
        DecodeI32ExceptionValue(encoded_values, &encoded_index, &vals[1]);
        DecodeI32ExceptionValue(encoded_values, &encoded_index, &vals[2]);
        DecodeI32ExceptionValue(encoded_values, &encoded_index, &vals[3]);
        base::WriteUnalignedValue<Simd128>(reinterpret_cast<Address>(p),
                                           Simd128(s128));
        p += sizeof(Simd128) / kSlotSize;
        break;
      }
      case kRef:
      case kRefNull: {
        Handle<Object> ref(encoded_values->get(encoded_index++), isolate_);
        if (sig->GetParam(i).value_type_code() == wasm::kFuncRefCode &&
            i::IsNull(*ref, isolate_)) {
          ref = isolate_->factory()->wasm_null();
        }
        StoreWasmRef(first_param_ref_stack_index++, ref);
        base::WriteUnalignedValue<WasmRef>(reinterpret_cast<Address>(p), ref);
        p += sizeof(WasmRef) / kSlotSize;
        break;
      }
      default:
        UNREACHABLE();
    }
  }
  DCHECK_EQ(WasmExceptionPackage::GetEncodedSize(&tag), encoded_index);
}

namespace {
void RedirectCodeToUnwindHandler(const uint8_t*& code) {
  // Resume execution from s2s_Unwind, which unwinds the Wasm stack frames
  code = reinterpret_cast<uint8_t*>(&s_unwind_code);
}
}  // namespace

// Allocate, initialize and throw a new exception. The exception values are
// being popped off the operand stack.
void WasmInterpreterRuntime::ThrowException(const uint8_t*& code, uint32_t* sp,
                                            uint32_t tag_index) {
  HandleScope handle_scope(isolate_);  // Avoid leaking handles.
  Handle<WasmTrustedInstanceData> trusted_data = wasm_trusted_instance_data();
  Handle<WasmExceptionTag> exception_tag(
      Cast<WasmExceptionTag>(trusted_data->tags_table()->get(tag_index)),
      isolate_);
  const WasmTag& tag = module_->tags[tag_index];
  uint32_t encoded_size = WasmExceptionPackage::GetEncodedSize(&tag);
  Handle<WasmExceptionPackage> exception_object =
      WasmExceptionPackage::New(isolate_, exception_tag, encoded_size);
  Handle<FixedArray> encoded_values = Cast<FixedArray>(
      WasmExceptionPackage::GetExceptionValues(isolate_, exception_object));

  // Encode the exception values on the operand stack into the exception
  // package allocated above. This encoding has to be in sync with other
  // backends so that exceptions can be passed between them.
  const WasmTagSig* sig = tag.sig;
  uint32_t encoded_index = 0;
  for (size_t index = 0; index < sig->parameter_count(); index++) {
    switch (sig->GetParam(index).kind()) {
      case kI32: {
        uint32_t u32 = pop<uint32_t>(sp, code, this);
        EncodeI32ExceptionValue(encoded_values, &encoded_index, u32);
        break;
      }
      case kF32: {
        float f32 = pop<float>(sp, code, this);
        EncodeI32ExceptionValue(encoded_values, &encoded_index,
                                *reinterpret_cast<uint32_t*>(&f32));
        break;
      }
      case kI64: {
        uint64_t u64 = pop<uint64_t>(sp, code, this);
        EncodeI64ExceptionValue(encoded_values, &encoded_index, u64);
        break;
      }
      case kF64: {
        double f64 = pop<double>(sp, code, this);
        EncodeI64ExceptionValue(encoded_values, &encoded_index,
                                *reinterpret_cast<uint64_t*>(&f64));
        break;
      }
      case kS128: {
        int32x4 s128 = pop<Simd128>(sp, code, this).to_i32x4();
        EncodeI32ExceptionValue(encoded_values, &encoded_index, s128.val[0]);
        EncodeI32ExceptionValue(encoded_values, &encoded_index, s128.val[1]);
        EncodeI32ExceptionValue(encoded_values, &encoded_index, s128.val[2]);
        EncodeI32ExceptionValue(encoded_values, &encoded_index, s128.val[3]);
        break;
      }
      case kRef:
      case kRefNull: {
        Handle<Object> ref = pop<WasmRef>(sp, code, this);
        if (IsWasmNull(*ref, isolate_)) {
          ref = handle(ReadOnlyRoots(isolate_).null_value(), isolate_);
        }
        encoded_values->set(encoded_index++, *ref);
        break;
      }
      default:
        UNREACHABLE();
    }
  }

  // Keep track of the code offset of the current instruction, which we'll need
  // to calculate the stack trace from Isolate::Throw.
  current_frame_.current_bytecode_ = code;

  DCHECK_NOT_NULL(current_thread_);
  current_thread_->SetCurrentFrame(current_frame_);

  // Now that the exception is ready, set it as pending.
  {
    wasm::ClearThreadInWasmScope clear_wasm_flag(isolate_);
    isolate_->Throw(*exception_object);
    if (HandleException(sp, code) != WasmInterpreterThread::HANDLED) {
      RedirectCodeToUnwindHandler(code);
    }
  }
}

// Throw a given existing exception caught by the catch block specified.
void WasmInterpreterRuntime::RethrowException(const uint8_t*& code,
                                              uint32_t* sp,
                                              uint32_t catch_block_index) {
  // Keep track of the code offset of the current instruction, which we'll need
  // to calculate the stack trace from Isolate::Throw.
  current_frame_.current_bytecode_ = code;

  DCHECK_NOT_NULL(current_thread_);
  current_thread_->SetCurrentFrame(current_frame_);

  // Now that the exception is ready, set it as pending.
  {
    wasm::ClearThreadInWasmScope clear_wasm_flag(isolate_);
    Handle<Object> exception_object =
        current_frame_.GetCaughtException(isolate_, catch_block_index);
    DCHECK(!IsTheHole(*exception_object));
    isolate_->Throw(*exception_object);
    if (HandleException(sp, code) != WasmInterpreterThread::HANDLED) {
      RedirectCodeToUnwindHandler(code);
    }
  }
}

// Handle a thrown exception. Returns whether the exception was handled inside
// of wasm. Unwinds the interpreted stack accordingly.
WasmInterpreterThread::ExceptionHandlingResult
WasmInterpreterRuntime::HandleException(uint32_t* sp,
                                        const uint8_t*& current_code) {
  DCHECK_IMPLIES(current_code, current_frame_.current_function_);
  DCHECK_IMPLIES(!current_code, !current_frame_.current_function_);
  DCHECK(isolate_->has_exception());

  bool catchable = current_frame_.current_function_ &&
```