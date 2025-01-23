Response: Let's break down the thought process for summarizing this C++ code and relating it to JavaScript.

**1. Initial Skim and Keyword Identification:**

The first step is to quickly read through the code, paying attention to:

* **Includes:**  `wasm`, `interpreter`, `runtime`, `execution`, `objects`. This immediately signals we're dealing with WebAssembly execution within V8.
* **Namespaces:** `v8::internal::wasm`. Confirms the context.
* **Class Names:** `WasmInterpreterRuntime`, `ValueTypes`, `IndirectFunctionTableEntry`. These are likely key organizational units.
* **Macros/Definitions:** `WASM_STACK_CHECK`. Indicates handling of stack limits.
* **Function Names:**  `Runtime_WasmRunInterpreter`, `GetInterpreterHandle`, `MemoryGrow`, `TableGet`, `ThrowException`, `HandleException`, `BeginExecution`, `ContinueExecution`, `ExecuteFunction`, `ExecuteImportedFunction`. These represent the core actions the code performs.
* **Data Structures:**  `std::vector<wasm::WasmValue>`, `Handle<...>`. These show how data is managed.
* **Comments:**  Hints about the purpose of certain code sections.

**2. High-Level Functionality Deduction:**

Based on the keywords, the overall picture starts to form: This code is the *runtime* component of the WebAssembly *interpreter* within V8. It's responsible for actually executing WebAssembly code in an interpreted fashion.

**3. Deciphering Key Classes and Functions:**

* **`WasmInterpreterRuntime`:** This is the central class. It likely holds the state and methods for running the interpreter. The constructor and destructor, along with methods like `Reset`, `InitGlobalAddressCache`, `InitMemoryAddresses`, `InitIndirectFunctionTables`, suggest its lifecycle management and initialization tasks. The presence of methods like `MemoryGrow`, `TableGet`, `TableSet`, etc., indicates it manages WebAssembly's linear memory and tables. The `ThrowException` and `HandleException` methods clearly deal with WebAssembly's exception handling mechanism. `BeginExecution` and `ContinueExecution` suggest the flow of running a WebAssembly function.
* **`Runtime_WasmRunInterpreter`:** The `RUNTIME_FUNCTION` macro is a strong indicator this is a function exposed to the V8 runtime, likely called from JavaScript. The arguments (`WasmInstanceObject`, `func_index`, `arg_buffer_obj`) reinforce this. The code within this function seems to bridge the gap between JavaScript and the Wasm interpreter. It unpacks arguments from a buffer, calls the interpreter, and then copies results back.
* **`GetInterpreterHandle`/`GetOrCreateInterpreterHandle`:** These likely manage the lifetime and access to an `InterpreterHandle` object, which seems to be necessary for interacting with the interpreter.
* **`IndirectFunctionTableEntry`:** This class deals with indirect calls through function tables, a core feature of WebAssembly.
* **`ValueTypes`:** A utility class for getting the size of WebAssembly value types.

**4. Identifying JavaScript Connections:**

The most obvious connection is `Runtime_WasmRunInterpreter`. The function signature and the way it handles arguments strongly suggest it's the entry point for calling WebAssembly functions *from* JavaScript when the interpreter is used.

**5. Constructing the Summary:**

Now, organize the findings into a coherent summary:

* **Core Function:** Start with the main purpose: executing WebAssembly code using an interpreter.
* **Key Components:** List the major classes and their roles (`WasmInterpreterRuntime`, `IndirectFunctionTableEntry`).
* **JavaScript Interaction:** Highlight `Runtime_WasmRunInterpreter` as the bridge and explain how it works (taking arguments, calling the interpreter, returning results).
* **Core Operations:** Mention the key functionalities managed by the runtime (memory, tables, globals, exceptions, function calls).
* **Stack Management:** Note the `WASM_STACK_CHECK` macro, indicating attention to stack overflow.

**6. Creating the JavaScript Example:**

Think about how the described C++ functionality would manifest in JavaScript:

* **Calling a Wasm Function:** The most direct analogy is calling an exported WebAssembly function.
* **Passing Arguments:** JavaScript arguments need to be converted to Wasm types.
* **Receiving Results:** Wasm return values need to be converted back to JavaScript types.
* **Error Handling:** Wasm traps and exceptions need to be handled in JavaScript (using `try...catch`).

This leads to the example code demonstrating loading a Wasm module, calling a function, and handling potential errors. The example emphasizes the data type conversion that the `Runtime_WasmRunInterpreter` likely handles behind the scenes.

**7. Review and Refine:**

Read through the summary and the JavaScript example. Ensure they are clear, concise, and accurate. Check for any jargon that needs further explanation. For instance, initially, I might just say "handles Wasm memory," but refining it to "manages the linear memory of the WebAssembly instance, including growing the memory" is more descriptive.

This iterative process of skimming, identifying key elements, deducing functionality, connecting to JavaScript, and then organizing and refining leads to a comprehensive and understandable summary.
这个C++源代码文件 `wasm-interpreter-runtime.cc` 是 V8 引擎中 WebAssembly 解释器的运行时环境实现。 它的主要功能是提供在解释执行 WebAssembly 代码时需要的各种运行时支持和操作。

**主要功能归纳:**

1. **WebAssembly 实例管理:**  它负责管理 WebAssembly 实例的运行时状态，包括内存、全局变量、表格（tables）等。
2. **解释器调用入口:**  `Runtime_WasmRunInterpreter` 函数是 JavaScript 调用 WebAssembly 解释器的入口点。它接收 WebAssembly 实例、函数索引和参数缓冲区，然后调用解释器执行相应的函数。
3. **内存管理:**  提供了 WebAssembly 线性内存的增长操作 (`MemoryGrow`) 以及内存初始化、拷贝、填充等操作 (`MemoryInit`, `MemoryCopy`, `MemoryFill`).
4. **表格管理:**  实现了 WebAssembly 表格的获取、设置、初始化、拷贝、增长、大小查询和填充等操作 (`TableGet`, `TableSet`, `TableInit`, `TableCopy`, `TableGrow`, `TableSize`, `TableFill`).
5. **全局变量管理:**  负责访问和更新 WebAssembly 实例中的全局变量。
6. **函数调用:**  处理 WebAssembly 函数的调用，包括直接调用和通过函数表格的间接调用。
7. **异常处理:**  实现了 WebAssembly 的异常处理机制，包括抛出异常 (`ThrowException`) 和捕获异常 (`HandleException`, `RethrowException`).
8. **原子操作支持:**  提供了对共享内存的原子操作的支持，例如 `AtomicNotify`, `I32AtomicWait`, `I64AtomicWait`。
9. **解释器线程管理:**  管理解释器线程的生命周期，包括开始执行 (`BeginExecution`) 和继续执行 (`ContinueExecution`)。
10. **类型转换和处理:**  在 JavaScript 和 WebAssembly 之间进行数据类型的转换和处理，例如在 `Runtime_WasmRunInterpreter` 中将 JavaScript 的参数转换为 WebAssembly 的 `WasmValue`，并将 WebAssembly 的返回值转换回 JavaScript 可以使用的格式。
11. **栈管理:**  管理解释器执行时的栈帧，包括栈溢出检测 (`WASM_STACK_CHECK`) 和栈帧的展开 (`UnwindCurrentStackFrame`)。
12. **间接函数表（IFT）管理:**  管理间接函数表的条目，用于处理函数指针调用。

**与 JavaScript 的关系及 JavaScript 示例:**

这个文件中的代码是 V8 引擎内部实现的一部分，它直接支持 JavaScript 对 WebAssembly 模块的调用和交互。 `Runtime_WasmRunInterpreter` 函数就是一个典型的例子，它允许 JavaScript 代码执行 WebAssembly 模块中的函数。

**JavaScript 示例:**

假设我们有一个名为 `my_module.wasm` 的 WebAssembly 模块，其中导出了一个名为 `add` 的函数，该函数接收两个整数参数并返回它们的和。

```javascript
async function loadAndRunWasm() {

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter-runtime.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
                   isolate_->is_catchable_by_wasm(isolate_->exception());
  if (catchable) {
    HandleScope scope(isolate_);
    Handle<Object> exception = handle(isolate_->exception(), isolate_);
    Tagged<WasmTrustedInstanceData> trusted_data =
        *wasm_trusted_instance_data();

    // We might need to allocate a new FixedArray<Object> to store the caught
    // exception.
    DCHECK(AllowHeapAllocation::IsAllowed());

    size_t current_code_offset =
        current_code - current_frame_.current_function_->GetCode();
    const WasmEHData::TryBlock* try_block =
        current_frame_.current_function_->GetTryBlock(current_code_offset);
    while (try_block) {
      for (const auto& catch_handler : try_block->catch_handlers) {
        if (catch_handler.tag_index < 0) {
          // Catch all.
          current_code = current_frame_.current_function_->GetCode() +
                         catch_handler.code_offset;
          current_frame_.SetCaughtException(
              isolate_, catch_handler.catch_block_index, exception);
          isolate_->clear_exception();
          return WasmInterpreterThread::HANDLED;
        } else if (IsWasmExceptionPackage(*exception, isolate_)) {
          // The exception was thrown by Wasm code and it's wrapped in a
          // WasmExceptionPackage.
          Handle<Object> caught_tag = WasmExceptionPackage::GetExceptionTag(
              isolate_, Cast<WasmExceptionPackage>(exception));
          Handle<Object> expected_tag =
              handle(trusted_data->tags_table()->get(catch_handler.tag_index),
                     isolate_);
          DCHECK(IsWasmExceptionTag(*expected_tag));
          // Determines whether the given exception has a tag matching the
          // expected tag for the given index within the exception table of the
          // current instance.
          if (expected_tag.is_identical_to(caught_tag)) {
            current_code = current_frame_.current_function_->GetCode() +
                           catch_handler.code_offset;
            DCHECK_LT(catch_handler.tag_index, module_->tags.size());
            const WasmTag& tag = module_->tags[catch_handler.tag_index];
            auto exception_payload_slot_offsets =
                current_frame_.current_function_
                    ->GetExceptionPayloadStartSlotOffsets(
                        catch_handler.catch_block_index);
            UnpackException(
                sp, tag, exception,
                exception_payload_slot_offsets.first_param_slot_offset,
                exception_payload_slot_offsets.first_param_ref_stack_index);
            current_frame_.SetCaughtException(
                isolate_, catch_handler.catch_block_index, exception);
            isolate_->clear_exception();
            return WasmInterpreterThread::HANDLED;
          }
        } else {
          // Check for the special case where the tag is WebAssembly.JSTag and
          // the exception is not a WebAssembly.Exception. In this case the
          // exception is caught and pushed on the operand stack.
          // Only perform this check if the tag signature is the same as
          // the JSTag signature, i.e. a single externref, otherwise we know
          // statically that it cannot be the JSTag.
          DCHECK_LT(catch_handler.tag_index, module_->tags.size());
          const WasmTagSig* sig = module_->tags[catch_handler.tag_index].sig;
          if (sig->return_count() != 0 || sig->parameter_count() != 1 ||
              (sig->GetParam(0).kind() != kRefNull &&
               sig->GetParam(0).kind() != kRef)) {
            continue;
          }

          Handle<JSObject> js_tag_object =
              handle(isolate_->native_context()->wasm_js_tag(), isolate_);
          Handle<WasmTagObject> wasm_tag_object(
              Cast<WasmTagObject>(*js_tag_object), isolate_);
          Handle<Object> caught_tag = handle(wasm_tag_object->tag(), isolate_);
          Handle<Object> expected_tag =
              handle(trusted_data->tags_table()->get(catch_handler.tag_index),
                     isolate_);
          if (!expected_tag.is_identical_to(caught_tag)) {
            continue;
          }

          current_code = current_frame_.current_function_->GetCode() +
                         catch_handler.code_offset;
          // Push exception on the operand stack.
          auto exception_payload_slot_offsets =
              current_frame_.current_function_
                  ->GetExceptionPayloadStartSlotOffsets(
                      catch_handler.catch_block_index);
          StoreWasmRef(
              exception_payload_slot_offsets.first_param_ref_stack_index,
              exception);
          base::WriteUnalignedValue<WasmRef>(
              reinterpret_cast<Address>(
                  sp + exception_payload_slot_offsets.first_param_slot_offset),
              exception);

          current_frame_.SetCaughtException(
              isolate_, catch_handler.catch_block_index, exception);
          isolate_->clear_exception();
          return WasmInterpreterThread::HANDLED;
        }
      }
      try_block =
          current_frame_.current_function_->GetParentTryBlock(try_block);
    }
  }

  DCHECK_NOT_NULL(current_thread_);
  current_thread_->Unwinding();
  return WasmInterpreterThread::UNWOUND;
}

bool WasmInterpreterRuntime::AllowsAtomicsWait() const {
  return !module_->memories.empty() && module_->memories[0].is_shared &&
         isolate_->allow_atomics_wait();
}

int32_t WasmInterpreterRuntime::AtomicNotify(uint64_t buffer_offset,
                                             int32_t val) {
  if (module_->memories.empty() || !module_->memories[0].is_shared) {
    return 0;
  } else {
    HandleScope handle_scope(isolate_);
    // TODO(paolosev@microsoft.com): Support multiple memories.
    uint32_t memory_index = 0;
    Handle<JSArrayBuffer> array_buffer(wasm_trusted_instance_data()
                                           ->memory_object(memory_index)
                                           ->array_buffer(),
                                       isolate_);
    int result = FutexEmulation::Wake(*array_buffer, buffer_offset, val);
    return result;
  }
}

int32_t WasmInterpreterRuntime::I32AtomicWait(uint64_t buffer_offset,
                                              int32_t val, int64_t timeout) {
  HandleScope handle_scope(isolate_);
  // TODO(paolosev@microsoft.com): Support multiple memories.
  uint32_t memory_index = 0;
  Handle<JSArrayBuffer> array_buffer(
      wasm_trusted_instance_data()->memory_object(memory_index)->array_buffer(),
      isolate_);
  auto result = FutexEmulation::WaitWasm32(isolate_, array_buffer,
                                           buffer_offset, val, timeout);
  return result.ToSmi().value();
}

int32_t WasmInterpreterRuntime::I64AtomicWait(uint64_t buffer_offset,
                                              int64_t val, int64_t timeout) {
  HandleScope handle_scope(isolate_);
  // TODO(paolosev@microsoft.com): Support multiple memories.
  uint32_t memory_index = 0;
  Handle<JSArrayBuffer> array_buffer(
      wasm_trusted_instance_data()->memory_object(memory_index)->array_buffer(),
      isolate_);
  auto result = FutexEmulation::WaitWasm64(isolate_, array_buffer,
                                           buffer_offset, val, timeout);
  return result.ToSmi().value();
}

void WasmInterpreterRuntime::BeginExecution(
    WasmInterpreterThread* thread, uint32_t func_index, Address frame_pointer,
    uint8_t* interpreter_fp, uint32_t ref_stack_offset,
    const std::vector<WasmValue>* argument_values) {
  current_thread_ = thread;
  start_function_index_ = func_index;

  thread->StartActivation(this, frame_pointer, interpreter_fp, current_frame_);

  current_frame_.current_function_ = nullptr;
  current_frame_.previous_frame_ = nullptr;
  current_frame_.current_bytecode_ = nullptr;
  current_frame_.current_sp_ = interpreter_fp;
  current_frame_.ref_array_current_sp_ = ref_stack_offset;
  current_frame_.thread_ = thread;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  current_frame_.current_stack_start_args_ = thread->CurrentStackFrameStart();
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  const FunctionSig* sig = module_->functions[func_index].sig;
  size_t args_count = 0;
  uint32_t rets_slots_size = 0;
  uint32_t ref_rets_count = 0;
  uint32_t ref_args_count = 0;
  WasmBytecode* target_function = GetFunctionBytecode(func_index);
  if (target_function) {
    args_count = target_function->args_count();
    rets_slots_size = target_function->rets_slots_size();
    ref_rets_count = target_function->ref_rets_count();
    ref_args_count = target_function->ref_args_count();
  } else {
    // We begin execution by calling an imported function.
    args_count = sig->parameter_count();
    rets_slots_size = WasmBytecode::RetsSizeInSlots(sig);
    ref_rets_count = WasmBytecode::RefRetsCount(sig);
    ref_args_count = WasmBytecode::RefArgsCount(sig);
  }

  // Here GC is disabled, we cannot "resize" the reference_stack_ FixedArray
  // before having created Handles for the Ref arguments passed in
  // argument_values.
  HandleScope handle_scope(isolate_);  // Avoid leaking handles.

  std::vector<Handle<Object>> ref_args;
  if (ref_args_count > 0) {
    ref_args.reserve(ref_args_count);
  }

  uint8_t* p = interpreter_fp + rets_slots_size * kSlotSize;

  // Check stack overflow.
  const uint8_t* stack_limit = thread->StackLimitAddress();
  if (V8_UNLIKELY(p + (ref_rets_count + ref_args_count) * sizeof(WasmRef) >=
                  stack_limit)) {
    size_t additional_required_size =
        p + (ref_rets_count + ref_args_count) * sizeof(WasmRef) - stack_limit;
    if (!thread->ExpandStack(additional_required_size)) {
      // TODO(paolosev@microsoft.com) - Calculate initial function offset.
      ClearThreadInWasmScope clear_wasm_flag(isolate_);
      SealHandleScope shs(isolate_);
      isolate_->StackOverflow();
      const pc_t trap_pc = 0;
      SetTrap(TrapReason::kTrapUnreachable, trap_pc);
      thread->FinishActivation();
      return;
    }
  }

  if (argument_values) {
    // We are being called from JS, arguments are passed in the
    // {argument_values} vector.
    for (size_t i = 0; i < argument_values->size(); i++) {
      const WasmValue& value = (*argument_values)[i];
      switch (value.type().kind()) {
        case kI32:
          base::WriteUnalignedValue<int32_t>(reinterpret_cast<Address>(p),
                                             value.to<int32_t>());
          p += sizeof(int32_t);
          break;
        case kI64:
          base::WriteUnalignedValue<int64_t>(reinterpret_cast<Address>(p),
                                             value.to<int64_t>());
          p += sizeof(int64_t);
          break;
        case kF32:
          base::WriteUnalignedValue<float>(reinterpret_cast<Address>(p),
                                           value.to<float>());
          p += sizeof(float);
          break;
        case kF64:
          base::WriteUnalignedValue<double>(reinterpret_cast<Address>(p),
                                            value.to<double>());
          p += sizeof(double);
          break;
        case kRef:
        case kRefNull: {
          Handle<Object> ref = value.to_ref();
          if (IsJSFunction(*ref, isolate_)) {
            Tagged<SharedFunctionInfo> sfi = Cast<JSFunction>(ref)->shared();
            if (sfi->HasWasmExportedFunctionData()) {
              Tagged<WasmExportedFunctionData> wasm_exported_function_data =
                  sfi->wasm_exported_function_data();
              ref = handle(
                  wasm_exported_function_data->func_ref()->internal(isolate_),
                  isolate_);
            }
          }
          ref_args.push_back(ref);
          base::WriteUnalignedValue<WasmRef>(reinterpret_cast<Address>(p),
                                             WasmRef(nullptr));
          p += sizeof(WasmRef);
          break;
        }
        case kS128:
        default:
          UNREACHABLE();
      }
    }
  } else {
    // We are being called from Wasm, arguments are already in the stack.
    for (size_t i = 0; i < args_count; i++) {
      switch (sig->GetParam(i).kind()) {
        case kI32:
          p += sizeof(int32_t);
          break;
        case kI64:
          p += sizeof(int64_t);
          break;
        case kF32:
          p += sizeof(float);
          break;
        case kF64:
          p += sizeof(double);
          break;
        case kS128:
          p += sizeof(Simd128);
          break;
        case kRef:
        case kRefNull: {
          Handle<Object> ref = base::ReadUnalignedValue<Handle<Object>>(
              reinterpret_cast<Address>(p));
          ref_args.push_back(ref);
          p += sizeof(WasmRef);
          break;
        }
        default:
          UNREACHABLE();
      }
    }
  }

  {
    // Once we have read ref argument passed on the stack and we have stored
    // them into the ref_args vector of Handles, we can re-enable the GC.
    AllowHeapAllocation allow_gc;

    if (ref_rets_count + ref_args_count > 0) {
      // Reserve space for reference args and return values in the
      // reference_stack_.
      EnsureRefStackSpace(current_frame_.ref_array_length_ + ref_rets_count +
                          ref_args_count);

      uint32_t ref_stack_arg_index = ref_rets_count;
      for (uint32_t ref_arg_index = 0; ref_arg_index < ref_args_count;
           ref_arg_index++) {
        StoreWasmRef(ref_stack_arg_index++, ref_args[ref_arg_index]);
      }
    }
  }
}

void WasmInterpreterRuntime::ContinueExecution(WasmInterpreterThread* thread,
                                               bool called_from_js) {
  DCHECK_NE(start_function_index_, UINT_MAX);

  uint32_t start_function_index = start_function_index_;
  FrameState current_frame = current_frame_;

  const uint8_t* code = nullptr;
  const FunctionSig* sig = nullptr;
  uint32_t return_count = 0;
  WasmBytecode* target_function = GetFunctionBytecode(start_function_index_);
  if (target_function) {
    sig = target_function->GetFunctionSignature();
    return_count = target_function->return_count();
    ExecuteFunction(code, start_function_index_, target_function->args_count(),
                    0, 0, 0);
  } else {
    sig = module_->functions[start_function_index_].sig;
    return_count = static_cast<uint32_t>(sig->return_count());
    ExecuteImportedFunction(code, start_function_index_,
                            static_cast<uint32_t>(sig->parameter_count()), 0, 0,
                            0);
  }

  // If there are Ref types in the set of result types defined in the function
  // signature, they are located from the first ref_stack_ slot of the current
  // Activation.
  uint32_t ref_result_slot_index = 0;

  if (state() == WasmInterpreterThread::State::RUNNING) {
    if (return_count > 0) {
      uint32_t* dst = reinterpret_cast<uint32_t*>(current_frame_.current_sp_);

      if (called_from_js) {
        // We are returning the results to a JS caller, we need to store them
        // into the {function_result_} vector and they will be retrieved via
        // {GetReturnValue}.
        function_result_.resize(return_count);
        for (size_t index = 0; index < return_count; index++) {
          switch (sig->GetReturn(index).kind()) {
            case kI32:
              function_result_[index] =
                  WasmValue(base::ReadUnalignedValue<int32_t>(
                      reinterpret_cast<Address>(dst)));
              dst += sizeof(uint32_t) / kSlotSize;
              break;
            case kI64:
              function_result_[index] =
                  WasmValue(base::ReadUnalignedValue<int64_t>(
                      reinterpret_cast<Address>(dst)));
              dst += sizeof(uint64_t) / kSlotSize;
              break;
            case kF32:
              function_result_[index] =
                  WasmValue(base::ReadUnalignedValue<float>(
                      reinterpret_cast<Address>(dst)));
              dst += sizeof(float) / kSlotSize;
              break;
            case kF64:
              function_result_[index] =
                  WasmValue(base::ReadUnalignedValue<double>(
                      reinterpret_cast<Address>(dst)));
              dst += sizeof(double) / kSlotSize;
              break;
            case kRef:
            case kRefNull: {
              Handle<Object> ref = ExtractWasmRef(ref_result_slot_index++);
              ref = WasmToJSObject(ref);
              function_result_[index] = WasmValue(
                  ref, sig->GetReturn(index).kind() == kRef ? kWasmRefString
                                                            : kWasmAnyRef);
              dst += sizeof(WasmRef) / kSlotSize;
              break;
            }
            case kS128:
            default:
              UNREACHABLE();
          }
        }
      } else {
        // We are returning the results on the stack
        for (size_t index = 0; index < return_count; index++) {
          switch (sig->GetReturn(index).kind()) {
            case kI32:
              dst += sizeof(uint32_t) / kSlotSize;
              break;
            case kI64:
              dst += sizeof(uint64_t) / kSlotSize;
              break;
            case kF32:
              dst += sizeof(float) / kSlotSize;
              break;
            case kF64:
              dst += sizeof(double) / kSlotSize;
              break;
            case kS128:
              dst += sizeof(Simd128) / kSlotSize;
              break;
            case kRef:
            case kRefNull: {
              // Make sure the ref result is termporarily stored in a stack
              // slot, to be retrieved by the caller.
              Handle<Object> ref = ExtractWasmRef(ref_result_slot_index++);
              base::WriteUnalignedValue<WasmRef>(reinterpret_cast<Address>(dst),
                                                 ref);
              dst += sizeof(WasmRef) / kSlotSize;
              break;
            }
            default:
              UNREACHABLE();
          }
        }
      }
    }

    if (ref_result_slot_index > 0) {
      ClearRefStackValues(current_frame_.ref_array_current_sp_,
                          ref_result_slot_index);
    }

    DCHECK(current_frame_.caught_exceptions_.is_null());

    start_function_index_ = start_function_index;
    current_frame_ = current_frame;
  } else if (state() == WasmInterpreterThread::State::TRAPPED) {
    MessageTemplate message_id =
        WasmOpcodes::TrapReasonToMessageId(thread->GetTrapReason());
    thread->RaiseException(isolate_, message_id);
  } else if (state() == WasmInterpreterThread::State::EH_UNWINDING) {
    // Uncaught exception.
    thread->Stop();
  } else {
    DCHECK_EQ(state(), WasmInterpreterThread::State::STOPPED);
  }

  thread->FinishActivation();
  const FrameState* frame_state = thread->GetCurrentActivationFor(this);
  current_frame_ = frame_state ? *frame_state : FrameState();
}

void WasmInterpreterRuntime::StoreWasmRef(uint32_t ref_stack_index,
                                          const WasmRef& ref) {
  uint32_t index = ref_stack_index + current_frame_.ref_array_current_sp_;
  if (ref.is_null()) {
    reference_stack_->set_the_hole(isolate_, index);
  } else {
    reference_stack_->set(index, *ref);
  }
}

WasmRef WasmInterpreterRuntime::ExtractWasmRef(uint32_t ref_stack_index) {
  int index =
      static_cast<int>(ref_stack_index) + current_frame_.ref_array_current_sp_;
  Handle<Object> ref(reference_stack_->get(index), isolate_);
  DCHECK(!IsTheHole(*ref, isolate_));
  return WasmRef(ref);
}

void WasmInterpreterRuntime::EnsureRefStackSpace(size_t new_size) {
  if (V8_LIKELY(current_ref_stack_size_ >= new_size)) return;
  size_t requested_size = base::bits::RoundUpToPowerOfTwo64(new_size);
  new_size = std::max(size_t{8},
                      std::max(2 * current_ref_stack_size_, requested_size));
  int grow_by = static_cast<int>(new_size - current_ref_stack_size_);
  HandleScope handle_scope(isolate_);  // Avoid leaking handles.
  Handle<FixedArray> new_ref_stack =
      isolate_->factory()->CopyFixedArrayAndGrow(reference_stack_, grow_by);
  new_ref_stack->FillWithHoles(static_cast<int>(current_ref_stack_size_),
                               static_cast<int>(new_size));
  isolate_->global_handles()->Destroy(reference_stack_.location());
  reference_stack_ = isolate_->global_handles()->Create(*new_ref_stack);
  current_ref_stack_size_ = new_size;
}

void WasmInterpreterRuntime::ClearRefStackValues(size_t index, size_t count) {
  reference_stack_->FillWithHoles(static_cast<int>(index),
                                  static_cast<int>(index + count));
}

// A tail call should not add an additional stack frame to the interpreter
// stack. This is implemented by unwinding the current stack frame just before
// the tail call.
void WasmInterpreterRuntime::UnwindCurrentStackFrame(
    uint32_t* sp, uint32_t slot_offset, uint32_t rets_size, uint32_t args_size,
    uint32_t rets_refs, uint32_t args_refs, uint32_t ref_stack_fp_offset) {
  // At the moment of the call the interpreter stack is as in the diagram below.
  // A new interpreter frame for the callee function has been initialized, with
  // `R` slots to contain the R return values, followed by {args_size} slots to
  // contain the callee arguments.
  //
  // In order to unwind an interpreter stack frame we just copy the content of
  // the slots that contain the callee arguments into the caller stack frame,
  // just after the slots of the return values. Note that the return call is
  // invalid if the number and types of the return values of the callee function
  // do not exactly match the number and types of the return values of the
  // caller function. Instead, the number of types of the caller and callee
  // functions arguments can differ.
  //
  // The other slots in the caller frame, for const values and locals, will be
  // initialized later in ExecuteFunction().
  //
  // +----------------------+
  // | argA-1               |      ^         ^
  // | ...                  |      |         | ->-----+
  // | ...                  |      |         |        |
  // | arg0                 |    callee      v        |
  // | retR-1               |    frame                |
  // | ...                  |      |                  |
  // | ret0                 |      v                  | copy
  // +----------------------+ (slot_offset)           |
  // | ...                  |      ^                  V
  // | <stack slots>        |      |                  |
  // | <locals slots>       |      |                  |
  // | <const slots>        |      |         ^        |
  // | argN-1               |    caller      | <------+
  // | ...                  |    frame       |
  // | arg0                 |      |         v
  // | retR-1               |      |
  // | ...                  |      |
  // | ret0                 |      v
  // +----------------------+ (0)

  uint8_t* next_sp = reinterpret_cast<uint8_t*>(sp);
  uint8_t* prev_sp = next_sp + slot_offset;
  // Here {args_size} is the number of arguments expected by the function we are
  // calling, which can be different from the number of args of the caller
  // function.
  ::memmove(next_sp + rets_size, prev_sp, args_size);

  // If some of the argument-slots contain Ref values, we need to move them
  // accordingly, in the {reference_stack_}.
  if (rets_refs) {
    ClearRefStackValues(current_frame_.ref_array_current_sp_, rets_refs);
  }
  // Here {args_refs} is the number of reference args expected by the function
  // we are calling, which can be different from the number of reference args of
  // the caller function.
  for (uint32_t i = 0; i < args_refs; i++) {
    StoreWasmRef(rets_refs + i, ExtractWasmRef(ref_stack_fp_offset + i));
  }
  if (ref_stack_fp_offset > rets_refs + args_refs) {
    ClearRefStackValues(
        current_frame_.ref_array_current_sp_ + rets_refs + args_refs,
        ref_stack_fp_offset - rets_refs - args_refs);
  }
}

void WasmInterpreterRuntime::StoreRefArgsIntoStackSlots(
    uint8_t* sp, uint32_t ref_stack_fp_index, const FunctionSig* sig) {
  // Argument values of type Ref, if present, are already stored in the
  // reference_stack_ starting at index ref_stack_fp_index + RefRetsCount(sig).
  // We want to temporarily copy the pointers to these object also in the stack
  // slots, because functions WasmInterpreter::RunInterpreter() and
  // WasmInterpreter::CallExternalJSFunction gets all arguments from the stack.

  // TODO(paolosev@microsoft.com) - Too slow?
  ref_stack_fp_index += WasmBytecode::RefRetsCount(sig);

  size_t args_count = sig->parameter_count();
  sp += WasmBytecode::RetsSizeInSlots(sig) * kSlotSize;
  for (size_t i = 0; i < args_count; i++) {
    switch (sig->GetParam(i).kind()) {
      case kI32:
      case kF32:
        sp += sizeof(int32_t);
        break;
      case kI64:
      case kF64:
        sp += sizeof(int64_t);
        break;
      case kS128:
        sp += sizeof(Simd128);
        break;
      case kRef:
      case kRefNull: {
        WasmRef ref = ExtractWasmRef(ref_stack_fp_index++);
        base::WriteUnalignedValue<WasmRef>(reinterpret_cast<Address>(sp), ref);
        sp += sizeof(WasmRef);
        break;
      }
      default:
        UNREACHABLE();
    }
  }
}

void WasmInterpreterRuntime::StoreRefResultsIntoRefStack(
    uint8_t* sp, uint32_t ref_stack_fp_index, const FunctionSig* sig) {
  size_t rets_count = sig->return_count();
  for (size_t i = 0; i < rets_count; i++) {
    switch (sig->GetReturn(i).kind()) {
      case kI32:
      case kF32:
        sp += sizeof(int32_t);
        break;
      case kI64:
      case kF64:
        sp += sizeof(int64_t);
        break;
      case kS128:
        sp += sizeof(Simd128);
        break;
      case kRef:
      case kRefNull:
        StoreWasmRef(ref_stack_fp_index++, base::ReadUnalignedValue<WasmRef>(
                                               reinterpret_cast<Address>(sp)));
        sp += sizeof(WasmRef);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void WasmInterpreterRuntime::ExecuteImportedFunction(
    const uint8_t*& code, uint32_t func_index, uint32_t current_stack_size,
    uint32_t ref_stack_fp_index, uint32_t slot_offset,
    uint32_t return_slot_offset) {
  WasmInterpreterThread* thread = this->thread();
  DCHECK_NOT_NULL(thread);

  // Store a pointer to the current FrameState before leaving the current
  // Activation.
  current_frame_.current_bytecode_ = code;
  thread->SetCurrentFrame(current_frame_);
  thread->SetCurrentActivationFrame(
      reinterpret_cast<uint32_t*>(current_frame_.current_sp_ + slot_offset),
      slot_offset, current_stack_size, ref_stack_fp_index);

  ExternalCallResult result = CallImportedFunction(
      code, func_index,
      reinterpret_cast<uint32_t*>(current_frame_.current_sp_ + slot_offset),
      current_stack_size, ref_stack_fp_index, slot_offset);

  if (result == ExternalCallResult::EXTERNAL_EXCEPTION) {
    if (HandleException(reinterpret_cast<uint32_t*>(current_frame_.current_sp_),
                        code) ==
        WasmInterpreterThread::ExceptionHandlingResult::HANDLED) {
      // The exception was caught by Wasm EH. Resume execution,
      // {HandleException} has already updated {code} to point to the first
      // instruction in the catch handler.
      thread->Run();
    } else {  // ExceptionHandlingResult::UNWRAPPED
      if (thread->state() != WasmInterpreterThread::State::EH_UNWINDING) {
        thread->Stop();
      }
      // Resume execution from s2s_Unwind, which unwinds the Wasm stack frames.
      RedirectCodeToUnwindHandler(code);
    }
  }
}

inline DISABLE_CFI_ICALL void CallThroughDispatchTable(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  kInstructionTable[ReadFnId(code) & kInstructionTableMask](
      code, sp, wasm_runtime, r0, fp0);
}

// Sets up the current interpreter stack frame to start executing a new function
// with a tail call. Do not move the stack pointer for the interpreter stack,
// and avoids calling WasmInterpreterRuntime::ExecuteFunction(), which would add
// a new C++ stack frame.
void WasmInterpreterRuntime::PrepareTailCall(const uint8_t*& code,
                                             uint32_t func_index,
                                             uint32_t current_stack_size,
                                             uint32_t return_slot_offset) {
  // TODO(paolosev@microsoft.com): avoid to duplicate code from ExecuteFunction?

  WASM_STACK_CHECK(isolate_, code);

  WasmBytecode* target_function = GetFunctionBytecode(func_index);
  DCHECK_NOT_NULL(target_function);

  current_frame_.current_bytecode_ = code;

  current_frame_.current_function_ = target_function;

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  current_frame_.current_stack_start_locals_ =
      current_frame_.current_stack_start_args_ + target_function->args_count();
  current_frame_.current_stack_start_stack_ =
      current_frame_.current_stack_start_locals_ +
      target_function->locals_count();

  if (v8_flags.trace_drumbrake_execution) {
    Trace("\nTailCallFunction: %d\n", func_index);
    Trace("= > PushFrame #%d(#%d @%d)\n", current_frame_.current_stack_height_,
          func_index, 0);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  const uint8_t* stack_limit = current_frame_.thread_->StackLimitAddress();
  if (V8_UNLIKELY(stack_limit <= current_frame_.current_sp_ ||
                  !target_function->InitializeSlots(
                      current_frame_.current_sp_,
                      stack_limit - current_frame_.current_sp_))) {
    // Try to resize the stack.
    size_t additional_required_space =
        target_function->frame_size() -
        (stack_limit - current_frame_.current_sp_);
    // Try again.
    if (!current_frame_.thread_->ExpandStack(additional_required_space) ||
        !target_function->InitializeSlots(
            current_frame_.current_sp_,
            (stack_limit = current_frame_.thread_->StackLimitAddress()) -
                current_frame_.current_sp_)) {
      ClearThreadInWasmScope clear_wasm_flag(isolate_);
      SealHandleScope shs(isolate_);
      SetTrap(TrapReason::kTrapUnreachable, code);
      isolate_->StackOverflow();
      return;
    }
  }

  uint32_t ref_slots_count = target_function->ref_slots_count();
  if (V8_UNLIKELY(ref_slots_count > 0)) {
    current_frame_.ref_array_length_ =
        current_frame_.ref_array_current_sp_ + ref_slots_count;
    EnsureRefStackSpace(current_frame_.ref_array_length_);

    // Initialize locals of ref types.
    if (V8_UNLIKELY(target_function->ref_locals_count() > 0)) {
      uint32_t ref_stack_index =
          target_function->ref_rets_count() + target_function->ref_args_count();
      for (uint32_t i = 0; i < target_function->ref_locals_count(); i++) {
        StoreWasmRef(ref_stack_index++,
                     WasmRef(isolate_->factory()->null_value()));
      }
    }
  }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  uint32_t shadow_stack_offset = 0;
  if (v8_flags.trace_drumbrake_execution) {
    shadow_stack_offset = target_function->rets_slots_size() * kSlotSize;
    for (uint32_t i = 0; i < target_function->args_count(); i++) {
      shadow_stack_offset +=
          TracePush(target_function->arg_type(i).kind(), shadow_stack_offset);
    }

    // Make room for locals in shadow stack
    shadow_stack_offset += target_function->const_slots_size_in_bytes();
    for (size_t i = 0; i < target_function->locals_count(); i++) {
      shadow_stack_offset +=
          TracePush(target_function->local_type(i).kind(), shadow_stack_offset);
    }
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  code = target_function->GetCode();
}

void WasmInterpreterRuntime::ExecuteFunction(const uint8_t*& code,
                                             uint32_t func_index,
                                             uint32_t current_stack_size,
                                             uint32_t ref_stack_fp_offset,
                                             uint32_t slot_offset,
                                             uint32_t return_slot_offset) {
  WASM_STACK_CHECK(isolate_, code);

  // Execute an internal call.
  WasmBytecode* target_function = GetFunctionBytecode(func_index);
  DCHECK_NOT_NULL(target_function);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  ShadowStack* prev_shadow_stack = shadow_stack_;
  ShadowStack shadow_stack;
  if (v8_flags.trace_drumbrake_execution) {
    shadow_stack_ = &shadow_stack;
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  // This HandleScope is used for all handles created in instruction handlers.
  // W
```