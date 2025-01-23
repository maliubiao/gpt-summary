Response:
Let's break down the thought process for analyzing this V8 header file.

1. **Initial Scan for Keywords and Structure:**  The first step is a quick scan of the file looking for common C++ patterns and WebAssembly-related terms. Keywords like `inline`, `namespace v8::internal::wasm`, `WasmInterpreter`, `WasmBytecode`, `FrameState`, `GetCode`, `BeginExecution`, `Read`, `push`, `pop`, and template usage immediately stand out. The `#ifndef` guard suggests it's a header file. The initial `#if !V8_ENABLE_WEBASSEMBLY` confirms its Wasm relevance and potential error handling.

2. **Identify the Core Purpose:**  The namespace `v8::internal::wasm` strongly indicates a part of the V8 engine specifically dealing with WebAssembly. The filename `wasm-interpreter-inl.h` suggests this file contains *inline* function definitions related to the Wasm interpreter. The `.inl` suffix is a common convention for inline implementations in header files.

3. **Analyze Key Classes and Structures:**

    * **`WasmInterpreter` and `WasmInterpreter::CodeMap`:**  The `CodeMap` nested class within `WasmInterpreter` and methods like `GetCode`, `GetFunctionBytecode`, and `AddFunction` strongly suggest this component manages the compiled (or interpreted) Wasm code for each function.

    * **`WasmInterpreterThread` and `WasmInterpreterThread::Activation`:**  The `Thread` class and its nested `Activation` class, along with methods like `StartActivation` and `FinishActivation`, point to managing the execution state of Wasm functions, potentially in a multi-threaded environment. The term "activation" likely refers to a specific function call's context.

    * **`FrameState`:** This class appears to hold the state of a Wasm function call frame, including handle scopes (important for garbage collection in V8).

    * **`WasmBytecode`:** This seems to represent the actual bytecode instructions for a Wasm function. Methods like `return_type`, `arg_type`, `local_type`, and calculations for slot sizes reinforce this.

    * **Template Functions (`Read`, `push`, `pop`, `JSMax`, `JSMin`, `ExecuteRemS`, `ExecuteRemU`):**  These suggest common operations used during interpretation, parameterized by data type. The `JSMax` and `JSMin` functions hinting at JavaScript semantics are interesting.

    * **`WasmBytecodeGenerator`:**  This class seems to be responsible for *generating* the `WasmBytecode`. Methods like `I32Push`, `F32Push`, `RefPush`, `Emit`, and handling of blocks, branches, and signatures confirm this.

4. **Map Functionality to Sections:**  Organize the observed functionalities into logical groups:

    * **Code Management:** `WasmInterpreter::CodeMap`, `GetCode`, `GetFunctionBytecode`, `AddFunction`.
    * **Execution Management:** `WasmInterpreterThread`, `Activation`, `StartActivation`, `FinishActivation`, `BeginExecution`.
    * **Stack and Frame Handling:** `FrameState`, `GetInterpretedStack`.
    * **Data Access and Manipulation:** `Read`, `push`, `pop`, `ReadMemoryAddress`, `ReadGlobalIndex`.
    * **JavaScript Interoperability (Hints):** `JSMax`, `JSMin`, `JSToWasmWrapperPackedArraySize`.
    * **Bytecode Structure and Metadata:** `WasmBytecode`, `return_type`, `arg_type`, `local_type`, size calculations.
    * **Bytecode Generation:** `WasmBytecodeGenerator`, `I32Push`, `RefPush`, `EmitBranchOffset`, block management.

5. **Infer Relationships and Dependencies:** Notice how `WasmInterpreter` uses `CodeMap` and `WasmInterpreterThread`. `WasmBytecode` contains information derived from `FunctionSig`. `WasmBytecodeGenerator` produces `WasmBytecode`. These relationships paint a picture of the overall system.

6. **Address Specific Questions:**

    * **".tq" extension:**  The prompt explicitly mentions `.tq`. Since this file is `.h`, the answer is straightforward: it's not a Torque file.
    * **Relationship with JavaScript:** The presence of `JSMax` and `JSMin` and the function `JSToWasmWrapperPackedArraySize` strongly indicate some level of interaction between the Wasm interpreter and JavaScript. The example provided focuses on the semantic differences in NaN handling.
    * **Code Logic Reasoning:** Choose a relatively simple function like `JSMax`. Formulate example inputs covering NaN, positive/negative zero, and normal cases to illustrate the function's behavior.
    * **Common Programming Errors:**  Think about the context of a Wasm interpreter and what could go wrong. Stack overflows (related to frame size calculations) and type mismatches (relevant to `push` and `pop`) are good candidates. Provide concrete examples in JavaScript that *would* lead to these errors when translated to Wasm and executed by the interpreter.

7. **Refine and Structure the Output:**  Organize the findings clearly, using headings and bullet points. Provide concise explanations for each function and class. Ensure the JavaScript examples are clear and illustrative. Double-check that all parts of the prompt have been addressed.

Essentially, the process involves a combination of code reading comprehension, domain knowledge (WebAssembly and compiler/interpreter concepts), and the ability to connect individual code snippets to the bigger picture. The explicit questions in the prompt serve as guideposts to focus the analysis.
好的，让我们来分析一下 `v8/src/wasm/interpreter/wasm-interpreter-inl.h` 这个文件。

**文件功能概述:**

这个 `.h` 文件定义了 WebAssembly 解释器的内联函数。内联函数通常用于性能关键的代码路径，通过将函数体直接插入到调用点来减少函数调用的开销。从文件名和包含的头文件来看，这个文件主要负责以下几个方面：

1. **WebAssembly 代码的管理和访问:**
   - 提供了 `WasmInterpreter::CodeMap` 类来管理已解释的 WebAssembly 函数的代码信息。
   - 包含获取特定函数索引的解释器代码 (`GetCode`) 和字节码 (`GetFunctionBytecode`) 的方法。
   - 提供了添加函数代码信息 (`AddFunction`) 的方法。

2. **WebAssembly 解释器线程和激活的管理:**
   - 定义了 `WasmInterpreterThread` 和其内部类 `Activation`，用于管理解释器线程的执行状态。
   - 提供了启动 (`StartActivation`) 和完成 (`FinishActivation`) 函数调用的方法。
   - 可以获取特定运行时上下文的当前激活状态 (`GetCurrentActivationFor`).

3. **WebAssembly 函数的执行:**
   - 包含启动 WebAssembly 函数执行的 `BeginExecution` 方法。

4. **获取 WebAssembly 函数的返回值和栈信息:**
   - 提供了获取函数返回值 (`GetReturnValue`) 和解释器栈信息 (`GetInterpretedStack`) 的方法。
   - 可以获取栈帧中特定索引的函数索引 (`GetFunctionIndex`).

5. **设置 Trap 函数索引:**
   - 允许设置一个用于处理 WebAssembly trap 的函数索引 (`SetTrapFunctionIndex`).

6. **辅助函数和模板函数:**
   - 提供了从字节码流中读取特定类型数据的模板函数 `Read`。
   - 包含了遵循 JavaScript 语义的 `JSMax` 和 `JSMin` 模板函数。
   - 提供了读取内存地址 (`ReadMemoryAddress`) 和全局变量索引 (`ReadGlobalIndex`) 的辅助函数。
   - 定义了 `push` 和 `pop` 模板函数用于在解释器栈上推入和弹出值。
   - 包含了 WebAssembly 的取模运算函数 `ExecuteRemS` (有符号) 和 `ExecuteRemU` (无符号)。

7. **WebAssembly 字节码信息的访问:**
   - 提供了访问 `WasmBytecode` 对象的返回类型 (`return_type`)、参数类型 (`arg_type`) 和局部变量类型 (`local_type`) 的内联方法。
   - 包含获取不同类型值在栈上占用槽位大小 (`GetValueSizeInSlots`) 的方法。
   - 提供了计算函数参数和返回值在栈上占用槽位大小的方法 (`ArgsSizeInSlots`, `RetsSizeInSlots`)。
   - 包含了计算引用类型参数和返回值的数量的方法 (`RefArgsCount`, `RefRetsCount`).
   - 提供了检查函数签名是否包含 SIMD 类型 (`ContainsSimd`) 或引用/SIMD 类型参数 (`HasRefOrSimdArgs`) 的方法。
   - 包含了计算 JavaScript 到 WebAssembly 包装器所需的打包数组大小的方法 (`JSToWasmWrapperPackedArraySize`).
   - 提供了计算引用类型局部变量数量 (`RefLocalsCount`) 和局部变量占用槽位大小 (`LocalsSizeInSlots`) 的方法。
   - 提供了初始化栈帧槽位的函数 (`InitializeSlots`).

8. **WebAssembly 字节码生成器的辅助函数:**
   - 提供了判断指令是否允许写入寄存器的函数 (`ToRegisterIsAllowed`).
   - 包含了向字节码流中推送不同类型值的槽位偏移的函数 (`I32Push`, `I64Push`, `F32Push`, `F64Push`, `S128Push`, `RefPush`, `Push`).
   - 提供了推送栈上现有槽位副本 (`PushCopySlot`) 和常量槽位 (`PushConstSlot`) 的函数。
   - 包含了判断 Block 是否具有 void 签名 (`HasVoidSignature`) 以及获取 Block 的参数和返回值数量和类型的方法。
   - 提供了获取全局变量类型 (`GetGlobalType`) 和内存相关信息 (`IsMemory64`, `IsMultiMemory`) 的方法。
   - 包含了发射全局变量索引 (`EmitGlobalIndex`) 和分支偏移 (`EmitBranchOffset`, `EmitBranchTableOffset`, `EmitIfElseBranchOffset`, `EmitTryCatchBranchOffset`) 的方法。
   - 提供了开始 Else 块 (`BeginElseBlock`) 和获取函数签名 (`GetFunctionSignature`) 的方法。
   - 包含了获取栈顶元素类型 (`GetTopStackType`) 和当前分支深度 (`GetCurrentBranchDepth`) 的方法。
   - 提供了获取目标分支索引 (`GetTargetBranch`) 的方法。

**关于文件扩展名和 Torque:**

根据你的描述，如果 `v8/src/wasm/interpreter/wasm-interpreter-inl.h` 以 `.tq` 结尾，那么它才是 V8 Torque 源代码。由于当前文件是 `.h` 结尾，所以它是一个标准的 C++ 头文件，包含了内联函数的定义。

**与 JavaScript 的功能关系及示例:**

这个文件中的代码直接参与了 WebAssembly 代码的解释执行。当 JavaScript 代码调用一个 WebAssembly 函数时，V8 引擎会使用这里的解释器（如果启用了解释器或在某些特定情况下）来执行该函数。

`JSMax` 和 `JSMin` 这两个模板函数尤其体现了与 JavaScript 的关系。WebAssembly 的 `f32.max` 和 `f64.max` 指令的行为与 JavaScript 的 `Math.max` 略有不同，尤其是在处理 `NaN` 和 `-0` 的时候。

**JavaScript 示例:**

```javascript
console.log(Math.max(NaN, 1));   // 输出: NaN
console.log(Math.max(-0, 0));    // 输出: 0
console.log(Math.min(NaN, 1));   // 输出: NaN
console.log(Math.min(-0, 0));    // 输出: -0
```

与之对应的，WebAssembly 的 `f32.max` 和 `f64.max` 指令的行为如下（简化描述）：

- 如果其中一个操作数是 `NaN`，结果是 `NaN`。
- `max(+0, -0)` 和 `max(-0, +0)` 都会返回 `+0`。
- `min(+0, -0)` 和 `min(-0, +0)` 都会返回 `-0`。

`JSMax` 和 `JSMin` 的存在是为了确保在 WebAssembly 解释器中模拟这些 JavaScript 特有的行为。

**代码逻辑推理和假设输入/输出 (以 `JSMax` 为例):**

**假设输入:**

- `x = NaN`, `y = 5`
- `x = -0`, `y = 0`
- `x = 3`, `y = 7`

**代码逻辑 (`JSMax`):**

```c++
template <typename T>
inline T JSMax(T x, T y) {
  if (std::isnan(x) || std::isnan(y)) {
    return std::numeric_limits<T>::quiet_NaN();
  }
  if (std::signbit(x) < std::signbit(y)) return x;
  return x > y ? x : y;
}
```

**推理和输出:**

1. **输入: `x = NaN`, `y = 5`**
   - `std::isnan(x)` 为 true。
   - 输出: `NaN`

2. **输入: `x = -0`, `y = 0`**
   - `std::isnan(x)` 和 `std::isnan(y)` 都为 false。
   - `std::signbit(x)` 为 true (因为是 -0)，`std::signbit(y)` 为 false (因为是 0)。
   - `std::signbit(x) < std::signbit(y)` 为 false。
   - `x > y` 为 false (-0 不大于 0)。
   - 输出: `y` (即 `0`)

3. **输入: `x = 3`, `y = 7`**
   - `std::isnan(x)` 和 `std::isnan(y)` 都为 false。
   - `std::signbit(x)` 和 `std::signbit(y)` 都为 false。
   - `std::signbit(x) < std::signbit(y)` 为 false。
   - `x > y` 为 false。
   - 输出: `y` (即 `7`)

**用户常见的编程错误 (可能与此文件相关):**

虽然用户不会直接编写这个头文件中的代码，但理解这里的逻辑有助于避免与 WebAssembly 解释器执行相关的错误。

1. **栈溢出:** 如果 WebAssembly 函数的局部变量或调用栈过大，可能会导致解释器栈溢出。`WasmBytecode::InitializeSlots` 中检查了栈空间，但如果分配的栈空间不足，仍然可能发生问题。

   **JavaScript 示例 (导致 WebAssembly 中栈溢出的情况):**

   ```javascript
   function recursiveFunction() {
     recursiveFunction(); // 无终止条件的递归调用
   }

   // 假设此 JavaScript 函数被编译成 WebAssembly
   recursiveFunction();
   ```

2. **类型不匹配:** WebAssembly 是一门强类型语言。如果在 JavaScript 和 WebAssembly 之间传递参数或返回值时类型不匹配，可能会导致解释器出错。例如，尝试将一个浮点数作为整数传递给 WebAssembly 函数。

   **JavaScript 示例:**

   ```javascript
   // 假设 webAssemblyInstance.exports.add 是一个接收两个 i32 参数的 WebAssembly 函数
   webAssemblyInstance.exports.add(1.5, 2.7); // 传递了浮点数而不是整数
   ```

3. **访问越界内存:** WebAssembly 实例的内存是有限制的。尝试访问超出这个范围的内存会导致运行时错误。虽然这个文件更多关注解释器逻辑，但理解内存访问机制对于避免此类错误很重要。

   **JavaScript 示例:**

   ```javascript
   // 假设 memory 是 WebAssembly 实例的 Memory 对象
   const buffer = new Uint8Array(memory.buffer);
   buffer[65536] = 42; // 假设内存大小不足以访问此索引
   ```

总的来说，`v8/src/wasm/interpreter/wasm-interpreter-inl.h` 是 V8 引擎中 WebAssembly 解释器的核心组成部分，它定义了用于管理、执行和操作 WebAssembly 代码的关键内联函数。理解这个文件的功能有助于深入了解 V8 如何执行 WebAssembly 代码以及可能出现的相关问题。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_INTERPRETER_WASM_INTERPRETER_INL_H_
#define V8_WASM_INTERPRETER_WASM_INTERPRETER_INL_H_

#include "src/handles/handles-inl.h"
#include "src/wasm/interpreter/wasm-interpreter-runtime.h"
#include "src/wasm/interpreter/wasm-interpreter.h"
#include "src/wasm/wasm-module.h"

namespace v8 {
namespace internal {
namespace wasm {

inline InterpreterCode* WasmInterpreter::CodeMap::GetCode(
    uint32_t function_index) {
  DCHECK_LT(function_index, interpreter_code_.size());
  InterpreterCode* code = &interpreter_code_[function_index];
  if (V8_UNLIKELY(!code->bytecode && code->start)) {
    Preprocess(function_index);
  }
  return code;
}

inline WasmBytecode* WasmInterpreter::CodeMap::GetFunctionBytecode(
    uint32_t func_index) {
  DCHECK_LT(func_index, interpreter_code_.size());

  // This precompiles the target function.
  InterpreterCode* code = GetCode(func_index);
  return code->bytecode.get();
}

inline void WasmInterpreter::CodeMap::AddFunction(const WasmFunction* function,
                                                  const uint8_t* code_start,
                                                  const uint8_t* code_end) {
  DCHECK_EQ(interpreter_code_.size(), function->func_index);
  interpreter_code_.emplace_back(function, BodyLocalDecls(),
                                 const_cast<uint8_t*>(code_start),
                                 const_cast<uint8_t*>(code_end));
}

inline Isolate* WasmInterpreterThread::Activation::GetIsolate() const {
  return wasm_runtime_->GetIsolate();
}

inline WasmInterpreterThread::Activation*
WasmInterpreterThread::StartActivation(WasmInterpreterRuntime* wasm_runtime,
                                       Address frame_pointer,
                                       uint8_t* interpreter_fp,
                                       const FrameState& frame_state) {
  Run();
  activations_.emplace_back(std::make_unique<Activation>(
      this, wasm_runtime, frame_pointer, interpreter_fp, frame_state));
  return activations_.back().get();
}

inline void WasmInterpreterThread::FinishActivation() {
  DCHECK(!activations_.empty());
  activations_.pop_back();
  if (activations_.empty()) {
    if (state_ != State::TRAPPED && state_ != State::STOPPED) {
      Finish();
    }
  }
}

inline const FrameState* WasmInterpreterThread::GetCurrentActivationFor(
    const WasmInterpreterRuntime* wasm_runtime) const {
  for (int i = static_cast<int>(activations_.size()) - 1; i >= 0; i--) {
    if (activations_[i]->GetWasmRuntime() == wasm_runtime) {
      return &activations_[i]->GetCurrentFrame();
    }
  }
  return nullptr;
}

inline void WasmInterpreter::BeginExecution(
    WasmInterpreterThread* thread, uint32_t function_index,
    Address frame_pointer, uint8_t* interpreter_fp, uint32_t ref_stack_offset,
    const std::vector<WasmValue>& args) {
  codemap_.GetCode(function_index);
  wasm_runtime_->BeginExecution(thread, function_index, frame_pointer,
                                interpreter_fp, ref_stack_offset, &args);
}

inline void WasmInterpreter::BeginExecution(WasmInterpreterThread* thread,
                                            uint32_t function_index,
                                            Address frame_pointer,
                                            uint8_t* interpreter_fp) {
  codemap_.GetCode(function_index);
  wasm_runtime_->BeginExecution(thread, function_index, frame_pointer,
                                interpreter_fp, 0);
}

inline WasmValue WasmInterpreter::GetReturnValue(int index) const {
  return wasm_runtime_->GetReturnValue(index);
}

inline std::vector<WasmInterpreterStackEntry>
WasmInterpreter::GetInterpretedStack(Address frame_pointer) {
  return wasm_runtime_->GetInterpretedStack(frame_pointer);
}

inline int WasmInterpreter::GetFunctionIndex(Address frame_pointer,
                                             int index) const {
  return wasm_runtime_->GetFunctionIndex(frame_pointer, index);
}

inline void WasmInterpreter::SetTrapFunctionIndex(int32_t func_index) {
  wasm_runtime_->SetTrapFunctionIndex(func_index);
}

template <typename T>
inline T Read(const uint8_t*& code) {
  T res = base::ReadUnalignedValue<T>(reinterpret_cast<Address>(code));
  code += sizeof(T);
  return res;
}

// Returns the maximum of the two parameters according to JavaScript semantics.
template <typename T>
inline T JSMax(T x, T y) {
  if (std::isnan(x) || std::isnan(y)) {
    return std::numeric_limits<T>::quiet_NaN();
  }
  if (std::signbit(x) < std::signbit(y)) return x;
  return x > y ? x : y;
}

// Returns the minimum of the two parameters according to JavaScript semantics.
template <typename T>
inline T JSMin(T x, T y) {
  if (std::isnan(x) || std::isnan(y)) {
    return std::numeric_limits<T>::quiet_NaN();
  }
  if (std::signbit(x) < std::signbit(y)) return y;
  return x > y ? y : x;
}

inline uint8_t* ReadMemoryAddress(uint8_t*& code) {
  Address res =
      base::ReadUnalignedValue<Address>(reinterpret_cast<Address>(code));
  code += sizeof(Address);
  return reinterpret_cast<uint8_t*>(res);
}

inline uint32_t ReadGlobalIndex(const uint8_t*& code) {
  uint32_t res =
      base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(code));
  code += sizeof(uint32_t);
  return res;
}

template <typename T>
inline void push(uint32_t*& sp, const uint8_t*& code,
                 WasmInterpreterRuntime* wasm_runtime, T val) {
  uint32_t offset = Read<int32_t>(code);
  base::WriteUnalignedValue<T>(reinterpret_cast<Address>(sp + offset), val);
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution)
    wasm_runtime->TracePush<T>(offset * kSlotSize);
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
}

template <>
inline void push(uint32_t*& sp, const uint8_t*& code,
                 WasmInterpreterRuntime* wasm_runtime, WasmRef ref) {
  uint32_t offset = Read<int32_t>(code);
  uint32_t ref_stack_index = Read<int32_t>(code);
  base::WriteUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + offset),
                                      kSlotsZapValue);
  //*reinterpret_cast<uint64_t*>(sp + offset) = kSlotsZapValue;
  wasm_runtime->StoreWasmRef(ref_stack_index, ref);
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution)
    wasm_runtime->TracePush<WasmRef>(offset * kSlotSize);
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
}

template <typename T>
inline T pop(uint32_t*& sp, const uint8_t*& code,
             WasmInterpreterRuntime* wasm_runtime) {
  uint32_t offset = Read<int32_t>(code);
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) wasm_runtime->TracePop();
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  return base::ReadUnalignedValue<T>(reinterpret_cast<Address>(sp + offset));
}

template <>
inline WasmRef pop(uint32_t*& sp, const uint8_t*& code,
                   WasmInterpreterRuntime* wasm_runtime) {
  uint32_t ref_stack_index = Read<int32_t>(code);
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) wasm_runtime->TracePop();
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  return wasm_runtime->ExtractWasmRef(ref_stack_index);
}

template <typename T>
inline T ExecuteRemS(T lval, T rval) {
  if (rval == -1) return 0;
  return lval % rval;
}

template <typename T>
inline T ExecuteRemU(T lval, T rval) {
  return lval % rval;
}

inline ValueType WasmBytecode::return_type(size_t index) const {
  DCHECK_LT(index, return_count());
  return signature_->GetReturn(index);
}

inline ValueType WasmBytecode::arg_type(size_t index) const {
  DCHECK_LT(index, args_count());
  return signature_->GetParam(index);
}

inline ValueType WasmBytecode::local_type(size_t index) const {
  DCHECK_LT(index, locals_count());
  DCHECK_LT(index, interpreter_code_->locals.num_locals);
  return interpreter_code_->locals.local_types[index];
}

inline uint32_t GetValueSizeInSlots(ValueKind kind) {
  switch (kind) {
    case kI32:
      return sizeof(int32_t) / kSlotSize;
    case kI64:
      return sizeof(int64_t) / kSlotSize;
    case kF32:
      return sizeof(float) / kSlotSize;
    case kF64:
      return sizeof(double) / kSlotSize;
    case kS128:
      return sizeof(Simd128) / kSlotSize;
    case kRef:
    case kRefNull:
      return sizeof(WasmRef) / kSlotSize;
    default:
      UNREACHABLE();
  }
}

inline void FrameState::ResetHandleScope(Isolate* isolate) {
  DCHECK_NOT_NULL(handle_scope_);
  {
    HandleScope old(std::move(*handle_scope_));
    // The HandleScope destructor cleans up the old HandleScope.
  }
  // Now that the old HandleScope has been destroyed, make a new one.
  *handle_scope_ = HandleScope(isolate);
}

inline uint32_t WasmBytecode::ArgsSizeInSlots(const FunctionSig* sig) {
  uint32_t args_slots_size = 0;
  size_t args_count = sig->parameter_count();
  for (size_t i = 0; i < args_count; i++) {
    args_slots_size += GetValueSizeInSlots(sig->GetParam(i).kind());
  }
  return args_slots_size;
}

inline uint32_t WasmBytecode::RetsSizeInSlots(const FunctionSig* sig) {
  uint32_t rets_slots_size = 0;
  size_t return_count = static_cast<uint32_t>(sig->return_count());
  for (size_t i = 0; i < return_count; i++) {
    rets_slots_size += GetValueSizeInSlots(sig->GetReturn(i).kind());
  }
  return rets_slots_size;
}

inline uint32_t WasmBytecode::RefArgsCount(const FunctionSig* sig) {
  uint32_t refs_args_count = 0;
  size_t args_count = static_cast<uint32_t>(sig->parameter_count());
  for (size_t i = 0; i < args_count; i++) {
    ValueKind kind = sig->GetParam(i).kind();
    if (wasm::is_reference(kind)) refs_args_count++;
  }
  return refs_args_count;
}

inline uint32_t WasmBytecode::RefRetsCount(const FunctionSig* sig) {
  uint32_t refs_rets_count = 0;
  size_t return_count = static_cast<uint32_t>(sig->return_count());
  for (size_t i = 0; i < return_count; i++) {
    ValueKind kind = sig->GetReturn(i).kind();
    if (wasm::is_reference(kind)) refs_rets_count++;
  }
  return refs_rets_count;
}

inline bool WasmBytecode::ContainsSimd(const FunctionSig* sig) {
  size_t args_count = static_cast<uint32_t>(sig->parameter_count());
  for (size_t i = 0; i < args_count; i++) {
    if (sig->GetParam(i).kind() == kS128) return true;
  }

  size_t return_count = static_cast<uint32_t>(sig->return_count());
  for (size_t i = 0; i < return_count; i++) {
    if (sig->GetReturn(i).kind() == kS128) return true;
  }

  return false;
}

inline bool WasmBytecode::HasRefOrSimdArgs(const FunctionSig* sig) {
  size_t args_count = static_cast<uint32_t>(sig->parameter_count());
  for (size_t i = 0; i < args_count; i++) {
    ValueKind kind = sig->GetParam(i).kind();
    if (wasm::is_reference(kind) || kind == kS128) return true;
  }
  return false;
}

inline uint32_t WasmBytecode::JSToWasmWrapperPackedArraySize(
    const FunctionSig* sig) {
  static_assert(kSystemPointerSize == 8);

  uint32_t args_size = 0;
  size_t args_count = static_cast<uint32_t>(sig->parameter_count());
  for (size_t i = 0; i < args_count; i++) {
    switch (sig->GetParam(i).kind()) {
      case kI32:
      case kF32:
        args_size += sizeof(int32_t);
        break;
      case kI64:
      case kF64:
        args_size += sizeof(int64_t);
        break;
      case kS128:
        args_size += sizeof(Simd128);
        break;
      case kRef:
      case kRefNull:
        // Make sure Ref slots are 64-bit aligned.
        args_size += (args_size & 0x04);
        args_size += sizeof(WasmRef);
        break;
      default:
        UNREACHABLE();
    }
  }

  uint32_t rets_size = 0;
  size_t rets_count = static_cast<uint32_t>(sig->return_count());
  for (size_t i = 0; i < rets_count; i++) {
    switch (sig->GetReturn(i).kind()) {
      case kI32:
      case kF32:
        rets_size += sizeof(int32_t);
        break;
      case kI64:
      case kF64:
        rets_size += sizeof(int64_t);
        break;
      case kS128:
        rets_size += sizeof(Simd128);
        break;
      case kRef:
      case kRefNull:
        // Make sure Ref slots are 64-bit aligned.
        rets_size += (rets_size & 0x04);
        rets_size += sizeof(WasmRef);
        break;
      default:
        UNREACHABLE();
    }
  }

  uint32_t size = std::max(args_size, rets_size);
  // Make sure final size is 64-bit aligned.
  size += (size & 0x04);
  return size;
}

inline uint32_t WasmBytecode::RefLocalsCount(const InterpreterCode* wasm_code) {
  uint32_t refs_locals_count = 0;
  size_t locals_count = wasm_code->locals.num_locals;
  for (size_t i = 0; i < locals_count; i++) {
    ValueKind kind = wasm_code->locals.local_types[i].kind();
    if (wasm::is_reference(kind)) {
      refs_locals_count++;
    }
  }
  return refs_locals_count;
}

inline uint32_t WasmBytecode::LocalsSizeInSlots(
    const InterpreterCode* wasm_code) {
  uint32_t locals_slots_size = 0;
  size_t locals_count = wasm_code->locals.num_locals;
  for (size_t i = 0; i < locals_count; i++) {
    locals_slots_size +=
        GetValueSizeInSlots(wasm_code->locals.local_types[i].kind());
  }
  return locals_slots_size;
}

inline bool WasmBytecode::InitializeSlots(uint8_t* sp,
                                          size_t stack_space) const {
  // Check for overflow
  if (total_frame_size_in_bytes_ > stack_space) {
    return false;
  }

  uint32_t args_slots_size_in_bytes = args_slots_size() * kSlotSize;
  uint32_t rets_slots_size_in_bytes = rets_slots_size() * kSlotSize;
  uint32_t const_slots_size_in_bytes = this->const_slots_size_in_bytes();

  uint8_t* start_const_area =
      sp + args_slots_size_in_bytes + rets_slots_size_in_bytes;

  // Initialize const slots
  if (const_slots_size_in_bytes) {
    memcpy(start_const_area, const_slots_values_.data(),
           const_slots_size_in_bytes);
  }

  // Initialize local slots
  memset(start_const_area + const_slots_size_in_bytes, 0,
         locals_slots_size() * kSlotSize);

  return true;
}

inline bool WasmBytecodeGenerator::ToRegisterIsAllowed(
    const WasmInstruction& instr) {
  if (!instr.SupportsToRegister()) return false;

  // Even if the instruction is marked as supporting ToRegister, reference
  // values should not be stored in the register.
  switch (instr.opcode) {
    case kExprGlobalGet: {
      ValueKind kind = GetGlobalType(instr.optional.index);
      return !wasm::is_reference(kind) && kind != kS128;
    }
    case kExprSelect:
    case kExprSelectWithType: {
      DCHECK_GE(stack_size(), 2);
      ValueKind kind = slots_[stack_[stack_size() - 2]].kind();
      return !wasm::is_reference(kind) && kind != kS128;
    }
    default:
      return true;
  }
}

inline void WasmBytecodeGenerator::I32Push(bool emit) {
  uint32_t slot_index = _PushSlot(kWasmI32);
  uint32_t slot_offset = slots_[slot_index].slot_offset;
  if (emit) Emit(&slot_offset, sizeof(uint32_t));
}

inline void WasmBytecodeGenerator::I64Push(bool emit) {
  uint32_t slot_index = _PushSlot(kWasmI64);
  uint32_t slot_offset = slots_[slot_index].slot_offset;
  if (emit) Emit(&slot_offset, sizeof(uint32_t));
}

inline void WasmBytecodeGenerator::F32Push(bool emit) {
  uint32_t slot_index = _PushSlot(kWasmF32);
  uint32_t slot_offset = slots_[slot_index].slot_offset;
  if (emit) Emit(&slot_offset, sizeof(uint32_t));
}

inline void WasmBytecodeGenerator::F64Push(bool emit) {
  uint32_t slot_index = _PushSlot(kWasmF64);
  uint32_t slot_offset = slots_[slot_index].slot_offset;
  if (emit) Emit(&slot_offset, sizeof(uint32_t));
}

inline void WasmBytecodeGenerator::S128Push(bool emit) {
  uint32_t slot_index = _PushSlot(kWasmS128);
  uint32_t slot_offset = slots_[slot_index].slot_offset;
  if (emit) Emit(&slot_offset, sizeof(uint32_t));
}

inline void WasmBytecodeGenerator::RefPush(ValueType type, bool emit) {
  uint32_t slot_index = _PushSlot(type);
  uint32_t slot_offset = slots_[slot_index].slot_offset;
  if (emit) {
    Emit(&slot_offset, sizeof(uint32_t));
    Emit(&slots_[slot_index].ref_stack_index, sizeof(uint32_t));
  }
}

inline void WasmBytecodeGenerator::Push(ValueType type) {
  switch (type.kind()) {
    case kI32:
      I32Push();
      break;
    case kI64:
      I64Push();
      break;
    case kF32:
      F32Push();
      break;
    case kF64:
      F64Push();
      break;
    case kS128:
      S128Push();
      break;
    case kRef:
    case kRefNull:
      RefPush(type);
      break;
    default:
      UNREACHABLE();
  }
}

inline void WasmBytecodeGenerator::PushCopySlot(uint32_t from) {
  DCHECK_LT(from, stack_.size());
  PushSlot(stack_[from]);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  TracePushCopySlot(from);
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
}

inline void WasmBytecodeGenerator::PushConstSlot(uint32_t slot_index) {
  PushSlot(slot_index);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  TracePushConstSlot(slot_index);
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
}

inline bool WasmBytecodeGenerator::HasVoidSignature(
    const WasmBytecodeGenerator::BlockData& block_data) const {
  if (block_data.signature_.value_type() == kWasmBottom) {
    const FunctionSig* sig =
        module_->signature(block_data.signature_.sig_index);
    return 0 == (sig->parameter_count() + sig->return_count());
  } else if (block_data.signature_.value_type() == kWasmVoid) {
    return true;
  }
  return false;
}

inline uint32_t WasmBytecodeGenerator::ParamsCount(
    const WasmBytecodeGenerator::BlockData& block_data) const {
  if (block_data.signature_.value_type() == kWasmBottom) {
    const FunctionSig* sig =
        module_->signature(block_data.signature_.sig_index);
    return static_cast<uint32_t>(sig->parameter_count());
  }
  return 0;
}

inline ValueType WasmBytecodeGenerator::GetParamType(
    const WasmBytecodeGenerator::BlockData& block_data, size_t index) const {
  DCHECK_EQ(block_data.signature_.value_type(), kWasmBottom);
  const FunctionSig* sig = module_->signature(block_data.signature_.sig_index);
  return sig->GetParam(index);
}

inline uint32_t WasmBytecodeGenerator::ReturnsCount(
    const WasmBytecodeGenerator::BlockData& block_data) const {
  if (block_data.signature_.value_type() == kWasmBottom) {
    const FunctionSig* sig =
        module_->signature(block_data.signature_.sig_index);
    return static_cast<uint32_t>(sig->return_count());
  } else if (block_data.signature_.value_type() == kWasmVoid) {
    return 0;
  }
  return 1;
}

inline ValueType WasmBytecodeGenerator::GetReturnType(
    const WasmBytecodeGenerator::BlockData& block_data, size_t index) const {
  DCHECK_NE(block_data.signature_.value_type(), kWasmVoid);
  if (block_data.signature_.value_type() == kWasmBottom) {
    const FunctionSig* sig =
        module_->signature(block_data.signature_.sig_index);
    return sig->GetReturn(index);
  }
  DCHECK_EQ(index, 0);
  return block_data.signature_.value_type();
}

inline ValueKind WasmBytecodeGenerator::GetGlobalType(uint32_t index) const {
  return module_->globals[index].type.kind();
}

inline bool WasmBytecodeGenerator::IsMemory64() const {
  return !module_->memories.empty() && module_->memories[0].is_memory64();
}

inline bool WasmBytecodeGenerator::IsMultiMemory() const {
  return module_->memories.size() > 1;
}

inline void WasmBytecodeGenerator::EmitGlobalIndex(uint32_t index) {
  Emit(&index, sizeof(index));
}

inline uint32_t WasmBytecodeGenerator::GetCurrentBranchDepth() const {
  DCHECK_GE(current_block_index_, 0);
  int index = blocks_[current_block_index_].parent_block_index_;
  uint32_t depth = 0;
  while (index >= 0) {
    depth++;
    index = blocks_[index].parent_block_index_;
  }
  return depth;
}

inline int32_t WasmBytecodeGenerator::GetTargetBranch(uint32_t delta) const {
  int index = current_block_index_;
  while (delta--) {
    DCHECK_GE(index, 0);
    index = blocks_[index].parent_block_index_;
  }
  return index;
}

inline void WasmBytecodeGenerator::EmitBranchOffset(uint32_t delta) {
  int32_t target_branch_index = GetTargetBranch(delta);
  DCHECK_GE(target_branch_index, 0);
  blocks_[target_branch_index].branch_code_offsets_.emplace_back(
      CurrentCodePos());

  const uint32_t current_code_offset = CurrentCodePos();
  Emit(&current_code_offset, sizeof(current_code_offset));
}

inline void WasmBytecodeGenerator::EmitBranchTableOffset(uint32_t delta,
                                                         uint32_t code_pos) {
  int32_t target_branch_index = GetTargetBranch(delta);
  DCHECK_GE(target_branch_index, 0);
  blocks_[target_branch_index].branch_code_offsets_.emplace_back(code_pos);

  Emit(&code_pos, sizeof(code_pos));
}

inline void WasmBytecodeGenerator::EmitIfElseBranchOffset() {
  // Initially emits offset to jump the end of the 'if' block. If we meet an
  // 'else' instruction later, this offset needs to be updated with the offset
  // to the beginning of that 'else' block.
  blocks_[current_block_index_].branch_code_offsets_.emplace_back(
      CurrentCodePos());

  const uint32_t current_code_offset = CurrentCodePos();
  Emit(&current_code_offset, sizeof(current_code_offset));
}

inline void WasmBytecodeGenerator::EmitTryCatchBranchOffset() {
  // Initially emits offset to jump the end of the 'try/catch' blocks. When we
  // meet the corresponding 'end' instruction later, this offset needs to be
  // updated with the offset to the 'end' instruction.
  blocks_[current_block_index_].branch_code_offsets_.emplace_back(
      CurrentCodePos());

  const uint32_t current_code_offset = CurrentCodePos();
  Emit(&current_code_offset, sizeof(current_code_offset));
}

inline void WasmBytecodeGenerator::BeginElseBlock(uint32_t if_block_index,
                                                  bool dummy) {
  EndBlock(kExprElse);  // End matching if block.
  RestoreIfElseParams(if_block_index);

  int32_t else_block_index =
      BeginBlock(kExprElse, blocks_[if_block_index].signature_);
  blocks_[if_block_index].if_else_block_index_ = else_block_index;
  blocks_[else_block_index].if_else_block_index_ = if_block_index;
  blocks_[else_block_index].first_block_index_ =
      blocks_[if_block_index].first_block_index_;
}

inline const FunctionSig* WasmBytecodeGenerator::GetFunctionSignature(
    uint32_t function_index) const {
  return module_->functions[function_index].sig;
}

inline ValueKind WasmBytecodeGenerator::GetTopStackType(
    RegMode reg_mode) const {
  switch (reg_mode) {
    case RegMode::kNoReg:
      if (stack_.empty()) return kI32;  // not used
      return slots_[stack_[stack_top_index()]].kind();
    case RegMode::kI32Reg:
      return kI32;
    case RegMode::kI64Reg:
      return kI64;
    case RegMode::kF32Reg:
      return kF32;
    case RegMode::kF64Reg:
      return kF64;
    case RegMode::kAnyReg:
    default:
      UNREACHABLE();
  }
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8

#endif  // V8_WASM_INTERPRETER_WASM_INTERPRETER_INL_H_
```