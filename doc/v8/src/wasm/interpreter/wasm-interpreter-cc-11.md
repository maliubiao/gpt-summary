Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The user wants a summary of the functionality of the provided C++ code snippet, specifically focusing on its role within the V8 JavaScript engine's WebAssembly interpreter. The prompt also includes specific constraints related to Torque, JavaScript examples, logical reasoning, common errors, and the fact that this is part 12 of 15.

2. **Identify the Core Function:**  The code snippet is a case statement within a larger function (likely processing a stream of WebAssembly instructions). Each `case` corresponds to a different WebAssembly opcode (e.g., `kExprCallFunction`, `kExprLocalGet`, `kExprI32Add`). The code within each case seems to be generating lower-level instructions or making calls to handler functions (`EMIT_INSTR_HANDLER`). This suggests the core function of this code is *compiling* or *translating* WebAssembly instructions into a form that the interpreter can execute.

3. **Break Down by Opcode Categories:** The opcodes can be grouped logically:
    * **Function Calls (`kExprCallFunction`, `kExprCallIndirect`, `kExprCallRef`, `kExprReturnCallIndirect`, `kExprReturnCallRef`):** These handle invoking functions, both direct and indirect calls. Key aspects are managing the stack for arguments and return values.
    * **Stack Manipulation (`kExprDrop`, `kExprSelect`):**  These instructions alter the interpreter's value stack.
    * **Local Variables (`kExprLocalGet`, `kExprLocalSet`, `kExprLocalTee`):** These access and modify local variables within a function's scope.
    * **Global Variables (`kExprGlobalGet`, `kExprGlobalSet`):**  These access and modify global variables accessible across the module.
    * **Table Access (`kExprTableGet`, `kExprTableSet`):** These deal with function tables used for indirect calls.
    * **Memory Access (`kExprI32LoadMem...`, `kExprI32StoreMem...`, `kExprMemoryGrow`, `kExprMemorySize`):** These handle reading from and writing to linear memory, as well as managing the size of the memory.
    * **Constants (`kExprI32Const`, `kExprI64Const`, etc.):** These push constant values onto the stack.
    * **Arithmetic and Logic Operations (`kExprI32Add`, `kExprI64Sub`, etc.):** These perform basic operations.

4. **Address Specific Constraints:**

    * **Torque:** The prompt explicitly asks about `.tq` files. Since this file is `.cc`, it's *not* a Torque file. Torque is a higher-level language used to generate C++ code for V8's built-in functions.
    * **JavaScript Relationship:**  WebAssembly's purpose is to run alongside JavaScript in web browsers. The connection lies in how JavaScript can load, instantiate, and interact with WebAssembly modules. A simple example would be calling a WebAssembly function from JavaScript.
    * **Logical Reasoning (Input/Output):** Choose a simple opcode, like `kExprI32Const`. If the input is the instruction `kExprI32Const` with a value of `42`, the output is the interpreter's stack having `42` pushed onto it.
    * **Common Programming Errors:** Focus on errors related to WebAssembly's stack-based nature, type mismatches, and memory access violations. Examples like stack underflow or trying to store the wrong type into memory are relevant.

5. **Synthesize the Functionality Summary:** Combine the breakdown by opcode category and the analysis of the code's actions (pushing, popping, emitting handler calls) into a concise description of the file's purpose. Emphasize its role in the WebAssembly interpreter.

6. **Consider the "Part 12 of 15" Context:** This suggests that the file handles a significant portion of WebAssembly's instruction set, but not all of it. The earlier parts likely handle setup and control flow, while later parts might deal with more specialized instructions or cleanup.

7. **Structure the Answer:** Organize the information into clear sections addressing each part of the prompt: core functionality, relationship to Torque, JavaScript examples, logical reasoning, common errors, and the final summary. Use formatting (like bullet points) to improve readability.

8. **Refine and Iterate:** Review the answer for clarity, accuracy, and completeness. Ensure it addresses all aspects of the prompt. For instance, I initially might have focused too much on the *execution* of the instructions. However, the code is primarily about *preparing* the instructions for execution by generating the necessary interpreter actions. I'd adjust the wording to reflect this more accurately.

By following this process, I can construct a comprehensive and accurate answer that addresses all the user's requirements and constraints.
好的，根据你提供的代码片段，以下是 `v8/src/wasm/interpreter/wasm-interpreter.cc` 文件第 12 部分的功能归纳：

**核心功能：WebAssembly 指令的解释执行（针对函数调用、控制流、局部/全局变量、内存访问等操作）**

这段代码是 WebAssembly 解释器实现的核心部分，负责处理各种 WebAssembly 指令的执行逻辑。它通过一个大的 `switch` 语句，针对不同的 WebAssembly 操作码 (`instr.opcode`)，生成相应的解释器操作。

**具体功能分解：**

1. **函数调用 (Call/CallIndirect/CallRef/ReturnCall...)：**
   - 处理直接函数调用 (`kExprCallFunction`)、间接函数调用 (`kExprCallIndirect`) 和引用调用 (`kExprCallRef`)。
   - 处理尾调用优化 (`kExprReturnCallFunction`, `kExprReturnCallIndirect`, `kExprReturnCallRef`)。
   - 在调用前后进行栈帧的管理，包括参数的弹出和返回值的压入。
   - 调用解释器处理函数 (`EMIT_INSTR_HANDLER_WITH_PC`) 来执行实际的调用逻辑。
   - 记录可能抛出异常的指令 (`eh_data_.RecordPotentialExceptionThrowingInstruction`)。

2. **控制流 (Drop/Select)：**
   - `kExprDrop`: 将栈顶的值弹出，实现值的丢弃。
   - `kExprSelect`/`kExprSelectWithType`: 根据条件选择两个值中的一个，并压入栈顶。

3. **局部变量 (LocalGet/LocalSet/LocalTee)：**
   - `kExprLocalGet`: 将局部变量的值复制到栈顶。
   - `kExprLocalSet`: 将栈顶的值存储到局部变量。
   - `kExprLocalTee`: 将栈顶的值存储到局部变量，并保留一份副本在栈顶。

4. **全局变量 (GlobalGet/GlobalSet)：**
   - `kExprGlobalGet`: 将全局变量的值复制到栈顶。
   - `kExprGlobalSet`: 将栈顶的值存储到全局变量。

5. **表操作 (TableGet/TableSet)：**
   - `kExprTableGet`: 从指定的表中获取元素（函数引用），并压入栈顶。
   - `kExprTableSet`: 将栈顶的值（函数引用）存储到指定的表中。

6. **内存操作 (Load/Store/MemoryGrow/MemorySize)：**
   - `kExprI32LoadMem...`/`kExprI64LoadMem...`/`kExprF32LoadMem`/`kExprF64LoadMem`: 从线性内存中加载不同类型的值到栈顶。
   - `kExprI32StoreMem...`/`kExprI64StoreMem...`/`kExprF32StoreMem`/`kExprF64StoreMem`: 将栈顶的值存储到线性内存中。
   - `kExprMemoryGrow`: 增加线性内存的大小。
   - `kExprMemorySize`: 获取当前线性内存的大小。

7. **常量 (Const)：**
   - `kExprI32Const`/`kExprI64Const`/`kExprF32Const`/`kExprF64Const`: 将常量值压入栈顶。

8. **比较运算 (如 I32Eq, I64Ne, F32Lt...)：**
   - 执行各种类型的比较运算，并将结果（通常是 i32 类型的 0 或 1）压入栈顶。

**关于 .tq 文件：**

如果 `v8/src/wasm/interpreter/wasm-interpreter.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种用于编写 V8 内部函数的领域特定语言，它可以生成高效的 C++ 代码。 然而，根据你提供的文件名，它以 `.cc` 结尾，所以它是标准的 C++ 源代码。

**与 JavaScript 的关系及示例：**

WebAssembly 旨在与 JavaScript 并行运行。JavaScript 可以加载、编译和实例化 WebAssembly 模块，并调用其中导出的函数。

```javascript
// 假设你有一个编译好的 WebAssembly 模块实例叫做 'wasmInstance'
const addFunction = wasmInstance.exports.add; // 获取导出的名为 'add' 的函数

const result = addFunction(5, 10); // 从 JavaScript 调用 WebAssembly 函数
console.log(result); // 输出 WebAssembly 函数的返回值
```

在这个例子中，`v8/src/wasm/interpreter/wasm-interpreter.cc` 中的代码就负责执行 `addFunction` 内部的 WebAssembly 指令。

**代码逻辑推理（假设输入与输出）：**

假设输入的 WebAssembly 指令是 `kExprI32Const`，并且其值为 `100`。

* **输入:** `instr.opcode = kExprI32Const`, `instr.optional.i32 = 100`
* **代码逻辑:** 进入 `case kExprI32Const:` 分支，然后进入 `case kS2S:` 分支（假设当前的执行模式是 `kS2S`，Stack-to-Stack）。`PushConstSlot<int32_t>(instr.optional.i32)` 会被调用。
* **输出:** 解释器内部的栈顶会压入一个值为 `100` 的槽位，并且该槽位的类型被标记为 `kI32`。

**用户常见的编程错误（在 WebAssembly 层面，解释器会捕获）：**

1. **类型不匹配：**  例如，尝试将一个浮点数存储到需要整数的内存位置，或者在函数调用时传递了错误类型的参数。解释器在执行 `kExprLocalSet` 或 `kExprCallFunction` 等指令时会进行类型检查。

   ```c++
   // 例如，如果栈顶是 f32，但尝试存储到 i32 类型的局部变量
   case kExprLocalSet: {
       // ...
       const ValueType value_type = slots_[stack_[instr.optional.index]].value_type;
       const ValueKind kind = value_type.kind();
       DCHECK(CheckEqualKind(kind, top_stack_slot_type)); // 这里会检查类型是否匹配
       // ...
   }
   ```

2. **栈溢出/下溢：**  在执行需要栈上有特定数量值的指令时，如果栈为空或者值不足，会导致错误。例如，在执行二元运算时，需要栈顶至少有两个操作数。

   ```c++
   case kExprI32Add: {
       DCHECK_GE(stack_size(), 2); // 确保栈上有至少两个元素
       // ...
   }
   ```

3. **越界内存访问：** 尝试读取或写入超出线性内存边界的位置。解释器在执行 `kExprI32LoadMem` 或 `kExprI32StoreMem` 等指令时会进行边界检查。

   ```c++
   // 内存访问相关的指令通常会调用底层的内存访问函数，这些函数会进行边界检查
   case kExprI32LoadMem: {
       EMIT_INSTR_HANDLER_WITH_PC(s2s_I32LoadMem, instr.pc);
       // ...
   }
   ```

**第 12 部分功能归纳：**

作为 15 个部分中的第 12 部分，这段代码主要集中在处理 WebAssembly 的核心执行逻辑，涵盖了函数调用、基本的控制流操作、局部和全局变量的访问以及内存的读写。它负责将高级的 WebAssembly 指令转化为解释器可以理解和执行的低级操作。由于是中间部分，它依赖于之前部分建立的解释器框架和数据结构，并为后续部分处理更复杂的指令或优化做准备。 这部分代码体现了解释器执行 WebAssembly 代码时的核心机制。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第12部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
);
        } else {
          EMIT_INSTR_HANDLER_WITH_PC(s2s_CallFunction, instr.pc);
        }
      }
      EmitI32Const(function_index);
      EmitI32Const(static_cast<uint32_t>(stack_.size()));
      EmitI32Const(slot_offset);
      EmitI32Const(ref_stack_fp_offset);

      // Function arguments are popped from the stack.
      for (size_t index = sig->parameter_count(); index > 0; index--) {
        Pop(sig->GetParam(index - 1).kind(), false);
      }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution) {
        EmitI32Const(rets_slots.empty()
                         ? 0
                         : slots_[rets_slots[0]].slot_offset * kSlotSize);
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

      if (!is_tail_call) {
        eh_data_.RecordPotentialExceptionThrowingInstruction(instr.opcode,
                                                             CurrentCodePos());
      }

      // Function results are pushed to the stack.
      for (size_t index = 0; index < sig->return_count(); index++) {
        const ValueType value_type = sig->GetReturn(index);
        const ValueKind kind = value_type.kind();
        switch (kind) {
          case kI32:
          case kI64:
          case kF32:
          case kF64:
          case kS128:
          case kRef:
          case kRefNull:
            PushSlot(rets_slots[index]);
            SetSlotType(stack_top_index(), value_type);
            break;
          default:
            UNREACHABLE();
        }
      }

      // If this is a tail call, the following instructions in this block are
      // unreachable.
      if (is_tail_call) {
        SetUnreachableMode();
      }

      return RegMode::kNoReg;
    }
    case kExprCallIndirect:
    case kExprReturnCallIndirect: {
      const FunctionSig* sig =
          module_->signature(instr.optional.indirect_call.sig_index);

      const bool is_tail_call = (instr.opcode == kExprReturnCallIndirect);
      uint32_t slot_offset = GetStackFrameSize() * kSlotSize;
      uint32_t ref_stack_fp_offset = ref_slots_count_;

      // Reserve space for return values.
      std::vector<uint32_t> rets_slots;
      rets_slots.resize(sig->return_count());
      for (size_t index = 0; index < sig->return_count(); index++) {
        rets_slots[index] = is_tail_call ? static_cast<uint32_t>(index)
                                         : CreateSlot(sig->GetReturn(index));
      }

      InitSlotsForFunctionArgs(sig, true);

      if (is_tail_call) {
        EMIT_INSTR_HANDLER_WITH_PC(s2s_ReturnCallIndirect, instr.pc);
        EmitI32Const(WasmBytecode::RetsSizeInSlots(sig) * kSlotSize);
        EmitI32Const(WasmBytecode::ArgsSizeInSlots(sig) * kSlotSize);
        EmitI32Const(WasmBytecode::RefRetsCount(sig));
        EmitI32Const(WasmBytecode::RefArgsCount(sig));
      } else {
        EMIT_INSTR_HANDLER_WITH_PC(s2s_CallIndirect, instr.pc);
      }

      // Pops the index of the function to call.
      I32Pop();

      EmitI32Const(instr.optional.indirect_call.table_index);
      EmitI32Const(instr.optional.indirect_call.sig_index);

      EmitI32Const(stack_size());
      EmitI32Const(slot_offset);
      EmitI32Const(ref_stack_fp_offset);

      // Function arguments are popped from the stack.
      for (size_t index = sig->parameter_count(); index > 0; index--) {
        Pop(sig->GetParam(index - 1).kind(), false);
      }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution) {
        EmitI32Const(rets_slots.empty()
                         ? 0
                         : slots_[rets_slots[0]].slot_offset * kSlotSize);
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

      if (!is_tail_call) {
        eh_data_.RecordPotentialExceptionThrowingInstruction(instr.opcode,
                                                             CurrentCodePos());
      }

      // Function result is pushed to the stack.
      for (size_t index = 0; index < sig->return_count(); index++) {
        ValueType value_type = sig->GetReturn(index);
        switch (value_type.kind()) {
          case kI32:
          case kI64:
          case kF32:
          case kF64:
          case kS128:
          case kRef:
          case kRefNull:
            PushSlot(rets_slots[index]);
            SetSlotType(stack_top_index(), value_type);
            break;
          default:
            UNREACHABLE();
        }
      }

      // If this is a tail call, the following instructions in this block are
      // unreachable.
      if (is_tail_call) {
        SetUnreachableMode();
      }

      return RegMode::kNoReg;
    }

    case kExprCallRef:
    case kExprReturnCallRef: {
      const FunctionSig* sig = module_->signature(instr.optional.index);
      const bool is_tail_call = (instr.opcode == kExprReturnCallRef);
      uint32_t slot_offset = GetStackFrameSize() * kSlotSize;
      uint32_t ref_stack_fp_offset = ref_slots_count_;

      // Reserve space for return values.
      std::vector<uint32_t> rets_slots;
      rets_slots.resize(sig->return_count());
      for (size_t index = 0; index < sig->return_count(); index++) {
        rets_slots[index] = is_tail_call ? static_cast<uint32_t>(index)
                                         : CreateSlot(sig->GetReturn(index));
      }

      InitSlotsForFunctionArgs(sig, true);

      if (is_tail_call) {
        EMIT_INSTR_HANDLER_WITH_PC(s2s_ReturnCallRef, instr.pc);
        EmitI32Const(WasmBytecode::RetsSizeInSlots(sig) * kSlotSize);
        EmitI32Const(WasmBytecode::ArgsSizeInSlots(sig) * kSlotSize);
        EmitI32Const(WasmBytecode::RefRetsCount(sig));
        EmitI32Const(WasmBytecode::RefArgsCount(sig));
      } else {
        EMIT_INSTR_HANDLER_WITH_PC(s2s_CallRef, instr.pc);
      }

      // Pops the function to call.
      RefPop();

      EmitI32Const(instr.optional.index);  // Signature index.
      EmitI32Const(stack_size());
      EmitI32Const(slot_offset);
      EmitI32Const(ref_stack_fp_offset);

      // Function arguments are popped from the stack.
      for (size_t index = sig->parameter_count(); index > 0; index--) {
        Pop(sig->GetParam(index - 1).kind(), false);
      }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution) {
        EmitI32Const(rets_slots.empty()
                         ? 0
                         : slots_[rets_slots[0]].slot_offset * kSlotSize);
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

      if (!is_tail_call) {
        eh_data_.RecordPotentialExceptionThrowingInstruction(instr.opcode,
                                                             CurrentCodePos());
      }

      // Function result is pushed to the stack.
      for (size_t index = 0; index < sig->return_count(); index++) {
        const ValueType value_type = sig->GetReturn(index);
        const ValueKind kind = value_type.kind();
        switch (kind) {
          case kI32:
          case kI64:
          case kF32:
          case kF64:
          case kS128:
          case kRef:
          case kRefNull:
            PushSlot(rets_slots[index]);
            SetSlotType(stack_top_index(), value_type);
            break;
          default:
            UNREACHABLE();
        }
      }

      // If this is a tail call, the following instructions in this block are
      // unreachable.
      if (is_tail_call) {
        SetUnreachableMode();
      }

      return RegMode::kNoReg;
    }

    case kExprDrop: {
      switch (top_stack_slot_type) {
        case kI32:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I32Drop);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I32Drop);
              I32Pop();
              return RegMode::kNoReg;
          }
          break;
        case kI64:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I64Drop);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I64Drop);
              I64Pop();
              return RegMode::kNoReg;
          }
          break;
        case kF32:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F32Drop);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F32Drop);
              F32Pop();
              return RegMode::kNoReg;
          }
          break;
        case kF64:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F64Drop);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F64Drop);
              F64Pop();
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_S128Drop);
              S128Pop();
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_RefDrop);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_RefDrop);
              RefPop();
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kExprSelect:
    case kExprSelectWithType: {
      DCHECK_GE(stack_size(), 2);
      switch (slots_[stack_[stack_size() - 2]].kind()) {
        case kI32:
          switch (mode) {
            case kR2R:
              EMIT_INSTR_HANDLER(r2r_I32Select);
              I32Pop();  // val2
              I32Pop();  // val1
              return RegMode::kI32Reg;
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I32Select);
              I32Pop();   // val2
              I32Pop();   // val1
              I32Push();  // result
              return RegMode::kNoReg;
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_I32Select);
              I32Pop();  // condition
              I32Pop();  // val2
              I32Pop();  // val1
              return RegMode::kI32Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I32Select);
              I32Pop();   // condition
              I32Pop();   // val2
              I32Pop();   // val1
              I32Push();  // result
              return RegMode::kNoReg;
          }
          break;
        case kI64:
          switch (mode) {
            case kR2R:
              EMIT_INSTR_HANDLER(r2r_I64Select);
              I64Pop();  // val2
              I64Pop();  // val1
              return RegMode::kI64Reg;
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I64Select);
              I64Pop();   // val2
              I64Pop();   // val1
              I64Push();  // result
              return RegMode::kNoReg;
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_I64Select);
              I32Pop();  // condition
              I64Pop();  // val2
              I64Pop();  // val1
              return RegMode::kI64Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I64Select);
              I32Pop();  // condition
              I64Pop();
              I64Pop();
              I64Push();
              return RegMode::kNoReg;
          }
          break;
        case kF32:
          switch (mode) {
            case kR2R:
              EMIT_INSTR_HANDLER(r2r_F32Select);
              F32Pop();  // val2
              F32Pop();  // val1
              return RegMode::kF32Reg;
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F32Select);
              F32Pop();   // val2
              F32Pop();   // val1
              F32Push();  // result
              return RegMode::kNoReg;
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_F32Select);
              I32Pop();  // condition
              F32Pop();  // val2
              F32Pop();  // val1
              return RegMode::kF32Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F32Select);
              I32Pop();  // condition
              F32Pop();
              F32Pop();
              F32Push();
              return RegMode::kNoReg;
          }
          break;
        case kF64:
          switch (mode) {
            case kR2R:
              EMIT_INSTR_HANDLER(r2r_F64Select);
              F64Pop();  // val2
              F64Pop();  // val1
              return RegMode::kF64Reg;
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F64Select);
              F64Pop();   // val2
              F64Pop();   // val1
              F64Push();  // result
              return RegMode::kNoReg;
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_F64Select);
              I32Pop();  // condition
              F64Pop();  // val2
              F64Pop();  // val1
              return RegMode::kF64Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F64Select);
              I32Pop();  // condition
              F64Pop();
              F64Pop();
              F64Push();
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_S128Select);
              S128Pop();
              S128Pop();
              S128Push();
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_S128Select);
              I32Pop();  // condition
              S128Pop();
              S128Pop();
              S128Push();
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S: {
              EMIT_INSTR_HANDLER(r2s_RefSelect);
              RefPop();                   // val2
              ValueType type = RefPop();  // val1
              RefPush(type);              // result
              return RegMode::kNoReg;
            }
            case kS2S: {
              EMIT_INSTR_HANDLER(s2s_RefSelect);
              I32Pop();  // condition
              RefPop();
              ValueType type = RefPop();
              RefPush(type);
              return RegMode::kNoReg;
            }
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }

    case kExprLocalGet: {
      switch (slots_[stack_[instr.optional.index]].kind()) {
        case kI32:
        case kI64:
        case kF32:
        case kF64:
        case kS128:
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              PushCopySlot(instr.optional.index);
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kExprLocalSet: {
      DCHECK_LE(instr.optional.index, stack_size());
      // Validation ensures that the target slot type must be the same as the
      // stack top slot type.
      const ValueType value_type =
          slots_[stack_[instr.optional.index]].value_type;
      const ValueKind kind = value_type.kind();
      DCHECK(CheckEqualKind(kind, top_stack_slot_type));
      switch (kind) {
        case kI32:
        case kI64:
        case kF32:
        case kF64:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              CopyToSlotAndPop(value_type, instr.optional.index, false, true);
              return RegMode::kNoReg;
            case kS2S:
              CopyToSlotAndPop(value_type, instr.optional.index, false, false);
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              CopyToSlotAndPop(value_type, instr.optional.index, false, false);
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              CopyToSlotAndPop(slots_[stack_.back()].value_type,
                               instr.optional.index, false, false);
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kExprLocalTee: {
      DCHECK_LE(instr.optional.index, stack_size());
      // Validation ensures that the target slot type must be the same as the
      // stack top slot type.
      const ValueType value_type =
          slots_[stack_[instr.optional.index]].value_type;
      const ValueKind kind = value_type.kind();
      DCHECK(CheckEqualKind(kind, top_stack_slot_type));
      switch (kind) {
        case kI32:
        case kI64:
        case kF32:
        case kF64:
          switch (mode) {
            case kR2R:
              CopyToSlotAndPop(value_type, instr.optional.index, true, true);
              return GetRegMode(value_type.kind());
            case kR2S:
              UNREACHABLE();
            case kS2R:
              UNREACHABLE();
            case kS2S:
              CopyToSlotAndPop(value_type, instr.optional.index, true, false);
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              CopyToSlotAndPop(value_type, instr.optional.index, true, false);
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              CopyToSlotAndPop(slots_[stack_.back()].value_type,
                               instr.optional.index, true, false);
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kExprGlobalGet: {
      switch (GetGlobalType(instr.optional.index)) {
        case kI32:
          switch (mode) {
            case kR2R:
            case kR2S:
              UNREACHABLE();
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_I32GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kI32Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I32GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              I32Push();
              return RegMode::kNoReg;
          }
          break;
        case kI64:
          switch (mode) {
            case kR2R:
            case kR2S:
              UNREACHABLE();
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_I64GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kI64Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I64GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              I64Push();
              return RegMode::kNoReg;
          }
          break;
        case kF32:
          switch (mode) {
            case kR2R:
            case kR2S:
              UNREACHABLE();
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_F32GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kF32Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F32GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              F32Push();
              return RegMode::kNoReg;
          }
          break;
        case kF64:
          switch (mode) {
            case kR2R:
            case kR2S:
              UNREACHABLE();
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_F64GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kF64Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F64GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              F64Push();
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_S128GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              S128Push();
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_RefGlobalGet);
              EmitGlobalIndex(instr.optional.index);
              RefPush(module_->globals[instr.optional.index].type);
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kExprGlobalSet: {
      switch (top_stack_slot_type) {
        case kI32:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I32GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I32GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              I32Pop();
              return RegMode::kNoReg;
          }
          break;
        case kI64:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I64GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I64GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              I64Pop();
              return RegMode::kNoReg;
          }
          break;
        case kF32:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F32GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F32GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              F32Pop();
              return RegMode::kNoReg;
          }
          break;
        case kF64:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F64GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F64GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              F64Pop();
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_S128GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              S128Pop();
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_RefGlobalSet);
              EmitGlobalIndex(instr.optional.index);
              RefPop();
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }

    case kExprTableGet: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_TableGet, instr.pc);
      EmitI32Const(instr.optional.index);
      I32Pop();
      RefPush(module_->tables[instr.optional.index].type);
      break;
    }

    case kExprTableSet: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_TableSet, instr.pc);
      EmitI32Const(instr.optional.index);
      RefPop();
      I32Pop();
      break;
    }

#define LOAD_CASE(name, ctype, mtype, rep, type)          \
  case kExpr##name: {                                     \
    switch (mode) {                                       \
      case kR2R:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(r2r_##name, instr.pc); \
        EmitI64Const(instr.optional.offset);              \
        return RegMode::k##type##Reg;                     \
      case kR2S:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(r2s_##name, instr.pc); \
        EmitI64Const(instr.optional.offset);              \
        type##Push();                                     \
        return RegMode::kNoReg;                           \
      case kS2R:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(s2r_##name, instr.pc); \
        EmitI64Const(instr.optional.offset);              \
        I32Pop();                                         \
        return RegMode::k##type##Reg;                     \
      case kS2S:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(s2s_##name, instr.pc); \
        EmitI64Const(instr.optional.offset);              \
        I32Pop();                                         \
        type##Push();                                     \
        return RegMode::kNoReg;                           \
    }                                                     \
    break;                                                \
  }
      LOAD_CASE(I32LoadMem8S, int32_t, int8_t, kWord8, I32);
      LOAD_CASE(I32LoadMem8U, int32_t, uint8_t, kWord8, I32);
      LOAD_CASE(I32LoadMem16S, int32_t, int16_t, kWord16, I32);
      LOAD_CASE(I32LoadMem16U, int32_t, uint16_t, kWord16, I32);
      LOAD_CASE(I64LoadMem8S, int64_t, int8_t, kWord8, I64);
      LOAD_CASE(I64LoadMem8U, int64_t, uint8_t, kWord16, I64);
      LOAD_CASE(I64LoadMem16S, int64_t, int16_t, kWord16, I64);
      LOAD_CASE(I64LoadMem16U, int64_t, uint16_t, kWord16, I64);
      LOAD_CASE(I64LoadMem32S, int64_t, int32_t, kWord32, I64);
      LOAD_CASE(I64LoadMem32U, int64_t, uint32_t, kWord32, I64);
      LOAD_CASE(I32LoadMem, int32_t, int32_t, kWord32, I32);
      LOAD_CASE(I64LoadMem, int64_t, int64_t, kWord64, I64);
      LOAD_CASE(F32LoadMem, Float32, uint32_t, kFloat32, F32);
      LOAD_CASE(F64LoadMem, Float64, uint64_t, kFloat64, F64);
#undef LOAD_CASE

#define STORE_CASE(name, ctype, mtype, rep, type)         \
  case kExpr##name: {                                     \
    switch (mode) {                                       \
      case kR2R:                                          \
      case kS2R:                                          \
        UNREACHABLE();                                    \
        break;                                            \
      case kR2S:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(r2s_##name, instr.pc); \
        EmitI64Const(instr.optional.offset);              \
        I32Pop();                                         \
        return RegMode::kNoReg;                           \
      case kS2S:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(s2s_##name, instr.pc); \
        type##Pop();                                      \
        EmitI64Const(instr.optional.offset);              \
        I32Pop();                                         \
        return RegMode::kNoReg;                           \
    }                                                     \
    break;                                                \
  }
      STORE_CASE(I32StoreMem8, int32_t, int8_t, kWord8, I32);
      STORE_CASE(I32StoreMem16, int32_t, int16_t, kWord16, I32);
      STORE_CASE(I64StoreMem8, int64_t, int8_t, kWord8, I64);
      STORE_CASE(I64StoreMem16, int64_t, int16_t, kWord16, I64);
      STORE_CASE(I64StoreMem32, int64_t, int32_t, kWord32, I64);
      STORE_CASE(I32StoreMem, int32_t, int32_t, kWord32, I32);
      STORE_CASE(I64StoreMem, int64_t, int64_t, kWord64, I64);
      STORE_CASE(F32StoreMem, Float32, uint32_t, kFloat32, F32);
      STORE_CASE(F64StoreMem, Float64, uint64_t, kFloat64, F64);
#undef STORE_CASE

    case kExprMemoryGrow: {
      EMIT_INSTR_HANDLER(s2s_MemoryGrow);
      I32Pop();
      I32Push();
      break;
    }
    case kExprMemorySize:
      EMIT_INSTR_HANDLER(s2s_MemorySize);
      if (IsMemory64()) {
        I64Push();
      } else {
        I32Push();
      }
      break;

    case kExprI32Const: {
      switch (mode) {
        case kR2R:
        case kR2S:
        case kS2R:
          UNREACHABLE();
        case kS2S:
          PushConstSlot<int32_t>(instr.optional.i32);
          return RegMode::kNoReg;
      }
      break;
    }
    case kExprI64Const: {
      switch (mode) {
        case kR2R:
        case kR2S:
        case kS2R:
          UNREACHABLE();
        case kS2S:
          PushConstSlot<int64_t>(instr.optional.i64);
          return RegMode::kNoReg;
      }
      break;
    }
    case kExprF32Const: {
      switch (mode) {
        case kR2R:
        case kR2S:
        case kS2R:
          UNREACHABLE();
        case kS2S:
          PushConstSlot<float>(instr.optional.f32);
          return RegMode::kNoReg;
      }
      break;
    }
    case kExprF64Const: {
      switch (mode) {
        case kR2R:
        case kR2S:
        case kS2R:
          UNREACHABLE();
        case kS2S:
          PushConstSlot<double>(instr.optional.f64);
          return RegMode::kNoReg;
      }
      break;
    }

#define EXECUTE_BINOP(name, ctype, reg, op, type) \
  case kExpr##name: {                             \
    switch (mode) {                               \
      case kR2R:                                  \
        EMIT_INSTR_HANDLER(r2r_##name);           \
        type##Pop();                              \
        return RegMode::kI32Reg;                  \
      case kR2S:                                  \
        EMIT_INSTR_HANDLER(r2s_##name);           \
        type##Pop();                              \
        I32Push();                                \
        return RegMode::kNoReg;                   \
      case kS2R:                                  \
        EMIT_INSTR_HANDLER(s2r_##name);           \
        type##Pop();                              \
        type##Pop();                              \
        return RegMode::kI32Reg;                  \
      case kS2S:                                  \
        EMIT_INSTR_HANDLER(s2s_##name);           \
        type##Pop();                              \
        type##Pop();                              \
        I32Push();                                \
        return RegMode::kNoReg;                   \
    }                                             \
    break;                                        \
  }
      FOREACH_COMPARISON_BINOP(EXECUTE_BINOP)
#undef EXECUTE_BINOP

#define EXECUTE_BINOP(name, ctype, reg, op, type) \
  case kExpr##name: {                             \
    switch (mode) {                               \
      case kR2R:                                  \
        EMIT_INSTR_HANDLER(r2r_##name);           \
        type##Pop();                              \
        return RegMode::k##type##Reg;             \
      case kR2S:                                  \
        EMIT_INSTR_HANDLER(r2s_##name);           \
        type##Pop();                              \
        type##Push();                             \
        return RegMode::kNoReg;                   \
      case kS2R:                                  \
        EMIT_INSTR_HANDLER(s2r_
```