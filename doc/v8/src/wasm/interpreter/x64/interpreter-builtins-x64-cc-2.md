Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc`. The request asks for:

1. **Functionality Listing:** A summary of what the code does.
2. **Torque Check:**  Determine if it's a Torque file (it's not, since it doesn't end in `.tq`).
3. **JavaScript Relation:** If related to JavaScript, provide a JavaScript example.
4. **Code Logic Inference:** Explain the logic with hypothetical inputs and outputs.
5. **Common Programming Errors:** Point out potential user errors.
6. **Summary:** A concise overview of the code's purpose.

The code primarily deals with memory access within the WebAssembly interpreter on the x64 architecture. It defines functions to generate assembly code for loading and storing different data types (integers and floats) from and to WebAssembly memory. The functions are named based on the data flow: `r2r` (register to register), `r2s` (register to stack slot), `s2r` (stack slot to register), and `s2s` (stack slot to stack slot).

**High-Level Plan:**

1. **Analyze the `Return` Function:** Understand how it handles returning values from the interpreter.
2. **Analyze the Helper Functions:**  Focus on `EmitLoadInstruction`, `EmitStoreInstruction`, `WriteToSlot`, and `EmitLoadNextInstructionId`.
3. **Analyze the `Generate_*LoadMem` and `Generate_*StoreMem` Functions:** Decipher the assembly instructions for loading and storing data. Pay attention to the register usage and memory operands.
4. **Connect to WebAssembly Concepts:** Relate the code to standard WebAssembly instructions like `i32.load`, `f64.store`, etc.
5. **Identify Potential Errors:** Think about common mistakes when dealing with memory access (e.g., out-of-bounds).
6. **Formulate JavaScript Examples:**  Create simple JavaScript code that would trigger these WebAssembly memory operations.
7. **Summarize the Functionality.**
这是目录为v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc的v8源代码的第3部分，主要负责生成 WebAssembly 解释器在 x64 架构上的内置函数，用于 **从 WebAssembly 线性内存中加载各种类型的数值**。

**功能归纳:**

这部分代码定义了多个 `Generate_*LoadMem` 函数，它们的核心功能是生成执行以下操作的汇编代码：

1. **从 WebAssembly 代码中读取操作数:**  例如内存地址的偏移量。
2. **计算实际的内存地址:**  将基地址（memory_start）与偏移量和索引相加。
3. **从内存中加载指定类型的数据:** 根据不同的指令（如 `I32LoadMem8S`, `F64LoadMem`）加载 8 位、16 位、32 位、64 位的有符号或无符号整数，以及 32 位和 64 位浮点数。
4. **将加载的值存储到寄存器或栈槽中:** 根据指令类型将加载的值放入目标寄存器或栈上的指定位置。
5. **加载下一个指令处理器的 ID 并跳转到相应的处理代码:**  实现了解释器的指令执行流程。

**详细功能分解:**

* **`Return` 函数:**  这部分代码（在提供的片段之外，但与返回相关）负责处理 WebAssembly 函数的返回值。它根据返回值的类型（i32, i64, f32, f64, ref）将结果写入到指定的内存位置，并跳转到返回完成的标签。

* **辅助函数:**
    * **`EmitLoadInstruction` (整数):**  根据 `value_type` (期望的值类型，如 32 位或 64 位整数) 和 `memory_type` (内存中存储的类型，如 8 位有符号整数) 生成不同的汇编指令 (`movsxlq`, `movzxbl` 等) 来加载并扩展内存中的值到指定大小的寄存器。
    * **`EmitLoadInstruction` (浮点数):**  根据 `float_type` (单精度或双精度) 生成 `movss` 或 `movsd` 指令从内存加载浮点数到 XMM 寄存器。
    * **`WriteToSlot`:**  将寄存器中的值写入到栈上的指定偏移位置。
    * **`EmitStoreInstruction` (整数):**  根据 `memory_type` 生成不同的汇编指令 (`movq`, `movl`, `movw`, `movb`) 将寄存器中的值存储到内存。
    * **`EmitStoreInstruction` (浮点数):** 生成 `movss` 或 `movsd` 指令将 XMM 寄存器中的浮点数存储到内存。
    * **`EmitLoadNextInstructionId`:** 从 WebAssembly 字节码中读取下一个指令处理器的 ID，并进行安全检查，防止越界访问指令表。

* **`Generate_*LoadMem` 函数族:**
    * **命名约定:**  `Generate_<data_flow>_<value_type>LoadMem<size><signedness>`
        * `<data_flow>`:  `r2r` (寄存器到寄存器), `r2s` (寄存器到栈), `s2r` (栈到寄存器), `s2s` (栈到栈)。
        * `<value_type>`:  `I32`, `I64`, `F32`, `F64`。
        * `<size>`:  内存中加载的数据大小 (8, 16, 32，无表示完整大小)。
        * `<signedness>`:  `S` (有符号), `U` (无符号)。
    * **功能:** 这些函数生成具体的汇编代码来执行加载操作。它们会：
        * 获取内存起始地址 (`memory_start`)。
        * 从 WebAssembly 字节码中读取内存偏移量。
        * 从寄存器或栈中读取索引（如果需要）。
        * 计算最终的内存地址。
        * 调用 `EmitLoadInstruction` 来加载数据。
        * 将结果存储到目标寄存器或栈槽。
        * 加载下一个指令的 ID 并跳转。

**关于问题中的其他点:**

* **`.tq` 结尾:**  `v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc` 以 `.cc` 结尾，**不是**一个 v8 Torque 源代码文件。 Torque 文件通常以 `.tq` 结尾。

* **与 JavaScript 的关系:**  这段代码是 V8 引擎的一部分，负责执行 WebAssembly 代码。当 JavaScript 代码调用 WebAssembly 模块中的函数，并且该函数需要从内存中读取数据时，最终会执行到由这些函数生成的机器码。

* **JavaScript 举例:**

```javascript
// 假设有一个 WebAssembly 模块的实例叫做 'wasmInstance'
// 并且该模块导出了一个名为 'load_int' 的函数，
// 这个函数的功能是从 wasm 内存的指定地址加载一个 32 位整数。

const memory = wasmInstance.exports.memory; // 获取 WebAssembly 的内存对象
const address = 1024; // 要加载的内存地址

// 假设 'load_int' 函数的实现对应于这里生成的某个 Builtin
const loadedValue = wasmInstance.exports.load_int(address);

console.log(loadedValue);
```

在这个例子中，当 JavaScript 调用 `wasmInstance.exports.load_int(address)` 时，如果 `load_int` 的实现需要从内存加载一个整数，V8 引擎会执行 `interpreter-builtins-x64.cc` 中生成的相应机器码来完成加载操作。

* **代码逻辑推理 (假设输入与输出):**

假设我们执行 `Builtins::Generate_r2r_I32LoadMem8S` 生成的代码。

**假设输入:**

1. **`code` 寄存器:** 指向当前执行的 WebAssembly 字节码的指针，假设在偏移 `0x00` 处存储着 4 字节的内存偏移量，在偏移 `0x08` 处存储着 2 字节的下一个指令处理器的 ID。
2. **`wasm_runtime` 寄存器:** 指向 `WasmInterpreterRuntime` 对象的指针，该对象包含内存的起始地址。
3. **`memory_index` 寄存器:**  存储着内存访问的索引值，例如 5。
4. **WebAssembly 内存:** 从 `wasm_runtime->memory_start()` 指向的地址开始，在地址 `memory_start + offset + memory_index` 处存储着一个单字节的有符号整数，例如值为 `-1` (二进制补码为 `0xFF`)。

**代码逻辑:**

1. 从 `code + 0x00` 读取 4 字节的偏移量到 `memory_offset` 寄存器。
2. 将 `memory_index` 寄存器中的值（5）加到 `memory_offset`。
3. 从内存地址 `memory_start + memory_offset` 加载一个字节到 `result` 寄存器 (`r9`)，并进行符号扩展。
4. 从 `code + 0x08` 读取下一个处理器的 ID。
5. 跳转到下一个处理器对应的代码。

**预期输出:**

1. `r9` 寄存器（`result`）将包含值 `-1` (因为进行了符号扩展，`0xFF` 被扩展为 32 位的 `-1`)。
2. 程序执行流程跳转到下一个指令处理器。

* **用户常见的编程错误:**

1. **内存越界访问:**  如果传递给 `load_int` 的 `address` 加上偏移量超出了 WebAssembly 线性内存的范围，会导致程序崩溃或未定义的行为。WebAssembly 通常会有边界检查，但这部分代码是在解释器内部执行，假设了索引的有效性（在未定义 `V8_DRUMBRAKE_BOUNDS_CHECKS` 的情况下）。

   **JavaScript 示例 (可能导致错误):**

   ```javascript
   const memory = wasmInstance.exports.memory;
   const buffer = new Int8Array(memory.buffer);
   const outOfBoundsAddress = memory.buffer.byteLength + 10;
   // 尝试访问超出内存范围的地址
   // 对应的 wasm 代码如果直接使用这个地址加载，可能导致错误
   // (取决于 wasm 模块是否进行了边界检查)
   const value = wasmInstance.exports.load_int(outOfBoundsAddress);
   ```

2. **类型不匹配:**  如果 WebAssembly 代码尝试以错误的类型加载内存，例如将浮点数地址作为整数加载，虽然这段代码本身不会阻止这种操作，但可能会导致逻辑错误。

**总结:**

这部分 `interpreter-builtins-x64.cc` 代码是 WebAssembly 解释器的核心组成部分，专门用于生成 x64 架构下从 WebAssembly 线性内存中加载各种数据类型的机器码指令。它定义了针对不同数据流（寄存器到寄存器，寄存器到栈等）和不同数据类型的加载操作，并负责跳转到下一个指令处理器，驱动着 WebAssembly 代码的解释执行。

### 提示词
```
这是目录为v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
te(), WasmTaggedToFloat32),
          RelocInfo::CODE_TARGET);
  __ movq(packed_args, MemOperand(rbp, kCurrentResultAddressOffset));
  __ Movss(MemOperand(packed_args, 0), xmm0);
  __ addq(packed_args, Immediate(sizeof(float)));
  __ jmp(&return_done);

  __ bind(&return_kWasmF64);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmTaggedToFloat64),
          RelocInfo::CODE_TARGET);
  __ movq(packed_args, MemOperand(rbp, kCurrentResultAddressOffset));
  __ Movsd(MemOperand(packed_args, 0), xmm0);
  __ addq(packed_args, Immediate(sizeof(double)));
  __ jmp(&return_done);

  __ bind(&return_kWasmRef);
  __ movq(MemOperand(packed_args, 0), return_reg);
  __ addq(packed_args, Immediate(kSystemPointerSize));
  __ jmp(&return_done);
}

#ifndef V8_DRUMBRAKE_BOUNDS_CHECKS

namespace {

enum IntMemoryType {
  kIntS8,
  kIntU8,
  kIntS16,
  kIntU16,
  kIntS32,
  kIntU32,
  kInt64
};

enum IntValueType { kValueInt32, kValueInt64 };

enum FloatType { kFloat32, kFloat64 };

void EmitLoadInstruction(MacroAssembler* masm, Register result,
                         Register memory_start, Register memory_index,
                         IntValueType value_type, IntMemoryType memory_type) {
  switch (memory_type) {
    case kInt64:
      switch (value_type) {
        case kValueInt64:
          __ movq(result, Operand(memory_start, memory_index, times_1, 0));
          break;
        default:
          UNREACHABLE();
      }
      break;
    case kIntS32:
      switch (value_type) {
        case kValueInt64:
          __ movsxlq(result, Operand(memory_start, memory_index, times_1, 0));
          break;
        case kValueInt32:
          __ movl(result, Operand(memory_start, memory_index, times_1, 0));
          break;
      }
      break;
    case kIntU32:
      switch (value_type) {
        case kValueInt64:
          __ movl(result, Operand(memory_start, memory_index, times_1, 0));
          break;
        default:
          UNREACHABLE();
      }
      break;
    case kIntS16:
      switch (value_type) {
        case kValueInt64:
          __ movsxwq(result, Operand(memory_start, memory_index, times_1, 0));
          break;
        case kValueInt32:
          __ movsxwl(result, Operand(memory_start, memory_index, times_1, 0));
          break;
      }
      break;
    case kIntU16:
      switch (value_type) {
        case kValueInt64:
          __ movzxwq(result, Operand(memory_start, memory_index, times_1, 0));
          break;
        case kValueInt32:
          __ movzxwl(result, Operand(memory_start, memory_index, times_1, 0));
          break;
      }
      break;
    case kIntS8:
      switch (value_type) {
        case kValueInt64:
          __ movsxbq(result, Operand(memory_start, memory_index, times_1, 0));
          break;
        case kValueInt32:
          __ movsxbl(result, Operand(memory_start, memory_index, times_1, 0));
          break;
      }
      break;
    case kIntU8:
      switch (value_type) {
        case kValueInt64:
          __ movzxbq(result, Operand(memory_start, memory_index, times_1, 0));
          break;
        case kValueInt32:
          __ movzxbl(result, Operand(memory_start, memory_index, times_1, 0));
          break;
      }
      break;
    default:
      UNREACHABLE();
  }
}

void EmitLoadInstruction(MacroAssembler* masm, Register memory_start,
                         Register memory_offset, XMMRegister result,
                         FloatType float_type) {
  switch (float_type) {
    case kFloat32:
      __ movss(xmm0, Operand(memory_start, memory_offset, times_1, 0));
      __ cvtss2sd(result, xmm0);
      break;
    case kFloat64:
      __ movsd(result, Operand(memory_start, memory_offset, times_1, 0));
      break;
    default:
      UNREACHABLE();
  }
}

void EmitLoadInstruction(MacroAssembler* masm, Register memory_start,
                         Register memory_offset, Register sp,
                         Register slot_offset, FloatType float_type) {
  switch (float_type) {
    case kFloat32:
      __ movss(xmm0, Operand(memory_start, memory_offset, times_1, 0));
      __ movss(Operand(sp, slot_offset, times_4, 0), xmm0);
      break;
    case kFloat64:
      __ movsd(xmm0, Operand(memory_start, memory_offset, times_1, 0));
      __ movsd(Operand(sp, slot_offset, times_4, 0), xmm0);
      break;
    default:
      UNREACHABLE();
  }
}

void WriteToSlot(MacroAssembler* masm, Register sp, Register slot_offset,
                 Register value, IntValueType value_type) {
  switch (value_type) {
    case kValueInt64:
      __ movq(Operand(sp, slot_offset, times_4, 0), value);
      break;
    case kValueInt32:
      __ movl(Operand(sp, slot_offset, times_4, 0), value);
      break;
  }
}

void EmitStoreInstruction(MacroAssembler* masm, Register value,
                          Register memory_start, Register memory_index,
                          IntMemoryType memory_type) {
  switch (memory_type) {
    case kInt64:
      __ movq(Operand(memory_start, memory_index, times_1, 0), value);
      break;
    case kIntS32:
      __ movl(Operand(memory_start, memory_index, times_1, 0), value);
      break;
    case kIntS16:
      __ movw(Operand(memory_start, memory_index, times_1, 0), value);
      break;
    case kIntS8:
      __ movb(Operand(memory_start, memory_index, times_1, 0), value);
      break;
    default:
      UNREACHABLE();
  }
}

void EmitStoreInstruction(MacroAssembler* masm, XMMRegister value,
                          Register memory_start, Register memory_index,
                          FloatType float_type) {
  switch (float_type) {
    case kFloat32:
      __ movss(Operand(memory_start, memory_index, times_1, 0), value);
      break;
    case kFloat64:
      __ movsd(Operand(memory_start, memory_index, times_1, 0), value);
      break;
    default:
      UNREACHABLE();
  }
}

void EmitLoadNextInstructionId(MacroAssembler* masm, Register next_handler_id,
                               Register code, uint32_t code_offset) {
  // An InstructionHandler id is stored in the WasmBytecode as a uint16_t, so we
  // need to move a 16-bit word here.
  __ movzxwq(next_handler_id, MemOperand(code, code_offset));

  // Currently, there cannot be more than kInstructionTableSize = 1024 different
  // handlers, so (for additional security) we do a bitwise AND with 1023 to
  // make sure some attacker might somehow generate invalid WasmBytecode data
  // and force an indirect jump through memory outside the handler table.
  __ andq(next_handler_id, Immediate(wasm::kInstructionTableMask));
}

void Generate_r2r_ILoadMem(MacroAssembler* masm, IntValueType value_type,
                           IntMemoryType memory_type) {
  Register code = rcx;
  Register wasm_runtime = r8;
  Register memory_index = r9;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register memory_offset = rax;
  __ movq(memory_offset, MemOperand(code, 0x00));
  __ movl(memory_index, memory_index);
  __ addq(memory_offset, memory_index);

  Register result = r9;
  EmitLoadInstruction(masm, result, memory_start, memory_offset, value_type,
                      memory_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x08);
  __ addq(code, Immediate(0x0a));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_r2r_FLoadMem(MacroAssembler* masm, FloatType float_type) {
  Register code = rcx;
  Register wasm_runtime = r8;
  Register memory_index = r9;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register memory_offset = rax;
  __ movq(memory_offset, MemOperand(code, 0x00));
  __ movl(memory_index, memory_index);
  __ addq(memory_offset, memory_index);

  EmitLoadInstruction(masm, memory_start, memory_offset, xmm4, float_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x08);
  __ addq(code, Immediate(0x0a));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_r2s_ILoadMem(MacroAssembler* masm, IntValueType value_type,
                           IntMemoryType memory_type) {
  Register code = rcx;
  Register sp = rdx;
  Register wasm_runtime = r8;
  Register memory_index = r9;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register memory_offset = rax;
  __ movq(memory_offset, MemOperand(code, 0x00));
  __ movl(memory_index, memory_index);
  __ addq(memory_offset, memory_index);

  Register value = r10;
  EmitLoadInstruction(masm, value, memory_start, memory_offset, value_type,
                      memory_type);

  Register slot_offset = rax;
  __ movl(slot_offset, MemOperand(code, 0x08));

  WriteToSlot(masm, sp, slot_offset, value, value_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x0c);
  __ addq(code, Immediate(0x0e));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_r2s_FLoadMem(MacroAssembler* masm, FloatType float_type) {
  Register code = rcx;
  Register sp = rdx;
  Register wasm_runtime = r8;
  Register memory_index = r9;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register memory_offset = rax;
  __ movq(memory_offset, MemOperand(code, 0x00));
  __ movl(memory_index, memory_index);
  __ addq(memory_offset, memory_index);

  Register slot_offset = r11;
  __ movl(slot_offset, MemOperand(code, 0x08));

  EmitLoadInstruction(masm, memory_start, memory_offset, sp, slot_offset,
                      float_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x0c);
  __ addq(code, Immediate(0x0e));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_s2r_ILoadMem(MacroAssembler* masm, IntValueType value_type,
                           IntMemoryType memory_type) {
  Register code = rcx;
  Register sp = rdx;
  Register wasm_runtime = r8;

  Register memory_start = r9;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register memory_index_slot_offset = rax;
  __ movl(memory_index_slot_offset, MemOperand(code, 0x08));

  Register memory_offset = rax;
  __ movl(memory_offset, Operand(sp, memory_index_slot_offset, times_4, 0));
  __ addq(memory_offset, MemOperand(code, 0x00));

  Register value = r9;
  EmitLoadInstruction(masm, value, memory_start, memory_offset, value_type,
                      memory_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x0c);
  __ addq(code, Immediate(0x0e));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_s2r_FLoadMem(MacroAssembler* masm, FloatType float_type) {
  Register code = rcx;
  Register sp = rdx;
  Register wasm_runtime = r8;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register memory_index_slot_offset = rax;
  __ movl(memory_index_slot_offset, MemOperand(code, 0x08));

  Register memory_offset = rax;
  __ movl(memory_offset, Operand(sp, memory_index_slot_offset, times_4, 0));
  __ addq(memory_offset, MemOperand(code, 0x00));

  EmitLoadInstruction(masm, memory_start, memory_offset, xmm4, float_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x0c);
  __ addq(code, Immediate(0x0e));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_s2s_ILoadMem(MacroAssembler* masm, IntValueType value_type,
                           IntMemoryType memory_type) {
  Register code = rcx;
  Register sp = rdx;
  Register wasm_runtime = r8;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register pop_slot_offset = rax;
  __ movl(pop_slot_offset, MemOperand(code, 0x08));

  Register push_slot_offset = r11;
  __ movl(push_slot_offset, MemOperand(code, 0x0c));

  Register memory_index = r9;
  __ movl(memory_index, Operand(sp, pop_slot_offset, times_4, 0));

  Register memory_offset = rax;
  __ movq(memory_offset, MemOperand(code, 0x00));
  __ addq(memory_offset, memory_index);

  Register value = rax;
  EmitLoadInstruction(masm, value, memory_start, memory_offset, value_type,
                      memory_type);

  WriteToSlot(masm, sp, push_slot_offset, value, value_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x10);
  __ addq(code, Immediate(0x12));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_s2s_FLoadMem(MacroAssembler* masm, FloatType float_type) {
  Register code = rcx;
  Register sp = rdx;
  Register wasm_runtime = r8;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register slot_offset = rax;
  __ movl(slot_offset, MemOperand(code, 0x08));

  Register push_slot_offset = r11;
  __ movl(push_slot_offset, MemOperand(code, 0x0c));

  Register memory_index = r9;
  __ movl(memory_index, Operand(sp, slot_offset, times_4, 0));

  Register memory_offset = rax;
  __ movq(memory_offset, MemOperand(code, 0x00));
  __ addq(memory_offset, memory_index);

  EmitLoadInstruction(masm, memory_start, memory_offset, sp, push_slot_offset,
                      float_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x10);
  __ addq(code, Immediate(0x12));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_s2s_ILoadMem_LocalSet(MacroAssembler* masm,
                                    IntValueType value_type,
                                    IntMemoryType memory_type) {
  Register code = rcx;
  Register sp = rdx;
  Register wasm_runtime = r8;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register pop_slot_offset = rax;
  __ movl(pop_slot_offset, MemOperand(code, 0x08));

  Register push_slot_offset = r11;
  __ movl(push_slot_offset, MemOperand(code, 0x0c));

  Register memory_offset = rax;
  __ movl(memory_offset, Operand(sp, pop_slot_offset, times_4, 0));
  __ addq(memory_offset, MemOperand(code, 0x00));

  Register value = rax;
  EmitLoadInstruction(masm, value, memory_start, memory_offset, value_type,
                      memory_type);

  WriteToSlot(masm, sp, push_slot_offset, value, value_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x10);
  __ addq(code, Immediate(0x12));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_s2s_FLoadMem_LocalSet(MacroAssembler* masm,
                                    FloatType float_type) {
  Register code = rcx;
  Register sp = rdx;
  Register wasm_runtime = r8;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register pop_slot_offset = rax;
  __ movl(pop_slot_offset, MemOperand(code, 0x08));

  Register push_slot_offset = r11;
  __ movl(push_slot_offset, MemOperand(code, 0x0c));

  Register memory_offset = rax;
  __ movl(memory_offset, Operand(sp, pop_slot_offset, times_4, 0));
  __ addq(memory_offset, MemOperand(code, 0x00));

  EmitLoadInstruction(masm, memory_start, memory_offset, sp, push_slot_offset,
                      float_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x10);
  __ addq(code, Immediate(0x12));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_r2s_IStoreMem(MacroAssembler* masm, IntValueType /*value_type*/,
                            IntMemoryType memory_type) {
  Register code = rcx;
  Register sp = rdx;
  Register wasm_runtime = r8;
  Register value = r9;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register memory_index_slot_offset = rax;
  __ movl(memory_index_slot_offset, MemOperand(code, 0x08));

  Register memory_offset = rax;
  __ movl(memory_offset, Operand(sp, memory_index_slot_offset, times_4, 0));
  __ addq(memory_offset, MemOperand(code, 0x00));

  EmitStoreInstruction(masm, value, memory_start, memory_offset, memory_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x0c);
  __ addq(code, Immediate(0x0e));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_r2s_FStoreMem(MacroAssembler* masm, FloatType float_type) {
  Register code = rcx;
  Register sp = rdx;
  Register wasm_runtime = r8;

  XMMRegister value = xmm4;
  if (float_type == kFloat32) {
    __ cvtsd2ss(value, xmm4);
  }

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register memory_index_slot_offset = rax;
  __ movl(memory_index_slot_offset, MemOperand(code, 0x08));

  Register memory_offset = rax;
  __ movl(memory_offset, Operand(sp, memory_index_slot_offset, times_4, 0));
  __ addq(memory_offset, MemOperand(code, 0x00));

  EmitStoreInstruction(masm, value, memory_start, memory_offset, float_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x0c);
  __ addq(code, Immediate(0x0e));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_s2s_IStoreMem(MacroAssembler* masm, IntValueType /*value_type*/,
                            IntMemoryType memory_type) {
  Register sp = rdx;
  Register code = rcx;
  Register wasm_runtime = r8;

  Register value_slot_offset = rax;
  __ movl(value_slot_offset, MemOperand(code, 0x00));

  Register memory_index_slot_offset = r10;
  __ movl(memory_index_slot_offset, MemOperand(code, 0x0c));

  Register value = r11;
  switch (memory_type) {
    case kInt64:
      __ movq(value, MemOperand(sp, value_slot_offset, times_4, 0));
      break;
    case kIntS32:
      __ movl(value, MemOperand(sp, value_slot_offset, times_4, 0));
      break;
    case kIntS16:
      __ movw(value, MemOperand(sp, value_slot_offset, times_4, 0));
      break;
    case kIntS8:
      __ movb(value, MemOperand(sp, value_slot_offset, times_4, 0));
      break;
    default:
      UNREACHABLE();
  }

  Register memory_start = r9;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register memory_offset = rax;
  __ movl(memory_offset, MemOperand(sp, memory_index_slot_offset, times_4, 0));
  __ addq(memory_offset, MemOperand(code, 0x04));

  EmitStoreInstruction(masm, value, memory_start, memory_offset, memory_type);

  Register next_handler_id = rax;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x10);
  __ addq(code, Immediate(0x12));

  Register instr_table = r9;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_s2s_FStoreMem(MacroAssembler* masm, FloatType float_type) {
  Register sp = rdx;
  Register code = rcx;
  Register wasm_runtime = r8;

  Register value_slot_offset = rax;
  __ movl(value_slot_offset, MemOperand(code, 0x00));

  Register memory_index_slot_offset = r10;
  __ movl(memory_index_slot_offset, MemOperand(code, 0x0c));

  XMMRegister value = xmm0;
  switch (float_type) {
    case kFloat32:
      __ movss(value, MemOperand(sp, value_slot_offset, times_4, 0));
      break;
    case kFloat64:
      __ movsd(value, MemOperand(sp, value_slot_offset, times_4, 0));
      break;
    default:
      UNREACHABLE();
  }

  Register memory_start = r11;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register memory_offset = rax;
  __ movl(memory_offset, MemOperand(sp, memory_index_slot_offset, times_4, 0));
  __ addq(memory_offset, MemOperand(code, 0x04));

  EmitStoreInstruction(masm, value, memory_start, memory_offset, float_type);

  Register next_handler_id = r10;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x10);
  __ addq(code, Immediate(0x12));

  Register instr_table = rax;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_r2s_ILoadStoreMem(MacroAssembler* masm, IntValueType value_type,
                                IntMemoryType memory_type) {
  Register sp = rdx;
  Register code = rcx;
  Register wasm_runtime = r8;
  Register load_index = r9;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register load_offset = r11;
  __ movq(load_offset, MemOperand(code, 0x00));
  __ movl(load_index, load_index);
  __ addq(load_offset, load_index);

  Register value = rax;
  EmitLoadInstruction(masm, value, memory_start, load_offset, value_type,
                      memory_type);

  Register store_index_slot_offset = r9;
  __ movl(store_index_slot_offset, MemOperand(code, 0x10));

  Register store_offset = r11;
  __ movl(store_offset, MemOperand(sp, store_index_slot_offset, times_4, 0));
  __ addq(store_offset, MemOperand(code, 0x08));

  EmitStoreInstruction(masm, value, memory_start, store_offset, memory_type);

  Register next_handler_id = rax;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x14);
  __ addq(code, Immediate(0x16));

  Register instr_table = r9;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_s2s_ILoadStoreMem(MacroAssembler* masm, IntValueType value_type,
                                IntMemoryType memory_type) {
  Register sp = rdx;
  Register code = rcx;
  Register wasm_runtime = r8;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register load_index_slot_offset = r9;
  __ movl(load_index_slot_offset, MemOperand(code, 0x08));

  Register load_offset = r11;
  __ movl(load_offset, Operand(sp, load_index_slot_offset, times_4, 0));
  __ addq(load_offset, MemOperand(code, 0x00));

  Register value = rax;
  EmitLoadInstruction(masm, value, memory_start, load_offset, value_type,
                      memory_type);

  Register store_index_slot_offset = r9;
  __ movl(store_index_slot_offset, MemOperand(code, 0x14));

  Register store_offset = r11;
  __ movl(store_offset, MemOperand(sp, store_index_slot_offset, times_4, 0));
  __ addq(store_offset, MemOperand(code, 0x0c));

  EmitStoreInstruction(masm, value, memory_start, store_offset, memory_type);

  Register next_handler_id = rax;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x18);
  __ addq(code, Immediate(0x1a));

  Register instr_table = r9;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_r2s_FLoadStoreMem(MacroAssembler* masm, FloatType float_type) {
  Register sp = rdx;
  Register code = rcx;
  Register wasm_runtime = r8;
  Register load_index = r9;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register load_offset = r11;
  __ movq(load_offset, MemOperand(code, 0x00));
  __ movl(load_index, load_index);
  __ addq(load_offset, load_index);

  XMMRegister value = xmm0;
  switch (float_type) {
    case kFloat32:
      __ movss(value, Operand(memory_start, load_offset, times_1, 0));
      break;
    case kFloat64:
      __ movsd(value, Operand(memory_start, load_offset, times_1, 0));
      break;
    default:
      UNREACHABLE();
  }

  Register store_index_slot_offset = r9;
  __ movl(store_index_slot_offset, MemOperand(code, 0x10));

  Register store_offset = r11;
  __ movl(store_offset, MemOperand(sp, store_index_slot_offset, times_4, 0));
  __ addq(store_offset, MemOperand(code, 0x08));

  EmitStoreInstruction(masm, value, memory_start, store_offset, float_type);

  Register next_handler_id = rax;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x14);
  __ addq(code, Immediate(0x16));

  Register instr_table = r9;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

void Generate_s2s_FLoadStoreMem(MacroAssembler* masm, FloatType float_type) {
  Register sp = rdx;
  Register code = rcx;
  Register wasm_runtime = r8;

  Register memory_start = r10;
  __ movq(memory_start,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::memory_start_offset()));

  Register load_index_slot_offset = r9;
  __ movl(load_index_slot_offset, MemOperand(code, 0x08));

  Register load_offset = r11;
  __ movl(load_offset, Operand(sp, load_index_slot_offset, times_4, 0));
  __ addq(load_offset, MemOperand(code, 0x00));

  XMMRegister value = xmm0;
  switch (float_type) {
    case kFloat32:
      __ movss(value, Operand(memory_start, load_offset, times_1, 0));
      break;
    case kFloat64:
      __ movsd(value, Operand(memory_start, load_offset, times_1, 0));
      break;
    default:
      UNREACHABLE();
  }

  Register store_index_slot_offset = r9;
  __ movl(store_index_slot_offset, MemOperand(code, 0x14));

  Register store_offset = r11;
  __ movl(store_offset, MemOperand(sp, store_index_slot_offset, times_4, 0));
  __ addq(store_offset, MemOperand(code, 0x0c));

  EmitStoreInstruction(masm, value, memory_start, store_offset, float_type);

  Register next_handler_id = rax;
  EmitLoadNextInstructionId(masm, next_handler_id, code, 0x18);
  __ addq(code, Immediate(0x1a));

  Register instr_table = r9;
  __ movq(instr_table,
          MemOperand(wasm_runtime,
                     wasm::WasmInterpreterRuntime::instruction_table_offset()));

  Register next_handler_addr = rax;
  __ movq(next_handler_addr,
          MemOperand(instr_table, next_handler_id, times_8, 0));
  __ jmp(next_handler_addr);
}

}  // namespace

void Builtins::Generate_r2r_I32LoadMem8S(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt32, kIntS8);
}
void Builtins::Generate_r2r_I32LoadMem8U(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt32, kIntU8);
}
void Builtins::Generate_r2r_I32LoadMem16S(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt32, kIntS16);
}
void Builtins::Generate_r2r_I32LoadMem16U(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt32, kIntU16);
}
void Builtins::Generate_r2r_I64LoadMem8S(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt64, kIntS8);
}
void Builtins::Generate_r2r_I64LoadMem8U(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt64, kIntU8);
}
void Builtins::Generate_r2r_I64LoadMem16S(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt64, kIntS16);
}
void Builtins::Generate_r2r_I64LoadMem16U(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt64, kIntU16);
}
void Builtins::Generate_r2r_I64LoadMem32S(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt64, kIntS32);
}
void Builtins::Generate_r2r_I64LoadMem32U(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt64, kIntU32);
}
void Builtins::Generate_r2r_I32LoadMem(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt32, kIntS32);
}
void Builtins::Generate_r2r_I64LoadMem(MacroAssembler* masm) {
  return Generate_r2r_ILoadMem(masm, kValueInt64, kInt64);
}
void Builtins::Generate_r2r_F32LoadMem(MacroAssembler* masm) {
  return Generate_r2r_FLoadMem(masm, kFloat32);
}
void Builtins::Generate_r2r_F64LoadMem(MacroAssembler* masm) {
  return Generate_r2r_FLoadMem(masm, kFloat64);
}

void Builtins::
```