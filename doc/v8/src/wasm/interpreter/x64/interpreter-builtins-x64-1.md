Response: The user wants a summary of the provided C++ code, which is the second part of a file related to the WebAssembly interpreter in V8, specifically for the x64 architecture. I need to identify the primary functionalities implemented in this code snippet.

Looking at the code, I see a pattern of `Generate_...LoadMem` and `Generate_...StoreMem` functions. These functions seem to be generating assembly code for different WebAssembly memory access instructions. The naming conventions (e.g., `r2r`, `r2s`, `s2r`, `s2s`) likely indicate different register-to-register or stack-to-register data movement scenarios. The `I` and `F` prefixes suggest integer and floating-point operations, respectively.

The code also contains helper functions like `EmitLoadInstruction`, `EmitStoreInstruction`, and `WriteToSlot` which encapsulate common assembly sequences for memory access. The `EmitLoadNextInstructionId` function deals with fetching the next instruction to be executed.

The code interacts with `WasmInterpreterRuntime`, suggesting it's part of the runtime environment for executing WebAssembly code.

The presence of `#ifndef V8_DRUMBRAKE_BOUNDS_CHECKS` indicates that some bounds checking optimizations might be disabled in certain configurations.

To demonstrate the connection to JavaScript, I should provide an example of how these memory access instructions translate from WebAssembly to JavaScript.
这是第二部分代码，延续了第一部分的功能，主要负责为 WebAssembly 解释器生成针对 x64 架构的内置函数，用于处理内存的加载和存储操作。

**功能归纳：**

这部分代码主要实现了以下功能：

1. **内存加载指令的生成:**
   - 针对不同数据类型（int32, int64, float32, float64）和不同的内存访问方式（从寄存器到寄存器 `r2r`, 从寄存器到栈 `r2s`, 从栈到寄存器 `s2r`, 从栈到栈 `s2s`）生成相应的汇编代码。
   - 细分了不同大小的整数类型（8位、16位、32位），以及有符号和无符号的变体 (e.g., `I32LoadMem8S`, `I32LoadMem8U`)。
   -  `Generate_r2r_ILoadMem`, `Generate_r2s_ILoadMem`, `Generate_s2r_ILoadMem`, `Generate_s2s_ILoadMem` 等函数负责生成整数加载的汇编代码。
   - `Generate_r2r_FLoadMem`, `Generate_r2s_FLoadMem`, `Generate_s2r_FLoadMem`, `Generate_s2s_FLoadMem` 等函数负责生成浮点数加载的汇编代码。
   - `Generate_s2s_ILoadMem_LocalSet` 和 `Generate_s2s_FLoadMem_LocalSet` 可能是加载数据到内存并立即设置到本地变量的操作。

2. **内存存储指令的生成:**
   - 同样针对不同的数据类型和内存访问方式生成汇编代码。
   - `Generate_r2s_IStoreMem` 和 `Generate_s2s_IStoreMem`  负责生成整数存储的汇编代码。
   - `Generate_r2s_FStoreMem` 和 `Generate_s2s_FStoreMem` 负责生成浮点数存储的汇编代码。

3. **复合的加载和存储指令的生成:**
   - `Generate_r2s_ILoadStoreMem`, `Generate_s2s_ILoadStoreMem`, `Generate_r2s_FLoadStoreMem`, `Generate_s2s_FLoadStoreMem` 实现了先加载再存储到另一个位置的复合操作。

4. **辅助函数:**
   - `EmitLoadInstruction`: 根据不同的数据类型和内存类型，生成实际的内存加载汇编指令。
   - `EmitStoreInstruction`: 根据不同的数据类型和内存类型，生成实际的内存存储汇编指令。
   - `WriteToSlot`: 将数据写入栈上的指定位置。
   - `EmitLoadNextInstructionId`: 从代码中加载下一个指令的 ID，用于解释器的执行流程。

**与 Javascript 的关系及示例:**

这部分代码是 V8 引擎执行 WebAssembly 代码的关键部分。WebAssembly 模块在 JavaScript 中被加载和实例化后，当执行到访问内存的指令时，就会调用这些生成的内置函数。

例如，以下 WebAssembly 代码尝试从线性内存的某个地址加载一个 32 位整数：

```wasm
(module
  (memory (export "mem") 1)
  (func (export "load_int") (param $offset i32) (result i32)
    local.get $offset
    i32.load
  )
)
```

在 JavaScript 中调用这个 WebAssembly 函数：

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00,
  0x01, 0x01, 0x07, 0x0b, 0x01, 0x07, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x69,
  0x6e, 0x74, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x28,
  0x02, 0x00, 0x0b,
]);

const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule, { /* imports */ });
const memory = wasmInstance.exports.mem;
const loadInt = wasmInstance.exports.load_int;

const offset = 4; // 从内存偏移量为 4 的位置加载
const value = loadInt(offset);

console.log(value);
```

当 `loadInt(offset)` 被调用时，WebAssembly 解释器会执行相应的 `i32.load` 指令。在 x64 架构下，`Builtins::Generate_r2r_I32LoadMem(masm)` 或类似的函数生成的汇编代码将被执行。该汇编代码会：

1. 从传递的参数 `$offset` (对应于 JavaScript 中的 `offset`) 计算出内存地址。
2. 使用 `WasmInterpreterRuntime::memory_start_offset()` 获取 WebAssembly 线性内存的起始地址。
3. 将偏移量添加到起始地址，得到实际的内存访问地址。
4. 使用类似 `movl` 的汇编指令从该地址加载 32 位整数到寄存器。
5. 将加载的值作为函数的返回值传递回解释器，最终返回到 JavaScript 中的 `value` 变量。

总而言之，这部分 C++ 代码是 WebAssembly 解释器在 x64 架构上执行内存操作的核心实现，它将 WebAssembly 的内存访问指令翻译成底层的机器码，使得 JavaScript 能够安全高效地执行 WebAssembly 代码。

### 提示词
```
这是目录为v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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

void Builtins::Generate_r2s_I32LoadMem8S(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt32, kIntS8);
}
void Builtins::Generate_r2s_I32LoadMem8U(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt32, kIntU8);
}
void Builtins::Generate_r2s_I32LoadMem16S(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt32, kIntS16);
}
void Builtins::Generate_r2s_I32LoadMem16U(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt32, kIntU16);
}
void Builtins::Generate_r2s_I64LoadMem8S(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt64, kIntS8);
}
void Builtins::Generate_r2s_I64LoadMem8U(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt64, kIntU8);
}
void Builtins::Generate_r2s_I64LoadMem16S(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt64, kIntS16);
}
void Builtins::Generate_r2s_I64LoadMem16U(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt64, kIntU16);
}
void Builtins::Generate_r2s_I64LoadMem32S(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt64, kIntS32);
}
void Builtins::Generate_r2s_I64LoadMem32U(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt64, kIntU32);
}
void Builtins::Generate_r2s_I32LoadMem(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt32, kIntS32);
}
void Builtins::Generate_r2s_I64LoadMem(MacroAssembler* masm) {
  return Generate_r2s_ILoadMem(masm, kValueInt64, kInt64);
}
void Builtins::Generate_r2s_F32LoadMem(MacroAssembler* masm) {
  return Generate_r2s_FLoadMem(masm, kFloat32);
}
void Builtins::Generate_r2s_F64LoadMem(MacroAssembler* masm) {
  return Generate_r2s_FLoadMem(masm, kFloat64);
}

void Builtins::Generate_s2r_I32LoadMem8S(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt32, kIntS8);
}
void Builtins::Generate_s2r_I32LoadMem8U(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt32, kIntU8);
}
void Builtins::Generate_s2r_I32LoadMem16S(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt32, kIntS16);
}
void Builtins::Generate_s2r_I32LoadMem16U(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt32, kIntU16);
}
void Builtins::Generate_s2r_I64LoadMem8S(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt64, kIntS8);
}
void Builtins::Generate_s2r_I64LoadMem8U(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt64, kIntU8);
}
void Builtins::Generate_s2r_I64LoadMem16S(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt64, kIntS16);
}
void Builtins::Generate_s2r_I64LoadMem16U(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt64, kIntU16);
}
void Builtins::Generate_s2r_I64LoadMem32S(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt64, kIntS32);
}
void Builtins::Generate_s2r_I64LoadMem32U(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt64, kIntU32);
}
void Builtins::Generate_s2r_I32LoadMem(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt32, kIntS32);
}
void Builtins::Generate_s2r_I64LoadMem(MacroAssembler* masm) {
  return Generate_s2r_ILoadMem(masm, kValueInt64, kInt64);
}
void Builtins::Generate_s2r_F32LoadMem(MacroAssembler* masm) {
  return Generate_s2r_FLoadMem(masm, kFloat32);
}
void Builtins::Generate_s2r_F64LoadMem(MacroAssembler* masm) {
  return Generate_s2r_FLoadMem(masm, kFloat64);
}

void Builtins::Generate_s2s_I32LoadMem8S(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt32, kIntS8);
}
void Builtins::Generate_s2s_I32LoadMem8U(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt32, kIntU8);
}
void Builtins::Generate_s2s_I32LoadMem16S(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt32, kIntS16);
}
void Builtins::Generate_s2s_I32LoadMem16U(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt32, kIntU16);
}
void Builtins::Generate_s2s_I64LoadMem8S(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt64, kIntS8);
}
void Builtins::Generate_s2s_I64LoadMem8U(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt64, kIntU8);
}
void Builtins::Generate_s2s_I64LoadMem16S(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt64, kIntS16);
}
void Builtins::Generate_s2s_I64LoadMem16U(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt64, kIntU16);
}
void Builtins::Generate_s2s_I64LoadMem32S(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt64, kIntS32);
}
void Builtins::Generate_s2s_I64LoadMem32U(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt64, kIntU32);
}
void Builtins::Generate_s2s_I32LoadMem(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt32, kIntS32);
}
void Builtins::Generate_s2s_I64LoadMem(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem(masm, kValueInt64, kInt64);
}
void Builtins::Generate_s2s_F32LoadMem(MacroAssembler* masm) {
  return Generate_s2s_FLoadMem(masm, kFloat32);
}
void Builtins::Generate_s2s_F64LoadMem(MacroAssembler* masm) {
  return Generate_s2s_FLoadMem(masm, kFloat64);
}

void Builtins::Generate_s2s_I32LoadMem8S_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt32, kIntS8);
}
void Builtins::Generate_s2s_I32LoadMem8U_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt32, kIntU8);
}
void Builtins::Generate_s2s_I32LoadMem16S_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt32, kIntS16);
}
void Builtins::Generate_s2s_I32LoadMem16U_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt32, kIntU16);
}
void Builtins::Generate_s2s_I64LoadMem8S_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt64, kIntS8);
}
void Builtins::Generate_s2s_I64LoadMem8U_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt64, kIntU8);
}
void Builtins::Generate_s2s_I64LoadMem16S_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt64, kIntS16);
}
void Builtins::Generate_s2s_I64LoadMem16U_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt64, kIntU16);
}
void Builtins::Generate_s2s_I64LoadMem32S_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt64, kIntS32);
}
void Builtins::Generate_s2s_I64LoadMem32U_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt64, kIntU32);
}
void Builtins::Generate_s2s_I32LoadMem_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt32, kIntS32);
}
void Builtins::Generate_s2s_I64LoadMem_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_ILoadMem_LocalSet(masm, kValueInt64, kInt64);
}
void Builtins::Generate_s2s_F32LoadMem_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_FLoadMem_LocalSet(masm, kFloat32);
}
void Builtins::Generate_s2s_F64LoadMem_LocalSet(MacroAssembler* masm) {
  return Generate_s2s_FLoadMem_LocalSet(masm, kFloat64);
}

void Builtins::Generate_r2s_I32StoreMem8(MacroAssembler* masm) {
  return Generate_r2s_IStoreMem(masm, kValueInt32, kIntS8);
}
void Builtins::Generate_r2s_I32StoreMem16(MacroAssembler* masm) {
  return Generate_r2s_IStoreMem(masm, kValueInt32, kIntS16);
}
void Builtins::Generate_r2s_I64StoreMem8(MacroAssembler* masm) {
  return Generate_r2s_IStoreMem(masm, kValueInt64, kIntS8);
}
void Builtins::Generate_r2s_I64StoreMem16(MacroAssembler* masm) {
  return Generate_r2s_IStoreMem(masm, kValueInt64, kIntS16);
}
void Builtins::Generate_r2s_I64StoreMem32(MacroAssembler* masm) {
  return Generate_r2s_IStoreMem(masm, kValueInt64, kIntS32);
}
void Builtins::Generate_r2s_I32StoreMem(MacroAssembler* masm) {
  return Generate_r2s_IStoreMem(masm, kValueInt32, kIntS32);
}
void Builtins::Generate_r2s_I64StoreMem(MacroAssembler* masm) {
  return Generate_r2s_IStoreMem(masm, kValueInt64, kInt64);
}
void Builtins::Generate_r2s_F32StoreMem(MacroAssembler* masm) {
  return Generate_r2s_FStoreMem(masm, kFloat32);
}
void Builtins::Generate_r2s_F64StoreMem(MacroAssembler* masm) {
  return Generate_r2s_FStoreMem(masm, kFloat64);
}

void Builtins::Generate_s2s_I32StoreMem8(MacroAssembler* masm) {
  return Generate_s2s_IStoreMem(masm, kValueInt32, kIntS8);
}
void Builtins::Generate_s2s_I32StoreMem16(MacroAssembler* masm) {
  return Generate_s2s_IStoreMem(masm, kValueInt32, kIntS16);
}
void Builtins::Generate_s2s_I64StoreMem8(MacroAssembler* masm) {
  return Generate_s2s_IStoreMem(masm, kValueInt64, kIntS8);
}
void Builtins::Generate_s2s_I64StoreMem16(MacroAssembler* masm) {
  return Generate_s2s_IStoreMem(masm, kValueInt64, kIntS16);
}
void Builtins::Generate_s2s_I64StoreMem32(MacroAssembler* masm) {
  return Generate_s2s_IStoreMem(masm, kValueInt64, kIntS32);
}
void Builtins::Generate_s2s_I32StoreMem(MacroAssembler* masm) {
  return Generate_s2s_IStoreMem(masm, kValueInt32, kIntS32);
}
void Builtins::Generate_s2s_I64StoreMem(MacroAssembler* masm) {
  return Generate_s2s_IStoreMem(masm, kValueInt64, kInt64);
}
void Builtins::Generate_s2s_F32StoreMem(MacroAssembler* masm) {
  return Generate_s2s_FStoreMem(masm, kFloat32);
}
void Builtins::Generate_s2s_F64StoreMem(MacroAssembler* masm) {
  return Generate_s2s_FStoreMem(masm, kFloat64);
}

void Builtins::Generate_r2s_I32LoadStoreMem(MacroAssembler* masm) {
  return Generate_r2s_ILoadStoreMem(masm, kValueInt32, kIntS32);
}
void Builtins::Generate_r2s_I64LoadStoreMem(MacroAssembler* masm) {
  return Generate_r2s_ILoadStoreMem(masm, kValueInt64, kInt64);
}
void Builtins::Generate_r2s_F32LoadStoreMem(MacroAssembler* masm) {
  return Generate_r2s_FLoadStoreMem(masm, kFloat32);
}
void Builtins::Generate_r2s_F64LoadStoreMem(MacroAssembler* masm) {
  return Generate_r2s_FLoadStoreMem(masm, kFloat64);
}
void Builtins::Generate_s2s_I32LoadStoreMem(MacroAssembler* masm) {
  return Generate_s2s_ILoadStoreMem(masm, kValueInt32, kIntS32);
}
void Builtins::Generate_s2s_I64LoadStoreMem(MacroAssembler* masm) {
  return Generate_s2s_ILoadStoreMem(masm, kValueInt64, kInt64);
}
void Builtins::Generate_s2s_F32LoadStoreMem(MacroAssembler* masm) {
  return Generate_s2s_FLoadStoreMem(masm, kFloat32);
}
void Builtins::Generate_s2s_F64LoadStoreMem(MacroAssembler* masm) {
  return Generate_s2s_FLoadStoreMem(masm, kFloat64);
}

#endif  // !V8_DRUMBRAKE_BOUNDS_CHECKS

#endif  // V8_ENABLE_WEBASSEMBLY

#undef __

}  // namespace internal
}  // namespace v8
```