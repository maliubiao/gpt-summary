Response:
The user wants me to analyze a C++ header file (`liftoff-assembler-riscv32-inl.h`) from the V8 project.
I need to determine its purpose and functionalities.
If the file ended with `.tq`, I would have to mention it's a Torque source file, but it doesn't.
I need to check if its functionality relates to JavaScript and provide an example if it does.
If there's any code logic, I need to create a hypothetical input and output scenario.
I also need to identify potential common programming errors related to the code.
Finally, I need to summarize the functionalities of the provided code snippet (which is the second part of a larger file).

Looking at the code, it seems to be defining methods for a `LiftoffAssembler` class, specifically for the RISC-V 32-bit architecture. It deals with low-level operations like:

- **Memory access:** Loading and storing values of different sizes (8, 16, 32, 64 bits) from/to memory locations.
- **Atomic operations:** Implementing compare-and-exchange operations.
- **Stack manipulation:** Loading and storing values from/to the stack, moving stack values.
- **Register manipulation:** Moving data between registers, spilling and filling registers.
- **Arithmetic and logical operations:** Implementing various arithmetic (add, subtract, multiply, divide, modulo) and logical (and, or, xor, shift, rotate) operations for both 32-bit and 64-bit integers.
- **Floating-point operations:** Handling floating-point conversions and some basic operations.
- **Control flow:** Implementing jumps and conditional jumps.
- **Type conversions:** Converting between different data types.

Since this code is part of the V8 JavaScript engine, it directly relates to how JavaScript code is compiled and executed at a low level. Liftoff is a baseline compiler in V8, so this code is responsible for generating machine code for JavaScript functions.

**Plan:**

1. Summarize the functionalities observed in the provided code snippet.
2. Relate the functionalities to JavaScript execution.
3. Provide a JavaScript example showcasing the usage of some of these low-level operations.
4. Create a hypothetical input/output for a simple code block.
5. List common programming errors related to manual memory management or incorrect type handling that this kind of low-level code might expose.
这是一个V8源代码文件，路径为 `v8/src/wasm/baseline/riscv/liftoff-assembler-riscv32-inl.h`。由于它以 `.h` 结尾，因此不是V8 Torque源代码。

**功能归纳：**

这个头文件（`liftoff-assembler-riscv32-inl.h`）定义了 `LiftoffAssembler` 类的一些内联成员函数，这些函数是用于在 RISC-V 32位架构上生成 WebAssembly (Wasm) 代码的。 `Liftoff` 是 V8 中一个用于快速编译 Wasm 代码的 baseline 编译器。 这段代码定义了执行各种 Wasm 操作所需的底层 RISC-V 汇编指令的封装。

具体来说，从提供的代码片段来看，`LiftoffAssembler` 的功能包括：

*   **原子操作支持:** 提供了原子比较并交换内存值的操作 (`AtomicCompareExchange`).
*   **内存操作:**
    *   加载和存储不同大小的数据 (8, 16, 32 位) 到内存中 (`AtomicCompareExchange` 中有体现，但此处更多是针对字操作).
    *   加载调用者栈帧的槽位 (`LoadCallerFrameSlot`).
    *   存储调用者栈帧的槽位 (`StoreCallerFrameSlot`).
    *   加载返回栈的槽位 (`LoadReturnStackSlot`).
    *   在栈上移动值 (`MoveStackValue`).
*   **寄存器操作:**
    *   移动寄存器之间的值 (`Move`).
    *   将寄存器的值溢出到栈上 (`Spill`).
    *   将立即数溢出到栈上 (`Spill`).
    *   从栈上填充寄存器 (`Fill`).
    *   填充 64 位寄存器的一半 (`FillI64Half`).
*   **栈操作:** 用零填充指定大小的栈空间 (`FillStackSlotsWithZero`).
*   **位操作:**
    *   计算 64 位整数的前导零个数 (`emit_i64_clz`).
    *   计算 64 位整数的后导零个数 (`emit_i64_ctz`).
    *   计算 64 位整数的置位位数 (`emit_i64_popcnt`).
    *   计算 32 位整数的前导零个数 (`emit_i32_clz`).
    *   计算 32 位整数的后导零个数 (`emit_i32_ctz`).
    *   计算 32 位整数的置位位数 (`emit_i32_popcnt`).
*   **算术运算 (32 位):**
    *   乘法 (`emit_i32_mul`, `emit_i32_muli`).
    *   带符号除法 (`emit_i32_divs`).
    *   无符号除法 (`emit_i32_divu`).
    *   带符号取余 (`emit_i32_rems`).
    *   无符号取余 (`emit_i32_remu`).
    *   加法 (`emit_i32_add`, `emit_i32_addi`).
    *   减法 (`emit_i32_sub`, `emit_i32_subi`).
    *   按位与 (`emit_i32_and`, `emit_i32_andi`).
    *   按位或 (`emit_i32_or`, `emit_i32_ori`).
    *   按位异或 (`emit_i32_xor`, `emit_i32_xori`).
    *   左移 (`emit_i32_shl`, `emit_i32_shli`).
    *   算术右移 (`emit_i32_sar`, `emit_i32_sari`).
    *   逻辑右移 (`emit_i32_shr`, `emit_i32_shri`).
*   **算术运算 (64 位):**
    *   乘法 (`emit_i64_mul`).
    *   加法 (`emit_i64_add`, `emit_i64_addi`).
    *   减法 (`emit_i64_sub`).
    *   左移 (`emit_i64_shl`, `emit_i64_shli`).
    *   算术右移 (`emit_i64_sar`, `emit_i64_sari`).
    *   逻辑右移 (`emit_i64_shr`, `emit_i64_shri`).
*   **浮点转换:** 提供了一些浮点数转换的占位符或简单实现，例如 `emit_f64_ceil`, `emit_f64_floor` 等返回 `false`，表示可能由其他机制处理或尚未实现。但也实现了部分类型转换操作，例如整数和浮点数之间的转换 (`emit_type_conversion`).
*   **向量操作:** 提供了从 128 位向量中提取 64 位数据的操作 (`emit_i64x2_extract_lane`).
*   **符号扩展:**  提供了将较小整数类型扩展到较大整数类型的操作 (`emit_i32_signextend_i8`, `emit_i32_signextend_i16`, `emit_i64_signextend_i8`, `emit_i64_signextend_i16`, `emit_i64_signextend_i32`).
*   **控制流:**
    *   无条件跳转 (`emit_jump`).
    *   条件跳转 (`emit_cond_jump`, `emit_i32_cond_jumpi`).
    *   判断 32 位整数是否为零 (`emit_i32_eqz`).
    *   设置基于比较结果的标志 (`emit_i32_set_cond`, `emit_i64_set_cond`).
*   **其他操作:**
    *   递增内存中的 Smi 值 (`IncrementSmi`).

**与 JavaScript 的关系：**

这个文件直接关系到 JavaScript 的执行。当 V8 执行 WebAssembly 代码时，`LiftoffCompiler` 会将 Wasm 指令转换为目标架构（这里是 RISC-V 32位）的机器码。 `LiftoffAssembler` 提供的这些函数就是用于生成这些机器码指令的。 例如，当 JavaScript 调用一个 WebAssembly 函数，并且该函数内部执行了一个整数加法操作时，`emit_i32_add` 或类似的函数就会被调用来生成 RISC-V 的 `add` 指令。

**JavaScript 示例：**

虽然我们不能直接在 JavaScript 中调用这些 C++ 函数，但我们可以通过一个 JavaScript 例子来理解这些底层操作在 WebAssembly 中的作用，而 WebAssembly 又是由 JavaScript 调用的。

```javascript
// 假设我们有一个 WebAssembly 模块，它执行一个简单的整数加法
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // 魔数和版本
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // 类型定义：(i32, i32) => i32
  0x03, 0x02, 0x01, 0x00, // 函数定义：导入一个函数
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b // 代码段：本地函数实现 i0 + i1
]);

const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 调用 WebAssembly 模块中的函数
const result = wasmInstance.exports.add(5, 10);
console.log(result); // 输出 15
```

在这个例子中，Wasm 代码中的 `0x6a` 操作码代表 `i32.add`（32位整数加法）。当 V8 执行这段 Wasm 代码时，`LiftoffCompiler` 中的 `LiftoffAssembler` 会使用类似 `emit_i32_add` 的函数生成 RISC-V 的 `add` 指令，从而完成实际的加法运算。

**代码逻辑推理：**

以 `emit_i32_add(Register dst, Register lhs, Register rhs)` 函数为例：

**假设输入：**

*   `dst` 代表 RISC-V 寄存器 `a0`
*   `lhs` 代表 RISC-V 寄存器 `a1`，其值为 `5`
*   `rhs` 代表 RISC-V 寄存器 `a2`，其值为 `10`

**输出：**

该函数会生成 RISC-V 的 `add a0, a1, a2` 指令。执行这条指令后，寄存器 `a0` 的值将变为 `15`。

**用户常见的编程错误：**

在使用这种底层的汇编器时，常见的编程错误包括：

*   **寄存器分配错误：** 错误地使用了已经被占用的寄存器，导致数据被覆盖。`LiftoffAssembler` 尝试管理寄存器分配，但手动操作时容易出错。
*   **栈溢出/栈访问越界：** 在栈上分配或访问了超出范围的内存，可能导致程序崩溃或数据损坏。例如，在 `MoveStackValue` 中，如果 `dst_offset` 或 `src_offset` 计算错误，就可能发生越界访问。
*   **类型不匹配：**  尝试对不同类型的数据执行操作，例如将浮点数直接当作整数处理。尽管 `LiftoffAssembler` 在一定程度上强制类型，但在手动构建指令时仍可能出错。
*   **内存地址计算错误：** 在加载或存储数据时，计算的内存地址不正确，导致访问错误的内存位置。例如，在 `AtomicCompareExchange` 中，如果 `actual_addr` 的计算有误，原子操作将作用于错误的地址。
*   **条件码使用错误：** 在条件跳转指令中使用了错误的条件码，导致程序执行流程错误。
*   **不理解指令的副作用：**  某些指令可能会修改额外的寄存器或状态标志，如果没考虑到这些副作用，可能会导致意外的行为。例如，某些算术指令会设置标志位。

总结一下，这个代码片段是 V8 的 `Liftoff` 编译器在 RISC-V 32位架构下生成 WebAssembly 代码的关键部分，它封装了底层的 RISC-V 汇编指令，用于实现各种 Wasm 操作，直接关系到 JavaScript 中 WebAssembly 模块的执行效率和正确性。

### 提示词
```
这是目录为v8/src/wasm/baseline/riscv/liftoff-assembler-riscv32-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/riscv/liftoff-assembler-riscv32-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
expected.high_gp());
    Mv(a3, new_value.low_gp());
    Mv(a4, new_value.high_gp());
    Mv(a0, actual_addr);

    MultiPush(kJSCallerSaved - c_params - result_list);
    PrepareCallCFunction(5, 0, kScratchReg);
    CallCFunction(ExternalReference::atomic_pair_compare_exchange_function(), 5,
                  0);
    MultiPop(kJSCallerSaved - c_params - result_list);
    Mv(kScratchReg, kReturnRegister1);
    Mv(result.low_gp(), kReturnRegister0);
    Mv(result.high_gp(), kScratchReg);
    MultiPop(c_params - result_list);
    return;
  }
  // Make sure that {result} is unique.
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI64Store16:
    case StoreType::kI64Store32:
      LoadConstant(result.high(), WasmValue(0));
      result = result.low();
      new_value = new_value.low();
      expected = expected.low();
      break;
    case StoreType::kI32Store8:
    case StoreType::kI32Store16:
    case StoreType::kI32Store:
      break;
    default:
      UNREACHABLE();
  }

  UseScratchRegisterScope temps(this);
  Register actual_addr = liftoff::CalculateActualAddress(
      this, temps, dst_addr, offset_reg, offset_imm, kScratchReg);

  Register temp0 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp1 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp2 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();

  if (type.value() != StoreType::kI32Store &&
      type.value() != StoreType::kI64Store32) {
    And(temp1, actual_addr, 0x3);
    SubWord(temp0, actual_addr, Operand(temp1));
    SllWord(temp1, temp1, 3);
  }
  Label retry;
  Label done;
  bind(&retry);
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8:
      lr_w(true, true, temp2, temp0);
      ExtractBits(result.gp(), temp2, temp1, 8, false);
      ExtractBits(temp2, expected.gp(), zero_reg, 8, false);
      Branch(&done, ne, temp2, Operand(result.gp()));
      InsertBits(temp2, new_value.gp(), temp1, 8);
      sc_w(true, true, temp2, temp0, temp2);
      break;
    case StoreType::kI64Store16:
    case StoreType::kI32Store16:
      lr_w(true, true, temp2, temp0);
      ExtractBits(result.gp(), temp2, temp1, 16, false);
      ExtractBits(temp2, expected.gp(), zero_reg, 16, false);
      Branch(&done, ne, temp2, Operand(result.gp()));
      InsertBits(temp2, new_value.gp(), temp1, 16);
      sc_w(true, true, temp2, temp0, temp2);
      break;
    case StoreType::kI64Store32:
    case StoreType::kI32Store:
      lr_w(true, true, result.gp(), actual_addr);
      Branch(&done, ne, result.gp(), Operand(expected.gp()));
      sc_w(true, true, temp2, actual_addr, new_value.gp());
      break;
    default:
      UNREACHABLE();
  }
  bnez(temp2, &retry);
  bind(&done);
}

void LiftoffAssembler::AtomicFence() { sync(); }

void LiftoffAssembler::LoadCallerFrameSlot(LiftoffRegister dst,
                                           uint32_t caller_slot_idx,
                                           ValueKind kind) {
  int32_t offset = kSystemPointerSize * (caller_slot_idx + 1);
  liftoff::Load(this, dst, fp, offset, kind);
}

void LiftoffAssembler::StoreCallerFrameSlot(LiftoffRegister src,
                                            uint32_t caller_slot_idx,
                                            ValueKind kind,
                                            Register frame_pointer) {
  int32_t offset = kSystemPointerSize * (caller_slot_idx + 1);
  liftoff::Store(this, frame_pointer, offset, src, kind);
}

void LiftoffAssembler::LoadReturnStackSlot(LiftoffRegister dst, int offset,
                                           ValueKind kind) {
  liftoff::Load(this, dst, sp, offset, kind);
}

void LiftoffAssembler::MoveStackValue(uint32_t dst_offset, uint32_t src_offset,
                                      ValueKind kind) {
  DCHECK_NE(dst_offset, src_offset);

  MemOperand src = liftoff::GetStackSlot(src_offset);
  MemOperand dst = liftoff::GetStackSlot(dst_offset);
  switch (kind) {
    case kI32:
      Lw(kScratchReg, src);
      Sw(kScratchReg, dst);
      break;
    case kI64:
    case kRef:
    case kRefNull:
    case kRtt:
      Lw(kScratchReg, src);
      Sw(kScratchReg, dst);
      src = liftoff::GetStackSlot(src_offset - 4);
      dst = liftoff::GetStackSlot(dst_offset - 4);
      Lw(kScratchReg, src);
      Sw(kScratchReg, dst);
      break;
    case kF32:
      LoadFloat(kScratchDoubleReg, src);
      StoreFloat(kScratchDoubleReg, dst);
      break;
    case kF64:
      MacroAssembler::LoadDouble(kScratchDoubleReg, src);
      MacroAssembler::StoreDouble(kScratchDoubleReg, dst);
      break;
    case kS128: {
      VU.set(kScratchReg, E8, m1);
      Register src_reg = src.offset() == 0 ? src.rm() : kScratchReg;
      if (src.offset() != 0) {
        MacroAssembler::AddWord(src_reg, src.rm(), src.offset());
      }
      vl(kSimd128ScratchReg, src_reg, 0, E8);
      Register dst_reg = dst.offset() == 0 ? dst.rm() : kScratchReg;
      if (dst.offset() != 0) {
        AddWord(kScratchReg, dst.rm(), dst.offset());
      }
      vs(kSimd128ScratchReg, dst_reg, 0, VSew::E8);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Move(Register dst, Register src, ValueKind kind) {
  DCHECK_NE(dst, src);
  // TODO(ksreten): Handle different sizes here.
  MacroAssembler::Move(dst, src);
}

void LiftoffAssembler::Move(DoubleRegister dst, DoubleRegister src,
                            ValueKind kind) {
  DCHECK_NE(dst, src);
  if (kind != kS128) {
    MacroAssembler::Move(dst, src);
  } else {
    VU.set(kScratchReg, E8, m1);
    MacroAssembler::vmv_vv(dst.toV(), src.toV());
  }
}

void LiftoffAssembler::Spill(int offset, LiftoffRegister reg, ValueKind kind) {
  RecordUsedSpillOffset(offset);
  MemOperand dst = liftoff::GetStackSlot(offset);
  switch (kind) {
    case kI32:
    case kRef:
    case kRefNull:
    case kRtt:
      Sw(reg.gp(), dst);
      break;
    case kI64:
      Sw(reg.low_gp(), liftoff::GetHalfStackSlot(offset, kLowWord));
      Sw(reg.high_gp(), liftoff::GetHalfStackSlot(offset, kHighWord));
      break;
    case kF32:
      StoreFloat(reg.fp(), dst);
      break;
    case kF64:
      MacroAssembler::StoreDouble(reg.fp(), dst);
      break;
    case kS128: {
      VU.set(kScratchReg, E8, m1);
      Register dst_reg = dst.offset() == 0 ? dst.rm() : kScratchReg;
      if (dst.offset() != 0) {
        AddWord(kScratchReg, dst.rm(), dst.offset());
      }
      vs(reg.fp().toV(), dst_reg, 0, VSew::E8);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Spill(int offset, WasmValue value) {
  RecordUsedSpillOffset(offset);
  MemOperand dst = liftoff::GetStackSlot(offset);
  UseScratchRegisterScope assembler_temps(this);
  Register tmp = assembler_temps.Acquire();
  switch (value.type().kind()) {
    case kI32:
    case kRef:
    case kRefNull: {
      MacroAssembler::li(tmp, Operand(value.to_i32()));
      Sw(tmp, dst);
      break;
    }
    case kI64: {
      int32_t low_word = value.to_i64();
      int32_t high_word = value.to_i64() >> 32;
      MacroAssembler::li(tmp, Operand(low_word));
      Sw(tmp, liftoff::GetHalfStackSlot(offset, kLowWord));
      MacroAssembler::li(tmp, Operand(high_word));
      Sw(tmp, liftoff::GetHalfStackSlot(offset, kHighWord));
      break;
      break;
    }
    default:
      // kWasmF32 and kWasmF64 are unreachable, since those
      // constants are not tracked.
      UNREACHABLE();
  }
}

void LiftoffAssembler::Fill(LiftoffRegister reg, int offset, ValueKind kind) {
  MemOperand src = liftoff::GetStackSlot(offset);
  switch (kind) {
    case kI32:
    case kRef:
    case kRefNull:
      Lw(reg.gp(), src);
      break;
    case kI64:
      Lw(reg.low_gp(), liftoff::GetHalfStackSlot(offset, kLowWord));
      Lw(reg.high_gp(), liftoff::GetHalfStackSlot(offset, kHighWord));
      break;
    case kF32:
      LoadFloat(reg.fp(), src);
      break;
    case kF64:
      MacroAssembler::LoadDouble(reg.fp(), src);
      break;
    case kS128: {
      VU.set(kScratchReg, E8, m1);
      Register src_reg = src.offset() == 0 ? src.rm() : kScratchReg;
      if (src.offset() != 0) {
        MacroAssembler::AddWord(src_reg, src.rm(), src.offset());
      }
      vl(reg.fp().toV(), src_reg, 0, E8);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::FillI64Half(Register reg, int offset, RegPairHalf half) {
  Lw(reg, liftoff::GetHalfStackSlot(offset, half));
}

void LiftoffAssembler::FillStackSlotsWithZero(int start, int size) {
  DCHECK_LT(0, size);
  RecordUsedSpillOffset(start + size);

  // TODO(riscv32): check

  if (size <= 12 * kStackSlotSize) {
    // Special straight-line code for up to 12 slots. Generates one
    // instruction per slot (<= 12 instructions total).
    uint32_t remainder = size;
    for (; remainder >= kStackSlotSize; remainder -= kStackSlotSize) {
      Sw(zero_reg, liftoff::GetStackSlot(start + remainder));
      Sw(zero_reg, liftoff::GetStackSlot(start + remainder - 4));
    }
    DCHECK(remainder == 4 || remainder == 0);
    if (remainder) {
      Sw(zero_reg, liftoff::GetStackSlot(start + remainder));
    }
  } else {
    // General case for bigger counts (12 instructions).
    // Use a0 for start address (inclusive), a1 for end address (exclusive).
    Push(a1, a0);
    AddWord(a0, fp, Operand(-start - size));
    AddWord(a1, fp, Operand(-start));

    Label loop;
    bind(&loop);
    Sw(zero_reg, MemOperand(a0));
    addi(a0, a0, kSystemPointerSize);
    BranchShort(&loop, ne, a0, Operand(a1));

    Pop(a1, a0);
  }
}

void LiftoffAssembler::emit_i64_clz(LiftoffRegister dst, LiftoffRegister src) {
  // return high == 0 ? 32 + CLZ32(low) : CLZ32(high);
  Label done;
  Label high_is_zero;
  Branch(&high_is_zero, eq, src.high_gp(), Operand(zero_reg));

  Clz32(dst.low_gp(), src.high_gp());
  jmp(&done);

  bind(&high_is_zero);
  Clz32(dst.low_gp(), src.low_gp());
  AddWord(dst.low_gp(), dst.low_gp(), Operand(32));

  bind(&done);
  mv(dst.high_gp(), zero_reg);  // High word of result is always 0.
}

void LiftoffAssembler::emit_i64_ctz(LiftoffRegister dst, LiftoffRegister src) {
  // return low == 0 ? 32 + CTZ32(high) : CTZ32(low);
  Label done;
  Label low_is_zero;
  Branch(&low_is_zero, eq, src.low_gp(), Operand(zero_reg));

  Ctz32(dst.low_gp(), src.low_gp());
  jmp(&done);

  bind(&low_is_zero);
  Ctz32(dst.low_gp(), src.high_gp());
  AddWord(dst.low_gp(), dst.low_gp(), Operand(32));

  bind(&done);
  mv(dst.high_gp(), zero_reg);  // High word of result is always 0.
}

bool LiftoffAssembler::emit_i64_popcnt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  // Produce partial popcnts in the two dst registers.
  Register src1 = src.high_gp() == dst.low_gp() ? src.high_gp() : src.low_gp();
  Register src2 = src.high_gp() == dst.low_gp() ? src.low_gp() : src.high_gp();
  MacroAssembler::Popcnt32(dst.low_gp(), src1, kScratchReg);
  MacroAssembler::Popcnt32(dst.high_gp(), src2, kScratchReg);
  // Now add the two into the lower dst reg and clear the higher dst reg.
  AddWord(dst.low_gp(), dst.low_gp(), dst.high_gp());
  mv(dst.high_gp(), zero_reg);
  return true;
}

void LiftoffAssembler::emit_i32_mul(Register dst, Register lhs, Register rhs) {
  MacroAssembler::Mul(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_muli(Register dst, Register lhs, int32_t imm) {
  if (base::bits::IsPowerOfTwo(imm)) {
    emit_i32_shli(dst, lhs, base::bits::WhichPowerOfTwo(imm));
    return;
  }
  UseScratchRegisterScope temps{this};
  Register scratch = temps.Acquire();
  li(scratch, Operand{imm});
  MacroAssembler::Mul(dst, lhs, scratch);
}

void LiftoffAssembler::emit_i32_divs(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));

  // Check if lhs == kMinInt and rhs == -1, since this case is unrepresentable.
  MacroAssembler::CompareI(kScratchReg, lhs, Operand(kMinInt), ne);
  MacroAssembler::CompareI(kScratchReg2, rhs, Operand(-1), ne);
  add(kScratchReg, kScratchReg, kScratchReg2);
  MacroAssembler::Branch(trap_div_unrepresentable, eq, kScratchReg,
                         Operand(zero_reg));

  MacroAssembler::Div(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_divu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Divu(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_rems(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Mod(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_remu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Modu(dst, lhs, rhs);
}

#define I32_BINOP(name, instruction)                                 \
  void LiftoffAssembler::emit_i32_##name(Register dst, Register lhs, \
                                         Register rhs) {             \
    instruction(dst, lhs, rhs);                                      \
  }

// clang-format off
I32_BINOP(add, add)
I32_BINOP(sub, sub)
I32_BINOP(and, and_)
I32_BINOP(or, or_)
I32_BINOP(xor, xor_)
// clang-format on

#undef I32_BINOP

#define I32_BINOP_I(name, instruction)                                  \
  void LiftoffAssembler::emit_i32_##name##i(Register dst, Register lhs, \
                                            int32_t imm) {              \
    instruction(dst, lhs, Operand(imm));                                \
  }

// clang-format off
I32_BINOP_I(add, AddWord)
I32_BINOP_I(sub, SubWord)
I32_BINOP_I(and, And)
I32_BINOP_I(or, Or)
I32_BINOP_I(xor, Xor)
// clang-format on

#undef I32_BINOP_I

void LiftoffAssembler::emit_i32_clz(Register dst, Register src) {
  MacroAssembler::Clz32(dst, src);
}

void LiftoffAssembler::emit_i32_ctz(Register dst, Register src) {
  MacroAssembler::Ctz32(dst, src);
}

bool LiftoffAssembler::emit_i32_popcnt(Register dst, Register src) {
  MacroAssembler::Popcnt32(dst, src, kScratchReg);
  return true;
}

#define I32_SHIFTOP(name, instruction)                               \
  void LiftoffAssembler::emit_i32_##name(Register dst, Register src, \
                                         Register amount) {          \
    instruction(dst, src, amount);                                   \
  }
#define I32_SHIFTOP_I(name, instruction)                                \
  void LiftoffAssembler::emit_i32_##name##i(Register dst, Register src, \
                                            int amount) {               \
    instruction(dst, src, amount & 31);                                 \
  }

I32_SHIFTOP(shl, sll)
I32_SHIFTOP(sar, sra)
I32_SHIFTOP(shr, srl)

I32_SHIFTOP_I(shl, slli)
I32_SHIFTOP_I(sar, srai)
I32_SHIFTOP_I(shr, srli)

#undef I32_SHIFTOP
#undef I32_SHIFTOP_I

void LiftoffAssembler::emit_i64_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  MacroAssembler::MulPair(dst.low_gp(), dst.high_gp(), lhs.low_gp(),
                          lhs.high_gp(), rhs.low_gp(), rhs.high_gp(),
                          kScratchReg, kScratchReg2);
}

// Implemented by the host function in external-reference.h(Call to host
// function wasm::xxx).
bool LiftoffAssembler::emit_i64_divs(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  return false;
}

bool LiftoffAssembler::emit_i64_divu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  return false;
}

bool LiftoffAssembler::emit_i64_rems(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  return false;
}

bool LiftoffAssembler::emit_i64_remu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  return false;
}

namespace liftoff {

inline bool IsRegInRegPair(LiftoffRegister pair, Register reg) {
  DCHECK(pair.is_gp_pair());
  return pair.low_gp() == reg || pair.high_gp() == reg;
}

inline void Emit64BitShiftOperation(
    LiftoffAssembler* assm, LiftoffRegister dst, LiftoffRegister src,
    Register amount,
    void (MacroAssembler::*emit_shift)(Register, Register, Register, Register,
                                       Register, Register, Register)) {
  LiftoffRegList pinned{dst, src, amount};

  // If some of destination registers are in use, get another, unused pair.
  // That way we prevent overwriting some input registers while shifting.
  // Do this before any branch so that the cache state will be correct for
  // all conditions.
  Register amount_capped =
      pinned.set(assm->GetUnusedRegister(kGpReg, pinned).gp());
  assm->And(amount_capped, amount, Operand(63));
  if (liftoff::IsRegInRegPair(dst, amount) || dst.overlaps(src)) {
    // Do the actual shift.
    LiftoffRegister tmp = assm->GetUnusedRegister(kGpRegPair, pinned);
    (assm->*emit_shift)(tmp.low_gp(), tmp.high_gp(), src.low_gp(),
                        src.high_gp(), amount_capped, kScratchReg,
                        kScratchReg2);

    // Place result in destination register.
    assm->MacroAssembler::Move(dst.high_gp(), tmp.high_gp());
    assm->MacroAssembler::Move(dst.low_gp(), tmp.low_gp());
  } else {
    (assm->*emit_shift)(dst.low_gp(), dst.high_gp(), src.low_gp(),
                        src.high_gp(), amount_capped, kScratchReg,
                        kScratchReg2);
  }
}
}  // namespace liftoff

void LiftoffAssembler::emit_i64_add(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  MacroAssembler::AddPair(dst.low_gp(), dst.high_gp(), lhs.low_gp(),
                          lhs.high_gp(), rhs.low_gp(), rhs.high_gp(),
                          kScratchReg, kScratchReg2);
}

void LiftoffAssembler::emit_i64_addi(LiftoffRegister dst, LiftoffRegister lhs,
                                     int64_t imm) {
  LiftoffRegister imm_reg =
      GetUnusedRegister(kGpRegPair, LiftoffRegList{dst, lhs});
  int32_t imm_low_word = static_cast<int32_t>(imm);
  int32_t imm_high_word = static_cast<int32_t>(imm >> 32);

  // TODO(riscv32): are there some optimization we can make without
  // materializing?
  MacroAssembler::li(imm_reg.low_gp(), imm_low_word);
  MacroAssembler::li(imm_reg.high_gp(), imm_high_word);
  MacroAssembler::AddPair(dst.low_gp(), dst.high_gp(), lhs.low_gp(),
                          lhs.high_gp(), imm_reg.low_gp(), imm_reg.high_gp(),
                          kScratchReg, kScratchReg2);
}

void LiftoffAssembler::emit_i64_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  MacroAssembler::SubPair(dst.low_gp(), dst.high_gp(), lhs.low_gp(),
                          lhs.high_gp(), rhs.low_gp(), rhs.high_gp(),
                          kScratchReg, kScratchReg2);
}

void LiftoffAssembler::emit_i64_shl(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  ASM_CODE_COMMENT(this);
  liftoff::Emit64BitShiftOperation(this, dst, src, amount,
                                   &MacroAssembler::ShlPair);
}

void LiftoffAssembler::emit_i64_shli(LiftoffRegister dst, LiftoffRegister src,
                                     int amount) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  LiftoffRegister temp = GetUnusedRegister(kGpReg, LiftoffRegList{dst, src});
  temps.Include(temp.gp());
  // {src.low_gp()} will still be needed after writing {dst.high_gp()} and
  // {dst.low_gp()}.
  Register src_low = liftoff::EnsureNoAlias(this, src.low_gp(), dst, &temps);
  Register src_high = liftoff::EnsureNoAlias(this, src.high_gp(), dst, &temps);
  // {src.high_gp()} will still be needed after writing {dst.high_gp()}.
  DCHECK_NE(dst.low_gp(), kScratchReg);
  DCHECK_NE(dst.high_gp(), kScratchReg);

  MacroAssembler::ShlPair(dst.low_gp(), dst.high_gp(), src_low, src_high,
                          amount & 63, kScratchReg, kScratchReg2);
}

void LiftoffAssembler::emit_i64_sar(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::Emit64BitShiftOperation(this, dst, src, amount,
                                   &MacroAssembler::SarPair);
}

void LiftoffAssembler::emit_i64_sari(LiftoffRegister dst, LiftoffRegister src,
                                     int amount) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  LiftoffRegister temp = GetUnusedRegister(kGpReg, LiftoffRegList{dst, src});
  temps.Include(temp.gp());
  // {src.low_gp()} will still be needed after writing {dst.high_gp()} and
  // {dst.low_gp()}.
  Register src_low = liftoff::EnsureNoAlias(this, src.low_gp(), dst, &temps);
  Register src_high = liftoff::EnsureNoAlias(this, src.high_gp(), dst, &temps);
  DCHECK_NE(dst.low_gp(), kScratchReg);
  DCHECK_NE(dst.high_gp(), kScratchReg);

  MacroAssembler::SarPair(dst.low_gp(), dst.high_gp(), src_low, src_high,
                          amount & 63, kScratchReg, kScratchReg2);
}

void LiftoffAssembler::emit_i64_shr(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::Emit64BitShiftOperation(this, dst, src, amount,
                                   &MacroAssembler::ShrPair);
}

void LiftoffAssembler::emit_i64_shri(LiftoffRegister dst, LiftoffRegister src,
                                     int amount) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  LiftoffRegister temp = GetUnusedRegister(kGpReg, LiftoffRegList{dst, src});
  temps.Include(temp.gp());
  // {src.low_gp()} will still be needed after writing {dst.high_gp()} and
  // {dst.low_gp()}.
  Register src_low = liftoff::EnsureNoAlias(this, src.low_gp(), dst, &temps);
  Register src_high = liftoff::EnsureNoAlias(this, src.high_gp(), dst, &temps);
  DCHECK_NE(dst.low_gp(), kScratchReg);
  DCHECK_NE(dst.high_gp(), kScratchReg);

  MacroAssembler::ShrPair(dst.low_gp(), dst.high_gp(), src_low, src_high,
                          amount & 63, kScratchReg, kScratchReg2);
}

#define FP_UNOP_RETURN_FALSE(name)                                             \
  bool LiftoffAssembler::emit_##name(DoubleRegister dst, DoubleRegister src) { \
    return false;                                                              \
  }

FP_UNOP_RETURN_FALSE(f64_ceil)
FP_UNOP_RETURN_FALSE(f64_floor)
FP_UNOP_RETURN_FALSE(f64_trunc)
FP_UNOP_RETURN_FALSE(f64_nearest_int)

#undef FP_UNOP_RETURN_FALSE

bool LiftoffAssembler::emit_type_conversion(WasmOpcode opcode,
                                            LiftoffRegister dst,
                                            LiftoffRegister src, Label* trap) {
  switch (opcode) {
    case kExprI32ConvertI64:
      MacroAssembler::Move(dst.gp(), src.low_gp());
      return true;
    case kExprI32SConvertF32:
    case kExprI32UConvertF32:
    case kExprI32SConvertF64:
    case kExprI32UConvertF64:
    case kExprI64SConvertF32:
    case kExprI64UConvertF32:
    case kExprI64SConvertF64:
    case kExprI64UConvertF64:
    case kExprF32ConvertF64: {
      // real conversion, if src is out-of-bound of target integer types,
      // kScratchReg is set to 0
      switch (opcode) {
        case kExprI32SConvertF32:
          Trunc_w_s(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprI32UConvertF32:
          Trunc_uw_s(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprI32SConvertF64:
          Trunc_w_d(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprI32UConvertF64:
          Trunc_uw_d(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprF32ConvertF64:
          fcvt_s_d(dst.fp(), src.fp());
          break;
        case kExprI64SConvertF32:
        case kExprI64UConvertF32:
        case kExprI64SConvertF64:
        case kExprI64UConvertF64:
          return false;
        default:
          UNREACHABLE();
      }

      // Checking if trap.
      if (trap != nullptr) {
        MacroAssembler::Branch(trap, eq, kScratchReg, Operand(zero_reg));
      }

      return true;
    }
    case kExprI32ReinterpretF32:
      MacroAssembler::ExtractLowWordFromF64(dst.gp(), src.fp());
      return true;
    case kExprI64SConvertI32:
      MacroAssembler::Move(dst.low_gp(), src.gp());
      MacroAssembler::Move(dst.high_gp(), src.gp());
      srai(dst.high_gp(), dst.high_gp(), 31);
      return true;
    case kExprI64UConvertI32:
      MacroAssembler::Move(dst.low_gp(), src.gp());
      MacroAssembler::Move(dst.high_gp(), zero_reg);
      return true;
    case kExprI64ReinterpretF64:
      SubWord(sp, sp, kDoubleSize);
      StoreDouble(src.fp(), MemOperand(sp, 0));
      Lw(dst.low_gp(), MemOperand(sp, 0));
      Lw(dst.high_gp(), MemOperand(sp, 4));
      AddWord(sp, sp, kDoubleSize);
      return true;
    case kExprF32SConvertI32: {
      MacroAssembler::Cvt_s_w(dst.fp(), src.gp());
      return true;
    }
    case kExprF32UConvertI32:
      MacroAssembler::Cvt_s_uw(dst.fp(), src.gp());
      return true;
    case kExprF32ReinterpretI32:
      fmv_w_x(dst.fp(), src.gp());
      return true;
    case kExprF64SConvertI32: {
      MacroAssembler::Cvt_d_w(dst.fp(), src.gp());
      return true;
    }
    case kExprF64UConvertI32:
      MacroAssembler::Cvt_d_uw(dst.fp(), src.gp());
      return true;
    case kExprF64ConvertF32:
      fcvt_d_s(dst.fp(), src.fp());
      return true;
    case kExprF64ReinterpretI64:
      SubWord(sp, sp, kDoubleSize);
      Sw(src.low_gp(), MemOperand(sp, 0));
      Sw(src.high_gp(), MemOperand(sp, 4));
      LoadDouble(dst.fp(), MemOperand(sp, 0));
      AddWord(sp, sp, kDoubleSize);
      return true;
    case kExprI32SConvertSatF32: {
      fcvt_w_s(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_s(dst.gp(), src.fp());
      return true;
    }
    case kExprI32UConvertSatF32: {
      fcvt_wu_s(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_s(dst.gp(), src.fp());
      return true;
    }
    case kExprI32SConvertSatF64: {
      fcvt_w_d(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_d(dst.gp(), src.fp());
      return true;
    }
    case kExprI32UConvertSatF64: {
      fcvt_wu_d(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_d(dst.gp(), src.fp());
      return true;
    }
    case kExprI64SConvertSatF32:
    case kExprI64UConvertSatF32:
    case kExprI64SConvertSatF64:
    case kExprI64UConvertSatF64:
      return false;
    default:
      return false;
  }
}

void LiftoffAssembler::emit_i64x2_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E32, m1);
  vslidedown_vi(kSimd128ScratchReg, lhs.fp().toV(), (imm_lane_idx << 0x1) + 1);
  vmv_xs(dst.high_gp(), kSimd128ScratchReg);
  vslidedown_vi(kSimd128ScratchReg, lhs.fp().toV(), imm_lane_idx << 0x1);
  vmv_xs(dst.low_gp(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32_signextend_i8(Register dst, Register src) {
  slli(dst, src, 32 - 8);
  srai(dst, dst, 32 - 8);
}

void LiftoffAssembler::emit_i32_signextend_i16(Register dst, Register src) {
  slli(dst, src, 32 - 16);
  srai(dst, dst, 32 - 16);
}

void LiftoffAssembler::emit_i64_signextend_i8(LiftoffRegister dst,
                                              LiftoffRegister src) {
  emit_i32_signextend_i8(dst.low_gp(), src.low_gp());
  srai(dst.high_gp(), dst.low_gp(), 31);
}

void LiftoffAssembler::emit_i64_signextend_i16(LiftoffRegister dst,
                                               LiftoffRegister src) {
  emit_i32_signextend_i16(dst.low_gp(), src.low_gp());
  srai(dst.high_gp(), dst.low_gp(), 31);
}

void LiftoffAssembler::emit_i64_signextend_i32(LiftoffRegister dst,
                                               LiftoffRegister src) {
  mv(dst.low_gp(), src.low_gp());
  srai(dst.high_gp(), src.low_gp(), 31);
}

void LiftoffAssembler::emit_jump(Label* label) {
  MacroAssembler::Branch(label);
}

void LiftoffAssembler::emit_jump(Register target) {
  MacroAssembler::Jump(target);
}

void LiftoffAssembler::emit_cond_jump(Condition cond, Label* label,
                                      ValueKind kind, Register lhs,
                                      Register rhs,
                                      const FreezeCacheState& frozen) {
  if (rhs == no_reg) {
    DCHECK(kind == kI32);
    MacroAssembler::Branch(label, cond, lhs, Operand(zero_reg));
  } else {
    DCHECK((kind == kI32) ||
           (is_reference(kind) && (cond == kEqual || cond == kNotEqual)));
    MacroAssembler::Branch(label, cond, lhs, Operand(rhs));
  }
}

void LiftoffAssembler::emit_i32_cond_jumpi(Condition cond, Label* label,
                                           Register lhs, int32_t imm,
                                           const FreezeCacheState& frozen) {
  MacroAssembler::Branch(label, cond, lhs, Operand(imm));
}

void LiftoffAssembler::emit_i32_eqz(Register dst, Register src) {
  MacroAssembler::Sltu(dst, src, 1);
}

void LiftoffAssembler::emit_i32_set_cond(Condition cond, Register dst,
                                         Register lhs, Register rhs) {
  MacroAssembler::CompareI(dst, lhs, Operand(rhs), cond);
}

void LiftoffAssembler::emit_i64_eqz(Register dst, LiftoffRegister src) {
  Register tmp = GetUnusedRegister(kGpReg, LiftoffRegList{src, dst}).gp();
  Sltu(tmp, src.low_gp(), 1);
  Sltu(dst, src.high_gp(), 1);
  and_(dst, dst, tmp);
}

namespace liftoff {
inline Condition cond_make_unsigned(Condition cond) {
  switch (cond) {
    case kLessThan:
      return kUnsignedLessThan;
    case kLessThanEqual:
      return kUnsignedLessThanEqual;
    case kGreaterThan:
      return kUnsignedGreaterThan;
    case kGreaterThanEqual:
      return kUnsignedGreaterThanEqual;
    default:
      return cond;
  }
}
}  // namespace liftoff

void LiftoffAssembler::emit_i64_set_cond(Condition cond, Register dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  ASM_CODE_COMMENT(this);
  Label low, cont;

  // For signed i64 comparisons, we still need to use unsigned comparison for
  // the low word (the only bit carrying signedness information is the MSB in
  // the high word).
  Condition unsigned_cond = liftoff::cond_make_unsigned(cond);

  Register tmp = dst;
  if (liftoff::IsRegInRegPair(lhs, dst) || liftoff::IsRegInRegPair(rhs, dst)) {
    tmp = GetUnusedRegister(kGpReg, LiftoffRegList{dst, lhs, rhs}).gp();
  }

  // Write 1 initially in tmp register.
  MacroAssembler::li(tmp, 1);

  // If high words are equal, then compare low words, else compare high.
  Branch(&low, eq, lhs.high_gp(), Operand(rhs.high_gp()));

  Branch(&cont, cond, lhs.high_gp(), Operand(rhs.high_gp()));
  mv(tmp, zero_reg);
  Branch(&cont);

  bind(&low);
  if (unsigned_cond == cond) {
    Branch(&cont, cond, lhs.low_gp(), Operand(rhs.low_gp()));
    mv(tmp, zero_reg);
  } else {
    Label lt_zero;
    Branch(&lt_zero, lt, lhs.high_gp(), Operand(zero_reg));
    Branch(&cont, unsigned_cond, lhs.low_gp(), Operand(rhs.low_gp()));
    mv(tmp, zero_reg);
    Branch(&cont);
    bind(&lt_zero);
    Branch(&cont, unsigned_cond, rhs.low_gp(), Operand(lhs.low_gp()));
    mv(tmp, zero_reg);
    Branch(&cont);
  }
  bind(&cont);
  // Move result to dst register if needed.
  MacroAssembler::Move(dst, tmp);
}

void LiftoffAssembler::IncrementSmi(LiftoffRegister dst, int offset) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  SmiUntag(scratch, MemOperand(dst.gp(), offset));
  AddWord(scratch, scratch, Operand(1));
  SmiTag(scratch);
  Sw(scratch, MemOperand(dst.gp(), offset));
}

void LiftoffAssembler::LoadTransform(LiftoffRegister dst, Register src_addr,
                                     Register offset_reg, uintptr_t offset_imm,
                                     LoadType type,
                                     LoadTransformationKind transform,
                                     uint32_t* protected_load_pc) {
  UseScratchRegisterScope t
```