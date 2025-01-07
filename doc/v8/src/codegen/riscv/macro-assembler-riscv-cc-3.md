Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/riscv/macro-assembler-riscv.cc`. The request also includes several constraints:

1. **List Functionality:** Identify the operations performed by the code.
2. **Torque Check:** Determine if the file would be a Torque file if its extension were `.tq`.
3. **JavaScript Relation:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Logic Inference:** For code with logical steps, present a hypothetical input and output.
5. **Common Errors:**  Point out potential programming errors this code might help avoid.
6. **Part Number:** Acknowledge that this is part 4 of 9.
7. **Summarize Functionality:**  Provide a concise overview of the code's purpose.

Let's break down the code section by section:

* **`ShlPair` (Shift Left Pair):**  Deals with shifting a 64-bit value (represented by two 32-bit registers) to the left by a given amount. It handles shifts less than, equal to, and greater than 32 bits.
* **`ShrPair` (Shift Right Pair - Logical):**  Deals with shifting a 64-bit value to the right logically. It has two versions: one where the shift amount is in a register and one where it's an immediate value. It handles shifts less than and greater than 32 bits.
* **`SarPair` (Shift Right Pair - Arithmetic):**  Deals with shifting a 64-bit value to the right arithmetically (preserving the sign bit). Similar to `ShrPair`, it has versions with register and immediate shift amounts.
* **`ExtractBits`:** Extracts a sequence of bits from a register. It handles both RISCV64 and RISCV32 architectures.
* **`InsertBits`:** Inserts bits from one register into another at a specified position.
* **Floating-Point Operations:**  A series of functions for basic floating-point operations like negation (`Neg_s`, `Neg_d`), conversions (`Cvt_d_uw`, `Cvt_d_w`, etc.), rounding (`Trunc_uw_d`, `Round_w_s`, `Ceil_w_d`, `Floor_w_s`), and fused multiply-add/subtract (`Madd_s`, `Msub_d`).
* **Floating-Point Comparisons:**  Functions to compare floating-point numbers (`CompareF32`, `CompareF64`, `CompareIsNotNanF32`, `CompareIsNanF64`).
* **Branching:** Conditional branching based on register values (`BranchTrueShortF`, `BranchFalseF`).
* **`InsertHighWordF64`:** Inserts the high 32 bits of a 64-bit integer into a double-precision floating-point register.

**Plan:**

1. Describe the functionality of each function group.
2. Address the Torque question (unlikely as it's assembly manipulation).
3. Provide JavaScript examples for relevant operations (shifts, rounding).
4. Create hypothetical input/output for bit manipulation and pair shifts.
5. Illustrate common errors related to bit manipulation and shifts.
6. Acknowledge the part number.
7. Summarize the overall purpose of the code.
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的V8源代码的一部分，它提供了一系列用于生成RISC-V汇编指令的宏。 这部分代码主要集中在以下功能：

1. **64位值的移位操作 (Pair Shifts):**
    *   **`ShlPair` (Shift Left Pair):** 将由两个32位寄存器 (`src_low`, `src_high`) 表示的64位值向左移动指定的位数 (`shift`)，结果存储在两个目标寄存器 (`dst_low`, `dst_high`) 中。
    *   **`ShrPair` (Shift Right Pair):** 将由两个32位寄存器表示的64位值向右移动指定的位数 (`shift`)，可以是逻辑右移，结果存储在目标寄存器中。它有两个重载版本，一个接受寄存器作为移位量，另一个接受立即数。
    *   **`SarPair` (Shift Right Pair Arithmetic):** 将由两个32位寄存器表示的64位值进行算术右移，保持符号位，结果存储在目标寄存器中。它也有两个重载版本。

2. **位操作:**
    *   **`ExtractBits`:** 从寄存器 (`rs`) 中提取指定位置 (`pos`) 和大小 (`size`) 的位，可以选择是否进行符号扩展，结果存储在目标寄存器 (`rt`) 中。
    *   **`InsertBits`:** 将源寄存器 (`source`) 中的低 `size` 位插入到目标寄存器 (`dest`) 的指定位置 (`pos`)。

3. **浮点运算:**
    *   **`Neg_s` / `Neg_d`:**  对单精度/双精度浮点数取反。
    *   **`Cvt_d_uw` / `Cvt_d_w` / `Cvt_d_ul` / `Cvt_s_uw` / `Cvt_s_w` / `Cvt_s_ul`:** 将无符号/有符号的 32 位或 64 位整数转换为双精度或单精度浮点数。
    *   **`RoundFloatingPointToInteger` (模板函数):**  提供将浮点数四舍五入到整数的通用逻辑，并处理 NaN 和溢出的情况。
    *   **`Clear_if_nan_d` / `Clear_if_nan_s`:** 如果浮点数是 NaN，则将目标寄存器设置为零。
    *   **`Trunc_uw_d` / `Trunc_w_d` / `Trunc_uw_s` / `Trunc_w_s` / `Trunc_ul_d` / `Trunc_l_d` / `Trunc_ul_s` / `Trunc_l_s`:** 将双精度或单精度浮点数截断为无符号/有符号的 32 位或 64 位整数。
    *   **`Round_w_s` / `Round_w_d`:** 将单精度/双精度浮点数四舍五入到最接近的整数。
    *   **`Ceil_w_s` / `Ceil_w_d`:** 将单精度/双精度浮点数向上取整到最接近的整数。
    *   **`Floor_w_s` / `Floor_w_d`:** 将单精度/双精度浮点数向下取整到最接近的整数。
    *   **`RoundHelper` (模板函数):**  提供更精确的浮点数舍入行为，符合 JavaScript 的规范，处理 NaN、无穷大和零的情况。也有向量化的版本。
    *   **`Ceil_f` / `Ceil_d` / `Floor_f` / `Floor_d` / `Trunc_d` / `Trunc_f` / `Round_f` / `Round_d` (向量化版本):**  对向量寄存器中的浮点数进行相应的舍入操作。
    *   **`Floor_d_d` / `Ceil_d_d` / `Trunc_d_d` / `Round_d_d` / `Floor_s_s` / `Ceil_s_s` / `Trunc_s_s` / `Round_s_s`:**  根据指定的舍入模式对浮点数进行舍入操作。
    *   **`Madd_s` / `Madd_d` / `Msub_s` / `Msub_d`:** 执行单精度/双精度浮点数的 fused multiply-add 和 fused multiply-subtract 操作。
    *   **`CompareF32` / `CompareF64`:**  比较单精度/双精度浮点数，并将比较结果（0 或 1）存储到通用寄存器中。
    *   **`CompareIsNotNanF32` / `CompareIsNotNanF64`:**  检查两个单精度/双精度浮点数是否都不是 NaN。
    *   **`CompareIsNanF32` / `CompareIsNanF64`:**  检查两个单精度/双精度浮点数中是否至少有一个是 NaN。

4. **条件分支:**
    *   **`BranchTrueShortF` / `BranchFalseShortF`:**  根据寄存器的值是否为真（非零）或假（零）进行短跳转。
    *   **`BranchTrueF` / `BranchFalseF`:**  根据寄存器的值进行条件跳转，处理长跳转的情况。

5. **浮点数高字的插入:**
    *   **`InsertHighWordF64`:** 将通用寄存器 (`src_high`) 中的 32 位值插入到双精度浮点寄存器 (`dst`) 的高 32 位。

如果 `v8/src/codegen/riscv/macro-assembler-riscv.cc` 以 `.tq` 结尾，那它将是一个 **V8 Torque 源代码**。Torque 是一种用于编写 V8 内部函数的领域特定语言，它可以生成高效的 C++ 代码。

是的，这里面的很多功能都与 JavaScript 的功能有关系，尤其是浮点数和位运算。

**JavaScript 示例：**

```javascript
// 模拟 ShlPair (左移)
let low = 0xFFFFFFFF;
let high = 0x00000001;
let shift = 4;

// 在 JavaScript 中，我们通常不需要像汇编那样处理高低位
let combined = (BigInt(high) << 32n) | BigInt(low);
let shifted = combined << BigInt(shift);

console.log(shifted); // 输出结果会对应汇编 ShlPair 的计算结果

// 模拟 ShrPair (逻辑右移)
let combined_r = (BigInt(high) << 32n) | BigInt(low);
let shift_r = 4;
let shifted_r = combined_r >> BigInt(shift_r);
console.log(shifted_r);

// 模拟 SarPair (算术右移)
let combined_sar = (BigInt(high) << 32n) | BigInt(low);
let shift_sar = 4;
// JavaScript 的 >> 运算符执行算术右移
let shifted_sar = combined_sar >> BigInt(shift_sar);
console.log(shifted_sar);

// 模拟 ExtractBits
function extractBits(value, position, size) {
  return (value >> position) & ((1 << size) - 1);
}
let val = 0b11010110;
let pos = 2;
let size = 3;
console.log(extractBits(val, pos, size).toString(2)); // 输出 011

// 模拟 InsertBits
function insertBits(dest, source, position, size) {
  const mask = ((1 << size) - 1) << position;
  const clearedDest = dest & ~mask;
  const shiftedSource = (source & ((1 << size) - 1)) << position;
  return clearedDest | shiftedSource;
}
let destination = 0b11110000;
let source_insert = 0b101;
let position_insert = 2;
let size_insert = 3;
console.log(insertBits(destination, source_insert, position_insert, size_insert).toString(2)); // 输出 11110100

// 浮点数操作
let floatValue = 3.14;
console.log(Math.floor(floatValue)); // 模拟 Floor_w
console.log(Math.ceil(floatValue));  // 模拟 Ceil_w
console.log(Math.trunc(floatValue)); // 模拟 Trunc_w
console.log(Math.round(floatValue)); // 模拟 Round_w

let nanValue = NaN;
console.log(isNaN(nanValue)); // 对应 CompareIsNan
```

**代码逻辑推理示例：**

**假设输入 `ShlPair`：**

*   `dst_low`: 寄存器 `a0`
*   `dst_high`: 寄存器 `a1`
*   `src_low`: 寄存器 `a2`, 值为 `0xFFFFFFFF`
*   `src_high`: 寄存器 `a3`, 值为 `0x00000001`
*   `shift`: 整数 `4`
*   `scratch1`: 寄存器 `t0`
*   `scratch2`: 寄存器 `t1`

**输出：**

*   寄存器 `a0` 的值变为 `0xFFFFFFF0`
*   寄存器 `a1` 的值变为 `0x0000001F`

**推理：**

1. `shift` (4) 小于 32，进入 `else` 分支。
2. `slli(dst_high, src_high, shift)`: `a1` (dst_high) 的值变为 `0x00000010` (0x00000001 << 4)。
3. `slli(dst_low, src_low, shift)`: `a0` (dst_low) 的值变为 `0xFFFFFFF0` (0xFFFFFFFF << 4)。
4. `srli(scratch1, src_low, 32 - shift)`: `t0` (scratch1) 的值变为 `0x0000000F` (0xFFFFFFFF >> 28)。
5. `Or(dst_high, dst_high, scratch1)`: `a1` (dst_high) 的值变为 `0x0000001F` (0x00000010 | 0x0000000F)。

**用户常见的编程错误示例：**

*   **位移操作溢出：**  在进行位移操作时，没有考虑到数据类型的宽度，导致移出的位丢失，或者符号位被错误扩展。例如，在 C++ 或 JavaScript 中对小于 64 位的整数进行大于等于其位数的左移操作，可能会导致意想不到的结果。这段汇编代码通过区分高低位寄存器，有助于处理 64 位值的移位，从而降低这种错误的发生概率。
*   **错误的假设移位量：**  没有正确处理移位量为 0 或大于等于数据类型宽度的情况。例如，假设移位量总是小于 32，而实际情况可能不是。这段代码中对 `shift` 值的判断和处理 (例如 `shift &= 0x3F;`) 有助于避免这类错误。
*   **浮点数比较的精度问题：** 直接使用 `==` 比较浮点数可能会因为精度问题导致错误的结果。这段代码提供的浮点数比较函数，如 `CompareIsNotNanF32`，可以帮助开发者处理 NaN 的情况，这在浮点数编程中是一个常见的陷阱。
*   **整数与浮点数类型转换错误：**  在整数和浮点数之间进行类型转换时，如果没有明确地进行转换或者没有考虑到舍入模式，可能会导致精度丢失或得到错误的结果。这段代码提供的各种浮点数转换和舍入函数，可以帮助开发者更精确地控制类型转换的过程。

这是第 4 部分，共 9 部分。

**功能归纳：**

这部分 `macro-assembler-riscv.cc` 代码为 V8 引擎在 RISC-V 架构上提供了底层的汇编指令生成能力，专注于 64 位整数的移位操作、基本的位操作以及各种浮点数运算和比较操作。它提供了方便的宏来执行这些操作，并帮助开发者避免一些常见的编程错误，确保生成的代码能够正确高效地执行 JavaScript 的相关功能。

Prompt: 
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共9部分，请归纳一下它的功能

"""
If the shift amount is < 32, we're done
  // Note: the shift amount is always < 64, so we can just test if the 6th bit
  // is set
  And(scratch1, shift, 32);
  Branch(&done, eq, scratch1, Operand(zero_reg));
  Move(dst_high, dst_low);
  Move(dst_low, zero_reg);

  bind(&done);
}

void MacroAssembler::ShlPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high, int32_t shift,
                             Register scratch1, Register scratch2) {
  DCHECK_GE(63, shift);
  DCHECK_NE(dst_low, src_low);
  DCHECK_NE(dst_high, src_low);
  shift &= 0x3F;
  if (shift == 0) {
    Move(dst_high, src_high);
    Move(dst_low, src_low);
  } else if (shift == 32) {
    Move(dst_high, src_low);
    li(dst_low, Operand(0));
  } else if (shift > 32) {
    shift &= 0x1F;
    slli(dst_high, src_low, shift);
    li(dst_low, Operand(0));
  } else {
    slli(dst_high, src_high, shift);
    slli(dst_low, src_low, shift);
    srli(scratch1, src_low, 32 - shift);
    Or(dst_high, dst_high, scratch1);
  }
}

void MacroAssembler::ShrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift, Register scratch1,
                             Register scratch2) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Label done;
  UseScratchRegisterScope temps(this);
  Register scratch3 = no_reg;
  if (dst_high == src_high) {
    scratch3 = temps.Acquire();
    mv(scratch3, src_high);
  }
  And(scratch1, shift, 0x1F);
  // HIGH32 >> shamt
  srl(dst_high, src_high, scratch1);
  // LOW32 >> shamt
  srl(dst_low, src_low, scratch1);

  // If the shift amount is 0, we're done
  Branch(&done, eq, shift, Operand(zero_reg));

  // HIGH32 << (32 - shamt)
  li(scratch2, 32);
  Sub32(scratch2, scratch2, scratch1);
  if (dst_high == src_high) {
    sll(scratch1, scratch3, scratch2);
  } else {
    sll(scratch1, src_high, scratch2);
  }

  // (HIGH32 << (32 - shamt)) | (LOW32 >> shamt)
  Or(dst_low, dst_low, scratch1);

  // If the shift amount is < 32, we're done
  // Note: the shift amount is always < 64, so we can just test if the 6th bit
  // is set
  And(scratch1, shift, 32);
  Branch(&done, eq, scratch1, Operand(zero_reg));
  Move(dst_low, dst_high);
  Move(dst_high, zero_reg);

  bind(&done);
}

void MacroAssembler::ShrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high, int32_t shift,
                             Register scratch1, Register scratch2) {
  DCHECK_GE(63, shift);
  DCHECK_NE(dst_low, src_high);
  DCHECK_NE(dst_high, src_high);
  shift &= 0x3F;
  if (shift == 32) {
    mv(dst_low, src_high);
    li(dst_high, Operand(0));
  } else if (shift > 32) {
    shift &= 0x1F;
    srli(dst_low, src_high, shift);
    li(dst_high, Operand(0));
  } else if (shift == 0) {
    Move(dst_low, src_low);
    Move(dst_high, src_high);
  } else {
    srli(dst_low, src_low, shift);
    srli(dst_high, src_high, shift);
    slli(scratch1, src_high, 32 - shift);
    Or(dst_low, dst_low, scratch1);
  }
}

void MacroAssembler::SarPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift, Register scratch1,
                             Register scratch2) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Label done;
  UseScratchRegisterScope temps(this);
  Register scratch3 = no_reg;
  if (dst_high == src_high) {
    scratch3 = temps.Acquire();
    mv(scratch3, src_high);
  }
  And(scratch1, shift, 0x1F);
  // HIGH32 >> shamt (arithmetic)
  sra(dst_high, src_high, scratch1);
  // LOW32 >> shamt (logical)
  srl(dst_low, src_low, scratch1);

  // If the shift amount is 0, we're done
  Branch(&done, eq, shift, Operand(zero_reg));

  // HIGH32 << (32 - shamt)
  li(scratch2, 32);
  Sub32(scratch2, scratch2, scratch1);
  if (dst_high == src_high) {
    sll(scratch1, scratch3, scratch2);
  } else {
    sll(scratch1, src_high, scratch2);
  }
  // (HIGH32 << (32 - shamt)) | (LOW32 >> shamt)
  Or(dst_low, dst_low, scratch1);

  // If the shift amount is < 32, we're done
  // Note: the shift amount is always < 64, so we can just test if the 6th bit
  // is set
  And(scratch1, shift, 32);
  Branch(&done, eq, scratch1, Operand(zero_reg));
  Move(dst_low, dst_high);
  Sra32(dst_high, dst_high, 31);

  bind(&done);
}

void MacroAssembler::SarPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high, int32_t shift,
                             Register scratch1, Register scratch2) {
  DCHECK_GE(63, shift);
  DCHECK_NE(dst_low, src_high);
  DCHECK_NE(dst_high, src_high);
  shift = shift & 0x3F;
  if (shift == 0) {
    mv(dst_low, src_low);
    mv(dst_high, src_high);
  } else if (shift < 32) {
    srli(dst_low, src_low, shift);
    srai(dst_high, src_high, shift);
    slli(scratch1, src_high, 32 - shift);
    Or(dst_low, dst_low, scratch1);
  } else if (shift == 32) {
    srai(dst_high, src_high, 31);
    mv(dst_low, src_high);
  } else {
    srai(dst_high, src_high, 31);
    srai(dst_low, src_high, shift - 32);
  }
}
#endif

void MacroAssembler::ExtractBits(Register rt, Register rs, uint16_t pos,
                                 uint16_t size, bool sign_extend) {
#if V8_TARGET_ARCH_RISCV64
  DCHECK(pos < 64 && 0 < size && size <= 64 && 0 < pos + size &&
         pos + size <= 64);
  slli(rt, rs, 64 - (pos + size));
  if (sign_extend) {
    srai(rt, rt, 64 - size);
  } else {
    srli(rt, rt, 64 - size);
  }
#elif V8_TARGET_ARCH_RISCV32
  DCHECK_LT(pos, 32);
  DCHECK_GT(size, 0);
  DCHECK_LE(size, 32);
  DCHECK_GT(pos + size, 0);
  DCHECK_LE(pos + size, 32);
  slli(rt, rs, 32 - (pos + size));
  if (sign_extend) {
    srai(rt, rt, 32 - size);
  } else {
    srli(rt, rt, 32 - size);
  }
#endif
}

void MacroAssembler::InsertBits(Register dest, Register source, Register pos,
                                int size) {
#if V8_TARGET_ARCH_RISCV64
  DCHECK_LT(size, 64);
#elif V8_TARGET_ARCH_RISCV32
  DCHECK_LT(size, 32);
#endif
  UseScratchRegisterScope temps(this);
  Register mask = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register source_ = temps.Acquire();
  // Create a mask of the length=size.
  li(mask, 1);
  slli(mask, mask, size);
  addi(mask, mask, -1);
  and_(source_, mask, source);
  sll(source_, source_, pos);
  // Make a mask containing 0's. 0's start at "pos" with length=size.
  sll(mask, mask, pos);
  not_(mask, mask);
  // cut area for insertion of source.
  and_(dest, mask, dest);
  // insert source
  or_(dest, dest, source_);
}

void MacroAssembler::Neg_s(FPURegister fd, FPURegister fs) { fneg_s(fd, fs); }

void MacroAssembler::Neg_d(FPURegister fd, FPURegister fs) { fneg_d(fd, fs); }

void MacroAssembler::Cvt_d_uw(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_d_wu(fd, rs);
}

void MacroAssembler::Cvt_d_w(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_d_w(fd, rs);
}
#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Cvt_d_ul(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_d_lu(fd, rs);
}
#endif
void MacroAssembler::Cvt_s_uw(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_s_wu(fd, rs);
}

void MacroAssembler::Cvt_s_w(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_s_w(fd, rs);
}
#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Cvt_s_ul(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_s_lu(fd, rs);
}
#endif
template <typename CvtFunc>
void MacroAssembler::RoundFloatingPointToInteger(Register rd, FPURegister fs,
                                                 Register result,
                                                 CvtFunc fcvt_generator) {
  // Save csr_fflags to scratch & clear exception flags
  if (result.is_valid()) {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();

    int exception_flags = kInvalidOperation;
    csrrci(scratch, csr_fflags, exception_flags);

    // actual conversion instruction
    fcvt_generator(this, rd, fs);

    // check kInvalidOperation flag (out-of-range, NaN)
    // set result to 1 if normal, otherwise set result to 0 for abnormal
    frflags(result);
    andi(result, result, exception_flags);
    seqz(result, result);  // result <-- 1 (normal), result <-- 0 (abnormal)

    // restore csr_fflags
    csrw(csr_fflags, scratch);
  } else {
    // actual conversion instruction
    fcvt_generator(this, rd, fs);
  }
}

void MacroAssembler::Clear_if_nan_d(Register rd, FPURegister fs) {
  Label no_nan;
  DCHECK_NE(kScratchReg, rd);
  feq_d(kScratchReg, fs, fs);
  bnez(kScratchReg, &no_nan);
  Move(rd, zero_reg);
  bind(&no_nan);
}

void MacroAssembler::Clear_if_nan_s(Register rd, FPURegister fs) {
  Label no_nan;
  DCHECK_NE(kScratchReg, rd);
  feq_s(kScratchReg, fs, fs);
  bnez(kScratchReg, &no_nan);
  Move(rd, zero_reg);
  bind(&no_nan);
}

void MacroAssembler::Trunc_uw_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_wu_d(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_w_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_d(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_uw_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_wu_s(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_w_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_s(dst, src, RTZ);
      });
}
#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Trunc_ul_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_lu_d(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_l_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_l_d(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_ul_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_lu_s(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_l_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_l_s(dst, src, RTZ);
      });
}
#endif
void MacroAssembler::Round_w_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_s(dst, src, RNE);
      });
}

void MacroAssembler::Round_w_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_d(dst, src, RNE);
      });
}

void MacroAssembler::Ceil_w_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_s(dst, src, RUP);
      });
}

void MacroAssembler::Ceil_w_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_d(dst, src, RUP);
      });
}

void MacroAssembler::Floor_w_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_s(dst, src, RDN);
      });
}

void MacroAssembler::Floor_w_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_d(dst, src, RDN);
      });
}

// According to JS ECMA specification, for floating-point round operations, if
// the input is NaN, +/-infinity, or +/-0, the same input is returned as the
// rounded result; this differs from behavior of RISCV fcvt instructions (which
// round out-of-range values to the nearest max or min value), therefore special
// handling is needed by NaN, +/-Infinity, +/-0
#if V8_TARGET_ARCH_RISCV64
template <typename F>
void MacroAssembler::RoundHelper(FPURegister dst, FPURegister src,
                                 FPURegister fpu_scratch, FPURoundingMode frm) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch2 = temps.Acquire();

  DCHECK((std::is_same<float, F>::value) || (std::is_same<double, F>::value));
  // Need at least two FPRs, so check against dst == src == fpu_scratch
  DCHECK(!(dst == src && dst == fpu_scratch));

  const int kFloatMantissaBits =
      sizeof(F) == 4 ? kFloat32MantissaBits : kFloat64MantissaBits;
  const int kFloatExponentBits =
      sizeof(F) == 4 ? kFloat32ExponentBits : kFloat64ExponentBits;
  const int kFloatExponentBias =
      sizeof(F) == 4 ? kFloat32ExponentBias : kFloat64ExponentBias;
  Label done;

  {
    UseScratchRegisterScope temps2(this);
    Register scratch = temps2.Acquire();
    // extract exponent value of the source floating-point to scratch
    if (std::is_same<F, double>::value) {
      fmv_x_d(scratch, src);
    } else {
      fmv_x_w(scratch, src);
    }
    ExtractBits(scratch2, scratch, kFloatMantissaBits, kFloatExponentBits);
  }

  // if src is NaN/+-Infinity/+-Zero or if the exponent is larger than # of bits
  // in mantissa, the result is the same as src, so move src to dest  (to avoid
  // generating another branch)
  if (dst != src) {
    if (std::is_same<F, double>::value) {
      fmv_d(dst, src);
    } else {
      fmv_s(dst, src);
    }
  }
  {
    Label not_NaN;
    UseScratchRegisterScope temps2(this);
    Register scratch = temps2.Acquire();
    // According to the wasm spec
    // (https://webassembly.github.io/spec/core/exec/numerics.html#aux-nans)
    // if input is canonical NaN, then output is canonical NaN, and if input is
    // any other NaN, then output is any NaN with most significant bit of
    // payload is 1. In RISC-V, feq_d will set scratch to 0 if src is a NaN. If
    // src is not a NaN, branch to the label and do nothing, but if it is,
    // fmin_d will set dst to the canonical NaN.
    if (std::is_same<F, double>::value) {
      feq_d(scratch, src, src);
      bnez(scratch, &not_NaN);
      fmin_d(dst, src, src);
    } else {
      feq_s(scratch, src, src);
      bnez(scratch, &not_NaN);
      fmin_s(dst, src, src);
    }
    bind(&not_NaN);
  }

  // If real exponent (i.e., scratch2 - kFloatExponentBias) is greater than
  // kFloat32MantissaBits, it means the floating-point value has no fractional
  // part, thus the input is already rounded, jump to done. Note that, NaN and
  // Infinity in floating-point representation sets maximal exponent value, so
  // they also satisfy (scratch2 - kFloatExponentBias >= kFloatMantissaBits),
  // and JS round semantics specify that rounding of NaN (Infinity) returns NaN
  // (Infinity), so NaN and Infinity are considered rounded value too.
  Branch(&done, greater_equal, scratch2,
         Operand(kFloatExponentBias + kFloatMantissaBits));

  // Actual rounding is needed along this path

  // old_src holds the original input, needed for the case of src == dst
  FPURegister old_src = src;
  if (src == dst) {
    DCHECK(fpu_scratch != dst);
    Move(fpu_scratch, src);
    old_src = fpu_scratch;
  }

  // Since only input whose real exponent value is less than kMantissaBits
  // (i.e., 23 or 52-bits) falls into this path, the value range of the input
  // falls into that of 23- or 53-bit integers. So we round the input to integer
  // values, then convert them back to floating-point.
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    if (std::is_same<F, double>::value) {
      fcvt_l_d(scratch, src, frm);
      fcvt_d_l(dst, scratch, frm);
    } else {
      fcvt_w_s(scratch, src, frm);
      fcvt_s_w(dst, scratch, frm);
    }
  }
  // A special handling is needed if the input is a very small positive/negative
  // number that rounds to zero. JS semantics requires that the rounded result
  // retains the sign of the input, so a very small positive (negative)
  // floating-point number should be rounded to positive (negative) 0.
  // Therefore, we use sign-bit injection to produce +/-0 correctly. Instead of
  // testing for zero w/ a branch, we just insert sign-bit for everyone on this
  // path (this is where old_src is needed)
  if (std::is_same<F, double>::value) {
    fsgnj_d(dst, dst, old_src);
  } else {
    fsgnj_s(dst, dst, old_src);
  }

  bind(&done);
}
#elif V8_TARGET_ARCH_RISCV32
// According to JS ECMA specification, for floating-point round operations, if
// the input is NaN, +/-infinity, or +/-0, the same input is returned as the
// rounded result; this differs from behavior of RISCV fcvt instructions (which
// round out-of-range values to the nearest max or min value), therefore special
// handling is needed by NaN, +/-Infinity, +/-0
void MacroAssembler::RoundFloat(FPURegister dst, FPURegister src,
                                FPURegister fpu_scratch, FPURoundingMode frm) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch2 = temps.Acquire();

  // Need at least two FPRs, so check against dst == src == fpu_scratch
  DCHECK(!(dst == src && dst == fpu_scratch));

  const int kFloatMantissaBits = kFloat32MantissaBits;
  const int kFloatExponentBits = kFloat32ExponentBits;
  const int kFloatExponentBias = kFloat32ExponentBias;
  Label done;

  {
    UseScratchRegisterScope temps2(this);
    Register scratch = temps2.Acquire();
    // extract exponent value of the source floating-point to scratch
    fmv_x_w(scratch, src);
    ExtractBits(scratch2, scratch, kFloatMantissaBits, kFloatExponentBits);
  }

  // if src is NaN/+-Infinity/+-Zero or if the exponent is larger than # of bits
  // in mantissa, the result is the same as src, so move src to dest  (to avoid
  // generating another branch)
  if (dst != src) {
    fmv_s(dst, src);
  }
  {
    Label not_NaN;
    UseScratchRegisterScope temps2(this);
    Register scratch = temps2.Acquire();
    // According to the wasm spec
    // (https://webassembly.github.io/spec/core/exec/numerics.html#aux-nans)
    // if input is canonical NaN, then output is canonical NaN, and if input is
    // any other NaN, then output is any NaN with most significant bit of
    // payload is 1. In RISC-V, feq_d will set scratch to 0 if src is a NaN. If
    // src is not a NaN, branch to the label and do nothing, but if it is,
    // fmin_d will set dst to the canonical NaN.
    feq_s(scratch, src, src);
    bnez(scratch, &not_NaN);
    fmin_s(dst, src, src);
    bind(&not_NaN);
  }

  // If real exponent (i.e., scratch2 - kFloatExponentBias) is greater than
  // kFloat32MantissaBits, it means the floating-point value has no fractional
  // part, thus the input is already rounded, jump to done. Note that, NaN and
  // Infinity in floating-point representation sets maximal exponent value, so
  // they also satisfy (scratch2 - kFloatExponentBias >= kFloatMantissaBits),
  // and JS round semantics specify that rounding of NaN (Infinity) returns NaN
  // (Infinity), so NaN and Infinity are considered rounded value too.
  Branch(&done, greater_equal, scratch2,
         Operand(kFloatExponentBias + kFloatMantissaBits));

  // Actual rounding is needed along this path

  // old_src holds the original input, needed for the case of src == dst
  FPURegister old_src = src;
  if (src == dst) {
    DCHECK(fpu_scratch != dst);
    Move(fpu_scratch, src);
    old_src = fpu_scratch;
  }

  // Since only input whose real exponent value is less than kMantissaBits
  // (i.e., 23 or 52-bits) falls into this path, the value range of the input
  // falls into that of 23- or 53-bit integers. So we round the input to integer
  // values, then convert them back to floating-point.
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    fcvt_w_s(scratch, src, frm);
    fcvt_s_w(dst, scratch, frm);
  }
  // A special handling is needed if the input is a very small positive/negative
  // number that rounds to zero. JS semantics requires that the rounded result
  // retains the sign of the input, so a very small positive (negative)
  // floating-point number should be rounded to positive (negative) 0.
  // Therefore, we use sign-bit injection to produce +/-0 correctly. Instead of
  // testing for zero w/ a branch, we just insert sign-bit for everyone on this
  // path (this is where old_src is needed)
  fsgnj_s(dst, dst, old_src);

  bind(&done);
}
#endif  // V8_TARGET_ARCH_RISCV32
// According to JS ECMA specification, for floating-point round operations, if
// the input is NaN, +/-infinity, or +/-0, the same input is returned as the
// rounded result; this differs from behavior of RISCV fcvt instructions (which
// round out-of-range values to the nearest max or min value), therefore special
// handling is needed by NaN, +/-Infinity, +/-0
template <typename F>
void MacroAssembler::RoundHelper(VRegister dst, VRegister src, Register scratch,
                                 VRegister v_scratch, FPURoundingMode frm,
                                 bool keep_nan_same) {
  VU.set(scratch, std::is_same<F, float>::value ? E32 : E64, m1);
  // if src is NaN/+-Infinity/+-Zero or if the exponent is larger than # of bits
  // in mantissa, the result is the same as src, so move src to dest  (to avoid
  // generating another branch)

  // If real exponent (i.e., scratch2 - kFloatExponentBias) is greater than
  // kFloat32MantissaBits, it means the floating-point value has no fractional
  // part, thus the input is already rounded, jump to done. Note that, NaN and
  // Infinity in floating-point representation sets maximal exponent value, so
  // they also satisfy (scratch2 - kFloatExponentBias >= kFloatMantissaBits),
  // and JS round semantics specify that rounding of NaN (Infinity) returns NaN
  // (Infinity), so NaN and Infinity are considered rounded value too.
  const int kFloatMantissaBits =
      sizeof(F) == 4 ? kFloat32MantissaBits : kFloat64MantissaBits;
  const int kFloatExponentBits =
      sizeof(F) == 4 ? kFloat32ExponentBits : kFloat64ExponentBits;
  const int kFloatExponentBias =
      sizeof(F) == 4 ? kFloat32ExponentBias : kFloat64ExponentBias;

  // slli(rt, rs, 64 - (pos + size));
  // if (sign_extend) {
  //   srai(rt, rt, 64 - size);
  // } else {
  //   srli(rt, rt, 64 - size);
  // }
  vmv_vx(v_scratch, zero_reg);
  li(scratch, 64 - kFloatMantissaBits - kFloatExponentBits);
  vsll_vx(v_scratch, src, scratch);
  li(scratch, 64 - kFloatExponentBits);
  vsrl_vx(v_scratch, v_scratch, scratch);
  li(scratch, kFloatExponentBias + kFloatMantissaBits);
  vmslt_vx(v0, v_scratch, scratch);
  VU.set(frm);
  vmv_vv(dst, src);
  if (dst == src) {
    vmv_vv(v_scratch, src);
  }
  vfcvt_x_f_v(dst, src, MaskType::Mask);
  vfcvt_f_x_v(dst, dst, MaskType::Mask);

  // A special handling is needed if the input is a very small positive/negative
  // number that rounds to zero. JS semantics requires that the rounded result
  // retains the sign of the input, so a very small positive (negative)
  // floating-point number should be rounded to positive (negative) 0.
  if (dst == src) {
    vfsngj_vv(dst, dst, v_scratch);
  } else {
    vfsngj_vv(dst, dst, src);
  }
  if (!keep_nan_same) {
    vmfeq_vv(v0, src, src);
    vnot_vv(v0, v0);
    if (std::is_same<F, float>::value) {
      fmv_w_x(kScratchDoubleReg, zero_reg);
    } else {
#ifdef V8_TARGET_ARCH_RISCV64
      fmv_d_x(kScratchDoubleReg, zero_reg);
#elif V8_TARGET_ARCH_RISCV32
      fcvt_d_w(kScratchDoubleReg, zero_reg);
#endif
    }
    vfadd_vf(dst, src, kScratchDoubleReg, MaskType::Mask);
  }
}

void MacroAssembler::Ceil_f(VRegister vdst, VRegister vsrc, Register scratch,
                            VRegister v_scratch) {
  RoundHelper<float>(vdst, vsrc, scratch, v_scratch, RUP, false);
}

void MacroAssembler::Ceil_d(VRegister vdst, VRegister vsrc, Register scratch,
                            VRegister v_scratch) {
  RoundHelper<double>(vdst, vsrc, scratch, v_scratch, RUP, false);
}

void MacroAssembler::Floor_f(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<float>(vdst, vsrc, scratch, v_scratch, RDN, false);
}

void MacroAssembler::Floor_d(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<double>(vdst, vsrc, scratch, v_scratch, RDN, false);
}

void MacroAssembler::Trunc_d(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<double>(vdst, vsrc, scratch, v_scratch, RTZ, false);
}

void MacroAssembler::Trunc_f(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<float>(vdst, vsrc, scratch, v_scratch, RTZ, false);
}

void MacroAssembler::Round_f(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<float>(vdst, vsrc, scratch, v_scratch, RNE, false);
}

void MacroAssembler::Round_d(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<double>(vdst, vsrc, scratch, v_scratch, RNE, false);
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Floor_d_d(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
  RoundHelper<double>(dst, src, fpu_scratch, RDN);
}

void MacroAssembler::Ceil_d_d(FPURegister dst, FPURegister src,
                              FPURegister fpu_scratch) {
  RoundHelper<double>(dst, src, fpu_scratch, RUP);
}

void MacroAssembler::Trunc_d_d(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
  RoundHelper<double>(dst, src, fpu_scratch, RTZ);
}

void MacroAssembler::Round_d_d(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
  RoundHelper<double>(dst, src, fpu_scratch, RNE);
}
#endif

void MacroAssembler::Floor_s_s(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
#if V8_TARGET_ARCH_RISCV64
  RoundHelper<float>(dst, src, fpu_scratch, RDN);
#elif V8_TARGET_ARCH_RISCV32
  RoundFloat(dst, src, fpu_scratch, RDN);
#endif
}

void MacroAssembler::Ceil_s_s(FPURegister dst, FPURegister src,
                              FPURegister fpu_scratch) {
#if V8_TARGET_ARCH_RISCV64
  RoundHelper<float>(dst, src, fpu_scratch, RUP);
#elif V8_TARGET_ARCH_RISCV32
  RoundFloat(dst, src, fpu_scratch, RUP);
#endif
}

void MacroAssembler::Trunc_s_s(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
#if V8_TARGET_ARCH_RISCV64
  RoundHelper<float>(dst, src, fpu_scratch, RTZ);
#elif V8_TARGET_ARCH_RISCV32
  RoundFloat(dst, src, fpu_scratch, RTZ);
#endif
}

void MacroAssembler::Round_s_s(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
#if V8_TARGET_ARCH_RISCV64
  RoundHelper<float>(dst, src, fpu_scratch, RNE);
#elif V8_TARGET_ARCH_RISCV32
  RoundFloat(dst, src, fpu_scratch, RNE);
#endif
}

void MacroAssembler::Madd_s(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft) {
  fmadd_s(fd, fs, ft, fr);
}

void MacroAssembler::Madd_d(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft) {
  fmadd_d(fd, fs, ft, fr);
}

void MacroAssembler::Msub_s(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft) {
  fmsub_s(fd, fs, ft, fr);
}

void MacroAssembler::Msub_d(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft) {
  fmsub_d(fd, fs, ft, fr);
}

void MacroAssembler::CompareF32(Register rd, FPUCondition cc, FPURegister cmp1,
                                FPURegister cmp2) {
  switch (cc) {
    case EQ:
      feq_s(rd, cmp1, cmp2);
      break;
    case NE:
      feq_s(rd, cmp1, cmp2);
      NegateBool(rd, rd);
      break;
    case LT:
      flt_s(rd, cmp1, cmp2);
      break;
    case GE:
      fle_s(rd, cmp2, cmp1);
      break;
    case LE:
      fle_s(rd, cmp1, cmp2);
      break;
    case GT:
      flt_s(rd, cmp2, cmp1);
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::CompareF64(Register rd, FPUCondition cc, FPURegister cmp1,
                                FPURegister cmp2) {
  switch (cc) {
    case EQ:
      feq_d(rd, cmp1, cmp2);
      break;
    case NE:
      feq_d(rd, cmp1, cmp2);
      NegateBool(rd, rd);
      break;
    case LT:
      flt_d(rd, cmp1, cmp2);
      break;
    case GE:
      fle_d(rd, cmp2, cmp1);
      break;
    case LE:
      fle_d(rd, cmp1, cmp2);
      break;
    case GT:
      flt_d(rd, cmp2, cmp1);
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::CompareIsNotNanF32(Register rd, FPURegister cmp1,
                                        FPURegister cmp2) {
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.Acquire();

  feq_s(rd, cmp1, cmp1);       // rd <- !isNan(cmp1)
  feq_s(scratch, cmp2, cmp2);  // scratch <- !isNaN(cmp2)
  And(rd, rd, scratch);        // rd <- !isNan(cmp1) && !isNan(cmp2)
}

void MacroAssembler::CompareIsNotNanF64(Register rd, FPURegister cmp1,
                                        FPURegister cmp2) {
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.Acquire();

  feq_d(rd, cmp1, cmp1);       // rd <- !isNan(cmp1)
  feq_d(scratch, cmp2, cmp2);  // scratch <- !isNaN(cmp2)
  And(rd, rd, scratch);        // rd <- !isNan(cmp1) && !isNan(cmp2)
}

void MacroAssembler::CompareIsNanF32(Register rd, FPURegister cmp1,
                                     FPURegister cmp2) {
  CompareIsNotNanF32(rd, cmp1, cmp2);  // rd <- !isNan(cmp1) && !isNan(cmp2)
  Xor(rd, rd, 1);                      // rd <- isNan(cmp1) || isNan(cmp2)
}

void MacroAssembler::CompareIsNanF64(Register rd, FPURegister cmp1,
                                     FPURegister cmp2) {
  CompareIsNotNanF64(rd, cmp1, cmp2);  // rd <- !isNan(cmp1) && !isNan(cmp2)
  Xor(rd, rd, 1);                      // rd <- isNan(cmp1) || isNan(cmp2)
}

void MacroAssembler::BranchTrueShortF(Register rs, Label* target) {
  Branch(target, not_equal, rs, Operand(zero_reg));
}

void MacroAssembler::BranchFalseShortF(Register rs, Label* target) {
  Branch(target, equal, rs, Operand(zero_reg));
}

void MacroAssembler::BranchTrueF(Register rs, Label* target) {
  bool long_branch =
      target->is_bound() ? !is_near(target) : is_trampoline_emitted();
  if (long_branch) {
    Label skip;
    BranchFalseShortF(rs, &skip);
    BranchLong(target);
    bind(&skip);
  } else {
    BranchTrueShortF(rs, target);
  }
}

void MacroAssembler::BranchFalseF(Register rs, Label* target) {
  bool long_branch =
      target->is_bound() ? !is_near(target) : is_trampoline_emitted();
  if (long_branch) {
    Label skip;
    BranchTrueShortF(rs, &skip);
    BranchLong(target);
    bind(&skip);
  } else {
    BranchFalseShortF(rs, target);
  }
}

void MacroAssembler::InsertHighWordF64(FPURegister dst, Register src_high) {
#if V8_TARGET_ARCH_RISCV64
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);

  DCHECK(src_high != scratch2 && src_high != scratch);

  fmv_x_d(scratch, dst);
  slli(scratch2, src_high, 32);
  slli(scratch, scratch, 32);
  srli(scratch, scratch, 32);
  or_(scratch, scratch, scratch2);
  fmv_d_x(dst, scratch);
#elif V8_TARGET_ARCH_RISCV32
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Add32(sp, sp,
"""


```