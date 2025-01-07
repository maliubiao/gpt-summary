Response:
The user wants a summary of the functionality of the provided C++ code snippet from the V8 JavaScript engine. The code is part of the Liftoff assembler for the IA32 architecture, focusing on low-level code generation for WebAssembly.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The code defines functions within the `LiftoffAssembler` class that emit specific IA32 assembly instructions. The naming convention (e.g., `emit_i64_shl`, `emit_f32_add`) clearly indicates the operations being implemented.

2. **Categorize Functionality:** Group the functions based on the type of operation they perform. This makes the summary more structured and easier to understand. Categories could include:
    * Integer Arithmetic and Logic (shifts, CLZ, CTZ, POPCNT)
    * Floating-Point Arithmetic (add, sub, mul, div, min, max, copysign, abs, neg, round, sqrt)
    * Type Conversions (integer to float, float to integer, reinterpretations)
    * Bit Manipulation (sign extension)
    * Control Flow (jumps, conditional jumps)
    * Comparisons (integer and floating-point)
    * Selections (conditional assignment)
    * Smi (small integer) handling

3. **Explain Key Concepts:** Briefly explain any non-obvious concepts, like the use of register pairs for 64-bit integers on IA32, or the handling of NaN in floating-point comparisons.

4. **Address Specific Instructions:**
    * **`.tq` extension:** Confirm that the file is *not* a Torque file.
    * **JavaScript relation:**  Explain how this low-level code relates to JavaScript execution (compilation of WebAssembly). Provide a simple JavaScript example that might trigger some of these operations.
    * **Code logic inference:** Choose a simple function (like `emit_i64_shl`) and demonstrate its logic with a hypothetical input and output.
    * **Common programming errors:** Think about errors that could arise when dealing with low-level operations like shifts or type conversions.

5. **Structure the Summary:** Organize the information logically with clear headings and bullet points.

6. **Review and Refine:** Ensure the summary is accurate, concise, and addresses all parts of the user's request.

**Self-Correction/Refinement During Thought Process:**

* Initially, I might have been tempted to go into extreme detail about each assembly instruction. However, the user asked for a summary of *functionality*, not a detailed assembly language tutorial. Focusing on the *purpose* of each function is key.
*  I need to be careful about stating that a function *directly* corresponds to a specific JavaScript operation. The connection is more indirect, through the WebAssembly compilation process.
*  For the "common errors" section, avoid very basic errors (like syntax mistakes). Focus on errors related to the semantics of the operations, especially around integer overflow or loss of precision in floating-point conversions.
*  When providing the input/output example, choose realistic data types and values to illustrate the operation clearly.

By following these steps, I can generate a comprehensive and informative summary that addresses all the user's requirements.
这是V8源代码文件 `v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h` 的第三部分，该文件定义了 `LiftoffAssembler` 类的一些内联成员函数，这些函数负责为 IA-32 架构生成 WebAssembly 的基线代码。

**功能归纳:**

这部分代码主要实现了以下功能：

1. **64位整数的位移操作 (Shift Operations):**
   - `emit_i64_shl`: 生成左移指令。
   - `emit_i64_shli`: 生成立即数左移指令。
   - `emit_i64_sar`: 生成算术右移指令。
   - `emit_i64_sari`: 生成立即数算术右移指令。
   - `emit_i64_shr`: 生成逻辑右移指令。
   - `emit_i64_shri`: 生成立即数逻辑右移指令。

2. **64位整数的位计数操作 (Bit Counting Operations):**
   - `emit_i64_clz`: 生成计算前导零个数的指令。
   - `emit_i64_ctz`: 生成计算末尾零个数的指令。
   - `emit_i64_popcnt`: 生成计算人口计数的指令（需要 CPU 支持 POPCNT 特性）。

3. **Smi 操作:**
   - `IncrementSmi`: 生成递增 Smi (Small Integer) 值的指令。

4. **32位单精度浮点数运算 (Float32 Operations):**
   - `emit_f32_add`: 生成加法指令。
   - `emit_f32_sub`: 生成减法指令。
   - `emit_f32_mul`: 生成乘法指令。
   - `emit_f32_div`: 生成除法指令。
   - `emit_f32_min`: 生成最小值指令。
   - `emit_f32_max`: 生成最大值指令。
   - `emit_f32_copysign`: 生成复制符号位指令。
   - `emit_f32_abs`: 生成绝对值指令。
   - `emit_f32_neg`: 生成取反指令。
   - `emit_f32_ceil`: 生成向上取整指令（需要 SSE4.1 支持）。
   - `emit_f32_floor`: 生成向下取整指令（需要 SSE4.1 支持）。
   - `emit_f32_trunc`: 生成向零取整指令（需要 SSE4.1 支持）。
   - `emit_f32_nearest_int`: 生成四舍五入到最接近的整数指令（需要 SSE4.1 支持）。
   - `emit_f32_sqrt`: 生成平方根指令。

5. **64位双精度浮点数运算 (Float64 Operations):**
   - `emit_f64_add`: 生成加法指令。
   - `emit_f64_sub`: 生成减法指令。
   - `emit_f64_mul`: 生成乘法指令。
   - `emit_f64_div`: 生成除法指令。
   - `emit_f64_min`: 生成最小值指令。
   - `emit_f64_copysign`: 生成复制符号位指令。
   - `emit_f64_max`: 生成最大值指令。
   - `emit_f64_abs`: 生成绝对值指令。
   - `emit_f64_neg`: 生成取反指令。
   - `emit_f64_ceil`: 生成向上取整指令（需要 SSE4.1 支持）。
   - `emit_f64_floor`: 生成向下取整指令（需要 SSE4.1 支持）。
   - `emit_f64_trunc`: 生成向零取整指令（需要 SSE4.1 支持）。
   - `emit_f64_nearest_int`: 生成四舍五入到最接近的整数指令（需要 SSE4.1 支持）。
   - `emit_f64_sqrt`: 生成平方根指令。

6. **浮点数到整数的类型转换 (Float to Integer Conversions):**
   - 提供 `EmitTruncateFloatToInt` 和 `EmitSatTruncateFloatToInt` 模板函数，用于生成将浮点数截断转换为整数的指令，包括饱和转换（超出范围则取最大/最小值）。

7. **通用的类型转换 (Type Conversions):**
   - `emit_type_conversion`: 根据 `WasmOpcode` 枚举值，生成各种类型转换的指令，包括整数之间的转换、浮点数之间的转换、整数与浮点数之间的转换、以及重新解释内存表示的转换。

8. **符号扩展 (Sign Extension):**
   - `emit_i32_signextend_i8`: 生成将 8 位整数符号扩展到 32 位的指令。
   - `emit_i32_signextend_i16`: 生成将 16 位整数符号扩展到 32 位的指令。
   - `emit_i64_signextend_i8`: 生成将 8 位整数符号扩展到 64 位的指令。
   - `emit_i64_signextend_i16`: 生成将 16 位整数符号扩展到 64 位的指令。
   - `emit_i64_signextend_i32`: 生成将 32 位整数符号扩展到 64 位的指令。

9. **跳转指令 (Jump Instructions):**
   - `emit_jump`: 生成无条件跳转指令。
   - `emit_cond_jump`: 生成条件跳转指令。
   - `emit_i32_cond_jumpi`: 生成与立即数比较的条件跳转指令。

10. **条件设置指令 (Set Condition Instructions):**
    - 提供辅助函数 `setcc_32` 用于设置基于比较结果的标志位。
    - `emit_i32_eqz`: 生成判断 32 位整数是否为零并设置结果的指令。
    - `emit_i32_set_cond`: 生成根据条件比较 32 位整数并设置结果的指令。
    - `emit_i64_eqz`: 生成判断 64 位整数是否为零并设置结果的指令。
    - `emit_i64_set_cond`: 生成根据条件比较 64 位整数并设置结果的指令。
    - `emit_f32_set_cond`: 生成根据条件比较 32 位浮点数并设置结果的指令。
    - `emit_f64_set_cond`: 生成根据条件比较 64 位浮点数并设置结果的指令。

11. **选择指令 (Select Instruction):**
    - `emit_select`:  根据条件选择两个值中的一个（这部分代码返回 `false`，可能表示该功能尚未完全实现或有其他实现方式）。

12. **Smi 检查 (Smi Check):**
    - `emit_smi_check`: 生成检查一个值是否为 Smi 的指令。

**关于文件类型:**

如果 `v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h` 以 `.tq` 结尾，那么它才是 V8 Torque 源代码。目前的文件名以 `.h` 结尾，表示它是一个 C++ 头文件，其中包含了内联函数的定义。

**与 JavaScript 的关系:**

这段代码是 V8 引擎执行 WebAssembly 代码的关键部分。当 JavaScript 调用 WebAssembly 模块时，V8 会将 WebAssembly 的字节码编译成本地机器码执行。`LiftoffAssembler` 是一个轻量级的编译器，用于快速生成基线代码，以便快速启动 WebAssembly 的执行。

例如，在 JavaScript 中执行一个简单的 WebAssembly 加法操作：

```javascript
const instance = new WebAssembly.Instance(module, {});
const result = instance.exports.add(5, 10); // 假设 WebAssembly 导出了一个 add 函数
console.log(result); // 输出 15
```

当执行 `instance.exports.add(5, 10)` 时，如果 `add` 函数是用 i32 类型实现的，`LiftoffAssembler` 可能会生成类似于 `addl %edx, %eax` (IA-32 加法指令) 的代码来执行实际的加法运算。对于浮点数运算，则会生成相应的浮点数运算指令，例如 `addss` 或 `addsd`。

**代码逻辑推理和示例:**

以 `emit_i64_shl` 函数为例，它的作用是生成 64 位整数的左移指令。

**假设输入:**

- `dst`:  一个 `LiftoffRegister` 对象，表示目标寄存器对（例如，`{eax, edx}`，低位在 `eax`，高位在 `edx`）。
- `src`:  一个 `LiftoffRegister` 对象，表示源寄存器对（例如，`{ebx, ecx}`）。
- `amount`:  一个 `Register` 对象，表示位移量所在的寄存器（例如，`cl`）。

**输出:**

生成的 IA-32 汇编代码会执行以下操作：

1. **处理 `ecx` 冲突:** 如果目标寄存器包含 `ecx`，则会使用一个临时寄存器替换目标中的 `ecx`，并在最后将临时寄存器的值移回 `ecx`。这主要是为了避免位移量寄存器 `cl` (即 `ecx` 的低 8 位) 与操作数冲突。
2. **并行移动寄存器:** 使用 `ParallelRegisterMove` 函数高效地移动源操作数和位移量到目标寄存器和 `ecx`。
3. **执行左移:** 调用 `MacroAssembler::ShlPair_cl` 函数，该函数会生成实际的左移指令，例如 `shldl %cl, %edx, %eax` (先移动高位，再移动低位)。
4. **恢复 `ecx`:** 如果之前为了避免冲突而替换了 `ecx`，则将临时寄存器的值移回 `ecx`。

**用户常见的编程错误示例:**

1. **位移量超出范围:** 在 C++ 或 JavaScript 中，对整数进行位移操作时，如果位移量大于或等于数据类型的位数，行为是未定义的（或者在 JavaScript 中会被模运算）。WebAssembly 规范定义了明确的行为，但程序员可能会错误地假设位移量总是有效的。例如，对一个 32 位整数左移 32 位或更多。

   ```javascript
   // JavaScript 示例
   let x = 5;
   let y = x << 32; // JavaScript 中等价于 x << (32 % 32)，即 x << 0
   console.log(y); // 输出 5

   // 假设在 WebAssembly 中，程序员错误地认为左移 32 位会将值清零
   ```

2. **浮点数到整数转换的精度损失:** 将浮点数转换为整数时，小数部分会被截断。程序员可能会忘记考虑精度损失的风险，尤其是在将大浮点数转换为较小的整数类型时，可能导致数据丢失或溢出。

   ```javascript
   // JavaScript 示例
   let floatValue = 3.99;
   let intValue = parseInt(floatValue); // 结果是 3，小数部分被截断

   // WebAssembly 中，如果使用不饱和的转换指令，可能会导致 trap
   ```

3. **未考虑浮点数的 NaN (Not a Number):** 浮点数运算可能会产生 NaN 值。在进行浮点数比较或转换时，如果没有正确处理 NaN，可能会导致意外的结果。例如，NaN 与任何数字（包括自身）进行比较的结果都为 false (除了不等于)。

   ```javascript
   // JavaScript 示例
   let nanValue = NaN;
   console.log(nanValue == nanValue);   // 输出 false
   console.log(nanValue != nanValue);   // 输出 true

   // WebAssembly 中，浮点数比较指令需要特殊处理 NaN 的情况
   ```

总而言之，这段代码是 V8 引擎 Liftoff 编译器中用于生成 IA-32 架构 WebAssembly 代码的核心组件，涵盖了整数和浮点数运算、类型转换、位操作、控制流和比较等多种基本操作。理解这段代码有助于深入了解 WebAssembly 在 V8 引擎中的执行过程。

Prompt: 
```
这是目录为v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
pinned{dst};

  constexpr size_t kMaxRegMoves = 3;
  base::SmallVector<LiftoffAssembler::ParallelRegisterMoveTuple, kMaxRegMoves>
      reg_moves;

  // If {dst} contains {ecx}, replace it by an unused register, which is then
  // moved to {ecx} in the end.
  Register ecx_replace = no_reg;
  if (PairContains(dst, ecx)) {
    ecx_replace = assm->GetUnusedRegister(kGpReg, pinned).gp();
    dst = ReplaceInPair(dst, ecx, ecx_replace);
    // If {amount} needs to be moved to {ecx}, but {ecx} is in use (and not part
    // of {dst}, hence overwritten anyway), move {ecx} to a tmp register and
    // restore it at the end.
  } else if (amount != ecx &&
             (assm->cache_state()->is_used(LiftoffRegister(ecx)) ||
              pinned.has(LiftoffRegister(ecx)))) {
    ecx_replace = assm->GetUnusedRegister(kGpReg, pinned).gp();
    reg_moves.emplace_back(ecx_replace, ecx, kI32);
  }

  reg_moves.emplace_back(dst, src, kI64);
  reg_moves.emplace_back(ecx, amount, kI32);
  assm->ParallelRegisterMove(base::VectorOf(reg_moves));

  // Do the actual shift.
  (assm->*emit_shift)(dst.high_gp(), dst.low_gp());

  // Restore {ecx} if needed.
  if (ecx_replace != no_reg) assm->mov(ecx, ecx_replace);
}
}  // namespace liftoff

void LiftoffAssembler::emit_i64_shl(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::Emit64BitShiftOperation(this, dst, src, amount,
                                   &MacroAssembler::ShlPair_cl);
}

void LiftoffAssembler::emit_i64_shli(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  amount &= 63;
  if (amount >= 32) {
    if (dst.high_gp() != src.low_gp()) mov(dst.high_gp(), src.low_gp());
    if (amount != 32) shl(dst.high_gp(), amount - 32);
    xor_(dst.low_gp(), dst.low_gp());
  } else {
    if (dst != src) Move(dst, src, kI64);
    ShlPair(dst.high_gp(), dst.low_gp(), amount);
  }
}

void LiftoffAssembler::emit_i64_sar(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::Emit64BitShiftOperation(this, dst, src, amount,
                                   &MacroAssembler::SarPair_cl);
}

void LiftoffAssembler::emit_i64_sari(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  amount &= 63;
  if (amount >= 32) {
    if (dst.low_gp() != src.high_gp()) mov(dst.low_gp(), src.high_gp());
    if (dst.high_gp() != src.high_gp()) mov(dst.high_gp(), src.high_gp());
    if (amount != 32) sar(dst.low_gp(), amount - 32);
    sar(dst.high_gp(), 31);
  } else {
    if (dst != src) Move(dst, src, kI64);
    SarPair(dst.high_gp(), dst.low_gp(), amount);
  }
}
void LiftoffAssembler::emit_i64_shr(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::Emit64BitShiftOperation(this, dst, src, amount,
                                   &MacroAssembler::ShrPair_cl);
}

void LiftoffAssembler::emit_i64_shri(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  amount &= 63;
  if (amount >= 32) {
    if (dst.low_gp() != src.high_gp()) mov(dst.low_gp(), src.high_gp());
    if (amount != 32) shr(dst.low_gp(), amount - 32);
    xor_(dst.high_gp(), dst.high_gp());
  } else {
    if (dst != src) Move(dst, src, kI64);
    ShrPair(dst.high_gp(), dst.low_gp(), amount);
  }
}

void LiftoffAssembler::emit_i64_clz(LiftoffRegister dst, LiftoffRegister src) {
  // return high == 0 ? 32 + CLZ32(low) : CLZ32(high);
  Label done;
  Register safe_dst = dst.low_gp();
  if (src.low_gp() == safe_dst) safe_dst = dst.high_gp();
  if (CpuFeatures::IsSupported(LZCNT)) {
    CpuFeatureScope scope(this, LZCNT);
    lzcnt(safe_dst, src.high_gp());  // Sets CF if high == 0.
    j(not_carry, &done, Label::kNear);
    lzcnt(safe_dst, src.low_gp());
    add(safe_dst, Immediate(32));  // 32 + CLZ32(low)
  } else {
    // CLZ32(x) =^ x == 0 ? 32 : 31 - BSR32(x)
    Label high_is_zero;
    bsr(safe_dst, src.high_gp());  // Sets ZF is high == 0.
    j(zero, &high_is_zero, Label::kNear);
    xor_(safe_dst, Immediate(31));  // for x in [0..31], 31^x == 31-x.
    jmp(&done, Label::kNear);

    bind(&high_is_zero);
    Label low_not_zero;
    bsr(safe_dst, src.low_gp());
    j(not_zero, &low_not_zero, Label::kNear);
    mov(safe_dst, Immediate(64 ^ 63));  // 64, after the xor below.
    bind(&low_not_zero);
    xor_(safe_dst, 63);  // for x in [0..31], 63^x == 63-x.
  }

  bind(&done);
  if (safe_dst != dst.low_gp()) mov(dst.low_gp(), safe_dst);
  xor_(dst.high_gp(), dst.high_gp());  // High word of result is always 0.
}

void LiftoffAssembler::emit_i64_ctz(LiftoffRegister dst, LiftoffRegister src) {
  // return low == 0 ? 32 + CTZ32(high) : CTZ32(low);
  Label done;
  Register safe_dst = dst.low_gp();
  if (src.high_gp() == safe_dst) safe_dst = dst.high_gp();
  if (CpuFeatures::IsSupported(BMI1)) {
    CpuFeatureScope scope(this, BMI1);
    tzcnt(safe_dst, src.low_gp());  // Sets CF if low == 0.
    j(not_carry, &done, Label::kNear);
    tzcnt(safe_dst, src.high_gp());
    add(safe_dst, Immediate(32));  // 32 + CTZ32(high)
  } else {
    // CTZ32(x) =^ x == 0 ? 32 : BSF32(x)
    bsf(safe_dst, src.low_gp());  // Sets ZF is low == 0.
    j(not_zero, &done, Label::kNear);

    Label high_not_zero;
    bsf(safe_dst, src.high_gp());
    j(not_zero, &high_not_zero, Label::kNear);
    mov(safe_dst, 64);  // low == 0 and high == 0
    jmp(&done);
    bind(&high_not_zero);
    add(safe_dst, Immediate(32));  // 32 + CTZ32(high)
  }

  bind(&done);
  if (safe_dst != dst.low_gp()) mov(dst.low_gp(), safe_dst);
  xor_(dst.high_gp(), dst.high_gp());  // High word of result is always 0.
}

bool LiftoffAssembler::emit_i64_popcnt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(POPCNT)) return false;
  CpuFeatureScope scope(this, POPCNT);
  // Produce partial popcnts in the two dst registers.
  Register src1 = src.high_gp() == dst.low_gp() ? src.high_gp() : src.low_gp();
  Register src2 = src.high_gp() == dst.low_gp() ? src.low_gp() : src.high_gp();
  popcnt(dst.low_gp(), src1);
  popcnt(dst.high_gp(), src2);
  // Add the two into the lower dst reg, clear the higher dst reg.
  add(dst.low_gp(), dst.high_gp());
  xor_(dst.high_gp(), dst.high_gp());
  return true;
}

void LiftoffAssembler::IncrementSmi(LiftoffRegister dst, int offset) {
  add(Operand(dst.gp(), offset), Immediate(Smi::FromInt(1)));
}

void LiftoffAssembler::emit_f32_add(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vaddss(dst, lhs, rhs);
  } else if (dst == rhs) {
    addss(dst, lhs);
  } else {
    if (dst != lhs) movss(dst, lhs);
    addss(dst, rhs);
  }
}

void LiftoffAssembler::emit_f32_sub(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vsubss(dst, lhs, rhs);
  } else if (dst == rhs) {
    movss(liftoff::kScratchDoubleReg, rhs);
    movss(dst, lhs);
    subss(dst, liftoff::kScratchDoubleReg);
  } else {
    if (dst != lhs) movss(dst, lhs);
    subss(dst, rhs);
  }
}

void LiftoffAssembler::emit_f32_mul(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vmulss(dst, lhs, rhs);
  } else if (dst == rhs) {
    mulss(dst, lhs);
  } else {
    if (dst != lhs) movss(dst, lhs);
    mulss(dst, rhs);
  }
}

void LiftoffAssembler::emit_f32_div(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vdivss(dst, lhs, rhs);
  } else if (dst == rhs) {
    movss(liftoff::kScratchDoubleReg, rhs);
    movss(dst, lhs);
    divss(dst, liftoff::kScratchDoubleReg);
  } else {
    if (dst != lhs) movss(dst, lhs);
    divss(dst, rhs);
  }
}

namespace liftoff {
enum class MinOrMax : uint8_t { kMin, kMax };
template <typename type>
inline void EmitFloatMinOrMax(LiftoffAssembler* assm, DoubleRegister dst,
                              DoubleRegister lhs, DoubleRegister rhs,
                              MinOrMax min_or_max) {
  Label is_nan;
  Label lhs_below_rhs;
  Label lhs_above_rhs;
  Label done;

  // We need one tmp register to extract the sign bit. Get it right at the
  // beginning, such that the spilling code is not accidentially jumped over.
  Register tmp = assm->GetUnusedRegister(kGpReg, {}).gp();

#define dop(name, ...)            \
  do {                            \
    if (sizeof(type) == 4) {      \
      assm->name##s(__VA_ARGS__); \
    } else {                      \
      assm->name##d(__VA_ARGS__); \
    }                             \
  } while (false)

  // Check the easy cases first: nan (e.g. unordered), smaller and greater.
  // NaN has to be checked first, because PF=1 implies CF=1.
  dop(ucomis, lhs, rhs);
  assm->j(parity_even, &is_nan, Label::kNear);   // PF=1
  assm->j(below, &lhs_below_rhs, Label::kNear);  // CF=1
  assm->j(above, &lhs_above_rhs, Label::kNear);  // CF=0 && ZF=0

  // If we get here, then either
  // a) {lhs == rhs},
  // b) {lhs == -0.0} and {rhs == 0.0}, or
  // c) {lhs == 0.0} and {rhs == -0.0}.
  // For a), it does not matter whether we return {lhs} or {rhs}. Check the sign
  // bit of {rhs} to differentiate b) and c).
  dop(movmskp, tmp, rhs);
  assm->test(tmp, Immediate(1));
  assm->j(zero, &lhs_below_rhs, Label::kNear);
  assm->jmp(&lhs_above_rhs, Label::kNear);

  assm->bind(&is_nan);
  // Create a NaN output.
  dop(xorp, dst, dst);
  dop(divs, dst, dst);
  assm->jmp(&done, Label::kNear);

  assm->bind(&lhs_below_rhs);
  DoubleRegister lhs_below_rhs_src = min_or_max == MinOrMax::kMin ? lhs : rhs;
  if (dst != lhs_below_rhs_src) dop(movs, dst, lhs_below_rhs_src);
  assm->jmp(&done, Label::kNear);

  assm->bind(&lhs_above_rhs);
  DoubleRegister lhs_above_rhs_src = min_or_max == MinOrMax::kMin ? rhs : lhs;
  if (dst != lhs_above_rhs_src) dop(movs, dst, lhs_above_rhs_src);

  assm->bind(&done);
}
}  // namespace liftoff

void LiftoffAssembler::emit_f32_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax<float>(this, dst, lhs, rhs,
                                    liftoff::MinOrMax::kMin);
}

void LiftoffAssembler::emit_f32_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax<float>(this, dst, lhs, rhs,
                                    liftoff::MinOrMax::kMax);
}

void LiftoffAssembler::emit_f32_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  static constexpr int kF32SignBit = 1 << 31;
  LiftoffRegList pinned;
  Register scratch = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register scratch2 = GetUnusedRegister(kGpReg, pinned).gp();
  Movd(scratch, lhs);                      // move {lhs} into {scratch}.
  and_(scratch, Immediate(~kF32SignBit));  // clear sign bit in {scratch}.
  Movd(scratch2, rhs);                     // move {rhs} into {scratch2}.
  and_(scratch2, Immediate(kF32SignBit));  // isolate sign bit in {scratch2}.
  or_(scratch, scratch2);                  // combine {scratch2} into {scratch}.
  Movd(dst, scratch);                      // move result into {dst}.
}

void LiftoffAssembler::emit_f32_abs(DoubleRegister dst, DoubleRegister src) {
  static constexpr uint32_t kSignBit = uint32_t{1} << 31;
  if (dst == src) {
    MacroAssembler::Move(liftoff::kScratchDoubleReg, kSignBit - 1);
    Andps(dst, liftoff::kScratchDoubleReg);
  } else {
    MacroAssembler::Move(dst, kSignBit - 1);
    Andps(dst, src);
  }
}

void LiftoffAssembler::emit_f32_neg(DoubleRegister dst, DoubleRegister src) {
  static constexpr uint32_t kSignBit = uint32_t{1} << 31;
  if (dst == src) {
    MacroAssembler::Move(liftoff::kScratchDoubleReg, kSignBit);
    Xorps(dst, liftoff::kScratchDoubleReg);
  } else {
    MacroAssembler::Move(dst, kSignBit);
    Xorps(dst, src);
  }
}

bool LiftoffAssembler::emit_f32_ceil(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  roundss(dst, src, kRoundUp);
  return true;
}

bool LiftoffAssembler::emit_f32_floor(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  roundss(dst, src, kRoundDown);
  return true;
}

bool LiftoffAssembler::emit_f32_trunc(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  roundss(dst, src, kRoundToZero);
  return true;
}

bool LiftoffAssembler::emit_f32_nearest_int(DoubleRegister dst,
                                            DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  roundss(dst, src, kRoundToNearest);
  return true;
}

void LiftoffAssembler::emit_f32_sqrt(DoubleRegister dst, DoubleRegister src) {
  Sqrtss(dst, src);
}

void LiftoffAssembler::emit_f64_add(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vaddsd(dst, lhs, rhs);
  } else if (dst == rhs) {
    addsd(dst, lhs);
  } else {
    if (dst != lhs) movsd(dst, lhs);
    addsd(dst, rhs);
  }
}

void LiftoffAssembler::emit_f64_sub(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vsubsd(dst, lhs, rhs);
  } else if (dst == rhs) {
    movsd(liftoff::kScratchDoubleReg, rhs);
    movsd(dst, lhs);
    subsd(dst, liftoff::kScratchDoubleReg);
  } else {
    if (dst != lhs) movsd(dst, lhs);
    subsd(dst, rhs);
  }
}

void LiftoffAssembler::emit_f64_mul(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vmulsd(dst, lhs, rhs);
  } else if (dst == rhs) {
    mulsd(dst, lhs);
  } else {
    if (dst != lhs) movsd(dst, lhs);
    mulsd(dst, rhs);
  }
}

void LiftoffAssembler::emit_f64_div(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vdivsd(dst, lhs, rhs);
  } else if (dst == rhs) {
    movsd(liftoff::kScratchDoubleReg, rhs);
    movsd(dst, lhs);
    divsd(dst, liftoff::kScratchDoubleReg);
  } else {
    if (dst != lhs) movsd(dst, lhs);
    divsd(dst, rhs);
  }
}

void LiftoffAssembler::emit_f64_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax<double>(this, dst, lhs, rhs,
                                     liftoff::MinOrMax::kMin);
}

void LiftoffAssembler::emit_f64_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  static constexpr int kF32SignBit = 1 << 31;
  // On ia32, we cannot hold the whole f64 value in a gp register, so we just
  // operate on the upper half (UH).
  LiftoffRegList pinned;
  Register scratch = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register scratch2 = GetUnusedRegister(kGpReg, pinned).gp();

  Pextrd(scratch, lhs, 1);                 // move UH of {lhs} into {scratch}.
  and_(scratch, Immediate(~kF32SignBit));  // clear sign bit in {scratch}.
  Pextrd(scratch2, rhs, 1);                // move UH of {rhs} into {scratch2}.
  and_(scratch2, Immediate(kF32SignBit));  // isolate sign bit in {scratch2}.
  or_(scratch, scratch2);                  // combine {scratch2} into {scratch}.
  movsd(dst, lhs);                         // move {lhs} into {dst}.
  Pinsrd(dst, scratch, 1);                 // insert {scratch} into UH of {dst}.
}

void LiftoffAssembler::emit_f64_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax<double>(this, dst, lhs, rhs,
                                     liftoff::MinOrMax::kMax);
}

void LiftoffAssembler::emit_f64_abs(DoubleRegister dst, DoubleRegister src) {
  static constexpr uint64_t kSignBit = uint64_t{1} << 63;
  if (dst == src) {
    MacroAssembler::Move(liftoff::kScratchDoubleReg, kSignBit - 1);
    Andpd(dst, liftoff::kScratchDoubleReg);
  } else {
    MacroAssembler::Move(dst, kSignBit - 1);
    Andpd(dst, src);
  }
}

void LiftoffAssembler::emit_f64_neg(DoubleRegister dst, DoubleRegister src) {
  static constexpr uint64_t kSignBit = uint64_t{1} << 63;
  if (dst == src) {
    MacroAssembler::Move(liftoff::kScratchDoubleReg, kSignBit);
    Xorpd(dst, liftoff::kScratchDoubleReg);
  } else {
    MacroAssembler::Move(dst, kSignBit);
    Xorpd(dst, src);
  }
}

bool LiftoffAssembler::emit_f64_ceil(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  roundsd(dst, src, kRoundUp);
  return true;
}

bool LiftoffAssembler::emit_f64_floor(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  roundsd(dst, src, kRoundDown);
  return true;
}

bool LiftoffAssembler::emit_f64_trunc(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  roundsd(dst, src, kRoundToZero);
  return true;
}

bool LiftoffAssembler::emit_f64_nearest_int(DoubleRegister dst,
                                            DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  roundsd(dst, src, kRoundToNearest);
  return true;
}

void LiftoffAssembler::emit_f64_sqrt(DoubleRegister dst, DoubleRegister src) {
  Sqrtsd(dst, src);
}

namespace liftoff {
#define __ assm->
// Used for float to int conversions. If the value in {converted_back} equals
// {src} afterwards, the conversion succeeded.
template <typename dst_type, typename src_type>
inline void ConvertFloatToIntAndBack(LiftoffAssembler* assm, Register dst,
                                     DoubleRegister src,
                                     DoubleRegister converted_back,
                                     LiftoffRegList pinned) {
  if (std::is_same<double, src_type>::value) {  // f64
    if (std::is_signed<dst_type>::value) {      // f64 -> i32
      __ cvttsd2si(dst, src);
      __ Cvtsi2sd(converted_back, dst);
    } else {  // f64 -> u32
      __ Cvttsd2ui(dst, src, liftoff::kScratchDoubleReg);
      __ Cvtui2sd(converted_back, dst,
                  __ GetUnusedRegister(kGpReg, pinned).gp());
    }
  } else {                                  // f32
    if (std::is_signed<dst_type>::value) {  // f32 -> i32
      __ cvttss2si(dst, src);
      __ Cvtsi2ss(converted_back, dst);
    } else {  // f32 -> u32
      __ Cvttss2ui(dst, src, liftoff::kScratchDoubleReg);
      __ Cvtui2ss(converted_back, dst,
                  __ GetUnusedRegister(kGpReg, pinned).gp());
    }
  }
}

template <typename dst_type, typename src_type>
inline bool EmitTruncateFloatToInt(LiftoffAssembler* assm, Register dst,
                                   DoubleRegister src, Label* trap) {
  if (!CpuFeatures::IsSupported(SSE4_1)) {
    __ bailout(kMissingCPUFeature, "no SSE4.1");
    return true;
  }
  CpuFeatureScope feature(assm, SSE4_1);

  LiftoffRegList pinned{src, dst};
  DoubleRegister rounded =
      pinned.set(__ GetUnusedRegister(kFpReg, pinned)).fp();
  DoubleRegister converted_back =
      pinned.set(__ GetUnusedRegister(kFpReg, pinned)).fp();

  if (std::is_same<double, src_type>::value) {  // f64
    __ roundsd(rounded, src, kRoundToZero);
  } else {  // f32
    __ roundss(rounded, src, kRoundToZero);
  }
  ConvertFloatToIntAndBack<dst_type, src_type>(assm, dst, rounded,
                                               converted_back, pinned);
  if (std::is_same<double, src_type>::value) {  // f64
    __ ucomisd(converted_back, rounded);
  } else {  // f32
    __ ucomiss(converted_back, rounded);
  }

  // Jump to trap if PF is 0 (one of the operands was NaN) or they are not
  // equal.
  __ j(parity_even, trap);
  __ j(not_equal, trap);
  return true;
}

template <typename dst_type, typename src_type>
inline bool EmitSatTruncateFloatToInt(LiftoffAssembler* assm, Register dst,
                                      DoubleRegister src) {
  if (!CpuFeatures::IsSupported(SSE4_1)) {
    __ bailout(kMissingCPUFeature, "no SSE4.1");
    return true;
  }
  CpuFeatureScope feature(assm, SSE4_1);

  Label done;
  Label not_nan;
  Label src_positive;

  LiftoffRegList pinned{src, dst};
  DoubleRegister rounded =
      pinned.set(__ GetUnusedRegister(kFpReg, pinned)).fp();
  DoubleRegister converted_back =
      pinned.set(__ GetUnusedRegister(kFpReg, pinned)).fp();
  DoubleRegister zero_reg =
      pinned.set(__ GetUnusedRegister(kFpReg, pinned)).fp();

  if (std::is_same<double, src_type>::value) {  // f64
    __ roundsd(rounded, src, kRoundToZero);
  } else {  // f32
    __ roundss(rounded, src, kRoundToZero);
  }

  ConvertFloatToIntAndBack<dst_type, src_type>(assm, dst, rounded,
                                               converted_back, pinned);
  if (std::is_same<double, src_type>::value) {  // f64
    __ ucomisd(converted_back, rounded);
  } else {  // f32
    __ ucomiss(converted_back, rounded);
  }

  // Return 0 if PF is 0 (one of the operands was NaN)
  __ j(parity_odd, &not_nan);
  __ xor_(dst, dst);
  __ jmp(&done);

  __ bind(&not_nan);
  // If rounding is as expected, return result
  __ j(equal, &done);

  __ Xorpd(zero_reg, zero_reg);

  // if out-of-bounds, check if src is positive
  if (std::is_same<double, src_type>::value) {  // f64
    __ ucomisd(src, zero_reg);
  } else {  // f32
    __ ucomiss(src, zero_reg);
  }
  __ j(above, &src_positive);
  __ mov(dst, Immediate(std::numeric_limits<dst_type>::min()));
  __ jmp(&done);

  __ bind(&src_positive);

  __ mov(dst, Immediate(std::numeric_limits<dst_type>::max()));

  __ bind(&done);
  return true;
}
#undef __
}  // namespace liftoff

bool LiftoffAssembler::emit_type_conversion(WasmOpcode opcode,
                                            LiftoffRegister dst,
                                            LiftoffRegister src, Label* trap) {
  switch (opcode) {
    case kExprI32ConvertI64:
      if (dst.gp() != src.low_gp()) mov(dst.gp(), src.low_gp());
      return true;
    case kExprI32SConvertF32:
      return liftoff::EmitTruncateFloatToInt<int32_t, float>(this, dst.gp(),
                                                             src.fp(), trap);
    case kExprI32UConvertF32:
      return liftoff::EmitTruncateFloatToInt<uint32_t, float>(this, dst.gp(),
                                                              src.fp(), trap);
    case kExprI32SConvertF64:
      return liftoff::EmitTruncateFloatToInt<int32_t, double>(this, dst.gp(),
                                                              src.fp(), trap);
    case kExprI32UConvertF64:
      return liftoff::EmitTruncateFloatToInt<uint32_t, double>(this, dst.gp(),
                                                               src.fp(), trap);
    case kExprI32SConvertSatF32:
      return liftoff::EmitSatTruncateFloatToInt<int32_t, float>(this, dst.gp(),
                                                                src.fp());
    case kExprI32UConvertSatF32:
      return liftoff::EmitSatTruncateFloatToInt<uint32_t, float>(this, dst.gp(),
                                                                 src.fp());
    case kExprI32SConvertSatF64:
      return liftoff::EmitSatTruncateFloatToInt<int32_t, double>(this, dst.gp(),
                                                                 src.fp());
    case kExprI32UConvertSatF64:
      return liftoff::EmitSatTruncateFloatToInt<uint32_t, double>(
          this, dst.gp(), src.fp());
    case kExprI32ReinterpretF32:
      Movd(dst.gp(), src.fp());
      return true;
    case kExprI64SConvertI32:
      if (dst.low_gp() != src.gp()) mov(dst.low_gp(), src.gp());
      if (dst.high_gp() != src.gp()) mov(dst.high_gp(), src.gp());
      sar(dst.high_gp(), 31);
      return true;
    case kExprI64UConvertI32:
      if (dst.low_gp() != src.gp()) mov(dst.low_gp(), src.gp());
      xor_(dst.high_gp(), dst.high_gp());
      return true;
    case kExprI64ReinterpretF64:
      // Push src to the stack.
      AllocateStackSpace(8);
      movsd(Operand(esp, 0), src.fp());
      // Pop to dst.
      pop(dst.low_gp());
      pop(dst.high_gp());
      return true;
    case kExprF32SConvertI32:
      cvtsi2ss(dst.fp(), src.gp());
      return true;
    case kExprF32UConvertI32: {
      LiftoffRegList pinned{dst, src};
      Register scratch = GetUnusedRegister(kGpReg, pinned).gp();
      Cvtui2ss(dst.fp(), src.gp(), scratch);
      return true;
    }
    case kExprF32ConvertF64:
      cvtsd2ss(dst.fp(), src.fp());
      return true;
    case kExprF32ReinterpretI32:
      Movd(dst.fp(), src.gp());
      return true;
    case kExprF64SConvertI32:
      Cvtsi2sd(dst.fp(), src.gp());
      return true;
    case kExprF64UConvertI32: {
      LiftoffRegList pinned{dst, src};
      Register scratch = GetUnusedRegister(kGpReg, pinned).gp();
      Cvtui2sd(dst.fp(), src.gp(), scratch);
      return true;
    }
    case kExprF64ConvertF32:
      cvtss2sd(dst.fp(), src.fp());
      return true;
    case kExprF64ReinterpretI64:
      // Push src to the stack.
      push(src.high_gp());
      push(src.low_gp());
      // Pop to dst.
      movsd(dst.fp(), Operand(esp, 0));
      add(esp, Immediate(8));
      return true;
    default:
      return false;
  }
}

void LiftoffAssembler::emit_i32_signextend_i8(Register dst, Register src) {
  Register byte_reg = liftoff::GetTmpByteRegister(this, src);
  if (byte_reg != src) mov(byte_reg, src);
  movsx_b(dst, byte_reg);
}

void LiftoffAssembler::emit_i32_signextend_i16(Register dst, Register src) {
  movsx_w(dst, src);
}

void LiftoffAssembler::emit_i64_signextend_i8(LiftoffRegister dst,
                                              LiftoffRegister src) {
  Register byte_reg = liftoff::GetTmpByteRegister(this, src.low_gp());
  if (byte_reg != src.low_gp()) mov(byte_reg, src.low_gp());
  movsx_b(dst.low_gp(), byte_reg);
  liftoff::SignExtendI32ToI64(this, dst);
}

void LiftoffAssembler::emit_i64_signextend_i16(LiftoffRegister dst,
                                               LiftoffRegister src) {
  movsx_w(dst.low_gp(), src.low_gp());
  liftoff::SignExtendI32ToI64(this, dst);
}

void LiftoffAssembler::emit_i64_signextend_i32(LiftoffRegister dst,
                                               LiftoffRegister src) {
  if (dst.low_gp() != src.low_gp()) mov(dst.low_gp(), src.low_gp());
  liftoff::SignExtendI32ToI64(this, dst);
}

void LiftoffAssembler::emit_jump(Label* label) { jmp(label); }

void LiftoffAssembler::emit_jump(Register target) { jmp(target); }

void LiftoffAssembler::emit_cond_jump(Condition cond, Label* label,
                                      ValueKind kind, Register lhs,
                                      Register rhs,
                                      const FreezeCacheState& frozen) {
  if (rhs != no_reg) {
    switch (kind) {
      case kRef:
      case kRefNull:
      case kRtt:
        DCHECK(cond == kEqual || cond == kNotEqual);
        [[fallthrough]];
      case kI32:
        cmp(lhs, rhs);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    DCHECK_EQ(kind, kI32);
    test(lhs, lhs);
  }

  j(cond, label);
}

void LiftoffAssembler::emit_i32_cond_jumpi(Condition cond, Label* label,
                                           Register lhs, int imm,
                                           const FreezeCacheState& frozen) {
  cmp(lhs, Immediate(imm));
  j(cond, label);
}

namespace liftoff {

// Setcc into dst register, given a scratch byte register (might be the same as
// dst). Never spills.
inline void setcc_32_no_spill(LiftoffAssembler* assm, Condition cond,
                              Register dst, Register tmp_byte_reg) {
  assm->setcc(cond, tmp_byte_reg);
  assm->movzx_b(dst, tmp_byte_reg);
}

// Setcc into dst register (no constraints). Might spill.
inline void setcc_32(LiftoffAssembler* assm, Condition cond, Register dst) {
  Register tmp_byte_reg = GetTmpByteRegister(assm, dst);
  setcc_32_no_spill(assm, cond, dst, tmp_byte_reg);
}

}  // namespace liftoff

void LiftoffAssembler::emit_i32_eqz(Register dst, Register src) {
  test(src, src);
  liftoff::setcc_32(this, equal, dst);
}

void LiftoffAssembler::emit_i32_set_cond(Condition cond, Register dst,
                                         Register lhs, Register rhs) {
  cmp(lhs, rhs);
  liftoff::setcc_32(this, cond, dst);
}

void LiftoffAssembler::emit_i64_eqz(Register dst, LiftoffRegister src) {
  // Compute the OR of both registers in the src pair, using dst as scratch
  // register. Then check whether the result is equal to zero.
  if (src.low_gp() == dst) {
    or_(dst, src.high_gp());
  } else {
    if (src.high_gp() != dst) mov(dst, src.high_gp());
    or_(dst, src.low_gp());
  }
  liftoff::setcc_32(this, equal, dst);
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
  Condition unsigned_cond = liftoff::cond_make_unsigned(cond);

  // Get the tmp byte register out here, such that we don't conditionally spill
  // (this cannot be reflected in the cache state).
  Register tmp_byte_reg = liftoff::GetTmpByteRegister(this, dst);

  // For signed i64 comparisons, we still need to use unsigned comparison for
  // the low word (the only bit carrying signedness information is the MSB in
  // the high word).
  Label setcc;
  Label cont;
  // Compare high word first. If it differs, use if for the setcc. If it's
  // equal, compare the low word and use that for setcc.
  cmp(lhs.high_gp(), rhs.high_gp());
  j(not_equal, &setcc, Label::kNear);
  cmp(lhs.low_gp(), rhs.low_gp());
  if (unsigned_cond != cond) {
    // If the condition predicate for the low differs from that for the high
    // word, emit a separete setcc sequence for the low word.
    liftoff::setcc_32_no_spill(this, unsigned_cond, dst, tmp_byte_reg);
    jmp(&cont);
  }
  bind(&setcc);
  liftoff::setcc_32_no_spill(this, cond, dst, tmp_byte_reg);
  bind(&cont);
}

namespace liftoff {
template <void (Assembler::*cmp_op)(DoubleRegister, DoubleRegister)>
void EmitFloatSetCond(LiftoffAssembler* assm, Condition cond, Register dst,
                      DoubleRegister lhs, DoubleRegister rhs) {
  Label cont;
  Label not_nan;

  // Get the tmp byte register out here, such that we don't conditionally spill
  // (this cannot be reflected in the cache state).
  Register tmp_byte_reg = GetTmpByteRegister(assm, dst);

  (assm->*cmp_op)(lhs, rhs);
  // If PF is one, one of the operands was Nan. This needs special handling.
  assm->j(parity_odd, &not_nan, Label::kNear);
  // Return 1 for f32.ne, 0 for all other cases.
  if (cond == not_equal) {
    assm->mov(dst, Immediate(1));
  } else {
    assm->xor_(dst, dst);
  }
  assm->jmp(&cont, Label::kNear);
  assm->bind(&not_nan);

  setcc_32_no_spill(assm, cond, dst, tmp_byte_reg);
  assm->bind(&cont);
}
}  // namespace liftoff

void LiftoffAssembler::emit_f32_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  liftoff::EmitFloatSetCond<&Assembler::ucomiss>(this, cond, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  liftoff::EmitFloatSetCond<&Assembler::ucomisd>(this, cond, dst, lhs, rhs);
}

bool LiftoffAssembler::emit_select(LiftoffRegister dst, Register condition,
                                   LiftoffRegister true_value,
                                   LiftoffRegister false_value,
                                   ValueKind kind) {
  return false;
}

void LiftoffAssembler::emit_smi_check(Register obj, Label* target,
                         
"""


```