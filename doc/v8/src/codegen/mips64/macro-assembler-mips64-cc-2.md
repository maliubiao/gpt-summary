Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/mips64/macro-assembler-mips64.cc`. This is part 3 of a 7-part series.

The code defines a `MacroAssembler` class for the MIPS64 architecture in V8. It seems to be focused on implementing various arithmetic and conversion operations, particularly involving floating-point numbers and potentially SIMD (MSA) operations.

Here's a breakdown of the code's functionality:

1. **Floating-point Conversions:**  Functions like `Cvt_d_uw`, `Cvt_d_ul`, `Cvt_s_uw`, `Cvt_s_ul` are present. These seem to convert unsigned word/long integers to double/single-precision floating-point numbers.

2. **Floating-point Rounding:** Functions like `Round_l_d`, `Floor_l_d`, `Ceil_l_d`, `Trunc_l_d` suggest operations for rounding double-precision floating-point numbers to long integers using different rounding modes. There are also variants for unsigned long integers (`Trunc_l_ud`).

3. **Floating-point Truncation to Integers:**  Functions like `Trunc_uw_d`, `Trunc_uw_s`, `Trunc_ul_d`, `Trunc_ul_s`, `Trunc_w_d` appear to truncate floating-point numbers (both single and double precision) to unsigned/signed word/long integers. The implementations handle cases where the floating-point number is out of the representable range of the target integer type.

4. **Generic Floating-point Rounding:** Template functions `RoundDouble` and `RoundFloat` are used to implement rounding with different modes (floor, ceil, trunc, round) for double and single-precision floating-point numbers. These functions seem to handle potential edge cases and different MIPS64 architecture variants.

5. **MSA (SIMD) Operations:** Functions like `LoadLane`, `StoreLane`, `ExtMulLow`, `ExtMulHigh`, `LoadSplat`, `ExtAddPairwise`, `MSARoundW`, `MSARoundD` suggest support for MIPS SIMD Architecture (MSA) operations. These operations likely involve loading/storing data into/from vector registers, performing element-wise multiplications, additions, and rounding.

6. **Fused Multiply-Add/Subtract:** Functions like `Madd_s`, `Madd_d`, `Msub_s`, `Msub_d` implement fused multiply-add and multiply-subtract operations for single and double-precision floats.

7. **Floating-point Comparisons and Branching:** Functions like `CompareF`, `CompareIsNanF`, `BranchTrueShortF`, `BranchFalseShortF`, `BranchTrueF`, `BranchFalseF` provide functionality for comparing floating-point numbers and branching based on the comparison result. There are also MSA-specific branching instructions (`BranchMSA`, `BranchShortMSA`).

8. **Data Movement:** Functions like `FmoveLow`, `Move` (for immediate values to FPU registers), `Movz`, `Movn` are for moving data between registers.

9. **Conditional Moves:** Functions like `LoadZeroIfConditionNotZero`, `LoadZeroIfConditionZero`, `LoadZeroIfFPUCondition`, `LoadZeroIfNotFPUCondition`, `Movt`, `Movf` provide conditional move instructions.

10. **Bit Manipulation:** Functions like `Clz`, `Dclz`, `Ctz`, `Dctz`, `Popcnt`, `Dpopcnt` implement bit counting operations (count leading zeros, trailing zeros, set bits).

11. **Truncating Double to Integer with Overflow Handling:** The `TryInlineTruncateDoubleToI` and `TruncateDoubleToI` functions handle the truncation of a double-precision float to a signed integer, including checking for overflow and NaN cases. If the inline version fails, it falls back to a runtime call.

12. **Word Comparison:** The `CompareWord` function starts implementing comparisons between registers and operands (immediate or register).

Given that this is part 3 of 7, it's reasonable to assume that this file implements a subset of the macro-assembler functionality, likely focused on floating-point and SIMD operations.

Now, let's address the specific requirements:

* **Functionality Listing:** Done above.
* **Torque Source:** The filename does not end in `.tq`, so it's not a Torque source file.
* **Relationship to Javascript:** Many of these operations are directly related to how Javascript handles numbers, especially when dealing with floating-point values and Typed Arrays (which can leverage SIMD).
* **Javascript Examples:**
* **Code Logic Reasoning:**  Many functions have implicit logic (e.g., `Cvt_d_ul` handling values >= 2^63), but `Trunc_ul_d` and `Trunc_ul_s` have explicit logic with branches for handling large unsigned values.
* **Common Programming Errors:** Converting floating-point numbers to integers can lead to data loss or unexpected behavior due to truncation or rounding.

Let's generate the detailed response now.
这是 `v8/src/codegen/mips64/macro-assembler-mips64.cc` 源代码的第三部分，主要功能是提供了一系列用于在 MIPS64 架构上进行浮点数和部分 SIMD (MSA) 运算的宏指令。这些宏指令是更高级别的抽象，建立在底层的 MIPS64 汇编指令之上，方便 V8 引擎的代码生成器使用。

**功能归纳:**

这部分代码主要实现了以下功能：

1. **浮点数类型转换:**
   - 提供了将无符号 32 位和 64 位整数转换为双精度浮点数 (`Cvt_d_uw`, `Cvt_d_ul`) 和单精度浮点数 (`Cvt_s_uw`, `Cvt_s_ul`) 的指令。这些转换处理了将整数数据加载到浮点寄存器并执行转换的过程。

2. **浮点数取整:**
   - 实现了多种浮点数取整操作，包括向最接近的整数取整 (`Round_l_d`)，向下取整 (`Floor_l_d`)，向上取整 (`Ceil_l_d`)，以及向零取整 (`Trunc_l_d`)。这些操作将双精度浮点数转换为 64 位整数。
   - 还提供了将双精度浮点数截断为无符号 64 位整数的版本 (`Trunc_l_ud`)。

3. **浮点数截断为整数:**
   - 提供了将双精度和单精度浮点数截断为无符号 32 位整数 (`Trunc_uw_d`, `Trunc_uw_s`) 和无符号 64 位整数 (`Trunc_ul_d`, `Trunc_ul_s`) 的指令。
   - 实现了将双精度浮点数截断为有符号 32 位整数 (`Trunc_w_d`)，并提供了相应的取整操作 (`Round_w_d`, `Floor_w_d`, `Ceil_w_d`)。
   - `Trunc_uw_d` 和 `Trunc_uw_s` 的实现中，如果浮点数大于等于 2^32，则结果为 `UINT_32_MAX`。`Trunc_ul_d` 和 `Trunc_ul_s` 也处理了大于等于 2^63 的情况，并使用额外的寄存器来指示转换是否失败（如果结果为负数）。

4. **通用浮点数取整模板:**
   - 定义了模板函数 `RoundDouble` 和 `RoundFloat`，用于实现不同取整模式（最接近，向下，向上，向零）的双精度和单精度浮点数取整。这些模板函数根据架构变体 (kMips64r6) 选择不同的指令序列。

5. **MSA (MIPS SIMD Architecture) 操作:**
   - 提供了加载和存储 MSA 寄存器特定 Lane 的指令 (`LoadLane`, `StoreLane`)。
   - 实现了 MSA 寄存器的扩展乘法低位 (`ExtMulLow`) 和高位 (`ExtMulHigh`) 操作。
   - 提供了将内存中的值广播到 MSA 寄存器的指令 (`LoadSplat`)。
   - 实现了 MSA 寄存器的成对扩展加法 (`ExtAddPairwise`)。
   - 提供了 MSA 浮点数的取整操作 (`MSARoundW`, `MSARoundD`)，可以指定取整模式。

6. **浮点数融合乘加/乘减运算:**
   - 提供了浮点数的融合乘加 (`Madd_s`, `Madd_d`) 和乘减 (`Msub_s`, `Msub_d`) 运算，可以减少中间舍入误差。

7. **浮点数比较和分支:**
   - 提供了浮点数比较指令 (`CompareF`, `CompareIsNanF`)，可以比较单精度和双精度浮点数，并设置浮点条件码。
   - 提供了基于浮点条件码进行分支的指令 (`BranchTrueShortF`, `BranchFalseShortF`, `BranchTrueF`, `BranchFalseF`)。
   - 提供了基于 MSA 寄存器的条件进行分支的指令 (`BranchMSA`, `BranchShortMSA`)。

8. **数据移动:**
   - 提供了在浮点寄存器和通用寄存器之间移动低位数据的指令 (`FmoveLow`)。
   - 提供了将立即数加载到浮点寄存器的指令 (`Move`)，可以加载 32 位和 64 位立即数。

9. **条件移动:**
   - 提供了基于通用寄存器条件码进行条件移动的指令 (`Movz`, `Movn`)。
   - 提供了基于条件码将寄存器置零的指令 (`LoadZeroIfConditionNotZero`, `LoadZeroIfConditionZero`)。
   - 提供了基于浮点条件码进行条件移动的指令 (`Movt`, `Movf`) 以及将寄存器置零的指令 (`LoadZeroIfFPUCondition`, `LoadZeroIfNotFPUCondition`)。

10. **位操作:**
    - 提供了计算前导零个数 (`Clz`, `Dclz`) 和尾随零个数 (`Ctz`, `Dctz`) 的指令。
    - 提供了计算设置位个数 (`Popcnt`, `Dpopcnt`) 的指令。

11. **尝试内联截断双精度浮点数到整数:**
    - 提供了 `TryInlineTruncateDoubleToI` 函数，尝试将双精度浮点数内联截断为有符号整数，并检查溢出和 NaN。
    - `TruncateDoubleToI` 函数在内联版本失败时，会调用运行时 Stub 进行处理。

12. **字比较:**
    - `CompareWord` 函数开始实现通用寄存器之间的比较操作。

**关于 .tq 结尾:**

`v8/src/codegen/mips64/macro-assembler-mips64.cc` 的文件名以 `.cc` 结尾，这表示它是一个 C++ 源代码文件，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系及示例:**

这些宏指令直接服务于 V8 引擎执行 JavaScript 代码。JavaScript 中的 Number 类型在底层通常使用双精度浮点数表示。当 JavaScript 代码执行涉及数值计算、类型转换或位操作时，V8 的代码生成器可能会使用这些宏指令来生成高效的 MIPS64 汇编代码。

**JavaScript 示例：**

```javascript
// 浮点数转换
let unsignedInt = 4294967295; // 2^32 - 1
let doubleFromUnsigned = unsignedInt; // JavaScript 会自动转换为双精度浮点数

// 浮点数取整
let floatValue = 3.14;
let roundedDown = Math.floor(floatValue); // 向下取整

// 浮点数截断
let truncatedValue = Math.trunc(floatValue); // 向零取整

// 位操作 (通常用于整数，但 JavaScript 的位操作会先将浮点数转换为整数)
let num = 15; // 二进制 0b1111
let leadingZeros = Math.clz32(num); // 计算 32 位整数的前导零

// SIMD 操作 (通过 WebAssembly SIMD 或一些实验性 API)
// 假设存在一个 SIMD API
// let a = new Float32x4(1.0, 2.0, 3.0, 4.0);
// let b = new Float32x4(5.0, 6.0, 7.0, 8.0);
// let c = a.add(b); // 底层可能使用 MSA 加法指令
```

**代码逻辑推理示例:**

**假设输入:**
- `MacroAssembler::Cvt_d_ul(fd, rs)` 函数被调用，其中 `rs` 寄存器包含值 `0xFFFFFFFFFFFFFFFF` (最大的 64 位无符号整数)。

**代码逻辑:**
```c++
void MacroAssembler::Cvt_d_ul(FPURegister fd, Register rs) {
  // ...
  Label msb_clear, conversion_done;
  Branch(&msb_clear, ge, rs, Operand(zero_reg)); // 0xFF... 是正数，不跳转

  // Rs >= 2^63
  andi(t9, rs, 1); // t9 = 1
  dsrl(rs, rs, 1); // rs = 0x7FFFFFFFFFFFFFFF
  or_(t9, t9, rs); // t9 = 0x7FFFFFFFFFFFFFF
  dmtc1(t9, fd);  // 将 t9 的值（近似 2^63）加载到 fd 的低 64 位
  cvt_d_l(fd, fd); // 将 fd 中的整数值转换为双精度浮点数
  Branch(USE_DELAY_SLOT, &conversion_done);
  add_d(fd, fd, fd);  // 在延迟槽中，执行 fd = fd + fd，相当于乘以 2

  bind(&msb_clear); // 不会执行到这里

  // ...
}
```

**输出:**
- `fd` 寄存器将包含一个接近于 `1.8446744073709552e+19` 的双精度浮点数，这是 `0xFFFFFFFFFFFFFFFF` 的近似值。由于超过了浮点数的精度，可能会有精度损失。

**用户常见的编程错误示例:**

1. **浮点数到整数的直接转换可能导致数据丢失:**

   ```javascript
   let floatNum = 3.9;
   let intNum = parseInt(floatNum); // 结果是 3，小数部分被截断
   let anotherInt = floatNum | 0;    // 结果也是 3，通过位运算截断
   ```
   用户可能期望得到四舍五入的结果，但 `parseInt` 和按位或 `| 0` 都会执行截断。

2. **没有考虑到浮点数运算的精度问题:**

   ```javascript
   let a = 0.1;
   let b = 0.2;
   let sum = a + b;
   console.log(sum === 0.3); // 输出 false，因为浮点数运算存在精度误差
   ```
   用户可能会期望 `0.1 + 0.2` 精确等于 `0.3`，但由于浮点数的表示方式，结果会略有偏差。

3. **在需要整数的场合使用了浮点数，导致意外的截断或舍入:**

   ```javascript
   function processArray(index) {
       // 假设 index 应该是整数
       console.log("Processing element at index:", index);
   }

   let floatIndex = 2.9;
   processArray(floatIndex); // index 的值会被隐式转换为 2，可能不是用户期望的结果
   ```
   用户可能没有意识到传递给函数的浮点数会被转换为整数。

总而言之，这部分 `macro-assembler-mips64.cc` 代码是 V8 引擎在 MIPS64 架构上执行 JavaScript 代码的关键组成部分，它提供了执行浮点数和 SIMD 运算所需的底层指令支持。了解这些指令的功能有助于理解 V8 如何将高级的 JavaScript 代码转换为机器可以执行的指令。

### 提示词
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/macro-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
block_trampoline_pool(this);
  mfc1(t8, fs);
  Cvt_d_uw(fd, t8);
}

void MacroAssembler::Cvt_d_uw(FPURegister fd, Register rs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);

  // Convert rs to a FP value in fd.
  DCHECK(rs != t9);
  DCHECK(rs != at);

  // Zero extend int32 in rs.
  Dext(t9, rs, 0, 32);
  dmtc1(t9, fd);
  cvt_d_l(fd, fd);
}

void MacroAssembler::Cvt_d_ul(FPURegister fd, FPURegister fs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Move the data from fs to t8.
  dmfc1(t8, fs);
  Cvt_d_ul(fd, t8);
}

void MacroAssembler::Cvt_d_ul(FPURegister fd, Register rs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Convert rs to a FP value in fd.

  DCHECK(rs != t9);
  DCHECK(rs != at);

  Label msb_clear, conversion_done;

  Branch(&msb_clear, ge, rs, Operand(zero_reg));

  // Rs >= 2^63
  andi(t9, rs, 1);
  dsrl(rs, rs, 1);
  or_(t9, t9, rs);
  dmtc1(t9, fd);
  cvt_d_l(fd, fd);
  Branch(USE_DELAY_SLOT, &conversion_done);
  add_d(fd, fd, fd);  // In delay slot.

  bind(&msb_clear);
  // Rs < 2^63, we can do simple conversion.
  dmtc1(rs, fd);
  cvt_d_l(fd, fd);

  bind(&conversion_done);
}

void MacroAssembler::Cvt_s_uw(FPURegister fd, FPURegister fs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Move the data from fs to t8.
  mfc1(t8, fs);
  Cvt_s_uw(fd, t8);
}

void MacroAssembler::Cvt_s_uw(FPURegister fd, Register rs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Convert rs to a FP value in fd.
  DCHECK(rs != t9);
  DCHECK(rs != at);

  // Zero extend int32 in rs.
  Dext(t9, rs, 0, 32);
  dmtc1(t9, fd);
  cvt_s_l(fd, fd);
}

void MacroAssembler::Cvt_s_ul(FPURegister fd, FPURegister fs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Move the data from fs to t8.
  dmfc1(t8, fs);
  Cvt_s_ul(fd, t8);
}

void MacroAssembler::Cvt_s_ul(FPURegister fd, Register rs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Convert rs to a FP value in fd.

  DCHECK(rs != t9);
  DCHECK(rs != at);

  Label positive, conversion_done;

  Branch(&positive, ge, rs, Operand(zero_reg));

  // Rs >= 2^31.
  andi(t9, rs, 1);
  dsrl(rs, rs, 1);
  or_(t9, t9, rs);
  dmtc1(t9, fd);
  cvt_s_l(fd, fd);
  Branch(USE_DELAY_SLOT, &conversion_done);
  add_s(fd, fd, fd);  // In delay slot.

  bind(&positive);
  // Rs < 2^31, we can do simple conversion.
  dmtc1(rs, fd);
  cvt_s_l(fd, fd);

  bind(&conversion_done);
}

void MacroAssembler::Round_l_d(FPURegister fd, FPURegister fs) {
  round_l_d(fd, fs);
}

void MacroAssembler::Floor_l_d(FPURegister fd, FPURegister fs) {
  floor_l_d(fd, fs);
}

void MacroAssembler::Ceil_l_d(FPURegister fd, FPURegister fs) {
  ceil_l_d(fd, fs);
}

void MacroAssembler::Trunc_l_d(FPURegister fd, FPURegister fs) {
  trunc_l_d(fd, fs);
}

void MacroAssembler::Trunc_l_ud(FPURegister fd, FPURegister fs,
                                FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Load to GPR.
  dmfc1(t8, fs);
  // Reset sign bit.
  {
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x7FFFFFFFFFFFFFFF);
    and_(t8, t8, scratch1);
  }
  dmtc1(t8, fs);
  trunc_l_d(fd, fs);
}

void MacroAssembler::Trunc_uw_d(FPURegister fd, FPURegister fs,
                                FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Trunc_uw_d(t8, fs, scratch);
  mtc1(t8, fd);
}

void MacroAssembler::Trunc_uw_s(FPURegister fd, FPURegister fs,
                                FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Trunc_uw_s(t8, fs, scratch);
  mtc1(t8, fd);
}

void MacroAssembler::Trunc_ul_d(FPURegister fd, FPURegister fs,
                                FPURegister scratch, Register result) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Trunc_ul_d(t8, fs, scratch, result);
  dmtc1(t8, fd);
}

void MacroAssembler::Trunc_ul_s(FPURegister fd, FPURegister fs,
                                FPURegister scratch, Register result) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Trunc_ul_s(t8, fs, scratch, result);
  dmtc1(t8, fd);
}

void MacroAssembler::Trunc_w_d(FPURegister fd, FPURegister fs) {
  trunc_w_d(fd, fs);
}

void MacroAssembler::Round_w_d(FPURegister fd, FPURegister fs) {
  round_w_d(fd, fs);
}

void MacroAssembler::Floor_w_d(FPURegister fd, FPURegister fs) {
  floor_w_d(fd, fs);
}

void MacroAssembler::Ceil_w_d(FPURegister fd, FPURegister fs) {
  ceil_w_d(fd, fs);
}

void MacroAssembler::Trunc_uw_d(Register rd, FPURegister fs,
                                FPURegister scratch) {
  DCHECK(fs != scratch);
  DCHECK(rd != at);

  {
    // Load 2^32 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x41F00000);
    mtc1(zero_reg, scratch);
    mthc1(scratch1, scratch);
  }
  // Test if scratch > fd.
  // If fd < 2^32 we can convert it normally.
  Label simple_convert;
  CompareF64(ULT, fs, scratch);
  BranchTrueShortF(&simple_convert);

  // If fd > 2^32, the result should be UINT_32_MAX;
  Addu(rd, zero_reg, -1);

  Label done;
  Branch(&done);
  // Simple conversion.
  bind(&simple_convert);
  // Double -> Int64 -> Uint32;
  trunc_l_d(scratch, fs);
  mfc1(rd, scratch);

  bind(&done);
}

void MacroAssembler::Trunc_uw_s(Register rd, FPURegister fs,
                                FPURegister scratch) {
  DCHECK(fs != scratch);
  DCHECK(rd != at);

  {
    // Load 2^32 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x4F800000);
    mtc1(scratch1, scratch);
  }
  // Test if scratch > fs.
  // If fs < 2^32 we can convert it normally.
  Label simple_convert;
  CompareF32(ULT, fs, scratch);
  BranchTrueShortF(&simple_convert);

  // If fd > 2^32, the result should be UINT_32_MAX;
  Addu(rd, zero_reg, -1);

  Label done;
  Branch(&done);
  // Simple conversion.
  bind(&simple_convert);
  // Float -> Int64 -> Uint32;
  trunc_l_s(scratch, fs);
  mfc1(rd, scratch);

  bind(&done);
}

void MacroAssembler::Trunc_ul_d(Register rd, FPURegister fs,
                                FPURegister scratch, Register result) {
  DCHECK(fs != scratch);
  DCHECK(result.is_valid() ? !AreAliased(rd, result, at) : !AreAliased(rd, at));

  Label simple_convert, done, fail;
  if (result.is_valid()) {
    mov(result, zero_reg);
    Move(scratch, -1.0);
    // If fd =< -1 or unordered, then the conversion fails.
    CompareF64(ULE, fs, scratch);
    BranchTrueShortF(&fail);
  }

  // Load 2^63 into scratch as its double representation.
  li(at, 0x43E0000000000000);
  dmtc1(at, scratch);

  // Test if scratch > fs.
  // If fs < 2^63 or unordered, we can convert it normally.
  CompareF64(ULT, fs, scratch);
  BranchTrueShortF(&simple_convert);

  // First we subtract 2^63 from fs, then trunc it to rd
  // and add 2^63 to rd.
  sub_d(scratch, fs, scratch);
  trunc_l_d(scratch, scratch);
  dmfc1(rd, scratch);
  Or(rd, rd, Operand(1UL << 63));
  Branch(&done);

  // Simple conversion.
  bind(&simple_convert);
  trunc_l_d(scratch, fs);
  dmfc1(rd, scratch);

  bind(&done);
  if (result.is_valid()) {
    // Conversion is failed if the result is negative.
    {
      UseScratchRegisterScope temps(this);
      Register scratch1 = temps.Acquire();
      addiu(scratch1, zero_reg, -1);
      dsrl(scratch1, scratch1, 1);  // Load 2^62.
      dmfc1(result, scratch);
      xor_(result, result, scratch1);
    }
    Slt(result, zero_reg, result);
  }

  bind(&fail);
}

void MacroAssembler::Trunc_ul_s(Register rd, FPURegister fs,
                                FPURegister scratch, Register result) {
  DCHECK(fs != scratch);
  DCHECK(result.is_valid() ? !AreAliased(rd, result, at) : !AreAliased(rd, at));

  Label simple_convert, done, fail;
  if (result.is_valid()) {
    mov(result, zero_reg);
    Move(scratch, -1.0f);
    // If fd =< -1 or unordered, then the conversion fails.
    CompareF32(ULE, fs, scratch);
    BranchTrueShortF(&fail);
  }

  {
    // Load 2^63 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x5F000000);
    mtc1(scratch1, scratch);
  }

  // Test if scratch > fs.
  // If fs < 2^63 or unordered, we can convert it normally.
  CompareF32(ULT, fs, scratch);
  BranchTrueShortF(&simple_convert);

  // First we subtract 2^63 from fs, then trunc it to rd
  // and add 2^63 to rd.
  sub_s(scratch, fs, scratch);
  trunc_l_s(scratch, scratch);
  dmfc1(rd, scratch);
  Or(rd, rd, Operand(1UL << 63));
  Branch(&done);

  // Simple conversion.
  bind(&simple_convert);
  trunc_l_s(scratch, fs);
  dmfc1(rd, scratch);

  bind(&done);
  if (result.is_valid()) {
    // Conversion is failed if the result is negative or unordered.
    {
      UseScratchRegisterScope temps(this);
      Register scratch1 = temps.Acquire();
      addiu(scratch1, zero_reg, -1);
      dsrl(scratch1, scratch1, 1);  // Load 2^62.
      dmfc1(result, scratch);
      xor_(result, result, scratch1);
    }
    Slt(result, zero_reg, result);
  }

  bind(&fail);
}

template <typename RoundFunc>
void MacroAssembler::RoundDouble(FPURegister dst, FPURegister src,
                                 FPURoundingMode mode, RoundFunc round) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  if (kArchVariant == kMips64r6) {
    cfc1(scratch, FCSR);
    li(at, Operand(mode));
    ctc1(at, FCSR);
    rint_d(dst, src);
    ctc1(scratch, FCSR);
  } else {
    Label done;
    if (!IsDoubleZeroRegSet()) {
      Move(kDoubleRegZero, 0.0);
    }
    mfhc1(scratch, src);
    Ext(at, scratch, HeapNumber::kExponentShift, HeapNumber::kExponentBits);
    Branch(USE_DELAY_SLOT, &done, hs, at,
           Operand(HeapNumber::kExponentBias + HeapNumber::kMantissaBits));
    mov_d(dst, src);

    round(this, dst, src);
    dmfc1(at, dst);
    Branch(USE_DELAY_SLOT, &done, ne, at, Operand(zero_reg));
    cvt_d_l(dst, dst);
    srl(at, scratch, 31);
    sll(at, at, 31);
    mthc1(at, dst);
    bind(&done);
  }
}

void MacroAssembler::Floor_d_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_floor,
              [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
                masm->floor_l_d(dst, src);
              });
}

void MacroAssembler::Ceil_d_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_ceil,
              [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
                masm->ceil_l_d(dst, src);
              });
}

void MacroAssembler::Trunc_d_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_trunc,
              [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
                masm->trunc_l_d(dst, src);
              });
}

void MacroAssembler::Round_d_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_round,
              [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
                masm->round_l_d(dst, src);
              });
}

template <typename RoundFunc>
void MacroAssembler::RoundFloat(FPURegister dst, FPURegister src,
                                FPURoundingMode mode, RoundFunc round) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  if (kArchVariant == kMips64r6) {
    cfc1(scratch, FCSR);
    li(at, Operand(mode));
    ctc1(at, FCSR);
    rint_s(dst, src);
    ctc1(scratch, FCSR);
  } else {
    int32_t kFloat32ExponentBias = 127;
    int32_t kFloat32MantissaBits = 23;
    int32_t kFloat32ExponentBits = 8;
    Label done;
    if (!IsDoubleZeroRegSet()) {
      Move(kDoubleRegZero, 0.0);
    }
    mfc1(scratch, src);
    Ext(at, scratch, kFloat32MantissaBits, kFloat32ExponentBits);
    Branch(USE_DELAY_SLOT, &done, hs, at,
           Operand(kFloat32ExponentBias + kFloat32MantissaBits));
    mov_s(dst, src);

    round(this, dst, src);
    mfc1(at, dst);
    Branch(USE_DELAY_SLOT, &done, ne, at, Operand(zero_reg));
    cvt_s_w(dst, dst);
    srl(at, scratch, 31);
    sll(at, at, 31);
    mtc1(at, dst);
    bind(&done);
  }
}

void MacroAssembler::Floor_s_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_floor,
             [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
               masm->floor_w_s(dst, src);
             });
}

void MacroAssembler::Ceil_s_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_ceil,
             [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
               masm->ceil_w_s(dst, src);
             });
}

void MacroAssembler::Trunc_s_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_trunc,
             [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
               masm->trunc_w_s(dst, src);
             });
}

void MacroAssembler::Round_s_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_round,
             [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
               masm->round_w_s(dst, src);
             });
}

void MacroAssembler::LoadLane(MSASize sz, MSARegister dst, uint8_t laneidx,
                              MemOperand src) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  switch (sz) {
    case MSA_B:
      Lbu(scratch, src);
      insert_b(dst, laneidx, scratch);
      break;
    case MSA_H:
      Lhu(scratch, src);
      insert_h(dst, laneidx, scratch);
      break;
    case MSA_W:
      Lwu(scratch, src);
      insert_w(dst, laneidx, scratch);
      break;
    case MSA_D:
      Ld(scratch, src);
      insert_d(dst, laneidx, scratch);
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::StoreLane(MSASize sz, MSARegister src, uint8_t laneidx,
                               MemOperand dst) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  switch (sz) {
    case MSA_B:
      copy_u_b(scratch, src, laneidx);
      Sb(scratch, dst);
      break;
    case MSA_H:
      copy_u_h(scratch, src, laneidx);
      Sh(scratch, dst);
      break;
    case MSA_W:
      if (laneidx == 0) {
        FPURegister src_reg = FPURegister::from_code(src.code());
        Swc1(src_reg, dst);
      } else {
        copy_u_w(scratch, src, laneidx);
        Sw(scratch, dst);
      }
      break;
    case MSA_D:
      if (laneidx == 0) {
        FPURegister src_reg = FPURegister::from_code(src.code());
        Sdc1(src_reg, dst);
      } else {
        copy_s_d(scratch, src, laneidx);
        Sd(scratch, dst);
      }
      break;
    default:
      UNREACHABLE();
  }
}

#define EXT_MUL_BINOP(type, ilv_instr, dotp_instr)            \
  case type:                                                  \
    xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero); \
    ilv_instr(kSimd128ScratchReg, kSimd128RegZero, src1);     \
    ilv_instr(kSimd128RegZero, kSimd128RegZero, src2);        \
    dotp_instr(dst, kSimd128ScratchReg, kSimd128RegZero);     \
    break;

void MacroAssembler::ExtMulLow(MSADataType type, MSARegister dst,
                               MSARegister src1, MSARegister src2) {
  switch (type) {
    EXT_MUL_BINOP(MSAS8, ilvr_b, dotp_s_h)
    EXT_MUL_BINOP(MSAS16, ilvr_h, dotp_s_w)
    EXT_MUL_BINOP(MSAS32, ilvr_w, dotp_s_d)
    EXT_MUL_BINOP(MSAU8, ilvr_b, dotp_u_h)
    EXT_MUL_BINOP(MSAU16, ilvr_h, dotp_u_w)
    EXT_MUL_BINOP(MSAU32, ilvr_w, dotp_u_d)
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::ExtMulHigh(MSADataType type, MSARegister dst,
                                MSARegister src1, MSARegister src2) {
  switch (type) {
    EXT_MUL_BINOP(MSAS8, ilvl_b, dotp_s_h)
    EXT_MUL_BINOP(MSAS16, ilvl_h, dotp_s_w)
    EXT_MUL_BINOP(MSAS32, ilvl_w, dotp_s_d)
    EXT_MUL_BINOP(MSAU8, ilvl_b, dotp_u_h)
    EXT_MUL_BINOP(MSAU16, ilvl_h, dotp_u_w)
    EXT_MUL_BINOP(MSAU32, ilvl_w, dotp_u_d)
    default:
      UNREACHABLE();
  }
}
#undef EXT_MUL_BINOP

void MacroAssembler::LoadSplat(MSASize sz, MSARegister dst, MemOperand src) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  switch (sz) {
    case MSA_B:
      Lb(scratch, src);
      fill_b(dst, scratch);
      break;
    case MSA_H:
      Lh(scratch, src);
      fill_h(dst, scratch);
      break;
    case MSA_W:
      Lw(scratch, src);
      fill_w(dst, scratch);
      break;
    case MSA_D:
      Ld(scratch, src);
      fill_d(dst, scratch);
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::ExtAddPairwise(MSADataType type, MSARegister dst,
                                    MSARegister src) {
  switch (type) {
    case MSAS8:
      hadd_s_h(dst, src, src);
      break;
    case MSAU8:
      hadd_u_h(dst, src, src);
      break;
    case MSAS16:
      hadd_s_w(dst, src, src);
      break;
    case MSAU16:
      hadd_u_w(dst, src, src);
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::MSARoundW(MSARegister dst, MSARegister src,
                               FPURoundingMode mode) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  Register scratch2 = at;
  cfcmsa(scratch, MSACSR);
  if (mode == kRoundToNearest) {
    scratch2 = zero_reg;
  } else {
    li(scratch2, Operand(mode));
  }
  ctcmsa(MSACSR, scratch2);
  frint_w(dst, src);
  ctcmsa(MSACSR, scratch);
}

void MacroAssembler::MSARoundD(MSARegister dst, MSARegister src,
                               FPURoundingMode mode) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  Register scratch2 = at;
  cfcmsa(scratch, MSACSR);
  if (mode == kRoundToNearest) {
    scratch2 = zero_reg;
  } else {
    li(scratch2, Operand(mode));
  }
  ctcmsa(MSACSR, scratch2);
  frint_d(dst, src);
  ctcmsa(MSACSR, scratch);
}

void MacroAssembler::Madd_s(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft, FPURegister scratch) {
  DCHECK(fr != scratch && fs != scratch && ft != scratch);
  mul_s(scratch, fs, ft);
  add_s(fd, fr, scratch);
}

void MacroAssembler::Madd_d(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft, FPURegister scratch) {
  DCHECK(fr != scratch && fs != scratch && ft != scratch);
  mul_d(scratch, fs, ft);
  add_d(fd, fr, scratch);
}

void MacroAssembler::Msub_s(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft, FPURegister scratch) {
  DCHECK(fr != scratch && fs != scratch && ft != scratch);
  mul_s(scratch, fs, ft);
  sub_s(fd, scratch, fr);
}

void MacroAssembler::Msub_d(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft, FPURegister scratch) {
  DCHECK(fr != scratch && fs != scratch && ft != scratch);
  mul_d(scratch, fs, ft);
  sub_d(fd, scratch, fr);
}

void MacroAssembler::CompareF(SecondaryField sizeField, FPUCondition cc,
                              FPURegister cmp1, FPURegister cmp2) {
  if (kArchVariant == kMips64r6) {
    sizeField = sizeField == D ? L : W;
    DCHECK(cmp1 != kDoubleCompareReg && cmp2 != kDoubleCompareReg);
    cmp(cc, sizeField, kDoubleCompareReg, cmp1, cmp2);
  } else {
    c(cc, sizeField, cmp1, cmp2);
  }
}

void MacroAssembler::CompareIsNanF(SecondaryField sizeField, FPURegister cmp1,
                                   FPURegister cmp2) {
  CompareF(sizeField, UN, cmp1, cmp2);
}

void MacroAssembler::BranchTrueShortF(Label* target, BranchDelaySlot bd) {
  if (kArchVariant == kMips64r6) {
    bc1nez(target, kDoubleCompareReg);
  } else {
    bc1t(target);
  }
  if (bd == PROTECT) {
    nop();
  }
}

void MacroAssembler::BranchFalseShortF(Label* target, BranchDelaySlot bd) {
  if (kArchVariant == kMips64r6) {
    bc1eqz(target, kDoubleCompareReg);
  } else {
    bc1f(target);
  }
  if (bd == PROTECT) {
    nop();
  }
}

void MacroAssembler::BranchTrueF(Label* target, BranchDelaySlot bd) {
  bool long_branch =
      target->is_bound() ? !is_near(target) : is_trampoline_emitted();
  if (long_branch) {
    Label skip;
    BranchFalseShortF(&skip);
    BranchLong(target, bd);
    bind(&skip);
  } else {
    BranchTrueShortF(target, bd);
  }
}

void MacroAssembler::BranchFalseF(Label* target, BranchDelaySlot bd) {
  bool long_branch =
      target->is_bound() ? !is_near(target) : is_trampoline_emitted();
  if (long_branch) {
    Label skip;
    BranchTrueShortF(&skip);
    BranchLong(target, bd);
    bind(&skip);
  } else {
    BranchFalseShortF(target, bd);
  }
}

void MacroAssembler::BranchMSA(Label* target, MSABranchDF df,
                               MSABranchCondition cond, MSARegister wt,
                               BranchDelaySlot bd) {
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);

    if (target) {
      bool long_branch =
          target->is_bound() ? !is_near(target) : is_trampoline_emitted();
      if (long_branch) {
        Label skip;
        MSABranchCondition neg_cond = NegateMSABranchCondition(cond);
        BranchShortMSA(df, &skip, neg_cond, wt, bd);
        BranchLong(target, bd);
        bind(&skip);
      } else {
        BranchShortMSA(df, target, cond, wt, bd);
      }
    }
  }
}

void MacroAssembler::BranchShortMSA(MSABranchDF df, Label* target,
                                    MSABranchCondition cond, MSARegister wt,
                                    BranchDelaySlot bd) {
  if (IsEnabled(MIPS_SIMD)) {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    if (target) {
      switch (cond) {
        case all_not_zero:
          switch (df) {
            case MSA_BRANCH_D:
              bnz_d(wt, target);
              break;
            case MSA_BRANCH_W:
              bnz_w(wt, target);
              break;
            case MSA_BRANCH_H:
              bnz_h(wt, target);
              break;
            case MSA_BRANCH_B:
            default:
              bnz_b(wt, target);
          }
          break;
        case one_elem_not_zero:
          bnz_v(wt, target);
          break;
        case one_elem_zero:
          switch (df) {
            case MSA_BRANCH_D:
              bz_d(wt, target);
              break;
            case MSA_BRANCH_W:
              bz_w(wt, target);
              break;
            case MSA_BRANCH_H:
              bz_h(wt, target);
              break;
            case MSA_BRANCH_B:
            default:
              bz_b(wt, target);
          }
          break;
        case all_zero:
          bz_v(wt, target);
          break;
        default:
          UNREACHABLE();
      }
    }
  } else {
    UNREACHABLE();
  }
  if (bd == PROTECT) {
    nop();
  }
}

void MacroAssembler::FmoveLow(FPURegister dst, Register src_low) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  DCHECK(src_low != scratch);
  mfhc1(scratch, dst);
  mtc1(src_low, dst);
  mthc1(scratch, dst);
}

void MacroAssembler::Move(FPURegister dst, uint32_t src) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(static_cast<int32_t>(src)));
  mtc1(scratch, dst);
}

void MacroAssembler::Move(FPURegister dst, uint64_t src) {
  // Handle special values first.
  if (src == base::bit_cast<uint64_t>(0.0) && has_double_zero_reg_set_) {
    mov_d(dst, kDoubleRegZero);
  } else if (src == base::bit_cast<uint64_t>(-0.0) &&
             has_double_zero_reg_set_) {
    Neg_d(dst, kDoubleRegZero);
  } else {
    uint32_t lo = src & 0xFFFFFFFF;
    uint32_t hi = src >> 32;
    // Move the low part of the double into the lower of the corresponding FPU
    // register of FPU register pair.
    if (lo != 0) {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(lo));
      mtc1(scratch, dst);
    } else {
      mtc1(zero_reg, dst);
    }
    // Move the high part of the double into the higher of the corresponding FPU
    // register of FPU register pair.
    if (hi != 0) {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(hi));
      mthc1(scratch, dst);
    } else {
      mthc1(zero_reg, dst);
    }
    if (dst == kDoubleRegZero) has_double_zero_reg_set_ = true;
  }
}

void MacroAssembler::Movz(Register rd, Register rs, Register rt) {
  if (kArchVariant == kMips64r6) {
    Label done;
    Branch(&done, ne, rt, Operand(zero_reg));
    mov(rd, rs);
    bind(&done);
  } else {
    movz(rd, rs, rt);
  }
}

void MacroAssembler::Movn(Register rd, Register rs, Register rt) {
  if (kArchVariant == kMips64r6) {
    Label done;
    Branch(&done, eq, rt, Operand(zero_reg));
    mov(rd, rs);
    bind(&done);
  } else {
    movn(rd, rs, rt);
  }
}

void MacroAssembler::LoadZeroIfConditionNotZero(Register dest,
                                                Register condition) {
  if (kArchVariant == kMips64r6) {
    seleqz(dest, dest, condition);
  } else {
    Movn(dest, zero_reg, condition);
  }
}

void MacroAssembler::LoadZeroIfConditionZero(Register dest,
                                             Register condition) {
  if (kArchVariant == kMips64r6) {
    selnez(dest, dest, condition);
  } else {
    Movz(dest, zero_reg, condition);
  }
}

void MacroAssembler::LoadZeroIfFPUCondition(Register dest) {
  if (kArchVariant == kMips64r6) {
    dmfc1(kScratchReg, kDoubleCompareReg);
    LoadZeroIfConditionNotZero(dest, kScratchReg);
  } else {
    Movt(dest, zero_reg);
  }
}

void MacroAssembler::LoadZeroIfNotFPUCondition(Register dest) {
  if (kArchVariant == kMips64r6) {
    dmfc1(kScratchReg, kDoubleCompareReg);
    LoadZeroIfConditionZero(dest, kScratchReg);
  } else {
    Movf(dest, zero_reg);
  }
}

void MacroAssembler::Movt(Register rd, Register rs, uint16_t cc) {
  movt(rd, rs, cc);
}

void MacroAssembler::Movf(Register rd, Register rs, uint16_t cc) {
  movf(rd, rs, cc);
}

void MacroAssembler::Clz(Register rd, Register rs) { clz(rd, rs); }

void MacroAssembler::Dclz(Register rd, Register rs) { dclz(rd, rs); }

void MacroAssembler::Ctz(Register rd, Register rs) {
  if (kArchVariant == kMips64r6) {
    // We don't have an instruction to count the number of trailing zeroes.
    // Start by flipping the bits end-for-end so we can count the number of
    // leading zeroes instead.
    rotr(rd, rs, 16);
    wsbh(rd, rd);
    bitswap(rd, rd);
    Clz(rd, rd);
  } else {
    // Convert trailing zeroes to trailing ones, and bits to their left
    // to zeroes.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Daddu(scratch, rs, -1);
    Xor(rd, scratch, rs);
    And(rd, rd, scratch);
    // Count number of leading zeroes.
    Clz(rd, rd);
    // Subtract number of leading zeroes from 32 to get number of trailing
    // ones. Remember that the trailing ones were formerly trailing zeroes.
    li(scratch, 32);
    Subu(rd, scratch, rd);
  }
}

void MacroAssembler::Dctz(Register rd, Register rs) {
  if (kArchVariant == kMips64r6) {
    // We don't have an instruction to count the number of trailing zeroes.
    // Start by flipping the bits end-for-end so we can count the number of
    // leading zeroes instead.
    dsbh(rd, rs);
    dshd(rd, rd);
    dbitswap(rd, rd);
    dclz(rd, rd);
  } else {
    // Convert trailing zeroes to trailing ones, and bits to their left
    // to zeroes.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Daddu(scratch, rs, -1);
    Xor(rd, scratch, rs);
    And(rd, rd, scratch);
    // Count number of leading zeroes.
    dclz(rd, rd);
    // Subtract number of leading zeroes from 64 to get number of trailing
    // ones. Remember that the trailing ones were formerly trailing zeroes.
    li(scratch, 64);
    Dsubu(rd, scratch, rd);
  }
}

void MacroAssembler::Popcnt(Register rd, Register rs) {
  ASM_CODE_COMMENT(this);
  // https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
  //
  // A generalization of the best bit counting method to integers of
  // bit-widths up to 128 (parameterized by type T) is this:
  //
  // v = v - ((v >> 1) & (T)~(T)0/3);                           // temp
  // v = (v & (T)~(T)0/15*3) + ((v >> 2) & (T)~(T)0/15*3);      // temp
  // v = (v + (v >> 4)) & (T)~(T)0/255*15;                      // temp
  // c = (T)(v * ((T)~(T)0/255)) >> (sizeof(T) - 1) * BITS_PER_BYTE; //count
  //
  // For comparison, for 32-bit quantities, this algorithm can be executed
  // using 20 MIPS instructions (the calls to LoadConst32() generate two
  // machine instructions each for the values being used in this algorithm).
  // A(n unrolled) loop-based algorithm requires 25 instructions.
  //
  // For a 64-bit operand this can be performed in 24 instructions compared
  // to a(n unrolled) loop based algorithm which requires 38 instructions.
  //
  // There are algorithms which are faster in the cases where very few
  // bits are set but the algorithm here attempts to minimize the total
  // number of instructions executed even when a large number of bits
  // are set.
  uint32_t B0 = 0x55555555;     // (T)~(T)0/3
  uint32_t B1 = 0x33333333;     // (T)~(T)0/15*3
  uint32_t B2 = 0x0F0F0F0F;     // (T)~(T)0/255*15
  uint32_t value = 0x01010101;  // (T)~(T)0/255
  uint32_t shift = 24;          // (sizeof(T) - 1) * BITS_PER_BYTE

  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.Acquire();
  Register scratch2 = t8;
  srl(scratch, rs, 1);
  li(scratch2, B0);
  And(scratch, scratch, scratch2);
  Subu(scratch, rs, scratch);
  li(scratch2, B1);
  And(rd, scratch, scratch2);
  srl(scratch, scratch, 2);
  And(scratch, scratch, scratch2);
  Addu(scratch, rd, scratch);
  srl(rd, scratch, 4);
  Addu(rd, rd, scratch);
  li(scratch2, B2);
  And(rd, rd, scratch2);
  li(scratch, value);
  Mul(rd, rd, scratch);
  srl(rd, rd, shift);
}

void MacroAssembler::Dpopcnt(Register rd, Register rs) {
  ASM_CODE_COMMENT(this);
  uint64_t B0 = 0x5555555555555555l;     // (T)~(T)0/3
  uint64_t B1 = 0x3333333333333333l;     // (T)~(T)0/15*3
  uint64_t B2 = 0x0F0F0F0F0F0F0F0Fl;     // (T)~(T)0/255*15
  uint64_t value = 0x0101010101010101l;  // (T)~(T)0/255
  uint64_t shift = 24;                   // (sizeof(T) - 1) * BITS_PER_BYTE

  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.Acquire();
  Register scratch2 = t8;
  dsrl(scratch, rs, 1);
  li(scratch2, B0);
  And(scratch, scratch, scratch2);
  Dsubu(scratch, rs, scratch);
  li(scratch2, B1);
  And(rd, scratch, scratch2);
  dsrl(scratch, scratch, 2);
  And(scratch, scratch, scratch2);
  Daddu(scratch, rd, scratch);
  dsrl(rd, scratch, 4);
  Daddu(rd, rd, scratch);
  li(scratch2, B2);
  And(rd, rd, scratch2);
  li(scratch, value);
  Dmul(rd, rd, scratch);
  dsrl32(rd, rd, shift);
}

void MacroAssembler::TryInlineTruncateDoubleToI(Register result,
                                                DoubleRegister double_input,
                                                Label* done) {
  DoubleRegister single_scratch = kScratchDoubleReg.low();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t9;

  // Try a conversion to a signed integer.
  trunc_w_d(single_scratch, double_input);
  mfc1(result, single_scratch);
  // Retrieve the FCSR.
  cfc1(scratch, FCSR);
  // Check for overflow and NaNs.
  And(scratch, scratch,
      kFCSROverflowCauseMask | kFCSRUnderflowCauseMask |
          kFCSRInvalidOpCauseMask);
  // If we had no exceptions we are done.
  Branch(done, eq, scratch, Operand(zero_reg));
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode) {
  Label done;

  TryInlineTruncateDoubleToI(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub instead.
  push(ra);
  Dsubu(sp, sp, Operand(kDoubleSize));  // Put input on stack.
  Sdc1(double_input, MemOperand(sp, 0));

#if V8_ENABLE_WEBASSEMBLY
  if (stub_mode == StubCallMode::kCallWasmRuntimeStub) {
    Call(static_cast<Address>(Builtin::kDoubleToI), RelocInfo::WASM_STUB_CALL);
#else
  // For balance.
  if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    CallBuiltin(Builtin::kDoubleToI);
  }
  Ld(result, MemOperand(sp, 0));

  Daddu(sp, sp, Operand(kDoubleSize));
  pop(ra);

  bind(&done);
}

void MacroAssembler::CompareWord(Condition cond, Register dst, Register lhs,
                                 const Operand& rhs) {
  switch (cond) {
    case eq:
    case ne: {
      if (rhs.IsImmediate()) {
```