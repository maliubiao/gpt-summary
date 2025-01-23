Response:
The user wants a summary of the provided C++ code snippet from `v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h`.

Here's a breakdown of the request and how to address it:

1. **List the functions:** Identify all the `emit_` prefixed functions in the code.
2. **Determine functionality:**  Analyze each function's name and the ARM64 assembly instructions it uses to understand its purpose. The names generally follow a pattern like `emit_<wasm_type>_<operation>`.
3. **Check for Torque:** The filename ends in `.h`, not `.tq`, so it's not a Torque file.
4. **JavaScript relation:** Determine if the operations performed by the functions have direct equivalents in JavaScript, particularly in the context of WebAssembly. SIMD operations are a key area to consider.
5. **Illustrate with JavaScript:** If a connection exists, provide a JavaScript example using WebAssembly's JavaScript API.
6. **Code logic reasoning:** For functions with non-trivial logic (like `emit_i64x2_mul`), explain the process with an example. Provide input values and the expected output.
7. **Common programming errors:** Identify potential pitfalls developers might encounter when using the WebAssembly instructions these functions implement.
8. **Summarize the functionality:**  Provide a concise overview of the code's role.
9. **Part of a series:** Acknowledge that this is part 4 of 5.

**Mental Sandbox:**

* **Function Identification:**  Scanning for `emit_` is straightforward.
* **Functionality Mapping:** The function names are quite descriptive, pointing to specific WebAssembly SIMD (Single Instruction, Multiple Data) operations. The ARM assembly instructions further confirm this (e.g., `Add`, `Sub`, `Mul`, `Shl`, `Cmeq`, etc. operating on vector registers like `VnD`).
* **Torque Check:**  Simple filename check.
* **JavaScript Connection:**  These functions relate directly to WebAssembly's SIMD instructions, which have corresponding JavaScript API methods.
* **JavaScript Example:**  Need to construct a basic example using `WebAssembly.Module`, `WebAssembly.Instance`, and typed arrays to demonstrate the SIMD operations.
* **Logic Reasoning (for `emit_i64x2_mul`):** This function implements 64-bit integer vector multiplication. Need to pick sample 64-bit integer pairs and trace the calculation steps. The comments within the code provide valuable insights into the algorithm.
* **Common Errors:** Think about common mistakes when working with SIMD, like incorrect lane indices, type mismatches, or misunderstanding saturation behavior.
* **Summary:** Focus on the core purpose: generating ARM64 assembly code for WebAssembly SIMD operations within the Liftoff compiler.
* **Part of a series:** Simply note the context.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h以.tq结尾，那它是个v8 torque源代码: Yes
* 如果它与javascript的功能有关系，请用javascript举例说明: Yes
* 如果有代码逻辑推理，请给出假设输入与输出: Yes (for the more complex function)
* 如果涉及用户常见的编程错误，请举例说明: Yes
* 这是第4部分，共5部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

Strategizing complete. Proceeding with response generation.
目录 `v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h` 是 V8 引擎中 Liftoff 编译器的 ARM64 架构后端的一部分。这个头文件定义了 `LiftoffAssembler` 类的一些内联函数，这些函数用于生成 ARM64 汇编代码，以实现 WebAssembly 的各种操作，特别是 SIMD (Single Instruction, Multiple Data) 操作。

**功能列举:**

这个头文件中的函数主要负责为以下 WebAssembly SIMD 指令生成 ARM64 汇编代码：

* **i64x2 类型操作:**
    * 加法 (`emit_i64x2_add`)
    * 减法 (`emit_i64x2_sub`)
    * 乘法 (`emit_i64x2_mul`)
    * 扩展乘法（低位和高位）(`emit_i64x2_extmul_low_i32x4_s/u`, `emit_i64x2_extmul_high_i32x4_s/u`)
    * 位掩码 (`emit_i64x2_bitmask`)
    * 类型转换 (`emit_i64x2_sconvert_i32x4_low/high`, `emit_i64x2_uconvert_i32x4_low/high`)
    * 相等比较 (`emit_i64x2_eq`)
    * 不等比较 (`emit_i64x2_ne`)
    * 大于比较（有符号）(`emit_i64x2_gt_s`)
    * 大于等于比较（有符号）(`emit_i64x2_ge_s`)

* **i32x4 类型操作:**
    * 创建 (`emit_i32x4_splat`)
    * 提取通道 (`emit_i32x4_extract_lane`)
    * 替换通道 (`emit_i32x4_replace_lane`)
    * 取反 (`emit_i32x4_neg`)
    * 所有位为真判断 (`emit_i32x4_alltrue`)
    * 位掩码 (`emit_i32x4_bitmask`)
    * 左移 (`emit_i32x4_shl`, `emit_i32x4_shli`)
    * 右移（有符号和无符号） (`emit_i32x4_shr_s/u`, `emit_i32x4_shri_s/u`)
    * 加法 (`emit_i32x4_add`)
    * 减法 (`emit_i32x4_sub`)
    * 乘法 (`emit_i32x4_mul`)
    * 最小值（有符号和无符号） (`emit_i32x4_min_s/u`)
    * 最大值（有符号和无符号） (`emit_i32x4_max_s/u`)
    * 点积 (`emit_i32x4_dot_i16x8_s`)
    * 扩展加法 (`emit_i32x4_extadd_pairwise_i16x8_s/u`)
    * 扩展乘法（低位和高位） (`emit_i32x4_extmul_low_i16x8_s/u`, `emit_i32x4_extmul_high_i16x8_s/u`)
    * 相等比较 (`emit_i32x4_eq`)
    * 不等比较 (`emit_i32x4_ne`)
    * 大于比较（有符号和无符号） (`emit_i32x4_gt_s/u`)
    * 大于等于比较（有符号和无符号） (`emit_i32x4_ge_s/u`)
    * 类型转换（浮点转整数） (`emit_i32x4_sconvert_f32x4`, `emit_i32x4_uconvert_f32x4`)

* **i16x8 类型操作:**
    * 创建 (`emit_i16x8_splat`)
    * 提取通道 (`emit_i16x8_extract_lane_u/s`)
    * 替换通道 (`emit_i16x8_replace_lane`)
    * 取反 (`emit_i16x8_neg`)
    * 所有位为真判断 (`emit_i16x8_alltrue`)
    * 位掩码 (`emit_i16x8_bitmask`)
    * 左移 (`emit_i16x8_shl`, `emit_i16x8_shli`)
    * 右移（有符号和无符号） (`emit_i16x8_shr_s/u`, `emit_i16x8_shri_s/u`)
    * 加法 (`emit_i16x8_add`, `emit_i16x8_add_sat_s/u`)
    * 减法 (`emit_i16x8_sub`, `emit_i16x8_sub_sat_s/u`)
    * 乘法 (`emit_i16x8_mul`)
    * 最小值（有符号和无符号） (`emit_i16x8_min_s/u`)
    * 最大值（有符号和无符号） (`emit_i16x8_max_s/u`)
    * 相等比较 (`emit_i16x8_eq`)
    * 不等比较 (`emit_i16x8_ne`)
    * 大于比较（有符号和无符号） (`emit_i16x8_gt_s/u`)
    * 大于等于比较（有符号和无符号） (`emit_i16x8_ge_s/u`)

* **i8x16 类型操作:**
    * 混洗 (`emit_i8x16_shuffle`)
    * 统计设置位 (`emit_i8x16_popcnt`)
    * 创建 (`emit_i8x16_splat`)
    * 提取通道 (`emit_i8x16_extract_lane_u/s`)
    * 替换通道 (`emit_i8x16_replace_lane`)
    * 取反 (`emit_i8x16_neg`)
    * 任意位为真判断 (`emit_v128_anytrue`)
    * 所有位为真判断 (`emit_i8x16_alltrue`)
    * 位掩码 (`emit_i8x16_bitmask`)
    * 左移 (`emit_i8x16_shl`, `emit_i8x16_shli`)
    * 右移（有符号和无符号） (`emit_i8x16_shr_s/u`, `emit_i8x16_shri_s/u`)
    * 加法 (`emit_i8x16_add`, `emit_i8x16_add_sat_s/u`)
    * 减法 (`emit_i8x16_sub`, `emit_i8x16_sub_sat_s/u`)
    * 最小值（有符号和无符号） (`emit_i8x16_min_s/u`)
    * 最大值（有符号和无符号） (`emit_i8x16_max_s/u`)
    * 相等比较 (`emit_i8x16_eq`)
    * 不等比较 (`emit_i8x16_ne`)
    * 大于比较（有符号和无符号） (`emit_i8x16_gt_s/u`)
    * 大于等于比较（有符号和无符号） (`emit_i8x16_ge_s/u`)

* **f32x4 类型操作:**
    * 相等比较 (`emit_f32x4_eq`)
    * 不等比较 (`emit_f32x4_ne`)
    * 小于比较 (`emit_f32x4_lt`)
    * 小于等于比较 (`emit_f32x4_le`)
    * 类型转换（整数转浮点） (`emit_f32x4_sconvert_i32x4`, `emit_f32x4_uconvert_i32x4`)
    * 类型转换 (f64x2 降级为 f32x4) (`emit_f32x4_demote_f64x2_zero`)

* **f64x2 类型操作:**
    * 相等比较 (`emit_f64x2_eq`)
    * 不等比较 (`emit_f64x2_ne`)
    * 小于比较 (`emit_f64x2_lt`)
    * 小于等于比较 (`emit_f64x2_le`)

* **v128 类型操作:**
    * 加载常量 (`emit_s128_const`)
    * 按位取反 (`emit_s128_not`)
    * 按位与 (`emit_s128_and`)
    * 按位或 (`emit_s128_or`)
    * 按位异或 (`emit_s128_xor`)
    * 选择 (`emit_s128_select`)

* **类型转换:**
    * `emit_i8x16_sconvert_i16x8`

**关于文件类型:**

`v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h` 以 `.h` 结尾，这是一个标准的 C++ 头文件。如果它以 `.tq` 结尾，那它将是一个 V8 Torque 源代码文件。Torque 是一种用于编写 V8 内部代码的领域特定语言。

**与 JavaScript 的关系:**

这些函数生成的汇编代码直接对应于 WebAssembly 的 SIMD 指令集。WebAssembly 允许 JavaScript 代码创建和操作 SIMD 值，从而利用 CPU 的并行处理能力。

**JavaScript 示例:**

```javascript
const buffer = new Uint8Array([
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // i32x4 value: [0, 1, 0, 0]
  0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00  // i32x4 value: [2, 3, 0, 0]
]);

const wasmModule = new WebAssembly.Module(Uint8Array.from([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x07, 0x01, 0x60, 0x00, 0x01, 0x7b,
  0x03, 0x02, 0x01, 0x00,
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0xfd, 0x0b, 0x0b, // i32x4.add
  0x00, 0x00, 0x00, 0x00
]));

const wasmInstance = new WebAssembly.Instance(wasmModule, { /* imports */ });

// 假设 WebAssembly 模块导出一个函数，该函数执行 i32x4 加法
const add_i32x4 = wasmInstance.exports.add_i32x4;

// 创建两个 i32x4 值 (在 WebAssembly 内部)
// 这里只是概念性的，实际操作需要通过 WebAssembly 的内存和指令

// 在 JavaScript 中模拟 i32x4 加法 (与 wasm 中的操作对应)
const lane0_a = buffer.getInt32(0, true);
const lane1_a = buffer.getInt32(4, true);
const lane2_a = buffer.getInt32(8, true);
const lane3_a = buffer.getInt32(12, true);

const lane0_b = buffer.getInt32(16, true);
const lane1_b = buffer.getInt32(20, true);
const lane2_b = buffer.getInt32(24, true);
const lane3_b = buffer.getInt32(28, true);

const result_lane0 = lane0_a + lane0_b;
const result_lane1 = lane1_a + lane1_b;
const result_lane2 = lane2_a + lane2_b;
const result_lane3 = lane3_a + lane3_b;

console.log([result_lane0, result_lane1, result_lane2, result_lane3]); // 输出: [2, 4, 0, 0]

// 实际上，WebAssembly 的执行会使用 LiftoffAssembler 生成的 ARM64 代码
// 来高效地执行这些 SIMD 操作。
```

在这个例子中，`emit_i32x4_add` 函数会生成 ARM64 汇编指令，例如 `ADD Vd.4S, Vn.4S, Vm.4S`，其中 `Vd`、`Vn` 和 `Vm` 是 SIMD 寄存器，用于执行四个 32 位整数的并行加法。

**代码逻辑推理 (以 `emit_i64x2_mul` 为例):**

假设输入两个 `i64x2` 向量 `lhs` 和 `rhs`，其内部 64 位整数分别为 `(a, b)` 和 `(c, d)`。`emit_i64x2_mul` 函数旨在计算按元素相乘的结果 `(a * c, b * d)`。由于 ARM64 架构的限制，直接进行两个 64 位整数的并行乘法可能需要多个步骤。

**假设输入:**

* `lhs`: 包含两个 64 位整数，例如 `a = 5`, `b = 10`
* `rhs`: 包含两个 64 位整数，例如 `c = 2`, `d = 3`

**内部步骤 (根据代码注释):**

1. `Xtn(tmp1.V2S(), lhs.fp().V2D())`: 将 `lhs` 的两个 64 位整数截断为两个 32 位整数，存储到 `tmp1`。假设 `tmp1` 包含 `(5_low, 10_low)`。
2. `Xtn(tmp2.V2S(), rhs.fp().V2D())`: 将 `rhs` 的两个 64 位整数截断为两个 32 位整数，存储到 `tmp2`。假设 `tmp2` 包含 `(2_low, 3_low)`。
3. `Umull(tmp1.V2D(), tmp1.V2S(), tmp2.V2S())`: 执行无符号乘法，将 `tmp1` 和 `tmp2` 的低 32 位部分相乘，结果存储到 `tmp1`。`tmp1` 现在包含 `(5_low * 2_low, 10_low * 3_low)`，这对应于结果的低 64 位部分。
4. `Rev64(tmp2.V4S(), rhs.fp().V4S())`: 反转 `rhs` 中每 64 位的数据的字节顺序。
5. `Mul(tmp2.V4S(), tmp2.V4S(), lhs.fp().V4S())`: 将反转后的 `rhs` 与 `lhs` 相乘。
6. `Addp(tmp2.V4S(), tmp2.V4S(), tmp2.V4S())`:  成对相加 `tmp2` 中的元素。
7. `Shll(dst.fp().V2D(), tmp2.V2S(), 32)`: 将 `tmp2` 的低 64 位部分左移 32 位，准备存放结果的高 64 位。
8. `Add(dst.fp().V2D(), dst.fp().V2D(), tmp1.V2D())`: 将低 64 位部分 (`tmp1`) 加到 `dst` 中，完成乘法运算。

**预期输出:**

* `dst`: 包含两个 64 位整数，分别为 `5 * 2 = 10` 和 `10 * 3 = 30`。

**用户常见的编程错误:**

* **类型不匹配:**  尝试将不兼容类型的 SIMD 值进行运算，例如将 `i32x4` 和 `f32x4` 直接相加。WebAssembly 的类型系统会阻止这种操作，但在手动编写汇编或理解底层实现时容易出错。
* **通道索引错误:** 在提取或替换 SIMD 向量的通道时，使用超出范围的索引会导致未定义的行为或错误的结果。例如，对 `i32x4` 使用索引 4 或更大的值。
* **对饱和运算的误解:**  饱和运算 (如 `emit_i16x8_add_sat_s`) 在结果超出表示范围时会截断到最大或最小值，而不是溢出。不理解这种行为可能导致意外的结果。
    * **示例:** 如果两个 `i16x8` 向量的对应元素相加超过 `int16_t` 的最大值 (32767)，使用 `emit_i16x8_add` 会发生溢出，而 `emit_i16x8_add_sat_s` 会将结果钳制为 32767。
* **位移量错误:**  SIMD 位移指令的位移量通常有范围限制。例如，`i8x16` 的位移量通常在 0-7 之间。使用超出范围的位移量会导致未定义的行为。

**归纳一下它的功能 (作为第 4 部分):**

作为 Liftoff 编译器 ARM64 后端的关键组成部分，`v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h` 中定义的内联函数负责将 WebAssembly 的 SIMD 操作转化为高效的 ARM64 汇编代码。这部分代码专注于为各种整型和浮点型 SIMD 指令生成代码，包括算术运算、位操作、比较运算、类型转换等。它的主要目标是提供一个低级的接口，供 Liftoff 编译器的其他部分调用，以构建最终的可执行 WebAssembly 代码。这部分的功能是代码生成过程中的核心环节，直接影响 WebAssembly 在 ARM64 架构上的执行性能。

### 提示词
```
这是目录为v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
hs,
                                      LiftoffRegister rhs) {
  Add(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_i64x2_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Sub(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_i64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  UseScratchRegisterScope temps(this);
  VRegister tmp1 = temps.AcquireV(kFormat2D);
  VRegister tmp2 = temps.AcquireV(kFormat2D);

  // Algorithm copied from code-generator-arm64.cc with minor modifications:
  // - 2 (max number of scratch registers in Liftoff) temporaries instead of 3
  // - 1 more Umull instruction to calculate | cg | ae |,
  // - so, we can no longer use Umlal in the last step, and use Add instead.
  // Refer to comments there for details.
  Xtn(tmp1.V2S(), lhs.fp().V2D());
  Xtn(tmp2.V2S(), rhs.fp().V2D());
  Umull(tmp1.V2D(), tmp1.V2S(), tmp2.V2S());
  Rev64(tmp2.V4S(), rhs.fp().V4S());
  Mul(tmp2.V4S(), tmp2.V4S(), lhs.fp().V4S());
  Addp(tmp2.V4S(), tmp2.V4S(), tmp2.V4S());
  Shll(dst.fp().V2D(), tmp2.V2S(), 32);
  Add(dst.fp().V2D(), dst.fp().V2D(), tmp1.V2D());
}

void LiftoffAssembler::emit_i64x2_extmul_low_i32x4_s(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  Smull(dst.fp().V2D(), src1.fp().V2S(), src2.fp().V2S());
}

void LiftoffAssembler::emit_i64x2_extmul_low_i32x4_u(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  Umull(dst.fp().V2D(), src1.fp().V2S(), src2.fp().V2S());
}

void LiftoffAssembler::emit_i64x2_extmul_high_i32x4_s(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  Smull2(dst.fp().V2D(), src1.fp().V4S(), src2.fp().V4S());
}

void LiftoffAssembler::emit_i64x2_extmul_high_i32x4_u(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  Umull2(dst.fp().V2D(), src1.fp().V4S(), src2.fp().V4S());
}

void LiftoffAssembler::emit_i64x2_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I64x2BitMask(dst.gp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_sconvert_i32x4_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  Sxtl(dst.fp().V2D(), src.fp().V2S());
}

void LiftoffAssembler::emit_i64x2_sconvert_i32x4_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  Sxtl2(dst.fp().V2D(), src.fp().V4S());
}

void LiftoffAssembler::emit_i64x2_uconvert_i32x4_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  Uxtl(dst.fp().V2D(), src.fp().V2S());
}

void LiftoffAssembler::emit_i64x2_uconvert_i32x4_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  Uxtl2(dst.fp().V2D(), src.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Dup(dst.fp().V4S(), src.gp().W());
}

void LiftoffAssembler::emit_i32x4_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  Mov(dst.gp().W(), lhs.fp().V4S(), imm_lane_idx);
}

void LiftoffAssembler::emit_i32x4_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (dst != src1) {
    Mov(dst.fp().V4S(), src1.fp().V4S());
  }
  Mov(dst.fp().V4S(), imm_lane_idx, src2.gp().W());
}

void LiftoffAssembler::emit_i32x4_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Neg(dst.fp().V4S(), src.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  liftoff::EmitAllTrue(this, dst, src, kFormat4S);
}

void LiftoffAssembler::emit_i32x4_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I32x4BitMask(dst.gp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kLeft>(
      this, dst.fp().V4S(), lhs.fp().V4S(), rhs.gp(), kFormat4S);
}

void LiftoffAssembler::emit_i32x4_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  Shl(dst.fp().V4S(), lhs.fp().V4S(), rhs & 31);
}

void LiftoffAssembler::emit_i32x4_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kRight,
                         liftoff::ShiftSign::kSigned>(
      this, dst.fp().V4S(), lhs.fp().V4S(), rhs.gp(), kFormat4S);
}

void LiftoffAssembler::emit_i32x4_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftRightImmediate<kFormat4S, liftoff::ShiftSign::kSigned>(
      this, dst.fp().V4S(), lhs.fp().V4S(), rhs);
}

void LiftoffAssembler::emit_i32x4_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kRight,
                         liftoff::ShiftSign::kUnsigned>(
      this, dst.fp().V4S(), lhs.fp().V4S(), rhs.gp(), kFormat4S);
}

void LiftoffAssembler::emit_i32x4_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftRightImmediate<kFormat4S,
                                       liftoff::ShiftSign::kUnsigned>(
      this, dst.fp().V4S(), lhs.fp().V4S(), rhs);
}

void LiftoffAssembler::emit_i32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Add(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Sub(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Mul(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Smin(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Umin(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Smax(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Umax(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_dot_i16x8_s(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  UseScratchRegisterScope scope(this);
  VRegister tmp1 = scope.AcquireV(kFormat4S);
  VRegister tmp2 = scope.AcquireV(kFormat4S);
  Smull(tmp1, lhs.fp().V4H(), rhs.fp().V4H());
  Smull2(tmp2, lhs.fp().V8H(), rhs.fp().V8H());
  Addp(dst.fp().V4S(), tmp1, tmp2);
}

void LiftoffAssembler::emit_i32x4_extadd_pairwise_i16x8_s(LiftoffRegister dst,
                                                          LiftoffRegister src) {
  Saddlp(dst.fp().V4S(), src.fp().V8H());
}

void LiftoffAssembler::emit_i32x4_extadd_pairwise_i16x8_u(LiftoffRegister dst,
                                                          LiftoffRegister src) {
  Uaddlp(dst.fp().V4S(), src.fp().V8H());
}

void LiftoffAssembler::emit_i32x4_extmul_low_i16x8_s(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  Smull(dst.fp().V4S(), src1.fp().V4H(), src2.fp().V4H());
}

void LiftoffAssembler::emit_i32x4_extmul_low_i16x8_u(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  Umull(dst.fp().V4S(), src1.fp().V4H(), src2.fp().V4H());
}

void LiftoffAssembler::emit_i32x4_extmul_high_i16x8_s(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  Smull2(dst.fp().V4S(), src1.fp().V8H(), src2.fp().V8H());
}

void LiftoffAssembler::emit_i32x4_extmul_high_i16x8_u(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  Umull2(dst.fp().V4S(), src1.fp().V8H(), src2.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Dup(dst.fp().V8H(), src.gp().W());
}

void LiftoffAssembler::emit_i16x8_extract_lane_u(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  Umov(dst.gp().W(), lhs.fp().V8H(), imm_lane_idx);
}

void LiftoffAssembler::emit_i16x8_extract_lane_s(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  Smov(dst.gp().W(), lhs.fp().V8H(), imm_lane_idx);
}

void LiftoffAssembler::emit_i16x8_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (dst != src1) {
    Mov(dst.fp().V8H(), src1.fp().V8H());
  }
  Mov(dst.fp().V8H(), imm_lane_idx, src2.gp().W());
}

void LiftoffAssembler::emit_i16x8_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Neg(dst.fp().V8H(), src.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  liftoff::EmitAllTrue(this, dst, src, kFormat8H);
}

void LiftoffAssembler::emit_i16x8_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I16x8BitMask(dst.gp(), src.fp());
}

void LiftoffAssembler::emit_i16x8_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kLeft>(
      this, dst.fp().V8H(), lhs.fp().V8H(), rhs.gp(), kFormat8H);
}

void LiftoffAssembler::emit_i16x8_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  Shl(dst.fp().V8H(), lhs.fp().V8H(), rhs & 15);
}

void LiftoffAssembler::emit_i16x8_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kRight,
                         liftoff::ShiftSign::kSigned>(
      this, dst.fp().V8H(), lhs.fp().V8H(), rhs.gp(), kFormat8H);
}

void LiftoffAssembler::emit_i16x8_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftRightImmediate<kFormat8H, liftoff::ShiftSign::kSigned>(
      this, dst.fp().V8H(), lhs.fp().V8H(), rhs);
}

void LiftoffAssembler::emit_i16x8_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kRight,
                         liftoff::ShiftSign::kUnsigned>(
      this, dst.fp().V8H(), lhs.fp().V8H(), rhs.gp(), kFormat8H);
}

void LiftoffAssembler::emit_i16x8_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftRightImmediate<kFormat8H,
                                       liftoff::ShiftSign::kUnsigned>(
      this, dst.fp().V8H(), lhs.fp().V8H(), rhs);
}

void LiftoffAssembler::emit_i16x8_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Add(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_add_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  Sqadd(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Sub(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_sub_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  Sqsub(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_sub_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  Uqsub(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Mul(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_add_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  Uqadd(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Smin(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Umin(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Smax(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Umax(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i8x16_shuffle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs,
                                          const uint8_t shuffle[16],
                                          bool is_swizzle) {
  VRegister src1 = lhs.fp();
  VRegister src2 = rhs.fp();
  VRegister temp = dst.fp();
  if (dst == lhs || dst == rhs) {
    // dst overlaps with lhs or rhs, so we need a temporary.
    temp = GetUnusedRegister(kFpReg, LiftoffRegList{lhs, rhs}).fp();
  }

  UseScratchRegisterScope scope(this);

  if (src1 != src2 && !AreConsecutive(src1, src2)) {
    // Tbl needs consecutive registers, which our scratch registers are.
    src1 = scope.AcquireV(kFormat16B);
    src2 = scope.AcquireV(kFormat16B);
    DCHECK(AreConsecutive(src1, src2));
    Mov(src1.Q(), lhs.fp().Q());
    Mov(src2.Q(), rhs.fp().Q());
  }

  int64_t imms[2] = {0, 0};
  for (int i = 7; i >= 0; i--) {
    imms[0] = (imms[0] << 8) | (shuffle[i]);
    imms[1] = (imms[1] << 8) | (shuffle[i + 8]);
  }
  DCHECK_EQ(0, (imms[0] | imms[1]) &
                   (lhs == rhs ? 0xF0F0F0F0F0F0F0F0 : 0xE0E0E0E0E0E0E0E0));

  Movi(temp.V16B(), imms[1], imms[0]);

  if (src1 == src2) {
    Tbl(dst.fp().V16B(), src1.V16B(), temp.V16B());
  } else {
    Tbl(dst.fp().V16B(), src1.V16B(), src2.V16B(), temp.V16B());
  }
}

void LiftoffAssembler::emit_i8x16_popcnt(LiftoffRegister dst,
                                         LiftoffRegister src) {
  Cnt(dst.fp().V16B(), src.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Dup(dst.fp().V16B(), src.gp().W());
}

void LiftoffAssembler::emit_i8x16_extract_lane_u(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  Umov(dst.gp().W(), lhs.fp().V16B(), imm_lane_idx);
}

void LiftoffAssembler::emit_i8x16_extract_lane_s(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  Smov(dst.gp().W(), lhs.fp().V16B(), imm_lane_idx);
}

void LiftoffAssembler::emit_i8x16_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (dst != src1) {
    Mov(dst.fp().V16B(), src1.fp().V16B());
  }
  Mov(dst.fp().V16B(), imm_lane_idx, src2.gp().W());
}

void LiftoffAssembler::emit_i8x16_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Neg(dst.fp().V16B(), src.fp().V16B());
}

void LiftoffAssembler::emit_v128_anytrue(LiftoffRegister dst,
                                         LiftoffRegister src) {
  liftoff::EmitAnyTrue(this, dst, src);
}

void LiftoffAssembler::emit_i8x16_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  liftoff::EmitAllTrue(this, dst, src, kFormat16B);
}

void LiftoffAssembler::emit_i8x16_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  VRegister temp = NoVReg;

  if (CpuFeatures::IsSupported(PMULL1Q)) {
    temp = GetUnusedRegister(kFpReg, LiftoffRegList{src}).fp();
  }

  I8x16BitMask(dst.gp(), src.fp(), temp);
}

void LiftoffAssembler::emit_i8x16_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kLeft>(
      this, dst.fp().V16B(), lhs.fp().V16B(), rhs.gp(), kFormat16B);
}

void LiftoffAssembler::emit_i8x16_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  Shl(dst.fp().V16B(), lhs.fp().V16B(), rhs & 7);
}

void LiftoffAssembler::emit_i8x16_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kRight,
                         liftoff::ShiftSign::kSigned>(
      this, dst.fp().V16B(), lhs.fp().V16B(), rhs.gp(), kFormat16B);
}

void LiftoffAssembler::emit_i8x16_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftRightImmediate<kFormat16B, liftoff::ShiftSign::kSigned>(
      this, dst.fp().V16B(), lhs.fp().V16B(), rhs);
}

void LiftoffAssembler::emit_i8x16_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kRight,
                         liftoff::ShiftSign::kUnsigned>(
      this, dst.fp().V16B(), lhs.fp().V16B(), rhs.gp(), kFormat16B);
}

void LiftoffAssembler::emit_i8x16_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftRightImmediate<kFormat16B,
                                       liftoff::ShiftSign::kUnsigned>(
      this, dst.fp().V16B(), lhs.fp().V16B(), rhs);
}

void LiftoffAssembler::emit_i8x16_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Add(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_add_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  Sqadd(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Sub(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_sub_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  Sqsub(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_sub_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  Uqsub(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_add_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  Uqadd(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Smin(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Umin(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Smax(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Umax(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Cmeq(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Cmeq(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
  Mvn(dst.fp().V16B(), dst.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmgt(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmhi(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmge(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmhs(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i16x8_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Cmeq(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Cmeq(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
  Mvn(dst.fp().V8H(), dst.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmgt(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmhi(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmge(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i16x8_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmhs(dst.fp().V8H(), lhs.fp().V8H(), rhs.fp().V8H());
}

void LiftoffAssembler::emit_i32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Cmeq(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Cmeq(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
  Mvn(dst.fp().V4S(), dst.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmgt(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmhi(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmge(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmhs(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_i64x2_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Cmeq(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_i64x2_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Cmeq(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
  Mvn(dst.fp().V2D(), dst.fp().V2D());
}

void LiftoffAssembler::emit_i64x2_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmgt(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_i64x2_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  Cmge(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_f32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Fcmeq(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Fcmeq(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
  Mvn(dst.fp().V4S(), dst.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Fcmgt(dst.fp().V4S(), rhs.fp().V4S(), lhs.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Fcmge(dst.fp().V4S(), rhs.fp().V4S(), lhs.fp().V4S());
}

void LiftoffAssembler::emit_f64x2_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Fcmeq(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Fcmeq(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
  Mvn(dst.fp().V2D(), dst.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Fcmgt(dst.fp().V2D(), rhs.fp().V2D(), lhs.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Fcmge(dst.fp().V2D(), rhs.fp().V2D(), lhs.fp().V2D());
}

void LiftoffAssembler::emit_s128_const(LiftoffRegister dst,
                                       const uint8_t imms[16]) {
  uint64_t vals[2];
  memcpy(vals, imms, sizeof(vals));
  Movi(dst.fp().V16B(), vals[1], vals[0]);
}

void LiftoffAssembler::emit_s128_not(LiftoffRegister dst, LiftoffRegister src) {
  Mvn(dst.fp().V16B(), src.fp().V16B());
}

void LiftoffAssembler::emit_s128_and(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  And(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_s128_or(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  Orr(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_s128_xor(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  Eor(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_s128_select(LiftoffRegister dst,
                                        LiftoffRegister src1,
                                        LiftoffRegister src2,
                                        LiftoffRegister mask) {
  if (dst != mask) {
    Mov(dst.fp().V16B(), mask.fp().V16B());
  }
  Bsl(dst.fp().V16B(), src1.fp().V16B(), src2.fp().V16B());
}

void LiftoffAssembler::emit_i32x4_sconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  Fcvtzs(dst.fp().V4S(), src.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_uconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  Fcvtzu(dst.fp().V4S(), src.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  Scvtf(dst.fp().V4S(), src.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  Ucvtf(dst.fp().V4S(), src.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_demote_f64x2_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  Fcvtn(dst.fp().V2S(), src.fp().V2D());
}

void LiftoffAssembler::emit_i8x16_sconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  UseScratchRegisterScope temps(this);
  VRegister tmp = temps.AcquireV(kFormat8H);
  VRegister right = rhs.fp().V8H();
  if (dst == rhs) {
    Mov(tmp, right);
    right = tmp;
  }
  Sqxtn(dst.fp().V8B(), lhs.fp().V8H());
```