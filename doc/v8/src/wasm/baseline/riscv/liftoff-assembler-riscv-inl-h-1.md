Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of the V8 JavaScript engine and seems to implement WebAssembly SIMD (Single Instruction, Multiple Data) operations for the RISC-V architecture.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The code consists of numerous functions named `emit_...`. The names clearly indicate that these functions are responsible for emitting machine code instructions. The prefixes like `f32x4`, `i8x16`, `f64x2` strongly suggest that these instructions operate on SIMD vectors of different data types and sizes (e.g., four 32-bit floats, sixteen 8-bit integers, two 64-bit floats).

2. **Recognize the Architecture:** The filename `liftoff-assembler-riscv-inl.h` clearly states that this code is specific to the RISC-V architecture. The assembly instructions within the functions (like `vfwcvt_f_f_v`, `vfncvt_f_f_w`, `vmfeq_vv`, etc.) are RISC-V Vector Extension instructions.

3. **Infer the Purpose:**  Given that the code is within the `v8/src/wasm` directory and the function names align with WebAssembly SIMD opcodes, it's highly likely that this code is responsible for generating the low-level RISC-V assembly instructions required to execute WebAssembly SIMD operations. The "Liftoff" part of the filename likely refers to a specific code generation strategy within V8's WebAssembly implementation.

4. **Categorize the Operations:**  The functions can be broadly grouped by the data types they operate on and the type of operation they perform. Common categories include:
    * **Conversions:**  Functions like `emit_f64x2_convert_low_i32x4_s`, `emit_f32x4_demote_f64x2_zero` handle conversions between different SIMD vector types.
    * **Arithmetic Operations:**  Functions like `emit_i8x16_add`, `emit_f32x4_mul`, `emit_i64x2_sub` implement basic arithmetic operations.
    * **Bitwise Operations:** Functions like `emit_s128_and`, `emit_s128_not`, `emit_i8x16_shl` perform bitwise logical and shift operations.
    * **Comparison Operations:** Functions like `emit_f64x2_eq`, `emit_f64x2_lt` compare SIMD vectors.
    * **Other Operations:**  Functions like `emit_s128_const` load constants, `emit_s128_select` implement conditional selection, and `emit_v128_anytrue` and `emit_i8x16_alltrue` check conditions across vector elements.
    * **Reductions:**  Functions involving `vredminu_vs` perform reduction operations on the vector elements.

5. **Address Specific Questions:**
    * **`.tq` extension:** The code snippet is C++ (`.h`). The user correctly points out that a `.tq` extension would indicate Torque code. This snippet is not Torque.
    * **JavaScript relation:**  While the code is C++, it's used by the V8 engine to execute JavaScript (and in this case, WebAssembly). A JavaScript example would involve using WebAssembly SIMD features.
    * **Code Logic and Input/Output:** Each function implements a specific low-level operation. Providing a precise high-level input/output example is difficult without knowing the exact state of the registers before and after execution. However, the function names themselves provide a strong indication of the operation. For example, `emit_i8x16_add` takes two `i8x16` vectors as input and produces their element-wise sum as output.
    * **Common Programming Errors:** These functions deal with low-level SIMD instructions. Common errors at this level involve incorrect understanding of instruction semantics, incorrect register usage, and not handling edge cases (like NaN for floating-point operations).

6. **Synthesize the Summary:** Combine the observations from the previous steps into a concise summary. Highlight the core purpose, the target architecture, the types of operations supported, and the overall context within the V8 engine.

7. **Refine and Structure:** Organize the summary logically, using bullet points or headings to improve readability. Ensure that the language is clear and avoids excessive technical jargon. Address each of the user's specific points (file extension, JavaScript relation, etc.).

By following these steps, we can arrive at a comprehensive and accurate summary of the provided code snippet.
这是V8源代码文件 `v8/src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h` 的第二部分，延续了第一部分的内容，继续定义了 `LiftoffAssembler` 类中用于生成 RISC-V 汇编代码的成员函数，这些函数主要用于实现 WebAssembly 的 SIMD (Single Instruction, Multiple Data) 操作。

**功能归纳 (第2部分):**

这部分代码主要涵盖了以下 WebAssembly SIMD 指令在 RISC-V 架构上的具体实现：

* **浮点数类型转换和操作:**
    * `emit_f64x2_convert_low_i32x4_s/u`: 将 `i32x4` 向量的低位两个元素转换为 `f64x2` 向量。
    * `emit_f32x4_demote_f64x2_zero`: 将 `f64x2` 向量降级为 `f32x4`，高位两个元素置零。
    * `emit_i32x4_trunc_sat_f64x2_s/u_zero`: 将 `f64x2` 截断为有/无符号 `i32x4`，饱和处理，输入为零。
    * `emit_i32x4_relaxed_trunc_f32x4_s/u`:  宽松的将 `f32x4` 截断为有/无符号 `i32x4`。
    * `emit_i32x4_relaxed_trunc_f64x2_s/u_zero`: 宽松的将 `f64x2` 截断为有/无符号 `i32x4`，输入为零。
* **浮点数比较:**
    * `emit_f64x2_eq/ne/lt/le`:  比较两个 `f64x2` 向量是否相等、不等、小于、小于等于。结果是布尔向量。
* **128位向量的位运算:**
    * `emit_s128_const`: 加载 128 位常量到向量寄存器。
    * `emit_s128_not/and/or/xor`: 对 128 位向量执行按位取反、与、或、异或操作。
    * `emit_s128_and_not`: 对两个 128 位向量执行按位与非操作。
    * `emit_s128_select`: 根据掩码从两个 128 位向量中选择元素。
* **8位整数向量操作 (i8x16):**
    * `emit_i8x16_neg`: 取反。
    * `emit_v128_anytrue`: 判断向量中是否有任何元素为真。
    * `emit_i8x16_alltrue`: 判断向量中是否所有元素为真。
    * `emit_i8x16_bitmask`: 生成一个基于符号位的位掩码。
    * `emit_i8x16_shl/shli/shr_s/shri_s/shr_u/shri_u`:  左移、左移立即数、算术右移、算术右移立即数、逻辑右移、逻辑右移立即数。
    * `emit_i8x16_add/add_sat_s/add_sat_u`: 加法、饱和加法 (有符号和无符号)。
    * `emit_i8x16_sub/sub_sat_s/sub_sat_u`: 减法、饱和减法 (有符号和无符号)。
    * `emit_i8x16_min_s/min_u`: 取最小值 (有符号和无符号)。
    * `emit_i8x16_max_s/max_u`: 取最大值 (有符号和无符号)。
* **16位整数向量操作 (i16x8):**
    * `emit_i16x8_neg`: 取反。
    * `emit_i16x8_alltrue`: 判断向量中是否所有元素为真。
    * `emit_i16x8_bitmask`: 生成一个基于符号位的位掩码。
    * `emit_i16x8_shl/shli/shr_s/shri_s/shr_u/shri_u`:  移位操作。
    * `emit_i16x8_add/add_sat_s/add_sat_u`: 加法操作。
    * `emit_i16x8_sub/sub_sat_s/sub_sat_u`: 减法操作。
    * `emit_i16x8_mul`: 乘法。
    * `emit_i16x8_min_s/min_u`: 取最小值。
    * `emit_i16x8_max_s/max_u`: 取最大值。
* **32位整数向量操作 (i32x4):**
    * `emit_i32x4_neg`: 取反。
    * `emit_i32x4_alltrue`: 判断向量中是否所有元素为真。
    * `emit_i32x4_bitmask`: 生成位掩码。
    * `emit_i32x4_shl/shli/shr_s/shri_s/shr_u/shri_u`: 移位操作。
    * `emit_i32x4_add/sub/mul`: 加法、减法、乘法。
    * `emit_i32x4_min_s/min_u`: 取最小值。
    * `emit_i32x4_max_s/max_u`: 取最大值。
    * `emit_i32x4_dot_i16x8_s`: 计算 `i16x8` 的点积并累加到 `i32x4`。
    * `emit_i16x8_dot_i8x16_i7x16_s`:  计算 `i8x16` 和符号扩展的 `i7x16` 的点积得到 `i16x8`。
    * `emit_i32x4_dot_i8x16_i7x16_add_s`: 计算 `i8x16` 和符号扩展的 `i7x16` 的点积，并将结果加到累加器。
* **64位整数向量操作 (i64x2):**
    * `emit_i64x2_neg`: 取反。
    * `emit_i64x2_alltrue`: 判断是否全真。
    * `emit_i64x2_shl/shli/shr_s/shri_s/shr_u/shri_u`: 移位操作。
    * `emit_i64x2_add/sub/mul`: 加法、减法、乘法。
* **32位浮点数向量操作 (f32x4):**
    * `emit_f32x4_abs/neg/sqrt`: 绝对值、取反、平方根。
    * `emit_f32x4_ceil/floor/trunc/nearest_int`:  向上取整、向下取整、截断、四舍五入到最近的整数。
    * `emit_f32x4_add/sub/mul/div`: 加法、减法、乘法、除法。
    * `emit_f32x4_min/max`: 取最小值、最大值 (需要处理 NaN)。
    * `emit_f32x4_relaxed_min`: 宽松的最小值操作。

**关于文件类型和 JavaScript 关系:**

* 你是正确的，如果 `v8/src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h` 以 `.tq` 结尾，那它将是一个 V8 Torque 源代码文件。然而，`.h` 结尾表明它是一个 C++ 头文件，通常包含类和函数的声明和定义。
* 这个文件中的代码与 JavaScript 的功能有密切关系。WebAssembly 是一种可以在现代 Web 浏览器中运行的二进制指令格式。V8 引擎负责执行 WebAssembly 代码。当 JavaScript 代码调用 WebAssembly 模块中的 SIMD 函数时，V8 会使用 `LiftoffAssembler` 生成相应的 RISC-V 汇编指令来执行这些 SIMD 操作。

**JavaScript 示例 (概念性):**

虽然不能直接展示 `.h` 文件中 C++ 代码的 JavaScript 等价物，但可以展示一个概念性的 JavaScript 例子，它最终会触发这些 C++ 代码的执行：

```javascript
// 假设已经加载了一个 WebAssembly 模块，其中导出了一个名为 'add_f32x4' 的函数
const wasmModule = // ... 加载的 WebAssembly 模块 ...
const add_f32x4 = wasmModule.instance.exports.add_f32x4;

// 创建两个 Float32x4 类型的数组
const a = new Float32x4(1.0, 2.0, 3.0, 4.0);
const b = new Float32x4(5.0, 6.0, 7.0, 8.0);

// 调用 WebAssembly 函数
const result = add_f32x4(a, b);

// result 将会是一个 Float32x4 类型的数组，包含 a 和 b 的元素级加法结果
console.log(result); // 输出: Float32x4 { 6, 8, 10, 12 }
```

在这个例子中，当 JavaScript 调用 `add_f32x4` 函数时，V8 内部的 WebAssembly 执行流程会使用 `LiftoffAssembler`，特别是类似 `emit_f32x4_add` 这样的函数，来生成 RISC-V 汇编指令，从而在底层硬件上执行浮点数向量的加法运算。

**代码逻辑推理和假设输入/输出:**

以 `emit_i8x16_add` 函数为例：

```c++
void LiftoffAssembler::emit_i8x16_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vadd_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}
```

* **假设输入:**
    * `lhs` (LiftoffRegister):  对应 RISC-V 向量寄存器，其中存储了 16 个 8 位整数，例如 `[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]`。
    * `rhs` (LiftoffRegister):  对应 RISC-V 向量寄存器，其中存储了 16 个 8 位整数，例如 `[10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160]`。
* **代码逻辑:**
    1. `VU.set(kScratchReg, E8, m1);`: 设置向量单元的配置，指定操作的元素宽度为 8 位，使用 `m1` 的向量掩码（通常表示不进行掩码）。
    2. `vadd_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());`: 执行 RISC-V 向量加法指令，将 `lhs` 和 `rhs` 寄存器中的向量进行元素级的加法，结果存储到 `dst` 寄存器中。
* **预期输出:**
    * `dst` (LiftoffRegister): 对应的 RISC-V 向量寄存器将存储加法结果，例如 `[11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 121, 132, 143, 154, 165, 176]`。

**用户常见的编程错误 (在 WebAssembly 或使用 SIMD 时):**

虽然这个 `.h` 文件是底层的汇编代码生成器，但它所支持的 SIMD 操作在 WebAssembly 中使用时，容易出现以下编程错误：

1. **类型不匹配:**  WebAssembly 的类型系统是严格的。尝试将不兼容的 SIMD 类型进行操作会导致错误。例如，尝试将 `i32x4` 和 `f32x4` 直接相加。

2. **溢出和饱和问题:**  对于饱和算术指令 (`_sat_s`, `_sat_u`)，程序员需要理解饱和的概念。如果结果超出目标类型的表示范围，饱和算术会将其 clamp 到最大或最小值，而不是像普通算术那样发生溢出。不理解饱和算术的行为可能导致意想不到的结果。

   ```javascript
   // WebAssembly (假设有对应的 import)
   const a = new Int8x16Array([100, 100, ...]);
   const b = new Int8x16Array([50, 50, ...]);
   const result_add = wasm_i8x16_add(a, b); // 普通加法可能溢出
   const result_add_sat = wasm_i8x16_add_s(a, b); // 饱和加法会限制在 [-128, 127] 范围内
   ```

3. **位移操作的理解错误:** 需要正确理解逻辑位移和算术位移的区别，以及位移量的作用范围。例如，对于 8 位整数，位移量应该在 0-7 之间。

4. **NaN 的处理:**  浮点数运算中需要注意 NaN (Not a Number) 的传播行为。某些操作可能需要特殊处理 NaN 值。例如，`emit_f32x4_min` 和 `emit_f32x4_max` 函数中就包含了对 NaN 的处理逻辑。

5. **向量通道 (lane) 的错误访问:** 当使用 shuffle 或 extract 操作访问向量中的特定元素时，需要确保索引在有效范围内，否则会导致未定义的行为。

总之，`v8/src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h` 的第二部分继续定义了用于生成 RISC-V 汇编代码以支持 WebAssembly SIMD 操作的关键函数，涵盖了多种数据类型的向量运算，包括类型转换、算术运算、位运算和比较运算。这些底层的代码是 V8 引擎执行 WebAssembly SIMD 功能的基础。

### 提示词
```
这是目录为v8/src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
c.fp().toV()) {
    vfwcvt_f_f_v(dst.fp().toV(), src.fp().toV());
  } else {
    vfwcvt_f_f_v(kSimd128ScratchReg3, src.fp().toV());
    VU.set(kScratchReg, E64, m1);
    vmv_vv(dst.fp().toV(), kSimd128ScratchReg3);
  }
}

void LiftoffAssembler::emit_f32x4_demote_f64x2_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  VU.set(kScratchReg, E32, mf2);
  vfncvt_f_f_w(dst.fp().toV(), src.fp().toV());
  VU.set(kScratchReg, E32, m1);
  vmv_vi(v0, 12);
  vmerge_vx(dst.fp().toV(), zero_reg, dst.fp().toV());
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_s_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vmv_vx(kSimd128ScratchReg, zero_reg);
  vmfeq_vv(v0, src.fp().toV(), src.fp().toV());
  vmv_vv(kSimd128ScratchReg3, src.fp().toV());
  VU.set(kScratchReg, E32, m1);
  VU.set(FPURoundingMode::RTZ);
  vfncvt_x_f_w(kSimd128ScratchReg, kSimd128ScratchReg3, MaskType::Mask);
  vmv_vv(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_u_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vmv_vx(kSimd128ScratchReg, zero_reg);
  vmfeq_vv(v0, src.fp().toV(), src.fp().toV());
  vmv_vv(kSimd128ScratchReg3, src.fp().toV());
  VU.set(kScratchReg, E32, m1);
  VU.set(FPURoundingMode::RTZ);
  vfncvt_xu_f_w(kSimd128ScratchReg, kSimd128ScratchReg3, MaskType::Mask);
  vmv_vv(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_s(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  VU.set(FPURoundingMode::RTZ);
  VU.set(kScratchReg, E32, m1);
  vmfeq_vv(v0, src.fp().toV(), src.fp().toV());
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vmv_vx(dst.fp().toV(), zero_reg);
  vfcvt_x_f_v(dst.fp().toV(), kSimd128ScratchReg, MaskType::Mask);
}
void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_u(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  VU.set(FPURoundingMode::RTZ);
  VU.set(kScratchReg, E32, m1);
  vmfeq_vv(v0, src.fp().toV(), src.fp().toV());
  li(kScratchReg, Operand(-1));
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vmv_vx(dst.fp().toV(), kScratchReg);
  vfcvt_xu_f_v(dst.fp().toV(), kSimd128ScratchReg, MaskType::Mask);
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_s_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vmfeq_vv(v0, src.fp().toV(), src.fp().toV());

  VU.set(kScratchReg, E32, m1);
  VU.set(FPURoundingMode::RTZ);
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vmv_vx(dst.fp().toV(), zero_reg);
  vfncvt_x_f_w(dst.fp().toV(), kSimd128ScratchReg, MaskType::Mask);
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_u_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vmv_vv(kSimd128ScratchReg, v0);
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vmfeq_vv(v0, src.fp().toV(), src.fp().toV());
  VU.set(kScratchReg, E32, m1);
  VU.set(FPURoundingMode::RTZ);
  li(kScratchReg, Operand(-1));
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vmv_vx(dst.fp().toV(), zero_reg);
  vmerge_vx(dst.fp().toV(), kScratchReg, dst.fp().toV());
  vfncvt_xu_f_w(dst.fp().toV(), kSimd128ScratchReg, MaskType::Mask);
}

void LiftoffAssembler::emit_f64x2_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vmfeq_vv(v0, rhs.fp().toV(), lhs.fp().toV());
  vmv_vx(dst.fp().toV(), zero_reg);
  vmerge_vi(dst.fp().toV(), -1, dst.fp().toV());
}

void LiftoffAssembler::emit_f64x2_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vmfne_vv(v0, rhs.fp().toV(), lhs.fp().toV());
  vmv_vx(dst.fp().toV(), zero_reg);
  vmerge_vi(dst.fp().toV(), -1, dst.fp().toV());
}

void LiftoffAssembler::emit_f64x2_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vmflt_vv(v0, lhs.fp().toV(), rhs.fp().toV());
  vmv_vx(dst.fp().toV(), zero_reg);
  vmerge_vi(dst.fp().toV(), -1, dst.fp().toV());
}

void LiftoffAssembler::emit_f64x2_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vmfle_vv(v0, lhs.fp().toV(), rhs.fp().toV());
  vmv_vx(dst.fp().toV(), zero_reg);
  vmerge_vi(dst.fp().toV(), -1, dst.fp().toV());
}

void LiftoffAssembler::emit_s128_const(LiftoffRegister dst,
                                       const uint8_t imms[16]) {
  WasmRvvS128const(dst.fp().toV(), imms);
}

void LiftoffAssembler::emit_s128_not(LiftoffRegister dst, LiftoffRegister src) {
  VU.set(kScratchReg, E8, m1);
  vnot_vv(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_s128_and(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vand_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_s128_or(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vor_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_s128_xor(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vxor_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_s128_and_not(LiftoffRegister dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vnot_vv(kSimd128ScratchReg, rhs.fp().toV());
  vand_vv(dst.fp().toV(), lhs.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_s128_select(LiftoffRegister dst,
                                        LiftoffRegister src1,
                                        LiftoffRegister src2,
                                        LiftoffRegister mask) {
  VU.set(kScratchReg, E8, m1);
  vand_vv(kSimd128ScratchReg, src1.fp().toV(), mask.fp().toV());
  vnot_vv(kSimd128ScratchReg2, mask.fp().toV());
  vand_vv(kSimd128ScratchReg2, src2.fp().toV(), kSimd128ScratchReg2);
  vor_vv(dst.fp().toV(), kSimd128ScratchReg, kSimd128ScratchReg2);
}

void LiftoffAssembler::emit_i8x16_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E8, m1);
  vneg_vv(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_v128_anytrue(LiftoffRegister dst,
                                         LiftoffRegister src) {
  VU.set(kScratchReg, E8, m1);
  Label t;
  vmv_sx(kSimd128ScratchReg, zero_reg);
  vredmaxu_vs(kSimd128ScratchReg, src.fp().toV(), kSimd128ScratchReg);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
  beq(dst.gp(), zero_reg, &t);
  li(dst.gp(), 1);
  bind(&t);
}

void LiftoffAssembler::emit_i8x16_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  VU.set(kScratchReg, E8, m1);
  Label notalltrue;
  vmv_vi(kSimd128ScratchReg, -1);
  vredminu_vs(kSimd128ScratchReg, src.fp().toV(), kSimd128ScratchReg);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
  beqz(dst.gp(), &notalltrue);
  li(dst.gp(), 1);
  bind(&notalltrue);
}

void LiftoffAssembler::emit_i8x16_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  VU.set(kScratchReg, E8, m1);
  vmv_vx(kSimd128RegZero, zero_reg);
  vmv_vx(kSimd128ScratchReg, zero_reg);
  vmslt_vv(kSimd128ScratchReg, src.fp().toV(), kSimd128RegZero);
  VU.set(kScratchReg, E32, m1);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i8x16_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  andi(rhs.gp(), rhs.gp(), 8 - 1);
  vsll_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i8x16_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  DCHECK(is_uint5(rhs));
  VU.set(kScratchReg, E8, m1);
  vsll_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 8);
}

void LiftoffAssembler::emit_i8x16_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  andi(rhs.gp(), rhs.gp(), 8 - 1);
  vsra_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i8x16_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  VU.set(kScratchReg, E8, m1);
  vsra_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 8);
}

void LiftoffAssembler::emit_i8x16_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  andi(rhs.gp(), rhs.gp(), 8 - 1);
  vsrl_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i8x16_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  VU.set(kScratchReg, E8, m1);
  vsrl_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 8);
}

void LiftoffAssembler::emit_i8x16_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vadd_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i8x16_add_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vsadd_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i8x16_add_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vsaddu_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i8x16_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vsub_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i8x16_sub_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vssub_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i8x16_sub_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vssubu_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i8x16_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vmin_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i8x16_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vminu_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i8x16_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vmax_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i8x16_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vmaxu_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E16, m1);
  vneg_vv(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_i16x8_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  VU.set(kScratchReg, E16, m1);
  Label notalltrue;
  vmv_vi(kSimd128ScratchReg, -1);
  vredminu_vs(kSimd128ScratchReg, src.fp().toV(), kSimd128ScratchReg);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
  beqz(dst.gp(), &notalltrue);
  li(dst.gp(), 1);
  bind(&notalltrue);
}

void LiftoffAssembler::emit_i16x8_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  VU.set(kScratchReg, E16, m1);
  vmv_vx(kSimd128RegZero, zero_reg);
  vmv_vx(kSimd128ScratchReg, zero_reg);
  vmslt_vv(kSimd128ScratchReg, src.fp().toV(), kSimd128RegZero);
  VU.set(kScratchReg, E32, m1);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i16x8_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  andi(rhs.gp(), rhs.gp(), 16 - 1);
  vsll_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i16x8_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  VU.set(kScratchReg, E16, m1);
  vsll_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 16);
}

void LiftoffAssembler::emit_i16x8_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  andi(rhs.gp(), rhs.gp(), 16 - 1);
  vsra_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i16x8_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  VU.set(kScratchReg, E16, m1);
  vsra_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 16);
}

void LiftoffAssembler::emit_i16x8_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  andi(rhs.gp(), rhs.gp(), 16 - 1);
  vsrl_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i16x8_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  DCHECK(is_uint5(rhs));
  VU.set(kScratchReg, E16, m1);
  vsrl_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 16);
}

void LiftoffAssembler::emit_i16x8_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vadd_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_add_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vsadd_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_add_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vsaddu_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vsub_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_sub_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vssub_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_sub_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vssubu_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vmul_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vmin_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vminu_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vmax_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i16x8_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vmaxu_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i32x4_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  vneg_vv(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_i32x4_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  Label notalltrue;
  vmv_vi(kSimd128ScratchReg, -1);
  vredminu_vs(kSimd128ScratchReg, src.fp().toV(), kSimd128ScratchReg);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
  beqz(dst.gp(), &notalltrue);
  li(dst.gp(), 1);
  bind(&notalltrue);
}

void LiftoffAssembler::emit_i32x4_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  vmv_vx(kSimd128RegZero, zero_reg);
  vmv_vx(kSimd128ScratchReg, zero_reg);
  vmslt_vv(kSimd128ScratchReg, src.fp().toV(), kSimd128RegZero);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32x4_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  andi(rhs.gp(), rhs.gp(), 32 - 1);
  vsll_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i32x4_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  if (is_uint5(rhs % 32)) {
    vsll_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 32);
  } else {
    li(kScratchReg, rhs % 32);
    vsll_vx(dst.fp().toV(), lhs.fp().toV(), kScratchReg);
  }
}

void LiftoffAssembler::emit_i32x4_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  andi(rhs.gp(), rhs.gp(), 32 - 1);
  vsra_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i32x4_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  VU.set(kScratchReg, E32, m1);
  if (is_uint5(rhs % 32)) {
    vsra_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 32);
  } else {
    li(kScratchReg, rhs % 32);
    vsra_vx(dst.fp().toV(), lhs.fp().toV(), kScratchReg);
  }
}

void LiftoffAssembler::emit_i32x4_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  andi(rhs.gp(), rhs.gp(), 32 - 1);
  vsrl_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i32x4_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  VU.set(kScratchReg, E32, m1);
  if (is_uint5(rhs % 32)) {
    vsrl_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 32);
  } else {
    li(kScratchReg, rhs % 32);
    vsrl_vx(dst.fp().toV(), lhs.fp().toV(), kScratchReg);
  }
}

void LiftoffAssembler::emit_i32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vadd_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i32x4_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vsub_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i32x4_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vmul_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i32x4_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vmin_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i32x4_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vminu_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i32x4_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vmax_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i32x4_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vmaxu_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i32x4_dot_i16x8_s(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vwmul_vv(kSimd128ScratchReg3, lhs.fp().toV(), rhs.fp().toV());
  VU.set(kScratchReg, E32, m2);
  li(kScratchReg, 0b01010101);
  vmv_sx(v0, kScratchReg);
  vcompress_vv(kSimd128ScratchReg, kSimd128ScratchReg3, v0);

  li(kScratchReg, 0b10101010);
  vmv_sx(kSimd128ScratchReg2, kScratchReg);
  vcompress_vv(v0, kSimd128ScratchReg3, kSimd128ScratchReg2);
  VU.set(kScratchReg, E32, m1);
  vadd_vv(dst.fp().toV(), kSimd128ScratchReg, v0);
}

void LiftoffAssembler::emit_i16x8_dot_i8x16_i7x16_s(LiftoffRegister dst,
                                                    LiftoffRegister lhs,
                                                    LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vwmul_vv(kSimd128ScratchReg3, lhs.fp().toV(), rhs.fp().toV());
  VU.set(kScratchReg, E16, m2);

  constexpr int32_t FIRST_INDEX = 0b0101010101010101;
  constexpr int32_t SECOND_INDEX = 0b1010101010101010;
  li(kScratchReg, FIRST_INDEX);
  vmv_sx(v0, kScratchReg);
  vcompress_vv(kSimd128ScratchReg, kSimd128ScratchReg3, v0);

  li(kScratchReg, SECOND_INDEX);
  vmv_sx(kSimd128ScratchReg2, kScratchReg);
  vcompress_vv(v0, kSimd128ScratchReg3, kSimd128ScratchReg2);
  VU.set(kScratchReg, E16, m1);
  vadd_vv(dst.fp().toV(), kSimd128ScratchReg, v0);
}

void LiftoffAssembler::emit_i32x4_dot_i8x16_i7x16_add_s(LiftoffRegister dst,
                                                        LiftoffRegister lhs,
                                                        LiftoffRegister rhs,
                                                        LiftoffRegister acc) {
  DCHECK_NE(dst, acc);
  VU.set(kScratchReg, E8, m1);
  VRegister intermediate = kSimd128ScratchReg3;
  VRegister kSimd128ScratchReg4 =
      GetUnusedRegister(LiftoffRegList{LiftoffRegister(ft10)}).fp().toV();
  vwmul_vv(intermediate, lhs.fp().toV(), rhs.fp().toV());  // i16*16 v8 v9

  constexpr int32_t FIRST_INDEX = 0b0001000100010001;
  constexpr int32_t SECOND_INDEX = 0b0010001000100010;
  constexpr int32_t THIRD_INDEX = 0b0100010001000100;
  constexpr int32_t FOURTH_INDEX = 0b1000100010001000;

  VU.set(kScratchReg, E16, m2);
  li(kScratchReg, FIRST_INDEX);
  vmv_sx(v0, kScratchReg);
  vcompress_vv(kSimd128ScratchReg, intermediate, v0);  // i16*4 a
  li(kScratchReg, SECOND_INDEX);
  vmv_sx(kSimd128ScratchReg2, kScratchReg);
  vcompress_vv(v0, intermediate, kSimd128ScratchReg2);  // i16*4 b

  VU.set(kScratchReg, E16, m1);
  vwadd_vv(kSimd128ScratchReg4, kSimd128ScratchReg, v0);  // i32*4 c

  VU.set(kScratchReg, E16, m2);
  li(kScratchReg, THIRD_INDEX);
  vmv_sx(v0, kScratchReg);
  vcompress_vv(kSimd128ScratchReg, intermediate, v0);  // i16*4 a

  li(kScratchReg, FOURTH_INDEX);
  vmv_sx(kSimd128ScratchReg2, kScratchReg);
  vcompress_vv(v0, intermediate, kSimd128ScratchReg2);  // i16*4 b

  VU.set(kScratchReg, E16, m1);
  vwadd_vv(kSimd128ScratchReg3, kSimd128ScratchReg, v0);  // i32*4 c

  VU.set(kScratchReg, E32, m1);
  vadd_vv(dst.fp().toV(), kSimd128ScratchReg4, kSimd128ScratchReg3);
  vadd_vv(dst.fp().toV(), dst.fp().toV(), acc.fp().toV());
}

void LiftoffAssembler::emit_i64x2_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vneg_vv(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_i64x2_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  Label notalltrue;
  vmv_vi(kSimd128ScratchReg, -1);
  vredminu_vs(kSimd128ScratchReg, src.fp().toV(), kSimd128ScratchReg);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
  beqz(dst.gp(), &notalltrue);
  li(dst.gp(), 1);
  bind(&notalltrue);
}

void LiftoffAssembler::emit_i64x2_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  andi(rhs.gp(), rhs.gp(), 64 - 1);
  vsll_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i64x2_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  VU.set(kScratchReg, E64, m1);
  if (is_uint5(rhs % 64)) {
    vsll_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 64);
  } else {
    li(kScratchReg, rhs % 64);
    vsll_vx(dst.fp().toV(), lhs.fp().toV(), kScratchReg);
  }
}

void LiftoffAssembler::emit_i64x2_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  andi(rhs.gp(), rhs.gp(), 64 - 1);
  vsra_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i64x2_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  VU.set(kScratchReg, E64, m1);
  if (is_uint5(rhs % 64)) {
    vsra_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 64);
  } else {
    li(kScratchReg, rhs % 64);
    vsra_vx(dst.fp().toV(), lhs.fp().toV(), kScratchReg);
  }
}

void LiftoffAssembler::emit_i64x2_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  andi(rhs.gp(), rhs.gp(), 64 - 1);
  vsrl_vx(dst.fp().toV(), lhs.fp().toV(), rhs.gp());
}

void LiftoffAssembler::emit_i64x2_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  VU.set(kScratchReg, E64, m1);
  if (is_uint5(rhs % 64)) {
    vsrl_vi(dst.fp().toV(), lhs.fp().toV(), rhs % 64);
  } else {
    li(kScratchReg, rhs % 64);
    vsrl_vx(dst.fp().toV(), lhs.fp().toV(), kScratchReg);
  }
}

void LiftoffAssembler::emit_i64x2_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vadd_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i64x2_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vsub_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_i64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vmul_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_f32x4_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  vfabs_vv(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_f32x4_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  vfneg_vv(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_f32x4_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  vfsqrt_v(dst.fp().toV(), src.fp().toV());
}

bool LiftoffAssembler::emit_f32x4_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  Ceil_f(dst.fp().toV(), src.fp().toV(), kScratchReg, kSimd128ScratchReg);
  return true;
}

bool LiftoffAssembler::emit_f32x4_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Floor_f(dst.fp().toV(), src.fp().toV(), kScratchReg, kSimd128ScratchReg);
  return true;
}

bool LiftoffAssembler::emit_f32x4_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Trunc_f(dst.fp().toV(), src.fp().toV(), kScratchReg, kSimd128ScratchReg);
  return true;
}

bool LiftoffAssembler::emit_f32x4_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  Round_f(dst.fp().toV(), src.fp().toV(), kScratchReg, kSimd128ScratchReg);
  return true;
}

void LiftoffAssembler::emit_f32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vfadd_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_f32x4_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vfsub_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_f32x4_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  VU.set(FPURoundingMode::RTZ);
  vfmul_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_f32x4_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vfdiv_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_f32x4_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  const int32_t kNaN = 0x7FC00000;
  VU.set(kScratchReg, E32, m1);
  vmfeq_vv(v0, lhs.fp().toV(), lhs.fp().toV());
  vmfeq_vv(kSimd128ScratchReg, rhs.fp().toV(), rhs.fp().toV());
  vand_vv(v0, v0, kSimd128ScratchReg);
  li(kScratchReg, kNaN);
  vmv_vx(kSimd128ScratchReg, kScratchReg);
  vfmin_vv(kSimd128ScratchReg, rhs.fp().toV(), lhs.fp().toV(), Mask);
  vmv_vv(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_f32x4_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  const int32_t kNaN = 0x7FC00000;
  VU.set(kScratchReg, E32, m1);
  vmfeq_vv(v0, lhs.fp().toV(), lhs.fp().toV());
  vmfeq_vv(kSimd128ScratchReg, rhs.fp().toV(), rhs.fp().toV());
  vand_vv(v0, v0, kSimd128ScratchReg);
  li(kScratchReg, kNaN);
  vmv_vx(kSimd128ScratchReg, kScratchReg);
  vfmax_vv(kSimd128ScratchReg, rhs.fp().toV(), lhs.fp().toV(), Mask);
  vmv_vv(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_f32x4_relaxed_min(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  VU
```