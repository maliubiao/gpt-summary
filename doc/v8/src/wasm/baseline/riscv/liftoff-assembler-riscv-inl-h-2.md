Response:
The user wants a summary of the provided C++ code snippet.
The code is part of the V8 JavaScript engine, specifically for the WebAssembly baseline compiler on the RISC-V architecture.
The file `liftoff-assembler-riscv-inl.h` seems to contain inline implementations of methods for the `LiftoffAssembler` class.
These methods appear to generate RISC-V assembly instructions for various WebAssembly operations.

Let's break down the functionality:

1. **SIMD Operations:** A significant portion of the code deals with SIMD (Single Instruction, Multiple Data) operations for different data types (f32x4, f64x2, i8x16, i16x8, i32x4). These operations include:
    - Arithmetic: add, sub, mul, div
    - Comparison: relaxed min/max, pmin/pmax
    - Conversions: between integer and floating-point types, between different integer sizes
    - Other: abs, neg, sqrt, ceil, floor, trunc, nearest_int, rounding average
    - Lane manipulation: extract, replace
    - Fused Multiply-Add/Subtract (QFMA/QFMS)

2. **Stack Management:** Methods like `StackCheck`, `PushRegisters`, `PopRegisters`, `AllocateStackSlot`, `DeallocateStackSlot`. These handle managing the function call stack.

3. **Function Calls:** `CallNativeWasmCode`, `TailCallNativeWasmCode`, `CallIndirect`, `TailCallIndirect`, `CallBuiltin`. These functions generate instructions for calling other functions (native or WebAssembly).

4. **Control Flow:** `AssertUnreachable`.

5. **Frame Setup:** `CallFrameSetupStub` for setting up the call frame.

6. **Conditional Operations:** `emit_set_if_nan`, `emit_s128_set_if_nan`. These handle setting a value based on whether a floating-point number is NaN.

7. **F16x8 (Half-precision float) Support:**  While most SIMD operations are implemented, there are placeholder functions returning `false` for `f16x8`, indicating that these operations might not be fully supported or implemented in this specific part of the codebase.

Regarding the user's specific questions:

- **`.tq` extension:** The file ends in `.h`, so it's a standard C++ header file, not a Torque file.
- **Relationship with JavaScript:** These functions are used internally by V8 when executing WebAssembly code within a JavaScript environment. WebAssembly can be seen as a low-level compilation target for languages like C++ or Rust, and JavaScript engines like V8 can execute this compiled code.
- **Code logic and I/O:** The code primarily generates assembly instructions. The "input" is the desired WebAssembly operation and the "output" is the corresponding RISC-V assembly code.
- **Common programming errors:** While this code is low-level, incorrect usage could lead to issues like stack overflow (if stack management is faulty) or incorrect computation due to wrong assembly sequences.

The overall function of this file is to provide the low-level building blocks for the Liftoff compiler to translate WebAssembly operations into efficient RISC-V machine code.
这是V8源代码文件 `v8/src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h` 的第三部分，它延续了第一部分和第二部分的功能，主要负责定义 `LiftoffAssembler` 类的内联方法，用于生成 RISC-V 架构上的汇编指令，以实现 WebAssembly 的各种操作。

**归纳其功能如下：**

1. **扩展的浮点 SIMD (Single Instruction, Multiple Data) 操作支持:**  该部分继续定义了用于处理 128 位浮点向量的操作，包括：
   - **`f64x2` (双精度浮点数向量):**  绝对值 (`emit_f64x2_abs`)、取反 (`emit_f64x2_neg`)、平方根 (`emit_f64x2_sqrt`)、向上取整 (`emit_f64x2_ceil`)、向下取整 (`emit_f64x2_floor`)、截断 (`emit_f64x2_trunc`)、四舍五入到最近的整数 (`emit_f64x2_nearest_int`)、加法 (`emit_f64x2_add`)、减法 (`emit_f64x2_sub`)、乘法 (`emit_f64x2_mul`)、除法 (`emit_f64x2_div`)、宽松的最小值 (`emit_f64x2_relaxed_min`)、宽松的最大值 (`emit_f64x2_relaxed_max`)、按位最小值 (`emit_f64x2_pmin`)、按位最大值 (`emit_f64x2_pmax`)。

2. **整型和浮点型之间的 SIMD 数据转换:** 定义了在不同 SIMD 数据类型之间进行转换的指令：
   - `i32x4` 和 `f32x4` 之间的有符号和无符号转换 (`emit_i32x4_sconvert_f32x4`, `emit_i32x4_uconvert_f32x4`, `emit_f32x4_sconvert_i32x4`, `emit_f32x4_uconvert_i32x4`)。
   - `i8x16` 和 `i16x8` 之间的有符号和无符号缩小转换 (`emit_i8x16_sconvert_i16x8`, `emit_i8x16_uconvert_i16x8`)。
   - `i16x8` 和 `i32x4` 之间的有符号和无符号缩小转换 (`emit_i16x8_sconvert_i32x4`, `emit_i16x8_uconvert_i32x4`)。
   - `i16x8` 和 `i8x16` 之间的有符号和无符号扩展转换 (`emit_i16x8_sconvert_i8x16_low/high`, `emit_i16x8_uconvert_i8x16_low/high`)。
   - `i32x4` 和 `i16x8` 之间的有符号和无符号扩展转换 (`emit_i32x4_sconvert_i16x8_low/high`, `emit_i32x4_uconvert_i16x8_low/high`)。

3. **SIMD 向量的算术运算:** 提供了更多 SIMD 向量的算术运算：
   - `i8x16` 和 `i16x8` 的无符号四舍五入平均值 (`emit_i8x16_rounding_average_u`, `emit_i16x8_rounding_average_u`)。
   - `i8x16`, `i16x8`, `i64x2`, `i32x4` 的绝对值运算 (`emit_i8x16_abs`, `emit_i16x8_abs`, `emit_i64x2_abs`, `emit_i32x4_abs`)。

4. **SIMD 向量 Lane (通道) 操作:**  定义了用于提取和替换 SIMD 向量中特定元素的指令：
   - 提取 Lane (有符号和无符号)：`emit_i8x16_extract_lane_u/s`, `emit_i16x8_extract_lane_u/s`, `emit_i32x4_extract_lane`, `emit_f32x4_extract_lane`, `emit_f64x2_extract_lane`。
   - 替换 Lane：`emit_i8x16_replace_lane`, `emit_i16x8_replace_lane`, `emit_i32x4_replace_lane`, `emit_f32x4_replace_lane`, `emit_f64x2_replace_lane`。

5. **处理 NaN (非数字):**  `emit_s128_set_if_nan` 函数用于检查 SIMD 向量中是否存在 NaN 值，并根据结果设置目标寄存器的值。

6. **融合乘法加/减运算 (Fused Multiply-Add/Subtract):**  提供了高效的融合乘法加/减运算：
   - `f32x4` 的 `emit_f32x4_qfma` (加法) 和 `emit_f32x4_qfms` (减法)。
   - `f64x2` 的 `emit_f64x2_qfma` (加法) 和 `emit_f64x2_qfms` (减法)。

7. **栈管理:**
   - `StackCheck`: 用于检查栈是否溢出，如果溢出则跳转到指定的 OOL (Out-Of-Line) 代码。
   - `PushRegisters`: 将指定的寄存器列表压入栈。
   - `PopRegisters`: 从栈中弹出指定的寄存器列表。
   - `RecordSpillsInSafepoint`: 在安全点记录寄存器的溢出信息。
   - `DropStackSlotsAndRet`: 丢弃指定数量的栈槽并返回。

8. **函数调用:**
   - `CallNativeWasmCode`: 调用本地 WebAssembly 代码。
   - `TailCallNativeWasmCode`: 尾调用本地 WebAssembly 代码。
   - `CallIndirect`: 间接调用函数。
   - `TailCallIndirect`: 尾调用间接函数。
   - `CallBuiltin`: 调用内置函数。

9. **栈槽分配和释放:**
   - `AllocateStackSlot`: 在栈上分配指定大小的槽位。
   - `DeallocateStackSlot`: 释放栈上指定大小的槽位。

10. **其他操作:**
    - `AssertUnreachable`:  断言代码不可达。
    - `MaybeOSR`:  为 On-Stack Replacement (OSR) 提供入口点（当前为空实现）。
    - `emit_set_if_nan`:  如果浮点寄存器包含 NaN，则设置通用寄存器的值。
    - `CallFrameSetupStub`:  调用用于设置调用帧的内置桩函数。

11. **半精度浮点 (F16x8) 的占位符:**  存在 `f16x8` 相关的函数声明，但它们都返回 `false`，表明在当前的实现中，对 `f16x8` 的操作可能尚未完全支持或实现。

**关于您的问题：**

* **`.tq` 结尾:**  `v8/src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h` 以 `.h` 结尾，因此它是一个标准的 C++ 头文件，而不是 Torque 文件。Torque 文件通常用于定义 V8 的内置函数和类型。
* **与 JavaScript 的关系:**  这段代码是 V8 执行 WebAssembly 代码的核心部分。当 JavaScript 代码中运行 WebAssembly 模块时，V8 会使用 Liftoff 编译器将 WebAssembly 指令转换为 RISC-V 汇编指令来执行。这些内联函数定义了如何为各种 WebAssembly 操作生成相应的 RISC-V 指令。

   **JavaScript 例子：**

   ```javascript
   const buffer = new Uint8Array([
     0, 97, 115, 109, 1, 0, 0, 0, // WebAssembly 模块头
     // ... (省略模块的其他部分)
     0x7d, 0x04, 0x44, 0x00, 0x00, 0x00, 0x00, // f32.const 0.0
     0x7d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // f32.const 0.0
     0x92,                                     // f32.min
     0x0b                                      // end
   ]);
   const module = new WebAssembly.Module(buffer);
   const instance = new WebAssembly.Instance(module);
   // 当执行到 f32.min 指令时，V8 的 Liftoff 编译器会调用
   // LiftoffAssembler::emit_f32x4_relaxed_min (或其他相关的 min 函数)
   // 来生成 RISC-V 汇编指令，执行浮点数的最小值操作。
   ```

* **代码逻辑推理和假设输入/输出：**

   以 `emit_f32x4_relaxed_min` 为例：

   **假设输入：**
   - `dst`:  一个 `LiftoffRegister` 对象，表示目标寄存器 (例如，v10)。
   - `lhs`:  一个 `LiftoffRegister` 对象，表示左操作数寄存器 (例如，v11)。
   - `rhs`:  一个 `LiftoffRegister` 对象，表示右操作数寄存器 (例如，v12)。

   **代码逻辑：**
   1. `VU.set(kScratchReg, E32, m1);`: 设置向量单元，操作元素大小为 32 位，使用掩码 m1。
   2. `vfmin_vv(dst.fp().toV(), rhs.fp().toV(), lhs.fp().toV());`: 生成 RISC-V 向量浮点最小值指令 `vfmin.vv`，将 `rhs` 和 `lhs` 寄存器中的浮点向量进行按元素比较，并将最小值写入 `dst` 寄存器。

   **假设输出（生成的 RISC-V 汇编指令）：**
   ```assembly
   # 设置向量单元配置 (可能在之前的代码中完成，这里是假设)
   vsetvli zero, a0, e32, m1, ta, ma  # 假设 a0 包含了向量长度配置
   vfmin.vv v10, v12, v11
   ```

* **用户常见的编程错误：**

   虽然这些是底层的汇编生成代码，但用户在编写 WebAssembly 代码时可能会犯一些错误，这些错误最终会导致 Liftoff 生成不正确的指令或产生运行时错误。例如：

   1. **类型不匹配:**  WebAssembly 是一种类型安全的语言。如果 WebAssembly 代码尝试对不兼容的类型执行操作（例如，将整数加到浮点数上而没有显式转换），Liftoff 编译器会根据 WebAssembly 的类型规则生成相应的转换指令或抛出编译错误。

   2. **栈溢出:**  如果 WebAssembly 代码导致过多的函数调用或局部变量分配，可能会导致栈溢出。`LiftoffAssembler::StackCheck` 旨在在运行时检测到这种情况。

   3. **访问越界内存:**  WebAssembly 的内存访问是受限的。如果 WebAssembly 代码尝试访问超出分配内存范围的地址，可能会导致运行时错误。Liftoff 生成的加载和存储指令需要基于正确的内存地址计算。

   4. **不正确的 SIMD 操作:**  如果 WebAssembly 代码使用了不正确的 SIMD 操作序列或对齐方式，可能会导致未定义的行为或性能问题。例如，尝试对大小不匹配的向量进行操作。

   **JavaScript 例子 (导致类型不匹配的 WebAssembly 代码，虽然 Liftoff 会处理转换):**

   ```wat
   (module
     (func (export "add") (param $x i32) (param $y f32) (result f32)
       local.get $x
       f32.convert_i32_s  // 需要显式转换
       local.get $y
       f32.add
     )
   )
   ```

总而言之，`v8/src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h` 的这一部分定义了 `LiftoffAssembler` 类中用于生成 RISC-V 汇编指令以支持 WebAssembly 浮点和 SIMD 操作、栈管理以及函数调用的内联方法，是 V8 执行 WebAssembly 代码的关键组成部分。它直接将高级的 WebAssembly 指令翻译成可以在 RISC-V 处理器上执行的低级指令。

Prompt: 
```
这是目录为v8/src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
.set(kScratchReg, E32, m1);
  vfmin_vv(dst.fp().toV(), rhs.fp().toV(), lhs.fp().toV());
}

void LiftoffAssembler::emit_f32x4_relaxed_max(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vfmax_vv(dst.fp().toV(), rhs.fp().toV(), lhs.fp().toV());
}

void LiftoffAssembler::emit_f32x4_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  // b < a ? b : a
  vmflt_vv(v0, rhs.fp().toV(), lhs.fp().toV());
  vmerge_vv(dst.fp().toV(), rhs.fp().toV(), lhs.fp().toV());
}

void LiftoffAssembler::emit_f32x4_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  // a < b ? b : a
  vmflt_vv(v0, lhs.fp().toV(), rhs.fp().toV());
  vmerge_vv(dst.fp().toV(), rhs.fp().toV(), lhs.fp().toV());
}

void LiftoffAssembler::emit_f64x2_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vfabs_vv(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_f64x2_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vfneg_vv(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_f64x2_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vfsqrt_v(dst.fp().toV(), src.fp().toV());
}

bool LiftoffAssembler::emit_f64x2_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  Ceil_d(dst.fp().toV(), src.fp().toV(), kScratchReg, kSimd128ScratchReg);
  return true;
}

bool LiftoffAssembler::emit_f64x2_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Floor_d(dst.fp().toV(), src.fp().toV(), kScratchReg, kSimd128ScratchReg);
  return true;
}

bool LiftoffAssembler::emit_f64x2_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Trunc_d(dst.fp().toV(), src.fp().toV(), kScratchReg, kSimd128ScratchReg);
  return true;
}

bool LiftoffAssembler::emit_f64x2_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  Round_d(dst.fp().toV(), src.fp().toV(), kScratchReg, kSimd128ScratchReg);
  return true;
}

void LiftoffAssembler::emit_f64x2_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vfadd_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_f64x2_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vfsub_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_f64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vfmul_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_f64x2_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vfdiv_vv(dst.fp().toV(), lhs.fp().toV(), rhs.fp().toV());
}

void LiftoffAssembler::emit_f64x2_relaxed_min(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vfmin_vv(dst.fp().toV(), rhs.fp().toV(), lhs.fp().toV());
}

void LiftoffAssembler::emit_f64x2_relaxed_max(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  vfmax_vv(dst.fp().toV(), rhs.fp().toV(), lhs.fp().toV());
}

void LiftoffAssembler::emit_f64x2_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  // b < a ? b : a
  vmflt_vv(v0, rhs.fp().toV(), lhs.fp().toV());
  vmerge_vv(dst.fp().toV(), rhs.fp().toV(), lhs.fp().toV());
}

void LiftoffAssembler::emit_f64x2_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  // a < b ? b : a
  vmflt_vv(v0, lhs.fp().toV(), rhs.fp().toV());
  vmerge_vv(dst.fp().toV(), rhs.fp().toV(), lhs.fp().toV());
}

void LiftoffAssembler::emit_i32x4_sconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  VU.set(FPURoundingMode::RTZ);
  vmfeq_vv(v0, src.fp().toV(), src.fp().toV());
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vmv_vx(dst.fp().toV(), zero_reg);
  vfcvt_x_f_v(dst.fp().toV(), kSimd128ScratchReg, Mask);
}

void LiftoffAssembler::emit_i32x4_uconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  VU.set(FPURoundingMode::RTZ);
  vmfeq_vv(v0, src.fp().toV(), src.fp().toV());
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vmv_vx(dst.fp().toV(), zero_reg);
  vfcvt_xu_f_v(dst.fp().toV(), kSimd128ScratchReg, Mask);
}

void LiftoffAssembler::emit_f32x4_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  VU.set(FPURoundingMode::RTZ);
  vfcvt_f_x_v(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_f32x4_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  VU.set(FPURoundingMode::RTZ);
  vfcvt_f_xu_v(dst.fp().toV(), src.fp().toV());
}

void LiftoffAssembler::emit_i8x16_sconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vmv_vv(kSimd128ScratchReg, lhs.fp().toV());  // kSimd128ScratchReg v24
  vmv_vv(v25, rhs.fp().toV());
  VU.set(kScratchReg, E8, m1);
  VU.set(FPURoundingMode::RNE);
  vnclip_vi(dst.fp().toV(), kSimd128ScratchReg, 0);
}

void LiftoffAssembler::emit_i8x16_uconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  VU.set(kScratchReg, E16, m1);
  vmv_vv(kSimd128ScratchReg, lhs.fp().toV());  // kSimd128ScratchReg v24
  vmv_vv(v25, rhs.fp().toV());
  VU.set(kScratchReg, E16, m2);
  vmax_vx(kSimd128ScratchReg, kSimd128ScratchReg, zero_reg);
  VU.set(kScratchReg, E8, m1);
  VU.set(FPURoundingMode::RNE);
  vnclipu_vi(dst.fp().toV(), kSimd128ScratchReg, 0);
}

void LiftoffAssembler::emit_i16x8_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vmv_vv(kSimd128ScratchReg, lhs.fp().toV());  // kSimd128ScratchReg v24
  vmv_vv(v25, rhs.fp().toV());
  VU.set(kScratchReg, E16, m1);
  VU.set(FPURoundingMode::RNE);
  vnclip_vi(dst.fp().toV(), kSimd128ScratchReg, 0);
}

void LiftoffAssembler::emit_i16x8_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  VU.set(kScratchReg, E32, m1);
  vmv_vv(kSimd128ScratchReg, lhs.fp().toV());  // kSimd128ScratchReg v24
  vmv_vv(v25, rhs.fp().toV());
  VU.set(kScratchReg, E32, m2);
  vmax_vx(kSimd128ScratchReg, kSimd128ScratchReg, zero_reg);
  VU.set(kScratchReg, E16, m1);
  VU.set(FPURoundingMode::RNE);
  vnclipu_vi(dst.fp().toV(), kSimd128ScratchReg, 0);
}

void LiftoffAssembler::emit_i16x8_sconvert_i8x16_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  VU.set(kScratchReg, E16, m1);
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vsext_vf2(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i16x8_sconvert_i8x16_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  VU.set(kScratchReg, E8, m1);
  vslidedown_vi(kSimd128ScratchReg, src.fp().toV(), 8);
  VU.set(kScratchReg, E16, m1);
  vsext_vf2(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i16x8_uconvert_i8x16_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  VU.set(kScratchReg, E16, m1);
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vzext_vf2(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i16x8_uconvert_i8x16_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  VU.set(kScratchReg, E8, m1);
  vslidedown_vi(kSimd128ScratchReg, src.fp().toV(), 8);
  VU.set(kScratchReg, E16, m1);
  vzext_vf2(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32x4_sconvert_i16x8_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vsext_vf2(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32x4_sconvert_i16x8_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  VU.set(kScratchReg, E16, m1);
  vslidedown_vi(kSimd128ScratchReg, src.fp().toV(), 4);
  VU.set(kScratchReg, E32, m1);
  vsext_vf2(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32x4_uconvert_i16x8_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  vmv_vv(kSimd128ScratchReg, src.fp().toV());
  vzext_vf2(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32x4_uconvert_i16x8_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  VU.set(kScratchReg, E16, m1);
  vslidedown_vi(kSimd128ScratchReg, src.fp().toV(), 4);
  VU.set(kScratchReg, E32, m1);
  vzext_vf2(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i8x16_rounding_average_u(LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
  VU.set(kScratchReg, E8, m1);
  vwaddu_vv(kSimd128ScratchReg, lhs.fp().toV(), rhs.fp().toV());
  li(kScratchReg, 1);
  vwaddu_wx(kSimd128ScratchReg3, kSimd128ScratchReg, kScratchReg);
  li(kScratchReg, 2);
  VU.set(kScratchReg2, E16, m2);
  vdivu_vx(kSimd128ScratchReg3, kSimd128ScratchReg3, kScratchReg);
  VU.set(kScratchReg2, E8, m1);
  vnclipu_vi(dst.fp().toV(), kSimd128ScratchReg3, 0);
}
void LiftoffAssembler::emit_i16x8_rounding_average_u(LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
  VU.set(kScratchReg2, E16, m1);
  vwaddu_vv(kSimd128ScratchReg, lhs.fp().toV(), rhs.fp().toV());
  li(kScratchReg, 1);
  vwaddu_wx(kSimd128ScratchReg3, kSimd128ScratchReg, kScratchReg);
  li(kScratchReg, 2);
  VU.set(kScratchReg2, E32, m2);
  vdivu_vx(kSimd128ScratchReg3, kSimd128ScratchReg3, kScratchReg);
  VU.set(kScratchReg2, E16, m1);
  vnclipu_vi(dst.fp().toV(), kSimd128ScratchReg3, 0);
}

void LiftoffAssembler::emit_i8x16_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E8, m1);
  vmv_vx(kSimd128RegZero, zero_reg);
  vmv_vv(dst.fp().toV(), src.fp().toV());
  vmv_vv(v0, kSimd128RegZero);
  vmslt_vv(v0, src.fp().toV(), kSimd128RegZero);
  vneg_vv(dst.fp().toV(), src.fp().toV(), MaskType::Mask);
}

void LiftoffAssembler::emit_i16x8_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E16, m1);
  vmv_vx(kSimd128RegZero, zero_reg);
  vmv_vv(dst.fp().toV(), src.fp().toV());
  vmv_vv(v0, kSimd128RegZero);
  vmslt_vv(v0, src.fp().toV(), kSimd128RegZero);
  vneg_vv(dst.fp().toV(), src.fp().toV(), MaskType::Mask);
}

void LiftoffAssembler::emit_i64x2_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vmv_vx(kSimd128RegZero, zero_reg);
  vmv_vv(dst.fp().toV(), src.fp().toV());
  vmv_vv(v0, kSimd128RegZero);
  vmslt_vv(v0, src.fp().toV(), kSimd128RegZero);
  vneg_vv(dst.fp().toV(), src.fp().toV(), MaskType::Mask);
}

void LiftoffAssembler::emit_i32x4_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  VU.set(kScratchReg, E32, m1);
  vmv_vx(kSimd128RegZero, zero_reg);
  vmv_vv(dst.fp().toV(), src.fp().toV());
  vmv_vv(v0, kSimd128RegZero);
  vmslt_vv(v0, src.fp().toV(), kSimd128RegZero);
  vneg_vv(dst.fp().toV(), src.fp().toV(), MaskType::Mask);
}

void LiftoffAssembler::emit_i8x16_extract_lane_u(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E8, m1);
  vslidedown_vi(kSimd128ScratchReg, lhs.fp().toV(), imm_lane_idx);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
  slli(dst.gp(), dst.gp(), sizeof(void*) * 8 - 8);
  srli(dst.gp(), dst.gp(), sizeof(void*) * 8 - 8);
}

void LiftoffAssembler::emit_i8x16_extract_lane_s(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E8, m1);
  vslidedown_vi(kSimd128ScratchReg, lhs.fp().toV(), imm_lane_idx);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i16x8_extract_lane_u(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E16, m1);
  vslidedown_vi(kSimd128ScratchReg, lhs.fp().toV(), imm_lane_idx);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
  slli(dst.gp(), dst.gp(), sizeof(void*) * 8 - 16);
  srli(dst.gp(), dst.gp(), sizeof(void*) * 8 - 16);
}

void LiftoffAssembler::emit_i16x8_extract_lane_s(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E16, m1);
  vslidedown_vi(kSimd128ScratchReg, lhs.fp().toV(), imm_lane_idx);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32x4_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E32, m1);
  vslidedown_vi(kSimd128ScratchReg, lhs.fp().toV(), imm_lane_idx);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_f32x4_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E32, m1);
  vslidedown_vi(kSimd128ScratchReg, lhs.fp().toV(), imm_lane_idx);
  vfmv_fs(dst.fp(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_f64x2_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E64, m1);
  vslidedown_vi(kSimd128ScratchReg, lhs.fp().toV(), imm_lane_idx);
  vfmv_fs(dst.fp(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i8x16_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E64, m1);
  li(kScratchReg, 0x1 << imm_lane_idx);
  vmv_sx(v0, kScratchReg);
  VU.set(kScratchReg, E8, m1);
  vmerge_vx(dst.fp().toV(), src2.gp(), src1.fp().toV());
}

void LiftoffAssembler::emit_i16x8_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E16, m1);
  li(kScratchReg, 0x1 << imm_lane_idx);
  vmv_sx(v0, kScratchReg);
  vmerge_vx(dst.fp().toV(), src2.gp(), src1.fp().toV());
}

void LiftoffAssembler::emit_i32x4_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E32, m1);
  li(kScratchReg, 0x1 << imm_lane_idx);
  vmv_sx(v0, kScratchReg);
  vmerge_vx(dst.fp().toV(), src2.gp(), src1.fp().toV());
}

void LiftoffAssembler::emit_f32x4_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E32, m1);
  li(kScratchReg, 0x1 << imm_lane_idx);
  vmv_sx(v0, kScratchReg);
  fmv_x_w(kScratchReg, src2.fp());
  vmerge_vx(dst.fp().toV(), kScratchReg, src1.fp().toV());
}

void LiftoffAssembler::emit_f64x2_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E64, m1);
  li(kScratchReg, 0x1 << imm_lane_idx);
  vmv_sx(v0, kScratchReg);
  vfmerge_vf(dst.fp().toV(), src2.fp(), src1.fp().toV());
}

void LiftoffAssembler::emit_s128_set_if_nan(Register dst, LiftoffRegister src,
                                            Register tmp_gp,
                                            LiftoffRegister tmp_s128,
                                            ValueKind lane_kind) {
  ASM_CODE_COMMENT(this);
  if (lane_kind == kF32) {
    VU.set(kScratchReg, E32, m1);
    vmfeq_vv(kSimd128ScratchReg, src.fp().toV(),
             src.fp().toV());  // scratch <- !IsNan(tmp_fp)
  } else {
    VU.set(kScratchReg, E64, m1);
    DCHECK_EQ(lane_kind, kF64);
    vmfeq_vv(kSimd128ScratchReg, src.fp().toV(),
             src.fp().toV());  // scratch <- !IsNan(tmp_fp)
  }
  vmv_xs(kScratchReg, kSimd128ScratchReg);
  not_(kScratchReg, kScratchReg);
  andi(kScratchReg, kScratchReg, int32_t(lane_kind == kF32 ? 0xF : 0x3));
  Sw(kScratchReg, MemOperand(dst));
}

void LiftoffAssembler::emit_f32x4_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  VU.set(kScratchReg, E32, m1);
  vmv_vv(kSimd128ScratchReg, src1.fp().toV());
  vfmadd_vv(kSimd128ScratchReg, src2.fp().toV(), src3.fp().toV());
  vmv_vv(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_f32x4_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  VU.set(kScratchReg, E32, m1);
  vmv_vv(kSimd128ScratchReg, src1.fp().toV());
  vfnmsub_vv(kSimd128ScratchReg, src2.fp().toV(), src3.fp().toV());
  vmv_vv(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_f64x2_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  VU.set(kScratchReg, E64, m1);
  vmv_vv(kSimd128ScratchReg, src1.fp().toV());
  vfmadd_vv(kSimd128ScratchReg, src2.fp().toV(), src3.fp().toV());
  vmv_vv(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_f64x2_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  VU.set(kScratchReg, E64, m1);
  vmv_vv(kSimd128ScratchReg, src1.fp().toV());
  vfnmsub_vv(kSimd128ScratchReg, src2.fp().toV(), src3.fp().toV());
  vmv_vv(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::StackCheck(Label* ool_code) {
  UseScratchRegisterScope temps(this);
  Register limit_address = temps.Acquire();
  LoadStackLimit(limit_address, StackLimitKind::kInterruptStackLimit);
  MacroAssembler::Branch(ool_code, ule, sp, Operand(limit_address));
}

void LiftoffAssembler::AssertUnreachable(AbortReason reason) {
  if (v8_flags.debug_code) Abort(reason);
}

void LiftoffAssembler::PushRegisters(LiftoffRegList regs) {
  LiftoffRegList gp_regs = regs & kGpCacheRegList;
  int32_t num_gp_regs = gp_regs.GetNumRegsSet();
  if (num_gp_regs) {
    int32_t offset = num_gp_regs * kSystemPointerSize;
    AddWord(sp, sp, Operand(-offset));
    while (!gp_regs.is_empty()) {
      LiftoffRegister reg = gp_regs.GetFirstRegSet();
      offset -= kSystemPointerSize;
      StoreWord(reg.gp(), MemOperand(sp, offset));
      gp_regs.clear(reg);
    }
    DCHECK_EQ(offset, 0);
  }
  LiftoffRegList fp_regs = regs & kFpCacheRegList;
  int32_t num_fp_regs = fp_regs.GetNumRegsSet();
  if (num_fp_regs) {
    AddWord(sp, sp, Operand(-(num_fp_regs * kStackSlotSize)));
    int32_t offset = 0;
    while (!fp_regs.is_empty()) {
      LiftoffRegister reg = fp_regs.GetFirstRegSet();
      MacroAssembler::StoreDouble(reg.fp(), MemOperand(sp, offset));
      fp_regs.clear(reg);
      offset += sizeof(double);
    }
    DCHECK_EQ(offset, num_fp_regs * sizeof(double));
  }
}

void LiftoffAssembler::PopRegisters(LiftoffRegList regs) {
  LiftoffRegList fp_regs = regs & kFpCacheRegList;
  int32_t fp_offset = 0;
  while (!fp_regs.is_empty()) {
    LiftoffRegister reg = fp_regs.GetFirstRegSet();
    MacroAssembler::LoadDouble(reg.fp(), MemOperand(sp, fp_offset));
    fp_regs.clear(reg);
    fp_offset += sizeof(double);
  }
  if (fp_offset) AddWord(sp, sp, Operand(fp_offset));
  LiftoffRegList gp_regs = regs & kGpCacheRegList;
  int32_t gp_offset = 0;
  while (!gp_regs.is_empty()) {
    LiftoffRegister reg = gp_regs.GetLastRegSet();
    LoadWord(reg.gp(), MemOperand(sp, gp_offset));
    gp_regs.clear(reg);
    gp_offset += kSystemPointerSize;
  }
  AddWord(sp, sp, Operand(gp_offset));
}

void LiftoffAssembler::RecordSpillsInSafepoint(
    SafepointTableBuilder::Safepoint& safepoint, LiftoffRegList all_spills,
    LiftoffRegList ref_spills, int spill_offset) {
  LiftoffRegList fp_spills = all_spills & kFpCacheRegList;
  int spill_space_size = fp_spills.GetNumRegsSet() * kSimd128Size;
  LiftoffRegList gp_spills = all_spills & kGpCacheRegList;
  while (!gp_spills.is_empty()) {
    LiftoffRegister reg = gp_spills.GetFirstRegSet();
    if (ref_spills.has(reg)) {
      safepoint.DefineTaggedStackSlot(spill_offset);
    }
    gp_spills.clear(reg);
    ++spill_offset;
    spill_space_size += kSystemPointerSize;
  }
  // Record the number of additional spill slots.
  RecordOolSpillSpaceSize(spill_space_size);
}

void LiftoffAssembler::DropStackSlotsAndRet(uint32_t num_stack_slots) {
  MacroAssembler::DropAndRet(static_cast<int>(num_stack_slots));
}

void LiftoffAssembler::CallNativeWasmCode(Address addr) {
  Call(addr, RelocInfo::WASM_CALL);
}

void LiftoffAssembler::TailCallNativeWasmCode(Address addr) {
  Jump(addr, RelocInfo::WASM_CALL);
}

void LiftoffAssembler::CallIndirect(const ValueKindSig* sig,
                                    compiler::CallDescriptor* call_descriptor,
                                    Register target) {
  if (target == no_reg) {
    pop(t6);
    Call(t6);
  } else {
    Call(target);
  }
}

void LiftoffAssembler::TailCallIndirect(Register target) {
  if (target == no_reg) {
    Pop(t6);
    Jump(t6);
  } else {
    Jump(target);
  }
}

void LiftoffAssembler::CallBuiltin(Builtin builtin) {
  // A direct call to a builtin. Just encode the builtin index. This will be
  // patched at relocation.
  Call(static_cast<Address>(builtin), RelocInfo::WASM_STUB_CALL);
}

void LiftoffAssembler::AllocateStackSlot(Register addr, uint32_t size) {
  AddWord(sp, sp, Operand(-size));
  MacroAssembler::Move(addr, sp);
}

void LiftoffAssembler::DeallocateStackSlot(uint32_t size) {
  AddWord(sp, sp, Operand(size));
}

void LiftoffAssembler::MaybeOSR() {}

void LiftoffAssembler::emit_set_if_nan(Register dst, FPURegister src,
                                       ValueKind kind) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, 1);
  if (kind == kF32) {
    feq_s(scratch, src, src);  // rd <- !isNan(src)
  } else {
    DCHECK_EQ(kind, kF64);
    feq_d(scratch, src, src);  // rd <- !isNan(src)
  }
  seqz(scratch, scratch);
  Sw(scratch, MemOperand(dst));
}

void LiftoffAssembler::CallFrameSetupStub(int declared_function_index) {
// The standard library used by gcc tryjobs does not consider `std::find` to be
// `constexpr`, so wrap it in a `#ifdef __clang__` block.
#ifdef __clang__
  static_assert(std::find(std::begin(wasm::kGpParamRegisters),
                          std::end(wasm::kGpParamRegisters),
                          kLiftoffFrameSetupFunctionReg) ==
                std::end(wasm::kGpParamRegisters));
#endif

  // On MIPS64, we must push at least {ra} before calling the stub, otherwise
  // it would get clobbered with no possibility to recover it. So just set
  // up the frame here.
  EnterFrame(StackFrame::WASM);
  LoadConstant(LiftoffRegister(kLiftoffFrameSetupFunctionReg),
               WasmValue(declared_function_index));
  CallBuiltin(Builtin::kWasmLiftoffFrameSetup);
}

bool LiftoffAssembler::emit_f16x8_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_i16x8_sconvert_f16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_i16x8_uconvert_f16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_sconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_uconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_demote_f32x4_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f16x8_demote_f64x2_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  return false;
}
bool LiftoffAssembler::emit_f32x4_promote_low_f16x8(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  return false;
}

}  // namespace v8::internal::wasm

#endif  // V8_WASM_BASELINE_RISCV_LIFTOFF_ASSEMBLER_RISCV_INL_H_

"""


```