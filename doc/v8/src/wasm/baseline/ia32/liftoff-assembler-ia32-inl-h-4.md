Response:
The user wants to understand the functionality of a C++ header file in the V8 JavaScript engine. The file `v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h` contains implementations of methods for a `LiftoffAssembler` class, specifically for the IA32 architecture. The code snippets provided are all definitions of methods within this class. These methods seem to correspond to WebAssembly SIMD (Single Instruction, Multiple Data) operations.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the Core Purpose:** The code consists of function definitions within the `LiftoffAssembler` class. The function names clearly indicate they are related to SIMD operations for different data types (e.g., `i8x16`, `i16x8`, `f32x4`). The presence of `ia32` in the path and the use of assembly instructions like `Pxor`, `Paddw`, `Vpaddd` etc., strongly suggest this file provides low-level implementations of WebAssembly SIMD instructions for the IA32 architecture. The "Liftoff" part likely refers to a specific compiler or execution strategy within V8.

2. **Check for Torque:** The filename ends in `.h`, not `.tq`. Therefore, it's C++ code, not Torque.

3. **Relate to JavaScript (if applicable):** WebAssembly directly relates to JavaScript as it's a compilation target for code that can run in the same environment as JavaScript. JavaScript itself doesn't have direct equivalents for these low-level SIMD instructions exposed as individual functions. However, JavaScript's `WebAssembly` API allows execution of WebAssembly modules that *do* utilize these SIMD operations. Therefore, the connection is through the WebAssembly API. I need to provide a JavaScript example of *using* a WebAssembly module that would ultimately trigger this kind of code.

4. **Infer Functionality from Method Names and Operations:**
    * The method names (e.g., `emit_i8x16_add`, `emit_f32x4_sqrt`) clearly map to common arithmetic, logical, and bitwise operations on SIMD vectors of various data types.
    * The arguments `dst`, `lhs`, `rhs` (destination, left-hand side, right-hand side) are typical for binary operations.
    * The presence of `emit_*` suggests these methods generate the actual assembly code for these operations.
    * Helper functions like `EmitSimdCommutativeBinOp`, `EmitSimdNonCommutativeBinOp`, and `EmitSimdShiftOp` indicate a pattern for generating similar instructions.
    * Some methods have immediate versions (e.g., `emit_i16x8_shli`), taking an immediate value as an argument.
    * The inclusion of saturation (`_sat_s`, `_sat_u`) and relaxed (`relaxed_`) versions of operations indicates handling of edge cases and performance optimizations.
    * Operations like `bitmask` extract bit patterns from SIMD registers.
    * Conversion operations (e.g., `sconvert`, `uconvert`, `promote`) change the data type within the SIMD vector.

5. **Provide Code Logic Inference:** Choose a simple example, like `emit_i8x16_add`.
    * **Input:** Define sample `LiftoffRegister` objects representing the destination and source registers.
    * **Output:** Describe the expected assembly instruction that would be emitted (e.g., `paddb` or `vpaddb`). It's important to note the potential difference based on instruction set extensions (SSE vs. AVX).

6. **Illustrate Common Programming Errors:**  Consider potential misuse of SIMD operations:
    * **Incorrect Data Types:** Trying to perform operations on incompatible SIMD vector types.
    * **Alignment Issues:** SIMD instructions often require data to be aligned in memory.
    * **Out-of-Bounds Access:**  Accessing elements beyond the bounds of the SIMD vector (although less directly applicable to these specific assembler methods).

7. **Summarize the Functionality:** Combine the observations into a concise summary of the file's purpose. It provides the implementation details for generating IA32 assembly code for WebAssembly SIMD operations within the Liftoff compiler.

8. **Address the "Part X of Y" Information:** Acknowledge that this is part 5 of 6, suggesting it's a piece of a larger set of files. The functionality described so far aligns with the SIMD instruction implementations, so the summary should reflect that this part specifically deals with those operations.

**Self-Correction/Refinement during the Thought Process:**

* Initially, I might have focused too much on the direct JavaScript equivalents. It's more accurate to explain the connection through the WebAssembly API.
* When providing the code logic inference, it's crucial to mention the underlying assembly instructions and the role of instruction set extensions like SSE4.1 and AVX.
* For common programming errors, while general SIMD errors are relevant, focus on those that might be more pertinent at this low-level assembler stage (like data type mismatches which the compiler stage might not catch if not handled properly).
* The summary needs to emphasize the "IA32" and "Liftoff" context.
这是 V8 引擎中用于在 IA32 架构上生成 Liftoff (一种 WebAssembly 的快速基线编译器) 代码的汇编器的一部分。具体来说，这个头文件 `liftoff-assembler-ia32-inl.h` 包含了 `LiftoffAssembler` 类内联函数的定义，这些函数用于发射 (emit) 针对 WebAssembly SIMD (Single Instruction, Multiple Data) 操作的 IA32 汇编指令。

**功能归纳：**

这个文件的主要功能是提供了一系列 C++ 内联函数，作为 `LiftoffAssembler` 类的成员，用于生成 IA32 架构上执行 WebAssembly SIMD 指令所需的汇编代码。它针对不同的 SIMD 数据类型 (例如 `i8x16`, `i16x8`, `i32x4`, `i64x2`, `f32x4`, `f64x2`) 实现了各种操作，包括：

* **算术运算:** 加法、减法、乘法、除法、取反
* **比较运算:** 所有元素是否为真 (alltrue)
* **位运算:** 左移、右移 (算术和逻辑)
* **最小值/最大值运算:**  分别针对有符号和无符号整数以及浮点数
* **扩展运算:**  例如 `extadd_pairwise`, `extmul_low`, `extmul_high`，用于将较小的数据类型扩展到较大的数据类型进行运算
* **点积运算:** `dot`
* **类型转换:** 例如整数之间的转换、浮点数之间的转换
* **绝对值、平方根、ceil、floor、trunc、nearest_int 等浮点数操作**
* **位掩码提取:** `bitmask`
* **饱和运算:**  例如 `add_sat_s`, `add_sat_u`，防止溢出
* **Q15 乘法:**  定点数乘法
* **转换运算:** 例如将整数转换为浮点数

**关于文件类型：**

`v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h` 以 `.h` 结尾，所以它是 **C++ 头文件**，而不是 Torque 源代码。 Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系及示例：**

这个文件中的代码直接服务于 WebAssembly 的执行。当 JavaScript 代码调用一个 WebAssembly 模块，并且该模块使用了 SIMD 指令时，V8 的 Liftoff 编译器会使用这里的函数来生成对应的 IA32 汇编代码。

**JavaScript 示例：**

```javascript
// 假设你有一个编译好的 WebAssembly 模块 wasmModule，其中使用了 SIMD 指令

async function runWasmSimd() {
  const response = await fetch('your_wasm_module.wasm'); // 替换为你的 wasm 文件路径
  const bytes = await response.arrayBuffer();
  const instance = await WebAssembly.instantiate(bytes);

  // 假设你的 wasm 模块导出了一个名为 'add_i32x4' 的函数，
  // 该函数接收两个 i32x4 类型的参数并返回它们的和。

  // 创建两个 i32x4 类型的数组 (在 wasm 中表现为 packed SIMD 向量)
  const a = new Int32Array([1, 2, 3, 4]);
  const b = new Int32Array([5, 6, 7, 8]);

  // 将数组传递给 wasm 函数 (具体传递方式取决于 wasm 模块的接口)
  // 这里仅为示意，实际可能需要通过 wasm 的 Memory 对象来传递数据
  const result = instance.exports.add_i32x4(a, b);

  console.log(result); // 预期输出类似于 i32x4(6, 8, 10, 12)
}

runWasmSimd();
```

在这个例子中，当 `instance.exports.add_i32x4` 被调用时，如果 Liftoff 编译器被使用，并且该函数内部使用了类似 `i32x4.add` 的 SIMD 指令，那么 `LiftoffAssembler::emit_i32x4_add` 函数（在这个文件中定义的）就会被调用来生成相应的 IA32 汇编指令 (例如 `paddd` 或 `vpaddd`)。

**代码逻辑推理 (以 `emit_i16x8_neg` 为例)：**

**假设输入：**

* `dst`: 一个 `LiftoffRegister` 对象，代表目标寄存器 (例如，XMM1)。
* `src`: 一个 `LiftoffRegister` 对象，代表源寄存器 (例如，XMM2)。

**输出：**

如果 `dst` 和 `src` 指向同一个浮点寄存器，则会生成以下 IA32 汇编指令：

```assembly
pcmpeqw xmm?, xmm?  // 将一个寄存器与自身比较，结果为全 1 或全 0
psignw xmm1, xmm?   // 根据第二个操作数的符号位，改变第一个操作数的符号
```

其中 `xmm?` 代表一个临时 scratch 寄存器 (`liftoff::kScratchDoubleReg`)。

如果 `dst` 和 `src` 指向不同的浮点寄存器，则会生成以下 IA32 汇编指令：

```assembly
pxor xmm1, xmm1     // 将目标寄存器与自身异或，清零
psubw xmm1, xmm2     // 从清零的寄存器中减去源寄存器的值，相当于取反
```

**用户常见的编程错误 (与 SIMD 相关)：**

1. **数据类型不匹配：** 尝试对不同数据类型的 SIMD 向量执行操作。例如，尝试将一个 `i8x16` 向量加到一个 `i16x8` 向量。在 WebAssembly 中，这些操作通常会有明确的类型限制，但开发者可能在手动编写或理解 wasm 代码时犯错。

   ```javascript
   // WebAssembly (WAT 格式示意)
   (module
     (func $add_mismatch (param $a v128 (ref i8x16)) (param $b v128 (ref i16x8))
       ;; 尝试将 i8x16 加到 i16x8 (这将导致类型错误)
       local.get $a
       local.get $b
       i8x16.add  ;; 假设存在这样的指令，但实际上需要类型匹配
     )
   )
   ```

2. **对齐问题：** SIMD 指令通常对内存对齐有要求。如果加载或存储的数据没有正确对齐，可能会导致性能下降或程序崩溃。虽然这个文件是关于寄存器操作，但在实际的 wasm 执行中，从内存加载数据到 SIMD 寄存器时，对齐是一个重要的考虑因素。

3. **误解饱和运算和环绕运算：**  不清楚何时应该使用饱和运算 (超出范围的值会被限制在最大/最小值) 或环绕运算 (超出范围的值会回绕)。例如，在音频处理中，饱和运算可能更合适，而在其他场景下可能需要环绕运算。

   ```javascript
   // JavaScript 中模拟饱和加法
   function saturateAdd(a, b, maxValue) {
     const sum = a + b;
     return Math.min(maxValue, Math.max(0, sum)); // 假设范围是 0 到 maxValue
   }

   // WebAssembly 中提供了饱和加法指令 (例如 i8x16.add_s)
   ```

**第5部分功能归纳：**

作为第 5 部分，这个代码片段主要关注于 **实现 `LiftoffAssembler` 类中用于生成 IA32 汇编代码以执行 WebAssembly SIMD 整数和浮点数运算的方法**。它涵盖了多种 SIMD 操作，为 Liftoff 编译器在 IA32 架构上支持高效的 WebAssembly SIMD 执行提供了基础。可以推断，之前的或后续的部分可能涉及：

* **第1-4部分:**  `LiftoffAssembler` 类的其他核心功能，例如非 SIMD 指令的生成、内存操作、控制流等。
* **第6部分:**  可能包含与浮点数转换、比较运算或其他未在此部分涵盖的 SIMD 指令相关的实现，或者是一些辅助函数和类的定义。

Prompt: 
```
这是目录为v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
                 LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminsb, &Assembler::pminsb>(
      this, dst, lhs, rhs, SSE4_1);
}

void LiftoffAssembler::emit_i8x16_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminub, &Assembler::pminub>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i8x16_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxsb, &Assembler::pmaxsb>(
      this, dst, lhs, rhs, SSE4_1);
}

void LiftoffAssembler::emit_i8x16_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxub, &Assembler::pmaxub>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  if (dst.fp() == src.fp()) {
    Pcmpeqd(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
    Psignw(dst.fp(), liftoff::kScratchDoubleReg);
  } else {
    Pxor(dst.fp(), dst.fp());
    Psubw(dst.fp(), src.fp());
  }
}

void LiftoffAssembler::emit_i16x8_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  liftoff::EmitAllTrue<&MacroAssembler::Pcmpeqw>(this, dst, src);
}

void LiftoffAssembler::emit_i16x8_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  XMMRegister tmp = liftoff::kScratchDoubleReg;
  Packsswb(tmp, src.fp());
  Pmovmskb(dst.gp(), tmp);
  shr(dst.gp(), 8);
}

void LiftoffAssembler::emit_i16x8_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdShiftOp<&Assembler::vpsllw, &Assembler::psllw, 4>(this, dst,
                                                                     lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  liftoff::EmitSimdShiftOpImm<&Assembler::vpsllw, &Assembler::psllw, 4>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShiftOp<&Assembler::vpsraw, &Assembler::psraw, 4>(this, dst,
                                                                     lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftOpImm<&Assembler::vpsraw, &Assembler::psraw, 4>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShiftOp<&Assembler::vpsrlw, &Assembler::psrlw, 4>(this, dst,
                                                                     lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftOpImm<&Assembler::vpsrlw, &Assembler::psrlw, 4>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpaddw, &Assembler::paddw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_add_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpaddsw, &Assembler::paddsw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_add_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpaddusw, &Assembler::paddusw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpsubw, &Assembler::psubw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_sub_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpsubsw, &Assembler::psubsw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_sub_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpsubusw,
                                       &Assembler::psubusw>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i16x8_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmullw, &Assembler::pmullw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminsw, &Assembler::pminsw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminuw, &Assembler::pminuw>(
      this, dst, lhs, rhs, SSE4_1);
}

void LiftoffAssembler::emit_i16x8_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxsw, &Assembler::pmaxsw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxuw, &Assembler::pmaxuw>(
      this, dst, lhs, rhs, SSE4_1);
}

void LiftoffAssembler::emit_i16x8_extadd_pairwise_i8x16_s(LiftoffRegister dst,
                                                          LiftoffRegister src) {
  I16x8ExtAddPairwiseI8x16S(dst.fp(), src.fp(), liftoff::kScratchDoubleReg,
                            GetUnusedRegister(kGpReg, {}).gp());
}

void LiftoffAssembler::emit_i16x8_extadd_pairwise_i8x16_u(LiftoffRegister dst,
                                                          LiftoffRegister src) {
  I16x8ExtAddPairwiseI8x16U(dst.fp(), src.fp(),
                            GetUnusedRegister(kGpReg, {}).gp());
}

void LiftoffAssembler::emit_i16x8_extmul_low_i8x16_s(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  I16x8ExtMulLow(dst.fp(), src1.fp(), src2.fp(), liftoff::kScratchDoubleReg,
                 /*is_signed=*/true);
}

void LiftoffAssembler::emit_i16x8_extmul_low_i8x16_u(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  I16x8ExtMulLow(dst.fp(), src1.fp(), src2.fp(), liftoff::kScratchDoubleReg,
                 /*is_signed=*/false);
}

void LiftoffAssembler::emit_i16x8_extmul_high_i8x16_s(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  I16x8ExtMulHighS(dst.fp(), src1.fp(), src2.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_extmul_high_i8x16_u(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  I16x8ExtMulHighU(dst.fp(), src1.fp(), src2.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_q15mulr_sat_s(LiftoffRegister dst,
                                                LiftoffRegister src1,
                                                LiftoffRegister src2) {
  I16x8Q15MulRSatS(dst.fp(), src1.fp(), src2.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_relaxed_q15mulr_s(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2) {
  if (CpuFeatures::IsSupported(AVX) || dst == src1) {
    Pmulhrsw(dst.fp(), src1.fp(), src2.fp());
  } else {
    movdqa(dst.fp(), src1.fp());
    pmulhrsw(dst.fp(), src2.fp());
  }
}

void LiftoffAssembler::emit_i16x8_dot_i8x16_i7x16_s(LiftoffRegister dst,
                                                    LiftoffRegister lhs,
                                                    LiftoffRegister rhs) {
  I16x8DotI8x16I7x16S(dst.fp(), lhs.fp(), rhs.fp());
}

void LiftoffAssembler::emit_i32x4_dot_i8x16_i7x16_add_s(LiftoffRegister dst,
                                                        LiftoffRegister lhs,
                                                        LiftoffRegister rhs,
                                                        LiftoffRegister acc) {
  static constexpr RegClass tmp_rc = reg_class_for(kS128);
  LiftoffRegister tmp1 =
      GetUnusedRegister(tmp_rc, LiftoffRegList{dst, lhs, rhs, acc});
  LiftoffRegister tmp2 =
      GetUnusedRegister(tmp_rc, LiftoffRegList{dst, lhs, rhs, acc, tmp1});
  I32x4DotI8x16I7x16AddS(dst.fp(), lhs.fp(), rhs.fp(), acc.fp(), tmp1.fp(),
                         tmp2.fp());
}

void LiftoffAssembler::emit_i32x4_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  if (dst.fp() == src.fp()) {
    Pcmpeqd(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
    Psignd(dst.fp(), liftoff::kScratchDoubleReg);
  } else {
    Pxor(dst.fp(), dst.fp());
    Psubd(dst.fp(), src.fp());
  }
}

void LiftoffAssembler::emit_i32x4_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  liftoff::EmitAllTrue<&MacroAssembler::Pcmpeqd>(this, dst, src);
}

void LiftoffAssembler::emit_i32x4_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  Movmskps(dst.gp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdShiftOp<&Assembler::vpslld, &Assembler::pslld, 5>(this, dst,
                                                                     lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  liftoff::EmitSimdShiftOpImm<&Assembler::vpslld, &Assembler::pslld, 5>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShiftOp<&Assembler::vpsrad, &Assembler::psrad, 5>(this, dst,
                                                                     lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftOpImm<&Assembler::vpsrad, &Assembler::psrad, 5>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShiftOp<&Assembler::vpsrld, &Assembler::psrld, 5>(this, dst,
                                                                     lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftOpImm<&Assembler::vpsrld, &Assembler::psrld, 5>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpaddd, &Assembler::paddd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpsubd, &Assembler::psubd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmulld, &Assembler::pmulld>(
      this, dst, lhs, rhs, SSE4_1);
}

void LiftoffAssembler::emit_i32x4_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminsd, &Assembler::pminsd>(
      this, dst, lhs, rhs, SSE4_1);
}

void LiftoffAssembler::emit_i32x4_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminud, &Assembler::pminud>(
      this, dst, lhs, rhs, SSE4_1);
}

void LiftoffAssembler::emit_i32x4_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxsd, &Assembler::pmaxsd>(
      this, dst, lhs, rhs, SSE4_1);
}

void LiftoffAssembler::emit_i32x4_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxud, &Assembler::pmaxud>(
      this, dst, lhs, rhs, SSE4_1);
}

void LiftoffAssembler::emit_i32x4_dot_i16x8_s(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaddwd, &Assembler::pmaddwd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_extadd_pairwise_i16x8_s(LiftoffRegister dst,
                                                          LiftoffRegister src) {
  I32x4ExtAddPairwiseI16x8S(dst.fp(), src.fp(),
                            GetUnusedRegister(kGpReg, {}).gp());
}

void LiftoffAssembler::emit_i32x4_extadd_pairwise_i16x8_u(LiftoffRegister dst,
                                                          LiftoffRegister src) {
  I32x4ExtAddPairwiseI16x8U(dst.fp(), src.fp(), liftoff::kScratchDoubleReg);
}

namespace liftoff {
// Helper function to check for register aliasing, AVX support, and moves
// registers around before calling the actual macro-assembler function.
inline void I32x4ExtMulHelper(LiftoffAssembler* assm, XMMRegister dst,
                              XMMRegister src1, XMMRegister src2, bool low,
                              bool is_signed) {
  // I32x4ExtMul requires dst == src1 if AVX is not supported.
  if (CpuFeatures::IsSupported(AVX) || dst == src1) {
    assm->I32x4ExtMul(dst, src1, src2, liftoff::kScratchDoubleReg, low,
                      is_signed);
  } else if (dst != src2) {
    // dst != src1 && dst != src2
    assm->movaps(dst, src1);
    assm->I32x4ExtMul(dst, dst, src2, liftoff::kScratchDoubleReg, low,
                      is_signed);
  } else {
    // dst == src2
    // Extended multiplication is commutative,
    assm->movaps(dst, src2);
    assm->I32x4ExtMul(dst, dst, src1, liftoff::kScratchDoubleReg, low,
                      is_signed);
  }
}
}  // namespace liftoff

void LiftoffAssembler::emit_i32x4_extmul_low_i16x8_s(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  liftoff::I32x4ExtMulHelper(this, dst.fp(), src1.fp(), src2.fp(), /*low=*/true,
                             /*is_signed=*/true);
}

void LiftoffAssembler::emit_i32x4_extmul_low_i16x8_u(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  liftoff::I32x4ExtMulHelper(this, dst.fp(), src1.fp(), src2.fp(), /*low=*/true,
                             /*is_signed=*/false);
}

void LiftoffAssembler::emit_i32x4_extmul_high_i16x8_s(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  liftoff::I32x4ExtMulHelper(this, dst.fp(), src1.fp(), src2.fp(),
                             /*low=*/false,
                             /*is_signed=*/true);
}

void LiftoffAssembler::emit_i32x4_extmul_high_i16x8_u(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  liftoff::I32x4ExtMulHelper(this, dst.fp(), src1.fp(), src2.fp(),
                             /*low=*/false,
                             /*is_signed=*/false);
}

void LiftoffAssembler::emit_i64x2_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  I64x2Neg(dst.fp(), src.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i64x2_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  liftoff::EmitAllTrue<&MacroAssembler::Pcmpeqq>(this, dst, src, SSE4_1);
}

void LiftoffAssembler::emit_i64x2_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdShiftOp<&Assembler::vpsllq, &Assembler::psllq, 6>(this, dst,
                                                                     lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  liftoff::EmitSimdShiftOpImm<&Assembler::vpsllq, &Assembler::psllq, 6>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  XMMRegister tmp =
      GetUnusedRegister(RegClass::kFpReg, LiftoffRegList{dst, lhs}).fp();
  Register scratch =
      GetUnusedRegister(RegClass::kGpReg, LiftoffRegList{rhs}).gp();

  I64x2ShrS(dst.fp(), lhs.fp(), rhs.gp(), liftoff::kScratchDoubleReg, tmp,
            scratch);
}

void LiftoffAssembler::emit_i64x2_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  I64x2ShrS(dst.fp(), lhs.fp(), rhs & 0x3F, liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i64x2_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShiftOp<&Assembler::vpsrlq, &Assembler::psrlq, 6>(this, dst,
                                                                     lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftOpImm<&Assembler::vpsrlq, &Assembler::psrlq, 6>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpaddq, &Assembler::paddq>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpsubq, &Assembler::psubq>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  static constexpr RegClass tmp_rc = reg_class_for(kS128);
  LiftoffRegister tmp1 =
      GetUnusedRegister(tmp_rc, LiftoffRegList{dst, lhs, rhs});
  LiftoffRegister tmp2 =
      GetUnusedRegister(tmp_rc, LiftoffRegList{dst, lhs, rhs, tmp1});
  I64x2Mul(dst.fp(), lhs.fp(), rhs.fp(), tmp1.fp(), tmp2.fp());
}

void LiftoffAssembler::emit_i64x2_extmul_low_i32x4_s(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  I64x2ExtMul(dst.fp(), src1.fp(), src2.fp(), liftoff::kScratchDoubleReg,
              /*low=*/true, /*is_signed=*/true);
}

void LiftoffAssembler::emit_i64x2_extmul_low_i32x4_u(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  I64x2ExtMul(dst.fp(), src1.fp(), src2.fp(), liftoff::kScratchDoubleReg,
              /*low=*/true, /*is_signed=*/false);
}

void LiftoffAssembler::emit_i64x2_extmul_high_i32x4_s(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  I64x2ExtMul(dst.fp(), src1.fp(), src2.fp(), liftoff::kScratchDoubleReg,
              /*low=*/false, /*is_signed=*/true);
}

void LiftoffAssembler::emit_i64x2_extmul_high_i32x4_u(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  I64x2ExtMul(dst.fp(), src1.fp(), src2.fp(), liftoff::kScratchDoubleReg,
              /*low=*/false, /*is_signed=*/false);
}

void LiftoffAssembler::emit_i64x2_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  Movmskpd(dst.gp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_sconvert_i32x4_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  Pmovsxdq(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_sconvert_i32x4_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  I64x2SConvertI32x4High(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_uconvert_i32x4_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  Pmovzxdq(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_uconvert_i32x4_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  I64x2UConvertI32x4High(dst.fp(), src.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_f32x4_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Register tmp = GetUnusedRegister(kGpReg, {}).gp();
  Absps(dst.fp(), src.fp(), tmp);
}

void LiftoffAssembler::emit_f32x4_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Register tmp = GetUnusedRegister(kGpReg, {}).gp();
  Negps(dst.fp(), src.fp(), tmp);
}

void LiftoffAssembler::emit_f32x4_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  Sqrtps(dst.fp(), src.fp());
}

bool LiftoffAssembler::emit_f32x4_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundps(dst.fp(), src.fp(), kRoundUp);
  return true;
}

bool LiftoffAssembler::emit_f32x4_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundps(dst.fp(), src.fp(), kRoundDown);
  return true;
}

bool LiftoffAssembler::emit_f32x4_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundps(dst.fp(), src.fp(), kRoundToZero);
  return true;
}

bool LiftoffAssembler::emit_f32x4_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundps(dst.fp(), src.fp(), kRoundToNearest);
  return true;
}

void LiftoffAssembler::emit_f32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vaddps, &Assembler::addps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vsubps, &Assembler::subps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vmulps, &Assembler::mulps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vdivps, &Assembler::divps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  F32x4Min(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_f32x4_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  F32x4Max(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_f32x4_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  // Due to the way minps works, pmin(a, b) = minps(b, a).
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vminps, &Assembler::minps>(
      this, dst, rhs, lhs);
}

void LiftoffAssembler::emit_f32x4_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  // Due to the way maxps works, pmax(a, b) = maxps(b, a).
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vmaxps, &Assembler::maxps>(
      this, dst, rhs, lhs);
}

void LiftoffAssembler::emit_f32x4_relaxed_min(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vminps, &Assembler::minps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_relaxed_max(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vmaxps, &Assembler::maxps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Register tmp = GetUnusedRegister(kGpReg, {}).gp();
  Abspd(dst.fp(), src.fp(), tmp);
}

void LiftoffAssembler::emit_f64x2_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Register tmp = GetUnusedRegister(kGpReg, {}).gp();
  Negpd(dst.fp(), src.fp(), tmp);
}

void LiftoffAssembler::emit_f64x2_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  Sqrtpd(dst.fp(), src.fp());
}

bool LiftoffAssembler::emit_f64x2_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundpd(dst.fp(), src.fp(), kRoundUp);
  return true;
}

bool LiftoffAssembler::emit_f64x2_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundpd(dst.fp(), src.fp(), kRoundDown);
  return true;
}

bool LiftoffAssembler::emit_f64x2_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundpd(dst.fp(), src.fp(), kRoundToZero);
  return true;
}

bool LiftoffAssembler::emit_f64x2_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundpd(dst.fp(), src.fp(), kRoundToNearest);
  return true;
}

void LiftoffAssembler::emit_f64x2_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vaddpd, &Assembler::addpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vsubpd, &Assembler::subpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vmulpd, &Assembler::mulpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vdivpd, &Assembler::divpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  F64x2Min(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_f64x2_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  F64x2Max(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_f64x2_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  // Due to the way minpd works, pmin(a, b) = minpd(b, a).
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vminpd, &Assembler::minpd>(
      this, dst, rhs, lhs);
}

void LiftoffAssembler::emit_f64x2_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  // Due to the way maxpd works, pmax(a, b) = maxpd(b, a).
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vmaxpd, &Assembler::maxpd>(
      this, dst, rhs, lhs);
}

void LiftoffAssembler::emit_f64x2_relaxed_min(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vminpd, &Assembler::minpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_relaxed_max(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vmaxpd, &Assembler::maxpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_convert_low_i32x4_s(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  Cvtdq2pd(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_f64x2_convert_low_i32x4_u(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  Register tmp = GetUnusedRegister(kGpReg, {}).gp();
  F64x2ConvertLowI32x4U(dst.fp(), src.fp(), tmp);
}

void LiftoffAssembler::emit_f64x2_promote_low_f32x4(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  Cvtps2pd(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_sconvert_f32x4(LiftoffRegister dst,
                     
"""


```