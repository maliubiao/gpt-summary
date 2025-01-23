Response:
The user wants to understand the functionality of the provided C++ header file. I need to analyze the code and identify its purpose. The file name `macro-assembler-shared-ia32-x64.h` suggests that it defines a macro assembler for IA32 and x64 architectures, likely containing shared functionalities.

Here's a plan to address the request:

1. **Identify core functionalities:**  Look for the primary operations defined within the class. Focus on the method names and their parameters.
2. **Relate to architecture-specific instructions:**  Note the use of instructions like `roundpd`, `maxps`, `pmaddwd`, `pshufb`, etc., which are specific to IA32/x64 SIMD extensions (SSE/AVX).
3. **Connect to potential JavaScript functionalities:** Infer how these low-level operations could be used to implement higher-level JavaScript features. WebAssembly (Wasm) is explicitly mentioned in some method names, making this connection stronger.
4. **Illustrate with JavaScript examples:** If a connection to JavaScript is found, provide simple JavaScript code snippets that could potentially rely on the underlying functionality defined in the header.
5. **Provide code logic reasoning (if applicable):** For some methods, like `I32x4TruncF32x4U`, explain the step-by-step logic, including assumptions and expected outputs.
6. **Identify common programming errors:** Think about potential pitfalls when using or implementing the kinds of operations found in the header.
7. **Summarize the overall functionality:** Condense the findings into a concise summary.
```cpp
double(),
                     tmp));
      roundpd(dst, dst, kRoundToZero);
      addpd(dst,
            ExternalReferenceAsOperand(
                ExternalReference::address_of_wasm_double_2_power_52(), tmp));
      shufps(dst, scratch, 0x88);
    }
  }

  void I32x4TruncF32x4U(XMMRegister dst, XMMRegister src, XMMRegister scratch1,
                        XMMRegister scratch2) {
    // NAN->0, negative->0.
    Pxor(scratch1, scratch1);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope scope(this, AVX);
      vmaxps(dst, src, scratch1);
    } else {
      if (dst != src) movaps(dst, src);
      maxps(dst, scratch1);
    }
    // scratch: float representation of max_signed.
    Pcmpeqd(scratch1, scratch1);
    Psrld(scratch1, uint8_t{1});   // 0x7fffffff
    Cvtdq2ps(scratch1, scratch1);  // 0x4f000000
    // scratch2: convert (src-max_signed).
    // Set positive overflow lanes to 0x7FFFFFFF.
    // Set negative lanes to 0.
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope scope(this, AVX);
      vsubps(scratch2, dst, scratch1);
    } else {
      movaps(scratch2, dst);
      subps(scratch2, scratch1);
    }
    Cmpleps(scratch1, scratch2);
    Cvttps2dq(scratch2, scratch2);
    Pxor(scratch2, scratch1);
    Pxor(scratch1, scratch1);
    Pmaxsd(scratch2, scratch1);
    // Convert to int. Overflow lanes above max_signed will be 0x80000000.
    Cvttps2dq(dst, dst);
    // Add (src-max_signed) for overflow lanes.
    Paddd(dst, scratch2);
  }

  void I32x4ExtAddPairwiseI16x8S(XMMRegister dst, XMMRegister src,
                                 Register scratch) {
    ASM_CODE_COMMENT(this);
    Operand op = ExternalReferenceAsOperand(
        ExternalReference::address_of_wasm_i16x8_splat_0x0001(), scratch);
    // pmaddwd multiplies signed words in src and op, producing
    // signed doublewords, then adds pairwise.
    // src = |a|b|c|d|e|f|g|h|
    // dst = | a*1 + b*1 | c*1 + d*1 | e*1 + f*1 | g*1 + h*1 |
    if (!CpuFeatures::IsSupported(AVX) && (dst != src)) {
      movaps(dst, src);
      src = dst;
    }

    Pmaddwd(dst, src, op);
  }

  void I16x8ExtAddPairwiseI8x16S(XMMRegister dst, XMMRegister src,
                                 XMMRegister scratch, Register tmp) {
    ASM_CODE_COMMENT(this);
    // pmaddubsw treats the first operand as unsigned, so pass the external
    // reference to it as the first operand.
    Operand op = ExternalReferenceAsOperand(
        ExternalReference::address_of_wasm_i8x16_splat_0x01(), tmp);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      vmovdqa(scratch, op);
      vpmaddubsw(dst, scratch, src);
    } else {
      CpuFeatureScope sse_scope(this, SSSE3);
      if (dst == src) {
        movaps(scratch, op);
        pmaddubsw(scratch, src);
        movaps(dst, scratch);
      } else {
        movaps(dst, op);
        pmaddubsw(dst, src);
      }
    }
  }

  void I16x8ExtAddPairwiseI8x16U(XMMRegister dst, XMMRegister src,
                                 Register scratch) {
    ASM_CODE_COMMENT(this);
    Operand op = ExternalReferenceAsOperand(
        ExternalReference::address_of_wasm_i8x16_splat_0x01(), scratch);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      vpmaddubsw(dst, src, op);
    } else {
      CpuFeatureScope sse_scope(this, SSSE3);
      if (dst != src) {
        movaps(dst, src);
      }
      pmaddubsw(dst, op);
    }
  }

  void I8x16Swizzle(XMMRegister dst, XMMRegister src, XMMRegister mask,
                    XMMRegister scratch, Register tmp, bool omit_add = false) {
    ASM_CODE_COMMENT(this);
    if (omit_add) {
      // We have determined that the indices are immediates, and they are either
      // within bounds, or the top bit is set, so we can omit the add.
      Pshufb(dst, src, mask);
      return;
    }

    // Out-of-range indices should return 0, add 112 so that any value > 15
    // saturates to 128 (top bit set), so pshufb will zero that lane.
    Operand op = ExternalReferenceAsOperand(
        ExternalReference::address_of_wasm_i8x16_swizzle_mask(), tmp);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      vpaddusb(scratch, mask, op);
      vpshufb(dst, src, scratch);
    } else {
      CpuFeatureScope sse_scope(this, SSSE3);
      movaps(scratch, op);
      if (dst != src) {
        DCHECK_NE(dst, mask);
        movaps(dst, src);
      }
      paddusb(scratch, mask);
      pshufb(dst, scratch);
    }
  }

  void I8x16Popcnt(XMMRegister dst, XMMRegister src, XMMRegister tmp1,
                   XMMRegister tmp2, Register scratch) {
    ASM_CODE_COMMENT(this);
    DCHECK_NE(dst, tmp1);
    DCHECK_NE(src, tmp1);
    DCHECK_NE(dst, tmp2);
    DCHECK_NE(src, tmp2);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      vmovdqa(tmp1, ExternalReferenceAsOperand(
                        ExternalReference::address_of_wasm_i8x16_splat_0x0f(),
                        scratch));
      vpandn(tmp2, tmp1, src);
      vpand(dst, tmp1, src);
      vmovdqa(tmp1, ExternalReferenceAsOperand(
                        ExternalReference::address_of_wasm_i8x16_popcnt_mask(),
                        scratch));
      vpsrlw(tmp2, tmp2, 4);
      vpshufb(dst, tmp1, dst);
      vpshufb(tmp2, tmp1, tmp2);
      vpaddb(dst, dst, tmp2);
    } else if (CpuFeatures::IsSupported(INTEL_ATOM)) {
      // Pre-Goldmont low-power Intel microarchitectures have very slow
      // PSHUFB instruction, thus use PSHUFB-free divide-and-conquer
      // algorithm on these processors. ATOM CPU feature captures exactly
      // the right set of processors.
      movaps(tmp1, src);
      psrlw(tmp1, 1);
      if (dst != src) {
        movaps(dst, src);
      }
      andps(tmp1, ExternalReferenceAsOperand(
                      ExternalReference::address_of_wasm_i8x16_splat_0x55(),
                      scratch));
      psubb(dst, tmp1);
      Operand splat_0x33 = ExternalReferenceAsOperand(
          ExternalReference::address_of_wasm_i8x16_splat_0x33(), scratch);
      movaps(tmp1, dst);
      andps(dst, splat_0x33);
      psrlw(tmp1, 2);
      andps(tmp1, splat_0x33);
      paddb(dst, tmp1);
      movaps(tmp1, dst);
      psrlw(dst, 4);
      paddb(dst, tmp1);
      andps(dst, ExternalReferenceAsOperand(
                     ExternalReference::address_of_wasm_i8x16_splat_0x0f(),
                     scratch));
    } else {
      CpuFeatureScope sse_scope(this, SSSE3);
      movaps(tmp1, ExternalReferenceAsOperand(
                       ExternalReference::address_of_wasm_i8x16_splat_0x0f(),
                       scratch));
      Operand mask = ExternalReferenceAsOperand(
          ExternalReference::address_of_wasm_i8x16_popcnt_mask(), scratch);
      if (tmp2 != tmp1) {
        movaps(tmp2, tmp1);
      }
      andps(tmp1, src);
      andnps(tmp2, src);
      psrlw(tmp2, 4);
      movaps(dst, mask);
      pshufb(dst, tmp1);
      movaps(tmp1, mask);
      pshufb(tmp1, tmp2);
      paddb(dst, tmp1);
    }
  }

 private:
  // All implementation-specific methods must be called through this.
  Impl* impl() { return static_cast<Impl*>(this); }

  Operand ExternalReferenceAsOperand(ExternalReference reference,
                                     Register scratch) {
    return impl()->ExternalReferenceAsOperand(reference, scratch);
  }

  using FloatInstruction = void (SharedMacroAssemblerBase::*)(XMMRegister,
                                                              XMMRegister,
                                                              Operand);
  void FloatUnop(XMMRegister dst, XMMRegister src, Register tmp,
                 FloatInstruction op, ExternalReference ext) {
    if (!CpuFeatures::IsSupported(AVX) && (dst != src)) {
      movaps(dst, src);
      src = dst;
    }
    SharedMacroAssemblerBase* assm = this;
    (assm->*op)(dst, src, ExternalReferenceAsOperand(ext, tmp));
  }
};

}  // namespace internal
}  // namespace v8
#endif  // V8_CODEGEN_SHARED_IA32_X64_MACRO_ASSEMBLER_SHARED_IA32_X64_H_
```

这是 `v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h` 文件的第二部分代码，延续了第一部分的功能，主要提供了一系列用于生成 IA-32 和 x64 架构机器码的宏指令（high-level instructions）。这些宏指令封装了底层的汇编指令，使得代码生成器可以更方便地进行操作。

**功能归纳:**

这部分代码主要定义了以下功能的宏指令，特别关注了 SIMD (Single Instruction, Multiple Data) 操作，常用于处理向量数据：

1. **浮点数处理:**
   - `DoubleToI32RoundToZero`: 将双精度浮点数转换为 32 位整数，采用向零取整的方式。它还处理了超出 32 位整数范围的情况，将其限制在最小值或最大值。
   - `I32x4TruncF32x4U`: 将单精度浮点数向量转换为无符号 32 位整数向量，处理了 NAN (Not a Number) 和负数的情况，将它们转换为 0。

2. **向量加法:**
   - `I32x4ExtAddPairwiseI16x8S`:  将 16 位有符号整数向量的相邻元素进行成对相加，并将结果存储到 32 位整数向量中。
   - `I16x8ExtAddPairwiseI8x16S`: 将 8 位有符号整数向量的相邻元素进行成对相加，并将结果存储到 16 位整数向量中。
   - `I16x8ExtAddPairwiseI8x16U`: 将 8 位无符号整数向量的相邻元素进行成对相加，并将结果存储到 16 位整数向量中。

3. **向量数据重排:**
   - `I8x16Swizzle`:  根据一个索引掩码（mask）对 8 位整数向量的元素进行重新排列。如果索引超出范围，则对应位置的结果为 0。

4. **向量位运算:**
   - `I8x16Popcnt`: 计算 8 位整数向量中每个字节的 popcount (population count，即二进制表示中 1 的个数)。针对不同的 CPU 特性（如 AVX 和 Intel Atom）使用了不同的优化实现。

**关于 .tq 结尾的文件:**

如果 `v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。 Torque 是一种用于 V8 内部的类型安全的代码生成 DSL (Domain Specific Language)。 Torque 代码会被编译成 C++ 代码。这个文件当前是 `.h` 结尾，所以它是 C++ 头文件。

**与 JavaScript 的关系及示例:**

这些底层的宏指令直接支持了 JavaScript 中一些高级特性和 WebAssembly 的实现。

例如，`I32x4TruncF32x4U` 功能与 JavaScript 中对 Typed Arrays (特别是 `Uint32ClampedArray`) 的操作，以及 WebAssembly 中将浮点数转换为整数的操作密切相关。

```javascript
// JavaScript 示例 (可能在底层使用了类似 I32x4TruncF32x4U 的操作)
const floatArray = new Float32Array([3.14, -1.5, NaN, 10000000000]);
const uint32Array = new Uint32Array(floatArray.length);

for (let i = 0; i < floatArray.length; i++) {
  uint32Array[i] = Math.trunc(floatArray[i] < 0 || isNaN(floatArray[i]) ? 0 : floatArray[i]);
}

console.log(uint32Array); // 输出类似：Uint32Array [ 3, 0, 0, 10000000000 ]
```

`I8x16Popcnt` 功能支持了 JavaScript 中对二进制数据进行操作，以及 WebAssembly 中 `i8x16.popcnt` 指令的实现。

```javascript
// JavaScript 示例 (可能在底层使用了类似 I8x16Popcnt 的操作)
const buffer = new Uint8Array([0b01010101, 0b11110000, 0b00000000]);
let popcounts = [];
for (const byte of buffer) {
  let count = 0;
  for (let i = 0; i < 8; i++) {
    if ((byte >> i) & 1) {
      count++;
    }
  }
  popcounts.push(count);
}
console.log(popcounts); // 输出: [ 4, 4, 0 ]
```

**代码逻辑推理示例 (以 `I32x4TruncF32x4U` 为例):**

**假设输入:**

`src` (XMMRegister): 包含四个单精度浮点数，例如 `[3.14, -1.5, NaN, 1.9]`。

**输出:**

`dst` (XMMRegister): 包含四个无符号 32 位整数，对应于输入浮点数的截断结果。

**逻辑步骤:**

1. **处理 NAN 和负数:** 如果输入是 NAN 或负数，则结果为 0。
2. **限制正溢出:** 如果输入大于有符号 32 位整数的最大值，则结果会被限制在最大值。代码中通过与最大有符号整数进行比较和操作来实现。
3. **截断:** 使用 `cvttps2dq` 指令将浮点数转换为整数，采用截断方式（向零取整）。
4. **处理溢出:** 对于正溢出的情况，需要进行额外的处理，通过减去最大有符号整数并进行调整来得到正确的结果。

**假设输入 `src` 的值为 `[3.14, -1.5, NaN, 4294967295.9]` (最后一个值接近无符号 32 位整数的最大值):**

* `3.14` 会被截断为 `3`。
* `-1.5` 是负数，会被转换为 `0`。
* `NaN` 会被转换为 `0`。
* `4294967295.9` 超过了有符号 32 位整数的最大值，但 `I32x4TruncF32x4U` 旨在转换为无符号整数，其逻辑会将其处理为接近无符号最大值的值，但具体的行为取决于底层的指令和溢出处理。

**常见的编程错误举例:**

1. **类型不匹配:**  错误地将整数作为浮点数指令的输入，或者反之。例如，尝试用 `addpd` (用于双精度浮点数) 操作整数寄存器。
2. **寄存器冲突:**  在宏指令的参数中使用了相同的寄存器作为源和目标，而该宏指令的实现并不支持原地操作，导致数据被意外覆盖。 这在没有 AVX 指令的情况下更容易发生，因为很多 SSE 指令需要显式地 `movaps` 来复制数据。
3. **没有考虑 NAN 和特殊值:** 在处理浮点数时，没有正确处理 NAN、正负无穷大等特殊值，导致程序出现意外行为或崩溃。例如，在没有 `// NAN->0, negative->0.` 这样的显式处理的情况下，直接截断 NAN 可能会得到不可预测的结果。
4. **假设特定的 CPU 特性:**  编写的代码依赖于特定的 CPU 特性（如 AVX），但在运行时没有检查这些特性是否可用，导致在不支持的 CPU 上崩溃或产生错误结果。 代码中使用了 `CpuFeatures::IsSupported(AVX)` 进行检查，但如果开发者忘记进行这样的检查，就会出错。

总而言之，这部分代码是 V8 引擎中用于代码生成的重要组成部分，它提供了操作向量数据的底层能力，这些能力支撑了 JavaScript 的高级特性和 WebAssembly 的高效执行。理解这些宏指令的功能有助于深入理解 V8 引擎的工作原理。

### 提示词
```
这是目录为v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
double(),
                     tmp));
      roundpd(dst, dst, kRoundToZero);
      addpd(dst,
            ExternalReferenceAsOperand(
                ExternalReference::address_of_wasm_double_2_power_52(), tmp));
      shufps(dst, scratch, 0x88);
    }
  }

  void I32x4TruncF32x4U(XMMRegister dst, XMMRegister src, XMMRegister scratch1,
                        XMMRegister scratch2) {
    // NAN->0, negative->0.
    Pxor(scratch1, scratch1);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope scope(this, AVX);
      vmaxps(dst, src, scratch1);
    } else {
      if (dst != src) movaps(dst, src);
      maxps(dst, scratch1);
    }
    // scratch: float representation of max_signed.
    Pcmpeqd(scratch1, scratch1);
    Psrld(scratch1, uint8_t{1});   // 0x7fffffff
    Cvtdq2ps(scratch1, scratch1);  // 0x4f000000
    // scratch2: convert (src-max_signed).
    // Set positive overflow lanes to 0x7FFFFFFF.
    // Set negative lanes to 0.
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope scope(this, AVX);
      vsubps(scratch2, dst, scratch1);
    } else {
      movaps(scratch2, dst);
      subps(scratch2, scratch1);
    }
    Cmpleps(scratch1, scratch2);
    Cvttps2dq(scratch2, scratch2);
    Pxor(scratch2, scratch1);
    Pxor(scratch1, scratch1);
    Pmaxsd(scratch2, scratch1);
    // Convert to int. Overflow lanes above max_signed will be 0x80000000.
    Cvttps2dq(dst, dst);
    // Add (src-max_signed) for overflow lanes.
    Paddd(dst, scratch2);
  }

  void I32x4ExtAddPairwiseI16x8S(XMMRegister dst, XMMRegister src,
                                 Register scratch) {
    ASM_CODE_COMMENT(this);
    Operand op = ExternalReferenceAsOperand(
        ExternalReference::address_of_wasm_i16x8_splat_0x0001(), scratch);
    // pmaddwd multiplies signed words in src and op, producing
    // signed doublewords, then adds pairwise.
    // src = |a|b|c|d|e|f|g|h|
    // dst = | a*1 + b*1 | c*1 + d*1 | e*1 + f*1 | g*1 + h*1 |
    if (!CpuFeatures::IsSupported(AVX) && (dst != src)) {
      movaps(dst, src);
      src = dst;
    }

    Pmaddwd(dst, src, op);
  }

  void I16x8ExtAddPairwiseI8x16S(XMMRegister dst, XMMRegister src,
                                 XMMRegister scratch, Register tmp) {
    ASM_CODE_COMMENT(this);
    // pmaddubsw treats the first operand as unsigned, so pass the external
    // reference to it as the first operand.
    Operand op = ExternalReferenceAsOperand(
        ExternalReference::address_of_wasm_i8x16_splat_0x01(), tmp);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      vmovdqa(scratch, op);
      vpmaddubsw(dst, scratch, src);
    } else {
      CpuFeatureScope sse_scope(this, SSSE3);
      if (dst == src) {
        movaps(scratch, op);
        pmaddubsw(scratch, src);
        movaps(dst, scratch);
      } else {
        movaps(dst, op);
        pmaddubsw(dst, src);
      }
    }
  }

  void I16x8ExtAddPairwiseI8x16U(XMMRegister dst, XMMRegister src,
                                 Register scratch) {
    ASM_CODE_COMMENT(this);
    Operand op = ExternalReferenceAsOperand(
        ExternalReference::address_of_wasm_i8x16_splat_0x01(), scratch);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      vpmaddubsw(dst, src, op);
    } else {
      CpuFeatureScope sse_scope(this, SSSE3);
      if (dst != src) {
        movaps(dst, src);
      }
      pmaddubsw(dst, op);
    }
  }

  void I8x16Swizzle(XMMRegister dst, XMMRegister src, XMMRegister mask,
                    XMMRegister scratch, Register tmp, bool omit_add = false) {
    ASM_CODE_COMMENT(this);
    if (omit_add) {
      // We have determined that the indices are immediates, and they are either
      // within bounds, or the top bit is set, so we can omit the add.
      Pshufb(dst, src, mask);
      return;
    }

    // Out-of-range indices should return 0, add 112 so that any value > 15
    // saturates to 128 (top bit set), so pshufb will zero that lane.
    Operand op = ExternalReferenceAsOperand(
        ExternalReference::address_of_wasm_i8x16_swizzle_mask(), tmp);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      vpaddusb(scratch, mask, op);
      vpshufb(dst, src, scratch);
    } else {
      CpuFeatureScope sse_scope(this, SSSE3);
      movaps(scratch, op);
      if (dst != src) {
        DCHECK_NE(dst, mask);
        movaps(dst, src);
      }
      paddusb(scratch, mask);
      pshufb(dst, scratch);
    }
  }

  void I8x16Popcnt(XMMRegister dst, XMMRegister src, XMMRegister tmp1,
                   XMMRegister tmp2, Register scratch) {
    ASM_CODE_COMMENT(this);
    DCHECK_NE(dst, tmp1);
    DCHECK_NE(src, tmp1);
    DCHECK_NE(dst, tmp2);
    DCHECK_NE(src, tmp2);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      vmovdqa(tmp1, ExternalReferenceAsOperand(
                        ExternalReference::address_of_wasm_i8x16_splat_0x0f(),
                        scratch));
      vpandn(tmp2, tmp1, src);
      vpand(dst, tmp1, src);
      vmovdqa(tmp1, ExternalReferenceAsOperand(
                        ExternalReference::address_of_wasm_i8x16_popcnt_mask(),
                        scratch));
      vpsrlw(tmp2, tmp2, 4);
      vpshufb(dst, tmp1, dst);
      vpshufb(tmp2, tmp1, tmp2);
      vpaddb(dst, dst, tmp2);
    } else if (CpuFeatures::IsSupported(INTEL_ATOM)) {
      // Pre-Goldmont low-power Intel microarchitectures have very slow
      // PSHUFB instruction, thus use PSHUFB-free divide-and-conquer
      // algorithm on these processors. ATOM CPU feature captures exactly
      // the right set of processors.
      movaps(tmp1, src);
      psrlw(tmp1, 1);
      if (dst != src) {
        movaps(dst, src);
      }
      andps(tmp1, ExternalReferenceAsOperand(
                      ExternalReference::address_of_wasm_i8x16_splat_0x55(),
                      scratch));
      psubb(dst, tmp1);
      Operand splat_0x33 = ExternalReferenceAsOperand(
          ExternalReference::address_of_wasm_i8x16_splat_0x33(), scratch);
      movaps(tmp1, dst);
      andps(dst, splat_0x33);
      psrlw(tmp1, 2);
      andps(tmp1, splat_0x33);
      paddb(dst, tmp1);
      movaps(tmp1, dst);
      psrlw(dst, 4);
      paddb(dst, tmp1);
      andps(dst, ExternalReferenceAsOperand(
                     ExternalReference::address_of_wasm_i8x16_splat_0x0f(),
                     scratch));
    } else {
      CpuFeatureScope sse_scope(this, SSSE3);
      movaps(tmp1, ExternalReferenceAsOperand(
                       ExternalReference::address_of_wasm_i8x16_splat_0x0f(),
                       scratch));
      Operand mask = ExternalReferenceAsOperand(
          ExternalReference::address_of_wasm_i8x16_popcnt_mask(), scratch);
      if (tmp2 != tmp1) {
        movaps(tmp2, tmp1);
      }
      andps(tmp1, src);
      andnps(tmp2, src);
      psrlw(tmp2, 4);
      movaps(dst, mask);
      pshufb(dst, tmp1);
      movaps(tmp1, mask);
      pshufb(tmp1, tmp2);
      paddb(dst, tmp1);
    }
  }

 private:
  // All implementation-specific methods must be called through this.
  Impl* impl() { return static_cast<Impl*>(this); }

  Operand ExternalReferenceAsOperand(ExternalReference reference,
                                     Register scratch) {
    return impl()->ExternalReferenceAsOperand(reference, scratch);
  }

  using FloatInstruction = void (SharedMacroAssemblerBase::*)(XMMRegister,
                                                              XMMRegister,
                                                              Operand);
  void FloatUnop(XMMRegister dst, XMMRegister src, Register tmp,
                 FloatInstruction op, ExternalReference ext) {
    if (!CpuFeatures::IsSupported(AVX) && (dst != src)) {
      movaps(dst, src);
      src = dst;
    }
    SharedMacroAssemblerBase* assm = this;
    (assm->*op)(dst, src, ExternalReferenceAsOperand(ext, tmp));
  }
};

}  // namespace internal
}  // namespace v8
#endif  // V8_CODEGEN_SHARED_IA32_X64_MACRO_ASSEMBLER_SHARED_IA32_X64_H_
```