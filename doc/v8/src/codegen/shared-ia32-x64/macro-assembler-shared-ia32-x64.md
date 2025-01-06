Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality and relation to JavaScript.

1. **Understanding the Goal:** The request asks for a summary of the C++ code's functionality and how it relates to JavaScript, including an example. This means we need to understand *what* the code does at a higher level and *why* it exists in the context of V8.

2. **Initial Scan for Keywords and Structure:**  A quick scan reveals important keywords and structural elements:
    * `Copyright 2021 the V8 project authors`: This immediately tells us it's part of the V8 JavaScript engine.
    * `#include`:  Indicates dependencies on other V8 components.
    * `V8_TARGET_ARCH_IA32`, `V8_TARGET_ARCH_X64`: Conditional compilation based on architecture (32-bit vs. 64-bit).
    * `namespace v8 { namespace internal {`:  Standard C++ namespacing for V8 internals.
    * `class SharedMacroAssemblerBase`:  The core class of this file. "MacroAssembler" strongly suggests code generation or low-level instruction manipulation. "Shared" implies it's used across both IA32 and x64 architectures.
    * Function definitions like `Move`, `Add`, `And`, `Movhps`, `Movlps`, `Blendvpd`, etc. These function names look like assembly language instructions.
    * Use of `Register`, `XMMRegister`, `Operand`, `Immediate`:  These are likely abstractions representing CPU registers and memory operands.
    * Conditional checks using `CpuFeatures::IsSupported(AVX)`, `CpuFeatures::IsSupported(SSE4_1)`, etc.:  Indicates the code is optimized for different CPU instruction set extensions.

3. **Deduction of Core Functionality:** Based on the keywords and structure, the primary function seems to be providing a **platform-agnostic interface for generating machine code instructions for both IA32 and x64 architectures**. The "Shared" part is crucial – it abstracts away the differences between the instruction sets.

4. **Analyzing Key Function Examples:**  Let's look at a few representative functions:

    * **`Move(Register dst, uint32_t src)` and `Move(Register dst, Register src)`:**  These are simple move operations. The conditional compilation handles the different mnemonics (`mov` vs. `movl`/`movq`) and operand sizes. This reinforces the idea of an abstraction layer.

    * **`Movhps(XMMRegister dst, XMMRegister src1, Operand src2)`:**  This involves XMM registers and conditional logic based on CPU features (AVX). This suggests handling of Single Instruction Multiple Data (SIMD) operations, which are important for performance. The fallback mechanism when AVX isn't available indicates a focus on ensuring the functionality works across different hardware.

    * **Functions with `Blendvpd`, `Blendvps`, `Pblendvb`, `Shufps`, `F64x2ExtractLane`, etc.:**  These names are more specialized and point towards specific SIMD instructions for various data types (doubles, floats, packed bytes).

5. **Connecting to JavaScript:** Now, how does this relate to JavaScript?  V8 is the engine that *executes* JavaScript. To do so efficiently, it needs to translate JavaScript code into machine code. This file likely plays a role in that translation process.

    * **Just-In-Time (JIT) Compilation:** V8 uses JIT compilation. This means it dynamically generates machine code at runtime. The `SharedMacroAssemblerBase` provides the building blocks for this code generation.

    * **Optimization:** The use of SIMD instructions and CPU feature detection is all about performance optimization. JavaScript relies heavily on these optimizations to run complex code quickly.

    * **Internal Representation:** While JavaScript doesn't directly map to these assembly instructions, V8's *internal representation* of JavaScript values (numbers, objects, etc.) and operations will eventually be translated into these low-level operations.

6. **Crafting the JavaScript Example:** To illustrate the connection, we need to show a JavaScript operation that would likely involve some of the functionality provided by this C++ file. Good candidates are:

    * **Basic Arithmetic:**  `+`, `-`, `*`, `/` on numbers.
    * **Array Operations:**  Especially when dealing with large numerical arrays where SIMD can be beneficial.
    * **Typed Arrays:** These map more directly to the kinds of data structures handled by SIMD instructions.
    * **WebAssembly (Wasm):** Wasm has explicit SIMD instructions, making the connection even clearer.

    The example I chose focuses on array manipulation and highlights how a seemingly simple JavaScript operation might be implemented using SIMD instructions under the hood. Specifically, adding corresponding elements of two arrays is a classic use case for SIMD.

7. **Structuring the Explanation:** Finally, the explanation should be organized logically:

    * **Summary of Functionality:** Start with a high-level overview.
    * **Relationship to JavaScript:** Explain the role of the code in the V8 engine.
    * **Elaborate on Key Aspects:**  Mention the architecture abstraction, SIMD support, and CPU feature detection.
    * **JavaScript Example:** Provide a concrete example with explanation.
    * **Important Considerations:** Add clarifying points about direct mapping and internal complexity.

8. **Refinement and Language:** Use clear and concise language. Avoid overly technical jargon where possible, or explain it if necessary. Emphasize the "abstraction" and "optimization" aspects.

By following these steps, we can effectively analyze the C++ code and explain its purpose and relevance to JavaScript. The process involves understanding the code's structure, identifying key functionalities, connecting those functionalities to the broader context of V8 and JavaScript execution, and then illustrating the connection with a relevant example.
这个 C++ 源代码文件 `macro-assembler-shared-ia32-x64.cc` 的主要功能是为 V8 JavaScript 引擎提供一个**共享的、跨 IA-32 (x86) 和 x64 架构的宏汇编器基类** (`SharedMacroAssemblerBase`) 的实现。

**核心功能归纳:**

1. **提供架构抽象层:**  该文件定义了一个基类，封装了 IA-32 和 x64 两种架构下常用的汇编指令操作。通过条件编译 (`#if V8_TARGET_ARCH_IA32` 和 `#elif V8_TARGET_ARCH_X64`)，它能够根据目标架构选择正确的汇编指令助记符。例如，`Move` 函数在 IA-32 下调用 `mov`，在 x64 下调用 `movl` 或 `movq`。

2. **简化汇编代码生成:** 宏汇编器提供了一组高级的 C++ 接口，方便 V8 引擎的其他组件生成机器码。开发者可以使用 `Move`、`Add`、`And` 等函数，而无需直接编写原始的汇编指令，也无需关心不同架构的细节。

3. **支持 SIMD 指令 (SSE, AVX 等):** 文件中包含了大量处理 SIMD (单指令多数据流) 寄存器 (如 `XMMRegister`) 和指令的函数，例如 `Movhps`、`Movlps`、`Blendvpd`、`Shufps` 等。这些函数针对不同的 CPU 特性 (如 AVX, SSE4.1) 进行了优化，以提高性能。

4. **实现向量 (SIMD) 操作的抽象:**  该文件还实现了许多针对向量数据类型的操作，例如 `F32x4Min` (四个单精度浮点数的最小值)、`I8x16Splat` (将一个字节值广播到 16 字节的向量中)、`I16x8ExtMulLow` (八个 16 位整数的低位乘法) 等。这些操作为 JavaScript 中的 SIMD API (如 `Float32x4`, `Int8x16`) 提供了底层的实现支持。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个 C++ 文件与 JavaScript 的性能息息相关，因为它直接参与了 V8 引擎将 JavaScript 代码编译成高效机器码的过程。尤其是对于需要高性能计算的 JavaScript 代码，例如：

* **图形处理:** 使用 WebGL 或 Canvas 涉及到大量的向量和矩阵运算。
* **音频处理:** 处理音频数据通常需要进行 SIMD 操作。
* **科学计算:**  JavaScript 也可以用于科学计算，SIMD 指令可以显著加速计算密集型任务。
* **WebAssembly (Wasm):** WebAssembly 提供了对 SIMD 指令的直接访问，而 V8 引擎需要利用底层的汇编器来生成相应的机器码。

**JavaScript 示例:**

考虑以下使用 JavaScript SIMD API 的例子：

```javascript
const a = Float32x4(1.0, 2.0, 3.0, 4.0);
const b = Float32x4(5.0, 6.0, 7.0, 8.0);

// 对两个 Float32x4 向量进行加法运算
const sum = a.add(b);

console.log(sum.x, sum.y, sum.z, sum.w); // 输出 6, 8, 10, 12
```

在这个 JavaScript 例子中，`Float32x4` 代表一个包含四个单精度浮点数的向量。当 V8 引擎执行 `a.add(b)` 这个操作时，底层的实现很可能会调用 `macro-assembler-shared-ia32-x64.cc` 文件中提供的 SIMD 指令封装。

例如，如果目标架构支持 AVX，V8 可能会调用 `SharedMacroAssemblerBase` 中的某个函数，最终生成类似 `vaddps` (AVX 的单精度浮点数加法指令) 的机器码，从而实现高效的向量加法。

**更具体的例子 (假设 `F32x4Add` 是 `SharedMacroAssemblerBase` 中实现的函数):**

在 V8 的编译流程中，当遇到上述 JavaScript 代码时，编译器可能会生成类似以下的 C++ 代码来调用宏汇编器：

```c++
// 假设 lhs_reg 和 rhs_reg 分别是存储 a 和 b 的 XMM 寄存器
// 假设 result_reg 是用于存储结果的 XMM 寄存器
macro_assembler->F32x4Add(result_reg, lhs_reg, rhs_reg);
```

这里的 `macro_assembler` 是 `SharedMacroAssemblerBase` 的一个实例。`F32x4Add` 函数会根据目标架构选择合适的汇编指令 (例如 `addps` 在 SSE 下，`vaddps` 在 AVX 下) 来完成向量加法操作。

**总结:**

`macro-assembler-shared-ia32-x64.cc` 文件是 V8 引擎中一个非常重要的底层组件，它通过提供一个共享的宏汇编器基类，屏蔽了不同 CPU 架构的差异，并为 JavaScript 的高性能执行提供了基础支持，特别是对于 SIMD 相关的操作。JavaScript 开发者虽然不会直接接触到这个文件，但其编写的代码的性能很大程度上依赖于像这样的底层实现的效率。

Prompt: 
```
这是目录为v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h"

#include "src/codegen/assembler.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/register.h"

#if V8_TARGET_ARCH_IA32
#include "src/codegen/ia32/register-ia32.h"
#elif V8_TARGET_ARCH_X64
#include "src/codegen/x64/register-x64.h"
#else
#error Unsupported target architecture.
#endif

// Operand on IA32 can be a wrapper for a single register, in which case they
// should call I8x16Splat |src| being Register.
#if V8_TARGET_ARCH_IA32
#define DCHECK_OPERAND_IS_NOT_REG(op) DCHECK(!op.is_reg_only());
#else
#define DCHECK_OPERAND_IS_NOT_REG(op)
#endif

namespace v8 {
namespace internal {

void SharedMacroAssemblerBase::Move(Register dst, uint32_t src) {
  // Helper to paper over the different assembler function names.
#if V8_TARGET_ARCH_IA32
  mov(dst, Immediate(src));
#elif V8_TARGET_ARCH_X64
  movl(dst, Immediate(src));
#else
#error Unsupported target architecture.
#endif
}

void SharedMacroAssemblerBase::Move(Register dst, Register src) {
  // Helper to paper over the different assembler function names.
  if (dst != src) {
#if V8_TARGET_ARCH_IA32
    mov(dst, src);
#elif V8_TARGET_ARCH_X64
    movq(dst, src);
#else
#error Unsupported target architecture.
#endif
  }
}

void SharedMacroAssemblerBase::Add(Register dst, Immediate src) {
  // Helper to paper over the different assembler function names.
#if V8_TARGET_ARCH_IA32
  add(dst, src);
#elif V8_TARGET_ARCH_X64
  addq(dst, src);
#else
#error Unsupported target architecture.
#endif
}

void SharedMacroAssemblerBase::And(Register dst, Immediate src) {
  // Helper to paper over the different assembler function names.
#if V8_TARGET_ARCH_IA32
  and_(dst, src);
#elif V8_TARGET_ARCH_X64
  if (is_uint32(src.value())) {
    andl(dst, src);
  } else {
    andq(dst, src);
  }
#else
#error Unsupported target architecture.
#endif
}

void SharedMacroAssemblerBase::Movhps(XMMRegister dst, XMMRegister src1,
                                      Operand src2) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vmovhps(dst, src1, src2);
  } else {
    if (dst != src1) {
      movaps(dst, src1);
    }
    movhps(dst, src2);
  }
}

void SharedMacroAssemblerBase::Movlps(XMMRegister dst, XMMRegister src1,
                                      Operand src2) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vmovlps(dst, src1, src2);
  } else {
    if (dst != src1) {
      movaps(dst, src1);
    }
    movlps(dst, src2);
  }
}
void SharedMacroAssemblerBase::Blendvpd(XMMRegister dst, XMMRegister src1,
                                        XMMRegister src2, XMMRegister mask) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vblendvpd(dst, src1, src2, mask);
  } else {
    CpuFeatureScope scope(this, SSE4_1);
    DCHECK_EQ(mask, xmm0);
    DCHECK_EQ(dst, src1);
    blendvpd(dst, src2);
  }
}

void SharedMacroAssemblerBase::Blendvps(XMMRegister dst, XMMRegister src1,
                                        XMMRegister src2, XMMRegister mask) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vblendvps(dst, src1, src2, mask);
  } else {
    CpuFeatureScope scope(this, SSE4_1);
    DCHECK_EQ(mask, xmm0);
    DCHECK_EQ(dst, src1);
    blendvps(dst, src2);
  }
}

void SharedMacroAssemblerBase::Pblendvb(XMMRegister dst, XMMRegister src1,
                                        XMMRegister src2, XMMRegister mask) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vpblendvb(dst, src1, src2, mask);
  } else {
    CpuFeatureScope scope(this, SSE4_1);
    DCHECK_EQ(mask, xmm0);
    DCHECK_EQ(dst, src1);
    pblendvb(dst, src2);
  }
}

void SharedMacroAssemblerBase::Shufps(XMMRegister dst, XMMRegister src1,
                                      XMMRegister src2, uint8_t imm8) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vshufps(dst, src1, src2, imm8);
  } else {
    if (dst != src1) {
      movaps(dst, src1);
    }
    shufps(dst, src2, imm8);
  }
}

void SharedMacroAssemblerBase::F64x2ExtractLane(DoubleRegister dst,
                                                XMMRegister src, uint8_t lane) {
  ASM_CODE_COMMENT(this);
  if (lane == 0) {
    if (dst != src) {
      Movaps(dst, src);
    }
  } else {
    DCHECK_EQ(1, lane);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      // Pass src as operand to avoid false-dependency on dst.
      vmovhlps(dst, src, src);
    } else {
      movhlps(dst, src);
    }
  }
}

void SharedMacroAssemblerBase::F64x2ReplaceLane(XMMRegister dst,
                                                XMMRegister src,
                                                DoubleRegister rep,
                                                uint8_t lane) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    if (lane == 0) {
      vmovsd(dst, src, rep);
    } else {
      vmovlhps(dst, src, rep);
    }
  } else {
    CpuFeatureScope scope(this, SSE4_1);
    if (dst != src) {
      DCHECK_NE(dst, rep);  // Ensure rep is not overwritten.
      movaps(dst, src);
    }
    if (lane == 0) {
      movsd(dst, rep);
    } else {
      movlhps(dst, rep);
    }
  }
}

void SharedMacroAssemblerBase::F32x4Min(XMMRegister dst, XMMRegister lhs,
                                        XMMRegister rhs, XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  // The minps instruction doesn't propagate NaNs and +0's in its first
  // operand. Perform minps in both orders, merge the results, and adjust.
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vminps(scratch, lhs, rhs);
    vminps(dst, rhs, lhs);
  } else if (dst == lhs || dst == rhs) {
    XMMRegister src = dst == lhs ? rhs : lhs;
    movaps(scratch, src);
    minps(scratch, dst);
    minps(dst, src);
  } else {
    movaps(scratch, lhs);
    minps(scratch, rhs);
    movaps(dst, rhs);
    minps(dst, lhs);
  }
  // Propagate -0's and NaNs, which may be non-canonical.
  Orps(scratch, dst);
  // Canonicalize NaNs by quieting and clearing the payload.
  Cmpunordps(dst, dst, scratch);
  Orps(scratch, dst);
  Psrld(dst, dst, uint8_t{10});
  Andnps(dst, dst, scratch);
}

void SharedMacroAssemblerBase::F32x4Max(XMMRegister dst, XMMRegister lhs,
                                        XMMRegister rhs, XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  // The maxps instruction doesn't propagate NaNs and +0's in its first
  // operand. Perform maxps in both orders, merge the results, and adjust.
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vmaxps(scratch, lhs, rhs);
    vmaxps(dst, rhs, lhs);
  } else if (dst == lhs || dst == rhs) {
    XMMRegister src = dst == lhs ? rhs : lhs;
    movaps(scratch, src);
    maxps(scratch, dst);
    maxps(dst, src);
  } else {
    movaps(scratch, lhs);
    maxps(scratch, rhs);
    movaps(dst, rhs);
    maxps(dst, lhs);
  }
  // Find discrepancies.
  Xorps(dst, scratch);
  // Propagate NaNs, which may be non-canonical.
  Orps(scratch, dst);
  // Propagate sign discrepancy and (subtle) quiet NaNs.
  Subps(scratch, scratch, dst);
  // Canonicalize NaNs by clearing the payload. Sign is non-deterministic.
  Cmpunordps(dst, dst, scratch);
  Psrld(dst, dst, uint8_t{10});
  Andnps(dst, dst, scratch);
}

void SharedMacroAssemblerBase::F64x2Min(XMMRegister dst, XMMRegister lhs,
                                        XMMRegister rhs, XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    // The minpd instruction doesn't propagate NaNs and +0's in its first
    // operand. Perform minpd in both orders, merge the resuls, and adjust.
    vminpd(scratch, lhs, rhs);
    vminpd(dst, rhs, lhs);
    // propagate -0's and NaNs, which may be non-canonical.
    vorpd(scratch, scratch, dst);
    // Canonicalize NaNs by quieting and clearing the payload.
    vcmpunordpd(dst, dst, scratch);
    vorpd(scratch, scratch, dst);
    vpsrlq(dst, dst, uint8_t{13});
    vandnpd(dst, dst, scratch);
  } else {
    // Compare lhs with rhs, and rhs with lhs, and have the results in scratch
    // and dst. If dst overlaps with lhs or rhs, we can save a move.
    if (dst == lhs || dst == rhs) {
      XMMRegister src = dst == lhs ? rhs : lhs;
      movaps(scratch, src);
      minpd(scratch, dst);
      minpd(dst, src);
    } else {
      movaps(scratch, lhs);
      movaps(dst, rhs);
      minpd(scratch, rhs);
      minpd(dst, lhs);
    }
    orpd(scratch, dst);
    cmpunordpd(dst, scratch);
    orpd(scratch, dst);
    psrlq(dst, uint8_t{13});
    andnpd(dst, scratch);
  }
}

void SharedMacroAssemblerBase::F64x2Max(XMMRegister dst, XMMRegister lhs,
                                        XMMRegister rhs, XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    // The maxpd instruction doesn't propagate NaNs and +0's in its first
    // operand. Perform maxpd in both orders, merge the resuls, and adjust.
    vmaxpd(scratch, lhs, rhs);
    vmaxpd(dst, rhs, lhs);
    // Find discrepancies.
    vxorpd(dst, dst, scratch);
    // Propagate NaNs, which may be non-canonical.
    vorpd(scratch, scratch, dst);
    // Propagate sign discrepancy and (subtle) quiet NaNs.
    vsubpd(scratch, scratch, dst);
    // Canonicalize NaNs by clearing the payload. Sign is non-deterministic.
    vcmpunordpd(dst, dst, scratch);
    vpsrlq(dst, dst, uint8_t{13});
    vandnpd(dst, dst, scratch);
  } else {
    if (dst == lhs || dst == rhs) {
      XMMRegister src = dst == lhs ? rhs : lhs;
      movaps(scratch, src);
      maxpd(scratch, dst);
      maxpd(dst, src);
    } else {
      movaps(scratch, lhs);
      movaps(dst, rhs);
      maxpd(scratch, rhs);
      maxpd(dst, lhs);
    }
    xorpd(dst, scratch);
    orpd(scratch, dst);
    subpd(scratch, dst);
    cmpunordpd(dst, scratch);
    psrlq(dst, uint8_t{13});
    andnpd(dst, scratch);
  }
}

void SharedMacroAssemblerBase::F32x4Splat(XMMRegister dst, DoubleRegister src) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX2)) {
    CpuFeatureScope avx2_scope(this, AVX2);
    vbroadcastss(dst, src);
  } else if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vshufps(dst, src, src, 0);
  } else {
    if (dst == src) {
      // 1 byte shorter than pshufd.
      shufps(dst, src, 0);
    } else {
      pshufd(dst, src, 0);
    }
  }
}

void SharedMacroAssemblerBase::F32x4ExtractLane(FloatRegister dst,
                                                XMMRegister src, uint8_t lane) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lane, 4);
  // These instructions are shorter than insertps, but will leave junk in
  // the top lanes of dst.
  if (lane == 0) {
    if (dst != src) {
      Movaps(dst, src);
    }
  } else if (lane == 1) {
    Movshdup(dst, src);
  } else if (lane == 2 && dst == src) {
    // Check dst == src to avoid false dependency on dst.
    Movhlps(dst, src);
  } else if (dst == src) {
    Shufps(dst, src, src, lane);
  } else {
    Pshufd(dst, src, lane);
  }
}

void SharedMacroAssemblerBase::S128Store32Lane(Operand dst, XMMRegister src,
                                               uint8_t laneidx) {
  ASM_CODE_COMMENT(this);
  if (laneidx == 0) {
    Movss(dst, src);
  } else {
    DCHECK_GE(3, laneidx);
    Extractps(dst, src, laneidx);
  }
}

template <typename Op>
void SharedMacroAssemblerBase::I8x16SplatPreAvx2(XMMRegister dst, Op src,
                                                 XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(!CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope ssse3_scope(this, SSSE3);
  Movd(dst, src);
  Xorps(scratch, scratch);
  Pshufb(dst, scratch);
}

void SharedMacroAssemblerBase::I8x16Splat(XMMRegister dst, Register src,
                                          XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX2)) {
    CpuFeatureScope avx2_scope(this, AVX2);
    Movd(scratch, src);
    vpbroadcastb(dst, scratch);
  } else {
    I8x16SplatPreAvx2(dst, src, scratch);
  }
}

void SharedMacroAssemblerBase::I8x16Splat(XMMRegister dst, Operand src,
                                          XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK_OPERAND_IS_NOT_REG(src);
  if (CpuFeatures::IsSupported(AVX2)) {
    CpuFeatureScope avx2_scope(this, AVX2);
    vpbroadcastb(dst, src);
  } else {
    I8x16SplatPreAvx2(dst, src, scratch);
  }
}

void SharedMacroAssemblerBase::I8x16Shl(XMMRegister dst, XMMRegister src1,
                                        uint8_t src2, Register tmp1,
                                        XMMRegister tmp2) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(dst, tmp2);
  // Perform 16-bit shift, then mask away low bits.
  if (!CpuFeatures::IsSupported(AVX) && (dst != src1)) {
    movaps(dst, src1);
    src1 = dst;
  }

  uint8_t shift = truncate_to_int3(src2);
  Psllw(dst, src1, uint8_t{shift});

  uint8_t bmask = static_cast<uint8_t>(0xff << shift);
  uint32_t mask = bmask << 24 | bmask << 16 | bmask << 8 | bmask;
  Move(tmp1, mask);
  Movd(tmp2, tmp1);
  Pshufd(tmp2, tmp2, uint8_t{0});
  Pand(dst, tmp2);
}

void SharedMacroAssemblerBase::I8x16Shl(XMMRegister dst, XMMRegister src1,
                                        Register src2, Register tmp1,
                                        XMMRegister tmp2, XMMRegister tmp3) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(dst, tmp2, tmp3));
  DCHECK(!AreAliased(src1, tmp2, tmp3));

  // Take shift value modulo 8.
  Move(tmp1, src2);
  And(tmp1, Immediate(7));
  Add(tmp1, Immediate(8));
  // Create a mask to unset high bits.
  Movd(tmp3, tmp1);
  Pcmpeqd(tmp2, tmp2);
  Psrlw(tmp2, tmp2, tmp3);
  Packuswb(tmp2, tmp2);
  if (!CpuFeatures::IsSupported(AVX) && (dst != src1)) {
    movaps(dst, src1);
    src1 = dst;
  }
  // Mask off the unwanted bits before word-shifting.
  Pand(dst, src1, tmp2);
  Add(tmp1, Immediate(-8));
  Movd(tmp3, tmp1);
  Psllw(dst, dst, tmp3);
}

void SharedMacroAssemblerBase::I8x16ShrS(XMMRegister dst, XMMRegister src1,
                                         uint8_t src2, XMMRegister tmp) {
  ASM_CODE_COMMENT(this);
  // Unpack bytes into words, do word (16-bit) shifts, and repack.
  DCHECK_NE(dst, tmp);
  uint8_t shift = truncate_to_int3(src2) + 8;

  Punpckhbw(tmp, src1);
  Punpcklbw(dst, src1);
  Psraw(tmp, shift);
  Psraw(dst, shift);
  Packsswb(dst, tmp);
}

void SharedMacroAssemblerBase::I8x16ShrS(XMMRegister dst, XMMRegister src1,
                                         Register src2, Register tmp1,
                                         XMMRegister tmp2, XMMRegister tmp3) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(dst, tmp2, tmp3));
  DCHECK_NE(src1, tmp2);

  // Unpack the bytes into words, do arithmetic shifts, and repack.
  Punpckhbw(tmp2, src1);
  Punpcklbw(dst, src1);
  // Prepare shift value
  Move(tmp1, src2);
  // Take shift value modulo 8.
  And(tmp1, Immediate(7));
  Add(tmp1, Immediate(8));
  Movd(tmp3, tmp1);
  Psraw(tmp2, tmp3);
  Psraw(dst, tmp3);
  Packsswb(dst, tmp2);
}

void SharedMacroAssemblerBase::I8x16ShrU(XMMRegister dst, XMMRegister src1,
                                         uint8_t src2, Register tmp1,
                                         XMMRegister tmp2) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(dst, tmp2);
  if (!CpuFeatures::IsSupported(AVX) && (dst != src1)) {
    movaps(dst, src1);
    src1 = dst;
  }

  // Perform 16-bit shift, then mask away high bits.
  uint8_t shift = truncate_to_int3(src2);
  Psrlw(dst, src1, shift);

  uint8_t bmask = 0xff >> shift;
  uint32_t mask = bmask << 24 | bmask << 16 | bmask << 8 | bmask;
  Move(tmp1, mask);
  Movd(tmp2, tmp1);
  Pshufd(tmp2, tmp2, uint8_t{0});
  Pand(dst, tmp2);
}

void SharedMacroAssemblerBase::I8x16ShrU(XMMRegister dst, XMMRegister src1,
                                         Register src2, Register tmp1,
                                         XMMRegister tmp2, XMMRegister tmp3) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(dst, tmp2, tmp3));
  DCHECK_NE(src1, tmp2);

  // Unpack the bytes into words, do logical shifts, and repack.
  Punpckhbw(tmp2, src1);
  Punpcklbw(dst, src1);
  // Prepare shift value.
  Move(tmp1, src2);
  // Take shift value modulo 8.
  And(tmp1, Immediate(7));
  Add(tmp1, Immediate(8));
  Movd(tmp3, tmp1);
  Psrlw(tmp2, tmp3);
  Psrlw(dst, tmp3);
  Packuswb(dst, tmp2);
}

template <typename Op>
void SharedMacroAssemblerBase::I16x8SplatPreAvx2(XMMRegister dst, Op src) {
  DCHECK(!CpuFeatures::IsSupported(AVX2));
  Movd(dst, src);
  Pshuflw(dst, dst, uint8_t{0x0});
  Punpcklqdq(dst, dst);
}

void SharedMacroAssemblerBase::I16x8Splat(XMMRegister dst, Register src) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX2)) {
    CpuFeatureScope avx2_scope(this, AVX2);
    Movd(dst, src);
    vpbroadcastw(dst, dst);
  } else {
    I16x8SplatPreAvx2(dst, src);
  }
}

void SharedMacroAssemblerBase::I16x8Splat(XMMRegister dst, Operand src) {
  ASM_CODE_COMMENT(this);
  DCHECK_OPERAND_IS_NOT_REG(src);
  if (CpuFeatures::IsSupported(AVX2)) {
    CpuFeatureScope avx2_scope(this, AVX2);
    vpbroadcastw(dst, src);
  } else {
    I16x8SplatPreAvx2(dst, src);
  }
}

void SharedMacroAssemblerBase::I16x8ExtMulLow(XMMRegister dst, XMMRegister src1,
                                              XMMRegister src2,
                                              XMMRegister scratch,
                                              bool is_signed) {
  ASM_CODE_COMMENT(this);
  is_signed ? Pmovsxbw(scratch, src1) : Pmovzxbw(scratch, src1);
  is_signed ? Pmovsxbw(dst, src2) : Pmovzxbw(dst, src2);
  Pmullw(dst, scratch);
}

void SharedMacroAssemblerBase::I16x8ExtMulHighS(XMMRegister dst,
                                                XMMRegister src1,
                                                XMMRegister src2,
                                                XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpunpckhbw(scratch, src1, src1);
    vpsraw(scratch, scratch, 8);
    vpunpckhbw(dst, src2, src2);
    vpsraw(dst, dst, 8);
    vpmullw(dst, dst, scratch);
  } else {
    if (dst != src1) {
      movaps(dst, src1);
    }
    movaps(scratch, src2);
    punpckhbw(dst, dst);
    psraw(dst, 8);
    punpckhbw(scratch, scratch);
    psraw(scratch, 8);
    pmullw(dst, scratch);
  }
}

void SharedMacroAssemblerBase::I16x8ExtMulHighU(XMMRegister dst,
                                                XMMRegister src1,
                                                XMMRegister src2,
                                                XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  // The logic here is slightly complicated to handle all the cases of register
  // aliasing. This allows flexibility for callers in TurboFan and Liftoff.
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    if (src1 == src2) {
      vpxor(scratch, scratch, scratch);
      vpunpckhbw(dst, src1, scratch);
      vpmullw(dst, dst, dst);
    } else {
      if (dst == src2) {
        // We overwrite dst, then use src2, so swap src1 and src2.
        std::swap(src1, src2);
      }
      vpxor(scratch, scratch, scratch);
      vpunpckhbw(dst, src1, scratch);
      vpunpckhbw(scratch, src2, scratch);
      vpmullw(dst, dst, scratch);
    }
  } else {
    if (src1 == src2) {
      xorps(scratch, scratch);
      if (dst != src1) {
        movaps(dst, src1);
      }
      punpckhbw(dst, scratch);
      pmullw(dst, scratch);
    } else {
      // When dst == src1, nothing special needs to be done.
      // When dst == src2, swap src1 and src2, since we overwrite dst.
      // When dst is unique, copy src1 to dst first.
      if (dst == src2) {
        std::swap(src1, src2);
        // Now, dst == src1.
      } else if (dst != src1) {
        // dst != src1 && dst != src2.
        movaps(dst, src1);
      }
      xorps(scratch, scratch);
      punpckhbw(dst, scratch);
      punpckhbw(scratch, src2);
      psrlw(scratch, 8);
      pmullw(dst, scratch);
    }
  }
}

void SharedMacroAssemblerBase::I16x8SConvertI8x16High(XMMRegister dst,
                                                      XMMRegister src) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    // src = |a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p| (high)
    // dst = |i|i|j|j|k|k|l|l|m|m|n|n|o|o|p|p|
    vpunpckhbw(dst, src, src);
    vpsraw(dst, dst, 8);
  } else {
    CpuFeatureScope sse_scope(this, SSE4_1);
    if (dst == src) {
      // 2 bytes shorter than pshufd, but has depdency on dst.
      movhlps(dst, src);
      pmovsxbw(dst, dst);
    } else {
      // No dependency on dst.
      pshufd(dst, src, 0xEE);
      pmovsxbw(dst, dst);
    }
  }
}

void SharedMacroAssemblerBase::I16x8UConvertI8x16High(XMMRegister dst,
                                                      XMMRegister src,
                                                      XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    // tmp = |0|0|0|0|0|0|0|0 | 0|0|0|0|0|0|0|0|
    // src = |a|b|c|d|e|f|g|h | i|j|k|l|m|n|o|p|
    // dst = |0|a|0|b|0|c|0|d | 0|e|0|f|0|g|0|h|
    XMMRegister tmp = dst == src ? scratch : dst;
    vpxor(tmp, tmp, tmp);
    vpunpckhbw(dst, src, tmp);
  } else {
    CpuFeatureScope sse_scope(this, SSE4_1);
    if (dst == src) {
      // xorps can be executed on more ports than pshufd.
      xorps(scratch, scratch);
      punpckhbw(dst, scratch);
    } else {
      // No dependency on dst.
      pshufd(dst, src, 0xEE);
      pmovzxbw(dst, dst);
    }
  }
}

void SharedMacroAssemblerBase::I16x8Q15MulRSatS(XMMRegister dst,
                                                XMMRegister src1,
                                                XMMRegister src2,
                                                XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  // k = i16x8.splat(0x8000)
  Pcmpeqd(scratch, scratch);
  Psllw(scratch, scratch, uint8_t{15});

  if (!CpuFeatures::IsSupported(AVX) && (dst != src1)) {
    movaps(dst, src1);
    src1 = dst;
  }

  Pmulhrsw(dst, src1, src2);
  Pcmpeqw(scratch, dst);
  Pxor(dst, scratch);
}

void SharedMacroAssemblerBase::I16x8DotI8x16I7x16S(XMMRegister dst,
                                                   XMMRegister src1,
                                                   XMMRegister src2) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpmaddubsw(dst, src2, src1);
  } else {
    if (dst != src2) {
      movdqa(dst, src2);
    }
    pmaddubsw(dst, src1);
  }
}

void SharedMacroAssemblerBase::I32x4DotI8x16I7x16AddS(
    XMMRegister dst, XMMRegister src1, XMMRegister src2, XMMRegister src3,
    XMMRegister scratch, XMMRegister splat_reg) {
  ASM_CODE_COMMENT(this);
#if V8_TARGET_ARCH_X64
  if (CpuFeatures::IsSupported(AVX_VNNI_INT8)) {
    CpuFeatureScope avx_vnni_int8_scope(this, AVX_VNNI_INT8);
    if (dst == src3) {
      vpdpbssd(dst, src2, src1);
    } else {
      DCHECK_NE(dst, src1);
      DCHECK_NE(dst, src2);
      Movdqa(dst, src3);
      vpdpbssd(dst, src2, src1);
    }
    return;
  } else if (CpuFeatures::IsSupported(AVX_VNNI)) {
    CpuFeatureScope avx_scope(this, AVX_VNNI);
    if (dst == src3) {
      vpdpbusd(dst, src2, src1);
    } else {
      DCHECK_NE(dst, src1);
      DCHECK_NE(dst, src2);
      Movdqa(dst, src3);
      vpdpbusd(dst, src2, src1);
    }
    return;
  }
#endif

  // k = i16x8.splat(1)
  Pcmpeqd(splat_reg, splat_reg);
  Psrlw(splat_reg, splat_reg, uint8_t{15});

  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpmaddubsw(scratch, src2, src1);
  } else {
    movdqa(scratch, src2);
    pmaddubsw(scratch, src1);
  }
  Pmaddwd(scratch, splat_reg);
  if (dst == src3) {
    Paddd(dst, scratch);
  } else {
    Movdqa(dst, src3);
    Paddd(dst, scratch);
  }
}

void SharedMacroAssemblerBase::I32x4ExtAddPairwiseI16x8U(XMMRegister dst,
                                                         XMMRegister src,
                                                         XMMRegister tmp) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    // src = |a|b|c|d|e|f|g|h| (low)
    // scratch = |0|a|0|c|0|e|0|g|
    vpsrld(tmp, src, 16);
    // dst = |0|b|0|d|0|f|0|h|
    vpblendw(dst, src, tmp, 0xAA);
    // dst = |a+b|c+d|e+f|g+h|
    vpaddd(dst, tmp, dst);
  } else if (CpuFeatures::IsSupported(SSE4_1)) {
    CpuFeatureScope sse_scope(this, SSE4_1);
    // There is a potentially better lowering if we get rip-relative
    // constants, see https://github.com/WebAssembly/simd/pull/380.
    movaps(tmp, src);
    psrld(tmp, 16);
    if (dst != src) {
      movaps(dst, src);
    }
    pblendw(dst, tmp, 0xAA);
    paddd(dst, tmp);
  } else {
    // src = |a|b|c|d|e|f|g|h|
    // tmp = i32x4.splat(0x0000FFFF)
    pcmpeqd(tmp, tmp);
    psrld(tmp, uint8_t{16});
    // tmp =|0|b|0|d|0|f|0|h|
    andps(tmp, src);
    // dst = |0|a|0|c|0|e|0|g|
    if (dst != src) {
      movaps(dst, src);
    }
    psrld(dst, uint8_t{16});
    // dst = |a+b|c+d|e+f|g+h|
    paddd(dst, tmp);
  }
}

// 1. Multiply low word into scratch.
// 2. Multiply high word (can be signed or unsigned) into dst.
// 3. Unpack and interleave scratch and dst into dst.
void SharedMacroAssemblerBase::I32x4ExtMul(XMMRegister dst, XMMRegister src1,
                                           XMMRegister src2,
                                           XMMRegister scratch, bool low,
                                           bool is_signed) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpmullw(scratch, src1, src2);
    is_signed ? vpmulhw(dst, src1, src2) : vpmulhuw(dst, src1, src2);
    low ? vpunpcklwd(dst, scratch, dst) : vpunpckhwd(dst, scratch, dst);
  } else {
    DCHECK_EQ(dst, src1);
    movaps(scratch, src1);
    pmullw(dst, src2);
    is_signed ? pmulhw(scratch, src2) : pmulhuw(scratch, src2);
    low ? punpcklwd(dst, scratch) : punpckhwd(dst, scratch);
  }
}

void SharedMacroAssemblerBase::I32x4SConvertI16x8High(XMMRegister dst,
                                                      XMMRegister src) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    // src = |a|b|c|d|e|f|g|h| (high)
    // dst = |e|e|f|f|g|g|h|h|
    vpunpckhwd(dst, src, src);
    vpsrad(dst, dst, 16);
  } else {
    CpuFeatureScope sse_scope(this, SSE4_1);
    if (dst == src) {
      // 2 bytes shorter than pshufd, but has depdency on dst.
      movhlps(dst, src);
      pmovsxwd(dst, dst);
    } else {
      // No dependency on dst.
      pshufd(dst, src, 0xEE);
      pmovsxwd(dst, dst);
    }
  }
}

void SharedMacroAssemblerBase::I32x4UConvertI16x8High(XMMRegister dst,
                                                      XMMRegister src,
                                                      XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    // scratch = |0|0|0|0|0|0|0|0|
    // src     = |a|b|c|d|e|f|g|h|
    // dst     = |0|a|0|b|0|c|0|d|
    XMMRegister tmp = dst == src ? scratch : dst;
    vpxor(tmp, tmp, tmp);
    vpunpckhwd(dst, src, tmp);
  } else {
    if (dst == src) {
      // xorps can be executed on more ports than pshufd.
      xorps(scratch, scratch);
      punpckhwd(dst, scratch);
    } else {
      CpuFeatureScope sse_scope(this, SSE4_1);
      // No dependency on dst.
      pshufd(dst, src, 0xEE);
      pmovzxwd(dst, dst);
    }
  }
}

void SharedMacroAssemblerBase::I64x2Neg(XMMRegister dst, XMMRegister src,
                                        XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vpxor(scratch, scratch, scratch);
    vpsubq(dst, scratch, src);
  } else {
    if (dst == src) {
      movaps(scratch, src);
      std::swap(src, scratch);
    }
    pxor(dst, dst);
    psubq(dst, src);
  }
}

void SharedMacroAssemblerBase::I64x2Abs(XMMRegister dst, XMMRegister src,
                                        XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    XMMRegister tmp = dst == src ? scratch : dst;
    vpxor(tmp, tmp, tmp);
    vpsubq(tmp, tmp, src);
    vblendvpd(dst, src, tmp, src);
  } else {
    CpuFeatureScope sse_scope(this, SSE3);
    movshdup(scratch, src);
    if (dst != src) {
      movaps(dst, src);
    }
    psrad(scratch, 31);
    xorps(dst, scratch);
    psubq(dst, scratch);
  }
}

void SharedMacroAssemblerBase::I64x2GtS(XMMRegister dst, XMMRegister src0,
                                        XMMRegister src1, XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpcmpgtq(dst, src0, src1);
  } else if (CpuFeatures::IsSupported(SSE4_2)) {
    CpuFeatureScope sse_scope(this, SSE4_2);
    if (dst == src0) {
      pcmpgtq(dst, src1);
    } else if (dst == src1) {
      movaps(scratch, src0);
      pcmpgtq(scratch, src1);
      movaps(dst, scratch);
    } else {
      movaps(dst, src0);
      pcmpgtq(dst, src1);
    }
  } else {
    CpuFeatureScope sse_scope(this, SSE3);
    DCHECK_NE(dst, src0);
    DCHECK_NE(dst, src1);
    movaps(dst, src1);
    movaps(scratch, src0);
    psubq(dst, src0);
    pcmpeqd(scratch, src1);
    andps(dst, scratch);
    movaps(scratch, src0);
    pcmpgtd(scratch, src1);
    orps(dst, scratch);
    movshdup(dst, dst);
  }
}

void SharedMacroAssemblerBase::I64x2GeS(XMMRegister dst, XMMRegister src0,
                                        XMMRegister src1, XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpcmpgtq(dst, src1, src0);
    vpcmpeqd(scratch, scratch, scratch);
    vpxor(dst, dst, scratch);
  } else if (CpuFeatures::IsSupported(SSE4_2)) {
    CpuFeatureScope sse_scope(this, SSE4_2);
    DCHECK_NE(dst, src0);
    if (dst != src1) {
      movaps(dst, src1);
    }
    pcmpgtq(dst, src0);
    pcmpeqd(scratch, scratch);
    xorps(dst, scratch);
  } else {
    CpuFeatureScope sse_scope(this, SSE3);
    DCHECK_NE(dst, src0);
    DCHECK_NE(dst, src1);
    movaps(dst, src0);
    movaps(scratch, src1);
    psubq(dst, src1);
    pcmpeqd(scratch, src0);
    andps(dst, scratch);
    movaps(scratch, src1);
    pcmpgtd(scratch, src0);
    orps(dst, scratch);
    movshdup(dst, dst);
    pcmpeqd(scratch, scratch);
    xorps(dst, scratch);
  }
}

void SharedMacroAssemblerBase::I64x2ShrS(XMMRegister dst, XMMRegister src,
                                         uint8_t shift, XMMRegister xmm_tmp) {
  ASM_CODE_COMMENT(this);
  DCHECK_GT(64, shift);
  DCHECK_NE(xmm_tmp, dst);
  DCHECK_NE(xmm_tmp, src);
  // Use logical right shift to emulate arithmetic right shifts:
  // Given:
  // signed >> c
  //   == (signed + 2^63 - 2^63) >> c
  //   == ((signed + 2^63) >> c) - (2^63 >> c)
  //                                ^^^^^^^^^
  //                                 xmm_tmp
  // signed + 2^63 is an unsigned number, so we can use logical right shifts.

  // xmm_tmp = wasm_i64x2_const(0x80000000'00000000).
  Pcmpeqd(xmm_tmp, xmm_tmp);
  Psllq(xmm_tmp, uint8_t{63});

  if (!CpuFeatures::IsSupported(AVX) && (dst != src)) {
    movaps(dst, src);
    src = dst;
  }
  // Add a bias of 2^63 to convert signed to unsigned.
  // Since only highest bit changes, use pxor instead of paddq.
  Pxor(dst, src, xmm_tmp);
  // Logically shift both value and bias.
  Psrlq(dst, shift);
  Psrlq(xmm_tmp, shift);
  // Subtract shifted bias to convert back to signed value.
  Psubq(dst, xmm_tmp);
}

void SharedMacroAssemblerBase::I64x2ShrS(XMMRegister dst, XMMRegister src,
                                         Register shift, XMMRegister xmm_tmp,
                                         XMMRegister xmm_shift,
                                         Register tmp_shift) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(xmm_tmp, dst);
  DCHECK_NE(xmm_tmp, src);
  DCHECK_NE(xmm_shift, dst);
  DCHECK_NE(xmm_shift, src);
  // tmp_shift can alias shift since we don't use shift after masking it.

  // See I64x2ShrS with constant shift for explanation of this algorithm.
  Pcmpeqd(xmm_tmp, xmm_tmp);
  Psllq(xmm_tmp, uint8_t{63});

  // Shift modulo 64.
  Move(tmp_shift, shift);
  And(tmp_shift, Immediate(0x3F));
  Movd(xmm_shift, tmp_shift);

  if (!CpuFeatures::IsSupported(AVX) && (dst != src)) {
    movaps(dst, src);
    src = dst;
  }
  Pxor(dst, src, xmm_tmp);
  Psrlq(dst, xmm_shift);
  Psrlq(xmm_tmp, xmm_shift);
  Psubq(dst, xmm_tmp);
}

void SharedMacroAssemblerBase::I64x2Mul(XMMRegister dst, XMMRegister lhs,
                                        XMMRegister rhs, XMMRegister tmp1,
                                        XMMRegister tmp2) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(dst, tmp1, tmp2));
  DCHECK(!AreAliased(lhs, tmp1, tmp2));
  DCHECK(!AreAliased(rhs, tmp1, tmp2));

  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    // 1. Multiply high dword of each qword of left with right.
    vpsrlq(tmp1, lhs, uint8_t{32});
    vpmuludq(tmp1, tmp1, rhs);
    // 2. Multiply high dword of each qword of right with left.
    vpsrlq(tmp2, rhs, uint8_t{32});
    vpmuludq(tmp2, tmp2, lhs);
    // 3. Add 1 and 2, then shift left by 32 (this is the high dword of result).
    vpaddq(tmp2, tmp2, tmp1);
    vpsllq(tmp2, tmp2, uint8_t{32});
    // 4. Multiply low dwords (this is the low dword of result).
    vpmuludq(dst, lhs, rhs);
    // 5. Add 3 and 4.
    vpaddq(dst, dst, tmp2);
  } else {
    // Same algorithm as AVX version, but with moves to not overwrite inputs.
    movaps(tmp1, lhs);
    movaps(tmp2, rhs);
    psrlq(tmp1, uint8_t{32});
    pmuludq(tmp1, rhs);
    psrlq(tmp2, uint8_t{32});
    pmuludq(tmp2, lhs);
    paddq(tmp2, tmp1);
    psllq(tmp2, uint8_t{32});
    if (dst == rhs) {
      // pmuludq is commutative
      pmuludq(dst, lhs);
    } else {
      if (dst != lhs) {
        movaps(dst, lhs);
      }
      pmuludq(dst, rhs);
    }
    paddq(dst, tmp2);
  }
}

// 1. Unpack src0, src1 into even-number elements of scratch.
// 2. Unpack src1, src0 into even-number elements of dst.
// 3. Multiply 1. with 2.
// For non-AVX, use non-destructive pshufd instead of punpckldq/punpckhdq.
void SharedMacroAssemblerBase::I64x2ExtMul(XMMRegister dst, XMMRegister src1,
                                           XMMRegister src2,
                                           XMMRegister scratch, bool low,
                                           bool is_signed) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    if (low) {
      vpunpckldq(scratch, src1, src1);
      vpunpckldq(dst, src2, src2);
    } else {
      vpunpckhdq(scratch, src1, src1);
      vpunpckhdq(dst, src2, src2);
    }
    if (is_signed) {
      vpmuldq(dst, scratch, dst);
    } else {
      vpmuludq(dst, scratch, dst);
    }
  } else {
    uint8_t mask = low ? 0x50 : 0xFA;
    pshufd(scratch, src1, mask);
    pshufd(dst, src2, mask);
    if (is_signed) {
      CpuFeatureScope sse4_scope(this, SSE4_1);
      pmuldq(dst, scratch);
    } else {
      pmuludq(dst, scratch);
    }
  }
}

void SharedMacroAssemblerBase::I64x2SConvertI32x4High(XMMRegister dst,
                                                      XMMRegister src) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpunpckhqdq(dst, src, src);
    vpmovsxdq(dst, dst);
  } else {
    CpuFeatureScope sse_scope(this, SSE4_1);
    if (dst == src) {
      movhlps(dst, src);
    } else {
      pshufd(dst, src, 0xEE);
    }
    pmovsxdq(dst, dst);
  }
}

void SharedMacroAssemblerBase::I64x2UConvertI32x4High(XMMRegister dst,
                                                      XMMRegister src,
                                                      XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpxor(scratch, scratch, scratch);
    vpunpckhdq(dst, src, scratch);
  } else {
    if (dst == src) {
      // xorps can be executed on more ports than pshufd.
      xorps(scratch, scratch);
      punpckhdq(dst, scratch);
    } else {
      CpuFeatureScope sse_scope(this, SSE4_1);
      // No dependency on dst.
      pshufd(dst, src, 0xEE);
      pmovzxdq(dst, dst);
    }
  }
}

void SharedMacroAssemblerBase::S128Not(XMMRegister dst, XMMRegister src,
                                       XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  if (dst == src) {
    Pcmpeqd(scratch, scratch);
    Pxor(dst, scratch);
  } else {
    Pcmpeqd(dst, dst);
    Pxor(dst, src);
  }
}

void SharedMacroAssemblerBase::S128Select(XMMRegister dst, XMMRegister mask,
                                          XMMRegister src1, XMMRegister src2,
                                          XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  // v128.select = v128.or(v128.and(v1, c), v128.andnot(v2, c)).
  // pandn(x, y) = !x & y, so we have to flip the mask and input.
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpandn(scratch, mask, src2);
    vpand(dst, src1, mask);
    vpor(dst, dst, scratch);
  } else {
    DCHECK_EQ(dst, mask);
    // Use float ops as they are 1 byte shorter than int ops.
    movaps(scratch, mask);
    andnps(scratch, src2);
    andps(dst, src1);
    orps(dst, scratch);
  }
}

void SharedMacroAssemblerBase::S128Load8Splat(XMMRegister dst, Operand src,
                                              XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  // The trap handler uses the current pc to creating a landing, so that it can
  // determine if a trap occured in Wasm code due to a OOB load. Make sure the
  // first instruction in each case below is the one that loads.
  if (CpuFeatures::IsSupported(AVX2)) {
    CpuFeatureScope avx2_scope(this, AVX2);
    vpbroadcastb(dst, src);
  } else if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    // Avoid dependency on previous value of dst.
    vpinsrb(dst, scratch, src, uint8_t{0});
    vpxor(scratch, scratch, scratch);
    vpshufb(dst, dst, scratch);
  } else {
    CpuFeatureScope ssse4_scope(this, SSE4_1);
    pinsrb(dst, src, uint8_t{0});
    xorps(scratch, scratch);
    pshufb(dst, scratch);
  }
}

void SharedMacroAssemblerBase::S128Load16Splat(XMMRegister dst, Operand src,
                                               XMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  // The trap handler uses the current pc to creating a landing, so that it can
  // determine if a trap occured in Wasm code due to a OOB load. Make sure the
  // first instruction in each case below is the one that loads.
  if (CpuFeatures::IsSupported(AVX2)) {
    CpuFeatureScope avx2_scope(this, AVX2);
    vpbroadcastw(dst, src);
  } else if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    // Avoid dependency on previous value of dst.
    vpinsrw(dst, scratch, src, uint8_t{0});
    vpshuflw(dst, dst, uint8_t{0});
    vpunpcklqdq(dst, dst, dst);
  } else {
    pinsrw(dst, src, uint8_t{0});
    pshuflw(dst, dst, uint8_t{0});
    movlhps(dst, dst);
  }
}

void SharedMacroAssemblerBase::S128Load32Splat(XMMRegister dst, Operand src) {
  ASM_CODE_COMMENT(this);
  // The trap handler uses the current pc to creating a landing, so that it can
  // determine if a trap occured in Wasm code due to a OOB load. Make sure the
  // first instruction in each case below is the one that loads.
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vbroadcastss(dst, src);
  } else {
    movss(dst, src);
    shufps(dst, dst, uint8_t{0});
  }
}

void SharedMacroAssemblerBase::S128Store64Lane(Operand dst, XMMRegister src,
                                               uint8_t laneidx) {
  ASM_CODE_COMMENT(this);
  if (laneidx == 0) {
    Movlps(dst, src);
  } else {
    DCHECK_EQ(1, laneidx);
    Movhps(dst, src);
  }
}

void SharedMacroAssemblerBase::F32x4Qfma(XMMRegister dst, XMMRegister src1,
                                         XMMRegister src2, XMMRegister src3,
                                         XMMRegister tmp) {
  QFMA(ps)
}

void SharedMacroAssemblerBase::F32x4Qfms(XMMRegister dst, XMMRegister src1,
                                         XMMRegister src2, XMMRegister src3,
                                         XMMRegister tmp) {
  QFMS(ps)
}

void SharedMacroAssemblerBase::F64x2Qfma(XMMRegister dst, XMMRegister src1,
                                         XMMRegister src2, XMMRegister src3,
                                         XMMRegister tmp) {
  QFMA(pd);
}

void SharedMacroAssemblerBase::F64x2Qfms(XMMRegister dst, XMMRegister src1,
                                         XMMRegister src2, XMMRegister src3,
                                         XMMRegister tmp) {
  QFMS(pd);
}

#undef QFMOP

}  // namespace internal
}  // namespace v8

#undef DCHECK_OPERAND_IS_NOT_REG

"""

```