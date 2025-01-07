Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick scan for familiar keywords and patterns. I'm looking for:

* **Headers:** `#ifndef`, `#define`, `#include` immediately tell me it's a header file and identify dependencies.
* **Namespaces:** `namespace v8 { namespace internal { ... } }` indicates the file's organizational context within the V8 project.
* **Classes:** `class`, `class V8_EXPORT_PRIVATE SharedMacroAssemblerBase`, `template <typename Impl> class V8_EXPORT_PRIVATE SharedMacroAssembler` are key structural elements.
* **Macros:** `#define QFMA`, `#define QFMS`, `#define AVX_OP`, etc., jump out due to the `#define`. These often indicate code generation or conditional compilation.
* **Conditional Compilation:** `#if`, `#elif`, `#else`, `#endif`, particularly around `V8_TARGET_ARCH_IA32` and `V8_TARGET_ARCH_X64`, signal architecture-specific code.
* **Data Types:** `Register`, `XMMRegister`, `Operand`, `uint32_t`, `uint8_t`, etc., give hints about the domain (assembly, low-level operations).
* **Functions/Methods:**  The structure `void Move(...)`, `template <typename Op> void Pinsrb(...)`, etc., reveals the file's functionality.
* **Comments:** `// Copyright ...`, `// Helper macro ...`, `// Base class for ...` provide high-level descriptions.
* **`V8_EXPORT_PRIVATE`:**  Indicates this class is part of V8's internal API.

**2. Understanding the Core Classes:**

I focus on the main classes:

* **`SharedMacroAssemblerBase`:** The name suggests a base class providing common functionality for macro assemblers. The comments confirm this, noting it contains architecture-independent functions. The presence of `Move`, `Add`, `And`, and functions dealing with XMM registers points towards low-level manipulation.
* **`SharedMacroAssembler<Impl>`:** The template nature and the comment about CRTP (Curiously Recurring Template Pattern) are crucial. This signifies a pattern for achieving static polymorphism. The functions within this template seem to be higher-level operations built upon the base class.

**3. Analyzing Macros:**

Macros like `QFMA` and `QFMS` are clearly for generating code related to fused multiply-add (FMA) instructions. The logic within them handles different CPU feature support (FMA3, AVX, SSE) and register aliasing, which are common concerns in assembly programming for performance.

The `AVX_OP` family of macros is a code generation pattern. They are designed to conditionally call either AVX or non-AVX versions of instructions based on CPU feature support. The structure of `AvxHelper` confirms this intent.

**4. Identifying Key Functionality Areas:**

By looking at the function names and their arguments, I can categorize the functionality:

* **Basic Register Operations:** `Move`, `Add`, `And`.
* **Floating-Point Operations:**  Functions with names like `Addpd`, `Mulps`, `Sqrtpd`, and the presence of `XMMRegister` indicate a focus on floating-point arithmetic.
* **Vector/SIMD Operations:** Functions like `Blendvps`, `Pshufb`, `Packssdw`, and those starting with `I8x16`, `I16x8`, `I32x4`, `I64x2`, and `S128` strongly suggest support for Single Instruction, Multiple Data (SIMD) operations, likely related to WebAssembly's SIMD instructions.
* **Conditional Execution Based on CPU Features:**  The frequent checks for `CpuFeatures::IsSupported(AVX)`, `CpuFeatures::IsSupported(FMA3)`, etc., are a dominant pattern.
* **Helper Structures and Templates:** `AvxHelper` and the `SharedMacroAssembler` template itself are structural elements for code organization and conditional behavior.

**5. Connecting to JavaScript (Conceptual):**

While the header is C++, I consider how the functionality relates to JavaScript. V8 compiles JavaScript to machine code. This header file provides building blocks for that compilation process, particularly for:

* **Optimizing numerical operations:** The floating-point and SIMD instructions are crucial for speeding up JavaScript code that performs heavy calculations.
* **Implementing WebAssembly:** The presence of WebAssembly-specific vector operations (`F64x2`, `I8x16`, etc.) directly links this code to V8's WebAssembly support.

**6. Inferring Potential Programming Errors:**

The register aliasing handling in the `QFMA` and `QFMS` macros hints at a common low-level programming error:  modifying a source register when it's also the destination. V8's macro aims to prevent incorrect behavior in these cases.

**7. Formulating the Summary:**

Finally, I synthesize the observations into a concise summary, hitting the key points:

* **Purpose:** Low-level code generation for IA-32 and x64 architectures.
* **Key Abstraction:** `SharedMacroAssembler` provides an interface for emitting machine instructions.
* **CPU Feature Awareness:**  A strong focus on leveraging specific CPU features (AVX, FMA3, SSE) for optimization.
* **Instruction Set Support:**  Operations cover basic arithmetic, floating-point, and SIMD instructions.
* **WebAssembly Relevance:**  Significant support for WebAssembly's vector instructions.
* **Error Prevention:** Macros like `QFMA` and `QFMS` address register aliasing issues.
* **No Torque:** The filename extension is `.h`, not `.tq`.

This iterative process of scanning, understanding, categorizing, and connecting the pieces leads to a comprehensive understanding of the header file's purpose and functionality.
这是一个C++头文件，定义了 V8 JavaScript 引擎在 IA-32 和 x64 架构上共享的宏汇编器（macro-assembler）的基础功能。

**功能归纳:**

这个头文件的主要功能是为 V8 的代码生成器提供一个抽象层，用于生成特定架构（IA-32 或 x64）的机器码指令。它包含了一系列宏和函数，用于执行常见的汇编操作，并根据目标 CPU 的特性（例如 AVX, FMA3, SSE 等）选择最优的指令。

更具体地说，它的功能包括：

1. **架构抽象:**  通过条件编译 (`#if V8_TARGET_ARCH_IA32` 和 `#elif V8_TARGET_ARCH_X64`)，为不同的架构选择正确的寄存器类型 (`register-ia32.h` 或 `register-x64.h`)。

2. **宏定义简化指令:**  定义了像 `QFMA` 和 `QFMS` 这样的宏，用于简化复杂的浮点运算指令的生成，并自动处理寄存器别名的情况，以减少指令数量并提高效率。 例如，`QFMA` 宏根据 CPU 是否支持 FMA3 和寄存器别名的情况，选择 `vfmadd213`, `vfmadd231`, `vmul` 和 `vadd` 等不同的指令组合来实现带 FMA 的乘法累加操作。

3. **共享的汇编操作:**  定义了 `SharedMacroAssemblerBase` 类，其中包含可以在 IA-32 和 x64 架构之间共享的汇编操作函数，例如 `Move`, `Add`, `And`, 以及一些处理 XMM 寄存器的操作，例如 `Movhps`, `Movlps`, `Blendvps` 等。

4. **基于 CPU 特性的指令选择:**  通过 `CpuFeatures::IsSupported()` 函数检查 CPU 是否支持特定的指令集扩展（如 AVX, SSE 等），并根据支持情况选择不同的指令。例如，`Pshufb` 函数会根据是否支持 AVX 选择 `vpshufb` 或 `pshufb` 指令。

5. **模板化的汇编操作:**  定义了 `SharedMacroAssembler` 模板类，它继承自 `SharedMacroAssemblerBase`，并提供更多架构特定的汇编操作。 这个模板使用了 CRTP (Curiously Recurring Template Pattern)，允许子类（例如针对 IA-32 或 x64 的具体 `MacroAssembler` 类）扩展和定制功能。

6. **支持 SIMD 指令:**  包含了大量针对 SIMD (Single Instruction, Multiple Data) 指令的操作，特别是与 WebAssembly 的 SIMD 指令集相关的操作，例如 `F64x2ExtractLane`, `I8x16Splat`, `I32x4ExtMul` 等。

**关于文件扩展名和 Torque:**

你提到如果文件以 `.tq` 结尾，则它是 V8 Torque 源代码。 `v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h` 的扩展名是 `.h`，所以**它不是 Torque 源代码**。 它是标准的 C++ 头文件。

**与 Javascript 的关系:**

这个头文件中的代码与 Javascript 的执行效率密切相关。 V8 引擎将 Javascript 代码编译成机器码，而 `macro-assembler-shared-ia32-x64.h` 中定义的宏和函数正是用于生成这些机器码指令的工具。

**Javascript 例子 (概念性):**

假设有以下 Javascript 代码：

```javascript
function multiplyAdd(a, b, c) {
  return a * b + c;
}

let result = multiplyAdd(2.5, 3.0, 1.5);
```

当 V8 编译 `multiplyAdd` 函数时，可能会使用 `macro-assembler-shared-ia32-x64.h` 中定义的宏来生成相应的机器码。 例如，如果 CPU 支持 FMA3 指令，V8 可能会使用 `QFMA(pd)` 宏（假设操作数为双精度浮点数）来生成一个高效的 fused multiply-add 指令，而不是分别生成乘法和加法指令。

**代码逻辑推理 (假设输入与输出):**

考虑 `QFMA(ps)` 宏，假设输入：

* `dst`, `src1`, `src2`, `src3` 是代表 XMM 寄存器的变量。
* CPU 支持 FMA3 指令。
* `dst` 和 `src1` 指向同一个寄存器。

在这种情况下，`QFMA(ps)` 宏内部的第一个 `if (dst == src1)` 条件成立，V8 代码生成器会调用 `vfmadd213ps(dst, src2, src3)` 指令。  这意味着 `dst` 寄存器的值会被更新为 `dst * src2 + src3` 的结果。

**用户常见的编程错误 (低级角度):**

这个头文件本身是 V8 内部的代码，普通 Javascript 开发者不会直接接触。 但是，这个头文件中处理的一些问题反映了低级编程中常见的错误，例如：

* **寄存器别名问题:**  在汇编编程中，如果源操作数和目标操作数使用了相同的寄存器，可能会导致意想不到的结果。 `QFMA` 和 `QFMS` 宏通过检查寄存器别名并采取不同的指令序列来避免这类问题。

   **C++ 例子 (模拟汇编的场景):**

   ```c++
   // 假设模拟 XMM 寄存器操作
   double xmm0 = 2.0;
   double xmm1 = 3.0;
   double xmm2 = 4.0;

   // 如果直接翻译成汇编，没有考虑别名，可能出错
   // 错误的模拟: xmm0 = xmm0 * xmm1 + xmm2;
   xmm0 = xmm0 * xmm1;
   xmm0 = xmm0 + xmm2;

   // QFMA 宏会处理这种情况，确保结果正确
   // 正确的模拟 (概念上): 如果 dst == src1, 使用 vfmadd213
   if (&xmm0 == &xmm0) {
       xmm0 = xmm0 * xmm1 + xmm2; // 相当于 vfmadd213ps xmm0, xmm1, xmm2
   }
   ```

**第 1 部分功能归纳:**

总而言之，`v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h` 的第 1 部分定义了 V8 引擎在 IA-32 和 x64 架构上生成机器码的基础设施，专注于提供共享的汇编操作，并通过宏和模板根据 CPU 特性选择最优指令，尤其在浮点运算和 SIMD 指令方面。它旨在简化代码生成器的开发，并提高生成的机器码的效率。 它还体现了在底层编程中需要考虑的寄存器别名等问题。

Prompt: 
```
这是目录为v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_SHARED_IA32_X64_MACRO_ASSEMBLER_SHARED_IA32_X64_H_
#define V8_CODEGEN_SHARED_IA32_X64_MACRO_ASSEMBLER_SHARED_IA32_X64_H_

#include <optional>

#include "src/base/macros.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/external-reference.h"
#include "src/codegen/macro-assembler-base.h"

#if V8_TARGET_ARCH_IA32
#include "src/codegen/ia32/register-ia32.h"
#elif V8_TARGET_ARCH_X64
#include "src/codegen/x64/register-x64.h"
#else
#error Unsupported target architecture.
#endif

// Helper macro to define qfma macro-assembler. This takes care of every
// possible case of register aliasing to minimize the number of instructions.
#define QFMA(ps_or_pd)                        \
  if (CpuFeatures::IsSupported(FMA3)) {       \
    CpuFeatureScope fma3_scope(this, FMA3);   \
    if (dst == src1) {                        \
      vfmadd213##ps_or_pd(dst, src2, src3);   \
    } else if (dst == src2) {                 \
      vfmadd213##ps_or_pd(dst, src1, src3);   \
    } else if (dst == src3) {                 \
      vfmadd231##ps_or_pd(dst, src2, src1);   \
    } else {                                  \
      CpuFeatureScope avx_scope(this, AVX);   \
      vmovups(dst, src1);                     \
      vfmadd213##ps_or_pd(dst, src2, src3);   \
    }                                         \
  } else if (CpuFeatures::IsSupported(AVX)) { \
    CpuFeatureScope avx_scope(this, AVX);     \
    vmul##ps_or_pd(tmp, src1, src2);          \
    vadd##ps_or_pd(dst, tmp, src3);           \
  } else {                                    \
    if (dst == src1) {                        \
      mul##ps_or_pd(dst, src2);               \
      add##ps_or_pd(dst, src3);               \
    } else if (dst == src2) {                 \
      DCHECK_NE(src2, src1);                  \
      mul##ps_or_pd(dst, src1);               \
      add##ps_or_pd(dst, src3);               \
    } else if (dst == src3) {                 \
      DCHECK_NE(src3, src1);                  \
      movaps(tmp, src1);                      \
      mul##ps_or_pd(tmp, src2);               \
      add##ps_or_pd(dst, tmp);                \
    } else {                                  \
      movaps(dst, src1);                      \
      mul##ps_or_pd(dst, src2);               \
      add##ps_or_pd(dst, src3);               \
    }                                         \
  }

// Helper macro to define qfms macro-assembler. This takes care of every
// possible case of register aliasing to minimize the number of instructions.
#define QFMS(ps_or_pd)                        \
  if (CpuFeatures::IsSupported(FMA3)) {       \
    CpuFeatureScope fma3_scope(this, FMA3);   \
    if (dst == src1) {                        \
      vfnmadd213##ps_or_pd(dst, src2, src3);  \
    } else if (dst == src2) {                 \
      vfnmadd213##ps_or_pd(dst, src1, src3);  \
    } else if (dst == src3) {                 \
      vfnmadd231##ps_or_pd(dst, src2, src1);  \
    } else {                                  \
      CpuFeatureScope avx_scope(this, AVX);   \
      vmovups(dst, src1);                     \
      vfnmadd213##ps_or_pd(dst, src2, src3);  \
    }                                         \
  } else if (CpuFeatures::IsSupported(AVX)) { \
    CpuFeatureScope avx_scope(this, AVX);     \
    vmul##ps_or_pd(tmp, src1, src2);          \
    vsub##ps_or_pd(dst, src3, tmp);           \
  } else {                                    \
    movaps(tmp, src1);                        \
    mul##ps_or_pd(tmp, src2);                 \
    if (dst != src3) {                        \
      movaps(dst, src3);                      \
    }                                         \
    sub##ps_or_pd(dst, tmp);                  \
  }

namespace v8 {
namespace internal {
class Assembler;

// For WebAssembly we care about the full floating point register. If we are not
// running Wasm, we can get away with saving half of those registers.
#if V8_ENABLE_WEBASSEMBLY
constexpr int kStackSavedSavedFPSize = 2 * kDoubleSize;
#else
constexpr int kStackSavedSavedFPSize = kDoubleSize;
#endif  // V8_ENABLE_WEBASSEMBLY

// Base class for SharedMacroAssembler. This class contains macro-assembler
// functions that can be shared across ia32 and x64 without any template
// machinery, i.e. does not require the CRTP pattern that
// SharedMacroAssembler exposes. This allows us to keep the bulk of
// definition inside a separate source file, rather than putting everything
// inside this header.
class V8_EXPORT_PRIVATE SharedMacroAssemblerBase : public MacroAssemblerBase {
 public:
  using MacroAssemblerBase::MacroAssemblerBase;

  void Move(Register dst, uint32_t src);
  // Move if registers are not identical.
  void Move(Register dst, Register src);
  void Add(Register dst, Immediate src);
  void And(Register dst, Immediate src);

  // Will move src1 to dst if AVX is not supported.
  void Movhps(XMMRegister dst, XMMRegister src1, Operand src2);
  void Movlps(XMMRegister dst, XMMRegister src1, Operand src2);

  void Blendvps(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                XMMRegister mask);
  void Blendvpd(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                XMMRegister mask);
  void Pblendvb(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                XMMRegister mask);

  template <typename Op>
  void Pinsrb(XMMRegister dst, XMMRegister src1, Op src2, uint8_t imm8,
              uint32_t* load_pc_offset = nullptr) {
    PinsrHelper(this, &Assembler::vpinsrb, &Assembler::pinsrb, dst, src1, src2,
                imm8, load_pc_offset, {SSE4_1});
  }

  template <typename Op>
  void Pinsrw(XMMRegister dst, XMMRegister src1, Op src2, uint8_t imm8,
              uint32_t* load_pc_offset = nullptr) {
    PinsrHelper(this, &Assembler::vpinsrw, &Assembler::pinsrw, dst, src1, src2,
                imm8, load_pc_offset);
  }

  // Supports both SSE and AVX. Move src1 to dst if they are not equal on SSE.
  template <typename Op>
  void Pshufb(XMMRegister dst, XMMRegister src, Op mask) {
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      vpshufb(dst, src, mask);
    } else {
      // Make sure these are different so that we won't overwrite mask.
      DCHECK_NE(mask, dst);
      if (dst != src) {
        movaps(dst, src);
      }
      CpuFeatureScope sse_scope(this, SSSE3);
      pshufb(dst, mask);
    }
  }

  template <typename Op>
  void Pshufb(XMMRegister dst, Op mask) {
    Pshufb(dst, dst, mask);
  }

  // Shufps that will mov src1 into dst if AVX is not supported.
  void Shufps(XMMRegister dst, XMMRegister src1, XMMRegister src2,
              uint8_t imm8);

  // Helper struct to implement functions that check for AVX support and
  // dispatch to the appropriate AVX/SSE instruction.
  template <typename Dst, typename Arg, typename... Args>
  struct AvxHelper {
    Assembler* assm;
    std::optional<CpuFeature> feature = std::nullopt;
    // Call a method where the AVX version expects the dst argument to be
    // duplicated.
    // E.g. Andps(x, y) -> vandps(x, x, y)
    //                  -> andps(x, y)
    template <void (Assembler::*avx)(Dst, Dst, Arg, Args...),
              void (Assembler::*no_avx)(Dst, Arg, Args...)>
    void emit(Dst dst, Arg arg, Args... args) {
      if (CpuFeatures::IsSupported(AVX)) {
        CpuFeatureScope scope(assm, AVX);
        (assm->*avx)(dst, dst, arg, args...);
      } else if (feature.has_value()) {
        DCHECK(CpuFeatures::IsSupported(*feature));
        CpuFeatureScope scope(assm, *feature);
        (assm->*no_avx)(dst, arg, args...);
      } else {
        (assm->*no_avx)(dst, arg, args...);
      }
    }

    // Call a method in the AVX form (one more operand), but if unsupported will
    // check that dst == first src.
    // E.g. Andps(x, y, z) -> vandps(x, y, z)
    //                     -> andps(x, z) and check that x == y
    template <void (Assembler::*avx)(Dst, Arg, Args...),
              void (Assembler::*no_avx)(Dst, Args...)>
    void emit(Dst dst, Arg arg, Args... args) {
      if (CpuFeatures::IsSupported(AVX)) {
        CpuFeatureScope scope(assm, AVX);
        (assm->*avx)(dst, arg, args...);
      } else if (feature.has_value()) {
        DCHECK_EQ(dst, arg);
        DCHECK(CpuFeatures::IsSupported(*feature));
        CpuFeatureScope scope(assm, *feature);
        (assm->*no_avx)(dst, args...);
      } else {
        DCHECK_EQ(dst, arg);
        (assm->*no_avx)(dst, args...);
      }
    }

    // Call a method where the AVX version expects no duplicated dst argument.
    // E.g. Movddup(x, y) -> vmovddup(x, y)
    //                    -> movddup(x, y)
    template <void (Assembler::*avx)(Dst, Arg, Args...),
              void (Assembler::*no_avx)(Dst, Arg, Args...)>
    void emit(Dst dst, Arg arg, Args... args) {
      if (CpuFeatures::IsSupported(AVX)) {
        CpuFeatureScope scope(assm, AVX);
        (assm->*avx)(dst, arg, args...);
      } else if (feature.has_value()) {
        DCHECK(CpuFeatures::IsSupported(*feature));
        CpuFeatureScope scope(assm, *feature);
        (assm->*no_avx)(dst, arg, args...);
      } else {
        (assm->*no_avx)(dst, arg, args...);
      }
    }
  };

#define AVX_OP(macro_name, name)                                        \
  template <typename Dst, typename Arg, typename... Args>               \
  void macro_name(Dst dst, Arg arg, Args... args) {                     \
    AvxHelper<Dst, Arg, Args...>{this}                                  \
        .template emit<&Assembler::v##name, &Assembler::name>(dst, arg, \
                                                              args...); \
  }

// Define a macro which uses |avx_name| when AVX is supported, and |sse_name|
// when AVX is not supported. This is useful for bit-wise instructions like
// andpd/andps, where the behavior is exactly the same, but the *ps
// version is 1 byte shorter, and on SSE-only processors there is no
// performance difference since those processors don't differentiate integer
// and floating-point domains.
// Note: we require |avx_name| to be the AVX instruction without the "v"
// prefix. If we require the full AVX instruction name and the caller
// accidentally passes in a SSE instruction, we compile without any issues and
// generate the SSE instruction. By appending "v" here, we ensure that we will
// generate an AVX instruction.
#define AVX_OP_WITH_DIFF_SSE_INSTR(macro_name, avx_name, sse_name)     \
  template <typename Dst, typename Arg, typename... Args>              \
  void macro_name(Dst dst, Arg arg, Args... args) {                    \
    AvxHelper<Dst, Arg, Args...>{this}                                 \
        .template emit<&Assembler::v##avx_name, &Assembler::sse_name>( \
            dst, arg, args...);                                        \
  }

#define AVX_OP_SSE3(macro_name, name)                                   \
  template <typename Dst, typename Arg, typename... Args>               \
  void macro_name(Dst dst, Arg arg, Args... args) {                     \
    AvxHelper<Dst, Arg, Args...>{this, std::optional<CpuFeature>(SSE3)} \
        .template emit<&Assembler::v##name, &Assembler::name>(dst, arg, \
                                                              args...); \
  }

#define AVX_OP_SSSE3(macro_name, name)                                   \
  template <typename Dst, typename Arg, typename... Args>                \
  void macro_name(Dst dst, Arg arg, Args... args) {                      \
    AvxHelper<Dst, Arg, Args...>{this, std::optional<CpuFeature>(SSSE3)} \
        .template emit<&Assembler::v##name, &Assembler::name>(dst, arg,  \
                                                              args...);  \
  }

#define AVX_OP_SSE4_1(macro_name, name)                                   \
  template <typename Dst, typename Arg, typename... Args>                 \
  void macro_name(Dst dst, Arg arg, Args... args) {                       \
    AvxHelper<Dst, Arg, Args...>{this, std::optional<CpuFeature>(SSE4_1)} \
        .template emit<&Assembler::v##name, &Assembler::name>(dst, arg,   \
                                                              args...);   \
  }

#define AVX_OP_SSE4_2(macro_name, name)                                   \
  template <typename Dst, typename Arg, typename... Args>                 \
  void macro_name(Dst dst, Arg arg, Args... args) {                       \
    AvxHelper<Dst, Arg, Args...>{this, std::optional<CpuFeature>(SSE4_2)} \
        .template emit<&Assembler::v##name, &Assembler::name>(dst, arg,   \
                                                              args...);   \
  }

  // Keep this list sorted by required extension, then instruction name.
  AVX_OP(Addpd, addpd)
  AVX_OP(Addps, addps)
  AVX_OP(Addsd, addsd)
  AVX_OP(Addss, addss)
  AVX_OP(Andnpd, andnpd)
  AVX_OP(Andnps, andnps)
  AVX_OP(Andpd, andpd)
  AVX_OP(Andps, andps)
  AVX_OP(Cmpeqpd, cmpeqpd)
  AVX_OP(Cmpeqps, cmpeqps)
  AVX_OP(Cmplepd, cmplepd)
  AVX_OP(Cmpleps, cmpleps)
  AVX_OP(Cmpltpd, cmpltpd)
  AVX_OP(Cmpltps, cmpltps)
  AVX_OP(Cmpneqpd, cmpneqpd)
  AVX_OP(Cmpneqps, cmpneqps)
  AVX_OP(Cmpunordpd, cmpunordpd)
  AVX_OP(Cmpunordps, cmpunordps)
  AVX_OP(Cvtdq2pd, cvtdq2pd)
  AVX_OP(Cvtdq2ps, cvtdq2ps)
  AVX_OP(Cvtpd2ps, cvtpd2ps)
  AVX_OP(Cvtps2pd, cvtps2pd)
  AVX_OP(Cvtsd2ss, cvtsd2ss)
  AVX_OP(Cvtss2sd, cvtss2sd)
  AVX_OP(Cvttpd2dq, cvttpd2dq)
  AVX_OP(Cvttps2dq, cvttps2dq)
  AVX_OP(Cvttsd2si, cvttsd2si)
  AVX_OP(Cvttss2si, cvttss2si)
  AVX_OP(Divpd, divpd)
  AVX_OP(Divps, divps)
  AVX_OP(Divsd, divsd)
  AVX_OP(Divss, divss)
  AVX_OP(Maxpd, maxpd)
  AVX_OP(Maxps, maxps)
  AVX_OP(Minpd, minpd)
  AVX_OP(Minps, minps)
  AVX_OP(Movaps, movaps)
  AVX_OP(Movd, movd)
  AVX_OP(Movhlps, movhlps)
  AVX_OP(Movhps, movhps)
  AVX_OP(Movlps, movlps)
  AVX_OP(Movmskpd, movmskpd)
  AVX_OP(Movmskps, movmskps)
  AVX_OP(Movsd, movsd)
  AVX_OP(Movss, movss)
  AVX_OP(Movupd, movupd)
  AVX_OP(Movups, movups)
  AVX_OP(Mulpd, mulpd)
  AVX_OP(Mulps, mulps)
  AVX_OP(Mulsd, mulsd)
  AVX_OP(Mulss, mulss)
  AVX_OP(Orpd, orpd)
  AVX_OP(Orps, orps)
  AVX_OP(Packssdw, packssdw)
  AVX_OP(Packsswb, packsswb)
  AVX_OP(Packuswb, packuswb)
  AVX_OP(Paddb, paddb)
  AVX_OP(Paddd, paddd)
  AVX_OP(Paddq, paddq)
  AVX_OP(Paddsb, paddsb)
  AVX_OP(Paddsw, paddsw)
  AVX_OP(Paddusb, paddusb)
  AVX_OP(Paddusw, paddusw)
  AVX_OP(Paddw, paddw)
  AVX_OP(Pavgb, pavgb)
  AVX_OP(Pavgw, pavgw)
  AVX_OP(Pcmpgtb, pcmpgtb)
  AVX_OP(Pcmpgtd, pcmpgtd)
  AVX_OP(Pcmpgtw, pcmpgtw)
  AVX_OP(Pcmpeqb, pcmpeqb)
  AVX_OP(Pcmpeqd, pcmpeqd)
  AVX_OP(Pcmpeqw, pcmpeqw)
  AVX_OP(Pmaddwd, pmaddwd)
  AVX_OP(Pmaxsw, pmaxsw)
  AVX_OP(Pmaxub, pmaxub)
  AVX_OP(Pminsw, pminsw)
  AVX_OP(Pminub, pminub)
  AVX_OP(Pmovmskb, pmovmskb)
  AVX_OP(Pmullw, pmullw)
  AVX_OP(Pmuludq, pmuludq)
  AVX_OP(Pshufd, pshufd)
  AVX_OP(Pshufhw, pshufhw)
  AVX_OP(Pshuflw, pshuflw)
  AVX_OP(Pslld, pslld)
  AVX_OP(Psllq, psllq)
  AVX_OP(Psllw, psllw)
  AVX_OP(Psrad, psrad)
  AVX_OP(Psraw, psraw)
  AVX_OP(Psrld, psrld)
  AVX_OP(Psrlq, psrlq)
  AVX_OP(Psrlw, psrlw)
  AVX_OP(Psubb, psubb)
  AVX_OP(Psubd, psubd)
  AVX_OP(Psubq, psubq)
  AVX_OP(Psubsb, psubsb)
  AVX_OP(Psubsw, psubsw)
  AVX_OP(Psubusb, psubusb)
  AVX_OP(Psubusw, psubusw)
  AVX_OP(Psubw, psubw)
  AVX_OP(Punpckhbw, punpckhbw)
  AVX_OP(Punpckhdq, punpckhdq)
  AVX_OP(Punpckhqdq, punpckhqdq)
  AVX_OP(Punpckhwd, punpckhwd)
  AVX_OP(Punpcklbw, punpcklbw)
  AVX_OP(Punpckldq, punpckldq)
  AVX_OP(Punpcklqdq, punpcklqdq)
  AVX_OP(Punpcklwd, punpcklwd)
  AVX_OP(Rcpps, rcpps)
  AVX_OP(Rsqrtps, rsqrtps)
  AVX_OP(Sqrtpd, sqrtpd)
  AVX_OP(Sqrtps, sqrtps)
  AVX_OP(Sqrtsd, sqrtsd)
  AVX_OP(Sqrtss, sqrtss)
  AVX_OP(Subpd, subpd)
  AVX_OP(Subps, subps)
  AVX_OP(Subsd, subsd)
  AVX_OP(Subss, subss)
  AVX_OP(Ucomisd, ucomisd)
  AVX_OP(Ucomiss, ucomiss)
  AVX_OP(Unpcklps, unpcklps)
  AVX_OP(Xorpd, xorpd)
  AVX_OP(Xorps, xorps)

  // Many AVX processors have separate integer/floating-point domains, so use
  // vmovaps if AVX is supported. On SSE, movaps is 1 byte shorter than movdqa,
  // and has the same behavior. Most SSE processors also don't have the same
  // delay moving between integer and floating-point domains.
  AVX_OP_WITH_DIFF_SSE_INSTR(Movapd, movapd, movaps)
  AVX_OP_WITH_DIFF_SSE_INSTR(Movdqa, movdqa, movaps)
  AVX_OP_WITH_DIFF_SSE_INSTR(Movdqu, movdqu, movups)
  AVX_OP_WITH_DIFF_SSE_INSTR(Pand, pand, andps)
  AVX_OP_WITH_DIFF_SSE_INSTR(Por, por, orps)
  AVX_OP_WITH_DIFF_SSE_INSTR(Pxor, pxor, xorps)

  AVX_OP_SSE3(Haddps, haddps)
  AVX_OP_SSE3(Movddup, movddup)
  AVX_OP_SSE3(Movshdup, movshdup)

  AVX_OP_SSSE3(Pabsb, pabsb)
  AVX_OP_SSSE3(Pabsd, pabsd)
  AVX_OP_SSSE3(Pabsw, pabsw)
  AVX_OP_SSSE3(Palignr, palignr)
  AVX_OP_SSSE3(Pmulhrsw, pmulhrsw)
  AVX_OP_SSSE3(Psignb, psignb)
  AVX_OP_SSSE3(Psignd, psignd)
  AVX_OP_SSSE3(Psignw, psignw)

  AVX_OP_SSE4_1(Extractps, extractps)
  AVX_OP_SSE4_1(Insertps, insertps)
  AVX_OP_SSE4_1(Packusdw, packusdw)
  AVX_OP_SSE4_1(Pblendw, pblendw)
  AVX_OP_SSE4_1(Pcmpeqq, pcmpeqq)
  AVX_OP_SSE4_1(Pextrb, pextrb)
  AVX_OP_SSE4_1(Pextrw, pextrw)
  AVX_OP_SSE4_1(Pmaxsb, pmaxsb)
  AVX_OP_SSE4_1(Pmaxsd, pmaxsd)
  AVX_OP_SSE4_1(Pmaxud, pmaxud)
  AVX_OP_SSE4_1(Pmaxuw, pmaxuw)
  AVX_OP_SSE4_1(Pminsb, pminsb)
  AVX_OP_SSE4_1(Pminsd, pminsd)
  AVX_OP_SSE4_1(Pminud, pminud)
  AVX_OP_SSE4_1(Pminuw, pminuw)
  AVX_OP_SSE4_1(Pmovsxbw, pmovsxbw)
  AVX_OP_SSE4_1(Pmovsxdq, pmovsxdq)
  AVX_OP_SSE4_1(Pmovsxwd, pmovsxwd)
  AVX_OP_SSE4_1(Pmovzxbw, pmovzxbw)
  AVX_OP_SSE4_1(Pmovzxbd, pmovzxbd)
  AVX_OP_SSE4_1(Pmovzxdq, pmovzxdq)
  AVX_OP_SSE4_1(Pmovzxwd, pmovzxwd)
  AVX_OP_SSE4_1(Pmulld, pmulld)
  AVX_OP_SSE4_1(Ptest, ptest)
  AVX_OP_SSE4_1(Roundpd, roundpd)
  AVX_OP_SSE4_1(Roundps, roundps)
  AVX_OP_SSE4_1(Roundsd, roundsd)
  AVX_OP_SSE4_1(Roundss, roundss)

#undef AVX_OP
#undef AVX_OP_SSE3
#undef AVX_OP_SSSE3
#undef AVX_OP_SSE4_1
#undef AVX_OP_SSE4_2

  void F64x2ExtractLane(DoubleRegister dst, XMMRegister src, uint8_t lane);
  void F64x2ReplaceLane(XMMRegister dst, XMMRegister src, DoubleRegister rep,
                        uint8_t lane);
  void F64x2Min(XMMRegister dst, XMMRegister lhs, XMMRegister rhs,
                XMMRegister scratch);
  void F64x2Max(XMMRegister dst, XMMRegister lhs, XMMRegister rhs,
                XMMRegister scratch);
  void F32x4Splat(XMMRegister dst, DoubleRegister src);
  void F32x4ExtractLane(FloatRegister dst, XMMRegister src, uint8_t lane);
  void F32x4Min(XMMRegister dst, XMMRegister lhs, XMMRegister rhs,
                XMMRegister scratch);
  void F32x4Max(XMMRegister dst, XMMRegister lhs, XMMRegister rhs,
                XMMRegister scratch);
  void S128Store32Lane(Operand dst, XMMRegister src, uint8_t laneidx);
  void I8x16Splat(XMMRegister dst, Register src, XMMRegister scratch);
  void I8x16Splat(XMMRegister dst, Operand src, XMMRegister scratch);
  void I8x16Shl(XMMRegister dst, XMMRegister src1, uint8_t src2, Register tmp1,
                XMMRegister tmp2);
  void I8x16Shl(XMMRegister dst, XMMRegister src1, Register src2, Register tmp1,
                XMMRegister tmp2, XMMRegister tmp3);
  void I8x16ShrS(XMMRegister dst, XMMRegister src1, uint8_t src2,
                 XMMRegister tmp);
  void I8x16ShrS(XMMRegister dst, XMMRegister src1, Register src2,
                 Register tmp1, XMMRegister tmp2, XMMRegister tmp3);
  void I8x16ShrU(XMMRegister dst, XMMRegister src1, uint8_t src2, Register tmp1,
                 XMMRegister tmp2);
  void I8x16ShrU(XMMRegister dst, XMMRegister src1, Register src2,
                 Register tmp1, XMMRegister tmp2, XMMRegister tmp3);
  void I16x8Splat(XMMRegister dst, Register src);
  void I16x8Splat(XMMRegister dst, Operand src);
  void I16x8ExtMulLow(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                      XMMRegister scrat, bool is_signed);
  void I16x8ExtMulHighS(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                        XMMRegister scratch);
  void I16x8ExtMulHighU(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                        XMMRegister scratch);
  void I16x8SConvertI8x16High(XMMRegister dst, XMMRegister src);
  void I16x8UConvertI8x16High(XMMRegister dst, XMMRegister src,
                              XMMRegister scratch);
  // Will move src1 to dst if AVX is not supported.
  void I16x8Q15MulRSatS(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                        XMMRegister scratch);
  void I16x8DotI8x16I7x16S(XMMRegister dst, XMMRegister src1, XMMRegister src2);
  void I32x4DotI8x16I7x16AddS(XMMRegister dst, XMMRegister src1,
                              XMMRegister src2, XMMRegister src3,
                              XMMRegister scratch, XMMRegister splat_reg);
  void I32x4ExtAddPairwiseI16x8U(XMMRegister dst, XMMRegister src,
                                 XMMRegister tmp);
  // Requires that dst == src1 if AVX is not supported.
  void I32x4ExtMul(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                   XMMRegister scratch, bool low, bool is_signed);
  void I32x4SConvertI16x8High(XMMRegister dst, XMMRegister src);
  void I32x4UConvertI16x8High(XMMRegister dst, XMMRegister src,
                              XMMRegister scratch);
  void I64x2Neg(XMMRegister dst, XMMRegister src, XMMRegister scratch);
  void I64x2Abs(XMMRegister dst, XMMRegister src, XMMRegister scratch);
  void I64x2GtS(XMMRegister dst, XMMRegister src0, XMMRegister src1,
                XMMRegister scratch);
  void I64x2GeS(XMMRegister dst, XMMRegister src0, XMMRegister src1,
                XMMRegister scratch);
  void I64x2ShrS(XMMRegister dst, XMMRegister src, uint8_t shift,
                 XMMRegister xmm_tmp);
  void I64x2ShrS(XMMRegister dst, XMMRegister src, Register shift,
                 XMMRegister xmm_tmp, XMMRegister xmm_shift,
                 Register tmp_shift);
  void I64x2Mul(XMMRegister dst, XMMRegister lhs, XMMRegister rhs,
                XMMRegister tmp1, XMMRegister tmp2);
  void I64x2ExtMul(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                   XMMRegister scratch, bool low, bool is_signed);
  void I64x2SConvertI32x4High(XMMRegister dst, XMMRegister src);
  void I64x2UConvertI32x4High(XMMRegister dst, XMMRegister src,
                              XMMRegister scratch);
  void S128Not(XMMRegister dst, XMMRegister src, XMMRegister scratch);
  // Requires dst == mask when AVX is not supported.
  void S128Select(XMMRegister dst, XMMRegister mask, XMMRegister src1,
                  XMMRegister src2, XMMRegister scratch);
  void S128Load8Splat(XMMRegister dst, Operand src, XMMRegister scratch);
  void S128Load16Splat(XMMRegister dst, Operand src, XMMRegister scratch);
  void S128Load32Splat(XMMRegister dst, Operand src);
  void S128Store64Lane(Operand dst, XMMRegister src, uint8_t laneidx);

  void F64x2Qfma(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 XMMRegister src3, XMMRegister tmp);
  void F64x2Qfms(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 XMMRegister src3, XMMRegister tmp);
  void F32x4Qfma(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 XMMRegister src3, XMMRegister tmp);
  void F32x4Qfms(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 XMMRegister src3, XMMRegister tmp);

 protected:
  template <typename Op>
  using AvxFn = void (Assembler::*)(XMMRegister, XMMRegister, Op, uint8_t);
  template <typename Op>
  using NoAvxFn = void (Assembler::*)(XMMRegister, Op, uint8_t);

  template <typename Op>
  void PinsrHelper(Assembler* assm, AvxFn<Op> avx, NoAvxFn<Op> noavx,
                   XMMRegister dst, XMMRegister src1, Op src2, uint8_t imm8,
                   uint32_t* load_pc_offset = nullptr,
                   std::optional<CpuFeature> feature = std::nullopt) {
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope scope(assm, AVX);
      if (load_pc_offset) *load_pc_offset = assm->pc_offset();
      (assm->*avx)(dst, src1, src2, imm8);
      return;
    }

    if (dst != src1) assm->movaps(dst, src1);
    if (load_pc_offset) *load_pc_offset = assm->pc_offset();
    if (feature.has_value()) {
      DCHECK(CpuFeatures::IsSupported(*feature));
      CpuFeatureScope scope(assm, *feature);
      (assm->*noavx)(dst, src2, imm8);
    } else {
      (assm->*noavx)(dst, src2, imm8);
    }
  }

 private:
  template <typename Op>
  void I8x16SplatPreAvx2(XMMRegister dst, Op src, XMMRegister scratch);
  template <typename Op>
  void I16x8SplatPreAvx2(XMMRegister dst, Op src);
};

// Common base class template shared by ia32 and x64 MacroAssembler. This uses
// the Curiously Recurring Template Pattern (CRTP), where Impl is the actual
// class (subclass of SharedMacroAssembler instantiated with the actual
// class). This allows static polymorphism, where member functions can be move
// into SharedMacroAssemblerBase, and we can also call into member functions
// defined in ia32 or x64 specific MacroAssembler from within this template
// class, via Impl.
//
// Note: all member functions must be defined in this header file so that the
// compiler can generate code for the function definitions. See
// https://isocpp.org/wiki/faq/templates#templates-defn-vs-decl for rationale.
// If a function does not need polymorphism, move it into
// SharedMacroAssemblerBase, and define it outside of this header.
template <typename Impl>
class V8_EXPORT_PRIVATE SharedMacroAssembler : public SharedMacroAssemblerBase {
  using SharedMacroAssemblerBase::SharedMacroAssemblerBase;

 public:
  void Abspd(XMMRegister dst, XMMRegister src, Register tmp) {
    FloatUnop(dst, src, tmp, &SharedMacroAssemblerBase::Andps,
              ExternalReference::address_of_double_abs_constant());
  }

  void Absps(XMMRegister dst, XMMRegister src, Register tmp) {
    FloatUnop(dst, src, tmp, &SharedMacroAssemblerBase::Andps,
              ExternalReference::address_of_float_abs_constant());
  }

  void Absph(XMMRegister dst, XMMRegister src, Register tmp) {
    FloatUnop(dst, src, tmp, &SharedMacroAssemblerBase::Andps,
              ExternalReference::address_of_fp16_abs_constant());
  }

  void Negpd(XMMRegister dst, XMMRegister src, Register tmp) {
    FloatUnop(dst, src, tmp, &SharedMacroAssemblerBase::Xorps,
              ExternalReference::address_of_double_neg_constant());
  }

  void Negps(XMMRegister dst, XMMRegister src, Register tmp) {
    FloatUnop(dst, src, tmp, &SharedMacroAssemblerBase::Xorps,
              ExternalReference::address_of_float_neg_constant());
  }

  void Negph(XMMRegister dst, XMMRegister src, Register tmp) {
    FloatUnop(dst, src, tmp, &SharedMacroAssemblerBase::Xorps,
              ExternalReference::address_of_fp16_neg_constant());
  }
#undef FLOAT_UNOP

  void Pextrd(Register dst, XMMRegister src, uint8_t imm8) {
    if (imm8 == 0) {
      Movd(dst, src);
      return;
    }

    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope scope(this, AVX);
      vpextrd(dst, src, imm8);
    } else if (CpuFeatures::IsSupported(SSE4_1)) {
      CpuFeatureScope sse_scope(this, SSE4_1);
      pextrd(dst, src, imm8);
    } else {
      DCHECK_LT(imm8, 2);
      impl()->PextrdPreSse41(dst, src, imm8);
    }
  }

  template <typename Op>
  void Pinsrd(XMMRegister dst, XMMRegister src1, Op src2, uint8_t imm8,
              uint32_t* load_pc_offset = nullptr) {
    if (CpuFeatures::IsSupported(SSE4_1)) {
      PinsrHelper(this, &Assembler::vpinsrd, &Assembler::pinsrd, dst, src1,
                  src2, imm8, load_pc_offset,
                  std::optional<CpuFeature>(SSE4_1));
    } else {
      if (dst != src1) {
        movaps(dst, src1);
      }
      impl()->PinsrdPreSse41(dst, src2, imm8, load_pc_offset);
    }
  }

  template <typename Op>
  void Pinsrd(XMMRegister dst, Op src, uint8_t imm8,
              uint32_t* load_pc_offset = nullptr) {
    Pinsrd(dst, dst, src, imm8, load_pc_offset);
  }

  void F64x2ConvertLowI32x4U(XMMRegister dst, XMMRegister src,
                             Register scratch) {
    ASM_CODE_COMMENT(this);
    // dst = [ src_low, 0x43300000, src_high, 0x4330000 ];
    // 0x43300000'00000000 is a special double where the significand bits
    // precisely represents all uint32 numbers.
    if (!CpuFeatures::IsSupported(AVX) && dst != src) {
      movaps(dst, src);
      src = dst;
    }
    Unpcklps(dst, src,
             ExternalReferenceAsOperand(
                 ExternalReference::
                     address_of_wasm_f64x2_convert_low_i32x4_u_int_mask(),
                 scratch));
    Subpd(dst,
          ExternalReferenceAsOperand(
              ExternalReference::address_of_wasm_double_2_power_52(), scratch));
  }

  void I32x4SConvertF32x4(XMMRegister dst, XMMRegister src, XMMRegister tmp,
                          Register scratch) {
    ASM_CODE_COMMENT(this);
    Operand op = ExternalReferenceAsOperand(
        ExternalReference::address_of_wasm_int32_overflow_as_float(), scratch);

    // This algorithm works by:
    // 1. lanes with NaNs are zero-ed
    // 2. lanes ge than 2147483648.0f (MAX_INT32+1) set to 0xffff'ffff
    // 3. cvttps2dq sets all out of range lanes to 0x8000'0000
    //   a. correct for underflows (< MIN_INT32)
    //   b. wrong for overflow, and we know which lanes overflow from 2.
    // 4. adjust for 3b by xor-ing 2 and 3
    //   a. 0x8000'0000 xor 0xffff'ffff = 0x7fff'ffff (MAX_INT32)
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope scope(this, AVX);
      vcmpeqps(tmp, src, src);
      vandps(dst, src, tmp);
      vcmpgeps(tmp, src, op);
      vcvttps2dq(dst, dst);
      vpxor(dst, dst, tmp);
    } else {
      if (src == dst) {
        movaps(tmp, src);
        cmpeqps(tmp, tmp);
        andps(dst, tmp);
        movaps(tmp, op);
        cmpleps(tmp, dst);
        cvttps2dq(dst, dst);
        xorps(dst, tmp);
      } else {
        movaps(tmp, op);
        cmpleps(tmp, src);
        cvttps2dq(dst, src);
        xorps(dst, tmp);
        movaps(tmp, src);
        cmpeqps(tmp, tmp);
        andps(dst, tmp);
      }
    }
  }

  void I32x4TruncSatF64x2SZero(XMMRegister dst, XMMRegister src,
                               XMMRegister scratch, Register tmp) {
    ASM_CODE_COMMENT(this);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      XMMRegister original_dst = dst;
      // Make sure we don't overwrite src.
      if (dst == src) {
        DCHECK_NE(src, scratch);
        dst = scratch;
      }
      // dst = 0 if src == NaN, else all ones.
      vcmpeqpd(dst, src, src);
      // dst = 0 if src == NaN, else INT32_MAX as double.
      vandpd(
          dst, dst,
          ExternalReferenceAsOperand(
              ExternalReference::address_of_wasm_int32_max_as_double(), tmp));
      // dst = 0 if src == NaN, src is saturated to INT32_MAX as double.
      vminpd(dst, src, dst);
      // Values > INT32_MAX already saturated, values < INT32_MIN raises an
      // exception, which is masked and returns 0x80000000.
      vcvttpd2dq(original_dst, dst);
    } else {
      if (dst != src) {
        movaps(dst, src);
      }
      movaps(scratch, dst);
      cmpeqpd(scratch, dst);
      andps(scratch,
            ExternalReferenceAsOperand(
                ExternalReference::address_of_wasm_int32_max_as_double(), tmp));
      minpd(dst, scratch);
      cvttpd2dq(dst, dst);
    }
  }

  void I32x4TruncSatF64x2UZero(XMMRegister dst, XMMRegister src,
                               XMMRegister scratch, Register tmp) {
    ASM_CODE_COMMENT(this);
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope avx_scope(this, AVX);
      vxorpd(scratch, scratch, scratch);
      // Saturate to 0.
      vmaxpd(dst, src, scratch);
      // Saturate to UINT32_MAX.
      vminpd(
          dst, dst,
          ExternalReferenceAsOperand(
              ExternalReference::address_of_wasm_uint32_max_as_double(), tmp));
      // Truncate.
      vroundpd(dst, dst, kRoundToZero);
      // Add to special double where significant bits == uint32.
      vaddpd(dst, dst,
             ExternalReferenceAsOperand(
                 ExternalReference::address_of_wasm_double_2_power_52(), tmp));
      // Extract low 32 bits of each double's significand, zero top lanes.
      // dst = [dst[0], dst[2], 0, 0]
      vshufps(dst, dst, scratch, 0x88);
    } else {
      CpuFeatureScope scope(this, SSE4_1);
      if (dst != src) {
        movaps(dst, src);
      }
      xorps(scratch, scratch);
      maxpd(dst, scratch);
      minpd(dst, ExternalReferenceAsOperand(
                     ExternalReference::address_of_wasm_uint32_max_as_
"""


```