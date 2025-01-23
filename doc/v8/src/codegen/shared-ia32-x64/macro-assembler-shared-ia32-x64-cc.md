Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Understanding of the Request:**

The core request is to understand the *functionality* of the provided C++ code snippet. Key points to note are:

* **Context:** The code is part of V8, specifically within the `v8/src/codegen/shared-ia32-x64` directory. This immediately suggests it deals with low-level code generation for IA32 and x64 architectures.
* **File Name:** `macro-assembler-shared-ia32-x64.cc`. The "macro-assembler" part is crucial. Macro assemblers provide higher-level abstractions over raw assembly instructions. The "shared" part implies it contains logic common to both IA32 and x64.
* **Specific Questions:** The request also asks about potential Torque (V8's domain-specific language) connection, JavaScript relevance, code logic inference (with inputs/outputs), and common programming errors.

**2. High-Level Code Analysis (Skimming and Identifying Key Structures):**

The first step is to quickly skim the code to get a general feel for its structure. I'd look for:

* **Includes:** `#include` directives tell us about dependencies. Here, we see includes for `macro-assembler-shared-ia32-x64.h`, `assembler.h`, `cpu-features.h`, and `register.h`. The presence of architecture-specific headers (`ia32/register-ia32.h` and `x64/register-x64.h`) reinforces the architecture-specific nature.
* **Preprocessor Directives:** `#if`, `#elif`, `#else`, `#endif` blocks are very prominent. These are clearly used to handle differences between IA32 and x64. This confirms the "shared" aspect.
* **Namespaces:** `namespace v8 { namespace internal { ... } }` indicates the code belongs to V8's internal implementation.
* **Class Structure:** We see `SharedMacroAssemblerBase`. This is the central class, and its methods will likely be the core of the functionality.
* **Method Signatures:**  The methods have names like `Move`, `Add`, `And`, `Movhps`, `Blendvpd`, `F32x4Min`, `I8x16Splat`, `I16x8ExtMulLow`, etc. These names strongly suggest they correspond to assembly-level operations (move, add, and, vector instructions like blend, min, splat, multiply).
* **CPU Feature Checks:**  `CpuFeatures::IsSupported(AVX)` and similar checks appear frequently. This indicates the code leverages different instruction sets depending on the CPU's capabilities.
* **DCHECK Statements:** `DCHECK(...)` are assertions, used for internal debugging and verifying assumptions.

**3. Deeper Dive into Functionality (Analyzing Individual Methods):**

Now, I'd go through the methods more carefully, focusing on what each one does:

* **Basic Operations (Move, Add, And):**  These are straightforward wrappers around the architecture-specific assembly instructions (`mov`, `movl`, `movq`, `add`, `addq`, `and_`, `andl`, `andq`). The code clearly abstracts away the naming differences.
* **Floating-Point Operations (Movhps, Movlps, Blendvpd, Blendvps, Shufps, F64x2ExtractLane, etc.):** These deal with XMM registers and various SSE/AVX instructions for manipulating floating-point data. The code handles cases where AVX is available versus when it's not, providing fallback implementations using SSE instructions.
* **Vector Integer Operations (I8x16Splat, I8x16Shl, I8x16ShrS, I8x16ShrU, I16x8Splat, I16x8ExtMulLow/High, I32x4ExtMul, I64x2Neg/Abs/GtS/GeS/ShrS):**  This is a significant portion of the code, focusing on operations on 128-bit vectors of integers. Again, the code often provides different implementations based on CPU features (AVX2, SSSE3, etc.). The method names clearly correspond to SIMD (Single Instruction, Multiple Data) operations.
* **Helper Macros (DCHECK_OPERAND_IS_NOT_REG):** These are small utilities to enforce certain conditions.

**4. Answering the Specific Questions:**

* **Functionality Summary:** Based on the method names and the operations they perform, the core functionality is providing a **shared macro assembler** for IA32 and x64. It offers higher-level abstractions over assembly instructions, handling architecture differences and leveraging CPU features for optimization.
* **Torque Connection:** The prompt itself gives the hint: if the file ended in `.tq`, it would be Torque. Since it ends in `.cc`, it's standard C++. Thus, there's no direct Torque connection for *this specific file*. However, Torque might *generate* code that uses this macro assembler.
* **JavaScript Relevance:** This code is fundamental to how V8 executes JavaScript. JavaScript engines need to translate JavaScript code into machine code. This macro assembler is a key component in that process, providing the building blocks for generating efficient IA32/x64 assembly.
* **JavaScript Example:** A simple arithmetic operation like `const sum = a + b;` in JavaScript would, at the low level, likely involve a `Move` instruction to load the values of `a` and `b` into registers, and an `Add` instruction to perform the addition. More complex SIMD operations in JavaScript (e.g., using TypedArrays for vector math) would directly map to the vector instructions implemented here.
* **Code Logic Inference:**  Pick a simple method like `Move(Register dst, uint32_t src)`. Input: `dst` representing a register (e.g., `rax` on x64) and `src` being a 32-bit unsigned integer (e.g., `10`). Output: The register `dst` will contain the value `10`.
* **Common Programming Errors:** A potential error this code might help *avoid* is incorrect register usage or using the wrong instruction for a specific architecture. The macro assembler abstracts these details. A common *user* error that could relate is trying to perform operations on data types that don't match the underlying instructions (e.g., trying to add a float and an integer without proper conversion), although this code operates at a lower level.

**5. Structuring the Output:**

Finally, organize the findings into a clear and concise summary, addressing each part of the original request. Use bullet points and clear language to explain the functionality, connections, and examples.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the individual instruction names. It's important to step back and see the bigger picture: this is a *macro assembler*, providing an abstraction layer.
* I might have initially struggled to come up with a simple JavaScript example. The key is to relate it to fundamental operations.
* Ensuring the "assumptions" and "output" for code logic are clear and simple is crucial. Avoid overly complex examples.

By following these steps, iteratively analyzing the code, and relating it back to the original request, we can arrive at a comprehensive understanding of the functionality of `macro-assembler-shared-ia32-x64.cc`.
这是对V8 JavaScript引擎源代码文件 `v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.cc` 的第一部分的分析和功能归纳。

**功能列举:**

这个C++源文件的主要功能是定义了一个共享的宏汇编器基类 `SharedMacroAssemblerBase`，用于生成针对 IA32 (x86) 和 x64 架构的机器码。它提供了一系列高级接口（C++方法），这些接口封装了底层的汇编指令，使得在 V8 编译器的代码生成阶段更容易生成跨这两种架构的代码。

具体来说，它包含以下类型的操作：

1. **基本的寄存器操作:**
   - `Move(Register dst, uint32_t src)`: 将一个 32 位立即数移动到寄存器。
   - `Move(Register dst, Register src)`: 将一个寄存器的值移动到另一个寄存器。
   - `Add(Register dst, Immediate src)`: 将一个立即数加到寄存器。
   - `And(Register dst, Immediate src)`: 将一个立即数与寄存器进行按位与操作。

2. **浮点数和SIMD (SSE/AVX) 操作:**
   - 提供了诸如 `Movhps`, `Movlps`, `Blendvpd`, `Blendvps`, `Pblendvb`, `Shufps` 等 SSE 和 AVX 指令的封装，用于处理浮点数和 SIMD 数据。这些方法会根据 CPU 是否支持 AVX 指令集来选择不同的实现路径。
   - 实现了诸如 `F64x2ExtractLane`, `F64x2ReplaceLane`, `F32x4Min`, `F32x4Max`, `F64x2Min`, `F64x2Max`, `F32x4Splat`, `F32x4ExtractLane` 等针对 128 位 XMM 寄存器进行操作的函数，用于处理向量化的浮点数。

3. **向量整数操作:**
   - 提供了诸如 `I8x16Splat`, `I8x16Shl`, `I8x16ShrS`, `I8x16ShrU`, `I16x8Splat`, `I16x8ExtMulLow`, `I16x8ExtMulHighS`, `I16x8ExtMulHighU`, `I16x8SConvertI8x16High`, `I16x8UConvertI8x16High`, `I16x8Q15MulRSatS`, `I16x8DotI8x16I7x16S`, `I32x4DotI8x16I7x16AddS`, `I32x4ExtAddPairwiseI16x8U`, `I32x4ExtMul`, `I32x4SConvertI16x8High`, `I32x4UConvertI16x8High`, `I64x2Neg`, `I64x2Abs`, `I64x2GtS`, `I64x2GeS`, `I64x2ShrS` 等函数，用于处理 128 位 XMM 寄存器中的向量化整数操作，包括算术运算、位运算、比较运算等。 同样，这些方法会根据 CPU 特性选择合适的指令。

**关于 .tq 结尾的文件:**

如果 `v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是 V8 使用的一种领域特定语言 (DSL)，用于定义运行时函数的实现。  这个文件当前以 `.cc` 结尾，所以它是标准的 C++ 源代码。

**与 JavaScript 的关系:**

这个文件中的代码直接参与了将 JavaScript 代码编译成机器码的过程。当 V8 编译 JavaScript 代码时，它会使用宏汇编器生成目标架构的汇编指令。  `SharedMacroAssemblerBase` 提供的这些方法就是生成这些指令的工具。

**JavaScript 举例说明:**

例如，一个简单的 JavaScript 加法操作 `let sum = a + b;`，在 V8 编译时，可能会生成类似以下的汇编指令（简化示例）：

```assembly
// 假设 'a' 的值在寄存器 EAX， 'b' 的值在寄存器 EBX (IA32) 或 RAX, RBX (x64)
// 使用 SharedMacroAssemblerBase 的 Add 方法
// 在 IA32 上：
add(eax, ebx);
// 在 x64 上：
addq(rax, rbx);
// 然后将结果移动到存储 'sum' 的位置
```

`SharedMacroAssemblerBase::Add` 方法的作用就是封装了 `add` 或 `addq` 指令，使得编译器不需要关心当前的目标架构是 IA32 还是 x64。

对于 SIMD 操作，考虑以下 JavaScript 代码：

```javascript
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const sum = Float32Array.from(a, (val, i) => val + b[i]);
```

在 V8 编译这段代码时，可能会使用 `SharedMacroAssemblerBase` 提供的 SIMD 相关方法，例如 `F32x4Add` (虽然这个文件中没有直接看到 `F32x4Add`，但这是类似的功能)。底层的汇编指令可能是 `addps` (在支持 SSE 的情况下) 或 `vaddps` (在支持 AVX 的情况下)，这些都被 `SharedMacroAssemblerBase` 的方法所抽象。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `SharedMacroAssemblerBase::Move(Register(1), 0x12345678)`，其中 `Register(1)` 代表一个通用的寄存器，例如 IA32 的 `EAX` 或 x64 的 `RAX`。

* **假设输入:**
    * `dst`: 代表寄存器 EAX (IA32) 或 RAX (x64) 的 Register 对象。
    * `src`:  无符号 32 位整数 `0x12345678`。

* **输出:**
    * 在 IA32 架构下，生成的汇编指令将是 `mov eax, 0x12345678`。
    * 在 x64 架构下，生成的汇编指令将是 `movl rax, 0x12345678` (注意这里使用了 `movl` 来移动 32 位立即数到 64 位寄存器的低 32 位)。

假设我们调用 `SharedMacroAssemblerBase::F32x4Min(xmm1, xmm2, xmm3, xmm0)`，其中 `xmm1`, `xmm2`, `xmm3`, `xmm0` 代表 XMM 寄存器。

* **假设输入:**
    * `dst`:  XMM 寄存器 `xmm1`。
    * `lhs`:  XMM 寄存器 `xmm2`，包含四个单精度浮点数。
    * `rhs`:  XMM 寄存器 `xmm3`，包含四个单精度浮点数。
    * `scratch`: XMM 寄存器 `xmm0`，用作临时寄存器。

* **输出:**
    * 生成的汇编指令序列会比较 `xmm2` 和 `xmm3` 中对应的四个浮点数，并将最小值存储在 `xmm1` 中。具体的指令序列会根据是否支持 AVX 而有所不同，但最终结果是 `xmm1` 中的每个元素都是 `xmm2` 和 `xmm3` 对应元素的最小值。例如，如果 `xmm2` 包含 `[1.0, 3.0, 5.0, 7.0]`，`xmm3` 包含 `[2.0, 2.0, 6.0, 6.0]`，那么执行后 `xmm1` 将包含 `[1.0, 2.0, 5.0, 6.0]`，并且还会处理 NaN 值的情况。

**涉及用户常见的编程错误:**

虽然这个文件本身是 V8 内部的代码，用户不会直接编写或修改它，但它所生成的目标代码的效率和正确性会受到其实现的影响。与用户编程相关的常见错误可能包括：

1. **类型不匹配:**  例如，在 JavaScript 中对不同类型的数据进行操作，V8 需要生成相应的类型转换代码。宏汇编器需要提供支持这些转换的指令。如果宏汇编器的实现有误，可能会导致类型转换错误或性能下降。

2. **内存访问错误:** JavaScript 引擎在执行过程中需要管理内存。宏汇编器生成的指令负责读写内存。如果宏汇编器生成的地址计算有误，可能导致内存访问越界等错误。

3. **浮点数精度问题:** 浮点数运算存在精度问题。宏汇编器生成的浮点数运算指令的顺序和方式会影响最终结果的精度。用户可能会遇到意外的精度差异，这可能与宏汇编器如何使用 FPU 或 SSE/AVX 指令有关。

4. **SIMD 指令使用不当:** 如果 JavaScript 代码使用了 SIMD 操作（例如通过 `TypedArray`），宏汇编器需要正确地生成 SIMD 指令。常见的错误包括数据对齐问题、指令选择不当等，导致性能下降或产生错误结果。 例如，没有正确处理 NaN 值传播在 SIMD 最小值/最大值操作中是一个常见的陷阱，这个文件中的 `F32x4Min` 和 `F32x4Max` 方法就展示了如何处理这种情况。

**功能归纳:**

`v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.cc` 的第一部分主要定义了一个 **共享的宏汇编器基类**，它为 V8 编译器的代码生成阶段提供了一组 **高级的 C++ 接口**，用于生成针对 IA32 和 x64 架构的 **基本寄存器操作、浮点数和 SIMD 指令**。 这个类的设计目标是 **抽象掉不同架构的指令差异**，并 **利用 CPU 的特性 (如 AVX)** 来优化生成的代码。 它在 V8 将 JavaScript 代码转化为可执行的机器码的过程中扮演着至关重要的角色。

### 提示词
```
这是目录为v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  // tmp_shift can alias shift since we don't use shif
```