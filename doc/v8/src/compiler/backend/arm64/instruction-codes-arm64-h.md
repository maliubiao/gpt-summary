Response:
Let's break down the thought process to analyze this C++ header file.

1. **Identify the Core Purpose:** The filename `instruction-codes-arm64.h` strongly suggests this file defines instruction codes specific to the ARM64 architecture within the V8 JavaScript engine. The `#ifndef` and `#define` preprocessor directives confirm it's a header guard, preventing multiple inclusions.

2. **Namespace Analysis:** The code is within `v8::internal::compiler`. This tells us it's a low-level component within V8, part of the compilation pipeline. The `compiler` namespace further reinforces this.

3. **Core Structure - Macros:** The file heavily relies on macros (`#define`). This is a common pattern in low-level code for generating lists of similar items. The naming convention `TARGET_ARCH_*_LIST(V)` hints at a mechanism to define different categories of instruction codes.

4. **Deconstruct the Macros:**
    * `TARGET_ARCH_OPCODE_WITH_MEMORY_ACCESS_MODE_LIST(V)`: The name clearly indicates these opcodes involve memory access and likely have an associated `MemoryAccessMode`. The list contains instructions like `Ldr` (load register), `Str` (store register), and their variations (`b`, `D`, `h`, `Q`, etc., likely indicating byte, double word, halfword, quad word sizes). WASM-specific instructions are also present (`IF_WASM`). Atomic load/store instructions are also included.
    * `TARGET_ARCH_SIMD_OPCODE_LIST(V)`: This macro groups together opcodes related to Single Instruction Multiple Data (SIMD) operations. The prefixes `Arm64F`, `Arm64I`, and `Arm64S128` suggest floating-point, integer, and 128-bit SIMD operations, respectively. The suffixes like `fma`, `fms`, `pmin`, `pmax`, `shl`, `shr`, etc., point to specific SIMD operations (fused multiply-add, fused multiply-subtract, parallel minimum/maximum, shift left/right).
    * `TARGET_ARCH_OPCODE_LIST(V)`: This appears to be a comprehensive list of general ARM64 opcodes. It includes arithmetic (`Add`, `Sub`, `Mul`, `Div`), logical (`And`, `Or`, `Xor`), bit manipulation (`Lsl`, `Lsr`, `Asr`, `Ror`), comparison (`Cmp`, `Tst`), and floating-point (`Float32Add`, `Float64Mul`) instructions. It also contains instructions for conversions, atomic operations, and some utility instructions (`Claim`, `Poke`, `Peek`). Crucially, it *includes* the other two opcode lists, indicating a hierarchical structure.
    * `TARGET_ADDRESSING_MODE_LIST(V)`: This macro defines different ways data can be accessed (addressing modes). Examples include register direct (`R`), immediate values (`I`), memory access with register and immediate offset (`MRI`), memory access with register and register offset (`MRR`), and various shifted/extended register forms (`Operand2_R_*`).

5. **Infer Functionality:** Based on the identified opcodes and addressing modes, the primary function of this file is to define a set of symbolic names (enums or macro constants) representing the ARM64 instructions that the V8 compiler's backend can generate. These codes act as an intermediate representation between the compiler's high-level logic and the actual assembly instructions.

6. **Torque Check:** The prompt asks about the `.tq` extension. Since the file ends with `.h`, it's a standard C++ header file, not a Torque file. Torque files are used for defining built-in JavaScript functions and often have different syntax.

7. **JavaScript Relationship (Conceptual):**  While this file isn't directly JavaScript code, it's crucial for *executing* JavaScript on ARM64. When V8 compiles JavaScript, it eventually translates it into these low-level ARM64 instructions. Consider a simple JavaScript addition: `let a = 1; let b = 2; let c = a + b;`. The V8 compiler would use instructions defined in this header (like `Arm64Add`) to perform the addition on the ARM64 processor.

8. **Code Logic Inference (Simple Case):**  Take `Arm64Ldr` (Load Register). We can infer a basic input and output:
    * **Input:**  A memory address (calculated using an addressing mode like `MRI`), a destination register.
    * **Output:** The value at the memory address is loaded into the destination register.

9. **Common Programming Errors (Relating to Usage, not definition):**  This header itself doesn't contain programming logic that users would directly write. However, understanding these instruction codes is crucial for *compiler developers*. Errors might arise in the compiler backend if:
    * **Incorrect Opcode Selection:** The compiler chooses the wrong instruction for a given operation.
    * **Invalid Addressing Mode:** The compiler uses an addressing mode not supported by the chosen instruction.
    * **Register Allocation Issues:** The compiler assigns the wrong registers to operands, leading to incorrect instruction generation.

10. **Refine and Organize:**  Structure the findings into clear sections: Functionality, Torque check, JavaScript relationship, code logic example, and common errors (from a compiler development perspective). Use clear and concise language.

This structured approach, starting with the obvious and gradually digging deeper into the details of the macros and their contents, allows for a comprehensive understanding of the file's purpose and its role within the V8 engine.
这个头文件 `v8/src/compiler/backend/arm64/instruction-codes-arm64.h` 的主要功能是：

**定义了 V8 编译器后端在 ARM64 架构下生成机器码时所使用的指令代码（opcodes）。**

这些指令代码是编译器在将高级的中间表示（Intermediate Representation, IR）转换为实际的 ARM64 汇编指令的关键。每个宏定义（例如 `Arm64Ldr`, `Arm64Add`, `Arm64F64x2Qfma` 等）都代表一个特定的 ARM64 指令或指令序列。

**具体来说，这个文件做了以下几件事：**

1. **列举了 ARM64 架构下 V8 后端支持的所有指令。**  这些指令涵盖了加载/存储、算术运算、逻辑运算、比较、位操作、浮点运算、SIMD（单指令多数据）运算等。

2. **为每个指令定义了一个唯一的标识符（opcode）。**  这些标识符在编译器的后续阶段被用来选择正确的汇编指令生成逻辑。

3. **通过不同的宏定义对指令进行分类。**
   - `TARGET_ARCH_OPCODE_WITH_MEMORY_ACCESS_MODE_LIST`:  列出了需要指定内存访问模式的指令，例如各种 `Ldr`（Load Register）和 `Str`（Store Register）指令。
   - `TARGET_ARCH_SIMD_OPCODE_LIST`: 列出了 SIMD 相关的指令，这些指令可以并行处理多个数据元素。
   - `TARGET_ARCH_OPCODE_LIST`:  包含了所有指令的列表，它组合了前两个列表中的指令以及其他通用指令。
   - `TARGET_ADDRESSING_MODE_LIST`: 定义了指令可以使用的寻址模式，例如直接寻址、寄存器偏移寻址、立即数偏移寻址等。

**关于你提出的问题：**

* **如果 `v8/src/compiler/backend/arm64/instruction-codes-arm64.h` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**
   - 你的说法是正确的。如果文件以 `.tq` 结尾，那么它就是 V8 的 Torque 源代码。Torque 是一种用于定义 V8 内部运行时函数和内置对象的领域特定语言。然而，这个文件以 `.h` 结尾，所以它是标准的 C++ 头文件。

* **如果它与 javascript 的功能有关系，请用 javascript 举例说明。**
   - 这个头文件本身不是 JavaScript 代码，但它定义的指令代码是 **执行 JavaScript 代码的基础**。当 V8 编译 JavaScript 代码时，它会将 JavaScript 操作转换为一系列底层的机器指令，其中就包括这里定义的 ARM64 指令。

   **JavaScript 示例：**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   let result = add(5, 10);
   ```

   当 V8 编译 `add` 函数时，它最终会生成类似以下的 ARM64 指令（这只是一个简化的例子）：

   ```assembly
   // 假设 'a' 和 'b' 的值分别在寄存器 x0 和 x1 中
   add x2, x0, x1  // 将 x0 和 x1 的值相加，结果存入 x2 (对应 Arm64Add)
   mov x0, x2      // 将结果移动到返回值寄存器 x0
   ret             // 返回
   ```

   这里的 `add` 指令就对应于 `instruction-codes-arm64.h` 中定义的 `Arm64Add`。  简而言之，这个头文件定义了 V8 将 JavaScript 代码转化为机器可以执行的指令的“词汇表”。

* **如果有代码逻辑推理，请给出假设输入与输出。**
   - 这个头文件本身不包含可执行的代码逻辑，它只是定义了一些常量。 代码逻辑存在于 V8 编译器的其他部分，这些部分会使用这些指令代码来生成实际的汇编指令。

   但是，我们可以针对其中一个指令进行逻辑推理：

   **指令:** `Arm64Ldr x0, [x1, #8]` (假设这是由 `Arm64Ldr` 生成的一个具体指令)

   **假设输入:**
   - 寄存器 `x1` 的值为内存地址 `0x1000`
   - 内存地址 `0x1008` 处存储的值为 `0xABCDEF0123456789`

   **输出:**
   - 执行该指令后，寄存器 `x0` 的值将变为 `0xABCDEF0123456789`

   这个例子说明了 `Arm64Ldr` 指令的基本功能：从内存中加载数据到寄存器。

* **如果涉及用户常见的编程错误，请举例说明。**
   -  这个头文件本身不直接涉及用户常见的编程错误，因为它属于 V8 引擎的内部实现。 然而，理解这些底层的指令可以帮助理解一些潜在的性能问题或一些高级的 JavaScript 用法。

   一个相关的例子是 **类型混淆**。  在动态类型的 JavaScript 中，如果 V8 没有很好地进行类型推断，它可能需要生成更多的类型检查和转换指令。 了解不同的加载/存储指令（例如针对不同大小的数据类型）可以帮助理解为什么某些看似简单的操作在底层可能会产生更多的指令开销。

   例如，如果一个 JavaScript 变量在不同的地方被当作整数和浮点数使用，V8 可能需要生成指令来进行类型转换，例如 `Arm64Float64ToInt32` 或 `Arm64Int32ToFloat64`。 过多的这种转换操作可能会影响性能。

   另一个例子与 **SIMD 的高效使用** 相关。 如果开发者使用一些可以被 SIMD 指令加速的操作（例如数组的批量计算），V8 的编译器可能会使用 `TARGET_ARCH_SIMD_OPCODE_LIST` 中定义的指令，例如 `Arm64F64x2Qfma` (浮点数乘加) 来并行处理数据。  如果开发者没有意识到这一点，可能会编写出性能较差的循环代码，而编译器无法有效利用 SIMD 指令。

**总结：**

`v8/src/compiler/backend/arm64/instruction-codes-arm64.h` 是 V8 编译器后端在 ARM64 架构下的指令“字典”。它定义了编译器可以使用的所有基本操作，是连接高级 JavaScript 代码和底层硬件指令的关键桥梁。虽然普通 JavaScript 开发者不需要直接修改或查看这个文件，但了解其存在和功能有助于理解 JavaScript 执行的底层机制和潜在的性能优化方向。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/instruction-codes-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-codes-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_BACKEND_ARM64_INSTRUCTION_CODES_ARM64_H_
#define V8_COMPILER_BACKEND_ARM64_INSTRUCTION_CODES_ARM64_H_

namespace v8 {
namespace internal {
namespace compiler {

// ARM64-specific opcodes that specify which assembly sequence to emit.
// Most opcodes specify a single instruction.

// Opcodes that support a MemoryAccessMode.
#define TARGET_ARCH_OPCODE_WITH_MEMORY_ACCESS_MODE_LIST(V) \
  V(Arm64Ldr)                                              \
  V(Arm64Ldrb)                                             \
  V(Arm64LdrD)                                             \
  V(Arm64Ldrh)                                             \
  V(Arm64LdrQ)                                             \
  V(Arm64LdrS)                                             \
  V(Arm64LdrH)                                             \
  V(Arm64Ldrsb)                                            \
  V(Arm64LdrsbW)                                           \
  V(Arm64Ldrsh)                                            \
  V(Arm64LdrshW)                                           \
  V(Arm64Ldrsw)                                            \
  V(Arm64LdrW)                                             \
  IF_WASM(V, Arm64LoadLane)                                \
  IF_WASM(V, Arm64LoadSplat)                               \
  IF_WASM(V, Arm64S128Load16x4S)                           \
  IF_WASM(V, Arm64S128Load16x4U)                           \
  IF_WASM(V, Arm64S128Load32x2S)                           \
  IF_WASM(V, Arm64S128Load32x2U)                           \
  IF_WASM(V, Arm64S128Load8x8S)                            \
  IF_WASM(V, Arm64S128Load8x8U)                            \
  IF_WASM(V, Arm64StoreLane)                               \
  V(Arm64Str)                                              \
  V(Arm64StrPair)                                          \
  V(Arm64Strb)                                             \
  V(Arm64StrD)                                             \
  V(Arm64Strh)                                             \
  V(Arm64StrQ)                                             \
  V(Arm64StrS)                                             \
  V(Arm64StrH)                                             \
  V(Arm64StrW)                                             \
  V(Arm64StrWPair)                                         \
  V(Arm64LdrDecompressTaggedSigned)                        \
  V(Arm64LdrDecompressTagged)                              \
  V(Arm64LdrDecompressProtected)                           \
  V(Arm64StrCompressTagged)                                \
  V(Arm64Word64AtomicLoadUint64)                           \
  V(Arm64Word64AtomicStoreWord64)

#define TARGET_ARCH_SIMD_OPCODE_LIST(V) \
  V(Arm64F64x2Qfma)                     \
  V(Arm64F64x2Qfms)                     \
  V(Arm64F64x2Pmin)                     \
  V(Arm64F64x2Pmax)                     \
  V(Arm64F64x2ConvertLowI32x4S)         \
  V(Arm64F64x2ConvertLowI32x4U)         \
  V(Arm64F64x2PromoteLowF32x4)          \
  V(Arm64F32x4SConvertI32x4)            \
  V(Arm64F32x4UConvertI32x4)            \
  V(Arm64F32x4Qfma)                     \
  V(Arm64F32x4Qfms)                     \
  V(Arm64F32x4Pmin)                     \
  V(Arm64F32x4Pmax)                     \
  V(Arm64F32x4DemoteF64x2Zero)          \
  V(Arm64F16x8Pmin)                     \
  V(Arm64F16x8Pmax)                     \
  V(Arm64F32x4PromoteLowF16x8)          \
  V(Arm64F16x8SConvertI16x8)            \
  V(Arm64F16x8UConvertI16x8)            \
  V(Arm64F16x8DemoteF32x4Zero)          \
  V(Arm64F16x8DemoteF64x2Zero)          \
  V(Arm64I16x8SConvertF16x8)            \
  V(Arm64I16x8UConvertF16x8)            \
  V(Arm64F16x8Qfma)                     \
  V(Arm64F16x8Qfms)                     \
  V(Arm64I64x2ShrU)                     \
  V(Arm64I64x2BitMask)                  \
  V(Arm64I32x4SConvertF32x4)            \
  V(Arm64I32x4Shl)                      \
  V(Arm64I32x4ShrS)                     \
  V(Arm64I32x4Mul)                      \
  V(Arm64I16x8Q15MulRSatS)              \
  V(Arm64I16x8BitMask)                  \
  V(Arm64I8x16Shl)                      \
  V(Arm64I8x16ShrS)                     \
  V(Arm64I8x16SConvertI16x8)            \
  V(Arm64I8x16ShrU)                     \
  V(Arm64I8x16UConvertI16x8)            \
  V(Arm64I8x16BitMask)                  \
  V(Arm64S128Const)                     \
  V(Arm64S128Dup)                       \
  V(Arm64S128And)                       \
  V(Arm64S128Or)                        \
  V(Arm64S128Xor)                       \
  V(Arm64S128Not)                       \
  V(Arm64S128Select)                    \
  V(Arm64S128AndNot)                    \
  V(Arm64Ssra)                          \
  V(Arm64Usra)                          \
  V(Arm64S32x4ZipLeft)                  \
  V(Arm64S32x4ZipRight)                 \
  V(Arm64S32x4UnzipLeft)                \
  V(Arm64S32x4UnzipRight)               \
  V(Arm64S32x4TransposeLeft)            \
  V(Arm64S32x4TransposeRight)           \
  V(Arm64S32x4Shuffle)                  \
  V(Arm64S16x8ZipLeft)                  \
  V(Arm64S16x8ZipRight)                 \
  V(Arm64S16x8UnzipLeft)                \
  V(Arm64S16x8UnzipRight)               \
  V(Arm64S16x8TransposeLeft)            \
  V(Arm64S16x8TransposeRight)           \
  V(Arm64S8x16ZipLeft)                  \
  V(Arm64S8x16ZipRight)                 \
  V(Arm64S8x16UnzipLeft)                \
  V(Arm64S8x16UnzipRight)               \
  V(Arm64S8x16TransposeLeft)            \
  V(Arm64S8x16TransposeRight)           \
  V(Arm64S8x16Concat)                   \
  V(Arm64I8x16Swizzle)                  \
  V(Arm64I8x16Shuffle)                  \
  V(Arm64S32x4Reverse)                  \
  V(Arm64S32x4OneLaneSwizzle)           \
  V(Arm64S32x2Reverse)                  \
  V(Arm64S16x4Reverse)                  \
  V(Arm64S16x2Reverse)                  \
  V(Arm64S8x8Reverse)                   \
  V(Arm64S8x4Reverse)                   \
  V(Arm64S8x2Reverse)                   \
  V(Arm64V128AnyTrue)                   \
  V(Arm64I64x2AllTrue)                  \
  V(Arm64I32x4AllTrue)                  \
  V(Arm64I16x8AllTrue)                  \
  V(Arm64I8x16AllTrue)                  \
  V(Arm64Sxtl)                          \
  V(Arm64Sxtl2)                         \
  V(Arm64Uxtl)                          \
  V(Arm64Uxtl2)                         \
  V(Arm64FSplat)                        \
  V(Arm64FAbs)                          \
  V(Arm64FSqrt)                         \
  V(Arm64FNeg)                          \
  V(Arm64FExtractLane)                  \
  V(Arm64FReplaceLane)                  \
  V(Arm64ISplat)                        \
  V(Arm64IAbs)                          \
  V(Arm64INeg)                          \
  V(Arm64IExtractLane)                  \
  V(Arm64IReplaceLane)                  \
  V(Arm64I64x2Shl)                      \
  V(Arm64I64x2ShrS)                     \
  V(Arm64I64x2Mul)                      \
  V(Arm64I32x4UConvertF32x4)            \
  V(Arm64I32x4ShrU)                     \
  V(Arm64I32x4BitMask)                  \
  V(Arm64I32x4DotI16x8S)                \
  V(Arm64I16x8DotI8x16S)                \
  V(Arm64I32x4DotI8x16AddS)             \
  V(Arm64I8x16Addv)                     \
  V(Arm64I16x8Addv)                     \
  V(Arm64I32x4Addv)                     \
  V(Arm64I64x2AddPair)                  \
  V(Arm64F32x4AddReducePairwise)        \
  V(Arm64F64x2AddPair)                  \
  V(Arm64I32x4TruncSatF64x2SZero)       \
  V(Arm64I32x4TruncSatF64x2UZero)       \
  V(Arm64IExtractLaneU)                 \
  V(Arm64IExtractLaneS)                 \
  V(Arm64I16x8Shl)                      \
  V(Arm64I16x8ShrS)                     \
  V(Arm64I16x8SConvertI32x4)            \
  V(Arm64I16x8Mul)                      \
  V(Arm64I16x8ShrU)                     \
  V(Arm64I16x8UConvertI32x4)            \
  V(Arm64Mla)                           \
  V(Arm64Mls)                           \
  V(Arm64FAdd)                          \
  V(Arm64FSub)                          \
  V(Arm64FMul)                          \
  V(Arm64FMulElement)                   \
  V(Arm64FDiv)                          \
  V(Arm64FMin)                          \
  V(Arm64FMax)                          \
  V(Arm64FEq)                           \
  V(Arm64FNe)                           \
  V(Arm64FLt)                           \
  V(Arm64FLe)                           \
  V(Arm64FGt)                           \
  V(Arm64FGe)                           \
  V(Arm64IAdd)                          \
  V(Arm64ISub)                          \
  V(Arm64IEq)                           \
  V(Arm64INe)                           \
  V(Arm64IGtS)                          \
  V(Arm64IGeS)                          \
  V(Arm64ILtS)                          \
  V(Arm64ILeS)                          \
  V(Arm64IMinS)                         \
  V(Arm64IMaxS)                         \
  V(Arm64IMinU)                         \
  V(Arm64IMaxU)                         \
  V(Arm64IGtU)                          \
  V(Arm64IGeU)                          \
  V(Arm64IAddSatS)                      \
  V(Arm64ISubSatS)                      \
  V(Arm64IAddSatU)                      \
  V(Arm64ISubSatU)                      \
  V(Arm64RoundingAverageU)              \
  V(Arm64Smlal)                         \
  V(Arm64Smlal2)                        \
  V(Arm64Sadalp)                        \
  V(Arm64Saddlp)                        \
  V(Arm64Uadalp)                        \
  V(Arm64Uaddlp)                        \
  V(Arm64Umlal)                         \
  V(Arm64Umlal2)

#define TARGET_ARCH_OPCODE_LIST(V)                   \
  TARGET_ARCH_OPCODE_WITH_MEMORY_ACCESS_MODE_LIST(V) \
  V(Arm64Add)                                        \
  V(Arm64Add32)                                      \
  V(Arm64And)                                        \
  V(Arm64And32)                                      \
  V(Arm64Bic)                                        \
  V(Arm64Bic32)                                      \
  V(Arm64Clz)                                        \
  V(Arm64Clz32)                                      \
  V(Arm64Cmp)                                        \
  V(Arm64Cmp32)                                      \
  V(Arm64Cmn)                                        \
  V(Arm64Cmn32)                                      \
  V(Arm64Cnt)                                        \
  V(Arm64Cnt32)                                      \
  V(Arm64Cnt64)                                      \
  V(Arm64Tst)                                        \
  V(Arm64Tst32)                                      \
  V(Arm64Or)                                         \
  V(Arm64Or32)                                       \
  V(Arm64Orn)                                        \
  V(Arm64Orn32)                                      \
  V(Arm64Eor)                                        \
  V(Arm64Eor32)                                      \
  V(Arm64Eon)                                        \
  V(Arm64Eon32)                                      \
  V(Arm64Sub)                                        \
  V(Arm64Sub32)                                      \
  V(Arm64Mul)                                        \
  V(Arm64Mul32)                                      \
  V(Arm64Smulh)                                      \
  V(Arm64Smull)                                      \
  V(Arm64Smull2)                                     \
  V(Arm64Umull)                                      \
  V(Arm64Umulh)                                      \
  V(Arm64Umull2)                                     \
  V(Arm64Madd)                                       \
  V(Arm64Madd32)                                     \
  V(Arm64Msub)                                       \
  V(Arm64Msub32)                                     \
  V(Arm64Mneg)                                       \
  V(Arm64Mneg32)                                     \
  V(Arm64Idiv)                                       \
  V(Arm64Idiv32)                                     \
  V(Arm64Udiv)                                       \
  V(Arm64Udiv32)                                     \
  V(Arm64Imod)                                       \
  V(Arm64Imod32)                                     \
  V(Arm64Umod)                                       \
  V(Arm64Umod32)                                     \
  V(Arm64Not)                                        \
  V(Arm64Not32)                                      \
  V(Arm64Lsl)                                        \
  V(Arm64Lsl32)                                      \
  V(Arm64Lsr)                                        \
  V(Arm64Lsr32)                                      \
  V(Arm64Asr)                                        \
  V(Arm64Asr32)                                      \
  V(Arm64Ror)                                        \
  V(Arm64Ror32)                                      \
  V(Arm64Mov32)                                      \
  V(Arm64Sxtb32)                                     \
  V(Arm64Sxth32)                                     \
  V(Arm64Sxtb)                                       \
  V(Arm64Sxth)                                       \
  V(Arm64Sxtw)                                       \
  V(Arm64Sbfx)                                       \
  V(Arm64Sbfx32)                                     \
  V(Arm64Ubfx)                                       \
  V(Arm64Ubfx32)                                     \
  V(Arm64Ubfiz32)                                    \
  V(Arm64Sbfiz)                                      \
  V(Arm64Bfi)                                        \
  V(Arm64Rbit)                                       \
  V(Arm64Rbit32)                                     \
  V(Arm64Rev)                                        \
  V(Arm64Rev32)                                      \
  V(Arm64TestAndBranch32)                            \
  V(Arm64TestAndBranch)                              \
  V(Arm64CompareAndBranch32)                         \
  V(Arm64CompareAndBranch)                           \
  V(Arm64Claim)                                      \
  V(Arm64Poke)                                       \
  V(Arm64PokePair)                                   \
  V(Arm64Peek)                                       \
  V(Arm64Float16RoundDown)                           \
  V(Arm64Float16RoundUp)                             \
  V(Arm64Float16RoundTruncate)                       \
  V(Arm64Float16RoundTiesEven)                       \
  V(Arm64Float32Cmp)                                 \
  V(Arm64Float32Add)                                 \
  V(Arm64Float32Sub)                                 \
  V(Arm64Float32Mul)                                 \
  V(Arm64Float32Div)                                 \
  V(Arm64Float32Abs)                                 \
  V(Arm64Float32Abd)                                 \
  V(Arm64Float32Neg)                                 \
  V(Arm64Float32Sqrt)                                \
  V(Arm64Float32Fnmul)                               \
  V(Arm64Float32RoundDown)                           \
  V(Arm64Float32Max)                                 \
  V(Arm64Float32Min)                                 \
  V(Arm64Float64Cmp)                                 \
  V(Arm64Float64Add)                                 \
  V(Arm64Float64Sub)                                 \
  V(Arm64Float64Mul)                                 \
  V(Arm64Float64Div)                                 \
  V(Arm64Float64Mod)                                 \
  V(Arm64Float64Max)                                 \
  V(Arm64Float64Min)                                 \
  V(Arm64Float64Abs)                                 \
  V(Arm64Float64Abd)                                 \
  V(Arm64Float64Neg)                                 \
  V(Arm64Float64Sqrt)                                \
  V(Arm64Float64Fnmul)                               \
  V(Arm64Float64RoundDown)                           \
  V(Arm64Float32RoundUp)                             \
  V(Arm64Float64RoundUp)                             \
  V(Arm64Float64RoundTiesAway)                       \
  V(Arm64Float32RoundTruncate)                       \
  V(Arm64Float64RoundTruncate)                       \
  V(Arm64Float32RoundTiesEven)                       \
  V(Arm64Float64RoundTiesEven)                       \
  V(Arm64Float64SilenceNaN)                          \
  V(Arm64Float32ToFloat64)                           \
  V(Arm64Float64ToFloat32)                           \
  V(Arm64Float64ToFloat16RawBits)                    \
  V(Arm64Float32ToInt32)                             \
  V(Arm64Float64ToInt32)                             \
  V(Arm64Float32ToUint32)                            \
  V(Arm64Float64ToUint32)                            \
  V(Arm64Float32ToInt64)                             \
  V(Arm64Float64ToInt64)                             \
  V(Arm64Float32ToUint64)                            \
  V(Arm64Float64ToUint64)                            \
  V(Arm64Int32ToFloat32)                             \
  V(Arm64Int32ToFloat64)                             \
  V(Arm64Int64ToFloat32)                             \
  V(Arm64Int64ToFloat64)                             \
  V(Arm64Uint32ToFloat32)                            \
  V(Arm64Uint32ToFloat64)                            \
  V(Arm64Uint64ToFloat32)                            \
  V(Arm64Uint64ToFloat64)                            \
  V(Arm64Float64ExtractLowWord32)                    \
  V(Arm64Float64ExtractHighWord32)                   \
  V(Arm64Float64InsertLowWord32)                     \
  V(Arm64Float64InsertHighWord32)                    \
  V(Arm64Float64MoveU64)                             \
  V(Arm64U64MoveFloat64)                             \
  V(Arm64LdarDecompressTaggedSigned)                 \
  V(Arm64LdarDecompressTagged)                       \
  V(Arm64StlrCompressTagged)                         \
  V(Arm64StrIndirectPointer)                         \
  V(Arm64LdrDecodeSandboxedPointer)                  \
  V(Arm64StrEncodeSandboxedPointer)                  \
  V(Arm64DmbIsh)                                     \
  V(Arm64DsbIsb)                                     \
  V(Arm64Word64AtomicAddUint64)                      \
  V(Arm64Word64AtomicSubUint64)                      \
  V(Arm64Word64AtomicAndUint64)                      \
  V(Arm64Word64AtomicOrUint64)                       \
  V(Arm64Word64AtomicXorUint64)                      \
  V(Arm64Word64AtomicExchangeUint64)                 \
  V(Arm64Word64AtomicCompareExchangeUint64)          \
  IF_WASM(TARGET_ARCH_SIMD_OPCODE_LIST, V)

// Addressing modes represent the "shape" of inputs to an instruction.
// Many instructions support multiple addressing modes. Addressing modes
// are encoded into the InstructionCode of the instruction and tell the
// code generator after register allocation which assembler method to call.
//
// We use the following local notation for addressing modes:
//
// R = register
// O = register or stack slot
// D = double register
// I = immediate (handle, external, int32)
// MRI = [register + immediate]
// MRR = [register + register]
#define TARGET_ADDRESSING_MODE_LIST(V)                          \
  V(MRI)              /* [%r0 + K] */                           \
  V(MRR)              /* [%r0 + %r1] */                         \
  V(Operand2_R_LSL_I) /* %r0 LSL K */                           \
  V(Operand2_R_LSR_I) /* %r0 LSR K */                           \
  V(Operand2_R_ASR_I) /* %r0 ASR K */                           \
  V(Operand2_R_ROR_I) /* %r0 ROR K */                           \
  V(Operand2_R_UXTB)  /* %r0 UXTB (unsigned extend byte) */     \
  V(Operand2_R_UXTH)  /* %r0 UXTH (unsigned extend halfword) */ \
  V(Operand2_R_SXTB)  /* %r0 SXTB (signed extend byte) */       \
  V(Operand2_R_SXTH)  /* %r0 SXTH (signed extend halfword) */   \
  V(Operand2_R_SXTW)  /* %r0 SXTW (signed extend word) */       \
  V(Root)             /* [%rr + K] */

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_BACKEND_ARM64_INSTRUCTION_CODES_ARM64_H_

"""

```