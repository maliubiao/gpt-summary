Response:
Let's break down the thought process for analyzing the provided C++ header file.

1. **Initial Scan and Purpose Identification:** The first step is to quickly read through the file to grasp its general purpose. The filename `instruction-codes-loong64.h` strongly suggests this file deals with instruction codes for the LoongArch 64-bit architecture within the V8 JavaScript engine. The comments at the beginning confirm this. The `#ifndef` guards indicate a header file designed to prevent multiple inclusions.

2. **Macro Analysis (`TARGET_ARCH_OPCODE_WITH_MEMORY_ACCESS_MODE_LIST` and `TARGET_ARCH_OPCODE_LIST`):**  The core of the file lies within these macros. The `V` parameter is a strong indicator of a macro used for code generation or listing.

   * **`TARGET_ARCH_OPCODE_WITH_MEMORY_ACCESS_MODE_LIST`:**  The name itself gives a big clue. The listed opcodes (like `Loong64Ld_b`, `Loong64St_d`, etc.) clearly represent LoongArch instructions that involve memory access. The suffixes like `_b`, `_h`, `_w`, `_d` likely denote byte, half-word, word, and double-word sizes. The "MemoryAccessMode" in the macro name suggests that the way memory is accessed might be a configurable aspect for these instructions.

   * **`TARGET_ARCH_OPCODE_LIST`:** This macro includes the previous one and adds a much larger set of opcodes. These opcodes cover a wider range of arithmetic (`Add`, `Sub`, `Mul`, `Div`), logical (`And`, `Or`, `Xor`), bit manipulation (`Alsl`, `Sll`, `Rotr`), comparisons (`Cmp32`, `Cmp64`), floating-point operations (`Float32Add`, `Float64Sqrt`), SIMD/vector instructions (starting with `Loong64S128` and `Loong64I32x4`), and other utility instructions (`Mov`, `Push`, `StackClaim`). The naming convention `Loong64` followed by an operation name is consistent.

3. **Addressing Mode Analysis (`TARGET_ADDRESSING_MODE_LIST`):** This macro defines different ways the operands of an instruction can be specified.

   * `MRI`:  `[register + immediate]` - This means an operand's address is calculated by adding an immediate value to the contents of a register.
   * `MRR`:  `[register + register]` -  The operand's address is calculated by adding the contents of two registers.
   * `Root`: `[%rr + K]` - This likely refers to accessing data relative to a "root" register (`%rr`), which is a common technique in virtual machines and runtime environments for accessing global or heap-related data.

4. **Functionality Summary (Based on Opcode Analysis):**  Now, synthesize the information gathered from the macros. The file provides a comprehensive list of LoongArch 64-bit instructions that the V8 compiler can generate. Key functional areas include:

   * **Memory Access:** Loading and storing various data sizes (bytes, words, double-words), including tagged values (important for JavaScript's dynamic typing).
   * **Integer Arithmetic and Logic:** Standard arithmetic and logical operations on 32-bit and 64-bit integers.
   * **Floating-Point Arithmetic:** Operations on single-precision (float32) and double-precision (float64) floating-point numbers.
   * **Vector/SIMD Operations:**  Instructions for processing multiple data elements simultaneously, indicated by prefixes like `S128`, `I32x4`, `F64x2`, etc. These are essential for performance in JavaScript operations involving arrays and typed arrays.
   * **Bit Manipulation:** Operations like shifts, rotates, bit field extraction/insertion.
   * **Comparisons:** Instructions for comparing integer and floating-point values.
   * **Conversions:**  Instructions for converting between different data types (e.g., integer to float, float32 to float64).
   * **Stack Operations:** `Push`, `Peek`, `Poke`, `StackClaim` for managing the call stack.
   * **Sandboxed Pointers:** `LoadDecodeSandboxedPointer`, `StoreEncodeSandboxedPointer`, `StoreIndirectPointer` - these suggest mechanisms for memory safety and security, potentially related to isolating code within the V8 engine.
   * **Atomic Operations:** Instructions starting with `Loong64Word64Atomic` for performing atomic operations on memory, crucial for concurrent programming.

5. **Torque Source Check:**  The file ends with `.h`, not `.tq`, so it's a standard C++ header file, not a Torque file.

6. **Relationship to JavaScript:**  The opcodes defined in this file are the low-level building blocks for executing JavaScript code on LoongArch64. The V8 compiler translates JavaScript code into these machine instructions. Illustrative examples involving arithmetic, comparisons, and data access can be easily created in JavaScript to demonstrate the connection.

7. **Code Logic Inference (Hypothetical Input/Output):** While the header file itself doesn't contain executable logic, we can infer the behavior of individual instructions. For instance, `Loong64Add_d` takes two 64-bit inputs and produces their sum as a 64-bit output. `Loong64Ld_w` takes a memory address and loads a 32-bit word from that location.

8. **Common Programming Errors:**  Thinking about how these low-level instructions are used helps identify potential programming errors in JavaScript that might manifest as issues at this level. Examples include:

   * **Incorrect data types:**  Trying to perform an operation on incompatible types (e.g., adding a number to a string without proper conversion).
   * **Memory access violations:**  Accessing memory outside of allocated bounds, which could lead to crashes or security vulnerabilities. The sandboxed pointer instructions hint at V8's efforts to prevent this.
   * **Integer overflow/underflow:**  Performing arithmetic operations that exceed the limits of the integer data type. The `Ovf` suffixes on some opcodes suggest the hardware can detect these conditions.
   * **NaN (Not-a-Number) issues:**  Incorrect floating-point operations leading to NaN values, which can propagate through calculations.

By following these steps, we can systematically analyze the C++ header file and understand its role within the V8 JavaScript engine. The key is to break down the file into its constituent parts (macros, opcodes, addressing modes) and then interpret their meaning in the context of a compiler backend for a specific architecture.
This header file, `v8/src/compiler/backend/loong64/instruction-codes-loong64.h`, defines **LOONG64-specific instruction codes** used by the V8 JavaScript engine's backend compiler.

Here's a breakdown of its functionality:

**1. Defining Architecture-Specific Opcodes:**

* The core purpose is to enumerate all the specific machine instructions that the V8 compiler can emit when generating code for the LOONG64 (LoongArch 64-bit) architecture.
* These opcodes are represented as symbolic names (e.g., `Loong64Add_d`, `Loong64Ld_w`).
* These symbolic names act as identifiers within the V8 compiler's internal representation of code. The compiler uses these opcodes to decide which actual assembly instructions to generate during the code emission phase.

**2. Categorization of Opcodes:**

* The file uses C++ preprocessor macros (`#define`) to create lists of opcodes.
* `TARGET_ARCH_OPCODE_WITH_MEMORY_ACCESS_MODE_LIST(V)`: This macro lists opcodes that involve memory access and can have different memory access modes (e.g., loading a byte, a word, a double-word). The `V` likely represents a macro that will be applied to each opcode in the list.
* `TARGET_ARCH_OPCODE_LIST(V)`: This macro includes all opcodes, including those with memory access modes and other general-purpose instructions.

**3. Types of Instructions:**

Based on the listed opcodes, we can infer the types of operations supported by the LOONG64 architecture that V8 utilizes:

* **Load and Store:** `Loong64Ld_b`, `Loong64St_d`, etc. -  Loading data from memory into registers and storing data from registers to memory. Different suffixes indicate the size of the data (byte, half-word, word, double-word).
* **Arithmetic Operations:** `Loong64Add_d`, `Loong64Sub_w`, `Loong64Mul_d`, `Loong64Div_w`, etc. -  Addition, subtraction, multiplication, division on both 32-bit and 64-bit integers and floating-point numbers.
* **Logical Operations:** `Loong64And`, `Loong64Or`, `Loong64Xor`, `Loong64Nor` - Bitwise logical operations.
* **Shift and Rotate Operations:** `Loong64Alsl_d`, `Loong64Sll_w`, `Loong64Rotr_d` -  Bit shifting and rotation.
* **Bit Manipulation:** `Loong64Bstrpick_d`, `Loong64Bstrins_w`, `Loong64ByteSwap64` - Operations for extracting, inserting, and swapping bits.
* **Comparison Operations:** `Loong64Tst`, `Loong64Cmp32`, `Loong64Cmp64`, `Loong64Float32Cmp`, `Loong64Float64Cmp` - Comparing values.
* **Floating-Point Operations:** `Loong64Float32Add`, `Loong64Float64Sqrt`, `Loong64Float64ToFloat32` - Arithmetic, transcendental (like square root), and conversion operations for single-precision (float32) and double-precision (float64) floating-point numbers.
* **Vector (SIMD) Operations:**  Instructions starting with `Loong64S128`, `Loong64I32x4`, `Loong64F64x2` - Operations that perform the same action on multiple data elements simultaneously (Single Instruction, Multiple Data). This is crucial for optimizing performance-sensitive JavaScript code.
* **Stack Operations:** `Loong64Push`, `Loong64Peek`, `Loong64Poke`, `Loong64StackClaim` - Instructions for managing the call stack.
* **Atomic Operations:** `Loong64Word64AtomicLoadUint32`, `Loong64Word64AtomicAddUint64` - Operations that ensure exclusive access to memory locations, important for concurrent programming.
* **Tagged Value Handling:** `Loong64LoadDecompressTaggedSigned`, `Loong64StoreCompressTagged` -  Operations related to V8's internal representation of JavaScript values (which are often "tagged" with type information).
* **Sandboxed Pointer Handling:** `Loong64LoadDecodeSandboxedPointer`, `Loong64StoreEncodeSandboxedPointer` -  Likely related to memory safety and security mechanisms within V8.

**4. Addressing Modes:**

* `TARGET_ADDRESSING_MODE_LIST(V)` defines different ways operands can be specified for instructions.
    * `MRI`: Memory access with a register and an immediate offset (`[register + immediate]`).
    * `MRR`: Memory access with two registers (`[register + register]`).
    * `Root`: Memory access relative to a root register (`[%rr + K]`). This is often used to access global or heap-allocated data.

**Is `v8/src/compiler/backend/loong64/instruction-codes-loong64.h` a Torque source file?**

No, the file extension is `.h`, which signifies a C++ header file. Torque source files typically have a `.tq` extension.

**Relationship to JavaScript and Examples:**

This file directly relates to how JavaScript code is executed on LOONG64 processors. The V8 compiler translates JavaScript code into a sequence of these low-level machine instructions.

Here are some JavaScript examples and how they might relate to the defined opcodes:

**Example 1: Basic Arithmetic**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

* The `+` operation in JavaScript would likely be translated into a `Loong64Add_w` (for 32-bit integers) or `Loong64Add_d` (for 64-bit integers or floating-point numbers) instruction at the machine code level.

**Example 2: Array Access**

```javascript
let arr = [1, 2, 3];
let firstElement = arr[0];
```

* Accessing `arr[0]` would involve calculating the memory address of the first element. This could involve a `Loong64Mov` to get the base address of the array and then an access using an addressing mode like `MRI` (Memory Register Immediate) with an offset of 0, potentially using a `Loong64Ld_w` to load the 32-bit integer value.

**Example 3: Floating-Point Calculation**

```javascript
let x = 2.5;
let y = Math.sqrt(x);
```

* `Math.sqrt(x)` would likely be translated into a `Loong64Float64Sqrt` instruction to compute the square root of the double-precision floating-point number.

**Code Logic Inference (Hypothetical Input and Output):**

Let's consider a simple instruction: `Loong64Add_d`.

* **Hypothetical Input:**
    * Register `R1` contains the 64-bit integer value `10`.
    * Register `R2` contains the 64-bit integer value `20`.
* **Operation:** The `Loong64Add_d R1, R2, R3` instruction (hypothetical assembly syntax) would add the contents of `R1` and `R2`.
* **Hypothetical Output:**
    * Register `R3` would contain the 64-bit integer value `30`.

For a memory access instruction like `Loong64Ld_w`:

* **Hypothetical Input:**
    * Register `R1` contains the memory address `0x1000`.
    * The memory location at `0x1000` contains the 32-bit integer value `12345`.
* **Operation:** The `Loong64Ld_w R1, R2` instruction (hypothetical assembly syntax) would load the 32-bit word from the memory address in `R1`.
* **Hypothetical Output:**
    * Register `R2` would contain the 32-bit integer value `12345`.

**User-Common Programming Errors:**

While this header file itself doesn't directly cause user programming errors, it represents the underlying instructions that are generated when executing JavaScript code. Common errors in JavaScript can lead to unexpected behavior at this low level:

**Example 1: Type Mismatch**

```javascript
let a = 5;
let b = "10";
let sum = a + b; // JavaScript will perform string concatenation
```

*  Although JavaScript attempts to be forgiving with types, the underlying instructions might involve implicit conversions. If the engine expects an integer addition (`Loong64Add_w`) but one of the operands is a string, it might have to perform extra operations for conversion, which could introduce overhead or unexpected results. In more strictly typed languages, this would be a compilation error.

**Example 2: Out-of-Bounds Array Access**

```javascript
let arr = [1, 2, 3];
let value = arr[5]; // Accessing an element beyond the array's bounds
```

* This will result in `undefined` in JavaScript. At the lower level, the generated `Loong64Ld_w` instruction with an invalid memory address could lead to a segmentation fault or other memory access errors in other languages. V8 has mechanisms to handle these situations gracefully within the JavaScript environment.

**Example 3: Integer Overflow**

```javascript
let maxInt = 2147483647; // Maximum 32-bit signed integer
let result = maxInt + 1;
```

* In JavaScript, numbers are typically represented as 64-bit floating-point values, so integer overflow in the traditional sense is less common. However, if the underlying code uses 32-bit integer operations (`Loong64Add_w`) for optimization, adding 1 to the maximum 32-bit integer might wrap around, leading to an unexpected negative result if not handled correctly.

**In summary,** `instruction-codes-loong64.h` is a crucial file that defines the vocabulary of machine instructions that the V8 compiler uses to translate JavaScript code into executable form on LOONG64 processors. Understanding these opcodes provides insight into the low-level operations that underpin JavaScript execution.

### 提示词
```
这是目录为v8/src/compiler/backend/loong64/instruction-codes-loong64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/loong64/instruction-codes-loong64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_BACKEND_LOONG64_INSTRUCTION_CODES_LOONG64_H_
#define V8_COMPILER_BACKEND_LOONG64_INSTRUCTION_CODES_LOONG64_H_

namespace v8 {
namespace internal {
namespace compiler {

// LOONG64-specific opcodes that specify which assembly sequence to emit.
// Most opcodes specify a single instruction.

// Opcodes that support a MemoryAccessMode.
#define TARGET_ARCH_OPCODE_WITH_MEMORY_ACCESS_MODE_LIST(V) \
  V(Loong64Ld_b)                                           \
  V(Loong64Ld_bu)                                          \
  V(Loong64St_b)                                           \
  V(Loong64Ld_h)                                           \
  V(Loong64Ld_hu)                                          \
  V(Loong64St_h)                                           \
  V(Loong64Ld_w)                                           \
  V(Loong64Ld_wu)                                          \
  V(Loong64St_w)                                           \
  V(Loong64Ld_d)                                           \
  V(Loong64St_d)                                           \
  V(Loong64LoadDecompressTaggedSigned)                     \
  V(Loong64LoadDecompressTagged)                           \
  V(Loong64LoadDecompressProtected)                        \
  V(Loong64StoreCompressTagged)                            \
  V(Loong64Fld_s)                                          \
  V(Loong64Fst_s)                                          \
  V(Loong64Fld_d)                                          \
  V(Loong64Fst_d)                                          \
  V(Loong64LoadLane)                                       \
  V(Loong64StoreLane)                                      \
  V(Loong64S128LoadSplat)                                  \
  V(Loong64S128Load8x8S)                                   \
  V(Loong64S128Load8x8U)                                   \
  V(Loong64S128Load16x4S)                                  \
  V(Loong64S128Load16x4U)                                  \
  V(Loong64S128Load32x2S)                                  \
  V(Loong64S128Load32x2U)                                  \
  V(Loong64Word64AtomicLoadUint32)                         \
  V(Loong64Word64AtomicLoadUint64)                         \
  V(Loong64Word64AtomicStoreWord64)

#define TARGET_ARCH_OPCODE_LIST(V)                   \
  TARGET_ARCH_OPCODE_WITH_MEMORY_ACCESS_MODE_LIST(V) \
  V(Loong64Add_d)                                    \
  V(Loong64Add_w)                                    \
  V(Loong64AddOvf_d)                                 \
  V(Loong64Sub_d)                                    \
  V(Loong64Sub_w)                                    \
  V(Loong64SubOvf_d)                                 \
  V(Loong64Mul_d)                                    \
  V(Loong64MulOvf_w)                                 \
  V(Loong64MulOvf_d)                                 \
  V(Loong64Mulh_d)                                   \
  V(Loong64Mulh_w)                                   \
  V(Loong64Mulh_du)                                  \
  V(Loong64Mulh_wu)                                  \
  V(Loong64Mul_w)                                    \
  V(Loong64Div_d)                                    \
  V(Loong64Div_w)                                    \
  V(Loong64Div_du)                                   \
  V(Loong64Div_wu)                                   \
  V(Loong64Mod_d)                                    \
  V(Loong64Mod_w)                                    \
  V(Loong64Mod_du)                                   \
  V(Loong64Mod_wu)                                   \
  V(Loong64And)                                      \
  V(Loong64And32)                                    \
  V(Loong64Or)                                       \
  V(Loong64Or32)                                     \
  V(Loong64Nor)                                      \
  V(Loong64Nor32)                                    \
  V(Loong64Xor)                                      \
  V(Loong64Xor32)                                    \
  V(Loong64Alsl_d)                                   \
  V(Loong64Alsl_w)                                   \
  V(Loong64Sll_d)                                    \
  V(Loong64Sll_w)                                    \
  V(Loong64Srl_d)                                    \
  V(Loong64Srl_w)                                    \
  V(Loong64Sra_d)                                    \
  V(Loong64Sra_w)                                    \
  V(Loong64Rotr_d)                                   \
  V(Loong64Rotr_w)                                   \
  V(Loong64Bstrpick_d)                               \
  V(Loong64Bstrpick_w)                               \
  V(Loong64Bstrins_d)                                \
  V(Loong64Bstrins_w)                                \
  V(Loong64ByteSwap64)                               \
  V(Loong64ByteSwap32)                               \
  V(Loong64Clz_d)                                    \
  V(Loong64Clz_w)                                    \
  V(Loong64Mov)                                      \
  V(Loong64Tst)                                      \
  V(Loong64Cmp32)                                    \
  V(Loong64Cmp64)                                    \
  V(Loong64Float32Cmp)                               \
  V(Loong64Float32Add)                               \
  V(Loong64Float32Sub)                               \
  V(Loong64Float32Mul)                               \
  V(Loong64Float32Div)                               \
  V(Loong64Float32Abs)                               \
  V(Loong64Float32Neg)                               \
  V(Loong64Float32Sqrt)                              \
  V(Loong64Float32Max)                               \
  V(Loong64Float32Min)                               \
  V(Loong64Float32ToFloat64)                         \
  V(Loong64Float32RoundDown)                         \
  V(Loong64Float32RoundUp)                           \
  V(Loong64Float32RoundTruncate)                     \
  V(Loong64Float32RoundTiesEven)                     \
  V(Loong64Float32ToInt32)                           \
  V(Loong64Float32ToInt64)                           \
  V(Loong64Float32ToUint32)                          \
  V(Loong64Float32ToUint64)                          \
  V(Loong64Float64Cmp)                               \
  V(Loong64Float64Add)                               \
  V(Loong64Float64Sub)                               \
  V(Loong64Float64Mul)                               \
  V(Loong64Float64Div)                               \
  V(Loong64Float64Mod)                               \
  V(Loong64Float64Abs)                               \
  V(Loong64Float64Neg)                               \
  V(Loong64Float64Sqrt)                              \
  V(Loong64Float64Max)                               \
  V(Loong64Float64Min)                               \
  V(Loong64Float64ToFloat32)                         \
  V(Loong64Float64RoundDown)                         \
  V(Loong64Float64RoundUp)                           \
  V(Loong64Float64RoundTruncate)                     \
  V(Loong64Float64RoundTiesEven)                     \
  V(Loong64Float64ToInt32)                           \
  V(Loong64Float64ToInt64)                           \
  V(Loong64Float64ToUint32)                          \
  V(Loong64Float64ToUint64)                          \
  V(Loong64Int32ToFloat32)                           \
  V(Loong64Int32ToFloat64)                           \
  V(Loong64Int64ToFloat32)                           \
  V(Loong64Int64ToFloat64)                           \
  V(Loong64Uint32ToFloat32)                          \
  V(Loong64Uint32ToFloat64)                          \
  V(Loong64Uint64ToFloat32)                          \
  V(Loong64Uint64ToFloat64)                          \
  V(Loong64Float64ExtractLowWord32)                  \
  V(Loong64Float64ExtractHighWord32)                 \
  V(Loong64Float64FromWord32Pair)                    \
  V(Loong64Float64InsertLowWord32)                   \
  V(Loong64Float64InsertHighWord32)                  \
  V(Loong64BitcastDL)                                \
  V(Loong64BitcastLD)                                \
  V(Loong64Float64SilenceNaN)                        \
  V(Loong64LoadDecodeSandboxedPointer)               \
  V(Loong64StoreEncodeSandboxedPointer)              \
  V(Loong64StoreIndirectPointer)                     \
  V(Loong64Push)                                     \
  V(Loong64Peek)                                     \
  V(Loong64Poke)                                     \
  V(Loong64StackClaim)                               \
  V(Loong64Ext_w_b)                                  \
  V(Loong64Ext_w_h)                                  \
  V(Loong64Dbar)                                     \
  V(Loong64S128Const)                                \
  V(Loong64S128Zero)                                 \
  V(Loong64S128AllOnes)                              \
  V(Loong64I32x4Splat)                               \
  V(Loong64I32x4ExtractLane)                         \
  V(Loong64I32x4ReplaceLane)                         \
  V(Loong64I32x4Add)                                 \
  V(Loong64I32x4Sub)                                 \
  V(Loong64F64x2Abs)                                 \
  V(Loong64F64x2Neg)                                 \
  V(Loong64F32x4Splat)                               \
  V(Loong64F32x4ExtractLane)                         \
  V(Loong64F32x4ReplaceLane)                         \
  V(Loong64F32x4SConvertI32x4)                       \
  V(Loong64F32x4UConvertI32x4)                       \
  V(Loong64I32x4Mul)                                 \
  V(Loong64I32x4MaxS)                                \
  V(Loong64I32x4MinS)                                \
  V(Loong64I32x4Eq)                                  \
  V(Loong64I32x4Ne)                                  \
  V(Loong64I32x4Shl)                                 \
  V(Loong64I32x4ShrS)                                \
  V(Loong64I32x4ShrU)                                \
  V(Loong64I32x4MaxU)                                \
  V(Loong64I32x4MinU)                                \
  V(Loong64F64x2Sqrt)                                \
  V(Loong64F64x2Add)                                 \
  V(Loong64F64x2Sub)                                 \
  V(Loong64F64x2Mul)                                 \
  V(Loong64F64x2Div)                                 \
  V(Loong64F64x2Min)                                 \
  V(Loong64F64x2Max)                                 \
  V(Loong64F64x2Eq)                                  \
  V(Loong64F64x2Ne)                                  \
  V(Loong64F64x2Lt)                                  \
  V(Loong64F64x2Le)                                  \
  V(Loong64F64x2Splat)                               \
  V(Loong64F64x2ExtractLane)                         \
  V(Loong64F64x2ReplaceLane)                         \
  V(Loong64F64x2Pmin)                                \
  V(Loong64F64x2Pmax)                                \
  V(Loong64F64x2Ceil)                                \
  V(Loong64F64x2Floor)                               \
  V(Loong64F64x2Trunc)                               \
  V(Loong64F64x2NearestInt)                          \
  V(Loong64F64x2ConvertLowI32x4S)                    \
  V(Loong64F64x2ConvertLowI32x4U)                    \
  V(Loong64F64x2PromoteLowF32x4)                     \
  V(Loong64F64x2RelaxedMin)                          \
  V(Loong64F64x2RelaxedMax)                          \
  V(Loong64I64x2Splat)                               \
  V(Loong64I64x2ExtractLane)                         \
  V(Loong64I64x2ReplaceLane)                         \
  V(Loong64I64x2Add)                                 \
  V(Loong64I64x2Sub)                                 \
  V(Loong64I64x2Mul)                                 \
  V(Loong64I64x2Neg)                                 \
  V(Loong64I64x2Shl)                                 \
  V(Loong64I64x2ShrS)                                \
  V(Loong64I64x2ShrU)                                \
  V(Loong64I64x2BitMask)                             \
  V(Loong64I64x2Eq)                                  \
  V(Loong64I64x2Ne)                                  \
  V(Loong64I64x2GtS)                                 \
  V(Loong64I64x2GeS)                                 \
  V(Loong64I64x2Abs)                                 \
  V(Loong64I64x2SConvertI32x4Low)                    \
  V(Loong64I64x2SConvertI32x4High)                   \
  V(Loong64I64x2UConvertI32x4Low)                    \
  V(Loong64I64x2UConvertI32x4High)                   \
  V(Loong64ExtMulLow)                                \
  V(Loong64ExtMulHigh)                               \
  V(Loong64ExtAddPairwise)                           \
  V(Loong64F32x4Abs)                                 \
  V(Loong64F32x4Neg)                                 \
  V(Loong64F32x4Sqrt)                                \
  V(Loong64F32x4Add)                                 \
  V(Loong64F32x4Sub)                                 \
  V(Loong64F32x4Mul)                                 \
  V(Loong64F32x4Div)                                 \
  V(Loong64F32x4Max)                                 \
  V(Loong64F32x4Min)                                 \
  V(Loong64F32x4Eq)                                  \
  V(Loong64F32x4Ne)                                  \
  V(Loong64F32x4Lt)                                  \
  V(Loong64F32x4Le)                                  \
  V(Loong64F32x4Pmin)                                \
  V(Loong64F32x4Pmax)                                \
  V(Loong64F32x4Ceil)                                \
  V(Loong64F32x4Floor)                               \
  V(Loong64F32x4Trunc)                               \
  V(Loong64F32x4NearestInt)                          \
  V(Loong64F32x4DemoteF64x2Zero)                     \
  V(Loong64F32x4RelaxedMin)                          \
  V(Loong64F32x4RelaxedMax)                          \
  V(Loong64I32x4SConvertF32x4)                       \
  V(Loong64I32x4UConvertF32x4)                       \
  V(Loong64I32x4Neg)                                 \
  V(Loong64I32x4GtS)                                 \
  V(Loong64I32x4GeS)                                 \
  V(Loong64I32x4GtU)                                 \
  V(Loong64I32x4GeU)                                 \
  V(Loong64I32x4Abs)                                 \
  V(Loong64I32x4BitMask)                             \
  V(Loong64I32x4DotI16x8S)                           \
  V(Loong64I32x4TruncSatF64x2SZero)                  \
  V(Loong64I32x4TruncSatF64x2UZero)                  \
  V(Loong64I32x4RelaxedTruncF32x4S)                  \
  V(Loong64I32x4RelaxedTruncF32x4U)                  \
  V(Loong64I32x4RelaxedTruncF64x2SZero)              \
  V(Loong64I32x4RelaxedTruncF64x2UZero)              \
  V(Loong64I16x8Splat)                               \
  V(Loong64I16x8ExtractLaneU)                        \
  V(Loong64I16x8ExtractLaneS)                        \
  V(Loong64I16x8ReplaceLane)                         \
  V(Loong64I16x8Neg)                                 \
  V(Loong64I16x8Shl)                                 \
  V(Loong64I16x8ShrS)                                \
  V(Loong64I16x8ShrU)                                \
  V(Loong64I16x8Add)                                 \
  V(Loong64I16x8AddSatS)                             \
  V(Loong64I16x8Sub)                                 \
  V(Loong64I16x8SubSatS)                             \
  V(Loong64I16x8Mul)                                 \
  V(Loong64I16x8MaxS)                                \
  V(Loong64I16x8MinS)                                \
  V(Loong64I16x8Eq)                                  \
  V(Loong64I16x8Ne)                                  \
  V(Loong64I16x8GtS)                                 \
  V(Loong64I16x8GeS)                                 \
  V(Loong64I16x8AddSatU)                             \
  V(Loong64I16x8SubSatU)                             \
  V(Loong64I16x8MaxU)                                \
  V(Loong64I16x8MinU)                                \
  V(Loong64I16x8GtU)                                 \
  V(Loong64I16x8GeU)                                 \
  V(Loong64I16x8RoundingAverageU)                    \
  V(Loong64I16x8Abs)                                 \
  V(Loong64I16x8BitMask)                             \
  V(Loong64I16x8Q15MulRSatS)                         \
  V(Loong64I16x8RelaxedQ15MulRS)                     \
  V(Loong64I8x16Splat)                               \
  V(Loong64I8x16ExtractLaneU)                        \
  V(Loong64I8x16ExtractLaneS)                        \
  V(Loong64I8x16ReplaceLane)                         \
  V(Loong64I8x16Neg)                                 \
  V(Loong64I8x16Shl)                                 \
  V(Loong64I8x16ShrS)                                \
  V(Loong64I8x16Add)                                 \
  V(Loong64I8x16AddSatS)                             \
  V(Loong64I8x16Sub)                                 \
  V(Loong64I8x16SubSatS)                             \
  V(Loong64I8x16MaxS)                                \
  V(Loong64I8x16MinS)                                \
  V(Loong64I8x16Eq)                                  \
  V(Loong64I8x16Ne)                                  \
  V(Loong64I8x16GtS)                                 \
  V(Loong64I8x16GeS)                                 \
  V(Loong64I8x16ShrU)                                \
  V(Loong64I8x16AddSatU)                             \
  V(Loong64I8x16SubSatU)                             \
  V(Loong64I8x16MaxU)                                \
  V(Loong64I8x16MinU)                                \
  V(Loong64I8x16GtU)                                 \
  V(Loong64I8x16GeU)                                 \
  V(Loong64I8x16RoundingAverageU)                    \
  V(Loong64I8x16Abs)                                 \
  V(Loong64I8x16Popcnt)                              \
  V(Loong64I8x16BitMask)                             \
  V(Loong64S128And)                                  \
  V(Loong64S128Or)                                   \
  V(Loong64S128Xor)                                  \
  V(Loong64S128Not)                                  \
  V(Loong64S128Select)                               \
  V(Loong64S128AndNot)                               \
  V(Loong64I64x2AllTrue)                             \
  V(Loong64I32x4AllTrue)                             \
  V(Loong64I16x8AllTrue)                             \
  V(Loong64I8x16AllTrue)                             \
  V(Loong64V128AnyTrue)                              \
  V(Loong64S32x4InterleaveRight)                     \
  V(Loong64S32x4InterleaveLeft)                      \
  V(Loong64S32x4PackEven)                            \
  V(Loong64S32x4PackOdd)                             \
  V(Loong64S32x4InterleaveEven)                      \
  V(Loong64S32x4InterleaveOdd)                       \
  V(Loong64S32x4Shuffle)                             \
  V(Loong64S16x8InterleaveRight)                     \
  V(Loong64S16x8InterleaveLeft)                      \
  V(Loong64S16x8PackEven)                            \
  V(Loong64S16x8PackOdd)                             \
  V(Loong64S16x8InterleaveEven)                      \
  V(Loong64S16x8InterleaveOdd)                       \
  V(Loong64S16x4Reverse)                             \
  V(Loong64S16x2Reverse)                             \
  V(Loong64S8x16InterleaveRight)                     \
  V(Loong64S8x16InterleaveLeft)                      \
  V(Loong64S8x16PackEven)                            \
  V(Loong64S8x16PackOdd)                             \
  V(Loong64S8x16InterleaveEven)                      \
  V(Loong64S8x16InterleaveOdd)                       \
  V(Loong64I8x16Shuffle)                             \
  V(Loong64I8x16Swizzle)                             \
  V(Loong64S8x16Concat)                              \
  V(Loong64S8x8Reverse)                              \
  V(Loong64S8x4Reverse)                              \
  V(Loong64S8x2Reverse)                              \
  V(Loong64S128Load32Zero)                           \
  V(Loong64S128Load64Zero)                           \
  V(Loong64I32x4SConvertI16x8Low)                    \
  V(Loong64I32x4SConvertI16x8High)                   \
  V(Loong64I32x4UConvertI16x8Low)                    \
  V(Loong64I32x4UConvertI16x8High)                   \
  V(Loong64I16x8SConvertI8x16Low)                    \
  V(Loong64I16x8SConvertI8x16High)                   \
  V(Loong64I16x8SConvertI32x4)                       \
  V(Loong64I16x8UConvertI32x4)                       \
  V(Loong64I16x8UConvertI8x16Low)                    \
  V(Loong64I16x8UConvertI8x16High)                   \
  V(Loong64I8x16SConvertI16x8)                       \
  V(Loong64I8x16UConvertI16x8)                       \
  V(Loong64AtomicLoadDecompressTaggedSigned)         \
  V(Loong64AtomicLoadDecompressTagged)               \
  V(Loong64AtomicStoreCompressTagged)                \
  V(Loong64Word64AtomicAddUint64)                    \
  V(Loong64Word64AtomicSubUint64)                    \
  V(Loong64Word64AtomicAndUint64)                    \
  V(Loong64Word64AtomicOrUint64)                     \
  V(Loong64Word64AtomicXorUint64)                    \
  V(Loong64Word64AtomicExchangeUint64)               \
  V(Loong64Word64AtomicCompareExchangeUint64)

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
#define TARGET_ADDRESSING_MODE_LIST(V) \
  V(MRI)  /* [%r0 + K] */              \
  V(MRR)  /* [%r0 + %r1] */            \
  V(Root) /* [%rr + K] */

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_BACKEND_LOONG64_INSTRUCTION_CODES_LOONG64_H_
```