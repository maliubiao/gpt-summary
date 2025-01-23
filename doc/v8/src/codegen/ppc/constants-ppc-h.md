Response:
My thinking process to analyze the provided C++ header file went through these stages:

1. **Initial Skim and Keyword Recognition:** I first quickly read through the file, paying attention to keywords like `#ifndef`, `#define`, `#include`, `namespace`, `constexpr`, `const`, `enum`, `struct`, and capitalized words often indicating macros or constants. This gives a high-level understanding of the file's purpose as a header file defining constants and potentially some utility macros for the PowerPC architecture within the V8 project.

2. **Understanding the Header Guard:** The `#ifndef V8_CODEGEN_PPC_CONSTANTS_PPC_H_` and `#define V8_CODEGEN_PPC_CONSTANTS_PPC_H_` lines immediately tell me this is a standard header guard, preventing multiple inclusions of the file within a single compilation unit. This is a common practice in C/C++ to avoid redefinition errors.

3. **Analyzing Includes:** The `#include` directives (`<stdint.h>`, `"src/base/logging.h"`, `"src/base/macros.h"`, `"src/common/code-memory-access.h"`, `"src/common/globals.h"`) indicate the file's dependencies. These includes suggest the file deals with:
    * Standard integer types (`stdint.h`).
    * Logging and debugging facilities (`src/base/logging.h`).
    * Generic macros (`src/base/macros.h`).
    * Accessing code memory (`src/common/code-memory-access.h`).
    * Global definitions and settings within V8 (`src/common/globals.h`).

4. **Examining Macros:** The macros defined, like `UNIMPLEMENTED_PPC()`, and the ABI-related macros (`ABI_USES_FUNCTION_DESCRIPTORS`, `ABI_PASSES_HANDLES_IN_REGS`, etc.), are crucial.
    * `UNIMPLEMENTED_PPC()` is clearly for marking unimplemented functionality, especially useful during development and debugging. It conditionally prints a message in debug builds.
    * The ABI macros are conditional compilation flags based on the target PowerPC architecture (32-bit or 64-bit), operating system (AIX), and endianness. These determine how function calls are made, how arguments are passed, and how return values are handled. This strongly indicates the file's role in code generation for PPC, where ABI details are critical.

5. **Analyzing `constexpr` and `const` Variables:** The `constexpr` and `const` variables define various numeric constants:
    * `kMaxPCRelativeCodeRangeInMB`:  Relates to the range of PC-relative addressing.
    * `kHasFunctionDescriptorBitShift`, `kHasFunctionDescriptorBitMask`: Used for encoding information about function descriptors.
    * `kNumRegisters`, `kNumDoubleRegisters`: Define the number of general-purpose and floating-point registers.
    * `kNoRegister`: Represents an invalid or no register.
    * `kLoadPtrMaxReachBits`, `kLoadDoubleMaxReachBits`: Define the maximum reach for load instructions.
    * `kRootRegisterBias`:  An offset related to the root register.
    * `ABI_TOC_REGISTER`: Specifies the register used for the Table of Contents (TOC), a crucial element in some PPC ABIs.

6. **Analyzing `SIGN_EXT_IMM*` Macros:**  These macros perform sign extension on immediate values of different bit lengths. This is essential for working with signed immediate operands in PPC instructions.

7. **Analyzing the `Condition` Enum:** The `Condition` enum defines the different condition codes used for conditional branching and execution in PPC instructions. The `to_condition` and `is_signed` inline functions provide utilities for working with these conditions. The `NegateCondition` function allows for easily obtaining the opposite condition. This section heavily points towards the file's involvement in low-level code generation and instruction manipulation.

8. **Understanding `Instr`:** The `using Instr = uint32_t;` line declares a type alias, indicating that instructions are represented as 32-bit unsigned integers. This is a fundamental aspect of how machine code is represented.

9. **Analyzing the Instruction Opcode Macros (`PPC_XX3_OPCODE_SCALAR_LIST`, etc.):** These large macros define lists of PowerPC instructions. The naming convention (`XV...`, `XS...`, `XX...`, `DQU...`) and the accompanying opcode values strongly suggest that this file is used to define the instruction set architecture (ISA) elements for the PPC target. The grouping into scalar, vector, and decimal floating-point instructions further reinforces this.

10. **Synthesizing the Information:** After analyzing the individual parts, I started to connect the dots. The file is clearly specific to the PowerPC architecture (`v8/src/codegen/ppc/`). It defines constants related to registers, memory addressing, and instruction encoding. The ABI macros indicate how V8's generated code interacts with the operating system and libraries on PPC. The `Condition` enum and the instruction opcode macros are fundamental to the code generation process.

11. **Addressing the Specific Questions:** Finally, I addressed the specific questions in the prompt:
    * **Functionality:**  Summarized the file's role in defining constants and macros for PPC code generation.
    * **`.tq` Extension:**  Correctly identified that the file is a C++ header, not a Torque file.
    * **Relationship to JavaScript:** Explained that while indirectly related (used in the code generation that makes JavaScript run), it's not directly programmable in JavaScript. Provided an example of a concept (conditional execution) that the defined constants enable at the machine code level.
    * **Code Logic/Inference:** Demonstrated a simple example of how the `SIGN_EXT_IMM5` macro works.
    * **Common Programming Errors:**  Provided an example related to incorrect ABI assumptions.
    * **Overall Summary:** Condensed the key functionalities into a concise summary.

By following these steps, I could systematically dissect the provided C++ header file and understand its purpose within the larger V8 project, allowing me to answer the specific questions accurately.


这个头文件 `v8/src/codegen/ppc/constants-ppc.h` 的主要功能是：

1. **定义了用于在 PowerPC (PPC) 架构上生成和处理机器码的各种常量。** 这些常量包括：
    * **寄存器数量：** `kNumRegisters` (通用寄存器) 和 `kNumDoubleRegisters` (浮点寄存器)。
    * **特殊寄存器值：** `kNoRegister` 表示无效寄存器。
    * **内存寻址范围：** `kMaxPCRelativeCodeRangeInMB` (尽管目前为0，可能未来会使用相对跳转)。
    * **位移和掩码：** `kHasFunctionDescriptorBitShift` 和 `kHasFunctionDescriptorBitMask` 用于编码函数描述符的存在。
    * **加载指令的最大范围：** `kLoadPtrMaxReachBits` 和 `kLoadDoubleMaxReachBits`。
    * **根寄存器偏移：** `kRootRegisterBias`。
    * **ABI (Application Binary Interface) 相关的常量：**  例如 `ABI_USES_FUNCTION_DESCRIPTORS`, `ABI_PASSES_HANDLES_IN_REGS`, `ABI_RETURNS_OBJECT_PAIRS_IN_REGS`, `ABI_CALL_VIA_IP`, `ABI_TOC_REGISTER`。这些宏根据不同的 PPC 架构和操作系统定义了函数调用约定、参数传递方式等。

2. **定义了用于处理 PPC 指令的宏。** 例如：
    * `UNIMPLEMENTED_PPC()`:  在调试模式下打印未实现的函数信息。
    * `SIGN_EXT_IMM*`:  用于对不同位数的立即数进行符号扩展的宏，这在 PPC 指令编码中很常见。

3. **定义了 `Condition` 枚举，用于表示 PPC 指令中的条件码。**  包括相等、不等、大于、小于等各种条件，以及一些跨平台的别名。还提供了辅助函数 `to_condition`, `is_signed`, `NegateCondition` 来操作这些条件码。

4. **定义了 `Instr` 类型别名。** `using Instr = uint32_t;` 表明 PPC 指令在 V8 中被表示为 32 位的无符号整数。

5. **定义了大量的宏，用于列举各种 PPC 指令的操作码。** 这些宏如 `PPC_XX3_OPCODE_SCALAR_LIST`, `PPC_XX3_OPCODE_VECTOR_LIST`, `PPC_Z23_OPCODE_LIST` 等，分别列出了不同的 PPC 指令及其对应的枚举值和十六进制操作码。这些指令涵盖了标量浮点运算、向量运算、十进制浮点运算等。

**判断是否为 Torque 源代码:**

`v8/src/codegen/ppc/constants-ppc.h` 的文件扩展名是 `.h`，这表明它是一个 C++ 头文件，而不是以 `.tq` 结尾的 Torque 源代码。 Torque 源代码用于定义 V8 中一些底层的、类型化的操作。

**与 JavaScript 的关系:**

虽然这个头文件本身不是 JavaScript 代码，但它对于 V8 引擎执行 JavaScript 代码至关重要。V8 引擎需要将 JavaScript 代码编译成特定架构的机器码才能运行，而 `constants-ppc.h` 中定义的常量和宏正是用于在 PPC 架构上生成这些机器码的关键信息。

**JavaScript 示例说明:**

例如，`Condition` 枚举中定义的条件码（如 `eq`, `ne`, `gt`, `lt`）直接对应于 JavaScript 中的条件判断语句：

```javascript
let x = 10;
let y = 5;

if (x > y) { // 对应于 PPC 的 `gt` 条件码
  console.log("x is greater than y");
}

if (x === y) { // 对应于 PPC 的 `eq` 条件码
  console.log("x is equal to y");
}
```

当 V8 编译这段 JavaScript 代码时，会根据 `if` 语句中的条件生成相应的 PPC 机器码指令，这些指令会使用 `constants-ppc.h` 中定义的条件码来进行比较和跳转。

**代码逻辑推理 (假设输入与输出):**

假设我们使用 `SIGN_EXT_IMM5` 宏来扩展一个 5 位立即数：

```c++
#define SIGN_EXT_IMM5(imm) ((static_cast<int>(imm) << 27) >> 27)

int main() {
  unsigned char imm_positive = 0b00101; // 十进制 5
  unsigned char imm_negative = 0b11011; // 负数，二进制补码表示

  int extended_positive = SIGN_EXT_IMM5(imm_positive);
  int extended_negative = SIGN_EXT_IMM5(imm_negative);

  // 假设输出
  // extended_positive 的值应为 5
  // extended_negative 的值应为 -5
  return 0;
}
```

**用户常见的编程错误 (与 ABI 相关):**

如果在编写与 V8 交互的本地 (C++) 代码时，没有正确理解或遵守 `constants-ppc.h` 中定义的 ABI 约定，就可能导致严重的错误。例如，如果一个 C++ 函数需要被 V8 调用，但它的参数传递方式与 `ABI_PASSES_HANDLES_IN_REGS` 的定义不符，就会导致参数传递错误，程序崩溃或产生不可预测的结果。

```c++
// 错误的 C++ 函数定义，假设 V8 期望通过寄存器传递 Handle
extern "C" void MyPPCFunction(v8::Local<v8::String> str) {
  // ... 尝试使用 str ...
}

// 如果 ABI_PASSES_HANDLES_IN_REGS 为 1，但上面的函数没有按照寄存器传递的方式接收参数，
// 那么 str 的值可能是不正确的。
```

**功能归纳 (第 1 部分):**

`v8/src/codegen/ppc/constants-ppc.h` 文件是 V8 引擎中用于 PowerPC 架构代码生成的核心头文件，它定义了：

* **关键的架构常量：**  如寄存器数量、内存寻址范围等。
* **ABI 约定：**  描述了函数调用、参数传递和返回值处理的方式。
* **指令相关的定义：**  包括条件码和各种 PPC 指令的操作码。
* **辅助宏：**  用于简化指令编码和调试。

这个文件为 V8 在 PPC 架构上生成正确高效的机器码提供了基础。它不是 Torque 代码，但与 JavaScript 的执行息息相关，因为它是将 JavaScript 代码转换为机器码的关键组成部分。理解其中的 ABI 约定对于编写与 V8 互操作的本地代码至关重要，否则容易引发编程错误。

### 提示词
```
这是目录为v8/src/codegen/ppc/constants-ppc.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/constants-ppc.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_PPC_CONSTANTS_PPC_H_
#define V8_CODEGEN_PPC_CONSTANTS_PPC_H_

#include <stdint.h>

#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/common/code-memory-access.h"
#include "src/common/globals.h"

// UNIMPLEMENTED_ macro for PPC.
#ifdef DEBUG
#define UNIMPLEMENTED_PPC()                                                \
  v8::internal::PrintF("%s, \tline %d: \tfunction %s not implemented. \n", \
                       __FILE__, __LINE__, __func__)
#else
#define UNIMPLEMENTED_PPC()
#endif

#if V8_HOST_ARCH_PPC64 &&                                          \
    (V8_OS_AIX || (V8_TARGET_ARCH_PPC64 && V8_TARGET_BIG_ENDIAN && \
                   (!defined(_CALL_ELF) || _CALL_ELF == 1)))
#define ABI_USES_FUNCTION_DESCRIPTORS 1
#else
#define ABI_USES_FUNCTION_DESCRIPTORS 0
#endif

#if !V8_HOST_ARCH_PPC64 || V8_OS_AIX || V8_TARGET_ARCH_PPC64
#define ABI_PASSES_HANDLES_IN_REGS 1
#else
#define ABI_PASSES_HANDLES_IN_REGS 0
#endif

#if !V8_HOST_ARCH_PPC64 || !V8_TARGET_ARCH_PPC64 || V8_TARGET_LITTLE_ENDIAN || \
    (defined(_CALL_ELF) && _CALL_ELF == 2)
#define ABI_RETURNS_OBJECT_PAIRS_IN_REGS 1
#else
#define ABI_RETURNS_OBJECT_PAIRS_IN_REGS 0
#endif

#if !V8_HOST_ARCH_PPC64 ||   \
    (V8_TARGET_ARCH_PPC64 && \
     (V8_TARGET_LITTLE_ENDIAN || (defined(_CALL_ELF) && _CALL_ELF == 2)))
#define ABI_CALL_VIA_IP 1
#else
#define ABI_CALL_VIA_IP 0
#endif

#if !V8_HOST_ARCH_PPC64 || V8_OS_AIX || V8_TARGET_ARCH_PPC64
#define ABI_TOC_REGISTER 2
#else
#define ABI_TOC_REGISTER 13
#endif
namespace v8 {
namespace internal {

// TODO(sigurds): Change this value once we use relative jumps.
constexpr size_t kMaxPCRelativeCodeRangeInMB = 0;

// Used to encode a boolean value when emitting 32 bit
// opcodes which will indicate the presence of function descriptors
constexpr int kHasFunctionDescriptorBitShift = 4;
constexpr int kHasFunctionDescriptorBitMask = 1
                                              << kHasFunctionDescriptorBitShift;

// Number of registers
const int kNumRegisters = 32;

// FP support.
const int kNumDoubleRegisters = 32;

const int kNoRegister = -1;

// Used in embedded constant pool builder - max reach in bits for
// various load instructions (one less due to unsigned)
const int kLoadPtrMaxReachBits = 15;
const int kLoadDoubleMaxReachBits = 15;

// The actual value of the kRootRegister is offset from the IsolateData's start
// to take advantage of negative displacement values.
constexpr int kRootRegisterBias = 128;

// sign-extend the least significant 5-bits of value <imm>
#define SIGN_EXT_IMM5(imm) ((static_cast<int>(imm) << 27) >> 27)

// sign-extend the least significant 16-bits of value <imm>
#define SIGN_EXT_IMM16(imm) ((static_cast<int>(imm) << 16) >> 16)

// sign-extend the least significant 14-bits of value <imm>
#define SIGN_EXT_IMM18(imm) ((static_cast<int>(imm) << 14) >> 14)

// sign-extend the least significant 22-bits of value <imm>
#define SIGN_EXT_IMM22(imm) ((static_cast<int>(imm) << 10) >> 10)

// sign-extend the least significant 26-bits of value <imm>
#define SIGN_EXT_IMM26(imm) ((static_cast<int>(imm) << 6) >> 6)

// sign-extend the least significant 34-bits of prefix+suffix value <imm>
#define SIGN_EXT_IMM34(imm) ((static_cast<int64_t>(imm) << 30) >> 30)

// -----------------------------------------------------------------------------
// Conditions.

// Defines constants and accessor classes to assemble, disassemble and
// simulate PPC instructions.
//
// Section references in the code refer to the "PowerPC Microprocessor
// Family: The Programmer.s Reference Guide" from 10/95
// https://www-01.ibm.com/chips/techlib/techlib.nsf/techdocs/852569B20050FF778525699600741775/$file/prg.pdf
//

// Constants for specific fields are defined in their respective named enums.
// General constants are in an anonymous enum in class Instr.
enum Condition : int {
  kNoCondition = -1,
  eq = 0,         // Equal.
  ne = 1,         // Not equal.
  ge = 2,         // Greater or equal.
  lt = 3,         // Less than.
  gt = 4,         // Greater than.
  le = 5,         // Less then or equal
  unordered = 6,  // Floating-point unordered
  ordered = 7,
  overflow = 8,  // Summary overflow
  nooverflow = 9,
  al = 10,  // Always.

  // Unified cross-platform condition names/aliases.
  // Do not set unsigned constants equal to their signed variants.
  // We need to be able to differentiate between signed and unsigned enum
  // constants in order to emit the right instructions (i.e CmpS64 vs CmpU64).
  kEqual = eq,
  kNotEqual = ne,
  kLessThan = lt,
  kGreaterThan = gt,
  kLessThanEqual = le,
  kGreaterThanEqual = ge,
  kUnsignedLessThan = 11,
  kUnsignedGreaterThan = 12,
  kUnsignedLessThanEqual = 13,
  kUnsignedGreaterThanEqual = 14,
  kOverflow = overflow,
  kNoOverflow = nooverflow,
  kZero = 15,
  kNotZero = 16,
};

inline Condition to_condition(Condition cond) {
  switch (cond) {
    case kUnsignedLessThan:
      return lt;
    case kUnsignedGreaterThan:
      return gt;
    case kUnsignedLessThanEqual:
      return le;
    case kUnsignedGreaterThanEqual:
      return ge;
    case kZero:
      return eq;
    case kNotZero:
      return ne;
    default:
      break;
  }
  return cond;
}

inline bool is_signed(Condition cond) {
  switch (cond) {
    case kEqual:
    case kNotEqual:
    case kLessThan:
    case kGreaterThan:
    case kLessThanEqual:
    case kGreaterThanEqual:
    case kOverflow:
    case kNoOverflow:
    case kZero:
    case kNotZero:
      return true;

    case kUnsignedLessThan:
    case kUnsignedGreaterThan:
    case kUnsignedLessThanEqual:
    case kUnsignedGreaterThanEqual:
      return false;

    default:
      UNREACHABLE();
  }
}

inline Condition NegateCondition(Condition cond) {
  DCHECK(cond != al);
  return static_cast<Condition>(cond ^ ne);
}

// -----------------------------------------------------------------------------
// Instructions encoding.

// Instr is merely used by the Assembler to distinguish 32bit integers
// representing instructions from usual 32 bit values.
// Instruction objects are pointers to 32bit values, and provide methods to
// access the various ISA fields.
using Instr = uint32_t;

#define PPC_XX3_OPCODE_SCALAR_LIST(V)                                 \
  /* VSX Scalar Add Double-Precision */                               \
  V(xsadddp, XSADDDP, 0xF0000100)                                     \
  /* VSX Scalar Add Single-Precision */                               \
  V(xsaddsp, XSADDSP, 0xF0000000)                                     \
  /* VSX Scalar Compare Ordered Double-Precision */                   \
  V(xscmpodp, XSCMPODP, 0xF0000158)                                   \
  /* VSX Scalar Compare Unordered Double-Precision */                 \
  V(xscmpudp, XSCMPUDP, 0xF0000118)                                   \
  /* VSX Scalar Copy Sign Double-Precision */                         \
  V(xscpsgndp, XSCPSGNDP, 0xF0000580)                                 \
  /* VSX Scalar Divide Double-Precision */                            \
  V(xsdivdp, XSDIVDP, 0xF00001C0)                                     \
  /* VSX Scalar Divide Single-Precision */                            \
  V(xsdivsp, XSDIVSP, 0xF00000C0)                                     \
  /* VSX Scalar Multiply-Add Type-A Double-Precision */               \
  V(xsmaddadp, XSMADDADP, 0xF0000108)                                 \
  /* VSX Scalar Multiply-Add Type-A Single-Precision */               \
  V(xsmaddasp, XSMADDASP, 0xF0000008)                                 \
  /* VSX Scalar Multiply-Add Type-M Double-Precision */               \
  V(xsmaddmdp, XSMADDMDP, 0xF0000148)                                 \
  /* VSX Scalar Multiply-Add Type-M Single-Precision */               \
  V(xsmaddmsp, XSMADDMSP, 0xF0000048)                                 \
  /* VSX Scalar Maximum Double-Precision */                           \
  V(xsmaxdp, XSMAXDP, 0xF0000500)                                     \
  /* VSX Scalar Minimum Double-Precision */                           \
  V(xsmindp, XSMINDP, 0xF0000540)                                     \
  /* VSX Scalar Multiply-Subtract Type-A Double-Precision */          \
  V(xsmsubadp, XSMSUBADP, 0xF0000188)                                 \
  /* VSX Scalar Multiply-Subtract Type-A Single-Precision */          \
  V(xsmsubasp, XSMSUBASP, 0xF0000088)                                 \
  /* VSX Scalar Multiply-Subtract Type-M Double-Precision */          \
  V(xsmsubmdp, XSMSUBMDP, 0xF00001C8)                                 \
  /* VSX Scalar Multiply-Subtract Type-M Single-Precision */          \
  V(xsmsubmsp, XSMSUBMSP, 0xF00000C8)                                 \
  /* VSX Scalar Multiply Double-Precision */                          \
  V(xsmuldp, XSMULDP, 0xF0000180)                                     \
  /* VSX Scalar Multiply Single-Precision */                          \
  V(xsmulsp, XSMULSP, 0xF0000080)                                     \
  /* VSX Scalar Negative Multiply-Add Type-A Double-Precision */      \
  V(xsnmaddadp, XSNMADDADP, 0xF0000508)                               \
  /* VSX Scalar Negative Multiply-Add Type-A Single-Precision */      \
  V(xsnmaddasp, XSNMADDASP, 0xF0000408)                               \
  /* VSX Scalar Negative Multiply-Add Type-M Double-Precision */      \
  V(xsnmaddmdp, XSNMADDMDP, 0xF0000548)                               \
  /* VSX Scalar Negative Multiply-Add Type-M Single-Precision */      \
  V(xsnmaddmsp, XSNMADDMSP, 0xF0000448)                               \
  /* VSX Scalar Negative Multiply-Subtract Type-A Double-Precision */ \
  V(xsnmsubadp, XSNMSUBADP, 0xF0000588)                               \
  /* VSX Scalar Negative Multiply-Subtract Type-A Single-Precision */ \
  V(xsnmsubasp, XSNMSUBASP, 0xF0000488)                               \
  /* VSX Scalar Negative Multiply-Subtract Type-M Double-Precision */ \
  V(xsnmsubmdp, XSNMSUBMDP, 0xF00005C8)                               \
  /* VSX Scalar Negative Multiply-Subtract Type-M Single-Precision */ \
  V(xsnmsubmsp, XSNMSUBMSP, 0xF00004C8)                               \
  /* VSX Scalar Reciprocal Estimate Double-Precision */               \
  V(xsredp, XSREDP, 0xF0000168)                                       \
  /* VSX Scalar Subtract Double-Precision */                          \
  V(xssubdp, XSSUBDP, 0xF0000140)                                     \
  /* VSX Scalar Subtract Single-Precision */                          \
  V(xssubsp, XSSUBSP, 0xF0000040)                                     \
  /* VSX Scalar Test for software Divide Double-Precision */          \
  V(xstdivdp, XSTDIVDP, 0xF00001E8)

#define PPC_XX3_OPCODE_VECTOR_A_FORM_LIST(V)         \
  /* VSX Vector Compare Equal To Single-Precision */ \
  V(xvcmpeqsp, XVCMPEQSP, 0xF0000218)                \
  /* VSX Vector Compare Equal To Double-Precision */ \
  V(xvcmpeqdp, XVCMPEQDP, 0xF0000318)

#define PPC_XX3_OPCODE_VECTOR_B_FORM_LIST(V)                                  \
  /* VSX Vector Add Double-Precision */                                       \
  V(xvadddp, XVADDDP, 0xF0000300)                                             \
  /* VSX Vector Add Single-Precision */                                       \
  V(xvaddsp, XVADDSP, 0xF0000200)                                             \
  /* VSX Vector Compare Equal To Double-Precision & record CR6 */             \
  V(xvcmpeqdpx, XVCMPEQDPx, 0xF0000718)                                       \
  /* VSX Vector Compare Equal To Single-Precision & record CR6 */             \
  V(xvcmpeqspx, XVCMPEQSPx, 0xF0000618)                                       \
  /* VSX Vector Compare Greater Than or Equal To Double-Precision */          \
  V(xvcmpgedp, XVCMPGEDP, 0xF0000398)                                         \
  /* VSX Vector Compare Greater Than or Equal To Double-Precision & record */ \
  /* CR6 */                                                                   \
  V(xvcmpgedpx, XVCMPGEDPx, 0xF0000798)                                       \
  /* VSX Vector Compare Greater Than or Equal To Single-Precision */          \
  V(xvcmpgesp, XVCMPGESP, 0xF0000298)                                         \
  /* VSX Vector Compare Greater Than or Equal To Single-Precision & record */ \
  /* CR6 */                                                                   \
  V(xvcmpgespx, XVCMPGESPx, 0xF0000698)                                       \
  /* VSX Vector Compare Greater Than Double-Precision */                      \
  V(xvcmpgtdp, XVCMPGTDP, 0xF0000358)                                         \
  /* VSX Vector Compare Greater Than Double-Precision & record CR6 */         \
  V(xvcmpgtdpx, XVCMPGTDPx, 0xF0000758)                                       \
  /* VSX Vector Compare Greater Than Single-Precision */                      \
  V(xvcmpgtsp, XVCMPGTSP, 0xF0000258)                                         \
  /* VSX Vector Compare Greater Than Single-Precision & record CR6 */         \
  V(xvcmpgtspx, XVCMPGTSPx, 0xF0000658)                                       \
  /* VSX Vector Copy Sign Double-Precision */                                 \
  V(xvcpsgndp, XVCPSGNDP, 0xF0000780)                                         \
  /* VSX Vector Copy Sign Single-Precision */                                 \
  V(xvcpsgnsp, XVCPSGNSP, 0xF0000680)                                         \
  /* VSX Vector Divide Double-Precision */                                    \
  V(xvdivdp, XVDIVDP, 0xF00003C0)                                             \
  /* VSX Vector Divide Single-Precision */                                    \
  V(xvdivsp, XVDIVSP, 0xF00002C0)                                             \
  /* VSX Vector Multiply-Add Type-A Double-Precision */                       \
  V(xvmaddadp, XVMADDADP, 0xF0000308)                                         \
  /* VSX Vector Multiply-Add Type-A Single-Precision */                       \
  V(xvmaddasp, XVMADDASP, 0xF0000208)                                         \
  /* VSX Vector Multiply-Add Type-M Double-Precision */                       \
  V(xvmaddmdp, XVMADDMDP, 0xF0000348)                                         \
  /* VSX Vector Multiply-Add Type-M Single-Precision */                       \
  V(xvmaddmsp, XVMADDMSP, 0xF0000248)                                         \
  /* VSX Vector Maximum Double-Precision */                                   \
  V(xvmaxdp, XVMAXDP, 0xF0000700)                                             \
  /* VSX Vector Maximum Single-Precision */                                   \
  V(xvmaxsp, XVMAXSP, 0xF0000600)                                             \
  /* VSX Vector Minimum Double-Precision */                                   \
  V(xvmindp, XVMINDP, 0xF0000740)                                             \
  /* VSX Vector Minimum Single-Precision */                                   \
  V(xvminsp, XVMINSP, 0xF0000640)                                             \
  /* VSX Vector Multiply-Subtract Type-A Double-Precision */                  \
  V(xvmsubadp, XVMSUBADP, 0xF0000388)                                         \
  /* VSX Vector Multiply-Subtract Type-A Single-Precision */                  \
  V(xvmsubasp, XVMSUBASP, 0xF0000288)                                         \
  /* VSX Vector Multiply-Subtract Type-M Double-Precision */                  \
  V(xvmsubmdp, XVMSUBMDP, 0xF00003C8)                                         \
  /* VSX Vector Multiply-Subtract Type-M Single-Precision */                  \
  V(xvmsubmsp, XVMSUBMSP, 0xF00002C8)                                         \
  /* VSX Vector Multiply Double-Precision */                                  \
  V(xvmuldp, XVMULDP, 0xF0000380)                                             \
  /* VSX Vector Multiply Single-Precision */                                  \
  V(xvmulsp, XVMULSP, 0xF0000280)                                             \
  /* VSX Vector Negative Multiply-Add Type-A Double-Precision */              \
  V(xvnmaddadp, XVNMADDADP, 0xF0000708)                                       \
  /* VSX Vector Negative Multiply-Add Type-A Single-Precision */              \
  V(xvnmaddasp, XVNMADDASP, 0xF0000608)                                       \
  /* VSX Vector Negative Multiply-Add Type-M Double-Precision */              \
  V(xvnmaddmdp, XVNMADDMDP, 0xF0000748)                                       \
  /* VSX Vector Negative Multiply-Add Type-M Single-Precision */              \
  V(xvnmaddmsp, XVNMADDMSP, 0xF0000648)                                       \
  /* VSX Vector Negative Multiply-Subtract Type-A Double-Precision */         \
  V(xvnmsubadp, XVNMSUBADP, 0xF0000788)                                       \
  /* VSX Vector Negative Multiply-Subtract Type-A Single-Precision */         \
  V(xvnmsubasp, XVNMSUBASP, 0xF0000688)                                       \
  /* VSX Vector Negative Multiply-Subtract Type-M Double-Precision */         \
  V(xvnmsubmdp, XVNMSUBMDP, 0xF00007C8)                                       \
  /* VSX Vector Negative Multiply-Subtract Type-M Single-Precision */         \
  V(xvnmsubmsp, XVNMSUBMSP, 0xF00006C8)                                       \
  /* VSX Vector Reciprocal Estimate Double-Precision */                       \
  V(xvredp, XVREDP, 0xF0000368)                                               \
  /* VSX Vector Subtract Double-Precision */                                  \
  V(xvsubdp, XVSUBDP, 0xF0000340)                                             \
  /* VSX Vector Subtract Single-Precision */                                  \
  V(xvsubsp, XVSUBSP, 0xF0000240)                                             \
  /* VSX Vector Test for software Divide Double-Precision */                  \
  V(xvtdivdp, XVTDIVDP, 0xF00003E8)                                           \
  /* VSX Vector Test for software Divide Single-Precision */                  \
  V(xvtdivsp, XVTDIVSP, 0xF00002E8)                                           \
  /* VSX Logical AND */                                                       \
  V(xxland, XXLAND, 0xF0000410)                                               \
  /* VSX Logical AND with Complement */                                       \
  V(xxlandc, XXLANDC, 0xF0000450)                                             \
  /* VSX Logical Equivalence */                                               \
  V(xxleqv, XXLEQV, 0xF00005D0)                                               \
  /* VSX Logical NAND */                                                      \
  V(xxlnand, XXLNAND, 0xF0000590)                                             \
  /* VSX Logical NOR */                                                       \
  V(xxlnor, XXLNOR, 0xF0000510)                                               \
  /* VSX Logical OR */                                                        \
  V(xxlor, XXLOR, 0xF0000490)                                                 \
  /* VSX Logical OR with Complement */                                        \
  V(xxlorc, XXLORC, 0xF0000550)                                               \
  /* VSX Logical XOR */                                                       \
  V(xxlxor, XXLXOR, 0xF00004D0)                                               \
  /* VSX Merge High Word */                                                   \
  V(xxmrghw, XXMRGHW, 0xF0000090)                                             \
  /* VSX Merge Low Word */                                                    \
  V(xxmrglw, XXMRGLW, 0xF0000190)                                             \
  /* VSX Permute Doubleword Immediate */                                      \
  V(xxpermdi, XXPERMDI, 0xF0000050)                                           \
  /* VSX Shift Left Double by Word Immediate */                               \
  V(xxsldwi, XXSLDWI, 0xF0000010)                                             \
  /* VSX Splat Word */                                                        \
  V(xxspltw, XXSPLTW, 0xF0000290)

#define PPC_XX3_OPCODE_VECTOR_LIST(V)  \
  PPC_XX3_OPCODE_VECTOR_A_FORM_LIST(V) \
  PPC_XX3_OPCODE_VECTOR_B_FORM_LIST(V)

#define PPC_Z23_OPCODE_LIST(V)                                    \
  /* Decimal Quantize */                                          \
  V(dqua, DQUA, 0xEC000006)                                       \
  /* Decimal Quantize Immediate */                                \
  V(dquai, DQUAI, 0xEC000086)                                     \
  /* Decimal Quantize Immediate Quad */                           \
  V(dquaiq, DQUAIQ, 0xFC000086)                                   \
  /* Decimal Quantize Quad */                                     \
  V(dquaq, DQUAQ, 0xFC000006)                                     \
  /* Decimal Floating Round To FP Integer Without Inexact */      \
  V(drintn, DRINTN, 0xEC0001C6)                                   \
  /* Decimal Floating Round To FP Integer Without Inexact Quad */ \
  V(drintnq, DRINTNQ, 0xFC0001C6)                                 \
  /* Decimal Floating Round To FP Integer With Inexact */         \
  V(drintx, DRINTX, 0xEC0000C6)                                   \
  /* Decimal Floating Round To FP Integer With Inexact Quad */    \
  V(drintxq, DRINTXQ, 0xFC0000C6)                                 \
  /* Decimal Floating Reround */                                  \
  V(drrnd, DRRND, 0xEC000046)                                     \
  /* Decimal Floating Reround Quad */                             \
  V(drrndq, DRRNDQ, 0xFC000046)

#define PPC_Z22_OPCODE_LIST(V)                                  \
  /* Decimal Floating Shift Coefficient Left Immediate */       \
  V(dscli, DSCLI, 0xEC000084)                                   \
  /* Decimal Floating Shift Coefficient Left Immediate Quad */  \
  V(dscliq, DSCLIQ, 0xFC000084)                                 \
  /* Decimal Floating Shift Coefficient Right Immediate */      \
  V(dscri, DSCRI, 0xEC0000C4)                                   \
  /* Decimal Floating Shift Coefficient Right Immediate Quad */ \
  V(dscriq, DSCRIQ, 0xFC0000C4)                                 \
  /* Decimal Floating Test Data Class */                        \
  V(dtstdc, DTSTDC, 0xEC000184)                                 \
  /* Decimal Floating Test Data Class Quad */                   \
  V(dtstdcq, DTSTDCQ, 0xFC000184)                               \
  /* Decimal Floating Test Data Group */                        \
  V(dtstdg, DTSTDG, 0xEC0001C4)                                 \
  /* Decimal Floating Test Data Group Quad */                   \
  V(dtstdgq, DTSTDGQ, 0xFC0001C4)

#define PPC_XX2_OPCODE_VECTOR_A_FORM_LIST(V)                                 \
  /* VSX Vector Absolute Value Double-Precision */                           \
  V(xvabsdp, XVABSDP, 0xF0000764)                                            \
  /* VSX Vector Negate Double-Precision */                                   \
  V(xvnegdp, XVNEGDP, 0xF00007E4)                                            \
  /* VSX Vector Square Root Double-Precision */                              \
  V(xvsqrtdp, XVSQRTDP, 0xF000032C)                                          \
  /* VSX Vector Absolute Value Single-Precision */                           \
  V(xvabssp, XVABSSP, 0xF0000664)                                            \
  /* VSX Vector Negate Single-Precision */                                   \
  V(xvnegsp, XVNEGSP, 0xF00006E4)                                            \
  /* VSX Vector Reciprocal Estimate Single-Precision */                      \
  V(xvresp, XVRESP, 0xF0000268)                                              \
  /* VSX Vector Reciprocal Square Root Estimate Single-Precision */          \
  V(xvrsqrtesp, XVRSQRTESP, 0xF0000228)                                      \
  /* VSX Vector Square Root Single-Precision */                              \
  V(xvsqrtsp, XVSQRTSP, 0xF000022C)                                          \
  /* VSX Vector Convert Single-Precision to Signed Fixed-Point Word */       \
  /* Saturate */                                                             \
  V(xvcvspsxws, XVCVSPSXWS, 0xF0000260)                                      \
  /* VSX Vector Convert Single-Precision to Unsigned Fixed-Point Word */     \
  /* Saturate */                                                             \
  V(xvcvspuxws, XVCVSPUXWS, 0xF0000220)                                      \
  /* VSX Vector Convert Signed Fixed-Point Word to Single-Precision */       \
  V(xvcvsxwsp, XVCVSXWSP, 0xF00002E0)                                        \
  /* VSX Vector Convert Unsigned Fixed-Point Word to Single-Precision */     \
  V(xvcvuxwsp, XVCVUXWSP, 0xF00002A0)                                        \
  /* VSX Vector Round to Double-Precision Integer toward +Infinity */        \
  V(xvrdpip, XVRDPIP, 0xF00003A4)                                            \
  /* VSX Vector Round to Double-Precision Integer toward -Infinity */        \
  V(xvrdpim, XVRDPIM, 0xF00003E4)                                            \
  /* VSX Vector Round to Double-Precision Integer toward Zero */             \
  V(xvrdpiz, XVRDPIZ, 0xF0000364)                                            \
  /* VSX Vector Round to Double-Precision Integer */                         \
  V(xvrdpi, XVRDPI, 0xF0000324)                                              \
  /* VSX Vector Round to Single-Precision Integer toward +Infinity */        \
  V(xvrspip, XVRSPIP, 0xF00002A4)                                            \
  /* VSX Vector Round to Single-Precision Integer toward -Infinity */        \
  V(xvrspim, XVRSPIM, 0xF00002E4)                                            \
  /* VSX Vector Round to Single-Precision Integer toward Zero */             \
  V(xvrspiz, XVRSPIZ, 0xF0000264)                                            \
  /* VSX Vector Round to Single-Precision Integer */                         \
  V(xvrspi, XVRSPI, 0xF0000224)                                              \
  /* VSX Vector Convert Signed Fixed-Point Doubleword to Double-Precision */ \
  V(xvcvsxddp, XVCVSXDDP, 0xF00007E0)                                        \
  /* VSX Vector Convert Unsigned Fixed-Point Doubleword to Double- */        \
  /* Precision */                                                            \
  V(xvcvuxddp, XVCVUXDDP, 0xF00007A0)                                        \
  /* VSX Vector Convert Single-Precision to Double-Precision */              \
  V(xvcvspdp, XVCVSPDP, 0xF0000724)                                          \
  /* VSX Vector Convert Double-Precision to Single-Precision */              \
  V(xvcvdpsp, XVCVDPSP, 0xF0000624)                                          \
  /* VSX Vector Convert Double-Precision to Signed Fixed-Point Word */       \
  /* Saturate */                                                             \
  V(xvcvdpsxws, XVCVDPSXWS, 0xF0000360)                                      \
  /* VSX Vector Convert Double-Precision to Unsigned Fixed-Point Word */     \
  /* Saturate */                                                             \
  V(xvcvdpuxws, XVCVDPUXWS, 0xF0000320)

#define PPC_XX2_OPCODE_SCALAR_A_FORM_LIST(V)                                \
  /* VSX Scalar Convert Double-Precision to Single-Precision format Non- */ \
  /* signalling */                                                          \
  V(xscvdpspn, XSCVDPSPN, 0xF000042C)                                       \
  /* VSX Scalar Convert Single-Precision to Double-Precision format Non- */ \
  /* signalling */                                                          \
  V(xscvspdpn, XSCVSPDPN, 0xF000052C)

#define PPC_XX2_OPCODE_B_FORM_LIST(V)  \
  /* Vector Byte-Reverse Quadword */   \
  V(xxbrq, XXBRQ, 0xF01F076C)          \
  /* Vector Byte-Reverse Doubleword */ \
  V(xxbrd, XXBRD, 0xF017076C)          \
  /* Vector Byte-Reverse Word */       \
  V(xxbrw, XXBRW, 0xF00F076C)          \
  /* Vector Byte-Reverse Halfword */   \
  V(xxbrh, XXBRH, 0xF007076C)

#define PPC_XX2_OPCODE_UNUSED_LIST(V)                                        \
  /* VSX Scalar Square Root Double-Precision */                              \
  V(xssqrtdp, XSSQRTDP, 0xF000012C)                                          \
  /* VSX Scalar Reciprocal Estimate Single-Precision */                      \
  V(xsresp, XSRESP, 0xF0000068)                                              \
  /* VSX Scalar Reciprocal Square Root Estimate Single-Precision */          \
  V(xsrsqrtesp, XSRSQRTESP, 0xF0000028)                                      \
  /* VSX Scalar Square Root Single-Precision */                              \
  V(xssqrtsp, XSSQRTSP, 0xF000002C)                                          \
  /* VSX Scalar Absolute Value Double-Precision */                           \
  V(xsabsdp, XSABSDP, 0xF0000564)                                            \
  /* VSX Scalar Convert Double-Precision to Single-Precision */              \
  V(xscvdpsp, XSCVDPSP, 0xF0000424)                                          \
  /* VSX Scalar Convert Double-Precision to Signed Fixed-Point Doubleword */ \
  /* Saturate */                                                             \
  V(xscvdpsxds, XSCVDPSXDS, 0xF0000560)                                      \
  /* VSX Scalar Convert Double-Precision to Signed Fixed-Point Word */       \
  /* Saturate */                                                             \
  V(xscvdpsxws, XSCVDPSXWS, 0xF0000160)                                      \
  /* VSX Scalar Convert Double-Precision to Unsigned Fixed-Point */          \
  /* Doubleword Saturate */                                                  \
  V(xscvdpuxds, XSCVDPUXDS, 0xF0000520)                                      \
  /* VSX Scalar Convert Double-Precision to Unsigned Fixed-Point Word */     \
  /* Saturate */                                                             \
  V(xscvdpuxws, XSCVDPUXWS, 0xF0000120)                                      \
  /* VSX Scalar Convert Single-Precision to Double-Precision (p=1) */        \
  V(xscvspdp, XSCVSPDP, 0xF0000524)                                          \
  /* VSX Scalar Convert Signed Fixed-Point Doubleword to Double-Precision */ \
  V(xscvsxddp, XSCVSXDDP, 0xF00005E0)                                        \
  /* VSX Scalar Convert Signed Fixed-Point Doubleword to Single-Precision */ \
  V(xscvsxdsp, XSCVSXDSP, 0xF00004E0)                                        \
  /* VSX Scalar Convert Unsigned Fixed-Point Doubleword to Double- */        \
  /* Precision */                                                            \
  V(xscvuxddp, XSCVUXDDP, 0xF00005A0)                                        \
  /* VSX Scalar Convert Unsigned Fixed-Point Doubleword to Single- */        \
  /* Precision */                                                            \
  V(xscvuxdsp, XSCVUXDSP, 0xF00004A0)                                        \
  /* VSX Scalar Negative Absolute Value Double-Precision */                  \
  V(xsnabsdp, XSNABSDP, 0xF00005A4)                                          \
  /* VSX Scalar Negate Double-Precision */                                   \
  V(xsnegdp, XSNEGDP, 0xF00005E4)                                            \
  /* VSX Scalar Round to Double-Precision Integer */                         \
  V(xsrdpi, XSRDPI, 0xF0000124)                                              \
  /* VSX Scalar Round to Double-Precision Integer using Current rounding */  \
  /* mode */                                                                 \
  V(xsrdpic, XSRDPIC, 0xF00001AC)                                            \
  /* VSX Scalar Round to Double-Precision Integer toward -Infinity */        \
  V(xsrdpim, XSRDPIM, 0xF00001E4)                                            \
  /* VSX Scalar Round to Double-Precision Integer toward +Infinity */        \
  V(xsrdpip, XSRDPIP, 0xF00001A4)                                            \
  /* VSX Scalar Round to Double-Precision Integer toward Zero */             \
  V(xsrdpiz, XSRDPIZ, 0xF0000164)                                            \
  /* VSX Scalar Round to Single-Precision */                                 \
  V(xsrsp, XSRSP, 0xF0000464)                                                \
  /* VSX Scalar Reciprocal Square Root Estimate Double-Precision */          \
  V(xsrsqrtedp, XSRSQRTEDP, 0xF0000128)                                      \
  /* VSX Scalar Test for software Square Root Double-Precis
```