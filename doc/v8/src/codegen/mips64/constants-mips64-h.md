Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and Keyword Recognition:**

My first step is to quickly scan the content for recognizable C++ keywords and patterns. I see:

* `#ifndef`, `#define`, `#endif`:  This immediately tells me it's a header guard, preventing multiple inclusions.
* `#include`:  It includes other header files (`logging.h`, `macros.h`, `code-memory-access.h`, `globals.h`). This indicates dependencies on other parts of the V8 project.
* `// Copyright`: Standard copyright notice.
* `enum`:  Enumerated types like `ArchVariants`, `Endianness`. These define a set of named constants.
* `static const`:  Declaration of compile-time constants.
* `bool`:  A boolean constant `IsMipsSoftFloatABI`.
* `uint32_t`, `int32_t`, `uint64_t`, `int64_t`:  Standard integer types, often used for low-level representations.
* `namespace v8 { namespace internal { ... } }`:  Indicates this code belongs to the internal implementation details of the V8 JavaScript engine.
* `constexpr`:  Another way to define compile-time constants, often preferred for clarity.
* `class`: Declarations of `Registers`, `FPURegisters`, `MSARegisters`. These classes likely encapsulate related data and functionality.
* `using Instr = int32_t;`: A type alias, making the code more readable.
* `enum SoftwareInterruptCodes`: Another enumeration.
* `static_assert`: A compile-time assertion.
* A large number of `const int` or `constexpr Opcode` declarations. These look like definitions for instruction opcodes and related fields.
* Comments explaining MIPS architecture concepts.

**2. Identifying Core Functionality Areas:**

Based on the keywords and the content, I start to categorize the functionalities:

* **Architecture Definitions:**  The `ArchVariants` and `Endianness` enums, along with `kArchVariant` and `kArchEndian`, clearly define the target MIPS64 architecture and its endianness.
* **ABI (Application Binary Interface):**  The `IsMipsSoftFloatABI` constant hints at the floating-point calling convention used.
* **Memory Access Offsets:**  Constants like `kMipsLwrOffset`, `kMipsLdlOffset`, etc., seem related to how different parts of words and doublewords are accessed in memory, likely influenced by endianness.
* **Debugging/Error Handling:**  The `UNIMPLEMENTED_MIPS()` and `UNSUPPORTED_MIPS()` macros are for indicating missing or unsupported features.
* **Register Definitions:** The `kNumRegisters`, `kNumFPURegisters`, `kNumMSARegisters` constants, and the `Registers`, `FPURegisters`, `MSARegisters` classes, are clearly defining the register set for the MIPS64 architecture.
* **FPU (Floating-Point Unit) Control:** The `kFCSRRegister` and related constants (`kFCSRInexactFlagBit`, etc.) point to the control and status register of the FPU.
* **MSA (MIPS SIMD Architecture):** The `kNumMSARegisters`, `kMSAIRRegister`, and related enums (`MSASize`, `MSADataType`) indicate support for SIMD instructions.
* **Instruction Encoding:** The constants like `kOpcodeShift`, `kRsShift`, `kOpcodeMask`, and the numerous `constexpr Opcode` definitions are crucial for encoding and decoding MIPS64 instructions.

**3. Connecting to JavaScript and Torque (Instruction 2 & 3):**

I consider how these low-level definitions relate to the higher-level JavaScript engine.

* **JavaScript Connection:**  The connection is indirect but fundamental. V8 needs to generate machine code for the target architecture to execute JavaScript. This header file provides the building blocks for that code generation process. I realize I can illustrate this by showing a simple JavaScript operation and how V8 *might* translate it (at a conceptual level) into MIPS instructions. This leads to the example of adding two numbers.
* **Torque:**  I check the instruction about `.tq` files. Since this file ends in `.h`, it's a standard C++ header, not a Torque file. Torque is a higher-level language used to generate C++ code within V8, often related to built-in functions.

**4. Code Logic Inference and Error Scenarios (Instruction 4 & 5):**

* **Code Logic:** The endianness-dependent offsets are the most obvious piece of conditional logic. I choose this as the example. I formulate hypothetical inputs (little-endian and big-endian targets) and show the corresponding output values for the offset constants.
* **Common Errors:** I think about common programming errors related to low-level development. Incorrect register usage and incorrect instruction encoding are prime candidates. I create simple examples to illustrate these.

**5. Synthesizing the Summary (Instruction 6):**

Finally, I need to summarize the file's purpose. I combine the categories identified in step 2 into a concise overview. I emphasize its role in defining the MIPS64 architecture within the V8 context, focusing on key aspects like registers, instruction encoding, and endianness.

**Self-Correction/Refinement during the Process:**

* Initially, I might focus too much on individual constants. I then realize the importance of grouping them by functionality (registers, opcodes, etc.).
* I consider providing very technical MIPS instruction examples but realize that simpler JavaScript and conceptual MIPS examples are more effective for illustrating the connection.
* I make sure to address all the specific points raised in the prompt (Torque, JavaScript examples, logic, errors).
* I review the summary to ensure it's comprehensive and accurately reflects the content of the header file.

This structured approach, combining keyword recognition, functional decomposition, and connection to the broader context of V8, helps in understanding and summarizing the purpose of this complex header file.
```javascript
/*
这是一个目录为v8/src/codegen/mips64/constants-mips64.h的一个v8源代码， 请列举一下它的功能,
如果v8/src/codegen/mips64/constants-mips64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
*/
```

好的，让我们来分析一下 `v8/src/codegen/mips64/constants-mips64.h` 这个 C++ 头文件的功能。

**1. 功能列举：**

这个头文件主要定义了在 V8 JavaScript 引擎的 MIPS64 架构代码生成过程中使用的各种常量、宏和枚举类型。 它的核心功能可以归纳为：

* **架构定义:**
    * 定义了 MIPS64 架构的变体 (`ArchVariants`)，例如 `kMips64r2` 和 `kMips64r6`。
    * 定义了目标机器的字节序 (`Endianness`)，例如 `kLittle` (小端) 和 `kBig` (大端)。
    * 定义了是否使用软浮点 ABI (`IsMipsSoftFloatABI`)。

* **内存访问偏移:**
    * 定义了在不同字节序下访问内存中不同大小的数据时使用的偏移量，例如访问 32 位整数中的最低有效字节 (`kLeastSignificantByteInInt32Offset`) 或 64 位双字中的较低有效字 (`kLessSignificantWordInDoublewordOffset`)。这些偏移量对于正确地进行加载和存储操作至关重要。

* **调试和错误处理宏:**
    * 提供了 `UNIMPLEMENTED_MIPS()` 和 `UNSUPPORTED_MIPS()` 宏，用于在代码中标记尚未实现或不支持的 MIPS 指令或功能。这些宏在调试和开发过程中很有用。

* **寄存器定义:**
    * 定义了通用寄存器 (`kNumRegisters`)、浮点寄存器 (`kNumFPURegisters`) 和 MSA (SIMD) 寄存器 (`kNumMSARegisters`) 的数量。
    * 定义了无效寄存器的值 (`kInvalidRegister`, `kInvalidFPURegister`, `kInvalidMSARegister`)。
    * 定义了模拟器中使用的特殊寄存器，例如程序计数器 (`kPCRegister`)。
    * 提供了辅助类 `Registers`, `FPURegisters`, `MSARegisters`，用于在寄存器编号和名称之间进行转换。

* **浮点控制寄存器 (FCSR) 定义:**
    * 定义了浮点控制状态寄存器 (`kFCSRRegister`) 及其相关的位掩码和位移，用于处理浮点异常和舍入模式。

* **MSA (SIMD) 相关定义:**
    * 定义了 MSA 寄存器大小 (`kMSARegSize`)、通道数 (`kMSALanesByte`, `kMSALanesHalf`, 等) 以及相关的寄存器和数据类型枚举 (`MSASize`, `MSADataType`)。

* **指令编码常量:**
    * 定义了 MIPS 指令的固定长度 (`Instr`)，以及指令中各个字段的位移和位数，例如操作码 (`kOpcodeShift`, `kOpcodeBits`)、寄存器字段 (`kRsShift`, `kRtShift`, `kRdBits`) 和立即数字段 (`kImm16Shift`, `kImm16Bits`)。
    * 定义了各种指令类型的操作码和功能码，例如算术运算 (`ADDI`, `DADDI`)、加载存储 (`LW`, `SW`)、分支跳转 (`J`, `BEQ`) 和浮点运算指令 (`ADD_S`, `MUL_D`)。这些常量是 V8 代码生成器将高级代码转换为机器码的基础。

* **其他常量:**
    * 定义了软件中断代码 (`SoftwareInterruptCodes`)。
    * 定义了断点相关的代码范围 (`kMaxWatchpointCode`, `kMaxStopCode`)。
    * 定义了 `pref` 指令的 hints，用于预取数据到缓存。
    * 定义了根寄存器的偏移 (`kRootRegisterBias`)。

**2. 关于 `.tq` 结尾：**

你说得对。如果 `v8/src/codegen/mips64/constants-mips64.h` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是一种 V8 特有的类型化的中间语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。 由于该文件以 `.h` 结尾，它是一个标准的 C++ 头文件。

**3. 与 JavaScript 的关系和示例：**

虽然这个头文件本身是用 C++ 编写的，但它直接关系到 V8 如何执行 JavaScript 代码。 V8 需要将 JavaScript 代码编译成目标机器（在本例中为 MIPS64）的机器码才能执行。 `constants-mips64.h` 中定义的常量正是代码生成器在生成这些机器码时所使用的。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 编译 `add` 函数时，它需要生成 MIPS64 指令来执行加法操作。 这时，`constants-mips64.h` 中定义的常量就会被用到：

* **寄存器分配:** V8 会选择 MIPS64 的通用寄存器来存储变量 `a` 和 `b` 的值。`kNumRegisters` 定义了可用寄存器的数量，而 `Registers` 类可以帮助将抽象的寄存器概念映射到具体的物理寄存器。
* **加法指令:** V8 会生成 MIPS64 的加法指令，例如 `ADD` 或 `DADDU`（取决于数据类型）。  `SPECIAL` 常量和 `SecondaryField::ADD` 或 `SecondaryField::DADD` 定义了这些指令的操作码和功能码。
* **立即数:** 如果加数是常量，例如 `add(x, 5)`，则 `ADDI` 指令及其相关的 `kOpcodeShift` 和 `kImm16Shift` 等常量会用于编码包含立即数的指令。
* **内存访问:** 如果 `a` 或 `b` 是对象属性，则需要生成加载指令，例如 `LW` 或 `LD`。 `kOpcodeShift` 和其他相关的常量会用于编码这些指令，而字节序相关的偏移量 (`kMipsLwrOffset` 等) 确保从正确的内存位置加载数据。

**4. 代码逻辑推理和示例：**

`constants-mips64.h` 中最明显的代码逻辑与字节序有关。  根据目标机器是小端还是大端，某些常量的值会有所不同。

**假设输入：**

* 编译 V8 时定义了 `V8_TARGET_LITTLE_ENDIAN`。

**输出：**

```c++
const uint32_t kMipsLwrOffset = 0;
const uint32_t kMipsLwlOffset = 3;
// ... 其他小端相关的定义
```

**假设输入：**

* 编译 V8 时定义了 `V8_TARGET_BIG_ENDIAN`。

**输出：**

```c++
const uint32_t kMipsLwrOffset = 3;
const uint32_t kMipsLwlOffset = 0;
// ... 其他大端相关的定义
```

这里的逻辑是，对于小端系统，一个字（word）的最低有效字节位于地址的最低位（偏移为 0），而最高有效字节位于地址的最高位。对于大端系统，则正好相反。 `kMipsLwrOffset` 和 `kMipsLwlOffset` 等常量用于在进行部分字加载/存储操作时，指定需要访问的字节的偏移量。

**5. 用户常见的编程错误和示例：**

虽然普通 JavaScript 开发者不会直接修改这个头文件，但理解其中的概念有助于理解一些与性能相关的底层问题。 如果 V8 的代码生成器在生成 MIPS64 代码时使用了错误的常量（例如，错误的字节序偏移），则会导致程序行为异常。

**常见的编程错误（在假设 V8 开发者修改此文件的情况下）：**

* **错误的寄存器编号:**  如果开发者在生成代码时错误地使用了寄存器编号，例如使用了超出 `kNumRegisters` 范围的编号，会导致程序崩溃或产生不可预测的结果。

   ```c++
   // 错误的假设，MIPS64 不止 16 个通用寄存器
   const int kNumRegisters = 16;
   ```

* **指令编码错误:**  如果错误地定义了指令操作码或字段的位移和位数，会导致生成的机器码无效，从而导致程序崩溃或产生错误的结果。

   ```c++
   // 错误地定义了 ADDI 指令的操作码
   constexpr Opcode ADDI = ((1U << 3) + 8) << kOpcodeShift;
   ```

* **字节序处理错误:** 如果在处理内存访问时，没有正确考虑目标机器的字节序，可能会导致加载和存储的数据不正确。

   ```c++
   // 假设总是小端，忽略大端情况
   const uint32_t kMipsLwrOffset = 0;
   ```

这些错误通常会在 V8 的测试和验证过程中被发现，但了解这些底层的概念可以帮助理解 V8 内部的复杂性。

**归纳一下它的功能 (第 1 部分)：**

总而言之，`v8/src/codegen/mips64/constants-mips64.h` 是 V8 引擎中至关重要的一个头文件。 它为 MIPS64 架构的代码生成过程提供了基础性的定义，包括架构变体、字节序、寄存器定义、指令编码以及浮点和 SIMD 相关的常量。 这些常量确保了 V8 能够为 MIPS64 架构生成正确且高效的机器码，从而可靠地执行 JavaScript 代码。 它的核心作用是为 V8 的代码生成器提供关于目标硬件的必要信息。

### 提示词
```
这是目录为v8/src/codegen/mips64/constants-mips64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/constants-mips64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_MIPS64_CONSTANTS_MIPS64_H_
#define V8_CODEGEN_MIPS64_CONSTANTS_MIPS64_H_

#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/common/code-memory-access.h"
#include "src/common/globals.h"

// UNIMPLEMENTED_ macro for MIPS.
#ifdef DEBUG
#define UNIMPLEMENTED_MIPS()                                               \
  v8::internal::PrintF("%s, \tline %d: \tfunction %s not implemented. \n", \
                       __FILE__, __LINE__, __func__)
#else
#define UNIMPLEMENTED_MIPS()
#endif

#define UNSUPPORTED_MIPS() v8::internal::PrintF("Unsupported instruction.\n")

enum ArchVariants { kMips64r2, kMips64r6 };

#ifdef _MIPS_ARCH_MIPS64R2
static const ArchVariants kArchVariant = kMips64r2;
#elif _MIPS_ARCH_MIPS64R6
static const ArchVariants kArchVariant = kMips64r6;
#else
static const ArchVariants kArchVariant = kMips64r2;
#endif

enum Endianness { kLittle, kBig };

#if defined(V8_TARGET_LITTLE_ENDIAN)
static const Endianness kArchEndian = kLittle;
#elif defined(V8_TARGET_BIG_ENDIAN)
static const Endianness kArchEndian = kBig;
#else
#error Unknown endianness
#endif

// TODO(plind): consider renaming these ...
#if defined(__mips_hard_float) && __mips_hard_float != 0
// Use floating-point coprocessor instructions. This flag is raised when
// -mhard-float is passed to the compiler.
const bool IsMipsSoftFloatABI = false;
#elif defined(__mips_soft_float) && __mips_soft_float != 0
// This flag is raised when -msoft-float is passed to the compiler.
// Although FPU is a base requirement for v8, soft-float ABI is used
// on soft-float systems with FPU kernel emulation.
const bool IsMipsSoftFloatABI = true;
#else
const bool IsMipsSoftFloatABI = true;
#endif

#if defined(V8_TARGET_LITTLE_ENDIAN)
const uint32_t kMipsLwrOffset = 0;
const uint32_t kMipsLwlOffset = 3;
const uint32_t kMipsSwrOffset = 0;
const uint32_t kMipsSwlOffset = 3;
const uint32_t kMipsLdrOffset = 0;
const uint32_t kMipsLdlOffset = 7;
const uint32_t kMipsSdrOffset = 0;
const uint32_t kMipsSdlOffset = 7;
#elif defined(V8_TARGET_BIG_ENDIAN)
const uint32_t kMipsLwrOffset = 3;
const uint32_t kMipsLwlOffset = 0;
const uint32_t kMipsSwrOffset = 3;
const uint32_t kMipsSwlOffset = 0;
const uint32_t kMipsLdrOffset = 7;
const uint32_t kMipsLdlOffset = 0;
const uint32_t kMipsSdrOffset = 7;
const uint32_t kMipsSdlOffset = 0;
#else
#error Unknown endianness
#endif

#if defined(V8_TARGET_LITTLE_ENDIAN)
const uint32_t kLeastSignificantByteInInt32Offset = 0;
const uint32_t kLessSignificantWordInDoublewordOffset = 0;
#elif defined(V8_TARGET_BIG_ENDIAN)
const uint32_t kLeastSignificantByteInInt32Offset = 3;
const uint32_t kLessSignificantWordInDoublewordOffset = 4;
#else
#error Unknown endianness
#endif

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

// Defines constants and accessor classes to assemble, disassemble and
// simulate MIPS32 instructions.
//
// See: MIPS32 Architecture For Programmers
//      Volume II: The MIPS32 Instruction Set
// Try www.cs.cornell.edu/courses/cs3410/2008fa/MIPS_Vol2.pdf.

namespace v8 {
namespace internal {

// TODO(sigurds): Change this value once we use relative jumps.
constexpr size_t kMaxPCRelativeCodeRangeInMB = 0;

// -----------------------------------------------------------------------------
// Registers and FPURegisters.

// Number of general purpose registers.
const int kNumRegisters = 32;
const int kInvalidRegister = -1;

// Number of registers with HI, LO, and pc.
const int kNumSimuRegisters = 35;

// In the simulator, the PC register is simulated as the 34th register.
const int kPCRegister = 34;

// Number coprocessor registers.
const int kNumFPURegisters = 32;
const int kInvalidFPURegister = -1;

// Number of MSA registers
const int kNumMSARegisters = 32;
const int kInvalidMSARegister = -1;

const int kInvalidMSAControlRegister = -1;
const int kMSAIRRegister = 0;
const int kMSACSRRegister = 1;
const int kMSARegSize = 128;
const int kMSALanesByte = kMSARegSize / 8;
const int kMSALanesHalf = kMSARegSize / 16;
const int kMSALanesWord = kMSARegSize / 32;
const int kMSALanesDword = kMSARegSize / 64;

// FPU (coprocessor 1) control registers. Currently only FCSR is implemented.
const int kFCSRRegister = 31;
const int kInvalidFPUControlRegister = -1;
const uint32_t kFPUInvalidResult = static_cast<uint32_t>(1u << 31) - 1;
const int32_t kFPUInvalidResultNegative = static_cast<int32_t>(1u << 31);
const uint64_t kFPU64InvalidResult =
    static_cast<uint64_t>(static_cast<uint64_t>(1) << 63) - 1;
const int64_t kFPU64InvalidResultNegative =
    static_cast<int64_t>(static_cast<uint64_t>(1) << 63);

// FCSR constants.
const uint32_t kFCSRInexactFlagBit = 2;
const uint32_t kFCSRUnderflowFlagBit = 3;
const uint32_t kFCSROverflowFlagBit = 4;
const uint32_t kFCSRDivideByZeroFlagBit = 5;
const uint32_t kFCSRInvalidOpFlagBit = 6;
const uint32_t kFCSRNaN2008FlagBit = 18;

const uint32_t kFCSRInexactFlagMask = 1 << kFCSRInexactFlagBit;
const uint32_t kFCSRUnderflowFlagMask = 1 << kFCSRUnderflowFlagBit;
const uint32_t kFCSROverflowFlagMask = 1 << kFCSROverflowFlagBit;
const uint32_t kFCSRDivideByZeroFlagMask = 1 << kFCSRDivideByZeroFlagBit;
const uint32_t kFCSRInvalidOpFlagMask = 1 << kFCSRInvalidOpFlagBit;
const uint32_t kFCSRNaN2008FlagMask = 1 << kFCSRNaN2008FlagBit;

const uint32_t kFCSRFlagMask =
    kFCSRInexactFlagMask | kFCSRUnderflowFlagMask | kFCSROverflowFlagMask |
    kFCSRDivideByZeroFlagMask | kFCSRInvalidOpFlagMask;

const uint32_t kFCSRExceptionFlagMask = kFCSRFlagMask ^ kFCSRInexactFlagMask;

const uint32_t kFCSRInexactCauseBit = 12;
const uint32_t kFCSRUnderflowCauseBit = 13;
const uint32_t kFCSROverflowCauseBit = 14;
const uint32_t kFCSRDivideByZeroCauseBit = 15;
const uint32_t kFCSRInvalidOpCauseBit = 16;
const uint32_t kFCSRUnimplementedOpCauseBit = 17;

const uint32_t kFCSRInexactCauseMask = 1 << kFCSRInexactCauseBit;
const uint32_t kFCSRUnderflowCauseMask = 1 << kFCSRUnderflowCauseBit;
const uint32_t kFCSROverflowCauseMask = 1 << kFCSROverflowCauseBit;
const uint32_t kFCSRDivideByZeroCauseMask = 1 << kFCSRDivideByZeroCauseBit;
const uint32_t kFCSRInvalidOpCauseMask = 1 << kFCSRInvalidOpCauseBit;
const uint32_t kFCSRUnimplementedOpCauseMask = 1
                                               << kFCSRUnimplementedOpCauseBit;

const uint32_t kFCSRCauseMask =
    kFCSRInexactCauseMask | kFCSRUnderflowCauseMask | kFCSROverflowCauseMask |
    kFCSRDivideByZeroCauseMask | kFCSRInvalidOpCauseMask |
    kFCSRUnimplementedOpCauseBit;

// 'pref' instruction hints
const int32_t kPrefHintLoad = 0;
const int32_t kPrefHintStore = 1;
const int32_t kPrefHintLoadStreamed = 4;
const int32_t kPrefHintStoreStreamed = 5;
const int32_t kPrefHintLoadRetained = 6;
const int32_t kPrefHintStoreRetained = 7;
const int32_t kPrefHintWritebackInvalidate = 25;
const int32_t kPrefHintPrepareForStore = 30;

// Actual value of root register is offset from the root array's start
// to take advantage of negative displacement values.
constexpr int kRootRegisterBias = 256;

// Helper functions for converting between register numbers and names.
class Registers {
 public:
  // Return the name of the register.
  static const char* Name(int reg);

  // Lookup the register number for the name provided.
  static int Number(const char* name);

  struct RegisterAlias {
    int reg;
    const char* name;
  };

  static const int64_t kMaxValue = 0x7fffffffffffffffl;
  static const int64_t kMinValue = 0x8000000000000000l;

 private:
  static const char* names_[kNumSimuRegisters];
  static const RegisterAlias aliases_[];
};

// Helper functions for converting between register numbers and names.
class FPURegisters {
 public:
  // Return the name of the register.
  static const char* Name(int reg);

  // Lookup the register number for the name provided.
  static int Number(const char* name);

  struct RegisterAlias {
    int creg;
    const char* name;
  };

 private:
  static const char* names_[kNumFPURegisters];
  static const RegisterAlias aliases_[];
};

// Helper functions for converting between register numbers and names.
class MSARegisters {
 public:
  // Return the name of the register.
  static const char* Name(int reg);

  // Lookup the register number for the name provided.
  static int Number(const char* name);

  struct RegisterAlias {
    int creg;
    const char* name;
  };

 private:
  static const char* names_[kNumMSARegisters];
  static const RegisterAlias aliases_[];
};

// MSA sizes.
enum MSASize { MSA_B = 0x0, MSA_H = 0x1, MSA_W = 0x2, MSA_D = 0x3 };

// MSA data type, top bit set for unsigned data types.
enum MSADataType {
  MSAS8 = 0,
  MSAS16 = 1,
  MSAS32 = 2,
  MSAS64 = 3,
  MSAU8 = 4,
  MSAU16 = 5,
  MSAU32 = 6,
  MSAU64 = 7
};

// -----------------------------------------------------------------------------
// Instructions encoding constants.

// On MIPS all instructions are 32 bits.
using Instr = int32_t;

// Special Software Interrupt codes when used in the presence of the MIPS
// simulator.
enum SoftwareInterruptCodes {
  // Transition to C code.
  call_rt_redirected = 0xfffff
};

// On MIPS Simulator breakpoints can have different codes:
// - Breaks between 0 and kMaxWatchpointCode are treated as simple watchpoints,
//   the simulator will run through them and print the registers.
// - Breaks between kMaxWatchpointCode and kMaxStopCode are treated as stop()
//   instructions (see Assembler::stop()).
// - Breaks larger than kMaxStopCode are simple breaks, dropping you into the
//   debugger.
const uint32_t kMaxWatchpointCode = 31;
const uint32_t kMaxStopCode = 127;
static_assert(kMaxWatchpointCode < kMaxStopCode);

// ----- Fields offset and length.
const int kOpcodeShift = 26;
const int kOpcodeBits = 6;
const int kRsShift = 21;
const int kRsBits = 5;
const int kRtShift = 16;
const int kRtBits = 5;
const int kRdShift = 11;
const int kRdBits = 5;
const int kSaShift = 6;
const int kSaBits = 5;
const int kLsaSaBits = 2;
const int kFunctionShift = 0;
const int kFunctionBits = 6;
const int kLuiShift = 16;
const int kBp2Shift = 6;
const int kBp2Bits = 2;
const int kBp3Shift = 6;
const int kBp3Bits = 3;
const int kBaseShift = 21;
const int kBaseBits = 5;
const int kBit6Shift = 6;
const int kBit6Bits = 1;

const int kImm9Shift = 7;
const int kImm9Bits = 9;
const int kImm16Shift = 0;
const int kImm16Bits = 16;
const int kImm18Shift = 0;
const int kImm18Bits = 18;
const int kImm19Shift = 0;
const int kImm19Bits = 19;
const int kImm21Shift = 0;
const int kImm21Bits = 21;
const int kImm26Shift = 0;
const int kImm26Bits = 26;
const int kImm28Shift = 0;
const int kImm28Bits = 28;
const int kImm32Shift = 0;
const int kImm32Bits = 32;
const int kMsaImm8Shift = 16;
const int kMsaImm8Bits = 8;
const int kMsaImm5Shift = 16;
const int kMsaImm5Bits = 5;
const int kMsaImm10Shift = 11;
const int kMsaImm10Bits = 10;
const int kMsaImmMI10Shift = 16;
const int kMsaImmMI10Bits = 10;

// In branches and jumps immediate fields point to words, not bytes,
// and are therefore shifted by 2.
const int kImmFieldShift = 2;

const int kFrBits = 5;
const int kFrShift = 21;
const int kFsShift = 11;
const int kFsBits = 5;
const int kFtShift = 16;
const int kFtBits = 5;
const int kFdShift = 6;
const int kFdBits = 5;
const int kFCccShift = 8;
const int kFCccBits = 3;
const int kFBccShift = 18;
const int kFBccBits = 3;
const int kFBtrueShift = 16;
const int kFBtrueBits = 1;
const int kWtBits = 5;
const int kWtShift = 16;
const int kWsBits = 5;
const int kWsShift = 11;
const int kWdBits = 5;
const int kWdShift = 6;

// ----- Miscellaneous useful masks.
// Instruction bit masks.
const int kOpcodeMask = ((1 << kOpcodeBits) - 1) << kOpcodeShift;
const int kImm9Mask = ((1 << kImm9Bits) - 1) << kImm9Shift;
const int kImm16Mask = ((1 << kImm16Bits) - 1) << kImm16Shift;
const int kImm18Mask = ((1 << kImm18Bits) - 1) << kImm18Shift;
const int kImm19Mask = ((1 << kImm19Bits) - 1) << kImm19Shift;
const int kImm21Mask = ((1 << kImm21Bits) - 1) << kImm21Shift;
const int kImm26Mask = ((1 << kImm26Bits) - 1) << kImm26Shift;
const int kImm28Mask = ((1 << kImm28Bits) - 1) << kImm28Shift;
const int kImm5Mask = ((1 << 5) - 1);
const int kImm8Mask = ((1 << 8) - 1);
const int kImm10Mask = ((1 << 10) - 1);
const int kMsaI5I10Mask = ((7U << 23) | ((1 << 6) - 1));
const int kMsaI8Mask = ((3U << 24) | ((1 << 6) - 1));
const int kMsaI5Mask = ((7U << 23) | ((1 << 6) - 1));
const int kMsaMI10Mask = (15U << 2);
const int kMsaBITMask = ((7U << 23) | ((1 << 6) - 1));
const int kMsaELMMask = (15U << 22);
const int kMsaLongerELMMask = kMsaELMMask | (63U << 16);
const int kMsa3RMask = ((7U << 23) | ((1 << 6) - 1));
const int kMsa3RFMask = ((15U << 22) | ((1 << 6) - 1));
const int kMsaVECMask = (23U << 21);
const int kMsa2RMask = (7U << 18);
const int kMsa2RFMask = (15U << 17);
const int kRsFieldMask = ((1 << kRsBits) - 1) << kRsShift;
const int kRtFieldMask = ((1 << kRtBits) - 1) << kRtShift;
const int kRdFieldMask = ((1 << kRdBits) - 1) << kRdShift;
const int kSaFieldMask = ((1 << kSaBits) - 1) << kSaShift;
const int kFunctionFieldMask = ((1 << kFunctionBits) - 1) << kFunctionShift;
// Misc masks.
const int kHiMaskOf32 = 0xffff << 16;  // Only to be used with 32-bit values
const int kLoMaskOf32 = 0xffff;
const int kSignMaskOf32 = 0x80000000;  // Only to be used with 32-bit values
const int kJumpAddrMask = (1 << (kImm26Bits + kImmFieldShift)) - 1;
const int64_t kTop16MaskOf64 = (int64_t)0xffff << 48;
const int64_t kHigher16MaskOf64 = (int64_t)0xffff << 32;
const int64_t kUpper16MaskOf64 = (int64_t)0xffff << 16;
const int32_t kJalRawMark = 0x00000000;
const int32_t kJRawMark = 0xf0000000;
const int32_t kJumpRawMask = 0xf0000000;

// ----- MIPS Opcodes and Function Fields.
// We use this presentation to stay close to the table representation in
// MIPS32 Architecture For Programmers, Volume II: The MIPS32 Instruction Set.
using Opcode = uint32_t;
constexpr Opcode SPECIAL = 0U << kOpcodeShift;
constexpr Opcode REGIMM = 1U << kOpcodeShift;

constexpr Opcode J = ((0U << 3) + 2) << kOpcodeShift;
constexpr Opcode JAL = ((0U << 3) + 3) << kOpcodeShift;
constexpr Opcode BEQ = ((0U << 3) + 4) << kOpcodeShift;
constexpr Opcode BNE = ((0U << 3) + 5) << kOpcodeShift;
constexpr Opcode BLEZ = ((0U << 3) + 6) << kOpcodeShift;
constexpr Opcode BGTZ = ((0U << 3) + 7) << kOpcodeShift;

constexpr Opcode ADDI = ((1U << 3) + 0) << kOpcodeShift;
constexpr Opcode ADDIU = ((1U << 3) + 1) << kOpcodeShift;
constexpr Opcode SLTI = ((1U << 3) + 2) << kOpcodeShift;
constexpr Opcode SLTIU = ((1U << 3) + 3) << kOpcodeShift;
constexpr Opcode ANDI = ((1U << 3) + 4) << kOpcodeShift;
constexpr Opcode ORI = ((1U << 3) + 5) << kOpcodeShift;
constexpr Opcode XORI = ((1U << 3) + 6) << kOpcodeShift;
constexpr Opcode LUI = ((1U << 3) + 7) << kOpcodeShift;  // LUI/AUI family.
constexpr Opcode DAUI = ((3U << 3) + 5) << kOpcodeShift;

constexpr Opcode BEQC = ((2U << 3) + 0) << kOpcodeShift;
constexpr Opcode COP1 = ((2U << 3) + 1)
                        << kOpcodeShift;  // Coprocessor 1 class.
constexpr Opcode BEQL = ((2U << 3) + 4) << kOpcodeShift;
constexpr Opcode BNEL = ((2U << 3) + 5) << kOpcodeShift;
constexpr Opcode BLEZL = ((2U << 3) + 6) << kOpcodeShift;
constexpr Opcode BGTZL = ((2U << 3) + 7) << kOpcodeShift;

constexpr Opcode DADDI = ((3U << 3) + 0) << kOpcodeShift;  // This is also BNEC.
constexpr Opcode DADDIU = ((3U << 3) + 1) << kOpcodeShift;
constexpr Opcode LDL = ((3U << 3) + 2) << kOpcodeShift;
constexpr Opcode LDR = ((3U << 3) + 3) << kOpcodeShift;
constexpr Opcode SPECIAL2 = ((3U << 3) + 4) << kOpcodeShift;
constexpr Opcode MSA = ((3U << 3) + 6) << kOpcodeShift;
constexpr Opcode SPECIAL3 = ((3U << 3) + 7) << kOpcodeShift;

constexpr Opcode LB = ((4U << 3) + 0) << kOpcodeShift;
constexpr Opcode LH = ((4U << 3) + 1) << kOpcodeShift;
constexpr Opcode LWL = ((4U << 3) + 2) << kOpcodeShift;
constexpr Opcode LW = ((4U << 3) + 3) << kOpcodeShift;
constexpr Opcode LBU = ((4U << 3) + 4) << kOpcodeShift;
constexpr Opcode LHU = ((4U << 3) + 5) << kOpcodeShift;
constexpr Opcode LWR = ((4U << 3) + 6) << kOpcodeShift;
constexpr Opcode LWU = ((4U << 3) + 7) << kOpcodeShift;

constexpr Opcode SB = ((5U << 3) + 0) << kOpcodeShift;
constexpr Opcode SH = ((5U << 3) + 1) << kOpcodeShift;
constexpr Opcode SWL = ((5U << 3) + 2) << kOpcodeShift;
constexpr Opcode SW = ((5U << 3) + 3) << kOpcodeShift;
constexpr Opcode SDL = ((5U << 3) + 4) << kOpcodeShift;
constexpr Opcode SDR = ((5U << 3) + 5) << kOpcodeShift;
constexpr Opcode SWR = ((5U << 3) + 6) << kOpcodeShift;

constexpr Opcode LL = ((6U << 3) + 0) << kOpcodeShift;
constexpr Opcode LWC1 = ((6U << 3) + 1) << kOpcodeShift;
constexpr Opcode BC = ((6U << 3) + 2) << kOpcodeShift;
constexpr Opcode LLD = ((6U << 3) + 4) << kOpcodeShift;
constexpr Opcode LDC1 = ((6U << 3) + 5) << kOpcodeShift;
constexpr Opcode POP66 = ((6U << 3) + 6) << kOpcodeShift;
constexpr Opcode LD = ((6U << 3) + 7) << kOpcodeShift;

constexpr Opcode PREF = ((6U << 3) + 3) << kOpcodeShift;

constexpr Opcode SC = ((7U << 3) + 0) << kOpcodeShift;
constexpr Opcode SWC1 = ((7U << 3) + 1) << kOpcodeShift;
constexpr Opcode BALC = ((7U << 3) + 2) << kOpcodeShift;
constexpr Opcode PCREL = ((7U << 3) + 3) << kOpcodeShift;
constexpr Opcode SCD = ((7U << 3) + 4) << kOpcodeShift;
constexpr Opcode SDC1 = ((7U << 3) + 5) << kOpcodeShift;
constexpr Opcode POP76 = ((7U << 3) + 6) << kOpcodeShift;
constexpr Opcode SD = ((7U << 3) + 7) << kOpcodeShift;

constexpr Opcode COP1X = ((1U << 4) + 3) << kOpcodeShift;

// New r6 instruction.
constexpr Opcode POP06 = BLEZ;   // bgeuc/bleuc, blezalc, bgezalc
constexpr Opcode POP07 = BGTZ;   // bltuc/bgtuc, bgtzalc, bltzalc
constexpr Opcode POP10 = ADDI;   // beqzalc, bovc, beqc
constexpr Opcode POP26 = BLEZL;  // bgezc, blezc, bgec/blec
constexpr Opcode POP27 = BGTZL;  // bgtzc, bltzc, bltc/bgtc
constexpr Opcode POP30 = DADDI;  // bnezalc, bnvc, bnec

enum SecondaryField : uint32_t {
  // SPECIAL Encoding of Function Field.
  SLL = ((0U << 3) + 0),
  MOVCI = ((0U << 3) + 1),
  SRL = ((0U << 3) + 2),
  SRA = ((0U << 3) + 3),
  SLLV = ((0U << 3) + 4),
  LSA = ((0U << 3) + 5),
  SRLV = ((0U << 3) + 6),
  SRAV = ((0U << 3) + 7),

  JR = ((1U << 3) + 0),
  JALR = ((1U << 3) + 1),
  MOVZ = ((1U << 3) + 2),
  MOVN = ((1U << 3) + 3),
  BREAK = ((1U << 3) + 5),
  SYNC = ((1U << 3) + 7),

  MFHI = ((2U << 3) + 0),
  CLZ_R6 = ((2U << 3) + 0),
  CLO_R6 = ((2U << 3) + 1),
  MFLO = ((2U << 3) + 2),
  DCLZ_R6 = ((2U << 3) + 2),
  DCLO_R6 = ((2U << 3) + 3),
  DSLLV = ((2U << 3) + 4),
  DLSA = ((2U << 3) + 5),
  DSRLV = ((2U << 3) + 6),
  DSRAV = ((2U << 3) + 7),

  MULT = ((3U << 3) + 0),
  MULTU = ((3U << 3) + 1),
  DIV = ((3U << 3) + 2),
  DIVU = ((3U << 3) + 3),
  DMULT = ((3U << 3) + 4),
  DMULTU = ((3U << 3) + 5),
  DDIV = ((3U << 3) + 6),
  DDIVU = ((3U << 3) + 7),

  ADD = ((4U << 3) + 0),
  ADDU = ((4U << 3) + 1),
  SUB = ((4U << 3) + 2),
  SUBU = ((4U << 3) + 3),
  AND = ((4U << 3) + 4),
  OR = ((4U << 3) + 5),
  XOR = ((4U << 3) + 6),
  NOR = ((4U << 3) + 7),

  SLT = ((5U << 3) + 2),
  SLTU = ((5U << 3) + 3),
  DADD = ((5U << 3) + 4),
  DADDU = ((5U << 3) + 5),
  DSUB = ((5U << 3) + 6),
  DSUBU = ((5U << 3) + 7),

  TGE = ((6U << 3) + 0),
  TGEU = ((6U << 3) + 1),
  TLT = ((6U << 3) + 2),
  TLTU = ((6U << 3) + 3),
  TEQ = ((6U << 3) + 4),
  SELEQZ_S = ((6U << 3) + 5),
  TNE = ((6U << 3) + 6),
  SELNEZ_S = ((6U << 3) + 7),

  DSLL = ((7U << 3) + 0),
  DSRL = ((7U << 3) + 2),
  DSRA = ((7U << 3) + 3),
  DSLL32 = ((7U << 3) + 4),
  DSRL32 = ((7U << 3) + 6),
  DSRA32 = ((7U << 3) + 7),

  // Multiply integers in r6.
  MUL_MUH = ((3U << 3) + 0),      // MUL, MUH.
  MUL_MUH_U = ((3U << 3) + 1),    // MUL_U, MUH_U.
  D_MUL_MUH = ((7U << 2) + 0),    // DMUL, DMUH.
  D_MUL_MUH_U = ((7U << 2) + 1),  // DMUL_U, DMUH_U.
  RINT = ((3U << 3) + 2),

  MUL_OP = ((0U << 3) + 2),
  MUH_OP = ((0U << 3) + 3),
  DIV_OP = ((0U << 3) + 2),
  MOD_OP = ((0U << 3) + 3),

  DIV_MOD = ((3U << 3) + 2),
  DIV_MOD_U = ((3U << 3) + 3),
  D_DIV_MOD = ((3U << 3) + 6),
  D_DIV_MOD_U = ((3U << 3) + 7),

  // drotr in special4?

  // SPECIAL2 Encoding of Function Field.
  MUL = ((0U << 3) + 2),
  CLZ = ((4U << 3) + 0),
  CLO = ((4U << 3) + 1),
  DCLZ = ((4U << 3) + 4),
  DCLO = ((4U << 3) + 5),

  // SPECIAL3 Encoding of Function Field.
  EXT = ((0U << 3) + 0),
  DEXTM = ((0U << 3) + 1),
  DEXTU = ((0U << 3) + 2),
  DEXT = ((0U << 3) + 3),
  INS = ((0U << 3) + 4),
  DINSM = ((0U << 3) + 5),
  DINSU = ((0U << 3) + 6),
  DINS = ((0U << 3) + 7),

  BSHFL = ((4U << 3) + 0),
  DBSHFL = ((4U << 3) + 4),
  SC_R6 = ((4U << 3) + 6),
  SCD_R6 = ((4U << 3) + 7),
  LL_R6 = ((6U << 3) + 6),
  LLD_R6 = ((6U << 3) + 7),

  // SPECIAL3 Encoding of sa Field.
  BITSWAP = ((0U << 3) + 0),
  ALIGN = ((0U << 3) + 2),
  WSBH = ((0U << 3) + 2),
  SEB = ((2U << 3) + 0),
  SEH = ((3U << 3) + 0),

  DBITSWAP = ((0U << 3) + 0),
  DALIGN = ((0U << 3) + 1),
  DBITSWAP_SA = ((0U << 3) + 0) << kSaShift,
  DSBH = ((0U << 3) + 2),
  DSHD = ((0U << 3) + 5),

  // REGIMM  encoding of rt Field.
  BLTZ = ((0U << 3) + 0) << 16,
  BGEZ = ((0U << 3) + 1) << 16,
  BLTZAL = ((2U << 3) + 0) << 16,
  BGEZAL = ((2U << 3) + 1) << 16,
  BGEZALL = ((2U << 3) + 3) << 16,
  DAHI = ((0U << 3) + 6) << 16,
  DATI = ((3U << 3) + 6) << 16,

  // COP1 Encoding of rs Field.
  MFC1 = ((0U << 3) + 0) << 21,
  DMFC1 = ((0U << 3) + 1) << 21,
  CFC1 = ((0U << 3) + 2) << 21,
  MFHC1 = ((0U << 3) + 3) << 21,
  MTC1 = ((0U << 3) + 4) << 21,
  DMTC1 = ((0U << 3) + 5) << 21,
  CTC1 = ((0U << 3) + 6) << 21,
  MTHC1 = ((0U << 3) + 7) << 21,
  BC1 = ((1U << 3) + 0) << 21,
  S = ((2U << 3) + 0) << 21,
  D = ((2U << 3) + 1) << 21,
  W = ((2U << 3) + 4) << 21,
  L = ((2U << 3) + 5) << 21,
  PS = ((2U << 3) + 6) << 21,
  // COP1 Encoding of Function Field When rs=S.

  ADD_S = ((0U << 3) + 0),
  SUB_S = ((0U << 3) + 1),
  MUL_S = ((0U << 3) + 2),
  DIV_S = ((0U << 3) + 3),
  ABS_S = ((0U << 3) + 5),
  SQRT_S = ((0U << 3) + 4),
  MOV_S = ((0U << 3) + 6),
  NEG_S = ((0U << 3) + 7),
  ROUND_L_S = ((1U << 3) + 0),
  TRUNC_L_S = ((1U << 3) + 1),
  CEIL_L_S = ((1U << 3) + 2),
  FLOOR_L_S = ((1U << 3) + 3),
  ROUND_W_S = ((1U << 3) + 4),
  TRUNC_W_S = ((1U << 3) + 5),
  CEIL_W_S = ((1U << 3) + 6),
  FLOOR_W_S = ((1U << 3) + 7),
  RECIP_S = ((2U << 3) + 5),
  RSQRT_S = ((2U << 3) + 6),
  MADDF_S = ((3U << 3) + 0),
  MSUBF_S = ((3U << 3) + 1),
  CLASS_S = ((3U << 3) + 3),
  CVT_D_S = ((4U << 3) + 1),
  CVT_W_S = ((4U << 3) + 4),
  CVT_L_S = ((4U << 3) + 5),
  CVT_PS_S = ((4U << 3) + 6),
  // COP1 Encoding of Function Field When rs=D.
  ADD_D = ((0U << 3) + 0),
  SUB_D = ((0U << 3) + 1),
  MUL_D = ((0U << 3) + 2),
  DIV_D = ((0U << 3) + 3),
  SQRT_D = ((0U << 3) + 4),
  ABS_D = ((0U << 3) + 5),
  MOV_D = ((0U << 3) + 6),
  NEG_D = ((0U << 3) + 7),
  ROUND_L_D = ((1U << 3) + 0),
  TRUNC_L_D = ((1U << 3) + 1),
  CEIL_L_D = ((1U << 3) + 2),
  FLOOR_L_D = ((1U << 3) + 3),
  ROUND_W_D = ((1U << 3) + 4),
  TRUNC_W_D = ((1U << 3) + 5),
  CEIL_W_D = ((1U << 3) + 6),
  FLOOR_W_D = ((1U << 3) + 7),
  RECIP_D = ((2U << 3) + 5),
  RSQRT_D = ((2U << 3) + 6),
  MADDF_D = ((3U << 3) + 0),
  MSUBF_D = ((3U << 3) + 1),
  CLASS_D = ((3U << 3) + 3),
  MIN = ((3U << 3) + 4),
  MINA = ((3U << 3) + 5),
  MAX = ((3U << 3) + 6),
  MAXA = ((3U << 3) + 7),
  CVT_S_D = ((4U << 3) + 0),
  CVT_W_D = ((4U << 3) + 4),
  CVT_L_D = ((4U << 3) + 5),
  C_F_D = ((6U << 3) + 0),
  C_UN_D = ((6U << 3) + 1),
  C_EQ_D = ((6U << 3) + 2),
  C_UEQ_D = ((6U << 3) + 3),
  C_OLT_D = ((6U << 3) + 4),
  C_ULT_D = ((6U << 3) + 5),
  C_OLE_D = ((6U << 3) + 6),
  C_ULE_D = ((6U << 3) + 7),

  // COP1 Encoding of Function Field When rs=W or L.
  CVT_S_W = ((4U << 3) + 0),
  CVT_D_W = ((4U << 3) + 1),
  CVT_S_L = ((4U << 3) + 0),
  CVT_D_L = ((4U << 3) + 1),
  BC1EQZ = ((2U << 2) + 1) << 21,
  BC1NEZ = ((3U << 2) + 1) << 21,
  // COP1 CMP positive predicates Bit 5..4 = 00.
  CMP_AF = ((0U << 3) + 0),
  CMP_UN = ((0U << 3) + 1),
  CMP_EQ = ((0U << 3) + 2),
  CMP_UEQ = ((0U << 3) + 3),
  CMP_LT = ((0U << 3) + 4),
  CMP_ULT = ((0U << 3) + 5),
  CMP_LE = ((0U << 3) + 6),
  CMP_ULE = ((0U << 3) + 7),
  CMP_SAF = ((1U << 3) + 0),
  CMP_SUN = ((1U << 3) + 1),
  CMP_SEQ = ((1U << 3) + 2),
  CMP_SUEQ = ((1U << 3) + 3),
  CMP_SSLT = ((1U << 3) + 4),
  CMP_SSULT = ((1U << 3) + 5),
  CMP_SLE = ((1U << 3) + 6),
  CMP_SULE = ((1U << 3) + 7),
  // COP1 CMP negative predicates Bit 5..4 = 01.
  CMP_AT = ((2U << 3) + 0),  // Reserved, not implemented.
  CMP_OR = ((2U << 3) + 1),
  CMP_UNE = ((2U << 3) + 2),
  CMP_NE = ((2U << 3) + 3),
  CMP_UGE = ((2U << 3) + 4),  // Reserved, not implemented.
  CMP_OGE = ((2U << 3) + 5),  // Reserved, not implemented.
  CMP_UGT = ((2U << 3) + 6),  // Reserved, not implemented.
  CMP_OGT = ((2U << 3) + 7),  // Reserved, not implemented.
  CMP_SAT = ((3U << 3) + 0),  // Reserved, not implemented.
  CMP_SOR = ((3U << 3) + 1),
  CMP_SUNE = ((3U << 3) + 2),
  CMP_SNE = ((3U << 3) + 3),
  CMP_SUGE = ((3U << 3) + 4),  // Reserved, not implemented.
  CMP_SOGE = ((3U << 3) + 5),  // Reserved, not implemented.
  CMP_SUGT = ((3U << 3) + 6),  // Reserved, not implemented.
  CMP_SOGT = ((3U << 3) + 7),  // Reserved, not implemented.

  SEL = ((2U << 3) + 0),
  MOVF = ((2U << 3) + 1),      // Function field for MOVT.fmt and MOVF.fmt
  MOVZ_C = ((2U << 3) + 2),    // COP1 on FPR registers.
  MOVN_C = ((2U << 3) + 3),    // COP1 on FPR registers.
  SELEQZ_C = ((2U << 3) + 4),  // COP1 on FPR registers.
  SELNEZ_C = ((2U << 3) + 7),  // COP1 on FPR registers.

  // COP1 Encoding of Function Field When rs=PS.

  // COP1X Encoding of Function Field.
  MADD_S = ((4U << 3) + 0),
  MADD_D = ((4U << 3) + 1),
  MSUB_S = ((5U << 3) + 0),
  MSUB_D = ((5U << 3) + 1),

  // PCREL Encoding of rt Field.
  ADDIUPC = ((0U << 2) + 0),
  LWPC = ((0U << 2) + 1),
  LWUPC = ((0U << 2) + 2),
  LDPC = ((0U << 3) + 6),
  // reserved ((1U << 3) + 6),
  AUIPC = ((3U << 3) + 6),
  ALUIPC = ((3U << 3) + 7),

  // POP66 Encoding of rs Field.
  JIC = ((0U << 5) + 0),

  // POP76 Encoding of rs Field.
  JIALC = ((0U << 5) + 0),

  // COP1 Encoding of rs Field for MSA Branch Instructions
  BZ_V = (((1U << 3) + 3) << kRsShift),
  BNZ_V = (((1U << 3) + 7) << kRsShift),
  BZ_B = (((3U << 3) + 0) << kRsShift),
  BZ_H = (((3U << 3) + 1) << kRsShift),
  BZ_W = (((3U << 3) + 2) << kRsShift),
  BZ_D = (((3U << 3) + 3) << kRsShift),
  BNZ_B = (((3U << 3) + 4) << kRsShift),
  BNZ_H = (((3U << 3) + 5) << kRsShift),
  BNZ_W = (((3U << 3) + 6) << kRsShift),
  BNZ_D = (((3U << 3) + 7) << kRsShift),

  // MSA: Operation Field for MI10 Instruction Formats
  MSA_LD = (8U << 2),
  MSA_ST = (9U << 2),
  LD_B = ((8U << 2) + 0),
  LD_H = ((8U << 2) + 1),
  LD_W = ((8U << 2) + 2),
  LD_D = ((8U << 2) + 3),
  ST_B = ((9U << 2) + 0),
  ST_H = ((9U << 2) + 1),
  ST_W = ((9U << 2) + 2),
  ST_D = ((9U << 2) + 3),

  // MSA: Operation Field for I5 Instruction Format
  ADDVI = ((0U << 23) + 6),
  SUBVI = ((1U << 23) + 6),
  MAXI_S = ((2U << 23) + 6),
  MAXI_U = ((3U << 23) + 6),
  MINI_S = ((4U << 23) + 6),
  MINI_U = ((5U << 23) + 6),
  CEQI = ((0U << 23) + 7),
  CLTI_S = ((2U << 23) + 7),
  CLTI_U = ((3U << 23) + 7),
  CLEI_S = ((4U << 23) + 7),
  CLEI_U = ((5U << 23) + 7),
  LDI = ((6U << 23) + 7),  // I10 instruction format
  I5_DF_b = (0U << 21),
  I5_DF_h = (1U << 21),
  I5_DF_w = (2U << 21),
  I5_DF_d = (3U << 21),

  // MSA: Operation Field for I8 Instruction Format
  ANDI_B = ((0U << 24) + 0),
  ORI_B = ((1U << 24) + 0),
  NORI_B = ((2U << 24) + 0),
  XORI_B = ((3U << 24) + 0),
  BMNZI_B = ((0U << 24) + 1),
  BMZI_B = ((1U << 24) + 1),
  BSELI_B = ((2U << 24) + 1),
  SHF_B = ((0U << 24) + 2),
  SHF_H = ((1U << 24) + 2),
  SHF_W = ((2U << 24) + 2),

  MSA_VEC_2R_2RF_MINOR = ((3U << 3) + 6),

  // MSA: Operation Field for VEC Instruction Formats
  AND_V = (((0U << 2) + 0) << 21),
  OR_V = (((0U << 2) + 1) << 21),
  NOR_V = (((0U << 2) + 2) << 21),
  XOR_V = (((0U << 2) + 3) << 21),
  BMNZ_V = (((1U << 2) + 0) << 21),
  BMZ_V = (((1U << 2) + 1) << 21),
  BSEL_V = (((1U << 2) + 2) << 21),

  // MSA: Operation Field for 2R Instruction Formats
  MSA_2R_FORMAT = (((6U << 2) + 0) << 21),
  FILL = (0U << 18),
  PCNT = (1U << 18),
  NLOC = (2U << 18),
  NLZC = (3U << 18),
  MSA_2R_DF_b = (0U << 16),
  MSA_2R_DF_h = (1U << 16),
  MSA_2R_DF_w = (2U << 16),
  MSA_2R_DF_d = (3U << 16),

  // MSA: Operation Field for 2RF Instruction Formats
  MSA_2RF_FORMAT = (((6U << 2) + 1) << 21),
  FCLASS = (0U << 17),
  FTRUNC_S = (1U << 17),
  FTRUNC_U = (2U << 17),
  FSQRT = (3U << 17),
  FRSQRT = (4U << 17),
  FRCP = (5U << 17),
  FRINT = (6U << 17),
  FLOG2 = (7U << 17),
  FEXUPL = (8U << 17),
  FEXUPR = (9U << 17),
  FFQL = (10U << 17),
  FFQR = (11U << 17),
  FTINT_S = (12U << 17),
  FTINT_U = (13U << 17),
  FFINT_S = (14U << 17),
  FFINT_U = (15U << 17),
  MSA_2RF_DF_w = (0U << 16),
  MSA_2RF_DF_d = (1U << 16),

  // MSA: Operation Field for 3R Instruction Format
  SLL_MSA = ((0U << 23) + 13),
  SRA_MSA = ((1U << 23) + 13),
  SRL_MSA = ((2U << 23) + 13),
  BCLR = ((3U << 23) + 13),
  BSET = ((4U << 23) + 13),
  BNEG = ((5U << 23) + 13),
  BINSL = ((6U << 23) + 13),
  BINSR = ((7U << 23) + 13),
  ADDV = ((0U << 23) + 14),
  SUBV = ((1U << 23) + 14),
  MAX_S = ((2U << 23) + 14),
  MAX_U = ((3U << 23) + 14),
  MIN_S = ((4U << 23) + 14),
  MIN_U = ((5U << 23) + 14),
  MAX_A = ((6U << 23) + 14),
  MIN_A = ((7U << 23) + 14),
  CEQ = ((0U << 23) + 15),
  CLT_S = ((2U << 23) + 15),
  CLT_U = ((3U << 23) + 15),
  CLE_S = ((4U << 23) + 15),
  CLE_U = ((5U << 23) + 15),
  ADD_A = ((0U << 23) + 16),
  ADDS_A = ((1U << 23) + 16),
  ADDS_S = ((2U << 23) + 16),
  ADDS_U = ((3U << 23) + 16),
  AVE_S = ((4U << 23) + 16),
  AVE_U = ((5U << 23) + 16),
  AVER_S = ((6U << 23) + 16),
  AVER_U = ((7U << 23) + 16),
  SUBS_S = ((0U << 23) + 17),
  SUBS_U = ((1U << 23) + 17),
  SUBSUS_U = ((2U << 23) + 17),
  SUBSUU_S = ((3U << 23) + 17),
  ASUB_S = ((4U << 23) + 17),
  ASUB_U = ((5U << 23) + 17),
  MULV = ((0U << 23) + 18),
  MADDV = ((1U << 23) + 18),
  MSUBV = ((2U << 23) + 18),
  DIV_S_MSA = ((4U << 23) + 18),
  DIV_U = ((5U << 23) + 18),
  MOD_S = ((6U << 23) + 18),
  MOD_U = ((7U << 23) + 18),
  DOTP_S = ((0U << 23) + 19),
  DOTP_U = ((1U << 23) + 19),
  DPADD_S = ((2U << 23) + 19),
  DPADD_U = ((3U << 23) + 19),
  DPSUB_S = ((4U << 23) + 19),
  DPSUB_U = ((5U << 23) + 19),
  SLD = ((0U << 23) + 20),
  SPLAT = ((1U << 23) + 20),
  PCKEV = ((2U << 23) + 20),
  PCKOD = ((3U << 23) + 20),
  ILVL = ((4U << 23) + 20),
  ILVR = ((5U << 23) + 20),
  ILVEV = ((6U << 23) + 20),
  ILVOD = ((7U << 23) + 20),
  VSHF = ((0U << 23) + 21),
  SRAR = ((1U << 23) + 21),
  SRLR = ((2U << 23) + 21),
  HADD_S = ((4U << 23) + 21),
  HADD_U = ((5U << 23) + 21),
  HSUB_S = ((6U << 23) + 21),
  HSUB_U = ((7U << 23) + 21),
  MSA_3R_DF_b = (0U << 21),
  MSA_3R_DF_h = (1U << 21),
  MSA_3R_DF_w = (2U << 21),
  MSA_3R_DF_d = (3U << 21),

  // MSA: Operation Field for 3RF Instruction Format
  FCAF = ((0U << 22) + 26),
  FCUN = ((1U << 22) + 26),
  FCEQ = ((2U << 22) + 26),
  FCUEQ = ((3U << 22) + 26),
  FCLT = ((4U << 22) + 26),
  FCULT = ((5U << 22) + 26),
  FCLE = ((6U << 22) + 26),
  FCULE = ((7U << 22) + 26),
  FSAF = ((8U << 22) + 26),
  FSUN = ((9U << 22) + 26),
  FSEQ = ((10U << 22) + 26),
  FSUEQ = ((11U << 22) + 26),
  FSLT = ((12U << 22) + 26),
  FSULT = ((13U << 22) + 26),
  FSLE = ((14U << 22) + 26),
  FSULE = ((15U << 22) + 26),
  FADD = ((0U << 22) + 27),
  FSUB = ((1U << 22) + 27),
  FMUL = ((2U << 22) + 27),
  FDIV = ((3U << 22) + 27),
  FMADD = ((4U << 22) + 27),
  FMSUB = ((5U << 22) + 27),
  FEXP2 = ((7U << 22) + 27),
  FEXDO = ((8U << 22) + 27),
  FTQ = ((10U << 22) + 27),
  FMIN = ((12U << 22) + 27),
  FMIN_A = ((13U << 22) + 27),
  FMAX = ((14U << 22) + 27),
  FMAX_A = ((15U << 22) + 27),
  FCOR = ((1U << 22) + 28),
  FCUNE = ((2U << 22) + 28),
  FCNE = ((3U << 22) + 28),
  MUL_Q = ((4U << 22) + 28),
  MADD_Q = ((5U << 22) + 28),
  MSUB_Q = ((6U << 22) + 28),
  FSOR = ((9U << 22) + 28),
  FSUNE = ((10U << 22) + 28),
  FSNE = ((11U << 22) + 28),
  MULR_Q = ((12U << 22) + 28),
  MADDR_Q = ((13U << 22) + 28),
  MSUBR_Q = ((14U << 22) + 28),

  // MSA: Operation Field for ELM Instruction Format
  MSA_ELM_MINOR = ((3U << 3) + 1),
  SLDI = (0U << 22),
  CTCMSA = ((0U << 22) | (62U << 16)),
  SPLATI = (1U << 22),
  CFCMSA = ((1U << 22) | (62U << 16)),
  COPY_S = (2U << 22),
  MOVE_V = ((2U << 22) | (62U << 16)),
  COPY_U = (3U << 22),
  INSERT = (4U << 22),
  INSVE = (5U << 22),
  ELM_DF_B = ((0U << 4) << 16),
  ELM_DF_H = ((4U << 3) << 16),
  ELM_DF_W = ((12U << 2) << 16),
  ELM_DF_D = ((28U << 1) << 16),

  // MSA: Operation Field for BIT Instruction Format
  SLLI = ((0U << 23) + 9),
  SRAI
```