Response:
The user wants to understand the functionality of the provided C++ header file `v8/src/codegen/arm64/constants-arm64.h`. I need to analyze the content and summarize its purpose.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename suggests it defines constants specific to the ARM64 architecture within the V8 JavaScript engine's code generation module.

2. **Analyze the content:**
    * **Includes:**  Note the included headers (`src/base/macros.h`, `src/common/globals.h`, `<inttypes.h>`). These provide basic definitions and type information.
    * **Static Assertions:** These are crucial for verifying assumptions about the target architecture (LP64/LLP64).
    * **Constants:** The majority of the file consists of `constexpr` definitions. These are likely defining sizes, masks, and other architecture-specific values. I need to categorize these.
    * **Enums:** Identify the enums (`Condition`, `FlagsUpdate`, `StatusFlags`, `Shift`, `Extend`, `SystemHint`, `BranchTargetIdentifier`, `BarrierDomain`, `BarrierType`, `SystemRegister`). These define sets of related symbolic constants.
    * **Macros:** Pay attention to the `INSTRUCTION_FIELDS_LIST` and `SYSTEM_REGISTER_FIELDS_LIST` macros and their usage with `DECLARE_FIELDS_OFFSETS`. This is likely a systematic way of defining bitfield offsets and masks for ARM64 instructions.
    * **Instruction Enumerations:** The large section defining constants like `PCRelAddressingFixed`, `AddSubOpMask`, etc., clearly relates to ARM64 instruction encoding.

3. **Infer functionality based on the content:**
    * **Architecture Properties:**  Constants defining register sizes (WRegSize, XRegSize, etc.), pointer sizes, and bit masks (kWRegMask, kXRegMask, etc.) describe fundamental aspects of the ARM64 architecture.
    * **Instruction Encoding:**  The `INSTRUCTION_FIELDS_LIST`, the `DECLARE_FIELDS_OFFSETS` macros, and the numerous constants related to instruction opcodes (like `PCRelAddressingFixed`, `AddSubOpMask`) indicate this file plays a key role in encoding and decoding ARM64 instructions.
    * **Condition Codes and Flags:** The `Condition` and `StatusFlags` enums are essential for handling conditional execution and the processor's status register.
    * **Memory Access and Addressing:** Constants like `kMaxPCRelativeCodeRangeInMB`, `kAddressTagOffset`, and the definitions related to load/store instructions point to how V8 manages memory on ARM64.
    * **Floating-Point:** The constants related to mantissa and exponent bits for floats and doubles are specific to ARM64's floating-point representation.
    * **NEON Intrinsics:** The presence of `NEON` related constants indicates support for ARM's Advanced SIMD (NEON) instructions.

4. **Address the specific questions:**
    * **.tq extension:** Confirm that if the file ended in `.tq`, it would be a Torque source file.
    * **Relationship to JavaScript:** Explain that these low-level constants are indirectly related to JavaScript as they are used by the V8 engine to execute JavaScript code on ARM64. Provide a simple JavaScript example where the underlying ARM64 instructions would be used (e.g., addition).
    * **Code Logic Inference:**  Provide a simple example of how a constant like `kXRegSize` might be used in V8's code generation logic. Create a hypothetical function and input/output to illustrate this.
    * **Common Programming Errors:** Discuss how incorrect assumptions about sizes or bitfield layouts (which these constants help define correctly) can lead to errors in low-level code.

5. **Summarize the functionality:** Combine the insights into a concise summary of the file's purpose.

**Self-Correction/Refinement:**

* **Initial thought:** Focus heavily on individual constant definitions.
* **Correction:**  Recognize the importance of grouping related constants and identifying the higher-level concepts they represent (e.g., instruction encoding, memory management).
* **Initial thought:** Directly link specific constants to specific JavaScript features.
* **Correction:** Explain the *indirect* relationship – these constants are part of the *implementation* of the JavaScript engine on ARM64.
* **Initial thought:** Provide very complex code examples.
* **Correction:** Keep the JavaScript and hypothetical C++ examples simple and focused on illustrating the *use* of the constants.
`v8/src/codegen/arm64/constants-arm64.h` 是一个 C++ 头文件，它定义了在 V8 JavaScript 引擎中为 ARM64 架构生成代码时使用的各种常量。 这些常量涵盖了架构的多个方面，包括寄存器、指令格式、内存布局和浮点数表示。

**功能归纳:**

这个头文件的主要功能是为 V8 引擎的 ARM64 代码生成器提供一组明确定义的常量。 这些常量用于：

1. **定义 ARM64 架构的属性:**  例如，寄存器的大小 (`kWRegSize`, `kXRegSize`)、寄存器的数量 (`kNumberOfRegisters`)、指令的大小 (`kInstrSize`) 等。
2. **定义指令的编码格式:**  通过 `INSTRUCTION_FIELDS_LIST` 宏和后续的 `DECLARE_FIELDS_OFFSETS`，定义了 ARM64 指令中各个字段（如操作码、寄存器编号、立即数）的位置和掩码。 这对于构建和解析 ARM64 指令至关重要。
3. **定义条件码和标志位的常量:**  `Condition` 枚举定义了各种条件码（例如相等、不相等），`StatusFlags` 枚举定义了状态标志位（例如 N、Z、C、V）。
4. **定义移位和扩展操作的常量:**  `Shift` 和 `Extend` 枚举定义了在 ARM64 指令中使用的各种移位和扩展操作。
5. **定义系统寄存器和相关的常量:**  `SystemRegister` 枚举定义了特殊的系统寄存器，以及用于访问它们的掩码和偏移量。
6. **定义浮点数相关的常量:**  例如，双精度浮点数和单精度浮点数的尾数位数、指数位数和指数偏置。
7. **定义内存访问相关的常量:**  例如，`kMaxPCRelativeCodeRangeInMB` 定义了 PC 相对调用的最大范围。
8. **提供用于识别不同指令类型的常量和掩码:**  例如，`PCRelAddressingFixed`, `AddSubOpMask` 等用于区分不同的 ARM64 指令类型。

**关于文件扩展名和 Torque:**

如果 `v8/src/codegen/arm64/constants-arm64.h` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。 Torque 是一种由 V8 开发的领域特定语言，用于更安全、更易于维护地生成汇编代码。 然而，当前的这个文件以 `.h` 结尾，表明它是一个标准的 C++ 头文件。

**与 JavaScript 功能的关系 (间接):**

`constants-arm64.h` 中定义的常量与 JavaScript 的功能是间接相关的。 V8 引擎负责执行 JavaScript 代码，而为了在 ARM64 架构上执行，V8 需要将 JavaScript 代码编译成 ARM64 的机器码。  这个头文件中的常量就在这个编译过程中被大量使用。 例如：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3);
```

当 V8 执行 `add(5, 3)` 时，它会将 JavaScript 的加法操作编译成对应的 ARM64 指令。  在这个过程中，`constants-arm64.h` 中定义的常量会被用来：

* **选择正确的指令:** 例如，选择 `ADD` 或 `ADDS` 指令来执行加法。
* **编码指令的操作数:**  确定使用哪个寄存器来存储 `a` 和 `b` 的值，并将寄存器编号编码到指令中。 这会用到像 `kRegCodeMask` 这样的常量。
* **进行 PC 相对跳转 (如果需要):**  如果 `add` 函数调用了其他函数，可能会生成 PC 相对跳转指令，这会用到 `kMaxPCRelativeCodeRangeInMB` 等常量。

**代码逻辑推理 (假设):**

**假设输入:** V8 尝试生成一个将两个 32 位整数相加并将结果存储到寄存器 `x0` 的 ARM64 指令。 假设这两个 32 位整数分别存储在寄存器 `w1` 和 `w2` 中。

**代码逻辑 (简化):**  V8 的代码生成器可能会有类似这样的逻辑：

```c++
// 假设 rn_reg 和 rm_reg 分别存储 w1 和 w2 的寄存器编码
int rn_reg = 1;
int rm_reg = 2;
int rd_reg = 0; // x0 的寄存器编码

// 检查是否需要设置标志位 (假设不需要)
bool set_flags = false;

uint32_t instruction = 0;

// 设置指令的基本操作码 (ADD 指令，32 位)
instruction |= ADD; // 从 constants-arm64.h 获取 ADD 的值

// 编码目标寄存器 (Rd)
instruction |= (rd_reg & kRegCodeMask);

// 编码第一个源寄存器 (Rn)
instruction |= ((rn_reg & kRegCodeMask) << Rn_offset);

// 编码第二个源寄存器 (Rm)
instruction |= ((rm_reg & kRegCodeMask) << Rm_offset);

// 如果需要设置标志位
if (set_flags) {
  instruction |= AddSubSetFlagsBit; // 从 constants-arm64.h 获取 AddSubSetFlagsBit
}

// 输出生成的指令
// 输出结果将是一个代表 ARM64 ADD 指令的 32 位整数
```

**假设输出:**  生成的 `instruction` 变量的值将是一个 32 位整数，其二进制表示形式对应于 ARM64 的 `add w0, w1, w2` 指令（或者 `adds` 如果 `set_flags` 为 true）。  具体的二进制值取决于 `ADD` 常量以及 `Rn_offset` 和 `Rm_offset` 等在 `constants-arm64.h` 中定义的值。

**用户常见的编程错误 (与架构相关):**

对于直接编写 ARM64 汇编代码或底层代码的用户来说，常见的错误包括：

1. **寄存器大小不匹配:**  例如，尝试将 64 位的值加载到 32 位寄存器，或者反之。 `constants-arm64.h` 中定义的 `kWRegSize` 和 `kXRegSize` 可以帮助避免这种错误。

   ```c++
   // 错误示例 (假设在内联汇编中)
   // 尝试将 64 位的值加载到 32 位寄存器 w0 (实际上应该使用 x0)
   // mov w0, #0xFFFFFFFFFFFFFFFF // 错误！

   // 正确示例
   // mov x0, #0xFFFFFFFFFFFFFFFF
   ```

2. **错误的立即数范围:**  ARM64 指令中立即数的范围是有限制的。 使用超出范围的立即数会导致汇编错误或运行时错误。 `constants-arm64.h` 中虽然没有直接定义立即数的范围限制，但理解指令格式和编码可以帮助开发者避免这种错误。

   ```assembly
   // 错误示例: 假设某个指令的立即数范围是 12 位
   // mov w0, #0xFFF000 // 立即数过大，可能导致错误

   // 正确示例: 使用范围内的值
   // mov w0, #0xFFF
   ```

3. **条件码使用错误:**  在条件分支指令中使用错误的条件码会导致程序逻辑错误。  `constants-arm64.h` 中的 `Condition` 枚举提供了可用的条件码，但开发者需要理解每个条件码的含义。

   ```assembly
   // 错误示例: 假设想在两个数相等时跳转
   // cmp w0, w1
   // b.ne label  // 应该使用 b.eq

   // 正确示例
   // cmp w0, w1
   // b.eq label
   ```

4. **不正确的内存对齐:**  某些 ARM64 指令要求访问的内存地址是特定大小的倍数（例如，加载双字需要 8 字节对齐）。 不正确的对齐会导致性能下降或错误。  `constants-arm64.h` 中定义的 `kWordSizeInBytes` 和 `kDoubleWordSizeInBytes` 可以提醒开发者注意内存对齐。

**总结 `v8/src/codegen/arm64/constants-arm64.h` 的功能 (第 1 部分):**

`v8/src/codegen/arm64/constants-arm64.h` 是一个至关重要的 C++ 头文件，它为 V8 JavaScript 引擎的 ARM64 代码生成器提供了基础的架构常量定义。 这些常量涵盖了寄存器、指令编码、条件码、内存布局和浮点数表示等多个方面，是 V8 将 JavaScript 代码转化为可在 ARM64 处理器上执行的机器码的关键组成部分。 虽然与 JavaScript 功能的联系是间接的，但没有这些常量，V8 就无法在 ARM64 平台上高效且正确地运行 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/codegen/arm64/constants-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/constants-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_ARM64_CONSTANTS_ARM64_H_
#define V8_CODEGEN_ARM64_CONSTANTS_ARM64_H_

#include "src/base/macros.h"
#include "src/common/globals.h"

// Assert that this is an LP64 system, or LLP64 on Windows.
static_assert(sizeof(int) == sizeof(int32_t));
#if defined(V8_OS_WIN)
static_assert(sizeof(1L) == sizeof(int32_t));
#else
static_assert(sizeof(long) == sizeof(int64_t));  // NOLINT(runtime/int)
static_assert(sizeof(1L) == sizeof(int64_t));
#endif
static_assert(sizeof(void*) == sizeof(int64_t));
static_assert(sizeof(1) == sizeof(int32_t));

// Get the standard printf format macros for C99 stdint types.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

namespace v8 {
namespace internal {

// The maximum size of the code range s.t. pc-relative calls are possible
// between all Code objects in the range.
constexpr size_t kMaxPCRelativeCodeRangeInMB = 128;

constexpr uint8_t kInstrSize = 4;
constexpr uint8_t kInstrSizeLog2 = 2;
constexpr uint8_t kLoadLiteralScaleLog2 = 2;
constexpr uint8_t kLoadLiteralScale = 1 << kLoadLiteralScaleLog2;
constexpr int kMaxLoadLiteralRange = 1 * MB;

constexpr int kNumberOfRegisters = 32;
constexpr int kNumberOfVRegisters = 32;
// Callee saved registers are x19-x28.
constexpr int kNumberOfCalleeSavedRegisters = 10;
// Callee saved FP registers are d8-d15.
constexpr int kNumberOfCalleeSavedVRegisters = 8;
constexpr int kWRegSizeInBits = 32;
constexpr int kWRegSizeInBitsLog2 = 5;
constexpr int kWRegSize = kWRegSizeInBits >> 3;
constexpr int kWRegSizeLog2 = kWRegSizeInBitsLog2 - 3;
constexpr int kXRegSizeInBits = 64;
constexpr int kXRegSizeInBitsLog2 = 6;
constexpr int kXRegSize = kXRegSizeInBits >> 3;
constexpr int kXRegSizeLog2 = kXRegSizeInBitsLog2 - 3;
constexpr int kSRegSizeInBits = 32;
constexpr int kSRegSizeInBitsLog2 = 5;
constexpr int kSRegSize = kSRegSizeInBits >> 3;
constexpr int kSRegSizeLog2 = kSRegSizeInBitsLog2 - 3;
constexpr int kDRegSizeInBits = 64;
constexpr int kDRegSizeInBitsLog2 = 6;
constexpr int kDRegSize = kDRegSizeInBits >> 3;
constexpr int kDRegSizeLog2 = kDRegSizeInBitsLog2 - 3;
constexpr int kDRegSizeInBytesLog2 = kDRegSizeInBitsLog2 - 3;
constexpr int kBRegSizeInBits = 8;
constexpr int kBRegSize = kBRegSizeInBits >> 3;
constexpr int kHRegSizeInBits = 16;
constexpr int kHRegSize = kHRegSizeInBits >> 3;
constexpr int kQRegSizeInBits = 128;
constexpr int kQRegSizeInBitsLog2 = 7;
constexpr int kQRegSize = kQRegSizeInBits >> 3;
constexpr int kQRegSizeLog2 = kQRegSizeInBitsLog2 - 3;
constexpr int kVRegSizeInBits = kQRegSizeInBits;
constexpr int kVRegSize = kVRegSizeInBits >> 3;
constexpr int64_t kWRegMask = 0x00000000ffffffffL;
constexpr int64_t kXRegMask = 0xffffffffffffffffL;
constexpr int64_t kSRegMask = 0x00000000ffffffffL;
constexpr int64_t kDRegMask = 0xffffffffffffffffL;
// TODO(all) check if the expression below works on all compilers or if it
// triggers an overflow error.
constexpr int64_t kDSignBit = 63;
constexpr int64_t kDSignMask = 0x1LL << kDSignBit;
constexpr int64_t kSSignBit = 31;
constexpr int64_t kSSignMask = 0x1LL << kSSignBit;
constexpr int64_t kXSignBit = 63;
constexpr int64_t kXSignMask = 0x1LL << kXSignBit;
constexpr int64_t kWSignBit = 31;
constexpr int64_t kWSignMask = 0x1LL << kWSignBit;
constexpr int64_t kDQuietNanBit = 51;
constexpr int64_t kDQuietNanMask = 0x1LL << kDQuietNanBit;
constexpr int64_t kSQuietNanBit = 22;
constexpr int64_t kSQuietNanMask = 0x1LL << kSQuietNanBit;
constexpr int64_t kHQuietNanBit = 9;
constexpr int64_t kHQuietNanMask = 0x1LL << kHQuietNanBit;
constexpr int64_t kByteMask = 0xffL;
constexpr int64_t kHalfWordMask = 0xffffL;
constexpr int64_t kWordMask = 0xffffffffL;
constexpr uint64_t kXMaxUInt = 0xffffffffffffffffUL;
constexpr uint64_t kWMaxUInt = 0xffffffffUL;
constexpr int64_t kXMaxInt = 0x7fffffffffffffffL;
constexpr int64_t kXMinInt = 0x8000000000000000L;
constexpr int32_t kWMaxInt = 0x7fffffff;
constexpr int32_t kWMinInt = 0x80000000;
constexpr int kIp0Code = 16;
constexpr int kIp1Code = 17;
constexpr int kFramePointerRegCode = 29;
constexpr int kLinkRegCode = 30;
constexpr int kZeroRegCode = 31;
constexpr int kSPRegInternalCode = 63;
constexpr unsigned kRegCodeMask = 0x1f;
constexpr unsigned kShiftAmountWRegMask = 0x1f;
constexpr unsigned kShiftAmountXRegMask = 0x3f;
// Standard machine types defined by AAPCS64.
constexpr unsigned kHalfWordSize = 16;
constexpr unsigned kHalfWordSizeLog2 = 4;
constexpr unsigned kHalfWordSizeInBytes = kHalfWordSize >> 3;
constexpr unsigned kHalfWordSizeInBytesLog2 = kHalfWordSizeLog2 - 3;
constexpr unsigned kWordSize = 32;
constexpr unsigned kWordSizeLog2 = 5;
constexpr unsigned kWordSizeInBytes = kWordSize >> 3;
constexpr unsigned kWordSizeInBytesLog2 = kWordSizeLog2 - 3;
constexpr unsigned kDoubleWordSize = 64;
constexpr unsigned kDoubleWordSizeInBytes = kDoubleWordSize >> 3;
constexpr unsigned kQuadWordSize = 128;
constexpr unsigned kQuadWordSizeInBytes = kQuadWordSize >> 3;
constexpr int kMaxLanesPerVector = 16;

constexpr unsigned kAddressTagOffset = 56;
constexpr unsigned kAddressTagWidth = 8;
constexpr uint64_t kAddressTagMask = ((UINT64_C(1) << kAddressTagWidth) - 1)
                                     << kAddressTagOffset;
static_assert(kAddressTagMask == UINT64_C(0xff00000000000000),
              "AddressTagMask must represent most-significant eight bits.");

constexpr uint64_t kTTBRMask = UINT64_C(1) << 55;

// AArch64 floating-point specifics. These match IEEE-754.
constexpr unsigned kDoubleMantissaBits = 52;
constexpr unsigned kDoubleExponentBits = 11;
constexpr unsigned kDoubleExponentBias = 1023;
constexpr unsigned kFloatMantissaBits = 23;
constexpr unsigned kFloatExponentBits = 8;
constexpr unsigned kFloatExponentBias = 127;
constexpr unsigned kFloat16MantissaBits = 10;
constexpr unsigned kFloat16ExponentBits = 5;
constexpr unsigned kFloat16ExponentBias = 15;

// The actual value of the kRootRegister is offset from the IsolateData's start
// to take advantage of negative displacement values.
constexpr int kRootRegisterBias = 256;

using float16 = uint16_t;

#define INSTRUCTION_FIELDS_LIST(V_)                     \
  /* Register fields */                                 \
  V_(Rd, 4, 0, Bits)    /* Destination register.     */ \
  V_(Rn, 9, 5, Bits)    /* First source register.    */ \
  V_(Rm, 20, 16, Bits)  /* Second source register.   */ \
  V_(Ra, 14, 10, Bits)  /* Third source register.    */ \
  V_(Rt, 4, 0, Bits)    /* Load dest / store source. */ \
  V_(Rt2, 14, 10, Bits) /* Load second dest /        */ \
                        /* store second source.      */ \
  V_(Rs, 20, 16, Bits)  /* Store-exclusive status    */ \
  V_(PrefetchMode, 4, 0, Bits)                          \
                                                        \
  /* Common bits */                                     \
  V_(SixtyFourBits, 31, 31, Bits)                       \
  V_(FlagsUpdate, 29, 29, Bits)                         \
                                                        \
  /* PC relative addressing */                          \
  V_(ImmPCRelHi, 23, 5, SignedBits)                     \
  V_(ImmPCRelLo, 30, 29, Bits)                          \
                                                        \
  /* Add/subtract/logical shift register */             \
  V_(ShiftDP, 23, 22, Bits)                             \
  V_(ImmDPShift, 15, 10, Bits)                          \
                                                        \
  /* Add/subtract immediate */                          \
  V_(ImmAddSub, 21, 10, Bits)                           \
  V_(ShiftAddSub, 23, 22, Bits)                         \
                                                        \
  /* Add/subtract extend */                             \
  V_(ImmExtendShift, 12, 10, Bits)                      \
  V_(ExtendMode, 15, 13, Bits)                          \
                                                        \
  /* Move wide */                                       \
  V_(ImmMoveWide, 20, 5, Bits)                          \
  V_(ShiftMoveWide, 22, 21, Bits)                       \
                                                        \
  /* Logical immediate, bitfield and extract */         \
  V_(BitN, 22, 22, Bits)                                \
  V_(ImmRotate, 21, 16, Bits)                           \
  V_(ImmSetBits, 15, 10, Bits)                          \
  V_(ImmR, 21, 16, Bits)                                \
  V_(ImmS, 15, 10, Bits)                                \
                                                        \
  /* Test and branch immediate */                       \
  V_(ImmTestBranch, 18, 5, SignedBits)                  \
  V_(ImmTestBranchBit40, 23, 19, Bits)                  \
  V_(ImmTestBranchBit5, 31, 31, Bits)                   \
                                                        \
  /* Conditionals */                                    \
  V_(Condition, 15, 12, Bits)                           \
  V_(ConditionBranch, 3, 0, Bits)                       \
  V_(Nzcv, 3, 0, Bits)                                  \
  V_(ImmCondCmp, 20, 16, Bits)                          \
  V_(ImmCondBranch, 23, 5, SignedBits)                  \
                                                        \
  /* Floating point */                                  \
  V_(FPType, 23, 22, Bits)                              \
  V_(ImmFP, 20, 13, Bits)                               \
  V_(FPScale, 15, 10, Bits)                             \
                                                        \
  /* Load Store */                                      \
  V_(ImmLS, 20, 12, SignedBits)                         \
  V_(ImmLSUnsigned, 21, 10, Bits)                       \
  V_(ImmLSPair, 21, 15, SignedBits)                     \
  V_(ImmShiftLS, 12, 12, Bits)                          \
  V_(LSOpc, 23, 22, Bits)                               \
  V_(LSVector, 26, 26, Bits)                            \
  V_(LSSize, 31, 30, Bits)                              \
                                                        \
  /* NEON generic fields */                             \
  V_(NEONQ, 30, 30, Bits)                               \
  V_(NEONSize, 23, 22, Bits)                            \
  V_(NEONLSSize, 11, 10, Bits)                          \
  V_(NEONS, 12, 12, Bits)                               \
  V_(NEONL, 21, 21, Bits)                               \
  V_(NEONM, 20, 20, Bits)                               \
  V_(NEONH, 11, 11, Bits)                               \
  V_(ImmNEONExt, 14, 11, Bits)                          \
  V_(ImmNEON5, 20, 16, Bits)                            \
  V_(ImmNEON4, 14, 11, Bits)                            \
                                                        \
  /* Other immediates */                                \
  V_(ImmUncondBranch, 25, 0, SignedBits)                \
  V_(ImmCmpBranch, 23, 5, SignedBits)                   \
  V_(ImmLLiteral, 23, 5, SignedBits)                    \
  V_(ImmException, 20, 5, Bits)                         \
  V_(ImmHint, 11, 5, Bits)                              \
  V_(ImmBarrierDomain, 11, 10, Bits)                    \
  V_(ImmBarrierType, 9, 8, Bits)                        \
                                                        \
  /* System (MRS, MSR) */                               \
  V_(ImmSystemRegister, 19, 5, Bits)                    \
  V_(SysO0, 19, 19, Bits)                               \
  V_(SysOp1, 18, 16, Bits)                              \
  V_(SysOp2, 7, 5, Bits)                                \
  V_(CRn, 15, 12, Bits)                                 \
  V_(CRm, 11, 8, Bits)                                  \
                                                        \
  /* Load-/store-exclusive */                           \
  V_(LoadStoreXLoad, 22, 22, Bits)                      \
  V_(LoadStoreXNotExclusive, 23, 23, Bits)              \
  V_(LoadStoreXAcquireRelease, 15, 15, Bits)            \
  V_(LoadStoreXSizeLog2, 31, 30, Bits)                  \
  V_(LoadStoreXPair, 21, 21, Bits)                      \
                                                        \
  /* NEON load/store */                                 \
  V_(NEONLoad, 22, 22, Bits)                            \
                                                        \
  /* NEON Modified Immediate fields */                  \
  V_(ImmNEONabc, 18, 16, Bits)                          \
  V_(ImmNEONdefgh, 9, 5, Bits)                          \
  V_(NEONModImmOp, 29, 29, Bits)                        \
  V_(NEONCmode, 15, 12, Bits)                           \
                                                        \
  /* NEON Shift Immediate fields */                     \
  V_(ImmNEONImmhImmb, 22, 16, Bits)                     \
  V_(ImmNEONImmh, 22, 19, Bits)                         \
  V_(ImmNEONImmb, 18, 16, Bits)

#define SYSTEM_REGISTER_FIELDS_LIST(V_, M_) \
  /* NZCV */                                \
  V_(Flags, 31, 28, Bits, uint32_t)         \
  V_(N, 31, 31, Bits, bool)                 \
  V_(Z, 30, 30, Bits, bool)                 \
  V_(C, 29, 29, Bits, bool)                 \
  V_(V, 28, 28, Bits, bool)                 \
  M_(NZCV, Flags_mask)                      \
                                            \
  /* FPCR */                                \
  V_(AHP, 26, 26, Bits, bool)               \
  V_(DN, 25, 25, Bits, bool)                \
  V_(FZ, 24, 24, Bits, bool)                \
  V_(RMode, 23, 22, Bits, FPRounding)       \
  M_(FPCR, AHP_mask | DN_mask | FZ_mask | RMode_mask)

// Fields offsets.
#define DECLARE_FIELDS_OFFSETS(Name, HighBit, LowBit, unused_1, unused_2) \
  constexpr int Name##_offset = LowBit;                                   \
  constexpr int Name##_width = HighBit - LowBit + 1;                      \
  constexpr uint32_t Name##_mask = ((1 << Name##_width) - 1) << LowBit;
#define DECLARE_INSTRUCTION_FIELDS_OFFSETS(Name, HighBit, LowBit, unused_1) \
  DECLARE_FIELDS_OFFSETS(Name, HighBit, LowBit, unused_1, unused_2)
INSTRUCTION_FIELDS_LIST(DECLARE_INSTRUCTION_FIELDS_OFFSETS)
SYSTEM_REGISTER_FIELDS_LIST(DECLARE_FIELDS_OFFSETS, NOTHING)
#undef DECLARE_FIELDS_OFFSETS
#undef DECLARE_INSTRUCTION_FIELDS_OFFSETS

// ImmPCRel is a compound field (not present in INSTRUCTION_FIELDS_LIST), formed
// from ImmPCRelLo and ImmPCRelHi.
constexpr int ImmPCRel_mask = ImmPCRelLo_mask | ImmPCRelHi_mask;

// Condition codes.
enum Condition : int {
  eq = 0,   // Equal
  ne = 1,   // Not equal
  hs = 2,   // Unsigned higher or same (or carry set)
  cs = hs,  //   --
  lo = 3,   // Unsigned lower (or carry clear)
  cc = lo,  //   --
  mi = 4,   // Negative
  pl = 5,   // Positive or zero
  vs = 6,   // Signed overflow
  vc = 7,   // No signed overflow
  hi = 8,   // Unsigned higher
  ls = 9,   // Unsigned lower or same
  ge = 10,  // Signed greater than or equal
  lt = 11,  // Signed less than
  gt = 12,  // Signed greater than
  le = 13,  // Signed less than or equal
  al = 14,  // Always executed
  nv = 15,  // Behaves as always/al.

  // Unified cross-platform condition names/aliases.
  kEqual = eq,
  kNotEqual = ne,
  kLessThan = lt,
  kGreaterThan = gt,
  kLessThanEqual = le,
  kGreaterThanEqual = ge,
  kUnsignedLessThan = lo,
  kUnsignedGreaterThan = hi,
  kUnsignedLessThanEqual = ls,
  kUnsignedGreaterThanEqual = hs,
  kOverflow = vs,
  kNoOverflow = vc,
  kZero = eq,
  kNotZero = ne,
};

inline Condition NegateCondition(Condition cond) {
  // Conditions al and nv behave identically, as "always true". They can't be
  // inverted, because there is no never condition.
  DCHECK((cond != al) && (cond != nv));
  return static_cast<Condition>(cond ^ 1);
}

enum FlagsUpdate { SetFlags = 1, LeaveFlags = 0 };

enum StatusFlags {
  NoFlag = 0,

  // Derive the flag combinations from the system register bit descriptions.
  NFlag = N_mask,
  ZFlag = Z_mask,
  CFlag = C_mask,
  VFlag = V_mask,
  NZFlag = NFlag | ZFlag,
  NCFlag = NFlag | CFlag,
  NVFlag = NFlag | VFlag,
  ZCFlag = ZFlag | CFlag,
  ZVFlag = ZFlag | VFlag,
  CVFlag = CFlag | VFlag,
  NZCFlag = NFlag | ZFlag | CFlag,
  NZVFlag = NFlag | ZFlag | VFlag,
  NCVFlag = NFlag | CFlag | VFlag,
  ZCVFlag = ZFlag | CFlag | VFlag,
  NZCVFlag = NFlag | ZFlag | CFlag | VFlag,

  // Floating-point comparison results.
  FPEqualFlag = ZCFlag,
  FPLessThanFlag = NFlag,
  FPGreaterThanFlag = CFlag,
  FPUnorderedFlag = CVFlag
};

enum Shift {
  NO_SHIFT = -1,
  LSL = 0x0,
  LSR = 0x1,
  ASR = 0x2,
  ROR = 0x3,
  MSL = 0x4
};

enum Extend {
  NO_EXTEND = -1,
  UXTB = 0,
  UXTH = 1,
  UXTW = 2,
  UXTX = 3,
  SXTB = 4,
  SXTH = 5,
  SXTW = 6,
  SXTX = 7
};

enum SystemHint {
  NOP = 0,
  YIELD = 1,
  WFE = 2,
  WFI = 3,
  SEV = 4,
  SEVL = 5,
  CSDB = 20,
  BTI = 32,
  BTI_c = 34,
  BTI_j = 36,
  BTI_jc = 38
};

// In a guarded page, only BTI and PACI[AB]SP instructions are allowed to be
// the target of indirect branches. Details on which kinds of branches each
// instruction allows follow in the comments below:
enum class BranchTargetIdentifier {
  // Do not emit a BTI instruction.
  kNone,

  // Emit a BTI instruction. Cannot be the target of indirect jumps/calls.
  kBti,

  // Emit a "BTI c" instruction. Can be the target of indirect jumps (BR) with
  // x16/x17 as the target register, or indirect calls (BLR).
  kBtiCall,

  // Emit a "BTI j" instruction. Can be the target of indirect jumps (BR).
  kBtiJump,

  // Emit a "BTI jc" instruction, which is a combination of "BTI j" and "BTI c".
  kBtiJumpCall,

  // Emit a PACIBSP instruction, which acts like a "BTI c" or a "BTI jc",
  // based on the value of SCTLR_EL1.BT0.
  kPacibsp
};

enum BarrierDomain {
  OuterShareable = 0,
  NonShareable = 1,
  InnerShareable = 2,
  FullSystem = 3
};

enum BarrierType {
  BarrierOther = 0,
  BarrierReads = 1,
  BarrierWrites = 2,
  BarrierAll = 3
};

// System/special register names.
// This information is not encoded as one field but as the concatenation of
// multiple fields (Op0<0>, Op1, Crn, Crm, Op2).
enum SystemRegister {
  NZCV = ((0x1 << SysO0_offset) | (0x3 << SysOp1_offset) | (0x4 << CRn_offset) |
          (0x2 << CRm_offset) | (0x0 << SysOp2_offset)) >>
         ImmSystemRegister_offset,
  FPCR = ((0x1 << SysO0_offset) | (0x3 << SysOp1_offset) | (0x4 << CRn_offset) |
          (0x4 << CRm_offset) | (0x0 << SysOp2_offset)) >>
         ImmSystemRegister_offset
};

// Instruction enumerations.
//
// These are the masks that define a class of instructions, and the list of
// instructions within each class. Each enumeration has a Fixed, FMask and
// Mask value.
//
// Fixed: The fixed bits in this instruction class.
// FMask: The mask used to extract the fixed bits in the class.
// Mask:  The mask used to identify the instructions within a class.
//
// The enumerations can be used like this:
//
// DCHECK(instr->Mask(PCRelAddressingFMask) == PCRelAddressingFixed);
// switch(instr->Mask(PCRelAddressingMask)) {
//   case ADR:  Format("adr 'Xd, 'AddrPCRelByte"); break;
//   case ADRP: Format("adrp 'Xd, 'AddrPCRelPage"); break;
//   default:   printf("Unknown instruction\n");
// }

// Used to corrupt encodings by setting all bits when orred. Although currently
// unallocated in AArch64, this encoding is not guaranteed to be undefined
// indefinitely.
constexpr uint32_t kUnallocatedInstruction = 0xffffffff;

// Generic fields.
using GenericInstrField = uint32_t;
constexpr GenericInstrField SixtyFourBits = 0x80000000;
constexpr GenericInstrField ThirtyTwoBits = 0x00000000;
constexpr GenericInstrField FP32 = 0x00000000;
constexpr GenericInstrField FP64 = 0x00400000;

using NEONFormatField = uint32_t;
constexpr NEONFormatField NEONFormatFieldMask = 0x40C00000;
constexpr NEONFormatField NEON_Q = 0x40000000;
constexpr NEONFormatField NEON_sz = 0x00400000;
constexpr NEONFormatField NEON_8B = 0x00000000;
constexpr NEONFormatField NEON_16B = NEON_8B | NEON_Q;
constexpr NEONFormatField NEON_4H = 0x00400000;
constexpr NEONFormatField NEON_8H = NEON_4H | NEON_Q;
constexpr NEONFormatField NEON_2S = 0x00800000;
constexpr NEONFormatField NEON_4S = NEON_2S | NEON_Q;
constexpr NEONFormatField NEON_1D = 0x00C00000;
constexpr NEONFormatField NEON_2D = 0x00C00000 | NEON_Q;

using NEONFPFormatField = uint32_t;
constexpr NEONFPFormatField NEONFPFormatFieldMask = 0x40400000;
constexpr NEONFPFormatField NEON_FP_4H = 0x00000000;
constexpr NEONFPFormatField NEON_FP_8H = NEON_Q;
constexpr NEONFPFormatField NEON_FP_2S = FP32;
constexpr NEONFPFormatField NEON_FP_4S = FP32 | NEON_Q;
constexpr NEONFPFormatField NEON_FP_2D = FP64 | NEON_Q;

using NEONLSFormatField = uint32_t;
constexpr NEONLSFormatField NEONLSFormatFieldMask = 0x40000C00;
constexpr NEONLSFormatField LS_NEON_8B = 0x00000000;
constexpr NEONLSFormatField LS_NEON_16B = LS_NEON_8B | NEON_Q;
constexpr NEONLSFormatField LS_NEON_4H = 0x00000400;
constexpr NEONLSFormatField LS_NEON_8H = LS_NEON_4H | NEON_Q;
constexpr NEONLSFormatField LS_NEON_2S = 0x00000800;
constexpr NEONLSFormatField LS_NEON_4S = LS_NEON_2S | NEON_Q;
constexpr NEONLSFormatField LS_NEON_1D = 0x00000C00;
constexpr NEONLSFormatField LS_NEON_2D = LS_NEON_1D | NEON_Q;

using NEONScalarFormatField = uint32_t;
constexpr NEONScalarFormatField NEONScalarFormatFieldMask = 0x00C00000;
constexpr NEONScalarFormatField NEONScalar = 0x10000000;
constexpr NEONScalarFormatField NEON_B = 0x00000000;
constexpr NEONScalarFormatField NEON_H = 0x00400000;
constexpr NEONScalarFormatField NEON_S = 0x00800000;
constexpr NEONScalarFormatField NEON_D = 0x00C00000;

// PC relative addressing.
using PCRelAddressingOp = uint32_t;
constexpr PCRelAddressingOp PCRelAddressingFixed = 0x10000000;
constexpr PCRelAddressingOp PCRelAddressingFMask = 0x1F000000;
constexpr PCRelAddressingOp PCRelAddressingMask = 0x9F000000;
constexpr PCRelAddressingOp ADR = PCRelAddressingFixed | 0x00000000;
constexpr PCRelAddressingOp ADRP = PCRelAddressingFixed | 0x80000000;

// Add/sub (immediate, shifted and extended.)
constexpr int kSFOffset = 31;
using AddSubOp = uint32_t;
constexpr AddSubOp AddSubOpMask = 0x60000000;
constexpr AddSubOp AddSubSetFlagsBit = 0x20000000;
constexpr AddSubOp ADD = 0x00000000;
constexpr AddSubOp ADDS = ADD | AddSubSetFlagsBit;
constexpr AddSubOp SUB = 0x40000000;
constexpr AddSubOp SUBS = SUB | AddSubSetFlagsBit;

#define ADD_SUB_OP_LIST(V) \
  V(ADD);                  \
  V(ADDS);                 \
  V(SUB);                  \
  V(SUBS)

using AddSubImmediateOp = uint32_t;
constexpr AddSubImmediateOp AddSubImmediateFixed = 0x11000000;
constexpr AddSubImmediateOp AddSubImmediateFMask = 0x1F000000;
constexpr AddSubImmediateOp AddSubImmediateMask = 0xFF000000;
#define ADD_SUB_IMMEDIATE(A)                                        \
  constexpr AddSubImmediateOp A##_w_imm = AddSubImmediateFixed | A; \
  constexpr AddSubImmediateOp A##_x_imm =                           \
      AddSubImmediateFixed | A | SixtyFourBits
ADD_SUB_OP_LIST(ADD_SUB_IMMEDIATE);
#undef ADD_SUB_IMMEDIATE

using AddSubShiftedOp = uint32_t;
constexpr AddSubShiftedOp AddSubShiftedFixed = 0x0B000000;
constexpr AddSubShiftedOp AddSubShiftedFMask = 0x1F200000;
constexpr AddSubShiftedOp AddSubShiftedMask = 0xFF200000;
#define ADD_SUB_SHIFTED(A)                                        \
  constexpr AddSubShiftedOp A##_w_shift = AddSubShiftedFixed | A; \
  constexpr AddSubShiftedOp A##_x_shift = AddSubShiftedFixed | A | SixtyFourBits
ADD_SUB_OP_LIST(ADD_SUB_SHIFTED);
#undef ADD_SUB_SHIFTED

using AddSubExtendedOp = uint32_t;
constexpr AddSubExtendedOp AddSubExtendedFixed = 0x0B200000;
constexpr AddSubExtendedOp AddSubExtendedFMask = 0x1F200000;
constexpr AddSubExtendedOp AddSubExtendedMask = 0xFFE00000;
#define ADD_SUB_EXTENDED(A)                                       \
  constexpr AddSubExtendedOp A##_w_ext = AddSubExtendedFixed | A; \
  constexpr AddSubExtendedOp A##_x_ext = AddSubExtendedFixed | A | SixtyFourBits
ADD_SUB_OP_LIST(ADD_SUB_EXTENDED);
#undef ADD_SUB_EXTENDED

// Add/sub with carry.
using AddSubWithCarryOp = uint32_t;
constexpr AddSubWithCarryOp AddSubWithCarryFixed = 0x1A000000;
constexpr AddSubWithCarryOp AddSubWithCarryFMask = 0x1FE00000;
constexpr AddSubWithCarryOp AddSubWithCarryMask = 0xFFE0FC00;
constexpr AddSubWithCarryOp ADC_w = AddSubWithCarryFixed | ADD;
constexpr AddSubWithCarryOp ADC_x = AddSubWithCarryFixed | ADD | SixtyFourBits;
constexpr AddSubWithCarryOp ADC = ADC_w;
constexpr AddSubWithCarryOp ADCS_w = AddSubWithCarryFixed | ADDS;
constexpr AddSubWithCarryOp ADCS_x =
    AddSubWithCarryFixed | ADDS | SixtyFourBits;
constexpr AddSubWithCarryOp SBC_w = AddSubWithCarryFixed | SUB;
constexpr AddSubWithCarryOp SBC_x = AddSubWithCarryFixed | SUB | SixtyFourBits;
constexpr AddSubWithCarryOp SBC = SBC_w;
constexpr AddSubWithCarryOp SBCS_w = AddSubWithCarryFixed | SUBS;
constexpr AddSubWithCarryOp SBCS_x =
    AddSubWithCarryFixed | SUBS | SixtyFourBits;

// Logical (immediate and shifted register).
using LogicalOp = uint32_t;
constexpr LogicalOp LogicalOpMask = 0x60200000;
constexpr LogicalOp NOT = 0x00200000;
constexpr LogicalOp AND = 0x00000000;
constexpr LogicalOp BIC = AND | NOT;
constexpr LogicalOp ORR = 0x20000000;
constexpr LogicalOp ORN = ORR | NOT;
constexpr LogicalOp EOR = 0x40000000;
constexpr LogicalOp EON = EOR | NOT;
constexpr LogicalOp ANDS = 0x60000000;
constexpr LogicalOp BICS = ANDS | NOT;

// Logical immediate.
using LogicalImmediateOp = uint32_t;
constexpr LogicalImmediateOp LogicalImmediateFixed = 0x12000000;
constexpr LogicalImmediateOp LogicalImmediateFMask = 0x1F800000;
constexpr LogicalImmediateOp LogicalImmediateMask = 0xFF800000;
constexpr LogicalImmediateOp AND_w_imm = LogicalImmediateFixed | AND;
constexpr LogicalImmediateOp AND_x_imm =
    LogicalImmediateFixed | AND | SixtyFourBits;
constexpr LogicalImmediateOp ORR_w_imm = LogicalImmediateFixed | ORR;
constexpr LogicalImmediateOp ORR_x_imm =
    LogicalImmediateFixed | ORR | SixtyFourBits;
constexpr LogicalImmediateOp EOR_w_imm = LogicalImmediateFixed | EOR;
constexpr LogicalImmediateOp EOR_x_imm =
    LogicalImmediateFixed | EOR | SixtyFourBits;
constexpr LogicalImmediateOp ANDS_w_imm = LogicalImmediateFixed | ANDS;
constexpr LogicalImmediateOp ANDS_x_imm =
    LogicalImmediateFixed | ANDS | SixtyFourBits;

// Logical shifted register.
using LogicalShiftedOp = uint32_t;
constexpr LogicalShiftedOp LogicalShiftedFixed = 0x0A000000;
constexpr LogicalShiftedOp LogicalShiftedFMask = 0x1F000000;
constexpr LogicalShiftedOp LogicalShiftedMask = 0xFF200000;
constexpr LogicalShiftedOp AND_w = LogicalShiftedFixed | AND;
constexpr LogicalShiftedOp AND_x = LogicalShiftedFixed | AND | SixtyFourBits;
constexpr LogicalShiftedOp AND_shift = AND_w;
constexpr LogicalShiftedOp BIC_w = LogicalShiftedFixed | BIC;
constexpr LogicalShiftedOp BIC_x = LogicalShiftedFixed | BIC | SixtyFourBits;
constexpr LogicalShiftedOp BIC_shift = BIC_w;
constexpr LogicalShiftedOp ORR_w = LogicalShiftedFixed | ORR;
constexpr LogicalShiftedOp ORR_x = LogicalShiftedFixed | ORR | SixtyFourBits;
constexpr LogicalShiftedOp ORR_shift = ORR_w;
constexpr LogicalShiftedOp ORN_w = LogicalShiftedFixed | ORN;
constexpr LogicalShiftedOp ORN_x = LogicalShiftedFixed | ORN | SixtyFourBits;
constexpr LogicalShiftedOp ORN_shift = ORN_w;
constexpr LogicalShiftedOp EOR_w = LogicalShiftedFixed | EOR;
constexpr LogicalShiftedOp EOR_x = LogicalShiftedFixed | EOR | SixtyFourBits;
constexpr LogicalShiftedOp EOR_shift = EOR_w;
constexpr LogicalShiftedOp EON_w = LogicalShiftedFixed | EON;
constexpr LogicalShiftedOp EON_x = LogicalShiftedFixed | EON | SixtyFourBits;
constexpr LogicalShiftedOp EON_shift = EON_w;
constexpr LogicalShiftedOp ANDS_w = LogicalShiftedFixed | ANDS;
constexpr LogicalShiftedOp ANDS_x = LogicalShiftedFixed | ANDS | SixtyFourBits;
constexpr LogicalShiftedOp ANDS_shift = ANDS_w;
constexpr LogicalShiftedOp BICS_w = LogicalShiftedFixed | BICS;
constexpr LogicalShiftedOp BICS_x = LogicalShiftedFixed | BICS | SixtyFourBits;
constexpr LogicalShiftedOp BICS_shift = BICS_w;

// Move wide immediate.
using MoveWideImmediateOp = uint32_t;
constexpr MoveWideImmediateOp MoveWideImmediateFixed = 0x12800000;
constexpr MoveWideImmediateOp MoveWideImmediateFMask = 0x1F800000;
constexpr MoveWideImmediateOp MoveWideImmediateMask = 0xFF800000;
constexpr MoveWideImmediateOp MOVN = 0x00000000;
constexpr MoveWideImmediateOp MOVZ = 0x40000000;
constexpr MoveWideImmediateOp MOVK = 0x60000000;
constexpr MoveWideImmediateOp MOVN_w = MoveWideImmediateFixed | MOVN;
constexpr MoveWideImmediateOp MOVN_x =
    MoveWideImmediateFixed | MOVN | SixtyFourBits;
constexpr MoveWideImmediateOp MOVZ_w = MoveWideImmediateFixed | MOVZ;
constexpr MoveWideImmediateOp MOVZ_x =
    MoveWideImmediateFixed | MOVZ | SixtyFourBits;
constexpr MoveWideImmediateOp MOVK_w = MoveWideImmediateFixed | MOVK;
constexpr MoveWideImmediateOp MOVK_x =
    MoveWideImmediateFixed | MOVK | SixtyFourBits;

// Bitfield.
constexpr int kBitfieldNOffset = 22;
using BitfieldOp = uint32_t;
constexpr BitfieldOp BitfieldFixed = 0x13000000;
constexpr BitfieldOp BitfieldFMask = 0x1F800000;
constexpr BitfieldOp BitfieldMask = 0xFF800000;
constexpr BitfieldOp SBFM_w = BitfieldFixed | 0x00000000;
constexpr BitfieldOp SBFM_x = BitfieldFixed | 0x80000000;
constexpr BitfieldOp SBFM = SBFM_w;
constexpr BitfieldOp BFM_w = BitfieldFixed | 0x20000000;
constexpr BitfieldOp BFM_x = BitfieldFixed | 0xA0000000;
constexpr BitfieldOp BFM = BFM_w;
constexpr BitfieldOp UBFM_w = BitfieldFixed | 0x40000000;
constexpr BitfieldOp UBFM_x = BitfieldFixed | 0xC0000000;
constexpr BitfieldOp UBFM = UBFM_w;
// Bitfield N field.

// Extract.
using ExtractOp = uint32_t;
constexpr ExtractOp ExtractFixed = 0x13800000;
constexpr ExtractOp ExtractFMask = 0x1F800000;
constexpr ExtractOp ExtractMask = 0xFFA00000;
constexpr ExtractOp EXTR_w = ExtractFixed | 0x00000000;
constexpr ExtractOp EXTR_x = ExtractFixed | 0x80000000;
constexpr ExtractOp EXTR = EXTR_w;

// Unconditional branch.
using UnconditionalBranchOp = uint32_t;
constexpr UnconditionalBranchOp UnconditionalBranchFixed = 0x14000000;
constexpr UnconditionalBranchOp UnconditionalBranchFMask = 0x7C000000;
constexpr UnconditionalBranchOp UnconditionalBranchMask = 0xFC000000;
constexpr UnconditionalBranchOp B = UnconditionalBranchFixed | 0x00000000;
constexpr UnconditionalBranchOp BL = UnconditionalBranchFixed | 0x80000000;

// Unconditional branch to register.
using UnconditionalBranchToRegisterOp = uint32_t;
constexpr UnconditionalBranchToRegisterOp UnconditionalBranchToRegisterFixed =
    0xD6000000;
constexpr UnconditionalBranchToRegisterOp UnconditionalBranchToRegisterFMask =
    0xFE000000;
constexpr UnconditionalBranchToRegisterOp UnconditionalBranchToRegisterMask =
    0xFFFFFC1F;
constexpr UnconditionalBranchToRegisterOp BR =
    UnconditionalBranchToRegisterFixed | 0x001F0000;
constexpr UnconditionalBranchToRegisterOp BLR =
    UnconditionalBranchToRegisterFixed | 0x003F0000;
constexpr UnconditionalBranchToRegisterOp RET =
    UnconditionalBranchToRegisterFixed | 0x005F0000;

// Compare and branch.
using CompareBranchOp = uint32_t;
constexpr CompareBranchOp CompareBranchFixed = 0x34000000;
constexpr CompareBranchOp CompareBranchFMask = 0x7E000000;
constexpr CompareBranchOp CompareBranchMask = 0xFF000000;
constexpr CompareBranchOp CBZ_w = CompareBranchFixed | 0x00000000;
constexpr CompareBranchOp CBZ_x = CompareBranchFixed | 0x80000000;
constexpr CompareBranchOp CBZ = CBZ_w;
constexpr CompareBranchOp CBNZ_w = CompareBranchFixed | 0x01000000;
constexpr CompareBranchOp CBNZ_x = CompareBranchFixed | 0x81000000;
constexpr CompareBranchOp CBNZ = CBNZ_w;

// Test and branch.
using TestBranchOp = uint32_t;
constexpr TestBranchOp TestBranchFixed = 0x36000000;
constexpr TestBranchOp TestBranchFMask = 0x7E000000;
constexpr TestBranchOp TestBranchMask = 0x7F000000;
constexpr TestBranchOp TBZ = TestBranchFixed | 0x00000000;
constexpr TestBranchOp TBNZ = TestBranchFixed | 0x01000000;

// Conditional branch.
using ConditionalBranchOp = uint32_t;
constexpr ConditionalBranchOp ConditionalBranchFixed = 0x54000000;
constexpr ConditionalBranchOp ConditionalBranchFMask = 0xFE000000;
constexpr ConditionalBranchOp ConditionalBranchMask = 0xFF000010;
constexpr ConditionalBranchOp B_cond = ConditionalBranchFixed | 0x00000000;

// System.
// System instruction encoding is complicated because some instructions use op
// and CR fields to encode parameters. To handle this cleanly, the system
// instructions are split into more than one group.

using SystemOp = uint32_t;
constexpr SystemOp SystemFixed = 0xD5000000;
constexpr SystemOp SystemFMask = 0xFFC00000;

using SystemSysRegOp =
"""


```