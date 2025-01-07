Response: Let's break down the thought process for analyzing the C++ code and relating it to JavaScript.

1. **Understand the Goal:** The request asks for the functionality of the C++ code and its relationship to JavaScript, with an example. This means I need to understand *what* the code does at a high level and how those actions might influence the execution of JavaScript.

2. **Initial Scan for Keywords and Structure:** I quickly scan the code for recognizable keywords and structures:
    * `#include`: Indicates dependencies on other files.
    * `namespace v8::internal`:  Confirms this code is part of the V8 JavaScript engine's internal implementation.
    * `class Instruction`:  Suggests this code is dealing with individual machine instructions.
    * Function names like `SetInstructionBits`, `IsLoad`, `IsStore`, `ImmLogical`, `ImmPCOffset`, `SetImmPCOffsetTarget`. These hints at core functionalities related to instruction manipulation and analysis.
    * `NEONFormatDecoder`: Points to handling of ARM's NEON (Advanced SIMD) instructions, often used for performance-critical operations.
    * `#if V8_TARGET_ARCH_ARM64`:  Confirms this code is specific to the ARM64 architecture.

3. **Focus on Key Classes and Functions:**

    * **`Instruction` Class:** This seems central. I examine its member functions to understand its responsibilities:
        * `SetInstructionBits`:  Modifies the raw bit representation of an instruction. Crucial for code generation and manipulation.
        * `IsLoad`, `IsStore`: Determine if an instruction is a memory load or store operation. Important for understanding data flow.
        * `ImmLogical`, `ImmPCOffset`: Extract immediate values and program counter offsets from instructions. Necessary for understanding instruction operands and control flow.
        * `SetImmPCOffsetTarget`: Modifies the target address of branch instructions. Key for implementing jumps and calls.

    * **`NEONFormatDecoder` Class:** This class is clearly about decoding NEON instructions. I note the functions for extracting information about data types and formats used in SIMD operations.

4. **Inferring High-Level Functionality:** Based on the function names and the context of V8, I can infer the following:

    * **Instruction Representation:** The `Instruction` class likely represents a single ARM64 machine instruction. It provides methods to access and modify its various fields.
    * **Instruction Analysis:** Functions like `IsLoad`, `IsStore`, and the immediate value extraction methods are used to analyze the properties of individual instructions. This is essential for tasks like code optimization, debugging, and disassembly.
    * **Code Patching:**  Functions like `SetInstructionBits` and `SetImmPCOffsetTarget` are involved in modifying instructions in-place. This is a common technique in JIT (Just-In-Time) compilers like V8 for tasks like patching branch targets or inserting runtime checks.
    * **NEON Instruction Handling:** The `NEONFormatDecoder` specifically deals with the intricacies of NEON instructions, which are often used for optimizing JavaScript array operations and other data-intensive tasks.

5. **Connecting to JavaScript:** Now, the crucial part is linking this low-level C++ code to higher-level JavaScript concepts. I consider how the operations performed by this code might affect the execution of JavaScript:

    * **JIT Compilation:** V8 compiles JavaScript code to native machine code. This C++ code is part of that compilation process, specifically for the ARM64 architecture. The `Instruction` class is used to build the sequence of ARM64 instructions that represent the compiled JavaScript code.
    * **Memory Management:** Load and store instructions (`IsLoad`, `IsStore`) directly impact how JavaScript interacts with memory. Accessing JavaScript variables, object properties, and array elements involves these low-level memory operations.
    * **Control Flow:** Branch instructions (manipulated by `SetImmPCOffsetTarget`) are fundamental to implementing JavaScript control flow structures like `if`, `else`, loops, and function calls.
    * **Performance Optimization:** NEON instructions are used to accelerate JavaScript performance, especially for array manipulation and numerical computations. The `NEONFormatDecoder` helps V8 understand and work with these instructions effectively.

6. **Crafting the JavaScript Example:** To illustrate the connection, I need a JavaScript example that *demonstrates* the concepts being manipulated in the C++ code. I think about scenarios where these ARM64 instructions would be generated:

    * **Simple Arithmetic:** `const sum = a + b;`  This will likely involve load instructions to get the values of `a` and `b`, an addition instruction, and a store instruction to put the result in `sum`.
    * **Array Operations:** `const arr = [1, 2, 3]; const doubled = arr.map(x => x * 2);` This is a good candidate for NEON optimization, as multiplying each element of the array can be done in parallel with SIMD instructions.
    * **Conditional Logic:** `if (x > 10) { ... } else { ... }` This will definitely involve branch instructions.

    I choose the array example with `.map()` because it clearly connects to potential NEON usage and is a common JavaScript operation. I then explain how the C++ code is involved in generating the efficient ARM64 instructions for this JavaScript code.

7. **Refining the Explanation:** I review my explanation to ensure it's clear, concise, and accurate. I emphasize the role of the C++ code in the JIT compilation process and how it enables JavaScript to execute efficiently on ARM64 devices. I also make sure to connect the specific C++ functions to their corresponding roles in JavaScript execution.

This systematic approach—from high-level overview to specific details and then back to connecting with the target language—allows for a comprehensive understanding and a clear explanation of the C++ code's functionality and its relevance to JavaScript.
这个C++源代码文件 `instructions-arm64.cc` 是 V8 JavaScript 引擎中专门为 ARM64 架构定义和操作机器指令的核心组件。 它的主要功能可以归纳为以下几点：

**核心功能:**

1. **指令表示和操作:**  定义了 `Instruction` 类，用于表示 ARM64 架构的单个机器指令。  提供了方法来：
    * **设置指令位:** `SetInstructionBits`  允许直接修改指令的二进制表示。这在代码生成和修改过程中非常重要。
    * **判断指令类型:** `IsLoad`, `IsStore`  判断指令是否是加载或存储数据的操作。这对于代码分析和优化很有用。
    * **提取立即数:** `ImmLogical`, `ImmFP32`, `ImmFP64`, `ImmNEONabcdefgh` 等方法用于从指令中提取不同类型的立即数值（常量）。
    * **获取PC相对偏移:** `ImmPCOffset` 计算指令中存储的相对于程序计数器 (PC) 的偏移量，这对于跳转、调用等操作至关重要。
    * **设置PC相对目标:** `SetImmPCOffsetTarget`  根据目标指令的地址，设置指令中的 PC 相对偏移量，实现代码跳转和链接。
    * **处理不同的寻址模式:** 区分并处理 PC 相对寻址、立即数寻址等。

2. **逻辑立即数的解码:** `ImmLogical`  实现了 ARM64 架构中特殊的“逻辑立即数”的解码逻辑。逻辑立即数不是任意的 64 位值，而是通过一定的编码方式表示，该函数负责将其解码为实际的数值。

3. **NEON 指令处理:** 提供了 `NEONFormatDecoder` 类，用于解码和格式化 ARM64 的 NEON (Advanced SIMD) 指令。NEON 指令用于并行处理向量数据，在多媒体和数值计算中能显著提升性能。

4. **辅助函数:** 提供了一些辅助函数，如 `RotateRight` (右循环移位) 和 `RepeatBitsAcrossReg` (位重复)，用于处理指令中的特定位模式。

**与 JavaScript 的关系:**

这个文件直接参与了 V8 引擎将 JavaScript 代码编译成可执行的 ARM64 机器码的过程。当 V8 的 JIT (Just-In-Time) 编译器（如 Crankshaft 或 TurboFan）将 JavaScript 代码编译成机器码时，会使用 `Instruction` 类来构建和操作生成的 ARM64 指令。

具体来说：

* **JavaScript 的变量访问和赋值:**  当 JavaScript 代码访问或修改变量时，V8 可能会生成 `LDR` (load register) 和 `STR` (store register) 等指令，`Instruction::IsLoad()` 和 `Instruction::IsStore()` 就用于识别这些指令。
* **JavaScript 的算术运算:** 像加法、减法等算术运算会被编译成相应的 ARM64 算术指令，这些指令可能包含需要用 `ImmLogical()` 解码的立即数。
* **JavaScript 的控制流 (if, for, while 等):**  `if` 语句、循环等控制流结构会被编译成条件分支指令（例如 `B.cond`）和无条件分支指令 (`B`)，这些指令的目标地址是通过 `Instruction::SetImmPCOffsetTarget()` 设置的。
* **JavaScript 中对数组和类型化数组的操作:**  当 JavaScript 操作数组或类型化数组时，V8 可能会使用 NEON 指令进行优化，例如并行地对数组元素进行操作。`NEONFormatDecoder` 就是用来处理这些指令的。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

const arr = [1, 2, 3, 4];
const doubled = arr.map(x => x * 2);
```

**解释:**

1. **`add(a, b)` 函数:** 当 V8 编译这个函数时，可能会生成如下的 ARM64 指令片段（简化示例）：
   *  `ldr x0, [sp, #offset_a]`  // 加载变量 `a` 的值到寄存器 x0
   *  `ldr x1, [sp, #offset_b]`  // 加载变量 `b` 的值到寄存器 x1
   *  `add x2, x0, x1`          // 将 x0 和 x1 的值相加，结果存储到 x2
   *  `str x2, [sp, #offset_result]` // 将 x2 的值存储到结果变量的位置

   `Instruction::IsLoad()` 会识别前两条 `ldr` 指令为加载操作，`Instruction::IsStore()` 会识别最后一条 `str` 指令为存储操作。

2. **`arr.map(x => x * 2)`:**  对于数组的 `map` 操作，V8 可能会尝试使用 NEON 指令进行优化，例如：
   * `ld1 {v0.4s}, [x0]`   // 从内存加载 4 个单精度浮点数到 NEON 寄存器 v0
   * `fmul v1.4s, v0.4s, #2.0` // 将 v0 中的每个元素乘以 2.0，结果存入 v1
   * `st1 {v1.4s}, [x1]`   // 将 v1 中的值存储回内存

   `NEONFormatDecoder` 就负责解析这些 `ld1`, `fmul`, `st1` 等 NEON 指令，理解它们的操作数类型和向量格式。

**总结:**

`instructions-arm64.cc` 是 V8 引擎在 ARM64 架构上生成和操作机器指令的关键部分。它定义了指令的表示、提供了分析和修改指令的方法，并且专门处理了 ARM64 特有的逻辑立即数和 NEON 指令。 这些功能直接支撑着 V8 将 JavaScript 代码高效地编译成能够在 ARM64 设备上执行的机器码。

Prompt: 
```
这是目录为v8/src/codegen/arm64/instructions-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_ARM64

#include "src/codegen/arm64/instructions-arm64.h"

#include "src/codegen/arm64/assembler-arm64-inl.h"
#include "src/common/code-memory-access-inl.h"

namespace v8 {
namespace internal {

void Instruction::SetInstructionBits(Instr new_instr,
                                     WritableJitAllocation* jit_allocation) {
  // Usually this is aligned, but when de/serializing that's not guaranteed.
  if (jit_allocation) {
    jit_allocation->WriteUnalignedValue(reinterpret_cast<Address>(this),
                                        new_instr);
  } else {
    base::WriteUnalignedValue(reinterpret_cast<Address>(this), new_instr);
  }
}

bool Instruction::IsLoad() const {
  if (Mask(LoadStoreAnyFMask) != LoadStoreAnyFixed) {
    return false;
  }

  if (Mask(LoadStorePairAnyFMask) == LoadStorePairAnyFixed) {
    return Mask(LoadStorePairLBit) != 0;
  } else {
    LoadStoreOp op = static_cast<LoadStoreOp>(Mask(LoadStoreMask));
    switch (op) {
      case LDRB_w:
      case LDRH_w:
      case LDR_w:
      case LDR_x:
      case LDRSB_w:
      case LDRSB_x:
      case LDRSH_w:
      case LDRSH_x:
      case LDRSW_x:
      case LDR_b:
      case LDR_h:
      case LDR_s:
      case LDR_d:
      case LDR_q:
        return true;
      default:
        return false;
    }
  }
}

bool Instruction::IsStore() const {
  if (Mask(LoadStoreAnyFMask) != LoadStoreAnyFixed) {
    return false;
  }

  if (Mask(LoadStorePairAnyFMask) == LoadStorePairAnyFixed) {
    return Mask(LoadStorePairLBit) == 0;
  } else {
    LoadStoreOp op = static_cast<LoadStoreOp>(Mask(LoadStoreMask));
    switch (op) {
      case STRB_w:
      case STRH_w:
      case STR_w:
      case STR_x:
      case STR_b:
      case STR_h:
      case STR_s:
      case STR_d:
      case STR_q:
        return true;
      default:
        return false;
    }
  }
}

static uint64_t RotateRight(uint64_t value, unsigned int rotate,
                            unsigned int width) {
  DCHECK_LE(width, 64);
  rotate &= 63;
  if (rotate == 0) return value;
  return ((value & ((1ULL << rotate) - 1ULL)) << (width - rotate)) |
         (value >> rotate);
}

static uint64_t RepeatBitsAcrossReg(unsigned reg_size, uint64_t value,
                                    unsigned width) {
  DCHECK((width == 2) || (width == 4) || (width == 8) || (width == 16) ||
         (width == 32));
  DCHECK((reg_size == kWRegSizeInBits) || (reg_size == kXRegSizeInBits));
  uint64_t result = value & ((1ULL << width) - 1ULL);
  for (unsigned i = width; i < reg_size; i *= 2) {
    result |= (result << i);
  }
  return result;
}

// Logical immediates can't encode zero, so a return value of zero is used to
// indicate a failure case. Specifically, where the constraints on imm_s are not
// met.
uint64_t Instruction::ImmLogical() {
  unsigned reg_size = SixtyFourBits() ? kXRegSizeInBits : kWRegSizeInBits;
  int32_t n = BitN();
  int32_t imm_s = ImmSetBits();
  int32_t imm_r = ImmRotate();

  // An integer is constructed from the n, imm_s and imm_r bits according to
  // the following table:
  //
  //  N   imms    immr    size        S             R
  //  1  ssssss  rrrrrr    64    UInt(ssssss)  UInt(rrrrrr)
  //  0  0sssss  xrrrrr    32    UInt(sssss)   UInt(rrrrr)
  //  0  10ssss  xxrrrr    16    UInt(ssss)    UInt(rrrr)
  //  0  110sss  xxxrrr     8    UInt(sss)     UInt(rrr)
  //  0  1110ss  xxxxrr     4    UInt(ss)      UInt(rr)
  //  0  11110s  xxxxxr     2    UInt(s)       UInt(r)
  // (s bits must not be all set)
  //
  // A pattern is constructed of size bits, where the least significant S+1
  // bits are set. The pattern is rotated right by R, and repeated across a
  // 32 or 64-bit value, depending on destination register width.
  //

  if (n == 1) {
    if (imm_s == 0x3F) {
      return 0;
    }
    uint64_t bits = (1ULL << (imm_s + 1)) - 1;
    return RotateRight(bits, imm_r, 64);
  } else {
    if ((imm_s >> 1) == 0x1F) {
      return 0;
    }
    for (int width = 0x20; width >= 0x2; width >>= 1) {
      if ((imm_s & width) == 0) {
        int mask = width - 1;
        if ((imm_s & mask) == mask) {
          return 0;
        }
        uint64_t bits = (1ULL << ((imm_s & mask) + 1)) - 1;
        return RepeatBitsAcrossReg(
            reg_size, RotateRight(bits, imm_r & mask, width), width);
      }
    }
  }
  UNREACHABLE();
}

uint32_t Instruction::ImmNEONabcdefgh() const {
  return ImmNEONabc() << 5 | ImmNEONdefgh();
}

float Instruction::ImmFP32() { return Imm8ToFP32(ImmFP()); }

double Instruction::ImmFP64() { return Imm8ToFP64(ImmFP()); }

float Instruction::ImmNEONFP32() const { return Imm8ToFP32(ImmNEONabcdefgh()); }

double Instruction::ImmNEONFP64() const {
  return Imm8ToFP64(ImmNEONabcdefgh());
}

unsigned CalcLSDataSizeLog2(LoadStoreOp op) {
  DCHECK_EQ(LSSize_offset + LSSize_width, kInstrSize * 8);
  unsigned size_log2 = static_cast<Instr>(op) >> LSSize_offset;
  if ((op & LSVector_mask) != 0) {
    // Vector register memory operations encode the access size in the "size"
    // and "opc" fields.
    if (size_log2 == 0 && ((op & LSOpc_mask) >> LSOpc_offset) >= 2) {
      size_log2 = kQRegSizeLog2;
    }
  }
  return size_log2;
}

unsigned CalcLSPairDataSize(LoadStorePairOp op) {
  static_assert(kXRegSize == kDRegSize, "X and D registers must be same size.");
  static_assert(kWRegSize == kSRegSize, "W and S registers must be same size.");
  switch (op) {
    case STP_q:
    case LDP_q:
      return kQRegSizeLog2;
    case STP_x:
    case LDP_x:
    case STP_d:
    case LDP_d:
      return kXRegSizeLog2;
    default:
      return kWRegSizeLog2;
  }
}

int64_t Instruction::ImmPCOffset() {
  int64_t offset;
  if (IsPCRelAddressing()) {
    // PC-relative addressing. Only ADR is supported.
    offset = ImmPCRel();
  } else if (BranchType() != UnknownBranchType) {
    // All PC-relative branches.
    // Relative branch offsets are instruction-size-aligned.
    offset = ImmBranch() * kInstrSize;
  } else if (IsUnresolvedInternalReference()) {
    // Internal references are always word-aligned.
    offset = ImmUnresolvedInternalReference() * kInstrSize;
  } else {
    // Load literal (offset from PC).
    DCHECK(IsLdrLiteral());
    // The offset is always shifted by 2 bits, even for loads to 64-bits
    // registers.
    offset = ImmLLiteral() * kInstrSize;
  }
  return offset;
}

Instruction* Instruction::ImmPCOffsetTarget() {
  return InstructionAtOffset(ImmPCOffset());
}

bool Instruction::IsTargetInImmPCOffsetRange(Instruction* target) {
  return IsValidImmPCOffset(BranchType(), DistanceTo(target));
}

void Instruction::SetImmPCOffsetTarget(Zone* zone, AssemblerOptions options,
                                       Instruction* target) {
  if (IsPCRelAddressing()) {
    SetPCRelImmTarget(zone, options, target);
  } else if (IsCondBranchImm()) {
    SetBranchImmTarget<CondBranchType>(target);
  } else if (IsUncondBranchImm()) {
    SetBranchImmTarget<UncondBranchType>(target);
  } else if (IsCompareBranch()) {
    SetBranchImmTarget<CompareBranchType>(target);
  } else if (IsTestBranch()) {
    SetBranchImmTarget<TestBranchType>(target);
  } else if (IsUnresolvedInternalReference()) {
    SetUnresolvedInternalReferenceImmTarget(zone, options, target);
  } else {
    // Load literal (offset from PC).
    SetImmLLiteral(target);
  }
}

void Instruction::SetPCRelImmTarget(Zone* zone, AssemblerOptions options,
                                    Instruction* target) {
  // ADRP is not supported, so 'this' must point to an ADR instruction.
  DCHECK(IsAdr());

  ptrdiff_t target_offset = DistanceTo(target);
  Instr imm;
  if (Instruction::IsValidPCRelOffset(target_offset)) {
    imm = Assembler::ImmPCRelAddress(static_cast<int>(target_offset));
    SetInstructionBits(Mask(~ImmPCRel_mask) | imm);
  } else {
    PatchingAssembler patcher(zone, options, reinterpret_cast<uint8_t*>(this),
                              PatchingAssembler::kAdrFarPatchableNInstrs);
    patcher.PatchAdrFar(target_offset);
  }
}

void Instruction::SetUnresolvedInternalReferenceImmTarget(
    Zone* zone, AssemblerOptions options, Instruction* target) {
  DCHECK(IsUnresolvedInternalReference());
  DCHECK(IsAligned(DistanceTo(target), kInstrSize));
  DCHECK(is_int32(DistanceTo(target) >> kInstrSizeLog2));
  int32_t target_offset =
      static_cast<int32_t>(DistanceTo(target) >> kInstrSizeLog2);
  uint32_t high16 = unsigned_bitextract_32(31, 16, target_offset);
  uint32_t low16 = unsigned_bitextract_32(15, 0, target_offset);

  PatchingAssembler patcher(zone, options, reinterpret_cast<uint8_t*>(this), 2);
  patcher.brk(high16);
  patcher.brk(low16);
}

void Instruction::SetImmLLiteral(Instruction* source) {
  DCHECK(IsLdrLiteral());
  DCHECK(IsAligned(DistanceTo(source), kInstrSize));
  DCHECK(Assembler::IsImmLLiteral(DistanceTo(source)));
  Instr imm = Assembler::ImmLLiteral(
      static_cast<int>(DistanceTo(source) >> kLoadLiteralScaleLog2));
  Instr mask = ImmLLiteral_mask;

  SetInstructionBits(Mask(~mask) | imm);
}

NEONFormatDecoder::NEONFormatDecoder(const Instruction* instr) {
  instrbits_ = instr->InstructionBits();
  SetFormatMaps(IntegerFormatMap());
}

NEONFormatDecoder::NEONFormatDecoder(const Instruction* instr,
                                     const NEONFormatMap* format) {
  instrbits_ = instr->InstructionBits();
  SetFormatMaps(format);
}

NEONFormatDecoder::NEONFormatDecoder(const Instruction* instr,
                                     const NEONFormatMap* format0,
                                     const NEONFormatMap* format1) {
  instrbits_ = instr->InstructionBits();
  SetFormatMaps(format0, format1);
}

NEONFormatDecoder::NEONFormatDecoder(const Instruction* instr,
                                     const NEONFormatMap* format0,
                                     const NEONFormatMap* format1,
                                     const NEONFormatMap* format2) {
  instrbits_ = instr->InstructionBits();
  SetFormatMaps(format0, format1, format2);
}

void NEONFormatDecoder::SetFormatMaps(const NEONFormatMap* format0,
                                      const NEONFormatMap* format1,
                                      const NEONFormatMap* format2) {
  DCHECK_NOT_NULL(format0);
  formats_[0] = format0;
  formats_[1] = (format1 == nullptr) ? formats_[0] : format1;
  formats_[2] = (format2 == nullptr) ? formats_[1] : format2;
  // Support four parameters form (e.i. ld4r)
  // to avoid using positional arguments in DisassemblingDecoder.
  // See: https://crbug.com/v8/10365
  formats_[3] = formats_[2];
}

void NEONFormatDecoder::SetFormatMap(unsigned index,
                                     const NEONFormatMap* format) {
  DCHECK_LT(index, arraysize(formats_));
  DCHECK_NOT_NULL(format);
  formats_[index] = format;
}

const char* NEONFormatDecoder::SubstitutePlaceholders(const char* string) {
  return Substitute(string, kPlaceholder, kPlaceholder, kPlaceholder,
                    kPlaceholder);
}

const char* NEONFormatDecoder::Substitute(const char* string,
                                          SubstitutionMode mode0,
                                          SubstitutionMode mode1,
                                          SubstitutionMode mode2,
                                          SubstitutionMode mode3) {
  snprintf(form_buffer_, sizeof(form_buffer_), string, GetSubstitute(0, mode0),
           GetSubstitute(1, mode1), GetSubstitute(2, mode2),
           GetSubstitute(3, mode3));
  return form_buffer_;
}

const char* NEONFormatDecoder::Mnemonic(const char* mnemonic) {
  if ((instrbits_ & NEON_Q) != 0) {
    snprintf(mne_buffer_, sizeof(mne_buffer_), "%s2", mnemonic);
    return mne_buffer_;
  }
  return mnemonic;
}

VectorFormat NEONFormatDecoder::GetVectorFormat(int format_index) {
  return GetVectorFormat(formats_[format_index]);
}

VectorFormat NEONFormatDecoder::GetVectorFormat(
    const NEONFormatMap* format_map) {
  static const VectorFormat vform[] = {
      kFormatUndefined, kFormat8B, kFormat16B, kFormat4H, kFormat8H,
      kFormat2S,        kFormat4S, kFormat1D,  kFormat2D, kFormatB,
      kFormatH,         kFormatS,  kFormatD};
  DCHECK_LT(GetNEONFormat(format_map), arraysize(vform));
  return vform[GetNEONFormat(format_map)];
}

const char* NEONFormatDecoder::GetSubstitute(int index, SubstitutionMode mode) {
  if (mode == kFormat) {
    return NEONFormatAsString(GetNEONFormat(formats_[index]));
  }
  DCHECK_EQ(mode, kPlaceholder);
  return NEONFormatAsPlaceholder(GetNEONFormat(formats_[index]));
}

NEONFormat NEONFormatDecoder::GetNEONFormat(const NEONFormatMap* format_map) {
  return format_map->map[PickBits(format_map->bits)];
}

const char* NEONFormatDecoder::NEONFormatAsString(NEONFormat format) {
  static const char* formats[] = {"undefined", "8b", "16b", "4h", "8h",
                                  "2s",        "4s", "1d",  "2d", "b",
                                  "h",         "s",  "d"};
  DCHECK_LT(format, arraysize(formats));
  return formats[format];
}

const char* NEONFormatDecoder::NEONFormatAsPlaceholder(NEONFormat format) {
  DCHECK((format == NF_B) || (format == NF_H) || (format == NF_S) ||
         (format == NF_D) || (format == NF_UNDEF));
  static const char* formats[] = {
      "undefined", "undefined", "undefined", "undefined", "undefined",
      "undefined", "undefined", "undefined", "undefined", "'B",
      "'H",        "'S",        "'D"};
  return formats[format];
}

uint8_t NEONFormatDecoder::PickBits(const uint8_t bits[]) {
  uint8_t result = 0;
  for (unsigned b = 0; b < kNEONFormatMaxBits; b++) {
    if (bits[b] == 0) break;
    result <<= 1;
    result |= ((instrbits_ & (1 << bits[b])) == 0) ? 0 : 1;
  }
  return result;
}
}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_ARM64

"""

```