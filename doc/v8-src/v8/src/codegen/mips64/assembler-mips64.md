Response: The user wants me to summarize the functionality of the provided C++ code snippet.
This is the first part of a three-part file.
The code is part of the V8 JavaScript engine and seems to be related to the MIPS64 architecture.
It likely defines the assembler for generating MIPS64 machine code.

Key areas I see:
- Copyright and License information.
- Includes for necessary headers.
- Namespace declaration (`v8::internal`).
- Functions related to CPU feature detection.
- Functions to convert between register names and numbers.
- Implementation of `RelocInfo` for relocation information.
- Implementation of `Operand` and `MemOperand` for representing operands.
- Definitions of specific MIPS64 instruction patterns and masks.
- The `Assembler` class constructor and methods for code generation.
- Methods for aligning code, getting register information from instructions, and checking instruction types.
- Implementation of labels for branching.
- Functions for getting and setting target addresses of branches and jumps.
- Methods for binding labels and calculating branch distances.
- Helper functions for generating various MIPS64 instructions.
这个C++源代码文件是V8 JavaScript引擎针对MIPS64架构的汇编器（Assembler）的实现。它的主要功能是：

1. **提供用于生成MIPS64机器码的接口:**  它定义了 `Assembler` 类，该类提供了各种方法来生成不同的MIPS64指令。这些方法是对底层机器指令的抽象，使得在V8的编译过程中可以方便地生成目标平台的机器码。

2. **处理CPU特性:** 代码包含了检测和管理MIPS64 CPU特性的逻辑，例如是否支持浮点单元（FPU）和SIMD指令集（MSA）。这使得V8可以根据目标CPU的功能生成优化的代码。

3. **管理代码重定位信息:**  `RelocInfo` 类用于记录需要进行重定位的信息，例如嵌入的对象引用和外部函数调用地址。这对于代码在内存中的加载和执行至关重要。

4. **表示操作数:** `Operand` 和 `MemOperand` 类用于表示指令的操作数，包括寄存器、立即数和内存地址。

5. **定义指令常量和模式:** 代码中定义了一些常用的MIPS64指令常量和模式，方便在汇编器中使用和识别。

6. **支持代码标签 (Labels):**  `Label` 类用于表示代码中的跳转目标，汇编器允许在生成代码时先使用未绑定的标签，然后在后续绑定到实际的代码位置。

7. **实现长跳转和分支:**  代码处理了MIPS64架构中可能出现的短跳转范围限制，并提供了机制来生成长跳转指令，确保跳转目标在有效范围内。

8. **支持原子操作:**  虽然在这部分代码中没有显式看到原子操作的指令，但作为汇编器，它最终会支持生成这些指令。

**与JavaScript的功能的关系以及JavaScript示例:**

该汇编器是V8 JavaScript引擎的核心组件之一，负责将JavaScript代码编译成可以在MIPS64架构上执行的机器码。

**JavaScript示例:**

假设有以下简单的JavaScript代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当V8编译这段JavaScript代码时，`assembler-mips64.cc` 中的 `Assembler` 类会被用来生成对应的MIPS64机器码。例如，对于 `a + b` 这个加法操作，可能会生成如下的MIPS64指令序列（这只是一个简化的例子，实际情况会更复杂）：

```assembly
  // 假设 a 和 b 的值分别在寄存器 $t0 和 $t1 中
  addu  $v0, $t0, $t1  // 将 $t0 和 $t1 的值相加，结果存储到 $v0
  jr    $ra            // 返回
```

在这个例子中，`addu` 指令就是由 `Assembler` 类中的某个方法生成的，它直接对应了JavaScript中的加法操作。  `jr $ra` 指令也是汇编器生成用来返回的指令。

**总结来说， `assembler-mips64.cc` 这个文件是V8引擎将JavaScript代码转化为MIPS64机器码的关键组成部分，它提供了生成和管理底层机器指令的能力，使得JavaScript代码可以在MIPS64架构的处理器上高效执行。**

Prompt: 
```
这是目录为v8/src/codegen/mips64/assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright (c) 1994-2006 Sun Microsystems Inc.
// All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// - Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// - Redistribution in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// - Neither the name of Sun Microsystems or the names of contributors may
// be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// The original source code covered by the above license above has been
// modified significantly by Google Inc.
// Copyright 2012 the V8 project authors. All rights reserved.

#include "src/codegen/mips64/assembler-mips64.h"

#if V8_TARGET_ARCH_MIPS64

#include "src/base/cpu.h"
#include "src/codegen/flush-instruction-cache.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/mips64/assembler-mips64-inl.h"
#include "src/codegen/safepoint-table.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/objects/heap-number-inl.h"

namespace v8 {
namespace internal {

// Get the CPU features enabled by the build. For cross compilation the
// preprocessor symbols CAN_USE_FPU_INSTRUCTIONS
// can be defined to enable FPU instructions when building the
// snapshot.
static unsigned CpuFeaturesImpliedByCompiler() {
  unsigned answer = 0;
#ifdef CAN_USE_FPU_INSTRUCTIONS
  answer |= 1u << FPU;
#endif  // def CAN_USE_FPU_INSTRUCTIONS

  // If the compiler is allowed to use FPU then we can use FPU too in our code
  // generation even when generating snapshots.  This won't work for cross
  // compilation.
#if defined(__mips__) && defined(__mips_hard_float) && __mips_hard_float != 0
  answer |= 1u << FPU;
#endif

  return answer;
}

bool CpuFeatures::SupportsWasmSimd128() { return IsSupported(MIPS_SIMD); }

void CpuFeatures::ProbeImpl(bool cross_compile) {
  supported_ |= CpuFeaturesImpliedByCompiler();

  // Only use statically determined features for cross compile (snapshot).
  if (cross_compile) return;

    // If the compiler is allowed to use fpu then we can use fpu too in our
    // code generation.
#ifndef __mips__
  // For the simulator build, use FPU.
  supported_ |= 1u << FPU;
#if defined(_MIPS_ARCH_MIPS64R6) && defined(_MIPS_MSA)
  supported_ |= 1u << MIPS_SIMD;
#endif
#else
  // Probe for additional features at runtime.
  base::CPU cpu;
  if (cpu.has_fpu()) supported_ |= 1u << FPU;
#if defined(_MIPS_MSA)
  supported_ |= 1u << MIPS_SIMD;
#else
  if (cpu.has_msa()) supported_ |= 1u << MIPS_SIMD;
#endif
#endif

  // Set a static value on whether Simd is supported.
  // This variable is only used for certain archs to query SupportWasmSimd128()
  // at runtime in builtins using an extern ref. Other callers should use
  // CpuFeatures::SupportWasmSimd128().
  CpuFeatures::supports_wasm_simd_128_ = CpuFeatures::SupportsWasmSimd128();
}

void CpuFeatures::PrintTarget() {}
void CpuFeatures::PrintFeatures() {}

int ToNumber(Register reg) {
  DCHECK(reg.is_valid());
  const int kNumbers[] = {
      0,   // zero_reg
      1,   // at
      2,   // v0
      3,   // v1
      4,   // a0
      5,   // a1
      6,   // a2
      7,   // a3
      8,   // a4
      9,   // a5
      10,  // a6
      11,  // a7
      12,  // t0
      13,  // t1
      14,  // t2
      15,  // t3
      16,  // s0
      17,  // s1
      18,  // s2
      19,  // s3
      20,  // s4
      21,  // s5
      22,  // s6
      23,  // s7
      24,  // t8
      25,  // t9
      26,  // k0
      27,  // k1
      28,  // gp
      29,  // sp
      30,  // fp
      31,  // ra
  };
  return kNumbers[reg.code()];
}

Register ToRegister(int num) {
  DCHECK(num >= 0 && num < kNumRegisters);
  const Register kRegisters[] = {
      zero_reg, at, v0, v1, a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2, t3,
      s0,       s1, s2, s3, s4, s5, s6, s7, t8, t9, k0, k1, gp, sp, fp, ra};
  return kRegisters[num];
}

// -----------------------------------------------------------------------------
// Implementation of RelocInfo.

const int RelocInfo::kApplyMask =
    RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
    RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE_ENCODED);

bool RelocInfo::IsCodedSpecially() {
  // The deserializer needs to know whether a pointer is specially coded.  Being
  // specially coded on MIPS means that it is a lui/ori instruction, and that is
  // always the case inside code objects.
  return true;
}

bool RelocInfo::IsInConstantPool() { return false; }

uint32_t RelocInfo::wasm_call_tag() const {
  DCHECK(rmode_ == WASM_CALL || rmode_ == WASM_STUB_CALL);
  return static_cast<uint32_t>(
      Assembler::target_address_at(pc_, constant_pool_));
}

// -----------------------------------------------------------------------------
// Implementation of Operand and MemOperand.
// See assembler-mips-inl.h for inlined constructors.

Operand::Operand(Handle<HeapObject> handle)
    : rm_(no_reg), rmode_(RelocInfo::FULL_EMBEDDED_OBJECT) {
  value_.immediate = static_cast<intptr_t>(handle.address());
}

Operand Operand::EmbeddedNumber(double value) {
  int32_t smi;
  if (DoubleToSmiInteger(value, &smi)) return Operand(Smi::FromInt(smi));
  Operand result(0, RelocInfo::FULL_EMBEDDED_OBJECT);
  result.is_heap_number_request_ = true;
  result.value_.heap_number_request = HeapNumberRequest(value);
  return result;
}

MemOperand::MemOperand(Register rm, int32_t offset) : Operand(rm) {
  offset_ = offset;
}

MemOperand::MemOperand(Register rm, int32_t unit, int32_t multiplier,
                       OffsetAddend offset_addend)
    : Operand(rm) {
  offset_ = unit * multiplier + offset_addend;
}

void Assembler::AllocateAndInstallRequestedHeapNumbers(LocalIsolate* isolate) {
  DCHECK_IMPLIES(isolate == nullptr, heap_number_requests_.empty());
  for (auto& request : heap_number_requests_) {
    Handle<HeapObject> object;
    object = isolate->factory()->NewHeapNumber<AllocationType::kOld>(
        request.heap_number());
    Address pc = reinterpret_cast<Address>(buffer_start_) + request.offset();
    set_target_value_at(pc, reinterpret_cast<uint64_t>(object.location()));
  }
}

// -----------------------------------------------------------------------------
// Specific instructions, constants, and masks.

// daddiu(sp, sp, 8) aka Pop() operation or part of Pop(r)
// operations as post-increment of sp.
const Instr kPopInstruction = DADDIU | (sp.code() << kRsShift) |
                              (sp.code() << kRtShift) |
                              (kPointerSize & kImm16Mask);
// daddiu(sp, sp, -8) part of Push(r) operation as pre-decrement of sp.
const Instr kPushInstruction = DADDIU | (sp.code() << kRsShift) |
                               (sp.code() << kRtShift) |
                               (-kPointerSize & kImm16Mask);
// Sd(r, MemOperand(sp, 0))
const Instr kPushRegPattern = SD | (sp.code() << kRsShift) | (0 & kImm16Mask);
//  Ld(r, MemOperand(sp, 0))
const Instr kPopRegPattern = LD | (sp.code() << kRsShift) | (0 & kImm16Mask);

const Instr kLwRegFpOffsetPattern =
    LW | (fp.code() << kRsShift) | (0 & kImm16Mask);

const Instr kSwRegFpOffsetPattern =
    SW | (fp.code() << kRsShift) | (0 & kImm16Mask);

const Instr kLwRegFpNegOffsetPattern =
    LW | (fp.code() << kRsShift) | (kNegOffset & kImm16Mask);

const Instr kSwRegFpNegOffsetPattern =
    SW | (fp.code() << kRsShift) | (kNegOffset & kImm16Mask);
// A mask for the Rt register for push, pop, lw, sw instructions.
const Instr kRtMask = kRtFieldMask;
const Instr kLwSwInstrTypeMask = 0xFFE00000;
const Instr kLwSwInstrArgumentMask = ~kLwSwInstrTypeMask;
const Instr kLwSwOffsetMask = kImm16Mask;

Assembler::Assembler(const AssemblerOptions& options,
                     std::unique_ptr<AssemblerBuffer> buffer)
    : AssemblerBase(options, std::move(buffer)),
      scratch_register_list_({at, s0}) {
  if (CpuFeatures::IsSupported(MIPS_SIMD)) {
    EnableCpuFeature(MIPS_SIMD);
  }
  reloc_info_writer.Reposition(buffer_start_ + buffer_->size(), pc_);

  last_trampoline_pool_end_ = 0;
  no_trampoline_pool_before_ = 0;
  trampoline_pool_blocked_nesting_ = 0;
  // We leave space (16 * kTrampolineSlotsSize)
  // for BlockTrampolinePoolScope buffer.
  next_buffer_check_ = v8_flags.force_long_branches
                           ? kMaxInt
                           : kMaxBranchOffset - kTrampolineSlotsSize * 16;
  internal_trampoline_exception_ = false;
  last_bound_pos_ = 0;

  trampoline_emitted_ = v8_flags.force_long_branches;
  unbound_labels_count_ = 0;
  block_buffer_growth_ = false;
}

void Assembler::GetCode(Isolate* isolate, CodeDesc* desc) {
  GetCode(isolate->main_thread_local_isolate(), desc);
}
void Assembler::GetCode(LocalIsolate* isolate, CodeDesc* desc,
                        SafepointTableBuilderBase* safepoint_table_builder,
                        int handler_table_offset) {
  // As a crutch to avoid having to add manual Align calls wherever we use a
  // raw workflow to create InstructionStream objects (mostly in tests), add
  // another Align call here. It does no harm - the end of the InstructionStream
  // object is aligned to the (larger) kCodeAlignment anyways.
  // TODO(jgruber): Consider moving responsibility for proper alignment to
  // metadata table builders (safepoint, handler, constant pool, code
  // comments).
  DataAlign(InstructionStream::kMetadataAlignment);

  EmitForbiddenSlotInstruction();

  int code_comments_size = WriteCodeComments();

  DCHECK(pc_ <= reloc_info_writer.pos());  // No overlap.

  AllocateAndInstallRequestedHeapNumbers(isolate);

  // Set up code descriptor.
  // TODO(jgruber): Reconsider how these offsets and sizes are maintained up to
  // this point to make CodeDesc initialization less fiddly.

  static constexpr int kConstantPoolSize = 0;
  static constexpr int kBuiltinJumpTableInfoSize = 0;
  const int instruction_size = pc_offset();
  const int builtin_jump_table_info_offset =
      instruction_size - kBuiltinJumpTableInfoSize;
  const int code_comments_offset =
      builtin_jump_table_info_offset - code_comments_size;
  const int constant_pool_offset = code_comments_offset - kConstantPoolSize;
  const int handler_table_offset2 = (handler_table_offset == kNoHandlerTable)
                                        ? constant_pool_offset
                                        : handler_table_offset;
  const int safepoint_table_offset =
      (safepoint_table_builder == kNoSafepointTable)
          ? handler_table_offset2
          : safepoint_table_builder->safepoint_table_offset();
  const int reloc_info_offset =
      static_cast<int>(reloc_info_writer.pos() - buffer_->start());
  CodeDesc::Initialize(desc, this, safepoint_table_offset,
                       handler_table_offset2, constant_pool_offset,
                       code_comments_offset, builtin_jump_table_info_offset,
                       reloc_info_offset);
}

void Assembler::Align(int m) {
  DCHECK(m >= 4 && base::bits::IsPowerOfTwo(m));
  EmitForbiddenSlotInstruction();
  while ((pc_offset() & (m - 1)) != 0) {
    nop();
  }
}

void Assembler::CodeTargetAlign() {
  // No advantage to aligning branch/call targets to more than
  // single instruction, that I am aware of.
  Align(4);
}

Register Assembler::GetRtReg(Instr instr) {
  return Register::from_code((instr & kRtFieldMask) >> kRtShift);
}

Register Assembler::GetRsReg(Instr instr) {
  return Register::from_code((instr & kRsFieldMask) >> kRsShift);
}

Register Assembler::GetRdReg(Instr instr) {
  return Register::from_code((instr & kRdFieldMask) >> kRdShift);
}

uint32_t Assembler::GetRt(Instr instr) {
  return (instr & kRtFieldMask) >> kRtShift;
}

uint32_t Assembler::GetRtField(Instr instr) { return instr & kRtFieldMask; }

uint32_t Assembler::GetRs(Instr instr) {
  return (instr & kRsFieldMask) >> kRsShift;
}

uint32_t Assembler::GetRsField(Instr instr) { return instr & kRsFieldMask; }

uint32_t Assembler::GetRd(Instr instr) {
  return (instr & kRdFieldMask) >> kRdShift;
}

uint32_t Assembler::GetRdField(Instr instr) { return instr & kRdFieldMask; }

uint32_t Assembler::GetSa(Instr instr) {
  return (instr & kSaFieldMask) >> kSaShift;
}

uint32_t Assembler::GetSaField(Instr instr) { return instr & kSaFieldMask; }

uint32_t Assembler::GetOpcodeField(Instr instr) { return instr & kOpcodeMask; }

uint32_t Assembler::GetFunction(Instr instr) {
  return (instr & kFunctionFieldMask) >> kFunctionShift;
}

uint32_t Assembler::GetFunctionField(Instr instr) {
  return instr & kFunctionFieldMask;
}

uint32_t Assembler::GetImmediate16(Instr instr) { return instr & kImm16Mask; }

uint32_t Assembler::GetLabelConst(Instr instr) { return instr & ~kImm16Mask; }

bool Assembler::IsPop(Instr instr) {
  return (instr & ~kRtMask) == kPopRegPattern;
}

bool Assembler::IsPush(Instr instr) {
  return (instr & ~kRtMask) == kPushRegPattern;
}

bool Assembler::IsSwRegFpOffset(Instr instr) {
  return ((instr & kLwSwInstrTypeMask) == kSwRegFpOffsetPattern);
}

bool Assembler::IsLwRegFpOffset(Instr instr) {
  return ((instr & kLwSwInstrTypeMask) == kLwRegFpOffsetPattern);
}

bool Assembler::IsSwRegFpNegOffset(Instr instr) {
  return ((instr & (kLwSwInstrTypeMask | kNegOffset)) ==
          kSwRegFpNegOffsetPattern);
}

bool Assembler::IsLwRegFpNegOffset(Instr instr) {
  return ((instr & (kLwSwInstrTypeMask | kNegOffset)) ==
          kLwRegFpNegOffsetPattern);
}

// Labels refer to positions in the (to be) generated code.
// There are bound, linked, and unused labels.
//
// Bound labels refer to known positions in the already
// generated code. pos() is the position the label refers to.
//
// Linked labels refer to unknown positions in the code
// to be generated; pos() is the position of the last
// instruction using the label.

// The link chain is terminated by a value in the instruction of -1,
// which is an otherwise illegal value (branch -1 is inf loop).
// The instruction 16-bit offset field addresses 32-bit words, but in
// code is conv to an 18-bit value addressing bytes, hence the -4 value.

const int kEndOfChain = -4;
// Determines the end of the Jump chain (a subset of the label link chain).
const int kEndOfJumpChain = 0;

bool Assembler::IsMsaBranch(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  uint32_t rs_field = GetRsField(instr);
  if (opcode == COP1) {
    switch (rs_field) {
      case BZ_V:
      case BZ_B:
      case BZ_H:
      case BZ_W:
      case BZ_D:
      case BNZ_V:
      case BNZ_B:
      case BNZ_H:
      case BNZ_W:
      case BNZ_D:
        return true;
      default:
        return false;
    }
  } else {
    return false;
  }
}

bool Assembler::IsBranch(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  uint32_t rt_field = GetRtField(instr);
  uint32_t rs_field = GetRsField(instr);
  // Checks if the instruction is a branch.
  bool isBranch =
      opcode == BEQ || opcode == BNE || opcode == BLEZ || opcode == BGTZ ||
      opcode == BEQL || opcode == BNEL || opcode == BLEZL || opcode == BGTZL ||
      (opcode == REGIMM && (rt_field == BLTZ || rt_field == BGEZ ||
                            rt_field == BLTZAL || rt_field == BGEZAL)) ||
      (opcode == COP1 && rs_field == BC1) ||  // Coprocessor branch.
      (opcode == COP1 && rs_field == BC1EQZ) ||
      (opcode == COP1 && rs_field == BC1NEZ) || IsMsaBranch(instr);
  if (!isBranch && kArchVariant == kMips64r6) {
    // All the 3 variants of POP10 (BOVC, BEQC, BEQZALC) and
    // POP30 (BNVC, BNEC, BNEZALC) are branch ops.
    isBranch |= opcode == POP10 || opcode == POP30 || opcode == BC ||
                opcode == BALC ||
                (opcode == POP66 && rs_field != 0) ||  // BEQZC
                (opcode == POP76 && rs_field != 0);    // BNEZC
  }
  return isBranch;
}

bool Assembler::IsBc(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  // Checks if the instruction is a BC or BALC.
  return opcode == BC || opcode == BALC;
}

bool Assembler::IsNal(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  uint32_t rt_field = GetRtField(instr);
  uint32_t rs_field = GetRsField(instr);
  return opcode == REGIMM && rt_field == BLTZAL && rs_field == 0;
}

bool Assembler::IsBzc(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  // Checks if the instruction is BEQZC or BNEZC.
  return (opcode == POP66 && GetRsField(instr) != 0) ||
         (opcode == POP76 && GetRsField(instr) != 0);
}

bool Assembler::IsEmittedConstant(Instr instr) {
  uint32_t label_constant = GetLabelConst(instr);
  return label_constant == 0;  // Emitted label const in reg-exp engine.
}

bool Assembler::IsBeq(Instr instr) { return GetOpcodeField(instr) == BEQ; }

bool Assembler::IsBne(Instr instr) { return GetOpcodeField(instr) == BNE; }

bool Assembler::IsBeqzc(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  return opcode == POP66 && GetRsField(instr) != 0;
}

bool Assembler::IsBnezc(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  return opcode == POP76 && GetRsField(instr) != 0;
}

bool Assembler::IsBeqc(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  uint32_t rs = GetRsField(instr);
  uint32_t rt = GetRtField(instr);
  return opcode == POP10 && rs != 0 && rs < rt;  // && rt != 0
}

bool Assembler::IsBnec(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  uint32_t rs = GetRsField(instr);
  uint32_t rt = GetRtField(instr);
  return opcode == POP30 && rs != 0 && rs < rt;  // && rt != 0
}

bool Assembler::IsMov(Instr instr, Register rd, Register rs) {
  uint32_t opcode = GetOpcodeField(instr);
  uint32_t rd_field = GetRd(instr);
  uint32_t rs_field = GetRs(instr);
  uint32_t rt_field = GetRt(instr);
  uint32_t rd_reg = static_cast<uint32_t>(rd.code());
  uint32_t rs_reg = static_cast<uint32_t>(rs.code());
  uint32_t function_field = GetFunctionField(instr);
  // Checks if the instruction is an OR with zero_reg argument (aka MOV).
  bool res = opcode == SPECIAL && function_field == OR && rd_field == rd_reg &&
             rs_field == rs_reg && rt_field == 0;
  return res;
}

bool Assembler::IsJump(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  uint32_t rt_field = GetRtField(instr);
  uint32_t rd_field = GetRdField(instr);
  uint32_t function_field = GetFunctionField(instr);
  // Checks if the instruction is a jump.
  return opcode == J || opcode == JAL ||
         (opcode == SPECIAL && rt_field == 0 &&
          ((function_field == JALR) ||
           (rd_field == 0 && (function_field == JR))));
}

bool Assembler::IsJ(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  // Checks if the instruction is a jump.
  return opcode == J;
}

bool Assembler::IsJal(Instr instr) { return GetOpcodeField(instr) == JAL; }

bool Assembler::IsJr(Instr instr) {
  return GetOpcodeField(instr) == SPECIAL && GetFunctionField(instr) == JR;
}

bool Assembler::IsJalr(Instr instr) {
  return GetOpcodeField(instr) == SPECIAL && GetFunctionField(instr) == JALR;
}

bool Assembler::IsLui(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  // Checks if the instruction is a load upper immediate.
  return opcode == LUI;
}

bool Assembler::IsOri(Instr instr) {
  uint32_t opcode = GetOpcodeField(instr);
  // Checks if the instruction is a load upper immediate.
  return opcode == ORI;
}

bool Assembler::IsNop(Instr instr, unsigned int type) {
  // See Assembler::nop(type).
  DCHECK_LT(type, 32);
  uint32_t opcode = GetOpcodeField(instr);
  uint32_t function = GetFunctionField(instr);
  uint32_t rt = GetRt(instr);
  uint32_t rd = GetRd(instr);
  uint32_t sa = GetSa(instr);

  // Traditional mips nop == sll(zero_reg, zero_reg, 0)
  // When marking non-zero type, use sll(zero_reg, at, type)
  // to avoid use of mips ssnop and ehb special encodings
  // of the sll instruction.

  Register nop_rt_reg = (type == 0) ? zero_reg : at;
  bool ret = (opcode == SPECIAL && function == SLL &&
              rd == static_cast<uint32_t>(ToNumber(zero_reg)) &&
              rt == static_cast<uint32_t>(ToNumber(nop_rt_reg)) && sa == type);

  return ret;
}

int32_t Assembler::GetBranchOffset(Instr instr) {
  DCHECK(IsBranch(instr));
  return (static_cast<int16_t>(instr & kImm16Mask)) << 2;
}

bool Assembler::IsLw(Instr instr) {
  return (static_cast<uint32_t>(instr & kOpcodeMask) == LW);
}

int16_t Assembler::GetLwOffset(Instr instr) {
  DCHECK(IsLw(instr));
  return ((instr & kImm16Mask));
}

Instr Assembler::SetLwOffset(Instr instr, int16_t offset) {
  DCHECK(IsLw(instr));

  // We actually create a new lw instruction based on the original one.
  Instr temp_instr = LW | (instr & kRsFieldMask) | (instr & kRtFieldMask) |
                     (offset & kImm16Mask);

  return temp_instr;
}

bool Assembler::IsSw(Instr instr) {
  return (static_cast<uint32_t>(instr & kOpcodeMask) == SW);
}

Instr Assembler::SetSwOffset(Instr instr, int16_t offset) {
  DCHECK(IsSw(instr));
  return ((instr & ~kImm16Mask) | (offset & kImm16Mask));
}

bool Assembler::IsAddImmediate(Instr instr) {
  return ((instr & kOpcodeMask) == ADDIU || (instr & kOpcodeMask) == DADDIU);
}

Instr Assembler::SetAddImmediateOffset(Instr instr, int16_t offset) {
  DCHECK(IsAddImmediate(instr));
  return ((instr & ~kImm16Mask) | (offset & kImm16Mask));
}

bool Assembler::IsAndImmediate(Instr instr) {
  return GetOpcodeField(instr) == ANDI;
}

static Assembler::OffsetSize OffsetSizeInBits(Instr instr) {
  if (kArchVariant == kMips64r6) {
    if (Assembler::IsBc(instr)) {
      return Assembler::OffsetSize::kOffset26;
    } else if (Assembler::IsBzc(instr)) {
      return Assembler::OffsetSize::kOffset21;
    }
  }
  return Assembler::OffsetSize::kOffset16;
}

static inline int32_t AddBranchOffset(int pos, Instr instr) {
  int bits = OffsetSizeInBits(instr);
  const int32_t mask = (1 << bits) - 1;
  bits = 32 - bits;

  // Do NOT change this to <<2. We rely on arithmetic shifts here, assuming
  // the compiler uses arithmetic shifts for signed integers.
  int32_t imm = ((instr & mask) << bits) >> (bits - 2);

  if (imm == kEndOfChain) {
    // EndOfChain sentinel is returned directly, not relative to pc or pos.
    return kEndOfChain;
  } else {
    return pos + Assembler::kBranchPCOffset + imm;
  }
}

int Assembler::target_at(int pos, bool is_internal) {
  if (is_internal) {
    int64_t* p = reinterpret_cast<int64_t*>(buffer_start_ + pos);
    int64_t address = *p;
    if (address == kEndOfJumpChain) {
      return kEndOfChain;
    } else {
      int64_t instr_address = reinterpret_cast<int64_t>(p);
      DCHECK(instr_address - address < INT_MAX);
      int delta = static_cast<int>(instr_address - address);
      DCHECK(pos > delta);
      return pos - delta;
    }
  }
  Instr instr = instr_at(pos);
  if ((instr & ~kImm16Mask) == 0) {
    // Emitted label constant, not part of a branch.
    if (instr == 0) {
      return kEndOfChain;
    } else {
      int32_t imm18 = ((instr & static_cast<int32_t>(kImm16Mask)) << 16) >> 14;
      return (imm18 + pos);
    }
  }
  // Check we have a branch or jump instruction.
  DCHECK(IsBranch(instr) || IsJ(instr) || IsJal(instr) || IsLui(instr) ||
         IsMov(instr, t8, ra));
  // Do NOT change this to <<2. We rely on arithmetic shifts here, assuming
  // the compiler uses arithmetic shifts for signed integers.
  if (IsBranch(instr)) {
    return AddBranchOffset(pos, instr);
  } else if (IsMov(instr, t8, ra)) {
    int32_t imm32;
    if (IsAddImmediate(instr_at(pos + kInstrSize))) {
      Instr instr_daddiu = instr_at(pos + kInstrSize);
      imm32 = instr_daddiu & static_cast<int32_t>(kImm16Mask);
      imm32 = (imm32 << 16) >> 16;
      return imm32;
    }

    Instr instr_lui = instr_at(pos + 2 * kInstrSize);
    Instr instr_ori = instr_at(pos + 3 * kInstrSize);
    DCHECK(IsLui(instr_lui));
    DCHECK(IsOri(instr_ori));
    imm32 = (instr_lui & static_cast<int32_t>(kImm16Mask)) << kLuiShift;
    imm32 |= (instr_ori & static_cast<int32_t>(kImm16Mask));
    if (imm32 == kEndOfJumpChain) {
      // EndOfChain sentinel is returned directly, not relative to pc or pos.
      return kEndOfChain;
    }
    return pos + Assembler::kLongBranchPCOffset + imm32;
  } else if (IsLui(instr)) {
    if (IsNal(instr_at(pos + kInstrSize))) {
      int32_t imm32;
      Instr instr_lui = instr_at(pos + 0 * kInstrSize);
      Instr instr_ori = instr_at(pos + 2 * kInstrSize);
      DCHECK(IsLui(instr_lui));
      DCHECK(IsOri(instr_ori));
      imm32 = (instr_lui & static_cast<int32_t>(kImm16Mask)) << kLuiShift;
      imm32 |= (instr_ori & static_cast<int32_t>(kImm16Mask));
      if (imm32 == kEndOfJumpChain) {
        // EndOfChain sentinel is returned directly, not relative to pc or pos.
        return kEndOfChain;
      }
      return pos + Assembler::kLongBranchPCOffset + imm32;
    } else {
      Instr instr_lui = instr_at(pos + 0 * kInstrSize);
      Instr instr_ori = instr_at(pos + 1 * kInstrSize);
      Instr instr_ori2 = instr_at(pos + 3 * kInstrSize);
      DCHECK(IsOri(instr_ori));
      DCHECK(IsOri(instr_ori2));

      // TODO(plind) create named constants for shift values.
      int64_t imm = static_cast<int64_t>(instr_lui & kImm16Mask) << 48;
      imm |= static_cast<int64_t>(instr_ori & kImm16Mask) << 32;
      imm |= static_cast<int64_t>(instr_ori2 & kImm16Mask) << 16;
      // Sign extend address;
      imm >>= 16;

      if (imm == kEndOfJumpChain) {
        // EndOfChain sentinel is returned directly, not relative to pc or pos.
        return kEndOfChain;
      } else {
        uint64_t instr_address = reinterpret_cast<int64_t>(buffer_start_ + pos);
        DCHECK(instr_address - imm < INT_MAX);
        int delta = static_cast<int>(instr_address - imm);
        DCHECK(pos > delta);
        return pos - delta;
      }
    }
  } else {
    DCHECK(IsJ(instr) || IsJal(instr));
    int32_t imm28 = (instr & static_cast<int32_t>(kImm26Mask)) << 2;
    if (imm28 == kEndOfJumpChain) {
      // EndOfChain sentinel is returned directly, not relative to pc or pos.
      return kEndOfChain;
    } else {
      // Sign extend 28-bit offset.
      int32_t delta = static_cast<int32_t>((imm28 << 4) >> 4);
      return pos + delta;
    }
  }
}

static inline Instr SetBranchOffset(int32_t pos, int32_t target_pos,
                                    Instr instr) {
  int32_t bits = OffsetSizeInBits(instr);
  int32_t imm = target_pos - (pos + Assembler::kBranchPCOffset);
  DCHECK_EQ(imm & 3, 0);
  imm >>= 2;

  const int32_t mask = (1 << bits) - 1;
  instr &= ~mask;
  DCHECK(is_intn(imm, bits));

  return instr | (imm & mask);
}

void Assembler::target_at_put(int pos, int target_pos, bool is_internal) {
  if (is_internal) {
    uint64_t imm = reinterpret_cast<uint64_t>(buffer_start_) + target_pos;
    *reinterpret_cast<uint64_t*>(buffer_start_ + pos) = imm;
    return;
  }
  Instr instr = instr_at(pos);
  if ((instr & ~kImm16Mask) == 0) {
    DCHECK(target_pos == kEndOfChain || target_pos >= 0);
    // Emitted label constant, not part of a branch.
    // Make label relative to Code pointer of generated InstructionStream
    // object.
    instr_at_put(
        pos, target_pos + (InstructionStream::kHeaderSize - kHeapObjectTag));
    return;
  }

  if (IsBranch(instr)) {
    instr = SetBranchOffset(pos, target_pos, instr);
    instr_at_put(pos, instr);
  } else if (IsLui(instr)) {
    if (IsNal(instr_at(pos + kInstrSize))) {
      Instr instr_lui = instr_at(pos + 0 * kInstrSize);
      Instr instr_ori = instr_at(pos + 2 * kInstrSize);
      DCHECK(IsLui(instr_lui));
      DCHECK(IsOri(instr_ori));
      int32_t imm = target_pos - (pos + Assembler::kLongBranchPCOffset);
      DCHECK_EQ(imm & 3, 0);
      if (is_int16(imm + Assembler::kLongBranchPCOffset -
                   Assembler::kBranchPCOffset)) {
        // Optimize by converting to regular branch and link with 16-bit
        // offset.
        Instr instr_b = REGIMM | BGEZAL;  // Branch and link.
        instr_b = SetBranchOffset(pos, target_pos, instr_b);
        // Correct ra register to point to one instruction after jalr from
        // MacroAssembler::BranchAndLinkLong.
        Instr instr_a = DADDIU | ra.code() << kRsShift | ra.code() << kRtShift |
                        kOptimizedBranchAndLinkLongReturnOffset;

        instr_at_put(pos, instr_b);
        instr_at_put(pos + 1 * kInstrSize, instr_a);
      } else {
        instr_lui &= ~kImm16Mask;
        instr_ori &= ~kImm16Mask;

        instr_at_put(pos + 0 * kInstrSize,
                     instr_lui | ((imm >> kLuiShift) & kImm16Mask));
        instr_at_put(pos + 2 * kInstrSize, instr_ori | (imm & kImm16Mask));
      }
    } else {
      Instr instr_lui = instr_at(pos + 0 * kInstrSize);
      Instr instr_ori = instr_at(pos + 1 * kInstrSize);
      Instr instr_ori2 = instr_at(pos + 3 * kInstrSize);
      DCHECK(IsOri(instr_ori));
      DCHECK(IsOri(instr_ori2));

      uint64_t imm = reinterpret_cast<uint64_t>(buffer_start_) + target_pos;
      DCHECK_EQ(imm & 3, 0);

      instr_lui &= ~kImm16Mask;
      instr_ori &= ~kImm16Mask;
      instr_ori2 &= ~kImm16Mask;

      instr_at_put(pos + 0 * kInstrSize,
                   instr_lui | ((imm >> 32) & kImm16Mask));
      instr_at_put(pos + 1 * kInstrSize,
                   instr_ori | ((imm >> 16) & kImm16Mask));
      instr_at_put(pos + 3 * kInstrSize, instr_ori2 | (imm & kImm16Mask));
    }
  } else if (IsMov(instr, t8, ra)) {
    if (IsAddImmediate(instr_at(pos + kInstrSize))) {
      Instr instr_daddiu = instr_at(pos + kInstrSize);
      int32_t imm_short = target_pos - pos;
      DCHECK(is_int16(imm_short));

      instr_daddiu &= ~kImm16Mask;
      instr_at_put(pos + kInstrSize, instr_daddiu | (imm_short & kImm16Mask));
      return;
    }

    Instr instr_lui = instr_at(pos + 2 * kInstrSize);
    Instr instr_ori = instr_at(pos + 3 * kInstrSize);
    DCHECK(IsLui(instr_lui));
    DCHECK(IsOri(instr_ori));

    int32_t imm_short = target_pos - (pos + Assembler::kBranchPCOffset);

    if (is_int16(imm_short)) {
      // Optimize by converting to regular branch with 16-bit
      // offset
      Instr instr_b = BEQ;
      instr_b = SetBranchOffset(pos, target_pos, instr_b);

      Instr instr_j = instr_at(pos + 5 * kInstrSize);
      Instr instr_branch_delay;

      if (IsJump(instr_j)) {
        // Case when branch delay slot is protected.
        instr_branch_delay = nopInstr;
      } else {
        // Case when branch delay slot is used.
        instr_branch_delay = instr_at(pos + 7 * kInstrSize);
      }
      instr_at_put(pos, instr_b);
      instr_at_put(pos + 1 * kInstrSize, instr_branch_delay);
    } else {
      int32_t imm = target_pos - (pos + Assembler::kLongBranchPCOffset);
      DCHECK_EQ(imm & 3, 0);

      instr_lui &= ~kImm16Mask;
      instr_ori &= ~kImm16Mask;

      instr_at_put(pos + 2 * kInstrSize,
                   instr_lui | ((imm >> kLuiShift) & kImm16Mask));
      instr_at_put(pos + 3 * kInstrSize, instr_ori | (imm & kImm16Mask));
    }
  } else if (IsJ(instr) || IsJal(instr)) {
    int32_t imm28 = target_pos - pos;
    DCHECK_EQ(imm28 & 3, 0);

    uint32_t imm26 = static_cast<uint32_t>(imm28 >> 2);
    DCHECK(is_uint26(imm26));
    // Place 26-bit signed offset with markings.
    // When code is committed it will be resolved to j/jal.
    int32_t mark = IsJ(instr) ? kJRawMark : kJalRawMark;
    instr_at_put(pos, mark | (imm26 & kImm26Mask));
  } else {
    int32_t imm28 = target_pos - pos;
    DCHECK_EQ(imm28 & 3, 0);

    uint32_t imm26 = static_cast<uint32_t>(imm28 >> 2);
    DCHECK(is_uint26(imm26));
    // Place raw 26-bit signed offset.
    // When code is committed it will be resolved to j/jal.
    instr &= ~kImm26Mask;
    instr_at_put(pos, instr | (imm26 & kImm26Mask));
  }
}

void Assembler::print(const Label* L) {
  if (L->is_unused()) {
    PrintF("unused label\n");
  } else if (L->is_bound()) {
    PrintF("bound label to %d\n", L->pos());
  } else if (L->is_linked()) {
    Label l;
    l.link_to(L->pos());
    PrintF("unbound label");
    while (l.is_linked()) {
      PrintF("@ %d ", l.pos());
      Instr instr = instr_at(l.pos());
      if ((instr & ~kImm16Mask) == 0) {
        PrintF("value\n");
      } else {
        PrintF("%d\n", instr);
      }
      next(&l, is_internal_reference(&l));
    }
  } else {
    PrintF("label in inconsistent state (pos = %d)\n", L->pos_);
  }
}

void Assembler::bind_to(Label* L, int pos) {
  DCHECK(0 <= pos && pos <= pc_offset());  // Must have valid binding position.
  int trampoline_pos = kInvalidSlotPos;
  bool is_internal = false;
  if (L->is_linked() && !trampoline_emitted_) {
    unbound_labels_count_--;
    if (!is_internal_reference(L)) {
      next_buffer_check_ += kTrampolineSlotsSize;
    }
  }

  while (L->is_linked()) {
    int fixup_pos = L->pos();
    int dist = pos - fixup_pos;
    is_internal = is_internal_reference(L);
    next(L, is_internal);  // Call next before overwriting link with target at
                           // fixup_pos.
    Instr instr = instr_at(fixup_pos);
    if (is_internal) {
      target_at_put(fixup_pos, pos, is_internal);
    } else {
      if (IsBranch(instr)) {
        int branch_offset = BranchOffset(instr);
        if (dist > branch_offset) {
          if (trampoline_pos == kInvalidSlotPos) {
            trampoline_pos = get_trampoline_entry(fixup_pos);
            CHECK_NE(trampoline_pos, kInvalidSlotPos);
          }
          CHECK((trampoline_pos - fixup_pos) <= branch_offset);
          target_at_put(fixup_pos, trampoline_pos, false);
          fixup_pos = trampoline_pos;
        }
        target_at_put(fixup_pos, pos, false);
      } else {
        DCHECK(IsJ(instr) || IsJal(instr) || IsLui(instr) ||
               IsEmittedConstant(instr) || IsMov(instr, t8, ra));
        target_at_put(fixup_pos, pos, false);
      }
    }
  }
  L->bind_to(pos);

  // Keep track of the last bound label so we don't eliminate any instructions
  // before a bound label.
  if (pos > last_bound_pos_) last_bound_pos_ = pos;
}

void Assembler::bind(Label* L) {
  DCHECK(!L->is_bound());  // Label can only be bound once.
  bind_to(L, pc_offset());
}

void Assembler::next(Label* L, bool is_internal) {
  DCHECK(L->is_linked());
  int link = target_at(L->pos(), is_internal);
  if (link == kEndOfChain) {
    L->Unuse();
  } else {
    DCHECK_GE(link, 0);
    L->link_to(link);
  }
}

bool Assembler::is_near(Label* L) {
  DCHECK(L->is_bound());
  return pc_offset() - L->pos() < kMaxBranchOffset - 4 * kInstrSize;
}

bool Assembler::is_near(Label* L, OffsetSize bits) {
  if (L == nullptr || !L->is_bound()) return true;
  return ((pc_offset() - L->pos()) <
          (1 << (bits + 2 - 1)) - 1 - 5 * kInstrSize);
}

bool Assembler::is_near_branch(Label* L) {
  DCHECK(L->is_bound());
  return kArchVariant == kMips64r6 ? is_near_r6(L) : is_near_pre_r6(L);
}

int Assembler::BranchOffset(Instr instr) {
  // At pre-R6 and for other R6 branches the offset is 16 bits.
  int bits = OffsetSize::kOffset16;

  if (kArchVariant == kMips64r6) {
    uint32_t opcode = GetOpcodeField(instr);
    switch (opcode) {
      // Checks BC or BALC.
      case BC:
      case BALC:
        bits = OffsetSize::kOffset26;
        break;

      // Checks BEQZC or BNEZC.
      case POP66:
      case POP76:
        if (GetRsField(instr) != 0) bits = OffsetSize::kOffset21;
        break;
      default:
        break;
    }
  }

  return (1 << (bits + 2 - 1)) - 1;
}

// We have to use a temporary register for things that can be relocated even
// if they can be encoded in the MIPS's 16 bits of immediate-offset instruction
// space.  There is no guarantee that the relocated location can be similarly
// encoded.
bool Assembler::MustUseReg(RelocInfo::Mode rmode) {
  return !RelocInfo::IsNoInfo(rmode);
}

void Assembler::GenInstrRegister(Opcode opcode, Register rs, Register rt,
                                 Register rd, uint16_t sa,
                                 SecondaryField func) {
  DCHECK(rd.is_valid() && rs.is_valid() && rt.is_valid() && is_uint5(sa));
  Instr instr = opcode | (rs.code() << kRsShift) | (rt.code() << kRtShift) |
                (rd.code() << kRdShift) | (sa << kSaShift) | func;
  emit(instr);
}

void Assembler::GenInstrRegister(Opcode opcode, Register rs, Register rt,
                                 uint16_t msb, uint16_t lsb,
                                 SecondaryField func) {
  DCHECK(rs.is_valid() && rt.is_valid() && is_uint5(msb) && is_uint5(lsb));
  Instr instr = opcode | (rs.code() << kRsShift) | (rt.code() << kRtShift) |
                (msb << kRdShift) | (lsb << kSaShift) | func;
  emit(instr);
}

void Assembler::GenInstrRegister(Opcode opcode, SecondaryField fmt,
                                 FPURegister ft, FPURegister fs, FPURegister fd,
                                 SecondaryField func) {
  DCHECK(fd.is_valid() && fs.is_valid() && ft.is_valid());
  Instr instr = opcode | fmt | (ft.code() << kFtShift) |
                (fs.code() << kFsShift) | (fd.code() << kFdShift) | func;
  emit(instr);
}

void Assembler::GenInstrRegister(Opcode opcode, FPURegister fr, FPURegister ft,
                                 FPURegister fs, FPURegister fd,
                                 SecondaryField func) {
  DCHECK(fd.is_valid() && fr.is_valid() && fs.is_valid() && ft.is_valid());
  Instr instr = opcode | (fr.code() << kFrShift) | (ft.code() << kFtShift) |
                (fs.code() << kFsShift) | (fd.code() << kFdShift) | func;
  emit(instr);
}

void Assembler::GenInstrRegister(Opcode opcode, SecondaryField fmt, Register rt,
                                 FPURegister fs, FPURegister fd,
                                 SecondaryField func) {
  DCHECK(fd.is_valid() && fs.is_valid() && rt.is_valid());
  Instr instr = opcode | fmt | (rt.code() << kRtShift) |
                (fs.code() << kFsShift) | (fd.code() << kFdShift) | func;
  emit(instr);
}

void Assembler::GenInstrRegister(Opcode opcode, SecondaryField fmt, Register rt,
                                 FPUControlRegister fs, SecondaryField func) {
  DCHECK(fs.is_valid() && rt.is_valid());
  Instr instr =
      opcode | fmt | (rt.code() << kRtShift) | (fs.code() << kFsShift) | func;
  emit(instr);
}

// Instructions with immediate value.
// Registers are in the order of the instruction encoding, from left to right.
void Assembler::GenInstrImmediate(Opcode opcode, Register rs, Register rt,
                                  int32_t j,
                                  CompactBranchType is_compact_branch) {
  DCHECK(rs.is_valid() && rt.is_valid() && (is_int16(j) || is_uint16(j)));
  Instr instr = opcode | (rs.code() << kRsShift) | (rt.code() << kRtShift) |
                (j & kImm16Mask);
  emit(instr, is_compact_branch);
}

void Assembler::GenInstrImmediate(Opcode opcode, Register base, Register rt,
                                  int32_t offset9, int bit6,
                                  SecondaryField func) {
  DCHECK(base.is_valid() && rt.is_valid() && is_int9(offset9) &&
         is_uint1(bit6));
  Instr instr = opcode | (base.code() << kBaseShift) | (rt.code() << kRtShift) |
                ((offset9 << kImm9Shift) & kImm9Mask) | bit6 << kBit6Shift |
                func;
  emit(instr);
}

void Assembler::GenInstrImmediate(Opcode opcode, Register rs, SecondaryField SF,
                                  int32_t j,
                                  CompactBranchType is_compact_branch) {
  DCHECK(rs.is_valid() && (is_int16(j) || is_uint16(j)));
  Instr instr = opcode | (rs.code() << kRsShift) | SF | (j & kImm16Mask);
  emit(instr, is_compact_branch);
}

void Assembler::GenInstrImmediate(Opcode opcode, Register rs, FPURegister ft,
                                  int32_t j,
                                  CompactBranchType is_compact_branch) {
  DCHECK(rs.is_valid() && ft.is_valid() && (is_int16(j) || is_uint16(j)));
  Instr instr = opcode | (rs.code() << kRsShift) | (ft.code() << kFtShift) |
                (j & kImm16Mask);
  emit(instr, is_compact_branch);
}

void Assembler::GenInstrImmediate(Opcode opcode, Register rs, int32_t offset21,
                                  CompactBranchType is_compact_branch) {
  DCHECK(rs.is_valid() && (is_int21(offset21)));
  Instr instr = opcode | (rs.code() << kRsShift) | (offset21 & kImm21Mask);
  emit(instr, is_compact_branch);
}

void Assembler::GenInstrImmediate(Opcode opcode, Register rs,
                                  uint32_t offset21) {
  DCHECK(rs.is_valid() && (is_uint21(offset21)));
  Instr instr = opcode | (rs.code() << kRsShift) | (offset21 & kImm21Mask);
  emit(instr);
}

void Assembler::GenInstrImmediate(Opcode opcode, int32_t offset26,
                                  CompactBranchType is_compact_branch) {
  DCHECK(is_int26(offset26));
  Instr instr = opcode | (offset26 & kImm26Mask);
  emit(instr, is_compact_branch);
}

void Assembler::GenInstrJump(Opcode opcode, uint32_t address) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(is_uint26(address));
  Instr instr = opcode | address;
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

// MSA instructions
void Assembler::GenInstrMsaI8(SecondaryField operation, uint32_t imm8,
                              MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid() && is_uint8(imm8));
  Instr instr = MSA | operation | ((imm8 & kImm8Mask) << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

void Assembler::GenInstrMsaI5(SecondaryField operation, SecondaryField df,
                              int32_t imm5, MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid());
  DCHECK((operation == MAXI_S) || (operation == MINI_S) ||
                 (operation == CEQI) || (operation == CLTI_S) ||
                 (operation == CLEI_S)
             ? is_int5(imm5)
             : is_uint5(imm5));
  Instr instr = MSA | operation | df | ((imm5 & kImm5Mask) << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

void Assembler::GenInstrMsaBit(SecondaryField operation, SecondaryField df,
                               uint32_t m, MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid() && is_valid_msa_df_m(df, m));
  Instr instr = MSA | operation | df | (m << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

void Assembler::GenInstrMsaI10(SecondaryField operation, SecondaryField df,
                               int32_t imm10, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(wd.is_valid() && is_int10(imm10));
  Instr instr = MSA | operation | df | ((imm10 & kImm10Mask) << kWsShift) |
                (wd.code() << kWdShift);
  emit(instr);
}

template <typename RegType>
void Assembler::GenInstrMsa3R(SecondaryField operation, SecondaryField df,
                              RegType t, MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(t.is_valid() && ws.is_valid() && wd.is_valid());
  Instr instr = MSA | operation | df | (t.code() << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

template <typename DstType, typename SrcType>
void Assembler::GenInstrMsaElm(SecondaryField operation, SecondaryField df,
                               uint32_t n, SrcType src, DstType dst) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(src.is_valid() && dst.is_valid() && is_valid_msa_df_n(df, n));
  Instr instr = MSA | operation | df | (n << kWtShift) |
                (src.code() << kWsShift) | (dst.code() << kWdShift) |
                MSA_ELM_MINOR;
  emit(instr);
}

void Assembler::GenInstrMsa3RF(SecondaryField operation, uint32_t df,
                               MSARegister wt, MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(wt.is_valid() && ws.is_valid() && wd.is_valid());
  DCHECK_LT(df, 2);
  Instr instr = MSA | operation | (df << 21) | (wt.code() << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

void Assembler::GenInstrMsaVec(SecondaryField operation, MSARegister wt,
                               MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(wt.is_valid() && ws.is_valid() && wd.is_valid());
  Instr instr = MSA | operation | (wt.code() << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift) |
                MSA_VEC_2R_2RF_MINOR;
  emit(instr);
}

void Assembler::GenInstrMsaMI10(SecondaryField operation, int32_t s10,
                                Register rs, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(rs.is_valid() && wd.is_valid() && is_int10(s10));
  Instr instr = MSA | operation | ((s10 & kImm10Mask) << kWtShift) |
                (rs.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

void Assembler::GenInstrMsa2R(SecondaryField operation, SecondaryField df,
                              MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid());
  Instr instr = MSA | MSA_2R_FORMAT | operation | df | (ws.code() << kWsShift) |
                (wd.code() << kWdShift) | MSA_VEC_2R_2RF_MINOR;
  emit(instr);
}

void Assembler::GenInstrMsa2RF(SecondaryField operation, SecondaryField df,
                               MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid());
  Instr instr = MSA | MSA_2RF_FORMAT | operation | df |
                (ws.code() << kWsShift) | (wd.code() << kWdShift) |
                MSA_VEC_2R_2RF_MINOR;
  emit(instr);
}

void Assembler::GenInstrMsaBranch(SecondaryField operation, MSARegister wt,
                                  int32_t offset16) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(wt.is_valid() && is_int16(offset16));
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Instr instr =
      COP1 | operation | (wt.code() << kWtShift) | (offset16 & kImm16Mask);
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

// Returns the next free trampoline entry.
int32_t Assembler::get_trampoline_entry(int32_t pos) {
  int32_t trampoline_entry = kInvalidSlotPos;
  if (!internal_trampoline_exception_) {
    if (trampoline_.start() > pos) {
      trampoline_entry = trampoline_.take_slot();
    }

    if (kInvalidSlotPos == trampoline_entry) {
      internal_trampoline_exception_ = true;
    }
  }
  return trampoline_entry;
}

uint64_t Assembler::jump_address(Label* L) {
  int64_t target_pos;
  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      L->link_to(pc_offset());
    } else {
      L->link_to(pc_offset());
      return kEndOfJumpChain;
    }
  }
  uint64_t imm = reinterpret_cast<uint64_t>(buffer_start_) + target_pos;
  DCHECK_EQ(imm & 3, 0);

  return imm;
}

uint64_t Assembler::jump_offset(Label* L) {
  int64_t target_pos;
  int32_t pad = IsPrevInstrCompactBranch() ? kInstrSize : 0;

  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      L->link_to(pc_offset() + pad);
    } else {
      L->link_to(pc_offset() + pad);
      return kEndOfJumpChain;
    }
  }
  int64_t imm = target_pos - (pc_offset() + pad);
  DCHECK_EQ(imm & 3, 0);

  return static_cast<uint64_t>(imm);
}

uint64_t Assembler::branch_long_offset(Label* L) {
  int64_t target_pos;

  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      L->link_to(pc_offset());
    } else {
      L->link_to(pc_offset());
      return kEndOfJumpChain;
    }
  }
  int64_t offset = target_pos - (pc_offset() + kLongBranchPCOffset);
  DCHECK_EQ(offset & 3, 0);

  return static_cast<uint64_t>(offset);
}

int32_t Assembler::branch_offset_helper(Label* L, OffsetSize bits) {
  int32_t target_pos;
  int32_t pad = IsPrevInstrCompactBranch() ? kInstrSize : 0;

  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();
      L->link_to(pc_offset() + pad);
    } else {
      L->link_to(pc_offset() + pad);
      if (!trampoline_emitted_) {
        unbound_labels_count_++;
        next_buffer_check_ -= kTrampolineSlotsSize;
      }
      return kEndOfChain;
    }
  }

  int32_t offset = target_pos - (pc_offset() + kBranchPCOffset + pad);
  DCHECK(is_intn(offset, bits + 2));
  DCHECK_EQ(offset & 3, 0);

  return offset;
}

void Assembler::label_at_put(Label* L, int at_offset) {
  int target_pos;
  if (L->is_bound()) {
    target_pos = L->pos();
    instr_at_put(at_offset, target_pos + (InstructionStream::kHeaderSize -
                                          kHeapObjectTag));
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      int32_t imm18 = target_pos - at_offset;
      DCHECK_EQ(imm18 & 3, 0);
      int32_t imm16 = imm18 >> 2;
      DCHECK(is_int16(imm16));
      instr_at_put(at_offset, (imm16 & kImm16Mask));
    } else {
      target_pos = kEndOfChain;
      instr_at_put(at_offset, 0);
      if (!trampoline_emitted_) {
        unbound_labels_count_++;
        next_buffer_check_ -= kTrampolineSlotsSize;
      }
    }
    L->link_to(at_offset);
  }
}

//------- Branch and jump instructions --------

void Assembler::b(int16_t offset) { beq(zero_reg, zero_reg, offset); }

void Assembler::bal(int16_t offset) { bgezal(zero_reg, offset); }

void Assembler::bc(int32_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrImmediate(BC, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::balc(int32_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrImmediate(BALC, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::beq(Register rs, Register rt, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(BEQ, rs, rt, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bgez(Register rs, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(REGIMM, rs, BGEZ, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bgezc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  GenInstrImmediate(BLEZL, rt, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgeuc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  DCHECK(rt != zero_reg);
  DCHECK(rs.code() != rt.code());
  GenInstrImmediate(BLEZ, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgec(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  DCHECK(rt != zero_reg);
  DCHECK(rs.code() != rt.code());
  GenInstrImmediate(BLEZL, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgezal(Register rs, int16_t offset) {
  DCHECK(kArchVariant != kMips64r6 || rs == zero_reg);
  DCHECK(rs != ra);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(REGIMM, rs, BGEZAL, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bgtz(Register rs, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(BGTZ, rs, zero_reg, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bgtzc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  GenInstrImmediate(BGTZL, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::blez(Register rs, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(BLEZ, rs, zero_reg, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::blezc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  GenInstrImmediate(BLEZL, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bltzc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  GenInstrImmediate(BGTZL, rt, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bltuc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  DCHECK(rt != zero_reg);
  DCHECK(rs.code() != rt.code());
  GenInstrImmediate(BGTZ, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bltc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  DCHECK(rt != zero_reg);
  DCHECK(rs.code() != rt.code());
  GenInstrImmediate(BGTZL, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bltz(Register rs, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(REGIMM, rs, BLTZ, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bltzal(Register rs, int16_t offset) {
  DCHECK(kArchVariant != kMips64r6 || rs == zero_reg);
  DCHECK(rs != ra);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(REGIMM, rs, BLTZAL, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bne(Register rs, Register rt, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(BNE, rs, rt, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bovc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  if (rs.code() >= rt.code()) {
    GenInstrImmediate(ADDI, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
  } else {
    GenInstrImmediate(ADDI, rt, rs, offset, CompactBranchType::COMPACT_BRANCH);
  }
}

void Assembler::bnvc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  if (rs.code() >= rt.code()) {
    GenInstrImmediate(DADDI, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
  } else {
    GenInstrImmediate(DADDI, rt, rs, offset, CompactBranchType::COMPACT_BRANCH);
  }
}

void Assembler::blezalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(BLEZ, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgezalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(BLEZ, rt, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgezall(Register rs, int16_t offset) {
  DCHECK_NE(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  DCHECK(rs != ra);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(REGIMM, rs, BGEZALL, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bltzalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(BGTZ, rt, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgtzalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(BGTZ, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::beqzalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(ADDI, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bnezalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(DADDI, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::beqc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs.code() != rt.code() && rs.code() != 0 && rt.code() != 0);
  if (rs.code() < rt.code()) {
    GenInstrImmediate(ADDI, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
  } else {
    GenInstrImmediate(ADDI, rt, rs, offset, CompactBranchType::COMPACT_BRANCH);
  }
}

void Assembler::beqzc(Register rs, int32_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  GenInstrImmediate(POP66, rs, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bnec(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs.code() != rt.code() && rs.code() != 0 && rt.code() != 0);
  if (rs.code() < rt.code()) {
    GenInstrImmediate(DADDI, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
  } else {
    GenInstrImmediate(DADDI, rt, rs, offset, CompactBranchType::COMPACT_BRANCH);
  }
}

void Assembler::bnezc(Register rs, int32_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  GenInstrImmediate(POP76, rs, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::j(int64_t target) {
  // Deprecated. Use PC-relative jumps instead.
  UNREACHABLE();
}

void Assembler::j(Label* target) {
  // Deprecated. Use PC-relative jumps instead.
  UNREACHABLE();
}

void Assembler::jal(Label* target) {
  // Deprecated. Use PC-relative jumps instead.
  UNREACHABLE();
}

void Assembler::jal(int64_t target) {
  // Deprecated. Use PC-relative jumps instead.
  UNREACHABLE();
}

void Assembler::jr(Register rs) {
  if (kArchVariant != kMips64r6) {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    GenInstrRegister(SPECIAL, rs, zero_reg, zero_reg, 0, JR);
    BlockTrampolinePoolFor(1);  // For associated delay slot.
  } else {
    jalr(rs, zero_reg);
  }
}

void Assembler::jalr(Register rs, Register rd) {
  DCHECK(rs.code() != rd.code());
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrRegister(SPECIAL, rs, zero_reg, rd, 0, JALR);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::jic(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrImmediate(POP66, zero_reg, rt, offset);
}

void Assembler::jialc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrImmediate(POP76, zero_reg, rt, offset);
}

// -------Data-processing-instructions---------

// Arithmetic.

void Assembler::addu(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, ADDU);
}

void Assembler::addiu(Register rd, Register rs, int32_t j) {
  GenInstrImmediate(ADDIU, rs, rd, j);
}

void Assembler::subu(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SUBU);
}

void Assembler::mul(Register rd, Register rs, Register rt) {
  if (kArchVariant == kMips64r6) {
    GenInstrRegister(SPECIAL, rs, rt, rd, MUL_OP, MUL_MUH);
  } else {
    GenInstrRegister(SPECIAL2, rs, rt, rd, 0, MUL);
  }
}

void Assembler::muh(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUH_OP, MUL_MUH);
}

void Assembler::mulu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUL_OP, MUL_MUH_U);
}

void Assembler::muhu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUH_OP, MUL_MUH_U);
}

void Assembler::dmul(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUL_OP, D_MUL_MUH);
}

void Assembler::dmuh(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUH_OP, D_MUL_MUH);
}

void Assembler::dmulu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUL_OP, D_MUL_MUH_U);
}

void Assembler::dmuhu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUH_OP, D_MUL_MUH_U);
}

void Assembler::mult(Register rs, Register rt) {
  DCHECK_NE(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, MULT);
}

void Assembler::multu(Register rs, Register rt) {
  DCHECK_NE(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, MULTU);
}

void Assembler::daddiu(Register rd, Register rs, int32_t j) {
  GenInstrImmediate(DADDIU, rs, rd, j);
}

void Assembler::div(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DIV);
}

void Assembler::div(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, DIV_OP, DIV_MOD);
}

void Assembler::mod(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MOD_OP, DIV_MOD);
}

void Assembler::divu(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DIVU);
}

void Assembler::divu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, DIV_OP, DIV_MOD_U);
}

void Assembler::modu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MOD_OP, DIV_MOD_U);
}

void Assembler::daddu(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, DADDU);
}

void Assembler::dsubu(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, DSUBU);
}

void Assembler::dmult(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DMULT);
}

void Assembler::dmultu(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DMULTU);
}

void Assembler::ddiv(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DDIV);
}

void Assembler::ddiv(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, DIV_OP, D_DIV_MOD);
}

void Assembler::dmod(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MOD_OP, D_DIV_MOD);
}

void Assembler::ddivu(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DDIVU);
}

void Assembler::ddivu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, DIV_OP, D_DIV_MOD_U);
}

void Assembler::dmodu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MOD_OP, D_DIV_MOD_U);
}

// Logical.

void Assembler::and_(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, AND);
}

void Assembler::andi(Register rt, Register rs, int32_t j) {
  DCHECK(is_uint16(j));
  GenInstrImmediate(ANDI, rs, rt, j);
}

void Assembler::or_(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, OR);
}

void Assembler::ori(Register rt, Register rs, int32_t j) {
  DCHECK(is_uint16(j));
  GenInstrImmediate(ORI, rs, rt, j);
}

void Assembler::xor_(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, XOR);
}

void Assembler::xori(Register rt, Register rs, int32_t j) {
  DCHECK(is_uint16(j));
  GenInstrImmediate(XORI, rs, rt, j);
}

void Assembler::nor(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, NOR);
}

// Shifts.
void Assembler::sll(Register rd, Register rt, uint16_t sa,
                    bool coming_from_nop) {
  // Don't allow nop instructions in the form sll zero_reg, zero_reg to be
  // generated using the sll instruction. They must be generated using
  // nop(int/NopMarkerTypes).
  DCHECK(coming_from_nop || (rd != zero_reg && rt != zero_reg));
  GenInstrRegister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, SLL);
}

void Assembler::sllv(Register rd, Register rt, Register rs) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SLLV);
}

void Assembler::srl(Register rd, Register rt, uint16_t sa) {
  GenInstrRegister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, SRL);
}

void Assembler::srlv(Register rd, Register rt, Register rs) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SRLV);
}

void Assembler::sra(Register rd, Register rt, uint16_t sa) {
  GenInstrReg
"""


```