Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/mips64/assembler-mips64.cc`. They also have specific questions related to:

1. **File extension `.tq`:**  Whether this extension signifies a Torque source file in V8.
2. **Relationship to JavaScript:** If the code interacts with JavaScript, illustrate with a JavaScript example.
3. **Code logic and reasoning:** Provide hypothetical inputs and outputs if there's demonstrable logic.
4. **Common programming errors:**  Highlight potential mistakes users might make when working with similar concepts.
5. **Overall function:** Summarize the purpose of this code snippet.

Let's break down the code and address each point.

**Analysis of the C++ code:**

* **Copyright and Licensing:** The initial part is a standard copyright notice and licensing information.
* **Includes:**  The code includes various V8 headers related to code generation, CPU features, deoptimization, and object representation. This strongly suggests the code is involved in the process of turning JavaScript code into machine code for the MIPS64 architecture.
* **Namespace:** The code resides within the `v8::internal` namespace, a common practice in V8.
* **`CpuFeatures`:**  Functions like `CpuFeaturesImpliedByCompiler`, `SupportsWasmSimd128`, and `ProbeImpl` indicate this section deals with detecting and managing CPU capabilities, particularly for features like floating-point units (FPU) and SIMD instructions (MSA).
* **`ToNumber` and `ToRegister`:** These functions seem to provide mappings between `Register` objects (likely V8's internal representation of CPU registers) and integer codes, and vice versa. This is fundamental for assembler implementation.
* **`RelocInfo`:** The `RelocInfo` class and its methods (`IsCodedSpecially`, `IsInConstantPool`, `wasm_call_tag`) are crucial for managing relocatable information in the generated code. This information is necessary for the runtime to update addresses when code is loaded or moved in memory.
* **`Operand` and `MemOperand`:** These classes represent operands in assembly instructions, including immediate values, registers, and memory locations. The `EmbeddedNumber` function suggests handling the embedding of floating-point numbers.
* **`Assembler` Class:** This is the core of the code. It provides methods for generating MIPS64 assembly instructions. Key functionalities include:
    * **Constructor:** Initializes the assembler state, including CPU feature flags and relocation information writer.
    * **`GetCode`:** Finalizes the assembly process, writes code comments, allocates heap numbers, and prepares the `CodeDesc` structure, which describes the generated code.
    * **`Align` and `CodeTargetAlign`:**  Methods for aligning the generated code in memory.
    * **Register and Field Extraction:** Functions like `GetRtReg`, `GetRsReg`, `GetRdReg`, etc., are used to parse the fields of a MIPS64 instruction.
    * **Instruction Recognition:** Functions like `IsPop`, `IsPush`, `IsBranch`, `IsJump`, `IsLui`, `IsOri`, `IsNop`, etc., identify specific instruction types.
    * **Offset Management:** Functions like `GetBranchOffset`, `GetLwOffset`, `SetLwOffset`, and the logic for `target_at` and `target_at_put` deal with calculating and setting offsets in branch and load/store instructions. This is critical for code linking and relocation.
    * **Trampoline Pool:** The mentions of `trampoline_pool` and related variables suggest a mechanism for handling long jumps or calls that exceed the immediate offset range of standard branch instructions.

**Addressing the user's specific questions:**

1. **`.tq` extension:** The code snippet is a `.cc` file (C++ source code). The user's assumption about `.tq` is incorrect for this specific file. `.tq` files in V8 typically denote Torque source files, which are used for a higher-level code generation system within V8.

2. **Relationship to JavaScript:**  This code is deeply involved in the process of compiling JavaScript code to MIPS64 machine code. When V8 executes JavaScript, it goes through a compilation pipeline. This `assembler-mips64.cc` file provides the low-level tools to generate the actual MIPS64 instructions that the CPU will execute.

   **JavaScript Example:**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   add(5, 10);
   ```

   When V8 compiles this `add` function for MIPS64, the code in `assembler-mips64.cc` will be used to generate instructions that:
   * Load the values of `a` and `b` from memory or registers into MIPS64 registers.
   * Perform the addition operation using a MIPS64 addition instruction.
   * Store the result back into a register or memory.
   * Return the result.

3. **Code logic and reasoning:** The most prominent logic is in how branch offsets and jump targets are calculated and updated.

   **Hypothetical Input:** Imagine a branch instruction at memory address `0x1000` that needs to jump to a label at address `0x1080`.

   **Internal Calculation:** The `Assembler` would calculate the offset: `0x1080 - (0x1000 + 4)` (assuming a 4-byte instruction size and PC-relative addressing). This offset would be `0x7C`. The assembler would then encode this offset into the branch instruction.

   **Output (part of the generated instruction):** The relevant bits of the branch instruction would contain the encoded offset representing `0x7C`.

4. **Common programming errors:**  When working with assemblers or low-level code generation, common errors include:

   * **Incorrect register usage:**  Using the wrong registers for operations or accidentally overwriting registers containing important values.
   * **Incorrect offset calculations:**  Errors in calculating branch targets or memory addresses, leading to jumps to the wrong locations or accessing incorrect memory.
   * **Not handling long jumps:** Forgetting to use trampoline pools or other mechanisms when the target address is too far for a direct branch.
   * **Endianness issues:**  While not explicitly shown in this snippet, byte order can be a problem when dealing with raw memory and instructions.
   * **Forgetting branch delay slots:** On some MIPS architectures (though less common now), the instruction immediately following a branch is executed before the branch takes effect. Not accounting for this can lead to unexpected behavior.

5. **Overall function (Part 1):** This first part of `v8/src/codegen/mips64/assembler-mips64.cc` primarily focuses on **setting up the foundational infrastructure for generating MIPS64 assembly code within the V8 JavaScript engine.** It includes:

   * **CPU feature detection:** Determining the capabilities of the target MIPS64 processor.
   * **Register management:** Defining and mapping CPU registers.
   * **Operand and memory representation:**  Creating data structures to represent operands and memory locations.
   * **Relocation information management:** Handling information needed to adjust addresses at runtime.
   * **Basic assembler functionalities:** Providing core methods for instruction emission, alignment, and label management.

It lays the groundwork for the more complex instruction generation logic that will likely appear in the subsequent parts of the file. It doesn't directly implement high-level JavaScript features but provides the low-level building blocks to do so.

好的，根据您提供的代码片段，以下是对 `v8/src/codegen/mips64/assembler-mips64.cc` 第一部分功能的归纳：

**功能归纳 (第 1 部分):**

该文件是 V8 JavaScript 引擎中用于为 MIPS64 架构生成机器码的汇编器实现。这部分代码主要负责以下核心功能：

1. **CPU 特性检测与管理:**
   - 探测目标 MIPS64 CPU 的特性，例如是否支持浮点运算单元 (FPU) 和 SIMD 指令 (MSA)。
   - 提供接口 (`CpuFeatures`) 来查询和管理这些特性，以便在代码生成过程中根据 CPU 能力选择合适的指令。

2. **寄存器定义与映射:**
   - 定义了 MIPS64 架构的通用寄存器，并提供了将寄存器对象 (`Register`) 转换为数字表示 (`ToNumber`) 以及将数字转换为寄存器对象 (`ToRegister`) 的方法。

3. **重定位信息管理 (`RelocInfo`):**
   - 定义了 `RelocInfo` 类，用于存储和管理生成代码中的重定位信息。这些信息在代码加载或移动时用于更新指令中的地址。
   - 提供了判断重定位信息类型 (`IsCodedSpecially`, `IsInConstantPool`) 和获取 WebAssembly 调用标签 (`wasm_call_tag`) 的方法。

4. **操作数表示 (`Operand` 和 `MemOperand`):**
   - 定义了 `Operand` 类来表示汇编指令的操作数，包括立即数、寄存器和嵌入的对象 (例如，HeapObject)。
   - 提供了创建嵌入式数字操作数 (`EmbeddedNumber`) 的方法，该方法会根据数值类型选择合适的表示方式 (SMI 或 HeapNumber)。
   - 定义了 `MemOperand` 类来表示内存操作数，包括基址寄存器和偏移量。

5. **汇编器核心类 (`Assembler`):**
   - 定义了 `Assembler` 类，它是生成 MIPS64 汇编指令的核心组件。
   - 提供了构造函数，用于初始化汇编器状态，包括缓冲区、重定位信息写入器和 CPU 特性标志。
   - 提供了 `GetCode` 方法，用于完成汇编过程，包括添加对齐、写入代码注释、安装请求的堆数字，并生成 `CodeDesc` 结构，描述生成的代码。
   - 提供了代码对齐 (`Align`, `CodeTargetAlign`) 的方法，确保指令在内存中的正确排列。
   - 提供了从指令中提取寄存器和字段信息的方法 (`GetRtReg`, `GetRsReg`, `GetRdReg` 等)。
   - 提供了识别不同类型 MIPS64 指令的方法 (`IsPop`, `IsPush`, `IsBranch`, `IsJump`, `IsLui`, `IsOri`, `IsNop` 等)。
   - 提供了获取和设置分支偏移量和内存访问偏移量的方法 (`GetBranchOffset`, `GetLwOffset`, `SetLwOffset` 等)。
   - 实现了跳转目标地址的计算 (`target_at`) 和更新 (`target_at_put`) 逻辑，用于处理标签和跳转指令。

**关于您的问题的回答:**

* **`.tq` 结尾:** `v8/src/codegen/mips64/assembler-mips64.cc` 以 `.cc` 结尾，表示这是一个 C++ 源代码文件。以 `.tq` 结尾的文件通常是 V8 的 Torque 源代码，Torque 是一种用于生成 V8 内置函数的领域特定语言。

* **与 JavaScript 的关系:**  `assembler-mips64.cc` 与 JavaScript 的功能密切相关。它负责将 V8 编译后的中间代码转换为目标 MIPS64 架构的机器码，这是 JavaScript 代码执行的关键步骤。

   **JavaScript 示例:**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   let result = add(5, 3);
   console.log(result); // 输出 8
   ```

   当 V8 编译 `add` 函数时，`assembler-mips64.cc` 中的代码会被调用来生成相应的 MIPS64 汇编指令，例如：

   - 将 `a` 和 `b` 的值加载到寄存器中。
   - 使用 MIPS64 的加法指令将寄存器中的值相加。
   - 将结果存储回寄存器或内存。
   - 返回结果。

* **代码逻辑推理:**  `target_at` 和 `target_at_put` 方法中包含了代码逻辑推理。

   **假设输入:**
   - 一个分支指令位于内存地址 `0x1000`，需要跳转到标签 `L`。
   - 标签 `L` 当前绑定到内存地址 `0x1080`。

   **输出:**
   - `target_at(0x1000)` 将计算并返回跳转目标地址 `0x1080`。
   - `target_at_put(0x1000, 0x1080)` 将计算分支指令所需的偏移量，并将该偏移量编码到位于 `0x1000` 的分支指令中。

* **用户常见的编程错误:** 在使用汇编器或进行底层编程时，常见的错误包括：

   - **寄存器使用错误:**  错误地使用了保留寄存器或覆盖了重要寄存器的值。
   - **偏移量计算错误:** 在计算分支目标或内存地址时出现错误，导致跳转到错误的位置或访问错误的内存。
   - **未处理长跳转:**  当跳转目标超出短跳转指令的范围时，未采取必要的措施（例如使用跳转表或加载地址到寄存器后跳转）。
   - **指令编码错误:**  错误地组合指令的操作码和操作数，导致生成无效的机器码。

总之，`v8/src/codegen/mips64/assembler-mips64.cc` 的第一部分为 V8 在 MIPS64 架构上生成可执行代码奠定了基础，提供了底层的指令生成和管理能力。

### 提示词
```
这是目录为v8/src/codegen/mips64/assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    Pr
```