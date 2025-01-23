Response:
The user wants me to analyze a C++ source code file for the V8 JavaScript engine, specifically `v8/src/codegen/riscv/assembler-riscv.cc`. I need to identify its functionality, relate it to JavaScript if applicable, provide examples, and summarize its purpose.

Here's a breakdown of the thinking process:

1. **Identify the core function:** The file name `assembler-riscv.cc` strongly suggests it's responsible for generating RISC-V assembly code within the V8 engine. The presence of `Assembler` class and methods like `GetCode`, `Align`, `bind`, and instruction-related methods (`BranchOffset`, `SetBranchOffset`, etc.) confirms this.

2. **Determine the role within V8:** Assemblers are crucial for just-in-time (JIT) compilers. V8 compiles JavaScript code into machine code for faster execution. This file likely handles the RISC-V specific details of that compilation process.

3. **Check for Torque involvement:** The prompt mentions `.tq` files. This file is `.cc`, so it's not a Torque source file. Torque is a higher-level language used to define built-in functions, and this file deals with the lower-level assembly generation.

4. **Relate to JavaScript:** While this file doesn't directly contain JavaScript code, it's fundamental to how JavaScript runs in V8 on RISC-V architectures. When V8 executes JavaScript, it uses components like this assembler to generate the actual machine instructions that the CPU executes.

5. **Provide JavaScript examples:** To illustrate the connection, I need to show how JavaScript code ultimately leads to the use of this assembler. Simple JavaScript constructs like variable assignment, function calls, and conditional statements will eventually be translated into RISC-V instructions using this assembler.

6. **Identify code logic and provide examples:**  The code deals with label management, branching, and instruction encoding. I can illustrate the label linking process with a hypothetical scenario: a conditional jump in the generated code. I'll need to show how the assembler resolves the jump target even if it's not known at the time the jump instruction is generated.

7. **Address common programming errors:**  A common issue with assembly-level programming or interacting with low-level code is incorrect memory addressing or exceeding branch/jump offsets. I can provide an example of a large function causing a jump beyond the immediate range.

8. **Summarize the functionality:**  The core function is RISC-V assembly code generation for V8's JIT compiler. It handles instruction encoding, label resolution, and CPU feature detection.

9. **Structure the response:** I will organize the information into the categories requested by the user: functionality, Torque relevance, JavaScript relationship with examples, code logic with examples, common errors with examples, and a final summary.
这是 V8 源代码文件 `v8/src/codegen/riscv/assembler-riscv.cc` 的第一部分。它主要负责实现 **RISC-V 架构的汇编器 (Assembler)**。

以下是它在这一部分的主要功能：

1. **定义和管理 CPU 特性 (CPU Features):**
   - 它定义了 `CpuFeatures` 类，用于检测和存储 RISC-V 处理器支持的扩展指令集，例如 FPU (浮点单元), SIMD, 以及 Zba, Zbb, Zbs, Zicond 等扩展。
   - 它通过编译时宏 (`__riscv_f`, `__riscv_vector` 等) 和运行时 CPU 检测来确定支持的特性。
   - `CpuFeaturesImpliedByCompiler()` 函数根据编译器定义的宏来推断 CPU 特性。
   - `ProbeImpl()` 函数在运行时检测 CPU 特性。
   - `SupportsWasmSimd128()` 方法判断是否支持 WebAssembly SIMD 指令。
   - `PrintFeatures()` 方法打印支持的 RISC-V 扩展信息。

2. **定义寄存器 (Registers) 的表示和转换:**
   - 提供了 `ToNumber(Register reg)` 函数，将 RISC-V 寄存器对象转换为其数字表示。
   - 提供了 `ToRegister(int num)` 函数，将寄存器编号转换为 RISC-V 寄存器对象。

3. **实现重定位信息 (Relocation Information) 的处理:**
   - 定义了 `RelocInfo` 相关的常量和方法，用于描述代码中需要重定位的部分，例如嵌入的对象、代码目标等。
   - `IsCodedSpecially()` 说明 RISC-V 上指针是特殊编码的（通过 `lui/addi` 指令）。
   - `wasm_call_tag()` 用于获取 WebAssembly 调用指令的目标地址。

4. **实现操作数 (Operand) 和内存操作数 (MemOperand) 的表示:**
   - 定义了 `Operand` 类，用于表示汇编指令的操作数，可以是寄存器、立即数或内存地址。
   - 提供了 `EmbeddedNumber()` 方法，用于创建嵌入的数字操作数。
   - 定义了 `MemOperand` 类，用于表示内存操作数，包括基址寄存器和偏移量。

5. **实现汇编器 (Assembler) 的核心功能:**
   - `Assembler` 类是汇编器的核心，用于生成 RISC-V 机器码。
   - 构造函数 `Assembler()` 初始化汇编器，包括分配缓冲区、设置初始状态等。
   - `GetCode()` 方法用于获取生成的机器码，并填充 `CodeDesc` 结构。
   - `Align()` 方法用于在代码中插入对齐。
   - `CodeTargetAlign()` 方法用于对齐代码目标地址。

6. **处理代码标签 (Labels):**
   - 提供了 `Label` 类，用于表示代码中的标签，用于跳转和分支指令的目标地址。
   - 实现了标签的绑定 (`bind()`, `bind_to()`) 和链接 (`link_to()`) 机制，用于在代码生成过程中解析跳转目标。
   - `target_at()` 方法获取指定位置的指令跳转目标地址。
   - `target_at_put()` 方法设置指定位置的指令跳转目标地址。
   - `is_near()` 和 `is_near_branch()` 方法判断跳转是否在短距离内。
   - 提供了计算分支偏移量 (`BranchOffset()`, `BrachlongOffset()`) 和设置分支偏移量 (`SetBranchOffset()`, `SetJalOffset()`, `SetCBranchOffset()`, `SetCJalOffset()`) 的方法。

7. **实现长跳转 (Long Jump) 的处理 (通过 Trampoline):**
   - 提供了 `get_trampoline_entry()` 函数，用于获取跳转槽位，当跳转目标超出短距离时使用。
   - `trampoline_` 对象用于管理跳转槽位。

8. **指令编码助手函数:**
   - 提供了用于设置不同指令类型偏移量的静态内联函数，例如 `SetLoadOffset()`, `SetAuipcOffset()`, `SetJalrOffset()`.

**如果 `v8/src/codegen/riscv/assembler-riscv.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

然而，根据你提供的文件名，它以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 文件通常用于定义 V8 的内置函数。

**它与 JavaScript 的功能有关系，请用 javascript 举例说明:**

虽然 `assembler-riscv.cc` 不是直接用 JavaScript 编写的，但它是 V8 执行 JavaScript 代码的关键组成部分。当 V8 编译 JavaScript 代码时，它会使用这个汇编器将高级的 JavaScript 操作转换为底层的 RISC-V 机器指令。

例如，考虑以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 执行这段代码时，它的 JIT 编译器 (例如 TurboFan 或 Crankshaft) 会将 `add` 函数编译成 RISC-V 汇编代码。`assembler-riscv.cc` 中定义的 `Assembler` 类以及相关的指令生成方法会被用来生成类似以下的 RISC-V 指令序列（这只是一个简化的示例）：

```assembly
# 假设 a 在寄存器 a0， b 在寄存器 a1

add  a2, a0, a1  # 将 a0 和 a1 的值相加，结果放入 a2
mv   a0, a2      # 将结果从 a2 移到返回值寄存器 a0
ret             # 返回
```

这个 `assembler-riscv.cc` 文件就负责生成像 `add`, `mv`, `ret` 这样的 RISC-V 指令。

**如果有代码逻辑推理，请给出假设输入与输出:**

考虑标签绑定和跳转的逻辑。假设有以下代码片段正在被汇编：

```c++
Label target;
// ... 一些其他指令 ...
B(&target); // 分支到 target 标签
// ... 更多指令 ...
Bind(&target); // 绑定 target 标签到当前位置
```

**假设输入:**

- 在执行 `B(&target)` 时，`target` 标签尚未绑定。
- `pc_offset()` (当前代码生成位置) 是 100。
- `target` 标签最终绑定的位置是 200。

**代码逻辑推理:**

1. 当执行 `B(&target)` 时，由于 `target` 未绑定，`branch_offset_helper()` 会被调用。
2. `branch_offset_helper()` 会将当前指令的位置 (100) 链接到 `target` 标签的链接列表。`target` 的内部状态会记录着上一个链接的位置是 100。
3. 当执行 `Bind(&target)` 时，`bind_to()` 会被调用，传入 `target` 标签和当前位置 200。
4. `bind_to()` 会遍历 `target` 标签的链接列表，找到之前链接的位置 100。
5. 它会计算跳转偏移量：`200 - 100 = 100`。
6. 它会更新位置 100 的分支指令，将跳转目标设置为偏移量 100。具体的指令编码会根据 RISC-V 的分支指令格式进行。

**假设输出 (在位置 100 的指令):**

位置 100 的分支指令会被修改，使其能够跳转到偏移量为 100 的位置。具体的机器码会根据 RISC-V 的指令编码而定，但逻辑上是设置了正确的跳转目标。

**如果涉及用户常见的编程错误，请举例说明:**

一个常见的与汇编器相关的编程错误是 **跳转目标超出短跳转的范围**。

例如，在生成代码时，如果两个需要跳转的代码块之间的距离太远，以至于无法用 RISC-V 的短分支指令直接跳转，就会发生错误。

**示例:**

```c++
Label far_away;
// ... 生成大量的代码 ...
B(&far_away); // 尝试短跳转到 far_away

// ... 生成更多大量的代码 ...
Bind(&far_away);
```

在这种情况下，如果 `B` 指令是短分支指令，而 `far_away` 标签绑定的位置距离 `B` 指令的位置太远，就会导致跳转偏移量超出短分支指令的表示范围。

V8 的汇编器通常会处理这种情况，例如通过使用跳转槽 (trampoline) 来实现长跳转。但在手动编写汇编代码或与汇编器交互时，程序员需要注意跳转范围的限制。如果 V8 没有正确处理或程序员直接操作底层指令，就可能导致程序崩溃或行为异常。

**总结一下它的功能 (第 1 部分):**

`v8/src/codegen/riscv/assembler-riscv.cc` 的第一部分主要负责构建 RISC-V 汇编器的基础框架，包括：

- **管理 CPU 特性检测和存储。**
- **定义和转换 RISC-V 寄存器。**
- **处理代码重定位信息。**
- **表示汇编操作数和内存操作数。**
- **实现汇编器的核心功能，如代码生成和对齐。**
- **管理代码标签的绑定和链接，用于实现跳转和分支。**
- **初步处理长跳转的情况，为后续的跳转槽机制打下基础。**
- **提供指令编码的辅助函数。**

总的来说，这一部分为在 V8 中生成 RISC-V 机器码提供了必要的工具和数据结构。

### 提示词
```
这是目录为v8/src/codegen/riscv/assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
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
// Copyright 2021 the V8 project authors. All rights reserved.

#include "src/codegen/riscv/assembler-riscv.h"

#include "src/base/bits.h"
#include "src/base/cpu.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/safepoint-table.h"
#include "src/common/code-memory-access-inl.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/diagnostics/disasm.h"
#include "src/diagnostics/disassembler.h"
#include "src/objects/heap-number-inl.h"

namespace v8 {
namespace internal {
// Get the CPU features enabled by the build. For cross compilation the
// preprocessor symbols __riscv_f and __riscv_d
// can be defined to enable FPU instructions when building the
// snapshot.
static unsigned CpuFeaturesImpliedByCompiler() {
  unsigned answer = 0;
#if defined(__riscv_f) && defined(__riscv_d)
  answer |= 1u << FPU;
#endif  // def __riscv_f

#if (defined __riscv_vector) && (__riscv_v >= 1000000)
  answer |= 1u << RISCV_SIMD;
#endif  // def CAN_USE_RVV_INSTRUCTIONS

#if (defined __riscv_zba)
  answer |= 1u << ZBA;
#endif  // def __riscv_zba

#if (defined __riscv_zbb)
  answer |= 1u << ZBB;
#endif  // def __riscv_zbb

#if (defined __riscv_zbs)
  answer |= 1u << ZBS;
#endif  // def __riscv_zbs

#if (defined _riscv_zicond)
  answer |= 1u << ZICOND;
#endif  // def _riscv_zicond
  return answer;
}

#ifdef _RISCV_TARGET_SIMULATOR
static unsigned SimulatorFeatures() {
  unsigned answer = 0;
  answer |= 1u << RISCV_SIMD;
  answer |= 1u << ZBA;
  answer |= 1u << ZBB;
  answer |= 1u << ZBS;
  answer |= 1u << ZICOND;
  answer |= 1u << FPU;
  return answer;
}
#endif

bool CpuFeatures::SupportsWasmSimd128() { return IsSupported(RISCV_SIMD); }

void CpuFeatures::ProbeImpl(bool cross_compile) {
  supported_ |= CpuFeaturesImpliedByCompiler();

#ifdef _RISCV_TARGET_SIMULATOR
  supported_ |= SimulatorFeatures();
#endif  // _RISCV_TARGET_SIMULATOR
  // Only use statically determined features for cross compile (snapshot).
  if (cross_compile) return;
  // Probe for additional features at runtime.

#ifndef USE_SIMULATOR
  base::CPU cpu;
  if (cpu.has_fpu()) supported_ |= 1u << FPU;
  if (cpu.has_rvv()) supported_ |= 1u << RISCV_SIMD;
  if (cpu.has_zba()) supported_ |= 1u << ZBA;
  if (cpu.has_zbb()) supported_ |= 1u << ZBB;
  if (cpu.has_zbs()) supported_ |= 1u << ZBS;
  if (v8_flags.riscv_b_extension) {
    supported_ |= (1u << ZBA) | (1u << ZBB) | (1u << ZBS);
  }
#ifdef V8_COMPRESS_POINTERS
  if (cpu.riscv_mmu() == base::CPU::RV_MMU_MODE::kRiscvSV57) {
    FATAL("SV57 is not supported");
    UNIMPLEMENTED();
  }
#endif  // V8_COMPRESS_POINTERS
#endif  // USE_SIMULATOR
  // Set a static value on whether SIMD is supported.
  // This variable is only used for certain archs to query SupportWasmSimd128()
  // at runtime in builtins using an extern ref. Other callers should use
  // CpuFeatures::SupportWasmSimd128().
  CpuFeatures::supports_wasm_simd_128_ = CpuFeatures::SupportsWasmSimd128();
}

void CpuFeatures::PrintTarget() {}
void CpuFeatures::PrintFeatures() {
  printf("supports_wasm_simd_128=%d\n", CpuFeatures::SupportsWasmSimd128());
  printf("RISC-V Extension zba=%d,zbb=%d,zbs=%d,ZICOND=%d\n",
         CpuFeatures::IsSupported(ZBA), CpuFeatures::IsSupported(ZBB),
         CpuFeatures::IsSupported(ZBS), CpuFeatures::IsSupported(ZICOND));
}
int ToNumber(Register reg) {
  DCHECK(reg.is_valid());
  const int kNumbers[] = {
      0,   // zero_reg
      1,   // ra
      2,   // sp
      3,   // gp
      4,   // tp
      5,   // t0
      6,   // t1
      7,   // t2
      8,   // s0/fp
      9,   // s1
      10,  // a0
      11,  // a1
      12,  // a2
      13,  // a3
      14,  // a4
      15,  // a5
      16,  // a6
      17,  // a7
      18,  // s2
      19,  // s3
      20,  // s4
      21,  // s5
      22,  // s6
      23,  // s7
      24,  // s8
      25,  // s9
      26,  // s10
      27,  // s11
      28,  // t3
      29,  // t4
      30,  // t5
      31,  // t6
  };
  return kNumbers[reg.code()];
}

Register ToRegister(int num) {
  DCHECK(num >= 0 && num < kNumRegisters);
  const Register kRegisters[] = {
      zero_reg, ra, sp, gp, tp, t0, t1, t2, fp, s1, a0,  a1,  a2, a3, a4, a5,
      a6,       a7, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, t3, t4, t5, t6};
  return kRegisters[num];
}

// -----------------------------------------------------------------------------
// Implementation of RelocInfo.

const int RelocInfo::kApplyMask =
    RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
    RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE_ENCODED) |
    RelocInfo::ModeMask(RelocInfo::NEAR_BUILTIN_ENTRY) |
    RelocInfo::ModeMask(RelocInfo::RELATIVE_CODE_TARGET);

bool RelocInfo::IsCodedSpecially() {
  // The deserializer needs to know whether a pointer is specially coded.  Being
  // specially coded on RISC-V means that it is a lui/addi instruction, and that
  // is always the case inside code objects.
  return true;
}

bool RelocInfo::IsInConstantPool() { return false; }

uint32_t RelocInfo::wasm_call_tag() const {
  DCHECK(rmode_ == WASM_CALL || rmode_ == WASM_STUB_CALL);
  Instr instr = Assembler::instr_at(pc_);
  Instr instr1 = Assembler::instr_at(pc_ + 1 * kInstrSize);
  if (Assembler::IsAuipc(instr) && Assembler::IsJalr(instr1)) {
    DCHECK(reinterpret_cast<Instruction*>(pc_)->RdValue() ==
           reinterpret_cast<Instruction*>(pc_ + 4)->Rs1Value());
    return Assembler::BrachlongOffset(instr, instr1);
  } else {
    return static_cast<uint32_t>(
        Assembler::target_address_at(pc_, constant_pool_));
  }
}

// -----------------------------------------------------------------------------
// Implementation of Operand and MemOperand.
// See assembler-riscv-inl.h for inlined constructors.

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
    Handle<HeapObject> object =
        isolate->factory()->NewHeapNumber<AllocationType::kOld>(
            request.heap_number());
    Address pc = reinterpret_cast<Address>(buffer_start_) + request.offset();
    set_target_value_at(pc, reinterpret_cast<uintptr_t>(object.location()));
  }
}

// -----------------------------------------------------------------------------
// Specific instructions, constants, and masks.

Assembler::Assembler(const AssemblerOptions& options,
                     std::unique_ptr<AssemblerBuffer> buffer)
    : AssemblerBase(options, std::move(buffer)),
      VU(this),
      scratch_register_list_(DefaultTmpList()),
      scratch_double_register_list_(DefaultFPTmpList()),
      constpool_(this) {
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

void Assembler::AbortedCodeGeneration() { constpool_.Clear(); }
Assembler::~Assembler() { CHECK(constpool_.IsEmpty()); }

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

  ForceConstantPoolEmissionWithoutJump();

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
  while ((pc_offset() & (m - 1)) != 0) {
    NOP();
  }
}

void Assembler::CodeTargetAlign() {
  // No advantage to aligning branch/call targets to more than
  // single instruction, that I am aware of.
  Align(4);
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

// The link chain is terminated by a value in the instruction of 0,
// which is an otherwise illegal value (branch 0 is inf loop). When this case
// is detected, return an position of -1, an otherwise illegal position.
const int kEndOfChain = -1;
const int kEndOfJumpChain = 0;

int Assembler::target_at(int pos, bool is_internal) {
  if (is_internal) {
    uintptr_t* p = reinterpret_cast<uintptr_t*>(buffer_start_ + pos);
    uintptr_t address = *p;
    if (address == kEndOfJumpChain) {
      return kEndOfChain;
    } else {
      uintptr_t instr_address = reinterpret_cast<uintptr_t>(p);
      DCHECK(instr_address - address < INT_MAX);
      int delta = static_cast<int>(instr_address - address);
      DCHECK(pos > delta);
      return pos - delta;
    }
  }
  Instruction* instruction = Instruction::At(buffer_start_ + pos);
  DEBUG_PRINTF("target_at: %p (%d)\n\t",
               reinterpret_cast<Instr*>(buffer_start_ + pos), pos);
  Instr instr = instruction->InstructionBits();
  disassembleInstr(buffer_start_ + pos);

  switch (instruction->InstructionOpcodeType()) {
    case BRANCH: {
      int32_t imm13 = BranchOffset(instr);
      if (imm13 == kEndOfJumpChain) {
        // EndOfChain sentinel is returned directly, not relative to pc or pos.
        return kEndOfChain;
      } else {
        return pos + imm13;
      }
    }
    case JAL: {
      int32_t imm21 = JumpOffset(instr);
      if (imm21 == kEndOfJumpChain) {
        // EndOfChain sentinel is returned directly, not relative to pc or pos.
        return kEndOfChain;
      } else {
        return pos + imm21;
      }
    }
    case JALR: {
      int32_t imm12 = instr >> 20;
      if (imm12 == kEndOfJumpChain) {
        // EndOfChain sentinel is returned directly, not relative to pc or pos.
        return kEndOfChain;
      } else {
        return pos + imm12;
      }
    }
    case LUI: {
      Address pc = reinterpret_cast<Address>(buffer_start_ + pos);
      pc = target_address_at(pc);
      uintptr_t instr_address =
          reinterpret_cast<uintptr_t>(buffer_start_ + pos);
      uintptr_t imm = reinterpret_cast<uintptr_t>(pc);
      if (imm == kEndOfJumpChain) {
        return kEndOfChain;
      } else {
        DCHECK(instr_address - imm < INT_MAX);
        int32_t delta = static_cast<int32_t>(instr_address - imm);
        DCHECK(pos > delta);
        return pos - delta;
      }
    }
    case AUIPC: {
      Instr instr_auipc = instr;
      Instr instr_I = instr_at(pos + 4);
      DCHECK(IsJalr(instr_I) || IsAddi(instr_I));
      int32_t offset = BrachlongOffset(instr_auipc, instr_I);
      if (offset == kEndOfJumpChain) return kEndOfChain;
      return offset + pos;
    }
    case RO_C_J: {
      int32_t offset = instruction->RvcImm11CJValue();
      if (offset == kEndOfJumpChain) return kEndOfChain;
      return offset + pos;
    }
    case RO_C_BNEZ:
    case RO_C_BEQZ: {
      int32_t offset = instruction->RvcImm8BValue();
      if (offset == kEndOfJumpChain) return kEndOfChain;
      return pos + offset;
    }
    default: {
      if (instr == kEndOfJumpChain) {
        return kEndOfChain;
      } else {
        int32_t imm18 =
            ((instr & static_cast<int32_t>(kImm16Mask)) << 16) >> 14;
        return (imm18 + pos);
      }
    }
  }
}

[[nodiscard]] static inline Instr SetBranchOffset(int32_t pos,
                                                  int32_t target_pos,
                                                  Instr instr) {
  int32_t imm = target_pos - pos;
  DCHECK_EQ(imm & 1, 0);
  DCHECK(is_intn(imm, Assembler::kBranchOffsetBits));

  instr &= ~kBImm12Mask;
  int32_t imm12 = ((imm & 0x800) >> 4) |   // bit  11
                  ((imm & 0x1e) << 7) |    // bits 4-1
                  ((imm & 0x7e0) << 20) |  // bits 10-5
                  ((imm & 0x1000) << 19);  // bit 12

  return instr | (imm12 & kBImm12Mask);
}

[[nodiscard]] static inline Instr SetLoadOffset(int32_t offset, Instr instr) {
#if V8_TARGET_ARCH_RISCV64
  DCHECK(Assembler::IsLd(instr));
#elif V8_TARGET_ARCH_RISCV32
  DCHECK(Assembler::IsLw(instr));
#endif
  DCHECK(is_int12(offset));
  instr &= ~kImm12Mask;
  int32_t imm12 = offset << kImm12Shift;
  return instr | (imm12 & kImm12Mask);
}

[[nodiscard]] static inline Instr SetAuipcOffset(int32_t offset, Instr instr) {
  DCHECK(Assembler::IsAuipc(instr));
  DCHECK(is_int20(offset));
  instr = (instr & ~kImm31_12Mask) | ((offset & kImm19_0Mask) << 12);
  return instr;
}

[[nodiscard]] static inline Instr SetJalrOffset(int32_t offset, Instr instr) {
  DCHECK(Assembler::IsJalr(instr));
  DCHECK(is_int12(offset));
  instr &= ~kImm12Mask;
  int32_t imm12 = offset << kImm12Shift;
  DCHECK(Assembler::IsJalr(instr | (imm12 & kImm12Mask)));
  DCHECK_EQ(Assembler::JalrOffset(instr | (imm12 & kImm12Mask)), offset);
  return instr | (imm12 & kImm12Mask);
}

[[nodiscard]] static inline Instr SetJalOffset(int32_t pos, int32_t target_pos,
                                               Instr instr) {
  DCHECK(Assembler::IsJal(instr));
  int32_t imm = target_pos - pos;
  DCHECK_EQ(imm & 1, 0);
  DCHECK(is_intn(imm, Assembler::kJumpOffsetBits));

  instr &= ~kImm20Mask;
  int32_t imm20 = (imm & 0xff000) |          // bits 19-12
                  ((imm & 0x800) << 9) |     // bit  11
                  ((imm & 0x7fe) << 20) |    // bits 10-1
                  ((imm & 0x100000) << 11);  // bit  20

  return instr | (imm20 & kImm20Mask);
}

[[nodiscard]] static inline ShortInstr SetCJalOffset(int32_t pos,
                                                     int32_t target_pos,
                                                     Instr instr) {
  DCHECK(Assembler::IsCJal(instr));
  int32_t imm = target_pos - pos;
  DCHECK_EQ(imm & 1, 0);
  DCHECK(is_intn(imm, Assembler::kCJalOffsetBits));
  instr &= ~kImm11Mask;
  int16_t imm11 = ((imm & 0x800) >> 1) | ((imm & 0x400) >> 4) |
                  ((imm & 0x300) >> 1) | ((imm & 0x80) >> 3) |
                  ((imm & 0x40) >> 1) | ((imm & 0x20) >> 5) |
                  ((imm & 0x10) << 5) | (imm & 0xe);
  imm11 = imm11 << kImm11Shift;
  DCHECK(Assembler::IsCJal(instr | (imm11 & kImm11Mask)));
  return instr | (imm11 & kImm11Mask);
}
[[nodiscard]] static inline Instr SetCBranchOffset(int32_t pos,
                                                   int32_t target_pos,
                                                   Instr instr) {
  DCHECK(Assembler::IsCBranch(instr));
  int32_t imm = target_pos - pos;
  DCHECK_EQ(imm & 1, 0);
  DCHECK(is_intn(imm, Assembler::kCBranchOffsetBits));

  instr &= ~kRvcBImm8Mask;
  int32_t imm8 = ((imm & 0x20) >> 5) | ((imm & 0x6)) | ((imm & 0xc0) >> 3) |
                 ((imm & 0x18) << 2) | ((imm & 0x100) >> 1);
  imm8 = ((imm8 & 0x1f) << 2) | ((imm8 & 0xe0) << 5);
  DCHECK(Assembler::IsCBranch(instr | imm8 & kRvcBImm8Mask));

  return instr | (imm8 & kRvcBImm8Mask);
}

// We have to use a temporary register for things that can be relocated even
// if they can be encoded in RISC-V's 12 bits of immediate-offset instruction
// space.  There is no guarantee that the relocated location can be similarly
// encoded.
bool Assembler::MustUseReg(RelocInfo::Mode rmode) {
  return !RelocInfo::IsNoInfo(rmode);
}

void Assembler::disassembleInstr(uint8_t* pc) {
  if (!v8_flags.riscv_debug) return;
  disasm::NameConverter converter;
  disasm::Disassembler disasm(converter);
  base::EmbeddedVector<char, 128> disasm_buffer;

  disasm.InstructionDecode(disasm_buffer, pc);
  DEBUG_PRINTF("%s\n", disasm_buffer.begin());
}

void Assembler::target_at_put(int pos, int target_pos, bool is_internal) {
  if (is_internal) {
    uintptr_t imm = reinterpret_cast<uintptr_t>(buffer_start_) + target_pos;
    *reinterpret_cast<uintptr_t*>(buffer_start_ + pos) = imm;
    return;
  }
  DEBUG_PRINTF("\ttarget_at_put: %p (%d) to %p (%d)\n",
               reinterpret_cast<Instr*>(buffer_start_ + pos), pos,
               reinterpret_cast<Instr*>(buffer_start_ + target_pos),
               target_pos);
  Instruction* instruction = Instruction::At(buffer_start_ + pos);
  Instr instr = instruction->InstructionBits();

  switch (instruction->InstructionOpcodeType()) {
    case BRANCH: {
      instr = SetBranchOffset(pos, target_pos, instr);
      instr_at_put(pos, instr);
    } break;
    case JAL: {
      DCHECK(IsJal(instr));
      intptr_t offset = target_pos - pos;
      if (is_intn(offset, Assembler::kJumpOffsetBits)) {
        instr = SetJalOffset(pos, target_pos, instr);
        instr_at_put(pos, instr);
      } else {
        Instr instr_I = instr_at(pos + 4);
        CHECK_EQ(instr_I, kNopByte);
        CHECK(is_int32(offset + 0x800));
        Instr instr_auipc = AUIPC | t6.code() << kRdShift;
        instr_I = RO_JALR | (t6.code() << kRs1Shift) |
                  (instruction->RdValue() << kRdShift);

        int32_t Hi20 = (((int32_t)offset + 0x800) >> 12);
        int32_t Lo12 = (int32_t)offset << 20 >> 20;

        instr_auipc = SetAuipcOffset(Hi20, instr_auipc);
        instr_at_put(pos, instr_auipc);

        instr_I = SetJalrOffset(Lo12, instr_I);
        instr_at_put(pos + 4, instr_I);
        DCHECK_EQ(offset, BrachlongOffset(Assembler::instr_at(pos),
                                          Assembler::instr_at(pos + 4)));
      }
    } break;
    case LUI: {
      Address pc = reinterpret_cast<Address>(buffer_start_ + pos);
      set_target_value_at(
          pc, reinterpret_cast<uintptr_t>(buffer_start_ + target_pos));
    } break;
    case AUIPC: {
      Instr instr_auipc = instr;
      Instr instr_I = instr_at(pos + 4);
      Instruction* instruction_I = Instruction::At(buffer_start_ + pos + 4);
      DCHECK(IsJalr(instr_I) || IsAddi(instr_I));

      intptr_t offset = target_pos - pos;
      if (is_int21(offset) && IsJalr(instr_I) &&
          (instruction->RdValue() == instruction_I->Rs1Value())) {
        if (v8_flags.riscv_debug) {
          disassembleInstr(buffer_start_ + pos);
          disassembleInstr(buffer_start_ + pos + 4);
        }
        DEBUG_PRINTF("\ttarget_at_put: Relpace by JAL pos:(%d) \n", pos);
        DCHECK(is_int21(offset) && ((offset & 1) == 0));
        Instr instr = JAL | (instruction_I->RdValue() << kRdShift);
        instr = SetJalOffset(pos, target_pos, instr);
        DCHECK(IsJal(instr));
        DCHECK(JumpOffset(instr) == offset);
        instr_at_put(pos, instr);
        instr_at_put(pos + 4, kNopByte);
      } else {
        CHECK(is_int32(offset + 0x800));

        int32_t Hi20 = (((int32_t)offset + 0x800) >> 12);
        int32_t Lo12 = (int32_t)offset << 20 >> 20;

        instr_auipc = SetAuipcOffset(Hi20, instr_auipc);
        instr_at_put(pos, instr_auipc);

        const int kImm31_20Mask = ((1 << 12) - 1) << 20;
        const int kImm11_0Mask = ((1 << 12) - 1);
        instr_I = (instr_I & ~kImm31_20Mask) | ((Lo12 & kImm11_0Mask) << 20);
        instr_at_put(pos + 4, instr_I);
      }
    } break;
    case RO_C_J: {
      ShortInstr short_instr = SetCJalOffset(pos, target_pos, instr);
      instr_at_put(pos, short_instr);
    } break;
    case RO_C_BNEZ:
    case RO_C_BEQZ: {
      instr = SetCBranchOffset(pos, target_pos, instr);
      instr_at_put(pos, instr);
    } break;
    default: {
      // Emitted label constant, not part of a branch.
      // Make label relative to Code pointer of generated InstructionStream
      // object.
      instr_at_put(
          pos, target_pos + (InstructionStream::kHeaderSize - kHeapObjectTag));
    } break;
  }

  disassembleInstr(buffer_start_ + pos);
  if (instruction->InstructionOpcodeType() == AUIPC) {
    disassembleInstr(buffer_start_ + pos + 4);
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
  DEBUG_PRINTF("\tbinding %d to label %p\n", pos, L);
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
    next(L, is_internal);  // Call next before overwriting link with target
                           // at fixup_pos.
    Instr instr = instr_at(fixup_pos);
    DEBUG_PRINTF("\tfixup: %d to %d\n", fixup_pos, dist);
    if (is_internal) {
      target_at_put(fixup_pos, pos, is_internal);
    } else {
      if (IsBranch(instr)) {
        if (dist > kMaxBranchOffset) {
          if (trampoline_pos == kInvalidSlotPos) {
            trampoline_pos = get_trampoline_entry(fixup_pos);
            CHECK_NE(trampoline_pos, kInvalidSlotPos);
          }
          CHECK((trampoline_pos - fixup_pos) <= kMaxBranchOffset);
          DEBUG_PRINTF("\t\ttrampolining: %d\n", trampoline_pos);
          target_at_put(fixup_pos, trampoline_pos, false);
          fixup_pos = trampoline_pos;
        }
        target_at_put(fixup_pos, pos, false);
      } else if (IsJal(instr)) {
        if (dist > kMaxJumpOffset) {
          if (trampoline_pos == kInvalidSlotPos) {
            trampoline_pos = get_trampoline_entry(fixup_pos);
            CHECK_NE(trampoline_pos, kInvalidSlotPos);
          }
          CHECK((trampoline_pos - fixup_pos) <= kMaxJumpOffset);
          DEBUG_PRINTF("\t\ttrampolining: %d\n", trampoline_pos);
          target_at_put(fixup_pos, trampoline_pos, false);
          fixup_pos = trampoline_pos;
        }
        target_at_put(fixup_pos, pos, false);
      } else {
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
    DEBUG_PRINTF("\tnext: %p to %p (%d)\n", L,
                 reinterpret_cast<Instr*>(buffer_start_ + link), link);
    L->link_to(link);
  }
}

bool Assembler::is_near(Label* L) {
  DCHECK(L->is_bound());
  return is_intn((pc_offset() - L->pos()), kJumpOffsetBits);
}

bool Assembler::is_near(Label* L, OffsetSize bits) {
  if (L == nullptr || !L->is_bound()) return true;
  return is_intn((pc_offset() - L->pos()), bits);
}

bool Assembler::is_near_branch(Label* L) {
  DCHECK(L->is_bound());
  return is_intn((pc_offset() - L->pos()), kBranchOffsetBits);
}

int Assembler::BranchOffset(Instr instr) {
  // | imm[12] | imm[10:5] | rs2 | rs1 | funct3 | imm[4:1|11] | opcode |
  //  31          25                      11          7
  int32_t imm13 = ((instr & 0xf00) >> 7) | ((instr & 0x7e000000) >> 20) |
                  ((instr & 0x80) << 4) | ((instr & 0x80000000) >> 19);
  imm13 = imm13 << 19 >> 19;
  return imm13;
}

int Assembler::BrachlongOffset(Instr auipc, Instr instr_I) {
  DCHECK(reinterpret_cast<Instruction*>(&instr_I)->InstructionType() ==
         InstructionBase::kIType);
  DCHECK(IsAuipc(auipc));
  DCHECK_EQ((auipc & kRdFieldMask) >> kRdShift,
            (instr_I & kRs1FieldMask) >> kRs1Shift);
  int32_t imm_auipc = AuipcOffset(auipc);
  int32_t imm12 = static_cast<int32_t>(instr_I & kImm12Mask) >> 20;
  int32_t offset = imm12 + imm_auipc;
  return offset;
}

int Assembler::PatchBranchlongOffset(Address pc, Instr instr_auipc,
                                     Instr instr_jalr, int32_t offset,
                                     WritableJitAllocation* jit_allocation) {
  DCHECK(IsAuipc(instr_auipc));
  DCHECK(IsJalr(instr_jalr));
  CHECK(is_int32(offset + 0x800));
  int32_t Hi20 = (((int32_t)offset + 0x800) >> 12);
  int32_t Lo12 = (int32_t)offset << 20 >> 20;
  instr_at_put(pc, SetAuipcOffset(Hi20, instr_auipc), jit_allocation);
  instr_at_put(pc + 4, SetJalrOffset(Lo12, instr_jalr), jit_allocation);
  DCHECK(offset ==
         BrachlongOffset(Assembler::instr_at(pc), Assembler::instr_at(pc + 4)));
  return 2;
}

// Returns the next free trampoline entry.
int32_t Assembler::get_trampoline_entry(int32_t pos) {
  int32_t trampoline_entry = kInvalidSlotPos;
  if (!internal_trampoline_exception_) {
    DEBUG_PRINTF("\ttrampoline start: %d,pos: %d\n", trampoline_.start(), pos);
    if (trampoline_.start() > pos) {
      trampoline_entry = trampoline_.take_slot();
    }

    if (kInvalidSlotPos == trampoline_entry) {
      internal_trampoline_exception_ = true;
    }
  }
  return trampoline_entry;
}

uintptr_t Assembler::jump_address(Label* L) {
  intptr_t target_pos;
  DEBUG_PRINTF("\tjump_address: %p to %p (%d)\n", L,
               reinterpret_cast<Instr*>(buffer_start_ + pc_offset()),
               pc_offset());
  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      L->link_to(pc_offset());
    } else {
      L->link_to(pc_offset());
      if (!trampoline_emitted_) {
        unbound_labels_count_++;
        next_buffer_check_ -= kTrampolineSlotsSize;
      }
      DEBUG_PRINTF("\tstarted link\n");
      return kEndOfJumpChain;
    }
  }
  uintptr_t imm = reinterpret_cast<uintptr_t>(buffer_start_) + target_pos;
  if (v8_flags.riscv_c_extension)
    DCHECK_EQ(imm & 1, 0);
  else
    DCHECK_EQ(imm & 3, 0);

  return imm;
}

int32_t Assembler::branch_long_offset(Label* L) {
  intptr_t target_pos;

  DEBUG_PRINTF("\tbranch_long_offset: %p to %p (%d)\n", L,
               reinterpret_cast<Instr*>(buffer_start_ + pc_offset()),
               pc_offset());
  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      L->link_to(pc_offset());
    } else {
      L->link_to(pc_offset());
      if (!trampoline_emitted_) {
        unbound_labels_count_++;
        next_buffer_check_ -= kTrampolineSlotsSize;
      }
      DEBUG_PRINTF("\tstarted link\n");
      return kEndOfJumpChain;
    }
  }
  intptr_t offset = target_pos - pc_offset();
  if (v8_flags.riscv_c_extension)
    DCHECK_EQ(offset & 1, 0);
  else
    DCHECK_EQ(offset & 3, 0);
  DCHECK(is_int32(offset));
  VU.clear();
  return static_cast<int32_t>(offset);
}

int32_t Assembler::branch_offset_helper(Label* L, OffsetSize bits) {
  int32_t target_pos;

  DEBUG_PRINTF("\tbranch_offset_helper: %p to %p (%d)\n", L,
               reinterpret_cast<Instr*>(buffer_start_ + pc_offset()),
               pc_offset());
  if (L->is_bound()) {
    target_pos = L->pos();
    DEBUG_PRINTF("\tbound: %d", target_pos);
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();
      L->link_to(pc_offset());
      DEBUG_PRINTF("\tadded to link: %d\n", target_pos);
    } else {
      L->link_to(pc_offset());
      if (!trampoline_emitted_) {
        unbound_labels_count_++;
        next_buffer_check_ -= kTrampolineSlotsSize;
      }
      DEBUG_PRINTF("\tstarted link\n");
      return kEndOfJumpChain;
    }
  }

  int32_t offset = target_pos - pc_offset();
  DCHECK(is_intn(offset, bits));
  DCHECK_EQ(offset & 1, 0);
  DEBUG_PRINTF("\toffset = %d\n", offset);
  VU.clear();
  return offset;
}

void Assembler
```