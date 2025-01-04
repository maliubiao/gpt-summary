Response: My thinking process to summarize the C++ code and relate it to JavaScript functionality goes like this:

1. **Understand the Goal:** The request asks for a summary of the provided C++ code's functionality, specifically in the context of its relationship to JavaScript. It also emphasizes this is the *first part* of a larger file, suggesting focusing on the initial set of definitions and functionality.

2. **Initial Scan for Keywords and Structure:** I quickly scan the code for important keywords and structural elements:
    * `Copyright`, `Redistribution`:  Standard license information. Less relevant to the core functionality.
    * `#if V8_TARGET_ARCH_ARM64`: This is crucial. It tells me this code is specific to the ARM64 architecture.
    * `#include`:  Indicates dependencies on other V8 components (`assembler-arm64.h`, `base/bits.h`, etc.). This hints at the code's role in code generation.
    * `namespace v8 { namespace internal {`:  Confirms this is part of the V8 JavaScript engine's internals.
    * `class Assembler`: A key class likely responsible for generating machine code.
    * Functions like `b`, `bl`, `ldr`, `str`, `add`, `sub`, etc.: These look like ARM64 assembly instructions.
    * Sections about `CpuFeatures`, `CPURegList`, `RelocInfo`:  These are data structures and utilities used in the assembly process.
    * Conditional compilation (`#ifdef`, `#ifndef`):  Highlights platform-specific or build-specific logic.

3. **Focus on the Core Class:** The `Assembler` class seems to be the central component. Its constructor, destructor, and methods will likely reveal the main purpose.

4. **Identify Key Functionality Blocks:** I start to group related parts of the code:
    * **CPU Feature Detection (`CpuFeatures`):** This section clearly deals with identifying what ARM64 CPU features are supported (e.g., SIMD, atomics). This is important for optimizing code generation for different hardware.
    * **Register Management (`CPURegList`):**  This class manages lists of CPU registers, categorizing them as callee-saved, caller-saved, etc. This is fundamental for function calls and preserving data.
    * **Relocation Information (`RelocInfo`):** This appears to handle information about addresses within the generated code that need to be adjusted later (e.g., function calls, data addresses).
    * **Instruction Emission (Methods of `Assembler`):** The various `b`, `ldr`, `str`, `add`, etc., methods are for emitting specific ARM64 instructions. The names are highly suggestive of assembly language mnemonics.
    * **Label Management (`Label` interactions):**  The code deals with linking and binding labels, which are essential for implementing control flow (jumps, branches).
    * **Constant Pool (`ConstantPool` interactions):**  The mention of a constant pool suggests a mechanism for storing constant values used in the generated code.

5. **Infer the Overall Function:** Based on the identified blocks, the primary function of this code is to **generate ARM64 machine code for the V8 JavaScript engine.** It's an *assembler* in the traditional sense, but operating within the V8 environment.

6. **Connect to JavaScript:** Now, the crucial step is to link this back to JavaScript. How does this low-level code relate to what a JavaScript developer writes?
    * **Compilation:** JavaScript code needs to be translated into machine code for the CPU to execute. This `assembler-arm64.cc` file is a *part* of that compilation process for ARM64.
    * **Optimization:** The CPU feature detection directly impacts how efficiently JavaScript can run. For example, if the CPU supports SIMD instructions, V8 can use them to speed up array operations or other data-parallel tasks in JavaScript.
    * **Function Calls:** The register management is critical for implementing how JavaScript functions are called and how data is passed between them.
    * **Memory Access:** The `ldr` and `str` instructions are used to load and store data in memory, which is how JavaScript variables and objects are accessed.
    * **Control Flow:** JavaScript's `if`, `else`, `for`, `while` statements are ultimately translated into conditional and unconditional jumps managed by the label linking/binding mechanisms.

7. **Construct JavaScript Examples:** To illustrate the connection, I create simple JavaScript examples that would likely result in the use of the functionalities described in the C++ code:
    * **Arithmetic:**  `let sum = a + b;`  This would likely use `add` instructions.
    * **Conditional Logic:** `if (x > 10) { ... }` This involves comparison instructions (`cmp`) and conditional branches (`b.cond`).
    * **Function Calls:** `function myFunction() { ... }; myFunction();` This relates to the register management (saving/restoring registers) and the `bl` (branch and link) instruction.
    * **Array/Data Manipulation (if SIMD is mentioned):**  `const arr = [1, 2, 3]; const doubled = arr.map(x => x * 2);` This could potentially use SIMD instructions if the CPU supports them.

8. **Refine the Summary:**  Finally, I synthesize the gathered information into a concise summary, highlighting the key responsibilities of the file and explicitly linking it to JavaScript concepts with illustrative examples. I also acknowledge that this is just the first part of the file and anticipate further functionalities in subsequent parts. I make sure to use clear language and avoid overly technical jargon where possible, while still being accurate.
这是一个C++源代码文件，属于V8 JavaScript引擎中针对ARM64架构的代码生成器部分。它的主要功能是：

**作为 ARM64 汇编器:**

这个文件定义了一个 `Assembler` 类，它提供了一组用于生成 ARM64 汇编指令的接口。可以将其视为一个“高级”汇编器，它封装了底层的指令编码细节，让V8引擎更容易地生成目标平台的机器码。

**具体功能点（基于第一部分内容）：**

* **CPU 特性检测 (`CpuFeatures`):**  它负责检测当前运行的ARM64 CPU 支持哪些可选特性（例如：JSCVT, DOTPROD, LSE, PMULL1Q, FP16）。这些特性会影响到生成的代码可以使用的优化方式。它会尝试从编译器定义、目标操作系统以及运行时进行探测。
* **寄存器列表管理 (`CPURegList`):**  提供了一种管理和操作 ARM64 寄存器列表的方式。可以方便地获取特定类型的寄存器（通用寄存器、浮点寄存器），并区分调用者保存和被调用者保存的寄存器。这对于函数调用约定和代码优化非常重要。
* **重定位信息 (`RelocInfo`):**  处理代码中需要稍后进行地址修正的信息，例如函数调用目标地址、内建函数入口地址、内部引用以及Wasm stub调用。它可以判断一个指令是否包含需要特殊处理的地址，以及是否位于常量池中。
* **指令发射 (各种汇编指令方法):** 提供了大量的成员函数，对应于不同的 ARM64 汇编指令，例如：
    * **分支指令:** `b`, `bl`, `cbz`, `cbnz`, `tbz`, `tbnz`
    * **地址计算:** `adr`
    * **算术运算:** `add`, `adds`, `sub`, `subs`, `mul`, `div` 等
    * **逻辑运算:** `and_`, `orr`, `eor` 等
    * **位操作:** `bfm`, `sbfm`, `ubfm` 等
    * **条件选择:** `csel`, `csinc`, `csinv`, `csneg`
    * **内存访问:** `ldr`, `str`, `ldp`, `stp`, 以及原子操作相关的指令 (`ldar`, `stlr`, `cas` 等)
    * **NEON/SIMD 指令:**  例如 `sdot` (点积运算) 以及其他更通用的 NEON 指令生成方法 (`NEON3DifferentL`, `NEONPerm` 等)。
* **标签 (Label) 管理:**  允许定义和绑定代码标签，用于实现跳转和分支。它管理着未解析的分支，并在标签绑定时更新这些分支的目标地址。
* **常量池管理 (`ConstantPool`):**  负责管理代码中的常量池，用于存储字面量值，例如立即数或者对象的地址。
* **代码对齐:** 提供了 `Align` 和 `CodeTargetAlign` 方法，确保生成的代码按照特定的边界对齐，提高执行效率。
* **获取代码 (`GetCode`):** 提供将生成的汇编代码转换为可执行 `CodeDesc` 的方法，包括处理重定位信息、安全点信息、异常处理表等。

**与 JavaScript 功能的关系 (使用 JavaScript 举例说明):**

这个 `assembler-arm64.cc` 文件是 V8 引擎将 JavaScript 代码转换为机器码的关键组成部分。当 V8 执行 JavaScript 代码时，它会根据需要生成对应的 ARM64 汇编指令。

**例如：**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 编译执行 `add` 函数时，`assembler-arm64.cc` 中的方法会被调用，可能生成如下类似的 ARM64 汇编指令：

```assembly
// 假设 a 和 b 的值分别在寄存器 x0 和 x1 中
add x2, x0, x1  // 将 x0 和 x1 的值相加，结果存入 x2
mov x0, x2      // 将结果从 x2 移动到返回值寄存器 x0
ret             // 返回
```

再例如：

```javascript
if (x > 10) {
  console.log("x is greater than 10");
} else {
  console.log("x is not greater than 10");
}
```

这段 JavaScript 代码会涉及条件分支，`assembler-arm64.cc` 可能会生成类似以下的指令：

```assembly
// 假设 x 的值在寄存器 w0 中
cmp w0, #10     // 将 w0 的值与 10 进行比较
ble .Lelse      // 如果小于等于，则跳转到 .Lelse 标签
// ... 输出 "x is greater than 10" 的代码 ...
b .LendIf       // 跳转到 .LendIf 标签
.Lelse:
// ... 输出 "x is not greater than 10" 的代码 ...
.LendIf:
```

**总结来说，`v8/src/codegen/arm64/assembler-arm64.cc` 提供了 V8 引擎在 ARM64 架构上生成高性能机器码的基础工具，它使得 JavaScript 代码能够在 ARM64 设备上高效地执行。**  第一部分的内容主要集中在基础的汇编器框架、CPU特性检测、寄存器管理以及基本的指令生成功能。后续的部分可能会包含更复杂的代码生成和优化逻辑。

Prompt: 
```
这是目录为v8/src/codegen/arm64/assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#if V8_TARGET_ARCH_ARM64

#include "src/codegen/arm64/assembler-arm64.h"

#include "src/base/bits.h"
#include "src/base/cpu.h"
#include "src/base/small-vector.h"
#include "src/codegen/arm64/assembler-arm64-inl.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/safepoint-table.h"
#include "src/execution/frame-constants.h"

namespace v8 {
namespace internal {

namespace {

#ifdef USE_SIMULATOR
unsigned SimulatorFeaturesFromCommandLine() {
  if (strcmp(v8_flags.sim_arm64_optional_features, "none") == 0) {
    return 0;
  }
  if (strcmp(v8_flags.sim_arm64_optional_features, "all") == 0) {
    return (1u << NUMBER_OF_CPU_FEATURES) - 1;
  }
  fprintf(
      stderr,
      "Error: unrecognised value for --sim-arm64-optional-features ('%s').\n",
      v8_flags.sim_arm64_optional_features.value());
  fprintf(stderr,
          "Supported values are:  none\n"
          "                       all\n");
  FATAL("sim-arm64-optional-features");
}
#endif  // USE_SIMULATOR

constexpr unsigned CpuFeaturesFromCompiler() {
  unsigned features = 0;
#if defined(__ARM_FEATURE_JCVT) && !defined(V8_TARGET_OS_IOS)
  features |= 1u << JSCVT;
#endif
#if defined(__ARM_FEATURE_DOTPROD)
  features |= 1u << DOTPROD;
#endif
#if defined(__ARM_FEATURE_ATOMICS)
  features |= 1u << LSE;
#endif
// There is no __ARM_FEATURE_PMULL macro; instead, __ARM_FEATURE_AES
// covers the FEAT_PMULL feature too.
#if defined(__ARM_FEATURE_AES)
  features |= 1u << PMULL1Q;
#endif
  return features;
}

constexpr unsigned CpuFeaturesFromTargetOS() {
  unsigned features = 0;
#if defined(V8_TARGET_OS_MACOS) && !defined(V8_TARGET_OS_IOS)
  // TODO(v8:13004): Detect if an iPhone is new enough to support jscvt, dotprot
  // and lse.
  features |= 1u << JSCVT;
  features |= 1u << DOTPROD;
  features |= 1u << LSE;
  features |= 1u << PMULL1Q;
#endif
  return features;
}

}  // namespace

// -----------------------------------------------------------------------------
// CpuFeatures implementation.
bool CpuFeatures::SupportsWasmSimd128() { return true; }

void CpuFeatures::ProbeImpl(bool cross_compile) {
  // Only use statically determined features for cross compile (snapshot).
  if (cross_compile) {
    supported_ |= CpuFeaturesFromCompiler();
    supported_ |= CpuFeaturesFromTargetOS();
    return;
  }

  // We used to probe for coherent cache support, but on older CPUs it
  // causes crashes (crbug.com/524337), and newer CPUs don't even have
  // the feature any more.

#ifdef USE_SIMULATOR
  supported_ |= SimulatorFeaturesFromCommandLine();
#else
  // Probe for additional features at runtime.
  base::CPU cpu;
  unsigned runtime = 0;
  if (cpu.has_jscvt()) {
    runtime |= 1u << JSCVT;
  }
  if (cpu.has_dot_prod()) {
    runtime |= 1u << DOTPROD;
  }
  if (cpu.has_lse()) {
    runtime |= 1u << LSE;
  }
  if (cpu.has_pmull1q()) {
    runtime |= 1u << PMULL1Q;
  }
  if (cpu.has_fp16()) {
    runtime |= 1u << FP16;
  }

  // Use the best of the features found by CPU detection and those inferred from
  // the build system.
  supported_ |= CpuFeaturesFromCompiler();
  supported_ |= runtime;
#endif  // USE_SIMULATOR

  // Set a static value on whether Simd is supported.
  // This variable is only used for certain archs to query SupportWasmSimd128()
  // at runtime in builtins using an extern ref. Other callers should use
  // CpuFeatures::SupportWasmSimd128().
  CpuFeatures::supports_wasm_simd_128_ = CpuFeatures::SupportsWasmSimd128();
}

void CpuFeatures::PrintTarget() {}
void CpuFeatures::PrintFeatures() {}

// -----------------------------------------------------------------------------
// CPURegList utilities.

CPURegister CPURegList::PopLowestIndex() {
  if (IsEmpty()) {
    return NoCPUReg;
  }
  int index = base::bits::CountTrailingZeros(list_);
  DCHECK((1LL << index) & list_);
  Remove(index);
  return CPURegister::Create(index, size_, type_);
}

CPURegister CPURegList::PopHighestIndex() {
  if (IsEmpty()) {
    return NoCPUReg;
  }
  int index = CountLeadingZeros(list_, kRegListSizeInBits);
  index = kRegListSizeInBits - 1 - index;
  DCHECK((1LL << index) & list_);
  Remove(index);
  return CPURegister::Create(index, size_, type_);
}

void CPURegList::Align() {
  // Use padreg, if necessary, to maintain stack alignment.
  if (Count() % 2 != 0) {
    if (IncludesAliasOf(padreg)) {
      Remove(padreg);
    } else {
      Combine(padreg);
    }
  }

  DCHECK_EQ(Count() % 2, 0);
}

CPURegList CPURegList::GetCalleeSaved(int size) {
  return CPURegList(CPURegister::kRegister, size, 19, 28);
}

CPURegList CPURegList::GetCalleeSavedV(int size) {
  return CPURegList(CPURegister::kVRegister, size, 8, 15);
}

CPURegList CPURegList::GetCallerSaved(int size) {
  // x18 is the platform register and is reserved for the use of platform ABIs.
  // Registers x0-x17 are caller-saved.
  CPURegList list = CPURegList(CPURegister::kRegister, size, 0, 17);
  return list;
}

CPURegList CPURegList::GetCallerSavedV(int size) {
  // Registers d0-d7 and d16-d31 are caller-saved.
  CPURegList list = CPURegList(CPURegister::kVRegister, size, 0, 7);
  list.Combine(CPURegList(CPURegister::kVRegister, size, 16, 31));
  return list;
}

// -----------------------------------------------------------------------------
// Implementation of RelocInfo

const int RelocInfo::kApplyMask =
    RelocInfo::ModeMask(RelocInfo::CODE_TARGET) |
    RelocInfo::ModeMask(RelocInfo::NEAR_BUILTIN_ENTRY) |
    RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
    RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL);

bool RelocInfo::IsCodedSpecially() {
  // The deserializer needs to know whether a pointer is specially coded. Being
  // specially coded on ARM64 means that it is an immediate branch.
  Instruction* instr = reinterpret_cast<Instruction*>(pc_);
  if (instr->IsLdrLiteralX()) {
    return false;
  } else {
    DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
    return true;
  }
}

bool RelocInfo::IsInConstantPool() {
  Instruction* instr = reinterpret_cast<Instruction*>(pc_);
  DCHECK_IMPLIES(instr->IsLdrLiteralW(), COMPRESS_POINTERS_BOOL);
  return instr->IsLdrLiteralX() ||
         (COMPRESS_POINTERS_BOOL && instr->IsLdrLiteralW());
}

uint32_t RelocInfo::wasm_call_tag() const {
  DCHECK(rmode_ == WASM_CALL || rmode_ == WASM_STUB_CALL);
  Instruction* instr = reinterpret_cast<Instruction*>(pc_);
  if (instr->IsLdrLiteralX()) {
    return static_cast<uint32_t>(
        Memory<Address>(Assembler::target_pointer_address_at(pc_)));
  } else {
    DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
    return static_cast<uint32_t>(instr->ImmPCOffset() / kInstrSize);
  }
}

bool AreAliased(const CPURegister& reg1, const CPURegister& reg2,
                const CPURegister& reg3, const CPURegister& reg4,
                const CPURegister& reg5, const CPURegister& reg6,
                const CPURegister& reg7, const CPURegister& reg8) {
  int number_of_valid_regs = 0;
  int number_of_valid_fpregs = 0;

  uint64_t unique_regs = 0;
  uint64_t unique_fpregs = 0;

  const CPURegister regs[] = {reg1, reg2, reg3, reg4, reg5, reg6, reg7, reg8};

  for (unsigned i = 0; i < arraysize(regs); i++) {
    if (regs[i].IsRegister()) {
      number_of_valid_regs++;
      unique_regs |= (uint64_t{1} << regs[i].code());
    } else if (regs[i].IsVRegister()) {
      number_of_valid_fpregs++;
      unique_fpregs |= (uint64_t{1} << regs[i].code());
    } else {
      DCHECK(!regs[i].is_valid());
    }
  }

  int number_of_unique_regs =
      CountSetBits(unique_regs, sizeof(unique_regs) * kBitsPerByte);
  int number_of_unique_fpregs =
      CountSetBits(unique_fpregs, sizeof(unique_fpregs) * kBitsPerByte);

  DCHECK(number_of_valid_regs >= number_of_unique_regs);
  DCHECK(number_of_valid_fpregs >= number_of_unique_fpregs);

  return (number_of_valid_regs != number_of_unique_regs) ||
         (number_of_valid_fpregs != number_of_unique_fpregs);
}

bool AreSameSizeAndType(const CPURegister& reg1, const CPURegister& reg2,
                        const CPURegister& reg3, const CPURegister& reg4,
                        const CPURegister& reg5, const CPURegister& reg6,
                        const CPURegister& reg7, const CPURegister& reg8) {
  DCHECK(reg1.is_valid());
  bool match = true;
  match &= !reg2.is_valid() || reg2.IsSameSizeAndType(reg1);
  match &= !reg3.is_valid() || reg3.IsSameSizeAndType(reg1);
  match &= !reg4.is_valid() || reg4.IsSameSizeAndType(reg1);
  match &= !reg5.is_valid() || reg5.IsSameSizeAndType(reg1);
  match &= !reg6.is_valid() || reg6.IsSameSizeAndType(reg1);
  match &= !reg7.is_valid() || reg7.IsSameSizeAndType(reg1);
  match &= !reg8.is_valid() || reg8.IsSameSizeAndType(reg1);
  return match;
}

bool AreSameFormat(const Register& reg1, const Register& reg2,
                   const Register& reg3, const Register& reg4) {
  DCHECK(reg1.is_valid());
  return (!reg2.is_valid() || reg2.IsSameSizeAndType(reg1)) &&
         (!reg3.is_valid() || reg3.IsSameSizeAndType(reg1)) &&
         (!reg4.is_valid() || reg4.IsSameSizeAndType(reg1));
}

bool AreSameFormat(const VRegister& reg1, const VRegister& reg2,
                   const VRegister& reg3, const VRegister& reg4) {
  DCHECK(reg1.is_valid());
  return (!reg2.is_valid() || reg2.IsSameFormat(reg1)) &&
         (!reg3.is_valid() || reg3.IsSameFormat(reg1)) &&
         (!reg4.is_valid() || reg4.IsSameFormat(reg1));
}

bool AreConsecutive(const CPURegister& reg1, const CPURegister& reg2,
                    const CPURegister& reg3, const CPURegister& reg4) {
  DCHECK(reg1.is_valid());

  if (!reg2.is_valid()) {
    DCHECK(!reg3.is_valid() && !reg4.is_valid());
    return true;
  } else if (reg2.code() != ((reg1.code() + 1) % (reg1.MaxCode() + 1))) {
    return false;
  }

  if (!reg3.is_valid()) {
    DCHECK(!reg4.is_valid());
    return true;
  } else if (reg3.code() != ((reg2.code() + 1) % (reg1.MaxCode() + 1))) {
    return false;
  }

  if (!reg4.is_valid()) {
    return true;
  } else if (reg4.code() != ((reg3.code() + 1) % (reg1.MaxCode() + 1))) {
    return false;
  }

  return true;
}

bool AreEven(const CPURegister& reg1, const CPURegister& reg2,
             const CPURegister& reg3, const CPURegister& reg4,
             const CPURegister& reg5, const CPURegister& reg6,
             const CPURegister& reg7, const CPURegister& reg8) {
  DCHECK(reg1.is_valid());
  bool even = reg1.IsEven();
  even &= !reg2.is_valid() || reg2.IsEven();
  even &= !reg3.is_valid() || reg3.IsEven();
  even &= !reg4.is_valid() || reg4.IsEven();
  even &= !reg5.is_valid() || reg5.IsEven();
  even &= !reg6.is_valid() || reg6.IsEven();
  even &= !reg7.is_valid() || reg7.IsEven();
  even &= !reg8.is_valid() || reg8.IsEven();
  return even;
}

bool Operand::NeedsRelocation(const Assembler* assembler) const {
  RelocInfo::Mode rmode = immediate_.rmode();

  if (RelocInfo::IsOnlyForSerializer(rmode)) {
    return assembler->options().record_reloc_info_for_serialization;
  }

  return !RelocInfo::IsNoInfo(rmode);
}

// Assembler
Assembler::Assembler(const MaybeAssemblerZone& zone,
                     const AssemblerOptions& options,
                     std::unique_ptr<AssemblerBuffer> buffer)
    : AssemblerBase(options, std::move(buffer)),
      zone_(zone),
      unresolved_branches_(zone_.get()),
      constpool_(this) {
  Reset();

#if defined(V8_OS_WIN)
  if (options.collect_win64_unwind_info) {
    xdata_encoder_ = std::make_unique<win64_unwindinfo::XdataEncoder>(*this);
  }
#endif
}

Assembler::~Assembler() {
  DCHECK(constpool_.IsEmpty());
  DCHECK_EQ(veneer_pool_blocked_nesting_, 0);
}

void Assembler::AbortedCodeGeneration() { constpool_.Clear(); }

void Assembler::Reset() {
#ifdef DEBUG
  DCHECK((pc_ >= buffer_start_) && (pc_ < buffer_start_ + buffer_->size()));
  DCHECK_EQ(veneer_pool_blocked_nesting_, 0);
  DCHECK(unresolved_branches_.empty());
  memset(buffer_start_, 0, pc_ - buffer_start_);
#endif
  pc_ = buffer_start_;
  reloc_info_writer.Reposition(buffer_start_ + buffer_->size(), pc_);
  constpool_.Clear();
  constpool_.SetNextCheckIn(ConstantPool::kCheckInterval);
  next_veneer_pool_check_ = kMaxInt;
}

#if defined(V8_OS_WIN)
win64_unwindinfo::BuiltinUnwindInfo Assembler::GetUnwindInfo() const {
  DCHECK(options().collect_win64_unwind_info);
  DCHECK_NOT_NULL(xdata_encoder_);
  return xdata_encoder_->unwinding_info();
}
#endif

void Assembler::AllocateAndInstallRequestedHeapNumbers(LocalIsolate* isolate) {
  DCHECK_IMPLIES(isolate == nullptr, heap_number_requests_.empty());
  for (auto& request : heap_number_requests_) {
    Address pc = reinterpret_cast<Address>(buffer_start_) + request.offset();
    Handle<HeapObject> object =
        isolate->factory()->NewHeapNumber<AllocationType::kOld>(
            request.heap_number());
    EmbeddedObjectIndex index = AddEmbeddedObject(object);
    set_embedded_object_index_referenced_from(pc, index);
  }
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

  // Emit constant pool if necessary.
  ForceConstantPoolEmissionWithoutJump();
  DCHECK(constpool_.IsEmpty());

  int code_comments_size = WriteCodeComments();

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
  // If not, the loop below won't terminate.
  DCHECK(IsAligned(pc_offset(), kInstrSize));
  DCHECK(m >= kInstrSize && base::bits::IsPowerOfTwo(m));
  while ((pc_offset() & (m - 1)) != 0) {
    nop();
  }
}

void Assembler::CodeTargetAlign() {
  // Preferred alignment of jump targets on some ARM chips.
#if !defined(V8_TARGET_OS_MACOS)
  Align(8);
#endif
}

void Assembler::CheckLabelLinkChain(Label const* label) {
#ifdef DEBUG
  if (label->is_linked()) {
    static const int kMaxLinksToCheck = 64;  // Avoid O(n2) behaviour.
    int links_checked = 0;
    int64_t linkoffset = label->pos();
    bool end_of_chain = false;
    while (!end_of_chain) {
      if (++links_checked > kMaxLinksToCheck) break;
      Instruction* link = InstructionAt(linkoffset);
      int64_t linkpcoffset = link->ImmPCOffset();
      int64_t prevlinkoffset = linkoffset + linkpcoffset;

      end_of_chain = (linkoffset == prevlinkoffset);
      linkoffset = linkoffset + linkpcoffset;
    }
  }
#endif
}

void Assembler::RemoveBranchFromLabelLinkChain(Instruction* branch,
                                               Label* label,
                                               Instruction* label_veneer) {
  DCHECK(label->is_linked());

  CheckLabelLinkChain(label);

  Instruction* link = InstructionAt(label->pos());
  Instruction* prev_link = link;
  Instruction* next_link;

  if (link != branch) {
    int i = static_cast<int>(InstructionOffset(branch));
    // Currently, we don't support adr instructions sharing labels with
    // branches in the link chain.
    DCHECK(branch_link_chain_back_edge_.contains(i));
    prev_link = InstructionAt(branch_link_chain_back_edge_.at(i));
    link = branch;
  }

  DCHECK(branch == link);
  next_link = branch->ImmPCOffsetTarget();

  if (branch == prev_link) {
    // The branch is the first instruction in the chain.
    if (branch == next_link) {
      // It is also the last instruction in the chain, so it is the only branch
      // currently referring to this label.
      //
      // Label -> this branch -> start
      label->Unuse();
    } else {
      // Label -> this branch -> 1+ branches -> start
      label->link_to(static_cast<int>(InstructionOffset(next_link)));
      branch_link_chain_back_edge_.erase(
          static_cast<int>(InstructionOffset(next_link)));
    }
  } else if (branch == next_link) {
    // The branch is the last (but not also the first) instruction in the chain.
    //
    // Label -> 1+ branches -> this branch -> start
    prev_link->SetImmPCOffsetTarget(zone(), options(), prev_link);
    branch_link_chain_back_edge_.erase(
        static_cast<int>(InstructionOffset(branch)));
  } else {
    // The branch is in the middle of the chain.
    //
    // Label -> 1+ branches -> this branch -> 1+ branches -> start
    int n = static_cast<int>(InstructionOffset(next_link));
    if (branch_link_chain_back_edge_.contains(n)) {
      // Update back edge such that the branch after this branch points to the
      // branch before it.
      branch_link_chain_back_edge_[n] =
          static_cast<int>(InstructionOffset(prev_link));
      branch_link_chain_back_edge_.erase(
          static_cast<int>(InstructionOffset(branch)));
    }

    if (prev_link->IsTargetInImmPCOffsetRange(next_link)) {
      prev_link->SetImmPCOffsetTarget(zone(), options(), next_link);
    } else if (label_veneer != nullptr) {
      // Use the veneer for all previous links in the chain.
      prev_link->SetImmPCOffsetTarget(zone(), options(), prev_link);

      bool end_of_chain = false;
      link = next_link;
      while (!end_of_chain) {
        next_link = link->ImmPCOffsetTarget();
        end_of_chain = (link == next_link);
        link->SetImmPCOffsetTarget(zone(), options(), label_veneer);
        // {link} is now resolved; remove it from {unresolved_branches_} so
        // we won't later try to process it again, which would fail because
        // by walking the chain of its label's unresolved branch instructions,
        // we won't find it: {prev_link} is now the end of that chain after
        // its update above.
        if (link->IsCondBranchImm() || link->IsCompareBranch()) {
          static_assert(Instruction::ImmBranchRange(CondBranchType) ==
                        Instruction::ImmBranchRange(CompareBranchType));
          int max_reachable_pc = static_cast<int>(InstructionOffset(link)) +
                                 Instruction::ImmBranchRange(CondBranchType);
          unresolved_branches_.erase(max_reachable_pc);
        } else if (link->IsTestBranch()) {
          // Add 1 to account for branch type tag bit.
          int max_reachable_pc = static_cast<int>(InstructionOffset(link)) +
                                 Instruction::ImmBranchRange(TestBranchType) +
                                 1;
          unresolved_branches_.erase(max_reachable_pc);
        } else {
          // Other branch types are not handled by veneers.
        }
        link = next_link;
      }
    } else {
      // The assert below will fire.
      // Some other work could be attempted to fix up the chain, but it would be
      // rather complicated. If we crash here, we may want to consider using an
      // other mechanism than a chain of branches.
      //
      // Note that this situation currently should not happen, as we always call
      // this function with a veneer to the target label.
      // However this could happen with a MacroAssembler in the following state:
      //    [previous code]
      //    B(label);
      //    [20KB code]
      //    Tbz(label);   // First tbz. Pointing to unconditional branch.
      //    [20KB code]
      //    Tbz(label);   // Second tbz. Pointing to the first tbz.
      //    [more code]
      // and this function is called to remove the first tbz from the label link
      // chain. Since tbz has a range of +-32KB, the second tbz cannot point to
      // the unconditional branch.
      CHECK(prev_link->IsTargetInImmPCOffsetRange(next_link));
      UNREACHABLE();
    }
  }

  CheckLabelLinkChain(label);
}

void Assembler::bind(Label* label) {
  // Bind label to the address at pc_. All instructions (most likely branches)
  // that are linked to this label will be updated to point to the newly-bound
  // label.

  DCHECK(!label->is_near_linked());
  DCHECK(!label->is_bound());

  DeleteUnresolvedBranchInfoForLabel(label);

  // If the label is linked, the link chain looks something like this:
  //
  // |--I----I-------I-------L
  // |---------------------->| pc_offset
  // |-------------->|         linkoffset = label->pos()
  //         |<------|         link->ImmPCOffset()
  // |------>|                 prevlinkoffset = linkoffset + link->ImmPCOffset()
  //
  // On each iteration, the last link is updated and then removed from the
  // chain until only one remains. At that point, the label is bound.
  //
  // If the label is not linked, no preparation is required before binding.
  while (label->is_linked()) {
    int linkoffset = label->pos();
    Instruction* link = InstructionAt(linkoffset);
    int prevlinkoffset = linkoffset + static_cast<int>(link->ImmPCOffset());

    CheckLabelLinkChain(label);

    DCHECK_GE(linkoffset, 0);
    DCHECK(linkoffset < pc_offset());
    DCHECK((linkoffset > prevlinkoffset) ||
           (linkoffset - prevlinkoffset == kStartOfLabelLinkChain));
    DCHECK_GE(prevlinkoffset, 0);

    // Update the link to point to the label.
    if (link->IsUnresolvedInternalReference()) {
      // Internal references do not get patched to an instruction but directly
      // to an address.
      internal_reference_positions_.push_back(linkoffset);
      memcpy(link, &pc_, kSystemPointerSize);
    } else {
      link->SetImmPCOffsetTarget(zone(), options(),
                                 reinterpret_cast<Instruction*>(pc_));

      // Discard back edge data for this link.
      branch_link_chain_back_edge_.erase(
          static_cast<int>(InstructionOffset(link)));
    }

    // Link the label to the previous link in the chain.
    if (linkoffset - prevlinkoffset == kStartOfLabelLinkChain) {
      // We hit kStartOfLabelLinkChain, so the chain is fully processed.
      label->Unuse();
    } else {
      // Update the label for the next iteration.
      label->link_to(prevlinkoffset);
    }
  }
  label->bind_to(pc_offset());

  DCHECK(label->is_bound());
  DCHECK(!label->is_linked());
}

int Assembler::LinkAndGetByteOffsetTo(Label* label) {
  DCHECK_EQ(sizeof(*pc_), 1);
  CheckLabelLinkChain(label);

  int offset;
  if (label->is_bound()) {
    // The label is bound, so it does not need to be updated. Referring
    // instructions must link directly to the label as they will not be
    // updated.
    //
    // In this case, label->pos() returns the offset of the label from the
    // start of the buffer.
    //
    // Note that offset can be zero for self-referential instructions. (This
    // could be useful for ADR, for example.)
    offset = label->pos() - pc_offset();
    DCHECK_LE(offset, 0);
  } else {
    if (label->is_linked()) {
      // The label is linked, so the referring instruction should be added onto
      // the end of the label's link chain.
      //
      // In this case, label->pos() returns the offset of the last linked
      // instruction from the start of the buffer.
      offset = label->pos() - pc_offset();
      DCHECK_NE(offset, kStartOfLabelLinkChain);
      // Note that the offset here needs to be PC-relative only so that the
      // first instruction in a buffer can link to an unbound label. Otherwise,
      // the offset would be 0 for this case, and 0 is reserved for
      // kStartOfLabelLinkChain.
    } else {
      // The label is unused, so it now becomes linked and the referring
      // instruction is at the start of the new link chain.
      offset = kStartOfLabelLinkChain;
    }
    // The instruction at pc is now the last link in the label's chain.
    label->link_to(pc_offset());
  }

  return offset;
}

void Assembler::DeleteUnresolvedBranchInfoForLabelTraverse(Label* label) {
  DCHECK(label->is_linked());
  CheckLabelLinkChain(label);

  int link_offset = label->pos();
  int link_pcoffset;
  bool end_of_chain = false;

  while (!end_of_chain) {
    Instruction* link = InstructionAt(link_offset);
    int max_reachable_pc = static_cast<int>(InstructionOffset(link));

    // ADR instructions and unconditional branches are not handled by veneers.
    if (link->IsCondBranchImm() || link->IsCompareBranch()) {
      static_assert(Instruction::ImmBranchRange(CondBranchType) ==
                    Instruction::ImmBranchRange(CompareBranchType));
      max_reachable_pc += Instruction::ImmBranchRange(CondBranchType);
      unresolved_branches_.erase(max_reachable_pc);
      link_pcoffset = link->ImmCondBranch() * kInstrSize;
    } else if (link->IsTestBranch()) {
      // Add one to account for branch type tag bit.
      max_reachable_pc += Instruction::ImmBranchRange(TestBranchType) + 1;
      unresolved_branches_.erase(max_reachable_pc);
      link_pcoffset = link->ImmTestBranch() * kInstrSize;
    } else if (link->IsUncondBranchImm()) {
      link_pcoffset = link->ImmUncondBranch() * kInstrSize;
    } else {
      link_pcoffset = static_cast<int>(link->ImmPCOffset());
    }

    end_of_chain = (link_pcoffset == 0);
    link_offset = link_offset + link_pcoffset;
  }
}

void Assembler::DeleteUnresolvedBranchInfoForLabel(Label* label) {
  if (unresolved_branches_.empty()) {
    DCHECK_EQ(next_veneer_pool_check_, kMaxInt);
    return;
  }

  if (label->is_linked()) {
    // Branches to this label will be resolved when the label is bound, normally
    // just after all the associated info has been deleted.
    DeleteUnresolvedBranchInfoForLabelTraverse(label);
  }
  if (unresolved_branches_.empty()) {
    next_veneer_pool_check_ = kMaxInt;
  } else {
    next_veneer_pool_check_ =
        unresolved_branches_first_limit() - kVeneerDistanceCheckMargin;
  }
}

bool Assembler::IsConstantPoolAt(Instruction* instr) {
  // The constant pool marker is made of two instructions. These instructions
  // will never be emitted by the JIT, so checking for the first one is enough:
  // 0: ldr xzr, #<size of pool>
  bool result = instr->IsLdrLiteralX() && (instr->Rt() == kZeroRegCode);

  // It is still worth asserting the marker is complete.
  // 4: blr xzr
  DCHECK(!result || (instr->following()->IsBranchAndLinkToRegister() &&
                     instr->following()->Rn() == kZeroRegCode));

  return result;
}

int Assembler::ConstantPoolSizeAt(Instruction* instr) {
#ifdef USE_SIMULATOR
  // Assembler::debug() embeds constants directly into the instruction stream.
  // Although this is not a genuine constant pool, treat it like one to avoid
  // disassembling the constants.
  if ((instr->Mask(ExceptionMask) == HLT) &&
      (instr->ImmException() == kImmExceptionIsDebug)) {
    const char* message = reinterpret_cast<const char*>(
        instr->InstructionAtOffset(kDebugMessageOffset));
    int size = static_cast<int>(kDebugMessageOffset + strlen(message) + 1);
    return RoundUp(size, kInstrSize) / kInstrSize;
  }
  // Same for printf support, see MacroAssembler::CallPrintf().
  if ((instr->Mask(ExceptionMask) == HLT) &&
      (instr->ImmException() == kImmExceptionIsPrintf)) {
    return kPrintfLength / kInstrSize;
  }
#endif
  if (IsConstantPoolAt(instr)) {
    return instr->ImmLLiteral();
  } else {
    return -1;
  }
}

void Assembler::EmitPoolGuard() {
  // We must generate only one instruction as this is used in scopes that
  // control the size of the code generated.
  Emit(BLR | Rn(xzr));
}

void Assembler::StartBlockVeneerPool() { ++veneer_pool_blocked_nesting_; }

void Assembler::EndBlockVeneerPool() {
  if (--veneer_pool_blocked_nesting_ == 0) {
    // Check the veneer pool hasn't been blocked for too long.
    DCHECK(unresolved_branches_.empty() ||
           (pc_offset() < unresolved_branches_first_limit()));
  }
}

void Assembler::br(const Register& xn) {
  DCHECK(xn.Is64Bits());
  Emit(BR | Rn(xn));
}

void Assembler::blr(const Register& xn) {
  DCHECK(xn.Is64Bits());
  // The pattern 'blr xzr' is used as a guard to detect when execution falls
  // through the constant pool. It should not be emitted.
  DCHECK_NE(xn, xzr);
  Emit(BLR | Rn(xn));
}

void Assembler::ret(const Register& xn) {
  DCHECK(xn.Is64Bits());
  Emit(RET | Rn(xn));
}

void Assembler::b(int imm26) { Emit(B | ImmUncondBranch(imm26)); }

void Assembler::b(Label* label) {
  b(LinkAndGetBranchInstructionOffsetTo(label));
}

void Assembler::b(int imm19, Condition cond) {
  Emit(B_cond | ImmCondBranch(imm19) | cond);
}

void Assembler::b(Label* label, Condition cond) {
  b(LinkAndGetBranchInstructionOffsetTo(label), cond);
}

void Assembler::bl(int imm26) { Emit(BL | ImmUncondBranch(imm26)); }

void Assembler::bl(Label* label) {
  bl(LinkAndGetBranchInstructionOffsetTo(label));
}

void Assembler::cbz(const Register& rt, int imm19) {
  Emit(SF(rt) | CBZ | ImmCmpBranch(imm19) | Rt(rt));
}

void Assembler::cbz(const Register& rt, Label* label) {
  cbz(rt, LinkAndGetBranchInstructionOffsetTo(label));
}

void Assembler::cbnz(const Register& rt, int imm19) {
  Emit(SF(rt) | CBNZ | ImmCmpBranch(imm19) | Rt(rt));
}

void Assembler::cbnz(const Register& rt, Label* label) {
  cbnz(rt, LinkAndGetBranchInstructionOffsetTo(label));
}

void Assembler::tbz(const Register& rt, unsigned bit_pos, int imm14) {
  DCHECK(rt.Is64Bits() || (rt.Is32Bits() && (bit_pos < kWRegSizeInBits)));
  Emit(TBZ | ImmTestBranchBit(bit_pos) | ImmTestBranch(imm14) | Rt(rt));
}

void Assembler::tbz(const Register& rt, unsigned bit_pos, Label* label) {
  tbz(rt, bit_pos, LinkAndGetBranchInstructionOffsetTo(label));
}

void Assembler::tbnz(const Register& rt, unsigned bit_pos, int imm14) {
  DCHECK(rt.Is64Bits() || (rt.Is32Bits() && (bit_pos < kWRegSizeInBits)));
  Emit(TBNZ | ImmTestBranchBit(bit_pos) | ImmTestBranch(imm14) | Rt(rt));
}

void Assembler::tbnz(const Register& rt, unsigned bit_pos, Label* label) {
  tbnz(rt, bit_pos, LinkAndGetBranchInstructionOffsetTo(label));
}

void Assembler::adr(const Register& rd, int imm21) {
  DCHECK(rd.Is64Bits());
  Emit(ADR | ImmPCRelAddress(imm21) | Rd(rd));
}

void Assembler::adr(const Register& rd, Label* label) {
  adr(rd, LinkAndGetByteOffsetTo(label));
}

void Assembler::nop(NopMarkerTypes n) {
  DCHECK((FIRST_NOP_MARKER <= n) && (n <= LAST_NOP_MARKER));
  mov(Register::XRegFromCode(n), Register::XRegFromCode(n));
}

void Assembler::add(const Register& rd, const Register& rn,
                    const Operand& operand) {
  AddSub(rd, rn, operand, LeaveFlags, ADD);
}

void Assembler::adds(const Register& rd, const Register& rn,
                     const Operand& operand) {
  AddSub(rd, rn, operand, SetFlags, ADD);
}

void Assembler::cmn(const Register& rn, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rn);
  adds(zr, rn, operand);
}

void Assembler::sub(const Register& rd, const Register& rn,
                    const Operand& operand) {
  AddSub(rd, rn, operand, LeaveFlags, SUB);
}

void Assembler::subs(const Register& rd, const Register& rn,
                     const Operand& operand) {
  AddSub(rd, rn, operand, SetFlags, SUB);
}

void Assembler::cmp(const Register& rn, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rn);
  subs(zr, rn, operand);
}

void Assembler::neg(const Register& rd, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rd);
  sub(rd, zr, operand);
}

void Assembler::negs(const Register& rd, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rd);
  subs(rd, zr, operand);
}

void Assembler::adc(const Register& rd, const Register& rn,
                    const Operand& operand) {
  AddSubWithCarry(rd, rn, operand, LeaveFlags, ADC);
}

void Assembler::adcs(const Register& rd, const Register& rn,
                     const Operand& operand) {
  AddSubWithCarry(rd, rn, operand, SetFlags, ADC);
}

void Assembler::sbc(const Register& rd, const Register& rn,
                    const Operand& operand) {
  AddSubWithCarry(rd, rn, operand, LeaveFlags, SBC);
}

void Assembler::sbcs(const Register& rd, const Register& rn,
                     const Operand& operand) {
  AddSubWithCarry(rd, rn, operand, SetFlags, SBC);
}

void Assembler::ngc(const Register& rd, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rd);
  sbc(rd, zr, operand);
}

void Assembler::ngcs(const Register& rd, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rd);
  sbcs(rd, zr, operand);
}

// Logical instructions.
void Assembler::and_(const Register& rd, const Register& rn,
                     const Operand& operand) {
  Logical(rd, rn, operand, AND);
}

void Assembler::ands(const Register& rd, const Register& rn,
                     const Operand& operand) {
  Logical(rd, rn, operand, ANDS);
}

void Assembler::tst(const Register& rn, const Operand& operand) {
  ands(AppropriateZeroRegFor(rn), rn, operand);
}

void Assembler::bic(const Register& rd, const Register& rn,
                    const Operand& operand) {
  Logical(rd, rn, operand, BIC);
}

void Assembler::bics(const Register& rd, const Register& rn,
                     const Operand& operand) {
  Logical(rd, rn, operand, BICS);
}

void Assembler::orr(const Register& rd, const Register& rn,
                    const Operand& operand) {
  Logical(rd, rn, operand, ORR);
}

void Assembler::orn(const Register& rd, const Register& rn,
                    const Operand& operand) {
  Logical(rd, rn, operand, ORN);
}

void Assembler::eor(const Register& rd, const Register& rn,
                    const Operand& operand) {
  Logical(rd, rn, operand, EOR);
}

void Assembler::eon(const Register& rd, const Register& rn,
                    const Operand& operand) {
  Logical(rd, rn, operand, EON);
}

void Assembler::lslv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | LSLV | Rm(rm) | Rn(rn) | Rd(rd));
}

void Assembler::lsrv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | LSRV | Rm(rm) | Rn(rn) | Rd(rd));
}

void Assembler::asrv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | ASRV | Rm(rm) | Rn(rn) | Rd(rd));
}

void Assembler::rorv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | RORV | Rm(rm) | Rn(rn) | Rd(rd));
}

// Bitfield operations.
void Assembler::bfm(const Register& rd, const Register& rn, int immr,
                    int imms) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  Instr N = SF(rd) >> (kSFOffset - kBitfieldNOffset);
  Emit(SF(rd) | BFM | N | ImmR(immr, rd.SizeInBits()) |
       ImmS(imms, rn.SizeInBits()) | Rn(rn) | Rd(rd));
}

void Assembler::sbfm(const Register& rd, const Register& rn, int immr,
                     int imms) {
  DCHECK(rd.Is64Bits() || rn.Is32Bits());
  Instr N = SF(rd) >> (kSFOffset - kBitfieldNOffset);
  Emit(SF(rd) | SBFM | N | ImmR(immr, rd.SizeInBits()) |
       ImmS(imms, rn.SizeInBits()) | Rn(rn) | Rd(rd));
}

void Assembler::ubfm(const Register& rd, const Register& rn, int immr,
                     int imms) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  Instr N = SF(rd) >> (kSFOffset - kBitfieldNOffset);
  Emit(SF(rd) | UBFM | N | ImmR(immr, rd.SizeInBits()) |
       ImmS(imms, rn.SizeInBits()) | Rn(rn) | Rd(rd));
}

void Assembler::extr(const Register& rd, const Register& rn, const Register& rm,
                     int lsb) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Instr N = SF(rd) >> (kSFOffset - kBitfieldNOffset);
  Emit(SF(rd) | EXTR | N | Rm(rm) | ImmS(lsb, rn.SizeInBits()) | Rn(rn) |
       Rd(rd));
}

void Assembler::csel(const Register& rd, const Register& rn, const Register& rm,
                     Condition cond) {
  ConditionalSelect(rd, rn, rm, cond, CSEL);
}

void Assembler::csinc(const Register& rd, const Register& rn,
                      const Register& rm, Condition cond) {
  ConditionalSelect(rd, rn, rm, cond, CSINC);
}

void Assembler::csinv(const Register& rd, const Register& rn,
                      const Register& rm, Condition cond) {
  ConditionalSelect(rd, rn, rm, cond, CSINV);
}

void Assembler::csneg(const Register& rd, const Register& rn,
                      const Register& rm, Condition cond) {
  ConditionalSelect(rd, rn, rm, cond, CSNEG);
}

void Assembler::cset(const Register& rd, Condition cond) {
  DCHECK((cond != al) && (cond != nv));
  Register zr = AppropriateZeroRegFor(rd);
  csinc(rd, zr, zr, NegateCondition(cond));
}

void Assembler::csetm(const Register& rd, Condition cond) {
  DCHECK((cond != al) && (cond != nv));
  Register zr = AppropriateZeroRegFor(rd);
  csinv(rd, zr, zr, NegateCondition(cond));
}

void Assembler::cinc(const Register& rd, const Register& rn, Condition cond) {
  DCHECK((cond != al) && (cond != nv));
  csinc(rd, rn, rn, NegateCondition(cond));
}

void Assembler::cinv(const Register& rd, const Register& rn, Condition cond) {
  DCHECK((cond != al) && (cond != nv));
  csinv(rd, rn, rn, NegateCondition(cond));
}

void Assembler::cneg(const Register& rd, const Register& rn, Condition cond) {
  DCHECK((cond != al) && (cond != nv));
  csneg(rd, rn, rn, NegateCondition(cond));
}

void Assembler::ConditionalSelect(const Register& rd, const Register& rn,
                                  const Register& rm, Condition cond,
                                  ConditionalSelectOp op) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | op | Rm(rm) | Cond(cond) | Rn(rn) | Rd(rd));
}

void Assembler::ccmn(const Register& rn, const Operand& operand,
                     StatusFlags nzcv, Condition cond) {
  ConditionalCompare(rn, operand, nzcv, cond, CCMN);
}

void Assembler::ccmp(const Register& rn, const Operand& operand,
                     StatusFlags nzcv, Condition cond) {
  ConditionalCompare(rn, operand, nzcv, cond, CCMP);
}

void Assembler::DataProcessing3Source(const Register& rd, const Register& rn,
                                      const Register& rm, const Register& ra,
                                      DataProcessing3SourceOp op) {
  Emit(SF(rd) | op | Rm(rm) | Ra(ra) | Rn(rn) | Rd(rd));
}

void Assembler::mul(const Register& rd, const Register& rn,
                    const Register& rm) {
  DCHECK(AreSameSizeAndType(rd, rn, rm));
  Register zr = AppropriateZeroRegFor(rn);
  DataProcessing3Source(rd, rn, rm, zr, MADD);
}

void Assembler::madd(const Register& rd, const Register& rn, const Register& rm,
                     const Register& ra) {
  DCHECK(AreSameSizeAndType(rd, rn, rm, ra));
  DataProcessing3Source(rd, rn, rm, ra, MADD);
}

void Assembler::mneg(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(AreSameSizeAndType(rd, rn, rm));
  Register zr = AppropriateZeroRegFor(rn);
  DataProcessing3Source(rd, rn, rm, zr, MSUB);
}

void Assembler::msub(const Register& rd, const Register& rn, const Register& rm,
                     const Register& ra) {
  DCHECK(AreSameSizeAndType(rd, rn, rm, ra));
  DataProcessing3Source(rd, rn, rm, ra, MSUB);
}

void Assembler::smaddl(const Register& rd, const Register& rn,
                       const Register& rm, const Register& ra) {
  DCHECK(rd.Is64Bits() && ra.Is64Bits());
  DCHECK(rn.Is32Bits() && rm.Is32Bits());
  DataProcessing3Source(rd, rn, rm, ra, SMADDL_x);
}

void Assembler::smsubl(const Register& rd, const Register& rn,
                       const Register& rm, const Register& ra) {
  DCHECK(rd.Is64Bits() && ra.Is64Bits());
  DCHECK(rn.Is32Bits() && rm.Is32Bits());
  DataProcessing3Source(rd, rn, rm, ra, SMSUBL_x);
}

void Assembler::umaddl(const Register& rd, const Register& rn,
                       const Register& rm, const Register& ra) {
  DCHECK(rd.Is64Bits() && ra.Is64Bits());
  DCHECK(rn.Is32Bits() && rm.Is32Bits());
  DataProcessing3Source(rd, rn, rm, ra, UMADDL_x);
}

void Assembler::umsubl(const Register& rd, const Register& rn,
                       const Register& rm, const Register& ra) {
  DCHECK(rd.Is64Bits() && ra.Is64Bits());
  DCHECK(rn.Is32Bits() && rm.Is32Bits());
  DataProcessing3Source(rd, rn, rm, ra, UMSUBL_x);
}

void Assembler::smull(const Register& rd, const Register& rn,
                      const Register& rm) {
  DCHECK(rd.Is64Bits());
  DCHECK(rn.Is32Bits() && rm.Is32Bits());
  DataProcessing3Source(rd, rn, rm, xzr, SMADDL_x);
}

void Assembler::smulh(const Register& rd, const Register& rn,
                      const Register& rm) {
  DCHECK(rd.Is64Bits());
  DCHECK(rn.Is64Bits());
  DCHECK(rm.Is64Bits());
  DataProcessing3Source(rd, rn, rm, xzr, SMULH_x);
}

void Assembler::umulh(const Register& rd, const Register& rn,
                      const Register& rm) {
  DCHECK(rd.Is64Bits());
  DCHECK(rn.Is64Bits());
  DCHECK(rm.Is64Bits());
  DataProcessing3Source(rd, rn, rm, xzr, UMULH_x);
}

void Assembler::sdiv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | SDIV | Rm(rm) | Rn(rn) | Rd(rd));
}

void Assembler::udiv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | UDIV | Rm(rm) | Rn(rn) | Rd(rd));
}

void Assembler::rbit(const Register& rd, const Register& rn) {
  DataProcessing1Source(rd, rn, RBIT);
}

void Assembler::rev16(const Register& rd, const Register& rn) {
  DataProcessing1Source(rd, rn, REV16);
}

void Assembler::rev32(const Register& rd, const Register& rn) {
  DCHECK(rd.Is64Bits());
  DataProcessing1Source(rd, rn, REV);
}

void Assembler::rev(const Register& rd, const Register& rn) {
  DataProcessing1Source(rd, rn, rd.Is64Bits() ? REV_x : REV_w);
}

void Assembler::clz(const Register& rd, const Register& rn) {
  DataProcessing1Source(rd, rn, CLZ);
}

void Assembler::cls(const Register& rd, const Register& rn) {
  DataProcessing1Source(rd, rn, CLS);
}

void Assembler::pacib1716() { Emit(PACIB1716); }
void Assembler::autib1716() { Emit(AUTIB1716); }
void Assembler::pacibsp() { Emit(PACIBSP); }
void Assembler::autibsp() { Emit(AUTIBSP); }

void Assembler::bti(BranchTargetIdentifier id) {
  SystemHint op;
  switch (id) {
    case BranchTargetIdentifier::kBti:
      op = BTI;
      break;
    case BranchTargetIdentifier::kBtiCall:
      op = BTI_c;
      break;
    case BranchTargetIdentifier::kBtiJump:
      op = BTI_j;
      break;
    case BranchTargetIdentifier::kBtiJumpCall:
      op = BTI_jc;
      break;
    case BranchTargetIdentifier::kNone:
    case BranchTargetIdentifier::kPacibsp:
      // We always want to generate a BTI instruction here, so disallow
      // skipping its generation or generating a PACIBSP instead.
      UNREACHABLE();
  }
  hint(op);
}

void Assembler::ldp(const CPURegister& rt, const CPURegister& rt2,
                    const MemOperand& src) {
  LoadStorePair(rt, rt2, src, LoadPairOpFor(rt, rt2));
}

void Assembler::stp(const CPURegister& rt, const CPURegister& rt2,
                    const MemOperand& dst) {
  LoadStorePair(rt, rt2, dst, StorePairOpFor(rt, rt2));

#if defined(V8_OS_WIN)
  if (xdata_encoder_ && rt == x29 && rt2 == lr && dst.base().IsSP()) {
    xdata_encoder_->onSaveFpLr();
  }
#endif
}

void Assembler::ldpsw(const Register& rt, const Register& rt2,
                      const MemOperand& src) {
  DCHECK(rt.Is64Bits());
  LoadStorePair(rt, rt2, src, LDPSW_x);
}

void Assembler::LoadStorePair(const CPURegister& rt, const CPURegister& rt2,
                              const MemOperand& addr, LoadStorePairOp op) {
  // 'rt' and 'rt2' can only be aliased for stores.
  DCHECK(((op & LoadStorePairLBit) == 0) || rt != rt2);
  DCHECK(AreSameSizeAndType(rt, rt2));
  DCHECK(IsImmLSPair(addr.offset(), CalcLSPairDataSize(op)));
  int offset = static_cast<int>(addr.offset());

  Instr memop = op | Rt(rt) | Rt2(rt2) | RnSP(addr.base()) |
                ImmLSPair(offset, CalcLSPairDataSize(op));

  Instr addrmodeop;
  if (addr.IsImmediateOffset()) {
    addrmodeop = LoadStorePairOffsetFixed;
  } else {
    // Pre-index and post-index modes.
    DCHECK_NE(rt, addr.base());
    DCHECK_NE(rt2, addr.base());
    DCHECK_NE(addr.offset(), 0);
    if (addr.IsPreIndex()) {
      addrmodeop = LoadStorePairPreIndexFixed;
    } else {
      DCHECK(addr.IsPostIndex());
      addrmodeop = LoadStorePairPostIndexFixed;
    }
  }
  Emit(addrmodeop | memop);
}

// Memory instructions.
void Assembler::ldrb(const Register& rt, const MemOperand& src) {
  LoadStore(rt, src, LDRB_w);
}

void Assembler::strb(const Register& rt, const MemOperand& dst) {
  LoadStore(rt, dst, STRB_w);
}

void Assembler::ldrsb(const Register& rt, const MemOperand& src) {
  LoadStore(rt, src, rt.Is64Bits() ? LDRSB_x : LDRSB_w);
}

void Assembler::ldrh(const Register& rt, const MemOperand& src) {
  LoadStore(rt, src, LDRH_w);
}

void Assembler::strh(const Register& rt, const MemOperand& dst) {
  LoadStore(rt, dst, STRH_w);
}

void Assembler::ldrsh(const Register& rt, const MemOperand& src) {
  LoadStore(rt, src, rt.Is64Bits() ? LDRSH_x : LDRSH_w);
}

void Assembler::ldr(const CPURegister& rt, const MemOperand& src) {
  LoadStore(rt, src, LoadOpFor(rt));
}

void Assembler::str(const CPURegister& rt, const MemOperand& src) {
  LoadStore(rt, src, StoreOpFor(rt));
}

void Assembler::ldrsw(const Register& rt, const MemOperand& src) {
  DCHECK(rt.Is64Bits());
  LoadStore(rt, src, LDRSW_x);
}

void Assembler::ldr_pcrel(const CPURegister& rt, int imm19) {
  // The pattern 'ldr xzr, #offset' is used to indicate the beginning of a
  // constant pool. It should not be emitted.
  DCHECK(!rt.IsZero());
  Emit(LoadLiteralOpFor(rt) | ImmLLiteral(imm19) | Rt(rt));
}

Operand Operand::EmbeddedNumber(double number) {
  int32_t smi;
  if (DoubleToSmiInteger(number, &smi)) {
    return Operand(Immediate(Smi::FromInt(smi)));
  }
  return EmbeddedHeapNumber(number);
}

Operand Operand::EmbeddedHeapNumber(double number) {
  Operand result(0, RelocInfo::FULL_EMBEDDED_OBJECT);
  result.heap_number_request_.emplace(number);
  DCHECK(result.IsHeapNumberRequest());
  return result;
}

void Assembler::ldr(const CPURegister& rt, const Operand& operand) {
  if (operand.IsHeapNumberRequest()) {
    BlockPoolsScope no_pool_before_ldr_of_heap_number_request(this);
    RequestHeapNumber(operand.heap_number_request());
    ldr(rt, operand.immediate_for_heap_number_request());
  } else {
    ldr(rt, operand.immediate());
  }
}

void Assembler::ldr(const CPURegister& rt, const Immediate& imm) {
  BlockPoolsScope no_pool_before_ldr_pcrel_instr(this);
  RecordRelocInfo(imm.rmode(), imm.value());
  // The load will be patched when the constpool is emitted, patching code
  // expect a load literal with offset 0.
  ldr_pcrel(rt, 0);
}

void Assembler::ldar(const Register& rt, const Register& rn) {
  DCHECK(rn.Is64Bits());
  LoadStoreAcquireReleaseOp op = rt.Is32Bits() ? LDAR_w : LDAR_x;
  Emit(op | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::ldaxr(const Register& rt, const Register& rn) {
  DCHECK(rn.Is64Bits());
  LoadStoreAcquireReleaseOp op = rt.Is32Bits() ? LDAXR_w : LDAXR_x;
  Emit(op | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlr(const Register& rt, const Register& rn) {
  DCHECK(rn.Is64Bits());
  LoadStoreAcquireReleaseOp op = rt.Is32Bits() ? STLR_w : STLR_x;
  Emit(op | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlxr(const Register& rs, const Register& rt,
                      const Register& rn) {
  DCHECK(rn.Is64Bits());
  DCHECK(rs != rt && rs != rn);
  LoadStoreAcquireReleaseOp op = rt.Is32Bits() ? STLXR_w : STLXR_x;
  Emit(op | Rs(rs) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::ldarb(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(LDAR_b | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::ldaxrb(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(LDAXR_b | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlrb(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(STLR_b | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlxrb(const Register& rs, const Register& rt,
                       const Register& rn) {
  DCHECK(rs.Is32Bits());
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  DCHECK(rs != rt && rs != rn);
  Emit(STLXR_b | Rs(rs) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::ldarh(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(LDAR_h | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::ldaxrh(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(LDAXR_h | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlrh(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(STLR_h | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlxrh(const Register& rs, const Register& rt,
                       const Register& rn) {
  DCHECK(rs.Is32Bits());
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  DCHECK(rs != rt && rs != rn);
  Emit(STLXR_h | Rs(rs) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

#define COMPARE_AND_SWAP_W_X_LIST(V) \
  V(cas, CAS)                        \
  V(casa, CASA)                      \
  V(casl, CASL)                      \
  V(casal, CASAL)

#define DEFINE_ASM_FUNC(FN, OP)                                     \
  void Assembler::FN(const Register& rs, const Register& rt,        \
                     const MemOperand& src) {                       \
    DCHECK(IsEnabled(LSE));                                         \
    DCHECK(src.IsImmediateOffset() && (src.offset() == 0));         \
    LoadStoreAcquireReleaseOp op = rt.Is64Bits() ? OP##_x : OP##_w; \
    Emit(op | Rs(rs) | Rt(rt) | Rt2_mask | RnSP(src.base()));       \
  }
COMPARE_AND_SWAP_W_X_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define COMPARE_AND_SWAP_W_LIST(V) \
  V(casb, CASB)                    \
  V(casab, CASAB)                  \
  V(caslb, CASLB)                  \
  V(casalb, CASALB)                \
  V(cash, CASH)                    \
  V(casah, CASAH)                  \
  V(caslh, CASLH)                  \
  V(casalh, CASALH)

#define DEFINE_ASM_FUNC(FN, OP)                               \
  void Assembler::FN(const Register& rs, const Register& rt,  \
                     const MemOperand& src) {                 \
    DCHECK(IsEnabled(LSE));                                   \
    DCHECK(src.IsImmediateOffset() && (src.offset() == 0));   \
    Emit(OP | Rs(rs) | Rt(rt) | Rt2_mask | RnSP(src.base())); \
  }
COMPARE_AND_SWAP_W_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define COMPARE_AND_SWAP_PAIR_LIST(V) \
  V(casp, CASP)                       \
  V(caspa, CASPA)                     \
  V(caspl, CASPL)                     \
  V(caspal, CASPAL)

#define DEFINE_ASM_FUNC(FN, OP)                                     \
  void Assembler::FN(const Register& rs, const Register& rs1,       \
                     const Register& rt, const Register& rt1,       \
                     const MemOperand& src) {                       \
    DCHECK(IsEnabled(LSE));                                         \
    DCHECK(src.IsImmediateOffset() && (src.offset() == 0));         \
    DCHECK(AreEven(rs, rt));                                        \
    DCHECK(AreConsecutive(rs, rs1));                                \
    DCHECK(AreConsecutive(rt, rt1));                                \
    DCHECK(AreSameFormat(rs, rs1, rt, rt1));                        \
    LoadStoreAcquireReleaseOp op = rt.Is64Bits() ? OP##_x : OP##_w; \
    Emit(op | Rs(rs) | Rt(rt) | Rt2_mask | RnSP(src.base()));       \
  }
COMPARE_AND_SWAP_PAIR_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

// These macros generate all the variations of the atomic memory operations,
// e.g. ldadd, ldadda, ldaddb, staddl, etc.
// For a full list of the methods with comments, see the assembler header file.

#define ATOMIC_MEMORY_SIMPLE_OPERATION_LIST(V, DEF) \
  V(DEF, add, LDADD)                                \
  V(DEF, clr, LDCLR)                                \
  V(DEF, eor, LDEOR)                                \
  V(DEF, set, LDSET)                                \
  V(DEF, smax, LDSMAX)                              \
  V(DEF, smin, LDSMIN)                              \
  V(DEF, umax, LDUMAX)                              \
  V(DEF, umin, LDUMIN)

#define ATOMIC_MEMORY_STORE_MODES(V, NAME, OP) \
  V(NAME, OP##_x, OP##_w)                      \
  V(NAME##l, OP##L_x, OP##L_w)                 \
  V(NAME##b, OP##B, OP##B)                     \
  V(NAME##lb, OP##LB, OP##LB)                  \
  V(NAME##h, OP##H, OP##H)                     \
  V(NAME##lh, OP##LH, OP##LH)

#define ATOMIC_MEMORY_LOAD_MODES(V, NAME, OP) \
  ATOMIC_MEMORY_STORE_MODES(V, NAME, OP)      \
  V(NAME##a, OP##A_x, OP##A_w)                \
  V(NAME##al, OP##AL_x, OP##AL_w)             \
  V(NAME##ab, OP##AB, OP##AB)                 \
  V(NAME##alb, OP##ALB, OP##ALB)              \
  V(NAME##ah, OP##AH, OP##AH)                 \
  V(NAME##alh, OP##ALH, OP##ALH)

#define DEFINE_ASM_LOAD_FUNC(FN, OP_X, OP_W)                     \
  void Assembler::ld##FN(const Register& rs, const Register& rt, \
                         const MemOperand& src) {                \
    DCHECK(IsEnabled(LSE));                                      \
    DCHECK(src.IsImmediateOffset() && (src.offset() == 0));      \
    AtomicMemoryOp op = rt.Is64Bits() ? OP_X : OP_W;             \
    Emit(op | Rs(rs) | Rt(rt) | RnSP(src.base()));               \
  }
#define DEFINE_ASM_STORE_FUNC(FN, OP_X, OP_W)                         \
  void Assembler::st##FN(const Register& rs, const MemOperand& src) { \
    DCHECK(IsEnabled(LSE));                                           \
    ld##FN(rs, AppropriateZeroRegFor(rs), src);                       \
  }

ATOMIC_MEMORY_SIMPLE_OPERATION_LIST(ATOMIC_MEMORY_LOAD_MODES,
                                    DEFINE_ASM_LOAD_FUNC)
ATOMIC_MEMORY_SIMPLE_OPERATION_LIST(ATOMIC_MEMORY_STORE_MODES,
                                    DEFINE_ASM_STORE_FUNC)

#define DEFINE_ASM_SWP_FUNC(FN, OP_X, OP_W)                  \
  void Assembler::FN(const Register& rs, const Register& rt, \
                     const MemOperand& src) {                \
    DCHECK(IsEnabled(LSE));                                  \
    DCHECK(src.IsImmediateOffset() && (src.offset() == 0));  \
    AtomicMemoryOp op = rt.Is64Bits() ? OP_X : OP_W;         \
    Emit(op | Rs(rs) | Rt(rt) | RnSP(src.base()));           \
  }

ATOMIC_MEMORY_LOAD_MODES(DEFINE_ASM_SWP_FUNC, swp, SWP)

#undef DEFINE_ASM_LOAD_FUNC
#undef DEFINE_ASM_STORE_FUNC
#undef DEFINE_ASM_SWP_FUNC

void Assembler::sdot(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  DCHECK(IsEnabled(DOTPROD));
  DCHECK((vn.Is16B() && vd.Is4S()) || (vn.Is8B() && vd.Is2S()));
  DCHECK(AreSameFormat(vn, vm));
  Emit(VFormat(vd) | NEON_SDOT | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::NEON3DifferentL(const VRegister& vd, const VRegister& vn,
                                const VRegister& vm, NEON3DifferentOp vop) {
  DCHECK(AreSameFormat(vn, vm));
  DCHECK((vn.Is1H() && vd.Is1S()) || (vn.Is1S() && vd.Is1D()) ||
         (vn.Is8B() && vd.Is8H()) || (vn.Is4H() && vd.Is4S()) ||
         (vn.Is2S() && vd.Is2D()) || (vn.Is16B() && vd.Is8H()) ||
         (vn.Is8H() && vd.Is4S()) || (vn.Is4S() && vd.Is2D()));
  Instr format, op = vop;
  if (vd.IsScalar()) {
    op |= NEON_Q | NEONScalar;
    format = SFormat(vn);
  } else {
    format = VFormat(vn);
  }
  Emit(format | op | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::NEON3DifferentW(const VRegister& vd, const VRegister& vn,
                                const VRegister& vm, NEON3DifferentOp vop) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK((vm.Is8B() && vd.Is8H()) || (vm.Is4H() && vd.Is4S()) ||
         (vm.Is2S() && vd.Is2D()) || (vm.Is16B() && vd.Is8H()) ||
         (vm.Is8H() && vd.Is4S()) || (vm.Is4S() && vd.Is2D()));
  Emit(VFormat(vm) | vop | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::NEON3DifferentHN(const VRegister& vd, const VRegister& vn,
                                 const VRegister& vm, NEON3DifferentOp vop) {
  DCHECK(AreSameFormat(vm, vn));
  DCHECK((vd.Is8B() && vn.Is8H()) || (vd.Is4H() && vn.Is4S()) ||
         (vd.Is2S() && vn.Is2D()) || (vd.Is16B() && vn.Is8H()) ||
         (vd.Is8H() && vn.Is4S()) || (vd.Is4S() && vn.Is2D()));
  Emit(VFormat(vd) | vop | Rm(vm) | Rn(vn) | Rd(vd));
}

#define NEON_3DIFF_LONG_LIST(V)                                                \
  V(saddl, NEON_SADDL, vn.IsVector() && vn.IsD())                              \
  V(saddl2, NEON_SADDL2, vn.IsVector() && vn.IsQ())                            \
  V(sabal, NEON_SABAL, vn.IsVector() && vn.IsD())                              \
  V(sabal2, NEON_SABAL2, vn.IsVector() && vn.IsQ())                            \
  V(uabal, NEON_UABAL, vn.IsVector() && vn.IsD())                              \
  V(uabal2, NEON_UABAL2, vn.IsVector() && vn.IsQ())                            \
  V(sabdl, NEON_SABDL, vn.IsVector() && vn.IsD())                              \
  V(sabdl2, NEON_SABDL2, vn.IsVector() && vn.IsQ())                            \
  V(uabdl, NEON_UABDL, vn.IsVector() && vn.IsD())                              \
  V(uabdl2, NEON_UABDL2, vn.IsVector() && vn.IsQ())                            \
  V(smlal, NEON_SMLAL, vn.IsVector() && vn.IsD())                              \
  V(smlal2, NEON_SMLAL2, vn.IsVector() && vn.IsQ())                            \
  V(umlal, NEON_UMLAL, vn.IsVector() && vn.IsD())                              \
  V(umlal2, NEON_UMLAL2, vn.IsVector() && vn.IsQ())                            \
  V(smlsl, NEON_SMLSL, vn.IsVector() && vn.IsD())                              \
  V(smlsl2, NEON_SMLSL2, vn.IsVector() && vn.IsQ())                            \
  V(umlsl, NEON_UMLSL, vn.IsVector() && vn.IsD())                              \
  V(umlsl2, NEON_UMLSL2, vn.IsVector() && vn.IsQ())                            \
  V(smull, NEON_SMULL, vn.IsVector() && vn.IsD())                              \
  V(smull2, NEON_SMULL2, vn.IsVector() && vn.IsQ())                            \
  V(umull, NEON_UMULL, vn.IsVector() && vn.IsD())                              \
  V(umull2, NEON_UMULL2, vn.IsVector() && vn.IsQ())                            \
  V(ssubl, NEON_SSUBL, vn.IsVector() && vn.IsD())                              \
  V(ssubl2, NEON_SSUBL2, vn.IsVector() && vn.IsQ())                            \
  V(uaddl, NEON_UADDL, vn.IsVector() && vn.IsD())                              \
  V(uaddl2, NEON_UADDL2, vn.IsVector() && vn.IsQ())                            \
  V(usubl, NEON_USUBL, vn.IsVector() && vn.IsD())                              \
  V(usubl2, NEON_USUBL2, vn.IsVector() && vn.IsQ())                            \
  V(sqdmlal, NEON_SQDMLAL, vn.Is1H() || vn.Is1S() || vn.Is4H() || vn.Is2S())   \
  V(sqdmlal2, NEON_SQDMLAL2, vn.Is1H() || vn.Is1S() || vn.Is8H() || vn.Is4S()) \
  V(sqdmlsl, NEON_SQDMLSL, vn.Is1H() || vn.Is1S() || vn.Is4H() || vn.Is2S())   \
  V(sqdmlsl2, NEON_SQDMLSL2, vn.Is1H() || vn.Is1S() || vn.Is8H() || vn.Is4S()) \
  V(sqdmull, NEON_SQDMULL, vn.Is1H() || vn.Is1S() || vn.Is4H() || vn.Is2S())   \
  V(sqdmull2, NEON_SQDMULL2, vn.Is1H() || vn.Is1S() || vn.Is8H() || vn.Is4S())

#define DEFINE_ASM_FUNC(FN, OP, AS)                            \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm) {                    \
    DCHECK(AS);                                                \
    NEON3DifferentL(vd, vn, vm, OP);                           \
  }
NEON_3DIFF_LONG_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define NEON_3DIFF_HN_LIST(V)        \
  V(addhn, NEON_ADDHN, vd.IsD())     \
  V(addhn2, NEON_ADDHN2, vd.IsQ())   \
  V(raddhn, NEON_RADDHN, vd.IsD())   \
  V(raddhn2, NEON_RADDHN2, vd.IsQ()) \
  V(subhn, NEON_SUBHN, vd.IsD())     \
  V(subhn2, NEON_SUBHN2, vd.IsQ())   \
  V(rsubhn, NEON_RSUBHN, vd.IsD())   \
  V(rsubhn2, NEON_RSUBHN2, vd.IsQ())

#define DEFINE_ASM_FUNC(FN, OP, AS)                            \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm) {                    \
    DCHECK(AS);                                                \
    NEON3DifferentHN(vd, vn, vm, OP);                          \
  }
NEON_3DIFF_HN_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::NEONPerm(const VRegister& vd, const VRegister& vn,
                         const VRegister& vm, NEONPermOp op) {
  DCHECK(AreSameFormat(vd, vn, vm));
  DCHECK(!vd.Is1D());
  Emit(VFormat(vd) | op | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::trn1(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_TRN1);
}

void Assembler::trn2(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_TRN2);
}

void Assembler::uzp1(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_UZP1);
}

void Assembler::uzp2(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_UZP2);
}

void Assembler::zip1(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_ZIP1);
}

void Assembler::zip2(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_ZIP2);
}

void Assembler::NEONShiftImmediate(const VRegister& vd, const VRegister& vn,
                                   NEONShiftImmediateOp op, int immh_immb) {
  DCHECK(AreSameFormat(vd, vn));
  Instr q, scalar;
  if (vn.IsScalar()) {
    q = NEON_Q;
    scalar = NEON
"""


```