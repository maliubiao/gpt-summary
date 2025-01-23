Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Understand the Request:** The request asks for the functionality of the `assembler-arm64-inl.h` file in the V8 JavaScript engine. Key constraints include mentioning Torque if the filename ended in `.tq`, relating it to JavaScript with examples, providing logic reasoning with input/output, illustrating common programming errors, and finally, summarizing its function for Part 1.

2. **Initial Scan and Keyword Identification:** Quickly scan the file for recognizable C++ constructs and terms related to assembly, code generation, and V8 internals. Keywords like `assembler`, `Register`, `VRegister`, `Operand`, `MemOperand`, `Instruction`, `RelocInfo`, `Immediate`, `Code`, `Builtin`, and terms like "load," "store," "branch," and "shift" stand out. The `#ifndef` and `#define` indicate a header guard. The `namespace v8 { namespace internal {` clearly places this within V8's internal implementation.

3. **High-Level Function Guess:**  Based on the filename and initial scan, the file is strongly related to generating ARM64 assembly code. The "inl.h" suggests it contains inline function definitions to be included in other compilation units.

4. **Decomposition by Section (or logical grouping):** Instead of reading line by line, look for logical groupings of code.

    * **Includes:** The `#include` directives reveal dependencies on other V8 components like `assembler-arm64.h`, `assembler.h`, `objects-inl.h`, etc. This tells us it interacts with core V8 object representations and the broader assembler framework.

    * **`CpuFeatures::SupportsOptimizer()`:** This is a simple function indicating ARM64 supports optimization.

    * **`WritableRelocInfo::apply()`:** This function deals with updating addresses within generated code during relocation, essential for moving code in memory. It distinguishes between internal references and branches.

    * **`CPURegister`, `CPURegList`:** These structures and their associated methods (`IsSameSizeAndType`, `IsZero`, `IsSP`, `Combine`, `Remove`, `W()`, `X()`, `V()`, etc.) are clearly about representing and manipulating CPU registers (general-purpose and vector registers) on ARM64.

    * **`Register`, `VRegister` with `FromCode`:** These static methods provide ways to create register objects from their numerical codes. The `WRegFromCode`, `XRegFromCode`, etc., indicate different register sizes.

    * **`Immediate`:**  This struct represents immediate values (constants) used in instructions. The template specializations for `Tagged<Smi>` and `ExternalReference` highlight how V8-specific types are handled as immediates.

    * **`Operand`:** This struct encapsulates the operands of assembly instructions, which can be registers, immediate values, or shifted/extended registers. The logic within the constructor and the `Is...()` methods handles different operand forms.

    * **`MemOperand`:** This represents memory operands used in load and store instructions, handling different addressing modes (offset, pre/post-index, register offsets, etc.).

    * **`Assembler` static methods related to instructions:** Functions like `target_pointer_address_at`, `target_address_at`, `code_target_object_handle_at`, `set_target_address_at`, etc., are clearly about inspecting and modifying the embedded information within generated ARM64 instructions. They deal with things like target addresses for branches and loading constants.

    * **`RelocInfo` methods:** These methods (`target_address`, `target_object`, `set_target_object`, etc.) are crucial for managing relocation information. Relocation is the process of adjusting addresses in code when it's loaded into memory.

    * **`Assembler` helper functions for instruction encoding:** Functions like `LoadOpFor`, `StoreOpFor`, `LoadPairOpFor`, `StorePairOpFor`, `LoadLiteralOpFor`, and the inline `LoadStoreScaledImmOffset`, etc., are used to construct the bit patterns of ARM64 instructions based on the operation and operands.

    * **Encoding Helpers (Flags, Cond, Imm...):** These functions assist in packing immediate values, conditions, and other fields into the instruction word.

5. **Relate to JavaScript (if applicable):** Think about how these low-level assembly concepts map to higher-level JavaScript behavior. Function calls in JavaScript will often translate to branch instructions in assembly. Accessing object properties might involve load instructions. The `RelocInfo` handling is vital for supporting dynamic code generation and optimization, which are core to JavaScript engines.

    * **Example:**  A JavaScript function call `myFunction()` could correspond to a `BL` (Branch and Link) instruction in ARM64 assembly. The `target_address_at` function would be used to find the memory address of `myFunction`.

6. **Logic Reasoning with Input/Output (simple cases):**  For some functions, it's easy to create hypothetical input and output scenarios.

    * **`CPURegList::Combine`:** If `list_` is `0b0010` and `other.list_` is `0b0100`, the output would be `0b0110`.

7. **Common Programming Errors:** Consider how developers might misuse the functionality provided by this header.

    * **Incorrect register size:** Trying to use a 32-bit register where a 64-bit one is expected, or vice versa, can lead to errors.
    * **Invalid immediate values:**  ARM64 instructions have restrictions on the range of immediate values.
    * **Incorrect addressing modes:** Using the wrong `MemOperand` constructor or `AddrMode` could cause memory access errors.

8. **Torque Check:** The prompt specifically asks about `.tq`. Since the filename ends in `.h`, this is *not* a Torque file. State this clearly.

9. **Synthesize the Summary:** Combine the identified functionalities into a concise summary. Focus on the main purpose: defining data structures and inline functions to facilitate the generation of ARM64 assembly code within V8. Emphasize the role in representing registers, operands, memory operations, and instruction manipulation, including relocation.

10. **Review and Refine:** Read through the analysis to ensure accuracy, clarity, and completeness according to the prompt's requirements. Make sure the examples and explanations are easy to understand. For instance, initially, I might just say "deals with memory," but refining it to "represents memory operands used in load and store instructions, handling different addressing modes" is more precise.

This iterative process of scanning, decomposing, relating, exemplifying, and summarizing allows for a comprehensive understanding of the header file's functionality.
## 功能归纳：v8/src/codegen/arm64/assembler-arm64-inl.h (第 1 部分)

这个头文件 `v8/src/codegen/arm64/assembler-arm64-inl.h` 是 V8 JavaScript 引擎中用于 ARM64 架构的代码生成器（Assembler）的**内联函数定义**部分。它不以 `.tq` 结尾，因此不是 Torque 源代码。

其主要功能可以归纳为：

**1. 提供用于操作 ARM64 寄存器、立即数和内存操作数的便捷接口：**

* **寄存器表示 (`CPURegister`, `CPURegList`, `Register`, `VRegister`)：** 定义了用于表示 ARM64 通用寄存器（X/W）、SIMD/浮点寄存器（V/Q/D/S/H/B）及其列表的数据结构。提供了判断寄存器类型、大小、是否为零寄存器/堆栈指针等方法。
* **立即数表示 (`Immediate`)：**  定义了 `Immediate` 结构体，用于表示指令中的立即数，并能处理不同类型的立即数，包括普通的整数、Smi（Small Integer）、外部引用等。
* **操作数表示 (`Operand`)：** 定义了 `Operand` 结构体，用于表示指令的操作数，可以是寄存器、立即数，还可以是移位或扩展的寄存器。提供了判断操作数类型的便捷方法。
* **内存操作数表示 (`MemOperand`)：** 定义了 `MemOperand` 结构体，用于表示内存操作数，支持不同的寻址模式，包括立即数偏移、寄存器偏移、预/后索引等。

**2. 提供用于生成和操作 ARM64 指令的辅助函数：**

* **指令目标地址访问 (`target_pointer_address_at`, `target_address_at`, `code_target_object_handle_at`, 等)：**  提供了一系列函数，用于获取指令中嵌入的目标地址、代码对象句柄、内建函数等信息，这对于代码的链接、重定位和反序列化非常重要。
* **指令目标地址设置 (`set_target_address_at`, `set_target_compressed_address_at`)：** 提供了设置指令中目标地址的函数，允许在运行时修改生成的代码。
* **重定位信息处理 (`WritableRelocInfo::apply`, `RelocInfo::target_address`, `RelocInfo::target_object`, 等)：**  定义了处理重定位信息的相关方法，用于在代码移动时更新指令中的地址引用。
* **获取 Load/Store 指令操作码 (`LoadOpFor`, `StoreOpFor`, `LoadPairOpFor`, `StorePairOpFor`, `LoadLiteralOpFor`)：**  根据操作的寄存器类型和大小，返回对应的 Load/Store 指令操作码。
* **内联函数用于生成特定类型的指令 (`LoadStoreScaledImmOffset`, `LoadStoreUnscaledImmOffset`, `DataProcPlainRegister`, 等)：** 提供了一些内联函数，用于生成常见的 ARM64 指令序列，例如带偏移的加载/存储、数据处理指令等。
* **指令字段编码辅助函数 (`Flags`, `Cond`, `ImmPCRelAddress`, `ImmUncondBranch`, 等)：**  提供了一系列内联函数，用于将条件码、立即数等值编码到指令的特定位域中。

**3. 提供对 CPU 特性的支持：**

* **`CpuFeatures::SupportsOptimizer()`:**  简单地返回 `true`，表明 ARM64 平台支持优化器。

**与 JavaScript 功能的关系：**

这个头文件是 V8 引擎代码生成器的核心部分，它直接参与将 JavaScript 代码编译成可执行的 ARM64 机器码。  当 V8 执行 JavaScript 代码时，需要将 JavaScript 代码翻译成底层的机器指令。`assembler-arm64-inl.h` 中定义的结构体和函数就是用来构建这些机器指令的。

**JavaScript 示例：**

虽然 `assembler-arm64-inl.h` 是 C++ 代码，但它所生成的操作直接影响 JavaScript 的执行。例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
let result = add(5, 3);
```

V8 引擎在执行这段代码时，`assembler-arm64-inl.h` 中的功能会被用来生成类似以下的 ARM64 指令（简化表示）：

* 将参数 `a` 和 `b` 加载到寄存器中 (`LDR` 指令)。
* 执行加法运算 (`ADD` 指令)。
* 将结果存储到某个位置。
* 返回结果 (`BR` 或 `RET` 指令)。

`Operand` 结构体会用于表示 `a` 和 `b` 所在的寄存器或内存位置。 `Immediate` 结构体可能会用于表示常量 `5` 和 `3`。 `MemOperand` 结构体可能用于表示访问变量 `result` 的内存地址。

**代码逻辑推理（假设输入与输出）：**

考虑 `CPURegList::Combine` 函数：

**假设输入：**

* `CPURegList` 对象 `list1`，其内部 `list_` 值为 `0b0001` (表示只包含寄存器 0)。
* `CPURegList` 对象 `list2`，其内部 `list_` 值为 `0b0010` (表示只包含寄存器 1)。

**输出：**

调用 `list1.Combine(list2)` 后，`list1` 的内部 `list_` 值将变为 `0b0011` (表示包含寄存器 0 和 1)。

**用户常见的编程错误（在 V8 引擎开发中）：**

直接使用这个头文件进行编程是 V8 引擎内部开发的工作，普通 JavaScript 开发者不会直接接触。但是，在 V8 引擎的开发过程中，常见的错误可能包括：

* **错误地使用寄存器大小或类型：** 例如，尝试将一个 64 位的值加载到一个 32 位的寄存器中，或者在需要浮点寄存器的地方使用了通用寄存器。
* **使用了超出范围的立即数：** ARM64 指令对于立即数的值有一定的限制，使用了超出范围的值会导致指令编码错误。
* **错误的内存寻址：**  使用了不正确的 `MemOperand` 构造函数或寻址模式，导致访问了错误的内存地址。
* **忘记进行指令缓存刷新：** 在修改了生成的代码后，如果没有正确地刷新指令缓存，可能会导致 CPU 执行旧的指令。

**总结 (第 1 部分功能)：**

`v8/src/codegen/arm64/assembler-arm64-inl.h` (第 1 部分) 主要定义了用于在 V8 引擎中生成 ARM64 汇编代码所需的基本数据结构和内联函数。 它提供了表示和操作 ARM64 寄存器、立即数和内存操作数的工具，以及生成和修改 ARM64 指令的辅助功能。 这是 V8 将 JavaScript 代码转化为可执行机器码的关键组成部分。

### 提示词
```
这是目录为v8/src/codegen/arm64/assembler-arm64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/assembler-arm64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_ARM64_ASSEMBLER_ARM64_INL_H_
#define V8_CODEGEN_ARM64_ASSEMBLER_ARM64_INL_H_

#include <type_traits>

#include "src/base/memory.h"
#include "src/codegen/arm64/assembler-arm64.h"
#include "src/codegen/assembler.h"
#include "src/codegen/flush-instruction-cache.h"
#include "src/debug/debug.h"
#include "src/heap/heap-layout-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "src/objects/tagged.h"

namespace v8 {
namespace internal {

bool CpuFeatures::SupportsOptimizer() { return true; }

void WritableRelocInfo::apply(intptr_t delta) {
  // On arm64 only internal references and immediate branches need extra work.
  if (RelocInfo::IsInternalReference(rmode_)) {
    // Absolute code pointer inside code object moves with the code object.
    intptr_t internal_ref = ReadUnalignedValue<intptr_t>(pc_);
    internal_ref += delta;  // Relocate entry.
    jit_allocation_.WriteUnalignedValue<intptr_t>(pc_, internal_ref);
  } else {
    Instruction* instr = reinterpret_cast<Instruction*>(pc_);
    if (instr->IsBranchAndLink() || instr->IsUnconditionalBranch()) {
      Address old_target =
          reinterpret_cast<Address>(instr->ImmPCOffsetTarget());
      Address new_target = old_target - delta;
      instr->SetBranchImmTarget<UncondBranchType>(
          reinterpret_cast<Instruction*>(new_target), &jit_allocation_);
    }
  }
}

inline bool CPURegister::IsSameSizeAndType(const CPURegister& other) const {
  return (reg_size_ == other.reg_size_) && (reg_type_ == other.reg_type_);
}

inline bool CPURegister::IsZero() const {
  DCHECK(is_valid());
  return IsRegister() && (code() == kZeroRegCode);
}

inline bool CPURegister::IsSP() const {
  DCHECK(is_valid());
  return IsRegister() && (code() == kSPRegInternalCode);
}

inline void CPURegList::Combine(const CPURegList& other) {
  DCHECK(other.type() == type_);
  DCHECK(other.RegisterSizeInBits() == size_);
  list_ |= other.list_;
}

inline void CPURegList::Remove(const CPURegList& other) {
  if (other.type() == type_) {
    list_ &= ~other.list_;
  }
}

inline void CPURegList::Combine(const CPURegister& other) {
  DCHECK(other.type() == type_);
  DCHECK(other.SizeInBits() == size_);
  Combine(other.code());
}

inline void CPURegList::Remove(const CPURegister& other1,
                               const CPURegister& other2,
                               const CPURegister& other3,
                               const CPURegister& other4) {
  if (!other1.IsNone() && (other1.type() == type_)) Remove(other1.code());
  if (!other2.IsNone() && (other2.type() == type_)) Remove(other2.code());
  if (!other3.IsNone() && (other3.type() == type_)) Remove(other3.code());
  if (!other4.IsNone() && (other4.type() == type_)) Remove(other4.code());
}

inline void CPURegList::Combine(int code) {
  DCHECK(CPURegister::Create(code, size_, type_).is_valid());
  list_ |= (1ULL << code);
  DCHECK(is_valid());
}

inline void CPURegList::Remove(int code) {
  DCHECK(CPURegister::Create(code, size_, type_).is_valid());
  list_ &= ~(1ULL << code);
}

inline Register Register::XRegFromCode(unsigned code) {
  if (code == kSPRegInternalCode) {
    return sp;
  } else {
    DCHECK_LT(code, static_cast<unsigned>(kNumberOfRegisters));
    return Register::Create(code, kXRegSizeInBits);
  }
}

inline Register Register::WRegFromCode(unsigned code) {
  if (code == kSPRegInternalCode) {
    return wsp;
  } else {
    DCHECK_LT(code, static_cast<unsigned>(kNumberOfRegisters));
    return Register::Create(code, kWRegSizeInBits);
  }
}

inline VRegister VRegister::BRegFromCode(unsigned code) {
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return VRegister::Create(code, kBRegSizeInBits);
}

inline VRegister VRegister::HRegFromCode(unsigned code) {
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return VRegister::Create(code, kHRegSizeInBits);
}

inline VRegister VRegister::SRegFromCode(unsigned code) {
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return VRegister::Create(code, kSRegSizeInBits);
}

inline VRegister VRegister::DRegFromCode(unsigned code) {
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return VRegister::Create(code, kDRegSizeInBits);
}

inline VRegister VRegister::QRegFromCode(unsigned code) {
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return VRegister::Create(code, kQRegSizeInBits);
}

inline VRegister VRegister::VRegFromCode(unsigned code) {
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return VRegister::Create(code, kVRegSizeInBits);
}

inline Register CPURegister::W() const {
  DCHECK(IsRegister());
  return Register::WRegFromCode(code());
}

inline Register CPURegister::Reg() const {
  DCHECK(IsRegister());
  return Register::Create(code(), reg_size_);
}

inline VRegister CPURegister::VReg() const {
  DCHECK(IsVRegister());
  return VRegister::Create(code(), reg_size_);
}

inline Register CPURegister::X() const {
  DCHECK(IsRegister());
  return Register::XRegFromCode(code());
}

inline VRegister CPURegister::V() const {
  DCHECK(IsVRegister());
  return VRegister::VRegFromCode(code());
}

inline VRegister CPURegister::B() const {
  DCHECK(IsVRegister());
  return VRegister::BRegFromCode(code());
}

inline VRegister CPURegister::H() const {
  DCHECK(IsVRegister());
  return VRegister::HRegFromCode(code());
}

inline VRegister CPURegister::S() const {
  DCHECK(IsVRegister());
  return VRegister::SRegFromCode(code());
}

inline VRegister CPURegister::D() const {
  DCHECK(IsVRegister());
  return VRegister::DRegFromCode(code());
}

inline VRegister CPURegister::Q() const {
  DCHECK(IsVRegister());
  return VRegister::QRegFromCode(code());
}

// Immediate.
// Default initializer is for int types
template <typename T>
struct ImmediateInitializer {
  static inline RelocInfo::Mode rmode_for(T) { return RelocInfo::NO_INFO; }
  static inline int64_t immediate_for(T t) {
    static_assert(sizeof(T) <= 8);
    static_assert(std::is_integral<T>::value || std::is_enum<T>::value);
    return t;
  }
};

template <>
struct ImmediateInitializer<Tagged<Smi>> {
  static inline RelocInfo::Mode rmode_for(Tagged<Smi> t) {
    return RelocInfo::NO_INFO;
  }
  static inline int64_t immediate_for(Tagged<Smi> t) {
    return static_cast<int64_t>(t.ptr());
  }
};

template <>
struct ImmediateInitializer<ExternalReference> {
  static inline RelocInfo::Mode rmode_for(ExternalReference t) {
    return RelocInfo::EXTERNAL_REFERENCE;
  }
  static inline int64_t immediate_for(ExternalReference t) {
    return static_cast<int64_t>(t.raw());
  }
};

template <typename T>
Immediate::Immediate(Handle<T> handle, RelocInfo::Mode mode)
    : value_(static_cast<intptr_t>(handle.address())), rmode_(mode) {
  DCHECK(RelocInfo::IsEmbeddedObjectMode(mode));
}

template <typename T>
Immediate::Immediate(T t)
    : value_(ImmediateInitializer<T>::immediate_for(t)),
      rmode_(ImmediateInitializer<T>::rmode_for(t)) {}

template <typename T>
Immediate::Immediate(T t, RelocInfo::Mode rmode)
    : value_(ImmediateInitializer<T>::immediate_for(t)), rmode_(rmode) {
  static_assert(std::is_integral<T>::value);
}

template <typename T>
Operand::Operand(T t) : immediate_(t), reg_(NoReg) {}

template <typename T>
Operand::Operand(T t, RelocInfo::Mode rmode)
    : immediate_(t, rmode), reg_(NoReg) {}

Operand::Operand(Register reg, Shift shift, unsigned shift_amount)
    : immediate_(0),
      reg_(reg),
      shift_(shift),
      extend_(NO_EXTEND),
      shift_amount_(shift_amount) {
  DCHECK(reg.Is64Bits() || (shift_amount < kWRegSizeInBits));
  DCHECK(reg.Is32Bits() || (shift_amount < kXRegSizeInBits));
  DCHECK_IMPLIES(reg.IsSP(), shift_amount == 0);
}

Operand::Operand(Register reg, Extend extend, unsigned shift_amount)
    : immediate_(0),
      reg_(reg),
      shift_(NO_SHIFT),
      extend_(extend),
      shift_amount_(shift_amount) {
  DCHECK(reg.is_valid());
  DCHECK_LE(shift_amount, 4);
  DCHECK(!reg.IsSP());

  // Extend modes SXTX and UXTX require a 64-bit register.
  DCHECK(reg.Is64Bits() || ((extend != SXTX) && (extend != UXTX)));
}

bool Operand::IsHeapNumberRequest() const {
  DCHECK_IMPLIES(heap_number_request_.has_value(), reg_ == NoReg);
  DCHECK_IMPLIES(heap_number_request_.has_value(),
                 immediate_.rmode() == RelocInfo::FULL_EMBEDDED_OBJECT ||
                     immediate_.rmode() == RelocInfo::CODE_TARGET);
  return heap_number_request_.has_value();
}

HeapNumberRequest Operand::heap_number_request() const {
  DCHECK(IsHeapNumberRequest());
  return *heap_number_request_;
}

bool Operand::IsImmediate() const {
  return reg_ == NoReg && !IsHeapNumberRequest();
}

bool Operand::IsShiftedRegister() const {
  return reg_.is_valid() && (shift_ != NO_SHIFT);
}

bool Operand::IsExtendedRegister() const {
  return reg_.is_valid() && (extend_ != NO_EXTEND);
}

bool Operand::IsZero() const {
  if (IsImmediate()) {
    return ImmediateValue() == 0;
  } else {
    return reg().IsZero();
  }
}

Operand Operand::ToExtendedRegister() const {
  DCHECK(IsShiftedRegister());
  DCHECK((shift_ == LSL) && (shift_amount_ <= 4));
  return Operand(reg_, reg_.Is64Bits() ? UXTX : UXTW, shift_amount_);
}

Operand Operand::ToW() const {
  if (IsShiftedRegister()) {
    DCHECK(reg_.Is64Bits());
    return Operand(reg_.W(), shift(), shift_amount());
  } else if (IsExtendedRegister()) {
    DCHECK(reg_.Is64Bits());
    return Operand(reg_.W(), extend(), shift_amount());
  }
  DCHECK(IsImmediate());
  return *this;
}

Immediate Operand::immediate_for_heap_number_request() const {
  DCHECK(immediate_.rmode() == RelocInfo::FULL_EMBEDDED_OBJECT);
  return immediate_;
}

Immediate Operand::immediate() const {
  DCHECK(IsImmediate());
  return immediate_;
}

int64_t Operand::ImmediateValue() const {
  DCHECK(IsImmediate());
  return immediate_.value();
}

RelocInfo::Mode Operand::ImmediateRMode() const {
  DCHECK(IsImmediate() || IsHeapNumberRequest());
  return immediate_.rmode();
}

Register Operand::reg() const {
  DCHECK(IsShiftedRegister() || IsExtendedRegister());
  return reg_;
}

Shift Operand::shift() const {
  DCHECK(IsShiftedRegister());
  return shift_;
}

Extend Operand::extend() const {
  DCHECK(IsExtendedRegister());
  return extend_;
}

unsigned Operand::shift_amount() const {
  DCHECK(IsShiftedRegister() || IsExtendedRegister());
  return shift_amount_;
}

MemOperand::MemOperand()
    : base_(NoReg),
      regoffset_(NoReg),
      offset_(0),
      addrmode_(Offset),
      shift_(NO_SHIFT),
      extend_(NO_EXTEND),
      shift_amount_(0) {}

MemOperand::MemOperand(Register base, int64_t offset, AddrMode addrmode)
    : base_(base),
      regoffset_(NoReg),
      offset_(offset),
      addrmode_(addrmode),
      shift_(NO_SHIFT),
      extend_(NO_EXTEND),
      shift_amount_(0) {
  DCHECK(base.Is64Bits() && !base.IsZero());
}

MemOperand::MemOperand(Register base, Register regoffset, Extend extend,
                       unsigned shift_amount)
    : base_(base),
      regoffset_(regoffset),
      offset_(0),
      addrmode_(Offset),
      shift_(NO_SHIFT),
      extend_(extend),
      shift_amount_(shift_amount) {
  DCHECK(base.Is64Bits() && !base.IsZero());
  DCHECK(!regoffset.IsSP());
  DCHECK((extend == UXTW) || (extend == SXTW) || (extend == SXTX));

  // SXTX extend mode requires a 64-bit offset register.
  DCHECK(regoffset.Is64Bits() || (extend != SXTX));
}

MemOperand::MemOperand(Register base, Register regoffset, Shift shift,
                       unsigned shift_amount)
    : base_(base),
      regoffset_(regoffset),
      offset_(0),
      addrmode_(Offset),
      shift_(shift),
      extend_(NO_EXTEND),
      shift_amount_(shift_amount) {
  DCHECK(base.Is64Bits() && !base.IsZero());
  DCHECK(regoffset.Is64Bits() && !regoffset.IsSP());
  DCHECK(shift == LSL);
}

MemOperand::MemOperand(Register base, const Operand& offset, AddrMode addrmode)
    : base_(base), regoffset_(NoReg), addrmode_(addrmode) {
  DCHECK(base.Is64Bits() && !base.IsZero());

  if (offset.IsImmediate()) {
    offset_ = offset.ImmediateValue();
  } else if (offset.IsShiftedRegister()) {
    DCHECK((addrmode == Offset) || (addrmode == PostIndex));

    regoffset_ = offset.reg();
    shift_ = offset.shift();
    shift_amount_ = offset.shift_amount();

    extend_ = NO_EXTEND;
    offset_ = 0;

    // These assertions match those in the shifted-register constructor.
    DCHECK(regoffset_.Is64Bits() && !regoffset_.IsSP());
    DCHECK(shift_ == LSL);
  } else {
    DCHECK(offset.IsExtendedRegister());
    DCHECK(addrmode == Offset);

    regoffset_ = offset.reg();
    extend_ = offset.extend();
    shift_amount_ = offset.shift_amount();

    shift_ = NO_SHIFT;
    offset_ = 0;

    // These assertions match those in the extended-register constructor.
    DCHECK(!regoffset_.IsSP());
    DCHECK((extend_ == UXTW) || (extend_ == SXTW) || (extend_ == SXTX));
    DCHECK((regoffset_.Is64Bits() || (extend_ != SXTX)));
  }
}

bool MemOperand::IsImmediateOffset() const {
  return (addrmode_ == Offset) && regoffset_ == NoReg;
}

bool MemOperand::IsRegisterOffset() const {
  return (addrmode_ == Offset) && regoffset_ != NoReg;
}

bool MemOperand::IsPreIndex() const { return addrmode_ == PreIndex; }

bool MemOperand::IsPostIndex() const { return addrmode_ == PostIndex; }

void Assembler::Unreachable() { debug("UNREACHABLE", __LINE__, BREAK); }

Address Assembler::target_pointer_address_at(Address pc) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  DCHECK(instr->IsLdrLiteralX() || instr->IsLdrLiteralW());
  return reinterpret_cast<Address>(instr->ImmPCOffsetTarget());
}

// Read/Modify the code target address in the branch/call instruction at pc.
Address Assembler::target_address_at(Address pc, Address constant_pool) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  if (instr->IsLdrLiteralX()) {
    return Memory<Address>(target_pointer_address_at(pc));
  } else {
    DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
    return reinterpret_cast<Address>(instr->ImmPCOffsetTarget());
  }
}

Tagged_t Assembler::target_compressed_address_at(Address pc,
                                                 Address constant_pool) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  CHECK(instr->IsLdrLiteralW());
  return Memory<Tagged_t>(target_pointer_address_at(pc));
}

Handle<Code> Assembler::code_target_object_handle_at(Address pc) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  if (instr->IsLdrLiteralX()) {
    return Handle<Code>(reinterpret_cast<Address*>(
        Assembler::target_address_at(pc, 0 /* unused */)));
  } else {
    DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
    DCHECK_EQ(instr->ImmPCOffset() % kInstrSize, 0);
    return Cast<Code>(
        GetEmbeddedObject(instr->ImmPCOffset() >> kInstrSizeLog2));
  }
}

AssemblerBase::EmbeddedObjectIndex
Assembler::embedded_object_index_referenced_from(Address pc) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  if (instr->IsLdrLiteralX()) {
    static_assert(sizeof(EmbeddedObjectIndex) == sizeof(intptr_t));
    return Memory<EmbeddedObjectIndex>(target_pointer_address_at(pc));
  } else {
    DCHECK(instr->IsLdrLiteralW());
    return Memory<uint32_t>(target_pointer_address_at(pc));
  }
}

void Assembler::set_embedded_object_index_referenced_from(
    Address pc, EmbeddedObjectIndex data) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  if (instr->IsLdrLiteralX()) {
    Memory<EmbeddedObjectIndex>(target_pointer_address_at(pc)) = data;
  } else {
    DCHECK(instr->IsLdrLiteralW());
    DCHECK(is_uint32(data));
    WriteUnalignedValue<uint32_t>(target_pointer_address_at(pc),
                                  static_cast<uint32_t>(data));
  }
}

Handle<HeapObject> Assembler::target_object_handle_at(Address pc) {
  return GetEmbeddedObject(
      Assembler::embedded_object_index_referenced_from(pc));
}

Builtin Assembler::target_builtin_at(Address pc) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
  DCHECK_EQ(instr->ImmPCOffset() % kInstrSize, 0);
  int builtin_id = static_cast<int>(instr->ImmPCOffset() / kInstrSize);
  DCHECK(Builtins::IsBuiltinId(builtin_id));
  return static_cast<Builtin>(builtin_id);
}

int Assembler::deserialization_special_target_size(Address location) {
  Instruction* instr = reinterpret_cast<Instruction*>(location);
  if (instr->IsBranchAndLink() || instr->IsUnconditionalBranch()) {
    return kSpecialTargetSize;
  } else {
    DCHECK_EQ(instr->InstructionBits(), 0);
    return kSystemPointerSize;
  }
}

void Assembler::deserialization_set_target_internal_reference_at(
    Address pc, Address target, RelocInfo::Mode mode) {
  WriteUnalignedValue<Address>(pc, target);
}

void Assembler::set_target_address_at(Address pc, Address constant_pool,
                                      Address target,
                                      WritableJitAllocation* jit_allocation,
                                      ICacheFlushMode icache_flush_mode) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  if (instr->IsLdrLiteralX()) {
    if (jit_allocation) {
      jit_allocation->WriteValue<Address>(target_pointer_address_at(pc),
                                          target);
    } else {
      Memory<Address>(target_pointer_address_at(pc)) = target;
    }
    // Intuitively, we would think it is necessary to always flush the
    // instruction cache after patching a target address in the code. However,
    // in this case, only the constant pool contents change. The instruction
    // accessing the constant pool remains unchanged, so a flush is not
    // required.
  } else {
    DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
    if (target == 0) {
      // We are simply wiping the target out for serialization. Set the offset
      // to zero instead.
      target = pc;
    }
    instr->SetBranchImmTarget<UncondBranchType>(
        reinterpret_cast<Instruction*>(target), jit_allocation);
    if (icache_flush_mode != SKIP_ICACHE_FLUSH) {
      FlushInstructionCache(pc, kInstrSize);
    }
  }
}

void Assembler::set_target_compressed_address_at(
    Address pc, Address constant_pool, Tagged_t target,
    WritableJitAllocation* jit_allocation, ICacheFlushMode icache_flush_mode) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  CHECK(instr->IsLdrLiteralW());
  if (jit_allocation) {
    jit_allocation->WriteValue(target_pointer_address_at(pc), target);
  } else {
    Memory<Tagged_t>(target_pointer_address_at(pc)) = target;
  }
}

int RelocInfo::target_address_size() {
  if (IsCodedSpecially()) {
    return Assembler::kSpecialTargetSize;
  } else {
    Instruction* instr = reinterpret_cast<Instruction*>(pc_);
    DCHECK(instr->IsLdrLiteralX() || instr->IsLdrLiteralW());
    return instr->IsLdrLiteralW() ? kTaggedSize : kSystemPointerSize;
  }
}

Address RelocInfo::target_address() {
  DCHECK(IsCodeTarget(rmode_) || IsNearBuiltinEntry(rmode_) ||
         IsWasmCall(rmode_) || IsWasmStubCall(rmode_));
  return Assembler::target_address_at(pc_, constant_pool_);
}

Address RelocInfo::target_address_address() {
  DCHECK(HasTargetAddressAddress());
  Instruction* instr = reinterpret_cast<Instruction*>(pc_);
  // Read the address of the word containing the target_address in an
  // instruction stream.
  // The only architecture-independent user of this function is the serializer.
  // The serializer uses it to find out how many raw bytes of instruction to
  // output before the next target.
  // For an instruction like B/BL, where the target bits are mixed into the
  // instruction bits, the size of the target will be zero, indicating that the
  // serializer should not step forward in memory after a target is resolved
  // and written.
  // For LDR literal instructions, we can skip up to the constant pool entry
  // address. We make sure that RelocInfo is ordered by the
  // target_address_address so that we do not skip over any relocatable
  // instruction sequences.
  if (instr->IsLdrLiteralX()) {
    return constant_pool_entry_address();
  } else {
    DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
    return pc_;
  }
}

Address RelocInfo::constant_pool_entry_address() {
  DCHECK(IsInConstantPool());
  return Assembler::target_pointer_address_at(pc_);
}

Tagged<HeapObject> RelocInfo::target_object(PtrComprCageBase cage_base) {
  DCHECK(IsCodeTarget(rmode_) || IsEmbeddedObjectMode(rmode_));
  if (IsCompressedEmbeddedObject(rmode_)) {
    Tagged_t compressed =
        Assembler::target_compressed_address_at(pc_, constant_pool_);
    DCHECK(!HAS_SMI_TAG(compressed));
    Tagged<Object> obj(
        V8HeapCompressionScheme::DecompressTagged(cage_base, compressed));
    return Cast<HeapObject>(obj);
  } else {
    return Cast<HeapObject>(
        Tagged<Object>(Assembler::target_address_at(pc_, constant_pool_)));
  }
}

Handle<HeapObject> RelocInfo::target_object_handle(Assembler* origin) {
  if (IsEmbeddedObjectMode(rmode_)) {
    return origin->target_object_handle_at(pc_);
  } else {
    DCHECK(IsCodeTarget(rmode_));
    return origin->code_target_object_handle_at(pc_);
  }
}

void WritableRelocInfo::set_target_object(Tagged<HeapObject> target,
                                          ICacheFlushMode icache_flush_mode) {
  DCHECK(IsCodeTarget(rmode_) || IsEmbeddedObjectMode(rmode_));
  if (IsCompressedEmbeddedObject(rmode_)) {
    DCHECK(COMPRESS_POINTERS_BOOL);
    // We must not compress pointers to objects outside of the main pointer
    // compression cage as we wouldn't be able to decompress them with the
    // correct cage base.
    DCHECK_IMPLIES(V8_ENABLE_SANDBOX_BOOL, !HeapLayout::InTrustedSpace(target));
    DCHECK_IMPLIES(V8_EXTERNAL_CODE_SPACE_BOOL,
                   !HeapLayout::InCodeSpace(target));
    Assembler::set_target_compressed_address_at(
        pc_, constant_pool_,
        V8HeapCompressionScheme::CompressObject(target.ptr()), &jit_allocation_,
        icache_flush_mode);
  } else {
    DCHECK(IsFullEmbeddedObject(rmode_));
    Assembler::set_target_address_at(pc_, constant_pool_, target.ptr(),
                                     &jit_allocation_, icache_flush_mode);
  }
}

Address RelocInfo::target_external_reference() {
  DCHECK(rmode_ == EXTERNAL_REFERENCE);
  return Assembler::target_address_at(pc_, constant_pool_);
}

void WritableRelocInfo::set_target_external_reference(
    Address target, ICacheFlushMode icache_flush_mode) {
  DCHECK(rmode_ == RelocInfo::EXTERNAL_REFERENCE);
  Assembler::set_target_address_at(pc_, constant_pool_, target,
                                   &jit_allocation_, icache_flush_mode);
}

WasmCodePointer RelocInfo::wasm_indirect_call_target() const {
  DCHECK(rmode_ == WASM_INDIRECT_CALL_TARGET);
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  return Assembler::uint32_constant_at(pc_, constant_pool_);
#else
  return Assembler::target_address_at(pc_, constant_pool_);
#endif
}

void WritableRelocInfo::set_wasm_indirect_call_target(
    WasmCodePointer target, ICacheFlushMode icache_flush_mode) {
  DCHECK(rmode_ == RelocInfo::WASM_INDIRECT_CALL_TARGET);
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  Assembler::set_uint32_constant_at(pc_, constant_pool_, target,
                                    &jit_allocation_, icache_flush_mode);
#else
  Assembler::set_target_address_at(pc_, constant_pool_, target,
                                   &jit_allocation_, icache_flush_mode);
#endif
}

Address RelocInfo::target_internal_reference() {
  DCHECK(rmode_ == INTERNAL_REFERENCE);
  return ReadUnalignedValue<Address>(pc_);
}

Address RelocInfo::target_internal_reference_address() {
  DCHECK(rmode_ == INTERNAL_REFERENCE);
  return pc_;
}

Builtin RelocInfo::target_builtin_at(Assembler* origin) {
  DCHECK(IsNearBuiltinEntry(rmode_));
  return Assembler::target_builtin_at(pc_);
}

Address RelocInfo::target_off_heap_target() {
  DCHECK(IsOffHeapTarget(rmode_));
  return Assembler::target_address_at(pc_, constant_pool_);
}

uint32_t Assembler::uint32_constant_at(Address pc, Address constant_pool) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  CHECK(instr->IsLdrLiteralW());
  return ReadUnalignedValue<uint32_t>(target_pointer_address_at(pc));
}

void Assembler::set_uint32_constant_at(Address pc, Address constant_pool,
                                       uint32_t new_constant,
                                       WritableJitAllocation* jit_allocation,
                                       ICacheFlushMode icache_flush_mode) {
  Instruction* instr = reinterpret_cast<Instruction*>(pc);
  CHECK(instr->IsLdrLiteralW());
  if (jit_allocation) {
    jit_allocation->WriteUnalignedValue<uint32_t>(target_pointer_address_at(pc),
                                                  new_constant);
  } else {
    WriteUnalignedValue<uint32_t>(target_pointer_address_at(pc), new_constant);
  }
  // Icache flushing not needed for Ldr via the constant pool.
}

LoadStoreOp Assembler::LoadOpFor(const CPURegister& rt) {
  DCHECK(rt.is_valid());
  if (rt.IsRegister()) {
    return rt.Is64Bits() ? LDR_x : LDR_w;
  } else {
    DCHECK(rt.IsVRegister());
    switch (rt.SizeInBits()) {
      case kBRegSizeInBits:
        return LDR_b;
      case kHRegSizeInBits:
        return LDR_h;
      case kSRegSizeInBits:
        return LDR_s;
      case kDRegSizeInBits:
        return LDR_d;
      default:
        DCHECK(rt.IsQ());
        return LDR_q;
    }
  }
}

LoadStoreOp Assembler::StoreOpFor(const CPURegister& rt) {
  DCHECK(rt.is_valid());
  if (rt.IsRegister()) {
    return rt.Is64Bits() ? STR_x : STR_w;
  } else {
    DCHECK(rt.IsVRegister());
    switch (rt.SizeInBits()) {
      case kBRegSizeInBits:
        return STR_b;
      case kHRegSizeInBits:
        return STR_h;
      case kSRegSizeInBits:
        return STR_s;
      case kDRegSizeInBits:
        return STR_d;
      default:
        DCHECK(rt.IsQ());
        return STR_q;
    }
  }
}

LoadStorePairOp Assembler::LoadPairOpFor(const CPURegister& rt,
                                         const CPURegister& rt2) {
  DCHECK_EQ(STP_w | LoadStorePairLBit, LDP_w);
  return static_cast<LoadStorePairOp>(StorePairOpFor(rt, rt2) |
                                      LoadStorePairLBit);
}

LoadStorePairOp Assembler::StorePairOpFor(const CPURegister& rt,
                                          const CPURegister& rt2) {
  DCHECK(AreSameSizeAndType(rt, rt2));
  USE(rt2);
  if (rt.IsRegister()) {
    return rt.Is64Bits() ? STP_x : STP_w;
  } else {
    DCHECK(rt.IsVRegister());
    switch (rt.SizeInBits()) {
      case kSRegSizeInBits:
        return STP_s;
      case kDRegSizeInBits:
        return STP_d;
      default:
        DCHECK(rt.IsQ());
        return STP_q;
    }
  }
}

LoadLiteralOp Assembler::LoadLiteralOpFor(const CPURegister& rt) {
  if (rt.IsRegister()) {
    return rt.Is64Bits() ? LDR_x_lit : LDR_w_lit;
  } else {
    DCHECK(rt.IsVRegister());
    return rt.Is64Bits() ? LDR_d_lit : LDR_s_lit;
  }
}

inline void Assembler::LoadStoreScaledImmOffset(Instr memop, int offset,
                                                unsigned size) {
  Emit(LoadStoreUnsignedOffsetFixed | memop | ImmLSUnsigned(offset >> size));
}

inline void Assembler::LoadStoreUnscaledImmOffset(Instr memop, int offset) {
  Emit(LoadStoreUnscaledOffsetFixed | memop | ImmLS(offset));
}

inline void Assembler::LoadStoreWRegOffset(Instr memop,
                                           const Register& regoffset) {
  Emit(LoadStoreRegisterOffsetFixed | memop | Rm(regoffset) | ExtendMode(UXTW));
}

inline void Assembler::DataProcPlainRegister(const Register& rd,
                                             const Register& rn,
                                             const Register& rm, Instr op) {
  DCHECK(AreSameSizeAndType(rd, rn, rm));
  Emit(SF(rd) | AddSubShiftedFixed | op | Rm(rm) | Rn(rn) | Rd(rd));
}

inline void Assembler::CmpPlainRegister(const Register& rn,
                                        const Register& rm) {
  DCHECK(AreSameSizeAndType(rn, rm));
  Emit(SF(rn) | AddSubShiftedFixed | SUB | Flags(SetFlags) | Rm(rm) | Rn(rn) |
       Rd(xzr));
}

inline void Assembler::DataProcImmediate(const Register& rd, const Register& rn,
                                         int immediate, Instr op) {
  DCHECK(AreSameSizeAndType(rd, rn));
  DCHECK(IsImmAddSub(immediate));
  Emit(SF(rd) | AddSubImmediateFixed | op | ImmAddSub(immediate) | RdSP(rd) |
       RnSP(rn));
}

int Assembler::LinkAndGetBranchInstructionOffsetTo(Label* label) {
  DCHECK_EQ(kStartOfLabelLinkChain, 0);
  int offset = LinkAndGetByteOffsetTo(label);
  DCHECK(IsAligned(offset, kInstrSize));
  if (label->is_linked() && (offset != kStartOfLabelLinkChain)) {
    branch_link_chain_back_edge_.emplace(
        std::pair<int, int>(pc_offset() + offset, pc_offset()));
  }
  return offset >> kInstrSizeLog2;
}

Instr Assembler::Flags(FlagsUpdate S) {
  if (S == SetFlags) {
    return 1 << FlagsUpdate_offset;
  } else if (S == LeaveFlags) {
    return 0 << FlagsUpdate_offset;
  }
  UNREACHABLE();
}

Instr Assembler::Cond(Condition cond) { return cond << Condition_offset; }

Instr Assembler::ImmPCRelAddress(int imm21) {
  Instr imm = static_cast<Instr>(checked_truncate_to_int21(imm21));
  Instr immhi = (imm >> ImmPCRelLo_width) << ImmPCRelHi_offset;
  Instr immlo = imm << ImmPCRelLo_offset;
  return (immhi & ImmPCRelHi_mask) | (immlo & ImmPCRelLo_mask);
}

Instr Assembler::ImmUncondBranch(int imm26) {
  return checked_truncate_to_int26(imm26) << ImmUncondBranch_offset;
}

Instr Assembler::ImmCondBranch(int imm19) {
  return checked_truncate_to_int19(imm19) << ImmCondBranch_offset;
}

Instr Assembler::ImmCmpBranch(int imm19) {
  return checked_truncate_to_int19(imm19) << ImmCmpBranch_offset;
}

Instr Assembler::ImmTestBranch(int imm14) {
  return checked_truncate_to_int14(imm14) << ImmTestBranch_offset;
}

Instr Assembler::ImmTestBranchBit(unsigned bit_pos) {
  DCHECK(is_uint6(bit_pos));
  // Subtract five from the shift offset, as we need bit 5 from bit_pos.
  unsigned b5 = bit_pos << (ImmTestBranchBit5_offset - 5);
  unsigned b40 = bit_pos << ImmTestBranchBit40_offset;
  b5 &= ImmTestBranchBit5_mask;
  b40 &= ImmTestBranchBit40_mask;
  return b5 | b40;
}

Instr Assembler::SF(Register rd) {
  return rd.Is64Bits() ? SixtyFourBits : ThirtyTwoBits;
}

Instr Assembler::ImmAddSub(int imm) {
  DCHECK(IsImmAddSub(imm));
  if (is_uint12(imm)) {  // No shift required.
    imm <<= ImmAddSub_offset;
  } else {
    imm = ((imm >> 12) << ImmAddSub_offset) | (1 << ShiftAddSub_offset);
  }
  return imm;
}

Instr Assembler::ImmS(unsigned imms, unsigned reg_size) {
  DCHECK(((reg_size == kXRegSizeInBits) && is_uint6(imms)) ||
         ((reg_size == kWRegSizeInBits) && is_uint5(imms)));
  USE(reg_size);
  return imms << ImmS_offset;
}

Instr Assembler::ImmR(unsigned immr, unsigned reg_size) {
  DCHECK(((reg_size == kXRegSizeInBits) && is_uint6(immr)) ||
         ((reg_size == kWRegSizeInBits) && is_uint5(immr)));
  USE(reg_size);
  DCHECK(is_uint6(immr));
  return immr << ImmR_offset;
}

Instr Assembler::ImmSetBits(unsigned imms, unsigned reg_size) {
  DCHECK((reg_size == kWRegSizeInBits) || (reg_size == kXRegSizeInBits));
  DCHECK(is_uint6(imms));
  DCHECK((reg_size == kXRegSizeInBits) || is_uint6(imms + 3));
  USE(reg_size);
  return imms << ImmSetBits_offset;
}

Instr Assembler::ImmRotate(unsigned immr, unsigned reg_size) {
  DCHECK((reg_size == kWRegSizeInBits) || (reg_size == kXRegSizeInBits));
  DCHECK(((reg_size == kXRegSizeInBits) && is_uint6(immr)) ||
         ((reg_size == kWRegSizeInBits) && is_uint5(immr)));
  USE(reg_size);
  return immr << ImmRotate_offset;
}

Instr Assembler::ImmLLiteral(int imm19) {
  return checked_truncate_to_int19(imm19) << ImmLLiteral_offset;
}

Instr Assembler::BitN(unsigned bitn, unsigned reg_size) {
  DCHECK((reg_size == kWRegSizeInBits) || (reg_size == kXRegSizeInBits));
  DCHECK((reg_size == kXRegSizeInBits) || (bitn == 0));
  USE(reg_size);
  return bitn << BitN_offset;
}

Instr Assembler::ShiftDP(Shift shift) {
  DCHECK(shift == LSL || shift == LSR || shift == ASR || shift == ROR);
  return shift << ShiftDP_offset;
}

Instr Assembler::ImmDPShift(unsigned amount) {
  DCHECK(is_uint6(amount));
  return amount << ImmDPShift_offset;
}

Instr Assembler::ExtendMode(Extend extend) {
  return extend << ExtendMode_offset;
}

Instr Assembler::ImmExtendShift(unsigned left_shift) {
  DCHECK_LE(left_shift,
```