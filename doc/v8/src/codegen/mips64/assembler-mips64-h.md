Response:
Let's break down the thought process for analyzing the provided C++ header file `assembler-mips64.h`.

**1. Initial Scan and High-Level Understanding:**

The first step is a quick skim of the file contents. Keywords like `Copyright`, `#ifndef`, `#define`, `#include`, `namespace`, `class`, `Operand`, `MemOperand`, `Assembler`, and various instruction mnemonics immediately jump out. This suggests:

* **Copyright and Licensing:** Standard open-source licensing information.
* **Header Guard:**  `#ifndef V8_CODEGEN_MIPS64_ASSEMBLER_MIPS64_H_` and `#define V8_CODEGEN_MIPS64_ASSEMBLER_MIPS64_H_` are a standard C++ practice to prevent multiple inclusions.
* **Includes:** The file relies on other V8 headers (`assembler.h`, `external-reference.h`, etc.) and standard C++ headers (`stdio.h`, `memory`, `set`). This tells us it's part of a larger system.
* **Namespaces:** The code belongs to the `v8::internal` namespace, indicating its internal nature within the V8 JavaScript engine.
* **Classes:**  The core of the file defines the `Operand`, `MemOperand`, and `Assembler` classes.
* **Instruction Mnemonics:**  A large number of functions with names like `addiu`, `beq`, `lw`, `sw`, `jal`, `mtc1`, etc., clearly represent MIPS64 assembly instructions.

**2. Focusing on Key Classes:**

* **`Operand`:**  This class seems to represent the different types of data that MIPS64 instructions can operate on. The constructors for immediate values, external references, Smi (Small Integer), and registers confirm this. The `is_reg()` and `immediate()` methods provide ways to query the operand type. The nested `Value` union suggests different ways the operand's value is stored.
* **`MemOperand`:** This class inherits from `Operand` and specifically represents memory addresses used in load and store instructions. The constructor taking a base register and an offset is typical for MIPS addressing modes.
* **`Assembler`:** This is the central class. Its purpose is to generate MIPS64 machine code. The constructor and `GetCode` method confirm this. The `bind` method and the various branch instruction functions (`b`, `beq`, `bal`, etc.) strongly indicate assembly code generation. The presence of `Label` suggests support for symbolic addressing.

**3. Inferring Functionality from Methods:**

By examining the method names in the `Assembler` class, we can infer its detailed functionalities:

* **Code Emission:** `GetCode`, `Align`, `DataAlign`, `CodeTargetAlign`, `nop`.
* **Label Management:** `bind`, `is_near`, `branch_offset`, `jump_address`, `label_at_put`.
* **Instruction Encoding:** The large number of methods corresponding to MIPS64 instructions (arithmetic, logical, memory access, control flow, floating-point).
* **Relocation:** The use of `RelocInfo::Mode` in the `Operand` class and mentions of patching target addresses suggest support for relocatable code.
* **Safepoints:** The `SafepointTableBuilder` class interaction hints at garbage collection support.

**4. Connecting to JavaScript (Conceptual):**

At this stage, we understand that this code is about generating low-level machine instructions. The connection to JavaScript is indirect but crucial:

* **V8's Compilation Pipeline:** V8 compiles JavaScript code into machine code for efficient execution. This `assembler-mips64.h` file is a component of that compilation process for the MIPS64 architecture.
* **Optimization:** The generated assembly code directly implements the semantics of JavaScript operations. For example, a JavaScript addition will likely translate into an `addiu` or `daddu` instruction.
* **Runtime Support:**  The assembler helps generate code that interacts with V8's runtime system (e.g., for object allocation, function calls, garbage collection).

**5. Considering the `.tq` Question:**

The prompt asks about the `.tq` extension. Knowing that Torque is V8's internal language for defining built-in functions, the conclusion that `.tq` indicates Torque source code is a reasonable inference based on the context of V8 and the filename.

**6. Identifying Potential Programming Errors:**

Based on the functionality, potential errors related to using this assembler include:

* **Incorrect Operand Types:** Passing a register when an immediate is expected, or vice versa.
* **Out-of-Range Offsets:** Using branch instructions with targets too far away.
* **Register Allocation Issues:**  Using the same register for multiple purposes without proper saving and restoring.
* **Incorrect Instruction Sequences:**  Generating sequences of instructions that don't achieve the desired result.
* **Memory Access Errors:**  Accessing invalid memory locations.

**7. Structuring the Output:**

Finally, the information needs to be organized into a clear and comprehensive summary, addressing each point in the prompt:

* **Functionality Listing:**  Categorize the functionalities (instruction encoding, label management, etc.).
* **`.tq` Explanation:** Define Torque and its role.
* **JavaScript Relationship:** Provide a high-level explanation and a simple illustrative example.
* **Code Logic/Hypothetical Input/Output:** While not strictly defining a function, illustrate how the assembler translates high-level concepts to low-level instructions.
* **Common Programming Errors:** List concrete examples.
* **Summary:** Briefly reiterate the main purpose of the file.

This detailed thought process, moving from a high-level overview to specific details and connections, allows for a thorough understanding of the `assembler-mips64.h` file and its role within the V8 JavaScript engine.
好的，让我们来分析一下 `v8/src/codegen/mips64/assembler-mips64.h` 这个文件的功能。

**核心功能归纳：**

`v8/src/codegen/mips64/assembler-mips64.h` 是 V8 JavaScript 引擎中用于为 MIPS64 架构生成机器码的关键头文件。它定义了 `Assembler` 类，该类提供了一系列方法，用于将高级指令（类似于汇编语言）转换为实际的 MIPS64 机器码。

**具体功能列表：**

1. **定义 MIPS64 指令的操作数类型 (`Operand` 和 `MemOperand`):**
   - `Operand` 类用于表示 MIPS64 指令可以操作的不同类型的数据，包括：
     - 立即数 (`immediate`)
     - 外部引用 (`ExternalReference`)
     - V8 的小整数 (`Smi`)
     - 堆对象句柄 (`Handle<HeapObject>`)
     - 寄存器 (`Register`)
   - `MemOperand` 类继承自 `Operand`，专门用于表示内存操作数，包含基址寄存器和偏移量。

2. **提供 `Assembler` 类用于生成 MIPS64 机器码:**
   - `Assembler` 类继承自 `AssemblerBase`，提供了一组方法来生成各种 MIPS64 指令。
   - 它负责管理代码缓冲区，将生成的机器码存储在其中。
   - 提供了绑定标签 (`Label`) 和生成跳转指令的方法，用于控制代码的执行流程。
   - 包含了大量与 MIPS64 指令集对应的成员函数，例如：
     - **分支和跳转指令:** `b`, `bal`, `beq`, `j`, `jalr` 等。
     - **数据处理指令:** `addu`, `subu`, `mul`, `div`, `and_`, `or_`, `sll`, `srl` 等。
     - **内存访问指令:** `lb`, `lbu`, `lw`, `sb`, `sh`, `sw`, `ld`, `sd` 等。
     - **原子操作指令:** `ll`, `sc`, `lld`, `scd` 等。
     - **浮点运算指令:** `add_s`, `add_d`, `mul_s`, `mul_d`, `cvt_w_s` 等 (通过 `FPURegister`)。
     - **其他指令:**  `nop`, `break_`, `sync`, `mfhi`, `mflo` 等。

3. **处理代码布局和对齐:**
   - 提供了 `Align`, `DataAlign`, `CodeTargetAlign`, `LoopHeaderAlign` 等方法，用于在代码中插入填充字节或指令，以确保代码按照特定的边界对齐，提高性能。

4. **支持代码重定位:**
   -  `RelocInfo::Mode` 枚举被用于 `Operand` 类，表明在生成机器码时需要记录重定位信息，以便在代码加载到内存后，可以正确地更新地址引用。

5. **与 V8 运行时环境交互:**
   -  涉及到 `ExternalReference`，表明生成的代码需要调用 V8 运行时的一些函数或访问全局变量。
   -  `SafepointTableBuilder` 类表明该文件与垃圾回收机制有关，生成的代码需要在安全点上暂停执行，以便垃圾回收器可以安全地进行操作。

**关于文件后缀 `.tq`：**

如果 `v8/src/codegen/mips64/assembler-mips64.h` 以 `.tq` 结尾，那么它就不是一个普通的 C++ 头文件了。`.tq` 是 V8 中 **Torque 语言** 的文件扩展名。Torque 是一种用于定义 V8 内部函数（特别是 built-in 函数）的领域特定语言。Torque 代码会被编译成 C++ 代码，然后进一步编译成机器码。

**与 JavaScript 的关系及 JavaScript 示例：**

`assembler-mips64.h` 中定义的 `Assembler` 类是 V8 将 JavaScript 代码编译成 MIPS64 机器码的直接工具。当 V8 执行 JavaScript 代码时，它会将 JavaScript 代码编译成高效的机器码。`Assembler` 类提供的各种指令生成方法，就对应着 JavaScript 中不同的操作。

**例如，考虑以下简单的 JavaScript 代码：**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 V8 编译 `add` 函数时，`Assembler` 类可能会被用来生成类似以下的 MIPS64 指令序列（这只是一个简化的示例，实际情况会更复杂）：

```assembly
// 假设参数 a 和 b 分别在寄存器 r0 和 r1 中
addu  r2, r0, r1   // 将 r0 和 r1 的值相加，结果存入 r2
move  v0, r2      // 将结果从 r2 移动到返回值寄存器 v0
jr    ra          // 返回
```

在 `assembler-mips64.h` 中，上述汇编指令 `addu` 和 `move` 就对应着 `Assembler` 类的成员函数 `addu(Register rd, Register rs, Register rt)` 和 `move(Register dest, Register source)`（或者类似的函数，实际可能使用宏或者更底层的指令）。

**代码逻辑推理及假设输入与输出：**

由于这是一个头文件，主要定义的是接口和类结构，而不是具体的代码逻辑。但是，我们可以推断 `Assembler` 类内部的逻辑：

**假设输入：** 调用 `assembler->addiu(t0, zero_reg, 5)` 和 `assembler->addiu(t1, zero_reg, 10)`，然后调用 `assembler->addu(t2, t0, t1)`。

**内部逻辑推断：**
1. `addiu(t0, zero_reg, 5)` 会生成一条将立即数 5 加到 `zero_reg` (值始终为 0) 并将结果存入寄存器 `t0` 的 MIPS64 指令的机器码。
2. `addiu(t1, zero_reg, 10)` 同理，生成一条将 10 加到 `zero_reg` 并存入 `t1` 的指令的机器码。
3. `addu(t2, t0, t1)` 会生成一条将寄存器 `t0` 和 `t1` 的值相加，并将结果存入寄存器 `t2` 的 MIPS64 指令的机器码。

**假设输出：** 缓冲区中会依次添加对应这些操作的 MIPS64 机器码字节序列。具体的字节序列取决于 MIPS64 的指令编码格式。

**用户常见的编程错误：**

在使用 `Assembler` 类时，常见的编程错误可能包括：

1. **使用错误的寄存器类型或数量：** 例如，在需要浮点寄存器的地方使用了通用寄存器，或者指令需要的寄存器数量不匹配。
2. **立即数超出范围：** 某些 MIPS64 指令对立即数的大小有限制，如果提供的立即数超出范围，会导致指令编码错误。
3. **跳转目标超出范围：** 分支指令的跳转偏移量是有限的，如果跳转目标过远，需要使用更长的跳转指令序列或临时跳转表。
4. **忘记处理分支延迟槽：** 在某些 MIPS 架构中（虽然 MIPS64 简化了这一点），分支指令后会有一个延迟槽，需要放置一条无论分支是否发生都会执行的指令。
5. **不正确的内存操作数：** 例如，计算内存地址时使用了错误的基址寄存器或偏移量，导致访问错误的内存位置。
6. **没有正确处理重定位信息：** 当涉及到外部引用或代码地址时，需要确保生成正确的重定位信息，以便在代码加载时可以被正确地修正。

**第 1 部分功能归纳：**

总而言之，`v8/src/codegen/mips64/assembler-mips64.h` 文件的核心功能是定义了用于生成 MIPS64 架构机器码的 `Assembler` 类及其相关的操作数类型。它是 V8 引擎将 JavaScript 代码转化为可在 MIPS64 处理器上执行的机器码的关键组成部分。它提供了操作 MIPS64 指令集所需的各种方法，并处理代码布局和重定位等底层细节。如果文件以 `.tq` 结尾，则表明它是用 Torque 语言编写的，用于定义 V8 的内部函数。

### 提示词
```
这是目录为v8/src/codegen/mips64/assembler-mips64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/assembler-mips64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
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

#ifndef V8_CODEGEN_MIPS64_ASSEMBLER_MIPS64_H_
#define V8_CODEGEN_MIPS64_ASSEMBLER_MIPS64_H_

#include <stdio.h>

#include <memory>
#include <set>

#include "src/codegen/assembler.h"
#include "src/codegen/external-reference.h"
#include "src/codegen/label.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/mips64/constants-mips64.h"
#include "src/codegen/mips64/register-mips64.h"
#include "src/objects/contexts.h"
#include "src/objects/smi.h"

namespace v8 {
namespace internal {

class SafepointTableBuilder;

// -----------------------------------------------------------------------------
// Machine instruction Operands.
constexpr int kSmiShift = kSmiTagSize + kSmiShiftSize;
constexpr uint64_t kSmiShiftMask = (1UL << kSmiShift) - 1;
// Class Operand represents a shifter operand in data processing instructions.
class Operand {
 public:
  // Immediate.
  V8_INLINE explicit Operand(int64_t immediate,
                             RelocInfo::Mode rmode = RelocInfo::NO_INFO)
      : rm_(no_reg), rmode_(rmode) {
    value_.immediate = immediate;
  }
  V8_INLINE explicit Operand(const ExternalReference& f)
      : rm_(no_reg), rmode_(RelocInfo::EXTERNAL_REFERENCE) {
    value_.immediate = static_cast<int64_t>(f.address());
  }
  V8_INLINE explicit Operand(Tagged<Smi> value)
      : Operand(static_cast<intptr_t>(value.ptr())) {}

  explicit Operand(Handle<HeapObject> handle);

  static Operand EmbeddedNumber(double number);  // Smi or HeapNumber.

  // Register.
  V8_INLINE explicit Operand(Register rm) : rm_(rm) {}

  // Return true if this is a register operand.
  V8_INLINE bool is_reg() const;

  inline int64_t immediate() const;

  bool IsImmediate() const { return !rm_.is_valid(); }

  HeapNumberRequest heap_number_request() const {
    DCHECK(IsHeapNumberRequest());
    return value_.heap_number_request;
  }

  bool IsHeapNumberRequest() const {
    DCHECK_IMPLIES(is_heap_number_request_, IsImmediate());
    DCHECK_IMPLIES(is_heap_number_request_,
                   rmode_ == RelocInfo::FULL_EMBEDDED_OBJECT ||
                       rmode_ == RelocInfo::CODE_TARGET);
    return is_heap_number_request_;
  }

  Register rm() const { return rm_; }

  RelocInfo::Mode rmode() const { return rmode_; }

 private:
  Register rm_;
  union Value {
    Value() {}
    HeapNumberRequest heap_number_request;  // if is_heap_number_request_
    int64_t immediate;                      // otherwise
  } value_;                                 // valid if rm_ == no_reg
  bool is_heap_number_request_ = false;
  RelocInfo::Mode rmode_;

  friend class Assembler;
  friend class MacroAssembler;
};

// On MIPS we have only one addressing mode with base_reg + offset.
// Class MemOperand represents a memory operand in load and store instructions.
class V8_EXPORT_PRIVATE  MemOperand : public Operand {
 public:
  // Immediate value attached to offset.
  enum OffsetAddend { offset_minus_one = -1, offset_zero = 0 };

  explicit MemOperand(Register rn, int32_t offset = 0);
  explicit MemOperand(Register rn, int32_t unit, int32_t multiplier,
                      OffsetAddend offset_addend = offset_zero);
  int32_t offset() const { return offset_; }

  bool OffsetIsInt16Encodable() const { return is_int16(offset_); }

 private:
  int32_t offset_;

  friend class Assembler;
};

class V8_EXPORT_PRIVATE Assembler : public AssemblerBase {
 public:
  // Create an assembler. Instructions and relocation information are emitted
  // into a buffer, with the instructions starting from the beginning and the
  // relocation information starting from the end of the buffer. See CodeDesc
  // for a detailed comment on the layout (globals.h).
  //
  // If the provided buffer is nullptr, the assembler allocates and grows its
  // own buffer. Otherwise it takes ownership of the provided buffer.
  explicit Assembler(const AssemblerOptions&,
                     std::unique_ptr<AssemblerBuffer> = {});
  // For compatibility with assemblers that require a zone.
  Assembler(const MaybeAssemblerZone&, const AssemblerOptions& options,
            std::unique_ptr<AssemblerBuffer> buffer = {})
      : Assembler(options, std::move(buffer)) {}

  virtual ~Assembler() {}

  // GetCode emits any pending (non-emitted) code and fills the descriptor desc.
  static constexpr int kNoHandlerTable = 0;
  static constexpr SafepointTableBuilderBase* kNoSafepointTable = nullptr;
  void GetCode(LocalIsolate* isolate, CodeDesc* desc,
               SafepointTableBuilderBase* safepoint_table_builder,
               int handler_table_offset);

  // Convenience wrapper for allocating with an Isolate.
  void GetCode(Isolate* isolate, CodeDesc* desc);
  // Convenience wrapper for code without safepoint or handler tables.
  void GetCode(LocalIsolate* isolate, CodeDesc* desc) {
    GetCode(isolate, desc, kNoSafepointTable, kNoHandlerTable);
  }

  // Unused on this architecture.
  void MaybeEmitOutOfLineConstantPool() {}

  // Mips uses BlockTrampolinePool to prevent generating trampoline inside a
  // continuous instruction block. For Call instruction, it prevents generating
  // trampoline between jalr and delay slot instruction. In the destructor of
  // BlockTrampolinePool, it must check if it needs to generate trampoline
  // immediately, if it does not do this, the branch range will go beyond the
  // max branch offset, that means the pc_offset after call CheckTrampolinePool
  // may have changed. So we use pc_for_safepoint_ here for safepoint record.
  int pc_offset_for_safepoint() {
    return static_cast<int>(pc_for_safepoint_ - buffer_start_);
  }

  // Label operations & relative jumps (PPUM Appendix D).
  //
  // Takes a branch opcode (cc) and a label (L) and generates
  // either a backward branch or a forward branch and links it
  // to the label fixup chain. Usage:
  //
  // Label L;    // unbound label
  // j(cc, &L);  // forward branch to unbound label
  // bind(&L);   // bind label to the current pc
  // j(cc, &L);  // backward branch to bound label
  // bind(&L);   // illegal: a label may be bound only once
  //
  // Note: The same Label can be used for forward and backward branches
  // but it may be bound only once.
  void bind(Label* L);  // Binds an unbound label L to current code position.

  enum OffsetSize : int { kOffset26 = 26, kOffset21 = 21, kOffset16 = 16 };

  // Determines if Label is bound and near enough so that branch instruction
  // can be used to reach it, instead of jump instruction.
  bool is_near(Label* L);
  bool is_near(Label* L, OffsetSize bits);
  bool is_near_branch(Label* L);
  inline bool is_near_pre_r6(Label* L) {
    DCHECK(!(kArchVariant == kMips64r6));
    return pc_offset() - L->pos() < kMaxBranchOffset - 4 * kInstrSize;
  }
  inline bool is_near_r6(Label* L) {
    DCHECK_EQ(kArchVariant, kMips64r6);
    return pc_offset() - L->pos() < kMaxCompactBranchOffset - 4 * kInstrSize;
  }

  int BranchOffset(Instr instr);

  // Returns the branch offset to the given label from the current code
  // position. Links the label to the current position if it is still unbound.
  // Manages the jump elimination optimization if the second parameter is true.
  int32_t branch_offset_helper(Label* L, OffsetSize bits);
  inline int32_t branch_offset(Label* L) {
    return branch_offset_helper(L, OffsetSize::kOffset16);
  }
  inline int32_t branch_offset21(Label* L) {
    return branch_offset_helper(L, OffsetSize::kOffset21);
  }
  inline int32_t branch_offset26(Label* L) {
    return branch_offset_helper(L, OffsetSize::kOffset26);
  }
  inline int32_t shifted_branch_offset(Label* L) {
    return branch_offset(L) >> 2;
  }
  inline int32_t shifted_branch_offset21(Label* L) {
    return branch_offset21(L) >> 2;
  }
  inline int32_t shifted_branch_offset26(Label* L) {
    return branch_offset26(L) >> 2;
  }
  uint64_t jump_address(Label* L);
  uint64_t jump_offset(Label* L);
  uint64_t branch_long_offset(Label* L);

  // Puts a labels target address at the given position.
  // The high 8 bits are set to zero.
  void label_at_put(Label* L, int at_offset);

  // Read/Modify the code target address in the branch/call instruction at pc.
  // The isolate argument is unused (and may be nullptr) when skipping flushing.
  static Address target_address_at(Address pc);
  V8_INLINE static void set_target_address_at(
      Address pc, Address target, WritableJitAllocation* jit_allocation,
      ICacheFlushMode icache_flush_mode = FLUSH_ICACHE_IF_NEEDED) {
    set_target_value_at(pc, target, jit_allocation, icache_flush_mode);
  }
  // On MIPS there is no Constant Pool so we skip that parameter.
  V8_INLINE static Address target_address_at(Address pc,
                                             Address constant_pool) {
    return target_address_at(pc);
  }
  V8_INLINE static void set_target_address_at(
      Address pc, Address constant_pool, Address target,
      WritableJitAllocation* jit_allocation,
      ICacheFlushMode icache_flush_mode = FLUSH_ICACHE_IF_NEEDED) {
    set_target_address_at(pc, target, jit_allocation, icache_flush_mode);
  }

  static void set_target_value_at(
      Address pc, uint64_t target,
      WritableJitAllocation* jit_allocation = nullptr,
      ICacheFlushMode icache_flush_mode = FLUSH_ICACHE_IF_NEEDED);

  static void JumpLabelToJumpRegister(Address pc);

  // Get the size of the special target encoded at 'instruction_payload'.
  inline static int deserialization_special_target_size(
      Address instruction_payload);

  // This sets the internal reference at the pc.
  inline static void deserialization_set_target_internal_reference_at(
      Address pc, Address target,
      RelocInfo::Mode mode = RelocInfo::INTERNAL_REFERENCE);

  // Read/modify the uint32 constant used at pc.
  static inline uint32_t uint32_constant_at(Address pc, Address constant_pool);
  static inline void set_uint32_constant_at(
      Address pc, Address constant_pool, uint32_t new_constant,
      WritableJitAllocation* jit_allocation,
      ICacheFlushMode icache_flush_mode = FLUSH_ICACHE_IF_NEEDED);

  // Difference between address of current opcode and target address offset.
  static constexpr int kBranchPCOffset = kInstrSize;

  // Difference between address of current opcode and target address offset,
  // when we are generatinga sequence of instructions for long relative PC
  // branches
  static constexpr int kLongBranchPCOffset = 3 * kInstrSize;

  // Adjust ra register in branch delay slot of bal instruction so to skip
  // instructions not needed after optimization of PIC in
  // MacroAssembler::BranchAndLink method.

  static constexpr int kOptimizedBranchAndLinkLongReturnOffset = 4 * kInstrSize;

  // Here we are patching the address in the LUI/ORI instruction pair.
  // These values are used in the serialization process and must be zero for
  // MIPS platform, as InstructionStream, Embedded Object or External-reference
  // pointers are split across two consecutive instructions and don't exist
  // separately in the code, so the serializer should not step forwards in
  // memory after a target is resolved and written.
  static constexpr int kSpecialTargetSize = 0;

  // Number of consecutive instructions used to store 32bit/64bit constant.
  // This constant was used in RelocInfo::target_address_address() function
  // to tell serializer address of the instruction that follows
  // LUI/ORI instruction pair.
  static constexpr int kInstructionsFor32BitConstant = 2;
  static constexpr int kInstructionsFor64BitConstant = 4;

  // Difference between address of current opcode and value read from pc
  // register.
  static constexpr int kPcLoadDelta = 4;

  // Max offset for instructions with 16-bit offset field
  static constexpr int kMaxBranchOffset = (1 << (18 - 1)) - 1;

  // Max offset for compact branch instructions with 26-bit offset field
  static constexpr int kMaxCompactBranchOffset = (1 << (28 - 1)) - 1;

  static constexpr int kTrampolineSlotsSize =
      kArchVariant == kMips64r6 ? 2 * kInstrSize : 7 * kInstrSize;

  RegList* GetScratchRegisterList() { return &scratch_register_list_; }

  // ---------------------------------------------------------------------------
  // InstructionStream generation.

  // Insert the smallest number of nop instructions
  // possible to align the pc offset to a multiple
  // of m. m must be a power of 2 (>= 4).
  void Align(int m);
  // Insert the smallest number of zero bytes possible to align the pc offset
  // to a mulitple of m. m must be a power of 2 (>= 2).
  void DataAlign(int m);
  // Aligns code to something that's optimal for a jump target for the platform.
  void CodeTargetAlign();
  void LoopHeaderAlign() { CodeTargetAlign(); }

  // Different nop operations are used by the code generator to detect certain
  // states of the generated code.
  enum NopMarkerTypes {
    NON_MARKING_NOP = 0,
    DEBUG_BREAK_NOP,
    // IC markers.
    PROPERTY_ACCESS_INLINED,
    PROPERTY_ACCESS_INLINED_CONTEXT,
    PROPERTY_ACCESS_INLINED_CONTEXT_DONT_DELETE,
    // Helper values.
    LAST_CODE_MARKER,
    FIRST_IC_MARKER = PROPERTY_ACCESS_INLINED,
  };

  // Type == 0 is the default non-marking nop. For mips this is a
  // sll(zero_reg, zero_reg, 0). We use rt_reg == at for non-zero
  // marking, to avoid conflict with ssnop and ehb instructions.
  void nop(unsigned int type = 0) {
    DCHECK_LT(type, 32);
    Register nop_rt_reg = (type == 0) ? zero_reg : at;
    sll(zero_reg, nop_rt_reg, type, true);
  }

  // --------Branch-and-jump-instructions----------
  // We don't use likely variant of instructions.
  void b(int16_t offset);
  inline void b(Label* L) { b(shifted_branch_offset(L)); }
  void bal(int16_t offset);
  inline void bal(Label* L) { bal(shifted_branch_offset(L)); }
  void bc(int32_t offset);
  inline void bc(Label* L) { bc(shifted_branch_offset26(L)); }
  void balc(int32_t offset);
  inline void balc(Label* L) { balc(shifted_branch_offset26(L)); }

  void beq(Register rs, Register rt, int16_t offset);
  inline void beq(Register rs, Register rt, Label* L) {
    beq(rs, rt, shifted_branch_offset(L));
  }
  void bgez(Register rs, int16_t offset);
  void bgezc(Register rt, int16_t offset);
  inline void bgezc(Register rt, Label* L) {
    bgezc(rt, shifted_branch_offset(L));
  }
  void bgeuc(Register rs, Register rt, int16_t offset);
  inline void bgeuc(Register rs, Register rt, Label* L) {
    bgeuc(rs, rt, shifted_branch_offset(L));
  }
  void bgec(Register rs, Register rt, int16_t offset);
  inline void bgec(Register rs, Register rt, Label* L) {
    bgec(rs, rt, shifted_branch_offset(L));
  }
  void bgezal(Register rs, int16_t offset);
  void bgezalc(Register rt, int16_t offset);
  inline void bgezalc(Register rt, Label* L) {
    bgezalc(rt, shifted_branch_offset(L));
  }
  void bgezall(Register rs, int16_t offset);
  inline void bgezall(Register rs, Label* L) {
    bgezall(rs, branch_offset(L) >> 2);
  }
  void bgtz(Register rs, int16_t offset);
  void bgtzc(Register rt, int16_t offset);
  inline void bgtzc(Register rt, Label* L) {
    bgtzc(rt, shifted_branch_offset(L));
  }
  void blez(Register rs, int16_t offset);
  void blezc(Register rt, int16_t offset);
  inline void blezc(Register rt, Label* L) {
    blezc(rt, shifted_branch_offset(L));
  }
  void bltz(Register rs, int16_t offset);
  void bltzc(Register rt, int16_t offset);
  inline void bltzc(Register rt, Label* L) {
    bltzc(rt, shifted_branch_offset(L));
  }
  void bltuc(Register rs, Register rt, int16_t offset);
  inline void bltuc(Register rs, Register rt, Label* L) {
    bltuc(rs, rt, shifted_branch_offset(L));
  }
  void bltc(Register rs, Register rt, int16_t offset);
  inline void bltc(Register rs, Register rt, Label* L) {
    bltc(rs, rt, shifted_branch_offset(L));
  }
  void bltzal(Register rs, int16_t offset);
  void nal() { bltzal(zero_reg, 0); }
  void blezalc(Register rt, int16_t offset);
  inline void blezalc(Register rt, Label* L) {
    blezalc(rt, shifted_branch_offset(L));
  }
  void bltzalc(Register rt, int16_t offset);
  inline void bltzalc(Register rt, Label* L) {
    bltzalc(rt, shifted_branch_offset(L));
  }
  void bgtzalc(Register rt, int16_t offset);
  inline void bgtzalc(Register rt, Label* L) {
    bgtzalc(rt, shifted_branch_offset(L));
  }
  void beqzalc(Register rt, int16_t offset);
  inline void beqzalc(Register rt, Label* L) {
    beqzalc(rt, shifted_branch_offset(L));
  }
  void beqc(Register rs, Register rt, int16_t offset);
  inline void beqc(Register rs, Register rt, Label* L) {
    beqc(rs, rt, shifted_branch_offset(L));
  }
  void beqzc(Register rs, int32_t offset);
  inline void beqzc(Register rs, Label* L) {
    beqzc(rs, shifted_branch_offset21(L));
  }
  void bnezalc(Register rt, int16_t offset);
  inline void bnezalc(Register rt, Label* L) {
    bnezalc(rt, shifted_branch_offset(L));
  }
  void bnec(Register rs, Register rt, int16_t offset);
  inline void bnec(Register rs, Register rt, Label* L) {
    bnec(rs, rt, shifted_branch_offset(L));
  }
  void bnezc(Register rt, int32_t offset);
  inline void bnezc(Register rt, Label* L) {
    bnezc(rt, shifted_branch_offset21(L));
  }
  void bne(Register rs, Register rt, int16_t offset);
  inline void bne(Register rs, Register rt, Label* L) {
    bne(rs, rt, shifted_branch_offset(L));
  }
  void bovc(Register rs, Register rt, int16_t offset);
  inline void bovc(Register rs, Register rt, Label* L) {
    bovc(rs, rt, shifted_branch_offset(L));
  }
  void bnvc(Register rs, Register rt, int16_t offset);
  inline void bnvc(Register rs, Register rt, Label* L) {
    bnvc(rs, rt, shifted_branch_offset(L));
  }

  // Never use the int16_t b(l)cond version with a branch offset
  // instead of using the Label* version.

  void jalr(Register rs, Register rd = ra);
  void jr(Register target);
  void jic(Register rt, int16_t offset);
  void jialc(Register rt, int16_t offset);

  // Following instructions are deprecated and require 256 MB
  // code alignment. Use PC-relative instructions instead.
  void j(int64_t target);
  void jal(int64_t target);
  void j(Label* target);
  void jal(Label* target);

  // -------Data-processing-instructions---------

  // Arithmetic.
  void addu(Register rd, Register rs, Register rt);
  void subu(Register rd, Register rs, Register rt);

  void div(Register rs, Register rt);
  void divu(Register rs, Register rt);
  void ddiv(Register rs, Register rt);
  void ddivu(Register rs, Register rt);
  void div(Register rd, Register rs, Register rt);
  void divu(Register rd, Register rs, Register rt);
  void ddiv(Register rd, Register rs, Register rt);
  void ddivu(Register rd, Register rs, Register rt);
  void mod(Register rd, Register rs, Register rt);
  void modu(Register rd, Register rs, Register rt);
  void dmod(Register rd, Register rs, Register rt);
  void dmodu(Register rd, Register rs, Register rt);

  void mul(Register rd, Register rs, Register rt);
  void muh(Register rd, Register rs, Register rt);
  void mulu(Register rd, Register rs, Register rt);
  void muhu(Register rd, Register rs, Register rt);
  void mult(Register rs, Register rt);
  void multu(Register rs, Register rt);
  void dmul(Register rd, Register rs, Register rt);
  void dmuh(Register rd, Register rs, Register rt);
  void dmulu(Register rd, Register rs, Register rt);
  void dmuhu(Register rd, Register rs, Register rt);
  void daddu(Register rd, Register rs, Register rt);
  void dsubu(Register rd, Register rs, Register rt);
  void dmult(Register rs, Register rt);
  void dmultu(Register rs, Register rt);

  void addiu(Register rd, Register rs, int32_t j);
  void daddiu(Register rd, Register rs, int32_t j);

  // Logical.
  void and_(Register rd, Register rs, Register rt);
  void or_(Register rd, Register rs, Register rt);
  void xor_(Register rd, Register rs, Register rt);
  void nor(Register rd, Register rs, Register rt);

  void andi(Register rd, Register rs, int32_t j);
  void ori(Register rd, Register rs, int32_t j);
  void xori(Register rd, Register rs, int32_t j);
  void lui(Register rd, int32_t j);
  void aui(Register rt, Register rs, int32_t j);
  void daui(Register rt, Register rs, int32_t j);
  void dahi(Register rs, int32_t j);
  void dati(Register rs, int32_t j);

  // Shifts.
  // Please note: sll(zero_reg, zero_reg, x) instructions are reserved as nop
  // and may cause problems in normal code. coming_from_nop makes sure this
  // doesn't happen.
  void sll(Register rd, Register rt, uint16_t sa, bool coming_from_nop = false);
  void sllv(Register rd, Register rt, Register rs);
  void srl(Register rd, Register rt, uint16_t sa);
  void srlv(Register rd, Register rt, Register rs);
  void sra(Register rt, Register rd, uint16_t sa);
  void srav(Register rt, Register rd, Register rs);
  void rotr(Register rd, Register rt, uint16_t sa);
  void rotrv(Register rd, Register rt, Register rs);
  void dsll(Register rd, Register rt, uint16_t sa);
  void dsllv(Register rd, Register rt, Register rs);
  void dsrl(Register rd, Register rt, uint16_t sa);
  void dsrlv(Register rd, Register rt, Register rs);
  void drotr(Register rd, Register rt, uint16_t sa);
  void drotr32(Register rd, Register rt, uint16_t sa);
  void drotrv(Register rd, Register rt, Register rs);
  void dsra(Register rt, Register rd, uint16_t sa);
  void dsrav(Register rd, Register rt, Register rs);
  void dsll32(Register rt, Register rd, uint16_t sa);
  void dsrl32(Register rt, Register rd, uint16_t sa);
  void dsra32(Register rt, Register rd, uint16_t sa);

  // ------------Memory-instructions-------------

  void lb(Register rd, const MemOperand& rs);
  void lbu(Register rd, const MemOperand& rs);
  void lh(Register rd, const MemOperand& rs);
  void lhu(Register rd, const MemOperand& rs);
  void lw(Register rd, const MemOperand& rs);
  void lwu(Register rd, const MemOperand& rs);
  void lwl(Register rd, const MemOperand& rs);
  void lwr(Register rd, const MemOperand& rs);
  void sb(Register rd, const MemOperand& rs);
  void sh(Register rd, const MemOperand& rs);
  void sw(Register rd, const MemOperand& rs);
  void swl(Register rd, const MemOperand& rs);
  void swr(Register rd, const MemOperand& rs);
  void ldl(Register rd, const MemOperand& rs);
  void ldr(Register rd, const MemOperand& rs);
  void sdl(Register rd, const MemOperand& rs);
  void sdr(Register rd, const MemOperand& rs);
  void ld(Register rd, const MemOperand& rs);
  void sd(Register rd, const MemOperand& rs);

  // ----------Atomic instructions--------------

  void ll(Register rd, const MemOperand& rs);
  void sc(Register rd, const MemOperand& rs);
  void lld(Register rd, const MemOperand& rs);
  void scd(Register rd, const MemOperand& rs);

  // ---------PC-Relative-instructions-----------

  void addiupc(Register rs, int32_t imm19);
  void lwpc(Register rs, int32_t offset19);
  void lwupc(Register rs, int32_t offset19);
  void ldpc(Register rs, int32_t offset18);
  void auipc(Register rs, int16_t imm16);
  void aluipc(Register rs, int16_t imm16);

  // ----------------Prefetch--------------------

  void pref(int32_t hint, const MemOperand& rs);

  // -------------Misc-instructions--------------

  // Break / Trap instructions.
  void break_(uint32_t code, bool break_as_stop = false);
  void stop(uint32_t code = kMaxStopCode);
  void tge(Register rs, Register rt, uint16_t code);
  void tgeu(Register rs, Register rt, uint16_t code);
  void tlt(Register rs, Register rt, uint16_t code);
  void tltu(Register rs, Register rt, uint16_t code);
  void teq(Register rs, Register rt, uint16_t code);
  void tne(Register rs, Register rt, uint16_t code);

  // Memory barrier instruction.
  void sync();

  // Move from HI/LO register.
  void mfhi(Register rd);
  void mflo(Register rd);

  // Set on less than.
  void slt(Register rd, Register rs, Register rt);
  void sltu(Register rd, Register rs, Register rt);
  void slti(Register rd, Register rs, int32_t j);
  void sltiu(Register rd, Register rs, int32_t j);

  // Conditional move.
  void movz(Register rd, Register rs, Register rt);
  void movn(Register rd, Register rs, Register rt);
  void movt(Register rd, Register rs, uint16_t cc = 0);
  void movf(Register rd, Register rs, uint16_t cc = 0);

  void sel(SecondaryField fmt, FPURegister fd, FPURegister fs, FPURegister ft);
  void sel_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void sel_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void seleqz(Register rd, Register rs, Register rt);
  void seleqz(SecondaryField fmt, FPURegister fd, FPURegister fs,
              FPURegister ft);
  void selnez(Register rs, Register rt, Register rd);
  void selnez(SecondaryField fmt, FPURegister fd, FPURegister fs,
              FPURegister ft);
  void seleqz_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void seleqz_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void selnez_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void selnez_s(FPURegister fd, FPURegister fs, FPURegister ft);

  void movz_s(FPURegister fd, FPURegister fs, Register rt);
  void movz_d(FPURegister fd, FPURegister fs, Register rt);
  void movt_s(FPURegister fd, FPURegister fs, uint16_t cc = 0);
  void movt_d(FPURegister fd, FPURegister fs, uint16_t cc = 0);
  void movf_s(FPURegister fd, FPURegister fs, uint16_t cc = 0);
  void movf_d(FPURegister fd, FPURegister fs, uint16_t cc = 0);
  void movn_s(FPURegister fd, FPURegister fs, Register rt);
  void movn_d(FPURegister fd, FPURegister fs, Register rt);
  // Bit twiddling.
  void clz(Register rd, Register rs);
  void dclz(Register rd, Register rs);
  void ins_(Register rt, Register rs, uint16_t pos, uint16_t size);
  void ext_(Register rt, Register rs, uint16_t pos, uint16_t size);
  void dext_(Register rt, Register rs, uint16_t pos, uint16_t size);
  void dextm_(Register rt, Register rs, uint16_t pos, uint16_t size);
  void dextu_(Register rt, Register rs, uint16_t pos, uint16_t size);
  void dins_(Register rt, Register rs, uint16_t pos, uint16_t size);
  void dinsm_(Register rt, Register rs, uint16_t pos, uint16_t size);
  void dinsu_(Register rt, Register rs, uint16_t pos, uint16_t size);
  void bitswap(Register rd, Register rt);
  void dbitswap(Register rd, Register rt);
  void align(Register rd, Register rs, Register rt, uint8_t bp);
  void dalign(Register rd, Register rs, Register rt, uint8_t bp);

  void wsbh(Register rd, Register rt);
  void dsbh(Register rd, Register rt);
  void dshd(Register rd, Register rt);
  void seh(Register rd, Register rt);
  void seb(Register rd, Register rt);

  // --------Coprocessor-instructions----------------

  // Load, store, and move.
  void lwc1(FPURegister fd, const MemOperand& src);
  void ldc1(FPURegister fd, const MemOperand& src);

  void swc1(FPURegister fs, const MemOperand& dst);
  void sdc1(FPURegister fs, const MemOperand& dst);

  void mtc1(Register rt, FPURegister fs);
  void mthc1(Register rt, FPURegister fs);
  void dmtc1(Register rt, FPURegister fs);

  void mfc1(Register rt, FPURegister fs);
  void mfhc1(Register rt, FPURegister fs);
  void dmfc1(Register rt, FPURegister fs);

  void ctc1(Register rt, FPUControlRegister fs);
  void cfc1(Register rt, FPUControlRegister fs);

  // Arithmetic.
  void add_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void add_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void sub_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void sub_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void mul_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void mul_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void madd_s(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft);
  void madd_d(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft);
  void msub_s(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft);
  void msub_d(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft);
  void maddf_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void maddf_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void msubf_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void msubf_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void div_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void div_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void abs_s(FPURegister fd, FPURegister fs);
  void abs_d(FPURegister fd, FPURegister fs);
  void mov_d(FPURegister fd, FPURegister fs);
  void mov_s(FPURegister fd, FPURegister fs);
  void neg_s(FPURegister fd, FPURegister fs);
  void neg_d(FPURegister fd, FPURegister fs);
  void sqrt_s(FPURegister fd, FPURegister fs);
  void sqrt_d(FPURegister fd, FPURegister fs);
  void rsqrt_s(FPURegister fd, FPURegister fs);
  void rsqrt_d(FPURegister fd, FPURegister fs);
  void recip_d(FPURegister fd, FPURegister fs);
  void recip_s(FPURegister fd, FPURegister fs);

  // Conversion.
  void cvt_w_s(FPURegister fd, FPURegister fs);
  void cvt_w_d(FPURegister fd, FPURegister fs);
  void trunc_w_s(FPURegister fd, FPURegister fs);
  void trunc_w_d(FPURegister fd, FPURegister fs);
  void round_w_s(FPURegister fd, FPURegister fs);
  void round_w_d(FPURegister fd, FPURegister fs);
  void floor_w_s(FPURegister fd, FPURegister fs);
  void floor_w_d(FPURegister fd, FPURegister fs);
  void ceil_w_s(FPURegister fd, FPURegister fs);
  void ceil_w_d(FPURegister fd, FPURegister fs);
  void rint_s(FPURegister fd, FPURegister fs);
  void rint_d(FPURegister fd, FPURegister fs);
  void rint(SecondaryField fmt, FPURegister fd, FPURegister fs);

  void cvt_l_s(FPURegister fd, FPURegister fs);
  void cvt_l_d(FPURegister fd, FPURegister fs);
  void trunc_l_s(FPURegister fd, FPURegister fs);
  void trunc_l_d(FPURegister fd, FPURegister fs);
  void round_l_s(FPURegister fd, FPURegister fs);
  void round_l_d(FPURegister fd, FPURegister fs);
  void floor_l_s(FPURegister fd, FPURegister fs);
  void floor_l_d(FPURegister fd, FPURegister fs);
  void ceil_l_s(FPURegister fd, FPURegister fs);
  void ceil_l_d(FPURegister fd, FPURegister fs);

  void class_s(FPURegister fd, FPURegister fs);
  void class_d(FPURegister fd, FPURegister fs);

  void min(SecondaryField fmt, FPURegister fd, FPURegister fs, FPURegister ft);
  void mina(SecondaryField fmt, FPURegister fd, FPURegister fs, FPURegister ft);
  void max(SecondaryField fmt, FPURegister fd, FPURegister fs, FPURegister ft);
  void maxa(SecondaryField fmt, FPURegister fd, FPURegister fs, FPURegister ft);
  void min_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void min_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void max_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void max_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void mina_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void mina_d(FPURegister fd, FPURegister fs, FPURegister ft);
  void maxa_s(FPURegister fd, FPURegister fs, FPURegister ft);
  void maxa_d(FPURegister fd, FPURegister fs, FPURegister ft);

  void cvt_s_w(FPURegister fd, FPURegister fs);
  void cvt_s_l(FPURegister fd, FPURegister fs);
  void cvt_s_d(FPURegister fd, FPURegister fs);

  void
```