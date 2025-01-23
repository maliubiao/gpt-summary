Response:
The user wants a summary of the functionality of the provided C++ header file.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the File Type and Purpose:** The filename `assembler-loong64.h` and the directory `v8/src/codegen/loong64` strongly suggest this file defines an assembler for the LoongArch64 architecture within the V8 JavaScript engine. The `.h` extension confirms it's a header file, likely containing class declarations and inline function definitions.

2. **Scan the Header Guards:** The `#ifndef V8_CODEGEN_LOONG64_ASSEMBLER_LOONG64_H_` and `#define V8_CODEGEN_LOONG64_ASSEMBLER_LOONG64_H_` indicate standard header guards to prevent multiple inclusions.

3. **Identify Key Includes:** The included headers provide crucial context:
    * `<stdio.h>`: Standard input/output (likely for debugging or assertions).
    * `<memory>`: Smart pointers (like `std::unique_ptr`).
    * `<set>`:  Potentially used for managing labels or other data.
    * `"src/codegen/assembler.h"`: This is a base class, indicating inheritance.
    * `"src/codegen/external-reference.h"`:  Dealing with references to code or data outside the current code being generated.
    * `"src/codegen/label.h"`:  For managing code labels for branching.
    * `"src/codegen/loong64/constants-loong64.h"`: Architecture-specific constants.
    * `"src/codegen/loong64/register-loong64.h"`:  Definitions of LoongArch64 registers.
    * `"src/codegen/machine-type.h"`:  Information about data types.
    * `"src/objects/contexts.h"` and `"src/objects/smi.h"`: V8 object system components, likely for handling JavaScript values.

4. **Analyze Class Declarations:** The core of the file revolves around the `Operand`, `MemOperand`, and `Assembler` classes.

    * **`Operand`:** Represents operands for machine instructions (registers, immediate values, external references, Smi values, and heap object handles). It includes methods to check the operand type.

    * **`MemOperand`:** Represents memory operands for load/store instructions, specifying a base register and an optional offset (immediate or register).

    * **`Assembler`:**  This is the central class. It inherits from `AssemblerBase` and provides methods for:
        * **Initialization:** Constructors for buffer management.
        * **Code Emission:**  `GetCode` to finalize and retrieve generated code.
        * **Label Management:**  `bind`, `is_near_c`, `is_near`, `branch_offset`, `jump_address`, etc., for managing code flow and relative jumps.
        * **Instruction Emission:** A vast number of methods for emitting specific LoongArch64 instructions (arithmetic, logical, memory access, floating-point, branching). The names of these methods directly correspond to LoongArch64 assembly mnemonics (e.g., `add_w`, `ld_d`, `beq`).
        * **Utilities:** Alignment (`Align`, `DataAlign`, `CodeTargetAlign`), NOP insertion, size calculation (`SizeOfCodeGeneratedSince`), and scoping for managing buffer growth and trampoline pools.
        * **Deoptimization:** `RecordDeoptReason`.
        * **Data Emission:** `db`, `dd`, `dq` for inserting raw data.
        * **Instruction Manipulation:**  Methods to read and modify existing instructions (`instr_at`, `instr_at_put`).

5. **Address Specific Instructions:**

    * **`.tq` Check:** The prompt asks about `.tq` files. The code explicitly uses `.h`, so the answer should address this correctly.

    * **JavaScript Relationship:**  The assembler is *directly* related to JavaScript functionality. It's the component responsible for translating JavaScript code (or bytecode) into native machine instructions that the CPU can execute. Examples should illustrate simple JavaScript constructs and how they might be implemented at a low level.

    * **Code Logic Reasoning:** The branching and label mechanisms are prime candidates for demonstrating code logic. A simple conditional statement in assembly can illustrate this.

    * **Common Programming Errors:**  Branching beyond the allowed range is a classic assembly programming mistake.

6. **Synthesize the Summary:** Combine the identified functionalities into a concise overview, highlighting the key responsibilities of the `assembler-loong64.h` file.

7. **Structure the Answer:**  Organize the information logically, using headings and bullet points for clarity. Address each part of the user's request systematically.

By following these steps, we can accurately and comprehensively describe the functionality of the provided header file. The key is to understand the context (V8, LoongArch64, code generation) and then carefully analyze the declarations and methods within the file.
这是 V8 JavaScript 引擎中为 LoongArch64 架构定义汇编器（Assembler）的头文件。它提供了用于生成 LoongArch64 机器码的 C++ 接口。

以下是其主要功能归纳：

**核心功能：生成 LoongArch64 机器码**

* **提供指令级别的抽象:**  `Assembler` 类提供了 C++ 方法来对应 LoongArch64 架构的各种指令，例如算术运算、逻辑运算、内存访问、分支跳转、浮点运算等。
* **管理代码生成过程:**  它负责将这些指令编码成实际的机器码字节，并存储在缓冲区中。
* **处理代码重定位:**  当生成的代码被加载到内存中的不同位置时，需要调整某些指令中的地址。汇编器会记录这些需要重定位的信息。
* **支持标签（Labels）:**  允许在代码中定义标签，用于表示代码中的特定位置，方便进行跳转和分支操作。
* **优化代码生成:**  可能包含一些小的优化策略，例如短跳转的自动选择。

**具体功能点：**

* **操作数表示 (`Operand` 类):**
    * 封装了 LoongArch64 指令可以接受的不同类型的操作数，包括：
        * 立即数 (`immediate`)
        * 外部引用 (`ExternalReference`)
        * Smi (小整数)
        * 堆对象句柄 (`Handle<HeapObject>`)
        * 寄存器 (`Register`)
    * 提供了判断操作数类型的方法 (`is_reg`, `IsImmediate`, `IsHeapNumberRequest`)。

* **内存操作数表示 (`MemOperand` 类):**
    * 封装了内存操作数的表示方式，支持基址寄存器加偏移的形式：
        * `base_reg + off_imm` (偏移量可以是 12 位或 14 位左移 2 位)
        * `base_reg + offset_reg` (使用寄存器作为偏移)

* **汇编器核心 (`Assembler` 类):**
    * **初始化和代码获取:**
        * 构造函数用于创建汇编器实例，并管理用于存储机器码的缓冲区。
        * `GetCode` 方法用于获取最终生成的机器码，并填充代码描述符 (`CodeDesc`)。
    * **标签操作:**
        * `bind(Label* L)`: 将标签绑定到当前代码位置。
        * `is_near_c(Label* L)`, `is_near(Label* L, OffsetSize bits)`, `is_near_a(Label* L)`: 判断标签是否在当前位置附近的范围内，可以使用较短的跳转指令。
        * `branch_offset(...)`: 计算跳转到标签的偏移量。
        * `jump_address(Label* L)`, `jump_offset(Label* L)`: 获取跳转地址或偏移量。
    * **指令生成方法:** 提供了大量的以 LoongArch64 指令助记符命名的方法，用于生成各种指令，例如：
        * **分支和跳转:** `b`, `bl`, `beq`, `bne`, `jirl` 等。
        * **数据处理（算术、逻辑、位运算）:** `add_w`, `sub_d`, `andi`, `ori`, `sll_w`, `mul_d` 等。
        * **内存访问:** `ld_b`, `st_w`, `ldx_d`, `stx_h`, `ldptr_d`, `stptr_w` 等。
        * **浮点运算:** `fadd_s`, `fmul_d`, `fsqrt_s`, `fcmp_cond_d` 等。
    * **代码对齐:** `Align`, `DataAlign`, `CodeTargetAlign` 用于在代码中插入填充字节或指令，以满足特定的对齐要求。
    * **NOP 指令:** `nop` 用于插入空操作指令，常用于代码对齐或占位。
    * **代码修改和检查:**
        * `target_address_at`, `set_target_address_at`:  用于读取或修改跳转/调用指令的目标地址。
        * `instr_at`, `instr_at_put`:  用于读取或修改指定位置的机器指令。
        * `SizeOfCodeGeneratedSince`, `InstructionsGeneratedSince`:  用于计算自某个标签以来生成的代码大小或指令数量。
    * **Trampoline 池管理:** `BlockTrampolinePoolScope`, `BlockTrampolinePoolFor`: 用于管理跳转范围超出限制时使用的 trampoline 代码块。
    * **缓冲区管理:** `BlockGrowBufferScope`: 用于临时阻止汇编器扩展其内部缓冲区。
    * **调试支持:** `RecordDeoptReason`, `break_`, `stop`: 用于插入断点或记录反优化原因。
    * **数据写入:** `db`, `dd`, `dq`: 用于在代码流中写入字节、双字或四字数据。

**关于 .tq 结尾的文件：**

如果 `v8/src/codegen/loong64/assembler-loong64.h` 以 `.tq` 结尾，那么它确实是 V8 Torque 源代码。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。在这种情况下，该文件将包含使用 Torque 语法定义的，与 LoongArch64 架构相关的汇编代码生成逻辑。

**与 JavaScript 的关系及示例：**

`assembler-loong64.h` 直接关系到 JavaScript 的执行。V8 引擎需要将 JavaScript 代码编译成机器码才能在 CPU 上运行。`Assembler` 类就是负责将 V8 的内部表示（例如，中间代码或字节码）转换为 LoongArch64 机器码的关键组件。

**JavaScript 示例：**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译 `add` 函数时，`assembler-loong64.h` 中定义的 `Assembler` 类会被用来生成相应的 LoongArch64 机器码。  这可能涉及以下步骤（简化示例）：

1. **加载参数:** 将参数 `a` 和 `b` 从寄存器或栈中加载到 LoongArch64 的通用寄存器中。例如，可能使用 `ld_d` 指令。
2. **执行加法:** 使用 `add_d` 指令将两个寄存器中的值相加。
3. **返回结果:** 将结果存储到指定的寄存器或栈位置，并执行返回指令。

**假设输入与输出 (代码逻辑推理 - 标签和跳转):**

**假设输入:**

```c++
Assembler masm(...);
Label start, end;

masm.bind(&start);
masm.addi_d(a0, zero_reg, 10); // 将 10 加载到 a0 寄存器
masm.beq(a0, zero_reg, &end);  // 如果 a0 等于 0，则跳转到 end 标签
masm.addi_d(a0, a0, 5);     // 否则，将 a0 加 5
masm.bind(&end);
masm.nop();
```

**预期输出（简化表示，实际是机器码字节）:**

这段代码会生成类似以下的 LoongArch64 汇编指令序列：

```assembly
// 对应 masm.bind(&start);
// ... (start 标签对应的地址)

addi.d  a0, zero, 10  // 对应 masm.addi_d(a0, zero_reg, 10);
beq     a0, zero, <offset_to_end> // 对应 masm.beq(a0, zero_reg, &end);  <offset_to_end> 是到 end 标签的偏移量
addi.d  a0, a0, 5     // 对应 masm.addi_d(a0, a0, 5);

// 对应 masm.bind(&end);
// ... (end 标签对应的地址)
nop                   // 对应 masm.nop();
```

`beq` 指令中的 `<offset_to_end>` 会由汇编器计算出来，表示从 `beq` 指令的位置到 `end` 标签位置的偏移量。

**用户常见的编程错误示例：**

使用 `Assembler` 时，用户可能会遇到以下常见的编程错误：

1. **跳转目标超出范围:**  LoongArch64 的某些分支指令有跳转距离的限制。如果尝试跳转到距离当前位置太远的标签，汇编器会报错或者生成不正确的代码。例如：

   ```c++
   Assembler masm(...);
   Label target;
   // ... 生成大量代码 ...
   masm.bne(a0, a1, &target); // 如果 target 标签距离太远，可能会出错
   // ... 更多代码 ...
   masm.bind(&target);
   ```

   解决办法通常是使用无条件跳转指令 (`b`) 或调用指令 (`bl`)，它们通常具有更大的跳转范围，或者让汇编器自动插入 trampoline 代码。

2. **寄存器使用错误:**  错误地使用或假设寄存器的值。例如，在没有保存和恢复的情况下，修改了调用约定中规定的需要保护的寄存器。

3. **内存访问错误:**  访问了无效的内存地址，或者使用了错误的内存访问指令（例如，字节加载但期望加载字）。

4. **对齐错误:**  某些指令或数据需要特定的内存对齐。如果生成的代码违反了这些对齐要求，可能会导致程序崩溃或性能下降。例如，尝试在奇数地址加载双字数据。

**总结 `assembler-loong64.h` 的功能 (第 1 部分):**

总而言之，`v8/src/codegen/loong64/assembler-loong64.h` 是 V8 引擎中用于为 LoongArch64 架构生成机器码的关键组件。它提供了 C++ 接口来操作 LoongArch64 的指令、寄存器和内存，并负责管理代码生成、重定位和优化等过程。它直接将 V8 内部的表示转换为可以在 LoongArch64 处理器上执行的指令，是实现 JavaScript 动态执行的基础。

### 提示词
```
这是目录为v8/src/codegen/loong64/assembler-loong64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/loong64/assembler-loong64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_LOONG64_ASSEMBLER_LOONG64_H_
#define V8_CODEGEN_LOONG64_ASSEMBLER_LOONG64_H_

#include <stdio.h>

#include <memory>
#include <set>

#include "src/codegen/assembler.h"
#include "src/codegen/external-reference.h"
#include "src/codegen/label.h"
#include "src/codegen/loong64/constants-loong64.h"
#include "src/codegen/loong64/register-loong64.h"
#include "src/codegen/machine-type.h"
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

// Class MemOperand represents a memory operand in load and store instructions.
// 1: base_reg + off_imm( si12 | si14<<2)
// 2: base_reg + offset_reg
class V8_EXPORT_PRIVATE MemOperand {
 public:
  explicit MemOperand(Register rj, int32_t offset = 0);
  explicit MemOperand(Register rj, Register offset = no_reg);
  Register base() const { return base_; }
  Register index() const { return index_; }
  int32_t offset() const { return offset_; }

  bool hasIndexReg() const { return index_ != no_reg; }

 private:
  Register base_;   // base
  Register index_;  // index
  int32_t offset_;  // offset

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

  // Loong64 uses BlockTrampolinePool to prevent generating trampoline inside a
  // continuous instruction block. In the destructor of BlockTrampolinePool, it
  // must check if it needs to generate trampoline immediately, if it does not
  // do this, the branch range will go beyond the max branch offset, that means
  // the pc_offset after call CheckTrampolinePool may have changed. So we use
  // pc_for_safepoint_ here for safepoint record.
  int pc_offset_for_safepoint() {
    return static_cast<int>(pc_for_safepoint_ - buffer_start_);
  }

  // TODO(LOONG_dev): LOONG64 Check this comment
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

  enum OffsetSize : int {
    kOffset26 = 26,
    kOffset21 = 21,
    kOffset20 = 20,
    kOffset16 = 16
  };

  // Determines if Label is bound and near enough so that branch instruction
  // can be used to reach it, instead of jump instruction.
  // c means conditinal branch, a means always branch.
  bool is_near_c(Label* L);
  bool is_near(Label* L, OffsetSize bits);
  bool is_near_a(Label* L);

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
  static uint32_t target_compressed_address_at(Address pc);
  // On LOONG64 there is no Constant Pool so we skip that parameter.
  inline static Address target_address_at(Address pc, Address constant_pool) {
    return target_address_at(pc);
  }
  inline static Tagged_t target_compressed_address_at(Address pc,
                                                      Address constant_pool) {
    return target_compressed_address_at(pc);
  }
  inline static void set_target_address_at(
      Address pc, Address constant_pool, Address target,
      WritableJitAllocation* jit_allocation,
      ICacheFlushMode icache_flush_mode = FLUSH_ICACHE_IF_NEEDED) {
    set_target_value_at(pc, target, jit_allocation, icache_flush_mode);
  }
  inline static void set_target_compressed_address_at(
      Address pc, Address constant_pool, Tagged_t target,
      WritableJitAllocation* jit_allocation,
      ICacheFlushMode icache_flush_mode = FLUSH_ICACHE_IF_NEEDED) {
    set_target_compressed_value_at(pc, target, jit_allocation,
                                   icache_flush_mode);
  }

  inline Handle<Code> code_target_object_handle_at(Address pc,
                                                   Address constant_pool);

  // During code generation builtin targets in PC-relative call/jump
  // instructions are temporarily encoded as builtin ID until the generated
  // code is moved into the code space.
  static inline Builtin target_builtin_at(Address pc);

  static void set_target_value_at(
      Address pc, uint64_t target,
      WritableJitAllocation* jit_allocation = nullptr,
      ICacheFlushMode icache_flush_mode = FLUSH_ICACHE_IF_NEEDED);
  static void set_target_compressed_value_at(
      Address pc, uint32_t target,
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

  inline Handle<HeapObject> compressed_embedded_object_handle_at(
      Address pc, Address constant_pool);
  inline Handle<HeapObject> embedded_object_handle_at(Address pc,
                                                      Address constant_pool);

  // Read/modify the uint32 constant used at pc.
  static inline uint32_t uint32_constant_at(Address pc, Address constant_pool);
  static inline void set_uint32_constant_at(
      Address pc, Address constant_pool, uint32_t new_constant,
      WritableJitAllocation* jit_allocation,
      ICacheFlushMode icache_flush_mode = FLUSH_ICACHE_IF_NEEDED);

  // Here we are patching the address in the LUI/ORI instruction pair.
  // These values are used in the serialization process and must be zero for
  // LOONG platform, as InstructionStream, Embedded Object or External-reference
  // pointers are split across two consecutive instructions and don't exist
  // separately in the code, so the serializer should not step forwards in
  // memory after a target is resolved and written.
  static constexpr int kSpecialTargetSize = 0;

  // Number of consecutive instructions used to store 32bit/64bit constant.
  // This constant was used in RelocInfo::target_address_address() function
  // to tell serializer address of the instruction that follows
  // LUI/ORI instruction pair.
  // TODO(LOONG_dev): check this
  static constexpr int kInstructionsFor64BitConstant = 4;

  // Max offset for instructions with 16-bit offset field
  static constexpr int kMax16BranchOffset = (1 << (18 - 1)) - 1;

  // Max offset for instructions with 21-bit offset field
  static constexpr int kMax21BranchOffset = (1 << (23 - 1)) - 1;

  // Max offset for compact branch instructions with 26-bit offset field
  static constexpr int kMax26BranchOffset = (1 << (28 - 1)) - 1;

  static constexpr int kTrampolineSlotsSize = 2 * kInstrSize;

  RegList* GetScratchRegisterList() { return &scratch_register_list_; }

  DoubleRegList* GetScratchFPRegisterList() {
    return &scratch_fpregister_list_;
  }

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

  // Type == 0 is the default non-marking nop. For LoongArch this is a
  // andi(zero_reg, zero_reg, 0).
  void nop(unsigned int type = 0) {
    DCHECK_LT(type, 32);
    andi(zero_reg, zero_reg, type);
  }

  // --------Branch-and-jump-instructions----------
  // We don't use likely variant of instructions.
  void b(int32_t offset);
  inline void b(Label* L) { b(shifted_branch_offset26(L)); }
  void bl(int32_t offset);
  inline void bl(Label* L) { bl(shifted_branch_offset26(L)); }

  void beq(Register rj, Register rd, int32_t offset);
  inline void beq(Register rj, Register rd, Label* L) {
    beq(rj, rd, shifted_branch_offset(L));
  }
  void bne(Register rj, Register rd, int32_t offset);
  inline void bne(Register rj, Register rd, Label* L) {
    bne(rj, rd, shifted_branch_offset(L));
  }
  void blt(Register rj, Register rd, int32_t offset);
  inline void blt(Register rj, Register rd, Label* L) {
    blt(rj, rd, shifted_branch_offset(L));
  }
  void bge(Register rj, Register rd, int32_t offset);
  inline void bge(Register rj, Register rd, Label* L) {
    bge(rj, rd, shifted_branch_offset(L));
  }
  void bltu(Register rj, Register rd, int32_t offset);
  inline void bltu(Register rj, Register rd, Label* L) {
    bltu(rj, rd, shifted_branch_offset(L));
  }
  void bgeu(Register rj, Register rd, int32_t offset);
  inline void bgeu(Register rj, Register rd, Label* L) {
    bgeu(rj, rd, shifted_branch_offset(L));
  }
  void beqz(Register rj, int32_t offset);
  inline void beqz(Register rj, Label* L) {
    beqz(rj, shifted_branch_offset21(L));
  }
  void bnez(Register rj, int32_t offset);
  inline void bnez(Register rj, Label* L) {
    bnez(rj, shifted_branch_offset21(L));
  }

  void jirl(Register rd, Register rj, int32_t offset);

  void bceqz(CFRegister cj, int32_t si21);
  inline void bceqz(CFRegister cj, Label* L) {
    bceqz(cj, shifted_branch_offset21(L));
  }
  void bcnez(CFRegister cj, int32_t si21);
  inline void bcnez(CFRegister cj, Label* L) {
    bcnez(cj, shifted_branch_offset21(L));
  }

  // -------Data-processing-instructions---------

  // Arithmetic.
  void add_w(Register rd, Register rj, Register rk);
  void add_d(Register rd, Register rj, Register rk);
  void sub_w(Register rd, Register rj, Register rk);
  void sub_d(Register rd, Register rj, Register rk);

  void addi_w(Register rd, Register rj, int32_t si12);
  void addi_d(Register rd, Register rj, int32_t si12);

  void addu16i_d(Register rd, Register rj, int32_t si16);

  void alsl_w(Register rd, Register rj, Register rk, int32_t sa2);
  void alsl_wu(Register rd, Register rj, Register rk, int32_t sa2);
  void alsl_d(Register rd, Register rj, Register rk, int32_t sa2);

  void lu12i_w(Register rd, int32_t si20);
  void lu32i_d(Register rd, int32_t si20);
  void lu52i_d(Register rd, Register rj, int32_t si12);

  void slt(Register rd, Register rj, Register rk);
  void sltu(Register rd, Register rj, Register rk);
  void slti(Register rd, Register rj, int32_t si12);
  void sltui(Register rd, Register rj, int32_t si12);

  void pcaddi(Register rd, int32_t si20);
  void pcaddu12i(Register rd, int32_t si20);
  void pcaddu18i(Register rd, int32_t si20);
  void pcalau12i(Register rd, int32_t si20);

  void and_(Register rd, Register rj, Register rk);
  void or_(Register rd, Register rj, Register rk);
  void xor_(Register rd, Register rj, Register rk);
  void nor(Register rd, Register rj, Register rk);
  void andn(Register rd, Register rj, Register rk);
  void orn(Register rd, Register rj, Register rk);

  void andi(Register rd, Register rj, int32_t ui12);
  void ori(Register rd, Register rj, int32_t ui12);
  void xori(Register rd, Register rj, int32_t ui12);

  void mul_w(Register rd, Register rj, Register rk);
  void mulh_w(Register rd, Register rj, Register rk);
  void mulh_wu(Register rd, Register rj, Register rk);
  void mul_d(Register rd, Register rj, Register rk);
  void mulh_d(Register rd, Register rj, Register rk);
  void mulh_du(Register rd, Register rj, Register rk);

  void mulw_d_w(Register rd, Register rj, Register rk);
  void mulw_d_wu(Register rd, Register rj, Register rk);

  void div_w(Register rd, Register rj, Register rk);
  void mod_w(Register rd, Register rj, Register rk);
  void div_wu(Register rd, Register rj, Register rk);
  void mod_wu(Register rd, Register rj, Register rk);
  void div_d(Register rd, Register rj, Register rk);
  void mod_d(Register rd, Register rj, Register rk);
  void div_du(Register rd, Register rj, Register rk);
  void mod_du(Register rd, Register rj, Register rk);

  // Shifts.
  void sll_w(Register rd, Register rj, Register rk);
  void srl_w(Register rd, Register rj, Register rk);
  void sra_w(Register rd, Register rj, Register rk);
  void rotr_w(Register rd, Register rj, Register rk);

  void slli_w(Register rd, Register rj, int32_t ui5);
  void srli_w(Register rd, Register rj, int32_t ui5);
  void srai_w(Register rd, Register rj, int32_t ui5);
  void rotri_w(Register rd, Register rj, int32_t ui5);

  void sll_d(Register rd, Register rj, Register rk);
  void srl_d(Register rd, Register rj, Register rk);
  void sra_d(Register rd, Register rj, Register rk);
  void rotr_d(Register rd, Register rj, Register rk);

  void slli_d(Register rd, Register rj, int32_t ui6);
  void srli_d(Register rd, Register rj, int32_t ui6);
  void srai_d(Register rd, Register rj, int32_t ui6);
  void rotri_d(Register rd, Register rj, int32_t ui6);

  // Bit twiddling.
  void ext_w_b(Register rd, Register rj);
  void ext_w_h(Register rd, Register rj);

  void clo_w(Register rd, Register rj);
  void clz_w(Register rd, Register rj);
  void cto_w(Register rd, Register rj);
  void ctz_w(Register rd, Register rj);
  void clo_d(Register rd, Register rj);
  void clz_d(Register rd, Register rj);
  void cto_d(Register rd, Register rj);
  void ctz_d(Register rd, Register rj);

  void bytepick_w(Register rd, Register rj, Register rk, int32_t sa2);
  void bytepick_d(Register rd, Register rj, Register rk, int32_t sa3);

  void revb_2h(Register rd, Register rj);
  void revb_4h(Register rd, Register rj);
  void revb_2w(Register rd, Register rj);
  void revb_d(Register rd, Register rj);

  void revh_2w(Register rd, Register rj);
  void revh_d(Register rd, Register rj);

  void bitrev_4b(Register rd, Register rj);
  void bitrev_8b(Register rd, Register rj);

  void bitrev_w(Register rd, Register rj);
  void bitrev_d(Register rd, Register rj);

  void bstrins_w(Register rd, Register rj, int32_t msbw, int32_t lsbw);
  void bstrins_d(Register rd, Register rj, int32_t msbd, int32_t lsbd);

  void bstrpick_w(Register rd, Register rj, int32_t msbw, int32_t lsbw);
  void bstrpick_d(Register rd, Register rj, int32_t msbd, int32_t lsbd);

  void maskeqz(Register rd, Register rj, Register rk);
  void masknez(Register rd, Register rj, Register rk);

  // Memory-instructions
  void ld_b(Register rd, Register rj, int32_t si12);
  void ld_h(Register rd, Register rj, int32_t si12);
  void ld_w(Register rd, Register rj, int32_t si12);
  void ld_d(Register rd, Register rj, int32_t si12);
  void ld_bu(Register rd, Register rj, int32_t si12);
  void ld_hu(Register rd, Register rj, int32_t si12);
  void ld_wu(Register rd, Register rj, int32_t si12);
  void st_b(Register rd, Register rj, int32_t si12);
  void st_h(Register rd, Register rj, int32_t si12);
  void st_w(Register rd, Register rj, int32_t si12);
  void st_d(Register rd, Register rj, int32_t si12);

  void ldx_b(Register rd, Register rj, Register rk);
  void ldx_h(Register rd, Register rj, Register rk);
  void ldx_w(Register rd, Register rj, Register rk);
  void ldx_d(Register rd, Register rj, Register rk);
  void ldx_bu(Register rd, Register rj, Register rk);
  void ldx_hu(Register rd, Register rj, Register rk);
  void ldx_wu(Register rd, Register rj, Register rk);
  void stx_b(Register rd, Register rj, Register rk);
  void stx_h(Register rd, Register rj, Register rk);
  void stx_w(Register rd, Register rj, Register rk);
  void stx_d(Register rd, Register rj, Register rk);

  void ldptr_w(Register rd, Register rj, int32_t si14);
  void ldptr_d(Register rd, Register rj, int32_t si14);
  void stptr_w(Register rd, Register rj, int32_t si14);
  void stptr_d(Register rd, Register rj, int32_t si14);

  void amswap_w(Register rd, Register rk, Register rj);
  void amswap_d(Register rd, Register rk, Register rj);
  void amadd_w(Register rd, Register rk, Register rj);
  void amadd_d(Register rd, Register rk, Register rj);
  void amand_w(Register rd, Register rk, Register rj);
  void amand_d(Register rd, Register rk, Register rj);
  void amor_w(Register rd, Register rk, Register rj);
  void amor_d(Register rd, Register rk, Register rj);
  void amxor_w(Register rd, Register rk, Register rj);
  void amxor_d(Register rd, Register rk, Register rj);
  void ammax_w(Register rd, Register rk, Register rj);
  void ammax_d(Register rd, Register rk, Register rj);
  void ammin_w(Register rd, Register rk, Register rj);
  void ammin_d(Register rd, Register rk, Register rj);
  void ammax_wu(Register rd, Register rk, Register rj);
  void ammax_du(Register rd, Register rk, Register rj);
  void ammin_wu(Register rd, Register rk, Register rj);
  void ammin_du(Register rd, Register rk, Register rj);

  void amswap_db_w(Register rd, Register rk, Register rj);
  void amswap_db_d(Register rd, Register rk, Register rj);
  void amadd_db_w(Register rd, Register rk, Register rj);
  void amadd_db_d(Register rd, Register rk, Register rj);
  void amand_db_w(Register rd, Register rk, Register rj);
  void amand_db_d(Register rd, Register rk, Register rj);
  void amor_db_w(Register rd, Register rk, Register rj);
  void amor_db_d(Register rd, Register rk, Register rj);
  void amxor_db_w(Register rd, Register rk, Register rj);
  void amxor_db_d(Register rd, Register rk, Register rj);
  void ammax_db_w(Register rd, Register rk, Register rj);
  void ammax_db_d(Register rd, Register rk, Register rj);
  void ammin_db_w(Register rd, Register rk, Register rj);
  void ammin_db_d(Register rd, Register rk, Register rj);
  void ammax_db_wu(Register rd, Register rk, Register rj);
  void ammax_db_du(Register rd, Register rk, Register rj);
  void ammin_db_wu(Register rd, Register rk, Register rj);
  void ammin_db_du(Register rd, Register rk, Register rj);

  void ll_w(Register rd, Register rj, int32_t si14);
  void ll_d(Register rd, Register rj, int32_t si14);
  void sc_w(Register rd, Register rj, int32_t si14);
  void sc_d(Register rd, Register rj, int32_t si14);

  void dbar(int32_t hint);
  void ibar(int32_t hint);

  // Break instruction
  void break_(uint32_t code, bool break_as_stop = false);
  void stop(uint32_t code = kMaxStopCode);

  // Arithmetic.
  void fadd_s(FPURegister fd, FPURegister fj, FPURegister fk);
  void fadd_d(FPURegister fd, FPURegister fj, FPURegister fk);
  void fsub_s(FPURegister fd, FPURegister fj, FPURegister fk);
  void fsub_d(FPURegister fd, FPURegister fj, FPURegister fk);
  void fmul_s(FPURegister fd, FPURegister fj, FPURegister fk);
  void fmul_d(FPURegister fd, FPURegister fj, FPURegister fk);
  void fdiv_s(FPURegister fd, FPURegister fj, FPURegister fk);
  void fdiv_d(FPURegister fd, FPURegister fj, FPURegister fk);

  void fmadd_s(FPURegister fd, FPURegister fj, FPURegister fk, FPURegister fa);
  void fmadd_d(FPURegister fd, FPURegister fj, FPURegister fk, FPURegister fa);
  void fmsub_s(FPURegister fd, FPURegister fj, FPURegister fk, FPURegister fa);
  void fmsub_d(FPURegister fd, FPURegister fj, FPURegister fk, FPURegister fa);
  void fnmadd_s(FPURegister fd, FPURegister fj, FPURegister fk, FPURegister fa);
  void fnmadd_d(FPURegister fd, FPURegister fj, FPURegister fk, FPURegister fa);
  void fnmsub_s(FPURegister fd, FPURegister fj, FPURegister fk, FPURegister fa);
  void fnmsub_d(FPURegister fd, FPURegister fj, FPURegister fk, FPURegister fa);

  void fmax_s(FPURegister fd, FPURegister fj, FPURegister fk);
  void fmax_d(FPURegister fd, FPURegister fj, FPURegister fk);
  void fmin_s(FPURegister fd, FPURegister fj, FPURegister fk);
  void fmin_d(FPURegister fd, FPURegister fj, FPURegister fk);

  void fmaxa_s(FPURegister fd, FPURegister fj, FPURegister fk);
  void fmaxa_d(FPURegister fd, FPURegister fj, FPURegister fk);
  void fmina_s(FPURegister fd, FPURegister fj, FPURegister fk);
  void fmina_d(FPURegister fd, FPURegister fj, FPURegister fk);

  void fabs_s(FPURegister fd, FPURegister fj);
  void fabs_d(FPURegister fd, FPURegister fj);
  void fneg_s(FPURegister fd, FPURegister fj);
  void fneg_d(FPURegister fd, FPURegister fj);

  void fsqrt_s(FPURegister fd, FPURegister fj);
  void fsqrt_d(FPURegister fd, FPURegister fj);
  void frecip_s(FPURegister fd, FPURegister fj);
  void frecip_d(FPURegister fd, FPURegister fj);
  void frsqrt_s(FPURegister fd, FPURegister fj);
  void frsqrt_d(FPURegister fd, FPURegister fj);

  void fscaleb_s(FPURegister fd, FPURegister fj, FPURegister fk);
  void fscaleb_d(FPURegister fd, FPURegister fj, FPURegister fk);
  void flogb_s(FPURegister fd, FPURegister fj);
  void flogb_d(FPURegister fd, FPURegister fj);
  void fcopysign_s(FPURegister fd, FPURegister fj, FPURegister fk);
  void fcopysign_d(FPURegister fd, FPURegister fj, FPURegister fk);

  void fclass_s(FPURegister fd, FPURegister fj);
  void fclass_d(FPURegister fd, FPURegister fj);

  void fcmp_cond_s(FPUCondition cc, FPURegister fj, FPURegister fk,
                   CFRegister cd);
  void fcmp_cond_d(FPUCondition cc, FPURegister fj, FPURegister fk,
                   CFRegister cd);

  void fcvt_s_d(FPURegister fd, FPURegister fj);
  void fcvt_d_s(FPURegister fd, FPURegister fj);

  void ffint_s_w(FPURegister fd, FPURegister fj);
  void ffint_s_l(FPURegister fd, FPURegister fj);
  void ffint_d_w(FPURegister fd, FPURegister fj);
  void ffint_d_l(FPURegister fd, FPURegister fj);
  void ftint_w_s(FPURegister fd, FPURegister fj);
  void ftint_w_d(FPURegister fd, FPURegister fj);
  void ftint_l_s(FPURegister fd, FPURegister fj);
  void ftint_l_d(FPURegister fd, FPURegister fj);

  void ftintrm_w_s(FPURegister fd, FPURegister fj);
  void ftintrm_w_d(FPURegister fd, FPURegister fj);
  void ftintrm_l_s(FPURegister fd, FPURegister fj);
  void ftintrm_l_d(FPURegister fd, FPURegister fj);
  void ftintrp_w_s(FPURegister fd, FPURegister fj);
  void ftintrp_w_d(FPURegister fd, FPURegister fj);
  void ftintrp_l_s(FPURegister fd, FPURegister fj);
  void ftintrp_l_d(FPURegister fd, FPURegister fj);
  void ftintrz_w_s(FPURegister fd, FPURegister fj);
  void ftintrz_w_d(FPURegister fd, FPURegister fj);
  void ftintrz_l_s(FPURegister fd, FPURegister fj);
  void ftintrz_l_d(FPURegister fd, FPURegister fj);
  void ftintrne_w_s(FPURegister fd, FPURegister fj);
  void ftintrne_w_d(FPURegister fd, FPURegister fj);
  void ftintrne_l_s(FPURegister fd, FPURegister fj);
  void ftintrne_l_d(FPURegister fd, FPURegister fj);

  void frint_s(FPURegister fd, FPURegister fj);
  void frint_d(FPURegister fd, FPURegister fj);

  void fmov_s(FPURegister fd, FPURegister fj);
  void fmov_d(FPURegister fd, FPURegister fj);

  void fsel(CFRegister ca, FPURegister fd, FPURegister fj, FPURegister fk);

  void movgr2fr_w(FPURegister fd, Register rj);
  void movgr2fr_d(FPURegister fd, Register rj);
  void movgr2frh_w(FPURegister fd, Register rj);

  void movfr2gr_s(Register rd, FPURegister fj);
  void movfr2gr_d(Register rd, FPURegister fj);
  void movfrh2gr_s(Register rd, FPURegister fj);

  void movgr2fcsr(Register rj, FPUControlRegister fcsr = FCSR0);
  void movfcsr2gr(Register rd, FPUControlRegister fcsr = FCSR0);

  void movfr2cf(CFRegister cd, FPURegister fj);
  void movcf2fr(FPURegister fd, CFRegister cj);

  void movgr2cf(CFRegister cd, Register rj);
  void movcf2gr(Register rd, CFRegister cj);

  void fld_s(FPURegister fd, Register rj, int32_t si12);
  void fld_d(FPURegister fd, Register rj, int32_t si12);
  void fst_s(FPURegister fd, Register rj, int32_t si12);
  void fst_d(FPURegister fd, Register rj, int32_t si12);

  void fldx_s(FPURegister fd, Register rj, Register rk);
  void fldx_d(FPURegister fd, Register rj, Register rk);
  void fstx_s(FPURegister fd, Register rj, Register rk);
  void fstx_d(FPURegister fd, Register rj, Register rk);

  // Check the code size generated from label to here.
  int SizeOfCodeGeneratedSince(Label* label) {
    return pc_offset() - label->pos();
  }

  // Check the number of instructions generated from label to here.
  int InstructionsGeneratedSince(Label* label) {
    return SizeOfCodeGeneratedSince(label) / kInstrSize;
  }

  // Class for scoping postponing the trampoline pool generation.
  class V8_NODISCARD BlockTrampolinePoolScope {
   public:
    explicit BlockTrampolinePoolScope(Assembler* assem) : assem_(assem) {
      assem_->StartBlockTrampolinePool();
    }
    ~BlockTrampolinePoolScope() { assem_->EndBlockTrampolinePool(); }

   private:
    Assembler* assem_;

    DISALLOW_IMPLICIT_CONSTRUCTORS(BlockTrampolinePoolScope);
  };

  // Class for postponing the assembly buffer growth. Typically used for
  // sequences of instructions that must be emitted as a unit, before
  // buffer growth (and relocation) can occur.
  // This blocking scope is not nestable.
  class V8_NODISCARD BlockGrowBufferScope {
   public:
    explicit BlockGrowBufferScope(Assembler* assem) : assem_(assem) {
      assem_->StartBlockGrowBuffer();
    }
    ~BlockGrowBufferScope() { assem_->EndBlockGrowBuffer(); }

   private:
    Assembler* assem_;

    DISALLOW_IMPLICIT_CONSTRUCTORS(BlockGrowBufferScope);
  };

  // Record a deoptimization reason that can be used by a log or cpu profiler.
  // Use --trace-deopt to enable.
  void RecordDeoptReason(DeoptimizeReason reason, uint32_t node_id,
                         SourcePosition position, int id);

  static void RelocateRelativeReference(
      RelocInfo::Mode rmode, Address pc, intptr_t pc_delta,
      WritableJitAllocation* jit_allocation = nullptr);

  // Writes a single byte or word of data in the code stream.  Used for
  // inline tables, e.g., jump-tables.
  void db(uint8_t data);
  void dd(uint32_t data);
  void dq(uint64_t data);
  void dp(uintptr_t data) { dq(data); }
  void dd(Label* label);

  // Postpone the generation of the trampoline pool for the specified number of
  // instructions.
  void BlockTrampolinePoolFor(int instructions);

  // Check if there is less than kGap bytes available in the buffer.
  // If this is the case, we need to grow the buffer before emitting
  // an instruction or relocation information.
  inline bool overflow() const { return pc_ >= reloc_info_writer.pos() - kGap; }

  // Get the number of bytes available in the buffer.
  inline intptr_t available_space() const {
    return reloc_info_writer.pos() - pc_;
  }

  // Read/patch instructions.
  static Instr instr_at(Address pc) { return *reinterpret_cast<Instr*>(pc); }
  static void instr_at_put(Address pc, Instr instr,
                           WritableJitAllocation* jit_allocation = nullptr) {
    Instruction* i = reinterpret_cast<Instruction*>(pc);
    i->SetInstructionBits(instr, jit_allocation);
  }
  Instr instr_at(int pos) {
    return *reinterpret_cast<Instr*>(buffer_start_ + pos);
  }
  void instr_at_put(int pos, Instr instr,
                    WritableJitAllocation* jit_allocation = nullptr) {
    Instruction* i = reinterpret_cast<I
```