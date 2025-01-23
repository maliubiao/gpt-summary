Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided C++ header file (`assembler-s390.h`), specifically focusing on its role in V8, its relationship to JavaScript, potential errors, and whether it's a Torque file.

2. **Initial Scan and Keyword Identification:** I quickly scan the code for key terms and patterns. I see:
    * `Copyright 2014 the V8 project authors` - Confirms it's a V8 file.
    * `#ifndef V8_CODEGEN_S390_ASSEMBLER_S390_H_` -  Indicates a header file defining an interface.
    * `namespace v8 { namespace internal {` - Reinforces the V8 context.
    * `class V8_EXPORT_PRIVATE Assembler : public AssemblerBase` -  The core class is an `Assembler`.
    * Numerous function declarations with names resembling assembly instructions (e.g., `name`, `bc`, `lgr`, etc.) and format specifiers (e.g., `rr_format`, `rx_format`).
    * Classes like `Operand`, `MemOperand`, `Label`.
    * Mentions of `RelocInfo`, `CodeDesc`, `SafepointTableBuilder`.
    * S390-specific terms like "z/Architecture".

3. **Deduce Core Functionality:** Based on the keywords, especially "Assembler",  "instructions", "operands", "memory operands", and the S390 architecture, I conclude the primary function is **generating machine code instructions for the S390 architecture within the V8 JavaScript engine**. It provides an abstraction layer over raw machine code, making it easier to construct instructions.

4. **Address Specific Questions:**

    * **Is it a Torque file?** The request states: "如果v8/src/codegen/s390/assembler-s390.h以.tq结尾，那它是个v8 torque源代码". The filename ends in `.h`, not `.tq`. Therefore, it's **not a Torque file**.

    * **Relationship to JavaScript:**  Assemblers are low-level components. JavaScript itself isn't directly written in assembly. However, the V8 engine *compiles* JavaScript code into machine code for execution. This header provides the tools to generate that S390 machine code. The connection is through the **compilation process**.

    * **JavaScript Example (Conceptual):** Since this is low-level, a direct JavaScript equivalent isn't feasible. I need to illustrate the *effect*. A simple JavaScript operation like `a + b` would, during compilation, potentially lead to assembly instructions generated using the classes and methods defined in this header. I'd give a simplified conceptual example, acknowledging the complexity of the actual compilation.

    * **Code Logic Inference (Hypothetical):**  The code focuses on *instruction encoding*. I'd choose a simple instruction, like adding two registers (`agr`), and illustrate how the `rrd_format` function would take register codes and the opcode to construct the binary representation of the instruction. I need to provide hypothetical inputs (register codes, opcode) and the expected output (the encoded instruction).

    * **Common Programming Errors:**  The most likely errors when working with assemblers involve incorrect usage of the provided abstractions. I'd think about:
        * **Incorrect register usage:** Using the wrong register for an operation.
        * **Invalid operands:** Providing an immediate value that's out of range.
        * **Incorrect memory addressing:**  Calculating the wrong displacement.

5. **Structure the Answer:**  I organize my findings based on the request's prompts:

    * Start with a general summary of the file's purpose.
    * Address the Torque file question directly.
    * Explain the connection to JavaScript with an illustrative (though simplified) example.
    * Provide a hypothetical code logic inference example with inputs and outputs.
    * Give examples of common programming errors.
    * Finally, summarize the overall function as requested in "第1部分，共3部分，请归纳一下它的功能".

6. **Refine and Elaborate:** I review my drafted answer, ensuring clarity, accuracy, and completeness. I make sure to explain *why* things are the way they are (e.g., why it's not a Torque file, how assembly relates to JavaScript compilation).

By following these steps, I can systematically analyze the provided code snippet and generate a comprehensive and accurate answer that addresses all aspects of the request. The key is to understand the high-level purpose of an assembler within a JavaScript engine context and then relate the specific code elements to that purpose.
这是一个V8 JavaScript引擎中用于S390架构的代码生成器头文件（header file）。它的主要功能是提供一个**汇编器 (Assembler)** 类，用于生成S390架构的机器指令。

**功能归纳：**

1. **定义S390架构的汇编器类 (`Assembler`)：**  这个类是核心，提供了在内存中构建S390机器指令的方法。它继承自 `AssemblerBase`，并针对S390架构进行了定制。

2. **定义机器指令的操作数 (`Operand`)：**  `Operand` 类用于表示汇编指令的操作数，可以是立即数、寄存器、内存地址等。它提供了多种构造函数来创建不同类型的操作数。

3. **定义内存操作数 (`MemOperand`)：**  `MemOperand` 类专门用于表示内存操作数，包括基址寄存器、索引寄存器和偏移量。

4. **提供生成各种S390指令的方法：** 文件中定义了大量的内联函数，对应于S390架构的各种指令，例如：
   -  `ril_format`, `rr_format`, `rrd_format`, `rre_format`, `rx_format`, `rxy_format`, `rsy_format`, `rs_format`, `rxe_format`, `ri_format`, `rrf_format`, `rsi_format`, `rsl_format`, `s_format`, `si_format` 等底层格式化函数。
   -  以及基于这些格式化函数封装的更易于使用的指令生成函数，如 `lgr` (Load GR)、`agr` (Add GR)、`bc` (Branch on Condition) 等。

5. **处理标签 (Label) 和跳转：**  提供了 `Label` 类来标记代码位置，并提供了 `bind` 和 `link` 等方法来管理标签，以及生成跳转指令的方法。

6. **处理重定位信息 (Relocation Information)：**  `Operand` 类中包含了 `RelocInfo::Mode`，用于指示操作数是否需要重定位，例如外部引用或嵌入对象。

7. **提供访问和修改已生成代码的方法：**  例如 `target_address_at`, `set_target_address_at` 等函数允许在已生成的代码中读取或修改目标地址。

**关于是否为Torque源代码：**

`v8/src/codegen/s390/assembler-s390.h` 以 `.h` 结尾，因此它是一个 **C++ 头文件**，而不是 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

**与JavaScript的功能关系：**

`assembler-s390.h`  与 JavaScript 的执行效率密切相关。V8 引擎在执行 JavaScript 代码时，需要将其编译成机器码。`Assembler` 类就用于生成目标平台（在本例中是 S390）的机器码指令。

**JavaScript 例子（概念性）：**

虽然不能直接用 JavaScript 代码来体现 `assembler-s390.h` 的功能，但可以想象一下当执行以下 JavaScript 代码时，V8 引擎可能会使用这个头文件中定义的汇编器来生成相应的机器码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

在 V8 编译 `add` 函数时，`assembler-s390.h` 中的类和方法会被用来生成 S390 架构的加法指令，将 `a` 和 `b` 的值加载到寄存器，执行加法操作，并将结果存储起来。

**代码逻辑推理（假设输入与输出）：**

假设我们想生成一个将寄存器 `r1` 的值加到寄存器 `r2` 的指令，并假设 `r1` 的代码是 1，`r2` 的代码是 2，`agr` 指令的操作码是 `0x1A` (这是一个假设的简化值)。

**假设输入：**
- 指令：`agr` (Add GR)
- 目标寄存器 `r1`：代码 1
- 源寄存器 `r2`：代码 2

**相关代码片段（来自头文件）：**

```c++
#define DECLARE_S390_RR_INSTRUCTIONS(name, op_name, op_value) \
  inline void name(Register r1, Register r2) {                \
    rr_format(op_name, r1.code(), r2.code());                 \
  }

inline void rr_format(Opcode opcode, int f1, int f2) {
  emit2bytes(getfield<uint16_t, 2, 0, 8>(opcode) |
             getfield<uint16_t, 2, 8, 12>(f1) |
             getfield<uint16_t, 2, 12, 16>(f2));
}
```

**推理过程：**

1. 调用 `assembler.agr(r1, r2)`。
2. `agr` 函数会调用 `rr_format(AGR, r1.code(), r2.code())`。
3. 假设 `AGR` 的 `op_value` (也就是 `opcode`) 是 `0x1A`。
4. `rr_format` 函数会将操作码、`r1` 的代码 (1) 和 `r2` 的代码 (2) 组合成一个 2 字节的机器指令。
5. 最终生成的 2 字节机器码（十六进制）可能是 `0x1A12` （具体取决于 `getfield` 的位操作）。

**假设输出（机器码）：** `0x1A12` (这是一个简化的假设，实际情况更复杂)。

**用户常见的编程错误：**

1. **使用了错误的寄存器：** 例如，某些指令可能只允许使用特定的寄存器，如果使用了错误的寄存器，会导致生成的代码无法正确执行或崩溃。

   ```c++
   // 假设 lgr 指令需要两个通用寄存器
   assembler.lgr(r1, f0); // 错误：f0 是浮点寄存器，可能导致错误
   ```

2. **提供了超出范围的立即数：** 某些指令的操作数有位数限制，如果提供的立即数超出了这个范围，会导致指令编码错误。

   ```c++
   // 假设某些指令的立即数是 16 位的
   assembler.addi(r1, Operand(0xFFFFFFFF)); // 错误：0xFFFFFFFF 超出了 16 位有符号数的范围
   ```

3. **内存地址计算错误：** 在使用 `MemOperand` 时，如果基址寄存器或偏移量计算错误，会导致访问错误的内存地址。

   ```c++
   // 假设需要访问的地址是基址寄存器 r3 加上偏移 8
   assembler.lg(r1, MemOperand(r3, 16)); // 错误：偏移量错误，访问了错误的内存位置
   ```

**第1部分功能归纳：**

`v8/src/codegen/s390/assembler-s390.h` 的第1部分主要定义了用于在 V8 引擎中为 S390 架构生成机器指令的基础结构和类。它提供了：

-  `Assembler` 类作为生成机器码的核心工具。
-  `Operand` 和 `MemOperand` 类用于表示指令的操作数。
-  基本的指令生成方法和格式化函数。
-  处理标签和跳转的机制。

总而言之，这个头文件是 V8 引擎在 S390 架构上进行代码生成的核心组件，它提供了一种方便且类型安全的方式来构建底层的机器指令。

### 提示词
```
这是目录为v8/src/codegen/s390/assembler-s390.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/assembler-s390.h以.tq结尾，那它是个v8 torque源代码，
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
// modification, are permitted provided that the following conditions
// are met:
//
// - Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// - Redistribution in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the
// distribution.
//
// - Neither the name of Sun Microsystems or the names of contributors may
// be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.

// The original source code covered by the above license above has been
// modified significantly by Google Inc.
// Copyright 2014 the V8 project authors. All rights reserved.

// A light-weight S390 Assembler
// Generates user mode instructions for z/Architecture

#ifndef V8_CODEGEN_S390_ASSEMBLER_S390_H_
#define V8_CODEGEN_S390_ASSEMBLER_S390_H_
#include <stdio.h>
#include <memory>
#if V8_HOST_ARCH_S390X && !V8_OS_ZOS
// elf.h include is required for auxv check for STFLE facility used
// for hardware detection, which is sensible only on s390 hosts.
#include <elf.h>
#endif

#include <fcntl.h>
#include <unistd.h>

#include "src/base/platform/platform.h"
#include "src/codegen/assembler.h"
#include "src/codegen/external-reference.h"
#include "src/codegen/label.h"
#include "src/codegen/s390/constants-s390.h"
#include "src/codegen/s390/register-s390.h"
#include "src/objects/smi.h"

namespace v8 {
namespace internal {

class SafepointTableBuilder;

// -----------------------------------------------------------------------------
// Machine instruction Operands

// Class Operand represents a shifter operand in data processing instructions
// defining immediate numbers and masks
class V8_EXPORT_PRIVATE Operand {
 public:
  // immediate
  V8_INLINE explicit Operand(intptr_t immediate,
                             RelocInfo::Mode rmode = RelocInfo::NO_INFO)
      : rmode_(rmode) {
    value_.immediate = immediate;
  }
  V8_INLINE static Operand Zero() { return Operand(static_cast<intptr_t>(0)); }
  V8_INLINE explicit Operand(const ExternalReference& f)
      : rmode_(RelocInfo::EXTERNAL_REFERENCE) {
    value_.immediate = static_cast<intptr_t>(f.address());
  }
  explicit Operand(Handle<HeapObject> handle);
  V8_INLINE explicit Operand(Tagged<Smi> value) : rmode_(RelocInfo::NO_INFO) {
    value_.immediate = static_cast<intptr_t>(value.ptr());
  }

  // rm
  V8_INLINE explicit Operand(Register rm);

  static Operand EmbeddedNumber(double value);  // Smi or HeapNumber

  // Return true if this is a register operand.
  V8_INLINE bool is_reg() const { return rm_.is_valid(); }

  bool must_output_reloc_info(const Assembler* assembler) const;

  inline intptr_t immediate() const {
    DCHECK(!rm_.is_valid());
    DCHECK(!is_heap_number_request());
    return value_.immediate;
  }

  HeapNumberRequest heap_number_request() const {
    DCHECK(is_heap_number_request());
    return value_.heap_number_request;
  }

  inline void setBits(int n) {
    value_.immediate =
        (static_cast<uint32_t>(value_.immediate) << (32 - n)) >> (32 - n);
  }

  Register rm() const { return rm_; }

  bool is_heap_number_request() const {
    DCHECK_IMPLIES(is_heap_number_request_, !rm_.is_valid());
    DCHECK_IMPLIES(is_heap_number_request_,
                   rmode_ == RelocInfo::FULL_EMBEDDED_OBJECT ||
                       rmode_ == RelocInfo::CODE_TARGET);
    return is_heap_number_request_;
  }

  RelocInfo::Mode rmode() const { return rmode_; }

 private:
  Register rm_ = no_reg;
  union Value {
    Value() {}
    HeapNumberRequest heap_number_request;  // if is_heap_number_request_
    intptr_t immediate;                     // otherwise
  } value_;                                 // valid if rm_ == no_reg
  bool is_heap_number_request_ = false;

  RelocInfo::Mode rmode_;

  friend class Assembler;
  friend class MacroAssembler;
};

using Disp = int32_t;

// Class MemOperand represents a memory operand in load and store instructions
// On S390, we have various flavours of memory operands:
//   1) a base register + 16 bit unsigned displacement
//   2) a base register + index register + 16 bit unsigned displacement
//   3) a base register + index register + 20 bit signed displacement
class V8_EXPORT_PRIVATE MemOperand {
 public:
  explicit MemOperand(Register rx, Disp offset = 0);
  explicit MemOperand(Register rx, Register rb, Disp offset = 0);

  int32_t offset() const { return offset_; }
  uint32_t getDisplacement() const { return offset(); }

  // Base register
  Register rb() const {
    DCHECK(baseRegister != no_reg);
    return baseRegister;
  }

  Register getBaseRegister() const { return rb(); }

  // Index Register
  Register rx() const {
    DCHECK(indexRegister != no_reg);
    return indexRegister;
  }
  Register getIndexRegister() const { return rx(); }

 private:
  Register baseRegister;   // base
  Register indexRegister;  // index
  int32_t offset_;         // offset

  friend class Assembler;
};

class DeferredRelocInfo {
 public:
  DeferredRelocInfo() {}
  DeferredRelocInfo(int position, RelocInfo::Mode rmode, intptr_t data)
      : position_(position), rmode_(rmode), data_(data) {}

  int position() const { return position_; }
  RelocInfo::Mode rmode() const { return rmode_; }
  intptr_t data() const { return data_; }

 private:
  int position_;
  RelocInfo::Mode rmode_;
  intptr_t data_;
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

  static RegList DefaultTmpList();
  static DoubleRegList DefaultFPTmpList();

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

  // Label operations & relative jumps (PPUM Appendix D)
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

  void bind(Label* L);  // binds an unbound label L to the current code position

  // Links a label at the current pc_offset().  If already bound, returns the
  // bound position.  If already linked, returns the position of the prior link.
  // Otherwise, returns the current pc_offset().
  int link(Label* L);

  // Returns the branch offset to the given label from the current code position
  // Links the label to the current position if it is still unbound
  int branch_offset(Label* L) { return link(L) - pc_offset(); }

  void load_label_offset(Register r1, Label* L);

  // Read/Modify the code target address in the branch/call instruction at pc.
  // The isolate argument is unused (and may be nullptr) when skipping flushing.
  V8_INLINE static Address target_address_at(Address pc, Address constant_pool);

  // Read/Modify the code target address in the branch/call instruction at pc.
  inline static Tagged_t target_compressed_address_at(Address pc,
                                                      Address constant_pool);
  V8_INLINE static void set_target_address_at(
      Address pc, Address constant_pool, Address target,
      WritableJitAllocation* jit_allocation,
      ICacheFlushMode icache_flush_mode = FLUSH_ICACHE_IF_NEEDED);

  inline static void set_target_compressed_address_at(
      Address pc, Address constant_pool, Tagged_t target,
      WritableJitAllocation* jit_allocation,
      ICacheFlushMode icache_flush_mode = FLUSH_ICACHE_IF_NEEDED);

  inline Handle<Object> code_target_object_handle_at(Address pc);
  inline Handle<HeapObject> compressed_embedded_object_handle_at(
      Address pc, Address constant_pool);

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

  // Here we are patching the address in the IIHF/IILF instruction pair.
  // These values are used in the serialization process and must be zero for
  // S390 platform, as Code, Embedded Object or External-reference pointers
  // are split across two consecutive instructions and don't exist separately
  // in the code, so the serializer should not step forwards in memory after
  // a target is resolved and written.
  static constexpr int kSpecialTargetSize = 0;
// Number of bytes for instructions used to store pointer sized constant.
  static constexpr int kBytesForPtrConstant = 12;  // IIHF + IILF

  RegList* GetScratchRegisterList() { return &scratch_register_list_; }
  DoubleRegList* GetScratchDoubleRegisterList() {
    return &scratch_double_register_list_;
  }

  // ---------------------------------------------------------------------------
  // InstructionStream generation

  template <class T, int size, int lo, int hi>
  inline T getfield(T value) {
    DCHECK(lo < hi);
    DCHECK_GT(size, 0);
    int mask = hi - lo;
    int shift = size * 8 - hi;
    uint32_t mask_value = (mask == 32) ? 0xffffffff : (1 << mask) - 1;
    return (value & mask_value) << shift;
  }

#define DECLARE_S390_RIL_AB_INSTRUCTIONS(name, op_name, op_value) \
  template <class R1>                                             \
  inline void name(R1 r1, const Operand& i2) {                    \
    ril_format(op_name, r1.code(), i2.immediate());               \
  }
#define DECLARE_S390_RIL_C_INSTRUCTIONS(name, op_name, op_value) \
  inline void name(Condition m1, const Operand& i2) {            \
    ril_format(op_name, m1, i2.immediate());                     \
  }

  inline void ril_format(Opcode opcode, int f1, int f2) {
    uint32_t op1 = opcode >> 4;
    uint32_t op2 = opcode & 0xf;
    emit6bytes(
        getfield<uint64_t, 6, 0, 8>(op1) | getfield<uint64_t, 6, 8, 12>(f1) |
        getfield<uint64_t, 6, 12, 16>(op2) | getfield<uint64_t, 6, 16, 48>(f2));
  }
  S390_RIL_A_OPCODE_LIST(DECLARE_S390_RIL_AB_INSTRUCTIONS)
  S390_RIL_B_OPCODE_LIST(DECLARE_S390_RIL_AB_INSTRUCTIONS)
  S390_RIL_C_OPCODE_LIST(DECLARE_S390_RIL_C_INSTRUCTIONS)
#undef DECLARE_S390_RIL_AB_INSTRUCTIONS
#undef DECLARE_S390_RIL_C_INSTRUCTIONS

#define DECLARE_S390_RR_INSTRUCTIONS(name, op_name, op_value) \
  inline void name(Register r1, Register r2) {                \
    rr_format(op_name, r1.code(), r2.code());                 \
  }                                                           \
  inline void name(DoubleRegister r1, DoubleRegister r2) {    \
    rr_format(op_name, r1.code(), r2.code());                 \
  }                                                           \
  inline void name(Condition m1, Register r2) {               \
    rr_format(op_name, m1, r2.code());                        \
  }

  inline void rr_format(Opcode opcode, int f1, int f2) {
    emit2bytes(getfield<uint16_t, 2, 0, 8>(opcode) |
               getfield<uint16_t, 2, 8, 12>(f1) |
               getfield<uint16_t, 2, 12, 16>(f2));
  }
  S390_RR_OPCODE_LIST(DECLARE_S390_RR_INSTRUCTIONS)
#undef DECLARE_S390_RR_INSTRUCTIONS

#define DECLARE_S390_RRD_INSTRUCTIONS(name, op_name, op_value) \
  template <class R1, class R2, class R3>                      \
  inline void name(R1 r1, R3 r3, R2 r2) {                      \
    rrd_format(op_name, r1.code(), r3.code(), r2.code());      \
  }
  inline void rrd_format(Opcode opcode, int f1, int f2, int f3) {
    emit4bytes(getfield<uint32_t, 4, 0, 16>(opcode) |
               getfield<uint32_t, 4, 16, 20>(f1) |
               getfield<uint32_t, 4, 24, 28>(f2) |
               getfield<uint32_t, 4, 28, 32>(f3));
  }
  S390_RRD_OPCODE_LIST(DECLARE_S390_RRD_INSTRUCTIONS)
#undef DECLARE_S390_RRD_INSTRUCTIONS

#define DECLARE_S390_RRE_INSTRUCTIONS(name, op_name, op_value) \
  template <class R1, class R2>                                \
  inline void name(R1 r1, R2 r2) {                             \
    rre_format(op_name, r1.code(), r2.code());                 \
  }
  inline void rre_format(Opcode opcode, int f1, int f2) {
    emit4bytes(getfield<uint32_t, 4, 0, 16>(opcode) |
               getfield<uint32_t, 4, 24, 28>(f1) |
               getfield<uint32_t, 4, 28, 32>(f2));
  }
  S390_RRE_OPCODE_LIST(DECLARE_S390_RRE_INSTRUCTIONS)
  // Special format
  void lzdr(DoubleRegister r1) { rre_format(LZDR, r1.code(), 0); }
  void lzer(DoubleRegister r1) { rre_format(LZER, r1.code(), 0); }
#undef DECLARE_S390_RRE_INSTRUCTIONS

#define DECLARE_S390_RX_INSTRUCTIONS(name, op_name, op_value)            \
  template <class R1>                                                    \
  inline void name(R1 r1, Register x2, Register b2, const Operand& d2) { \
    rx_format(op_name, r1.code(), x2.code(), b2.code(), d2.immediate()); \
  }                                                                      \
  template <class R1>                                                    \
  inline void name(R1 r1, const MemOperand& opnd) {                      \
    name(r1, opnd.getIndexRegister(), opnd.getBaseRegister(),            \
         Operand(opnd.getDisplacement()));                               \
  }

  inline void rx_format(Opcode opcode, int f1, int f2, int f3, int f4) {
    DCHECK(is_uint8(opcode));
    DCHECK(is_uint12(f4));
    emit4bytes(
        getfield<uint32_t, 4, 0, 8>(opcode) | getfield<uint32_t, 4, 8, 12>(f1) |
        getfield<uint32_t, 4, 12, 16>(f2) | getfield<uint32_t, 4, 16, 20>(f3) |
        getfield<uint32_t, 4, 20, 32>(f4));
  }
  S390_RX_A_OPCODE_LIST(DECLARE_S390_RX_INSTRUCTIONS)

  void bc(Condition cond, const MemOperand& opnd) {
    bc(cond, opnd.getIndexRegister(), opnd.getBaseRegister(),
       Operand(opnd.getDisplacement()));
  }
  void bc(Condition cond, Register x2, Register b2, const Operand& d2) {
    rx_format(BC, cond, x2.code(), b2.code(), d2.immediate());
  }
#undef DECLARE_S390_RX_INSTRUCTIONS

#define DECLARE_S390_RXY_INSTRUCTIONS(name, op_name, op_value)            \
  template <class R1, class R2>                                           \
  inline void name(R1 r1, R2 r2, Register b2, const Operand& d2) {        \
    rxy_format(op_name, r1.code(), r2.code(), b2.code(), d2.immediate()); \
  }                                                                       \
  template <class R1>                                                     \
  inline void name(R1 r1, const MemOperand& opnd) {                       \
    name(r1, opnd.getIndexRegister(), opnd.getBaseRegister(),             \
         Operand(opnd.getDisplacement()));                                \
  }

  inline void rxy_format(Opcode opcode, int f1, int f2, int f3, int f4) {
    DCHECK(is_uint16(opcode));
    DCHECK(is_int20(f4));
    emit6bytes(getfield<uint64_t, 6, 0, 8>(opcode >> 8) |
               getfield<uint64_t, 6, 8, 12>(f1) |
               getfield<uint64_t, 6, 12, 16>(f2) |
               getfield<uint64_t, 6, 16, 20>(f3) |
               getfield<uint64_t, 6, 20, 32>(f4 & 0x0fff) |
               getfield<uint64_t, 6, 32, 40>(f4 >> 12) |
               getfield<uint64_t, 6, 40, 48>(opcode & 0x00ff));
  }
  S390_RXY_A_OPCODE_LIST(DECLARE_S390_RXY_INSTRUCTIONS)

  void pfd(Condition cond, const MemOperand& opnd) {
    pfd(cond, opnd.getIndexRegister(), opnd.getBaseRegister(),
        Operand(opnd.getDisplacement()));
  }
  void pfd(Condition cond, Register x2, Register b2, const Operand& d2) {
    rxy_format(PFD, cond, x2.code(), b2.code(), d2.immediate());
  }
#undef DECLARE_S390_RXY_INSTRUCTIONS

  inline void rsy_format(Opcode op, int f1, int f2, int f3, int f4) {
    DCHECK(is_int20(f4));
    DCHECK(is_uint16(op));
    uint64_t code =
        (getfield<uint64_t, 6, 0, 8>(op >> 8) |
         getfield<uint64_t, 6, 8, 12>(f1) | getfield<uint64_t, 6, 12, 16>(f2) |
         getfield<uint64_t, 6, 16, 20>(f3) |
         getfield<uint64_t, 6, 20, 32>(f4 & 0x0fff) |
         getfield<uint64_t, 6, 32, 40>(f4 >> 12) |
         getfield<uint64_t, 6, 40, 48>(op & 0xff));
    emit6bytes(code);
  }

#define DECLARE_S390_RSY_A_INSTRUCTIONS(name, op_name, op_value)            \
  void name(Register r1, Register r3, Register b2,                          \
            const Operand& d2 = Operand::Zero()) {                          \
    rsy_format(op_name, r1.code(), r3.code(), b2.code(), d2.immediate());   \
  }                                                                         \
  void name(Register r1, Register r3, Operand d2) { name(r1, r3, r0, d2); } \
  void name(Register r1, Register r3, const MemOperand& opnd) {             \
    name(r1, r3, opnd.getBaseRegister(), Operand(opnd.getDisplacement()));  \
  }
  S390_RSY_A_OPCODE_LIST(DECLARE_S390_RSY_A_INSTRUCTIONS)
#undef DECLARE_S390_RSY_A_INSTRUCTIONS

#define DECLARE_S390_RSY_B_INSTRUCTIONS(name, op_name, op_value)           \
  void name(Register r1, Condition m3, Register b2, const Operand& d2) {   \
    rsy_format(op_name, r1.code(), m3, b2.code(), d2.immediate());         \
  }                                                                        \
  void name(Register r1, Condition m3, const MemOperand& opnd) {           \
    name(r1, m3, opnd.getBaseRegister(), Operand(opnd.getDisplacement())); \
  }
  S390_RSY_B_OPCODE_LIST(DECLARE_S390_RSY_B_INSTRUCTIONS)
#undef DECLARE_S390_RSY_B_INSTRUCTIONS

  inline void rs_format(Opcode op, int f1, int f2, int f3, const int f4) {
    uint32_t code =
        getfield<uint32_t, 4, 0, 8>(op) | getfield<uint32_t, 4, 8, 12>(f1) |
        getfield<uint32_t, 4, 12, 16>(f2) | getfield<uint32_t, 4, 16, 20>(f3) |
        getfield<uint32_t, 4, 20, 32>(f4);
    emit4bytes(code);
  }

#define DECLARE_S390_RS_A_INSTRUCTIONS(name, op_name, op_value)            \
  void name(Register r1, Register r3, Register b2, const Operand& d2) {    \
    rs_format(op_name, r1.code(), r3.code(), b2.code(), d2.immediate());   \
  }                                                                        \
  void name(Register r1, Register r3, const MemOperand& opnd) {            \
    name(r1, r3, opnd.getBaseRegister(), Operand(opnd.getDisplacement())); \
  }
  S390_RS_A_OPCODE_LIST(DECLARE_S390_RS_A_INSTRUCTIONS)
#undef DECLARE_S390_RS_A_INSTRUCTIONS

#define DECLARE_S390_RS_B_INSTRUCTIONS(name, op_name, op_value)            \
  void name(Register r1, Condition m3, Register b2, const Operand& d2) {   \
    rs_format(op_name, r1.code(), m3, b2.code(), d2.immediate());          \
  }                                                                        \
  void name(Register r1, Condition m3, const MemOperand& opnd) {           \
    name(r1, m3, opnd.getBaseRegister(), Operand(opnd.getDisplacement())); \
  }
  S390_RS_B_OPCODE_LIST(DECLARE_S390_RS_B_INSTRUCTIONS)
#undef DECLARE_S390_RS_B_INSTRUCTIONS

#define DECLARE_S390_RS_SHIFT_FORMAT(name, opcode)                             \
  void name(Register r1, Register r2, const Operand& opnd = Operand::Zero()) { \
    rs_format(opcode, r1.code(), r0.code(), r2.code(), opnd.immediate());      \
  }                                                                            \
  void name(Register r1, const Operand& opnd) {                                \
    rs_format(opcode, r1.code(), r0.code(), r0.code(), opnd.immediate());      \
  }
  DECLARE_S390_RS_SHIFT_FORMAT(sll, SLL)
  DECLARE_S390_RS_SHIFT_FORMAT(srl, SRL)
  DECLARE_S390_RS_SHIFT_FORMAT(sla, SLA)
  DECLARE_S390_RS_SHIFT_FORMAT(sra, SRA)
  DECLARE_S390_RS_SHIFT_FORMAT(sldl, SLDL)
  DECLARE_S390_RS_SHIFT_FORMAT(srda, SRDA)
  DECLARE_S390_RS_SHIFT_FORMAT(srdl, SRDL)
#undef DECLARE_S390_RS_SHIFT_FORMAT

  inline void rxe_format(Opcode op, int f1, int f2, int f3, int f4,
                         int f5 = 0) {
    DCHECK(is_uint12(f4));
    DCHECK(is_uint16(op));
    uint64_t code =
        (getfield<uint64_t, 6, 0, 8>(op >> 8) |
         getfield<uint64_t, 6, 8, 12>(f1) | getfield<uint64_t, 6, 12, 16>(f2) |
         getfield<uint64_t, 6, 16, 20>(f3) |
         getfield<uint64_t, 6, 20, 32>(f4 & 0x0fff) |
         getfield<uint64_t, 6, 32, 36>(f5) |
         getfield<uint64_t, 6, 40, 48>(op & 0xff));
    emit6bytes(code);
  }

#define DECLARE_S390_RXE_INSTRUCTIONS(name, op_name, op_value)                \
  void name(Register r1, Register x2, Register b2, const Operand& d2,         \
            Condition m3 = static_cast<Condition>(0)) {                       \
    rxe_format(op_name, r1.code(), x2.code(), b2.code(), d2.immediate(), m3); \
  }                                                                           \
  template <class _R1Type>                                                    \
  void name(_R1Type r1, const MemOperand& opnd) {                             \
    name(Register::from_code(r1.code()), opnd.rx(), opnd.rb(),                \
         Operand(opnd.offset()));                                             \
  }
  S390_RXE_OPCODE_LIST(DECLARE_S390_RXE_INSTRUCTIONS)
#undef DECLARE_S390_RXE_INSTRUCTIONS

  inline void ri_format(Opcode opcode, int f1, int f2) {
    uint32_t op1 = opcode >> 4;
    uint32_t op2 = opcode & 0xf;
    emit4bytes(
        getfield<uint32_t, 4, 0, 8>(op1) | getfield<uint32_t, 4, 8, 12>(f1) |
        getfield<uint32_t, 4, 12, 16>(op2) | getfield<uint32_t, 4, 16, 32>(f2));
  }

#define DECLARE_S390_RI_A_INSTRUCTIONS(name, op_name, op_value)    \
  void name(Register r, const Operand& i2) {                       \
    DCHECK(is_uint12(op_name));                                    \
    DCHECK(is_uint16(i2.immediate()) || is_int16(i2.immediate())); \
    ri_format(op_name, r.code(), i2.immediate());                  \
  }
  S390_RI_A_OPCODE_LIST(DECLARE_S390_RI_A_INSTRUCTIONS)
#undef DECLARE_S390_RI_A_INSTRUCTIONS

#define DECLARE_S390_RI_B_INSTRUCTIONS(name, op_name, op_value)       \
  void name(Register r1, const Operand& imm) {                        \
    /* 2nd argument encodes # of halfwords, so divide by 2. */        \
    int16_t numHalfwords = static_cast<int16_t>(imm.immediate()) / 2; \
    Operand halfwordOp = Operand(numHalfwords);                       \
    halfwordOp.setBits(16);                                           \
    ri_format(op_name, r1.code(), halfwordOp.immediate());            \
  }
  S390_RI_B_OPCODE_LIST(DECLARE_S390_RI_B_INSTRUCTIONS)
#undef DECLARE_S390_RI_B_INSTRUCTIONS

#define DECLARE_S390_RI_C_INSTRUCTIONS(name, op_name, op_value) \
  void name(Condition m, const Operand& i2) {                   \
    DCHECK(is_uint12(op_name));                                 \
    DCHECK(is_uint4(m));                                        \
    DCHECK(op_name == BRC ? is_int16(i2.immediate())            \
                          : is_uint16(i2.immediate()));         \
    ri_format(op_name, m, i2.immediate());                      \
  }
  S390_RI_C_OPCODE_LIST(DECLARE_S390_RI_C_INSTRUCTIONS)
#undef DECLARE_S390_RI_C_INSTRUCTIONS

  inline void rrf_format(Opcode op, int f1, int f2, int f3, int f4) {
    uint32_t code =
        getfield<uint32_t, 4, 0, 16>(op) | getfield<uint32_t, 4, 16, 20>(f1) |
        getfield<uint32_t, 4, 20, 24>(f2) | getfield<uint32_t, 4, 24, 28>(f3) |
        getfield<uint32_t, 4, 28, 32>(f4);
    emit4bytes(code);
  }

#define DECLARE_S390_RRF_A_INSTRUCTIONS(name, op_name, op_value)   \
  void name(Register r1, Condition m4, Register r2, Register r3) { \
    rrf_format(op_name, r3.code(), m4, r1.code(), r2.code());      \
  }                                                                \
  void name(Register r1, Register r2, Register r3) {               \
    name(r1, Condition(0), r2, r3);                                \
  }
  S390_RRF_A_OPCODE_LIST(DECLARE_S390_RRF_A_INSTRUCTIONS)
#undef DECLARE_S390_RRF_A_INSTRUCTIONS

#define DECLARE_S390_RRF_B_INSTRUCTIONS(name, op_name, op_value)   \
  void name(Register r1, Condition m4, Register r2, Register r3) { \
    rrf_format(op_name, r3.code(), m4, r1.code(), r2.code());      \
  }                                                                \
  void name(Register r1, Register r2, Register r3) {               \
    name(r1, Condition(0), r2, r3);                                \
  }
  S390_RRF_B_OPCODE_LIST(DECLARE_S390_RRF_B_INSTRUCTIONS)
#undef DECLARE_S390_RRF_B_INSTRUCTIONS

#define DECLARE_S390_RRF_C_INSTRUCTIONS(name, op_name, op_value) \
  template <class R1, class R2>                                  \
  void name(Condition m3, Condition m4, R1 r1, R2 r2) {          \
    rrf_format(op_name, m3, m4, r1.code(), r2.code());           \
  }                                                              \
  template <class R1, class R2>                                  \
  void name(Condition m3, R1 r1, R2 r2) {                        \
    name(m3, Condition(0), r1, r2);                              \
  }
  S390_RRF_C_OPCODE_LIST(DECLARE_S390_RRF_C_INSTRUCTIONS)
#undef DECLARE_S390_RRF_C_INSTRUCTIONS

#define DECLARE_S390_RRF_D_INSTRUCTIONS(name, op_name, op_value) \
  template <class R1, class R2>                                  \
  void name(Condition m3, Condition m4, R1 r1, R2 r2) {          \
    rrf_format(op_name, m3, m4, r1.code(), r2.code());           \
  }                                                              \
  template <class R1, class R2>                                  \
  void name(Condition m3, R1 r1, R2 r2) {                        \
    name(m3, Condition(0), r1, r2);                              \
  }
  S390_RRF_D_OPCODE_LIST(DECLARE_S390_RRF_D_INSTRUCTIONS)
#undef DECLARE_S390_RRF_D_INSTRUCTIONS

#define DECLARE_S390_RRF_E_INSTRUCTIONS(name, op_name, op_value) \
  template <class M3, class M4, class R1, class R2>              \
  void name(M3 m3, M4 m4, R1 r1, R2 r2) {                        \
    rrf_format(op_name, m3, m4, r1.code(), r2.code());           \
  }                                                              \
  template <class M3, class R1, class R2>                        \
  void name(M3 m3, R1 r1, R2 r2) {                               \
    name(m3, Condition(0), r1, r2);                              \
  }
  S390_RRF_E_OPCODE_LIST(DECLARE_S390_RRF_E_INSTRUCTIONS)
#undef DECLARE_S390_RRF_E_INSTRUCTIONS

  inline void rsi_format(Opcode op, int f1, int f2, int f3) {
    DCHECK(is_uint8(op));
    DCHECK(is_uint16(f3) || is_int16(f3));
    uint32_t code =
        getfield<uint32_t, 4, 0, 8>(op) | getfield<uint32_t, 4, 8, 12>(f1) |
        getfield<uint32_t, 4, 12, 16>(f2) | getfield<uint32_t, 4, 16, 32>(f3);
    emit4bytes(code);
  }

#define DECLARE_S390_RSI_INSTRUCTIONS(name, op_name, op_value) \
  void name(Register r1, Register r3, const Operand& i2) {     \
    rsi_format(op_name, r1.code(), r3.code(), i2.immediate()); \
  }
  S390_RSI_OPCODE_LIST(DECLARE_S390_RSI_INSTRUCTIONS)
#undef DECLARE_S390_RSI_INSTRUCTIONS

  inline void rsl_format(Opcode op, uint16_t f1, int f2, int f3, int f4,
                         int f5) {
    DCHECK(is_uint16(op));
    uint64_t code =
        getfield<uint64_t, 6, 0, 8>(op >> 8) |
        getfield<uint64_t, 6, 8, 16>(f1) | getfield<uint64_t, 6, 16, 20>(f2) |
        getfield<uint64_t, 6, 20, 32>(f3) | getfield<uint64_t, 6, 32, 36>(f4) |
        getfield<uint64_t, 6, 36, 40>(f5) |
        getfield<uint64_t, 6, 40, 48>(op & 0x00FF);
    emit6bytes(code);
  }

#define DECLARE_S390_RSL_A_INSTRUCTIONS(name, op_name, op_value) \
  void name(const Operand& l1, Register b1, const Operand& d1) { \
    uint16_t L = static_cast<uint16_t>(l1.immediate() << 8);     \
    rsl_format(op_name, L, b1.code(), d1.immediate(), 0, 0);     \
  }
  S390_RSL_A_OPCODE_LIST(DECLARE_S390_RSL_A_INSTRUCTIONS)
#undef DECLARE_S390_RSL_A_INSTRUCTIONS

#define DECLARE_S390_RSL_B_INSTRUCTIONS(name, op_name, op_value)            \
  void name(const Operand& l2, Register b2, const Operand& d2, Register r1, \
            Condition m3) {                                                 \
    uint16_t L = static_cast<uint16_t>(l2.immediate());                     \
    rsl_format(op_name, L, b2.code(), d2.immediate(), r1.code(), m3);       \
  }
  S390_RSL_B_OPCODE_LIST(DECLARE_S390_RSL_B_INSTRUCTIONS)
#undef DECLARE_S390_RSL_B_INSTRUCTIONS

  inline void s_format(Opcode op, int f1, int f2) {
    DCHECK_NE(op & 0xff00, 0);
    DCHECK(is_uint12(f2));
    uint32_t code = getfield<uint32_t, 4, 0, 16>(op) |
                    getfield<uint32_t, 4, 16, 20>(f1) |
                    getfield<uint32_t, 4, 20, 32>(f2);
    emit4bytes(code);
  }

#define DECLARE_S390_S_INSTRUCTIONS(name, op_name, op_value) \
  void name(Register b1, const Operand& d2) {                \
    Opcode op = op_name;                                     \
    if ((op & 0xFF00) == 0) {                                \
      op = (Opcode)(op << 8);                                \
    }                                                        \
    s_format(op, b1.code(), d2.immediate());                 \
  }                                                          \
  void name(const MemOperand& opnd) {                        \
    Operand d2 = Operand(opnd.getDisplacement());            \
    name(opnd.getBaseRegister(), d2);                        \
  }
  S390_S_OPCODE_LIST(DECLARE_S390_S_INSTRUCTIONS)
#undef DECLARE_S390_S_INSTRUCTIONS

  inline void si_format(Opcode op, int f1, int f2, int f3) {
    uint32_t code =
        getfield<uint32_t, 4, 0, 8>(op) | getfield<uint32_t, 4, 8, 16>(f1) |
        getfield<uint32_t, 4, 16, 20>(f2) | getfield<uint32_t, 4, 20, 32>(f3);
    emit4bytes(code);
  }

#define DECLARE_S390_SI_INSTRUCTIONS(name, op_name, op_value)          \
  void name(const Operand& i2, Register b1, const Operand& d1) {       \
    si_format(op_name, i2.immediate(), b1.code(), d1.immediate());
```