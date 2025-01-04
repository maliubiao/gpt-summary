Response: The user wants a summary of the C++ source code file `v8/src/compiler/backend/loong64/code-generator-loong64.cc`.
The file seems to be part of the V8 JavaScript engine, specifically for the LoongArch 64-bit architecture.
It's likely responsible for generating machine code from a higher-level intermediate representation used by the V8 compiler.

Key functionalities I expect to find:
- **Instruction processing:** The code will iterate through instructions and translate them to LoongArch64 assembly.
- **Operand conversion:** It will handle different types of operands (registers, immediates, memory locations).
- **Code emission:** It will use a `MacroAssembler` to write the assembly code.
- **Architecture-specific details:** The code will contain LoongArch64 instruction mnemonics and addressing modes.
- **Interaction with the V8 runtime:** It might call into runtime functions for certain operations.
- **Support for JavaScript features:** It will likely have logic to handle JavaScript-specific concepts like object properties, function calls, and garbage collection.

The prompt also asks to illustrate the connection with JavaScript using an example. I'll need to identify a feature handled by this code generator and show how it's used in JavaScript. Function calls and basic arithmetic operations are good candidates.
这是 V8 JavaScript 引擎中用于 LoongArch 64 位架构的代码生成器的第一部分。它的主要功能是将 V8 编译器生成的中间表示（IR）指令转换为 LoongArch64 汇编代码。

**主要功能归纳：**

1. **指令处理和代码生成:**  遍历输入的 `Instruction` 序列，并为每个指令生成相应的 LoongArch64 汇编代码。这涉及到识别指令的类型和操作数。
2. **操作数转换:** 提供了一个 `Loong64OperandConverter` 类，用于将 V8 内部的 `InstructionOperand` 转换为 LoongArch64 汇编器可以理解的操作数格式，例如寄存器、立即数和内存操作数。
3. **内联和外联代码处理:**  对于一些复杂的或者需要特殊处理的情况，使用了 "out-of-line code" (OOL) 的概念，例如记录写屏障 (RecordWriteBarrier) 和浮点数的 min/max 操作。这部分代码会在主代码流之外生成，并在需要时通过跳转指令调用。
4. **支持特定的指令模式:**  代码中能看到针对不同寻址模式（例如 `kMode_MRI`, `kMode_MRR`）和内存访问模式的处理。
5. **与运行时交互:** 对于某些操作，例如浮点数运算的特殊情况或需要调用 C++ 标准库函数的情况，会生成调用 C 函数的代码。
6. **处理尾调用:** 实现了尾调用优化相关的代码生成逻辑。
7. **支持调试和断点:**  包含生成调试断点指令的功能。
8. **处理代码去优化:** 能够生成在代码需要去优化时跳转到特定内置函数的代码。
9. **原子操作支持:**  包含了生成 LoongArch64 原子操作指令的代码，用于多线程环境下的数据同步。
10. **浮点运算支持:** 实现了各种浮点数运算指令的生成，包括算术运算、比较、类型转换和一些特殊的数学函数 (例如 sin, cos, sqrt)。
11. **整数运算支持:**  实现了各种整数运算指令的生成，包括加减乘除、位运算和移位操作。

**与 JavaScript 功能的关系和 JavaScript 示例：**

这个代码生成器的最终目标是执行 JavaScript 代码。它将高级的 JavaScript 代码通过 V8 的编译流程转换成底层的机器码，使其能够在 LoongArch64 架构的处理器上运行。

**JavaScript 示例：**

假设有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 编译执行这段代码时，`code-generator-loong64.cc` 中的代码会参与生成 `add` 函数的机器码。例如，对于 `a + b` 这个加法操作，代码生成器可能会生成类似于以下的 LoongArch64 汇编指令 (简化示例)：

```assembly
  // 假设 a 在寄存器 r3，b 在寄存器 r4
  add.d  r5, r3, r4  // 将 r3 和 r4 的值相加，结果存储到 r5
  mov    a0, r5      // 将结果移动到返回寄存器 a0
  ret               // 返回
```

**更具体的例子：内联的算术运算**

如果 JavaScript 中有简单的加法操作，例如 `x + 1;`，并且 V8 决定内联这个操作，那么 `code-generator-loong64.cc` 可能会生成类似以下的指令：

```c++
// ... 在 CodeGenerator::AssembleArchInstruction 中处理加法指令 ...
case kLoong64Add_d:
  __ Add_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
  break;
// ...
```

这段 C++ 代码最终会调用 LoongArch64 汇编器的 `Add_d` 方法，生成实际的汇编指令，比如：

```assembly
  // 假设 x 在寄存器 t0，结果存储回 t0
  addi.d t0, t0, 1
```

**再例如，浮点数运算：**

如果 JavaScript 中有浮点数加法 `let z = x + y;`，并且 `x` 和 `y` 是浮点数，那么 `code-generator-loong64.cc` 可能会生成类似以下的指令：

```c++
case kLoong64Float64Add:
  __ fadd_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
            i.InputDoubleRegister(1));
  break;
```

这会生成类似以下的 LoongArch64 浮点数加法指令：

```assembly
  // 假设 x 在浮点寄存器 f0，y 在浮点寄存器 f1，结果存储到 f2
  fadd.d f2, f0, f1
```

总而言之，`code-generator-loong64.cc` 是 V8 将 JavaScript 代码转换为可在 LoongArch64 处理器上执行的机器码的关键组件。它处理各种 JavaScript 构造，并生成相应的底层指令。

Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/code-generator-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/loong64/constants-loong64.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/heap/mutable-page-metadata.h"

namespace v8 {
namespace internal {
namespace compiler {

#define __ masm()->

#define TRACE(...) PrintF(__VA_ARGS__)

// Adds Loong64-specific methods to convert InstructionOperands.
class Loong64OperandConverter final : public InstructionOperandConverter {
 public:
  Loong64OperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  FloatRegister OutputSingleRegister(size_t index = 0) {
    return ToSingleRegister(instr_->OutputAt(index));
  }

  FloatRegister InputSingleRegister(size_t index) {
    return ToSingleRegister(instr_->InputAt(index));
  }

  FloatRegister ToSingleRegister(InstructionOperand* op) {
    // Single (Float) and Double register namespace is same on LOONG64,
    // both are typedefs of FPURegister.
    return ToDoubleRegister(op);
  }

  Register InputOrZeroRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) {
      DCHECK_EQ(0, InputInt32(index));
      return zero_reg;
    }
    return InputRegister(index);
  }

  DoubleRegister InputOrZeroDoubleRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) return kDoubleRegZero;

    return InputDoubleRegister(index);
  }

  DoubleRegister InputOrZeroSingleRegister(size_t index) {
    if (instr_->InputAt(index)->IsImmediate()) return kDoubleRegZero;

    return InputSingleRegister(index);
  }

  Operand InputImmediate(size_t index) {
    Constant constant = ToConstant(instr_->InputAt(index));
    switch (constant.type()) {
      case Constant::kInt32:
        return Operand(constant.ToInt32());
      case Constant::kInt64:
        return Operand(constant.ToInt64());
      case Constant::kFloat32:
        return Operand::EmbeddedNumber(constant.ToFloat32());
      case Constant::kFloat64:
        return Operand::EmbeddedNumber(constant.ToFloat64().value());
      case Constant::kCompressedHeapObject: {
        RootIndex root_index;
        if (gen_->isolate()->roots_table().IsRootHandle(constant.ToHeapObject(),
                                                        &root_index)) {
          CHECK(COMPRESS_POINTERS_BOOL);
          CHECK(V8_STATIC_ROOTS_BOOL || !gen_->isolate()->bootstrapper());
          Tagged_t ptr =
              MacroAssemblerBase::ReadOnlyRootPtr(root_index, gen_->isolate());
          return Operand(ptr);
        }
        return Operand(constant.ToHeapObject());
      }
      case Constant::kExternalReference:
      case Constant::kHeapObject:
        break;
      case Constant::kRpoNumber:
        UNREACHABLE();  // TODO(titzer): RPO immediates on loong64?
    }
    UNREACHABLE();
  }

  Operand InputOperand(size_t index) {
    InstructionOperand* op = instr_->InputAt(index);
    if (op->IsRegister()) {
      return Operand(ToRegister(op));
    }
    return InputImmediate(index);
  }

  MemOperand MemoryOperand(size_t* first_index) {
    const size_t index = *first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
        break;
      case kMode_Root:
        *first_index += 1;
        return MemOperand(kRootRegister, InputInt32(index));
      case kMode_MRI:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputInt32(index + 1));
      case kMode_MRR:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1));
    }
    UNREACHABLE();
  }

  MemOperand MemoryOperand(size_t index = 0) { return MemoryOperand(&index); }

  MemOperand ToMemOperand(InstructionOperand* op) const {
    DCHECK_NOT_NULL(op);
    DCHECK(op->IsStackSlot() || op->IsFPStackSlot());
    return SlotToMemOperand(AllocatedOperand::cast(op)->index());
  }

  MemOperand SlotToMemOperand(int slot) const {
    FrameOffset offset = frame_access_state()->GetFrameOffset(slot);
    return MemOperand(offset.from_stack_pointer() ? sp : fp, offset.offset());
  }
};

static inline bool HasRegisterInput(Instruction* instr, size_t index) {
  return instr->InputAt(index)->IsRegister();
}

namespace {

class OutOfLineRecordWrite final : public OutOfLineCode {
 public:
  OutOfLineRecordWrite(
      CodeGenerator* gen, Register object, Operand offset, Register value,
      RecordWriteMode mode, StubCallMode stub_mode,
      IndirectPointerTag indirect_pointer_tag = kIndirectPointerNullTag)
      : OutOfLineCode(gen),
        object_(object),
        offset_(offset),
        value_(value),
        mode_(mode),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        must_save_lr_(!gen->frame_access_state()->has_frame()),
        zone_(gen->zone()),
        indirect_pointer_tag_(indirect_pointer_tag) {
  }

  void Generate() final {
    // When storing an indirect pointer, the value will always be a
    // full/decompressed pointer.
    if (COMPRESS_POINTERS_BOOL &&
        mode_ != RecordWriteMode::kValueIsIndirectPointer) {
      __ DecompressTagged(value_, value_);
    }

    __ CheckPageFlag(value_, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                     exit());

    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    if (must_save_lr_) {
      // We need to save and restore ra if the frame was elided.
      __ Push(ra);
    }
    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, offset_, save_fp_mode);
    } else if (mode_ == RecordWriteMode::kValueIsIndirectPointer) {
      DCHECK(IsValidIndirectPointerTag(indirect_pointer_tag_));
      __ CallIndirectPointerBarrier(object_, offset_, save_fp_mode,
                                    indirect_pointer_tag_);
#if V8_ENABLE_WEBASSEMBLY
    } else if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      __ CallRecordWriteStubSaveRegisters(object_, offset_, save_fp_mode,
                                          StubCallMode::kCallWasmRuntimeStub);
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      __ CallRecordWriteStubSaveRegisters(object_, offset_, save_fp_mode);
    }
    if (must_save_lr_) {
      __ Pop(ra);
    }
  }

 private:
  Register const object_;
  Operand const offset_;
  Register const value_;
  RecordWriteMode const mode_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode const stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  bool must_save_lr_;
  Zone* zone_;
  IndirectPointerTag indirect_pointer_tag_;
};

#define CREATE_OOL_CLASS(ool_name, masm_ool_name, T)                 \
  class ool_name final : public OutOfLineCode {                      \
   public:                                                           \
    ool_name(CodeGenerator* gen, T dst, T src1, T src2)              \
        : OutOfLineCode(gen), dst_(dst), src1_(src1), src2_(src2) {} \
                                                                     \
    void Generate() final { __ masm_ool_name(dst_, src1_, src2_); }  \
                                                                     \
   private:                                                          \
    T const dst_;                                                    \
    T const src1_;                                                   \
    T const src2_;                                                   \
  }

CREATE_OOL_CLASS(OutOfLineFloat32Max, Float32MaxOutOfLine, FPURegister);
CREATE_OOL_CLASS(OutOfLineFloat32Min, Float32MinOutOfLine, FPURegister);
CREATE_OOL_CLASS(OutOfLineFloat64Max, Float64MaxOutOfLine, FPURegister);
CREATE_OOL_CLASS(OutOfLineFloat64Min, Float64MinOutOfLine, FPURegister);

#undef CREATE_OOL_CLASS

#if V8_ENABLE_WEBASSEMBLY
class WasmOutOfLineTrap : public OutOfLineCode {
 public:
  WasmOutOfLineTrap(CodeGenerator* gen, Instruction* instr)
      : OutOfLineCode(gen), gen_(gen), instr_(instr) {}
  void Generate() override {
    Loong64OperandConverter i(gen_, instr_);
    TrapId trap_id =
        static_cast<TrapId>(i.InputInt32(instr_->InputCount() - 1));
    GenerateCallToTrap(trap_id);
  }

 protected:
  CodeGenerator* gen_;

  void GenerateWithTrapId(TrapId trap_id) { GenerateCallToTrap(trap_id); }

 private:
  void GenerateCallToTrap(TrapId trap_id) {
    gen_->AssembleSourcePosition(instr_);
    // A direct call to a wasm runtime stub defined in this module.
    // Just encode the stub index. This will be patched when the code
    // is added to the native module and copied into wasm code space.
    __ Call(static_cast<Address>(trap_id), RelocInfo::WASM_STUB_CALL);
    ReferenceMap* reference_map = gen_->zone()->New<ReferenceMap>(gen_->zone());
    gen_->RecordSafepoint(reference_map);
    __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
  }

  Instruction* instr_;
};

void RecordTrapInfoIfNeeded(Zone* zone, CodeGenerator* codegen,
                            InstructionCode opcode, Instruction* instr,
                            int pc) {
  const MemoryAccessMode access_mode = AccessModeField::decode(opcode);
  if (access_mode == kMemoryAccessProtectedMemOutOfBounds ||
      access_mode == kMemoryAccessProtectedNullDereference) {
    ReferenceMap* reference_map =
        codegen->zone()->New<ReferenceMap>(codegen->zone());
    // The safepoint has to be recorded at the return address of a call. Address
    // we use as the fake return address in the case of the trap handler is the
    // fault address (here `pc`) + 1. Therefore the safepoint here has to be
    // recorded at pc + 1;
    codegen->RecordSafepoint(reference_map, pc + 1);
    codegen->RecordProtectedInstruction(pc);
  }
}
#else
void RecordTrapInfoIfNeeded(Zone* zone, CodeGenerator* codegen,
                            InstructionCode opcode, Instruction* instr,
                            int pc) {
  DCHECK_EQ(kMemoryAccessDirect, AccessModeField::decode(opcode));
}
#endif  // V8_ENABLE_WEBASSEMBLY

Condition FlagsConditionToConditionCmp(FlagsCondition condition) {
  switch (condition) {
    case kEqual:
      return eq;
    case kNotEqual:
      return ne;
    case kSignedLessThan:
      return lt;
    case kSignedGreaterThanOrEqual:
      return ge;
    case kSignedLessThanOrEqual:
      return le;
    case kSignedGreaterThan:
      return gt;
    case kUnsignedLessThan:
      return lo;
    case kUnsignedGreaterThanOrEqual:
      return hs;
    case kUnsignedLessThanOrEqual:
      return ls;
    case kUnsignedGreaterThan:
      return hi;
    case kUnorderedEqual:
    case kUnorderedNotEqual:
      break;
    default:
      break;
  }
  UNREACHABLE();
}

Condition FlagsConditionToConditionTst(FlagsCondition condition) {
  switch (condition) {
    case kNotEqual:
      return ne;
    case kEqual:
      return eq;
    default:
      break;
  }
  UNREACHABLE();
}

Condition FlagsConditionToConditionOvf(FlagsCondition condition) {
  switch (condition) {
    case kOverflow:
      return ne;
    case kNotOverflow:
      return eq;
    default:
      break;
  }
  UNREACHABLE();
}

FPUCondition FlagsConditionToConditionCmpFPU(bool* predicate,
                                             FlagsCondition condition) {
  switch (condition) {
    case kEqual:
      *predicate = true;
      return CEQ;
    case kNotEqual:
      *predicate = false;
      return CEQ;
    case kUnsignedLessThan:
    case kFloatLessThan:
      *predicate = true;
      return CLT;
    case kUnsignedGreaterThanOrEqual:
      *predicate = false;
      return CLT;
    case kUnsignedLessThanOrEqual:
    case kFloatLessThanOrEqual:
      *predicate = true;
      return CLE;
    case kUnsignedGreaterThan:
      *predicate = false;
      return CLE;
    case kFloatGreaterThan:
      *predicate = false;
      return CULE;
    case kFloatGreaterThanOrEqual:
      *predicate = false;
      return CULT;
    case kFloatLessThanOrUnordered:
      *predicate = true;
      return CULT;
    case kFloatGreaterThanOrUnordered:
      *predicate = false;
      return CLE;
    case kFloatGreaterThanOrEqualOrUnordered:
      *predicate = false;
      return CLT;
    case kFloatLessThanOrEqualOrUnordered:
      *predicate = true;
      return CULE;
    case kUnorderedEqual:
    case kUnorderedNotEqual:
      *predicate = true;
      break;
    default:
      *predicate = true;
      break;
  }
  UNREACHABLE();
}

}  // namespace

#define ASSEMBLE_ATOMIC_LOAD_INTEGER(asm_instr)                          \
  do {                                                                   \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
    __ asm_instr(i.OutputRegister(), i.MemoryOperand());                 \
    __ dbar(0);                                                          \
  } while (0)

// TODO(LOONG_dev): remove second dbar?
#define ASSEMBLE_ATOMIC_STORE_INTEGER(asm_instr)                         \
  do {                                                                   \
    __ dbar(0);                                                          \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
    __ asm_instr(i.InputOrZeroRegister(2), i.MemoryOperand());           \
    __ dbar(0);                                                          \
  } while (0)

// only use for sub_w and sub_d
#define ASSEMBLE_ATOMIC_BINOP(load_linked, store_conditional, bin_instr)       \
  do {                                                                         \
    Label binop;                                                               \
    __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    __ dbar(0);                                                                \
    __ bind(&binop);                                                           \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());       \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0));     \
    __ bin_instr(i.TempRegister(1), i.OutputRegister(0),                       \
                 Operand(i.InputRegister(2)));                                 \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&binop, eq, i.TempRegister(1), Operand(zero_reg));          \
    __ dbar(0);                                                                \
  } while (0)

// TODO(LOONG_dev): remove second dbar?
#define ASSEMBLE_ATOMIC_BINOP_EXT(load_linked, store_conditional, sign_extend, \
                                  size, bin_instr, representation)             \
  do {                                                                         \
    Label binop;                                                               \
    __ add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    if (representation == 32) {                                                \
      __ andi(i.TempRegister(3), i.TempRegister(0), 0x3);                      \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ andi(i.TempRegister(3), i.TempRegister(0), 0x7);                      \
    }                                                                          \
    __ Sub_d(i.TempRegister(0), i.TempRegister(0),                             \
             Operand(i.TempRegister(3)));                                      \
    __ slli_w(i.TempRegister(3), i.TempRegister(3), 3);                        \
    __ dbar(0);                                                                \
    __ bind(&binop);                                                           \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());       \
    __ load_linked(i.TempRegister(1), MemOperand(i.TempRegister(0), 0));       \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(1), i.TempRegister(3),  \
                   size, sign_extend);                                         \
    __ bin_instr(i.TempRegister(2), i.OutputRegister(0),                       \
                 Operand(i.InputRegister(2)));                                 \
    __ InsertBits(i.TempRegister(1), i.TempRegister(2), i.TempRegister(3),     \
                  size);                                                       \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&binop, eq, i.TempRegister(1), Operand(zero_reg));          \
    __ dbar(0);                                                                \
  } while (0)

// TODO(LOONG_dev): remove second dbar?
#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(                                  \
    load_linked, store_conditional, sign_extend, size, representation)         \
  do {                                                                         \
    Label exchange;                                                            \
    __ add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    if (representation == 32) {                                                \
      __ andi(i.TempRegister(1), i.TempRegister(0), 0x3);                      \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ andi(i.TempRegister(1), i.TempRegister(0), 0x7);                      \
    }                                                                          \
    __ Sub_d(i.TempRegister(0), i.TempRegister(0),                             \
             Operand(i.TempRegister(1)));                                      \
    __ slli_w(i.TempRegister(1), i.TempRegister(1), 3);                        \
    __ dbar(0);                                                                \
    __ bind(&exchange);                                                        \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());       \
    __ load_linked(i.TempRegister(2), MemOperand(i.TempRegister(0), 0));       \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(2), i.TempRegister(1),  \
                   size, sign_extend);                                         \
    __ InsertBits(i.TempRegister(2), i.InputRegister(2), i.TempRegister(1),    \
                  size);                                                       \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&exchange, eq, i.TempRegister(2), Operand(zero_reg));       \
    __ dbar(0);                                                                \
  } while (0)

// TODO(LOONG_dev): remove second dbar?
#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(load_linked,                  \
                                                 store_conditional)            \
  do {                                                                         \
    Label compareExchange;                                                     \
    Label exit;                                                                \
    __ add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    __ dbar(0);                                                                \
    __ bind(&compareExchange);                                                 \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());       \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0));     \
    __ BranchShort(&exit, ne, i.InputRegister(2),                              \
                   Operand(i.OutputRegister(0)));                              \
    __ mov(i.TempRegister(2), i.InputRegister(3));                             \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&compareExchange, eq, i.TempRegister(2),                    \
                   Operand(zero_reg));                                         \
    __ bind(&exit);                                                            \
    __ dbar(0);                                                                \
  } while (0)

// TODO(LOONG_dev): remove second dbar?
#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(                          \
    load_linked, store_conditional, sign_extend, size, representation)         \
  do {                                                                         \
    Label compareExchange;                                                     \
    Label exit;                                                                \
    __ add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    if (representation == 32) {                                                \
      __ andi(i.TempRegister(1), i.TempRegister(0), 0x3);                      \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ andi(i.TempRegister(1), i.TempRegister(0), 0x7);                      \
    }                                                                          \
    __ Sub_d(i.TempRegister(0), i.TempRegister(0),                             \
             Operand(i.TempRegister(1)));                                      \
    __ slli_w(i.TempRegister(1), i.TempRegister(1), 3);                        \
    __ dbar(0);                                                                \
    __ bind(&compareExchange);                                                 \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());       \
    __ load_linked(i.TempRegister(2), MemOperand(i.TempRegister(0), 0));       \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(2), i.TempRegister(1),  \
                   size, sign_extend);                                         \
    __ ExtractBits(i.TempRegister(2), i.InputRegister(2), zero_reg, size,      \
                   sign_extend);                                               \
    __ BranchShort(&exit, ne, i.TempRegister(2),                               \
                   Operand(i.OutputRegister(0)));                              \
    __ InsertBits(i.TempRegister(2), i.InputRegister(3), i.TempRegister(1),    \
                  size);                                                       \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&compareExchange, eq, i.TempRegister(2),                    \
                   Operand(zero_reg));                                         \
    __ bind(&exit);                                                            \
    __ dbar(0);                                                                \
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                        \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    UseScratchRegisterScope temps(masm());                                  \
    Register scratch = temps.Acquire();                                     \
    __ PrepareCallCFunction(0, 2, scratch);                                 \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 2); \
  } while (0)

#define ASSEMBLE_IEEE754_UNOP(name)                                         \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    UseScratchRegisterScope temps(masm());                                  \
    Register scratch = temps.Acquire();                                     \
    __ PrepareCallCFunction(0, 1, scratch);                                 \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 1); \
  } while (0)

#define ASSEMBLE_F64X2_ARITHMETIC_BINOP(op)                     \
  do {                                                          \
    __ op(i.OutputSimd128Register(), i.InputSimd128Register(0), \
          i.InputSimd128Register(1));                           \
  } while (0)

void CodeGenerator::AssembleDeconstructFrame() {
  __ mov(sp, fp);
  __ Pop(ra, fp);
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ Ld_d(ra, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
    __ Ld_d(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
  }
  frame_access_state()->SetFrameAccessToSP();
}

namespace {

void AdjustStackPointerForTailCall(MacroAssembler* masm,
                                   FrameAccessState* state,
                                   int new_slot_above_sp,
                                   bool allow_shrinkage = true) {
  int current_sp_offset = state->GetSPToFPSlotCount() +
                          StandardFrameConstants::kFixedSlotCountAboveFp;
  int stack_slot_delta = new_slot_above_sp - current_sp_offset;
  if (stack_slot_delta > 0) {
    masm->Sub_d(sp, sp, stack_slot_delta * kSystemPointerSize);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    masm->Add_d(sp, sp, -stack_slot_delta * kSystemPointerSize);
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset, false);
}

void CodeGenerator::AssembleTailCallAfterGap(Instruction* instr,
                                             int first_unused_slot_offset) {
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset);
}

// Check that {kJavaScriptCallCodeStartRegister} is correct.
void CodeGenerator::AssembleCodeStartRegisterCheck() {
  UseScratchRegisterScope temps(masm());
  Register scratch = temps.Acquire();
  __ ComputeCodeStartAddress(scratch);
  __ Assert(eq, AbortReason::kWrongFunctionCodeStart,
            kJavaScriptCallCodeStartRegister, Operand(scratch));
}

#ifdef V8_ENABLE_LEAPTIERING
// Check that {kJavaScriptCallDispatchHandleRegister} is correct.
void CodeGenerator::AssembleDispatchHandleRegisterCheck() {
  DCHECK(linkage()->GetIncomingDescriptor()->IsJSFunctionCall());

  // We currently don't check this for JS builtins as those are sometimes
  // called directly (e.g. from other builtins) and not through the dispatch
  // table. This is fine as builtin functions don't use the dispatch handle,
  // but we could enable this check in the future if we make sure to pass the
  // kInvalidDispatchHandle whenever we do a direct call to a JS builtin.
  if (Builtins::IsBuiltinId(info()->builtin())) {
    return;
  }

  // For now, we only ensure that the register references a valid dispatch
  // entry with the correct parameter count. In the future, we may also be able
  // to check that the entry points back to this code.
  UseScratchRegisterScope temps(masm());
  Register actual_parameter_count = temps.Acquire();
  Register scratch = temps.Acquire();
  __ LoadParameterCountFromJSDispatchTable(
      actual_parameter_count, kJavaScriptCallDispatchHandleRegister, scratch);
  __ Assert(eq, AbortReason::kWrongFunctionDispatchHandle,
            actual_parameter_count, Operand(parameter_count_));
}
#endif  // V8_ENABLE_LEAPTIERING

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void CodeGenerator::BailoutIfDeoptimized() {
  UseScratchRegisterScope temps(masm());
  Register scratch = temps.Acquire();
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  __ LoadProtectedPointerField(
      scratch, MemOperand(kJavaScriptCallCodeStartRegister, offset));
  __ Ld_wu(scratch, FieldMemOperand(scratch, Code::kFlagsOffset));
  __ And(scratch, scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));
  __ TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, ne, scratch,
                     Operand(zero_reg));
}

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  Loong64OperandConverter i(this, instr);
  InstructionCode opcode = instr->opcode();
  ArchOpcode arch_opcode = ArchOpcodeField::decode(opcode);
  switch (arch_opcode) {
    case kArchCallCodeObject: {
      if (instr->InputAt(0)->IsImmediate()) {
        __ Call(i.InputCode(0), RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        CodeEntrypointTag tag =
            i.InputCodeEntrypointTag(instr->CodeEnrypointTagInputIndex());
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ CallCodeObject(reg, tag);
      }
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchCallBuiltinPointer: {
      DCHECK(!instr->InputAt(0)->IsImmediate());
      Register builtin_index = i.InputRegister(0);
      Register target =
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister)
              ? kJavaScriptCallCodeStartRegister
              : builtin_index;
      __ CallBuiltinByIndex(builtin_index, target);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
#if V8_ENABLE_WEBASSEMBLY
    case kArchCallWasmFunction: {
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Call(wasm_code, constant.rmode());
      } else {
        __ Call(i.InputRegister(0));
      }
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchTailCallWasm: {
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Jump(wasm_code, constant.rmode());
      } else {
        __ Jump(i.InputRegister(0));
      }
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchTailCallCodeObject: {
      if (instr->InputAt(0)->IsImmediate()) {
        __ Jump(i.InputCode(0), RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        CodeEntrypointTag tag =
            i.InputCodeEntrypointTag(instr->CodeEnrypointTagInputIndex());
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ JumpCodeObject(reg, tag);
      }
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchTailCallAddress: {
      CHECK(!instr->InputAt(0)->IsImmediate());
      Register reg = i.InputRegister(0);
      DCHECK_IMPLIES(
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
          reg == kJavaScriptCallCodeStartRegister);
      __ Jump(reg);
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchCallJSFunction: {
      Register func = i.InputRegister(0);
      if (v8_flags.debug_code) {
        UseScratchRegisterScope temps(masm());
        Register scratch = temps.Acquire();
        // Check the function's context matches the context argument.
        __ LoadTaggedField(scratch,
                           FieldMemOperand(func, JSFunction::kContextOffset));
        __ Assert(eq, AbortReason::kWrongFunctionContext, cp, Operand(scratch));
      }
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      __ PrepareCallCFunction(num_gp_parameters, num_fp_parameters, scratch);
      // Frame alignment requires using FP-relative frame addressing.
      frame_access_state()->SetFrameAccessToFP();
      break;
    }
    case kArchSaveCallerRegisters: {
      fp_mode_ =
          static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode()));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // kReturnRegister0 should have been saved before entering the stub.
      int bytes = __ PushCallerSaved(fp_mode_, kReturnRegister0);
      DCHECK(IsAligned(bytes, kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      frame_access_state()->IncreaseSPDelta(bytes / kSystemPointerSize);
      DCHECK(!caller_registers_saved_);
      caller_registers_saved_ = true;
      break;
    }
    case kArchRestoreCallerRegisters: {
      DCHECK(fp_mode_ ==
             static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode())));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // Don't overwrite the returned value.
      int bytes = __ PopCallerSaved(fp_mode_, kReturnRegister0);
      frame_access_state()->IncreaseSPDelta(-(bytes / kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      DCHECK(caller_registers_saved_);
      caller_registers_saved_ = false;
      break;
    }
    case kArchPrepareTailCall:
      AssemblePrepareTailCall();
      break;
    case kArchCallCFunctionWithFrameState:
    case kArchCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes;
      Label return_location;
#if V8_ENABLE_WEBASSEMBLY
      bool isWasmCapiFunction =
          linkage()->GetIncomingDescriptor()->IsWasmCapiFunction();
      if (isWasmCapiFunction) {
        __ LoadLabelRelative(t7, &return_location);
        __ St_d(t7, MemOperand(fp, WasmExitFrameConstants::kCallingPCOffset));
        set_isolate_data_slots = SetIsolateDataSlots::kNo;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      int pc_offset;
      if (instr->InputAt(0)->IsImmediate()) {
        ExternalReference ref = i.InputExternalReference(0);
        pc_offset = __ CallCFunction(ref, num_gp_parameters, num_fp_parameters,
                                     set_isolate_data_slots, &return_location);
      } else {
        Register func = i.InputRegister(0);
        pc_offset = __ CallCFunction(func, num_gp_parameters, num_fp_parameters,
                                     set_isolate_data_slots, &return_location);
      }
      RecordSafepoint(instr->reference_map(), pc_offset);

      bool const needs_frame_state =
          (arch_opcode == kArchCallCFunctionWithFrameState);
      if (needs_frame_state) {
        RecordDeoptInfo(instr, pc_offset);
      }

      frame_access_state()->SetFrameAccessToDefault();
      // Ideally, we should decrement SP delta to match the change of stack
      // pointer in CallCFunction. However, for certain architectures (e.g.
      // ARM), there may be more strict alignment requirement, causing old SP
      // to be saved on the stack. In those cases, we can not calculate the SP
      // delta statically.
      frame_access_state()->ClearSPDelta();
      if (caller_registers_saved_) {
        // Need to re-sync SP delta introduced in kArchSaveCallerRegisters.
        // Here, we assume the sequence to be:
        //   kArchSaveCallerRegisters;
        //   kArchCallCFunction;
        //   kArchRestoreCallerRegisters;
        int bytes =
            __ RequiredStackSizeForCallerSaved(fp_mode_, kReturnRegister0);
        frame_access_state()->IncreaseSPDelta(bytes / kSystemPointerSize);
      }
      break;
    }
    case kArchJmp:
      AssembleArchJump(i.InputRpo(0));
      break;
    case kArchBinarySearchSwitch:
      AssembleArchBinarySearchSwitch(instr);
      break;
    case kArchTableSwitch:
      AssembleArchTableSwitch(instr);
      break;
    case kArchAbortCSADcheck:
      DCHECK(i.InputRegister(0) == a0);
      {
        // We don't actually want to generate a pile of code for this, so just
        // claim there is a stack frame, without generating one.
        FrameScope scope(masm(), StackFrame::NO_FRAME_TYPE);
        __ CallBuiltin(Builtin::kAbortCSADcheck);
      }
      __ stop();
      break;
    case kArchDebugBreak:
      __ DebugBreak();
      break;
    case kArchComment:
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt64(0)),
                       SourceLocation());
      break;
    case kArchNop:
    case kArchThrowTerminator:
      // don't emit code for nops.
      break;
    case kArchDeoptimize: {
      DeoptimizationExit* exit =
          BuildTranslation(instr, -1, 0, 0, OutputFrameStateCombine::Ignore());
      __ Branch(exit->label());
      break;
    }
    case kArchRet:
      AssembleReturn(instr->InputAt(0));
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      // The register allocator expects an allocatable register for the output,
      // we cannot use sp directly.
      __ mov(i.OutputRegister(), sp);
      break;
    case kArchSetStackPointer: {
      DCHECK(instr->InputAt(0)->IsRegister());
      __ mov(sp, i.InputRegister(0));
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchStackPointerGreaterThan: {
      Register lhs_register = sp;
      uint32_t offset;
      if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
        lhs_register = i.TempRegister(1);
        __ Sub_d(lhs_register, sp, offset);
      }
      __ Sltu(i.TempRegister(0), i.InputRegister(0), lhs_register);
      break;
    }
    case kArchStackCheckOffset:
      __ Move(i.OutputRegister(), Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchFramePointer:
      __ mov(i.OutputRegister(), fp);
      break;
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ Ld_d(i.OutputRegister(), MemOperand(fp, 0));
      } else {
        __ mov(i.OutputRegister(), fp);
      }
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode());
      break;
    case kArchStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      Register object = i.InputRegister(0);
      Register value = i.InputRegister(2);

      if (addressing_mode == kMode_MRI) {
        auto ool = zone()->New<OutOfLineRecordWrite>(
            this, object, Operand(i.InputInt64(1)), value, mode,
            DetermineStubCallMode());
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        __ StoreTaggedField(value, MemOperand(object, i.InputInt64(1)));
        if (mode > RecordWriteMode::kValueIsPointer) {
          __ JumpIfSmi(value, ool->exit());
        }
        __ CheckPageFlag(object,
                         MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                         ool->entry());
        __ bind(ool->exit());
      } else {
        DCHECK_EQ(addressing_mode, kMode_MRR);
        auto ool = zone()->New<OutOfLineRecordWrite>(
            this, object, Operand(i.InputRegister(1)), value, mode,
            DetermineStubCallMode());
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        __ StoreTaggedField(value, MemOperand(object, i.InputRegister(1)));
        if (mode > RecordWriteMode::kValueIsIndirectPointer) {
          __ JumpIfSmi(value, ool->exit());
        }
        __ CheckPageFlag(object,
                         MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                         ool->entry());
        __ bind(ool->exit());
      }
      break;
    }
    case kArchAtomicStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      Register object = i.InputRegister(0);
      int64_t offset = i.InputInt64(1);
      Register value = i.InputRegister(2);

      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, Operand(offset), value, mode, DetermineStubCallMode());
      __ AtomicStoreTaggedField(value, MemOperand(object, offset));
      // Skip the write barrier if the value is a Smi. However, this is only
      // valid if the value isn't an indirect pointer. Otherwise the value will
      // be a pointer table index, which will always look like a Smi (but
      // actually reference a pointer in the pointer table).
      if (mode > RecordWriteMode::kValueIsIndirectPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask,
                       ne, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      DCHECK_EQ(mode, RecordWriteMode::kValueIsIndirectPointer);
      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      IndirectPointerTag tag = static_cast<IndirectPointerTag>(i.InputInt64(3));
      DCHECK(IsValidIndirectPointerTag(tag));
      Register object = i.InputRegister(0);
      Register value = i.InputRegister(2);

      if (addressing_mode == kMode_MRI) {
        auto ool = zone()->New<OutOfLineRecordWrite>(
            this, object, Operand(i.InputInt32(1)), value, mode,
            DetermineStubCallMode(), tag);
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        __ StoreIndirectPointerField(value,
                                     MemOperand(object, i.InputInt32(1)));
        __ CheckPageFlag(object,
                         MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                         ool->entry());
        __ bind(ool->exit());
      } else {
        DCHECK_EQ(addressing_mode, kMode_MRR);
        auto ool = zone()->New<OutOfLineRecordWrite>(
            this, object, Operand(i.InputRegister(1)), value, mode,
            DetermineStubCallMode(), tag);
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        __ StoreIndirectPointerField(value,
                                     MemOperand(object, i.InputRegister(1)));
        __ CheckPageFlag(object,
                         MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                         ool->entry());
        __ bind(ool->exit());
      }
      break;
    }
    case kArchStackSlot: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      Register base_reg = offset.from_stack_pointer() ? sp : fp;
      __ Add_d(i.OutputRegister(), base_reg, Operand(offset.offset()));
      if (v8_flags.debug_code) {
        // Verify that the output_register is properly aligned
        __ And(scratch, i.OutputRegister(), Operand(kSystemPointerSize - 1));
        __ Assert(eq, AbortReason::kAllocationIsNotDoubleAligned, scratch,
                  Operand(zero_reg));
      }
      break;
    }
    case kIeee754Float64Acos:
      ASSEMBLE_IEEE754_UNOP(acos);
      break;
    case kIeee754Float64Acosh:
      ASSEMBLE_IEEE754_UNOP(acosh);
      break;
    case kIeee754Float64Asin:
      ASSEMBLE_IEEE754_UNOP(asin);
      break;
    case kIeee754Float64Asinh:
      ASSEMBLE_IEEE754_UNOP(asinh);
      break;
    case kIeee754Float64Atan:
      ASSEMBLE_IEEE754_UNOP(atan);
      break;
    case kIeee754Float64Atanh:
      ASSEMBLE_IEEE754_UNOP(atanh);
      break;
    case kIeee754Float64Atan2:
      ASSEMBLE_IEEE754_BINOP(atan2);
      break;
    case kIeee754Float64Cos:
      ASSEMBLE_IEEE754_UNOP(cos);
      break;
    case kIeee754Float64Cosh:
      ASSEMBLE_IEEE754_UNOP(cosh);
      break;
    case kIeee754Float64Cbrt:
      ASSEMBLE_IEEE754_UNOP(cbrt);
      break;
    case kIeee754Float64Exp:
      ASSEMBLE_IEEE754_UNOP(exp);
      break;
    case kIeee754Float64Expm1:
      ASSEMBLE_IEEE754_UNOP(expm1);
      break;
    case kIeee754Float64Log:
      ASSEMBLE_IEEE754_UNOP(log);
      break;
    case kIeee754Float64Log1p:
      ASSEMBLE_IEEE754_UNOP(log1p);
      break;
    case kIeee754Float64Log2:
      ASSEMBLE_IEEE754_UNOP(log2);
      break;
    case kIeee754Float64Log10:
      ASSEMBLE_IEEE754_UNOP(log10);
      break;
    case kIeee754Float64Pow:
      ASSEMBLE_IEEE754_BINOP(pow);
      break;
    case kIeee754Float64Sin:
      ASSEMBLE_IEEE754_UNOP(sin);
      break;
    case kIeee754Float64Sinh:
      ASSEMBLE_IEEE754_UNOP(sinh);
      break;
    case kIeee754Float64Tan:
      ASSEMBLE_IEEE754_UNOP(tan);
      break;
    case kIeee754Float64Tanh:
      ASSEMBLE_IEEE754_UNOP(tanh);
      break;
    case kLoong64Add_w:
      __ Add_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Add_d:
      __ Add_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64AddOvf_d:
      __ AddOverflow_d(i.OutputRegister(), i.InputRegister(0),
                       i.InputOperand(1), t8);
      break;
    case kLoong64Sub_w:
      __ Sub_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Sub_d:
      __ Sub_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64SubOvf_d:
      __ SubOverflow_d(i.OutputRegister(), i.InputRegister(0),
                       i.InputOperand(1), t8);
      break;
    case kLoong64Mul_w:
      __ Mul_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64MulOvf_w:
      __ MulOverflow_w(i.OutputRegister(), i.InputRegister(0),
                       i.InputOperand(1), t8);
      break;
    case kLoong64MulOvf_d:
      __ MulOverflow_d(i.OutputRegister(), i.InputRegister(0),
                       i.InputOperand(1), t8);
      break;
    case kLoong64Mulh_w:
      __ Mulh_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mulh_wu:
      __ Mulh_wu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mulh_d:
      __ Mulh_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mulh_du:
      __ Mulh_du(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Div_w:
      __ Div_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      __ maskeqz(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kLoong64Div_wu:
      __ Div_wu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      __ maskeqz(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kLoong64Mod_w:
      __ Mod_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mod_wu:
      __ Mod_wu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mul_d:
      __ Mul_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Div_d:
      __ Div_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      __ maskeqz(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kLoong64Div_du:
      __ Div_du(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      __ maskeqz(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kLoong64Mod_d:
      __ Mod_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mod_du:
      __ Mod_du(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Alsl_d:
      DCHECK(instr->InputAt(2)->IsImmediate());
      __ Alsl_d(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.InputInt8(2), t7);
      break;
    case kLoong64Alsl_w:
      DCHECK(instr->InputAt(2)->IsImmediate());
      __ Alsl_w(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.InputInt8(2), t7);
      break;
    case kLoong64And:
    case kLoong64And32:
      __ And(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Or:
    case kLoong64Or32:
      __ Or(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Nor:
    case kLoong64Nor32:
      if (instr->InputAt(1)->IsRegister()) {
        __ Nor(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      } else {
        DCHECK_EQ(0, i.InputOperand(1).immediate());
        __ Nor(i.OutputRegister(), i.InputRegister(0), zero_reg);
      }
      break;
    case kLoong64Xor:
    case kLoong64Xor32:
      __ Xor(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Clz_w:
      __ clz_w(i.OutputRegister(), i.InputRegister(0));
      break;
    case kLoong64Clz_d:
      __ clz_d(i.OutputRegister(), i.InputRegister(0));
      break;
    case kLoong64Sll_w:
      if (instr->InputAt(1)->IsRegister()) {
        __ sll_w(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ slli_w(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
      }
      break;
    case kLoong64Srl_w:
      if (instr->InputAt(1)->IsRegister()) {
        __ srl_w(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ srli_w(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
      }
      break;
    case kLoong64Sra_w:
      if (instr->InputAt(1)->IsRegister()) {
        __ sra_w(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ srai_w(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
      }
      break;
    case kLoong64Bstrpick_w:
      __ bstrpick_w(i.OutputRegister(), i.InputRegister(0),
                    i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      break;
    case kLoong64Bstrins_w:
      if (instr->InputAt(1)->IsImmediate() && i.InputInt8(1) == 0) {
        __ bstrins_w(i.OutputRegister(), zero_reg,
                     i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      } else {
        __ bstrins_w(i.OutputRegister(), i.InputRegister(0),
                     i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      }
      break;
    case kLoong64Bstrpick_d: {
      __ bstrpick_d(i.OutputRegister(), i.InputRegister(0),
                    i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      break;
    }
    case kLoong64Bstrins_d:
      if (instr->InputAt(1)->IsImmediate() && i.InputInt8(1) == 0) {
        __ bstrins_d(i.OutputRegister(), zero_reg,
                     i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      } else {
        __ bstrins_d(i.OutputRegister(), i.InputRegister(0),
                     i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      }
      break;
    case kLoong64Sll_d:
      if (instr->InputAt(1)->IsRegister()) {
        __ sll_d(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ slli_d(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
      }
      break;
    case kLoong64Srl_d:
      if (instr->InputAt(1)->IsRegister()) {
        __ srl_d(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ srli_d(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
      }
      break;
    case kLoong64Sra_d:
      if (instr->InputAt(1)->IsRegister()) {
        __ sra_d(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ srai_d(i.OutputRegister(), i.InputRegister(0), imm);
      }
      break;
    case kLoong64Rotr_w:
      __ Rotr_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Rotr_d:
      __ Rotr_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Tst:
      __ And(t8, i.InputRegister(0), i.InputOperand(1));
      // Pseudo-instruction used for cmp/branch. No opcode emitted here.
      break;
    case kLoong64Cmp32:
    case kLoong64Cmp64:
      // Pseudo-instruction used for cmp/branch. No opcode emitted here.
      break;
    case kLoong64Mov:
      // TODO(LOONG_dev): Should we combine mov/li, or use separate instr?
      //    - Also see x64 ASSEMBLE_BINOP & RegisterOrOperandType
      if (HasRegisterInput(instr, 0)) {
        __ mov(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ li(i.OutputRegister(), i.InputOperand(0));
      }
      break;

    case kLoong64Float32Cmp: {
      FPURegister left = i.InputOrZeroSingleRegister(0);
      FPURegister right = i.InputOrZeroSingleRegister(1);
      bool predicate;
      FPUCondition cc =
          FlagsConditionToConditionCmpFPU(&predicate, instr->flags_condition());

      if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
          !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }

      __ CompareF32(left, right, cc);
    } break;
    case kLoong64Float32Add:
      __ fadd_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float32Sub:
      __ fsub_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float32Mul:
      __ fmul_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float32Div:
      __ fdiv_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float32Abs:
      __ fabs_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    case kLoong64Float32Neg:
      __ Neg_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    case kLoong64Float32Sqrt: {
      __ fsqrt_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float32Min: {
      FPURegister dst = i.OutputSingleRegister();
      FPURegister src1 = i.InputSingleRegister(0);
      FPURegister src2 = i.InputSingleRegister(1);
      auto ool = zone()->New<OutOfLineFloat32Min>(this, dst, src1, src2);
      __ Float32Min(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kLoong64Float32Max: {
      FPURegister dst = i.OutputSingleRegister();
      FPURegister src1 = i.InputSingleRegister(0);
      FPURegister src2 = i.InputSingleRegister(1);
      auto ool = zone()->New<OutOfLineFloat32Max>(this, dst, src1, src2);
      __ Float32Max(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kLoong64Float64Cmp: {
      FPURegister left = i.InputOrZeroDoubleRegister(0);
      FPURegister right = i.InputOrZeroDoubleRegister(1);
      bool predicate;
      FPUCondition cc =
          FlagsConditionToConditionCmpFPU(&predicate, instr->flags_condition());
      if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
          !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }

      __ CompareF64(left, right, cc);
    } break;
    case kLoong64Float64Add:
      __ fadd_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float64Sub:
      __ fsub_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float64Mul:
      // TODO(LOONG_dev): LOONG64 add special case: right op is -1.0, see arm
      // port.
      __ fmul_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float64Div:
      __ fdiv_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float64Mod: {
      // TODO(turbofan): implement directly.
      FrameScope scope(masm(), StackFrame::MANUAL);
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ PrepareCallCFunction(0, 2, scratch);
      __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
      break;
    }
    case kLoong64Float64Abs:
      __ fabs_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float64Neg:
      __ Neg_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float64Sqrt: {
      __ fsqrt_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float64Min: {
      FPURegister dst = i.OutputDoubleRegister();
      FPURegister src1 = i.InputDoubleRegister(0);
      FPURegister src2 = i.InputDoubleRegister(1);
      auto ool = zone()->New<OutOfLineFloat64Min>(this, dst, src1, src2);
      __ Float64Min(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kLoong64Float64Max: {
      FPURegister dst = i.OutputDoubleRegister();
      FPURegister src1 = i.InputDoubleRegister(0);
      FPURegister src2 = i.InputDoubleRegister(1);
      auto ool = zone()->New<OutOfLineFloat64Max>(this, dst, src1, src2);
      __ Float64Max(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kLoong64Float64RoundDown: {
      __ Floor_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float32RoundDown: {
      __ Floor_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kLoong64Float64RoundTruncate: {
      __ Trunc_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float32RoundTruncate: {
      __ Trunc_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kLoong64Float64RoundUp: {
      __ Ceil_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float32RoundUp: {
      __ Ceil_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kLoong64Float64RoundTiesEven: {
      __ Round_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float32RoundTiesEven: {
      __ Round_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kLoong64Float64SilenceNaN:
      __ FPUCanonicalizeNaN(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float64ToFloat32:
      __ fcvt_s_d(i.OutputSingleRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float32ToFloat64:
      __ fcvt_d_s(i.OutputDoubleRegister(), i.InputSingleRegister(0));
      break;
    case kLoong64Int32ToFloat64: {
      FPURegister scratch = kScratchDoubleReg;
      __ movgr2fr_w(scratch, i.InputRegister(0));
      __ ffint_d_w(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kLoong64Int32ToFloat32: {
      FPURegister scratch = kScratchDoubleReg;
      __ movgr2fr_w(scratch, i.InputRegister(0));
      __ ffint_s_w(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kLoong64Uint32ToFloat32: {
      __ Ffint_s_uw(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kLoong64Int64ToFloat32: {
      FPURegister scratch = kScratchDoubleReg;
      __ movgr2fr_d(scratch, i.InputRegister(0));
      __ ffint_s_l(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kLoong64Int64ToFloat64: {
      FPURegister scratch = kScratchDoubleReg;
      __ movgr2fr_d(scratch, i.InputRegister(0));
      __ ffint_d_l(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kLoong64Uint32ToFloat64: {
      __ Ffint_d_uw(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kLoong64Uint64ToFloat64: {
      __ Ffint_d_ul(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kLoong64Uint64ToFloat32: {
      __ Ffint_s_ul(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kLoong64Float64ToInt32: {
      FPURegister scratch = kScratchDoubleReg;
      __ ftintrz_w_d(scratch, i.InputDoubleRegister(0));
      __ movfr2gr_s(i.OutputRegister(), scratch);
      if (instr->OutputCount() > 1) {
        // Check for inputs below INT32_MIN and NaN.
        __ li(i.OutputRegister(1), 1);
        __ Move(scratch, static_cast<double>(INT32_MIN));
        __ CompareF64(scratch, i.InputDoubleRegister(0), CLE);
        __ LoadZeroIfNotFPUCondition(i.OutputRegister(1));
        __ Move(scratch, static_cast<double>(INT32_MAX) + 1);
        __ CompareF64(scratch, i.InputDoubleRegister(0), CLE);
        __ LoadZeroIfFPUCondition(i.OutputRegister(1));
      }
      break;
    }
    case kLoong64Float32ToInt32: {
      FPURegister scratch_d = kScratchDoubleReg;
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      __ ftintrz_w_s(scratch_d, i.InputDoubleRegister(0));
      __ movfr2gr_s(i.OutputRegister(), scratch_d);
      if (set_overflow_to_min_i32) {
        UseScratchRegisterScope temps(masm());
        Register scratch = temps.Acquire();
        // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
        // because INT32_MIN allows easier out-of-bounds detection.
        __ addi_w(scratch, i.OutputRegister(), 1);
        __ slt(scratch, scratch, i.OutputRegister());
        __ add_w(i.OutputRegister(), i.OutputRegister(), scratch);
      }
      break;
    }
    case kLoong64Float32ToInt64: {
      FPURegister scratch_d = kScratchDoubleReg;

      bool load_status = instr->OutputCount() > 1;
      // Other arches use round to zero here, so we follow.
      __ ftintrz_l_s(scratch_d, i.InputDoubleRegister(0));
      __ movfr2gr_d(i.OutputRegister(), scratch_d);
      if (load_status) {
        Register output2 = i.OutputRegister(1);
        __ movfcsr2gr(output2, FCSR2);
        // Check for overflow and NaNs.
        __ And(output2, output2,
               kFCSROverflowCauseMask | kFCSRInvalidOpCauseMask);
        __ Slt(output2, zero_reg, output2);
        __ xori(output2, output2, 1);
      }
      break;
    }
    case kLoong64Float64ToInt64: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      FPURegister scratch_d = kScratchDoubleReg;

      bool set_overflow_to_min_i64 = MiscField::decode(instr->opcode());
      bool load_status = instr->OutputCount() > 1;
      // Other arches use round to zero here, so we follow.
      __ ftintrz_l_d(scratch_d, i.InputDoubleRegister(0));
      __ movfr2gr_d(i.OutputRegister(0), scratch_d);
      if (load_status) {
        Register output2 = i.OutputRegister(1);
   
"""


```