Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is part of the V8 JavaScript engine and resides in the `v8/src/compiler/backend/mips64` directory. This suggests it's responsible for code generation for the MIPS64 architecture within the V8 compiler's backend.

Here's a breakdown of how to analyze the code snippet:

1. **Identify the core class:** The main class is `CodeGenerator`, and the provided code snippet defines MIPS64-specific methods and utilities within this class.

2. **Analyze included headers:** The `#include` directives provide clues about the code's purpose. It includes headers related to code generation, assembly, machine types, optimized compilation, and instruction handling. Specifically, the presence of `assembler-inl.h`, `macro-assembler.h`, and `code-generator-impl.h` strongly indicates its role in generating machine code.

3. **Examine helper classes:** The `MipsOperandConverter` class is clearly designed to handle MIPS-specific operand conversions for instructions.

4. **Look for key functionalities:**  The code contains various function definitions and macros that reveal its capabilities:
    - Handling function calls (`kArchCallCodeObject`, `kArchCallBuiltinPointer`, `kArchCallJSFunction`, `kArchCallCFunction`).
    - Managing tail calls (`kArchTailCallCodeObject`, `kArchTailCallAddress`, `AssemblePrepareTailCall`).
    - Handling stack frame manipulation (`AssembleDeconstructFrame`).
    - Implementing record write barriers for garbage collection.
    - Implementing atomic operations.
    - Implementing floating-point operations (using IEEE754 C library functions).
    - Handling WebAssembly calls (if `V8_ENABLE_WEBASSEMBLY` is defined).

5. **Check for architecture-specific details:** The presence of MIPS-specific register names (like `sp`, `fp`, `ra`, `zero_reg`) and instructions (like `Daddu`, `Ld`, `Sd`, `sync`, `ll`, `sc`) confirms its architecture-specific nature.

6. **Consider the context:** The code is part of the compiler's backend, meaning it takes high-level intermediate representation of code (instructions) and translates them into low-level machine instructions.

7. **Address the specific questions in the prompt:**
    - The code is indeed V8 source code, written in C++.
    - It's not a Torque file (doesn't end with `.tq`).
    - It's directly related to JavaScript execution, as it's responsible for generating the machine code that executes JavaScript.

8. **Illustrate with JavaScript (if applicable):**  Since the code generates machine code for JavaScript functions, a simple JavaScript function can be used as an example of what this code helps execute.

9. **Consider code logic and assumptions:**  The atomic operations section reveals specific logic for ensuring atomicity, with loops and conditional stores. This suggests assumptions about memory access and multi-threading.

10. **Think about potential errors:** The code handles record write barriers, which are crucial for garbage collection and preventing dangling pointers. Incorrectly implemented or missing write barriers are a common source of errors in garbage-collected languages.

Based on these observations, I can now construct a summary of the code's functionality.
这个C++源代码文件 `v8/src/compiler/backend/mips64/code-generator-mips64.cc` 是 **V8 JavaScript 引擎** 中 **MIPS64 架构** 的 **代码生成器** 的实现。它的主要功能是将 **高级的中间表示 (IR) 指令** 转换为 **底层的 MIPS64 汇编指令**，以便在 MIPS64 处理器上执行 JavaScript 代码。

以下是它更详细的功能分解：

1. **指令转换和汇编生成:**
   - 它定义了 `CodeGenerator` 类，该类继承自通用的代码生成器框架，并添加了 MIPS64 架构特定的指令生成方法。
   - 它使用了 `MacroAssembler` 类（通过 `masm()` 访问）来生成实际的 MIPS64 汇编代码。
   - `AssembleArchInstruction` 函数是核心，它根据输入的 IR 指令 (`Instruction* instr`) 的操作码 (`arch_opcode`)，调用相应的 MIPS64 汇编指令生成方法。

2. **操作数处理:**
   - `MipsOperandConverter` 类负责将通用的指令操作数 (`InstructionOperand`) 转换为 MIPS64 特定的操作数类型（如寄存器、立即数、内存操作数）。这包括处理不同类型的立即数和寻址模式。

3. **函数调用处理:**
   - 支持不同类型的函数调用，包括：
     - 调用代码对象 (`kArchCallCodeObject`)
     - 调用内置函数指针 (`kArchCallBuiltinPointer`)
     - 调用 JavaScript 函数 (`kArchCallJSFunction`)
     - 调用 C 函数 (`kArchCallCFunction`, `kArchCallCFunctionWithFrameState`)
     - 调用 WebAssembly 函数 (`kArchCallWasmFunction`, 如果启用了 WebAssembly)
   - 它处理调用前的准备工作，例如参数传递、栈帧设置等。

4. **尾调用优化:**
   - 实现了尾调用优化 (`kArchTailCallCodeObject`, `kArchTailCallAddress`, `AssemblePrepareTailCall`)，这可以避免不必要的栈帧增长，提高性能。

5. **栈帧管理:**
   - 负责栈帧的创建和销毁 (`AssembleDeconstructFrame`)。
   - 提供了在尾调用前后调整栈指针的方法 (`AdjustStackPointerForTailCall`).

6. **代码起始地址检查:**
   - 提供了 `AssembleCodeStartRegisterCheck` 函数来验证 `kJavaScriptCallCodeStartRegister` 的正确性。

7. **反优化处理:**
   - `BailoutIfDeoptimized` 函数检查代码对象是否被标记为需要反优化，如果是，则跳转到反优化相关的内置函数。

8. **记录写屏障 (Record Write Barrier):**
   - `OutOfLineRecordWrite` 类实现了写屏障的内联代码，用于在修改堆对象指针时通知垃圾回收器。这对于保持垃圾回收的正确性至关重要。

9. **原子操作支持:**
   - 提供了一系列宏 (`ASSEMBLE_ATOMIC_LOAD_INTEGER`, `ASSEMBLE_ATOMIC_STORE_INTEGER`, `ASSEMBLE_ATOMIC_BINOP`, `ASSEMBLE_ATOMIC_EXCHANGE_INTEGER`, `ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER`) 来生成原子操作的汇编代码，确保在多线程环境下的数据一致性。

10. **浮点运算支持:**
    - 使用 IEEE754 标准的 C 库函数来实现一些复杂的浮点运算（例如 `Float32MaxOutOfLine`, `Float64MinOutOfLine`）。
    - 提供了处理浮点比较的函数，将 `FlagsCondition` 转换为 MIPS64 的浮点条件码。

11. **WebAssembly 支持 (可选):**
    - 如果 `V8_ENABLE_WEBASSEMBLY` 宏被定义，则会包含处理 WebAssembly 函数调用的代码。

**关于代码是否为 Torque 源代码:**

代码以 `.cc` 结尾，这表明它是一个 C++ 源代码文件。如果它是 Torque 源代码，文件名会以 `.tq` 结尾。因此，该文件不是 Torque 源代码。

**与 JavaScript 功能的关系 (示例):**

这个 C++ 代码直接负责将 JavaScript 代码编译成机器码。例如，考虑以下简单的 JavaScript 函数：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 引擎执行这段代码时，`code-generator-mips64.cc` 中的代码会被调用，将 `add` 函数的字节码或中间表示转换为一系列 MIPS64 指令，例如：

```assembly
  // (简化的 MIPS64 示例)
  lw  $t0, [sp + offset_of_a]  // 加载参数 a 到寄存器 $t0
  lw  $t1, [sp + offset_of_b]  // 加载参数 b 到寄存器 $t1
  add $v0, $t0, $t1          // 将 $t0 和 $t1 相加，结果放入 $v0
  jr  $ra                      // 返回
```

`code-generator-mips64.cc` 中的各种函数和逻辑，例如处理函数调用约定、寄存器分配、算术运算等，都会参与到生成上述汇编代码的过程中。

**代码逻辑推理 (假设输入与输出):**

假设有一个 IR 指令，表示将两个寄存器 `r1` 和 `r2` 的内容相加，并将结果存储到寄存器 `r0`。

**假设输入 (Instruction 对象):**

- `opcode`: 代表加法操作的特定枚举值 (例如 `kMips64Add`)
- `OutputAt(0)`: 表示输出寄存器 `r0`
- `InputAt(0)`: 表示输入寄存器 `r1`
- `InputAt(1)`: 表示输入寄存器 `r2`

**代码逻辑 (在 `AssembleArchInstruction` 中):**

```c++
// 假设 arch_opcode 是 kMips64Add
case kMips64Add: {
  __ Add(i.OutputRegister(0), i.InputRegister(0), i.InputRegister(1));
  break;
}
```

这里 `i` 是 `MipsOperandConverter` 的实例，它会将 `OutputAt(0)`、`InputAt(0)` 和 `InputAt(1)` 转换为 MIPS64 的寄存器对象。`__ Add` 是 `MacroAssembler` 提供的方法，用于生成 `add` 指令。

**假设输出 (生成的汇编代码):**

```assembly
add r0, r1, r2
```

**用户常见的编程错误 (与记录写屏障相关):**

在手动管理内存的语言中，忘记释放不再使用的内存会导致内存泄漏。在像 JavaScript 这样的垃圾回收语言中，虽然不需要手动释放内存，但是不正确地更新对象之间的引用关系可能会导致垃圾回收器无法正确识别哪些对象仍然被使用，从而过早地回收对象，导致程序崩溃或产生未定义的行为。

**示例 (JavaScript):**

```javascript
let obj1 = { data: {} };
let obj2 = { ref: obj1.data }; // obj2 引用了 obj1 的 data 属性

// 错误地直接修改 obj1.data 的引用，而不是其内容
obj1.data = {};

// 现在 obj2.ref 指向旧的 obj1.data 对象，而 obj1.data 指向新的空对象。
// 如果没有正确的记录写屏障，垃圾回收器可能认为旧的 obj1.data 没有被引用，并将其回收。
// 之后访问 obj2.ref 可能会导致错误。
console.log(obj2.ref);
```

在这个例子中，如果 V8 的代码生成器没有正确地插入记录写屏障，当 `obj1.data = {}` 执行时，垃圾回收器可能不会注意到 `obj2.ref` 仍然引用着旧的 `obj1.data` 对象。这可能导致旧的 `obj1.data` 对象被过早回收，使得 `obj2.ref` 变成一个悬空指针。`code-generator-mips64.cc` 中的 `OutOfLineRecordWrite` 类及其相关的代码，正是为了防止这类错误而存在的。当修改一个对象的属性，使其指向一个新的堆对象时，写屏障会通知垃圾回收器，确保引用关系的正确性。

**第1部分功能归纳:**

总而言之，`v8/src/compiler/backend/mips64/code-generator-mips64.cc` 的第一部分主要定义了 **MIPS64 架构的代码生成器的基础结构和核心功能**，包括：

- **MIPS64 特定的操作数处理和指令生成工具。**
- **处理各种类型的函数调用的机制。**
- **尾调用优化的初步实现。**
- **栈帧管理的基本功能。**
- **用于确保代码正确性的检查机制。**
- **记录写屏障的内联代码，以支持垃圾回收。**
- **原子操作的基本框架。**
- **部分浮点运算的支持。**

这部分代码是 V8 引擎将 JavaScript 代码转换为可在 MIPS64 架构上执行的机器码的关键组成部分。

Prompt: 
```
这是目录为v8/src/compiler/backend/mips64/code-generator-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/mips64/code-generator-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/mips64/constants-mips64.h"
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

// Adds Mips-specific methods to convert InstructionOperands.
class MipsOperandConverter final : public InstructionOperandConverter {
 public:
  MipsOperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  FloatRegister OutputSingleRegister(size_t index = 0) {
    return ToSingleRegister(instr_->OutputAt(index));
  }

  FloatRegister InputSingleRegister(size_t index) {
    return ToSingleRegister(instr_->InputAt(index));
  }

  FloatRegister ToSingleRegister(InstructionOperand* op) {
    // Single (Float) and Double register namespace is same on MIPS,
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
      case Constant::kExternalReference:
      case Constant::kCompressedHeapObject:
      case Constant::kHeapObject:
        // TODO(plind): Maybe we should handle ExtRef & HeapObj here?
        //    maybe not done on arm due to const pool ??
        break;
      case Constant::kRpoNumber:
        UNREACHABLE();  // TODO(titzer): RPO immediates on mips?
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
        // TODO(plind): r6 address mode, to be implemented ...
        UNREACHABLE();
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
  OutOfLineRecordWrite(CodeGenerator* gen, Register object, Register index,
                       Register value, Register scratch0, Register scratch1,
                       RecordWriteMode mode, StubCallMode stub_mode)
      : OutOfLineCode(gen),
        object_(object),
        index_(index),
        value_(value),
        scratch0_(scratch0),
        scratch1_(scratch1),
        mode_(mode),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        must_save_lr_(!gen->frame_access_state()->has_frame()),
        zone_(gen->zone()) {
    DCHECK(!AreAliased(object, index, scratch0, scratch1));
    DCHECK(!AreAliased(value, index, scratch0, scratch1));
  }

  void Generate() final {
    __ CheckPageFlag(value_, scratch0_,
                     MemoryChunk::kPointersToHereAreInterestingMask, eq,
                     exit());
    __ Daddu(scratch1_, object_, index_);
    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    if (must_save_lr_) {
      // We need to save and restore ra if the frame was elided.
      __ Push(ra);
    }
    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, scratch1_, save_fp_mode);
#if V8_ENABLE_WEBASSEMBLY
    } else if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      __ CallRecordWriteStubSaveRegisters(object_, scratch1_, save_fp_mode,
                                          StubCallMode::kCallWasmRuntimeStub);
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      __ CallRecordWriteStubSaveRegisters(object_, scratch1_, save_fp_mode);
    }
    if (must_save_lr_) {
      __ Pop(ra);
    }
  }

 private:
  Register const object_;
  Register const index_;
  Register const value_;
  Register const scratch0_;
  Register const scratch1_;
  RecordWriteMode const mode_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode const stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  bool must_save_lr_;
  Zone* zone_;
};

#define CREATE_OOL_CLASS(ool_name, tasm_ool_name, T)                 \
  class ool_name final : public OutOfLineCode {                      \
   public:                                                           \
    ool_name(CodeGenerator* gen, T dst, T src1, T src2)              \
        : OutOfLineCode(gen), dst_(dst), src1_(src1), src2_(src2) {} \
                                                                     \
    void Generate() final { __ tasm_ool_name(dst_, src1_, src2_); }  \
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
      return EQ;
    case kNotEqual:
      *predicate = false;
      return EQ;
    case kUnsignedLessThan:
    case kFloatLessThan:
      *predicate = true;
      return OLT;
    case kUnsignedGreaterThanOrEqual:
      *predicate = false;
      return OLT;
    case kUnsignedLessThanOrEqual:
    case kFloatLessThanOrEqual:
      *predicate = true;
      return OLE;
    case kUnsignedGreaterThan:
      *predicate = false;
      return OLE;
    case kFloatGreaterThan:
      *predicate = false;
      return ULE;
    case kFloatGreaterThanOrEqual:
      *predicate = false;
      return ULT;
    case kFloatLessThanOrUnordered:
      *predicate = true;
      return ULT;
    case kFloatGreaterThanOrUnordered:
      *predicate = false;
      return OLE;
    case kFloatGreaterThanOrEqualOrUnordered:
      *predicate = false;
      return OLT;
    case kFloatLessThanOrEqualOrUnordered:
      *predicate = true;
      return ULE;
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

#define ASSEMBLE_ATOMIC_LOAD_INTEGER(asm_instr)          \
  do {                                                   \
    __ asm_instr(i.OutputRegister(), i.MemoryOperand()); \
    __ sync();                                           \
  } while (0)

#define ASSEMBLE_ATOMIC_STORE_INTEGER(asm_instr)               \
  do {                                                         \
    __ sync();                                                 \
    __ asm_instr(i.InputOrZeroRegister(2), i.MemoryOperand()); \
    __ sync();                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP(load_linked, store_conditional, bin_instr)       \
  do {                                                                         \
    Label binop;                                                               \
    __ Daddu(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    __ sync();                                                                 \
    __ bind(&binop);                                                           \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0));     \
    __ bin_instr(i.TempRegister(1), i.OutputRegister(0),                       \
                 Operand(i.InputRegister(2)));                                 \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&binop, eq, i.TempRegister(1), Operand(zero_reg));          \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP_EXT(load_linked, store_conditional, sign_extend, \
                                  size, bin_instr, representation)             \
  do {                                                                         \
    Label binop;                                                               \
    __ daddu(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    if (representation == 32) {                                                \
      __ andi(i.TempRegister(3), i.TempRegister(0), 0x3);                      \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ andi(i.TempRegister(3), i.TempRegister(0), 0x7);                      \
    }                                                                          \
    __ Dsubu(i.TempRegister(0), i.TempRegister(0),                             \
             Operand(i.TempRegister(3)));                                      \
    __ sll(i.TempRegister(3), i.TempRegister(3), 3);                           \
    __ sync();                                                                 \
    __ bind(&binop);                                                           \
    __ load_linked(i.TempRegister(1), MemOperand(i.TempRegister(0), 0));       \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(1), i.TempRegister(3),  \
                   size, sign_extend);                                         \
    __ bin_instr(i.TempRegister(2), i.OutputRegister(0),                       \
                 Operand(i.InputRegister(2)));                                 \
    __ InsertBits(i.TempRegister(1), i.TempRegister(2), i.TempRegister(3),     \
                  size);                                                       \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&binop, eq, i.TempRegister(1), Operand(zero_reg));          \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(load_linked, store_conditional)       \
  do {                                                                         \
    Label exchange;                                                            \
    __ sync();                                                                 \
    __ bind(&exchange);                                                        \
    __ daddu(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0));     \
    __ mov(i.TempRegister(1), i.InputRegister(2));                             \
    __ store_conditional(i.TempRegister(1), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&exchange, eq, i.TempRegister(1), Operand(zero_reg));       \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(                                  \
    load_linked, store_conditional, sign_extend, size, representation)         \
  do {                                                                         \
    Label exchange;                                                            \
    __ daddu(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    if (representation == 32) {                                                \
      __ andi(i.TempRegister(1), i.TempRegister(0), 0x3);                      \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ andi(i.TempRegister(1), i.TempRegister(0), 0x7);                      \
    }                                                                          \
    __ Dsubu(i.TempRegister(0), i.TempRegister(0),                             \
             Operand(i.TempRegister(1)));                                      \
    __ sll(i.TempRegister(1), i.TempRegister(1), 3);                           \
    __ sync();                                                                 \
    __ bind(&exchange);                                                        \
    __ load_linked(i.TempRegister(2), MemOperand(i.TempRegister(0), 0));       \
    __ ExtractBits(i.OutputRegister(0), i.TempRegister(2), i.TempRegister(1),  \
                   size, sign_extend);                                         \
    __ InsertBits(i.TempRegister(2), i.InputRegister(2), i.TempRegister(1),    \
                  size);                                                       \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&exchange, eq, i.TempRegister(2), Operand(zero_reg));       \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(load_linked,                  \
                                                 store_conditional)            \
  do {                                                                         \
    Label compareExchange;                                                     \
    Label exit;                                                                \
    __ daddu(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    __ sync();                                                                 \
    __ bind(&compareExchange);                                                 \
    __ load_linked(i.OutputRegister(0), MemOperand(i.TempRegister(0), 0));     \
    __ BranchShort(&exit, ne, i.InputRegister(2),                              \
                   Operand(i.OutputRegister(0)));                              \
    __ mov(i.TempRegister(2), i.InputRegister(3));                             \
    __ store_conditional(i.TempRegister(2), MemOperand(i.TempRegister(0), 0)); \
    __ BranchShort(&compareExchange, eq, i.TempRegister(2),                    \
                   Operand(zero_reg));                                         \
    __ bind(&exit);                                                            \
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(                          \
    load_linked, store_conditional, sign_extend, size, representation)         \
  do {                                                                         \
    Label compareExchange;                                                     \
    Label exit;                                                                \
    __ daddu(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));       \
    if (representation == 32) {                                                \
      __ andi(i.TempRegister(1), i.TempRegister(0), 0x3);                      \
    } else {                                                                   \
      DCHECK_EQ(representation, 64);                                           \
      __ andi(i.TempRegister(1), i.TempRegister(0), 0x7);                      \
    }                                                                          \
    __ Dsubu(i.TempRegister(0), i.TempRegister(0),                             \
             Operand(i.TempRegister(1)));                                      \
    __ sll(i.TempRegister(1), i.TempRegister(1), 3);                           \
    __ sync();                                                                 \
    __ bind(&compareExchange);                                                 \
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
    __ sync();                                                                 \
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                        \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    __ PrepareCallCFunction(0, 2, kScratchReg);                             \
    __ MovToFloatParameters(i.InputDoubleRegister(0),                       \
                            i.InputDoubleRegister(1));                      \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 2); \
    /* Move the result in the double result register. */                    \
    __ MovFromFloatResult(i.OutputDoubleRegister());                        \
  } while (0)

#define ASSEMBLE_IEEE754_UNOP(name)                                         \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    __ PrepareCallCFunction(0, 1, kScratchReg);                             \
    __ MovToFloatParameter(i.InputDoubleRegister(0));                       \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 1); \
    /* Move the result in the double result register. */                    \
    __ MovFromFloatResult(i.OutputDoubleRegister());                        \
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
    __ Ld(ra, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
    __ Ld(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
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
    masm->Dsubu(sp, sp, stack_slot_delta * kSystemPointerSize);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    masm->Daddu(sp, sp, -stack_slot_delta * kSystemPointerSize);
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
  __ ComputeCodeStartAddress(kScratchReg);
  __ Assert(eq, AbortReason::kWrongFunctionCodeStart,
            kJavaScriptCallCodeStartRegister, Operand(kScratchReg));
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void CodeGenerator::BailoutIfDeoptimized() {
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  __ Ld(kScratchReg, MemOperand(kJavaScriptCallCodeStartRegister, offset));
  __ Lwu(kScratchReg, FieldMemOperand(kScratchReg, Code::kFlagsOffset));
  __ And(kScratchReg, kScratchReg,
         Operand(1 << Code::kMarkedForDeoptimizationBit));
  __ TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, ne, kScratchReg,
                     Operand(zero_reg));
}

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  MipsOperandConverter i(this, instr);
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
        __ daddiu(kScratchReg, i.InputRegister(0), 0);
        __ Call(kScratchReg);
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
        __ daddiu(kScratchReg, i.InputRegister(0), 0);
        __ Jump(kScratchReg);
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
        // Check the function's context matches the context argument.
        __ Ld(kScratchReg, FieldMemOperand(func, JSFunction::kContextOffset));
        __ Assert(eq, AbortReason::kWrongFunctionContext, cp,
                  Operand(kScratchReg));
      }
      __ CallJSFunction(func);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction: {
      int const num_parameters = MiscField::decode(instr->opcode());
      __ PrepareCallCFunction(num_parameters, kScratchReg);
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
        // Put the return address in a stack slot.
        __ LoadAddressPCRelative(kScratchReg, &return_location);
        __ sd(kScratchReg,
              MemOperand(fp, WasmExitFrameConstants::kCallingPCOffset));
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
      // delt
"""


```