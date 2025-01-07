Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for a summary of the functionality of the provided C++ code snippet, which is part of V8's S390 backend. It also includes specific constraints related to file extensions, JavaScript relevance, logical inference, common errors, and the "part 1 of 5" indication.

2. **Initial Scan for Keywords and Structure:** I quickly scan the code for important keywords and structural elements:
    * `#include`:  Indicates dependencies on other V8 components (assembler, codegen, compiler).
    * `namespace v8::internal::compiler`:  Confirms the code's location within the V8 project.
    * Class `S390OperandConverter`:  Suggests handling of operands for S390 instructions.
    * Class `OutOfLineRecordWrite`:  Points to a mechanism for handling write barriers.
    * Macros like `__ masm()->`, `RRInstr`, `RIInstr`, etc.: Imply code generation patterns and instruction assembly.
    * Numerous `#define ASSEMBLE_*`:  Strongly indicates the core function is assembling S390 instructions.
    * Mentions of WebAssembly (`V8_ENABLE_WEBASSEMBLY`).
    * References to stack slots, registers (general and floating-point), and memory operands.

3. **Identify Key Functionalities:** Based on the initial scan, I deduce the main functionalities:
    * **Operand Conversion:**  `S390OperandConverter` is responsible for translating abstract instruction operands into S390-specific representations.
    * **Instruction Assembly:** The numerous macros and `AssembleOp` functions clearly show the code's role in generating machine code for S390. The macros abstract common instruction patterns (register-register, register-immediate, register-memory).
    * **Write Barriers:** `OutOfLineRecordWrite` implements a mechanism to ensure memory consistency when writing to objects in the garbage-collected heap. This is a critical part of V8's garbage collection.
    * **Conditional Logic:**  The `FlagsConditionToCondition` function and comparisons within the assembly macros indicate support for conditional execution.
    * **Floating-Point Operations:**  The `ASSEMBLE_FLOAT_*` macros and mentions of double registers signify handling of floating-point arithmetic.
    * **WebAssembly Support:** The `#if V8_ENABLE_WEBASSEMBLY` sections indicate specific handling for WebAssembly code generation.

4. **Address Specific Constraints:**

    * **File Extension:** The code explicitly states that if the file ended in `.tq`, it would be Torque code. Since it doesn't, it's regular C++ code.
    * **JavaScript Relationship:** The code directly translates higher-level instructions (from the compiler's intermediate representation) into low-level S390 machine code. This is the core of how JavaScript is executed. I need to create a simple JavaScript example that would likely trigger some of these instructions.
    * **Logical Inference:**  I should pick a simple assembly macro (like `RRInstr`) and illustrate the input and output. This requires understanding the macro's purpose.
    * **Common Errors:**  Focus on a common error in assembly or low-level programming, such as incorrect register usage or memory addressing.
    * **Part 1 of 5:** Acknowledge this and understand it implies further functionality will be present in subsequent parts.

5. **Construct the Summary:**  I start writing the summary, organizing it around the key functionalities identified earlier. I use clear and concise language, avoiding overly technical jargon where possible.

6. **Provide Examples:** I create the JavaScript example, the logical inference scenario, and the common error example. These should be simple and illustrative. For the logical inference, I trace the execution of a macro with sample inputs. For the common error, I describe a typical mistake and its potential consequences.

7. **Refine and Review:** I reread the summary and examples to ensure they are accurate, clear, and address all aspects of the request. I check for any inconsistencies or areas that could be explained better. I make sure to explicitly state what the code *does* rather than just listing code elements. I pay attention to the "part 1 of 5" and make sure the summary reflects that it's a piece of a larger system.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and accurate answer that addresses all the requirements of the request. The process emphasizes understanding the code's purpose within the larger context of the V8 engine.
好的，让我们来归纳一下 `v8/src/compiler/backend/s390/code-generator-s390.cc` 这段代码的功能。

**功能归纳：**

这段 C++ 代码是 V8 JavaScript 引擎中针对 s390 架构的**代码生成器（Code Generator）**的一部分。它的主要职责是将编译器生成的**中间表示（Intermediate Representation, IR）**的指令转换为**实际的 s390 汇编代码**。

更具体地说，它负责以下功能：

1. **指令转换和汇编:**
   - 它读取编译器后端生成的指令（`Instruction` 对象）。
   - 它使用 `S390OperandConverter` 类来处理指令的操作数，将其转换为 s390 汇编代码中使用的寄存器、内存地址或立即数。
   - 它使用宏（例如 `RRInstr`, `RIInstr`, `RMInstr` 等）来简化不同类型 s390 指令的生成。
   - 最终，它调用 `MacroAssembler` 类的方法（例如 `__ add()`, `__ mov()`, `__ load()` 等）来生成实际的机器码。

2. **支持不同的操作数类型和寻址模式:**
   - `S390OperandConverter` 能够处理各种类型的操作数，包括寄存器、立即数、栈槽和内存地址。
   - 它支持 s390 架构的不同寻址模式（例如寄存器寻址、立即数偏移寻址、寄存器偏移寻址等）。

3. **处理浮点数操作:**
   - 代码中包含了 `ASSEMBLE_FLOAT_UNOP`, `ASSEMBLE_FLOAT_BINOP`, `ASSEMBLE_FLOAT_COMPARE` 等宏，用于生成 s390 浮点数运算指令。

4. **实现写屏障（Write Barrier）:**
   - `OutOfLineRecordWrite` 类实现了**写屏障**的逻辑。当需要更新堆中对象的指针时，写屏障会确保垃圾回收器能够正确跟踪这些更新，维护堆的完整性。

5. **处理条件码和条件跳转:**
   - `FlagsConditionToCondition` 函数将编译器的条件码转换为 s390 汇编中使用的条件码。
   - 代码生成器能够根据条件码生成条件跳转指令。

6. **支持 WebAssembly (如果启用):**
   - 代码中包含了 `#if V8_ENABLE_WEBASSEMBLY` 的条件编译，表明它也参与了 WebAssembly 代码的生成过程。

**关于文件扩展名：**

代码中明确指出，如果 `v8/src/compiler/backend/s390/code-generator-s390.cc` 以 `.tq` 结尾，那么它将是 V8 的 Torque 源代码。由于它以 `.cc` 结尾，所以是标准的 C++ 源代码。

**与 JavaScript 功能的关系及 JavaScript 示例：**

`v8/src/compiler/backend/s390/code-generator-s390.cc` 直接关系到 JavaScript 代码的执行。当 V8 引擎执行 JavaScript 代码时，它会经历以下主要步骤：

1. **解析 (Parsing):** 将 JavaScript 代码转换为抽象语法树 (AST)。
2. **编译 (Compilation):** 将 AST 转换为中间表示 (IR)。
3. **代码生成 (Code Generation):**  **这就是 `code-generator-s390.cc` 发挥作用的阶段。** 它将 IR 转换为特定于 s390 架构的机器码。
4. **执行 (Execution):** CPU 执行生成的机器码。

**JavaScript 示例：**

假设有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 编译 `add` 函数时，`code-generator-s390.cc` 可能会生成类似于以下的 s390 汇编代码（这只是一个简化的例子，实际生成的代码会更复杂）：

```assembly
; 函数入口
function_start:
  // 将参数 a 加载到寄存器 r3
  lgr r3, [栈地址 + 偏移量_a]
  // 将参数 b 加载到寄存器 r4
  lgr r4, [栈地址 + 偏移量_b]
  // 执行加法运算，结果存储在 r3
  agr r3, r4
  // 将结果存储到返回值位置
  lgr [栈地址 + 偏移量_返回值], r3
  // 函数返回
  br function_return
```

在这个例子中，`code-generator-s390.cc` 负责将 JavaScript 的加法操作 (`a + b`) 转换为 s390 的加法指令 (`agr`)。

**代码逻辑推理示例：**

假设有一个 IR 指令表示将一个 32 位整数加载到寄存器中：

**假设输入：**

- `instr->opcode()`:  `kS390_LoadWord32` (表示加载 32 位字的指令)
- `instr->OutputAt(0)`:  一个表示寄存器 `r5` 的 `LocationOperand` 对象。
- `instr->InputAt(0)`: 一个表示内存地址 `[r2 + 16]` 的 `LocationOperand` 对象。

**生成的汇编代码：**

根据 `ASSEMBLE_LOAD_INTEGER` 宏和 `i.MemoryOperand()` 的逻辑，可能会生成以下 s390 汇编指令：

```assembly
l  r5, 16(r2)  ; 将内存地址 r2 + 16 处的值加载到寄存器 r5
```

**涉及用户常见的编程错误示例：**

虽然这个代码生成器是 V8 内部的组件，但它生成的代码质量会影响 JavaScript 代码的性能和正确性。用户在编写 JavaScript 时的一些常见错误，可能会导致代码生成器生成效率较低或潜在有 bug 的机器码。

例如：

1. **类型不匹配：**  如果 JavaScript 代码中频繁进行不同类型之间的转换，代码生成器可能需要插入额外的指令来处理类型转换，这会降低性能。

   ```javascript
   let x = 5;
   let y = "10";
   let sum = x + y; // 字符串拼接，可能导致额外的类型转换
   ```

2. **频繁访问全局变量：** 访问全局变量通常比访问局部变量慢，因为代码生成器需要生成额外的代码来查找全局变量。

   ```javascript
   let globalVar = 10;
   function myFunction() {
     return globalVar + 5; // 访问全局变量 globalVar
   }
   ```

3. **在循环中进行复杂操作：** 如果循环体内的操作过于复杂，代码生成器可能难以进行有效的优化。

   ```javascript
   let arr = [1, 2, 3, 4, 5];
   for (let i = 0; i < arr.length; i++) {
     // 非常复杂的计算或对象操作
     arr[i] = Math.sin(arr[i] * Math.random() + Date.now());
   }
   ```

这些 JavaScript 编程习惯可能会导致代码生成器生成效率较低的机器码，从而影响程序的执行速度。

**总结 (针对第 1 部分):**

`v8/src/compiler/backend/s390/code-generator-s390.cc` 的第 1 部分定义了代码生成器的基础结构和一些核心功能，包括：

- **`S390OperandConverter`**: 用于将中间表示的操作数转换为 s390 汇编的操作数。
- **指令汇编宏**:  简化了常见 s390 指令的生成。
- **浮点数操作支持**:  包含了生成浮点数运算指令的宏。
- **写屏障的初步实现**:  `OutOfLineRecordWrite` 类用于处理对象指针更新时的写屏障。
- **条件码转换**:  `FlagsConditionToCondition` 函数用于将编译器条件码转换为 s390 条件码。

这部分代码是 s390 代码生成器的基础 building block，为后续更复杂的指令生成和优化奠定了基础。后续的部分很可能会涉及更多类型的指令、更复杂的控制流处理、以及可能的性能优化策略。

Prompt: 
```
这是目录为v8/src/compiler/backend/s390/code-generator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/code-generator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/heap/mutable-page-metadata.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

#define __ masm()->

#define kScratchReg ip

// Adds S390-specific methods to convert InstructionOperands.
class S390OperandConverter final : public InstructionOperandConverter {
 public:
  S390OperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  size_t OutputCount() { return instr_->OutputCount(); }

  bool Is64BitOperand(int index) {
    return LocationOperand::cast(instr_->InputAt(index))->representation() ==
           MachineRepresentation::kWord64;
  }

  bool Is32BitOperand(int index) {
    return LocationOperand::cast(instr_->InputAt(index))->representation() ==
           MachineRepresentation::kWord32;
  }

  bool CompareLogical() const {
    switch (instr_->flags_condition()) {
      case kUnsignedLessThan:
      case kUnsignedGreaterThanOrEqual:
      case kUnsignedLessThanOrEqual:
      case kUnsignedGreaterThan:
        return true;
      default:
        return false;
    }
    UNREACHABLE();
  }

  Operand InputImmediate(size_t index) {
    Constant constant = ToConstant(instr_->InputAt(index));
    switch (constant.type()) {
      case Constant::kInt32:
        return Operand(constant.ToInt32());
      case Constant::kFloat32:
        return Operand::EmbeddedNumber(constant.ToFloat32());
      case Constant::kFloat64:
        return Operand::EmbeddedNumber(constant.ToFloat64().value());
      case Constant::kInt64:
        return Operand(constant.ToInt64());
      case Constant::kExternalReference:
        return Operand(constant.ToExternalReference());
      case Constant::kCompressedHeapObject:
      case Constant::kHeapObject:
      case Constant::kRpoNumber:
        break;
    }
    UNREACHABLE();
  }

  MemOperand MemoryOperand(AddressingMode* mode, size_t* first_index) {
    const size_t index = *first_index;
    if (mode) *mode = AddressingModeField::decode(instr_->opcode());
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
        break;
      case kMode_MR:
        *first_index += 1;
        return MemOperand(InputRegister(index + 0), 0);
      case kMode_MRI:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputInt32(index + 1));
      case kMode_MRR:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1));
      case kMode_MRRI:
        *first_index += 3;
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1),
                          InputInt32(index + 2));
      case kMode_Root:
        *first_index += 1;
        return MemOperand(kRootRegister, InputInt32(index));
    }
    UNREACHABLE();
  }

  MemOperand MemoryOperand(AddressingMode* mode = nullptr,
                           size_t first_index = 0) {
    return MemoryOperand(mode, &first_index);
  }

  MemOperand ToMemOperand(InstructionOperand* op) const {
    DCHECK_NOT_NULL(op);
    DCHECK(op->IsStackSlot() || op->IsFPStackSlot());
    return SlotToMemOperand(AllocatedOperand::cast(op)->index());
  }

  MemOperand SlotToMemOperand(int slot) const {
    FrameOffset offset = frame_access_state()->GetFrameOffset(slot);
    return MemOperand(offset.from_stack_pointer() ? sp : fp, offset.offset());
  }

  MemOperand InputStackSlot(size_t index) {
    InstructionOperand* op = instr_->InputAt(index);
    return SlotToMemOperand(AllocatedOperand::cast(op)->index());
  }

  MemOperand InputStackSlot32(size_t index) {
#if V8_TARGET_ARCH_S390X && !V8_TARGET_LITTLE_ENDIAN
    // We want to read the 32-bits directly from memory
    MemOperand mem = InputStackSlot(index);
    return MemOperand(mem.rx(), mem.rb(), mem.offset() + 4);
#else
    return InputStackSlot(index);
#endif
  }
};

static inline bool HasRegisterOutput(Instruction* instr, int index = 0) {
  return instr->OutputCount() > 0 && instr->OutputAt(index)->IsRegister();
}

static inline bool HasFPRegisterInput(Instruction* instr, int index) {
  return instr->InputAt(index)->IsFPRegister();
}

static inline bool HasRegisterInput(Instruction* instr, int index) {
  return instr->InputAt(index)->IsRegister() ||
         HasFPRegisterInput(instr, index);
}

static inline bool HasImmediateInput(Instruction* instr, size_t index) {
  return instr->InputAt(index)->IsImmediate();
}

static inline bool HasFPStackSlotInput(Instruction* instr, size_t index) {
  return instr->InputAt(index)->IsFPStackSlot();
}

static inline bool HasStackSlotInput(Instruction* instr, size_t index) {
  return instr->InputAt(index)->IsStackSlot() ||
         HasFPStackSlotInput(instr, index);
}

namespace {

class OutOfLineRecordWrite final : public OutOfLineCode {
 public:
  OutOfLineRecordWrite(CodeGenerator* gen, Register object, MemOperand operand,
                       Register value, Register scratch0, Register scratch1,
                       RecordWriteMode mode, StubCallMode stub_mode,
                       UnwindingInfoWriter* unwinding_info_writer)
      : OutOfLineCode(gen),
        object_(object),
        operand_(operand),
        value_(value),
        scratch0_(scratch0),
        scratch1_(scratch1),
        mode_(mode),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        must_save_lr_(!gen->frame_access_state()->has_frame()),
        unwinding_info_writer_(unwinding_info_writer),
        zone_(gen->zone()) {
    DCHECK(!AreAliased(object, scratch0, scratch1));
    DCHECK(!AreAliased(value, scratch0, scratch1));
  }

  void Generate() final {
    if (COMPRESS_POINTERS_BOOL) {
      __ DecompressTagged(value_, value_);
    }
    __ CheckPageFlag(value_, scratch0_,
                     MemoryChunk::kPointersToHereAreInterestingMask, eq,
                     exit());
    __ lay(scratch1_, operand_);
    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    if (must_save_lr_) {
      // We need to save and restore r14 if the frame was elided.
      __ Push(r14);
      unwinding_info_writer_->MarkLinkRegisterOnTopOfStack(__ pc_offset());
    }
    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, scratch1_, save_fp_mode);
#if V8_ENABLE_WEBASSEMBLY
    } else if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      __ CallRecordWriteStubSaveRegisters(object_, scratch1_, save_fp_mode,
                                          StubCallMode::kCallWasmRuntimeStub);
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      __ CallRecordWriteStubSaveRegisters(object_, scratch1_, save_fp_mode);
    }
    if (must_save_lr_) {
      // We need to save and restore r14 if the frame was elided.
      __ Pop(r14);
      unwinding_info_writer_->MarkPopLinkRegisterFromTopOfStack(__ pc_offset());
    }
  }

 private:
  Register const object_;
  MemOperand const operand_;
  Register const value_;
  Register const scratch0_;
  Register const scratch1_;
  RecordWriteMode const mode_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  bool must_save_lr_;
  UnwindingInfoWriter* const unwinding_info_writer_;
  Zone* zone_;
};

Condition FlagsConditionToCondition(FlagsCondition condition, ArchOpcode op) {
  switch (condition) {
    case kEqual:
      return eq;
    case kNotEqual:
      return ne;
    case kUnsignedLessThan:
      // unsigned number never less than 0
      if (op == kS390_LoadAndTestWord32 || op == kS390_LoadAndTestWord64)
        return CC_NOP;
      [[fallthrough]];
    case kSignedLessThan:
      return lt;
    case kUnsignedGreaterThanOrEqual:
      // unsigned number always greater than or equal 0
      if (op == kS390_LoadAndTestWord32 || op == kS390_LoadAndTestWord64)
        return CC_ALWAYS;
      [[fallthrough]];
    case kSignedGreaterThanOrEqual:
      return ge;
    case kUnsignedLessThanOrEqual:
      // unsigned number never less than 0
      if (op == kS390_LoadAndTestWord32 || op == kS390_LoadAndTestWord64)
        return CC_EQ;
      [[fallthrough]];
    case kSignedLessThanOrEqual:
      return le;
    case kUnsignedGreaterThan:
      // unsigned number always greater than or equal 0
      if (op == kS390_LoadAndTestWord32 || op == kS390_LoadAndTestWord64)
        return ne;
      [[fallthrough]];
    case kSignedGreaterThan:
      return gt;
    case kOverflow:
      // Overflow checked for AddS64/SubS64 only.
      switch (op) {
        case kS390_Add32:
        case kS390_Add64:
        case kS390_Sub32:
        case kS390_Sub64:
        case kS390_Abs64:
        case kS390_Abs32:
        case kS390_Mul32:
        case kS390_Mul64WithOverflow:
          return overflow;
        default:
          break;
      }
      break;
    case kNotOverflow:
      switch (op) {
        case kS390_Add32:
        case kS390_Add64:
        case kS390_Sub32:
        case kS390_Sub64:
        case kS390_Abs64:
        case kS390_Abs32:
        case kS390_Mul32:
        case kS390_Mul64WithOverflow:
          return nooverflow;
        default:
          break;
      }
      break;
    default:
      break;
  }
  UNREACHABLE();
}

#define GET_MEMOPERAND32(ret, fi)                                       \
  ([&](int& ret) {                                                      \
    AddressingMode mode = AddressingModeField::decode(instr->opcode()); \
    MemOperand mem(r0);                                                 \
    if (mode != kMode_None) {                                           \
      size_t first_index = (fi);                                        \
      mem = i.MemoryOperand(&mode, &first_index);                       \
      ret = first_index;                                                \
    } else {                                                            \
      mem = i.InputStackSlot32(fi);                                     \
    }                                                                   \
    return mem;                                                         \
  })(ret)

#define GET_MEMOPERAND(ret, fi)                                         \
  ([&](int& ret) {                                                      \
    AddressingMode mode = AddressingModeField::decode(instr->opcode()); \
    MemOperand mem(r0);                                                 \
    if (mode != kMode_None) {                                           \
      size_t first_index = (fi);                                        \
      mem = i.MemoryOperand(&mode, &first_index);                       \
      ret = first_index;                                                \
    } else {                                                            \
      mem = i.InputStackSlot(fi);                                       \
    }                                                                   \
    return mem;                                                         \
  })(ret)

#define RRInstr(instr)                                \
  [&]() {                                             \
    DCHECK(i.OutputRegister() == i.InputRegister(0)); \
    __ instr(i.OutputRegister(), i.InputRegister(1)); \
    return 2;                                         \
  }
#define RIInstr(instr)                                 \
  [&]() {                                              \
    DCHECK(i.OutputRegister() == i.InputRegister(0));  \
    __ instr(i.OutputRegister(), i.InputImmediate(1)); \
    return 2;                                          \
  }
#define RMInstr(instr, GETMEM)                        \
  [&]() {                                             \
    DCHECK(i.OutputRegister() == i.InputRegister(0)); \
    int ret = 2;                                      \
    __ instr(i.OutputRegister(), GETMEM(ret, 1));     \
    return ret;                                       \
  }
#define RM32Instr(instr) RMInstr(instr, GET_MEMOPERAND32)
#define RM64Instr(instr) RMInstr(instr, GET_MEMOPERAND)

#define RRRInstr(instr)                                                   \
  [&]() {                                                                 \
    __ instr(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1)); \
    return 2;                                                             \
  }
#define RRIInstr(instr)                                                    \
  [&]() {                                                                  \
    __ instr(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1)); \
    return 2;                                                              \
  }
#define RRMInstr(instr, GETMEM)                                       \
  [&]() {                                                             \
    int ret = 2;                                                      \
    __ instr(i.OutputRegister(), i.InputRegister(0), GETMEM(ret, 1)); \
    return ret;                                                       \
  }
#define RRM32Instr(instr) RRMInstr(instr, GET_MEMOPERAND32)
#define RRM64Instr(instr) RRMInstr(instr, GET_MEMOPERAND)

#define DDInstr(instr)                                            \
  [&]() {                                                         \
    DCHECK(i.OutputDoubleRegister() == i.InputDoubleRegister(0)); \
    __ instr(i.OutputDoubleRegister(), i.InputDoubleRegister(1)); \
    return 2;                                                     \
  }

#define DMInstr(instr)                                            \
  [&]() {                                                         \
    DCHECK(i.OutputDoubleRegister() == i.InputDoubleRegister(0)); \
    int ret = 2;                                                  \
    __ instr(i.OutputDoubleRegister(), GET_MEMOPERAND(ret, 1));   \
    return ret;                                                   \
  }

#define DMTInstr(instr)                                           \
  [&]() {                                                         \
    DCHECK(i.OutputDoubleRegister() == i.InputDoubleRegister(0)); \
    int ret = 2;                                                  \
    __ instr(i.OutputDoubleRegister(), GET_MEMOPERAND(ret, 1),    \
             kScratchDoubleReg);                                  \
    return ret;                                                   \
  }

#define R_MInstr(instr)                                   \
  [&]() {                                                 \
    int ret = 2;                                          \
    __ instr(i.OutputRegister(), GET_MEMOPERAND(ret, 0)); \
    return ret;                                           \
  }

#define R_DInstr(instr)                                     \
  [&]() {                                                   \
    __ instr(i.OutputRegister(), i.InputDoubleRegister(0)); \
    return 2;                                               \
  }

#define D_DInstr(instr)                                           \
  [&]() {                                                         \
    __ instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0)); \
    return 2;                                                     \
  }

#define D_MInstr(instr)                                         \
  [&]() {                                                       \
    int ret = 2;                                                \
    __ instr(i.OutputDoubleRegister(), GET_MEMOPERAND(ret, 0)); \
    return ret;                                                 \
  }

#define D_MTInstr(instr)                                       \
  [&]() {                                                      \
    int ret = 2;                                               \
    __ instr(i.OutputDoubleRegister(), GET_MEMOPERAND(ret, 0), \
             kScratchDoubleReg);                               \
    return ret;                                                \
  }

static int nullInstr() { UNREACHABLE(); }

template <int numOfOperand, class RType, class MType, class IType>
static inline int AssembleOp(Instruction* instr, RType r, MType m, IType i) {
  AddressingMode mode = AddressingModeField::decode(instr->opcode());
  if (mode != kMode_None || HasStackSlotInput(instr, numOfOperand - 1)) {
    return m();
  } else if (HasRegisterInput(instr, numOfOperand - 1)) {
    return r();
  } else if (HasImmediateInput(instr, numOfOperand - 1)) {
    return i();
  } else {
    UNREACHABLE();
  }
}

template <class _RR, class _RM, class _RI>
static inline int AssembleBinOp(Instruction* instr, _RR _rr, _RM _rm, _RI _ri) {
  return AssembleOp<2>(instr, _rr, _rm, _ri);
}

template <class _R, class _M, class _I>
static inline int AssembleUnaryOp(Instruction* instr, _R _r, _M _m, _I _i) {
  return AssembleOp<1>(instr, _r, _m, _i);
}

#define ASSEMBLE_BIN_OP(_rr, _rm, _ri) AssembleBinOp(instr, _rr, _rm, _ri)
#define ASSEMBLE_UNARY_OP(_r, _m, _i) AssembleUnaryOp(instr, _r, _m, _i)

#define CHECK_AND_ZERO_EXT_OUTPUT(num)                                \
  ([&](int index) {                                                   \
    DCHECK(HasImmediateInput(instr, (index)));                        \
    int doZeroExt = i.InputInt32(index);                              \
    if (doZeroExt) __ LoadU32(i.OutputRegister(), i.OutputRegister()); \
  })(num)

#define ASSEMBLE_BIN32_OP(_rr, _rm, _ri) \
  { CHECK_AND_ZERO_EXT_OUTPUT(AssembleBinOp(instr, _rr, _rm, _ri)); }

}  // namespace

#define ASSEMBLE_FLOAT_UNOP(asm_instr)                                \
  do {                                                                \
    __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0)); \
  } while (0)

#define ASSEMBLE_FLOAT_BINOP(asm_instr)                              \
  do {                                                               \
    __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0), \
                 i.InputDoubleRegister(1));                          \
  } while (0)

#define ASSEMBLE_COMPARE(cmp_instr, cmpl_instr)                         \
  do {                                                                  \
    AddressingMode mode = AddressingModeField::decode(instr->opcode()); \
    if (mode != kMode_None) {                                           \
      size_t first_index = 1;                                           \
      MemOperand operand = i.MemoryOperand(&mode, &first_index);        \
      if (i.CompareLogical()) {                                         \
        __ cmpl_instr(i.InputRegister(0), operand);                     \
      } else {                                                          \
        __ cmp_instr(i.InputRegister(0), operand);                      \
      }                                                                 \
    } else if (HasRegisterInput(instr, 1)) {                            \
      if (i.CompareLogical()) {                                         \
        __ cmpl_instr(i.InputRegister(0), i.InputRegister(1));          \
      } else {                                                          \
        __ cmp_instr(i.InputRegister(0), i.InputRegister(1));           \
      }                                                                 \
    } else if (HasImmediateInput(instr, 1)) {                           \
      if (i.CompareLogical()) {                                         \
        __ cmpl_instr(i.InputRegister(0), i.InputImmediate(1));         \
      } else {                                                          \
        __ cmp_instr(i.InputRegister(0), i.InputImmediate(1));          \
      }                                                                 \
    } else {                                                            \
      DCHECK(HasStackSlotInput(instr, 1));                              \
      if (i.CompareLogical()) {                                         \
        __ cmpl_instr(i.InputRegister(0), i.InputStackSlot(1));         \
      } else {                                                          \
        __ cmp_instr(i.InputRegister(0), i.InputStackSlot(1));          \
      }                                                                 \
    }                                                                   \
  } while (0)

#define ASSEMBLE_COMPARE32(cmp_instr, cmpl_instr)                       \
  do {                                                                  \
    AddressingMode mode = AddressingModeField::decode(instr->opcode()); \
    if (mode != kMode_None) {                                           \
      size_t first_index = 1;                                           \
      MemOperand operand = i.MemoryOperand(&mode, &first_index);        \
      if (i.CompareLogical()) {                                         \
        __ cmpl_instr(i.InputRegister(0), operand);                     \
      } else {                                                          \
        __ cmp_instr(i.InputRegister(0), operand);                      \
      }                                                                 \
    } else if (HasRegisterInput(instr, 1)) {                            \
      if (i.CompareLogical()) {                                         \
        __ cmpl_instr(i.InputRegister(0), i.InputRegister(1));          \
      } else {                                                          \
        __ cmp_instr(i.InputRegister(0), i.InputRegister(1));           \
      }                                                                 \
    } else if (HasImmediateInput(instr, 1)) {                           \
      if (i.CompareLogical()) {                                         \
        __ cmpl_instr(i.InputRegister(0), i.InputImmediate(1));         \
      } else {                                                          \
        __ cmp_instr(i.InputRegister(0), i.InputImmediate(1));          \
      }                                                                 \
    } else {                                                            \
      DCHECK(HasStackSlotInput(instr, 1));                              \
      if (i.CompareLogical()) {                                         \
        __ cmpl_instr(i.InputRegister(0), i.InputStackSlot32(1));       \
      } else {                                                          \
        __ cmp_instr(i.InputRegister(0), i.InputStackSlot32(1));        \
      }                                                                 \
    }                                                                   \
  } while (0)

#define ASSEMBLE_FLOAT_COMPARE(cmp_rr_instr, cmp_rm_instr, load_instr)     \
  do {                                                                     \
    AddressingMode mode = AddressingModeField::decode(instr->opcode());    \
    if (mode != kMode_None) {                                              \
      size_t first_index = 1;                                              \
      MemOperand operand = i.MemoryOperand(&mode, &first_index);           \
      __ cmp_rm_instr(i.InputDoubleRegister(0), operand);                  \
    } else if (HasFPRegisterInput(instr, 1)) {                             \
      __ cmp_rr_instr(i.InputDoubleRegister(0), i.InputDoubleRegister(1)); \
    } else {                                                               \
      USE(HasFPStackSlotInput);                                            \
      DCHECK(HasFPStackSlotInput(instr, 1));                               \
      MemOperand operand = i.InputStackSlot(1);                            \
      if (operand.offset() >= 0) {                                         \
        __ cmp_rm_instr(i.InputDoubleRegister(0), operand);                \
      } else {                                                             \
        __ load_instr(kScratchDoubleReg, operand);                         \
        __ cmp_rr_instr(i.InputDoubleRegister(0), kScratchDoubleReg);      \
      }                                                                    \
    }                                                                      \
  } while (0)

// Divide instruction dr will implicity use register pair
// r0 & r1 below.
// R0:R1 = R1 / divisor - R0 remainder
// Copy remainder to output reg
#define ASSEMBLE_MODULO(div_instr, shift_instr) \
  do {                                          \
    __ mov(r0, i.InputRegister(0));             \
    __ shift_instr(r0, Operand(32));            \
    __ div_instr(r0, i.InputRegister(1));       \
    __ LoadU32(i.OutputRegister(), r0);         \
  } while (0)

#define ASSEMBLE_FLOAT_MODULO()                                             \
  do {                                                                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                           \
    __ Push(r2, r3, r4, r5);                                                \
    __ PrepareCallCFunction(0, 2, kScratchReg);                             \
    __ MovToFloatParameters(i.InputDoubleRegister(0),                       \
                            i.InputDoubleRegister(1));                      \
    __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2); \
    __ MovFromFloatResult(i.OutputDoubleRegister());                        \
    __ Pop(r2, r3, r4, r5);                                                 \
  } while (0)

#define ASSEMBLE_IEEE754_UNOP(name)                                            \
  do {                                                                         \
    /* TODO(bmeurer): We should really get rid of this special instruction, */ \
    /* and generate a CallAddress instruction instead. */                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                              \
    __ Push(r2, r3, r4, r5);                                                   \
    __ PrepareCallCFunction(0, 1, kScratchReg);                                \
    __ MovToFloatParameter(i.InputDoubleRegister(0));                          \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 1);    \
    /* Move the result in the double result register. */                       \
    __ MovFromFloatResult(i.OutputDoubleRegister());                           \
    __ Pop(r2, r3, r4, r5);                                                    \
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                           \
  do {                                                                         \
    /* TODO(bmeurer): We should really get rid of this special instruction, */ \
    /* and generate a CallAddress instruction instead. */                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                              \
    __ Push(r2, r3, r4, r5);                                                   \
    __ PrepareCallCFunction(0, 2, kScratchReg);                                \
    __ MovToFloatParameters(i.InputDoubleRegister(0),                          \
                            i.InputDoubleRegister(1));                         \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 2);    \
    /* Move the result in the double result register. */                       \
    __ MovFromFloatResult(i.OutputDoubleRegister());                           \
    __ Pop(r2, r3, r4, r5);                                                    \
  } while (0)

//
// Only MRI mode for these instructions available
#define ASSEMBLE_LOAD_FLOAT(asm_instr)                \
  do {                                                \
    DoubleRegister result = i.OutputDoubleRegister(); \
    AddressingMode mode = kMode_None;                 \
    MemOperand operand = i.MemoryOperand(&mode);      \
    __ asm_instr(result, operand);                    \
  } while (0)

#define ASSEMBLE_LOAD_INTEGER(asm_instr)         \
  do {                                           \
    Register result = i.OutputRegister();        \
    AddressingMode mode = kMode_None;            \
    MemOperand operand = i.MemoryOperand(&mode); \
    __ asm_instr(result, operand);               \
  } while (0)

#define ASSEMBLE_LOADANDTEST64(asm_instr_rr, asm_instr_rm)              \
  {                                                                     \
    AddressingMode mode = AddressingModeField::decode(instr->opcode()); \
    Register dst = HasRegisterOutput(instr) ? i.OutputRegister() : r0;  \
    if (mode != kMode_None) {                                           \
      size_t first_index = 0;                                           \
      MemOperand operand = i.MemoryOperand(&mode, &first_index);        \
      __ asm_instr_rm(dst, operand);                                    \
    } else if (HasRegisterInput(instr, 0)) {                            \
      __ asm_instr_rr(dst, i.InputRegister(0));                         \
    } else {                                                            \
      DCHECK(HasStackSlotInput(instr, 0));                              \
      __ asm_instr_rm(dst, i.InputStackSlot(0));                        \
    }                                                                   \
  }

#define ASSEMBLE_LOADANDTEST32(asm_instr_rr, asm_instr_rm)              \
  {                                                                     \
    AddressingMode mode = AddressingModeField::decode(instr->opcode()); \
    Register dst = HasRegisterOutput(instr) ? i.OutputRegister() : r0;  \
    if (mode != kMode_None) {                                           \
      size_t first_index = 0;                                           \
      MemOperand operand = i.MemoryOperand(&mode, &first_index);        \
      __ asm_instr_rm(dst, operand);                                    \
    } else if (HasRegisterInput(instr, 0)) {                            \
      __ asm_instr_rr(dst, i.InputRegister(0));                         \
    } else {                                                            \
      DCHECK(HasStackSlotInput(instr, 0));                              \
      __ asm_instr_rm(dst, i.InputStackSlot32(0));                      \
    }                                                                   \
  }

#define ASSEMBLE_STORE_FLOAT32()                         \
  do {                                                   \
    size_t index = 0;                                    \
    AddressingMode mode = kMode_None;                    \
    MemOperand operand = i.MemoryOperand(&mode, &index); \
    DoubleRegister value = i.InputDoubleRegister(index); \
    __ StoreF32(value, operand);                         \
  } while (0)

#define ASSEMBLE_STORE_DOUBLE()                          \
  do {                                                   \
    size_t index = 0;                                    \
    AddressingMode mode = kMode_None;                    \
    MemOperand operand = i.MemoryOperand(&mode, &index); \
    DoubleRegister value = i.InputDoubleRegister(index); \
    __ StoreF64(value, operand);                         \
  } while (0)

#define ASSEMBLE_STORE_INTEGER(asm_instr)                \
  do {                                                   \
    size_t index = 0;                                    \
    AddressingMode mode = kMode_None;                    \
    MemOperand operand = i.MemoryOperand(&mode, &index); \
    Register value = i.InputRegister(index);             \
    __ asm_instr(value, operand);                        \
  } while (0)

static inline bool is_wasm_on_be(OptimizedCompilationInfo* info) {
#if defined(V8_ENABLE_WEBASSEMBLY) && defined(V8_TARGET_BIG_ENDIAN)
  return info->IsWasm();
#else
  return false;
#endif
}

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_BYTE(load_and_ext)                   \
  do {                                                                        \
    Register old_value = i.InputRegister(0);                                  \
    Register new_value = i
"""


```