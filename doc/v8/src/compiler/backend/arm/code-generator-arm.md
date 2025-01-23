Response: My goal is to analyze the provided C++ code snippet and summarize its functionality, focusing on its connection to JavaScript. Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The filename `code-generator-arm.cc` within the `v8/src/compiler/backend/arm/` directory strongly suggests this file is responsible for generating ARM assembly code for the V8 JavaScript engine's optimizing compiler.

2. **Scan for Key Components:**  I look for major classes, data structures, and function groups. The `#include` directives give initial clues about the dependencies and types being used. I see includes related to:
    * ARM assembly (`assembler-arm.h`, `constants-arm.h`, `register-arm.h`)
    * Code generation infrastructure (`code-generator-impl.h`, `code-generator.h`)
    * Instruction representation (`instruction-codes.h`, `instruction.h`)
    * Memory management and heap (`heap/mutable-page-metadata.h`)
    * WebAssembly support (`wasm/*`)

3. **Examine the `ArmOperandConverter` Class:** This class stands out early. The name and its inheritance from `InstructionOperandConverter` indicate its role in translating high-level instruction operands into ARM-specific operands. The various `Input...` and `To...` methods confirm this. This class is crucial for the translation process.

4. **Analyze Out-of-Line Code Classes:** The `OutOfLineRecordWrite`, `OutOfLineFloatMin`, and `OutOfLineFloatMax` classes suggest handling less common or more complex operations that are factored out of the main instruction assembly flow. The `OutOfLineRecordWrite` class, particularly, with its reference to "write barrier," points to memory management complexities important in garbage-collected languages like JavaScript.

5. **Focus on Key Functions:** I look for functions directly involved in assembly generation, particularly those using the `__` macro, which conventionally represents the `MacroAssembler` in V8. Functions like `AssembleArchInstruction`, `AssembleDeconstructFrame`, `AssemblePrepareTailCall`, and the atomic operation macros (`ASSEMBLE_ATOMIC_LOAD_INTEGER`, etc.) are important.

6. **Identify JavaScript Connections:** The presence of "write barrier" immediately connects to JavaScript's garbage collection. The functions related to function calls (`kArchCallJSFunction`, `kArchTailCallCodeObject`) are also clear indicators. The handling of floating-point numbers and the inclusion of WebAssembly support further tie this code to the features and requirements of the JavaScript engine.

7. **Infer Functionality from Assembly Primitives:** Although I don't need to understand every ARM instruction in detail, recognizing patterns like `ldr` (load register), `str` (store register), `add`, `sub`, `cmp` (compare), and conditional branches helps understand the basic operations being performed. The presence of SIMD/NEON instructions (`vadd`, `vmul`, etc.) shows support for vectorized operations, which can be relevant to JavaScript performance.

8. **Structure the Summary:** I aim for a clear and concise summary, highlighting the core function (generating ARM assembly), key components (operand conversion, out-of-line code), and the connection to JavaScript (garbage collection, function calls, data type handling). I also note the WebAssembly integration.

9. **Construct the JavaScript Examples:** To illustrate the connection, I create simple JavaScript code snippets that would trigger the kind of operations handled by the C++ code. For instance:
    * Object property assignment for the write barrier.
    * Function calls to demonstrate how the code generator handles different call types.
    * Mathematical operations to show the use of floating-point instructions.

10. **Refine and Iterate:**  I review the summary and examples for clarity and accuracy. I ensure that the examples logically connect to the described C++ functionality. I consider if any important aspects have been missed. For example, the tail call optimization is a performance-related feature relevant to JavaScript execution.

By following these steps, I can effectively analyze the C++ code and provide a meaningful summary of its functionality and its relationship to JavaScript. The process involves a combination of code scanning, pattern recognition, and domain knowledge about compilers and JavaScript engines.
这是 `v8/src/compiler/backend/arm/code-generator-arm.cc` 文件的第一部分，主要负责 **将中间表示（IR）指令转换为 ARM 汇编代码**。  更具体地说，它定义了将平台无关的指令操作数转换为 ARM 特定的操作数，并包含了生成各种 ARM 汇编指令的代码。

以下是代码功能的详细归纳：

**核心功能：**

* **指令到 ARM 汇编的转换:**  这是该文件的核心任务。它读取编译器生成的中间表示指令，并针对 ARM 架构生成相应的机器码指令。
* **操作数转换:**  `ArmOperandConverter` 类负责将通用的指令操作数（例如寄存器、立即数、内存地址）转换为 ARM 汇编器可以理解的 `Operand` 和 `MemOperand` 对象。 这包括处理不同的寻址模式和移位操作。
* **生成具体的 ARM 指令:**  在 `CodeGenerator::AssembleArchInstruction` 函数中，根据不同的 `ArchOpcode`（架构特定的操作码），调用 `MacroAssembler` 的方法来生成相应的 ARM 汇编指令（例如 `add`, `sub`, `ldr`, `str`, `vadd`, `vmul` 等）。
* **处理特殊情况和优化:**  文件中包含一些针对特定情况的处理，例如：
    * **写屏障 (`OutOfLineRecordWrite`)**:  用于在修改堆对象时维护垃圾回收机制的正确性。
    * **浮点数 `min` 和 `max` (`OutOfLineFloatMin`, `OutOfLineFloatMax`)**:  处理 NaN 值的情况，确保符合 IEEE 754 标准。
    * **尾调用优化:**  `AssemblePrepareTailCall`, `AdjustStackPointerForTailCall` 等函数用于实现尾调用优化，提高性能。
* **支持 WebAssembly:**  代码中包含 `#if V8_ENABLE_WEBASSEMBLY` 块，表明它也负责为 WebAssembly 生成 ARM 代码。
* **处理函数调用:**  包含了生成函数调用相关指令的代码，包括 JavaScript 函数调用 (`kArchCallJSFunction`)、C 函数调用 (`kArchCallCFunction`) 和内置函数调用 (`kArchCallBuiltinPointer`)。
* **处理控制流:**  包含生成跳转指令 (`kArchJmp`)、分支指令（通过条件码设置）和 switch 语句 (`kArchBinarySearchSwitch`, `kArchTableSwitch`) 的代码。
* **处理浮点运算:**  生成各种浮点运算的 ARM 指令，包括基本的加减乘除、比较、平方根以及更复杂的数学函数（通过调用 C 函数实现）。
* **处理 SIMD/NEON 指令:**  包含了生成 ARM NEON 扩展指令的代码，用于向量化运算。
* **处理原子操作:**  定义了宏 (`ASSEMBLE_ATOMIC_LOAD_INTEGER`, `ASSEMBLE_ATOMIC_STORE_INTEGER` 等) 用于生成原子操作的指令，确保多线程环境下的数据一致性。
* **处理栈帧:**  包含操作栈帧的指令，例如分配和释放栈空间、保存和恢复寄存器。

**与 Javascript 的关系 (并用 Javascript 举例说明):**

这个 C++ 文件是 V8 JavaScript 引擎的一部分，直接负责将 JavaScript 代码编译成可以在 ARM 架构上执行的机器码。  它处理的许多操作都直接对应于 JavaScript 的语法和特性。

**例子:**

1. **对象属性赋值和写屏障:**

   ```javascript
   let obj = { x: 1 };
   let otherObj = { y: 2 };
   obj.x = otherObj; // 这里会触发写屏障
   ```

   当执行 `obj.x = otherObj;` 时，如果 `otherObj` 是一个需要垃圾回收的对象，V8 会执行一个写屏障操作，记录这次写入，以便垃圾回收器在后续的扫描中能正确跟踪对象的引用关系。  `OutOfLineRecordWrite` 类中的代码就是用来生成实现这个写屏障的 ARM 汇编指令。

2. **函数调用:**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   let result = add(5, 3);
   ```

   当调用 `add(5, 3)` 时，`kArchCallJSFunction` 分支下的代码会被执行，生成 ARM 汇编指令来设置函数参数，调用函数，并处理返回值。

3. **算术运算:**

   ```javascript
   let sum = 10 + 5;
   let product = 4 * 6;
   ```

   对于 `10 + 5`，`kArmAdd` 分支下的代码会生成 ARM 的 `add` 指令。对于 `4 * 6`，`kArmMul` 分支下的代码会生成 ARM 的 `mul` 指令。

4. **浮点数运算:**

   ```javascript
   let pi = Math.PI;
   let sqrtOfTwo = Math.sqrt(2);
   ```

   当执行 `Math.sqrt(2)` 时，`kArmVsqrtF64` 分支下的代码会被执行，生成 ARM 的 `vsqrt` 指令来计算平方根。

5. **数组操作 (可能涉及 SIMD):**

   ```javascript
   let arr1 = [1, 2, 3, 4];
   let arr2 = arr1.map(x => x * 2); // map 操作可能被优化为 SIMD 指令
   ```

   在某些情况下，V8 的优化编译器可以识别出数组的 map 操作，并利用 SIMD 指令 (例如通过 `kArmVmulS128` 等分支生成 NEON 指令) 来并行处理数组元素，提高性能。

**总结:**

该文件的第一部分是 V8 引擎中一个至关重要的组件，它充当了高级 JavaScript 代码和底层 ARM 硬件之间的桥梁。 通过将中间表示指令转换成高效的 ARM 汇编代码，它直接影响着 JavaScript 代码的执行效率。 各种针对特定场景的优化和对 WebAssembly 的支持也体现了 V8 引擎的复杂性和强大功能。

### 提示词
```
这是目录为v8/src/compiler/backend/arm/code-generator-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/numbers/double.h"
#include "src/codegen/arm/assembler-arm.h"
#include "src/codegen/arm/constants-arm.h"
#include "src/codegen/arm/register-arm.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/utils/boxed-float.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

#define __ masm()->

// Adds Arm-specific methods to convert InstructionOperands.
class ArmOperandConverter final : public InstructionOperandConverter {
 public:
  ArmOperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  SBit OutputSBit() const {
    switch (instr_->flags_mode()) {
      case kFlags_branch:
      case kFlags_conditional_branch:
      case kFlags_deoptimize:
      case kFlags_set:
      case kFlags_conditional_set:
      case kFlags_trap:
      case kFlags_select:
        return SetCC;
      case kFlags_none:
        return LeaveCC;
    }
    UNREACHABLE();
  }

  Operand InputImmediate(size_t index) const {
    return ToImmediate(instr_->InputAt(index));
  }

  Operand InputOperand2(size_t first_index) {
    const size_t index = first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
      case kMode_Offset_RI:
      case kMode_Offset_RR:
      case kMode_Root:
        break;
      case kMode_Operand2_I:
        return InputImmediate(index + 0);
      case kMode_Operand2_R:
        return Operand(InputRegister(index + 0));
      case kMode_Operand2_R_ASR_I:
        return Operand(InputRegister(index + 0), ASR, InputInt5(index + 1));
      case kMode_Operand2_R_ASR_R:
        return Operand(InputRegister(index + 0), ASR, InputRegister(index + 1));
      case kMode_Operand2_R_LSL_I:
        return Operand(InputRegister(index + 0), LSL, InputInt5(index + 1));
      case kMode_Operand2_R_LSL_R:
        return Operand(InputRegister(index + 0), LSL, InputRegister(index + 1));
      case kMode_Operand2_R_LSR_I:
        return Operand(InputRegister(index + 0), LSR, InputInt5(index + 1));
      case kMode_Operand2_R_LSR_R:
        return Operand(InputRegister(index + 0), LSR, InputRegister(index + 1));
      case kMode_Operand2_R_ROR_I:
        return Operand(InputRegister(index + 0), ROR, InputInt5(index + 1));
      case kMode_Operand2_R_ROR_R:
        return Operand(InputRegister(index + 0), ROR, InputRegister(index + 1));
    }
    UNREACHABLE();
  }

  MemOperand InputOffset(size_t* first_index) {
    const size_t index = *first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
      case kMode_Operand2_I:
      case kMode_Operand2_R:
      case kMode_Operand2_R_ASR_I:
      case kMode_Operand2_R_ASR_R:
      case kMode_Operand2_R_LSL_R:
      case kMode_Operand2_R_LSR_I:
      case kMode_Operand2_R_LSR_R:
      case kMode_Operand2_R_ROR_I:
      case kMode_Operand2_R_ROR_R:
        break;
      case kMode_Operand2_R_LSL_I:
        *first_index += 3;
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1),
                          LSL, InputInt32(index + 2));
      case kMode_Offset_RI:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputInt32(index + 1));
      case kMode_Offset_RR:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1));
      case kMode_Root:
        *first_index += 1;
        return MemOperand(kRootRegister, InputInt32(index));
    }
    UNREACHABLE();
  }

  MemOperand InputOffset(size_t first_index = 0) {
    return InputOffset(&first_index);
  }

  Operand ToImmediate(InstructionOperand* operand) const {
    Constant constant = ToConstant(operand);
    switch (constant.type()) {
      case Constant::kInt32:
        return Operand(constant.ToInt32(), constant.rmode());
      case Constant::kFloat32:
        return Operand::EmbeddedNumber(constant.ToFloat32());
      case Constant::kFloat64:
        return Operand::EmbeddedNumber(constant.ToFloat64().value());
      case Constant::kExternalReference:
        return Operand(constant.ToExternalReference());
      case Constant::kInt64:
      case Constant::kCompressedHeapObject:
      case Constant::kHeapObject:
      // TODO(dcarney): loading RPO constants on arm.
      case Constant::kRpoNumber:
        break;
    }
    UNREACHABLE();
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

  NeonMemOperand NeonInputOperand(size_t first_index) {
    const size_t index = first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_Operand2_R:
        return NeonMemOperand(InputRegister(index + 0));
      default:
        break;
    }
    UNREACHABLE();
  }
};

namespace {

class OutOfLineRecordWrite final : public OutOfLineCode {
 public:
  OutOfLineRecordWrite(CodeGenerator* gen, Register object, Operand offset,
                       Register value, RecordWriteMode mode,
                       StubCallMode stub_mode,
                       UnwindingInfoWriter* unwinding_info_writer)
      : OutOfLineCode(gen),
        object_(object),
        offset_(offset),
        value_(value),
        mode_(mode),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        must_save_lr_(!gen->frame_access_state()->has_frame()),
        unwinding_info_writer_(unwinding_info_writer),
        zone_(gen->zone()) {
  }

  void Generate() final {
    __ CheckPageFlag(value_, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                     exit());
    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    if (must_save_lr_) {
      // We need to save and restore lr if the frame was elided.
      __ Push(lr);
      unwinding_info_writer_->MarkLinkRegisterOnTopOfStack(__ pc_offset());
    }
    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, offset_, save_fp_mode);
#if V8_ENABLE_WEBASSEMBLY
    } else if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      __ CallRecordWriteStubSaveRegisters(object_, offset_, save_fp_mode,
                                          StubCallMode::kCallWasmRuntimeStub);
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      __ CallRecordWriteStubSaveRegisters(object_, offset_, save_fp_mode);
    }
    if (must_save_lr_) {
      __ Pop(lr);
      unwinding_info_writer_->MarkPopLinkRegisterFromTopOfStack(__ pc_offset());
    }
  }

 private:
  Register const object_;
  Operand const offset_;
  Register const value_;
  RecordWriteMode const mode_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  bool must_save_lr_;
  UnwindingInfoWriter* const unwinding_info_writer_;
  Zone* zone_;
};

template <typename T>
class OutOfLineFloatMin final : public OutOfLineCode {
 public:
  OutOfLineFloatMin(CodeGenerator* gen, T result, T left, T right)
      : OutOfLineCode(gen), result_(result), left_(left), right_(right) {}

  void Generate() final { __ FloatMinOutOfLine(result_, left_, right_); }

 private:
  T const result_;
  T const left_;
  T const right_;
};
using OutOfLineFloat32Min = OutOfLineFloatMin<SwVfpRegister>;
using OutOfLineFloat64Min = OutOfLineFloatMin<DwVfpRegister>;

template <typename T>
class OutOfLineFloatMax final : public OutOfLineCode {
 public:
  OutOfLineFloatMax(CodeGenerator* gen, T result, T left, T right)
      : OutOfLineCode(gen), result_(result), left_(left), right_(right) {}

  void Generate() final { __ FloatMaxOutOfLine(result_, left_, right_); }

 private:
  T const result_;
  T const left_;
  T const right_;
};
using OutOfLineFloat32Max = OutOfLineFloatMax<SwVfpRegister>;
using OutOfLineFloat64Max = OutOfLineFloatMax<DwVfpRegister>;

Condition FlagsConditionToCondition(FlagsCondition condition) {
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
    case kFloatLessThanOrUnordered:
      return lt;
    case kFloatGreaterThanOrEqual:
      return ge;
    case kFloatLessThanOrEqual:
      return ls;
    case kFloatGreaterThanOrUnordered:
      return hi;
    case kFloatLessThan:
      return lo;
    case kFloatGreaterThanOrEqualOrUnordered:
      return hs;
    case kFloatLessThanOrEqualOrUnordered:
      return le;
    case kFloatGreaterThan:
      return gt;
    case kOverflow:
      return vs;
    case kNotOverflow:
      return vc;
    case kPositiveOrZero:
      return pl;
    case kNegative:
      return mi;
    default:
      break;
  }
  UNREACHABLE();
}

}  // namespace

#define ASSEMBLE_ATOMIC_LOAD_INTEGER(asm_instr)                       \
  do {                                                                \
    __ asm_instr(i.OutputRegister(),                                  \
                 MemOperand(i.InputRegister(0), i.InputRegister(1))); \
    __ dmb(ISH);                                                      \
  } while (0)

#define ASSEMBLE_ATOMIC_STORE_INTEGER(asm_instr, order)   \
  do {                                                    \
    __ dmb(ISH);                                          \
    __ asm_instr(i.InputRegister(0), i.InputOffset(1));   \
    if (order == AtomicMemoryOrder::kSeqCst) __ dmb(ISH); \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(load_instr, store_instr)             \
  do {                                                                        \
    Label exchange;                                                           \
    __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));        \
    __ dmb(ISH);                                                              \
    __ bind(&exchange);                                                       \
    __ load_instr(i.OutputRegister(0), i.TempRegister(1));                    \
    __ store_instr(i.TempRegister(0), i.InputRegister(2), i.TempRegister(1)); \
    __ teq(i.TempRegister(0), Operand(0));                                    \
    __ b(ne, &exchange);                                                      \
    __ dmb(ISH);                                                              \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(load_instr, store_instr,     \
                                                 cmp_reg)                     \
  do {                                                                        \
    Label compareExchange;                                                    \
    Label exit;                                                               \
    __ dmb(ISH);                                                              \
    __ bind(&compareExchange);                                                \
    __ load_instr(i.OutputRegister(0), i.TempRegister(1));                    \
    __ teq(cmp_reg, Operand(i.OutputRegister(0)));                            \
    __ b(ne, &exit);                                                          \
    __ store_instr(i.TempRegister(0), i.InputRegister(3), i.TempRegister(1)); \
    __ teq(i.TempRegister(0), Operand(0));                                    \
    __ b(ne, &compareExchange);                                               \
    __ bind(&exit);                                                           \
    __ dmb(ISH);                                                              \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP(load_instr, store_instr, bin_instr)            \
  do {                                                                       \
    Label binop;                                                             \
    __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));       \
    __ dmb(ISH);                                                             \
    __ bind(&binop);                                                         \
    __ load_instr(i.OutputRegister(0), i.TempRegister(1));                   \
    __ bin_instr(i.TempRegister(0), i.OutputRegister(0),                     \
                 Operand(i.InputRegister(2)));                               \
    __ store_instr(i.TempRegister(2), i.TempRegister(0), i.TempRegister(1)); \
    __ teq(i.TempRegister(2), Operand(0));                                   \
    __ b(ne, &binop);                                                        \
    __ dmb(ISH);                                                             \
  } while (0)

#define ASSEMBLE_ATOMIC64_ARITH_BINOP(instr1, instr2)                  \
  do {                                                                 \
    Label binop;                                                       \
    __ add(i.TempRegister(0), i.InputRegister(2), i.InputRegister(3)); \
    __ dmb(ISH);                                                       \
    __ bind(&binop);                                                   \
    __ ldrexd(r2, r3, i.TempRegister(0));                              \
    __ instr1(i.TempRegister(1), r2, i.InputRegister(0), SetCC);       \
    __ instr2(i.TempRegister(2), r3, Operand(i.InputRegister(1)));     \
    DCHECK_EQ(LeaveCC, i.OutputSBit());                                \
    __ strexd(i.TempRegister(3), i.TempRegister(1), i.TempRegister(2), \
              i.TempRegister(0));                                      \
    __ teq(i.TempRegister(3), Operand(0));                             \
    __ b(ne, &binop);                                                  \
    __ dmb(ISH);                                                       \
  } while (0)

#define ASSEMBLE_ATOMIC64_LOGIC_BINOP(instr)                           \
  do {                                                                 \
    Label binop;                                                       \
    __ add(i.TempRegister(0), i.InputRegister(2), i.InputRegister(3)); \
    __ dmb(ISH);                                                       \
    __ bind(&binop);                                                   \
    __ ldrexd(r2, r3, i.TempRegister(0));                              \
    __ instr(i.TempRegister(1), r2, Operand(i.InputRegister(0)));      \
    __ instr(i.TempRegister(2), r3, Operand(i.InputRegister(1)));      \
    __ strexd(i.TempRegister(3), i.TempRegister(1), i.TempRegister(2), \
              i.TempRegister(0));                                      \
    __ teq(i.TempRegister(3), Operand(0));                             \
    __ b(ne, &binop);                                                  \
    __ dmb(ISH);                                                       \
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                           \
  do {                                                                         \
    /* TODO(bmeurer): We should really get rid of this special instruction, */ \
    /* and generate a CallAddress instruction instead. */                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                              \
    __ PrepareCallCFunction(0, 2);                                             \
    __ MovToFloatParameters(i.InputDoubleRegister(0),                          \
                            i.InputDoubleRegister(1));                         \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 2);    \
    /* Move the result in the double result register. */                       \
    __ MovFromFloatResult(i.OutputDoubleRegister());                           \
    DCHECK_EQ(LeaveCC, i.OutputSBit());                                        \
  } while (0)

#define ASSEMBLE_IEEE754_UNOP(name)                                            \
  do {                                                                         \
    /* TODO(bmeurer): We should really get rid of this special instruction, */ \
    /* and generate a CallAddress instruction instead. */                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                              \
    __ PrepareCallCFunction(0, 1);                                             \
    __ MovToFloatParameter(i.InputDoubleRegister(0));                          \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 1);    \
    /* Move the result in the double result register. */                       \
    __ MovFromFloatResult(i.OutputDoubleRegister());                           \
    DCHECK_EQ(LeaveCC, i.OutputSBit());                                        \
  } while (0)

#define ASSEMBLE_NEON_NARROWING_OP(dt, sdt)           \
  do {                                                \
    Simd128Register dst = i.OutputSimd128Register(),  \
                    src0 = i.InputSimd128Register(0), \
                    src1 = i.InputSimd128Register(1); \
    if (dst == src0 && dst == src1) {                 \
      __ vqmovn(dt, sdt, dst.low(), src0);            \
      __ vmov(dst.high(), dst.low());                 \
    } else if (dst == src0) {                         \
      __ vqmovn(dt, sdt, dst.low(), src0);            \
      __ vqmovn(dt, sdt, dst.high(), src1);           \
    } else {                                          \
      __ vqmovn(dt, sdt, dst.high(), src1);           \
      __ vqmovn(dt, sdt, dst.low(), src0);            \
    }                                                 \
  } while (0)

#define ASSEMBLE_F64X2_ARITHMETIC_BINOP(op)                                   \
  do {                                                                        \
    __ op(i.OutputSimd128Register().low(), i.InputSimd128Register(0).low(),   \
          i.InputSimd128Register(1).low());                                   \
    __ op(i.OutputSimd128Register().high(), i.InputSimd128Register(0).high(), \
          i.InputSimd128Register(1).high());                                  \
  } while (0)

// If shift value is an immediate, we can call asm_imm, taking the shift value
// modulo 2^width. Otherwise, emit code to perform the modulus operation, and
// call vshl.
#define ASSEMBLE_SIMD_SHIFT_LEFT(asm_imm, width, sz, dt) \
  do {                                                   \
    QwNeonRegister dst = i.OutputSimd128Register();      \
    QwNeonRegister src = i.InputSimd128Register(0);      \
    if (instr->InputAt(1)->IsImmediate()) {              \
      __ asm_imm(dt, dst, src, i.InputInt##width(1));    \
    } else {                                             \
      UseScratchRegisterScope temps(masm());             \
      Simd128Register tmp = temps.AcquireQ();            \
      Register shift = temps.Acquire();                  \
      constexpr int mask = (1 << width) - 1;             \
      __ and_(shift, i.InputRegister(1), Operand(mask)); \
      __ vdup(sz, tmp, shift);                           \
      __ vshl(dt, dst, src, tmp);                        \
    }                                                    \
  } while (0)

// If shift value is an immediate, we can call asm_imm, taking the shift value
// modulo 2^width. Otherwise, emit code to perform the modulus operation, and
// call vshl, passing in the negative shift value (treated as a right shift).
#define ASSEMBLE_SIMD_SHIFT_RIGHT(asm_imm, width, sz, dt) \
  do {                                                    \
    QwNeonRegister dst = i.OutputSimd128Register();       \
    QwNeonRegister src = i.InputSimd128Register(0);       \
    if (instr->InputAt(1)->IsImmediate()) {               \
      __ asm_imm(dt, dst, src, i.InputInt##width(1));     \
    } else {                                              \
      UseScratchRegisterScope temps(masm());              \
      Simd128Register tmp = temps.AcquireQ();             \
      Register shift = temps.Acquire();                   \
      constexpr int mask = (1 << width) - 1;              \
      __ and_(shift, i.InputRegister(1), Operand(mask));  \
      __ vdup(sz, tmp, shift);                            \
      __ vneg(sz, tmp, tmp);                              \
      __ vshl(dt, dst, src, tmp);                         \
    }                                                     \
  } while (0)

void CodeGenerator::AssembleDeconstructFrame() {
  __ LeaveFrame(StackFrame::MANUAL);
  unwinding_info_writer_.MarkFrameDeconstructed(__ pc_offset());
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ ldm(ia, fp, {lr, fp});
  }
  frame_access_state()->SetFrameAccessToSP();
}

namespace {

void FlushPendingPushRegisters(MacroAssembler* masm,
                               FrameAccessState* frame_access_state,
                               ZoneVector<Register>* pending_pushes) {
  switch (pending_pushes->size()) {
    case 0:
      break;
    case 1:
      masm->push((*pending_pushes)[0]);
      break;
    case 2:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1]);
      break;
    case 3:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1],
                 (*pending_pushes)[2]);
      break;
    default:
      UNREACHABLE();
  }
  frame_access_state->IncreaseSPDelta(pending_pushes->size());
  pending_pushes->clear();
}

void AdjustStackPointerForTailCall(
    MacroAssembler* masm, FrameAccessState* state, int new_slot_above_sp,
    ZoneVector<Register>* pending_pushes = nullptr,
    bool allow_shrinkage = true) {
  int current_sp_offset = state->GetSPToFPSlotCount() +
                          StandardFrameConstants::kFixedSlotCountAboveFp;
  int stack_slot_delta = new_slot_above_sp - current_sp_offset;
  if (stack_slot_delta > 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->AllocateStackSpace(stack_slot_delta * kSystemPointerSize);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->add(sp, sp, Operand(-stack_slot_delta * kSystemPointerSize));
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

#if DEBUG
bool VerifyOutputOfAtomicPairInstr(ArmOperandConverter* converter,
                                   const Instruction* instr, Register low,
                                   Register high) {
  DCHECK_GE(instr->OutputCount() + instr->TempCount(), 2);
  if (instr->OutputCount() == 2) {
    return (converter->OutputRegister(0) == low &&
            converter->OutputRegister(1) == high);
  }
  if (instr->OutputCount() == 1) {
    return (converter->OutputRegister(0) == low &&
            converter->TempRegister(instr->TempCount() - 1) == high) ||
           (converter->OutputRegister(0) == high &&
            converter->TempRegister(instr->TempCount() - 1) == low);
  }
  DCHECK_EQ(instr->OutputCount(), 0);
  return (converter->TempRegister(instr->TempCount() - 2) == low &&
          converter->TempRegister(instr->TempCount() - 1) == high);
}
#endif

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  ZoneVector<MoveOperands*> pushes(zone());
  GetPushCompatibleMoves(instr, kRegisterPush, &pushes);

  if (!pushes.empty() &&
      (LocationOperand::cast(pushes.back()->destination()).index() + 1 ==
       first_unused_slot_offset)) {
    ArmOperandConverter g(this, instr);
    ZoneVector<Register> pending_pushes(zone());
    for (auto move : pushes) {
      LocationOperand destination_location(
          LocationOperand::cast(move->destination()));
      InstructionOperand source(move->source());
      AdjustStackPointerForTailCall(
          masm(), frame_access_state(),
          destination_location.index() - pending_pushes.size(),
          &pending_pushes);
      // Pushes of non-register data types are not supported.
      DCHECK(source.IsRegister());
      LocationOperand source_location(LocationOperand::cast(source));
      pending_pushes.push_back(source_location.GetRegister());
      // TODO(arm): We can push more than 3 registers at once. Add support in
      // the macro-assembler for pushing a list of registers.
      if (pending_pushes.size() == 3) {
        FlushPendingPushRegisters(masm(), frame_access_state(),
                                  &pending_pushes);
      }
      move->Eliminate();
    }
    FlushPendingPushRegisters(masm(), frame_access_state(), &pending_pushes);
  }
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset, nullptr, false);
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
  __ cmp(scratch, kJavaScriptCallCodeStartRegister);
  __ Assert(eq, AbortReason::kWrongFunctionCodeStart);
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void CodeGenerator::BailoutIfDeoptimized() { __ BailoutIfDeoptimized(); }

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  ArmOperandConverter i(this, instr);

  __ MaybeCheckConstPool();
  InstructionCode opcode = instr->opcode();
  ArchOpcode arch_opcode = ArchOpcodeField::decode(opcode);
  switch (arch_opcode) {
    case kArchCallCodeObject: {
      if (instr->InputAt(0)->IsImmediate()) {
        __ Call(i.InputCode(0), RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ CallCodeObject(reg);
      }
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
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
        Address wasm_code = static_cast<Address>(constant.ToInt32());
        __ Call(wasm_code, constant.rmode());
      } else {
        __ Call(i.InputRegister(0));
      }
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchTailCallWasm: {
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt32());
        __ Jump(wasm_code, constant.rmode());
      } else {
        __ Jump(i.InputRegister(0));
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      unwinding_info_writer_.MarkBlockWillExit();
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
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ JumpCodeObject(reg);
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      unwinding_info_writer_.MarkBlockWillExit();
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
      unwinding_info_writer_.MarkBlockWillExit();
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
        __ ldr(scratch, FieldMemOperand(func, JSFunction::kContextOffset));
        __ cmp(cp, scratch);
        __ Assert(eq, AbortReason::kWrongFunctionContext);
      }
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments);
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      __ PrepareCallCFunction(num_gp_parameters + num_fp_parameters);
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
      int const num_parameters = ParamField::decode(instr->opcode()) +
                                 FPParamField::decode(instr->opcode());
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes;
      Label return_location;
#if V8_ENABLE_WEBASSEMBLY
      if (linkage()->GetIncomingDescriptor()->IsWasmCapiFunction()) {
        // Put the return address in a stack slot.
        Register pc_scratch = r5;
        __ Push(pc_scratch);
        __ GetLabelAddress(pc_scratch, &return_location);
        __ str(pc_scratch,
               MemOperand(fp, WasmExitFrameConstants::kCallingPCOffset));
        __ Pop(pc_scratch);
        set_isolate_data_slots = SetIsolateDataSlots::kNo;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      int pc_offset;
      if (instr->InputAt(0)->IsImmediate()) {
        ExternalReference ref = i.InputExternalReference(0);
        pc_offset = __ CallCFunction(ref, num_parameters,
                                     set_isolate_data_slots, &return_location);
      } else {
        Register func = i.InputRegister(0);
        pc_offset = __ CallCFunction(func, num_parameters,
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
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchBinarySearchSwitch:
      AssembleArchBinarySearchSwitch(instr);
      break;
    case kArchTableSwitch:
      AssembleArchTableSwitch(instr);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchAbortCSADcheck:
      DCHECK(i.InputRegister(0) == r1);
      {
        // We don't actually want to generate a pile of code for this, so just
        // claim there is a stack frame, without generating one.
        FrameScope scope(masm(), StackFrame::NO_FRAME_TYPE);
        __ CallBuiltin(Builtin::kAbortCSADcheck);
      }
      __ stop();
      unwinding_info_writer_.MarkBlockWillExit();
      break;
    case kArchDebugBreak:
      __ DebugBreak();
      break;
    case kArchComment:
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt32(0)),
                       SourceLocation());
      break;
    case kArchThrowTerminator:
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      unwinding_info_writer_.MarkBlockWillExit();
      break;
    case kArchNop:
      // don't emit code for nops.
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchDeoptimize: {
      DeoptimizationExit* exit =
          BuildTranslation(instr, -1, 0, 0, OutputFrameStateCombine::Ignore());
      __ b(exit->label());
      break;
    }
    case kArchRet:
      AssembleReturn(instr->InputAt(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchFramePointer:
      __ mov(i.OutputRegister(), fp);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ ldr(i.OutputRegister(), MemOperand(fp, 0));
      } else {
        __ mov(i.OutputRegister(), fp);
      }
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      // The register allocator expects an allocatable register for the output,
      // we cannot use sp directly.
      __ mov(i.OutputRegister(), sp);
      break;
    case kArchSetStackPointer:
      DCHECK(instr->InputAt(0)->IsRegister());
      __ mov(sp, i.InputRegister(0));
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchStackPointerGreaterThan: {
      // Potentially apply an offset to the current stack pointer before the
      // comparison to consider the size difference of an optimized frame versus
      // the contained unoptimized frames.

      Register lhs_register = sp;
      uint32_t offset;

      if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
        lhs_register = i.TempRegister(0);
        __ sub(lhs_register, sp, Operand(offset));
      }

      constexpr size_t kValueIndex = 0;
      DCHECK(instr->InputAt(kValueIndex)->IsRegister());
      __ cmp(lhs_register, i.InputRegister(kValueIndex));
      break;
    }
    case kArchStackCheckOffset:
      __ Move(i.OutputRegister(), Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchStoreWithWriteBarrier:  // Fall through.
    case kArchAtomicStoreWithWriteBarrier: {
      RecordWriteMode mode;
      if (arch_opcode == kArchStoreWithWriteBarrier) {
        mode = RecordWriteModeField::decode(instr->opcode());
      } else {
        mode = AtomicStoreRecordWriteModeField::decode(instr->opcode());
      }
      Register object = i.InputRegister(0);
      Register value = i.InputRegister(2);

      if (v8_flags.debug_code) {
        // Checking that |value| is not a cleared weakref: our write barrier
        // does not support that for now.
        __ cmp(value, Operand(kClearedWeakHeapObjectLower32));
        __ Check(ne, AbortReason::kOperandIsCleared);
      }

      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      Operand offset(0);

      if (arch_opcode == kArchAtomicStoreWithWriteBarrier) {
        __ dmb(ISH);
      }
      if (addressing_mode == kMode_Offset_RI) {
        int32_t immediate = i.InputInt32(1);
        offset = Operand(immediate);
        __ str(value, MemOperand(object, immediate));
      } else {
        DCHECK_EQ(kMode_Offset_RR, addressing_mode);
        Register reg = i.InputRegister(1);
        offset = Operand(reg);
        __ str(value, MemOperand(object, reg));
      }
      if (arch_opcode == kArchAtomicStoreWithWriteBarrier &&
          AtomicMemoryOrderField::decode(instr->opcode()) ==
              AtomicMemoryOrder::kSeqCst) {
        __ dmb(ISH);
      }

      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, offset, value, mode, DetermineStubCallMode(),
          &unwinding_info_writer_);
      if (mode > RecordWriteMode::kValueIsPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask,
                       ne, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier:
      UNREACHABLE();
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      Register base = offset.from_stack_pointer() ? sp : fp;
      __ add(i.OutputRegister(0), base, Operand(offset.offset()));
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
    case kIeee754Float64Cbrt:
      ASSEMBLE_IEEE754_UNOP(cbrt);
      break;
    case kIeee754Float64Cos:
      ASSEMBLE_IEEE754_UNOP(cos);
      break;
    case kIeee754Float64Cosh:
      ASSEMBLE_IEEE754_UNOP(cosh);
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
    case kArmAdd:
      __ add(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmAnd:
      __ and_(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
              i.OutputSBit());
      break;
    case kArmBic:
      __ bic(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmMul:
      __ mul(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
             i.OutputSBit());
      break;
    case kArmMla:
      __ mla(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
             i.InputRegister(2), i.OutputSBit());
      break;
    case kArmMls: {
      CpuFeatureScope scope(masm(), ARMv7);
      __ mls(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
             i.InputRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmSmull:
      __ smull(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
               i.InputRegister(1));
      break;
    case kArmSmmul:
      __ smmul(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmSmmla:
      __ smmla(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.InputRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmUmull:
      __ umull(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
               i.InputRegister(1), i.OutputSBit());
      break;
    case kArmSdiv: {
      CpuFeatureScope scope(masm(), SUDIV);
      __ sdiv(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmUdiv: {
      CpuFeatureScope scope(masm(), SUDIV);
      __ udiv(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmMov:
      __ Move(i.OutputRegister(), i.InputOperand2(0), i.OutputSBit());
      break;
    case kArmMvn:
      __ mvn(i.OutputRegister(), i.InputOperand2(0), i.OutputSBit());
      break;
    case kArmOrr:
      __ orr(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmEor:
      __ eor(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmSub:
      __ sub(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmRsb:
      __ rsb(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmBfc: {
      CpuFeatureScope scope(masm(), ARMv7);
      __ bfc(i.OutputRegister(), i.InputInt8(1), i.InputInt8(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmUbfx: {
      CpuFeatureScope scope(masm(), ARMv7);
      __ ubfx(i.OutputRegister(), i.InputRegister(0), i.InputInt8(1),
              i.InputInt8(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmSbfx: {
      CpuFeatureScope scope(masm(), ARMv7);
      __ sbfx(i.OutputRegister(), i.InputRegister(0), i.InputInt8(1),
              i.InputInt8(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmSxtb:
      __ sxtb(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmSxth:
      __ sxth(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmSxtab:
      __ sxtab(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.InputInt32(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmSxtah:
      __ sxtah(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.InputInt32(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmUxtb:
      __ uxtb(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmUxth:
      __ uxth(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmUxtab:
      __ uxtab(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.InputInt32(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmUxtah:
      __ uxtah(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.InputInt32(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmRbit: {
      CpuFeatureScope scope(masm(), ARMv7);
      __ rbit(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmRev:
      __ rev(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmClz:
      __ clz(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmCmp:
      __ cmp(i.InputRegister(0), i.InputOperand2(1));
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmCmn:
      __ cmn(i.InputRegister(0), i.InputOperand2(1));
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmTst:
      __ tst(i.InputRegister(0), i.InputOperand2(1));
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmTeq:
      __ teq(i.InputRegister(0), i.InputOperand2(1));
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmAddPair:
      // i.InputRegister(0) ... left low word.
      // i.InputRegister(1) ... left high word.
      // i.InputRegister(2) ... right low word.
      // i.InputRegister(3) ... right high word.
      __ add(i.OutputRegister(0), i.InputRegister(0), i.InputRegister(2),
             SetCC);
      __ adc(i.OutputRegister(1), i.InputRegister(1),
             Operand(i.InputRegister(3)));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmSubPair:
      // i.InputRegister(0) ... left low word.
      // i.InputRegister(1) ... left high word.
      // i.InputRegister(2) ... right low word.
      // i.InputRegister(3) ... right high word.
      __ sub(i.OutputRegister(0), i.InputRegister(0), i.InputRegister(2),
             SetCC);
      __ sbc(i.OutputRegister(1), i.InputRegister(1),
             Operand(i.InputRegister(3)));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmMulPair:
      // i.InputRegister(0) ... left low word.
      // i.InputRegister(1) ... left high word.
      // i.InputRegister(2) ... right low word.
      // i.InputRegister(3) ... right high word.
      __ umull(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
               i.InputRegister(2));
      __ mla(i.OutputRegister(1), i.InputRegister(0), i.InputRegister(3),
             i.OutputRegister(1));
      __ mla(i.OutputRegister(1), i.InputRegister(2), i.InputRegister(1),
             i.OutputRegister(1));
      break;
    case kArmLslPair: {
      Register second_output =
          instr->OutputCount() >= 2 ? i.OutputRegister(1) : i.TempRegister(0);
      if (instr->InputAt(2)->IsImmediate()) {
        __ LslPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputInt32(2));
      } else {
        __ LslPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputRegister(2));
      }
      break;
    }
    case kArmLsrPair: {
      Register second_output =
          instr->OutputCount() >= 2 ? i.OutputRegister(1) : i.TempRegister(0);
      if (instr->InputAt(2)->IsImmediate()) {
        __ LsrPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputInt32(2));
      } else {
        __ LsrPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputRegister(2));
      }
      break;
    }
    case kArmAsrPair: {
      Register second_output =
          instr->OutputCount() >= 2 ? i.OutputRegister(1) : i.TempRegister(0);
      if (instr->InputAt(2)->IsImmediate()) {
        __ AsrPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputInt32(2));
      } else {
        __ AsrPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputRegister(2));
      }
      break;
    }
    case kArmVcmpF32:
      if (instr->InputAt(1)->IsFPRegister()) {
        __ VFPCompareAndSetFlags(i.InputFloatRegister(0),
                                 i.InputFloatRegister(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        // 0.0 is the only immediate supported by vcmp instructions.
        DCHECK_EQ(0.0f, i.InputFloat32(1));
        __ VFPCompareAndSetFlags(i.InputFloatRegister(0), i.InputFloat32(1));
      }
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmVaddF32:
      __ vadd(i.OutputFloatRegister(), i.InputFloatRegister(0),
              i.InputFloatRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVsubF32:
      __ vsub(i.OutputFloatRegister(), i.InputFloatRegister(0),
              i.InputFloatRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmulF32:
      __ vmul(i.OutputFloatRegister(), i.InputFloatRegister(0),
              i.InputFloatRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmlaF32:
      __ vmla(i.OutputFloatRegister(), i.InputFloatRegister(1),
              i.InputFloatRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmlsF32:
      __ vmls(i.OutputFloatRegister(), i.InputFloatRegister(1),
              i.InputFloatRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVdivF32:
      __ vdiv(i.OutputFloatRegister(), i.InputFloatRegister(0),
              i.InputFloatRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVsqrtF32:
      __ vsqrt(i.OutputFloatRegister(), i.InputFloatRegister(0));
      break;
    case kArmVabsF32:
      __ vabs(i.OutputFloatRegister(), i.InputFloatRegister(0));
      break;
    case kArmVnegF32:
      __ vneg(i.OutputFloatRegister(), i.InputFloatRegister(0));
      break;
    case kArmVcmpF64:
      if (instr->InputAt(1)->IsFPRegister()) {
        __ VFPCompareAndSetFlags(i.InputDoubleRegister(0),
                                 i.InputDoubleRegister(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        // 0.0 is the only immediate supported by vcmp instructions.
        DCHECK_EQ(0.0, i.InputDouble(1));
        __ VFPCompareAndSetFlags(i.InputDoubleRegister(0), i.InputDouble(1));
      }
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmVaddF64:
      __ vadd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVsubF64:
      __ vsub(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmulF64:
      __ vmul(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmlaF64:
      __ vmla(i.OutputDoubleRegister(), i.InputDoubleRegister(1),
              i.InputDoubleRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmlsF64:
      __ vmls(i.OutputDoubleRegister(), i.InputDoubleRegister(1),
              i.InputDoubleRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVdivF64:
      __ vdiv(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmodF64: {
      // TODO(bmeurer): We should really get rid of this special instruction,
      // and generate a CallAddress instruction instead.
      FrameScope scope(masm(), StackFrame::MANUAL);
      __ PrepareCallCFunction(0, 2);
      __ MovToFloatParameters(i.InputDoubleRegister(0),
                              i.InputDoubleRegister(1));
      __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
      // Move the result in the double result register.
      __ MovFromFloatResult(i.OutputDoubleRegister());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVsqrtF64:
      __ vsqrt(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kArmVabsF64:
      __ vabs(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kArmVnegF64:
      __ vneg(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kArmVrintmF32: {
      CpuFeatureScope scope(masm(), ARMv8);
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ vrintm(NeonS32, i.OutputSimd128Register(),
                  i.InputSimd128Register(0));
      } else {
        __ vrintm(i.OutputFloatRegister(), i.InputFloatRegister(0));
      }
      break;
    }
    case kArmVrintmF64: {
      CpuFeatureScope scope(masm(), ARMv8);
      __ vrintm(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kArmVrintpF32: {
      CpuFeatureScope scope(masm(), ARMv8);
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ vrintp(NeonS32, i.OutputSimd128Register(),
                  i.InputSimd128Register(0));
      } else {
        __ vrintp(i.OutputFloatRegister(), i.InputFloatRegister(0));
      }
      break;
    }
    case kArmVrintpF64: {
      CpuFeatureScope scope(masm(), ARMv8);
      __ vrintp(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kArmVrintzF32: {
      CpuFeatureScope scope(masm(), ARMv8);
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ vrintz(NeonS32, i.OutputSimd128Register(),
                  i.InputSimd128Register(0));
      } else {
        __ vrintz(i.OutputFloatRegister(), i.InputFloatRegister(0));
      }
      break;
    }
    case kArmVrintzF64: {
      CpuFeatureScope scope(masm(), ARMv8);
      __ vrintz(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kArmVrintaF64: {
      CpuFeatureScope scope(masm(), ARMv8);
      __ vrinta(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kArmVrintnF32: {
      CpuFeatureScope scope(masm(), ARMv8);
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ vrintn(NeonS32, i.OutputSimd128Register(),
                  i.InputSimd128Register(0));
      } else {
        __ vrintn(i.OutputFloatRegister(), i.InputFloatRegister(0));
      }
      break;
    }
    case kArmVrintnF64: {
      CpuFeatureScope scope(masm(), ARMv8);
      __ vrintn(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kArmVcvtF32F64: {
      __ vcvt_f32_f64(i.OutputFloatRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtF64F32: {
      __ vcvt_f64_f32(i.OutputDoubleRegister(), i.InputFloatRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtF32S32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vmov(scratch, i.InputRegister(0));
      __ vcvt_f32_s32(i.OutputFloatRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtF32U32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vmov(scratch, i.InputRegister(0));
      __ vcvt_f32_u32(i.OutputFloatRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtF64S32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vmov(scratch, i.InputRegister(0));
      __ vcvt_f64_s32(i.OutputDoubleRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtF64U32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vmov(scratch, i.InputRegister(0));
      __ vcvt_f64_u32(i.OutputDoubleRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtS32F32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vcvt_s32_f32(scratch, i.InputFloatRegister(0));
      __ vmov(i.OutputRegister(), scratch);
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_i32) {
        // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
        // because INT32_MIN allows easier out-of-bounds detection.
        __ cmn(i.OutputRegister(), Operand(1));
        __ mov(i.OutputRegister(), Operand(INT32_MIN), LeaveCC, vs);
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtU32F32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vcvt_u32_f32(scratch, i.InputFloatRegister(0));
      __ vmov(i.OutputRegister(), scratch);
      bool set_overflow_to_min_u32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_u32) {
        // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
        // because 0 allows easier out-of-bounds detection.
        __ cmn(i.OutputRegister(), Operand(1));
        __ adc(i.OutputRegister(), i.OutputRegister(), Operand::Zero());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtS32F64: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vcvt_s32_f64(scratch, i.InputDoubleRegister(0));
      __ vmov(i.OutputRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtU32F64: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vcvt_u32_f64(scratch, i.InputDoubleRegister(0));
      __ vmov(i.OutputRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVmovU32F32:
      __ vmov(i.OutputRegister(), i.InputFloatRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovF32U32:
      __ vmov(i.OutputFloatRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovLowU32F64:
      __ VmovLow(i.OutputRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovLowF64U32:
      __ VmovLow(i.OutputDoubleRegister(), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovHighU32F64:
      __ VmovHigh(i.OutputRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovHighF64U32:
      __ VmovHigh(i.OutputDoubleRegister(), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovF64U32U32:
      __ vmov(i.OutputDoubleRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovU32U32F64:
      __ vmov(i.OutputRegister(0), i.OutputRegister(1),
              i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVcnt: {
      __ vcnt(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmLdrb:
      __ ldrb(i.OutputRegister(), i.InputOffset());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmLdrsb:
      __ ldrsb(i.OutputRegister(), i.InputOffset());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmStrb:
      __ strb(i.InputRegister(0), i.InputOffset(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmLdrh:
      __ ldrh(i.OutputRegister(), i.InputOffset());
      break;
    case kArmLdrsh:
      __ ldrsh(i.OutputRegister(), i.InputOffset());
      break;
    case kArmStrh:
      __ strh(i.InputRegister(0), i.InputOffset(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmLdr:
      __ ldr(i.OutputRegister(), i.InputOffset());
      break;
    case kArmStr:
      __ str(i.InputRegister(0), i.InputOffset(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVldrF32: {
      __ vldr(i.OutputFloatRegister(), i.InputOffset());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVstrF32:
      __ vstr(i.InputFloatRegister(0), i.InputOffset(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVld1F64: {
      __ vld1(Neon8, NeonListOperand(i.OutputDoubleRegister()),
              i.NeonInputOperand(0));
      break;
    }
    case kArmVst1F64: {
      __ vst1(Neon8, NeonListOperand(i.InputDoubleRegister(0)),
              i.NeonInputOperand(1));
      break;
    }
    case kArmVld1S128: {
      __ vld1(Neon8, NeonListOperand(i.OutputSimd128Register()),
              i.NeonInputOperand(0));
      break;
    }
    case kArmVst1S128: {
      __ vst1(Neon8, NeonListOperand(i.InputSimd128Register(0)),
              i.NeonInputOperand(1));
      break;
    }
    case kArmVldrF64: {
      __ vldr(i.OutputDoubleRegister(), i.InputOffset());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVstrF64:
      __ vstr(i.InputDoubleRegister(0), i.InputOffset(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmFloat32Max: {
      SwVfpRegister result = i.OutputFloatRegister();
      SwVfpRegister left = i.InputFloatRegister(0);
      SwVfpRegister right = i.InputFloatRegister(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool = zone()->New<OutOfLineFloat32Max>(this, result, left, right);
        __ FloatMax(result, left, right, ool->entry());
        __ bind(ool->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmFloat64Max: {
      DwVfpRegister result = i.OutputDoubleRegister();
      DwVfpRegister left = i.InputDoubleRegister(0);
      DwVfpRegister right = i.InputDoubleRegister(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool = zone()->New<OutOfLineFloat64Max>(this, result, left, right);
        __ FloatMax(result, left, right, ool->entry());
        __ bind(ool->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmFloat32Min: {
      SwVfpRegister result = i.Out
```