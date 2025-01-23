Response: My goal is to summarize the functionality of the provided C++ code snippet. Here's a breakdown of my thought process:

1. **Initial Skim and Keyword Identification:** I first scanned the code looking for recurring keywords and patterns. I noticed:
    * `CodeGenerator` and `Assemble` prefixes (e.g., `AssembleArchInstruction`, `AssembleDeconstructFrame`). This strongly suggests code generation functionality for a specific architecture.
    * `x64` in the file path and many class names (e.g., `X64OperandConverter`). This confirms the target architecture is x64.
    * Mentions of `Instruction`, `Operand`, `Register`, `Immediate`. These are core concepts in assembly and code generation.
    * Includes of various headers like `assembler-x64.h`, `code-generator-impl.h`, `codegen/`. These point towards compilation and low-level code manipulation.
    * References to `javascript` and `wasm` (WebAssembly), indicating the code generator handles both.
    * Specific assembly instructions like `mov`, `add`, `cmp`, `call`, `jmp`, `xor`, `push`, `pop`, and SSE/AVX instructions. This reinforces the code generation aspect.
    * Concepts like "macro fusion", "out-of-line code", "record write barrier", "TSAN", and "tail call". These suggest optimizations and specific runtime mechanisms.

2. **Identifying Core Classes and Their Roles:**  I then focused on the key classes:
    * `CodeGenerator`:  This seems to be the central class responsible for generating the x64 machine code. The various `Assemble...` methods confirm this.
    * `X64OperandConverter`:  This class appears to be responsible for translating high-level instruction operands into x64-specific operands (registers, memory addresses, immediates). It handles different addressing modes.
    * Out-of-line code classes (e.g., `OutOfLineLoadFloat32NaN`, `OutOfLineRecordWrite`, `OutOfLineTruncateDoubleToI`, `WasmOutOfLineTrap`, `OutOfLineTSANStore`, `OutOfLineTSANRelaxedLoad`): These represent less common or more complex code sequences that are generated separately and jumped to when needed. This is a common optimization technique.

3. **Grouping Functionality by Theme:** Based on the identified keywords and class roles, I started grouping the functionalities:
    * **Instruction Assembly:** The core of the file is the `AssembleArchInstruction` function, which handles the translation of high-level instructions into x64 assembly. The `ASSEMBLE_*` macros are crucial here.
    * **Operand Conversion:** `X64OperandConverter` plays a key role in this, taking abstract operands and turning them into concrete x64 operands.
    * **Control Flow:**  Functions like `AssembleDeconstructFrame`, `AssemblePrepareTailCall`, `AssembleTailCallBeforeGap`, `AssembleTailCallAfterGap` deal with stack management and function call/return sequences, particularly for tail calls.
    * **Out-of-Line Code Handling:** The various `OutOfLine...` classes handle specific, less frequent scenarios.
    * **Memory Access and Barriers:** The `OutOfLineRecordWrite` class specifically deals with the record write barrier, a crucial mechanism for garbage collection. The presence of `EmitStore` and related functions reinforces this.
    * **Floating-Point Operations:** The `OutOfLineLoadFloat*NaN` and `OutOfLineTruncateDoubleToI` classes handle special cases for floating-point numbers.
    * **WebAssembly Integration:**  The `WasmOutOfLineTrap` class and related comments clearly indicate support for WebAssembly.
    * **Thread Safety (TSAN):** The `OutOfLineTSANStore` and `OutOfLineTSANRelaxedLoad` classes, along with `EmitTSANAwareStore`, suggest integration with ThreadSanitizer for detecting data races.
    * **Macro Fusion:** The initial part of the code defines enums and functions related to macro fusion, an optimization technique where multiple instructions are combined into one.
    * **Debugging and Assertions:** Functions like `AssembleCodeStartRegisterCheck`, `AssembleDispatchHandleRegisterCheck`, and `BailoutIfDeoptimized` suggest debugging and runtime checks.

4. **Summarization and Refinement:** I started writing the summary based on the groupings. I aimed for concise descriptions of each major area of functionality. I focused on what the code *does* rather than going into excessive implementation details.

5. **JavaScript Example (Connecting to the User's Request):**  I thought about how the C++ code connects to JavaScript. The key is that this code generator is part of the V8 JavaScript engine. Therefore, it's responsible for taking optimized JavaScript code (represented as instructions) and turning it into efficient x64 machine code that the processor can execute. I chose examples that illustrate the kind of operations that would trigger the generation of the x64 instructions handled in this file: basic arithmetic, function calls, and memory access.

6. **Structure and Clarity:** I organized the summary into logical sections with clear headings. I used bullet points to improve readability. I also tried to use precise terminology related to compilation and assembly.

7. **Addressing "Part 1 of 5":** I recognized the user's prompt specified "part 1 of 5" and understood that this snippet likely represents an initial stage of the code generation process. This helped frame the summary as focusing on the core instruction assembly and operand handling aspects.

By following these steps, I was able to arrive at the provided summary, focusing on the core functionality of generating x64 machine code for JavaScript and WebAssembly within the V8 engine.
这是 `v8/src/compiler/backend/x64/code-generator-x64.cc` 文件的第一部分，主要负责 **x64 架构下代码生成器的基础框架和一些核心辅助功能**。它定义了一些通用的辅助类、枚举和宏，用于后续更具体的指令生成。

具体来说，这部分代码的功能可以归纳为：

1. **头文件和命名空间引入:**  引入了必要的 C++ 标准库头文件以及 V8 项目中相关的头文件，例如汇编器 (`assembler-x64.h`)、代码生成器接口 (`code-generator-impl.h`)、指令表示 (`instruction-codes.h`) 等。所有代码都在 `v8::internal::compiler` 命名空间下。

2. **宏融合支持 (Macro Fusion):**  定义了枚举 `FirstMacroFusionInstKind` 和 `SecondMacroFusionInstKind` 以及函数 `IsMacroFused` 和 `GetSecondMacroFusionInstKind`。这些用于判断两条相邻的 x64 指令是否可以进行宏融合优化，从而提高执行效率。宏融合是指将两个简单指令合并成一个更复杂的指令。

3. **x64 操作数转换器 (`X64OperandConverter`):**  定义了一个继承自 `InstructionOperandConverter` 的类 `X64OperandConverter`。这个类的主要作用是将中间表示的指令操作数（例如寄存器、内存地址、立即数）转换为 x64 汇编器能够识别的具体操作数形式。它提供了便捷的方法来获取输入和输出操作数，并处理不同的寻址模式。

4. **辅助函数和类定义:**  定义了一些辅助函数和类，用于处理特定的代码生成场景：
    * `HasAddressingMode` 和 `HasImmediateInput/RegisterInput`：用于判断指令是否使用了特定的寻址模式或输入类型。
    * `OutOfLineLoadFloat32NaN/Float64NaN`:  用于生成加载 NaN (非数字) 浮点数值的 out-of-line 代码。
    * `OutOfLineTruncateDoubleToI`: 用于生成将双精度浮点数截断为整数的 out-of-line 代码，处理一些特殊情况。
    * `OutOfLineRecordWrite`: 用于生成记录写屏障的 out-of-line 代码，这是垃圾回收的关键部分。
    * `EmitStore`:  一个模板函数，用于生成存储指令，并根据内存顺序选择不同的指令。
    * `WasmOutOfLineTrap` (在 `V8_ENABLE_WEBASSEMBLY` 宏定义下): 用于生成 WebAssembly 陷阱处理的 out-of-line 代码。
    * `RecordTrapInfoIfNeeded`:  用于记录可能触发陷阱的指令信息。
    * `OutOfLineTSANStore/TSANRelaxedLoad` (在 `V8_IS_TSAN` 宏定义下): 用于生成与 ThreadSanitizer (TSAN) 集成的存储和加载指令，用于检测多线程环境下的数据竞争。
    * `EmitTSANAwareStore/RelaxedLoadOOLIfNeeded`:  辅助生成 TSAN 感知的存储和加载代码。

5. **通用汇编宏定义:**  定义了一系列以 `ASSEMBLE_` 开头的宏，用于简化各种指令的汇编过程。例如：
    * `ASSEMBLE_UNOP`:  汇编一元操作。
    * `ASSEMBLE_BINOP`:  汇编二元操作。
    * `ASSEMBLE_COMPARE`: 汇编比较操作。
    * `ASSEMBLE_MOVX`: 汇编数据移动操作。
    * `ASSEMBLE_SSE_BINOP/UNOP`: 汇编 SSE (Streaming SIMD Extensions) 指令。
    * `ASSEMBLE_AVX_BINOP`: 汇编 AVX (Advanced Vector Extensions) 指令。
    * `ASSEMBLE_SIMD_*`: 汇编 SIMD (Single Instruction, Multiple Data) 指令。

**与 JavaScript 的关系:**

这个文件的核心功能是 **将 V8 引擎编译优化后的 JavaScript 代码 (以中间表示的形式) 转换为可以在 x64 架构上执行的机器码**。  当 V8 引擎需要执行 JavaScript 代码时，它会经过解析、编译、优化等步骤，最终由这里的代码生成器将优化后的指令翻译成 x64 汇编指令。

**JavaScript 示例:**

假设有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 引擎编译这段代码时，`code-generator-x64.cc` 中定义的类和函数会被用来生成类似以下的 x64 汇编指令（简化示例）：

* **函数调用 `add(5, 10)`:**
    * 可能生成 `mov` 指令将参数 `5` 和 `10` 移动到寄存器或栈上。
    * 生成 `call` 指令跳转到 `add` 函数的代码。
* **`add` 函数内部 `return a + b;`:**
    * 如果 `a` 和 `b` 存储在寄存器中，可能会生成 `add` 指令进行加法运算。
    * 生成 `mov` 指令将结果移动到返回值寄存器。
    * 生成 `ret` 指令返回。

**更具体的例子，涉及到宏融合:**

考虑一个简单的条件判断：

```javascript
if (x > 0) {
  // ...
}
```

这在底层可能会被翻译成先比较 `x` 和 `0`，然后根据比较结果进行跳转。  `code-generator-x64.cc` 中的宏融合逻辑可能会将比较指令 (`cmp`) 和跳转指令 (`jg`) 合并成一个更高效的指令，例如 `jg` 可以直接根据 `cmp` 指令设置的标志位进行跳转。

**总结:**

这部分代码是 x64 代码生成器的基础，它定义了构建 x64 汇编指令所需的工具和抽象。它处理了操作数的转换、常见指令的生成以及一些特殊的代码生成场景，为后续更复杂的 JavaScript 逻辑的编译奠定了基础。 宏融合和 TSAN 的支持表明了 V8 引擎在性能优化和代码安全方面的考虑。

### 提示词
```
这是目录为v8/src/compiler/backend/x64/code-generator-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <optional>

#include "src/base/logging.h"
#include "src/base/overflowing-math.h"
#include "src/builtins/builtins.h"
#include "src/codegen/assembler.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/external-reference.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/codegen/x64/assembler-x64.h"
#include "src/codegen/x64/register-x64.h"
#include "src/common/globals.h"
#include "src/common/ptr-compr-inl.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/execution/frame-constants.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/objects/code-kind.h"
#include "src/objects/smi.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8::internal::compiler {

#define __ masm()->

enum class FirstMacroFusionInstKind {
  // TEST
  kTest,
  // CMP
  kCmp,
  // AND
  kAnd,
  // ADD, SUB
  kAddSub,
  // INC, DEC
  kIncDec,
  // Not valid as a first macro fusion instruction.
  kInvalid
};

enum class SecondMacroFusionInstKind {
  // JA, JB and variants.
  kAB,
  // JE, JL, JG and variants.
  kELG,
  // Not a fusible jump.
  kInvalid,
};

bool IsMacroFused(FirstMacroFusionInstKind first_kind,
                  SecondMacroFusionInstKind second_kind) {
  switch (first_kind) {
    case FirstMacroFusionInstKind::kTest:
    case FirstMacroFusionInstKind::kAnd:
      return true;
    case FirstMacroFusionInstKind::kCmp:
    case FirstMacroFusionInstKind::kAddSub:
      return second_kind == SecondMacroFusionInstKind::kAB ||
             second_kind == SecondMacroFusionInstKind::kELG;
    case FirstMacroFusionInstKind::kIncDec:
      return second_kind == SecondMacroFusionInstKind::kELG;
    case FirstMacroFusionInstKind::kInvalid:
      return false;
  }
}

SecondMacroFusionInstKind GetSecondMacroFusionInstKind(
    FlagsCondition condition) {
  switch (condition) {
    // JE,JZ
    case kEqual:
      // JNE,JNZ
    case kNotEqual:
    // JL,JNGE
    case kSignedLessThan:
    // JLE,JNG
    case kSignedLessThanOrEqual:
    // JG,JNLE
    case kSignedGreaterThan:
    // JGE,JNL
    case kSignedGreaterThanOrEqual:
      return SecondMacroFusionInstKind::kELG;
    // JB,JC
    case kUnsignedLessThan:
    // JNA,JBE
    case kUnsignedLessThanOrEqual:
    // JA,JNBE
    case kUnsignedGreaterThan:
    // JAE,JNC,JNB
    case kUnsignedGreaterThanOrEqual:
      return SecondMacroFusionInstKind::kAB;
    default:
      return SecondMacroFusionInstKind::kInvalid;
  }
}

bool ShouldAlignForJCCErratum(Instruction* instr,
                              FirstMacroFusionInstKind first_kind) {
  if (!CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION)) return false;
  FlagsMode mode = FlagsModeField::decode(instr->opcode());
  if (mode == kFlags_branch || mode == kFlags_deoptimize) {
    FlagsCondition condition = FlagsConditionField::decode(instr->opcode());
    if (IsMacroFused(first_kind, GetSecondMacroFusionInstKind(condition))) {
      return true;
    }
  }
  return false;
}

// Adds X64 specific methods for decoding operands.
class X64OperandConverter : public InstructionOperandConverter {
 public:
  X64OperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  Immediate InputImmediate(size_t index) {
    return ToImmediate(instr_->InputAt(index));
  }

  Operand InputOperand(size_t index, int extra = 0) {
    return ToOperand(instr_->InputAt(index), extra);
  }

  Operand OutputOperand() { return ToOperand(instr_->Output()); }

  Immediate ToImmediate(InstructionOperand* operand) {
    Constant constant = ToConstant(operand);
    if (constant.type() == Constant::kCompressedHeapObject) {
      CHECK(COMPRESS_POINTERS_BOOL);
      CHECK(V8_STATIC_ROOTS_BOOL || !gen_->isolate()->bootstrapper());
      RootIndex root_index;
      CHECK(gen_->isolate()->roots_table().IsRootHandle(constant.ToHeapObject(),
                                                        &root_index));
      return Immediate(
          MacroAssemblerBase::ReadOnlyRootPtr(root_index, gen_->isolate()));
    }
    if (constant.type() == Constant::kFloat64) {
      DCHECK_EQ(0, constant.ToFloat64().AsUint64());
      return Immediate(0);
    }
    return Immediate(constant.ToInt32(), constant.rmode());
  }

  Operand ToOperand(InstructionOperand* op, int extra = 0) {
    DCHECK(op->IsStackSlot() || op->IsFPStackSlot());
    return SlotToOperand(AllocatedOperand::cast(op)->index(), extra);
  }

  Operand SlotToOperand(int slot_index, int extra = 0) {
    FrameOffset offset = frame_access_state()->GetFrameOffset(slot_index);
    return Operand(offset.from_stack_pointer() ? rsp : rbp,
                   offset.offset() + extra);
  }

  static size_t NextOffset(size_t* offset) {
    size_t i = *offset;
    (*offset)++;
    return i;
  }

  static ScaleFactor ScaleFor(AddressingMode one, AddressingMode mode) {
    static_assert(0 == static_cast<int>(times_1));
    static_assert(1 == static_cast<int>(times_2));
    static_assert(2 == static_cast<int>(times_4));
    static_assert(3 == static_cast<int>(times_8));
    int scale = static_cast<int>(mode - one);
    DCHECK(scale >= 0 && scale < 4);
    return static_cast<ScaleFactor>(scale);
  }

  Operand MemoryOperand(size_t* offset) {
    AddressingMode mode = AddressingModeField::decode(instr_->opcode());
    switch (mode) {
      case kMode_MR: {
        Register base = InputRegister(NextOffset(offset));
        int32_t disp = 0;
        return Operand(base, disp);
      }
      case kMode_MRI: {
        Register base = InputRegister(NextOffset(offset));
        int32_t disp = InputInt32(NextOffset(offset));
        return Operand(base, disp);
      }
      case kMode_MR1:
      case kMode_MR2:
      case kMode_MR4:
      case kMode_MR8: {
        Register base = InputRegister(NextOffset(offset));
        Register index = InputRegister(NextOffset(offset));
        ScaleFactor scale = ScaleFor(kMode_MR1, mode);
        int32_t disp = 0;
        return Operand(base, index, scale, disp);
      }
      case kMode_MR1I:
      case kMode_MR2I:
      case kMode_MR4I:
      case kMode_MR8I: {
        Register base = InputRegister(NextOffset(offset));
        Register index = InputRegister(NextOffset(offset));
        ScaleFactor scale = ScaleFor(kMode_MR1I, mode);
        int32_t disp = InputInt32(NextOffset(offset));
        return Operand(base, index, scale, disp);
      }
      case kMode_M1: {
        Register base = InputRegister(NextOffset(offset));
        int32_t disp = 0;
        return Operand(base, disp);
      }
      case kMode_M2:
        UNREACHABLE();  // Should use kModeMR with more compact encoding instead
      case kMode_M4:
      case kMode_M8: {
        Register index = InputRegister(NextOffset(offset));
        ScaleFactor scale = ScaleFor(kMode_M1, mode);
        int32_t disp = 0;
        return Operand(index, scale, disp);
      }
      case kMode_M1I:
      case kMode_M2I:
      case kMode_M4I:
      case kMode_M8I: {
        Register index = InputRegister(NextOffset(offset));
        ScaleFactor scale = ScaleFor(kMode_M1I, mode);
        int32_t disp = InputInt32(NextOffset(offset));
        return Operand(index, scale, disp);
      }
      case kMode_Root: {
        Register base = kRootRegister;
        int32_t disp = InputInt32(NextOffset(offset));
        return Operand(base, disp);
      }
      case kMode_MCR: {
        Register base = kPtrComprCageBaseRegister;
        Register index = InputRegister(NextOffset(offset));
        ScaleFactor scale = static_cast<ScaleFactor>(0);
        int32_t disp = 0;
        return Operand(base, index, scale, disp);
      }
      case kMode_MCRI: {
        Register base = kPtrComprCageBaseRegister;
        Register index = InputRegister(NextOffset(offset));
        ScaleFactor scale = static_cast<ScaleFactor>(0);
        int32_t disp = InputInt32(NextOffset(offset));
        return Operand(base, index, scale, disp);
      }
      case kMode_None:
        UNREACHABLE();
    }
    UNREACHABLE();
  }

  Operand MemoryOperand(size_t first_input = 0) {
    return MemoryOperand(&first_input);
  }
};

namespace {

bool HasAddressingMode(Instruction* instr) {
  return instr->addressing_mode() != kMode_None;
}

bool HasImmediateInput(Instruction* instr, size_t index) {
  return instr->InputAt(index)->IsImmediate();
}

bool HasRegisterInput(Instruction* instr, size_t index) {
  return instr->InputAt(index)->IsRegister();
}

class OutOfLineLoadFloat32NaN final : public OutOfLineCode {
 public:
  OutOfLineLoadFloat32NaN(CodeGenerator* gen, XMMRegister result)
      : OutOfLineCode(gen), result_(result) {}

  void Generate() final {
    __ Xorps(result_, result_);
    __ Divss(result_, result_);
  }

 private:
  XMMRegister const result_;
};

class OutOfLineLoadFloat64NaN final : public OutOfLineCode {
 public:
  OutOfLineLoadFloat64NaN(CodeGenerator* gen, XMMRegister result)
      : OutOfLineCode(gen), result_(result) {}

  void Generate() final {
    __ Xorpd(result_, result_);
    __ Divsd(result_, result_);
  }

 private:
  XMMRegister const result_;
};

class OutOfLineTruncateDoubleToI final : public OutOfLineCode {
 public:
  OutOfLineTruncateDoubleToI(CodeGenerator* gen, Register result,
                             XMMRegister input, StubCallMode stub_mode,
                             UnwindingInfoWriter* unwinding_info_writer)
      : OutOfLineCode(gen),
        result_(result),
        input_(input),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        unwinding_info_writer_(unwinding_info_writer),
        isolate_(gen->isolate()),
        zone_(gen->zone()) {
  }

  void Generate() final {
    __ AllocateStackSpace(kDoubleSize);
    unwinding_info_writer_->MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                      kDoubleSize);
    __ Movsd(MemOperand(rsp, 0), input_);
#if V8_ENABLE_WEBASSEMBLY
    if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      // A direct call to a builtin. Just encode the builtin index. This will be
      // patched when the code is added to the native module and copied into
      // wasm code space.
      __ near_call(static_cast<intptr_t>(Builtin::kDoubleToI),
                   RelocInfo::WASM_STUB_CALL);
#else
    // For balance.
    if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      // With embedded builtins we do not need the isolate here. This allows
      // the call to be generated asynchronously.
      __ CallBuiltin(Builtin::kDoubleToI);
    }
    __ movl(result_, MemOperand(rsp, 0));
    __ addq(rsp, Immediate(kDoubleSize));
    unwinding_info_writer_->MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                      -kDoubleSize);
  }

 private:
  Register const result_;
  XMMRegister const input_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  UnwindingInfoWriter* const unwinding_info_writer_;
  Isolate* isolate_;
  Zone* zone_;
};

class OutOfLineRecordWrite final : public OutOfLineCode {
 public:
  OutOfLineRecordWrite(
      CodeGenerator* gen, Register object, Operand operand, Register value,
      Register scratch0, Register scratch1, RecordWriteMode mode,
      StubCallMode stub_mode,
      IndirectPointerTag indirect_pointer_tag = kIndirectPointerNullTag)
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
        zone_(gen->zone()),
        indirect_pointer_tag_(indirect_pointer_tag) {
    DCHECK(!AreAliased(object, scratch0, scratch1));
    DCHECK(!AreAliased(value, scratch0, scratch1));
  }

#if V8_ENABLE_STICKY_MARK_BITS_BOOL
  Label* stub_call() { return &stub_call_; }
#endif  // V8_ENABLE_STICKY_MARK_BITS_BOOL

  void Generate() final {
    // When storing an indirect pointer, the value will always be a
    // full/decompressed pointer.
    if (COMPRESS_POINTERS_BOOL &&
        mode_ != RecordWriteMode::kValueIsIndirectPointer) {
      __ DecompressTagged(value_, value_);
    }

    // No need to check value page flags with the indirect pointer write barrier
    // because the value is always an ExposedTrustedObject.
    if (mode_ != RecordWriteMode::kValueIsIndirectPointer) {
#if V8_ENABLE_STICKY_MARK_BITS_BOOL
      // TODO(333906585): Optimize this path.
      Label stub_call_with_decompressed_value;
      __ CheckPageFlag(value_, scratch0_, MemoryChunk::kIsInReadOnlyHeapMask,
                       not_zero, exit());
      __ CheckMarkBit(value_, scratch0_, scratch1_, carry, exit());
      __ jmp(&stub_call_with_decompressed_value);

      __ bind(&stub_call_);
      if (COMPRESS_POINTERS_BOOL &&
          mode_ != RecordWriteMode::kValueIsIndirectPointer) {
        __ DecompressTagged(value_, value_);
      }

      __ bind(&stub_call_with_decompressed_value);
#else   // !V8_ENABLE_STICKY_MARK_BITS_BOOL
      __ CheckPageFlag(value_, scratch0_,
                       MemoryChunk::kPointersToHereAreInterestingMask, zero,
                       exit());
#endif  // !V8_ENABLE_STICKY_MARK_BITS_BOOL
    }

    __ leaq(scratch1_, operand_);

    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;

    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, scratch1_, save_fp_mode);
    } else if (mode_ == RecordWriteMode::kValueIsIndirectPointer) {
      // We must have a valid indirect pointer tag here. Otherwise, we risk not
      // invoking the correct write barrier, which may lead to subtle issues.
      CHECK(IsValidIndirectPointerTag(indirect_pointer_tag_));
      __ CallIndirectPointerBarrier(object_, scratch1_, save_fp_mode,
                                    indirect_pointer_tag_);
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
  }

 private:
  Register const object_;
  Operand const operand_;
  Register const value_;
  Register const scratch0_;
  Register const scratch1_;
  RecordWriteMode const mode_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode const stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  Zone* zone_;
  IndirectPointerTag indirect_pointer_tag_;
#if V8_ENABLE_STICKY_MARK_BITS_BOOL
  Label stub_call_;
#endif  // V8_ENABLE_STICKY_MARK_BITS_BOOL
};

template <std::memory_order order>
int EmitStore(MacroAssembler* masm, Operand operand, Register value,
              MachineRepresentation rep) {
  int store_instr_offset;
  if (order == std::memory_order_relaxed) {
    store_instr_offset = masm->pc_offset();
    switch (rep) {
      case MachineRepresentation::kWord8:
        masm->movb(operand, value);
        break;
      case MachineRepresentation::kWord16:
        masm->movw(operand, value);
        break;
      case MachineRepresentation::kWord32:
        masm->movl(operand, value);
        break;
      case MachineRepresentation::kWord64:
        masm->movq(operand, value);
        break;
      case MachineRepresentation::kTagged:
        masm->StoreTaggedField(operand, value);
        break;
      case MachineRepresentation::kSandboxedPointer:
        masm->StoreSandboxedPointerField(operand, value);
        break;
      case MachineRepresentation::kIndirectPointer:
        masm->StoreIndirectPointerField(operand, value);
        break;
      default:
        UNREACHABLE();
    }
    return store_instr_offset;
  }

  DCHECK_EQ(order, std::memory_order_seq_cst);
  switch (rep) {
    case MachineRepresentation::kWord8:
      masm->movq(kScratchRegister, value);
      store_instr_offset = masm->pc_offset();
      masm->xchgb(kScratchRegister, operand);
      break;
    case MachineRepresentation::kWord16:
      masm->movq(kScratchRegister, value);
      store_instr_offset = masm->pc_offset();
      masm->xchgw(kScratchRegister, operand);
      break;
    case MachineRepresentation::kWord32:
      masm->movq(kScratchRegister, value);
      store_instr_offset = masm->pc_offset();
      masm->xchgl(kScratchRegister, operand);
      break;
    case MachineRepresentation::kWord64:
      masm->movq(kScratchRegister, value);
      store_instr_offset = masm->pc_offset();
      masm->xchgq(kScratchRegister, operand);
      break;
    case MachineRepresentation::kTagged:
      store_instr_offset = masm->pc_offset();
      masm->AtomicStoreTaggedField(operand, value);
      break;
    default:
      UNREACHABLE();
  }
  return store_instr_offset;
}

template <std::memory_order order>
int EmitStore(MacroAssembler* masm, Operand operand, Immediate value,
              MachineRepresentation rep);

template <>
int EmitStore<std::memory_order_relaxed>(MacroAssembler* masm, Operand operand,
                                         Immediate value,
                                         MachineRepresentation rep) {
  int store_instr_offset = masm->pc_offset();
  switch (rep) {
    case MachineRepresentation::kWord8:
      masm->movb(operand, value);
      break;
    case MachineRepresentation::kWord16:
      masm->movw(operand, value);
      break;
    case MachineRepresentation::kWord32:
      masm->movl(operand, value);
      break;
    case MachineRepresentation::kWord64:
      masm->movq(operand, value);
      break;
    case MachineRepresentation::kTagged:
      masm->StoreTaggedField(operand, value);
      break;
    default:
      UNREACHABLE();
  }
  return store_instr_offset;
}

#if V8_ENABLE_WEBASSEMBLY
class WasmOutOfLineTrap : public OutOfLineCode {
 public:
  WasmOutOfLineTrap(CodeGenerator* gen, Instruction* instr)
      : OutOfLineCode(gen), gen_(gen), instr_(instr) {}

  void Generate() override {
    X64OperandConverter i(gen_, instr_);
    TrapId trap_id =
        static_cast<TrapId>(i.InputInt32(instr_->InputCount() - 1));
    GenerateWithTrapId(trap_id);
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
    __ near_call(static_cast<Address>(trap_id), RelocInfo::WASM_STUB_CALL);
    ReferenceMap* reference_map = gen_->zone()->New<ReferenceMap>(gen_->zone());
    gen_->RecordSafepoint(reference_map);
    __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
  }

  Instruction* instr_;
};

void RecordTrapInfoIfNeeded(Zone* zone, CodeGenerator* codegen,
                            InstructionCode opcode, Instruction* instr,
                            int pc) {
  const MemoryAccessMode access_mode = instr->memory_access_mode();
  if (access_mode == kMemoryAccessProtectedMemOutOfBounds ||
      access_mode == kMemoryAccessProtectedNullDereference) {
    codegen->RecordProtectedInstruction(pc);
  }
}

#else

void RecordTrapInfoIfNeeded(Zone* zone, CodeGenerator* codegen,
                            InstructionCode opcode, Instruction* instr,
                            int pc) {
  DCHECK_EQ(kMemoryAccessDirect, instr->memory_access_mode());
}

#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef V8_IS_TSAN
void EmitMemoryProbeForTrapHandlerIfNeeded(MacroAssembler* masm,
                                           Register scratch, Operand operand,
                                           StubCallMode mode, int size) {
#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  // The wasm OOB trap handler needs to be able to look up the faulting
  // instruction pointer to handle the SIGSEGV raised by an OOB access. It
  // will not handle SIGSEGVs raised by the TSAN store helpers. Emit a
  // redundant load here to give the trap handler a chance to handle any
  // OOB SIGSEGVs.
  if (trap_handler::IsTrapHandlerEnabled() &&
      mode == StubCallMode::kCallWasmRuntimeStub) {
    switch (size) {
      case kInt8Size:
        masm->movb(scratch, operand);
        break;
      case kInt16Size:
        masm->movw(scratch, operand);
        break;
      case kInt32Size:
        masm->movl(scratch, operand);
        break;
      case kInt64Size:
        masm->movq(scratch, operand);
        break;
      default:
        UNREACHABLE();
    }
  }
#endif
}

class OutOfLineTSANStore : public OutOfLineCode {
 public:
  OutOfLineTSANStore(CodeGenerator* gen, Operand operand, Register value,
                     Register scratch0, StubCallMode stub_mode, int size,
                     std::memory_order order)
      : OutOfLineCode(gen),
        operand_(operand),
        value_(value),
        scratch0_(scratch0),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        size_(size),
        memory_order_(order),
        zone_(gen->zone()) {
    DCHECK(!AreAliased(value, scratch0));
  }

  void Generate() final {
    const SaveFPRegsMode save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    __ leaq(scratch0_, operand_);

#if V8_ENABLE_WEBASSEMBLY
    if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      masm()->CallTSANStoreStub(scratch0_, value_, save_fp_mode, size_,
                                StubCallMode::kCallWasmRuntimeStub,
                                memory_order_);
      return;
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    masm()->CallTSANStoreStub(scratch0_, value_, save_fp_mode, size_,
                              StubCallMode::kCallBuiltinPointer, memory_order_);
  }

 private:
  Operand const operand_;
  Register const value_;
  Register const scratch0_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode const stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  int size_;
  const std::memory_order memory_order_;
  Zone* zone_;
};

void EmitTSANStoreOOL(Zone* zone, CodeGenerator* codegen, MacroAssembler* masm,
                      Operand operand, Register value_reg,
                      X64OperandConverter& i, StubCallMode mode, int size,
                      std::memory_order order) {
  // The FOR_TESTING code doesn't initialize the root register. We can't call
  // the TSAN builtin since we need to load the external reference through the
  // root register.
  // TODO(solanes, v8:7790, v8:11600): See if we can support the FOR_TESTING
  // path. It is not crucial, but it would be nice to remove this restriction.
  DCHECK_NE(codegen->code_kind(), CodeKind::FOR_TESTING);

  Register scratch0 = i.TempRegister(0);
  auto tsan_ool = zone->New<OutOfLineTSANStore>(codegen, operand, value_reg,
                                                scratch0, mode, size, order);
  masm->jmp(tsan_ool->entry());
  masm->bind(tsan_ool->exit());
}

template <std::memory_order order>
Register GetTSANValueRegister(MacroAssembler* masm, Register value,
                              X64OperandConverter& i,
                              MachineRepresentation rep) {
  if (rep == MachineRepresentation::kSandboxedPointer) {
    // SandboxedPointers need to be encoded.
    Register value_reg = i.TempRegister(1);
    masm->movq(value_reg, value);
    masm->EncodeSandboxedPointer(value_reg);
    return value_reg;
  } else if (rep == MachineRepresentation::kIndirectPointer) {
    // Indirect pointer fields contain an index to a pointer table entry, which
    // is obtained from the referenced object.
    Register value_reg = i.TempRegister(1);
    masm->movl(
        value_reg,
        FieldOperand(value, ExposedTrustedObject::kSelfIndirectPointerOffset));
    return value_reg;
  }
  return value;
}

template <std::memory_order order>
Register GetTSANValueRegister(MacroAssembler* masm, Immediate value,
                              X64OperandConverter& i,
                              MachineRepresentation rep);

template <>
Register GetTSANValueRegister<std::memory_order_relaxed>(
    MacroAssembler* masm, Immediate value, X64OperandConverter& i,
    MachineRepresentation rep) {
  Register value_reg = i.TempRegister(1);
  masm->movq(value_reg, value);
  if (rep == MachineRepresentation::kSandboxedPointer) {
    // SandboxedPointers need to be encoded.
    masm->EncodeSandboxedPointer(value_reg);
  } else if (rep == MachineRepresentation::kIndirectPointer) {
    // Indirect pointer fields contain an index to a pointer table entry, which
    // is obtained from the referenced object.
    masm->movl(value_reg,
               FieldOperand(value_reg,
                            ExposedTrustedObject::kSelfIndirectPointerOffset));
  }
  return value_reg;
}

template <std::memory_order order, typename ValueT>
void EmitTSANAwareStore(Zone* zone, CodeGenerator* codegen,
                        MacroAssembler* masm, Operand operand, ValueT value,
                        X64OperandConverter& i, StubCallMode stub_call_mode,
                        MachineRepresentation rep, Instruction* instr) {
  // The FOR_TESTING code doesn't initialize the root register. We can't call
  // the TSAN builtin since we need to load the external reference through the
  // root register.
  // TODO(solanes, v8:7790, v8:11600): See if we can support the FOR_TESTING
  // path. It is not crucial, but it would be nice to remove this restriction.
  if (codegen->code_kind() != CodeKind::FOR_TESTING) {
    if (instr->HasMemoryAccessMode()) {
      RecordTrapInfoIfNeeded(zone, codegen, instr->opcode(), instr,
                             masm->pc_offset());
    }
    int size = ElementSizeInBytes(rep);
    EmitMemoryProbeForTrapHandlerIfNeeded(masm, i.TempRegister(0), operand,
                                          stub_call_mode, size);
    Register value_reg = GetTSANValueRegister<order>(masm, value, i, rep);
    EmitTSANStoreOOL(zone, codegen, masm, operand, value_reg, i, stub_call_mode,
                     size, order);
  } else {
    int store_instr_offset = EmitStore<order>(masm, operand, value, rep);
    if (instr->HasMemoryAccessMode()) {
      RecordTrapInfoIfNeeded(zone, codegen, instr->opcode(), instr,
                             store_instr_offset);
    }
  }
}

class OutOfLineTSANRelaxedLoad final : public OutOfLineCode {
 public:
  OutOfLineTSANRelaxedLoad(CodeGenerator* gen, Operand operand,
                           Register scratch0, StubCallMode stub_mode, int size)
      : OutOfLineCode(gen),
        operand_(operand),
        scratch0_(scratch0),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        size_(size),
        zone_(gen->zone()) {
  }

  void Generate() final {
    const SaveFPRegsMode save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    __ leaq(scratch0_, operand_);

#if V8_ENABLE_WEBASSEMBLY
    if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      __ CallTSANRelaxedLoadStub(scratch0_, save_fp_mode, size_,
                                 StubCallMode::kCallWasmRuntimeStub);
      return;
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    __ CallTSANRelaxedLoadStub(scratch0_, save_fp_mode, size_,
                               StubCallMode::kCallBuiltinPointer);
  }

 private:
  Operand const operand_;
  Register const scratch0_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode const stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  int size_;
  Zone* zone_;
};

void EmitTSANRelaxedLoadOOLIfNeeded(Zone* zone, CodeGenerator* codegen,
                                    MacroAssembler* masm, Operand operand,
                                    X64OperandConverter& i, StubCallMode mode,
                                    int size) {
  // The FOR_TESTING code doesn't initialize the root register. We can't call
  // the TSAN builtin since we need to load the external reference through the
  // root register.
  // TODO(solanes, v8:7790, v8:11600): See if we can support the FOR_TESTING
  // path. It is not crucial, but it would be nice to remove this if.
  if (codegen->code_kind() == CodeKind::FOR_TESTING) return;

  Register scratch0 = i.TempRegister(0);
  auto tsan_ool = zone->New<OutOfLineTSANRelaxedLoad>(codegen, operand,
                                                      scratch0, mode, size);
  masm->jmp(tsan_ool->entry());
  masm->bind(tsan_ool->exit());
}

#else
template <std::memory_order order, typename ValueT>
void EmitTSANAwareStore(Zone* zone, CodeGenerator* codegen,
                        MacroAssembler* masm, Operand operand, ValueT value,
                        X64OperandConverter& i, StubCallMode stub_call_mode,
                        MachineRepresentation rep, Instruction* instr) {
  DCHECK(order == std::memory_order_relaxed ||
         order == std::memory_order_seq_cst);
  int store_instr_off = EmitStore<order>(masm, operand, value, rep);
  if (instr->HasMemoryAccessMode()) {
    RecordTrapInfoIfNeeded(zone, codegen, instr->opcode(), instr,
                           store_instr_off);
  }
}

void EmitTSANRelaxedLoadOOLIfNeeded(Zone* zone, CodeGenerator* codegen,
                                    MacroAssembler* masm, Operand operand,
                                    X64OperandConverter& i, StubCallMode mode,
                                    int size) {}
#endif  // V8_IS_TSAN

}  // namespace

#define ASSEMBLE_UNOP(asm_instr)         \
  do {                                   \
    if (instr->Output()->IsRegister()) { \
      __ asm_instr(i.OutputRegister());  \
    } else {                             \
      __ asm_instr(i.OutputOperand());   \
    }                                    \
  } while (false)

#define ASSEMBLE_BINOP(asm_instr)                                \
  do {                                                           \
    if (HasAddressingMode(instr)) {                              \
      size_t index = 1;                                          \
      Operand right = i.MemoryOperand(&index);                   \
      __ asm_instr(i.InputRegister(0), right);                   \
    } else {                                                     \
      if (HasImmediateInput(instr, 1)) {                         \
        if (HasRegisterInput(instr, 0)) {                        \
          __ asm_instr(i.InputRegister(0), i.InputImmediate(1)); \
        } else {                                                 \
          __ asm_instr(i.InputOperand(0), i.InputImmediate(1));  \
        }                                                        \
      } else {                                                   \
        if (HasRegisterInput(instr, 1)) {                        \
          __ asm_instr(i.InputRegister(0), i.InputRegister(1));  \
        } else {                                                 \
          __ asm_instr(i.InputRegister(0), i.InputOperand(1));   \
        }                                                        \
      }                                                          \
    }                                                            \
  } while (false)

#define ASSEMBLE_COMPARE(cmp_instr, test_instr)                    \
  do {                                                             \
    if (HasAddressingMode(instr)) {                                \
      size_t index = 0;                                            \
      Operand left = i.MemoryOperand(&index);                      \
      if (HasImmediateInput(instr, index)) {                       \
        __ cmp_instr(left, i.InputImmediate(index));               \
      } else {                                                     \
        __ cmp_instr(left, i.InputRegister(index));                \
      }                                                            \
    } else {                                                       \
      if (HasImmediateInput(instr, 1)) {                           \
        Immediate right = i.InputImmediate(1);                     \
        if (HasRegisterInput(instr, 0)) {                          \
          if (right.value() == 0) {                                \
            __ test_instr(i.InputRegister(0), i.InputRegister(0)); \
          } else {                                                 \
            __ cmp_instr(i.InputRegister(0), right);               \
          }                                                        \
        } else {                                                   \
          __ cmp_instr(i.InputOperand(0), right);                  \
        }                                                          \
      } else {                                                     \
        if (HasRegisterInput(instr, 1)) {                          \
          __ cmp_instr(i.InputRegister(0), i.InputRegister(1));    \
        } else {                                                   \
          __ cmp_instr(i.InputRegister(0), i.InputOperand(1));     \
        }                                                          \
      }                                                            \
    }                                                              \
  } while (false)

#define ASSEMBLE_TEST(asm_instr)                                 \
  do {                                                           \
    if (HasAddressingMode(instr)) {                              \
      size_t index = 0;                                          \
      Operand left = i.MemoryOperand(&index);                    \
      if (HasImmediateInput(instr, index)) {                     \
        __ asm_instr(left, i.InputImmediate(index));             \
      } else {                                                   \
        __ asm_instr(left, i.InputRegister(index));              \
      }                                                          \
    } else {                                                     \
      if (HasImmediateInput(instr, 1)) {                         \
        if (HasRegisterInput(instr, 0)) {                        \
          __ asm_instr(i.InputRegister(0), i.InputImmediate(1)); \
        } else {                                                 \
          __ asm_instr(i.InputOperand(0), i.InputImmediate(1));  \
        }                                                        \
      } else {                                                   \
        if (HasRegisterInput(instr, 1)) {                        \
          __ asm_instr(i.InputRegister(0), i.InputRegister(1));  \
        } else {                                                 \
          __ asm_instr(i.InputRegister(0), i.InputOperand(1));   \
        }                                                        \
      }                                                          \
    }                                                            \
  } while (false)

#define ASSEMBLE_MULT(asm_instr)                              \
  do {                                                        \
    if (HasImmediateInput(instr, 1)) {                        \
      if (HasRegisterInput(instr, 0)) {                       \
        __ asm_instr(i.OutputRegister(), i.InputRegister(0),  \
                     i.InputImmediate(1));                    \
      } else {                                                \
        __ asm_instr(i.OutputRegister(), i.InputOperand(0),   \
                     i.InputImmediate(1));                    \
      }                                                       \
    } else {                                                  \
      if (HasRegisterInput(instr, 1)) {                       \
        __ asm_instr(i.OutputRegister(), i.InputRegister(1)); \
      } else {                                                \
        __ asm_instr(i.OutputRegister(), i.InputOperand(1));  \
      }                                                       \
    }                                                         \
  } while (false)

#define ASSEMBLE_SHIFT(asm_instr, width)                                   \
  do {                                                                     \
    if (HasImmediateInput(instr, 1)) {                                     \
      if (instr->Output()->IsRegister()) {                                 \
        __ asm_instr(i.OutputRegister(), Immediate(i.InputInt##width(1))); \
      } else {                                                             \
        __ asm_instr(i.OutputOperand(), Immediate(i.InputInt##width(1)));  \
      }                                                                    \
    } else {                                                               \
      if (instr->Output()->IsRegister()) {                                 \
        __ asm_instr##_cl(i.OutputRegister());                             \
      } else {                                                             \
        __ asm_instr##_cl(i.OutputOperand());                              \
      }                                                                    \
    }                                                                      \
  } while (false)

#define ASSEMBLE_MOVX(asm_instr)                            \
  do {                                                      \
    if (HasAddressingMode(instr)) {                         \
      __ asm_instr(i.OutputRegister(), i.MemoryOperand());  \
    } else if (HasRegisterInput(instr, 0)) {                \
      __ asm_instr(i.OutputRegister(), i.InputRegister(0)); \
    } else {                                                \
      __ asm_instr(i.OutputRegister(), i.InputOperand(0));  \
    }                                                       \
  } while (false)

#define ASSEMBLE_SSE_BINOP(asm_instr)                                     \
  do {                                                                    \
    if (HasAddressingMode(instr)) {                                       \
      size_t index = 1;                                                   \
      Operand right = i.MemoryOperand(&index);                            \
      __ asm_instr(i.InputDoubleRegister(0), right);                      \
    } else {                                                              \
      if (instr->InputAt(1)->IsFPRegister()) {                            \
        __ asm_instr(i.InputDoubleRegister(0), i.InputDoubleRegister(1)); \
      } else {                                                            \
        __ asm_instr(i.InputDoubleRegister(0), i.InputOperand(1));        \
      }                                                                   \
    }                                                                     \
  } while (false)

#define ASSEMBLE_SSE_UNOP(asm_instr)                                    \
  do {                                                                  \
    if (instr->InputAt(0)->IsFPRegister()) {                            \
      __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0)); \
    } else {                                                            \
      __ asm_instr(i.OutputDoubleRegister(), i.InputOperand(0));        \
    }                                                                   \
  } while (false)

#define ASSEMBLE_AVX_BINOP(asm_instr)                                          \
  do {                                                                         \
    CpuFeatureScope avx_scope(masm(), AVX);                                    \
    if (HasAddressingMode(instr)) {                                            \
      size_t index = 1;                                                        \
      Operand right = i.MemoryOperand(&index);                                 \
      __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0), right); \
    } else {                                                                   \
      if (instr->InputAt(1)->IsFPRegister()) {                                 \
        __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0),       \
                     i.InputDoubleRegister(1));                                \
      } else {                                                                 \
        __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0),       \
                     i.InputOperand(1));                                       \
      }                                                                        \
    }                                                                          \
  } while (false)

#define ASSEMBLE_IEEE754_BINOP(name)                                     \
  do {                                                                   \
    __ PrepareCallCFunction(2);                                          \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 2); \
  } while (false)

#define ASSEMBLE_IEEE754_UNOP(name)                                      \
  do {                                                                   \
    __ PrepareCallCFunction(1);                                          \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 1); \
  } while (false)

#define ASSEMBLE_ATOMIC_BINOP(bin_inst, mov_inst, cmpxchg_inst)          \
  do {                                                                   \
    Label binop;                                                         \
    __ bind(&binop);                                                     \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
    __ mov_inst(rax, i.MemoryOperand(1));                                \
    __ movl(i.TempRegister(0), rax);                                     \
    __ bin_inst(i.TempRegister(0), i.InputRegister(0));                  \
    __ lock();                                                           \
    __ cmpxchg_inst(i.MemoryOperand(1), i.TempRegister(0));              \
    __ j(not_equal, &binop);                                             \
  } while (false)

#define ASSEMBLE_ATOMIC64_BINOP(bin_inst, mov_inst, cmpxchg_inst)        \
  do {                                                                   \
    Label binop;                                                         \
    __ bind(&binop);                                                     \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
    __ mov_inst(rax, i.MemoryOperand(1));                                \
    __ movq(i.TempRegister(0), rax);                                     \
    __ bin_inst(i.TempRegister(0), i.InputRegister(0));                  \
    __ lock();                                                           \
    __ cmpxchg_inst(i.MemoryOperand(1), i.TempRegister(0));              \
    __ j(not_equal, &binop);                                             \
  } while (false)

// Handles both SSE and AVX codegen. For SSE we use DefineSameAsFirst, so the
// dst and first src will be the same. For AVX we don't restrict it that way, so
// we will omit unnecessary moves.
#define ASSEMBLE_SIMD_BINOP(opcode)                                      \
  do {                                                                   \
    if (CpuFeatures::IsSupported(AVX)) {                                 \
      CpuFeatureScope avx_scope(masm(), AVX);                            \
      __ v##opcode(i.OutputSimd128Register(), i.InputSimd128Register(0), \
                   i.InputSimd128Register(1));                           \
    } else {                                                             \
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));   \
      __ opcode(i.OutputSimd128Register(), i.InputSimd128Register(1));   \
    }                                                                    \
  } while (false)

#define ASSEMBLE_SIMD_F16x8_BINOP(instr)              \
  do {                                                \
    CpuFeatureScope f16c_scope(masm(), F16C);         \
    CpuFeatureScope avx_scope(masm(), AVX);           \
    YMMRegister tmp1 = i.TempSimd256Register(0);      \
    YMMRegister tmp2 = i.TempSimd256Register(1);      \
    __ vcvtph2ps(tmp1, i.InputSimd128Register(0));    \
    __ vcvtph2ps(tmp2, i.InputSimd128Register(1));    \
    __ instr(tmp2, tmp1, tmp2);                       \
    __ vcvtps2ph(i.OutputSimd128Register(), tmp2, 0); \
  } while (false)

#define ASSEMBLE_SIMD_F16x8_RELOP(instr)                 \
  do {                                                   \
    CpuFeatureScope f16c_scope(masm(), F16C);            \
    CpuFeatureScope avx_scope(masm(), AVX);              \
    YMMRegister tmp1 = i.TempSimd256Register(0);         \
    YMMRegister tmp2 = i.TempSimd256Register(1);         \
    __ vcvtph2ps(tmp1, i.InputSimd128Register(0));       \
    __ vcvtph2ps(tmp2, i.InputSimd128Register(1));       \
    __ instr(tmp2, tmp1, tmp2);                          \
    __ vpackssdw(i.OutputSimd128Register(), tmp2, tmp2); \
  } while (false)

#define ASSEMBLE_SIMD256_BINOP(opcode, cpu_feature)                    \
  do {                                                                 \
    CpuFeatureScope avx_scope(masm(), cpu_feature);                    \
    __ v##opcode(i.OutputSimd256Register(), i.InputSimd256Register(0), \
                 i.InputSimd256Register(1));                           \
  } while (false)

#define ASSEMBLE_SIMD_INSTR(opcode, dst_operand, index)      \
  do {                                                       \
    if (instr->InputAt(index)->IsSimd128Register()) {        \
      __ opcode(dst_operand, i.InputSimd128Register(index)); \
    } else {                                                 \
      __ opcode(dst_operand, i.InputOperand(index));         \
    }                                                        \
  } while (false)

#define ASSEMBLE_SIMD_IMM_INSTR(opcode, dst_operand, index, imm)  \
  do {                                                            \
    if (instr->InputAt(index)->IsSimd128Register()) {             \
      __ opcode(dst_operand, i.InputSimd128Register(index), imm); \
    } else {                                                      \
      __ opcode(dst_operand, i.InputOperand(index), imm);         \
    }                                                             \
  } while (false)

#define ASSEMBLE_SIMD_PUNPCK_SHUFFLE(opcode)                    \
  do {                                                          \
    XMMRegister dst = i.OutputSimd128Register();                \
    uint8_t input_index = instr->InputCount() == 2 ? 1 : 0;     \
    if (CpuFeatures::IsSupported(AVX)) {                        \
      CpuFeatureScope avx_scope(masm(), AVX);                   \
      DCHECK(instr->InputAt(input_index)->IsSimd128Register()); \
      __ v##opcode(dst, i.InputSimd128Register(0),              \
                   i.InputSimd128Register(input_index));        \
    } else {                                                    \
      DCHECK_EQ(dst, i.InputSimd128Register(0));                \
      ASSEMBLE_SIMD_INSTR(opcode, dst, input_index);            \
    }                                                           \
  } while (false)

#define ASSEMBLE_SIMD_IMM_SHUFFLE(opcode, imm)                \
  do {                                                        \
    XMMRegister dst = i.OutputSimd128Register();              \
    XMMRegister src = i.InputSimd128Register(0);              \
    if (CpuFeatures::IsSupported(AVX)) {                      \
      CpuFeatureScope avx_scope(masm(), AVX);                 \
      DCHECK(instr->InputAt(1)->IsSimd128Register());         \
      __ v##opcode(dst, src, i.InputSimd128Register(1), imm); \
    } else {                                                  \
      DCHECK_EQ(dst, src);                                    \
      if (instr->InputAt(1)->IsSimd128Register()) {           \
        __ opcode(dst, i.InputSimd128Register(1), imm);       \
      } else {                                                \
        __ opcode(dst, i.InputOperand(1), imm);               \
      }                                                       \
    }                                                         \
  } while (false)

#define ASSEMBLE_SIMD_ALL_TRUE(opcode)                       \
  do {                                                       \
    Register dst = i.OutputRegister();                       \
    __ xorq(dst, dst);                                       \
    __ Pxor(kScratchDoubleReg, kScratchDoubleReg);           \
    __ opcode(kScratchDoubleReg, i.InputSimd128Register(0)); \
    __ Ptest(kScratchDoubleReg, kScratchDoubleReg);          \
    __ setcc(equal, dst);                                    \
  } while (false)

// This macro will directly emit the opcode if the shift is an immediate - the
// shift value will be taken modulo 2^width. Otherwise, it will emit code to
// perform the modulus operation.
#define ASSEMBLE_SIMD_SHIFT(opcode, width)                               \
  do {                                                                   \
    XMMRegister dst = i.OutputSimd128Register();                         \
    if (HasImmediateInput(instr, 1)) {                                   \
      if (CpuFeatures::IsSupported(AVX)) {                               \
        CpuFeatureScope avx_scope(masm(), AVX);                          \
        __ v##opcode(dst, i.InputSimd128Register(0),                     \
                     uint8_t{i.InputInt##width(1)});                     \
      } else {                                                           \
        DCHECK_EQ(dst, i.InputSimd128Register(0));                       \
        __ opcode(dst, uint8_t{i.InputInt##width(1)});                   \
      }                                                                  \
    } else {                                                             \
      constexpr int mask = (1 << width) - 1;                             \
      __ movq(kScratchRegister, i.InputRegister(1));                     \
      __ andq(kScratchRegister, Immediate(mask));                        \
      __ Movq(kScratchDoubleReg, kScratchRegister);                      \
      if (CpuFeatures::IsSupported(AVX)) {                               \
        CpuFeatureScope avx_scope(masm(), AVX);                          \
        __ v##opcode(dst, i.InputSimd128Register(0), kScratchDoubleReg); \
      } else {                                                           \
        DCHECK_EQ(dst, i.InputSimd128Register(0));                       \
        __ opcode(dst, kScratchDoubleReg);                               \
      }                                                                  \
    }                                                                    \
  } while (false)

#define ASSEMBLE_SIMD256_SHIFT(opcode, width)                \
  do {                                                       \
    CpuFeatureScope avx_scope(masm(), AVX2);                 \
    YMMRegister src = i.InputSimd256Register(0);             \
    YMMRegister dst = i.OutputSimd256Register();             \
    if (HasImmediateInput(instr, 1)) {                       \
      __ v##opcode(dst, src, uint8_t{i.InputInt##width(1)}); \
    } else {                                                 \
      constexpr int mask = (1 << width) - 1;                 \
      __ movq(kScratchRegister, i.InputRegister(1));         \
      __ andq(kScratchRegister, Immediate(mask));            \
      __ Movq(kScratchDoubleReg, kScratchRegister);          \
      __ v##opcode(dst, src, kScratchDoubleReg);             \
    }                                                        \
  } while (false)

#define ASSEMBLE_PINSR(ASM_INSTR)                                        \
  do {                                                                   \
    XMMRegister dst = i.OutputSimd128Register();                         \
    XMMRegister src = i.InputSimd128Register(0);                         \
    uint8_t laneidx = i.InputUint8(1);                                   \
    uint32_t load_offset;                                                \
    if (HasAddressingMode(instr)) {                                      \
      __ ASM_INSTR(dst, src, i.MemoryOperand(2), laneidx, &load_offset); \
    } else if (instr->InputAt(2)->IsFPRegister()) {                      \
      __ Movq(kScratchRegister, i.InputDoubleRegister(2));               \
      __ ASM_INSTR(dst, src, kScratchRegister, laneidx, &load_offset);   \
    } else if (instr->InputAt(2)->IsRegister()) {                        \
      __ ASM_INSTR(dst, src, i.InputRegister(2), laneidx, &load_offset); \
    } else {                                                             \
      __ ASM_INSTR(dst, src, i.InputOperand(2), laneidx, &load_offset);  \
    }                                                                    \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, load_offset);    \
  } while (false)

#define ASSEMBLE_SEQ_CST_STORE(rep)                                            \
  do {                                                                         \
    Register value = i.InputRegister(0);                                       \
    Operand operand = i.MemoryOperand(1);                                      \
    EmitTSANAwareStore<std::memory_order_seq_cst>(                             \
        zone(), this, masm(), operand, value, i, DetermineStubCallMode(), rep, \
        instr);                                                                \
  } while (false)

void CodeGenerator::AssembleDeconstructFrame() {
  unwinding_info_writer_.MarkFrameDeconstructed(__ pc_offset());
  __ movq(rsp, rbp);
  __ popq(rbp);
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ movq(rbp, MemOperand(rbp, 0));
  }
  frame_access_state()->SetFrameAccessToSP();
}

namespace {

void AdjustStackPointerForTailCall(Instruction* instr,
                                   MacroAssembler* assembler, Linkage* linkage,
                                   OptimizedCompilationInfo* info,
                                   FrameAccessState* state,
                                   int new_slot_above_sp,
                                   bool allow_shrinkage = true) {
  int stack_slot_delta;
  if (instr->HasCallDescriptorFlag(CallDescriptor::kIsTailCallForTierUp)) {
    // For this special tail-call mode, the callee has the same arguments and
    // linkage as the caller, and arguments adapter frames must be preserved.
    // Thus we simply have reset the stack pointer register to its original
    // value before frame construction.
    // See also: AssembleConstructFrame.
    DCHECK(!info->is_osr());
    DCHECK(linkage->GetIncomingDescriptor()->CalleeSavedRegisters().is_empty());
    DCHECK(
        linkage->GetIncomingDescriptor()->CalleeSavedFPRegisters().is_empty());
    DCHECK_EQ(state->frame()->GetReturnSlotCount(), 0);
    stack_slot_delta = (state->frame()->GetTotalFrameSlotCount() -
                        kReturnAddressStackSlotCount) *
                       -1;
    DCHECK_LE(stack_slot_delta, 0);
  } else {
    int current_sp_offset = state->GetSPToFPSlotCount() +
                            StandardFrameConstants::kFixedSlotCountAboveFp;
    stack_slot_delta = new_slot_above_sp - current_sp_offset;
  }

  if (stack_slot_delta > 0) {
    assembler->AllocateStackSpace(stack_slot_delta * kSystemPointerSize);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    assembler->addq(rsp, Immediate(-stack_slot_delta * kSystemPointerSize));
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

void SetupSimdImmediateInRegister(MacroAssembler* assembler, uint32_t* imms,
                                  XMMRegister reg) {
  assembler->Move(reg, make_uint64(imms[3], imms[2]),
                  make_uint64(imms[1], imms[0]));
}

void SetupSimd256ImmediateInRegister(MacroAssembler* assembler, uint32_t* imms,
                                     YMMRegister reg, XMMRegister scratch) {
  bool is_splat = std::all_of(imms, imms + kSimd256Size,
                              [imms](uint32_t v) { return v == imms[0]; });
  if (is_splat) {
    assembler->Move(scratch, imms[0]);
    CpuFeatureScope avx_scope(assembler, AVX2);
    assembler->vpbroadcastd(reg, scratch);
  } else {
    assembler->Move(reg, make_uint64(imms[3], imms[2]),
                    make_uint64(imms[1], imms[0]));
    assembler->Move(scratch, make_uint64(imms[7], imms[6]),
                    make_uint64(imms[5], imms[4]));
    CpuFeatureScope avx_scope(assembler, AVX2);
    assembler->vinserti128(reg, reg, scratch, uint8_t{1});
  }
}

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  CodeGenerator::PushTypeFlags flags(kImmediatePush | kScalarPush);
  ZoneVector<MoveOperands*> pushes(zone());
  GetPushCompatibleMoves(instr, flags, &pushes);

  if (!pushes.empty() &&
      (LocationOperand::cast(pushes.back()->destination()).index() + 1 ==
       first_unused_slot_offset)) {
    DCHECK(!instr->HasCallDescriptorFlag(CallDescriptor::kIsTailCallForTierUp));
    X64OperandConverter g(this, instr);
    for (auto move : pushes) {
      LocationOperand destination_location(
          LocationOperand::cast(move->destination()));
      InstructionOperand source(move->source());
      AdjustStackPointerForTailCall(instr, masm(), linkage(), info(),
                                    frame_access_state(),
                                    destination_location.index());
      if (source.IsStackSlot()) {
        LocationOperand source_location(LocationOperand::cast(source));
        __ Push(g.SlotToOperand(source_location.index()));
      } else if (source.IsRegister()) {
        LocationOperand source_location(LocationOperand::cast(source));
        __ Push(source_location.GetRegister());
      } else if (source.IsImmediate()) {
        __ Push(Immediate(ImmediateOperand::cast(source).inline_int32_value()));
      } else {
        // Pushes of non-scalar data types is not supported.
        UNIMPLEMENTED();
      }
      frame_access_state()->IncreaseSPDelta(1);
      move->Eliminate();
    }
  }
  AdjustStackPointerForTailCall(instr, masm(), linkage(), info(),
                                frame_access_state(), first_unused_slot_offset,
                                false);
}

void CodeGenerator::AssembleTailCallAfterGap(Instruction* instr,
                                             int first_unused_slot_offset) {
  AdjustStackPointerForTailCall(instr, masm(), linkage(), info(),
                                frame_access_state(), first_unused_slot_offset);
}

// Check that {kJavaScriptCallCodeStartRegister} is correct.
void CodeGenerator::AssembleCodeStartRegisterCheck() {
  __ ComputeCodeStartAddress(rbx);
  __ cmpq(rbx, kJavaScriptCallCodeStartRegister);
  __ Assert(equal, AbortReason::kWrongFunctionCodeStart);
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
  __ LoadParameterCountFromJSDispatchTable(
      rbx, kJavaScriptCallDispatchHandleRegister);
  __ cmpl(rbx, Immediate(parameter_count_));
  __ Assert(equal, AbortReason::kWrongFunctionDispatchHandle);
}
#endif  // V8_ENABLE_LEAPTIERING

void CodeGenerator::BailoutIfDeoptimized() { __ BailoutIfDeoptimized(rbx); }

bool ShouldClearOutputRegisterBeforeInstruction(CodeGenerator* g,
                                                Instruction* instr) {
  X64OperandConverter i(g, instr);
  FlagsMode mode = FlagsModeField::decode(instr->opcode());
  if (mode == kFlags_set) {
    FlagsCondition condition = FlagsConditionField::decode(instr->opcode());
    if (condition != kUnorderedEqual && condition != kUnorderedNotEqual) {
      Register reg = i.OutputRegister(instr->OutputCount() - 1);
      // Do not clear output register when it is also input register.
      for (size_t index = 0; index < instr->InputCount(); ++index) {
        if (HasRegisterInput(instr, index) && reg == i.InputRegister(index))
          return false;
      }
      return true;
    }
  }
  return false;
}

void CodeGenerator::AssemblePlaceHolderForLazyDeopt(Instruction* instr) {
  if (info()->shadow_stack_compliant_lazy_deopt() &&
      instr->HasCallDescriptorFlag(CallDescriptor::kNeedsFrameState)) {
    __ Nop(MacroAssembler::kIntraSegmentJmpInstrSize);
  }
}

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  X64OperandConverter i(this, instr);
  InstructionCode opcode = instr->opcode();
  ArchOpcode arch_opcode = ArchOpcodeField::decode(opcode);
  if (ShouldClearOutputRegisterBeforeInstruction(this, instr)) {
    // Transform setcc + movzxbl into xorl + setcc to avoid register stall and
    // encode one byte shorter.
    Register reg = i.OutputRegister(instr->OutputCount() - 1);
    __ xorl(reg, reg);
  }
  switch (arch_opcode) {
    case kX64TraceInstruction: {
      __ emit_trace_instruction(i.InputImmediate(0));
      break;
    }
    case kArchCallCodeObject: {
      if (HasImmediateInput(instr, 0)) {
        Handle<Code> code = i.InputCode(0);
        __ Call(code, RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        CodeEntrypointTag tag =
            i.InputCodeEntrypointTag(instr->CodeEnrypointTagInputIndex());
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ LoadCodeInstructionStart(reg, reg, tag);
        __ call(reg);
      }
      RecordCallPosition(instr);
      AssemblePlaceHolderForLazyDeopt(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchCallBuiltinPointer: {
      DCHECK(!HasImmediateInput(instr, 0));
      Register builtin_index = i.InputRegister(0);
      __ CallBuiltinByIndex(builtin_index);
      RecordCallPosition(instr);
      AssemblePlaceHolderForLazyDeopt(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
#if V8_ENABLE_WEBASSEMBLY
    case kArchCallWasmFunction: {
      if (HasImmediateInput(instr, 0)) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        if (DetermineStubCallMode() == StubCallMode::kCallWasmRuntimeStub) {
          __ near_call(wasm_code, constant.rmode());
        } else {
          __ Call(wasm_code, constant.rmode());
        }
      } else {
        __ call(i.InputRegister(0));
      }
      RecordCallPosition(instr);
      AssemblePlaceHolderFo
```