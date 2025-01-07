Response:
My thought process to answer the request about `code-generator-ia32.cc` goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of this specific V8 source file. They also provide some contextual hints (Torque, JavaScript relation) and request a summary of the provided code snippet.

2. **Identify Key Information in the Code Snippet:** I scan the provided C++ code for important clues about its purpose. I notice:
    * **File Path:** `v8/src/compiler/backend/ia32/code-generator-ia32.cc` - This immediately tells me it's part of the V8 compiler, specifically the backend for the IA-32 (x86) architecture. The "code-generator" part is crucial.
    * **Includes:** The included headers like `assembler-ia32.h`, `register-ia32.h`, `code-generator-impl.h`, `code-generator.h` confirm its role in generating machine code.
    * **Namespace:** `v8::internal::compiler` reinforces it's part of the compiler's internal workings.
    * **Class `IA32OperandConverter`:** This class is clearly responsible for handling operands (inputs and outputs of instructions) in the IA-32 context. It converts between different operand representations (registers, stack slots, immediates).
    * **Macros (`__`, `ASSEMBLE_*`):** The heavy use of macros suggests this code is involved in emitting assembly instructions. The `ASSEMBLE_*` macros hint at how different high-level instructions are translated to IA-32 assembly.
    * **`AssembleArchInstruction` Function:** This function is the heart of the code generation process. It takes an intermediate representation instruction and emits the corresponding IA-32 assembly. The `switch` statement within this function, handling different `arch_opcode` values, is a key indicator of its purpose.
    * **Out-of-Line Code Classes:** Classes like `OutOfLineLoadFloat32NaN`, `OutOfLineTruncateDoubleToI`, `OutOfLineRecordWrite` suggest handling less common or more complex scenarios that require separate code blocks.
    * **Tail Call Handling (`AssemblePrepareTailCall`, `AssembleTailCallBeforeGap`, etc.):**  This points to optimizations related to function calls where the current stack frame can be reused.
    * **Deoptimization Handling (`BailoutIfDeoptimized`):** This is related to V8's optimization and deoptimization process.
    * **Specific IA-32 Instructions:**  The code uses IA-32 assembly mnemonics like `mov`, `add`, `cmp`, `call`, `jmp`, `push`, `pop`, `xor`, etc. This solidifies its role in generating low-level code.
    * **SIMD Instructions (`ASSEMBLE_SIMD_*`):**  This indicates support for Single Instruction, Multiple Data operations, which are important for performance in certain types of computations.

3. **Formulate the High-Level Functionality:** Based on the identified clues, I can deduce that `code-generator-ia32.cc` is the part of the V8 compiler responsible for translating platform-independent intermediate representation (IR) instructions into concrete IA-32 machine code. This involves:
    * **Operand Handling:** Converting IR operands into IA-32 specific operands (registers, memory locations).
    * **Instruction Emission:** Generating IA-32 assembly instructions based on the IR instructions.
    * **Handling Special Cases:**  Dealing with things like NaN values, type conversions, garbage collection barriers (record writes), and tail calls.
    * **Optimization Support:** Implementing optimizations like tail call optimization.
    * **Deoptimization Support:**  Handling cases where optimized code needs to be abandoned.

4. **Address the Specific Questions:**

    * **Torque:** The filename doesn't end in `.tq`, so it's not a Torque source file.
    * **JavaScript Relationship:**  This is a crucial link. The code generator's purpose is to *execute* JavaScript efficiently. I need to explain that the generated IA-32 code directly implements the logic of JavaScript code. I can use a simple JavaScript example to illustrate how an addition operation in JavaScript might be translated into IA-32 assembly.
    * **Code Logic Inference (Hypothetical Input/Output):**  I can pick a simple operation like adding two numbers and show how the `AssembleArchInstruction` function might handle the corresponding IR instruction, resulting in IA-32 `add` instructions.
    * **Common Programming Errors:**  Relating this low-level code to common *JavaScript* errors is difficult directly. However, I can explain that incorrect logic in the code generator could *lead to* runtime errors in JavaScript, like incorrect calculations or memory corruption (though the V8 team works hard to prevent this!). I should frame it as potential issues *if* this code were buggy.

5. **Summarize the Functionality:**  Combine the key findings into a concise summary that highlights the core purpose of the file.

6. **Structure the Answer:** Organize the information logically with clear headings and examples to make it easy to understand. Use the specific terms and concepts from the code (like "operands," "instructions," "registers") to demonstrate understanding.

7. **Refine and Review:** Read through the answer to ensure accuracy, clarity, and completeness. Check if all parts of the original request have been addressed.

By following these steps, I can generate a comprehensive and informative answer that addresses the user's request effectively, even with complex source code like this. The key is to break down the code into manageable pieces, understand the overall context, and then connect the low-level details to the high-level purpose of the V8 engine.
这是一个V8 JavaScript引擎中用于IA-32架构的代码生成器的C++源代码文件。它负责将V8的中间表示（IR）转换为可以在IA-32处理器上执行的机器码。

以下是该文件的功能归纳：

**核心功能：将V8的中间表示（IR）转换为IA-32汇编代码。**

更具体地说，`code-generator-ia32.cc` 实现了 `CodeGenerator` 类的特定于 IA-32 架构的部分。 它定义了如何将各种高级操作（例如算术运算、对象访问、函数调用等）翻译成 IA-32 指令。

**主要职责和功能点：**

1. **指令处理和汇编:**
   - 它遍历编译器生成的中间表示（IR）指令。
   - 对于每个 IR 指令，它生成相应的 IA-32 汇编指令。这涉及到选择合适的 IA-32 操作码、操作数（寄存器、内存地址、立即数）以及处理不同的寻址模式。
   - 使用 `MacroAssembler` 类 (`__ masm()->`) 来生成 IA-32 汇编代码。

2. **操作数转换:**
   - `IA32OperandConverter` 类负责将中间表示的操作数转换为 IA-32 汇编语言中使用的操作数类型（例如，寄存器、内存操作数、立即数）。
   - 它处理栈槽、寄存器和常量等不同类型的操作数。

3. **特定于 IA-32 的优化和处理:**
   - 实现了针对 IA-32 架构的优化策略。
   - 处理浮点数运算（使用 x87 或 SSE/AVX 指令，具体取决于 CPU 功能）。
   - 处理整数运算、位运算、比较操作等。
   - 实现原子操作（例如，用于多线程编程）。
   - 支持 SIMD (Single Instruction, Multiple Data) 指令，以提高并行处理能力。

4. **函数调用和尾调用:**
   - 生成用于标准函数调用和尾调用的汇编代码。
   - 处理参数传递、栈帧的设置和销毁。

5. **内联代码（Out-of-line Code）处理:**
   - 对于一些不常见的或复杂的场景，例如加载 NaN 值、截断浮点数到整数、记录写屏障等，使用“内联代码” (OutOfLineCode) 的方式生成单独的代码块，并在需要时跳转到这些代码块执行。这有助于保持主代码路径的简洁。

6. **Deoptimization 支持:**
   - 包含了用于处理代码去优化的逻辑。如果优化后的代码不再有效（例如，由于类型假设失效），则会跳转到去优化流程。

7. **WebAssembly 支持:**
   - 包含了与 WebAssembly 相关的代码生成逻辑（如果 `V8_ENABLE_WEBASSEMBLY` 宏被定义）。

**如果 `v8/src/compiler/backend/ia32/code-generator-ia32.cc` 以 `.tq` 结尾：**

那么它将是一个 **Torque** 源代码文件。Torque 是 V8 使用的一种类型化的中间语言，用于生成高效的 C++ 代码，包括一些底层的运行时函数和代码生成器。  当前的文件名是 `.cc`，表明它是纯 C++ 代码。

**与 JavaScript 功能的关系及示例：**

`code-generator-ia32.cc` 直接负责将 JavaScript 代码编译成机器码，因此它与 JavaScript 的所有功能都有关系。 任何你执行的 JavaScript 代码最终都会通过类似这样的代码生成器转换成 CPU 可以理解的指令。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 编译这段 `add` 函数时，`code-generator-ia32.cc` 会生成类似于以下的 IA-32 汇编代码（这只是一个简化的示例）：

```assembly
push ebp         ; 保存旧的基址指针
mov ebp, esp     ; 设置新的基址指针

; 获取参数 a 和 b (假设它们在栈上)
mov eax, [ebp + 8]  ; 将 a 加载到 eax 寄存器
mov ecx, [ebp + 12] ; 将 b 加载到 ecx 寄存器

add eax, ecx      ; 执行加法操作，结果在 eax 中

; 返回值通常放在 eax 寄存器中
pop ebp          ; 恢复旧的基址指针
ret              ; 返回
```

**代码逻辑推理（假设输入与输出）：**

**假设输入 (IR 指令):**  一个表示整数加法的 IR 指令，例如 `IROpcode::kAdd`, 输入操作数是寄存器 `r1` 和立即数 `5`，输出操作数是寄存器 `r2`。

**假设输出 (生成的 IA-32 汇编代码):**

```assembly
mov eax, r1      ; 假设 r1 映射到 eax
add eax, 5       ; 将立即数 5 加到 eax
mov r2, eax      ; 假设 r2 映射到某个寄存器，将结果存入
```

**用户常见的编程错误 (与代码生成器的间接关系):**

虽然用户不会直接与 `code-generator-ia32.cc` 交互，但该代码生成器中的错误可能会导致用户代码的意外行为。例如：

* **类型错误:** 如果代码生成器在处理类型转换时存在 bug，可能会导致 JavaScript 中本应抛出类型错误的运算没有抛出，或者得到错误的结果。
   ```javascript
   // 例如，如果代码生成器错误地处理字符串和数字的加法
   let result = "5" + 3; // 应该得到 "53"，但可能由于代码生成器 bug 得到 8
   ```
* **内存访问错误:** 代码生成器负责生成访问内存的指令。如果存在错误，可能导致访问越界或访问了不应该访问的内存区域，导致程序崩溃或产生未定义行为。
   ```javascript
   let arr = [1, 2, 3];
   // 如果代码生成器在处理数组访问时存在 bug，
   // 访问 arr[10] 可能不会抛出错误，反而读取了其他内存。
   console.log(arr[10]);
   ```
* **逻辑错误:** 代码生成器中的逻辑错误可能导致生成的机器码无法正确实现 JavaScript 代码的意图。例如，条件判断的生成逻辑错误可能导致代码执行错误的路径。
   ```javascript
   function isEven(n) {
     return n % 2 === 0;
   }
   // 如果代码生成器错误地处理取模运算符，
   // isEven(3) 可能返回 true。
   console.log(isEven(3));
   ```

**第 1 部分功能归纳：**

这部分代码主要负责以下功能：

* **定义了 `IA32OperandConverter` 类:** 用于将中间表示的操作数转换为 IA-32 汇编操作数。
* **定义了一些辅助宏和内联代码类:** 用于简化汇编代码的生成，并处理一些特殊的代码生成场景（例如，NaN 值的加载、类型转换、记录写屏障）。
* **实现了 `AssembleDeconstructFrame` 和 `AssemblePrepareTailCall` 等函数:** 用于处理函数调用和尾调用相关的栈帧操作。
* **实现了 `AssembleTailCallBeforeGap` 和 `AssembleTailCallAfterGap`:**  用于在尾调用前后调整栈指针。
* **实现了代码启动寄存器检查和去优化检查:** 确保代码执行的正确性和处理去优化流程。
* **定义了 `AssembleArchInstruction` 函数的框架:**  这是核心的代码生成函数，用于根据不同的架构操作码生成相应的 IA-32 汇编代码 (但只展示了部分 case)。

总的来说，这部分代码是 IA-32 代码生成器的基础结构，定义了操作数转换、栈帧处理、尾调用支持以及代码生成的核心框架。它为后续 `AssembleArchInstruction` 函数中针对各种具体 IR 指令的代码生成提供了必要的工具和基础。

Prompt: 
```
这是目录为v8/src/compiler/backend/ia32/code-generator-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/code-generator-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/overflowing-math.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/ia32/assembler-ia32.h"
#include "src/codegen/ia32/register-ia32.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/objects/smi.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

#define __ masm()->

#define kScratchDoubleReg xmm0

// Adds IA-32 specific methods for decoding operands.
class IA32OperandConverter : public InstructionOperandConverter {
 public:
  IA32OperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  Operand InputOperand(size_t index, int extra = 0) {
    return ToOperand(instr_->InputAt(index), extra);
  }

  Immediate InputImmediate(size_t index) {
    return ToImmediate(instr_->InputAt(index));
  }

  Operand OutputOperand() { return ToOperand(instr_->Output()); }

  Operand ToOperand(InstructionOperand* op, int extra = 0) {
    if (op->IsRegister()) {
      DCHECK_EQ(0, extra);
      return Operand(ToRegister(op));
    } else if (op->IsFPRegister()) {
      DCHECK_EQ(0, extra);
      return Operand(ToDoubleRegister(op));
    }
    DCHECK(op->IsStackSlot() || op->IsFPStackSlot());
    return SlotToOperand(AllocatedOperand::cast(op)->index(), extra);
  }

  Operand SlotToOperand(int slot, int extra = 0) {
    FrameOffset offset = frame_access_state()->GetFrameOffset(slot);
    return Operand(offset.from_stack_pointer() ? esp : ebp,
                   offset.offset() + extra);
  }

  Immediate ToImmediate(InstructionOperand* operand) {
    Constant constant = ToConstant(operand);
    switch (constant.type()) {
      case Constant::kInt32:
        return Immediate(constant.ToInt32(), constant.rmode());
      case Constant::kFloat32:
        return Immediate::EmbeddedNumber(constant.ToFloat32());
      case Constant::kFloat64:
        return Immediate::EmbeddedNumber(constant.ToFloat64().value());
      case Constant::kExternalReference:
        return Immediate(constant.ToExternalReference());
      case Constant::kHeapObject:
        return Immediate(constant.ToHeapObject());
      case Constant::kCompressedHeapObject:
        break;
      case Constant::kInt64:
        break;
      case Constant::kRpoNumber:
        return Immediate::CodeRelativeOffset(ToLabel(operand));
    }
    UNREACHABLE();
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
        Constant ctant = ToConstant(instr_->InputAt(NextOffset(offset)));
        return Operand(base, ctant.ToInt32(), ctant.rmode());
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
        Constant ctant = ToConstant(instr_->InputAt(NextOffset(offset)));
        return Operand(base, index, scale, ctant.ToInt32(), ctant.rmode());
      }
      case kMode_M1:
      case kMode_M2:
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
        Constant ctant = ToConstant(instr_->InputAt(NextOffset(offset)));
        return Operand(index, scale, ctant.ToInt32(), ctant.rmode());
      }
      case kMode_MI: {
        Constant ctant = ToConstant(instr_->InputAt(NextOffset(offset)));
        return Operand(ctant.ToInt32(), ctant.rmode());
      }
      case kMode_Root: {
        Register base = kRootRegister;
        int32_t disp = InputInt32(NextOffset(offset));
        return Operand(base, disp);
      }
      case kMode_None:
        UNREACHABLE();
    }
    UNREACHABLE();
  }

  Operand MemoryOperand(size_t first_input = 0) {
    return MemoryOperand(&first_input);
  }

  Operand NextMemoryOperand(size_t offset = 0) {
    AddressingMode mode = AddressingModeField::decode(instr_->opcode());
    Register base = InputRegister(NextOffset(&offset));
    const int32_t disp = 4;
    if (mode == kMode_MR1) {
      Register index = InputRegister(NextOffset(&offset));
      ScaleFactor scale = ScaleFor(kMode_MR1, kMode_MR1);
      return Operand(base, index, scale, disp);
    } else if (mode == kMode_MRI) {
      Constant ctant = ToConstant(instr_->InputAt(NextOffset(&offset)));
      return Operand(base, ctant.ToInt32() + disp, ctant.rmode());
    } else {
      UNREACHABLE();
    }
  }

  void MoveInstructionOperandToRegister(Register destination,
                                        InstructionOperand* op) {
    if (op->IsImmediate() || op->IsConstant()) {
      gen_->masm()->mov(destination, ToImmediate(op));
    } else if (op->IsRegister()) {
      gen_->masm()->Move(destination, ToRegister(op));
    } else {
      gen_->masm()->mov(destination, ToOperand(op));
    }
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
    __ xorps(result_, result_);
    __ divss(result_, result_);
  }

 private:
  XMMRegister const result_;
};

class OutOfLineLoadFloat64NaN final : public OutOfLineCode {
 public:
  OutOfLineLoadFloat64NaN(CodeGenerator* gen, XMMRegister result)
      : OutOfLineCode(gen), result_(result) {}

  void Generate() final {
    __ xorpd(result_, result_);
    __ divsd(result_, result_);
  }

 private:
  XMMRegister const result_;
};

class OutOfLineTruncateDoubleToI final : public OutOfLineCode {
 public:
  OutOfLineTruncateDoubleToI(CodeGenerator* gen, Register result,
                             XMMRegister input, StubCallMode stub_mode)
      : OutOfLineCode(gen),
        result_(result),
        input_(input),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        isolate_(gen->isolate()),
        zone_(gen->zone()) {
  }

  void Generate() final {
    __ AllocateStackSpace(kDoubleSize);
    __ Movsd(MemOperand(esp, 0), input_);
#if V8_ENABLE_WEBASSEMBLY
    if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      // A direct call to a builtin. Just encode the builtin index. This will be
      // patched when the code is added to the native module and copied into
      // wasm code space.
      __ wasm_call(static_cast<Address>(Builtin::kDoubleToI),
                   RelocInfo::WASM_STUB_CALL);
#else
    // For balance.
    if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      __ CallBuiltin(Builtin::kDoubleToI);
    }
    __ mov(result_, MemOperand(esp, 0));
    __ add(esp, Immediate(kDoubleSize));
  }

 private:
  Register const result_;
  XMMRegister const input_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  Isolate* isolate_;
  Zone* zone_;
};

class OutOfLineRecordWrite final : public OutOfLineCode {
 public:
  OutOfLineRecordWrite(CodeGenerator* gen, Register object, Operand operand,
                       Register value, Register scratch0, Register scratch1,
                       RecordWriteMode mode, StubCallMode stub_mode)
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
        zone_(gen->zone()) {
    DCHECK(!AreAliased(object, scratch0, scratch1));
    DCHECK(!AreAliased(value, scratch0, scratch1));
  }

  void Generate() final {
    __ CheckPageFlag(value_, scratch0_,
                     MemoryChunk::kPointersToHereAreInterestingMask, zero,
                     exit());
    __ lea(scratch1_, operand_);
    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
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
};

}  // namespace

#define ASSEMBLE_COMPARE(asm_instr)                              \
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
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                     \
  do {                                                                   \
    /* Pass two doubles as arguments on the stack. */                    \
    __ PrepareCallCFunction(4, eax);                                     \
    __ movsd(Operand(esp, 0 * kDoubleSize), i.InputDoubleRegister(0));   \
    __ movsd(Operand(esp, 1 * kDoubleSize), i.InputDoubleRegister(1));   \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 4); \
    /* Return value is in st(0) on ia32. */                              \
    /* Store it into the result register. */                             \
    __ AllocateStackSpace(kDoubleSize);                                  \
    __ fstp_d(Operand(esp, 0));                                          \
    __ movsd(i.OutputDoubleRegister(), Operand(esp, 0));                 \
    __ add(esp, Immediate(kDoubleSize));                                 \
  } while (false)

#define ASSEMBLE_IEEE754_UNOP(name)                                      \
  do {                                                                   \
    /* Pass one double as argument on the stack. */                      \
    __ PrepareCallCFunction(2, eax);                                     \
    __ movsd(Operand(esp, 0 * kDoubleSize), i.InputDoubleRegister(0));   \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 2); \
    /* Return value is in st(0) on ia32. */                              \
    /* Store it into the result register. */                             \
    __ AllocateStackSpace(kDoubleSize);                                  \
    __ fstp_d(Operand(esp, 0));                                          \
    __ movsd(i.OutputDoubleRegister(), Operand(esp, 0));                 \
    __ add(esp, Immediate(kDoubleSize));                                 \
  } while (false)

#define ASSEMBLE_BINOP(asm_instr)                             \
  do {                                                        \
    if (HasAddressingMode(instr)) {                           \
      size_t index = 1;                                       \
      Operand right = i.MemoryOperand(&index);                \
      __ asm_instr(i.InputRegister(0), right);                \
    } else {                                                  \
      if (HasImmediateInput(instr, 1)) {                      \
        __ asm_instr(i.InputOperand(0), i.InputImmediate(1)); \
      } else {                                                \
        __ asm_instr(i.InputRegister(0), i.InputOperand(1));  \
      }                                                       \
    }                                                         \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP(bin_inst, mov_inst, cmpxchg_inst) \
  do {                                                          \
    Label binop;                                                \
    __ bind(&binop);                                            \
    __ mov_inst(eax, i.MemoryOperand(1));                       \
    __ Move(i.TempRegister(0), eax);                            \
    __ bin_inst(i.TempRegister(0), i.InputRegister(0));         \
    __ lock();                                                  \
    __ cmpxchg_inst(i.MemoryOperand(1), i.TempRegister(0));     \
    __ j(not_equal, &binop);                                    \
  } while (false)

#define ASSEMBLE_I64ATOMIC_BINOP(instr1, instr2)                \
  do {                                                          \
    Label binop;                                                \
    __ bind(&binop);                                            \
    __ mov(eax, i.MemoryOperand(2));                            \
    __ mov(edx, i.NextMemoryOperand(2));                        \
    __ push(ebx);                                               \
    frame_access_state()->IncreaseSPDelta(1);                   \
    i.MoveInstructionOperandToRegister(ebx, instr->InputAt(0)); \
    __ push(i.InputRegister(1));                                \
    __ instr1(ebx, eax);                                        \
    __ instr2(i.InputRegister(1), edx);                         \
    __ lock();                                                  \
    __ cmpxchg8b(i.MemoryOperand(2));                           \
    __ pop(i.InputRegister(1));                                 \
    __ pop(ebx);                                                \
    frame_access_state()->IncreaseSPDelta(-1);                  \
    __ j(not_equal, &binop);                                    \
  } while (false);

#define ASSEMBLE_MOVX(mov_instr)                            \
  do {                                                      \
    if (HasAddressingMode(instr)) {                         \
      __ mov_instr(i.OutputRegister(), i.MemoryOperand());  \
    } else if (HasRegisterInput(instr, 0)) {                \
      __ mov_instr(i.OutputRegister(), i.InputRegister(0)); \
    } else {                                                \
      __ mov_instr(i.OutputRegister(), i.InputOperand(0));  \
    }                                                       \
  } while (0)

#define ASSEMBLE_SIMD_PUNPCK_SHUFFLE(opcode)                         \
  do {                                                               \
    XMMRegister src0 = i.InputSimd128Register(0);                    \
    Operand src1 = i.InputOperand(instr->InputCount() == 2 ? 1 : 0); \
    if (CpuFeatures::IsSupported(AVX)) {                             \
      CpuFeatureScope avx_scope(masm(), AVX);                        \
      __ v##opcode(i.OutputSimd128Register(), src0, src1);           \
    } else {                                                         \
      DCHECK_EQ(i.OutputSimd128Register(), src0);                    \
      __ opcode(i.OutputSimd128Register(), src1);                    \
    }                                                                \
  } while (false)

#define ASSEMBLE_SIMD_IMM_SHUFFLE(opcode, SSELevel, imm)               \
  if (CpuFeatures::IsSupported(AVX)) {                                 \
    CpuFeatureScope avx_scope(masm(), AVX);                            \
    __ v##opcode(i.OutputSimd128Register(), i.InputSimd128Register(0), \
                 i.InputOperand(1), imm);                              \
  } else {                                                             \
    CpuFeatureScope sse_scope(masm(), SSELevel);                       \
    DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));   \
    __ opcode(i.OutputSimd128Register(), i.InputOperand(1), imm);      \
  }

#define ASSEMBLE_SIMD_ALL_TRUE(opcode)               \
  do {                                               \
    Register dst = i.OutputRegister();               \
    Operand src = i.InputOperand(0);                 \
    Register tmp = i.TempRegister(0);                \
    XMMRegister tmp_simd = i.TempSimd128Register(1); \
    __ mov(tmp, Immediate(1));                       \
    __ xor_(dst, dst);                               \
    __ Pxor(tmp_simd, tmp_simd);                     \
    __ opcode(tmp_simd, src);                        \
    __ Ptest(tmp_simd, tmp_simd);                    \
    __ cmov(zero, dst, tmp);                         \
  } while (false)

#define ASSEMBLE_SIMD_SHIFT(opcode, width)                \
  do {                                                    \
    XMMRegister dst = i.OutputSimd128Register();          \
    DCHECK_EQ(dst, i.InputSimd128Register(0));            \
    if (HasImmediateInput(instr, 1)) {                    \
      __ opcode(dst, dst, uint8_t{i.InputInt##width(1)}); \
    } else {                                              \
      XMMRegister tmp = i.TempSimd128Register(0);         \
      Register tmp_shift = i.TempRegister(1);             \
      constexpr int mask = (1 << width) - 1;              \
      __ mov(tmp_shift, i.InputRegister(1));              \
      __ and_(tmp_shift, Immediate(mask));                \
      __ Movd(tmp, tmp_shift);                            \
      __ opcode(dst, dst, tmp);                           \
    }                                                     \
  } while (false)

#define ASSEMBLE_SIMD_PINSR(OPCODE, CPU_FEATURE)             \
  do {                                                       \
    XMMRegister dst = i.OutputSimd128Register();             \
    XMMRegister src = i.InputSimd128Register(0);             \
    int8_t laneidx = i.InputInt8(1);                         \
    if (HasAddressingMode(instr)) {                          \
      if (CpuFeatures::IsSupported(AVX)) {                   \
        CpuFeatureScope avx_scope(masm(), AVX);              \
        __ v##OPCODE(dst, src, i.MemoryOperand(2), laneidx); \
      } else {                                               \
        DCHECK_EQ(dst, src);                                 \
        CpuFeatureScope sse_scope(masm(), CPU_FEATURE);      \
        __ OPCODE(dst, i.MemoryOperand(2), laneidx);         \
      }                                                      \
    } else {                                                 \
      if (CpuFeatures::IsSupported(AVX)) {                   \
        CpuFeatureScope avx_scope(masm(), AVX);              \
        __ v##OPCODE(dst, src, i.InputOperand(2), laneidx);  \
      } else {                                               \
        DCHECK_EQ(dst, src);                                 \
        CpuFeatureScope sse_scope(masm(), CPU_FEATURE);      \
        __ OPCODE(dst, i.InputOperand(2), laneidx);          \
      }                                                      \
    }                                                        \
  } while (false)

void CodeGenerator::AssembleDeconstructFrame() {
  __ mov(esp, ebp);
  __ pop(ebp);
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ mov(ebp, MemOperand(ebp, 0));
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
    masm->AllocateStackSpace(stack_slot_delta * kSystemPointerSize);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    masm->add(esp, Immediate(-stack_slot_delta * kSystemPointerSize));
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

#ifdef DEBUG
bool VerifyOutputOfAtomicPairInstr(IA32OperandConverter* converter,
                                   const Instruction* instr) {
  if (instr->OutputCount() == 2) {
    return (converter->OutputRegister(0) == eax &&
            converter->OutputRegister(1) == edx);
  }
  if (instr->OutputCount() == 1) {
    return (converter->OutputRegister(0) == eax &&
            converter->TempRegister(0) == edx) ||
           (converter->OutputRegister(0) == edx &&
            converter->TempRegister(0) == eax);
  }
  DCHECK_EQ(instr->OutputCount(), 0);
  return (converter->TempRegister(0) == eax &&
          converter->TempRegister(1) == edx);
}
#endif

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  CodeGenerator::PushTypeFlags flags(kImmediatePush | kScalarPush);
  ZoneVector<MoveOperands*> pushes(zone());
  GetPushCompatibleMoves(instr, flags, &pushes);

  if (!pushes.empty() &&
      (LocationOperand::cast(pushes.back()->destination()).index() + 1 ==
       first_unused_slot_offset)) {
    IA32OperandConverter g(this, instr);
    for (auto move : pushes) {
      LocationOperand destination_location(
          LocationOperand::cast(move->destination()));
      InstructionOperand source(move->source());
      AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                    destination_location.index());
      if (source.IsStackSlot()) {
        LocationOperand source_location(LocationOperand::cast(source));
        __ push(g.SlotToOperand(source_location.index()));
      } else if (source.IsRegister()) {
        LocationOperand source_location(LocationOperand::cast(source));
        __ push(source_location.GetRegister());
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
  __ push(eax);  // Push eax so we can use it as a scratch register.
  __ ComputeCodeStartAddress(eax);
  __ cmp(eax, kJavaScriptCallCodeStartRegister);
  __ Assert(equal, AbortReason::kWrongFunctionCodeStart);
  __ pop(eax);  // Restore eax.
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
  __ push(eax);  // Push eax so we can use it as a scratch register.
  __ mov(eax, Operand(kJavaScriptCallCodeStartRegister, offset));
  __ test(FieldOperand(eax, Code::kFlagsOffset),
          Immediate(1 << Code::kMarkedForDeoptimizationBit));
  __ pop(eax);  // Restore eax.

  Label skip;
  __ j(zero, &skip, Label::kNear);
  __ TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode);
  __ bind(&skip);
}

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  IA32OperandConverter i(this, instr);
  InstructionCode opcode = instr->opcode();
  ArchOpcode arch_opcode = ArchOpcodeField::decode(opcode);
  switch (arch_opcode) {
    case kArchCallCodeObject: {
      InstructionOperand* op = instr->InputAt(0);
      if (op->IsImmediate()) {
        Handle<Code> code = i.InputCode(0);
        __ Call(code, RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ CallCodeObject(reg);
      }
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchCallBuiltinPointer: {
      DCHECK(!HasImmediateInput(instr, 0));
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
      if (HasImmediateInput(instr, 0)) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt32());
        if (DetermineStubCallMode() == StubCallMode::kCallWasmRuntimeStub) {
          __ wasm_call(wasm_code, constant.rmode());
        } else {
          __ call(wasm_code, constant.rmode());
        }
      } else {
        __ call(i.InputRegister(0));
      }
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchTailCallWasm: {
      if (HasImmediateInput(instr, 0)) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt32());
        __ jmp(wasm_code, constant.rmode());
      } else {
        __ jmp(i.InputRegister(0));
      }
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchTailCallCodeObject: {
      if (HasImmediateInput(instr, 0)) {
        Handle<Code> code = i.InputCode(0);
        __ Jump(code, RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ JumpCodeObject(reg);
      }
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchTailCallAddress: {
      CHECK(!HasImmediateInput(instr, 0));
      Register reg = i.InputRegister(0);
      DCHECK_IMPLIES(
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
          reg == kJavaScriptCallCodeStartRegister);
      __ jmp(reg);
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchCallJSFunction: {
      Register func = i.InputRegister(0);
      if (v8_flags.debug_code) {
        // Check the function's context matches the context argument.
        __ cmp(esi, FieldOperand(func, JSFunction::kContextOffset));
        __ Assert(equal, AbortReason::kWrongFunctionContext);
      }
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction: {
      // Frame alignment requires using FP-relative frame addressing.
      frame_access_state()->SetFrameAccessToFP();
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      __ PrepareCallCFunction(num_gp_parameters + num_fp_parameters,
                              i.TempRegister(0));
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
      fra
"""


```