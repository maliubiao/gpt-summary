Response:
My thinking process to arrive at the summary of `code-generator-loong64.cc` goes like this:

1. **Identify the core purpose:** The filename itself, `code-generator-loong64.cc`, strongly suggests this file is responsible for generating machine code specifically for the LoongArch 64-bit architecture within the V8 JavaScript engine's compiler.

2. **Scan for key data structures and classes:**  I look for prominent class definitions and data structures used in the code. The `Loong64OperandConverter` is immediately apparent and likely handles the translation of high-level instruction operands into LoongArch specific representations. The various `OutOfLine*` classes signal the presence of handling for less common or more complex operations that are generated separately.

3. **Look for architecture-specific keywords and functions:** I search for LoongArch specific assembly instructions (e.g., `__ Add_d`, `__ Ld_d`, `__ BranchShort`, `__ dbar`), register names (`sp`, `fp`, `ra`, `zero_reg`), and constants (e.g., `kRootRegister`). This confirms the file's purpose and gives hints about the low-level operations it manages.

4. **Analyze the `OutOfLineCode` subclasses:** These are important. They indicate special handling for tasks like record writes (for garbage collection), floating-point min/max operations, and potentially WebAssembly traps. Understanding these helps to understand the broader scope of the code generator.

5. **Examine the conditional compilation (`#ifdef`) directives:** The presence of `#if V8_ENABLE_WEBASSEMBLY` indicates support for WebAssembly and that certain code paths are specific to this feature. This adds another dimension to the file's functionality.

6. **Focus on the `AssembleArchInstruction` function:** This is likely the central function where the actual assembly of individual instructions happens. I look at the different `case` statements within the `switch` block to understand the types of instructions being handled: function calls (`kArchCallCodeObject`, `kArchCallBuiltinPointer`, `kArchCallWasmFunction`), tail calls, and other architecture-specific operations.

7. **Infer relationships to other parts of the V8 pipeline:**  The code interacts with concepts like `CodeGenerator`, `Instruction`, `Operand`, `Register`, `FrameAccessState`, and `MacroAssembler`. This indicates it's part of the backend compilation process, taking high-level instructions and converting them into machine code.

8. **Synthesize the findings into functional categories:** Based on the above observations, I group the functionalities into logical categories:
    * **Instruction Encoding:** Translating instructions and operands.
    * **Memory Access:** Handling memory operations with specific modes.
    * **Function Calls:**  Generating code for different types of function calls (JS, built-in, WebAssembly).
    * **Tail Calls:**  Optimizing function calls.
    * **Specialized Operations:**  Implementing complex or less frequent operations out-of-line.
    * **Atomic Operations:** Supporting atomic memory operations.
    * **Floating-Point Operations:** Handling floating-point arithmetic, including special cases like min/max.
    * **WebAssembly Support:** Specific handling for WebAssembly instructions.
    * **Deoptimization Handling:** Mechanisms for bailing out of optimized code.

9. **Address the specific questions in the prompt:** Finally, I go back to the prompt and explicitly address each question:
    * **Main Functionality:** Summarize the core purpose.
    * **`.tq` extension:**  Explain that it's not a Torque file based on the extension.
    * **Relationship to JavaScript:**  Explain that it generates the low-level code that *executes* JavaScript. Provide a conceptual JavaScript example (even if the C++ code doesn't directly *translate* it).
    * **Code Logic/Input-Output:**  This is harder to give a specific example without deep diving. I opt for a general description of the translation process.
    * **Common Programming Errors:** Suggest that incorrect assumptions about register usage or memory layout could be errors the *code generator developers* might encounter.
    * **Summary for Part 1:** Condense the key takeaways.

This systematic approach of examining the code structure, keywords, and function names allows for a comprehensive understanding of the file's purpose and its role within the larger V8 project. It moves from concrete observations to higher-level interpretations and finally addresses the specific requirements of the prompt.
这是一个V8 JavaScript引擎的源代码文件，路径为 `v8/src/compiler/backend/loong64/code-generator-loong64.cc`，专门为 LoongArch 64位架构（loong64）生成机器码。

**功能归纳 (第1部分):**

这个文件的主要功能是**为V8的编译器后端提供LoongArch 64位架构的代码生成能力**。 具体来说，它负责将编译器生成的中间表示（Instruction）转换为可以在LoongArch64处理器上执行的机器指令。

以下是它更详细的功能点：

* **定义了 LoongArch 64 位架构特定的操作数转换器 (`Loong64OperandConverter`)**:  这个类负责将与指令相关的操作数（寄存器、立即数、内存地址等）转换为 LoongArch 汇编器可以理解的形式。它处理了LoongArch架构中单精度和双精度浮点寄存器使用相同命名空间的情况。

* **实现了多种内联和外联的代码生成模式**: 对于一些常见的操作，代码可以直接内联生成。对于一些复杂或不常用的操作，则会生成跳转到"外联"代码的指令，这些外联代码在 `OutOfLineCode` 的子类中定义，例如处理记录写入屏障、浮点数最大/最小值等。

* **处理函数调用和尾调用**:  它包含了生成不同类型函数调用（如调用Code对象、内置函数、WebAssembly函数）和尾调用所需的机器指令的逻辑。

* **支持原子操作**:  文件中定义了宏，用于生成 LoongArch 架构的原子加载、存储和算术运算指令。

* **处理浮点运算**:  包括基本的浮点算术运算，以及通过调用C函数库来实现的一些特殊浮点操作（例如 `ieee754_min_function`）。

* **支持 WebAssembly (通过条件编译)**: 如果启用了 WebAssembly，文件中会包含处理 WebAssembly 特有指令的代码生成逻辑，包括陷阱（trap）处理。

* **实现代码开始寄存器和分发句柄的检查**:  在特定的编译配置下，它可以生成代码来验证一些关键寄存器是否包含预期的值，这有助于调试和验证编译器的正确性。

* **处理去优化 (Deoptimization)**:  文件中包含检测代码对象是否被标记为去优化的逻辑，如果是，则会跳转到相应的内置函数。

**关于 .tq 结尾：**

如果 `v8/src/compiler/backend/loong64/code-generator-loong64.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是一种 V8 内部使用的类型化的中间语言，用于生成高效的 C++ 代码。 但根据您提供的文件名，它是 `.cc` 结尾，所以它是一个 **C++ 源代码文件**。

**与 JavaScript 的关系：**

`code-generator-loong64.cc` 的核心功能是将 JavaScript 代码编译成可以在 LoongArch64 处理器上执行的机器码。当 V8 引擎执行 JavaScript 代码时，它会经过解析、优化等阶段，最终到达代码生成阶段。这个文件就是负责将优化后的中间表示翻译成实际的处理器指令，从而让 JavaScript 代码得以运行。

**JavaScript 示例说明：**

虽然 `code-generator-loong64.cc` 是 C++ 代码，但它最终影响着 JavaScript 代码的执行效率和行为。例如，考虑一个简单的 JavaScript 加法运算：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result); // 输出 8
```

当 V8 编译 `add` 函数时，`code-generator-loong64.cc` 中的代码会生成类似于以下 LoongArch 汇编指令 (简化示例)：

```assembly
  ld.d   $t0, [sp, #arg_a_offset]  // 加载参数 a 到寄存器 $t0
  ld.d   $t1, [sp, #arg_b_offset]  // 加载参数 b 到寄存器 $t1
  add.d  $v0, $t0, $t1             // 将 $t0 和 $t1 的值相加，结果存入 $v0
  st.d   $v0, [sp, #return_offset] // 将结果存储到返回地址
  retl                             // 返回
```

这个 C++ 文件中的逻辑就负责生成类似这样的汇编代码，从而实现 JavaScript 的加法运算。

**代码逻辑推理（假设输入与输出）：**

假设输入是一个表示 JavaScript 加法操作的 `Instruction` 对象，其中指定了两个输入寄存器（例如，存放操作数 `a` 和 `b` 的寄存器）和一个输出寄存器（用于存放结果）。

**假设输入：**

* `Instruction` 对象，其 `opcode` 表示加法操作 (例如，`kArchAdd` 或类似的架构特定加法指令)。
* 输入操作数：两个寄存器，分别存储整数值 5 和 3。
* 输出操作数：一个目标寄存器。

**预期输出：**

* 生成的 LoongArch 机器码指令，会将输入寄存器的值相加，并将结果存储到输出寄存器中。例如，对应的汇编代码可能是 `add.d  $rd, $rs1, $rs2`，其中 `$rd` 是输出寄存器，`$rs1` 和 `$rs2` 是输入寄存器。

**用户常见的编程错误（与此文件间接相关）：**

虽然普通 JavaScript 开发者不会直接修改 `code-generator-loong64.cc`，但他们编写的 JavaScript 代码中的某些模式可能会触发代码生成器中的特定路径，从而暴露编译器中的错误或性能问题。 例如：

* **类型不稳定：** 如果一个 JavaScript 函数的参数或变量的类型在不同的调用中发生变化，代码生成器可能需要生成更通用的、性能较低的代码来处理所有可能的情况。 这不是 `code-generator-loong64.cc` 本身的错误，而是 JavaScript 代码的特性影响了代码生成的效果。

```javascript
function calculate(x) {
  return x + 1;
}

console.log(calculate(5));    // x 是 number
console.log(calculate("hello")); // x 是 string，可能导致之前生成的优化代码失效
```

* **过度使用动态特性：**  过度依赖 JavaScript 的动态特性，例如运行时添加属性或使用 `eval()`，可能会使代码生成器难以进行静态分析和优化，导致生成的机器码效率不高。

**总结：**

`v8/src/compiler/backend/loong64/code-generator-loong64.cc` 是 V8 引擎中至关重要的组成部分，它专门负责将高级的 JavaScript 代码转换为能够在 LoongArch 64位架构上高效执行的机器指令。它处理了各种指令类型、函数调用、原子操作以及浮点运算，并且在启用了 WebAssembly 的情况下还支持 WebAssembly 代码的生成。虽然开发者通常不会直接接触这个文件，但它的正确性和效率直接影响着 JavaScript 代码的性能。

Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/code-generator-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/loong64/code-generator-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

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
     
"""


```