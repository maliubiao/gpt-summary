Response: The user wants a summary of the provided C++ code file `v8/src/baseline/baseline-compiler.cc`.
The goal is to understand its functionality, and if it relates to Javascript, provide a Javascript example.

**Plan:**

1. **High-level Overview:** Identify the main purpose of the file based on its name and included headers. It seems to be related to compiling Javascript bytecode to machine code within V8's "baseline" tier.
2. **Key Components:** Look for important classes and methods that reveal the core functionalities. `BaselineCompiler`, `GenerateCode`, `Build`, `Visit...` methods stand out.
3. **Connection to Javascript:** Determine how the compilation process relates to Javascript features. Bytecode processing, handling of different Javascript constructs (like function calls, property access, operators), and built-in functions are likely involved.
4. **Javascript Example (if applicable):** If a connection to Javascript is found, construct a simple Javascript example that demonstrates the code's functionality.
5. **Structure the Summary:** Organize the information logically into a clear and concise summary.
这是一个 C++ 源代码文件，属于 V8 JavaScript 引擎的 baseline 编译器部分。其主要功能是将 JavaScript 字节码编译成本地机器码，以便执行。由于是 baseline 编译器，它的目标是快速生成代码，而不是生成高度优化的代码。

**功能归纳:**

1. **字节码到机器码的转换:** 该文件定义了 `BaselineCompiler` 类，负责遍历输入的 JavaScript 字节码，并为每个字节码生成相应的机器指令。
2. **架构特定的代码生成:** 文件中包含了针对不同 CPU 架构（如 x64, ARM64, IA32 等）的特定实现（通过 `#ifdef V8_TARGET_ARCH_...` 宏）。这意味着 `BaselineCompiler` 会根据目标架构生成不同的机器码。
3. **处理 JavaScript 语言特性:**  文件中大量的 `Visit...` 方法对应着不同的 JavaScript 字节码指令。这些方法负责生成处理各种 JavaScript 语言特性的机器码，例如：
    *   变量的加载和存储 (`Lda...`, `Sta...`)
    *   函数调用 (`Call...`, `Construct...`)
    *   属性访问 (`GetNamedProperty`, `SetKeyedProperty`)
    *   运算符 (`Add`, `Sub`, `TestEqual`)
    *   控制流 (`Jump`, 条件跳转)
    *   内置函数调用 (`CallBuiltin`)
    *   运行时函数调用 (`CallRuntime`)
    *   上下文管理 (`PushContext`, `PopContext`)
4. **使用汇编器:**  `BaselineCompiler` 内部使用了 `BaselineAssembler` 来生成机器指令。`BaselineAssembler` 提供了一组与目标架构相关的汇编指令的抽象。
5. **反馈向量的使用:** 代码中多次出现 "FeedbackVector"，这表明 baseline 编译器会利用反馈向量中的信息，可能用于进行类型推断或优化某些操作。
6. **生成代码对象:**  `Build` 方法负责将生成的机器码封装成一个 `Code` 对象，这个对象可以在 V8 引擎中执行。
7. **支持调试:**  代码中包含一些 `#ifdef DEBUG` 的部分，用于在调试模式下进行额外的检查和验证。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`baseline-compiler.cc` 的核心功能就是将 JavaScript 代码转换成机器可以执行的指令。每一个 `Visit...` 方法都对应着一个或一组 JavaScript 的操作。

例如，`VisitAdd()` 方法对应着 JavaScript 中的加法运算符 `+`。当 JavaScript 引擎遇到加法运算时，会生成相应的字节码，而 baseline 编译器会调用 `VisitAdd()` 方法来生成执行加法的机器码。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3); // 当执行这行代码时，V8 的 baseline 编译器可能会处理 'a + b' 这个加法运算。
```

在这个简单的例子中，当 V8 引擎执行 `add(5, 3)` 时，它会先将 JavaScript 代码解析成字节码。然后，baseline 编译器会遍历这些字节码，当遇到对应 `a + b` 的字节码指令时，`VisitAdd()` 方法（或其他类似的加法处理方法）会被调用，生成底层的机器码来执行实际的加法操作。

再比如，`VisitLdaGlobal()` 方法对应着访问全局变量的操作。

**JavaScript 示例:**

```javascript
console.log("Hello"); // 当访问全局变量 'console' 时，可能会涉及到 VisitLdaGlobal() 的处理。
```

当 V8 执行 `console.log()` 时，访问全局对象 `console` 的过程就可能由 `VisitLdaGlobal()` 方法生成的机器码来完成。

总而言之，`v8/src/baseline/baseline-compiler.cc` 是 V8 引擎中至关重要的一个组件，它负责将高级的 JavaScript 代码翻译成低级的机器指令，使得 JavaScript 代码能够在计算机上运行。虽然它生成的代码不如优化编译器生成的代码效率高，但它的编译速度很快，是 V8 引擎快速启动和执行代码的关键。

### 提示词
```
这是目录为v8/src/baseline/baseline-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/baseline/baseline-compiler.h"

#include <algorithm>
#include <optional>
#include <type_traits>

#include "src/base/bits.h"
#include "src/baseline/baseline-assembler-inl.h"
#include "src/baseline/baseline-assembler.h"
#include "src/builtins/builtins-constructor.h"
#include "src/builtins/builtins-descriptors.h"
#include "src/builtins/builtins.h"
#include "src/codegen/assembler.h"
#include "src/codegen/compiler.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/common/globals.h"
#include "src/execution/frame-constants.h"
#include "src/heap/local-factory-inl.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/code.h"
#include "src/objects/heap-object.h"
#include "src/objects/instance-type.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/roots/roots.h"

#if V8_TARGET_ARCH_X64
#include "src/baseline/x64/baseline-compiler-x64-inl.h"
#elif V8_TARGET_ARCH_ARM64
#include "src/baseline/arm64/baseline-compiler-arm64-inl.h"
#elif V8_TARGET_ARCH_IA32
#include "src/baseline/ia32/baseline-compiler-ia32-inl.h"
#elif V8_TARGET_ARCH_ARM
#include "src/baseline/arm/baseline-compiler-arm-inl.h"
#elif V8_TARGET_ARCH_PPC64
#include "src/baseline/ppc/baseline-compiler-ppc-inl.h"
#elif V8_TARGET_ARCH_S390X
#include "src/baseline/s390/baseline-compiler-s390-inl.h"
#elif V8_TARGET_ARCH_RISCV64
#include "src/baseline/riscv/baseline-compiler-riscv-inl.h"
#elif V8_TARGET_ARCH_RISCV32
#include "src/baseline/riscv/baseline-compiler-riscv-inl.h"
#elif V8_TARGET_ARCH_MIPS64
#include "src/baseline/mips64/baseline-compiler-mips64-inl.h"
#elif V8_TARGET_ARCH_LOONG64
#include "src/baseline/loong64/baseline-compiler-loong64-inl.h"
#else
#error Unsupported target architecture.
#endif

namespace v8 {
namespace internal {
namespace baseline {

#define __ basm_.

#define RCS_BASELINE_SCOPE(rcs)                               \
  RCS_SCOPE(stats_,                                           \
            local_isolate_->is_main_thread()                  \
                ? RuntimeCallCounterId::kCompileBaseline##rcs \
                : RuntimeCallCounterId::kCompileBackgroundBaseline##rcs)

template <typename IsolateT>
Handle<TrustedByteArray> BytecodeOffsetTableBuilder::ToBytecodeOffsetTable(
    IsolateT* isolate) {
  if (bytes_.empty()) return isolate->factory()->empty_trusted_byte_array();
  Handle<TrustedByteArray> table =
      isolate->factory()->NewTrustedByteArray(static_cast<int>(bytes_.size()));
  MemCopy(table->begin(), bytes_.data(), bytes_.size());
  return table;
}

namespace detail {

#ifdef DEBUG
bool Clobbers(Register target, Register reg) { return target == reg; }
bool Clobbers(Register target, DirectHandle<Object> handle) { return false; }
bool Clobbers(Register target, Tagged<Smi> smi) { return false; }
bool Clobbers(Register target, Tagged<TaggedIndex> index) { return false; }
bool Clobbers(Register target, int32_t imm) { return false; }
bool Clobbers(Register target, RootIndex index) { return false; }
bool Clobbers(Register target, interpreter::Register reg) { return false; }
bool Clobbers(Register target, interpreter::RegisterList list) { return false; }

// We don't know what's inside machine registers or operands, so assume they
// match.
bool MachineTypeMatches(MachineType type, Register reg) { return true; }
bool MachineTypeMatches(MachineType type, MemOperand reg) { return true; }
bool MachineTypeMatches(MachineType type, DirectHandle<HeapObject> handle) {
  return type.IsTagged() && !type.IsTaggedSigned();
}
bool MachineTypeMatches(MachineType type, Tagged<Smi> handle) {
  return type.IsTagged() && !type.IsTaggedPointer();
}
bool MachineTypeMatches(MachineType type, Tagged<TaggedIndex> handle) {
  // Tagged<TaggedIndex> doesn't have a separate type, so check for the same
  // type as for Smis.
  return type.IsTagged() && !type.IsTaggedPointer();
}
bool MachineTypeMatches(MachineType type, int32_t imm) {
  // 32-bit immediates can be used for 64-bit params -- they'll be
  // zero-extended.
  return type.representation() == MachineRepresentation::kWord32 ||
         type.representation() == MachineRepresentation::kWord64;
}
bool MachineTypeMatches(MachineType type, RootIndex index) {
  return type.IsTagged() && !type.IsTaggedSigned();
}
bool MachineTypeMatches(MachineType type, interpreter::Register reg) {
  return type.IsTagged();
}

template <typename Descriptor, typename... Args>
struct CheckArgsHelper;

template <typename Descriptor>
struct CheckArgsHelper<Descriptor> {
  static void Check(BaselineAssembler* masm, int i) {
    if (Descriptor::AllowVarArgs()) {
      CHECK_GE(i, Descriptor::GetParameterCount());
    } else {
      CHECK_EQ(i, Descriptor::GetParameterCount());
    }
  }
};

template <typename Descriptor, typename Arg, typename... Args>
struct CheckArgsHelper<Descriptor, Arg, Args...> {
  static void Check(BaselineAssembler* masm, int i, Arg arg, Args... args) {
    if (i >= Descriptor::GetParameterCount()) {
      CHECK(Descriptor::AllowVarArgs());
      return;
    }
    CHECK(MachineTypeMatches(Descriptor().GetParameterType(i), arg));
    CheckArgsHelper<Descriptor, Args...>::Check(masm, i + 1, args...);
  }
};

template <typename Descriptor, typename... Args>
struct CheckArgsHelper<Descriptor, interpreter::RegisterList, Args...> {
  static void Check(BaselineAssembler* masm, int i,
                    interpreter::RegisterList list, Args... args) {
    for (int reg_index = 0; reg_index < list.register_count();
         ++reg_index, ++i) {
      if (i >= Descriptor::GetParameterCount()) {
        CHECK(Descriptor::AllowVarArgs());
        return;
      }
      CHECK(MachineTypeMatches(Descriptor().GetParameterType(i),
                               list[reg_index]));
    }
    CheckArgsHelper<Descriptor, Args...>::Check(masm, i, args...);
  }
};

template <typename Descriptor, typename... Args>
void CheckArgs(BaselineAssembler* masm, Args... args) {
  CheckArgsHelper<Descriptor, Args...>::Check(masm, 0, args...);
}

void CheckSettingDoesntClobber(Register target) {}
template <typename Arg, typename... Args>
void CheckSettingDoesntClobber(Register target, Arg arg, Args... args) {
  DCHECK(!Clobbers(target, arg));
  CheckSettingDoesntClobber(target, args...);
}

#else  // DEBUG

template <typename Descriptor, typename... Args>
void CheckArgs(Args... args) {}

template <typename... Args>
void CheckSettingDoesntClobber(Register target, Args... args) {}

#endif  // DEBUG

template <typename Descriptor, int ArgIndex, bool kIsRegister, typename... Args>
struct ArgumentSettingHelper;

template <typename Descriptor, int ArgIndex, bool kIsRegister>
struct ArgumentSettingHelper<Descriptor, ArgIndex, kIsRegister> {
  static void Set(BaselineAssembler* masm) {
    // Should only ever be called for the end of register arguments.
    static_assert(ArgIndex == Descriptor::GetRegisterParameterCount());
  }
};

template <typename Descriptor, int ArgIndex, typename Arg, typename... Args>
struct ArgumentSettingHelper<Descriptor, ArgIndex, true, Arg, Args...> {
  static void Set(BaselineAssembler* masm, Arg arg, Args... args) {
    static_assert(ArgIndex < Descriptor::GetRegisterParameterCount());
    Register target = Descriptor::GetRegisterParameter(ArgIndex);
    CheckSettingDoesntClobber(target, args...);
    masm->Move(target, arg);
    ArgumentSettingHelper<Descriptor, ArgIndex + 1,
                          (ArgIndex + 1 <
                           Descriptor::GetRegisterParameterCount()),
                          Args...>::Set(masm, args...);
  }
};

template <typename Descriptor, int ArgIndex>
struct ArgumentSettingHelper<Descriptor, ArgIndex, true,
                             interpreter::RegisterList> {
  static void Set(BaselineAssembler* masm, interpreter::RegisterList list) {
    static_assert(ArgIndex < Descriptor::GetRegisterParameterCount());
    DCHECK_EQ(ArgIndex + list.register_count(),
              Descriptor::GetRegisterParameterCount());
    for (int i = 0; ArgIndex + i < Descriptor::GetRegisterParameterCount();
         ++i) {
      Register target = Descriptor::GetRegisterParameter(ArgIndex + i);
      masm->Move(target, masm->RegisterFrameOperand(list[i]));
    }
  }
};

template <typename Descriptor, int ArgIndex, typename Arg, typename... Args>
struct ArgumentSettingHelper<Descriptor, ArgIndex, false, Arg, Args...> {
  static void Set(BaselineAssembler* masm, Arg arg, Args... args) {
    if (Descriptor::kStackArgumentOrder == StackArgumentOrder::kDefault) {
      masm->Push(arg, args...);
    } else {
      masm->PushReverse(arg, args...);
    }
  }
};

template <Builtin kBuiltin, typename... Args>
void MoveArgumentsForBuiltin(BaselineAssembler* masm, Args... args) {
  using Descriptor = typename CallInterfaceDescriptorFor<kBuiltin>::type;
  CheckArgs<Descriptor>(masm, args...);
  ArgumentSettingHelper<Descriptor, 0,
                        (0 < Descriptor::GetRegisterParameterCount()),
                        Args...>::Set(masm, args...);
  if (Descriptor::HasContextParameter()) {
    masm->LoadContext(Descriptor::ContextRegister());
  }
}

}  // namespace detail

namespace {

AssemblerOptions BaselineAssemblerOptions(Isolate* isolate) {
  AssemblerOptions options = AssemblerOptions::Default(isolate);
  options.builtin_call_jump_mode =
      isolate->is_short_builtin_calls_enabled()
          ? BuiltinCallJumpMode::kPCRelative
          : kFallbackBuiltinCallJumpModeForBaseline;
  return options;
}

// Rough upper-bound estimate. Copying the data is most likely more expensive
// than pre-allocating a large enough buffer.
#ifdef V8_TARGET_ARCH_IA32
const int kAverageBytecodeToInstructionRatio = 5;
#else
const int kAverageBytecodeToInstructionRatio = 7;
#endif
std::unique_ptr<AssemblerBuffer> AllocateBuffer(
    DirectHandle<BytecodeArray> bytecodes) {
  int estimated_size;
  {
    DisallowHeapAllocation no_gc;
    estimated_size = BaselineCompiler::EstimateInstructionSize(*bytecodes);
  }
  return NewAssemblerBuffer(RoundUp(estimated_size, 4 * KB));
}
}  // namespace

BaselineCompiler::BaselineCompiler(
    LocalIsolate* local_isolate,
    Handle<SharedFunctionInfo> shared_function_info,
    Handle<BytecodeArray> bytecode)
    : local_isolate_(local_isolate),
      stats_(local_isolate->runtime_call_stats()),
      shared_function_info_(shared_function_info),
      bytecode_(bytecode),
      zone_(local_isolate->allocator(), ZONE_NAME),
      masm_(
          local_isolate->GetMainThreadIsolateUnsafe(), &zone_,
          BaselineAssemblerOptions(local_isolate->GetMainThreadIsolateUnsafe()),
          CodeObjectRequired::kNo, AllocateBuffer(bytecode)),
      basm_(&masm_),
      iterator_(bytecode_),
      labels_(zone_.AllocateArray<Label>(bytecode_->length())),
      label_tags_(2 * bytecode_->length(), &zone_) {
  // Empirically determined expected size of the offset table at the 95th %ile,
  // based on the size of the bytecode, to be:
  //
  //   16 + (bytecode size) / 4
  bytecode_offset_table_builder_.Reserve(
      base::bits::RoundUpToPowerOfTwo(16 + bytecode_->Size() / 4));
}

void BaselineCompiler::GenerateCode() {
  {
    RCS_BASELINE_SCOPE(PreVisit);
    // Mark exception handlers as valid indirect jump targets. This is required
    // when CFI is enabled, to allow indirect jumps into baseline code.
    HandlerTable table(*bytecode_);
    for (int i = 0; i < table.NumberOfRangeEntries(); ++i) {
      MarkIndirectJumpTarget(table.GetRangeHandler(i));
    }
    for (; !iterator_.done(); iterator_.Advance()) {
      PreVisitSingleBytecode();
    }
    iterator_.Reset();
  }

  // No code generated yet.
  DCHECK_EQ(__ pc_offset(), 0);
  __ CodeEntry();

  {
    RCS_BASELINE_SCOPE(Visit);
    Prologue();
    AddPosition();
    for (; !iterator_.done(); iterator_.Advance()) {
      VisitSingleBytecode();
      AddPosition();
    }
  }
}

MaybeHandle<Code> BaselineCompiler::Build() {
  RCS_BASELINE_SCOPE(Build);
  CodeDesc desc;
  __ GetCode(local_isolate_, &desc);

  // Allocate the bytecode offset table.
  Handle<TrustedByteArray> bytecode_offset_table =
      bytecode_offset_table_builder_.ToBytecodeOffsetTable(local_isolate_);

  Factory::CodeBuilder code_builder(local_isolate_, desc, CodeKind::BASELINE);
  code_builder.set_bytecode_offset_table(bytecode_offset_table);
  if (shared_function_info_->HasInterpreterData(local_isolate_)) {
    code_builder.set_interpreter_data(
        handle(shared_function_info_->interpreter_data(local_isolate_),
               local_isolate_));
  } else {
    code_builder.set_interpreter_data(bytecode_);
  }
  code_builder.set_parameter_count(bytecode_->parameter_count());
  return code_builder.TryBuild();
}

int BaselineCompiler::EstimateInstructionSize(Tagged<BytecodeArray> bytecode) {
  return bytecode->length() * kAverageBytecodeToInstructionRatio;
}

interpreter::Register BaselineCompiler::RegisterOperand(int operand_index) {
  return iterator().GetRegisterOperand(operand_index);
}

void BaselineCompiler::LoadRegister(Register output, int operand_index) {
  __ LoadRegister(output, RegisterOperand(operand_index));
}

void BaselineCompiler::StoreRegister(int operand_index, Register value) {
#ifdef DEBUG
  effect_state_.CheckEffect();
#endif
  __ Move(RegisterOperand(operand_index), value);
}

void BaselineCompiler::StoreRegisterPair(int operand_index, Register val0,
                                         Register val1) {
#ifdef DEBUG
  effect_state_.CheckEffect();
#endif
  interpreter::Register reg0, reg1;
  std::tie(reg0, reg1) = iterator().GetRegisterPairOperand(operand_index);
  __ StoreRegister(reg0, val0);
  __ StoreRegister(reg1, val1);
}
template <typename Type>
Handle<Type> BaselineCompiler::Constant(int operand_index) {
  return Cast<Type>(
      iterator().GetConstantForIndexOperand(operand_index, local_isolate_));
}
Tagged<Smi> BaselineCompiler::ConstantSmi(int operand_index) {
  return iterator().GetConstantAtIndexAsSmi(operand_index);
}
template <typename Type>
void BaselineCompiler::LoadConstant(Register output, int operand_index) {
  __ Move(output, Constant<Type>(operand_index));
}
uint32_t BaselineCompiler::Uint(int operand_index) {
  return iterator().GetUnsignedImmediateOperand(operand_index);
}
int32_t BaselineCompiler::Int(int operand_index) {
  return iterator().GetImmediateOperand(operand_index);
}
uint32_t BaselineCompiler::Index(int operand_index) {
  return iterator().GetIndexOperand(operand_index);
}
uint32_t BaselineCompiler::Flag8(int operand_index) {
  return iterator().GetFlag8Operand(operand_index);
}
uint32_t BaselineCompiler::Flag16(int operand_index) {
  return iterator().GetFlag16Operand(operand_index);
}
uint32_t BaselineCompiler::RegisterCount(int operand_index) {
  return iterator().GetRegisterCountOperand(operand_index);
}
Tagged<TaggedIndex> BaselineCompiler::IndexAsTagged(int operand_index) {
  return TaggedIndex::FromIntptr(Index(operand_index));
}
Tagged<TaggedIndex> BaselineCompiler::UintAsTagged(int operand_index) {
  return TaggedIndex::FromIntptr(Uint(operand_index));
}
Tagged<Smi> BaselineCompiler::IndexAsSmi(int operand_index) {
  return Smi::FromInt(Index(operand_index));
}
Tagged<Smi> BaselineCompiler::IntAsSmi(int operand_index) {
  return Smi::FromInt(Int(operand_index));
}
Tagged<Smi> BaselineCompiler::UintAsSmi(int operand_index) {
  return Smi::FromInt(Uint(operand_index));
}
Tagged<Smi> BaselineCompiler::Flag8AsSmi(int operand_index) {
  return Smi::FromInt(Flag8(operand_index));
}
Tagged<Smi> BaselineCompiler::Flag16AsSmi(int operand_index) {
  return Smi::FromInt(Flag16(operand_index));
}

MemOperand BaselineCompiler::FeedbackVector() {
  return __ FeedbackVectorOperand();
}

void BaselineCompiler::LoadFeedbackVector(Register output) {
  ASM_CODE_COMMENT(&masm_);
  __ Move(output, __ FeedbackVectorOperand());
}

void BaselineCompiler::LoadClosureFeedbackArray(Register output) {
  LoadFeedbackVector(output);
  __ LoadTaggedField(output, output,
                     FeedbackVector::kClosureFeedbackCellArrayOffset);
}

void BaselineCompiler::SelectBooleanConstant(
    Register output, std::function<void(Label*, Label::Distance)> jump_func) {
  Label done, set_true;
  jump_func(&set_true, Label::kNear);
  __ LoadRoot(output, RootIndex::kFalseValue);
  __ Jump(&done, Label::kNear);
  __ Bind(&set_true);
  __ LoadRoot(output, RootIndex::kTrueValue);
  __ Bind(&done);
}

void BaselineCompiler::AddPosition() {
  bytecode_offset_table_builder_.AddPosition(__ pc_offset());
}

void BaselineCompiler::PreVisitSingleBytecode() {
  switch (iterator().current_bytecode()) {
    case interpreter::Bytecode::kJumpLoop:
      EnsureLabel(iterator().GetJumpTargetOffset(),
                  MarkAsIndirectJumpTarget::kYes);
      break;
    default:
      break;
  }
}

void BaselineCompiler::VisitSingleBytecode() {
#ifdef DEBUG
  effect_state_.clear();
#endif
  int offset = iterator().current_offset();
  if (IsJumpTarget(offset)) __ Bind(&labels_[offset]);
  // Mark position as valid jump target unconditionnaly when the deoptimizer can
  // jump to baseline code. This is required when CFI is enabled.
  if (v8_flags.deopt_to_baseline || IsIndirectJumpTarget(offset)) {
    __ JumpTarget();
  }

  ASM_CODE_COMMENT_STRING(&masm_, [&]() {
    std::ostringstream str;
    iterator().PrintTo(str);
    return str.str();
  });

  VerifyFrame();

#ifdef V8_TRACE_UNOPTIMIZED
  TraceBytecode(Runtime::kTraceUnoptimizedBytecodeEntry);
#endif

  {
    interpreter::Bytecode bytecode = iterator().current_bytecode();

#ifdef DEBUG
    std::optional<EnsureAccumulatorPreservedScope> accumulator_preserved_scope;
    // We should make sure to preserve the accumulator whenever the bytecode
    // isn't registered as writing to it. We can't do this for jumps or switches
    // though, since the control flow would not match the control flow of this
    // scope.
    if (v8_flags.debug_code &&
        !interpreter::Bytecodes::WritesOrClobbersAccumulator(bytecode) &&
        !interpreter::Bytecodes::IsJump(bytecode) &&
        !interpreter::Bytecodes::IsSwitch(bytecode)) {
      accumulator_preserved_scope.emplace(&basm_);
    }
#endif  // DEBUG

    switch (bytecode) {
#define BYTECODE_CASE(name, ...)       \
  case interpreter::Bytecode::k##name: \
    Visit##name();                     \
    break;
      BYTECODE_LIST(BYTECODE_CASE, BYTECODE_CASE)
#undef BYTECODE_CASE
    }
  }

#ifdef V8_TRACE_UNOPTIMIZED
  TraceBytecode(Runtime::kTraceUnoptimizedBytecodeExit);
#endif
}

void BaselineCompiler::VerifyFrame() {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(&masm_);
    __ RecordComment(" -- Verify frame size");
    VerifyFrameSize();

    __ RecordComment(" -- Verify feedback vector");
    {
      BaselineAssembler::ScratchRegisterScope temps(&basm_);
      Register scratch = temps.AcquireScratch();
      __ Move(scratch, __ FeedbackVectorOperand());
      Label is_smi, is_ok;
      __ JumpIfSmi(scratch, &is_smi);
      __ JumpIfObjectTypeFast(kEqual, scratch, FEEDBACK_VECTOR_TYPE, &is_ok);
      __ Bind(&is_smi);
      __ masm()->Abort(AbortReason::kExpectedFeedbackVector);
      __ Bind(&is_ok);
    }

    // TODO(leszeks): More verification.
  }
}

#ifdef V8_TRACE_UNOPTIMIZED
void BaselineCompiler::TraceBytecode(Runtime::FunctionId function_id) {
  if (!v8_flags.trace_baseline_exec) return;
  ASM_CODE_COMMENT_STRING(&masm_,
                          function_id == Runtime::kTraceUnoptimizedBytecodeEntry
                              ? "Trace bytecode entry"
                              : "Trace bytecode exit");
  SaveAccumulatorScope accumulator_scope(this, &basm_);
  CallRuntime(function_id, bytecode_,
              Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                           iterator().current_offset()),
              kInterpreterAccumulatorRegister);
}
#endif

#define DECLARE_VISITOR(name, ...) void Visit##name();
BYTECODE_LIST(DECLARE_VISITOR, DECLARE_VISITOR)
#undef DECLARE_VISITOR

#define DECLARE_VISITOR(name, ...) \
  void VisitIntrinsic##name(interpreter::RegisterList args);
INTRINSICS_LIST(DECLARE_VISITOR)
#undef DECLARE_VISITOR

void BaselineCompiler::UpdateInterruptBudgetAndJumpToLabel(
    int weight, Label* label, Label* skip_interrupt_label,
    StackCheckBehavior stack_check_behavior) {
  if (weight != 0) {
    ASM_CODE_COMMENT(&masm_);
    __ AddToInterruptBudgetAndJumpIfNotExceeded(weight, skip_interrupt_label);

    DCHECK_LT(weight, 0);
    CallRuntime(stack_check_behavior == kEnableStackCheck
                    ? Runtime::kBytecodeBudgetInterruptWithStackCheck_Sparkplug
                    : Runtime::kBytecodeBudgetInterrupt_Sparkplug,
                __ FunctionOperand());
  }
  if (label) __ Jump(label);
}

void BaselineCompiler::JumpIfRoot(RootIndex root) {
  Label dont_jump;
  __ JumpIfNotRoot(kInterpreterAccumulatorRegister, root, &dont_jump,
                   Label::kNear);
  __ Jump(BuildForwardJumpLabel());
  __ Bind(&dont_jump);
}

void BaselineCompiler::JumpIfNotRoot(RootIndex root) {
  Label dont_jump;
  __ JumpIfRoot(kInterpreterAccumulatorRegister, root, &dont_jump,
                Label::kNear);
  __ Jump(BuildForwardJumpLabel());
  __ Bind(&dont_jump);
}

Label* BaselineCompiler::BuildForwardJumpLabel() {
  int target_offset = iterator().GetJumpTargetOffset();
  return EnsureLabel(target_offset);
}

#ifdef DEBUG
// Allowlist to mark builtin calls during which it is impossible that the
// sparkplug frame would have to be deoptimized. Either because they don't
// execute any user code, or because they would anyway replace the current
// frame, e.g., due to OSR.
constexpr static bool BuiltinMayDeopt(Builtin id) {
  switch (id) {
    case Builtin::kSuspendGeneratorBaseline:
    case Builtin::kBaselineOutOfLinePrologue:
    case Builtin::kIncBlockCounter:
    case Builtin::kToObject:
    case Builtin::kStoreScriptContextSlotBaseline:
    case Builtin::kStoreCurrentScriptContextSlotBaseline:
    // This one explicitly skips the construct if the debugger is enabled.
    case Builtin::kFindNonDefaultConstructorOrConstruct:
      return false;
    default:
      return true;
  }
}
#endif  // DEBUG

template <Builtin kBuiltin, typename... Args>
void BaselineCompiler::CallBuiltin(Args... args) {
#ifdef DEBUG
  effect_state_.CheckEffect();
  if (BuiltinMayDeopt(kBuiltin)) {
    effect_state_.MayDeopt();
  }
#endif
  ASM_CODE_COMMENT(&masm_);
  detail::MoveArgumentsForBuiltin<kBuiltin>(&basm_, args...);
  __ CallBuiltin(kBuiltin);
}

template <Builtin kBuiltin, typename... Args>
void BaselineCompiler::TailCallBuiltin(Args... args) {
#ifdef DEBUG
  effect_state_.CheckEffect();
#endif
  detail::MoveArgumentsForBuiltin<kBuiltin>(&basm_, args...);
  __ TailCallBuiltin(kBuiltin);
}

template <typename... Args>
void BaselineCompiler::CallRuntime(Runtime::FunctionId function, Args... args) {
#ifdef DEBUG
  effect_state_.CheckEffect();
  effect_state_.MayDeopt();
#endif
  __ LoadContext(kContextRegister);
  int nargs = __ Push(args...);
  __ CallRuntime(function, nargs);
}

// Returns into kInterpreterAccumulatorRegister
void BaselineCompiler::JumpIfToBoolean(bool do_jump_if_true, Label* label,
                                       Label::Distance distance) {
  CallBuiltin<Builtin::kToBooleanForBaselineJump>(
      kInterpreterAccumulatorRegister);
  // ToBooleanForBaselineJump returns the ToBoolean value into return reg 1, and
  // the original value into kInterpreterAccumulatorRegister, so we don't have
  // to worry about it getting clobbered.
  static_assert(kReturnRegister0 == kInterpreterAccumulatorRegister);
  __ JumpIfSmi(do_jump_if_true ? kNotEqual : kEqual, kReturnRegister1,
               Smi::FromInt(0), label, distance);
}

void BaselineCompiler::VisitLdaZero() {
  __ Move(kInterpreterAccumulatorRegister, Smi::FromInt(0));
}

void BaselineCompiler::VisitLdaSmi() {
  Tagged<Smi> constant = Smi::FromInt(iterator().GetImmediateOperand(0));
  __ Move(kInterpreterAccumulatorRegister, constant);
}

void BaselineCompiler::VisitLdaUndefined() {
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
}

void BaselineCompiler::VisitLdaNull() {
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kNullValue);
}

void BaselineCompiler::VisitLdaTheHole() {
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTheHoleValue);
}

void BaselineCompiler::VisitLdaTrue() {
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
}

void BaselineCompiler::VisitLdaFalse() {
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
}

void BaselineCompiler::VisitLdaConstant() {
  LoadConstant<HeapObject>(kInterpreterAccumulatorRegister, 0);
}

void BaselineCompiler::VisitLdaGlobal() {
  CallBuiltin<Builtin::kLoadGlobalICBaseline>(Constant<Name>(0),  // name
                                              IndexAsTagged(1));  // slot
}

void BaselineCompiler::VisitLdaGlobalInsideTypeof() {
  CallBuiltin<Builtin::kLoadGlobalICInsideTypeofBaseline>(
      Constant<Name>(0),  // name
      IndexAsTagged(1));  // slot
}

void BaselineCompiler::VisitStaGlobal() {
  CallBuiltin<Builtin::kStoreGlobalICBaseline>(
      Constant<Name>(0),                // name
      kInterpreterAccumulatorRegister,  // value
      IndexAsTagged(1));                // slot
}

void BaselineCompiler::VisitPushContext() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  __ LoadContext(context);
  __ StoreContext(kInterpreterAccumulatorRegister);
  StoreRegister(0, context);
}

void BaselineCompiler::VisitPopContext() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  LoadRegister(context, 0);
  __ StoreContext(context);
}

void BaselineCompiler::VisitLdaContextSlot() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  LoadRegister(context, 0);
  uint32_t index = Index(1);
  uint32_t depth = Uint(2);
  __ LdaContextSlot(context, index, depth);
}

void BaselineCompiler::VisitLdaScriptContextSlot() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  Label done;
  LoadRegister(context, 0);
  uint32_t index = Index(1);
  uint32_t depth = Uint(2);
  __ LdaContextSlot(context, index, depth,
                    BaselineAssembler::CompressionMode::kForceDecompression);
  __ JumpIfSmi(kInterpreterAccumulatorRegister, &done);
  __ JumpIfObjectTypeFast(kNotEqual, kInterpreterAccumulatorRegister,
                          HEAP_NUMBER_TYPE, &done, Label::kNear);
  CallBuiltin<Builtin::kAllocateIfMutableHeapNumberScriptContextSlot>(
      kInterpreterAccumulatorRegister,  // heap number
      context,                          // context
      Smi::FromInt(index));             // slot
  __ Bind(&done);
}

void BaselineCompiler::VisitLdaImmutableContextSlot() { VisitLdaContextSlot(); }

void BaselineCompiler::VisitLdaCurrentContextSlot() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  __ LoadContext(context);
  __ LoadTaggedField(kInterpreterAccumulatorRegister, context,
                     Context::OffsetOfElementAt(Index(0)));
}

void BaselineCompiler::VisitLdaCurrentScriptContextSlot() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register context = scratch_scope.AcquireScratch();
  Label done;
  uint32_t index = Index(0);
  __ LoadContext(context);
  __ LoadTaggedField(kInterpreterAccumulatorRegister, context,
                     Context::OffsetOfElementAt(index));
  __ JumpIfSmi(kInterpreterAccumulatorRegister, &done);
  __ JumpIfObjectTypeFast(kNotEqual, kInterpreterAccumulatorRegister,
                          HEAP_NUMBER_TYPE, &done, Label::kNear);
  CallBuiltin<Builtin::kAllocateIfMutableHeapNumberScriptContextSlot>(
      kInterpreterAccumulatorRegister,  // heap number
      context,                          // context
      Smi::FromInt(index));             // slot
  __ Bind(&done);
}

void BaselineCompiler::VisitLdaImmutableCurrentContextSlot() {
  VisitLdaCurrentContextSlot();
}

void BaselineCompiler::VisitStaContextSlot() {
  Register value = WriteBarrierDescriptor::ValueRegister();
  Register context = WriteBarrierDescriptor::ObjectRegister();
  DCHECK(!AreAliased(value, context, kInterpreterAccumulatorRegister));
  __ Move(value, kInterpreterAccumulatorRegister);
  LoadRegister(context, 0);
  uint32_t index = Index(1);
  uint32_t depth = Uint(2);
  __ StaContextSlot(context, value, index, depth);
}

void BaselineCompiler::VisitStaCurrentContextSlot() {
  Register value = WriteBarrierDescriptor::ValueRegister();
  Register context = WriteBarrierDescriptor::ObjectRegister();
  DCHECK(!AreAliased(value, context, kInterpreterAccumulatorRegister));
  __ Move(value, kInterpreterAccumulatorRegister);
  __ LoadContext(context);
  __ StoreTaggedFieldWithWriteBarrier(
      context, Context::OffsetOfElementAt(Index(0)), value);
}

void BaselineCompiler::VisitStaScriptContextSlot() {
  Register value = WriteBarrierDescriptor::ValueRegister();
  Register context = WriteBarrierDescriptor::ObjectRegister();
  DCHECK(!AreAliased(value, context, kInterpreterAccumulatorRegister));
  __ Move(value, kInterpreterAccumulatorRegister);
  LoadRegister(context, 0);
  SaveAccumulatorScope accumulator_scope(this, &basm_);
  CallBuiltin<Builtin::kStoreScriptContextSlotBaseline>(
      context,           // context
      value,             // value
      IndexAsSmi(1),     // slot
      UintAsTagged(2));  // depth
}

void BaselineCompiler::VisitStaCurrentScriptContextSlot() {
  Register value = WriteBarrierDescriptor::ValueRegister();
  DCHECK(!AreAliased(value, kInterpreterAccumulatorRegister));
  SaveAccumulatorScope accumulator_scope(this, &basm_);
  __ Move(value, kInterpreterAccumulatorRegister);
  CallBuiltin<Builtin::kStoreCurrentScriptContextSlotBaseline>(
      value,           // value
      IndexAsSmi(0));  // slot
}

void BaselineCompiler::VisitLdaLookupSlot() {
  CallRuntime(Runtime::kLoadLookupSlot, Constant<Name>(0));
}

void BaselineCompiler::VisitLdaLookupContextSlot() {
  CallBuiltin<Builtin::kLookupContextBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitLdaLookupScriptContextSlot() {
  CallBuiltin<Builtin::kLookupScriptContextBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitLdaLookupGlobalSlot() {
  CallBuiltin<Builtin::kLookupGlobalICBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitLdaLookupSlotInsideTypeof() {
  CallRuntime(Runtime::kLoadLookupSlotInsideTypeof, Constant<Name>(0));
}

void BaselineCompiler::VisitLdaLookupContextSlotInsideTypeof() {
  CallBuiltin<Builtin::kLookupContextInsideTypeofBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitLdaLookupScriptContextSlotInsideTypeof() {
  CallBuiltin<Builtin::kLookupScriptContextInsideTypeofBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitLdaLookupGlobalSlotInsideTypeof() {
  CallBuiltin<Builtin::kLookupGlobalICInsideTypeofBaseline>(
      Constant<Name>(0), UintAsTagged(2), IndexAsTagged(1));
}

void BaselineCompiler::VisitStaLookupSlot() {
  uint32_t flags = Flag8(1);
  Runtime::FunctionId function_id;
  if (flags & interpreter::StoreLookupSlotFlags::LanguageModeBit::kMask) {
    function_id = Runtime::kStoreLookupSlot_Strict;
  } else if (flags &
             interpreter::StoreLookupSlotFlags::LookupHoistingModeBit::kMask) {
    function_id = Runtime::kStoreLookupSlot_SloppyHoisting;
  } else {
    function_id = Runtime::kStoreLookupSlot_Sloppy;
  }
  CallRuntime(function_id, Constant<Name>(0),    // name
              kInterpreterAccumulatorRegister);  // value
}

void BaselineCompiler::VisitLdar() {
  LoadRegister(kInterpreterAccumulatorRegister, 0);
}

void BaselineCompiler::VisitStar() {
  StoreRegister(0, kInterpreterAccumulatorRegister);
}

#define SHORT_STAR_VISITOR(Name, ...)                                         \
  void BaselineCompiler::Visit##Name() {                                      \
    __ StoreRegister(                                                         \
        interpreter::Register::FromShortStar(interpreter::Bytecode::k##Name), \
        kInterpreterAccumulatorRegister);                                     \
  }
SHORT_STAR_BYTECODE_LIST(SHORT_STAR_VISITOR)
#undef SHORT_STAR_VISITOR

void BaselineCompiler::VisitMov() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register scratch = scratch_scope.AcquireScratch();
  LoadRegister(scratch, 0);
  StoreRegister(1, scratch);
}

void BaselineCompiler::VisitGetNamedProperty() {
  CallBuiltin<Builtin::kLoadICBaseline>(RegisterOperand(0),  // object
                                        Constant<Name>(1),   // name
                                        IndexAsTagged(2));   // slot
}

void BaselineCompiler::VisitGetNamedPropertyFromSuper() {
  __ LoadPrototype(
      LoadWithReceiverAndVectorDescriptor::LookupStartObjectRegister(),
      kInterpreterAccumulatorRegister);

  CallBuiltin<Builtin::kLoadSuperICBaseline>(
      RegisterOperand(0),  // object
      LoadWithReceiverAndVectorDescriptor::
          LookupStartObjectRegister(),  // lookup start
      Constant<Name>(1),                // name
      IndexAsTagged(2));                // slot
}

void BaselineCompiler::VisitGetKeyedProperty() {
  CallBuiltin<Builtin::kKeyedLoadICBaseline>(
      RegisterOperand(0),               // object
      kInterpreterAccumulatorRegister,  // key
      IndexAsTagged(1));                // slot
}

void BaselineCompiler::VisitGetEnumeratedKeyedProperty() {
  DCHECK(v8_flags.enable_enumerated_keyed_access_bytecode);
  CallBuiltin<Builtin::kEnumeratedKeyedLoadICBaseline>(
      RegisterOperand(0),               // object
      kInterpreterAccumulatorRegister,  // key
      RegisterOperand(1),               // enum index
      RegisterOperand(2),               // cache type
      IndexAsTagged(3));                // slot
}

void BaselineCompiler::VisitLdaModuleVariable() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register scratch = scratch_scope.AcquireScratch();
  __ LoadContext(scratch);
  int cell_index = Int(0);
  int depth = Uint(1);
  __ LdaModuleVariable(scratch, cell_index, depth);
}

void BaselineCompiler::VisitStaModuleVariable() {
  int cell_index = Int(0);
  if (V8_UNLIKELY(cell_index < 0)) {
    // Not supported (probably never).
    CallRuntime(Runtime::kAbort,
                Smi::FromInt(static_cast<int>(
                    AbortReason::kUnsupportedModuleOperation)));
    __ Trap();
  }
  Register value = WriteBarrierDescriptor::ValueRegister();
  Register scratch = WriteBarrierDescriptor::ObjectRegister();
  DCHECK(!AreAliased(value, scratch, kInterpreterAccumulatorRegister));
  __ Move(value, kInterpreterAccumulatorRegister);
  __ LoadContext(scratch);
  int depth = Uint(1);
  __ StaModuleVariable(scratch, value, cell_index, depth);
}

void BaselineCompiler::VisitSetNamedProperty() {
  // StoreIC is currently a base class for multiple property store operations
  // and contains mixed logic for named and keyed, set and define operations,
  // the paths are controlled by feedback.
  // TODO(v8:12548): refactor SetNamedIC as a subclass of StoreIC, which can be
  // called here.
  CallBuiltin<Builtin::kStoreICBaseline>(
      RegisterOperand(0),               // object
      Constant<Name>(1),                // name
      kInterpreterAccumulatorRegister,  // value
      IndexAsTagged(2));                // slot
}

void BaselineCompiler::VisitDefineNamedOwnProperty() {
  CallBuiltin<Builtin::kDefineNamedOwnICBaseline>(
      RegisterOperand(0),               // object
      Constant<Name>(1),                // name
      kInterpreterAccumulatorRegister,  // value
      IndexAsTagged(2));                // slot
}

void BaselineCompiler::VisitSetKeyedProperty() {
  // KeyedStoreIC is currently a base class for multiple keyed property store
  // operations and contains mixed logic for set and define operations,
  // the paths are controlled by feedback.
  // TODO(v8:12548): refactor SetKeyedIC as a subclass of KeyedStoreIC, which
  // can be called here.
  CallBuiltin<Builtin::kKeyedStoreICBaseline>(
      RegisterOperand(0),               // object
      RegisterOperand(1),               // key
      kInterpreterAccumulatorRegister,  // value
      IndexAsTagged(2));                // slot
}

void BaselineCompiler::VisitDefineKeyedOwnProperty() {
  CallBuiltin<Builtin::kDefineKeyedOwnICBaseline>(
      RegisterOperand(0),               // object
      RegisterOperand(1),               // key
      kInterpreterAccumulatorRegister,  // value
      Flag8AsSmi(2),                    // flags
      IndexAsTagged(3));                // slot
}

void BaselineCompiler::VisitStaInArrayLiteral() {
  CallBuiltin<Builtin::kStoreInArrayLiteralICBaseline>(
      RegisterOperand(0),               // object
      RegisterOperand(1),               // name
      kInterpreterAccumulatorRegister,  // value
      IndexAsTagged(2));                // slot
}

void BaselineCompiler::VisitDefineKeyedOwnPropertyInLiteral() {
  // Here we should save the accumulator, since
  // DefineKeyedOwnPropertyInLiteral doesn't write the accumulator, but
  // Runtime::kDefineKeyedOwnPropertyInLiteral returns the value that we got
  // from the accumulator so this still works.
  CallRuntime(Runtime::kDefineKeyedOwnPropertyInLiteral,
              RegisterOperand(0),               // object
              RegisterOperand(1),               // name
              kInterpreterAccumulatorRegister,  // value
              Flag8AsSmi(2),                    // flags
              FeedbackVector(),                 // feedback vector
              IndexAsTagged(3));                // slot
}

void BaselineCompiler::VisitAdd() {
  CallBuiltin<Builtin::kAdd_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitSub() {
  CallBuiltin<Builtin::kSubtract_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitMul() {
  CallBuiltin<Builtin::kMultiply_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitDiv() {
  CallBuiltin<Builtin::kDivide_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitMod() {
  CallBuiltin<Builtin::kModulus_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitExp() {
  CallBuiltin<Builtin::kExponentiate_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitBitwiseOr() {
  CallBuiltin<Builtin::kBitwiseOr_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitBitwiseXor() {
  CallBuiltin<Builtin::kBitwiseXor_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitBitwiseAnd() {
  CallBuiltin<Builtin::kBitwiseAnd_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitShiftLeft() {
  CallBuiltin<Builtin::kShiftLeft_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitShiftRight() {
  CallBuiltin<Builtin::kShiftRight_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitShiftRightLogical() {
  CallBuiltin<Builtin::kShiftRightLogical_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitAddSmi() {
  CallBuiltin<Builtin::kAddSmi_Baseline>(kInterpreterAccumulatorRegister,
                                         IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitSubSmi() {
  CallBuiltin<Builtin::kSubtractSmi_Baseline>(kInterpreterAccumulatorRegister,
                                              IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitMulSmi() {
  CallBuiltin<Builtin::kMultiplySmi_Baseline>(kInterpreterAccumulatorRegister,
                                              IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitDivSmi() {
  CallBuiltin<Builtin::kDivideSmi_Baseline>(kInterpreterAccumulatorRegister,
                                            IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitModSmi() {
  CallBuiltin<Builtin::kModulusSmi_Baseline>(kInterpreterAccumulatorRegister,
                                             IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitExpSmi() {
  CallBuiltin<Builtin::kExponentiateSmi_Baseline>(
      kInterpreterAccumulatorRegister, IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitBitwiseOrSmi() {
  CallBuiltin<Builtin::kBitwiseOrSmi_Baseline>(kInterpreterAccumulatorRegister,
                                               IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitBitwiseXorSmi() {
  CallBuiltin<Builtin::kBitwiseXorSmi_Baseline>(kInterpreterAccumulatorRegister,
                                                IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitBitwiseAndSmi() {
  CallBuiltin<Builtin::kBitwiseAndSmi_Baseline>(kInterpreterAccumulatorRegister,
                                                IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitShiftLeftSmi() {
  CallBuiltin<Builtin::kShiftLeftSmi_Baseline>(kInterpreterAccumulatorRegister,
                                               IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitShiftRightSmi() {
  CallBuiltin<Builtin::kShiftRightSmi_Baseline>(kInterpreterAccumulatorRegister,
                                                IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitShiftRightLogicalSmi() {
  CallBuiltin<Builtin::kShiftRightLogicalSmi_Baseline>(
      kInterpreterAccumulatorRegister, IntAsSmi(0), Index(1));
}

void BaselineCompiler::VisitInc() {
  CallBuiltin<Builtin::kIncrement_Baseline>(kInterpreterAccumulatorRegister,
                                            Index(0));
}

void BaselineCompiler::VisitDec() {
  CallBuiltin<Builtin::kDecrement_Baseline>(kInterpreterAccumulatorRegister,
                                            Index(0));
}

void BaselineCompiler::VisitNegate() {
  CallBuiltin<Builtin::kNegate_Baseline>(kInterpreterAccumulatorRegister,
                                         Index(0));
}

void BaselineCompiler::VisitBitwiseNot() {
  CallBuiltin<Builtin::kBitwiseNot_Baseline>(kInterpreterAccumulatorRegister,
                                             Index(0));
}

void BaselineCompiler::VisitToBooleanLogicalNot() {
  SelectBooleanConstant(kInterpreterAccumulatorRegister,
                        [&](Label* if_true, Label::Distance distance) {
                          JumpIfToBoolean(false, if_true, distance);
                        });
}

void BaselineCompiler::VisitLogicalNot() {
  SelectBooleanConstant(kInterpreterAccumulatorRegister,
                        [&](Label* if_true, Label::Distance distance) {
                          __ JumpIfRoot(kInterpreterAccumulatorRegister,
                                        RootIndex::kFalseValue, if_true,
                                        distance);
                        });
}

void BaselineCompiler::VisitTypeOf() {
  CallBuiltin<Builtin::kTypeof_Baseline>(kInterpreterAccumulatorRegister,
                                         Index(0));
}

void BaselineCompiler::VisitDeletePropertyStrict() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register scratch = scratch_scope.AcquireScratch();
  __ Move(scratch, kInterpreterAccumulatorRegister);
  CallBuiltin<Builtin::kDeleteProperty>(RegisterOperand(0), scratch,
                                        Smi::FromEnum(LanguageMode::kStrict));
}

void BaselineCompiler::VisitDeletePropertySloppy() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register scratch = scratch_scope.AcquireScratch();
  __ Move(scratch, kInterpreterAccumulatorRegister);
  CallBuiltin<Builtin::kDeleteProperty>(RegisterOperand(0), scratch,
                                        Smi::FromEnum(LanguageMode::kSloppy));
}

void BaselineCompiler::VisitGetSuperConstructor() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register prototype = scratch_scope.AcquireScratch();
  __ LoadPrototype(prototype, kInterpreterAccumulatorRegister);
  StoreRegister(0, prototype);
}

void BaselineCompiler::VisitFindNonDefaultConstructorOrConstruct() {
  SaveAccumulatorScope accumulator_scope(this, &basm_);
  CallBuiltin<Builtin::kFindNonDefaultConstructorOrConstruct>(
      RegisterOperand(0), RegisterOperand(1));
  StoreRegisterPair(2, kReturnRegister0, kReturnRegister1);
}

namespace {
constexpr Builtin ConvertReceiverModeToCompactBuiltin(
    ConvertReceiverMode mode) {
  switch (mode) {
    case ConvertReceiverMode::kAny:
      return Builtin::kCall_ReceiverIsAny_Baseline_Compact;
    case ConvertReceiverMode::kNullOrUndefined:
      return Builtin::kCall_ReceiverIsNullOrUndefined_Baseline_Compact;
    case ConvertReceiverMode::kNotNullOrUndefined:
      return Builtin::kCall_ReceiverIsNotNullOrUndefined_Baseline_Compact;
  }
}
constexpr Builtin ConvertReceiverModeToBuiltin(ConvertReceiverMode mode) {
  switch (mode) {
    case ConvertReceiverMode::kAny:
      return Builtin::kCall_ReceiverIsAny_Baseline;
    case ConvertReceiverMode::kNullOrUndefined:
      return Builtin::kCall_ReceiverIsNullOrUndefined_Baseline;
    case ConvertReceiverMode::kNotNullOrUndefined:
      return Builtin::kCall_ReceiverIsNotNullOrUndefined_Baseline;
  }
}
}  // namespace

template <ConvertReceiverMode kMode, typename... Args>
void BaselineCompiler::BuildCall(uint32_t slot, uint32_t arg_count,
                                 Args... args) {
  uint32_t bitfield;
  if (CallTrampoline_Baseline_CompactDescriptor::EncodeBitField(arg_count, slot,
                                                                &bitfield)) {
    CallBuiltin<ConvertReceiverModeToCompactBuiltin(kMode)>(
        RegisterOperand(0),  // kFunction
        bitfield,            // kActualArgumentsCount | kSlot
        args...);            // Arguments
  } else {
    CallBuiltin<ConvertReceiverModeToBuiltin(kMode)>(
        RegisterOperand(0),  // kFunction
        arg_count,           // kActualArgumentsCount
        slot,                // kSlot
        args...);            // Arguments
  }
}

void BaselineCompiler::VisitCallAnyReceiver() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  uint32_t arg_count = args.register_count();
  BuildCall<ConvertReceiverMode::kAny>(Index(3), arg_count, args);
}

void BaselineCompiler::VisitCallProperty() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  uint32_t arg_count = args.register_count();
  BuildCall<ConvertReceiverMode::kNotNullOrUndefined>(Index(3), arg_count,
                                                      args);
}

void BaselineCompiler::VisitCallProperty0() {
  BuildCall<ConvertReceiverMode::kNotNullOrUndefined>(
      Index(2), JSParameterCount(0), RegisterOperand(1));
}

void BaselineCompiler::VisitCallProperty1() {
  BuildCall<ConvertReceiverMode::kNotNullOrUndefined>(
      Index(3), JSParameterCount(1), RegisterOperand(1), RegisterOperand(2));
}

void BaselineCompiler::VisitCallProperty2() {
  BuildCall<ConvertReceiverMode::kNotNullOrUndefined>(
      Index(4), JSParameterCount(2), RegisterOperand(1), RegisterOperand(2),
      RegisterOperand(3));
}

void BaselineCompiler::VisitCallUndefinedReceiver() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  uint32_t arg_count = JSParameterCount(args.register_count());
  BuildCall<ConvertReceiverMode::kNullOrUndefined>(
      Index(3), arg_count, RootIndex::kUndefinedValue, args);
}

void BaselineCompiler::VisitCallUndefinedReceiver0() {
  BuildCall<ConvertReceiverMode::kNullOrUndefined>(
      Index(1), JSParameterCount(0), RootIndex::kUndefinedValue);
}

void BaselineCompiler::VisitCallUndefinedReceiver1() {
  BuildCall<ConvertReceiverMode::kNullOrUndefined>(
      Index(2), JSParameterCount(1), RootIndex::kUndefinedValue,
      RegisterOperand(1));
}

void BaselineCompiler::VisitCallUndefinedReceiver2() {
  BuildCall<ConvertReceiverMode::kNullOrUndefined>(
      Index(3), JSParameterCount(2), RootIndex::kUndefinedValue,
      RegisterOperand(1), RegisterOperand(2));
}

void BaselineCompiler::VisitCallWithSpread() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);

  // Do not push the spread argument
  interpreter::Register spread_register = args.last_register();
  args = args.Truncate(args.register_count() - 1);

  uint32_t arg_count = args.register_count();

  CallBuiltin<Builtin::kCallWithSpread_Baseline>(
      RegisterOperand(0),  // kFunction
      arg_count,           // kActualArgumentsCount
      spread_register,     // kSpread
      Index(3),            // kSlot
      args);
}

void BaselineCompiler::VisitCallRuntime() {
  CallRuntime(iterator().GetRuntimeIdOperand(0),
              iterator().GetRegisterListOperand(1));
}

void BaselineCompiler::VisitCallRuntimeForPair() {
  auto builtin = iterator().GetRuntimeIdOperand(0);
  switch (builtin) {
    case Runtime::kLoadLookupSlotForCall: {
      // TODO(olivf) Once we have more builtins to support here we should find
      // out how to do this generically.
      auto in = iterator().GetRegisterListOperand(1);
      auto out = iterator().GetRegisterPairOperand(3);
      BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
      Register out_reg = scratch_scope.AcquireScratch();
      __ RegisterFrameAddress(out.first, out_reg);
      DCHECK_EQ(in.register_count(), 1);
      CallRuntime(Runtime::kLoadLookupSlotForCall_Baseline, in.first_register(),
                  out_reg);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void BaselineCompiler::VisitCallJSRuntime() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  uint32_t arg_count = JSParameterCount(args.register_count());

  // Load context for LoadNativeContextSlot.
  __ LoadContext(kContextRegister);
  __ LoadNativeContextSlot(kJavaScriptCallTargetRegister,
                           iterator().GetNativeContextIndexOperand(0));
  CallBuiltin<Builtin::kCall_ReceiverIsNullOrUndefined>(
      kJavaScriptCallTargetRegister,  // kFunction
      arg_count,                      // kActualArgumentsCount
      RootIndex::kUndefinedValue,     // kReceiver
      args);
}

void BaselineCompiler::VisitInvokeIntrinsic() {
  Runtime::FunctionId intrinsic_id = iterator().GetIntrinsicIdOperand(0);
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  switch (intrinsic_id) {
#define CASE(Name, ...)         \
  case Runtime::kInline##Name:  \
    VisitIntrinsic##Name(args); \
    break;
    INTRINSICS_LIST(CASE)
#undef CASE

    default:
      UNREACHABLE();
  }
}

void BaselineCompiler::VisitIntrinsicCopyDataProperties(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kCopyDataProperties>(args);
}

void BaselineCompiler::
    VisitIntrinsicCopyDataPropertiesWithExcludedPropertiesOnStack(
        interpreter::RegisterList args) {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register rscratch = scratch_scope.AcquireScratch();
  // Use an offset from args[0] instead of args[1] to pass a valid "end of"
  // pointer in the case where args.register_count() == 1.
  basm_.RegisterFrameAddress(interpreter::Register(args[0].index() + 1),
                             rscratch);
  CallBuiltin<Builtin::kCopyDataPropertiesWithExcludedPropertiesOnStack>(
      args[0], args.register_count() - 1, rscratch);
}

void BaselineCompiler::VisitIntrinsicCreateIterResultObject(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kCreateIterResultObject>(args);
}

void BaselineCompiler::VisitIntrinsicCreateAsyncFromSyncIterator(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kCreateAsyncFromSyncIteratorBaseline>(args[0]);
}

void BaselineCompiler::VisitIntrinsicCreateJSGeneratorObject(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kCreateGeneratorObject>(args);
}

void BaselineCompiler::VisitIntrinsicGeneratorGetResumeMode(
    interpreter::RegisterList args) {
  __ LoadRegister(kInterpreterAccumulatorRegister, args[0]);
  __ LoadTaggedField(kInterpreterAccumulatorRegister,
                     kInterpreterAccumulatorRegister,
                     JSGeneratorObject::kResumeModeOffset);
}

void BaselineCompiler::VisitIntrinsicGeneratorClose(
    interpreter::RegisterList args) {
  __ LoadRegister(kInterpreterAccumulatorRegister, args[0]);
  __ StoreTaggedSignedField(kInterpreterAccumulatorRegister,
                            JSGeneratorObject::kContinuationOffset,
                            Smi::FromInt(JSGeneratorObject::kGeneratorClosed));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
}

void BaselineCompiler::VisitIntrinsicGetImportMetaObject(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kGetImportMetaObjectBaseline>();
}

void BaselineCompiler::VisitIntrinsicAsyncFunctionAwait(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncFunctionAwait>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncFunctionEnter(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncFunctionEnter>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncFunctionReject(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncFunctionReject>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncFunctionResolve(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncFunctionResolve>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncGeneratorAwait(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncGeneratorAwait>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncGeneratorReject(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncGeneratorReject>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncGeneratorResolve(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncGeneratorResolve>(args);
}

void BaselineCompiler::VisitIntrinsicAsyncGeneratorYieldWithAwait(
    interpreter::RegisterList args) {
  CallBuiltin<Builtin::kAsyncGeneratorYieldWithAwait>(args);
}

void BaselineCompiler::VisitConstruct() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);
  uint32_t arg_count = JSParameterCount(args.register_count());
  CallBuiltin<Builtin::kConstruct_Baseline>(
      RegisterOperand(0),               // kFunction
      kInterpreterAccumulatorRegister,  // kNewTarget
      arg_count,                        // kActualArgumentsCount
      Index(3),                         // kSlot
      RootIndex::kUndefinedValue,       // kReceiver
      args);
}

void BaselineCompiler::VisitConstructWithSpread() {
  interpreter::RegisterList args = iterator().GetRegisterListOperand(1);

  // Do not push the spread argument
  interpreter::Register spread_register = args.last_register();
  args = args.Truncate(args.register_count() - 1);

  uint32_t arg_count = JSParameterCount(args.register_count());

  using Descriptor =
      CallInterfaceDescriptorFor<Builtin::kConstructWithSpread_Baseline>::type;
  Register new_target =
      Descriptor::GetRegisterParameter(Descriptor::kNewTarget);
  __ Move(new_target, kInterpreterAccumulatorRegister);

  CallBuiltin<Builtin::kConstructWithSpread_Baseline>(
      RegisterOperand(0),          // kFunction
      new_target,                  // kNewTarget
      arg_count,                   // kActualArgumentsCount
      spread_register,             // kSpread
      IndexAsTagged(3),            // kSlot
      RootIndex::kUndefinedValue,  // kReceiver
      args);
}

void BaselineCompiler::VisitConstructForwardAllArgs() {
  using Descriptor = CallInterfaceDescriptorFor<
      Builtin::kConstructForwardAllArgs_Baseline>::type;
  Register new_target =
      Descriptor::GetRegisterParameter(Descriptor::kNewTarget);
  __ Move(new_target, kInterpreterAccumulatorRegister);

  CallBuiltin<Builtin::kConstructForwardAllArgs_Baseline>(
      RegisterOperand(0),  // kFunction
      new_target,          // kNewTarget
      IndexAsTagged(1));   // kSlot
}

void BaselineCompiler::VisitTestEqual() {
  CallBuiltin<Builtin::kEqual_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestEqualStrict() {
  CallBuiltin<Builtin::kStrictEqual_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestLessThan() {
  CallBuiltin<Builtin::kLessThan_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestGreaterThan() {
  CallBuiltin<Builtin::kGreaterThan_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestLessThanOrEqual() {
  CallBuiltin<Builtin::kLessThanOrEqual_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestGreaterThanOrEqual() {
  CallBuiltin<Builtin::kGreaterThanOrEqual_Baseline>(
      RegisterOperand(0), kInterpreterAccumulatorRegister, Index(1));
}

void BaselineCompiler::VisitTestReferenceEqual() {
  SelectBooleanConstant(
      kInterpreterAccumulatorRegister,
      [&](Label* is_true, Label::Distance distance) {
        __ JumpIfTagged(kEqual, __ RegisterFrameOperand(RegisterOperand(0)),
                        kInterpreterAccumulatorRegister, is_true, distance);
      });
}

void BaselineCompiler::VisitTestInstanceOf() {
  using Descriptor =
      CallInterfaceDescriptorFor<Builtin::kInstanceOf_Baseline>::type;
  Register callable = Descriptor::GetRegisterParameter(Descriptor::kRight);
  __ Move(callable, kInterpreterAccumulatorRegister);

  CallBuiltin<Builtin::kInstanceOf_Baseline>(RegisterOperand(0),  // object
                                             callable,            // callable
                                             Index(1));           // slot
}

void BaselineCompiler::VisitTestIn() {
  CallBuiltin<Builtin::kKeyedHasICBaseline>(
      kInterpreterAccumulatorRegister,  // object
      RegisterOperand(0),               // name
      IndexAsTagged(1));                // slot
}

void BaselineCompiler::VisitTestUndetectable() {
  Label done, is_smi, not_undetectable;
  __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);

  Register map_bit_field = kInterpreterAccumulatorRegister;
  __ LoadMap(map_bit_field, kInterpreterAccumulatorRegister);
  __ LoadWord8Field(map_bit_field, map_bit_field, Map::kBitFieldOffset);
  __ TestAndBranch(map_bit_field, Map::Bits1::IsUndetectableBit::kMask, kZero,
                   &not_undetectable, Label::kNear);

  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
  __ Jump(&done, Label::kNear);

  __ Bind(&is_smi);
  __ Bind(&not_undetectable);
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
  __ Bind(&done);
}

void BaselineCompiler::VisitTestNull() {
  SelectBooleanConstant(kInterpreterAccumulatorRegister,
                        [&](Label* is_true, Label::Distance distance) {
                          __ JumpIfRoot(kInterpreterAccumulatorRegister,
                                        RootIndex::kNullValue, is_true,
                                        distance);
                        });
}

void BaselineCompiler::VisitTestUndefined() {
  SelectBooleanConstant(kInterpreterAccumulatorRegister,
                        [&](Label* is_true, Label::Distance distance) {
                          __ JumpIfRoot(kInterpreterAccumulatorRegister,
                                        RootIndex::kUndefinedValue, is_true,
                                        distance);
                        });
}

void BaselineCompiler::VisitTestTypeOf() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);

  auto literal_flag =
      static_cast<interpreter::TestTypeOfFlags::LiteralFlag>(Flag8(0));

  Label done;
  switch (literal_flag) {
    case interpreter::TestTypeOfFlags::LiteralFlag::kNumber: {
      Label is_smi, is_heap_number;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);
      __ JumpIfObjectTypeFast(kEqual, kInterpreterAccumulatorRegister,
                              HEAP_NUMBER_TYPE, &is_heap_number, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&is_heap_number);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kString: {
      Label is_smi, bad_instance_type;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);
      static_assert(INTERNALIZED_TWO_BYTE_STRING_TYPE == FIRST_TYPE);
      __ JumpIfObjectType(kGreaterThanEqual, kInterpreterAccumulatorRegister,
                          FIRST_NONSTRING_TYPE, scratch_scope.AcquireScratch(),
                          &bad_instance_type, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&bad_instance_type);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kSymbol: {
      Label is_smi, bad_instance_type;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);
      __ JumpIfObjectTypeFast(kNotEqual, kInterpreterAccumulatorRegister,
                              SYMBOL_TYPE, &bad_instance_type, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&bad_instance_type);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kBoolean: {
      Label is_true, is_false;
      __ JumpIfRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue,
                    &is_true, Label::kNear);
      __ JumpIfRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue,
                    &is_false, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_true);
      __ Bind(&is_false);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kBigInt: {
      Label is_smi, bad_instance_type;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);
      __ JumpIfObjectTypeFast(kNotEqual, kInterpreterAccumulatorRegister,
                              BIGINT_TYPE, &bad_instance_type, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&bad_instance_type);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kUndefined: {
      Label is_smi, is_null, not_undetectable;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);

      // null is undetectable, so test it explicitly, and return false.
      __ JumpIfRoot(kInterpreterAccumulatorRegister, RootIndex::kNullValue,
                    &is_null, Label::kNear);

      // All other undetectable maps are typeof undefined.
      Register map_bit_field = kInterpreterAccumulatorRegister;
      __ LoadMap(map_bit_field, kInterpreterAccumulatorRegister);
      __ LoadWord8Field(map_bit_field, map_bit_field, Map::kBitFieldOffset);
      __ TestAndBranch(map_bit_field, Map::Bits1::IsUndetectableBit::kMask,
                       kZero, &not_undetectable, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&is_null);
      __ Bind(&not_undetectable);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kFunction: {
      Label is_smi, not_callable, undetectable;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);

      // Check if the map is callable but not undetectable.
      Register map_bit_field = kInterpreterAccumulatorRegister;
      __ LoadMap(m
```