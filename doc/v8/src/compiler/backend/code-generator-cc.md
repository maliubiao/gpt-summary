Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding of the Goal:**

The request asks for a summary of the functionality of `v8/src/compiler/backend/code-generator.cc`. It also introduces the concept of Torque and asks to relate the code to JavaScript if possible, provide examples, and identify potential programming errors. The fact that it's "Part 1" suggests there will be more to come.

**2. High-Level Analysis (Skimming the Code):**

The first step is to quickly read through the code, paying attention to key terms, class names, and included headers. This gives a general idea of the code's purpose.

* **Includes:**  `assembler-inl.h`, `macro-assembler-inl.h`, `optimized-compilation-info.h`, `linkage.h`, `deoptimizer/translated-state.h`, etc. These headers strongly suggest code generation, optimization, and interaction with the V8 runtime.
* **Class Name:** `CodeGenerator`. This is the central class, so its methods and members are key.
* **Constructor:** Takes arguments like `Frame`, `Linkage`, `InstructionSequence`, `OptimizedCompilationInfo`. This reinforces the idea of generating code based on higher-level representations.
* **Methods:**  `AssembleCode()`, `AssembleBlock()`, `AssembleInstruction()`, `AssembleArchInstruction()`, `AssembleDeoptimizerCall()`, `FinalizeCode()`, etc. These names clearly indicate the process of generating assembly code.
* **Data Members:** `masm_` (likely a MacroAssembler), `instructions_`, `labels_`, `safepoints_`, `handlers_`, `deoptimization_exits_`. These suggest the code manages assembly instructions, labels, safepoints for garbage collection, exception handlers, and deoptimization points.

**3. Identifying Core Functionality (Connecting the Dots):**

Based on the high-level analysis, the core functionality starts to emerge:

* **Input:** Takes an `InstructionSequence`, which is a higher-level representation of the code to be generated.
* **Process:**  Iterates through blocks and instructions in the `InstructionSequence`. For each instruction, it calls architecture-specific assembly routines (`AssembleArchInstruction`). It manages labels, safepoints, and deoptimization information.
* **Output:** Produces machine code via the `MacroAssembler` (`masm_`).

**4. Relating to Compilation Phases:**

Knowing that this code resides in `v8/src/compiler/backend`, it's clear that this is a part of the *backend* of the V8 compiler. Specifically, it's the stage that translates the optimized intermediate representation (likely represented by `InstructionSequence`) into actual machine code.

**5. Addressing Specific Questions in the Prompt:**

* **Torque:** The code explicitly checks for `.tq` extension, but since it's `.cc`, it's not Torque.
* **JavaScript Relationship:** This is the crucial part. The generated machine code *directly executes* JavaScript. The code generator takes the optimized representation of JavaScript code and transforms it into instructions the CPU can understand. Examples of JavaScript constructs that would lead to this code being executed include function calls, arithmetic operations, conditional statements, etc. The deoptimization mechanisms are triggered by runtime failures when optimized assumptions don't hold true (e.g., assuming an object has a certain shape).
* **Code Logic Inference:** The `ComputeBranchInfo` method is a good example. It analyzes branch conditions and block order to optimize jumps, demonstrating logical reasoning about code flow.
* **Common Programming Errors:** The deoptimization exits are a direct consequence of JavaScript's dynamic nature. Optimizations are based on assumptions, and if those assumptions are violated (e.g., a previously integer variable becomes a string), the optimized code needs to bail out. Type errors are a prime example.

**6. Structuring the Summary:**

The request asks for a summary of the functionality. A good summary will:

* Start with the core purpose (generating machine code).
* Identify the key inputs and outputs.
* Mention important concepts like safepoints and deoptimization.
* Briefly touch upon the internal structure (blocks and instructions).

**7. Refinement and Detail (Looking Closer):**

As you examine the code more closely, you can add more detail to the summary:

* The role of `OptimizedCompilationInfo`:  It provides context for optimization.
* The `Frame` object:  Represents the stack frame.
* The different types of deoptimization (eager and lazy).
* The handling of out-of-line code.
* The emission of metadata like source position tables and handler tables.

**8. Considering the "Part 1" Context:**

Since this is Part 1, the summary should focus on the core responsibilities of the `CodeGenerator`. Details about how the `InstructionSequence` is created or how the generated code is actually executed might be left for Part 2.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the code generator just creates assembly *text*.
* **Correction:** The presence of `MacroAssembler` and the `GetCode` method indicates it's generating binary machine code directly.
* **Initial thought:**  Focus heavily on individual assembly instructions.
* **Refinement:**  Focus more on the *overall process* of translating the intermediate representation into machine code and the management of related data structures. The specific assembly instructions are architecture-dependent and less important for a general functional overview.

By following these steps, we can arrive at a comprehensive and accurate summary of the functionality of `v8/src/compiler/backend/code-generator.cc`, addressing all the points raised in the prompt.
好的，让我们来分析一下 `v8/src/compiler/backend/code-generator.cc` 这个文件的功能。

**功能归纳：**

`v8/src/compiler/backend/code-generator.cc` 文件的核心功能是将 **经过优化的中间表示 (InstructionSequence)** 转换为 **目标机器的汇编代码 (或机器码)**。 它是 V8 编译器的后端关键组成部分，负责生成最终的可执行代码。

**具体功能点：**

1. **代码生成主流程控制:**  `CodeGenerator` 类是代码生成的核心，负责组织整个代码生成的流程。`AssembleCode()` 方法是主要的入口点，它驱动着整个代码生成过程。

2. **处理指令块 (InstructionBlock):** 代码被划分为多个指令块，`AssembleBlock()` 方法负责处理单个指令块的汇编代码生成。

3. **处理单个指令 (Instruction):** `AssembleInstruction()` 方法负责处理单个指令的汇编代码生成。它会根据指令的操作码 (opcode) 调用相应的架构相关的汇编函数 (`AssembleArchInstruction`)。

4. **架构相关的汇编代码生成:**  `AssembleArchInstruction()` 是一个虚函数（在实际的架构特定子类中实现），负责根据目标架构生成具体的汇编指令。

5. **管理寄存器分配和栈帧:**  虽然代码片段中没有直接看到寄存器分配的细节，但代码生成器需要与寄存器分配器协作，将虚拟寄存器映射到物理寄存器。它还负责管理栈帧的布局，包括局部变量、参数和临时变量的存储。

6. **处理控制流:**  代码生成器需要处理各种控制流结构，例如跳转 (`AssembleArchJump`)、条件跳转 (`AssembleArchConditionalBranch`) 和分支 (`ComputeBranchInfo`)。

7. **处理函数调用和返回:**  代码生成器负责生成函数调用和返回的汇编代码，包括参数传递、保存和恢复寄存器等。

8. **支持去优化 (Deoptimization):**  当优化的代码执行过程中出现假设不成立的情况时，需要进行去优化。`AssembleDeoptimizerCall()` 方法负责生成调用去优化入口点的代码。代码中也管理了 `deoptimization_exits_` 列表，记录了需要进行去优化的位置。

9. **生成安全点 (Safepoints):**  安全点是垃圾回收器可以安全地暂停程序并检查对象引用的位置。`RecordSafepoint()` 方法负责在代码中插入安全点信息。

10. **处理异常 (Exception Handling):** 代码中可以看到 `handlers_` 列表，用于管理异常处理信息。代码生成器会生成相应的汇编代码来处理异常情况。

11. **生成跳转表 (Jump Tables):**  对于 `switch` 语句等结构，代码生成器会生成跳转表，以实现高效的多路分支。

12. **生成元数据:** 代码生成器还需要生成一些元数据，例如源代码位置信息 (`source_position_table_builder_`)，用于调试和性能分析。

13. **支持 WebAssembly:** 代码中可以看到 `#if V8_ENABLE_WEBASSEMBLY` 相关的代码，表明代码生成器也支持 WebAssembly 的代码生成。

**关于代码类型和 JavaScript 关系：**

* **`.tq` 后缀:**  代码明确指出，如果文件名以 `.tq` 结尾，则它是 V8 Torque 源代码。由于 `v8/src/compiler/backend/code-generator.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码**。

* **与 JavaScript 的关系:**  `v8/src/compiler/backend/code-generator.cc` 生成的汇编代码 **直接对应着 JavaScript 代码的执行**。 当 V8 执行 JavaScript 代码时，TurboFan 优化编译器会将 JavaScript 代码转换为中间表示，然后 `code-generator.cc` 将这个中间表示转换为能够在目标机器上运行的机器码。

**JavaScript 举例说明:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 优化编译 `add` 函数时，`code-generator.cc` 负责生成类似于以下（简化的，架构相关的）汇编代码：

```assembly
// 假设目标架构是 x64

// 函数入口
push rbp          ; 保存栈基指针
mov rbp, rsp      ; 设置新的栈基指针

// 将参数 a 加载到寄存器
mov rax, [rbp + 16] ; 假设参数 a 在栈上的偏移是 16

// 将参数 b 加载到寄存器
mov rdx, [rbp + 24] ; 假设参数 b 在栈上的偏移是 24

// 执行加法
add rax, rdx

// 将结果存储到返回值寄存器
mov [rbp - 8], rax  ; 假设返回值位置在栈上的偏移是 -8

// 函数返回
pop rbp           ; 恢复栈基指针
ret               ; 返回
```

这段汇编代码就是 `code-generator.cc` 的工作成果之一，它实现了 `add` 函数的加法操作。

**代码逻辑推理 (假设输入与输出):**

假设有一个简单的指令块，包含一个加法操作和一个返回操作：

**假设输入 (InstructionSequence 中的一个 InstructionBlock):**

```
Block B0:
  v1 = LoadConstant(5)
  v2 = LoadConstant(10)
  v3 = Add(v1, v2)
  Return(v3)
```

**预期输出 (简化的汇编代码片段，针对 x64):**

```assembly
// Block B0 start
mov eax, 5      ; 加载常量 5 到 eax
mov edx, 10     ; 加载常量 10 到 edx
add eax, edx    ; eax = eax + edx
mov [rsp - 8], eax ; 将结果存储到栈上的返回值位置 (假设)
// 返回操作相关的汇编指令
```

**用户常见的编程错误 (导致去优化):**

一个常见的编程错误是 **类型假设失败**。 例如，如果优化器假设某个变量总是整数，但实际运行时它变成了字符串，就会触发去优化。

**示例:**

```javascript
function multiply(x) {
  return x * 2;
}

multiply(5); // 第一次调用，假设 x 是数字，生成优化代码

multiply("hello"); // 第二次调用，x 是字符串，导致之前优化的代码失效，需要去优化
```

在这个例子中，当 `multiply` 函数第一次被调用时，V8 可能会优化它，假设 `x` 是一个数字。 然而，当第二次调用时，`x` 成为了字符串，这与之前的假设不符，会导致 V8 放弃执行优化后的代码，转而执行未优化的代码或重新进行优化。`code-generator.cc` 中生成的去优化相关的代码就负责处理这种情况。

**总结 `v8/src/compiler/backend/code-generator.cc` (第 1 部分):**

到目前为止，我们可以总结出 `v8/src/compiler/backend/code-generator.cc` 的主要功能是 **作为 V8 优化编译器的后端核心组件，负责将优化的中间表示转换为目标机器的汇编代码。** 它处理指令块和单个指令，生成架构相关的汇编代码，管理栈帧和寄存器，处理控制流、函数调用、去优化、异常和跳转表，并生成必要的元数据。 它生成的代码直接执行 JavaScript 代码，并且需要处理由于 JavaScript 的动态特性可能导致的类型假设失败等情况。

Prompt: 
```
这是目录为v8/src/compiler/backend/code-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/code-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/backend/code-generator.h"

#include <optional>

#include "src/base/bounds.h"
#include "src/base/iterator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/globals.h"
#include "src/compiler/linkage.h"
#include "src/compiler/pipeline.h"
#include "src/deoptimizer/translated-state.h"
#include "src/diagnostics/eh-frame.h"
#include "src/execution/frames.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/objects/code-kind.h"
#include "src/objects/smi.h"
#include "src/utils/address-map.h"
#include "src/utils/utils.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-deopt-data.h"
#endif

namespace v8 {
namespace internal {
namespace compiler {

class CodeGenerator::JumpTable final : public ZoneObject {
 public:
  JumpTable(JumpTable* next, const base::Vector<Label*>& targets)
      : next_(next), targets_(targets) {}

  Label* label() { return &label_; }
  JumpTable* next() const { return next_; }
  const base::Vector<Label*>& targets() const { return targets_; }

 private:
  Label label_;
  JumpTable* const next_;
  base::Vector<Label*> const targets_;
};

CodeGenerator::CodeGenerator(Zone* codegen_zone, Frame* frame, Linkage* linkage,
                             InstructionSequence* instructions,
                             OptimizedCompilationInfo* info, Isolate* isolate,
                             std::optional<OsrHelper> osr_helper,
                             int start_source_position,
                             JumpOptimizationInfo* jump_opt,
                             const AssemblerOptions& options, Builtin builtin,
                             size_t max_unoptimized_frame_height,
                             size_t max_pushed_argument_count,
                             const char* debug_name)
    : zone_(codegen_zone),
      isolate_(isolate),
      frame_access_state_(nullptr),
      linkage_(linkage),
      instructions_(instructions),
      unwinding_info_writer_(codegen_zone),
      info_(info),
      labels_(codegen_zone->AllocateArray<Label>(
          instructions->InstructionBlockCount())),
      current_block_(RpoNumber::Invalid()),
      start_source_position_(start_source_position),
      current_source_position_(SourcePosition::Unknown()),
      masm_(isolate, codegen_zone, options, CodeObjectRequired::kNo,
            std::unique_ptr<AssemblerBuffer>{}),
      resolver_(this),
      safepoints_(codegen_zone),
      handlers_(codegen_zone),
      deoptimization_exits_(codegen_zone),
      protected_deoptimization_literals_(codegen_zone),
      deoptimization_literals_(codegen_zone),
      translations_(codegen_zone),
      max_unoptimized_frame_height_(max_unoptimized_frame_height),
      max_pushed_argument_count_(max_pushed_argument_count),
      caller_registers_saved_(false),
      jump_tables_(nullptr),
      ools_(nullptr),
      osr_helper_(std::move(osr_helper)),
      osr_pc_offset_(-1),
      source_position_table_builder_(
          codegen_zone, SourcePositionTableBuilder::RECORD_SOURCE_POSITIONS),
#if V8_ENABLE_WEBASSEMBLY
      protected_instructions_(codegen_zone),
#endif  // V8_ENABLE_WEBASSEMBLY
      result_(kSuccess),
      block_starts_(codegen_zone),
      instr_starts_(codegen_zone),
      debug_name_(debug_name) {
  for (int i = 0; i < instructions->InstructionBlockCount(); ++i) {
    new (&labels_[i]) Label;
  }
  CreateFrameAccessState(frame);
  CHECK_EQ(info->is_osr(), osr_helper_.has_value());
  masm_.set_jump_optimization_info(jump_opt);
  CodeKind code_kind = info->code_kind();
  if (code_kind == CodeKind::WASM_FUNCTION ||
      code_kind == CodeKind::WASM_TO_CAPI_FUNCTION ||
      code_kind == CodeKind::WASM_TO_JS_FUNCTION ||
      code_kind == CodeKind::JS_TO_WASM_FUNCTION) {
    masm_.set_abort_hard(true);
  }
  masm_.set_builtin(builtin);
}

void CodeGenerator::RecordProtectedInstruction(uint32_t instr_offset) {
#if V8_ENABLE_WEBASSEMBLY
  protected_instructions_.push_back({instr_offset});
#endif  // V8_ENABLE_WEBASSEMBLY
}

void CodeGenerator::CreateFrameAccessState(Frame* frame) {
  FinishFrame(frame);
  frame_access_state_ = zone()->New<FrameAccessState>(frame);
}

bool CodeGenerator::ShouldApplyOffsetToStackCheck(Instruction* instr,
                                                  uint32_t* offset) {
  DCHECK_EQ(instr->arch_opcode(), kArchStackPointerGreaterThan);

  StackCheckKind kind =
      static_cast<StackCheckKind>(MiscField::decode(instr->opcode()));
  if (kind != StackCheckKind::kJSFunctionEntry) return false;

  uint32_t stack_check_offset = *offset = GetStackCheckOffset();
  return stack_check_offset > kStackLimitSlackForDeoptimizationInBytes;
}

uint32_t CodeGenerator::GetStackCheckOffset() {
  if (!frame_access_state()->has_frame()) {
    DCHECK_EQ(max_unoptimized_frame_height_, 0);
    DCHECK_EQ(max_pushed_argument_count_, 0);
    return 0;
  }

  size_t incoming_parameter_count =
      linkage_->GetIncomingDescriptor()->ParameterSlotCount();
  DCHECK(is_int32(incoming_parameter_count));
  int32_t optimized_frame_height =
      static_cast<int32_t>(incoming_parameter_count) * kSystemPointerSize +
      frame()->GetTotalFrameSlotCount() * kSystemPointerSize;
  DCHECK(is_int32(max_unoptimized_frame_height_));
  int32_t signed_max_unoptimized_frame_height =
      static_cast<int32_t>(max_unoptimized_frame_height_);

  // The offset is either the delta between the optimized frames and the
  // interpreted frame, or the maximal number of bytes pushed to the stack
  // while preparing for function calls, whichever is bigger.
  uint32_t frame_height_delta = static_cast<uint32_t>(std::max(
      signed_max_unoptimized_frame_height - optimized_frame_height, 0));
  uint32_t max_pushed_argument_bytes =
      static_cast<uint32_t>(max_pushed_argument_count_ * kSystemPointerSize);
  return std::max(frame_height_delta, max_pushed_argument_bytes);
}

CodeGenerator::CodeGenResult CodeGenerator::AssembleDeoptimizerCall(
    DeoptimizationExit* exit) {
  int deoptimization_id = exit->deoptimization_id();
  if (deoptimization_id > Deoptimizer::kMaxNumberOfEntries) {
    return kTooManyDeoptimizationBailouts;
  }

  DeoptimizeKind deopt_kind = exit->kind();
  DeoptimizeReason deoptimization_reason = exit->reason();
  Label* jump_deoptimization_entry_label =
      &jump_deoptimization_entry_labels_[static_cast<int>(deopt_kind)];
  if (info()->source_positions()) {
    masm()->RecordDeoptReason(deoptimization_reason, exit->node_id(),
                              exit->pos(), deoptimization_id);
  }

  if (deopt_kind == DeoptimizeKind::kLazy) {
    ++lazy_deopt_count_;
    masm()->BindExceptionHandler(exit->label());
  } else {
    ++eager_deopt_count_;
    masm()->bind(exit->label());
  }
  Builtin target = Deoptimizer::GetDeoptimizationEntry(deopt_kind);
  masm()->CallForDeoptimization(target, deoptimization_id, exit->label(),
                                deopt_kind, exit->continue_label(),
                                jump_deoptimization_entry_label);

  exit->set_emitted();

  return kSuccess;
}

void CodeGenerator::MaybeEmitOutOfLineConstantPool() {
  masm()->MaybeEmitOutOfLineConstantPool();
}

void CodeGenerator::AssembleCode() {
  OptimizedCompilationInfo* info = this->info();
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  // Compute incoming parameter count for code using JS linkage. This will
  // ultimately set the parameter count on the resulting Code object.
  if (call_descriptor->IsJSFunctionCall()) {
    parameter_count_ = call_descriptor->ParameterSlotCount();
    if (Builtins::IsBuiltinId(info->builtin())) {
      CHECK_EQ(parameter_count_,
               Builtins::GetStackParameterCount(info->builtin()));
    } else if (info->has_bytecode_array()) {
      CHECK_EQ(parameter_count_, info->bytecode_array()->parameter_count());
    }
  }

  // Open a frame scope to indicate that there is a frame on the stack.  The
  // MANUAL indicates that the scope shouldn't actually generate code to set up
  // the frame (that is done in AssemblePrologue).
  FrameScope frame_scope(masm(), StackFrame::MANUAL);

  if (info->source_positions()) {
    AssembleSourcePosition(start_source_position());
  }
  offsets_info_.code_start_register_check = masm()->pc_offset();

  masm()->CodeEntry();

  // Check that {kJavaScriptCallCodeStartRegister} has been set correctly.
  if (v8_flags.debug_code && info->called_with_code_start_register()) {
    masm()->RecordComment("-- Prologue: check code start register --");
    AssembleCodeStartRegisterCheck();
  }

#ifdef V8_ENABLE_LEAPTIERING
  // Check that {kJavaScriptCallDispatchHandleRegister} has been set correctly.
  if (v8_flags.debug_code && call_descriptor->IsJSFunctionCall()) {
    masm()->RecordComment("-- Prologue: check dispatch handle register --");
    AssembleDispatchHandleRegisterCheck();
  }
#endif

#if V8_ENABLE_WEBASSEMBLY
  if (info->code_kind() == CodeKind::WASM_TO_JS_FUNCTION ||
      info->builtin() == Builtin::kWasmToJsWrapperCSA ||
      wasm::BuiltinLookup::IsWasmBuiltinId(info->builtin())) {
    // By default the code generator can convert slot IDs to SP-relative memory
    // operands depending on the offset if the encoding is more efficient.
    // However the SP may switch to the central stack for wasm-to-js wrappers
    // and wasm builtins, so disable this optimization there.
    // TODO(thibaudm): Disable this more selectively, only wasm builtins that
    // call JS builtins can switch, and only around the call site.
    frame_access_state()->SetFPRelativeOnly(true);
  }
#endif

  offsets_info_.deopt_check = masm()->pc_offset();
  // We want to bailout only from JS functions, which are the only ones
  // that are optimized.
  if (info->IsOptimizing()) {
    DCHECK(call_descriptor->IsJSFunctionCall());
    masm()->RecordComment("-- Prologue: check for deoptimization --");
    BailoutIfDeoptimized();
  }

  // Define deoptimization literals for all inlined functions.
  DCHECK_EQ(0u, deoptimization_literals_.size());
  for (OptimizedCompilationInfo::InlinedFunctionHolder& inlined :
       info->inlined_functions()) {
    if (!inlined.shared_info.equals(info->shared_info())) {
      int index = DefineDeoptimizationLiteral(
          DeoptimizationLiteral(inlined.shared_info));
      inlined.RegisterInlinedFunctionId(index);
    }
  }
  inlined_function_count_ = deoptimization_literals_.size();

  unwinding_info_writer_.SetNumberOfInstructionBlocks(
      instructions()->InstructionBlockCount());

  if (info->trace_turbo_json()) {
    block_starts_.assign(instructions()->instruction_blocks().size(), -1);
    instr_starts_.assign(instructions()->instructions().size(), {});
  }
  // Assemble instructions in assembly order.
  offsets_info_.blocks_start = masm()->pc_offset();
  for (const InstructionBlock* block : instructions()->ao_blocks()) {
    // Align loop headers on vendor recommended boundaries.
    if (block->ShouldAlignLoopHeader()) {
      masm()->LoopHeaderAlign();
    } else if (block->ShouldAlignCodeTarget()) {
      masm()->CodeTargetAlign();
    }

    if (info->trace_turbo_json()) {
      block_starts_[block->rpo_number().ToInt()] = masm()->pc_offset();
    }
    // Bind a label for a block.
    current_block_ = block->rpo_number();
    unwinding_info_writer_.BeginInstructionBlock(masm()->pc_offset(), block);
    if (v8_flags.code_comments && !block->omitted_by_jump_threading()) {
      std::ostringstream buffer;
      buffer << "-- B" << block->rpo_number().ToInt() << " start";
      if (block->IsDeferred()) buffer << " (deferred)";
      if (!block->needs_frame()) buffer << " (no frame)";
      if (block->must_construct_frame()) buffer << " (construct frame)";
      if (block->must_deconstruct_frame()) buffer << " (deconstruct frame)";

      if (block->IsLoopHeader()) {
        buffer << " (loop up to " << block->loop_end().ToInt() << ")";
      }
      if (block->loop_header().IsValid()) {
        buffer << " (in loop " << block->loop_header().ToInt() << ")";
      }
      buffer << " --";
      masm()->RecordComment(buffer.str().c_str(), SourceLocation());
    }

    frame_access_state()->MarkHasFrame(block->needs_frame());

    masm()->bind(GetLabel(current_block_));

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
    if (block->IsSwitchTarget()) {
      masm()->JumpTarget();
    }
#endif

    if (block->must_construct_frame()) {
      AssembleConstructFrame();
      // We need to setup the root register after we assemble the prologue, to
      // avoid clobbering callee saved registers in case of C linkage and
      // using the roots.
      // TODO(mtrofin): investigate how we can avoid doing this repeatedly.
      if (call_descriptor->InitializeRootRegister()) {
        masm()->InitializeRootRegister();
      }
    }
#ifdef CAN_USE_RVV_INSTRUCTIONS
    // RVV uses VectorUnit to emit vset{i}vl{i}, reducing the static and dynamic
    // overhead of the vset{i}vl{i} instruction. However there are some jumps
    // back between blocks. the Rvv instruction may get an incorrect vtype. so
    // here VectorUnit needs to be cleared to ensure that the vtype is correct
    // within the block.
    masm()->VU.clear();
#endif
    if (V8_EMBEDDED_CONSTANT_POOL_BOOL && !block->needs_frame()) {
      ConstantPoolUnavailableScope constant_pool_unavailable(masm());
      result_ = AssembleBlock(block);
    } else {
      result_ = AssembleBlock(block);
    }
    if (result_ != kSuccess) return;
    unwinding_info_writer_.EndInstructionBlock(block);
  }

  // Assemble all out-of-line code.
  offsets_info_.out_of_line_code = masm()->pc_offset();
  if (ools_) {
    masm()->RecordComment("-- Out of line code --");
    for (OutOfLineCode* ool = ools_; ool; ool = ool->next()) {
      masm()->bind(ool->entry());
      ool->Generate();
      if (ool->exit()->is_bound()) masm()->jmp(ool->exit());
    }
  }

  // This nop operation is needed to ensure that the trampoline is not
  // confused with the pc of the call before deoptimization.
  // The test regress/regress-259 is an example of where we need it.
  masm()->nop();

  // For some targets, we must make sure that constant and veneer pools are
  // emitted before emitting the deoptimization exits.
  PrepareForDeoptimizationExits(&deoptimization_exits_);

  deopt_exit_start_offset_ = masm()->pc_offset();

  // Assemble deoptimization exits.
  offsets_info_.deoptimization_exits = masm()->pc_offset();
  int last_updated = 0;
  // We sort the deoptimization exits here so that the lazy ones will be visited
  // last. We need this as lazy deopts might need additional instructions.
  auto cmp = [](const DeoptimizationExit* a, const DeoptimizationExit* b) {
    // The deoptimization exits are sorted so that lazy deopt exits appear after
    // eager deopts.
    static_assert(static_cast<int>(DeoptimizeKind::kLazy) ==
                      static_cast<int>(kLastDeoptimizeKind),
                  "lazy deopts are expected to be emitted last");
    if (a->kind() != b->kind()) {
      return a->kind() < b->kind();
    }
    return a->pc_offset() < b->pc_offset();
  };
  std::sort(deoptimization_exits_.begin(), deoptimization_exits_.end(), cmp);

  {
#ifdef V8_TARGET_ARCH_PPC64
    v8::internal::Assembler::BlockTrampolinePoolScope block_trampoline_pool(
        masm());
#endif
    for (DeoptimizationExit* exit : deoptimization_exits_) {
      if (exit->emitted()) continue;
      exit->set_deoptimization_id(next_deoptimization_id_++);
      result_ = AssembleDeoptimizerCall(exit);
      if (result_ != kSuccess) return;

      // UpdateDeoptimizationInfo expects lazy deopts to be visited in pc_offset
      // order, which is always the case since they are added to
      // deoptimization_exits_ in that order, and the optional sort operation
      // above preserves that order.
      if (exit->kind() == DeoptimizeKind::kLazy) {
        int trampoline_pc = exit->label()->pos();
        last_updated = safepoints()->UpdateDeoptimizationInfo(
            exit->pc_offset(), trampoline_pc, last_updated,
            exit->deoptimization_id());
      }
    }
  }

  offsets_info_.pools = masm()->pc_offset();
  // TODO(jgruber): Move all inlined metadata generation into a new,
  // architecture-independent version of FinishCode. Currently, this includes
  // the safepoint table, handler table, constant pool, and code comments, in
  // that order.
  FinishCode();

  offsets_info_.jump_tables = masm()->pc_offset();
  // Emit the jump tables.
  if (jump_tables_) {
    masm()->Align(kSystemPointerSize);
    for (JumpTable* table = jump_tables_; table; table = table->next()) {
      masm()->bind(table->label());
      AssembleJumpTable(table->targets());
    }
  }

  // The LinuxPerfJitLogger logs code up until here, excluding the safepoint
  // table. Resolve the unwinding info now so it is aware of the same code
  // size as reported by perf.
  unwinding_info_writer_.Finish(masm()->pc_offset());

  // Final alignment before starting on the metadata section.
  masm()->Align(InstructionStream::kMetadataAlignment);

  safepoints()->Emit(masm(), frame()->GetTotalFrameSlotCount());

  // Emit the exception handler table.
  if (!handlers_.empty()) {
    handler_table_offset_ = HandlerTable::EmitReturnTableStart(masm());
    for (size_t i = 0; i < handlers_.size(); ++i) {
      int pos = handlers_[i].handler != nullptr ? handlers_[i].handler->pos()
                                                : HandlerTable::kLazyDeopt;
      HandlerTable::EmitReturnEntry(masm(), handlers_[i].pc_offset, pos);
    }
  }

  masm()->MaybeEmitOutOfLineConstantPool();
  masm()->FinalizeJumpOptimizationInfo();

  result_ = kSuccess;
}

#ifndef V8_TARGET_ARCH_X64
void CodeGenerator::AssembleArchBinarySearchSwitchRange(
    Register input, RpoNumber def_block, std::pair<int32_t, Label*>* begin,
    std::pair<int32_t, Label*>* end) {
  if (end - begin < kBinarySearchSwitchMinimalCases) {
    while (begin != end) {
      masm()->JumpIfEqual(input, begin->first, begin->second);
      ++begin;
    }
    AssembleArchJumpRegardlessOfAssemblyOrder(def_block);
    return;
  }
  auto middle = begin + (end - begin) / 2;
  Label less_label;
  masm()->JumpIfLessThan(input, middle->first, &less_label);
  AssembleArchBinarySearchSwitchRange(input, def_block, middle, end);
  masm()->bind(&less_label);
  AssembleArchBinarySearchSwitchRange(input, def_block, begin, middle);
}
#endif  // V8_TARGET_ARCH_X64

void CodeGenerator::AssembleArchJump(RpoNumber target) {
  if (!IsNextInAssemblyOrder(target))
    AssembleArchJumpRegardlessOfAssemblyOrder(target);
}

base::OwnedVector<uint8_t> CodeGenerator::GetSourcePositionTable() {
  return source_position_table_builder_.ToSourcePositionTableVector();
}

base::OwnedVector<uint8_t> CodeGenerator::GetProtectedInstructionsData() {
#if V8_ENABLE_WEBASSEMBLY
  return base::OwnedVector<uint8_t>::Of(
      base::Vector<uint8_t>::cast(base::VectorOf(protected_instructions_)));
#else
  return {};
#endif  // V8_ENABLE_WEBASSEMBLY
}

MaybeHandle<Code> CodeGenerator::FinalizeCode() {
  if (result_ != kSuccess) {
    masm()->AbortedCodeGeneration();
    return {};
  }

  // Allocate the source position table.
  Handle<TrustedByteArray> source_positions =
      source_position_table_builder_.ToSourcePositionTable(isolate());

  // Allocate and install the code.
  CodeDesc desc;
  masm()->GetCode(isolate()->main_thread_local_isolate(), &desc, safepoints(),
                  handler_table_offset_);

#if defined(V8_OS_WIN64)
  if (Builtins::IsBuiltinId(info_->builtin())) {
    isolate_->SetBuiltinUnwindData(info_->builtin(), masm()->GetUnwindInfo());
  }
#endif  // V8_OS_WIN64

  if (unwinding_info_writer_.eh_frame_writer()) {
    unwinding_info_writer_.eh_frame_writer()->GetEhFrame(&desc);
  }

  Factory::CodeBuilder builder(isolate(), desc, info()->code_kind());
  builder.set_builtin(info()->builtin())
      .set_inlined_bytecode_size(info()->inlined_bytecode_size())
      .set_parameter_count(parameter_count_)
      .set_source_position_table(source_positions)
      .set_is_turbofanned()
      .set_stack_slots(frame()->GetTotalFrameSlotCount())
      .set_profiler_data(info()->profiler_data())
      .set_osr_offset(info()->osr_offset());

  if (info()->function_context_specializing()) {
    builder.set_is_context_specialized();
  }

  if (CodeKindUsesDeoptimizationData(info()->code_kind())) {
    builder.set_deoptimization_data(GenerateDeoptimizationData());
    DCHECK(info()->has_bytecode_array() ||
           info()->code_kind() == CodeKind::WASM_FUNCTION);
  }

  MaybeHandle<Code> maybe_code = builder.TryBuild();

  Handle<Code> code;
  if (!maybe_code.ToHandle(&code)) {
    masm()->AbortedCodeGeneration();
    return {};
  }

  LOG_CODE_EVENT(isolate(), CodeLinePosInfoRecordEvent(
                                code->instruction_start(), *source_positions,
                                JitCodeEvent::JIT_CODE));

  return code;
}

bool CodeGenerator::IsNextInAssemblyOrder(RpoNumber block) const {
  return instructions()
      ->InstructionBlockAt(current_block_)
      ->ao_number()
      .IsNext(instructions()->InstructionBlockAt(block)->ao_number());
}

void CodeGenerator::RecordSafepoint(ReferenceMap* references, int pc_offset) {
  auto safepoint = safepoints()->DefineSafepoint(masm(), pc_offset);

  for (int tagged : frame()->tagged_slots()) {
    safepoint.DefineTaggedStackSlot(tagged);
  }

  int frame_header_offset = frame()->GetFixedSlotCount();
  for (const InstructionOperand& operand : references->reference_operands()) {
    if (operand.IsStackSlot()) {
      int index = LocationOperand::cast(operand).index();
      DCHECK_LE(0, index);
      // We might index values in the fixed part of the frame (i.e. the
      // closure pointer or the context pointer); these are not spill slots
      // and therefore don't work with the SafepointTable currently, but
      // we also don't need to worry about them, since the GC has special
      // knowledge about those fields anyway.
      if (index < frame_header_offset) continue;
      safepoint.DefineTaggedStackSlot(index);
    }
  }
}

bool CodeGenerator::IsMaterializableFromRoot(Handle<HeapObject> object,
                                             RootIndex* index_return) {
  const CallDescriptor* incoming_descriptor =
      linkage()->GetIncomingDescriptor();
  if (incoming_descriptor->flags() & CallDescriptor::kCanUseRoots) {
    return isolate()->roots_table().IsRootHandle(object, index_return) &&
           RootsTable::IsImmortalImmovable(*index_return);
  }
  return false;
}

CodeGenerator::CodeGenResult CodeGenerator::AssembleBlock(
    const InstructionBlock* block) {
  if (block->IsHandler()) {
    masm()->ExceptionHandler();
  }
  for (int i = block->code_start(); i < block->code_end(); ++i) {
    CodeGenResult result = AssembleInstruction(i, block);
    if (result != kSuccess) return result;
  }
  return kSuccess;
}

bool CodeGenerator::IsValidPush(InstructionOperand source,
                                CodeGenerator::PushTypeFlags push_type) {
  if (source.IsImmediate() &&
      ((push_type & CodeGenerator::kImmediatePush) != 0)) {
    return true;
  }
  if (source.IsRegister() &&
      ((push_type & CodeGenerator::kRegisterPush) != 0)) {
    return true;
  }
  if (source.IsStackSlot() &&
      ((push_type & CodeGenerator::kStackSlotPush) != 0)) {
    return true;
  }
  return false;
}

void CodeGenerator::GetPushCompatibleMoves(Instruction* instr,
                                           PushTypeFlags push_type,
                                           ZoneVector<MoveOperands*>* pushes) {
  static constexpr int first_push_compatible_index =
      kReturnAddressStackSlotCount;
  pushes->clear();
  for (int i = Instruction::FIRST_GAP_POSITION;
       i <= Instruction::LAST_GAP_POSITION; ++i) {
    Instruction::GapPosition inner_pos =
        static_cast<Instruction::GapPosition>(i);
    ParallelMove* parallel_move = instr->GetParallelMove(inner_pos);
    if (parallel_move != nullptr) {
      for (auto move : *parallel_move) {
        InstructionOperand source = move->source();
        InstructionOperand destination = move->destination();
        // If there are any moves from slots that will be overridden by pushes,
        // then the full gap resolver must be used since optimization with
        // pushes don't participate in the parallel move and might clobber
        // values needed for the gap resolve.
        if (source.IsAnyStackSlot() && LocationOperand::cast(source).index() >=
                                           first_push_compatible_index) {
          pushes->clear();
          return;
        }
        // TODO(danno): Right now, only consider moves from the FIRST gap for
        // pushes. Theoretically, we could extract pushes for both gaps (there
        // are cases where this happens), but the logic for that would also have
        // to check to make sure that non-memory inputs to the pushes from the
        // LAST gap don't get clobbered in the FIRST gap.
        if (i == Instruction::FIRST_GAP_POSITION) {
          if (destination.IsStackSlot() &&
              LocationOperand::cast(destination).index() >=
                  first_push_compatible_index) {
            int index = LocationOperand::cast(destination).index();
            if (IsValidPush(source, push_type)) {
              if (index >= static_cast<int>(pushes->size())) {
                pushes->resize(index + 1);
              }
              (*pushes)[index] = move;
            }
          }
        }
      }
    }
  }

  // For now, only support a set of continuous pushes at the end of the list.
  size_t push_count_upper_bound = pushes->size();
  size_t push_begin = push_count_upper_bound;
  for (auto move : base::Reversed(*pushes)) {
    if (move == nullptr) break;
    push_begin--;
  }
  size_t push_count = pushes->size() - push_begin;
  std::copy(pushes->begin() + push_begin,
            pushes->begin() + push_begin + push_count, pushes->begin());
  pushes->resize(push_count);
}

CodeGenerator::MoveType::Type CodeGenerator::MoveType::InferMove(
    InstructionOperand* source, InstructionOperand* destination) {
  if (source->IsConstant()) {
    if (destination->IsAnyRegister()) {
      return MoveType::kConstantToRegister;
    } else {
      DCHECK(destination->IsAnyStackSlot());
      return MoveType::kConstantToStack;
    }
  }
  DCHECK(LocationOperand::cast(source)->IsCompatible(
      LocationOperand::cast(destination)));
  if (source->IsAnyRegister()) {
    if (destination->IsAnyRegister()) {
      return MoveType::kRegisterToRegister;
    } else {
      DCHECK(destination->IsAnyStackSlot());
      return MoveType::kRegisterToStack;
    }
  } else {
    DCHECK(source->IsAnyStackSlot());
    if (destination->IsAnyRegister()) {
      return MoveType::kStackToRegister;
    } else {
      DCHECK(destination->IsAnyStackSlot());
      return MoveType::kStackToStack;
    }
  }
}

CodeGenerator::MoveType::Type CodeGenerator::MoveType::InferSwap(
    InstructionOperand* source, InstructionOperand* destination) {
  DCHECK(LocationOperand::cast(source)->IsCompatible(
      LocationOperand::cast(destination)));
  if (source->IsAnyRegister()) {
    if (destination->IsAnyRegister()) {
      return MoveType::kRegisterToRegister;
    } else {
      DCHECK(destination->IsAnyStackSlot());
      return MoveType::kRegisterToStack;
    }
  } else {
    DCHECK(source->IsAnyStackSlot());
    DCHECK(destination->IsAnyStackSlot());
    return MoveType::kStackToStack;
  }
}

RpoNumber CodeGenerator::ComputeBranchInfo(BranchInfo* branch,
                                           FlagsCondition condition,
                                           Instruction* instr) {
  // Assemble a branch after this instruction.
  InstructionOperandConverter i(this, instr);
  RpoNumber true_rpo =
      i.InputRpo(instr->InputCount() - kBranchEndOffsetOfTrueBlock);
  RpoNumber false_rpo =
      i.InputRpo(instr->InputCount() - kBranchEndOffsetOfFalseBlock);

  if (true_rpo == false_rpo) {
    return true_rpo;
  }
  if (IsNextInAssemblyOrder(true_rpo) || instructions()
                                             ->InstructionBlockAt(false_rpo)
                                             ->IsLoopHeaderInAssemblyOrder()) {
    // true block is next, can fall through if condition negated.
    // false block is loop header, can save one jump if condition negated.
    std::swap(true_rpo, false_rpo);
    condition = NegateFlagsCondition(condition);
  }
  branch->condition = condition;
  branch->true_label = GetLabel(true_rpo);
  branch->false_label = GetLabel(false_rpo);
  branch->fallthru = IsNextInAssemblyOrder(false_rpo);
  return RpoNumber::Invalid();
}

CodeGenerator::CodeGenResult CodeGenerator::AssembleInstruction(
    int instruction_index, const InstructionBlock* block) {
  Instruction* instr = instructions()->InstructionAt(instruction_index);
  if (info()->trace_turbo_json()) {
    instr_starts_[instruction_index].gap_pc_offset = masm()->pc_offset();
  }
  int first_unused_stack_slot;
  FlagsMode mode = FlagsModeField::decode(instr->opcode());
  if (mode != kFlags_trap) {
    AssembleSourcePosition(instr);
  }
  bool adjust_stack =
      GetSlotAboveSPBeforeTailCall(instr, &first_unused_stack_slot);
  if (adjust_stack) AssembleTailCallBeforeGap(instr, first_unused_stack_slot);
  if (instr->opcode() == kArchNop && block->successors().empty() &&
      block->code_end() - block->code_start() == 1) {
    // When the frame-less dummy end block in Turbofan contains a Phi node,
    // don't attempt to access spill slots.
    // TODO(dmercadier): When the switch to Turboshaft is complete, this
    // will no longer be required.
  } else {
    AssembleGaps(instr);
  }
  if (adjust_stack) AssembleTailCallAfterGap(instr, first_unused_stack_slot);
  DCHECK_IMPLIES(
      block->must_deconstruct_frame(),
      instr != instructions()->InstructionAt(block->last_instruction_index()) ||
          instr->IsRet() || instr->IsJump());
  if (instr->IsJump() && block->must_deconstruct_frame()) {
    AssembleDeconstructFrame();
  }
  if (info()->trace_turbo_json()) {
    instr_starts_[instruction_index].arch_instr_pc_offset = masm()->pc_offset();
  }
  // Assemble architecture-specific code for the instruction.
  CodeGenResult result = AssembleArchInstruction(instr);
  if (result != kSuccess) return result;

  if (info()->trace_turbo_json()) {
    instr_starts_[instruction_index].condition_pc_offset = masm()->pc_offset();
  }

  FlagsCondition condition = FlagsConditionField::decode(instr->opcode());
  switch (mode) {
    case kFlags_branch:
    case kFlags_conditional_branch: {
      if (mode == kFlags_conditional_branch) {
        InstructionOperandConverter i(this, instr);
        condition = static_cast<FlagsCondition>(
            i.ToConstant(instr->InputAt(instr->InputCount() -
                                        kConditionalBranchEndOffsetOfCondition))
                .ToInt64());
      }
      BranchInfo branch;
      RpoNumber target = ComputeBranchInfo(&branch, condition, instr);
      if (target.IsValid()) {
        // redundant branch.
        if (!IsNextInAssemblyOrder(target)) {
          AssembleArchJump(target);
        }
        return kSuccess;
      }
      if (mode == kFlags_branch) {
        // Assemble architecture-specific branch.
        AssembleArchBranch(instr, &branch);
      } else {
        AssembleArchConditionalBranch(instr, &branch);
      }
      break;
    }
    case kFlags_deoptimize: {
      // Assemble a conditional eager deoptimization after this instruction.
      InstructionOperandConverter i(this, instr);
      size_t frame_state_offset =
          DeoptFrameStateOffsetField::decode(instr->opcode());
      size_t immediate_args_count =
          DeoptImmedArgsCountField::decode(instr->opcode());
      DeoptimizationExit* const exit = AddDeoptimizationExit(
          instr, frame_state_offset, immediate_args_count);
      BranchInfo branch;
      branch.condition = condition;
      branch.true_label = exit->label();
      branch.false_label = exit->continue_label();
      branch.fallthru = true;
      AssembleArchDeoptBranch(instr, &branch);
      masm()->bind(exit->continue_label());
      break;
    }
    case kFlags_set: {
      // Assemble a boolean materialization after this instruction.
      AssembleArchBoolean(instr, condition);
      break;
    }
    c
"""


```