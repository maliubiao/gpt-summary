Response: The user is asking for a summary of the C++ source code file `v8/src/maglev/maglev-graph-builder.cc`. They have also specified that this is part 1 of 9 and want to know if the code relates to JavaScript and if so, have an example.

Based on the header includes and the class name `MaglevGraphBuilder`, it's clear this file is part of the Maglev compiler pipeline in V8. Maglev is a next-generation optimizing compiler for JavaScript in V8. Therefore, this code is directly related to how JavaScript is compiled and executed.

**Breakdown of the code snippet:**

1. **Copyright and Includes:** Standard C++ copyright notice and a long list of include headers. These headers reveal the file interacts with various parts of the V8 engine:
    *   Core utilities (`<algorithm>`, `<limits>`, etc.)
    *   Code generation (`src/codegen/...`)
    *   Compiler infrastructure (`src/compiler/...`)
    *   Interpreter (`src/interpreter/...`)
    *   Maglev specific components (`src/maglev/...`)
    *   Object model (`src/objects/...`)
    *   Runtime functions (`src/builtins/...`)
    *   Deoptimization (`src/deoptimizer/...`)

2. **Namespace:**  The code is within the `v8::internal::maglev` namespace.

3. **Macros:** `TRACE` and `FAIL` are for debugging and error handling.

4. **Anonymous Namespace:** Contains helper enums and classes:
    *   `CpuOperation`:  Represents CPU-specific operations, suggesting architecture-dependent optimizations.
    *   `IsSupported`:  Checks if a `CpuOperation` is supported on the current architecture.
    *   `FunctionContextSpecialization`:  Deals with optimizing access to function contexts.

5. **`MaglevGraphBuilder` Class:**  The core of the file. It seems to be responsible for constructing the Maglev intermediate representation (IR) graph from bytecode. Methods like `TryGetParentContext`, `MinimizeContextChainDepth`, `EscapeContext` indicate it manages the context chain during graph building.

6. **`CallArguments` Class:**  A utility class to manage arguments for function calls, handling different calling conventions (with receiver, spread operator, array-like arguments).

7. **`SaveCallSpeculationScope` Class:**  Manages speculation during function calls, likely related to optimizations based on observed behavior.

8. **`DeoptFrameScope` Class:**  Deals with deoptimization frames, which are crucial for handling situations where the compiler's assumptions are invalidated at runtime. It appears to manage the creation and nesting of these frames.

9. **`MaglevSubGraphBuilder` Class:**  Used to build subgraphs within the main graph, possibly for handling conditional logic or loops. It has inner classes `Variable` and `Label` which suggest it manages local variables and control flow.

10. **`BranchBuilder` Class:**  Helps build conditional branches in the graph.

**Relationship to JavaScript and Example:**

This code is *fundamental* to the execution of JavaScript in V8. When JavaScript code is executed, V8's interpreter first runs it. For frequently executed code, V8 tries to optimize it using compilers like Maglev. `MaglevGraphBuilder` takes the bytecode produced by the interpreter and translates it into a graph-based representation that Maglev can then optimize and generate machine code from.

**JavaScript Example:**

Consider this simple JavaScript function:

```javascript
function add(a, b) {
  return a + b;
}
```

When this function is executed repeatedly, Maglev might compile it. The `MaglevGraphBuilder` would be involved in:

*   **Creating nodes for the parameters `a` and `b`.**
*   **Creating a node for the `+` operation.** This node might represent an integer addition or a floating-point addition depending on the type information Maglev has.
*   **Creating a node for the `return` statement.**
*   **Managing the context in which the function executes.**
*   **Potentially speculating about the types of `a` and `b`** (e.g., assuming they are always integers) to generate faster code, and setting up deoptimization if that speculation fails.

**In essence, `v8/src/maglev/maglev-graph-builder.cc` is a crucial component that bridges the gap between JavaScript bytecode and optimized machine code, enabling V8 to execute JavaScript efficiently.**

Given this is part 1 of 9, it likely focuses on the foundational aspects of graph construction, handling basic control flow, and managing the execution context. Subsequent parts would likely delve into more complex bytecode handling, optimizations, and interactions with other V8 components.

好的，根据提供的C++源代码文件 `v8/src/maglev/maglev-graph-builder.cc` 的第一部分，其主要功能可以归纳为：

**核心功能：构建 Maglev IR 图（Intermediate Representation Graph）**

这个文件的核心职责是实现 `MaglevGraphBuilder` 类，该类负责将 JavaScript 字节码转换为 Maglev 编译器的中间表示形式——Maglev IR 图。这个过程是 Maglev 编译器将高级的 JavaScript 代码转化为可执行的机器码的关键步骤。

**具体功能点 (基于代码片段的推断):**

*   **管理编译上下文:**  `MaglevGraphBuilder` 维护了编译过程中的各种状态，例如当前的作用域、上下文、已知的节点信息等。
*   **处理字节码:**  通过 `BytecodeArrayIterator` 迭代器遍历 JavaScript 字节码，并为每个字节码指令生成相应的 IR 节点。
*   **构建基本块 (Basic Blocks):**  将线性执行的指令序列组织成基本块，这是控制流图的基础。
*   **处理控制流:**  支持构建条件分支、循环等控制流结构，例如 `BranchBuilder` 类用于构建条件跳转。
*   **管理变量和寄存器:**  `MaglevSubGraphBuilder` 和 `Variable` 类似乎用于管理子图中的局部变量，模拟解释器寄存器的行为。
*   **处理函数调用:**  `CallArguments` 类用于处理函数调用的参数，包括接收者和参数列表。`SaveCallSpeculationScope` 涉及函数调用的推测优化。
*   **处理异常:**  虽然这部分代码中没有直接看到异常处理的明显痕迹，但包含了 `HandlerTable` 相关的头文件，暗示了后续部分可能会涉及异常处理的图构建。
*   **支持内联:**  代码中存在 `is_inline()` 的判断，以及对父 `MaglevGraphBuilder` 的引用，表明它支持函数内联。
*   **处理去优化 (Deoptimization):**  `DeoptFrameScope` 类用于管理去优化帧，在运行时发生类型不匹配等情况时，程序需要回到解释器执行。
*   **类型推断和优化:**  代码中出现了 `NodeType` 和 `ValueRepresentation`，表明 `MaglevGraphBuilder` 在构建图的过程中会进行类型推断，并根据类型信息进行优化。
*   **处理上下文 (Context):**  `TryGetParentContext` 和 `MinimizeContextChainDepth` 表明该类能够处理 JavaScript 的作用域链。

**与 JavaScript 功能的关系及示例:**

`MaglevGraphBuilder` 的工作是直接为 JavaScript 代码的执行服务的。它将 JavaScript 代码的逻辑结构（由字节码表示）转换为 Maglev 编译器可以理解和优化的图结构。

**JavaScript 示例:**

假设有以下简单的 JavaScript 函数：

```javascript
function add(x, y) {
  return x + y;
}
```

当 V8 决定使用 Maglev 编译这个函数时，`MaglevGraphBuilder` 会：

1. **读取 `add` 函数对应的字节码。**
2. **为参数 `x` 和 `y` 创建代表其值的节点。**
3. **创建一个表示加法操作的节点。**  这个节点可能会根据 `x` 和 `y` 的类型推断，选择合适的加法操作（例如，整数加法或浮点数加法）。
4. **创建一个表示 `return` 语句的节点。**
5. **如果涉及到内联，`MaglevGraphBuilder` 可能会处理内联函数的图构建。**
6. **如果在运行时 `x` 或 `y` 的类型与编译时的推断不符，`DeoptFrameScope` 会参与生成去优化的信息。**

**总结:**

`v8/src/maglev/maglev-graph-builder.cc` 的第一部分主要定义了 `MaglevGraphBuilder` 类的基础结构和核心功能，即负责将 JavaScript 字节码转换为 Maglev IR 图，为后续的优化和代码生成阶段做准备。它直接关联着 JavaScript 代码的编译和执行效率。

这是第一部分，后续的部分很可能会继续完善图构建的各个方面，例如处理更复杂的字节码指令、实现更高级的优化等。

Prompt: 
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共9部分，请归纳一下它的功能

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/maglev/maglev-graph-builder.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <utility>

#include "src/base/bounds.h"
#include "src/base/ieee754.h"
#include "src/base/logging.h"
#include "src/base/vector.h"
#include "src/builtins/builtins-constructor.h"
#include "src/builtins/builtins.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/compiler/access-info.h"
#include "src/compiler/bytecode-liveness-map.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/feedback-source.h"
#include "src/compiler/heap-refs.h"
#include "src/compiler/js-heap-broker-inl.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/processed-feedback.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/execution/protectors.h"
#include "src/flags/flags.h"
#include "src/handles/maybe-handles-inl.h"
#include "src/ic/handler-configuration-inl.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/interpreter/bytecode-register.h"
#include "src/interpreter/bytecodes.h"
#include "src/maglev/maglev-compilation-info.h"
#include "src/maglev/maglev-compilation-unit.h"
#include "src/maglev/maglev-graph-printer.h"
#include "src/maglev/maglev-interpreter-frame-state.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-ir.h"
#include "src/numbers/conversions.h"
#include "src/numbers/ieee754.h"
#include "src/objects/arguments.h"
#include "src/objects/elements-kind.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/fixed-array.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-array.h"
#include "src/objects/js-function.h"
#include "src/objects/js-objects.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/name-inl.h"
#include "src/objects/object-list-macros.h"
#include "src/objects/property-cell.h"
#include "src/objects/property-details.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/slots-inl.h"
#include "src/objects/type-hints.h"
#include "src/roots/roots.h"
#include "src/utils/utils.h"
#include "src/zone/zone.h"

#ifdef V8_INTL_SUPPORT
#include "src/objects/intl-objects.h"
#endif

#define TRACE(...)                            \
  if (v8_flags.trace_maglev_graph_building) { \
    std::cout << __VA_ARGS__ << std::endl;    \
  }

#define FAIL(...)                                                         \
  TRACE("Failed " << __func__ << ":" << __LINE__ << ": " << __VA_ARGS__); \
  return ReduceResult::Fail();

namespace v8::internal::maglev {

namespace {

enum class CpuOperation {
  kFloat64Round,
};

// TODO(leszeks): Add a generic mechanism for marking nodes as optionally
// supported.
bool IsSupported(CpuOperation op) {
  switch (op) {
    case CpuOperation::kFloat64Round:
#if defined(V8_TARGET_ARCH_X64) || defined(V8_TARGET_ARCH_IA32)
      return CpuFeatures::IsSupported(SSE4_1) || CpuFeatures::IsSupported(AVX);
#elif defined(V8_TARGET_ARCH_ARM)
      return CpuFeatures::IsSupported(ARMv8);
#elif defined(V8_TARGET_ARCH_ARM64) || defined(V8_TARGET_ARCH_PPC64) ||   \
    defined(V8_TARGET_ARCH_S390X) || defined(V8_TARGET_ARCH_RISCV64) ||   \
    defined(V8_TARGET_ARCH_RISCV32) || defined(V8_TARGET_ARCH_LOONG64) || \
    defined(V8_TARGET_ARCH_MIPS64)
      return true;
#else
#error "V8 does not support this architecture."
#endif
  }
}

class FunctionContextSpecialization final : public AllStatic {
 public:
  static compiler::OptionalContextRef TryToRef(
      const MaglevCompilationUnit* unit, ValueNode* context, size_t* depth) {
    DCHECK(unit->info()->specialize_to_function_context());
    if (Constant* n = context->TryCast<Constant>()) {
      return n->ref().AsContext().previous(unit->broker(), depth);
    }
    return {};
  }
};

}  // namespace

ValueNode* MaglevGraphBuilder::TryGetParentContext(ValueNode* node) {
  if (CreateFunctionContext* n = node->TryCast<CreateFunctionContext>()) {
    return n->context().node();
  }

  if (InlinedAllocation* alloc = node->TryCast<InlinedAllocation>()) {
    return alloc->object()->get(
        Context::OffsetOfElementAt(Context::PREVIOUS_INDEX));
  }

  if (CallRuntime* n = node->TryCast<CallRuntime>()) {
    switch (n->function_id()) {
      case Runtime::kPushBlockContext:
      case Runtime::kPushCatchContext:
      case Runtime::kNewFunctionContext:
        return n->context().node();
      default:
        break;
    }
  }

  return nullptr;
}

// Attempts to walk up the context chain through the graph in order to reduce
// depth and thus the number of runtime loads.
void MaglevGraphBuilder::MinimizeContextChainDepth(ValueNode** context,
                                                   size_t* depth) {
  while (*depth > 0) {
    ValueNode* parent_context = TryGetParentContext(*context);
    if (parent_context == nullptr) return;
    *context = parent_context;
    (*depth)--;
  }
}

void MaglevGraphBuilder::EscapeContext() {
  ValueNode* context = GetContext();
  if (InlinedAllocation* alloc = context->TryCast<InlinedAllocation>()) {
    alloc->ForceEscaping();
  }
}

class CallArguments {
 public:
  enum Mode {
    kDefault,
    kWithSpread,
    kWithArrayLike,
  };

  CallArguments(ConvertReceiverMode receiver_mode,
                interpreter::RegisterList reglist,
                const InterpreterFrameState& frame, Mode mode = kDefault)
      : receiver_mode_(receiver_mode),
        args_(reglist.register_count()),
        mode_(mode) {
    for (int i = 0; i < reglist.register_count(); i++) {
      args_[i] = frame.get(reglist[i]);
    }
    DCHECK_IMPLIES(args_.size() == 0,
                   receiver_mode == ConvertReceiverMode::kNullOrUndefined);
    DCHECK_IMPLIES(mode != kDefault,
                   receiver_mode == ConvertReceiverMode::kAny);
    DCHECK_IMPLIES(mode == kWithArrayLike, args_.size() == 2);
  }

  explicit CallArguments(ConvertReceiverMode receiver_mode)
      : receiver_mode_(receiver_mode), args_(), mode_(kDefault) {
    DCHECK_EQ(receiver_mode, ConvertReceiverMode::kNullOrUndefined);
  }

  CallArguments(ConvertReceiverMode receiver_mode,
                std::initializer_list<ValueNode*> args, Mode mode = kDefault)
      : receiver_mode_(receiver_mode), args_(args), mode_(mode) {
    DCHECK_IMPLIES(mode != kDefault,
                   receiver_mode == ConvertReceiverMode::kAny);
    DCHECK_IMPLIES(mode == kWithArrayLike, args_.size() == 2);
    CheckArgumentsAreNotConversionNodes();
  }

  CallArguments(ConvertReceiverMode receiver_mode,
                base::SmallVector<ValueNode*, 8>&& args, Mode mode = kDefault)
      : receiver_mode_(receiver_mode), args_(std::move(args)), mode_(mode) {
    DCHECK_IMPLIES(mode != kDefault,
                   receiver_mode == ConvertReceiverMode::kAny);
    DCHECK_IMPLIES(mode == kWithArrayLike, args_.size() == 2);
    CheckArgumentsAreNotConversionNodes();
  }

  ValueNode* receiver() const {
    if (receiver_mode_ == ConvertReceiverMode::kNullOrUndefined) {
      return nullptr;
    }
    return args_[0];
  }

  void set_receiver(ValueNode* receiver) {
    if (receiver_mode_ == ConvertReceiverMode::kNullOrUndefined) {
      args_.insert(args_.data(), receiver);
      receiver_mode_ = ConvertReceiverMode::kAny;
    } else {
      DCHECK(!receiver->properties().is_conversion());
      args_[0] = receiver;
    }
  }

  ValueNode* array_like_argument() {
    DCHECK_EQ(mode_, kWithArrayLike);
    DCHECK_GT(count(), 0);
    return args_[args_.size() - 1];
  }

  size_t count() const {
    if (receiver_mode_ == ConvertReceiverMode::kNullOrUndefined) {
      return args_.size();
    }
    return args_.size() - 1;
  }

  size_t count_with_receiver() const { return count() + 1; }

  ValueNode* operator[](size_t i) const {
    if (receiver_mode_ != ConvertReceiverMode::kNullOrUndefined) {
      i++;
    }
    if (i >= args_.size()) return nullptr;
    return args_[i];
  }

  void set_arg(size_t i, ValueNode* node) {
    if (receiver_mode_ != ConvertReceiverMode::kNullOrUndefined) {
      i++;
    }
    DCHECK_LT(i, args_.size());
    DCHECK(!node->properties().is_conversion());
    args_[i] = node;
  }

  Mode mode() const { return mode_; }

  ConvertReceiverMode receiver_mode() const { return receiver_mode_; }

  void PopArrayLikeArgument() {
    DCHECK_EQ(mode_, kWithArrayLike);
    DCHECK_GT(count(), 0);
    args_.pop_back();
  }

  void PopReceiver(ConvertReceiverMode new_receiver_mode) {
    DCHECK_NE(receiver_mode_, ConvertReceiverMode::kNullOrUndefined);
    DCHECK_NE(new_receiver_mode, ConvertReceiverMode::kNullOrUndefined);
    DCHECK_GT(args_.size(), 0);  // We have at least a receiver to pop!
    // TODO(victorgomes): Do this better!
    for (size_t i = 0; i < args_.size() - 1; i++) {
      args_[i] = args_[i + 1];
    }
    args_.pop_back();

    // If there is no non-receiver argument to become the new receiver,
    // consider the new receiver to be known undefined.
    receiver_mode_ = args_.empty() ? ConvertReceiverMode::kNullOrUndefined
                                   : new_receiver_mode;
  }

 private:
  ConvertReceiverMode receiver_mode_;
  base::SmallVector<ValueNode*, 8> args_;
  Mode mode_;

  void CheckArgumentsAreNotConversionNodes() {
#ifdef DEBUG
    // Arguments can leak to the interpreter frame if the call is inlined,
    // conversions should be stored in known_node_aspects/NodeInfo.
    for (ValueNode* arg : args_) {
      DCHECK(!arg->properties().is_conversion());
    }
#endif  // DEBUG
  }
};

class V8_NODISCARD MaglevGraphBuilder::SaveCallSpeculationScope {
 public:
  explicit SaveCallSpeculationScope(
      MaglevGraphBuilder* builder,
      compiler::FeedbackSource feedback_source = compiler::FeedbackSource())
      : builder_(builder) {
    saved_ = builder_->current_speculation_feedback_;
    // Only set the current speculation feedback if speculation is allowed.
    if (IsSpeculationAllowed(builder_->broker(), feedback_source)) {
      builder->current_speculation_feedback_ = feedback_source;
    } else {
      builder->current_speculation_feedback_ = compiler::FeedbackSource();
    }
  }
  ~SaveCallSpeculationScope() {
    builder_->current_speculation_feedback_ = saved_;
  }

  const compiler::FeedbackSource& value() { return saved_; }

 private:
  MaglevGraphBuilder* builder_;
  compiler::FeedbackSource saved_;

  static bool IsSpeculationAllowed(compiler::JSHeapBroker* broker,
                                   compiler::FeedbackSource feedback_source) {
    if (!feedback_source.IsValid()) return false;
    compiler::ProcessedFeedback const& processed_feedback =
        broker->GetFeedbackForCall(feedback_source);
    if (processed_feedback.IsInsufficient()) return false;
    return processed_feedback.AsCall().speculation_mode() ==
           SpeculationMode::kAllowSpeculation;
  }
};

class V8_NODISCARD MaglevGraphBuilder::DeoptFrameScope {
 public:
  DeoptFrameScope(MaglevGraphBuilder* builder, Builtin continuation,
                  compiler::OptionalJSFunctionRef maybe_js_target = {})
      : builder_(builder),
        parent_(builder->current_deopt_scope_),
        data_(DeoptFrame::BuiltinContinuationFrameData{
            continuation, {}, builder->GetContext(), maybe_js_target}) {
    builder_->current_interpreter_frame().virtual_objects().Snapshot();
    builder_->current_deopt_scope_ = this;
    builder_->AddDeoptUse(
        data_.get<DeoptFrame::BuiltinContinuationFrameData>().context);
    DCHECK(data_.get<DeoptFrame::BuiltinContinuationFrameData>()
               .parameters.empty());
  }

  DeoptFrameScope(MaglevGraphBuilder* builder, Builtin continuation,
                  compiler::OptionalJSFunctionRef maybe_js_target,
                  base::Vector<ValueNode* const> parameters)
      : builder_(builder),
        parent_(builder->current_deopt_scope_),
        data_(DeoptFrame::BuiltinContinuationFrameData{
            continuation, builder->zone()->CloneVector(parameters),
            builder->GetContext(), maybe_js_target}) {
    builder_->current_interpreter_frame().virtual_objects().Snapshot();
    builder_->current_deopt_scope_ = this;
    builder_->AddDeoptUse(
        data_.get<DeoptFrame::BuiltinContinuationFrameData>().context);
    if (parameters.size() > 0) {
      if (InlinedAllocation* receiver =
              parameters[0]->TryCast<InlinedAllocation>()) {
        // We escape the first argument, since the builtin continuation call can
        // trigger a stack iteration, which expects the receiver to be a
        // meterialized object.
        receiver->ForceEscaping();
      }
    }
    for (ValueNode* node :
         data_.get<DeoptFrame::BuiltinContinuationFrameData>().parameters) {
      builder_->AddDeoptUse(node);
    }
  }

  DeoptFrameScope(MaglevGraphBuilder* builder, ValueNode* receiver)
      : builder_(builder),
        parent_(builder->current_deopt_scope_),
        data_(DeoptFrame::ConstructInvokeStubFrameData{
            *builder->compilation_unit(), builder->current_source_position_,
            receiver, builder->GetContext()}) {
    builder_->current_interpreter_frame().virtual_objects().Snapshot();
    builder_->current_deopt_scope_ = this;
    builder_->AddDeoptUse(
        data_.get<DeoptFrame::ConstructInvokeStubFrameData>().receiver);
    builder_->AddDeoptUse(
        data_.get<DeoptFrame::ConstructInvokeStubFrameData>().context);
  }

  ~DeoptFrameScope() {
    builder_->current_deopt_scope_ = parent_;
    // We might have cached a checkpointed frame which includes this scope;
    // reset it just in case.
    builder_->latest_checkpointed_frame_.reset();
  }

  DeoptFrameScope* parent() const { return parent_; }

  bool IsLazyDeoptContinuationFrame() const {
    if (data_.tag() != DeoptFrame::FrameType::kBuiltinContinuationFrame) {
      return false;
    }
    switch (data_.get<DeoptFrame::FrameType::kBuiltinContinuationFrame>()
                .builtin_id) {
      case Builtin::kGetIteratorWithFeedbackLazyDeoptContinuation:
      case Builtin::kCallIteratorWithFeedbackLazyDeoptContinuation:
      case Builtin::kArrayForEachLoopLazyDeoptContinuation:
      case Builtin::kGenericLazyDeoptContinuation:
      case Builtin::kToBooleanLazyDeoptContinuation:
        return true;
      default:
        return false;
    }
  }

  DeoptFrame::FrameData& data() { return data_; }
  const DeoptFrame::FrameData& data() const { return data_; }

 private:
  MaglevGraphBuilder* builder_;
  DeoptFrameScope* parent_;
  DeoptFrame::FrameData data_;
};

class MaglevGraphBuilder::MaglevSubGraphBuilder::Variable {
 public:
  explicit Variable(int index) : pseudo_register_(index) {}

 private:
  friend class MaglevSubGraphBuilder;

  // Variables pretend to be interpreter registers as far as the dummy
  // compilation unit and merge states are concerned.
  interpreter::Register pseudo_register_;
};

class MaglevGraphBuilder::MaglevSubGraphBuilder::Label {
 public:
  Label(MaglevSubGraphBuilder* sub_builder, int predecessor_count)
      : predecessor_count_(predecessor_count),
        liveness_(
            sub_builder->builder_->zone()->New<compiler::BytecodeLivenessState>(
                sub_builder->compilation_unit_->register_count(),
                sub_builder->builder_->zone())) {}
  Label(MaglevSubGraphBuilder* sub_builder, int predecessor_count,
        std::initializer_list<Variable*> vars)
      : Label(sub_builder, predecessor_count) {
    for (Variable* var : vars) {
      liveness_->MarkRegisterLive(var->pseudo_register_.index());
    }
  }

 private:
  explicit Label(MergePointInterpreterFrameState* merge_state,
                 BasicBlock* basic_block)
      : merge_state_(merge_state), ref_(basic_block) {}

  friend class MaglevSubGraphBuilder;
  friend class BranchBuilder;
  MergePointInterpreterFrameState* merge_state_ = nullptr;
  int predecessor_count_ = -1;
  compiler::BytecodeLivenessState* liveness_ = nullptr;
  BasicBlockRef ref_;
};

class MaglevGraphBuilder::MaglevSubGraphBuilder::LoopLabel {
 public:
 private:
  explicit LoopLabel(MergePointInterpreterFrameState* merge_state,
                     BasicBlock* loop_header)
      : merge_state_(merge_state), loop_header_(loop_header) {}

  friend class MaglevSubGraphBuilder;
  MergePointInterpreterFrameState* merge_state_ = nullptr;
  BasicBlock* loop_header_;
};

class MaglevGraphBuilder::MaglevSubGraphBuilder::
    BorrowParentKnownNodeAspectsAndVOs {
 public:
  explicit BorrowParentKnownNodeAspectsAndVOs(
      MaglevSubGraphBuilder* sub_builder)
      : sub_builder_(sub_builder) {
    sub_builder_->TakeKnownNodeAspectsAndVOsFromParent();
  }
  ~BorrowParentKnownNodeAspectsAndVOs() {
    sub_builder_->MoveKnownNodeAspectsAndVOsToParent();
  }

 private:
  MaglevSubGraphBuilder* sub_builder_;
};

void MaglevGraphBuilder::BranchBuilder::StartFallthroughBlock(
    BasicBlock* predecessor) {
  switch (mode()) {
    case kBytecodeJumpTarget: {
      auto& data = data_.bytecode_target;
      if (data.patch_accumulator_scope &&
          (data.patch_accumulator_scope->node_ == builder_->GetAccumulator())) {
        SetAccumulatorInBranch(BranchType::kBranchIfTrue);
        builder_->MergeIntoFrameState(predecessor, data.jump_target_offset);
        SetAccumulatorInBranch(BranchType::kBranchIfFalse);
        builder_->StartFallthroughBlock(data.fallthrough_offset, predecessor);
      } else {
        builder_->MergeIntoFrameState(predecessor, data.jump_target_offset);
        builder_->StartFallthroughBlock(data.fallthrough_offset, predecessor);
      }
      break;
    }
    case kLabelJumpTarget:
      auto& data = data_.label_target;
      sub_builder_->MergeIntoLabel(data.jump_label, predecessor);
      builder_->StartNewBlock(predecessor, nullptr, data.fallthrough);
      break;
  }
}

void MaglevGraphBuilder::BranchBuilder::SetAccumulatorInBranch(
    BranchType jump_type) const {
  DCHECK_EQ(mode(), kBytecodeJumpTarget);
  auto& data = data_.bytecode_target;
  if (branch_specialization_mode_ == BranchSpecializationMode::kAlwaysBoolean) {
    builder_->SetAccumulatorInBranch(builder_->GetBooleanConstant(
        data.patch_accumulator_scope->jump_type_ == jump_type));
  } else if (data.patch_accumulator_scope->jump_type_ == jump_type) {
    builder_->SetAccumulatorInBranch(
        builder_->GetRootConstant(data.patch_accumulator_scope->root_index_));
  } else {
    builder_->SetAccumulatorInBranch(data.patch_accumulator_scope->node_);
  }
}

BasicBlockRef* MaglevGraphBuilder::BranchBuilder::jump_target() {
  switch (mode()) {
    case kBytecodeJumpTarget:
      return &builder_->jump_targets_[data_.bytecode_target.jump_target_offset];
    case kLabelJumpTarget:
      return &data_.label_target.jump_label->ref_;
  }
}

BasicBlockRef* MaglevGraphBuilder::BranchBuilder::fallthrough() {
  switch (mode()) {
    case kBytecodeJumpTarget:
      return &builder_->jump_targets_[data_.bytecode_target.fallthrough_offset];
    case kLabelJumpTarget:
      return &data_.label_target.fallthrough;
  }
}

BasicBlockRef* MaglevGraphBuilder::BranchBuilder::true_target() {
  return jump_type_ == BranchType::kBranchIfTrue ? jump_target()
                                                 : fallthrough();
}

BasicBlockRef* MaglevGraphBuilder::BranchBuilder::false_target() {
  return jump_type_ == BranchType::kBranchIfFalse ? jump_target()
                                                  : fallthrough();
}

MaglevGraphBuilder::BranchResult MaglevGraphBuilder::BranchBuilder::FromBool(
    bool value) const {
  switch (mode()) {
    case kBytecodeJumpTarget: {
      BranchType type_if_need_to_jump =
          (value ? BranchType::kBranchIfTrue : BranchType::kBranchIfFalse);
      builder_->MarkBranchDeadAndJumpIfNeeded(jump_type_ ==
                                              type_if_need_to_jump);
      return BranchResult::kDefault;
    }
    case kLabelJumpTarget:
      return value ? BranchResult::kAlwaysTrue : BranchResult::kAlwaysFalse;
  }
}

template <typename ControlNodeT, typename... Args>
MaglevGraphBuilder::BranchResult MaglevGraphBuilder::BranchBuilder::Build(
    std::initializer_list<ValueNode*> control_inputs, Args&&... args) {
  static_assert(IsConditionalControlNode(Node::opcode_of<ControlNodeT>));
  BasicBlock* block = builder_->FinishBlock<ControlNodeT>(
      control_inputs, std::forward<Args>(args)..., true_target(),
      false_target());
  StartFallthroughBlock(block);
  return BranchResult::kDefault;
}

MaglevGraphBuilder::MaglevSubGraphBuilder::MaglevSubGraphBuilder(
    MaglevGraphBuilder* builder, int variable_count)
    : builder_(builder),
      compilation_unit_(MaglevCompilationUnit::NewDummy(
          builder->zone(), builder->compilation_unit(), variable_count, 0, 0)),
      pseudo_frame_(*compilation_unit_, nullptr, VirtualObject::List()) {
  // We need to set a context, since this is unconditional in the frame state,
  // so set it to the real context.
  pseudo_frame_.set(interpreter::Register::current_context(),
                    builder_->current_interpreter_frame().get(
                        interpreter::Register::current_context()));
  DCHECK_NULL(pseudo_frame_.known_node_aspects());
}

MaglevGraphBuilder::MaglevSubGraphBuilder::LoopLabel
MaglevGraphBuilder::MaglevSubGraphBuilder::BeginLoop(
    std::initializer_list<Variable*> loop_vars) {
  // Create fake liveness and loop info for the loop, with all given loop vars
  // set to be live and assigned inside the loop.
  compiler::BytecodeLivenessState* loop_header_liveness =
      builder_->zone()->New<compiler::BytecodeLivenessState>(
          compilation_unit_->register_count(), builder_->zone());
  compiler::LoopInfo* loop_info = builder_->zone()->New<compiler::LoopInfo>(
      -1, 0, kMaxInt, compilation_unit_->parameter_count(),
      compilation_unit_->register_count(), builder_->zone());
  for (Variable* var : loop_vars) {
    loop_header_liveness->MarkRegisterLive(var->pseudo_register_.index());
    loop_info->assignments().Add(var->pseudo_register_);
  }

  // Finish the current block, jumping (as a fallthrough) to the loop header.
  BasicBlockRef loop_header_ref;
  BasicBlock* loop_predecessor =
      builder_->FinishBlock<Jump>({}, &loop_header_ref);

  // Create a state for the loop header, with two predecessors (the above jump
  // and the back edge), and initialise with the current state.
  MergePointInterpreterFrameState* loop_state =
      MergePointInterpreterFrameState::NewForLoop(
          pseudo_frame_, *compilation_unit_, 0, 2, loop_header_liveness,
          loop_info);

  {
    BorrowParentKnownNodeAspectsAndVOs borrow(this);
    loop_state->Merge(builder_, *compilation_unit_, pseudo_frame_,
                      loop_predecessor);
  }

  // Start a new basic block for the loop.
  DCHECK_NULL(pseudo_frame_.known_node_aspects());
  pseudo_frame_.CopyFrom(*compilation_unit_, *loop_state);
  MoveKnownNodeAspectsAndVOsToParent();

  builder_->ProcessMergePointPredecessors(*loop_state, loop_header_ref);
  builder_->StartNewBlock(nullptr, loop_state, loop_header_ref);

  return LoopLabel{loop_state, loop_header_ref.block_ptr()};
}

template <typename ControlNodeT, typename... Args>
void MaglevGraphBuilder::MaglevSubGraphBuilder::GotoIfTrue(
    Label* true_target, std::initializer_list<ValueNode*> control_inputs,
    Args&&... args) {
  static_assert(IsConditionalControlNode(Node::opcode_of<ControlNodeT>));

  BasicBlockRef fallthrough_ref;

  // Pass through to FinishBlock, converting Labels to BasicBlockRefs and the
  // fallthrough label to the fallthrough ref.
  BasicBlock* block = builder_->FinishBlock<ControlNodeT>(
      control_inputs, std::forward<Args>(args)..., &true_target->ref_,
      &fallthrough_ref);

  MergeIntoLabel(true_target, block);

  builder_->StartNewBlock(block, nullptr, fallthrough_ref);
}

template <typename ControlNodeT, typename... Args>
void MaglevGraphBuilder::MaglevSubGraphBuilder::GotoIfFalse(
    Label* false_target, std::initializer_list<ValueNode*> control_inputs,
    Args&&... args) {
  static_assert(IsConditionalControlNode(Node::opcode_of<ControlNodeT>));

  BasicBlockRef fallthrough_ref;

  // Pass through to FinishBlock, converting Labels to BasicBlockRefs and the
  // fallthrough label to the fallthrough ref.
  BasicBlock* block = builder_->FinishBlock<ControlNodeT>(
      control_inputs, std::forward<Args>(args)..., &fallthrough_ref,
      &false_target->ref_);

  MergeIntoLabel(false_target, block);

  builder_->StartNewBlock(block, nullptr, fallthrough_ref);
}

void MaglevGraphBuilder::MaglevSubGraphBuilder::GotoOrTrim(Label* label) {
  if (builder_->current_block_ == nullptr) {
    ReducePredecessorCount(label);
    return;
  }
  Goto(label);
}

void MaglevGraphBuilder::MaglevSubGraphBuilder::Goto(Label* label) {
  CHECK_NOT_NULL(builder_->current_block_);
  BasicBlock* block = builder_->FinishBlock<Jump>({}, &label->ref_);
  MergeIntoLabel(label, block);
}

void MaglevGraphBuilder::MaglevSubGraphBuilder::ReducePredecessorCount(
    Label* label, unsigned num) {
  DCHECK_GE(label->predecessor_count_, num);
  if (num == 0) {
    return;
  }
  label->predecessor_count_ -= num;
  if (label->merge_state_ != nullptr) {
    label->merge_state_->MergeDead(*compilation_unit_, num);
  }
}

void MaglevGraphBuilder::MaglevSubGraphBuilder::EndLoop(LoopLabel* loop_label) {
  if (builder_->current_block_ == nullptr) {
    loop_label->merge_state_->MergeDeadLoop(*compilation_unit_);
    return;
  }

  BasicBlock* block =
      builder_->FinishBlock<JumpLoop>({}, loop_label->loop_header_);
  {
    BorrowParentKnownNodeAspectsAndVOs borrow(this);
    loop_label->merge_state_->MergeLoop(builder_, *compilation_unit_,
                                        pseudo_frame_, block);
  }
  block->set_predecessor_id(loop_label->merge_state_->predecessor_count() - 1);
}

ReduceResult MaglevGraphBuilder::MaglevSubGraphBuilder::TrimPredecessorsAndBind(
    Label* label) {
  int predecessors_so_far = label->merge_state_ == nullptr
                                ? 0
                                : label->merge_state_->predecessors_so_far();
  DCHECK_LE(predecessors_so_far, label->predecessor_count_);
  builder_->current_block_ = nullptr;
  ReducePredecessorCount(label,
                         label->predecessor_count_ - predecessors_so_far);
  if (predecessors_so_far == 0) return ReduceResult::DoneWithAbort();
  Bind(label);
  return ReduceResult::Done();
}

void MaglevGraphBuilder::MaglevSubGraphBuilder::Bind(Label* label) {
  DCHECK_NULL(builder_->current_block_);

  DCHECK_NULL(pseudo_frame_.known_node_aspects());
  pseudo_frame_.CopyFrom(*compilation_unit_, *label->merge_state_);
  MoveKnownNodeAspectsAndVOsToParent();

  CHECK_EQ(label->merge_state_->predecessors_so_far(),
           label->predecessor_count_);

  builder_->ProcessMergePointPredecessors(*label->merge_state_, label->ref_);
  builder_->StartNewBlock(nullptr, label->merge_state_, label->ref_);
}

void MaglevGraphBuilder::MaglevSubGraphBuilder::set(Variable& var,
                                                    ValueNode* value) {
  pseudo_frame_.set(var.pseudo_register_, value);
}
ValueNode* MaglevGraphBuilder::MaglevSubGraphBuilder::get(
    const Variable& var) const {
  return pseudo_frame_.get(var.pseudo_register_);
}

template <typename FCond, typename FTrue, typename FFalse>
ReduceResult MaglevGraphBuilder::MaglevSubGraphBuilder::Branch(
    std::initializer_list<MaglevSubGraphBuilder::Variable*> vars, FCond cond,
    FTrue if_true, FFalse if_false) {
  MaglevSubGraphBuilder::Label else_branch(this, 1);
  BranchBuilder builder(builder_, this, BranchType::kBranchIfFalse,
                        &else_branch);
  BranchResult branch_result = cond(builder);
  if (branch_result == BranchResult::kAlwaysTrue) {
    return if_true();
  }
  if (branch_result == BranchResult::kAlwaysFalse) {
    return if_false();
  }
  DCHECK(branch_result == BranchResult::kDefault);
  MaglevSubGraphBuilder::Label done(this, 2, vars);
  ReduceResult result_if_true = if_true();
  CHECK(result_if_true.IsDone());
  GotoOrTrim(&done);
  Bind(&else_branch);
  ReduceResult result_if_false = if_false();
  CHECK(result_if_false.IsDone());
  if (result_if_true.IsDoneWithAbort() && result_if_false.IsDoneWithAbort()) {
    return ReduceResult::DoneWithAbort();
  }
  GotoOrTrim(&done);
  Bind(&done);
  return ReduceResult::Done();
}

template <typename FCond, typename FTrue, typename FFalse>
ValueNode* MaglevGraphBuilder::Select(FCond cond, FTrue if_true,
                                      FFalse if_false) {
  MaglevSubGraphBuilder subgraph(this, 1);
  MaglevSubGraphBuilder::Label else_branch(&subgraph, 1);
  BranchBuilder builder(this, &subgraph, BranchType::kBranchIfFalse,
                        &else_branch);
  BranchResult branch_result = cond(builder);
  if (branch_result == BranchResult::kAlwaysTrue) {
    return if_true();
  }
  if (branch_result == BranchResult::kAlwaysFalse) {
    return if_false();
  }
  DCHECK(branch_result == BranchResult::kDefault);
  MaglevSubGraphBuilder::Variable ret_val(0);
  MaglevSubGraphBuilder::Label done(&subgraph, 2, {&ret_val});
  subgraph.set(ret_val, if_true());
  subgraph.Goto(&done);
  subgraph.Bind(&else_branch);
  subgraph.set(ret_val, if_false());
  subgraph.Goto(&done);
  subgraph.Bind(&done);
  return subgraph.get(ret_val);
}

template <typename FCond, typename FTrue, typename FFalse>
ReduceResult MaglevGraphBuilder::SelectReduction(FCond cond, FTrue if_true,
                                                 FFalse if_false) {
  MaglevSubGraphBuilder subgraph(this, 1);
  MaglevSubGraphBuilder::Label else_branch(&subgraph, 1);
  BranchBuilder builder(this, &subgraph, BranchType::kBranchIfFalse,
                        &else_branch);
  BranchResult branch_result = cond(builder);
  if (branch_result == BranchResult::kAlwaysTrue) {
    return if_true();
  }
  if (branch_result == BranchResult::kAlwaysFalse) {
    return if_false();
  }
  DCHECK(branch_result == BranchResult::kDefault);
  MaglevSubGraphBuilder::Variable ret_val(0);
  MaglevSubGraphBuilder::Label done(&subgraph, 2, {&ret_val});
  ReduceResult result_if_true = if_true();
  CHECK(result_if_true.IsDone());
  if (result_if_true.IsDoneWithValue()) {
    subgraph.set(ret_val, result_if_true.value());
  }
  subgraph.GotoOrTrim(&done);
  subgraph.Bind(&else_branch);
  ReduceResult result_if_false = if_false();
  CHECK(result_if_false.IsDone());
  if (result_if_true.IsDoneWithAbort() && result_if_false.IsDoneWithAbort()) {
    return ReduceResult::DoneWithAbort();
  }
  if (result_if_false.IsDoneWithValue()) {
    subgraph.set(ret_val, result_if_false.value());
  }
  subgraph.GotoOrTrim(&done);
  subgraph.Bind(&done);
  return subgraph.get(ret_val);
}

// Known node aspects for the pseudo frame are null aside from when merging --
// before each merge, we should borrow the node aspects from the parent
// builder, and after each merge point, we should copy the node aspects back
// to the parent. This is so that the parent graph builder can update its own
// known node aspects without having to worry about this pseudo frame.
void MaglevGraphBuilder::MaglevSubGraphBuilder::
    TakeKnownNodeAspectsAndVOsFromParent() {
  DCHECK_NULL(pseudo_frame_.known_node_aspects());
  DCHECK(pseudo_frame_.virtual_objects().is_empty());
  pseudo_frame_.set_known_node_aspects(
      builder_->current_interpreter_frame_.known_node_aspects());
  pseudo_frame_.set_virtual_objects(
      builder_->current_interpreter_frame_.virtual_objects());
}

void MaglevGraphBuilder::MaglevSubGraphBuilder::
    MoveKnownNodeAspectsAndVOsToParent() {
  DCHECK_NOT_NULL(pseudo_frame_.known_node_aspects());
  builder_->current_interpreter_frame_.set_known_node_aspects(
      pseudo_frame_.known_node_aspects());
  pseudo_frame_.clear_known_node_aspects();
  builder_->current_interpreter_frame_.set_virtual_objects(
      pseudo_frame_.virtual_objects());
  pseudo_frame_.set_virtual_objects(VirtualObject::List());
}

void MaglevGraphBuilder::MaglevSubGraphBuilder::MergeIntoLabel(
    Label* label, BasicBlock* predecessor) {
  BorrowParentKnownNodeAspectsAndVOs borrow(this);

  if (label->merge_state_ == nullptr) {
    // If there's no merge state, allocate a new one.
    label->merge_state_ = MergePointInterpreterFrameState::New(
        *compilation_unit_, pseudo_frame_, 0, label->predecessor_count_,
        predecessor, label->liveness_);
  } else {
    // If there already is a frame state, merge.
    label->merge_state_->Merge(builder_, *compilation_unit_, pseudo_frame_,
                               predecessor);
  }
}

MaglevGraphBuilder::MaglevGraphBuilder(
    LocalIsolate* local_isolate, MaglevCompilationUnit* compilation_unit,
    Graph* graph, float call_frequency, BytecodeOffset caller_bytecode_offset,
    bool caller_is_inside_loop, int inlining_id, MaglevGraphBuilder* parent)
    : local_isolate_(local_isolate),
      compilation_unit_(compilation_unit),
      parent_(parent),
      graph_(graph),
      bytecode_analysis_(bytecode().object(), zone(),
                         compilation_unit->osr_offset(), true),
      iterator_(bytecode().object()),
      source_position_iterator_(bytecode().SourcePositionTable(broker())),
      allow_loop_peeling_(v8_flags.maglev_loop_peeling),
      loop_effects_stack_(zone()),
      decremented_predecessor_offsets_(zone()),
      loop_headers_to_peel_(bytecode().length(), zone()),
      current_source_position_(SourcePosition(
          compilation_unit_->shared_function_info().StartPosition(),
          inlining_id)),
      call_frequency_(call_frequency),
      // Add an extra jump_target slot for the inline exit if needed.
      jump_targets_(zone()->AllocateArray<BasicBlockRef>(
          bytecode().length() + (is_inline() ? 1 : 0))),
      // Overallocate merge_states_ by one to allow always looking up the
      // next offset. This overallocated slot can also be used for the inline
      // exit when needed.
      merge_states_(zone()->AllocateArray<MergePointInterpreterFrameState*>(
          bytecode().length() + 1)),
      current_interpreter_frame_(
          *compilation_unit_,
          is_inline() ? parent->current_interpreter_frame_.known_node_aspects()
                      : compilation_unit_->zone()->New<KnownNodeAspects>(
                            compilation_unit_->zone()),
          is_inline() ? parent->current_interpreter_frame_.virtual_objects()
                      : VirtualObject::List()),
      caller_bytecode_offset_(caller_bytecode_offset),
      caller_is_inside_loop_(caller_is_inside_loop),
      entrypoint_(compilation_unit->is_osr()
                      ? bytecode_analysis_.osr_entry_point()
                      : 0),
      inlining_id_(inlining_id),
      catch_block_stack_(zone()),
      unobserved_context_slot_stores_(zone()) {
  memset(merge_states_, 0,
         (bytecode().length() + 1) * sizeof(InterpreterFrameState*));
  // Default construct basic block refs.
  // TODO(leszeks): This could be a memset of nullptr to ..._jump_targets_.
  for (int i = 0; i < bytecode().length(); ++i) {
    new (&jump_targets_[i]) BasicBlockRef();
  }

  if (is_inline()) {
    DCHECK_NOT_NULL(parent_);
    DCHECK_GT(compilation_unit->inlining_depth(), 0);
    // The allocation/initialisation logic here relies on inline_exit_offset
    // being the offset one past the end of the bytecode.
    DCHECK_EQ(inline_exit_offset(), bytecode().length());
    merge_states_[inline_exit_offset()] = nullptr;
    new (&jump_targets_[inline_exit_offset()]) BasicBlockRef();
    if (parent_->loop_effects_) {
      loop_effects_ = parent->loop_effects_;
      loop_effects_stack_.push_back(loop_effects_);
    }
    unobserved_context_slot_stores_ = parent_->unobserved_context_slot_stores_;
  }

  CHECK_IMPLIES(compilation_unit_->is_osr(), graph_->is_osr());
  CHECK_EQ(compilation_unit_->info()->toplevel_osr_offset() !=
               BytecodeOffset::None(),
           graph_->is_osr());
  if (compilation_unit_->is_osr()) {
    CHECK(!is_inline());
#ifdef DEBUG
    // OSR'ing into the middle of a loop is currently not supported. There
    // should not be any issue with OSR'ing outside of loops, just we currently
    // dont do it...
    iterator_.SetOffset(compilation_unit_->osr_offset().ToInt());
    DCHECK_EQ(iterator_.current_bytecode(), interpreter::Bytecode::kJumpLoop);
    DCHECK_EQ(entrypoint_, iterator_.GetJumpTargetOffset());
    iterator_.SetOffset(entrypoint_);
#endif

    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "- Non-standard entrypoint @" << entrypoint_
                << " by OSR from @" << compilation_unit_->osr_offset().ToInt()
                << std::endl;
    }
  }
  CHECK_IMPLIES(!compilation_unit_->is_osr(), entrypoint_ == 0);

  CalculatePredecessorCounts();
}

void MaglevGraphBuilder::StartPrologue() {
  current_block_ = zone()->New<BasicBlock>(nullptr, zone());
}

BasicBlock* MaglevGraphBuilder::EndPrologue() {
  BasicBlock* first_block;
  if (!is_inline() &&
      (v8_flags.maglev_hoist_osr_value_phi_untagging && graph_->is_osr())) {
    first_block =
        FinishBlock<CheckpointedJump>({}, &jump_targets_[entrypoint_]);
  } else {
    first_block = FinishBlock<Jump>({}, &jump_targets_[entrypoint_]);
  }
  MergeIntoFrameState(first_block, entrypoint_);
  return first_block;
}

void MaglevGraphBuilder::SetArgument(int i, ValueNode* value) {
  interpreter::Register reg = interpreter::Register::FromParameterIndex(i);
  current_interpreter_frame_.set(reg, value);
}

ValueNode* MaglevGraphBuilder::GetArgument(int i) {
  DCHECK_LT(i, parameter_count());
  interpreter::Register reg = interpreter::Register::FromParameterIndex(i);
  return current_interpreter_frame_.get(reg);
}

ValueNode* MaglevGraphBuilder::GetInlinedArgument(int i) {
  DCHECK(is_inline());
  DCHECK_LT(i, argument_count());
  return inlined_arguments_[i];
}

void MaglevGraphBuilder::InitializeRegister(interpreter::Register reg,
                                            ValueNode* value) {
  current_interpreter_frame_.set(
      reg, value ? value : AddNewNode<InitialValue>({}, reg));
}

void MaglevGraphBuilder::BuildRegisterFrameInitialization(
    ValueNode* context, ValueNode* closure, ValueNode* new_target) {
  if (closure == nullptr &&
      compilation_unit_->info()->specialize_to_function_context()) {
    compiler::JSFunctionRef function = compiler::MakeRefAssumeMemoryFence(
        broker(), broker()->CanonicalPersistentHandle(
                      compilation_unit_->info()->toplevel_function()));
    closure = GetConstant(function);
    context = GetConstant(function.context(broker()));
  }
  InitializeRegister(interpreter::Register::current_context(), context);
  InitializeRegister(interpreter::Register::function_closure(), closure);

  interpreter::Register new_target_or_generator_register =
      bytecode().incoming_new_target_or_generator_register();

  int register_index = 0;

  if (compilation_unit_->is_osr()) {
    for (; register_index < register_count(); register_index++) {
      auto val =
          AddNewNode<InitialValue>({}, interpreter::Register(register_index));
      InitializeRegister(interpreter::Register(register_index), val);
      graph_->osr_values().push_back(val);
    }
    return;
  }

  // TODO(leszeks): Don't emit if not needed.
  ValueNode* undefined_value = GetRootConstant(RootIndex::kUndefinedValue);
  if (new_target_or_generator_register.is_valid()) {
    int new_target_index = new_target_or_generator_register.index();
    for (; register_index < new_target_index; register_index++) {
      current_interpreter_frame_.set(interpreter::Register(register_index),
                                     undefined_value);
    }
    current_interpreter_frame_.set(
        new_target_or_generator_register,
        new_target ? new_target
                   : GetRegisterInput(kJavaScriptCallNewTargetRegister));
    register_index++;
  }
  for (; register_index < register_count(); register_index++) {
    InitializeRegister(interpreter::Register(register_index), undefined_value);
  }
}

void MaglevGraphBuilder::BuildMergeStates() {
  auto offset_and_info = bytecode_analysis().GetLoopInfos().begin();
  auto end = bytecode_analysis().GetLoopInfos().end();
  while (offset_and_info != end && offset_and_info->first < entrypoint_) {
    ++offset_and_info;
  }
  for (; offset_and_info != end; ++offset_and_info) {
    int offset = offset_and_info->first;
    const compiler::LoopInfo& loop_info = offset_and_info->second;
    if (loop_headers_to_peel_.Contains(offset)) {
      // Peeled loops are treated like normal merges at first. We will construct
      // the proper loop header merge state when reaching the `JumpLoop` of the
      // peeled iteration.
      continue;
    }
    const compiler::BytecodeLivenessState* liveness = GetInLivenessFor(offset);
    DCHECK_NULL(merge_states_[offset]);
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "- Creating loop merge state at @" << offset << std::endl;
    }
    merge_states_[offset] = MergePointInterpreterFrameState::NewForLoop(
        current_interpreter_frame_, *compilation_unit_, offset,
        predecessor_count(offset), liveness, &loop_info);
  }

  if (bytecode().handler_table_size() > 0) {
    HandlerTable table(*bytecode().object());
    for (int i = 0; i < table.NumberOfRangeEntries(); i++) {
      const int offset = table.GetRangeHandler(i);
      const bool was_used = table.HandlerWasUsed(i);
      const interpreter::Register context_reg(table.GetRangeData(i));
      const compiler::BytecodeLivenessState* liveness =
          GetInLivenessFor(offset);
      DCHECK_EQ(predecessor_count(offset), 0);
      DCHECK_NULL(merge_states_[offset]);
      if (v8_flags.trace_maglev_graph_building) {
        std::cout << "- Creating exception merge state at @" << offset
                  << (was_used ? "" : " (never used)") << ", context register r"
                  << context_reg.index() << std::endl;
      }
      merge_states_[offset] = MergePointInterpreterFrameState::NewForCatchBlock(
          *compilation_unit_, liveness, offset, was_used, context_reg, graph_);
    }
  }
}

namespace {

template <int index, interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper;

// Terminal cases
template <int index>
struct GetResultLocationAndSizeHelper<index> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    // TODO(leszeks): This should probably actually be "UNREACHABLE" but we have
    // lazy deopt info for interrupt budget updates at returns, not for actual
    // lazy deopts, but just for stack iteration purposes.
    return {interpreter::Register::invalid_value(), 0};
  }
  static bool HasOutputRegisterOperand() { return false; }
};

template <int index, interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper<index, interpreter::OperandType::kRegOut,
                                      operands...> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    // We shouldn't have any other output operands than this one.
    return {iterator.GetRegisterOperand(index), 1};
  }
  static bool HasOutputRegisterOperand() { return true; }
};

template <int index, interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper<
    index, interpreter::OperandType::kRegOutPair, operands...> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    // We shouldn't have any other output operands than this one.
    return {iterator.GetRegisterOperand(index), 2};
  }
  static bool HasOutputRegisterOperand() { return true; }
};

template <int index, interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper<
    index, interpreter::OperandType::kRegOutTriple, operands...> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    // We shouldn't have any other output operands than this one.
    DCHECK(!(GetResultLocationAndSizeHelper<
             index + 1, operands...>::HasOutputRegisterOperand()));
    return {iterator.GetRegisterOperand(index), 3};
  }
  static bool HasOutputRegisterOperand() { return true; }
};

// We don't support RegOutList for lazy deopts.
template <int index, interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper<
    index, interpreter::OperandType::kRegOutList, operands...> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    interpreter::RegisterList list = iterator.GetRegisterListOperand(index);
    return {list.first_register(), list.register_count()};
  }
  static bool HasOutputRegisterOperand() { return true; }
};

// Induction case.
template <int index, interpreter::OperandType operand,
          interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper<index, operand, operands...> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    return GetResultLocationAndSizeHelper<
        index + 1, operands...>::GetResultLocationAndSize(iterator);
  }
  static bool HasOutputRegisterOperand() {
    return GetResultLocationAndSizeHelper<
        index + 1, operands...>::HasOutputRegisterOperand();
  }
};

template <interpreter::Bytecode bytecode,
          interpreter::ImplicitRegisterUse implicit_use,
          interpreter::OperandType... operands>
std::pair<interpreter::Register, int> GetResultLocationAndSizeForBytecode(
    const interpreter::BytecodeArrayIterator& iterator) {
  // We don't support output registers for implicit registers.
  DCHECK(!interpreter::BytecodeOperands::WritesImplicitRegister(implicit_use));
  if (interpreter::BytecodeOperands::WritesAccumulator(implicit_use)) {
    // If we write the accumulator, we shouldn't also write an output register.
    DCHECK(!(GetResultLocationAndSizeHelper<
             0, operands...>::HasOutputRegisterOperand()));
    return {interpreter::Register::virtual_accumulator(), 1};
  }

  // Use template magic to output a the appropriate GetRegisterOperand call and
  // size for this bytecode.
  return GetResultLocationAndSizeHelper<
      0, operands...>::GetResultLocationAndSize(iterator);
}

}  // namespace

std::pair<interpreter::Register, int>
MaglevGraphBuilder::GetResultLocationAndSize() const {
  using Bytecode = interpreter::Bytecode;
  using OperandType = interpreter::OperandType;
  using ImplicitRegisterUse = interpreter::ImplicitRegisterUse;
  Bytecode bytecode = iterator_.current_bytecode();
  // TODO(leszeks): Only emit these cases for bytecodes we know can lazy deopt.
  switch (bytecode) {
#define CASE(Name, ...)                                           \
  case Bytecode::k##Name:                                         \
    return GetResultLocationAndSizeForBytecode<Bytecode::k##Name, \
                                               __VA_ARGS__>(iterator_);
    BYTECODE_LIST(CASE, CASE)
#undef CASE
  }
  UNREACHABLE();
}

#ifdef DEBUG
bool MaglevGraphBuilder::HasOutputRegister(interpreter::Register reg) const {
  interpreter::Bytecode bytecode = iterator_.current_bytecode();
  if (reg == interpreter::Register::virtual_accumulator()) {
    return interpreter::Bytecodes::WritesAccumulator(bytecode);
  }
  for (int i = 0; i < interpreter::Bytecodes::NumberOfOperands(bytecode); ++i) {
    if (interpreter::Bytecodes::IsRegisterOutputOperandType(
            interpreter::Bytecodes::GetOperandType(bytecode, i))) {
      interpreter::Register operand_reg = iterator_.GetRegisterOperand(i);
      int operand_range = iterator_.GetRegisterOperandRange(i);
      if (base::IsInRange(reg.index(), operand_reg.index(),
                          operand_reg.index() + operand_range)) {
        return true;
      }
    }
  }
  return false;
}
#endif

DeoptFrame* MaglevGraphBuilder::GetParentDeoptFrame() {
  if (parent_ == nullptr) return nullptr;
  if (parent_deopt_frame_ == nullptr) {
    // The parent resumes after the call, which is roughly equivalent to a lazy
    // deopt. Use the helper function directly so that we can mark the
    // accumulator as dead (since it'll be overwritten by this function's
    // return value anyway).
    // TODO(leszeks): This is true for our current set of
    // inlinings/continuations, but there might be cases in the future where it
    // isn't. We may need to store the relevant overwritten register in
    // LazyDeoptFrameScope.
    DCHECK(interpreter::Bytecodes::WritesAccumulator(
        parent_->iterator_.current_bytecode()));

    parent_deopt_frame_ =
        zone()->New<DeoptFrame>(parent_->GetDeoptFrameForLazyDeoptHelper(
            interpreter::Register::invalid_value(), 0,
            parent_->current_deopt_scope_, true));
    // Only create InlinedArgumentsDeoptFrame if we have a mismatch between
    // formal parameter and arguments count.
    if (HasMismatchedArgumentAndParameterCount()) {
      parent_deopt_frame_ = zone()->New<InlinedArgumentsDeoptFrame>(
          *compilation_unit_, caller_bytecode_offset_, GetClosure(),
          inlined_arguments_, parent_deopt_frame_);
      AddDeoptUse(GetClosure());
      for (ValueNode* arg :
           parent_deopt_frame_->as_inlined_arguments().arguments()) {
        AddDeoptUse(arg);
      }
    }
  }
  return parent_deopt_frame_;
}

DeoptFrame MaglevGraphBuilder::GetLatestCheckpointedFrame() {
  if (in_prologue_) {
    return GetDeoptFrameForEntryStackCheck();
  }
  if (!latest_checkpointed_frame_) {
    current_interpreter_frame_.virtual_objects().Snapshot();
    latest_checkpointed_frame_.emplace(InterpretedDeoptFrame(
        *compilation_unit_,
        zone()->New<CompactInterpreterFrameState>(
            *compilation_unit_, GetInLiveness(), current_interpreter_frame_),
        GetClosure(), BytecodeOffset(iterator_.current_offset()),
        current_source_position_, GetParentDeoptFrame()));

    latest_checkpointed_frame_->as_interpreted().frame_state()->ForEachValue(
        *compilation_unit_,
        [&](ValueNode* node, interpreter::Register) { AddDeoptUse(node); });
    AddDeoptUse(latest_checkpointed_frame_->as_interpreted().closure());

    // Skip lazy deopt builtin continuations.
    const DeoptFrameScope* deopt_scope = current_deopt_scope_;
    while (deopt_scope != nullptr &&
           deopt_scope->IsLazyDeoptContinuationFrame()) {
      deopt_scope = deopt_scope->parent();
    }

    if (deopt_scope != nullptr) {
      // Support exactly one eager deopt builtin continuation. This can be
      // expanded in the future if necessary.
      DCHECK_NULL(deopt_scope->parent());
      DCHECK_EQ(deopt_scope->data().tag(),
                DeoptFrame::FrameType::kBuiltinContinuationFrame);
#ifdef DEBUG
      if (deopt_scope->data().tag() ==
          DeoptFrame::FrameType::kBuiltinContinuationFrame) {
        const DeoptFrame::BuiltinContinuationFrameData& frame =
            deopt_scope->data().get<DeoptFrame::BuiltinContinuationFrameData>();
        if (frame.maybe_js_target) {
          int stack_parameter_count =
              Builtins::GetStackParameterCount(frame.builtin_id);
          DCHECK_EQ(stack_parameter_count, frame.parameters.length());
        } else {
          CallInterfaceDescriptor descriptor =
              Builtins::CallInterfaceDescriptorFor(frame.builtin_id);
          DCHECK_EQ(descriptor.GetParameterCount(), frame.parameters.length());
        }
      }
#endif

      // Wrap the above frame in the scope frame.
      latest_checkpointed_frame_.emplace(
          deopt_scope->data(),
          zone()->New<DeoptFrame>(*latest_checkpointed_frame_));
    }
  }
  return *latest_checkpointed_frame_;
}

DeoptFrame MaglevGraphBuilder::GetDeoptFrameForLazyDeopt(
    interpreter::Register result_location, int result_size) {
  return GetDeoptFrameForLazyDeoptHelper(result_location, result_size,
                                         current_deopt_scope_, false);
}

DeoptFrame MaglevGraphBuilder::GetDeoptFrameForLazyDeoptHelper(
    interpreter::Register result_location, int result_size,
    DeoptFrameScope* scope, bool mark_accumulator_dead) {
  if (scope == nullptr) {
    compiler::BytecodeLivenessState* liveness =
        zone()->New<compiler::BytecodeLivenessState>(*GetOutLiveness(), zone());
    // Remove result locations from liveness.
    if (result_location == interpreter::Register::virtual_accumulator()) {
      DCHECK_EQ(result_size, 1);
      liveness->MarkAccumulatorDead();
      mark_accumulator_dead = false;
    } else {
      DCHECK(!result_location.is_parameter());
      for (int i = 0; i < result_size; i++) {
        liveness->MarkRegisterDead(result_location.index() + i);
      }
    }
    // Explicitly drop the accumulator if needed.
    if (mark_accumulator_dead && liveness->AccumulatorIsLive()) {
      liveness->MarkAccumulatorDead();
    }
    current_interpreter_frame_.virtual_objects().Snapshot();
    InterpretedDeoptFrame ret(
        *compilation_unit_,
        zone()->New<CompactInterpreterFrameState>(*compilation_unit_, liveness,
                                                  current_interpreter_frame_),
        GetClosure(), BytecodeOffset(iterator_.current_offset()),
        current_source_position_, GetParentDeoptFrame());
    ret.frame_state()->ForEachValue(
        *compilation_unit_, [this](ValueNode* node, interpreter::Register reg) {
          // Receiver and closure values have to be materialized, even if
          // they don't otherwise escape.
          if (reg == interpreter::Register::receiver() ||
              reg == interpreter::Register::function_closure()) {
            node->add_use();
          } else {
            AddDeoptUse(node);
          }
        });
    AddDeoptUse(ret.closure());
    return ret;
  }

  // Currently only support builtin continuations for bytecodes that write to
  // the accumulator
  DCHECK(interpreter::Bytecodes::WritesOrClobbersAccumulator(
      iterator_.current_bytecode()));

#ifdef DEBUG
  if (scope->data().tag() == DeoptFrame::FrameType::kBuiltinContinuationFrame) {
    const DeoptFrame::BuiltinContinuationFrameData& frame =
        current_deopt_scope_->data()
            .get<DeoptFrame::BuiltinContinuationFrameData>();
    if (frame.maybe_js_target) {
      int stack_parameter_count =
          Builtins::GetStackParameterCount(frame.builtin_id);
      // The deopt input value is passed by the deoptimizer, so shouldn't be a
      // parameter here.
      DCHECK_EQ(stack_parameter_count, frame.parameters.length() + 1);
    } else {
      CallInterfaceDescriptor descriptor =
          Builtins::CallInterfaceDescriptorFor(frame.builtin_id);
      // The deopt input value is passed by the deoptimizer, so shouldn't be a
      // parameter here.
      DCHECK_EQ(descriptor.GetParameterCount(), frame.parameters.length() + 1);
      // The deopt input value is passed on the stack.
      DCHECK_GT(descriptor.GetStackParameterCount(), 0);
    }
  }
#endif

  // Mark the accumulator dead in parent frames since we know that the
  // continuation will write it.
  return DeoptFrame(scope->data(),
                    zone()->New<DeoptFrame>(GetDeoptFrameForLazyDeoptHelper(
                        result_location, result_size, scope->parent(),
                        scope->data().tag() ==
                            DeoptFrame::FrameType::kBuiltinContinuationFrame)));
}

InterpretedDeoptFrame MaglevGraphBuilder::GetDeoptFrameForEntryStackCheck() {
  if (entry_stack_check_frame_) return *entry_stack_check_frame_;
  DCHECK_EQ(iterator_.current_offset(), entrypoint_);
  DCHECK_NULL(parent_);
  entry_stack_check_frame_.emplace(
      *compilation_unit_,
      zone()->New<CompactInterpreterFrameState>(
          *compilation_unit_,
          GetInLivenessFor(graph_->is_osr() ? bailout_for_entrypoint() : 0),
          current_interpreter_frame_),
      GetClosure(), BytecodeOffset(bailout_for_entrypoint()),
      current_source_position_, nullptr);

  (*entry_stack_check_frame_)
      .frame_state()
      ->ForEachValue(
          *compilation_unit_,
          [&](ValueNode* node, interpreter::Register) { AddDeoptUse(node); });
  AddDeoptUse((*entry_stack_check_frame_).closure());
  return *entry_stack_check_frame_;
}

ValueNode* MaglevGraphBuilder::GetTaggedValue(
    ValueNode* value, UseReprHintRecording record_use_repr_hint) {
  if (V8_LIKELY(record_use_repr_hint == UseReprHintRecording::kRecord)) {
    RecordUseReprHintIfPhi(value, UseRepresentation::kTagged);
  }

  ValueRepresentation representation =
      value->properties().value_representation();
  if (representation == ValueRepresentation::kTagged) return value;

  if (Int32Constant* as_int32_constant = value->TryCast<Int32Constant>();
      as_int32_constant && Smi::IsValid(as_int32_constant->value())) {
    return GetSmiConstant(as_int32_constant->value());
  }

  NodeInfo* node_info = GetOrCreateInfoFor(value);
  auto& alternative = node_info->alternative();

  if (ValueNode* alt = alternative.tagged()) {
    return alt;
  }

  switch (representation) {
    case ValueRepresentation::kInt32: {
      if (NodeTypeIsSmi(node_info->type())) {
        return alternative.set_tagged(AddNewNode<UnsafeSmiTagInt32>({value}));
      }
      return alternative.set_tagged(AddNewNode<Int32ToNumber>({value}));
    }
    case ValueRepresentation::kUint32: {
      if (NodeTypeIsSmi(node_info->type())) {
        return alternative.set_tagged(AddNewNode<UnsafeSmiTagUint32>({value}));
      }
      return alternative.set_tagged(AddNewNode<Uint32ToNumber>({value}));
    }
    case ValueRepresentation::kFloat64: {
      return alternative.set_tagged(AddNewNode<Float64ToTagged>(
          {value}, Float64ToTagged::ConversionMode::kCanonicalizeSmi));
    }
    case ValueRepresentation::kHoleyFloat64: {
      return alternative.set_tagged(AddNewNode<HoleyFloat64ToTagged>(
          {value}, HoleyFloat64ToTagged::ConversionMode::kForceHeapNumber));
    }

    case ValueRepresentation::kTagged:
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
  UNREACHABLE();
}

ReduceResult MaglevGraphBuilder::GetSmiValue(
    ValueNode* value, UseReprHintRecording record_use_repr_hint) {
  if (V8_LIKELY(record_use_repr_hint == UseReprHintRecording::kRecord)) {
    RecordUseReprHintIfPhi(value, UseRepresentation::kTagged);
  }

  NodeInfo* node_info = GetOrCreateInfoFor(value);

  ValueRepresentation representation =
      value->properties().value_representation();
  if (representation == ValueRepresentation::kTagged) {
    return BuildCheckSmi(value, !value->Is<Phi>());
  }

  auto& alternative = node_info->alternative();

  if (ValueNode* alt = alternative.tagged()) {
    // HoleyFloat64ToTagged does not canonicalize Smis by default, since it can
    // be expensive. If we are reading a Smi value, we should try to
    // canonicalize now.
    if (HoleyFloat64ToTagged* conversion_node =
            alt->TryCast<HoleyFloat64ToTagged>()) {
      conversion_node->SetMode(
          HoleyFloat64ToTagged::ConversionMode::kCanonicalizeSmi);
    }
    return BuildCheckSmi(alt, !value->Is<Phi>());
  }

  switch (representation) {
    case ValueRepresentation::kInt32: {
      if (NodeTypeIsSmi(node_info->type())) {
        return alternative.set_tagged(AddNewNode<UnsafeSmiTagInt32>({value}));
      }
      return alternative.set_tagged(AddNewNode<CheckedSmiTagInt32>({value}));
    }
    case ValueRepresentation::kUint32: {
      if (NodeTypeIsSmi(node_info->type())) {
        return alternative.set_tagged(AddNewNode<UnsafeSmiTagUint32>({value}));
      }
      return alternative.set_tagged(AddNewNode<CheckedSmiTagUint32>({value}));
    }
    case ValueRepresentation::kFloat64: {
      return alternative.set_tagged(AddNewNode<CheckedSmiTagFloat64>({value}));
    }
    case ValueRepresentation::kHoleyFloat64: {
      return alternative.set_tagged(AddNewNode<CheckedSmiTagFloat64>({value}));
    }

    case ValueRepresentation::kTagged:
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
  UNREACHABLE();
}

namespace {
CheckType GetCheckType(NodeType type) {
  return NodeTypeIs(type, NodeType::kAnyHeapObject)
             ? CheckType::kOmitHeapObjectCheck
             : CheckType::kCheckHeapObject;
}
}  // namespace

ValueNode* MaglevGraphBuilder::GetInternalizedString(
    interpreter::Register reg) {
  ValueNode* node = current_interpreter_frame_.get(reg);
  NodeType old_type;
  if (CheckType(node, NodeType::kInternalizedString, &old_type)) return node;
  NodeInfo* known_info = GetOrCreateInfoFor(node);
  if (known_info->alternative().checked_value()) {
    node = known_info->alternative().checked_value();
    if (CheckType(node, NodeType::kInternalizedString, &old_type)) return node;
  }

  if (!NodeTypeIs(old_type, NodeType::kString)) {
    known_info->CombineType(NodeType::kString);
  }

  // This node may unwrap ThinStrings.
  ValueNode* maybe_unwrapping_node =
      AddNewNode<CheckedInternalizedString>({node}, GetCheckType(old_type));
  known_info->alternative().set_checked_value(maybe_unwrapping_node);

  current_interpreter_frame_.set(reg, maybe_unwrapping_node);
  return maybe_unwrapping_node;
}

namespace {
NodeType ToNumberHintToNodeType(ToNumberHint conversion_type) {
  switch (conversion_type) {
    case ToNumberHint::kAssumeSmi:
      return NodeType::kSmi;
    case ToNumberHint::kDisallowToNumber:
    case ToNumberHint::kAssumeNumber:
      return NodeType::kNumber;
    case ToNumberHint::kAssumeNumberOrBoolean:
      return NodeType::kNumberOrBoolean;
    case ToNumberHint::kAssumeNumberOrOddball:
      return NodeType::kNumberOrOddball;
  }
}
TaggedToFloat64ConversionType ToNumberHintToConversionType(
    ToNumberHint conversion_type) {
  switch (conversion_type) {
    case ToNumberHint::kAssumeSmi:
      UNREACHABLE();
    case ToNumberHint::kDisallowToNumber:
    case ToNumberHint::kAssumeNumber:
      return TaggedToFloat64ConversionType::kOnlyNumber;
    case ToNumberHint::kAssumeNumberOrOddball:
      return TaggedToFloat64ConversionType::kNumberOrOddball;
    case ToNumberHint::kAssumeNumberOrBoolean:
      return TaggedToFloat64ConversionType::kNumberOrBoolean;
  }
}
}  // namespace

ValueNode* MaglevGraphBuilder::GetTruncatedInt32ForToNumber(ValueNode* value,
                                                            ToNumberHint hint) {
  RecordUseReprHintIfPhi(value, UseRepresentation::kTruncatedInt32);

  ValueRepresentation representation =
      value->properties().value_representation();
  if (representation == ValueRepresentation::kInt32) return value;
  if (representation == ValueRepresentation::kUint32) {
    // This node is cheap (no code gen, just a bitcast), so don't cache it.
    return AddNewNode<TruncateUint32ToInt32>({value});
  }

  // Process constants first to avoid allocating NodeInfo for them.
  switch (value->opcode()) {
    case Opcode::kConstant: {
      compiler::ObjectRef object = value->Cast<Constant>()->object();
      if (!object.IsHeapNumber()) break;
      int32_t truncated_value = DoubleToInt32(object.AsHeapNumber().value());
      if (!Smi::IsValid(truncated_value)) break;
      return GetInt32Constant(truncated_value);
    }
    case Opcode::kSmiConstant:
      return GetInt32Constant(value->Cast<SmiConstant>()->value().value());
    case Opcode::kRootConstant: {
      Tagged<Object> root_object =
          local_isolate_->root(value->Cast<RootConstant>()->index());
      if (!IsOddball(root_object, local_isolate_)) break;
      int32_t truncated_value =
          DoubleToInt32(Cast<Oddball>(root_object)->to_number_raw());
      // All oddball ToNumber truncations are valid Smis.
      DCHECK(Smi::IsValid(truncated_value));
      return GetInt32Constant(truncated_value);
    }
    case Opcode::kFloat64Constant: {
      int32_t truncated_value =
          DoubleToInt32(value->Cast<Float64Constant>()->value().get_scalar());
      if (!Smi::IsValid(truncated_value)) break;
      return GetInt32Constant(truncated_value);
    }

    // We could emit unconditional eager deopts for other kinds of constant, but
    // it's not necessary, the appropriate checking conversion nodes will deopt.
    default:
      break;
  }

  NodeInfo* node_info = GetOrCreateInfoFor(value);
  auto& alternative = node_info->alternative();

  // If there is an int32_alternative, then that works as a truncated value
  // too.
  if (ValueNode* alt = alternative.int32()) {
    return alt;
  }
  if (ValueNode* alt = alternative.truncated_int32_to_number()) {
    return alt;
  }

  switch (representation) {
    case ValueRepresentation::kTagged: {
      NodeType old_type;
      NodeType desired_type = ToNumberHintToNodeType(hint);
      EnsureType(value, desired_type, &old_type);
      if (NodeTypeIsSmi(old_type)) {
        // Smi untagging can be cached as an int32 alternative, not just a
        // tr
"""


```