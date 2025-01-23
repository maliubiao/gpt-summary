Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the summary.

**1. Initial Understanding and Goal:**

The core request is to understand the functionality of the `v8/src/maglev/maglev-graph-builder.cc` file in V8. The output should specifically address the points mentioned in the prompt: is it Torque, its relationship to JavaScript, code logic examples, common programming errors it might help avoid, and a high-level summary. The prompt also emphasizes that this is the *first part* of a larger file.

**2. Keyword Spotting and Core Concepts:**

Scanning the includes and the namespace (`v8::internal::maglev`) immediately reveals key terms:

* **`maglev`**: This is a V8 optimization technique, likely an intermediate representation or compiler tier.
* **`graph-builder`**:  Suggests the code's primary purpose is to construct a graph data structure. This graph likely represents the program's execution flow or data dependencies.
* **Includes like `<algorithm>`, `<utility>`, `<vector>`**: Standard C++ library usage, indicating general-purpose programming.
* **Includes like `"src/compiler/*"` and `"src/interpreter/*"`**:  Strongly suggest a connection to the V8 compiler and interpreter pipelines.
* **Specific V8 classes like `MaglevCompilationUnit`, `InterpreterFrameState`, `BasicBlock`, `ValueNode`**: These are core building blocks of the Maglev system, confirming the graph construction hypothesis.
* **`Builtin`, `Runtime`**: These refer to V8's built-in functions and runtime calls, showing how Maglev interacts with the JavaScript engine's core functionalities.
* **`DeoptFrame`**:  Indicates support for deoptimization, a mechanism to fall back to the interpreter when optimizations become invalid.
* **`CallArguments`**:  Clearly relates to managing arguments during function calls.
* **`Label`, `Variable` within `MaglevSubGraphBuilder`**:  Points towards a mechanism for structured control flow within the graph building process.

**3. Inferring Core Functionality (Graph Construction):**

Based on the keywords, the most likely primary function is to take some form of input (likely bytecode from the interpreter) and construct a directed graph representation. The nodes in this graph probably represent operations or instructions, and the edges represent control flow or data flow.

**4. Addressing Specific Prompt Points:**

* **Torque:** The prompt explicitly asks about the `.tq` extension. The provided snippet has a `.cc` extension, so it's C++, not Torque.

* **JavaScript Relationship:**  The presence of compiler and interpreter related includes, as well as terms like "builtins," "runtime," and the handling of function calls, strongly links this code to the execution of JavaScript. The graph being built is likely a representation of JavaScript code.

* **JavaScript Example (Illustrative):** To demonstrate the connection to JavaScript, a simple function example is needed. A function with basic operations (like addition or property access) is a good choice, as it can be easily visualized how bytecode for such a function would be transformed into a graph.

* **Code Logic Inference (Hypothetical Input/Output):**  Since this is a graph *builder*, a good example would be how it handles a simple conditional statement. The input would be bytecode for an `if` statement, and the output would be a graph structure with branches representing the `then` and `else` blocks. This highlights the control flow aspect of the graph.

* **Common Programming Errors:**  Considering the context of optimization and intermediate representation, common errors related to type assumptions, incorrect handling of side effects, or overly aggressive optimizations leading to deoptimization are relevant examples.

* **Part 1 Summary:**  The summary should consolidate the key findings: it's a C++ file for building a graph in the Maglev compiler, related to JavaScript optimization, and handles various aspects of program execution like function calls and control flow.

**5. Analyzing Key Classes and Structures:**

The code contains several important classes. Understanding their roles helps in summarizing the overall functionality:

* **`MaglevGraphBuilder`**: The central class responsible for the entire graph construction process. It likely holds the state of the graph being built.
* **`CallArguments`**:  Manages the arguments for function calls, including handling the `this` receiver and spread syntax.
* **`DeoptFrameScope`**: Manages the creation of "deoptimization frames," which are used when an optimized code path needs to revert to the interpreter.
* **`MaglevSubGraphBuilder`**:  A helper class for building sub-graphs, likely used for handling control flow structures or nested expressions. The `Label` and `Variable` classes within it are key for this.
* **`BranchBuilder`**:  Specifically handles the creation of conditional branches in the graph.

**6. Refining the Summary:**

The initial summary can be refined by incorporating details about the key classes and their roles. For instance, mentioning that it handles function calls, control flow (with labels), and deoptimization adds more depth.

**7. Iteration and Review:**

After drafting the initial summary and examples, reviewing them against the original code and the prompt ensures accuracy and completeness. For example, checking that the JavaScript example aligns with the explained functionality. Verifying that the code logic example makes sense in the context of graph building.

By following these steps, combining keyword analysis, structural understanding, and a systematic approach to addressing the prompt's requirements, we can arrive at a comprehensive and accurate summary of the `v8/src/maglev/maglev-graph-builder.cc` file's functionality.
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能,
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共18部分，请归纳一下它的功能
```

根据提供的代码片段，`v8/src/maglev/maglev-graph-builder.cc` 是一个 **C++** 源代码文件 (以 `.cc` 结尾)。它属于 V8 JavaScript 引擎的 `maglev` 组件，其主要功能是 **构建 Maglev 图**。

以下是基于代码片段的功能归纳：

**主要功能：构建 Maglev 执行图**

该文件定义了 `MaglevGraphBuilder` 类，该类负责将 JavaScript 代码的中间表示（可能是字节码）转换为 Maglev 执行图。Maglev 是 V8 的一个中间编译器，旨在提供比解释器更高的性能，但比完整优化编译器（TurboFan）更快的编译速度。

**核心功能点：**

1. **图节点创建和连接:**  `MaglevGraphBuilder` 提供了一系列方法来创建表示不同操作的节点（例如 `ValueNode`、`BasicBlock`）并将它们连接起来，形成执行图。

2. **处理字节码:** 代码中包含对 `interpreter::BytecodeArrayIterator` 和 `interpreter::bytecodes.h` 的引用，表明 `MaglevGraphBuilder` 会遍历 JavaScript 字节码并为其生成图结构。

3. **管理执行上下文:**  代码中多次出现 `Context` 和相关操作（例如 `GetContext()`, `TryGetParentContext()`, `EscapeContext()`），说明 `MaglevGraphBuilder` 负责处理 JavaScript 的词法作用域和上下文。

4. **函数调用支持:**  `CallArguments` 类用于处理函数调用的参数，包括 receiver 的处理和 spread 运算符的支持。

5. **控制流构建:**  `Label`、`MaglevSubGraphBuilder` 和 `BranchBuilder` 等类用于构建图的控制流，例如条件分支和循环。

6. **Deoptimization 支持:**  `DeoptFrameScope` 类用于处理去优化（deoptimization），这发生在 Maglev 无法继续执行优化的代码时，需要回退到解释器执行。

7. **类型推断和优化暗示:** 代码中包含对 `compiler::FeedbackSource` 和 `compiler::ProcessedFeedback` 的使用，表明 `MaglevGraphBuilder` 会利用 V8 的反馈机制来获取类型信息，并可能进行一些基于反馈的优化。

8. **虚拟对象 (Virtual Objects):**  代码中出现了 `VirtualObject`，这可能用于在图构建阶段表示尚未完全物化的对象，用于延迟分配和优化。

9. **已知节点方面 (Known Node Aspects):**  `known_node_aspects()` 似乎用于跟踪节点的某些属性，以便进行更精确的优化或推理。

**与 JavaScript 功能的关系及示例:**

`MaglevGraphBuilder` 的核心目标是将 JavaScript 代码转换为可执行的图结构。以下 JavaScript 示例说明了其可能处理的功能：

```javascript
function add(a, b) {
  if (a > 0) {
    return a + b;
  } else {
    return b;
  }
}

add(5, 10);
```

对于这段 JavaScript 代码，`MaglevGraphBuilder` 可能会执行以下操作：

* **创建函数入口节点:** 表示函数 `add` 的开始。
* **创建参数节点:**  表示参数 `a` 和 `b`。
* **创建比较节点:**  表示 `a > 0` 的比较操作。
* **创建条件分支节点:**  根据比较结果，跳转到不同的代码块。
* **创建加法节点:**  表示 `a + b` 的加法运算。
* **创建返回节点:**  表示函数的返回值。
* **连接节点:**  将这些节点按照执行顺序连接起来，形成控制流图。

**代码逻辑推理示例:**

假设输入是 JavaScript 字节码，对应于以下代码：

```javascript
let x = 10;
if (x > 5) {
  x = x + 1;
}
```

**假设输入 (简化的字节码表示):**

```
LdaSmi 10        // Load small integer 10
Star r0           // Store to register r0 (representing x)
Ldar r0           // Load register r0
SmiLiteral 5      // Load small integer 5
GreaterThan       // Perform greater than comparison
JumpIfFalse [target_else] // Jump if false to target_else
Ldar r0
SmiLiteral 1
Add             // Add 1
Star r0
[target_else]:
...
```

**可能的输出 (简化的 Maglev 图表示):**

```
Block 1 (入口):
  CreateVariable x
  Constant(10) -> AssignVariable(x)
  Jump -> Block 2

Block 2 (条件判断):
  LoadVariable(x) -> ValueNode a
  Constant(5) -> ValueNode b
  GreaterThan(a, b) -> ConditionNode cond
  Branch(cond, Block 3, Block 4)

Block 3 (then 分支):
  LoadVariable(x) -> ValueNode current_x
  Constant(1) -> ValueNode one
  Add(current_x, one) -> ValueNode new_x
  AssignVariable(x, new_x)
  Jump -> Block 4

Block 4 (合并点):
  ...
```

**用户常见的编程错误（可能被 Maglev 处理或优化）：**

虽然 `maglev-graph-builder.cc` 本身不直接处理用户编程错误，但它构建的图会影响后续的优化和执行，可能会间接处理某些错误模式。例如：

1. **类型不一致导致的隐式转换:** 如果 JavaScript 代码中存在类型不一致的操作，Maglev 图可能会包含类型转换节点。例如：

   ```javascript
   let y = "5" + 2; // 字符串 "5" 和数字 2 相加
   ```

   Maglev 图可能包含一个将数字 `2` 转换为字符串的节点。

2. **访问未定义属性:**  虽然这通常会在运行时抛出错误，但 Maglev 可能会尝试根据反馈信息进行优化，例如，如果某个对象的属性始终存在，则可能会生成更快的访问代码。

3. **频繁的类型更改:** 如果一个变量的类型在运行时频繁变化，Maglev 生成的优化代码可能会失效，导致去优化。

**总结 (基于提供的第 1 部分):**

`v8/src/maglev/maglev-graph-builder.cc` 的第 1 部分主要定义了 `MaglevGraphBuilder` 类的基础结构和核心功能，用于将 JavaScript 代码的中间表示转换为 Maglev 执行图。它处理了基本的图节点创建、执行上下文管理、函数调用参数处理、控制流构建以及去优化支持。此外，它还展示了利用反馈信息进行优化的迹象。  这个文件的目标是构建一个能够被 Maglev 进一步处理和优化的中间表示，从而提升 JavaScript 代码的执行效率。
```
### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共18部分，请归纳一下它的功能
```

### 源代码
```cpp
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
        predecessor, label->
```