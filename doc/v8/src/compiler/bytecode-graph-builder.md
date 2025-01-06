Response: The user wants a summary of the provided C++ code file, `bytecode-graph-builder.cc`, specifically focusing on its functionality and its relationship with JavaScript. They also indicate this is part 1 of 3, suggesting the need for a summary that can be built upon later.

**Plan:**

1. **Identify the core class:** The code defines a class `BytecodeGraphBuilder`. This is the central element.
2. **Analyze the class purpose:** The class name suggests it's involved in building a graph from bytecode.
3. **Examine the class members and methods:**  Look for key functionalities like:
    * Handling bytecode iteration.
    * Creating graph nodes (using `JSGraph`).
    * Managing the execution environment (registers, accumulator, context).
    * Handling control flow (jumps, loops).
    * Dealing with feedback (for optimization).
    * Relating to JavaScript concepts (like variables, function calls, operators).
4. **Connect to JavaScript:**  Look for instances where the code interacts with JavaScript concepts and identify examples.
5. **Formulate the summary:** Combine the findings into a concise description of the file's functionality, highlighting its role in the V8 compilation pipeline and its connection to JavaScript.
这是 V8 JavaScript 引擎中负责将字节码转换成图表示（通常是用于优化的中间表示）的组件。更具体地说，`BytecodeGraphBuilder` 类的主要功能是遍历 JavaScript 函数的字节码，并为每个字节码指令在 V8 的 IR（Intermediate Representation）图中创建相应的节点。

**主要功能归纳:**

1. **字节码到图的转换:**  它接收一个 JavaScript 函数的字节码数组 (`BytecodeArrayRef`)，并将其转换为一个 `JSGraph` 对象。这个 `JSGraph` 是 V8 优化编译器 Turbofan 使用的图结构。
2. **模拟执行环境:**  `BytecodeGraphBuilder` 维护了一个抽象的执行环境 (`Environment` 类)，用于跟踪寄存器、累加器、上下文等的状态。在遍历字节码时，它会更新这个环境的状态，并利用环境中的信息来创建图节点。
3. **控制流处理:**  它能识别和处理字节码中的控制流指令（例如跳转、循环、条件分支），并在图中构建相应的控制流节点（例如 `Merge`、`Loop`、`Branch`）。
4. **反馈信息集成:**  它使用来自反馈向量 (`FeedbackVectorRef`) 的类型反馈信息，这有助于进行有根据的优化决策，例如内联、类型特化等。
5. **内联支持:**  代码中包含了 `inlining_id`，这表明 `BytecodeGraphBuilder` 也参与了内联的过程，它可以为内联的函数构建图的一部分。
6. **OSR（On-Stack Replacement）支持:**  `osr_offset` 参数和相关的逻辑表明它也支持 OSR，即在函数执行过程中进行优化编译。
7. **异常处理:**  代码中定义了 `ExceptionHandler` 结构和相关的逻辑，用于处理字节码中的 try-catch 块。
8. **源码位置追踪:**  它与 `SourcePositionTable` 和 `NodeOriginTable` 协同工作，记录每个图节点对应的源码位置，用于调试和性能分析。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`BytecodeGraphBuilder` 的工作是 V8 引擎将 JavaScript 代码转化为高效机器码的关键步骤之一。它直接操作由 JavaScript 代码编译而来的字节码，并生成用于后续优化的图表示。

以下是一些 JavaScript 功能与 `BytecodeGraphBuilder` 中处理的字节码和生成的图节点之间的关系示例：

**1. 变量声明和访问:**

* **JavaScript:** `let x = 10; console.log(x);`
* **可能生成的字节码:** `LdaSmi [10]`, `Star r0`, `Ldar r0`, ...
* **`BytecodeGraphBuilder` 的操作:**  `VisitLdaSmi` 会创建一个表示常量 10 的节点，`VisitStar` 会将该节点绑定到寄存器 `r0`，`VisitLdar` 会从寄存器 `r0` 获取值。在图中会创建表示这些操作的节点。

**2. 函数调用:**

* **JavaScript:** `function add(a, b) { return a + b; } add(5, 3);`
* **可能生成的字节码:** `LdaGlobal [add]`, `Push arg1`, `Push arg2`, `Call`, ...
* **`BytecodeGraphBuilder` 的操作:** `VisitLdaGlobal` 会查找全局变量 `add`，`VisitPush` 会将参数压入栈（在图构建中会表示为节点），`VisitCall` 会创建一个调用节点的，并连接被调用函数和参数。

**3. 算术运算:**

* **JavaScript:** `let sum = a + b;`
* **可能生成的字节码:** `Ldar r0`, `Add r1`, `Star r2`, ...
* **`BytecodeGraphBuilder` 的操作:** `VisitLdar` 加载 `a` 的值，`VisitAdd` 创建一个加法运算的节点，连接 `a` 和 `b` 对应的节点，`VisitStar` 将结果存储到寄存器。

**4. 控制流语句 (if/else, for, while):**

* **JavaScript:** `if (x > 0) { console.log("positive"); } else { console.log("non-positive"); }`
* **可能生成的字节码:** `Ldar r0`, `GreaterThanZero`, `JumpIfFalse`, ..., `Jump`
* **`BytecodeGraphBuilder` 的操作:** `VisitLdar` 加载 `x`，`VisitGreaterThanZero` 创建比较节点，`VisitJumpIfFalse` 和 `VisitJump` 创建条件分支和跳转节点，并在图中构建相应的控制流结构。

**总结:**

`v8/src/compiler/bytecode-graph-builder.cc` 中的 `BytecodeGraphBuilder` 类是 V8 编译流程中的核心组件，它负责将 JavaScript 编译产生的字节码转换为图这种更适合优化的中间表示。  它直接关联着各种 JavaScript 语言特性，通过分析字节码并生成相应的图节点，为后续的优化和最终机器码生成奠定了基础。

Prompt: 
```
这是目录为v8/src/compiler/bytecode-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/bytecode-graph-builder.h"

#include <optional>

#include "src/ast/ast.h"
#include "src/codegen/source-position-table.h"
#include "src/codegen/tick-counter.h"
#include "src/common/assert-scope.h"
#include "src/compiler/bytecode-analysis.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/js-type-hint-lowering.h"
#include "src/compiler/linkage.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-observer.h"
#include "src/compiler/node-origin-table.h"
#include "src/compiler/operator-properties.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/state-values-utils.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/interpreter/bytecode-register.h"
#include "src/interpreter/bytecodes.h"
#include "src/objects/elements-kind.h"
#include "src/objects/js-generator.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/scope-info.h"
#include "src/objects/template-objects-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

class BytecodeGraphBuilder {
 public:
  BytecodeGraphBuilder(
      JSHeapBroker* broker, Zone* local_zone, NativeContextRef native_context,
      SharedFunctionInfoRef shared_info, BytecodeArrayRef bytecode,
      FeedbackCellRef feedback_cell, BytecodeOffset osr_offset,
      JSGraph* jsgraph, CallFrequency const& invocation_frequency,
      SourcePositionTable* source_positions, NodeOriginTable* node_origins,
      int inlining_id, CodeKind code_kind, BytecodeGraphBuilderFlags flags,
      TickCounter* tick_counter, ObserveNodeInfo const& observe_node_info);

  BytecodeGraphBuilder(const BytecodeGraphBuilder&) = delete;
  BytecodeGraphBuilder& operator=(const BytecodeGraphBuilder&) = delete;

  // Creates a graph by visiting bytecodes.
  void CreateGraph();

 private:
  class Environment;
  class OsrIteratorState;
  class BytecodePositionDecorator;
  struct SubEnvironment;

  void RemoveMergeEnvironmentsBeforeOffset(int limit_offset);
  void AdvanceToOsrEntryAndPeelLoops();

  // Advance {bytecode_iterator} to the given offset. If possible, also advance
  // {source_position_iterator} while updating the source position table.
  void AdvanceIteratorsTo(int bytecode_offset);

  void VisitSingleBytecode();
  void VisitBytecodes();

  void AddBytecodePositionDecorator();
  void RemoveBytecodePositionDecorator();

  // Get or create the node that represents the outer function closure.
  Node* GetFunctionClosure();

  // Get or create the node for this parameter index. If such a node is
  // already cached, it is returned directly and the {debug_name_hint} is
  // ignored.
  Node* GetParameter(int index, const char* debug_name_hint = nullptr);

  CodeKind code_kind() const { return code_kind_; }

  // The node representing the current feedback vector is generated once prior
  // to visiting bytecodes, and is later passed as input to other nodes that
  // may need it.
  // TODO(jgruber): Remove feedback_vector() and rename feedback_vector_node()
  // to feedback_vector() once all uses of the direct heap object reference
  // have been replaced with a Node* reference.
  void CreateFeedbackVectorNode();
  Node* feedback_vector_node() const {
    DCHECK_NOT_NULL(feedback_vector_node_);
    return feedback_vector_node_;
  }

  // Same as above for the feedback vector node.
  void CreateNativeContextNode();
  Node* native_context_node() const {
    DCHECK_NOT_NULL(native_context_node_);
    return native_context_node_;
  }

  Node* BuildLoadFeedbackCell(int index);

  // Builder for loading a native context field.
  Node* BuildLoadNativeContextField(int index);

  // Helper function for creating a feedback source containing type feedback
  // vector and a feedback slot.
  FeedbackSource CreateFeedbackSource(int slot_id);
  FeedbackSource CreateFeedbackSource(FeedbackSlot slot);

  void set_environment(Environment* env) { environment_ = env; }
  const Environment* environment() const { return environment_; }
  Environment* environment() { return environment_; }

  // Node creation helpers
  Node* NewNode(const Operator* op, bool incomplete = false) {
    return MakeNode(op, 0, static_cast<Node**>(nullptr), incomplete);
  }

  template <class... Args>
  Node* NewNode(const Operator* op, Node* n0, Args... nodes) {
    Node* buffer[] = {n0, nodes...};
    return MakeNode(op, arraysize(buffer), buffer);
  }

  // Helpers to create new control nodes.
  Node* NewIfTrue() { return NewNode(common()->IfTrue()); }
  Node* NewIfFalse() { return NewNode(common()->IfFalse()); }
  Node* NewIfValue(int32_t value) { return NewNode(common()->IfValue(value)); }
  Node* NewIfDefault() { return NewNode(common()->IfDefault()); }
  Node* NewMerge() { return NewNode(common()->Merge(1), true); }
  Node* NewLoop() { return NewNode(common()->Loop(1), true); }
  Node* NewBranch(Node* condition, BranchHint hint = BranchHint::kNone) {
    return NewNode(common()->Branch(hint), condition);
  }
  Node* NewSwitch(Node* condition, int control_output_count) {
    return NewNode(common()->Switch(control_output_count), condition);
  }

  // Creates a new Phi node having {count} input values.
  Node* NewPhi(int count, Node* input, Node* control);
  Node* NewEffectPhi(int count, Node* input, Node* control);

  // Helpers for merging control, effect or value dependencies.
  Node* MergeControl(Node* control, Node* other);
  Node* MergeEffect(Node* effect, Node* other_effect, Node* control);
  Node* MergeValue(Node* value, Node* other_value, Node* control);

  // The main node creation chokepoint. Adds context, frame state, effect,
  // and control dependencies depending on the operator.
  Node* MakeNode(const Operator* op, int value_input_count,
                 Node* const* value_inputs, bool incomplete = false);

  Node** EnsureInputBufferSize(int size);

  Node* const* GetCallArgumentsFromRegisters(Node* callee, Node* receiver,
                                              interpreter::Register first_arg,
                                              int arg_count);
  Node* const* ProcessCallVarArgs(ConvertReceiverMode receiver_mode,
                                  Node* callee, interpreter::Register first_reg,
                                  int arg_count);
  Node* const* GetConstructArgumentsFromRegister(
      Node* target, Node* new_target, interpreter::Register first_arg,
      int arg_count);
  Node* ProcessCallRuntimeArguments(const Operator* call_runtime_op,
                                    interpreter::Register receiver,
                                    size_t reg_count);

  // Prepare information for eager deoptimization. This information is carried
  // by dedicated {Checkpoint} nodes that are wired into the effect chain.
  // Conceptually this frame state is "before" a given operation.
  void PrepareEagerCheckpoint();

  // Prepare information for lazy deoptimization. This information is attached
  // to the given node and the output value produced by the node is combined.
  //
  // The low-level chokepoint - use the variants below instead.
  void PrepareFrameState(Node* node, OutputFrameStateCombine combine,
                         BytecodeOffset bailout_id,
                         const BytecodeLivenessState* liveness);

  // In the common case, frame states are conceptually "after" a given
  // operation and at the current bytecode offset.
  void PrepareFrameState(Node* node, OutputFrameStateCombine combine) {
    if (!OperatorProperties::HasFrameStateInput(node->op())) return;
    const int offset = bytecode_iterator().current_offset();
    return PrepareFrameState(node, combine, BytecodeOffset(offset),
                             bytecode_analysis().GetOutLivenessFor(offset));
  }

  // For function-entry stack checks, they're conceptually "before" the first
  // bytecode and at a special marker bytecode offset.
  // In the case of FE stack checks, the current bytecode is also the first
  // bytecode, so we use a special marker bytecode offset to signify a virtual
  // bytecode before the first physical bytecode.
  void PrepareFrameStateForFunctionEntryStackCheck(Node* node) {
    DCHECK_EQ(bytecode_iterator().current_offset(), 0);
    DCHECK(OperatorProperties::HasFrameStateInput(node->op()));
    DCHECK(node->opcode() == IrOpcode::kJSStackCheck);
    return PrepareFrameState(node, OutputFrameStateCombine::Ignore(),
                             BytecodeOffset(kFunctionEntryBytecodeOffset),
                             bytecode_analysis().GetInLivenessFor(0));
  }

  // For OSR-entry stack checks, they're conceptually "before" the first
  // bytecode of the current loop. We implement this in a similar manner to
  // function-entry (FE) stack checks above, i.e. we deopt at the predecessor
  // of the current bytecode.
  // In the case of OSR-entry stack checks, a physical predecessor bytecode
  // exists: the JumpLoop bytecode. We attach to JumpLoop by using
  // `bytecode_analysis().osr_bailout_id()` instead of current_offset (the
  // former points at JumpLoop, the latter at the loop header, i.e. the target
  // of JumpLoop).
  void PrepareFrameStateForOSREntryStackCheck(Node* node) {
    DCHECK(OperatorProperties::HasFrameStateInput(node->op()));
    DCHECK(node->opcode() == IrOpcode::kJSStackCheck);
    const int offset = bytecode_analysis().osr_bailout_id().ToInt();
    return PrepareFrameState(node, OutputFrameStateCombine::Ignore(),
                             BytecodeOffset(offset),
                             bytecode_analysis().GetOutLivenessFor(offset));
  }

  void BuildCreateArguments(CreateArgumentsType type);
  Node* BuildLoadGlobal(NameRef name, uint32_t feedback_slot_index,
                        TypeofMode typeof_mode);

  enum class NamedStoreMode {
    // Check the prototype chain before storing.
    kSet,
    // Define value to the receiver without checking the prototype chain.
    kDefineOwn,
  };
  void BuildNamedStore(NamedStoreMode store_mode);
  void BuildLdaLookupSlot(TypeofMode typeof_mode);
  void BuildLdaLookupContextSlot(TypeofMode typeof_mode);
  void BuildLdaLookupGlobalSlot(TypeofMode typeof_mode);
  void BuildCallVarArgs(ConvertReceiverMode receiver_mode);
  void BuildCall(ConvertReceiverMode receiver_mode, Node* const* args,
                 size_t arg_count, int slot_id);
  void BuildCall(ConvertReceiverMode receiver_mode,
                 std::initializer_list<Node*> args, int slot_id) {
    BuildCall(receiver_mode, args.begin(), args.size(), slot_id);
  }
  void BuildUnaryOp(const Operator* op);
  void BuildBinaryOp(const Operator* op);
  void BuildBinaryOpWithImmediate(const Operator* op);
  void BuildCompareOp(const Operator* op);
  void BuildDelete(LanguageMode language_mode);
  void BuildCastOperator(const Operator* op);
  void BuildHoleCheckAndThrow(Node* condition, Runtime::FunctionId runtime_id,
                              Node* name = nullptr);

  // Optional early lowering to the simplified operator level.  Note that
  // the result has already been wired into the environment just like
  // any other invocation of {NewNode} would do.
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedUnaryOp(
      const Operator* op, Node* operand, FeedbackSlot slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedBinaryOp(
      const Operator* op, Node* left, Node* right, FeedbackSlot slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedForInNext(
      Node* receiver, Node* cache_array, Node* cache_type, Node* index,
      FeedbackSlot slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedForInPrepare(
      Node* receiver, FeedbackSlot slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedToNumber(
      Node* input, FeedbackSlot slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedCall(const Operator* op,
                                                            Node* const* args,
                                                            int arg_count,
                                                            FeedbackSlot slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedConstruct(
      const Operator* op, Node* const* args, int arg_count, FeedbackSlot slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedGetIterator(
      const Operator* op, Node* receiver, FeedbackSlot load_slot,
      FeedbackSlot call_slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedLoadNamed(
      const Operator* op, FeedbackSlot slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedLoadKeyed(
      const Operator* op, Node* receiver, Node* key, FeedbackSlot slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedStoreNamed(
      const Operator* op, Node* receiver, Node* value, FeedbackSlot slot);
  JSTypeHintLowering::LoweringResult TryBuildSimplifiedStoreKeyed(
      const Operator* op, Node* receiver, Node* key, Node* value,
      FeedbackSlot slot);

  // Applies the given early reduction onto the current environment.
  void ApplyEarlyReduction(JSTypeHintLowering::LoweringResult reduction);

  // Check the context chain for extensions, for lookup fast paths.
  Environment* CheckContextExtensions(uint32_t depth);
  // Slow path taken when we cannot figure out the current scope info.
  Environment* CheckContextExtensionsSlowPath(uint32_t depth);
  // Helper function that tries to get the current scope info.
  OptionalScopeInfoRef TryGetScopeInfo();
  // Helper function to create a context extension check.
  Environment* CheckContextExtensionAtDepth(Environment* slow_environment,
                                            uint32_t depth);

  // Helper function to create for-in mode from the recorded type feedback.
  ForInMode GetForInMode(FeedbackSlot slot);

  // Helper function to compute call frequency from the recorded type
  // feedback. Returns unknown if invocation count is unknown. Returns 0 if
  // feedback is insufficient.
  CallFrequency ComputeCallFrequency(int slot_id) const;

  // Helper function to extract the speculation mode from the recorded type
  // feedback. Returns kDisallowSpeculation if feedback is insufficient.
  SpeculationMode GetSpeculationMode(int slot_id) const;

  // Helper function to determine the call feedback relation from the recorded
  // type feedback. Returns kUnrelated if feedback is insufficient.
  CallFeedbackRelation ComputeCallFeedbackRelation(int slot_id) const;

  // Helpers for building the implicit FunctionEntry and IterationBody
  // StackChecks.
  void BuildFunctionEntryStackCheck();
  void BuildIterationBodyStackCheck();
  void BuildOSREntryStackCheck();

  // Control flow plumbing.
  void BuildJump();
  void BuildJumpIf(Node* condition);
  void BuildJumpIfNot(Node* condition);
  void BuildJumpIfEqual(Node* comperand);
  void BuildJumpIfNotEqual(Node* comperand);
  void BuildJumpIfTrue();
  void BuildJumpIfFalse();
  void BuildJumpIfToBooleanTrue();
  void BuildJumpIfToBooleanFalse();
  void BuildJumpIfNotHole();
  void BuildJumpIfJSReceiver();
  void BuildJumpIfForInDone();

  void BuildSwitchOnSmi(Node* condition);
  void BuildSwitchOnGeneratorState(
      const ZoneVector<ResumeJumpTarget>& resume_jump_targets,
      bool allow_fallthrough_on_executing);

  // Simulates control flow by forward-propagating environments.
  void MergeIntoSuccessorEnvironment(int target_offset);
  void BuildLoopHeaderEnvironment(int current_offset);
  void SwitchToMergeEnvironment(int current_offset);

  // Simulates control flow that exits the function body.
  void MergeControlToLeaveFunction(Node* exit);

  // Builds loop exit nodes for every exited loop between the current bytecode
  // offset and {target_offset}.
  void BuildLoopExitsForBranch(int target_offset);
  void BuildLoopExitsForFunctionExit(const BytecodeLivenessState* liveness);
  void BuildLoopExitsUntilLoop(int loop_offset,
                               const BytecodeLivenessState* liveness);

  // Helper for building a return (from an actual return or a suspend).
  void BuildReturn(const BytecodeLivenessState* liveness);

  // Simulates entry and exit of exception handlers.
  void ExitThenEnterExceptionHandlers(int current_offset);

  // Update the current position of {SourcePositionTable} and
  // {NodeOriginTable} to that bytecode at {offset}, if any.
  void UpdateSourceAndBytecodePosition(int offset);

  // Growth increment for the temporary buffer used to construct input lists to
  // new nodes.
  static const int kInputBufferSizeIncrement = 64;

  // An abstract representation for an exception handler that is being
  // entered and exited while the graph builder is iterating over the
  // underlying bytecode. The exception handlers within the bytecode are
  // well scoped, hence will form a stack during iteration.
  struct ExceptionHandler {
    int start_offset_;      // Start offset of the handled area in the bytecode.
    int end_offset_;        // End offset of the handled area in the bytecode.
    int handler_offset_;    // Handler entry offset within the bytecode.
    int context_register_;  // Index of register holding handler context.
  };

  template <class T = Object>
  typename ref_traits<T>::ref_type MakeRefForConstantForIndexOperand(
      int operand_index) {
    // The BytecodeArray itself was fetched by using a barrier so all reads
    // from the constant pool are safe.
    return MakeRefAssumeMemoryFence(
        broker(), broker()->CanonicalPersistentHandle(
                      Cast<T>(bytecode_iterator().GetConstantForIndexOperand(
                          operand_index, local_isolate_))));
  }

  Graph* graph() const { return jsgraph_->graph(); }
  CommonOperatorBuilder* common() const { return jsgraph_->common(); }
  Zone* graph_zone() const { return graph()->zone(); }
  JSGraph* jsgraph() const { return jsgraph_; }
  Isolate* isolate() const { return jsgraph_->isolate(); }
  JSOperatorBuilder* javascript() const { return jsgraph_->javascript(); }
  SimplifiedOperatorBuilder* simplified() const {
    return jsgraph_->simplified();
  }
  Zone* local_zone() const { return local_zone_; }
  BytecodeArrayRef bytecode_array() const { return bytecode_array_; }
  FeedbackVectorRef feedback_vector() const { return feedback_vector_; }
  const JSTypeHintLowering& type_hint_lowering() const {
    return type_hint_lowering_;
  }
  const FrameStateFunctionInfo* frame_state_function_info() const {
    return frame_state_function_info_;
  }
  SourcePositionTableIterator& source_position_iterator() {
    return source_position_iterator_;
  }
  interpreter::BytecodeArrayIterator const& bytecode_iterator() const {
    return bytecode_iterator_;
  }
  interpreter::BytecodeArrayIterator& bytecode_iterator() {
    return bytecode_iterator_;
  }
  BytecodeAnalysis const& bytecode_analysis() const {
    return bytecode_analysis_;
  }
  int currently_peeled_loop_offset() const {
    return currently_peeled_loop_offset_;
  }
  void set_currently_peeled_loop_offset(int offset) {
    currently_peeled_loop_offset_ = offset;
  }
  bool skip_first_stack_check() const {
    return skip_first_stack_and_tierup_check_;
  }
  bool skip_tierup_check() const {
    return skip_first_stack_and_tierup_check_ || osr_;
  }
  int current_exception_handler() const { return current_exception_handler_; }
  void set_current_exception_handler(int index) {
    current_exception_handler_ = index;
  }
  bool needs_eager_checkpoint() const { return needs_eager_checkpoint_; }
  void mark_as_needing_eager_checkpoint(bool value) {
    needs_eager_checkpoint_ = value;
  }
  JSHeapBroker* broker() const { return broker_; }
  NativeContextRef native_context() const { return native_context_; }
  SharedFunctionInfoRef shared_info() const { return shared_info_; }

#define DECLARE_VISIT_BYTECODE(name, ...) void Visit##name();
  BYTECODE_LIST(DECLARE_VISIT_BYTECODE, DECLARE_VISIT_BYTECODE)
#undef DECLARE_VISIT_BYTECODE

  JSHeapBroker* const broker_;
  LocalIsolate* const local_isolate_;
  Zone* const local_zone_;
  JSGraph* const jsgraph_;
  // The native context for which we optimize.
  NativeContextRef const native_context_;
  SharedFunctionInfoRef const shared_info_;
  BytecodeArrayRef const bytecode_array_;
  FeedbackCellRef const feedback_cell_;
  FeedbackVectorRef const feedback_vector_;
  CallFrequency const invocation_frequency_;
  JSTypeHintLowering const type_hint_lowering_;
  const FrameStateFunctionInfo* const frame_state_function_info_;
  SourcePositionTableIterator source_position_iterator_;
  interpreter::BytecodeArrayIterator bytecode_iterator_;
  BytecodeAnalysis const bytecode_analysis_;
  Environment* environment_;
  BytecodePositionDecorator* decorator_;
  bool const osr_;
  int currently_peeled_loop_offset_;

  const bool skip_first_stack_and_tierup_check_;

  // Merge environments are snapshots of the environment at points where the
  // control flow merges. This models a forward data flow propagation of all
  // values from all predecessors of the merge in question. They are indexed by
  // the bytecode offset
  ZoneMap<int, Environment*> merge_environments_;

  // Generator merge environments are snapshots of the current resume
  // environment, tracing back through loop headers to the resume switch of a
  // generator. They allow us to model a single resume jump as several switch
  // statements across loop headers, keeping those loop headers reducible,
  // without having to merge the "executing" environments of the generator into
  // the "resuming" ones. They are indexed by the suspend id of the resume.
  ZoneMap<int, Environment*> generator_merge_environments_;

  ZoneVector<Node*> cached_parameters_;

  // Exception handlers currently entered by the iteration.
  ZoneStack<ExceptionHandler> exception_handlers_;
  int current_exception_handler_;

  // Temporary storage for building node input lists.
  int input_buffer_size_;
  Node** input_buffer_;

  const CodeKind code_kind_;
  Node* feedback_vector_node_;
  Node* native_context_node_;

  // Optimization to only create checkpoints when the current position in the
  // control-flow is not effect-dominated by another checkpoint already. All
  // operations that do not have observable side-effects can be re-evaluated.
  bool needs_eager_checkpoint_;

  // Nodes representing values in the activation record.
  SetOncePointer<Node> function_closure_;

  // Control nodes that exit the function body.
  ZoneVector<Node*> exit_controls_;

  StateValuesCache state_values_cache_;

  // The node origins table, to store bytecode origins.
  NodeOriginTable* const node_origins_;

  // The source position table, to be populated.
  SourcePositionTable* const source_positions_;

  SourcePosition const start_position_;

  TickCounter* const tick_counter_;

  ObserveNodeInfo const observe_node_info_;

  static constexpr int kBinaryOperationHintIndex = 1;
  static constexpr int kBinaryOperationSmiHintIndex = 1;
  static constexpr int kCompareOperationHintIndex = 1;
  static constexpr int kCountOperationHintIndex = 0;
  static constexpr int kUnaryOperationHintIndex = 0;
};

// The abstract execution environment simulates the content of the interpreter
// register file. The environment performs SSA-renaming of all tracked nodes at
// split and merge points in the control flow.
class BytecodeGraphBuilder::Environment : public ZoneObject {
 public:
  Environment(BytecodeGraphBuilder* builder, int register_count,
              int parameter_count,
              interpreter::Register incoming_new_target_or_generator,
              Node* control_dependency);

  // Specifies whether environment binding methods should attach frame state
  // inputs to nodes representing the value being bound. This is done because
  // the {OutputFrameStateCombine} is closely related to the binding method.
  enum FrameStateAttachmentMode { kAttachFrameState, kDontAttachFrameState };

  int parameter_count() const { return parameter_count_; }
  int register_count() const { return register_count_; }

  Node* LookupAccumulator() const;
  Node* LookupRegister(interpreter::Register the_register) const;
  Node* LookupGeneratorState() const;

  void BindAccumulator(Node* node,
                       FrameStateAttachmentMode mode = kDontAttachFrameState);
  void BindRegister(interpreter::Register the_register, Node* node,
                    FrameStateAttachmentMode mode = kDontAttachFrameState);
  void BindRegistersToProjections(
      interpreter::Register first_reg, Node* node,
      FrameStateAttachmentMode mode = kDontAttachFrameState);
  void BindGeneratorState(Node* node);
  void RecordAfterState(Node* node,
                        FrameStateAttachmentMode mode = kDontAttachFrameState);

  // Effect dependency tracked by this environment.
  Node* GetEffectDependency() { return effect_dependency_; }
  void UpdateEffectDependency(Node* dependency) {
    effect_dependency_ = dependency;
  }

  // Preserve a checkpoint of the environment for the IR graph. Any
  // further mutation of the environment will not affect checkpoints.
  Node* Checkpoint(BytecodeOffset bytecode_offset,
                   OutputFrameStateCombine combine,
                   const BytecodeLivenessState* liveness);

  // Control dependency tracked by this environment.
  Node* GetControlDependency() const { return control_dependency_; }
  void UpdateControlDependency(Node* dependency) {
    control_dependency_ = dependency;
  }

  Node* Context() const { return context_; }
  void SetContext(Node* new_context) { context_ = new_context; }

  Environment* Copy();
  void Merge(Environment* other, const BytecodeLivenessState* liveness);

  void FillWithOsrValues();
  void PrepareForLoop(const BytecodeLoopAssignments& assignments,
                      const BytecodeLivenessState* liveness);
  void PrepareForLoopExit(Node* loop,
                          const BytecodeLoopAssignments& assignments,
                          const BytecodeLivenessState* liveness);

 private:
  friend Zone;

  explicit Environment(const Environment* copy);

  bool StateValuesRequireUpdate(Node** state_values, Node** values, int count);
  void UpdateStateValues(Node** state_values, Node** values, int count);
  Node* GetStateValuesFromCache(Node** values, int count,
                                const BytecodeLivenessState* liveness);

  int RegisterToValuesIndex(interpreter::Register the_register) const;

  Zone* zone() const { return builder_->local_zone(); }
  Graph* graph() const { return builder_->graph(); }
  CommonOperatorBuilder* common() const { return builder_->common(); }
  BytecodeGraphBuilder* builder() const { return builder_; }
  const NodeVector* values() const { return &values_; }
  NodeVector* values() { return &values_; }
  int register_base() const { return register_base_; }
  int accumulator_base() const { return accumulator_base_; }

  BytecodeGraphBuilder* builder_;
  int register_count_;
  int parameter_count_;
  Node* context_;
  Node* control_dependency_;
  Node* effect_dependency_;
  NodeVector values_;
  Node* parameters_state_values_;
  Node* generator_state_;
  int register_base_;
  int accumulator_base_;
};

// A helper for creating a temporary sub-environment for simple branches.
struct BytecodeGraphBuilder::SubEnvironment final {
 public:
  explicit SubEnvironment(BytecodeGraphBuilder* builder)
      : builder_(builder), parent_(builder->environment()->Copy()) {}

  ~SubEnvironment() { builder_->set_environment(parent_); }

 private:
  BytecodeGraphBuilder* builder_;
  BytecodeGraphBuilder::Environment* parent_;
};

// Issues:
// - Scopes - intimately tied to AST. Need to eval what is needed.
// - Need to resolve closure parameter treatment.
BytecodeGraphBuilder::Environment::Environment(
    BytecodeGraphBuilder* builder, int register_count, int parameter_count,
    interpreter::Register incoming_new_target_or_generator,
    Node* control_dependency)
    : builder_(builder),
      register_count_(register_count),
      parameter_count_(parameter_count),
      control_dependency_(control_dependency),
      effect_dependency_(control_dependency),
      values_(builder->local_zone()),
      parameters_state_values_(nullptr),
      generator_state_(nullptr) {
  // The layout of values_ is:
  //
  // [receiver] [parameters] [registers] [accumulator]
  //
  // parameter[0] is the receiver (this), parameters 1..N are the
  // parameters supplied to the method (arg0..argN-1). The accumulator
  // is stored separately.

  // Parameters including the receiver
  for (int i = 0; i < parameter_count; i++) {
    const char* debug_name = (i == 0) ? "%this" : nullptr;
    Node* parameter = builder->GetParameter(i, debug_name);
    values()->push_back(parameter);
  }

  // Registers
  register_base_ = static_cast<int>(values()->size());
  Node* undefined_constant = builder->jsgraph()->UndefinedConstant();
  values()->insert(values()->end(), register_count, undefined_constant);

  // Accumulator
  accumulator_base_ = static_cast<int>(values()->size());
  values()->push_back(undefined_constant);

  // Context
  int context_index = Linkage::GetJSCallContextParamIndex(parameter_count);
  context_ = builder->GetParameter(context_index, "%context");

  // Incoming new.target or generator register
  if (incoming_new_target_or_generator.is_valid()) {
    int new_target_index =
        Linkage::GetJSCallNewTargetParamIndex(parameter_count);
    Node* new_target_node =
        builder->GetParameter(new_target_index, "%new.target");

    int values_index = RegisterToValuesIndex(incoming_new_target_or_generator);
    values()->at(values_index) = new_target_node;
  }
}

BytecodeGraphBuilder::Environment::Environment(
    const BytecodeGraphBuilder::Environment* other)
    : builder_(other->builder_),
      register_count_(other->register_count_),
      parameter_count_(other->parameter_count_),
      context_(other->context_),
      control_dependency_(other->control_dependency_),
      effect_dependency_(other->effect_dependency_),
      values_(other->zone()),
      parameters_state_values_(other->parameters_state_values_),
      generator_state_(other->generator_state_),
      register_base_(other->register_base_),
      accumulator_base_(other->accumulator_base_) {
  values_ = other->values_;
}


int BytecodeGraphBuilder::Environment::RegisterToValuesIndex(
    interpreter::Register the_register) const {
  if (the_register.is_parameter()) {
    return the_register.ToParameterIndex();
  } else {
    return the_register.index() + register_base();
  }
}

Node* BytecodeGraphBuilder::Environment::LookupAccumulator() const {
  return values()->at(accumulator_base_);
}

Node* BytecodeGraphBuilder::Environment::LookupGeneratorState() const {
  DCHECK_NOT_NULL(generator_state_);
  return generator_state_;
}

Node* BytecodeGraphBuilder::Environment::LookupRegister(
    interpreter::Register the_register) const {
  if (the_register.is_current_context()) {
    return Context();
  } else if (the_register.is_function_closure()) {
    return builder()->GetFunctionClosure();
  } else {
    int values_index = RegisterToValuesIndex(the_register);
    return values()->at(values_index);
  }
}

void BytecodeGraphBuilder::Environment::BindAccumulator(
    Node* node, FrameStateAttachmentMode mode) {
  if (mode == FrameStateAttachmentMode::kAttachFrameState) {
    builder()->PrepareFrameState(node, OutputFrameStateCombine::PokeAt(0));
  }
  values()->at(accumulator_base_) = node;
}

void BytecodeGraphBuilder::Environment::BindGeneratorState(Node* node) {
  generator_state_ = node;
}

void BytecodeGraphBuilder::Environment::BindRegister(
    interpreter::Register the_register, Node* node,
    FrameStateAttachmentMode mode) {
  int values_index = RegisterToValuesIndex(the_register);
  if (mode == FrameStateAttachmentMode::kAttachFrameState) {
    builder()->PrepareFrameState(node, OutputFrameStateCombine::PokeAt(
                                           accumulator_base_ - values_index));
  }
  values()->at(values_index) = node;
}

void BytecodeGraphBuilder::Environment::BindRegistersToProjections(
    interpreter::Register first_reg, Node* node,
    FrameStateAttachmentMode mode) {
  int values_index = RegisterToValuesIndex(first_reg);
  if (mode == FrameStateAttachmentMode::kAttachFrameState) {
    builder()->PrepareFrameState(node, OutputFrameStateCombine::PokeAt(
                                           accumulator_base_ - values_index));
  }
  for (int i = 0; i < node->op()->ValueOutputCount(); i++) {
    values()->at(values_index + i) =
        builder()->NewNode(common()->Projection(i), node);
  }
}

void BytecodeGraphBuilder::Environment::RecordAfterState(
    Node* node, FrameStateAttachmentMode mode) {
  if (mode == FrameStateAttachmentMode::kAttachFrameState) {
    builder()->PrepareFrameState(node, OutputFrameStateCombine::Ignore());
  }
}

BytecodeGraphBuilder::Environment* BytecodeGraphBuilder::Environment::Copy() {
  return zone()->New<Environment>(this);
}

void BytecodeGraphBuilder::Environment::Merge(
    BytecodeGraphBuilder::Environment* other,
    const BytecodeLivenessState* liveness) {
  // Create a merge of the control dependencies of both environments and update
  // the current environment's control dependency accordingly.
  Node* control = builder()->MergeControl(GetControlDependency(),
                                          other->GetControlDependency());
  UpdateControlDependency(control);

  // Create a merge of the effect dependencies of both environments and update
  // the current environment's effect dependency accordingly.
  Node* effect = builder()->MergeEffect(GetEffectDependency(),
                                        other->GetEffectDependency(), control);
  UpdateEffectDependency(effect);

  // Introduce Phi nodes for values that are live and have differing inputs at
  // the merge point, potentially extending an existing Phi node if possible.
  context_ = builder()->MergeValue(context_, other->context_, control);
  for (int i = 0; i < parameter_count(); i++) {
    values_[i] = builder()->MergeValue(values_[i], other->values_[i], control);
  }
  for (int i = 0; i < register_count(); i++) {
    int index = register_base() + i;
    if (liveness == nullptr || liveness->RegisterIsLive(i)) {
#if DEBUG
      // We only do these DCHECKs when we are not in the resume path of a
      // generator -- this is, when either there is no generator state at all,
      // or the generator state is not the constant "executing" value.
      if (generator_state_ == nullptr ||
          NumberMatcher(generator_state_)
              .Is(JSGeneratorObject::kGeneratorExecuting)) {
        DCHECK_NE(values_[index], builder()->jsgraph()->OptimizedOutConstant());
        DCHECK_NE(other->values_[index],
                  builder()->jsgraph()->OptimizedOutConstant());
      }
#endif

      values_[index] =
          builder()->MergeValue(values_[index], other->values_[index], control);

    } else {
      values_[index] = builder()->jsgraph()->OptimizedOutConstant();
    }
  }

  if (liveness == nullptr || liveness->AccumulatorIsLive()) {
    DCHECK_NE(values_[accumulator_base()],
              builder()->jsgraph()->OptimizedOutConstant());
    DCHECK_NE(other->values_[accumulator_base()],
              builder()->jsgraph()->OptimizedOutConstant());

    values_[accumulator_base()] =
        builder()->MergeValue(values_[accumulator_base()],
                              other->values_[accumulator_base()], control);
  } else {
    values_[accumulator_base()] = builder()->jsgraph()->OptimizedOutConstant();
  }

  if (generator_state_ != nullptr) {
    DCHECK_NOT_NULL(other->generator_state_);
    generator_state_ = builder()->MergeValue(generator_state_,
                                             other->generator_state_, control);
  }
}

void BytecodeGraphBuilder::Environment::PrepareForLoop(
    const BytecodeLoopAssignments& assignments,
    const BytecodeLivenessState* liveness) {
  // Create a control node for the loop header.
  Node* control = builder()->NewLoop();

  // Create a Phi for external effects.
  Node* effect = builder()->NewEffectPhi(1, GetEffectDependency(), control);
  UpdateEffectDependency(effect);

  // Create Phis for any values that are live on entry to the loop and may be
  // updated by the end of the loop.
  context_ = builder()->NewPhi(1, context_, control);
  for (int i = 0; i < parameter_count(); i++) {
    if (assignments.ContainsParameter(i)) {
      values_[i] = builder()->NewPhi(1, values_[i], control);
    }
  }
  for (int i = 0; i < register_count(); i++) {
    if (assignments.ContainsLocal(i) &&
        (liveness == nullptr || liveness->RegisterIsLive(i))) {
      int index = register_base() + i;
      values_[index] = builder()->NewPhi(1, values_[index], control);
    }
  }
  // The accumulator should not be live on entry.
  DCHECK_IMPLIES(liveness != nullptr, !liveness->AccumulatorIsLive());

  if (generator_state_ != nullptr) {
    generator_state_ = builder()->NewPhi(1, generator_state_, control);
  }

  // Connect to the loop end.
  Node* terminate = builder()->graph()->NewNode(
      builder()->common()->Terminate(), effect, control);
  builder()->exit_controls_.push_back(terminate);
}

void BytecodeGraphBuilder::Environment::FillWithOsrValues() {
  Node* start = graph()->start();

  // Create OSR values for each environment value.
  SetContext(graph()->NewNode(
      common()->OsrValue(Linkage::kOsrContextSpillSlotIndex), start));
  int size = static_cast<int>(values()->size());
  for (int i = 0; i < size; i++) {
    int idx = i;  // Indexing scheme follows {StandardFrame}, adapt accordingly.
    if (i >= register_base()) idx += InterpreterFrameConstants::kExtraSlotCount;
    if (i >= accumulator_base()) idx = Linkage::kOsrAccumulatorRegisterIndex;
    values()->at(i) = graph()->NewNode(common()->OsrValue(idx), start);
  }
}

bool BytecodeGraphBuilder::Environment::StateValuesRequireUpdate(
    Node** state_values, Node** values, int count) {
  if (*state_values == nullptr) {
    return true;
  }
  Node::Inputs inputs = (*state_values)->inputs();
  if (inputs.count() != count) return true;
  for (int i = 0; i < count; i++) {
    if (inputs[i] != values[i]) {
      return true;
    }
  }
  return false;
}

void BytecodeGraphBuilder::Environment::PrepareForLoopExit(
    Node* loop, const BytecodeLoopAssignments& assignments,
    const BytecodeLivenessState* liveness) {
  DCHECK_EQ(loop->opcode(), IrOpcode::kLoop);

  Node* control = GetControlDependency();

  // Create the loop exit node.
  Node* loop_exit = graph()->NewNode(common()->LoopExit(), control, loop);
  UpdateControlDependency(loop_exit);

  // Rename the effect.
  Node* effect_rename = graph()->NewNode(common()->LoopExitEffect(),
                                         GetEffectDependency(), loop_exit);
  UpdateEffectDependency(effect_rename);

  // TODO(jarin) We should also rename context here. However, unconditional
  // renaming confuses global object and native context specialization.
  // We should only rename if the context is assigned in the loop.

  // Rename the environment values if they were assigned in the loop and are
  // live after exiting the loop.
  for (int i = 0; i < parameter_count(); i++) {
    if (assignments.ContainsParameter(i)) {
      Node* rename = graph()->NewNode(
          common()->LoopExitValue(MachineRepresentation::kTagged), values_[i],
          loop_exit);
      values_[i] = rename;
    }
  }
  for (int i = 0; i < register_count(); i++) {
    if (assignments.ContainsLocal(i) &&
        (liveness == nullptr || liveness->RegisterIsLive(i))) {
      Node* rename = graph()->NewNode(
          common()->LoopExitValue(MachineRepresentation::kTagged),
          values_[register_base() + i], loop_exit);
      values_[register_base() + i] = rename;
    }
  }
  if (liveness == nullptr || liveness->AccumulatorIsLive()) {
    Node* rename = graph()->NewNode(
        common()->LoopExitValue(MachineRepresentation::kTagged),
        values_[accumulator_base()], loop_exit);
    values_[accumulator_base()] = rename;
  }

  if (generator_state_ != nullptr) {
    generator_state_ = graph()->NewNode(
        common()->LoopExitValue(MachineRepresentation::kTagged),
        generator_state_, loop_exit);
  }
}

void BytecodeGraphBuilder::Environment::UpdateStateValues(Node** state_values,
                                                          Node** values,
                                                          int count) {
  if (StateValuesRequireUpdate(state_values, values, count)) {
    const Operator* op = common()->StateValues(count, SparseInputMask::Dense());
    (*state_values) = graph()->NewNode(op, count, values);
  }
}

Node* BytecodeGraphBuilder::Environment::GetStateValuesFromCache(
    Node** values, int count, const BytecodeLivenessState* liveness) {
  return builder_->state_values_cache_.GetNodeForValues(
      values, static_cast<size_t>(count), liveness);
}

Node* BytecodeGraphBuilder::Environment::Checkpoint(
    BytecodeOffset bailout_id, OutputFrameStateCombine combine,
    const BytecodeLivenessState* liveness) {
  if (parameter_count() == register_count()) {
    // Re-use the state-value cache if the number of local registers happens
    // to match the parameter count.
    parameters_state_values_ =
        GetStateValuesFromCache(&values()->at(0), parameter_count(), nullptr);
  } else {
    UpdateStateValues(&parameters_state_values_, &values()->at(0),
                      parameter_count());
  }

  Node* registers_state_values = GetStateValuesFromCache(
      &values()->at(register_base()), register_count(), liveness);

  bool accumulator_is_live = !liveness || liveness->AccumulatorIsLive();
  Node* accumulator_state_value =
      accumulator_is_live && combine != OutputFrameStateCombine::PokeAt(0)
          ? values()->at(accumulator_base())
          : builder()->jsgraph()->OptimizedOutConstant();

  const Operator* op = common()->FrameState(
      bailout_id, combine, builder()->frame_state_function_info());
  Node* result = graph()->NewNode(
      op, parameters_state_values_, registers_state_values,
      accumulator_state_value, Context(), builder()->GetFunctionClosure(),
      builder()->graph()->start());

  return result;
}

class BytecodeGraphBuilder::BytecodePositionDecorator final :
public GraphDecorator {
 public:
  explicit BytecodePositionDecorator(NodeOriginTable* node_origins)
      :  node_origins_(node_origins) {}

  void Decorate(Node* node) final {
    node_origins_->SetNodeOrigin(node->id(), NodeOrigin::kJSBytecode,
                                 node_origins_->GetCurrentBytecodePosition());
  }

 private:
  NodeOriginTable* node_origins_;
};

BytecodeGraphBuilder::BytecodeGraphBuilder(
    JSHeapBroker* broker, Zone* local_zone, NativeContextRef native_context,
    SharedFunctionInfoRef shared_info, BytecodeArrayRef bytecode,
    FeedbackCellRef feedback_cell, BytecodeOffset osr_offset, JSGraph* jsgraph,
    CallFrequency const& invocation_frequency,
    SourcePositionTable* source_positions, NodeOriginTable* node_origins,
    int inlining_id, CodeKind code_kind, BytecodeGraphBuilderFlags flags,
    TickCounter* tick_counter, ObserveNodeInfo const& observe_node_info)
    : broker_(broker),
      local_isolate_(broker_->local_isolate()
                         ? broker_->local_isolate()
                         : broker_->isolate()->AsLocalIsolate()),
      local_zone_(local_zone),
      jsgraph_(jsgraph),
      native_context_(native_context),
      shared_info_(shared_info),
      bytecode_array_(bytecode),
      feedback_cell_(feedback_cell),
      feedback_vector_(feedback_cell.feedback_vector(broker).value()),
      invocation_frequency_(invocation_frequency),
      type_hint_lowering_(
          broker, jsgraph, feedback_vector_,
          (flags & BytecodeGraphBuilderFlag::kBailoutOnUninitialized)
              ? JSTypeHintLowering::kBailoutOnUninitialized
              : JSTypeHintLowering::kNoFlags),
      frame_state_function_info_(common()->CreateFrameStateFunctionInfo(
          FrameStateType::kUnoptimizedFunction,
          bytecode_array().parameter_count(), bytecode_array().max_arguments(),
          bytecode_array().register_count(), shared_info.object(),
          bytecode_array().object())),
      source_position_iterator_(bytecode_array().SourcePositionTable(broker)),
      bytecode_iterator_(bytecode_array().object()),
      bytecode_analysis_(
          bytecode_array().object(), local_zone, osr_offset,
          flags & BytecodeGraphBuilderFlag::kAnalyzeEnvironmentLiveness),
      environment_(nullptr),
      decorator_(nullptr),
      osr_(!osr_offset.IsNone()),
      currently_peeled_loop_offset_(-1),
      skip_first_stack_and_tierup_check_(
          flags & BytecodeGraphBuilderFlag::kSkipFirstStackAndTierupCheck),
      merge_environments_(local_zone),
      generator_merge_environments_(local_zone),
      cached_parameters_(local_zone),
      exception_handlers_(local_zone),
      current_exception_handler_(0),
      input_buffer_size_(0),
      input_buffer_(nullptr),
      code_kind_(code_kind),
      feedback_vector_node_(nullptr),
      native_context_node_(nullptr),
      needs_eager_checkpoint_(true),
      exit_controls_(local_zone),
      state_values_cache_(jsgraph),
      node_origins_(node_origins),
      source_positions_(source_positions),
      start_position_(shared_info.StartPosition(), inlining_id),
      tick_counter_(tick_counter),
      observe_node_info_(observe_node_info) {}

Node* BytecodeGraphBuilder::GetFunctionClosure() {
  if (!function_closure_.is_set()) {
    int index = Linkage::kJSCallClosureParamIndex;
    Node* node = GetParameter(index, "%closure");
    function_closure_.set(node);
  }
  return function_closure_.get();
}

Node* BytecodeGraphBuilder::GetParameter(int parameter_index,
                                         const char* debug_name_hint) {
  // We use negative indices for some parameters.
  DCHECK_LE(ParameterInfo::kMinIndex, parameter_index);
  const size_t index =
      static_cast<size_t>(parameter_index - ParameterInfo::kMinIndex);

  if (cached_parameters_.size() <= index) {
    cached_parameters_.resize(index + 1, nullptr);
  }

  if (cached_parameters_[index] == nullptr) {
    cached_parameters_[index] =
        NewNode(common()->Parameter(parameter_index, debug_name_hint),
                graph()->start());
  }

  return cached_parameters_[index];
}

void BytecodeGraphBuilder::CreateFeedbackVectorNode() {
  DCHECK_NULL(feedback_vector_node_);
  feedback_vector_node_ =
      jsgraph()->ConstantNoHole(feedback_vector(), broker());
}

Node* BytecodeGraphBuilder::BuildLoadFeedbackCell(int index) {
  return jsgraph()->ConstantNoHole(
      feedback_vector().GetClosureFeedbackCell(broker(), index), broker());
}

void BytecodeGraphBuilder::CreateNativeContextNode() {
  DCHECK_NULL(native_context_node_);
  native_context_node_ = jsgraph()->ConstantNoHole(native_context(), broker());
}

Node* BytecodeGraphBuilder::BuildLoadNativeContextField(int index) {
  Node* result = NewNode(javascript()->LoadContext(0, index, true));
  NodeProperties::ReplaceContextInput(result, native_context_node());
  return result;
}

FeedbackSource BytecodeGraphBuilder::CreateFeedbackSource(int slot_id) {
  return CreateFeedbackSource(FeedbackVector::ToSlot(slot_id));
}

FeedbackSource BytecodeGraphBuilder::CreateFeedbackSource(FeedbackSlot slot) {
  return FeedbackSource(feedback_vector(), slot);
}

void BytecodeGraphBuilder::CreateGraph() {
  SourcePositionTable::Scope pos_scope(source_positions_, start_position_);
  if (node_origins_) {
    AddBytecodePositionDecorator();
  }
  // Set up the basic structure of the graph. Outputs for {Start} are the formal
  // parameters (including the receiver) plus new target, number of arguments,
  // context and closure.
  int start_output_arity = StartNode::OutputArityForFormalParameterCount(
      bytecode_array().parameter_count());
  graph()->SetStart(graph()->NewNode(common()->Start(start_output_arity)));

  Environment env(this, bytecode_array().register_count(),
                  bytecode_array().parameter_count(),
                  bytecode_array().incoming_new_target_or_generator_register(),
                  graph()->start());
  set_environment(&env);

  CreateFeedbackVectorNode();
  CreateNativeContextNode();

  VisitBytecodes();

  // Finish the basic structure of the graph.
  DCHECK_NE(0u, exit_controls_.size());
  int const input_count = static_cast<int>(exit_controls_.size());
  Node** const inputs = &exit_controls_.front();
  Node* end = graph()->NewNode(common()->End(input_count), input_count, inputs);
  graph()->SetEnd(end);
  if (node_origins_) {
    RemoveBytecodePositionDecorator();
  }
}

void BytecodeGraphBuilder::PrepareEagerCheckpoint() {
  if (needs_eager_checkpoint()) {
    // Create an explicit checkpoint node for before the operation. This only
    // needs to happen if we aren't effect-dominated by a {Checkpoint} already.
    mark_as_needing_eager_checkpoint(false);
    Node* node = NewNode(common()->Checkpoint());
    DCHECK_EQ(1, OperatorProperties::GetFrameStateInputCount(node->op()));
    DCHECK_EQ(IrOpcode::kDead,
              NodeProperties::GetFrameStateInput(node)->opcode());
    BytecodeOffset bailout_id(bytecode_iterator().current_offset());

    const BytecodeLivenessState* liveness_before =
        bytecode_analysis().GetInLivenessFor(
            bytecode_iterator().current_offset());

    Node* frame_state_before = environment()->Checkpoint(
        bailout_id, OutputFrameStateCombine::Ignore(), liveness_before);
    NodeProperties::ReplaceFrameStateInput(node, frame_state_before);
#ifdef DEBUG
  } else {
    // In case we skipped checkpoint creation above, we must be able to find an
    // existing checkpoint that effect-dominates the nodes about to be created.
    // Starting a search from the current effect-dependency has to succeed.
    Node* effect = environment()->GetEffectDependency();
    while (effect->opcode() != IrOpcode::kCheckpoint) {
      DCHECK(effect->op()->HasProperty(Operator::kNoWrite));
      DCHECK_EQ(1, effect->op()->EffectInputCount());
      effect = NodeProperties::GetEffectInput(effect);
    }
  }
#else
  }
#endif  // DEBUG
}

void BytecodeGraphBuilder::PrepareFrameState(
    Node* node, OutputFrameStateCombine combine, BytecodeOffset bailout_id,
    const BytecodeLivenessState* liveness) {
  if (OperatorProperties::HasFrameStateInput(node->op())) {
    // Add the frame state for after the operation. The node in question has
    // already been created and had a {Dead} frame state input up until now.
    DCHECK_EQ(1, OperatorProperties::GetFrameStateInputCount(node->op()));
    DCHECK_EQ(IrOpcode::kDead,
              NodeProperties::GetFrameStateInput(node)->opcode());

    Node* frame_state_after =
        environment()->Checkpoint(bailout_id, combine, liveness);
    NodeProperties::ReplaceFrameStateInput(node, frame_state_after);
  }
}

void BytecodeGraphBuilder::AdvanceIteratorsTo(int bytecode_offset) {
  for (; bytecode_iterator().current_offset() != bytecode_offset;
       bytecode_iterator().Advance()) {
    int current_offset = bytecode_iterator().current_offset();
    UpdateSourceAndBytecodePosition(current_offset);
  }
}

// Stores the state of the SourcePosition iterator, and the index to the
// current exception handlers stack. We need, during the OSR graph generation,
// to backup the states of these iterators at the LoopHeader offset of each
// outer loop which contains the OSR loop. The iterators are then restored when
// peeling the loops, so that both exception handling and synchronisation with
// the source position can be achieved.
class BytecodeGraphBuilder::OsrIteratorState {
 public:
  explicit OsrIteratorState(BytecodeGraphBuilder* graph_builder)
      : graph_builder_(graph_builder),
        saved_states_(graph_builder->local_zone()) {}

  void ProcessOsrPrelude() {
    ZoneVector<int> outer_loop_offsets(graph_builder_->local_zone());
    int osr_entry = graph_builder_->bytecode_analysis().osr_entry_point();

    // We find here the outermost loop which contains the OSR loop.
    int outermost_loop_offset = osr_entry;
    while ((outermost_loop_offset = graph_builder_->bytecode_analysis()
                                        .GetLoopInfoFor(outermost_loop_offset)
                                        .parent_offset()) != -1) {
      outer_loop_offsets.push_back(outermost_loop_offset);
    }
    outermost_loop_offset =
        outer_loop_offsets.empty() ? osr_entry : outer_loop_offsets.back();
    graph_builder_->AdvanceIteratorsTo(outermost_loop_offset);

    // We save some iterators states at the offsets of the loop headers of the
    // outer loops (the ones containing the OSR loop). They will be used for
    // jumping back in the bytecode.
    for (ZoneVector<int>::const_reverse_iterator it =
             outer_loop_offsets.crbegin();
         it != outer_loop_offsets.crend(); ++it) {
      graph_builder_->AdvanceIteratorsTo(*it);
      graph_builder_->ExitThenEnterExceptionHandlers(
          graph_builder_->bytecode_iterator().current_offset());
      saved_states_.push(IteratorsStates(
          graph_builder_->current_exception_handler(),
          graph_builder_->source_position_iterator().GetState()));
    }

    // Finishing by advancing to the OSR entry
    graph_builder_->AdvanceIteratorsTo(osr_entry);

    // Enters all remaining exception handler which end before the OSR loop
    // so that on next call of VisitSingleBytecode they will get popped from
    // the exception handlers stack.
    graph_builder_->ExitThenEnterExceptionHandlers(osr_entry);
    graph_builder_->set_currently_peeled_loop_offset(
        graph_builder_->bytecode_analysis()
            .GetLoopInfoFor(osr_entry)
            .parent_offset());
  }

  void RestoreState(int target_offset, int new_parent_offset) {
    graph_builder_->bytecode_iterator().SetOffset(target_offset);
    // In case of a return, we must not build loop exits for
    // not-yet-built outer loops.
    graph_builder_->set_currently_peeled_loop_offset(new_parent_offset);
    IteratorsStates saved_state = saved_states_.top();
    graph_builder_->source_position_iterator().RestoreState(
        saved_state.source_iterator_state_);
    graph_builder_->set_current_exception_handler(
        saved_state.exception_handler_index_);
    saved_states_.pop();
  }

 private:
  struct IteratorsStates {
    int exception_handler_index_;
    SourcePositionTableIterator::IndexAndPositionState source_iterator_state_;

    IteratorsStates(int exception_handler_index,
                    SourcePositionTableIterator::IndexAndPositionState
                        source_iterator_state)
        : exception_handler_index_(exception_handler_index),
          source_iterator_state_(source_iterator_state) {}
  };

  BytecodeGraphBuilder* graph_builder_;
  ZoneStack<IteratorsStates> saved_states_;
};

void BytecodeGraphBuilder::RemoveMergeEnvironmentsBeforeOffset(
    int limit_offset) {
  if (!merge_environments_.empty()) {
    ZoneMap<int, Environment*>::iterator it = merge_environments_.begin();
    ZoneMap<int, Environment*>::iterator stop_it = merge_environments_.end();
    while (it != stop_it && it->first <= limit_offset) {
      it = merge_environments_.erase(it);
    }
  }
}

void BytecodeGraphBuilder::BuildFunctionEntryStackCheck() {
  if (!skip_first_stack_check()) {
    DCHECK(exception_handlers_.empty());
    Node* node =
        NewNode(javascript()->StackCheck(StackCheckKind::kJSFunctionEntry));
    PrepareFrameStateForFunctionEntryStackCheck(node);
  }
}

void BytecodeGraphBuilder::BuildIterationBodyStackCheck() {
  Node* node =
      NewNode(javascript()->StackCheck(StackCheckKind::kJSIterationBody));
  environment()->RecordAfterState(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::BuildOSREntryStackCheck() {
  DCHECK(exception_handlers_.empty());
  Node* node =
      NewNode(javascript()->StackCheck(StackCheckKind::kJSFunctionEntry));
  PrepareFrameStateForOSREntryStackCheck(node);
}

// We will iterate through the OSR loop, then its parent, and so on
// until we have reached the outmost loop containing the OSR loop. We do
// not generate nodes for anything before the outermost loop.
void BytecodeGraphBuilder::AdvanceToOsrEntryAndPeelLoops() {
  environment()->FillWithOsrValues();

  // The entry stack check has to happen *before* initialising the OSR prelude;
  // it has to happen before setting up exception handlers, so that the
  // optimized code can't accidentally catch a failingstack with a OSR-ed loop
  // inside a try-catch, e.g.
  //
  //   try {
  //     loop { OSR(); }
  //   } catch {
  //     // Ignore failed stack check.
  //   }
  BuildOSREntryStackCheck();

  OsrIteratorState iterator_states(this);
  iterator_states.ProcessOsrPrelude();
  int osr_entry = bytecode_analysis().osr_entry_point();
  DCHECK_EQ(bytecode_iterator().current_offset(), osr_entry);

  // Suppose we have n nested loops, loop_0 being the outermost one, and
  // loop_n being the OSR loop. We start iterating the bytecode at the header
  // of loop_n (the OSR loop), and then we peel the part of the the body of
  // loop_{n-1} following the end of loop_n. We then rewind the iterator to
  // the header of loop_{n-1}, and so on until we have partly peeled loop 0.
  // The full loop_0 body will be generating with the rest of the function,
  // outside the OSR generation.

  // To do so, if we are visiting a loop, we continue to visit what's left
  // of its parent, and then when reaching the parent's JumpLoop, we do not
  // create any jump for that but rewind the bytecode iterator to visit the
  // parent loop entirely, and so on.

  int current_parent_offset =
      bytecode_analysis().GetLoopInfoFor(osr_entry).parent_offset();
  while (current_parent_offset != -1) {
    const LoopInfo& current_parent_loop =
        bytecode_analysis().GetLoopInfoFor(current_parent_offset);
    // We iterate until the back edge of the parent loop, which we detect by
    // the offset that the JumpLoop targets.
    for (; !bytecode_iterator().done(); bytecode_iterator().Advance()) {
      if (bytecode_iterator().current_bytecode() ==
              interpreter::Bytecode::kJumpLoop &&
          bytecode_iterator().GetJumpTargetOffset() == current_parent_offset) {
        // Reached the end of the current parent loop.
        break;
      }
      VisitSingleBytecode();
    }
    DCHECK(!bytecode_iterator()
                .done());  // Should have found the loop's jump target.

    // We also need to take care of the merge environments and exceptions
    // handlers here because the omitted JumpLoop bytecode can still be the
    // target of jumps or the first bytecode after a try block.
    ExitThenEnterExceptionHandlers(bytecode_iterator().current_offset());
    SwitchToMergeEnvironment(bytecode_iterator().current_offset());

    // This jump is the jump of our parent loop, which is not yet created.
    // So we do not build the jump nodes, but restore the bytecode and the
    // SourcePosition iterators to the values they had when we were visiting
    // the offset pointed at by the JumpLoop we've just reached.
    // We have already built nodes for inner loops, but now we will
    // iterate again over them and build new nodes corresponding to the same
    // bytecode offsets. Any jump or reference to this inner loops must now
    // point to the new nodes we will build, hence we clear the relevant part
    // of the environment.
    // Completely clearing the environment is not possible because merge
    // environments for forward jumps out of the loop need to be preserved
    // (e.g. a return or a labeled break in the middle of a loop).
    RemoveMergeEnvironmentsBeforeOffset(bytecode_iterator().current_offset());
    iterator_states.RestoreState(current_parent_offset,
                                 current_parent_loop.parent_offset());
    current_parent_offset = current_parent_loop.parent_offset();
  }
}

void BytecodeGraphBuilder::VisitSingleBytecode() {
  tick_counter_->TickAndMaybeEnterSafepoint();
  int current_offset = bytecode_iterator().current_offset();
  UpdateSourceAndBytecodePosition(current_offset);
  ExitThenEnterExceptionHandlers(current_offset);
  DCHECK_GE(exception_handlers_.empty() ? current_offset
                                        : exception_handlers_.top().end_offset_,
            current_offset);
  SwitchToMergeEnvironment(current_offset);

  if (environment() != nullptr) {
    BuildLoopHeaderEnvironment(current_offset);

    switch (bytecode_iterator().current_bytecode()) {
#define BYTECODE_CASE(name, ...)       \
  case interpreter::Bytecode::k##name: \
    Visit##name();                     \
    break;
      BYTECODE_LIST(BYTECODE_CASE, BYTECODE_CASE)
#undef BYTECODE_CASE
    }
  }
}

void BytecodeGraphBuilder::VisitBytecodes() {
  if (!bytecode_analysis().resume_jump_targets().empty()) {
    environment()->BindGeneratorState(
        jsgraph()->SmiConstant(JSGeneratorObject::kGeneratorExecuting));
  }

  if (osr_) {
    // We peel the OSR loop and any outer loop containing it except that we
    // leave the nodes corresponding to the whole outermost loop (including
    // the last copies of the loops it contains) to be generated by the normal
    // bytecode iteration below.
    AdvanceToOsrEntryAndPeelLoops();
  } else {
    BuildFunctionEntryStackCheck();
  }

  for (; !bytecode_iterator().done(); bytecode_iterator().Advance()) {
    VisitSingleBytecode();
  }

  DCHECK(exception_handlers_.empty());
}

void BytecodeGraphBuilder::AddBytecodePositionDecorator() {
  DCHECK_NULL(decorator_);
  decorator_ = graph_zone()->New<BytecodePositionDecorator>(node_origins_);
  graph()->AddDecorator(decorator_);
}

void BytecodeGraphBuilder::RemoveBytecodePositionDecorator() {
  DCHECK_NOT_NULL(decorator_);
  graph()->RemoveDecorator(decorator_);
  decorator_ = nullptr;
}

void BytecodeGraphBuilder::VisitLdaZero() {
  Node* node = jsgraph()->ZeroConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaSmi() {
  Node* node =
      jsgraph()->ConstantNoHole(bytecode_iterator().GetImmediateOperand(0));
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaConstant() {
  ObjectRef object = MakeRefForConstantForIndexOperand(0);
  Node* node = jsgraph()->ConstantNoHole(object, broker());
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaUndefined() {
  Node* node = jsgraph()->UndefinedConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaNull() {
  Node* node = jsgraph()->NullConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaTheHole() {
  Node* node = jsgraph()->TheHoleConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaTrue() {
  Node* node = jsgraph()->TrueConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaFalse() {
  Node* node = jsgraph()->FalseConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdar() {
  Node* value =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  environment()->BindAccumulator(value);
}

void BytecodeGraphBuilder::VisitStar() {
  Node* value = environment()->LookupAccumulator();
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(0), value);
}

#define SHORT_STAR_VISITOR(Name, ...)                                         \
  void BytecodeGraphBuilder::Visit##Name() {                                  \
    Node* value = environment()->LookupAccumulator();                         \
    environment()->BindRegister(                                              \
        interpreter::Register::FromShortStar(interpreter::Bytecode::k##Name), \
        value);                                                               \
  }
SHORT_STAR_BYTECODE_LIST(SHORT_STAR_VISITOR)
#undef SHORT_STAR_VISITOR

void BytecodeGraphBuilder::VisitMov() {
  Node* value =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(1), value);
}

Node* BytecodeGraphBuilder::BuildLoadGlobal(NameRef name,
                                            uint32_t feedback_slot_index,
                                            TypeofMode typeof_mode) {
  FeedbackSource feedback = CreateFeedbackSource(feedback_slot_index);
  DCHECK(IsLoadGlobalICKind(broker()->GetFeedbackSlotKind(feedback)));
  const Operator* op = javascript()->LoadGlobal(name, feedback, typeof_mode);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  return NewNode(op, feedback_vector_node());
}

void BytecodeGraphBuilder::VisitLdaGlobal() {
  PrepareEagerCheckpoint();
  NameRef name = MakeRefForConstantForIndexOperand<Name>(0);
  uint32_t feedback_slot_index = bytecode_iterator().GetIndexOperand(1);
  Node* node =
      BuildLo
"""


```