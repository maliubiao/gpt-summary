Response:
My thinking process to arrive at the summary of `v8/src/maglev/maglev-graph-builder.h` went through these stages:

1. **Initial Skim and Keyword Identification:** I first quickly scanned the code, looking for prominent keywords and structures. Terms like `GraphBuilder`, `Build`, `Node`, `Bytecode`, `Merge`, `Loop`, `Deopt`, `Inline`, `Constant`, `Type`, `FrameState`,  `Visitor`, and namespace names (`v8::internal::maglev`) immediately stood out. These gave me a high-level idea of the file's purpose.

2. **Header Guard and Includes:** The presence of `#ifndef V8_MAGLEV_MAGLEV_GRAPH_BUILDER_H_` and numerous `#include` directives indicated this is a header file defining an interface and likely relying on other V8 components. The included files hinted at functionalities like base utilities, code generation, compiler aspects, interpreter interaction, object representation, and more.

3. **`ReduceResult` Analysis:**  The `ReduceResult` class was prominent early on. I recognized its role in handling results of operations, indicating success, failure, or incompleteness. The `RETURN_IF_DONE` and similar macros reinforced this idea and hinted at a pattern of early exit or branching based on operation outcomes. I noted its structure with the enum `Kind` and the `payload_`.

4. **`MaglevGraphBuilder` Class - Core Focus:**  The main class, `MaglevGraphBuilder`, was clearly the central element. I looked at its public methods, which provided clues about its main functions:
    * `Build()`:  A primary method likely responsible for the overall graph construction.
    * `BuildInlined()`:  Indicates support for inlining function calls.
    * Methods related to prologue/epilogue (`StartPrologue`, `EndPrologue`).
    * Methods for handling arguments (`SetArgument`, `GetArgument`).
    * Methods dealing with loops (`PeelLoop`, `BuildLoopForPeeling`).
    * Methods for obtaining constants (`GetSmiConstant`, `GetInt32Constant`, etc.).
    * Methods for type checking and ensuring (`CheckStaticType`, `CheckType`, `EnsureType`).
    * Accessors for internal components (`graph()`, `zone()`, `broker()`, etc.).
    * Methods related to merging control flow (`ProcessMergePoint`).
    * Methods for handling deoptimization (`EmitUnconditionalDeopt`).

5. **Inferring Functionality from Methods:** By examining the names and parameters of the `MaglevGraphBuilder` methods, I could start inferring its core tasks:
    * **Graph Construction:**  The "GraphBuilder" name and methods like `Build`, and the presence of `Graph* graph()` strongly pointed to this.
    * **Bytecode Processing:** The inclusion of interpreter-related headers and the `VisitSingleBytecode()` method suggested the builder iterates through bytecode instructions.
    * **Control Flow Management:** Methods like `Goto`, `GotoIfTrue`, `GotoIfFalse`, `Bind`, and the presence of `BasicBlock` indicated the builder constructs the control flow graph. The merging-related methods (`ProcessMergePoint`) further supported this.
    * **Data Flow Management:** Methods for getting and setting arguments, initializing registers, and the presence of `ValueNode` suggested the builder manages data flow between operations.
    * **Optimization Techniques:**  Features like loop peeling (`PeelLoop`), inlining (`BuildInlined`), and type checking/ensuring hinted at optimization strategies.
    * **Deoptimization Handling:** The presence of `Deopt` nodes and related methods showed the builder handles situations where optimized code needs to revert to the interpreter.
    * **Constant Handling:** The `Get...Constant` methods indicated efficient management of constant values.
    * **Type System Integration:** The various `CheckType` and `EnsureType` methods suggested the builder works with type information to make optimization decisions.

6. **Nested Class Analysis:** I noted the `MaglevSubGraphBuilder` and its purpose of creating isolated subgraphs, which is important for constructs like conditional expressions or short-circuiting logic.

7. **Macros and Enums:** The macros like `RETURN_IF_DONE`, `RETURN_VOID_IF_DONE`, and the enums like `ToNumberHint` and `UseReprHintRecording` provided insights into specific patterns and options within the graph building process.

8. **Comments and Copyright:**  The copyright notice and occasional comments provided context and confirmed it's part of the V8 project.

9. **Synthesizing the Summary:**  Based on the above analysis, I started formulating the summary, focusing on the core responsibilities of the `MaglevGraphBuilder`. I used the identified keywords and concepts to structure the description. I specifically highlighted:
    * Its role in the Maglev compiler pipeline.
    * Its primary function of converting bytecode to a Maglev IR graph.
    * Key aspects like control flow, data flow, inlining, loop handling, deoptimization, and type system integration.
    * The helper classes and macros that support its functionality.

10. **Addressing Specific Instructions:** Finally, I went through the specific instructions in the prompt:
    * **Listing functions:** I explicitly listed the major functional areas.
    * **`.tq` check:** I confirmed it's a `.h` file, not `.tq`.
    * **JavaScript relation:** I inferred the relationship through bytecode processing and the goal of optimizing JavaScript execution.
    * **Code logic/examples:**  While the header doesn't have executable code, I used the method names to *infer* logic (e.g., type checking before an operation). I couldn't provide concrete JavaScript examples *directly* from the header but explained the *purpose* in the context of JavaScript optimization.
    * **Common programming errors:** I linked type errors and incorrect assumptions to the type checking and deoptimization mechanisms.
    * **Part 1 summary:** I explicitly stated that the provided text is primarily the header file definition, focusing on declaring the interface and data structures.

By following these steps, I could systematically analyze the header file and generate a comprehensive summary of its functionality within the V8 Maglev compiler.
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_MAGLEV_MAGLEV_GRAPH_BUILDER_H_
#define V8_MAGLEV_MAGLEV_GRAPH_BUILDER_H_

#include <cmath>
#include <iomanip>
#include <map>
#include <optional>
#include <type_traits>
#include <utility>

#include "src/base/functional.h"
#include "src/base/logging.h"
#include "src/base/vector.h"
#include "src/codegen/external-reference.h"
#include "src/codegen/source-position-table.h"
#include "src/common/globals.h"
#include "src/compiler-dispatcher/optimizing-compile-dispatcher.h"
#include "src/compiler/bytecode-analysis.h"
#include "src/compiler/bytecode-liveness-map.h"
#include "src/compiler/feedback-source.h"
#include "src/compiler/heap-refs.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/processed-feedback.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/flags/flags.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/interpreter/bytecode-decoder.h"
#include "src/interpreter/bytecode-register.h"
#include "src/interpreter/bytecodes.h"
#include "src/interpreter/interpreter-intrinsics.h"
#include "src/maglev/maglev-graph-labeller.h"
#include "src/maglev/maglev-graph-printer.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-interpreter-frame-state.h"
#include "src/maglev/maglev-ir.h"
#include "src/objects/arguments.h"
#include "src/objects/bytecode-array.h"
#include "src/objects/elements-kind.h"
#include "src/objects/string.h"
#include "src/utils/memcopy.h"

namespace v8 {
namespace internal {
namespace maglev {

class CallArguments;

class V8_NODISCARD ReduceResult {
 public:
  enum Kind {
    kDoneWithValue = 0,  // No need to mask while returning the pointer.
    kDoneWithAbort,
    kDoneWithoutValue,
    kFail,
    kNone,
  };

  ReduceResult() : payload_(kNone) {}

  // NOLINTNEXTLINE
  ReduceResult(ValueNode* value) : payload_(value) { DCHECK_NOT_NULL(value); }

  ValueNode* value() const {
    DCHECK(HasValue());
    return payload_.GetPointerWithKnownPayload(kDoneWithValue);
  }
  bool HasValue() const { return kind() == kDoneWithValue; }

  static ReduceResult Done(ValueNode* value) { return ReduceResult(value); }
  static ReduceResult Done() { return ReduceResult(kDoneWithoutValue); }
  static ReduceResult DoneWithAbort() { return ReduceResult(kDoneWithAbort); }
  static ReduceResult Fail() { return ReduceResult(kFail); }

  ReduceResult(const ReduceResult&) V8_NOEXCEPT = default;
  ReduceResult& operator=(const ReduceResult&) V8_NOEXCEPT = default;

  // No/undefined result, created by default constructor.
  bool IsNone() const { return kind() == kNone; }

  // Either DoneWithValue, DoneWithoutValue or DoneWithAbort.
  bool IsDone() const { return !IsFail() && !IsNone(); }

  // ReduceResult failed.
  bool IsFail() const { return kind() == kFail; }

  // Done with a ValueNode.
  bool IsDoneWithValue() const { return HasValue(); }

  // Done without producing a ValueNode.
  bool IsDoneWithoutValue() const { return kind() == kDoneWithoutValue; }

  // Done with an abort (unconditional deopt, infinite loop in an inlined
  // function, etc)
  bool IsDoneWithAbort() const { return kind() == kDoneWithAbort; }

  Kind kind() const { return payload_.GetPayload(); }

 private:
  explicit ReduceResult(Kind kind) : payload_(kind) {}
  base::PointerWithPayload<ValueNode, Kind, 3> payload_;
};

#define RETURN_IF_DONE(result)   \
  do {                           \
    ReduceResult res = (result); \
    if (res.IsDone()) {          \
      return res;                \
    }                            \
  } while (false)

#define RETURN_VOID_IF_DONE(result) \
  do {                              \
    ReduceResult res = (result);    \
    if (res.IsDone()) {             \
      if (res.IsDoneWithAbort()) {  \
        MarkBytecodeDead();         \
        return;                     \
      }                             \
      return;                       \
    }                               \
  } while (false)

#define PROCESS_AND_RETURN_IF_DONE(result, value_processor) \
  do {                                                      \
    ReduceResult res = (result);                            \
    if (res.IsDone()) {                                     \
      if (res.IsDoneWithAbort()) {                          \
        MarkBytecodeDead();                                 \
      } else if (res.IsDoneWithValue()) {                   \
        value_processor(res.value());                       \
      }                                                     \
      return;                                               \
    }                                                       \
  } while (false)

#define RETURN_IF_ABORT(result)             \
  do {                                      \
    if ((result).IsDoneWithAbort()) {       \
      return ReduceResult::DoneWithAbort(); \
    }                                       \
  } while (false)

#define GET_VALUE_OR_ABORT(variable, result) \
  do {                                       \
    ReduceResult res = (result);             \
    if (res.IsDoneWithAbort()) {             \
      return ReduceResult::DoneWithAbort();  \
    }                                        \
    DCHECK(res.IsDoneWithValue());           \
    variable = res.value();                  \
  } while (false)

#define RETURN_VOID_IF_ABORT(result)  \
  do {                                \
    if ((result).IsDoneWithAbort()) { \
      MarkBytecodeDead();             \
      return;                         \
    }                                 \
  } while (false)

#define RETURN_VOID_ON_ABORT(result) \
  do {                               \
    ReduceResult res = (result);     \
    USE(res);                        \
    DCHECK(res.IsDoneWithAbort());   \
    MarkBytecodeDead();              \
    return;                          \
  } while (false)

enum class ToNumberHint {
  kDisallowToNumber,
  kAssumeSmi,
  kAssumeNumber,
  kAssumeNumberOrBoolean,
  kAssumeNumberOrOddball
};

enum class UseReprHintRecording { kRecord, kDoNotRecord };

NodeType StaticTypeForNode(compiler::JSHeapBroker* broker,
                           LocalIsolate* isolate, ValueNode* node);

class MaglevGraphBuilder {
 public:
  class DeoptFrameScope;

  explicit MaglevGraphBuilder(
      LocalIsolate* local_isolate, MaglevCompilationUnit* compilation_unit,
      Graph* graph, float call_frequency = 1.0f,
      BytecodeOffset caller_bytecode_offset = BytecodeOffset::None(),
      bool caller_is_inside_loop = false,
      int inlining_id = SourcePosition::kNotInlined,
      MaglevGraphBuilder* parent = nullptr);

  void Build() {
    DCHECK(!is_inline());

    StartPrologue();
    for (int i = 0; i < parameter_count(); i++) {
      // TODO(v8:7700): Consider creating InitialValue nodes lazily.
      InitialValue* v = AddNewNode<InitialValue>(
          {}, interpreter::Register::FromParameterIndex(i));
      DCHECK_EQ(graph()->parameters().size(), static_cast<size_t>(i));
      graph()->parameters().push_back(v);
      SetArgument(i, v);
    }

    BuildRegisterFrameInitialization();

    // Don't use the AddNewNode helper for the function entry stack check, so
    // that we can set a custom deopt frame on it.
    FunctionEntryStackCheck* function_entry_stack_check =
        NodeBase::New<FunctionEntryStackCheck>(zone(), 0);
    new (function_entry_stack_check->lazy_deopt_info()) LazyDeoptInfo(
        zone(), GetDeoptFrameForEntryStackCheck(),
        interpreter::Register::invalid_value(), 0, compiler::FeedbackSource());
    AddInitializedNodeToGraph(function_entry_stack_check);

    BuildMergeStates();
    EndPrologue();
    in_prologue_ = false;

    compiler::ScopeInfoRef scope_info =
        compilation_unit_->shared_function_info().scope_info(broker());
    if (scope_info.HasOuterScopeInfo()) {
      scope_info = scope_info.OuterScopeInfo(broker());
      CHECK(scope_info.HasContext());
      graph()->record_scope_info(GetContext(), scope_info);
    }
    if (compilation_unit_->is_osr()) {
      OsrAnalyzePrequel();
    }

    BuildBody();
  }

  ReduceResult BuildInlined(ValueNode* context, ValueNode* function,
                            ValueNode* new_target, const CallArguments& args);

  void StartPrologue();
  void SetArgument(int i, ValueNode* value);
  void InitializeRegister(interpreter::Register reg, ValueNode* value);
  ValueNode* GetArgument(int i);
  ValueNode* GetInlinedArgument(int i);
  void BuildRegisterFrameInitialization(ValueNode* context = nullptr,
                                        ValueNode* closure = nullptr,
                                        ValueNode* new_target = nullptr);
  void BuildMergeStates();
  BasicBlock* EndPrologue();
  void PeelLoop();
  void BuildLoopForPeeling();

  void OsrAnalyzePrequel();

  void BuildBody() {
    while (!source_position_iterator_.done() &&
           source_position_iterator_.code_offset() < entrypoint_) {
      current_source_position_ = SourcePosition(
          source_position_iterator_.source_position().ScriptOffset(),
          inlining_id_);
      source_position_iterator_.Advance();
    }
    for (iterator_.SetOffset(entrypoint_); !iterator_.done();
         iterator_.Advance()) {
      local_isolate_->heap()->Safepoint();
      if (V8_UNLIKELY(
              loop_headers_to_peel_.Contains(iterator_.current_offset()))) {
        PeelLoop();
        DCHECK_EQ(iterator_.current_bytecode(),
                  interpreter::Bytecode::kJumpLoop);
        continue;
      }
      VisitSingleBytecode();
    }
    DCHECK_EQ(loop_effects_stack_.size(),
              is_inline() && parent_->loop_effects_ ? 1 : 0);
  }

  VirtualObject* CreateVirtualObjectForMerge(compiler::MapRef map,
                                             uint32_t slot_count);

  SmiConstant* GetSmiConstant(int constant) const {
    DCHECK(Smi::IsValid(constant));
    auto it = graph_->smi().find(constant);
    if (it == graph_->smi().end()) {
      SmiConstant* node =
          CreateNewConstantNode<SmiConstant>(0, Smi::FromInt(constant));
      graph_->smi().emplace(constant, node);
      return node;
    }
    return it->second;
  }

  TaggedIndexConstant* GetTaggedIndexConstant(int constant) {
    DCHECK(TaggedIndex::IsValid(constant));
    auto it = graph_->tagged_index().find(constant);
    if (it == graph_->tagged_index().end()) {
      TaggedIndexConstant* node = CreateNewConstantNode<TaggedIndexConstant>(
          0, TaggedIndex::FromIntptr(constant));
      graph_->tagged_index().emplace(constant, node);
      return node;
    }
    return it->second;
  }

  Int32Constant* GetInt32Constant(int32_t constant) {
    auto it = graph_->int32().find(constant);
    if (it == graph_->int32().end()) {
      Int32Constant* node = CreateNewConstantNode<Int32Constant>(0, constant);
      graph_->int32().emplace(constant, node);
      return node;
    }
    return it->second;
  }

  Uint32Constant* GetUint32Constant(int constant) {
    auto it = graph_->uint32().find(constant);
    if (it == graph_->uint32().end()) {
      Uint32Constant* node = CreateNewConstantNode<Uint32Constant>(0, constant);
      graph_->uint32().emplace(constant, node);
      return node;
    }
    return it->second;
  }

  Float64Constant* GetFloat64Constant(double constant) {
    return GetFloat64Constant(
        Float64::FromBits(base::double_to_uint64(constant)));
  }

  Float64Constant* GetFloat64Constant(Float64 constant) {
    auto it = graph_->float64().find(constant.get_bits());
    if (it == graph_->float64().end()) {
      Float64Constant* node =
          CreateNewConstantNode<Float64Constant>(0, constant);
      graph_->float64().emplace(constant.get_bits(), node);
      return node;
    }
    return it->second;
  }

  ValueNode* GetNumberConstant(double constant);

  static compiler::OptionalHeapObjectRef TryGetConstant(
      compiler::JSHeapBroker* broker, LocalIsolate* isolate, ValueNode* node);

  Graph* graph() const { return graph_; }
  Zone* zone() const { return compilation_unit_->zone(); }
  MaglevCompilationUnit* compilation_unit() const { return compilation_unit_; }
  const InterpreterFrameState& current_interpreter_frame() const {
    return current_interpreter_frame_;
  }
  MaglevGraphBuilder* parent() const { return parent_; }
  const DeoptFrameScope* current_deopt_scope() const {
    return current_deopt_scope_;
  }
  compiler::JSHeapBroker* broker() const { return broker_; }
  LocalIsolate* local_isolate() const { return local_isolate_; }

  bool has_graph_labeller() const {
    return compilation_unit_->has_graph_labeller();
  }
  MaglevGraphLabeller* graph_labeller() const {
    return compilation_unit_->graph_labeller();
  }

  DeoptFrame GetLatestCheckpointedFrame();

  bool need_checkpointed_loop_entry() {
    return v8_flags.maglev_speculative_hoist_phi_untagging ||
           v8_flags.maglev_licm;
  }

  bool TopLevelFunctionPassMaglevPrintFilter() {
    if (parent_) {
      return parent_->TopLevelFunctionPassMaglevPrintFilter();
    }
    return compilation_unit_->shared_function_info().object()->PassesFilter(
        v8_flags.maglev_print_filter);
  }

  void RecordUseReprHint(Phi* phi, UseRepresentationSet reprs) {
    phi->RecordUseReprHint(reprs, iterator_.current_offset());
  }
  void RecordUseReprHint(Phi* phi, UseRepresentation repr) {
    RecordUseReprHint(phi, UseRepresentationSet{repr});
  }
  void RecordUseReprHintIfPhi(ValueNode* node, UseRepresentation repr) {
    if (Phi* phi = node->TryCast<Phi>()) {
      RecordUseReprHint(phi, repr);
    }
  }

 private:
  // Helper class for building a subgraph with its own control flow, that is not
  // attached to any bytecode.
  //
  // It does this by creating a fake dummy compilation unit and frame state, and
  // wrapping up all the places where it pretends to be interpreted but isn't.
  class MaglevSubGraphBuilder {
   public:
    class Variable;
    class Label;
    class LoopLabel;

    MaglevSubGraphBuilder(MaglevGraphBuilder* builder, int variable_count);
    LoopLabel BeginLoop(std::initializer_list<Variable*> loop_vars);
    template <typename ControlNodeT, typename... Args>
    void GotoIfTrue(Label* true_target,
                    std::initializer_list<ValueNode*> control_inputs,
                    Args&&... args);
    template <typename ControlNodeT, typename... Args>
    void GotoIfFalse(Label* false_target,
                     std::initializer_list<ValueNode*> control_inputs,
                     Args&&... args);
    void GotoOrTrim(Label* label);
    void Goto(Label* label);
    void ReducePredecessorCount(Label* label, unsigned num = 1);
    void EndLoop(LoopLabel* loop_label);
    void Bind(Label* label);
    V8_NODISCARD ReduceResult TrimPredecessorsAndBind(Label* label);
    void set(Variable& var, ValueNode* value);
    ValueNode* get(const Variable& var) const;

    template <typename FCond, typename FTrue, typename FFalse>
    ReduceResult Branch(std::initializer_list<Variable*> vars, FCond cond,
                        FTrue if_true, FFalse if_false);

    void MergeIntoLabel(Label* label, BasicBlock* predecessor);

   private:
    class BorrowParentKnownNodeAspectsAndVOs;
    void TakeKnownNodeAspectsAndVOsFromParent();
    void MoveKnownNodeAspectsAndVOsToParent();

    MaglevGraphBuilder* builder_;
    MaglevCompilationUnit* compilation_unit_;
    InterpreterFrameState pseudo_frame_;
  };

  // TODO(olivf): Currently identifying dead code relies on the fact that loops
  // must be entered through the loop header by at least one of the
  // predecessors. We might want to re-evaluate this in case we want to be able
  // to OSR into nested loops while compiling the full continuation.
  static constexpr bool kLoopsMustBeEnteredThroughHeader = true;

  class CallSpeculationScope;
  class SaveCallSpeculationScope;

  bool CheckStaticType(ValueNode* node, NodeType type, NodeType* old = nullptr);
  bool CheckType(ValueNode* node, NodeType type, NodeType* old = nullptr);
  NodeType CheckTypes(ValueNode* node, std::initializer_list<NodeType> types);
  bool EnsureType(ValueNode* node, NodeType type, NodeType* old = nullptr);
  NodeType GetType(ValueNode* node);
  NodeInfo* GetOrCreateInfoFor(ValueNode* node) {
    return known_node_aspects().GetOrCreateInfoFor(node, broker(),
                                                   local_isolate());
  }

  // Returns true if we statically know that {lhs} and {rhs} have different
  // types.
  bool HaveDifferentTypes(ValueNode* lhs, ValueNode* rhs);
  bool HasDifferentType(ValueNode* lhs, NodeType rhs_type);

  template <typename Function>
  bool EnsureType(ValueNode* node, NodeType type, Function ensure_new_type);
  bool MayBeNullOrUndefined(ValueNode* node);

  void SetKnownValue(ValueNode* node, compiler::ObjectRef constant,
                     NodeType new_node_type);
  bool ShouldEmitInterruptBudgetChecks() {
    if (is_inline()) return false;
    if (compilation_unit()->info()->for_turboshaft_frontend()) {
      // As the top-tier compiler, Turboshaft doesn't need interrupt budget
      // checks.
      return false;
    }
    return v8_flags.force_emit_interrupt_budget_checks || v8_flags.turbofan;
  }
  bool ShouldEmitOsrInterruptBudgetChecks() {
    if (!v8_flags.turbofan || !v8_flags.use_osr || !v8_flags.osr_from_maglev)
      return false;
    if (!graph_->is_osr() && !v8_flags.always_osr_from_maglev) return false;
    // TODO(olivf) OSR from maglev requires lazy recompilation (see
    // CompileOptimizedOSRFromMaglev for details). Without this we end up in
    // deopt loops, e.g., in chromium content_unittests.
    if (!OptimizingCompileDispatcher::Enabled()) {
      return false;
    }
    // TODO(olivf) OSR'ing from inlined loops is something we might want, but
    // can't with our current osr-from-maglev implementation. The reason is that
    // we OSR up by first going down to the interpreter. For inlined loops this
    // means we would deoptimize to the caller and then probably end up in the
    // same maglev osr code again, before reaching the turbofan OSR code in the
    // callee. The solution is to support osr from maglev without
    // deoptimization.
    return !(graph_->is_osr() && is_inline());
  }
  bool MaglevIsTopTier() const { return !v8_flags.turbofan && v8_flags.maglev; }
  BasicBlock* CreateEdgeSplitBlock(BasicBlockRef& jump_targets,
                                   BasicBlock* predecessor) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "== New empty block ==" << std::endl;
      PrintVirtualObjects();
    }
    DCHECK_NULL(current_block_);
    current_block_ = zone()->New<BasicBlock>(nullptr, zone());
    BasicBlock* result = FinishBlock<Jump>({}, &jump_targets);
    result->set_edge_split_block(predecessor);
#ifdef DEBUG
    new_nodes_.clear();
#endif
    return result;
  }

  void ProcessMergePointAtExceptionHandlerStart(int offset) {
    MergePointInterpreterFrameState& merge_state = *merge_states_[offset];
    DCHECK_EQ(merge_state.predecessor_count(), 0);

    // Copy state.
    current_interpreter_frame_.CopyFrom(*compilation_unit_, merge_state);
    // Expressions would have to be explicitly preserved across exceptions.
    // However, at this point we do not know which ones might be used.
    current_interpreter_frame_.known_node_aspects()
        ->ClearAvailableExpressions();

    // Merges aren't simple fallthroughs, so we should reset the checkpoint
    // validity.
    ResetBuilderCachedState();

    // Register exception phis.
    if (has_graph_labeller()) {
      for (Phi* phi : *merge_states_[offset]->phis()) {
        graph_labeller()->RegisterNode(phi, compilation_unit_,
                                       BytecodeOffset(offset),
                                       current_source_position_);
        if (v8_flags.trace_maglev_graph_building) {
          std::cout << "  " << phi << "  "
                    << PrintNodeLabel(graph_labeller(), phi) << ": "
                    << PrintNode(graph_labeller(), phi) << std::endl;
        }
      }
    }
  }

  void ProcessMergePoint(int offset, bool preserve_known_node_aspects) {
    // First copy the merge state to be the current state.
    MergePointInterpreterFrameState& merge_state = *merge_states_[offset];
    current_interpreter_frame_.CopyFrom(*compilation_unit_, merge_state,
                                        preserve_known_node_aspects, zone());

    ProcessMergePointPredecessors(merge_state, jump_targets_[offset]);
  }

  // Splits incoming critical edges and labels predecessors.
  void ProcessMergePointPredecessors(
      MergePointInterpreterFrameState& merge_state,
      BasicBlockRef& jump_targets) {
    // Merges aren't simple fallthroughs, so we should reset state which is
    // cached directly on the builder instead of on the merge states.
    ResetBuilderCachedState();

    if (merge_state.is_loop()) {
      DCHECK_EQ(merge_state.predecessors_so_far(),
                merge_state.predecessor_count() - 1);
    } else {
      DCHECK_EQ(merge_state.predecessors_so_far(),
                merge_state.predecessor_count());
    }

    if (merge_state.predecessor_count() == 1) return;

    // Set up edge-split.
    int predecessor_index = merge_state.predecessor_count() - 1;
    if (merge_state.is_loop()) {
      // For loops, the JumpLoop block hasn't been generated yet, and so isn't
      // in the list of jump targets. IT's the last predecessor, so drop the
      // index by one.
      DCHECK(merge_state.is_unmerged_loop());
      predecessor_index--;
    }
    BasicBlockRef* old_jump_targets = jump_targets.Reset();
    while (old_jump_targets != nullptr) {
      BasicBlock* predecessor = merge_state.predecessor_at(predecessor_index);
      CHECK(predecessor);
      ControlNode* control = predecessor->control_node();
      if (control->Is<ConditionalControlNode>()) {
        // CreateEmptyBlock automatically registers itself with the offset.
        predecessor = CreateEdgeSplitBlock(jump_targets, predecessor);
        // Set the old predecessor's (the conditional block) reference to
        // point to the new empty predecessor block.
        old_jump_targets =
            old_jump_targets->SetToBlockAndReturnNext(predecessor);
        merge_state.set_predecessor_at(predecessor_index, predecessor);
      } else {
        // Re-register the block in the offset's ref list.
        old_jump_targets = old_jump_targets->MoveToRefList(&jump_targets);
      }
      // We only set the predecessor id after splitting critical edges, to make
      // sure the edge split blocks pick up the correct predecessor index.
      predecessor->set_predecessor_id(predecessor_index--);
    }
    DCHECK_EQ(predecessor_index, -1);
    RegisterPhisWithGraphLabeller(merge_state);
  }

  void RegisterPhisWithGraphLabeller(
      MergePointInterpreterFrameState& merge_state) {
    if (!has_graph_labeller()) return;

    for (Phi* phi : *merge_state.phis()) {
      graph_labeller()->RegisterNode(phi);
      if (v8_flags.trace_maglev_graph_building) {
        std::cout << "  " << phi << "  "
                  << PrintNodeLabel(graph_labeller(), phi) << ": "
                  << PrintNode(graph_labeller(), phi) << std::endl;
      }
    }
  }

  // Return true if the given offset is a merge point, i.e. there are jumps
  // targetting it.
  bool IsOffsetAMergePoint(int offset) {
    return merge_states_[offset] != nullptr;
  }

  ValueNode* GetContextAtDepth(ValueNode* context, size_t depth);
  bool CheckContextExtensions(size_t depth);

  // Called when a block is killed by an unconditional eager deopt.
  ReduceResult EmitUnconditionalDeopt(DeoptimizeReason reason) {
    current_block_->set_deferred(true);
    // Create a block rather than calling finish, since we don't yet know the
    // next block's offset before the loop skipping the rest of the bytecodes.
    FinishBlock<Deopt>({}, reason);
    return ReduceResult::DoneWithAbort();
  }

  void KillPeeledLoopTargets(int peelings) {
    DCHECK_EQ(iterator_.current_bytecode(), interpreter::Bytecode::kJumpLoop);
    int target = iterator_.GetJumpTargetOffset();
    // Since we ended up not peeling we must kill all the doubly accounted
    // jumps out of the loop.
    interpreter::BytecodeArrayIterator iterator(bytecode().object());
    for (iterator.SetOffset(target);
         iterator.current_offset() < iterator_.current_offset();

Prompt: 
```
这是目录为v8/src/maglev/maglev-graph-builder.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_MAGLEV_MAGLEV_GRAPH_BUILDER_H_
#define V8_MAGLEV_MAGLEV_GRAPH_BUILDER_H_

#include <cmath>
#include <iomanip>
#include <map>
#include <optional>
#include <type_traits>
#include <utility>

#include "src/base/functional.h"
#include "src/base/logging.h"
#include "src/base/vector.h"
#include "src/codegen/external-reference.h"
#include "src/codegen/source-position-table.h"
#include "src/common/globals.h"
#include "src/compiler-dispatcher/optimizing-compile-dispatcher.h"
#include "src/compiler/bytecode-analysis.h"
#include "src/compiler/bytecode-liveness-map.h"
#include "src/compiler/feedback-source.h"
#include "src/compiler/heap-refs.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/processed-feedback.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/flags/flags.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/interpreter/bytecode-decoder.h"
#include "src/interpreter/bytecode-register.h"
#include "src/interpreter/bytecodes.h"
#include "src/interpreter/interpreter-intrinsics.h"
#include "src/maglev/maglev-graph-labeller.h"
#include "src/maglev/maglev-graph-printer.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-interpreter-frame-state.h"
#include "src/maglev/maglev-ir.h"
#include "src/objects/arguments.h"
#include "src/objects/bytecode-array.h"
#include "src/objects/elements-kind.h"
#include "src/objects/string.h"
#include "src/utils/memcopy.h"

namespace v8 {
namespace internal {
namespace maglev {

class CallArguments;

class V8_NODISCARD ReduceResult {
 public:
  enum Kind {
    kDoneWithValue = 0,  // No need to mask while returning the pointer.
    kDoneWithAbort,
    kDoneWithoutValue,
    kFail,
    kNone,
  };

  ReduceResult() : payload_(kNone) {}

  // NOLINTNEXTLINE
  ReduceResult(ValueNode* value) : payload_(value) { DCHECK_NOT_NULL(value); }

  ValueNode* value() const {
    DCHECK(HasValue());
    return payload_.GetPointerWithKnownPayload(kDoneWithValue);
  }
  bool HasValue() const { return kind() == kDoneWithValue; }

  static ReduceResult Done(ValueNode* value) { return ReduceResult(value); }
  static ReduceResult Done() { return ReduceResult(kDoneWithoutValue); }
  static ReduceResult DoneWithAbort() { return ReduceResult(kDoneWithAbort); }
  static ReduceResult Fail() { return ReduceResult(kFail); }

  ReduceResult(const ReduceResult&) V8_NOEXCEPT = default;
  ReduceResult& operator=(const ReduceResult&) V8_NOEXCEPT = default;

  // No/undefined result, created by default constructor.
  bool IsNone() const { return kind() == kNone; }

  // Either DoneWithValue, DoneWithoutValue or DoneWithAbort.
  bool IsDone() const { return !IsFail() && !IsNone(); }

  // ReduceResult failed.
  bool IsFail() const { return kind() == kFail; }

  // Done with a ValueNode.
  bool IsDoneWithValue() const { return HasValue(); }

  // Done without producing a ValueNode.
  bool IsDoneWithoutValue() const { return kind() == kDoneWithoutValue; }

  // Done with an abort (unconditional deopt, infinite loop in an inlined
  // function, etc)
  bool IsDoneWithAbort() const { return kind() == kDoneWithAbort; }

  Kind kind() const { return payload_.GetPayload(); }

 private:
  explicit ReduceResult(Kind kind) : payload_(kind) {}
  base::PointerWithPayload<ValueNode, Kind, 3> payload_;
};

#define RETURN_IF_DONE(result)   \
  do {                           \
    ReduceResult res = (result); \
    if (res.IsDone()) {          \
      return res;                \
    }                            \
  } while (false)

#define RETURN_VOID_IF_DONE(result) \
  do {                              \
    ReduceResult res = (result);    \
    if (res.IsDone()) {             \
      if (res.IsDoneWithAbort()) {  \
        MarkBytecodeDead();         \
        return;                     \
      }                             \
      return;                       \
    }                               \
  } while (false)

#define PROCESS_AND_RETURN_IF_DONE(result, value_processor) \
  do {                                                      \
    ReduceResult res = (result);                            \
    if (res.IsDone()) {                                     \
      if (res.IsDoneWithAbort()) {                          \
        MarkBytecodeDead();                                 \
      } else if (res.IsDoneWithValue()) {                   \
        value_processor(res.value());                       \
      }                                                     \
      return;                                               \
    }                                                       \
  } while (false)

#define RETURN_IF_ABORT(result)             \
  do {                                      \
    if ((result).IsDoneWithAbort()) {       \
      return ReduceResult::DoneWithAbort(); \
    }                                       \
  } while (false)

#define GET_VALUE_OR_ABORT(variable, result) \
  do {                                       \
    ReduceResult res = (result);             \
    if (res.IsDoneWithAbort()) {             \
      return ReduceResult::DoneWithAbort();  \
    }                                        \
    DCHECK(res.IsDoneWithValue());           \
    variable = res.value();                  \
  } while (false)

#define RETURN_VOID_IF_ABORT(result)  \
  do {                                \
    if ((result).IsDoneWithAbort()) { \
      MarkBytecodeDead();             \
      return;                         \
    }                                 \
  } while (false)

#define RETURN_VOID_ON_ABORT(result) \
  do {                               \
    ReduceResult res = (result);     \
    USE(res);                        \
    DCHECK(res.IsDoneWithAbort());   \
    MarkBytecodeDead();              \
    return;                          \
  } while (false)

enum class ToNumberHint {
  kDisallowToNumber,
  kAssumeSmi,
  kAssumeNumber,
  kAssumeNumberOrBoolean,
  kAssumeNumberOrOddball
};

enum class UseReprHintRecording { kRecord, kDoNotRecord };

NodeType StaticTypeForNode(compiler::JSHeapBroker* broker,
                           LocalIsolate* isolate, ValueNode* node);

class MaglevGraphBuilder {
 public:
  class DeoptFrameScope;

  explicit MaglevGraphBuilder(
      LocalIsolate* local_isolate, MaglevCompilationUnit* compilation_unit,
      Graph* graph, float call_frequency = 1.0f,
      BytecodeOffset caller_bytecode_offset = BytecodeOffset::None(),
      bool caller_is_inside_loop = false,
      int inlining_id = SourcePosition::kNotInlined,
      MaglevGraphBuilder* parent = nullptr);

  void Build() {
    DCHECK(!is_inline());

    StartPrologue();
    for (int i = 0; i < parameter_count(); i++) {
      // TODO(v8:7700): Consider creating InitialValue nodes lazily.
      InitialValue* v = AddNewNode<InitialValue>(
          {}, interpreter::Register::FromParameterIndex(i));
      DCHECK_EQ(graph()->parameters().size(), static_cast<size_t>(i));
      graph()->parameters().push_back(v);
      SetArgument(i, v);
    }

    BuildRegisterFrameInitialization();

    // Don't use the AddNewNode helper for the function entry stack check, so
    // that we can set a custom deopt frame on it.
    FunctionEntryStackCheck* function_entry_stack_check =
        NodeBase::New<FunctionEntryStackCheck>(zone(), 0);
    new (function_entry_stack_check->lazy_deopt_info()) LazyDeoptInfo(
        zone(), GetDeoptFrameForEntryStackCheck(),
        interpreter::Register::invalid_value(), 0, compiler::FeedbackSource());
    AddInitializedNodeToGraph(function_entry_stack_check);

    BuildMergeStates();
    EndPrologue();
    in_prologue_ = false;

    compiler::ScopeInfoRef scope_info =
        compilation_unit_->shared_function_info().scope_info(broker());
    if (scope_info.HasOuterScopeInfo()) {
      scope_info = scope_info.OuterScopeInfo(broker());
      CHECK(scope_info.HasContext());
      graph()->record_scope_info(GetContext(), scope_info);
    }
    if (compilation_unit_->is_osr()) {
      OsrAnalyzePrequel();
    }

    BuildBody();
  }

  ReduceResult BuildInlined(ValueNode* context, ValueNode* function,
                            ValueNode* new_target, const CallArguments& args);

  void StartPrologue();
  void SetArgument(int i, ValueNode* value);
  void InitializeRegister(interpreter::Register reg, ValueNode* value);
  ValueNode* GetArgument(int i);
  ValueNode* GetInlinedArgument(int i);
  void BuildRegisterFrameInitialization(ValueNode* context = nullptr,
                                        ValueNode* closure = nullptr,
                                        ValueNode* new_target = nullptr);
  void BuildMergeStates();
  BasicBlock* EndPrologue();
  void PeelLoop();
  void BuildLoopForPeeling();

  void OsrAnalyzePrequel();

  void BuildBody() {
    while (!source_position_iterator_.done() &&
           source_position_iterator_.code_offset() < entrypoint_) {
      current_source_position_ = SourcePosition(
          source_position_iterator_.source_position().ScriptOffset(),
          inlining_id_);
      source_position_iterator_.Advance();
    }
    for (iterator_.SetOffset(entrypoint_); !iterator_.done();
         iterator_.Advance()) {
      local_isolate_->heap()->Safepoint();
      if (V8_UNLIKELY(
              loop_headers_to_peel_.Contains(iterator_.current_offset()))) {
        PeelLoop();
        DCHECK_EQ(iterator_.current_bytecode(),
                  interpreter::Bytecode::kJumpLoop);
        continue;
      }
      VisitSingleBytecode();
    }
    DCHECK_EQ(loop_effects_stack_.size(),
              is_inline() && parent_->loop_effects_ ? 1 : 0);
  }

  VirtualObject* CreateVirtualObjectForMerge(compiler::MapRef map,
                                             uint32_t slot_count);

  SmiConstant* GetSmiConstant(int constant) const {
    DCHECK(Smi::IsValid(constant));
    auto it = graph_->smi().find(constant);
    if (it == graph_->smi().end()) {
      SmiConstant* node =
          CreateNewConstantNode<SmiConstant>(0, Smi::FromInt(constant));
      graph_->smi().emplace(constant, node);
      return node;
    }
    return it->second;
  }

  TaggedIndexConstant* GetTaggedIndexConstant(int constant) {
    DCHECK(TaggedIndex::IsValid(constant));
    auto it = graph_->tagged_index().find(constant);
    if (it == graph_->tagged_index().end()) {
      TaggedIndexConstant* node = CreateNewConstantNode<TaggedIndexConstant>(
          0, TaggedIndex::FromIntptr(constant));
      graph_->tagged_index().emplace(constant, node);
      return node;
    }
    return it->second;
  }

  Int32Constant* GetInt32Constant(int32_t constant) {
    auto it = graph_->int32().find(constant);
    if (it == graph_->int32().end()) {
      Int32Constant* node = CreateNewConstantNode<Int32Constant>(0, constant);
      graph_->int32().emplace(constant, node);
      return node;
    }
    return it->second;
  }

  Uint32Constant* GetUint32Constant(int constant) {
    auto it = graph_->uint32().find(constant);
    if (it == graph_->uint32().end()) {
      Uint32Constant* node = CreateNewConstantNode<Uint32Constant>(0, constant);
      graph_->uint32().emplace(constant, node);
      return node;
    }
    return it->second;
  }

  Float64Constant* GetFloat64Constant(double constant) {
    return GetFloat64Constant(
        Float64::FromBits(base::double_to_uint64(constant)));
  }

  Float64Constant* GetFloat64Constant(Float64 constant) {
    auto it = graph_->float64().find(constant.get_bits());
    if (it == graph_->float64().end()) {
      Float64Constant* node =
          CreateNewConstantNode<Float64Constant>(0, constant);
      graph_->float64().emplace(constant.get_bits(), node);
      return node;
    }
    return it->second;
  }

  ValueNode* GetNumberConstant(double constant);

  static compiler::OptionalHeapObjectRef TryGetConstant(
      compiler::JSHeapBroker* broker, LocalIsolate* isolate, ValueNode* node);

  Graph* graph() const { return graph_; }
  Zone* zone() const { return compilation_unit_->zone(); }
  MaglevCompilationUnit* compilation_unit() const { return compilation_unit_; }
  const InterpreterFrameState& current_interpreter_frame() const {
    return current_interpreter_frame_;
  }
  MaglevGraphBuilder* parent() const { return parent_; }
  const DeoptFrameScope* current_deopt_scope() const {
    return current_deopt_scope_;
  }
  compiler::JSHeapBroker* broker() const { return broker_; }
  LocalIsolate* local_isolate() const { return local_isolate_; }

  bool has_graph_labeller() const {
    return compilation_unit_->has_graph_labeller();
  }
  MaglevGraphLabeller* graph_labeller() const {
    return compilation_unit_->graph_labeller();
  }

  DeoptFrame GetLatestCheckpointedFrame();

  bool need_checkpointed_loop_entry() {
    return v8_flags.maglev_speculative_hoist_phi_untagging ||
           v8_flags.maglev_licm;
  }

  bool TopLevelFunctionPassMaglevPrintFilter() {
    if (parent_) {
      return parent_->TopLevelFunctionPassMaglevPrintFilter();
    }
    return compilation_unit_->shared_function_info().object()->PassesFilter(
        v8_flags.maglev_print_filter);
  }

  void RecordUseReprHint(Phi* phi, UseRepresentationSet reprs) {
    phi->RecordUseReprHint(reprs, iterator_.current_offset());
  }
  void RecordUseReprHint(Phi* phi, UseRepresentation repr) {
    RecordUseReprHint(phi, UseRepresentationSet{repr});
  }
  void RecordUseReprHintIfPhi(ValueNode* node, UseRepresentation repr) {
    if (Phi* phi = node->TryCast<Phi>()) {
      RecordUseReprHint(phi, repr);
    }
  }

 private:
  // Helper class for building a subgraph with its own control flow, that is not
  // attached to any bytecode.
  //
  // It does this by creating a fake dummy compilation unit and frame state, and
  // wrapping up all the places where it pretends to be interpreted but isn't.
  class MaglevSubGraphBuilder {
   public:
    class Variable;
    class Label;
    class LoopLabel;

    MaglevSubGraphBuilder(MaglevGraphBuilder* builder, int variable_count);
    LoopLabel BeginLoop(std::initializer_list<Variable*> loop_vars);
    template <typename ControlNodeT, typename... Args>
    void GotoIfTrue(Label* true_target,
                    std::initializer_list<ValueNode*> control_inputs,
                    Args&&... args);
    template <typename ControlNodeT, typename... Args>
    void GotoIfFalse(Label* false_target,
                     std::initializer_list<ValueNode*> control_inputs,
                     Args&&... args);
    void GotoOrTrim(Label* label);
    void Goto(Label* label);
    void ReducePredecessorCount(Label* label, unsigned num = 1);
    void EndLoop(LoopLabel* loop_label);
    void Bind(Label* label);
    V8_NODISCARD ReduceResult TrimPredecessorsAndBind(Label* label);
    void set(Variable& var, ValueNode* value);
    ValueNode* get(const Variable& var) const;

    template <typename FCond, typename FTrue, typename FFalse>
    ReduceResult Branch(std::initializer_list<Variable*> vars, FCond cond,
                        FTrue if_true, FFalse if_false);

    void MergeIntoLabel(Label* label, BasicBlock* predecessor);

   private:
    class BorrowParentKnownNodeAspectsAndVOs;
    void TakeKnownNodeAspectsAndVOsFromParent();
    void MoveKnownNodeAspectsAndVOsToParent();

    MaglevGraphBuilder* builder_;
    MaglevCompilationUnit* compilation_unit_;
    InterpreterFrameState pseudo_frame_;
  };

  // TODO(olivf): Currently identifying dead code relies on the fact that loops
  // must be entered through the loop header by at least one of the
  // predecessors. We might want to re-evaluate this in case we want to be able
  // to OSR into nested loops while compiling the full continuation.
  static constexpr bool kLoopsMustBeEnteredThroughHeader = true;

  class CallSpeculationScope;
  class SaveCallSpeculationScope;

  bool CheckStaticType(ValueNode* node, NodeType type, NodeType* old = nullptr);
  bool CheckType(ValueNode* node, NodeType type, NodeType* old = nullptr);
  NodeType CheckTypes(ValueNode* node, std::initializer_list<NodeType> types);
  bool EnsureType(ValueNode* node, NodeType type, NodeType* old = nullptr);
  NodeType GetType(ValueNode* node);
  NodeInfo* GetOrCreateInfoFor(ValueNode* node) {
    return known_node_aspects().GetOrCreateInfoFor(node, broker(),
                                                   local_isolate());
  }

  // Returns true if we statically know that {lhs} and {rhs} have different
  // types.
  bool HaveDifferentTypes(ValueNode* lhs, ValueNode* rhs);
  bool HasDifferentType(ValueNode* lhs, NodeType rhs_type);

  template <typename Function>
  bool EnsureType(ValueNode* node, NodeType type, Function ensure_new_type);
  bool MayBeNullOrUndefined(ValueNode* node);

  void SetKnownValue(ValueNode* node, compiler::ObjectRef constant,
                     NodeType new_node_type);
  bool ShouldEmitInterruptBudgetChecks() {
    if (is_inline()) return false;
    if (compilation_unit()->info()->for_turboshaft_frontend()) {
      // As the top-tier compiler, Turboshaft doesn't need interrupt budget
      // checks.
      return false;
    }
    return v8_flags.force_emit_interrupt_budget_checks || v8_flags.turbofan;
  }
  bool ShouldEmitOsrInterruptBudgetChecks() {
    if (!v8_flags.turbofan || !v8_flags.use_osr || !v8_flags.osr_from_maglev)
      return false;
    if (!graph_->is_osr() && !v8_flags.always_osr_from_maglev) return false;
    // TODO(olivf) OSR from maglev requires lazy recompilation (see
    // CompileOptimizedOSRFromMaglev for details). Without this we end up in
    // deopt loops, e.g., in chromium content_unittests.
    if (!OptimizingCompileDispatcher::Enabled()) {
      return false;
    }
    // TODO(olivf) OSR'ing from inlined loops is something we might want, but
    // can't with our current osr-from-maglev implementation. The reason is that
    // we OSR up by first going down to the interpreter. For inlined loops this
    // means we would deoptimize to the caller and then probably end up in the
    // same maglev osr code again, before reaching the turbofan OSR code in the
    // callee. The solution is to support osr from maglev without
    // deoptimization.
    return !(graph_->is_osr() && is_inline());
  }
  bool MaglevIsTopTier() const { return !v8_flags.turbofan && v8_flags.maglev; }
  BasicBlock* CreateEdgeSplitBlock(BasicBlockRef& jump_targets,
                                   BasicBlock* predecessor) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "== New empty block ==" << std::endl;
      PrintVirtualObjects();
    }
    DCHECK_NULL(current_block_);
    current_block_ = zone()->New<BasicBlock>(nullptr, zone());
    BasicBlock* result = FinishBlock<Jump>({}, &jump_targets);
    result->set_edge_split_block(predecessor);
#ifdef DEBUG
    new_nodes_.clear();
#endif
    return result;
  }

  void ProcessMergePointAtExceptionHandlerStart(int offset) {
    MergePointInterpreterFrameState& merge_state = *merge_states_[offset];
    DCHECK_EQ(merge_state.predecessor_count(), 0);

    // Copy state.
    current_interpreter_frame_.CopyFrom(*compilation_unit_, merge_state);
    // Expressions would have to be explicitly preserved across exceptions.
    // However, at this point we do not know which ones might be used.
    current_interpreter_frame_.known_node_aspects()
        ->ClearAvailableExpressions();

    // Merges aren't simple fallthroughs, so we should reset the checkpoint
    // validity.
    ResetBuilderCachedState();

    // Register exception phis.
    if (has_graph_labeller()) {
      for (Phi* phi : *merge_states_[offset]->phis()) {
        graph_labeller()->RegisterNode(phi, compilation_unit_,
                                       BytecodeOffset(offset),
                                       current_source_position_);
        if (v8_flags.trace_maglev_graph_building) {
          std::cout << "  " << phi << "  "
                    << PrintNodeLabel(graph_labeller(), phi) << ": "
                    << PrintNode(graph_labeller(), phi) << std::endl;
        }
      }
    }
  }

  void ProcessMergePoint(int offset, bool preserve_known_node_aspects) {
    // First copy the merge state to be the current state.
    MergePointInterpreterFrameState& merge_state = *merge_states_[offset];
    current_interpreter_frame_.CopyFrom(*compilation_unit_, merge_state,
                                        preserve_known_node_aspects, zone());

    ProcessMergePointPredecessors(merge_state, jump_targets_[offset]);
  }

  // Splits incoming critical edges and labels predecessors.
  void ProcessMergePointPredecessors(
      MergePointInterpreterFrameState& merge_state,
      BasicBlockRef& jump_targets) {
    // Merges aren't simple fallthroughs, so we should reset state which is
    // cached directly on the builder instead of on the merge states.
    ResetBuilderCachedState();

    if (merge_state.is_loop()) {
      DCHECK_EQ(merge_state.predecessors_so_far(),
                merge_state.predecessor_count() - 1);
    } else {
      DCHECK_EQ(merge_state.predecessors_so_far(),
                merge_state.predecessor_count());
    }

    if (merge_state.predecessor_count() == 1) return;

    // Set up edge-split.
    int predecessor_index = merge_state.predecessor_count() - 1;
    if (merge_state.is_loop()) {
      // For loops, the JumpLoop block hasn't been generated yet, and so isn't
      // in the list of jump targets. IT's the last predecessor, so drop the
      // index by one.
      DCHECK(merge_state.is_unmerged_loop());
      predecessor_index--;
    }
    BasicBlockRef* old_jump_targets = jump_targets.Reset();
    while (old_jump_targets != nullptr) {
      BasicBlock* predecessor = merge_state.predecessor_at(predecessor_index);
      CHECK(predecessor);
      ControlNode* control = predecessor->control_node();
      if (control->Is<ConditionalControlNode>()) {
        // CreateEmptyBlock automatically registers itself with the offset.
        predecessor = CreateEdgeSplitBlock(jump_targets, predecessor);
        // Set the old predecessor's (the conditional block) reference to
        // point to the new empty predecessor block.
        old_jump_targets =
            old_jump_targets->SetToBlockAndReturnNext(predecessor);
        merge_state.set_predecessor_at(predecessor_index, predecessor);
      } else {
        // Re-register the block in the offset's ref list.
        old_jump_targets = old_jump_targets->MoveToRefList(&jump_targets);
      }
      // We only set the predecessor id after splitting critical edges, to make
      // sure the edge split blocks pick up the correct predecessor index.
      predecessor->set_predecessor_id(predecessor_index--);
    }
    DCHECK_EQ(predecessor_index, -1);
    RegisterPhisWithGraphLabeller(merge_state);
  }

  void RegisterPhisWithGraphLabeller(
      MergePointInterpreterFrameState& merge_state) {
    if (!has_graph_labeller()) return;

    for (Phi* phi : *merge_state.phis()) {
      graph_labeller()->RegisterNode(phi);
      if (v8_flags.trace_maglev_graph_building) {
        std::cout << "  " << phi << "  "
                  << PrintNodeLabel(graph_labeller(), phi) << ": "
                  << PrintNode(graph_labeller(), phi) << std::endl;
      }
    }
  }

  // Return true if the given offset is a merge point, i.e. there are jumps
  // targetting it.
  bool IsOffsetAMergePoint(int offset) {
    return merge_states_[offset] != nullptr;
  }

  ValueNode* GetContextAtDepth(ValueNode* context, size_t depth);
  bool CheckContextExtensions(size_t depth);

  // Called when a block is killed by an unconditional eager deopt.
  ReduceResult EmitUnconditionalDeopt(DeoptimizeReason reason) {
    current_block_->set_deferred(true);
    // Create a block rather than calling finish, since we don't yet know the
    // next block's offset before the loop skipping the rest of the bytecodes.
    FinishBlock<Deopt>({}, reason);
    return ReduceResult::DoneWithAbort();
  }

  void KillPeeledLoopTargets(int peelings) {
    DCHECK_EQ(iterator_.current_bytecode(), interpreter::Bytecode::kJumpLoop);
    int target = iterator_.GetJumpTargetOffset();
    // Since we ended up not peeling we must kill all the doubly accounted
    // jumps out of the loop.
    interpreter::BytecodeArrayIterator iterator(bytecode().object());
    for (iterator.SetOffset(target);
         iterator.current_offset() < iterator_.current_offset();
         iterator.Advance()) {
      interpreter::Bytecode bc = iterator.current_bytecode();
      DCHECK_NE(bc, interpreter::Bytecode::kJumpLoop);
      int kill = -1;
      if (interpreter::Bytecodes::IsJump(bc) &&
          iterator.GetJumpTargetOffset() > iterator_.current_offset()) {
        kill = iterator.GetJumpTargetOffset();
      } else if (is_inline() && interpreter::Bytecodes::Returns(bc)) {
        kill = inline_exit_offset();
      }
      if (kill != -1) {
        if (merge_states_[kill]) {
          for (int i = 0; i < peelings; ++i) {
            merge_states_[kill]->MergeDead(*compilation_unit_);
          }
        }
        UpdatePredecessorCount(kill, -peelings);
      }
    }
  }

  void MarkBytecodeDead() {
    DCHECK_NULL(current_block_);
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "== Dead ==\n"
                << std::setw(4) << iterator_.current_offset() << " : ";
      interpreter::BytecodeDecoder::Decode(std::cout,
                                           iterator_.current_address());
      std::cout << std::endl;
    }

    // If the current bytecode is a jump to elsewhere, then this jump is
    // also dead and we should make sure to merge it as a dead predecessor.
    interpreter::Bytecode bytecode = iterator_.current_bytecode();
    if (interpreter::Bytecodes::IsForwardJump(bytecode)) {
      // Jumps merge into their target, and conditional jumps also merge into
      // the fallthrough.
      MergeDeadIntoFrameState(iterator_.GetJumpTargetOffset());
      if (interpreter::Bytecodes::IsConditionalJump(bytecode)) {
        MergeDeadIntoFrameState(iterator_.next_offset());
      }
    } else if (bytecode == interpreter::Bytecode::kJumpLoop) {
      // JumpLoop merges into its loop header, which has to be treated
      // specially by the merge.
      if (!in_peeled_iteration() || in_optimistic_peeling_iteration()) {
        MergeDeadLoopIntoFrameState(iterator_.GetJumpTargetOffset());
      }
    } else if (interpreter::Bytecodes::IsSwitch(bytecode)) {
      // Switches merge into their targets, and into the fallthrough.
      for (auto offset : iterator_.GetJumpTableTargetOffsets()) {
        MergeDeadIntoFrameState(offset.target_offset);
      }
      MergeDeadIntoFrameState(iterator_.next_offset());
    } else if (!interpreter::Bytecodes::Returns(bytecode) &&
               !interpreter::Bytecodes::UnconditionallyThrows(bytecode)) {
      // Any other bytecode that doesn't return or throw will merge into the
      // fallthrough.
      MergeDeadIntoFrameState(iterator_.next_offset());
    } else if (interpreter::Bytecodes::Returns(bytecode) && is_inline()) {
      MergeDeadIntoFrameState(inline_exit_offset());
    }

    // TODO(leszeks): We could now continue iterating the bytecode
  }

  void UpdateSourceAndBytecodePosition(int offset) {
    if (source_position_iterator_.done()) return;
    if (source_position_iterator_.code_offset() == offset) {
      current_source_position_ = SourcePosition(
          source_position_iterator_.source_position().ScriptOffset(),
          inlining_id_);
      source_position_iterator_.Advance();
    } else {
      DCHECK_GT(source_position_iterator_.code_offset(), offset);
    }
  }

  void PrintVirtualObjects() {
    if (!v8_flags.trace_maglev_graph_building) return;
    current_interpreter_frame_.virtual_objects().Print(
        std::cout, "* VOs (Interpreter Frame State): ",
        compilation_unit()->graph_labeller());
  }

  void VisitSingleBytecode() {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << std::setw(4) << iterator_.current_offset() << " : ";
      interpreter::BytecodeDecoder::Decode(std::cout,
                                           iterator_.current_address());
      std::cout << std::endl;
    }

    int offset = iterator_.current_offset();
    UpdateSourceAndBytecodePosition(offset);

    MergePointInterpreterFrameState* merge_state = merge_states_[offset];
    if (V8_UNLIKELY(merge_state != nullptr)) {
      bool preserve_known_node_aspects = in_optimistic_peeling_iteration() &&
                                         loop_headers_to_peel_.Contains(offset);
      if (merge_state->is_resumable_loop()) {
        current_for_in_state.enum_cache_indices = nullptr;
      }
      if (current_block_ != nullptr) {
        DCHECK(!preserve_known_node_aspects);
        // TODO(leszeks): Re-evaluate this DCHECK, we might hit it if the only
        // bytecodes in this basic block were only register juggling.
        // DCHECK(!current_block_->nodes().is_empty());
        BasicBlock* predecessor;
        if (merge_state->is_loop() && !merge_state->is_resumable_loop() &&
            need_checkpointed_loop_entry()) {
          predecessor =
              FinishBlock<CheckpointedJump>({}, &jump_targets_[offset]);
        } else {
          predecessor = FinishBlock<Jump>({}, &jump_targets_[offset]);
        }
        merge_state->Merge(this, *compilation_unit_, current_interpreter_frame_,
                           predecessor);
      }
      if (v8_flags.trace_maglev_graph_building) {
        auto detail = merge_state->is_exception_handler() ? "exception handler"
                      : merge_state->is_loop()            ? "loop header"
                                                          : "merge";
        std::cout << "== New block (" << detail << " @" << merge_state
                  << ") at "
                  << compilation_unit()->shared_function_info().object()
                  << "==" << std::endl;
        PrintVirtualObjects();
      }

      if (V8_UNLIKELY(merge_state->is_exception_handler())) {
        DCHECK_EQ(predecessor_count(offset), 0);
        // If we have no reference to this block, then the exception handler is
        // dead.
        if (!jump_targets_[offset].has_ref() ||
            !merge_state->exception_handler_was_used()) {
          MarkBytecodeDead();
          return;
        }
        ProcessMergePointAtExceptionHandlerStart(offset);
      } else if (merge_state->is_loop() && !merge_state->is_resumable_loop() &&
                 merge_state->is_unreachable_loop()) {
        // We encoutered a loop header that is only reachable by the JumpLoop
        // back-edge, but the bytecode_analysis didn't notice upfront. This can
        // e.g. be a loop that is entered on a dead fall-through.
        static_assert(kLoopsMustBeEnteredThroughHeader);
        MarkBytecodeDead();
        return;
      } else {
        ProcessMergePoint(offset, preserve_known_node_aspects);
      }

      if (is_loop_effect_tracking_enabled() && merge_state->is_loop()) {
        BeginLoopEffects(offset);
      }
      // We pass nullptr for the `predecessor` argument of StartNewBlock because
      // this block is guaranteed to have a merge_state_, and hence to not have
      // a `predecessor_` field.
      StartNewBlock(offset, /*predecessor*/ nullptr);
    } else if (V8_UNLIKELY(current_block_ == nullptr)) {
      // If we don't have a current block, the bytecode must be dead (because of
      // some earlier deopt). Mark this bytecode dead too and return.
      // TODO(leszeks): Merge these two conditions by marking dead states with
      // a sentinel value.
#ifdef DEBUG
      if (predecessor_count(offset) == 1) {
        DCHECK_NULL(merge_state);
        DCHECK(bytecode_analysis().IsLoopHeader(offset));
      } else {
        DCHECK_EQ(predecessor_count(offset), 0);
      }
#endif
      MarkBytecodeDead();
      return;
    }

    // Handle exceptions if we have a table.
    if (bytecode().handler_table_size() > 0) {
      // Pop all entries where offset >= end.
      while (IsInsideTryBlock()) {
        HandlerTableEntry& entry = catch_block_stack_.top();
        if (offset < entry.end) break;
        catch_block_stack_.pop();
      }
      // Push new entries from interpreter handler table where offset >= start
      // && offset < end.
      HandlerTable table(*bytecode().object());
      while (next_handler_table_index_ < table.NumberOfRangeEntries()) {
        int start = table.GetRangeStart(next_handler_table_index_);
        if (offset < start) break;
        int end = table.GetRangeEnd(next_handler
"""


```