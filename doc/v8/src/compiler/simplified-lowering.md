Response: The user wants to understand the functionality of the C++ code file `v8/src/compiler/simplified-lowering.cc`. The request specifically asks for a summary of its purpose and a JavaScript example if it relates to JavaScript functionality. This is the first of four parts of the file.

**Plan:**

1. **Read the header comments:** These usually provide a high-level overview.
2. **Identify key classes and enums:** Look for names that suggest the file's purpose. The enum `Phase` and the class `RepresentationSelector` seem particularly important.
3. **Analyze the `Phase` enum:** Understand the different stages of the process described.
4. **Analyze the `RepresentationSelector` class:** This class appears to be central to the file's logic. Focus on its member variables and methods. Pay attention to methods that seem to handle different node types (like `VisitBinop`, `VisitPhi`).
5. **Infer the overall function:** Combine the insights from the above steps to formulate a concise summary of the file's role in the compilation pipeline.
6. **Identify the connection to JavaScript:** Look for terms like "Tagged", "HeapObject", "Smi", which hint at the representation of JavaScript values. Consider how the different phases might relate to optimizing JavaScript code.
7. **Construct a JavaScript example:**  If a connection is found, create a simple JavaScript snippet that demonstrates the kind of optimization the file might be involved in. Focus on the concept of type specialization.这个C++源代码文件 `v8/src/compiler/simplified-lowering.cc` 的主要功能是**将“简化（Simplified）”中间表示形式（IR）的节点转换为更底层的“机器（Machine）”表示形式的节点，并在这个过程中进行类型表示的选择和优化**。

具体来说，这个文件定义了一个 `SimplifiedLowering` 的编译阶段，它负责以下几个关键任务：

1. **表示选择（Representation Selection）:**  为图中的每个值选择最合适的机器表示形式（例如，Tagged、Word32、Float64）。这涉及到分析值的用途和类型信息，以确定高效的底层表示。
2. **降低（Lowering）简化操作:** 将高层的“简化”操作符替换为更接近硬件的“机器”操作符。例如，一个“Simplified 加法”操作可能会被降低为机器级的整数加法或浮点数加法，具体取决于操作数的表示形式。
3. **插入表示转换（Representation Change Insertion）:**  如果在某个操作需要特定表示形式的输入，但其输入节点产生的是另一种表示形式，则插入显式的转换操作（例如，从Tagged转换为Word32）。这确保了所有操作都能在其期望的表示形式上执行。
4. **固定点计算（Fixpoint Calculation）:**  由于表示选择和降低是相互依赖的，该文件使用一个迭代的固定点计算过程来同时确定每个节点的最佳输出表示和降低方式。这个过程分为 `PROPAGATE`，`RETYPE` 和 `LOWER` 三个阶段。

**与 JavaScript 的关系：**

这个过程与 JavaScript 的动态类型特性密切相关。JavaScript 变量可以存储不同类型的值，因此在编译时需要进行类型推断和表示选择。`SimplifiedLowering` 阶段尝试利用类型信息（例如，通过类型反馈收集到的信息）来优化 JavaScript 代码的执行效率。

**JavaScript 示例：**

考虑以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10); // 第一次调用，假设触发了类型反馈，得知 a 和 b 都是小整数
```

在 V8 的编译过程中，当第一次调用 `add(5, 10)` 时，`SimplifiedLowering` 可能会进行如下的优化：

1. **类型推断:** 通过类型反馈得知 `a` 和 `b` 很可能是小整数（Smi）。
2. **表示选择:**  为 `a` 和 `b` 选择 `TaggedSigned` 表示（因为 Smi 是直接编码在指针中的）。
3. **操作降低:** 将 “+” 操作降低为机器级的整数加法指令，因为已知操作数是整数。

如果后续调用 `add` 使用了不同的类型，例如：

```javascript
add(3.14, 2.71); // 第二次调用，类型反馈得知 a 和 b 是浮点数
```

`SimplifiedLowering` 可能会进行不同的优化：

1. **类型推断:** 通过类型反馈得知 `a` 和 `b` 是浮点数。
2. **表示选择:** 为 `a` 和 `b` 选择 `Float64` 表示。
3. **操作降低:** 将 “+” 操作降低为机器级的浮点数加法指令。

**总结:**

`v8/src/compiler/simplified-lowering.cc` 文件是 Turbofan 编译器中一个至关重要的组件，它通过选择合适的机器表示形式和降低高层操作，来优化 JavaScript 代码的执行效率。它利用类型信息（包括动态类型反馈）来生成更高效的机器码，从而提升 JavaScript 的性能。

### 提示词
```
这是目录为v8/src/compiler/simplified-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/simplified-lowering.h"

#include <limits>
#include <optional>

#include "include/v8-fast-api-calls.h"
#include "src/base/small-vector.h"
#include "src/codegen/callable.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/tick-counter.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/diamond.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/linkage.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-observer.h"
#include "src/compiler/node-origin-table.h"
#include "src/compiler/operation-typer.h"
#include "src/compiler/operator-properties.h"
#include "src/compiler/representation-change.h"
#include "src/compiler/simplified-lowering-verifier.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/turbofan-graph-visualizer.h"
#include "src/compiler/type-cache.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/objects.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/value-type.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

// Macro for outputting trace information from representation inference.
#define TRACE(...)                                          \
  do {                                                      \
    if (v8_flags.trace_representation) PrintF(__VA_ARGS__); \
  } while (false)

const char* kSimplifiedLoweringReducerName = "SimplifiedLowering";

// Representation selection and lowering of {Simplified} operators to machine
// operators are interwined. We use a fixpoint calculation to compute both the
// output representation and the best possible lowering for {Simplified} nodes.
// Representation change insertion ensures that all values are in the correct
// machine representation after this phase, as dictated by the machine
// operators themselves.
enum Phase {
  // 1.) PROPAGATE: Traverse the graph from the end, pushing usage information
  //     backwards from uses to definitions, around cycles in phis, according
  //     to local rules for each operator.
  //     During this phase, the usage information for a node determines the best
  //     possible lowering for each operator so far, and that in turn determines
  //     the output representation.
  //     Therefore, to be correct, this phase must iterate to a fixpoint before
  //     the next phase can begin.
  PROPAGATE,

  // 2.) RETYPE: Propagate types from type feedback forwards.
  RETYPE,

  // 3.) LOWER: perform lowering for all {Simplified} nodes by replacing some
  //     operators for some nodes, expanding some nodes to multiple nodes, or
  //     removing some (redundant) nodes.
  //     During this phase, use the {RepresentationChanger} to insert
  //     representation changes between uses that demand a particular
  //     representation and nodes that produce a different representation.
  LOWER
};

namespace {

MachineRepresentation MachineRepresentationFromArrayType(
    ExternalArrayType array_type) {
  switch (array_type) {
    case kExternalUint8Array:
    case kExternalUint8ClampedArray:
    case kExternalInt8Array:
      return MachineRepresentation::kWord8;
    case kExternalUint16Array:
    case kExternalInt16Array:
      return MachineRepresentation::kWord16;
    case kExternalUint32Array:
    case kExternalInt32Array:
      return MachineRepresentation::kWord32;
    case kExternalFloat32Array:
      return MachineRepresentation::kFloat32;
    case kExternalFloat64Array:
      return MachineRepresentation::kFloat64;
    case kExternalBigInt64Array:
    case kExternalBigUint64Array:
      return MachineRepresentation::kWord64;
    case kExternalFloat16Array:
      UNIMPLEMENTED();
  }
  UNREACHABLE();
}

UseInfo CheckedUseInfoAsWord32FromHint(
    NumberOperationHint hint, IdentifyZeros identify_zeros = kDistinguishZeros,
    const FeedbackSource& feedback = FeedbackSource()) {
  switch (hint) {
    case NumberOperationHint::kSignedSmall:
    case NumberOperationHint::kSignedSmallInputs:
      return UseInfo::CheckedSignedSmallAsWord32(identify_zeros, feedback);
    case NumberOperationHint::kNumber:
      DCHECK_EQ(identify_zeros, kIdentifyZeros);
      return UseInfo::CheckedNumberAsWord32(feedback);
    case NumberOperationHint::kNumberOrBoolean:
      // Not used currently.
      UNREACHABLE();
    case NumberOperationHint::kNumberOrOddball:
      DCHECK_EQ(identify_zeros, kIdentifyZeros);
      return UseInfo::CheckedNumberOrOddballAsWord32(feedback);
  }
  UNREACHABLE();
}

UseInfo CheckedUseInfoAsFloat64FromHint(
    NumberOperationHint hint, const FeedbackSource& feedback,
    IdentifyZeros identify_zeros = kDistinguishZeros) {
  switch (hint) {
    case NumberOperationHint::kSignedSmall:
    case NumberOperationHint::kSignedSmallInputs:
      // Not used currently.
      UNREACHABLE();
    case NumberOperationHint::kNumber:
      return UseInfo::CheckedNumberAsFloat64(identify_zeros, feedback);
    case NumberOperationHint::kNumberOrBoolean:
      return UseInfo::CheckedNumberOrBooleanAsFloat64(identify_zeros, feedback);
    case NumberOperationHint::kNumberOrOddball:
      return UseInfo::CheckedNumberOrOddballAsFloat64(identify_zeros, feedback);
  }
  UNREACHABLE();
}

UseInfo TruncatingUseInfoFromRepresentation(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kTaggedSigned:
      return UseInfo::TaggedSigned();
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
    case MachineRepresentation::kIndirectPointer:
    case MachineRepresentation::kMapWord:
      return UseInfo::AnyTagged();
    case MachineRepresentation::kFloat64:
      return UseInfo::TruncatingFloat64();
    case MachineRepresentation::kFloat16:
    case MachineRepresentation::kFloat32:
      return UseInfo::Float32();
    case MachineRepresentation::kWord8:
    case MachineRepresentation::kWord16:
    case MachineRepresentation::kWord32:
      return UseInfo::TruncatingWord32();
    case MachineRepresentation::kWord64:
      return UseInfo::TruncatingWord64();
    case MachineRepresentation::kBit:
      return UseInfo::Bool();
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
    case MachineRepresentation::kProtectedPointer:
    case MachineRepresentation::kSandboxedPointer:
    case MachineRepresentation::kSimd128:
    case MachineRepresentation::kSimd256:
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }
}

UseInfo UseInfoForBasePointer(const FieldAccess& access) {
  return access.tag() != 0 ? UseInfo::AnyTagged() : UseInfo::Word();
}

UseInfo UseInfoForBasePointer(const ElementAccess& access) {
  return access.tag() != 0 ? UseInfo::AnyTagged() : UseInfo::Word();
}

void ReplaceEffectControlUses(Node* node, Node* effect, Node* control) {
  for (Edge edge : node->use_edges()) {
    if (NodeProperties::IsControlEdge(edge)) {
      edge.UpdateTo(control);
    } else if (NodeProperties::IsEffectEdge(edge)) {
      edge.UpdateTo(effect);
    } else {
      DCHECK(NodeProperties::IsValueEdge(edge) ||
             NodeProperties::IsContextEdge(edge));
    }
  }
}

bool CanOverflowSigned32(const Operator* op, Type left, Type right,
                         TypeCache const* type_cache, Zone* type_zone) {
  // We assume the inputs are checked Signed32 (or known statically to be
  // Signed32). Technically, the inputs could also be minus zero, which we treat
  // as 0 for the purpose of this function.
  if (left.Maybe(Type::MinusZero())) {
    left = Type::Union(left, type_cache->kSingletonZero, type_zone);
  }
  if (right.Maybe(Type::MinusZero())) {
    right = Type::Union(right, type_cache->kSingletonZero, type_zone);
  }
  left = Type::Intersect(left, Type::Signed32(), type_zone);
  right = Type::Intersect(right, Type::Signed32(), type_zone);
  if (left.IsNone() || right.IsNone()) return false;
  switch (op->opcode()) {
    case IrOpcode::kSpeculativeSafeIntegerAdd:
      return (left.Max() + right.Max() > kMaxInt) ||
             (left.Min() + right.Min() < kMinInt);

    case IrOpcode::kSpeculativeSafeIntegerSubtract:
      return (left.Max() - right.Min() > kMaxInt) ||
             (left.Min() - right.Max() < kMinInt);

    default:
      UNREACHABLE();
  }
}

bool IsSomePositiveOrderedNumber(Type type) {
  return type.Is(Type::OrderedNumber()) && (type.IsNone() || type.Min() > 0);
}

inline bool IsLargeBigInt(Type type) {
  return type.Is(Type::BigInt()) && !type.Is(Type::SignedBigInt64()) &&
         !type.Is(Type::UnsignedBigInt64());
}

class JSONGraphWriterWithVerifierTypes : public JSONGraphWriter {
 public:
  JSONGraphWriterWithVerifierTypes(std::ostream& os, const Graph* graph,
                                   const SourcePositionTable* positions,
                                   const NodeOriginTable* origins,
                                   SimplifiedLoweringVerifier* verifier)
      : JSONGraphWriter(os, graph, positions, origins), verifier_(verifier) {}

 protected:
  std::optional<Type> GetType(Node* node) override {
    return verifier_->GetType(node);
  }

 private:
  SimplifiedLoweringVerifier* verifier_;
};

}  // namespace

#ifdef DEBUG
// Helpers for monotonicity checking.
class InputUseInfos {
 public:
  explicit InputUseInfos(Zone* zone) : input_use_infos_(zone) {}

  void SetAndCheckInput(Node* node, int index, UseInfo use_info) {
    if (input_use_infos_.empty()) {
      input_use_infos_.resize(node->InputCount(), UseInfo::None());
    }
    // Check that the new use informatin is a super-type of the old
    // one.
    DCHECK(IsUseLessGeneral(input_use_infos_[index], use_info));
    input_use_infos_[index] = use_info;
  }

 private:
  ZoneVector<UseInfo> input_use_infos_;

  static bool IsUseLessGeneral(UseInfo use1, UseInfo use2) {
    return use1.truncation().IsLessGeneralThan(use2.truncation());
  }
};

#endif  // DEBUG

class RepresentationSelector {
  // The purpose of this nested class is to hide method
  // v8::internal::compiler::NodeProperties::ChangeOp which should not be
  // directly used by code in RepresentationSelector and SimplifiedLowering.
  // RepresentationSelector code should call RepresentationSelector::ChangeOp in
  // place of NodeProperties::ChangeOp, in order to notify the changes to a
  // registered ObserveNodeManager and support the %ObserveNode intrinsic.
  class NodeProperties : public compiler::NodeProperties {
    static void ChangeOp(Node* node, const Operator* new_op) { UNREACHABLE(); }
  };

 public:
  // Information for each node tracked during the fixpoint.
  class NodeInfo final {
   public:
    // Adds new use to the node. Returns true if something has changed
    // and the node has to be requeued.
    bool AddUse(UseInfo info) {
      Truncation old_truncation = truncation_;
      truncation_ = Truncation::Generalize(truncation_, info.truncation());
      return truncation_ != old_truncation;
    }

    void set_queued() { state_ = kQueued; }
    void set_visited() { state_ = kVisited; }
    void set_pushed() { state_ = kPushed; }
    void reset_state() { state_ = kUnvisited; }
    bool visited() const { return state_ == kVisited; }
    bool queued() const { return state_ == kQueued; }
    bool pushed() const { return state_ == kPushed; }
    bool unvisited() const { return state_ == kUnvisited; }
    Truncation truncation() const { return truncation_; }
    void set_output(MachineRepresentation output) { representation_ = output; }

    MachineRepresentation representation() const { return representation_; }

    // Helpers for feedback typing.
    void set_feedback_type(Type type) { feedback_type_ = type; }
    Type feedback_type() const { return feedback_type_; }
    void set_weakened() { weakened_ = true; }
    bool weakened() const { return weakened_; }
    void set_restriction_type(Type type) { restriction_type_ = type; }
    Type restriction_type() const { return restriction_type_; }

   private:
    // Fields are ordered to avoid mixing byte and word size fields to minimize
    // padding.
    enum State : uint8_t { kUnvisited, kPushed, kVisited, kQueued };
    State state_ = kUnvisited;
    MachineRepresentation representation_ =
        MachineRepresentation::kNone;             // Output representation.
    Truncation truncation_ = Truncation::None();  // Information about uses.
    bool weakened_ = false;

    Type restriction_type_ = Type::Any();
    Type feedback_type_;
  };

  RepresentationSelector(JSGraph* jsgraph, JSHeapBroker* broker, Zone* zone,
                         RepresentationChanger* changer,
                         SourcePositionTable* source_positions,
                         NodeOriginTable* node_origins,
                         TickCounter* tick_counter, Linkage* linkage,
                         ObserveNodeManager* observe_node_manager,
                         SimplifiedLoweringVerifier* verifier)
      : jsgraph_(jsgraph),
        broker_(broker),
        zone_(zone),
        might_need_revisit_(zone),
        count_(jsgraph->graph()->NodeCount()),
        info_(count_, zone),
#ifdef DEBUG
        node_input_use_infos_(count_, InputUseInfos(zone), zone),
#endif
        replacements_(zone),
        changer_(changer),
        revisit_queue_(zone),
        traversal_nodes_(zone),
        source_positions_(source_positions),
        node_origins_(node_origins),
        type_cache_(TypeCache::Get()),
        op_typer_(broker, graph_zone()),
        tick_counter_(tick_counter),
        linkage_(linkage),
        observe_node_manager_(observe_node_manager),
        verifier_(verifier) {
    singleton_true_ =
        Type::Constant(broker, broker->true_value(), graph_zone());
    singleton_false_ =
        Type::Constant(broker, broker->false_value(), graph_zone());
  }

  bool verification_enabled() const { return verifier_ != nullptr; }

  void ResetNodeInfoState() {
    // Clean up for the next phase.
    for (NodeInfo& info : info_) {
      info.reset_state();
    }
  }

  Type TypeOf(Node* node) {
    Type type = GetInfo(node)->feedback_type();
    return type.IsInvalid() ? NodeProperties::GetType(node) : type;
  }

  Type FeedbackTypeOf(Node* node) {
    Type type = GetInfo(node)->feedback_type();
    return type.IsInvalid() ? Type::None() : type;
  }

  Type TypePhi(Node* node) {
    int arity = node->op()->ValueInputCount();
    Type type = FeedbackTypeOf(node->InputAt(0));
    for (int i = 1; i < arity; ++i) {
      type = op_typer_.Merge(type, FeedbackTypeOf(node->InputAt(i)));
    }
    return type;
  }

  Type TypeSelect(Node* node) {
    return op_typer_.Merge(FeedbackTypeOf(node->InputAt(1)),
                           FeedbackTypeOf(node->InputAt(2)));
  }

  bool UpdateFeedbackType(Node* node) {
    if (node->op()->ValueOutputCount() == 0) return false;
    if ((IrOpcode::IsMachineOpcode(node->opcode()) ||
         IrOpcode::IsMachineConstantOpcode(node->opcode())) &&
        node->opcode() != IrOpcode::kLoadFramePointer) {
      DCHECK(NodeProperties::GetType(node).Is(Type::Machine()));
    }

    // For any non-phi node just wait until we get all inputs typed. We only
    // allow untyped inputs for phi nodes because phis are the only places
    // where cycles need to be broken.
    if (node->opcode() != IrOpcode::kPhi) {
      for (int i = 0; i < node->op()->ValueInputCount(); i++) {
        if (GetInfo(node->InputAt(i))->feedback_type().IsInvalid()) {
          return false;
        }
      }
    }

    NodeInfo* info = GetInfo(node);
    Type type = info->feedback_type();
    Type new_type = NodeProperties::GetType(node);

    // We preload these values here to avoid increasing the binary size too
    // much, which happens if we inline the calls into the macros below.
    Type input0_type;
    if (node->InputCount() > 0) input0_type = FeedbackTypeOf(node->InputAt(0));
    Type input1_type;
    if (node->InputCount() > 1) input1_type = FeedbackTypeOf(node->InputAt(1));

    switch (node->opcode()) {
#define DECLARE_CASE(Name)                               \
  case IrOpcode::k##Name: {                              \
    new_type = op_typer_.Name(input0_type, input1_type); \
    break;                                               \
  }
      SIMPLIFIED_NUMBER_BINOP_LIST(DECLARE_CASE)
      DECLARE_CASE(SameValue)
#undef DECLARE_CASE

#define DECLARE_CASE(Name)                                               \
  case IrOpcode::k##Name: {                                              \
    new_type = Type::Intersect(op_typer_.Name(input0_type, input1_type), \
                               info->restriction_type(), graph_zone());  \
    break;                                                               \
  }
      SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(DECLARE_CASE)
      SIMPLIFIED_SPECULATIVE_BIGINT_BINOP_LIST(DECLARE_CASE)
#undef DECLARE_CASE

#define DECLARE_CASE(Name)                  \
  case IrOpcode::k##Name: {                 \
    new_type = op_typer_.Name(input0_type); \
    break;                                  \
  }
      SIMPLIFIED_NUMBER_UNOP_LIST(DECLARE_CASE)
#undef DECLARE_CASE

#define DECLARE_CASE(Name)                                              \
  case IrOpcode::k##Name: {                                             \
    new_type = Type::Intersect(op_typer_.Name(input0_type),             \
                               info->restriction_type(), graph_zone()); \
    break;                                                              \
  }
      SIMPLIFIED_SPECULATIVE_NUMBER_UNOP_LIST(DECLARE_CASE)
#undef DECLARE_CASE

      case IrOpcode::kConvertReceiver:
        new_type = op_typer_.ConvertReceiver(input0_type);
        break;

      case IrOpcode::kPlainPrimitiveToNumber:
        new_type = op_typer_.ToNumber(input0_type);
        break;

      case IrOpcode::kCheckBounds:
        new_type =
            Type::Intersect(op_typer_.CheckBounds(input0_type, input1_type),
                            info->restriction_type(), graph_zone());
        break;

      case IrOpcode::kCheckFloat64Hole:
        new_type = Type::Intersect(op_typer_.CheckFloat64Hole(input0_type),
                                   info->restriction_type(), graph_zone());
        break;

      case IrOpcode::kCheckNumber:
        new_type = Type::Intersect(op_typer_.CheckNumber(input0_type),
                                   info->restriction_type(), graph_zone());
        break;

      case IrOpcode::kPhi: {
        new_type = TypePhi(node);
        if (!type.IsInvalid()) {
          new_type = Weaken(node, type, new_type);
        }
        break;
      }

      case IrOpcode::kConvertTaggedHoleToUndefined:
        new_type = op_typer_.ConvertTaggedHoleToUndefined(
            FeedbackTypeOf(node->InputAt(0)));
        break;

      case IrOpcode::kTypeGuard: {
        new_type = op_typer_.TypeTypeGuard(node->op(),
                                           FeedbackTypeOf(node->InputAt(0)));
        break;
      }

      case IrOpcode::kSelect: {
        new_type = TypeSelect(node);
        break;
      }

      default:
        // Shortcut for operations that we do not handle.
        if (type.IsInvalid()) {
          GetInfo(node)->set_feedback_type(NodeProperties::GetType(node));
          return true;
        }
        return false;
    }
    // We need to guarantee that the feedback type is a subtype of the upper
    // bound. Naively that should hold, but weakening can actually produce
    // a bigger type if we are unlucky with ordering of phi typing. To be
    // really sure, just intersect the upper bound with the feedback type.
    new_type = Type::Intersect(GetUpperBound(node), new_type, graph_zone());

    if (!type.IsInvalid() && new_type.Is(type)) return false;
    GetInfo(node)->set_feedback_type(new_type);
    if (v8_flags.trace_representation) {
      PrintNodeFeedbackType(node);
    }
    return true;
  }

  void PrintNodeFeedbackType(Node* n) {
    StdoutStream os;
    os << "#" << n->id() << ":" << *n->op() << "(";
    int j = 0;
    for (Node* const i : n->inputs()) {
      if (j++ > 0) os << ", ";
      os << "#" << i->id() << ":" << i->op()->mnemonic();
    }
    os << ")";
    if (NodeProperties::IsTyped(n)) {
      Type static_type = NodeProperties::GetType(n);
      os << "  [Static type: " << static_type;
      Type feedback_type = GetInfo(n)->feedback_type();
      if (!feedback_type.IsInvalid() && feedback_type != static_type) {
        os << ", Feedback type: " << feedback_type;
      }
      os << "]";
    }
    os << std::endl;
  }

  Type Weaken(Node* node, Type previous_type, Type current_type) {
    // If the types have nothing to do with integers, return the types.
    Type const integer = type_cache_->kInteger;
    if (!previous_type.Maybe(integer)) {
      return current_type;
    }
    DCHECK(current_type.Maybe(integer));

    Type current_integer = Type::Intersect(current_type, integer, graph_zone());
    DCHECK(!current_integer.IsNone());
    Type previous_integer =
        Type::Intersect(previous_type, integer, graph_zone());
    DCHECK(!previous_integer.IsNone());

    // Once we start weakening a node, we should always weaken.
    if (!GetInfo(node)->weakened()) {
      // Only weaken if there is range involved; we should converge quickly
      // for all other types (the exception is a union of many constants,
      // but we currently do not increase the number of constants in unions).
      Type previous = previous_integer.GetRange();
      Type current = current_integer.GetRange();
      if (current.IsInvalid() || previous.IsInvalid()) {
        return current_type;
      }
      // Range is involved => we are weakening.
      GetInfo(node)->set_weakened();
    }

    return Type::Union(current_type,
                       op_typer_.WeakenRange(previous_integer, current_integer),
                       graph_zone());
  }

  // Generates a pre-order traversal of the nodes, starting with End.
  void GenerateTraversal() {
    // Reset previous state.
    ResetNodeInfoState();
    traversal_nodes_.clear();
    count_ = graph()->NodeCount();
    info_.resize(count_);

    ZoneStack<NodeState> stack(zone_);

    stack.push({graph()->end(), 0});
    GetInfo(graph()->end())->set_pushed();
    while (!stack.empty()) {
      NodeState& current = stack.top();
      Node* node = current.node;
      // If there is an unvisited input, push it and continue with that node.
      bool pushed_unvisited = false;
      while (current.input_index < node->InputCount()) {
        Node* input = node->InputAt(current.input_index);
        NodeInfo* input_info = GetInfo(input);
        current.input_index++;
        if (input_info->unvisited()) {
          input_info->set_pushed();
          stack.push({input, 0});
          pushed_unvisited = true;
          break;
        } else if (input_info->pushed()) {
          // Optimization for the Retype phase.
          // If we had already pushed (and not visited) an input, it means that
          // the current node will be visited in the Retype phase before one of
          // its inputs. If this happens, the current node might need to be
          // revisited.
          MarkAsPossibleRevisit(node, input);
        }
      }

      if (pushed_unvisited) continue;

      stack.pop();
      NodeInfo* info = GetInfo(node);
      info->set_visited();

      // Generate the traversal
      traversal_nodes_.push_back(node);
    }
  }

  void PushNodeToRevisitIfVisited(Node* node) {
    NodeInfo* info = GetInfo(node);
    if (info->visited()) {
      TRACE(" QUEUEING #%d: %s\n", node->id(), node->op()->mnemonic());
      info->set_queued();
      revisit_queue_.push(node);
    }
  }

  // Tries to update the feedback type of the node, as well as setting its
  // machine representation (in VisitNode). Returns true iff updating the
  // feedback type is successful.
  bool RetypeNode(Node* node) {
    NodeInfo* info = GetInfo(node);
    info->set_visited();
    bool updated = UpdateFeedbackType(node);
    TRACE(" visit #%d: %s\n", node->id(), node->op()->mnemonic());
    VisitNode<RETYPE>(node, info->truncation(), nullptr);
    TRACE("  ==> output %s\n", MachineReprToString(info->representation()));
    return updated;
  }

  // Visits the node and marks it as visited. Inside of VisitNode, we might
  // change the truncation of one of our inputs (see EnqueueInput<PROPAGATE> for
  // this). If we change the truncation of an already visited node, we will add
  // it to the revisit queue.
  void PropagateTruncation(Node* node) {
    NodeInfo* info = GetInfo(node);
    info->set_visited();
    TRACE(" visit #%d: %s (trunc: %s)\n", node->id(), node->op()->mnemonic(),
          info->truncation().description());
    VisitNode<PROPAGATE>(node, info->truncation(), nullptr);
  }

  // Backward propagation of truncations to a fixpoint.
  void RunPropagatePhase() {
    TRACE("--{Propagate phase}--\n");
    ResetNodeInfoState();
    DCHECK(revisit_queue_.empty());

    // Process nodes in reverse post order, with End as the root.
    for (auto it = traversal_nodes_.crbegin(); it != traversal_nodes_.crend();
         ++it) {
      PropagateTruncation(*it);

      while (!revisit_queue_.empty()) {
        Node* node = revisit_queue_.front();
        revisit_queue_.pop();
        PropagateTruncation(node);
      }
    }
  }

  // Forward propagation of types from type feedback to a fixpoint.
  void RunRetypePhase() {
    TRACE("--{Retype phase}--\n");
    ResetNodeInfoState();
    DCHECK(revisit_queue_.empty());

    for (auto it = traversal_nodes_.cbegin(); it != traversal_nodes_.cend();
         ++it) {
      Node* node = *it;
      if (!RetypeNode(node)) continue;

      auto revisit_it = might_need_revisit_.find(node);
      if (revisit_it == might_need_revisit_.end()) continue;

      for (Node* const user : revisit_it->second) {
        PushNodeToRevisitIfVisited(user);
      }

      // Process the revisit queue.
      while (!revisit_queue_.empty()) {
        Node* revisit_node = revisit_queue_.front();
        revisit_queue_.pop();
        if (!RetypeNode(revisit_node)) continue;
        // Here we need to check all uses since we can't easily know which
        // nodes will need to be revisited due to having an input which was
        // a revisited node.
        for (Node* const user : revisit_node->uses()) {
          PushNodeToRevisitIfVisited(user);
        }
      }
    }
  }

  // Lowering and change insertion phase.
  void RunLowerPhase(SimplifiedLowering* lowering) {
    TRACE("--{Lower phase}--\n");
    for (auto it = traversal_nodes_.cbegin(); it != traversal_nodes_.cend();
         ++it) {
      Node* node = *it;
      NodeInfo* info = GetInfo(node);
      TRACE(" visit #%d: %s\n", node->id(), node->op()->mnemonic());
      // Reuse {VisitNode()} so the representation rules are in one place.
      SourcePositionTable::Scope scope(
          source_positions_, source_positions_->GetSourcePosition(node));
      NodeOriginTable::Scope origin_scope(node_origins_, "simplified lowering",
                                          node);
      VisitNode<LOWER>(node, info->truncation(), lowering);
    }

    // Perform the final replacements.
    for (NodeVector::iterator i = replacements_.begin();
         i != replacements_.end(); ++i) {
      Node* node = *i;
      Node* replacement = *(++i);
      node->ReplaceUses(replacement);
      node->Kill();
      // We also need to replace the node in the rest of the vector.
      for (NodeVector::iterator j = i + 1; j != replacements_.end(); ++j) {
        ++j;
        if (*j == node) *j = replacement;
      }
    }
  }

  void RunVerifyPhase(OptimizedCompilationInfo* info) {
    DCHECK_NOT_NULL(verifier_);

    TRACE("--{Verify Phase}--\n");

    // Patch pending type overrides.
    for (const auto& [constant, uses] :
         verifier_->machine_uses_of_constants()) {
      Node* typed_constant =
          InsertTypeOverrideForVerifier(Type::Machine(), constant);
      for (auto use : uses) {
        for (int i = 0; i < use->InputCount(); ++i) {
          if (use->InputAt(i) == constant) {
            use->ReplaceInput(i, typed_constant);
          }
        }
      }
    }

    // Generate a new traversal containing all the new nodes created during
    // lowering.
    GenerateTraversal();

    // Set node types to the refined types computed during retyping.
    for (Node* node : traversal_nodes_) {
      NodeInfo* info = GetInfo(node);
      if (!info->feedback_type().IsInvalid()) {
        NodeProperties::SetType(node, info->feedback_type());
      }
    }

    // Print graph.
    if (info != nullptr && info->trace_turbo_json()) {
      UnparkedScopeIfNeeded scope(broker_);
      AllowHandleDereference allow_deref;

      TurboJsonFile json_of(info, std::ios_base::app);
      JSONGraphWriter writer(json_of, graph(), source_positions_,
                             node_origins_);
      writer.PrintPhase("V8.TFSimplifiedLowering [after lower]");
    }

    // Verify all nodes.
    for (Node* node : traversal_nodes_) {
      verifier_->VisitNode(node, op_typer_);
    }

    // Print graph.
    if (info != nullptr && info->trace_turbo_json()) {
      UnparkedScopeIfNeeded scope(broker_);
      AllowHandleDereference allow_deref;

      TurboJsonFile json_of(info, std::ios_base::app);
      JSONGraphWriterWithVerifierTypes writer(
          json_of, graph(), source_positions_, node_origins_, verifier_);
      writer.PrintPhase("V8.TFSimplifiedLowering [after verify]");
    }

    // Eliminate all introduced hints.
    for (Node* node : verifier_->inserted_hints()) {
      Node* input = node->InputAt(0);
      node->ReplaceUses(input);
      node->Kill();
    }
  }

  void Run(SimplifiedLowering* lowering) {
    GenerateTraversal();
    RunPropagatePhase();
    RunRetypePhase();
    RunLowerPhase(lowering);
    if (verification_enabled()) {
      RunVerifyPhase(lowering->info_);
    }
  }

  // Just assert for Retype and Lower. Propagate specialized below.
  template <Phase T>
  void EnqueueInput(Node* use_node, int index,
                    UseInfo use_info = UseInfo::None()) {
    static_assert(retype<T>() || lower<T>(),
                  "This version of EnqueueInput has to be called in "
                  "the Retype or Lower phase.");
  }

  template <Phase T>
  static constexpr bool propagate() {
    return T == PROPAGATE;
  }

  template <Phase T>
  static constexpr bool retype() {
    return T == RETYPE;
  }

  template <Phase T>
  static constexpr bool lower() {
    return T == LOWER;
  }

  template <Phase T>
  void SetOutput(Node* node, MachineRepresentation representation,
                 Type restriction_type = Type::Any());

  Type GetUpperBound(Node* node) { return NodeProperties::GetType(node); }

  bool InputCannotBe(Node* node, Type type) {
    DCHECK_EQ(1, node->op()->ValueInputCount());
    return !GetUpperBound(node->InputAt(0)).Maybe(type);
  }

  bool InputIs(Node* node, Type type) {
    DCHECK_EQ(1, node->op()->ValueInputCount());
    return GetUpperBound(node->InputAt(0)).Is(type);
  }

  bool BothInputsAreSigned32(Node* node) {
    return BothInputsAre(node, Type::Signed32());
  }

  bool BothInputsAreUnsigned32(Node* node) {
    return BothInputsAre(node, Type::Unsigned32());
  }

  bool BothInputsAre(Node* node, Type type) {
    DCHECK_EQ(2, node->op()->ValueInputCount());
    return GetUpperBound(node->InputAt(0)).Is(type) &&
           GetUpperBound(node->InputAt(1)).Is(type);
  }

  bool IsNodeRepresentationTagged(Node* node) {
    MachineRepresentation representation = GetInfo(node)->representation();
    return IsAnyTagged(representation);
  }

  bool OneInputCannotBe(Node* node, Type type) {
    DCHECK_EQ(2, node->op()->ValueInputCount());
    return !GetUpperBound(node->InputAt(0)).Maybe(type) ||
           !GetUpperBound(node->InputAt(1)).Maybe(type);
  }

  void ChangeToDeadValue(Node* node, Node* effect, Node* control) {
    DCHECK(TypeOf(node).IsNone());
    // If the node is unreachable, insert an Unreachable node and mark the
    // value dead.
    // TODO(jarin,turbofan) Find a way to unify/merge this insertion with
    // InsertUnreachableIfNecessary.
    Node* unreachable = effect =
        graph()->NewNode(common()->Unreachable(), effect, control);
    const Operator* dead_value =
        common()->DeadValue(GetInfo(node)->representation());
    node->ReplaceInput(0, unreachable);
    node->TrimInputCount(dead_value->ValueInputCount());
    ReplaceEffectControlUses(node, effect, control);
    ChangeOp(node, dead_value);
  }

  // This function is a generalization of ChangeToPureOp. It can be used to
  // replace a node that is part of the effect and control chain by a pure node.
  void ReplaceWithPureNode(Node* node, Node* pure_node) {
    DCHECK(pure_node->op()->HasProperty(Operator::kPure));
    if (node->op()->EffectInputCount() > 0) {
      DCHECK_LT(0, node->op()->ControlInputCount());
      Node* control = NodeProperties::GetControlInput(node);
      Node* effect = NodeProperties::GetEffectInput(node);
      if (TypeOf(node).IsNone()) {
        ChangeToDeadValue(node, effect, control);
        return;
      }
      // Rewire the effect and control chains.
      ReplaceEffectControlUses(node, effect, control);
    } else {
      DCHECK_EQ(0, node->op()->ControlInputCount());
    }
    DeferReplacement(node, pure_node);
  }

  void ChangeToPureOp(Node* node, const Operator* new_op) {
    DCHECK(new_op->HasProperty(Operator::kPure));
    DCHECK_EQ(new_op->ValueInputCount(), node->op()->ValueInputCount());
    if (node->op()->EffectInputCount() > 0) {
      DCHECK_LT(0, node->op()->ControlInputCount());
      Node* control = NodeProperties::GetControlInput(node);
      Node* effect = NodeProperties::GetEffectInput(node);
      if (TypeOf(node).IsNone()) {
        ChangeToDeadValue(node, effect, control);
        return;
      }
      // Rewire the effect and control chains.
      node->TrimInputCount(new_op->ValueInputCount());
      ReplaceEffectControlUses(node, effect, control);
    } else {
      DCHECK_EQ(0, node->op()->ControlInputCount());
    }
    ChangeOp(node, new_op);
  }

  void ChangeUnaryToPureBinaryOp(Node* node, const Operator* new_op,
                                 int new_input_index, Node* new_input) {
    DCHECK(new_op->HasProperty(Operator::kPure));
    DCHECK_EQ(new_op->ValueInputCount(), 2);
    DCHECK_EQ(node->op()->ValueInputCount(), 1);
    DCHECK_LE(0, new_input_index);
    DCHECK_LE(new_input_index, 1);
    if (node->op()->EffectInputCount() > 0) {
      DCHECK_LT(0, node->op()->ControlInputCount());
      Node* control = NodeProperties::GetControlInput(node);
      Node* effect = NodeProperties::GetEffectInput(node);
      if (TypeOf(node).IsNone()) {
        ChangeToDeadValue(node, effect, control);
        return;
      }
      node->TrimInputCount(node->op()->ValueInputCount());
      ReplaceEffectControlUses(node, effect, control);
    } else {
      DCHECK_EQ(0, node->op()->ControlInputCount());
    }
    if (new_input_index == 0) {
      node->InsertInput(jsgraph_->zone(), 0, new_input);
    } else {
      DCHECK_EQ(new_input_index, 1);
      DCHECK_EQ(node->InputCount(), 1);
      node->AppendInput(jsgraph_->zone(), new_input);
    }
    ChangeOp(node, new_op);
  }

  // Converts input {index} of {node} according to given UseInfo {use},
  // assuming the type of the input is {input_type}. If {input_type} is null,
  // it takes the input from the input node {TypeOf(node->InputAt(index))}.
  void ConvertInput(Node* node, int index, UseInfo use,
                    Type input_type = Type::Invalid()) {
    // In the change phase, insert a change before the use if necessary.
    if (use.representation() == MachineRepresentation::kNone)
      return;  // No input requirement on the use.
    Node* input = node->InputAt(index);
    DCHECK_NOT_NULL(input);
    NodeInfo* input_info = GetInfo(input);
    MachineRepresentation input_rep = input_info->representation();
    if (input_rep != use.representation() ||
        use.type_check() != TypeCheckKind::kNone) {
      // Output representation doesn't match usage.
      TRACE("  change: #%d:%s(@%d #%d:%s) ", node->id(), node->op()->mnemonic(),
            index, input->id(), input->op()->mnemonic());
      TRACE("from %s to %s:%s\n",
            MachineReprToString(input_info->representation()),
            MachineReprToString(use.representation()),
            use.truncation().description());
      if (input_type.IsInvalid()) {
        input_type = TypeOf(input);
      } else {
        // This case is reached when ConvertInput is called for TypeGuard nodes
        // which explicitly set the {input_type} for their input. In order to
        // correctly verify the resulting graph, we have to preserve this
        // forced type for the verifier.
        DCHECK_EQ(node->opcode(), IrOpcode::kTypeGuard);
        input = InsertTypeOverrideForVerifier(input_type, input);
      }
      Node* n = changer_->GetRepresentationFor(input, input_rep, input_type,
                                               node, use);
      node->ReplaceInput(index, n);
    }
  }

  template <Phase T>
  void ProcessInput(Node* node, int index, UseInfo use);

  // Just assert for Retype and Lower. Propagate specialized below.
  template <Phase T>
  void ProcessRemainingInputs(Node* node, int index) {
    static_assert(retype<T>() || lower<T>(),
                  "This version of ProcessRemainingInputs has to be called in "
                  "the Retype or Lower phase.");
    DCHECK_GE(index, NodeProperties::PastValueIndex(node));
    DCHECK_GE(index, NodeProperties::PastContextIndex(node));
  }

  // Marks node as a possible revisit since it is a use of input that will be
  // visited before input is visited.
  void MarkAsPossibleRevisit(Node* node, Node* input) {
    auto it = might_need_revisit_.find(input);
    if (it == might_need_revisit_.end()) {
      it = might_need_revisit_.insert({input, ZoneVector<Node*>(zone())}).first;
    }
    it->second.push_back(node);
    TRACE(" Marking #%d: %s as needing revisit due to #%d: %s\n", node->id(),
          node->op()->mnemonic(), input->id(), input->op()->mnemonic());
  }

  // Just assert for Retype. Propagate and Lower specialized below.
  template <Phase T>
  void VisitInputs(Node* node) {
    static_assert(
        retype<T>(),
        "This version of VisitInputs has to be called in the Retype phase.");
  }

  template <Phase T>
  void VisitReturn(Node* node) {
    int first_effect_index = NodeProperties::FirstEffectIndex(node);
    // Visit integer slot count to pop
    ProcessInput<T>(node, 0, UseInfo::TruncatingWord32());

    // Visit value, context and frame state inputs as tagged.
    for (int i = 1; i < first_effect_index; i++) {
      ProcessInput<T>(node, i, UseInfo::AnyTagged());
    }
    // Only enqueue other inputs (effects, control).
    for (int i = first_effect_index; i < node->InputCount(); i++) {
      EnqueueInput<T>(node, i);
    }
  }

  // Helper for an unused node.
  template <Phase T>
  void VisitUnused(Node* node) {
    int first_effect_index = NodeProperties::FirstEffectIndex(node);
    for (int i = 0; i < first_effect_index; i++) {
      ProcessInput<T>(node, i, UseInfo::None());
    }
    ProcessRemainingInputs<T>(node, first_effect_index);

    if (lower<T>()) {
      TRACE("disconnecting unused #%d:%s\n", node->id(),
            node->op()->mnemonic());
      DisconnectFromEffectAndControl(node);
      node->NullAllInputs();  // Node is now dead.
      DeferReplacement(node, graph()->NewNode(common()->Plug()));
    }
  }

  // Helper for no-op node.
  template <Phase T>
  void VisitNoop(Node* node, Truncation truncation) {
    if (truncation.IsUnused()) return VisitUnused<T>(node);
    MachineRepresentation representation =
        GetOutputInfoForPhi(TypeOf(node), truncation);
    VisitUnop<T>(node, UseInfo(representation, truncation), representation);
    if (lower<T>()) DeferReplacement(node, node->InputAt(0));
  }

  // Helper for binops of the R x L -> O variety.
  template <Phase T>
  void VisitBinop(Node* node, UseInfo left_use, UseInfo right_use,
                  MachineRepresentation output,
                  Type restriction_type = Type::Any()) {
    DCHECK_EQ(2, node->op()->ValueInputCount());
    ProcessInput<T>(node, 0, left_use);
    ProcessInput<T>(node, 1, right_use);
    for (int i = 2; i < node->InputCount(); i++) {
      EnqueueInput<T>(node, i);
    }
    SetOutput<T>(node, output, restriction_type);
  }

  // Helper for binops of the I x I -> O variety.
  template <Phase T>
  void VisitBinop(Node* node, UseInfo input_use, MachineRepresentation output,
                  Type restriction_type = Type::Any()) {
    VisitBinop<T>(node, input_use, input_use, output, restriction_type);
  }

  template <Phase T>
  void VisitSpeculativeInt32Binop(Node* node) {
    DCHECK_EQ(2, node->op()->ValueInputCount());
    if (BothInputsAre(node, Type::NumberOrOddball())) {
      return VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                           MachineRepresentation::kWord32);
    }
    NumberOperationHint hint = NumberOperationHintOf(node->op());
    return VisitBinop<T>(node,
                         CheckedUseInfoAsWord32FromHint(hint, kIdentifyZeros),
                         MachineRepresentation::kWord32);
  }

  // Helper for unops of the I -> O variety.
  template <Phase T>
  void VisitUnop(Node* node, UseInfo input_use, MachineRepresentation output,
                 Type restriction_type = Type::Any()) {
    DCHECK_EQ(1, node->op()->ValueInputCount());
    ProcessInput<T>(node, 0, input_use);
    ProcessRemainingInputs<T>(node, 1);
    SetOutput<T>(node, output, restriction_type);
  }

  // Helper for leaf nodes.
  template <Phase T>
  void VisitLeaf(Node* node, MachineRepresentation output) {
    DCHECK_EQ(0, node->InputCount());
    SetOutput<T>(node, output);
  }

  // Helpers for specific types of binops.

  template <Phase T>
  void VisitFloat64Binop(Node* node) {
    VisitBinop<T>(node, UseInfo::TruncatingFloat64(),
                  MachineRepresentation::kFloat64);
  }

  template <Phase T>
  void VisitInt64Binop(Node* node) {
    VisitBinop<T>(node, UseInfo::Word64(), MachineRepresentation::kWord64);
  }

  template <Phase T>
  void VisitWord32TruncatingBinop(Node* node) {
    VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                  MachineRepresentation::kWord32);
  }

  // Infer representation for phi-like nodes.
  MachineRepresentation GetOutputInfoForPhi(Type type, Truncation use) {
    // Compute the representation.
    if (type.Is(Type::None())) {
      return MachineRepresentation::kNone;
    } else if (type.Is(Type::Signed32()) || type.Is(Type::Unsigned32())) {
      return MachineRepresentation::kWord32;
    } else if (type.Is(Type::NumberOrOddball()) && use.IsUsedAsWord32()) {
      return MachineRepresentation::kWord32;
    } else if (type.Is(Type::Boolean())) {
      return MachineRepresentation::kBit;
    } else if (type.Is(Type::NumberOrOddball()) &&
               use.TruncatesOddballAndBigIntToNumber()) {
      return MachineRepresentation::kFloat64;
    } else if (type.Is(Type::Union(Type::SignedSmall(), Type::NaN(), zone()))) {
      // TODO(turbofan): For Phis that return either NaN or some Smi, it's
      // beneficial to not go all the way to double, unless the uses are
      // double uses. For tagging that just means some potentially expensive
      // allocation code; we might want to do the same for -0 as well?
      return MachineRepresentation::kTagged;
    } else if (type.Is(Type::Number())) {
      return MachineRepresentation::kFloat64;
    } else if (type.Is(Type::BigInt()) && Is64() && use.IsUsedAsWord64()) {
      return MachineRepresentation::kWord64;
    } else if (type.Is(Type::ExternalPointer()) ||
               type.Is(Type::SandboxedPointer())) {
      return MachineType::PointerRepresentation();
    }
    return MachineRepresentation::kTagged;
  }

  // Helper for handling selects.
  template <Phase T>
  void VisitSelect(Node* node, Truncation truncation,
                   SimplifiedLowering* lowering) {
    DCHECK(TypeOf(node->InputAt(0)).Is(Type::Boolean()));
    ProcessInput<T>(node, 0, UseInfo::Bool());

    MachineRepresentation output =
        GetOutputInfoForPhi(TypeOf(node), truncation);
    SetOutput<T>(node, output);

    if (lower<T>()) {
      // Update the select operator.
      SelectParameters p = SelectParametersOf(node->op());
      if (output != p.representation()) {
        ChangeOp(node, lowering->common()->Select(output, p.hint()));
      }
    }
    // Convert inputs to the output representation of this phi, pass the
    // truncation truncation along.
    UseInfo input_use(output, truncation);
    ProcessInput<T>(node, 1, input_use);
    ProcessInput<T>(node, 2, input_use);
  }

  // Helper for handling phis.
  template <Phase T>
  void VisitPhi(Node* node, Truncation truncation,
                SimplifiedLowering* lowering) {
    // If we already have a non-tagged representation set in the Phi node, it
    // does come from subgraphs using machine operators we introduced early in
    // the pipeline. In this case, we just keep the representation.
    MachineRepresentation output = PhiRepresentationOf(node->op());
    if (output == MachineRepresentation::kTagged) {
      output = GetOutputInfoForPhi(TypeOf(node), truncation);
    }
    // Only set the output representation if not running with type
    // feedback. (Feedback typing will set the representation.)
    SetOutput<T>(node, output);

    int values = node->op()->ValueInputCount();
    if (lower<T>()) {
      // Update the phi operator.
      if (output != PhiRepresentationOf(node->op())) {
        ChangeOp(node, lowering->common()->Phi(output, values));
      }
    }

    // Convert inputs to the output representation of this phi, pass the
    // truncation along.
    UseInfo input_use(output, truncation);
    for (int i = 0; i < node->InputCount(); i++) {
      ProcessInput<T>(node, i, i < values ? input_use : UseInfo::None());
    }
  }

  template <Phase T>
  void VisitObjectIs(Node* node, Type type, SimplifiedLowering* lowering) {
    Type const input_type = TypeOf(node->InputAt(0));
    if (input_type.Is(type)) {
      VisitUnop<T>(node, UseInfo::None(), MachineRepresentation::kBit);
      if (lower<T>()) {
        DeferReplacement(
            node, InsertTypeOverrideForVerifier(
                      true_type(), lowering->jsgraph()->Int32Constant(1)));
      }
    } else {
      VisitUnop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kBit);
      if (lower<T>() && !input_type.Maybe(type)) {
        DeferReplacement(
            node, InsertTypeOverrideForVerifier(
                      false_type(), lowering->jsgraph()->Int32Constant(0)));
      }
    }
  }

  template <Phase T>
  void VisitCheck(Node* node, Type type, SimplifiedLowering* lowering) {
    if (InputIs(node, type)) {
      VisitUnop<T>(node, UseInfo::AnyTagged(),
                   MachineRepresentation::kTaggedPointer);
      if (lower<T>()) DeferReplacement(node, node->InputAt(0));
    } else {
      VisitUnop<T>(node,
                   UseInfo::CheckedHeapObjectAsTaggedPointer(FeedbackSource()),
                   MachineRepresentation::kTaggedPointer);
    }
  }

  template <Phase T>
  void VisitCall(Node* node, SimplifiedLowering* lowering) {
    auto call_descriptor = CallDescriptorOf(node->op());
    int params = static_cast<int>(call_descriptor->ParameterCount());
    int value_input_count = node->op()->ValueInputCount();

    DCHECK_GT(value_input_count, 0);
    DCHECK_GE(value_input_count, params);

    // The target of the call.
    ProcessInput<T>(node, 0, UseInfo::Any());

    // For the parameters (indexes [1, ..., params]), propagate representation
    // information from call descriptor.
    for (int i = 1; i <= params; i++) {
      ProcessInput<T>(node, i,
                      TruncatingUseInfoFromRepresentation(
                          call_descriptor->GetInputType(i).representation()));
    }

    // Rest of the value inputs.
    for (int i = params + 1; i < value_input_count; i++) {
      ProcessInput<T>(node, i, UseInfo::AnyTagged());
    }

    // Effect and Control.
    ProcessRemainingInputs<T>(node, value_input_count);

    if (call_descriptor->ReturnCount() > 0) {
      SetOutput<T>(node, call_descriptor->GetReturnType(0).representation());
    } else {
      SetOutput<T>(node, MachineRepresentation::kTagged);
    }
  }

  void MaskShiftOperand(Node* node, Type rhs_type) {
    if (!rhs_type.Is(type_cache_->kZeroToThirtyOne)) {
      Node* const rhs = NodeProperties::GetValueInput(node, 1);
      node->ReplaceInput(1,
                         graph()->NewNode(jsgraph_->machine()->Word32And(), rhs,
                                          jsgraph_->Int32Constant(0x1F)));
    }
  }

  static MachineSemantic DeoptValueSemanticOf(Type type) {
    // We only need signedness to do deopt correctly.
    if (type.Is(Type::Signed32())) {
      return MachineSemantic::kInt32;
    } else if (type.Is(Type::Unsigned32())) {
      return MachineSemantic::kUint32;
    } else {
      return MachineSemantic::kAny;
    }
  }

  static MachineType DeoptMachineTypeOf(MachineRepresentation rep, Type type) {
    if (type.IsNone()) {
      return MachineType::None();
    }
    // Do not distinguish between various Tagged variations.
    if (IsAnyTagged(rep)) {
      return MachineType::AnyTagged();
    }
    if (rep == MachineRepresentation::kWord64) {
      if (type.Is(Type::SignedBigInt64())) {
        return MachineType::SignedBigInt64();
      }

      if (type.Is(Type::UnsignedBigInt64())) {
        return MachineType::UnsignedBigInt64();
      }

      if (type.Is(Type::BigInt())) {
        return MachineType::AnyTagged();
      }

      DCHECK(type.Is(TypeCache::Get()->kSafeInteger));
      return MachineType(rep, MachineSemantic::kInt64);
    }
    MachineType machine_type(rep, DeoptValueSemanticOf(type));
    DCHECK_IMPLIES(
        machine_type.representation() == MachineRepresentation::kWord32,
        machine_type.semantic() == MachineSemantic::kInt32 ||
            machine_type.semantic() == MachineSemantic::kUint32);
    DCHECK_IMPLIES(machine_type.representation() == MachineRepresentation::kBit,
                   type.Is(Type::Boolean()));
    return machine_type;
  }

  template <Phase T>
  void VisitStateValues(Node* node) {
    if (propagate<T>()) {
      for (int i = 0; i < node->InputCount(); i++) {
        // BigInt64s are rematerialized in deoptimization. The other BigInts
        // must be rematerialized before deoptimization. By propagating an
        // AnyTagged use, the RepresentationChanger is going to insert the
        // necessary conversions.
        if (IsLargeBigInt(TypeOf(node->InputAt(i)))) {
          EnqueueInput<T>(node, i, UseInfo::AnyTagged());
        } else {
          EnqueueInput<T>(node, i, UseInfo::Any());
        }
      }
    } else if (lower<T>()) {
      Zone* zone = jsgraph_->zone();
      ZoneVector<MachineType>* types =
          zone->New<ZoneVector<MachineType>>(node->InputCount(), zone);
      for (int i = 0; i < node->InputCount(); i++) {
        Node* input = node->InputAt(i);
        if (IsLargeBigInt(TypeOf(input))) {
          ConvertInput(node, i, UseInfo::AnyTagged());
        }

        (*types)[i] =
            DeoptMachineTypeOf(GetInfo(input)->representation(), TypeOf(input));
      }
      SparseInputMask mask = SparseInputMaskOf(node->op());
      ChangeOp(node, common()->TypedStateValues(types, mask));
    }
    SetOutput<T>(node, MachineRepresentation::kTagged);
  }

  template <Phase T>
  void VisitFrameState(FrameState node) {
    DCHECK_EQ(5, node->op()->ValueInputCount());
    DCHECK_EQ(1, OperatorProperties::GetFrameStateInputCount(node->op()));
    DCHECK_EQ(FrameState::kFrameStateInputCount, node->InputCount());

    ProcessInput<T>(node, FrameState::kFrameStateParametersInput,
                    UseInfo::AnyTagged());
    ProcessInput<T>(node, FrameState::kFrameStateLocalsInput,
                    UseInfo::AnyTagged());

    // Accumulator is a special flower - we need to remember its type in
    // a singleton typed-state-values node (as if it was a singleton
    // state-values node).
    Node* accumulator = node.stack();
    if (propagate<T>()) {
      if (IsLargeBigInt(TypeOf(accumulator))) {
        EnqueueInput<T>(node, FrameState::kFrameStateStackInput,
                        UseInfo::AnyTagged());
      } else {
        EnqueueInput<T>(node, FrameState::kFrameStateStackInput,
                        UseInfo::Any());
      }
    } else if (lower<T>()) {
      if (IsLargeBigInt(TypeOf(accumulator))) {
        ConvertInput(node, FrameState::kFrameStateStackInput,
                     UseInfo::AnyTagged());
        accumulator = node.stack();
      }
      Zone* zone = jsgraph_->zone();
      if (accumulator == jsgraph_->OptimizedOutConstant()) {
        node->ReplaceInput(FrameState::kFrameStateStackInput,
                           jsgraph_->SingleDeadTypedStateValues());
      } else {
        ZoneVector<MachineType>* types =
            zone->New<ZoneVector<MachineType>>(1, zone);
        (*types)[0] = DeoptMachineTypeOf(GetInfo(accumulator)->representation(),
                                         TypeOf(accumulator));

        node->ReplaceInput(
            FrameState::kFrameStateStackInput,
            jsgraph_->graph()->NewNode(
                common()->TypedStateValues(types, SparseInputMask::Dense()),
                node.stack()));
      }
    }

    ProcessInput<T>(node, FrameState::kFrameStateContextInput,
                    UseInfo::AnyTagged());
    ProcessInput<T>(node, FrameState::kFrameStateFunctionInput,
                    UseInfo::AnyTagged());
    ProcessInput<T>(node, FrameState::kFrameStateOuterStateInput,
                    UseInfo::AnyTagged());
    return SetOutput<T>(node, MachineRepresentation::kTagged);
  }

  template <Phase T>
  void VisitObjectState(Node* node) {
    if (propagate<T>()) {
      for (int i = 0; i < node->InputCount(); i++) {
        if (IsLargeBigInt(TypeOf(node->InputAt(i)))) {
          EnqueueInput<T>(node, i, UseInfo::AnyTagged());
        } else {
          EnqueueInput<T>(node, i, UseInfo::Any());
        }
      }
    } else if (lower<T>()) {
      Zone* zone = jsgraph_->zone();
      ZoneVector<MachineType>* types =
          zone->New<ZoneVector<MachineType>>(node->InputCount(), zone);
      for (int i = 0; i < node->InputCount(); i++) {
        Node* input = node->InputAt(i);
        (*types)[i] =
            DeoptMachineTypeOf(GetInfo(input)->representation(), TypeOf(input));
        if (IsLargeBigInt(TypeOf(input))) {
          ConvertInput(node, i, UseInfo::AnyTagged());
        }
      }
      ChangeOp(node, common()->TypedObjectState(ObjectIdOf(node->op()), types));
    }
    SetOutput<T>(node, MachineRepresentation::kTagged);
  }

  const Operator* Int32Op(Node* node) {
    return changer_->Int32OperatorFor(node->opcode());
  }

  const Operator* Int32OverflowOp(Node* node) {
    return changer_->Int32OverflowOperatorFor(node->opcode());
  }

  const Operator* Int64Op(Node* node) {
    return changer_->Int64OperatorFor(node->opcode());
  }

  const Operator* Int64OverflowOp(Node* node) {
    return changer_->Int64OverflowOperatorFor(node->opcode());
  }

  const Operator* BigIntOp(Node* node) {
    return changer_->BigIntOperatorFor(node->opcode());
  }

  const Operator* Uint32Op(Node* node) {
    return changer_->Uint32OperatorFor(node->opcode());
  }

  const Operator* Uint32OverflowOp(Node* node) {
    return changer_->Uint32OverflowOperatorFor(node->opcode());
  }

  const Operator* Float64Op(Node* node) {
    return changer_->Float64OperatorFor(node->opcode());
  }

  WriteBarrierKind WriteBarrierKindFor(
      BaseTaggedness base_taggedness,
      MachineRepresentation field_representation, Type field_type,
      MachineRepresentation value_representation, Node* value) {
    if (base_taggedness == kTaggedBase &&
        CanBeTaggedPointer(field_representation)) {
      Type value_type = NodeProperties::GetType(value);
      if (value_representation == MachineRepresentation::kTaggedSigned) {
        // Write barriers are only for stores of heap objects.
        return kNoWriteBarrier;
      }
      if (field_type.Is(Type::BooleanOrNullOrUndefined()) ||
          value_type.Is(Type::BooleanOrNullOrUndefined())) {
        // Write barriers are not necessary when storing true, false, null or
        // undefined, because these special oddballs are always in the root set.
        return kNoWriteBarrier;
      }
      if (value_type.IsHeapConstant()) {
        RootIndex root_index;
        const RootsTable& roots_table = jsgraph_->isolate()->roots_table();
        if (roots_table.IsRootHandle(value_type.AsHeapConstant()->Value(),
                                     &root_index)) {
          if (RootsTable::IsImmortalImmovable(root_index)) {
            // Write barriers are unnecessary for immortal immovable roots.
            return kNoWriteBarrier;
          }
        }
      }
      if (field_representation == MachineRepresentation::kTaggedPointer ||
          value_representation == MachineRepresentation::kTaggedPointer) {
        // Write barriers for heap objects are cheaper.
        return kPointerWriteBarrier;
      }
      NumberMatcher m(value);
      if (m.HasResolvedValue()) {
        if (IsSmiDouble(m.ResolvedValue())) {
          // Storing a smi doesn't need a write barrier.
          return kNoWriteBarrier;
        }
        // The NumberConstant will be represented as HeapNumber.
        return kPointerWriteBarrier;
      }
      return kFullWriteBarrier;
    }
    return kNoWriteBarrier;
  }

  WriteBarrierKind WriteBarrierKindFor(
      BaseTaggedness base_taggedness,
      MachineRepresentation field_representation, int field_offset,
      Type field_type, MachineRepresentation value_representation,
      Node* value) {
    WriteBarrierKind write_barrier_kind =
        WriteBarrierKindFor(base_taggedness, field_representation, field_type,
                            value_representation, value);
    if (write_barrier_kind != kNoWriteBarrier) {
      if (base_taggedness == kTaggedBase &&
          field_offset == HeapObject::kMapOffset) {
        write_barrier_kind = kMapWriteBarrier;
      }
    }
    return write_barrier_kind;
  }

  Graph* graph() const { return jsgraph_->graph(); }
  CommonOperatorBuilder* common() const { return jsgraph_->common(); }
  SimplifiedOperatorBuilder* simplified() const {
    return jsgraph_->simplified();
  }

  template <Phase T>
  void VisitForCheckedInt32Mul(Node* node, Truncation truncation,
                               Type input0_type, Type input1_type,
                               UseInfo input_use) {
    DCHECK_EQ(node->opcode(), IrOpcode::kSpeculativeNumberMultiply);
    // A -0 input is impossible or will cause a deopt.
    DCHECK(BothInputsAre(node, Type::Signed32()) ||
           !input_use.truncation().IdentifiesZeroAndMinusZero());

    CheckForMinusZeroMode mz_mode;
    Type restriction;
    if (IsSomePositiveOrderedNumber(input0_type) ||
        IsSomePositiveOrderedNumber(input1_type)) {
      mz_mode = CheckForMinusZeroMode::kDontCheckForMinusZero;
      restriction = Type::Signed32();
    } else if (truncation.IdentifiesZeroAndMinusZero()) {
      mz_mode = CheckForMinusZeroMode::kDontCheckForMinusZero;
      restriction = Type::Signed32OrMinusZero();
    } else {
      mz_mode = CheckForMinusZeroMode::kCheckForMinusZero;
      restriction = Type::Signed32();
    }

    VisitBinop<T>(node, input_use, MachineRepresentation::kWord32, restriction);
    if (lower<T>()) ChangeOp(node, simplified()->CheckedInt32Mul(mz_mode));
  }

  void ChangeToInt32OverflowOp(Node* node) {
    ChangeOp(node, Int32OverflowOp(node));
  }

  void ChangeToUint32OverflowOp(Node* node) {
    ChangeOp(node, Uint32OverflowOp(node));
  }

  template <Phase T>
  void VisitSpeculativeIntegerAdditiveOp(Node* node, Truncation truncation,
                                         SimplifiedLowering* lowering) {
    Type left_upper = GetUpperBound(node->InputAt(0));
    Type right_upper = GetUpperBound(node->InputAt(1));

    if (left_upper.Is(type_cache_->kAdditiveSafeIntegerOrMinusZero) &&
        right_upper.Is(type_cache_->kAdditiveSafeIntegerOrMinusZero)) {
      // Only eliminate the node if its typing rule can be satisfied, namely
      // that a safe integer is produced.
      if (truncation.IsUnused()) return VisitUnused<T>(node);

      // If we know how to interpret the result or if the users only care
      // about the low 32-bits, we can truncate to Word32 do a wrapping
      // addition.
      if (GetUpperBound(node).Is(Type::Signed32()) ||
          GetUpperBound(node).Is(Type::Unsigned32()) ||
          truncation.IsUsedAsWord32()) {
        // => Int32Add/Sub
        VisitWord32TruncatingBinop<T>(node);
        if (lower<T>()) ChangeToPureOp(node, Int32Op(node));
        return;
      }
    }

    // Try to use type feedback.
    NumberOperationHint const hint = NumberOperationHint::kSignedSmall;
    DCHECK_EQ(hint, NumberOperationHintOf(node->op()));

    Type left_feedback_type = TypeOf(node->InputAt(0));
    Type right_feedback_type = TypeOf(node->InputAt(1));

    // Using Signed32 as restriction type amounts to promising there won't be
    // signed overflow. This is incompatible with relying on a Word32 truncation
    // in order to skip the overflow check.  Similarly, we must not drop -0 from
    // the result type unless we deopt for -0 inputs.
    Type const restriction =
        truncation.IsUsedAsWord32()
            ? Type::Any()
            : (truncation.identify_zeros() == kIdentifyZeros)
                  ? Type::Signed32OrMinusZero()
                  : Type::Signed32();

    // Handle the case when no int32 checks on inputs are necessary (but
    // an overflow check is needed on the output). Note that we do not
    // have to do any check if at most one side can be minus zero. For
    // subtraction we need to handle the case of -0 - 0 properly, since
    // that can produce -0.
    Type left_constraint_type =
        node->opcode() == IrOpcode::kSpeculativeSafeIntegerAdd
            ? Type::Signed32OrMinusZero()
            : Type::Signed32();
    if (left_upper.Is(left_constraint_type) &&
        right_upper.Is(Type::Signed32OrMinusZero()) &&
        (left_upper.Is(Type::Signed32()) || right_upper.Is(Type::Signed32()))) {
      VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                    MachineRepresentation::kWord32, restriction);
    } else {
      // If the output's truncation is identify-zeros, we can pass it
      // along. Moreover, if the operation is addition and we know the
      // right-hand side is not minus zero, we do not have to distinguish
      // between 0 and -0.
      IdentifyZeros left_identify_zeros = truncation.identify_zeros();
      if (node->opcode() == IrOpcode::kSpeculativeSafeIntegerAdd &&
          !right_feedback_type.Maybe(Type::MinusZero())) {
        left_identify_zeros = kIdentifyZeros;
      }
      UseInfo left_use =
          CheckedUseInfoAsWord32FromHint(hint, left_identify_zeros);
      // For CheckedInt32Add and CheckedInt32Sub, we don't need to do
      // a minus zero check for the right hand side, since we already
      // know that the left hand side is a proper Signed32 value,
      // potentially guarded by a check.
      UseInfo right_use = CheckedUseInfoAsWord32FromHint(hint, kIdentifyZeros);
      VisitBinop<T>(node, left_use, right_use, MachineRepresentation::kWord32,
                    restriction);
    }

    if (lower<T>()) {
      if (truncation.IsUsedAsWord32() ||
          !CanOverflowSigned32(node->op(), left_feedback_type,
                               right_feedback_type, type_cache_,
                               graph_zone())) {
        ChangeToPureOp(node, Int32Op(node));
      } else {
        ChangeToInt32OverflowOp(node);
      }
    }
  }

  template <Phase T>
  void VisitSpeculativeAdditiveOp(Node* node, Truncation truncation,
                                  SimplifiedLowering* lowering) {
    if (BothInputsAre(node, type_cache_->kAdditiveSafeIntegerOrMinusZero) &&
        (GetUpperBound(node).Is(Type::Signed32()) ||
         GetUpperBound(node).Is(Type::Unsigned32()) ||
         truncation.IsUsedAsWord32())) {
      // => Int32Add/Sub
      VisitWord32TruncatingBinop<T>(node);
      if (lower<T>()) ChangeToPureOp(node, Int32Op(node));
      return;
    }

    // default case => Float64Add/Sub
    VisitBinop<T>(node,
                  UseInfo::CheckedNumberOrOddballAsFloat64(kDistinguishZeros,
                                                           FeedbackSource()),
                  MachineRepresentation::kFloat64, Type::Number());
    if (lower<T>()) {
      ChangeToPureOp(node, Float64Op(node));
    }
  }

  template <Phase T>
  void VisitSpeculativeNumberModulus(Node* node, Truncation truncation,
                                     SimplifiedLowering* lowering) {
```