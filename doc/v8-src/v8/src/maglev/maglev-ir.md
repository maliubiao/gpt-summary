Response: The user wants me to summarize the functionality of the C++ code in `v8/src/maglev/maglev-ir.cc`.
This is part 1 of a 5-part series, so the summary should focus on the elements present in this specific chunk.

Based on the included headers and the namespace `v8::internal::maglev`, this file appears to define the **Intermediate Representation (IR)** for the **Maglev** compiler in V8.

Here's a breakdown of the code's purpose:

1. **Defines core IR concepts**: It introduces fundamental classes and structures that represent operations and data within the Maglev compiler.
2. **Node representation**: The `NodeBase` class serves as the base for all IR nodes, representing individual operations. It includes information like opcode, inputs, and properties.
3. **Value and Control flow**:  Distinguishes between `ValueNode` (representing computed values) and `ControlNode` (managing control flow).
4. **Specific Node types**: Defines various concrete node types like `Phi`, `Constant`, `Call`, `Load`, `Store`, and arithmetic operations. Each node type represents a specific operation in the Maglev IR.
5. **Type information**:  Includes mechanisms for tracking value representations (`ValueRepresentation`) and ensuring type safety.
6. **Deoptimization support**:  Contains structures like `DeoptInfo` and `LazyDeoptInfo` to handle deoptimization scenarios.
7. **Code generation hints**:  Provides hints for code generation, such as register allocation constraints.
8. **Debugging and printing**: Offers functionalities to print the IR graph for debugging purposes.
9. **Integration with V8**: Uses various V8 components like `Isolate`, `Factory`, `Builtins`, etc., highlighting its role within the V8 ecosystem.

Regarding the relationship with JavaScript, this C++ code is crucial for *compiling* JavaScript code. Maglev takes JavaScript bytecode and transforms it into machine code. The IR defined here is an intermediate step in that process.

**Illustrative Example in JavaScript (Conceptual):**

While you can't directly interact with this C++ IR in JavaScript, you can understand its function by considering how a JavaScript operation might be represented in this IR.

```javascript
function add(a, b) {
  return a + b;
}
```

When the Maglev compiler processes this `add` function, it might create IR nodes similar to these (simplified conceptual representation):

*   `Parameter a`: A `Parameter` node representing the input 'a'.
*   `Parameter b`: A `Parameter` node representing the input 'b'.
*   `LoadVariable a`:  A `LoadVariable` node to get the value of 'a'.
*   `LoadVariable b`:  A `LoadVariable` node to get the value of 'b'.
*   `BinaryOperation +`: A `BinaryOperation` node representing the addition operation, with the `LoadVariable` nodes as inputs.
*   `Return`: A `Return` node taking the output of the `BinaryOperation` as input.

The C++ code in `maglev-ir.cc` defines the actual C++ classes and structures for these conceptual nodes, including details about their inputs, outputs, and properties relevant for efficient code generation.

功能归纳：

这段C++代码是V8 JavaScript引擎中Maglev编译器的核心组成部分，它定义了**中间表示 (Intermediate Representation, IR)** 的结构和操作。  Maglev编译器使用这个IR来表示和优化JavaScript代码，最终生成机器码。

具体来说，这段代码主要负责：

1. **定义了Maglev IR中的各种节点类型 (Node Types)**：
    *   `NodeBase` 是所有IR节点的基类，包含了所有节点共有的属性，例如操作码 (opcode)、输入 (inputs) 和属性 (properties)。
    *   `ValueNode` 表示产生值的节点，例如常量、变量读取、算术运算等。
    *   `ControlNode` 表示控制流的节点，例如跳转、分支、返回等。
    *   各种具体的节点类型，例如 `Phi` (用于合并控制流)、`Constant` (常量值)、`Call` (函数调用)、`Load` (加载值)、`Store` (存储值) 等。每种节点都代表了Maglev IR中的一个特定操作。

2. **定义了节点之间的连接方式 (Inputs and Outputs)**：通过 `Input` 类来表示节点的输入，每个输入连接到另一个 `ValueNode` 的输出。

3. **管理节点的属性 (Node Properties)**：例如，节点是否会触发eager deoptimization 或 lazy deoptimization，是否需要寄存器快照等。

4. **处理Phi节点**： `Phi` 节点用于在控制流合并的地方汇集来自不同路径的值。代码中包含了 `Phi` 节点的创建、输入管理以及类型推断相关的功能。

5. **支持Deoptimization (反优化)**：定义了 `DeoptInfo` 和 `LazyDeoptInfo` 等结构，用于记录反优化所需的信息，以便在运行时发生错误时能够回到解释器执行。

6. **提供调试和打印功能**：  包含了用于将IR图打印出来的代码，方便开发者调试和理解IR的结构。

与JavaScript功能的关系：

这段C++代码是JavaScript代码执行的关键环节——编译过程的一部分。Maglev编译器会将JavaScript源代码（更准确地说是字节码）转换成高效的机器码。`maglev-ir.cc` 中定义的IR就是这个转换过程中的一个中间产物。

**JavaScript 示例说明：**

假设有如下简单的JavaScript函数：

```javascript
function add(x, y) {
  return x + y;
}
```

当Maglev编译器编译这个函数时，它可能会在内部创建一些类似于以下概念的IR节点（这只是一个简化的概念性表示，并非实际的IR结构）：

*   一个表示参数 `x` 的节点 (例如，类型为 `Parameter`)。
*   一个表示参数 `y` 的节点 (例如，类型为 `Parameter`)。
*   一个表示加法操作的节点 (例如，类型为 `BinaryOperation`，操作码为 `+`)，其输入连接到表示 `x` 和 `y` 的节点。
*   一个表示返回操作的节点 (例如，类型为 `Return`)，其输入连接到表示加法结果的节点。

`v8/src/maglev/maglev-ir.cc` 中的代码就是用来定义 `Parameter`，`BinaryOperation`，`Return` 这些节点在C++中的具体结构和行为。它并不直接执行JavaScript代码，而是负责构建一个可以被进一步优化和转换为机器码的中间表示，从而加速JavaScript代码的执行。

总结来说，`v8/src/maglev/maglev-ir.cc` 定义了Maglev编译器所使用的蓝图，它规定了如何用C++数据结构来表示JavaScript代码中的各种操作和数据流动，是Maglev编译器理解和优化JavaScript代码的基础。

Prompt: 
```
这是目录为v8/src/maglev/maglev-ir.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/maglev/maglev-ir.h"

#include <cmath>
#include <limits>
#include <optional>

#include "src/base/bounds.h"
#include "src/base/logging.h"
#include "src/builtins/builtins-constructor.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/interface-descriptors.h"
#include "src/common/globals.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/fast-api-calls.h"
#include "src/compiler/heap-refs.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/execution/isolate-inl.h"
#include "src/heap/local-heap.h"
#include "src/heap/parked-scope.h"
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/objects/fixed-array.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array.h"
#include "src/objects/js-generator.h"
#include "src/objects/property-cell.h"
#include "src/roots/static-roots.h"
#ifdef V8_ENABLE_MAGLEV
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-assembler.h"
#include "src/maglev/maglev-code-gen-state.h"
#endif
#include "src/maglev/maglev-compilation-unit.h"
#include "src/maglev/maglev-graph-labeller.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/roots/roots.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm->

const char* OpcodeToString(Opcode opcode) {
#define DEF_NAME(Name) #Name,
  static constexpr const char* const names[] = {NODE_BASE_LIST(DEF_NAME)};
#undef DEF_NAME
  return names[static_cast<int>(opcode)];
}

BasicBlock* Phi::predecessor_at(int i) {
  return merge_state_->predecessor_at(i);
}

namespace {

// Prevent people from accidentally using kScratchRegister here and having their
// code break in arm64.
[[maybe_unused]] struct Do_not_use_kScratchRegister_in_arch_independent_code {
} kScratchRegister;
[[maybe_unused]] struct
    Do_not_use_kScratchDoubleRegister_in_arch_independent_code {
} kScratchDoubleRegister;
static_assert(!std::is_same_v<decltype(kScratchRegister), Register>);
static_assert(
    !std::is_same_v<decltype(kScratchDoubleRegister), DoubleRegister>);

}  // namespace

#ifdef DEBUG
namespace {

template <size_t InputCount, typename Base, typename Derived>
int StaticInputCount(FixedInputNodeTMixin<InputCount, Base, Derived>*) {
  return InputCount;
}

int StaticInputCount(NodeBase*) { UNREACHABLE(); }

}  // namespace

void NodeBase::CheckCanOverwriteWith(Opcode new_opcode,
                                     OpProperties new_properties) {
  if (new_opcode == Opcode::kDead) return;

  DCHECK_IMPLIES(new_properties.can_eager_deopt(),
                 properties().can_eager_deopt());
  DCHECK_IMPLIES(new_properties.can_lazy_deopt(),
                 properties().can_lazy_deopt());
  DCHECK_IMPLIES(new_properties.needs_register_snapshot(),
                 properties().needs_register_snapshot());

  int old_input_count = input_count();
  size_t old_sizeof = -1;
  switch (opcode()) {
#define CASE(op)             \
  case Opcode::k##op:        \
    old_sizeof = sizeof(op); \
    break;
    NODE_BASE_LIST(CASE);
#undef CASE
  }

  switch (new_opcode) {
#define CASE(op)                                                          \
  case Opcode::k##op: {                                                   \
    DCHECK_EQ(old_input_count, StaticInputCount(static_cast<op*>(this))); \
    DCHECK_EQ(sizeof(op), old_sizeof);                                    \
    break;                                                                \
  }
    NODE_BASE_LIST(CASE)
#undef CASE
  }
}

#endif  // DEBUG

bool Phi::is_loop_phi() const { return merge_state()->is_loop(); }

bool Phi::is_unmerged_loop_phi() const {
  DCHECK(is_loop_phi());
  return merge_state()->is_unmerged_loop();
}

void Phi::RecordUseReprHint(UseRepresentationSet repr_mask,
                            int current_offset) {
  if (is_loop_phi() && merge_state()->HasLoopInfo() &&
      merge_state()->loop_info()->Contains(current_offset)) {
    same_loop_uses_repr_hint_.Add(repr_mask);
  }

  if (!repr_mask.is_subset_of(uses_repr_hint_)) {
    uses_repr_hint_.Add(repr_mask);

    // Propagate in inputs, ignoring unbounded loop backedges.
    int bound_inputs = input_count();
    if (merge_state()->is_unmerged_loop()) --bound_inputs;

    for (int i = 0; i < bound_inputs; i++) {
      if (Phi* phi_input = input(i).node()->TryCast<Phi>()) {
        phi_input->RecordUseReprHint(repr_mask, current_offset);
      }
    }
  }
}

void Phi::SetUseRequires31BitValue() {
  if (uses_require_31_bit_value()) return;
  set_uses_require_31_bit_value();
  auto inputs =
      is_loop_phi() ? merge_state_->predecessors_so_far() : input_count();
  for (uint32_t i = 0; i < inputs; ++i) {
    ValueNode* input_node = input(i).node();
    DCHECK(input_node);
    if (auto phi = input_node->TryCast<Phi>()) {
      phi->SetUseRequires31BitValue();
    }
  }
}

InitialValue::InitialValue(uint64_t bitfield, interpreter::Register source)
    : Base(bitfield), source_(source) {}

namespace {

// ---
// Print
// ---

bool IsStoreToNonEscapedObject(const NodeBase* node) {
  switch (node->opcode()) {
    case Opcode::kStoreMap:
    case Opcode::kStoreTaggedFieldWithWriteBarrier:
    case Opcode::kStoreTaggedFieldNoWriteBarrier:
    case Opcode::kStoreScriptContextSlotWithWriteBarrier:
    case Opcode::kStoreFloat64:
      DCHECK_GT(node->input_count(), 0);
      if (InlinedAllocation* alloc =
              node->input(0).node()->template TryCast<InlinedAllocation>()) {
        return alloc->HasBeenAnalysed() && alloc->HasBeenElided();
      }
      return false;
    default:
      return false;
  }
}

void PrintInputs(std::ostream& os, MaglevGraphLabeller* graph_labeller,
                 const NodeBase* node) {
  if (!node->has_inputs()) return;

  os << " [";
  for (int i = 0; i < node->input_count(); i++) {
    if (i != 0) os << ", ";
    graph_labeller->PrintInput(os, node->input(i));
  }
  if (IsStoreToNonEscapedObject(node)) {
    os << " 🪦";
  }
  os << "]";
}

void PrintResult(std::ostream& os, MaglevGraphLabeller* graph_labeller,
                 const NodeBase* node) {}

void PrintResult(std::ostream& os, MaglevGraphLabeller* graph_labeller,
                 const ValueNode* node) {
  os << " → " << node->result().operand();
  if (node->result().operand().IsAllocated() && node->is_spilled() &&
      node->spill_slot() != node->result().operand()) {
    os << " (spilled: " << node->spill_slot() << ")";
  }
  if (node->has_valid_live_range()) {
    os << ", live range: [" << node->live_range().start << "-"
       << node->live_range().end << "]";
  }
  if (!node->has_id()) {
    os << ", " << node->use_count() << " uses";
    if (const InlinedAllocation* alloc = node->TryCast<InlinedAllocation>()) {
      os << " (" << alloc->non_escaping_use_count() << " non escaping uses)";
      if (alloc->HasBeenAnalysed() && alloc->HasBeenElided()) {
        os << " 🪦";
      }
    } else if (!node->is_used()) {
      if (node->opcode() != Opcode::kAllocationBlock &&
          node->properties().is_required_when_unused()) {
        os << ", but required";
      } else {
        os << " 🪦";
      }
    }
  }
}

void PrintTargets(std::ostream& os, MaglevGraphLabeller* graph_labeller,
                  const NodeBase* node) {}

void PrintTargets(std::ostream& os, MaglevGraphLabeller* graph_labeller,
                  const UnconditionalControlNode* node) {
  os << " b" << graph_labeller->BlockId(node->target());
}

void PrintTargets(std::ostream& os, MaglevGraphLabeller* graph_labeller,
                  const BranchControlNode* node) {
  os << " b" << graph_labeller->BlockId(node->if_true()) << " b"
     << graph_labeller->BlockId(node->if_false());
}

void PrintTargets(std::ostream& os, MaglevGraphLabeller* graph_labeller,
                  const Switch* node) {
  for (int i = 0; i < node->size(); i++) {
    const BasicBlockRef& target = node->Cast<Switch>()->targets()[i];
    os << " b" << graph_labeller->BlockId(target.block_ptr());
  }
  if (node->Cast<Switch>()->has_fallthrough()) {
    BasicBlock* fallthrough_target = node->Cast<Switch>()->fallthrough();
    os << " b" << graph_labeller->BlockId(fallthrough_target);
  }
}

class MaybeUnparkForPrint {
 public:
  MaybeUnparkForPrint() {
    LocalHeap* local_heap = LocalHeap::Current();
    if (!local_heap) {
      local_heap = Isolate::Current()->main_thread_local_heap();
    }
    DCHECK_NOT_NULL(local_heap);
    if (local_heap->IsParked()) {
      scope_.emplace(local_heap);
    }
  }

 private:
  std::optional<UnparkedScope> scope_;
};

template <typename NodeT>
void PrintImpl(std::ostream& os, MaglevGraphLabeller* graph_labeller,
               const NodeT* node, bool skip_targets) {
  MaybeUnparkForPrint unpark;
  os << node->opcode();
  node->PrintParams(os, graph_labeller);
  PrintInputs(os, graph_labeller, node);
  PrintResult(os, graph_labeller, node);
  if (!skip_targets) {
    PrintTargets(os, graph_labeller, node);
  }
}

bool RootToBoolean(RootIndex index) {
  switch (index) {
    case RootIndex::kFalseValue:
    case RootIndex::kNullValue:
    case RootIndex::kUndefinedValue:
    case RootIndex::kNanValue:
    case RootIndex::kHoleNanValue:
    case RootIndex::kMinusZeroValue:
    case RootIndex::kempty_string:
#ifdef V8_ENABLE_WEBASSEMBLY
    case RootIndex::kWasmNull:
#endif
      return false;
    default:
      return true;
  }
}

#ifdef DEBUG
// For all RO roots, check that RootToBoolean returns the same value as
// BooleanValue on that root.
bool CheckToBooleanOnAllRoots(LocalIsolate* local_isolate) {
  ReadOnlyRoots roots(local_isolate);
  // Use the READ_ONLY_ROOT_LIST macro list rather than a for loop to get nicer
  // error messages if there is a failure.
#define DO_CHECK(type, name, CamelName)                                   \
  /* Ignore 'undefined' roots that are not the undefined value itself. */ \
  if (roots.name() != roots.undefined_value() ||                          \
      RootIndex::k##CamelName == RootIndex::kUndefinedValue) {            \
    DCHECK_EQ(Object::BooleanValue(roots.name(), local_isolate),          \
              RootToBoolean(RootIndex::k##CamelName));                    \
  }
  READ_ONLY_ROOT_LIST(DO_CHECK)
#undef DO_CHECK
  return true;
}
#endif

size_t GetInputLocationSizeForValueNode(VirtualObject::List virtual_objects,
                                        ValueNode* value) {
  // We allocate the space needed for the Virtual Object plus one location
  // used if the allocation escapes.
  DCHECK(!value->Is<VirtualObject>());
  if (const InlinedAllocation* alloc = value->TryCast<InlinedAllocation>()) {
    VirtualObject* vobject = virtual_objects.FindAllocatedWith(alloc);
    CHECK_NOT_NULL(vobject);
    return vobject->InputLocationSizeNeeded(virtual_objects) + 1;
  }
  return 1;
}

size_t GetInputLocationSizeForArray(VirtualObject::List virtual_objects,
                                    base::Vector<ValueNode*> array) {
  size_t size = 0;
  for (ValueNode* value : array) {
    size += GetInputLocationSizeForValueNode(virtual_objects, value);
  }
  return size;
}

size_t GetInputLocationSizeForCompactFrame(
    const MaglevCompilationUnit& unit, VirtualObject::List virtual_objects,
    const CompactInterpreterFrameState* frame) {
  size_t size = 0;
  frame->ForEachValue(unit, [&](ValueNode* value, interpreter::Register) {
    if (value != nullptr) {
      size += GetInputLocationSizeForValueNode(virtual_objects, value);
    }
  });
  return size;
}

size_t GetInputLocationSizeForVirtualObjectSlot(
    VirtualObject::List virtual_objects, ValueNode* node) {
  if (IsConstantNode(node->opcode()) ||
      node->opcode() == Opcode::kArgumentsElements ||
      node->opcode() == Opcode::kArgumentsLength ||
      node->opcode() == Opcode::kRestLength) {
    return 0;
  }
  return GetInputLocationSizeForValueNode(virtual_objects, node);
}

}  // namespace

size_t VirtualObject::InputLocationSizeNeeded(
    VirtualObject::List virtual_objects) const {
  if (type() != kDefault) return 0;
  size_t size = 0;
  for (uint32_t i = 0; i < slot_count(); i++) {
    size += GetInputLocationSizeForVirtualObjectSlot(virtual_objects,
                                                     slots_.data[i]);
  }
  return size;
}

void VirtualObject::List::Print(std::ostream& os, const char* prefix,
                                MaglevGraphLabeller* labeller) const {
  CHECK_NOT_NULL(labeller);
  os << prefix;
  for (const VirtualObject* vo : *this) {
    labeller->PrintNodeLabel(os, vo);
    os << "; ";
  }
  os << std::endl;
}

size_t DeoptFrame::GetInputLocationsArraySize() const {
  size_t size = 0;
  const DeoptFrame* frame = this;
  VirtualObject::List virtual_objects = GetVirtualObjects(*frame);
  do {
    switch (frame->type()) {
      case DeoptFrame::FrameType::kInterpretedFrame:
        size += GetInputLocationSizeForValueNode(
                    virtual_objects, frame->as_interpreted().closure()) +
                GetInputLocationSizeForCompactFrame(
                    frame->as_interpreted().unit(), virtual_objects,
                    frame->as_interpreted().frame_state());
        break;
      case DeoptFrame::FrameType::kInlinedArgumentsFrame:
        size += GetInputLocationSizeForValueNode(
                    virtual_objects, frame->as_inlined_arguments().closure()) +
                GetInputLocationSizeForArray(
                    virtual_objects, frame->as_inlined_arguments().arguments());
        break;
      case DeoptFrame::FrameType::kConstructInvokeStubFrame:
        size += GetInputLocationSizeForValueNode(
                    virtual_objects, frame->as_construct_stub().receiver()) +
                GetInputLocationSizeForValueNode(
                    virtual_objects, frame->as_construct_stub().context());
        break;
      case DeoptFrame::FrameType::kBuiltinContinuationFrame:
        size +=
            GetInputLocationSizeForArray(
                virtual_objects,
                frame->as_builtin_continuation().parameters()) +
            GetInputLocationSizeForValueNode(
                virtual_objects, frame->as_builtin_continuation().context());
        break;
    }
    frame = frame->parent();
  } while (frame != nullptr);
  return size;
}

bool RootConstant::ToBoolean(LocalIsolate* local_isolate) const {
#ifdef DEBUG
  // (Ab)use static locals to call CheckToBooleanOnAllRoots once, on first
  // call to this function.
  static bool check_once = CheckToBooleanOnAllRoots(local_isolate);
  DCHECK(check_once);
#endif
  // ToBoolean is only supported for RO roots.
  DCHECK(RootsTable::IsReadOnly(index_));
  return RootToBoolean(index_);
}

bool FromConstantToBool(LocalIsolate* local_isolate, ValueNode* node) {
  DCHECK(IsConstantNode(node->opcode()));
  switch (node->opcode()) {
#define CASE(Name)                                       \
  case Opcode::k##Name: {                                \
    return node->Cast<Name>()->ToBoolean(local_isolate); \
  }
    CONSTANT_VALUE_NODE_LIST(CASE)
#undef CASE
    default:
      UNREACHABLE();
  }
}

void Input::clear() {
  node_->remove_use();
  node_ = nullptr;
}

DeoptInfo::DeoptInfo(Zone* zone, const DeoptFrame top_frame,
                     compiler::FeedbackSource feedback_to_update,
                     size_t input_locations_size)
    : top_frame_(top_frame),
      feedback_to_update_(feedback_to_update),
      input_locations_(
          zone->AllocateArray<InputLocation>(input_locations_size)) {
  // Initialise InputLocations so that they correctly don't have a next use id.
  for (size_t i = 0; i < input_locations_size; ++i) {
    new (&input_locations_[i]) InputLocation();
  }
#ifdef DEBUG
  input_location_count_ = input_locations_size;
#endif  // DEBUG
}

bool LazyDeoptInfo::IsResultRegister(interpreter::Register reg) const {
  if (top_frame().type() == DeoptFrame::FrameType::kConstructInvokeStubFrame) {
    return reg == interpreter::Register::virtual_accumulator();
  }
  if (V8_LIKELY(result_size() == 1)) {
    return reg == result_location_;
  }
  if (result_size() == 0) {
    return false;
  }
  DCHECK_EQ(result_size(), 2);
  return reg == result_location_ ||
         reg == interpreter::Register(result_location_.index() + 1);
}

bool LazyDeoptInfo::InReturnValues(interpreter::Register reg,
                                   interpreter::Register result_location,
                                   int result_size) {
  if (result_size == 0 || !result_location.is_valid()) {
    return false;
  }
  return base::IsInRange(reg.index(), result_location.index(),
                         result_location.index() + result_size - 1);
}

int InterpretedDeoptFrame::ComputeReturnOffset(
    interpreter::Register result_location, int result_size) const {
  // Return offsets are counted from the end of the translation frame,
  // which is the array [parameters..., locals..., accumulator]. Since
  // it's the end, we don't need to worry about earlier frames.
  if (result_location == interpreter::Register::virtual_accumulator()) {
    return 0;
  } else if (result_location.is_parameter()) {
    // This is slightly tricky to reason about because of zero indexing
    // and fence post errors. As an example, consider a frame with 2
    // locals and 2 parameters, where we want argument index 1 -- looking
    // at the array in reverse order we have:
    //   [acc, r1, r0, a1, a0]
    //                  ^
    // and this calculation gives, correctly:
    //   2 + 2 - 1 = 3
    return unit().register_count() + unit().parameter_count() -
           result_location.ToParameterIndex();
  } else {
    return unit().register_count() - result_location.index();
  }
}

const InterpretedDeoptFrame& LazyDeoptInfo::GetFrameForExceptionHandler(
    const ExceptionHandlerInfo* handler_info) {
  const DeoptFrame* target_frame = &top_frame();
  for (int i = 0;; i++) {
    while (target_frame->type() != DeoptFrame::FrameType::kInterpretedFrame) {
      target_frame = target_frame->parent();
    }
    if (i == handler_info->depth) break;
    target_frame = target_frame->parent();
  }
  return target_frame->as_interpreted();
}

void NodeBase::Print(std::ostream& os, MaglevGraphLabeller* graph_labeller,
                     bool skip_targets) const {
  switch (opcode()) {
#define V(Name)         \
  case Opcode::k##Name: \
    return PrintImpl(os, graph_labeller, this->Cast<Name>(), skip_targets);
    NODE_BASE_LIST(V)
#undef V
  }
  UNREACHABLE();
}

void NodeBase::Print() const {
  MaglevGraphLabeller labeller;
  Print(std::cout, &labeller);
  std::cout << std::endl;
}

void ValueNode::SetHint(compiler::InstructionOperand hint) {
  if (!hint_.IsInvalid()) return;
  hint_ = hint;
  if (result_.operand().IsUnallocated()) {
    auto operand = compiler::UnallocatedOperand::cast(result_.operand());
    if (operand.HasSameAsInputPolicy()) {
      input(operand.input_index()).node()->SetHint(hint);
    }
  }
  if (this->Is<Phi>()) {
    for (Input& input : *this) {
      if (input.node()->has_id() && input.node()->id() < this->id()) {
        input.node()->SetHint(hint);
      }
    }
  }
}

void ValueNode::SetNoSpill() {
  DCHECK(!IsConstantNode(opcode()));
#ifdef DEBUG
  state_ = kSpill;
#endif  // DEBUG
  spill_ = compiler::InstructionOperand();
}

void ValueNode::SetConstantLocation() {
  DCHECK(IsConstantNode(opcode()));
#ifdef DEBUG
  state_ = kSpill;
#endif  // DEBUG
  spill_ = compiler::ConstantOperand(
      compiler::UnallocatedOperand::cast(result().operand())
          .virtual_register());
}

ExternalReference Float64Ieee754Unary::ieee_function_ref() const {
  switch (ieee_function_) {
#define CASE(MathName, ExtName, EnumName) \
  case Ieee754Function::k##EnumName:      \
    return ExternalReference::ieee754_##ExtName##_function();
    IEEE_754_UNARY_LIST(CASE)
#undef CASE
  }
}

// ---
// Check input value representation
// ---

ValueRepresentation ToValueRepresentation(MachineType type) {
  switch (type.representation()) {
    case MachineRepresentation::kTagged:
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kTaggedPointer:
      return ValueRepresentation::kTagged;
    case MachineRepresentation::kFloat64:
      return ValueRepresentation::kFloat64;
    case MachineRepresentation::kWord64:
      DCHECK_EQ(kSystemPointerSize, 8);
      return ValueRepresentation::kIntPtr;
    default:
      return ValueRepresentation::kInt32;
  }
}

void CheckValueInputIs(const NodeBase* node, int i,
                       ValueRepresentation expected,
                       MaglevGraphLabeller* graph_labeller) {
  ValueNode* input = node->input(i).node();
  DCHECK(!input->Is<Identity>());
  ValueRepresentation got = input->properties().value_representation();
  // Allow Float64 values to be inputs when HoleyFloat64 is expected.
  bool valid =
      (got == expected) || (got == ValueRepresentation::kFloat64 &&
                            expected == ValueRepresentation::kHoleyFloat64);
  if (!valid) {
    std::ostringstream str;
    str << "Type representation error: node ";
    if (graph_labeller) {
      str << "#" << graph_labeller->NodeId(node) << " : ";
    }
    str << node->opcode() << " (input @" << i << " = " << input->opcode()
        << ") type " << got << " is not " << expected;
    FATAL("%s", str.str().c_str());
  }
}

void CheckValueInputIs(const NodeBase* node, int i, Opcode expected,
                       MaglevGraphLabeller* graph_labeller) {
  ValueNode* input = node->input(i).node();
  Opcode got = input->opcode();
  if (got != expected) {
    std::ostringstream str;
    str << "Opcode error: node ";
    if (graph_labeller) {
      str << "#" << graph_labeller->NodeId(node) << " : ";
    }
    str << node->opcode() << " (input @" << i << " = " << input->opcode()
        << ") opcode " << got << " is not " << expected;
    FATAL("%s", str.str().c_str());
  }
}

void GeneratorStore::VerifyInputs(MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

void Phi::VerifyInputs(MaglevGraphLabeller* graph_labeller) const {
  switch (value_representation()) {
#define CASE_REPR(repr)                                        \
  case ValueRepresentation::k##repr:                           \
    for (int i = 0; i < input_count(); i++) {                  \
      CheckValueInputIs(this, i, ValueRepresentation::k##repr, \
                        graph_labeller);                       \
    }                                                          \
    break;

    CASE_REPR(Tagged)
    CASE_REPR(Int32)
    CASE_REPR(Uint32)
    CASE_REPR(Float64)
    CASE_REPR(HoleyFloat64)
#undef CASE_REPR
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
}

void Call::VerifyInputs(MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void Call::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void CallForwardVarargs::VerifyInputs(
    MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void CallForwardVarargs::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void CallWithArrayLike::VerifyInputs(
    MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void CallWithArrayLike::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void CallWithSpread::VerifyInputs(MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void CallWithSpread::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void CallSelf::VerifyInputs(MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void CallSelf::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void CallKnownJSFunction::VerifyInputs(
    MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void CallKnownJSFunction::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void CallKnownApiFunction::VerifyInputs(
    MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void CallKnownApiFunction::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void Construct::VerifyInputs(MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void Construct::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void ConstructWithSpread::VerifyInputs(
    MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void ConstructWithSpread::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void CallBuiltin::VerifyInputs(MaglevGraphLabeller* graph_labeller) const {
  auto descriptor = Builtins::CallInterfaceDescriptorFor(builtin());
  int count = input_count();
  // Verify context.
  if (descriptor.HasContextParameter()) {
    CheckValueInputIs(this, count - 1, ValueRepresentation::kTagged,
                      graph_labeller);
    count--;
  }

// {all_input_count} includes the feedback slot and vector.
#ifdef DEBUG
  int all_input_count = count + (has_feedback() ? 2 : 0);
  if (descriptor.AllowVarArgs()) {
    DCHECK_GE(all_input_count, descriptor.GetParameterCount());
  } else {
    DCHECK_EQ(all_input_count, descriptor.GetParameterCount());
  }
#endif
  int i = 0;
  // Check the rest of inputs.
  for (; i < count; ++i) {
    MachineType type = i < descriptor.GetParameterCount()
                           ? descriptor.GetParameterType(i)
                           : MachineType::AnyTagged();
    CheckValueInputIs(this, i, ToValueRepresentation(type), graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void CallBuiltin::MarkTaggedInputsAsDecompressing() {
  auto descriptor = Builtins::CallInterfaceDescriptorFor(builtin());
  int count = input_count();
  // Set context.
  if (descriptor.HasContextParameter()) {
    input(count - 1).node()->SetTaggedResultNeedsDecompress();
    count--;
  }
  int i = 0;
  // Set the rest of the tagged inputs.
  for (; i < count; ++i) {
    MachineType type = i < descriptor.GetParameterCount()
                           ? descriptor.GetParameterType(i)
                           : MachineType::AnyTagged();
    if (type.IsTagged() && !type.IsTaggedSigned()) {
      input(i).node()->SetTaggedResultNeedsDecompress();
    }
  }
}
#endif

void CallCPPBuiltin::VerifyInputs(MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void CallCPPBuiltin::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void CallRuntime::VerifyInputs(MaglevGraphLabeller* graph_labeller) const {
  for (int i = 0; i < input_count(); i++) {
    CheckValueInputIs(this, i, ValueRepresentation::kTagged, graph_labeller);
  }
}

#ifdef V8_COMPRESS_POINTERS
void CallRuntime::MarkTaggedInputsAsDecompressing() {
  for (int i = 0; i < input_count(); i++) {
    input(i).node()->SetTaggedResultNeedsDecompress();
  }
}
#endif

void InlinedAllocation::VerifyInputs(
    MaglevGraphLabeller* graph_labeller) const {
  Base::VerifyInputs(graph_labeller);
  CheckValueInputIs(this, 0, Opcode::kAllocationBlock, graph_labeller);
}

// ---
// Reify constants
// ---

Handle<Object> ValueNode::Reify(LocalIsolate* isolate) const {
  switch (opcode()) {
#define V(Name)         \
  case Opcode::k##Name: \
    return this->Cast<Name>()->DoReify(isolate);
    CONSTANT_VALUE_NODE_LIST(V)
#undef V
    default:
      UNREACHABLE();
  }
}

Handle<Object> ExternalConstant::DoReify(LocalIsolate* isolate) const {
  UNREACHABLE();
}

Handle<Object> SmiConstant::DoReify(LocalIsolate* isolate) const {
  return handle(value_, isolate);
}

Handle<Object> TaggedIndexConstant::DoReify(LocalIsolate* isolate) const {
  UNREACHABLE();
}

Handle<Object> Int32Constant::DoReify(LocalIsolate* isolate) const {
  return isolate->factory()->NewNumberFromInt<AllocationType::kOld>(value());
}

Handle<Object> Uint32Constant::DoReify(LocalIsolate* isolate) const {
  return isolate->factory()->NewNumberFromUint<AllocationType::kOld>(value());
}

Handle<Object> Float64Constant::DoReify(LocalIsolate* isolate) const {
  return isolate->factory()->NewNumber<AllocationType::kOld>(
      value_.get_scalar());
}

Handle<Object> Constant::DoReify(LocalIsolate* isolate) const {
  return object_.object();
}

Handle<Object> TrustedConstant::DoReify(LocalIsolate* isolate) const {
  return object_.object();
}

Handle<Object> RootConstant::DoReify(LocalIsolate* isolate) const {
  return isolate->root_handle(index());
}

#ifdef V8_ENABLE_MAGLEV

bool FromConstantToBool(MaglevAssembler* masm, ValueNode* node) {
  // TODO(leszeks): Getting the main thread local isolate is not what we
  // actually want here, but it's all we have, and it happens to work because
  // really all we're using it for is ReadOnlyRoots. We should change ToBoolean
  // to be able to pass ReadOnlyRoots in directly.
  return FromConstantToBool(masm->isolate()->AsLocalIsolate(), node);
}

// ---
// Load node to registers
// ---

namespace {
template <typename NodeT>
void LoadToRegisterHelper(NodeT* node, MaglevAssembler* masm, Register reg) {
  if constexpr (!IsDoubleRepresentation(
                    NodeT::kProperties.value_representation())) {
    return node->DoLoadToRegister(masm, reg);
  } else {
    UNREACHABLE();
  }
}
template <typename NodeT>
void LoadToRegisterHelper(NodeT* node, MaglevAssembler* masm,
                          DoubleRegister reg) {
  if constexpr (IsDoubleRepresentation(
                    NodeT::kProperties.value_representation())) {
    return node->DoLoadToRegister(masm, reg);
  } else {
    UNREACHABLE();
  }
}
}  // namespace

void ValueNode::LoadToRegister(MaglevAssembler* masm, Register reg) {
  switch (opcode()) {
#define V(Name)         \
  case Opcode::k##Name: \
    return LoadToRegisterHelper(this->Cast<Name>(), masm, reg);
    VALUE_NODE_LIST(V)
#undef V
    default:
      UNREACHABLE();
  }
}
void ValueNode::LoadToRegister(MaglevAssembler* masm, DoubleRegister reg) {
  switch (opcode()) {
#define V(Name)         \
  case Opcode::k##Name: \
    return LoadToRegisterHelper(this->Cast<Name>(), masm, reg);
    VALUE_NODE_LIST(V)
#undef V
    default:
      UNREACHABLE();
  }
}

void ValueNode::DoLoadToRegister(MaglevAssembler* masm, Register reg) {
  DCHECK(is_spilled());
  DCHECK(!use_double_register());
  __ Move(reg,
          masm->GetStackSlot(compiler::AllocatedOperand::cast(spill_slot())));
}

void ValueNode::DoLoadToRegister(MaglevAssembler* masm, DoubleRegister reg) {
  DCHECK(is_spilled());
  DCHECK(use_double_register());
  __ LoadFloat64(
      reg, masm->GetStackSlot(compiler::AllocatedOperand::cast(spill_slot())));
}

void ExternalConstant::DoLoadToRegister(MaglevAssembler* masm, Register reg) {
  __ Move(reg, reference());
}

void SmiConstant::DoLoadToRegister(MaglevAssembler* masm, Register reg) {
  __ Move(reg, value());
}

void TaggedIndexConstant::DoLoadToRegister(MaglevAssembler* masm,
                                           Register reg) {
  __ Move(reg, value());
}

void Int32Constant::DoLoadToRegister(MaglevAssembler* masm, Register reg) {
  __ Move(reg, value());
}

void Uint32Constant::DoLoadToRegister(MaglevAssembler* masm, Register reg) {
  __ Move(reg, value());
}

void Float64Constant::DoLoadToRegister(MaglevAssembler* masm,
                                       DoubleRegister reg) {
  __ Move(reg, value());
}

void Constant::DoLoadToRegister(MaglevAssembler* masm, Register reg) {
  __ Move(reg, object_.object());
}

void RootConstant::DoLoadToRegister(MaglevAssembler* masm, Register reg) {
  __ LoadRoot(reg, index());
}

void TrustedConstant::DoLoadToRegister(MaglevAssembler* masm, Register reg) {
  __ Move(reg, object_.object());
}

// ---
// Arch agnostic nodes
// ---

void ExternalConstant::SetValueLocationConstraints() { DefineAsConstant(this); }
void ExternalConstant::GenerateCode(MaglevAssembler* masm,
                                    const ProcessingState& state) {}

void SmiConstant::SetValueLocationConstraints() { DefineAsConstant(this); }
void SmiConstant::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {}

void TaggedIndexConstant::SetValueLocationConstraints() {
  DefineAsConstant(this);
}
void TaggedIndexConstant::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {}

void Int32Constant::SetValueLocationConstraints() { DefineAsConstant(this); }
void Int32Constant::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {}

void Uint32Constant::SetValueLocationConstraints() { DefineAsConstant(this); }
void Uint32Constant::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {}

void Float64Constant::SetValueLocationConstraints() { DefineAsConstant(this); }
void Float64Constant::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {}

void Constant::SetValueLocationConstraints() { DefineAsConstant(this); }
void Constant::GenerateCode(MaglevAssembler* masm,
                            const ProcessingState& state) {}

void TrustedConstant::SetValueLocationConstraints() { DefineAsConstant(this); }
void TrustedConstant::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
#ifndef V8_ENABLE_SANDBOX
  UNREACHABLE();
#endif
}

void RootConstant::SetValueLocationConstraints() { DefineAsConstant(this); }
void RootConstant::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {}

void InitialValue::SetValueLocationConstraints() {
  result().SetUnallocated(compiler::UnallocatedOperand::FIXED_SLOT,
                          stack_slot(), kNoVreg);
}
void InitialValue::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  // No-op, the value is already in the appropriate slot.
}

// static
uint32_t InitialValue::stack_slot(uint32_t register_index) {
  // TODO(leszeks): Make this nicer.
  return (StandardFrameConstants::kExpressionsOffset -
          UnoptimizedFrameConstants::kRegisterFileFromFp) /
             kSystemPointerSize +
         register_index;
}

uint32_t InitialValue::stack_slot() const {
  return stack_slot(source_.index());
}

int FunctionEntryStackCheck::MaxCallStackArgs() const { return 0; }
void FunctionEntryStackCheck::SetValueLocationConstraints() {
  set_temporaries_needed(2);
  // kReturnRegister0 should not be one of the available temporary registers.
  RequireSpecificTemporary(kReturnRegister0);
}
void FunctionEntryStackCheck::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  // Stack check. This folds the checks for both the interrupt stack limit
  // check and the real stack limit into one by just checking for the
  // interrupt limit. The interrupt limit is either equal to the real
  // stack limit or tighter. By ensuring we have space until that limit
  // after building the frame we can quickly precheck both at once.
  const int stack_check_offset = masm->code_gen_state()->stack_check_offset();
  // Only NewTarget can be live at this point.
  DCHECK_LE(register_snapshot().live_registers.Count(), 1);
  Builtin builtin =
      register_snapshot().live_tagged_registers.has(
          kJavaScriptCallNewTargetRegister)
          ? Builtin::kMaglevFunctionEntryStackCheck_WithNewTarget
          : Builtin::kMaglevFunctionEntryStackCheck_WithoutNewTarget;
  ZoneLabelRef done(masm);
  Condition cond = __ FunctionEntryStackCheck(stack_check_offset);
  if (masm->isolate()->is_short_builtin_calls_enabled()) {
    __ JumpIf(cond, *done, Label::kNear);
    __ Move(kReturnRegister0, Smi::FromInt(stack_check_offset));
    __ MacroAssembler::CallBuiltin(builtin);
    masm->DefineLazyDeoptPoint(lazy_deopt_info());
  } else {
    __ JumpToDeferredIf(
        NegateCondition(cond),
        [](MaglevAssembler* masm, ZoneLabelRef done,
           FunctionEntryStackCheck* node, Builtin builtin,
           int stack_check_offset) {
          __ Move(kReturnRegister0, Smi::FromInt(stack_check_offset));
          __ MacroAssembler::CallBuiltin(builtin);
          masm->DefineLazyDeoptPoint(node->lazy_deopt_info());
          __ Jump(*done);
        },
        done, this, builtin, stack_check_offset);
  }
  __ bind(*done);
}

void RegisterInput::SetValueLocationConstraints() {
  DefineAsFixed(this, input());
}
void RegisterInput::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  // Nothing to be done, the value is already in the register.
}

void GetSecondReturnedValue::SetValueLocationConstraints() {
  DefineAsFixed(this, kReturnRegister1);
}
void GetSecondReturnedValue::GenerateCode(MaglevAssembler* masm,
                                          const ProcessingState& state) {
  // No-op. This is just a hack that binds kReturnRegister1 to a value node.
  // kReturnRegister1 is guaranteed to be free in the register allocator, since
  // previous node in the basic block is a call.
#ifdef DEBUG
  // Check if the previous node is call.
  Node* previous = nullptr;
  for (Node* node : state.block()->nodes()) {
    if (node == this) {
      break;
    }
    previous = node;
  }
  DCHECK_NE(previous, nullptr);
  DCHECK(previous->properties().is_call());
#endif  // DEBUG
}

void Deopt::SetValueLocationConstraints() {}
void Deopt::GenerateCode(MaglevAssembler* masm, const ProcessingState& state) {
  __ EmitEagerDeopt(this, reason());
}

void Phi::SetValueLocationConstraints() {
  for (Input& input : *this) {
    UseAny(input);
  }

  // We have to pass a policy for the result, but it is ignored during register
  // allocation. See StraightForwardRegisterAllocator::AllocateRegisters which
  // has special handling for Phis.
  static const compiler::UnallocatedOperand::ExtendedPolicy kIgnoredPolicy =
      compiler::UnallocatedOperand::REGISTER_OR_SLOT_OR_CONSTANT;

  result().SetUnallocated(kIgnoredPolicy, kNoVreg);
}

void Phi::GenerateCode(MaglevAssembler* masm, const ProcessingState& state) {}

void ArgumentsElements::SetValueLocationConstraints() {
  using SloppyArgsD =
      CallInterfaceDescriptorFor<Builtin::kNewSloppyArgumentsElements>::type;
  using StrictArgsD =
      CallInterfaceDescriptorFor<Builtin::kNewStrictArgumentsElements>::type;
  using RestArgsD =
      CallInterfaceDescriptorFor<Builtin::kNewRestArgumentsElements>::type;
  static_assert(
      SloppyArgsD::GetRegisterParameter(SloppyArgsD::kArgumentCount) ==
      StrictArgsD::GetRegisterParameter(StrictArgsD::kArgumentCount));
  static_assert(
      SloppyArgsD::GetRegisterParameter(SloppyArgsD::kArgumentCount) ==
      StrictArgsD::GetRegisterParameter(RestArgsD::kArgumentCount));
  UseFixed(arguments_count_input(),
           SloppyArgsD::GetRegisterParameter(SloppyArgsD::kArgumentCount));
  DefineAsFixed(this, kReturnRegister0);
}

void ArgumentsElements::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  Register arguments_count = ToRegister(arguments_count_input());
  switch (type()) {
    case CreateArgumentsType::kMappedArguments:
      __ CallBuiltin<Builtin::kNewSloppyArgumentsElements>(
          __ GetFramePointer(), formal_parameter_count(), arguments_count);
      break;
    case CreateArgumentsType::kUnmappedArguments:
      __ CallBuiltin<Builtin::kNewStrictArgumentsElements>(
          __ GetFramePointer(), formal_parameter_count(), arguments_count);
      break;
    case CreateArgumentsType::kRestParameter:
      __ CallBuiltin<Builtin::kNewRestArgumentsElements>(
          __ GetFramePointer(), formal_parameter_count(), arguments_count);
      break;
  }
}

void AllocateElementsArray::SetValueLocationConstraints() {
  UseAndClobberRegister(length_input());
  DefineAsRegister(this);
  set_temporaries_needed(1);
}
void AllocateElementsArray::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  Register length = ToRegister(length_input());
  Register elements = ToRegister(result());
  Label allocate_elements, done;
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  // Be sure to save the length in the register snapshot.
  RegisterSnapshot snapshot = register_snapshot();
  snapshot.live_registers.set(length);

  // Return empty fixed array if length equal zero.
  __ CompareInt32AndJumpIf(length, 0, kNotEqual, &allocate_elements,
                           Label::Distance::kNear);
  __ LoadRoot(elements, RootIndex::kEmptyFixedArray);
  __ Jump(&done);

  // Allocate a fixed array object.
  __ bind(&allocate_elements);
  __ CompareInt32AndJumpIf(
      length, JSArray::kInitialMaxFastElementArray, kGreaterThanEqual,
      __ GetDeoptLabel(this,
                       DeoptimizeReason::kGreaterThanMaxFastElementArray));
  {
    Register size_in_bytes = scratch;
    __ Move(size_in_bytes, length);
    __ ShiftLeft(size_in_bytes, kTaggedSizeLog2);
    __ AddInt32(size_in_bytes, OFFSET_OF_DATA_START(FixedArray));
    __ Allocate(snapshot, elements, size_in_bytes, allocation_type_);
    __ SetMapAsRoot(elements, RootIndex::kFixedArrayMap);
  }
  {
    Register smi_length = scratch;
    __ UncheckedSmiTagInt32(smi_length, length);
    __ StoreTaggedFieldNoWriteBarrier(elements, offsetof(FixedArray, length_),
                                      smi_length);
  }

  // Initialize the array with holes.
  {
    Label loop;
    Register the_hole = scratch;
    __ LoadTaggedRoot(the_hole, RootIndex::kTheHoleValue);
    __ bind(&loop);
    __ DecrementInt32(length);
    // TODO(victorgomes): This can be done more efficiently  by have the root
    // (the_hole) as an immediate in the store.
    __ StoreFixedArrayElementNoWriteBarrier(elements, length, the_hole);
    __ CompareInt32AndJumpIf(length, 0, kGreaterThan, &loop,
                             Label::Distance::kNear);
  }
  __ bind(&done);
}

namespace {

constexpr Builtin BuiltinFor(Operation operation) {
  switch (operation) {
#define CASE(name)         \
  case Operation::k##name: \
    return Builtin::k##name##_WithFeedback;
    OPERATION_LIST(CASE)
#undef CASE
  }
}

}  // namespace

template <class Derived, Operation kOperation>
void UnaryWithFeedbackNode<Derived, kOperation>::SetValueLocationConstraints() {
  using D = UnaryOp_WithFeedbackDescriptor;
  UseFixed(operand_input(), D::GetRegisterParameter(D::kValue));
  DefineAsFixed(this, kReturnRegister0);
}

template <class Derived, Operation kOperation>
void UnaryWithFeedbackNode<Derived, kOperation>::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  __ CallBuiltin<BuiltinFor(kOperation)>(
      masm->native_context().object(),  // context
      operand_input(),                  // value
      feedback().index(),               // feedback slot
      feedback().vector                 // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

template <class Derived, Operation kOperation>
void BinaryWithFeedbackNode<Derived,
                            kOperation>::SetValueLocationConstraints() {
  using D = BinaryOp_WithFeedbackDescriptor;
  UseFixed(left_input(), D::GetRegisterParameter(D::kLeft));
  UseFixed(right_input(), D::GetRegisterParameter(D::kRight));
  DefineAsFixed(this, kReturnRegister0);
}

template <class Derived, Operation kOperation>
void BinaryWithFeedbackNode<Derived, kOperation>::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  __ CallBuiltin<BuiltinFor(kOperation)>(
      masm->native_context().object(),  // context
      left_input(),                     // left
      right_input(),                    // right
      feedback().index(),               // feedback slot
      feedback().vector                 // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

#define DEF_OPERATION(Name)                               \
  void Name::SetValueLocationConstraints() {              \
    Base::SetValueLocationConstraints();                  \
  }                                                       \
  void Name::GenerateCode(MaglevAssembler* masm,          \
                          const ProcessingState& state) { \
    Base::GenerateCode(masm, state);                      \
  }
GENERIC_OPERATIONS_NODE_LIST(DEF_OPERATION)
#undef DEF_OPERATION

void ConstantGapMove::SetValueLocationConstraints() { UNREACHABLE(); }

namespace {
template <typename T>
struct GetRegister;
template <>
struct GetRegister<Register> {
  static Register Get(compiler::AllocatedOperand target) {
    return target.GetRegister();
  }
};
template <>
struct GetRegister<DoubleRegister> {
  static DoubleRegister Get(compiler::AllocatedOperand target) {
    return target.GetDoubleRegister();
  }
};
}  // namespace

void ConstantGapMove::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  switch (node_->opcode()) {
#define CASE(Name)                                \
  case Opcode::k##Name:                           \
    return node_->Cast<Name>()->DoLoadToRegister( \
        masm, GetRegister<Name::OutputRegister>::Get(target()));
    CONSTANT_VALUE_NODE_LIST(CASE)
#undef CASE
    default:
      UNREACHABLE();
  }
}

void GapMove::SetValueLocationConstraints() { UNREACHABLE(); }
void GapMove::GenerateCode(MaglevAssembler* masm,
                           const ProcessingState& state) {
  DCHECK_EQ(source().representation(), target().representation());
  MachineRepresentation repr = source().representation();
  if (source().IsRegister()) {
    Register source_reg = ToRegister(source());
    if (target().IsAnyRegister()) {
      DCHECK(target().IsRegister());
      __ MoveRepr(repr, ToRegister(target()), source_reg);
    } else {
      __ MoveRepr(repr, masm->ToMemOperand(target()), source_reg);
    }
  } else if (source().IsDoubleRegister()) {
    DoubleRegister source_reg = ToDoubleRegister(source());
    if (target().IsAnyRegister()) {
      DCHECK(target().IsDoubleRegister());
      __ Move(ToDoubleRegister(target()), source_reg);
    } else {
      __ StoreFloat64(masm->ToMemOperand(target()), source_reg);
    }
  } else {
    DCHECK(source().IsAnyStackSlot());
    MemOperand source_op = masm->ToMemOperand(source());
    if (target().IsRegister()) {
      __ MoveRepr(MachineRepresentation::kTaggedPointer, ToRegister(target()),
                  source_op);
    } else if (target().IsDoubleRegister()) {
      __ LoadFloat64(ToDoubleRegister(target()), source_op);
    } else {
      DCHECK(target().IsAnyStackSlot());
      DCHECK_EQ(ElementSizeInBytes(repr), kSystemPointerSize);
      __ MoveRepr(repr, masm->ToMemOperand(target()), source_op);
    }
  }
}

void AssertInt32::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
}
void AssertInt32::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  __ CompareInt32AndAssert(ToRegister(left_input()), ToRegister(right_input()),
                           ToCondition(condition_), reason_);
}

void CheckUint32IsSmi::SetValueLocationConstraints() { UseRegister(input()); }
void CheckUint32IsSmi::GenerateCode(MaglevAssembler* masm,
                                    const ProcessingState& state) {
  Register reg = ToRegister(input());
  // Perform an unsigned comparison against Smi::kMaxValue.
  __ CompareUInt32AndEmitEagerDeoptIf(reg, Smi::kMaxValue, kUnsignedGreaterThan,
                                      DeoptimizeReason::kNotASmi, this);
}

void CheckedSmiUntag::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}

void CheckedSmiUntag::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register value = ToRegister(input());
  // TODO(leszeks): Consider optimizing away this test and using the carry bit
  // of the `sarl` for cases where the deopt uses the value from a different
  // register.
  __ EmitEagerDeoptIfNotSmi(this, value, DeoptimizeReason::kNotASmi);
  __ SmiToInt32(value);
}

void UnsafeSmiUntag::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}

void UnsafeSmiUntag::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  Register value = ToRegister(input());
  __ AssertSmi(value);
  __ SmiToInt32(value);
}

void CheckInt32IsSmi::SetValueLocationConstraints() { UseRegister(input()); }
void CheckInt32IsSmi::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  // We shouldn't be emitting this node for 32-bit Smis.
  DCHECK(!SmiValuesAre32Bits());

  // TODO(leszeks): This basically does a SmiTag and throws the result away.
  // Don't throw the result away if we want to actually use it.
  Register reg = ToRegister(input());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kNotASmi);
  __ CheckInt32IsSmi(reg, fail);
}

void CheckedInt32ToUint32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void CheckedInt32ToUint32::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  __ CompareInt32AndJumpIf(
      ToRegister(input()), 0, kLessThan,
      __ GetDeoptLabel(this, DeoptimizeReason::kNotUint32));
}

void UnsafeInt32ToUint32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void UnsafeInt32ToUint32::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {}

void CheckHoleyFloat64IsSmi::SetValueLocationConstraints() {
  UseRegister(input());
  set_temporaries_needed(1);
}
void CheckHoleyFloat64IsSmi::GenerateCode(MaglevAssembler* masm,
                                          const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kNotASmi);
  __ TryTruncateDoubleToInt32(scratch, value, fail);
  if (!SmiValuesAre32Bits()) {
    __ CheckInt32IsSmi(scratch, fail, scratch);
  }
}

void CheckedSmiTagInt32::SetValueLocationConstraints() {
  UseAndClobberRegister(input());
  DefineSameAsFirst(this);
}
void CheckedSmiTagInt32::GenerateCode(MaglevAssembler* masm,
                                      const ProcessingState& state) {
  Register reg = ToRegister(input());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kNotASmi);
  // None of the mutated input registers should be a register input into the
  // eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{reg} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ SmiTagInt32AndJumpIfFail(reg, fail);
}

void CheckedSmiSizedInt32::SetValueLocationConstraints() {
  UseAndClobberRegister(input());
  DefineSameAsFirst(this);
}
void CheckedSmiSizedInt32::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  // We shouldn't be emitting this node for 32-bit Smis.
  DCHECK(!SmiValuesAre32Bits());

  Register reg = ToRegister(input());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kNotASmi);
  __ CheckInt32IsSmi(reg, fail);
}

void CheckedSmiTagUint32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void CheckedSmiTagUint32::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  Register reg = ToRegister(input());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kNotASmi);
  // None of the mutated input registers should be a register input into the
  // eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{reg} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ SmiTagUint32AndJumpIfFail(reg, fail);
}

void UnsafeSmiTagInt32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void UnsafeSmiTagInt32::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  __ UncheckedSmiTagInt32(ToRegister(input()));
}

void UnsafeSmiTagUint32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void UnsafeSmiTagUint32::GenerateCode(MaglevAssembler* masm,
                                      const ProcessingState& state) {
  __ UncheckedSmiTagUint32(ToRegister(input()));
}

void CheckedSmiIncrement::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineSameAsFirst(this);
}

void CheckedSmiIncrement::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  Label* deopt_label = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ SmiAddConstant(ToRegister(value_input()), 1, deopt_label);
}

void CheckedSmiDecrement::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineSameAsFirst(this);
}

void CheckedSmiDecrement::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  Label* deopt_label = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ SmiSubConstant(ToRegister(value_input()), 1, deopt_label);
}

namespace {

void JumpToFailIfNotHeapNumberOrOddball(
    MaglevAssembler* masm, Register value,
    TaggedToFloat64ConversionType conversion_type, Label* fail) {
  if (!fail && !v8_flags.debug_code) return;

  static_assert(InstanceType::HEAP_NUMBER_TYPE + 1 ==
                InstanceType::ODDBALL_TYPE);
  switch (conversion_type) {
    case TaggedToFloat64ConversionType::kNumberOrBoolean: {
      // Check if HeapNumber or Boolean, jump to fail otherwise.
      MaglevAssembler::TemporaryRegisterScope temps(masm);
      Register map = temps.AcquireScratch();

#if V8_STATIC_ROOTS_BOOL
      static_assert(StaticReadOnlyRoot::kBooleanMap + Map::kSize ==
                    StaticReadOnlyRoot::kHeapNumberMap);
      __ LoadMapForCompare(map, value);
      if (fail) {
        __ JumpIfObjectNotInRange(map, StaticReadOnlyRoot::kBooleanMap,
                                  StaticReadOnlyRoot::kHeapNumberMap, fail);
      } else {
        __ AssertObjectInRange(map, StaticReadOnlyRoot::kBooleanMap,
                               StaticReadOnlyRoot::kHeapNumberMap,
                               AbortReason::kUnexpectedValue);
      }
#else
      Label done;
      __ LoadMap(map, value);
      __ CompareRoot(map, RootIndex::kHeapNumberMap);
      __ JumpIf(kEqual, &done);
      __ CompareRoot(map, RootIndex::kBooleanMap);
      if (fail) {
        __ JumpIf(kNotEqual, fail);
      } else {
        __ Assert(kEqual, AbortReason::kUnexpectedValue);
      }
      __ bind(&done);
#endif
      break;
    }
    case TaggedToFloat64ConversionType::kNumberOrOddball:
      // Check if HeapNumber or Oddball, jump to fail otherwise.
      if (fail) {
        __ JumpIfObjectTypeNotInRange(value, InstanceType::HEAP_NUMBER_TYPE,
                                      InstanceType::ODDBALL_TYPE, fail);
      } else {
        __ AssertObjectTypeInRange(value, InstanceType::HEAP_NUMBER_TYPE,
                                   InstanceType::ODDBALL_TYPE,
                                   AbortReason::kUnexpectedValue);
      }
      break;
    case TaggedToFloat64ConversionType::kOnlyNumber:
      // Check if HeapNumber, jump to fail otherwise.
      if (fail) {
        __ JumpIfNotObjectType(value, InstanceType::HEAP_NUMBER_TYPE, fail);
      } else {
        __ AssertObjectType(value, InstanceType::HEAP_NUMBER_TYPE,
                            AbortReason::kUnexpectedValue);
      }
      break;
  }
}

void TryUnboxNumberOrOddball(MaglevAssembler* masm, DoubleRegister dst,
                             Register clobbered_src,
                             TaggedToFloat64ConversionType conversion_type,
                             Label* fail) {
  Label is_not_smi, done;
  // Check if Smi.
  __ JumpIfNotSmi(clobbered_src, &is_not_smi, Label::kNear);
  // If Smi, convert to Float64.
  __ SmiToInt32(clobbered_src);
  __ Int32ToDouble(dst, clobbered_src);
  __ Jump(&done);
  __ bind(&is_not_smi);
  JumpToFailIfNotHeapNumberOrOddball(masm, clobbered_src, conversion_type,
                                     fail);
  __ LoadHeapNumberOrOddballValue(dst, clobbered_src);
  __ bind(&done);
}

}  // namespace
template <typename Derived, ValueRepresentation FloatType>
  requires(FloatType == ValueRepresentation::kFloat64 ||
           FloatType == ValueRepresentation::kHoleyFloat64)
void CheckedNumberOrOddballToFloat64OrHoleyFloat64<
    Derived, FloatType>::SetValueLocationConstraints() {
  UseAndClobberRegister(input());
  DefineAsRegister(this);
}
template <typename Derived, ValueRepresentation FloatType>
  requires(FloatType == ValueRepresentation::kFloat64 ||
           FloatType == ValueRepresentation::kHoleyFloat64)
void CheckedNumberOrOddballToFloat64OrHoleyFloat64<
    Derived, FloatType>::GenerateCode(MaglevAssembler* masm,
                                      const ProcessingState& state) {
  Register value = ToRegister(input());
  TryUnboxNumberOrOddball(masm, ToDoubleRegister(result()), value,
                          conversion_type(),
                          __ GetDeoptLabel(this, deoptimize_reason()));
}

void UncheckedNumberOrOddballToFloat64::SetValueLocationConstraints() {
  UseAndClobberRegister(input());
  DefineAsRegister(this);
}
void UncheckedNumberOrOddballToFloat64::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  Register value = ToRegister(input());
  TryUnboxNumberOrOddball(masm, ToDoubleRegister(result()), value,
                          conversion_type(), nullptr);
}

namespace {

void EmitTruncateNumberOrOddballToInt32(
    MaglevAssembler* masm, Register value, Register result_reg,
    TaggedToFloat64ConversionType conversion_type, Label* not_a_number) {
  Label is_not_smi, done;
  // Check if Smi.
  __ JumpIfNotSmi(value, &is_not_smi, Label::kNear);
  // If Smi, convert to Int32.
  __ SmiToInt32(value);
  __ Jump(&done, Label::kNear);
  __ bind(&is_not_smi);
  JumpToFailIfNotHeapNumberOrOddball(masm, value, conversion_type,
                                     not_a_number);
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  DoubleRegister double_value = temps.AcquireScratchDouble();
  __ LoadHeapNumberOrOddballValue(double_value, value);
  __ TruncateDoubleToInt32(result_reg, double_value);
  __ bind(&done);
}

}  // namespace

void CheckedObjectToIndex::SetValueLocationConstraints() {
  UseRegister(object_input());
  DefineAsRegister(this);
  set_double_temporaries_needed(1);
}
void CheckedObjectToIndex::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register object = ToRegister(object_input());
  Register result_reg = ToRegister(result());
  ZoneLabelRef done(masm);
  __ JumpIfNotSmi(
      object,
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, Register object, Register result_reg,
             ZoneLabelRef done, CheckedObjectToIndex* node) {
            MaglevAssembler::TemporaryRegisterScope temps(masm);
            Register map = temps.AcquireScratch();
            Label check_string;
            __ LoadMapForCompare(map, object);
            __ JumpIfNotRoot(
                map, RootIndex::kHeapNumberMap, &check_string,
                v8_flags.deopt_every_n_times > 0 ? Label::kFar : Label::kNear);
            {
              DoubleRegister number_value = temps.AcquireDouble();
              __ LoadHeapNumberValue(number_value, object);
              __ TryChangeFloat64ToIndex(
                  result_reg, number_value, *done,
                  __ GetDeoptLabel(node, DeoptimizeReason::kNotInt32));
            }
            __ bind(&check_string);
            // The IC will go generic if it encounters something other than a
            // Number or String key.
            __ JumpIfStringMap(
                map, __ GetDeoptLabel(node, DeoptimizeReason::kNotInt32),
                Label::kFar, false);
            // map is clobbered after this call.

            {
              // TODO(verwaest): Load the cached number from the string hash.
              RegisterSnapshot snapshot = node->register_snapshot();
              snapshot.live_registers.clear(result_reg);
              DCHECK(!snapshot.live_tagged_registers.has(result_reg));
              {
                SaveRegisterStateForCall save_register_state(masm, snapshot);
                AllowExternalCallThatCantCauseGC scope(masm);
                __ PrepareCallCFunction(1);
                __ Move(kCArgRegs[0], object);
                __ CallCFunction(
                    ExternalReference::string_to_array_index_function(), 1);
                // No need for safepoint since this is a fast C call.
                __ Move(result_reg, kReturnRegister0);
              }
              __ CompareInt32AndJumpIf(
                  result_reg, 0, kLessThan,
                  __ GetDeoptLabel(node, DeoptimizeReason::kNotInt32));
              __ Jump(*done);
            }
          },
          object, result_reg, done, this));

  // If we didn't enter the deferred block, we're a Smi.
  __ SmiToInt32(result_reg, object);
  __ bind(*done);
}

void CheckedTruncateNumberOrOddballToInt32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void CheckedTruncateNumberOrOddballToInt32::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  Register value = ToRegister(input());
  Register result_reg = ToRegister(result());
  DCHECK_EQ(value, result_reg);
  Label* deopt_label =
      __ GetDeoptLabel(this, DeoptimizeReason::kNotANumberOrOddball);
  EmitTruncateNumberOrOddballToInt32(masm, value, result_reg, conversion_type(),
                                     deopt_label);
}

void TruncateNumberOrOddballToInt32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void TruncateNumberOrOddballToInt32::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  Register value = ToRegister(input());
  Register result_reg = ToRegister(result());
  DCHECK_EQ(value, result_reg);
  EmitTruncateNumberOrOddballToInt32(masm, value, result_reg, conversion_type(),
                                     nullptr);
}

void ChangeInt32ToFloat64::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void ChangeInt32ToFloat64::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  __ Int32ToDouble(ToDoubleRegister(result()), ToRegister(input()));
}

void ChangeUint32ToFloat64::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void ChangeUint32ToFloat64::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  __ Uint32ToDouble(ToDoubleRegister(result()),
"""


```