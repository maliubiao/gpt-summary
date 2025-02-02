Response: The user has provided the first part of a C++ source code file and asked for a summary of its functionality.

The file `v8/src/compiler/turboshaft/graph-builder.cc` seems to be responsible for building a graph representation within the Turboshaft compiler. This process likely involves traversing an existing intermediate representation (IR) and converting it into the Turboshaft graph structure.

Key aspects to consider based on the included headers and code:

*   **Graph Representation:** The code interacts with `src/compiler/turboshaft/graph.h` and `src/compiler/turboshaft/operations.h`, indicating that it constructs the Turboshaft graph, likely composed of nodes representing operations.
*   **Schedule Processing:** The inclusion of `src/compiler/schedule.h` and the presence of `Schedule& schedule` in the `GraphBuilder` class suggest that the graph construction is driven by a schedule, which defines the order of basic blocks and nodes to process.
*   **IR Node Mapping:** The `op_mapping` and `block_mapping` suggest a mechanism to map nodes and basic blocks from the original IR to the newly constructed Turboshaft graph.
*   **Assembler Integration:** The `TSAssembler` suggests the involvement of an assembler-like component for emitting low-level instructions or operations within the graph.
*   **Deoptimization Handling:**  The presence of `src/compiler/turboshaft/deopt-data.h` and the `ProcessDeoptInput` function indicate logic for handling deoptimization scenarios, potentially capturing the state needed for reverting to an interpreter.
*   **Control Flow Handling:** The `BlockKind` function and the processing of control flow instructions like `Branch` and `Switch` point to the graph builder's role in constructing the control flow structure of the Turboshaft graph.
*   **Operator Processing:** The `Process` function, which handles various `IrOpcode` values, is the core of the graph construction logic, translating individual IR operations into Turboshaft operations.
*   **JavaScript Interaction:** The presence of headers like `src/objects/js-objects.h` and the handling of specific JavaScript-related opcodes (like `kCall`, `kReturn`, object property access, and type conversions) suggest a connection to the execution of JavaScript code.

Therefore, the primary function of this part of the code is to **take a scheduled intermediate representation (likely from TurboFan) and build a corresponding graph representation within the Turboshaft compiler framework.** This involves mapping IR nodes and blocks to Turboshaft operations and blocks, handling control flow, and managing deoptimization information. It directly relates to the compilation and optimization of JavaScript code within the V8 engine.
这是 C++ 源代码文件 `v8/src/compiler/turboshaft/graph-builder.cc` 的第一部分，它的主要功能是 **将 TurboFan 的调度图 (Schedule) 转换为 Turboshaft 的图表示 (Graph)**。

更具体地说，这个文件的代码定义了一个 `GraphBuilder` 类，它的作用是遍历 TurboFan 的调度器输出的指令序列（以基本块的形式），并为每个操作和控制流结构在 Turboshaft 的图结构中创建相应的节点。

以下是其功能的详细归纳：

*   **构建 Turboshaft 图:**  `GraphBuilder` 负责创建 Turboshaft 的 `Graph` 对象，其中包含表示计算步骤的 `Operation` 节点和表示控制流的 `Block` 节点。
*   **处理 TurboFan 调度:** 它接收一个 `Schedule` 对象作为输入，该对象定义了基本块的顺序和每个块中节点的顺序。`GraphBuilder` 按照这个顺序处理基本块和节点。
*   **映射 TurboFan 节点到 Turboshaft 操作:**  `Process` 函数是核心，它根据 TurboFan 节点的 `IrOpcode` 创建相应的 Turboshaft `Operation` 对象。例如，TurboFan 的 `kInt32Add` 会被映射到 Turboshaft 的 `Word32AddOp`。
*   **处理控制流:**  `GraphBuilder` 负责创建 Turboshaft 的 `Block` 对象来表示控制流的基本块，并处理如 `kGoto`、`kBranch` 和 `kSwitch` 等控制流操作。
*   **处理 Phi 节点:**  它能够处理 TurboFan 的 `kPhi` 节点，创建 Turboshaft 的 `PhiOp` 来表示不同控制流路径上的值合并。
*   **处理框架状态 (Frame State):**  `GraphBuilder` 能够处理 TurboFan 的 `kFrameState` 节点，创建 Turboshaft 的 `FrameStateOp`，用于支持去优化 (deoptimization)。
*   **处理去优化:**  它包含了处理去优化指令 (`kDeoptimizeIf`, `kDeoptimizeUnless`, `kDeoptimize`) 的逻辑，将 TurboFan 的去优化信息转换为 Turboshaft 的表示。
*   **处理调用 (Call) 和尾调用 (Tail Call):**  能够将 TurboFan 的 `kCall` 和 `kTailCall` 节点转换为 Turboshaft 的 `CallOp` 和 `TailCallOp`.
*   **处理内存操作 (Load/Store):**  `GraphBuilder` 可以将 TurboFan 的 `kLoad` 和 `kStore` 操作转换为 Turboshaft 的 `LoadOp` 和 `StoreOp`。
*   **处理常量:**  能够处理各种类型的常量，如整数、浮点数、堆对象等，创建相应的 Turboshaft 常量操作。
*   **处理类型转换:**  包含了将 TurboFan 的类型转换操作转换为 Turboshaft 对应操作的逻辑。
*   **可选的源码位置和节点起源信息:** 可以记录每个 Turboshaft 操作对应的 TurboFan 源码位置和节点起源信息。

**与 JavaScript 的关系：**

Turboshaft 是 V8 JavaScript 引擎的下一代编译器。因此，`graph-builder.cc` 的功能直接关系到 JavaScript 代码的编译和优化。

**JavaScript 例子：**

假设有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个函数时，TurboFan 可能会生成一个包含以下操作的调度图（简化版）：

1. `Parameter` (表示参数 `a`)
2. `Parameter` (表示参数 `b`)
3. `NumberAdd` (表示加法操作 `a + b`)
4. `Return` (表示返回结果)

`graph-builder.cc` 的 `GraphBuilder` 类会读取这个调度图，并在 Turboshaft 的图结构中创建相应的节点：

1. `ParameterOp` (对应参数 `a`)
2. `ParameterOp` (对应参数 `b`)
3. `Float64AddOp` 或 `Word32AddOp` (根据 `a` 和 `b` 的类型，对应加法操作)
4. `ReturnOp` (对应返回操作)

**更复杂的例子：**

```javascript
function compare(x) {
  if (x > 10) {
    return "greater";
  } else {
    return "not greater";
  }
}
```

TurboFan 的调度图可能包含：

1. `Parameter` (表示参数 `x`)
2. `NumberConstant` (表示常量 `10`)
3. `NumberGreaterThan` (表示比较操作 `x > 10`)
4. `IfTrue` (如果比较结果为真)
5. `Return` (返回 "greater")
6. `IfFalse` (如果比较结果为假)
7. `Return` (返回 "not greater")

`graph-builder.cc` 会将其转换为 Turboshaft 图，其中可能包含：

1. `ParameterOp`
2. `Float64ConstantOp` 或 `SmiConstantOp`
3. `Float64GreaterThanOp` 或 `Int32GreaterThanOp`
4. `BranchOp` (根据比较结果跳转到不同的 `Block`)
5. 两个不同的 `Block`，每个包含一个 `HeapConstantOp` (表示字符串 "greater" 或 "not greater") 和一个 `ReturnOp`。

总而言之，`graph-builder.cc` 是将 TurboFan 的中间表示转换为 Turboshaft 可以理解和进一步优化的表示的关键组件，它直接影响了 JavaScript 代码的最终执行效率。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turboshaft/graph-builder.h"

#include <limits>
#include <numeric>
#include <optional>
#include <string_view>

#include "src/base/container-utils.h"
#include "src/base/logging.h"
#include "src/base/safe_conversions.h"
#include "src/base/small-vector.h"
#include "src/base/vector.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/machine-type.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/fast-api-calls.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-aux-data.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-origin-table.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator.h"
#include "src/compiler/schedule.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/state-values-utils.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/deopt-data.h"
#include "src/compiler/turboshaft/explicit-truncation-reducer.h"
#include "src/compiler/turboshaft/graph.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/compiler/turboshaft/variable-reducer.h"
#include "src/flags/flags.h"
#include "src/heap/factory-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/map.h"
#include "src/zone/zone-containers.h"

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

namespace {

struct GraphBuilder {
  Zone* phase_zone;
  Schedule& schedule;
  Linkage* linkage;

  Isolate* isolate;
  JSHeapBroker* broker;
  Zone* graph_zone;
  using AssemblerT = TSAssembler<ExplicitTruncationReducer, VariableReducer>;
  AssemblerT assembler;
  SourcePositionTable* source_positions;
  NodeOriginTable* origins;
  JsWasmCallsSidetable* js_wasm_calls_sidetable;
  TurboshaftPipelineKind pipeline_kind;

  GraphBuilder(PipelineData* data, Zone* phase_zone, Schedule& schedule,
               Linkage* linkage, JsWasmCallsSidetable* js_wasm_calls_sidetable)
      : phase_zone(phase_zone),
        schedule(schedule),
        linkage(linkage),
        isolate(data->isolate()),
        broker(data->broker()),
        graph_zone(data->graph_zone()),
        assembler(data, data->graph(), data->graph(), phase_zone),
        source_positions(data->source_positions()),
        origins(data->node_origins()),
        js_wasm_calls_sidetable(js_wasm_calls_sidetable),
        pipeline_kind(data->pipeline_kind()) {}

  struct BlockData {
    Block* block;
    OpIndex final_frame_state;
  };
  NodeAuxData<OpIndex> op_mapping{phase_zone};
  ZoneVector<BlockData> block_mapping{schedule.RpoBlockCount(), phase_zone};
  bool inside_region = false;

  std::optional<BailoutReason> Run();
  AssemblerT& Asm() { return assembler; }

 private:
  template <typename T>
  V<T> Map(Node* old_node) {
    V<T> result = V<T>::Cast(op_mapping.Get(old_node));
    DCHECK(__ output_graph().IsValid(result));
    return result;
  }

  OpIndex Map(Node* old_node) {
    OpIndex result = op_mapping.Get(old_node);
    DCHECK(__ output_graph().IsValid(result));
    return result;
  }

  Block* Map(BasicBlock* block) {
    Block* result = block_mapping[block->rpo_number()].block;
    DCHECK_NOT_NULL(result);
    return result;
  }

  void FixLoopPhis(BasicBlock* loop) {
    DCHECK(loop->IsLoopHeader());
    for (Node* node : *loop->nodes()) {
      if (node->opcode() != IrOpcode::kPhi) {
        continue;
      }
      OpIndex phi_index = Map(node);
      PendingLoopPhiOp& pending_phi =
          __ output_graph().Get(phi_index).Cast<PendingLoopPhiOp>();
      __ output_graph().Replace<PhiOp>(
          phi_index,
          base::VectorOf({pending_phi.first(), Map(node->InputAt(1))}),
          pending_phi.rep);
    }
  }

  void ProcessDeoptInput(FrameStateData::Builder* builder, Node* input,
                         MachineType type) {
    DCHECK_NE(input->opcode(), IrOpcode::kObjectState);
    DCHECK_NE(input->opcode(), IrOpcode::kStateValues);
    DCHECK_NE(input->opcode(), IrOpcode::kTypedStateValues);
    if (input->opcode() == IrOpcode::kObjectId) {
      builder->AddDematerializedObjectReference(ObjectIdOf(input->op()));
    } else if (input->opcode() == IrOpcode::kTypedObjectState) {
      const TypedObjectStateInfo& info =
          OpParameter<TypedObjectStateInfo>(input->op());
      int field_count = input->op()->ValueInputCount();
      builder->AddDematerializedObject(info.object_id(),
                                       static_cast<uint32_t>(field_count));
      for (int i = 0; i < field_count; ++i) {
        ProcessDeoptInput(builder, input->InputAt(i),
                          (*info.machine_types())[i]);
      }
    } else if (input->opcode() == IrOpcode::kArgumentsElementsState) {
      builder->AddArgumentsElements(ArgumentsStateTypeOf(input->op()));
    } else if (input->opcode() == IrOpcode::kArgumentsLengthState) {
      builder->AddArgumentsLength();
    } else {
      builder->AddInput(type, Map(input));
    }
  }

  void ProcessStateValues(FrameStateData::Builder* builder,
                          Node* state_values) {
    for (auto it = StateValuesAccess(state_values).begin(); !it.done(); ++it) {
      if (Node* node = it.node()) {
        ProcessDeoptInput(builder, node, (*it).type);
      } else {
        builder->AddUnusedRegister();
      }
    }
  }

  void BuildFrameStateData(FrameStateData::Builder* builder,
                           compiler::FrameState frame_state) {
    if (frame_state.outer_frame_state()->opcode() != IrOpcode::kStart) {
      builder->AddParentFrameState(Map(frame_state.outer_frame_state()));
    }
    ProcessDeoptInput(builder, frame_state.function(),
                      MachineType::AnyTagged());
    ProcessStateValues(builder, frame_state.parameters());
    ProcessDeoptInput(builder, frame_state.context(), MachineType::AnyTagged());
    ProcessStateValues(builder, frame_state.locals());
    Node* stack = frame_state.stack();
    ProcessStateValues(builder, stack);
  }

  Block::Kind BlockKind(BasicBlock* block) {
    switch (block->front()->opcode()) {
      case IrOpcode::kStart:
      case IrOpcode::kEnd:
      case IrOpcode::kMerge:
        return Block::Kind::kMerge;
      case IrOpcode::kIfTrue:
      case IrOpcode::kIfFalse:
      case IrOpcode::kIfValue:
      case IrOpcode::kIfDefault:
      case IrOpcode::kIfSuccess:
      case IrOpcode::kIfException:
        return Block::Kind::kBranchTarget;
      case IrOpcode::kLoop:
        return Block::Kind::kLoopHeader;
      default:
        block->front()->Print();
        UNIMPLEMENTED();
    }
  }
  OpIndex Process(Node* node, BasicBlock* block,
                  const base::SmallVector<int, 16>& predecessor_permutation,
                  OpIndex& dominating_frame_state,
                  std::optional<BailoutReason>* bailout,
                  bool is_final_control = false);
};

std::optional<BailoutReason> GraphBuilder::Run() {
  for (BasicBlock* block : *schedule.rpo_order()) {
    block_mapping[block->rpo_number()].block =
        block->IsLoopHeader() ? __ NewLoopHeader() : __ NewBlock();
  }

  for (BasicBlock* block : *schedule.rpo_order()) {
    Block* target_block = Map(block);
    if (!__ Bind(target_block)) continue;

    // Since we visit blocks in rpo-order, the new block predecessors are sorted
    // in rpo order too. However, the input schedule does not order
    // predecessors, so we have to apply a corresponding permutation to phi
    // inputs.
    const BasicBlockVector& predecessors = block->predecessors();
    base::SmallVector<int, 16> predecessor_permutation(predecessors.size());
    std::iota(predecessor_permutation.begin(), predecessor_permutation.end(),
              0);
    std::sort(predecessor_permutation.begin(), predecessor_permutation.end(),
              [&](size_t i, size_t j) {
                return predecessors[i]->rpo_number() <
                       predecessors[j]->rpo_number();
              });

    OpIndex dominating_frame_state = OpIndex::Invalid();
    if (!predecessors.empty()) {
      dominating_frame_state =
          block_mapping[predecessors[0]->rpo_number()].final_frame_state;
      for (size_t i = 1; i < predecessors.size(); ++i) {
        if (block_mapping[predecessors[i]->rpo_number()].final_frame_state !=
            dominating_frame_state) {
          dominating_frame_state = OpIndex::Invalid();
          break;
        }
      }
    }
    std::optional<BailoutReason> bailout = std::nullopt;
    for (Node* node : *block->nodes()) {
      if (V8_UNLIKELY(node->InputCount() >=
                      int{std::numeric_limits<
                          decltype(Operation::input_count)>::max()})) {
        return BailoutReason::kTooManyArguments;
      }
      OpIndex i = Process(node, block, predecessor_permutation,
                          dominating_frame_state, &bailout);
      if (V8_UNLIKELY(bailout)) return bailout;
      if (!__ current_block()) break;
      op_mapping.Set(node, i);
    }
    // We have terminated this block with `Unreachable`, so we stop generation
    // here and continue with the next block.
    if (!__ current_block()) continue;

    if (Node* node = block->control_input()) {
      if (V8_UNLIKELY(node->InputCount() >=
                      int{std::numeric_limits<
                          decltype(Operation::input_count)>::max()})) {
        return BailoutReason::kTooManyArguments;
      }
      OpIndex i = Process(node, block, predecessor_permutation,
                          dominating_frame_state, &bailout, true);
      if (V8_UNLIKELY(bailout)) return bailout;
      op_mapping.Set(node, i);
    }
    switch (block->control()) {
      case BasicBlock::kGoto: {
        DCHECK_EQ(block->SuccessorCount(), 1);
        Block* destination = Map(block->SuccessorAt(0));
        __ Goto(destination);
        if (destination->IsBound()) {
          DCHECK(destination->IsLoop());
          FixLoopPhis(block->SuccessorAt(0));
        }
        break;
      }
      case BasicBlock::kBranch:
      case BasicBlock::kSwitch:
      case BasicBlock::kReturn:
      case BasicBlock::kDeoptimize:
      case BasicBlock::kThrow:
      case BasicBlock::kCall:
      case BasicBlock::kTailCall:
        break;
      case BasicBlock::kNone:
        UNREACHABLE();
    }
    DCHECK_NULL(__ current_block());

    block_mapping[block->rpo_number()].final_frame_state =
        dominating_frame_state;
  }

  if (source_positions->IsEnabled()) {
    for (OpIndex index : __ output_graph().AllOperationIndices()) {
      compiler::NodeId origin =
          __ output_graph().operation_origins()[index].DecodeTurbofanNodeId();
      __ output_graph().source_positions()[index] =
          source_positions->GetSourcePosition(origin);
    }
  }

  if (origins) {
    for (OpIndex index : __ output_graph().AllOperationIndices()) {
      OpIndex origin = __ output_graph().operation_origins()[index];
      origins->SetNodeOrigin(index.id(), origin.DecodeTurbofanNodeId());
    }
  }

  return std::nullopt;
}

OpIndex GraphBuilder::Process(
    Node* node, BasicBlock* block,
    const base::SmallVector<int, 16>& predecessor_permutation,
    OpIndex& dominating_frame_state, std::optional<BailoutReason>* bailout,
    bool is_final_control) {
  if (Asm().current_block() == nullptr) {
    return OpIndex::Invalid();
  }
  __ SetCurrentOrigin(OpIndex::EncodeTurbofanNodeId(node->id()));
  const Operator* op = node->op();
  Operator::Opcode opcode = op->opcode();
  switch (opcode) {
    case IrOpcode::kStart:
    case IrOpcode::kMerge:
    case IrOpcode::kLoop:
    case IrOpcode::kIfTrue:
    case IrOpcode::kIfFalse:
    case IrOpcode::kIfDefault:
    case IrOpcode::kIfValue:
    case IrOpcode::kStateValues:
    case IrOpcode::kTypedStateValues:
    case IrOpcode::kObjectId:
    case IrOpcode::kTypedObjectState:
    case IrOpcode::kArgumentsElementsState:
    case IrOpcode::kArgumentsLengthState:
    case IrOpcode::kEffectPhi:
    case IrOpcode::kTerminate:
      return OpIndex::Invalid();

    case IrOpcode::kCheckpoint: {
      // Preserve the frame state from this checkpoint for following nodes.
      dominating_frame_state = Map(NodeProperties::GetFrameStateInput(node));
      return OpIndex::Invalid();
    }

    case IrOpcode::kIfException: {
      return __ CatchBlockBegin();
    }

    case IrOpcode::kIfSuccess: {
      return OpIndex::Invalid();
    }

    case IrOpcode::kParameter: {
      const ParameterInfo& info = ParameterInfoOf(op);
      RegisterRepresentation rep =
          RegisterRepresentation::FromMachineRepresentation(
              linkage->GetParameterType(ParameterIndexOf(node->op()))
                  .representation());
      return __ Parameter(info.index(), rep, info.debug_name());
    }

    case IrOpcode::kOsrValue: {
      return __ OsrValue(OsrValueIndexOf(op));
    }

    case IrOpcode::kPhi: {
      int input_count = op->ValueInputCount();
      RegisterRepresentation rep =
          RegisterRepresentation::FromMachineRepresentation(
              PhiRepresentationOf(op));
      if (__ current_block()->IsLoop()) {
        DCHECK_EQ(input_count, 2);
        return __ PendingLoopPhi(Map(node->InputAt(0)), rep);
      } else {
        base::SmallVector<OpIndex, 16> inputs;
        for (int i = 0; i < input_count; ++i) {
          // If this predecessor end with an unreachable (and doesn't jump to
          // this merge block), we skip its Phi input.
          Block* pred = Map(block->PredecessorAt(predecessor_permutation[i]));
          if (!pred->IsBound() ||
              pred->LastOperation(__ output_graph()).Is<UnreachableOp>()) {
            continue;
          }
          inputs.push_back(Map(node->InputAt(predecessor_permutation[i])));
        }
        return __ Phi(base::VectorOf(inputs), rep);
      }
    }

    case IrOpcode::kInt64Constant:
      return __ Word64Constant(static_cast<uint64_t>(OpParameter<int64_t>(op)));
    case IrOpcode::kInt32Constant:
      return __ Word32Constant(static_cast<uint32_t>(OpParameter<int32_t>(op)));
    case IrOpcode::kFloat64Constant:
      return __ Float64Constant(OpParameter<double>(op));
    case IrOpcode::kFloat32Constant:
      return __ Float32Constant(OpParameter<float>(op));
    case IrOpcode::kNumberConstant:
      return __ NumberConstant(OpParameter<double>(op));
    case IrOpcode::kTaggedIndexConstant:
      return __ TaggedIndexConstant(OpParameter<int32_t>(op));
    case IrOpcode::kHeapConstant:
      return __ HeapConstant(HeapConstantOf(op));
    case IrOpcode::kCompressedHeapConstant:
      return __ CompressedHeapConstant(HeapConstantOf(op));
    case IrOpcode::kTrustedHeapConstant:
      return __ TrustedHeapConstant(HeapConstantOf(op));
    case IrOpcode::kExternalConstant:
      return __ ExternalConstant(OpParameter<ExternalReference>(op));
    case IrOpcode::kRelocatableInt64Constant:
      return __ RelocatableConstant(
          OpParameter<RelocatablePtrConstantInfo>(op).value(),
          OpParameter<RelocatablePtrConstantInfo>(op).rmode());
#define BINOP_CASE(opcode, assembler_op) \
  case IrOpcode::k##opcode:              \
    return __ assembler_op(Map(node->InputAt(0)), Map(node->InputAt(1)));

      BINOP_CASE(Int32Add, Word32Add)
      BINOP_CASE(Int64Add, Word64Add)
      BINOP_CASE(Int32Mul, Word32Mul)
      BINOP_CASE(Int64Mul, Word64Mul)
      BINOP_CASE(Word32And, Word32BitwiseAnd)
      BINOP_CASE(Word64And, Word64BitwiseAnd)
      BINOP_CASE(Word32Or, Word32BitwiseOr)
      BINOP_CASE(Word64Or, Word64BitwiseOr)
      BINOP_CASE(Word32Xor, Word32BitwiseXor)
      BINOP_CASE(Word64Xor, Word64BitwiseXor)
      BINOP_CASE(Int32Sub, Word32Sub)
      BINOP_CASE(Int64Sub, Word64Sub)
      BINOP_CASE(Int32Div, Int32Div)
      BINOP_CASE(Uint32Div, Uint32Div)
      BINOP_CASE(Int64Div, Int64Div)
      BINOP_CASE(Uint64Div, Uint64Div)
      BINOP_CASE(Int32Mod, Int32Mod)
      BINOP_CASE(Uint32Mod, Uint32Mod)
      BINOP_CASE(Int64Mod, Int64Mod)
      BINOP_CASE(Uint64Mod, Uint64Mod)
      BINOP_CASE(Int32MulHigh, Int32MulOverflownBits)
      BINOP_CASE(Int64MulHigh, Int64MulOverflownBits)
      BINOP_CASE(Uint32MulHigh, Uint32MulOverflownBits)
      BINOP_CASE(Uint64MulHigh, Uint64MulOverflownBits)

      BINOP_CASE(Float32Add, Float32Add)
      BINOP_CASE(Float64Add, Float64Add)
      BINOP_CASE(Float32Sub, Float32Sub)
      BINOP_CASE(Float64Sub, Float64Sub)
      BINOP_CASE(Float64Mul, Float64Mul)
      BINOP_CASE(Float32Mul, Float32Mul)
      BINOP_CASE(Float32Div, Float32Div)
      BINOP_CASE(Float64Div, Float64Div)
      BINOP_CASE(Float32Min, Float32Min)
      BINOP_CASE(Float64Min, Float64Min)
      BINOP_CASE(Float32Max, Float32Max)
      BINOP_CASE(Float64Max, Float64Max)
      BINOP_CASE(Float64Mod, Float64Mod)
      BINOP_CASE(Float64Pow, Float64Power)
      BINOP_CASE(Float64Atan2, Float64Atan2)

      BINOP_CASE(Word32Shr, Word32ShiftRightLogical)
      BINOP_CASE(Word64Shr, Word64ShiftRightLogical)

      BINOP_CASE(Word32Shl, Word32ShiftLeft)
      BINOP_CASE(Word64Shl, Word64ShiftLeft)

      BINOP_CASE(Word32Rol, Word32RotateLeft)
      BINOP_CASE(Word64Rol, Word64RotateLeft)

      BINOP_CASE(Word32Ror, Word32RotateRight)
      BINOP_CASE(Word64Ror, Word64RotateRight)

      BINOP_CASE(Float32Equal, Float32Equal)
      BINOP_CASE(Float64Equal, Float64Equal)

      BINOP_CASE(Int32LessThan, Int32LessThan)
      BINOP_CASE(Int64LessThan, Int64LessThan)
      BINOP_CASE(Uint32LessThan, Uint32LessThan)
      BINOP_CASE(Uint64LessThan, Uint64LessThan)
      BINOP_CASE(Float32LessThan, Float32LessThan)
      BINOP_CASE(Float64LessThan, Float64LessThan)

      BINOP_CASE(Int32LessThanOrEqual, Int32LessThanOrEqual)
      BINOP_CASE(Int64LessThanOrEqual, Int64LessThanOrEqual)
      BINOP_CASE(Uint32LessThanOrEqual, Uint32LessThanOrEqual)
      BINOP_CASE(Uint64LessThanOrEqual, Uint64LessThanOrEqual)
      BINOP_CASE(Float32LessThanOrEqual, Float32LessThanOrEqual)
      BINOP_CASE(Float64LessThanOrEqual, Float64LessThanOrEqual)

      BINOP_CASE(Int32AddWithOverflow, Int32AddCheckOverflow)
      BINOP_CASE(Int64AddWithOverflow, Int64AddCheckOverflow)
      BINOP_CASE(Int32MulWithOverflow, Int32MulCheckOverflow)
      BINOP_CASE(Int64MulWithOverflow, Int64MulCheckOverflow)
      BINOP_CASE(Int32SubWithOverflow, Int32SubCheckOverflow)
      BINOP_CASE(Int64SubWithOverflow, Int64SubCheckOverflow)
#undef BINOP_CASE

    case IrOpcode::kWord32Equal: {
      OpIndex left = Map(node->InputAt(0));
      OpIndex right = Map(node->InputAt(1));
      if constexpr (kTaggedSize == kInt32Size) {
        // Unfortunately, CSA produces Word32Equal for tagged comparison.
        if (V8_UNLIKELY(pipeline_kind == TurboshaftPipelineKind::kCSA)) {
          // We need to detect these cases and construct a consistent graph.
          const bool left_is_tagged =
              __ output_graph().Get(left).outputs_rep().at(0) ==
              RegisterRepresentation::Tagged();
          const bool right_is_tagged =
              __ output_graph().Get(right).outputs_rep().at(0) ==
              RegisterRepresentation::Tagged();
          if (left_is_tagged && right_is_tagged) {
            return __ TaggedEqual(V<Object>::Cast(left),
                                  V<Object>::Cast(right));
          } else if (left_is_tagged) {
            return __ Word32Equal(
                __ TruncateWordPtrToWord32(
                    __ BitcastTaggedToWordPtr(V<Object>::Cast(left))),
                V<Word32>::Cast(right));
          } else if (right_is_tagged) {
            return __ Word32Equal(
                V<Word32>::Cast(left),
                __ TruncateWordPtrToWord32(
                    __ BitcastTaggedToWordPtr(V<Object>::Cast(right))));
          }
        }
      }
      return __ Word32Equal(V<Word32>::Cast(left), V<Word32>::Cast(right));
    }

    case IrOpcode::kWord64Equal: {
      OpIndex left = Map(node->InputAt(0));
      OpIndex right = Map(node->InputAt(1));
      if constexpr (kTaggedSize == kInt64Size) {
        // Unfortunately, CSA produces Word32Equal for tagged comparison.
        if (V8_UNLIKELY(pipeline_kind == TurboshaftPipelineKind::kCSA)) {
          // We need to detect these cases and construct a consistent graph.
          const bool left_is_tagged =
              __ output_graph().Get(left).outputs_rep().at(0) ==
              RegisterRepresentation::Tagged();
          const bool right_is_tagged =
              __ output_graph().Get(right).outputs_rep().at(0) ==
              RegisterRepresentation::Tagged();
          if (left_is_tagged && right_is_tagged) {
            return __ TaggedEqual(V<Object>::Cast(left),
                                  V<Object>::Cast(right));
          } else if (left_is_tagged) {
            DCHECK((std::is_same_v<WordPtr, Word64>));
            return __ Word64Equal(V<Word64>::Cast(__ BitcastTaggedToWordPtr(
                                      V<Object>::Cast(left))),
                                  V<Word64>::Cast(right));
          } else if (right_is_tagged) {
            DCHECK((std::is_same_v<WordPtr, Word64>));
            return __ Word64Equal(V<Word64>::Cast(left),
                                  V<Word64>::Cast(__ BitcastTaggedToWordPtr(
                                      V<Object>::Cast(right))));
          }
        }
      }
      return __ Word64Equal(V<Word64>::Cast(left), V<Word64>::Cast(right));
    }

    case IrOpcode::kWord64Sar:
    case IrOpcode::kWord32Sar: {
      WordRepresentation rep = opcode == IrOpcode::kWord64Sar
                                   ? WordRepresentation::Word64()
                                   : WordRepresentation::Word32();
      ShiftOp::Kind kind;
      switch (ShiftKindOf(op)) {
        case ShiftKind::kShiftOutZeros:
          kind = ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros;
          break;
        case ShiftKind::kNormal:
          kind = ShiftOp::Kind::kShiftRightArithmetic;
          break;
      }
      return __ Shift(Map(node->InputAt(0)), Map(node->InputAt(1)), kind, rep);
    }

#define UNARY_CASE(opcode, assembler_op) \
  case IrOpcode::k##opcode:              \
    return __ assembler_op(Map(node->InputAt(0)));

      UNARY_CASE(Word32ReverseBytes, Word32ReverseBytes)
      UNARY_CASE(Word64ReverseBytes, Word64ReverseBytes)
      UNARY_CASE(Word32Clz, Word32CountLeadingZeros)
      UNARY_CASE(Word64Clz, Word64CountLeadingZeros)
      UNARY_CASE(Word32Ctz, Word32CountTrailingZeros)
      UNARY_CASE(Word64Ctz, Word64CountTrailingZeros)
      UNARY_CASE(Word32Popcnt, Word32PopCount)
      UNARY_CASE(Word64Popcnt, Word64PopCount)
      UNARY_CASE(SignExtendWord8ToInt32, Word32SignExtend8)
      UNARY_CASE(SignExtendWord16ToInt32, Word32SignExtend16)
      UNARY_CASE(SignExtendWord8ToInt64, Word64SignExtend8)
      UNARY_CASE(SignExtendWord16ToInt64, Word64SignExtend16)
      UNARY_CASE(Int32AbsWithOverflow, Int32AbsCheckOverflow)
      UNARY_CASE(Int64AbsWithOverflow, Int64AbsCheckOverflow)

      UNARY_CASE(Float32Abs, Float32Abs)
      UNARY_CASE(Float64Abs, Float64Abs)
      UNARY_CASE(Float32Neg, Float32Negate)
      UNARY_CASE(Float64Neg, Float64Negate)
      UNARY_CASE(Float64SilenceNaN, Float64SilenceNaN)
      UNARY_CASE(Float32RoundDown, Float32RoundDown)
      UNARY_CASE(Float64RoundDown, Float64RoundDown)
      UNARY_CASE(Float32RoundUp, Float32RoundUp)
      UNARY_CASE(Float64RoundUp, Float64RoundUp)
      UNARY_CASE(Float32RoundTruncate, Float32RoundToZero)
      UNARY_CASE(Float64RoundTruncate, Float64RoundToZero)
      UNARY_CASE(Float32RoundTiesEven, Float32RoundTiesEven)
      UNARY_CASE(Float64RoundTiesEven, Float64RoundTiesEven)
      UNARY_CASE(Float64Log, Float64Log)
      UNARY_CASE(Float32Sqrt, Float32Sqrt)
      UNARY_CASE(Float64Sqrt, Float64Sqrt)
      UNARY_CASE(Float64Exp, Float64Exp)
      UNARY_CASE(Float64Expm1, Float64Expm1)
      UNARY_CASE(Float64Sin, Float64Sin)
      UNARY_CASE(Float64Cos, Float64Cos)
      UNARY_CASE(Float64Sinh, Float64Sinh)
      UNARY_CASE(Float64Cosh, Float64Cosh)
      UNARY_CASE(Float64Asin, Float64Asin)
      UNARY_CASE(Float64Acos, Float64Acos)
      UNARY_CASE(Float64Asinh, Float64Asinh)
      UNARY_CASE(Float64Acosh, Float64Acosh)
      UNARY_CASE(Float64Tan, Float64Tan)
      UNARY_CASE(Float64Tanh, Float64Tanh)
      UNARY_CASE(Float64Log2, Float64Log2)
      UNARY_CASE(Float64Log10, Float64Log10)
      UNARY_CASE(Float64Log1p, Float64Log1p)
      UNARY_CASE(Float64Atan, Float64Atan)
      UNARY_CASE(Float64Atanh, Float64Atanh)
      UNARY_CASE(Float64Cbrt, Float64Cbrt)

      UNARY_CASE(BitcastWord32ToWord64, BitcastWord32ToWord64)
      UNARY_CASE(BitcastFloat32ToInt32, BitcastFloat32ToWord32)
      UNARY_CASE(BitcastInt32ToFloat32, BitcastWord32ToFloat32)
      UNARY_CASE(BitcastFloat64ToInt64, BitcastFloat64ToWord64)
      UNARY_CASE(BitcastInt64ToFloat64, BitcastWord64ToFloat64)
      UNARY_CASE(ChangeUint32ToUint64, ChangeUint32ToUint64)
      UNARY_CASE(ChangeInt32ToInt64, ChangeInt32ToInt64)
      UNARY_CASE(SignExtendWord32ToInt64, ChangeInt32ToInt64)

      UNARY_CASE(ChangeFloat32ToFloat64, ChangeFloat32ToFloat64)

      UNARY_CASE(ChangeFloat64ToInt32, ReversibleFloat64ToInt32)
      UNARY_CASE(ChangeFloat64ToInt64, ReversibleFloat64ToInt64)
      UNARY_CASE(ChangeFloat64ToUint32, ReversibleFloat64ToUint32)
      UNARY_CASE(ChangeFloat64ToUint64, ReversibleFloat64ToUint64)

      UNARY_CASE(ChangeInt32ToFloat64, ChangeInt32ToFloat64)
      UNARY_CASE(ChangeInt64ToFloat64, ReversibleInt64ToFloat64)
      UNARY_CASE(ChangeUint32ToFloat64, ChangeUint32ToFloat64)

      UNARY_CASE(RoundFloat64ToInt32, TruncateFloat64ToInt32OverflowUndefined)
      UNARY_CASE(RoundInt32ToFloat32, ChangeInt32ToFloat32)
      UNARY_CASE(RoundInt64ToFloat32, ChangeInt64ToFloat32)
      UNARY_CASE(RoundInt64ToFloat64, ChangeInt64ToFloat64)
      UNARY_CASE(RoundUint32ToFloat32, ChangeUint32ToFloat32)
      UNARY_CASE(RoundUint64ToFloat32, ChangeUint64ToFloat32)
      UNARY_CASE(RoundUint64ToFloat64, ChangeUint64ToFloat64)
      UNARY_CASE(TruncateFloat64ToFloat32, TruncateFloat64ToFloat32)
      UNARY_CASE(TruncateFloat64ToFloat16RawBits,
                 TruncateFloat64ToFloat16RawBits)
      UNARY_CASE(TruncateFloat64ToUint32,
                 TruncateFloat64ToUint32OverflowUndefined)
      UNARY_CASE(TruncateFloat64ToWord32, JSTruncateFloat64ToWord32)

      UNARY_CASE(TryTruncateFloat32ToInt64, TryTruncateFloat32ToInt64)
      UNARY_CASE(TryTruncateFloat32ToUint64, TryTruncateFloat32ToUint64)
      UNARY_CASE(TryTruncateFloat64ToInt32, TryTruncateFloat64ToInt32)
      UNARY_CASE(TryTruncateFloat64ToInt64, TryTruncateFloat64ToInt64)
      UNARY_CASE(TryTruncateFloat64ToUint32, TryTruncateFloat64ToUint32)
      UNARY_CASE(TryTruncateFloat64ToUint64, TryTruncateFloat64ToUint64)

      UNARY_CASE(Float64ExtractLowWord32, Float64ExtractLowWord32)
      UNARY_CASE(Float64ExtractHighWord32, Float64ExtractHighWord32)
#undef UNARY_CASE
    case IrOpcode::kTruncateInt64ToInt32:
      return __ TruncateWord64ToWord32(Map(node->InputAt(0)));
    case IrOpcode::kTruncateFloat32ToInt32:
      switch (OpParameter<TruncateKind>(node->op())) {
        case TruncateKind::kArchitectureDefault:
          return __ TruncateFloat32ToInt32OverflowUndefined(
              Map(node->InputAt(0)));
        case TruncateKind::kSetOverflowToMin:
          return __ TruncateFloat32ToInt32OverflowToMin(Map(node->InputAt(0)));
      }
    case IrOpcode::kTruncateFloat32ToUint32:
      switch (OpParameter<TruncateKind>(node->op())) {
        case TruncateKind::kArchitectureDefault:
          return __ TruncateFloat32ToUint32OverflowUndefined(
              Map(node->InputAt(0)));
        case TruncateKind::kSetOverflowToMin:
          return __ TruncateFloat32ToUint32OverflowToMin(Map(node->InputAt(0)));
      }
    case IrOpcode::kTruncateFloat64ToInt64:
      switch (OpParameter<TruncateKind>(node->op())) {
        case TruncateKind::kArchitectureDefault:
          return __ TruncateFloat64ToInt64OverflowUndefined(
              Map(node->InputAt(0)));
        case TruncateKind::kSetOverflowToMin:
          return __ TruncateFloat64ToInt64OverflowToMin(Map(node->InputAt(0)));
      }
    case IrOpcode::kFloat64InsertLowWord32: {
      V<Word32> high;
      V<Word32> low = Map<Word32>(node->InputAt(1));
      if (node->InputAt(0)->opcode() == IrOpcode::kFloat64InsertHighWord32) {
        // We can turn this into a single operation.
        high = Map<Word32>(node->InputAt(0)->InputAt(1));
      } else {
        // We need to extract the high word to combine it.
        high = __ Float64ExtractHighWord32(Map(node->InputAt(0)));
      }
      return __ BitcastWord32PairToFloat64(high, low);
    }
    case IrOpcode::kFloat64InsertHighWord32: {
      V<Word32> high = Map<Word32>(node->InputAt(1));
      V<Word32> low;
      if (node->InputAt(0)->opcode() == IrOpcode::kFloat64InsertLowWord32) {
        // We can turn this into a single operation.
        low = Map<Word32>(node->InputAt(0)->InputAt(1));
      } else {
        // We need to extract the low word to combine it.
        low = __ Float64ExtractLowWord32(Map<Float64>(node->InputAt(0)));
      }
      return __ BitcastWord32PairToFloat64(high, low);
    }
    case IrOpcode::kBitcastTaggedToWord:
      return __ BitcastTaggedToWordPtr(Map(node->InputAt(0)));
    case IrOpcode::kBitcastWordToTagged: {
      V<WordPtr> input = Map(node->InputAt(0));
      if (V8_UNLIKELY(pipeline_kind == TurboshaftPipelineKind::kCSA)) {
        // TODO(nicohartmann@): This is currently required to properly compile
        // builtins. We should fix them and remove this.
        if (LoadOp* load = __ output_graph().Get(input).TryCast<LoadOp>()) {
          CHECK_EQ(2, node->InputAt(0)->UseCount());
          CHECK(base::all_equal(node->InputAt(0)->uses(), node));
          // CSA produces the pattern
          //   BitcastWordToTagged(Load<RawPtr>(...))
          // which is not safe to translate to Turboshaft, because
          // LateLoadElimination can potentially merge this with an identical
          // untagged load that would be unsound in presence of a GC.
          CHECK(load->loaded_rep == MemoryRepresentation::UintPtr() ||
                load->loaded_rep == (Is64() ? MemoryRepresentation::Int64()
                                            : MemoryRepresentation::Int32()));
          CHECK_EQ(load->result_rep, RegisterRepresentation::WordPtr());
          // In this case we turn the load into a tagged load directly...
          load->loaded_rep = MemoryRepresentation::UncompressedTaggedPointer();
          load->result_rep = RegisterRepresentation::Tagged();
          // ... and skip the bitcast.
          return input;
        }
      }
      return __ BitcastWordPtrToTagged(Map(node->InputAt(0)));
    }
    case IrOpcode::kNumberIsFinite:
      return __ Float64Is(Map(node->InputAt(0)), NumericKind::kFinite);
    case IrOpcode::kNumberIsInteger:
      return __ Float64Is(Map(node->InputAt(0)), NumericKind::kInteger);
    case IrOpcode::kNumberIsSafeInteger:
      return __ Float64Is(Map(node->InputAt(0)), NumericKind::kSafeInteger);
    case IrOpcode::kNumberIsFloat64Hole:
      return __ Float64Is(Map(node->InputAt(0)), NumericKind::kFloat64Hole);
    case IrOpcode::kNumberIsMinusZero:
      return __ Float64Is(Map(node->InputAt(0)), NumericKind::kMinusZero);
    case IrOpcode::kNumberIsNaN:
      return __ Float64Is(Map(node->InputAt(0)), NumericKind::kNaN);
    case IrOpcode::kObjectIsMinusZero:
      return __ ObjectIsNumericValue(Map(node->InputAt(0)),
                                     NumericKind::kMinusZero,
                                     FloatRepresentation::Float64());
    case IrOpcode::kObjectIsNaN:
      return __ ObjectIsNumericValue(Map(node->InputAt(0)), NumericKind::kNaN,
                                     FloatRepresentation::Float64());
    case IrOpcode::kObjectIsFiniteNumber:
      return __ ObjectIsNumericValue(Map(node->InputAt(0)),
                                     NumericKind::kFinite,
                                     FloatRepresentation::Float64());
    case IrOpcode::kObjectIsInteger:
      return __ ObjectIsNumericValue(Map(node->InputAt(0)),
                                     NumericKind::kInteger,
                                     FloatRepresentation::Float64());
    case IrOpcode::kObjectIsSafeInteger:
      return __ ObjectIsNumericValue(Map(node->InputAt(0)),
                                     NumericKind::kSafeInteger,
                                     FloatRepresentation::Float64());

#define OBJECT_IS_CASE(kind)                                             \
  case IrOpcode::kObjectIs##kind: {                                      \
    return __ ObjectIs(Map(node->InputAt(0)), ObjectIsOp::Kind::k##kind, \
                       ObjectIsOp::InputAssumptions::kNone);             \
  }
      OBJECT_IS_CASE(ArrayBufferView)
      OBJECT_IS_CASE(BigInt)
      OBJECT_IS_CASE(Callable)
      OBJECT_IS_CASE(Constructor)
      OBJECT_IS_CASE(DetectableCallable)
      OBJECT_IS_CASE(NonCallable)
      OBJECT_IS_CASE(Number)
      OBJECT_IS_CASE(Receiver)
      OBJECT_IS_CASE(Smi)
      OBJECT_IS_CASE(String)
      OBJECT_IS_CASE(Symbol)
      OBJECT_IS_CASE(Undetectable)
#undef OBJECT_IS_CASE

#define CHECK_OBJECT_IS_CASE(code, kind, input_assumptions, reason, feedback) \
  case IrOpcode::k##code: {                                                   \
    DCHECK(dominating_frame_state.valid());                                   \
    V<Object> input = Map(node->InputAt(0));                                  \
    V<Word32> check =                                                         \
        __ ObjectIs(input, ObjectIsOp::Kind::k##kind,                         \
                    ObjectIsOp::InputAssumptions::k##input_assumptions);      \
    __ DeoptimizeIfNot(check, dominating_frame_state,                         \
                       DeoptimizeReason::k##reason, feedback);                \
    return input;                                                             \
  }
      CHECK_OBJECT_IS_CASE(CheckInternalizedString, InternalizedString,
                           HeapObject, WrongInstanceType, {})
      CHECK_OBJECT_IS_CASE(CheckNumber, Number, None, NotANumber,
                           CheckParametersOf(op).feedback())
      CHECK_OBJECT_IS_CASE(CheckReceiver, Receiver, HeapObject,
                           NotAJavaScriptObject, {})
      CHECK_OBJECT_IS_CASE(CheckReceiverOrNullOrUndefined,
                           ReceiverOrNullOrUndefined, HeapObject,
                           NotAJavaScriptObjectOrNullOrUndefined, {})
      CHECK_OBJECT_IS_CASE(CheckString, String, HeapObject, NotAString,
                           CheckParametersOf(op).feedback())
      CHECK_OBJECT_IS_CASE(CheckStringOrStringWrapper, StringOrStringWrapper,
                           HeapObject, NotAStringOrStringWrapper,
                           CheckParametersOf(op).feedback())
      CHECK_OBJECT_IS_CASE(CheckSymbol, Symbol, HeapObject, NotASymbol, {})
      CHECK_OBJECT_IS_CASE(CheckBigInt, BigInt, None, NotABigInt,
                           CheckParametersOf(op).feedback())
      CHECK_OBJECT_IS_CASE(CheckedBigIntToBigInt64, BigInt64, BigInt,
                           NotABigInt64, CheckParametersOf(op).feedback())
#undef CHECK_OBJECT_IS_CASE

    case IrOpcode::kPlainPrimitiveToNumber:
      return __ ConvertPlainPrimitiveToNumber(Map(node->InputAt(0)));
    case IrOpcode::kPlainPrimitiveToWord32:
      return __ ConvertJSPrimitiveToUntagged(
          Map(node->InputAt(0)),
          ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kInt32,
          ConvertJSPrimitiveToUntaggedOp::InputAssumptions::kPlainPrimitive);
    case IrOpcode::kPlainPrimitiveToFloat64:
      return __ ConvertJSPrimitiveToUntagged(
          Map(node->InputAt(0)),
          ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kFloat64,
          ConvertJSPrimitiveToUntaggedOp::InputAssumptions::kPlainPrimitive);

    case IrOpcode::kConvertTaggedHoleToUndefined: {
      V<Object> input = Map(node->InputAt(0));
      V<Word32> is_the_hole = __ TaggedEqual(
          input, __ HeapConstant(isolate->factory()->the_hole_value()));
      return __ Conditional(
          is_the_hole, __ HeapConstant(isolate->factory()->undefined_value()),
          input, BranchHint::kFalse);
    }

    case IrOpcode::kConvertReceiver:
      return __ ConvertJSPrimitiveToObject(
          Map(node->InputAt(0)), Map(node->InputAt(1)), Map(node->InputAt(2)),
          ConvertReceiverModeOf(node->op()));

    case IrOpcode::kToBoolean:
      return __ ConvertToBoolean(Map(node->InputAt(0)));
    case IrOpcode::kNumberToString:
      return __ ConvertNumberToString(Map(node->InputAt(0)));
    case IrOpcode::kStringToNumber:
      return __ ConvertStringToNumber(Map(node->InputAt(0)));
    case IrOpcode::kChangeTaggedToTaggedSigned:
      return __ Convert(Map(node->InputAt(0)),
                        ConvertOp::Kind::kNumberOrOddball,
                        ConvertOp::Kind::kSmi);

    case IrOpcode::kCheckedTaggedToTaggedSigned: {
      DCHECK(dominating_frame_state.valid());
      V<Object> input = Map(node->InputAt(0));
      __ DeoptimizeIfNot(__ ObjectIsSmi(input), dominating_frame_state,
                         DeoptimizeReason::kNotASmi,
                         CheckParametersOf(node->op()).feedback());
      return input;
    }

    case IrOpcode::kCheckedTaggedToTaggedPointer: {
      DCHECK(dominating_frame_state.valid());
      V<Object> input = Map(node->InputAt(0));
      __ DeoptimizeIf(__ ObjectIsSmi(input), dominating_frame_state,
                      DeoptimizeReason::kSmi,
                      CheckParametersOf(node->op()).feedback());
      return input;
    }

#define CONVERT_PRIMITIVE_TO_OBJECT_CASE(name, kind, input_type,  \
                                         input_interpretation)    \
  case IrOpcode::k##name:                                         \
    return __ ConvertUntaggedToJSPrimitive(                       \
        Map(node->InputAt(0)),                                    \
        ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::k##kind, \
        V<input_type>::rep,                                       \
        ConvertUntaggedToJSPrimitiveOp::InputInterpretation::     \
            k##input_interpretation,                              \
        CheckForMinusZeroMode::kDontCheckForMinusZero);
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeInt32ToTagged, Number, Word32,
                                       Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeUint32ToTagged, Number, Word32,
                                       Unsigned)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeInt64ToTagged, Number, Word64,
                                       Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeUint64ToTagged, Number, Word64,
                                       Unsigned)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeFloat64ToTaggedPointer, HeapNumber,
                                       Float64, Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeInt64ToBigInt, BigInt, Word64,
                                       Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeUint64ToBigInt, BigInt, Word64,
                                       Unsigned)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeInt31ToTaggedSigned, Smi, Word32,
                                       Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeBitToTagged, Boolean, Word32,
                                       Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(StringFromSingleCharCode, String, Word32,
                                       CharCode)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(StringFromSingleCodePoint, String,
                                       Word32, CodePoint)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeFloat64HoleToTagged,
                                       HeapNumberOrUndefined, Float64, Signed)

    case IrOpcode::kChangeFloat64ToTagged:
      return __ ConvertUntaggedToJSPrimitive(
          Map(node->InputAt(0)),
          ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kNumber,
          RegisterRepresentation::Float64(),
          ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned,
          CheckMinusZeroModeOf(node->op()));
#undef CONVERT_PRIMITIVE_TO_OBJECT_CASE

#define CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE(name, kind, input_type, \
                                                  input_interpretation)   \
  case IrOpcode::k##name: {                                               \
    DCHECK(dominating_frame_state.valid());                               \
    const CheckParameters& params = CheckParametersOf(node->op());        \
    return __ ConvertUntaggedToJSPrimitiveOrDeopt(                        \
        Map(node->InputAt(0)), dominating_frame_state,                    \
        ConvertUntaggedToJSPrimitiveOrDeoptOp::JSPrimitiveKind::k##kind,  \
        V<input_type>::rep,                                               \
        ConvertUntaggedToJSPrimitiveOrDeoptOp::InputInterpretation::      \
            k##input_interpretation,                                      \
        params.feedback());                                               \
  }
      CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE(CheckedInt32ToTaggedSigned, Smi,
                                                Word32, Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE(CheckedUint32ToTaggedSigned,
                                                Smi, Word32, Unsigned)
      CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE(CheckedInt64ToTaggedSigned, Smi,
                                                Word64, Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE(CheckedUint64ToTaggedSigned,
                                                Smi, Word64, Unsigned)
#undef CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE

#define CONVERT_OBJECT_TO_PRIMITIVE_CASE(name, kind, input_assumptions) \
  case IrOpcode::k##name:                                               \
    return __ ConvertJSPrimitiveToUntagged(                             \
        Map(node->InputAt(0)),                                          \
        ConvertJSPrimitiveToUntaggedOp::UntaggedKind::k##kind,          \
        ConvertJSPrimitiveToUntaggedOp::InputAssumptions::              \
            k##input_assumptions);
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedSignedToInt32, Int32, Smi)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedSignedToInt64, Int64, Smi)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedToBit, Bit, Boolean)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedToInt32, Int32,
                                       NumberOrOddball)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedToUint32, Uint32,
                                       NumberOrOddball)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedToInt64, Int64,
                                       NumberOrOddball)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedToFloat64, Float64,
                                       NumberOrOddball)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(TruncateTaggedToFloat64, Float64,
                                       NumberOrOddball)
#undef CONVERT_OBJECT_TO_PRIMITIVE_CASE

#define TRUNCATE_OBJECT_TO_PRIMITIVE_CASE(name, kind, input_assumptions) \
  case IrOpcode::k##name:                                                \
    return __ TruncateJSPrimitiveToUntagged(                             \
        Map(node->InputAt(0)),                                           \
        TruncateJSPrimitiveToUntaggedOp::UntaggedKind::k##kind,          \
        TruncateJSPrimitiveToUntaggedOp::InputAssumptions::              \
            k##input_assumptions);
      TRUNCATE_OBJECT_TO_PRIMITIVE_CASE(TruncateTaggedToWord32, Int32,
                                        NumberOrOddball)
      TRUNCATE_OBJECT_TO_PRIMITIVE_CASE(TruncateBigIntToWord64, Int64, BigInt)
      TRUNCATE_OBJECT_TO_PRIMITIVE_CASE(TruncateTaggedToBit, Bit, Object)
      TRUNCATE_OBJECT_TO_PRIMITIVE_CASE(TruncateTaggedPointerToBit, Bit,
                                        HeapObject)
#undef TRUNCATE_OBJECT_TO_PRIMITIVE_CASE

    case IrOpcode::kCheckedTruncateTaggedToWord32:
      DCHECK(dominating_frame_state.valid());
      using IR = TruncateJSPrimitiveToUntaggedOrDeoptOp::InputRequirement;
      IR input_requirement;
      switch (CheckTaggedInputParametersOf(node->op()).mode()) {
        case CheckTaggedInputMode::kNumber:
          input_requirement = IR::kNumber;
          break;
        case CheckTaggedInputMode::kNumberOrBoolean:
          input_requirement = IR::kNumberOrBoolean;
          break;
        case CheckTaggedInputMode::kNumberOrOddball:
          input_requirement = IR::kNumberOrOddball;
          break;
      }
      return __ TruncateJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state,
          TruncateJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32,
          input_requirement,
          CheckTaggedInputParametersOf(node->op()).feedback());

#define CHANGE_OR_DEOPT_INT_CASE(kind)                                     \
  case IrOpcode::kChecked##kind: {                                         \
    DCHECK(dominating_frame_state.valid());                                \
    const CheckParameters& params = CheckParametersOf(node->op());         \
    return __ ChangeOrDeopt(Map(node->InputAt(0)), dominating_frame_state, \
                            ChangeOrDeoptOp::Kind::k##kind,                \
                            CheckForMinusZeroMode::kDontCheckForMinusZero, \
                            params.feedback());                            \
  }
      CHANGE_OR_DEOPT_INT_CASE(Uint32ToInt32)
      CHANGE_OR_DEOPT_INT_CASE(Int64ToInt32)
      CHANGE_OR_DEOPT_INT_CASE(Uint64ToInt32)
      CHANGE_OR_DEOPT_INT_CASE(Uint64ToInt64)
#undef CHANGE_OR_DEOPT_INT_CASE

    case IrOpcode::kCheckedFloat64ToInt32: {
      DCHECK(dominating_frame_state.valid());
      const CheckMinusZeroParameters& params =
          CheckMinusZeroParametersOf(node->op());
      return __ ChangeOrDeopt(Map(node->InputAt(0)), dominating_frame_state,
                              ChangeOrDeoptOp::Kind::kFloat64ToInt32,
                              params.mode(), params.feedback());
    }

    case IrOpcode::kCheckedFloat64ToInt64: {
      DCHECK(dominating_frame_state.valid());
      const CheckMinusZeroParameters& params =
          CheckMinusZeroParametersOf(node->op());
      return __ ChangeOrDeopt(Map(node->InputAt(0)), dominating_frame_state,
                              ChangeOrDeoptOp::Kind::kFloat64ToInt64,
                              params.mode(), params.feedback());
    }

    case IrOpcode::kCheckedTaggedToInt32: {
      DCHECK(dominating_frame_state.valid());
      const CheckMinusZeroParameters& params =
          CheckMinusZeroParametersOf(node->op());
      return __ ConvertJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kNumber,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32,
          params.mode(), params.feedback());
    }

    case IrOpcode::kCheckedTaggedToInt64: {
      DCHECK(dominating_frame_state.valid());
      const CheckMinusZeroParameters& params =
          CheckMinusZeroParametersOf(node->op());
      return __ ConvertJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kNumber,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt64,
          params.mode(), params.feedback());
    }

    case IrOpcode::kCheckedTaggedToFloat64: {
      DCHECK(dominating_frame_state.valid());
      const CheckTaggedInputParameters& params =
          CheckTaggedInputParametersOf(node->op());
      ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind from_kind;
      switch (params.mode()) {
#define CASE(mode)                                                       \
  case CheckTaggedInputMode::k##mode:                                    \
    from_kind =                                                          \
        ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::k##mode; \
    break;
        CASE(Number)
        CASE(NumberOrBoolean)
        CASE(NumberOrOddball)
#undef CASE
      }
      return __ ConvertJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state, from_kind,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kFloat64,
          CheckForMinusZeroMode::kDontCheckForMinusZero, params.feedback());
    }

    case IrOpcode::kCheckedTaggedToArrayIndex: {
      DCHECK(dominating_frame_state.valid());
      const CheckParameters& params = CheckParametersOf(node->op());
      return __ ConvertJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::
              kNumberOrString,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kArrayIndex,
          CheckForMinusZeroMode::kCheckForMinusZero, params.feedback());
    }

    case IrOpcode::kCheckedTaggedSignedToInt32: {
      DCHECK(dominating_frame_state.valid());
      const CheckParameters& params = CheckParametersOf(node->op());
      return __ ConvertJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kSmi,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32,
          CheckForMinusZeroMode::kDontCheckForMinusZero, params.feedback());
    }

    case IrOpcode::kSelect: {
      V<Word32> cond = Map(node->InputAt(0));
      V<Any> vtrue = Map(node->InputAt(1));
      V<Any> vfalse = Map(node->InputAt(2));
      const SelectParameters& params = SelectParametersOf(op);
      return __ Select(cond, vtrue, vfalse,
                       RegisterRepresentation::FromMachineRepresentation(
                           params.representation()),
                       params.hint(), SelectOp::Implementation::kBranch);
    }
    case IrOpcode::kWord32Select:
      return __ Select(
          Map<Word32>(node->InputAt(0)), Map<Word32>(node->InputAt(1)),
          Map<Word32>(node->InputAt(2)), RegisterRepresentation::Word32(),
          BranchHint::kNone, SelectOp::Implementation::kCMove);
    case IrOpcode::kWord64Select:
      return __ Select(
          Map<Word32>(node->InputAt(0)), Map<Word64>(node->InputAt(1)),
          Map<Word64>(node->InputAt(2)), RegisterRepresentation::Word64(),
          BranchHint::kNone, SelectOp::Implementation::kCMove);

    case IrOpcode::kLoad:
    case IrOpcode::kLoadImmutable:
    case IrOpcode::kUnalignedLoad: {
      MemoryRepresentation loaded_rep =
          MemoryRepresentation::FromMachineType(LoadRepresentationOf(op));
      Node* base = node->InputAt(0);
      Node* index = node->InputAt(1);
      // It's ok to merge LoadImmutable into Load after scheduling.
      LoadOp::Kind kind = opcode == IrOpcode::kUnalignedLoad
                              ? LoadOp::Kind::RawUnaligned()
                              : LoadOp::Kind::RawAligned();
      if (__ output_graph().Get(Map(base)).outputs_rep().at(0) ==
          RegisterRepresentation::Tagged()) {
        kind = LoadOp::Kind::TaggedBase();
      }
      if (index->opcode() == IrOpcode::kInt32Constant) {
        int32_t offset = OpParameter<int32_t>(index->op());
        if (kind.tagged_base) offset += kHeapObjectTag;
        return __ Load(Map(base), kind, loaded_rep, offset);
      }
      if (index->opcode() == IrOpcode::kInt64Constant) {
        int64_t offset = OpParameter<int64_t>(index->op());
        if (kind.tagged_base) offset += kHeapObjectTag;
        if (base::IsValueInRangeForNumericType<int32_t>(offset)) {
          return __ Load(Map(base), kind, loaded_rep,
                         static_cast<int32_t>(offset));
        }
      }
      int32_t offset = kind.tagged_base ? kHeapObjectTag : 0;
      uint8_t element_size_log2 = 0;
      return __ Load(Map(base), Map(index), kind, loaded_rep, offset,
                     element_size_log2);
    }
    case IrOpcode::kProtectedLoad: {
      MemoryRepresentation loaded_rep =
          MemoryRepresentation::FromMachineType(LoadRepresentationOf(op));
      return __ Load(Map(node->InputAt(0)), Map(node->InputAt(1)),
                     LoadOp::Kind::Protected(), loaded_rep);
    }

    case IrOpcode::kStore:
    case IrOpcode::kUnalignedStore: {
      OpIndex base = Map(node->InputAt(0));
      if (pipeline_kind == TurboshaftPipelineKind::kCSA) {
        // TODO(nicohartmann@): This is currently required to properly compile
        // builtins. We should fix them and remove this.
        if (__ output_graph().Get(base).outputs_rep()[0] ==
            RegisterRepresentation::Tagged()) {
          base = __ BitcastTaggedToWordPtr(base);
        }
      }
      bool aligned = opcode != IrOpcode::kUnalignedStore;
      StoreRepresentation store_rep =
          aligned ? StoreRepresentationOf(op)
                  : StoreRepresentation(UnalignedStoreRepresentationOf(op),
                                        WriteBarrierKind::kNoWriteBarrier);
      StoreOp::Kind kind = opcode == IrOpcode::kStore
                               ? StoreOp::Kind::RawAligned()
                               : StoreOp::Kind::RawUnaligned();
      bool initializing_transitioning = inside_region;

      Node* index = node->InputAt(1);
      Node* value = node->InputAt(2);
      if (index->opcode() == IrOpcode::kInt32Constant) {
        int32_t offset = OpParameter<int32_t>(index->op());
        __ Store(base, Map(value), kind,
                 MemoryRepresentation::FromMachineRepresentation(
                     store_rep.representation()),
                 store_rep.write_barrier_kind(), offset,
                 initializing_transitioning);
        return OpIndex::Invalid();
      }
      if (index->opcode() == IrOpcode::kInt64Constant) {
        int64_t offset = OpParameter<int64_t>(index->op());
        if (base::IsValueInRangeForNumericType<int32_t>(offset)) {
          __ Store(base, Map(value), kind,
                   MemoryRepresentation::FromMachineRepresentation(
                       store_rep.representation()),
                   store_rep.write_barrier_kind(), static_cast<int32_t>(offset),
                   initializing_transitioning);
          return OpIndex::Invalid();
        }
      }
      int32_t offset = 0;
      uint8_t element_size_log2 = 0;
      __ Store(base, Map(index), Map(value), kind,
               MemoryRepresentation::FromMachineRepresentation(
                   store_rep.representation()),
               store_rep.write_barrier_kind(), offset, element_size_log2,
               initializing_transitioning);
      return OpIndex::Invalid();
    }
    case IrOpcode::kProtectedStore:
      // We don't mark ProtectedStores as initialzing even when inside regions,
      // since we don't store-store eliminate them because they have a raw base.
      __ Store(Map(node->InputAt(0)), Map(node->InputAt(1)),
               Map(node->InputAt(2)), StoreOp::Kind::Protected(),
               MemoryRepresentation::FromMachineRepresentation(
                   OpParameter<MachineRepresentation>(node->op())),
               WriteBarrierKind::kNoWriteBarrier);
      return OpIndex::Invalid();

    case IrOpcode::kRetain:
      __ Retain(Map(node->InputAt(0)));
      return OpIndex::Invalid();
    case IrOpcode::kStackPointerGreaterThan:
      return __ StackPointerGreaterThan(Map<WordPtr>(node->InputAt(0)),
                                        StackCheckKindOf(op));
    case IrOpcode::kLoadStackCheckOffset:
      return __ StackCheckOffset();
    case IrOpcode::kLoadFramePointer:
      return __ FramePointer();
    case IrOpcode::kLoadParentFramePointer:
      return __ ParentFramePointer();

    case IrOpcode::kStackSlot: {
      StackSlotRepresentation rep = StackSlotRepresentationOf(op);
      return __ StackSlot(rep.size(), rep.alignment(), rep.is_tagged());
    }
    case IrOpcode::kBranch:
      DCHECK_EQ(block->SuccessorCount(), 2);
      __ Branch(Map(node->InputAt(0)), Map(block->SuccessorAt(0)),
                Map(block->SuccessorAt(1)), BranchHintOf(node->op()));
      return OpIndex::Invalid();

    case IrOpcode::kSwitch: {
      BasicBlock* default_branch = block->successors().back();
      DCHECK_EQ(IrOpcode::kIfDefault, default_branch->front()->opcode());
      size_t case_count = block->SuccessorCount() - 1;
      base::SmallVector<SwitchOp::Case, 16> cases;
      for (size_t i = 0; i < case_count; ++i) {
        BasicBlock* branch = block->SuccessorAt(i);
        const IfValueParameters& p = IfValueParametersOf(branch->front()->op());
        cases.emplace_back(p.value(), Map(branch), p.hint());
      }
      __ Switch(
          Map(node->InputAt(0)), graph_zone->CloneVector(base::VectorOf(cases)),
          Map(default_branch), BranchHintOf(default_branch->front()->op()));
      return OpIndex::Invalid();
    }

    case IrOpcode::kCall: {
      auto call_descriptor = CallDescriptorOf(op);
      const JSWasmCallParameters* wasm_call_parameters = nullptr;
#if V8_ENABLE_WEBASSEMBLY
      if (call_descriptor->kind() == CallDescriptor::kCallWasmFunction &&
          v8_flags.turboshaft_wasm_in_js_inlining) {
        // A JS-to-Wasm call where the wrapper got inlined in TurboFan but the
        // actual Wasm body inlining was either not possible or is going to
        // happen later in Turboshaft. See https://crbug.com/353475584.
        // Make sure that for each not-yet-body-inlined call node, there is an
        // entry in the sidetable.
        DCHECK_NOT_NULL(js_wasm_calls_sidetable);
        auto it = js_wasm_calls_sidetable->find(node->id());
        CHECK_NE(it, js_wasm_calls_sidetable->end());
        wasm_call_parameters = it->second;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      CanThrow can_throw =
          op->HasProperty(Operator::kNoThrow) ? CanThrow::kNo : CanThrow::kYes;
      const TSCallDescriptor* ts_descriptor = TSCallDescriptor::Create(
          call_descriptor, can_throw, LazyDeoptOnThrow::kNo, graph_zone,
          wasm_call_parameters);

      base::SmallVector<OpIndex, 16> arguments;
      // The input `0` is the callee, the following value inputs are the
      // arguments. `CallDescriptor::InputCount()` counts the callee and
      // arguments, but excludes a possible `FrameState` input.
      OpIndex callee = Map(node->InputAt(0));
      for (int i = 1; i < static_cast<int>(call_descriptor->InputCount());
           ++i) {
        arguments.emplace_back(Map(node->InputAt(i)));
      }

      OpIndex frame_state_idx = OpIndex::Invalid();
      if (call_descriptor->NeedsFrameState()) {
        compiler::FrameState frame_state{
            node->InputAt(static_cast<int>(call_descriptor->InputCount()))};
        frame_state_idx = Map(frame_state);
      }
      std::optional<decltype(assembler)::CatchScope> catch_scope;
      if (is_final_control) {
        Block* catch_block = Map(block->SuccessorAt(1));
        catch_scope.emplace(assembler, catch_block);
      }
      OpEffects effects =
          OpEffects().CanDependOnChecks().CanChangeControlFlow().CanDeopt();
      if ((call_descriptor->flags() & CallDescriptor::kNoAllocate) == 0) {
        effects = effects.CanAllocate();
      }
      if (!op->HasProperty(Operator::kNoWrite)) {
        effects = effects.CanWriteMemory();
      }
      if (!op->HasProperty(Operator::kNoRead)) {
        effects = effects.CanReadMemory();
      }
      OpIndex result =
          __ Call(callee, frame_state_idx, base::VectorOf(arguments),
                  ts_descriptor, effects);
      if (is_final_control) {
        // The `__ Call()` before has already created exceptional control flow
        // and bound a new block for the success case. So we can just `Goto` the
        // block that Turbofan designated as the `IfSuccess` successor.
        __ Goto(Map(block->SuccessorAt(0)));
      }
      return result;
    }

    case IrOpcode::kTailCall: {
      auto call_descriptor = CallDescriptorOf(op);
      base::SmallVector<OpIndex, 16> arguments;
      // The input `0` is the callee, the following value inputs are the
      // arguments. `CallDescriptor::InputCount()` counts the callee and
      // arguments.
      OpIndex callee = Map(node->InputAt(0));
      for (int i = 1; i < static_cast<int>(call_descriptor->InputCount());
           ++i) {
        arguments.emplace_back(Map(node->InputAt(i)));
      }

      CanThrow can_throw =
          op->HasProperty(Operator::kNoThrow) ? CanThrow::kNo : CanThrow::kYes;
      const TSCallDescriptor* ts_descriptor = TSCallDescriptor::Create(
          call_descriptor, can_throw, LazyDeoptOnThrow::kNo, graph_zone);

      __ TailCall(callee, base::VectorOf(arguments), ts_descriptor);
      return OpIndex::Invalid();
    }

    case IrOpcode::kFrameState: {
      compiler::FrameState frame_state{node};
      FrameStateData::Builder builder;
      BuildFrameStateData(&builder, frame_state);
      if (builder.Inputs().size() >
          std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
        *bailout = BailoutReason::kTooManyArguments;
        return OpIndex::Invalid();
      }
      return __ FrameState(builder.Inputs(), builder.inlined(),
                           builder.AllocateFrameStateData(
                               frame_state.frame_state_info(), graph_zone));
    }

    case IrOpcode::kDeoptimizeIf:
      __ DeoptimizeIf(Map(node->InputAt(0)), Map(node->InputAt(1)),
                      &DeoptimizeParametersOf(op));
      return OpIndex::Invalid();
    case IrOpcode::kDeoptimizeUnless:
      __ DeoptimizeIfNot(Map(node->InputAt(0)), Map(node->InputAt(1)),
                         &DeoptimizeParametersOf(op));
      return OpIndex::Invalid();

#if V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kTrapIf:
      // For wasm the dominating_frame_state is invalid and will not be used.
      // For traps inlined into JS the dominating_frame_state is valid and is
      // needed for the trap.
      __ TrapIf(Map(node->InputAt(0)), dominating_frame_state, TrapIdOf(op));
      return OpIndex::Invalid();

    case IrOpcode::kTrapUnless:
      // For wasm the dominating_frame_state is invalid and will not be used.
      // For traps inlined into JS the dominating_frame_state is valid and is
      // needed for the trap.
      __ TrapIfNot(Map(node->InputAt(0)), dominating_frame_state, TrapIdOf(op));
      return OpIndex::Invalid();
#endif  // V8_ENABLE_WEBASSEMBLY

    case IrOpcode::kDeoptimize: {
      V<FrameState> frame_state = Map(node->InputAt(0));
      __ Deoptimize(frame_state, &DeoptimizeParametersOf(op));
      return OpIndex::Invalid();
    }

    case IrOpcode::kReturn: {
      Node* pop_count = node->InputAt(0);
      base::SmallVector<OpIndex, 4> return_values;
      for (int i = 1; i < node->op()->ValueInputCount(); ++i) {
        return_values.push_back(Map(node->InputAt(i)));
      }
      __ Return(Map(pop_count), base::VectorOf(return_values));
      return OpIndex::Invalid();
    }
    case IrOpcode::kUnreachable:
    case IrOpcode::kThrow:
      __ Unreachable();
      return OpIndex::Invalid();

    case IrOpcode::kDeadValue:
      // Typically, DeadValue nodes have Unreachable as their input. In this
      // case, we would not get here because Unreachable already terminated the
      // block and we stopped generating additional operations.
      DCHECK_NE(node->InputAt(0)->opcode(), IrOpcode::kUnreachable);
      // If we find a DeadValue without an Unreachable input, we just generate
      // one here and stop.
      __ Unreachable();
      return OpIndex::Invalid();

    case IrOpcode::kProjection: {
      Node* input = node->InputAt(0);
      size_t index = ProjectionIndexOf(op);
      RegisterRepresentation rep =
          RegisterRepresentation::FromMachineRepresentation(
              NodeProperties::GetProjectionType(node));
      return __ Projection(Map(input), index, rep);
    }

    case IrOpcode::kStaticAssert:
      __ StaticAssert(Map(node->InputAt(0)), StaticAssertSourceOf(node->op()));
      return OpIndex::Invalid();

    case IrOpcode::kAllocate: {
      AllocationType allocation = AllocationTypeOf(node->op());
      return __ FinishInitialization(
          __ Allocate(Map(node->InputAt(0)), allocation));
    }
    // TODO(nicohartmann@): We might not see AllocateRaw here anymore.
    case IrOpcode::kAllocateRaw: {
      Node* size = node->InputAt(0);
      const AllocateParameters& params = AllocateParametersOf(node->op());
      return __ FinishInitialization(
          __ Allocate(Map(size), params.allocation_type()));
    }
    case IrOpcode::kStoreToObject: {
      Node* object = node->InputAt(0);
      Node* offset =
```