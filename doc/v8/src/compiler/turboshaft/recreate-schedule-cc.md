Response:
My thinking process to arrive at the summary of `recreate-schedule.cc`'s functionality goes like this:

1. **Initial Scan for Keywords and Concepts:** I first read through the code, paying attention to the included headers, namespace, and struct names. Keywords like "schedule," "recreate," "compiler," "turboshaft," "turbofan," "graph," "node," "block," "operation," and "machine" immediately stand out. These suggest the file is related to the compilation process, specifically transforming a representation of code (`turboshaft::Graph`) into something that Turbofan (V8's optimizing compiler) can understand and further optimize (`compiler::Graph` and `compiler::Schedule`).

2. **Focus on the `ScheduleBuilder` Struct:** This struct seems central. It holds references to various compiler data structures (`PipelineData`, `CallDescriptor`, `TFPipelineData`), the input and output graphs, and crucial builder objects for creating Turbofan nodes and blocks (`machine`, `common`). The `Run()` method is a strong indicator of the core functionality.

3. **Analyze the `Run()` Method:** The steps within `Run()` are critical:
    * Creating basic blocks in the Turbofan schedule based on the input graph's blocks.
    * Setting up the start and end nodes of the Turbofan graph.
    * Iterating through the operations in each block of the input graph and calling `ProcessOperation`.
    * Handling loop phis (merging values at loop entry).
    * Computing RPO (Reverse Postorder) and dominator tree for the Turbofan schedule.

4. **Examine the `ProcessOperation()` Method:** This method is the workhorse. The `switch` statement based on `op.opcode` confirms its role in translating different `turboshaft` operations into their Turbofan equivalents. The `TURBOSHAFT_OPERATION_LIST` macro indicates a systematic handling of various operation types.

5. **Identify Helper Methods:**  Methods like `MakeNode`, `AddNode`, `GetNode`, and the various `IntPtr...` helper functions suggest utility functions for creating and managing nodes in the Turbofan graph. The numerous specific `ProcessOperation` overloads for different operation types (e.g., `WordBinopOp`, `FloatBinopOp`) further detail the translation process.

6. **Infer the Overall Goal:** Based on the above observations, the primary function seems to be *recreating* a `compiler::Schedule` and `compiler::Graph` (Turbofan's representation) from a `turboshaft::Graph`. This likely happens after some initial optimization or transformation stages within the Turboshaft pipeline.

7. **Consider the File Name:** `recreate-schedule.cc` directly reinforces the idea of reconstructing a schedule.

8. **Address the Specific Questions from the Prompt:**
    * **File extension:** The code snippet is `.cc`, so it's C++, not Torque.
    * **Relationship to JavaScript:** While the code itself is C++, it's part of V8, the JavaScript engine. The transformations happening here are ultimately about optimizing JavaScript code.
    * **Code logic and assumptions:** The `ProcessOperation` methods contain the core logic. The assumption is that the input `turboshaft::Graph` represents valid code that can be translated into a Turbofan graph. Input would be a `turboshaft::Graph`, and output would be a `compiler::Graph` and `compiler::Schedule`.
    * **User programming errors:**  This level of compiler code isn't directly related to *user* programming errors. It deals with internal representations and optimizations.
    * **Functionality Summary:** Combine the above points into a concise summary.

9. **Refine the Summary:**  Ensure the summary accurately captures the key aspects: the input and output, the core process of translating operations, the purpose within the Turboshaft pipeline, and the connection to Turbofan.

By following these steps, I can systematically analyze the code and extract its core functionality, leading to the provided summary. The key is to look for structural elements, naming conventions, and the overall flow of data and transformations within the code.
Based on the provided C++ source code for `v8/src/compiler/turboshaft/recreate-schedule.cc`, here's a breakdown of its functionality:

**Core Functionality:**

The primary function of `recreate-schedule.cc` is to **reconstruct a Turbofan schedule and graph from a Turboshaft graph**. Essentially, it bridges the gap between Turboshaft's intermediate representation and Turbofan's representation, enabling further optimization and code generation by Turbofan.

**Key Aspects and Functionalities:**

* **Input:** Takes a `turboshaft::Graph` (represented by `input_graph`) as input. This graph is the output of previous phases within the Turboshaft compiler pipeline.
* **Output:** Creates a `compiler::Graph` (represented by `tf_graph`) and a `compiler::Schedule` (represented by `schedule`), which are the data structures used by Turbofan.
* **Translation of Operations:** The code iterates through each operation (`Operation`) in the Turboshaft graph and translates it into corresponding nodes in the Turbofan graph. This translation is handled by the `ProcessOperation` method and its specialized overloads for different operation types (e.g., `WordBinopOp`, `FloatBinopOp`, `ChangeOp`).
* **Basic Block Mapping:**  It maps the basic blocks from the Turboshaft graph to basic blocks in the Turbofan schedule.
* **Node Creation:** It uses `compiler::MachineOperatorBuilder` and `compiler::CommonOperatorBuilder` to create the necessary Turbofan nodes, representing machine-level operations.
* **Handling Different Operation Types:** The `ProcessOperation` method uses a switch statement to handle various Turboshaft operation types, creating the appropriate Turbofan nodes with the correct inputs. It handles arithmetic operations, bitwise operations, floating-point operations, type conversions, comparisons, and more.
* **Lowering to Machine Operations:**  Many of the `ProcessOperation` methods directly translate Turboshaft's higher-level operations into lower-level machine-specific operations that Turbofan understands.
* **Loop Phi Handling:** The code identifies and correctly links loop phi operations, which are crucial for representing values that change across loop iterations.
* **Schedule Finalization:** After processing all operations, it computes the reverse postorder (RPO) and dominator tree for the newly created Turbofan schedule, which are essential for subsequent compiler passes.

**Regarding the questions:**

* **File Extension:** The code snippet shows `.cc`, indicating it's a **C++ source file**, not a Torque file (`.tq`).

* **Relationship to Javascript:** This code is **indirectly related to Javascript**. Turboshaft and Turbofan are components of the V8 JavaScript engine's optimizing compiler. They take the initial bytecode generated from JavaScript code and perform various optimizations to generate efficient machine code. This file is part of that optimization pipeline.

* **Javascript Example (Illustrative):** While this C++ code doesn't directly execute JavaScript, the transformations it performs are on the *internal representation* of JavaScript code. For example, a simple JavaScript addition:

   ```javascript
   function add(a, b) {
     return a + b;
   }
   ```

   Internally, Turboshaft might represent the `a + b` operation as an `AddOp`. This `recreate-schedule.cc` file would then translate that `AddOp` into a corresponding machine-level addition instruction (e.g., `machine.Int32Add()` or `machine.Float64Add()`) in the Turbofan graph.

* **Code Logic Inference (Hypothetical):**

   **Assumption:** The input `turboshaft::Graph` contains a basic block with a `WordBinopOp` representing the addition of two 32-bit integers.

   **Input (Conceptual Turboshaft Representation):**
   ```
   Block 0:
     Op1: Parameter(0, Int32) -> ValueA
     Op2: Parameter(1, Int32) -> ValueB
     Op3: WordBinop(ValueA, ValueB, Add, Word32) -> Result
     Op4: Return(Result)
   ```

   **Output (Conceptual Turbofan Representation):**
   ```
   BasicBlock BB0:
     Node1: Parameter(0)
     Node2: Parameter(1)
     Node3: Int32Add(Node1, Node2)
     Node4: Return(Node3)
   ```

   The `ProcessOperation(const WordBinopOp& op)` method (specifically the case for `Kind::kAdd` and `WordRepresentation::Word32()`) would be responsible for creating the `Int32Add` node in the Turbofan graph.

* **User Programming Errors:** This code doesn't directly prevent user programming errors in JavaScript. Its role is in optimizing the code *after* it's been written. However, the compiler's ability to reason about types and operations can sometimes indirectly expose potential issues (e.g., type mismatches that might lead to deoptimizations).

**Summary of Functionality (Part 1):**

The `v8/src/compiler/turboshaft/recreate-schedule.cc` file is responsible for the crucial task of **reconstructing a Turbofan-compatible schedule and graph from a Turboshaft graph**. It acts as a translator, converting Turboshaft's operations and control flow into the corresponding Turbofan representations. This process is essential for enabling Turbofan's subsequent optimization passes and code generation within the V8 JavaScript engine.

### 提示词
```
这是目录为v8/src/compiler/turboshaft/recreate-schedule.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/recreate-schedule.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turboshaft/recreate-schedule.h"

#include "src/base/logging.h"
#include "src/base/safe_conversions.h"
#include "src/base/small-vector.h"
#include "src/base/template-utils.h"
#include "src/base/vector.h"
#include "src/codegen/callable.h"
#include "src/codegen/machine-type.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/feedback-source.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/linkage.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-origin-table.h"
#include "src/compiler/phase.h"
#include "src/compiler/pipeline-data-inl.h"
#include "src/compiler/schedule.h"
#include "src/compiler/scheduler.h"
#include "src/compiler/turbofan-graph.h"
#include "src/compiler/turboshaft/deopt-data.h"
#include "src/compiler/turboshaft/graph.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/compiler/write-barrier-kind.h"
#include "src/utils/utils.h"
#include "src/zone/zone-containers.h"

namespace v8::internal::compiler::turboshaft {

namespace {

struct ScheduleBuilder {
  PipelineData* data;
  CallDescriptor* call_descriptor;
  Zone* phase_zone;
  compiler::TFPipelineData* turbofan_data;

  const Graph& input_graph = data->graph();
  JSHeapBroker* broker = data->broker();
  Zone* graph_zone = turbofan_data->graph_zone();
  SourcePositionTable* source_positions = turbofan_data->source_positions();
  NodeOriginTable* origins = turbofan_data->node_origins();

  Schedule* const schedule = turbofan_data->schedule();
  compiler::Graph* const tf_graph = turbofan_data->graph();
  compiler::MachineOperatorBuilder& machine = *turbofan_data->machine();
  compiler::CommonOperatorBuilder& common = *turbofan_data->common();

  compiler::BasicBlock* current_block = schedule->start();
  const Block* current_input_block = nullptr;
  ZoneAbslFlatHashMap<int, Node*> parameters{phase_zone};
  ZoneAbslFlatHashMap<int, Node*> osr_values{phase_zone};
  std::vector<BasicBlock*> blocks = {};
  std::vector<Node*> nodes{input_graph.op_id_count()};
  std::vector<std::pair<Node*, OpIndex>> loop_phis = {};

  RecreateScheduleResult Run();
  Node* MakeNode(const Operator* op, base::Vector<Node* const> inputs);
  Node* MakeNode(const Operator* op, std::initializer_list<Node*> inputs) {
    return MakeNode(op, base::VectorOf(inputs));
  }
  Node* AddNode(const Operator* op, base::Vector<Node* const> inputs);
  Node* AddNode(const Operator* op, std::initializer_list<Node*> inputs) {
    return AddNode(op, base::VectorOf(inputs));
  }
  Node* GetNode(OpIndex i) { return nodes[i.id()]; }
  BasicBlock* GetBlock(const Block& block) {
    return blocks[block.index().id()];
  }
  Node* IntPtrConstant(intptr_t value) {
    return AddNode(machine.Is64() ? common.Int64Constant(value)
                                  : common.Int32Constant(
                                        base::checked_cast<int32_t>(value)),
                   {});
  }
  Node* IntPtrAdd(Node* a, Node* b) {
    return AddNode(machine.Is64() ? machine.Int64Add() : machine.Int32Add(),
                   {a, b});
  }
  Node* IntPtrShl(Node* a, Node* b) {
    return AddNode(machine.Is64() ? machine.Word64Shl() : machine.Word32Shl(),
                   {a, b});
  }
  Node* RelocatableIntPtrConstant(intptr_t value, RelocInfo::Mode mode) {
    return AddNode(machine.Is64()
                       ? common.RelocatableInt64Constant(value, mode)
                       : common.RelocatableInt32Constant(
                             base::checked_cast<int32_t>(value), mode),
                   {});
  }
  void ProcessOperation(const Operation& op);
#define DECL_PROCESS_OPERATION(Name) Node* ProcessOperation(const Name##Op& op);
  TURBOSHAFT_OPERATION_LIST(DECL_PROCESS_OPERATION)
#undef DECL_PROCESS_OPERATION

  std::pair<Node*, MachineType> BuildDeoptInput(FrameStateData::Iterator* it);
  Node* BuildStateValues(FrameStateData::Iterator* it, int32_t size);
  Node* BuildTaggedInput(FrameStateData::Iterator* it);
};

Node* ScheduleBuilder::MakeNode(const Operator* op,
                                base::Vector<Node* const> inputs) {
  Node* node = tf_graph->NewNodeUnchecked(op, static_cast<int>(inputs.size()),
                                          inputs.data());
  return node;
}
Node* ScheduleBuilder::AddNode(const Operator* op,
                               base::Vector<Node* const> inputs) {
  DCHECK_NOT_NULL(current_block);
  Node* node = MakeNode(op, inputs);
  schedule->AddNode(current_block, node);
  return node;
}

RecreateScheduleResult ScheduleBuilder::Run() {
  DCHECK_GE(input_graph.block_count(), 1);
  blocks.reserve(input_graph.block_count());
  blocks.push_back(current_block);
  for (size_t i = 1; i < input_graph.block_count(); ++i) {
    blocks.push_back(schedule->NewBasicBlock());
  }
  // The value output count of the start node does not actually matter.
  tf_graph->SetStart(tf_graph->NewNode(common.Start(0)));
  tf_graph->SetEnd(tf_graph->NewNode(common.End(0)));

  for (const Block& block : input_graph.blocks()) {
    current_input_block = &block;
    current_block = GetBlock(block);
    for (OpIndex op : input_graph.OperationIndices(block)) {
      DCHECK_NOT_NULL(current_block);
      ProcessOperation(input_graph.Get(op));
    }
  }

  for (auto& p : loop_phis) {
    p.first->ReplaceInput(1, GetNode(p.second));
  }

  DCHECK(schedule->rpo_order()->empty());
  Scheduler::ComputeSpecialRPO(phase_zone, schedule);
  // Note that Scheduler::GenerateDominatorTree also infers which blocks are
  // deferred, so we only need to set branch targets as deferred based on the
  // hints, and we let Scheduler::GenerateDominatorTree propagate this
  // information to other blocks.
  Scheduler::GenerateDominatorTree(schedule);
  return {tf_graph, schedule};
}

void ScheduleBuilder::ProcessOperation(const Operation& op) {
  if (!turboshaft::ShouldSkipOptimizationStep() && ShouldSkipOperation(op)) {
    return;
  }
  Node* node;
  switch (op.opcode) {
#define SWITCH_CASE(Name)                         \
  case Opcode::k##Name:                           \
    node = ProcessOperation(op.Cast<Name##Op>()); \
    break;
    TURBOSHAFT_OPERATION_LIST(SWITCH_CASE)
#undef SWITCH_CASE
  }
  OpIndex index = input_graph.Index(op);
  DCHECK_LT(index.id(), nodes.size());
  nodes[index.id()] = node;
  if (source_positions && source_positions->IsEnabled() && node) {
    source_positions->SetSourcePosition(node,
                                        input_graph.source_positions()[index]);
  }
  if (origins && node) {
    origins->SetNodeOrigin(node->id(), index.id());
  }
}

#define SHOULD_HAVE_BEEN_LOWERED(op) \
  Node* ScheduleBuilder::ProcessOperation(const op##Op&) { UNREACHABLE(); }
// These operations should have been lowered in previous reducers already.
TURBOSHAFT_JS_OPERATION_LIST(SHOULD_HAVE_BEEN_LOWERED)
TURBOSHAFT_SIMPLIFIED_OPERATION_LIST(SHOULD_HAVE_BEEN_LOWERED)
TURBOSHAFT_OTHER_OPERATION_LIST(SHOULD_HAVE_BEEN_LOWERED)
TURBOSHAFT_WASM_OPERATION_LIST(SHOULD_HAVE_BEEN_LOWERED)
SHOULD_HAVE_BEEN_LOWERED(Dead)
#undef SHOULD_HAVE_BEEN_LOWERED

Node* ScheduleBuilder::ProcessOperation(const WordBinopOp& op) {
  using Kind = WordBinopOp::Kind;
  const Operator* o;
  switch (op.rep.value()) {
    case WordRepresentation::Word32():
      switch (op.kind) {
        case Kind::kAdd:
          o = machine.Int32Add();
          break;
        case Kind::kSub:
          o = machine.Int32Sub();
          break;
        case Kind::kMul:
          o = machine.Int32Mul();
          break;
        case Kind::kSignedMulOverflownBits:
          o = machine.Int32MulHigh();
          break;
        case Kind::kUnsignedMulOverflownBits:
          o = machine.Uint32MulHigh();
          break;
        case Kind::kSignedDiv:
          o = machine.Int32Div();
          break;
        case Kind::kUnsignedDiv:
          o = machine.Uint32Div();
          break;
        case Kind::kSignedMod:
          o = machine.Int32Mod();
          break;
        case Kind::kUnsignedMod:
          o = machine.Uint32Mod();
          break;
        case Kind::kBitwiseAnd:
          o = machine.Word32And();
          break;
        case Kind::kBitwiseOr:
          o = machine.Word32Or();
          break;
        case Kind::kBitwiseXor:
          o = machine.Word32Xor();
          break;
      }
      break;
    case WordRepresentation::Word64():
      switch (op.kind) {
        case Kind::kAdd:
          o = machine.Int64Add();
          break;
        case Kind::kSub:
          o = machine.Int64Sub();
          break;
        case Kind::kMul:
          o = machine.Int64Mul();
          break;
        case Kind::kSignedDiv:
          o = machine.Int64Div();
          break;
        case Kind::kUnsignedDiv:
          o = machine.Uint64Div();
          break;
        case Kind::kSignedMod:
          o = machine.Int64Mod();
          break;
        case Kind::kUnsignedMod:
          o = machine.Uint64Mod();
          break;
        case Kind::kBitwiseAnd:
          o = machine.Word64And();
          break;
        case Kind::kBitwiseOr:
          o = machine.Word64Or();
          break;
        case Kind::kBitwiseXor:
          o = machine.Word64Xor();
          break;
        case Kind::kSignedMulOverflownBits:
          o = machine.Int64MulHigh();
          break;
        case Kind::kUnsignedMulOverflownBits:
          o = machine.Uint64MulHigh();
          break;
      }
      break;
    default:
      UNREACHABLE();
  }
  return AddNode(o, {GetNode(op.left()), GetNode(op.right())});
}
Node* ScheduleBuilder::ProcessOperation(const FloatBinopOp& op) {
  using Kind = FloatBinopOp::Kind;
  const Operator* o;
  switch (op.rep.value()) {
    case FloatRepresentation::Float32():
      switch (op.kind) {
        case Kind::kAdd:
          o = machine.Float32Add();
          break;
        case Kind::kSub:
          o = machine.Float32Sub();
          break;
        case Kind::kMul:
          o = machine.Float32Mul();
          break;
        case Kind::kDiv:
          o = machine.Float32Div();
          break;
        case Kind::kMin:
          o = machine.Float32Min();
          break;
        case Kind::kMax:
          o = machine.Float32Max();
          break;
        case Kind::kPower:
        case Kind::kAtan2:
        case Kind::kMod:
          UNREACHABLE();
      }
      break;
    case FloatRepresentation::Float64():
      switch (op.kind) {
        case Kind::kAdd:
          o = machine.Float64Add();
          break;
        case Kind::kSub:
          o = machine.Float64Sub();
          break;
        case Kind::kMul:
          o = machine.Float64Mul();
          break;
        case Kind::kDiv:
          o = machine.Float64Div();
          break;
        case Kind::kMod:
          o = machine.Float64Mod();
          break;
        case Kind::kMin:
          o = machine.Float64Min();
          break;
        case Kind::kMax:
          o = machine.Float64Max();
          break;
        case Kind::kPower:
          o = machine.Float64Pow();
          break;
        case Kind::kAtan2:
          o = machine.Float64Atan2();
          break;
      }
      break;
    default:
      UNREACHABLE();
  }
  return AddNode(o, {GetNode(op.left()), GetNode(op.right())});
}

Node* ScheduleBuilder::ProcessOperation(const OverflowCheckedBinopOp& op) {
  const Operator* o;
  switch (op.rep.value()) {
    case WordRepresentation::Word32():
      switch (op.kind) {
        case OverflowCheckedBinopOp::Kind::kSignedAdd:
          o = machine.Int32AddWithOverflow();
          break;
        case OverflowCheckedBinopOp::Kind::kSignedSub:
          o = machine.Int32SubWithOverflow();
          break;
        case OverflowCheckedBinopOp::Kind::kSignedMul:
          o = machine.Int32MulWithOverflow();
          break;
      }
      break;
    case WordRepresentation::Word64():
      switch (op.kind) {
        case OverflowCheckedBinopOp::Kind::kSignedAdd:
          o = machine.Int64AddWithOverflow();
          break;
        case OverflowCheckedBinopOp::Kind::kSignedSub:
          o = machine.Int64SubWithOverflow();
          break;
        case OverflowCheckedBinopOp::Kind::kSignedMul:
          o = machine.Int64MulWithOverflow();
          break;
      }
      break;
    default:
      UNREACHABLE();
  }
  return AddNode(o, {GetNode(op.left()), GetNode(op.right())});
}
Node* ScheduleBuilder::ProcessOperation(const WordUnaryOp& op) {
  bool word64 = op.rep == WordRepresentation::Word64();
  const Operator* o;
  switch (op.kind) {
    case WordUnaryOp::Kind::kReverseBytes:
      o = word64 ? machine.Word64ReverseBytes() : machine.Word32ReverseBytes();
      break;
    case WordUnaryOp::Kind::kCountLeadingZeros:
      o = word64 ? machine.Word64Clz() : machine.Word32Clz();
      break;
    case WordUnaryOp::Kind::kCountTrailingZeros:
      o = word64 ? machine.Word64Ctz().op() : machine.Word32Ctz().op();
      break;
    case WordUnaryOp::Kind::kPopCount:
      o = word64 ? machine.Word64Popcnt().op() : machine.Word32Popcnt().op();
      break;
    case WordUnaryOp::Kind::kSignExtend8:
      o = word64 ? machine.SignExtendWord8ToInt64()
                 : machine.SignExtendWord8ToInt32();
      break;
    case WordUnaryOp::Kind::kSignExtend16:
      o = word64 ? machine.SignExtendWord16ToInt64()
                 : machine.SignExtendWord16ToInt32();
      break;
  }
  return AddNode(o, {GetNode(op.input())});
}

Node* ScheduleBuilder::ProcessOperation(const OverflowCheckedUnaryOp& op) {
  bool word64 = op.rep == WordRepresentation::Word64();
  const Operator* o;
  switch (op.kind) {
    case OverflowCheckedUnaryOp::Kind::kAbs:
      o = word64 ? machine.Int64AbsWithOverflow().op()
                 : machine.Int32AbsWithOverflow().op();
  }
  return AddNode(o, {GetNode(op.input())});
}

Node* ScheduleBuilder::ProcessOperation(const FloatUnaryOp& op) {
  DCHECK(FloatUnaryOp::IsSupported(op.kind, op.rep));
  bool float64 = op.rep == FloatRepresentation::Float64();
  const Operator* o;
  switch (op.kind) {
    case FloatUnaryOp::Kind::kAbs:
      o = float64 ? machine.Float64Abs() : machine.Float32Abs();
      break;
    case FloatUnaryOp::Kind::kNegate:
      o = float64 ? machine.Float64Neg() : machine.Float32Neg();
      break;
    case FloatUnaryOp::Kind::kRoundDown:
      o = float64 ? machine.Float64RoundDown().op()
                  : machine.Float32RoundDown().op();
      break;
    case FloatUnaryOp::Kind::kRoundUp:
      o = float64 ? machine.Float64RoundUp().op()
                  : machine.Float32RoundUp().op();
      break;
    case FloatUnaryOp::Kind::kRoundToZero:
      o = float64 ? machine.Float64RoundTruncate().op()
                  : machine.Float32RoundTruncate().op();
      break;
    case FloatUnaryOp::Kind::kRoundTiesEven:
      o = float64 ? machine.Float64RoundTiesEven().op()
                  : machine.Float32RoundTiesEven().op();
      break;
    case FloatUnaryOp::Kind::kSqrt:
      o = float64 ? machine.Float64Sqrt() : machine.Float32Sqrt();
      break;
    case FloatUnaryOp::Kind::kSilenceNaN:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64SilenceNaN();
      break;
    case FloatUnaryOp::Kind::kLog:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Log();
      break;
    case FloatUnaryOp::Kind::kExp:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Exp();
      break;
    case FloatUnaryOp::Kind::kExpm1:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Expm1();
      break;
    case FloatUnaryOp::Kind::kSin:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Sin();
      break;
    case FloatUnaryOp::Kind::kCos:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Cos();
      break;
    case FloatUnaryOp::Kind::kAsin:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Asin();
      break;
    case FloatUnaryOp::Kind::kAcos:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Acos();
      break;
    case FloatUnaryOp::Kind::kSinh:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Sinh();
      break;
    case FloatUnaryOp::Kind::kCosh:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Cosh();
      break;
    case FloatUnaryOp::Kind::kAsinh:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Asinh();
      break;
    case FloatUnaryOp::Kind::kAcosh:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Acosh();
      break;
    case FloatUnaryOp::Kind::kTan:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Tan();
      break;
    case FloatUnaryOp::Kind::kTanh:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Tanh();
      break;
    case FloatUnaryOp::Kind::kLog2:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Log2();
      break;
    case FloatUnaryOp::Kind::kLog10:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Log10();
      break;
    case FloatUnaryOp::Kind::kLog1p:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Log1p();
      break;
    case FloatUnaryOp::Kind::kAtan:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Atan();
      break;
    case FloatUnaryOp::Kind::kAtanh:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Atanh();
      break;
    case FloatUnaryOp::Kind::kCbrt:
      DCHECK_EQ(op.rep, FloatRepresentation::Float64());
      o = machine.Float64Cbrt();
      break;
  }
  return AddNode(o, {GetNode(op.input())});
}
Node* ScheduleBuilder::ProcessOperation(const ShiftOp& op) {
  DCHECK(op.rep == WordRepresentation::Word32() ||
         op.rep == WordRepresentation::Word64());
  bool word64 = op.rep == WordRepresentation::Word64();
  Node* right = GetNode(op.right());
  if (word64) {
    // In Turboshaft's ShiftOp, the right hand side always has Word32
    // representation, so for 64 bit shifts, we have to zero-extend when
    // constructing Turbofan.
    if (const ConstantOp* constant =
            input_graph.Get(op.right()).TryCast<Opmask::kWord32Constant>()) {
      int64_t value = static_cast<int64_t>(constant->word32());
      right = AddNode(common.Int64Constant(value), {});
    } else {
      right = AddNode(machine.ChangeUint32ToUint64(), {right});
    }
  }
  const Operator* o;
  switch (op.kind) {
    case ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros:
      o = word64 ? machine.Word64SarShiftOutZeros()
                 : machine.Word32SarShiftOutZeros();
      break;
    case ShiftOp::Kind::kShiftRightArithmetic:
      o = word64 ? machine.Word64Sar() : machine.Word32Sar();
      break;
    case ShiftOp::Kind::kShiftRightLogical:
      o = word64 ? machine.Word64Shr() : machine.Word32Shr();
      break;
    case ShiftOp::Kind::kShiftLeft:
      o = word64 ? machine.Word64Shl() : machine.Word32Shl();
      break;
    case ShiftOp::Kind::kRotateLeft:
      o = word64 ? machine.Word64Rol().op() : machine.Word32Rol().op();
      break;
    case ShiftOp::Kind::kRotateRight:
      o = word64 ? machine.Word64Ror() : machine.Word32Ror();
      break;
  }
  return AddNode(o, {GetNode(op.left()), right});
}
Node* ScheduleBuilder::ProcessOperation(const ComparisonOp& op) {
  const Operator* o;
  switch (op.rep.value()) {
    case RegisterRepresentation::Word32():
      switch (op.kind) {
        case ComparisonOp::Kind::kEqual:
          o = machine.Word32Equal();
          break;
        case ComparisonOp::Kind::kSignedLessThan:
          o = machine.Int32LessThan();
          break;
        case ComparisonOp::Kind::kSignedLessThanOrEqual:
          o = machine.Int32LessThanOrEqual();
          break;
        case ComparisonOp::Kind::kUnsignedLessThan:
          o = machine.Uint32LessThan();
          break;
        case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
          o = machine.Uint32LessThanOrEqual();
          break;
      }
      break;
    case RegisterRepresentation::Word64():
      switch (op.kind) {
        case ComparisonOp::Kind::kEqual:
          o = machine.Word64Equal();
          break;
        case ComparisonOp::Kind::kSignedLessThan:
          o = machine.Int64LessThan();
          break;
        case ComparisonOp::Kind::kSignedLessThanOrEqual:
          o = machine.Int64LessThanOrEqual();
          break;
        case ComparisonOp::Kind::kUnsignedLessThan:
          o = machine.Uint64LessThan();
          break;
        case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
          o = machine.Uint64LessThanOrEqual();
          break;
      }
      break;
    case RegisterRepresentation::Float32():
      switch (op.kind) {
        case ComparisonOp::Kind::kEqual:
          o = machine.Float32Equal();
          break;
        case ComparisonOp::Kind::kSignedLessThan:
          o = machine.Float32LessThan();
          break;
        case ComparisonOp::Kind::kSignedLessThanOrEqual:
          o = machine.Float32LessThanOrEqual();
          break;
        case ComparisonOp::Kind::kUnsignedLessThan:
        case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
          UNREACHABLE();
      }
      break;
    case RegisterRepresentation::Float64():
      switch (op.kind) {
        case ComparisonOp::Kind::kEqual:
          o = machine.Float64Equal();
          break;
        case ComparisonOp::Kind::kSignedLessThan:
          o = machine.Float64LessThan();
          break;
        case ComparisonOp::Kind::kSignedLessThanOrEqual:
          o = machine.Float64LessThanOrEqual();
          break;
        case ComparisonOp::Kind::kUnsignedLessThan:
        case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
          UNREACHABLE();
      }
      break;
    case RegisterRepresentation::Tagged():
      switch (op.kind) {
        case ComparisonOp::Kind::kEqual:
          o = machine.TaggedEqual();
          break;
        case ComparisonOp::Kind::kSignedLessThan:
        case ComparisonOp::Kind::kSignedLessThanOrEqual:
        case ComparisonOp::Kind::kUnsignedLessThan:
        case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
          UNREACHABLE();
      }
      break;
    default:
      UNREACHABLE();
  }
  return AddNode(o, {GetNode(op.left()), GetNode(op.right())});
}
Node* ScheduleBuilder::ProcessOperation(const ChangeOp& op) {
  const Operator* o;
  switch (op.kind) {
    using Kind = ChangeOp::Kind;
    using Assumption = ChangeOp::Assumption;
    case Kind::kFloatConversion:
      if (op.from == FloatRepresentation::Float64() &&
          op.to == FloatRepresentation::Float32()) {
        o = machine.TruncateFloat64ToFloat32();
      } else if (op.from == FloatRepresentation::Float32() &&
                 op.to == FloatRepresentation::Float64()) {
        o = machine.ChangeFloat32ToFloat64();
      } else {
        UNIMPLEMENTED();
      }
      break;
    case Kind::kSignedFloatTruncateOverflowToMin:
    case Kind::kUnsignedFloatTruncateOverflowToMin: {
      bool is_signed = op.kind == Kind::kSignedFloatTruncateOverflowToMin;
      if (op.assumption == Assumption::kReversible) {
        if (op.from == FloatRepresentation::Float64() &&
            op.to == WordRepresentation::Word64()) {
          o = is_signed ? machine.ChangeFloat64ToInt64()
                        : machine.ChangeFloat64ToUint64();
        } else if (op.from == FloatRepresentation::Float64() &&
                   op.to == WordRepresentation::Word32()) {
          o = is_signed ? machine.ChangeFloat64ToInt32()
                        : machine.ChangeFloat64ToUint32();
        } else {
          UNIMPLEMENTED();
        }
        break;
      }
      TruncateKind truncate_kind;
      switch (op.assumption) {
        case ChangeOp::Assumption::kReversible:
          UNREACHABLE();
        case ChangeOp::Assumption::kNoAssumption:
          truncate_kind = TruncateKind::kSetOverflowToMin;
          break;
        case ChangeOp::Assumption::kNoOverflow:
          truncate_kind = TruncateKind::kArchitectureDefault;
          break;
      }
      if (op.from == FloatRepresentation::Float64() &&
          op.to == WordRepresentation::Word64()) {
        DCHECK(is_signed);
        o = machine.TruncateFloat64ToInt64(truncate_kind);
      } else if (op.from == FloatRepresentation::Float64() &&
                 op.to == WordRepresentation::Word32()) {
        if (is_signed) {
          DCHECK_EQ(truncate_kind, TruncateKind::kArchitectureDefault);
          o = machine.RoundFloat64ToInt32();
        } else {
          o = machine.TruncateFloat64ToUint32();
        }
      } else if (op.from == FloatRepresentation::Float32() &&
                 op.to == WordRepresentation::Word32()) {
        o = is_signed ? machine.TruncateFloat32ToInt32(truncate_kind)
                      : machine.TruncateFloat32ToUint32(truncate_kind);
      } else {
        UNIMPLEMENTED();
      }
      break;
    }
    case Kind::kJSFloatTruncate:
      if (op.from == FloatRepresentation::Float64() &&
          op.to == WordRepresentation::Word32()) {
        o = machine.TruncateFloat64ToWord32();
      } else {
        UNIMPLEMENTED();
      }
      break;
    case Kind::kJSFloat16TruncateWithBitcast:
      if (op.from == FloatRepresentation::Float64() &&
          op.to == WordRepresentation::Word32()) {
        o = machine.TruncateFloat64ToFloat16RawBits().placeholder();
      } else {
        UNIMPLEMENTED();
      }
      break;
    case Kind::kSignedToFloat:
      if (op.from == WordRepresentation::Word32() &&
          op.to == FloatRepresentation::Float64()) {
        DCHECK_EQ(op.assumption, Assumption::kNoAssumption);
        o = machine.ChangeInt32ToFloat64();
      } else if (op.from == WordRepresentation::Word64() &&
                 op.to == FloatRepresentation::Float64()) {
        o = op.assumption == Assumption::kReversible
                ? machine.ChangeInt64ToFloat64()
                : machine.RoundInt64ToFloat64();
      } else if (op.from == WordRepresentation::Word32() &&
                 op.to == FloatRepresentation::Float32()) {
        o = machine.RoundInt32ToFloat32();
      } else if (op.from == WordRepresentation::Word64() &&
                 op.to == FloatRepresentation::Float32()) {
        o = machine.RoundInt64ToFloat32();
      } else {
        UNIMPLEMENTED();
      }
      break;
    case Kind::kUnsignedToFloat:
      if (op.from == WordRepresentation::Word32() &&
          op.to == FloatRepresentation::Float64()) {
        o = machine.ChangeUint32ToFloat64();
      } else if (op.from == WordRepresentation::Word32() &&
                 op.to == FloatRepresentation::Float32()) {
        o = machine.RoundUint32ToFloat32();
      } else if (op.from == WordRepresentation::Word64() &&
                 op.to == FloatRepresentation::Float32()) {
        o = machine.RoundUint64ToFloat32();
      } else if (op.from == WordRepresentation::Word64() &&
                 op.to == FloatRepresentation::Float64()) {
        o = machine.RoundUint64ToFloat64();
      } else {
        UNIMPLEMENTED();
      }
      break;
    case Kind::kExtractHighHalf:
      DCHECK_EQ(op.from, FloatRepresentation::Float64());
      DCHECK_EQ(op.to, WordRepresentation::Word32());
      o = machine.Float64ExtractHighWord32();
      break;
    case Kind::kExtractLowHalf:
      DCHECK_EQ(op.from, FloatRepresentation::Float64());
      DCHECK_EQ(op.to, WordRepresentation::Word32());
      o = machine.Float64ExtractLowWord32();
      break;
    case Kind::kBitcast:
      if (op.from == WordRepresentation::Word32() &&
          op.to == WordRepresentation::Word64()) {
        o = machine.BitcastWord32ToWord64();
      } else if (op.from == FloatRepresentation::Float32() &&
                 op.to == WordRepresentation::Word32()) {
        o = machine.BitcastFloat32ToInt32();
      } else if (op.from == WordRepresentation::Word32() &&
                 op.to == FloatRepresentation::Float32()) {
        o = machine.BitcastInt32ToFloat32();
      } else if (op.from == FloatRepresentation::Float64() &&
                 op.to == WordRepresentation::Word64()) {
        o = machine.BitcastFloat64ToInt64();
      } else if (op.from == WordRepresentation::Word64() &&
                 op.to == FloatRepresentation::Float64()) {
        o = machine.BitcastInt64ToFloat64();
      } else {
        UNIMPLEMENTED();
      }
      break;
    case Kind::kSignExtend:
      if (op.from == WordRepresentation::Word32() &&
          op.to == WordRepresentation::Word64()) {
        o = machine.ChangeInt32ToInt64();
      } else {
        UNIMPLEMENTED();
      }
      break;
    case Kind::kZeroExtend:
      if (op.from == WordRepresentation::Word32() &&
          op.to == WordRepresentation::Word64()) {
        o = machine.ChangeUint32ToUint64();
      } else {
        UNIMPLEMENTED();
      }
      break;
    case Kind::kTruncate:
      if (op.from == WordRepresentation::Word64() &&
          op.to == WordRepresentation::Word32()) {
        o = machine.TruncateInt64ToInt32();
      } else {
        UNIMPLEMENTED();
      }
  }
  return AddNode(o, {GetNode(op.input())});
}
Node* ScheduleBuilder::ProcessOperation(const TryChangeOp& op) {
  const Operator* o;
  switch (op.kind) {
    using Kind = TryChangeOp::Kind;
    case Kind::kSignedFloatTruncateOverflowUndefined:
      if (op.from == FloatRepresentation::Float64() &&
          op.to == WordRepresentation::Word64()) {
        o = machine.TryTruncateFloat64ToInt64();
      } else if (op.from == FloatRepresentation::Float64() &&
                 op.to == WordRepresentation::Word32()) {
        o = machine.TryTruncateFloat64ToInt32();
      } else if (op.from == FloatRepresentation::Float32() &&
                 op.to == WordRepresentation::Word64()) {
        o = machine.TryTruncateFloat32ToInt64();
      } else {
        UNREACHABLE();
      }
      break;
    case Kind::kUnsignedFloatTruncateOverflowUndefined:
      if (op.from == FloatRepresentation::Float64() &&
          op.to == WordRepresentation::Word64()) {
        o = machine.TryTruncateFloat64ToUint64();
      } else if (op.from == FloatRepresentation::Float64() &&
                 op.to == WordRepresentation::Word32()) {
        o = machine.TryTruncateFloat64ToUint32();
      } else if (op.from == FloatRepresentation::Float32() &&
                 op.to == WordRepresentation::Word64()) {
        o = machine.TryTruncateFloat32ToUint64();
      } else {
        UNREACHABLE();
      }
      break;
  }
  return AddNode(o, {GetNode(op.input())});
}
Node* ScheduleBuilder::ProcessOperation(
    const BitcastWord32PairToFloat64Op& op) {
  Node* temp = AddNode(
      machine.Float64InsertHighWord32(),
      {AddNode(common.Float64Constant(0), {}), GetNode(op.high_word32())});
  return AddNode(machine.Float64InsertLowWord32(),
                 {temp, GetNode(op.low_word32())});
}
Node* ScheduleBuilder::ProcessOperation(const TaggedBitcastOp& op) {
  using Rep = RegisterRepresentation;
  const Operator* o;
  switch (multi(op.from, op.to)) {
    case multi(Rep::Tagged(), Rep::Word32()):
      if constexpr (Is64()) {
        DCHECK_EQ(op.kind, TaggedBitcastOp::Kind::kSmi);
        DCHECK(SmiValuesAre31Bits());
        o = machine.TruncateInt64ToInt32();
      } else {
        o = machine.BitcastTaggedToWord();
      }
      break;
    case multi(Rep::Tagged(), Rep::Word64()):
      o = machine.BitcastTaggedToWord();
      break;
    case multi(Rep::Word32(), Rep::Tagged()):
    case multi(Rep::Word64(), Rep::Tagged()):
      if (op.kind == TaggedBitcastOp::Kind::kSmi) {
        o = machine.BitcastWordToTaggedSigned();
      } else {
        o = machine.BitcastWordToTagged();
      }
      break;
    case multi(Rep::Compressed(), Rep::Word32()):
      o = machine.BitcastTaggedToWord();
      break;
    default:
      UNIMPLEMENTED();
  }
  return AddNode(o, {GetNode(op.input())});
}
Node* ScheduleBuilder::ProcessOperation(const SelectOp& op) {
  // If there is a Select, then it should only be one that is supported by the
  // machine, and it should be meant to be implementation
```