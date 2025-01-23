Response: Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The immediate request is to summarize the functionality of `int64-lowering.cc`. The name itself gives a big hint: it's about "lowering" int64 operations. The "compiler" directory suggests this is part of the V8 compiler. The request also specifically asks about its relation to JavaScript and examples.

2. **Initial Code Scan - High-Level Structure:**  Quickly look at the includes. They reveal connections to:
    * Core compiler components (`common-operator.h`, `machine-operator.h`, `node.h`, `turbofan-graph.h`).
    * WebAssembly (`wasm-*`).
    * Platform architecture (`V8_TARGET_ARCH_32_BIT`).

3. **Focus on the Class:** The core of the file is the `Int64Lowering` class. This is where the main logic resides.

4. **Constructor Analysis:** The constructor takes key compiler components as arguments (`Graph`, `MachineOperatorBuilder`, etc.). This reinforces the idea that this is a compilation phase. The `replacements_` member and its allocation suggest a transformation process where nodes are being replaced.

5. **Key Method - `LowerGraph()`:** This is likely the entry point of the lowering process. The use of a stack and the `state_` array (for tracking visited nodes) points to a graph traversal algorithm, probably depth-first. The logic around `IrOpcode::kPhi`, `kEffectPhi`, and `kLoop` indicates handling of control flow structures.

6. **"Lowering" - What does it mean?** The term "lowering" in compiler contexts usually means translating higher-level operations into lower-level, more machine-specific instructions. The `#if V8_TARGET_ARCH_32_BIT` block strongly suggests this file deals with how 64-bit integers are handled on 32-bit architectures. This is because 32-bit architectures don't natively support 64-bit integer operations.

7. **Identify Core Lowering Strategies:**  Start looking at the `LowerNode()` method and the helper functions like `LowerLoadOperator`, `LowerStoreOperator`, and `LowerComparison`. Notice patterns:
    * **Splitting into Low and High Words:**  Many operations on `IrOpcode::kInt64Constant`, arithmetic operations, bitwise operations, and memory access are handled by splitting the 64-bit value into two 32-bit parts (low and high).
    * **Using Machine-Specific Operators:**  The code uses `machine()->Word32And()`, `machine()->Int32PairAdd()`, etc., indicating it's translating to machine-level operations.
    * **Handling Different Operation Types:** The `switch` statement in `LowerNode()` handles various IR opcodes differently, applying the appropriate lowering strategy for each.
    * **Projections for Multi-Value Returns:**  The code uses `ReplaceNodeWithProjections()` for operations like `kInt64Add` and `kCall`, where a 64-bit result is split into two 32-bit values.

8. **Connect to JavaScript:**  JavaScript's `Number` type can represent integers up to a certain limit (53 bits for safe integers). While JavaScript doesn't have explicit 64-bit integer types in the same way C++ does, there are scenarios where V8 might internally deal with 64-bit values, especially when interacting with WebAssembly or performing certain low-level operations. Think about how large integers are handled. This lowering process is crucial for making those operations work on 32-bit devices.

9. **Construct JavaScript Examples:** To illustrate the connection, think about:
    * **Large Integers:**  Demonstrate JavaScript's ability to handle large integers (though potentially with precision limitations).
    * **Bitwise Operations:** Show how bitwise operations might internally involve 64-bit representations.
    * **WebAssembly:** This is a strong connection, as WebAssembly *does* have explicit 64-bit integers. Show a simple WebAssembly example that uses i64 and how it might interact with JavaScript.

10. **Refine the Summary:**  Organize the findings into a coherent summary. Start with the core purpose, then elaborate on the key techniques used (splitting into low/high words, using machine operators). Explain *why* this is necessary (handling 64-bit integers on 32-bit architectures). Finally, connect it to JavaScript with relevant examples.

11. **Review and Iterate:**  Read through the summary and examples. Are they clear and accurate?  Is there anything missing?  For example, the role of the `replacements_` array in storing the lowered nodes is a crucial detail. Make sure to mention the conditional compilation based on `V8_TARGET_ARCH_32_BIT`.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This might be about optimizing int64 operations."  **Correction:** While optimization might be a side effect, the primary goal is *correctness* – making 64-bit operations work on platforms that don't natively support them.
* **Initial thought:** "The JavaScript connection is weak." **Correction:** Realize the importance of WebAssembly and how JavaScript interacts with it. Also, consider JavaScript's representation of large numbers and how they *might* be handled internally.
* **Focus on specific opcodes:** Initially, might get lost in the details of each `case` in `LowerNode()`. **Correction:** Step back and identify the *common patterns* of lowering rather than just listing every single opcode.

By following this kind of structured analysis, moving from high-level understanding to detailed examination, and constantly connecting back to the original request, you can effectively analyze and summarize complex code like this.
这个C++源代码文件 `int64-lowering.cc` 的主要功能是 **将 64 位整数（int64）操作在 32 位架构上进行转换（降低）**。

在 32 位架构上，CPU 无法直接执行 64 位整数的运算。因此，这个文件实现了一系列转换规则，将 64 位整数的操作分解为两个 32 位整数的操作，从而使得 V8 引擎能够在 32 位系统上正确处理 64 位整数。

**具体来说，它做了以下几件事：**

1. **识别 64 位整数操作:**  遍历 V8 的中间表示（IR）图，查找涉及 64 位整数的节点，例如 `kInt64Constant`, `kInt64Add`, `kWord64And` 等。

2. **拆分 64 位值:** 将 64 位整数值拆分成两个 32 位的值：低 32 位和高 32 位。

3. **转换操作:** 将 64 位整数的操作转换为对这两个 32 位值进行相应的 32 位操作。例如：
   -  64 位加法 (`kInt64Add`) 被转换为两个 32 位加法，并处理进位。
   -  64 位按位与 (`kWord64And`) 被转换为分别对低 32 位和高 32 位进行按位与。
   -  加载 64 位值 (`kLoad` with `MachineRepresentation::kWord64`) 被转换为加载两个 32 位值。

4. **处理函数调用和返回:** 当函数参数或返回值是 64 位整数时，会调整函数调用描述符（`CallDescriptor`）和签名（`Signature`），以便传递和接收两个 32 位的值。

5. **处理内存访问:**  对于涉及 64 位整数的内存加载和存储操作，会生成两个 32 位的加载或存储操作，分别访问内存中的低 32 位和高 32 位。

6. **支持原子操作:**  针对 64 位整数的原子操作，会将其转换为相应的 32 位原子操作对。

**与 JavaScript 的关系以及 JavaScript 示例：**

虽然 JavaScript 的 `Number` 类型主要用于表示浮点数和有限精度的整数（通常安全整数范围是 -2^53 到 2^53），但在以下场景中，V8 可能会在内部处理 64 位整数，并且 `int64-lowering.cc` 会发挥作用：

1. **WebAssembly (Wasm):** WebAssembly 具有显式的 64 位整数类型 (i64)。当 JavaScript 代码与 WebAssembly 模块交互，并且涉及到传递或接收 i64 类型的值时，V8 引擎需要能够处理这些 64 位整数。`int64-lowering.cc` 确保了在 32 位架构上也能正确处理这些 WebAssembly 的 64 位整数。

   **JavaScript 示例 (与 WebAssembly 交互):**

   ```javascript
   // 假设你有一个 WebAssembly 模块，其中定义了一个函数 add64，接受两个 i64 参数并返回一个 i64。
   // 你已经加载并实例化了这个模块。

   const wasmModule = // ... 加载的 WebAssembly 模块实例

   // 假设 add64 函数的 JavaScript 接口是 wasmModule.instance.exports.add64

   const low32_1 = 100;
   const high32_1 = 0; // 代表一个 64 位整数 100 (低 32 位为 100，高 32 位为 0)

   const low32_2 = 200;
   const high32_2 = 0; // 代表一个 64 位整数 200

   // 调用 WebAssembly 函数，传递 64 位整数的低 32 位和高 32 位
   const result_low = wasmModule.instance.exports.add64(low32_1, high32_1, low32_2, high32_2);

   // result_low 可能是返回的 64 位整数的低 32 位
   console.log(result_low);
   ```

   **在幕后，当 V8 在 32 位架构上执行这段代码时，`int64-lowering.cc` 会确保传递给 WebAssembly 模块的两个 32 位值被正确地组合成 64 位整数，并且 WebAssembly 模块返回的 64 位整数结果被正确地拆分成两个 32 位值供 JavaScript 使用。**

2. **`BigInt` 类型 (相对较新):**  虽然 JavaScript 的 `BigInt` 类型可以表示任意精度的整数，但它在 V8 内部的实现可能也会涉及到 64 位整数的处理，特别是在底层运算或者与原生代码交互时。`int64-lowering.cc` 可能在处理 `BigInt` 的某些底层操作时起到作用，尽管 `BigInt` 的主要目标是处理超出安全整数范围的整数。

   **JavaScript 示例 (`BigInt`):**

   ```javascript
   const largeNumber1 = 9007199254740991n; // 大于安全整数范围的 BigInt
   const largeNumber2 = 1n;

   const sum = largeNumber1 + largeNumber2;
   console.log(sum); // 输出 9007199254740992n
   ```

   虽然用户代码直接操作的是 `BigInt`，V8 在内部可能仍然会使用 64 位整数运算的组合来处理 `BigInt` 的加法，特别是在 32 位架构上。`int64-lowering.cc` 提供的机制使得这种分解和组合成为可能。

**总结:**

`int64-lowering.cc` 是 V8 编译器中一个关键的组件，它负责弥合 64 位整数操作和 32 位硬件架构之间的差距。这对于在 32 位系统上运行 JavaScript 代码，特别是与 WebAssembly 交互时处理 64 位整数至关重要。虽然 JavaScript 自身的主要数字类型是基于浮点数的，但在与 WebAssembly 或使用 `BigInt` 这样的新特性时，64 位整数的处理变得相关，而这个文件就负责处理这些底层的转换工作。

### 提示词
```
这是目录为v8/src/compiler/int64-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/int64-lowering.h"

#include "src/compiler/common-operator.h"
#include "src/compiler/diamond.h"
#include "src/compiler/linkage.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/node.h"
#include "src/compiler/turbofan-graph.h"
#include "src/compiler/wasm-call-descriptors.h"
#include "src/compiler/wasm-compiler.h"
#include "src/wasm/wasm-engine.h"
// TODO(wasm): Remove this include.
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-subtyping.h"
#include "src/zone/zone.h"

#if V8_TARGET_ARCH_32_BIT

namespace v8 {
namespace internal {
namespace compiler {

Int64Lowering::Int64Lowering(Graph* graph, MachineOperatorBuilder* machine,
                             CommonOperatorBuilder* common,
                             SimplifiedOperatorBuilder* simplified, Zone* zone,
                             Signature<MachineRepresentation>* signature)
    : graph_(graph),
      machine_(machine),
      common_(common),
      simplified_(simplified),
      zone_(zone),
      signature_(signature),
      state_(graph->NodeCount(), State::kUnvisited),
      stack_(zone),
      replacements_(nullptr),
      placeholder_(graph->NewNode(common->Dead())) {
  DCHECK_NOT_NULL(graph);
  DCHECK_NOT_NULL(graph->end());
  replacements_ = zone->AllocateArray<Replacement>(graph->NodeCount());
  memset(replacements_, 0, sizeof(Replacement) * graph->NodeCount());
}

void Int64Lowering::LowerGraph() {
  stack_.push_back({graph()->end(), 0});
  state_[graph()->end()->id()] = State::kOnStack;

  while (!stack_.empty()) {
    NodeState& top = stack_.back();
    if (top.input_index == top.node->InputCount()) {
      // All inputs of top have already been lowered, now lower top.
      Node* node = top.node;
      stack_.pop_back();
      state_[node->id()] = State::kVisited;
      LowerNode(node);
    } else {
      // Push the next input onto the stack.
      Node* input = top.node->InputAt(top.input_index++);
      if (state_[input->id()] == State::kUnvisited) {
        if (input->opcode() == IrOpcode::kPhi) {
          // To break cycles with phi nodes we push phis on a separate stack so
          // that they are processed after all other nodes.
          PreparePhiReplacement(input);
          stack_.push_front({input, 0});
        } else if (input->opcode() == IrOpcode::kEffectPhi ||
                   input->opcode() == IrOpcode::kLoop) {
          stack_.push_front({input, 0});
        } else {
          stack_.push_back({input, 0});
        }
        state_[input->id()] = State::kOnStack;
      }
    }
  }
}

namespace {

int GetReturnIndexAfterLowering(const CallDescriptor* call_descriptor,
                                int old_index) {
  int result = old_index;
  for (int i = 0; i < old_index; i++) {
    if (call_descriptor->GetReturnType(i).representation() ==
        MachineRepresentation::kWord64) {
      result++;
    }
  }
  return result;
}

int GetReturnCountAfterLowering(const CallDescriptor* call_descriptor) {
  return GetReturnIndexAfterLowering(
      call_descriptor, static_cast<int>(call_descriptor->ReturnCount()));
}

int GetParameterIndexAfterLowering(
    Signature<MachineRepresentation>* signature, int old_index) {
  int result = old_index;
  // Be robust towards special indexes (>= param count).
  int max_to_check =
      std::min(old_index, static_cast<int>(signature->parameter_count()));
  for (int i = 0; i < max_to_check; i++) {
    if (signature->GetParam(i) == MachineRepresentation::kWord64) {
      result++;
    }
  }
  return result;
}

int GetReturnCountAfterLowering(Signature<MachineRepresentation>* signature) {
  int result = static_cast<int>(signature->return_count());
  for (int i = 0; i < static_cast<int>(signature->return_count()); i++) {
    if (signature->GetReturn(i) == MachineRepresentation::kWord64) {
      result++;
    }
  }
  return result;
}

}  // namespace

void Int64Lowering::LowerWord64AtomicBinop(Node* node, const Operator* op) {
  DCHECK_EQ(5, node->InputCount());
  LowerMemoryBaseAndIndex(node);
  Node* value = node->InputAt(2);
  node->ReplaceInput(2, GetReplacementLow(value));
  node->InsertInput(zone(), 3, GetReplacementHigh(value));
  NodeProperties::ChangeOp(node, op);
  ReplaceNodeWithProjections(node);
}

void Int64Lowering::LowerWord64AtomicNarrowOp(Node* node, const Operator* op) {
  DefaultLowering(node, true);
  NodeProperties::ChangeOp(node, op);
  ReplaceNode(node, node, graph()->NewNode(common()->Int32Constant(0)));
}

// static
int Int64Lowering::GetParameterCountAfterLowering(
    Signature<MachineRepresentation>* signature) {
  // GetParameterIndexAfterLowering(parameter_count) returns the parameter count
  // after lowering.
  return GetParameterIndexAfterLowering(
      signature, static_cast<int>(signature->parameter_count()));
}

void Int64Lowering::GetIndexNodes(Node* index, Node** index_low,
                                  Node** index_high) {
  // We want to transform constant indices into constant indices, because
  // wasm-typer depends on them.
  Int32Matcher m(index);
  Node* index_second =
      m.HasResolvedValue()
          ? graph()->NewNode(common()->Int32Constant(m.ResolvedValue() + 4))
          : graph()->NewNode(machine()->Int32Add(), index,
                             graph()->NewNode(common()->Int32Constant(4)));
#if defined(V8_TARGET_LITTLE_ENDIAN)
  *index_low = index;
  *index_high = index_second;
#elif defined(V8_TARGET_BIG_ENDIAN)
  *index_low = index_second;
  *index_high = index;
#endif
}

void Int64Lowering::LowerLoadOperator(Node* node, MachineRepresentation rep,
                                      const Operator* load_op) {
  if (rep == MachineRepresentation::kWord64) {
    LowerMemoryBaseAndIndex(node);
    Node* base = node->InputAt(0);
    Node* index = node->InputAt(1);
    Node* index_low;
    Node* index_high;
    GetIndexNodes(index, &index_low, &index_high);
    Node* high_node;
    if (node->InputCount() > 2) {
      Node* effect_high = node->InputAt(2);
      Node* control_high = node->InputAt(3);
      high_node = graph()->NewNode(load_op, base, index_high, effect_high,
                                   control_high);
      // change the effect change from old_node --> old_effect to
      // old_node --> high_node --> old_effect.
      node->ReplaceInput(2, high_node);
    } else {
      high_node = graph()->NewNode(load_op, base, index_high);
    }
    node->ReplaceInput(1, index_low);
    NodeProperties::ChangeOp(node, load_op);
    ReplaceNode(node, node, high_node);
  } else {
    DefaultLowering(node);
  }
}

void Int64Lowering::LowerStoreOperator(Node* node, MachineRepresentation rep,
                                       const Operator* store_op) {
  if (rep == MachineRepresentation::kWord64) {
    // We change the original store node to store the low word, and create
    // a new store node to store the high word. The effect and control edges
    // are copied from the original store to the new store node, the effect
    // edge of the original store is redirected to the new store.
    LowerMemoryBaseAndIndex(node);
    Node* base = node->InputAt(0);
    Node* index = node->InputAt(1);
    Node* index_low;
    Node* index_high;
    GetIndexNodes(index, &index_low, &index_high);
    Node* value = node->InputAt(2);
    DCHECK(HasReplacementLow(value));
    DCHECK(HasReplacementHigh(value));

    Node* high_node;
    if (node->InputCount() > 3) {
      Node* effect_high = node->InputAt(3);
      Node* control_high = node->InputAt(4);
      high_node = graph()->NewNode(store_op, base, index_high,
                                   GetReplacementHigh(value), effect_high,
                                   control_high);
      node->ReplaceInput(3, high_node);

    } else {
      high_node = graph()->NewNode(store_op, base, index_high,
                                   GetReplacementHigh(value));
    }

    node->ReplaceInput(1, index_low);
    node->ReplaceInput(2, GetReplacementLow(value));
    NodeProperties::ChangeOp(node, store_op);
    ReplaceNode(node, node, high_node);
  } else {
    DefaultLowering(node, true);
  }
}

void Int64Lowering::LowerNode(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kInt64Constant: {
      int64_t value = OpParameter<int64_t>(node->op());
      Node* low_node = graph()->NewNode(
          common()->Int32Constant(static_cast<int32_t>(value & 0xFFFFFFFF)));
      Node* high_node = graph()->NewNode(
          common()->Int32Constant(static_cast<int32_t>(value >> 32)));
      ReplaceNode(node, low_node, high_node);
      break;
    }
    case IrOpcode::kLoad: {
      MachineRepresentation rep =
          LoadRepresentationOf(node->op()).representation();
      LowerLoadOperator(node, rep, machine()->Load(MachineType::Int32()));
      break;
    }
    case IrOpcode::kUnalignedLoad: {
      MachineRepresentation rep =
          LoadRepresentationOf(node->op()).representation();
      LowerLoadOperator(node, rep,
                        machine()->UnalignedLoad(MachineType::Int32()));
      break;
    }
    case IrOpcode::kLoadImmutable: {
      MachineRepresentation rep =
          LoadRepresentationOf(node->op()).representation();
      LowerLoadOperator(node, rep,
                        machine()->LoadImmutable(MachineType::Int32()));
      break;
    }
    case IrOpcode::kLoadFromObject: {
      ObjectAccess access = ObjectAccessOf(node->op());
      LowerLoadOperator(node, access.machine_type.representation(),
                        simplified()->LoadFromObject(ObjectAccess(
                            MachineType::Int32(), access.write_barrier_kind)));
      break;
    }
    case IrOpcode::kLoadImmutableFromObject: {
      ObjectAccess access = ObjectAccessOf(node->op());
      LowerLoadOperator(node, access.machine_type.representation(),
                        simplified()->LoadImmutableFromObject(ObjectAccess(
                            MachineType::Int32(), access.write_barrier_kind)));
      break;
    }
    case IrOpcode::kStore: {
      StoreRepresentation store_rep = StoreRepresentationOf(node->op());
      LowerStoreOperator(
          node, store_rep.representation(),
          machine()->Store(StoreRepresentation(
              MachineRepresentation::kWord32, store_rep.write_barrier_kind())));
      break;
    }
    case IrOpcode::kUnalignedStore: {
      UnalignedStoreRepresentation store_rep =
          UnalignedStoreRepresentationOf(node->op());
      LowerStoreOperator(
          node, store_rep,
          machine()->UnalignedStore(MachineRepresentation::kWord32));
      break;
    }
    case IrOpcode::kStoreToObject: {
      ObjectAccess access = ObjectAccessOf(node->op());
      LowerStoreOperator(node, access.machine_type.representation(),
                         simplified()->StoreToObject(ObjectAccess(
                             MachineType::Int32(), access.write_barrier_kind)));
      break;
    }
    case IrOpcode::kInitializeImmutableInObject: {
      ObjectAccess access = ObjectAccessOf(node->op());
      LowerStoreOperator(node, access.machine_type.representation(),
                         simplified()->InitializeImmutableInObject(ObjectAccess(
                             MachineType::Int32(), access.write_barrier_kind)));
      break;
    }
    case IrOpcode::kStart: {
      int parameter_count = GetParameterCountAfterLowering(signature());
      // Only exchange the node if the parameter count actually changed.
      if (parameter_count != static_cast<int>(signature()->parameter_count())) {
        int delta =
            parameter_count - static_cast<int>(signature()->parameter_count());
        int new_output_count = node->op()->ValueOutputCount() + delta;
        NodeProperties::ChangeOp(node, common()->Start(new_output_count));
      }
      break;
    }
    case IrOpcode::kParameter: {
      DCHECK_EQ(1, node->InputCount());
      int param_count = static_cast<int>(signature()->parameter_count());
      // Only exchange the node if the parameter count actually changed. We do
      // not even have to do the default lowering because the the start node,
      // the only input of a parameter node, only changes if the parameter count
      // changes.
      if (GetParameterCountAfterLowering(signature()) != param_count) {
        int old_index = ParameterIndexOf(node->op());
        // Adjust old_index to be compliant with the signature.
        --old_index;
        int new_index = GetParameterIndexAfterLowering(signature(), old_index);
        // Adjust new_index to consider the instance parameter.
        ++new_index;
        NodeProperties::ChangeOp(node, common()->Parameter(new_index));

        if (old_index < 0 || old_index >= param_count) {
          // Special parameters (JS closure/context) don't have kWord64
          // representation anyway.
          break;
        }

        if (signature()->GetParam(old_index) ==
            MachineRepresentation::kWord64) {
          Node* high_node = graph()->NewNode(common()->Parameter(new_index + 1),
                                             graph()->start());
          ReplaceNode(node, node, high_node);
        }
      }
      break;
    }
    case IrOpcode::kReturn: {
      int input_count = node->InputCount();
      DefaultLowering(node);
      if (input_count != node->InputCount()) {
        int new_return_count = GetReturnCountAfterLowering(signature());
        if (static_cast<int>(signature()->return_count()) != new_return_count) {
          NodeProperties::ChangeOp(node, common()->Return(new_return_count));
        }
      }
      break;
    }
    case IrOpcode::kTailCall: {
      auto call_descriptor =
          const_cast<CallDescriptor*>(CallDescriptorOf(node->op()));
      bool returns_require_lowering =
          GetReturnCountAfterLowering(call_descriptor) !=
          static_cast<int>(call_descriptor->ReturnCount());
      if (DefaultLowering(node) || returns_require_lowering) {
        // Tail calls do not have return values, so adjusting the call
        // descriptor is enough.
        NodeProperties::ChangeOp(
            node, common()->TailCall(LowerCallDescriptor(call_descriptor)));
      }
      break;
    }
    case IrOpcode::kCall: {
      auto call_descriptor = CallDescriptorOf(node->op());

      bool returns_require_lowering =
          GetReturnCountAfterLowering(call_descriptor) !=
          static_cast<int>(call_descriptor->ReturnCount());
      if (DefaultLowering(node) || returns_require_lowering) {
        // We have to adjust the call descriptor.
        NodeProperties::ChangeOp(
            node, common()->Call(LowerCallDescriptor(call_descriptor)));
      }
      if (returns_require_lowering) {
        size_t return_arity = call_descriptor->ReturnCount();
        if (return_arity == 1) {
          // We access the additional return values through projections.
          ReplaceNodeWithProjections(node);
        } else {
          ZoneVector<Node*> projections(return_arity, zone());
          NodeProperties::CollectValueProjections(node, projections.data(),
                                                  return_arity);
          for (size_t old_index = 0, new_index = 0; old_index < return_arity;
               ++old_index, ++new_index) {
            Node* use_node = projections[old_index];
            DCHECK_EQ(ProjectionIndexOf(use_node->op()), old_index);
            DCHECK_EQ(GetReturnIndexAfterLowering(call_descriptor,
                                                  static_cast<int>(old_index)),
                      static_cast<int>(new_index));
            if (new_index != old_index) {
              NodeProperties::ChangeOp(
                  use_node, common()->Projection(new_index));
            }
            if (call_descriptor->GetReturnType(old_index).representation() ==
                MachineRepresentation::kWord64) {
              Node* high_node = graph()->NewNode(
                  common()->Projection(new_index + 1), node, graph()->start());
              ReplaceNode(use_node, use_node, high_node);
              ++new_index;
            }
          }
        }
      }
      break;
    }
    case IrOpcode::kWord64And: {
      DCHECK_EQ(2, node->InputCount());
      Node* left = node->InputAt(0);
      Node* right = node->InputAt(1);

      Node* low_node =
          graph()->NewNode(machine()->Word32And(), GetReplacementLow(left),
                           GetReplacementLow(right));
      Node* high_node =
          graph()->NewNode(machine()->Word32And(), GetReplacementHigh(left),
                           GetReplacementHigh(right));
      ReplaceNode(node, low_node, high_node);
      break;
    }
    case IrOpcode::kTruncateInt64ToInt32: {
      DCHECK_EQ(1, node->InputCount());
      Node* input = node->InputAt(0);
      ReplaceNode(node, GetReplacementLow(input), nullptr);
      node->NullAllInputs();
      break;
    }
    case IrOpcode::kInt64Add: {
      DCHECK_EQ(2, node->InputCount());

      Node* right = node->InputAt(1);
      node->ReplaceInput(1, GetReplacementLow(right));
      node->AppendInput(zone(), GetReplacementHigh(right));

      Node* left = node->InputAt(0);
      node->ReplaceInput(0, GetReplacementLow(left));
      node->InsertInput(zone(), 1, GetReplacementHigh(left));

      NodeProperties::ChangeOp(node, machine()->Int32PairAdd());
      // We access the additional return values through projections.
      ReplaceNodeWithProjections(node);
      break;
    }
    case IrOpcode::kInt64Sub: {
      DCHECK_EQ(2, node->InputCount());

      Node* right = node->InputAt(1);
      node->ReplaceInput(1, GetReplacementLow(right));
      node->AppendInput(zone(), GetReplacementHigh(right));

      Node* left = node->InputAt(0);
      node->ReplaceInput(0, GetReplacementLow(left));
      node->InsertInput(zone(), 1, GetReplacementHigh(left));

      NodeProperties::ChangeOp(node, machine()->Int32PairSub());
      // We access the additional return values through projections.
      ReplaceNodeWithProjections(node);
      break;
    }
    case IrOpcode::kInt64Mul: {
      DCHECK_EQ(2, node->InputCount());

      Node* right = node->InputAt(1);
      node->ReplaceInput(1, GetReplacementLow(right));
      node->AppendInput(zone(), GetReplacementHigh(right));

      Node* left = node->InputAt(0);
      node->ReplaceInput(0, GetReplacementLow(left));
      node->InsertInput(zone(), 1, GetReplacementHigh(left));

      NodeProperties::ChangeOp(node, machine()->Int32PairMul());
      // We access the additional return values through projections.
      ReplaceNodeWithProjections(node);
      break;
    }
    case IrOpcode::kWord64Or: {
      DCHECK_EQ(2, node->InputCount());
      Node* left = node->InputAt(0);
      Node* right = node->InputAt(1);

      Node* low_node =
          graph()->NewNode(machine()->Word32Or(), GetReplacementLow(left),
                           GetReplacementLow(right));
      Node* high_node =
          graph()->NewNode(machine()->Word32Or(), GetReplacementHigh(left),
                           GetReplacementHigh(right));
      ReplaceNode(node, low_node, high_node);
      break;
    }
    case IrOpcode::kWord64Xor: {
      DCHECK_EQ(2, node->InputCount());
      Node* left = node->InputAt(0);
      Node* right = node->InputAt(1);

      Node* low_node =
          graph()->NewNode(machine()->Word32Xor(), GetReplacementLow(left),
                           GetReplacementLow(right));
      Node* high_node =
          graph()->NewNode(machine()->Word32Xor(), GetReplacementHigh(left),
                           GetReplacementHigh(right));
      ReplaceNode(node, low_node, high_node);
      break;
    }
    case IrOpcode::kWord64Shl: {
      // TODO(turbofan): if the shift count >= 32, then we can set the low word
      // of the output to 0 and just calculate the high word.
      DCHECK_EQ(2, node->InputCount());
      Node* shift = node->InputAt(1);
      if (HasReplacementLow(shift)) {
        // We do not have to care about the high word replacement, because
        // the shift can only be between 0 and 63 anyways.
        node->ReplaceInput(1, GetReplacementLow(shift));
      }

      Node* value = node->InputAt(0);
      node->ReplaceInput(0, GetReplacementLow(value));
      node->InsertInput(zone(), 1, GetReplacementHigh(value));

      NodeProperties::ChangeOp(node, machine()->Word32PairShl());
      // We access the additional return values through projections.
      ReplaceNodeWithProjections(node);
      break;
    }
    case IrOpcode::kWord64Shr: {
      // TODO(turbofan): if the shift count >= 32, then we can set the low word
      // of the output to 0 and just calculate the high word.
      DCHECK_EQ(2, node->InputCount());
      Node* shift = node->InputAt(1);
      if (HasReplacementLow(shift)) {
        // We do not have to care about the high word replacement, because
        // the shift can only be between 0 and 63 anyways.
        node->ReplaceInput(1, GetReplacementLow(shift));
      }

      Node* value = node->InputAt(0);
      node->ReplaceInput(0, GetReplacementLow(value));
      node->InsertInput(zone(), 1, GetReplacementHigh(value));

      NodeProperties::ChangeOp(node, machine()->Word32PairShr());
      // We access the additional return values through projections.
      ReplaceNodeWithProjections(node);
      break;
    }
    case IrOpcode::kWord64Sar: {
      // TODO(turbofan): if the shift count >= 32, then we can set the low word
      // of the output to 0 and just calculate the high word.
      DCHECK_EQ(2, node->InputCount());
      Node* shift = node->InputAt(1);
      if (HasReplacementLow(shift)) {
        // We do not have to care about the high word replacement, because
        // the shift can only be between 0 and 63 anyways.
        node->ReplaceInput(1, GetReplacementLow(shift));
      }

      Node* value = node->InputAt(0);
      node->ReplaceInput(0, GetReplacementLow(value));
      node->InsertInput(zone(), 1, GetReplacementHigh(value));

      NodeProperties::ChangeOp(node, machine()->Word32PairSar());
      // We access the additional return values through projections.
      ReplaceNodeWithProjections(node);
      break;
    }
    case IrOpcode::kWord64Equal: {
      DCHECK_EQ(2, node->InputCount());
      Node* left = node->InputAt(0);
      Node* right = node->InputAt(1);

      // TODO(wasm): Use explicit comparisons and && here?
      Node* replacement = graph()->NewNode(
          machine()->Word32Equal(),
          graph()->NewNode(
              machine()->Word32Or(),
              graph()->NewNode(machine()->Word32Xor(), GetReplacementLow(left),
                               GetReplacementLow(right)),
              graph()->NewNode(machine()->Word32Xor(), GetReplacementHigh(left),
                               GetReplacementHigh(right))),
          graph()->NewNode(common()->Int32Constant(0)));
      ReplaceNode(node, replacement, nullptr);
      break;
    }
    case IrOpcode::kInt64LessThan: {
      LowerComparison(node, machine()->Int32LessThan(),
                      machine()->Uint32LessThan());
      break;
    }
    case IrOpcode::kInt64LessThanOrEqual: {
      LowerComparison(node, machine()->Int32LessThan(),
                      machine()->Uint32LessThanOrEqual());
      break;
    }
    case IrOpcode::kUint64LessThan: {
      LowerComparison(node, machine()->Uint32LessThan(),
                      machine()->Uint32LessThan());
      break;
    }
    case IrOpcode::kUint64LessThanOrEqual: {
      LowerComparison(node, machine()->Uint32LessThan(),
                      machine()->Uint32LessThanOrEqual());
      break;
    }
    case IrOpcode::kSignExtendWord32ToInt64:
    case IrOpcode::kChangeInt32ToInt64: {
      DCHECK_EQ(1, node->InputCount());
      Node* input = node->InputAt(0);
      if (HasReplacementLow(input)) {
        input = GetReplacementLow(input);
      }
      // We use SAR to preserve the sign in the high word.
      Node* high_node =
          graph()->NewNode(machine()->Word32Sar(), input,
                           graph()->NewNode(common()->Int32Constant(31)));
      ReplaceNode(node, input, high_node);
      node->NullAllInputs();
      break;
    }
    case IrOpcode::kChangeUint32ToUint64: {
      DCHECK_EQ(1, node->InputCount());
      Node* input = node->InputAt(0);
      if (HasReplacementLow(input)) {
        input = GetReplacementLow(input);
      }
      ReplaceNode(node, input, graph()->NewNode(common()->Int32Constant(0)));
      node->NullAllInputs();
      break;
    }
    case IrOpcode::kBitcastInt64ToFloat64: {
      DCHECK_EQ(1, node->InputCount());
      Node* input = node->InputAt(0);

      Node* high_half =
          graph()->NewNode(machine()->Float64InsertHighWord32(),
                           graph()->NewNode(common()->Float64Constant(0.0)),
                           GetReplacementHigh(input));
      Node* result = graph()->NewNode(machine()->Float64InsertLowWord32(),
                                      high_half, GetReplacementLow(input));
      ReplaceNode(node, result, nullptr);
      break;
    }
    case IrOpcode::kBitcastFloat64ToInt64: {
      DCHECK_EQ(1, node->InputCount());
      Node* input = node->InputAt(0);
      if (HasReplacementLow(input)) {
        input = GetReplacementLow(input);
      }

      Node* low_node =
          graph()->NewNode(machine()->Float64ExtractLowWord32(), input);
      Node* high_node =
          graph()->NewNode(machine()->Float64ExtractHighWord32(), input);
      ReplaceNode(node, low_node, high_node);
      break;
    }
    case IrOpcode::kWord64RolLowerable:
      DCHECK(machine()->Word32Rol().IsSupported());
      [[fallthrough]];
    case IrOpcode::kWord64RorLowerable: {
      DCHECK_EQ(3, node->InputCount());
      Node* input = node->InputAt(0);
      Node* shift = HasReplacementLow(node->InputAt(1))
                        ? GetReplacementLow(node->InputAt(1))
                        : node->InputAt(1);
      Int32Matcher m(shift);
      if (m.HasResolvedValue()) {
        // Precondition: 0 <= shift < 64.
        int32_t shift_value = m.ResolvedValue() & 0x3F;
        if (shift_value == 0) {
          ReplaceNode(node, GetReplacementLow(input),
                      GetReplacementHigh(input));
        } else if (shift_value == 32) {
          ReplaceNode(node, GetReplacementHigh(input),
                      GetReplacementLow(input));
        } else {
          Node* low_input;
          Node* high_input;
          if (shift_value < 32) {
            low_input = GetReplacementLow(input);
            high_input = GetReplacementHigh(input);
          } else {
            low_input = GetReplacementHigh(input);
            high_input = GetReplacementLow(input);
          }
          int32_t masked_shift_value = shift_value & 0x1F;
          Node* masked_shift =
              graph()->NewNode(common()->Int32Constant(masked_shift_value));
          Node* inv_shift = graph()->NewNode(
              common()->Int32Constant(32 - masked_shift_value));

          auto* op1 = machine()->Word32Shr();
          auto* op2 = machine()->Word32Shl();
          bool is_ror = node->opcode() == IrOpcode::kWord64RorLowerable;
          if (!is_ror) std::swap(op1, op2);

          Node* low_node =
              graph()->NewNode(machine()->Word32Or(),
                               graph()->NewNode(op1, low_input, masked_shift),
                               graph()->NewNode(op2, high_input, inv_shift));
          Node* high_node =
              graph()->NewNode(machine()->Word32Or(),
                               graph()->NewNode(op1, high_input, masked_shift),
                               graph()->NewNode(op2, low_input, inv_shift));
          ReplaceNode(node, low_node, high_node);
        }
      } else {
        Node* safe_shift = shift;
        if (!machine()->Word32ShiftIsSafe()) {
          safe_shift =
              graph()->NewNode(machine()->Word32And(), shift,
                               graph()->NewNode(common()->Int32Constant(0x1F)));
        }

        bool is_ror = node->opcode() == IrOpcode::kWord64RorLowerable;
        Node* inv_mask =
            is_ror ? graph()->NewNode(
                         machine()->Word32Xor(),
                         graph()->NewNode(
                             machine()->Word32Shr(),
                             graph()->NewNode(common()->Int32Constant(-1)),
                             safe_shift),
                         graph()->NewNode(common()->Int32Constant(-1)))
                   : graph()->NewNode(
                         machine()->Word32Shl(),
                         graph()->NewNode(common()->Int32Constant(-1)),
                         safe_shift);

        Node* bit_mask =
            graph()->NewNode(machine()->Word32Xor(), inv_mask,
                             graph()->NewNode(common()->Int32Constant(-1)));

        // We have to mask the shift value for this comparison. If
        // !machine()->Word32ShiftIsSafe() then the masking should already be
        // part of the graph.
        Node* masked_shift6 = shift;
        if (machine()->Word32ShiftIsSafe()) {
          masked_shift6 =
              graph()->NewNode(machine()->Word32And(), shift,
                               graph()->NewNode(common()->Int32Constant(0x3F)));
        }

        Diamond lt32(
            graph(), common(),
            graph()->NewNode(machine()->Int32LessThan(), masked_shift6,
                             graph()->NewNode(common()->Int32Constant(32))));
        lt32.Chain(NodeProperties::GetControlInput(node));

        // The low word and the high word can be swapped either at the input or
        // at the output. We swap the inputs so that shift does not have to be
        // kept for so long in a register.
        Node* input_low =
            lt32.Phi(MachineRepresentation::kWord32, GetReplacementLow(input),
                     GetReplacementHigh(input));
        Node* input_high =
            lt32.Phi(MachineRepresentation::kWord32, GetReplacementHigh(input),
                     GetReplacementLow(input));

        const Operator* oper =
            is_ror ? machine()->Word32Ror() : machine()->Word32Rol().op();

        Node* rotate_low = graph()->NewNode(oper, input_low, safe_shift);
        Node* rotate_high = graph()->NewNode(oper, input_high, safe_shift);

        auto* mask1 = bit_mask;
        auto* mask2 = inv_mask;
        if (!is_ror) std::swap(mask1, mask2);

        Node* low_node = graph()->NewNode(
            machine()->Word32Or(),
            graph()->NewNode(machine()->Word32And(), rotate_low, mask1),
            graph()->NewNode(machine()->Word32And(), rotate_high, mask2));
        Node* high_node = graph()->NewNode(
            machine()->Word32Or(),
            graph()->NewNode(machine()->Word32And(), rotate_high, mask1),
            graph()->NewNode(machine()->Word32And(), rotate_low, mask2));
        ReplaceNode(node, low_node, high_node);
      }
      break;
    }
    case IrOpcode::kWord64ClzLowerable: {
      DCHECK_EQ(2, node->InputCount());
      Node* input = node->InputAt(0);
      Diamond d(
          graph(), common(),
          graph()->NewNode(machine()->Word32Equal(), GetReplacementHigh(input),
                           graph()->NewNode(common()->Int32Constant(0))));
      d.Chain(NodeProperties::GetControlInput(node));

      Node* low_node = d.Phi(
          MachineRepresentation::kWord32,
          graph()->NewNode(machine()->Int32Add(),
                           graph()->NewNode(machine()->Word32Clz(),
                                            GetReplacementLow(input)),
                           graph()->NewNode(common()->Int32Constant(32))),
          graph()->NewNode(machine()->Word32Clz(), GetReplacementHigh(input)));
      ReplaceNode(node, low_node, graph()->NewNode(common()->Int32Constant(0)));
      break;
    }
    case IrOpcode::kWord64CtzLowerable: {
      DCHECK_EQ(2, node->InputCount());
      DCHECK(machine()->Word32Ctz().IsSupported());
      Node* input = node->InputAt(0);
      Diamond d(
          graph(), common(),
          graph()->NewNode(machine()->Word32Equal(), GetReplacementLow(input),
                           graph()->NewNode(common()->Int32Constant(0))));
      d.Chain(NodeProperties::GetControlInput(node));

      Node* low_node =
          d.Phi(MachineRepresentation::kWord32,
                graph()->NewNode(machine()->Int32Add(),
                                 graph()->NewNode(machine()->Word32Ctz().op(),
                                                  GetReplacementHigh(input)),
                                 graph()->NewNode(common()->Int32Constant(32))),
                graph()->NewNode(machine()->Word32Ctz().op(),
                                 GetReplacementLow(input)));
      ReplaceNode(node, low_node, graph()->NewNode(common()->Int32Constant(0)));
      break;
    }
    case IrOpcode::kWord64Ror:
    case IrOpcode::kWord64Rol:
    case IrOpcode::kWord64Ctz:
    case IrOpcode::kWord64Clz:
      FATAL("%s operator should not be used in 32-bit systems",
            node->op()->mnemonic());
    case IrOpcode::kWord64Popcnt: {
      DCHECK_EQ(1, node->InputCount());
      Node* input = node->InputAt(0);
      // We assume that a Word64Popcnt node only has been created if
      // Word32Popcnt is actually supported.
      DCHECK(machine()->Word32Popcnt().IsSupported());
      Node* low_node =
          graph()->NewNode(machine()->Int32Add(),
                           graph()->NewNode(machine()->Word32Popcnt().op(),
                                            GetReplacementLow(input)),
                           graph()->NewNode(machine()->Word32Popcnt().op(),
                                            GetReplacementHigh(input)));
      ReplaceNode(node, low_node, graph()->NewNode(common()->Int32Constant(0)));
      break;
    }
    case IrOpcode::kPhi: {
      MachineRepresentation rep = PhiRepresentationOf(node->op());
      if (rep == MachineRepresentation::kWord64) {
        // The replacement nodes have already been created, we only have to
        // replace placeholder nodes.
        Node* low_node = GetReplacementLow(node);
        Node* high_node = GetReplacementHigh(node);
        for (int i = 0; i < node->op()->ValueInputCount(); i++) {
          low_node->ReplaceInput(i, GetReplacementLow(node->InputAt(i)));
          high_node->ReplaceInput(i, GetReplacementHigh(node->InputAt(i)));
        }
      } else {
        DefaultLowering(node);
      }
      break;
    }
    case IrOpcode::kLoopExitValue: {
      MachineRepresentation rep = LoopExitValueRepresentationOf(node->op());
      if (rep == MachineRepresentation::kWord64) {
        Node* low_node = graph()->NewNode(
            common()->LoopExitValue(MachineRepresentation::kWord32),
            GetReplacementLow(node->InputAt(0)), node->InputAt(1));
        Node* high_node = graph()->NewNode(
            common()->LoopExitValue(MachineRepresentation::kWord32),
            GetReplacementHigh(node->InputAt(0)), node->InputAt(1));
        ReplaceNode(node, low_node, high_node);
      } else {
        DefaultLowering(node);
      }
      break;
    }
    case IrOpcode::kWord64ReverseBytes: {
      Node* input = node->InputAt(0);
      Node* low_node = graph()->NewNode(machine()->Word32ReverseBytes(),
                                        GetReplacementHigh(input));
      Node* high_node = graph()->NewNode(machine()->Word32ReverseBytes(),
                                         GetReplacementLow(input));
      ReplaceNode(node, low_node, high_node);
      break;
    }
    case IrOpcode::kSignExtendWord8ToInt64: {
      DCHECK_EQ(1, node->InputCount());
      Node* input = node->InputAt(0);
      if (HasReplacementLow(input)) {
        input = GetReplacementLow(input);
      }
      // Sign extend low node to Int32
      Node* low_node =
          graph()->NewNode(machine()->SignExtendWord8ToInt32(), input);
      // We use SAR to preserve the sign in the high word.
      Node* high_node =
          graph()->NewNode(machine()->Word32Sar(), low_node,
                           graph()->NewNode(common()->Int32Constant(31)));
      ReplaceNode(node, low_node, high_node);
      node->NullAllInputs();
      break;
    }
    case IrOpcode::kSignExtendWord16ToInt64: {
      DCHECK_EQ(1, node->InputCount());
      Node* input = node->InputAt(0);
      if (HasReplacementLow(input)) {
        input = GetReplacementLow(input);
      }
      // Sign extend low node to Int32
      Node* low_node =
          graph()->NewNode(machine()->SignExtendWord16ToInt32(), input);
      // We use SAR to preserve the sign in the high word.
      Node* high_node =
          graph()->NewNode(machine()->Word32Sar(), low_node,
                           graph()->NewNode(common()->Int32Constant(31)));
      ReplaceNode(node, low_node, high_node);
      node->NullAllInputs();
      break;
    }
    case IrOpcode::kWord64AtomicLoad: {
      DCHECK_EQ(4, node->InputCount());
      AtomicLoadParameters params = AtomicLoadParametersOf(node->op());
      DefaultLowering(node, true);
      if (params.representation() == MachineType::Uint64()) {
        NodeProperties::ChangeOp(
            node, machine()->Word32AtomicPairLoad(params.order()));
        ReplaceNodeWithProjections(node);
      } else {
        NodeProperties::ChangeOp(node, machine()->Word32AtomicLoad(params));
        ReplaceNode(node, node, graph()->NewNode(common()->Int32Constant(0)));
      }
      break;
    }
    case IrOpcode::kWord64AtomicStore: {
      DCHECK_EQ(5, node->InputCount());
      AtomicStoreParameters params = AtomicStoreParametersOf(node->op());
      if (params.representation() == MachineRepresentation::kWord64) {
        LowerMemoryBaseAndIndex(node);
        Node* value = node->InputAt(2);
        node->ReplaceInput(2, GetReplacementLow(value));
        node->InsertInput(zone(), 3, GetReplacementHigh(value));
        NodeProperties::ChangeOp(
            node, machine()->Word32AtomicPairStore(params.order()));
      } else {
        DefaultLowering(node, true);
        NodeProperties::ChangeOp(node, machine()->Word32AtomicStore(params));
      }
      break;
    }
#define ATOMIC_CASE(name)                                                   \
  case IrOpcode::kWord64Atomic##name: {                                     \
    MachineType type = AtomicOpType(node->op());                            \
    if (type == MachineType::Uint64()) {                                    \
      LowerWord64AtomicBinop(node, machine()->Word32AtomicPair##name());    \
    } else {                                                                \
      LowerWord64AtomicNarrowOp(node, machine()->Word32Atomic##name(type)); \
    }                                                                       \
    break;                                                                  \
  }
      ATOMIC_CASE(Add)
      ATOMIC_CASE(Sub)
      ATOMIC_CASE(And)
      ATOMIC_CASE(Or)
      ATOMIC_CASE(Xor)
      ATOMIC_CASE(Exchange)
#undef ATOMIC_CASE
    case IrOpcode::kWord64AtomicCompareExchange: {
      MachineType type = AtomicOpType(node->op());
      if (type == MachineType::Uint64()) {
        LowerMemoryBaseAndIndex(node);
        Node* old_value = node->InputAt(2);
        Node* new_value = node->InputAt(3);
        node->ReplaceInput(2, GetReplacementLow(old_value));
        node->ReplaceInput(3, GetReplacementHigh(old_value));
        node->InsertInput(zone(), 4, GetReplacementLow(new_value));
        node->InsertInput(zone(), 5, GetReplacementHigh(new_value));
        NodeProperties::ChangeOp(node,
                                 machine()->Word32AtomicPairCompareExchange());
        ReplaceNodeWithProjections(node);
      } else {
        DCHECK(type == MachineType::Uint32() || type == MachineType::Uint16() ||
               type == MachineType::Uint8());
        DefaultLowering(node, true);
        NodeProperties::ChangeOp(node,
                                 machine()->Word32AtomicCompareExchange(type));
        ReplaceNode(node, node, graph()->NewNode(common()->Int32Constant(0)));
      }
      break;
    }
    case IrOpcode::kI64x2Splat: {
      DCHECK_EQ(1, node->InputCount());
      Node* input = node->InputAt(0);
      node->ReplaceInput(0, GetReplacementLow(input));
      node->AppendInput(zone(), GetReplacementHigh(input));
      NodeProperties::ChangeOp(node, machine()->I64x2SplatI32Pair());
      break;
    }
    case IrOpcode::kI64x2ExtractLane: {
      DCHECK_EQ(1, node->InputCount());
      Node* input = node->InputAt(0);
      int32_t lane = OpParameter<int32_t>(node->op());
      Node* low_node =
          graph()->NewNode(machine()->I32x4ExtractLane(lane * 2), input);
      Node* high_node =
          graph()->NewNode(machine()->I32x4ExtractLane(lane * 2 + 1), input);
      ReplaceNode(node, low_node, high_node);
      break;
    }
    case IrOpcode::kI64x2ReplaceLane: {
      DCHECK_EQ(2, node->InputCount());
      int32_t lane = OpParameter<int32_t>(node->op());
      Node* input = node->InputAt(1);
      node->ReplaceInput(1, GetReplacementLow(input));
      node->AppendInput(zone(), GetReplacementHigh(input));
      NodeProperties::ChangeOp(node, machine()->I64x2ReplaceLaneI32Pair(lane));
      break;
    }

    default: { DefaultLowering(node); }
  }
}

void Int64Lowering::LowerComparison(Node* node, const Operator* high_word_op,
                                    const Operator* low_word_op) {
  DCHECK_EQ(2, node->InputCount());
  Node* left = node->InputAt(0);
  Node* right = node->InputAt(1);
  Node* replacement = graph()->NewNode(
      machine()->Word32Or(),
      graph()->NewNode(high_word_op, GetReplacementHigh(left),
                       GetReplacementHigh(right)),
      graph()->NewNode(
          machine()->Word32And(),
          graph()->NewNode(machine()->Word32Equal(), GetReplacementHigh(left),
                           GetReplacementHigh(right)),
          graph()->NewNode(low_word_op, GetReplacementLow(left),
                           GetReplacementLow(right))));
  ReplaceNode(node, replacement, nullptr);
}

bool Int64Lowering::DefaultLowering(Node* node, bool low_word_only) {
  bool something_changed = false;
  for (int i = NodeProperties::PastValueIndex(node) - 1; i >= 0; i--) {
    Node* input = node->InputAt(i);
    if (HasReplacementLow(input)) {
      something_changed = true;
      node->ReplaceInput(i, GetReplacementLow(input));
    }
    if (!low_word_only && HasReplacementHigh(input)) {
      something_changed = true;
      node->InsertInput(zone(), i + 1, GetReplacementHigh(input));
    }
  }
  return something_changed;
}

const CallDescriptor* Int64Lowering::LowerCallDescriptor(
    const CallDescriptor* call_descriptor) {
  CallDescriptor* maybe_special_replacement =
      wasm::GetWasmEngine()->call_descriptors()->GetLoweredCallDescriptor(
          call_descriptor);
  if (maybe_special_replacement) return maybe_special_replacement;
  return GetI32WasmCallDescriptor(zone(), call_descriptor);
}

void Int64Lowering::ReplaceNode(Node* old, Node* new_low, Node* new_high) {
  // if new_low == nullptr, then also new_high == nullptr.
  DCHECK(new_low != nullptr || new_high == nullptr);
  replacements_[old->id()].low = new_low;
  replacements_[old->id()].high = new_high;
}

bool Int64Lowering::HasReplacementLow(Node* node) {
  return replacements_[node->id()].low != nullptr;
}

Node* Int64Lowering::GetReplacementLow(Node* node) {
  Node* result = replacements_[node->id()].low;
  DCHECK(result);
  return result;
}

bool Int64Lowering::HasReplacementHigh(Node* node) {
  return replacements_[node->id()].high != nullptr;
}

Node* Int64Lowering::GetReplacementHigh(Node* node) {
  Node* result = replacements_[node->id()].high;
  DCHECK(result);
  return result;
}

void Int64Lowering::PreparePhiReplacement(Node* phi) {
  MachineRepresentation rep = PhiRepresentationOf(phi->op());
  if (rep == MachineRepresentation::kWord64) {
    // We have to create the replacements for a phi node before we actually
    // lower the phi to break potential cycles in the graph. The replacements of
    // input nodes do not exist yet, so we use a placeholder node to pass the
    // graph verifier.
    int value_count = phi->op()->ValueInputCount();
    Node** inputs_low = zone()->AllocateArray<Node*>(value_count + 1);
    Node** inputs_high = zone()->AllocateArray<Node*>(value_count + 1);
    for (int i = 0; i < value_count; i++) {
      inputs_low[i] = placeholder_;
      inputs_high[i] = placeholder_;
    }
    inputs_low[value_count] = NodeProperties::GetControlInput(phi, 0);
    inputs_high[value_count] = NodeProperties::GetControlInput(phi, 0);
    ReplaceNode(phi,
                graph()->NewNode(
                    common()->Phi(MachineRepresentation::kWord32, value_count),
                    value_count + 1, inputs_low, false),
                graph()->NewNode(
                    common()->Phi(MachineRepresentation::kWord32, value_count),
                    value_count + 1, inputs_high, false));
  }
}

void Int64Lowering::ReplaceNodeWithProjections(Node* node) {
  DCHECK(node != nullptr);
  Node* low_node =
      graph()->NewNode(common()->Projection(0), node, graph()->start());
  Node* high_node =
      graph()->NewNode(common()->Projection(1), node, graph()->start());
  ReplaceNode(node, low_node, high_node);
}

void Int64Lowering::LowerMemoryBaseAndIndex(Node* node) {
  DCHECK(node != nullptr);
  // Low word only replacements for memory operands for 32-bit address space.
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  if (HasReplacementLow(base)) {
    node->ReplaceInput(0, GetReplacementLow(base));
  }
  if (HasReplacementLow(index)) {
    node->ReplaceInput(1, GetReplacementLow(index));
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_32_BIT
```