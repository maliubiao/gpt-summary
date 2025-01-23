Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Assessment & Keyword Scan:**

The first step is to quickly scan the code for prominent keywords and structures. This helps establish the general context and purpose. Keywords that jump out are:

* `// Copyright`, `// Use of this source code`:  Standard copyright and licensing information. Indicates real-world code.
* `#include`: C++ preprocessor directives, signaling dependencies on other files. The included headers like `src/compiler/common-operator.h`, `src/compiler/machine-operator.h`, etc., strongly suggest this code is part of a compiler.
* `namespace v8`, `namespace internal`, `namespace compiler`:  Clearly within the V8 JavaScript engine's compiler infrastructure.
* `Int64Lowering`: This is a very descriptive class name. "Lowering" often refers to translating high-level representations into lower-level ones. "Int64" suggests handling 64-bit integer types.
* `Graph* graph`, `MachineOperatorBuilder* machine`, `CommonOperatorBuilder* common`, `SimplifiedOperatorBuilder* simplified`: These look like core compiler components for building and manipulating an intermediate representation (the "graph").
* `LowerGraph()`, `LowerNode(Node* node)`, `LowerLoadOperator`, `LowerStoreOperator`:  Function names clearly indicating the purpose of transformation or lowering.
* `MachineRepresentation::kWord64`, `MachineType::Int32()`:  References to machine-level data types.
* `ReplaceNode`, `ReplaceNodeWithProjections`: Functions for modifying the graph structure.
* `IrOpcode::kInt64Constant`, `IrOpcode::kLoad`, `IrOpcode::kStore`, etc.:  These look like opcodes for different operations within the compiler's intermediate representation, specifically dealing with 64-bit integers.
* `#if V8_TARGET_ARCH_32_BIT`: Conditional compilation, indicating architecture-specific logic.

**2. Inferring the Core Functionality:**

Based on the keywords and the `Int64Lowering` class name, the primary function is likely to *transform* or *lower* operations involving 64-bit integers (`int64_t`) into operations that can be handled more directly on a 32-bit architecture. The `#if V8_TARGET_ARCH_32_BIT` strongly reinforces this inference. On a 32-bit architecture, you can't directly perform 64-bit arithmetic in a single instruction. Therefore, these operations need to be broken down.

**3. Analyzing Key Methods:**

* **`Int64Lowering::LowerGraph()`:** This seems to be the main entry point for the lowering process. The use of a `stack_` and `state_` suggests a graph traversal algorithm (likely depth-first). The code handles `Phi` nodes (used for control flow merging) specifically, which is common in compiler IRs.
* **`Int64Lowering::LowerNode(Node* node)`:** This is the core logic where the actual lowering of individual nodes happens. The `switch` statement based on `node->opcode()` indicates that different 64-bit operations are handled differently.
* **`Int64Lowering::LowerLoadOperator` and `Int64Lowering::LowerStoreOperator`:** These handle loading and storing 64-bit values from memory, splitting the 64-bit access into two 32-bit accesses (low and high words). The `GetIndexNodes` function further supports this by calculating the memory addresses for the two 32-bit parts.
* **Specific `IrOpcode` cases (e.g., `kInt64Add`, `kInt64Mul`, `kWord64And`):**  These show how specific 64-bit arithmetic and logical operations are transformed into pairs of 32-bit operations, often using helper machine instructions like `Int32PairAdd`. The handling of shifts (`kWord64Shl`, `kWord64Shr`, `kWord64Sar`) demonstrates the need to handle shifts greater than 31 bits carefully.

**4. Considering the Context (V8 and Compilation):**

Knowing this is V8's compiler helps understand *why* this lowering is needed. JavaScript numbers are double-precision floats. While V8 supports bitwise operations on 32-bit integers, efficient handling of 64-bit integer operations (often arising from Typed Arrays or WebAssembly) requires specific optimization steps during compilation. This lowering pass bridges the gap between the high-level IR and the target machine's instruction set.

**5. Thinking about JavaScript Examples:**

Since the code deals with 64-bit integers, examples involving bitwise operations or Typed Arrays manipulating 64-bit integer types (`BigInt64Array`, `BigUint64Array`) are the most relevant.

**6. Considering Potential Errors:**

Looking at how 64-bit operations are split into 32-bit parts immediately brings to mind potential issues:

* **Endianness:** The `GetIndexNodes` function explicitly handles endianness (`V8_TARGET_LITTLE_ENDIAN`, `V8_TARGET_BIG_ENDIAN`), highlighting that the order of the low and high words in memory is crucial. Incorrect handling could lead to incorrect results.
* **Data Races (if not careful):**  When performing a 64-bit load or store as two 32-bit operations, there's a brief window where the data might be inconsistent if another thread is modifying the same memory location. The atomic operations hint at mechanisms to mitigate this.

**7. Structuring the Summary:**

Finally, organize the findings into a clear and concise summary covering the key functional aspects, the connection to JavaScript, potential errors, and the overall purpose of the code. Highlighting the 32-bit architecture constraint is essential.

This detailed breakdown shows how to systematically analyze a piece of code even without deep prior knowledge of the specific system. By combining keyword analysis, structural understanding, and logical reasoning, one can arrive at a good understanding of the code's purpose.
这是 V8 JavaScript 引擎中 `v8/src/compiler/int64-lowering.cc` 文件的代码，它的主要功能是：

**功能归纳：**

这个文件的主要功能是在 **32位架构** 上，将中间表示 (IR) 图中 **64位整数 (int64_t)** 的操作转换为由 **两个 32位整数** 操作组成的等价序列。这个过程被称为 "降低 (lowering)"。这是编译器优化管道中的一个重要步骤，因为它允许在不支持原生 64 位整数运算的架构上执行这些操作。

**详细功能列表:**

1. **处理 64 位常量:**  将 `Int64Constant` 节点分解为两个 `Int32Constant` 节点，分别表示低 32 位和高 32 位。

2. **处理 64 位加载和存储:**  将 `Load` 和 `Store` 操作（针对 `MachineRepresentation::kWord64`）分解为对低 32 位和高 32 位的两次单独的 32 位加载或存储操作。它会调整内存访问的索引以正确读取/写入高低位。

3. **处理 64 位算术运算:** 将诸如 `Int64Add`, `Int64Sub`, `Int64Mul`, `Word64And`, `Word64Or`, `Word64Xor`, `Word64Shl`, `Word64Shr`, `Word64Sar` 等 64 位算术和位运算操作，转换为相应的 32 位操作序列。通常会引入新的 32 位操作符，如 `Int32PairAdd`。

4. **处理 64 位比较运算:** 将 `Int64LessThan`, `Int64LessThanOrEqual`, `Uint64LessThan`, `Uint64LessThanOrEqual` 等 64 位比较操作，转换为使用 32 位比较操作的组合来实现。

5. **处理类型转换:**  将 32 位整数转换为 64 位整数 (`SignExtendWord32ToInt64`, `ChangeInt32ToInt64`, `ChangeUint32ToUint64`)，以及将 64 位整数截断为 32 位整数 (`TruncateInt64ToInt32`)。

6. **处理位操作 (旋转和计数前导/尾随零):**  对于 `Word64RolLowerable`, `Word64RorLowerable`, `Word64ClzLowerable`, `Word64CtzLowerable` 等操作，使用 32 位操作来实现。

7. **调整函数调用和返回:** 当函数参数或返回值是 64 位整数时，会修改 `Start`, `Parameter`, `Return`, `Call`, `TailCall` 等节点，以处理低 32 位和高 32 位。它会更新调用描述符 (CallDescriptor) 和签名 (Signature) 以反映这种转换。

8. **处理位铸造 (Bitcast):** 将 64 位整数与双精度浮点数之间进行位模式转换的操作 (`BitcastInt64ToFloat64`, `BitcastFloat64ToInt64`) 分解为操作 32 位字的操作。

9. **图遍历和节点替换:** 使用深度优先搜索 (DFS) 遍历 IR 图，并使用 `ReplaceNode` 和 `ReplaceNodeWithProjections` 函数来替换和修改图中的节点。

**关于 .tq 结尾:**

如果 `v8/src/compiler/int64-lowering.cc` 文件以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。Torque 是 V8 用来定义运行时内置函数和一些底层操作的 DSL (领域特定语言)。 然而，当前给出的代码是 `.cc` 结尾，表明它是 C++ 源代码。

**与 JavaScript 的关系 (举例说明):**

JavaScript 本身使用 IEEE 754 双精度浮点数来表示数字，可以安全地表示 -2<sup>53</sup> 到 2<sup>53</sup> 之间的整数。然而，ES2020 引入了 `BigInt` 类型，可以表示任意精度的整数。此外，Typed Arrays 允许使用 `BigInt64Array` 和 `BigUint64Array` 来表示 64 位有符号和无符号整数。

`int64-lowering.cc` 的功能直接影响到 V8 如何高效地执行涉及到 `BigInt` 和 64 位 Typed Arrays 的 JavaScript 代码，尤其是在 32 位架构上。

**JavaScript 示例:**

```javascript
// 使用 BigInt
const bigIntA = 9007199254740991n + 1n; // 超过 Number 安全范围
const bigIntB = 10n;
const sumBigInt = bigIntA + bigIntB;
console.log(sumBigInt); // 输出 9007199254741002n

// 使用 BigInt64Array
const buffer = new ArrayBuffer(16);
const bigInt64Array = new BigInt64Array(buffer);
bigInt64Array[0] = 100n;
bigInt64Array[1] = -200n;
console.log(bigInt64Array[0]); // 输出 100n
console.log(bigInt64Array[1]); // 输出 -200n

// 位运算在 BigInt 上
const bigIntC = 0xFFFFFFFFFFFFFFFFn;
const shiftedBigInt = bigIntC >> 32n;
console.log(shiftedBigInt); // 输出 4294967295n
```

当 V8 执行这些涉及 `BigInt` 或 `BigInt64Array` 的操作时，在 32 位架构上，`int64-lowering.cc` 中的代码会确保这些 64 位操作被正确地转换为一系列 32 位操作。

**代码逻辑推理 (假设输入与输出):**

**假设输入:** 一个表示 `x + y` 的 IR 节点，其中 `x` 和 `y` 是 64 位整数。

**IR 节点可能如下所示 (简化表示):**

```
kInt64Add(x_low, x_high, y_low, y_high) // 假设输入已经被表示为低高位
```

**`int64-lowering.cc` 的处理逻辑:**

1. 获取 `x` 的低位 (`x_low`) 和高位 (`x_high`) 的节点。
2. 获取 `y` 的低位 (`y_low`) 和高位 (`y_high`) 的节点。
3. 创建一个新的 `Int32PairAdd` 节点，将 `x_low`, `x_high`, `y_low`, `y_high` 作为输入。

**输出 (替换后的 IR 节点):**

```
kInt32PairAdd(x_low, x_high, y_low, y_high)
```

并且可能会创建两个投影节点来访问 `kInt32PairAdd` 结果的低 32 位和高 32 位。

**用户常见的编程错误 (与 64 位整数相关):**

1. **在 JavaScript 中超出 Number 的安全整数范围进行运算:**  在 `BigInt` 出现之前，JavaScript 的 `Number` 类型无法精确表示大于 2<sup>53</sup> - 1 或小于 -(2<sup>53</sup> - 1) 的整数。进行此类运算会导致精度丢失。

   ```javascript
   let a = 9007199254740991;
   let b = a + 1;
   console.log(b); // 输出 9007199254740992，精度丢失
   ```

2. **在 32 位系统上进行假设 64 位整数运算的位操作:**  即使在 JavaScript 中使用位运算符（如 `|`, `&`, `^`, `<<`, `>>`, `>>>`），这些操作在内部会被转换为 32 位有符号整数。如果用户期望在超出 32 位范围的值上进行位操作，结果可能与预期不符。`BigInt` 解决了这个问题。

   ```javascript
   console.log(0xFFFFFFFF << 1); // 输出 -2  (因为被视为 32 位有符号整数)
   console.log(0xFFFFFFFFn << 1n); // 输出 8589934590n (BigInt 可以处理)
   ```

3. **不正确地处理 64 位 Typed Array 的数据:**  当直接操作 `ArrayBuffer` 时，如果对 64 位整数的字节顺序（endianness）理解不正确，可能会导致读取或写入错误的值。

**总结 `int64-lowering.cc` 的功能 (针对第 1 部分):**

`v8/src/compiler/int64-lowering.cc` 的主要功能是在 V8 编译器的优化阶段，特别是针对 32 位目标架构，**将 IR 图中的 64 位整数操作分解为一系列等价的 32 位整数操作**。这使得 V8 能够在不支持原生 64 位指令的平台上高效地执行涉及 64 位整数的 JavaScript 代码（例如，使用 `BigInt` 或 64 位 Typed Arrays）。 它通过遍历 IR 图，识别 64 位操作相关的节点，并使用相应的 32 位操作序列替换它们来实现。 这涉及到处理常量、加载、存储、算术运算、比较运算、类型转换以及函数调用和返回的调整。

### 提示词
```
这是目录为v8/src/compiler/int64-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/int64-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```