Response:
The user wants me to summarize the functionality of the provided C++ code snippet. I need to analyze the code and describe what it does within the context of the V8 JavaScript engine.

Here's a breakdown of the thought process:

1. **Identify the file:** The file is `v8/src/compiler/machine-operator-reducer.cc`. The name suggests it's related to the compiler and optimization, specifically reducing machine-level operations.

2. **Recognize the code structure:** The code consists of a class `MachineOperatorReducer` with a method `Reduce(Node* node)`. This method seems to take a node from the compiler's intermediate representation (likely the *machine graph*) and attempts to simplify or optimize it.

3. **Analyze the `switch` statement:** The core logic revolves around a `switch` statement that operates on the opcode of the input `node`. This means the reducer handles different kinds of machine instructions.

4. **Examine individual `case` blocks:**  Each `case` handles a specific machine opcode. The operations inside these cases involve:
    * **Matching input operands:** Using `Matcher` classes like `Float64Matcher`, `Int32Matcher`, etc., to check the properties of the input nodes.
    * **Constant folding:** If the inputs are constants, the operation is performed at compile time, and the node is replaced with a constant node (e.g., `ReplaceInt32`, `ReplaceFloat64`).
    * **Algebraic simplification:** Applying mathematical identities to simplify expressions (e.g., `x + 0 => x`, `x * 1 => x`).
    * **Instruction combining:** Replacing a sequence of instructions with a single, more efficient one.
    * **Pattern matching and replacement:** Identifying specific patterns of instructions and replacing them with optimized versions.
    * **No-ops:**  Returning `NoChange()` when no optimization is possible for a given node.

5. **Look for connections to JavaScript:**  The presence of operations like `kChangeFloat64ToInt32`, `kChangeInt32ToFloat64`, `kTruncateFloat64ToWord32` suggests this reducer deals with conversions between JavaScript's number types (which are often represented as doubles) and integer types used at the machine level.

6. **Infer overall purpose:** Based on the individual cases, the primary function of this code is to perform low-level optimizations on the machine graph. It tries to simplify arithmetic operations, perform constant folding, eliminate redundant conversions, and generally generate more efficient machine code.

7. **Consider the `.tq` extension:** The prompt mentions the `.tq` extension and its association with Torque. This is a hint that some of the operations might be related to or implemented using Torque, V8's internal language for defining built-in functions.

8. **Think about common programming errors:**  While the code itself isn't directly about *user* errors, the optimizations it performs can sometimes reveal inefficiencies in generated code that stem from certain JavaScript programming patterns. For instance, unnecessary type conversions or redundant computations.

9. **Formulate the summary:** Based on the above analysis, the summary should highlight the core function of optimizing machine-level operations, mention constant folding, algebraic simplification, type conversion handling, and its role in generating efficient machine code within the V8 compiler. It should also address the `.tq` point and the connection to JavaScript.
这是V8源代码文件 `v8/src/compiler/machine-operator-reducer.cc` 的第二部分，该文件的主要功能是**对编译器生成的机器操作进行简化和优化**。

以下是根据提供的代码片段归纳的功能点：

**类型转换优化:**

* **常量折叠:**  如果类型转换的输入是常量，则直接计算出结果并替换为常量节点。例如，将一个常量浮点数转换为整数。
  ```c++
  case IrOpcode::kChangeFloat64ToInt32: {
    Float64Matcher m(node->InputAt(0));
    if (m.HasResolvedValue())
      return ReplaceInt32(FastD2IChecked(m.ResolvedValue()));
    // ...
  }
  ```
* **消除冗余转换:** 如果存在连续的类型转换，可以将其消除。例如，先将整数转换为浮点数，再将浮点数转换为相同的整数类型。
  ```c++
  case IrOpcode::kChangeFloat64ToInt32: {
    // ...
    if (m.IsChangeInt32ToFloat64()) return Replace(m.node()->InputAt(0));
    // ...
  }
  ```
  **JavaScript 示例:**
  ```javascript
  let x = 10;
  let y = Number(x); // 冗余的转换
  ```
  在编译过程中，`Number(x)` 可能会被优化掉，因为它已经是数字类型了。

* **处理 NaN:**  对于浮点数到其他类型的转换，会考虑 NaN (Not a Number) 的传播和静默。
  ```c++
  case IrOpcode::kChangeFloat64ToFloat32: {
    Float64Matcher m(node->InputAt(0));
    if (m.HasResolvedValue()) {
      if (signalling_nan_propagation_ == kSilenceSignallingNan && m.IsNaN()) {
        return ReplaceFloat32(DoubleToFloat32(SilenceNaN(m.ResolvedValue())));
      }
      return ReplaceFloat32(DoubleToFloat32(m.ResolvedValue()));
    }
    // ...
  }
  ```

**位运算优化:**

* **`BitcastWord32ToWord64` 优化:** 如果将一个 32 位整数转换为 64 位整数，且该 32 位整数是通过截断 64 位整数得到的，则可以直接使用原始的 64 位整数。
  ```c++
  case IrOpcode::kBitcastWord32ToWord64: {
    Int32Matcher m(node->InputAt(0));
    if (m.HasResolvedValue()) return ReplaceInt64(m.ResolvedValue());
    // No need to truncate the value, since top 32 bits are not important.
    if (m.IsTruncateInt64ToInt32()) return Replace(m.node()->InputAt(0));
    break;
  }
  ```

**加载 (Load) 操作优化:**

* **地址计算优化:**  如果加载操作的地址是通过加法计算得到的，且加法的一个操作数是常量，则可以将常量值加到偏移量中。
  ```c++
  case IrOpcode::kLoad:
  case IrOpcode::kProtectedLoad:
  case IrOpcode::kLoadTrapOnNull: {
    Node* input0 = node->InputAt(0);
    Node* input1 = node->InputAt(1);
    if (input0->opcode() == IrOpcode::kInt64Add) {
      Int64BinopMatcher m(input0);
      if (m.right().HasResolvedValue()) {
        int64_t value = m.right().ResolvedValue();
        node->ReplaceInput(0, m.left().node());
        Node* new_node = Int64Add(input1, Int64Constant(value));
        node->ReplaceInput(1, new_node);
        return Changed(node);
      }
    }
    break;
  }
  ```

**条件分支优化:**

* **`Select` 操作优化:** 如果 `Select` 操作的条件是常量 0 或非 0，则可以直接选择相应的输入。
  ```c++
  case IrOpcode::kFloat32Select:
  case IrOpcode::kFloat64Select:
  case IrOpcode::kWord32Select:
  case IrOpcode::kWord64Select: {
    Int32Matcher match(node->InputAt(0));
    if (match.HasResolvedValue()) {
      if (match.Is(0)) {
        return Replace(node->InputAt(2));
      } else {
        return Replace(node->InputAt(1));
      }
    }
    break;
  }
  ```
  **JavaScript 示例:**
  ```javascript
  let condition = false;
  let result = condition ? 10 : 20;
  ```
  如果 `condition` 在编译时已知是 `false`，那么 `Select` 操作会直接选择 `20`。

**浮点数比较优化:**

* 对于浮点数比较操作 (`kFloat64Equal`, `kFloat64LessThan`, `kFloat64LessThanOrEqual`)，存在相应的优化处理 (具体实现未在当前代码片段中)。

**其他操作优化:**

* **插入字 (Insert Word) 操作优化:**  `kFloat64InsertLowWord32` 和 `kFloat64InsertHighWord32` 存在相应的优化处理 (具体实现未在当前代码片段中)。
* **存储 (Store) 操作优化:** `kStore` 和 `kUnalignedStore` 存在相应的优化处理 (具体实现未在当前代码片段中)。

**关于 `.tq` 结尾:**

代码片段是 `.cc` 文件，因此它不是 Torque 源代码。如果 `v8/src/compiler/machine-operator-reducer.cc` 以 `.tq` 结尾，那它才是 V8 Torque 源代码。Torque 用于定义 V8 的内置函数。

**用户常见的编程错误 (可能间接相关):**

虽然 `machine-operator-reducer.cc` 不直接处理用户代码，但其优化可以减轻一些因编程习惯不良导致的性能问题。例如：

* **不必要的类型转换:** 用户可能在 JavaScript 中进行不必要的类型转换，例如将一个已经是数字的变量再次转换为数字。Reducer 可以尝试消除这些冗余的转换。
* **复杂的算术运算:**  Reducer 可以对简单的算术运算进行常量折叠和代数简化。

**假设输入与输出 (以类型转换为例):**

**假设输入:** 一个表示将浮点数常量 `3.14` 转换为整数的节点。
```
node->opcode() == IrOpcode::kChangeFloat64ToInt32
node->InputAt(0) 是一个表示常量 3.14 的节点
```
**输出:** 一个表示整数常量 `3` 的节点。
```
返回 ReplaceInt32(3);
```

**总结:**

`v8/src/compiler/machine-operator-reducer.cc` 的第二部分主要负责对机器级别的操作进行优化，特别是针对类型转换、位运算、加载操作和条件分支等场景，通过常量折叠、消除冗余操作等手段提高代码执行效率。它关注的是编译器生成的中间表示，并尝试将其简化为更高效的形式。 虽然不直接处理用户编写的 JavaScript 代码，但其优化工作可以间接提升最终执行的 JavaScript 代码的性能，并可能减轻一些因不良编程习惯带来的性能损耗。

Prompt: 
```
这是目录为v8/src/compiler/machine-operator-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/machine-operator-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
agation_ == kSilenceSignallingNan &&
            std::isnan(m.ResolvedValue())) {
          return ReplaceFloat64(SilenceNaN(m.ResolvedValue()));
        }
        return ReplaceFloat64(m.ResolvedValue());
      }
      break;
    }
    case IrOpcode::kChangeFloat64ToInt32: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceInt32(FastD2IChecked(m.ResolvedValue()));
      if (m.IsChangeInt32ToFloat64()) return Replace(m.node()->InputAt(0));
      break;
    }
    case IrOpcode::kChangeFloat64ToInt64: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceInt64(static_cast<int64_t>(m.ResolvedValue()));
      if (m.IsChangeInt64ToFloat64()) return Replace(m.node()->InputAt(0));
      break;
    }
    case IrOpcode::kChangeFloat64ToUint32: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceInt32(FastD2UI(m.ResolvedValue()));
      if (m.IsChangeUint32ToFloat64()) return Replace(m.node()->InputAt(0));
      break;
    }
    case IrOpcode::kChangeInt32ToFloat64: {
      Int32Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(FastI2D(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kBitcastWord32ToWord64: {
      Int32Matcher m(node->InputAt(0));
      if (m.HasResolvedValue()) return ReplaceInt64(m.ResolvedValue());
      // No need to truncate the value, since top 32 bits are not important.
      if (m.IsTruncateInt64ToInt32()) return Replace(m.node()->InputAt(0));
      break;
    }
    case IrOpcode::kChangeInt32ToInt64: {
      Int32Matcher m(node->InputAt(0));
      if (m.HasResolvedValue()) return ReplaceInt64(m.ResolvedValue());
      break;
    }
    case IrOpcode::kChangeInt64ToFloat64: {
      Int64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(static_cast<double>(m.ResolvedValue()));
      if (m.IsChangeFloat64ToInt64()) return Replace(m.node()->InputAt(0));
      break;
    }
    case IrOpcode::kChangeUint32ToFloat64: {
      Uint32Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(FastUI2D(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kChangeUint32ToUint64: {
      Uint32Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceInt64(static_cast<uint64_t>(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kTruncateFloat64ToWord32: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceInt32(DoubleToInt32(m.ResolvedValue()));
      if (m.IsChangeInt32ToFloat64()) return Replace(m.node()->InputAt(0));
      return NoChange();
    }
    case IrOpcode::kTruncateInt64ToInt32:
      return ReduceTruncateInt64ToInt32(node);
    case IrOpcode::kTruncateFloat64ToFloat32: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue()) {
        if (signalling_nan_propagation_ == kSilenceSignallingNan && m.IsNaN()) {
          return ReplaceFloat32(DoubleToFloat32(SilenceNaN(m.ResolvedValue())));
        }
        return ReplaceFloat32(DoubleToFloat32(m.ResolvedValue()));
      }
      if (signalling_nan_propagation_ == kPropagateSignallingNan &&
          m.IsChangeFloat32ToFloat64())
        return Replace(m.node()->InputAt(0));
      break;
    }
    case IrOpcode::kRoundFloat64ToInt32: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue()) {
        return ReplaceInt32(DoubleToInt32(m.ResolvedValue()));
      }
      if (m.IsChangeInt32ToFloat64()) return Replace(m.node()->InputAt(0));
      break;
    }
    case IrOpcode::kFloat64InsertLowWord32:
      return ReduceFloat64InsertLowWord32(node);
    case IrOpcode::kFloat64InsertHighWord32:
      return ReduceFloat64InsertHighWord32(node);
    case IrOpcode::kStore:
    case IrOpcode::kUnalignedStore:
      return ReduceStore(node);
    case IrOpcode::kFloat64Equal:
    case IrOpcode::kFloat64LessThan:
    case IrOpcode::kFloat64LessThanOrEqual:
      return ReduceFloat64Compare(node);
    case IrOpcode::kFloat64RoundDown:
      return ReduceFloat64RoundDown(node);
    case IrOpcode::kBitcastTaggedToWord:
    case IrOpcode::kBitcastTaggedToWordForTagAndSmiBits: {
      NodeMatcher m(node->InputAt(0));
      if (m.IsBitcastWordToTaggedSigned()) {
        RelaxEffectsAndControls(node);
        return Replace(m.InputAt(0));
      }
      break;
    }
    case IrOpcode::kBranch:
    case IrOpcode::kDeoptimizeIf:
    case IrOpcode::kDeoptimizeUnless:
#if V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kTrapIf:
    case IrOpcode::kTrapUnless:
#endif
      return ReduceConditional(node);
    case IrOpcode::kInt64LessThan: {
      Int64BinopMatcher m(node);
      if (m.IsFoldable()) {  // K < K => K  (K stands for arbitrary constants)
        return ReplaceBool(m.left().ResolvedValue() <
                           m.right().ResolvedValue());
      }
      return ReduceWord64Comparisons(node);
    }
    case IrOpcode::kInt64LessThanOrEqual: {
      Int64BinopMatcher m(node);
      if (m.IsFoldable()) {  // K <= K => K  (K stands for arbitrary constants)
        return ReplaceBool(m.left().ResolvedValue() <=
                           m.right().ResolvedValue());
      }
      return ReduceWord64Comparisons(node);
    }
    case IrOpcode::kUint64LessThan: {
      Uint64BinopMatcher m(node);
      if (m.IsFoldable()) {  // K < K => K  (K stands for arbitrary constants)
        return ReplaceBool(m.left().ResolvedValue() <
                           m.right().ResolvedValue());
      }
      return ReduceWord64Comparisons(node);
    }
    case IrOpcode::kUint64LessThanOrEqual: {
      return ReduceUintNLessThanOrEqual<Word64Adapter>(node);
    }
    case IrOpcode::kFloat32Select:
    case IrOpcode::kFloat64Select:
    case IrOpcode::kWord32Select:
    case IrOpcode::kWord64Select: {
      Int32Matcher match(node->InputAt(0));
      if (match.HasResolvedValue()) {
        if (match.Is(0)) {
          return Replace(node->InputAt(2));
        } else {
          return Replace(node->InputAt(1));
        }
      }
      break;
    }
    case IrOpcode::kLoad:
    case IrOpcode::kProtectedLoad:
    case IrOpcode::kLoadTrapOnNull: {
      Node* input0 = node->InputAt(0);
      Node* input1 = node->InputAt(1);
      if (input0->opcode() == IrOpcode::kInt64Add) {
        Int64BinopMatcher m(input0);
        if (m.right().HasResolvedValue()) {
          int64_t value = m.right().ResolvedValue();
          node->ReplaceInput(0, m.left().node());
          Node* new_node = Int64Add(input1, Int64Constant(value));
          node->ReplaceInput(1, new_node);
          return Changed(node);
        }
      }
      break;
    }
    default:
      break;
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceTruncateInt64ToInt32(Node* node) {
  Int64Matcher m(node->InputAt(0));
  if (m.HasResolvedValue())
    return ReplaceInt32(static_cast<int32_t>(m.ResolvedValue()));
  if (m.IsChangeInt32ToInt64() || m.IsChangeUint32ToUint64())
    return Replace(m.node()->InputAt(0));
  // TruncateInt64ToInt32(BitcastTaggedToWordForTagAndSmiBits(Load(x))) =>
  // Load(x)
  // where the new Load uses Int32 rather than the tagged representation.
  if (m.IsBitcastTaggedToWordForTagAndSmiBits() && m.node()->UseCount() == 1) {
    Node* input = m.node()->InputAt(0);
    if (input->opcode() == IrOpcode::kLoad ||
        input->opcode() == IrOpcode::kLoadImmutable) {
      LoadRepresentation load_rep = LoadRepresentationOf(input->op());
      if (ElementSizeLog2Of(load_rep.representation()) == 2) {
        // Ensure that the value output of the load is only ever used by the
        // BitcastTaggedToWordForTagAndSmiBits.
        int value_edges = 0;
        for (Edge edge : input->use_edges()) {
          if (NodeProperties::IsValueEdge(edge)) ++value_edges;
        }
        if (value_edges == 1) {
          // Removing the input is required as node is replaced by the Load, but
          // is still used by the the BitcastTaggedToWordForTagAndSmiBits, so
          // will prevent future CanCover calls being true.
          m.node()->RemoveInput(0);
          NodeProperties::ChangeOp(
              input,
              input->opcode() == IrOpcode::kLoad
                  ? machine()->Load(LoadRepresentation::Int32())
                  : machine()->LoadImmutable(LoadRepresentation::Int32()));
          return Replace(input);
        }
      }
    }
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceInt32Add(Node* node) {
  DCHECK_EQ(IrOpcode::kInt32Add, node->opcode());
  Int32BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x + 0 => x
  if (m.IsFoldable()) {  // K + K => K  (K stands for arbitrary constants)
    return ReplaceInt32(base::AddWithWraparound(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  if (m.left().IsInt32Sub()) {
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.left().Is(0)) {  // (0 - x) + y => y - x
      node->ReplaceInput(0, m.right().node());
      node->ReplaceInput(1, mleft.right().node());
      NodeProperties::ChangeOp(node, machine()->Int32Sub());
      return Changed(node).FollowedBy(ReduceInt32Sub(node));
    }
  }
  if (m.right().IsInt32Sub()) {
    Int32BinopMatcher mright(m.right().node());
    if (mright.left().Is(0)) {  // y + (0 - x) => y - x
      node->ReplaceInput(1, mright.right().node());
      NodeProperties::ChangeOp(node, machine()->Int32Sub());
      return Changed(node).FollowedBy(ReduceInt32Sub(node));
    }
  }
  // (x + Int32Constant(a)) + Int32Constant(b)) => x + Int32Constant(a + b)
  if (m.right().HasResolvedValue() && m.left().IsInt32Add()) {
    Int32BinopMatcher n(m.left().node());
    if (n.right().HasResolvedValue() && m.OwnsInput(m.left().node())) {
      node->ReplaceInput(
          1, Int32Constant(base::AddWithWraparound(m.right().ResolvedValue(),
                                                   n.right().ResolvedValue())));
      node->ReplaceInput(0, n.left().node());
      return Changed(node);
    }
  }

  return NoChange();
}

Reduction MachineOperatorReducer::ReduceInt64Add(Node* node) {
  DCHECK_EQ(IrOpcode::kInt64Add, node->opcode());
  Int64BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x + 0 => 0
  if (m.IsFoldable()) {
    return ReplaceInt64(base::AddWithWraparound(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  // (x + Int64Constant(a)) + Int64Constant(b) => x + Int64Constant(a + b)
  if (m.right().HasResolvedValue() && m.left().IsInt64Add()) {
    Int64BinopMatcher n(m.left().node());
    if (n.right().HasResolvedValue() && m.OwnsInput(m.left().node())) {
      node->ReplaceInput(
          1, Int64Constant(base::AddWithWraparound(m.right().ResolvedValue(),
                                                   n.right().ResolvedValue())));
      node->ReplaceInput(0, n.left().node());
      return Changed(node);
    }
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceInt32Sub(Node* node) {
  DCHECK_EQ(IrOpcode::kInt32Sub, node->opcode());
  Int32BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x - 0 => x
  if (m.IsFoldable()) {  // K - K => K  (K stands for arbitrary constants)
    return ReplaceInt32(base::SubWithWraparound(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  if (m.LeftEqualsRight()) return ReplaceInt32(0);  // x - x => 0
  if (m.right().HasResolvedValue()) {               // x - K => x + -K
    node->ReplaceInput(
        1,
        Int32Constant(base::NegateWithWraparound(m.right().ResolvedValue())));
    NodeProperties::ChangeOp(node, machine()->Int32Add());
    return Changed(node).FollowedBy(ReduceInt32Add(node));
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceInt64Sub(Node* node) {
  DCHECK_EQ(IrOpcode::kInt64Sub, node->opcode());
  Int64BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x - 0 => x
  if (m.IsFoldable()) {  // K - K => K  (K stands for arbitrary constants)
    return ReplaceInt64(base::SubWithWraparound(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  if (m.LeftEqualsRight()) return Replace(Int64Constant(0));  // x - x => 0
  if (m.right().HasResolvedValue()) {                         // x - K => x + -K
    node->ReplaceInput(
        1,
        Int64Constant(base::NegateWithWraparound(m.right().ResolvedValue())));
    NodeProperties::ChangeOp(node, machine()->Int64Add());
    return Changed(node).FollowedBy(ReduceInt64Add(node));
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceInt64Mul(Node* node) {
  DCHECK_EQ(IrOpcode::kInt64Mul, node->opcode());
  Int64BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.right().node());  // x * 0 => 0
  if (m.right().Is(1)) return Replace(m.left().node());   // x * 1 => x
  if (m.IsFoldable()) {  // K * K => K  (K stands for arbitrary constants)
    return ReplaceInt64(base::MulWithWraparound(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  if (m.right().Is(-1)) {  // x * -1 => 0 - x
    node->ReplaceInput(0, Int64Constant(0));
    node->ReplaceInput(1, m.left().node());
    NodeProperties::ChangeOp(node, machine()->Int64Sub());
    return Changed(node);
  }
  if (m.right().IsPowerOf2()) {  // x * 2^n => x << n
    node->ReplaceInput(
        1,
        Int64Constant(base::bits::WhichPowerOfTwo(m.right().ResolvedValue())));
    NodeProperties::ChangeOp(node, machine()->Word64Shl());
    return Changed(node).FollowedBy(ReduceWord64Shl(node));
  }
  // (x * Int64Constant(a)) * Int64Constant(b)) => x * Int64Constant(a * b)
  if (m.right().HasResolvedValue() && m.left().IsInt64Mul()) {
    Int64BinopMatcher n(m.left().node());
    if (n.right().HasResolvedValue() && m.OwnsInput(m.left().node())) {
      node->ReplaceInput(
          1, Int64Constant(base::MulWithWraparound(m.right().ResolvedValue(),
                                                   n.right().ResolvedValue())));
      node->ReplaceInput(0, n.left().node());
      return Changed(node);
    }
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceInt32Div(Node* node) {
  Int32BinopMatcher m(node);
  if (m.left().Is(0)) return Replace(m.left().node());    // 0 / x => 0
  if (m.right().Is(0)) return Replace(m.right().node());  // x / 0 => 0
  if (m.right().Is(1)) return Replace(m.left().node());   // x / 1 => x
  if (m.IsFoldable()) {  // K / K => K  (K stands for arbitrary constants)
    return ReplaceInt32(base::bits::SignedDiv32(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  if (m.LeftEqualsRight()) {  // x / x => x != 0
    Node* const zero = Int32Constant(0);
    return Replace(Word32Equal(Word32Equal(m.left().node(), zero), zero));
  }
  if (m.right().Is(-1)) {  // x / -1 => 0 - x
    node->ReplaceInput(0, Int32Constant(0));
    node->ReplaceInput(1, m.left().node());
    node->TrimInputCount(2);
    NodeProperties::ChangeOp(node, machine()->Int32Sub());
    return Changed(node);
  }
  if (m.right().HasResolvedValue()) {
    int32_t const divisor = m.right().ResolvedValue();
    Node* const dividend = m.left().node();
    Node* quotient = dividend;
    if (base::bits::IsPowerOfTwo(Abs(divisor))) {
      uint32_t const shift = base::bits::WhichPowerOfTwo(Abs(divisor));
      DCHECK_NE(0u, shift);
      if (shift > 1) {
        quotient = Word32Sar(quotient, 31);
      }
      quotient = Int32Add(Word32Shr(quotient, 32u - shift), dividend);
      quotient = Word32Sar(quotient, shift);
    } else {
      quotient = Int32Div(quotient, Abs(divisor));
    }
    if (divisor < 0) {
      node->ReplaceInput(0, Int32Constant(0));
      node->ReplaceInput(1, quotient);
      node->TrimInputCount(2);
      NodeProperties::ChangeOp(node, machine()->Int32Sub());
      return Changed(node);
    }
    return Replace(quotient);
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceInt64Div(Node* node) {
  Int64BinopMatcher m(node);
  if (m.left().Is(0)) return Replace(m.left().node());    // 0 / x => 0
  if (m.right().Is(0)) return Replace(m.right().node());  // x / 0 => 0
  if (m.right().Is(1)) return Replace(m.left().node());   // x / 1 => x
  if (m.IsFoldable()) {  // K / K => K  (K stands for arbitrary constants)
    return ReplaceInt64(base::bits::SignedDiv64(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  if (m.LeftEqualsRight()) {  // x / x => x != 0
    Node* const zero = Int64Constant(0);
    // {Word64Equal} can get reduced to a bool/int32, but we need this
    // operation to produce an int64.
    return Replace(ChangeInt32ToInt64(
        Word64Equal(Word64Equal(m.left().node(), zero), zero)));
  }
  if (m.right().Is(-1)) {  // x / -1 => 0 - x
    node->ReplaceInput(0, Int64Constant(0));
    node->ReplaceInput(1, m.left().node());
    node->TrimInputCount(2);
    NodeProperties::ChangeOp(node, machine()->Int64Sub());
    return Changed(node);
  }
  if (m.right().HasResolvedValue()) {
    int64_t const divisor = m.right().ResolvedValue();
    Node* const dividend = m.left().node();
    Node* quotient = dividend;
    if (base::bits::IsPowerOfTwo(Abs(divisor))) {
      uint32_t const shift = base::bits::WhichPowerOfTwo(Abs(divisor));
      DCHECK_NE(0u, shift);
      if (shift > 1) {
        quotient = Word64Sar(quotient, 63);
      }
      quotient = Int64Add(Word64Shr(quotient, 64u - shift), dividend);
      quotient = Word64Sar(quotient, shift);
    } else {
      quotient = Int64Div(quotient, Abs(divisor));
    }
    if (divisor < 0) {
      node->ReplaceInput(0, Int64Constant(0));
      node->ReplaceInput(1, quotient);
      node->TrimInputCount(2);
      NodeProperties::ChangeOp(node, machine()->Int64Sub());
      return Changed(node);
    }
    return Replace(quotient);
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceUint32Div(Node* node) {
  Uint32BinopMatcher m(node);
  if (m.left().Is(0)) return Replace(m.left().node());    // 0 / x => 0
  if (m.right().Is(0)) return Replace(m.right().node());  // x / 0 => 0
  if (m.right().Is(1)) return Replace(m.left().node());   // x / 1 => x
  if (m.IsFoldable()) {  // K / K => K  (K stands for arbitrary constants)
    return ReplaceUint32(base::bits::UnsignedDiv32(m.left().ResolvedValue(),
                                                   m.right().ResolvedValue()));
  }
  if (m.LeftEqualsRight()) {  // x / x => x != 0
    Node* const zero = Int32Constant(0);
    return Replace(Word32Equal(Word32Equal(m.left().node(), zero), zero));
  }
  if (m.right().HasResolvedValue()) {
    Node* const dividend = m.left().node();
    uint32_t const divisor = m.right().ResolvedValue();
    if (base::bits::IsPowerOfTwo(divisor)) {  // x / 2^n => x >> n
      node->ReplaceInput(1, Uint32Constant(base::bits::WhichPowerOfTwo(
                                m.right().ResolvedValue())));
      node->TrimInputCount(2);
      NodeProperties::ChangeOp(node, machine()->Word32Shr());
      return Changed(node);
    } else {
      return Replace(Uint32Div(dividend, divisor));
    }
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceUint64Div(Node* node) {
  Uint64BinopMatcher m(node);
  if (m.left().Is(0)) return Replace(m.left().node());    // 0 / x => 0
  if (m.right().Is(0)) return Replace(m.right().node());  // x / 0 => 0
  if (m.right().Is(1)) return Replace(m.left().node());   // x / 1 => x
  if (m.IsFoldable()) {  // K / K => K  (K stands for arbitrary constants)
    return ReplaceUint64(base::bits::UnsignedDiv64(m.left().ResolvedValue(),
                                                   m.right().ResolvedValue()));
  }
  if (m.LeftEqualsRight()) {  // x / x => x != 0
    Node* const zero = Int64Constant(0);
    // {Word64Equal} can get reduced to a bool/int32, but we need this
    // operation to produce an int64.
    return Replace(ChangeInt32ToInt64(
        Word64Equal(Word64Equal(m.left().node(), zero), zero)));
  }
  if (m.right().HasResolvedValue()) {
    Node* const dividend = m.left().node();
    uint64_t const divisor = m.right().ResolvedValue();
    if (base::bits::IsPowerOfTwo(divisor)) {  // x / 2^n => x >> n
      node->ReplaceInput(1, Uint64Constant(base::bits::WhichPowerOfTwo(
                                m.right().ResolvedValue())));
      node->TrimInputCount(2);
      NodeProperties::ChangeOp(node, machine()->Word64Shr());
      return Changed(node);
    } else {
      return Replace(Uint64Div(dividend, divisor));
    }
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceInt32Mod(Node* node) {
  Int32BinopMatcher m(node);
  if (m.left().Is(0)) return Replace(m.left().node());    // 0 % x  => 0
  if (m.right().Is(0)) return Replace(m.right().node());  // x % 0  => 0
  if (m.right().Is(1)) return ReplaceInt32(0);            // x % 1  => 0
  if (m.right().Is(-1)) return ReplaceInt32(0);           // x % -1 => 0
  if (m.LeftEqualsRight()) return ReplaceInt32(0);        // x % x  => 0
  if (m.IsFoldable()) {  // K % K => K  (K stands for arbitrary constants)
    return ReplaceInt32(base::bits::SignedMod32(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  if (m.right().HasResolvedValue()) {
    Node* const dividend = m.left().node();
    uint32_t const divisor = Abs(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(divisor)) {
      uint32_t const mask = divisor - 1;
      Node* const zero = Int32Constant(0);
      Diamond d(graph(), common(),
                graph()->NewNode(machine()->Int32LessThan(), dividend, zero),
                BranchHint::kFalse);
      return Replace(
          d.Phi(MachineRepresentation::kWord32,
                Int32Sub(zero, Word32And(Int32Sub(zero, dividend), mask)),
                Word32And(dividend, mask)));
    } else {
      Node* quotient = Int32Div(dividend, divisor);
      DCHECK_EQ(dividend, node->InputAt(0));
      node->ReplaceInput(1, Int32Mul(quotient, Int32Constant(divisor)));
      node->TrimInputCount(2);
      NodeProperties::ChangeOp(node, machine()->Int32Sub());
    }
    return Changed(node);
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceInt64Mod(Node* node) {
  Int64BinopMatcher m(node);
  if (m.left().Is(0)) return Replace(m.left().node());    // 0 % x  => 0
  if (m.right().Is(0)) return Replace(m.right().node());  // x % 0  => 0
  if (m.right().Is(1)) return ReplaceInt64(0);            // x % 1  => 0
  if (m.right().Is(-1)) return ReplaceInt64(0);           // x % -1 => 0
  if (m.LeftEqualsRight()) return ReplaceInt64(0);        // x % x  => 0
  if (m.IsFoldable()) {  // K % K => K  (K stands for arbitrary constants)
    return ReplaceInt64(base::bits::SignedMod64(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  if (m.right().HasResolvedValue()) {
    Node* const dividend = m.left().node();
    uint64_t const divisor = Abs(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(divisor)) {
      uint64_t const mask = divisor - 1;
      Node* const zero = Int64Constant(0);
      Diamond d(graph(), common(),
                graph()->NewNode(machine()->Int64LessThan(), dividend, zero),
                BranchHint::kFalse);
      return Replace(
          d.Phi(MachineRepresentation::kWord64,
                Int64Sub(zero, Word64And(Int64Sub(zero, dividend), mask)),
                Word64And(dividend, mask)));
    } else {
      Node* quotient = Int64Div(dividend, divisor);
      DCHECK_EQ(dividend, node->InputAt(0));
      node->ReplaceInput(1, Int64Mul(quotient, Int64Constant(divisor)));
      node->TrimInputCount(2);
      NodeProperties::ChangeOp(node, machine()->Int64Sub());
    }
    return Changed(node);
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceUint32Mod(Node* node) {
  Uint32BinopMatcher m(node);
  if (m.left().Is(0)) return Replace(m.left().node());    // 0 % x => 0
  if (m.right().Is(0)) return Replace(m.right().node());  // x % 0 => 0
  if (m.right().Is(1)) return ReplaceUint32(0);           // x % 1 => 0
  if (m.LeftEqualsRight()) return ReplaceUint32(0);       // x % x  => 0
  if (m.IsFoldable()) {  // K % K => K  (K stands for arbitrary constants)
    return ReplaceUint32(base::bits::UnsignedMod32(m.left().ResolvedValue(),
                                                   m.right().ResolvedValue()));
  }
  if (m.right().HasResolvedValue()) {
    Node* const dividend = m.left().node();
    uint32_t const divisor = m.right().ResolvedValue();
    if (base::bits::IsPowerOfTwo(divisor)) {  // x % 2^n => x & 2^n-1
      node->ReplaceInput(1, Uint32Constant(m.right().ResolvedValue() - 1));
      node->TrimInputCount(2);
      NodeProperties::ChangeOp(node, machine()->Word32And());
    } else {
      Node* quotient = Uint32Div(dividend, divisor);
      DCHECK_EQ(dividend, node->InputAt(0));
      node->ReplaceInput(1, Int32Mul(quotient, Uint32Constant(divisor)));
      node->TrimInputCount(2);
      NodeProperties::ChangeOp(node, machine()->Int32Sub());
    }
    return Changed(node);
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceUint64Mod(Node* node) {
  Uint64BinopMatcher m(node);
  if (m.left().Is(0)) return Replace(m.left().node());    // 0 % x => 0
  if (m.right().Is(0)) return Replace(m.right().node());  // x % 0 => 0
  if (m.right().Is(1)) return ReplaceUint64(0);           // x % 1 => 0
  if (m.LeftEqualsRight()) return ReplaceUint64(0);       // x % x  => 0
  if (m.IsFoldable()) {  // K % K => K  (K stands for arbitrary constants)
    return ReplaceUint64(base::bits::UnsignedMod64(m.left().ResolvedValue(),
                                                   m.right().ResolvedValue()));
  }
  if (m.right().HasResolvedValue()) {
    Node* const dividend = m.left().node();
    uint64_t const divisor = m.right().ResolvedValue();
    if (base::bits::IsPowerOfTwo(divisor)) {  // x % 2^n => x & 2^n-1
      node->ReplaceInput(1, Uint64Constant(m.right().ResolvedValue() - 1));
      node->TrimInputCount(2);
      NodeProperties::ChangeOp(node, machine()->Word64And());
    } else {
      Node* quotient = Uint64Div(dividend, divisor);
      DCHECK_EQ(dividend, node->InputAt(0));
      node->ReplaceInput(1, Int64Mul(quotient, Uint64Constant(divisor)));
      node->TrimInputCount(2);
      NodeProperties::ChangeOp(node, machine()->Int64Sub());
    }
    return Changed(node);
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceStore(Node* node) {
  NodeMatcher nm(node);
  DCHECK(nm.IsStore() || nm.IsUnalignedStore());
  MachineRepresentation rep =
      nm.IsStore() ? StoreRepresentationOf(node->op()).representation()
                   : UnalignedStoreRepresentationOf(node->op());

  const int value_input = 2;
  Node* const value = node->InputAt(value_input);

  switch (value->opcode()) {
    case IrOpcode::kWord32And: {
      Uint32BinopMatcher m(value);
      if (m.right().HasResolvedValue() &&
          ((rep == MachineRepresentation::kWord8 &&
            (m.right().ResolvedValue() & 0xFF) == 0xFF) ||
           (rep == MachineRepresentation::kWord16 &&
            (m.right().ResolvedValue() & 0xFFFF) == 0xFFFF))) {
        node->ReplaceInput(value_input, m.left().node());
        return Changed(node);
      }
      break;
    }
    case IrOpcode::kWord32Sar: {
      Int32BinopMatcher m(value);
      if (m.left().IsWord32Shl() && ((rep == MachineRepresentation::kWord8 &&
                                      m.right().IsInRange(1, 24)) ||
                                     (rep == MachineRepresentation::kWord16 &&
                                      m.right().IsInRange(1, 16)))) {
        Int32BinopMatcher mleft(m.left().node());
        if (mleft.right().Is(m.right().ResolvedValue())) {
          node->ReplaceInput(value_input, mleft.left().node());
          return Changed(node);
        }
      }
      break;
    }
    default:
      break;
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceProjection(size_t index, Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kInt32AddWithOverflow: {
      DCHECK(index == 0 || index == 1);
      Int32BinopMatcher m(node);
      if (m.IsFoldable()) {
        int32_t val;
        bool ovf = base::bits::SignedAddOverflow32(
            m.left().ResolvedValue(), m.right().ResolvedValue(), &val);
        return ReplaceInt32(index == 0 ? val : ovf);
      }
      if (m.right().Is(0)) {
        return Replace(index == 0 ? m.left().node() : m.right().node());
      }
      break;
    }
    case IrOpcode::kInt32SubWithOverflow: {
      DCHECK(index == 0 || index == 1);
      Int32BinopMatcher m(node);
      if (m.IsFoldable()) {
        int32_t val;
        bool ovf = base::bits::SignedSubOverflow32(
            m.left().ResolvedValue(), m.right().ResolvedValue(), &val);
        return ReplaceInt32(index == 0 ? val : ovf);
      }
      if (m.right().Is(0)) {
        return Replace(index == 0 ? m.left().node() : m.right().node());
      }
      break;
    }
    case IrOpcode::kInt32MulWithOverflow: {
      DCHECK(index == 0 || index == 1);
      Int32BinopMatcher m(node);
      if (m.IsFoldable()) {
        int32_t val;
        bool ovf = base::bits::SignedMulOverflow32(
            m.left().ResolvedValue(), m.right().ResolvedValue(), &val);
        return ReplaceInt32(index == 0 ? val : ovf);
      }
      if (m.right().Is(0)) {
        return Replace(m.right().node());
      }
      if (m.right().Is(1)) {
        return index == 0 ? Replace(m.left().node()) : ReplaceInt32(0);
      }
      break;
    }
    default:
      break;
  }
  return NoChange();
}

namespace {

// Returns true if "value << shift >> shift == value". This can be interpreted
// as "left shifting |value| by |shift| doesn't shift away significant bits".
// Or, equivalently, "left shifting |value| by |shift| doesn't have signed
// overflow".
template <typename T>
bool CanRevertLeftShiftWithRightShift(T value, T shift) {
  using unsigned_T = typename std::make_unsigned<T>::type;
  if (shift < 0 || shift >= std::numeric_limits<T>::digits + 1) {
    // This shift would be UB in C++
    return false;
  }
  if (static_cast<T>(static_cast<unsigned_T>(value) << shift) >> shift !=
      static_cast<T>(value)) {
    return false;
  }
  return true;
}

bool CanTruncate(int64_t value) {
  return value >= std::numeric_limits<int32_t>::min() &&
         value <= std::numeric_limits<int32_t>::max();
}

}  // namespace

Reduction MachineOperatorReducer::ReduceWord32Comparisons(Node* node) {
  DCHECK(node->opcode() == IrOpcode::kInt32LessThan ||
         node->opcode() == IrOpcode::kInt32LessThanOrEqual ||
         node->opcode() == IrOpcode::kUint32LessThan ||
         node->opcode() == IrOpcode::kUint32LessThanOrEqual);
  Int32BinopMatcher m(node);
  // (x >> K) < (y >> K) => x < y   if only zeros shifted out
  if (m.left().op() == machine()->Word32SarShiftOutZeros() &&
      m.right().op() == machine()->Word32SarShiftOutZeros()) {
    Int32BinopMatcher mleft(m.left().node());
    Int32BinopMatcher mright(m.right().node());
    if (mleft.right().HasResolvedValue() &&
        mright.right().Is(mleft.right().ResolvedValue())) {
      node->ReplaceInput(0, mleft.left().node());
      node->ReplaceInput(1, mright.left().node());
      return Changed(node);
    }
  }
  // Simplifying (x >> n) <= k into x <= (k << n), with "k << n" being
  // computed here at compile time.
  if (m.right().HasResolvedValue() &&
      m.left().op() == machine()->Word32SarShiftOutZeros() &&
      m.left().node()->UseCount() == 1) {
    uint32_t right = m.right().ResolvedValue();
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue()) {
      auto shift = mleft.right().ResolvedValue();
      if (CanRevertLeftShiftWithRightShift<int32_t>(right, shift)) {
        node->ReplaceInput(0, mleft.left().node());
        node->ReplaceInput(1, Int32Constant(right << shift));
        return Changed(node);
      }
    }
  }
  // Simplifying k <= (x >> n) into (k << n) <= x, with "k << n" being
  // computed here at compile time.
  if (m.left().HasResolvedValue() &&
      m.right().op() == machine()->Word32SarShiftOutZeros() &&
      m.right().node()->UseCount() == 1) {
    uint32_t left = m.left().ResolvedValue();
    Int32BinopMatcher mright(m.right().node());
    if (mright.right().Ha
"""


```