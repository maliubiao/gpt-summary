Response: Let's break down the thought process for summarizing the second part of the `machine-operator-reducer.cc` file.

1. **Understand the Context:** The prompt clearly states this is *part 2* of a file analysis, focusing on functionality. This immediately suggests building upon the understanding from part 1 (even though we don't have part 1's content here, the naming convention implies a logical division). The file name, `machine-operator-reducer.cc`, is a strong indicator of its purpose.

2. **Initial Scan for Key Concepts:**  Quickly read through the code, looking for recurring keywords, function names, and patterns. Some immediately stand out:
    * `Reduce...`:  This prefix is consistently used for many functions. It strongly suggests the core function of these methods is to *simplify* or *transform* nodes in the graph.
    * `Word32`, `Word64`, `Float64`, `Int32`, `Int64`, `Uint32`, `Uint64`: These types clearly indicate the operations being performed are at the machine level, dealing with specific data sizes.
    * `Shl`, `Shr`, `Sar`, `And`, `Or`, `Xor`, `Equal`, `LessThan`, `LessThanOrEqual`: These are standard bitwise and arithmetic operations.
    * `Constant`:  Indicates simplification involving known values.
    * `Comparison`, `Branch`, `Conditional`: Points to logic and control flow simplification.
    * `Matcher`: This likely represents a helper class for easily accessing and checking the inputs of a node.
    * `ReplaceInput`, `ChangeOp`, `Replace`: These methods are about modifying the structure of the graph.

3. **Identify Major Categories of Operations:** Based on the keywords and function prefixes, we can start grouping related functionalities:
    * **Bitwise Operations:** Functions like `ReduceWord32Shl`, `ReduceWord64And`, `ReduceWord32Or`, etc., clearly belong here. The code within these functions often involves bit manipulations and constant folding.
    * **Comparisons:**  Functions like `ReduceWord64Comparisons`, `ReduceWord32Equal`, `ReduceFloat64Compare` are about simplifying comparison operations. They often involve type conversions and constant propagation.
    * **Floating-Point Operations:** `ReduceFloat64InsertLowWord32`, `ReduceFloat64RoundDown` are specific to floating-point manipulations.
    * **Conditional Logic:** `ReduceConditional`, `SimplifyBranch` deal with simplifying the conditions in `if` statements and branches.

4. **Analyze Individual Function Patterns:**  For each category, examine the functions within. Notice common patterns:
    * **Constant Folding:**  Many functions check if inputs are constants (`IsFoldable`, `HasResolvedValue`) and perform the operation at compile time.
    * **Identity and Zero Cases:**  Often, there are special cases for operations with 0 or -1.
    * **Algebraic Simplifications:**  Look for transformations like `(x >> K) << K` becoming `x & mask`.
    * **Type Conversions:**  Simplifying comparisons between different integer sizes or between floats and doubles.
    * **Pattern Matching:**  Recognizing specific sequences of operations that can be replaced by a more efficient one (e.g., the ROR optimization).

5. **Look for Connections to JavaScript (as requested):**  While this is C++ code operating at a low level, the transformations directly impact how JavaScript code is executed. Consider:
    * **Bitwise Operations:** JavaScript uses bitwise operators (`&`, `|`, `^`, `<<`, `>>`, `>>>`). The optimizations here directly speed up these operations. Examples can be constructed to show how these operators work.
    * **Comparisons:** JavaScript's comparison operators (`==`, `!=`, `<`, `>`, `<=`, `>=`) are affected by these reductions. Type coercion in JavaScript often leads to comparisons between different numeric types, making these optimizations relevant.
    * **Floating-Point Numbers:** JavaScript uses double-precision floating-point numbers. Optimizations on `Float64` directly improve the performance of JavaScript code dealing with numbers.
    * **Conditional Statements:** JavaScript's `if` statements are influenced by the simplification of branch conditions.

6. **Formulate the Summary:** Based on the above analysis, start drafting the summary. Focus on:
    * **Overall Purpose:** Reinforce the idea of optimizing machine-level operations.
    * **Key Areas of Focus:** List the main categories of operations being reduced.
    * **Specific Examples of Reductions:** Provide concrete examples of how the code simplifies expressions. Use illustrative variable names (like `x`, `y`, `K`).
    * **Connection to JavaScript:** Explain *why* these optimizations matter for JavaScript performance and provide simple JavaScript code examples to illustrate the relevant concepts.

7. **Refine and Organize:**  Review the summary for clarity, conciseness, and accuracy. Ensure the JavaScript examples are easy to understand. Use bullet points or numbered lists to improve readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just optimizes bitwise operations."  **Correction:**  Realized it also covers comparisons and floating-point operations.
* **Initial thought:** "The JavaScript connection is weak." **Correction:** Focused on how the *results* of these low-level optimizations directly impact the performance of JavaScript operators and control flow. Providing concrete JavaScript examples helped solidify the connection.
* **Initial thought:** "Just list all the functions." **Correction:** Grouped functions into logical categories for a more structured and understandable summary.
* **Struggling to understand a specific function:** Read the code comments carefully. Look for patterns in the input node types and how the output node is modified. Try to infer the algebraic identity being applied.

By following this structured approach, we can effectively analyze and summarize the functionality of this C++ code and its relevance to JavaScript.
这是 `v8/src/compiler/machine-operator-reducer.cc` 源代码文件的第二部分，它延续了第一部分的功能，**核心目标仍然是通过模式匹配和代数简化来优化机器级别的操作**。

以下是这部分的主要功能归纳：

**1. 进一步简化位运算：**

* **移位操作 (`Word32Shl`, `Word64Shl`, `Word32Shr`, `Word64Shr`, `Word32Sar`, `Word64Sar`)：**
    * 处理移位 0 的情况，直接替换为原操作数。
    * 常量移位：如果左右操作数都是常量，直接计算结果。
    * 识别和简化特定模式，例如 `(x >> K) << L` 的各种情况。
    * 利用 `Word32SarShiftOutZeros` 和 `Word64SarShiftOutZeros` 来进行优化，这通常与 Smi (Small Integer) 的解标签操作有关。
    * 移除不必要的 `Word32And` 操作，如果机器指令本身已经保证了移位量的安全性。
* **按位与、或、异或操作 (`ReduceWord32And`, `ReduceWord64And`, `ReduceWord32Or`, `ReduceWord64Or`, `ReduceWord32Xor`, `ReduceWord64Xor`)：**
    * 处理与 0、与 -1、或 0、或 -1 的情况。
    * 常量折叠：如果左右操作数都是常量，直接计算结果。
    * 识别和简化特定模式，例如 `x & x` 替换为 `x`， `x ^ 0` 替换为 `x`。
    * 尝试匹配和替换为更高效的旋转操作 (`Word32Ror`)。
    * 针对按位与操作，尝试识别多个针对同一源的位域检查，并将其合并成单个检查。

**2. 进一步简化比较操作：**

* **整数比较 (`ReduceWord64Comparisons`, `ReduceWord32Equal`, `ReduceWord64Equal`)：**
    * 处理比较常量的情况，直接得出布尔结果。
    * 简化比较操作，例如将 `x - y == 0` 替换为 `x == y`。
    * 优化涉及 `ChangeInt32ToInt64` 和 `ChangeUint32ToUint64` 的比较。
    * 如果比较的一方是常量，且另一方是移位操作，尝试将常量移位后再进行比较。
    * 如果可以安全地将 64 位常量转换为 32 位常量，则将 64 位比较降级为 32 位比较。
* **浮点数比较 (`ReduceFloat64Compare`)：**
    * 处理浮点数常量比较的情况。
    * 如果比较的双方都是从 `Float32` 转换而来，则可以将其降级为 `Float32` 的比较。

**3. 简化浮点数操作：**

* `ReduceFloat64InsertLowWord32` 和 `ReduceFloat64InsertHighWord32`：如果输入是常量，则直接计算结果。
* `ReduceFloat64RoundDown`：如果输入是常量，则直接计算结果。

**4. 简化条件分支：**

* `SimplifyBranch`：尝试简化分支条件，移除顶层的 `Word32Equal(x, 0)`，并根据移除情况调整分支方向。
* `ReduceConditional`：处理条件分支、DeoptimizeIf/Unless 和 TrapIf/Unless 节点，尝试简化其条件表达式。
* `TrySimplifyCompareForTestBit`: 优化形如 `Word32Equal(Word32And(x, constant1), constant1)` 的模式，常用于测试特定位是否被设置。
* `TrySimplifyCompareZero`:  移除条件中顶层的 "等于 0" 的比较，并相应地翻转条件的含义。

**5. 通用工具函数和模板：**

* 提供了一些辅助函数和模板，例如 `Map64To32Comparison` 用于将 64 位比较操作映射到 32 位操作，以及 `ReduceWordNAnd`、`ReduceWordNOr`、`ReduceWordNXor`、`ReduceUintNLessThanOrEqual` 等模板函数，用于处理不同位宽的整数运算。
* `TryMatchWord32Ror` 和模板化的 `TryMatchWordNRor` 用于识别并替换为旋转操作。
* `ReduceWordEqualForConstantRhs` 模板函数用于优化与常量进行相等比较的情况。

**与 JavaScript 的关系及示例：**

这部分代码的功能直接影响 JavaScript 代码的执行效率。V8 引擎在编译 JavaScript 代码时，会将其转换为中间表示 (IR)，而 `machine-operator-reducer.cc` 就是在 IR 层面进行优化的。

**JavaScript 示例：**

```javascript
function testBitwise(a) {
  // JavaScript 的位运算操作
  return (a >> 2) & 1; // 右移 2 位，然后与 1 按位与，检查第 3 位是否为 1
}

function compareNumbers(x, y) {
  // JavaScript 的比较操作
  return x <= y;
}

function floatManipulation(f) {
  // JavaScript 的浮点数操作
  return Math.floor(f);
}

function conditionalLogic(value) {
  // JavaScript 的条件语句
  if (value & 8) { // 检查 value 的第 4 位是否为 1
    console.log("bit is set");
  }
}
```

**对应 C++ 代码的优化：**

* **`testBitwise`:**  `ReduceWord32Shr` 和 `ReduceWord32And` 可以优化 `(a >> 2) & 1` 这个表达式。`TrySimplifyCompareForTestBit` 可以将 `(a & 8) == 8` 的模式简化为直接检查 `a & 8` 的结果。
* **`compareNumbers`:** `ReduceWord64Comparisons` 或 `ReduceFloat64Compare` 可以优化数字的比较操作，例如，如果 `x` 和 `y` 都是小的整数，则可能将 64 位比较降级为 32 位比较。
* **`floatManipulation`:** `ReduceFloat64RoundDown` 可以直接计算 `Math.floor()` 的结果，如果 `f` 是一个常量。
* **`conditionalLogic`:** `SimplifyBranch` 和 `ReduceConditional` 可以优化 `if` 语句的条件，例如，如果条件是 `(value & 8) == 0`，则可以将其简化，并可能调整分支方向。

**总结：**

`machine-operator-reducer.cc` 的第二部分继续致力于对 V8 引擎的中间表示进行细致的机器级优化，涵盖了位运算、比较运算、浮点数运算以及条件分支等多个方面。这些优化直接提升了 JavaScript 代码在底层执行的效率，使得代码运行得更快。它通过识别常见的运算模式，并利用代数和位运算的性质进行简化和替换，生成更高效的机器码。

Prompt: 
```
这是目录为v8/src/compiler/machine-operator-reducer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
sResolvedValue()) {
      auto shift = mright.right().ResolvedValue();
      if (CanRevertLeftShiftWithRightShift<int32_t>(left, shift)) {
        node->ReplaceInput(0, Int32Constant(left << shift));
        node->ReplaceInput(1, mright.left().node());
        return Changed(node);
      }
    }
  }
  return NoChange();
}

const Operator* MachineOperatorReducer::Map64To32Comparison(
    const Operator* op, bool sign_extended) {
  switch (op->opcode()) {
    case IrOpcode::kInt64LessThan:
      return sign_extended ? machine()->Int32LessThan()
                           : machine()->Uint32LessThan();
    case IrOpcode::kInt64LessThanOrEqual:
      return sign_extended ? machine()->Int32LessThanOrEqual()
                           : machine()->Uint32LessThanOrEqual();
    case IrOpcode::kUint64LessThan:
      return machine()->Uint32LessThan();
    case IrOpcode::kUint64LessThanOrEqual:
      return machine()->Uint32LessThanOrEqual();
    default:
      UNREACHABLE();
  }
}

Reduction MachineOperatorReducer::ReduceWord64Comparisons(Node* node) {
  DCHECK(node->opcode() == IrOpcode::kInt64LessThan ||
         node->opcode() == IrOpcode::kInt64LessThanOrEqual ||
         node->opcode() == IrOpcode::kUint64LessThan ||
         node->opcode() == IrOpcode::kUint64LessThanOrEqual);
  Int64BinopMatcher m(node);

  bool sign_extended =
      m.left().IsChangeInt32ToInt64() && m.right().IsChangeInt32ToInt64();
  if (sign_extended || (m.left().IsChangeUint32ToUint64() &&
                        m.right().IsChangeUint32ToUint64())) {
    node->ReplaceInput(0, NodeProperties::GetValueInput(m.left().node(), 0));
    node->ReplaceInput(1, NodeProperties::GetValueInput(m.right().node(), 0));
    NodeProperties::ChangeOp(node,
                             Map64To32Comparison(node->op(), sign_extended));
    return Changed(node).FollowedBy(Reduce(node));
  }

  // (x >> K) < (y >> K) => x < y   if only zeros shifted out
  // This is useful for Smi untagging, which results in such a shift.
  if (m.left().op() == machine()->Word64SarShiftOutZeros() &&
      m.right().op() == machine()->Word64SarShiftOutZeros()) {
    Int64BinopMatcher mleft(m.left().node());
    Int64BinopMatcher mright(m.right().node());
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
      m.left().op() == machine()->Word64SarShiftOutZeros() &&
      m.left().node()->UseCount() == 1) {
    Int64BinopMatcher mleft(m.left().node());
    uint64_t right = m.right().ResolvedValue();
    if (mleft.right().HasResolvedValue()) {
      auto shift = mleft.right().ResolvedValue();
      if (CanRevertLeftShiftWithRightShift<int64_t>(right, shift)) {
        sign_extended = mleft.left().IsChangeInt32ToInt64();
        uint64_t value = right << shift;
        // Reducing to 32-bit comparison when possible.
        if ((sign_extended || mleft.left().IsChangeUint32ToUint64()) &&
            CanTruncate(static_cast<int64_t>(value))) {
          NodeProperties::ChangeOp(
              node, Map64To32Comparison(node->op(), sign_extended));
          node->ReplaceInput(0, mleft.left().node()->InputAt(0));
          node->ReplaceInput(1, Int32Constant(static_cast<int32_t>(value)));
          return Changed(node).FollowedBy(Reduce(node));
        }
        node->ReplaceInput(0, mleft.left().node());
        node->ReplaceInput(1, Int64Constant(value));
        return Changed(node);
      }
    }
  }

  // Simplifying k <= (x >> n) into (k << n) <= x, with "k << n" being
  // computed here at compile time.
  if (m.left().HasResolvedValue() &&
      m.right().op() == machine()->Word64SarShiftOutZeros() &&
      m.right().node()->UseCount() == 1) {
    uint64_t left = m.left().ResolvedValue();
    Int64BinopMatcher mright(m.right().node());
    if (mright.right().HasResolvedValue()) {
      auto shift = mright.right().ResolvedValue();
      if (CanRevertLeftShiftWithRightShift<int64_t>(left, shift)) {
        sign_extended = mright.left().IsChangeInt32ToInt64();
        uint64_t value = left << shift;
        // Reducing to 32-bit comparison when possible.
        if ((sign_extended || mright.left().IsChangeUint32ToUint64()) &&
            CanTruncate(static_cast<int64_t>(value))) {
          NodeProperties::ChangeOp(
              node, Map64To32Comparison(node->op(), sign_extended));
          node->ReplaceInput(0, Int32Constant(static_cast<int32_t>(value)));
          node->ReplaceInput(1, mright.left().node()->InputAt(0));
          return Changed(node).FollowedBy(Reduce(node));
        }
        node->ReplaceInput(0, Int64Constant(value));
        node->ReplaceInput(1, mright.left().node());
        return Changed(node);
      }
    }
  }

  /*
    If Int64Constant(c) can be casted from an Int32Constant:
    -------------------------------------------------
    Int64LessThan(Int32ToInt64(a), Int64Constant(c))
    ====>
    Int32LessThan(a,Int32Constant(c))
    -------------------------------------------------
  */
  if (node->opcode() == IrOpcode::kInt64LessThan ||
      node->opcode() == IrOpcode::kInt64LessThanOrEqual) {
    // Int64LessThan(Int32ToInt64(a), Int64Constant(c))
    if (m.left().IsChangeInt32ToInt64() && m.right().HasResolvedValue()) {
      int64_t right_value = static_cast<int64_t>(m.right().ResolvedValue());
      // Int64Constant can be casted from an Int32Constant
      if (right_value == static_cast<int32_t>(right_value)) {
        const Operator* new_op;

        if (node->opcode() == IrOpcode::kInt64LessThan) {
          new_op = machine()->Int32LessThan();
        } else {
          new_op = machine()->Int32LessThanOrEqual();
        }
        NodeProperties::ChangeOp(node, new_op);
        node->ReplaceInput(0, m.left().InputAt(0));
        node->ReplaceInput(1, Int32Constant(static_cast<int32_t>(right_value)));
        return Changed(node);
      } else if (right_value < std::numeric_limits<int32_t>::min()) {
        // left > right always
        node->TrimInputCount(0);
        NodeProperties::ChangeOp(node, common()->Int32Constant(0));
        return Changed(node);
      } else if (right_value > std::numeric_limits<int32_t>::max()) {
        // left < right always
        node->TrimInputCount(0);
        NodeProperties::ChangeOp(node, common()->Int32Constant(1));
        return Changed(node);
      }
    }
    // Int64LessThan(Int64Constant(c), Int32ToInt64(a))
    if (m.right().IsChangeInt32ToInt64() && m.left().HasResolvedValue()) {
      int64_t left_value = static_cast<int64_t>(m.left().ResolvedValue());
      // Int64Constant can be casted from an Int32Constant
      if (left_value == static_cast<int32_t>(left_value)) {
        const Operator* new_op;

        if (node->opcode() == IrOpcode::kInt64LessThan) {
          new_op = machine()->Int32LessThan();
        } else {
          new_op = machine()->Int32LessThanOrEqual();
        }
        NodeProperties::ChangeOp(node, new_op);
        node->ReplaceInput(1, m.right().InputAt(0));
        node->ReplaceInput(0, Int32Constant(static_cast<int32_t>(left_value)));
        return Changed(node);
      } else if (left_value < std::numeric_limits<int32_t>::min()) {
        // left < right always
        node->TrimInputCount(0);
        NodeProperties::ChangeOp(node, common()->Int32Constant(1));
        return Changed(node);
      } else if (left_value > std::numeric_limits<int32_t>::max()) {
        // left > right always
        node->TrimInputCount(0);
        NodeProperties::ChangeOp(node, common()->Int32Constant(0));
        return Changed(node);
      }
    }
  }

  /*
    If Uint64Constant(c) can be casted from an Uint32Constant:
    -------------------------------------------------
    Uint64LessThan(Uint32ToInt64(a), Uint64Constant(c))
    ====>
    Uint32LessThan(a,Uint32Constant(c))
    -------------------------------------------------
  */
  if (node->opcode() == IrOpcode::kUint64LessThan ||
      node->opcode() == IrOpcode::kUint64LessThanOrEqual) {
    // Uint64LessThan(Uint32ToInt64(a), Uint32Constant(c))
    if (m.left().IsChangeUint32ToUint64() && m.right().HasResolvedValue()) {
      uint64_t right_value = static_cast<uint64_t>(m.right().ResolvedValue());
      // Uint64Constant can be casted from an Uint32Constant
      if (right_value == static_cast<uint32_t>(right_value)) {
        const Operator* new_op;

        if (node->opcode() == IrOpcode::kUint64LessThan) {
          new_op = machine()->Uint32LessThan();
        } else {
          new_op = machine()->Uint32LessThanOrEqual();
        }
        NodeProperties::ChangeOp(node, new_op);
        node->ReplaceInput(0, m.left().InputAt(0));
        node->ReplaceInput(1,
                           Uint32Constant(static_cast<uint32_t>(right_value)));
        return Changed(node);
      } else {
        // left < right always
        node->TrimInputCount(0);
        NodeProperties::ChangeOp(node, common()->Int32Constant(1));
        return Changed(node);
      }
    }
    // Uint64LessThan(Uint64Constant(c), Uint32ToInt64(a))
    if (m.right().IsChangeUint32ToUint64() && m.left().HasResolvedValue()) {
      uint64_t left_value = static_cast<uint64_t>(m.left().ResolvedValue());
      // Uint64Constant can be casted from an Uint32Constant
      if (left_value == static_cast<uint32_t>(left_value)) {
        const Operator* new_op;
        if (node->opcode() == IrOpcode::kUint64LessThan) {
          new_op = machine()->Uint32LessThan();
        } else {
          new_op = machine()->Uint32LessThanOrEqual();
        }
        NodeProperties::ChangeOp(node, new_op);
        node->ReplaceInput(1, m.right().InputAt(0));
        node->ReplaceInput(0,
                           Uint32Constant(static_cast<uint32_t>(left_value)));
        return Changed(node);
      } else {
        // left > right always
        node->TrimInputCount(0);
        NodeProperties::ChangeOp(node, common()->Int32Constant(0));
        return Changed(node);
      }
    }
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceWord32Shifts(Node* node) {
  DCHECK((node->opcode() == IrOpcode::kWord32Shl) ||
         (node->opcode() == IrOpcode::kWord32Shr) ||
         (node->opcode() == IrOpcode::kWord32Sar));
  if (machine()->Word32ShiftIsSafe()) {
    // Remove the explicit 'and' with 0x1F if the shift provided by the machine
    // instruction matches that required by JavaScript.
    Int32BinopMatcher m(node);
    if (m.right().IsWord32And()) {
      Int32BinopMatcher mright(m.right().node());
      if (mright.right().Is(0x1F)) {
        node->ReplaceInput(1, mright.left().node());
        return Changed(node);
      }
    }
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceWord32Shl(Node* node) {
  DCHECK_EQ(IrOpcode::kWord32Shl, node->opcode());
  Int32BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x << 0 => x
  if (m.IsFoldable()) {  // K << K => K  (K stands for arbitrary constants)
    return ReplaceInt32(base::ShlWithWraparound(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  if (m.right().IsInRange(1, 31)) {
    if (m.left().IsWord32Sar() || m.left().IsWord32Shr()) {
      Int32BinopMatcher mleft(m.left().node());

      // If x >> K only shifted out zeros:
      // (x >> K) << L => x           if K == L
      // (x >> K) << L => x >> (K-L) if K > L
      // (x >> K) << L => x << (L-K)  if K < L
      // Since this is used for Smi untagging, we currently only need it for
      // signed shifts.
      if (mleft.op() == machine()->Word32SarShiftOutZeros() &&
          mleft.right().IsInRange(1, 31)) {
        Node* x = mleft.left().node();
        int k = mleft.right().ResolvedValue();
        int l = m.right().ResolvedValue();
        if (k == l) {
          return Replace(x);
        } else if (k > l) {
          node->ReplaceInput(0, x);
          node->ReplaceInput(1, Uint32Constant(k - l));
          NodeProperties::ChangeOp(node, machine()->Word32Sar());
          return Changed(node).FollowedBy(ReduceWord32Sar(node));
        } else {
          DCHECK(k < l);
          node->ReplaceInput(0, x);
          node->ReplaceInput(1, Uint32Constant(l - k));
          return Changed(node);
        }
      }

      // (x >>> K) << K => x & ~(2^K - 1)
      // (x >> K) << K => x & ~(2^K - 1)
      if (mleft.right().Is(m.right().ResolvedValue())) {
        node->ReplaceInput(0, mleft.left().node());
        node->ReplaceInput(1,
                           Uint32Constant(std::numeric_limits<uint32_t>::max()
                                          << m.right().ResolvedValue()));
        NodeProperties::ChangeOp(node, machine()->Word32And());
        return Changed(node).FollowedBy(ReduceWord32And(node));
      }
    }
  }
  return ReduceWord32Shifts(node);
}

Reduction MachineOperatorReducer::ReduceWord64Shl(Node* node) {
  DCHECK_EQ(IrOpcode::kWord64Shl, node->opcode());
  Int64BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x << 0 => x
  if (m.IsFoldable()) {  // K << K => K  (K stands for arbitrary constants)
    return ReplaceInt64(base::ShlWithWraparound(m.left().ResolvedValue(),
                                                m.right().ResolvedValue()));
  }
  if (m.right().IsInRange(1, 63) &&
      (m.left().IsWord64Sar() || m.left().IsWord64Shr())) {
    Int64BinopMatcher mleft(m.left().node());

    // If x >> K only shifted out zeros:
    // (x >> K) << L => x           if K == L
    // (x >> K) << L => x >> (K-L) if K > L
    // (x >> K) << L => x << (L-K)  if K < L
    // Since this is used for Smi untagging, we currently only need it for
    // signed shifts.
    if (mleft.op() == machine()->Word64SarShiftOutZeros() &&
        mleft.right().IsInRange(1, 63)) {
      Node* x = mleft.left().node();
      int64_t k = mleft.right().ResolvedValue();
      int64_t l = m.right().ResolvedValue();
      if (k == l) {
        return Replace(x);
      } else if (k > l) {
        node->ReplaceInput(0, x);
        node->ReplaceInput(1, Uint64Constant(k - l));
        NodeProperties::ChangeOp(node, machine()->Word64Sar());
        return Changed(node).FollowedBy(ReduceWord64Sar(node));
      } else {
        DCHECK(k < l);
        node->ReplaceInput(0, x);
        node->ReplaceInput(1, Uint64Constant(l - k));
        return Changed(node);
      }
    }

    // (x >>> K) << K => x & ~(2^K - 1)
    // (x >> K) << K => x & ~(2^K - 1)
    if (mleft.right().Is(m.right().ResolvedValue())) {
      node->ReplaceInput(0, mleft.left().node());
      node->ReplaceInput(1, Uint64Constant(std::numeric_limits<uint64_t>::max()
                                           << m.right().ResolvedValue()));
      NodeProperties::ChangeOp(node, machine()->Word64And());
      return Changed(node).FollowedBy(ReduceWord64And(node));
    }
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceWord32Shr(Node* node) {
  Uint32BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x >>> 0 => x
  if (m.IsFoldable()) {  // K >>> K => K  (K stands for arbitrary constants)
    return ReplaceInt32(m.left().ResolvedValue() >>
                        (m.right().ResolvedValue() & 31));
  }
  if (m.left().IsWord32And() && m.right().HasResolvedValue()) {
    Uint32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue()) {
      uint32_t shift = m.right().ResolvedValue() & 31;
      uint32_t mask = mleft.right().ResolvedValue();
      if ((mask >> shift) == 0) {
        // (m >>> s) == 0 implies ((x & m) >>> s) == 0
        return ReplaceInt32(0);
      }
    }
  }
  return ReduceWord32Shifts(node);
}

Reduction MachineOperatorReducer::ReduceWord64Shr(Node* node) {
  DCHECK_EQ(IrOpcode::kWord64Shr, node->opcode());
  Uint64BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x >>> 0 => x
  if (m.IsFoldable()) {  // K >> K => K  (K stands for arbitrary constants)
    return ReplaceInt64(m.left().ResolvedValue() >>
                        (m.right().ResolvedValue() & 63));
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceWord32Sar(Node* node) {
  Int32BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x >> 0 => x
  if (m.IsFoldable()) {  // K >> K => K  (K stands for arbitrary constants)
    return ReplaceInt32(m.left().ResolvedValue() >>
                        (m.right().ResolvedValue() & 31));
  }
  if (m.left().IsWord32Shl()) {
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.left().IsComparison()) {
      if (m.right().Is(31) && mleft.right().Is(31)) {
        // Comparison << 31 >> 31 => 0 - Comparison
        node->ReplaceInput(0, Int32Constant(0));
        node->ReplaceInput(1, mleft.left().node());
        NodeProperties::ChangeOp(node, machine()->Int32Sub());
        return Changed(node).FollowedBy(ReduceInt32Sub(node));
      }
    } else if (mleft.left().IsLoad()) {
      LoadRepresentation const rep =
          LoadRepresentationOf(mleft.left().node()->op());
      if (m.right().Is(24) && mleft.right().Is(24) &&
          rep == MachineType::Int8()) {
        // Load[kMachInt8] << 24 >> 24 => Load[kMachInt8]
        return Replace(mleft.left().node());
      }
      if (m.right().Is(16) && mleft.right().Is(16) &&
          rep == MachineType::Int16()) {
        // Load[kMachInt16] << 16 >> 16 => Load[kMachInt8]
        return Replace(mleft.left().node());
      }
    }
  }
  return ReduceWord32Shifts(node);
}

Reduction MachineOperatorReducer::ReduceWord64Sar(Node* node) {
  Int64BinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x >> 0 => x
  if (m.IsFoldable()) {
    return ReplaceInt64(m.left().ResolvedValue() >>
                        (m.right().ResolvedValue() & 63));
  }
  return NoChange();
}

template <typename WordNAdapter>
Reduction MachineOperatorReducer::ReduceWordNAnd(Node* node) {
  using A = WordNAdapter;
  A a(this);

  typename A::IntNBinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.right().node());  // x & 0  => 0
  if (m.right().Is(-1)) return Replace(m.left().node());  // x & -1 => x
  if (m.right().Is(1)) {
    // (x + x) & 1 => 0
    Node* left = m.left().node();
    while (left->opcode() == IrOpcode::kTruncateInt64ToInt32 ||
           left->opcode() == IrOpcode::kChangeInt32ToInt64 ||
           left->opcode() == IrOpcode::kChangeUint32ToUint64) {
      left = left->InputAt(0);
    }
    if ((left->opcode() == IrOpcode::kInt32Add ||
         left->opcode() == IrOpcode::kInt64Add) &&
        left->InputAt(0) == left->InputAt(1)) {
      return a.ReplaceIntN(0);
    }
  }
  if (m.left().IsComparison() && m.right().Is(1)) {  // CMP & 1 => CMP
    return Replace(m.left().node());
  }
  if (m.IsFoldable()) {  // K & K  => K  (K stands for arbitrary constants)
    return a.ReplaceIntN(m.left().ResolvedValue() & m.right().ResolvedValue());
  }
  if (m.LeftEqualsRight()) return Replace(m.left().node());  // x & x => x
  if (A::IsWordNAnd(m.left()) && m.right().HasResolvedValue()) {
    typename A::IntNBinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue()) {  // (x & K) & K => x & K
      node->ReplaceInput(0, mleft.left().node());
      node->ReplaceInput(1, a.IntNConstant(m.right().ResolvedValue() &
                                           mleft.right().ResolvedValue()));
      return Changed(node).FollowedBy(a.ReduceWordNAnd(node));
    }
  }
  if (m.right().IsNegativePowerOf2()) {
    typename A::intN_t const mask = m.right().ResolvedValue();
    typename A::intN_t const neg_mask = base::NegateWithWraparound(mask);
    if (A::IsWordNShl(m.left())) {
      typename A::UintNBinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue() &&
          (mleft.right().ResolvedValue() & (A::WORD_SIZE - 1)) >=
              base::bits::CountTrailingZeros(mask)) {
        // (x << L) & (-1 << K) => x << L iff L >= K
        return Replace(mleft.node());
      }
    } else if (A::IsIntNAdd(m.left())) {
      typename A::IntNBinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue() &&
          (mleft.right().ResolvedValue() & mask) ==
              mleft.right().ResolvedValue()) {
        // (x + (K << L)) & (-1 << L) => (x & (-1 << L)) + (K << L)
        node->ReplaceInput(0,
                           a.WordNAnd(mleft.left().node(), m.right().node()));
        node->ReplaceInput(1, mleft.right().node());
        NodeProperties::ChangeOp(node, a.IntNAdd(machine()));
        return Changed(node).FollowedBy(a.ReduceIntNAdd(node));
      }
      if (A::IsIntNMul(mleft.left())) {
        typename A::IntNBinopMatcher mleftleft(mleft.left().node());
        if (mleftleft.right().IsMultipleOf(neg_mask)) {
          // (y * (K << L) + x) & (-1 << L) => (x & (-1 << L)) + y * (K << L)
          node->ReplaceInput(
              0, a.WordNAnd(mleft.right().node(), m.right().node()));
          node->ReplaceInput(1, mleftleft.node());
          NodeProperties::ChangeOp(node, a.IntNAdd(machine()));
          return Changed(node).FollowedBy(a.ReduceIntNAdd(node));
        }
      }
      if (A::IsIntNMul(mleft.right())) {
        typename A::IntNBinopMatcher mleftright(mleft.right().node());
        if (mleftright.right().IsMultipleOf(neg_mask)) {
          // (x + y * (K << L)) & (-1 << L) => (x & (-1 << L)) + y * (K << L)
          node->ReplaceInput(0,
                             a.WordNAnd(mleft.left().node(), m.right().node()));
          node->ReplaceInput(1, mleftright.node());
          NodeProperties::ChangeOp(node, a.IntNAdd(machine()));
          return Changed(node).FollowedBy(a.ReduceIntNAdd(node));
        }
      }
      if (A::IsWordNShl(mleft.left())) {
        typename A::IntNBinopMatcher mleftleft(mleft.left().node());
        if (mleftleft.right().Is(base::bits::CountTrailingZeros(mask))) {
          // (y << L + x) & (-1 << L) => (x & (-1 << L)) + y << L
          node->ReplaceInput(
              0, a.WordNAnd(mleft.right().node(), m.right().node()));
          node->ReplaceInput(1, mleftleft.node());
          NodeProperties::ChangeOp(node, a.IntNAdd(machine()));
          return Changed(node).FollowedBy(a.ReduceIntNAdd(node));
        }
      }
      if (A::IsWordNShl(mleft.right())) {
        typename A::IntNBinopMatcher mleftright(mleft.right().node());
        if (mleftright.right().Is(base::bits::CountTrailingZeros(mask))) {
          // (x + y << L) & (-1 << L) => (x & (-1 << L)) + y << L
          node->ReplaceInput(0,
                             a.WordNAnd(mleft.left().node(), m.right().node()));
          node->ReplaceInput(1, mleftright.node());
          NodeProperties::ChangeOp(node, a.IntNAdd(machine()));
          return Changed(node).FollowedBy(a.ReduceIntNAdd(node));
        }
      }
    } else if (A::IsIntNMul(m.left())) {
      typename A::IntNBinopMatcher mleft(m.left().node());
      if (mleft.right().IsMultipleOf(neg_mask)) {
        // (x * (K << L)) & (-1 << L) => x * (K << L)
        return Replace(mleft.node());
      }
    }
  }
  return NoChange();
}

template <typename WordNAdapter>
Reduction MachineOperatorReducer::ReduceUintNLessThanOrEqual(Node* node) {
  using A = WordNAdapter;
  A a(this);

  typename A::UintNBinopMatcher m(node);
  typename A::uintN_t kMaxUIntN =
      std::numeric_limits<typename A::uintN_t>::max();
  if (m.left().Is(0)) return ReplaceBool(true);           // 0 <= x  =>  true
  if (m.right().Is(kMaxUIntN)) return ReplaceBool(true);  // x <= M  =>  true
  if (m.IsFoldable()) {  // K <= K  =>  K  (K stands for arbitrary constants)
    return ReplaceBool(m.left().ResolvedValue() <= m.right().ResolvedValue());
  }
  if (m.LeftEqualsRight()) return ReplaceBool(true);  // x <= x  =>  true
  if (m.right().Is(0)) {                              // x <= 0  =>  x == 0
    NodeProperties::ChangeOp(node, a.WordNEqual(machine()));
    return Changed(node);
  }
  return a.ReduceWordNComparisons(node);
}

namespace {

// Represents an operation of the form `(source & mask) == masked_value`.
// where each bit set in masked_value also has to be set in mask.
struct BitfieldCheck {
  Node* const source;
  uint32_t const mask;
  uint32_t const masked_value;
  bool const truncate_from_64_bit;

  BitfieldCheck(Node* source, uint32_t mask, uint32_t masked_value,
                bool truncate_from_64_bit)
      : source(source),
        mask(mask),
        masked_value(masked_value),
        truncate_from_64_bit(truncate_from_64_bit) {
    CHECK_EQ(masked_value & ~mask, 0);
  }

  static std::optional<BitfieldCheck> Detect(Node* node) {
    // There are two patterns to check for here:
    // 1. Single-bit checks: `(val >> shift) & 1`, where:
    //    - the shift may be omitted, and/or
    //    - the result may be truncated from 64 to 32
    // 2. Equality checks: `(val & mask) == expected`, where:
    //    - val may be truncated from 64 to 32 before masking (see
    //      ReduceWordEqualForConstantRhs)
    if (node->opcode() == IrOpcode::kWord32Equal) {
      Uint32BinopMatcher eq(node);
      if (eq.left().IsWord32And()) {
        Uint32BinopMatcher mand(eq.left().node());
        if (mand.right().HasResolvedValue() && eq.right().HasResolvedValue()) {
          uint32_t mask = mand.right().ResolvedValue();
          uint32_t masked_value = eq.right().ResolvedValue();
          if ((masked_value & ~mask) != 0) return {};
          if (mand.left().IsTruncateInt64ToInt32()) {
            return BitfieldCheck(
                NodeProperties::GetValueInput(mand.left().node(), 0), mask,
                masked_value, true);
          } else {
            return BitfieldCheck(mand.left().node(), mask, masked_value, false);
          }
        }
      }
    } else {
      if (node->opcode() == IrOpcode::kTruncateInt64ToInt32) {
        return TryDetectShiftAndMaskOneBit<Word64Adapter>(
            NodeProperties::GetValueInput(node, 0));
      } else {
        return TryDetectShiftAndMaskOneBit<Word32Adapter>(node);
      }
    }
    return {};
  }

  std::optional<BitfieldCheck> TryCombine(const BitfieldCheck& other) {
    if (source != other.source ||
        truncate_from_64_bit != other.truncate_from_64_bit) {
      return {};
    }
    uint32_t overlapping_bits = mask & other.mask;
    // It would be kind of strange to have any overlapping bits, but they can be
    // allowed as long as they don't require opposite values in the same
    // positions.
    if ((masked_value & overlapping_bits) !=
        (other.masked_value & overlapping_bits)) {
      return {};
    }
    return BitfieldCheck{source, mask | other.mask,
                         masked_value | other.masked_value,
                         truncate_from_64_bit};
  }

 private:
  template <typename WordNAdapter>
  static std::optional<BitfieldCheck> TryDetectShiftAndMaskOneBit(Node* node) {
    // Look for the pattern `(val >> shift) & 1`. The shift may be omitted.
    if (WordNAdapter::IsWordNAnd(NodeMatcher(node))) {
      typename WordNAdapter::IntNBinopMatcher mand(node);
      if (mand.right().HasResolvedValue() &&
          mand.right().ResolvedValue() == 1) {
        if (WordNAdapter::IsWordNShr(mand.left()) ||
            WordNAdapter::IsWordNSar(mand.left())) {
          typename WordNAdapter::UintNBinopMatcher shift(mand.left().node());
          if (shift.right().HasResolvedValue() &&
              shift.right().ResolvedValue() < 32u) {
            uint32_t mask = 1 << shift.right().ResolvedValue();
            return BitfieldCheck{shift.left().node(), mask, mask,
                                 WordNAdapter::WORD_SIZE == 64};
          }
        }
        return BitfieldCheck{mand.left().node(), 1, 1,
                             WordNAdapter::WORD_SIZE == 64};
      }
    }
    return {};
  }
};

}  // namespace

Reduction MachineOperatorReducer::ReduceWord32And(Node* node) {
  DCHECK_EQ(IrOpcode::kWord32And, node->opcode());
  Reduction reduction = ReduceWordNAnd<Word32Adapter>(node);
  if (reduction.Changed()) {
    return reduction;
  }

  // Attempt to detect multiple bitfield checks from the same bitfield struct
  // and fold them into a single check.
  Int32BinopMatcher m(node);
  if (auto right_bitfield = BitfieldCheck::Detect(m.right().node())) {
    if (auto left_bitfield = BitfieldCheck::Detect(m.left().node())) {
      if (auto combined_bitfield = left_bitfield->TryCombine(*right_bitfield)) {
        Node* source = combined_bitfield->source;
        if (combined_bitfield->truncate_from_64_bit) {
          source = TruncateInt64ToInt32(source);
        }
        node->ReplaceInput(0, Word32And(source, combined_bitfield->mask));
        node->ReplaceInput(1, Int32Constant(combined_bitfield->masked_value));
        NodeProperties::ChangeOp(node, machine()->Word32Equal());
        return Changed(node).FollowedBy(ReduceWord32Equal(node));
      }
    }
  }

  return NoChange();
}

Reduction MachineOperatorReducer::ReduceWord64And(Node* node) {
  DCHECK_EQ(IrOpcode::kWord64And, node->opcode());
  return ReduceWordNAnd<Word64Adapter>(node);
}

Reduction MachineOperatorReducer::TryMatchWord32Ror(Node* node) {
  // Recognize rotation, we are matching and transforming as follows:
  //   x << y         |  x >>> (32 - y)    =>  x ror (32 - y)
  //   x << (32 - y)  |  x >>> y           =>  x ror y
  //   x << y         ^  x >>> (32 - y)    =>  x ror (32 - y)   if y & 31 != 0
  //   x << (32 - y)  ^  x >>> y           =>  x ror y          if y & 31 != 0
  // (As well as the commuted forms.)
  // Note the side condition for XOR: the optimization doesn't hold for
  // multiples of 32.

  DCHECK(IrOpcode::kWord32Or == node->opcode() ||
         IrOpcode::kWord32Xor == node->opcode());
  Int32BinopMatcher m(node);
  Node* shl = nullptr;
  Node* shr = nullptr;
  if (m.left().IsWord32Shl() && m.right().IsWord32Shr()) {
    shl = m.left().node();
    shr = m.right().node();
  } else if (m.left().IsWord32Shr() && m.right().IsWord32Shl()) {
    shl = m.right().node();
    shr = m.left().node();
  } else {
    return NoChange();
  }

  Int32BinopMatcher mshl(shl);
  Int32BinopMatcher mshr(shr);
  if (mshl.left().node() != mshr.left().node()) return NoChange();

  if (mshl.right().HasResolvedValue() && mshr.right().HasResolvedValue()) {
    // Case where y is a constant.
    if (mshl.right().ResolvedValue() + mshr.right().ResolvedValue() != 32) {
      return NoChange();
    }
    if (node->opcode() == IrOpcode::kWord32Xor &&
        (mshl.right().ResolvedValue() & 31) == 0) {
      return NoChange();
    }
  } else {
    Node* sub = nullptr;
    Node* y = nullptr;
    if (mshl.right().IsInt32Sub()) {
      sub = mshl.right().node();
      y = mshr.right().node();
    } else if (mshr.right().IsInt32Sub()) {
      sub = mshr.right().node();
      y = mshl.right().node();
    } else {
      return NoChange();
    }

    Int32BinopMatcher msub(sub);
    if (!msub.left().Is(32) || msub.right().node() != y) return NoChange();
    if (node->opcode() == IrOpcode::kWord32Xor) {
      return NoChange();  // Can't guarantee y & 31 != 0.
    }
  }

  node->ReplaceInput(0, mshl.left().node());
  node->ReplaceInput(1, mshr.right().node());
  NodeProperties::ChangeOp(node, machine()->Word32Ror());
  return Changed(node);
}

template <typename WordNAdapter>
Reduction MachineOperatorReducer::ReduceWordNOr(Node* node) {
  using A = WordNAdapter;
  A a(this);

  typename A::IntNBinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());    // x | 0  => x
  if (m.right().Is(-1)) return Replace(m.right().node());  // x | -1 => -1
  if (m.IsFoldable()) {  // K | K  => K  (K stands for arbitrary constants)
    return a.ReplaceIntN(m.left().ResolvedValue() | m.right().ResolvedValue());
  }
  if (m.LeftEqualsRight()) return Replace(m.left().node());  // x | x => x

  // (x & K1) | K2 => x | K2 if K2 has ones for every zero bit in K1.
  // This case can be constructed by UpdateWord and UpdateWord32 in CSA.
  if (m.right().HasResolvedValue()) {
    if (A::IsWordNAnd(m.left())) {
      typename A::IntNBinopMatcher mand(m.left().node());
      if (mand.right().HasResolvedValue()) {
        if ((m.right().ResolvedValue() | mand.right().ResolvedValue()) == -1) {
          node->ReplaceInput(0, mand.left().node());
          return Changed(node);
        }
      }
    }
  }

  return a.TryMatchWordNRor(node);
}

Reduction MachineOperatorReducer::ReduceWord32Or(Node* node) {
  DCHECK_EQ(IrOpcode::kWord32Or, node->opcode());
  return ReduceWordNOr<Word32Adapter>(node);
}

Reduction MachineOperatorReducer::ReduceWord64Or(Node* node) {
  DCHECK_EQ(IrOpcode::kWord64Or, node->opcode());
  return ReduceWordNOr<Word64Adapter>(node);
}

template <typename WordNAdapter>
Reduction MachineOperatorReducer::ReduceWordNXor(Node* node) {
  using A = WordNAdapter;
  A a(this);

  typename A::IntNBinopMatcher m(node);
  if (m.right().Is(0)) return Replace(m.left().node());  // x ^ 0 => x
  if (m.IsFoldable()) {  // K ^ K => K  (K stands for arbitrary constants)
    return a.ReplaceIntN(m.left().ResolvedValue() ^ m.right().ResolvedValue());
  }
  if (m.LeftEqualsRight()) return Replace(a.IntNConstant(0));  // x ^ x => 0
  if (A::IsWordNXor(m.left()) && m.right().Is(-1)) {
    typename A::IntNBinopMatcher mleft(m.left().node());
    if (mleft.right().Is(-1)) {  // (x ^ -1) ^ -1 => x
      return Replace(mleft.left().node());
    }
  }

  return a.TryMatchWordNRor(node);
}

Reduction MachineOperatorReducer::ReduceWord32Xor(Node* node) {
  DCHECK_EQ(IrOpcode::kWord32Xor, node->opcode());
  Int32BinopMatcher m(node);
  if (m.right().IsWord32Equal() && m.left().Is(1)) {
    return Replace(Word32Equal(m.right().node(), Int32Constant(0)));
  }
  return ReduceWordNXor<Word32Adapter>(node);
}

Reduction MachineOperatorReducer::ReduceWord64Xor(Node* node) {
  DCHECK_EQ(IrOpcode::kWord64Xor, node->opcode());
  return ReduceWordNXor<Word64Adapter>(node);
}

Reduction MachineOperatorReducer::ReduceWord32Equal(Node* node) {
  Int32BinopMatcher m(node);
  if (m.IsFoldable()) {  // K == K => K  (K stands for arbitrary constants)
    return ReplaceBool(m.left().ResolvedValue() == m.right().ResolvedValue());
  }
  if (m.left().IsInt32Sub() && m.right().Is(0)) {  // x - y == 0 => x == y
    Int32BinopMatcher msub(m.left().node());
    node->ReplaceInput(0, msub.left().node());
    node->ReplaceInput(1, msub.right().node());
    return Changed(node);
  }
  // TODO(turbofan): fold HeapConstant, ExternalReference, pointer compares
  if (m.LeftEqualsRight()) return ReplaceBool(true);  // x == x => true
  if (m.right().HasResolvedValue()) {
    std::optional<std::pair<Node*, uint32_t>> replacements;
    if (m.left().IsTruncateInt64ToInt32()) {
      replacements = ReduceWordEqualForConstantRhs<Word64Adapter, uint32_t>(
          NodeProperties::GetValueInput(m.left().node(), 0),
          static_cast<uint32_t>(m.right().ResolvedValue()));
    } else {
      replacements = ReduceWordEqualForConstantRhs<Word32Adapter, uint32_t>(
          m.left().node(), static_cast<uint32_t>(m.right().ResolvedValue()));
    }
    if (replacements) {
      node->ReplaceInput(0, replacements->first);
      node->ReplaceInput(1, Uint32Constant(replacements->second));
      return Changed(node);
    }

    // Simplifying (x+k1)==k2 into x==k2-k1.
    if (m.left().IsInt32Add() && m.right().IsInt32Constant()) {
      Int32AddMatcher m_add(m.left().node());
      if (m_add.right().IsInt32Constant()) {
        int32_t lte_right = m.right().ResolvedValue();
        int32_t add_right = m_add.right().ResolvedValue();
        // No need to consider overflow in this condition (==).
        node->ReplaceInput(0, m_add.left().node());
        node->ReplaceInput(1, Int32Constant(static_cast<uint32_t>(lte_right) -
                                            static_cast<uint32_t>(add_right)));
        return Changed(node);
      }
    }
  }

  return NoChange();
}

Reduction MachineOperatorReducer::ReduceWord64Equal(Node* node) {
  Int64BinopMatcher m(node);
  if (m.IsFoldable()) {  // K == K => K  (K stands for arbitrary constants)
    return ReplaceBool(m.left().ResolvedValue() == m.right().ResolvedValue());
  }
  if (m.left().IsInt64Sub() && m.right().Is(0)) {  // x - y == 0 => x == y
    Int64BinopMatcher msub(m.left().node());
    node->ReplaceInput(0, msub.left().node());
    node->ReplaceInput(1, msub.right().node());
    return Changed(node);
  }
  // TODO(turbofan): fold HeapConstant, ExternalReference, pointer compares
  if (m.LeftEqualsRight()) return ReplaceBool(true);  // x == x => true
  if (m.right().HasResolvedValue()) {
    std::optional<std::pair<Node*, uint64_t>> replacements =
        ReduceWordEqualForConstantRhs<Word64Adapter, uint64_t>(
            m.left().node(), static_cast<uint64_t>(m.right().ResolvedValue()));
    if (replacements) {
      node->ReplaceInput(0, replacements->first);
      node->ReplaceInput(1, Uint64Constant(replacements->second));
      return Changed(node);
    }

    // Simplifying (x+k1)==k2 into x==k2-k1.
    if (m.left().IsInt64Add() && m.right().IsInt64Constant()) {
      Int64AddMatcher m_add(m.left().node());
      if (m_add.right().IsInt64Constant()) {
        int64_t lte_right = m.right().ResolvedValue();
        int64_t add_right = m_add.right().ResolvedValue();
        // No need to consider overflow in this condition (==).
        node->ReplaceInput(0, m_add.left().node());
        node->ReplaceInput(1, Int64Constant(static_cast<uint64_t>(lte_right) -
                                            static_cast<uint64_t>(add_right)));
        return Changed(node);
      }
    }

    /*
      If Int64Constant(c) can be casted from an Int32Constant:
      -------------------------------------------------
      Word64Equal(Int32ToInt64(a), Int64Constant(c))
      ====>
      Word32Equal(a,Int32Constant(c))
      -------------------------------------------------
    */
    if (m.left().IsChangeInt32ToInt64()) {
      int64_t right_value = m.right().ResolvedValue();
      // Int64Constant can be casted from an Int32Constant
      if (right_value == static_cast<int32_t>(right_value)) {
        NodeProperties::ChangeOp(node, machine()->Word32Equal());
        node->ReplaceInput(0, m.left().InputAt(0));
        node->ReplaceInput(1, Int32Constant(static_cast<int32_t>(right_value)));
        return Changed(node);
      } else {
        // Always false, change node op to zero(false).
        node->TrimInputCount(0);
        NodeProperties::ChangeOp(node, common()->Int32Constant(0));
        return Changed(node);
      }
    }
  }

  return NoChange();
}

Reduction MachineOperatorReducer::ReduceFloat64InsertLowWord32(Node* node) {
  DCHECK_EQ(IrOpcode::kFloat64InsertLowWord32, node->opcode());
  Float64Matcher mlhs(node->InputAt(0));
  Uint32Matcher mrhs(node->InputAt(1));
  if (mlhs.HasResolvedValue() && mrhs.HasResolvedValue()) {
    return ReplaceFloat64(
        base::bit_cast<double>((base::bit_cast<uint64_t>(mlhs.ResolvedValue()) &
                                uint64_t{0xFFFFFFFF00000000}) |
                               mrhs.ResolvedValue()));
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceFloat64InsertHighWord32(Node* node) {
  DCHECK_EQ(IrOpcode::kFloat64InsertHighWord32, node->opcode());
  Float64Matcher mlhs(node->InputAt(0));
  Uint32Matcher mrhs(node->InputAt(1));
  if (mlhs.HasResolvedValue() && mrhs.HasResolvedValue()) {
    return ReplaceFloat64(base::bit_cast<double>(
        (base::bit_cast<uint64_t>(mlhs.ResolvedValue()) &
         uint64_t{0xFFFFFFFF}) |
        (static_cast<uint64_t>(mrhs.ResolvedValue()) << 32)));
  }
  return NoChange();
}

namespace {

bool IsFloat64RepresentableAsFloat32(const Float64Matcher& m) {
  if (m.HasResolvedValue()) {
    double v = m.ResolvedValue();
    return DoubleToFloat32(v) == v;
  }
  return false;
}

}  // namespace

Reduction MachineOperatorReducer::ReduceFloat64Compare(Node* node) {
  DCHECK(IrOpcode::kFloat64Equal == node->opcode() ||
         IrOpcode::kFloat64LessThan == node->opcode() ||
         IrOpcode::kFloat64LessThanOrEqual == node->opcode());
  Float64BinopMatcher m(node);
  if (m.IsFoldable()) {
    switch (node->opcode()) {
      case IrOpcode::kFloat64Equal:
        return ReplaceBool(m.left().ResolvedValue() ==
                           m.right().ResolvedValue());
      case IrOpcode::kFloat64LessThan:
        return ReplaceBool(m.left().ResolvedValue() <
                           m.right().ResolvedValue());
      case IrOpcode::kFloat64LessThanOrEqual:
        return ReplaceBool(m.left().ResolvedValue() <=
                           m.right().ResolvedValue());
      default:
        UNREACHABLE();
    }
  } else if ((m.left().IsChangeFloat32ToFloat64() &&
              m.right().IsChangeFloat32ToFloat64()) ||
             (m.left().IsChangeFloat32ToFloat64() &&
              IsFloat64RepresentableAsFloat32(m.right())) ||
             (IsFloat64RepresentableAsFloat32(m.left()) &&
              m.right().IsChangeFloat32ToFloat64())) {
    // As all Float32 values have an exact representation in Float64, comparing
    // two Float64 values both converted from Float32 is equivalent to comparing
    // the original Float32s, so we can ignore the conversions. We can also
    // reduce comparisons of converted Float64 values against constants that
    // can be represented exactly as Float32.
    switch (node->opcode()) {
      case IrOpcode::kFloat64Equal:
        NodeProperties::ChangeOp(node, machine()->Float32Equal());
        break;
      case IrOpcode::kFloat64LessThan:
        NodeProperties::ChangeOp(node, machine()->Float32LessThan());
        break;
      case IrOpcode::kFloat64LessThanOrEqual:
        NodeProperties::ChangeOp(node, machine()->Float32LessThanOrEqual());
        break;
      default:
        UNREACHABLE();
    }
    node->ReplaceInput(
        0, m.left().HasResolvedValue()
               ? Float32Constant(static_cast<float>(m.left().ResolvedValue()))
               : m.left().InputAt(0));
    node->ReplaceInput(
        1, m.right().HasResolvedValue()
               ? Float32Constant(static_cast<float>(m.right().ResolvedValue()))
               : m.right().InputAt(0));
    return Changed(node);
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceFloat64RoundDown(Node* node) {
  DCHECK_EQ(IrOpcode::kFloat64RoundDown, node->opcode());
  Float64Matcher m(node->InputAt(0));
  if (m.HasResolvedValue()) {
    return ReplaceFloat64(std::floor(m.ResolvedValue()));
  }
  return NoChange();
}

namespace {

// Returns true if |node| is a constant whose value is 0.
bool IsZero(Node* node) {
  switch (node->opcode()) {
#define CASE_IS_ZERO(opcode, matcher) \
  case IrOpcode::opcode: {            \
    matcher m(node);                  \
    return m.Is(0);                   \
  }
    CASE_IS_ZERO(kInt32Constant, Int32Matcher)
    CASE_IS_ZERO(kInt64Constant, Int64Matcher)
#undef CASE_IS_ZERO
    default:
      break;
  }
  return false;
}

// If |node| is of the form "x == 0", then return "x" (in order to remove the
// "== 0" part).
std::optional<Node*> TryGetInvertedCondition(Node* cond) {
  if (cond->opcode() == IrOpcode::kWord32Equal) {
    Int32BinopMatcher m(cond);
    if (IsZero(m.right().node())) {
      return m.left().node();
    }
  }
  return std::nullopt;
}

struct SimplifiedCondition {
  Node* condition;
  bool is_inverted;
};

// Tries to simplifies |cond| by removing all top-level "== 0". Everytime such a
// construction is removed, the meaning of the comparison is inverted. This is
// recorded by the variable |is_inverted| throughout this function, and returned
// at the end. If |is_inverted| is true at the end, the caller should invert the
// if/else branches following the comparison.
std::optional<SimplifiedCondition> TrySimplifyCompareZero(Node* cond) {
  bool is_inverted = false;
  bool changed = false;
  std::optional<Node*> new_cond;
  while ((new_cond = TryGetInvertedCondition(cond)).has_value()) {
    cond = *new_cond;
    is_inverted = !is_inverted;
    changed = true;
  }
  if (changed) {
    return SimplifiedCondition{cond, is_inverted};
  } else {
    return {};
  }
}

/*
Remove WordEqual after WordAnd if it aims to test a bit.
For Example:
------------------------
691:  Int32Constant[8]
1857: Word32And(1838,691)
1858: Word32Equal(1857,691)
1859: Branch(1858,2141)
======>
691:  Int32Constant[8]
1857: Word32And(1838,691)
1859: Branch(1857,2141)
------------------------

Assembly code:
------------------------
andl r9,0x8
cmpb r9l,0x8
jz 0x7f242017bf3c
======>
testb r9,0x8
jnz 0x7f56c017be2e
------------------------
*/
Node* TrySimplifyCompareForTestBit(Node* cond) {
  if (cond->opcode() != IrOpcode::kWord32Equal) {
    return nullptr;
  }
  Node* word_equal_left = cond->InputAt(0);
  Node* word_equal_right = cond->InputAt(1);

  if (word_equal_left->opcode() != IrOpcode::kWord32And ||
      word_equal_right->opcode() != IrOpcode::kInt32Constant) {
    return nullptr;
  }

  Node* word_and_right = word_equal_left->InputAt(1);
  if (word_and_right->opcode() != IrOpcode::kInt32Constant) {
    return nullptr;
  }
  int32_t a = OpParameter<int32_t>(word_and_right->op());
  int32_t b = OpParameter<int32_t>(word_equal_right->op());
  if (a != b || !base::bits::IsPowerOfTwo(a)) {
    return nullptr;
  }
  DCHECK_EQ(word_equal_left->opcode(), IrOpcode::kWord32And);
  return word_equal_left;
}

}  // namespace

void MachineOperatorReducer::SwapBranches(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kBranch);
  for (Node* const use : node->uses()) {
    switch (use->opcode()) {
      case IrOpcode::kIfTrue:
        NodeProperties::ChangeOp(use, common()->IfFalse());
        break;
      case IrOpcode::kIfFalse:
        NodeProperties::ChangeOp(use, common()->IfTrue());
        break;
      default:
        UNREACHABLE();
    }
  }
  NodeProperties::ChangeOp(
      node, common()->Branch(NegateBranchHint(BranchHintOf(node->op()))));
}

// If |node| is a branch, removes all top-level 32-bit "== 0" from |node|.
Reduction MachineOperatorReducer::SimplifyBranch(Node* node) {
  Node* cond = node->InputAt(0);
  if (auto simplified = TrySimplifyCompareZero(cond)) {
    node->ReplaceInput(0, simplified->condition);
    if (simplified->is_inverted) {
      switch (node->opcode()) {
        case IrOpcode::kBranch:
          SwapBranches(node);
          break;
#if V8_ENABLE_WEBASSEMBLY
        case IrOpcode::kTrapIf: {
          const bool has_frame_state = node->op()->ValueInputCount() > 1;
          NodeProperties::ChangeOp(
              node,
              common()->TrapUnless(TrapIdOf(node->op()), has_frame_state));
          break;
        }
        case IrOpcode::kTrapUnless: {
          const bool has_frame_state = node->op()->ValueInputCount() > 1;
          NodeProperties::ChangeOp(
              node, common()->TrapIf(TrapIdOf(node->op()), has_frame_state));
          break;
        }
#endif  // V8_ENABLE_WEBASSEMBLY
        case IrOpcode::kDeoptimizeIf: {
          DeoptimizeParameters p = DeoptimizeParametersOf(node->op());
          NodeProperties::ChangeOp(
              node, common()->DeoptimizeUnless(p.reason(), p.feedback()));
          break;
        }
        case IrOpcode::kDeoptimizeUnless: {
          DeoptimizeParameters p = DeoptimizeParametersOf(node->op());
          NodeProperties::ChangeOp(
              node, common()->DeoptimizeIf(p.reason(), p.feedback()));
          break;
        }
        default:

          UNREACHABLE();
      }
    }
    return Changed(node);
  } else if (auto new_cond = TrySimplifyCompareForTestBit(cond)) {
    node->ReplaceInput(0, new_cond);
    return Changed(node);
  }
  return NoChange();
}

Reduction MachineOperatorReducer::ReduceConditional(Node* node) {
  DCHECK(node->opcode() == IrOpcode::kBranch ||
         node->opcode() == IrOpcode::kDeoptimizeIf ||
         node->opcode() == IrOpcode::kDeoptimizeUnless ||
         node->opcode() == IrOpcode::kTrapIf ||
         node->opcode() == IrOpcode::kTrapUnless);
  // This reducer only applies operator reductions to the branch condition.
  // Reductions involving control flow happen elsewhere. Non-zero inputs are
  // considered true in all conditional ops.
  NodeMatcher condition(NodeProperties::GetValueInput(node, 0));
  Reduction reduction = NoChange();
  if (condition.IsTruncateInt64ToInt32()) {
    if (auto replacement =
            ReduceConditionalN<Word64Adapter>(condition.node())) {
      NodeProperties::ReplaceValueInput(node, *replacement, 0);
      reduction = Changed(node);
    }
  } else if (auto replacement = ReduceConditionalN<Word32Adapter>(node)) {
    NodeProperties::ReplaceValueInput(node, *replacement, 0);
    reduction = Changed(node);
  }
  return reduction.FollowedBy(SimplifyBranch(node));
}

template <typename WordNAdapter>
std::optional<Node*> MachineOperatorReducer::ReduceConditionalN(Node* node) {
  NodeMatcher condition(NodeProperties::GetValueInput(node, 0));
  // Branch conditions are 32-bit comparisons against zero, so they are the
  // opposite of a 32-bit `x == 0` node. To avoid repetition, we can reuse logic
  // for Word32Equal: if `x == 0` can reduce to `y == 0`, then branch(x) can
  // reduce to branch(y).
  auto replacements = ReduceWordEqualForConstantRhs<WordNAdapter, uint32_t>(
      condition.node(), 0);
  if (replacements && replacements->second == 0) return replacements->first;
  return {};
}

template <typename WordNAdapter, typename uintN_t, typename intN_t>
std::optional<std::pair<Node*, uintN_t>>
MachineOperatorReducer::ReduceWordEqualForConstantRhs(Node* lhs, uintN_t rhs) {
  if (WordNAdapter::IsWordNAnd(NodeMatcher(lhs))) {
    typename WordNAdapter::UintNBinopMatcher mand(lhs);
    if ((WordNAdapter::IsWordNShr(mand.left()) ||
         WordNAdapter::IsWordNSar(mand.left())) &&
        mand.right().HasResolvedValue()) {
      typename WordNAdapter::UintNBinopMatcher mshift(mand.left().node());
      // ((x >> K1) & K2) == K3 => (x & (K2 << K1)) == (K3 << K1)
      if (mshift.right().HasResolvedValue()) {
        auto shift_bits = mshift.right().ResolvedValue();
        auto mask = mand.right().ResolvedValue();
        // Make sure that we won't shift data off the end, and that all of the
        // data ends up in the lower 32 bits for 64-bit mode.
        if (shift_bits <= base::bits::CountLeadingZeros(mask) &&
            shift_bits <= base::bits::CountLeadingZeros(rhs) &&
            (std::is_same_v<uintN_t, uint64_t> ||
             mask << shift_bits <= std::numeric_limits<uintN_t>::max())) {
          Node* new_input = mshift.left().node();
          uintN_t new_mask = static_cast<uintN_t>(mask << shift_bits);
          uintN_t new_rhs = rhs << shift_bits;
          if (std::is_same_v<uintN_t, uint32_t> &&
              WordNAdapter::WORD_SIZE == 64) {
            // We can truncate before performing the And.
            new_input = TruncateInt64ToInt32(new_input);
            return std::make_pair(Word32And(new_input, new_mask), new_rhs);
          } else {
            WordNAdapter a(this);
            return std::make_pair(
                a.WordNAnd(new_input, a.UintNConstant(new_mask)), new_rhs);
          }
        }
      }
    }
  }
  // Replaces (x >> n) == k with x == k << n, with "k << n" being computed
  // here at compile time.
  if (std::is_same_v<intN_t, typename WordNAdapter::intN_t> &&
      WordNAdapter::IsWordNSarShiftOutZeros(lhs->op()) &&
      lhs->UseCount() == 1) {
    typename WordNAdapter::UintNBinopMatcher mshift(lhs);
    if (mshift.right().HasResolvedValue()) {
      intN_t shift = static_cast<intN_t>(mshift.right().ResolvedValue());
      if (CanRevertLeftShiftWithRightShift<intN_t>(rhs, shift)) {
        return std::make_pair(mshift.left().node(), rhs << shift);
      }
    }
  }
  return {};
}

CommonOperatorBuilder* MachineOperatorReducer::common() const {
  return mcgraph()->common();
}

MachineOperatorBuilder* MachineOperatorReducer::machine() const {
  return mcgraph()->machine();
}

Graph* MachineOperatorReducer::graph() const { return mcgraph()->graph(); }

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```