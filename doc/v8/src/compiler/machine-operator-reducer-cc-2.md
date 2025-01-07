Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/machine-operator-reducer.cc`. The request has several constraints:

1. **List the functions:** Identify the actions the code performs.
2. **Torque Check:** Determine if the file could be a Torque file based on its extension.
3. **JavaScript Relation:** If the code relates to JavaScript, provide a JavaScript example.
4. **Logic Inference:**  Present an example of the code's logic with hypothetical input and output.
5. **Common Errors:**  Highlight potential programming errors the code might address or prevent.
6. **Part of a Series:**  Acknowledge this is part 3 of 4 and summarize the overall function.

**Mental Walkthrough:**

1. **Functionality Analysis:**  The code seems to be optimizing machine-level operations within the V8 compiler. It focuses on specific instruction patterns (shifts, comparisons, bitwise operations) and attempts to simplify them. Keywords like `Reduce`, `ReplaceInput`, `ChangeOp`, and matcher classes (`Int32BinopMatcher`, `Int64BinopMatcher`, etc.) are strong indicators of this. I'll go through each `Reduce` function and summarize its specific optimization.

2. **Torque Check:** The instruction explicitly states to check if the file ends with `.tq`. Since it doesn't, it's not a Torque file.

3. **JavaScript Relation:**  These low-level optimizations directly impact the performance of JavaScript code. When JavaScript performs bitwise operations, comparisons, or arithmetic, the compiler (with components like this reducer) attempts to translate them into efficient machine code. I can create JavaScript examples that would trigger these underlying machine operations.

4. **Logic Inference:** For each optimization, I can create a simplified example. For instance, for the left shift followed by a right shift simplification, I can show a concrete numerical example.

5. **Common Errors:**  Some of the optimizations seem to address potential inefficiencies or redundant operations. For example, unnecessary masking in shift operations or comparing constants directly. I can frame these as potential user errors.

6. **Overall Function (Part 3):**  Based on the analysis, this section appears to be dealing with the reduction and optimization of integer and bitwise operations, specifically focusing on 64-bit and 32-bit integers, shifts, comparisons, and logical AND/OR/XOR. The earlier parts likely handle other types of operations, and the final part will probably wrap up the overall reducer functionality.

**Pre-computation/Pre-analysis (Specific Examples):**

* **Shift Optimization:**  JavaScript `x << 5 >> 5` can be optimized to `x` if it's a signed right shift and only zeros are shifted out.
* **64-bit to 32-bit Comparison:**  JavaScript comparing small integers stored as 64-bit values can be optimized to 32-bit comparisons.
* **Bitwise AND Optimization:** JavaScript `x & 0` can be optimized to `0`.

**Confidence Score:** 5/5 - I'm confident I can address all aspects of the prompt.

Strategizing complete. I will now generate the response based on the outlined steps and examples.好的，根据你提供的代码片段，以下是 `v8/src/compiler/machine-operator-reducer.cc` 第3部分的功能归纳：

**功能概述**

这段代码主要负责对V8编译器中间表示（IR）中的**机器操作符**进行**简化和优化**，目的是生成更高效的机器代码。 它专注于**32位和64位整数的位运算和比较操作**，通过识别特定的模式并将其替换为更简单的等效操作或常量值来实现优化。

**具体功能列举**

* **简化位移操作:**
    * 移除不必要的位与运算 (`& 0x1F`)，如果机器指令提供的位移行为与JavaScript要求的一致。
    * 优化左移 (`<<`) 操作，例如 `x << 0` 替换为 `x`，常量左移直接计算结果。
    * 针对特定模式的左移后跟右移操作进行优化，例如 `(x >> K) << L` 的各种情况。
    * 优化无符号右移 (`>>>`) 操作，例如 `x >>> 0` 替换为 `x`，常量右移直接计算结果。
    * 优化有符号右移 (`>>`) 操作，例如 `x >> 0` 替换为 `x`，常量右移直接计算结果。
    * 特殊情况下优化有符号右移，例如 `Comparison << 31 >> 31` 简化为 `0 - Comparison`。
    * 针对加载操作后的位移进行优化，例如 `Load[kMachInt8] << 24 >> 24` 简化为 `Load[kMachInt8]`。
* **优化64位比较操作:**
    * 将涉及符号扩展或零扩展的64位比较操作转换为相应的32位比较操作，提高效率。
    * 识别并优化特定模式的64位比较，例如 `(x >> K) < (y >> K)` 简化为 `x < y`。
    * 将常量与位移比较进行简化，例如 `(x >> n) <= k` 简化为 `x <= (k << n)`。
    * 针对与 `Int32ToInt64` 和常量比较的情况进行优化，如果常量可以安全转换为32位整数，则将64位比较降级为32位比较。
    * 针对与 `Uint32ToUint64` 和常量比较的情况进行优化，如果常量可以安全转换为32位无符号整数，则将64位比较降级为32位比较。
* **优化位与 (`&`) 操作:**
    * 识别并替换位与零 (`x & 0`) 为零。
    * 识别并替换位与全一 (`x & -1`) 为 `x`。
    * 识别并优化特定模式的位与操作，例如 `(x + x) & 1` 简化为 `0`。
    * 识别并替换 `CMP & 1` 为 `CMP`。
    * 常量位与操作直接计算结果。
    * 识别并优化重复的位与操作，例如 `(x & K) & K` 简化为 `x & K`。
    * 针对位与负二次幂的情况进行特定优化，例如 `(x << L) & (-1 << K)`。
* **优化位或 (`|`) 操作:**
    * 识别并替换位或零 (`x | 0`) 为 `x`。
    * 识别并替换位或全一 (`x | -1`) 为 `-1`。
    * 常量位或操作直接计算结果。
    * 识别并替换 `x | x` 为 `x`。
    * 优化特定模式的位或操作，例如 `(x & K1) | K2`。
    * 尝试匹配并优化为**循环移位 (ROR)** 操作。
* **优化无符号小于等于 (`<=`) 比较操作:**
    * 优化与零和最大值的比较。
    * 常量比较直接计算结果。
    * 识别并替换 `x <= x` 为 `true`。
    * 识别并替换 `x <= 0` 为 `x == 0`。
* **检测和组合位域检查:**
    * 识别形如 `(source & mask) == masked_value` 的位域检查模式。
    * 尝试将多个针对同一源的位域检查合并为一个更复杂的检查。
* **循环右移 (ROR) 匹配:**
    * 尝试将特定的左移和右移组合模式（通过位或或位异或连接）识别为循环右移操作。

**如果 `v8/src/compiler/machine-operator-reducer.cc` 以 `.tq` 结尾**

如果该文件以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。Torque 是一种用于编写 V8 内部代码的领域特定语言，它比 C++ 更高级，更安全，并且更易于维护。

**与 JavaScript 的关系 (及 JavaScript 示例)**

这段 C++ 代码直接影响 JavaScript 代码的性能。当 JavaScript 代码执行涉及位运算和比较操作时，V8 的编译器会将其转换为一系列的机器操作。`machine-operator-reducer.cc` 中的代码正是用于优化这些底层的机器操作，从而提升 JavaScript 代码的执行效率。

**JavaScript 示例:**

```javascript
// 对应于位移优化，例如 (x >> K) << L
function testShiftOptimization(x) {
  return (x >> 2) << 1; // 相当于 C++ 中的 (x >>> 2) << 1 或 (x >> 2) << 1
}

// 对应于64位比较优化
function test64BitComparison(a, b) {
  return a < b; // 如果 a 和 b 是较小的整数，可能会被表示为 64 位
}

// 对应于位与优化
function testBitwiseAnd(x) {
  return x & 0xF;
}

// 对应于位或优化和循环右移匹配
function testBitwiseOrRotate(x, y) {
  return (x << y) | (x >>> (32 - y));
}

// 对应于位域检查
function testBitfieldCheck(flags) {
  return (flags & 0b00000100) === 0b00000100; // 检查特定位是否被设置
}
```

**代码逻辑推理 (假设输入与输出)**

**假设输入 (针对 64 位比较优化):**

一个 IR 节点表示 `Int64LessThan(ChangeInt32ToInt64(a), Int64Constant(10))`，其中 `a` 是一个 `Int32` 类型的节点。

**输出:**

该节点会被替换为 `Int32LessThan(a, Int32Constant(10))`，操作符从 `Int64LessThan` 变为 `Int32LessThan`，输入也相应调整。

**假设输入 (针对左移优化):**

一个 IR 节点表示 `Word32Shl(x, Int32Constant(0))`。

**输出:**

该节点会被直接替换为 `x` 节点。

**涉及用户常见的编程错误 (及示例)**

* **不必要的类型转换和扩展:** 用户可能在 JavaScript 中进行操作时，由于类型系统的原因，导致数值被提升为 64 位，即使它们可以安全地表示为 32 位。优化器可以消除这种不必要的开销。
    ```javascript
    // 这里的 a 和 b 可能是小于 2^31 的整数，但由于某些操作可能被表示为 64 位
    let a = 5;
    let b = 10;
    if (a < b) {
      // ...
    }
    ```
* **低效的位运算组合:** 用户可能无意中使用了可以通过位运算的恒等式或优化规则简化的表达式。
    ```javascript
    let x = 5;
    let y = 3;
    let result = (x << y) | (x >>> (32 - y)); // 本意是循环右移，但可能直接写成这样
    ```
* **冗余的掩码操作:** 用户可能在位移后进行了不必要的掩码操作，而机器指令本身已经处理了。
    ```javascript
    let value = 10;
    let shifted = value << 2;
    let masked = shifted & 0xFFFFFFFF; // 对于 32 位整数来说，这个掩码通常是冗余的
    ```

**第3部分功能归纳**

这部分 `machine-operator-reducer.cc` 代码专注于**优化 V8 编译器中针对 32 位和 64 位整数的位运算（移位、与、或、异或）和比较操作**。它通过模式匹配和代数简化，将复杂的或冗余的机器操作替换为更简单、更高效的等价形式，从而提升生成的机器代码的执行效率。 尤其关注将 64 位操作尽可能降级为 32 位操作，以及识别和优化特定的位运算组合模式，包括循环移位和位域检查。

Prompt: 
```
这是目录为v8/src/compiler/machine-operator-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/machine-operator-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

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
  DCH
"""


```