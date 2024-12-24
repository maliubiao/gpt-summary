Response: The user wants a summary of the C++ code in `v8/src/compiler/machine-operator-reducer.cc`. This file seems to be part of the Turbofan compiler in V8, specifically for optimizing machine-level operations.

**Plan:**

1. Identify the main goal of the `MachineOperatorReducer`.
2. Point out the types of optimizations it performs (constant folding, strength reduction).
3. Mention the handling of different data types (integers, floats, words).
4. Note the use of adapters for Word32 and Word64 operations.
5. If possible, relate some of the optimizations to JavaScript code behavior.这个C++源代码文件 `v8/src/compiler/machine-operator-reducer.cc` 的功能是 **对 V8 虚拟机中机器操作进行优化**。它属于 Turbofan 编译器的一部分，负责在代码生成的后期阶段，对已经转换成机器指令的操作进行精简和优化，以提高执行效率。

主要的功能可以归纳为以下几点：

1. **常量折叠 (Constant Folding):**  如果一个操作的所有输入都是常量，那么在编译时就计算出结果，并用该常量结果替换整个操作。例如，`3 + 5` 在编译时会被替换为 `8`。
2. **强度削减 (Strength Reduction):** 将一些开销较大的操作替换为等价的、开销较小的操作。例如，将乘以 2 的幂运算替换为左移操作，或者将除以 2 的幂运算替换为右移操作。
3. **代数简化:**  应用代数规则来简化表达式。例如，`x + 0` 被简化为 `x`， `x * 1` 被简化为 `x`。
4. **位运算优化:** 针对位运算（AND, OR, XOR, SHIFT 等）进行特定的优化。
5. **浮点数优化:** 对浮点数运算进行常量折叠以及一些特定的优化，例如处理 NaN 值。
6. **条件分支优化:** 简化基于常量比较的条件分支。
7. **处理溢出:** 针对带溢出的算术运算进行优化。
8. **类型转换优化:** 简化一些不必要的类型转换。

这个文件定义了一个 `MachineOperatorReducer` 类，它继承自 `AdvancedReducer`。它遍历程序的图结构（Graph），并尝试对每个机器操作节点应用上述的优化策略。

**它与 JavaScript 的功能有关系，因为它直接影响 JavaScript 代码的执行效率。**  Turbofan 编译器将 JavaScript 代码编译成高效的机器码，而 `MachineOperatorReducer` 的优化步骤能让最终生成的机器码更加精简快速。

**JavaScript 例子:**

考虑以下 JavaScript 代码片段：

```javascript
function add(x) {
  return x + 0;
}

function multiplyByEight(y) {
  return y * 8;
}

function compareWithZero(z) {
  return z < 0;
}
```

当 Turbofan 编译 `add(x)` 函数时，`MachineOperatorReducer` 会识别出 `x + 0` 中的 `+ 0` 是多余的，可以直接返回 `x`，从而避免实际的加法运算。

对于 `multiplyByEight(y)`， `MachineOperatorReducer` 会将乘以 8 替换为等价的左移 3 位操作 (`y << 3`)，因为位运算通常比乘法运算更快。

对于 `compareWithZero(z)`， `MachineOperatorReducer` 可能会对涉及位运算的比较进行优化（虽然在这个例子中没有直接体现，但在更复杂的位运算场景下会发生）。

**更具体的 JavaScript 和对应的优化例子 (基于代码片段)：**

假设在 JavaScript 中有如下代码：

```javascript
function bitwiseAnd(a) {
  return a & 0xFF;
}

function shiftRight(b) {
  return b >> 8;
}
```

在 `bitwiseAnd(a)` 中，如果后续的操作是将结果存储到一个字节大小的内存位置，`MachineOperatorReducer` 可能会识别出 `& 0xFF` 操作是多余的，因为存储操作本身会截断高位。 这在 `ReduceStore` 函数中有所体现。

在 `shiftRight(b)` 中，如果比较操作是基于移位后的值，例如 `(b >> K) < C`，`MachineOperatorReducer` 会尝试将其转换为更直接的比较 `b < (C << K)`，前提是移位没有丢失重要的信息，这在 `ReduceWord32Comparisons` 函数中有所体现。

总而言之，`v8/src/compiler/machine-operator-reducer.cc`  是 V8 优化 JavaScript 代码执行效率的关键组件之一，它通过对底层的机器操作进行智能的分析和转换，显著提升了 JavaScript 程序的性能。
Prompt: 
```
这是目录为v8/src/compiler/machine-operator-reducer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/machine-operator-reducer.h"

#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/base/ieee754.h"
#include "src/base/logging.h"
#include "src/base/overflowing-math.h"
#include "src/builtins/builtins.h"
#include "src/compiler/diamond.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/machine-graph.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/turbofan-graph.h"
#include "src/numbers/conversions-inl.h"
#include "src/numbers/ieee754.h"

namespace v8 {
namespace internal {
namespace compiler {

// Some optimizations performed by the MachineOperatorReducer can be applied
// to both Word32 and Word64 operations. Those are implemented in a generic
// way to be reused for different word sizes.
// This class adapts a generic algorithm to Word32 operations.
class Word32Adapter {
 public:
  using IntNBinopMatcher = Int32BinopMatcher;
  using UintNBinopMatcher = Uint32BinopMatcher;
  using intN_t = int32_t;
  using uintN_t = uint32_t;
  // WORD_SIZE refers to the N for which this adapter specializes.
  static constexpr std::size_t WORD_SIZE = 32;

  explicit Word32Adapter(MachineOperatorReducer* reducer) : r_(reducer) {}

  template <typename T>
  static bool IsWordNAnd(const T& x) {
    return x.IsWord32And();
  }
  template <typename T>
  static bool IsWordNShl(const T& x) {
    return x.IsWord32Shl();
  }
  template <typename T>
  static bool IsWordNShr(const T& x) {
    return x.IsWord32Shr();
  }
  template <typename T>
  static bool IsWordNSar(const T& x) {
    return x.IsWord32Sar();
  }
  static bool IsWordNSarShiftOutZeros(const Operator* op) {
    return op->opcode() == IrOpcode::kWord32Sar &&
           OpParameter<ShiftKind>(op) == ShiftKind::kShiftOutZeros;
  }
  template <typename T>
  static bool IsWordNXor(const T& x) {
    return x.IsWord32Xor();
  }
  template <typename T>
  static bool IsIntNAdd(const T& x) {
    return x.IsInt32Add();
  }
  template <typename T>
  static bool IsIntNMul(const T& x) {
    return x.IsInt32Mul();
  }

  const Operator* IntNAdd(MachineOperatorBuilder* machine) {
    return machine->Int32Add();
  }
  static const Operator* WordNEqual(MachineOperatorBuilder* machine) {
    return machine->Word32Equal();
  }

  Reduction ReplaceIntN(int32_t value) { return r_->ReplaceInt32(value); }
  Reduction ReduceWordNAnd(Node* node) { return r_->ReduceWord32And(node); }
  Reduction ReduceIntNAdd(Node* node) { return r_->ReduceInt32Add(node); }
  Reduction TryMatchWordNRor(Node* node) { return r_->TryMatchWord32Ror(node); }

  Node* IntNConstant(int32_t value) { return r_->Int32Constant(value); }
  Node* UintNConstant(uint32_t value) { return r_->Uint32Constant(value); }
  Node* WordNAnd(Node* lhs, Node* rhs) { return r_->Word32And(lhs, rhs); }

  Reduction ReduceWordNComparisons(Node* node) {
    return r_->ReduceWord32Comparisons(node);
  }

 private:
  MachineOperatorReducer* r_;
};

// Some optimizations performed by the MachineOperatorReducer can be applied
// to both Word32 and Word64 operations. Those are implemented in a generic
// way to be reused for different word sizes.
// This class adapts a generic algorithm to Word64 operations.
class Word64Adapter {
 public:
  using IntNBinopMatcher = Int64BinopMatcher;
  using UintNBinopMatcher = Uint64BinopMatcher;
  using intN_t = int64_t;
  using uintN_t = uint64_t;
  // WORD_SIZE refers to the N for which this adapter specializes.
  static constexpr std::size_t WORD_SIZE = 64;

  explicit Word64Adapter(MachineOperatorReducer* reducer) : r_(reducer) {}

  template <typename T>
  static bool IsWordNAnd(const T& x) {
    return x.IsWord64And();
  }
  template <typename T>
  static bool IsWordNShl(const T& x) {
    return x.IsWord64Shl();
  }
  template <typename T>
  static bool IsWordNShr(const T& x) {
    return x.IsWord64Shr();
  }
  template <typename T>
  static bool IsWordNSar(const T& x) {
    return x.IsWord64Sar();
  }
  static bool IsWordNSarShiftOutZeros(const Operator* op) {
    return op->opcode() == IrOpcode::kWord64Sar &&
           OpParameter<ShiftKind>(op) == ShiftKind::kShiftOutZeros;
  }
  template <typename T>
  static bool IsWordNXor(const T& x) {
    return x.IsWord64Xor();
  }
  template <typename T>
  static bool IsIntNAdd(const T& x) {
    return x.IsInt64Add();
  }
  template <typename T>
  static bool IsIntNMul(const T& x) {
    return x.IsInt64Mul();
  }

  static const Operator* IntNAdd(MachineOperatorBuilder* machine) {
    return machine->Int64Add();
  }
  static const Operator* WordNEqual(MachineOperatorBuilder* machine) {
    return machine->Word64Equal();
  }

  Reduction ReplaceIntN(int64_t value) { return r_->ReplaceInt64(value); }
  Reduction ReduceWordNAnd(Node* node) { return r_->ReduceWord64And(node); }
  Reduction ReduceIntNAdd(Node* node) { return r_->ReduceInt64Add(node); }
  Reduction TryMatchWordNRor(Node* node) {
    // TODO(nicohartmann@): Add a MachineOperatorReducer::TryMatchWord64Ror.
    return r_->NoChange();
  }

  Node* IntNConstant(int64_t value) { return r_->Int64Constant(value); }
  Node* UintNConstant(uint64_t value) { return r_->Uint64Constant(value); }
  Node* WordNAnd(Node* lhs, Node* rhs) { return r_->Word64And(lhs, rhs); }

  Reduction ReduceWordNComparisons(Node* node) {
    return r_->ReduceWord64Comparisons(node);
  }

 private:
  MachineOperatorReducer* r_;
};

namespace {

// TODO(jgruber): Consider replacing all uses of this function by
// std::numeric_limits<T>::quiet_NaN().
template <class T>
T SilenceNaN(T x) {
  DCHECK(std::isnan(x));
  // Do some calculation to make a signalling NaN quiet.
  return x - x;
}

}  // namespace

MachineOperatorReducer::MachineOperatorReducer(
    Editor* editor, MachineGraph* mcgraph,
    SignallingNanPropagation signalling_nan_propagation)
    : AdvancedReducer(editor),
      mcgraph_(mcgraph),
      signalling_nan_propagation_(signalling_nan_propagation) {}

MachineOperatorReducer::~MachineOperatorReducer() = default;

Node* MachineOperatorReducer::Float32Constant(float value) {
  return graph()->NewNode(common()->Float32Constant(value));
}

Node* MachineOperatorReducer::Float64Constant(double value) {
  return mcgraph()->Float64Constant(value);
}

Node* MachineOperatorReducer::Int32Constant(int32_t value) {
  return mcgraph()->Int32Constant(value);
}

Node* MachineOperatorReducer::Int64Constant(int64_t value) {
  return graph()->NewNode(common()->Int64Constant(value));
}

Node* MachineOperatorReducer::Float64Mul(Node* lhs, Node* rhs) {
  return graph()->NewNode(machine()->Float64Mul(), lhs, rhs);
}

Node* MachineOperatorReducer::Float64PowHalf(Node* value) {
  value =
      graph()->NewNode(machine()->Float64Add(), Float64Constant(0.0), value);
  Diamond d(graph(), common(),
            graph()->NewNode(machine()->Float64LessThanOrEqual(), value,
                             Float64Constant(-V8_INFINITY)),
            BranchHint::kFalse);
  return d.Phi(MachineRepresentation::kFloat64, Float64Constant(V8_INFINITY),
               graph()->NewNode(machine()->Float64Sqrt(), value));
}

Node* MachineOperatorReducer::Word32And(Node* lhs, Node* rhs) {
  Node* const node = graph()->NewNode(machine()->Word32And(), lhs, rhs);
  Reduction const reduction = ReduceWord32And(node);
  return reduction.Changed() ? reduction.replacement() : node;
}

Node* MachineOperatorReducer::Word32Sar(Node* lhs, uint32_t rhs) {
  if (rhs == 0) return lhs;
  return graph()->NewNode(machine()->Word32Sar(), lhs, Uint32Constant(rhs));
}

Node* MachineOperatorReducer::Word64Sar(Node* lhs, uint32_t rhs) {
  if (rhs == 0) return lhs;
  return graph()->NewNode(machine()->Word64Sar(), lhs, Uint64Constant(rhs));
}

Node* MachineOperatorReducer::Word32Shr(Node* lhs, uint32_t rhs) {
  if (rhs == 0) return lhs;
  return graph()->NewNode(machine()->Word32Shr(), lhs, Uint32Constant(rhs));
}

Node* MachineOperatorReducer::Word64Shr(Node* lhs, uint32_t rhs) {
  if (rhs == 0) return lhs;
  return graph()->NewNode(machine()->Word64Shr(), lhs, Uint64Constant(rhs));
}

Node* MachineOperatorReducer::Word32Equal(Node* lhs, Node* rhs) {
  return graph()->NewNode(machine()->Word32Equal(), lhs, rhs);
}

Node* MachineOperatorReducer::Word64Equal(Node* lhs, Node* rhs) {
  return graph()->NewNode(machine()->Word64Equal(), lhs, rhs);
}

Node* MachineOperatorReducer::Word64And(Node* lhs, Node* rhs) {
  Node* const node = graph()->NewNode(machine()->Word64And(), lhs, rhs);
  Reduction const reduction = ReduceWord64And(node);
  return reduction.Changed() ? reduction.replacement() : node;
}

Node* MachineOperatorReducer::Int32Add(Node* lhs, Node* rhs) {
  Node* const node = graph()->NewNode(machine()->Int32Add(), lhs, rhs);
  Reduction const reduction = ReduceInt32Add(node);
  return reduction.Changed() ? reduction.replacement() : node;
}

Node* MachineOperatorReducer::Int64Add(Node* lhs, Node* rhs) {
  Node* const node = graph()->NewNode(machine()->Int64Add(), lhs, rhs);
  Reduction const reduction = ReduceInt64Add(node);
  return reduction.Changed() ? reduction.replacement() : node;
}

Node* MachineOperatorReducer::Int32Sub(Node* lhs, Node* rhs) {
  Node* const node = graph()->NewNode(machine()->Int32Sub(), lhs, rhs);
  Reduction const reduction = ReduceInt32Sub(node);
  return reduction.Changed() ? reduction.replacement() : node;
}

Node* MachineOperatorReducer::Int64Sub(Node* lhs, Node* rhs) {
  Node* const node = graph()->NewNode(machine()->Int64Sub(), lhs, rhs);
  Reduction const reduction = ReduceInt64Sub(node);
  return reduction.Changed() ? reduction.replacement() : node;
}

Node* MachineOperatorReducer::Int32Mul(Node* lhs, Node* rhs) {
  return graph()->NewNode(machine()->Int32Mul(), lhs, rhs);
}

Node* MachineOperatorReducer::Int64Mul(Node* lhs, Node* rhs) {
  return graph()->NewNode(machine()->Int64Mul(), lhs, rhs);
}

Node* MachineOperatorReducer::Int32Div(Node* dividend, int32_t divisor) {
  DCHECK_NE(0, divisor);
  DCHECK_NE(std::numeric_limits<int32_t>::min(), divisor);
  base::MagicNumbersForDivision<uint32_t> const mag =
      base::SignedDivisionByConstant(base::bit_cast<uint32_t>(divisor));
  Node* quotient = graph()->NewNode(machine()->Int32MulHigh(), dividend,
                                    Uint32Constant(mag.multiplier));
  if (divisor > 0 && base::bit_cast<int32_t>(mag.multiplier) < 0) {
    quotient = Int32Add(quotient, dividend);
  } else if (divisor < 0 && base::bit_cast<int32_t>(mag.multiplier) > 0) {
    quotient = Int32Sub(quotient, dividend);
  }
  return Int32Add(Word32Sar(quotient, mag.shift), Word32Shr(dividend, 31));
}

Node* MachineOperatorReducer::Int64Div(Node* dividend, int64_t divisor) {
  DCHECK_NE(0, divisor);
  DCHECK_NE(std::numeric_limits<int64_t>::min(), divisor);
  base::MagicNumbersForDivision<uint64_t> const mag =
      base::SignedDivisionByConstant(base::bit_cast<uint64_t>(divisor));
  Node* quotient = graph()->NewNode(machine()->Int64MulHigh(), dividend,
                                    Uint64Constant(mag.multiplier));
  if (divisor > 0 && base::bit_cast<int64_t>(mag.multiplier) < 0) {
    quotient = Int64Add(quotient, dividend);
  } else if (divisor < 0 && base::bit_cast<int64_t>(mag.multiplier) > 0) {
    quotient = Int64Sub(quotient, dividend);
  }
  return Int64Add(Word64Sar(quotient, mag.shift), Word64Shr(dividend, 63));
}

Node* MachineOperatorReducer::Uint32Div(Node* dividend, uint32_t divisor) {
  DCHECK_LT(0u, divisor);
  // If the divisor is even, we can avoid using the expensive fixup by shifting
  // the dividend upfront.
  unsigned const shift = base::bits::CountTrailingZeros(divisor);
  dividend = Word32Shr(dividend, shift);
  divisor >>= shift;
  // Compute the magic number for the (shifted) divisor.
  base::MagicNumbersForDivision<uint32_t> const mag =
      base::UnsignedDivisionByConstant(divisor, shift);
  Node* quotient = graph()->NewNode(machine()->Uint32MulHigh(), dividend,
                                    Uint32Constant(mag.multiplier));
  if (mag.add) {
    DCHECK_LE(1u, mag.shift);
    quotient = Word32Shr(
        Int32Add(Word32Shr(Int32Sub(dividend, quotient), 1), quotient),
        mag.shift - 1);
  } else {
    quotient = Word32Shr(quotient, mag.shift);
  }
  return quotient;
}

Node* MachineOperatorReducer::Uint64Div(Node* dividend, uint64_t divisor) {
  DCHECK_LT(0u, divisor);
  // If the divisor is even, we can avoid using the expensive fixup by shifting
  // the dividend upfront.
  unsigned const shift = base::bits::CountTrailingZeros(divisor);
  dividend = Word64Shr(dividend, shift);
  divisor >>= shift;
  // Compute the magic number for the (shifted) divisor.
  base::MagicNumbersForDivision<uint64_t> const mag =
      base::UnsignedDivisionByConstant(divisor, shift);
  Node* quotient = graph()->NewNode(machine()->Uint64MulHigh(), dividend,
                                    Uint64Constant(mag.multiplier));
  if (mag.add) {
    DCHECK_LE(1u, mag.shift);
    quotient = Word64Shr(
        Int64Add(Word64Shr(Int64Sub(dividend, quotient), 1), quotient),
        mag.shift - 1);
  } else {
    quotient = Word64Shr(quotient, mag.shift);
  }
  return quotient;
}

Node* MachineOperatorReducer::TruncateInt64ToInt32(Node* value) {
  Node* const node = graph()->NewNode(machine()->TruncateInt64ToInt32(), value);
  Reduction const reduction = ReduceTruncateInt64ToInt32(node);
  return reduction.Changed() ? reduction.replacement() : node;
}

Node* MachineOperatorReducer::ChangeInt32ToInt64(Node* value) {
  return graph()->NewNode(machine()->ChangeInt32ToInt64(), value);
}

// Perform constant folding and strength reduction on machine operators.
Reduction MachineOperatorReducer::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kProjection:
      return ReduceProjection(ProjectionIndexOf(node->op()), node->InputAt(0));
    case IrOpcode::kWord32And:
      return ReduceWord32And(node);
    case IrOpcode::kWord64And:
      return ReduceWord64And(node);
    case IrOpcode::kWord32Or:
      return ReduceWord32Or(node);
    case IrOpcode::kWord64Or:
      return ReduceWord64Or(node);
    case IrOpcode::kWord32Xor:
      return ReduceWord32Xor(node);
    case IrOpcode::kWord64Xor:
      return ReduceWord64Xor(node);
    case IrOpcode::kWord32Shl:
      return ReduceWord32Shl(node);
    case IrOpcode::kWord64Shl:
      return ReduceWord64Shl(node);
    case IrOpcode::kWord32Shr:
      return ReduceWord32Shr(node);
    case IrOpcode::kWord64Shr:
      return ReduceWord64Shr(node);
    case IrOpcode::kWord32Sar:
      return ReduceWord32Sar(node);
    case IrOpcode::kWord64Sar:
      return ReduceWord64Sar(node);
    case IrOpcode::kWord32Ror: {
      Int32BinopMatcher m(node);
      if (m.right().Is(0)) return Replace(m.left().node());  // x ror 0 => x
      if (m.IsFoldable()) {  // K ror K => K  (K stands for arbitrary constants)
        return ReplaceInt32(base::bits::RotateRight32(
            m.left().ResolvedValue(), m.right().ResolvedValue() & 31));
      }
      break;
    }
    case IrOpcode::kWord32Equal:
      return ReduceWord32Equal(node);
    case IrOpcode::kWord64Equal:
      return ReduceWord64Equal(node);
    case IrOpcode::kInt32Add:
      return ReduceInt32Add(node);
    case IrOpcode::kInt64Add:
      return ReduceInt64Add(node);
    case IrOpcode::kInt32Sub:
      return ReduceInt32Sub(node);
    case IrOpcode::kInt64Sub:
      return ReduceInt64Sub(node);
    case IrOpcode::kInt32Mul: {
      Int32BinopMatcher m(node);
      if (m.right().Is(0)) return Replace(m.right().node());  // x * 0 => 0
      if (m.right().Is(1)) return Replace(m.left().node());   // x * 1 => x
      if (m.IsFoldable()) {  // K * K => K  (K stands for arbitrary constants)
        return ReplaceInt32(base::MulWithWraparound(m.left().ResolvedValue(),
                                                    m.right().ResolvedValue()));
      }
      if (m.right().Is(-1)) {  // x * -1 => 0 - x
        node->ReplaceInput(0, Int32Constant(0));
        node->ReplaceInput(1, m.left().node());
        NodeProperties::ChangeOp(node, machine()->Int32Sub());
        return Changed(node);
      }
      if (m.right().IsPowerOf2()) {  // x * 2^n => x << n
        node->ReplaceInput(1, Int32Constant(base::bits::WhichPowerOfTwo(
                                  m.right().ResolvedValue())));
        NodeProperties::ChangeOp(node, machine()->Word32Shl());
        return Changed(node).FollowedBy(ReduceWord32Shl(node));
      }
      // (x * Int32Constant(a)) * Int32Constant(b)) => x * Int32Constant(a * b)
      if (m.right().HasResolvedValue() && m.left().IsInt32Mul()) {
        Int32BinopMatcher n(m.left().node());
        if (n.right().HasResolvedValue() && m.OwnsInput(m.left().node())) {
          node->ReplaceInput(
              1, Int32Constant(base::MulWithWraparound(
                     m.right().ResolvedValue(), n.right().ResolvedValue())));
          node->ReplaceInput(0, n.left().node());
          return Changed(node);
        }
      }
      break;
    }
    case IrOpcode::kInt32MulWithOverflow: {
      Int32BinopMatcher m(node);
      if (m.right().Is(2)) {
        node->ReplaceInput(1, m.left().node());
        NodeProperties::ChangeOp(node, machine()->Int32AddWithOverflow());
        return Changed(node);
      }
      if (m.right().Is(-1)) {
        node->ReplaceInput(0, Int32Constant(0));
        node->ReplaceInput(1, m.left().node());
        NodeProperties::ChangeOp(node, machine()->Int32SubWithOverflow());
        return Changed(node);
      }
      break;
    }
    case IrOpcode::kInt64Mul:
      return ReduceInt64Mul(node);
    case IrOpcode::kInt32Div:
      return ReduceInt32Div(node);
    case IrOpcode::kInt64Div:
      return ReduceInt64Div(node);
    case IrOpcode::kUint32Div:
      return ReduceUint32Div(node);
    case IrOpcode::kUint64Div:
      return ReduceUint64Div(node);
    case IrOpcode::kInt32Mod:
      return ReduceInt32Mod(node);
    case IrOpcode::kInt64Mod:
      return ReduceInt64Mod(node);
    case IrOpcode::kUint32Mod:
      return ReduceUint32Mod(node);
    case IrOpcode::kUint64Mod:
      return ReduceUint64Mod(node);
    case IrOpcode::kInt32LessThan: {
      Int32BinopMatcher m(node);
      if (m.IsFoldable()) {  // K < K => K  (K stands for arbitrary constants)
        return ReplaceBool(m.left().ResolvedValue() <
                           m.right().ResolvedValue());
      }
      if (m.LeftEqualsRight()) return ReplaceBool(false);  // x < x => false
      if (m.left().IsWord32Or() && m.right().Is(0)) {
        // (x | K) < 0 => true or (K | x) < 0 => true iff K < 0
        Int32BinopMatcher mleftmatcher(m.left().node());
        if (mleftmatcher.left().IsNegative() ||
            mleftmatcher.right().IsNegative()) {
          return ReplaceBool(true);
        }
      }
      return ReduceWord32Comparisons(node);
    }
    case IrOpcode::kInt32LessThanOrEqual: {
      Int32BinopMatcher m(node);
      if (m.IsFoldable()) {  // K <= K => K  (K stands for arbitrary constants)
        return ReplaceBool(m.left().ResolvedValue() <=
                           m.right().ResolvedValue());
      }
      if (m.LeftEqualsRight()) return ReplaceBool(true);  // x <= x => true
      return ReduceWord32Comparisons(node);
    }
    case IrOpcode::kUint32LessThan: {
      Uint32BinopMatcher m(node);
      if (m.left().Is(kMaxUInt32)) return ReplaceBool(false);  // M < x => false
      if (m.right().Is(0)) return ReplaceBool(false);          // x < 0 => false
      if (m.IsFoldable()) {  // K < K => K  (K stands for arbitrary constants)
        return ReplaceBool(m.left().ResolvedValue() <
                           m.right().ResolvedValue());
      }
      if (m.LeftEqualsRight()) return ReplaceBool(false);  // x < x => false
      if (m.left().IsWord32Sar() && m.right().HasResolvedValue()) {
        Int32BinopMatcher mleft(m.left().node());
        if (mleft.right().HasResolvedValue()) {
          // (x >> K) < C => x < (C << K)
          // when C < (M >> K)
          const uint32_t c = m.right().ResolvedValue();
          const uint32_t k = mleft.right().ResolvedValue() & 0x1F;
          if (c < static_cast<uint32_t>(kMaxInt >> k)) {
            node->ReplaceInput(0, mleft.left().node());
            node->ReplaceInput(1, Uint32Constant(c << k));
            return Changed(node);
          }
          // TODO(turbofan): else the comparison is always true.
        }
      }
      return ReduceWord32Comparisons(node);
    }
    case IrOpcode::kUint32LessThanOrEqual: {
      return ReduceUintNLessThanOrEqual<Word32Adapter>(node);
    }
    case IrOpcode::kFloat32Sub: {
      Float32BinopMatcher m(node);
      if (signalling_nan_propagation_ == kPropagateSignallingNan &&
          m.right().Is(0) &&
          (std::copysign(1.0, m.right().ResolvedValue()) > 0)) {
        return Replace(m.left().node());  // x - 0 => x
      }
      if (m.right().IsNaN()) {  // x - NaN => NaN
        return ReplaceFloat32(SilenceNaN(m.right().ResolvedValue()));
      }
      if (m.left().IsNaN()) {  // NaN - x => NaN
        return ReplaceFloat32(SilenceNaN(m.left().ResolvedValue()));
      }
      if (m.IsFoldable()) {  // L - R => (L - R)
        return ReplaceFloat32(m.left().ResolvedValue() -
                              m.right().ResolvedValue());
      }
      if (signalling_nan_propagation_ == kPropagateSignallingNan &&
          m.left().IsMinusZero()) {
        // -0.0 - round_down(-0.0 - R) => round_up(R)
        if (machine()->Float32RoundUp().IsSupported() &&
            m.right().IsFloat32RoundDown()) {
          if (m.right().InputAt(0)->opcode() == IrOpcode::kFloat32Sub) {
            Float32BinopMatcher mright0(m.right().InputAt(0));
            if (mright0.left().IsMinusZero()) {
              return Replace(graph()->NewNode(machine()->Float32RoundUp().op(),
                                              mright0.right().node()));
            }
          }
        }
        // -0.0 - R => -R
        node->RemoveInput(0);
        NodeProperties::ChangeOp(node, machine()->Float32Neg());
        return Changed(node);
      }
      break;
    }
    case IrOpcode::kFloat64Add: {
      Float64BinopMatcher m(node);
      if (m.right().IsNaN()) {  // x + NaN => NaN
        return ReplaceFloat64(SilenceNaN(m.right().ResolvedValue()));
      }
      if (m.left().IsNaN()) {  // NaN + x => NaN
        return ReplaceFloat64(SilenceNaN(m.left().ResolvedValue()));
      }
      if (m.IsFoldable()) {  // K + K => K  (K stands for arbitrary constants)
        return ReplaceFloat64(m.left().ResolvedValue() +
                              m.right().ResolvedValue());
      }
      break;
    }
    case IrOpcode::kFloat64Sub: {
      Float64BinopMatcher m(node);
      if (signalling_nan_propagation_ == kPropagateSignallingNan &&
          m.right().Is(0) &&
          (base::Double(m.right().ResolvedValue()).Sign() > 0)) {
        return Replace(m.left().node());  // x - 0 => x
      }
      if (m.right().IsNaN()) {  // x - NaN => NaN
        return ReplaceFloat64(SilenceNaN(m.right().ResolvedValue()));
      }
      if (m.left().IsNaN()) {  // NaN - x => NaN
        return ReplaceFloat64(SilenceNaN(m.left().ResolvedValue()));
      }
      if (m.IsFoldable()) {  // L - R => (L - R)
        return ReplaceFloat64(m.left().ResolvedValue() -
                              m.right().ResolvedValue());
      }
      if (signalling_nan_propagation_ == kPropagateSignallingNan &&
          m.left().IsMinusZero()) {
        // -0.0 - round_down(-0.0 - R) => round_up(R)
        if (machine()->Float64RoundUp().IsSupported() &&
            m.right().IsFloat64RoundDown()) {
          if (m.right().InputAt(0)->opcode() == IrOpcode::kFloat64Sub) {
            Float64BinopMatcher mright0(m.right().InputAt(0));
            if (mright0.left().IsMinusZero()) {
              return Replace(graph()->NewNode(machine()->Float64RoundUp().op(),
                                              mright0.right().node()));
            }
          }
        }
        // -0.0 - R => -R
        node->RemoveInput(0);
        NodeProperties::ChangeOp(node, machine()->Float64Neg());
        return Changed(node);
      }
      break;
    }
    case IrOpcode::kFloat64Mul: {
      Float64BinopMatcher m(node);
      if (signalling_nan_propagation_ == kPropagateSignallingNan &&
          m.right().Is(1))
        return Replace(m.left().node());  // x * 1.0 => x
      if (m.right().Is(-1)) {             // x * -1.0 => -0.0 - x
        node->ReplaceInput(0, Float64Constant(-0.0));
        node->ReplaceInput(1, m.left().node());
        NodeProperties::ChangeOp(node, machine()->Float64Sub());
        return Changed(node);
      }
      if (m.right().IsNaN()) {  // x * NaN => NaN
        return ReplaceFloat64(SilenceNaN(m.right().ResolvedValue()));
      }
      if (m.IsFoldable()) {  // K * K => K  (K stands for arbitrary constants)
        return ReplaceFloat64(m.left().ResolvedValue() *
                              m.right().ResolvedValue());
      }
      if (m.right().Is(2)) {  // x * 2.0 => x + x
        node->ReplaceInput(1, m.left().node());
        NodeProperties::ChangeOp(node, machine()->Float64Add());
        return Changed(node);
      }
      break;
    }
    case IrOpcode::kFloat64Div: {
      Float64BinopMatcher m(node);
      if (signalling_nan_propagation_ == kPropagateSignallingNan &&
          m.right().Is(1))
        return Replace(m.left().node());  // x / 1.0 => x
      // TODO(ahaas): We could do x / 1.0 = x if we knew that x is not an sNaN.
      if (m.right().IsNaN()) {  // x / NaN => NaN
        return ReplaceFloat64(SilenceNaN(m.right().ResolvedValue()));
      }
      if (m.left().IsNaN()) {  // NaN / x => NaN
        return ReplaceFloat64(SilenceNaN(m.left().ResolvedValue()));
      }
      if (m.IsFoldable()) {  // K / K => K  (K stands for arbitrary constants)
        return ReplaceFloat64(
            base::Divide(m.left().ResolvedValue(), m.right().ResolvedValue()));
      }
      if (signalling_nan_propagation_ == kPropagateSignallingNan &&
          m.right().Is(-1)) {  // x / -1.0 => -x
        node->RemoveInput(1);
        NodeProperties::ChangeOp(node, machine()->Float64Neg());
        return Changed(node);
      }
      if (m.right().IsNormal() && m.right().IsPositiveOrNegativePowerOf2()) {
        // All reciprocals of non-denormal powers of two can be represented
        // exactly, so division by power of two can be reduced to
        // multiplication by reciprocal, with the same result.
        node->ReplaceInput(1, Float64Constant(1.0 / m.right().ResolvedValue()));
        NodeProperties::ChangeOp(node, machine()->Float64Mul());
        return Changed(node);
      }
      break;
    }
    case IrOpcode::kFloat64Mod: {
      Float64BinopMatcher m(node);
      if (m.right().Is(0)) {  // x % 0 => NaN
        return ReplaceFloat64(std::numeric_limits<double>::quiet_NaN());
      }
      if (m.right().IsNaN()) {  // x % NaN => NaN
        return ReplaceFloat64(SilenceNaN(m.right().ResolvedValue()));
      }
      if (m.left().IsNaN()) {  // NaN % x => NaN
        return ReplaceFloat64(SilenceNaN(m.left().ResolvedValue()));
      }
      if (m.IsFoldable()) {  // K % K => K  (K stands for arbitrary constants)
        return ReplaceFloat64(
            Modulo(m.left().ResolvedValue(), m.right().ResolvedValue()));
      }
      break;
    }
    case IrOpcode::kFloat64Acos: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::acos(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Acosh: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::acosh(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Asin: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::asin(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Asinh: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::asinh(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Atan: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::atan(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Atanh: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::atanh(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Atan2: {
      Float64BinopMatcher m(node);
      if (m.right().IsNaN()) {
        return ReplaceFloat64(SilenceNaN(m.right().ResolvedValue()));
      }
      if (m.left().IsNaN()) {
        return ReplaceFloat64(SilenceNaN(m.left().ResolvedValue()));
      }
      if (m.IsFoldable()) {
        return ReplaceFloat64(base::ieee754::atan2(m.left().ResolvedValue(),
                                                   m.right().ResolvedValue()));
      }
      break;
    }
    case IrOpcode::kFloat64Cbrt: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::cbrt(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Cos: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(COS_IMPL(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Cosh: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::cosh(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Exp: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::exp(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Expm1: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::expm1(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Log: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::log(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Log1p: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::log1p(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Log10: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::log10(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Log2: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::log2(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Pow: {
      Float64BinopMatcher m(node);
      if (m.IsFoldable()) {
        return ReplaceFloat64(
            math::pow(m.left().ResolvedValue(), m.right().ResolvedValue()));
      } else if (m.right().Is(0.0)) {  // x ** +-0.0 => 1.0
        return ReplaceFloat64(1.0);
      } else if (m.right().Is(2.0)) {  // x ** 2.0 => x * x
        node->ReplaceInput(1, m.left().node());
        NodeProperties::ChangeOp(node, machine()->Float64Mul());
        return Changed(node);
      } else if (m.right().Is(0.5)) {
        // x ** 0.5 => if x <= -Infinity then Infinity else sqrt(0.0 + x)
        return Replace(Float64PowHalf(m.left().node()));
      }
      break;
    }
    case IrOpcode::kFloat64Sin: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(SIN_IMPL(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Sinh: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::sinh(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Tan: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::tan(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kFloat64Tanh: {
      Float64Matcher m(node->InputAt(0));
      if (m.HasResolvedValue())
        return ReplaceFloat64(base::ieee754::tanh(m.ResolvedValue()));
      break;
    }
    case IrOpcode::kChangeFloat32ToFloat64: {
      Float32Matcher m(node->InputAt(0));
      if (m.HasResolvedValue()) {
        if (signalling_nan_propagation_ == kSilenceSignallingNan &&
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