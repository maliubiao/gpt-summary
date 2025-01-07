Response:
The user wants to understand the functionality of the `v8/src/compiler/machine-operator-reducer.cc` file in the V8 JavaScript engine. I need to analyze the provided C++ code snippet and explain its purpose.

Here's a breakdown of the steps:

1. **Identify the core functionality:** The file name and the presence of methods like `ReduceWord32And`, `ReduceInt32Add`, etc., strongly suggest that this file is responsible for optimizing machine-level operations in the V8 compiler. It seems to perform constant folding and strength reduction.

2. **Check if it's a Torque file:** The prompt explicitly asks to check if the file ends with `.tq`. This file ends with `.cc`, so it's not a Torque file.

3. **Determine its relation to JavaScript:** Since this file is part of the V8 compiler, which compiles JavaScript code, its optimizations directly impact the performance of JavaScript execution. I need to provide a JavaScript example demonstrating how these optimizations might be relevant.

4. **Illustrate code logic reasoning:** The code contains specific optimization rules, like simplifying `x * 0` to `0`. I should provide a hypothetical input (an IR node representing such an operation) and the expected output (the simplified node).

5. **Highlight common programming errors:** Some optimizations might relate to how developers write code. I need to think about common mistakes that could be caught or optimized by this reducer.

6. **Summarize the overall functionality:** Based on the analysis, I need to provide a concise summary of the `MachineOperatorReducer`'s role.
```javascript
// 这是一个 JavaScript 例子，展示了 machine-operator-reducer.cc 可能优化的场景

function example(a) {
  return a * 0; // 这是一个简单的乘法运算
}

// 当 V8 编译上述 JavaScript 函数时，machine-operator-reducer.cc 中的逻辑
// 会识别出乘以 0 的操作，并将其简化为直接返回 0，避免执行实际的乘法运算。
```

`v8/src/compiler/machine-operator-reducer.cc` 文件的主要功能是**对 V8 编译器生成的中间代码（machine code）中的机器操作进行优化**。它通过识别可以简化的操作模式，例如常量折叠和强度削减，来提高生成的机器代码的效率。

**功能归纳:**

1. **常量折叠 (Constant Folding):** 如果一个操作的所有输入都是常量，那么在编译时就计算出结果，而不是在运行时执行。例如，`3 + 4` 可以直接被替换为 `7`。
2. **强度削减 (Strength Reduction):** 将计算量大的操作替换为计算量小的等价操作。例如，乘以 2 的幂可以使用左移操作代替（`x * 8` 可以替换为 `x << 3`）。
3. **代数简化:** 应用代数恒等式来简化表达式。例如，`x * 1` 可以被替换为 `x`，`x - x` 可以被替换为 `0`。
4. **位运算优化:** 对位运算进行特定的优化，例如与零进行 AND 运算结果为零，或者对移位操作的优化。
5. **浮点数运算优化:** 对浮点数运算进行特定的优化，例如处理 NaN 值，以及一些特殊的乘法和除法情况。

**根据提供的代码片段，可以观察到以下具体功能点:**

* **适配器模式 (Word32Adapter, Word64Adapter):**  使用了适配器模式，将一些通用的优化算法应用于不同字长的操作（32 位和 64 位）。
* **常量节点创建:** 提供了创建特定类型常量节点的辅助方法 (例如 `Float32Constant`, `Int32Constant`)。
* **二元操作的简化:** 包含了对各种二元机器操作（例如加法、减法、乘法、位运算等）的简化逻辑。
* **浮点数特殊值处理:**  对 NaN (Not a Number) 和无穷大等浮点数特殊值进行处理和优化。
* **移位优化:** 对左移、右移等操作进行优化，例如移位量为 0 的情况。
* **除法优化:**  针对常量除数的情况，使用乘法和移位来替代除法运算，提高效率。
* **三角函数和数学函数优化:**  对于一些数学函数，如果输入是常量，则直接计算结果。

**代码逻辑推理示例:**

**假设输入:** 一个表示 `Word32And` 操作的节点，其左输入是一个值为 `10` 的常量节点，右输入是一个值为 `5` 的常量节点。

```
// 假设 graph() 是当前的图构建器
Node* left = Int32Constant(10); // 二进制: 0000...1010
Node* right = Int32Constant(5);  // 二进制: 0000...0101
Node* and_node = graph()->NewNode(machine()->Word32And(), left, right);
```

**`ReduceWord32And` 函数的逻辑会识别出两个输入都是常量，并执行位与运算:**

10 (十进制)  = 1010 (二进制)
 5 (十进制)  = 0101 (二进制)
------------------ AND
             = 0000 (二进制) = 0 (十进制)

**输出:** `ReduceWord32And` 函数会返回一个 `ReplaceInt32(0)` 的 `Reduction` 对象，指示将原始的 `Word32And` 节点替换为一个值为 `0` 的常量节点。

**用户常见的编程错误示例:**

虽然 `machine-operator-reducer.cc` 主要处理编译器内部的优化，但它优化的一些场景可能与用户常见的编程习惯有关，例如：

1. **不必要的乘法或除法:** 程序员可能会写出类似 `x * 1` 或 `y / 1` 的代码。`machine-operator-reducer.cc` 可以识别并消除这些不必要的操作。

   ```javascript
   function unnecessaryArithmetic(x, y) {
     return x * 1 + y / 1;
   }
   // 优化后等价于：
   function unnecessaryArithmeticOptimized(x, y) {
     return x + y;
   }
   ```

2. **使用复杂的表达式进行简单的位操作:**  虽然程序员可能不会直接写出可以使用强度削减优化的代码，但某些复杂的逻辑可能会被编译器转换为可以优化的形式。

3. **重复计算:**  在某些情况下，虽然不是 `machine-operator-reducer.cc` 直接处理的，但它的优化能力可以与其他优化阶段协同工作，减少重复计算。

**总结:**

`v8/src/compiler/machine-operator-reducer.cc` 是 V8 编译器中的一个关键组件，负责对生成的机器代码进行低级别的优化，包括常量折叠、强度削减、代数简化以及特定于位运算和浮点数运算的优化。它的目标是生成更高效的机器代码，从而提升 JavaScript 代码的执行性能。

Prompt: 
```
这是目录为v8/src/compiler/machine-operator-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/machine-operator-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

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
        if (signalling_nan_prop
"""


```