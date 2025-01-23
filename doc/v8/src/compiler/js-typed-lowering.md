Response: My thought process to arrive at the summary of `js-typed-lowering.cc` goes like this:

1. **Identify the core purpose from the file name and includes:** The name "js-typed-lowering.cc" strongly suggests the file deals with *lowering* JavaScript operations, and the inclusion of `<optional>`, various AST and compiler headers (`src/ast/modules.h`, `src/compiler/...`), and specifically `src/compiler/js-graph.h` points to a transformation within the Turbofan pipeline. The "typed" part hints at leveraging type information for optimization.

2. **Scan for key classes and structures:**  The code immediately introduces `JSBinopReduction`. The name suggests it helps with binary operations. The presence of `JSTypedLowering` as the main class confirms the file's central role in the lowering process.

3. **Analyze `JSBinopReduction`:** This class has methods like `GetCompareNumberOperationHint`, `IsStringCompareOperation`, `CheckInputsToString`, `ConvertInputsToNumber`, and `ChangeToPureOperator`. This reveals its function: to analyze and potentially transform binary JavaScript operations based on the types of their inputs. It aims to replace high-level JavaScript operations with more specific, lower-level, and often pure (side-effect free) operations from the "simplified" operator set.

4. **Analyze `JSTypedLowering` methods:**  Methods like `ReduceJSBitwiseNot`, `ReduceJSAdd`, `ReduceJSComparison`, `ReduceJSEqual`, `ReduceJSToNumber`, `ReduceJSToString`, `ReduceJSLoadNamed`, etc., clearly indicate the file's role in processing various JavaScript operators and built-in functions. The "Reduce" prefix signifies an attempt to simplify or lower these operations.

5. **Look for patterns and common themes:**  Several methods within `JSTypedLowering` check input types. If the types are specific enough (e.g., both inputs to `JSAdd` are numbers), they transform the operation into a more efficient lower-level equivalent (`NumberAdd`). The use of "simplified" operators is a recurring pattern. There's also handling of string concatenation, comparisons, and type conversions.

6. **Connect to JavaScript functionality:**  The file processes core JavaScript operations like `+`, `-`, `*`, `==`, `===`, type conversions (`ToNumber`, `ToString`), and property access. This is a strong indication of its relationship to how JavaScript code is executed.

7. **Formulate a high-level summary:** Based on the observations above, I'd start drafting: "This C++ file (`js-typed-lowering.cc`) is part of the V8 JavaScript engine's Turbofan compiler. Its primary function is to optimize JavaScript code during the *typed lowering* phase."

8. **Elaborate on the key mechanisms:**  Then, I'd add detail about `JSBinopReduction` and its role in handling binary operations based on type information. Mention the goal of replacing generic JavaScript operations with more specific simplified ones.

9. **Provide concrete examples:**  To illustrate the connection to JavaScript, I'd pick a few representative methods and explain their transformations. `ReduceJSAdd` is a good example because it handles both numeric addition and string concatenation, showcasing type-based optimization. Showing how `JSAdd(number, number)` becomes `NumberAdd` and how `JSAdd(string, string)` becomes string concatenation makes the concept tangible. Similarly, explaining how `JSEqual` might be optimized for specific types enhances understanding.

10. **Refine and structure:** Finally, I would organize the summary into a clear structure, starting with the main function, then explaining the supporting mechanisms, and finally illustrating with JavaScript examples. I would ensure the language is concise and focuses on the key takeaways. I'd also explicitly mention that this is part 1 and that further functionalities may be present in part 2.

This systematic analysis of the code structure, method names, and the overall purpose within a compiler pipeline allows for a comprehensive and accurate summary of the file's functionality and its relation to JavaScript.
这个C++源代码文件 `v8/src/compiler/js-typed-lowering.cc` 是 V8 JavaScript 引擎中 Turbofan 编译器的 **类型化降低 (Typed Lowering)** 阶段的一部分。

**它的主要功能是：**

将相对高级的、与 JavaScript 语义紧密相关的操作 (例如 `JSAdd`, `JSEqual`, `JSToNumber` 等) 转换成更底层的、更接近机器指令的 **简化操作 (Simplified Operations)**。  这个过程会利用已有的类型信息 (例如通过类型推断或反馈收集得到) 来进行优化。

**更具体地说，这个文件负责：**

1. **识别可以进行类型优化的 JavaScript 操作:**  遍历编译图中的节点，查找代表各种 JavaScript 操作的节点。
2. **检查操作数的类型:**  分析这些操作的输入值的类型信息。
3. **基于类型信息进行转换:**  根据操作数类型的不同，将 JavaScript 操作替换为更具体的简化操作。例如：
    * 如果 `JSAdd` 的两个操作数都是数字类型，则可以降低为 `NumberAdd`。
    * 如果 `JSEqual` 的两个操作数都是字符串类型，则可以降低为 `StringEqual`。
    * 类型转换操作 (`JSToNumber`, `JSToString` 等) 如果输入类型已知，则可以被优化或直接替换为常量。
4. **插入类型检查:**  在类型信息不完全可靠或需要运行时验证的情况下，会插入 `Check...` 类型的节点来确保类型安全。
5. **处理不同的 JavaScript 运算符和内置函数:**  针对不同的 JavaScript 运算符 (如算术运算符、比较运算符、位运算符) 和内置函数 (如类型转换函数)，提供相应的降低逻辑。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

这个文件直接影响 JavaScript 代码的执行效率。通过利用类型信息进行优化，Turbofan 能够生成更快速的机器码。

**以下是一些 JavaScript 示例，说明了 `js-typed-lowering.cc` 可能进行的优化：**

**1. 加法运算符 (+):**

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2); // a 和 b 都是数字
add("hello", " world"); // a 和 b 都是字符串
add(1, " world"); // a 是数字，b 是字符串
```

* **如果 `a` 和 `b` 的类型在编译时被推断或已知为数字，`js-typed-lowering.cc` 可以将 `a + b` 降低为 `NumberAdd` 操作，这是一个高效的数字加法操作。**
* **如果 `a` 和 `b` 的类型是字符串，`js-typed-lowering.cc` 可以将其降低为字符串连接操作 (例如 `StringConcat` 或 `NewConsString`)。**
* **如果类型不确定或混合，则可能需要插入类型转换操作 (`JSToString` 等) 或使用更通用的加法操作。**

**2. 相等运算符 (== 和 ===):**

```javascript
function compare(x, y) {
  return x == y;
  return x === y;
}

compare(1, 1); // 数字比较
compare("hello", "hello"); // 字符串比较
compare(null, undefined); // 特殊情况
compare({value: 1}, {value: 1}); // 对象比较
```

* **如果 `x` 和 `y` 的类型已知为相同的原始类型 (例如都是数字或都是字符串)，`js-typed-lowering.cc` 可以将 `==` 或 `===` 降低为更高效的 `NumberEqual` 或 `StringEqual` 操作。**
* **对于严格相等 `===`，如果类型已知且兼容 (例如都是对象)，可以降低为 `ReferenceEqual` (检查引用是否相同)。**
* **对于抽象相等 `==`，则需要处理更复杂的类型转换规则。**

**3. 类型转换函数 (如 `Number()`, `String()`):**

```javascript
function convert(value) {
  return Number(value);
  return String(value);
}

convert("123");
convert(true);
convert(10);
```

* **如果 `Number(value)` 的 `value` 在编译时已知是数字，`js-typed-lowering.cc` 可以直接将其替换为 `value` 本身。**
* **如果 `value` 是布尔值，则可以替换为对应的数字 `0` 或 `1`。**
* **类似地，对于 `String(value)`，如果 `value` 已知是字符串，则直接使用 `value`。如果已知是其他原始类型，则可以替换为对应的字符串常量 (`"true"`, `"false"`, `"null"`, `"undefined"`) 或调用底层的字符串转换操作。**

总而言之，`v8/src/compiler/js-typed-lowering.cc` 是 Turbofan 编译器中一个至关重要的组成部分，它通过分析类型信息，将高级的 JavaScript 操作转换为更底层的、性能更高的简化操作，从而显著提升 JavaScript 代码的执行效率。 这是类型优化编译的关键步骤。

### 提示词
```
这是目录为v8/src/compiler/js-typed-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/js-typed-lowering.h"

#include <optional>

#include "src/ast/modules.h"
#include "src/builtins/builtins-utils.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/allocation-builder-inl.h"
#include "src/compiler/allocation-builder.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/graph-assembler.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/linkage.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/node.h"
#include "src/compiler/operator-properties.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/turbofan-types.h"
#include "src/compiler/type-cache.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/execution/protectors.h"
#include "src/objects/casting.h"
#include "src/objects/heap-number.h"
#include "src/objects/js-generator.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/objects/property-cell.h"

namespace v8 {
namespace internal {
namespace compiler {

// A helper class to simplify the process of reducing a single binop node with a
// JSOperator. This class manages the rewriting of context, control, and effect
// dependencies during lowering of a binop and contains numerous helper
// functions for matching the types of inputs to an operation.
class JSBinopReduction final {
 public:
  JSBinopReduction(JSTypedLowering* lowering, Node* node)
      : lowering_(lowering), node_(node) {}

  bool GetCompareNumberOperationHint(NumberOperationHint* hint) {
    DCHECK_EQ(1, node_->op()->EffectOutputCount());
    switch (GetCompareOperationHint(node_)) {
      case CompareOperationHint::kSignedSmall:
        *hint = NumberOperationHint::kSignedSmall;
        return true;
      case CompareOperationHint::kNumber:
        *hint = NumberOperationHint::kNumber;
        return true;
      case CompareOperationHint::kNumberOrBoolean:
        *hint = NumberOperationHint::kNumberOrBoolean;
        return true;
      case CompareOperationHint::kNumberOrOddball:
        *hint = NumberOperationHint::kNumberOrOddball;
        return true;
      case CompareOperationHint::kAny:
      case CompareOperationHint::kNone:
      case CompareOperationHint::kString:
      case CompareOperationHint::kSymbol:
      case CompareOperationHint::kBigInt:
      case CompareOperationHint::kBigInt64:
      case CompareOperationHint::kReceiver:
      case CompareOperationHint::kReceiverOrNullOrUndefined:
      case CompareOperationHint::kInternalizedString:
        break;
    }
    return false;
  }

  bool GetCompareBigIntOperationHint(BigIntOperationHint* hint) {
    DCHECK_EQ(1, node_->op()->EffectOutputCount());
    switch (GetCompareOperationHint(node_)) {
      case CompareOperationHint::kSignedSmall:
      case CompareOperationHint::kNumber:
      case CompareOperationHint::kNumberOrBoolean:
      case CompareOperationHint::kNumberOrOddball:
      case CompareOperationHint::kAny:
      case CompareOperationHint::kNone:
      case CompareOperationHint::kString:
      case CompareOperationHint::kSymbol:
      case CompareOperationHint::kReceiver:
      case CompareOperationHint::kReceiverOrNullOrUndefined:
      case CompareOperationHint::kInternalizedString:
        return false;
      case CompareOperationHint::kBigInt:
        *hint = BigIntOperationHint::kBigInt;
        return true;
      case CompareOperationHint::kBigInt64:
        *hint = BigIntOperationHint::kBigInt64;
        return true;
    }
    UNREACHABLE();
  }

  bool IsInternalizedStringCompareOperation() {
    DCHECK_EQ(1, node_->op()->EffectOutputCount());
    return (GetCompareOperationHint(node_) ==
            CompareOperationHint::kInternalizedString) &&
           BothInputsMaybe(Type::InternalizedString());
  }

  bool IsReceiverCompareOperation() {
    DCHECK_EQ(1, node_->op()->EffectOutputCount());
    return (GetCompareOperationHint(node_) ==
            CompareOperationHint::kReceiver) &&
           BothInputsMaybe(Type::Receiver());
  }

  bool IsReceiverOrNullOrUndefinedCompareOperation() {
    DCHECK_EQ(1, node_->op()->EffectOutputCount());
    return (GetCompareOperationHint(node_) ==
            CompareOperationHint::kReceiverOrNullOrUndefined) &&
           BothInputsMaybe(Type::ReceiverOrNullOrUndefined());
  }

  bool IsStringCompareOperation() {
    DCHECK_EQ(1, node_->op()->EffectOutputCount());
    return (GetCompareOperationHint(node_) == CompareOperationHint::kString) &&
           BothInputsMaybe(Type::String());
  }

  bool IsSymbolCompareOperation() {
    DCHECK_EQ(1, node_->op()->EffectOutputCount());
    return (GetCompareOperationHint(node_) == CompareOperationHint::kSymbol) &&
           BothInputsMaybe(Type::Symbol());
  }

  // Check if a string addition will definitely result in creating a ConsString,
  // i.e. if the combined length of the resulting string exceeds the ConsString
  // minimum length.
  bool ShouldCreateConsString() {
    DCHECK_EQ(IrOpcode::kJSAdd, node_->opcode());
    DCHECK(OneInputIs(Type::String()));
    if (BothInputsAre(Type::String()) ||
        GetBinaryOperationHint(node_) == BinaryOperationHint::kString) {
      HeapObjectBinopMatcher m(node_);
      JSHeapBroker* broker = lowering_->broker();
      if (m.right().HasResolvedValue() && m.right().Ref(broker).IsString()) {
        StringRef right_string = m.right().Ref(broker).AsString();
        if (right_string.length() >= ConsString::kMinLength) return true;
      }
      if (m.left().HasResolvedValue() && m.left().Ref(broker).IsString()) {
        StringRef left_string = m.left().Ref(broker).AsString();
        if (left_string.length() >= ConsString::kMinLength) {
          // The invariant for ConsString requires the left hand side to be
          // a sequential or external string if the right hand side is the
          // empty string. Since we don't know anything about the right hand
          // side here, we must ensure that the left hand side satisfy the
          // constraints independent of the right hand side.
          return left_string.IsSeqString() || left_string.IsExternalString();
        }
      }
    }
    return false;
  }

  // Inserts a CheckReceiver for the left input.
  void CheckLeftInputToReceiver() {
    Node* left_input = graph()->NewNode(simplified()->CheckReceiver(), left(),
                                        effect(), control());
    node_->ReplaceInput(0, left_input);
    update_effect(left_input);
  }

  // Inserts a CheckReceiverOrNullOrUndefined for the left input.
  void CheckLeftInputToReceiverOrNullOrUndefined() {
    Node* left_input =
        graph()->NewNode(simplified()->CheckReceiverOrNullOrUndefined(), left(),
                         effect(), control());
    node_->ReplaceInput(0, left_input);
    update_effect(left_input);
  }

  // Checks that both inputs are Receiver, and if we don't know
  // statically that one side is already a Receiver, insert a
  // CheckReceiver node.
  void CheckInputsToReceiver() {
    if (!left_type().Is(Type::Receiver())) {
      CheckLeftInputToReceiver();
    }
    if (!right_type().Is(Type::Receiver())) {
      Node* right_input = graph()->NewNode(simplified()->CheckReceiver(),
                                           right(), effect(), control());
      node_->ReplaceInput(1, right_input);
      update_effect(right_input);
    }
  }

  // Checks that both inputs are Receiver, Null or Undefined and if
  // we don't know statically that one side is already a Receiver,
  // Null or Undefined, insert CheckReceiverOrNullOrUndefined nodes.
  void CheckInputsToReceiverOrNullOrUndefined() {
    if (!left_type().Is(Type::ReceiverOrNullOrUndefined())) {
      CheckLeftInputToReceiverOrNullOrUndefined();
    }
    if (!right_type().Is(Type::ReceiverOrNullOrUndefined())) {
      Node* right_input =
          graph()->NewNode(simplified()->CheckReceiverOrNullOrUndefined(),
                           right(), effect(), control());
      node_->ReplaceInput(1, right_input);
      update_effect(right_input);
    }
  }

  // Inserts a CheckSymbol for the left input.
  void CheckLeftInputToSymbol() {
    Node* left_input = graph()->NewNode(simplified()->CheckSymbol(), left(),
                                        effect(), control());
    node_->ReplaceInput(0, left_input);
    update_effect(left_input);
  }

  // Checks that both inputs are Symbol, and if we don't know
  // statically that one side is already a Symbol, insert a
  // CheckSymbol node.
  void CheckInputsToSymbol() {
    if (!left_type().Is(Type::Symbol())) {
      CheckLeftInputToSymbol();
    }
    if (!right_type().Is(Type::Symbol())) {
      Node* right_input = graph()->NewNode(simplified()->CheckSymbol(), right(),
                                           effect(), control());
      node_->ReplaceInput(1, right_input);
      update_effect(right_input);
    }
  }

  // Checks that both inputs are String, and if we don't know
  // statically that one side is already a String, insert a
  // CheckString node.
  void CheckInputsToString() {
    if (!left_type().Is(Type::String())) {
      Node* left_input =
          graph()->NewNode(simplified()->CheckString(FeedbackSource()), left(),
                           effect(), control());
      node_->ReplaceInput(0, left_input);
      update_effect(left_input);
    }
    if (!right_type().Is(Type::String())) {
      Node* right_input =
          graph()->NewNode(simplified()->CheckString(FeedbackSource()), right(),
                           effect(), control());
      node_->ReplaceInput(1, right_input);
      update_effect(right_input);
    }
  }

  // Checks that both inputs are String or string wrapper, and if we don't know
  // statically that one side is already a String or a string wrapper, insert a
  // CheckStringOrStringWrapper node.
  void CheckInputsToStringOrStringWrapper() {
    if (!left_type().Is(Type::StringOrStringWrapper())) {
      Node* left_input = graph()->NewNode(
          simplified()->CheckStringOrStringWrapper(FeedbackSource()), left(),
          effect(), control());
      node_->ReplaceInput(0, left_input);
      update_effect(left_input);
    }
    if (!right_type().Is(Type::StringOrStringWrapper())) {
      Node* right_input = graph()->NewNode(
          simplified()->CheckStringOrStringWrapper(FeedbackSource()), right(),
          effect(), control());
      node_->ReplaceInput(1, right_input);
      update_effect(right_input);
    }
  }

  // Checks that both inputs are InternalizedString, and if we don't know
  // statically that one side is already an InternalizedString, insert a
  // CheckInternalizedString node.
  void CheckInputsToInternalizedString() {
    if (!left_type().Is(Type::UniqueName())) {
      Node* left_input = graph()->NewNode(
          simplified()->CheckInternalizedString(), left(), effect(), control());
      node_->ReplaceInput(0, left_input);
      update_effect(left_input);
    }
    if (!right_type().Is(Type::UniqueName())) {
      Node* right_input =
          graph()->NewNode(simplified()->CheckInternalizedString(), right(),
                           effect(), control());
      node_->ReplaceInput(1, right_input);
      update_effect(right_input);
    }
  }

  void ConvertInputsToNumber() {
    DCHECK(left_type().Is(Type::PlainPrimitive()));
    DCHECK(right_type().Is(Type::PlainPrimitive()));
    node_->ReplaceInput(0, ConvertPlainPrimitiveToNumber(left()));
    node_->ReplaceInput(1, ConvertPlainPrimitiveToNumber(right()));
  }

  void ConvertInputsToUI32(Signedness left_signedness,
                           Signedness right_signedness) {
    node_->ReplaceInput(0, ConvertToUI32(left(), left_signedness));
    node_->ReplaceInput(1, ConvertToUI32(right(), right_signedness));
  }

  void SwapInputs() {
    Node* l = left();
    Node* r = right();
    node_->ReplaceInput(0, r);
    node_->ReplaceInput(1, l);
  }

  // Remove all effect and control inputs and outputs to this node and change
  // to the pure operator {op}.
  Reduction ChangeToPureOperator(const Operator* op, Type type = Type::Any()) {
    DCHECK_EQ(0, op->EffectInputCount());
    DCHECK_EQ(false, OperatorProperties::HasContextInput(op));
    DCHECK_EQ(0, op->ControlInputCount());
    DCHECK_EQ(2, op->ValueInputCount());

    // Remove the effects from the node, and update its effect/control usages.
    if (node_->op()->EffectInputCount() > 0) {
      lowering_->RelaxEffectsAndControls(node_);
    }
    // Remove the inputs corresponding to context, effect, and control.
    NodeProperties::RemoveNonValueInputs(node_);
    // Remove the feedback vector input, if applicable.
    if (JSOperator::IsBinaryWithFeedback(node_->opcode())) {
      node_->RemoveInput(JSBinaryOpNode::FeedbackVectorIndex());
    }
    // Finally, update the operator to the new one.
    NodeProperties::ChangeOp(node_, op);

    // TODO(jarin): Replace the explicit typing hack with a call to some method
    // that encapsulates changing the operator and re-typing.
    Type node_type = NodeProperties::GetType(node_);
    NodeProperties::SetType(node_, Type::Intersect(node_type, type, zone()));

    return lowering_->Changed(node_);
  }

  Reduction ChangeToSpeculativeOperator(const Operator* op, Type upper_bound) {
    DCHECK_EQ(1, op->EffectInputCount());
    DCHECK_EQ(1, op->EffectOutputCount());
    DCHECK_EQ(false, OperatorProperties::HasContextInput(op));
    DCHECK_EQ(1, op->ControlInputCount());
    DCHECK_EQ(0, op->ControlOutputCount());
    DCHECK_EQ(0, OperatorProperties::GetFrameStateInputCount(op));
    DCHECK_EQ(2, op->ValueInputCount());

    DCHECK_EQ(1, node_->op()->EffectInputCount());
    DCHECK_EQ(1, node_->op()->EffectOutputCount());
    DCHECK_EQ(1, node_->op()->ControlInputCount());

    // Reconnect the control output to bypass the IfSuccess node and
    // possibly disconnect from the IfException node.
    lowering_->RelaxControls(node_);

    // Remove the frame state and the context.
    if (OperatorProperties::HasFrameStateInput(node_->op())) {
      node_->RemoveInput(NodeProperties::FirstFrameStateIndex(node_));
    }
    node_->RemoveInput(NodeProperties::FirstContextIndex(node_));

    // Remove the feedback vector input, if applicable.
    if (JSOperator::IsBinaryWithFeedback(node_->opcode())) {
      node_->RemoveInput(JSBinaryOpNode::FeedbackVectorIndex());
    }
    // Finally, update the operator to the new one.
    NodeProperties::ChangeOp(node_, op);

    // Update the type to number.
    Type node_type = NodeProperties::GetType(node_);
    NodeProperties::SetType(node_,
                            Type::Intersect(node_type, upper_bound, zone()));

    return lowering_->Changed(node_);
  }

  const Operator* NumberOp() {
    switch (node_->opcode()) {
      case IrOpcode::kJSAdd:
        return simplified()->NumberAdd();
      case IrOpcode::kJSSubtract:
        return simplified()->NumberSubtract();
      case IrOpcode::kJSMultiply:
        return simplified()->NumberMultiply();
      case IrOpcode::kJSDivide:
        return simplified()->NumberDivide();
      case IrOpcode::kJSModulus:
        return simplified()->NumberModulus();
      case IrOpcode::kJSExponentiate:
        return simplified()->NumberPow();
      case IrOpcode::kJSBitwiseAnd:
        return simplified()->NumberBitwiseAnd();
      case IrOpcode::kJSBitwiseOr:
        return simplified()->NumberBitwiseOr();
      case IrOpcode::kJSBitwiseXor:
        return simplified()->NumberBitwiseXor();
      case IrOpcode::kJSShiftLeft:
        return simplified()->NumberShiftLeft();
      case IrOpcode::kJSShiftRight:
        return simplified()->NumberShiftRight();
      case IrOpcode::kJSShiftRightLogical:
        return simplified()->NumberShiftRightLogical();
      default:
        break;
    }
    UNREACHABLE();
  }

  bool LeftInputIs(Type t) { return left_type().Is(t); }

  bool RightInputIs(Type t) { return right_type().Is(t); }

  bool OneInputIs(Type t) { return LeftInputIs(t) || RightInputIs(t); }

  bool BothInputsAre(Type t) { return LeftInputIs(t) && RightInputIs(t); }

  bool BothInputsMaybe(Type t) {
    return left_type().Maybe(t) && right_type().Maybe(t);
  }

  bool OneInputCannotBe(Type t) {
    return !left_type().Maybe(t) || !right_type().Maybe(t);
  }

  bool NeitherInputCanBe(Type t) {
    return !left_type().Maybe(t) && !right_type().Maybe(t);
  }

  BinaryOperationHint GetBinaryOperationHint(Node* node) const {
    const FeedbackParameter& p = FeedbackParameterOf(node->op());
    return lowering_->broker()->GetFeedbackForBinaryOperation(p.feedback());
  }

  Node* effect() { return NodeProperties::GetEffectInput(node_); }
  Node* control() { return NodeProperties::GetControlInput(node_); }
  Node* context() { return NodeProperties::GetContextInput(node_); }
  Node* left() { return NodeProperties::GetValueInput(node_, 0); }
  Node* right() { return NodeProperties::GetValueInput(node_, 1); }
  Type left_type() { return NodeProperties::GetType(node_->InputAt(0)); }
  Type right_type() { return NodeProperties::GetType(node_->InputAt(1)); }
  Type type() { return NodeProperties::GetType(node_); }

  SimplifiedOperatorBuilder* simplified() { return lowering_->simplified(); }
  Graph* graph() const { return lowering_->graph(); }
  JSGraph* jsgraph() { return lowering_->jsgraph(); }
  Isolate* isolate() { return jsgraph()->isolate(); }
  JSOperatorBuilder* javascript() { return lowering_->javascript(); }
  CommonOperatorBuilder* common() { return jsgraph()->common(); }
  Zone* zone() const { return graph()->zone(); }

 private:
  JSTypedLowering* lowering_;  // The containing lowering instance.
  Node* node_;                 // The original node.

  Node* ConvertPlainPrimitiveToNumber(Node* node) {
    DCHECK(NodeProperties::GetType(node).Is(Type::PlainPrimitive()));
    // Avoid inserting too many eager ToNumber() operations.
    Reduction const reduction = lowering_->ReduceJSToNumberInput(node);
    if (reduction.Changed()) return reduction.replacement();
    if (NodeProperties::GetType(node).Is(Type::Number())) {
      return node;
    }
    return graph()->NewNode(simplified()->PlainPrimitiveToNumber(), node);
  }

  Node* ConvertToUI32(Node* node, Signedness signedness) {
    // Avoid introducing too many eager NumberToXXnt32() operations.
    Type type = NodeProperties::GetType(node);
    if (signedness == kSigned) {
      if (!type.Is(Type::Signed32())) {
        node = graph()->NewNode(simplified()->NumberToInt32(), node);
      }
    } else {
      DCHECK_EQ(kUnsigned, signedness);
      if (!type.Is(Type::Unsigned32())) {
        node = graph()->NewNode(simplified()->NumberToUint32(), node);
      }
    }
    return node;
  }

  CompareOperationHint GetCompareOperationHint(Node* node) const {
    const FeedbackParameter& p = FeedbackParameterOf(node->op());
    return lowering_->broker()->GetFeedbackForCompareOperation(p.feedback());
  }

  void update_effect(Node* effect) {
    NodeProperties::ReplaceEffectInput(node_, effect);
  }
};


// TODO(turbofan): js-typed-lowering improvements possible
// - immediately put in type bounds for all new nodes
// - relax effects from generic but not-side-effecting operations

JSTypedLowering::JSTypedLowering(Editor* editor, JSGraph* jsgraph,
                                 JSHeapBroker* broker, Zone* zone)
    : AdvancedReducer(editor),
      jsgraph_(jsgraph),
      broker_(broker),
      empty_string_type_(
          Type::Constant(broker, broker->empty_string(), graph()->zone())),
      pointer_comparable_type_(
          Type::Union(Type::Union(Type::BooleanOrNullOrUndefined(),
                                  Type::Hole(), graph()->zone()),
                      Type::Union(Type::SymbolOrReceiver(), empty_string_type_,
                                  graph()->zone()),
                      graph()->zone())),
      type_cache_(TypeCache::Get()) {}

Reduction JSTypedLowering::ReduceJSBitwiseNot(Node* node) {
  Node* input = NodeProperties::GetValueInput(node, 0);
  Type input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::PlainPrimitive())) {
    // JSBitwiseNot(x) => NumberBitwiseXor(ToInt32(x), -1)
    const FeedbackParameter& p = FeedbackParameterOf(node->op());
    node->InsertInput(graph()->zone(), 1, jsgraph()->SmiConstant(-1));
    NodeProperties::ChangeOp(node, javascript()->BitwiseXor(p.feedback()));
    JSBinopReduction r(this, node);
    r.ConvertInputsToNumber();
    r.ConvertInputsToUI32(kSigned, kSigned);
    return r.ChangeToPureOperator(r.NumberOp(), Type::Signed32());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSDecrement(Node* node) {
  Node* input = NodeProperties::GetValueInput(node, 0);
  Type input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::PlainPrimitive())) {
    // JSDecrement(x) => NumberSubtract(ToNumber(x), 1)
    const FeedbackParameter& p = FeedbackParameterOf(node->op());
    node->InsertInput(graph()->zone(), 1, jsgraph()->OneConstant());
    NodeProperties::ChangeOp(node, javascript()->Subtract(p.feedback()));
    JSBinopReduction r(this, node);
    r.ConvertInputsToNumber();
    DCHECK_EQ(simplified()->NumberSubtract(), r.NumberOp());
    return r.ChangeToPureOperator(r.NumberOp(), Type::Number());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSIncrement(Node* node) {
  Node* input = NodeProperties::GetValueInput(node, 0);
  Type input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::PlainPrimitive())) {
    // JSIncrement(x) => NumberAdd(ToNumber(x), 1)
    const FeedbackParameter& p = FeedbackParameterOf(node->op());
    node->InsertInput(graph()->zone(), 1, jsgraph()->OneConstant());
    NodeProperties::ChangeOp(node, javascript()->Add(p.feedback()));
    JSBinopReduction r(this, node);
    r.ConvertInputsToNumber();
    DCHECK_EQ(simplified()->NumberAdd(), r.NumberOp());
    return r.ChangeToPureOperator(r.NumberOp(), Type::Number());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSNegate(Node* node) {
  Node* input = NodeProperties::GetValueInput(node, 0);
  Type input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::PlainPrimitive())) {
    // JSNegate(x) => NumberMultiply(ToNumber(x), -1)
    const FeedbackParameter& p = FeedbackParameterOf(node->op());
    node->InsertInput(graph()->zone(), 1, jsgraph()->SmiConstant(-1));
    NodeProperties::ChangeOp(node, javascript()->Multiply(p.feedback()));
    JSBinopReduction r(this, node);
    r.ConvertInputsToNumber();
    return r.ChangeToPureOperator(r.NumberOp(), Type::Number());
  }
  return NoChange();
}

Reduction JSTypedLowering::GenerateStringAddition(
    Node* node, Node* left, Node* right, Node* context, Node* frame_state,
    Node** effect, Node** control, bool should_create_cons_string) {
  // Compute the resulting length.
  Node* left_length = graph()->NewNode(simplified()->StringLength(), left);
  Node* right_length = graph()->NewNode(simplified()->StringLength(), right);
  Node* length =
      graph()->NewNode(simplified()->NumberAdd(), left_length, right_length);

  PropertyCellRef string_length_protector =
      MakeRef(broker(), factory()->string_length_protector());
  string_length_protector.CacheAsProtector(broker());

  if (string_length_protector.value(broker()).AsSmi() ==
      Protectors::kProtectorValid) {
    // We can just deoptimize if the {length} is out-of-bounds. Besides
    // generating a shorter code sequence than the version below, this
    // has the additional benefit of not holding on to the lazy {frame_state}
    // and thus potentially reduces the number of live ranges and allows for
    // more truncations.
    length = *effect = graph()->NewNode(
        simplified()->CheckBounds(FeedbackSource()), length,
        jsgraph()->ConstantNoHole(String::kMaxLength + 1), *effect, *control);
  } else {
    // Check if we would overflow the allowed maximum string length.
    Node* check =
        graph()->NewNode(simplified()->NumberLessThanOrEqual(), length,
                         jsgraph()->ConstantNoHole(String::kMaxLength));
    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kTrue), check, *control);
    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* efalse = *effect;
    {
      // Throw a RangeError in case of overflow.
      Node* vfalse = efalse = if_false = graph()->NewNode(
          javascript()->CallRuntime(Runtime::kThrowInvalidStringLength),
          context, frame_state, efalse, if_false);

      // Update potential {IfException} uses of {node} to point to the
      // %ThrowInvalidStringLength runtime call node instead.
      Node* on_exception = nullptr;
      if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
        NodeProperties::ReplaceControlInput(on_exception, vfalse);
        NodeProperties::ReplaceEffectInput(on_exception, efalse);
        if_false = graph()->NewNode(common()->IfSuccess(), vfalse);
        Revisit(on_exception);
      }

      // The above %ThrowInvalidStringLength runtime call is an unconditional
      // throw, making it impossible to return a successful completion in this
      // case. We simply connect the successful completion to the graph end.
      if_false = graph()->NewNode(common()->Throw(), efalse, if_false);
      MergeControlToEnd(graph(), common(), if_false);
    }
    *control = graph()->NewNode(common()->IfTrue(), branch);
    length = *effect =
        graph()->NewNode(common()->TypeGuard(type_cache_->kStringLengthType),
                         length, *effect, *control);
  }
  // TODO(bmeurer): Ideally this should always use StringConcat and decide to
  // optimize to NewConsString later during SimplifiedLowering, but for that
  // to work we need to know that it's safe to create a ConsString.
  Operator const* const op = should_create_cons_string
                                 ? simplified()->NewConsString()
                                 : simplified()->StringConcat();
  Node* value = graph()->NewNode(op, length, left, right);
  ReplaceWithValue(node, value, *effect, *control);
  return Replace(value);
}

Node* JSTypedLowering::UnwrapStringWrapper(Node* string_or_wrapper,
                                           Node** effect, Node** control) {
  Node* check =
      graph()->NewNode(simplified()->ObjectIsString(), string_or_wrapper);
  Node* branch = graph()->NewNode(common()->Branch(), check, *control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = *effect;
  Node* vtrue = string_or_wrapper;

  // We just checked that the value is a string.
  vtrue = etrue = graph()->NewNode(common()->TypeGuard(Type::String()), vtrue,
                                   etrue, if_true);

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = *effect;

  Node* vfalse = efalse = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSPrimitiveWrapperValue()),
      string_or_wrapper, *effect, *control);

  // The value read from a string wrapper is a string.
  vfalse = efalse = graph()->NewNode(common()->TypeGuard(Type::String()),
                                     vfalse, efalse, if_false);

  *control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  *effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, *control);

  return graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                          vtrue, vfalse, *control);
}

Reduction JSTypedLowering::ReduceJSAdd(Node* node) {
  JSBinopReduction r(this, node);
  if (r.BothInputsAre(Type::Number())) {
    // JSAdd(x:number, y:number) => NumberAdd(x, y)
    return r.ChangeToPureOperator(simplified()->NumberAdd(), Type::Number());
  }
  if (r.BothInputsAre(Type::PlainPrimitive()) &&
      r.NeitherInputCanBe(Type::StringOrReceiver())) {
    // JSAdd(x:-string, y:-string) => NumberAdd(ToNumber(x), ToNumber(y))
    r.ConvertInputsToNumber();
    return r.ChangeToPureOperator(simplified()->NumberAdd(), Type::Number());
  }

  // Strength-reduce if one input is already known to be a string.
  if (r.LeftInputIs(Type::String())) {
    // JSAdd(x:string, y) => JSAdd(x, JSToString(y))
    Reduction const reduction = ReduceJSToStringInput(r.right());
    if (reduction.Changed()) {
      NodeProperties::ReplaceValueInput(node, reduction.replacement(), 1);
    }
  } else if (r.RightInputIs(Type::String())) {
    // JSAdd(x, y:string) => JSAdd(JSToString(x), y)
    Reduction const reduction = ReduceJSToStringInput(r.left());
    if (reduction.Changed()) {
      NodeProperties::ReplaceValueInput(node, reduction.replacement(), 0);
    }
  }

  PropertyCellRef to_primitive_protector =
      MakeRef(broker(), factory()->string_wrapper_to_primitive_protector());
  to_primitive_protector.CacheAsProtector(broker());
  bool can_inline_string_wrapper_add = false;

  // Always bake in String feedback into the graph.
  if (r.GetBinaryOperationHint(node) == BinaryOperationHint::kString) {
    r.CheckInputsToString();
  } else if (r.GetBinaryOperationHint(node) ==
             BinaryOperationHint::kStringOrStringWrapper) {
    can_inline_string_wrapper_add =
        dependencies()->DependOnProtector(to_primitive_protector);
    if (can_inline_string_wrapper_add) {
      r.CheckInputsToStringOrStringWrapper();
    }
  }

  // Strength-reduce concatenation of empty strings if both sides are
  // primitives, as in that case the ToPrimitive on the other side is
  // definitely going to be a no-op.
  if (r.BothInputsAre(Type::Primitive())) {
    if (r.LeftInputIs(empty_string_type_)) {
      // JSAdd("", x:primitive) => JSToString(x)
      NodeProperties::ReplaceValueInputs(node, r.right());
      NodeProperties::ChangeOp(node, javascript()->ToString());
      NodeProperties::SetType(
          node, Type::Intersect(r.type(), Type::String(), graph()->zone()));
      return Changed(node).FollowedBy(ReduceJSToString(node));
    } else if (r.RightInputIs(empty_string_type_)) {
      // JSAdd(x:primitive, "") => JSToString(x)
      NodeProperties::ReplaceValueInputs(node, r.left());
      NodeProperties::ChangeOp(node, javascript()->ToString());
      NodeProperties::SetType(
          node, Type::Intersect(r.type(), Type::String(), graph()->zone()));
      return Changed(node).FollowedBy(ReduceJSToString(node));
    }
  }

  Node* context = NodeProperties::GetContextInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Lower to string addition if both inputs are known to be strings.
  if (r.BothInputsAre(Type::String())) {
    return GenerateStringAddition(node, r.left(), r.right(), context,
                                  frame_state, &effect, &control,
                                  r.ShouldCreateConsString());
  } else if (r.BothInputsAre(Type::StringOrStringWrapper()) &&
             can_inline_string_wrapper_add) {
    // If the left hand side is a string wrapper, unwrap it.
    Node* left_string = UnwrapStringWrapper(r.left(), &effect, &control);

    // If the right hand side is a string wrapper, unwrap it.
    Node* right_string = UnwrapStringWrapper(r.right(), &effect, &control);

    // Generate the string addition.
    return GenerateStringAddition(node, left_string, right_string, context,
                                  frame_state, &effect, &control, false);
  }

  // We never get here when we had String feedback.
  DCHECK_NE(BinaryOperationHint::kString, r.GetBinaryOperationHint(node));
  if (r.OneInputIs(Type::String())) {
    StringAddFlags flags = STRING_ADD_CHECK_NONE;
    if (!r.LeftInputIs(Type::String())) {
      flags = STRING_ADD_CONVERT_LEFT;
    } else if (!r.RightInputIs(Type::String())) {
      flags = STRING_ADD_CONVERT_RIGHT;
    }
    Operator::Properties properties = node->op()->properties();
    if (r.NeitherInputCanBe(Type::Receiver())) {
      // Both sides are already strings, so we know that the
      // string addition will not cause any observable side
      // effects; it can still throw obviously.
      properties = Operator::kNoWrite | Operator::kNoDeopt;
    }

    // JSAdd(x:string, y) => CallStub[StringAdd](x, y)
    // JSAdd(x, y:string) => CallStub[StringAdd](x, y)
    Callable const callable = CodeFactory::StringAdd(isolate(), flags);
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(),
        CallDescriptor::kNeedsFrameState, properties);
    DCHECK_EQ(1, OperatorProperties::GetFrameStateInputCount(node->op()));
    node->RemoveInput(JSAddNode::FeedbackVectorIndex());
    node->InsertInput(graph()->zone(), 0,
                      jsgraph()->HeapConstantNoHole(callable.code()));
    NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
    return Changed(node);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceNumberBinop(Node* node) {
  JSBinopReduction r(this, node);
  if (r.BothInputsAre(Type::PlainPrimitive())) {
    r.ConvertInputsToNumber();
    return r.ChangeToPureOperator(r.NumberOp(), Type::Number());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceInt32Binop(Node* node) {
  JSBinopReduction r(this, node);
  if (r.BothInputsAre(Type::PlainPrimitive())) {
    r.ConvertInputsToNumber();
    r.ConvertInputsToUI32(kSigned, kSigned);
    return r.ChangeToPureOperator(r.NumberOp(), Type::Signed32());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceUI32Shift(Node* node, Signedness signedness) {
  JSBinopReduction r(this, node);
  if (r.BothInputsAre(Type::PlainPrimitive())) {
    r.ConvertInputsToNumber();
    r.ConvertInputsToUI32(signedness, kUnsigned);
    return r.ChangeToPureOperator(r.NumberOp(), signedness == kUnsigned
                                                    ? Type::Unsigned32()
                                                    : Type::Signed32());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSComparison(Node* node) {
  JSBinopReduction r(this, node);
  if (r.BothInputsAre(Type::String())) {
    // If both inputs are definitely strings, perform a string comparison.
    const Operator* stringOp;
    switch (node->opcode()) {
      case IrOpcode::kJSLessThan:
        stringOp = simplified()->StringLessThan();
        break;
      case IrOpcode::kJSGreaterThan:
        stringOp = simplified()->StringLessThan();
        r.SwapInputs();  // a > b => b < a
        break;
      case IrOpcode::kJSLessThanOrEqual:
        stringOp = simplified()->StringLessThanOrEqual();
        break;
      case IrOpcode::kJSGreaterThanOrEqual:
        stringOp = simplified()->StringLessThanOrEqual();
        r.SwapInputs();  // a >= b => b <= a
        break;
      default:
        return NoChange();
    }
    r.ChangeToPureOperator(stringOp);
    return Changed(node);
  }

  const Operator* less_than;
  const Operator* less_than_or_equal;
  if (r.BothInputsAre(Type::Signed32()) ||
      r.BothInputsAre(Type::Unsigned32())) {
    less_than = simplified()->NumberLessThan();
    less_than_or_equal = simplified()->NumberLessThanOrEqual();
  } else if (r.OneInputCannotBe(Type::StringOrReceiver()) &&
             r.BothInputsAre(Type::PlainPrimitive())) {
    r.ConvertInputsToNumber();
    less_than = simplified()->NumberLessThan();
    less_than_or_equal = simplified()->NumberLessThanOrEqual();
  } else if (r.IsStringCompareOperation()) {
    r.CheckInputsToString();
    less_than = simplified()->StringLessThan();
    less_than_or_equal = simplified()->StringLessThanOrEqual();
  } else {
    return NoChange();
  }
  const Operator* comparison;
  switch (node->opcode()) {
    case IrOpcode::kJSLessThan:
      comparison = less_than;
      break;
    case IrOpcode::kJSGreaterThan:
      comparison = less_than;
      r.SwapInputs();  // a > b => b < a
      break;
    case IrOpcode::kJSLessThanOrEqual:
      comparison = less_than_or_equal;
      break;
    case IrOpcode::kJSGreaterThanOrEqual:
      comparison = less_than_or_equal;
      r.SwapInputs();  // a >= b => b <= a
      break;
    default:
      return NoChange();
  }
  return r.ChangeToPureOperator(comparison);
}

Reduction JSTypedLowering::ReduceJSEqual(Node* node) {
  JSBinopReduction r(this, node);

  if (r.BothInputsAre(Type::UniqueName())) {
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.IsInternalizedStringCompareOperation()) {
    r.CheckInputsToInternalizedString();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.BothInputsAre(Type::String())) {
    return r.ChangeToPureOperator(simplified()->StringEqual());
  }
  if (r.BothInputsAre(Type::Boolean())) {
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.BothInputsAre(Type::Receiver())) {
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.OneInputIs(Type::NullOrUndefined())) {
    RelaxEffectsAndControls(node);
    node->RemoveInput(r.LeftInputIs(Type::NullOrUndefined()) ? 0 : 1);
    node->TrimInputCount(1);
    NodeProperties::ChangeOp(node, simplified()->ObjectIsUndetectable());
    return Changed(node);
  }

  if (r.BothInputsAre(Type::Signed32()) ||
      r.BothInputsAre(Type::Unsigned32())) {
    return r.ChangeToPureOperator(simplified()->NumberEqual());
  } else if (r.BothInputsAre(Type::Number())) {
    return r.ChangeToPureOperator(simplified()->NumberEqual());
  } else if (r.IsReceiverCompareOperation()) {
    r.CheckInputsToReceiver();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  } else if (r.IsReceiverOrNullOrUndefinedCompareOperation()) {
    // Check that both inputs are Receiver, Null or Undefined.
    r.CheckInputsToReceiverOrNullOrUndefined();

    // If one side is known to be a detectable receiver now, we
    // can simply perform reference equality here, since this
    // known detectable receiver is going to only match itself.
    if (r.OneInputIs(Type::DetectableReceiver())) {
      return r.ChangeToPureOperator(simplified()->ReferenceEqual());
    }

    // Known that both sides are Receiver, Null or Undefined, the
    // abstract equality operation can be performed like this:
    //
    // if left == undefined || left == null
    //    then ObjectIsUndetectable(right)
    // else if right == undefined || right == null
    //    then ObjectIsUndetectable(left)
    // else ReferenceEqual(left, right)
#define __ gasm.
    JSGraphAssembler gasm(broker(), jsgraph(), jsgraph()->zone(),
                          BranchSemantics::kJS);
    gasm.InitializeEffectControl(r.effect(), r.control());

    auto lhs = TNode<Object>::UncheckedCast(r.left());
    auto rhs = TNode<Object>::UncheckedCast(r.right());

    auto done = __ MakeLabel(MachineRepresentation::kTagged);
    auto check_undetectable = __ MakeLabel(MachineRepresentation::kTagged);

    __ GotoIf(__ ReferenceEqual(lhs, __ UndefinedConstant()),
              &check_undetectable, rhs);
    __ GotoIf(__ ReferenceEqual(lhs, __ NullConstant()), &check_undetectable,
              rhs);
    __ GotoIf(__ ReferenceEqual(rhs, __ UndefinedConstant()),
              &check_undetectable, lhs);
    __ GotoIf(__ ReferenceEqual(rhs, __ NullConstant()), &check_undetectable,
              lhs);
    __ Goto(&done, __ ReferenceEqual(lhs, rhs));

    __ Bind(&check_undetectable);
    __ Goto(&done,
            __ ObjectIsUndetectable(check_undetectable.PhiAt<Object>(0)));

    __ Bind(&done);
    Node* value = done.PhiAt(0);
    ReplaceWithValue(node, value, gasm.effect(), gasm.control());
    return Replace(value);
#undef __
  } else if (r.IsStringCompareOperation()) {
    r.CheckInputsToString();
    return r.ChangeToPureOperator(simplified()->StringEqual());
  } else if (r.IsSymbolCompareOperation()) {
    r.CheckInputsToSymbol();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSStrictEqual(Node* node) {
  JSBinopReduction r(this, node);
  if (r.type().IsSingleton()) {
    // Let ConstantFoldingReducer handle this.
    return NoChange();
  }
  if (r.left() == r.right()) {
    // x === x is always true if x != NaN
    Node* replacement = graph()->NewNode(
        simplified()->BooleanNot(),
        graph()->NewNode(simplified()->ObjectIsNaN(), r.left()));
    DCHECK(NodeProperties::GetType(replacement).Is(r.type()));
    ReplaceWithValue(node, replacement);
    return Replace(replacement);
  }

  if (r.BothInputsAre(Type::Unique())) {
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.OneInputIs(pointer_comparable_type_)) {
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.IsInternalizedStringCompareOperation()) {
    r.CheckInputsToInternalizedString();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  if (r.BothInputsAre(Type::String())) {
    return r.ChangeToPureOperator(simplified()->StringEqual());
  }

  NumberOperationHint hint;
  BigIntOperationHint hint_bigint;
  if (r.BothInputsAre(Type::Signed32()) ||
      r.BothInputsAre(Type::Unsigned32())) {
    return r.ChangeToPureOperator(simplified()->NumberEqual());
  } else if (r.GetCompareNumberOperationHint(&hint) &&
             hint != NumberOperationHint::kNumberOrOddball &&
             hint != NumberOperationHint::kNumberOrBoolean) {
    // SpeculativeNumberEqual performs implicit conversion of oddballs to
    // numbers, so me must not generate it for strict equality with respective
    // hint.
    DCHECK(hint == NumberOperationHint::kNumber ||
           hint == NumberOperationHint::kSignedSmall);
    return r.ChangeToSpeculativeOperator(
        simplified()->SpeculativeNumberEqual(hint), Type::Boolean());
  } else if (r.BothInputsAre(Type::Number())) {
    return r.ChangeToPureOperator(simplified()->NumberEqual());
  } else if (r.GetCompareBigIntOperationHint(&hint_bigint)) {
    DCHECK(hint_bigint == BigIntOperationHint::kBigInt ||
           hint_bigint == BigIntOperationHint::kBigInt64);
    return r.ChangeToSpeculativeOperator(
        simplified()->SpeculativeBigIntEqual(hint_bigint), Type::Boolean());
  } else if (r.IsReceiverCompareOperation()) {
    // For strict equality, it's enough to know that one input is a Receiver,
    // as a strict equality comparison with a Receiver can only yield true if
    // both sides refer to the same Receiver.
    r.CheckLeftInputToReceiver();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  } else if (r.IsReceiverOrNullOrUndefinedCompareOperation()) {
    // For strict equality, it's enough to know that one input is a Receiver,
    // Null or Undefined, as a strict equality comparison with a Receiver,
    // Null or Undefined can only yield true if both sides refer to the same
    // instance.
    r.CheckLeftInputToReceiverOrNullOrUndefined();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  } else if (r.IsStringCompareOperation()) {
    r.CheckInputsToString();
    return r.ChangeToPureOperator(simplified()->StringEqual());
  } else if (r.IsSymbolCompareOperation()) {
    // For strict equality, it's enough to know that one input is a Symbol,
    // as a strict equality comparison with a Symbol can only yield true if
    // both sides refer to the same Symbol.
    r.CheckLeftInputToSymbol();
    return r.ChangeToPureOperator(simplified()->ReferenceEqual());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToName(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::Name())) {
    // JSToName(x:name) => x
    ReplaceWithValue(node, input);
    return Replace(input);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToLength(Node* node) {
  Node* input = NodeProperties::GetValueInput(node, 0);
  Type input_type = NodeProperties::GetType(input);
  if (input_type.Is(type_cache_->kIntegerOrMinusZero)) {
    if (input_type.IsNone() || input_type.Max() <= 0.0) {
      input = jsgraph()->ZeroConstant();
    } else if (input_type.Min() >= kMaxSafeInteger) {
      input = jsgraph()->ConstantNoHole(kMaxSafeInteger);
    } else {
      if (input_type.Min() <= 0.0) {
        input = graph()->NewNode(simplified()->NumberMax(),
                                 jsgraph()->ZeroConstant(), input);
      }
      if (input_type.Max() > kMaxSafeInteger) {
        input =
            graph()->NewNode(simplified()->NumberMin(),
                             jsgraph()->ConstantNoHole(kMaxSafeInteger), input);
      }
    }
    ReplaceWithValue(node, input);
    return Replace(input);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToNumberInput(Node* input) {
  // Try constant-folding of JSToNumber with constant inputs.
  Type input_type = NodeProperties::GetType(input);

  if (input_type.Is(Type::String())) {
    HeapObjectMatcher m(input);
    if (m.HasResolvedValue() && m.Ref(broker()).IsString()) {
      StringRef input_value = m.Ref(broker()).AsString();
      std::optional<double> number = input_value.ToNumber(broker());
      if (!number.has_value()) return NoChange();
      return Replace(jsgraph()->ConstantNoHole(number.value()));
    }
  }
  if (input_type.IsHeapConstant()) {
    HeapObjectRef input_value = input_type.AsHeapConstant()->Ref();
    double value;
    if (input_value.OddballToNumber(broker()).To(&value)) {
      return Replace(jsgraph()->ConstantNoHole(value));
    }
  }
  if (input_type.Is(Type::Number())) {
    // JSToNumber(x:number) => x
    return Changed(input);
  }
  if (input_type.Is(Type::Undefined())) {
    // JSToNumber(undefined) => #NaN
    return Replace(jsgraph()->NaNConstant());
  }
  if (input_type.Is(Type::Null())) {
    // JSToNumber(null) => #0
    return Replace(jsgraph()->ZeroConstant());
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToNumber(Node* node) {
  // Try to reduce the input first.
  Node* const input = node->InputAt(0);
  Reduction reduction = ReduceJSToNumberInput(input);
  if (reduction.Changed()) {
    ReplaceWithValue(node, reduction.replacement());
    return reduction;
  }
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::PlainPrimitive())) {
    RelaxEffectsAndControls(node);
    node->TrimInputCount(1);
    // For a PlainPrimitive, ToNumeric is the same as ToNumber.
    Type node_type = NodeProperties::GetType(node);
    NodeProperties::SetType(
        node, Type::Intersect(node_type, Type::Number(), graph()->zone()));
    NodeProperties::ChangeOp(node, simplified()->PlainPrimitiveToNumber());
    return Changed(node);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToBigInt(Node* node) {
  // TODO(panq): Reduce constant inputs.
  Node* const input = node->InputAt(0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::BigInt())) {
    ReplaceWithValue(node, input);
    return Changed(input);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToBigIntConvertNumber(Node* node) {
  // TODO(panq): Reduce constant inputs.
  Node* const input = node->InputAt(0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::BigInt())) {
    ReplaceWithValue(node, input);
    return Changed(input);
  } else if (input_type.Is(Type::Signed32OrMinusZero()) ||
             input_type.Is(Type::Unsigned32OrMinusZero())) {
    RelaxEffectsAndControls(node);
    node->TrimInputCount(1);
    Type node_type = NodeProperties::GetType(node);
    NodeProperties::SetType(
        node,
        Type::Intersect(node_type, Type::SignedBigInt64(), graph()->zone()));
    NodeProperties::ChangeOp(node,
                             simplified()->Integral32OrMinusZeroToBigInt());
    return Changed(node);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToNumeric(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::NonBigIntPrimitive())) {
    // ToNumeric(x:primitive\bigint) => ToNumber(x)
    NodeProperties::ChangeOp(node, javascript()->ToNumber());
    Type node_type = NodeProperties::GetType(node);
    NodeProperties::SetType(
        node, Type::Intersect(node_type, Type::Number(), graph()->zone()));
    return Changed(node).FollowedBy(ReduceJSToNumber(node));
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToStringInput(Node* input) {
  if (input->opcode() == IrOpcode::kJSToString) {
    // Recursively try to reduce the input first.
    Reduction result = ReduceJSToString(input);
    if (result.Changed()) return result;
    return Changed(input);  // JSToString(JSToString(x)) => JSToString(x)
  }
  Type input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::String())) {
    return Changed(input);  // JSToString(x:string) => x
  }
  if (input_type.Is(Type::Boolean())) {
    return Replace(graph()->NewNode(
        common()->Select(MachineRepresentation::kTagged), input,
        jsgraph()->HeapConstantNoHole(factory()->true_string()),
        jsgraph()->HeapConstantNoHole(factory()->false_string())));
  }
  if (input_type.Is(Type::Undefined())) {
    return Replace(
        jsgraph()->HeapConstantNoHole(factory()->undefined_string()));
  }
  if (input_type.Is(Type::Null())) {
    return Replace(jsgraph()->HeapConstantNoHole(factory()->null_string()));
  }
  if (input_type.Is(Type::NaN())) {
    return Replace(jsgraph()->HeapConstantNoHole(factory()->NaN_string()));
  }
  if (input_type.Is(Type::Number())) {
    return Replace(graph()->NewNode(simplified()->NumberToString(), input));
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToString(Node* node) {
  DCHECK_EQ(IrOpcode::kJSToString, node->opcode());
  // Try to reduce the input first.
  Node* const input = node->InputAt(0);
  Reduction reduction = ReduceJSToStringInput(input);
  if (reduction.Changed()) {
    ReplaceWithValue(node, reduction.replacement());
    return reduction;
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSToObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSToObject, node->opcode());
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  Type receiver_type = NodeProperties::GetType(receiver);
  Node* context = NodeProperties::GetContextInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  if (receiver_type.Is(Type::Receiver())) {
    ReplaceWithValue(node, receiver, effect, control);
    return Replace(receiver);
  }

  // Check whether {receiver} is a spec object.
  Node* check = graph()->NewNode(simplified()->ObjectIsReceiver(), receiver);
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;
  Node* rtrue = receiver;

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;
  Node* rfalse;
  {
    // Convert {receiver} using the ToObjectStub.
    Callable callable = Builtins::CallableFor(isolate(), Builtin::kToObject);
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(),
        CallDescriptor::kNeedsFrameState, node->op()->properties());
    Node* call = rfalse = efalse = if_false =
        graph()->NewNode(common()->Call(call_descriptor),
                         jsgraph()->HeapConstantNoHole(callable.code()),
                         receiver, context, frame_state, efalse, if_false);

    // We preserve the type of {node}. This is generally useful (to  enable
    // type-based optimizations), and is also required in order to help
    // verification of TypeGuards.
    NodeProperties::SetType(call, NodeProperties::GetType(node));
  }

  // Update potential {IfException} uses of {node} to point to the above
  // ToObject stub call node instead. Note that the stub can only throw on
  // receivers that can be null or undefined.
  Node* on_exception = nullptr;
  if (receiver_type.Maybe(Type::NullOrUndefined()) &&
      NodeProperties::IsExceptionalCall(node, &on_exception)) {
    NodeProperties::ReplaceControlInput(on_exception, if_false);
    NodeProperties::ReplaceEffectInput(on_exception, efalse);
    if_false = graph()->NewNode(common()->IfSuccess(), if_false);
    Revisit(on_exception);
  }

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);

  // Morph the {node} into an appropriate Phi.
  ReplaceWithValue(node, node, effect, control);
  node->ReplaceInput(0, rtrue);
  node->ReplaceInput(1, rfalse);
  node->ReplaceInput(2, control);
  node->TrimInputCount(3);
  NodeProperties::ChangeOp(node,
                           common()->Phi(MachineRepresentation::kTagged, 2));
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSLoadNamed(Node* node) {
  JSLoadNamedNode n(node);
  Node* receiver = n.object();
  Type receiver_type = NodeProperties::GetType(receiver);
  NameRef name = NamedAccessOf(node->op()).name();
  NameRef length_str = broker()->length_string();
  // Optimize "length" property of strings.
  if (name.equals(length_str) && receiver_type.Is(Type::String())) {
    Node* value = graph()->NewNode(simplified()->StringLength(), receiver);
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSHasInPrototypeChain(Node* node) {
  DCHECK_EQ(IrOpcode::kJSHasInPrototypeChain, node->opcode());
  Node* value = NodeProperties::GetValueInput(node, 0);
  Type value_type = NodeProperties::GetType(value);
  Node* prototype = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // If {value} cannot be a receiver, then it cannot have {prototype} in
  // it's prototype chain (all Primitive values have a null prototype).
  if (value_type.Is(Type::Primitive())) {
    value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  }

  Node* check0 = graph()->NewNode(simplified()->ObjectIsSmi(), value);
  Node* branch0 =
      graph()->NewNode(common()->Branch(BranchHint::kFalse), check0, control);

  Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
  Node* etrue0 = effect;
  Node* vtrue0 = jsgraph()->FalseConstant();

  control = graph()->NewNode(common()->IfFalse(), branch0);

  // Loop through the {value}s prototype chain looking for the {prototype}.
  Node* loop = control = graph()->NewNode(common()->Loop(2), control, control);
  Node* eloop = effect =
      graph()->NewNode(common()->EffectPhi(2), effect, effect, loop);
  Node* terminate = graph()->NewNode(common()->Terminate(), eloop, loop);
  MergeControlToEnd(graph(), common(), terminate);
  Node* vloop = value = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), value, value, loop);
  NodeProperties::SetType(vloop, Type::NonInternal());

  // Load the {value} map and instance type.
  Node* value_map = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMap()), value, effect, control);
  Node* value_instance_type = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapInstanceType()), value_map,
      effect, control);

  // Check if the {value} is a special receiver, because for special
  // receivers, i.e. proxies or API values that need access checks,
  // we have to use the %HasInPrototypeChain runtime function instead.
  Node* check1 = graph()->NewNode(
      simplified()->NumberLessThanOrEqual(), value_instance_type,
      jsgraph()->ConstantNoHole(LAST_SPECIAL_RECEIVER_TYPE));
  Node* branch1 =
      graph()->NewNode(common()->Branch(BranchHint::kFalse), check1, control);

  control = graph()->NewNode(common()->IfFalse(), branch1);

  Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
  Node* etrue1 = effect;
  Node* vtrue1;

  // Check if the {value} is not a receiver at all.
  Node* check10 =
      graph()->NewNode(simplified()->NumberLessThan(), value_instance_type,
                       jsgraph()->ConstantNoHole(FIRST_JS_RECEIVER_TYPE));
  Node* branch10 =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check10, if_true1);

  // A primitive value cannot match the {prototype} we're looking for.
  if_true1 = graph()->NewNode(common()->IfTrue(), branch10);
  vtrue1 = jsgraph()->FalseConstant();

  Node* if_false1 = graph()->NewNode(common()->IfFalse(), branch10);
  Node* efalse1 = etrue1;
  Node* vfalse1;
  {
    // Slow path, need to call the %HasInPrototypeChain runtime function.
    vfalse1 = efalse1 = if_false1 = graph()->NewNode(
        javascript()->CallRuntime(Runtime::kHasInPrototypeChain), value,
        prototype, context, frame_state, efalse1, if_false1);

    // Replace any potential {IfException} uses of {node} to catch
    // exceptions from this %HasInPrototypeChain runtime call instead.
    Node* on_exception = nullptr;
    if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
      NodeProperties::ReplaceControlInput(on_exception, vfalse1);
      NodeProperties::ReplaceEffectInput(on_exception, efalse1);
      if_false1 = graph()->NewNode(common()->IfSuccess(), vfalse1);
      Revisit(on_exception);
    }
  }

  // Load the {value} prototype.
  Node* value_prototype = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapPrototype()), value_map,
      effect, control);

  // Check if we reached the end of {value}s prototype chain.
  Node* check2 = graph()->NewNode(simplified()->ReferenceEqual(),
                                  value_prototype, jsgraph()->NullConstant());
  Node* branch2 = graph()->NewNode(common()->Branch(), check2, control);

  Node* if_true2 = graph()->NewNode(common()->IfTrue(), branch2);
  Node* etrue2 = effect;
  Node* vtrue2 = jsgraph()->FalseConstant();

  control = graph()->NewNode(common()->IfFalse(), branch2);

  // Check if we reached the {prototype}.
  Node* check3 = graph()->NewNode(simplified()->ReferenceEqual(),
                                  value_prototype, prototype);
  Node* branch3 = graph()->NewNode(common()->Branch(), check3, control);

  Node* if_true3 = graph()->NewNode(common()->IfTrue(), branch3);
  Node* etrue3 = effect;
  Node* vtrue3 = jsgraph()->TrueConstant();

  control = graph()->NewNode(common()->IfFalse(), branch3);

  // Close the loop.
  vloop->ReplaceInput(1, value_prototype);
  eloop->ReplaceInput(1, effect);
  loop->ReplaceInput(1, control);

  control = graph()->NewNode(common()->Merge(5), if_true0, if_true1, if_true2,
                             if_true3, if_false1);
  effect = graph()->NewNode(common()->EffectPhi(5), etrue0, etrue1, etrue2,
                            etrue3, efalse1, control);

  // Morph the {node} into an appropriate Phi.
  ReplaceWithValue(node, node, effect, control);
  node->ReplaceInput(0, vtrue0);
  node->ReplaceInput(1, vtrue1);
  node->ReplaceInput(2, vtrue2);
  node->ReplaceInput(3, vtrue3);
  node->ReplaceInput(4, vfalse1);
  node->ReplaceInput(5, control);
  node->TrimInputCount(6);
  NodeProperties::ChangeOp(node,
                           common()->Phi(MachineRepresentation::kTagged, 5));
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSOrdinaryHasInstance(Node* node) {
  DCHECK_EQ(IrOpcode::kJSOrdinaryHasInstance, node->opcode());
  Node* constructor = NodeProperties::GetValueInput(node, 0);
  Type constructor_type = NodeProperties::GetType(constructor);
  Node* object = NodeProperties::GetValueInput(node, 1);
  Type object_type = NodeProperties::GetType(object);

  // Check if the {constructor} cannot be callable.
  // See ES6 section 7.3.19 OrdinaryHasInstance ( C, O ) step 1.
  if (!constructor_type.Maybe(Type::Callable())) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  // If the {constructor} cannot be a JSBoundFunction and then {object}
  // cannot be a JSReceiver, then this can be constant-folded to false.
  // See ES6 section 7.3.19 OrdinaryHasInstance ( C, O ) step 2 and 3.
  if (!object_type.Maybe(Type::Receiver()) &&
      !constructor_type.Maybe(Type::BoundFunction())) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  return NoChange();
}

Reduction JSTypedLowering::ReduceJSHasContextExtension(Node* node) {
  DCHECK_EQ(IrOpcode::kJSHasContextExtension, node->opcode());
  size_t depth = OpParameter<size_t>(node->op());
  Node* effect = NodeProperties::GetEffectInput(node);
  TNode<Context> context =
      TNode<Context>::UncheckedCast(NodeProperties::GetContextInput(node));
  Node* control = graph()->start();

  JSGraphAssembler gasm(broker(), jsgraph_, jsgraph_->zone(),
                        BranchSemantics::kJS);
  gasm.InitializeEffectControl(effect, control);

  for (size_t i = 0; i < depth; ++i) {
#if DEBUG
    // Const tracking let data is stored in the extension slot of a
    // ScriptContext - however, it's unrelated to the sloppy eval variable
    // extension. We should never iterate through a ScriptContext here.

    TNode<ScopeInfo> scope_info = gasm.LoadField<ScopeInfo>(
        AccessBuilder::ForContextSlot(Context::SCOPE_INFO_INDEX), context);
    TNode<Word32T> scope_info_flags = gasm.EnterMachineGraph<Word32T>(
        gasm.LoadField<Word32T>(AccessBuilder::ForScopeInfoFlags(), scope_info),
        UseInfo::TruncatingWord32());
    TNode<Word32T> scope_type = gasm.Word32And(
        scope_info_flags, gasm.Uint32Constant(ScopeInfo::ScopeTypeBits::kMask));
    TNode<Word32T> is_script_scope = gasm.Word32Equal(
        scope_type, gasm.Uint32Constant(ScopeType::SCRIPT_SCOPE));
    TNode<Word32T> is_not_script_scope =
        gasm.Word32Equal(is_script_scope, gasm.Uint32Constant(0));
    gasm.Assert(is_not_script_scope, "we should no see a ScriptContext here",
                __FILE__, __LINE__);
#endif

    context = gasm.LoadField<Context>(
        AccessBuilder::ForContextSlotKnownPointer(Context::PREVIOUS_INDEX),
        context);
  }
  TNode<ScopeInfo> scope_info = gasm.LoadField<ScopeInfo>(
      AccessBuilder::ForContextSlot(Context::SCOPE_INFO_INDEX), context);
  TNode<Word32T> scope_info_flags = gasm.EnterMachineGraph<Word32T>(
      gasm.LoadField<Word32T>(AccessBuilder::ForScopeInfoFlags(), scope_info),
      UseInfo::TruncatingWord32());
  TNode<Word32T> flags_masked = gasm.Word32And(
      scope_info_flags,
      gasm.Uint32Constant(ScopeInfo::HasContextExtensionSlotBit::kMask));
  TNode<Word32T> no_extension =
      gasm.Word32Equal(flags_masked, gasm.Uint32Constant(0));
  TNode<Word32T> has_extension =
      gasm.Word32Equal(no_extension, gasm.Uint32Constant(0));
  TNode<Boolean> has_extension_boolean = gasm.ExitMachineGraph<Boolean>(
      has_extension, MachineRepresentation::kBit, Type::Boolean());

  ReplaceWithValue(node, has_extension_boolean, gasm.effect(), gasm.control());
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSLoadContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSLoadContext, node->opcode());
  ContextAccess const& access = ContextAccessOf(node->op());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* context = NodeProperties::GetContextInput(node);
  Node* control = graph()->start();
  for (size_t i = 0; i < access.depth(); ++i) {
    context = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForContextSlotKnownPointer(Context::PREVIOUS_INDEX)),
        context, effect, control);
  }
  node->ReplaceInput(0, context);
  node->ReplaceInput(1, effect);
  node->AppendInput(jsgraph()->zone(), control);
  NodeProperties::ChangeOp(
      node,
      simplified()->LoadField(AccessBuilder::ForContextSlot(access.index())));
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSLoadScriptContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSLoadScriptContext, node->opcode());
  ContextAccess const& access = ContextAccessOf(node->op());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  JSGraphAssembler gasm(broker(), jsgraph(), jsgraph()->zone(),
                        BranchSemantics::kJS);
  gasm.InitializeEffectControl(effect, control);

  TNode<Context> context =
      TNode<Context>::UncheckedCast(NodeProperties::GetContextInput(node));
  for (size_t i = 0; i < access.depth(); ++i) {
    context = gasm.LoadField<Context>(
        AccessBuilder::ForContextSlotKnownPointer(Context::PREVIOUS_INDEX),
        con
```