Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Function:** The code is in `v8/src/compiler/js-typed-lowering.cc`. The name "typed-lowering" suggests it's a compiler optimization pass that refines JavaScript operations into more specific, lower-level operations based on type information.

2. **Analyze the `JSBinopReduction` Class:** This class seems to be a helper for simplifying binary operations. Key observations:
    * It takes a `JSTypedLowering` instance and a `Node` (likely from the compiler's intermediate representation).
    * It has methods like `GetCompareNumberOperationHint`, `IsStringCompareOperation`, `CheckInputsToString`, `ConvertInputsToNumber`, and `ChangeToPureOperator`. These indicate that it's involved in analyzing the types of operands and transforming binary operations.
    * It deals with inserting type checks (`CheckReceiver`, `CheckString`, etc.) and type conversions (`ConvertInputsToNumber`).
    * The `ChangeToPureOperator` method suggests replacing high-level JS operations with simpler, type-specific ones.

3. **Analyze the `JSTypedLowering` Class:**
    * It inherits from `AdvancedReducer`, a compiler optimization base class in V8.
    * It has methods like `ReduceJSBitwiseNot`, `ReduceJSDecrement`, `ReduceJSIncrement`, `ReduceJSNegate`, and `ReduceJSAdd`. These suggest it handles the lowering of specific JavaScript operators.
    * The `ReduceJSAdd` function seems particularly complex, dealing with string concatenation and numeric addition.
    * It uses `JSHeapBroker` to access information about the JavaScript heap and `TypeCache` for type information.
    * The code mentions deoptimization and protectors, indicating it handles cases where assumptions about types might be invalid.

4. **Connect the Classes and Functionality:** The `JSBinopReduction` class is used within the `JSTypedLowering` methods to handle the details of lowering binary operations. For example, `ReduceJSAdd` uses `JSBinopReduction` to perform type checks and conversions.

5. **Infer Overall Purpose:** Based on the above, the core functionality is to optimize JavaScript code during compilation by leveraging type information. It aims to replace generic JavaScript operators with more efficient, type-specific lower-level operations. This improves performance.

6. **Address Specific Instructions:**
    * **File Extension:**  The user provided a rule about `.tq` files. This is irrelevant since the given file ends in `.cc`.
    * **Relationship to JavaScript:**  This is a crucial part. The lowering process directly transforms JavaScript operations. Examples should demonstrate how a high-level JS operation gets translated to a more specific, potentially lower-level operation based on type. Focus on simple examples like `+` with numbers and strings.
    * **Code Logic Inference (Hypothetical Input/Output):** Choose a simple case like `a + b` where both `a` and `b` are known to be numbers. Show how the `JSAdd` operation might be replaced by `NumberAdd`. Similarly, show the string concatenation case.
    * **Common Programming Errors:**  Think about errors related to type mismatches that this lowering process might encounter or try to handle. Concatenating a number and a string is a classic example.
    * **Overall Summary:**  Combine the individual observations into a concise summary of the file's role in the V8 compilation pipeline.

7. **Structure the Answer:**  Organize the findings into logical sections based on the user's request (functionality, file extension, JavaScript relation, logic inference, common errors, summary).

8. **Refine and Elaborate:** Add details and explanations to make the answer clear and comprehensive. For example, explain what "lowering" means in the context of compilation. Explain the role of type checks and conversions.

By following this thought process, we can arrive at a detailed and accurate answer that addresses all aspects of the user's query.
## 功能归纳：v8/src/compiler/js-typed-lowering.cc (第 1 部分)

**功能总览:**

`v8/src/compiler/js-typed-lowering.cc` 是 V8 引擎中 Turbofan 编译器的重要组成部分，它的主要功能是 **基于类型信息对 JavaScript 代码进行降级优化 (Typed Lowering)**。  这意味着它会将相对高层次、通用的 JavaScript 操作 (例如 `JSAdd`, `JSToNumber`) 转换为更具体、更底层的操作 (例如 `NumberAdd`, `PlainPrimitiveToNumber`)，以便后续的编译阶段能够生成更高效的机器代码。

**详细功能分解:**

1. **识别和处理特定 JavaScript 操作:**  代码中包含 `ReduceJSBitwiseNot`, `ReduceJSDecrement`, `ReduceJSIncrement`, `ReduceJSNegate`, `ReduceJSAdd` 等方法，表明该文件负责处理这些特定的 JavaScript 运算符。

2. **类型推断和利用:**  该文件依赖于 V8 编译器的类型系统，通过分析节点的类型信息 (例如 `NodeProperties::GetType(input)`)，判断是否可以进行类型相关的优化。

3. **操作降级:**  根据操作数 (operands) 的类型，将通用的 JavaScript 操作替换为更底层的操作。例如：
    * 如果 `JSAdd` 的两个操作数都是 `Number` 类型，则可以降级为 `NumberAdd`。
    * 如果 `JSBitwiseNot` 的操作数是 `PlainPrimitive` 类型，则可以降级为 `NumberBitwiseXor`。

4. **插入类型检查:**  在某些情况下，为了确保类型假设的正确性，会插入类型检查节点 (例如 `simplified()->CheckReceiver()`, `simplified()->CheckString()`).

5. **插入类型转换:**  如果操作需要的类型与操作数类型不符，并且可以安全转换，则会插入类型转换节点 (例如 `simplified()->PlainPrimitiveToNumber()`, `simplified()->NumberToInt32()`).

6. **处理字符串操作:**  专门处理字符串连接 (`JSAdd` 且操作数是字符串) 的情况，可能生成 `NewConsString` 或 `StringConcat` 操作。

7. **处理装箱类型 (String Wrapper):**  提供了 `UnwrapStringWrapper` 函数，用于解开 String 包装对象，获取其原始字符串值。

8. **利用反馈信息 (Feedback):**  通过 `GetBinaryOperationHint` 和 `GetCompareOperationHint` 等方法，获取运行时反馈信息，用于指导类型降级决策。

9. **优化特定场景:**  例如，针对与空字符串的连接进行优化。

10. **辅助类 `JSBinopReduction`:**  提供了一系列便捷的方法，用于简化二元操作符的降级过程，例如类型判断、类型转换、操作符替换等。

**文件类型判断:**

根据代码内容，`v8/src/compiler/js-typed-lowering.cc` **不是**以 `.tq` 结尾，因此它是一个 **C++** 源代码文件，而不是 V8 Torque 源代码。

**与 JavaScript 功能的关系及示例:**

`v8/src/compiler/js-typed-lowering.cc` 的功能直接关系到 JavaScript 的执行性能。它通过在编译时利用类型信息进行优化，减少了运行时的类型检查和转换开销。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2); // 这里的 '+' 操作符，typed-lowering 可能会将其降级为 NumberAdd
add("hello", "world"); // 这里的 '+' 操作符，typed-lowering 可能会将其降级为 StringConcat 或 NewConsString
add(5, "!"); // 这里的 '+' 操作符，typed-lowering 可能会插入类型转换操作，最终执行字符串连接
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  一个表示 `a + b` 的 AST 节点，其中 `a` 和 `b` 的类型都被推断为 `Number`。

**输出:**  该节点被替换为一个表示 `NumberAdd(a, b)` 的新的操作节点。

**假设输入:**  一个表示 `a + b` 的 AST 节点，其中 `a` 的类型被推断为 `String`，`b` 的类型未知。

**输出:**  可能会将 `b` 的输入节点替换为 `JSToString(b)` 的节点，然后将 `+` 操作降级为字符串连接相关的操作 (取决于具体情况，可能是 `StringConcat` 或 `NewConsString`)。

**涉及用户常见的编程错误及示例:**

此文件本身是编译器代码，并不直接处理用户代码的运行时错误。但是，它所做的优化工作与用户代码中常见的类型相关错误息息相关。

**示例 (可能触发类型降级失败或 deoptimization 的用户错误):**

```javascript
function calculate(x) {
  return x + 5; // 如果 x 的类型在运行时不是 Number，会导致 typed-lowering 的假设失效
}

calculate(10);
calculate("invalid"); // 这里的 "invalid" 是字符串，与 + 运算符的预期类型不符，可能导致 deoptimization
```

**功能归纳:**

总而言之，`v8/src/compiler/js-typed-lowering.cc` 的核心功能是 **在 Turbofan 编译过程中，根据类型信息将通用的 JavaScript 操作降级为更高效的底层操作，从而提升 JavaScript 代码的执行性能。** 它通过类型推断、插入类型检查和转换、以及处理特定的 JavaScript 运算符和数据类型来实现这一目标。

Prompt: 
```
这是目录为v8/src/compiler/js-typed-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-typed-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
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
    Callable const callable = 
"""


```