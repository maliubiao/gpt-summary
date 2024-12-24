Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality and relationship to JavaScript.

1. **Understand the Goal:** The request asks for a summary of the C++ code's function and how it relates to JavaScript, providing examples if applicable. This means focusing on the *purpose* of the code within the larger V8 context, not just its technical implementation details.

2. **Identify the Class:** The core of the file is the `TypedOptimization` class. This immediately suggests the code is related to optimization based on types.

3. **Examine the Constructor:** The constructor initializes several key members: `dependencies_`, `jsgraph_`, `broker_`, `true_type_`, `false_type_`, and `type_cache_`. These names provide important clues:
    * `dependencies_`: Likely tracks dependencies for optimization invalidation.
    * `jsgraph_`:  Almost certainly a representation of the intermediate representation (IR) graph used by the compiler.
    * `broker_`: Seems to be an interface to the JavaScript heap, allowing access to objects and their properties.
    * `true_type_`, `false_type_`: Represent the boolean true and false types.
    * `type_cache_`:  Caches type information for efficiency.

4. **Analyze the `Reduce` Method:** This is the central method. The `switch` statement on `node->opcode()` indicates that `TypedOptimization` operates on nodes within the compiler's IR graph. Each `case` corresponds to a specific IR operation (e.g., `kConvertReceiver`, `kCheckHeapObject`, `kLoadField`). This strongly suggests the class performs optimizations *specific* to these operations.

5. **Infer the Optimization Strategy:** The names of the `Reduce` methods (e.g., `ReduceConvertReceiver`, `ReduceCheckMaps`) suggest that the goal is to simplify or eliminate these operations based on type information. The code often checks types (`NodeProperties::GetType`) and then, if certain conditions are met, replaces the node with a simpler equivalent or removes it entirely.

6. **Connect to JavaScript Concepts:**  Now, link the C++ operations to corresponding JavaScript behavior:
    * `ConvertReceiver`:  Relates to how `this` is resolved in JavaScript function calls.
    * `CheckHeapObject`, `CheckMaps`, `CheckNumber`, `CheckString`: These directly relate to JavaScript's dynamic typing and the need to verify object types at runtime.
    * `LoadField`: Accessing properties of JavaScript objects.
    * `NumberCeil`, `NumberFloor`, `NumberRound`:  Standard JavaScript Math functions.
    * `StringEqual`, `StringLessThan`:  String comparison operators in JavaScript.
    * `TypeOf`: The `typeof` operator in JavaScript.
    * `ToBoolean`:  Implicit and explicit type coercion to boolean (e.g., in `if` statements).
    * `SpeculativeToNumber`, `SpeculativeNumberAdd`: Optimizations related to JavaScript's loose typing where the compiler might initially assume a value is a number.

7. **Formulate the Functional Summary:** Based on the above analysis, the core function of `TypedOptimization` is to analyze the compiler's IR graph, leveraging type information to simplify or remove redundant operations. This makes the generated machine code more efficient.

8. **Develop JavaScript Examples:**  For each category of optimization, create simple JavaScript code snippets that demonstrate the underlying JavaScript behavior being optimized. The examples should be clear and directly correspond to the C++ operation. For instance:
    * For `CheckMaps`, show how V8 can optimize property access on objects with stable shapes.
    * For `ToBoolean`, illustrate how different JavaScript values are coerced to boolean.

9. **Refine and Structure:** Organize the information logically. Start with a general summary, then delve into specific categories of optimizations with corresponding JavaScript examples. Use clear language and avoid overly technical jargon where possible. Explain *why* these optimizations are important for JavaScript performance.

10. **Review and Iterate:** Read through the explanation to ensure accuracy, clarity, and completeness. Are the JavaScript examples accurate and easy to understand?  Does the explanation connect the C++ code back to observable JavaScript behavior?  (Self-correction: Initially, I might focus too much on the C++ implementation details. I need to shift the focus to the *impact* on JavaScript execution.)

By following this process, we can move from analyzing the raw C++ code to a comprehensive explanation of its purpose and relevance within the context of JavaScript and the V8 engine.
这个C++源代码文件 `typed-optimization.cc`  实现了 V8 JavaScript 引擎中 TurboFan 编译器的 **类型化优化（Typed Optimization）** 功能。

**功能归纳:**

`TypedOptimization` 类的主要职责是在编译管道中，利用类型信息来优化中间代码（IR，Intermediate Representation）。 它通过检查和转换 IR 节点，尽可能地消除冗余操作，简化代码，并生成更高效的机器码。  核心思想是，当编译器能更精确地了解变量的类型时，就可以进行更激进的优化。

具体来说，`TypedOptimization` 类实现了 `AdvancedReducer` 接口，它遍历 IR 图中的节点，并根据节点的类型和操作码执行以下类型的优化：

* **类型检查的优化:**  例如，如果编译器已经确定一个值肯定是数字，那么 `CheckNumber` 节点就可以被移除。 类似地，对于 `CheckHeapObject`, `CheckMaps`, `CheckString` 等检查节点也会进行类似的优化。
* **类型转换的优化:**  例如，如果已知一个值已经是布尔类型，那么 `ToBoolean` 操作就可以被替换为该值本身。
* **数学运算的优化:**  例如，针对特定类型的数字运算，可以替换为更高效的操作，例如 `NumberFloor` 在已知输入是整数时可以被直接替换为输入。
* **字符串操作的优化:**  例如，已知字符串的长度，可以直接替换 `StringLength` 操作。 字符串比较操作在某些特定情况下可以被优化为数字比较。
* **逻辑运算的优化:**  例如，根据条件表达式的类型，可以简化 `Select` 节点。
* **类型收窄:**  `ReducePhi` 函数尝试根据输入值的类型，更精确地推断 Phi 节点的类型。
* **常量折叠:**  对于输入是常量的情况，一些操作可以直接计算出结果，例如 `StringLength`。
* **Speculative 操作的优化:**  对于带有 "Speculative" 前缀的操作，表示编译器在某些情况下假设了类型。 `TypedOptimization` 会根据实际的类型信息，将这些投机操作转换为更具体的、非投机的操作，或者直接消除它们。

**与 JavaScript 的关系及 JavaScript 举例说明:**

`TypedOptimization` 的所有优化都直接服务于提升 JavaScript 代码的执行效率。 JavaScript 是一门动态类型语言，变量的类型在运行时才能确定。 这给编译器优化带来了挑战。 TurboFan 编译器通过各种分析手段（包括类型推断）来尽可能地了解变量的类型，然后 `TypedOptimization` 就利用这些类型信息来执行具体的优化。

以下是一些与 `typed-optimization.cc` 中优化相关的 JavaScript 示例：

**1. 类型检查的优化 (例如 `ReduceCheckNumber`, `ReduceCheckString`):**

```javascript
function add(x, y) {
  if (typeof x === 'number' && typeof y === 'number') { // 类型检查
    return x + y;
  }
  return NaN;
}

add(5, 10); // V8 可能会推断出 x 和 y 是数字，从而消除内部的类型检查
```

在上面的例子中，JavaScript 代码显式地进行了类型检查。 TurboFan 编译器可能会通过类型推断发现 `add(5, 10)` 调用中 `x` 和 `y` 总是数字，从而在编译后的代码中移除或简化内部的 `typeof` 检查，对应于 `ReduceCheckNumber` 等优化。

**2. 类型转换的优化 (例如 `ReduceToBoolean`):**

```javascript
function isTruthy(value) {
  return !!value; // 显式转换为布尔值
}

isTruthy("hello"); // V8 可以根据字符串类型直接进行布尔转换的优化
isTruthy(0);       // V8 可以根据数字类型直接进行布尔转换的优化
```

`ReduceToBoolean` 函数尝试优化 `ToBoolean` 操作。 例如，如果编译器知道 `value` 是一个字符串，那么 `!!value` 这样的操作可能会被优化为直接检查字符串是否为空。

**3. 数学运算的优化 (例如 `ReduceNumberFloor`):**

```javascript
function integerDivide(a, b) {
  return Math.floor(a / b);
}

integerDivide(10, 3); // 如果 V8 推断出 a 和 b 是整数，可能会优化除法和 floor 操作
```

如果 V8 能够推断出 `a` 和 `b` 是整数，`ReduceNumberFloor` 可能会将 `Math.floor(a / b)` 优化为更高效的整数除法操作。

**4. 字符串操作的优化 (例如 `ReduceStringLength`, `ReduceStringComparison`):**

```javascript
function getStringLength(str) {
  return str.length;
}

getStringLength("example"); // V8 可以直接获取常量字符串的长度

function compareStrings(str1, str2) {
  return str1 < str2;
}

compareStrings("a", "b"); // V8 在比较字符串时可能会进行优化
```

`ReduceStringLength` 可以直接替换常量字符串的长度。 `ReduceStringComparison` 可以将某些字符串比较优化为数字比较，例如比较由 `String.fromCharCode` 生成的单字符字符串。

**5. Speculative 操作的优化 (例如 `ReduceSpeculativeNumberAdd`):**

```javascript
function addPossiblyNumbers(a, b) {
  return a + b; // "+" 运算符可能触发 SpeculativeNumberAdd
}

addPossiblyNumbers(5, 10);   // V8 如果确定 a 和 b 是数字，会优化为真正的数字加法
addPossiblyNumbers("5", "10"); // 如果 a 和 b 是字符串，则会执行字符串连接
```

当编译器不能完全确定 `a + b` 中 `a` 和 `b` 的类型时，可能会使用 `SpeculativeNumberAdd`。 `TypedOptimization` 如果后续发现它们总是数字，就会将其替换为真正的 `NumberAdd` 操作。

**总结:**

`typed-optimization.cc` 文件中的代码是 V8 引擎为了提升 JavaScript 代码性能而进行的关键优化步骤。 它通过深入分析类型信息，消除了许多不必要的运行时检查和转换，使得生成的机器码更加高效。 这些优化对于提供流畅的 JavaScript 执行体验至关重要。

Prompt: 
```
这是目录为v8/src/compiler/typed-optimization.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/typed-optimization.h"

#include <optional>

#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/type-cache.h"
#include "src/execution/isolate-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

TypedOptimization::TypedOptimization(Editor* editor,
                                     CompilationDependencies* dependencies,
                                     JSGraph* jsgraph, JSHeapBroker* broker)
    : AdvancedReducer(editor),
      dependencies_(dependencies),
      jsgraph_(jsgraph),
      broker_(broker),
      true_type_(Type::Constant(broker, broker->true_value(), graph()->zone())),
      false_type_(
          Type::Constant(broker, broker->false_value(), graph()->zone())),
      type_cache_(TypeCache::Get()) {}

TypedOptimization::~TypedOptimization() = default;

Reduction TypedOptimization::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kConvertReceiver:
      return ReduceConvertReceiver(node);
    case IrOpcode::kMaybeGrowFastElements:
      return ReduceMaybeGrowFastElements(node);
    case IrOpcode::kCheckHeapObject:
      return ReduceCheckHeapObject(node);
    case IrOpcode::kCheckBounds:
      return ReduceCheckBounds(node);
    case IrOpcode::kCheckNotTaggedHole:
      return ReduceCheckNotTaggedHole(node);
    case IrOpcode::kCheckMaps:
      return ReduceCheckMaps(node);
    case IrOpcode::kCheckNumber:
      return ReduceCheckNumber(node);
    case IrOpcode::kCheckString:
      return ReduceCheckString(node);
    case IrOpcode::kCheckStringOrStringWrapper:
      return ReduceCheckStringOrStringWrapper(node);
    case IrOpcode::kCheckEqualsInternalizedString:
      return ReduceCheckEqualsInternalizedString(node);
    case IrOpcode::kCheckEqualsSymbol:
      return ReduceCheckEqualsSymbol(node);
    case IrOpcode::kLoadField:
      return ReduceLoadField(node);
    case IrOpcode::kNumberCeil:
    case IrOpcode::kNumberRound:
    case IrOpcode::kNumberTrunc:
      return ReduceNumberRoundop(node);
    case IrOpcode::kNumberFloor:
      return ReduceNumberFloor(node);
    case IrOpcode::kNumberSilenceNaN:
      return ReduceNumberSilenceNaN(node);
    case IrOpcode::kNumberToUint8Clamped:
      return ReduceNumberToUint8Clamped(node);
    case IrOpcode::kPhi:
      return ReducePhi(node);
    case IrOpcode::kReferenceEqual:
      return ReduceReferenceEqual(node);
    case IrOpcode::kStringEqual:
    case IrOpcode::kStringLessThan:
    case IrOpcode::kStringLessThanOrEqual:
      return ReduceStringComparison(node);
    case IrOpcode::kStringLength:
      return ReduceStringLength(node);
    case IrOpcode::kSameValue:
      return ReduceSameValue(node);
    case IrOpcode::kSelect:
      return ReduceSelect(node);
    case IrOpcode::kTypeOf:
      return ReduceTypeOf(node);
    case IrOpcode::kToBoolean:
      return ReduceToBoolean(node);
    case IrOpcode::kSpeculativeToNumber:
      return ReduceSpeculativeToNumber(node);
    case IrOpcode::kSpeculativeNumberAdd:
      return ReduceSpeculativeNumberAdd(node);
    case IrOpcode::kSpeculativeNumberSubtract:
    case IrOpcode::kSpeculativeNumberMultiply:
    case IrOpcode::kSpeculativeNumberPow:
    case IrOpcode::kSpeculativeNumberDivide:
    case IrOpcode::kSpeculativeNumberModulus:
      return ReduceSpeculativeNumberBinop(node);
    case IrOpcode::kSpeculativeNumberEqual:
    case IrOpcode::kSpeculativeNumberLessThan:
    case IrOpcode::kSpeculativeNumberLessThanOrEqual:
      return ReduceSpeculativeNumberComparison(node);
    default:
      break;
  }
  return NoChange();
}

namespace {

OptionalMapRef GetStableMapFromObjectType(JSHeapBroker* broker,
                                          Type object_type) {
  if (object_type.IsHeapConstant()) {
    HeapObjectRef object = object_type.AsHeapConstant()->Ref();
    MapRef object_map = object.map(broker);
    if (object_map.is_stable()) return object_map;
  }
  return {};
}

Node* ResolveSameValueRenames(Node* node) {
  while (true) {
    switch (node->opcode()) {
      case IrOpcode::kCheckHeapObject:
      case IrOpcode::kCheckNumber:
      case IrOpcode::kCheckSmi:
      case IrOpcode::kFinishRegion:
      case IrOpcode::kTypeGuard:
        if (node->IsDead()) {
          return node;
        } else {
          node = node->InputAt(0);
          continue;
        }
      default:
        return node;
    }
  }
}

}  // namespace

Reduction TypedOptimization::ReduceConvertReceiver(Node* node) {
  Node* const value = NodeProperties::GetValueInput(node, 0);
  Type const value_type = NodeProperties::GetType(value);
  Node* const global_proxy = NodeProperties::GetValueInput(node, 2);
  if (value_type.Is(Type::Receiver())) {
    ReplaceWithValue(node, value);
    return Replace(value);
  } else if (value_type.Is(Type::NullOrUndefined())) {
    ReplaceWithValue(node, global_proxy);
    return Replace(global_proxy);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceCheckHeapObject(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (!input_type.Maybe(Type::SignedSmall())) {
    ReplaceWithValue(node, input);
    return Replace(input);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceMaybeGrowFastElements(Node* node) {
  Node* const elements = NodeProperties::GetValueInput(node, 1);
  Node* const index = NodeProperties::GetValueInput(node, 2);
  Node* const length = NodeProperties::GetValueInput(node, 3);
  Node* const effect = NodeProperties::GetEffectInput(node);
  Node* const control = NodeProperties::GetControlInput(node);

  Type const index_type = NodeProperties::GetType(index);
  Type const length_type = NodeProperties::GetType(length);
  CHECK(index_type.Is(Type::Unsigned31()));
  CHECK(length_type.Is(Type::Unsigned31()));

  if (!index_type.IsNone() && !length_type.IsNone() &&
      index_type.Max() < length_type.Min()) {
    if (v8_flags.turbo_typer_hardening) {
      Node* check_bounds = graph()->NewNode(
          simplified()->CheckBounds(FeedbackSource{},
                                    CheckBoundsFlag::kAbortOnOutOfBounds),
          index, length, effect, control);
      ReplaceWithValue(node, elements, check_bounds);
      return Replace(check_bounds);
    } else {
      RelaxEffectsAndControls(node);
      return Replace(elements);
    }
  }

  return NoChange();
}

Reduction TypedOptimization::ReduceCheckBounds(Node* node) {
  CheckBoundsParameters const& p = CheckBoundsParametersOf(node->op());
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (p.flags() & CheckBoundsFlag::kConvertStringAndMinusZero &&
      !input_type.Maybe(Type::String()) &&
      !input_type.Maybe(Type::MinusZero())) {
    NodeProperties::ChangeOp(
        node,
        simplified()->CheckBounds(
            p.check_parameters().feedback(),
            p.flags().without(CheckBoundsFlag::kConvertStringAndMinusZero)));
    return Changed(node);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceCheckNotTaggedHole(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (!input_type.Maybe(Type::Hole())) {
    ReplaceWithValue(node, input);
    return Replace(input);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceCheckMaps(Node* node) {
  // The CheckMaps(o, ...map...) can be eliminated if map is stable,
  // o has type Constant(object) and map == object->map, and either
  //  (1) map cannot transition further, or
  //  (2) we can add a code dependency on the stability of map
  //      (to guard the Constant type information).
  Node* const object = NodeProperties::GetValueInput(node, 0);
  Type const object_type = NodeProperties::GetType(object);
  Node* const effect = NodeProperties::GetEffectInput(node);
  OptionalMapRef object_map = GetStableMapFromObjectType(broker(), object_type);
  if (object_map.has_value()) {
    for (int i = 1; i < node->op()->ValueInputCount(); ++i) {
      Node* const map = NodeProperties::GetValueInput(node, i);
      Type const map_type = NodeProperties::GetType(map);
      if (map_type.IsHeapConstant() &&
          map_type.AsHeapConstant()->Ref().equals(*object_map)) {
        if (object_map->CanTransition()) {
          dependencies()->DependOnStableMap(*object_map);
        }
        return Replace(effect);
      }
    }
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceCheckNumber(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::Number())) {
    ReplaceWithValue(node, input);
    return Replace(input);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceCheckString(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::String())) {
    ReplaceWithValue(node, input);
    return Replace(input);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceCheckStringOrStringWrapper(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::StringOrStringWrapper())) {
    ReplaceWithValue(node, input);
    return Replace(input);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceCheckEqualsInternalizedString(Node* node) {
  Node* const exp = NodeProperties::GetValueInput(node, 0);
  Type const exp_type = NodeProperties::GetType(exp);
  Node* const val = NodeProperties::GetValueInput(node, 1);
  Type const val_type = NodeProperties::GetType(val);
  Node* const effect = NodeProperties::GetEffectInput(node);
  if (val_type.Is(exp_type)) return Replace(effect);
  // TODO(turbofan): Should we also try to optimize the
  // non-internalized String case for {val} here?
  return NoChange();
}

Reduction TypedOptimization::ReduceCheckEqualsSymbol(Node* node) {
  Node* const exp = NodeProperties::GetValueInput(node, 0);
  Type const exp_type = NodeProperties::GetType(exp);
  Node* const val = NodeProperties::GetValueInput(node, 1);
  Type const val_type = NodeProperties::GetType(val);
  Node* const effect = NodeProperties::GetEffectInput(node);
  if (val_type.Is(exp_type)) return Replace(effect);
  return NoChange();
}

Reduction TypedOptimization::ReduceLoadField(Node* node) {
  Node* const object = NodeProperties::GetValueInput(node, 0);
  Type const object_type = NodeProperties::GetType(object);
  FieldAccess const& access = FieldAccessOf(node->op());
  if (access.base_is_tagged == kTaggedBase &&
      access.offset == HeapObject::kMapOffset) {
    // We can replace LoadField[Map](o) with map if is stable, and
    // o has type Constant(object) and map == object->map, and either
    //  (1) map cannot transition further, or
    //  (2) deoptimization is enabled and we can add a code dependency on the
    //      stability of map (to guard the Constant type information).
    OptionalMapRef object_map =
        GetStableMapFromObjectType(broker(), object_type);
    if (object_map.has_value()) {
      dependencies()->DependOnStableMap(*object_map);
      Node* const value = jsgraph()->ConstantNoHole(*object_map, broker());
      ReplaceWithValue(node, value);
      return Replace(value);
    }
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceNumberFloor(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(type_cache_->kIntegerOrMinusZeroOrNaN)) {
    return Replace(input);
  }
  if (input_type.Is(Type::PlainNumber()) &&
      (input->opcode() == IrOpcode::kNumberDivide ||
       input->opcode() == IrOpcode::kSpeculativeNumberDivide)) {
    Node* const lhs = NodeProperties::GetValueInput(input, 0);
    Type const lhs_type = NodeProperties::GetType(lhs);
    Node* const rhs = NodeProperties::GetValueInput(input, 1);
    Type const rhs_type = NodeProperties::GetType(rhs);
    if (lhs_type.IsNone() || rhs_type.IsNone()) return NoChange();
    if (lhs_type.Is(Type::Unsigned32()) && rhs_type.Is(Type::Unsigned32())) {
      // We can replace
      //
      //   NumberFloor(NumberDivide(lhs: unsigned32,
      //                            rhs: unsigned32)): plain-number
      //
      // with
      //
      //   Unsigned32Divide(lhs, rhs)
      //
      // and have the new node typed to [0...lhs.Max],
      // as the truncated result must be lower than {lhs}'s maximum
      // value (note that {rhs} cannot be less than 1 due to the
      // plain-number type constraint on the {node}).
      node = graph()->NewNode(simplified()->Unsigned32Divide(), lhs, rhs);
      return Replace(node);
    }
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceNumberRoundop(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(type_cache_->kIntegerOrMinusZeroOrNaN)) {
    return Replace(input);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceNumberSilenceNaN(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::OrderedNumber())) {
    return Replace(input);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceNumberToUint8Clamped(Node* node) {
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(type_cache_->kUint8)) {
    return Replace(input);
  }
  return NoChange();
}

Reduction TypedOptimization::ReducePhi(Node* node) {
  // Try to narrow the type of the Phi {node}, which might be more precise now
  // after lowering based on types, i.e. a SpeculativeNumberAdd has a more
  // precise type than the JSAdd that was in the graph when the Typer was run.
  DCHECK_EQ(IrOpcode::kPhi, node->opcode());
  // Prevent new types from being propagated through loop-related Phis for now.
  // This is to avoid slow convergence of type narrowing when we learn very
  // precise information about loop variables.
  if (NodeProperties::GetControlInput(node, 0)->opcode() == IrOpcode::kLoop) {
    return NoChange();
  }
  int arity = node->op()->ValueInputCount();
  Type type = NodeProperties::GetType(node->InputAt(0));
  for (int i = 1; i < arity; ++i) {
    type = Type::Union(type, NodeProperties::GetType(node->InputAt(i)),
                       graph()->zone());
  }
  Type const node_type = NodeProperties::GetType(node);
  if (!node_type.Is(type)) {
    type = Type::Intersect(node_type, type, graph()->zone());
    NodeProperties::SetType(node, type);
    return Changed(node);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceReferenceEqual(Node* node) {
  DCHECK_EQ(IrOpcode::kReferenceEqual, node->opcode());
  Node* const lhs = NodeProperties::GetValueInput(node, 0);
  Node* const rhs = NodeProperties::GetValueInput(node, 1);
  Type const lhs_type = NodeProperties::GetType(lhs);
  Type const rhs_type = NodeProperties::GetType(rhs);
  if (!lhs_type.Maybe(rhs_type)) {
    Node* replacement = jsgraph()->FalseConstant();
    // Make sure we do not widen the type.
    if (NodeProperties::GetType(replacement)
            .Is(NodeProperties::GetType(node))) {
      return Replace(jsgraph()->FalseConstant());
    }
  }
  if (rhs_type.Is(Type::Boolean()) && rhs_type.IsHeapConstant() &&
      lhs_type.Is(Type::Boolean())) {
    std::optional<bool> maybe_result =
        rhs_type.AsHeapConstant()->Ref().TryGetBooleanValue(broker());
    if (maybe_result.has_value()) {
      if (maybe_result.value()) {
        return Replace(node->InputAt(0));
      } else {
        node->TrimInputCount(1);
        NodeProperties::ChangeOp(node, simplified()->BooleanNot());
        return Changed(node);
      }
    }
  }
  return NoChange();
}

const Operator* TypedOptimization::NumberComparisonFor(const Operator* op) {
  switch (op->opcode()) {
    case IrOpcode::kStringEqual:
      return simplified()->NumberEqual();
    case IrOpcode::kStringLessThan:
      return simplified()->NumberLessThan();
    case IrOpcode::kStringLessThanOrEqual:
      return simplified()->NumberLessThanOrEqual();
    default:
      break;
  }
  UNREACHABLE();
}

Reduction TypedOptimization::
    TryReduceStringComparisonOfStringFromSingleCharCodeToConstant(
        Node* comparison, StringRef string, bool inverted) {
  switch (comparison->opcode()) {
    case IrOpcode::kStringEqual:
      if (string.length() != 1) {
        // String.fromCharCode(x) always has length 1.
        return Replace(jsgraph()->BooleanConstant(false));
      }
      break;
    case IrOpcode::kStringLessThan:
      [[fallthrough]];
    case IrOpcode::kStringLessThanOrEqual:
      if (string.length() == 0) {
        // String.fromCharCode(x) <= "" is always false,
        // "" < String.fromCharCode(x) is always true.
        return Replace(jsgraph()->BooleanConstant(inverted));
      }
      break;
    default:
      UNREACHABLE();
  }
  return NoChange();
}

// Try to reduces a string comparison of the form
// String.fromCharCode(x) {comparison} {constant} if inverted is false,
// and {constant} {comparison} String.fromCharCode(x) if inverted is true.
Reduction
TypedOptimization::TryReduceStringComparisonOfStringFromSingleCharCode(
    Node* comparison, Node* from_char_code, Type constant_type, bool inverted) {
  DCHECK_EQ(IrOpcode::kStringFromSingleCharCode, from_char_code->opcode());

  if (!constant_type.IsHeapConstant()) return NoChange();
  ObjectRef constant = constant_type.AsHeapConstant()->Ref();

  if (!constant.IsString()) return NoChange();
  StringRef string = constant.AsString();

  // Check if comparison can be resolved statically.
  Reduction red = TryReduceStringComparisonOfStringFromSingleCharCodeToConstant(
      comparison, string, inverted);
  if (red.Changed()) return red;

  const Operator* comparison_op = NumberComparisonFor(comparison->op());
  Node* from_char_code_repl = NodeProperties::GetValueInput(from_char_code, 0);
  Type from_char_code_repl_type = NodeProperties::GetType(from_char_code_repl);
  if (!from_char_code_repl_type.Is(type_cache_->kUint16)) {
    // Convert to signed int32 to satisfy type of {NumberBitwiseAnd}.
    from_char_code_repl =
        graph()->NewNode(simplified()->NumberToInt32(), from_char_code_repl);
    from_char_code_repl = graph()->NewNode(
        simplified()->NumberBitwiseAnd(), from_char_code_repl,
        jsgraph()->ConstantNoHole(std::numeric_limits<uint16_t>::max()));
  }
  if (!string.GetFirstChar(broker()).has_value()) return NoChange();
  Node* constant_repl =
      jsgraph()->ConstantNoHole(string.GetFirstChar(broker()).value());

  Node* number_comparison = nullptr;
  if (inverted) {
    // "x..." <= String.fromCharCode(z) is true if x < z.
    if (string.length() > 1 &&
        comparison->opcode() == IrOpcode::kStringLessThanOrEqual) {
      comparison_op = simplified()->NumberLessThan();
    }
    number_comparison =
        graph()->NewNode(comparison_op, constant_repl, from_char_code_repl);
  } else {
    // String.fromCharCode(z) < "x..." is true if z <= x.
    if (string.length() > 1 &&
        comparison->opcode() == IrOpcode::kStringLessThan) {
      comparison_op = simplified()->NumberLessThanOrEqual();
    }
    number_comparison =
        graph()->NewNode(comparison_op, from_char_code_repl, constant_repl);
  }
  ReplaceWithValue(comparison, number_comparison);
  return Replace(number_comparison);
}

Reduction TypedOptimization::ReduceStringComparison(Node* node) {
  DCHECK(IrOpcode::kStringEqual == node->opcode() ||
         IrOpcode::kStringLessThan == node->opcode() ||
         IrOpcode::kStringLessThanOrEqual == node->opcode());
  Node* const lhs = NodeProperties::GetValueInput(node, 0);
  Node* const rhs = NodeProperties::GetValueInput(node, 1);
  Type lhs_type = NodeProperties::GetType(lhs);
  Type rhs_type = NodeProperties::GetType(rhs);
  if (lhs->opcode() == IrOpcode::kStringFromSingleCharCode) {
    if (rhs->opcode() == IrOpcode::kStringFromSingleCharCode) {
      Node* left = NodeProperties::GetValueInput(lhs, 0);
      Node* right = NodeProperties::GetValueInput(rhs, 0);
      Type left_type = NodeProperties::GetType(left);
      Type right_type = NodeProperties::GetType(right);
      if (!left_type.Is(type_cache_->kUint16)) {
        // Convert to signed int32 to satisfy type of {NumberBitwiseAnd}.
        left = graph()->NewNode(simplified()->NumberToInt32(), left);
        left = graph()->NewNode(
            simplified()->NumberBitwiseAnd(), left,
            jsgraph()->ConstantNoHole(std::numeric_limits<uint16_t>::max()));
      }
      if (!right_type.Is(type_cache_->kUint16)) {
        // Convert to signed int32 to satisfy type of {NumberBitwiseAnd}.
        right = graph()->NewNode(simplified()->NumberToInt32(), right);
        right = graph()->NewNode(
            simplified()->NumberBitwiseAnd(), right,
            jsgraph()->ConstantNoHole(std::numeric_limits<uint16_t>::max()));
      }
      Node* equal =
          graph()->NewNode(NumberComparisonFor(node->op()), left, right);
      ReplaceWithValue(node, equal);
      return Replace(equal);
    } else {
      return TryReduceStringComparisonOfStringFromSingleCharCode(
          node, lhs, rhs_type, false);
    }
  } else if (rhs->opcode() == IrOpcode::kStringFromSingleCharCode) {
    return TryReduceStringComparisonOfStringFromSingleCharCode(node, rhs,
                                                               lhs_type, true);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceStringLength(Node* node) {
  DCHECK_EQ(IrOpcode::kStringLength, node->opcode());
  Node* const input = NodeProperties::GetValueInput(node, 0);
  switch (input->opcode()) {
    case IrOpcode::kHeapConstant: {
      // Constant-fold the String::length of the {input}.
      HeapObjectMatcher m(input);
      if (m.Ref(broker()).IsString()) {
        uint32_t const length = m.Ref(broker()).AsString().length();
        Node* value = jsgraph()->ConstantNoHole(length);
        return Replace(value);
      }
      break;
    }
    case IrOpcode::kStringConcat: {
      // The first value input to the {input} is the resulting length.
      return Replace(input->InputAt(0));
    }
    case IrOpcode::kStringFromSingleCharCode: {
      // Note that this isn't valid for StringFromCodePointAt, since it the
      // string it returns can be 1 or 2 characters long.
      return Replace(jsgraph()->ConstantNoHole(1));
    }
    default:
      break;
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceSameValue(Node* node) {
  DCHECK_EQ(IrOpcode::kSameValue, node->opcode());
  Node* const lhs = NodeProperties::GetValueInput(node, 0);
  Node* const rhs = NodeProperties::GetValueInput(node, 1);
  Type const lhs_type = NodeProperties::GetType(lhs);
  Type const rhs_type = NodeProperties::GetType(rhs);
  if (ResolveSameValueRenames(lhs) == ResolveSameValueRenames(rhs)) {
    if (NodeProperties::GetType(node).IsNone()) {
      return NoChange();
    }
    // SameValue(x,x) => #true
    return Replace(jsgraph()->TrueConstant());
  } else if (lhs_type.Is(Type::Unique()) && rhs_type.Is(Type::Unique())) {
    // SameValue(x:unique,y:unique) => ReferenceEqual(x,y)
    NodeProperties::ChangeOp(node, simplified()->ReferenceEqual());
    return Changed(node);
  } else if (lhs_type.Is(Type::String()) && rhs_type.Is(Type::String())) {
    // SameValue(x:string,y:string) => StringEqual(x,y)
    NodeProperties::ChangeOp(node, simplified()->StringEqual());
    return Changed(node);
  } else if (lhs_type.Is(Type::MinusZero())) {
    // SameValue(x:minus-zero,y) => ObjectIsMinusZero(y)
    node->RemoveInput(0);
    NodeProperties::ChangeOp(node, simplified()->ObjectIsMinusZero());
    return Changed(node);
  } else if (rhs_type.Is(Type::MinusZero())) {
    // SameValue(x,y:minus-zero) => ObjectIsMinusZero(x)
    node->RemoveInput(1);
    NodeProperties::ChangeOp(node, simplified()->ObjectIsMinusZero());
    return Changed(node);
  } else if (lhs_type.Is(Type::NaN())) {
    // SameValue(x:nan,y) => ObjectIsNaN(y)
    node->RemoveInput(0);
    NodeProperties::ChangeOp(node, simplified()->ObjectIsNaN());
    return Changed(node);
  } else if (rhs_type.Is(Type::NaN())) {
    // SameValue(x,y:nan) => ObjectIsNaN(x)
    node->RemoveInput(1);
    NodeProperties::ChangeOp(node, simplified()->ObjectIsNaN());
    return Changed(node);
  } else if (lhs_type.Is(Type::PlainNumber()) &&
             rhs_type.Is(Type::PlainNumber())) {
    // SameValue(x:plain-number,y:plain-number) => NumberEqual(x,y)
    NodeProperties::ChangeOp(node, simplified()->NumberEqual());
    return Changed(node);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceSelect(Node* node) {
  DCHECK_EQ(IrOpcode::kSelect, node->opcode());
  Node* const condition = NodeProperties::GetValueInput(node, 0);
  Type const condition_type = NodeProperties::GetType(condition);
  Node* const vtrue = NodeProperties::GetValueInput(node, 1);
  Type const vtrue_type = NodeProperties::GetType(vtrue);
  Node* const vfalse = NodeProperties::GetValueInput(node, 2);
  Type const vfalse_type = NodeProperties::GetType(vfalse);
  if (condition_type.Is(true_type_)) {
    // Select(condition:true, vtrue, vfalse) => vtrue
    return Replace(vtrue);
  }
  if (condition_type.Is(false_type_)) {
    // Select(condition:false, vtrue, vfalse) => vfalse
    return Replace(vfalse);
  }
  if (vtrue_type.Is(true_type_) && vfalse_type.Is(false_type_)) {
    // Select(condition, vtrue:true, vfalse:false) => condition
    return Replace(condition);
  }
  if (vtrue_type.Is(false_type_) && vfalse_type.Is(true_type_)) {
    // Select(condition, vtrue:false, vfalse:true) => BooleanNot(condition)
    node->TrimInputCount(1);
    NodeProperties::ChangeOp(node, simplified()->BooleanNot());
    return Changed(node);
  }
  // Try to narrow the type of the Select {node}, which might be more precise
  // now after lowering based on types.
  Type type = Type::Union(vtrue_type, vfalse_type, graph()->zone());
  Type const node_type = NodeProperties::GetType(node);
  if (!node_type.Is(type)) {
    type = Type::Intersect(node_type, type, graph()->zone());
    NodeProperties::SetType(node, type);
    return Changed(node);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceSpeculativeToNumber(Node* node) {
  DCHECK_EQ(IrOpcode::kSpeculativeToNumber, node->opcode());
  Node* const input = NodeProperties::GetValueInput(node, 0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::Number())) {
    // SpeculativeToNumber(x:number) => x
    ReplaceWithValue(node, input);
    return Replace(input);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceTypeOf(Node* node) {
  Node* const input = node->InputAt(0);
  Type const type = NodeProperties::GetType(input);
  if (type.Is(Type::Boolean())) {
    return Replace(
        jsgraph()->ConstantNoHole(broker()->boolean_string(), broker()));
  } else if (type.Is(Type::Number())) {
    return Replace(
        jsgraph()->ConstantNoHole(broker()->number_string(), broker()));
  } else if (type.Is(Type::String())) {
    return Replace(
        jsgraph()->ConstantNoHole(broker()->string_string(), broker()));
  } else if (type.Is(Type::BigInt())) {
    return Replace(
        jsgraph()->ConstantNoHole(broker()->bigint_string(), broker()));
  } else if (type.Is(Type::Symbol())) {
    return Replace(
        jsgraph()->ConstantNoHole(broker()->symbol_string(), broker()));
  } else if (type.Is(Type::OtherUndetectableOrUndefined())) {
    return Replace(
        jsgraph()->ConstantNoHole(broker()->undefined_string(), broker()));
  } else if (type.Is(Type::NonCallableOrNull())) {
    return Replace(
        jsgraph()->ConstantNoHole(broker()->object_string(), broker()));
  } else if (type.Is(Type::Function())) {
    return Replace(
        jsgraph()->ConstantNoHole(broker()->function_string(), broker()));
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceToBoolean(Node* node) {
  Node* const input = node->InputAt(0);
  Type const input_type = NodeProperties::GetType(input);
  if (input_type.Is(Type::Boolean())) {
    // ToBoolean(x:boolean) => x
    return Replace(input);
  } else if (input_type.Is(Type::OrderedNumber())) {
    // SToBoolean(x:ordered-number) => BooleanNot(NumberEqual(x,#0))
    node->ReplaceInput(0, graph()->NewNode(simplified()->NumberEqual(), input,
                                           jsgraph()->ZeroConstant()));
    node->TrimInputCount(1);
    NodeProperties::ChangeOp(node, simplified()->BooleanNot());
    return Changed(node);
  } else if (input_type.Is(Type::Number())) {
    // ToBoolean(x:number) => NumberToBoolean(x)
    node->TrimInputCount(1);
    NodeProperties::ChangeOp(node, simplified()->NumberToBoolean());
    return Changed(node);
  } else if (input_type.Is(Type::DetectableReceiverOrNull())) {
    // ToBoolean(x:detectable receiver \/ null)
    //   => BooleanNot(ReferenceEqual(x,#null))
    node->ReplaceInput(0, graph()->NewNode(simplified()->ReferenceEqual(),
                                           input, jsgraph()->NullConstant()));
    node->TrimInputCount(1);
    NodeProperties::ChangeOp(node, simplified()->BooleanNot());
    return Changed(node);
  } else if (input_type.Is(Type::ReceiverOrNullOrUndefined())) {
    // ToBoolean(x:receiver \/ null \/ undefined)
    //   => BooleanNot(ObjectIsUndetectable(x))
    node->ReplaceInput(
        0, graph()->NewNode(simplified()->ObjectIsUndetectable(), input));
    node->TrimInputCount(1);
    NodeProperties::ChangeOp(node, simplified()->BooleanNot());
    return Changed(node);
  } else if (input_type.Is(Type::String())) {
    // ToBoolean(x:string) => BooleanNot(ReferenceEqual(x,""))
    node->ReplaceInput(0,
                       graph()->NewNode(simplified()->ReferenceEqual(), input,
                                        jsgraph()->EmptyStringConstant()));
    node->TrimInputCount(1);
    NodeProperties::ChangeOp(node, simplified()->BooleanNot());
    return Changed(node);
  }
  return NoChange();
}

namespace {
bool BothAre(Type t1, Type t2, Type t3) { return t1.Is(t3) && t2.Is(t3); }

bool NeitherCanBe(Type t1, Type t2, Type t3) {
  return !t1.Maybe(t3) && !t2.Maybe(t3);
}

const Operator* NumberOpFromSpeculativeNumberOp(
    SimplifiedOperatorBuilder* simplified, const Operator* op) {
  switch (op->opcode()) {
    case IrOpcode::kSpeculativeNumberEqual:
      return simplified->NumberEqual();
    case IrOpcode::kSpeculativeNumberLessThan:
      return simplified->NumberLessThan();
    case IrOpcode::kSpeculativeNumberLessThanOrEqual:
      return simplified->NumberLessThanOrEqual();
    case IrOpcode::kSpeculativeNumberAdd:
      // Handled by ReduceSpeculativeNumberAdd.
      UNREACHABLE();
    case IrOpcode::kSpeculativeNumberSubtract:
      return simplified->NumberSubtract();
    case IrOpcode::kSpeculativeNumberMultiply:
      return simplified->NumberMultiply();
    case IrOpcode::kSpeculativeNumberPow:
      return simplified->NumberPow();
    case IrOpcode::kSpeculativeNumberDivide:
      return simplified->NumberDivide();
    case IrOpcode::kSpeculativeNumberModulus:
      return simplified->NumberModulus();
    default:
      break;
  }
  UNREACHABLE();
}

}  // namespace

Reduction TypedOptimization::ReduceSpeculativeNumberAdd(Node* node) {
  Node* const lhs = NodeProperties::GetValueInput(node, 0);
  Node* const rhs = NodeProperties::GetValueInput(node, 1);
  Type const lhs_type = NodeProperties::GetType(lhs);
  Type const rhs_type = NodeProperties::GetType(rhs);
  NumberOperationHint hint = NumberOperationHintOf(node->op());
  if ((hint == NumberOperationHint::kNumber ||
       hint == NumberOperationHint::kNumberOrOddball) &&
      BothAre(lhs_type, rhs_type, Type::PlainPrimitive()) &&
      NeitherCanBe(lhs_type, rhs_type, Type::StringOrReceiver())) {
    // SpeculativeNumberAdd(x:-string, y:-string) =>
    //     NumberAdd(ToNumber(x), ToNumber(y))
    Node* const toNum_lhs = ConvertPlainPrimitiveToNumber(lhs);
    Node* const toNum_rhs = ConvertPlainPrimitiveToNumber(rhs);
    Node* const value =
        graph()->NewNode(simplified()->NumberAdd(), toNum_lhs, toNum_rhs);
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceJSToNumberInput(Node* input) {
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

Node* TypedOptimization::ConvertPlainPrimitiveToNumber(Node* node) {
  DCHECK(NodeProperties::GetType(node).Is(Type::PlainPrimitive()));
  // Avoid inserting too many eager ToNumber() operations.
  Reduction const reduction = ReduceJSToNumberInput(node);
  if (reduction.Changed()) return reduction.replacement();
  if (NodeProperties::GetType(node).Is(Type::Number())) {
    return node;
  }
  return graph()->NewNode(simplified()->PlainPrimitiveToNumber(), node);
}

Reduction TypedOptimization::ReduceSpeculativeNumberBinop(Node* node) {
  Node* const lhs = NodeProperties::GetValueInput(node, 0);
  Node* const rhs = NodeProperties::GetValueInput(node, 1);
  Type const lhs_type = NodeProperties::GetType(lhs);
  Type const rhs_type = NodeProperties::GetType(rhs);
  NumberOperationHint hint = NumberOperationHintOf(node->op());
  if ((hint == NumberOperationHint::kNumber ||
       hint == NumberOperationHint::kNumberOrOddball) &&
      BothAre(lhs_type, rhs_type, Type::NumberOrOddball())) {
    // We intentionally do this only in the Number and NumberOrOddball hint case
    // because simplified lowering of these speculative ops may do some clever
    // reductions in the other cases.
    Node* const toNum_lhs = ConvertPlainPrimitiveToNumber(lhs);
    Node* const toNum_rhs = ConvertPlainPrimitiveToNumber(rhs);
    Node* const value = graph()->NewNode(
        NumberOpFromSpeculativeNumberOp(simplified(), node->op()), toNum_lhs,
        toNum_rhs);
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  return NoChange();
}

Reduction TypedOptimization::ReduceSpeculativeNumberComparison(Node* node) {
  Node* const lhs = NodeProperties::GetValueInput(node, 0);
  Node* const rhs = NodeProperties::GetValueInput(node, 1);
  Type const lhs_type = NodeProperties::GetType(lhs);
  Type const rhs_type = NodeProperties::GetType(rhs);
  if (BothAre(lhs_type, rhs_type, Type::Signed32()) ||
      BothAre(lhs_type, rhs_type, Type::Unsigned32())) {
    Node* const value = graph()->NewNode(
        NumberOpFromSpeculativeNumberOp(simplified(), node->op()), lhs, rhs);
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  return NoChange();
}

Factory* TypedOptimization::factory() const {
  return jsgraph()->isolate()->factory();
}

Graph* TypedOptimization::graph() const { return jsgraph()->graph(); }

SimplifiedOperatorBuilder* TypedOptimization::simplified() const {
  return jsgraph()->simplified();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```