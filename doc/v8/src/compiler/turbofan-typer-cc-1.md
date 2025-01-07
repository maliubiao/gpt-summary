Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/turbofan-typer.cc`. The code defines a `Typer::Visitor` class and its methods, which seem to be related to determining the data type of intermediate values in the Turbofan compiler.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Class:** The central element is `Typer::Visitor`. The methods within this class are the key to understanding the functionality.

2. **Recognize the Naming Convention:** The methods are named `Type...`, which strongly suggests they are responsible for determining the *type* of a specific *operation* or *node* in the compiler's intermediate representation.

3. **Infer the Context:** The file path `v8/src/compiler/turbofan-typer.cc` clearly indicates this code is part of the Turbofan compiler's type system. The `.cc` extension confirms it's C++ source code.

4. **Analyze Method Functionality (High Level):** Scan through the method names. Many correspond to specific operations in the V8 intermediate representation (e.g., `TypeHeapConstant`, `TypeSelect`, `TypePhi`, `TypeJSAdd`, `TypeJSLoadProperty`, etc.). This reinforces the idea that each method determines the output type of a particular operation.

5. **Identify Key Categories of Operations:** Group the methods based on the types of operations they handle. Obvious categories emerge:
    * **Constants:** `TypeHeapConstant`, `TypeExternalConstant`, etc.
    * **Control Flow:** `TypeSelect`, `TypePhi`, `TypeLoopExit`, etc.
    * **Machine Operations:** `TypeEnterMachineGraph`, `TypeExitMachineGraph`.
    * **JavaScript Operators:**  Many `TypeJS...` methods for arithmetic, comparison, logical, object, context, and other JavaScript operations.
    * **Conversions:**  `TypeToBoolean`, `TypeToNumber`, etc.
    * **Object Manipulation:** `TypeJSCreate...`, `TypeJSLoad...`, `TypeJSSet...`, etc.
    * **Specialized Nodes:** `TypeInductionVariablePhi`, `TypeProjection`, etc.

6. **Look for Specific Logic:**  Notice methods with more complex logic, like `TypeInductionVariablePhi` (handling loop variables) and the comparison operators (e.g., `JSEqualTyper`, `JSCompareTyper`). This indicates the typer handles more sophisticated type inference.

7. **Consider the "Visitor" Pattern:** The class name `Visitor` suggests this class is part of a visitor pattern, where it traverses the compiler's intermediate representation and performs type analysis at each node.

8. **Address the Specific Questions:**
    * **Functionality:** Summarize the core task as determining the type of operations in the Turbofan graph.
    * **Torque:**  The code ends with `.cc`, so it's C++, not Torque.
    * **JavaScript Relationship:** Many methods directly correspond to JavaScript operations. Provide illustrative examples in JavaScript to show the connection.
    * **Code Logic Inference:** The `TypeInductionVariablePhi` method is a good candidate. Describe its logic for inferring the range of loop variables based on initial values and increments. Create a hypothetical input and output.
    * **Common Programming Errors:** Focus on type-related errors that the typer might help detect or prevent, like incorrect assumptions about the type of a variable leading to unexpected behavior.
    * **Overall Function:** Reiterate the core function as performing type analysis in the Turbofan compiler.

9. **Structure the Summary:** Organize the findings logically with clear headings and bullet points for readability. Start with a high-level overview and then delve into more specific details.

10. **Refine and Polish:** Review the summary for clarity, accuracy, and completeness. Ensure it addresses all aspects of the user's prompt. For example, ensure the Javascript examples are clear and relevant, and the hypothetical input/output for `TypeInductionVariablePhi` makes sense.
好的，这是对提供的V8源代码 `v8/src/compiler/turbofan-typer.cc` 第二部分的分析和功能归纳。

**功能归纳 (基于第二部分代码):**

这部分代码主要集中在 `Typer::Visitor` 类中各种 `Type...` 方法的实现。这些方法的核心功能是：

* **为Turbofan编译器中间表示（IR）中的各种节点（操作）推断和确定其输出值的类型。**  每个 `Type` 开头的方法都对应着一种特定的IR节点类型（例如 `HeapConstant`，`Select`，`Phi`，`JSAdd` 等），并根据该节点的操作数（输入）类型和操作本身的语义，计算出该节点输出值的静态类型信息。

* **处理控制流相关的节点类型：** 例如 `TypeSelect` 处理选择节点，返回两个输入类型的并集；`TypePhi` 处理 Phi 节点（通常在控制流合并时出现），返回所有输入类型的并集。

* **专门处理循环结构：** `TypeInductionVariablePhi` 专门用于分析循环归纳变量的类型，它会考虑循环的初始值、增量以及循环的上下界，以更精确地推断归纳变量在循环中的取值范围。这部分逻辑较为复杂，旨在优化循环相关的代码。

* **处理常量：** `TypeHeapConstant`, `TypeTrustedHeapConstant`, `TypeExternalConstant`, `TypePointerConstant`  用于确定各种常量节点的类型。

* **处理机器相关的操作：** `TypeEnterMachineGraph` 和 `TypeExitMachineGraph` 处理进入和退出机器码图的节点，涉及更底层的类型信息。

* **处理JavaScript操作符和内置函数：** 大量的 `TypeJS...` 方法对应着各种JavaScript操作符（例如 `JSAdd`, `JSSubtract`, `JSEqual`, `JSLoadProperty` 等）和内置函数（例如 `DateNow`, `DoubleArrayMin`）。 这些方法模拟了这些操作在类型层面的行为，返回操作结果的可能类型。

* **支持类型收窄和Guard：** `TypeTypeGuard` 和 `TypeMapGuard` 用于处理类型断言和Map Guard，帮助编译器进行更精细的类型推断。

* **处理对象创建和属性访问：**  `TypeJSCreate...` 系列方法用于确定各种对象创建操作的输出类型， `TypeJSLoad...` 和 `TypeJSSet...` 系列方法用于处理属性的读取和写入操作。

* **处理函数调用：** `TypeCall` 和 `TypeFastApiCall` 用于确定函数调用的返回类型，`TypeJSWasmCall` 处理 WebAssembly 函数调用。

* **提供类型操作辅助函数：** 例如 `JSEqualTyper`, `JSStrictEqualTyper`, `JSCompareTyper` 等，用于实现特定JavaScript操作的类型推断逻辑。

* **提供类型弱化机制：** `Weaken` 方法用于在类型推断过程中，如果遇到可能导致无限循环的情况，适当放宽类型的范围，以加速定点计算的收敛。

**与其他部分的关系:**

这部分代码是 `v8/src/compiler/turbofan-typer.cc` 的一部分，因此它与该文件中的其他部分紧密相关，共同构成了 Turbofan 编译器的类型推断系统。 第一部分可能包含了 `Typer` 类和 `Typer::Visitor` 类的声明，以及一些基础的类型定义和辅助函数。第三部分可能包含更多 `Type...` 方法的实现，或者与类型推断的收敛、缓存等相关的逻辑。

**与JavaScript的功能关系以及示例:**

这部分代码中的很多方法都直接对应着JavaScript的运行时行为。

**例子 1: `TypeJSAddTyper` 和加法操作符**

```javascript
function add(a, b) {
  return a + b;
}

// 假设 Typer::Visitor 在分析 'a + b' 这个操作时，
// 调用了 TypeJSAddTyper，并且已知 a 的类型是 Number，b 的类型是 Number，
// 那么 TypeJSAddTyper 会返回 Number 类型。

// 如果 a 的类型是 String，b 的类型是 Number，
// 那么 TypeJSAddTyper 会返回 String 类型 (因为 JavaScript 中 + 可以做字符串拼接)。

// 如果 a 的类型是 String，b 的类型是 String，
// 那么 TypeJSAddTyper 也会返回 String 类型。
```

**例子 2: `TypeJSLoadProperty` 和属性访问**

```javascript
function getProperty(obj, key) {
  return obj[key];
}

// 假设 Typer::Visitor 在分析 'obj[key]' 这个操作时，
// 调用了 TypeJSLoadProperty。由于我们无法静态地确定 'key' 的值，
// 并且 'obj' 的类型可能比较宽泛，TypeJSLoadProperty 通常会返回一个比较宽泛的类型，
// 例如 Type::Any() 或者 Type::NonInternal()，表示可以是任何非内部对象的值。
```

**代码逻辑推理示例:**

**假设输入 (针对 `TypeInductionVariablePhi`):**

* 一个循环的控制节点。
* 一个 `InductionVariablePhi` 节点 `phi`，代表循环中的一个归纳变量。
* `phi` 的初始值来自一个类型为 `Range(0, 10, zone())` 的节点（表示 0 到 10 的整数范围）。
* `phi` 的增量来自一个类型为 `Singleton(1)` 的节点（表示常量 1）。
* 循环的上界由一个类型为 `Range(15, 20, zone())` 的节点控制。

**预期输出:**

`TypeInductionVariablePhi` 可能会推断出 `phi` 在循环中的类型为 `Range(0, 20, zone())` 或者更精确的范围，例如考虑到严格上界可能是 `Range(0, 19, zone())`。  这是因为归纳变量从 0 开始，每次增加 1，并且循环会在某个小于等于 20 的值时结束。

**用户常见的编程错误示例:**

* **类型假设错误导致运算错误:**

```javascript
function calculate(input) {
  return input + 5;
}

// 用户可能期望 input 是一个数字，但是如果 input 实际上是一个字符串，
// 例如 "3"，那么 JavaScript 的 '+' 操作符会执行字符串拼接，结果是 "35" 而不是 8。
// 类型推断可以帮助在编译时发现这种潜在的类型不匹配问题。
```

* **未考虑 `null` 或 `undefined` 导致的属性访问错误:**

```javascript
function getNameLength(obj) {
  return obj.name.length;
}

// 如果调用 `getNameLength(null)` 或 `getNameLength(undefined)`，
// 会抛出 "TypeError: Cannot read properties of null (or undefined) (reading 'name')" 错误。
// 类型推断如果能识别出 `obj` 可能为 `null` 或 `undefined`，
// 就可以帮助优化器生成更安全的代码，或者在开发阶段提示潜在的错误。
```

总而言之，这部分代码是 Turbofan 编译器进行关键类型分析的核心组成部分，它为后续的优化和代码生成提供了重要的类型信息基础。

Prompt: 
```
这是目录为v8/src/compiler/turbofan-typer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turbofan-typer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
ant(HeapConstantOf(node->op()));
}

Type Typer::Visitor::TypeCompressedHeapConstant(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeTrustedHeapConstant(Node* node) {
  return TypeConstant(HeapConstantOf(node->op()));
}

Type Typer::Visitor::TypeExternalConstant(Node* node) {
  return Type::ExternalPointer();
}

Type Typer::Visitor::TypePointerConstant(Node* node) {
  return Type::ExternalPointer();
}

Type Typer::Visitor::TypeSelect(Node* node) {
  return Type::Union(Operand(node, 1), Operand(node, 2), zone());
}

Type Typer::Visitor::TypePhi(Node* node) {
  int arity = node->op()->ValueInputCount();
  Type type = Operand(node, 0);
  for (int i = 1; i < arity; ++i) {
    type = Type::Union(type, Operand(node, i), zone());
  }
  return type;
}

Type Typer::Visitor::TypeEnterMachineGraph(Node* node) {
  return Type::Machine();
}

Type Typer::Visitor::TypeExitMachineGraph(Node* node) {
  return ExitMachineGraphParametersOf(node->op()).output_type();
}

Type Typer::Visitor::TypeInductionVariablePhi(Node* node) {
  int arity = NodeProperties::GetControlInput(node)->op()->ControlInputCount();
  DCHECK_EQ(IrOpcode::kLoop, NodeProperties::GetControlInput(node)->opcode());
  DCHECK_EQ(2, NodeProperties::GetControlInput(node)->InputCount());

  Type initial_type = Operand(node, 0);
  Type increment_type = Operand(node, 2);

  // Fallback to normal phi typing in a variety of cases:
  // - when the induction variable is not initially of type Integer, because we
  //   want to work with ranges in the algorithm below.
  // - when the increment is zero, because in that case normal phi typing will
  //   generally yield a more precise type.
  // - when the induction variable can become NaN (through addition/subtraction
  //   of opposing infinities), because the code below can't handle that case.
  if (initial_type.IsNone() ||
      increment_type.Is(typer_->cache_->kSingletonZero) ||
      !initial_type.Is(typer_->cache_->kInteger) ||
      !increment_type.Is(typer_->cache_->kInteger) ||
      increment_type.Min() == -V8_INFINITY ||
      increment_type.Max() == +V8_INFINITY) {
    // Unfortunately, without baking in the previous type, monotonicity might be
    // violated because we might not yet have retyped the incrementing operation
    // even though the increment's type might been already reflected in the
    // induction variable phi.
    Type type = NodeProperties::IsTyped(node) ? NodeProperties::GetType(node)
                                              : Type::None();
    for (int i = 0; i < arity; ++i) {
      type = Type::Union(type, Operand(node, i), zone());
    }
    return type;
  }

  auto res = induction_vars_->induction_variables().find(node->id());
  DCHECK_NE(res, induction_vars_->induction_variables().end());
  InductionVariable* induction_var = res->second;
  InductionVariable::ArithmeticType arithmetic_type = induction_var->Type();

  double min = -V8_INFINITY;
  double max = V8_INFINITY;

  double increment_min;
  double increment_max;
  if (arithmetic_type == InductionVariable::ArithmeticType::kAddition) {
    increment_min = increment_type.Min();
    increment_max = increment_type.Max();
  } else {
    DCHECK_EQ(arithmetic_type, InductionVariable::ArithmeticType::kSubtraction);
    increment_min = -increment_type.Max();
    increment_max = -increment_type.Min();
  }

  if (increment_min >= 0) {
    // Increasing sequence.
    min = initial_type.Min();
    for (auto bound : induction_var->upper_bounds()) {
      Type bound_type = TypeOrNone(bound.bound);
      // If the type is not an integer, just skip the bound.
      if (!bound_type.Is(typer_->cache_->kInteger)) continue;
      // If the type is not inhabited, then we can take the initial value.
      if (bound_type.IsNone()) {
        max = initial_type.Max();
        break;
      }
      double bound_max = bound_type.Max();
      if (bound.kind == InductionVariable::kStrict) {
        bound_max -= 1;
      }
      max = std::min(max, bound_max + increment_max);
    }
    // The upper bound must be at least the initial value's upper bound.
    max = std::max(max, initial_type.Max());
  } else if (increment_max <= 0) {
    // Decreasing sequence.
    max = initial_type.Max();
    for (auto bound : induction_var->lower_bounds()) {
      Type bound_type = TypeOrNone(bound.bound);
      // If the type is not an integer, just skip the bound.
      if (!bound_type.Is(typer_->cache_->kInteger)) continue;
      // If the type is not inhabited, then we can take the initial value.
      if (bound_type.IsNone()) {
        min = initial_type.Min();
        break;
      }
      double bound_min = bound_type.Min();
      if (bound.kind == InductionVariable::kStrict) {
        bound_min += 1;
      }
      min = std::max(min, bound_min + increment_min);
    }
    // The lower bound must be at most the initial value's lower bound.
    min = std::min(min, initial_type.Min());
  } else {
    // If the increment can be both positive and negative, the variable can go
    // arbitrarily far. Use the maximal range in that case. Note that this may
    // be less precise than what ordinary typing would produce.
    min = -V8_INFINITY;
    max = +V8_INFINITY;
  }

  if (v8_flags.trace_turbo_loop) {
    StdoutStream{} << std::setprecision(10) << "Loop ("
                   << NodeProperties::GetControlInput(node)->id()
                   << ") variable bounds in "
                   << (arithmetic_type ==
                               InductionVariable::ArithmeticType::kAddition
                           ? "addition"
                           : "subtraction")
                   << " for phi " << node->id() << ": (" << min << ", " << max
                   << ")\n";
  }

  return Type::Range(min, max, typer_->zone());
}

bool Typer::Visitor::InductionVariablePhiTypeIsPrefixedPoint(
    InductionVariable* induction_var) {
  Node* node = induction_var->phi();
  DCHECK_EQ(node->opcode(), IrOpcode::kInductionVariablePhi);
  Node* arith = node->InputAt(1);
  Type type = NodeProperties::GetType(node);
  Type initial_type = Operand(node, 0);
  Type arith_type = Operand(node, 1);
  Type increment_type = Operand(node, 2);

  // Intersect {type} with useful bounds.
  for (auto bound : induction_var->upper_bounds()) {
    Type bound_type = TypeOrNone(bound.bound);
    if (!bound_type.Is(typer_->cache_->kInteger)) continue;
    if (!bound_type.IsNone()) {
      bound_type = Type::Range(
          -V8_INFINITY,
          bound_type.Max() - (bound.kind == InductionVariable::kStrict),
          zone());
    }
    type = Type::Intersect(type, bound_type, typer_->zone());
  }
  for (auto bound : induction_var->lower_bounds()) {
    Type bound_type = TypeOrNone(bound.bound);
    if (!bound_type.Is(typer_->cache_->kInteger)) continue;
    if (!bound_type.IsNone()) {
      bound_type = Type::Range(
          bound_type.Min() + (bound.kind == InductionVariable::kStrict),
          +V8_INFINITY, typer_->zone());
    }
    type = Type::Intersect(type, bound_type, typer_->zone());
  }

  if (arith_type.IsNone()) {
    type = Type::None();
  } else {
    // We support a few additional type conversions on the lhs of the arithmetic
    // operation. This needs to be kept in sync with the corresponding code in
    // {LoopVariableOptimizer::TryGetInductionVariable}.
    Node* arith_input = arith->InputAt(0);
    switch (arith_input->opcode()) {
      case IrOpcode::kSpeculativeToNumber:
        type = typer_->operation_typer_.SpeculativeToNumber(type);
        break;
      case IrOpcode::kJSToNumber:
        type = typer_->operation_typer_.ToNumber(type);
        break;
      case IrOpcode::kJSToNumberConvertBigInt:
        type = typer_->operation_typer_.ToNumberConvertBigInt(type);
        break;
      default:
        break;
    }

    // Apply ordinary typing to the "increment" operation.
    // clang-format off
    switch (arith->opcode()) {
#define CASE(x)                             \
      case IrOpcode::k##x:                    \
        type = Type##x(type, increment_type); \
        break;
      CASE(JSAdd)
      CASE(JSSubtract)
      CASE(NumberAdd)
      CASE(NumberSubtract)
      CASE(SpeculativeNumberAdd)
      CASE(SpeculativeNumberSubtract)
      CASE(SpeculativeSafeIntegerAdd)
      CASE(SpeculativeSafeIntegerSubtract)
#undef CASE
      default:
        UNREACHABLE();
    }
    // clang-format on
  }

  type = Type::Union(initial_type, type, typer_->zone());

  return type.Is(NodeProperties::GetType(node));
}

Type Typer::Visitor::TypeEffectPhi(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeLoopExit(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeLoopExitValue(Node* node) { return Operand(node, 0); }

Type Typer::Visitor::TypeLoopExitEffect(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeEnsureWritableFastElements(Node* node) {
  return Operand(node, 1);
}

Type Typer::Visitor::TypeMaybeGrowFastElements(Node* node) {
  return Operand(node, 1);
}

Type Typer::Visitor::TypeTransitionElementsKind(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeCheckpoint(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeBeginRegion(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeFinishRegion(Node* node) { return Operand(node, 0); }

Type Typer::Visitor::TypeFrameState(Node* node) {
  // TODO(rossberg): Ideally FrameState wouldn't have a value output.
  return Type::Internal();
}

Type Typer::Visitor::TypeStateValues(Node* node) { return Type::Internal(); }

Type Typer::Visitor::TypeTypedStateValues(Node* node) {
  return Type::Internal();
}

Type Typer::Visitor::TypeObjectId(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeArgumentsElementsState(Node* node) {
  return Type::Internal();
}

Type Typer::Visitor::TypeArgumentsLengthState(Node* node) {
  return Type::Internal();
}

Type Typer::Visitor::TypeObjectState(Node* node) { return Type::Internal(); }

Type Typer::Visitor::TypeTypedObjectState(Node* node) {
  return Type::Internal();
}

Type Typer::Visitor::TypeCall(Node* node) { return Type::Any(); }

Type Typer::Visitor::TypeFastApiCall(Node* node) {
  FastApiCallParameters const& op_params = FastApiCallParametersOf(node->op());

  const CFunctionInfo* c_signature = op_params.c_function().signature;
  CTypeInfo return_type = c_signature->ReturnInfo();

  switch (return_type.GetType()) {
    case CTypeInfo::Type::kBool:
      return Type::Boolean();
    case CTypeInfo::Type::kFloat32:
    case CTypeInfo::Type::kFloat64:
      return Type::Number();
    case CTypeInfo::Type::kInt32:
      return Type::Signed32();
    case CTypeInfo::Type::kInt64:
      if (c_signature->GetInt64Representation() ==
          CFunctionInfo::Int64Representation::kBigInt) {
        return Type::SignedBigInt64();
      }
      DCHECK_EQ(c_signature->GetInt64Representation(),
                CFunctionInfo::Int64Representation::kNumber);
      return Type::Number();
    case CTypeInfo::Type::kSeqOneByteString:
      return Type::String();
    case CTypeInfo::Type::kUint32:
      return Type::Unsigned32();
    case CTypeInfo::Type::kUint64:
      if (c_signature->GetInt64Representation() ==
          CFunctionInfo::Int64Representation::kBigInt) {
        return Type::UnsignedBigInt64();
      }
      DCHECK_EQ(c_signature->GetInt64Representation(),
                CFunctionInfo::Int64Representation::kNumber);
      return Type::Number();
    case CTypeInfo::Type::kUint8:
      return Type::UnsignedSmall();
    case CTypeInfo::Type::kAny:
      // This type is only supposed to be used for parameters, not returns.
      UNREACHABLE();
    case CTypeInfo::Type::kPointer:
    case CTypeInfo::Type::kApiObject:
    case CTypeInfo::Type::kV8Value:
    case CTypeInfo::Type::kVoid:
      return Type::Any();
  }
}

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
Type Typer::Visitor::TypeGetContinuationPreservedEmbedderData(Node* node) {
  return Type::Any();
}

Type Typer::Visitor::TypeSetContinuationPreservedEmbedderData(Node* node) {
  UNREACHABLE();
}
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

#if V8_ENABLE_WEBASSEMBLY
Type Typer::Visitor::TypeJSWasmCall(Node* node) {
  const JSWasmCallParameters& op_params = JSWasmCallParametersOf(node->op());
  const wasm::CanonicalSig* wasm_signature = op_params.signature();
  if (wasm_signature->return_count() > 0) {
    return JSWasmCallNode::TypeForWasmReturnType(wasm_signature->GetReturn());
  }
  return Type::Any();
}
#endif  // V8_ENABLE_WEBASSEMBLY

Type Typer::Visitor::TypeProjection(Node* node) {
  Type const type = Operand(node, 0);
  if (type.Is(Type::None())) return Type::None();
  int const index = static_cast<int>(ProjectionIndexOf(node->op()));
  if (type.IsTuple() && index < type.AsTuple()->Arity()) {
    return type.AsTuple()->Element(index);
  }
  return Type::Any();
}

Type Typer::Visitor::TypeMapGuard(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeTypeGuard(Node* node) {
  Type const type = Operand(node, 0);
  return typer_->operation_typer()->TypeTypeGuard(node->op(), type);
}

Type Typer::Visitor::TypeDead(Node* node) { return Type::None(); }
Type Typer::Visitor::TypeDeadValue(Node* node) { return Type::None(); }
Type Typer::Visitor::TypeUnreachable(Node* node) { return Type::None(); }

Type Typer::Visitor::TypePlug(Node* node) { UNREACHABLE(); }
Type Typer::Visitor::TypeStaticAssert(Node* node) { UNREACHABLE(); }
Type Typer::Visitor::TypeSLVerifierHint(Node* node) { UNREACHABLE(); }

// JS comparison operators.

Type Typer::Visitor::JSEqualTyper(Type lhs, Type rhs, Typer* t) {
  if (lhs.IsNone() || rhs.IsNone()) return Type::None();
  if (lhs.Is(Type::NaN()) || rhs.Is(Type::NaN())) return t->singleton_false_;
  if (lhs.Is(Type::NullOrUndefined()) && rhs.Is(Type::NullOrUndefined())) {
    return t->singleton_true_;
  }
  if (lhs.Is(Type::Number()) && rhs.Is(Type::Number()) &&
      (lhs.Max() < rhs.Min() || lhs.Min() > rhs.Max())) {
    return t->singleton_false_;
  }
  if (lhs.IsSingleton() && rhs.Is(lhs)) {
    // Types are equal and are inhabited only by a single semantic value,
    // which is not nan due to the earlier check.
    DCHECK(lhs.Is(rhs));
    return t->singleton_true_;
  }
  return Type::Boolean();
}

Type Typer::Visitor::JSStrictEqualTyper(Type lhs, Type rhs, Typer* t) {
  return t->operation_typer()->StrictEqual(lhs, rhs);
}

// The ECMAScript specification defines the four relational comparison operators
// (<, <=, >=, >) with the help of a single abstract one.  It behaves like <
// but returns undefined when the inputs cannot be compared.
// We implement the typing analogously.
Typer::Visitor::ComparisonOutcome Typer::Visitor::JSCompareTyper(Type lhs,
                                                                 Type rhs,
                                                                 Typer* t) {
  lhs = ToPrimitive(lhs, t);
  rhs = ToPrimitive(rhs, t);
  if (lhs.Maybe(Type::String()) && rhs.Maybe(Type::String())) {
    return ComparisonOutcome(kComparisonTrue) |
           ComparisonOutcome(kComparisonFalse);
  }
  lhs = ToNumeric(lhs, t);
  rhs = ToNumeric(rhs, t);
  if (lhs.Is(Type::Number()) && rhs.Is(Type::Number())) {
    return NumberCompareTyper(lhs, rhs, t);
  }
  return ComparisonOutcome(kComparisonTrue) |
         ComparisonOutcome(kComparisonFalse) |
         ComparisonOutcome(kComparisonUndefined);
}

Typer::Visitor::ComparisonOutcome Typer::Visitor::NumberCompareTyper(Type lhs,
                                                                     Type rhs,
                                                                     Typer* t) {
  DCHECK(lhs.Is(Type::Number()));
  DCHECK(rhs.Is(Type::Number()));

  if (lhs.IsNone() || rhs.IsNone()) return {};

  // Shortcut for NaNs.
  if (lhs.Is(Type::NaN()) || rhs.Is(Type::NaN())) return kComparisonUndefined;

  ComparisonOutcome result;
  if (lhs.IsHeapConstant() && rhs.Is(lhs)) {
    // Types are equal and are inhabited only by a single semantic value.
    result = kComparisonFalse;
  } else if (lhs.Min() >= rhs.Max()) {
    result = kComparisonFalse;
  } else if (lhs.Max() < rhs.Min()) {
    result = kComparisonTrue;
  } else {
    return ComparisonOutcome(kComparisonTrue) |
           ComparisonOutcome(kComparisonFalse) |
           ComparisonOutcome(kComparisonUndefined);
  }
  // Add the undefined if we could see NaN.
  if (lhs.Maybe(Type::NaN()) || rhs.Maybe(Type::NaN())) {
    result |= kComparisonUndefined;
  }
  return result;
}

Type Typer::Visitor::JSLessThanTyper(Type lhs, Type rhs, Typer* t) {
  return FalsifyUndefined(JSCompareTyper(lhs, rhs, t), t);
}

Type Typer::Visitor::JSGreaterThanTyper(Type lhs, Type rhs, Typer* t) {
  return FalsifyUndefined(JSCompareTyper(rhs, lhs, t), t);
}

Type Typer::Visitor::JSLessThanOrEqualTyper(Type lhs, Type rhs, Typer* t) {
  return FalsifyUndefined(Invert(JSCompareTyper(rhs, lhs, t), t), t);
}

Type Typer::Visitor::JSGreaterThanOrEqualTyper(Type lhs, Type rhs, Typer* t) {
  return FalsifyUndefined(Invert(JSCompareTyper(lhs, rhs, t), t), t);
}

// JS bitwise operators.

Type Typer::Visitor::JSBitwiseOrTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberBitwiseOr);
}

Type Typer::Visitor::JSBitwiseAndTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberBitwiseAnd);
}

Type Typer::Visitor::JSBitwiseXorTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberBitwiseXor);
}

Type Typer::Visitor::JSShiftLeftTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberShiftLeft);
}

Type Typer::Visitor::JSShiftRightTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberShiftRight);
}

Type Typer::Visitor::JSShiftRightLogicalTyper(Type lhs, Type rhs, Typer* t) {
  return NumberShiftRightLogical(ToNumber(lhs, t), ToNumber(rhs, t), t);
}

// JS arithmetic operators.

Type Typer::Visitor::JSAddTyper(Type lhs, Type rhs, Typer* t) {
  lhs = ToPrimitive(lhs, t);
  rhs = ToPrimitive(rhs, t);
  if (lhs.Maybe(Type::String()) || rhs.Maybe(Type::String())) {
    if (lhs.Is(Type::String()) || rhs.Is(Type::String())) {
      return Type::String();
    } else {
      return Type::NumericOrString();
    }
  }
  // The addition must be numeric.
  return BinaryNumberOpTyper(lhs, rhs, t, NumberAdd);
}

Type Typer::Visitor::JSSubtractTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberSubtract);
}

Type Typer::Visitor::JSMultiplyTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberMultiply);
}

Type Typer::Visitor::JSDivideTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberDivide);
}

Type Typer::Visitor::JSModulusTyper(Type lhs, Type rhs, Typer* t) {
  return BinaryNumberOpTyper(lhs, rhs, t, NumberModulus);
}

Type Typer::Visitor::JSExponentiateTyper(Type lhs, Type rhs, Typer* t) {
  // TODO(neis): Refine using BinaryNumberOpTyper?
  return Type::Numeric();
}

// JS unary operators.

#define DEFINE_METHOD(Name)                       \
  Type Typer::Visitor::TypeJS##Name(Type input) { \
    return TypeUnaryOp(input, Name);              \
  }
DEFINE_METHOD(BitwiseNot)
DEFINE_METHOD(Decrement)
DEFINE_METHOD(Increment)
DEFINE_METHOD(Negate)
DEFINE_METHOD(ToLength)
DEFINE_METHOD(ToName)
DEFINE_METHOD(ToNumber)
DEFINE_METHOD(ToNumberConvertBigInt)
DEFINE_METHOD(ToBigInt)
DEFINE_METHOD(ToBigIntConvertNumber)
DEFINE_METHOD(ToNumeric)
DEFINE_METHOD(ToObject)
DEFINE_METHOD(ToString)
#undef DEFINE_METHOD

Type Typer::Visitor::TypeTypeOf(Node* node) {
  return Type::InternalizedString();
}

// JS conversion operators.

Type Typer::Visitor::TypeToBoolean(Node* node) {
  return TypeUnaryOp(node, ToBoolean);
}

// JS object operators.

Type Typer::Visitor::TypeJSCreate(Node* node) { return Type::Object(); }

Type Typer::Visitor::TypeJSCreateArguments(Node* node) {
  switch (CreateArgumentsTypeOf(node->op())) {
    case CreateArgumentsType::kRestParameter:
      return Type::Array();
    case CreateArgumentsType::kMappedArguments:
    case CreateArgumentsType::kUnmappedArguments:
      return Type::OtherObject();
  }
  UNREACHABLE();
}

Type Typer::Visitor::TypeJSCreateArray(Node* node) { return Type::Array(); }

Type Typer::Visitor::TypeJSCreateArrayIterator(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateAsyncFunctionObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateCollectionIterator(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateBoundFunction(Node* node) {
  return Type::BoundFunction();
}

Type Typer::Visitor::TypeJSCreateGeneratorObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateClosure(Node* node) {
  SharedFunctionInfoRef shared =
      JSCreateClosureNode{node}.Parameters().shared_info();
  if (IsClassConstructor(shared.kind())) {
    return Type::ClassConstructor();
  } else {
    return Type::CallableFunction();
  }
}

Type Typer::Visitor::TypeJSCreateIterResultObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateStringIterator(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateKeyValueArray(Node* node) {
  return Type::Array();
}

Type Typer::Visitor::TypeJSCreateObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateStringWrapper(Node* node) {
  return Type::StringWrapper();
}

Type Typer::Visitor::TypeJSCreatePromise(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateTypedArray(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateLiteralArray(Node* node) {
  return Type::Array();
}

Type Typer::Visitor::TypeJSCreateEmptyLiteralArray(Node* node) {
  return Type::Array();
}

Type Typer::Visitor::TypeJSCreateArrayFromIterable(Node* node) {
  return Type::Array();
}

Type Typer::Visitor::TypeJSCreateLiteralObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateEmptyLiteralObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCloneObject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSCreateLiteralRegExp(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSGetTemplateObject(Node* node) {
  return Type::Array();
}

Type Typer::Visitor::TypeJSLoadProperty(Node* node) { return Type::Any(); }

Type Typer::Visitor::TypeJSLoadNamed(Node* node) {
#ifdef DEBUG
  // Loading of private methods is compiled to a named load of a BlockContext
  // via a private brand, which is an internal object. However, native context
  // specialization should always apply for those cases, so assert that the name
  // is not a private brand here. Otherwise Type::NonInternal() is wrong.
  JSLoadNamedNode n(node);
  NamedAccess const& p = n.Parameters();
  DCHECK(!p.name().object()->IsPrivateBrand());
#endif
  return Type::NonInternal();
}

Type Typer::Visitor::TypeJSLoadNamedFromSuper(Node* node) {
  return Type::NonInternal();
}

Type Typer::Visitor::TypeJSLoadGlobal(Node* node) {
  return Type::NonInternal();
}

Type Typer::Visitor::TypeJSParseInt(Type input) { return Type::Number(); }

Type Typer::Visitor::TypeJSRegExpTest(Node* node) { return Type::Boolean(); }

// Returns a somewhat larger range if we previously assigned
// a (smaller) range to this node. This is used  to speed up
// the fixpoint calculation in case there appears to be a loop
// in the graph. In the current implementation, we are
// increasing the limits to the closest power of two.
Type Typer::Visitor::Weaken(Node* node, Type current_type, Type previous_type) {
  static const double kWeakenMinLimits[] = {0.0,
                                            -1073741824.0,
                                            -2147483648.0,
                                            -4294967296.0,
                                            -8589934592.0,
                                            -17179869184.0,
                                            -34359738368.0,
                                            -68719476736.0,
                                            -137438953472.0,
                                            -274877906944.0,
                                            -549755813888.0,
                                            -1099511627776.0,
                                            -2199023255552.0,
                                            -4398046511104.0,
                                            -8796093022208.0,
                                            -17592186044416.0,
                                            -35184372088832.0,
                                            -70368744177664.0,
                                            -140737488355328.0,
                                            -281474976710656.0,
                                            -562949953421312.0};
  static const double kWeakenMaxLimits[] = {0.0,
                                            1073741823.0,
                                            2147483647.0,
                                            4294967295.0,
                                            8589934591.0,
                                            17179869183.0,
                                            34359738367.0,
                                            68719476735.0,
                                            137438953471.0,
                                            274877906943.0,
                                            549755813887.0,
                                            1099511627775.0,
                                            2199023255551.0,
                                            4398046511103.0,
                                            8796093022207.0,
                                            17592186044415.0,
                                            35184372088831.0,
                                            70368744177663.0,
                                            140737488355327.0,
                                            281474976710655.0,
                                            562949953421311.0};
  static_assert(arraysize(kWeakenMinLimits) == arraysize(kWeakenMaxLimits));

  // If the types have nothing to do with integers, return the types.
  Type const integer = typer_->cache_->kInteger;
  if (!previous_type.Maybe(integer)) {
    return current_type;
  }
  DCHECK(current_type.Maybe(integer));

  Type current_integer = Type::Intersect(current_type, integer, zone());
  Type previous_integer = Type::Intersect(previous_type, integer, zone());

  // Once we start weakening a node, we should always weaken.
  if (!IsWeakened(node->id())) {
    // Only weaken if there is range involved; we should converge quickly
    // for all other types (the exception is a union of many constants,
    // but we currently do not increase the number of constants in unions).
    Type previous = previous_integer.GetRange();
    Type current = current_integer.GetRange();
    if (current.IsInvalid() || previous.IsInvalid()) {
      return current_type;
    }
    // Range is involved => we are weakening.
    SetWeakened(node->id());
  }

  double current_min = current_integer.Min();
  double new_min = current_min;
  // Find the closest lower entry in the list of allowed
  // minima (or negative infinity if there is no such entry).
  if (current_min != previous_integer.Min()) {
    new_min = -V8_INFINITY;
    for (double const min : kWeakenMinLimits) {
      if (min <= current_min) {
        new_min = min;
        break;
      }
    }
  }

  double current_max = current_integer.Max();
  double new_max = current_max;
  // Find the closest greater entry in the list of allowed
  // maxima (or infinity if there is no such entry).
  if (current_max != previous_integer.Max()) {
    new_max = V8_INFINITY;
    for (double const max : kWeakenMaxLimits) {
      if (max >= current_max) {
        new_max = max;
        break;
      }
    }
  }

  return Type::Union(current_type,
                     Type::Range(new_min, new_max, typer_->zone()),
                     typer_->zone());
}

Type Typer::Visitor::TypeJSSetKeyedProperty(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSDefineKeyedOwnProperty(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSSetNamedProperty(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSStoreGlobal(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSDefineNamedOwnProperty(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSDefineKeyedOwnPropertyInLiteral(Node* node) {
  UNREACHABLE();
}

Type Typer::Visitor::TypeJSStoreInArrayLiteral(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSDeleteProperty(Node* node) {
  return Type::Boolean();
}

Type Typer::Visitor::TypeJSHasProperty(Node* node) { return Type::Boolean(); }

// JS instanceof operator.

Type Typer::Visitor::JSHasInPrototypeChainTyper(Type lhs, Type rhs, Typer* t) {
  return Type::Boolean();
}

Type Typer::Visitor::JSInstanceOfTyper(Type lhs, Type rhs, Typer* t) {
  return Type::Boolean();
}

Type Typer::Visitor::JSOrdinaryHasInstanceTyper(Type lhs, Type rhs, Typer* t) {
  return Type::Boolean();
}

Type Typer::Visitor::TypeJSGetSuperConstructor(Node* node) {
  return Type::NonInternal();
}

Type Typer::Visitor::TypeJSFindNonDefaultConstructorOrConstruct(Node* node) {
  return Type::Tuple(Type::Boolean(), Type::ReceiverOrNull(), zone());
}

// JS context operators.
Type Typer::Visitor::TypeJSHasContextExtension(Node* node) {
  return Type::Boolean();
}

Type Typer::Visitor::TypeJSLoadContext(Node* node) {
  ContextAccess const& access = ContextAccessOf(node->op());
  switch (access.index()) {
    case Context::PREVIOUS_INDEX:
    case Context::SCOPE_INFO_INDEX:
      return Type::OtherInternal();
    default:
      return Type::Any();
  }
}

Type Typer::Visitor::TypeJSLoadScriptContext(Node* node) {
  ContextAccess const& access = ContextAccessOf(node->op());
  switch (access.index()) {
    case Context::PREVIOUS_INDEX:
    case Context::SCOPE_INFO_INDEX:
    case Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX:
      return Type::OtherInternal();
    default:
      return Type::Any();
  }
}

Type Typer::Visitor::TypeJSStoreContext(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSStoreScriptContext(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSCreateFunctionContext(Node* node) {
  return Type::OtherInternal();
}

Type Typer::Visitor::TypeJSCreateCatchContext(Node* node) {
  return Type::OtherInternal();
}

Type Typer::Visitor::TypeJSCreateWithContext(Node* node) {
  return Type::OtherInternal();
}

Type Typer::Visitor::TypeJSCreateBlockContext(Node* node) {
  return Type::OtherInternal();
}

// JS other operators.

Type Typer::Visitor::TypeJSConstructForwardVarargs(Node* node) {
  return Type::Receiver();
}

Type Typer::Visitor::TypeJSConstructForwardAllArgs(Node* node) {
  return Type::Receiver();
}

Type Typer::Visitor::TypeJSConstruct(Node* node) { return Type::Receiver(); }

Type Typer::Visitor::TypeJSConstructWithArrayLike(Node* node) {
  return Type::Receiver();
}

Type Typer::Visitor::TypeJSConstructWithSpread(Node* node) {
  return Type::Receiver();
}

Type Typer::Visitor::TypeJSObjectIsArray(Node* node) { return Type::Boolean(); }

Type Typer::Visitor::TypeDateNow(Node* node) { return Type::Number(); }

Type Typer::Visitor::TypeDoubleArrayMin(Node* node) { return Type::Number(); }

Type Typer::Visitor::TypeDoubleArrayMax(Node* node) { return Type::Number(); }

Type Typer::Visitor::TypeUnsigned32Divide(Node* node) {
  Type lhs = Operand(node, 0);
  return Type::Range(0, lhs.Max(), zone());
}

Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
  if (!fun.IsHeapConstant() || !fun.AsHeapConstant()->Ref().IsJSFunction()) {
    return Type::NonInternal();
  }
  JSFunctionRef function = fun.AsHeapConstant()->Ref().AsJSFunction();
  if (!function.shared(t->broker()).HasBuiltinId()) {
    return Type::NonInternal();
  }
  switch (function.shared(t->broker()).builtin_id()) {
    case Builtin::kMathRandom:
      return Type::PlainNumber();
    case Builtin::kMathFloor:
    case Builtin::kMathCeil:
    case Builtin::kMathRound:
    case Builtin::kMathTrunc:
      return t->cache_->kIntegerOrMinusZeroOrNaN;
    // Unary math functions.
    case Builtin::kMathAbs:
    case Builtin::kMathExp:
      return Type::Union(Type::PlainNumber(), Type::NaN(), t->zone());
    case Builtin::kMathAcos:
    case Builtin::kMathAcosh:
    case Builtin::kMathAsin:
    case Builtin::kMathAsinh:
    case Builtin::kMathAtan:
    case Builtin::kMathAtanh:
    case Bu
"""


```