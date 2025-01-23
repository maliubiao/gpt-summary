Response: The user is asking for a summary of the C++ code provided in the file `v8/src/maglev/maglev-graph-builder.cc`. This is the second part of a larger file. The goal is to understand the functionality implemented in this specific chunk of code and illustrate its connection to JavaScript, if any.

**Breakdown of the code:**

The code mainly deals with converting between different data representations used in V8's Maglev compiler and performing arithmetic and comparison operations. Key areas include:

1. **Type Conversions:** Functions like `GetTruncatedInt32ForToNumber`, `GetInt32`, `GetFloat64`, `GetHoleyFloat64ForToNumber`, and `GetUint8ClampedForToNumber` are responsible for converting values to specific representations (Int32, Float64, etc.). These conversions often involve checks and potential deoptimizations if the value doesn't fit the target representation.
2. **Constant Handling:**  Functions like `TryGetInt32Constant`, `TryGetUint32Constant`, and `TryGetFloat64Constant` attempt to extract constant values from `ValueNode`s. This is important for constant folding optimizations.
3. **Arithmetic Operations:**  The code defines templates for building nodes representing various arithmetic operations (`BuildGenericUnaryOperationNode`, `BuildGenericBinaryOperationNode`, `BuildInt32UnaryOperationNode`, `BuildInt32BinaryOperationNode`, `BuildFloat64UnaryOperationNodeForToNumber`, `BuildFloat64BinaryOperationNodeForToNumber`). It also includes logic for constant folding these operations.
4. **Comparison Operations:**  The `VisitCompareOperation` function handles building comparison nodes, including optimizations for comparing against constants and specialized handling for strings and symbols.
5. **Context Slot Access:** Functions like `BuildLoadContextSlot`, `BuildStoreContextSlot`, `VisitLdaContextSlot`, `VisitStaContextSlot` deal with accessing variables stored in JavaScript contexts. There's also logic for caching loaded context slots.
6. **Register Management:**  Functions like `VisitLdar`, `VisitStar`, `VisitMov` handle moving data between registers.
7. **Tagged Value Equality:** The `BuildTaggedEqual` function compares JavaScript values for equality.

**Relationship to JavaScript:**

This C++ code is a crucial part of the Maglev compiler, which optimizes JavaScript execution. The type conversions and operations implemented here directly correspond to JavaScript's dynamic typing and operators.

**Illustrative JavaScript Examples:**

I will provide JavaScript examples that correspond to some of the functions and operations seen in the C++ code.
这是 `v8/src/maglev/maglev-graph-builder.cc` 文件第 2 部分的代码，主要负责构建 Maglev 图中与**数值类型转换、常量获取和基本的算术及比较运算**相关的节点。 它延续了第 1 部分关于类型转换和节点创建的功能。

**主要功能归纳:**

1. **数值类型转换 (续):**
    *   提供了更多将 `ValueNode` 转换为特定数值类型（例如 `int32_t`, `uint32_t`, `float64`）的函数，例如 `GetTruncatedInt32ForToNumber` (用于 `ToNumber` 操作的截断整数), `GetInt32`, `GetFloat64`, `GetHoleyFloat64ForToNumber` (用于处理可能包含 hole 的浮点数), `GetUint8ClampedForToNumber` (用于将数值钳制到 uint8 范围)。
    *   这些转换函数会根据 `ValueNode` 的当前表示形式 (`ValueRepresentation`) 和期望的类型 (`NodeType`) 生成不同的转换节点。
    *   部分转换会考虑 `ToNumberHint`，这是一种优化提示，用于指导如何将值转换为数字。

2. **常量获取:**
    *   提供了 `TryGetInt32Constant`, `TryGetUint32Constant`, `TryGetFloat64Constant` 等函数，尝试从 `ValueNode` 中提取出编译时的常量值。
    *   这些函数会检查 `ValueNode` 的操作码 (`opcode`) 是否表示常量，并返回相应的常量值（如果可以提取）。

3. **基本的算术运算:**
    *   定义了用于构建各种算术运算节点（如加、减、乘、除、取模、位运算等）的模板函数，例如 `BuildGenericUnaryOperationNode`, `BuildGenericBinaryOperationNode`, `BuildInt32UnaryOperationNode`, `BuildInt32BinaryOperationNode`, `BuildFloat64UnaryOperationNodeForToNumber`, `BuildFloat64BinaryOperationNodeForToNumber`。
    *   针对不同的操作和操作数类型（例如 `Int32`, `Float64`），会创建不同的节点类型。
    *   实现了简单的常量折叠优化，例如 `TryFoldInt32UnaryOperation`, `TryFoldInt32BinaryOperation`, `TryFoldFloat64UnaryOperationForToNumber`, `TryFoldFloat64BinaryOperationForToNumber`，如果在编译时操作数都是常量，则直接计算出结果并生成常量节点。

4. **比较运算:**
    *   `VisitCompareOperation` 函数负责构建比较运算节点（例如等于、严格等于、小于、大于等）。
    *   它会根据类型反馈 (`CompareOperationHint`) 选择合适的比较节点，例如 `Int32Compare`, `Float64Compare`, `StringEqual` 等。
    *   包含了一些针对常量比较的优化，例如 `TryReduceCompareEqualAgainstConstant`，可以针对某些与布尔常量比较的情况进行简化。

5. **加载和存储上下文变量:**
    *   `BuildLoadContextSlot`, `BuildStoreContextSlot` 以及 `VisitLdaContextSlot` 系列和 `VisitStaContextSlot` 系列函数负责构建加载和存储上下文变量的节点。
    *   考虑了上下文的深度 (`depth`) 和槽的索引 (`slot_index`)。
    *   包含了一些优化，例如 `TrySpecializeLoadContextSlotToFunctionContext` (尝试将加载上下文槽操作优化为直接使用常量) 和针对脚本上下文槽的特殊处理 (`TrySpecializeLoadScriptContextSlot`, `TrySpecializeStoreScriptContextSlot`)。
    *   实现了上下文槽的缓存 (`LoadAndCacheContextSlot`, `StoreAndCacheContextSlot`)，以避免重复加载相同上下文槽的值。

6. **寄存器操作:**
    *   `VisitLdar`, `VisitStar`, `VisitMov` 等函数负责构建在寄存器之间移动数据的节点。

7. **Tagged 值相等性判断:**
    *   `BuildTaggedEqual` 函数用于构建判断两个 JavaScript 值是否相等的节点，考虑了类型检查和常量优化。

**与 JavaScript 的关系 (举例说明):**

这段 C++ 代码的功能直接对应于 JavaScript 中对数值和变量的操作。Maglev 编译器使用这些代码来优化 JavaScript 代码的执行。

**JavaScript 示例:**

*   **数值类型转换:**

    ```javascript
    function foo(x) {
      return x | 0; // 将 x 转换为 32 位整数 (对应于 GetTruncatedInt32ForToNumber)
    }

    function bar(y) {
      return +y; // 将 y 转换为数字 (对应于 GetFloat64ForToNumber)
    }
    ```

*   **常量获取和常量折叠:**

    ```javascript
    const a = 10;
    const b = 20;
    const sum = a + b; // Maglev 可以在编译时计算出 sum 的值 (对应于 TryFoldInt32BinaryOperation)
    ```

*   **算术运算:**

    ```javascript
    function add(p, q) {
      return p + q; // 对应于 BuildInt32BinaryOperationNode 或 BuildFloat64BinaryOperationNodeForToNumber
    }
    ```

*   **比较运算:**

    ```javascript
    function compare(m, n) {
      return m === n; // 对应于 VisitCompareOperation 并可能生成 TaggedEqual 节点
    }
    ```

*   **加载和存储上下文变量:**

    ```javascript
    let globalVar = 5;

    function outer() {
      let localVar = 10;
      function inner() {
        console.log(localVar + globalVar); // 加载 localVar 和 globalVar (对应于 VisitLdaContextSlot 或 VisitLdaScriptContextSlot)
        localVar = 15; // 存储 localVar (对应于 VisitStaContextSlot 或 VisitStaScriptContextSlot)
      }
      inner();
    }

    outer();
    ```

总而言之，这段代码是 Maglev 编译器将 JavaScript 的高级语义转换为底层可执行图的关键部分，专注于数值和变量操作的优化。它通过精细的类型转换、常量处理和针对性地构建不同类型的节点来实现高效的 JavaScript 执行。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共9部分，请归纳一下它的功能
```

### 源代码
```
uncated alternative.
        return alternative.set_int32(BuildSmiUntag(value));
      }
      if (desired_type == NodeType::kSmi) {
        return alternative.set_int32(AddNewNode<CheckedSmiUntag>({value}));
      }
      TaggedToFloat64ConversionType conversion_type =
          ToNumberHintToConversionType(hint);
      if (NodeTypeIs(old_type, desired_type)) {
        return alternative.set_truncated_int32_to_number(
            AddNewNode<TruncateNumberOrOddballToInt32>({value},
                                                       conversion_type));
      }
      return alternative.set_truncated_int32_to_number(
          AddNewNode<CheckedTruncateNumberOrOddballToInt32>({value},
                                                            conversion_type));
    }
    case ValueRepresentation::kFloat64:
    // Ignore conversion_type for HoleyFloat64, and treat them like Float64.
    // ToNumber of undefined is anyway a NaN, so we'll simply truncate away
    // the NaN-ness of the hole, and don't need to do extra oddball checks so
    // we can ignore the hint (though we'll miss updating the feedback).
    case ValueRepresentation::kHoleyFloat64: {
      return alternative.set_truncated_int32_to_number(
          AddNewNode<TruncateFloat64ToInt32>({value}));
    }

    case ValueRepresentation::kInt32:
    case ValueRepresentation::kUint32:
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
  UNREACHABLE();
}

std::optional<int32_t> MaglevGraphBuilder::TryGetInt32Constant(
    ValueNode* value) {
  switch (value->opcode()) {
    case Opcode::kInt32Constant:
      return value->Cast<Int32Constant>()->value();
    case Opcode::kUint32Constant: {
      uint32_t uint32_value = value->Cast<Uint32Constant>()->value();
      if (uint32_value <= INT32_MAX) {
        return static_cast<int32_t>(uint32_value);
      }
      return {};
    }
    case Opcode::kSmiConstant:
      return value->Cast<SmiConstant>()->value().value();
    case Opcode::kFloat64Constant: {
      double double_value =
          value->Cast<Float64Constant>()->value().get_scalar();
      if (!IsInt32Double(double_value)) return {};
      return FastD2I(value->Cast<Float64Constant>()->value().get_scalar());
    }
    default:
      return {};
  }
}

std::optional<uint32_t> MaglevGraphBuilder::TryGetUint32Constant(
    ValueNode* value) {
  switch (value->opcode()) {
    case Opcode::kInt32Constant: {
      int32_t int32_value = value->Cast<Int32Constant>()->value();
      if (int32_value >= 0) {
        return static_cast<uint32_t>(int32_value);
      }
      return {};
    }
    case Opcode::kUint32Constant:
      return value->Cast<Uint32Constant>()->value();
    case Opcode::kSmiConstant: {
      int32_t smi_value = value->Cast<SmiConstant>()->value().value();
      if (smi_value >= 0) {
        return static_cast<uint32_t>(smi_value);
      }
      return {};
    }
    case Opcode::kFloat64Constant: {
      double double_value =
          value->Cast<Float64Constant>()->value().get_scalar();
      if (!IsUint32Double(double_value)) return {};
      return FastD2UI(value->Cast<Float64Constant>()->value().get_scalar());
    }
    default:
      return {};
  }
}

ValueNode* MaglevGraphBuilder::GetInt32(ValueNode* value) {
  RecordUseReprHintIfPhi(value, UseRepresentation::kInt32);

  ValueRepresentation representation =
      value->properties().value_representation();
  if (representation == ValueRepresentation::kInt32) return value;

  // Process constants first to avoid allocating NodeInfo for them.
  if (auto cst = TryGetInt32Constant(value)) {
    return GetInt32Constant(cst.value());
  }
  // We could emit unconditional eager deopts for other kinds of constant, but
  // it's not necessary, the appropriate checking conversion nodes will deopt.

  NodeInfo* node_info = GetOrCreateInfoFor(value);
  auto& alternative = node_info->alternative();

  if (ValueNode* alt = alternative.int32()) {
    return alt;
  }

  switch (representation) {
    case ValueRepresentation::kTagged: {
      // TODO(leszeks): Widen this path to allow HeapNumbers with Int32 values.
      return alternative.set_int32(BuildSmiUntag(value));
    }
    case ValueRepresentation::kUint32: {
      if (node_info->is_smi()) {
        return alternative.set_int32(
            AddNewNode<TruncateUint32ToInt32>({value}));
      }
      return alternative.set_int32(AddNewNode<CheckedUint32ToInt32>({value}));
    }
    case ValueRepresentation::kFloat64:
    // The check here will also work for the hole NaN, so we can treat
    // HoleyFloat64 as Float64.
    case ValueRepresentation::kHoleyFloat64: {
      return alternative.set_int32(
          AddNewNode<CheckedTruncateFloat64ToInt32>({value}));
    }

    case ValueRepresentation::kInt32:
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
  UNREACHABLE();
}

std::optional<double> MaglevGraphBuilder::TryGetFloat64Constant(
    ValueNode* value, ToNumberHint hint) {
  switch (value->opcode()) {
    case Opcode::kConstant: {
      compiler::ObjectRef object = value->Cast<Constant>()->object();
      if (object.IsHeapNumber()) {
        return object.AsHeapNumber().value();
      }
      // Oddballs should be RootConstants.
      DCHECK(!IsOddball(*object.object()));
      return {};
    }
    case Opcode::kInt32Constant:
      return value->Cast<Int32Constant>()->value();
    case Opcode::kSmiConstant:
      return value->Cast<SmiConstant>()->value().value();
    case Opcode::kFloat64Constant:
      return value->Cast<Float64Constant>()->value().get_scalar();
    case Opcode::kRootConstant: {
      Tagged<Object> root_object =
          local_isolate_->root(value->Cast<RootConstant>()->index());
      if (hint != ToNumberHint::kDisallowToNumber && IsOddball(root_object)) {
        return Cast<Oddball>(root_object)->to_number_raw();
      }
      if (IsHeapNumber(root_object)) {
        return Cast<HeapNumber>(root_object)->value();
      }
      return {};
    }
    default:
      return {};
  }
}

ValueNode* MaglevGraphBuilder::GetFloat64(ValueNode* value) {
  RecordUseReprHintIfPhi(value, UseRepresentation::kFloat64);
  return GetFloat64ForToNumber(value, ToNumberHint::kDisallowToNumber);
}

ValueNode* MaglevGraphBuilder::GetFloat64ForToNumber(ValueNode* value,
                                                     ToNumberHint hint) {
  ValueRepresentation representation =
      value->properties().value_representation();
  if (representation == ValueRepresentation::kFloat64) return value;

  // Process constants first to avoid allocating NodeInfo for them.
  if (auto cst = TryGetFloat64Constant(value, hint)) {
    return GetFloat64Constant(cst.value());
  }
  // We could emit unconditional eager deopts for other kinds of constant, but
  // it's not necessary, the appropriate checking conversion nodes will deopt.

  NodeInfo* node_info = GetOrCreateInfoFor(value);
  auto& alternative = node_info->alternative();

  if (ValueNode* alt = alternative.float64()) {
    return alt;
  }

  switch (representation) {
    case ValueRepresentation::kTagged: {
      switch (hint) {
        case ToNumberHint::kAssumeSmi:
          // Get the float64 value of a Smi value its int32 representation.
          return GetFloat64(GetInt32(value));
        case ToNumberHint::kDisallowToNumber:
        case ToNumberHint::kAssumeNumber:
          // Number->Float64 conversions are exact alternatives, so they can
          // also become the canonical float64_alternative.
          return alternative.set_float64(BuildNumberOrOddballToFloat64(
              value, TaggedToFloat64ConversionType::kOnlyNumber));
        case ToNumberHint::kAssumeNumberOrBoolean:
        case ToNumberHint::kAssumeNumberOrOddball: {
          // NumberOrOddball->Float64 conversions are not exact alternatives,
          // since they lose the information that this is an oddball, so they
          // can only become the canonical float64_alternative if they are a
          // known number (and therefore not oddball).
          ValueNode* float64_node = BuildNumberOrOddballToFloat64(
              value, ToNumberHintToConversionType(hint));
          if (NodeTypeIsNumber(node_info->type())) {
            alternative.set_float64(float64_node);
          }
          return float64_node;
        }
      }
    }
    case ValueRepresentation::kInt32:
      return alternative.set_float64(AddNewNode<ChangeInt32ToFloat64>({value}));
    case ValueRepresentation::kUint32:
      return alternative.set_float64(
          AddNewNode<ChangeUint32ToFloat64>({value}));
    case ValueRepresentation::kHoleyFloat64: {
      switch (hint) {
        case ToNumberHint::kAssumeSmi:
        case ToNumberHint::kDisallowToNumber:
        case ToNumberHint::kAssumeNumber:
        case ToNumberHint::kAssumeNumberOrBoolean:
          // Number->Float64 conversions are exact alternatives, so they can
          // also become the canonical float64_alternative.
          return alternative.set_float64(
              AddNewNode<CheckedHoleyFloat64ToFloat64>({value}));
        case ToNumberHint::kAssumeNumberOrOddball:
          // NumberOrOddball->Float64 conversions are not exact alternatives,
          // since they lose the information that this is an oddball, so they
          // cannot become the canonical float64_alternative.
          return AddNewNode<HoleyFloat64ToMaybeNanFloat64>({value});
      }
    }
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
  UNREACHABLE();
}

ValueNode* MaglevGraphBuilder::GetHoleyFloat64ForToNumber(ValueNode* value,
                                                          ToNumberHint hint) {
  RecordUseReprHintIfPhi(value, UseRepresentation::kHoleyFloat64);
  ValueRepresentation representation =
      value->properties().value_representation();
  // Ignore the hint for
  if (representation == ValueRepresentation::kHoleyFloat64) return value;
  return GetFloat64ForToNumber(value, hint);
}

namespace {
int32_t ClampToUint8(int32_t value) {
  if (value < 0) return 0;
  if (value > 255) return 255;
  return value;
}
}  // namespace

ValueNode* MaglevGraphBuilder::GetUint8ClampedForToNumber(ValueNode* value,
                                                          ToNumberHint hint) {
  switch (value->properties().value_representation()) {
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kTagged: {
      if (SmiConstant* constant = value->TryCast<SmiConstant>()) {
        return GetInt32Constant(ClampToUint8(constant->value().value()));
      }
      NodeInfo* info = known_node_aspects().TryGetInfoFor(value);
      if (info && info->alternative().int32()) {
        return AddNewNode<Int32ToUint8Clamped>({info->alternative().int32()});
      }
      return AddNewNode<CheckedNumberToUint8Clamped>({value});
    }
    // Ignore conversion_type for HoleyFloat64, and treat them like Float64.
    // ToNumber of undefined is anyway a NaN, so we'll simply truncate away the
    // NaN-ness of the hole, and don't need to do extra oddball checks so we can
    // ignore the hint (though we'll miss updating the feedback).
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      // TODO(leszeks): Handle Float64Constant, which requires the correct
      // rounding for clamping.
      return AddNewNode<Float64ToUint8Clamped>({value});
    case ValueRepresentation::kInt32:
      if (Int32Constant* constant = value->TryCast<Int32Constant>()) {
        return GetInt32Constant(ClampToUint8(constant->value()));
      }
      return AddNewNode<Int32ToUint8Clamped>({value});
    case ValueRepresentation::kUint32:
      return AddNewNode<Uint32ToUint8Clamped>({value});
  }
  UNREACHABLE();
}

namespace {
template <Operation kOperation>
struct NodeForOperationHelper;

#define NODE_FOR_OPERATION_HELPER(Name)               \
  template <>                                         \
  struct NodeForOperationHelper<Operation::k##Name> { \
    using generic_type = Generic##Name;               \
  };
OPERATION_LIST(NODE_FOR_OPERATION_HELPER)
#undef NODE_FOR_OPERATION_HELPER

template <Operation kOperation>
using GenericNodeForOperation =
    typename NodeForOperationHelper<kOperation>::generic_type;

// Bitwise operations reinterprets the numeric input as Int32 bits for a
// bitwise operation, which means we want to do slightly different conversions.
template <Operation kOperation>
constexpr bool BinaryOperationIsBitwiseInt32() {
  switch (kOperation) {
    case Operation::kBitwiseNot:
    case Operation::kBitwiseAnd:
    case Operation::kBitwiseOr:
    case Operation::kBitwiseXor:
    case Operation::kShiftLeft:
    case Operation::kShiftRight:
    case Operation::kShiftRightLogical:
      return true;
    default:
      return false;
  }
}
}  // namespace

// MAP_OPERATION_TO_NODES are tuples with the following format:
// - Operation name,
// - Int32 operation node,
// - Identity of int32 operation (e.g, 0 for add/sub and 1 for mul/div), if it
//   exists, or otherwise {}.
#define MAP_BINARY_OPERATION_TO_INT32_NODE(V) \
  V(Add, Int32AddWithOverflow, 0)             \
  V(Subtract, Int32SubtractWithOverflow, 0)   \
  V(Multiply, Int32MultiplyWithOverflow, 1)   \
  V(Divide, Int32DivideWithOverflow, 1)       \
  V(Modulus, Int32ModulusWithOverflow, {})    \
  V(BitwiseAnd, Int32BitwiseAnd, ~0)          \
  V(BitwiseOr, Int32BitwiseOr, 0)             \
  V(BitwiseXor, Int32BitwiseXor, 0)           \
  V(ShiftLeft, Int32ShiftLeft, 0)             \
  V(ShiftRight, Int32ShiftRight, 0)           \
  V(ShiftRightLogical, Int32ShiftRightLogical, {})

#define MAP_UNARY_OPERATION_TO_INT32_NODE(V) \
  V(BitwiseNot, Int32BitwiseNot)             \
  V(Increment, Int32IncrementWithOverflow)   \
  V(Decrement, Int32DecrementWithOverflow)   \
  V(Negate, Int32NegateWithOverflow)

// MAP_OPERATION_TO_FLOAT64_NODE are tuples with the following format:
// (Operation name, Float64 operation node).
#define MAP_OPERATION_TO_FLOAT64_NODE(V) \
  V(Add, Float64Add)                     \
  V(Subtract, Float64Subtract)           \
  V(Multiply, Float64Multiply)           \
  V(Divide, Float64Divide)               \
  V(Modulus, Float64Modulus)             \
  V(Exponentiate, Float64Exponentiate)

template <Operation kOperation>
static constexpr std::optional<int> Int32Identity() {
  switch (kOperation) {
#define CASE(op, _, identity) \
  case Operation::k##op:      \
    return identity;
    MAP_BINARY_OPERATION_TO_INT32_NODE(CASE)
#undef CASE
    default:
      UNREACHABLE();
  }
}

namespace {
template <Operation kOperation>
struct Int32NodeForHelper;
#define SPECIALIZATION(op, OpNode, ...)         \
  template <>                                   \
  struct Int32NodeForHelper<Operation::k##op> { \
    using type = OpNode;                        \
  };
MAP_UNARY_OPERATION_TO_INT32_NODE(SPECIALIZATION)
MAP_BINARY_OPERATION_TO_INT32_NODE(SPECIALIZATION)
#undef SPECIALIZATION

template <Operation kOperation>
using Int32NodeFor = typename Int32NodeForHelper<kOperation>::type;

template <Operation kOperation>
struct Float64NodeForHelper;
#define SPECIALIZATION(op, OpNode)                \
  template <>                                     \
  struct Float64NodeForHelper<Operation::k##op> { \
    using type = OpNode;                          \
  };
MAP_OPERATION_TO_FLOAT64_NODE(SPECIALIZATION)
#undef SPECIALIZATION

template <Operation kOperation>
using Float64NodeFor = typename Float64NodeForHelper<kOperation>::type;
}  // namespace

template <Operation kOperation>
void MaglevGraphBuilder::BuildGenericUnaryOperationNode() {
  FeedbackSlot slot_index = GetSlotOperand(0);
  ValueNode* value = GetAccumulator();
  SetAccumulator(AddNewNode<GenericNodeForOperation<kOperation>>(
      {value}, compiler::FeedbackSource{feedback(), slot_index}));
}

template <Operation kOperation>
void MaglevGraphBuilder::BuildGenericBinaryOperationNode() {
  ValueNode* left = LoadRegister(0);
  ValueNode* right = GetAccumulator();
  FeedbackSlot slot_index = GetSlotOperand(1);
  SetAccumulator(AddNewNode<GenericNodeForOperation<kOperation>>(
      {left, right}, compiler::FeedbackSource{feedback(), slot_index}));
}

template <Operation kOperation>
void MaglevGraphBuilder::BuildGenericBinarySmiOperationNode() {
  ValueNode* left = GetAccumulator();
  int constant = iterator_.GetImmediateOperand(0);
  ValueNode* right = GetSmiConstant(constant);
  FeedbackSlot slot_index = GetSlotOperand(1);
  SetAccumulator(AddNewNode<GenericNodeForOperation<kOperation>>(
      {left, right}, compiler::FeedbackSource{feedback(), slot_index}));
}

template <Operation kOperation>
ReduceResult MaglevGraphBuilder::TryFoldInt32UnaryOperation(ValueNode* node) {
  auto cst = TryGetInt32Constant(node);
  if (!cst.has_value()) return ReduceResult::Fail();
  switch (kOperation) {
    case Operation::kBitwiseNot:
      return GetInt32Constant(~cst.value());
    case Operation::kIncrement:
      if (cst.value() < INT32_MAX) {
        return GetInt32Constant(cst.value() + 1);
      }
      return ReduceResult::Fail();
    case Operation::kDecrement:
      if (cst.value() > INT32_MIN) {
        return GetInt32Constant(cst.value() - 1);
      }
      return ReduceResult::Fail();
    case Operation::kNegate:
      if (cst.value() == 0) {
        return ReduceResult::Fail();
      }
      if (cst.value() != INT32_MIN) {
        return GetInt32Constant(-cst.value());
      }
      return ReduceResult::Fail();
    default:
      UNREACHABLE();
  }
}

template <Operation kOperation>
void MaglevGraphBuilder::BuildInt32UnaryOperationNode() {
  // Use BuildTruncatingInt32BitwiseNotForToNumber with Smi input hint
  // for truncating operations.
  static_assert(!BinaryOperationIsBitwiseInt32<kOperation>());
  ValueNode* value = GetAccumulator();
  PROCESS_AND_RETURN_IF_DONE(TryFoldInt32UnaryOperation<kOperation>(value),
                             SetAccumulator);
  using OpNodeT = Int32NodeFor<kOperation>;
  SetAccumulator(AddNewNode<OpNodeT>({value}));
}

void MaglevGraphBuilder::BuildTruncatingInt32BitwiseNotForToNumber(
    ToNumberHint hint) {
  ValueNode* value = GetTruncatedInt32ForToNumber(
      current_interpreter_frame_.accumulator(), hint);
  PROCESS_AND_RETURN_IF_DONE(
      TryFoldInt32UnaryOperation<Operation::kBitwiseNot>(value),
      SetAccumulator);
  SetAccumulator(AddNewNode<Int32BitwiseNot>({value}));
}

template <Operation kOperation>
ReduceResult MaglevGraphBuilder::TryFoldInt32BinaryOperation(ValueNode* left,
                                                             ValueNode* right) {
  auto cst_right = TryGetInt32Constant(right);
  if (!cst_right.has_value()) return ReduceResult::Fail();
  return TryFoldInt32BinaryOperation<kOperation>(left, cst_right.value());
}

template <Operation kOperation>
ReduceResult MaglevGraphBuilder::TryFoldInt32BinaryOperation(
    ValueNode* left, int32_t cst_right) {
  auto cst_left = TryGetInt32Constant(left);
  if (!cst_left.has_value()) return ReduceResult::Fail();
  switch (kOperation) {
    case Operation::kAdd: {
      int64_t result = static_cast<int64_t>(cst_left.value()) +
                       static_cast<int64_t>(cst_right);
      if (result >= INT32_MIN && result <= INT32_MAX) {
        return GetInt32Constant(static_cast<int32_t>(result));
      }
      return ReduceResult::Fail();
    }
    case Operation::kSubtract: {
      int64_t result = static_cast<int64_t>(cst_left.value()) -
                       static_cast<int64_t>(cst_right);
      if (result >= INT32_MIN && result <= INT32_MAX) {
        return GetInt32Constant(static_cast<int32_t>(result));
      }
      return ReduceResult::Fail();
    }
    case Operation::kMultiply: {
      int64_t result = static_cast<int64_t>(cst_left.value()) *
                       static_cast<int64_t>(cst_right);
      if (result >= INT32_MIN && result <= INT32_MAX) {
        return GetInt32Constant(static_cast<int32_t>(result));
      }
      return ReduceResult::Fail();
    }
    case Operation::kModulus:
      // TODO(v8:7700): Constant fold mod.
      return ReduceResult::Fail();
    case Operation::kDivide:
      // TODO(v8:7700): Constant fold division.
      return ReduceResult::Fail();
    case Operation::kBitwiseAnd:
      return GetInt32Constant(cst_left.value() & cst_right);
    case Operation::kBitwiseOr:
      return GetInt32Constant(cst_left.value() | cst_right);
    case Operation::kBitwiseXor:
      return GetInt32Constant(cst_left.value() ^ cst_right);
    case Operation::kShiftLeft:
      return GetInt32Constant(cst_left.value()
                              << (static_cast<uint32_t>(cst_right) % 32));
    case Operation::kShiftRight:
      return GetInt32Constant(cst_left.value() >>
                              (static_cast<uint32_t>(cst_right) % 32));
    case Operation::kShiftRightLogical:
      return GetUint32Constant(static_cast<uint32_t>(cst_left.value()) >>
                               (static_cast<uint32_t>(cst_right) % 32));
    default:
      UNREACHABLE();
  }
}

template <Operation kOperation>
void MaglevGraphBuilder::BuildInt32BinaryOperationNode() {
  // Use BuildTruncatingInt32BinaryOperationNodeForToNumber with Smi input hint
  // for truncating operations.
  static_assert(!BinaryOperationIsBitwiseInt32<kOperation>());
  ValueNode* left = LoadRegister(0);
  ValueNode* right = GetAccumulator();
  PROCESS_AND_RETURN_IF_DONE(
      TryFoldInt32BinaryOperation<kOperation>(left, right), SetAccumulator);
  using OpNodeT = Int32NodeFor<kOperation>;
  SetAccumulator(AddNewNode<OpNodeT>({left, right}));
}

template <Operation kOperation>
void MaglevGraphBuilder::BuildTruncatingInt32BinaryOperationNodeForToNumber(
    ToNumberHint hint) {
  static_assert(BinaryOperationIsBitwiseInt32<kOperation>());
  ValueNode* left;
  ValueNode* right;
  if (IsRegisterEqualToAccumulator(0)) {
    left = right = GetTruncatedInt32ForToNumber(
        current_interpreter_frame_.get(iterator_.GetRegisterOperand(0)), hint);
  } else {
    left = GetTruncatedInt32ForToNumber(
        current_interpreter_frame_.get(iterator_.GetRegisterOperand(0)), hint);
    right = GetTruncatedInt32ForToNumber(
        current_interpreter_frame_.accumulator(), hint);
  }
  PROCESS_AND_RETURN_IF_DONE(
      TryFoldInt32BinaryOperation<kOperation>(left, right), SetAccumulator);
  SetAccumulator(AddNewNode<Int32NodeFor<kOperation>>({left, right}));
}

template <Operation kOperation>
void MaglevGraphBuilder::BuildInt32BinarySmiOperationNode() {
  // Truncating Int32 nodes treat their input as a signed int32 regardless
  // of whether it's really signed or not, so we allow Uint32 by loading a
  // TruncatedInt32 value.
  static_assert(!BinaryOperationIsBitwiseInt32<kOperation>());
  ValueNode* left = GetAccumulator();
  int32_t constant = iterator_.GetImmediateOperand(0);
  if (std::optional<int>(constant) == Int32Identity<kOperation>()) {
    // Deopt if {left} is not an Int32.
    EnsureInt32(left);
    // If the constant is the unit of the operation, it already has the right
    // value, so just return.
    return;
  }
  PROCESS_AND_RETURN_IF_DONE(
      TryFoldInt32BinaryOperation<kOperation>(left, constant), SetAccumulator);
  ValueNode* right = GetInt32Constant(constant);
  using OpNodeT = Int32NodeFor<kOperation>;
  SetAccumulator(AddNewNode<OpNodeT>({left, right}));
}

template <Operation kOperation>
void MaglevGraphBuilder::BuildTruncatingInt32BinarySmiOperationNodeForToNumber(
    ToNumberHint hint) {
  static_assert(BinaryOperationIsBitwiseInt32<kOperation>());
  ValueNode* left = GetTruncatedInt32ForToNumber(
      current_interpreter_frame_.accumulator(), hint);
  int32_t constant = iterator_.GetImmediateOperand(0);
  if (std::optional<int>(constant) == Int32Identity<kOperation>()) {
    // If the constant is the unit of the operation, it already has the right
    // value, so use the truncated value (if not just a conversion) and return.
    if (!left->properties().is_conversion()) {
      current_interpreter_frame_.set_accumulator(left);
    }
    return;
  }
  PROCESS_AND_RETURN_IF_DONE(
      TryFoldInt32BinaryOperation<kOperation>(left, constant), SetAccumulator);
  ValueNode* right = GetInt32Constant(constant);
  SetAccumulator(AddNewNode<Int32NodeFor<kOperation>>({left, right}));
}

ValueNode* MaglevGraphBuilder::GetNumberConstant(double constant) {
  if (IsSmiDouble(constant)) {
    return GetInt32Constant(FastD2I(constant));
  }
  return GetFloat64Constant(constant);
}

template <Operation kOperation>
ReduceResult MaglevGraphBuilder::TryFoldFloat64UnaryOperationForToNumber(
    ToNumberHint hint, ValueNode* value) {
  auto cst = TryGetFloat64Constant(value, hint);
  if (!cst.has_value()) return ReduceResult::Fail();
  switch (kOperation) {
    case Operation::kNegate:
      return GetNumberConstant(-cst.value());
    case Operation::kIncrement:
      return GetNumberConstant(cst.value() + 1);
    case Operation::kDecrement:
      return GetNumberConstant(cst.value() - 1);
    default:
      UNREACHABLE();
  }
}

template <Operation kOperation>
ReduceResult MaglevGraphBuilder::TryFoldFloat64BinaryOperationForToNumber(
    ToNumberHint hint, ValueNode* left, ValueNode* right) {
  auto cst_right = TryGetFloat64Constant(right, hint);
  if (!cst_right.has_value()) return ReduceResult::Fail();
  return TryFoldFloat64BinaryOperationForToNumber<kOperation>(
      hint, left, cst_right.value());
}

template <Operation kOperation>
ReduceResult MaglevGraphBuilder::TryFoldFloat64BinaryOperationForToNumber(
    ToNumberHint hint, ValueNode* left, double cst_right) {
  auto cst_left = TryGetFloat64Constant(left, hint);
  if (!cst_left.has_value()) return ReduceResult::Fail();
  switch (kOperation) {
    case Operation::kAdd:
      return GetNumberConstant(cst_left.value() + cst_right);
    case Operation::kSubtract:
      return GetNumberConstant(cst_left.value() - cst_right);
    case Operation::kMultiply:
      return GetNumberConstant(cst_left.value() * cst_right);
    case Operation::kDivide:
      return GetNumberConstant(cst_left.value() / cst_right);
    case Operation::kModulus:
      // TODO(v8:7700): Constant fold mod.
      return ReduceResult::Fail();
    case Operation::kExponentiate:
      return GetNumberConstant(math::pow(cst_left.value(), cst_right));
    default:
      UNREACHABLE();
  }
}

template <Operation kOperation>
void MaglevGraphBuilder::BuildFloat64BinarySmiOperationNodeForToNumber(
    ToNumberHint hint) {
  // TODO(v8:7700): Do constant identity folding. Make sure to normalize
  // HoleyFloat64 nodes if folded.
  ValueNode* left = GetAccumulatorHoleyFloat64ForToNumber(hint);
  double constant = static_cast<double>(iterator_.GetImmediateOperand(0));
  PROCESS_AND_RETURN_IF_DONE(
      TryFoldFloat64BinaryOperationForToNumber<kOperation>(hint, left,
                                                           constant),
      SetAccumulator);
  ValueNode* right = GetFloat64Constant(constant);
  SetAccumulator(AddNewNode<Float64NodeFor<kOperation>>({left, right}));
}

template <Operation kOperation>
void MaglevGraphBuilder::BuildFloat64UnaryOperationNodeForToNumber(
    ToNumberHint hint) {
  // TODO(v8:7700): Do constant identity folding. Make sure to normalize
  // HoleyFloat64 nodes if folded.
  ValueNode* value = GetAccumulatorHoleyFloat64ForToNumber(hint);
  PROCESS_AND_RETURN_IF_DONE(
      TryFoldFloat64UnaryOperationForToNumber<kOperation>(hint, value),
      SetAccumulator);
  switch (kOperation) {
    case Operation::kNegate:
      SetAccumulator(AddNewNode<Float64Negate>({value}));
      break;
    case Operation::kIncrement:
      SetAccumulator(AddNewNode<Float64Add>({value, GetFloat64Constant(1)}));
      break;
    case Operation::kDecrement:
      SetAccumulator(
          AddNewNode<Float64Subtract>({value, GetFloat64Constant(1)}));
      break;
    default:
      UNREACHABLE();
  }
}

template <Operation kOperation>
void MaglevGraphBuilder::BuildFloat64BinaryOperationNodeForToNumber(
    ToNumberHint hint) {
  // TODO(v8:7700): Do constant identity folding. Make sure to normalize
  // HoleyFloat64 nodes if folded.
  ValueNode* left = LoadRegisterHoleyFloat64ForToNumber(0, hint);
  ValueNode* right = GetAccumulatorHoleyFloat64ForToNumber(hint);
  PROCESS_AND_RETURN_IF_DONE(
      TryFoldFloat64BinaryOperationForToNumber<kOperation>(hint, left, right),
      SetAccumulator);
  SetAccumulator(AddNewNode<Float64NodeFor<kOperation>>({left, right}));
}

namespace {
ToNumberHint BinopHintToToNumberHint(BinaryOperationHint hint) {
  switch (hint) {
    case BinaryOperationHint::kSignedSmall:
      return ToNumberHint::kAssumeSmi;
    case BinaryOperationHint::kSignedSmallInputs:
    case BinaryOperationHint::kNumber:
      return ToNumberHint::kAssumeNumber;
    case BinaryOperationHint::kNumberOrOddball:
      return ToNumberHint::kAssumeNumberOrOddball;

    case BinaryOperationHint::kNone:
    case BinaryOperationHint::kString:
    case BinaryOperationHint::kStringOrStringWrapper:
    case BinaryOperationHint::kBigInt:
    case BinaryOperationHint::kBigInt64:
    case BinaryOperationHint::kAny:
      UNREACHABLE();
  }
}
}  // namespace

template <Operation kOperation>
void MaglevGraphBuilder::VisitUnaryOperation() {
  FeedbackNexus nexus = FeedbackNexusForOperand(0);
  BinaryOperationHint feedback_hint = nexus.GetBinaryOperationFeedback();
  switch (feedback_hint) {
    case BinaryOperationHint::kNone:
      RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForBinaryOperation));
    case BinaryOperationHint::kSignedSmall:
    case BinaryOperationHint::kSignedSmallInputs:
    case BinaryOperationHint::kNumber:
    case BinaryOperationHint::kNumberOrOddball: {
      ToNumberHint hint = BinopHintToToNumberHint(feedback_hint);
      if constexpr (BinaryOperationIsBitwiseInt32<kOperation>()) {
        static_assert(kOperation == Operation::kBitwiseNot);
        return BuildTruncatingInt32BitwiseNotForToNumber(hint);
      } else if (feedback_hint == BinaryOperationHint::kSignedSmall) {
        return BuildInt32UnaryOperationNode<kOperation>();
      }
      return BuildFloat64UnaryOperationNodeForToNumber<kOperation>(hint);
      break;
    }
    case BinaryOperationHint::kString:
    case BinaryOperationHint::kStringOrStringWrapper:
    case BinaryOperationHint::kBigInt:
    case BinaryOperationHint::kBigInt64:
    case BinaryOperationHint::kAny:
      // Fallback to generic node.
      break;
  }
  BuildGenericUnaryOperationNode<kOperation>();
}

template <Operation kOperation>
void MaglevGraphBuilder::VisitBinaryOperation() {
  FeedbackNexus nexus = FeedbackNexusForOperand(1);
  BinaryOperationHint feedback_hint = nexus.GetBinaryOperationFeedback();
  switch (feedback_hint) {
    case BinaryOperationHint::kNone:
      RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForBinaryOperation));
    case BinaryOperationHint::kSignedSmall:
    case BinaryOperationHint::kSignedSmallInputs:
    case BinaryOperationHint::kNumber:
    case BinaryOperationHint::kNumberOrOddball: {
      ToNumberHint hint = BinopHintToToNumberHint(feedback_hint);
      if constexpr (BinaryOperationIsBitwiseInt32<kOperation>()) {
        return BuildTruncatingInt32BinaryOperationNodeForToNumber<kOperation>(
            hint);
      } else if (feedback_hint == BinaryOperationHint::kSignedSmall) {
        if constexpr (kOperation == Operation::kExponentiate) {
          // Exponentiate never updates the feedback to be a Smi.
          UNREACHABLE();
        } else {
          return BuildInt32BinaryOperationNode<kOperation>();
        }
      } else {
        return BuildFloat64BinaryOperationNodeForToNumber<kOperation>(hint);
      }
      break;
    }
    case BinaryOperationHint::kString:
      if constexpr (kOperation == Operation::kAdd) {
        ValueNode* left = LoadRegister(0);
        ValueNode* right = GetAccumulator();
        if (RootConstant* root_constant = left->TryCast<RootConstant>()) {
          if (root_constant->index() == RootIndex::kempty_string) {
            BuildCheckString(right);
            // The right side is already in the accumulator register.
            return;
          }
        }
        if (RootConstant* root_constant = right->TryCast<RootConstant>()) {
          if (root_constant->index() == RootIndex::kempty_string) {
            BuildCheckString(left);
            MoveNodeBetweenRegisters(
                iterator_.GetRegisterOperand(0),
                interpreter::Register::virtual_accumulator());
            return;
          }
        }
        BuildCheckString(left);
        BuildCheckString(right);
        SetAccumulator(AddNewNode<StringConcat>({left, right}));
        return;
      }
      break;
    case BinaryOperationHint::kStringOrStringWrapper:
      if constexpr (kOperation == Operation::kAdd) {
        if (broker()
                ->dependencies()
                ->DependOnStringWrapperToPrimitiveProtector()) {
          ValueNode* left = LoadRegister(0);
          ValueNode* right = GetAccumulator();
          BuildCheckStringOrStringWrapper(left);
          BuildCheckStringOrStringWrapper(right);
          SetAccumulator(AddNewNode<StringWrapperConcat>({left, right}));
          return;
        }
      }
      [[fallthrough]];
    case BinaryOperationHint::kBigInt:
    case BinaryOperationHint::kBigInt64:
    case BinaryOperationHint::kAny:
      // Fallback to generic node.
      break;
  }
  BuildGenericBinaryOperationNode<kOperation>();
}

template <Operation kOperation>
void MaglevGraphBuilder::VisitBinarySmiOperation() {
  FeedbackNexus nexus = FeedbackNexusForOperand(1);
  BinaryOperationHint feedback_hint = nexus.GetBinaryOperationFeedback();
  switch (feedback_hint) {
    case BinaryOperationHint::kNone:
      RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForBinaryOperation));
    case BinaryOperationHint::kSignedSmall:
    case BinaryOperationHint::kSignedSmallInputs:
    case BinaryOperationHint::kNumber:
    case BinaryOperationHint::kNumberOrOddball: {
      ToNumberHint hint = BinopHintToToNumberHint(feedback_hint);
      if constexpr (BinaryOperationIsBitwiseInt32<kOperation>()) {
        return BuildTruncatingInt32BinarySmiOperationNodeForToNumber<
            kOperation>(hint);
      } else if (feedback_hint == BinaryOperationHint::kSignedSmall) {
        if constexpr (kOperation == Operation::kExponentiate) {
          // Exponentiate never updates the feedback to be a Smi.
          UNREACHABLE();
        } else {
          return BuildInt32BinarySmiOperationNode<kOperation>();
        }
      } else {
        return BuildFloat64BinarySmiOperationNodeForToNumber<kOperation>(hint);
      }
      break;
    }
    case BinaryOperationHint::kString:
    case BinaryOperationHint::kStringOrStringWrapper:
    case BinaryOperationHint::kBigInt:
    case BinaryOperationHint::kBigInt64:
    case BinaryOperationHint::kAny:
      // Fallback to generic node.
      break;
  }
  BuildGenericBinarySmiOperationNode<kOperation>();
}

template <Operation kOperation, typename type>
bool OperationValue(type left, type right) {
  switch (kOperation) {
    case Operation::kEqual:
    case Operation::kStrictEqual:
      return left == right;
    case Operation::kLessThan:
      return left < right;
    case Operation::kLessThanOrEqual:
      return left <= right;
    case Operation::kGreaterThan:
      return left > right;
    case Operation::kGreaterThanOrEqual:
      return left >= right;
  }
}

// static
compiler::OptionalHeapObjectRef MaglevGraphBuilder::TryGetConstant(
    compiler::JSHeapBroker* broker, LocalIsolate* isolate, ValueNode* node) {
  if (Constant* c = node->TryCast<Constant>()) {
    return c->object();
  }
  if (RootConstant* c = node->TryCast<RootConstant>()) {
    return MakeRef(broker, isolate->root_handle(c->index())).AsHeapObject();
  }
  return {};
}

compiler::OptionalHeapObjectRef MaglevGraphBuilder::TryGetConstant(
    ValueNode* node, ValueNode** constant_node) {
  if (auto result = TryGetConstant(broker(), local_isolate(), node)) {
    if (constant_node) *constant_node = node;
    return result;
  }
  const NodeInfo* info = known_node_aspects().TryGetInfoFor(node);
  if (info) {
    if (auto c = info->alternative().checked_value()) {
      return TryGetConstant(c, constant_node);
    }
  }
  return {};
}

template <Operation kOperation>
bool MaglevGraphBuilder::TryReduceCompareEqualAgainstConstant() {
  if (kOperation != Operation::kStrictEqual && kOperation != Operation::kEqual)
    return false;

  ValueNode* left = LoadRegister(0);
  ValueNode* right = GetAccumulator();

  ValueNode* other = right;
  compiler::OptionalHeapObjectRef maybe_constant = TryGetConstant(left);
  if (!maybe_constant) {
    maybe_constant = TryGetConstant(right);
    other = left;
  }
  if (!maybe_constant) return false;

  if (CheckType(other, NodeType::kBoolean)) {
    std::optional<bool> compare_bool = {};
    if (maybe_constant.equals(broker_->true_value())) {
      compare_bool = {true};
    } else if (maybe_constant.equals(broker_->false_value())) {
      compare_bool = {false};
    } else if (kOperation == Operation::kEqual) {
      // For `bool == num` we can convert the actual comparison `ToNumber(bool)
      // == num` into `(num == 1) ? bool : ((num == 0) ? !bool : false)`,
      std::optional<double> val = {};
      if (maybe_constant.value().IsSmi()) {
        val = maybe_constant.value().AsSmi();
      } else if (maybe_constant.value().IsHeapNumber()) {
        val = maybe_constant.value().AsHeapNumber().value();
      }
      if (val) {
        if (*val == 0) {
          compare_bool = {false};
        } else if (*val == 1) {
          compare_bool = {true};
        } else {
          // The constant number is neither equal to `ToNumber(true)` nor
          // `ToNumber(false)`.
          SetAccumulator(GetBooleanConstant(false));
          return true;
        }
      }
    }
    if (compare_bool) {
      if (*compare_bool) {
        SetAccumulator(other);
      } else {
        compiler::OptionalHeapObjectRef both_constant = TryGetConstant(other);
        if (both_constant) {
          DCHECK(both_constant.equals(broker_->true_value()) ||
                 both_constant.equals(broker_->false_value()));
          SetAccumulator(GetBooleanConstant(
              *compare_bool == both_constant.equals(broker_->true_value())));
        } else {
          SetAccumulator(AddNewNode<LogicalNot>({other}));
        }
      }
      return true;
    }
  }

  if (kOperation != Operation::kStrictEqual) return false;

  InstanceType type = maybe_constant.value().map(broker()).instance_type();
  if (!InstanceTypeChecker::IsReferenceComparable(type)) return false;

  // If the constant is the undefined value, we can compare it
  // against holey floats.
  if (maybe_constant->IsUndefined()) {
    ValueNode* holey_float = nullptr;
    if (left->properties().value_representation() ==
        ValueRepresentation::kHoleyFloat64) {
      holey_float = left;
    } else if (right->properties().value_representation() ==
               ValueRepresentation::kHoleyFloat64) {
      holey_float = right;
    }
    if (holey_float) {
      SetAccumulator(AddNewNode<HoleyFloat64IsHole>({holey_float}));
      return true;
    }
  }

  if (left->properties().value_representation() !=
          ValueRepresentation::kTagged ||
      right->properties().value_representation() !=
          ValueRepresentation::kTagged) {
    SetAccumulator(GetBooleanConstant(false));
  } else {
    SetAccumulator(BuildTaggedEqual(left, right));
  }
  return true;
}

template <Operation kOperation>
void MaglevGraphBuilder::VisitCompareOperation() {
  if (TryReduceCompareEqualAgainstConstant<kOperation>()) return;

  // Compare opcodes are not always commutative. We sort the ones which are for
  // better CSE coverage.
  auto SortCommute = [](ValueNode*& left, ValueNode*& right) {
    if (!v8_flags.maglev_cse) return;
    if (kOperation != Operation::kEqual &&
        kOperation != Operation::kStrictEqual) {
      return;
    }
    if (left > right) {
      std::swap(left, right);
    }
  };

  auto TryConstantFoldInt32 = [&](ValueNode* left, ValueNode* right) {
    if (left->Is<Int32Constant>() && right->Is<Int32Constant>()) {
      int left_value = left->Cast<Int32Constant>()->value();
      int right_value = right->Cast<Int32Constant>()->value();
      SetAccumulator(GetBooleanConstant(
          OperationValue<kOperation>(left_value, right_value)));
      return true;
    }
    return false;
  };

  auto TryConstantFoldEqual = [&](ValueNode* left, ValueNode* right) {
    if (left == right) {
      SetAccumulator(
          GetBooleanConstant(kOperation == Operation::kEqual ||
                             kOperation == Operation::kStrictEqual ||
                             kOperation == Operation::kLessThanOrEqual ||
                             kOperation == Operation::kGreaterThanOrEqual));
      return true;
    }
    return false;
  };

  auto MaybeOddballs = [&]() {
    auto MaybeOddball = [&](ValueNode* value) {
      ValueRepresentation rep = value->value_representation();
      switch (rep) {
        case ValueRepresentation::kInt32:
        case ValueRepresentation::kUint32:
        case ValueRepresentation::kFloat64:
          return false;
        default:
          break;
      }
      return !CheckType(value, NodeType::kNumber);
    };
    return MaybeOddball(LoadRegister(0)) || MaybeOddball(GetAccumulator());
  };

  FeedbackNexus nexus = FeedbackNexusForOperand(1);
  switch (nexus.GetCompareOperationFeedback()) {
    case CompareOperationHint::kNone:
      RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForCompareOperation));

    case CompareOperationHint::kSignedSmall: {
      // TODO(victorgomes): Add a smart equality operator, that compares for
      // constants in different representations.
      ValueNode* left = GetInt32(LoadRegister(0));
      ValueNode* right = GetInt32(GetAccumulator());
      if (TryConstantFoldEqual(left, right)) return;
      if (TryConstantFoldInt32(left, right)) return;
      SortCommute(left, right);
      SetAccumulator(AddNewNode<Int32Compare>({left, right}, kOperation));
      return;
    }
    case CompareOperationHint::kNumberOrOddball:
      // TODO(leszeks): we could support all kNumberOrOddball with
      // BranchIfFloat64Compare, but we'd need to special case comparing
      // oddballs with NaN value (e.g. undefined) against themselves.
      if (MaybeOddballs()) {
        break;
      }
      [[fallthrough]];
    case CompareOperationHint::kNumberOrBoolean:
      if (kOperation == Operation::kStrictEqual && MaybeOddballs()) {
        break;
      }
      [[fallthrough]];
    case CompareOperationHint::kNumber: {
      ValueNode* left = LoadRegister(0);
      ValueNode* right = GetAccumulator();
      if (left->value_representation() == ValueRepresentation::kInt32 &&
          right->value_representation() == ValueRepresentation::kInt32) {
        if (TryConstantFoldEqual(left, right)) return;
        if (TryConstantFoldInt32(left, right)) return;
        SortCommute(left, right);
        SetAccumulator(AddNewNode<Int32Compare>({left, right}, kOperation));
        return;
      }
      ToNumberHint to_number_hint =
          nexus.GetCompareOperationFeedback() ==
                  CompareOperationHint::kNumberOrBoolean
              ? ToNumberHint::kAssumeNumberOrBoolean
              : ToNumberHint::kDisallowToNumber;
      left = GetFloat64ForToNumber(left, to_number_hint);
      right = GetFloat64ForToNumber(right, to_number_hint);
      if (left->Is<Float64Constant>() && right->Is<Float64Constant>()) {
        double left_value = left->Cast<Float64Constant>()->value().get_scalar();
        double right_value =
            right->Cast<Float64Constant>()->value().get_scalar();
        SetAccumulator(GetBooleanConstant(
            OperationValue<kOperation>(left_value, right_value)));
        return;
      }
      SortCommute(left, right);
      SetAccumulator(AddNewNode<Float64Compare>({left, right}, kOperation));
      return;
    }
    case CompareOperationHint::kInternalizedString: {
      DCHECK(kOperation == Operation::kEqual ||
             kOperation == Operation::kStrictEqual);
      ValueNode *left, *right;
      if (IsRegisterEqualToAccumulator(0)) {
        left = right = GetInternalizedString(iterator_.GetRegisterOperand(0));
        SetAccumulator(GetRootConstant(RootIndex::kTrueValue));
        return;
      }
      left = GetInternalizedString(iterator_.GetRegisterOperand(0));
      right =
          GetInternalizedString(interpreter::Register::virtual_accumulator());
      if (TryConstantFoldEqual(left, right)) return;
      SetAccumulator(BuildTaggedEqual(left, right));
      return;
    }
    case CompareOperationHint::kSymbol: {
      DCHECK(kOperation == Operation::kEqual ||
             kOperation == Operation::kStrictEqual);

      ValueNode* left = LoadRegister(0);
      ValueNode* right = GetAccumulator();
      BuildCheckSymbol(left);
      BuildCheckSymbol(right);
      if (TryConstantFoldEqual(left, right)) return;
      SetAccumulator(BuildTaggedEqual(left, right));
      return;
    }
    case CompareOperationHint::kString: {
      ValueNode* left = LoadRegister(0);
      ValueNode* right = GetAccumulator();
      BuildCheckString(left);
      BuildCheckString(right);

      ValueNode* result;
      if (TryConstantFoldEqual(left, right)) return;
      ValueNode* tagged_left = GetTaggedValue(left);
      ValueNode* tagged_right = GetTaggedValue(right);
      switch (kOperation) {
        case Operation::kEqual:
        case Operation::kStrictEqual:
          result = AddNewNode<StringEqual>({tagged_left, tagged_right});
          break;
        case Operation::kLessThan:
          result = BuildCallBuiltin<Builtin::kStringLessThan>(
              {tagged_left, tagged_right});
          break;
        case Operation::kLessThanOrEqual:
          result = BuildCallBuiltin<Builtin::kStringLessThanOrEqual>(
              {tagged_left, tagged_right});
          break;
        case Operation::kGreaterThan:
          result = BuildCallBuiltin<Builtin::kStringGreaterThan>(
              {tagged_left, tagged_right});
          break;
        case Operation::kGreaterThanOrEqual:
          result = BuildCallBuiltin<Builtin::kStringGreaterThanOrEqual>(
              {tagged_left, tagged_right});
          break;
      }

      SetAccumulator(result);
      return;
    }
    case CompareOperationHint::kAny:
    case CompareOperationHint::kBigInt64:
    case CompareOperationHint::kBigInt:
    case CompareOperationHint::kReceiverOrNullOrUndefined:
      break;
    case CompareOperationHint::kReceiver: {
      DCHECK(kOperation == Operation::kEqual ||
             kOperation == Operation::kStrictEqual);

      ValueNode* left = LoadRegister(0);
      ValueNode* right = GetAccumulator();
      BuildCheckJSReceiver(left);
      BuildCheckJSReceiver(right);
      SetAccumulator(BuildTaggedEqual(left, right));
      return;
    }
  }

  BuildGenericBinaryOperationNode<kOperation>();
}

void MaglevGraphBuilder::VisitLdar() {
  MoveNodeBetweenRegisters(iterator_.GetRegisterOperand(0),
                           interpreter::Register::virtual_accumulator());
}

void MaglevGraphBuilder::VisitLdaZero() { SetAccumulator(GetSmiConstant(0)); }
void MaglevGraphBuilder::VisitLdaSmi() {
  int constant = iterator_.GetImmediateOperand(0);
  SetAccumulator(GetSmiConstant(constant));
}
void MaglevGraphBuilder::VisitLdaUndefined() {
  SetAccumulator(GetRootConstant(RootIndex::kUndefinedValue));
}
void MaglevGraphBuilder::VisitLdaNull() {
  SetAccumulator(GetRootConstant(RootIndex::kNullValue));
}
void MaglevGraphBuilder::VisitLdaTheHole() {
  SetAccumulator(GetRootConstant(RootIndex::kTheHoleValue));
}
void MaglevGraphBuilder::VisitLdaTrue() {
  SetAccumulator(GetRootConstant(RootIndex::kTrueValue));
}
void MaglevGraphBuilder::VisitLdaFalse() {
  SetAccumulator(GetRootConstant(RootIndex::kFalseValue));
}
void MaglevGraphBuilder::VisitLdaConstant() {
  SetAccumulator(GetConstant(GetRefOperand<HeapObject>(0)));
}

bool MaglevGraphBuilder::TrySpecializeLoadContextSlotToFunctionContext(
    ValueNode* context, int slot_index, ContextSlotMutability slot_mutability) {
  DCHECK(compilation_unit_->info()->specialize_to_function_context());

  if (slot_mutability == kMutable) return false;

  auto constant = TryGetConstant(context);
  if (!constant) return false;

  compiler::ContextRef context_ref = constant.value().AsContext();

  compiler::OptionalObjectRef maybe_slot_value =
      context_ref.get(broker(), slot_index);
  if (!maybe_slot_value.has_value()) return false;

  compiler::ObjectRef slot_value = maybe_slot_value.value();
  if (slot_value.IsHeapObject()) {
    // Even though the context slot is immutable, the context might have escaped
    // before the function to which it belongs has initialized the slot.  We
    // must be conservative and check if the value in the slot is currently the
    // hole or undefined. Only if it is neither of these, can we be sure that it
    // won't change anymore.
    //
    // See also: JSContextSpecialization::ReduceJSLoadContext.
    compiler::OddballType oddball_type =
        slot_value.AsHeapObject().map(broker()).oddball_type(broker());
    if (oddball_type == compiler::OddballType::kUndefined ||
        slot_value.IsTheHole()) {
      return false;
    }
  }

  // Fold the load of the immutable slot.

  SetAccumulator(GetConstant(slot_value));
  return true;
}

ValueNode* MaglevGraphBuilder::TrySpecializeLoadScriptContextSlot(
    ValueNode* context_node, int index) {
  if (!context_node->Is<Constant>()) return {};
  compiler::ContextRef context =
      context_node->Cast<Constant>()->ref().AsContext();
  DCHECK(context.object()->IsScriptContext());
  auto maybe_property = context.object()->GetScriptContextSideProperty(index);
  auto property =
      maybe_property ? maybe_property.value() : ContextSidePropertyCell::kOther;
  int offset = Context::OffsetOfElementAt(index);
  switch (property) {
    case ContextSidePropertyCell::kConst: {
      compiler::OptionalObjectRef constant = context.get(broker(), index);
      if (!constant.has_value()) {
        return BuildLoadTaggedField<LoadTaggedFieldForContextSlot>(context_node,
                                                                   offset);
      }
      broker()->dependencies()->DependOnScriptContextSlotProperty(
          context, index, property, broker());
      return GetConstant(*constant);
    }
    case ContextSidePropertyCell::kSmi: {
      broker()->dependencies()->DependOnScriptContextSlotProperty(
          context, index, property, broker());
      ValueNode* value = BuildLoadTaggedField<LoadTaggedFieldForContextSlot>(
          context_node, offset);
      EnsureType(value, NodeType::kSmi);
      return value;
    }
    case ContextSidePropertyCell::kMutableHeapNumber:
      broker()->dependencies()->DependOnScriptContextSlotProperty(
          context, index, property, broker());
      return AddNewNode<LoadDoubleField>({context_node}, offset);
    case ContextSidePropertyCell::kOther:
      return BuildLoadTaggedField<LoadTaggedFieldForContextSlot>(context_node,
                                                                 offset);
  }
}

ValueNode* MaglevGraphBuilder::LoadAndCacheContextSlot(
    ValueNode* context, int index, ContextSlotMutability slot_mutability,
    ContextKind context_kind) {
  int offset = Context::OffsetOfElementAt(index);
  ValueNode*& cached_value =
      slot_mutability == kMutable
          ? known_node_aspects().loaded_context_slots[{context, offset}]
          : known_node_aspects().loaded_context_constants[{context, offset}];
  if (cached_value) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  * Reusing cached context slot "
                << PrintNodeLabel(graph_labeller(), context) << "[" << offset
                << "]: " << PrintNode(graph_labeller(), cached_value)
                << std::endl;
    }
    return cached_value;
  }
  known_node_aspects().UpdateMayHaveAliasingContexts(context);
  if (context_kind == ContextKind::kScriptContext) {
    cached_value = TrySpecializeLoadScriptContextSlot(context, index);
    if (cached_value) return cached_value;
    return cached_value =
               BuildLoadTaggedField<LoadTaggedFieldForScriptContextSlot>(
                   context, index);
  }
  return cached_value = BuildLoadTaggedField<LoadTaggedFieldForContextSlot>(
             context, offset);
}

bool MaglevGraphBuilder::ContextMayAlias(
    ValueNode* context, compiler::OptionalScopeInfoRef scope_info) {
  if (!scope_info.has_value()) {
    return true;
  }
  auto other = graph()->TryGetScopeInfo(context, broker());
  if (!other.has_value()) {
    return true;
  }
  return scope_info->equals(*other);
}

ReduceResult MaglevGraphBuilder::TrySpecializeStoreScriptContextSlot(
    ValueNode* context, int index, ValueNode* value, Node** store) {
  DCHECK_NOT_NULL(store);
  DCHECK(v8_flags.script_context_mutable_heap_number ||
         v8_flags.const_tracking_let);
  if (!context->Is<Constant>()) {
    *store = AddNewNode<StoreScriptContextSlotWithWriteBarrier>(
        {context, value}, index);
    return ReduceResult::Done();
  }

  compiler::ContextRef context_ref =
      context->Cast<Constant>()->ref().AsContext();
  DCHECK(context_ref.object()->IsScriptContext());
  auto maybe_property =
      context_ref.object()->GetScriptContextSideProperty(index);
  if (!maybe_property) {
    *store = AddNewNode<StoreScriptContextSlotWithWriteBarrier>(
        {context, value}, index);
    return ReduceResult::Done();
  }
  auto property = maybe_property.value();
  int offset = Context::OffsetOfElementAt(index);
  if (property == ContextSidePropertyCell::kConst) {
    compiler::OptionalObjectRef constant = context_ref.get(broker(), index);
    if (!constant.has_value() ||
        (constant->IsString() && !constant->IsInternalizedString())) {
      *store = AddNewNode<StoreScriptContextSlotWithWriteBarrier>(
          {context, value}, index);
      return ReduceResult::Done();
    }
    broker()->dependencies()->DependOnScriptContextSlotProperty(
        context_ref, index, property, broker());
    return BuildCheckValue(value, *constant);
  }

  if (!v8_flags.script_context_mutable_heap_number) {
    *store = BuildStoreTaggedField(context, value, offset,
                                   StoreTaggedMode::kDefault);
    return ReduceResult::Done();
  }

  switch (property) {
    case ContextSidePropertyCell::kConst:
      UNREACHABLE();
    case ContextSidePropertyCell::kSmi:
      RETURN_IF_ABORT(BuildCheckSmi(value));
      broker()->dependencies()->DependOnScriptContextSlotProperty(
          context_ref, index, property, broker());
      *store = BuildStoreTaggedField(context, value, offset,
                                     StoreTaggedMode::kDefault);
      break;
    case ContextSidePropertyCell::kMutableHeapNumber:
      BuildCheckNumber(value);
      broker()->dependencies()->DependOnScriptContextSlotProperty(
          context_ref, index, property, broker());
      *store = AddNewNode<StoreDoubleField>({context, value}, offset);
      break;
    case ContextSidePropertyCell::kOther:
      *store = BuildStoreTaggedField(context, value, offset,
                                     StoreTaggedMode::kDefault);
      break;
  }
  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::StoreAndCacheContextSlot(
    ValueNode* context, int index, ValueNode* value, ContextKind context_kind) {
  int offset = Context::OffsetOfElementAt(index);
  DCHECK_EQ(
      known_node_aspects().loaded_context_constants.count({context, offset}),
      0);

  Node* store = nullptr;
  if ((v8_flags.script_context_mutable_heap_number ||
       v8_flags.const_tracking_let) &&
      context_kind == ContextKind::kScriptContext) {
    ReduceResult result =
        TrySpecializeStoreScriptContextSlot(context, index, value, &store);
    RETURN_IF_ABORT(result);
    if (!store) {
      // If we didn't need to emit any store, there is nothing to cache.
      DCHECK(result.IsDone());
      return result;
    }
  } else {
    store = BuildStoreTaggedField(context, value, offset,
                                  StoreTaggedMode::kDefault);
  }

  if (v8_flags.trace_maglev_graph_building) {
    std::cout << "  * Recording context slot store "
              << PrintNodeLabel(graph_labeller(), context) << "[" << offset
              << "]: " << PrintNode(graph_labeller(), value) << std::endl;
  }
  known_node_aspects().UpdateMayHaveAliasingContexts(context);
  KnownNodeAspects::LoadedContextSlots& loaded_context_slots =
      known_node_aspects().loaded_context_slots;
  if (known_node_aspects().may_have_aliasing_contexts() ==
      KnownNodeAspects::ContextSlotLoadsAlias::Yes) {
    compiler::OptionalScopeInfoRef scope_info =
        graph()->TryGetScopeInfo(context, broker());
    for (auto& cache : loaded_context_slots) {
      if (std::get<int>(cache.first) == offset &&
          std::get<ValueNode*>(cache.first) != context) {
        if (ContextMayAlias(std::get<ValueNode*>(cache.first), scope_info) &&
            cache.second != value) {
          if (v8_flags.trace_maglev_graph_building) {
            std::cout << "  * Clearing probably aliasing value "
                      << PrintNodeLabel(graph_labeller(),
                                        std::get<ValueNode*>(cache.first))
                      << "[" << offset
                      << "]: " << PrintNode(graph_labeller(), value)
                      << std::endl;
          }
          cache.second = nullptr;
          if (is_loop_effect_tracking()) {
            loop_effects_->context_slot_written.insert(cache.first);
            loop_effects_->may_have_aliasing_contexts = true;
          }
        }
      }
    }
  }
  KnownNodeAspects::LoadedContextSlotsKey key{context, offset};
  auto updated = loaded_context_slots.emplace(key, value);
  if (updated.second) {
    if (is_loop_effect_tracking()) {
      loop_effects_->context_slot_written.insert(key);
    }
    unobserved_context_slot_stores_[key] = store;
  } else {
    if (updated.first->second != value) {
      updated.first->second = value;
      if (is_loop_effect_tracking()) {
        loop_effects_->context_slot_written.insert(key);
      }
    }
    if (known_node_aspects().may_have_aliasing_contexts() !=
        KnownNodeAspects::ContextSlotLoadsAlias::Yes) {
      auto last_store = unobserved_context_slot_stores_.find(key);
      if (last_store != unobserved_context_slot_stores_.end()) {
        MarkNodeDead(last_store->second);
        last_store->second = store;
      } else {
        unobserved_context_slot_stores_[key] = store;
      }
    }
  }
  return ReduceResult::Done();
}

void MaglevGraphBuilder::BuildLoadContextSlot(
    ValueNode* context, size_t depth, int slot_index,
    ContextSlotMutability slot_mutability, ContextKind context_kind) {
  context = GetContextAtDepth(context, depth);
  if (compilation_unit_->info()->specialize_to_function_context() &&
      TrySpecializeLoadContextSlotToFunctionContext(context, slot_index,
                                                    slot_mutability)) {
    return;  // Our work here is done.
  }

  // Always load the slot here as if it were mutable. Immutable slots have a
  // narrow range of mutability if the context escapes before the slot is
  // initialized, so we can't safely assume that the load can be cached in case
  // it's a load before initialization (e.g. var a = a + 42).
  current_interpreter_frame_.set_accumulator(
      LoadAndCacheContextSlot(context, slot_index, kMutable, context_kind));
}

ReduceResult MaglevGraphBuilder::BuildStoreContextSlot(
    ValueNode* context, size_t depth, int slot_index, ValueNode* value,
    ContextKind context_kind) {
  context = GetContextAtDepth(context, depth);
  return StoreAndCacheContextSlot(context, slot_index, value, context_kind);
}

void MaglevGraphBuilder::VisitLdaContextSlot() {
  ValueNode* context = LoadRegister(0);
  int slot_index = iterator_.GetIndexOperand(1);
  size_t depth = iterator_.GetUnsignedImmediateOperand(2);
  BuildLoadContextSlot(context, depth, slot_index, kMutable,
                       ContextKind::kDefault);
}
void MaglevGraphBuilder::VisitLdaScriptContextSlot() {
  ValueNode* context = LoadRegister(0);
  int slot_index = iterator_.GetIndexOperand(1);
  size_t depth = iterator_.GetUnsignedImmediateOperand(2);
  BuildLoadContextSlot(context, depth, slot_index, kMutable,
                       ContextKind::kScriptContext);
}
void MaglevGraphBuilder::VisitLdaImmutableContextSlot() {
  ValueNode* context = LoadRegister(0);
  int slot_index = iterator_.GetIndexOperand(1);
  size_t depth = iterator_.GetUnsignedImmediateOperand(2);
  BuildLoadContextSlot(context, depth, slot_index, kImmutable,
                       ContextKind::kDefault);
}
void MaglevGraphBuilder::VisitLdaCurrentContextSlot() {
  ValueNode* context = GetContext();
  int slot_index = iterator_.GetIndexOperand(0);
  BuildLoadContextSlot(context, 0, slot_index, kMutable, ContextKind::kDefault);
}
void MaglevGraphBuilder::VisitLdaCurrentScriptContextSlot() {
  ValueNode* context = GetContext();
  int slot_index = iterator_.GetIndexOperand(0);
  BuildLoadContextSlot(context, 0, slot_index, kMutable,
                       ContextKind::kScriptContext);
}
void MaglevGraphBuilder::VisitLdaImmutableCurrentContextSlot() {
  ValueNode* context = GetContext();
  int slot_index = iterator_.GetIndexOperand(0);
  BuildLoadContextSlot(context, 0, slot_index, kImmutable,
                       ContextKind::kDefault);
}

void MaglevGraphBuilder::VisitStaContextSlot() {
  ValueNode* context = LoadRegister(0);
  int slot_index = iterator_.GetIndexOperand(1);
  size_t depth = iterator_.GetUnsignedImmediateOperand(2);
  RETURN_VOID_IF_DONE(BuildStoreContextSlot(
      context, depth, slot_index, GetAccumulator(), ContextKind::kDefault));
}
void MaglevGraphBuilder::VisitStaCurrentContextSlot() {
  ValueNode* context = GetContext();
  int slot_index = iterator_.GetIndexOperand(0);
  RETURN_VOID_IF_DONE(BuildStoreContextSlot(
      context, 0, slot_index, GetAccumulator(), ContextKind::kDefault));
}

void MaglevGraphBuilder::VisitStaScriptContextSlot() {
  ValueNode* context = LoadRegister(0);
  int slot_index = iterator_.GetIndexOperand(1);
  size_t depth = iterator_.GetUnsignedImmediateOperand(2);
  RETURN_VOID_IF_DONE(BuildStoreContextSlot(context, depth, slot_index,
                                            GetAccumulator(),
                                            ContextKind::kScriptContext));
}

void MaglevGraphBuilder::VisitStaCurrentScriptContextSlot() {
  ValueNode* context = GetContext();
  int slot_index = iterator_.GetIndexOperand(0);
  RETURN_VOID_IF_DONE(BuildStoreContextSlot(
      context, 0, slot_index, GetAccumulator(), ContextKind::kScriptContext));
}

void MaglevGraphBuilder::VisitStar() {
  MoveNodeBetweenRegisters(interpreter::Register::virtual_accumulator(),
                           iterator_.GetRegisterOperand(0));
}
#define SHORT_STAR_VISITOR(Name, ...)                                          \
  void MaglevGraphBuilder::Visit##Name() {                                     \
    MoveNodeBetweenRegisters(                                                  \
        interpreter::Register::virtual_accumulator(),                          \
        interpreter::Register::FromShortStar(interpreter::Bytecode::k##Name)); \
  }
SHORT_STAR_BYTECODE_LIST(SHORT_STAR_VISITOR)
#undef SHORT_STAR_VISITOR

void MaglevGraphBuilder::VisitMov() {
  MoveNodeBetweenRegisters(iterator_.GetRegisterOperand(0),
                           iterator_.GetRegisterOperand(1));
}

void MaglevGraphBuilder::VisitPushContext() {
  MoveNodeBetweenRegisters(interpreter::Register::current_context(),
                           iterator_.GetRegisterOperand(0));
  SetContext(GetAccumulator());
}

void MaglevGraphBuilder::VisitPopContext() { SetContext(LoadRegister(0)); }

ValueNode* MaglevGraphBuilder::BuildTaggedEqual(ValueNode* lhs,
                                                ValueNode* rhs) {
  ValueNode* tagged_lhs = GetTaggedValue(lhs);
  ValueNode* tagged_rhs = GetTaggedValue(rhs);
  if (tagged_lhs == tagged_rhs) {
    return GetBooleanConstant(true);
  }
  if (HaveDifferentTypes(tagged_lhs, tagged_rhs)) {
    return GetBooleanConstant(false);
  }
  // TODO(victorgomes): We could retrieve the HeapObjectRef in Constant and
  // compare them.
  if (IsConstantNode(tagged_lhs->opcode()) && !tagged_lhs->Is<Constant>() &&
      tagged_lhs->opcode() == tagged_rhs->opcode()) {
    // Constants nodes are canonicalized, except for the node holding
    // HeapObjectRef, so equal constants should have been handled above.
    return GetBooleanConstant(false);
  }
  return AddNewNode<TaggedEqual>({tagged_lhs, tagged_rhs});
}

ValueNode* MaglevGraphBuilder::BuildTaggedEqual(ValueNode* lhs,
                                                RootIndex rhs_index) {
  return BuildTaggedEqual(lhs, GetRootConstant(rhs_index));
}

void MaglevGraphBuilder::VisitTestReferenceEqual() {
  V
```