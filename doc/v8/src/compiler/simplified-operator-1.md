Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is part of the `simplified-operator.cc` file in the V8 JavaScript engine. This is the second part of the file. I also need to explain how it relates to JavaScript, providing JavaScript examples if applicable.

**Part 2 Focus:**  Based on the keywords and function names in the code, this part seems to heavily focus on:

1. **WebAssembly (Wasm) Operators:** Functions like `WasmTypeCastAbstract`, `RttCanon`, `IsNull`, `IsNotNull`, `Null`, `AssertNotNull`, `WasmAnyConvertExtern`, `WasmExternConvertAny`, `WasmStructGet`, `WasmStructSet`, `WasmArrayGet`, `WasmArraySet`, `WasmArrayLength`, and `WasmArrayInitializeLength` clearly indicate support for WebAssembly operations.
2. **Type Checking and Conversions:** Operators like `CheckIf`, `ChangeFloat64ToTagged`, `CheckedInt32Mul`, `CheckedFloat64ToInt32`, `CheckedFloat64ToInt64`, `CheckedTaggedToInt32`, `CheckedTaggedToFloat64`, and `CheckedTruncateTaggedToWord32` are involved in ensuring type safety and performing conversions between different data types.
3. **Object and Map Operations:** Functions like `CheckMaps`, `MapGuard`, `CompareMaps`, `ConvertReceiver`, and `CheckFloat64Hole` deal with the structure and properties of JavaScript objects.
4. **BigInt Support:**  The `SpeculativeBigInt` prefixed functions suggest operations related to JavaScript's BigInt data type.
5. **Feedback and Optimization:** The presence of `FeedbackSource` parameters in several functions indicates that these operators are used in the context of optimizing JavaScript execution based on runtime feedback.
6. **Array and Element Access:** Operators like `EnsureWritableFastElements`, `MaybeGrowFastElements`, `TransitionElementsKind`, `LoadElement`, `StoreElement`, `LoadTypedElement`, `StoreTypedElement`, and functions related to `Arguments` handling deal with array operations.
7. **Object Property Access:** Operators like `LoadField`, `StoreField`, `LoadFromObject`, `StoreToObject`, `LoadImmutableFromObject`, and `InitializeImmutableInObject` are used for accessing and modifying object properties.
8. **Fast API Calls:** The `FastApiCall` operator enables efficient calls to C++ functions from JavaScript.

**JavaScript Relationship:** Many of these operators directly correspond to operations that can be performed in JavaScript. For example, type checks, conversions, arithmetic operations, object property access, and array manipulation are fundamental JavaScript concepts. The WebAssembly operators bridge the gap between JavaScript and WebAssembly modules.

**Plan:** I will categorize the functionalities, explain their purpose, and provide relevant JavaScript examples for the categories that have a clear connection to JavaScript features. For WebAssembly specific operators, I will explain their role in the interaction between JavaScript and WebAssembly.
这是 `v8/src/compiler/simplified-operator.cc` 文件的第二部分，它延续了第一部分的功能，主要负责定义和构建 **Simplified 阶段** 图中使用的操作符（Operators）。Simplified 阶段是 V8 编译器中的一个关键步骤，它将高级的 JavaScript 操作转换为更底层的、更接近机器指令的操作。

**总的来说，这部分代码的功能是扩展了 Simplified 阶段可以表示的操作，尤其侧重于以下几个方面：**

1. **WebAssembly 支持:** 提供了与 WebAssembly 交互所需的各种操作符，例如类型转换、RTTI 操作、空值检查、结构体和数组的读取和写入等。
2. **更精细的类型检查和转换:** 定义了更具体的类型检查操作符，例如针对 `null` 和 `undefined` 的检查，以及带有溢出检查的整数乘法和浮点数到整数的转换。
3. **更细粒度的对象和 Map 操作:**  引入了 `CheckMaps`、`MapGuard` 和 `CompareMaps` 等操作符，用于更精确地处理 JavaScript 对象的类型和结构信息，这对于优化代码至关重要。
4. **BigInt 支持:**  添加了用于处理 JavaScript BigInt 类型的操作符，包括算术运算、比较和类型转换。
5. **更精细的数值转换:** 提供了带有反馈信息的数值转换操作符，例如 `SpeculativeToNumber`，允许编译器根据运行时反馈进行更优化的转换。
6. **数组和元素操作:**  定义了用于管理和操作 JavaScript 数组元素的操作符，包括调整数组大小、元素类型转换以及更底层的元素加载和存储。
7. **函数参数处理:**  引入了 `ArgumentsLength` 和 `RestLength` 操作符，用于获取函数参数的长度，特别是处理剩余参数的情况。
8. **更细致的属性访问:**  提供了更底层的属性加载和存储操作符，例如 `LoadField`、`StoreField`、`LoadElement`、`StoreElement` 等，并区分了不同类型的属性访问（例如，不可变属性）。
9. **与 C++ 代码的交互:** 引入了 `FastApiCall` 操作符，用于高效地调用 C++ 函数，这是 V8 扩展机制的关键部分。
10. **其他辅助操作:**  还包含一些辅助性的操作符，例如用于加载和存储消息、处理 continuation 保存的 embedder data 等。

**与 JavaScript 的关系及 JavaScript 示例:**

这部分代码定义的操作符最终会被用于表示 JavaScript 代码的执行逻辑。以下是一些与 JavaScript 功能相关的示例：

**1. WebAssembly 支持:**

```javascript
// JavaScript 调用 WebAssembly 模块
const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
const result = instance.exports.add(10, 20); // 调用 wasm 模块的 add 函数

// SimplifiedOperatorBuilder 中相关的操作符：
// - WasmTypeCastAbstract: 用于 wasm 类型之间的抽象转换。
// - RttCanon: 用于获取 wasm RTTI 的规范表示。
// - WasmStructGet/WasmStructSet: 用于访问 wasm 结构体的字段。
// - WasmArrayGet/WasmArraySet: 用于访问 wasm 数组的元素。
```

**2. 类型检查和转换:**

```javascript
function foo(x) {
  if (x === null) {
    return 0;
  }
  return x + 1;
}

// SimplifiedOperatorBuilder 中相关的操作符：
// - IsNull: 检查一个值是否为 null。
// - AssertNotNull: 断言一个值不为 null。
// - ChangeFloat64ToTagged: 将浮点数转换为 Tagged 类型（V8 内部表示）。
```

**3. 对象和 Map 操作:**

```javascript
const obj = { a: 1, b: 2 };
if ("a" in obj) {
  console.log(obj.a);
}

// SimplifiedOperatorBuilder 中相关的操作符：
// - CheckMaps: 检查对象的 map 是否符合预期，用于类型优化。
// - MapGuard: 用于保证对象的 map 是特定的。
// - CompareMaps: 用于比较两个对象的 map。
```

**4. BigInt 支持:**

```javascript
const bigIntValue = 9007199254740991n + 1n;
console.log(bigIntValue * 2n);

// SimplifiedOperatorBuilder 中相关的操作符：
// - SpeculativeBigIntAdd/SpeculativeBigIntMultiply 等: 用于 BigInt 的算术运算。
// - SpeculativeBigIntEqual/SpeculativeBigIntLessThan 等: 用于 BigInt 的比较。
// - SpeculativeToBigInt: 将其他类型转换为 BigInt。
```

**5. 数组和元素操作:**

```javascript
const arr = [1, 2, 3];
arr.push(4);
console.log(arr[0]);

// SimplifiedOperatorBuilder 中相关的操作符：
// - EnsureWritableFastElements: 确保数组处于可写状态。
// - MaybeGrowFastElements:  可能扩展数组的存储空间。
// - TransitionElementsKind: 改变数组元素的类型表示（例如，从 SMI 到 DOUBLE）。
// - LoadElement/StoreElement: 加载和存储数组元素。
```

**6. 函数参数处理:**

```javascript
function sum(a, b, ...rest) {
  console.log("Arguments length:", arguments.length);
  console.log("Rest arguments:", rest);
}

sum(1, 2, 3, 4, 5);

// SimplifiedOperatorBuilder 中相关的操作符：
// - ArgumentsLength: 获取 'arguments' 对象的长度。
// - RestLength: 获取剩余参数的长度。
```

**7. 属性访问:**

```javascript
const obj = { x: 10 };
console.log(obj.x);
obj.y = 20;

// SimplifiedOperatorBuilder 中相关的操作符：
// - LoadField: 加载对象的属性值。
// - StoreField: 存储对象的属性值。
```

**总结:**

`v8/src/compiler/simplified-operator.cc` 的第二部分继续定义了 V8 编译器 Simplified 阶段使用的操作符，这些操作符覆盖了更广泛的 JavaScript 功能，特别是与 WebAssembly 互操作、更精细的类型处理、BigInt 支持以及更底层的对象和数组操作。这些操作符是 V8 编译器将 JavaScript 代码转换为高效机器码的关键构建块。通过这些操作符，编译器能够更好地理解和优化 JavaScript 代码的执行。

### 提示词
```
这是目录为v8/src/compiler/simplified-operator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
rite | Operator::kNoThrow | Operator::kIdempotent,
      "WasmTypeCastAbstract", 1, 1, 1, 1, 1, 1, config);
}

const Operator* SimplifiedOperatorBuilder::RttCanon(
    wasm::ModuleTypeIndex index) {
  return zone()->New<Operator1<int>>(IrOpcode::kRttCanon, Operator::kPure,
                                     "RttCanon", 1, 0, 0, 1, 0, 0, index.index);
}

// Note: The following two operators have a control input solely to find the
// typing context from the control path in wasm-gc-operator-reducer.
struct IsNullOperator final : public Operator1<wasm::ValueType> {
  explicit IsNullOperator(wasm::ValueType type)
      : Operator1(IrOpcode::kIsNull, Operator::kPure, "IsNull", 1, 0, 1, 1, 0,
                  0, type) {}
};

struct IsNotNullOperator final : public Operator1<wasm::ValueType> {
  explicit IsNotNullOperator(wasm::ValueType type)
      : Operator1(IrOpcode::kIsNotNull, Operator::kPure, "IsNotNull", 1, 0, 1,
                  1, 0, 0, type) {}
};

struct NullOperator final : public Operator1<wasm::ValueType> {
  explicit NullOperator(wasm::ValueType type)
      : Operator1(IrOpcode::kNull, Operator::kPure, "Null", 0, 0, 0, 1, 0, 0,
                  type) {}
};

struct AssertNotNullOperator final : public Operator1<AssertNotNullParameters> {
  explicit AssertNotNullOperator(wasm::ValueType type, TrapId trap_id)
      : Operator1(
            IrOpcode::kAssertNotNull,
            Operator::kNoWrite | Operator::kNoThrow | Operator::kIdempotent,
            "AssertNotNull", 1, 1, 1, 1, 1, 1, {type, trap_id}) {}
};

const Operator* SimplifiedOperatorBuilder::Null(wasm::ValueType type) {
  return zone()->New<NullOperator>(type);
}

const Operator* SimplifiedOperatorBuilder::AssertNotNull(wasm::ValueType type,
                                                         TrapId trap_id) {
  return zone()->New<AssertNotNullOperator>(type, trap_id);
}

const Operator* SimplifiedOperatorBuilder::IsNull(wasm::ValueType type) {
  return zone()->New<IsNullOperator>(type);
}
const Operator* SimplifiedOperatorBuilder::IsNotNull(wasm::ValueType type) {
  return zone()->New<IsNotNullOperator>(type);
}

const Operator* SimplifiedOperatorBuilder::StringAsWtf16() {
  return &cache_.kStringAsWtf16;
}

const Operator* SimplifiedOperatorBuilder::StringPrepareForGetCodeunit() {
  return &cache_.kStringPrepareForGetCodeunit;
}

const Operator* SimplifiedOperatorBuilder::WasmAnyConvertExtern() {
  return zone()->New<Operator>(IrOpcode::kWasmAnyConvertExtern,
                               Operator::kEliminatable, "WasmAnyConvertExtern",
                               1, 1, 1, 1, 1, 1);
}

const Operator* SimplifiedOperatorBuilder::WasmExternConvertAny() {
  return zone()->New<Operator>(IrOpcode::kWasmExternConvertAny,
                               Operator::kEliminatable, "WasmExternConvertAny",
                               1, 1, 1, 1, 1, 1);
}

const Operator* SimplifiedOperatorBuilder::WasmStructGet(
    const wasm::StructType* type, int field_index, bool is_signed,
    CheckForNull null_check) {
  return zone()->New<Operator1<WasmFieldInfo>>(
      IrOpcode::kWasmStructGet, Operator::kEliminatable, "WasmStructGet", 1, 1,
      1, 1, 1, 1, WasmFieldInfo{type, field_index, is_signed, null_check});
}

const Operator* SimplifiedOperatorBuilder::WasmStructSet(
    const wasm::StructType* type, int field_index, CheckForNull null_check) {
  return zone()->New<Operator1<WasmFieldInfo>>(
      IrOpcode::kWasmStructSet,
      Operator::kNoDeopt | Operator::kNoThrow | Operator::kNoRead,
      "WasmStructSet", 2, 1, 1, 0, 1, 1,
      WasmFieldInfo{type, field_index, true /* unused */, null_check});
}

const Operator* SimplifiedOperatorBuilder::WasmArrayGet(
    const wasm::ArrayType* type, bool is_signed) {
  return zone()->New<Operator1<WasmElementInfo>>(
      IrOpcode::kWasmArrayGet, Operator::kEliminatable, "WasmArrayGet", 2, 1, 1,
      1, 1, 0, WasmElementInfo{type, is_signed});
}

const Operator* SimplifiedOperatorBuilder::WasmArraySet(
    const wasm::ArrayType* type) {
  return zone()->New<Operator1<const wasm::ArrayType*>>(
      IrOpcode::kWasmArraySet,
      Operator::kNoDeopt | Operator::kNoThrow | Operator::kNoRead,
      "WasmArraySet", 3, 1, 1, 0, 1, 0, type);
}

const Operator* SimplifiedOperatorBuilder::WasmArrayLength(
    CheckForNull null_check) {
  return null_check == kWithNullCheck ? &cache_.kWasmArrayLengthNullCheck
                                      : &cache_.kWasmArrayLengthNoNullCheck;
}

const Operator* SimplifiedOperatorBuilder::WasmArrayInitializeLength() {
  return &cache_.kWasmArrayInitializeLength;
}

#endif  // V8_ENABLE_WEBASSEMBLY

const Operator* SimplifiedOperatorBuilder::CheckIf(
    DeoptimizeReason reason, const FeedbackSource& feedback) {
  if (!feedback.IsValid()) {
    switch (reason) {
#define CHECK_IF(Name, message)   \
  case DeoptimizeReason::k##Name: \
    return &cache_.kCheckIf##Name;
    DEOPTIMIZE_REASON_LIST(CHECK_IF)
#undef CHECK_IF
    }
  }
  return zone()->New<Operator1<CheckIfParameters>>(
      IrOpcode::kCheckIf, Operator::kFoldable | Operator::kNoThrow, "CheckIf",
      1, 1, 1, 0, 1, 0, CheckIfParameters(reason, feedback));
}

const Operator* SimplifiedOperatorBuilder::ChangeFloat64ToTagged(
    CheckForMinusZeroMode mode) {
  switch (mode) {
    case CheckForMinusZeroMode::kCheckForMinusZero:
      return &cache_.kChangeFloat64ToTaggedCheckForMinusZeroOperator;
    case CheckForMinusZeroMode::kDontCheckForMinusZero:
      return &cache_.kChangeFloat64ToTaggedDontCheckForMinusZeroOperator;
  }
  UNREACHABLE();
}

const Operator* SimplifiedOperatorBuilder::CheckedInt32Mul(
    CheckForMinusZeroMode mode) {
  switch (mode) {
    case CheckForMinusZeroMode::kCheckForMinusZero:
      return &cache_.kCheckedInt32MulCheckForMinusZeroOperator;
    case CheckForMinusZeroMode::kDontCheckForMinusZero:
      return &cache_.kCheckedInt32MulDontCheckForMinusZeroOperator;
  }
  UNREACHABLE();
}

const Operator* SimplifiedOperatorBuilder::CheckedFloat64ToInt32(
    CheckForMinusZeroMode mode, const FeedbackSource& feedback) {
  if (!feedback.IsValid()) {
    switch (mode) {
      case CheckForMinusZeroMode::kCheckForMinusZero:
        return &cache_.kCheckedFloat64ToInt32CheckForMinusZeroOperator;
      case CheckForMinusZeroMode::kDontCheckForMinusZero:
        return &cache_.kCheckedFloat64ToInt32DontCheckForMinusZeroOperator;
    }
  }
  return zone()->New<Operator1<CheckMinusZeroParameters>>(
      IrOpcode::kCheckedFloat64ToInt32,
      Operator::kFoldable | Operator::kNoThrow, "CheckedFloat64ToInt32", 1, 1,
      1, 1, 1, 0, CheckMinusZeroParameters(mode, feedback));
}

const Operator* SimplifiedOperatorBuilder::CheckedFloat64ToInt64(
    CheckForMinusZeroMode mode, const FeedbackSource& feedback) {
  if (!feedback.IsValid()) {
    switch (mode) {
      case CheckForMinusZeroMode::kCheckForMinusZero:
        return &cache_.kCheckedFloat64ToInt64CheckForMinusZeroOperator;
      case CheckForMinusZeroMode::kDontCheckForMinusZero:
        return &cache_.kCheckedFloat64ToInt64DontCheckForMinusZeroOperator;
    }
  }
  return zone()->New<Operator1<CheckMinusZeroParameters>>(
      IrOpcode::kCheckedFloat64ToInt64,
      Operator::kFoldable | Operator::kNoThrow, "CheckedFloat64ToInt64", 1, 1,
      1, 1, 1, 0, CheckMinusZeroParameters(mode, feedback));
}

const Operator* SimplifiedOperatorBuilder::CheckedTaggedToInt32(
    CheckForMinusZeroMode mode, const FeedbackSource& feedback) {
  if (!feedback.IsValid()) {
    switch (mode) {
      case CheckForMinusZeroMode::kCheckForMinusZero:
        return &cache_.kCheckedTaggedToInt32CheckForMinusZeroOperator;
      case CheckForMinusZeroMode::kDontCheckForMinusZero:
        return &cache_.kCheckedTaggedToInt32DontCheckForMinusZeroOperator;
    }
  }
  return zone()->New<Operator1<CheckMinusZeroParameters>>(
      IrOpcode::kCheckedTaggedToInt32, Operator::kFoldable | Operator::kNoThrow,
      "CheckedTaggedToInt32", 1, 1, 1, 1, 1, 0,
      CheckMinusZeroParameters(mode, feedback));
}

const Operator* SimplifiedOperatorBuilder::CheckedTaggedToInt64(
    CheckForMinusZeroMode mode, const FeedbackSource& feedback) {
  if (!feedback.IsValid()) {
    switch (mode) {
      case CheckForMinusZeroMode::kCheckForMinusZero:
        return &cache_.kCheckedTaggedToInt64CheckForMinusZeroOperator;
      case CheckForMinusZeroMode::kDontCheckForMinusZero:
        return &cache_.kCheckedTaggedToInt64DontCheckForMinusZeroOperator;
    }
  }
  return zone()->New<Operator1<CheckMinusZeroParameters>>(
      IrOpcode::kCheckedTaggedToInt64, Operator::kFoldable | Operator::kNoThrow,
      "CheckedTaggedToInt64", 1, 1, 1, 1, 1, 0,
      CheckMinusZeroParameters(mode, feedback));
}

const Operator* SimplifiedOperatorBuilder::CheckedTaggedToFloat64(
    CheckTaggedInputMode mode, const FeedbackSource& feedback) {
  if (!feedback.IsValid()) {
    switch (mode) {
      case CheckTaggedInputMode::kNumber:
        return &cache_.kCheckedTaggedToFloat64NumberOperator;
      case CheckTaggedInputMode::kNumberOrBoolean:
        return &cache_.kCheckedTaggedToFloat64NumberOrBooleanOperator;
      case CheckTaggedInputMode::kNumberOrOddball:
        return &cache_.kCheckedTaggedToFloat64NumberOrOddballOperator;
    }
  }
  return zone()->New<Operator1<CheckTaggedInputParameters>>(
      IrOpcode::kCheckedTaggedToFloat64,
      Operator::kFoldable | Operator::kNoThrow, "CheckedTaggedToFloat64", 1, 1,
      1, 1, 1, 0, CheckTaggedInputParameters(mode, feedback));
}

const Operator* SimplifiedOperatorBuilder::CheckedTruncateTaggedToWord32(
    CheckTaggedInputMode mode, const FeedbackSource& feedback) {
  if (!feedback.IsValid()) {
    switch (mode) {
      case CheckTaggedInputMode::kNumber:
        return &cache_.kCheckedTruncateTaggedToWord32NumberOperator;
      case CheckTaggedInputMode::kNumberOrBoolean:
        // Not used currently.
        UNREACHABLE();
      case CheckTaggedInputMode::kNumberOrOddball:
        return &cache_.kCheckedTruncateTaggedToWord32NumberOrOddballOperator;
    }
  }
  return zone()->New<Operator1<CheckTaggedInputParameters>>(
      IrOpcode::kCheckedTruncateTaggedToWord32,
      Operator::kFoldable | Operator::kNoThrow, "CheckedTruncateTaggedToWord32",
      1, 1, 1, 1, 1, 0, CheckTaggedInputParameters(mode, feedback));
}

const Operator* SimplifiedOperatorBuilder::CheckMaps(
    CheckMapsFlags flags, ZoneRefSet<Map> maps,
    const FeedbackSource& feedback) {
  CheckMapsParameters const parameters(flags, maps, feedback);
  Operator::Properties operator_props = Operator::kNoThrow;
  if (!(flags & CheckMapsFlag::kTryMigrateInstance)) {
    operator_props |= Operator::kNoWrite;
  }
  return zone()->New<Operator1<CheckMapsParameters>>(  // --
      IrOpcode::kCheckMaps,                            // opcode
      operator_props,                                  // flags
      "CheckMaps",                                     // name
      1, 1, 1, 0, 1, 0,                                // counts
      parameters);                                     // parameter
}

const Operator* SimplifiedOperatorBuilder::MapGuard(ZoneRefSet<Map> maps) {
  DCHECK_LT(0, maps.size());
  return zone()->New<Operator1<ZoneRefSet<Map>>>(    // --
      IrOpcode::kMapGuard, Operator::kEliminatable,  // opcode
      "MapGuard",                                    // name
      1, 1, 1, 0, 1, 0,                              // counts
      maps);                                         // parameter
}

const Operator* SimplifiedOperatorBuilder::CompareMaps(ZoneRefSet<Map> maps) {
  DCHECK_LT(0, maps.size());
  return zone()->New<Operator1<ZoneRefSet<Map>>>(  // --
      IrOpcode::kCompareMaps,                      // opcode
      Operator::kNoThrow | Operator::kNoWrite,     // flags
      "CompareMaps",                               // name
      1, 1, 1, 1, 1, 0,                            // counts
      maps);                                       // parameter
}

const Operator* SimplifiedOperatorBuilder::ConvertReceiver(
    ConvertReceiverMode mode) {
  switch (mode) {
    case ConvertReceiverMode::kAny:
      return &cache_.kConvertReceiverAnyOperator;
    case ConvertReceiverMode::kNullOrUndefined:
      return &cache_.kConvertReceiverNullOrUndefinedOperator;
    case ConvertReceiverMode::kNotNullOrUndefined:
      return &cache_.kConvertReceiverNotNullOrUndefinedOperator;
  }
  UNREACHABLE();
}

const Operator* SimplifiedOperatorBuilder::CheckFloat64Hole(
    CheckFloat64HoleMode mode, FeedbackSource const& feedback) {
  if (!feedback.IsValid()) {
    switch (mode) {
      case CheckFloat64HoleMode::kAllowReturnHole:
        return &cache_.kCheckFloat64HoleAllowReturnHoleOperator;
      case CheckFloat64HoleMode::kNeverReturnHole:
        return &cache_.kCheckFloat64HoleNeverReturnHoleOperator;
    }
    UNREACHABLE();
  }
  return zone()->New<Operator1<CheckFloat64HoleParameters>>(
      IrOpcode::kCheckFloat64Hole, Operator::kFoldable | Operator::kNoThrow,
      "CheckFloat64Hole", 1, 1, 1, 1, 1, 0,
      CheckFloat64HoleParameters(mode, feedback));
}

// TODO(panq): Cache speculative bigint operators.
#define SPECULATIVE_BIGINT_BINOP(Name)                                         \
  const Operator* SimplifiedOperatorBuilder::Name(BigIntOperationHint hint) {  \
    return zone()->New<Operator1<BigIntOperationHint>>(                        \
        IrOpcode::k##Name, Operator::kFoldable | Operator::kNoThrow, #Name, 2, \
        1, 1, 1, 1, 0, hint);                                                  \
  }
SIMPLIFIED_SPECULATIVE_BIGINT_BINOP_LIST(SPECULATIVE_BIGINT_BINOP)
SPECULATIVE_BIGINT_BINOP(SpeculativeBigIntEqual)
SPECULATIVE_BIGINT_BINOP(SpeculativeBigIntLessThan)
SPECULATIVE_BIGINT_BINOP(SpeculativeBigIntLessThanOrEqual)
#undef SPECULATIVE_BIGINT_BINOP

const Operator* SimplifiedOperatorBuilder::SpeculativeBigIntNegate(
    BigIntOperationHint hint) {
  return zone()->New<Operator1<BigIntOperationHint>>(
      IrOpcode::kSpeculativeBigIntNegate,
      Operator::kFoldable | Operator::kNoThrow, "SpeculativeBigIntNegate", 1, 1,
      1, 1, 1, 0, hint);
}

const Operator* SimplifiedOperatorBuilder::SpeculativeToBigInt(
    BigIntOperationHint hint, const FeedbackSource& feedback) {
  if (!feedback.IsValid()) {
    switch (hint) {
      case BigIntOperationHint::kBigInt64:
        return &cache_.kSpeculativeToBigIntBigInt64Operator;
      case BigIntOperationHint::kBigInt:
        return &cache_.kSpeculativeToBigIntBigIntOperator;
    }
  }
  return zone()->New<Operator1<BigIntOperationParameters>>(
      IrOpcode::kSpeculativeToBigInt, Operator::kFoldable | Operator::kNoThrow,
      "SpeculativeToBigInt", 1, 1, 1, 1, 1, 0,
      BigIntOperationParameters(hint, feedback));
}

const Operator* SimplifiedOperatorBuilder::CheckClosure(
    const Handle<FeedbackCell>& feedback_cell) {
  return zone()->New<Operator1<IndirectHandle<FeedbackCell>>>(  // --
      IrOpcode::kCheckClosure,                                  // opcode
      Operator::kNoThrow | Operator::kNoWrite,                  // flags
      "CheckClosure",                                           // name
      1, 1, 1, 1, 1, 0,                                         // counts
      feedback_cell);                                           // parameter
}

Handle<FeedbackCell> FeedbackCellOf(const Operator* op) {
  DCHECK(IrOpcode::kCheckClosure == op->opcode());
  return OpParameter<IndirectHandle<FeedbackCell>>(op);
}

const Operator* SimplifiedOperatorBuilder::SpeculativeToNumber(
    NumberOperationHint hint, const FeedbackSource& feedback) {
  if (!feedback.IsValid()) {
    switch (hint) {
      case NumberOperationHint::kSignedSmall:
        return &cache_.kSpeculativeToNumberSignedSmallOperator;
      case NumberOperationHint::kSignedSmallInputs:
        break;
      case NumberOperationHint::kNumber:
        return &cache_.kSpeculativeToNumberNumberOperator;
      case NumberOperationHint::kNumberOrBoolean:
        // Not used currently.
        UNREACHABLE();
      case NumberOperationHint::kNumberOrOddball:
        return &cache_.kSpeculativeToNumberNumberOrOddballOperator;
    }
  }
  return zone()->New<Operator1<NumberOperationParameters>>(
      IrOpcode::kSpeculativeToNumber, Operator::kFoldable | Operator::kNoThrow,
      "SpeculativeToNumber", 1, 1, 1, 1, 1, 0,
      NumberOperationParameters(hint, feedback));
}

const Operator* SimplifiedOperatorBuilder::EnsureWritableFastElements() {
  return &cache_.kEnsureWritableFastElements;
}

const Operator* SimplifiedOperatorBuilder::MaybeGrowFastElements(
    GrowFastElementsMode mode, const FeedbackSource& feedback) {
  if (!feedback.IsValid()) {
    switch (mode) {
      case GrowFastElementsMode::kDoubleElements:
        return &cache_.kGrowFastElementsOperatorDoubleElements;
      case GrowFastElementsMode::kSmiOrObjectElements:
        return &cache_.kGrowFastElementsOperatorSmiOrObjectElements;
    }
  }
  return zone()->New<Operator1<GrowFastElementsParameters>>(  // --
      IrOpcode::kMaybeGrowFastElements,                       // opcode
      Operator::kNoThrow,                                     // flags
      "MaybeGrowFastElements",                                // name
      4, 1, 1, 1, 1, 0,                                       // counts
      GrowFastElementsParameters(mode, feedback));            // parameter
}

const Operator* SimplifiedOperatorBuilder::TransitionElementsKind(
    ElementsTransition transition) {
  return zone()->New<Operator1<ElementsTransition>>(  // --
      IrOpcode::kTransitionElementsKind,              // opcode
      Operator::kNoThrow,                             // flags
      "TransitionElementsKind",                       // name
      1, 1, 1, 0, 1, 0,                               // counts
      transition);                                    // parameter
}

const Operator* SimplifiedOperatorBuilder::ArgumentsLength() {
  return zone()->New<Operator>(    // --
      IrOpcode::kArgumentsLength,  // opcode
      Operator::kPure,             // flags
      "ArgumentsLength",           // name
      0, 0, 0, 1, 0, 0);           // counts
}

const Operator* SimplifiedOperatorBuilder::RestLength(
    int formal_parameter_count) {
  return zone()->New<Operator1<int>>(  // --
      IrOpcode::kRestLength,           // opcode
      Operator::kPure,                 // flags
      "RestLength",                    // name
      0, 0, 0, 1, 0, 0,                // counts
      formal_parameter_count);         // parameter
}

int FormalParameterCountOf(const Operator* op) {
  DCHECK(op->opcode() == IrOpcode::kArgumentsLength ||
         op->opcode() == IrOpcode::kRestLength);
  return OpParameter<int>(op);
}

bool operator==(CheckParameters const& lhs, CheckParameters const& rhs) {
  return lhs.feedback() == rhs.feedback();
}

size_t hash_value(CheckParameters const& p) {
  FeedbackSource::Hash feedback_hash;
  return feedback_hash(p.feedback());
}

std::ostream& operator<<(std::ostream& os, CheckParameters const& p) {
  return os << p.feedback();
}

CheckParameters const& CheckParametersOf(Operator const* op) {
  if (op->opcode() == IrOpcode::kCheckBounds ||
      op->opcode() == IrOpcode::kCheckedUint32Bounds ||
      op->opcode() == IrOpcode::kCheckedUint64Bounds) {
    return OpParameter<CheckBoundsParameters>(op).check_parameters();
  }
#define MAKE_OR(name, arg2, arg3) op->opcode() == IrOpcode::k##name ||
  CHECK((CHECKED_WITH_FEEDBACK_OP_LIST(MAKE_OR) false));
#undef MAKE_OR
  return OpParameter<CheckParameters>(op);
}

bool operator==(CheckBoundsParameters const& lhs,
                CheckBoundsParameters const& rhs) {
  return lhs.check_parameters() == rhs.check_parameters() &&
         lhs.flags() == rhs.flags();
}

size_t hash_value(CheckBoundsParameters const& p) {
  return base::hash_combine(hash_value(p.check_parameters()), p.flags());
}

std::ostream& operator<<(std::ostream& os, CheckBoundsParameters const& p) {
  os << p.check_parameters() << ", " << p.flags();
  return os;
}

CheckBoundsParameters const& CheckBoundsParametersOf(Operator const* op) {
  DCHECK(op->opcode() == IrOpcode::kCheckBounds ||
         op->opcode() == IrOpcode::kCheckedUint32Bounds ||
         op->opcode() == IrOpcode::kCheckedUint64Bounds);
  return OpParameter<CheckBoundsParameters>(op);
}

bool operator==(CheckIfParameters const& lhs, CheckIfParameters const& rhs) {
  return lhs.reason() == rhs.reason() && lhs.feedback() == rhs.feedback();
}

size_t hash_value(CheckIfParameters const& p) {
  FeedbackSource::Hash feedback_hash;
  return base::hash_combine(p.reason(), feedback_hash(p.feedback()));
}

std::ostream& operator<<(std::ostream& os, CheckIfParameters const& p) {
  return os << p.reason() << ", " << p.feedback();
}

CheckIfParameters const& CheckIfParametersOf(Operator const* op) {
  CHECK(op->opcode() == IrOpcode::kCheckIf);
  return OpParameter<CheckIfParameters>(op);
}

FastApiCallParameters const& FastApiCallParametersOf(const Operator* op) {
  DCHECK_EQ(IrOpcode::kFastApiCall, op->opcode());
  return OpParameter<FastApiCallParameters>(op);
}

std::ostream& operator<<(std::ostream& os, FastApiCallParameters const& p) {
  FastApiCallFunction c_function = p.c_function();
  os << c_function.address << ":" << c_function.signature << ", ";
  return os << p.feedback() << ", " << p.descriptor();
}

size_t hash_value(FastApiCallParameters const& p) {
  FastApiCallFunction c_function = p.c_function();
  size_t hash = base::hash_combine(c_function.address, c_function.signature);
  return base::hash_combine(hash, FeedbackSource::Hash()(p.feedback()),
                            p.descriptor());
}

bool operator==(FastApiCallParameters const& lhs,
                FastApiCallParameters const& rhs) {
  return lhs.c_function() == rhs.c_function() &&
         lhs.feedback() == rhs.feedback() &&
         lhs.descriptor() == rhs.descriptor();
}

const Operator* SimplifiedOperatorBuilder::NewDoubleElements(
    AllocationType allocation) {
  return zone()->New<Operator1<AllocationType>>(  // --
      IrOpcode::kNewDoubleElements,               // opcode
      Operator::kEliminatable,                    // flags
      "NewDoubleElements",                        // name
      1, 1, 1, 1, 1, 0,                           // counts
      allocation);                                // parameter
}

const Operator* SimplifiedOperatorBuilder::NewSmiOrObjectElements(
    AllocationType allocation) {
  return zone()->New<Operator1<AllocationType>>(  // --
      IrOpcode::kNewSmiOrObjectElements,          // opcode
      Operator::kEliminatable,                    // flags
      "NewSmiOrObjectElements",                   // name
      1, 1, 1, 1, 1, 0,                           // counts
      allocation);                                // parameter
}

const Operator* SimplifiedOperatorBuilder::NewArgumentsElements(
    CreateArgumentsType type, int formal_parameter_count) {
  return zone()->New<Operator1<NewArgumentsElementsParameters>>(  // --
      IrOpcode::kNewArgumentsElements,                            // opcode
      Operator::kEliminatable,                                    // flags
      "NewArgumentsElements",                                     // name
      1, 1, 0, 1, 1, 0,                                           // counts
      NewArgumentsElementsParameters(type,
                                     formal_parameter_count));  // parameter
}

bool operator==(const NewArgumentsElementsParameters& lhs,
                const NewArgumentsElementsParameters& rhs) {
  return lhs.arguments_type() == rhs.arguments_type() &&
         lhs.formal_parameter_count() == rhs.formal_parameter_count();
}

inline size_t hash_value(const NewArgumentsElementsParameters& params) {
  return base::hash_combine(params.arguments_type(),
                            params.formal_parameter_count());
}

std::ostream& operator<<(std::ostream& os,
                         const NewArgumentsElementsParameters& params) {
  return os << params.arguments_type()
            << ", parameter_count = " << params.formal_parameter_count();
}

const NewArgumentsElementsParameters& NewArgumentsElementsParametersOf(
    const Operator* op) {
  DCHECK_EQ(IrOpcode::kNewArgumentsElements, op->opcode());
  return OpParameter<NewArgumentsElementsParameters>(op);
}

const Operator* SimplifiedOperatorBuilder::Allocate(Type type,
                                                    AllocationType allocation) {
  return zone()->New<Operator1<AllocateParameters>>(
      IrOpcode::kAllocate, Operator::kEliminatable, "Allocate", 1, 1, 1, 1, 1,
      0, AllocateParameters(type, allocation));
}

const Operator* SimplifiedOperatorBuilder::AllocateRaw(
    Type type, AllocationType allocation) {
  return zone()->New<Operator1<AllocateParameters>>(
      IrOpcode::kAllocateRaw, Operator::kEliminatable, "AllocateRaw", 1, 1, 1,
      1, 1, 1, AllocateParameters(type, allocation));
}

#define SPECULATIVE_NUMBER_BINOP(Name)                                        \
  const Operator* SimplifiedOperatorBuilder::Name(NumberOperationHint hint) { \
    switch (hint) {                                                           \
      case NumberOperationHint::kSignedSmall:                                 \
        return &cache_.k##Name##SignedSmallOperator;                          \
      case NumberOperationHint::kSignedSmallInputs:                           \
        return &cache_.k##Name##SignedSmallInputsOperator;                    \
      case NumberOperationHint::kNumber:                                      \
        return &cache_.k##Name##NumberOperator;                               \
      case NumberOperationHint::kNumberOrBoolean:                             \
        /* Not used currenly. */                                              \
        UNREACHABLE();                                                        \
      case NumberOperationHint::kNumberOrOddball:                             \
        return &cache_.k##Name##NumberOrOddballOperator;                      \
    }                                                                         \
    UNREACHABLE();                                                            \
    return nullptr;                                                           \
  }
SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(SPECULATIVE_NUMBER_BINOP)
SPECULATIVE_NUMBER_BINOP(SpeculativeNumberLessThan)
SPECULATIVE_NUMBER_BINOP(SpeculativeNumberLessThanOrEqual)
#undef SPECULATIVE_NUMBER_BINOP
const Operator* SimplifiedOperatorBuilder::SpeculativeNumberEqual(
    NumberOperationHint hint) {
  switch (hint) {
    case NumberOperationHint::kSignedSmall:
      return &cache_.kSpeculativeNumberEqualSignedSmallOperator;
    case NumberOperationHint::kSignedSmallInputs:
      return &cache_.kSpeculativeNumberEqualSignedSmallInputsOperator;
    case NumberOperationHint::kNumber:
      return &cache_.kSpeculativeNumberEqualNumberOperator;
    case NumberOperationHint::kNumberOrBoolean:
      return &cache_.kSpeculativeNumberEqualNumberOrBooleanOperator;
    case NumberOperationHint::kNumberOrOddball:
      return &cache_.kSpeculativeNumberEqualNumberOrOddballOperator;
  }
  UNREACHABLE();
}

#define ACCESS_OP_LIST(V)                                                  \
  V(LoadField, FieldAccess, Operator::kNoWrite, 1, 1, 1)                   \
  V(LoadElement, ElementAccess, Operator::kNoWrite, 2, 1, 1)               \
  V(StoreElement, ElementAccess, Operator::kNoRead, 3, 1, 0)               \
  V(LoadTypedElement, ExternalArrayType, Operator::kNoWrite, 4, 1, 1)      \
  V(StoreTypedElement, ExternalArrayType, Operator::kNoRead, 5, 1, 0)      \
  V(LoadFromObject, ObjectAccess, Operator::kNoWrite, 2, 1, 1)             \
  V(StoreToObject, ObjectAccess, Operator::kNoRead, 3, 1, 0)               \
  V(LoadImmutableFromObject, ObjectAccess, Operator::kNoWrite, 2, 1, 1)    \
  V(InitializeImmutableInObject, ObjectAccess, Operator::kNoRead, 3, 1, 0) \
  V(LoadDataViewElement, ExternalArrayType, Operator::kNoWrite, 4, 1, 1)   \
  V(StoreDataViewElement, ExternalArrayType, Operator::kNoRead, 5, 1, 0)

#define ACCESS(Name, Type, properties, value_input_count, control_input_count, \
               output_count)                                                   \
  const Operator* SimplifiedOperatorBuilder::Name(const Type& access) {        \
    return zone()->New<Operator1<Type>>(                                       \
        IrOpcode::k##Name,                                                     \
        Operator::kNoDeopt | Operator::kNoThrow | properties, #Name,           \
        value_input_count, 1, control_input_count, output_count, 1, 0,         \
        access);                                                               \
  }
ACCESS_OP_LIST(ACCESS)
#undef ACCESS

const Operator* SimplifiedOperatorBuilder::StoreField(
    const FieldAccess& access, bool maybe_initializing_or_transitioning) {
  FieldAccess store_access = access;
  store_access.maybe_initializing_or_transitioning_store =
      maybe_initializing_or_transitioning;
  return zone()->New<Operator1<FieldAccess>>(
      IrOpcode::kStoreField,
      Operator::kNoDeopt | Operator::kNoThrow | Operator::kNoRead, "StoreField",
      2, 1, 1, 0, 1, 0, store_access);
}

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
const Operator*
SimplifiedOperatorBuilder::GetContinuationPreservedEmbedderData() {
  return &cache_.kGetContinuationPreservedEmbedderData;
}

const Operator*
SimplifiedOperatorBuilder::SetContinuationPreservedEmbedderData() {
  return &cache_.kSetContinuationPreservedEmbedderData;
}
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

const Operator* SimplifiedOperatorBuilder::LoadMessage() {
  return zone()->New<Operator>(IrOpcode::kLoadMessage, Operator::kEliminatable,
                               "LoadMessage", 1, 1, 1, 1, 1, 0);
}

const Operator* SimplifiedOperatorBuilder::StoreMessage() {
  return zone()->New<Operator>(
      IrOpcode::kStoreMessage,
      Operator::kNoDeopt | Operator::kNoThrow | Operator::kNoRead,
      "StoreMessage", 2, 1, 1, 0, 1, 0);
}

const Operator* SimplifiedOperatorBuilder::LoadStackArgument() {
  return &cache_.kLoadStackArgument;
}

const Operator* SimplifiedOperatorBuilder::TransitionAndStoreElement(
    MapRef double_map, MapRef fast_map) {
  TransitionAndStoreElementParameters parameters(double_map, fast_map);
  return zone()->New<Operator1<TransitionAndStoreElementParameters>>(
      IrOpcode::kTransitionAndStoreElement,
      Operator::kNoDeopt | Operator::kNoThrow, "TransitionAndStoreElement", 3,
      1, 1, 0, 1, 0, parameters);
}

const Operator* SimplifiedOperatorBuilder::StoreSignedSmallElement() {
  return zone()->New<Operator>(IrOpcode::kStoreSignedSmallElement,
                               Operator::kNoDeopt | Operator::kNoThrow,
                               "StoreSignedSmallElement", 3, 1, 1, 0, 1, 0);
}

const Operator* SimplifiedOperatorBuilder::TransitionAndStoreNumberElement(
    MapRef double_map) {
  TransitionAndStoreNumberElementParameters parameters(double_map);
  return zone()->New<Operator1<TransitionAndStoreNumberElementParameters>>(
      IrOpcode::kTransitionAndStoreNumberElement,
      Operator::kNoDeopt | Operator::kNoThrow,
      "TransitionAndStoreNumberElement", 3, 1, 1, 0, 1, 0, parameters);
}

const Operator* SimplifiedOperatorBuilder::TransitionAndStoreNonNumberElement(
    MapRef fast_map, Type value_type) {
  TransitionAndStoreNonNumberElementParameters parameters(fast_map, value_type);
  return zone()->New<Operator1<TransitionAndStoreNonNumberElementParameters>>(
      IrOpcode::kTransitionAndStoreNonNumberElement,
      Operator::kNoDeopt | Operator::kNoThrow,
      "TransitionAndStoreNonNumberElement", 3, 1, 1, 0, 1, 0, parameters);
}

const Operator* SimplifiedOperatorBuilder::FastApiCall(
    FastApiCallFunction c_function, FeedbackSource const& feedback,
    CallDescriptor* descriptor) {
  CHECK_NOT_NULL(c_function.signature);
  const CFunctionInfo* signature = c_function.signature;
  const int c_arg_count = signature->ArgumentCount();
  // Arguments for CallApiCallbackOptimizedXXX builtin (including context)
  // plus JS arguments (including receiver).
  int slow_arg_count = static_cast<int>(descriptor->ParameterCount());

  int value_input_count =
      FastApiCallNode::ArityForArgc(c_arg_count, slow_arg_count);
  return zone()->New<Operator1<FastApiCallParameters>>(
      IrOpcode::kFastApiCall, Operator::kNoProperties, "FastApiCall",
      value_input_count, 1, 1, 1, 1, 2,
      FastApiCallParameters(c_function, feedback, descriptor));
}

// static
int FastApiCallNode::FastCallArgumentCount(Node* node) {
  FastApiCallParameters p = FastApiCallParametersOf(node->op());
  const CFunctionInfo* signature = p.c_function().signature;
  CHECK_NOT_NULL(signature);
  return signature->ArgumentCount();
}

// static
int FastApiCallNode::SlowCallArgumentCount(Node* node) {
  FastApiCallParameters p = FastApiCallParametersOf(node->op());
  CallDescriptor* descriptor = p.descriptor();
  CHECK_NOT_NULL(descriptor);
  return kSlowCodeTarget + static_cast<int>(descriptor->ParameterCount()) +
         kFrameState;
}

#undef PURE_OP_LIST
#undef EFFECT_DEPENDENT_OP_LIST
#undef SPECULATIVE_NUMBER_BINOP_LIST
#undef CHECKED_WITH_FEEDBACK_OP_LIST
#undef CHECKED_BOUNDS_OP_LIST
#undef CHECKED_OP_LIST
#undef ACCESS_OP_LIST

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```