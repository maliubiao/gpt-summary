Response:
My thinking process to arrive at the summary of the provided C++ code snippet goes through these stages:

1. **Identify the Core Function:** The code is within a `switch` statement based on `IrOpcode`. This immediately tells me the code's primary purpose is to handle different intermediate representation (IR) opcodes within the Turboshaft compiler. Each `case` likely corresponds to a specific operation within the compilation process.

2. **Recognize Common Themes:**  As I scan through the `case` statements, several recurring themes emerge:
    * **Type Checking/Assertions:**  Many cases start with `DCHECK` or involve `ObjectIs`, `CheckInternalizedString`, `CheckNumber`, etc. This points to a significant role in verifying the types of operands.
    * **Conversions:**  Numerous cases deal with converting between different data representations (e.g., `PlainPrimitiveToNumber`, `ConvertTaggedHoleToUndefined`, `ChangeInt32ToTagged`, `TruncateTaggedToWord32`). This is a crucial part of compilation as JavaScript's dynamic typing requires frequent conversions.
    * **Memory Operations:**  `Load`, `Store`, `Allocate`, and `ProtectedLoad/Store` indicate the code interacts with memory, fetching data and storing results.
    * **Control Flow:** `Branch`, `Switch`, `DeoptimizeIf/Unless`, `Return`, `TailCall` are all related to managing the execution flow of the compiled code.
    * **Function Calls:** `Call` and `TailCall` handle invoking functions.
    * **Frame Management:** `FrameState`, `StackPointerGreaterThan`, `LoadFramePointer` are involved in managing the execution stack.
    * **Selections/Conditionals:** `Select`, `Word32Select`, `Word64Select` handle conditional assignments.

3. **Group Related Cases:**  I start mentally grouping similar cases. For example, all the `OBJECT_IS_CASE` and `CHECK_OBJECT_IS_CASE` blocks are clearly related to type checks. The `CONVERT_PRIMITIVE_TO_OBJECT_CASE` and `CONVERT_OBJECT_TO_PRIMITIVE_CASE` blocks are about conversions. This helps in summarizing the functionalities more concisely.

4. **Infer High-Level Purpose:** Based on the identified themes, I can infer that this code snippet is responsible for translating high-level IR opcodes into lower-level operations that the Turboshaft compiler's backend can understand and execute. This involves ensuring type safety, performing necessary data conversions, managing memory, and controlling the flow of execution.

5. **Relate to JavaScript (Where Possible):**  I look for cases that directly correspond to JavaScript concepts. For instance:
    * Type checks (`ObjectIs`, `CheckNumber`) relate to JavaScript's dynamic type system and the need to verify types at runtime or during compilation.
    * Conversions (`StringToNumber`, `NumberToString`) are fundamental in JavaScript due to implicit type coercion.
    * `ConvertReceiver` relates to the process of converting primitive values to objects when methods are called on them (e.g., `1.toString()`).
    * `ToBoolean` corresponds to JavaScript's concept of truthiness and falsiness.

6. **Consider Potential Errors:** The presence of `DeoptimizeIf/Unless` suggests that the compiler needs to handle situations where assumptions about types or values are incorrect. This hints at potential runtime errors in JavaScript code that the compiler tries to optimize but might need to fall back from.

7. **Formulate the Summary:** I synthesize my observations into a concise summary, focusing on the core functionalities and the overarching purpose of the code. I use action verbs and clearly state what the code *does*. I also include points about potential errors and connections to JavaScript.

8. **Refine the Summary:** I review the summary for clarity and completeness, ensuring it accurately reflects the content of the code snippet without getting bogged down in excessive detail. I try to use language that is accessible even to someone who isn't deeply familiar with the V8 internals. For this part 2, I focus on summarizing the provided snippet.

By following these steps, I can effectively analyze the C++ code snippet and generate a comprehensive and informative summary of its functionalities. The key is to identify patterns, group related operations, and infer the high-level goals of the code within the larger context of a compiler.
这是目录为`v8/src/compiler/turboshaft/graph-builder.cc` 的一个 V8 源代码片段，它负责 Turboshaft 编译器的图构建阶段中，将中间表示 (IR) 节点转换为更底层的 Turboshaft 图操作。

以下是这个代码片段的功能归纳：

**核心功能：将 IR 节点转换为 Turboshaft 图操作**

这个代码片段是 `GraphBuilder::VisitNode` 函数的一部分，它根据输入的 IR 节点的 `IrOpcode` 类型，生成相应的 Turboshaft 图操作。 这部分代码主要处理与类型检查、类型转换以及部分内存操作相关的 IR 节点。

**具体功能细分：**

1. **类型检查 (Type Checks):**
   - `kObjectIsSafeInteger`: 检查对象是否为安全整数。
   - `kObjectIs...` (各种类型):  一系列 `OBJECT_IS_CASE` 宏定义的 case，用于检查对象是否为特定的类型，如 ArrayBufferView、BigInt、Callable、String 等。
   - `kCheck...` (各种类型): 一系列 `CHECK_OBJECT_IS_CASE` 宏定义的 case，用于在编译时进行类型断言，并在运行时如果类型不符合预期则触发反优化 (deoptimization)。

2. **类型转换 (Type Conversions):**
   - `kPlainPrimitiveToNumber`, `kPlainPrimitiveToWord32`, `kPlainPrimitiveToFloat64`: 将原始类型值转换为数字、32位整数或64位浮点数。
   - `kConvertTaggedHoleToUndefined`: 将特殊的 "hole" 值转换为 `undefined`。
   - `kConvertReceiver`: 用于将原始值转换为对象 (装箱)。
   - `kToBoolean`: 将值转换为布尔值。
   - `kNumberToString`, `kStringToNumber`: 数字与字符串之间的转换。
   - `kChangeTaggedToTaggedSigned`, `kCheckedTaggedToTaggedSigned`, `kCheckedTaggedToTaggedPointer`:  与有符号整数指针相关的类型转换和检查。
   - `kChange...ToTagged...`: 一系列 `CONVERT_PRIMITIVE_TO_OBJECT_CASE` 宏定义的 case，用于将原始类型的数值转换为相应的对象类型 (如 Number, BigInt, Boolean, String)。
   - `kChangeFloat64ToTagged`: 将 64 位浮点数转换为 Tagged 类型。
   - `kChecked...ToTaggedSigned`: 一系列 `CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE` 宏定义的 case，用于在转换到有符号整数时进行检查，并在必要时触发反优化。
   - `kChangeTaggedSignedToInt32`, `kChangeTaggedToInt32`, 等: 一系列 `CONVERT_OBJECT_TO_PRIMITIVE_CASE` 宏定义的 case，用于将对象类型转换为原始类型 (如 Int32, Float64)。
   - `kTruncateTaggedToWord32`, `kTruncateBigIntToWord64`, 等: 一系列 `TRUNCATE_OBJECT_TO_PRIMITIVE_CASE` 宏定义的 case，用于将对象类型截断转换为原始类型。
   - `kCheckedTruncateTaggedToWord32`:  将 Tagged 值截断为 32 位整数，并在必要时触发反优化。
   - `kCheckedUint32ToInt32`, `kCheckedFloat64ToInt32`, 等: 一系列 `CHANGE_OR_DEOPT_INT_CASE` 宏定义的 case，用于在类型转换时进行溢出检查，并在必要时触发反优化。
   - `kCheckedTaggedToInt32`, `kCheckedTaggedToFloat64`, `kCheckedTaggedToArrayIndex`, `kCheckedTaggedSignedToInt32`:  更细粒度的带检查的类型转换，可能会触发反优化。

3. **条件选择 (Conditional Selection):**
   - `kSelect`, `kWord32Select`, `kWord64Select`: 根据条件选择不同的值。

4. **内存操作 (Memory Operations):**
   - `kLoad`, `kLoadImmutable`, `kUnalignedLoad`: 从内存中加载数据。
   - `kProtectedLoad`:  受保护的内存加载。
   - `kStore`, `kUnalignedStore`: 将数据存储到内存中。
   - `kProtectedStore`: 受保护的内存存储。

**关于文件类型和 JavaScript 关系：**

- `v8/src/compiler/turboshaft/graph-builder.cc` **不是**以 `.tq` 结尾，因此它是一个 **C++** 源代码文件，而不是 Torque 源代码。 Torque 文件通常用于定义 V8 内部的运行时函数和类型。
- 这个代码片段的功能与 **JavaScript 的类型系统和类型转换**密切相关。 JavaScript 是一门动态类型语言，因此在编译和执行过程中需要进行大量的类型检查和转换。 Turboshaft 编译器需要理解 JavaScript 的类型规则，并生成相应的低级操作来实现这些规则。

**JavaScript 举例说明 (与类型检查和转换相关):**

```javascript
function example(input) {
  if (typeof input === 'number') { // 对应 kObjectIsNumber 等
    console.log("Input is a number:", input);
    let integerPart = input | 0; // 对应 kTruncateTaggedToWord32 等
    console.log("Integer part:", integerPart);
  } else if (typeof input === 'string') { // 对应 kObjectIsString 等
    console.log("Input is a string:", input);
    let num = Number(input); // 对应 kStringToNumber
    if (!isNaN(num)) {
      console.log("String converted to number:", num);
    }
  } else if (Array.isArray(input)) { // 虽然这里没有直接对应的 Opcode，但可以说明类型检查的重要性
    console.log("Input is an array:", input);
  }
  return input + 10; // 可能会涉及到类型转换，比如 input 是字符串的情况
}

example(5);
example("15");
example([1, 2, 3]);
example("hello");
```

在上面的 JavaScript 代码中，`typeof input === 'number'` 和 `typeof input === 'string'` 就类似于 `kObjectIsNumber` 和 `kObjectIsString` 的检查。 `Number(input)` 类似于 `kStringToNumber` 的转换。  `input | 0` 涉及到将数值转换为整数，可能对应 `kTruncateTaggedToWord32` 这样的操作。

**代码逻辑推理 (假设输入与输出):**

假设 IR 节点表示一个检查变量 `x` 是否为数字的操作：

**假设输入 (IR Node):**
```
IrOpcode::kObjectIsNumber, 输入 0 指向代表变量 x 的 Turboshaft 图节点
```

**预期输出 (Turboshaft 图操作):**
```
__ ObjectIs(Map(node->InputAt(0)), ObjectIsOp::Kind::kNumber, ObjectIsOp::InputAssumptions::kNone);
```
这将生成一个 Turboshaft 操作，该操作会检查 `x` 的 Map (对象的元信息) 是否对应于 Number 类型。

假设 IR 节点表示将一个 Tagged 值转换为 32 位整数的操作：

**假设输入 (IR Node):**
```
IrOpcode::kTruncateTaggedToWord32, 输入 0 指向代表 Tagged 值的 Turboshaft 图节点
```

**预期输出 (Turboshaft 图操作):**
```
__ TruncateJSPrimitiveToUntagged(
    Map(node->InputAt(0)),
    TruncateJSPrimitiveToUntaggedOp::UntaggedKind::kInt32,
    TruncateJSPrimitiveToUntaggedOp::InputAssumptions::NumberOrOddball);
```
这将生成一个 Turboshaft 操作，尝试将输入的 Tagged 值截断为 32 位整数。这里假设输入是 Number 或 Oddball 类型。

**用户常见的编程错误 (与这里涉及的 Opcode 相关):**

1. **类型错误导致的运行时异常:**
   ```javascript
   function add(a, b) {
     return a + b;
   }
   add(5, "hello"); // JavaScript 会尝试将 "hello" 转换为数字，可能得到 NaN
   ```
   在 Turboshaft 编译 `add` 函数时，如果做了类型假设 (例如，假设 `a` 和 `b` 都是数字)，但运行时类型不符，就会触发类似 `kDeoptimizeIf` 的操作进行反优化。

2. **不正确的类型转换:**
   ```javascript
   let str = "3.14";
   let num = parseInt(str); // 程序员可能期望得到浮点数，但 parseInt 只取整数部分
   ```
   Turboshaft 在处理 `parseInt` 时，会生成相应的转换操作 (可能涉及到 `kStringToNumber` 和截断操作)，如果程序员对转换结果的预期不正确，就会导致逻辑错误。

3. **假设对象是特定类型但实际不是:**
   ```javascript
   function processString(input) {
     if (typeof input === 'string') {
       console.log(input.toUpperCase());
     }
   }
   processString(123); // 运行时会因为 123 没有 toUpperCase 方法而报错
   ```
   Turboshaft 可能会尝试优化 `processString`，基于 `typeof input === 'string'` 的判断生成特定的代码。如果类型判断有误或者后续代码的假设不成立，就会导致问题。

**第 2 部分功能归纳:**

这部分 `graph-builder.cc` 代码主要负责将与 **类型检查、类型转换和部分内存访问** 相关的 IR 节点转换为 Turboshaft 图中的具体操作。它确保了在编译过程中，能够正确地处理 JavaScript 的动态类型，并在必要时插入运行时类型检查和转换，或者在类型假设不成立时触发反优化。 这部分是 Turboshaft 编译器理解和执行 JavaScript 代码语义的关键组成部分。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
rOpcode::kObjectIsSafeInteger:
      return __ ObjectIsNumericValue(Map(node->InputAt(0)),
                                     NumericKind::kSafeInteger,
                                     FloatRepresentation::Float64());

#define OBJECT_IS_CASE(kind)                                             \
  case IrOpcode::kObjectIs##kind: {                                      \
    return __ ObjectIs(Map(node->InputAt(0)), ObjectIsOp::Kind::k##kind, \
                       ObjectIsOp::InputAssumptions::kNone);             \
  }
      OBJECT_IS_CASE(ArrayBufferView)
      OBJECT_IS_CASE(BigInt)
      OBJECT_IS_CASE(Callable)
      OBJECT_IS_CASE(Constructor)
      OBJECT_IS_CASE(DetectableCallable)
      OBJECT_IS_CASE(NonCallable)
      OBJECT_IS_CASE(Number)
      OBJECT_IS_CASE(Receiver)
      OBJECT_IS_CASE(Smi)
      OBJECT_IS_CASE(String)
      OBJECT_IS_CASE(Symbol)
      OBJECT_IS_CASE(Undetectable)
#undef OBJECT_IS_CASE

#define CHECK_OBJECT_IS_CASE(code, kind, input_assumptions, reason, feedback) \
  case IrOpcode::k##code: {                                                   \
    DCHECK(dominating_frame_state.valid());                                   \
    V<Object> input = Map(node->InputAt(0));                                  \
    V<Word32> check =                                                         \
        __ ObjectIs(input, ObjectIsOp::Kind::k##kind,                         \
                    ObjectIsOp::InputAssumptions::k##input_assumptions);      \
    __ DeoptimizeIfNot(check, dominating_frame_state,                         \
                       DeoptimizeReason::k##reason, feedback);                \
    return input;                                                             \
  }
      CHECK_OBJECT_IS_CASE(CheckInternalizedString, InternalizedString,
                           HeapObject, WrongInstanceType, {})
      CHECK_OBJECT_IS_CASE(CheckNumber, Number, None, NotANumber,
                           CheckParametersOf(op).feedback())
      CHECK_OBJECT_IS_CASE(CheckReceiver, Receiver, HeapObject,
                           NotAJavaScriptObject, {})
      CHECK_OBJECT_IS_CASE(CheckReceiverOrNullOrUndefined,
                           ReceiverOrNullOrUndefined, HeapObject,
                           NotAJavaScriptObjectOrNullOrUndefined, {})
      CHECK_OBJECT_IS_CASE(CheckString, String, HeapObject, NotAString,
                           CheckParametersOf(op).feedback())
      CHECK_OBJECT_IS_CASE(CheckStringOrStringWrapper, StringOrStringWrapper,
                           HeapObject, NotAStringOrStringWrapper,
                           CheckParametersOf(op).feedback())
      CHECK_OBJECT_IS_CASE(CheckSymbol, Symbol, HeapObject, NotASymbol, {})
      CHECK_OBJECT_IS_CASE(CheckBigInt, BigInt, None, NotABigInt,
                           CheckParametersOf(op).feedback())
      CHECK_OBJECT_IS_CASE(CheckedBigIntToBigInt64, BigInt64, BigInt,
                           NotABigInt64, CheckParametersOf(op).feedback())
#undef CHECK_OBJECT_IS_CASE

    case IrOpcode::kPlainPrimitiveToNumber:
      return __ ConvertPlainPrimitiveToNumber(Map(node->InputAt(0)));
    case IrOpcode::kPlainPrimitiveToWord32:
      return __ ConvertJSPrimitiveToUntagged(
          Map(node->InputAt(0)),
          ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kInt32,
          ConvertJSPrimitiveToUntaggedOp::InputAssumptions::kPlainPrimitive);
    case IrOpcode::kPlainPrimitiveToFloat64:
      return __ ConvertJSPrimitiveToUntagged(
          Map(node->InputAt(0)),
          ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kFloat64,
          ConvertJSPrimitiveToUntaggedOp::InputAssumptions::kPlainPrimitive);

    case IrOpcode::kConvertTaggedHoleToUndefined: {
      V<Object> input = Map(node->InputAt(0));
      V<Word32> is_the_hole = __ TaggedEqual(
          input, __ HeapConstant(isolate->factory()->the_hole_value()));
      return __ Conditional(
          is_the_hole, __ HeapConstant(isolate->factory()->undefined_value()),
          input, BranchHint::kFalse);
    }

    case IrOpcode::kConvertReceiver:
      return __ ConvertJSPrimitiveToObject(
          Map(node->InputAt(0)), Map(node->InputAt(1)), Map(node->InputAt(2)),
          ConvertReceiverModeOf(node->op()));

    case IrOpcode::kToBoolean:
      return __ ConvertToBoolean(Map(node->InputAt(0)));
    case IrOpcode::kNumberToString:
      return __ ConvertNumberToString(Map(node->InputAt(0)));
    case IrOpcode::kStringToNumber:
      return __ ConvertStringToNumber(Map(node->InputAt(0)));
    case IrOpcode::kChangeTaggedToTaggedSigned:
      return __ Convert(Map(node->InputAt(0)),
                        ConvertOp::Kind::kNumberOrOddball,
                        ConvertOp::Kind::kSmi);

    case IrOpcode::kCheckedTaggedToTaggedSigned: {
      DCHECK(dominating_frame_state.valid());
      V<Object> input = Map(node->InputAt(0));
      __ DeoptimizeIfNot(__ ObjectIsSmi(input), dominating_frame_state,
                         DeoptimizeReason::kNotASmi,
                         CheckParametersOf(node->op()).feedback());
      return input;
    }

    case IrOpcode::kCheckedTaggedToTaggedPointer: {
      DCHECK(dominating_frame_state.valid());
      V<Object> input = Map(node->InputAt(0));
      __ DeoptimizeIf(__ ObjectIsSmi(input), dominating_frame_state,
                      DeoptimizeReason::kSmi,
                      CheckParametersOf(node->op()).feedback());
      return input;
    }

#define CONVERT_PRIMITIVE_TO_OBJECT_CASE(name, kind, input_type,  \
                                         input_interpretation)    \
  case IrOpcode::k##name:                                         \
    return __ ConvertUntaggedToJSPrimitive(                       \
        Map(node->InputAt(0)),                                    \
        ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::k##kind, \
        V<input_type>::rep,                                       \
        ConvertUntaggedToJSPrimitiveOp::InputInterpretation::     \
            k##input_interpretation,                              \
        CheckForMinusZeroMode::kDontCheckForMinusZero);
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeInt32ToTagged, Number, Word32,
                                       Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeUint32ToTagged, Number, Word32,
                                       Unsigned)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeInt64ToTagged, Number, Word64,
                                       Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeUint64ToTagged, Number, Word64,
                                       Unsigned)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeFloat64ToTaggedPointer, HeapNumber,
                                       Float64, Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeInt64ToBigInt, BigInt, Word64,
                                       Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeUint64ToBigInt, BigInt, Word64,
                                       Unsigned)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeInt31ToTaggedSigned, Smi, Word32,
                                       Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeBitToTagged, Boolean, Word32,
                                       Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(StringFromSingleCharCode, String, Word32,
                                       CharCode)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(StringFromSingleCodePoint, String,
                                       Word32, CodePoint)
      CONVERT_PRIMITIVE_TO_OBJECT_CASE(ChangeFloat64HoleToTagged,
                                       HeapNumberOrUndefined, Float64, Signed)

    case IrOpcode::kChangeFloat64ToTagged:
      return __ ConvertUntaggedToJSPrimitive(
          Map(node->InputAt(0)),
          ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kNumber,
          RegisterRepresentation::Float64(),
          ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned,
          CheckMinusZeroModeOf(node->op()));
#undef CONVERT_PRIMITIVE_TO_OBJECT_CASE

#define CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE(name, kind, input_type, \
                                                  input_interpretation)   \
  case IrOpcode::k##name: {                                               \
    DCHECK(dominating_frame_state.valid());                               \
    const CheckParameters& params = CheckParametersOf(node->op());        \
    return __ ConvertUntaggedToJSPrimitiveOrDeopt(                        \
        Map(node->InputAt(0)), dominating_frame_state,                    \
        ConvertUntaggedToJSPrimitiveOrDeoptOp::JSPrimitiveKind::k##kind,  \
        V<input_type>::rep,                                               \
        ConvertUntaggedToJSPrimitiveOrDeoptOp::InputInterpretation::      \
            k##input_interpretation,                                      \
        params.feedback());                                               \
  }
      CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE(CheckedInt32ToTaggedSigned, Smi,
                                                Word32, Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE(CheckedUint32ToTaggedSigned,
                                                Smi, Word32, Unsigned)
      CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE(CheckedInt64ToTaggedSigned, Smi,
                                                Word64, Signed)
      CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE(CheckedUint64ToTaggedSigned,
                                                Smi, Word64, Unsigned)
#undef CONVERT_PRIMITIVE_TO_OBJECT_OR_DEOPT_CASE

#define CONVERT_OBJECT_TO_PRIMITIVE_CASE(name, kind, input_assumptions) \
  case IrOpcode::k##name:                                               \
    return __ ConvertJSPrimitiveToUntagged(                             \
        Map(node->InputAt(0)),                                          \
        ConvertJSPrimitiveToUntaggedOp::UntaggedKind::k##kind,          \
        ConvertJSPrimitiveToUntaggedOp::InputAssumptions::              \
            k##input_assumptions);
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedSignedToInt32, Int32, Smi)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedSignedToInt64, Int64, Smi)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedToBit, Bit, Boolean)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedToInt32, Int32,
                                       NumberOrOddball)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedToUint32, Uint32,
                                       NumberOrOddball)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedToInt64, Int64,
                                       NumberOrOddball)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(ChangeTaggedToFloat64, Float64,
                                       NumberOrOddball)
      CONVERT_OBJECT_TO_PRIMITIVE_CASE(TruncateTaggedToFloat64, Float64,
                                       NumberOrOddball)
#undef CONVERT_OBJECT_TO_PRIMITIVE_CASE

#define TRUNCATE_OBJECT_TO_PRIMITIVE_CASE(name, kind, input_assumptions) \
  case IrOpcode::k##name:                                                \
    return __ TruncateJSPrimitiveToUntagged(                             \
        Map(node->InputAt(0)),                                           \
        TruncateJSPrimitiveToUntaggedOp::UntaggedKind::k##kind,          \
        TruncateJSPrimitiveToUntaggedOp::InputAssumptions::              \
            k##input_assumptions);
      TRUNCATE_OBJECT_TO_PRIMITIVE_CASE(TruncateTaggedToWord32, Int32,
                                        NumberOrOddball)
      TRUNCATE_OBJECT_TO_PRIMITIVE_CASE(TruncateBigIntToWord64, Int64, BigInt)
      TRUNCATE_OBJECT_TO_PRIMITIVE_CASE(TruncateTaggedToBit, Bit, Object)
      TRUNCATE_OBJECT_TO_PRIMITIVE_CASE(TruncateTaggedPointerToBit, Bit,
                                        HeapObject)
#undef TRUNCATE_OBJECT_TO_PRIMITIVE_CASE

    case IrOpcode::kCheckedTruncateTaggedToWord32:
      DCHECK(dominating_frame_state.valid());
      using IR = TruncateJSPrimitiveToUntaggedOrDeoptOp::InputRequirement;
      IR input_requirement;
      switch (CheckTaggedInputParametersOf(node->op()).mode()) {
        case CheckTaggedInputMode::kNumber:
          input_requirement = IR::kNumber;
          break;
        case CheckTaggedInputMode::kNumberOrBoolean:
          input_requirement = IR::kNumberOrBoolean;
          break;
        case CheckTaggedInputMode::kNumberOrOddball:
          input_requirement = IR::kNumberOrOddball;
          break;
      }
      return __ TruncateJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state,
          TruncateJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32,
          input_requirement,
          CheckTaggedInputParametersOf(node->op()).feedback());

#define CHANGE_OR_DEOPT_INT_CASE(kind)                                     \
  case IrOpcode::kChecked##kind: {                                         \
    DCHECK(dominating_frame_state.valid());                                \
    const CheckParameters& params = CheckParametersOf(node->op());         \
    return __ ChangeOrDeopt(Map(node->InputAt(0)), dominating_frame_state, \
                            ChangeOrDeoptOp::Kind::k##kind,                \
                            CheckForMinusZeroMode::kDontCheckForMinusZero, \
                            params.feedback());                            \
  }
      CHANGE_OR_DEOPT_INT_CASE(Uint32ToInt32)
      CHANGE_OR_DEOPT_INT_CASE(Int64ToInt32)
      CHANGE_OR_DEOPT_INT_CASE(Uint64ToInt32)
      CHANGE_OR_DEOPT_INT_CASE(Uint64ToInt64)
#undef CHANGE_OR_DEOPT_INT_CASE

    case IrOpcode::kCheckedFloat64ToInt32: {
      DCHECK(dominating_frame_state.valid());
      const CheckMinusZeroParameters& params =
          CheckMinusZeroParametersOf(node->op());
      return __ ChangeOrDeopt(Map(node->InputAt(0)), dominating_frame_state,
                              ChangeOrDeoptOp::Kind::kFloat64ToInt32,
                              params.mode(), params.feedback());
    }

    case IrOpcode::kCheckedFloat64ToInt64: {
      DCHECK(dominating_frame_state.valid());
      const CheckMinusZeroParameters& params =
          CheckMinusZeroParametersOf(node->op());
      return __ ChangeOrDeopt(Map(node->InputAt(0)), dominating_frame_state,
                              ChangeOrDeoptOp::Kind::kFloat64ToInt64,
                              params.mode(), params.feedback());
    }

    case IrOpcode::kCheckedTaggedToInt32: {
      DCHECK(dominating_frame_state.valid());
      const CheckMinusZeroParameters& params =
          CheckMinusZeroParametersOf(node->op());
      return __ ConvertJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kNumber,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32,
          params.mode(), params.feedback());
    }

    case IrOpcode::kCheckedTaggedToInt64: {
      DCHECK(dominating_frame_state.valid());
      const CheckMinusZeroParameters& params =
          CheckMinusZeroParametersOf(node->op());
      return __ ConvertJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kNumber,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt64,
          params.mode(), params.feedback());
    }

    case IrOpcode::kCheckedTaggedToFloat64: {
      DCHECK(dominating_frame_state.valid());
      const CheckTaggedInputParameters& params =
          CheckTaggedInputParametersOf(node->op());
      ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind from_kind;
      switch (params.mode()) {
#define CASE(mode)                                                       \
  case CheckTaggedInputMode::k##mode:                                    \
    from_kind =                                                          \
        ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::k##mode; \
    break;
        CASE(Number)
        CASE(NumberOrBoolean)
        CASE(NumberOrOddball)
#undef CASE
      }
      return __ ConvertJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state, from_kind,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kFloat64,
          CheckForMinusZeroMode::kDontCheckForMinusZero, params.feedback());
    }

    case IrOpcode::kCheckedTaggedToArrayIndex: {
      DCHECK(dominating_frame_state.valid());
      const CheckParameters& params = CheckParametersOf(node->op());
      return __ ConvertJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::
              kNumberOrString,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kArrayIndex,
          CheckForMinusZeroMode::kCheckForMinusZero, params.feedback());
    }

    case IrOpcode::kCheckedTaggedSignedToInt32: {
      DCHECK(dominating_frame_state.valid());
      const CheckParameters& params = CheckParametersOf(node->op());
      return __ ConvertJSPrimitiveToUntaggedOrDeopt(
          Map(node->InputAt(0)), dominating_frame_state,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kSmi,
          ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32,
          CheckForMinusZeroMode::kDontCheckForMinusZero, params.feedback());
    }

    case IrOpcode::kSelect: {
      V<Word32> cond = Map(node->InputAt(0));
      V<Any> vtrue = Map(node->InputAt(1));
      V<Any> vfalse = Map(node->InputAt(2));
      const SelectParameters& params = SelectParametersOf(op);
      return __ Select(cond, vtrue, vfalse,
                       RegisterRepresentation::FromMachineRepresentation(
                           params.representation()),
                       params.hint(), SelectOp::Implementation::kBranch);
    }
    case IrOpcode::kWord32Select:
      return __ Select(
          Map<Word32>(node->InputAt(0)), Map<Word32>(node->InputAt(1)),
          Map<Word32>(node->InputAt(2)), RegisterRepresentation::Word32(),
          BranchHint::kNone, SelectOp::Implementation::kCMove);
    case IrOpcode::kWord64Select:
      return __ Select(
          Map<Word32>(node->InputAt(0)), Map<Word64>(node->InputAt(1)),
          Map<Word64>(node->InputAt(2)), RegisterRepresentation::Word64(),
          BranchHint::kNone, SelectOp::Implementation::kCMove);

    case IrOpcode::kLoad:
    case IrOpcode::kLoadImmutable:
    case IrOpcode::kUnalignedLoad: {
      MemoryRepresentation loaded_rep =
          MemoryRepresentation::FromMachineType(LoadRepresentationOf(op));
      Node* base = node->InputAt(0);
      Node* index = node->InputAt(1);
      // It's ok to merge LoadImmutable into Load after scheduling.
      LoadOp::Kind kind = opcode == IrOpcode::kUnalignedLoad
                              ? LoadOp::Kind::RawUnaligned()
                              : LoadOp::Kind::RawAligned();
      if (__ output_graph().Get(Map(base)).outputs_rep().at(0) ==
          RegisterRepresentation::Tagged()) {
        kind = LoadOp::Kind::TaggedBase();
      }
      if (index->opcode() == IrOpcode::kInt32Constant) {
        int32_t offset = OpParameter<int32_t>(index->op());
        if (kind.tagged_base) offset += kHeapObjectTag;
        return __ Load(Map(base), kind, loaded_rep, offset);
      }
      if (index->opcode() == IrOpcode::kInt64Constant) {
        int64_t offset = OpParameter<int64_t>(index->op());
        if (kind.tagged_base) offset += kHeapObjectTag;
        if (base::IsValueInRangeForNumericType<int32_t>(offset)) {
          return __ Load(Map(base), kind, loaded_rep,
                         static_cast<int32_t>(offset));
        }
      }
      int32_t offset = kind.tagged_base ? kHeapObjectTag : 0;
      uint8_t element_size_log2 = 0;
      return __ Load(Map(base), Map(index), kind, loaded_rep, offset,
                     element_size_log2);
    }
    case IrOpcode::kProtectedLoad: {
      MemoryRepresentation loaded_rep =
          MemoryRepresentation::FromMachineType(LoadRepresentationOf(op));
      return __ Load(Map(node->InputAt(0)), Map(node->InputAt(1)),
                     LoadOp::Kind::Protected(), loaded_rep);
    }

    case IrOpcode::kStore:
    case IrOpcode::kUnalignedStore: {
      OpIndex base = Map(node->InputAt(0));
      if (pipeline_kind == TurboshaftPipelineKind::kCSA) {
        // TODO(nicohartmann@): This is currently required to properly compile
        // builtins. We should fix them and remove this.
        if (__ output_graph().Get(base).outputs_rep()[0] ==
            RegisterRepresentation::Tagged()) {
          base = __ BitcastTaggedToWordPtr(base);
        }
      }
      bool aligned = opcode != IrOpcode::kUnalignedStore;
      StoreRepresentation store_rep =
          aligned ? StoreRepresentationOf(op)
                  : StoreRepresentation(UnalignedStoreRepresentationOf(op),
                                        WriteBarrierKind::kNoWriteBarrier);
      StoreOp::Kind kind = opcode == IrOpcode::kStore
                               ? StoreOp::Kind::RawAligned()
                               : StoreOp::Kind::RawUnaligned();
      bool initializing_transitioning = inside_region;

      Node* index = node->InputAt(1);
      Node* value = node->InputAt(2);
      if (index->opcode() == IrOpcode::kInt32Constant) {
        int32_t offset = OpParameter<int32_t>(index->op());
        __ Store(base, Map(value), kind,
                 MemoryRepresentation::FromMachineRepresentation(
                     store_rep.representation()),
                 store_rep.write_barrier_kind(), offset,
                 initializing_transitioning);
        return OpIndex::Invalid();
      }
      if (index->opcode() == IrOpcode::kInt64Constant) {
        int64_t offset = OpParameter<int64_t>(index->op());
        if (base::IsValueInRangeForNumericType<int32_t>(offset)) {
          __ Store(base, Map(value), kind,
                   MemoryRepresentation::FromMachineRepresentation(
                       store_rep.representation()),
                   store_rep.write_barrier_kind(), static_cast<int32_t>(offset),
                   initializing_transitioning);
          return OpIndex::Invalid();
        }
      }
      int32_t offset = 0;
      uint8_t element_size_log2 = 0;
      __ Store(base, Map(index), Map(value), kind,
               MemoryRepresentation::FromMachineRepresentation(
                   store_rep.representation()),
               store_rep.write_barrier_kind(), offset, element_size_log2,
               initializing_transitioning);
      return OpIndex::Invalid();
    }
    case IrOpcode::kProtectedStore:
      // We don't mark ProtectedStores as initialzing even when inside regions,
      // since we don't store-store eliminate them because they have a raw base.
      __ Store(Map(node->InputAt(0)), Map(node->InputAt(1)),
               Map(node->InputAt(2)), StoreOp::Kind::Protected(),
               MemoryRepresentation::FromMachineRepresentation(
                   OpParameter<MachineRepresentation>(node->op())),
               WriteBarrierKind::kNoWriteBarrier);
      return OpIndex::Invalid();

    case IrOpcode::kRetain:
      __ Retain(Map(node->InputAt(0)));
      return OpIndex::Invalid();
    case IrOpcode::kStackPointerGreaterThan:
      return __ StackPointerGreaterThan(Map<WordPtr>(node->InputAt(0)),
                                        StackCheckKindOf(op));
    case IrOpcode::kLoadStackCheckOffset:
      return __ StackCheckOffset();
    case IrOpcode::kLoadFramePointer:
      return __ FramePointer();
    case IrOpcode::kLoadParentFramePointer:
      return __ ParentFramePointer();

    case IrOpcode::kStackSlot: {
      StackSlotRepresentation rep = StackSlotRepresentationOf(op);
      return __ StackSlot(rep.size(), rep.alignment(), rep.is_tagged());
    }
    case IrOpcode::kBranch:
      DCHECK_EQ(block->SuccessorCount(), 2);
      __ Branch(Map(node->InputAt(0)), Map(block->SuccessorAt(0)),
                Map(block->SuccessorAt(1)), BranchHintOf(node->op()));
      return OpIndex::Invalid();

    case IrOpcode::kSwitch: {
      BasicBlock* default_branch = block->successors().back();
      DCHECK_EQ(IrOpcode::kIfDefault, default_branch->front()->opcode());
      size_t case_count = block->SuccessorCount() - 1;
      base::SmallVector<SwitchOp::Case, 16> cases;
      for (size_t i = 0; i < case_count; ++i) {
        BasicBlock* branch = block->SuccessorAt(i);
        const IfValueParameters& p = IfValueParametersOf(branch->front()->op());
        cases.emplace_back(p.value(), Map(branch), p.hint());
      }
      __ Switch(
          Map(node->InputAt(0)), graph_zone->CloneVector(base::VectorOf(cases)),
          Map(default_branch), BranchHintOf(default_branch->front()->op()));
      return OpIndex::Invalid();
    }

    case IrOpcode::kCall: {
      auto call_descriptor = CallDescriptorOf(op);
      const JSWasmCallParameters* wasm_call_parameters = nullptr;
#if V8_ENABLE_WEBASSEMBLY
      if (call_descriptor->kind() == CallDescriptor::kCallWasmFunction &&
          v8_flags.turboshaft_wasm_in_js_inlining) {
        // A JS-to-Wasm call where the wrapper got inlined in TurboFan but the
        // actual Wasm body inlining was either not possible or is going to
        // happen later in Turboshaft. See https://crbug.com/353475584.
        // Make sure that for each not-yet-body-inlined call node, there is an
        // entry in the sidetable.
        DCHECK_NOT_NULL(js_wasm_calls_sidetable);
        auto it = js_wasm_calls_sidetable->find(node->id());
        CHECK_NE(it, js_wasm_calls_sidetable->end());
        wasm_call_parameters = it->second;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      CanThrow can_throw =
          op->HasProperty(Operator::kNoThrow) ? CanThrow::kNo : CanThrow::kYes;
      const TSCallDescriptor* ts_descriptor = TSCallDescriptor::Create(
          call_descriptor, can_throw, LazyDeoptOnThrow::kNo, graph_zone,
          wasm_call_parameters);

      base::SmallVector<OpIndex, 16> arguments;
      // The input `0` is the callee, the following value inputs are the
      // arguments. `CallDescriptor::InputCount()` counts the callee and
      // arguments, but excludes a possible `FrameState` input.
      OpIndex callee = Map(node->InputAt(0));
      for (int i = 1; i < static_cast<int>(call_descriptor->InputCount());
           ++i) {
        arguments.emplace_back(Map(node->InputAt(i)));
      }

      OpIndex frame_state_idx = OpIndex::Invalid();
      if (call_descriptor->NeedsFrameState()) {
        compiler::FrameState frame_state{
            node->InputAt(static_cast<int>(call_descriptor->InputCount()))};
        frame_state_idx = Map(frame_state);
      }
      std::optional<decltype(assembler)::CatchScope> catch_scope;
      if (is_final_control) {
        Block* catch_block = Map(block->SuccessorAt(1));
        catch_scope.emplace(assembler, catch_block);
      }
      OpEffects effects =
          OpEffects().CanDependOnChecks().CanChangeControlFlow().CanDeopt();
      if ((call_descriptor->flags() & CallDescriptor::kNoAllocate) == 0) {
        effects = effects.CanAllocate();
      }
      if (!op->HasProperty(Operator::kNoWrite)) {
        effects = effects.CanWriteMemory();
      }
      if (!op->HasProperty(Operator::kNoRead)) {
        effects = effects.CanReadMemory();
      }
      OpIndex result =
          __ Call(callee, frame_state_idx, base::VectorOf(arguments),
                  ts_descriptor, effects);
      if (is_final_control) {
        // The `__ Call()` before has already created exceptional control flow
        // and bound a new block for the success case. So we can just `Goto` the
        // block that Turbofan designated as the `IfSuccess` successor.
        __ Goto(Map(block->SuccessorAt(0)));
      }
      return result;
    }

    case IrOpcode::kTailCall: {
      auto call_descriptor = CallDescriptorOf(op);
      base::SmallVector<OpIndex, 16> arguments;
      // The input `0` is the callee, the following value inputs are the
      // arguments. `CallDescriptor::InputCount()` counts the callee and
      // arguments.
      OpIndex callee = Map(node->InputAt(0));
      for (int i = 1; i < static_cast<int>(call_descriptor->InputCount());
           ++i) {
        arguments.emplace_back(Map(node->InputAt(i)));
      }

      CanThrow can_throw =
          op->HasProperty(Operator::kNoThrow) ? CanThrow::kNo : CanThrow::kYes;
      const TSCallDescriptor* ts_descriptor = TSCallDescriptor::Create(
          call_descriptor, can_throw, LazyDeoptOnThrow::kNo, graph_zone);

      __ TailCall(callee, base::VectorOf(arguments), ts_descriptor);
      return OpIndex::Invalid();
    }

    case IrOpcode::kFrameState: {
      compiler::FrameState frame_state{node};
      FrameStateData::Builder builder;
      BuildFrameStateData(&builder, frame_state);
      if (builder.Inputs().size() >
          std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
        *bailout = BailoutReason::kTooManyArguments;
        return OpIndex::Invalid();
      }
      return __ FrameState(builder.Inputs(), builder.inlined(),
                           builder.AllocateFrameStateData(
                               frame_state.frame_state_info(), graph_zone));
    }

    case IrOpcode::kDeoptimizeIf:
      __ DeoptimizeIf(Map(node->InputAt(0)), Map(node->InputAt(1)),
                      &DeoptimizeParametersOf(op));
      return OpIndex::Invalid();
    case IrOpcode::kDeoptimizeUnless:
      __ DeoptimizeIfNot(Map(node->InputAt(0)), Map(node->InputAt(1)),
                         &DeoptimizeParametersOf(op));
      return OpIndex::Invalid();

#if V8_ENABLE_WEBASSEMBLY
    case IrOpcode::kTrapIf:
      // For wasm the dominating_frame_state is invalid and will not be used.
      // For traps inlined into JS the dominating_frame_state is valid and is
      // needed for the trap.
      __ TrapIf(Map(node->InputAt(0)), dominating_frame_state, TrapIdOf(op));
      return OpIndex::Invalid();

    case IrOpcode::kTrapUnless:
      // For wasm the dominating_frame_state is invalid and will not be used.
      // For traps inlined into JS the dominating_frame_state is valid and is
      // needed for the trap.
      __ TrapIfNot(Map(node->InputAt(0)), dominating_frame_state, TrapIdOf(op));
      return OpIndex::Invalid();
#endif  // V8_ENABLE_WEBASSEMBLY

    case IrOpcode::kDeoptimize: {
      V<FrameState> frame_state = Map(node->InputAt(0));
      __ Deoptimize(frame_state, &DeoptimizeParametersOf(op));
      return OpIndex::Invalid();
    }

    case IrOpcode::kReturn: {
      Node* pop_count = node->InputAt(0);
      base::SmallVector<OpIndex, 4> return_values;
      for (int i = 1; i < node->op()->ValueInputCount(); ++i) {
        return_values.push_back(Map(node->InputAt(i)));
      }
      __ Return(Map(pop_count), base::VectorOf(return_values));
      return OpIndex::Invalid();
    }
    case IrOpcode::kUnreachable:
    case IrOpcode::kThrow:
      __ Unreachable();
      return OpIndex::Invalid();

    case IrOpcode::kDeadValue:
      // Typically, DeadValue nodes have Unreachable as their input. In this
      // case, we would not get here because Unreachable already terminated the
      // block and we stopped generating additional operations.
      DCHECK_NE(node->InputAt(0)->opcode(), IrOpcode::kUnreachable);
      // If we find a DeadValue without an Unreachable input, we just generate
      // one here and stop.
      __ Unreachable();
      return OpIndex::Invalid();

    case IrOpcode::kProjection: {
      Node* input = node->InputAt(0);
      size_t index = ProjectionIndexOf(op);
      RegisterRepresentation rep =
          RegisterRepresentation::FromMachineRepresentation(
              NodeProperties::GetProjectionType(node));
      return __ Projection(Map(input), index, rep);
    }

    case IrOpcode::kStaticAssert:
      __ StaticAssert(Map(node->InputAt(0)), StaticAssertSourceOf(node->op()));
      return OpIndex::Invalid();

    case IrOpcode::kAllocate: {
      AllocationType allocation = AllocationTypeOf(node->op());
      return __ FinishInitialization(
          __ Allocate(Map(node->InputAt(0)), allocation));
    }
    // TODO(nicohartmann@): We might not see AllocateRaw here anymore.
    case IrOpcode::kAllocateRaw: {
      Node* size = node->InputAt(0);
      const AllocateParameters& params = AllocateParametersOf(node->op());
      return __ FinishInitialization(
          __ Allocate(Map(size), params.allocation_type()));
    }
    case IrOpcode::kStoreToObject: {
      Node* object = node->InputAt(0);
      Node* offset =
```