Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/simplified-operator.cc`.

Here's a breakdown of the thought process to address the request:

1. **Identify the core purpose:** The code defines various operator creation methods within the `SimplifiedOperatorBuilder` class. These operators are used in V8's intermediate representation (IR) for representing simplified operations.

2. **Analyze individual operator groups:**
    * **Wasm Operators:** The code block starting with `#ifdef V8_ENABLE_WEBASSEMBLY` clearly deals with WebAssembly specific operators. These include casting, RTTI operations (`RttCanon`), null checks, struct/array access, and conversions between Wasm and JS types.
    * **Generic Operators:** The rest of the code defines a wider range of operators like `CheckIf`, type conversions (`ChangeFloat64ToTagged`), checked operations (`CheckedInt32Mul`, `CheckedFloat64ToInt32`), map checks (`CheckMaps`, `MapGuard`, `CompareMaps`), receiver conversion (`ConvertReceiver`), hole checks (`CheckFloat64Hole`), bigint operations (`SpeculativeBigInt*`), closure checks (`CheckClosure`), number conversions (`SpeculativeToNumber`), array element manipulation (`EnsureWritableFastElements`, `MaybeGrowFastElements`, `TransitionElementsKind`), argument handling (`ArgumentsLength`, `RestLength`), allocation (`NewDoubleElements`, `NewSmiOrObjectElements`, `NewArgumentsElements`, `Allocate`, `AllocateRaw`), speculative number operations (`SpeculativeNumber*`), memory access (`LoadField`, `LoadElement`, `StoreElement`, etc.), continuation-related operators, message loading/storing, stack argument loading, element transition and store operations, and fast API call support.

3. **Relate to Javascript functionality:**  Many of these operators directly correspond to JavaScript language features and operations. For example:
    * Type conversions are essential for JavaScript's dynamic typing.
    * Checked operations reflect runtime checks for potential errors (e.g., overflow).
    * Map checks are related to object property access and prototype chains.
    * Array element operations are fundamental to array manipulation.
    * Speculative operators are part of V8's optimization strategy, attempting to optimize based on assumed types.
    * Fast API calls are for interacting with native code.

4. **Provide Javascript examples:** For the most relevant operators with JavaScript connections, concrete examples should be provided. Focus on demonstrating the behavior that the operator represents in the IR.

5. **Address specific instructions:**
    * **`.tq` extension:**  Explain that `.tq` signifies Torque, V8's type definition language, and confirm that this file is `.cc`, not `.tq`.
    * **Code logic/Input-Output:**  For operators like `IsNull` or `IsNotNull`, providing a simple input and the expected boolean output makes the functionality clear. For more complex operators, illustrating a specific scenario is helpful.
    * **Common programming errors:** Link certain operators to common errors, such as `AssertNotNull` relating to `null` or `undefined` access, or checked integer operations potentially throwing errors on overflow.

6. **Structure the answer:** Organize the information logically. Start with the overall function of the file, then delve into groups of operators, provide JavaScript examples, address specific instructions from the prompt, and finally summarize the functionality.

7. **Refine and clarify:** Review the generated answer for clarity, accuracy, and completeness. Ensure that technical terms are explained or are clear from the context. Make sure the connection between C++ operators and JavaScript behavior is evident. Double-check that all parts of the prompt have been addressed. For instance, explicitly state the file is not a Torque file.

**(Self-Correction during thought process):**  Initially, I might have focused too much on listing each operator individually. Recognizing the patterns and grouping related operators (e.g., all the Wasm operators, all the checked integer operators) makes the explanation more concise and understandable. Also, initially I might have skipped providing explicit JavaScript examples, but realizing the prompt asked for this, adding them significantly improves the explanation for someone familiar with JavaScript. Making sure to address *every* part of the multi-part prompt is crucial.
好的，让我们来分析一下 `v8/src/compiler/simplified-operator.cc` 这部分代码的功能。

**功能归纳：**

这段代码定义了 `v8` 编译器中用于构建“简化操作”（Simplified Operators）的各种方法。简化操作是 V8 的中间表示（Intermediate Representation，IR）的一部分，它在高级优化和代码生成之间提供了一个抽象层。这个文件主要负责提供创建特定简化操作实例的工厂方法。这些操作涵盖了各种底层操作，例如内存访问、类型转换、算术运算、对象操作以及与 WebAssembly 相关的操作。

**详细功能列表：**

这段代码主要定义了 `SimplifiedOperatorBuilder` 类中的成员函数，这些函数用于创建各种 `Operator` 类的实例。每个 `Operator` 实例都代表一个特定的简化操作。以下是一些关键的功能分组：

1. **WebAssembly 相关操作 (在 `#ifdef V8_ENABLE_WEBASSEMBLY` 块中):**
    *   `WasmTypeCastAbstract`:  创建 WebAssembly 类型转换操作。
    *   `RttCanon`: 创建 WebAssembly RTTI 规范化操作。
    *   `IsNull`/`IsNotNull`: 创建 WebAssembly 空值检查操作。
    *   `Null`: 创建 WebAssembly 空值常量操作。
    *   `AssertNotNull`: 创建 WebAssembly 断言非空操作。
    *   `WasmAnyConvertExtern`/`WasmExternConvertAny`:  创建 WebAssembly 的 `anyref` 和 `externref` 之间的转换操作。
    *   `WasmStructGet`/`WasmStructSet`: 创建 WebAssembly 结构体字段的读取和写入操作。
    *   `WasmArrayGet`/`WasmArraySet`: 创建 WebAssembly 数组元素的读取和写入操作。
    *   `WasmArrayLength`: 创建 WebAssembly 数组长度获取操作。
    *   `WasmArrayInitializeLength`: 创建 WebAssembly 数组初始化长度操作。

2. **通用控制流和断言操作:**
    *   `CheckIf`: 创建条件检查操作，如果条件不满足则触发反优化。

3. **类型转换操作:**
    *   `ChangeFloat64ToTagged`: 创建将 `float64` 转换为 `Tagged` 指针的操作。
    *   `CheckedFloat64ToInt32`/`CheckedFloat64ToInt64`: 创建带溢出检查的 `float64` 到 `int32`/`int64` 的转换操作。
    *   `CheckedTaggedToInt32`/`CheckedTaggedToInt64`: 创建带溢出检查的 `Tagged` 指针到 `int32`/`int64` 的转换操作。
    *   `CheckedTaggedToFloat64`: 创建带检查的 `Tagged` 指针到 `float64` 的转换操作。
    *   `CheckedTruncateTaggedToWord32`: 创建带检查的 `Tagged` 指针截断到 `Word32` 的操作。

4. **对象和属性操作:**
    *   `CheckMaps`: 创建检查对象 Map 的操作，用于类型守卫。
    *   `MapGuard`: 创建 Map 守卫操作，用于优化。
    *   `CompareMaps`: 创建比较对象 Map 的操作。
    *   `ConvertReceiver`: 创建转换接收者对象的操作。

5. **浮点数操作:**
    *   `CheckFloat64Hole`: 创建检查 `float64` 值是否为洞（hole）的操作。

6. **BigInt 操作 (带有 `Speculative` 前缀):**
    *   `SpeculativeBigInt*`:  创建推测性的 BigInt 算术和比较操作。
    *   `SpeculativeToBigInt`: 创建推测性的转换为 BigInt 的操作。

7. **闭包操作:**
    *   `CheckClosure`: 创建检查闭包的操作。

8. **数字操作 (带有 `SpeculativeToNumber` 前缀):**
    *   `SpeculativeToNumber`: 创建推测性的转换为 Number 的操作。

9. **数组元素操作:**
    *   `EnsureWritableFastElements`: 创建确保数组元素可写且为快速元素的操作。
    *   `MaybeGrowFastElements`: 创建可能增长快速元素数组的操作。
    *   `TransitionElementsKind`: 创建转换数组元素类型的操作。

10. **参数和长度操作:**
    *   `ArgumentsLength`: 创建获取 arguments 对象长度的操作。
    *   `RestLength`: 创建计算剩余参数长度的操作。

11. **内存分配操作:**
    *   `NewDoubleElements`/`NewSmiOrObjectElements`: 创建新的双精度浮点数或 Smi/对象元素数组的操作。
    *   `NewArgumentsElements`: 创建新的 arguments 对象元素的操作。
    *   `Allocate`: 创建分配内存的操作。
    *   `AllocateRaw`: 创建分配原始内存的操作。

12. **推测性数字运算操作 (带有 `SpeculativeNumber` 前缀):**
    *   `SpeculativeNumber*`: 创建推测性的数字算术和比较操作。

13. **内存访问操作 (带有 `Load...` 和 `Store...` 前缀):**
    *   `LoadField`/`StoreField`: 创建读取和写入对象字段的操作。
    *   `LoadElement`/`StoreElement`: 创建读取和写入数组元素的操作。
    *   `LoadTypedElement`/`StoreTypedElement`: 创建读取和写入类型化数组元素的操作。
    *   `LoadFromObject`/`StoreToObject`: 创建从对象读取和写入属性的操作。
    *   `LoadImmutableFromObject`/`InitializeImmutableInObject`: 创建读取和初始化对象不可变属性的操作。
    *   `LoadDataViewElement`/`StoreDataViewElement`: 创建读取和写入 DataView 元素的操作。

14. **Continuation 相关操作:**
    *   `GetContinuationPreservedEmbedderData`/`SetContinuationPreservedEmbedderData`:  创建获取和设置 Continuation 保留的嵌入器数据的操作。

15. **消息操作:**
    *   `LoadMessage`/`StoreMessage`: 创建加载和存储消息的操作。

16. **栈操作:**
    *   `LoadStackArgument`: 创建加载栈参数的操作。

17. **元素转换和存储操作:**
    *   `TransitionAndStoreElement`: 创建转换元素类型并存储的操作。
    *   `StoreSignedSmallElement`: 创建存储有符号小整数元素的操作。
    *   `TransitionAndStoreNumberElement`/`TransitionAndStoreNonNumberElement`: 创建转换并存储数字或非数字元素的操作。

18. **Fast API Call 操作:**
    *   `FastApiCall`: 创建调用快速 C++ API 的操作。

**关于文件类型和 JavaScript 示例：**

*   **文件类型:** 正如你所见，`v8/src/compiler/simplified-operator.cc` 的确是以 `.cc` 结尾，这意味着它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

*   **与 JavaScript 的关系和示例:**  这些简化操作最终代表了 JavaScript 代码在 V8 内部执行时的底层步骤。让我们用一些 JavaScript 例子来说明：

    *   **`CheckedFloat64ToInt32`:** 当你将一个可能超出 `int32` 范围的浮点数转换为整数时，会用到这个操作。
        ```javascript
        let floatValue = 2**32 + 1.5;
        let intValue = floatValue | 0; // 使用位运算进行转换
        // 或者
        intValue = parseInt(floatValue);
        ```
        V8 需要检查 `floatValue` 是否超出 `int32` 的范围。

    *   **`LoadField`:** 当你访问对象的属性时，会用到这个操作。
        ```javascript
        const obj = { a: 10 };
        const value = obj.a; // 这里会使用 LoadField 读取 'a' 字段
        ```

    *   **`StoreField`:** 当你给对象的属性赋值时，会用到这个操作。
        ```javascript
        const obj = {};
        obj.b = 20; // 这里会使用 StoreField 写入 'b' 字段
        ```

    *   **`CheckMaps`:** 当 V8 尝试优化代码时，它会检查对象的“形状”（Map）是否与之前的假设一致。
        ```javascript
        function foo(obj) {
          return obj.x + 1;
        }

        const obj1 = { x: 5 };
        foo(obj1); // V8 可能会假设传递给 foo 的对象具有特定的形状

        const obj2 = { y: 10, x: 7 };
        foo(obj2); // 如果 obj2 的形状与 V8 的假设不同，可能会触发反优化
        ```

    *   **`WasmArrayGet` (如果启用了 WebAssembly):**  当你访问 WebAssembly 数组的元素时。
        ```javascript
        const wasmInstance = new WebAssembly.Instance(wasmModule);
        const wasmArray = wasmInstance.exports.memory;
        const element = wasmArray[index];
        ```

**代码逻辑推理和假设输入输出：**

让我们以 `IsNullOperator` 为例进行代码逻辑推理：

*   **假设输入:**  一个表示 WebAssembly 值的节点，这个值可能是 `null` 或非 `null`。
*   **操作:** `IsNullOperator` 会检查输入值是否为 `null`。
*   **输出:** 一个布尔值，如果输入是 `null`，则为 `true`，否则为 `false`。

例如，在编译 WebAssembly 代码时，如果遇到一个 `(ref.is_null)` 指令，编译器会创建一个 `IsNullOperator`。

**用户常见的编程错误：**

*   **类型转换错误:**  在 JavaScript 中进行不安全的类型转换可能导致意外的结果或运行时错误。例如，尝试将一个非数字字符串转换为数字，或者将超出范围的浮点数转换为整数。V8 的带检查的类型转换操作（如 `CheckedFloat64ToInt32`）有助于在编译或运行时捕获这些错误。

    ```javascript
    let str = "hello";
    let num = parseInt(str); // num 将是 NaN (Not a Number)

    let largeFloat = 2**32 + 1;
    let intValue = largeFloat | 0; // intValue 可能不是你期望的值，因为发生了溢出
    ```

*   **空指针/未定义访问:**  在 WebAssembly 中，尝试访问空引用会触发错误。`AssertNotNullOperator` 对应于断言值非空的场景，如果断言失败，则会抛出陷阱 (Trap)。在 JavaScript 中，访问 `null` 或 `undefined` 的属性会抛出 `TypeError`。

    ```javascript
    let obj = null;
    // obj.property; // TypeError: Cannot read properties of null (reading 'property')
    ```

**总结这段代码的功能：**

`v8/src/compiler/simplified-operator.cc` 是 V8 编译器中至关重要的一个组件，它定义了创建各种底层操作的机制，这些操作构成了 JavaScript 和 WebAssembly 代码在 V8 内部表示和执行的基础。它提供了一组丰富的操作符，涵盖了类型转换、内存访问、控制流、算术运算等，为后续的优化和代码生成阶段提供了必要的抽象和信息。这段代码并没有直接实现这些操作的逻辑，而是定义了如何创建表示这些操作的对象。

Prompt: 
```
这是目录为v8/src/compiler/simplified-operator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/simplified-operator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
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
  const CFunctionInfo* signature 
"""


```