Response: The user wants me to summarize the functionality of the provided V8 Torque source code (`v8/src/builtins/base.tq`). This is part 2 of the code, so I should focus on the functions and macros defined in this snippet. I need to identify the purpose of each macro/function, explain its relation to JavaScript (if any) with examples, provide potential input and output for code logic, and highlight common programming errors it might help prevent or be related to.

Here's a breakdown of the functions/macros in this part:

1. **`IsNullOrUndefined(value)`**: Checks if a value is null or undefined. (Part 1)
2. **`ThrowTypeError(MessageTemplate, ...)`**: Throws a TypeError. (Part 1)
3. **`BranchIfSameValue(JSAny|TaggedWithIdentity, JSAny|TaggedWithIdentity)`**: Branches based on whether two values are the same.
4. **`SameValue(a, b)`**: Returns true if two values are the same, false otherwise. Relies on `BranchIfSameValue`.
5. **`CheckIntegerIndexAdditionOverflow(index1, index2, limit)`**: Checks for potential uintptr overflow when adding two integer indices.
6. **`kModeValueIsSafeIntegerUintPtr`, `kModeValueIsSafeInteger`, `kModeValueIsAnyNumber`**: Constants defining modes for number to uintptr conversion.
7. **`TryNumberToUintPtr(valueNumber, kMode)`**: Tries to convert a Number to a uintptr, handling different modes and potential overflows.
8. **`ChangeUintPtrNumberToUintPtr(value)`**: Converts a Number assumed to be a safe integer within uintptr range to uintptr.
9. **`ChangeSafeIntegerNumberToUintPtr(value)`**: Converts a Number assumed to be a safe integer to uintptr, checking for uintptr overflow.
10. **`ToUintPtr(value)`**: Converts a JSAny to a uintptr after converting it to an integer.
11. **`ToIndex(value)`**: Converts a JSAny to a uintptr, similar to ToUintPtr but throws RangeError for out-of-bounds values.
12. **`GetLengthProperty(o)`**: Gets the 'length' property of an object.
13. **`GetMethod(o, name)` (multiple overloads)**: Gets a method from an object.
14. **`GetInterestingMethod(o, name)`**: Optimized version of GetMethod for "interesting" properties.
15. **`IsOneByteStringMap(Map)`**: Checks if a Map is for one-byte strings.
16. **`IsOneByteStringInstanceType(InstanceType)`**: Checks if an InstanceType is for one-byte strings.
17. **`ConvertAndClampRelativeIndex(index, length)` (multiple overloads)**: Calculates and clamps a relative index.
18. **`ConvertRelativeIndex(indexNumber, length)`**: Calculates a relative index with specific out-of-bounds labels.
19. **`ClampToIndexRange(index, limit)` (multiple overloads)**: Clamps an index to a given range.
20. **`ObjectToString(Context, JSAny)`**: Converts an object to a string (external builtin).
21. **`StringRepeat(Context, String, Number)`**: Repeats a string (external builtin).
22. **`KeyValuePair` struct**: Simple structure for key-value pairs.
23. **`IsFastJSArray(o, context)`**: Checks if an object is a fast JSArray. (legacy API)
24. **`BranchIfFastJSArray(o, context)`**: Branches based on whether an object is a fast JSArray. (legacy API)
25. **`BranchIfFastJSArrayForRead(o, context)`**: Branches based on whether an object is a fast JSArray for read. (legacy API)
26. **`IsFastJSArrayWithNoCustomIteration(context, o)`**: Checks if an object is a fast JSArray with no custom iteration.
27. **`IsFastJSArrayForReadWithNoCustomIteration(context, o)`**: Checks if an object is a fast JSArray for read with no custom iteration.
28. **`CreateDataProperty(receiver, key, value)`**: Creates a data property on an object (external runtime).
29. **`SetOwnPropertyIgnoreAttributes(receiver, key, value, Smi)`**: Sets an own property ignoring attributes (external runtime).
30. **`runtime::GetDerivedMap(Context, JSFunction, JSReceiver, JSAny)`**: Gets the derived map (external runtime).
31. **`IsDeprecatedMap(Map)`**: Checks if a Map is deprecated.
32. **`LoadSlowObjectWithNullPrototypeMap(NativeContext)`**: Loads the map for slow objects with null prototype (external macro).
33. **`FastCreateDataProperty(receiver, key, value)`**: Attempts to create a data property on a fast JSArray, falling back to `CreateDataProperty`.
34. **`VerifiedUnreachable()`**: Marks code as unreachable.
35. **`Float64IsSomeInfinity(value)`**: Checks if a float64 is positive or negative infinity.
36. **`IsIntegerOrSomeInfinity(o)`**: Checks if an object is an integer or infinity.
37. **`NumberIsSomeInfinity(n)`**: Checks if a Number is positive or negative infinity.
38. **`ReplaceTheHoleWithUndefined(o)`**: Replaces the hole value with undefined.
39. **`DecodeScopeInfoHasContextExtension(intptr)`**: Decodes scope info to check for context extension (external macro).
40. **`ConstantIterator<T>` struct and macro**: Defines a simple iterator that always returns the same value.
41. **`FeedbackIteratorEntrySize()`**: Gets the size of a feedback iterator entry (external macro).
42. **`FeedbackIteratorHandlerOffset()`**: Gets the offset of a feedback iterator handler (external macro).
43. **`LoadWeakFixedArrayElement(WeakFixedArray, intptr)`**: Loads an element from a WeakFixedArray (external macro).
44. **`LoadUint8Ptr(RawPtr<uint8>, intptr)`, `LoadUint64Ptr(RawPtr<uint64>, intptr)`**: Loads uint8 and uint64 from raw pointers (external macros).
45. **`HashFieldType` enum**: Defines types for hash fields.
46. **`HashFieldTypeEquals(s1, s2)`**: Checks if two HashFieldTypes are equal.
47. **`kNoHashSentinel`**: Constant for no hash sentinel.
48. **`LoadNameHash(Name)`**: Loads the hash of a Name (external macro).
49. **`ToName(implicit context: Context)(JSAny)`**: Converts a JSAny to an AnyName (external builtin).
50. **`LoadSimd128(intptr)`**: Loads a Simd128 value (external macro).
51. **`I8x16BitMask(I8X16)`**: Creates a bitmask from an I8X16 value (external macro).
52. **`I8x16Eq(I8X16, I8X16)`**: Checks if two I8X16 values are equal (external macro).
53. **`I8x16Splat(int32)`**: Creates an I8X16 value by splatting an int32 (external macro).

Now I can start organizing the information and generating the response.
这是v8 torque源代码文件 `v8/src/builtins/base.tq` 的第二部分，延续了第一部分定义的基础工具宏和函数，旨在提供在V8的内置函数实现中常用的底层操作和类型转换。

**功能归纳:**

这一部分主要包含了以下功能：

*   **类型检查和转换增强:** 提供了更细粒度的数值类型转换，特别是将 JavaScript 的 `Number` 类型转换为 `uintptr`，并考虑了安全整数范围和 `uintptr` 的大小限制，以及可能的溢出情况。
*   **索引处理:** 提供了多种处理 JavaScript 对象索引的方式，包括将任意值转换为合法的索引 (`ToIndex`)，以及根据长度进行相对索引的计算和裁剪 (`ConvertAndClampRelativeIndex`)，以及将索引限制在指定范围内 (`ClampToIndexRange`)。
*   **方法获取:** 提供了安全地从对象上获取方法的方式 (`GetMethod` 和 `GetInterestingMethod`)，并且在方法不存在或不可调用时抛出 `TypeError`。
*   **数组优化辅助:** 提供了一些宏用于判断 JSArray 的特定优化状态，例如是否是快速数组 (`IsFastJSArray`)，以及是否可以安全地进行快速迭代 (`IsFastJSArrayWithNoCustomIteration`)。
*   **属性操作辅助:** 提供了在已知对象类型下快速创建数据属性的宏 (`FastCreateDataProperty`)，作为对通用属性创建操作的优化。
*   **特殊值处理:** 提供了对正负无穷大 (`Float64IsSomeInfinity`, `IsIntegerOrSomeInfinity`, `NumberIsSomeInfinity`) 和 `TheHole` 值的处理。
*   **底层内存和数据访问:** 包含了一些用于访问底层内存的宏，例如加载弱引用数组元素 (`LoadWeakFixedArrayElement`) 和从原始指针加载数据 (`LoadUint8Ptr`, `LoadUint64Ptr`)，以及处理哈希值的相关宏 (`LoadNameHash`)。
*   **SIMD支持:** 提供了一些与 SIMD (Single Instruction, Multiple Data) 操作相关的宏，用于处理 128 位 SIMD 数据类型 (`LoadSimd128`, `I8x16BitMask`, `I8x16Eq`, `I8x16Splat`)。
*   **其他辅助结构和宏:** 定义了一些辅助结构 (`KeyValuePair`) 和常量，以及用于标记不可达代码的宏 (`VerifiedUnreachable`)。

**与 JavaScript 功能的关系及示例:**

这些底层的宏和函数为 V8 引擎实现 JavaScript 的内置功能提供了基础。许多 JavaScript 操作最终会调用到这些底层的实现。

*   **索引访问和数组操作:** `ToIndex`, `ConvertAndClampRelativeIndex`, `ClampToIndexRange` 等宏与 JavaScript 中数组的索引访问、`slice`、`splice` 等方法密切相关。

    ```javascript
    const arr = [1, 2, 3, 4, 5];
    const index = 2.7; // JavaScript 会将其转换为整数 2
    console.log(arr[index]); // 输出 3

    const relativeIndex = -1;
    console.log(arr.slice(relativeIndex)); // 输出 [5] (相当于 arr.slice(4))
    ```

    在 V8 的实现中，访问 `arr[index]` 时，会将 `index` (2.7) 通过类似 `ToIndex` 的操作转换为整数索引。`slice` 方法的实现则会使用 `ConvertAndClampRelativeIndex` 来处理负数索引。

*   **方法调用:** `GetMethod` 宏用于实现 JavaScript 中的方法调用。

    ```javascript
    const obj = {
      myMethod() {
        console.log("Method called");
      }
    };
    obj.myMethod();
    ```

    当调用 `obj.myMethod()` 时，V8 会使用类似 `GetMethod` 的机制来查找并获取 `myMethod` 属性，并确保它是可调用的。

*   **属性创建:** `FastCreateDataProperty` 和 `CreateDataProperty` 与 JavaScript 中动态添加属性有关。

    ```javascript
    const obj = {};
    obj.newProperty = 10;
    ```

    当执行 `obj.newProperty = 10` 时，V8 可能会尝试使用 `FastCreateDataProperty` 进行优化，如果条件不满足，则会回退到更通用的 `CreateDataProperty`。

**代码逻辑推理 (假设输入与输出):**

*   **`SameValue(a, b)`:**
    *   假设输入 `a = 5`, `b = 5`，输出为 `true`。
    *   假设输入 `a = NaN`, `b = NaN`，输出为 `true` (根据 SameValueZero 语义)。
    *   假设输入 `a = {}`, `b = {}`，输出为 `false` (引用不相同)。

*   **`CheckIntegerIndexAdditionOverflow(index1, index2, limit)`:**
    *   假设输入 `index1 = 10`, `index2 = 20`, `limit = 100`，没有 `IfOverflow` 跳转。
    *   假设输入 `index1 = kMaxSafeInteger`, `index2 = 1`, `limit = kMaxSafeInteger`，会发生 `IfOverflow` 跳转 (在 64 位系统上不一定，但在 32 位系统上更有可能，因为 uintptr 范围小)。
    *   假设输入 `index1 = uintptr 最大值 - 5`, `index2 = 10`, `limit = uintptr 最大值 - 2`，会发生 `IfOverflow` 跳转。

*   **`ConvertAndClampRelativeIndex(index, length)`:**
    *   假设输入 `index = 2`, `length = 5`，输出为 `2`。
    *   假设输入 `index = -1`, `length = 5`，输出为 `4`。
    *   假设输入 `index = 10`, `length = 5`，输出为 `5`。
    *   假设输入 `index = -10`, `length = 5`，输出为 `0`。

**用户常见的编程错误及示例:**

这些宏和函数在底层帮助 V8 引擎处理一些常见的 JavaScript 编程错误，并提供更健壮的实现。

*   **访问 `null` 或 `undefined` 的属性或方法:** `GetMethod` 等宏会在尝试访问 `null` 或 `undefined` 的方法时抛出 `TypeError`，这对应于 JavaScript 中常见的错误。

    ```javascript
    const obj = null;
    // obj.myMethod(); // TypeError: Cannot read properties of null (or undefined)
    ```

*   **数组索引越界:**  虽然 JavaScript 允许访问超出数组长度的索引，但 V8 内部的索引处理宏会确保在某些操作中索引的有效性，防止内存访问错误。 `ToIndex` 宏在用于某些需要有效索引的场景时，会检查索引范围。

    ```javascript
    const arr = [1, 2, 3];
    console.log(arr[10]); // 输出 undefined，但 V8 内部的某些操作会检查索引是否有效
    ```

*   **数值类型转换错误:**  将非数字的值用于需要数字的场合，或者超出安全整数范围的数值，可能会导致意外的结果。 `TryNumberToUintPtr` 等宏处理了这些转换的细节，并在必要时抛出错误。

    ```javascript
    const index = "abc";
    // arr[index]; // JavaScript 会将 "abc" 转换为 0，可能不是期望的结果
    ```

*   **方法调用错误:** 尝试调用非函数类型的属性会引发错误。 `GetMethod` 确保获取的属性是可调用的。

    ```javascript
    const obj = { prop: 10 };
    // obj.prop(); // TypeError: obj.prop is not a function
    ```

总而言之，`v8/src/builtins/base.tq` 的第二部分继续为 V8 引擎的内置函数提供了重要的基础工具，涵盖了类型处理、索引操作、方法获取、数组优化等多个方面，并帮助引擎更安全、高效地执行 JavaScript 代码。它间接地帮助开发者避免了一些常见的编程错误，并在底层提供了更强的类型安全和错误处理机制。

### 提示词
```
这是目录为v8/src/builtins/base.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
it context: Context)(value: JSAny, name: constexpr string): JSAny {
  if (IsNullOrUndefined(value)) {
    ThrowTypeError(MessageTemplate::kCalledOnNullOrUndefined, name);
  }
  return value;
}

extern macro BranchIfSameValue(
    JSAny|TaggedWithIdentity, JSAny|TaggedWithIdentity): never labels Taken,
    NotTaken;
macro SameValue(
    a: JSAny|TaggedWithIdentity, b: JSAny|TaggedWithIdentity): bool {
  BranchIfSameValue(a, b) otherwise return true, return false;
}

// Does "if (index1 + index2 > limit) goto IfOverflow" in an uintptr overflow
// friendly way where index1 and index2 are in [0, kMaxSafeInteger] range.
macro CheckIntegerIndexAdditionOverflow(
    index1: uintptr, index2: uintptr, limit: uintptr): void labels IfOverflow {
  if constexpr (Is64()) {
    dcheck(index1 <= kMaxSafeIntegerUint64);
    dcheck(index2 <= kMaxSafeIntegerUint64);
    // Given that both index1 and index2 are in a safe integer range the
    // addition can't overflow.
    if (index1 + index2 > limit) goto IfOverflow;
  } else {
    // Uintptr range is "smaller" than [0, kMaxSafeInteger] range, so
    // "index1 + index2" may overflow, so we check the condition in the
    // following way "if (index1 > limit - index2) goto IfOverflow" and check
    // that "limit - index2" does not underflow.
    const index1Limit = limit - index2;
    if (index1 > index1Limit) goto IfOverflow;
    // Handle potential index1Limit underflow.
    if (index1Limit > limit) goto IfOverflow;
  }
}

// TODO(turbofan): Define enum here once they appear in Torque.
//
// The value is a SafeInteger that fits into uintptr range, so no bounds checks
// are necessary.
const kModeValueIsSafeIntegerUintPtr: constexpr int31 = 0;
// The value is a SafeInteger that may not fit into uintptr range, so only
// uintptr bounds check is necessary.
const kModeValueIsSafeInteger: constexpr int31 = 1;
// The value is can be whatever non-NaN number, all checks are necessary.
const kModeValueIsAnyNumber: constexpr int31 = 2;

macro TryNumberToUintPtr(valueNumber: Number, kMode: constexpr int31):
    uintptr labels IfLessThanZero, IfUIntPtrOverflow, IfSafeIntegerOverflow {
  typeswitch (valueNumber) {
    case (valueSmi: Smi): {
      if (kMode == kModeValueIsAnyNumber) {
        if (valueSmi < 0) goto IfLessThanZero;
      } else {
        dcheck(valueSmi >= 0);
      }
      const value: uintptr = Unsigned(Convert<intptr>(valueSmi));
      // Positive Smi values definitely fit into both [0, kMaxSafeInteger] and
      // [0, kMaxUintPtr] ranges.
      return value;
    }
    case (valueHeapNumber: HeapNumber): {
      dcheck(IsNumberNormalized(valueHeapNumber));
      const valueDouble: float64 = Convert<float64>(valueHeapNumber);
      // NaNs must be handled outside.
      dcheck(!Float64IsNaN(valueDouble));
      if (kMode == kModeValueIsAnyNumber) {
        if (valueDouble < 0) goto IfLessThanZero;
      } else {
        dcheck(valueDouble >= 0);
      }

      if constexpr (Is64()) {
        // On 64-bit architectures uintptr range is bigger than safe integer
        // range.
        if (kMode == kModeValueIsAnyNumber) {
          if (valueDouble > kMaxSafeInteger) goto IfSafeIntegerOverflow;
        } else {
          dcheck(valueDouble <= kMaxSafeInteger);
        }
      } else {
        // On 32-bit architectures uintptr range is smaller than safe integer
        // range.
        if (kMode == kModeValueIsAnyNumber ||
            kMode == kModeValueIsSafeInteger) {
          if (valueDouble > kMaxUInt32Double) goto IfUIntPtrOverflow;
        } else {
          dcheck(valueDouble <= kMaxUInt32Double);
        }
      }
      return ChangeFloat64ToUintPtr(valueDouble);
    }
  }
}

@export
macro ChangeUintPtrNumberToUintPtr(value: Number): uintptr {
  try {
    return TryNumberToUintPtr(value, kModeValueIsSafeIntegerUintPtr)
        otherwise InvalidValue, InvalidValue, InvalidValue;
  } label InvalidValue {
    unreachable;
  }
}

@export
macro ChangeSafeIntegerNumberToUintPtr(value: Number):
    uintptr labels IfUIntPtrOverflow {
  try {
    return TryNumberToUintPtr(value, kModeValueIsSafeInteger)
        otherwise InvalidValue, IfUIntPtrOverflow, InvalidValue;
  } label InvalidValue {
    unreachable;
  }
}

transitioning macro ToUintPtr(implicit context: Context)(value: JSAny):
    uintptr labels IfLessThanZero, IfUIntPtrOverflow, IfSafeIntegerOverflow {
  if (value == Undefined) return 0;
  const indexNumber = ToInteger_Inline(value);
  return TryNumberToUintPtr(indexNumber, kModeValueIsAnyNumber)
      otherwise IfLessThanZero, IfUIntPtrOverflow, IfSafeIntegerOverflow;
}

// https://tc39.github.io/ecma262/#sec-toindex
// Unlike ToIndex from the spec this implementation triggers IfRangeError if
// the result is bigger than min(kMaxUIntPtr, kMaxSafeInteger).
// We can do this because all callers do a range checks against uintptr length
// anyway and throw a RangeError in case of out-of-bounds index.
@export
transitioning macro ToIndex(
    implicit context: Context)(value: JSAny): uintptr labels IfRangeError {
  if (value == Undefined) return 0;
  const indexNumber = ToInteger_Inline(value);
  // Less than 0 case, uintptr range overflow and safe integer range overflow
  // imply IfRangeError.
  return TryNumberToUintPtr(indexNumber, kModeValueIsAnyNumber)
      otherwise IfRangeError, IfRangeError, IfRangeError;
}

transitioning macro GetLengthProperty(
    implicit context: Context)(o: JSAny): Number {
  try {
    typeswitch (o) {
      case (a: JSArray): {
        return a.length;
      }
      case (a: JSStrictArgumentsObject): {
        goto ToLength(a.length);
      }
      case (a: JSSloppyArgumentsObject): {
        goto ToLength(a.length);
      }
      case (JSAny): deferred {
        goto ToLength(GetProperty(o, kLengthString));
      }
    }
  } label ToLength(length: JSAny) deferred {
    return ToLength_Inline(length);
  }
}

transitioning macro GetMethod(
    implicit context: Context)(o: JSAny, name: AnyName):
    Callable labels IfNullOrUndefined,
    IfMethodNotCallable(JSAny) {
  // Use GetInterestingMethod - a version of GetMethod optimized for interesting
  // properties.
  dcheck(!IsInterestingProperty(name));
  const value = GetProperty(o, name);
  // TODO(v8:9933): Consider checking for null/undefined after checking for
  // callable because the latter seems to be more common.
  if (value == Undefined || value == Null) goto IfNullOrUndefined;
  return Cast<Callable>(value)
      otherwise goto IfMethodNotCallable(value);
}

transitioning macro GetMethod(
    implicit context: Context)(o: JSAny,
    name: String): Callable labels IfNullOrUndefined {
  // Use GetInterestingMethod - a version of GetMethod optimized for interesting
  // properties.
  dcheck(!IsInterestingProperty(name));
  try {
    return GetMethod(o, name) otherwise IfNullOrUndefined, IfMethodNotCallable;
  } label IfMethodNotCallable(value: JSAny) deferred {
    ThrowTypeError(MessageTemplate::kPropertyNotFunction, value, name, o);
  }
}

transitioning macro GetMethod(
    implicit context: Context)(o: JSAny,
    name: constexpr string): Callable labels IfNullOrUndefined {
  return GetMethod(o, StringConstant(name)) otherwise IfNullOrUndefined;
}

transitioning macro GetMethod(
    implicit context: Context)(o: JSAny,
    symbol: Symbol): Callable labels IfNullOrUndefined {
  // Use GetInterestingMethod - a version of GetMethod optimized for interesting
  // properties.
  dcheck(!IsInterestingProperty(symbol));
  const value = GetProperty(o, symbol);
  if (value == Undefined || value == Null) goto IfNullOrUndefined;
  return Cast<Callable>(value)
      otherwise ThrowTypeError(
      MessageTemplate::kPropertyNotFunction, value, symbol, o);
}

transitioning macro GetInterestingMethod(
    implicit context: Context)(o: JSReceiver,
    name: String): Callable labels IfNullOrUndefined {
  dcheck(IsInterestingProperty(name));
  try {
    const value = GetInterestingProperty(context, o, name)
        otherwise goto IfNullOrUndefined;
    if (value == Undefined || value == Null) goto IfNullOrUndefined;
    return Cast<Callable>(value)
        otherwise goto IfMethodNotCallable(value);
  } label IfMethodNotCallable(value: JSAny) deferred {
    ThrowTypeError(MessageTemplate::kPropertyNotFunction, value, name, o);
  }
}

extern macro IsOneByteStringMap(Map): bool;
extern macro IsOneByteStringInstanceType(InstanceType): bool;

// After converting an index to an integer, calculate a relative index:
// return index < 0 ? max(length + index, 0) : min(index, length)
@export
transitioning macro ConvertAndClampRelativeIndex(
    implicit context: Context)(index: JSAny, length: uintptr): uintptr {
  const indexNumber: Number = ToInteger_Inline(index);
  return ConvertAndClampRelativeIndex(indexNumber, length);
}

// Calculate a relative index:
// return index < 0 ? max(length + index, 0) : min(index, length)
@export
macro ConvertAndClampRelativeIndex(
    indexNumber: Number, length: uintptr): uintptr {
  try {
    return ConvertRelativeIndex(indexNumber, length) otherwise OutOfBoundsLow,
           OutOfBoundsHigh;
  } label OutOfBoundsLow {
    return 0;
  } label OutOfBoundsHigh {
    return length;
  }
}

// Calculate a relative index with explicit out-of-bounds labels.
macro ConvertRelativeIndex(indexNumber: Number, length: uintptr):
    uintptr labels OutOfBoundsLow, OutOfBoundsHigh {
  typeswitch (indexNumber) {
    case (indexSmi: Smi): {
      const indexIntPtr: intptr = Convert<intptr>(indexSmi);
      // The logic is implemented using unsigned types.
      if (indexIntPtr < 0) {
        const relativeIndex: uintptr = Unsigned(indexIntPtr) + length;
        if (relativeIndex < length) return relativeIndex;
        goto OutOfBoundsLow;

      } else {
        const relativeIndex: uintptr = Unsigned(indexIntPtr);
        if (relativeIndex < length) return relativeIndex;
        goto OutOfBoundsHigh;
      }
    }
    case (indexHeapNumber: HeapNumber): {
      dcheck(IsNumberNormalized(indexHeapNumber));
      const indexDouble: float64 = Convert<float64>(indexHeapNumber);
      // NaNs must already be handled by ConvertAndClampRelativeIndex() version
      // above accepting JSAny indices.
      dcheck(!Float64IsNaN(indexDouble));
      const lengthDouble: float64 = Convert<float64>(length);
      dcheck(lengthDouble <= kMaxSafeInteger);
      if (indexDouble < 0) {
        const relativeIndex: float64 = lengthDouble + indexDouble;
        if (relativeIndex > 0) {
          return ChangeFloat64ToUintPtr(relativeIndex);
        }
        goto OutOfBoundsLow;

      } else {
        if (indexDouble < lengthDouble) {
          return ChangeFloat64ToUintPtr(indexDouble);
        }
        goto OutOfBoundsHigh;
      }
    }
  }
}

// After converting an index to a signed integer, clamps it to the provided
// range [0, limit]:
// return min(max(index, 0), limit)
@export
transitioning macro ClampToIndexRange(
    implicit context: Context)(index: JSAny, limit: uintptr): uintptr {
  const indexNumber: Number = ToInteger_Inline(index);
  return ClampToIndexRange(indexNumber, limit);
}

// Clamps given signed indexNumber to the provided range [0, limit]:
// return min(max(index, 0), limit)
@export
macro ClampToIndexRange(indexNumber: Number, limit: uintptr): uintptr {
  typeswitch (indexNumber) {
    case (indexSmi: Smi): {
      if (indexSmi < 0) return 0;
      const index: uintptr = Unsigned(Convert<intptr>(indexSmi));
      if (index >= limit) return limit;
      return index;
    }
    case (indexHeapNumber: HeapNumber): {
      dcheck(IsNumberNormalized(indexHeapNumber));
      const indexDouble: float64 = Convert<float64>(indexHeapNumber);
      // NaNs must already be handled by ClampToIndexRange() version
      // above accepting JSAny indices.
      dcheck(!Float64IsNaN(indexDouble));
      if (indexDouble <= 0) return 0;

      const maxIndexDouble: float64 = Convert<float64>(limit);
      dcheck(maxIndexDouble <= kMaxSafeInteger);
      if (indexDouble >= maxIndexDouble) return limit;

      return ChangeFloat64ToUintPtr(indexDouble);
    }
  }
}

extern builtin ObjectToString(Context, JSAny): String;
extern builtin StringRepeat(Context, String, Number): String;

@export
struct KeyValuePair {
  key: JSAny;
  value: JSAny;
}

// Macro definitions for compatibility that expose functionality to the CSA
// using "legacy" APIs. In Torque code, these should not be used.
@export
macro IsFastJSArray(o: Object, context: Context): bool {
  // Long-term, it's likely not a good idea to have this slow-path test here,
  // since it fundamentally breaks the type system.
  if (IsForceSlowPath()) return false;
  return Is<FastJSArray>(o);
}

@export
macro BranchIfFastJSArray(o: Object, context: Context): never labels True,
    False {
  if (IsFastJSArray(o, context)) {
    goto True;
  } else {
    goto False;
  }
}

@export
macro BranchIfFastJSArrayForRead(o: Object, context: Context):
    never labels True, False {
  // Long-term, it's likely not a good idea to have this slow-path test here,
  // since it fundamentally breaks the type system.
  if (IsForceSlowPath()) goto False;
  if (Is<FastJSArrayForRead>(o)) {
    goto True;
  } else {
    goto False;
  }
}

@export
macro IsFastJSArrayWithNoCustomIteration(context: Context, o: Object): bool {
  return Is<FastJSArrayWithNoCustomIteration>(o);
}

@export
macro IsFastJSArrayForReadWithNoCustomIteration(
    context: Context, o: Object): bool {
  return Is<FastJSArrayForReadWithNoCustomIteration>(o);
}

extern transitioning runtime CreateDataProperty(
    implicit context: Context)(JSReceiver, JSAny, JSAny): void;

extern transitioning runtime SetOwnPropertyIgnoreAttributes(
    implicit context: Context)(JSObject, String, JSAny, Smi): void;

namespace runtime {
extern runtime GetDerivedMap(Context, JSFunction, JSReceiver, JSAny): Map;
}
extern macro IsDeprecatedMap(Map): bool;

extern macro LoadSlowObjectWithNullPrototypeMap(NativeContext): Map;

transitioning builtin FastCreateDataProperty(
    implicit context: Context)(receiver: JSReceiver, key: JSAny,
    value: JSAny): Object {
  try {
    const array = Cast<FastJSArray>(receiver) otherwise Slow;
    const index: Smi = Cast<Smi>(key) otherwise goto Slow;
    if (index < 0 || index > array.length) goto Slow;
    const isAppend = index == array.length;

    if (isAppend) {
      // Fast append only works on fast elements kind and with writable length.
      const kind = EnsureArrayPushable(array.map) otherwise Slow;
      array::EnsureWriteableFastElements(array);

      // We may have to transition a.
      // For now, if transition is required, jump away to slow.
      if (IsFastSmiElementsKind(kind)) {
        BuildAppendJSArray(ElementsKind::HOLEY_SMI_ELEMENTS, array, value)
            otherwise Slow;
      } else if (IsDoubleElementsKind(kind)) {
        BuildAppendJSArray(ElementsKind::HOLEY_DOUBLE_ELEMENTS, array, value)
            otherwise Slow;
      } else {
        dcheck(IsFastSmiOrTaggedElementsKind(kind));
        BuildAppendJSArray(ElementsKind::HOLEY_ELEMENTS, array, value)
            otherwise Slow;
      }
    } else {
      // Non-appending element store.
      const kind = array.map.elements_kind;
      array::EnsureWriteableFastElements(array);

      // We may have to transition a.
      // For now, if transition is required, jump away to slow.
      if (IsFastSmiElementsKind(kind)) {
        const smiValue = Cast<Smi>(value) otherwise Slow;
        const elements = Cast<FixedArray>(array.elements) otherwise unreachable;
        elements[index] = smiValue;
      } else if (IsDoubleElementsKind(kind)) {
        const numberValue = Cast<Number>(value) otherwise Slow;
        const doubleElements = Cast<FixedDoubleArray>(array.elements)
            otherwise unreachable;
        doubleElements[index] = numberValue;
      } else {
        dcheck(IsFastSmiOrTaggedElementsKind(kind));
        const elements = Cast<FixedArray>(array.elements) otherwise unreachable;
        elements[index] = value;
      }
    }
  } label Slow {
    CreateDataProperty(receiver, key, value);
  }
  return Undefined;
}

macro VerifiedUnreachable(): never {
  static_assert(false);
  unreachable;
}

macro Float64IsSomeInfinity(value: float64): bool {
  if (value == V8_INFINITY) {
    return true;
  }
  return value == (Convert<float64>(0) - V8_INFINITY);
}

macro IsIntegerOrSomeInfinity(o: Object): bool {
  typeswitch (o) {
    case (Smi): {
      return true;
    }
    case (hn: HeapNumber): {
      if (Float64IsSomeInfinity(Convert<float64>(hn))) {
        return true;
      }
      return IsInteger(hn);
    }
    case (Object): {
      return false;
    }
  }
}

macro NumberIsSomeInfinity(n: Number): bool {
  typeswitch (n) {
    case (Smi): {
      return false;
    }
    case (hn: HeapNumber): {
      return Float64IsSomeInfinity(Convert<float64>(hn));
    }
  }
}

macro ReplaceTheHoleWithUndefined(o: JSAny|TheHole): JSAny {
  typeswitch (o) {
    case (TheHole): {
      return Undefined;
    }
    case (a: JSAny): {
      return a;
    }
  }
}

extern macro DecodeScopeInfoHasContextExtension(intptr): intptr;

struct ConstantIterator<T: type> {
  macro Empty(): bool {
    return false;
  }
  macro Next(): T labels _NoMore {
    return this.value;
  }

  value: T;
}
macro ConstantIterator<T: type>(value: T): ConstantIterator<T> {
  return ConstantIterator{value};
}

extern macro FeedbackIteratorEntrySize(): intptr;
extern macro FeedbackIteratorHandlerOffset(): intptr;
extern operator '[]' macro LoadWeakFixedArrayElement(
    WeakFixedArray, intptr): MaybeObject;

extern operator '[]' macro LoadUint8Ptr(RawPtr<uint8>, intptr): uint8;
extern operator '[]' macro LoadUint64Ptr(RawPtr<uint64>, intptr): uint64;

extern enum HashFieldType extends uint32 constexpr 'Name::HashFieldType' {
  kHash,
  kIntegerIndex,
  kForwardingIndex,
  kEmpty
}

operator '==' macro HashFieldTypeEquals(
    s1: HashFieldType, s2: HashFieldType): bool {
  return Word32Equal(s1, s2);
}

const kNoHashSentinel:
    constexpr int32 generates 'PropertyArray::kNoHashSentinel';
extern macro LoadNameHash(Name): uint32;

extern transitioning builtin ToName(implicit context: Context)(JSAny): AnyName;

extern macro LoadSimd128(intptr): Simd128;
extern macro I8x16BitMask(I8X16): int32;
extern macro I8x16Eq(I8X16, I8X16): I8X16;
extern macro I8x16Splat(int32): I8X16;
```