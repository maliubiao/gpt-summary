Response: Let's break down the thought process for analyzing this Torque file.

1. **Initial Skim and High-Level Understanding:**

   - The file name `number.tq` in the `v8/src/builtins` directory strongly suggests it deals with JavaScript's `Number` object and related operations.
   - The `// Copyright` and `#include` statements are boilerplate.
   - The `extern enum Operation` immediately tells me this code is about implementing various numerical operations. The specific operations listed (add, subtract, multiply, etc.) confirm this.
   - The `namespace runtime` block indicates interactions with lower-level V8 runtime functions. This is common in builtins.
   - The `namespace number` block is where the main logic resides.

2. **Identify Key Sections and Concepts:**

   - **Macros:**  These are like inline functions in C/C++. Look for `macro` keywords. Examples: `ThisNumberValue`, `ToCharCode`, `IntToDecimalStringImpl`, `IntToDecimalString`, `IntToString`. These are likely helper functions for common tasks.
   - **Builtins:** These are the core JavaScript-callable functions implemented in Torque. Look for `transitioning javascript builtin`. Examples: `NumberPrototypeToString`, `NumberIsFinite`, `NumberIsInteger`, etc. These directly correspond to `Number` object methods and static methods.
   - **Type Switching:**  The `typeswitch` statement is heavily used. This is a key mechanism in Torque for handling different JavaScript value types (Smi, HeapNumber, BigInt, String, etc.).
   - **Labels:**  The `label` keyword, often used with `goto`, indicates control flow within the Torque code. This can sometimes make the code harder to follow, but it's part of Torque's syntax.
   - **Runtime Calls:**  The `runtime::` prefix indicates calls to C++ runtime functions. These handle tasks that are either performance-critical or too complex to implement directly in Torque.
   - **Constants:**  Look for `constexpr` and explicitly named constants (e.g., `ZeroStringConstant`, `NaNStringConstant`).
   - **Operations Enum:** This defines the set of supported numerical operations.

3. **Analyze Individual Macros and Builtins:**

   - **Macros:** Focus on what they do.
     - `ThisNumberValue`:  Likely enforces that the `this` value is a Number.
     - `ToCharCode`: Converts a small integer to a character.
     - `IntToDecimalStringImpl`/`IntToDecimalString`/`IntToString`:  Handle converting integers to string representations in different bases. Pay attention to the optimizations for common cases (e.g., small numbers, radix 10).
   - **Builtins:**  Connect them to their JavaScript counterparts.
     - `NumberPrototypeToString`:  The `toString()` method of a Number. Note the handling of radix.
     - `NumberIsFinite`, `NumberIsInteger`, `NumberIsNaN`, `NumberIsSafeInteger`:  Static methods on the `Number` object. Their implementations involve type checking.
     - `NumberPrototypeValueOf`:  The `valueOf()` method.
     - `NumberParseFloat`, `NumberParseInt`:  Static parsing methods. Note the attempt to optimize for cached array indices.
     - Arithmetic Operators (`Add`, `Subtract`, `Multiply`, `Divide`, `Modulus`, `Exponentiate`): These are complex due to the need to handle different numeric types (Smi, HeapNumber, BigInt) and potential string coercion for addition. The `BinaryOp1` and `BinaryOp2` macros are key to understanding the dispatch logic.
     - Bitwise Operators (`BitwiseNot`, `ShiftLeft`, `ShiftRight`, `ShiftRightLogical`, `BitwiseAnd`, `BitwiseOr`, `BitwiseXor`): These often involve truncating to 32-bit integers.
     - Unary Operators (`Negate`, `Decrement`, `Increment`): Relatively straightforward.
     - Relational Operators (`LessThan`, `LessThanOrEqual`, `GreaterThan`, `GreaterThanOrEqual`, `Equal`, `StrictEqual`):  Delegate to lower-level comparison logic.

4. **Identify Relationships with JavaScript:**

   - The names of the builtins are directly related to JavaScript's `Number` object and its methods.
   - The logic within the builtins often mirrors the steps described in the ECMAScript specification (e.g., `NumberPrototypeToString` follows the spec).
   - Examples can be created by calling the corresponding JavaScript methods.

5. **Look for Code Logic and Potential Edge Cases:**

   - **Type Handling:** The extensive use of `typeswitch` highlights the importance of handling different JavaScript types correctly.
   - **Optimizations:** Notice the checks for Smi values and cached array indices, which are performance optimizations.
   - **Error Handling:**  `ThrowRangeError` in `NumberPrototypeToString` shows error handling.
   - **Overflow/Underflow:**  The `TrySmiAdd` and `TrySmiSub` suggest awareness of potential integer overflow.
   - **NaN and Infinity:**  Specific handling for `NaN`, `Infinity`, and `-Infinity` in `NumberPrototypeToString`.
   - **Radix Handling:**  The checks for valid radix values in `NumberPrototypeToString` and `ParseInt`.

6. **Consider Common Programming Errors:**

   - **Incorrect Radix:** Passing an invalid radix to `parseInt` or `toString`.
   - **Type Coercion:** Implicit type conversions in operations like addition can lead to unexpected results (e.g., adding a number and a string).
   - **Integer Overflow:** Bitwise operations and arithmetic with large numbers can lead to unexpected results due to integer limits.
   - **NaN Comparisons:**  Understanding that `NaN` is not equal to itself.
   - **Floating-Point Precision:**  The inherent imprecision of floating-point numbers can cause issues in comparisons.

7. **Structure the Summary:**

   - Start with a general overview of the file's purpose.
   - Detail the functionality of key macros and builtins, linking them to their JavaScript equivalents.
   - Provide concrete JavaScript examples to illustrate the functionality.
   - Explain any interesting code logic or assumptions.
   - List common programming errors related to the code.

**Self-Correction/Refinement During Analysis:**

- **Initial thought:**  "This file just converts numbers to strings."  **Correction:**  While string conversion is a part, it also implements many other core `Number` functionalities like arithmetic, comparisons, and parsing.
- **Initial thought:** "The `goto` statements are confusing." **Refinement:** While not ideal for readability, understand that it's part of Torque's control flow and try to follow the logic flow by looking at the labels.
- **Initial thought:** "Why so much type switching?" **Refinement:** JavaScript is dynamically typed, so V8 needs to handle different types at runtime. Torque's type switching is a direct reflection of this.

By following these steps, iterating, and refining understanding, a comprehensive analysis of the Torque file can be achieved.
这个v8 torque文件 `v8/src/builtins/number.tq`  实现了JavaScript中 `Number` 对象相关的内置函数和一些底层的数字操作。它负责处理数字类型的转换、运算、格式化等核心功能。

**功能归纳：**

1. **数字类型转换:**
   - 将其他类型转换为数字 (`ToNumericOrPrimitive`, `NonNumberToNumeric`)。
   - 将数字转换为字符串 (`IntToDecimalString`, `IntToString`, `NumberPrototypeToString`, `DoubleToStringWithRadix`)。
   - 将字符串转换为数字 (`StringParseFloat`, `StringParseInt`, `NumberParseFloat`, `NumberParseInt`)。

2. **数字运算:**
   - 实现了各种算术运算符（加、减、乘、除、取模、幂运算）： `Add`, `Subtract`, `Multiply`, `Divide`, `Modulus`, `Exponentiate`。
   - 实现了位运算符（位与、位或、位异或、左移、右移、无符号右移）： `BitwiseAnd`, `BitwiseOr`, `BitwiseXor`, `ShiftLeft`, `ShiftRight`, `ShiftRightLogical`。
   - 实现了单目运算符（取负、按位取反、自增、自减）： `Negate`, `BitwiseNot`, `Increment`, `Decrement`。

3. **数字比较:**
   - 实现了关系运算符（小于、小于等于、大于、大于等于）： `LessThan`, `LessThanOrEqual`, `GreaterThan`, `GreaterThanOrEqual`。
   - 实现了相等和严格相等运算符： `Equal`, `StrictEqual`。

4. **`Number` 对象的方法和静态方法实现:**
   - `Number.prototype.toString()`: 将数字转换为指定进制的字符串。
   - `Number.isFinite()`: 判断一个值是否是有限数。
   - `Number.isInteger()`: 判断一个值是否是整数。
   - `Number.isNaN()`: 判断一个值是否是 `NaN`。
   - `Number.isSafeInteger()`: 判断一个值是否是安全整数。
   - `Number.prototype.valueOf()`: 返回 `Number` 对象的原始值。
   - `Number.parseFloat()`: 将字符串解析为浮点数。
   - `Number.parseInt()`: 将字符串解析为整数。

**与 Javascript 功能的关系及 Javascript 示例:**

这个 torque 文件中的代码直接实现了 JavaScript 中 `Number` 对象及其原型上的方法，以及全局的 `parseInt` 和 `parseFloat` 函数的功能。

```javascript
// Number.prototype.toString()
const num = 10;
console.log(num.toString()); // "10"
console.log(num.toString(2)); // "1010" (二进制)

// Number.isFinite()
console.log(Number.isFinite(10)); // true
console.log(Number.isFinite(Infinity)); // false
console.log(Number.isFinite(NaN)); // false

// Number.isInteger()
console.log(Number.isInteger(10)); // true
console.log(Number.isInteger(10.5)); // false

// Number.isNaN()
console.log(Number.isNaN(NaN)); // true
console.log(Number.isNaN(10)); // false

// Number.isSafeInteger()
console.log(Number.isSafeInteger(Math.pow(2, 53) - 1)); // true
console.log(Number.isSafeInteger(Math.pow(2, 53))); // false

// Number.prototype.valueOf()
const numberObj = new Number(10);
console.log(numberObj.valueOf()); // 10

// Number.parseFloat()
console.log(Number.parseFloat("10.5")); // 10.5
console.log(Number.parseFloat("  10  ")); // 10

// Number.parseInt()
console.log(Number.parseInt("10")); // 10
console.log(Number.parseInt("10.5")); // 10
console.log(Number.parseInt("0xA")); // 10 (十六进制)
console.log(Number.parseInt("10", 2)); // 2 (二进制)

// 算术运算符
console.log(5 + 3); // 8
console.log(5 - 3); // 2
console.log(5 * 3); // 15
console.log(6 / 3); // 2
console.log(7 % 3); // 1
console.log(2 ** 3); // 8

// 位运算符
console.log(5 & 3); // 1
console.log(5 | 3); // 7
console.log(5 ^ 3); // 6
console.log(5 << 1); // 10
console.log(10 >> 1); // 5
console.log(-1 >>> 1); // 4294967295

// 单目运算符
let x = 5;
console.log(-x); // -5
console.log(~x); // -6
console.log(x++); // 5 (后自增)
console.log(--x); // 5 (前自减)

// 关系运算符
console.log(5 < 3); // false
console.log(5 <= 5); // true
console.log(5 > 3); // true
console.log(5 >= 5); // true

// 相等运算符
console.log(5 == "5"); // true (类型转换)
console.log(5 === "5"); // false (类型和值都必须相等)
```

**代码逻辑推理及假设输入与输出:**

**示例 1: `IntToDecimalString(x: int32)`**

* **假设输入:** `x = 123`
* **代码逻辑:**
    - 判断是否为 64 位架构，如果是则使用优化的路径。
    - 由于 `x >= 0` 且 `x >= 10`，进入 `IntToDecimalStringImpl(x, log10OffsetsTable, true)`。
    - `IntToDecimalStringImpl` 中通过循环计算每一位数字，从低位到高位，并将其转换为字符。
    - 最终构建字符串 "123"。
* **预期输出:** 字符串 "123"

* **假设输入:** `x = -45`
* **代码逻辑:**
    - 判断是否为 64 位架构。
    - 进入 `IntToDecimalStringImpl(x, log10OffsetsTable, false)`。
    - `IntToDecimalStringImpl` 处理负数的情况，先计算绝对值的字符串，然后在前面加上 "-"。
    - 最终构建字符串 "-45"。
* **预期输出:** 字符串 "-45"

**示例 2: `NumberPrototypeToString(receiver: JSAny, ...arguments)`**

* **假设输入:** `receiver` 是一个值为 `10` 的 `Number` 对象， `arguments` 为空。
* **代码逻辑:**
    - `ThisNumberValue` 确保 `receiver` 是一个 `Number` 类型。
    - `radixNumber` 默认为 10。
    - `radixNumber == 10`，调用 `NumberToString(x)`，最终会调用 `IntToDecimalString(10)`。
* **预期输出:** 字符串 "10"

* **假设输入:** `receiver` 是一个值为 `15` 的 `Number` 对象， `arguments` 为 `[16]`。
* **代码逻辑:**
    - `ThisNumberValue` 确保 `receiver` 是一个 `Number` 类型。
    - `radixNumber` 从 `arguments[0]` 中获取，为 16。
    - `radixNumber != 10`，且 `x` 是 Smi，调用 `IntToString(15, 16)`。
    - `IntToString` 将 15 转换为十六进制字符串 "f"。
* **预期输出:** 字符串 "f"

**用户常见的编程错误及示例:**

1. **`parseInt` 或 `Number.parseInt` 使用错误的进制:**

   ```javascript
   console.log(parseInt("10", 8)); // 输出 8，因为 "10" 被当作八进制解析
   console.log(parseInt("010")); // 在一些旧浏览器中可能被当作八进制解析，导致不一致的行为
   ```
   **建议:**  始终显式指定 `parseInt` 的进制参数。

2. **不理解 `parseFloat` 和 `parseInt` 的差异:**

   ```javascript
   console.log(parseInt("10.5")); // 输出 10，parseInt 只解析整数部分
   console.log(parseFloat("10.5")); // 输出 10.5
   ```
   **建议:** 根据需要选择合适的解析函数。

3. **对非数字类型使用 `Number` 对象的方法:**

   ```javascript
   // 可能会抛出 TypeError
   // Number.isNaN("hello"); // 返回 false，因为 "hello" 不是 Number 类型

   // 应该使用全局的 isNaN()
   console.log(isNaN("hello")); // 返回 true
   ```
   **建议:**  注意 `Number` 对象的方法通常期望 `this` 是一个 `Number` 类型。

4. **二进制位运算的误用导致非预期的结果:**

   ```javascript
   console.log(1 << 32); // 结果可能是 1，因为 JavaScript 的位运算会转换为 32 位整数
   ```
   **建议:**  理解位运算的原理和 JavaScript 中位运算的限制。

5. **浮点数精度问题导致的比较错误:**

   ```javascript
   console.log(0.1 + 0.2 === 0.3); // 输出 false，因为浮点数存在精度问题
   ```
   **建议:**  避免直接比较浮点数是否相等，可以使用一个小的误差范围进行比较。

6. **对 `NaN` 的误解:**

   ```javascript
   console.log(NaN == NaN); // 输出 false
   console.log(NaN === NaN); // 输出 false
   ```
   **建议:**  使用 `isNaN()` 来判断一个值是否是 `NaN`。

总而言之，`v8/src/builtins/number.tq` 文件是 V8 引擎中实现 JavaScript `Number` 对象核心功能的关键组成部分，它涉及到数字的表示、转换和运算等底层操作。理解这个文件的内容有助于深入了解 JavaScript 数字类型的工作原理。

Prompt: 
```
这是目录为v8/src/builtins/number.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved. Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

#include 'src/ic/binary-op-assembler.h'

extern enum Operation extends uint31 {
  // Binary operations.
  kAdd,
  kSubtract,
  kMultiply,
  kDivide,
  kModulus,
  kExponentiate,
  kBitwiseAnd,
  kBitwiseOr,
  kBitwiseXor,
  kShiftLeft,
  kShiftRight,
  kShiftRightLogical,
  // Unary operations.
  kBitwiseNot,
  kNegate,
  kIncrement,
  kDecrement,
  // Compare operations.
  kEqual,
  kStrictEqual,
  kLessThan,
  kLessThanOrEqual,
  kGreaterThan,
  kGreaterThanOrEqual
}

namespace runtime {
extern transitioning runtime DoubleToStringWithRadix(
    implicit context: Context)(Number, Number): String;

extern transitioning runtime StringParseFloat(
    implicit context: Context)(String): Number;
extern transitioning runtime StringParseInt(
    implicit context: Context)(JSAny, JSAny): Number;

extern runtime BigIntUnaryOp(Context, BigInt, SmiTagged<Operation>): BigInt;
extern runtime BigIntExponentiate(Context, Numeric, Numeric): BigInt;
}  // namespace runtime

namespace number {
extern macro NaNStringConstant(): String;
extern macro ZeroStringConstant(): String;
extern macro InfinityStringConstant(): String;
extern macro MinusInfinityStringConstant(): String;
extern macro Log10OffsetTable(): RawPtr<uint64>;

transitioning macro ThisNumberValue(
    implicit context: Context)(receiver: JSAny,
    method: constexpr string): Number {
  return UnsafeCast<Number>(
      ToThisValue(receiver, PrimitiveType::kNumber, method));
}

macro ToCharCode(input: uint32): char8 {
  dcheck(input < 36);
  // 48 == '0', 97 == 'a'.
  return input < 10 ? %RawDownCast<char8>(input + 48) :
                      %RawDownCast<char8>(input - 10 + 97);
}

macro IntToDecimalStringImpl(
    x: int32, log10OffsetsTable: RawPtr<uint64>,
    isPositive: constexpr bool): String {
  dcheck(isPositive == (x >= 0));
  let n: uint32 = isPositive ? Unsigned(x) : Unsigned(0 - x);
  const log2: int32 = 31 - math::Word32Clz(Signed(n) | 1);
  const tableEntry: uint64 = log10OffsetsTable[Convert<intptr>(log2)];
  const digitCount: uint64 = (Convert<uint64>(n) + tableEntry) >>> 32;
  let length = Convert<uint32>(digitCount);
  if constexpr (!isPositive) length++;  // For the '-'.
  const string = AllocateNonEmptySeqOneByteString(length);
  if constexpr (isPositive) {
    string.raw_hash_field = MakeArrayIndexHash(n, length);
  }
  const lengthIntptr = Convert<intptr>(Signed(length));
  let cursor: intptr = lengthIntptr - 1;
  const rawChars = &string.chars;
  while (true) {
    const kInverse: uint64 = 0xcccccccd;
    const quotient = Convert<uint32>((Convert<uint64>(n) * kInverse) >>> 35);
    const remainder = n - quotient * 10;
    const nextChar = %RawDownCast<char8>(remainder | 48);  // 48 == '0'
    // Writing to string.chars[cursor] directly would implicitly emit a
    // bounds check, and we don't want no bounds check, thank you very much.
    *UnsafeConstCast(rawChars.UncheckedAtIndex(cursor)) = nextChar;
    cursor--;
    n = quotient;
    if (n == 0) break;
  }
  if constexpr (!isPositive) {
    *UnsafeConstCast(rawChars.UncheckedAtIndex(0)) = 45;  // 45 == '-'
  }
  return string;
}

@export
macro IntToDecimalString(x: int32): String {
  if constexpr (Is64()) {
    const log10OffsetsTable: RawPtr<uint64> = Log10OffsetTable();
    if (x >= 0) {
      if (x < 10) {
        if (x == 0) {
          return ZeroStringConstant();
        }
        return StringFromSingleCharCode(ToCharCode(Unsigned(x)));
      }
      return IntToDecimalStringImpl(x, log10OffsetsTable, true);
    } else {
      return IntToDecimalStringImpl(x, log10OffsetsTable, false);
    }
  } else {
    // The generic implementation doesn't rely on 64-bit instructions.
    return IntToString(x, 10);
  }
}

macro IntToString(x: int32, radix: uint32): String {
  if constexpr (Is64()) {
    dcheck(radix != 10);  // Use IntToDecimalString otherwise.
  }
  const isNegative: bool = x < 0;
  let n: uint32;
  if (!isNegative) {
    // Fast case where the result is a one character string.
    n = Unsigned(x);
    if (n < radix) {
      if (n == 0) {
        return ZeroStringConstant();
      }
      return StringFromSingleCharCode(ToCharCode(n));
    }
  } else {
    dcheck(isNegative);
    n = Unsigned(0 - x);
  }

  // Calculate length and pre-allocate the result string.
  let temp: uint32 = n;
  let length: int32 = isNegative ? Convert<int32>(1) : Convert<int32>(0);
  while (temp > 0) {
    temp = temp / radix;
    length = length + 1;
  }
  dcheck(length > 0);
  const strSeq = AllocateNonEmptySeqOneByteString(Unsigned(length));
  let cursor: intptr = Convert<intptr>(length) - 1;
  while (n > 0) {
    const digit: uint32 = n % radix;
    n = n / radix;
    *UnsafeConstCast(&strSeq.chars[cursor]) = ToCharCode(digit);
    cursor = cursor - 1;
  }
  if (isNegative) {
    dcheck(cursor == 0);
    // Insert '-' to result.
    *UnsafeConstCast(&strSeq.chars[0]) = 45;
  } else {
    dcheck(cursor == -1);
    if constexpr (!Is64()) {
      if (radix == 10) {
        dcheck(strSeq.raw_hash_field == kNameEmptyHashField);
        strSeq.raw_hash_field =
            MakeArrayIndexHash(Unsigned(x), Unsigned(length));
      }
    }
  }
  return strSeq;
}

// https://tc39.github.io/ecma262/#sec-number.prototype.tostring
transitioning javascript builtin NumberPrototypeToString(
    js-implicit context: NativeContext, receiver: JSAny)(
    ...arguments): String {
  // 1. Let x be ? thisNumberValue(this value).
  const x = ThisNumberValue(receiver, 'Number.prototype.toString');

  // 2. If radix is not present, let radixNumber be 10.
  // 3. Else if radix is undefined, let radixNumber be 10.
  // 4. Else, let radixNumber be ? ToInteger(radix).
  const radix: JSAny = arguments[0];
  const radixNumber: Number = radix == Undefined ? 10 : ToInteger_Inline(radix);

  // 5. If radixNumber < 2 or radixNumber > 36, throw a RangeError exception.
  if (radixNumber < 2 || radixNumber > 36) {
    ThrowRangeError(MessageTemplate::kToRadixFormatRange);
  }

  // 6. If radixNumber = 10, return ! ToString(x).
  if (radixNumber == 10) {
    return NumberToString(x);
  }

  // 7. Return the String representation of this Number
  //    value using the radix specified by radixNumber.

  if (TaggedIsSmi(x)) {
    return IntToString(
        Convert<int32>(x), Unsigned(Convert<int32>(radixNumber)));
  }

  if (x == -0) {
    return ZeroStringConstant();
  } else if (::NumberIsNaN(x)) {
    return NaNStringConstant();
  } else if (x == V8_INFINITY) {
    return InfinityStringConstant();
  } else if (x == MINUS_V8_INFINITY) {
    return MinusInfinityStringConstant();
  }

  return runtime::DoubleToStringWithRadix(x, radixNumber);
}

// ES6 #sec-number.isfinite
javascript builtin NumberIsFinite(
    js-implicit context: NativeContext, receiver: JSAny)(
    value: JSAny): Boolean {
  typeswitch (value) {
    case (Smi): {
      return True;
    }
    case (h: HeapNumber): {
      const number: float64 = Convert<float64>(h);
      const infiniteOrNaN: bool = Float64IsNaN(number - number);
      return Convert<Boolean>(!infiniteOrNaN);
    }
    case (JSAnyNotNumber): {
      return False;
    }
  }
}

// ES6 #sec-number.isinteger
javascript builtin NumberIsInteger(
    js-implicit context: NativeContext)(value: JSAny): Boolean {
  return SelectBooleanConstant(IsInteger(value));
}

// ES6 #sec-number.isnan
javascript builtin NumberIsNaN(
    js-implicit context: NativeContext)(value: JSAny): Boolean {
  typeswitch (value) {
    case (Smi): {
      return False;
    }
    case (h: HeapNumber): {
      const number: float64 = Convert<float64>(h);
      return Convert<Boolean>(Float64IsNaN(number));
    }
    case (JSAnyNotNumber): {
      return False;
    }
  }
}

// ES6 #sec-number.issafeinteger
javascript builtin NumberIsSafeInteger(
    js-implicit context: NativeContext)(value: JSAny): Boolean {
  return SelectBooleanConstant(IsSafeInteger(value));
}

// ES6 #sec-number.prototype.valueof
transitioning javascript builtin NumberPrototypeValueOf(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return ToThisValue(
      receiver, PrimitiveType::kNumber, 'Number.prototype.valueOf');
}

// ES6 #sec-number.parsefloat
transitioning javascript builtin NumberParseFloat(
    js-implicit context: NativeContext)(value: JSAny): Number {
  try {
    typeswitch (value) {
      case (s: Smi): {
        return s;
      }
      case (h: HeapNumber): {
        // The input is already a Number. Take care of -0.
        // The sense of comparison is important for the NaN case.
        return (Convert<float64>(h) == 0) ? SmiConstant(0) : h;
      }
      case (s: String): {
        goto String(s);
      }
      case (HeapObject): {
        goto String(string::ToString(context, value));
      }
    }
  } label String(s: String) {
    // Check if the string is a cached array index.
    const hash: NameHash = s.raw_hash_field;
    if (IsIntegerIndex(hash) &&
        hash.array_index_length < kMaxCachedArrayIndexLength) {
      const arrayIndex: uint32 = hash.array_index_value;
      return SmiFromUint32(arrayIndex);
    }
    // Fall back to the runtime to convert string to a number.
    return runtime::StringParseFloat(s);
  }
}

extern macro TruncateFloat64ToWord32(float64): uint32;

transitioning builtin ParseInt(
    implicit context: Context)(input: JSAny, radix: JSAny): Number {
  try {
    // Check if radix should be 10 (i.e. undefined, 0 or 10).
    if (radix != Undefined && !TaggedEqual(radix, SmiConstant(10)) &&
        !TaggedEqual(radix, SmiConstant(0))) {
      goto CallRuntime;
    }

    typeswitch (input) {
      case (s: Smi): {
        return s;
      }
      case (h: HeapNumber): {
        // Check if the input value is in Signed32 range.
        const asFloat64: float64 = Convert<float64>(h);
        const asInt32: int32 = Signed(TruncateFloat64ToWord32(asFloat64));
        // The sense of comparison is important for the NaN case.
        if (asFloat64 == ChangeInt32ToFloat64(asInt32)) goto Int32(asInt32);

        // Check if the absolute value of input is in the [1,1<<31[ range. Call
        // the runtime for the range [0,1[ because the result could be -0.
        const kMaxAbsValue: float64 = 2147483648.0;
        const absInput: float64 = math::Float64Abs(asFloat64);
        if (absInput < kMaxAbsValue && absInput >= 1.0) goto Int32(asInt32);
        goto CallRuntime;
      }
      case (s: String): {
        goto String(s);
      }
      case (HeapObject): {
        goto CallRuntime;
      }
    }
  } label Int32(i: int32) {
    return ChangeInt32ToTagged(i);
  } label String(s: String) {
    // Check if the string is a cached array index.
    const hash: NameHash = s.raw_hash_field;
    if (IsIntegerIndex(hash) &&
        hash.array_index_length < kMaxCachedArrayIndexLength) {
      const arrayIndex: uint32 = hash.array_index_value;
      return SmiFromUint32(arrayIndex);
    }
    // Fall back to the runtime.
    goto CallRuntime;
  } label CallRuntime {
    tail runtime::StringParseInt(input, radix);
  }
}

// ES6 #sec-number.parseint
transitioning javascript builtin NumberParseInt(
    js-implicit context: NativeContext)(value: JSAny, radix: JSAny): Number {
  return ParseInt(value, radix);
}

extern builtin NonNumberToNumeric(implicit context: Context)(JSAny): Numeric;
extern builtin Subtract(implicit context: Context)(Number, Number): Number;
extern builtin Add(implicit context: Context)(Number, Number): Number;
extern builtin StringAddConvertLeft(implicit context: Context)(JSAny, String):
    JSAny;
extern builtin StringAddConvertRight(implicit context: Context)(String, JSAny):
    JSAny;

extern macro BitwiseOp(int32, int32, constexpr Operation): Number;
extern macro RelationalComparison(constexpr Operation, JSAny, JSAny, Context):
    Boolean;
extern macro TruncateNumberToWord32(Number): int32;

// TODO(bbudge) Use a simpler macro structure that doesn't loop when converting
// non-numbers, if such a code sequence doesn't make the builtin bigger.

transitioning macro ToNumericOrPrimitive(
    implicit context: Context)(value: JSAny): JSAny {
  typeswitch (value) {
    case (v: JSReceiver): {
      return NonPrimitiveToPrimitive_Default(context, v);
    }
    case (v: JSPrimitive): {
      return NonNumberToNumeric(v);
    }
  }
}

transitioning builtin Add(
    implicit context: Context)(leftArg: JSAny, rightArg: JSAny): JSAny {
  let left: JSAny = leftArg;
  let right: JSAny = rightArg;
  try {
    while (true) {
      typeswitch (left) {
        case (left: Smi): {
          typeswitch (right) {
            case (right: Smi): {
              return math::TrySmiAdd(left, right) otherwise goto Float64s(
                  SmiToFloat64(left), SmiToFloat64(right));
            }
            case (right: HeapNumber): {
              goto Float64s(SmiToFloat64(left), Convert<float64>(right));
            }
            case (right: BigInt): {
              goto Numerics(left, right);
            }
            case (right: String): {
              goto StringAddConvertLeft(left, right);
            }
            case (HeapObject): {
              right = ToNumericOrPrimitive(right);
              continue;
            }
          }
        }
        case (left: HeapNumber): {
          typeswitch (right) {
            case (right: Smi): {
              goto Float64s(Convert<float64>(left), SmiToFloat64(right));
            }
            case (right: HeapNumber): {
              goto Float64s(Convert<float64>(left), Convert<float64>(right));
            }
            case (right: BigInt): {
              goto Numerics(left, right);
            }
            case (right: String): {
              goto StringAddConvertLeft(left, right);
            }
            case (HeapObject): {
              right = ToNumericOrPrimitive(right);
              continue;
            }
          }
        }
        case (left: BigInt): {
          typeswitch (right) {
            case (right: Numeric): {
              goto Numerics(left, right);
            }
            case (right: String): {
              goto StringAddConvertLeft(left, right);
            }
            case (HeapObject): {
              right = ToNumericOrPrimitive(right);
              continue;
            }
          }
        }
        case (left: String): {
          goto StringAddConvertRight(left, right);
        }
        case (leftReceiver: JSReceiver): {
          left = ToPrimitiveDefault(leftReceiver);
        }
        case (HeapObject): {
          // left: HeapObject
          typeswitch (right) {
            case (right: String): {
              goto StringAddConvertLeft(left, right);
            }
            case (rightReceiver: JSReceiver): {
              // left is JSPrimitive and right is JSReceiver, convert right
              // with priority.
              right = ToPrimitiveDefault(rightReceiver);
              continue;
            }
            case (JSPrimitive): {
              // Neither left or right is JSReceiver, convert left.
              left = NonNumberToNumeric(left);
              continue;
            }
          }
        }
      }
    }
  } label StringAddConvertLeft(left: JSAny, right: String) {
    tail StringAddConvertLeft(left, right);
  } label StringAddConvertRight(left: String, right: JSAny) {
    tail StringAddConvertRight(left, right);
  } label Numerics(left: Numeric, right: Numeric) {
    tail bigint::BigIntAdd(left, right);
  } label Float64s(left: float64, right: float64) {
    return AllocateHeapNumberWithValue(left + right);
  }
  unreachable;
}

// Unary type switch on Number | BigInt.
macro UnaryOp1(implicit context: Context)(value: JSAny): never labels
Number(Number), BigInt(BigInt) {
  let x: JSAny = value;
  while (true) {
    typeswitch (x) {
      case (n: Number): {
        goto Number(n);
      }
      case (b: BigInt): {
        goto BigInt(b);
      }
      case (JSAnyNotNumeric): {
        x = NonNumberToNumeric(x);
      }
    }
  }
  unreachable;
}

// Unary type switch on Smi | HeapNumber | BigInt.
macro UnaryOp2(implicit context: Context)(value: JSAny): never labels
Smi(Smi), HeapNumber(HeapNumber), BigInt(BigInt) {
  let x: JSAny = value;
  while (true) {
    typeswitch (x) {
      case (s: Smi): {
        goto Smi(s);
      }
      case (h: HeapNumber): {
        goto HeapNumber(h);
      }
      case (b: BigInt): {
        goto BigInt(b);
      }
      case (JSAnyNotNumeric): {
        x = NonNumberToNumeric(x);
      }
    }
  }
  unreachable;
}

// Binary type switch on Number | BigInt.
macro BinaryOp1(implicit context: Context)(leftVal: JSAny, rightVal: JSAny):
    never labels
Number(Number, Number), AtLeastOneBigInt(Numeric, Numeric) {
  let left: JSAny = leftVal;
  let right: JSAny = rightVal;
  while (true) {
    try {
      typeswitch (left) {
        case (left: Number): {
          typeswitch (right) {
            case (right: Number): {
              goto Number(left, right);
            }
            case (right: BigInt): {
              goto AtLeastOneBigInt(left, right);
            }
            case (JSAnyNotNumeric): {
              goto RightNotNumeric;
            }
          }
        }
        case (left: BigInt): {
          typeswitch (right) {
            case (right: Numeric): {
              goto AtLeastOneBigInt(left, right);
            }
            case (JSAnyNotNumeric): {
              goto RightNotNumeric;
            }
          }
        }
        case (JSAnyNotNumeric): {
          left = NonNumberToNumeric(left);
        }
      }
    } label RightNotNumeric {
      right = NonNumberToNumeric(right);
    }
  }
  unreachable;
}

// Binary type switch on Smi | HeapNumber | BigInt.
macro BinaryOp2(implicit context: Context)(leftVal: JSAny, rightVal: JSAny):
    never labels Smis(Smi, Smi), Float64s(float64, float64),
    AtLeastOneBigInt(Numeric, Numeric) {
  let left: JSAny = leftVal;
  let right: JSAny = rightVal;
  while (true) {
    try {
      typeswitch (left) {
        case (left: Smi): {
          typeswitch (right) {
            case (right: Smi): {
              goto Smis(left, right);
            }
            case (right: HeapNumber): {
              goto Float64s(SmiToFloat64(left), Convert<float64>(right));
            }
            case (right: BigInt): {
              goto AtLeastOneBigInt(left, right);
            }
            case (JSAnyNotNumeric): {
              goto RightNotNumeric;
            }
          }
        }
        case (left: HeapNumber): {
          typeswitch (right) {
            case (right: Smi): {
              goto Float64s(Convert<float64>(left), SmiToFloat64(right));
            }
            case (right: HeapNumber): {
              goto Float64s(Convert<float64>(left), Convert<float64>(right));
            }
            case (right: BigInt): {
              goto AtLeastOneBigInt(left, right);
            }
            case (JSAnyNotNumeric): {
              goto RightNotNumeric;
            }
          }
        }
        case (left: BigInt): {
          typeswitch (right) {
            case (right: Numeric): {
              goto AtLeastOneBigInt(left, right);
            }
            case (JSAnyNotNumeric): {
              goto RightNotNumeric;
            }
          }
        }
        case (JSAnyNotNumeric): {
          left = NonNumberToNumeric(left);
        }
      }
    } label RightNotNumeric {
      right = NonNumberToNumeric(right);
    }
  }
  unreachable;
}

builtin Subtract(implicit context: Context)(left: JSAny, right: JSAny):
    Numeric {
  try {
    BinaryOp2(left, right) otherwise Smis, Float64s, AtLeastOneBigInt;
  } label Smis(left: Smi, right: Smi) {
    try {
      return math::TrySmiSub(left, right) otherwise Overflow;
    } label Overflow {
      goto Float64s(SmiToFloat64(left), SmiToFloat64(right));
    }
  } label Float64s(left: float64, right: float64) {
    return AllocateHeapNumberWithValue(left - right);
  } label AtLeastOneBigInt(left: Numeric, right: Numeric) {
    tail bigint::BigIntSubtract(left, right);
  }
}

builtin Multiply(implicit context: Context)(left: JSAny, right: JSAny):
    Numeric {
  try {
    BinaryOp2(left, right) otherwise Smis, Float64s, AtLeastOneBigInt;
  } label Smis(left: Smi, right: Smi) {
    // The result is not necessarily a smi, in case of overflow.
    return SmiMul(left, right);
  } label Float64s(left: float64, right: float64) {
    return AllocateHeapNumberWithValue(left * right);
  } label AtLeastOneBigInt(left: Numeric, right: Numeric) {
    tail bigint::BigIntMultiply(left, right);
  }
}

const kSmiValueSize: constexpr int32 generates 'kSmiValueSize';
const kMinInt32: constexpr int32 generates 'kMinInt';
const kMinInt31: constexpr int32 generates 'kMinInt31';
const kMinimumDividend: int32 = (kSmiValueSize == 32) ? kMinInt32 : kMinInt31;

builtin Divide(implicit context: Context)(left: JSAny, right: JSAny):
    Numeric {
  try {
    BinaryOp2(left, right) otherwise Smis, Float64s, AtLeastOneBigInt;
  } label Smis(left: Smi, right: Smi) {
    // TODO(jkummerow): Consider just always doing a double division.
    // Bail out if {divisor} is zero.
    if (right == 0) goto SmiBailout(left, right);

    // Bail out if dividend is zero and divisor is negative.
    if (left == 0 && right < 0) goto SmiBailout(left, right);

    const dividend: int32 = SmiToInt32(left);
    const divisor: int32 = SmiToInt32(right);

    // Bail out if dividend is kMinInt31 (or kMinInt32 if Smis are 32 bits)
    // and divisor is -1.
    if (divisor == -1 && dividend == kMinimumDividend) {
      goto SmiBailout(left, right);
    }
    // TODO(epertoso): consider adding a machine instruction that returns
    // both the result and the remainder.
    const result: int32 = dividend / divisor;
    const truncated: int32 = result * divisor;
    if (dividend != truncated) goto SmiBailout(left, right);
    return SmiFromInt32(result);
  } label SmiBailout(left: Smi, right: Smi) {
    goto Float64s(SmiToFloat64(left), SmiToFloat64(right));
  } label Float64s(left: float64, right: float64) {
    return AllocateHeapNumberWithValue(left / right);
  } label AtLeastOneBigInt(left: Numeric, right: Numeric) {
    tail bigint::BigIntDivide(left, right);
  }
}

builtin Modulus(implicit context: Context)(left: JSAny, right: JSAny):
    Numeric {
  try {
    BinaryOp2(left, right) otherwise Smis, Float64s, AtLeastOneBigInt;
  } label Smis(left: Smi, right: Smi) {
    return SmiMod(left, right);
  } label Float64s(left: float64, right: float64) {
    return AllocateHeapNumberWithValue(left % right);
  } label AtLeastOneBigInt(left: Numeric, right: Numeric) {
    tail bigint::BigIntModulus(left, right);
  }
}

builtin Exponentiate(implicit context: Context)(left: JSAny, right: JSAny):
    Numeric {
  try {
    BinaryOp1(left, right) otherwise Numbers, AtLeastOneBigInt;
  } label Numbers(left: Number, right: Number) {
    return math::MathPowImpl(left, right);
  } label AtLeastOneBigInt(left: Numeric, right: Numeric) {
    tail runtime::BigIntExponentiate(context, left, right);
  }
}

builtin Negate(implicit context: Context)(value: JSAny): Numeric {
  try {
    UnaryOp2(value) otherwise Smi, HeapNumber, BigInt;
  } label Smi(s: Smi) {
    return SmiMul(s, -1);
  } label HeapNumber(h: HeapNumber) {
    return AllocateHeapNumberWithValue(Convert<float64>(h) * -1.0);
  } label BigInt(b: BigInt) {
    tail runtime::BigIntUnaryOp(
        context, b, SmiTag<Operation>(Operation::kNegate));
  }
}

builtin BitwiseNot(implicit context: Context)(value: JSAny): Numeric {
  try {
    UnaryOp1(value) otherwise Number, BigInt;
  } label Number(n: Number) {
    return BitwiseOp(TruncateNumberToWord32(n), -1, Operation::kBitwiseXor);
  } label BigInt(b: BigInt) {
    return runtime::BigIntUnaryOp(
        context, b, SmiTag<Operation>(Operation::kBitwiseNot));
  }
}

builtin Decrement(implicit context: Context)(value: JSAny): Numeric {
  try {
    UnaryOp1(value) otherwise Number, BigInt;
  } label Number(n: Number) {
    tail Subtract(n, 1);
  } label BigInt(b: BigInt) {
    return runtime::BigIntUnaryOp(
        context, b, SmiTag<Operation>(Operation::kDecrement));
  }
}

builtin Increment(implicit context: Context)(value: JSAny): Numeric {
  try {
    UnaryOp1(value) otherwise Number, BigInt;
  } label Number(n: Number) {
    tail Add(n, 1);
  } label BigInt(b: BigInt) {
    return runtime::BigIntUnaryOp(
        context, b, SmiTag<Operation>(Operation::kIncrement));
  }
}

// Bitwise binary operations.

extern macro BinaryOpAssembler::Generate_BitwiseBinaryOp(
    constexpr Operation, JSAny, JSAny, Context): Object;

builtin ShiftLeft(implicit context: Context)(left: JSAny, right: JSAny):
    Object {
  return Generate_BitwiseBinaryOp(Operation::kShiftLeft, left, right, context);
}

builtin ShiftRight(implicit context: Context)(left: JSAny, right: JSAny):
    Object {
  return Generate_BitwiseBinaryOp(Operation::kShiftRight, left, right, context);
}

builtin ShiftRightLogical(
    implicit context: Context)(left: JSAny, right: JSAny): Object {
  return Generate_BitwiseBinaryOp(
      Operation::kShiftRightLogical, left, right, context);
}

builtin BitwiseAnd(implicit context: Context)(left: JSAny, right: JSAny):
    Numeric {
  try {
    BinaryOp1(left, right) otherwise Number, AtLeastOneBigInt;
  } label Number(left: Number, right: Number) {
    return BitwiseOp(
        TruncateNumberToWord32(left), TruncateNumberToWord32(right),
        Operation::kBitwiseAnd);
  } label AtLeastOneBigInt(left: Numeric, right: Numeric) {
    tail bigint::BigIntBitwiseAnd(left, right);
  }
}

builtin BitwiseOr(implicit context: Context)(left: JSAny, right: JSAny):
    Numeric {
  try {
    BinaryOp1(left, right) otherwise Number, AtLeastOneBigInt;
  } label Number(left: Number, right: Number) {
    return BitwiseOp(
        TruncateNumberToWord32(left), TruncateNumberToWord32(right),
        Operation::kBitwiseOr);
  } label AtLeastOneBigInt(left: Numeric, right: Numeric) {
    tail bigint::BigIntBitwiseOr(left, right);
  }
}

builtin BitwiseXor(implicit context: Context)(left: JSAny, right: JSAny):
    Numeric {
  try {
    BinaryOp1(left, right) otherwise Number, AtLeastOneBigInt;
  } label Number(left: Number, right: Number) {
    return BitwiseOp(
        TruncateNumberToWord32(left), TruncateNumberToWord32(right),
        Operation::kBitwiseXor);
  } label AtLeastOneBigInt(left: Numeric, right: Numeric) {
    tail bigint::BigIntBitwiseXor(left, right);
  }
}

// Relational builtins.

builtin LessThan(implicit context: Context)(left: JSAny, right: JSAny):
    Object {
  return RelationalComparison(Operation::kLessThan, left, right, context);
}

builtin LessThanOrEqual(implicit context: Context)(left: JSAny, right: JSAny):
    Object {
  return RelationalComparison(
      Operation::kLessThanOrEqual, left, right, context);
}

builtin GreaterThan(implicit context: Context)(left: JSAny, right: JSAny):
    Object {
  return RelationalComparison(Operation::kGreaterThan, left, right, context);
}

builtin GreaterThanOrEqual(
    implicit context: Context)(left: JSAny, right: JSAny): Object {
  return RelationalComparison(
      Operation::kGreaterThanOrEqual, left, right, context);
}

builtin Equal(implicit context: Context)(left: JSAny, right: JSAny): Object {
  return Equal(left, right, context);
}

builtin StrictEqual(implicit context: Context)(left: JSAny, right: JSAny):
    Object {
  return ::StrictEqual(left, right);
}

}  // namespace number

"""

```