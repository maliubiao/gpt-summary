Response: Let's break down the thought process to analyze the given Torque code for BigInt builtins.

1. **Understand the Goal:** The core task is to analyze a V8 Torque source file related to BigInts and summarize its functionality, relate it to JavaScript, provide examples, and highlight common errors.

2. **Initial Scan for Key Information:**  First, read through the code to get a high-level understanding. Look for:
    * **Copyright and License:** Standard boilerplate, noting the project and license.
    * **Includes:**  `'src/builtins/builtins-bigint-gen.h'` suggests code generation or shared definitions.
    * **Namespace:** `namespace bigint` clearly defines the scope.
    * **Constants:** `kPositiveSign`, `kNegativeSign`, `kGreaterThan`, `kLessThan`, `kMustRoundDownBitShift` hint at internal representations and comparison logic.
    * **`extern macro` declarations:** These are crucial. They indicate calls to C++ implementations for core BigInt operations. This is a key point: Torque is defining the *interface* and high-level logic, while C++ handles the heavy lifting of arbitrary-precision arithmetic. List these out: `CppAbsoluteAddAndCanonicalize`, `CppAbsoluteSubAndCanonicalize`, etc.
    * **`macro` definitions:** These are Torque functions. Focus on their names and parameters to understand their purpose (e.g., `IsCanonicalized`, `InvertSign`, `AllocateEmptyBigInt`, `MutableBigIntAbsoluteCompare`).
    * **`builtin` definitions:** These are the externally visible functions that directly correspond to JavaScript BigInt operations. These are the most important for relating back to JavaScript. Notice the `NoThrow` variants – this indicates error handling strategies.

3. **Categorize Functionality:** Group the `builtin` functions by the JavaScript BigInt operations they implement. This will form the basis of the functionality summary:
    * **Arithmetic:** `BigIntAdd`, `BigIntSubtract`, `BigIntMultiply`, `BigIntDivide`, `BigIntModulus`
    * **Bitwise:** `BigIntBitwiseAnd`, `BigIntBitwiseOr`, `BigIntBitwiseXor`, `BigIntShiftLeft`, `BigIntShiftRight`
    * **Comparison:** `BigIntEqual`, `BigIntLessThan`, `BigIntGreaterThan`, `BigIntLessThanOrEqual`, `BigIntGreaterThanOrEqual`
    * **Unary:** `BigIntUnaryMinus`

4. **Explain Core Concepts:**
    * **Canonicalization:** The `IsCanonicalized` macro and the use of "Canonicalize" in the C++ macro names suggest an important optimization or normalization step. Explain what this means for BigInt representation (no leading zeros).
    * **Sign and Length:**  The `ReadBigIntSign`, `ReadBigIntLength`, and `WriteBigIntSignAndLength` macros highlight the internal representation of BigInts.
    * **Allocation:**  The `AllocateBigInt` and `AllocateRawBigInt` macros indicate memory management. The `NoThrow` variants and the associated error handling (e.g., `BigIntTooBig`) are important.

5. **Relate to JavaScript:** For each category of `builtin` functions, provide corresponding JavaScript examples. This directly connects the low-level Torque code to the user-facing JavaScript API.

6. **Identify Code Logic and Provide Examples:** Look for interesting logic within the `macro` and `builtin` functions. Focus on:
    * **Sign handling:** How are positive and negative BigInts treated differently in arithmetic and bitwise operations?
    * **Zero handling:**  Pay attention to the special cases for zero (`length == 0`).
    * **Comparison logic:** The `BigIntCompareAbsolute` and `BigIntCompare` macros show how comparisons are implemented.
    * **Shift operations:** The logic for left and right shifts, including handling large shifts and negative shift amounts, is worth noting.
    * **Error handling:** The `try...otherwise` blocks and the `BigIntTooBig` and `BigIntDivZero` labels demonstrate how exceptions are managed.

    For these logical points, create simple "assume input, expect output" examples. Don't need to trace every single bit, but illustrate the core behavior.

7. **Identify Common Programming Errors:** Think about how users might misuse BigInts in JavaScript. Common errors related to the functionality in the code include:
    * **Mixing BigInts with other types:** The `MixedTypes` label and `ThrowTypeError` highlight this.
    * **Dividing by zero:** The `BigIntDivZero` label and `ThrowRangeError` are key here.
    * **Creating very large BigInts:** The `BigIntTooBig` label and `ThrowRangeError` point to potential overflow issues.
    * **Incorrect assumptions about bitwise operations on negative numbers:** This is a subtle area where understanding the two's complement representation is important.

8. **Structure the Output:** Organize the analysis logically with clear headings and bullet points. Start with a general summary, then delve into specific aspects like JavaScript examples, code logic, and common errors.

9. **Refine and Review:** Read through the analysis to ensure clarity, accuracy, and completeness. Check for any inconsistencies or missing information. For example, initially, I might have missed the significance of the `NoThrow` variants and their relation to returning Smi sentinels. Reviewing the code would reveal this. Also, double-check the JavaScript examples for correctness.

This step-by-step approach helps to systematically analyze the code and extract the relevant information needed to answer the prompt effectively. The key is to understand the relationship between the low-level Torque implementation and the high-level JavaScript API for BigInts.
这个v8 Torque 源代码文件 `builtins-bigint.tq` 定义了 **BigInt** 在 V8 JavaScript 引擎中的内置操作的实现。它使用 Torque 语言来描述这些操作的底层逻辑。

**功能归纳:**

该文件主要负责实现 JavaScript 中 `BigInt` 类型的各种算术、位运算和比较操作。 具体来说，它定义了以下功能：

1. **基本算术运算:**
   - 加法 (`+`)
   - 减法 (`-`)
   - 乘法 (`*`)
   - 除法 (`/`)
   - 取模 (`%`)

2. **位运算:**
   - 按位与 (`&`)
   - 按位或 (`|`)
   - 按位异或 (`^`)
   - 左移 (`<<`)
   - 右移 (`>>`)

3. **比较运算:**
   - 相等 (`==`)
   - 小于 (`<`)
   - 大于 (`>`)
   - 小于等于 (`<=`)
   - 大于等于 (`>=`)

4. **一元运算:**
   - 一元负号 (`-`)

5. **内部辅助功能:**
   - BigInt 的内存分配和管理。
   - BigInt 的符号和长度的读取和写入。
   - 绝对值比较和运算。
   - BigInt 的规范化表示（去除前导零）。

**与 JavaScript 功能的关系及举例:**

该文件中的每个 `builtin` 函数都对应着 JavaScript 中 `BigInt` 对象上的一个操作符或方法。

| Torque Builtin 函数     | JavaScript 操作符/方法 | 示例                                  |
|--------------------------|------------------------|---------------------------------------|
| `BigIntAdd`              | `+`                    | `10n + 5n`                            |
| `BigIntSubtract`         | `-`                    | `100n - 20n`                          |
| `BigIntMultiply`         | `*`                    | `5n * 3n`                             |
| `BigIntDivide`           | `/`                    | `10n / 3n`                            |
| `BigIntModulus`          | `%`                    | `10n % 3n`                            |
| `BigIntBitwiseAnd`       | `&`                    | `15n & 9n`                            |
| `BigIntBitwiseOr`        | `|`                    | `15n | 9n`                            |
| `BigIntBitwiseXor`       | `^`                    | `15n ^ 9n`                            |
| `BigIntShiftLeft`        | `<<`                   | `5n << 2n`                            |
| `BigIntShiftRight`       | `>>`                   | `16n >> 2n`                           |
| `BigIntEqual`            | `==`                   | `10n == 10n`                          |
| `BigIntLessThan`         | `<`                    | `5n < 10n`                            |
| `BigIntGreaterThan`      | `>`                    | `100n > 50n`                          |
| `BigIntLessThanOrEqual`  | `<=`                   | `7n <= 7n`                            |
| `BigIntGreaterThanOrEqual`| `>=`                   | `12n >= 10n`                          |
| `BigIntUnaryMinus`       | `-` (一元)              | `-5n`                                 |

**代码逻辑推理及假设输入与输出:**

以 `BigIntAddImpl` 函数为例，它实现了 BigInt 的加法。

**假设输入:**

- `x`: 一个 BigInt 对象，假设值为 `12345678901234567890n`
- `y`: 一个 BigInt 对象，假设值为 `98765432109876543210n`

**代码逻辑:**

1. 获取 `x` 和 `y` 的符号 (`xsign`, `ysign`)。
2. 如果符号相同，则进行绝对值加法 (`MutableBigIntAbsoluteAdd`)，结果的符号与输入相同。
3. 如果符号不同，则进行绝对值减法 (`MutableBigIntAbsoluteSub`)。比较 `x` 和 `y` 的绝对值，决定结果的符号。

**预期输出:**

- 由于 `x` 和 `y` 都是正数，所以执行绝对值加法。
- `MutableBigIntAbsoluteAdd` 会将两个 BigInt 的内部表示（例如，数字数组）相加。
- 最终返回一个新的 BigInt 对象，其值为 `12345678901234567890n + 98765432109876543210n = 111111111011111111100n`。

**假设输入与输出 (不同符号的情况):**

- `x`: `10n`
- `y`: `-5n`

**代码逻辑:**

1. `xsign` 为正，`ysign` 为负。
2. 进入符号不同的分支。
3. 比较 `x` 和 `y` 的绝对值：`|10n| > |-5n|`。
4. 执行 `MutableBigIntAbsoluteSub(x, y, xsign)`，即计算 `10n - 5n`，结果符号为正。

**预期输出:** `5n`

**涉及用户常见的编程错误:**

1. **混合 BigInt 和其他类型进行运算:**

   ```javascript
   let bigInt = 10n;
   let number = 5;
   // 错误：不能混合 BigInt 和 Number 进行运算
   // let result = bigInt + number;
   ```

   该文件中的 `BigIntAdd` 等 `builtin` 函数会检查输入是否都是 `BigInt` 类型，如果不是，则会抛出 `TypeError` (`ThrowTypeError(MessageTemplate::kBigIntMixedTypes);`)。

2. **BigInt 除以零:**

   ```javascript
   let bigInt = 10n;
   let zero = 0n;
   // 错误：BigInt 除以零会抛出 RangeError
   // let result = bigInt / zero;
   ```

   `BigIntDivideImpl` 和 `BigIntModulusImpl` 函数中会检查除数是否为零 (`ylength == 0`)，如果是，则会抛出 `RangeError` (`ThrowRangeError(MessageTemplate::kBigIntDivZero);`)。

3. **BigInt 运算结果超出范围 (理论上, 在当前 JavaScript 引擎实现中 BigInt 可以表示任意大的整数, 但内部实现仍然有资源限制):**

   虽然 JavaScript 的 BigInt 可以表示任意大小的整数，但在内部实现中，分配内存可能会遇到限制。 该文件中的 `AllocateEmptyBigIntNoThrow` 函数会检查分配的长度是否超过最大值 (`length > kBigIntMaxLength`)，如果超过，则会跳转到 `BigIntTooBig` 标签，最终可能抛出 `RangeError` (`ThrowRangeError(MessageTemplate::kBigIntTooBig);`)。 虽然用户不太可能直接触发这个错误，但在进行非常大量的计算时，内部可能会遇到此问题。

**总结:**

`builtins-bigint.tq` 文件是 V8 引擎中实现 JavaScript `BigInt` 功能的核心代码。它定义了各种 BigInt 操作的底层实现逻辑，并处理了可能的错误情况。理解这个文件有助于深入了解 JavaScript BigInt 的工作原理。

Prompt: 
```
这是目录为v8/src/builtins/builtins-bigint.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-bigint-gen.h'

namespace bigint {

const kPositiveSign: uint32 = 0;
const kNegativeSign: uint32 = 1;
const kGreaterThan: intptr = 1;
const kLessThan: intptr = -1;

const kMustRoundDownBitShift: uint32 = 30;

extern macro BigIntBuiltinsAssembler::CppAbsoluteAddAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppAbsoluteSubAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppAbsoluteMulAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): int32;
extern macro BigIntBuiltinsAssembler::CppAbsoluteDivAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): int32;
extern macro BigIntBuiltinsAssembler::CppAbsoluteModAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): int32;
extern macro BigIntBuiltinsAssembler::CppBitwiseAndPosPosAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppBitwiseAndNegNegAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppBitwiseAndPosNegAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppBitwiseOrPosPosAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppBitwiseOrNegNegAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppBitwiseOrPosNegAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppBitwiseXorPosPosAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppBitwiseXorNegNegAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppBitwiseXorPosNegAndCanonicalize(
    MutableBigInt, BigIntBase, BigIntBase): void;
extern macro BigIntBuiltinsAssembler::CppLeftShiftAndCanonicalize(
    MutableBigInt, BigIntBase, intptr): void;
extern macro BigIntBuiltinsAssembler::CppRightShiftResultLength(
    BigIntBase, uint32, intptr): uint32;
extern macro BigIntBuiltinsAssembler::CppRightShiftAndCanonicalize(
    MutableBigInt, BigIntBase, intptr, uint32): void;
extern macro BigIntBuiltinsAssembler::CppAbsoluteCompare(
    BigIntBase, BigIntBase): int32;

extern macro BigIntBuiltinsAssembler::ReadBigIntSign(BigIntBase): uint32;
extern macro BigIntBuiltinsAssembler::ReadBigIntLength(BigIntBase): intptr;
extern macro BigIntBuiltinsAssembler::WriteBigIntSignAndLength(
    MutableBigInt, uint32, intptr): void;

extern macro CodeStubAssembler::AllocateBigInt(intptr): MutableBigInt;
extern macro CodeStubAssembler::AllocateRawBigInt(intptr): MutableBigInt;
extern macro CodeStubAssembler::StoreBigIntDigit(
    MutableBigInt, intptr, uintptr): void;
extern macro CodeStubAssembler::LoadBigIntDigit(BigIntBase, intptr): uintptr;

macro IsCanonicalized(bigint: BigIntBase): bool {
  const length = ReadBigIntLength(bigint);

  if (length == 0) {
    return ReadBigIntSign(bigint) == kPositiveSign;
  }

  return LoadBigIntDigit(bigint, length - 1) != 0;
}

macro InvertSign(sign: uint32): uint32 {
  return sign == kPositiveSign ? kNegativeSign : kPositiveSign;
}

macro AllocateEmptyBigIntNoThrow(
    implicit context: Context)(sign: uint32,
    length: intptr): MutableBigInt labels BigIntTooBig {
  if (length > kBigIntMaxLength) {
    goto BigIntTooBig;
  }
  const result: MutableBigInt = AllocateRawBigInt(length);

  WriteBigIntSignAndLength(result, sign, length);
  return result;
}

macro AllocateEmptyBigInt(
    implicit context: Context)(sign: uint32, length: intptr): MutableBigInt {
  try {
    return AllocateEmptyBigIntNoThrow(sign, length) otherwise BigIntTooBig;
  } label BigIntTooBig {
    ThrowRangeError(MessageTemplate::kBigIntTooBig);
  }
}

macro MutableBigIntAbsoluteCompare(x: BigIntBase, y: BigIntBase): int32 {
  return CppAbsoluteCompare(x, y);
}

macro MutableBigIntAbsoluteSub(
    implicit context: Context)(x: BigInt, y: BigInt,
    resultSign: uint32): BigInt {
  const xlength = ReadBigIntLength(x);
  const ylength = ReadBigIntLength(y);
  const xsign = ReadBigIntSign(x);

  dcheck(MutableBigIntAbsoluteCompare(x, y) >= 0);
  if (xlength == 0) {
    dcheck(ylength == 0);
    return x;
  }

  if (ylength == 0) {
    return resultSign == xsign ? x : BigIntUnaryMinus(x);
  }

  const result = AllocateEmptyBigInt(resultSign, xlength);
  CppAbsoluteSubAndCanonicalize(result, x, y);
  return Convert<BigInt>(result);
}

macro MutableBigIntAbsoluteAdd(
    implicit context: Context)(xBigint: BigInt, yBigint: BigInt,
    resultSign: uint32): BigInt labels BigIntTooBig {
  let xlength = ReadBigIntLength(xBigint);
  let ylength = ReadBigIntLength(yBigint);

  let x = xBigint;
  let y = yBigint;
  if (xlength < ylength) {
    // Swap x and y so that x is longer.
    x = yBigint;
    y = xBigint;
    const tempLength = xlength;
    xlength = ylength;
    ylength = tempLength;
  }

  // case: 0n + 0n
  if (xlength == 0) {
    dcheck(ylength == 0);
    return x;
  }

  // case: x + 0n
  if (ylength == 0) {
    return resultSign == ReadBigIntSign(x) ? x : BigIntUnaryMinus(x);
  }

  // case: x + y
  const result = AllocateEmptyBigIntNoThrow(resultSign, xlength + 1)
      otherwise BigIntTooBig;
  CppAbsoluteAddAndCanonicalize(result, x, y);
  return Convert<BigInt>(result);
}

macro BigIntAddImpl(implicit context: Context)(x: BigInt, y: BigInt): BigInt
    labels BigIntTooBig {
  const xsign = ReadBigIntSign(x);
  const ysign = ReadBigIntSign(y);
  if (xsign == ysign) {
    // x + y == x + y
    // -x + -y == -(x + y)
    return MutableBigIntAbsoluteAdd(x, y, xsign) otherwise BigIntTooBig;
  }

  // x + -y == x - y == -(y - x)
  // -x + y == y - x == -(x - y)
  if (MutableBigIntAbsoluteCompare(x, y) >= 0) {
    return MutableBigIntAbsoluteSub(x, y, xsign);
  }
  return MutableBigIntAbsoluteSub(y, x, InvertSign(xsign));
}

builtin BigIntAddNoThrow(implicit context: Context)(x: BigInt, y: BigInt):
    Numeric {
  try {
    return BigIntAddImpl(x, y) otherwise BigIntTooBig;
  } label BigIntTooBig {
    // Smi sentinal is used to signal BigIntTooBig exception.
    return Convert<Smi>(0);
  }
}

builtin BigIntAdd(implicit context: Context)(xNum: Numeric, yNum: Numeric):
    BigInt {
  try {
    const x = Cast<BigInt>(xNum) otherwise MixedTypes;
    const y = Cast<BigInt>(yNum) otherwise MixedTypes;

    return BigIntAddImpl(x, y) otherwise BigIntTooBig;
  } label MixedTypes {
    ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
  } label BigIntTooBig {
    ThrowRangeError(MessageTemplate::kBigIntTooBig);
  }
}

macro BigIntSubtractImpl(implicit context: Context)(x: BigInt, y: BigInt):
    BigInt labels BigIntTooBig {
  const xsign = ReadBigIntSign(x);
  const ysign = ReadBigIntSign(y);
  if (xsign != ysign) {
    // x - (-y) == x + y
    // (-x) - y == -(x + y)
    return MutableBigIntAbsoluteAdd(x, y, xsign) otherwise BigIntTooBig;
  }

  // x - y == -(y - x)
  // (-x) - (-y) == y - x == -(x - y)
  if (MutableBigIntAbsoluteCompare(x, y) >= 0) {
    return MutableBigIntAbsoluteSub(x, y, xsign);
  }
  return MutableBigIntAbsoluteSub(y, x, InvertSign(xsign));
}

builtin BigIntSubtractNoThrow(
    implicit context: Context)(x: BigInt, y: BigInt): Numeric {
  try {
    return BigIntSubtractImpl(x, y) otherwise BigIntTooBig;
  } label BigIntTooBig {
    // Smi sentinal is used to signal BigIntTooBig exception.
    return Convert<Smi>(0);
  }
}

builtin BigIntSubtract(
    implicit context: Context)(xNum: Numeric, yNum: Numeric): BigInt {
  try {
    const x = Cast<BigInt>(xNum) otherwise MixedTypes;
    const y = Cast<BigInt>(yNum) otherwise MixedTypes;

    return BigIntSubtractImpl(x, y) otherwise BigIntTooBig;
  } label MixedTypes {
    ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
  } label BigIntTooBig {
    ThrowRangeError(MessageTemplate::kBigIntTooBig);
  }
}

macro BigIntMultiplyImpl(implicit context: Context)(x: BigInt, y: BigInt):
    BigInt labels BigIntTooBig, TerminationRequested {
  const xlength = ReadBigIntLength(x);
  const ylength = ReadBigIntLength(y);

  // case: 0n * y
  if (xlength == 0) {
    return x;
  }

  // case: x * 0n
  if (ylength == 0) {
    return y;
  }

  // case: x * y
  const xsign = ReadBigIntSign(x);
  const ysign = ReadBigIntSign(y);
  const resultSign = (xsign != ysign) ? kNegativeSign : kPositiveSign;
  const result = AllocateEmptyBigIntNoThrow(resultSign, xlength + ylength)
      otherwise BigIntTooBig;

  if (CppAbsoluteMulAndCanonicalize(result, x, y) == 1) {
    goto TerminationRequested;
  }

  return Convert<BigInt>(result);
}

builtin BigIntMultiplyNoThrow(
    implicit context: Context)(x: BigInt, y: BigInt): Numeric {
  try {
    return BigIntMultiplyImpl(x, y) otherwise BigIntTooBig,
           TerminationRequested;
  } label BigIntTooBig {
    // Smi sentinel 0 is used to signal BigIntTooBig exception.
    return Convert<Smi>(0);
  } label TerminationRequested {
    // Smi sentinel 1 is used to signal TerminateExecution exception.
    return Convert<Smi>(1);
  }
}

builtin BigIntMultiply(
    implicit context: Context)(xNum: Numeric, yNum: Numeric): BigInt {
  try {
    const x = Cast<BigInt>(xNum) otherwise MixedTypes;
    const y = Cast<BigInt>(yNum) otherwise MixedTypes;

    return BigIntMultiplyImpl(x, y) otherwise BigIntTooBig,
           TerminationRequested;
  } label MixedTypes {
    ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
  } label BigIntTooBig {
    ThrowRangeError(MessageTemplate::kBigIntTooBig);
  } label TerminationRequested {
    TerminateExecution();
  }
}

macro BigIntDivideImpl(implicit context: Context)(x: BigInt, y: BigInt):
    BigInt labels BigIntDivZero, TerminationRequested {
  const xlength = ReadBigIntLength(x);
  const ylength = ReadBigIntLength(y);

  // case: x / 0n
  if (ylength == 0) {
    goto BigIntDivZero;
  }

  // case: x / y, where x < y
  if (MutableBigIntAbsoluteCompare(x, y) < 0) {
    const zero = AllocateEmptyBigInt(kPositiveSign, 0);
    return Convert<BigInt>(zero);
  }

  // case: x / 1n
  const xsign = ReadBigIntSign(x);
  const ysign = ReadBigIntSign(y);
  const resultSign = (xsign != ysign) ? kNegativeSign : kPositiveSign;
  if (ylength == 1 && LoadBigIntDigit(y, 0) == 1) {
    return resultSign == xsign ? x : BigIntUnaryMinus(x);
  }

  // case: x / y
  let resultLength = xlength - ylength + 1;
  // This implies a *very* conservative estimate that kBarrettThreshold > 10.
  if (ylength > 10) resultLength++;
  const result = AllocateEmptyBigIntNoThrow(resultSign, resultLength)
      otherwise unreachable;

  if (CppAbsoluteDivAndCanonicalize(result, x, y) == 1) {
    goto TerminationRequested;
  }

  return Convert<BigInt>(result);
}

builtin BigIntDivideNoThrow(implicit context: Context)(x: BigInt, y: BigInt):
    Numeric {
  try {
    return BigIntDivideImpl(x, y) otherwise BigIntDivZero, TerminationRequested;
  } label BigIntDivZero {
    // Smi sentinel 0 is used to signal BigIntDivZero exception.
    return Convert<Smi>(0);
  } label TerminationRequested {
    // Smi sentinel 1 is used to signal TerminateExecution exception.
    return Convert<Smi>(1);
  }
}

builtin BigIntDivide(implicit context: Context)(xNum: Numeric, yNum: Numeric):
    BigInt {
  try {
    const x = Cast<BigInt>(xNum) otherwise MixedTypes;
    const y = Cast<BigInt>(yNum) otherwise MixedTypes;

    return BigIntDivideImpl(x, y) otherwise BigIntDivZero, TerminationRequested;
  } label MixedTypes {
    ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
  } label BigIntDivZero {
    ThrowRangeError(MessageTemplate::kBigIntDivZero);
  } label TerminationRequested {
    TerminateExecution();
  }
}

macro BigIntModulusImpl(implicit context: Context)(x: BigInt, y: BigInt):
    BigInt labels BigIntDivZero, TerminationRequested {
  const ylength = ReadBigIntLength(y);

  // case: x % 0n
  if (ylength == 0) {
    goto BigIntDivZero;
  }

  // case: x % y, where x < y
  if (MutableBigIntAbsoluteCompare(x, y) < 0) {
    return x;
  }

  // case: x % 1n or x % -1n
  if (ylength == 1 && LoadBigIntDigit(y, 0) == 1) {
    const zero = AllocateEmptyBigInt(kPositiveSign, 0);
    return Convert<BigInt>(zero);
  }

  // case: x % y
  const resultSign = ReadBigIntSign(x);
  const resultLength = ylength;
  const result = AllocateEmptyBigIntNoThrow(resultSign, resultLength)
      otherwise unreachable;

  if (CppAbsoluteModAndCanonicalize(result, x, y) == 1) {
    goto TerminationRequested;
  }

  return Convert<BigInt>(result);
}

builtin BigIntModulusNoThrow(implicit context: Context)(x: BigInt, y: BigInt):
    Numeric {
  try {
    return BigIntModulusImpl(x, y) otherwise BigIntDivZero,
           TerminationRequested;
  } label BigIntDivZero {
    // Smi sentinel 0 is used to signal BigIntDivZero exception.
    return Convert<Smi>(0);
  } label TerminationRequested {
    // Smi sentinel 1 is used to signal TerminateExecution exception.
    return Convert<Smi>(1);
  }
}

builtin BigIntModulus(
    implicit context: Context)(xNum: Numeric, yNum: Numeric): BigInt {
  try {
    const x = Cast<BigInt>(xNum) otherwise MixedTypes;
    const y = Cast<BigInt>(yNum) otherwise MixedTypes;

    return BigIntModulusImpl(x, y) otherwise BigIntDivZero,
           TerminationRequested;
  } label MixedTypes {
    ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
  } label BigIntDivZero {
    ThrowRangeError(MessageTemplate::kBigIntDivZero);
  } label TerminationRequested {
    TerminateExecution();
  }
}

macro BigIntBitwiseAndImpl(implicit context: Context)(x: BigInt, y: BigInt):
    BigInt labels BigIntTooBig {
  const xlength = ReadBigIntLength(x);
  const ylength = ReadBigIntLength(y);

  // case: 0n & y
  if (xlength == 0) {
    return x;
  }

  // case: x & 0n
  if (ylength == 0) {
    return y;
  }

  const xsign = ReadBigIntSign(x);
  const ysign = ReadBigIntSign(y);

  if (xsign == kPositiveSign && ysign == kPositiveSign) {
    const resultLength = (xlength < ylength) ? xlength : ylength;
    const result = AllocateEmptyBigIntNoThrow(kPositiveSign, resultLength)
        otherwise unreachable;
    CppBitwiseAndPosPosAndCanonicalize(result, x, y);
    return Convert<BigInt>(result);
  } else if (xsign == kNegativeSign && ysign == kNegativeSign) {
    const resultLength = ((xlength > ylength) ? xlength : ylength) + 1;
    const result = AllocateEmptyBigIntNoThrow(kNegativeSign, resultLength)
        otherwise BigIntTooBig;
    CppBitwiseAndNegNegAndCanonicalize(result, x, y);
    return Convert<BigInt>(result);
  } else if (xsign == kPositiveSign && ysign == kNegativeSign) {
    const result = AllocateEmptyBigIntNoThrow(kPositiveSign, xlength)
        otherwise unreachable;
    CppBitwiseAndPosNegAndCanonicalize(result, x, y);
    return Convert<BigInt>(result);
  } else {
    const result = AllocateEmptyBigIntNoThrow(kPositiveSign, ylength)
        otherwise unreachable;
    CppBitwiseAndPosNegAndCanonicalize(result, y, x);
    return Convert<BigInt>(result);
  }
}

builtin BigIntBitwiseAndNoThrow(
    implicit context: Context)(x: BigInt, y: BigInt): Numeric {
  try {
    return BigIntBitwiseAndImpl(x, y) otherwise BigIntTooBig;
  } label BigIntTooBig {
    // Smi sentinel 0 is used to signal BigIntTooBig exception.
    return Convert<Smi>(0);
  }
}

builtin BigIntBitwiseAnd(
    implicit context: Context)(xNum: Numeric, yNum: Numeric): BigInt {
  try {
    const x = Cast<BigInt>(xNum) otherwise MixedTypes;
    const y = Cast<BigInt>(yNum) otherwise MixedTypes;

    return BigIntBitwiseAndImpl(x, y) otherwise BigIntTooBig;
  } label MixedTypes {
    ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
  } label BigIntTooBig {
    ThrowRangeError(MessageTemplate::kBigIntTooBig);
  }
}

macro BigIntBitwiseOrImpl(implicit context: Context)(x: BigInt, y: BigInt):
    BigInt {
  const xlength = ReadBigIntLength(x);
  const ylength = ReadBigIntLength(y);

  // case: 0n | y
  if (xlength == 0) {
    return y;
  }

  // case: x | 0n
  if (ylength == 0) {
    return x;
  }

  const xsign = ReadBigIntSign(x);
  const ysign = ReadBigIntSign(y);
  const resultLength = (xlength > ylength) ? xlength : ylength;

  if (xsign == kPositiveSign && ysign == kPositiveSign) {
    const result = AllocateEmptyBigIntNoThrow(kPositiveSign, resultLength)
        otherwise unreachable;
    CppBitwiseOrPosPosAndCanonicalize(result, x, y);
    return Convert<BigInt>(result);
  } else if (xsign == kNegativeSign && ysign == kNegativeSign) {
    const result = AllocateEmptyBigIntNoThrow(kNegativeSign, resultLength)
        otherwise unreachable;
    CppBitwiseOrNegNegAndCanonicalize(result, x, y);
    return Convert<BigInt>(result);
  } else if (xsign == kPositiveSign && ysign == kNegativeSign) {
    const result = AllocateEmptyBigIntNoThrow(kNegativeSign, resultLength)
        otherwise unreachable;
    CppBitwiseOrPosNegAndCanonicalize(result, x, y);
    return Convert<BigInt>(result);
  } else {
    const result = AllocateEmptyBigIntNoThrow(kNegativeSign, resultLength)
        otherwise unreachable;
    CppBitwiseOrPosNegAndCanonicalize(result, y, x);
    return Convert<BigInt>(result);
  }
}

builtin BigIntBitwiseOrNoThrow(
    implicit context: Context)(x: BigInt, y: BigInt): Numeric {
  return BigIntBitwiseOrImpl(x, y);
}

builtin BigIntBitwiseOr(
    implicit context: Context)(xNum: Numeric, yNum: Numeric): BigInt {
  try {
    const x = Cast<BigInt>(xNum) otherwise MixedTypes;
    const y = Cast<BigInt>(yNum) otherwise MixedTypes;

    return BigIntBitwiseOrImpl(x, y);
  } label MixedTypes {
    ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
  }
}

macro BigIntBitwiseXorImpl(implicit context: Context)(x: BigInt, y: BigInt):
    BigInt labels BigIntTooBig {
  const xlength = ReadBigIntLength(x);
  const ylength = ReadBigIntLength(y);

  // case: 0n ^ y
  if (xlength == 0) {
    return y;
  }

  // case: x ^ 0n
  if (ylength == 0) {
    return x;
  }

  const xsign = ReadBigIntSign(x);
  const ysign = ReadBigIntSign(y);

  if (xsign == kPositiveSign && ysign == kPositiveSign) {
    const resultLength = (xlength > ylength) ? xlength : ylength;
    const result = AllocateEmptyBigIntNoThrow(kPositiveSign, resultLength)
        otherwise unreachable;
    CppBitwiseXorPosPosAndCanonicalize(result, x, y);
    return Convert<BigInt>(result);
  } else if (xsign == kNegativeSign && ysign == kNegativeSign) {
    const resultLength = (xlength > ylength) ? xlength : ylength;
    const result = AllocateEmptyBigIntNoThrow(kPositiveSign, resultLength)
        otherwise unreachable;
    CppBitwiseXorNegNegAndCanonicalize(result, x, y);
    return Convert<BigInt>(result);
  } else if (xsign == kPositiveSign && ysign == kNegativeSign) {
    const resultLength = ((xlength > ylength) ? xlength : ylength) + 1;
    const result = AllocateEmptyBigIntNoThrow(kNegativeSign, resultLength)
        otherwise BigIntTooBig;
    CppBitwiseXorPosNegAndCanonicalize(result, x, y);
    return Convert<BigInt>(result);
  } else {
    const resultLength = ((xlength > ylength) ? xlength : ylength) + 1;
    const result = AllocateEmptyBigIntNoThrow(kNegativeSign, resultLength)
        otherwise BigIntTooBig;
    CppBitwiseXorPosNegAndCanonicalize(result, y, x);
    return Convert<BigInt>(result);
  }
}

builtin BigIntBitwiseXorNoThrow(
    implicit context: Context)(x: BigInt, y: BigInt): Numeric {
  try {
    return BigIntBitwiseXorImpl(x, y) otherwise BigIntTooBig;
  } label BigIntTooBig {
    // Smi sentinel 0 is used to signal BigIntTooBig exception.
    return Convert<Smi>(0);
  }
}

builtin BigIntBitwiseXor(
    implicit context: Context)(xNum: Numeric, yNum: Numeric): BigInt {
  try {
    const x = Cast<BigInt>(xNum) otherwise MixedTypes;
    const y = Cast<BigInt>(yNum) otherwise MixedTypes;

    return BigIntBitwiseXorImpl(x, y) otherwise BigIntTooBig;
  } label MixedTypes {
    ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
  } label BigIntTooBig {
    ThrowRangeError(MessageTemplate::kBigIntTooBig);
  }
}

macro MutableBigIntLeftShiftByAbsolute(
    implicit context: Context)(x: BigInt,
    y: BigInt): BigInt labels BigIntTooBig {
  const xlength = ReadBigIntLength(x);
  const ylength = ReadBigIntLength(y);

  // case: 0n << y
  if (xlength == 0) {
    return x;
  }

  // case: x << 0n
  if (ylength == 0) {
    return x;
  }

  if (ylength > 1) {
    // Depends on kBigIntMaxLengthBits <= (1 << kBigIntDigitSize).
    goto BigIntTooBig;
  }
  const shiftAbs = LoadBigIntDigit(y, 0);
  if (shiftAbs > kBigIntMaxLengthBits) {
    goto BigIntTooBig;
  }

  // {shift} is positive.
  const shift = Convert<intptr>(shiftAbs);
  let resultLength = xlength + shift / kBigIntDigitBits;
  const bitsShift = shift % kBigIntDigitBits;
  const xmsd = LoadBigIntDigit(x, xlength - 1);
  if (bitsShift != 0 &&
      xmsd >>> Convert<uintptr>(kBigIntDigitBits - bitsShift) != 0) {
    resultLength++;
  }
  const result = AllocateEmptyBigIntNoThrow(ReadBigIntSign(x), resultLength)
      otherwise BigIntTooBig;
  CppLeftShiftAndCanonicalize(result, x, shift);
  return Convert<BigInt>(result);
}

macro RightShiftByMaximum(implicit context: Context)(sign: uint32): BigInt {
  if (sign == kNegativeSign) {
    const minusOne = AllocateEmptyBigInt(kNegativeSign, 1);
    StoreBigIntDigit(minusOne, 0, 1);
    return Convert<BigInt>(minusOne);
  } else {
    return Convert<BigInt>(AllocateEmptyBigInt(kPositiveSign, 0));
  }
}

macro MutableBigIntRightShiftByAbsolute(
    implicit context: Context)(x: BigInt, y: BigInt): BigInt {
  const xlength = ReadBigIntLength(x);
  const ylength = ReadBigIntLength(y);

  // case: 0n >> y
  if (xlength == 0) {
    return x;
  }

  // case: x >> 0n
  if (ylength == 0) {
    return x;
  }

  const sign = ReadBigIntSign(x);
  if (ylength > 1) {
    // Depends on kBigIntMaxLengthBits <= (1 << kBigIntDigitSize).
    return RightShiftByMaximum(sign);
  }
  const shiftAbs = LoadBigIntDigit(y, 0);
  if (shiftAbs > kBigIntMaxLengthBits) {
    return RightShiftByMaximum(sign);
  }

  // {shift} is positive.
  const shift = Convert<intptr>(shiftAbs);
  const returnVal = CppRightShiftResultLength(x, sign, shift);
  const mustRoundDown = returnVal >>> kMustRoundDownBitShift;
  const lengthMask = (1 << kMustRoundDownBitShift) - 1;
  const resultLength = Convert<intptr>(returnVal & lengthMask);
  if (resultLength == 0) {
    return RightShiftByMaximum(sign);
  }

  const result = AllocateEmptyBigIntNoThrow(sign, resultLength)
      otherwise unreachable;
  CppRightShiftAndCanonicalize(result, x, shift, mustRoundDown);
  return Convert<BigInt>(result);
}

macro BigIntShiftLeftImpl(implicit context: Context)(x: BigInt, y: BigInt):
    BigInt labels BigIntTooBig {
  if (ReadBigIntSign(y) == kNegativeSign) {
    return MutableBigIntRightShiftByAbsolute(x, y);
  } else {
    return MutableBigIntLeftShiftByAbsolute(x, y) otherwise BigIntTooBig;
  }
}

macro BigIntShiftRightImpl(implicit context: Context)(x: BigInt, y: BigInt):
    BigInt labels BigIntTooBig {
  if (ReadBigIntSign(y) == kNegativeSign) {
    return MutableBigIntLeftShiftByAbsolute(x, y) otherwise BigIntTooBig;
  } else {
    return MutableBigIntRightShiftByAbsolute(x, y);
  }
}

builtin BigIntShiftLeftNoThrow(
    implicit context: Context)(x: BigInt, y: BigInt): Numeric {
  try {
    return BigIntShiftLeftImpl(x, y) otherwise BigIntTooBig;
  } label BigIntTooBig {
    // Smi sentinel 0 is used to signal BigIntTooBig exception.
    return Convert<Smi>(0);
  }
}

builtin BigIntShiftLeft(
    implicit context: Context)(xNum: Numeric, yNum: Numeric): BigInt {
  try {
    const x = Cast<BigInt>(xNum) otherwise MixedTypes;
    const y = Cast<BigInt>(yNum) otherwise MixedTypes;

    return BigIntShiftLeftImpl(x, y) otherwise BigIntTooBig;
  } label MixedTypes {
    ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
  } label BigIntTooBig {
    ThrowRangeError(MessageTemplate::kBigIntTooBig);
  }
}

builtin BigIntShiftRightNoThrow(
    implicit context: Context)(x: BigInt, y: BigInt): Numeric {
  try {
    return BigIntShiftRightImpl(x, y) otherwise BigIntTooBig;
  } label BigIntTooBig {
    // Smi sentinel 0 is used to signal BigIntTooBig exception.
    return Convert<Smi>(0);
  }
}

builtin BigIntShiftRight(
    implicit context: Context)(xNum: Numeric, yNum: Numeric): BigInt {
  try {
    const x = Cast<BigInt>(xNum) otherwise MixedTypes;
    const y = Cast<BigInt>(yNum) otherwise MixedTypes;

    return BigIntShiftRightImpl(x, y) otherwise BigIntTooBig;
  } label MixedTypes {
    ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
  } label BigIntTooBig {
    ThrowRangeError(MessageTemplate::kBigIntTooBig);
  }
}

builtin BigIntEqual(implicit context: Context)(x: BigInt, y: BigInt):
    Boolean {
  if (ReadBigIntSign(x) != ReadBigIntSign(y)) {
    return False;
  }

  const xlength = ReadBigIntLength(x);
  const ylength = ReadBigIntLength(y);
  if (xlength != ylength) {
    return False;
  }

  for (let i: intptr = 0; i < xlength; ++i) {
    if (LoadBigIntDigit(x, i) != LoadBigIntDigit(y, i)) {
      return False;
    }
  }

  return True;
}

// Returns r such that r < 0 if |x| < |y|; r > 0 if |x| > |y|;
// r == 0 if |x| == |y|.
macro BigIntCompareAbsolute(
    implicit context: Context)(x: BigInt, y: BigInt): intptr {
  const xlength = ReadBigIntLength(x);
  const ylength = ReadBigIntLength(y);
  const diff = xlength - ylength;
  if (diff != 0) {
    return diff;
  }

  // case: {xlength} == {ylength}
  for (let i: intptr = xlength - 1; i >= 0; --i) {
    const xdigit = LoadBigIntDigit(x, i);
    const ydigit = LoadBigIntDigit(y, i);
    if (xdigit != ydigit) {
      return (xdigit > ydigit) ? kGreaterThan : kLessThan;
    }
  }
  return 0;
}

// Returns r such that r < 0 if x < y; r > 0 if x > y; r == 0 if x == y.
macro BigIntCompare(implicit context: Context)(x: BigInt, y: BigInt):
    intptr {
  const xsign = ReadBigIntSign(x);
  const ysign = ReadBigIntSign(y);
  if (xsign != ysign) {
    return xsign == kPositiveSign ? kGreaterThan : kLessThan;
  }

  // case: {xsign} == {ysign}
  const diff = BigIntCompareAbsolute(x, y);
  return xsign == kPositiveSign ? diff : 0 - diff;
}

builtin BigIntLessThan(implicit context: Context)(x: BigInt, y: BigInt):
    Boolean {
  return BigIntCompare(x, y) < 0 ? True : False;
}

builtin BigIntGreaterThan(implicit context: Context)(x: BigInt, y: BigInt):
    Boolean {
  return BigIntCompare(x, y) > 0 ? True : False;
}

builtin BigIntLessThanOrEqual(
    implicit context: Context)(x: BigInt, y: BigInt): Boolean {
  return BigIntCompare(x, y) <= 0 ? True : False;
}

builtin BigIntGreaterThanOrEqual(
    implicit context: Context)(x: BigInt, y: BigInt): Boolean {
  return BigIntCompare(x, y) >= 0 ? True : False;
}

builtin BigIntUnaryMinus(implicit context: Context)(bigint: BigInt): BigInt {
  const length = ReadBigIntLength(bigint);

  // There is no -0n.
  if (length == 0) {
    return bigint;
  }

  const result =
      AllocateEmptyBigInt(InvertSign(ReadBigIntSign(bigint)), length);
  for (let i: intptr = 0; i < length; ++i) {
    StoreBigIntDigit(result, i, LoadBigIntDigit(bigint, i));
  }
  return Convert<BigInt>(result);
}

}  // namespace bigint

"""

```