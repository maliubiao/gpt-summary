Response: Let's break down the thought process for analyzing this Torque code.

1. **Understand the Goal:** The primary goal is to understand the functionality of the provided V8 Torque code, specifically the `v8/src/builtins/math.tq` file. This means figuring out what JavaScript `Math` methods it implements and how.

2. **Identify Key Structural Elements:**  The code uses several keywords and structures that are important for understanding:
    * `namespace math`:  This immediately tells us the code is related to the `Math` object in JavaScript.
    * `transitioning macro`:  These look like helper functions or optimized pathways. `ReduceToSmiOrFloat64` seems crucial as it's used by many builtins.
    * `transitioning javascript builtin`: This is a strong indicator that these functions are the *implementations* of the JavaScript `Math` methods.
    * `extern macro`: These are external functions, likely implemented in C++, that perform the core mathematical operations.
    * `labels`: Used for non-local control flow, similar to exceptions but within Torque.
    * `implicit context`:  A Torque-specific way to pass context information.
    * `JSAny`, `Smi`, `HeapNumber`, `float64`, `Number`: These are V8's internal type representations.

3. **Process Each `builtin` Function:**  The most efficient way to understand the code is to go through each `transitioning javascript builtin` function individually. For each one:

    * **Identify the JavaScript counterpart:** The comments like `// ES6 #sec-math.abs` directly link the Torque code to the corresponding JavaScript `Math` method. This is the most direct and crucial piece of information.

    * **Analyze the core logic:**
        * **`ReduceToSmiOrFloat64`:** Notice its frequent use. It attempts to convert the input to a `Smi` (small integer) or a `float64`. This is a performance optimization in V8. If it's not a number, it tries to convert it to one.
        * **Direct Calls to `extern macro`:**  Many builtins simply call an `extern macro` like `Float64Abs`, `Float64Ceil`, etc. This means the actual mathematical calculation is done in C++. The Torque code acts as a bridge and handles type conversions.
        * **Special Handling (e.g., `MathAbs`):**  Some functions have more complex logic, like `MathAbs`'s handling of potential `Smi` overflow. This needs closer inspection.
        * **Argument Handling (e.g., `MathMax`, `MathMin`, `MathHypot`):** Pay attention to how these functions handle multiple arguments using loops and how they initialize their results.

    * **Relate to JavaScript behavior:**  For each builtin, think about how the corresponding JavaScript `Math` method works. Does the Torque code's logic align with the expected JavaScript behavior?

    * **Consider edge cases and potential errors:**
        * **Type Conversions:** The code explicitly handles conversions from `JSAny` to numbers. This raises the question of what happens if the input *cannot* be converted to a number. (Though not explicitly shown in the happy paths, implicit conversions might throw errors at lower levels).
        * **Overflow:**  `MathAbs` specifically handles `Smi` overflow.
        * **NaN and Infinity:**  `MathMax`, `MathMin`, and `MathHypot` handle `NaN` and `Infinity`.

4. **Look for Patterns and Reusable Components:**
    * **`ReduceToSmiOrFloat64`:**  This is a clear pattern of input normalization.
    * **Direct `extern macro` calls:**  A common pattern for simple mathematical operations.

5. **Address Specific Prompts:**  Once you have a good understanding of the individual builtins, you can address the specific questions:

    * **Functionality Summary:**  Combine the information gathered for each builtin.
    * **JavaScript Examples:**  Provide concrete examples showing how the JavaScript `Math` methods are used.
    * **Code Logic Inference (Input/Output):** For simpler functions, provide examples of how inputs are processed and what the outputs would be. Focus on demonstrating the type handling and core logic.
    * **Common Programming Errors:** Think about how developers might misuse these `Math` methods in JavaScript. Focus on type issues and edge cases (like `NaN`, `Infinity`, or providing non-numeric inputs).

6. **Refine and Organize:**  Structure the answer logically, starting with a general overview and then going into specifics for each category of question. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This Torque code is confusing."  **Correction:** Focus on the `builtin` definitions and the associated JavaScript methods. The comments are key.
* **Realization:** "Many functions just call `extern macro`." **Insight:** The core math is in C++, Torque is handling the JavaScript interface and type conversions.
* **Question:** "What happens with non-numeric input?" **Answer:** `ReduceToSmiOrFloat64` attempts conversion. If that fails, the `ToNumber_Inline` function called within other builtins will likely handle it (though error handling isn't explicitly shown in *this* code snippet).
* **Focus:** Initially I might have gotten bogged down in the details of Torque syntax. **Correction:** Prioritize understanding the *what* (JavaScript functionality) before the *how* (Torque implementation details).

By following this systematic approach, breaking down the code into manageable parts, and constantly relating the Torque code back to familiar JavaScript concepts, you can effectively analyze and understand the functionality of this V8 source file.
这个 Torque 源代码文件 `v8/src/builtins/math.tq` 定义了 V8 JavaScript 引擎中 `Math` 对象上的一些内置方法的实现。它使用 Torque 语言来描述这些方法的行为，这些方法通常直接对应于 ECMAScript 标准中 `Math` 对象定义的方法。

**功能归纳:**

该文件包含了以下 JavaScript `Math` 对象方法的 Torque 实现：

* **基本数学运算:** `abs`, `ceil`, `floor`, `round`, `trunc`
* **幂运算:** `pow`
* **最值:** `max`, `min`
* **三角函数:** `acos`, `acosh`, `asin`, `asinh`, `atan`, `atan2`, `atanh`, `cos`, `cosh`, `sin`, `sinh`, `tan`, `tanh`
* **指数和对数:** `exp`, `expm1`, `log`, `log1p`, `log10`, `log2`
* **其他:** `cbrt`, `clz32`, `fround`, `f16round`, `imul`, `sign`, `sqrt`, `hypot`, `random`

这些 Torque 代码负责处理 JavaScript 传入的参数，进行必要的类型转换，调用底层的 C++ 数学函数执行实际的计算，并将结果转换回 JavaScript 可以理解的类型（通常是 `Number`）。

**与 JavaScript 功能的关系及举例:**

文件中的每一个 `transitioning javascript builtin` 定义都直接对应一个 JavaScript `Math` 对象的方法。例如：

* `transitioning javascript builtin MathAbs(...)` 对应 `Math.abs()`
* `transitioning javascript builtin MathCeil(...)` 对应 `Math.ceil()`
* ...以此类推

**JavaScript 示例:**

```javascript
console.log(Math.abs(-5));     // 输出 5
console.log(Math.ceil(4.2));    // 输出 5
console.log(Math.floor(4.8));   // 输出 4
console.log(Math.pow(2, 3));   // 输出 8
console.log(Math.max(1, 5, 2)); // 输出 5
console.log(Math.random());    // 输出一个 0 (包含) 到 1 (不包含) 之间的随机数
```

**代码逻辑推理 (假设输入与输出):**

我们以 `Math.abs()` 为例进行逻辑推理：

**假设输入:**

* `x` 是一个 JavaScript 数字 `-3` (在 V8 内部可能表示为 `Smi(-3)`)
* `x` 是一个 JavaScript 数字 `4.7` (在 V8 内部可能表示为 `HeapNumber(4.7)`)
* `x` 是一个 JavaScript 字符串 `"  -10  "`

**输出:**

* **输入 `-3`:**
    1. `ReduceToSmiOrFloat64(-3)` 会直接进入 `SmiResult` 分支，`s` 为 `-3`。
    2. `TrySmiAbs(-3)` 会成功，返回 `Smi(3)`。
    3. `MathAbs` 返回 `3`。
* **输入 `4.7`:**
    1. `ReduceToSmiOrFloat64(4.7)` 会直接进入 `Float64Result` 分支，`f` 为 `4.7`。
    2. `Float64Abs(4.7)` 被调用，返回 `4.7`。
    3. `MathAbs` 返回 `4.7`。
* **输入 `"  -10  "`:**
    1. `ReduceToSmiOrFloat64("  -10  ")` 进入 `JSAnyNotNumber` 分支。
    2. `conversion::NonNumberToNumber("  -10  ")` 被调用，将字符串转换为数字 `-10`。
    3. 循环再次执行，此时 `x1` 是 `Smi(-10)`。
    4. 逻辑同第一个例子，最终返回 `10`。

**涉及用户常见的编程错误及举例说明:**

1. **向需要数字的方法传递非数字类型：**

   ```javascript
   console.log(Math.abs("hello")); // 输出 NaN (因为 "hello" 无法转换为有意义的数字)
   console.log(Math.sqrt("abc")); // 输出 NaN
   ```

   在 Torque 代码中，`ReduceToSmiOrFloat64` 尝试将输入转换为数字，但如果无法转换，最终底层的数学函数会返回 `NaN`，这在 JavaScript 中是预期的行为。

2. **对 `Math.max` 或 `Math.min` 传递非数字类型：**

   ```javascript
   console.log(Math.max(1, "a", 3)); // 输出 NaN (因为 "a" 无法转换为数字)
   console.log(Math.min(5, null, 10)); // 输出 0 (因为 null 被转换为 0)
   ```

   Torque 代码中的 `TruncateTaggedToFloat64` 会尝试将参数转换为浮点数。对于无法有效转换的值，可能会得到 `NaN`，这会影响 `Math.max` 和 `Math.min` 的结果。

3. **误解 `Math.round` 的行为：**

   ```javascript
   console.log(Math.round(4.4));  // 输出 4
   console.log(Math.round(4.5));  // 输出 5
   console.log(Math.round(4.6));  // 输出 5
   console.log(Math.round(-4.4)); // 输出 -4
   console.log(Math.round(-4.5)); // 输出 -4  // 注意：四舍五入到最接近的整数，如果是 .5 则远离零
   console.log(Math.round(-4.6)); // 输出 -5
   ```

   用户可能错误地认为 `Math.round` 总是简单地“四舍五入”，而忽略了 `.5` 的特殊处理规则。

4. **对 `Math.pow` 传递不合理的参数导致 `NaN` 或 `Infinity`：**

   ```javascript
   console.log(Math.pow(-2, 0.5)); // 输出 NaN (负数的非整数次幂)
   console.log(Math.pow(Infinity, 2)); // 输出 Infinity
   console.log(Math.pow(0, -1));    // 输出 Infinity
   ```

   这些行为都符合 ECMAScript 规范，Torque 代码调用底层的 `Float64Pow` 函数会遵循这些规则。

5. **使用 `Math.random` 时误认为会生成指定范围内的整数：**

   ```javascript
   // 错误的做法，可能不是均匀分布
   const randomNumber = Math.round(Math.random() * 10);

   // 正确的做法生成 0 到 9 的随机整数
   const randomNumberCorrect = Math.floor(Math.random() * 10);
   ```

   `Math.random()` 返回的是 `[0, 1)` 范围内的浮点数。需要根据具体需求进行缩放和取整才能得到期望范围内的整数。

总而言之，`v8/src/builtins/math.tq` 文件是 V8 引擎实现 JavaScript `Math` 对象方法的关键部分，它负责连接 JavaScript 层和底层的 C++ 数学运算实现，并处理类型转换和一些边界情况。理解这个文件可以帮助我们更深入地了解 JavaScript `Math` 对象的内部工作原理。

Prompt: 
```
这是目录为v8/src/builtins/math.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved. Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

namespace math {

transitioning macro ReduceToSmiOrFloat64(implicit context: Context)(x: JSAny):
    never
    labels SmiResult(Smi), Float64Result(float64) {
  let x1: JSAny = x;
  while (true) {
    typeswitch (x1) {
      case (s: Smi): {
        goto SmiResult(s);
      }
      case (h: HeapNumber): {
        goto Float64Result(Convert<float64>(h));
      }
      case (a: JSAnyNotNumber): {
        x1 = conversion::NonNumberToNumber(a);
      }
    }
  }
  VerifiedUnreachable();
}

// ES6 #sec-math.abs
extern macro IsIntPtrAbsWithOverflowSupported(): constexpr bool;
extern macro TrySmiAdd(Smi, Smi): Smi labels Overflow;
extern macro TrySmiSub(Smi, Smi): Smi labels Overflow;
extern macro TrySmiAbs(Smi): Smi labels Overflow;
extern macro Float64Abs(float64): float64;
const kSmiMaxValuePlusOne:
    constexpr float64 generates '0.0 - kSmiMinValue';

transitioning javascript builtin MathAbs(
    js-implicit context: NativeContext)(x: JSAny): Number {
  try {
    ReduceToSmiOrFloat64(x) otherwise SmiResult, Float64Result;
  } label SmiResult(s: Smi) {
    try {
      if constexpr (IsIntPtrAbsWithOverflowSupported()) {
        const result: Smi = TrySmiAbs(s)
            otherwise SmiOverflow;
        return result;
      } else {
        if (0 <= s) {
          return s;
        } else {
          const result: Smi = TrySmiSub(0, s) otherwise SmiOverflow;
          return result;
        }
      }
    } label SmiOverflow {
      return NumberConstant(kSmiMaxValuePlusOne);
    }
  } label Float64Result(f: float64) {
    return Convert<Number>(Float64Abs(f));
  }
}

// ES6 #sec-math.ceil
extern macro Float64Ceil(float64): float64;
transitioning javascript builtin MathCeil(
    js-implicit context: NativeContext)(x: JSAny): Number {
  try {
    ReduceToSmiOrFloat64(x) otherwise SmiResult, Float64Result;
  } label SmiResult(s: Smi) {
    return s;
  } label Float64Result(f: float64) {
    return Convert<Number>(Float64Ceil(f));
  }
}

// ES6 #sec-math.floor
extern macro Float64Floor(float64): float64;
transitioning javascript builtin MathFloor(
    js-implicit context: NativeContext)(x: JSAny): Number {
  try {
    ReduceToSmiOrFloat64(x) otherwise SmiResult, Float64Result;
  } label SmiResult(s: Smi) {
    return s;
  } label Float64Result(f: float64) {
    return Convert<Number>(Float64Floor(f));
  }
}

// ES6 #sec-math.round
extern macro Float64Round(float64): float64;
transitioning javascript builtin MathRound(
    js-implicit context: NativeContext)(x: JSAny): Number {
  try {
    ReduceToSmiOrFloat64(x) otherwise SmiResult, Float64Result;
  } label SmiResult(s: Smi) {
    return s;
  } label Float64Result(f: float64) {
    return Convert<Number>(Float64Round(f));
  }
}

// ES6 #sec-math.trunc
extern macro Float64Trunc(float64): float64;
transitioning javascript builtin MathTrunc(
    js-implicit context: NativeContext)(x: JSAny): Number {
  try {
    ReduceToSmiOrFloat64(x) otherwise SmiResult, Float64Result;
  } label SmiResult(s: Smi) {
    return s;
  } label Float64Result(f: float64) {
    return Convert<Number>(Float64Trunc(f));
  }
}

// ES6 #sec-math.pow
extern macro Float64Pow(float64, float64): float64;
extern macro TruncateTaggedToFloat64(implicit context: Context)(JSAny):
    float64;

@export
macro MathPowImpl(implicit context: Context)(base: JSAny, exponent: JSAny):
    Number {
  const baseValue: float64 = TruncateTaggedToFloat64(base);
  const exponentValue: float64 = TruncateTaggedToFloat64(exponent);
  const result: float64 = Float64Pow(baseValue, exponentValue);
  return Convert<Number>(result);
}

transitioning javascript builtin MathPow(
    js-implicit context: NativeContext)(base: JSAny, exponent: JSAny): Number {
  return MathPowImpl(base, exponent);
}

// ES6 #sec-math.max
extern macro Float64Max(float64, float64): float64;
transitioning javascript builtin MathMax(
    js-implicit context: NativeContext)(...arguments): Number {
  let result: float64 = MINUS_V8_INFINITY;
  const argCount = arguments.length;
  for (let i: intptr = 0; i < argCount; i++) {
    const doubleValue = TruncateTaggedToFloat64(arguments[i]);
    result = Float64Max(result, doubleValue);
  }
  return Convert<Number>(result);
}

// ES6 #sec-math.min
extern macro Float64Min(float64, float64): float64;
transitioning javascript builtin MathMin(
    js-implicit context: NativeContext)(...arguments): Number {
  let result: float64 = V8_INFINITY;
  const argCount = arguments.length;
  for (let i: intptr = 0; i < argCount; i++) {
    const doubleValue = TruncateTaggedToFloat64(arguments[i]);
    result = Float64Min(result, doubleValue);
  }
  return Convert<Number>(result);
}

// ES6 #sec-math.acos
extern macro Float64Acos(float64): float64;

transitioning javascript builtin MathAcos(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Acos(value));
}

// ES6 #sec-math.acosh
extern macro Float64Acosh(float64): float64;

transitioning javascript builtin MathAcosh(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Acosh(value));
}

// ES6 #sec-math.asin
extern macro Float64Asin(float64): float64;

transitioning javascript builtin MathAsin(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Asin(value));
}

// ES6 #sec-math.asinh
extern macro Float64Asinh(float64): float64;

transitioning javascript builtin MathAsinh(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Asinh(value));
}

// ES6 #sec-math.atan
extern macro Float64Atan(float64): float64;

transitioning javascript builtin MathAtan(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Atan(value));
}

// ES6 #sec-math.atan2
extern macro Float64Atan2(float64, float64): float64;

transitioning javascript builtin MathAtan2(
    js-implicit context: NativeContext)(y: JSAny, x: JSAny): Number {
  const yValue = Convert<float64>(ToNumber_Inline(y));
  const xValue = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Atan2(yValue, xValue));
}

// ES6 #sec-math.atanh
extern macro Float64Atanh(float64): float64;

transitioning javascript builtin MathAtanh(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Atanh(value));
}

// ES6 #sec-math.cbrt
extern macro Float64Cbrt(float64): float64;

transitioning javascript builtin MathCbrt(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Cbrt(value));
}

// ES6 #sec-math.clz32
extern macro Word32Clz(int32): int32;

transitioning javascript builtin MathClz32(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value: int32 = Convert<int32>(ToNumber_Inline(x));
  return Convert<Number>(Word32Clz(value));
}

// ES6 #sec-math.cos
extern macro Float64Cos(float64): float64;

transitioning javascript builtin MathCos(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Cos(value));
}

// ES6 #sec-math.cosh
extern macro Float64Cosh(float64): float64;

transitioning javascript builtin MathCosh(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Cosh(value));
}

// ES6 #sec-math.exp
extern macro Float64Exp(float64): float64;

transitioning javascript builtin MathExp(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Exp(value));
}

// ES6 #sec-math.expm1
extern macro Float64Expm1(float64): float64;

transitioning javascript builtin MathExpm1(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Expm1(value));
}

// ES6 #sec-math.fround
transitioning javascript builtin MathFround(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const x32 = Convert<float32>(ToNumber_Inline(x));
  const x64 = Convert<float64>(x32);
  return Convert<Number>(x64);
}

// ES6 #sec-math.f16round
transitioning javascript builtin MathF16round(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const x16 = Convert<float16_raw_bits>(ToNumber_Inline(x));
  const x64 = Convert<float64>(x16);
  return Convert<Number>(x64);
}

// ES6 #sec-math.imul
transitioning javascript builtin MathImul(
    js-implicit context: NativeContext)(x: JSAny, y: JSAny): Number {
  const x = Convert<int32>(ToNumber_Inline(x));
  const y = Convert<int32>(ToNumber_Inline(y));
  return Convert<Number>(x * y);
}

// ES6 #sec-math.log
extern macro Float64Log(float64): float64;

transitioning javascript builtin MathLog(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Log(value));
}

// ES6 #sec-math.log1p
extern macro Float64Log1p(float64): float64;

transitioning javascript builtin MathLog1p(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Log1p(value));
}

// ES6 #sec-math.log10
extern macro Float64Log10(float64): float64;

transitioning javascript builtin MathLog10(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Log10(value));
}

// ES6 #sec-math.log2
extern macro Float64Log2(float64): float64;

transitioning javascript builtin MathLog2(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Log2(value));
}

// ES6 #sec-math.sin
extern macro Float64Sin(float64): float64;

transitioning javascript builtin MathSin(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Sin(value));
}

// ES6 #sec-math.sign
transitioning javascript builtin MathSign(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const num = ToNumber_Inline(x);
  const value = Convert<float64>(num);

  if (value < 0) {
    return -1;
  } else if (value > 0) {
    return 1;
  } else {
    return num;
  }
}

// ES6 #sec-math.sinh
extern macro Float64Sinh(float64): float64;

transitioning javascript builtin MathSinh(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Sinh(value));
}

// ES6 #sec-math.sqrt
extern macro Float64Sqrt(float64): float64;

transitioning javascript builtin MathSqrt(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Sqrt(value));
}

// ES6 #sec-math.tan
extern macro Float64Tan(float64): float64;

transitioning javascript builtin MathTan(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Tan(value));
}

// ES6 #sec-math.tanh
extern macro Float64Tanh(float64): float64;

transitioning javascript builtin MathTanh(
    js-implicit context: NativeContext)(x: JSAny): Number {
  const value = Convert<float64>(ToNumber_Inline(x));
  return Convert<Number>(Float64Tanh(value));
}

// Fast path for few arguments to avoid loop comparison.
transitioning macro FastMathHypot(
    implicit context: Context)(arguments: Arguments): Number labels Slow {
  const length = arguments.length;

  if (length > 3) {
    goto Slow;
  }

  if (length == 0) {
    return 0;
  }

  const a = Float64Abs(Convert<float64>(ToNumber_Inline(arguments[0])));

  if (length == 1) {
    return Convert<Number>(a);
  }

  let max: float64 = 0;
  const b = Float64Abs(Convert<float64>(ToNumber_Inline(arguments[1])));

  if (length == 2) {
    if (a == V8_INFINITY || b == V8_INFINITY) {
      return V8_INFINITY;
    }

    max = Float64Max(a, b);

    if (Float64IsNaN(max)) {
      return kNaN;
    }

    if (max == 0) {
      return 0;
    }

    return Convert<Number>(
        Float64Sqrt((a / max) * (a / max) + (b / max) * (b / max)) * max);
  }

  if (length == 3) {
    const c = Float64Abs(Convert<float64>(ToNumber_Inline(arguments[2])));
    if (a == V8_INFINITY || b == V8_INFINITY || c == V8_INFINITY) {
      return V8_INFINITY;
    }

    max = Float64Max(Float64Max(a, b), c);

    if (Float64IsNaN(max)) {
      return kNaN;
    }

    if (max == 0) {
      return 0;
    }

    const powerA: float64 = (a / max) * (a / max);
    const powerB: float64 = (b / max) * (b / max);
    const compensation: float64 = (powerA + powerB) - powerA - powerB;
    const powerC: float64 = (c / max) * (c / max) - compensation;

    return Convert<Number>(Float64Sqrt(powerA + powerB + powerC) * max);
  }
  unreachable;
}

// ES6 #sec-math.hypot
transitioning javascript builtin MathHypot(
    js-implicit context: NativeContext, receiver: JSAny)(
    ...arguments): Number {
  try {
    return FastMathHypot(arguments) otherwise Slow;
  } label Slow {
    const length = arguments.length;
    const absValues = AllocateZeroedFixedDoubleArray(length);
    let oneArgIsNaN: bool = false;
    let max: float64 = 0;
    for (let i: intptr = 0; i < length; ++i) {
      const value = Convert<float64>(ToNumber_Inline(arguments[i]));
      if (Float64IsNaN(value)) {
        oneArgIsNaN = true;
      } else {
        const absValue = Float64Abs(value);
        absValues.values[i] = Convert<float64_or_hole>(absValue);
        if (absValue > max) {
          max = absValue;
        }
      }
    }
    if (max == V8_INFINITY) {
      return V8_INFINITY;
    } else if (oneArgIsNaN) {
      return kNaN;
    } else if (max == 0) {
      return 0;
    }
    dcheck(max > 0);

    // Kahan summation to avoid rounding errors.
    // Normalize the numbers to the largest one to avoid overflow.
    let sum: float64 = 0;
    let compensation: float64 = 0;
    for (let i: intptr = 0; i < length; ++i) {
      const n = absValues.values[i].ValueUnsafeAssumeNotHole() / max;
      const summand = n * n - compensation;
      const preliminary = sum + summand;
      compensation = (preliminary - sum) - summand;
      sum = preliminary;
    }
    return Convert<Number>(Float64Sqrt(sum) * max);
  }
}

// ES6 #sec-math.random
extern macro RefillMathRandom(NativeContext): Smi;

transitioning javascript builtin MathRandom(
    js-implicit context: NativeContext, receiver: JSAny)(): Number {
  let smiIndex: Smi = *NativeContextSlot(ContextSlot::MATH_RANDOM_INDEX_INDEX);
  if (smiIndex == 0) {
    // refill math random.
    smiIndex = RefillMathRandom(context);
  }
  const newSmiIndex: Smi = smiIndex - 1;
  *NativeContextSlot(ContextSlot::MATH_RANDOM_INDEX_INDEX) = newSmiIndex;

  const array: FixedDoubleArray =
      *NativeContextSlot(ContextSlot::MATH_RANDOM_CACHE_INDEX);
  const random: float64 =
      array.values[Convert<intptr>(newSmiIndex)].ValueUnsafeAssumeNotHole();
  return AllocateHeapNumberWithValue(random);
}
}

"""

```