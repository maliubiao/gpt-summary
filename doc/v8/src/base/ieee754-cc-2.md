Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `v8/src/base/ieee754.cc` file in the V8 JavaScript engine. I need to:

1. **Identify the core functionalities:**  The code defines implementations for various mathematical functions related to IEEE 754 floating-point numbers. These include logarithms (base 2 and base 10), exponential minus 1, cube root, sine, tangent, hyperbolic cosine, and power.

2. **Check for Torque:** The filename ends with `.cc`, not `.tq`, so it's not a Torque file.

3. **Relate to JavaScript:** These functions are the underlying implementations for `Math` object methods in JavaScript.

4. **Provide JavaScript examples:** For each function, I should provide a corresponding `Math` method example.

5. **Infer code logic:** I can analyze the comments and the structure of the functions to understand their purpose and how they handle special cases. I should provide an example of input and output for one of the simpler functions.

6. **Highlight common programming errors:** I need to think about how these functions could be misused in JavaScript and provide illustrative examples.

7. **Summarize the functionality:** Based on the above points, I need to create a concise summary of the code's purpose.

**Function-by-function analysis and planning:**

* **`k_log1p(double f)`:** This seems like a helper function for calculating `log(1 + f)`. I should mention this as a building block.
* **`log2(double x)`:**  JavaScript equivalent is `Math.log2()`. I need to consider edge cases like negative numbers, zero, infinity, and NaN.
* **`log10(double x)`:** JavaScript equivalent is `Math.log10()`. Similar edge cases to `log2`.
* **`expm1(double x)`:** JavaScript equivalent is `Math.expm1()`. Important for accuracy near zero. Edge cases to consider.
* **`cbrt(double x)`:** JavaScript equivalent is `Math.cbrt()`. Handles negative numbers correctly.
* **`sin(double x)`:** JavaScript equivalent is `Math.sin()`. Considers argument reduction and special values.
* **`tan(double x)`:** JavaScript equivalent is `Math.tan()`. Similar to `sin()`.
* **`cosh(double x)`:** JavaScript equivalent is `Math.cosh()`. Deals with overflow.
* **`pow(double x, double y)`:** JavaScript equivalent is `Math.pow()` or the `**` operator. This function has many special cases to handle.

**Overall structure for the response:**

* Start with a general summary of the file's purpose.
* Mention it's not a Torque file.
* Describe the relationship to JavaScript `Math` object methods.
* For each function:
    * State its purpose.
    * Provide a JavaScript example.
    * Provide an example of input and output (for a simpler function).
* Provide examples of common programming errors when using the corresponding JavaScript methods.
* Conclude with a concise summary.
`v8/src/base/ieee754.cc` 的功能是提供了符合 IEEE 754 标准的浮点数运算的底层实现。它包含了一系列用于计算常用数学函数的 C++ 代码，这些函数通常是 JavaScript `Math` 对象中方法的底层实现。

由于 `v8/src/base/ieee754.cc` 的文件扩展名是 `.cc` 而不是 `.tq`，因此它不是一个 V8 Torque 源代码文件。

是的，`v8/src/base/ieee754.cc` 中的功能与 JavaScript 的功能有密切关系。该文件中的 C++ 函数是 JavaScript `Math` 对象中许多方法的底层实现。例如：

* **`log2(double x)`:**  对应 JavaScript 的 `Math.log2(x)`，计算以 2 为底的对数。
  ```javascript
  console.log(Math.log2(8)); // 输出 3
  console.log(Math.log2(0)); // 输出 -Infinity
  console.log(Math.log2(-1)); // 输出 NaN
  ```

* **`log10(double x)`:** 对应 JavaScript 的 `Math.log10(x)`，计算以 10 为底的对数。
  ```javascript
  console.log(Math.log10(100)); // 输出 2
  console.log(Math.log10(0.1)); // 输出 -1
  ```

* **`expm1(double x)`:** 对应 JavaScript 的 `Math.expm1(x)`，计算 `exp(x) - 1`。这个函数在 `x` 非常接近 0 时能提供比直接计算 `Math.exp(x) - 1` 更精确的结果。
  ```javascript
  console.log(Math.expm1(1)); // 输出约 1.718281828459045
  console.log(Math.expm1(0)); // 输出 0
  ```

* **`cbrt(double x)`:** 对应 JavaScript 的 `Math.cbrt(x)`，计算立方根。
  ```javascript
  console.log(Math.cbrt(27)); // 输出 3
  console.log(Math.cbrt(-8)); // 输出 -2
  ```

* **`sin(double x)`:** 对应 JavaScript 的 `Math.sin(x)`，计算正弦值。
  ```javascript
  console.log(Math.sin(Math.PI / 2)); // 输出 1
  ```

* **`tan(double x)`:** 对应 JavaScript 的 `Math.tan(x)`，计算正切值。
  ```javascript
  console.log(Math.tan(0)); // 输出 0
  ```

* **`cosh(double x)`:** 对应 JavaScript 的 `Math.cosh(x)`，计算双曲余弦值。
  ```javascript
  console.log(Math.cosh(0)); // 输出 1
  ```

* **`pow(double x, double y)`:** 对应 JavaScript 的 `Math.pow(x, y)` 或 `x ** y`，计算 `x` 的 `y` 次方。
  ```javascript
  console.log(Math.pow(2, 3)); // 输出 8
  console.log(2 ** 3);       // 输出 8
  ```

**代码逻辑推理示例 (针对 `log2`)：**

假设输入 `x` 为 `8.0`。

1. **提取浮点数组成部分:**  `EXTRACT_WORDS(hx, lx, x)` 会将 `8.0` 的高位字 `hx` 和低位字 `lx` 提取出来。对于 `8.0`，`hx` 的值会反映其指数部分。
2. **处理特殊情况:**  代码首先检查 `x` 是否小于 `2**-1022` (次正规数)，是否为 0，是否为负数，或者是否为无穷大或 NaN。由于 `8.0` 不是这些特殊情况，代码会继续执行。
3. **处理 `log(1)` 的情况:** 检查 `x` 是否为 1。`8.0` 不是 1。
4. **提取指数 `k`:** 对于 `8.0`，指数 `k` 将会被计算出来 (基于 `hx` 的移位)。对于 `8.0` (2<sup>3</sup>)，`k` 应该是 3。
5. **归一化 `x`:** 将 `x` 归一化到 `[1, 2)` 或 `[0.5, 1)` 之间，并相应调整 `k` 的值。
6. **计算 `f = x - 1.0`:** 计算归一化后的 `x` 与 1 的差值。
7. **调用 `k_log1p(f)`:**  使用泰勒展开或其他近似方法计算 `log(1 + f)`。
8. **最终计算:** 将 `k` 和 `k_log1p(f)` 的结果组合起来，得到最终的 `log2(x)` 的值。对于输入 `8.0`，预期输出为 `3.0`。

**用户常见的编程错误示例 (使用 JavaScript)：**

* **对负数取自然对数/以 2 为底/以 10 为底的对数：**
  ```javascript
  console.log(Math.log(-1));   // 输出 NaN
  console.log(Math.log2(-5));  // 输出 NaN
  console.log(Math.log10(-10)); // 输出 NaN
  ```
  **错误原因：** 对数函数的定义域不包含负数。

* **对零取自然对数/以 2 为底/以 10 为底的对数：**
  ```javascript
  console.log(Math.log(0));   // 输出 -Infinity
  console.log(Math.log2(0));  // 输出 -Infinity
  console.log(Math.log10(0)); // 输出 -Infinity
  ```
  **错误原因：**  当 x 趋近于 0 时，log(x) 趋近于负无穷大。

* **`Math.pow()` 的参数顺序错误：**
  ```javascript
  console.log(Math.pow(3, 2)); // 正确：输出 9 (3 的 2 次方)
  console.log(Math.pow(2, 3)); // 正确：输出 8 (2 的 3 次方)
  ```
  **错误原因：** `Math.pow(base, exponent)`，第一个参数是底数，第二个参数是指数。

* **`Math.expm1()` 的误用:**  可能用户不知道 `Math.expm1()` 的存在，而是在 `x` 接近 0 的时候使用 `Math.exp(x) - 1`，这可能会导致精度损失。

**归纳 `v8/src/base/ieee754.cc` 的功能 (第 3 部分):**

这部分代码主要实现了以下数学函数，这些函数是 JavaScript `Math` 对象中对应方法的底层 C++ 实现：

* **`log2(double x)`:** 计算以 2 为底的对数。
* **`log10(double x)`:** 计算以 10 为底的对数。
* **`expm1(double x)`:** 计算 `exp(x) - 1`，在接近 0 时提供更高的精度。
* **`cbrt(double x)`:** 计算立方根。
* **`sin(double x)`:** 计算正弦值。
* **`tan(double x)`:** 计算正切值。
* **`cosh(double x)`:** 计算双曲余弦值。
* **`pow(double x, double y)`:** 计算幂运算。

这些函数都遵循 IEEE 754 标准，并处理了各种特殊情况，例如 NaN、无穷大和零，以确保数值计算的准确性和可靠性。它们直接支持了 JavaScript 中 `Math` 对象的相应功能。

### 提示词
```
这是目录为v8/src/base/ieee754.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/ieee754.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
i is always exact for |n| < 2000.
 *
 * Special cases:
 *      log(x) is NaN with signal if x < 0 (including -INF) ;
 *      log(+INF) is +INF; log(0) is -INF with signal;
 *      log(NaN) is that NaN with no signal.
 *
 * Accuracy:
 *      according to an error analysis, the error is always less than
 *      1 ulp (unit in the last place).
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following
 * constants. The decimal values may be used, provided that the
 * compiler will convert from decimal to binary accurately enough
 * to produce the hexadecimal values shown.
 */

static const double Lg1 = 6.666666666666735130e-01, /* 3FE55555 55555593 */
    Lg2 = 3.999999999940941908e-01,                 /* 3FD99999 9997FA04 */
    Lg3 = 2.857142874366239149e-01,                 /* 3FD24924 94229359 */
    Lg4 = 2.222219843214978396e-01,                 /* 3FCC71C5 1D8E78AF */
    Lg5 = 1.818357216161805012e-01,                 /* 3FC74664 96CB03DE */
    Lg6 = 1.531383769920937332e-01,                 /* 3FC39A09 D078C69F */
    Lg7 = 1.479819860511658591e-01;                 /* 3FC2F112 DF3E5244 */

/*
 * We always inline k_log1p(), since doing so produces a
 * substantial performance improvement (~40% on amd64).
 */
static inline double k_log1p(double f) {
  double hfsq, s, z, R, w, t1, t2;

  s = f / (2.0 + f);
  z = s * s;
  w = z * z;
  t1 = w * (Lg2 + w * (Lg4 + w * Lg6));
  t2 = z * (Lg1 + w * (Lg3 + w * (Lg5 + w * Lg7)));
  R = t2 + t1;
  hfsq = 0.5 * f * f;
  return s * (hfsq + R);
}

/*
 * Return the base 2 logarithm of x.  See e_log.c and k_log.h for most
 * comments.
 *
 * This reduces x to {k, 1+f} exactly as in e_log.c, then calls the kernel,
 * then does the combining and scaling steps
 *    log2(x) = (f - 0.5*f*f + k_log1p(f)) / ln2 + k
 * in not-quite-routine extra precision.
 */
double log2(double x) {
  static const double
      two54 = 1.80143985094819840000e+16,   /* 0x43500000, 0x00000000 */
      ivln2hi = 1.44269504072144627571e+00, /* 0x3FF71547, 0x65200000 */
      ivln2lo = 1.67517131648865118353e-10; /* 0x3DE705FC, 0x2EEFA200 */

  double f, hfsq, hi, lo, r, val_hi, val_lo, w, y;
  int32_t i, k, hx;
  uint32_t lx;

  EXTRACT_WORDS(hx, lx, x);

  k = 0;
  if (hx < 0x00100000) { /* x < 2**-1022  */
    if (((hx & 0x7FFFFFFF) | lx) == 0) {
      return -std::numeric_limits<double>::infinity(); /* log(+-0)=-inf */
    }
    if (hx < 0) {
      return std::numeric_limits<double>::signaling_NaN(); /* log(-#) = NaN */
    }
    k -= 54;
    x *= two54; /* subnormal number, scale up x */
    GET_HIGH_WORD(hx, x);
  }
  if (hx >= 0x7FF00000) return x + x;
  if (hx == 0x3FF00000 && lx == 0) return 0.0; /* log(1) = +0 */
  k += (hx >> 20) - 1023;
  hx &= 0x000FFFFF;
  i = (hx + 0x95F64) & 0x100000;
  SET_HIGH_WORD(x, hx | (i ^ 0x3FF00000)); /* normalize x or x/2 */
  k += (i >> 20);
  y = static_cast<double>(k);
  f = x - 1.0;
  hfsq = 0.5 * f * f;
  r = k_log1p(f);

  /*
   * f-hfsq must (for args near 1) be evaluated in extra precision
   * to avoid a large cancellation when x is near sqrt(2) or 1/sqrt(2).
   * This is fairly efficient since f-hfsq only depends on f, so can
   * be evaluated in parallel with R.  Not combining hfsq with R also
   * keeps R small (though not as small as a true `lo' term would be),
   * so that extra precision is not needed for terms involving R.
   *
   * Compiler bugs involving extra precision used to break Dekker's
   * theorem for spitting f-hfsq as hi+lo, unless double_t was used
   * or the multi-precision calculations were avoided when double_t
   * has extra precision.  These problems are now automatically
   * avoided as a side effect of the optimization of combining the
   * Dekker splitting step with the clear-low-bits step.
   *
   * y must (for args near sqrt(2) and 1/sqrt(2)) be added in extra
   * precision to avoid a very large cancellation when x is very near
   * these values.  Unlike the above cancellations, this problem is
   * specific to base 2.  It is strange that adding +-1 is so much
   * harder than adding +-ln2 or +-log10_2.
   *
   * This uses Dekker's theorem to normalize y+val_hi, so the
   * compiler bugs are back in some configurations, sigh.  And I
   * don't want to used double_t to avoid them, since that gives a
   * pessimization and the support for avoiding the pessimization
   * is not yet available.
   *
   * The multi-precision calculations for the multiplications are
   * routine.
   */
  hi = f - hfsq;
  SET_LOW_WORD(hi, 0);
  lo = (f - hi) - hfsq + r;
  val_hi = hi * ivln2hi;
  val_lo = (lo + hi) * ivln2lo + lo * ivln2hi;

  /* spadd(val_hi, val_lo, y), except for not using double_t: */
  w = y + val_hi;
  val_lo += (y - w) + val_hi;
  val_hi = w;

  return val_lo + val_hi;
}

/*
 * Return the base 10 logarithm of x
 *
 * Method :
 *      Let log10_2hi = leading 40 bits of log10(2) and
 *          log10_2lo = log10(2) - log10_2hi,
 *          ivln10   = 1/log(10) rounded.
 *      Then
 *              n = ilogb(x),
 *              if(n<0)  n = n+1;
 *              x = scalbn(x,-n);
 *              log10(x) := n*log10_2hi + (n*log10_2lo + ivln10*log(x))
 *
 *  Note 1:
 *     To guarantee log10(10**n)=n, where 10**n is normal, the rounding
 *     mode must set to Round-to-Nearest.
 *  Note 2:
 *      [1/log(10)] rounded to 53 bits has error .198 ulps;
 *      log10 is monotonic at all binary break points.
 *
 *  Special cases:
 *      log10(x) is NaN if x < 0;
 *      log10(+INF) is +INF; log10(0) is -INF;
 *      log10(NaN) is that NaN;
 *      log10(10**N) = N  for N=0,1,...,22.
 */
double log10(double x) {
  static const double
      two54 = 1.80143985094819840000e+16, /* 0x43500000, 0x00000000 */
      ivln10 = 4.34294481903251816668e-01,
      log10_2hi = 3.01029995663611771306e-01, /* 0x3FD34413, 0x509F6000 */
      log10_2lo = 3.69423907715893078616e-13; /* 0x3D59FEF3, 0x11F12B36 */

  double y;
  int32_t i, k, hx;
  uint32_t lx;

  EXTRACT_WORDS(hx, lx, x);

  k = 0;
  if (hx < 0x00100000) { /* x < 2**-1022  */
    if (((hx & 0x7FFFFFFF) | lx) == 0) {
      return -std::numeric_limits<double>::infinity(); /* log(+-0)=-inf */
    }
    if (hx < 0) {
      return std::numeric_limits<double>::quiet_NaN(); /* log(-#) = NaN */
    }
    k -= 54;
    x *= two54; /* subnormal number, scale up x */
    GET_HIGH_WORD(hx, x);
    GET_LOW_WORD(lx, x);
  }
  if (hx >= 0x7FF00000) return x + x;
  if (hx == 0x3FF00000 && lx == 0) return 0.0; /* log(1) = +0 */
  k += (hx >> 20) - 1023;

  i = (k & 0x80000000) >> 31;
  hx = (hx & 0x000FFFFF) | ((0x3FF - i) << 20);
  y = k + i;
  SET_HIGH_WORD(x, hx);
  SET_LOW_WORD(x, lx);

  double z = y * log10_2lo + ivln10 * log(x);
  return z + y * log10_2hi;
}

/* expm1(x)
 * Returns exp(x)-1, the exponential of x minus 1.
 *
 * Method
 *   1. Argument reduction:
 *  Given x, find r and integer k such that
 *
 *               x = k*ln2 + r,  |r| <= 0.5*ln2 ~ 0.34658
 *
 *      Here a correction term c will be computed to compensate
 *  the error in r when rounded to a floating-point number.
 *
 *   2. Approximating expm1(r) by a special rational function on
 *  the interval [0,0.34658]:
 *  Since
 *      r*(exp(r)+1)/(exp(r)-1) = 2+ r^2/6 - r^4/360 + ...
 *  we define R1(r*r) by
 *      r*(exp(r)+1)/(exp(r)-1) = 2+ r^2/6 * R1(r*r)
 *  That is,
 *      R1(r**2) = 6/r *((exp(r)+1)/(exp(r)-1) - 2/r)
 *         = 6/r * ( 1 + 2.0*(1/(exp(r)-1) - 1/r))
 *         = 1 - r^2/60 + r^4/2520 - r^6/100800 + ...
 *      We use a special Reme algorithm on [0,0.347] to generate
 *   a polynomial of degree 5 in r*r to approximate R1. The
 *  maximum error of this polynomial approximation is bounded
 *  by 2**-61. In other words,
 *      R1(z) ~ 1.0 + Q1*z + Q2*z**2 + Q3*z**3 + Q4*z**4 + Q5*z**5
 *  where   Q1  =  -1.6666666666666567384E-2,
 *     Q2  =   3.9682539681370365873E-4,
 *     Q3  =  -9.9206344733435987357E-6,
 *     Q4  =   2.5051361420808517002E-7,
 *     Q5  =  -6.2843505682382617102E-9;
 *    z   =  r*r,
 *  with error bounded by
 *      |                  5           |     -61
 *      | 1.0+Q1*z+...+Q5*z   -  R1(z) | <= 2
 *      |                              |
 *
 *  expm1(r) = exp(r)-1 is then computed by the following
 *   specific way which minimize the accumulation rounding error:
 *             2     3
 *            r     r    [ 3 - (R1 + R1*r/2)  ]
 *        expm1(r) = r + --- + --- * [--------------------]
 *                  2     2    [ 6 - r*(3 - R1*r/2) ]
 *
 *  To compensate the error in the argument reduction, we use
 *    expm1(r+c) = expm1(r) + c + expm1(r)*c
 *         ~ expm1(r) + c + r*c
 *  Thus c+r*c will be added in as the correction terms for
 *  expm1(r+c). Now rearrange the term to avoid optimization
 *   screw up:
 *            (      2                                    2 )
 *            ({  ( r    [ R1 -  (3 - R1*r/2) ]  )  }    r  )
 *   expm1(r+c)~r - ({r*(--- * [--------------------]-c)-c} - --- )
 *                  ({  ( 2    [ 6 - r*(3 - R1*r/2) ]  )  }    2  )
 *                      (                                             )
 *
 *       = r - E
 *   3. Scale back to obtain expm1(x):
 *  From step 1, we have
 *     expm1(x) = either 2^k*[expm1(r)+1] - 1
 *        = or     2^k*[expm1(r) + (1-2^-k)]
 *   4. Implementation notes:
 *  (A). To save one multiplication, we scale the coefficient Qi
 *       to Qi*2^i, and replace z by (x^2)/2.
 *  (B). To achieve maximum accuracy, we compute expm1(x) by
 *    (i)   if x < -56*ln2, return -1.0, (raise inexact if x!=inf)
 *    (ii)  if k=0, return r-E
 *    (iii) if k=-1, return 0.5*(r-E)-0.5
 *        (iv)  if k=1 if r < -0.25, return 2*((r+0.5)- E)
 *                  else       return  1.0+2.0*(r-E);
 *    (v)   if (k<-2||k>56) return 2^k(1-(E-r)) - 1 (or exp(x)-1)
 *    (vi)  if k <= 20, return 2^k((1-2^-k)-(E-r)), else
 *    (vii) return 2^k(1-((E+2^-k)-r))
 *
 * Special cases:
 *  expm1(INF) is INF, expm1(NaN) is NaN;
 *  expm1(-INF) is -1, and
 *  for finite argument, only expm1(0)=0 is exact.
 *
 * Accuracy:
 *  according to an error analysis, the error is always less than
 *  1 ulp (unit in the last place).
 *
 * Misc. info.
 *  For IEEE double
 *      if x >  7.09782712893383973096e+02 then expm1(x) overflow
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following
 * constants. The decimal values may be used, provided that the
 * compiler will convert from decimal to binary accurately enough
 * to produce the hexadecimal values shown.
 */
double expm1(double x) {
  static const double
      one = 1.0,
      tiny = 1.0e-300,
      o_threshold = 7.09782712893383973096e+02, /* 0x40862E42, 0xFEFA39EF */
      ln2_hi = 6.93147180369123816490e-01,      /* 0x3FE62E42, 0xFEE00000 */
      ln2_lo = 1.90821492927058770002e-10,      /* 0x3DEA39EF, 0x35793C76 */
      invln2 = 1.44269504088896338700e+00,      /* 0x3FF71547, 0x652B82FE */
      /* Scaled Q's: Qn_here = 2**n * Qn_above, for R(2*z) where z = hxs =
         x*x/2: */
      Q1 = -3.33333333333331316428e-02, /* BFA11111 111110F4 */
      Q2 = 1.58730158725481460165e-03,  /* 3F5A01A0 19FE5585 */
      Q3 = -7.93650757867487942473e-05, /* BF14CE19 9EAADBB7 */
      Q4 = 4.00821782732936239552e-06,  /* 3ED0CFCA 86E65239 */
      Q5 = -2.01099218183624371326e-07; /* BE8AFDB7 6E09C32D */

  static volatile double huge = 1.0e+300;

  double y, hi, lo, c, t, e, hxs, hfx, r1, twopk;
  int32_t k, xsb;
  uint32_t hx;

  GET_HIGH_WORD(hx, x);
  xsb = hx & 0x80000000; /* sign bit of x */
  hx &= 0x7FFFFFFF;      /* high word of |x| */

  /* filter out huge and non-finite argument */
  if (hx >= 0x4043687A) {   /* if |x|>=56*ln2 */
    if (hx >= 0x40862E42) { /* if |x|>=709.78... */
      if (hx >= 0x7FF00000) {
        uint32_t low;
        GET_LOW_WORD(low, x);
        if (((hx & 0xFFFFF) | low) != 0)
          return x + x; /* NaN */
        else
          return (xsb == 0) ? x : -1.0; /* exp(+-inf)={inf,-1} */
      }
      if (x > o_threshold) return huge * huge; /* overflow */
    }
    if (xsb != 0) {        /* x < -56*ln2, return -1.0 with inexact */
      if (x + tiny < 0.0)  /* raise inexact */
        return tiny - one; /* return -1 */
    }
  }

  /* argument reduction */
  if (hx > 0x3FD62E42) {   /* if  |x| > 0.5 ln2 */
    if (hx < 0x3FF0A2B2) { /* and |x| < 1.5 ln2 */
      if (xsb == 0) {
        hi = x - ln2_hi;
        lo = ln2_lo;
        k = 1;
      } else {
        hi = x + ln2_hi;
        lo = -ln2_lo;
        k = -1;
      }
    } else {
      k = invln2 * x + ((xsb == 0) ? 0.5 : -0.5);
      t = k;
      hi = x - t * ln2_hi; /* t*ln2_hi is exact here */
      lo = t * ln2_lo;
    }
    x = hi - lo;
    c = (hi - x) - lo;
  } else if (hx < 0x3C900000) { /* when |x|<2**-54, return x */
    t = huge + x;               /* return x with inexact flags when x!=0 */
    return x - (t - (huge + x));
  } else {
    k = 0;
  }

  /* x is now in primary range */
  hfx = 0.5 * x;
  hxs = x * hfx;
  r1 = one + hxs * (Q1 + hxs * (Q2 + hxs * (Q3 + hxs * (Q4 + hxs * Q5))));
  t = 3.0 - r1 * hfx;
  e = hxs * ((r1 - t) / (6.0 - x * t));
  if (k == 0) {
    return x - (x * e - hxs); /* c is 0 */
  } else {
    INSERT_WORDS(
        twopk,
        0x3FF00000 + static_cast<int32_t>(static_cast<uint32_t>(k) << 20),
        0); /* 2^k */
    e = (x * (e - c) - c);
    e -= hxs;
    if (k == -1) return 0.5 * (x - e) - 0.5;
    if (k == 1) {
      if (x < -0.25)
        return -2.0 * (e - (x + 0.5));
      else
        return one + 2.0 * (x - e);
    }
    if (k <= -2 || k > 56) { /* suffice to return exp(x)-1 */
      y = one - (e - x);
      // TODO(mvstanton): is this replacement for the hex float
      // sufficient?
      // if (k == 1024) y = y*2.0*0x1p1023;
      if (k == 1024)
        y = y * 2.0 * 8.98846567431158e+307;
      else
        y = y * twopk;
      return y - one;
    }
    t = one;
    if (k < 20) {
      SET_HIGH_WORD(t, 0x3FF00000 - (0x200000 >> k)); /* t=1-2^-k */
      y = t - (e - x);
      y = y * twopk;
    } else {
      SET_HIGH_WORD(t, ((0x3FF - k) << 20)); /* 2^-k */
      y = x - (e + t);
      y += one;
      y = y * twopk;
    }
  }
  return y;
}

double cbrt(double x) {
  static const uint32_t
      B1 = 715094163, /* B1 = (1023-1023/3-0.03306235651)*2**20 */
      B2 = 696219795; /* B2 = (1023-1023/3-54/3-0.03306235651)*2**20 */

  /* |1/cbrt(x) - p(x)| < 2**-23.5 (~[-7.93e-8, 7.929e-8]). */
  static const double P0 = 1.87595182427177009643, /* 0x3FFE03E6, 0x0F61E692 */
      P1 = -1.88497979543377169875,                /* 0xBFFE28E0, 0x92F02420 */
      P2 = 1.621429720105354466140,                /* 0x3FF9F160, 0x4A49D6C2 */
      P3 = -0.758397934778766047437,               /* 0xBFE844CB, 0xBEE751D9 */
      P4 = 0.145996192886612446982;                /* 0x3FC2B000, 0xD4E4EDD7 */

  int32_t hx;
  double r, s, t = 0.0, w;
  uint32_t sign;
  uint32_t high, low;

  EXTRACT_WORDS(hx, low, x);
  sign = hx & 0x80000000; /* sign= sign(x) */
  hx ^= sign;
  if (hx >= 0x7FF00000) return (x + x); /* cbrt(NaN,INF) is itself */

  /*
   * Rough cbrt to 5 bits:
   *    cbrt(2**e*(1+m) ~= 2**(e/3)*(1+(e%3+m)/3)
   * where e is integral and >= 0, m is real and in [0, 1), and "/" and
   * "%" are integer division and modulus with rounding towards minus
   * infinity.  The RHS is always >= the LHS and has a maximum relative
   * error of about 1 in 16.  Adding a bias of -0.03306235651 to the
   * (e%3+m)/3 term reduces the error to about 1 in 32. With the IEEE
   * floating point representation, for finite positive normal values,
   * ordinary integer division of the value in bits magically gives
   * almost exactly the RHS of the above provided we first subtract the
   * exponent bias (1023 for doubles) and later add it back.  We do the
   * subtraction virtually to keep e >= 0 so that ordinary integer
   * division rounds towards minus infinity; this is also efficient.
   */
  if (hx < 0x00100000) {             /* zero or subnormal? */
    if ((hx | low) == 0) return (x); /* cbrt(0) is itself */
    SET_HIGH_WORD(t, 0x43500000);    /* set t= 2**54 */
    t *= x;
    GET_HIGH_WORD(high, t);
    INSERT_WORDS(t, sign | ((high & 0x7FFFFFFF) / 3 + B2), 0);
  } else {
    INSERT_WORDS(t, sign | (hx / 3 + B1), 0);
  }

  /*
   * New cbrt to 23 bits:
   *    cbrt(x) = t*cbrt(x/t**3) ~= t*P(t**3/x)
   * where P(r) is a polynomial of degree 4 that approximates 1/cbrt(r)
   * to within 2**-23.5 when |r - 1| < 1/10.  The rough approximation
   * has produced t such than |t/cbrt(x) - 1| ~< 1/32, and cubing this
   * gives us bounds for r = t**3/x.
   *
   * Try to optimize for parallel evaluation as in k_tanf.c.
   */
  r = (t * t) * (t / x);
  t = t * ((P0 + r * (P1 + r * P2)) + ((r * r) * r) * (P3 + r * P4));

  /*
   * Round t away from zero to 23 bits (sloppily except for ensuring that
   * the result is larger in magnitude than cbrt(x) but not much more than
   * 2 23-bit ulps larger).  With rounding towards zero, the error bound
   * would be ~5/6 instead of ~4/6.  With a maximum error of 2 23-bit ulps
   * in the rounded t, the infinite-precision error in the Newton
   * approximation barely affects third digit in the final error
   * 0.667; the error in the rounded t can be up to about 3 23-bit ulps
   * before the final error is larger than 0.667 ulps.
   */
  uint64_t bits = base::bit_cast<uint64_t>(t);
  bits = (bits + 0x80000000) & 0xFFFFFFFFC0000000ULL;
  t = base::bit_cast<double>(bits);

  /* one step Newton iteration to 53 bits with error < 0.667 ulps */
  s = t * t;             /* t*t is exact */
  r = x / s;             /* error <= 0.5 ulps; |r| < |t| */
  w = t + t;             /* t+t is exact */
  r = (r - t) / (w + r); /* r-t is exact; w+r ~= 3*t */
  t = t + t * r;         /* error <= 0.5 + 0.5/3 + epsilon */

  return (t);
}

/* sin(x)
 * Return sine function of x.
 *
 * kernel function:
 *      __kernel_sin            ... sine function on [-pi/4,pi/4]
 *      __kernel_cos            ... cose function on [-pi/4,pi/4]
 *      __ieee754_rem_pio2      ... argument reduction routine
 *
 * Method.
 *      Let S,C and T denote the sin, cos and tan respectively on
 *      [-PI/4, +PI/4]. Reduce the argument x to y1+y2 = x-k*pi/2
 *      in [-pi/4 , +pi/4], and let n = k mod 4.
 *      We have
 *
 *          n        sin(x)      cos(x)        tan(x)
 *     ----------------------------------------------------------
 *          0          S           C             T
 *          1          C          -S            -1/T
 *          2         -S          -C             T
 *          3         -C           S            -1/T
 *     ----------------------------------------------------------
 *
 * Special cases:
 *      Let trig be any of sin, cos, or tan.
 *      trig(+-INF)  is NaN, with signals;
 *      trig(NaN)    is that NaN;
 *
 * Accuracy:
 *      TRIG(x) returns trig(x) nearly rounded
 */
#if defined(V8_USE_LIBM_TRIG_FUNCTIONS)
double fdlibm_sin(double x) {
#else
double sin(double x) {
#endif
  double y[2], z = 0.0;
  int32_t n, ix;

  /* High word of x. */
  GET_HIGH_WORD(ix, x);

  /* |x| ~< pi/4 */
  ix &= 0x7FFFFFFF;
  if (ix <= 0x3FE921FB) {
    return __kernel_sin(x, z, 0);
  } else if (ix >= 0x7FF00000) {
    /* sin(Inf or NaN) is NaN */
    return x - x;
  } else {
    /* argument reduction needed */
    n = __ieee754_rem_pio2(x, y);
    switch (n & 3) {
      case 0:
        return __kernel_sin(y[0], y[1], 1);
      case 1:
        return __kernel_cos(y[0], y[1]);
      case 2:
        return -__kernel_sin(y[0], y[1], 1);
      default:
        return -__kernel_cos(y[0], y[1]);
    }
  }
}

/* tan(x)
 * Return tangent function of x.
 *
 * kernel function:
 *      __kernel_tan            ... tangent function on [-pi/4,pi/4]
 *      __ieee754_rem_pio2      ... argument reduction routine
 *
 * Method.
 *      Let S,C and T denote the sin, cos and tan respectively on
 *      [-PI/4, +PI/4]. Reduce the argument x to y1+y2 = x-k*pi/2
 *      in [-pi/4 , +pi/4], and let n = k mod 4.
 *      We have
 *
 *          n        sin(x)      cos(x)        tan(x)
 *     ----------------------------------------------------------
 *          0          S           C             T
 *          1          C          -S            -1/T
 *          2         -S          -C             T
 *          3         -C           S            -1/T
 *     ----------------------------------------------------------
 *
 * Special cases:
 *      Let trig be any of sin, cos, or tan.
 *      trig(+-INF)  is NaN, with signals;
 *      trig(NaN)    is that NaN;
 *
 * Accuracy:
 *      TRIG(x) returns trig(x) nearly rounded
 */
double tan(double x) {
  double y[2], z = 0.0;
  int32_t n, ix;

  /* High word of x. */
  GET_HIGH_WORD(ix, x);

  /* |x| ~< pi/4 */
  ix &= 0x7FFFFFFF;
  if (ix <= 0x3FE921FB) {
    return __kernel_tan(x, z, 1);
  } else if (ix >= 0x7FF00000) {
    /* tan(Inf or NaN) is NaN */
    return x - x; /* NaN */
  } else {
    /* argument reduction needed */
    n = __ieee754_rem_pio2(x, y);
    /* 1 -> n even, -1 -> n odd */
    return __kernel_tan(y[0], y[1], 1 - ((n & 1) << 1));
  }
}

/*
 * ES6 draft 09-27-13, section 20.2.2.12.
 * Math.cosh
 * Method :
 * mathematically cosh(x) if defined to be (exp(x)+exp(-x))/2
 *      1. Replace x by |x| (cosh(x) = cosh(-x)).
 *      2.
 *                                                      [ exp(x) - 1 ]^2
 *          0        <= x <= ln2/2  :  cosh(x) := 1 + -------------------
 *                                                         2*exp(x)
 *
 *                                                 exp(x) + 1/exp(x)
 *          ln2/2    <= x <= 22     :  cosh(x) := -------------------
 *                                                        2
 *          22       <= x <= lnovft :  cosh(x) := exp(x)/2
 *          lnovft   <= x <= ln2ovft:  cosh(x) := exp(x/2)/2 * exp(x/2)
 *          ln2ovft  <  x           :  cosh(x) := huge*huge (overflow)
 *
 * Special cases:
 *      cosh(x) is |x| if x is +INF, -INF, or NaN.
 *      only cosh(0)=1 is exact for finite x.
 */
double cosh(double x) {
  static const double KCOSH_OVERFLOW = 710.4758600739439;
  static const double one = 1.0, half = 0.5;
  static volatile double huge = 1.0e+300;

  int32_t ix;

  /* High word of |x|. */
  GET_HIGH_WORD(ix, x);
  ix &= 0x7FFFFFFF;

  // |x| in [0,0.5*log2], return 1+expm1(|x|)^2/(2*exp(|x|))
  if (ix < 0x3FD62E43) {
    double t = expm1(fabs(x));
    double w = one + t;
    // For |x| < 2^-55, cosh(x) = 1
    if (ix < 0x3C800000) return w;
    return one + (t * t) / (w + w);
  }

  // |x| in [0.5*log2, 22], return (exp(|x|)+1/exp(|x|)/2
  if (ix < 0x40360000) {
    double t = exp(fabs(x));
    return half * t + half / t;
  }

  // |x| in [22, log(maxdouble)], return half*exp(|x|)
  if (ix < 0x40862E42) return half * exp(fabs(x));

  // |x| in [log(maxdouble), overflowthreshold]
  if (fabs(x) <= KCOSH_OVERFLOW) {
    double w = exp(half * fabs(x));
    double t = half * w;
    return t * w;
  }

  /* x is INF or NaN */
  if (ix >= 0x7FF00000) return x * x;

  // |x| > overflowthreshold.
  return huge * huge;
}

namespace legacy {
/*
 * ES2019 Draft 2019-01-02 12.6.4
 * Math.pow & Exponentiation Operator
 *
 * Return X raised to the Yth power
 *
 * Method:
 *     Let x =  2   * (1+f)
 *     1. Compute and return log2(x) in two pieces:
 *        log2(x) = w1 + w2,
 *        where w1 has 53-24 = 29 bit trailing zeros.
 *     2. Perform y*log2(x) = n+y' by simulating muti-precision
 *        arithmetic, where |y'|<=0.5.
 *     3. Return x**y = 2**n*exp(y'*log2)
 *
 * Special cases:
 *     1.  (anything) ** 0  is 1
 *     2.  (anything) ** 1  is itself
 *     3.  (anything) ** NAN is NAN
 *     4.  NAN ** (anything except 0) is NAN
 *     5.  +-(|x| > 1) **  +INF is +INF
 *     6.  +-(|x| > 1) **  -INF is +0
 *     7.  +-(|x| < 1) **  +INF is +0
 *     8.  +-(|x| < 1) **  -INF is +INF
 *     9.  +-1         ** +-INF is NAN
 *     10. +0 ** (+anything except 0, NAN)               is +0
 *     11. -0 ** (+anything except 0, NAN, odd integer)  is +0
 *     12. +0 ** (-anything except 0, NAN)               is +INF
 *     13. -0 ** (-anything except 0, NAN, odd integer)  is +INF
 *     14. -0 ** (odd integer) = -( +0 ** (odd integer) )
 *     15. +INF ** (+anything except 0,NAN) is +INF
 *     16. +INF ** (-anything except 0,NAN) is +0
 *     17. -INF ** (anything)  = -0 ** (-anything)
 *     18. (-anything) ** (integer) is (-1)**(integer)*(+anything**integer)
 *     19. (-anything except 0 and inf) ** (non-integer) is NAN
 *
 * Accuracy:
 *      pow(x,y) returns x**y nearly rounded. In particular,
 *      pow(integer, integer) always returns the correct integer provided it is
 *      representable.
 *
 * Constants:
 *     The hexadecimal values are the intended ones for the following
 *     constants. The decimal values may be used, provided that the
 *     compiler will convert from decimal to binary accurately enough
 *     to produce the hexadecimal values shown.
 */

double pow(double x, double y) {
  static const double
      bp[] = {1.0, 1.5},
      dp_h[] = {0.0, 5.84962487220764160156e-01},  // 0x3FE2B803, 0x40000000
      dp_l[] = {0.0, 1.35003920212974897128e-08},  // 0x3E4CFDEB, 0x43CFD006
      zero = 0.0, one = 1.0, two = 2.0,
      two53 = 9007199254740992.0,  // 0x43400000, 0x00000000
      huge = 1.0e300, tiny = 1.0e-300,
      // poly coefs for (3/2)*(log(x)-2s-2/3*s**3
      L1 = 5.99999999999994648725e-01,      // 0x3FE33333, 0x33333303
      L2 = 4.28571428578550184252e-01,      // 0x3FDB6DB6, 0xDB6FABFF
      L3 = 3.33333329818377432918e-01,      // 0x3FD55555, 0x518F264D
      L4 = 2.72728123808534006489e-01,      // 0x3FD17460, 0xA91D4101
      L5 = 2.30660745775561754067e-01,      // 0x3FCD864A, 0x93C9DB65
      L6 = 2.06975017800338417784e-01,      // 0x3FCA7E28, 0x4A454EEF
      P1 = 1.66666666666666019037e-01,      // 0x3FC55555, 0x5555553E
      P2 = -2.77777777770155933842e-03,     // 0xBF66C16C, 0x16BEBD93
      P3 = 6.61375632143793436117e-05,      // 0x3F11566A, 0xAF25DE2C
      P4 = -1.65339022054652515390e-06,     // 0xBEBBBD41, 0xC5D26BF1
      P5 = 4.13813679705723846039e-08,      // 0x3E663769, 0x72BEA4D0
      lg2 = 6.93147180559945286227e-01,     // 0x3FE62E42, 0xFEFA39EF
      lg2_h = 6.93147182464599609375e-01,   // 0x3FE62E43, 0x00000000
      lg2_l = -1.90465429995776804525e-09,  // 0xBE205C61, 0x0CA86C39
      ovt = 8.0085662595372944372e-0017,    // -(1024-log2(ovfl+.5ulp))
      cp = 9.61796693925975554329e-01,      // 0x3FEEC709, 0xDC3A03FD =2/(3ln2)
      cp_h = 9.61796700954437255859e-01,    // 0x3FEEC709, 0xE0000000 =(float)cp
      cp_l = -7.02846165095275826516e-09,   // 0xBE3E2FE0, 0x145B01F5 =tail cp_h
      ivln2 = 1.44269504088896338700e+00,   // 0x3FF71547, 0x652B82FE =1/ln2
      ivln2_h =
          1.44269502162933349609e+00,  // 0x3FF71547, 0x60000000 =24b 1/ln2
      ivln2_l =
          1.92596299112661746887e-08;  // 0x3E54AE0B, 0xF85DDF44 =1/ln2 tail

  double z, ax, z_h, z_l, p_h, p_l;
  double y1, t1, t2, r, s, t, u, v, w;
  int i, j, k, yisint, n;
  int hx, hy, ix, iy;
  unsigned lx, ly;

  EXTRACT_WORDS(hx, lx, x);
  EXTRACT_WORDS(hy, ly, y);
  ix = hx & 0x7fffffff;
  iy = hy & 0x7fffffff;

  /* y==zero: x**0 = 1 */
  if ((iy | ly) == 0) return one;

  /* +-NaN return x+y */
  if (ix > 0x7ff00000 || ((ix == 0x7ff00000) && (lx != 0)) || iy > 0x7ff00000 ||
      ((iy == 0x7ff00000) && (ly != 0))) {
    return x + y;
  }

  /* determine if y is an odd int when x < 0
   * yisint = 0 ... y is not an integer
   * yisint = 1 ... y is an odd int
   * yisint = 2 ... y is an even int
   */
  yisint = 0;
  if (hx < 0) {
    if (iy >= 0x43400000) {
      yisint = 2; /* even integer y */
    } else if (iy >= 0x3ff00000) {
      k = (iy >> 20) - 0x3ff; /* exponent */
      if (k > 20) {
        j = ly >> (52 - k);
        if ((j << (52 - k)) == static_cast<int>(ly)) yisint = 2 - (j & 1);
      } else if (ly == 0) {
        j = iy >> (20 - k);
        if ((j << (20 - k)) == iy) yisint = 2 - (j & 1);
      }
    }
  }

  /* special value of y */
  if (ly == 0) {
    if (iy == 0x7ff00000) { /* y is +-inf */
      if (((ix - 0x3ff00000) | lx) == 0) {
        return y - y;                /* inf**+-1 is NaN */
      } else if (ix >= 0x3ff00000) { /* (|x|>1)**+-inf = inf,0 */
        return (hy >= 0) ? y : zero;
      } else { /* (|x|<1)**-,+inf = inf,0 */
        return (hy < 0) ? -y : zero;
      }
    }
    if (iy == 0x3ff00000) { /* y is  +-1 */
      if (hy < 0) {
        return base::Divide(one, x);
      } else {
        return x;
      }
    }
    if (hy == 0x40000000) return x * x; /* y is  2 */
    if (hy == 0x3fe00000) {             /* y is  0.5 */
      if (hx >= 0) {                    /* x >= +0 */
        return sqrt(x);
      }
    }
  }

  ax = fabs(x);
  /* special value of x */
  if (lx == 0) {
    if (ix == 0x7ff00000 || ix == 0 || ix == 0x3ff00000) {
      z = ax;                               /*x is +-0,+-inf,+-1*/
      if (hy < 0) z = base::Divide(one, z); /* z = (1/|x|) */
      if (hx < 0) {
        if (((ix - 0x3ff00000) | yisint) == 0) {
          /* (-1)**non-int is NaN */
          z = std::numeric_limits<double>::signaling_NaN();
        } else if (yisint == 1) {
          z = -z; /* (x<0)**odd = -(|x|**odd) */
        }
      }
      return z;
    }
  }

  n = (hx >> 31) + 1;

  /* (x<0)**(non-int) is NaN */
  if ((n | yisint) == 0) {
    return std::numeric_limits<double>::signaling_NaN();
  }

  s = one; /* s (sign of result -ve**odd) = -1 else = 1 */
  if ((n | (yisint - 1)) == 0) s = -one; /* (-ve)**(odd int) */

  /* |y| is huge */
  if (iy > 0x41e00000) {   /* if |y| > 2**31 */
    if (iy > 0x43f00000) { /* if |y| > 2**64, must o/uflow */
      if (ix <= 0x3fefffff) return (hy < 0) ? huge * huge : tiny * tiny;
      if (ix >= 0x3ff00000) return (hy > 0) ? huge * huge : tiny * tiny;
    }
    /* over/underflow if x is not close to one */
    if (ix < 0x3fefffff) return (hy < 0) ? s * huge * huge : s * tiny * tiny;
    if (ix > 0x3ff00000) return (hy > 0) ? s * huge * huge : s * tiny * tiny;
    /* now |1-x| is tiny <= 2**-20, suffice to compute
       log(x) by x-x^2/2+x^3/3-x^4/4 */
    t = ax - one; /* t has 20 trailing zeros */
    w = (t * t) * (0.5 - t * (0.3333333333333333333333 - t * 0.25));
    u = ivln2_h * t; /* ivln2_h has 21 sig. bits */
    v = t * ivln2_l - w * ivln2;
    t1 = u + v;
    SET_LOW_WORD(t1, 0);
    t2 = v - (t1 - u);
  } else {
    double ss, s2, s_h, s_l, t_h, t_l;
    n = 0;
    /* take care subnormal number */
    if (ix < 0x00100000) {
      ax *= two53;
      n -= 53;
      GET_HIGH_WORD(ix, ax);
    }
    n += ((ix) >> 20) - 0x3ff;
    j = ix & 0x000fffff;
    /* determine interval */
    ix = j | 0x3ff00000; /* normalize ix */
    if (j <= 0x3988E) {
      k = 0; /* |x|<sqrt(3/2) */
    } else if (j < 0xBB67A) {
      k = 1; /* |x|<sqrt(3)   */
    } else {
      k = 0;
      n += 1;
      ix -= 0x00100000;
    }
    SET_HIGH_WORD(ax, ix);

    /* compute ss = s_h+s_l = (x-1)/(x+1) or (x-1.5)/(x+1.5) */
    u = ax - bp[k]; /* bp[0]=1.0, bp[1]=1.5 */
    v = base::Divide(one, ax + bp[k]);
    ss = u * v;
    s_h = ss;
    SET_LOW_WORD(s_h, 0);
    /* t_h=ax+bp[k] High */
    t_h = zero;
    SET_HIGH_WORD(t_h, ((ix >> 1) | 0x20000000) + 0x00080000 + (k << 18));
    t_l = ax - (t_h - bp[k]);
    s_l = v * ((u - s_h * t_h) - s_h * t_l);
    /* compute log(ax) */
    s2 = ss * ss;
    r = s2 * s2 *
        (L1 + s2 * (L2 + s2 * (L3 + s2 * (L4 + s2 * (L5 + s2 * L6)))));
    r += s_l * (s_h + ss);
    s2 = s_h * s_h;
    t_h = 3.0 + s2 + r;
    SET_LOW_WORD(t_h, 0);
    t_l = r - ((t_h - 3.0) - s2);
    /* u+v = ss*(1+...) */
    u = s_h * t_h;
    v = s_l * t_h + t_l * ss;
    /* 2/(3log2)*(ss+...) */
    p_h = u + v;
    SET_LOW_WORD(p_h, 0);
    p_l = v - (p_h - u);
    z_h = cp_h * p_h; /* cp_h+cp_l = 2/(3*log2) */
    z_l = cp_l * p_h + p_l * cp + dp_l[k];
    /* log2(ax) = (ss+..)*2/(3*log2) = n + dp_h + z_h + z_l */
    t = static_cast<double>(n);
    t1 = (((z_h + z_l) + dp_h[k]) + t);
    SET_LOW_WORD(t1, 0);
    t2 = z_l - (((t1 - t) - dp_h[k]) - z_h);
  }

  /* split up y into y1+y2 and compute (y1+y2)*(t1+t2) */
  y1 = y;
  SET_LOW_WORD(y1, 0);
  p_l = (y - y1) * t1 + y * t2;
  p_h = y1 * t1;
  z = p_l + p_h;
  EXTRACT_WORDS(j, i, z);
  if (j >= 0x40900000) {               /* z >= 1024 */
    if (((j - 0x40900000) | i) != 0) { /* if z > 1024 */
      return s * huge * huge;          /* overflow */
    } else {
      if (p_l + ovt > z - p_h) return s * huge * huge; /* overflow */
    }
  } else if ((j & 0x7fffffff) >= 0x4090cc00) { /* z <= -1075 */
    if (((j - 0xc090cc00) | i) != 0) {         /* z < -1075 */
      return s * tiny * tiny;                  /* underflow */
    } else {
      if (
```