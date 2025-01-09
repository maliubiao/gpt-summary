Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/base/ieee754.cc`. The summary should also address specific points: whether it's related to JavaScript, provide JavaScript examples if so, discuss potential programming errors, and handle the case where the file might be a Torque file (though it isn't based on the `.cc` extension).

Here's a breakdown of the code's functionality and how to address the user's requests:

1. **Identify the core purpose:** The code implements various mathematical functions, mostly related to IEEE 754 floating-point arithmetic. These include `asin`, `asinh`, `atan`, `atan2`, `cos`, `exp`, `atanh`, `log`, and `log1p`.

2. **Address the `.tq` question:**  Since the file extension is `.cc`, it's not a Torque file. State this clearly.

3. **JavaScript relationship:** These functions are fundamental building blocks for JavaScript's `Math` object. Provide concrete JavaScript examples using the `Math` object that correspond to the implemented C++ functions.

4. **Code logic and I/O:** For a few representative functions, outline the core logic and give example inputs and expected outputs. Focus on demonstrating the function's purpose.

5. **Common programming errors:** Think about how incorrect usage of these functions in JavaScript could lead to errors or unexpected results. Examples include passing invalid inputs (out-of-range values for `asin`, negative values for `log`, etc.) or misunderstanding the behavior of edge cases (like `atan2` with infinities or zeros).

6. **Overall Functionality Summary:**  Provide a concise summary encapsulating the main purpose of the code.

7. **Structure for the response:** Organize the information clearly into sections addressing each of the user's requests.
这是 `v8/src/base/ieee754.cc` 源代码的第二部分，主要包含了一系列实现 IEEE 754 标准中规定的常用数学函数的 C++ 代码。这些函数用于处理 `double` 类型的浮点数，提供了精确的数学运算。

**功能归纳:**

这部分代码的主要功能是实现了以下 IEEE 754 标准中定义的数学函数，用于 `double` 类型的浮点数运算：

* **反三角函数:**
    * `asin(double x)`: 反正弦函数，计算给定值的反正弦值。
    * `atan(double x)`: 反正切函数，计算给定值的反正切值。
    * `atan2(double y, double x)`:  四象限反正切函数，计算 y/x 的反正切值，并根据 x 和 y 的符号确定返回值所在的象限。
    * `asinh(double x)`: 反双曲正弦函数，计算给定值的反双曲正弦值。
    * `atanh(double x)`: 反双曲正切函数，计算给定值的反双曲正切值。

* **三角函数:**
    * `cos(double x)`: 余弦函数，计算给定角度的余弦值。

* **指数和对数函数:**
    * `exp(double x)`: 指数函数，计算 e 的 x 次方。
    * `log(double x)`: 自然对数函数，计算给定值的自然对数。
    * `log1p(double x)`:  计算 1 + x 的自然对数，在 x 接近 0 时能提供更高的精度。

**与 JavaScript 的关系:**

这部分代码实现的数学函数直接对应于 JavaScript 中 `Math` 对象的方法。当 JavaScript 代码调用 `Math.sin()`, `Math.cos()`, `Math.log()`, `Math.asin()`, `Math.atan2()` 等方法时，V8 引擎很可能会调用 `v8/src/base/ieee754.cc` 中实现的相应 C++ 函数来进行底层的浮点数运算。

**JavaScript 举例说明:**

```javascript
// 调用 C++ 中的 asin 函数
let result_asin = Math.asin(0.5);
console.log("Math.asin(0.5):", result_asin); // 输出接近 0.5235987755982989

// 调用 C++ 中的 atan2 函数
let result_atan2 = Math.atan2(1, 1);
console.log("Math.atan2(1, 1):", result_atan2); // 输出接近 0.7853981633974483

// 调用 C++ 中的 log 函数
let result_log = Math.log(Math.E);
console.log("Math.log(Math.E):", result_log); // 输出 1

// 调用 C++ 中的 exp 函数
let result_exp = Math.exp(1);
console.log("Math.exp(1):", result_exp); // 输出接近 2.718281828459045
```

**代码逻辑推理 (以 `asin(double x)` 为例):**

**假设输入:** `x = 0.5`

**逻辑推理:**

1. `ix` 会被设置为 `0x3FE00000` (0.5 的 IEEE 754 表示的高 32 位)。
2. 由于 `ix < 0x3FF00000` 且 `ix >= 0x3FE00000`，代码会进入 `|x|<0.5` 的分支。
3. `t` 会被计算为 `x * x = 0.25`。
4. `p` 和 `q` 是多项式近似计算的分子和分母，使用 `t` 的不同幂次进行计算。
5. `w` 被计算为 `p / q`。
6. 最终返回 `x + x * w`，这是反正弦函数的泰勒展开近似。

**预期输出:** 一个接近 `π/6` 的 `double` 值，约为 `0.5235987755982989`。

**假设输入:** `x = 2.0`

**逻辑推理:**

1. `ix` 会被设置为大于 `0x3FF00000` 的值。
2. 代码会进入 `|x|>= 1` 的分支。
3. 由于 `x > 1`，会返回 `std::numeric_limits<double>::signaling_NaN()`。

**预期输出:**  一个表示 NaN (Not a Number) 的 `double` 值。

**用户常见的编程错误举例说明:**

1. **`asin()` 函数的输入超出范围:**  `asin(x)` 的定义域是 `[-1, 1]`。如果用户传递的参数不在这个范围内，会返回 NaN。

    ```javascript
    let error_asin = Math.asin(2);
    console.log("Math.asin(2):", error_asin); // 输出 NaN
    ```

2. **`log()` 函数的输入为负数或零:** `log(x)` 的定义域是 `x > 0`。如果用户传递的参数小于等于 0，会返回 `-Infinity` 或 `NaN`。

    ```javascript
    let error_log_negative = Math.log(-1);
    console.log("Math.log(-1):", error_log_negative); // 输出 NaN

    let error_log_zero = Math.log(0);
    console.log("Math.log(0):", error_log_zero); // 输出 -Infinity
    ```

3. **`atanh()` 函数的输入超出范围:** `atanh(x)` 的定义域是 `(-1, 1)`。如果用户传递的参数不在这个范围内（包括 -1 和 1），会返回 NaN 或 +/-Infinity。

    ```javascript
    let error_atanh_greater_than_1 = Math.atanh(2);
    console.log("Math.atanh(2):", error_atanh_greater_than_1); // 输出 NaN

    let error_atanh_equal_to_1 = Math.atanh(1);
    console.log("Math.atanh(1):", error_atanh_equal_to_1); // 输出 Infinity
    ```

**关于 .tq 结尾:**

如果 `v8/src/base/ieee754.cc` 的文件名以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。 Torque 是一种用于为 V8 编写高性能运行时代码的领域特定语言。但是，由于这里的文件名是 `.cc`，它是一个标准的 C++ 源代码文件。

总而言之，这部分 `v8/src/base/ieee754.cc` 代码是 V8 引擎中实现基础数学运算的关键部分，直接支持了 JavaScript 中 `Math` 对象的许多方法。它遵循 IEEE 754 标准，力求提供精确可靠的浮点数运算。

Prompt: 
```
这是目录为v8/src/base/ieee754.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/ieee754.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
0.5] by
 *              asin(x) = x + x*x^2*R(x^2)
 *      where
 *              R(x^2) is a rational approximation of (asin(x)-x)/x^3
 *      and its remez error is bounded by
 *              |(asin(x)-x)/x^3 - R(x^2)| < 2^(-58.75)
 *
 *      For x in [0.5,1]
 *              asin(x) = pi/2-2*asin(sqrt((1-x)/2))
 *      Let y = (1-x), z = y/2, s := sqrt(z), and pio2_hi+pio2_lo=pi/2;
 *      then for x>0.98
 *              asin(x) = pi/2 - 2*(s+s*z*R(z))
 *                      = pio2_hi - (2*(s+s*z*R(z)) - pio2_lo)
 *      For x<=0.98, let pio4_hi = pio2_hi/2, then
 *              f = hi part of s;
 *              c = sqrt(z) - f = (z-f*f)/(s+f)         ...f+c=sqrt(z)
 *      and
 *              asin(x) = pi/2 - 2*(s+s*z*R(z))
 *                      = pio4_hi+(pio4-2s)-(2s*z*R(z)-pio2_lo)
 *                      = pio4_hi+(pio4-2f)-(2s*z*R(z)-(pio2_lo+2c))
 *
 * Special cases:
 *      if x is NaN, return x itself;
 *      if |x|>1, return NaN with invalid signal.
 */
double asin(double x) {
  static const double
      one = 1.00000000000000000000e+00, /* 0x3FF00000, 0x00000000 */
      huge = 1.000e+300,
      pio2_hi = 1.57079632679489655800e+00, /* 0x3FF921FB, 0x54442D18 */
      pio2_lo = 6.12323399573676603587e-17, /* 0x3C91A626, 0x33145C07 */
      pio4_hi = 7.85398163397448278999e-01, /* 0x3FE921FB, 0x54442D18 */
                                            /* coefficient for R(x^2) */
      pS0 = 1.66666666666666657415e-01,     /* 0x3FC55555, 0x55555555 */
      pS1 = -3.25565818622400915405e-01,    /* 0xBFD4D612, 0x03EB6F7D */
      pS2 = 2.01212532134862925881e-01,     /* 0x3FC9C155, 0x0E884455 */
      pS3 = -4.00555345006794114027e-02,    /* 0xBFA48228, 0xB5688F3B */
      pS4 = 7.91534994289814532176e-04,     /* 0x3F49EFE0, 0x7501B288 */
      pS5 = 3.47933107596021167570e-05,     /* 0x3F023DE1, 0x0DFDF709 */
      qS1 = -2.40339491173441421878e+00,    /* 0xC0033A27, 0x1C8A2D4B */
      qS2 = 2.02094576023350569471e+00,     /* 0x40002AE5, 0x9C598AC8 */
      qS3 = -6.88283971605453293030e-01,    /* 0xBFE6066C, 0x1B8D0159 */
      qS4 = 7.70381505559019352791e-02;     /* 0x3FB3B8C5, 0xB12E9282 */

  double t, w, p, q, c, r, s;
  int32_t hx, ix;

  t = 0;
  GET_HIGH_WORD(hx, x);
  ix = hx & 0x7FFFFFFF;
  if (ix >= 0x3FF00000) { /* |x|>= 1 */
    uint32_t lx;
    GET_LOW_WORD(lx, x);
    if (((ix - 0x3FF00000) | lx) == 0) { /* asin(1)=+-pi/2 with inexact */
      return x * pio2_hi + x * pio2_lo;
    }
    return std::numeric_limits<double>::signaling_NaN();  // asin(|x|>1) is NaN
  } else if (ix < 0x3FE00000) {     /* |x|<0.5 */
    if (ix < 0x3E400000) {          /* if |x| < 2**-27 */
      if (huge + x > one) return x; /* return x with inexact if x!=0*/
    } else {
      t = x * x;
    }
    p = t * (pS0 + t * (pS1 + t * (pS2 + t * (pS3 + t * (pS4 + t * pS5)))));
    q = one + t * (qS1 + t * (qS2 + t * (qS3 + t * qS4)));
    w = p / q;
    return x + x * w;
  }
  /* 1> |x|>= 0.5 */
  w = one - fabs(x);
  t = w * 0.5;
  p = t * (pS0 + t * (pS1 + t * (pS2 + t * (pS3 + t * (pS4 + t * pS5)))));
  q = one + t * (qS1 + t * (qS2 + t * (qS3 + t * qS4)));
  s = sqrt(t);
  if (ix >= 0x3FEF3333) { /* if |x| > 0.975 */
    w = p / q;
    t = pio2_hi - (2.0 * (s + s * w) - pio2_lo);
  } else {
    w = s;
    SET_LOW_WORD(w, 0);
    c = (t - w * w) / (s + w);
    r = p / q;
    p = 2.0 * s * r - (pio2_lo - 2.0 * c);
    q = pio4_hi - 2.0 * w;
    t = pio4_hi - (p - q);
  }
  if (hx > 0)
    return t;
  else
    return -t;
}
/* asinh(x)
 * Method :
 *      Based on
 *              asinh(x) = sign(x) * log [ |x| + sqrt(x*x+1) ]
 *      we have
 *      asinh(x) := x  if  1+x*x=1,
 *               := sign(x)*(log(x)+ln2)) for large |x|, else
 *               := sign(x)*log(2|x|+1/(|x|+sqrt(x*x+1))) if|x|>2, else
 *               := sign(x)*log1p(|x| + x^2/(1 + sqrt(1+x^2)))
 */
double asinh(double x) {
  static const double
      one = 1.00000000000000000000e+00, /* 0x3FF00000, 0x00000000 */
      ln2 = 6.93147180559945286227e-01, /* 0x3FE62E42, 0xFEFA39EF */
      huge = 1.00000000000000000000e+300;

  double t, w;
  int32_t hx, ix;
  GET_HIGH_WORD(hx, x);
  ix = hx & 0x7FFFFFFF;
  if (ix >= 0x7FF00000) return x + x; /* x is inf or NaN */
  if (ix < 0x3E300000) {              /* |x|<2**-28 */
    if (huge + x > one) return x;     /* return x inexact except 0 */
  }
  if (ix > 0x41B00000) { /* |x| > 2**28 */
    w = log(fabs(x)) + ln2;
  } else if (ix > 0x40000000) { /* 2**28 > |x| > 2.0 */
    t = fabs(x);
    w = log(2.0 * t + one / (sqrt(x * x + one) + t));
  } else { /* 2.0 > |x| > 2**-28 */
    t = x * x;
    w = log1p(fabs(x) + t / (one + sqrt(one + t)));
  }
  if (hx > 0) {
    return w;
  } else {
    return -w;
  }
}

/* atan(x)
 * Method
 *   1. Reduce x to positive by atan(x) = -atan(-x).
 *   2. According to the integer k=4t+0.25 chopped, t=x, the argument
 *      is further reduced to one of the following intervals and the
 *      arctangent of t is evaluated by the corresponding formula:
 *
 *      [0,7/16]      atan(x) = t-t^3*(a1+t^2*(a2+...(a10+t^2*a11)...)
 *      [7/16,11/16]  atan(x) = atan(1/2) + atan( (t-0.5)/(1+t/2) )
 *      [11/16.19/16] atan(x) = atan( 1 ) + atan( (t-1)/(1+t) )
 *      [19/16,39/16] atan(x) = atan(3/2) + atan( (t-1.5)/(1+1.5t) )
 *      [39/16,INF]   atan(x) = atan(INF) + atan( -1/t )
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following
 * constants. The decimal values may be used, provided that the
 * compiler will convert from decimal to binary accurately enough
 * to produce the hexadecimal values shown.
 */
double atan(double x) {
  static const double atanhi[] = {
      4.63647609000806093515e-01, /* atan(0.5)hi 0x3FDDAC67, 0x0561BB4F */
      7.85398163397448278999e-01, /* atan(1.0)hi 0x3FE921FB, 0x54442D18 */
      9.82793723247329054082e-01, /* atan(1.5)hi 0x3FEF730B, 0xD281F69B */
      1.57079632679489655800e+00, /* atan(inf)hi 0x3FF921FB, 0x54442D18 */
  };

  static const double atanlo[] = {
      2.26987774529616870924e-17, /* atan(0.5)lo 0x3C7A2B7F, 0x222F65E2 */
      3.06161699786838301793e-17, /* atan(1.0)lo 0x3C81A626, 0x33145C07 */
      1.39033110312309984516e-17, /* atan(1.5)lo 0x3C700788, 0x7AF0CBBD */
      6.12323399573676603587e-17, /* atan(inf)lo 0x3C91A626, 0x33145C07 */
  };

  static const double aT[] = {
      3.33333333333329318027e-01,  /* 0x3FD55555, 0x5555550D */
      -1.99999999998764832476e-01, /* 0xBFC99999, 0x9998EBC4 */
      1.42857142725034663711e-01,  /* 0x3FC24924, 0x920083FF */
      -1.11111104054623557880e-01, /* 0xBFBC71C6, 0xFE231671 */
      9.09088713343650656196e-02,  /* 0x3FB745CD, 0xC54C206E */
      -7.69187620504482999495e-02, /* 0xBFB3B0F2, 0xAF749A6D */
      6.66107313738753120669e-02,  /* 0x3FB10D66, 0xA0D03D51 */
      -5.83357013379057348645e-02, /* 0xBFADDE2D, 0x52DEFD9A */
      4.97687799461593236017e-02,  /* 0x3FA97B4B, 0x24760DEB */
      -3.65315727442169155270e-02, /* 0xBFA2B444, 0x2C6A6C2F */
      1.62858201153657823623e-02,  /* 0x3F90AD3A, 0xE322DA11 */
  };

  static const double one = 1.0, huge = 1.0e300;

  double w, s1, s2, z;
  int32_t ix, hx, id;

  GET_HIGH_WORD(hx, x);
  ix = hx & 0x7FFFFFFF;
  if (ix >= 0x44100000) { /* if |x| >= 2^66 */
    uint32_t low;
    GET_LOW_WORD(low, x);
    if (ix > 0x7FF00000 || (ix == 0x7FF00000 && (low != 0)))
      return x + x; /* NaN */
    if (hx > 0)
      return atanhi[3] + *const_cast<volatile double*>(&atanlo[3]);
    else
      return -atanhi[3] - *const_cast<volatile double*>(&atanlo[3]);
  }
  if (ix < 0x3FDC0000) {            /* |x| < 0.4375 */
    if (ix < 0x3E400000) {          /* |x| < 2^-27 */
      if (huge + x > one) return x; /* raise inexact */
    }
    id = -1;
  } else {
    x = fabs(x);
    if (ix < 0x3FF30000) {   /* |x| < 1.1875 */
      if (ix < 0x3FE60000) { /* 7/16 <=|x|<11/16 */
        id = 0;
        x = (2.0 * x - one) / (2.0 + x);
      } else { /* 11/16<=|x|< 19/16 */
        id = 1;
        x = (x - one) / (x + one);
      }
    } else {
      if (ix < 0x40038000) { /* |x| < 2.4375 */
        id = 2;
        x = (x - 1.5) / (one + 1.5 * x);
      } else { /* 2.4375 <= |x| < 2^66 */
        id = 3;
        x = -1.0 / x;
      }
    }
  }
  /* end of argument reduction */
  z = x * x;
  w = z * z;
  /* break sum from i=0 to 10 aT[i]z**(i+1) into odd and even poly */
  s1 = z * (aT[0] +
            w * (aT[2] + w * (aT[4] + w * (aT[6] + w * (aT[8] + w * aT[10])))));
  s2 = w * (aT[1] + w * (aT[3] + w * (aT[5] + w * (aT[7] + w * aT[9]))));
  if (id < 0) {
    return x - x * (s1 + s2);
  } else {
    z = atanhi[id] - ((x * (s1 + s2) - atanlo[id]) - x);
    return (hx < 0) ? -z : z;
  }
}

/* atan2(y,x)
 * Method :
 *  1. Reduce y to positive by atan2(y,x)=-atan2(-y,x).
 *  2. Reduce x to positive by (if x and y are unexceptional):
 *    ARG (x+iy) = arctan(y/x)       ... if x > 0,
 *    ARG (x+iy) = pi - arctan[y/(-x)]   ... if x < 0,
 *
 * Special cases:
 *
 *  ATAN2((anything), NaN ) is NaN;
 *  ATAN2(NAN , (anything) ) is NaN;
 *  ATAN2(+-0, +(anything but NaN)) is +-0  ;
 *  ATAN2(+-0, -(anything but NaN)) is +-pi ;
 *  ATAN2(+-(anything but 0 and NaN), 0) is +-pi/2;
 *  ATAN2(+-(anything but INF and NaN), +INF) is +-0 ;
 *  ATAN2(+-(anything but INF and NaN), -INF) is +-pi;
 *  ATAN2(+-INF,+INF ) is +-pi/4 ;
 *  ATAN2(+-INF,-INF ) is +-3pi/4;
 *  ATAN2(+-INF, (anything but,0,NaN, and INF)) is +-pi/2;
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following
 * constants. The decimal values may be used, provided that the
 * compiler will convert from decimal to binary accurately enough
 * to produce the hexadecimal values shown.
 */
double atan2(double y, double x) {
  static volatile double tiny = 1.0e-300;
  static const double
      zero = 0.0,
      pi_o_4 = 7.8539816339744827900E-01, /* 0x3FE921FB, 0x54442D18 */
      pi_o_2 = 1.5707963267948965580E+00, /* 0x3FF921FB, 0x54442D18 */
      pi = 3.1415926535897931160E+00;     /* 0x400921FB, 0x54442D18 */
  static volatile double pi_lo =
      1.2246467991473531772E-16; /* 0x3CA1A626, 0x33145C07 */

  double z;
  int32_t k, m, hx, hy, ix, iy;
  uint32_t lx, ly;

  EXTRACT_WORDS(hx, lx, x);
  ix = hx & 0x7FFFFFFF;
  EXTRACT_WORDS(hy, ly, y);
  iy = hy & 0x7FFFFFFF;
  if (((ix | ((lx | NegateWithWraparound<int32_t>(lx)) >> 31)) > 0x7FF00000) ||
      ((iy | ((ly | NegateWithWraparound<int32_t>(ly)) >> 31)) > 0x7FF00000)) {
    return x + y; /* x or y is NaN */
  }
  if ((SubWithWraparound(hx, 0x3FF00000) | lx) == 0) {
    return atan(y); /* x=1.0 */
  }
  m = ((hy >> 31) & 1) | ((hx >> 30) & 2);           /* 2*sign(x)+sign(y) */

  /* when y = 0 */
  if ((iy | ly) == 0) {
    switch (m) {
      case 0:
      case 1:
        return y; /* atan(+-0,+anything)=+-0 */
      case 2:
        return pi + tiny; /* atan(+0,-anything) = pi */
      case 3:
        return -pi - tiny; /* atan(-0,-anything) =-pi */
    }
  }
  /* when x = 0 */
  if ((ix | lx) == 0) return (hy < 0) ? -pi_o_2 - tiny : pi_o_2 + tiny;

  /* when x is INF */
  if (ix == 0x7FF00000) {
    if (iy == 0x7FF00000) {
      switch (m) {
        case 0:
          return pi_o_4 + tiny; /* atan(+INF,+INF) */
        case 1:
          return -pi_o_4 - tiny; /* atan(-INF,+INF) */
        case 2:
          return 3.0 * pi_o_4 + tiny; /*atan(+INF,-INF)*/
        case 3:
          return -3.0 * pi_o_4 - tiny; /*atan(-INF,-INF)*/
      }
    } else {
      switch (m) {
        case 0:
          return zero; /* atan(+...,+INF) */
        case 1:
          return -zero; /* atan(-...,+INF) */
        case 2:
          return pi + tiny; /* atan(+...,-INF) */
        case 3:
          return -pi - tiny; /* atan(-...,-INF) */
      }
    }
  }
  /* when y is INF */
  if (iy == 0x7FF00000) return (hy < 0) ? -pi_o_2 - tiny : pi_o_2 + tiny;

  /* compute y/x */
  k = (iy - ix) >> 20;
  if (k > 60) { /* |y/x| >  2**60 */
    z = pi_o_2 + 0.5 * pi_lo;
    m &= 1;
  } else if (hx < 0 && k < -60) {
    z = 0.0; /* 0 > |y|/x > -2**-60 */
  } else {
    z = atan(fabs(y / x)); /* safe to do y/x */
  }
  switch (m) {
    case 0:
      return z; /* atan(+,+) */
    case 1:
      return -z; /* atan(-,+) */
    case 2:
      return pi - (z - pi_lo); /* atan(+,-) */
    default:                   /* case 3 */
      return (z - pi_lo) - pi; /* atan(-,-) */
  }
}

/* cos(x)
 * Return cosine function of x.
 *
 * kernel function:
 *      __kernel_sin            ... sine function on [-pi/4,pi/4]
 *      __kernel_cos            ... cosine function on [-pi/4,pi/4]
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
double fdlibm_cos(double x) {
#else
double cos(double x) {
#endif
  double y[2], z = 0.0;
  int32_t n, ix;

  /* High word of x. */
  GET_HIGH_WORD(ix, x);

  /* |x| ~< pi/4 */
  ix &= 0x7FFFFFFF;
  if (ix <= 0x3FE921FB) {
    return __kernel_cos(x, z);
  } else if (ix >= 0x7FF00000) {
    /* cos(Inf or NaN) is NaN */
    return x - x;
  } else {
    /* argument reduction needed */
    n = __ieee754_rem_pio2(x, y);
    switch (n & 3) {
      case 0:
        return __kernel_cos(y[0], y[1]);
      case 1:
        return -__kernel_sin(y[0], y[1], 1);
      case 2:
        return -__kernel_cos(y[0], y[1]);
      default:
        return __kernel_sin(y[0], y[1], 1);
    }
  }
}

/* exp(x)
 * Returns the exponential of x.
 *
 * Method
 *   1. Argument reduction:
 *      Reduce x to an r so that |r| <= 0.5*ln2 ~ 0.34658.
 *      Given x, find r and integer k such that
 *
 *               x = k*ln2 + r,  |r| <= 0.5*ln2.
 *
 *      Here r will be represented as r = hi-lo for better
 *      accuracy.
 *
 *   2. Approximation of exp(r) by a special rational function on
 *      the interval [0,0.34658]:
 *      Write
 *          R(r**2) = r*(exp(r)+1)/(exp(r)-1) = 2 + r*r/6 - r**4/360 + ...
 *      We use a special Remes algorithm on [0,0.34658] to generate
 *      a polynomial of degree 5 to approximate R. The maximum error
 *      of this polynomial approximation is bounded by 2**-59. In
 *      other words,
 *          R(z) ~ 2.0 + P1*z + P2*z**2 + P3*z**3 + P4*z**4 + P5*z**5
 *      (where z=r*r, and the values of P1 to P5 are listed below)
 *      and
 *          |                  5          |     -59
 *          | 2.0+P1*z+...+P5*z   -  R(z) | <= 2
 *          |                             |
 *      The computation of exp(r) thus becomes
 *                             2*r
 *              exp(r) = 1 + -------
 *                            R - r
 *                                 r*R1(r)
 *                     = 1 + r + ----------- (for better accuracy)
 *                                2 - R1(r)
 *      where
 *                               2       4             10
 *              R1(r) = r - (P1*r  + P2*r  + ... + P5*r   ).
 *
 *   3. Scale back to obtain exp(x):
 *      From step 1, we have
 *         exp(x) = 2^k * exp(r)
 *
 * Special cases:
 *      exp(INF) is INF, exp(NaN) is NaN;
 *      exp(-INF) is 0, and
 *      for finite argument, only exp(0)=1 is exact.
 *
 * Accuracy:
 *      according to an error analysis, the error is always less than
 *      1 ulp (unit in the last place).
 *
 * Misc. info.
 *      For IEEE double
 *          if x >  7.09782712893383973096e+02 then exp(x) overflow
 *          if x < -7.45133219101941108420e+02 then exp(x) underflow
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following
 * constants. The decimal values may be used, provided that the
 * compiler will convert from decimal to binary accurately enough
 * to produce the hexadecimal values shown.
 */
double exp(double x) {
  static const double
      one = 1.0,
      halF[2] = {0.5, -0.5},
      o_threshold = 7.09782712893383973096e+02,  /* 0x40862E42, 0xFEFA39EF */
      u_threshold = -7.45133219101941108420e+02, /* 0xC0874910, 0xD52D3051 */
      ln2HI[2] = {6.93147180369123816490e-01,    /* 0x3FE62E42, 0xFEE00000 */
                  -6.93147180369123816490e-01},  /* 0xBFE62E42, 0xFEE00000 */
      ln2LO[2] = {1.90821492927058770002e-10,    /* 0x3DEA39EF, 0x35793C76 */
                  -1.90821492927058770002e-10},  /* 0xBDEA39EF, 0x35793C76 */
      invln2 = 1.44269504088896338700e+00,       /* 0x3FF71547, 0x652B82FE */
      P1 = 1.66666666666666019037e-01,           /* 0x3FC55555, 0x5555553E */
      P2 = -2.77777777770155933842e-03,          /* 0xBF66C16C, 0x16BEBD93 */
      P3 = 6.61375632143793436117e-05,           /* 0x3F11566A, 0xAF25DE2C */
      P4 = -1.65339022054652515390e-06,          /* 0xBEBBBD41, 0xC5D26BF1 */
      P5 = 4.13813679705723846039e-08,           /* 0x3E663769, 0x72BEA4D0 */
      E = 2.718281828459045;                     /* 0x4005BF0A, 0x8B145769 */

  static volatile double
      huge = 1.0e+300,
      twom1000 = 9.33263618503218878990e-302, /* 2**-1000=0x01700000,0*/
      two1023 = 8.988465674311579539e307;     /* 0x1p1023 */

  double y, hi = 0.0, lo = 0.0, c, t, twopk;
  int32_t k = 0, xsb;
  uint32_t hx;

  GET_HIGH_WORD(hx, x);
  xsb = (hx >> 31) & 1; /* sign bit of x */
  hx &= 0x7FFFFFFF;     /* high word of |x| */

  /* filter out non-finite argument */
  if (hx >= 0x40862E42) { /* if |x|>=709.78... */
    if (hx >= 0x7FF00000) {
      uint32_t lx;
      GET_LOW_WORD(lx, x);
      if (((hx & 0xFFFFF) | lx) != 0)
        return x + x; /* NaN */
      else
        return (xsb == 0) ? x : 0.0; /* exp(+-inf)={inf,0} */
    }
    if (x > o_threshold) return huge * huge;         /* overflow */
    if (x < u_threshold) return twom1000 * twom1000; /* underflow */
  }

  /* argument reduction */
  if (hx > 0x3FD62E42) {   /* if  |x| > 0.5 ln2 */
    if (hx < 0x3FF0A2B2) { /* and |x| < 1.5 ln2 */
      /* TODO(rtoy): We special case exp(1) here to return the correct
       * value of E, as the computation below would get the last bit
       * wrong. We should probably fix the algorithm instead.
       */
      if (x == 1.0) return E;
      hi = x - ln2HI[xsb];
      lo = ln2LO[xsb];
      k = 1 - xsb - xsb;
    } else {
      k = static_cast<int>(invln2 * x + halF[xsb]);
      t = k;
      hi = x - t * ln2HI[0]; /* t*ln2HI is exact here */
      lo = t * ln2LO[0];
    }
    x = hi - lo;
  } else if (hx < 0x3E300000) {         /* when |x|<2**-28 */
    if (huge + x > one) return one + x; /* trigger inexact */
  } else {
    k = 0;
  }

  /* x is now in primary range */
  t = x * x;
  if (k >= -1021) {
    INSERT_WORDS(
        twopk,
        0x3FF00000 + static_cast<int32_t>(static_cast<uint32_t>(k) << 20), 0);
  } else {
    INSERT_WORDS(twopk, 0x3FF00000 + (static_cast<uint32_t>(k + 1000) << 20),
                 0);
  }
  c = x - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t * P5))));
  if (k == 0) {
    return one - ((x * c) / (c - 2.0) - x);
  } else {
    y = one - ((lo - (x * c) / (2.0 - c)) - hi);
  }
  if (k >= -1021) {
    if (k == 1024) return y * 2.0 * two1023;
    return y * twopk;
  } else {
    return y * twopk * twom1000;
  }
}

/*
 * Method :
 *    1.Reduced x to positive by atanh(-x) = -atanh(x)
 *    2.For x>=0.5
 *              1              2x                          x
 *  atanh(x) = --- * log(1 + -------) = 0.5 * log1p(2 * --------)
 *              2             1 - x                      1 - x
 *
 *   For x<0.5
 *  atanh(x) = 0.5*log1p(2x+2x*x/(1-x))
 *
 * Special cases:
 *  atanh(x) is NaN if |x| > 1 with signal;
 *  atanh(NaN) is that NaN with no signal;
 *  atanh(+-1) is +-INF with signal.
 *
 */
double atanh(double x) {
  static const double one = 1.0, huge = 1e300;
  static const double zero = 0.0;

  double t;
  int32_t hx, ix;
  uint32_t lx;
  EXTRACT_WORDS(hx, lx, x);
  ix = hx & 0x7FFFFFFF;
  if ((ix | ((lx | NegateWithWraparound<int32_t>(lx)) >> 31)) > 0x3FF00000) {
    /* |x|>1 */
    return std::numeric_limits<double>::signaling_NaN();
  }
  if (ix == 0x3FF00000) {
    return x > 0 ? std::numeric_limits<double>::infinity()
                 : -std::numeric_limits<double>::infinity();
  }
  if (ix < 0x3E300000 && (huge + x) > zero) return x; /* x<2**-28 */
  SET_HIGH_WORD(x, ix);
  if (ix < 0x3FE00000) { /* x < 0.5 */
    t = x + x;
    t = 0.5 * log1p(t + t * x / (one - x));
  } else {
    t = 0.5 * log1p((x + x) / (one - x));
  }
  if (hx >= 0)
    return t;
  else
    return -t;
}

/* log(x)
 * Return the logrithm of x
 *
 * Method :
 *   1. Argument Reduction: find k and f such that
 *     x = 2^k * (1+f),
 *     where  sqrt(2)/2 < 1+f < sqrt(2) .
 *
 *   2. Approximation of log(1+f).
 *  Let s = f/(2+f) ; based on log(1+f) = log(1+s) - log(1-s)
 *     = 2s + 2/3 s**3 + 2/5 s**5 + .....,
 *         = 2s + s*R
 *      We use a special Reme algorithm on [0,0.1716] to generate
 *  a polynomial of degree 14 to approximate R The maximum error
 *  of this polynomial approximation is bounded by 2**-58.45. In
 *  other words,
 *            2      4      6      8      10      12      14
 *      R(z) ~ Lg1*s +Lg2*s +Lg3*s +Lg4*s +Lg5*s  +Lg6*s  +Lg7*s
 *    (the values of Lg1 to Lg7 are listed in the program)
 *  and
 *      |      2          14          |     -58.45
 *      | Lg1*s +...+Lg7*s    -  R(z) | <= 2
 *      |                             |
 *  Note that 2s = f - s*f = f - hfsq + s*hfsq, where hfsq = f*f/2.
 *  In order to guarantee error in log below 1ulp, we compute log
 *  by
 *    log(1+f) = f - s*(f - R)  (if f is not too large)
 *    log(1+f) = f - (hfsq - s*(hfsq+R)). (better accuracy)
 *
 *  3. Finally,  log(x) = k*ln2 + log(1+f).
 *          = k*ln2_hi+(f-(hfsq-(s*(hfsq+R)+k*ln2_lo)))
 *     Here ln2 is split into two floating point number:
 *      ln2_hi + ln2_lo,
 *     where n*ln2_hi is always exact for |n| < 2000.
 *
 * Special cases:
 *  log(x) is NaN with signal if x < 0 (including -INF) ;
 *  log(+INF) is +INF; log(0) is -INF with signal;
 *  log(NaN) is that NaN with no signal.
 *
 * Accuracy:
 *  according to an error analysis, the error is always less than
 *  1 ulp (unit in the last place).
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following
 * constants. The decimal values may be used, provided that the
 * compiler will convert from decimal to binary accurately enough
 * to produce the hexadecimal values shown.
 */
double log(double x) {
  static const double                      /* -- */
      ln2_hi = 6.93147180369123816490e-01, /* 3fe62e42 fee00000 */
      ln2_lo = 1.90821492927058770002e-10, /* 3dea39ef 35793c76 */
      two54 = 1.80143985094819840000e+16,  /* 43500000 00000000 */
      Lg1 = 6.666666666666735130e-01,      /* 3FE55555 55555593 */
      Lg2 = 3.999999999940941908e-01,      /* 3FD99999 9997FA04 */
      Lg3 = 2.857142874366239149e-01,      /* 3FD24924 94229359 */
      Lg4 = 2.222219843214978396e-01,      /* 3FCC71C5 1D8E78AF */
      Lg5 = 1.818357216161805012e-01,      /* 3FC74664 96CB03DE */
      Lg6 = 1.531383769920937332e-01,      /* 3FC39A09 D078C69F */
      Lg7 = 1.479819860511658591e-01;      /* 3FC2F112 DF3E5244 */

  static const double zero = 0.0;

  double hfsq, f, s, z, R, w, t1, t2, dk;
  int32_t k, hx, i, j;
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
  k += (hx >> 20) - 1023;
  hx &= 0x000FFFFF;
  i = (hx + 0x95F64) & 0x100000;
  SET_HIGH_WORD(x, hx | (i ^ 0x3FF00000)); /* normalize x or x/2 */
  k += (i >> 20);
  f = x - 1.0;
  if ((0x000FFFFF & (2 + hx)) < 3) { /* -2**-20 <= f < 2**-20 */
    if (f == zero) {
      if (k == 0) {
        return zero;
      } else {
        dk = static_cast<double>(k);
        return dk * ln2_hi + dk * ln2_lo;
      }
    }
    R = f * f * (0.5 - 0.33333333333333333 * f);
    if (k == 0) {
      return f - R;
    } else {
      dk = static_cast<double>(k);
      return dk * ln2_hi - ((R - dk * ln2_lo) - f);
    }
  }
  s = f / (2.0 + f);
  dk = static_cast<double>(k);
  z = s * s;
  i = hx - 0x6147A;
  w = z * z;
  j = 0x6B851 - hx;
  t1 = w * (Lg2 + w * (Lg4 + w * Lg6));
  t2 = z * (Lg1 + w * (Lg3 + w * (Lg5 + w * Lg7)));
  i |= j;
  R = t2 + t1;
  if (i > 0) {
    hfsq = 0.5 * f * f;
    if (k == 0)
      return f - (hfsq - s * (hfsq + R));
    else
      return dk * ln2_hi - ((hfsq - (s * (hfsq + R) + dk * ln2_lo)) - f);
  } else {
    if (k == 0)
      return f - s * (f - R);
    else
      return dk * ln2_hi - ((s * (f - R) - dk * ln2_lo) - f);
  }
}

/* double log1p(double x)
 *
 * Method :
 *   1. Argument Reduction: find k and f such that
 *      1+x = 2^k * (1+f),
 *     where  sqrt(2)/2 < 1+f < sqrt(2) .
 *
 *      Note. If k=0, then f=x is exact. However, if k!=0, then f
 *  may not be representable exactly. In that case, a correction
 *  term is need. Let u=1+x rounded. Let c = (1+x)-u, then
 *  log(1+x) - log(u) ~ c/u. Thus, we proceed to compute log(u),
 *  and add back the correction term c/u.
 *  (Note: when x > 2**53, one can simply return log(x))
 *
 *   2. Approximation of log1p(f).
 *  Let s = f/(2+f) ; based on log(1+f) = log(1+s) - log(1-s)
 *     = 2s + 2/3 s**3 + 2/5 s**5 + .....,
 *         = 2s + s*R
 *      We use a special Reme algorithm on [0,0.1716] to generate
 *  a polynomial of degree 14 to approximate R The maximum error
 *  of this polynomial approximation is bounded by 2**-58.45. In
 *  other words,
 *            2      4      6      8      10      12      14
 *      R(z) ~ Lp1*s +Lp2*s +Lp3*s +Lp4*s +Lp5*s  +Lp6*s  +Lp7*s
 *    (the values of Lp1 to Lp7 are listed in the program)
 *  and
 *      |      2          14          |     -58.45
 *      | Lp1*s +...+Lp7*s    -  R(z) | <= 2
 *      |                             |
 *  Note that 2s = f - s*f = f - hfsq + s*hfsq, where hfsq = f*f/2.
 *  In order to guarantee error in log below 1ulp, we compute log
 *  by
 *    log1p(f) = f - (hfsq - s*(hfsq+R)).
 *
 *  3. Finally, log1p(x) = k*ln2 + log1p(f).
 *           = k*ln2_hi+(f-(hfsq-(s*(hfsq+R)+k*ln2_lo)))
 *     Here ln2 is split into two floating point number:
 *      ln2_hi + ln2_lo,
 *     where n*ln2_hi is always exact for |n| < 2000.
 *
 * Special cases:
 *  log1p(x) is NaN with signal if x < -1 (including -INF) ;
 *  log1p(+INF) is +INF; log1p(-1) is -INF with signal;
 *  log1p(NaN) is that NaN with no signal.
 *
 * Accuracy:
 *  according to an error analysis, the error is always less than
 *  1 ulp (unit in the last place).
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following
 * constants. The decimal values may be used, provided that the
 * compiler will convert from decimal to binary accurately enough
 * to produce the hexadecimal values shown.
 *
 * Note: Assuming log() return accurate answer, the following
 *   algorithm can be used to compute log1p(x) to within a few ULP:
 *
 *    u = 1+x;
 *    if(u==1.0) return x ; else
 *         return log(u)*(x/(u-1.0));
 *
 *   See HP-15C Advanced Functions Handbook, p.193.
 */
double log1p(double x) {
  static const double                      /* -- */
      ln2_hi = 6.93147180369123816490e-01, /* 3fe62e42 fee00000 */
      ln2_lo = 1.90821492927058770002e-10, /* 3dea39ef 35793c76 */
      two54 = 1.80143985094819840000e+16,  /* 43500000 00000000 */
      Lp1 = 6.666666666666735130e-01,      /* 3FE55555 55555593 */
      Lp2 = 3.999999999940941908e-01,      /* 3FD99999 9997FA04 */
      Lp3 = 2.857142874366239149e-01,      /* 3FD24924 94229359 */
      Lp4 = 2.222219843214978396e-01,      /* 3FCC71C5 1D8E78AF */
      Lp5 = 1.818357216161805012e-01,      /* 3FC74664 96CB03DE */
      Lp6 = 1.531383769920937332e-01,      /* 3FC39A09 D078C69F */
      Lp7 = 1.479819860511658591e-01;      /* 3FC2F112 DF3E5244 */

  static const double zero = 0.0;

  double hfsq, f, c, s, z, R, u;
  int32_t k, hx, hu, ax;

  GET_HIGH_WORD(hx, x);
  ax = hx & 0x7FFFFFFF;

  k = 1;
  if (hx < 0x3FDA827A) {    /* 1+x < sqrt(2)+ */
    if (ax >= 0x3FF00000) { /* x <= -1.0 */
      if (x == -1.0)
        return -std::numeric_limits<double>::infinity(); /* log1p(-1)=+inf */
      else
        return std::numeric_limits<double>::signaling_NaN();  // log1p(x<-1)=NaN
    }
    if (ax < 0x3E200000) {    /* |x| < 2**-29 */
      if (two54 + x > zero    /* raise inexact */
          && ax < 0x3C900000) /* |x| < 2**-54 */
        return x;
      else
        return x - x * x * 0.5;
    }
    if (hx > 0 || hx <= static_cast<int32_t>(0xBFD2BEC4)) {
      k = 0;
      f = x;
      hu = 1;
    } /* sqrt(2)/2- <= 1+x < sqrt(2)+ */
  }
  if (hx >= 0x7FF00000) return x + x;
  if (k != 0) {
    if (hx < 0x43400000) {
      u = 1.0 + x;
      GET_HIGH_WORD(hu, u);
      k = (hu >> 20) - 1023;
      c = (k > 0) ? 1.0 - (u - x) : x - (u - 1.0); /* correction term */
      c /= u;
    } else {
      u = x;
      GET_HIGH_WORD(hu, u);
      k = (hu >> 20) - 1023;
      c = 0;
    }
    hu &= 0x000FFFFF;
    /*
     * The approximation to sqrt(2) used in thresholds is not
     * critical.  However, the ones used above must give less
     * strict bounds than the one here so that the k==0 case is
     * never reached from here, since here we have committed to
     * using the correction term but don't use it if k==0.
     */
    if (hu < 0x6A09E) {                  /* u ~< sqrt(2) */
      SET_HIGH_WORD(u, hu | 0x3FF00000); /* normalize u */
    } else {
      k += 1;
      SET_HIGH_WORD(u, hu | 0x3FE00000); /* normalize u/2 */
      hu = (0x00100000 - hu) >> 2;
    }
    f = u - 1.0;
  }
  hfsq = 0.5 * f * f;
  if (hu == 0) { /* |f| < 2**-20 */
    if (f == zero) {
      if (k == 0) {
        return zero;
      } else {
        c += k * ln2_lo;
        return k * ln2_hi + c;
      }
    }
    R = hfsq * (1.0 - 0.66666666666666666 * f);
    if (k == 0)
      return f - R;
    else
      return k * ln2_hi - ((R - (k * ln2_lo + c)) - f);
  }
  s = f / (2.0 + f);
  z = s * s;
  R = z * (Lp1 +
           z * (Lp2 + z * (Lp3 + z * (Lp4 + z * (Lp5 + z * (Lp6 + z * Lp7))))));
  if (k == 0)
    return f - (hfsq - s * (hfsq + R));
  else
    return k * ln2_hi - ((hfsq - (s * (hfsq + R) + (k * ln2_lo + c))) - f);
}

/*
 * k_log1p(f):
 * Return log(1+f) - f for 1+f in ~[sqrt(2)/2, sqrt(2)].
 *
 * The following describes the overall strategy for computing
 * logarithms in base e.  The argument reduction and adding the final
 * term of the polynomial are done by the caller for increased accuracy
 * when different bases are used.
 *
 * Method :
 *   1. Argument Reduction: find k and f such that
 *         x = 2^k * (1+f),
 *         where  sqrt(2)/2 < 1+f < sqrt(2) .
 *
 *   2. Approximation of log(1+f).
 *      Let s = f/(2+f) ; based on log(1+f) = log(1+s) - log(1-s)
 *            = 2s + 2/3 s**3 + 2/5 s**5 + .....,
 *            = 2s + s*R
 *      We use a special Reme algorithm on [0,0.1716] to generate
 *      a polynomial of degree 14 to approximate R The maximum error
 *      of this polynomial approximation is bounded by 2**-58.45. In
 *      other words,
 *          2      4      6      8      10      12      14
 *          R(z) ~ Lg1*s +Lg2*s +Lg3*s +Lg4*s +Lg5*s  +Lg6*s  +Lg7*s
 *      (the values of Lg1 to Lg7 are listed in the program)
 *      and
 *          |      2          14          |     -58.45
 *          | Lg1*s +...+Lg7*s    -  R(z) | <= 2
 *          |                             |
 *      Note that 2s = f - s*f = f - hfsq + s*hfsq, where hfsq = f*f/2.
 *      In order to guarantee error in log below 1ulp, we compute log
 *      by
 *          log(1+f) = f - s*(f - R)            (if f is not too large)
 *          log(1+f) = f - (hfsq - s*(hfsq+R)). (better accuracy)
 *
 *   3. Finally,  log(x) = k*ln2 + log(1+f).
 *          = k*ln2_hi+(f-(hfsq-(s*(hfsq+R)+k*ln2_lo)))
 *      Here ln2 is split into two floating point number:
 *          ln2_hi + ln2_lo,
 *      where n*ln2_h
"""


```