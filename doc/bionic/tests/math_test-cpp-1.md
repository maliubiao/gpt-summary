Response:
The user wants a summary of the functionality of the provided C++ test file `bionic/tests/math_test.cpp`. This file is part of Android's bionic library and tests the `math.h` header.

To summarize the functionality, I need to identify the main purpose of the tests and the types of functions being tested.

The core purpose is to verify the correctness of the mathematical functions provided by `math.h` in Android's bionic library.

The tests cover a wide range of standard C math functions, including:

- Rounding functions (`round`, `roundf`, `roundl`, `trunc`, `truncf`, `truncl`)
- Functions for finding the next representable floating-point number (`nextafter`, `nextafterf`, `nextafterl`, `nexttoward`, `nexttowardf`, `nexttowardl`)
- Functions for manipulating the sign of a floating-point number (`copysign`, `copysignf`, `copysignl`)
- Functions for extracting the significand and scaling (`significand`, `significandf`, `significandl`, `scalb`, `scalbf`, `scalbln`, `scalblnf`, `scalblnl`, `scalbn`, `scalbnf`, `scalbnl`)
- Gamma and related functions (`gamma`, `gammaf`, `gamma_r`, `gammaf_r`, `lgamma`, `lgammaf`, `lgammal`, `lgamma_r`, `lgammaf_r`, `lgammal_r`, `tgamma`, `tgammaf`, `tgammal`)
- Bessel functions (`j0`, `j0f`, `j1`, `j1f`, `jn`, `jnf`, `y0`, `y0f`, `y1`, `y1f`, `yn`, `ynf`)
- Functions for breaking down floating-point numbers (`frexp`, `frexpf`, `frexpl`, `modf`, `modff`, `modfl`)
- Remainder function (`remquo`, `remquof`, `remquol`)
- Exponential and logarithmic functions (`exp2`, `exp2f`, `log2`, `log2f`)
- Trigonometric and hyperbolic functions (implicitly tested via the inclusion of "math_data/*.h" files for functions like `acos`, `asin`, `atan`, `cos`, `sin`, `tan`, `acosh`, `asinh`, `atanh`, `cosh`, `sinh`, `tanh`)
- Other functions like `cbrt`, `ceil`, `fdim`, `floor`, `fma`, `fmax`, `fmin`, `fmod`, `hypot`, `ilogb`, `ldexp`, `llrint`, `log`, `log10`, `log1p`, `logb`, `lrint`, `nearbyint`, `pow`, `remainder`, `rint`, `round`, `scalb`, `scalbn`, `significand`, `sqrt`, `trunc`.

The tests use Google Test framework (`ASSERT_*` macros) to verify the expected output of these functions for various inputs, including normal values, edge cases (like zero, infinity, NaN), and specific values from "intel_data" files.

Some tests also check for specific historical bugs in certain platforms (like OpenBSD).

Therefore, the summary should focus on the comprehensive testing of `math.h` functions, including accuracy and handling of special values.
这个`bionic/tests/math_test.cpp` 文件的第 2 部分延续了第 1 部分的功能，主要目标是**测试 Android Bionic 库中 `math.h` 头文件提供的各种数学函数的正确性**。

具体来说，这一部分主要测试了以下类型的数学函数：

* **舍入函数**:
    * `round`, `roundf`, `roundl`: 将浮点数舍入到最接近的整数，远离零。
    * `trunc`, `truncf`, `truncl`: 将浮点数向零截断取整。
* **寻找相邻浮点数函数**:
    * `nextafter`, `nextafterf`, `nextafterl`: 返回目标方向上给定浮点数的下一个可表示的浮点数。
    * `nexttoward`, `nexttowardf`, `nexttowardl`: 返回朝向第二个参数方向上给定浮点数的下一个可表示的浮点数。
* **符号操作函数**:
    * `copysign`, `copysignf`, `copysignl`: 返回一个数值，其大小与第一个参数相同，符号与第二个参数相同。
* **提取有效数字和比例调整函数**:
    * `significand`, `significandf`, `significandl`: 提取浮点数的规格化有效数字（尾数）。
    * `scalb`, `scalbf`: 将浮点数乘以 2 的整数次幂。
    * `scalbln`, `scalblnf`, `scalblnl`: 将浮点数乘以 `FLT_RADIX` (通常是 2) 的 `long int` 次幂。
    * `scalbn`, `scalbnf`, `scalbnl`: 将浮点数乘以 `FLT_RADIX` (通常是 2) 的 `int` 次幂。
* **伽马函数和相关函数**:
    * `gamma`, `gammaf`: 计算伽马函数的对数（`log(|Γ(x)|)`）。(注意：在某些系统中可能不可用)
    * `gamma_r`, `gammaf_r`: 计算伽马函数的对数，并通过一个单独的参数返回结果的符号。(Bionic 特有)
    * `lgamma`, `lgammaf`, `lgammal`: 计算伽马函数的对数（`log(|Γ(x)|)`）。
    * `lgamma_r`, `lgammaf_r`, `lgammal_r`: 计算伽马函数的对数，并通过一个单独的参数返回结果的符号。
    * `tgamma`, `tgammaf`, `tgammal`: 计算伽马函数 Γ(x)。
* **贝塞尔函数**:
    * `j0`, `j0f`: 计算第一类零阶贝塞尔函数。
    * `j1`, `j1f`: 计算第一类一阶贝塞尔函数。
    * `jn`, `jnf`: 计算第一类 n 阶贝塞尔函数。
    * `y0`, `y0f`: 计算第二类零阶贝塞尔函数。
    * `y1`, `y1f`: 计算第二类一阶贝塞尔函数。
    * `yn`, `ynf`: 计算第二类 n 阶贝塞尔函数。
* **分解浮点数函数**:
    * `frexp`, `frexpf`, `frexpl`: 将浮点数分解为规格化的分数和一个 2 的幂次的指数。
    * `modf`, `modff`, `modfl`: 将浮点数分解为整数部分和小数部分。
* **求余数函数**:
    * `remquo`, `remquof`, `remquol`: 计算浮点数的余数，并返回商的后几位。
* **指数和对数函数**:
    * `exp2`, `exp2f`, `exp2l`: 计算 2 的 x 次幂。
* **与特定平台或历史 Bug 相关的测试**:
    * 针对 OpenBSD 上 `exp2` 和 `nextafterl` 函数的已知 bug 进行了测试。
    * 针对之前报告的 `frexpf` 公共 bug 进行了回归测试。
* **使用 Intel 数据进行更细致的测试**:
    * 包含了 `math_data` 目录下的大量头文件，这些头文件包含了来自 Intel 的测试数据，用于更全面地测试各种数学函数（如 `acos`, `acosh`, `asin`, `asinh`, `atan`, `atanh`, `cbrt`, `ceil`, `copysign`, `cos`, `cosh`, `exp`, `exp2`, `expm1`, `fabs`, `fdim`, `floor`, `fma`, `fmax`, `fmin`, `fmod`, `frexp`, `hypot`, `ilogb`, `ldexp`, `llrint`, `log`, `log10`, `log1p`, `log2`, `logb`, `lrint`, `modf`, `nearbyint`, `nextafter`, `pow`, `remainder`, `remquo`, `rint`, `round`, `scalb`, `scalbn`, `significand`, `sin`, `sinh`, `sincos`, `sqrt`, `tan`, `tanh`, `trunc`）。这些测试用例使用了 `DoMathDataTest` 模板函数，它会读取这些数据并断言函数的返回值是否与预期一致。

**总结来说，`bionic/tests/math_test.cpp` 的第 2 部分的功能是：**

**通过大量的单元测试用例，详细验证 Android Bionic 库提供的 `math.h` 中各种标准 C 数学函数的实现是否正确，包括对正常值、边界情况（如零、无穷大、NaN）以及特定平台已知问题的测试，并使用了来自 Intel 的更全面的测试数据来提高测试覆盖率。**

这个文件的目的是确保 Android 系统中使用的数学运算的准确性和可靠性。

### 提示词
```
这是目录为bionic/tests/math_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
zero.
  ASSERT_DOUBLE_EQ(1.0, round(0.5));
  ASSERT_DOUBLE_EQ(-1.0, round(-0.5));
  ASSERT_DOUBLE_EQ(0.0, round(0.0));
  ASSERT_DOUBLE_EQ(-0.0, round(-0.0));
  ASSERT_TRUE(isnan(round(nan(""))));
  ASSERT_DOUBLE_EQ(HUGE_VAL, round(HUGE_VAL));
  ASSERT_DOUBLE_EQ(-HUGE_VAL, round(-HUGE_VAL));
}

TEST(math_h, roundf) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });
  fesetround(FE_TOWARDZERO); // roundf ignores the rounding mode and always rounds away from zero.
  ASSERT_FLOAT_EQ(1.0f, roundf(0.5f));
  ASSERT_FLOAT_EQ(-1.0f, roundf(-0.5f));
  ASSERT_FLOAT_EQ(0.0f, roundf(0.0f));
  ASSERT_FLOAT_EQ(-0.0f, roundf(-0.0f));
  ASSERT_TRUE(isnanf(roundf(nanf(""))));
  ASSERT_FLOAT_EQ(HUGE_VALF, roundf(HUGE_VALF));
  ASSERT_FLOAT_EQ(-HUGE_VALF, roundf(-HUGE_VALF));
}

TEST(math_h, roundl) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });
  fesetround(FE_TOWARDZERO); // roundl ignores the rounding mode and always rounds away from zero.
  ASSERT_DOUBLE_EQ(1.0L, roundl(0.5L));
  ASSERT_DOUBLE_EQ(-1.0L, roundl(-0.5L));
  ASSERT_DOUBLE_EQ(0.0L, roundl(0.0L));
  ASSERT_DOUBLE_EQ(-0.0L, roundl(-0.0L));
  ASSERT_TRUE(isnan(roundl(nanl(""))));
  ASSERT_DOUBLE_EQ(HUGE_VALL, roundl(HUGE_VALL));
  ASSERT_DOUBLE_EQ(-HUGE_VALL, roundl(-HUGE_VALL));
}

TEST(math_h, trunc) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });
  fesetround(FE_UPWARD); // trunc ignores the rounding mode and always rounds toward zero.
  ASSERT_DOUBLE_EQ(1.0, trunc(1.5));
  ASSERT_DOUBLE_EQ(-1.0, trunc(-1.5));
  ASSERT_DOUBLE_EQ(0.0, trunc(0.0));
  ASSERT_DOUBLE_EQ(-0.0, trunc(-0.0));
  ASSERT_TRUE(isnan(trunc(nan(""))));
  ASSERT_DOUBLE_EQ(HUGE_VAL, trunc(HUGE_VAL));
  ASSERT_DOUBLE_EQ(-HUGE_VAL, trunc(-HUGE_VAL));
}

TEST(math_h, truncf) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });
  fesetround(FE_UPWARD); // truncf ignores the rounding mode and always rounds toward zero.
  ASSERT_FLOAT_EQ(1.0f, truncf(1.5f));
  ASSERT_FLOAT_EQ(-1.0f, truncf(-1.5f));
  ASSERT_FLOAT_EQ(0.0f, truncf(0.0f));
  ASSERT_FLOAT_EQ(-0.0f, truncf(-0.0f));
  ASSERT_TRUE(isnan(truncf(nanf(""))));
  ASSERT_FLOAT_EQ(HUGE_VALF, truncf(HUGE_VALF));
  ASSERT_FLOAT_EQ(-HUGE_VALF, truncf(-HUGE_VALF));
}

TEST(math_h, truncl) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });
  fesetround(FE_UPWARD); // truncl ignores the rounding mode and always rounds toward zero.
  ASSERT_DOUBLE_EQ(1.0L, truncl(1.5L));
  ASSERT_DOUBLE_EQ(-1.0L, truncl(-1.5L));
  ASSERT_DOUBLE_EQ(0.0L, truncl(0.0L));
  ASSERT_DOUBLE_EQ(-0.0L, truncl(-0.0L));
  ASSERT_TRUE(isnan(truncl(nan(""))));
  ASSERT_DOUBLE_EQ(HUGE_VALL, truncl(HUGE_VALL));
  ASSERT_DOUBLE_EQ(-HUGE_VALL, truncl(-HUGE_VALL));
}

TEST(math_h, nextafter) {
  ASSERT_DOUBLE_EQ(0.0, nextafter(0.0, 0.0));
  ASSERT_DOUBLE_EQ(4.9406564584124654e-324, nextafter(0.0, 1.0));
  ASSERT_DOUBLE_EQ(-4.9406564584124654e-324, nextafter(0.0, -1.0));
}

TEST(math_h, nextafterf) {
  ASSERT_FLOAT_EQ(0.0f, nextafterf(0.0f, 0.0f));
  ASSERT_FLOAT_EQ(1.4012985e-45f, nextafterf(0.0f, 1.0f));
  ASSERT_FLOAT_EQ(-1.4012985e-45f, nextafterf(0.0f, -1.0f));
}

TEST(math_h, nextafterl) {
  ASSERT_DOUBLE_EQ(0.0L, nextafterl(0.0L, 0.0L));
  // Use a runtime value to accomodate the case when
  // sizeof(double) == sizeof(long double)
  long double smallest_positive = ldexpl(1.0L, LDBL_MIN_EXP - LDBL_MANT_DIG);
  ASSERT_DOUBLE_EQ(smallest_positive, nextafterl(0.0L, 1.0L));
  ASSERT_DOUBLE_EQ(-smallest_positive, nextafterl(0.0L, -1.0L));
}

TEST(math_h, nexttoward) {
  ASSERT_DOUBLE_EQ(0.0, nexttoward(0.0, 0.0L));
  ASSERT_DOUBLE_EQ(4.9406564584124654e-324, nexttoward(0.0, 1.0L));
  ASSERT_DOUBLE_EQ(-4.9406564584124654e-324, nexttoward(0.0, -1.0L));
}

TEST(math_h, nexttowardf) {
  ASSERT_FLOAT_EQ(0.0f, nexttowardf(0.0f, 0.0L));
  ASSERT_FLOAT_EQ(1.4012985e-45f, nexttowardf(0.0f, 1.0L));
  ASSERT_FLOAT_EQ(-1.4012985e-45f, nexttowardf(0.0f, -1.0L));
}

TEST(math_h, nexttowardl) {
  ASSERT_DOUBLE_EQ(0.0L, nexttowardl(0.0L, 0.0L));
  // Use a runtime value to accomodate the case when
  // sizeof(double) == sizeof(long double)
  long double smallest_positive = ldexpl(1.0L, LDBL_MIN_EXP - LDBL_MANT_DIG);
  ASSERT_DOUBLE_EQ(smallest_positive, nexttowardl(0.0L, 1.0L));
  ASSERT_DOUBLE_EQ(-smallest_positive, nexttowardl(0.0L, -1.0L));
}

TEST(math_h, copysign) {
  ASSERT_DOUBLE_EQ(0.0, copysign(0.0, 1.0));
  ASSERT_DOUBLE_EQ(-0.0, copysign(0.0, -1.0));
  ASSERT_DOUBLE_EQ(2.0, copysign(2.0, 1.0));
  ASSERT_DOUBLE_EQ(-2.0, copysign(2.0, -1.0));
}

TEST(math_h, copysignf) {
  ASSERT_FLOAT_EQ(0.0f, copysignf(0.0f, 1.0f));
  ASSERT_FLOAT_EQ(-0.0f, copysignf(0.0f, -1.0f));
  ASSERT_FLOAT_EQ(2.0f, copysignf(2.0f, 1.0f));
  ASSERT_FLOAT_EQ(-2.0f, copysignf(2.0f, -1.0f));
}

TEST(math_h, copysignl) {
  ASSERT_DOUBLE_EQ(0.0L, copysignl(0.0L, 1.0L));
  ASSERT_DOUBLE_EQ(-0.0L, copysignl(0.0L, -1.0L));
  ASSERT_DOUBLE_EQ(2.0L, copysignl(2.0L, 1.0L));
  ASSERT_DOUBLE_EQ(-2.0L, copysignl(2.0L, -1.0L));
}

TEST(math_h, significand) {
  ASSERT_DOUBLE_EQ(0.0, significand(0.0));
  ASSERT_DOUBLE_EQ(1.2, significand(1.2));
  ASSERT_DOUBLE_EQ(1.53125, significand(12.25));
}

TEST(math_h, significandf) {
  ASSERT_FLOAT_EQ(0.0f, significandf(0.0f));
  ASSERT_FLOAT_EQ(1.2f, significandf(1.2f));
  ASSERT_FLOAT_EQ(1.53125f, significandf(12.25f));
}

TEST(math_h, significandl) {
#if !defined(ANDROID_HOST_MUSL)
  ASSERT_DOUBLE_EQ(0.0L, significandl(0.0L));
  ASSERT_DOUBLE_EQ(1.2L, significandl(1.2L));
  ASSERT_DOUBLE_EQ(1.53125L, significandl(12.25L));
#else
  GTEST_SKIP() << "musl doesn't have significandl";
#endif
}

TEST(math_h, scalb) {
  ASSERT_DOUBLE_EQ(12.0, scalb(3.0, 2.0));
}

TEST(math_h, scalbf) {
  ASSERT_FLOAT_EQ(12.0f, scalbf(3.0f, 2.0f));
}

TEST(math_h, scalbln) {
  ASSERT_DOUBLE_EQ(12.0, scalbln(3.0, 2L));
}

TEST(math_h, scalblnf) {
  ASSERT_FLOAT_EQ(12.0f, scalblnf(3.0f, 2L));
}

TEST(math_h, scalblnl) {
  ASSERT_DOUBLE_EQ(12.0L, scalblnl(3.0L, 2L));
}

TEST(math_h, scalbn) {
  ASSERT_DOUBLE_EQ(12.0, scalbn(3.0, 2));
}

TEST(math_h, scalbnf) {
  ASSERT_FLOAT_EQ(12.0f, scalbnf(3.0f, 2));
}

TEST(math_h, scalbnl) {
  ASSERT_DOUBLE_EQ(12.0L, scalbnl(3.0L, 2));
}

TEST(math_h, gamma) {
#if !defined(ANDROID_HOST_MUSL)
  ASSERT_DOUBLE_EQ(log(24.0), gamma(5.0));
#else
  GTEST_SKIP() << "musl doesn't have gamma";
#endif
}

TEST(math_h, gammaf) {
#if !defined(ANDROID_HOST_MUSL)
  ASSERT_FLOAT_EQ(logf(24.0f), gammaf(5.0f));
#else
  GTEST_SKIP() << "musl doesn't have gammaf";
#endif
}

TEST(math_h, gamma_r) {
#if defined(__BIONIC__)
  int sign;
  ASSERT_DOUBLE_EQ(log(24.0), gamma_r(5.0, &sign));
  ASSERT_EQ(1, sign);
#else // __BIONIC__
  GTEST_SKIP() << "glibc doesn't have gamma_r";
#endif // __BIONIC__
}

TEST(math_h, gammaf_r) {
#if defined(__BIONIC__)
  int sign;
  ASSERT_FLOAT_EQ(logf(24.0f), gammaf_r(5.0f, &sign));
  ASSERT_EQ(1, sign);
#else // __BIONIC__
  GTEST_SKIP() << "glibc doesn't have gammaf_r";
#endif // __BIONIC__
}

TEST(math_h, lgamma) {
  ASSERT_DOUBLE_EQ(log(24.0), lgamma(5.0));
}

TEST(math_h, lgammaf) {
  ASSERT_FLOAT_EQ(logf(24.0f), lgammaf(5.0f));
}

TEST(math_h, lgammal) {
  ASSERT_DOUBLE_EQ(logl(24.0L), lgammal(5.0L));
}

TEST(math_h, lgamma_r) {
  int sign;
  ASSERT_DOUBLE_EQ(log(24.0), lgamma_r(5.0, &sign));
  ASSERT_EQ(1, sign);
}

TEST(math_h, lgamma_r_17471883) {
  int sign;

  sign = 0;
  ASSERT_DOUBLE_EQ(HUGE_VAL, lgamma_r(0.0, &sign));
  ASSERT_EQ(1, sign);
  sign = 0;
  ASSERT_DOUBLE_EQ(HUGE_VAL, lgamma_r(-0.0, &sign));
  ASSERT_EQ(-1, sign);
}

TEST(math_h, lgammaf_r) {
  int sign;
  ASSERT_FLOAT_EQ(logf(24.0f), lgammaf_r(5.0f, &sign));
  ASSERT_EQ(1, sign);
}

TEST(math_h, lgammaf_r_17471883) {
  int sign;

  sign = 0;
  ASSERT_FLOAT_EQ(HUGE_VALF, lgammaf_r(0.0f, &sign));
  ASSERT_EQ(1, sign);
  sign = 0;
  ASSERT_FLOAT_EQ(HUGE_VALF, lgammaf_r(-0.0f, &sign));
  ASSERT_EQ(-1, sign);
}

TEST(math_h, lgammal_r) {
  int sign;
  ASSERT_DOUBLE_EQ(log(24.0L), lgamma_r(5.0L, &sign));
  ASSERT_EQ(1, sign);
}

TEST(math_h, lgammal_r_17471883) {
  int sign;

  sign = 0;
  ASSERT_DOUBLE_EQ(HUGE_VAL, lgammal_r(0.0L, &sign));
  ASSERT_EQ(1, sign);
  sign = 0;
  ASSERT_DOUBLE_EQ(HUGE_VAL, lgammal_r(-0.0L, &sign));
  ASSERT_EQ(-1, sign);
}

TEST(math_h, tgamma_NaN) {
  ASSERT_TRUE(isnan(tgamma(nan(""))));
  ASSERT_TRUE(isnanf(tgammaf(nanf(""))));
  ASSERT_TRUE(isnanl(tgammal(nanl(""))));
}

TEST(math_h, tgamma_inf) {
  ASSERT_TRUE(isinf(tgamma(HUGE_VAL)));
  ASSERT_TRUE(isinff(tgammaf(HUGE_VALF)));
  ASSERT_TRUE(isinfl(tgammal(HUGE_VALL)));
}

TEST(math_h, tgamma_negative) {
  ASSERT_TRUE(isnan(tgamma(-1.0)));
  ASSERT_TRUE(isnanf(tgammaf(-1.0f)));
  ASSERT_TRUE(isnanl(tgammal(-1.0L)));
}

TEST(math_h, tgamma) {
  ASSERT_DOUBLE_EQ(24.0, tgamma(5.0));
  ASSERT_DOUBLE_EQ(120.0, tgamma(6.0));
  ASSERT_TRUE(isinf(tgamma(172.0)));
}

TEST(math_h, tgammaf) {
  ASSERT_FLOAT_EQ(24.0f, tgammaf(5.0f));
  ASSERT_FLOAT_EQ(120.0f, tgammaf(6.0f));
  ASSERT_TRUE(isinff(tgammaf(172.0f)));
}

TEST(math_h, tgammal) {
  ASSERT_DOUBLE_EQ(24.0L, tgammal(5.0L));
  ASSERT_DOUBLE_EQ(120.0L, tgammal(6.0L));
  ASSERT_TRUE(isinf(tgammal(172.0L)));
}

TEST(math_h, j0) {
  ASSERT_DOUBLE_EQ(1.0, j0(0.0));
  ASSERT_DOUBLE_EQ(0.76519768655796661, j0(1.0));
}

TEST(math_h, j0f) {
  ASSERT_FLOAT_EQ(1.0f, j0f(0.0f));
  ASSERT_FLOAT_EQ(0.76519769f, j0f(1.0f));
}

TEST(math_h, j1) {
  ASSERT_DOUBLE_EQ(0.0, j1(0.0));
  ASSERT_DOUBLE_EQ(0.44005058574493355, j1(1.0));
}

TEST(math_h, j1f) {
  ASSERT_FLOAT_EQ(0.0f, j1f(0.0f));
  ASSERT_FLOAT_EQ(0.44005057f, j1f(1.0f));
}

TEST(math_h, jn) {
  ASSERT_DOUBLE_EQ(0.0, jn(4, 0.0));
  ASSERT_DOUBLE_EQ(0.0024766389641099553, jn(4, 1.0));
}

TEST(math_h, jnf) {
  ASSERT_FLOAT_EQ(0.0f, jnf(4, 0.0f));
  ASSERT_FLOAT_EQ(0.0024766389f, jnf(4, 1.0f));
}

TEST(math_h, y0) {
  ASSERT_DOUBLE_EQ(-HUGE_VAL, y0(0.0));
  ASSERT_DOUBLE_EQ(0.08825696421567697, y0(1.0));
}

TEST(math_h, y0f) {
  ASSERT_FLOAT_EQ(-HUGE_VALF, y0f(0.0f));
  ASSERT_FLOAT_EQ(0.088256963f, y0f(1.0f));
}

TEST(math_h, y1) {
  ASSERT_DOUBLE_EQ(-HUGE_VAL, y1(0.0));
  ASSERT_DOUBLE_EQ(-0.78121282130028868, y1(1.0));
}

TEST(math_h, y1f) {
  ASSERT_FLOAT_EQ(-HUGE_VALF, y1f(0.0f));
  ASSERT_FLOAT_EQ(-0.78121281f, y1f(1.0f));
}

TEST(math_h, yn) {
  ASSERT_DOUBLE_EQ(-HUGE_VAL, yn(4, 0.0));
  ASSERT_DOUBLE_EQ(-33.278423028972114, yn(4, 1.0));
}

TEST(math_h, ynf) {
  ASSERT_FLOAT_EQ(-HUGE_VALF, ynf(4, 0.0f));
  ASSERT_FLOAT_EQ(-33.278423f, ynf(4, 1.0f));
}

TEST(math_h, frexp) {
  int exp;
  double dr = frexp(1024.0, &exp);
  ASSERT_DOUBLE_EQ(1024.0, scalbn(dr, exp));
}

TEST(math_h, frexpf) {
  int exp;
  float fr = frexpf(1024.0f, &exp);
  ASSERT_FLOAT_EQ(1024.0f, scalbnf(fr, exp));
}

TEST(math_h, frexpl) {
  int exp;
  long double ldr = frexpl(1024.0L, &exp);
  ASSERT_DOUBLE_EQ(1024.0L, scalbnl(ldr, exp));
}

TEST(math_h, modf) {
  double di;
  double df = modf(123.75, &di);
  ASSERT_DOUBLE_EQ(123.0, di);
  ASSERT_DOUBLE_EQ(0.75, df);
}

TEST(math_h, modff) {
  float fi;
  float ff = modff(123.75f, &fi);
  ASSERT_FLOAT_EQ(123.0f, fi);
  ASSERT_FLOAT_EQ(0.75f, ff);
}

TEST(math_h, modfl) {
  long double ldi;
  long double ldf = modfl(123.75L, &ldi);
  ASSERT_DOUBLE_EQ(123.0L, ldi);
  ASSERT_DOUBLE_EQ(0.75L, ldf);
}

TEST(math_h, remquo) {
  int q;
  double d = remquo(13.0, 4.0, &q);
  ASSERT_EQ(3, q);
  ASSERT_DOUBLE_EQ(1.0, d);

  // If x or y is a NaN, NaN is returned.
  ASSERT_TRUE(isnan(remquo(nan(""), 10.0, &q)));
  ASSERT_TRUE(isnan(remquo(12.0, nan(""), &q)));

  // If x is an infinity, NaN is returned.
  ASSERT_TRUE(isnan(remquo(HUGE_VAL, 10.0, &q)));
  ASSERT_TRUE(isnan(remquo(-HUGE_VAL, 10.0, &q)));

  // If y is 0, NaN is returned.
  ASSERT_TRUE(isnan(remquo(12.0, 0.0, &q)));
}

TEST(math_h, remquof) {
  int q;
  float f = remquof(13.0f, 4.0f, &q);
  ASSERT_EQ(3, q);
  ASSERT_FLOAT_EQ(1.0, f);

  // If x or y is a NaN, NaN is returned.
  ASSERT_TRUE(isnanf(remquof(nanf(""), 10.0f, &q)));
  ASSERT_TRUE(isnanf(remquof(12.0f, nanf(""), &q)));

  // If x is an infinity, NaN is returned.
  ASSERT_TRUE(isnanf(remquof(HUGE_VALF, 10.0f, &q)));
  ASSERT_TRUE(isnanf(remquof(-HUGE_VALF, 10.0f, &q)));

  // If y is 0, NaN is returned.
  ASSERT_TRUE(isnanf(remquof(12.0f, 0.0f, &q)));
}

TEST(math_h, remquol) {
  int q;
  long double ld = remquol(13.0L, 4.0L, &q);
  ASSERT_DOUBLE_EQ(3L, q);
  ASSERT_DOUBLE_EQ(1.0L, ld);

  // If x or y is a NaN, NaN is returned.
  ASSERT_TRUE(isnanl(remquol(nanl(""), 10.0L, &q)));
  ASSERT_TRUE(isnanl(remquol(12.0L, nanl(""), &q)));

  // If x is an infinity, NaN is returned.
  ASSERT_TRUE(isnanl(remquol(HUGE_VALL, 10.0L, &q)));
  ASSERT_TRUE(isnanl(remquol(-HUGE_VALL, 10.0L, &q)));

  // If y is 0, NaN is returned.
  ASSERT_TRUE(isnanl(remquol(12.0L, 0.0L, &q)));
}

// https://code.google.com/p/android/issues/detail?id=6697
TEST(math_h, frexpf_public_bug_6697) {
  int exp;
  float fr = frexpf(14.1f, &exp);
  ASSERT_FLOAT_EQ(14.1f, scalbnf(fr, exp));
}

TEST(math_h, exp2_STRICT_ALIGN_OpenBSD_bug) {
  // OpenBSD/x86's libm had a bug here, but it was already fixed in FreeBSD:
  // http://svnweb.FreeBSD.org/base/head/lib/msun/src/math_private.h?revision=240827&view=markup
  ASSERT_DOUBLE_EQ(5.0, exp2(log2(5)));
  ASSERT_FLOAT_EQ(5.0f, exp2f(log2f(5)));
  ASSERT_DOUBLE_EQ(5.0L, exp2l(log2l(5)));
}

TEST(math_h, nextafterl_OpenBSD_bug) {
  // OpenBSD/x86's libm had a bug here.
  ASSERT_TRUE(nextafter(1.0, 0.0) - 1.0 < 0.0);
  ASSERT_TRUE(nextafterf(1.0f, 0.0f) - 1.0f < 0.0f);
  ASSERT_TRUE(nextafterl(1.0L, 0.0L) - 1.0L < 0.0L);
}

#include "math_data/acos_intel_data.h"
TEST(math_h, acos_intel) {
  DoMathDataTest<1>(g_acos_intel_data, acos);
}

#include "math_data/acosf_intel_data.h"
TEST(math_h, acosf_intel) {
  DoMathDataTest<1>(g_acosf_intel_data, acosf);
}

#include "math_data/acosh_intel_data.h"
TEST(math_h, acosh_intel) {
  DoMathDataTest<2>(g_acosh_intel_data, acosh);
}

#include "math_data/acoshf_intel_data.h"
TEST(math_h, acoshf_intel) {
  DoMathDataTest<2>(g_acoshf_intel_data, acoshf);
}

#include "math_data/asin_intel_data.h"
TEST(math_h, asin_intel) {
  DoMathDataTest<1>(g_asin_intel_data, asin);
}

#include "math_data/asinf_intel_data.h"
TEST(math_h, asinf_intel) {
  DoMathDataTest<1>(g_asinf_intel_data, asinf);
}

#include "math_data/asinh_intel_data.h"
TEST(math_h, asinh_intel) {
  DoMathDataTest<2>(g_asinh_intel_data, asinh);
}

#include "math_data/asinhf_intel_data.h"
TEST(math_h, asinhf_intel) {
  DoMathDataTest<2>(g_asinhf_intel_data, asinhf);
}

#include "math_data/atan2_intel_data.h"
TEST(math_h, atan2_intel) {
  DoMathDataTest<2>(g_atan2_intel_data, atan2);
}

#include "math_data/atan2f_intel_data.h"
TEST(math_h, atan2f_intel) {
  DoMathDataTest<2>(g_atan2f_intel_data, atan2f);
}

#include "math_data/atan_intel_data.h"
TEST(math_h, atan_intel) {
  DoMathDataTest<1>(g_atan_intel_data, atan);
}

#include "math_data/atanf_intel_data.h"
TEST(math_h, atanf_intel) {
  DoMathDataTest<1>(g_atanf_intel_data, atanf);
}

#include "math_data/atanh_intel_data.h"
TEST(math_h, atanh_intel) {
  DoMathDataTest<2>(g_atanh_intel_data, atanh);
}

#include "math_data/atanhf_intel_data.h"
TEST(math_h, atanhf_intel) {
  DoMathDataTest<2>(g_atanhf_intel_data, atanhf);
}

#include "math_data/cbrt_intel_data.h"
TEST(math_h, cbrt_intel) {
  DoMathDataTest<1>(g_cbrt_intel_data, cbrt);
}

#include "math_data/cbrtf_intel_data.h"
TEST(math_h, cbrtf_intel) {
  DoMathDataTest<1>(g_cbrtf_intel_data, cbrtf);
}

#include "math_data/ceil_intel_data.h"
TEST(math_h, ceil_intel) {
  DoMathDataTest<1>(g_ceil_intel_data, ceil);
}

#include "math_data/ceilf_intel_data.h"
TEST(math_h, ceilf_intel) {
  DoMathDataTest<1>(g_ceilf_intel_data, ceilf);
}

#include "math_data/copysign_intel_data.h"
TEST(math_h, copysign_intel) {
  DoMathDataTest<1>(g_copysign_intel_data, copysign);
}

#include "math_data/copysignf_intel_data.h"
TEST(math_h, copysignf_intel) {
  DoMathDataTest<1>(g_copysignf_intel_data, copysignf);
}

#include "math_data/cos_intel_data.h"
TEST(math_h, cos_intel) {
  DoMathDataTest<1>(g_cos_intel_data, cos);
}

#include "math_data/cosf_intel_data.h"
TEST(math_h, cosf_intel) {
  DoMathDataTest<1>(g_cosf_intel_data, cosf);
}

#include "math_data/cosh_intel_data.h"
TEST(math_h, cosh_intel) {
  DoMathDataTest<2>(g_cosh_intel_data, cosh);
}

#include "math_data/coshf_intel_data.h"
TEST(math_h, coshf_intel) {
  DoMathDataTest<2>(g_coshf_intel_data, coshf);
}

#include "math_data/exp_intel_data.h"
TEST(math_h, exp_intel) {
  DoMathDataTest<1>(g_exp_intel_data, exp);
}

#include "math_data/expf_intel_data.h"
TEST(math_h, expf_intel) {
  DoMathDataTest<1>(g_expf_intel_data, expf);
}

#include "math_data/exp2_intel_data.h"
TEST(math_h, exp2_intel) {
  DoMathDataTest<1>(g_exp2_intel_data, exp2);
}

#include "math_data/exp2f_intel_data.h"
TEST(math_h, exp2f_intel) {
  DoMathDataTest<1>(g_exp2f_intel_data, exp2f);
}

#include "math_data/expm1_intel_data.h"
TEST(math_h, expm1_intel) {
  DoMathDataTest<1>(g_expm1_intel_data, expm1);
}

#include "math_data/expm1f_intel_data.h"
TEST(math_h, expm1f_intel) {
  DoMathDataTest<1>(g_expm1f_intel_data, expm1f);
}

#include "math_data/fabs_intel_data.h"
TEST(math_h, fabs_intel) {
  DoMathDataTest<1>(g_fabs_intel_data, fabs);
}

#include "math_data/fabsf_intel_data.h"
TEST(math_h, fabsf_intel) {
  DoMathDataTest<1>(g_fabsf_intel_data, fabsf);
}

#include "math_data/fdim_intel_data.h"
TEST(math_h, fdim_intel) {
  DoMathDataTest<1>(g_fdim_intel_data, fdim);
}

#include "math_data/fdimf_intel_data.h"
TEST(math_h, fdimf_intel) {
  DoMathDataTest<1>(g_fdimf_intel_data, fdimf);
}

#include "math_data/floor_intel_data.h"
TEST(math_h, floor_intel) {
  DoMathDataTest<1>(g_floor_intel_data, floor);
}

#include "math_data/floorf_intel_data.h"
TEST(math_h, floorf_intel) {
  DoMathDataTest<1>(g_floorf_intel_data, floorf);
}

#include "math_data/fma_intel_data.h"
TEST(math_h, fma_intel) {
  DoMathDataTest<1>(g_fma_intel_data, fma);
}

#include "math_data/fmaf_intel_data.h"
TEST(math_h, fmaf_intel) {
  DoMathDataTest<1>(g_fmaf_intel_data, fmaf);
}

#include "math_data/fmax_intel_data.h"
TEST(math_h, fmax_intel) {
  DoMathDataTest<1>(g_fmax_intel_data, fmax);
}

#include "math_data/fmaxf_intel_data.h"
TEST(math_h, fmaxf_intel) {
  DoMathDataTest<1>(g_fmaxf_intel_data, fmaxf);
}

#include "math_data/fmin_intel_data.h"
TEST(math_h, fmin_intel) {
  DoMathDataTest<1>(g_fmin_intel_data, fmin);
}

#include "math_data/fminf_intel_data.h"
TEST(math_h, fminf_intel) {
  DoMathDataTest<1>(g_fminf_intel_data, fminf);
}

#include "math_data/fmod_intel_data.h"
TEST(math_h, fmod_intel) {
  DoMathDataTest<1>(g_fmod_intel_data, fmod);
}

#include "math_data/fmodf_intel_data.h"
TEST(math_h, fmodf_intel) {
  DoMathDataTest<1>(g_fmodf_intel_data, fmodf);
}

#include "math_data/frexp_intel_data.h"
TEST(math_h, frexp_intel) {
  DoMathDataTest<1>(g_frexp_intel_data, frexp);
}

#include "math_data/frexpf_intel_data.h"
TEST(math_h, frexpf_intel) {
  DoMathDataTest<1>(g_frexpf_intel_data, frexpf);
}

#include "math_data/hypot_intel_data.h"
TEST(math_h, hypot_intel) {
  DoMathDataTest<1>(g_hypot_intel_data, hypot);
}

#include "math_data/hypotf_intel_data.h"
TEST(math_h, hypotf_intel) {
  DoMathDataTest<1>(g_hypotf_intel_data, hypotf);
}

#include "math_data/ilogb_intel_data.h"
TEST(math_h, ilogb_intel) {
  DoMathDataTest<1>(g_ilogb_intel_data, ilogb);
}

#include "math_data/ilogbf_intel_data.h"
TEST(math_h, ilogbf_intel) {
  DoMathDataTest<1>(g_ilogbf_intel_data, ilogbf);
}

#include "math_data/ldexp_intel_data.h"
TEST(math_h, ldexp_intel) {
  DoMathDataTest<1>(g_ldexp_intel_data, ldexp);
}

#include "math_data/ldexpf_intel_data.h"
TEST(math_h, ldexpf_intel) {
  DoMathDataTest<1>(g_ldexpf_intel_data, ldexpf);
}

#include "math_data/llrint_intel_data.h"
TEST(math_h, llrint_intel) {
  DoMathDataTest<1>(g_llrint_intel_data, llrint);
}

#include "math_data/llrintf_intel_data.h"
TEST(math_h, llrintf_intel) {
  DoMathDataTest<1>(g_llrintf_intel_data, llrintf);
}

#include "math_data/log_intel_data.h"
TEST(math_h, log_intel) {
  DoMathDataTest<1>(g_log_intel_data, log);
}

#include "math_data/logf_intel_data.h"
TEST(math_h, logf_intel) {
  DoMathDataTest<1>(g_logf_intel_data, logf);
}

#include "math_data/log10_intel_data.h"
TEST(math_h, log10_intel) {
  DoMathDataTest<1>(g_log10_intel_data, log10);
}

#include "math_data/log10f_intel_data.h"
TEST(math_h, log10f_intel) {
  DoMathDataTest<1>(g_log10f_intel_data, log10f);
}

#include "math_data/log1p_intel_data.h"
TEST(math_h, log1p_intel) {
  DoMathDataTest<1>(g_log1p_intel_data, log1p);
}

#include "math_data/log1pf_intel_data.h"
TEST(math_h, log1pf_intel) {
  DoMathDataTest<1>(g_log1pf_intel_data, log1pf);
}

#include "math_data/log2_intel_data.h"
TEST(math_h, log2_intel) {
  DoMathDataTest<1>(g_log2_intel_data, log2);
}

#include "math_data/log2f_intel_data.h"
TEST(math_h, log2f_intel) {
  DoMathDataTest<1>(g_log2f_intel_data, log2f);
}

#include "math_data/logb_intel_data.h"
TEST(math_h, logb_intel) {
  DoMathDataTest<1>(g_logb_intel_data, logb);
}

#include "math_data/logbf_intel_data.h"
TEST(math_h, logbf_intel) {
  DoMathDataTest<1>(g_logbf_intel_data, logbf);
}

#include "math_data/lrint_intel_data.h"
TEST(math_h, lrint_intel) {
  DoMathDataTest<1>(g_lrint_intel_data, lrint);
}

#include "math_data/lrintf_intel_data.h"
TEST(math_h, lrintf_intel) {
  DoMathDataTest<1>(g_lrintf_intel_data, lrintf);
}

#include "math_data/modf_intel_data.h"
TEST(math_h, modf_intel) {
  DoMathDataTest<1>(g_modf_intel_data, modf);
}

#include "math_data/modff_intel_data.h"
TEST(math_h, modff_intel) {
  DoMathDataTest<1>(g_modff_intel_data, modff);
}

#include "math_data/nearbyint_intel_data.h"
TEST(math_h, nearbyint_intel) {
  DoMathDataTest<1>(g_nearbyint_intel_data, nearbyint);
}

#include "math_data/nearbyintf_intel_data.h"
TEST(math_h, nearbyintf_intel) {
  DoMathDataTest<1>(g_nearbyintf_intel_data, nearbyintf);
}

#include "math_data/nextafter_intel_data.h"
TEST(math_h, nextafter_intel) {
  DoMathDataTest<1>(g_nextafter_intel_data, nextafter);
}

#include "math_data/nextafterf_intel_data.h"
TEST(math_h, nextafterf_intel) {
  DoMathDataTest<1>(g_nextafterf_intel_data, nextafterf);
}

#include "math_data/pow_intel_data.h"
TEST(math_h, pow_intel) {
  DoMathDataTest<1>(g_pow_intel_data, pow);
}

#include "math_data/powf_intel_data.h"
TEST(math_h, powf_intel) {
  DoMathDataTest<1>(g_powf_intel_data, powf);
}

#include "math_data/remainder_intel_data.h"
TEST(math_h, remainder_intel) {
  DoMathDataTest<1>(g_remainder_intel_data, remainder);
}

#include "math_data/remainderf_intel_data.h"
TEST(math_h, remainderf_intel) {
  DoMathDataTest<1>(g_remainderf_intel_data, remainderf);
}

#include "math_data/remquo_intel_data.h"
TEST(math_h, remquo_intel) {
  DoMathDataTest<1>(g_remquo_intel_data, remquo);
}

#include "math_data/remquof_intel_data.h"
TEST(math_h, remquof_intel) {
  DoMathDataTest<1>(g_remquof_intel_data, remquof);
}

#include "math_data/rint_intel_data.h"
TEST(math_h, rint_intel) {
  DoMathDataTest<1>(g_rint_intel_data, rint);
}

#include "math_data/rintf_intel_data.h"
TEST(math_h, rintf_intel) {
  DoMathDataTest<1>(g_rintf_intel_data, rintf);
}

#include "math_data/round_intel_data.h"
TEST(math_h, round_intel) {
  DoMathDataTest<1>(g_round_intel_data, round);
}

#include "math_data/roundf_intel_data.h"
TEST(math_h, roundf_intel) {
  DoMathDataTest<1>(g_roundf_intel_data, roundf);
}

#include "math_data/scalb_intel_data.h"
TEST(math_h, scalb_intel) {
  DoMathDataTest<1>(g_scalb_intel_data, scalb);
}

#include "math_data/scalbf_intel_data.h"
TEST(math_h, scalbf_intel) {
  DoMathDataTest<1>(g_scalbf_intel_data, scalbf);
}

#include "math_data/scalbn_intel_data.h"
TEST(math_h, scalbn_intel) {
  DoMathDataTest<1>(g_scalbn_intel_data, scalbn);
}

#include "math_data/scalbnf_intel_data.h"
TEST(math_h, scalbnf_intel) {
  DoMathDataTest<1>(g_scalbnf_intel_data, scalbnf);
}

#include "math_data/significand_intel_data.h"
TEST(math_h, significand_intel) {
  DoMathDataTest<1>(g_significand_intel_data, significand);
}

#include "math_data/significandf_intel_data.h"
TEST(math_h, significandf_intel) {
  DoMathDataTest<1>(g_significandf_intel_data, significandf);
}

#include "math_data/sin_intel_data.h"
TEST(math_h, sin_intel) {
  DoMathDataTest<1>(g_sin_intel_data, sin);
}

#include "math_data/sinf_intel_data.h"
TEST(math_h, sinf_intel) {
  DoMathDataTest<1>(g_sinf_intel_data, sinf);
}

#include "math_data/sinh_intel_data.h"
TEST(math_h, sinh_intel) {
  DoMathDataTest<2>(g_sinh_intel_data, sinh);
}

#include "math_data/sinhf_intel_data.h"
TEST(math_h, sinhf_intel) {
  DoMathDataTest<2>(g_sinhf_intel_data, sinhf);
}

#include "math_data/sincos_intel_data.h"
TEST(math_h, sincos_intel) {
  DoMathDataTest<1>(g_sincos_intel_data, sincos);
}

#include "math_data/sincosf_intel_data.h"
TEST(math_h, sincosf_intel) {
  DoMathDataTest<1>(g_sincosf_intel_data, sincosf);
}

#include "math_data/sqrt_intel_data.h"
TEST(math_h, sqrt_intel) {
  DoMathDataTest<1>(g_sqrt_intel_data, sqrt);
}

#include "math_data/sqrtf_intel_data.h"
TEST(math_h, sqrtf_intel) {
  DoMathDataTest<1>(g_sqrtf_intel_data, sqrtf);
}

#include "math_data/tan_intel_data.h"
TEST(math_h, tan_intel) {
  DoMathDataTest<1>(g_tan_intel_data, tan);
}

#include "math_data/tanf_intel_data.h"
TEST(math_h, tanf_intel) {
  DoMathDataTest<1>(g_tanf_intel_data, tanf);
}

#include "math_data/tanh_intel_data.h"
TEST(math_h, tanh_intel) {
  DoMathDataTest<2>(g_tanh_intel_data, tanh);
}

#include "math_data/tanhf_intel_data.h"
TEST(math_h, tanhf_intel) {
  DoMathDataTest<2>(g_tanhf_intel_data, tanhf);
}

#include "math_data/trunc_intel_data.h"
TEST(math_h, trunc_intel) {
  DoMathDataTest<1>(g_trunc_intel_data, trunc);
}

#include "math_data/truncf_intel_data.h"
TEST(math_h, truncf_intel) {
  DoMathDataTest<1>(g_truncf_intel_data, truncf);
}
```