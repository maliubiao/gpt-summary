Response:
The user wants a summary of the functionality of the provided C++ code file `bionic/tests/math_test.cpp`. This file is part of the Android Bionic library and is specifically a test file for the math library (`<math.h>`).

Here's a breakdown of the file's purpose:

1. **Test Suite:** The file contains a comprehensive set of tests for the functions and macros defined in the `<math.h>` header file provided by Bionic.
2. **Macro Capture and Testing:** It demonstrates a technique to test the Bionic-specific implementations of type-generic math macros by capturing them before including headers from `libc++` (which might redefine them).
3. **Function Testing:**  It uses the Google Test framework to verify the behavior of various math functions like `fpclassify`, `isfinite`, `isinf`, `isnan`, trigonometric functions (`sin`, `cos`, `tan`, etc.), logarithmic functions (`log`, `log10`, etc.), exponential functions (`exp`, `exp2`, etc.), rounding functions (`ceil`, `floor`, `round`, etc.), and other utility functions (`fmax`, `fmin`, `hypot`, etc.).
4. **Historical BSD Cruft Testing:** It also tests some historical BSD-specific versions of math functions (prefixed with `__`).
5. **Edge Case Testing:** The tests cover various input values, including normal numbers, zero, subnormal numbers, infinity, and NaN (Not a Number), to ensure robustness.
6. **Floating-Point Environment Testing:** Some tests, like those for `lrint` and `rint`, explicitly manipulate the floating-point rounding mode and check the behavior of the functions accordingly.

Therefore, the primary function of this file is to **rigorously test the correctness and completeness of the math functions and macros implemented in Android's Bionic library.**
这是位于 Android Bionic 库中的 `bionic/tests/math_test.cpp` 源代码文件。它的主要功能是 **测试 Android Bionic 提供的数学库 `<math.h>` 的实现是否正确且符合预期。**

更具体地说，这个文件的功能可以归纳为以下几点：

1. **测试 `<math.h>` 中定义的宏：**  文件中使用了一系列 `capture_generic_macro` 宏来“捕获” `<math.h>` 中定义的类型通用宏（如 `fpclassify`, `signbit`, `isfinite` 等）。这是因为 C++ 标准库 `<cmath>` 可能会重新定义这些宏，而这个测试文件需要测试的是 Bionic 自身的实现。捕获宏之后，它会使用断言 (`ASSERT_EQ`, `ASSERT_TRUE`, `ASSERT_FALSE`) 来验证这些宏在不同输入下的行为是否符合预期。

2. **测试 `<math.h>` 中声明的数学函数：**  文件中包含了大量的 `TEST` 宏，每个 `TEST` 针对 `<math.h>` 中声明的一个或多个数学函数进行测试。这些测试覆盖了各种类型的函数，包括：
    * **浮点数分类函数：** 例如 `fpclassify`, `isfinite`, `isinf`, `isnan`, `isnormal` 等，用于判断浮点数的类型。
    * **三角函数和反三角函数：** 例如 `sin`, `cos`, `tan`, `asin`, `acos`, `atan`, `atan2` 等。
    * **双曲函数和反双曲函数：** 例如 `sinh`, `cosh`, `tanh`, `asinh`, `acosh`, `atanh` 等。
    * **指数和对数函数：** 例如 `exp`, `exp2`, `expm1`, `log`, `log2`, `log10`, `log1p` 等。
    * **幂函数和根函数：** 例如 `pow`, `sqrt`, `cbrt` 等。
    * **舍入函数：** 例如 `ceil`, `floor`, `round`, `lrint`, `rint`, `nearbyint`, `lround` 等。
    * **其他数学函数：** 例如 `fabs`, `ldexp`, `fmod`, `remainder`, `drem`, `fmax`, `fmin`, `fma`, `hypot`, `erf`, `erfc`, `ilogb`, `logb`, `fdim` 等。

3. **测试历史遗留的 BSD 函数：**  文件中还测试了一些以 `__` 开头的数学函数，这些函数是历史遗留的 BSD 系统中的函数，在当前的 `<math.h>` 中可能不再直接暴露。例如 `__fpclassify`, `__isfinite`, `__isinf`, `__isnan`, `__isnormal`, `__signbit` 等。

4. **覆盖各种输入情况：**  测试用例覆盖了各种可能的输入值，包括：
    * **正常值**
    * **零 (正零和负零)**
    * **正无穷和负无穷 (`INFINITY`, `HUGE_VAL`)**
    * **NaN (Not a Number)**
    * **次正规数 (subnormal numbers)**

5. **使用 Google Test 框架：**  这个文件使用了 Google Test 框架来组织和运行测试用例，并提供了清晰的测试结果输出。

6. **测试浮点数环境：** 部分测试用例，例如针对舍入函数的测试，会显式地设置浮点数舍入模式 (`fesetround`)，以验证函数在不同舍入模式下的行为是否符合预期。

**与 Android 功能的关系举例说明：**

Android 系统广泛使用 Bionic 库提供的数学功能。以下是一些例子：

* **图形渲染 (Framework/NDK):**  OpenGL ES 或 Vulkan 等图形 API 底层依赖数学运算，例如向量、矩阵的计算，三角函数用于角度和旋转，`sqrt` 用于计算距离等。这些运算最终会调用 Bionic 的数学库实现。
* **音频处理 (Framework/NDK):** 音频编解码、音频特效处理等涉及到傅里叶变换、滤波等复杂的数学运算，同样依赖 Bionic 的数学库。
* **传感器数据处理 (Framework):**  处理加速度计、陀螺仪等传感器数据时，可能需要进行向量计算、角度转换等数学运算。
* **游戏开发 (NDK):** 游戏引擎大量使用数学运算来处理物理模拟、碰撞检测、人物动画等。
* **科学计算类应用 (NDK):**  一些需要进行复杂数值计算的 App，会直接使用 NDK 调用 Bionic 的数学库。

**举例说明：** 假设一个 Android 应用需要计算两个向量的夹角。这可能涉及到计算向量的点积和模长，然后使用反余弦函数 `acos`。最终，应用调用的 `acos` 函数就是 Bionic 库中 `math_test.cpp` 正在测试的实现。

**详细解释每一个 libc 函数的功能是如何实现的：**

由于这是一个测试文件，它本身并不包含 libc 函数的实现。libc 函数的实现位于 Bionic 库的 `libc/` 和 `libm/` 目录下的其他源文件中。这个测试文件通过调用这些函数并检查其返回值来验证其正确性。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个特定的 `math_test.cpp` 文件主要关注的是数学函数的测试，它本身并不直接涉及到 dynamic linker 的功能。测试代码通常会被编译成一个可执行文件，该文件链接到 `libm.so` (包含数学函数的共享库)。

**so 布局样本：**

```
libm.so:
  地址 0x... (基地址)
  .text 段:
    acos (函数代码)
    sin (函数代码)
    ... (其他数学函数代码)
  .data 段:
    一些全局变量和常量
  .dynsym 段:
    acos (符号表项)
    sin (符号表项)
    ...
```

**链接的处理过程：**

1. **编译阶段：** 编译器会将 `math_test.cpp` 编译成目标文件 `math_test.o`。在编译过程中，如果遇到 `acos()` 等数学函数调用，编译器会生成对这些符号的未解析引用。
2. **链接阶段：** 链接器 (`ld`) 会将 `math_test.o` 与 Bionic 的 `libm.so` 链接起来。链接器会查找 `libm.so` 的 `.dynsym` 段，找到 `acos` 等符号的定义地址，并将 `math_test.o` 中对这些符号的未解析引用替换为 `libm.so` 中对应函数的地址。
3. **加载阶段：** 当 Android 系统加载 `math_test` 可执行文件时，dynamic linker (`linker64` 或 `linker`) 会负责加载所有依赖的共享库，包括 `libm.so`。dynamic linker 会根据 `libm.so` 的基地址，将其加载到内存中的合适位置，并更新 `math_test` 中指向 `libm.so` 函数的地址。

**如果做了逻辑推理，请给出假设输入与输出：**

例如，对于 `TEST(math_h, sin)`：

* **假设输入：** `0.0`
* **预期输出：** `0.0` (通过 `ASSERT_DOUBLE_EQ(0.0, sin(0.0));` 断言验证)

对于 `TEST(math_h, isinf)`：

* **假设输入：** `HUGE_VALF` (代表正无穷的 `float` 类型)
* **预期输出：** `true` (通过 `ASSERT_TRUE(isinf(HUGE_VALF));` 断言验证)

**如果涉及用户或者编程常见的使用错误，请举例说明：**

* **忘记包含头文件 `<math.h>`：**  如果代码中使用了数学函数，但忘记包含 `<math.h>`，会导致编译错误，因为编译器不知道这些函数的声明。
* **类型不匹配：**  例如，将 `float` 类型的变量传递给需要 `double` 类型参数的数学函数，可能会导致精度损失或编译警告。虽然大多数情况下会自动进行隐式类型转换，但最好保持类型一致。
* **对 NaN 或无穷大的结果未进行处理：**  某些数学运算，例如除以零或对负数开平方根，会产生 NaN 或无穷大的结果。如果不进行适当的检查和处理，可能会导致程序行为异常。
* **舍入误差：**  浮点数运算存在固有的舍入误差。在比较浮点数是否相等时，不能直接使用 `==`，而应该使用一个小的容差值进行比较，例如 `abs(a - b) < epsilon`。这个测试文件中的 `ASSERT_DOUBLE_EQ` 和 `ASSERT_FLOAT_EQ` 宏就考虑了浮点数的精度问题。
* **超出定义域：**  某些数学函数有其定义域限制。例如，`acos` 函数的输入值必须在 [-1, 1] 之间。超出定义域的输入会导致未定义的行为或返回 NaN。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 或 NDK 代码发起数学运算：**
   * **Framework:** 例如，一个动画效果可能需要计算角度和位置，从而调用 `Math` 类中的方法，这些方法最终会调用到 Bionic 的数学函数。
   * **NDK:**  开发者在 C/C++ 代码中使用 `<math.h>` 中的函数，例如在 OpenGL ES 代码中计算模型变换矩阵。

2. **调用 Bionic 的 `libm.so` 中的函数：**  无论是 Framework 还是 NDK，最终的数学运算都会通过函数调用进入 Bionic 库的 `libm.so`。

3. **`libm.so` 执行数学运算并返回结果：** `libm.so` 中包含了各种数学函数的实现代码。它接收输入参数，执行相应的计算，并将结果返回给调用者。

**Frida Hook 示例：**

假设我们要 hook `sin` 函数的调用，可以这样做：

```javascript
if (Process.arch === "arm64" || Process.arch === "arm") {
  const libm = Module.load("libm.so");
  const sin = libm.findExportByName("sin");

  if (sin) {
    Interceptor.attach(sin, {
      onEnter: function (args) {
        console.log("[*] Called sin with argument: " + args[0]);
      },
      onLeave: function (retval) {
        console.log("[*] sin returned: " + retval);
      }
    });
    console.log("[*] Hooked sin function");
  } else {
    console.log("[!] sin function not found");
  }
} else {
  console.log("[!] Unsupported architecture for this hook.");
}
```

**调试步骤：**

1. **找到 `libm.so` 的基地址：**  可以使用 `Process.enumerateModules()` 或在 Frida Console 中查看已加载的模块。
2. **找到要 hook 的函数的地址：**  可以使用 `Module.findExportByName()` 查找导出函数的地址。
3. **使用 `Interceptor.attach()` 进行 hook：**  在 `onEnter` 中可以查看函数参数，在 `onLeave` 中可以查看返回值。

**假设输入与输出 (Frida Hook)：**

如果 Android 应用或 NDK 代码调用 `sin(1.0)`，Frida hook 的输出可能会是：

```
[*] Hooked sin function
[*] Called sin with argument: 1
[*] sin returned: 0.8414709848078965
```

**第1部分功能归纳：**

`bionic/tests/math_test.cpp` 文件的主要功能是 **作为 Android Bionic 库中数学库 `<math.h>` 的一个全面的测试套件。** 它通过使用 Google Test 框架，对 `<math.h>` 中定义的各种宏和函数进行细致的测试，覆盖了不同的输入值和边界情况，以确保 Bionic 提供的数学功能的正确性和可靠性。它还测试了一些历史遗留的 BSD 数学函数。 虽然该文件本身不涉及 dynamic linker 的直接功能，但它测试的数学函数最终会被 Android 系统和应用程序调用，并通过 dynamic linker 加载到内存中。

Prompt: 
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
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE 1
#include <math.h>

// <math.h> is required to define type-generic macros: fpclassify, signbit,
// isfinite, isinf, isnan, isnormal, isgreater, isgreaterequal, isless,
// islessequal, islessgreater, and isunordered.
//
// <cmath> is required to #undef these macros and make equivalent sets of
// _overloaded_ functions available in namespace std. So the isnan() macro,
// for example, is replaced by std::isnan(float), std::isnan(double),
// and std::isnan(long double).
//
// We're trying to test the bionic macros rather than whatever libc++'s
// implementation happens to be, so we #include <math.h> and "capture" the
// macros in our own _template_ functions in the global namespace before
// we #include any files that include <cmath>, such as <gtest.h>.

#define capture_generic_macro(capture_function_name, generic_macro_name) \
  template <typename T> inline int capture_function_name(const T in) { \
    return generic_macro_name(in); \
  }

capture_generic_macro(test_capture_fpclassify, fpclassify)
capture_generic_macro(test_capture_signbit, signbit)
capture_generic_macro(test_capture_isfinite, isfinite)
capture_generic_macro(test_capture_isinf, isinf)
capture_generic_macro(test_capture_isnan, isnan)
capture_generic_macro(test_capture_isnormal, isnormal)
capture_generic_macro(test_capture_isgreater, isgreater)
capture_generic_macro(test_capture_isgreaterequal, isgreaterequal)
capture_generic_macro(test_capture_isless, isless)
capture_generic_macro(test_capture_islessequal, islessequal)
capture_generic_macro(test_capture_islessgreater, islessgreater)
capture_generic_macro(test_capture_isunordered, isunordered)

#include "math_data_test.h"

#include <gtest/gtest.h>

#include <fenv.h>
#include <float.h>
#include <limits.h>
#include <stdint.h>
#include <sys/cdefs.h>

#include <android-base/scopeguard.h>

// Now we've included all the headers we need, we can redefine the generic
// function-like macros to point to the bionic <math.h> versions we captured
// earlier.
#define fpclassify test_capture_fpclassify
#define signbit test_capture_signbit
#define isfinite test_capture_isfinite
#define isinf test_capture_isinf
#define isnan test_capture_isnan
#define isnormal test_capture_isnormal
#define isgreater test_capture_isgreater
#define isgreaterequal test_capture_isgreaterequal
#define isless test_capture_isless
#define islessequal test_capture_islessequal
#define islessgreater test_capture_islessgreater
#define isunordered test_capture_isunordered

static float float_subnormal() {
  union {
    float f;
    uint32_t i;
  } u;
  u.i = 0x007fffff;
  return u.f;
}

static double double_subnormal() {
  union {
    double d;
    uint64_t i;
  } u;
  u.i = 0x000fffffffffffffLL;
  return u.d;
}

static long double ldouble_subnormal() {
  union {
    long double e;
    unsigned char c[sizeof(long double)];
  } u;

  // Subnormals must have a zero exponent and non zero significand.
  // On all supported representation the 17 bit (counting from either sides)
  // is part of the significand so it should be enough to set that.
  // It also applies for the case sizeof(double) = sizeof(long double)
  for (unsigned int i = 0; i < sizeof(long double); i++) {
    u.c[i] = 0x00;
  }
  u.c[sizeof(long double) - 3] = 0x80;
  u.c[2] = 0x80;

  return u.e;
}

TEST(math_h, fpclassify) {
  ASSERT_EQ(FP_INFINITE, fpclassify(INFINITY));
  ASSERT_EQ(FP_INFINITE, fpclassify(HUGE_VALF));
  ASSERT_EQ(FP_INFINITE, fpclassify(-HUGE_VALF));
  ASSERT_EQ(FP_INFINITE, fpclassify(HUGE_VAL));
  ASSERT_EQ(FP_INFINITE, fpclassify(-HUGE_VAL));
  ASSERT_EQ(FP_INFINITE, fpclassify(HUGE_VALL));
  ASSERT_EQ(FP_INFINITE, fpclassify(-HUGE_VALL));

  ASSERT_EQ(FP_NAN, fpclassify(nanf("")));
  ASSERT_EQ(FP_NAN, fpclassify(nan("")));
  ASSERT_EQ(FP_NAN, fpclassify(nanl("")));

  ASSERT_EQ(FP_NORMAL, fpclassify(1.0f));
  ASSERT_EQ(FP_NORMAL, fpclassify(1.0));
  ASSERT_EQ(FP_NORMAL, fpclassify(1.0L));

  ASSERT_EQ(FP_SUBNORMAL, fpclassify(float_subnormal()));
  ASSERT_EQ(FP_SUBNORMAL, fpclassify(double_subnormal()));
  ASSERT_EQ(FP_SUBNORMAL, fpclassify(ldouble_subnormal()));

  ASSERT_EQ(FP_ZERO, fpclassify(0.0f));
  ASSERT_EQ(FP_ZERO, fpclassify(0.0));
  ASSERT_EQ(FP_ZERO, fpclassify(0.0L));
}

TEST(math_h, isfinite) {
  ASSERT_TRUE(isfinite(123.0f));
  ASSERT_TRUE(isfinite(123.0));
  ASSERT_TRUE(isfinite(123.0L));
  ASSERT_FALSE(isfinite(HUGE_VALF));
  ASSERT_FALSE(isfinite(-HUGE_VALF));
  ASSERT_FALSE(isfinite(HUGE_VAL));
  ASSERT_FALSE(isfinite(-HUGE_VAL));
  ASSERT_FALSE(isfinite(HUGE_VALL));
  ASSERT_FALSE(isfinite(-HUGE_VALL));
}

TEST(math_h, isinf) {
  ASSERT_FALSE(isinf(123.0f));
  ASSERT_FALSE(isinf(123.0));
  ASSERT_FALSE(isinf(123.0L));
  ASSERT_TRUE(isinf(HUGE_VALF));
  ASSERT_TRUE(isinf(-HUGE_VALF));
  ASSERT_TRUE(isinf(HUGE_VAL));
  ASSERT_TRUE(isinf(-HUGE_VAL));
  ASSERT_TRUE(isinf(HUGE_VALL));
  ASSERT_TRUE(isinf(-HUGE_VALL));
}

TEST(math_h, isnan) {
  ASSERT_FALSE(isnan(123.0f));
  ASSERT_FALSE(isnan(123.0));
  ASSERT_FALSE(isnan(123.0L));
  ASSERT_TRUE(isnan(nanf("")));
  ASSERT_TRUE(isnan(nan("")));
  ASSERT_TRUE(isnan(nanl("")));
}

TEST(math_h, isnormal) {
  ASSERT_TRUE(isnormal(123.0f));
  ASSERT_TRUE(isnormal(123.0));
  ASSERT_TRUE(isnormal(123.0L));
  ASSERT_FALSE(isnormal(float_subnormal()));
  ASSERT_FALSE(isnormal(double_subnormal()));
  ASSERT_FALSE(isnormal(ldouble_subnormal()));
}

// TODO: isgreater, isgreaterequals, isless, islessequal, islessgreater, isunordered
TEST(math_h, signbit) {
  ASSERT_EQ(0, signbit(0.0f));
  ASSERT_EQ(0, signbit(0.0));
  ASSERT_EQ(0, signbit(0.0L));

  ASSERT_EQ(0, signbit(1.0f));
  ASSERT_EQ(0, signbit(1.0));
  ASSERT_EQ(0, signbit(1.0L));

  ASSERT_NE(0, signbit(-1.0f));
  ASSERT_NE(0, signbit(-1.0));
  ASSERT_NE(0, signbit(-1.0L));
}

// Historical BSD cruft that isn't exposed in <math.h> any more.
extern "C" int __fpclassify(double);
extern "C" int __fpclassifyd(double);
extern "C" int __fpclassifyf(float);
extern "C" int __fpclassifyl(long double);

TEST(math_h, __fpclassify) {
  ASSERT_EQ(FP_INFINITE, __fpclassify(HUGE_VAL));
  ASSERT_EQ(FP_INFINITE, __fpclassify(-HUGE_VAL));
  ASSERT_EQ(FP_NAN, __fpclassify(nan("")));
  ASSERT_EQ(FP_NORMAL, __fpclassify(1.0));
  ASSERT_EQ(FP_SUBNORMAL, __fpclassify(double_subnormal()));
  ASSERT_EQ(FP_ZERO, __fpclassify(0.0));
}

TEST(math_h, __fpclassifyd) {
#if defined(__GLIBC__) || defined(ANDROID_HOST_MUSL)
#define __fpclassifyd __fpclassify
#endif
  ASSERT_EQ(FP_INFINITE, __fpclassifyd(HUGE_VAL));
  ASSERT_EQ(FP_INFINITE, __fpclassifyd(-HUGE_VAL));
  ASSERT_EQ(FP_NAN, __fpclassifyd(nan("")));
  ASSERT_EQ(FP_NORMAL, __fpclassifyd(1.0));
  ASSERT_EQ(FP_SUBNORMAL, __fpclassifyd(double_subnormal()));
  ASSERT_EQ(FP_ZERO, __fpclassifyd(0.0));
}

TEST(math_h, __fpclassifyf) {
  ASSERT_EQ(FP_INFINITE, __fpclassifyf(HUGE_VALF));
  ASSERT_EQ(FP_INFINITE, __fpclassifyf(-HUGE_VALF));
  ASSERT_EQ(FP_NAN, __fpclassifyf(nanf("")));
  ASSERT_EQ(FP_NORMAL, __fpclassifyf(1.0f));
  ASSERT_EQ(FP_SUBNORMAL, __fpclassifyf(float_subnormal()));
  ASSERT_EQ(FP_ZERO, __fpclassifyf(0.0f));
}

TEST(math_h, __fpclassifyl) {
  EXPECT_EQ(FP_INFINITE, __fpclassifyl(HUGE_VALL));
  EXPECT_EQ(FP_INFINITE, __fpclassifyl(-HUGE_VALL));
  EXPECT_EQ(FP_NAN, __fpclassifyl(nanl("")));
  EXPECT_EQ(FP_NORMAL, __fpclassifyl(1.0L));
  EXPECT_EQ(FP_SUBNORMAL, __fpclassifyl(ldouble_subnormal()));
  EXPECT_EQ(FP_ZERO, __fpclassifyl(0.0L));
}

TEST(math_h, finitef) {
  ASSERT_TRUE(finitef(123.0f));
  ASSERT_FALSE(finitef(HUGE_VALF));
  ASSERT_FALSE(finitef(-HUGE_VALF));
}

// Historical BSD cruft that isn't exposed in <math.h> any more.
extern "C" int __isfinite(double);
extern "C" int __isfinitef(float);
extern "C" int isfinitef(float);
extern "C" int __isfinitel(long double);
extern "C" int isfinitel(long double);

TEST(math_h, __isfinite) {
#if defined(__GLIBC__)
#define __isfinite __finite
#elif defined(ANDROID_HOST_MUSL)
#define __isfinite isfinite
#endif
  ASSERT_TRUE(__isfinite(123.0));
  ASSERT_FALSE(__isfinite(HUGE_VAL));
  ASSERT_FALSE(__isfinite(-HUGE_VAL));
}

TEST(math_h, __isfinitef) {
#if defined(__GLIBC__)
#define __isfinitef __finitef
#elif defined(ANDROID_HOST_MUSL)
#define __isfinitef isfinite
#endif
  ASSERT_TRUE(__isfinitef(123.0f));
  ASSERT_FALSE(__isfinitef(HUGE_VALF));
  ASSERT_FALSE(__isfinitef(-HUGE_VALF));
}

TEST(math_h, isfinitef) {
#if defined(__GLIBC__)
#define isfinitef __finitef
#elif defined(ANDROID_HOST_MUSL)
#define isfinitef isfinite
#endif
  ASSERT_TRUE(isfinitef(123.0f));
  ASSERT_FALSE(isfinitef(HUGE_VALF));
  ASSERT_FALSE(isfinitef(-HUGE_VALF));
}

TEST(math_h, __isfinitel) {
#if defined(__GLIBC__)
#define __isfinitel __finitel
#elif defined(ANDROID_HOST_MUSL)
#define __isfinitel isfinite
#endif
  ASSERT_TRUE(__isfinitel(123.0L));
  ASSERT_FALSE(__isfinitel(HUGE_VALL));
  ASSERT_FALSE(__isfinitel(-HUGE_VALL));
}

TEST(math_h, isfinitel) {
#if defined(__GLIBC__)
#define isfinitel __finitel
#elif defined(ANDROID_HOST_MUSL)
#define isfinitel isfinite
#endif
  ASSERT_TRUE(isfinitel(123.0L));
  ASSERT_FALSE(isfinitel(HUGE_VALL));
  ASSERT_FALSE(isfinitel(-HUGE_VALL));
}

TEST(math_h, finite) {
  ASSERT_TRUE(finite(123.0));
  ASSERT_FALSE(finite(HUGE_VAL));
  ASSERT_FALSE(finite(-HUGE_VAL));
}

TEST(math_h, isinf_function) {
  // The isinf macro deals with all three types; the isinf function is for doubles.
  ASSERT_FALSE((isinf)(123.0));
  ASSERT_TRUE((isinf)(HUGE_VAL));
  ASSERT_TRUE((isinf)(-HUGE_VAL));
}

// Historical BSD cruft that isn't exposed in <math.h> any more.
extern "C" int __isinf(double);
extern "C" int __isinff(float);
extern "C" int __isinfl(long double);

TEST(math_h, __isinf) {
#if defined(ANDROID_HOST_MUSL)
#define __isinf isinf
#endif
  ASSERT_FALSE(__isinf(123.0));
  ASSERT_TRUE(__isinf(HUGE_VAL));
  ASSERT_TRUE(__isinf(-HUGE_VAL));
}

TEST(math_h, __isinff) {
#if defined(ANDROID_HOST_MUSL)
#define __isinff isinf
#endif
  ASSERT_FALSE(__isinff(123.0f));
  ASSERT_TRUE(__isinff(HUGE_VALF));
  ASSERT_TRUE(__isinff(-HUGE_VALF));
}

TEST(math_h, isinff) {
#if defined(ANDROID_HOST_MUSL)
#define isinff isinf
#endif
  ASSERT_FALSE(isinff(123.0f));
  ASSERT_TRUE(isinff(HUGE_VALF));
  ASSERT_TRUE(isinff(-HUGE_VALF));
}

TEST(math_h, __isinfl) {
#if defined(ANDROID_HOST_MUSL)
#define __isinfl isinf
#endif
  ASSERT_FALSE(__isinfl(123.0L));
  ASSERT_TRUE(__isinfl(HUGE_VALL));
  ASSERT_TRUE(__isinfl(-HUGE_VALL));
}

TEST(math_h, isinfl) {
#if defined(ANDROID_HOST_MUSL)
#define isinfl isinf
#endif
  ASSERT_FALSE(isinfl(123.0L));
  ASSERT_TRUE(isinfl(HUGE_VALL));
  ASSERT_TRUE(isinfl(-HUGE_VALL));
}

TEST(math_h, isnan_function) {
  // The isnan macro deals with all three types; the isnan function is for doubles.
  ASSERT_FALSE((isnan)(123.0));
  ASSERT_TRUE((isnan)(nan("")));
}

// Historical BSD cruft that isn't exposed in <math.h> any more.
extern "C" int __isnan(double);
extern "C" int __isnanf(float);
extern "C" int __isnanl(long double);

TEST(math_h, __isnan) {
#if defined(ANDROID_HOST_MUSL)
#define __isnan isnan
#endif
  ASSERT_FALSE(__isnan(123.0));
  ASSERT_TRUE(__isnan(nan("")));
}

TEST(math_h, __isnanf) {
#if defined(ANDROID_HOST_MUSL)
#define __isnanf isnan
#endif
  ASSERT_FALSE(__isnanf(123.0f));
  ASSERT_TRUE(__isnanf(nanf("")));
}

TEST(math_h, isnanf) {
#if defined(ANDROID_HOST_MUSL)
#define isnanf isnan
#endif
  ASSERT_FALSE(isnanf(123.0f));
  ASSERT_TRUE(isnanf(nanf("")));
}

TEST(math_h, __isnanl) {
#if defined(ANDROID_HOST_MUSL)
#define __isnanl isnan
#endif
  ASSERT_FALSE(__isnanl(123.0L));
  ASSERT_TRUE(__isnanl(nanl("")));
}

TEST(math_h, isnanl) {
#if defined(ANDROID_HOST_MUSL)
#define isnanl isnan
#endif
  ASSERT_FALSE(isnanl(123.0L));
  ASSERT_TRUE(isnanl(nanl("")));
}

// Historical BSD cruft that isn't exposed in <math.h> any more.
extern "C" int __isnormal(double);
extern "C" int __isnormalf(float);
extern "C" int isnormalf(float);
extern "C" int __isnormall(long double);
extern "C" int isnormall(long double);

TEST(math_h, __isnormal) {
#if defined(__BIONIC__)
  ASSERT_TRUE(__isnormal(123.0));
  ASSERT_FALSE(__isnormal(double_subnormal()));
#else // __BIONIC__
  GTEST_SKIP() << "glibc doesn't have __isnormal";
#endif // __BIONIC__
}

TEST(math_h, __isnormalf) {
#if defined(__BIONIC__)
  ASSERT_TRUE(__isnormalf(123.0f));
  ASSERT_FALSE(__isnormalf(float_subnormal()));
#else // __BIONIC__
  GTEST_SKIP() << "glibc doesn't have __isnormalf";
#endif // __BIONIC__
}

TEST(math_h, isnormalf) {
#if defined(__BIONIC__)
  ASSERT_TRUE(isnormalf(123.0f));
  ASSERT_FALSE(isnormalf(float_subnormal()));
#else // __BIONIC__
  GTEST_SKIP() << "glibc doesn't have isnormalf";
#endif // __BIONIC__
}

TEST(math_h, __isnormall) {
#if defined(__BIONIC__)
  ASSERT_TRUE(__isnormall(123.0L));
  ASSERT_FALSE(__isnormall(ldouble_subnormal()));
#else // __BIONIC__
  GTEST_SKIP() << "glibc doesn't have __isnormall";
#endif // __BIONIC__
}

TEST(math_h, isnormall) {
#if defined(__BIONIC__)
  ASSERT_TRUE(isnormall(123.0L));
  ASSERT_FALSE(isnormall(ldouble_subnormal()));
#else // __BIONIC__
  GTEST_SKIP() << "glibc doesn't have isnormall";
#endif // __BIONIC__
}

// Historical BSD cruft that isn't exposed in <math.h> any more.
extern "C" int __signbit(double);
extern "C" int __signbitf(float);
extern "C" int __signbitl(long double);

TEST(math_h, __signbit) {
  ASSERT_EQ(0, __signbit(0.0));
  ASSERT_EQ(0, __signbit(1.0));
  ASSERT_NE(0, __signbit(-1.0));
}

TEST(math_h, __signbitf) {
  ASSERT_EQ(0, __signbitf(0.0f));
  ASSERT_EQ(0, __signbitf(1.0f));
  ASSERT_NE(0, __signbitf(-1.0f));
}

TEST(math_h, __signbitl) {
  ASSERT_EQ(0L, __signbitl(0.0L));
  ASSERT_EQ(0L, __signbitl(1.0L));
  ASSERT_NE(0L, __signbitl(-1.0L));
}

TEST(math_h, acos) {
  ASSERT_DOUBLE_EQ(M_PI/2.0, acos(0.0));
}

TEST(math_h, acosf) {
  ASSERT_FLOAT_EQ(static_cast<float>(M_PI)/2.0f, acosf(0.0f));
}

TEST(math_h, acosl) {
  ASSERT_DOUBLE_EQ(M_PI/2.0L, acosl(0.0L));
}

TEST(math_h, asin) {
  ASSERT_DOUBLE_EQ(0.0, asin(0.0));
}

TEST(math_h, asinf) {
  ASSERT_FLOAT_EQ(0.0f, asinf(0.0f));
}

TEST(math_h, asinl) {
  ASSERT_DOUBLE_EQ(0.0L, asinl(0.0L));
}

TEST(math_h, atan) {
  ASSERT_DOUBLE_EQ(0.0, atan(0.0));
}

TEST(math_h, atanf) {
  ASSERT_FLOAT_EQ(0.0f, atanf(0.0f));
}

TEST(math_h, atanl) {
  ASSERT_DOUBLE_EQ(0.0L, atanl(0.0L));
}

TEST(math_h, atan2) {
  ASSERT_DOUBLE_EQ(0.0, atan2(0.0, 0.0));
}

TEST(math_h, atan2f) {
  ASSERT_FLOAT_EQ(0.0f, atan2f(0.0f, 0.0f));
}

TEST(math_h, atan2l) {
  ASSERT_DOUBLE_EQ(0.0L, atan2l(0.0L, 0.0L));
}

TEST(math_h, cos) {
  ASSERT_DOUBLE_EQ(1.0, cos(0.0));
}

TEST(math_h, cosf) {
  ASSERT_FLOAT_EQ(1.0f, cosf(0.0f));
}

TEST(math_h, cosl) {
  ASSERT_DOUBLE_EQ(1.0L, cosl(0.0L));
}

TEST(math_h, sin) {
  ASSERT_DOUBLE_EQ(0.0, sin(0.0));
}

TEST(math_h, sinf) {
  ASSERT_FLOAT_EQ(0.0f, sinf(0.0f));
}

TEST(math_h, sinl) {
  ASSERT_DOUBLE_EQ(0.0L, sinl(0.0L));
}

TEST(math_h, sincos) {
  double s, c;
  sincos(0.0, &s, &c);
  ASSERT_DOUBLE_EQ(0.0, s);
  ASSERT_DOUBLE_EQ(1.0, c);
}

TEST(math_h, sincosf) {
  float s, c;
  sincosf(0.0f, &s, &c);
  ASSERT_FLOAT_EQ(0.0f, s);
  ASSERT_FLOAT_EQ(1.0f, c);
}

TEST(math_h, sincosl) {
  long double s, c;
  sincosl(0.0L, &s, &c);
  ASSERT_DOUBLE_EQ(0.0L, s);
  ASSERT_DOUBLE_EQ(1.0L, c);
}

TEST(math_h, tan) {
  ASSERT_DOUBLE_EQ(0.0, tan(0.0));
}

TEST(math_h, tanf) {
  ASSERT_FLOAT_EQ(0.0f, tanf(0.0f));
}

TEST(math_h, tanl) {
  ASSERT_DOUBLE_EQ(0.0L, tanl(0.0L));
}

TEST(math_h, acosh) {
  ASSERT_DOUBLE_EQ(0.0, acosh(1.0));
}

TEST(math_h, acoshf) {
  ASSERT_FLOAT_EQ(0.0f, acoshf(1.0f));
}

TEST(math_h, acoshl) {
  ASSERT_DOUBLE_EQ(0.0L, acoshl(1.0L));
}

TEST(math_h, asinh) {
  ASSERT_DOUBLE_EQ(0.0, asinh(0.0));
}

TEST(math_h, asinhf) {
  ASSERT_FLOAT_EQ(0.0f, asinhf(0.0f));
}

TEST(math_h, asinhl) {
  ASSERT_DOUBLE_EQ(0.0L, asinhl(0.0L));
}

TEST(math_h, atanh) {
  ASSERT_DOUBLE_EQ(0.0, atanh(0.0));
}

TEST(math_h, atanhf) {
  ASSERT_FLOAT_EQ(0.0f, atanhf(0.0f));
}

TEST(math_h, atanhl) {
  ASSERT_DOUBLE_EQ(0.0L, atanhl(0.0L));
}

TEST(math_h, cosh) {
  ASSERT_DOUBLE_EQ(1.0, cosh(0.0));
}

TEST(math_h, coshf) {
  ASSERT_FLOAT_EQ(1.0f, coshf(0.0f));
}

TEST(math_h, coshl) {
  ASSERT_DOUBLE_EQ(1.0L, coshl(0.0L));
}

TEST(math_h, sinh) {
  ASSERT_DOUBLE_EQ(0.0, sinh(0.0));
}

TEST(math_h, sinhf) {
  ASSERT_FLOAT_EQ(0.0f, sinhf(0.0f));
}

TEST(math_h, sinhl) {
  ASSERT_DOUBLE_EQ(0.0L, sinhl(0.0L));
}

TEST(math_h, tanh) {
  ASSERT_DOUBLE_EQ(0.0, tanh(0.0));
}

TEST(math_h, tanhf) {
  ASSERT_FLOAT_EQ(0.0f, tanhf(0.0f));
}

TEST(math_h, tanhl) {
  ASSERT_DOUBLE_EQ(0.0L, tanhl(0.0L));
}

TEST(math_h, log) {
  ASSERT_DOUBLE_EQ(1.0, log(M_E));
}

TEST(math_h, logf) {
  ASSERT_FLOAT_EQ(1.0f, logf(static_cast<float>(M_E)));
}

TEST(math_h, logl) {
  ASSERT_DOUBLE_EQ(1.0L, logl(M_E));
}

TEST(math_h, log2) {
  ASSERT_DOUBLE_EQ(12.0, log2(4096.0));
}

TEST(math_h, log2f) {
  ASSERT_FLOAT_EQ(12.0f, log2f(4096.0f));
}

TEST(math_h, log2l) {
  ASSERT_DOUBLE_EQ(12.0L, log2l(4096.0L));
}

TEST(math_h, log10) {
  ASSERT_DOUBLE_EQ(3.0, log10(1000.0));
}

TEST(math_h, log10f) {
  ASSERT_FLOAT_EQ(3.0f, log10f(1000.0f));
}

TEST(math_h, log10l) {
  ASSERT_DOUBLE_EQ(3.0L, log10l(1000.0L));
}

TEST(math_h, cbrt) {
  ASSERT_DOUBLE_EQ(3.0, cbrt(27.0));
}

TEST(math_h, cbrtf) {
  ASSERT_FLOAT_EQ(3.0f, cbrtf(27.0f));
}

TEST(math_h, cbrtl) {
  ASSERT_DOUBLE_EQ(3.0L, cbrtl(27.0L));
}

TEST(math_h, sqrt) {
  ASSERT_DOUBLE_EQ(2.0, sqrt(4.0));
}

TEST(math_h, sqrtf) {
  ASSERT_FLOAT_EQ(2.0f, sqrtf(4.0f));
}

TEST(math_h, sqrtl) {
  ASSERT_DOUBLE_EQ(2.0L, sqrtl(4.0L));
}

TEST(math_h, exp) {
  ASSERT_DOUBLE_EQ(1.0, exp(0.0));
  ASSERT_DOUBLE_EQ(M_E, exp(1.0));
}

TEST(math_h, expf) {
  ASSERT_FLOAT_EQ(1.0f, expf(0.0f));
  ASSERT_FLOAT_EQ(static_cast<float>(M_E), expf(1.0f));
}

TEST(math_h, expl) {
  ASSERT_DOUBLE_EQ(1.0L, expl(0.0L));
  ASSERT_DOUBLE_EQ(M_E, expl(1.0L));
}

TEST(math_h, exp2) {
  ASSERT_DOUBLE_EQ(8.0, exp2(3.0));
}

TEST(math_h, exp2f) {
  ASSERT_FLOAT_EQ(8.0f, exp2f(3.0f));
}

TEST(math_h, exp2l) {
  ASSERT_DOUBLE_EQ(8.0L, exp2l(3.0L));
}

TEST(math_h, expm1) {
  ASSERT_DOUBLE_EQ(M_E - 1.0, expm1(1.0));
}

TEST(math_h, expm1f) {
  ASSERT_FLOAT_EQ(static_cast<float>(M_E) - 1.0f, expm1f(1.0f));
}

TEST(math_h, expm1l) {
  ASSERT_DOUBLE_EQ(M_E - 1.0L, expm1l(1.0L));
}

TEST(math_h, pow) {
  ASSERT_TRUE(isnan(pow(nan(""), 3.0)));
  ASSERT_DOUBLE_EQ(1.0, (pow(1.0, nan(""))));
  ASSERT_TRUE(isnan(pow(2.0, nan(""))));
  ASSERT_DOUBLE_EQ(8.0, pow(2.0, 3.0));
}

TEST(math_h, powf) {
  ASSERT_TRUE(isnanf(powf(nanf(""), 3.0f)));
  ASSERT_FLOAT_EQ(1.0f, (powf(1.0f, nanf(""))));
  ASSERT_TRUE(isnanf(powf(2.0f, nanf(""))));
  ASSERT_FLOAT_EQ(8.0f, powf(2.0f, 3.0f));
}

TEST(math_h, powl) {
  ASSERT_TRUE(__isnanl(powl(nanl(""), 3.0L)));
  ASSERT_DOUBLE_EQ(1.0L, (powl(1.0L, nanl(""))));
  ASSERT_TRUE(__isnanl(powl(2.0L, nanl(""))));
  ASSERT_DOUBLE_EQ(8.0L, powl(2.0L, 3.0L));
}

TEST(math_h, ceil) {
  ASSERT_DOUBLE_EQ(1.0, ceil(0.9));
}

TEST(math_h, ceilf) {
  ASSERT_FLOAT_EQ(1.0f, ceilf(0.9f));
}

TEST(math_h, ceill) {
  ASSERT_DOUBLE_EQ(1.0L, ceill(0.9L));
}

TEST(math_h, floor) {
  ASSERT_DOUBLE_EQ(1.0, floor(1.1));
}

TEST(math_h, floorf) {
  ASSERT_FLOAT_EQ(1.0f, floorf(1.1f));
}

TEST(math_h, floorl) {
  ASSERT_DOUBLE_EQ(1.0L, floorl(1.1L));
}

TEST(math_h, fabs) {
  ASSERT_DOUBLE_EQ(1.0, fabs(-1.0));
}

TEST(math_h, fabsf) {
  ASSERT_FLOAT_EQ(1.0f, fabsf(-1.0f));
}

TEST(math_h, fabsl) {
  ASSERT_DOUBLE_EQ(1.0L, fabsl(-1.0L));
}

TEST(math_h, ldexp) {
  ASSERT_DOUBLE_EQ(16.0, ldexp(2.0, 3.0));
}

TEST(math_h, ldexpf) {
  ASSERT_FLOAT_EQ(16.0f, ldexpf(2.0f, 3.0f));
}

TEST(math_h, ldexpl) {
  ASSERT_DOUBLE_EQ(16.0L, ldexpl(2.0L, 3.0));
}

TEST(math_h, fmod) {
  ASSERT_DOUBLE_EQ(2.0, fmod(12.0, 10.0));

  // If x is an infinity, NaN is returned.
  ASSERT_TRUE(isnan(fmod(HUGE_VAL, 10.0f)));
  ASSERT_TRUE(isnan(fmod(-HUGE_VAL, 10.0f)));

  // If x or y is a NaN, NaN is returned.
  ASSERT_TRUE(isnan(fmod(nan(""), 10.0)));
  ASSERT_TRUE(isnan(fmod(12.0, nan(""))));

  // If y is 0, NaN is returned.
  ASSERT_TRUE(isnan(fmod(3.0, 0.0)));
}

TEST(math_h, fmodf) {
  ASSERT_FLOAT_EQ(2.0f, fmodf(12.0f, 10.0f));

  // If x is an infinity, NaN is returned.
  ASSERT_TRUE(isnanf(fmodf(HUGE_VALF, 10.0f)));
  ASSERT_TRUE(isnanf(fmodf(-HUGE_VALF, 10.0f)));

  // If x or y is a NaN, NaN is returned.
  ASSERT_TRUE(isnanf(fmodf(nanf(""), 10.0f)));
  ASSERT_TRUE(isnanf(fmodf(12.0f, nan(""))));

  // If y is 0, NaN is returned.
  ASSERT_TRUE(isnanf(fmodf(3.0f, 0.0f)));
}

TEST(math_h, fmodl) {
  ASSERT_DOUBLE_EQ(2.0L, fmodl(12.0L, 10.0L));

  // If x is an infinity, NaN is returned.
  ASSERT_TRUE(isnanl(fmodl(HUGE_VALL, 10.0L)));
  ASSERT_TRUE(isnanl(fmodl(-HUGE_VALL, 10.0L)));

  // If x or y is a NaN, NaN is returned.
  ASSERT_TRUE(isnanl(fmodl(nanl(""), 10.0L)));
  ASSERT_TRUE(isnanl(fmodl(12.0L, nanl(""))));

  // If y is 0, NaN is returned.
  ASSERT_TRUE(isnanl(fmodl(3.0L, 0.0L)));
}

TEST(math_h, remainder) {
  ASSERT_DOUBLE_EQ(2.0, remainder(12.0, 10.0));

  // If x or y is a NaN, NaN is returned.
  ASSERT_TRUE(isnan(remainder(nan(""), 10.0)));
  ASSERT_TRUE(isnan(remainder(12.0, nan(""))));

  // If x is an infinity, NaN is returned.
  ASSERT_TRUE(isnan(remainder(HUGE_VAL, 10.0)));
  ASSERT_TRUE(isnan(remainder(-HUGE_VAL, 10.0)));

  // If y is 0, NaN is returned.
  ASSERT_TRUE(isnan(remainder(12.0, 0.0)));
}

TEST(math_h, remainderf) {
  ASSERT_FLOAT_EQ(2.0f, remainderf(12.0f, 10.0f));

  // If x or y is a NaN, NaN is returned.
  ASSERT_TRUE(isnanf(remainderf(nanf(""), 10.0f)));
  ASSERT_TRUE(isnanf(remainderf(12.0f, nanf(""))));

  // If x is an infinity, NaN is returned.
  ASSERT_TRUE(isnanf(remainderf(HUGE_VALF, 10.0f)));
  ASSERT_TRUE(isnanf(remainderf(-HUGE_VALF, 10.0f)));

  // If y is 0, NaN is returned.
  ASSERT_TRUE(isnanf(remainderf(12.0f, 0.0f)));
}

TEST(math_h, remainderl) {
  ASSERT_DOUBLE_EQ(2.0L, remainderl(12.0L, 10.0L));

  // If x or y is a NaN, NaN is returned.
  ASSERT_TRUE(isnanl(remainderl(nanl(""), 10.0L)));
  ASSERT_TRUE(isnanl(remainderl(12.0L, nanl(""))));

  // If x is an infinity, NaN is returned.
  ASSERT_TRUE(isnanl(remainderl(HUGE_VALL, 10.0L)));
  ASSERT_TRUE(isnanl(remainderl(-HUGE_VALL, 10.0L)));

  // If y is 0, NaN is returned.
  ASSERT_TRUE(isnanl(remainderl(12.0L, 0.0L)));
}

TEST(math_h, drem) {
  ASSERT_DOUBLE_EQ(2.0, drem(12.0, 10.0));
}

TEST(math_h, dremf) {
  ASSERT_FLOAT_EQ(2.0f, dremf(12.0f, 10.0f));
}

TEST(math_h, fmax) {
  ASSERT_DOUBLE_EQ(12.0, fmax(12.0, 10.0));
  ASSERT_DOUBLE_EQ(12.0, fmax(12.0, nan("")));
  ASSERT_DOUBLE_EQ(12.0, fmax(nan(""), 12.0));
}

TEST(math_h, fmaxf) {
  ASSERT_FLOAT_EQ(12.0f, fmaxf(12.0f, 10.0f));
  ASSERT_FLOAT_EQ(12.0f, fmaxf(12.0f, nanf("")));
  ASSERT_FLOAT_EQ(12.0f, fmaxf(nanf(""), 12.0f));
}

TEST(math_h, fmaxl) {
  ASSERT_DOUBLE_EQ(12.0L, fmaxl(12.0L, 10.0L));
  ASSERT_DOUBLE_EQ(12.0L, fmaxl(12.0L, nanl("")));
  ASSERT_DOUBLE_EQ(12.0L, fmaxl(nanl(""), 12.0L));
}

TEST(math_h, fmin) {
  ASSERT_DOUBLE_EQ(10.0, fmin(12.0, 10.0));
  ASSERT_DOUBLE_EQ(12.0, fmin(12.0, nan("")));
  ASSERT_DOUBLE_EQ(12.0, fmin(nan(""), 12.0));
}

TEST(math_h, fminf) {
  ASSERT_FLOAT_EQ(10.0f, fminf(12.0f, 10.0f));
  ASSERT_FLOAT_EQ(12.0f, fminf(12.0f, nanf("")));
  ASSERT_FLOAT_EQ(12.0f, fminf(nanf(""), 12.0f));
}

TEST(math_h, fminl) {
  ASSERT_DOUBLE_EQ(10.0L, fminl(12.0L, 10.0L));
  ASSERT_DOUBLE_EQ(12.0L, fminl(12.0L, nanl("")));
  ASSERT_DOUBLE_EQ(12.0L, fminl(nanl(""), 12.0L));
}

TEST(math_h, fma) {
  ASSERT_DOUBLE_EQ(10.0, fma(2.0, 3.0, 4.0));
}

TEST(math_h, fmaf) {
  ASSERT_FLOAT_EQ(10.0f, fmaf(2.0f, 3.0f, 4.0f));
}

TEST(math_h, fmal) {
  ASSERT_DOUBLE_EQ(10.0L, fmal(2.0L, 3.0L, 4.0L));
}

TEST(math_h, hypot) {
  ASSERT_DOUBLE_EQ(5.0, hypot(3.0, 4.0));

  // If x or y is an infinity, returns positive infinity.
  ASSERT_EQ(HUGE_VAL, hypot(3.0, HUGE_VAL));
  ASSERT_EQ(HUGE_VAL, hypot(3.0, -HUGE_VAL));
  ASSERT_EQ(HUGE_VAL, hypot(HUGE_VAL, 4.0));
  ASSERT_EQ(HUGE_VAL, hypot(-HUGE_VAL, 4.0));

  // If x or y is a NaN, returns NaN.
  ASSERT_TRUE(isnan(hypot(3.0, nan(""))));
  ASSERT_TRUE(isnan(hypot(nan(""), 4.0)));
}

TEST(math_h, hypotf) {
  ASSERT_FLOAT_EQ(5.0f, hypotf(3.0f, 4.0f));

  // If x or y is an infinity, returns positive infinity.
  ASSERT_EQ(HUGE_VALF, hypotf(3.0f, HUGE_VALF));
  ASSERT_EQ(HUGE_VALF, hypotf(3.0f, -HUGE_VALF));
  ASSERT_EQ(HUGE_VALF, hypotf(HUGE_VALF, 4.0f));
  ASSERT_EQ(HUGE_VALF, hypotf(-HUGE_VALF, 4.0f));

  // If x or y is a NaN, returns NaN.
  ASSERT_TRUE(isnanf(hypotf(3.0f, nanf(""))));
  ASSERT_TRUE(isnanf(hypotf(nanf(""), 4.0f)));
}

TEST(math_h, hypotl) {
  ASSERT_DOUBLE_EQ(5.0L, hypotl(3.0L, 4.0L));

  // If x or y is an infinity, returns positive infinity.
  ASSERT_EQ(HUGE_VALL, hypotl(3.0L, HUGE_VALL));
  ASSERT_EQ(HUGE_VALL, hypotl(3.0L, -HUGE_VALL));
  ASSERT_EQ(HUGE_VALL, hypotl(HUGE_VALL, 4.0L));
  ASSERT_EQ(HUGE_VALL, hypotl(-HUGE_VALL, 4.0L));

  // If x or y is a NaN, returns NaN.
  ASSERT_TRUE(isnanl(hypotl(3.0L, nanl(""))));
  ASSERT_TRUE(isnanl(hypotl(nanl(""), 4.0L)));
}

TEST(math_h, erf) {
  ASSERT_DOUBLE_EQ(0.84270079294971489, erf(1.0));
}

TEST(math_h, erff) {
  ASSERT_FLOAT_EQ(0.84270078f, erff(1.0f));
}

TEST(math_h, erfl) {
  ASSERT_DOUBLE_EQ(0.84270079294971489L, erfl(1.0L));
}

TEST(math_h, erfc) {
  ASSERT_DOUBLE_EQ(0.15729920705028513, erfc(1.0));
}

TEST(math_h, erfcf) {
  ASSERT_FLOAT_EQ(0.15729921f, erfcf(1.0f));
}

TEST(math_h, erfcl) {
  ASSERT_DOUBLE_EQ(0.15729920705028513L, erfcl(1.0L));
}

TEST(math_h, lrint) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });

  fesetround(FE_UPWARD); // lrint/lrintf/lrintl obey the rounding mode.
  EXPECT_EQ(1235, lrint(1234.01));
  EXPECT_EQ(1235, lrintf(1234.01f));
  EXPECT_EQ(1235, lrintl(1234.01L));
  fesetround(FE_TOWARDZERO); // lrint/lrintf/lrintl obey the rounding mode.
  EXPECT_EQ(1234, lrint(1234.01));
  EXPECT_EQ(1234, lrintf(1234.01f));
  EXPECT_EQ(1234, lrintl(1234.01L));

  fesetround(FE_UPWARD); // llrint/llrintf/llrintl obey the rounding mode.
  EXPECT_EQ(1235L, llrint(1234.01));
  EXPECT_EQ(1235L, llrintf(1234.01f));
  EXPECT_EQ(1235L, llrintl(1234.01L));
  fesetround(FE_TOWARDZERO); // llrint/llrintf/llrintl obey the rounding mode.
  EXPECT_EQ(1234L, llrint(1234.01));
  EXPECT_EQ(1234L, llrintf(1234.01f));
  EXPECT_EQ(1234L, llrintl(1234.01L));
}

TEST(math_h, rint) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });

  fesetround(FE_UPWARD); // rint/rintf/rintl obey the rounding mode.
  feclearexcept(FE_ALL_EXCEPT); // rint/rintf/rintl do set the FE_INEXACT flag.
  ASSERT_EQ(1234.0, rint(1234.0));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) == 0);
  ASSERT_EQ(1235.0, rint(1234.01));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) != 0);

  feclearexcept(FE_ALL_EXCEPT); // rint/rintf/rintl do set the FE_INEXACT flag.
  ASSERT_EQ(1234.0f, rintf(1234.0f));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) == 0);
  ASSERT_EQ(1235.0f, rintf(1234.01f));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) != 0);

  feclearexcept(FE_ALL_EXCEPT); // rint/rintf/rintl do set the FE_INEXACT flag.
  ASSERT_EQ(1234.0, rintl(1234.0L));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) == 0);
  ASSERT_EQ(1235.0, rintl(1234.01L));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) != 0);

  fesetround(FE_TOWARDZERO); // rint/rintf obey the rounding mode.
  ASSERT_EQ(1234.0, rint(1234.01));
  ASSERT_EQ(1234.0f, rintf(1234.01f));
  ASSERT_EQ(1234.0, rintl(1234.01L));
}

TEST(math_h, nearbyint) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });
  fesetround(FE_UPWARD); // nearbyint/nearbyintf/nearbyintl obey the rounding mode.
  feclearexcept(FE_ALL_EXCEPT); // nearbyint/nearbyintf/nearbyintl don't set the FE_INEXACT flag.
  ASSERT_EQ(1234.0, nearbyint(1234.0));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) == 0);
  ASSERT_EQ(1235.0, nearbyint(1234.01));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) == 0);

  feclearexcept(FE_ALL_EXCEPT);
  ASSERT_EQ(1234.0f, nearbyintf(1234.0f));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) == 0);
  ASSERT_EQ(1235.0f, nearbyintf(1234.01f));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) == 0);

  feclearexcept(FE_ALL_EXCEPT); // nearbyint/nearbyintf/nearbyintl don't set the FE_INEXACT flag.
  ASSERT_EQ(1234.0, nearbyintl(1234.0L));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) == 0);
  ASSERT_EQ(1235.0, nearbyintl(1234.01L));
  ASSERT_TRUE((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) == 0);

  fesetround(FE_TOWARDZERO); // nearbyint/nearbyintf/nearbyintl obey the rounding mode.
  ASSERT_EQ(1234.0, nearbyint(1234.01));
  ASSERT_EQ(1234.0f, nearbyintf(1234.01f));
  ASSERT_EQ(1234.0, nearbyintl(1234.01L));
}

TEST(math_h, lround) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });
  fesetround(FE_UPWARD); // lround ignores the rounding mode.
  ASSERT_EQ(1234, lround(1234.01));
  ASSERT_EQ(1234, lroundf(1234.01f));
  ASSERT_EQ(1234, lroundl(1234.01L));
}

TEST(math_h, llround) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });
  fesetround(FE_UPWARD); // llround ignores the rounding mode.
  ASSERT_EQ(1234L, llround(1234.01));
  ASSERT_EQ(1234L, llroundf(1234.01f));
  ASSERT_EQ(1234L, llroundl(1234.01L));
}

TEST(math_h, ilogb) {
  ASSERT_EQ(FP_ILOGB0, ilogb(0.0));
  ASSERT_EQ(FP_ILOGBNAN, ilogb(nan("")));
  ASSERT_EQ(INT_MAX, ilogb(HUGE_VAL));
  ASSERT_EQ(INT_MAX, ilogb(-HUGE_VAL));
  ASSERT_EQ(0, ilogb(1.0));
  ASSERT_EQ(3, ilogb(10.0));
}

TEST(math_h, ilogbf) {
  ASSERT_EQ(FP_ILOGB0, ilogbf(0.0f));
  ASSERT_EQ(FP_ILOGBNAN, ilogbf(nanf("")));
  ASSERT_EQ(INT_MAX, ilogbf(HUGE_VALF));
  ASSERT_EQ(INT_MAX, ilogbf(-HUGE_VALF));
  ASSERT_EQ(0, ilogbf(1.0f));
  ASSERT_EQ(3, ilogbf(10.0f));
}

TEST(math_h, ilogbl) {
  ASSERT_EQ(FP_ILOGB0, ilogbl(0.0L));
  ASSERT_EQ(FP_ILOGBNAN, ilogbl(nanl("")));
  ASSERT_EQ(INT_MAX, ilogbl(HUGE_VALL));
  ASSERT_EQ(INT_MAX, ilogbl(-HUGE_VALL));
  ASSERT_EQ(0L, ilogbl(1.0L));
  ASSERT_EQ(3L, ilogbl(10.0L));
}

TEST(math_h, logb) {
  ASSERT_EQ(-HUGE_VAL, logb(0.0));
  ASSERT_TRUE(isnan(logb(nan(""))));
  ASSERT_TRUE(isinf(logb(HUGE_VAL)));
  ASSERT_TRUE(isinf(logb(-HUGE_VAL)));
  ASSERT_EQ(0.0, logb(1.0));
  ASSERT_EQ(3.0, logb(10.0));
}

TEST(math_h, logbf) {
  ASSERT_EQ(-HUGE_VALF, logbf(0.0f));
  ASSERT_TRUE(isnanf(logbf(nanf(""))));
  ASSERT_TRUE(isinff(logbf(HUGE_VALF)));
  ASSERT_TRUE(isinff(logbf(-HUGE_VALF)));
  ASSERT_EQ(0.0f, logbf(1.0f));
  ASSERT_EQ(3.0f, logbf(10.0f));
}

TEST(math_h, logbl) {
  ASSERT_EQ(-HUGE_VAL, logbl(0.0L));
  ASSERT_TRUE(isnan(logbl(nanl(""))));
  ASSERT_TRUE(isinf(logbl(HUGE_VALL)));
  ASSERT_TRUE(isinf(logbl(-HUGE_VALL)));
  ASSERT_EQ(0.0L, logbl(1.0L));
  ASSERT_EQ(3.0L, logbl(10.0L));
}

TEST(math_h, log1p) {
  ASSERT_EQ(-HUGE_VAL, log1p(-1.0));
  ASSERT_TRUE(isnan(log1p(nan(""))));
  ASSERT_TRUE(isinf(log1p(HUGE_VAL)));
  ASSERT_TRUE(isnan(log1p(-HUGE_VAL)));
  ASSERT_DOUBLE_EQ(1.0, log1p(M_E - 1.0));
}

TEST(math_h, log1pf) {
  ASSERT_EQ(-HUGE_VALF, log1pf(-1.0f));
  ASSERT_TRUE(isnanf(log1pf(nanf(""))));
  ASSERT_TRUE(isinff(log1pf(HUGE_VALF)));
  ASSERT_TRUE(isnanf(log1pf(-HUGE_VALF)));
  ASSERT_FLOAT_EQ(1.0f, log1pf(static_cast<float>(M_E) - 1.0f));
}

TEST(math_h, log1pl) {
  ASSERT_EQ(-HUGE_VALL, log1pl(-1.0L));
  ASSERT_TRUE(isnanl(log1pl(nanl(""))));
  ASSERT_TRUE(isinfl(log1pl(HUGE_VALL)));
  ASSERT_TRUE(isnanl(log1pl(-HUGE_VALL)));
  ASSERT_DOUBLE_EQ(1.0L, log1pl(M_E - 1.0L));
}

TEST(math_h, fdim) {
  ASSERT_DOUBLE_EQ(0.0, fdim(1.0, 1.0));
  ASSERT_DOUBLE_EQ(1.0, fdim(2.0, 1.0));
  ASSERT_DOUBLE_EQ(0.0, fdim(1.0, 2.0));
}

TEST(math_h, fdimf) {
  ASSERT_FLOAT_EQ(0.0f, fdimf(1.0f, 1.0f));
  ASSERT_FLOAT_EQ(1.0f, fdimf(2.0f, 1.0f));
  ASSERT_FLOAT_EQ(0.0f, fdimf(1.0f, 2.0f));
}

TEST(math_h, fdiml) {
  ASSERT_DOUBLE_EQ(0.0L, fdiml(1.0L, 1.0L));
  ASSERT_DOUBLE_EQ(1.0L, fdiml(2.0L, 1.0L));
  ASSERT_DOUBLE_EQ(0.0L, fdiml(1.0L, 2.0L));
}

TEST(math_h, round) {
  auto guard = android::base::make_scope_guard([]() { fesetenv(FE_DFL_ENV); });
  fesetround(FE_TOWARDZERO); // round ignores the rounding mode and always rounds away from 
"""


```