Response:
Let's break down the thought process for analyzing this `s_erf.c` file.

1. **Understanding the Goal:** The request asks for a comprehensive analysis of the C code for `erf` and `erfc` functions. This includes:
    * Functionality description.
    * Relationship to Android.
    * Detailed implementation explanation.
    * Dynamic linker aspects (SO layout, symbol resolution).
    * Logical reasoning (input/output examples).
    * Common usage errors.
    * Tracing how the code is reached in Android.

2. **Initial Code Scan (High-Level):**
    * Immediately recognize the copyright and the mathematical definitions of `erf` (Error Function) and `erfc` (Complementary Error Function).
    * Notice the different computational methods based on the input `x`'s magnitude. This suggests optimization strategies for different ranges.
    * See the inclusion of `float.h`, `math.h`, and `math_private.h`. These are standard C/math headers, and the `_private.h` hints at internal implementation details.
    * Observe the definition of constants like `tiny`, `half`, `one`, `two`, and the polynomial coefficients (`pp`, `qq`, `pa`, `qa`, `ra`, `sa`, `rb`, `sb`). This points towards polynomial approximations.
    * Identify the core functions: `erf(double x)` and `erfc(double x)`.
    * See the `__weak_reference` macros, suggesting these functions might have `long double` counterparts (`erfl`, `erfcl`).

3. **Functionality Breakdown (Instruction 1):**
    * Clearly state the primary functions: calculating the error function (`erf`) and the complementary error function (`erfc`).
    * Mention the mathematical definitions provided in the comments.
    * Highlight the properties: `erf(-x) = -erf(x)` and `erfc(-x) = 2 - erfc(x)`.

4. **Android Relevance (Instruction 2):**
    * Explicitly state that this code is part of Android's math library (`libm`).
    * Give concrete examples of how `erf` and `erfc` might be used in Android, such as in:
        * Probability and statistics calculations.
        * Signal processing.
        * Machine learning libraries.
        * Graphics and physics engines.

5. **Detailed Implementation Explanation (Instruction 3):**
    * **Organize by Input Range:**  The code itself is structured around different ranges of `x`. Use this structure to explain the methods used for each range.
    * **Focus on the Core Techniques:**  Identify the key mathematical approximations being used:
        * **Polynomial Approximation:** For small `|x|`. Explain the form of the rational function (P/Q).
        * **Taylor Series Expansion (Around x=1):**  For `|x|` near 1. Explain the shift `s = |x| - 1`.
        * **Asymptotic Series:** For larger `|x|`. Explain the approximation involving `exp(-x*x)` and a polynomial in `1/x^2`.
    * **Explain the Code Logic:**  For each range:
        * Explain how the code determines the input range using bitwise operations on the floating-point representation (`GET_HIGH_WORD`).
        * Describe the calculations involved (polynomial evaluation, exponentiation).
        * Explain the handling of signs and special cases (0, infinity, NaN).
        * Note any optimizations or tricks (like the handling of very small `x` to avoid underflow).
    * **Highlight Key Variables:** Briefly explain the purpose of variables like `z`, `r`, `s`, `P`, `Q`, `R`, `S`.

6. **Dynamic Linker (Instruction 4):**
    * **SO Layout:** Provide a simplified example of a shared object (`libm.so`) layout, showing sections like `.text`, `.rodata`, `.data`, `.bss`, `.symtab`, `.strtab`, etc.
    * **Symbol Resolution:**  Explain the process for different symbol types:
        * **Global Functions (e.g., `erf`):** How they are exported and resolved by the dynamic linker.
        * **Global Variables (e.g., `tiny`, coefficients):** How they are handled in `.data` or `.rodata`.
        * **Static Functions/Variables:**  Explain that they are not visible outside the SO.
        * **Weak Symbols (due to `__weak_reference`):** Explain their purpose and how they are resolved.

7. **Logical Reasoning (Instruction 5):**
    * Choose a few representative input values and trace the execution flow:
        * **Small `x` (e.g., 0.1):** Show how the polynomial approximation is used.
        * **`x` near 1 (e.g., 0.9):** Show the Taylor series approximation.
        * **Large positive `x` (e.g., 10):** Show the asymptotic series approximation for `erfc`.
        * **Negative `x` (e.g., -0.5):** Show how the properties `erf(-x) = -erf(x)` and `erfc(-x) = 2 - erfc(x)` are used.
        * **Special Values (0, infinity, NaN):** Explain the direct handling of these cases.

8. **Common Usage Errors (Instruction 6):**
    * Focus on errors a programmer might make *when using* the `erf` and `erfc` functions:
        * Passing NaN or infinity (explain the expected behavior).
        * Underflow/overflow (though less likely with `double`).
        * Incorrectly interpreting the results (understanding the range of `erf` and `erfc`).

9. **Android Framework/NDK Tracing (Instruction 7):**
    * **Start with the User/NDK:**  Explain how a developer using the NDK would include `<cmath>` or `<math.h>`.
    * **NDK Toolchain:** Mention the compiler and linker involved.
    * **System Calls/Library Loading:** Explain how the dynamic linker loads `libm.so` when a program uses math functions.
    * **Framework Usage:** Give examples of how the Android Framework itself might use `erf`/`erfc` indirectly (e.g., via Java APIs that call native code).
    * **Debugging:** Briefly mention using `adb`, `gdb`, or logging to trace execution.

10. **Review and Refine:**  Read through the entire analysis to ensure clarity, accuracy, and completeness. Check that all parts of the request have been addressed. Make sure the explanations are easy to understand, even for someone who might not be deeply familiar with numerical methods. For instance, while mentioning the "asymptotic series," you don't need to derive it, just explain its purpose.
This is a detailed analysis of the `s_erf.c` file from Android's Bionic library, covering its functionality, relationship to Android, implementation details, dynamic linking aspects, logical reasoning, potential errors, and debugging information.

**1. Functionality of `s_erf.c`:**

The `s_erf.c` file implements two core mathematical functions:

* **`double erf(double x)` (Error Function):**  Calculates the error function of a given real number `x`. Mathematically, it's defined as the integral of the Gaussian function from 0 to `x`, scaled by a constant factor. It represents the probability that a random variable with a standard normal distribution falls within the range `[-x, x]`.

* **`double erfc(double x)` (Complementary Error Function):** Calculates the complementary error function of a given real number `x`. It's defined as `1 - erf(x)`. For large positive values of `x`, `erfc(x)` approaches 0.

**Key Properties:**

The comments in the code highlight important properties:

* `erf(-x) = -erf(x)` (Odd function)
* `erfc(-x) = 2 - erfc(x)`

**2. Relationship to Android Functionality:**

The `erf` and `erfc` functions are fundamental mathematical building blocks and are used in various parts of the Android system and applications. Here are some examples:

* **Probability and Statistics:**  Android applications dealing with statistical analysis, machine learning, or data science heavily rely on these functions. For instance, calculating confidence intervals or p-values in statistical tests.
* **Signal Processing:**  In audio and video processing, these functions might be used in algorithms related to noise reduction, filtering, or equalization.
* **Machine Learning Libraries (e.g., TensorFlow Lite, ML Kit):** Many machine learning models internally use Gaussian distributions, making `erf` and `erfc` essential for calculations related to activation functions, probability densities, and error analysis.
* **Graphics and Physics Engines:**  Simulating physical phenomena or rendering graphics might involve calculations based on probability distributions where these functions are useful.
* **Location and Navigation:**  Algorithms for GPS accuracy and confidence levels could potentially use these functions.

**Example:** Imagine an Android app that analyzes sensor data (like accelerometer readings) and tries to detect patterns. If the app models the noise in the sensor readings as a Gaussian distribution, it might use `erf` to calculate the probability of a certain reading occurring within a specific range, helping to distinguish real signals from noise.

**3. Detailed Explanation of Libc Function Implementations:**

The code implements `erf` and `erfc` using different approximation methods depending on the input value `x` to achieve accuracy and performance.

**Common Strategies:**

* **Polynomial Approximations:** For smaller values of `|x|`, the functions are approximated using rational functions (ratio of two polynomials). This is efficient for moderate accuracy.
* **Taylor Series Expansion:** Around specific points (like `x=1` in this case), Taylor series expansions are used to approximate the function.
* **Asymptotic Series:** For large values of `|x|`, asymptotic series provide accurate approximations. These often involve terms with `exp(-x*x)`.

**Implementation Breakdown:**

Let's analyze the `erf(double x)` function step by step:

1. **Handle Special Cases:**
   * **NaN:** If `x` is NaN (Not a Number), `erf(x)` returns NaN.
   * **Infinity:** If `x` is positive infinity, `erf(x)` returns 1. If `x` is negative infinity, `erf(x)` returns -1.

2. **Small `|x|` (Polynomial Approximation):**
   * **Very Small `|x|` (< 2<sup>-28</sup>):**  A simplified linear approximation (`x + efx*x`) or even just a scaled `x` is used for performance since the higher-order terms in the Taylor series are negligible.
   * **`|x|` in [2<sup>-28</sup>, 0.84375]:**  A rational function approximation is used: `erf(x) = x + x * R(x^2)`, where `R(x^2) = P(x^2) / Q(x^2)`. `P` is an odd polynomial of degree 8, and `Q` is an odd polynomial of degree 10 (in terms of `x`, making them even polynomials in terms of `x^2`). The coefficients `pp0` through `pp4` and `qq1` through `qq5` define these polynomials.

3. **Intermediate `|x|` (Taylor Expansion around 1):**
   * **`|x|` in [0.84375, 1.25]:** Let `s = |x| - 1`. The approximation is `erf(x) = sign(x) * (c + P1(s) / Q1(s))`, where `c` is a constant (`erx`), and `P1` and `Q1` are polynomials in `s` of degree 6. The coefficients `pa0` through `pa6` and `qa1` through `qa6` define these polynomials.

4. **Larger `|x|` (Asymptotic Series):**
   * **`|x|` in [1.25, ~2.857]:**  `erfc(x)` is calculated using an asymptotic expansion: `erfc(x) = (1/x) * exp(-x*x - 0.5625 + R1(1/x^2) / S1(1/x^2))`. `R1` is a polynomial of degree 7, and `S1` is a polynomial of degree 8 in `1/x^2`. `erf(x)` is then calculated as `1 - erfc(x)`.
   * **`|x|` in [~2.857, 28]:** Similar asymptotic expansion for `erfc(x)` is used with different polynomials `R2` (degree 6) and `S2` (degree 7) in `1/x^2`. Special handling for negative `x` in this range is included.
   * **`|x|` >= 6:** `erf(x)` is approximated as `sign(x) * (1 - tiny)` (very close to +/-1), raising the inexact exception.

5. **Very Large `|x|` (Approaching Infinity):**
   * **`|x|` >= 28:** `erf(x)` is approximated as `sign(x) * (1 - tiny)`. `erfc(x)` is approximated as `tiny * tiny` for positive `x` (raising underflow) and `2 - tiny` for negative `x`.

The `erfc(double x)` function follows a similar structure, using different approximations optimized for calculating `1 - erf(x)` directly to avoid potential loss of precision when `erf(x)` is very close to 1.

**Explanation of Libc Function Implementation Details:**

* **`GET_HIGH_WORD(hx, x)` and `SET_LOW_WORD(z, 0)`:** These are likely macros defined in `math_private.h` for efficient manipulation of the double-precision floating-point representation. They allow accessing and modifying the sign, exponent, and high/low parts of the mantissa without resorting to slower memory copies.
* **Polynomial Evaluation:** The code uses Horner's method for efficient polynomial evaluation (e.g., `r = pp0 + z * (pp1 + z * (pp2 + ...))`).
* **Constants:** The constants like `tiny`, `half`, `one`, `two`, `erx`, and the polynomial coefficients are carefully chosen to minimize approximation errors within each range.
* **Accuracy:** The comments mention the error bounds for the approximations in different ranges, ensuring the functions meet the required precision for double-precision floating-point numbers.

**4. Dynamic Linker Functionality:**

The dynamic linker (like `linker64` or `linker`) in Android is responsible for loading shared libraries (like `libm.so`) into the process's address space at runtime and resolving symbols (functions and variables) used by the program.

**SO Layout Sample for `libm.so`:**

```
ELF Header
Program Headers
Section Headers:
  .text          PROGBITS, ALLOC, EXECUTE  ; Contains the executable code of the functions
  .rodata        PROGBITS, ALLOC, LOAD    ; Read-only data (e.g., string literals, constant coefficients)
  .data          PROGBITS, ALLOC, WRITE    ; Initialized global and static variables
  .bss           NOBITS, ALLOC, WRITE      ; Uninitialized global and static variables
  .symtab        SYMTAB                    ; Symbol table (information about symbols)
  .strtab        STRTAB                    ; String table (names of symbols)
  .dynsym        DYNSYM                    ; Dynamic symbol table
  .dynstr        DYNSTR                    ; Dynamic string table
  .rel.dyn       RELA                      ; Relocation entries for the .data section
  .rel.plt       RELA                      ; Relocation entries for the Procedure Linkage Table (PLT)
  .plt           PROGBITS, ALLOC, EXECUTE  ; Procedure Linkage Table
  ... (other sections like .hash, .gnu.version, etc.)
```

**Symbol Processing:**

1. **Global Functions (e.g., `erf`, `erfc`):**
   * **Definition:** The `libm.so` file defines these functions in its `.text` section. Their symbols are present in the `.symtab` and `.dynsym` tables, marked as global and with their addresses within the `.text` section.
   * **Resolution:** When another program or library uses `erf`, the dynamic linker looks up the symbol `erf` in `libm.so`'s dynamic symbol table (`.dynsym`). Once found, the linker resolves the reference by replacing it with the actual address of the `erf` function in `libm.so`. This might involve relocation entries in `.rel.plt`.

2. **Global Variables (e.g., `tiny`, `half`, coefficients):**
   * **Definition:** These constants are typically stored in the `.rodata` section since they are read-only. Their symbols are in `.symtab` and `.dynsym`, marked as global, and point to their locations in `.rodata`.
   * **Resolution:** Similar to global functions, the dynamic linker resolves references to these variables by looking up their symbols in `libm.so`'s dynamic symbol table and using the relocation entries in `.rel.dyn` to update the addresses.

3. **Static Functions and Variables:**
   * **Definition:** If there were `static` functions or variables within `s_erf.c`, they would reside in the `.text` or `.data`/`.bss` sections of `libm.so`, but their symbols would typically have internal linkage and not be present in the dynamic symbol table (`.dynsym`). They are only accessible within `libm.so`.

4. **Weak Symbols (using `__weak_reference`):**
   * **Purpose:** `__weak_reference(erf, erfl);` creates a weak alias. If a strong symbol `erfl` (likely the `long double` version) exists elsewhere, the reference to `erfl` will resolve to that strong symbol. If `erfl` does not exist, the weak reference to `erf` will be used instead. This allows for optional implementations or fallback mechanisms.
   * **Resolution:** The dynamic linker first tries to find a strong symbol matching the weak reference. If found, it's resolved to that. Otherwise, the weak symbol itself (if defined) is used, or the reference might resolve to null or a default implementation depending on the architecture and linking process.

**5. Logical Reasoning: Assumptions, Inputs, and Outputs:**

Let's consider the `erf(double x)` function:

* **Assumption:** The input `x` is a valid double-precision floating-point number.
* **Input Examples and Expected Outputs:**
    * `erf(0.0)`:  Output should be approximately `0.0`. (Integral from 0 to 0 is 0).
    * `erf(1.0)`: Output should be approximately `0.84270079...`.
    * `erf(-1.0)`: Output should be approximately `-0.84270079...` (due to the odd property).
    * `erf(10.0)`: Output should be very close to `1.0`.
    * `erf(-10.0)`: Output should be very close to `-1.0`.
    * `erf(INFINITY)`: Output should be `1.0`.
    * `erf(-INFINITY)`: Output should be `-1.0`.
    * `erf(NAN)`: Output should be `NAN`.

Let's consider the `erfc(double x)` function:

* **Assumption:** The input `x` is a valid double-precision floating-point number.
* **Input Examples and Expected Outputs:**
    * `erfc(0.0)`: Output should be approximately `1.0`.
    * `erfc(1.0)`: Output should be approximately `0.15729920...`.
    * `erfc(-1.0)`: Output should be approximately `1.84270079...`.
    * `erfc(10.0)`: Output should be very close to `0.0`.
    * `erfc(-10.0)`: Output should be very close to `2.0`.
    * `erfc(INFINITY)`: Output should be `0.0`.
    * `erfc(-INFINITY)`: Output should be `2.0`.
    * `erfc(NAN)`: Output should be `NAN`.

The code implements different calculation methods based on the input range to optimize for accuracy and performance. The selection of these ranges and the polynomial coefficients is based on rigorous mathematical analysis to minimize approximation errors.

**6. Common Usage Errors:**

* **Passing NaN or Infinity:** While the functions handle these cases gracefully by returning NaN, 1, -1, 0, or 2, relying on this behavior without proper input validation can lead to unexpected results or propagate NaNs through calculations.
* **Underflow/Overflow (Less likely with `double`):** For extremely large positive values of `x`, `erfc(x)` becomes very close to zero and might underflow if not handled carefully in subsequent calculations. Similarly, intermediate calculations within the function could potentially overflow, although the implementation tries to mitigate this.
* **Incorrect Interpretation of Results:**  Understanding the range of `erf` ([-1, 1]) and `erfc` ([0, 2]) is crucial. Misinterpreting the probability meaning or using the wrong function can lead to incorrect conclusions.
* **Performance Concerns (For repeated calls):** While the implementation is optimized, repeatedly calling these functions in performance-critical sections might still be a bottleneck. Consider alternative approaches or caching results if applicable.

**Example of a potential error:**

```c
#include <stdio.h>
#include <math.h>

int main() {
  double x = 1000.0;
  double result_erfc = erfc(x);
  printf("erfc(%f) = %e\n", x, result_erfc); // Output will likely be very close to 0 or underflow

  // Potential error: Dividing by a very small number
  double inverse_erfc = 1.0 / result_erfc; // This could lead to overflow or infinity
  printf("1 / erfc(%f) = %f\n", x, inverse_erfc);

  return 0;
}
```

**7. Android Framework or NDK Access:**

Here's a breakdown of how an Android application or framework component might reach the `erf` or `erfc` functions in `s_erf.c`:

1. **NDK Application:**
   * **C/C++ Code:** An Android application using the NDK (Native Development Kit) can directly call these functions by including `<cmath>` or `<math.h>`.
   * **Compilation:** The NDK compiler (e.g., `clang`) compiles the C/C++ code.
   * **Linking:** The NDK linker links the application's native code against `libm.so`, which contains the implementations of `erf` and `erfc`.
   * **Runtime:** When the application runs, the Android dynamic linker loads `libm.so` into the process, and calls to `erf` and `erfc` are resolved to the code in `s_erf.c`.

2. **Android Framework (Java Code indirectly):**
   * **Java API Calls:** The Android Framework (written in Java) provides various classes and methods that might internally rely on these mathematical functions. For example, classes related to graphics, sensors, or machine learning.
   * **JNI (Java Native Interface):** When the Java code needs to perform a calculation that relies on `erf` or `erfc`, it might call native code (C/C++) through JNI.
   * **Framework Native Libraries:** The framework often has its own native libraries that are linked against `libm.so`. These libraries would contain the C/C++ implementations that ultimately call the `erf` and `erfc` functions.

**Debugging Lineage:**

To trace how execution reaches `s_erf.c`, you can use various debugging techniques:

* **`adb logcat`:** Check system logs for any relevant information or errors related to mathematical calculations.
* **NDK Debugging (gdb/lldb):** If you have the NDK source code and are debugging a native application, you can set breakpoints in `s_erf.c` and step through the code to see how it's being called and with what values.
* **System Tracing (systrace):**  This tool can capture system-level events, including library calls, which might help identify when `libm.so` functions are being used.
* **Android Studio Profiler:**  The profiler can show CPU usage and function call stacks, potentially revealing calls to math library functions.
* **Instrumentation:** You could add logging statements within the `erf` and `erfc` functions (if you have a custom build of Android or are working within the framework) to track their invocation.

By understanding the structure of Android's libraries and the dynamic linking process, you can follow the chain of calls from your application code or framework components down to the specific implementations in `s_erf.c`.

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/s_erf.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/* double erf(double x)
 * double erfc(double x)
 *			     x
 *		      2      |\
 *     erf(x)  =  ---------  | exp(-t*t)dt
 *	 	   sqrt(pi) \|
 *			     0
 *
 *     erfc(x) =  1-erf(x)
 *  Note that
 *		erf(-x) = -erf(x)
 *		erfc(-x) = 2 - erfc(x)
 *
 * Method:
 *	1. For |x| in [0, 0.84375]
 *	    erf(x)  = x + x*R(x^2)
 *          erfc(x) = 1 - erf(x)           if x in [-.84375,0.25]
 *                  = 0.5 + ((0.5-x)-x*R)  if x in [0.25,0.84375]
 *	   where R = P/Q where P is an odd poly of degree 8 and
 *	   Q is an odd poly of degree 10.
 *						 -57.90
 *			| R - (erf(x)-x)/x | <= 2
 *
 *
 *	   Remark. The formula is derived by noting
 *          erf(x) = (2/sqrt(pi))*(x - x^3/3 + x^5/10 - x^7/42 + ....)
 *	   and that
 *          2/sqrt(pi) = 1.128379167095512573896158903121545171688
 *	   is close to one. The interval is chosen because the fix
 *	   point of erf(x) is near 0.6174 (i.e., erf(x)=x when x is
 *	   near 0.6174), and by some experiment, 0.84375 is chosen to
 * 	   guarantee the error is less than one ulp for erf.
 *
 *      2. For |x| in [0.84375,1.25], let s = |x| - 1, and
 *         c = 0.84506291151 rounded to single (24 bits)
 *         	erf(x)  = sign(x) * (c  + P1(s)/Q1(s))
 *         	erfc(x) = (1-c)  - P1(s)/Q1(s) if x > 0
 *			  1+(c+P1(s)/Q1(s))    if x < 0
 *         	|P1/Q1 - (erf(|x|)-c)| <= 2**-59.06
 *	   Remark: here we use the taylor series expansion at x=1.
 *		erf(1+s) = erf(1) + s*Poly(s)
 *			 = 0.845.. + P1(s)/Q1(s)
 *	   That is, we use rational approximation to approximate
 *			erf(1+s) - (c = (single)0.84506291151)
 *	   Note that |P1/Q1|< 0.078 for x in [0.84375,1.25]
 *	   where
 *		P1(s) = degree 6 poly in s
 *		Q1(s) = degree 6 poly in s
 *
 *      3. For x in [1.25,1/0.35(~2.857143)],
 *         	erfc(x) = (1/x)*exp(-x*x-0.5625+R1/S1)
 *         	erf(x)  = 1 - erfc(x)
 *	   where
 *		R1(z) = degree 7 poly in z, (z=1/x^2)
 *		S1(z) = degree 8 poly in z
 *
 *      4. For x in [1/0.35,28]
 *         	erfc(x) = (1/x)*exp(-x*x-0.5625+R2/S2) if x > 0
 *			= 2.0 - (1/x)*exp(-x*x-0.5625+R2/S2) if -6<x<0
 *			= 2.0 - tiny		(if x <= -6)
 *         	erf(x)  = sign(x)*(1.0 - erfc(x)) if x < 6, else
 *         	erf(x)  = sign(x)*(1.0 - tiny)
 *	   where
 *		R2(z) = degree 6 poly in z, (z=1/x^2)
 *		S2(z) = degree 7 poly in z
 *
 *      Note1:
 *	   To compute exp(-x*x-0.5625+R/S), let s be a single
 *	   precision number and s := x; then
 *		-x*x = -s*s + (s-x)*(s+x)
 *	        exp(-x*x-0.5626+R/S) =
 *			exp(-s*s-0.5625)*exp((s-x)*(s+x)+R/S);
 *      Note2:
 *	   Here 4 and 5 make use of the asymptotic series
 *			  exp(-x*x)
 *		erfc(x) ~ ---------- * ( 1 + Poly(1/x^2) )
 *			  x*sqrt(pi)
 *	   We use rational approximation to approximate
 *      	g(s)=f(1/x^2) = log(erfc(x)*x) - x*x + 0.5625
 *	   Here is the error bound for R1/S1 and R2/S2
 *      	|R1/S1 - f(x)|  < 2**(-62.57)
 *      	|R2/S2 - f(x)|  < 2**(-61.52)
 *
 *      5. For inf > x >= 28
 *         	erf(x)  = sign(x) *(1 - tiny)  (raise inexact)
 *         	erfc(x) = tiny*tiny (raise underflow) if x > 0
 *			= 2 - tiny if x<0
 *
 *      7. Special case:
 *         	erf(0)  = 0, erf(inf)  = 1, erf(-inf) = -1,
 *         	erfc(0) = 1, erfc(inf) = 0, erfc(-inf) = 2,
 *	   	erfc/erf(NaN) is NaN
 */

#include <float.h>
#include "math.h"
#include "math_private.h"

/* XXX Prevent compilers from erroneously constant folding: */
static const volatile double tiny= 1e-300;

static const double
half= 0.5,
one = 1,
two = 2,
/* c = (float)0.84506291151 */
erx =  8.45062911510467529297e-01, /* 0x3FEB0AC1, 0x60000000 */
/*
 * In the domain [0, 2**-28], only the first term in the power series
 * expansion of erf(x) is used.  The magnitude of the first neglected
 * terms is less than 2**-84.
 */
efx =  1.28379167095512586316e-01, /* 0x3FC06EBA, 0x8214DB69 */
efx8=  1.02703333676410069053e+00, /* 0x3FF06EBA, 0x8214DB69 */
/*
 * Coefficients for approximation to erf on [0,0.84375]
 */
pp0  =  1.28379167095512558561e-01, /* 0x3FC06EBA, 0x8214DB68 */
pp1  = -3.25042107247001499370e-01, /* 0xBFD4CD7D, 0x691CB913 */
pp2  = -2.84817495755985104766e-02, /* 0xBF9D2A51, 0xDBD7194F */
pp3  = -5.77027029648944159157e-03, /* 0xBF77A291, 0x236668E4 */
pp4  = -2.37630166566501626084e-05, /* 0xBEF8EAD6, 0x120016AC */
qq1  =  3.97917223959155352819e-01, /* 0x3FD97779, 0xCDDADC09 */
qq2  =  6.50222499887672944485e-02, /* 0x3FB0A54C, 0x5536CEBA */
qq3  =  5.08130628187576562776e-03, /* 0x3F74D022, 0xC4D36B0F */
qq4  =  1.32494738004321644526e-04, /* 0x3F215DC9, 0x221C1A10 */
qq5  = -3.96022827877536812320e-06, /* 0xBED09C43, 0x42A26120 */
/*
 * Coefficients for approximation to erf in [0.84375,1.25]
 */
pa0  = -2.36211856075265944077e-03, /* 0xBF6359B8, 0xBEF77538 */
pa1  =  4.14856118683748331666e-01, /* 0x3FDA8D00, 0xAD92B34D */
pa2  = -3.72207876035701323847e-01, /* 0xBFD7D240, 0xFBB8C3F1 */
pa3  =  3.18346619901161753674e-01, /* 0x3FD45FCA, 0x805120E4 */
pa4  = -1.10894694282396677476e-01, /* 0xBFBC6398, 0x3D3E28EC */
pa5  =  3.54783043256182359371e-02, /* 0x3FA22A36, 0x599795EB */
pa6  = -2.16637559486879084300e-03, /* 0xBF61BF38, 0x0A96073F */
qa1  =  1.06420880400844228286e-01, /* 0x3FBB3E66, 0x18EEE323 */
qa2  =  5.40397917702171048937e-01, /* 0x3FE14AF0, 0x92EB6F33 */
qa3  =  7.18286544141962662868e-02, /* 0x3FB2635C, 0xD99FE9A7 */
qa4  =  1.26171219808761642112e-01, /* 0x3FC02660, 0xE763351F */
qa5  =  1.36370839120290507362e-02, /* 0x3F8BEDC2, 0x6B51DD1C */
qa6  =  1.19844998467991074170e-02, /* 0x3F888B54, 0x5735151D */
/*
 * Coefficients for approximation to erfc in [1.25,1/0.35]
 */
ra0  = -9.86494403484714822705e-03, /* 0xBF843412, 0x600D6435 */
ra1  = -6.93858572707181764372e-01, /* 0xBFE63416, 0xE4BA7360 */
ra2  = -1.05586262253232909814e+01, /* 0xC0251E04, 0x41B0E726 */
ra3  = -6.23753324503260060396e+01, /* 0xC04F300A, 0xE4CBA38D */
ra4  = -1.62396669462573470355e+02, /* 0xC0644CB1, 0x84282266 */
ra5  = -1.84605092906711035994e+02, /* 0xC067135C, 0xEBCCABB2 */
ra6  = -8.12874355063065934246e+01, /* 0xC0545265, 0x57E4D2F2 */
ra7  = -9.81432934416914548592e+00, /* 0xC023A0EF, 0xC69AC25C */
sa1  =  1.96512716674392571292e+01, /* 0x4033A6B9, 0xBD707687 */
sa2  =  1.37657754143519042600e+02, /* 0x4061350C, 0x526AE721 */
sa3  =  4.34565877475229228821e+02, /* 0x407B290D, 0xD58A1A71 */
sa4  =  6.45387271733267880336e+02, /* 0x40842B19, 0x21EC2868 */
sa5  =  4.29008140027567833386e+02, /* 0x407AD021, 0x57700314 */
sa6  =  1.08635005541779435134e+02, /* 0x405B28A3, 0xEE48AE2C */
sa7  =  6.57024977031928170135e+00, /* 0x401A47EF, 0x8E484A93 */
sa8  = -6.04244152148580987438e-02, /* 0xBFAEEFF2, 0xEE749A62 */
/*
 * Coefficients for approximation to erfc in [1/.35,28]
 */
rb0  = -9.86494292470009928597e-03, /* 0xBF843412, 0x39E86F4A */
rb1  = -7.99283237680523006574e-01, /* 0xBFE993BA, 0x70C285DE */
rb2  = -1.77579549177547519889e+01, /* 0xC031C209, 0x555F995A */
rb3  = -1.60636384855821916062e+02, /* 0xC064145D, 0x43C5ED98 */
rb4  = -6.37566443368389627722e+02, /* 0xC083EC88, 0x1375F228 */
rb5  = -1.02509513161107724954e+03, /* 0xC0900461, 0x6A2E5992 */
rb6  = -4.83519191608651397019e+02, /* 0xC07E384E, 0x9BDC383F */
sb1  =  3.03380607434824582924e+01, /* 0x403E568B, 0x261D5190 */
sb2  =  3.25792512996573918826e+02, /* 0x40745CAE, 0x221B9F0A */
sb3  =  1.53672958608443695994e+03, /* 0x409802EB, 0x189D5118 */
sb4  =  3.19985821950859553908e+03, /* 0x40A8FFB7, 0x688C246A */
sb5  =  2.55305040643316442583e+03, /* 0x40A3F219, 0xCEDF3BE6 */
sb6  =  4.74528541206955367215e+02, /* 0x407DA874, 0xE79FE763 */
sb7  = -2.24409524465858183362e+01; /* 0xC03670E2, 0x42712D62 */

double
erf(double x)
{
	int32_t hx,ix,i;
	double R,S,P,Q,s,y,z,r;
	GET_HIGH_WORD(hx,x);
	ix = hx&0x7fffffff;
	if(ix>=0x7ff00000) {		/* erf(nan)=nan */
	    i = ((u_int32_t)hx>>31)<<1;
	    return (double)(1-i)+one/x;	/* erf(+-inf)=+-1 */
	}

	if(ix < 0x3feb0000) {		/* |x|<0.84375 */
	    if(ix < 0x3e300000) { 	/* |x|<2**-28 */
	        if (ix < 0x00800000)
		    return (8*x+efx8*x)/8;	/* avoid spurious underflow */
		return x + efx*x;
	    }
	    z = x*x;
	    r = pp0+z*(pp1+z*(pp2+z*(pp3+z*pp4)));
	    s = one+z*(qq1+z*(qq2+z*(qq3+z*(qq4+z*qq5))));
	    y = r/s;
	    return x + x*y;
	}
	if(ix < 0x3ff40000) {		/* 0.84375 <= |x| < 1.25 */
	    s = fabs(x)-one;
	    P = pa0+s*(pa1+s*(pa2+s*(pa3+s*(pa4+s*(pa5+s*pa6)))));
	    Q = one+s*(qa1+s*(qa2+s*(qa3+s*(qa4+s*(qa5+s*qa6)))));
	    if(hx>=0) return erx + P/Q; else return -erx - P/Q;
	}
	if (ix >= 0x40180000) {		/* inf>|x|>=6 */
	    if(hx>=0) return one-tiny; else return tiny-one;
	}
	x = fabs(x);
 	s = one/(x*x);
	if(ix< 0x4006DB6E) {	/* |x| < 1/0.35 */
	    R=ra0+s*(ra1+s*(ra2+s*(ra3+s*(ra4+s*(ra5+s*(ra6+s*ra7))))));
	    S=one+s*(sa1+s*(sa2+s*(sa3+s*(sa4+s*(sa5+s*(sa6+s*(sa7+
		s*sa8)))))));
	} else {	/* |x| >= 1/0.35 */
	    R=rb0+s*(rb1+s*(rb2+s*(rb3+s*(rb4+s*(rb5+s*rb6)))));
	    S=one+s*(sb1+s*(sb2+s*(sb3+s*(sb4+s*(sb5+s*(sb6+s*sb7))))));
	}
	z  = x;
	SET_LOW_WORD(z,0);
	r  =  exp(-z*z-0.5625)*exp((z-x)*(z+x)+R/S);
	if(hx>=0) return one-r/x; else return  r/x-one;
}

#if (LDBL_MANT_DIG == 53)
__weak_reference(erf, erfl);
#endif

double
erfc(double x)
{
	int32_t hx,ix;
	double R,S,P,Q,s,y,z,r;
	GET_HIGH_WORD(hx,x);
	ix = hx&0x7fffffff;
	if(ix>=0x7ff00000) {			/* erfc(nan)=nan */
						/* erfc(+-inf)=0,2 */
	    return (double)(((u_int32_t)hx>>31)<<1)+one/x;
	}

	if(ix < 0x3feb0000) {		/* |x|<0.84375 */
	    if(ix < 0x3c700000)  	/* |x|<2**-56 */
		return one-x;
	    z = x*x;
	    r = pp0+z*(pp1+z*(pp2+z*(pp3+z*pp4)));
	    s = one+z*(qq1+z*(qq2+z*(qq3+z*(qq4+z*qq5))));
	    y = r/s;
	    if(hx < 0x3fd00000) {  	/* x<1/4 */
		return one-(x+x*y);
	    } else {
		r = x*y;
		r += (x-half);
	        return half - r ;
	    }
	}
	if(ix < 0x3ff40000) {		/* 0.84375 <= |x| < 1.25 */
	    s = fabs(x)-one;
	    P = pa0+s*(pa1+s*(pa2+s*(pa3+s*(pa4+s*(pa5+s*pa6)))));
	    Q = one+s*(qa1+s*(qa2+s*(qa3+s*(qa4+s*(qa5+s*qa6)))));
	    if(hx>=0) {
	        z  = one-erx; return z - P/Q;
	    } else {
		z = erx+P/Q; return one+z;
	    }
	}
	if (ix < 0x403c0000) {		/* |x|<28 */
	    x = fabs(x);
 	    s = one/(x*x);
	    if(ix< 0x4006DB6D) {	/* |x| < 1/.35 ~ 2.857143*/
		R=ra0+s*(ra1+s*(ra2+s*(ra3+s*(ra4+s*(ra5+s*(ra6+s*ra7))))));
		S=one+s*(sa1+s*(sa2+s*(sa3+s*(sa4+s*(sa5+s*(sa6+s*(sa7+
		    s*sa8)))))));
	    } else {			/* |x| >= 1/.35 ~ 2.857143 */
		if(hx<0&&ix>=0x40180000) return two-tiny;/* x < -6 */
		R=rb0+s*(rb1+s*(rb2+s*(rb3+s*(rb4+s*(rb5+s*rb6)))));
		S=one+s*(sb1+s*(sb2+s*(sb3+s*(sb4+s*(sb5+s*(sb6+s*sb7))))));
	    }
	    z  = x;
	    SET_LOW_WORD(z,0);
	    r  =  exp(-z*z-0.5625)*exp((z-x)*(z+x)+R/S);
	    if(hx>0) return r/x; else return two-r/x;
	} else {
	    if(hx>0) return tiny*tiny; else return two-tiny;
	}
}

#if (LDBL_MANT_DIG == 53)
__weak_reference(erfc, erfcl);
#endif
```