Response:
Let's break down the thought process for analyzing this `s_erfl.c` file.

**1. Understanding the Context:**

* **File Path:** `bionic/libm/upstream-freebsd/lib/msun/ld128/s_erfl.c` immediately tells us a lot:
    * `bionic`:  This is Android's core C library.
    * `libm`:  This indicates it's part of the math library.
    * `upstream-freebsd`: The code is derived from FreeBSD's math library. This is a crucial piece of information. It means we can often refer to FreeBSD documentation or source code for deeper understanding.
    * `ld128`: This strongly suggests it's dealing with `long double` (128-bit) floating-point numbers.
    * `s_erfl.c`: The "s_" prefix often signifies a core implementation, and "erfl" hints at the error function (`erf`) for `long double`.

**2. Initial Code Scan - Identifying Key Areas:**

* **Copyright Notice:**  Confirms the origin (Sun Microsystems/SunPro) and licensing (free distribution).
* **Includes:** `<float.h>`, `"fpmath.h"`, `"math.h"`, `"math_private.h"` - These headers provide necessary definitions for floating-point types, math functions, and internal math library structures.
* **Static Constants:** A large number of `static const long double` and `static const double` variables. These are clearly coefficients for polynomial approximations. The comments next to them ("Domain...", "range...", "|(erf(x) - ...)| < ...") are invaluable for understanding the approximation strategy.
* **Function Definitions:** `long double erfl(long double x)` and `long double erfcl(long double x)`. The names strongly suggest the error function (`erf`) and complementary error function (`erfc`) for `long double`.
* **EXTRACT_LDBL128_WORDS Macro:**  This macro is used to access the internal representation of the `long double`. This points to low-level manipulation of the floating-point bits.
* **Conditional Logic (if/else):** The code has multiple `if/else` blocks based on the magnitude of the input `x`. This reinforces the idea of different approximation methods being used for different input ranges.

**3. Deeper Analysis - Function by Function:**

* **`erfl(long double x)`:**
    * **NaN/Infinity Handling:**  The first `if` block checks for NaN and Infinity inputs, returning the appropriate values according to the IEEE 754 standard.
    * **Small Input Handling:** The `if(ax < 0.84375)` block handles small values using a power series expansion. The comment about `2**-40` is key here.
    * **Polynomial Approximations:**  The code then uses several `if/else if` blocks to handle different input ranges (0.84375 to 1.25, 1.25 to 9, and >= 9). Within each range, it computes polynomial approximations for `erf(x)` based on the pre-computed coefficients. The rational function approximations (`P/Q`, `R/S`) are evident.
    * **Large Input Optimization:** For very large inputs (`ax >= 9`), it directly returns values close to +/- 1.
    * **Exploit of `exp`:**  For moderate to large inputs, it uses the relationship between `erfc` and the Gaussian integral, employing `expl` (exponential function) in the calculation.
* **`erfcl(long double x)`:**
    * **Similar Structure:**  Mirrors the structure of `erfl`, with different logic and coefficients.
    * **Complementary Error Function:**  The comments and return values (e.g., `one - ...`, `two - ...`) confirm it's calculating the complementary error function (1 - erf(x)).
    * **Small Input Optimization:** Special handling for very small inputs.
    * **Conditional Calculation:**  Different calculations are performed depending on the input range, again using polynomial approximations and leveraging the relationship with the exponential function.

**4. Connecting to Android and Dynamic Linking (Conceptual at this Stage):**

* **Android Framework/NDK:**  Think about how a high-level Android app might need mathematical functions. The NDK allows native C/C++ code, and the framework itself (in its native components) uses the C library. A call to `java.lang.Math.erf()` or a similar NDK math function would eventually lead to a call into the native `libm` which contains this code.
* **Dynamic Linker:**  The dynamic linker is responsible for loading shared libraries (`.so` files) at runtime and resolving symbols (function names, global variables). The `erfl` and `erfcl` functions would be symbols within `libm.so`.

**5. Answering the Specific Questions:**

Now, with a solid understanding of the code, we can address the prompt's questions systematically:

* **Functionality:** List the core purposes of the functions.
* **Android Relation:**  Explain how this code fits into the Android ecosystem.
* **Libc Function Implementation:** Detail the approximation methods used (power series, rational functions).
* **Dynamic Linker:**  Speculate on the `.so` layout and symbol resolution process.
* **Logic Inference:** Provide examples of input and output based on the code's structure (e.g., small inputs, large inputs).
* **Common Errors:** Think about how developers might misuse these functions or encounter issues related to precision or input ranges.
* **Debugging Clues:**  Outline the call stack from the Android framework/NDK down to this specific C function.

**6. Refining and Organizing:**

Finally, structure the answers clearly, providing code snippets where necessary, and using precise terminology related to math functions and dynamic linking. Emphasize the importance of the pre-computed coefficients and the range-based approximation strategy. Acknowledge any limitations in the analysis (e.g., not having the exact build environment).

This detailed thought process allows for a comprehensive understanding of the code and its role within the Android system. The key is to break down the problem, analyze the code systematically, and leverage contextual information about Android and standard math library practices.
This C source file, `s_erfl.c`, located within the Android Bionic library's math component, implements the **error function (`erf`) and the complementary error function (`erfc`) for `long double` (128-bit extended precision floating-point numbers).**

Here's a breakdown of its functionalities and connections to Android:

**1. Functionality:**

* **`long double erfl(long double x)`:** Calculates the error function of `x`. The error function is defined as:
   ```
   erf(x) = (2 / sqrt(π)) * ∫[0 to x] e^(-t^2) dt
   ```
   It's a fundamental function in probability, statistics, and physics. It represents the probability that a standard normally distributed random variable falls within a certain range.

* **`long double erfcl(long double x)`:** Calculates the complementary error function of `x`. It's defined as:
   ```
   erfc(x) = 1 - erf(x) = (2 / sqrt(π)) * ∫[x to ∞] e^(-t^2) dt
   ```
   The complementary error function is useful when dealing with the tails of the normal distribution or situations where `erf(x)` is close to 1, as it avoids potential loss of precision due to subtraction.

**2. Relationship with Android Functionality and Examples:**

The `erfl` and `erfcl` functions are part of Android's math library (`libm`), which provides standard mathematical functions for use by applications and the Android system itself.

* **Android Framework:**
    * **Statistical Analysis:** The Android framework might use these functions internally for statistical calculations, for example, in performance monitoring, battery usage analysis, or sensor data processing.
    * **Graphics and Signal Processing:** Certain graphics algorithms or signal processing tasks within the framework could utilize the error function.

* **Android NDK:**
    * **Game Development:** Game developers using the NDK for performance-critical calculations might need the error function for AI, physics simulations, or procedural content generation.
    * **Scientific Computing Apps:** Applications performing scientific simulations or data analysis would directly benefit from these highly accurate implementations of `erf` and `erfc`.
    * **Machine Learning Libraries:**  Native machine learning libraries built with the NDK could use these functions in the implementation of various algorithms.

**Example:** Imagine an Android app that analyzes sensor data from a gyroscope. To filter out noise based on a Gaussian distribution, the developer might need to calculate the probability of the noise falling within a certain range. This would involve using the error function. With the NDK, they could call the native `erfl` function for high precision.

**3. Detailed Explanation of Libc Function Implementation:**

The code implements `erfl` and `erfcl` using **piecewise polynomial approximations and rational function approximations**. This is a common technique for implementing transcendental functions in math libraries to achieve both accuracy and performance.

Here's a breakdown of the implementation strategy:

* **Range Reduction:** The input domain of `x` is divided into several intervals. Different approximation formulas are used for each interval. This is because a single polynomial or rational function might not provide sufficient accuracy across the entire input range.

* **Special Cases:** The code first handles special cases like NaN (Not a Number) and infinity.

* **Small Arguments (Near Zero):**
    * For very small `|x|`, a power series expansion of `erf(x)` is used: `erf(x) ≈ x + (efx * x)`. For extremely small values, it further simplifies to avoid potential underflow.
    * The constants `efx` and `efx8` are pre-calculated coefficients for this approximation.

* **Moderate Arguments (Polynomial/Rational Approximations):**
    * For arguments within specific ranges (e.g., `0` to `0.84375`, `0.84375` to `1.25`), the code uses rational function approximations of the form `x + x * P(x^2) / Q(x^2)` for `erfl` or directly approximates `erf(x)` or `erfc(x)`.
    * `P` and `Q` are polynomials, and the constants `pp0` to `pp9` and `qq1` to `qq9` are the coefficients of these polynomials. Similarly, `pa0` to `pa11` and `qa1` to `qa12` are used for another range.
    * The comments in the code indicate the domain and the maximum error of these approximations (e.g., `|(erf(x) - x)/x - pp(x)/qq(x)| < 2**-125.29`).

* **Larger Arguments (Asymptotic Expansions and Relationships):**
    * For larger `|x|`, the code utilizes the relationship between `erfc(x)` and the Gaussian integral and employs asymptotic expansions. It approximates `log(x * erfc(x)) + x^2 + 0.5625` using rational functions `R(1/x^2) / S(1/x^2)`.
    * The constants `ra0` to `ra16`, `sa1` to `sa16`, `rb0` to `rb14`, `sb1` to `sb14`, `rc0` to `rc9`, and `sc1` to `sc9` are the coefficients for these rational function approximations in different ranges.
    * The code then uses the exponential function (`expl`) to calculate `erfc(x)` from this approximation.

* **Very Large Arguments:**
    * For extremely large `|x|`, the values of `erf(x)` and `erfc(x)` approach their limits (±1 and 0, respectively). The code returns values very close to these limits to avoid unnecessary computation.

**Why this approach?**

* **Accuracy:** Polynomial and rational function approximations can be tailored to achieve high accuracy within specific intervals. By using different approximations for different ranges, the overall accuracy of the function is maintained.
* **Performance:** Evaluating polynomials and rational functions is computationally efficient. This is crucial for math libraries used in performance-sensitive applications.

**4. Dynamic Linker Functionality:**

The dynamic linker (e.g., `linker64` or `linker`) in Android is responsible for loading shared libraries (`.so` files) into memory when they are needed by an application or the system. `libm.so` is a shared library containing the implementations of the math functions.

**SO Layout Sample for `libm.so`:**

```
libm.so:
    .text (Executable code)
        ...
        erfl:         <-- Entry point for the erfl function
            <instructions for erfl>
        erfcl:        <-- Entry point for the erfcl function
            <instructions for erfcl>
        ... (other math functions)
    .rodata (Read-only data)
        ...
        tiny:         <-- Address of the 'tiny' constant
        half:         <-- Address of the 'half' constant
        pp0:          <-- Address of the 'pp0' constant
        ... (other constants used by erfl and erfcl)
    .data (Initialized data)
        ... (may contain global variables, though less common in libm)
    .bss (Uninitialized data)
        ...
    .symtab (Symbol table)
        ...
        erfl (GLOBAL, FUNCTION, .text, address_of_erfl)
        erfcl (GLOBAL, FUNCTION, .text, address_of_erfcl)
        tiny (GLOBAL, OBJECT, .rodata, address_of_tiny)
        half (GLOBAL, OBJECT, .rodata, address_of_half)
        pp0 (GLOBAL, OBJECT, .rodata, address_of_pp0)
        ...
    .dynsym (Dynamic symbol table - subset of .symtab)
        ...
        erfl
        erfcl
        ...
    .rel.dyn (Relocation entries for dynamic linking)
        ...
    .rel.plt (Relocation entries for Procedure Linkage Table)
        ...
```

**Symbol Processing During Dynamic Linking:**

1. **Symbol Lookup:** When a program or another library (e.g., the Android framework or an NDK-based application) needs to call `erfl` or `erfcl`, the dynamic linker searches for these symbols in the loaded shared libraries.

2. **Symbol Resolution:**
   * The linker looks at the `.dynsym` (dynamic symbol table) of `libm.so`.
   * It finds the entries for `erfl` and `erfcl`, which contain the virtual memory addresses where the code for these functions resides within `libm.so`.
   * If the symbol is not found, the linker will report an error.

3. **Relocation:**
   * The `.rel.dyn` and `.rel.plt` sections contain information about addresses that need to be adjusted when the library is loaded at a specific address in memory (due to Address Space Layout Randomization - ASLR).
   * For example, if the `erfl` function needs to access the `tiny` constant, the address of `tiny` in the code might need to be updated based on where `libm.so` is loaded. The relocation entries guide this process.
   * The Procedure Linkage Table (`.plt`) is used for lazy binding of function calls, meaning the actual address of a function is resolved only when it's first called.

**How Constants are Handled:**

The constants (like `tiny`, `half`, `pp0`, etc.) are typically placed in the `.rodata` section, which is a read-only segment. When `erfl` or `erfcl` is loaded, the dynamic linker ensures that the code within these functions can correctly access the addresses of these constants. The symbol table contains entries for these constants, allowing the linker to resolve their addresses.

**5. Logical Reasoning with Assumptions:**

Let's consider the `erfl` function and a few assumptions:

**Assumption 1: Input is a small positive number (e.g., `x = 0.001`)**

* **Reasoning:** The code checks `if(ax < 0.84375)` and then `if(ax < 0x1p-40L)`. Since 0.001 is larger than `0x1p-40L`, the code will proceed to the approximation `x + efx * x`.
* **Expected Output:**  `erf(0.001)` will be approximately `0.001 + (1.28379167095512573896158903121545167e-01L * 0.001)`, which is close to `0.001128379`.

**Assumption 2: Input is a moderate positive number (e.g., `x = 0.5`)**

* **Reasoning:**  `0.5` falls within the range where the rational function approximation using `pp` and `qq` coefficients is used. The code will calculate `z = x*x` and then evaluate the polynomials `r` and `s`. Finally, it will return `x + x * (r/s)`.
* **Expected Output:**  `erf(0.5)` will be calculated based on the polynomial approximation. You would need to evaluate the polynomials with the given coefficients to get the precise output. It should be close to the actual value of `erf(0.5) ≈ 0.5205`.

**Assumption 3: Input is a large positive number (e.g., `x = 10`)**

* **Reasoning:** `10` is greater than `9`, so the code will enter the `if (ax >= 9)` block. Since `x` is positive, it will return `one - tiny`, where `tiny` is a very small number.
* **Expected Output:**  A value very close to `1.0`.

**6. Common Usage Errors and Examples:**

* **Incorrect Data Type:** Passing a `float` or `double` to a function expecting `long double` might lead to implicit conversions and loss of precision or unexpected results.
   ```c
   float f = 1.0f;
   long double result = erfl(f); // Implicit conversion, potential loss of precision
   ```

* **Overflow/Underflow:** While the code handles infinities, providing extremely large positive or negative inputs to `erfcl` might lead to values very close to 0 or 2, potentially causing underflow if not handled carefully in subsequent calculations.

* **Performance Considerations:**  Repeatedly calling these functions within tight loops can be computationally expensive. Developers should consider optimizing their algorithms if performance is critical.

* **Misunderstanding the Domain:**  While the functions are generally defined for all real numbers, the accuracy of the approximations might vary across different input ranges. Developers should be aware of the specified domains for each approximation to understand the potential for error.

**7. Debugging Clues: Android Framework/NDK to `s_erfl.c`:**

Here's a typical call path for how an Android application might reach the `erfl` function:

1. **Java Code (Android Framework):**
   ```java
   double x = 1.0;
   double erf_x = java.lang.Math.erf(x); // Calls into native code
   ```

2. **Native Bridge (JNI):** The `java.lang.Math.erf()` method is a native method. When called, the Java Virtual Machine (Dalvik or ART) uses the Java Native Interface (JNI) to transition to native code.

3. **`libjavacrypto.so` or `libopenjdk.so` (or similar):**  Historically, some basic math functions were handled in `libjavacrypto.so`. More recently, the trend is towards `libopenjdk.so`. The native implementation of `java.lang.Math.erf()` would likely reside here.

4. **`libm.so` (Android's Math Library):** The native implementation in `libjavacrypto.so` or `libopenjdk.so` will likely call the standard C math library function `erf`. In Android, this resolves to the implementation in `libm.so`.

5. **`erfl` (for `long double`) or `erf` (for `double`) in `libm.so`:**
   * If the underlying implementation in `libjavacrypto.so` or `libopenjdk.so` uses `double` precision, it would call the `erf` function in `libm.so` (likely implemented in `s_erf.c`).
   * If a developer uses the NDK and explicitly calls the `erfl` function for `long double` precision:
     ```c++
     #include <cmath>
     long double x = 1.0L;
     long double erf_x = erfl(x); // Directly calls the long double version
     ```
     This would directly call the `erfl` function implemented in `s_erfl.c`.

**Debugging Steps:**

* **NDK Debugging:** If the issue originates from NDK code, you can use tools like `gdb` or `lldb` to set breakpoints in your C/C++ code and step through the execution to see when `erfl` is called and with what arguments.

* **System Tracing (Systrace/Perfetto):** These tools can help trace system calls and function calls, potentially showing the call stack leading to `erfl` from the framework.

* **Logging:** Adding `ALOG` statements in the `erfl` or `erfcl` functions (if you have a custom build or are debugging the platform) can help track the input values and execution flow.

* **Static Analysis:** Examining the source code of the framework or NDK components that call `erf` can reveal the exact call path and data types being used.

By understanding the call chain and the implementation details of `erfl` and `erfcl`, developers can effectively debug issues related to these functions in their Android applications.

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/ld128/s_erfl.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
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

/*
 * See s_erf.c for complete comments.
 *
 * Converted to long double by Steven G. Kargl.
 */
#include <float.h>

#include "fpmath.h"
#include "math.h"
#include "math_private.h"

/* XXX Prevent compilers from erroneously constant folding these: */
static const volatile long double tiny = 0x1p-10000L;

static const double
half= 0.5,
one = 1,
two = 2;
/*
 * In the domain [0, 2**-40], only the first term in the power series
 * expansion of erf(x) is used.  The magnitude of the first neglected
 * terms is less than 2**-120.
 */
static const long double
efx  =  1.28379167095512573896158903121545167e-01L,	/* 0xecbff6a7, 0x481dd788, 0xb64d21a8, 0xeb06fc3f */
efx8 =  1.02703333676410059116927122497236133e+00L,	/* 0xecbff6a7, 0x481dd788, 0xb64d21a8, 0xeb06ff3f */
/*
 * Domain [0, 0.84375], range ~[-1.919e-38, 1.919e-38]:
 * |(erf(x) - x)/x - pp(x)/qq(x)| < 2**-125.29
 */
pp0  =  1.28379167095512573896158903121545167e-01L,	/* 0x3ffc06eb, 0xa8214db6, 0x88d71d48, 0xa7f6bfec */
pp1  = -3.14931554396568573802046931159683404e-01L,	/* 0xbffd427d, 0x6ada7263, 0x547eb096, 0x95f37463 */
pp2  = -5.27514920282183487103576956956725309e-02L,	/* 0xbffab023, 0xe5a271e3, 0xb0e79b01, 0x2f7ac962 */
pp3  = -1.13202828509005281355609495523452713e-02L,	/* 0xbff872f1, 0x6a5023a1, 0xe08b3884, 0x326af20f */
pp4  = -9.18626155872522453865998391206048506e-04L,	/* 0xbff4e19f, 0xea5fb024, 0x43247a37, 0xe430b06c */
pp5  = -7.87518862406176274922506447157284230e-05L,	/* 0xbff14a4f, 0x31a85fe0, 0x7fff2204, 0x09c49b37 */
pp6  = -3.42357944472240436548115331090560881e-06L,	/* 0xbfeccb81, 0x4b43c336, 0xcd2eb6c2, 0x903f2d87 */
pp7  = -1.37317432573890412634717890726745428e-07L,	/* 0xbfe826e3, 0x0e915eb6, 0x42aee414, 0xf7e36805 */
pp8  = -2.71115170113861755855049008732113726e-09L,	/* 0xbfe2749e, 0x2b94fd00, 0xecb4d166, 0x0efb91f8 */
pp9  = -3.37925756196555959454018189718117864e-11L,	/* 0xbfdc293e, 0x1d9060cb, 0xd043204a, 0x314cd7f0 */
qq1  =  4.76672625471551170489978555182449450e-01L,	/* 0x3ffde81c, 0xde6531f0, 0x76803bee, 0x526e29e9 */
qq2  =  1.06713144672281502058807525850732240e-01L,	/* 0x3ffbb518, 0xd7a6bb74, 0xcd9bdd33, 0x7601eee5 */
qq3  =  1.47747613127513761102189201923147490e-02L,	/* 0x3ff8e423, 0xae527e18, 0xf12cb447, 0x723b4749 */
qq4  =  1.39939377672028671891148770908874816e-03L,	/* 0x3ff56ed7, 0xba055d84, 0xc21b45c4, 0x388d1812 */
qq5  =  9.44302939359455241271983309378738276e-05L,	/* 0x3ff18c11, 0xc18c99a4, 0x86d0fe09, 0x46387b4c */
qq6  =  4.56199342312522842161301671745365650e-06L,	/* 0x3fed3226, 0x73421d05, 0x08875300, 0x32fa1432 */
qq7  =  1.53019260483764773845294600092361197e-07L,	/* 0x3fe8489b, 0x3a63f627, 0x2b9ad2ce, 0x26516e57 */
qq8  =  3.25542691121324805094777901250005508e-09L,	/* 0x3fe2bf6c, 0x26d93a29, 0x9142be7c, 0x9f1dd043 */
qq9  =  3.37405581964478060434410167262684979e-11L;	/* 0x3fdc28c8, 0xfb8fa1be, 0x10e57eec, 0xaa19e49f */

static const long double
erx  =  8.42700792949714894142232424201210961e-01L,	/* 0x3ffeaf76, 0x7a741088, 0xb0000000, 0x00000000 */
/*
 * Domain [0.84375, 1.25], range ~[-2.521e-36, 2.523e-36]:
 * |(erf(x) - erx) - pa(x)/qa(x)| < 2**-120.15
 */
pa0  = -2.48010117891186017024438233323795897e-17L,	/* 0xbfc7c97f, 0x77812279, 0x6c877f22, 0xef4bfb2e */
pa1  =  4.15107497420594680894327969504526489e-01L,	/* 0x3ffda911, 0xf096fbc2, 0x55662005, 0x2337fa64 */
pa2  = -3.94180628087084846724448515851892609e-02L,	/* 0xbffa42e9, 0xab54528c, 0xad529da1, 0x6efc2af3 */
pa3  =  4.48897599625192107295954790681677462e-02L,	/* 0x3ffa6fbc, 0xa65edba1, 0x0e4cbcea, 0x73ef9a31 */
pa4  =  8.02069252143016600110972019232995528e-02L,	/* 0x3ffb4887, 0x0e8b548e, 0x3230b417, 0x11b553b3 */
pa5  = -1.02729816533435279443621120242391295e-02L,	/* 0xbff850a0, 0x041de3ee, 0xd5bca6c9, 0x4ef5f9f2 */
pa6  =  5.70777694530755634864821094419982095e-03L,	/* 0x3ff77610, 0x9b501e10, 0x4c978382, 0x742df68f */
pa7  =  1.22635150233075521018231779267077071e-03L,	/* 0x3ff5417b, 0x0e623682, 0x60327da0, 0x96b9219e */
pa8  =  5.36100234820204569428412542856666503e-04L,	/* 0x3ff41912, 0x27ceb4c1, 0x1d3298ec, 0x84ced627 */
pa9  = -1.97753571846365167177187858667583165e-04L,	/* 0xbff29eb8, 0x23f5bcf3, 0x15c83c46, 0xe4fda98b */
pa10 =  6.19333039900846970674794789568415105e-05L,	/* 0x3ff103c4, 0x60f88e46, 0xc0c9fb02, 0x13cc7fc1 */
pa11 = -5.40531400436645861492290270311751349e-06L,	/* 0xbfed6abe, 0x9665f8a8, 0xdd0ad3ba, 0xe5dc0ee3 */
qa1  =  9.05041313265490487793231810291907851e-01L,	/* 0x3ffecf61, 0x93340222, 0xe9930620, 0xc4e61168 */
qa2  =  6.79848064708886864767240880834868092e-01L,	/* 0x3ffe5c15, 0x0ba858dc, 0xf7900ae9, 0xfea1e09a */
qa3  =  4.04720609926471677581066689316516445e-01L,	/* 0x3ffd9e6f, 0x145e9b00, 0x6d8c1749, 0xd2928623 */
qa4  =  1.69183273898369996364661075664302225e-01L,	/* 0x3ffc5a7c, 0xc2a363c1, 0xd6c19097, 0xef9b4063 */
qa5  =  7.44476185988067992342479750486764248e-02L,	/* 0x3ffb30ef, 0xfc7259ef, 0x1bcbb089, 0x686dd62d */
qa6  =  2.02981172725892407200420389604788573e-02L,	/* 0x3ff94c90, 0x7976cb0e, 0x21e1d36b, 0x0f09ca2b */
qa7  =  6.94281866271607668268269403102277234e-03L,	/* 0x3ff7c701, 0x2b193250, 0xc5d46ecc, 0x374843d8 */
qa8  =  1.12952275469171559611651594706820034e-03L,	/* 0x3ff52818, 0xfd2a7c06, 0xd13e38fd, 0xda4b34f5 */
qa9  =  3.13736683241992737197226578597710179e-04L,	/* 0x3ff348fa, 0x0cb48d18, 0x051f849b, 0x135ccf74 */
qa10 =  1.17037675204033225470121134087771410e-05L,	/* 0x3fee88b6, 0x98f47704, 0xa5d8f8f2, 0xc6422e11 */
qa11 =  4.61312518293853991439362806880973592e-06L,	/* 0x3fed3594, 0xe31db94f, 0x3592b693, 0xed4386b4 */
qa12 = -1.02158572037456893687737553657431771e-06L;	/* 0xbfeb123a, 0xd60d9b1e, 0x1f6fdeb9, 0x7dc8410a */
/*
 * Domain [1.25,2.85715], range ~[-2.922e-37,2.922e-37]:
 * |log(x*erfc(x)) + x**2 + 0.5625 - ra(x)/sa(x)| < 2**-121.36
 */
static const long double
ra0  = -9.86494292470069009555706994426014461e-03L,	/* 0xbff84341, 0x239e8709, 0xe941b06a, 0xcb4b6ec5 */
ra1  = -1.13580436992565640457579040117568870e+00L,	/* 0xbfff22c4, 0x133f7c0d, 0x72d5e231, 0x2eb1ee3f */
ra2  = -4.89744330295291950661185707066921755e+01L,	/* 0xc00487cb, 0xa38b4fc2, 0xc136695b, 0xc1df8047 */
ra3  = -1.10766149300215937173768072715352140e+03L,	/* 0xc00914ea, 0x55e6beb3, 0xabc50e07, 0xb6e5664d */
ra4  = -1.49991031232170934967642795601952100e+04L,	/* 0xc00cd4b8, 0xd33243e6, 0xffbf6545, 0x3c57ef6e */
ra5  = -1.29805749738318462882524181556996692e+05L,	/* 0xc00ffb0d, 0xbfeed9b6, 0x5b2a3ff4, 0xe245bd3c */
ra6  = -7.42828497044940065828871976644647850e+05L,	/* 0xc0126ab5, 0x8fe7caca, 0x473352d9, 0xcd4e0c90 */
ra7  = -2.85637299581890734287995171242421106e+06L,	/* 0xc0145cad, 0xa7f76fe7, 0x3e358051, 0x1799f927 */
ra8  = -7.40674797129824999383748865571026084e+06L,	/* 0xc015c412, 0x6fe29c02, 0x298ad158, 0x7d24e45c */
ra9  = -1.28653420911930973914078724204151759e+07L,	/* 0xc016889e, 0x7c2eb0dc, 0x95d5863b, 0x0aa34dc3 */
ra10 = -1.47198163599330179552932489109452638e+07L,	/* 0xc016c136, 0x90b84923, 0xf9bcb497, 0x19bbd0f5 */
ra11 = -1.07812992258382800318665248311522624e+07L,	/* 0xc0164904, 0xe673a113, 0x35d7f079, 0xe13701f3 */
ra12 = -4.83545565681708642630419905537756076e+06L,	/* 0xc0152721, 0xfea094a8, 0x869eb39d, 0x413d6f13 */
ra13 = -1.23956521201673964822976917356685286e+06L,	/* 0xc0132ea0, 0xd3646baa, 0x2fe62b0d, 0xbae5ce85 */
ra14 = -1.62289333553652417591275333240371812e+05L,	/* 0xc0103cf8, 0xaab1e2d6, 0x4c25e014, 0x248d76ab */
ra15 = -8.82890392601176969729168894389833110e+03L,	/* 0xc00c13e7, 0x3b3d8f94, 0x6fbda6f6, 0xe7049a82 */
ra16 = -1.22591866337261720023681535568334619e+02L,	/* 0xc005ea5e, 0x12358891, 0xcfa712c5, 0x77f050d4 */
sa1  =  6.44508918884710829371852723353794047e+01L,	/* 0x400501cd, 0xb69a6c0f, 0x5716de14, 0x47161af6 */
sa2  =  1.76118475473171481523704824327358534e+03L,	/* 0x4009b84b, 0xd305829f, 0xc4c771b0, 0xbf1f7f9b */
sa3  =  2.69448346969488374857087646131950188e+04L,	/* 0x400da503, 0x56bacc05, 0x4fdba68d, 0x2cca27e6 */
sa4  =  2.56826633369941456778326497384543763e+05L,	/* 0x4010f59d, 0x51124428, 0x69c41de6, 0xbd0d5753 */
sa5  =  1.60647413092257206847700054645905859e+06L,	/* 0x40138834, 0xa2184244, 0x557a1bed, 0x68c9d556 */
sa6  =  6.76963075165099718574753447122393797e+06L,	/* 0x40159d2f, 0x7b01b0cc, 0x8bac9e95, 0x5d35d56e */
sa7  =  1.94295690905361884290986932493647741e+07L,	/* 0x40172878, 0xc1172d61, 0x3068501e, 0x2f3c71da */
sa8  =  3.79774781017759149060839255547073541e+07L,	/* 0x401821be, 0xc30d06fe, 0x410563d7, 0x032111fd */
sa9  =  5.00659831846029484248302236457727397e+07L,	/* 0x40187df9, 0x1f97a111, 0xc51d6ac2, 0x4b389793 */
sa10 =  4.36486287620506484276130525941972541e+07L,	/* 0x40184d03, 0x3a618ae0, 0x2a723357, 0xfa45c60a */
sa11 =  2.43779678791333894255510508253951934e+07L,	/* 0x401773fa, 0x6fe10ee2, 0xc467850d, 0xc6b7ff30 */
sa12 =  8.30732360384443202039372372212966542e+06L,	/* 0x4015fb09, 0xee6a5631, 0xdd98de7e, 0x8b00461a */
sa13 =  1.60160846942050515734192397495105693e+06L,	/* 0x40138704, 0x8782bf13, 0x5b8fb315, 0xa898abe5 */
sa14 =  1.54255505242533291014555153757001825e+05L,	/* 0x40102d47, 0xc0abc98e, 0x843c9490, 0xb4352440 */
sa15 =  5.87949220002375547561467275493888824e+03L,	/* 0x400b6f77, 0xe00d21d1, 0xec4d41e8, 0x2f8e1673 */
sa16 =  4.97272976346793193860385983372237710e+01L;	/* 0x40048dd1, 0x816c1b3f, 0x24f540a6, 0x4cfe03cc */
/*
 * Domain [2.85715,9], range ~[-7.886e-37,7.918e-37]:
 * |log(x*erfc(x)) + x**2 + 0.5625 - rb(x)/sb(x)| < 2**-120
 */
static const long double
rb0  = -9.86494292470008707171371994479162369e-3L, /* 0xbff84341, 0x239e86f4, 0x2f57e561, 0xf4469360 */
rb1  = -1.57047326624110727986326503729442830L,    /* 0xbfff920a, 0x8935bf73, 0x8803b894, 0x4656482d */
rb2  = -1.03228196364885474342132255440317065e2L,  /* 0xc0059ce9, 0xac4ed0ff, 0x2cff0ff7, 0x5e70d1ab */
rb3  = -3.74000570653418227179358710865224376e3L,  /* 0xc00ad380, 0x2ebf7835, 0xf6b07ed2, 0x861242f7 */
rb4  = -8.35435477739098044190860390632813956e4L,  /* 0xc00f4657, 0x8c3ae934, 0x3647d7b3, 0x80e76fb7 */
rb5  = -1.21398672055223642118716640216747152e6L,  /* 0xc0132862, 0x2b8761c8, 0x27d18c0f, 0x137c9463 */
rb6  = -1.17669175877248796101665344873273970e7L,  /* 0xc0166719, 0x0b2cea46, 0x81f14174, 0x11602ea5 */
rb7  = -7.66108006086998253606773064264599615e7L,  /* 0xc019243f, 0x3c26f4f0, 0x1cc05241, 0x3b953728 */
rb8  = -3.32547117558141845968704725353130804e8L,  /* 0xc01b3d24, 0x42d8ee26, 0x24ef6f3b, 0x604a8c65 */
rb9  = -9.41561252426350696802167711221739746e8L,  /* 0xc01cc0f8, 0xad23692a, 0x8ddb2310, 0xe9937145 */
rb10 = -1.67157110805390944549427329626281063e9L,  /* 0xc01d8e88, 0x9a903734, 0x09a55fa3, 0xd205c903 */
rb11 = -1.74339631004410841337645931421427373e9L,  /* 0xc01d9fa8, 0x77582d2a, 0xc183b8ab, 0x7e00cb05 */
rb12 = -9.57655233596934915727573141357471703e8L,  /* 0xc01cc8a5, 0x460cc685, 0xd0271fa0, 0x6a70e3da */
rb13 = -2.26320062731339353035254704082495066e8L,  /* 0xc01aafab, 0xd7d76721, 0xc9720e11, 0x6a8bd489 */
rb14 = -1.42777302996263256686002973851837039e7L,  /* 0xc016b3b8, 0xc499689f, 0x2b88d965, 0xc32414f9 */
sb1  =  1.08512869705594540211033733976348506e2L,  /* 0x4005b20d, 0x2db7528d, 0x00d20dcb, 0x858f6191 */
sb2  =  5.02757713761390460534494530537572834e3L,  /* 0x400b3a39, 0x3bf4a690, 0x3025d28d, 0xfd40a891 */
sb3  =  1.31019107205412870059331647078328430e5L,  /* 0x400fffcb, 0x1b71d05e, 0x3b28361d, 0x2a3c3690 */
sb4  =  2.13021555152296846166736757455018030e6L,  /* 0x40140409, 0x3c6984df, 0xc4491d7c, 0xb04aa08d */
sb5  =  2.26649105281820861953868568619768286e7L,  /* 0x401759d6, 0xce8736f0, 0xf28ad037, 0x2a901e0c */
sb6  =  1.61071939490875921812318684143076081e8L,  /* 0x401a3338, 0x686fb541, 0x6bd27d06, 0x4f95c9ac */
sb7  =  7.66895673844301852676056750497991966e8L,  /* 0x401c6daf, 0x31cec121, 0x54699126, 0x4bd9bf9e */
sb8  =  2.41884450436101936436023058196042526e9L,  /* 0x401e2059, 0x46b0b8d7, 0x87b64cbf, 0x78bc296d */
sb9  =  4.92403055884071695093305291535107666e9L,  /* 0x401f257e, 0xbe5ed739, 0x39e17346, 0xcadd2e55 */
sb10 =  6.18627786365587486459633615573786416e9L,  /* 0x401f70bb, 0x1be7a7e7, 0x6a45b5ae, 0x607c70f0 */
sb11 =  4.45898013426501378097430226324743199e9L,  /* 0x401f09c6, 0xa32643d7, 0xf1724620, 0x9ea46c32 */
sb12 =  1.63006115763329848117160344854224975e9L,  /* 0x401d84a3, 0x0996887f, 0x65a4f43b, 0x978c1d74 */
sb13 =  2.39216717012421697446304015847567721e8L,  /* 0x401ac845, 0x09a065c2, 0x30095da7, 0x9d72d6ae */
sb14 =  7.84837329009278694937250358810225609e6L;  /* 0x4015df06, 0xd5290e15, 0x63031fac, 0x4d9c894c */
/*
 * Domain [9,108], range ~[-5.324e-38,5.340e-38]:
 * |log(x*erfc(x)) + x**2 + 0.5625 - r(x)/s(x)| < 2**-124
 */
static const long double
rc0  = -9.86494292470008707171367567652935673e-3L, /* 0xbff84341, 0x239e86f4, 0x2f57e55b, 0x1aa10fd3 */
rc1  = -1.26229447747315096406518846411562266L,    /* 0xbfff4325, 0xbb1aab28, 0xda395cd9, 0xfb861c15 */
rc2  = -6.13742634438922591780742637728666162e1L,  /* 0xc004eafe, 0x7dd51cd8, 0x3c7c5928, 0x751e50cf */
rc3  = -1.50455835478908280402912854338421517e3L,  /* 0xc0097823, 0xbc15b9ab, 0x3d60745c, 0x523e80a5 */
rc4  = -2.04415631865861549920184039902945685e4L,  /* 0xc00d3f66, 0x40b3fc04, 0x5388f2ec, 0xb009e1f0 */
rc5  = -1.57625662981714582753490610560037638e5L,  /* 0xc01033dc, 0xd4dc95b6, 0xfd4da93b, 0xf355b4a9 */
rc6  = -6.73473451616752528402917538033283794e5L,  /* 0xc01248d8, 0x2e73a4f9, 0xcded49c5, 0xfa3bfeb7 */
rc7  = -1.47433165421387483167186683764364857e6L,  /* 0xc01367f1, 0xba77a8f7, 0xcfdd0dbb, 0x25d554b3 */
rc8  = -1.38811981807868828563794929997744139e6L,  /* 0xc01352e5, 0x7d16d9ad, 0xbbdcbf38, 0x38fbc5ea */
rc9  = -3.59659700530831825640766479698155060e5L,  /* 0xc0115f3a, 0xecd57f45, 0x21f8ad6c, 0x910a5958 */
sc1  =  7.72730753022908298637508998072635696e1L,  /* 0x40053517, 0xa10d52bc, 0xdabb55b6, 0xbd0328cd */
sc2  =  2.36825757341694050500333261769082182e3L,  /* 0x400a2808, 0x3e0a9b42, 0x82977842, 0x9c5de29e */
sc3  =  3.72210540173034735352888847134073099e4L,  /* 0x400e22ca, 0x1ba827ef, 0xac8390d7, 0x1fc39a41 */
sc4  =  3.24136032646418336712461033591393412e5L,  /* 0x40113c8a, 0x0216e100, 0xc59d1e44, 0xf0e68d9d */
sc5  =  1.57836135851134393802505823370009175e6L,  /* 0x40138157, 0x95bc7664, 0x17575961, 0xdbe58eeb */
sc6  =  4.12881981392063738026679089714182355e6L,  /* 0x4014f801, 0x9e82e8d2, 0xb8b3a70e, 0xfd84185d */
sc7  =  5.24438427289213488410596395361544142e6L,  /* 0x40154017, 0x81177109, 0x2aa6c3b0, 0x1f106625 */
sc8  =  2.59909544563616121735963429710382149e6L,  /* 0x40143d45, 0xbb90a9b1, 0x12bf9390, 0xa827a700 */
sc9  =  2.80930665169282501639651995082335693e5L;  /* 0x40111258, 0xaa92222e, 0xa97e3216, 0xa237fa6c */

long double
erfl(long double x)
{
	long double ax,R,S,P,Q,s,y,z,r;
	uint64_t lx, llx;
	int32_t i;
	uint16_t hx;

	EXTRACT_LDBL128_WORDS(hx, lx, llx, x);

	if((hx & 0x7fff) == 0x7fff) {	/* erfl(nan)=nan */
		i = (hx>>15)<<1;
		return (1-i)+one/x;	/* erfl(+-inf)=+-1 */
	}

	ax = fabsl(x);
	if(ax < 0.84375) {
	    if(ax < 0x1p-40L) {
	        if(ax < 0x1p-16373L)	
		    return (8*x+efx8*x)/8;	/* avoid spurious underflow */
		return x + efx*x;
	    }
	    z = x*x;
	    r = pp0+z*(pp1+z*(pp2+z*(pp3+z*(pp4+z*(pp5+z*(pp6+z*(pp7+
		z*(pp8+z*pp9))))))));
	    s = one+z*(qq1+z*(qq2+z*(qq3+z*(qq4+z*(qq5+z*(qq6+z*(qq7+
		z*(qq8+z*qq9))))))));
	    y = r/s;
	    return x + x*y;
	}
	if(ax < 1.25) {
	    s = ax-one;
	    P = pa0+s*(pa1+s*(pa2+s*(pa3+s*(pa4+s*(pa5+s*(pa6+s*(pa7+
		s*(pa8+s*(pa9+s*(pa10+s*pa11))))))))));
	    Q = one+s*(qa1+s*(qa2+s*(qa3+s*(qa4+s*(qa5+s*(qa6+s*(qa7+
		s*(qa8+s*(qa9+s*(qa10+s*(qa11+s*qa12)))))))))));
	    if(x>=0) return (erx + P/Q); else return (-erx - P/Q);
	}
	if (ax >= 9) {			/* inf>|x|>= 9 */
	    if(x>=0) return (one-tiny); else return (tiny-one);
	}
	s = one/(ax*ax);
	if(ax < 2.85715) {	/* |x| < 2.85715 */
	    R=ra0+s*(ra1+s*(ra2+s*(ra3+s*(ra4+s*(ra5+s*(ra6+s*(ra7+
		s*(ra8+s*(ra9+s*(ra10+s*(ra11+s*(ra12+s*(ra13+s*(ra14+
		s*(ra15+s*ra16)))))))))))))));
	    S=one+s*(sa1+s*(sa2+s*(sa3+s*(sa4+s*(sa5+s*(sa6+s*(sa7+
		s*(sa8+s*(sa9+s*(sa10+s*(sa11+s*(sa12+s*(sa13+s*(sa14+
		s*(sa15+s*sa16)))))))))))))));
	} else {	/* |x| >= 2.85715 */
	    R=rb0+s*(rb1+s*(rb2+s*(rb3+s*(rb4+s*(rb5+s*(rb6+s*(rb7+
		s*(rb8+s*(rb9+s*(rb10+s*(rb11+s*(rb12+s*(rb13+
		s*rb14)))))))))))));
	    S=one+s*(sb1+s*(sb2+s*(sb3+s*(sb4+s*(sb5+s*(sb6+s*(sb7+
		s*(sb8+s*(sb9+s*(sb10+s*(sb11+s*(sb12+s*(sb13+
		s*sb14)))))))))))));
	}
	z = (float)ax;
	r = expl(-z*z-0.5625)*expl((z-ax)*(z+ax)+R/S);
	if(x>=0) return (one-r/ax); else return (r/ax-one);
}

long double
erfcl(long double x)
{
	long double ax,R,S,P,Q,s,y,z,r;
	uint64_t lx, llx;
	uint16_t hx;

	EXTRACT_LDBL128_WORDS(hx, lx, llx, x);

	if((hx & 0x7fff) == 0x7fff) {	/* erfcl(nan)=nan */
					/* erfcl(+-inf)=0,2 */
	    return ((hx>>15)<<1)+one/x;
	}

	ax = fabsl(x);
	if(ax < 0.84375L) {
	    if(ax < 0x1p-34L)
		return one-x;
	    z = x*x;
	    r = pp0+z*(pp1+z*(pp2+z*(pp3+z*(pp4+z*(pp5+z*(pp6+z*(pp7+
		z*(pp8+z*pp9))))))));
	    s = one+z*(qq1+z*(qq2+z*(qq3+z*(qq4+z*(qq5+z*(qq6+z*(qq7+
		z*(qq8+z*qq9))))))));
	    y = r/s;
	    if(ax < 0.25L) {  	/* x<1/4 */
		return one-(x+x*y);
	    } else {
		r = x*y;
		r += (x-half);
	       return half - r;
	    }
	}
	if(ax < 1.25L) {
	    s = ax-one;
	    P = pa0+s*(pa1+s*(pa2+s*(pa3+s*(pa4+s*(pa5+s*(pa6+s*(pa7+
		    s*(pa8+s*(pa9+s*(pa10+s*pa11))))))))));
	    Q = one+s*(qa1+s*(qa2+s*(qa3+s*(qa4+s*(qa5+s*(qa6+s*(qa7+
		    s*(qa8+s*(qa9+s*(qa10+s*(qa11+s*qa12)))))))))));
	    if(x>=0) {
	        z  = one-erx; return z - P/Q;
	    } else {
		z = erx+P/Q; return one+z;
	    }
	}

	if(ax < 108) {			/* |x| < 108 */
 	    s = one/(ax*ax);
	    if(ax < 2.85715) {		/* |x| < 2.85715 */
	        R=ra0+s*(ra1+s*(ra2+s*(ra3+s*(ra4+s*(ra5+s*(ra6+s*(ra7+
		    s*(ra8+s*(ra9+s*(ra10+s*(ra11+s*(ra12+s*(ra13+s*(ra14+
		    s*(ra15+s*ra16)))))))))))))));
	        S=one+s*(sa1+s*(sa2+s*(sa3+s*(sa4+s*(sa5+s*(sa6+s*(sa7+
		    s*(sa8+s*(sa9+s*(sa10+s*(sa11+s*(sa12+s*(sa13+s*(sa14+
		    s*(sa15+s*sa16)))))))))))))));
	    } else if(ax < 9) {
		R=rb0+s*(rb1+s*(rb2+s*(rb3+s*(rb4+s*(rb5+s*(rb6+s*(rb7+
		    s*(rb8+s*(rb9+s*(rb10+s*(rb11+s*(rb12+s*(rb13+
		    s*rb14)))))))))))));
		S=one+s*(sb1+s*(sb2+s*(sb3+s*(sb4+s*(sb5+s*(sb6+s*(sb7+
		    s*(sb8+s*(sb9+s*(sb10+s*(sb11+s*(sb12+s*(sb13+
		    s*sb14)))))))))))));
	    } else {
		if(x < -9) return two-tiny;	/* x < -9 */
		R=rc0+s*(rc1+s*(rc2+s*(rc3+s*(rc4+s*(rc5+s*(rc6+s*(rc7+
		    s*(rc8+s*rc9))))))));
		S=one+s*(sc1+s*(sc2+s*(sc3+s*(sc4+s*(sc5+s*(sc6+s*(sc7+
		    s*(sc8+s*sc9))))))));
	    }
	    z = (float)ax;
	    r = expl(-z*z-0.5625)*expl((z-ax)*(z+ax)+R/S);
	    if(x>0) return r/ax; else return two-r/ax;
	} else {
	    if(x>0) return tiny*tiny; else return two-tiny;
	}
}

"""

```