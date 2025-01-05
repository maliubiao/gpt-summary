Response:
Let's break down the thought process to analyze the `catrigf.c` file.

**1. Initial Understanding & Context:**

The prompt states the file is `bionic/libm/upstream-freebsd/lib/msun/src/catrigf.c` within the Android Bionic library. This immediately tells us:

* **Language:** C
* **Purpose:**  Part of the math library (`libm`). Likely implements trigonometric and hyperbolic functions for complex numbers.
* **Origin:**  Upstream from FreeBSD. This is a crucial point – it means the core logic likely comes from a well-established source, but Android might have adapted or modified it.
* **Data Type:** The `f` suffix in `catrigf.c` strongly suggests it deals with `float complex` (single-precision complex numbers).

**2. High-Level Functionality Identification (Skimming):**

A quick scan of the code reveals several functions: `casinhf`, `casinf`, `cacosf`, `cacoshf`, `catanhf`, `catanf`, and a helper function `clog_for_large_values`. The names are very indicative:

* `casinhf`: Complex Arc Sine Hyperbolic (float)
* `casinf`:  Complex Arc Sine (float)
* `cacosf`:  Complex Arc Cosine (float)
* `cacoshf`: Complex Arc Cosine Hyperbolic (float)
* `catanhf`: Complex Arc Tangent Hyperbolic (float)
* `catanf`:  Complex Arc Tangent (float)
* `clog_for_large_values`:  Likely a special case for calculating the complex logarithm when the magnitude of the input is large.

Therefore, the primary function of this file is to provide implementations for complex inverse trigonometric and hyperbolic functions in single-precision floating-point.

**3. Detailed Function Analysis (Iterative Process):**

Now, we examine each function individually, looking for key aspects:

* **Input/Output:** Each function takes a `float complex` as input and returns a `float complex`.
* **Error Handling (NaN/Inf):**  Almost every function starts with checks for `isnan` and `isinf` on the input's real and imaginary parts. The return values in these cases often involve propagating NaNs or specific infinities. This is standard practice for robust numerical libraries.
* **Special Cases:**  Look for conditions like `x == 0 && y == 0`, or when one part is very small or very large. These are common optimization points or edge cases that need careful handling. The comments mentioning "crossover" values also hint at different algorithms being used based on input magnitude.
* **Core Algorithm:**  Try to understand the main calculation. The initial comment about Hull, Fairgrieve, and Tang's paper on complex arcsine/arccosine is a big clue. The `do_hard_work` function seems to be a core component for `casinhf` and `cacosf`.
* **Helper Functions:**  Note the usage of `clog_for_large_values`, `hypotf`, `atan2f`, `log1pf`, `sqrtf`, `asinf`, `acosf`, `atanf`, etc. These are standard math library functions.
* **Internal Macros/Constants:**  Pay attention to constants like `A_crossover`, `B_crossover`, `FLT_EPSILON`, `pio2_hi`, `pio2_lo`, etc. These are often related to precision and algorithm thresholds. The `#undef` and `#define` for `isinf`, `isnan`, and `signbit` indicate potential platform-specific differences or optimizations.
* **Relationships between Functions:** Notice how `casinf` calls `casinhf` with swapped real and imaginary parts, and similarly for `catanf` and `catanhf`. This leverages the mathematical relationships between these functions. `cacoshf` uses `cacosf`.

**4. Android-Specific Considerations:**

* **Bionic's Role:**  Remember that Bionic is Android's standard C library. This file *is* an Android function.
* **NDK/Framework:**  Consider how this code would be reached from higher levels. An Android app using the NDK could directly call these functions. The Android framework itself (written in Java/Kotlin) might indirectly use these functions through JNI calls if it needs complex number math.
* **Dynamic Linking:**  This code resides in `libm.so`. The dynamic linker (`linker64` or `linker`) is responsible for loading this library and resolving symbols when an app uses these functions. We need to imagine a scenario where an app links against `libm.so`.

**5. Addressing Specific Prompt Questions:**

Now, go through each part of the prompt systematically:

* **Functionality:**  List the implemented functions and their purpose.
* **Android Relationship:** Explain that these are standard math functions in Bionic and provide examples of NDK usage and potential framework indirect use.
* **Libc Function Implementation:** For each function, explain the steps involved, paying attention to error handling, special cases, and the core algorithm (referencing the "hard work" function). Explain the helper functions used.
* **Dynamic Linker:** Describe the role of the dynamic linker, provide a simplified `.so` layout, and explain the symbol resolution process. Mention the need for `-lm` during compilation.
* **Logic and Assumptions:**  For the `do_hard_work` function, create a few simple input/output examples to illustrate the different code paths (e.g., small x, small y, large x, large y).
* **User Errors:** Think about common mistakes: passing NaNs or Infs without realizing the implications, or expecting perfect precision given the nature of floating-point arithmetic.
* **Debugging:**  Outline how to trace a call from the Android framework or NDK down to this specific C function using debugging tools (breakpoints, logging, stepping through code).

**6. Refinement and Organization:**

Finally, organize the information clearly, using headings and bullet points to make it easy to read and understand. Ensure the explanations are accurate and cover the key aspects of the code and its role within Android. Review for any gaps or inaccuracies. For example, initially, I might not have fully grasped the significance of the `upstream-freebsd` path, but upon reflection, realizing it's a port helps understand the code's origin and potential for commonalities with other systems. Similarly, explicitly mentioning the `-lm` linker flag is important for anyone trying to use these functions.
This C source file, `catrigf.c`, located within the Android Bionic library's math (`libm`) implementation, provides implementations for several complex inverse trigonometric and hyperbolic functions for single-precision floating-point numbers (`float complex`). It's derived from FreeBSD's `libm` implementation.

Here's a breakdown of its functionality:

**Functionality:**

This file implements the following complex functions:

* **`casinhf(float complex z)`:**  Calculates the complex inverse hyperbolic sine of `z`.
* **`casinf(float complex z)`:** Calculates the complex inverse sine of `z`.
* **`cacosf(float complex z)`:** Calculates the complex inverse cosine of `z`.
* **`cacoshf(float complex z)`:** Calculates the complex inverse hyperbolic cosine of `z`.
* **`catanhf(float complex z)`:** Calculates the complex inverse hyperbolic tangent of `z`.
* **`catanf(float complex z)`:** Calculates the complex inverse tangent of `z`.
* **`clog_for_large_values(float complex z)`:** A helper function used by the other functions to calculate the complex logarithm when the magnitude of the input `z` is large, to avoid overflow or underflow.
* **Internal helper functions:** `f`, `do_hard_work`, `sum_squares`, `real_part_reciprocal`. These are not directly exposed but assist in the calculations.

**Relationship to Android Functionality and Examples:**

These functions are fundamental building blocks for mathematical computations involving complex numbers in Android. They are part of the standard C math library (`libm`) that Android provides.

* **NDK Usage:**  Android Native Development Kit (NDK) developers can directly use these functions in their C/C++ code.
    ```c++
    #include <complex.h>
    #include <stdio.h>

    int main() {
        float complex z = 1.0f + 1.0fi;
        float complex asinh_z = casinhf(z);
        printf("casinhf(1+i) = %f + %fi\n", crealf(asinh_z), cimagf(asinh_z));
        return 0;
    }
    ```
    To compile this using the NDK, you would link against `libm`:
    ```bash
    # Example using clang (NDK's compiler)
    clang++ -o my_app my_app.cpp -lm
    ```
* **Android Framework (Indirect Usage):** While the Android framework itself is primarily written in Java/Kotlin, there are instances where native code is used for performance-critical tasks. If the framework required complex number calculations, it *could* potentially call these `libm` functions through the Java Native Interface (JNI). However, complex number math is less common in core framework components compared to areas like graphics or signal processing.
* **Game Development:** Games often involve complex numbers, particularly in areas like signal processing for audio or advanced physics simulations. NDK-based game engines or game code could leverage these functions.
* **Scientific/Engineering Applications:** Android devices are increasingly used for scientific and engineering tasks. Applications in areas like signal processing, control systems, or computational fluid dynamics might use complex number math and thus rely on these functions.

**Detailed Explanation of Libc Function Implementations:**

Let's break down the implementation of some key functions:

**1. `casinhf(float complex z)` (Complex Inverse Hyperbolic Sine):**

* **Input:** A `float complex` number `z`.
* **Core Logic:**
    * **Handle NaN and Infinity:** Checks for `NaN` and `Infinity` in the real and imaginary parts of `z` and returns appropriate values according to complex number rules.
    * **Large Values Optimization:** If the magnitude of `z` is very large, it calls the helper function `clog_for_large_values` to calculate the logarithm, as `asinh(z) = log(z + sqrt(z^2 + 1))`.
    * **Small Values Optimization:** For very small values of `z`, it directly returns `z` as an approximation.
    * **Main Calculation (`do_hard_work`):**  The core calculation is performed by the `do_hard_work` function. This function implements a carefully designed algorithm (likely based on the paper mentioned in the comments) to compute the real and imaginary parts of the inverse hyperbolic sine accurately, considering different ranges of input values to avoid loss of precision or overflow.
    * **Sign Handling:** The signs of the real and imaginary parts of the result are determined based on the signs of the input.
* **`do_hard_work(float x, float y, float *rx, int *B_is_usable, float *B, float *sqrt_A2my2, float *new_y)`:** This internal function takes the absolute values of the real and imaginary parts of the input (`x`, `y`). It calculates intermediate values like `R` and `S` (related to `hypot(x, y +/- 1)`), and `A`. Based on the value of `A`, it uses different formulas to calculate the real part (`*rx`) of the result. It also calculates a value `B` and `sqrt_A2my2` which are used to determine the imaginary part. The `B_is_usable` flag indicates whether a simpler formula using `asinf` can be used for the imaginary part, or if a more general `atan2f` calculation is needed.

**2. `casinf(float complex z)` (Complex Inverse Sine):**

* **Input:** A `float complex` number `z`.
* **Core Logic:** It leverages the relationship between inverse sine and inverse hyperbolic sine: `arcsin(z) = -i * arcsinh(iz)`. The implementation cleverly uses `casinhf` by swapping the real and imaginary parts of the input and then swapping them back in the result.

**3. `cacosf(float complex z)` (Complex Inverse Cosine):**

* **Input:** A `float complex` number `z`.
* **Core Logic:** Similar to `casinhf`, it handles `NaN` and `Infinity` cases. It also has optimizations for large values using `clog_for_large_values` and for small values. The core calculation is also done by `do_hard_work`, but with the real and imaginary parts of the input swapped compared to `casinhf`. The result is then adjusted based on the quadrant of the input.

**4. `cacoshf(float complex z)` (Complex Inverse Hyperbolic Cosine):**

* **Input:** A `float complex` number `z`.
* **Core Logic:** It uses the relationship `arccosh(z) = arccos(z)`. It calls `cacosf` and then adjusts the real and imaginary parts of the result based on the sign of the imaginary part of the input.

**5. `catanhf(float complex z)` (Complex Inverse Hyperbolic Tangent):**

* **Input:** A `float complex` number `z`.
* **Core Logic:**
    * **Handle Special Cases:** Deals with cases where `y` is 0 and `ax <= 1`, and where `x` is 0.
    * **NaN and Infinity Handling.**
    * **Large Values Optimization:** For large magnitudes, it uses an optimized calculation involving the reciprocal.
    * **Small Values Approximation.**
    * **Main Calculation:**  For the general case, it uses formulas based on logarithms and squares of differences to calculate the real and imaginary parts.
* **Helper Functions:** Uses `sum_squares` to calculate `(ax - 1)^2 + ay^2` and `real_part_reciprocal` for the large value case.

**6. `catanf(float complex z)` (Complex Inverse Tangent):**

* **Input:** A `float complex` number `z`.
* **Core Logic:** Similar to `casinf`, it uses the relationship `arctan(z) = -i * arctanh(iz)` and calls `catanhf` with swapped real and imaginary parts.

**7. `clog_for_large_values(float complex z)` (Complex Logarithm for Large Values):**

* **Input:** A `float complex` number `z`.
* **Core Logic:** This function calculates `log(z)` when the magnitude of `z` is large. It uses different formulas depending on the relative magnitudes of the real and imaginary parts to avoid overflow or underflow issues that can arise when directly calculating `log(hypot(x, y))`.

**Dynamic Linker Functionality and SO Layout:**

The functions in `catrigf.c` are compiled and linked into a shared object (SO) file, typically `libm.so` in Android.

**SO Layout Sample (Simplified):**

```
libm.so:
    .text:
        casinhf:  # Code for casinhf function
            ...
        casinf:   # Code for casinf function
            ...
        cacosf:   # Code for cacosf function
            ...
        cacoshf:  # Code for cacoshf function
            ...
        catanhf:  # Code for catanhf function
            ...
        catanf:   # Code for catanf function
            ...
        clog_for_large_values: # Code for helper function
            ...
        # ... other math functions ...
    .rodata:
        A_crossover:  # Value of A_crossover constant
        B_crossover:  # Value of B_crossover constant
        # ... other constants ...
    .data:
        # ... initialized data ...
    .symtab:
        # Symbol table containing names and addresses of exported functions
        casinhf: address_of_casinhf
        casinf:  address_of_casinf
        cacosf:  address_of_cacosf
        cacoshf: address_of_cacoshf
        catanhf: address_of_catanhf
        catanf:  address_of_catanf
        # ... other symbols ...
    .dynsym:
        # Dynamic symbol table (subset of .symtab for dynamic linking)
        casinhf
        casinf
        cacosf
        cacoshf
        catanhf
        catanf
        # ...
    .rel.dyn:
        # Relocation information for dynamic linking
        # ...
```

**Linking Process:**

1. **Compilation:** When you compile C/C++ code that uses these functions (e.g., using the NDK), the compiler generates object files (`.o`).
2. **Linking:** The linker (part of the toolchain) is responsible for combining these object files and linking them against necessary libraries, including `libm.so`.
3. **Dynamic Linking (at runtime):**
   - When an Android application starts, the dynamic linker (`/system/bin/linker` or `/system/bin/linker64` depending on the architecture) is responsible for loading the required shared libraries.
   - If your application or a library it depends on uses any of the complex math functions, the dynamic linker will load `libm.so` into the process's memory.
   - **Symbol Resolution:** The dynamic linker then resolves the symbols (function names like `casinhf`) used by your code. It looks up the addresses of these functions in the `.dynsym` table of `libm.so`.
   - **Relocation:** The `.rel.dyn` section contains information about where in your code calls to these external functions need to be patched with the actual addresses found in `libm.so`.
   - Once the linking process is complete, your code can successfully call the functions from `libm.so`.

**To use these functions, you typically need to link against `libm` during compilation (e.g., using the `-lm` flag with `gcc` or `clang`).**

**Logical Reasoning, Assumptions, Input & Output Examples:**

Let's consider the `do_hard_work` function in `casinhf` as an example of logical reasoning and assumptions:

* **Assumption:** The input `x` and `y` to `do_hard_work` are the absolute values of the real and imaginary parts of the complex number for which we are calculating the inverse hyperbolic sine.
* **Logical Reasoning:** The function uses different formulas to calculate the real part (`rx`) based on the magnitude of `A`. This is likely done to optimize for different input ranges and maintain accuracy. For example:
    * If `A` is small (close to 1), specific formulas are used that are more accurate in this range.
    * If `A` is larger, a more general logarithmic formula is used.
* **Input & Output Examples for `do_hard_work` (Illustrative):**

    | Input `ax` | Input `ay` |  Likely Code Path | Approximate `*rx` (Real Part of casinhf) | Notes                                    |
    |------------|------------|-------------------|-----------------------------------------|------------------------------------------|
    | 0.1        | 0.1        | `A < A_crossover`, small `y` | Small positive value                | Input close to zero                    |
    | 1.0        | 2.0        | `A < A_crossover`, general case |  Calculated using logarithmic formula |                                          |
    | 100.0      | 50.0       | `A >= A_crossover`          | Larger positive value               | Input with larger magnitude            |
    | 0.00001    | 1.0        | `A < A_crossover`, `y` close to 1 | Calculated using specific formula   | Imaginary part close to 1              |

**Common User or Programming Errors:**

* **Incorrectly Handling NaN or Infinity:**  Users might not be aware of the special rules for complex numbers involving `NaN` and `Infinity`. Passing these values as input might lead to unexpected results if not handled correctly in the calling code.
* **Loss of Precision:**  Floating-point arithmetic has inherent limitations in precision. Users might expect exact results, but these functions provide the closest representable floating-point value. Repeated calculations can accumulate small errors.
* **Domain Errors:** While these functions are defined for all complex numbers, certain edge cases (e.g., very large magnitudes) might lead to loss of accuracy or trigger optimizations that users might not fully understand.
* **Not Linking `libm`:** For NDK developers, forgetting to link against `libm` during the build process will result in linker errors.
* **Assuming Real-Valued Behavior:** Users familiar with real-valued inverse trigonometric functions might incorrectly assume the behavior extends directly to complex numbers. The results can be complex even for real inputs.

**Debugging Lineage from Android Framework/NDK:**

Here's how you can trace a call to these functions as a debugging line:

**Scenario 1: NDK Application:**

1. **Identify the NDK code:** Pinpoint the C/C++ code in your NDK application that calls one of the complex math functions (e.g., `casinhf`).
2. **Set a breakpoint:** Use a debugger (like GDB or LLDB, often integrated into Android Studio) to set a breakpoint at the line where the function is called.
3. **Run the application in debug mode:**  Android Studio allows you to run your native code in debug mode.
4. **Step into the function:** When the breakpoint is hit, use the debugger's "step into" command to go inside the `casinhf` function. This will lead you directly into the code within `catrigf.c` (or a similar implementation if architecture-specific optimizations exist).

**Scenario 2: Android Framework (More Complex):**

1. **Identify potential JNI calls:** If you suspect the framework is indirectly using these functions, you need to find the Java/Kotlin code that might be calling a native method related to complex number calculations.
2. **Find the corresponding native method:** Use the JNI mechanism to find the C/C++ implementation of that native method.
3. **Trace through the native code:**  Set breakpoints in the native code and step through it. Eventually, you might encounter a call to a `libm` function like `casinhf`.
4. **System tracing (Systrace/Perfetto):** For a broader view, you can use system tracing tools like Systrace or Perfetto. These tools can capture function calls across the entire system, including calls into `libm`. You can analyze the trace to see if and when these complex math functions are being called.
5. **Logging:**  Adding `ALOG` statements (Android's logging mechanism) in the native code, including within the `libm` functions (if you have the source and the ability to rebuild), can help trace the execution flow.

**Debugging Tips:**

* **Symbols:** Ensure you have debugging symbols available for `libm.so`. These symbols contain the function names and line numbers, making debugging much easier. Android system images often have separate symbol packages.
* **Architecture:** Be aware of the target architecture (e.g., ARM64, x86). The specific `libm.so` and the implementation might vary slightly.
* **Logging within `libm` (Advanced):** If you have a custom build environment or are deeply investigating an issue, you could potentially add logging within the `catrigf.c` file itself to see the intermediate values and execution flow. However, this requires rebuilding the system libraries.

By understanding the functionality, the Android context, and the debugging techniques, you can effectively work with and troubleshoot code that utilizes these complex math functions in the Android environment.

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/catrigf.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2012 Stephen Montgomery-Smith <stephen@FreeBSD.ORG>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * The algorithm is very close to that in "Implementing the complex arcsine
 * and arccosine functions using exception handling" by T. E. Hull, Thomas F.
 * Fairgrieve, and Ping Tak Peter Tang, published in ACM Transactions on
 * Mathematical Software, Volume 23 Issue 3, 1997, Pages 299-335,
 * http://dl.acm.org/citation.cfm?id=275324.
 *
 * See catrig.c for complete comments.
 *
 * XXX comments were removed automatically, and even short ones on the right
 * of statements were removed (all of them), contrary to normal style.  Only
 * a few comments on the right of declarations remain.
 */

#include <complex.h>
#include <float.h>

#include "math.h"
#include "math_private.h"

#undef isinf
#define isinf(x)	(fabsf(x) == INFINITY)
#undef isnan
#define isnan(x)	((x) != (x))
#define	raise_inexact()	do { volatile float junk __unused = 1 + tiny; } while(0)
#undef signbit
#define signbit(x)	(__builtin_signbitf(x))

static const float
A_crossover =		10,
B_crossover =		0.6417,
FOUR_SQRT_MIN =		0x1p-61,
QUARTER_SQRT_MAX =	0x1p61,
m_e =			2.7182818285e0,		/*  0xadf854.0p-22 */
m_ln2 =			6.9314718056e-1,	/*  0xb17218.0p-24 */
pio2_hi =		1.5707962513e0,		/*  0xc90fda.0p-23 */
RECIP_EPSILON =		1 / FLT_EPSILON,
SQRT_3_EPSILON =	5.9801995673e-4,	/*  0x9cc471.0p-34 */
SQRT_6_EPSILON =	8.4572793338e-4,	/*  0xddb3d7.0p-34 */
SQRT_MIN =		0x1p-63;

static const volatile float
pio2_lo =		7.5497899549e-8,	/*  0xa22169.0p-47 */
tiny =			0x1p-100;

static float complex clog_for_large_values(float complex z);

static inline float
f(float a, float b, float hypot_a_b)
{
	if (b < 0)
		return ((hypot_a_b - b) / 2);
	if (b == 0)
		return (a / 2);
	return (a * a / (hypot_a_b + b) / 2);
}

static inline void
do_hard_work(float x, float y, float *rx, int *B_is_usable, float *B,
    float *sqrt_A2my2, float *new_y)
{
	float R, S, A;
	float Am1, Amy;

	R = hypotf(x, y + 1);
	S = hypotf(x, y - 1);

	A = (R + S) / 2;
	if (A < 1)
		A = 1;

	if (A < A_crossover) {
		if (y == 1 && x < FLT_EPSILON * FLT_EPSILON / 128) {
			*rx = sqrtf(x);
		} else if (x >= FLT_EPSILON * fabsf(y - 1)) {
			Am1 = f(x, 1 + y, R) + f(x, 1 - y, S);
			*rx = log1pf(Am1 + sqrtf(Am1 * (A + 1)));
		} else if (y < 1) {
			*rx = x / sqrtf((1 - y) * (1 + y));
		} else {
			*rx = log1pf((y - 1) + sqrtf((y - 1) * (y + 1)));
		}
	} else {
		*rx = logf(A + sqrtf(A * A - 1));
	}

	*new_y = y;

	if (y < FOUR_SQRT_MIN) {
		*B_is_usable = 0;
		*sqrt_A2my2 = A * (2 / FLT_EPSILON);
		*new_y = y * (2 / FLT_EPSILON);
		return;
	}

	*B = y / A;
	*B_is_usable = 1;

	if (*B > B_crossover) {
		*B_is_usable = 0;
		if (y == 1 && x < FLT_EPSILON / 128) {
			*sqrt_A2my2 = sqrtf(x) * sqrtf((A + y) / 2);
		} else if (x >= FLT_EPSILON * fabsf(y - 1)) {
			Amy = f(x, y + 1, R) + f(x, y - 1, S);
			*sqrt_A2my2 = sqrtf(Amy * (A + y));
		} else if (y > 1) {
			*sqrt_A2my2 = x * (4 / FLT_EPSILON / FLT_EPSILON) * y /
			    sqrtf((y + 1) * (y - 1));
			*new_y = y * (4 / FLT_EPSILON / FLT_EPSILON);
		} else {
			*sqrt_A2my2 = sqrtf((1 - y) * (1 + y));
		}
	}
}

float complex
casinhf(float complex z)
{
	float x, y, ax, ay, rx, ry, B, sqrt_A2my2, new_y;
	int B_is_usable;
	float complex w;

	x = crealf(z);
	y = cimagf(z);
	ax = fabsf(x);
	ay = fabsf(y);

	if (isnan(x) || isnan(y)) {
		if (isinf(x))
			return (CMPLXF(x, y + y));
		if (isinf(y))
			return (CMPLXF(y, x + x));
		if (y == 0)
			return (CMPLXF(x + x, y));
		return (CMPLXF(nan_mix(x, y), nan_mix(x, y)));
	}

	if (ax > RECIP_EPSILON || ay > RECIP_EPSILON) {
		if (signbit(x) == 0)
			w = clog_for_large_values(z) + m_ln2;
		else
			w = clog_for_large_values(-z) + m_ln2;
		return (CMPLXF(copysignf(crealf(w), x),
		    copysignf(cimagf(w), y)));
	}

	if (x == 0 && y == 0)
		return (z);

	raise_inexact();

	if (ax < SQRT_6_EPSILON / 4 && ay < SQRT_6_EPSILON / 4)
		return (z);

	do_hard_work(ax, ay, &rx, &B_is_usable, &B, &sqrt_A2my2, &new_y);
	if (B_is_usable)
		ry = asinf(B);
	else
		ry = atan2f(new_y, sqrt_A2my2);
	return (CMPLXF(copysignf(rx, x), copysignf(ry, y)));
}

float complex
casinf(float complex z)
{
	float complex w = casinhf(CMPLXF(cimagf(z), crealf(z)));

	return (CMPLXF(cimagf(w), crealf(w)));
}

float complex
cacosf(float complex z)
{
	float x, y, ax, ay, rx, ry, B, sqrt_A2mx2, new_x;
	int sx, sy;
	int B_is_usable;
	float complex w;

	x = crealf(z);
	y = cimagf(z);
	sx = signbit(x);
	sy = signbit(y);
	ax = fabsf(x);
	ay = fabsf(y);

	if (isnan(x) || isnan(y)) {
		if (isinf(x))
			return (CMPLXF(y + y, -INFINITY));
		if (isinf(y))
			return (CMPLXF(x + x, -y));
		if (x == 0)
			return (CMPLXF(pio2_hi + pio2_lo, y + y));
		return (CMPLXF(nan_mix(x, y), nan_mix(x, y)));
	}

	if (ax > RECIP_EPSILON || ay > RECIP_EPSILON) {
		w = clog_for_large_values(z);
		rx = fabsf(cimagf(w));
		ry = crealf(w) + m_ln2;
		if (sy == 0)
			ry = -ry;
		return (CMPLXF(rx, ry));
	}

	if (x == 1 && y == 0)
		return (CMPLXF(0, -y));

	raise_inexact();

	if (ax < SQRT_6_EPSILON / 4 && ay < SQRT_6_EPSILON / 4)
		return (CMPLXF(pio2_hi - (x - pio2_lo), -y));

	do_hard_work(ay, ax, &ry, &B_is_usable, &B, &sqrt_A2mx2, &new_x);
	if (B_is_usable) {
		if (sx == 0)
			rx = acosf(B);
		else
			rx = acosf(-B);
	} else {
		if (sx == 0)
			rx = atan2f(sqrt_A2mx2, new_x);
		else
			rx = atan2f(sqrt_A2mx2, -new_x);
	}
	if (sy == 0)
		ry = -ry;
	return (CMPLXF(rx, ry));
}

float complex
cacoshf(float complex z)
{
	float complex w;
	float rx, ry;

	w = cacosf(z);
	rx = crealf(w);
	ry = cimagf(w);
	if (isnan(rx) && isnan(ry))
		return (CMPLXF(ry, rx));
	if (isnan(rx))
		return (CMPLXF(fabsf(ry), rx));
	if (isnan(ry))
		return (CMPLXF(ry, ry));
	return (CMPLXF(fabsf(ry), copysignf(rx, cimagf(z))));
}

static float complex
clog_for_large_values(float complex z)
{
	float x, y;
	float ax, ay, t;

	x = crealf(z);
	y = cimagf(z);
	ax = fabsf(x);
	ay = fabsf(y);
	if (ax < ay) {
		t = ax;
		ax = ay;
		ay = t;
	}

	if (ax > FLT_MAX / 2)
		return (CMPLXF(logf(hypotf(x / m_e, y / m_e)) + 1,
		    atan2f(y, x)));

	if (ax > QUARTER_SQRT_MAX || ay < SQRT_MIN)
		return (CMPLXF(logf(hypotf(x, y)), atan2f(y, x)));

	return (CMPLXF(logf(ax * ax + ay * ay) / 2, atan2f(y, x)));
}

static inline float
sum_squares(float x, float y)
{

	if (y < SQRT_MIN)
		return (x * x);

	return (x * x + y * y);
}

static inline float
real_part_reciprocal(float x, float y)
{
	float scale;
	uint32_t hx, hy;
	int32_t ix, iy;

	GET_FLOAT_WORD(hx, x);
	ix = hx & 0x7f800000;
	GET_FLOAT_WORD(hy, y);
	iy = hy & 0x7f800000;
#define	BIAS	(FLT_MAX_EXP - 1)
#define	CUTOFF	(FLT_MANT_DIG / 2 + 1)
	if (ix - iy >= CUTOFF << 23 || isinf(x))
		return (1 / x);
	if (iy - ix >= CUTOFF << 23)
		return (x / y / y);
	if (ix <= (BIAS + FLT_MAX_EXP / 2 - CUTOFF) << 23)
		return (x / (x * x + y * y));
	SET_FLOAT_WORD(scale, 0x7f800000 - ix);
	x *= scale;
	y *= scale;
	return (x / (x * x + y * y) * scale);
}

float complex
catanhf(float complex z)
{
	float x, y, ax, ay, rx, ry;

	x = crealf(z);
	y = cimagf(z);
	ax = fabsf(x);
	ay = fabsf(y);

	if (y == 0 && ax <= 1)
		return (CMPLXF(atanhf(x), y));

	if (x == 0)
		return (CMPLXF(x, atanf(y)));

	if (isnan(x) || isnan(y)) {
		if (isinf(x))
			return (CMPLXF(copysignf(0, x), y + y));
		if (isinf(y))
			return (CMPLXF(copysignf(0, x),
			    copysignf(pio2_hi + pio2_lo, y)));
		return (CMPLXF(nan_mix(x, y), nan_mix(x, y)));
	}

	if (ax > RECIP_EPSILON || ay > RECIP_EPSILON)
		return (CMPLXF(real_part_reciprocal(x, y),
		    copysignf(pio2_hi + pio2_lo, y)));

	if (ax < SQRT_3_EPSILON / 2 && ay < SQRT_3_EPSILON / 2) {
		raise_inexact();
		return (z);
	}

	if (ax == 1 && ay < FLT_EPSILON)
		rx = (m_ln2 - logf(ay)) / 2;
	else
		rx = log1pf(4 * ax / sum_squares(ax - 1, ay)) / 4;

	if (ax == 1)
		ry = atan2f(2, -ay) / 2;
	else if (ay < FLT_EPSILON)
		ry = atan2f(2 * ay, (1 - ax) * (1 + ax)) / 2;
	else
		ry = atan2f(2 * ay, (1 - ax) * (1 + ax) - ay * ay) / 2;

	return (CMPLXF(copysignf(rx, x), copysignf(ry, y)));
}

float complex
catanf(float complex z)
{
	float complex w = catanhf(CMPLXF(cimagf(z), crealf(z)));

	return (CMPLXF(cimagf(w), crealf(w)));
}

"""

```