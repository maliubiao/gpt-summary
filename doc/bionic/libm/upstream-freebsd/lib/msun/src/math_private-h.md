Response:
My thought process to answer the request involves several steps:

1. **Understanding the Request:** I first carefully read the request, noting the context (bionic/libm/upstream-freebsd/lib/msun/src/math_private.handroid), the desired outputs (functionality, Android relevance, libc function details, dynamic linker info, logical reasoning examples, common errors, and debugging hints), and the provided source code. The keyword "math_private.h" is crucial as it immediately signals a header file containing private math library definitions.

2. **Initial Analysis of the Header File:** I scan the header file (`math_private.h`) for its main components. I recognize it's primarily a collection of:
    * **Macros:**  Large sections are dedicated to macros for extracting and inserting parts of floating-point numbers (doubles, floats, long doubles). These are endianness-aware.
    * **Type Definitions:** Unions like `ieee_double_shape_type`, `ieee_float_shape_type`, and `ieee_quad_shape_type` are defined to facilitate bit-level manipulation of floating-point values.
    * **Inline Functions:**  Small, efficient functions like `rnint`, `rnintf`, `rnintl`, `irint`, etc., are present, focusing on rounding and integer conversion.
    * **Function Declarations:** Declarations for internal kernel functions like `__kernel_rem_pio2`, `__kernel_sin`, `__kernel_cos`, etc., are listed. These are the workhorses of the math library.
    * **Conditional Compilation:**  `#ifdef` and `#ifndef` directives are used extensively for platform-specific configurations (e.g., endianness, architecture).
    * **Comments:**  The comments provide valuable context and explanations of the code's purpose and history.

3. **Identifying Core Functionality:** Based on the contents, I deduce the primary functions of this header file:
    * **Low-Level Floating-Point Manipulation:** The macros and type definitions are clearly designed for directly accessing and manipulating the bit representation of floating-point numbers, crucial for implementing efficient math functions.
    * **Endianness Handling:** The code explicitly handles both big-endian and little-endian architectures, ensuring portability.
    * **Performance Optimization:** Inline functions and macros are used to minimize function call overhead and potentially enable compiler optimizations.
    * **Internal Math Library Support:** The declared kernel functions suggest this header provides the building blocks for more complex mathematical operations.
    * **Platform Abstraction:**  The conditional compilation hints at an attempt to abstract away platform-specific details.

4. **Connecting to Android:**  Knowing that bionic is Android's C library, I recognize the direct relevance of this file. It's part of the foundational math library used by Android's applications and framework. I can provide concrete examples like NDK usage of `sin()`, `cos()`, etc., which internally rely on the primitives defined here.

5. **Explaining libc Function Implementation (Focusing on Macros):** Since the header file doesn't *implement* high-level libc functions directly, I shift my focus to explaining how the *macros* contribute to their implementation. I choose a representative macro like `EXTRACT_WORDS` and break down its steps, explaining how it accesses the high and low words of a double. I emphasize the importance of these low-level manipulations for implementing accurate and efficient math functions. I also note the historical context of why these macros were introduced (to avoid non-ANSI code and issues with GCC's instruction scheduler).

6. **Addressing Dynamic Linker (A More General Approach):** The header file itself doesn't contain dynamic linker code. Therefore, I need to provide a more general explanation of how the dynamic linker interacts with libraries like `libm`. I create a sample `.so` layout, explain the different symbol types (global, local, undefined), and outline the linking process (symbol resolution, relocation). This is based on my general knowledge of how dynamic linkers work.

7. **Logical Reasoning and Examples:**  For logical reasoning, I choose a simple macro like `GET_HIGH_WORD`. I provide an example with a specific double value and trace how the macro extracts the high word. This demonstrates the bit-level manipulation.

8. **Common Usage Errors:** I think about common mistakes developers might make when dealing with floating-point numbers, such as assuming exact equality, not handling NaN and infinity, and potential issues with implicit type conversions.

9. **Tracing the Path from Android Framework/NDK:** I outline the call chain, starting from a high-level Android API (e.g., `android.location.Location.distanceTo()`), going through the framework (possibly native methods), the NDK (if used directly), the libc math functions (like `hypot`), and finally reaching the low-level kernel functions declared in `math_private.h`. This shows how the code in this header file is part of a much larger system.

10. **Structuring the Answer:** I organize the information into logical sections based on the request's prompts. I use clear headings and bullet points to improve readability. I aim for a balance between technical detail and understandable explanations.

11. **Review and Refinement:**  I review my answer to ensure accuracy, completeness, and clarity. I check for any inconsistencies or areas where further explanation might be needed. For instance, I ensure I've clearly distinguished between the header file's role and the actual implementation of math functions.

This iterative process of analyzing the code, connecting it to the broader Android ecosystem, and structuring the information allows me to generate a comprehensive and helpful answer to the user's request. Even when a specific element of the request isn't directly present in the provided code (like the dynamic linker), I use my general knowledge to provide relevant context.
这个目录 `bionic/libm/upstream-freebsd/lib/msun/src/math_private.handroid` 下的 `math_private.h` 文件是 Android Bionic libc 库中数学库的私有头文件。它的主要功能是为 libm 内部实现提供底层的、与平台相关的定义和宏，这些定义和宏通常不应该被外部用户直接使用。

以下是该文件的详细功能列表和说明：

**主要功能:**

1. **定义用于操作浮点数的宏:**  这是该文件最核心的功能。它定义了各种宏，用于从 `double`, `float`, 和 `long double` 类型中提取和插入组成它们的 32 位或 64 位整数，并考虑了不同架构的字节序 (endianness)。
2. **处理字节序 (Endianness):**  根据架构 (`__arm__` 等) 和编译选项 (`__VFP_FP__`, `__ARM_EABI__`)，定义了 `IEEE_WORD_ORDER` 宏，用于指示当前平台的字节序 (大端或小端)。后续的浮点数操作宏会根据这个定义进行调整。
3. **定义用于表示浮点数的联合体 (Union):** 定义了 `ieee_double_shape_type`, `ieee_float_shape_type`, 和 `ieee_quad_shape_type` 等联合体，允许将浮点数类型与其内部的整数表示进行转换。这对于进行底层的位操作非常有用。
4. **提供访问浮点数内部表示的宏:**  例如 `EXTRACT_WORDS`, `GET_HIGH_WORD`, `SET_LOW_WORD` 等宏，允许开发者直接访问和修改浮点数的符号位、指数和尾数。
5. **定义用于处理 `long double` 类型的宏:**  提供了针对 80 位和 128 位 `long double` 类型的宏，用于提取和插入其内部的多个整数部分。
6. **定义用于处理复数的类型:**  如果定义了 `_COMPLEX_H`，则会定义 `float_complex`, `double_complex`, `long_double_complex` 等类型，以及访问实部和虚部的宏 `REALPART` 和 `IMAGPART`。
7. **提供内联的复数构造函数:**  定义了 `CMPLXF`, `CMPLX`, `CMPLXL` 等内联函数，用于安全地构造复数，避免某些编译器在直接使用 `x + I * y` 时可能产生的问题。
8. **提供快速的舍入到最近整数的函数:**  定义了 `rnint`, `rnintf`, `rnintl` 等内联函数，用于将浮点数舍入到最近的整数。
9. **提供将浮点数转换为整数的函数:** 定义了 `irint`, `i64rint` 等宏或内联函数，用于将浮点数转换为整数。
10. **提供快速 floor 函数的宏:**  定义了 `FFLOORF`, `FFLOOR`, `FFLOORL80`, `FFLOORL128` 等宏，用于在特定条件下快速计算浮点数的 floor 值。
11. **声明内部的 kernel 函数:**  声明了 `__kernel_rem_pio2`, `__kernel_sin`, `__kernel_cos` 等 libm 内部使用的核心函数。这些函数实现了复杂的数学运算。
12. **提供一些调试和优化的辅助宏:**  例如 `breakpoint()` 用于插入断点，`STRICT_ASSIGN` 用于强制严格赋值以避免编译器优化带来的精度问题。

**与 Android 功能的关系及举例:**

这个头文件是 Android 数学库 libm 的一部分，libm 提供了标准 C 语言的数学函数（例如 `sin`, `cos`, `sqrt`, `pow` 等）。Android 框架和 NDK 中的许多功能都依赖于这些数学函数。

* **Android Framework:**
    * **图形渲染:**  Android 的图形渲染管道大量使用浮点数运算，例如计算顶点坐标、矩阵变换、光照效果等。这些运算最终会调用 libm 中的数学函数。
    * **动画和物理模拟:**  动画的插值计算、物理引擎的模拟都需要精确的浮点数运算。
    * **传感器数据处理:**  例如，加速度传感器、陀螺仪的数据通常是浮点数，需要进行各种数学运算才能得到有意义的信息。
    * **定位服务:**  计算两个地理位置之间的距离、角度等需要使用三角函数和反三角函数。

* **Android NDK:**
    * 使用 NDK 开发的原生 C/C++ 代码可以直接调用标准 C 库的数学函数，这些函数最终会使用 libm 中的实现，并依赖 `math_private.h` 中定义的宏和类型。
    * 例如，一个使用 OpenGL ES 进行图形渲染的 NDK 应用会频繁调用 `sin`, `cos`, `sqrt` 等函数。
    * 一个进行音频处理的 NDK 应用可能会使用对数、指数等函数。

**libc 函数的实现解释 (以 `sin()` 为例，但此文件只定义辅助宏):**

`math_private.h` 本身并不实现 `libc` 函数，而是为它们的实现提供基础工具。以 `sin()` 函数为例，它的实现通常会经历以下步骤，而 `math_private.h` 中的定义会在某些步骤中被使用：

1. **参数规约 (Argument Reduction):** 对于 `sin(x)`，首先需要将输入角度 `x` 规约到一个较小的范围内，通常是 `[-pi/4, pi/4]` 或 `[0, pi/2]`。这通常涉及到使用 π 的精确近似值，并通过取模运算或减去 π 的倍数来实现。`__ieee754_rem_pio2` 或类似的函数会用到这里，而这个函数的实现可能会用到 `math_private.h` 中定义的浮点数操作宏来处理浮点数的内部表示。
2. **泰勒展开或其他近似计算:** 在规约后的范围内，可以使用泰勒展开、切比雪夫逼近或其他数值方法来计算 `sin` 的值。这些计算涉及到大量的浮点数乘法、加法和减法。
3. **精度处理和边界条件:**  需要处理特殊值，例如 NaN (非数字)、无穷大，以及输入接近于零的情况。还需要保证计算的精度符合要求。
4. **返回结果:**  最终返回计算得到的 `sin` 值。

**`math_private.h` 在 `sin()` 实现中的作用：**

* **`EXTRACT_WORDS` 等宏:** 可能用于快速访问 `x` 的高低位，以便进行参数规约或处理特殊值。
* **`INSERT_WORDS` 等宏:**  可能用于构造中间结果或最终结果的浮点数。
* **类型定义 (如 `ieee_double_shape_type`):**  用于在不同表示之间进行转换。
* **内部 kernel 函数的声明 (`__kernel_sin`):**  `sin()` 的实现可能会调用更底层的 kernel 函数来进行核心计算。

**Dynamic Linker 的功能 (一般性解释，此文件不涉及):**

动态链接器 (在 Android 上是 `linker` 或 `linker64`) 负责在程序运行时将程序依赖的共享库 (`.so` 文件) 加载到内存中，并将程序中对共享库函数的调用链接到库中实际的函数地址。

**SO 布局样本:**

```
.so 文件布局:

ELF Header:  (包含文件类型、架构、入口点等信息)

Program Headers: (描述内存段的加载信息，如代码段、数据段)
  LOAD: 可执行代码段 (.text)
  LOAD: 只读数据段 (.rodata)
  LOAD: 可读写数据段 (.data, .bss)
  DYNAMIC: 动态链接信息段

Section Headers: (描述各个节的信息，如名称、大小、地址)
  .text:  可执行机器码
  .rodata: 只读数据，如字符串常量、const 变量
  .data:  已初始化的全局变量和静态变量
  .bss:   未初始化的全局变量和静态变量
  .symtab: 符号表 (包含全局符号和本地符号)
  .strtab: 字符串表 (存储符号名称等字符串)
  .dynsym: 动态符号表 (包含需要在运行时链接的符号)
  .dynstr: 动态字符串表
  .rel.dyn: 数据段重定位表
  .rel.plt: PLT (Procedure Linkage Table) 重定位表

```

**每种符号的处理过程:**

1. **全局符号 (Global Symbols):** 在 `.symtab` 和 `.dynsym` 中定义，可以被其他模块引用。
   * **定义 (Definition):**  如果当前 `.so` 文件定义了一个全局符号 (例如一个函数或全局变量)，链接器会将该符号的地址记录在符号表中。
   * **引用 (Reference):** 如果当前 `.so` 文件引用了其他 `.so` 文件定义的全局符号，链接器会在运行时查找定义该符号的库，并将其地址解析到当前模块的引用处。

2. **本地符号 (Local Symbols):** 主要在 `.symtab` 中定义，作用域仅限于当前 `.so` 文件。
   * 本地符号的地址在链接时确定，动态链接器通常不需要处理本地符号的重定位。

3. **未定义符号 (Undefined Symbols):** 在 `.dynsym` 中标记，表示当前 `.so` 文件引用了其他库中定义的符号。
   * 动态链接器负责在加载依赖库时，查找这些未定义符号的定义，并完成符号解析 (Symbol Resolution)。

**符号解析过程:**

1. 当程序加载时，动态链接器会加载程序依赖的所有共享库。
2. 对于每个共享库，动态链接器会解析其动态符号表 (`.dynsym`)。
3. 如果一个 `.so` 文件中存在未定义的符号，动态链接器会在其他已加载的 `.so` 文件中查找匹配的全局符号定义。
4. 一旦找到匹配的定义，动态链接器会将未定义符号的地址更新为已定义符号的地址，这个过程称为重定位 (Relocation)。
5. 对于函数调用，通常会使用 PLT (Procedure Linkage Table) 和 GOT (Global Offset Table) 进行延迟绑定 (Lazy Binding)，即在第一次调用函数时才进行符号解析和地址绑定。

**假设输入与输出 (针对 `EXTRACT_WORDS` 宏):**

假设输入一个 `double` 类型的变量 `d`，其值为 `3.141592653589793`，并且平台是小端序。

**假设输入:**

```c
double d = 3.141592653589793;
uint32_t ix0, ix1;
```

**输出 (执行 `EXTRACT_WORDS(ix0, ix1, d)` 后):**

* `ix0`:  `0x400921fb` (高 32 位，包含符号位和部分指数及尾数)
* `ix1`:  `0x54442d18` (低 32 位，包含尾数的剩余部分)

**逻辑推理:**

`EXTRACT_WORDS` 宏会通过联合体 `ieee_double_shape_type` 将 `double` 类型的 `d` 的内存表示拆分成两个 32 位的整数。由于是小端序，低地址存储低位，高地址存储高位。因此，`d` 的低 32 位会被赋值给 `ix1`，高 32 位会被赋值给 `ix0`。具体的十六进制值取决于浮点数的 IEEE 754 表示。

**用户或编程常见的使用错误:**

1. **直接使用 `math_private.h` 中的宏:**  这个头文件是私有的，不应该被外部代码直接包含和使用。直接使用可能导致代码在不同 Android 版本或不同架构上崩溃或行为异常。
2. **错误地假设字节序:**  如果在进行跨平台开发时，错误地假设了目标平台的字节序，可能会导致浮点数的位操作结果不正确。应该使用头文件中提供的宏来处理字节序问题。
3. **不理解浮点数的内部表示:**  直接操作浮点数的位表示需要深入理解 IEEE 754 标准，包括符号位、指数和尾数的含义。不正确的操作可能导致计算错误或产生非预期的结果 (例如 NaN, 无穷大)。
4. **精度问题:**  直接操作浮点数的位表示可能会引入精度问题，尤其是在进行复杂的数值计算时。应该尽量使用标准库提供的数学函数，这些函数经过了仔细的测试和优化。
5. **误用舍入函数:**  `rnint`, `irint` 等函数有其特定的使用场景和限制。例如，`irint` 只能正确处理已经是整数的浮点数。不当使用可能导致结果错误。

**Android Framework 或 NDK 如何到达这里 (调试线索):**

1. **Android Framework 调用:**  例如，`android.util.MathUtils.sin()` 方法最终会调用到 Java Native Interface (JNI) 层。
2. **JNI 调用:**  JNI 层会将 Java 的 `double` 类型参数传递给对应的 native 函数。
3. **NDK 代码 (如果使用):**  如果开发者使用了 NDK，他们的 C/C++ 代码可能会直接调用 `<math.h>` 中声明的 `sin()` 函数。
4. **Bionic libc 的 `sin()` 实现:**  无论是 Framework 还是 NDK 调用，最终都会链接到 Bionic libc 的 `libm.so` 中的 `sin()` 函数实现。
5. **libm 内部实现:**  `libm.so` 中的 `sin()` 函数实现 (例如在 `bionic/libm/upstream-freebsd/lib/msun/src/s_sin.c` 中) 可能会调用更底层的 kernel 函数，例如 `__ieee754_rem_pio2` 和 `__kernel_sin`。
6. **`math_private.h` 的使用:**  在这些底层 kernel 函数的实现中，会包含 `math_private.h` 头文件，并使用其中定义的宏来操作浮点数的内部表示，进行参数规约、特殊值处理等操作。

**调试线索:**

* **使用 GDB 调试 native 代码:**  可以在 NDK 代码中设置断点，逐步跟踪 `sin()` 函数的调用过程，查看参数值和中间结果。
* **查看 Bionic libc 源代码:**  可以查看 `bionic/libm` 目录下的源代码，了解 `sin()` 函数的具体实现。
* **打印日志:**  在 native 代码中打印关键变量的值，以便分析计算过程。
* **使用性能分析工具:**  例如 Simpleperf，可以分析程序的性能瓶颈，了解哪些数学函数被频繁调用。
* **关注浮点数异常:**  可以使用 `fenv.h` 中提供的函数来检查和处理浮点数异常，例如溢出、下溢、除零等。

总而言之，`bionic/libm/upstream-freebsd/lib/msun/src/math_private.handroid/math_private.h` 是 Android 数学库 libm 的一个内部基础头文件，它定义了用于高效、平台相关的浮点数操作的宏和类型，为 libm 中各种数学函数的实现提供了必要的支持。开发者通常不需要直接使用它，但理解其功能有助于深入理解 Android 数学库的工作原理。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/math_private.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 */

#ifndef _MATH_PRIVATE_H_
#define	_MATH_PRIVATE_H_

#include <sys/types.h>
#include <machine/endian.h>

/*
 * The original fdlibm code used statements like:
 *	n0 = ((*(int*)&one)>>29)^1;		* index of high word *
 *	ix0 = *(n0+(int*)&x);			* high word of x *
 *	ix1 = *((1-n0)+(int*)&x);		* low word of x *
 * to dig two 32 bit words out of the 64 bit IEEE floating point
 * value.  That is non-ANSI, and, moreover, the gcc instruction
 * scheduler gets it wrong.  We instead use the following macros.
 * Unlike the original code, we determine the endianness at compile
 * time, not at run time; I don't see much benefit to selecting
 * endianness at run time.
 */

/*
 * A union which permits us to convert between a double and two 32 bit
 * ints.
 */

#ifdef __arm__
#if defined(__VFP_FP__) || defined(__ARM_EABI__)
#define	IEEE_WORD_ORDER	BYTE_ORDER
#else
#define	IEEE_WORD_ORDER	BIG_ENDIAN
#endif
#else /* __arm__ */
#define	IEEE_WORD_ORDER	BYTE_ORDER
#endif

/* A union which permits us to convert between a long double and
   four 32 bit ints.  */

#if IEEE_WORD_ORDER == BIG_ENDIAN

typedef union
{
  long double value;
  struct {
    u_int32_t mswhi;
    u_int32_t mswlo;
    u_int32_t lswhi;
    u_int32_t lswlo;
  } parts32;
  struct {
    u_int64_t msw;
    u_int64_t lsw;
  } parts64;
} ieee_quad_shape_type;

#endif

#if IEEE_WORD_ORDER == LITTLE_ENDIAN

typedef union
{
  long double value;
  struct {
    u_int32_t lswlo;
    u_int32_t lswhi;
    u_int32_t mswlo;
    u_int32_t mswhi;
  } parts32;
  struct {
    u_int64_t lsw;
    u_int64_t msw;
  } parts64;
} ieee_quad_shape_type;

#endif

#if IEEE_WORD_ORDER == BIG_ENDIAN

typedef union
{
  double value;
  struct
  {
    u_int32_t msw;
    u_int32_t lsw;
  } parts;
  struct
  {
    u_int64_t w;
  } xparts;
} ieee_double_shape_type;

#endif

#if IEEE_WORD_ORDER == LITTLE_ENDIAN

typedef union
{
  double value;
  struct
  {
    u_int32_t lsw;
    u_int32_t msw;
  } parts;
  struct
  {
    u_int64_t w;
  } xparts;
} ieee_double_shape_type;

#endif

/* Get two 32 bit ints from a double.  */

#define EXTRACT_WORDS(ix0,ix1,d)				\
do {								\
  ieee_double_shape_type ew_u;					\
  ew_u.value = (d);						\
  (ix0) = ew_u.parts.msw;					\
  (ix1) = ew_u.parts.lsw;					\
} while (0)

/* Get a 64-bit int from a double. */
#define EXTRACT_WORD64(ix,d)					\
do {								\
  ieee_double_shape_type ew_u;					\
  ew_u.value = (d);						\
  (ix) = ew_u.xparts.w;						\
} while (0)

/* Get the more significant 32 bit int from a double.  */

#define GET_HIGH_WORD(i,d)					\
do {								\
  ieee_double_shape_type gh_u;					\
  gh_u.value = (d);						\
  (i) = gh_u.parts.msw;						\
} while (0)

/* Get the less significant 32 bit int from a double.  */

#define GET_LOW_WORD(i,d)					\
do {								\
  ieee_double_shape_type gl_u;					\
  gl_u.value = (d);						\
  (i) = gl_u.parts.lsw;						\
} while (0)

/* Set a double from two 32 bit ints.  */

#define INSERT_WORDS(d,ix0,ix1)					\
do {								\
  ieee_double_shape_type iw_u;					\
  iw_u.parts.msw = (ix0);					\
  iw_u.parts.lsw = (ix1);					\
  (d) = iw_u.value;						\
} while (0)

/* Set a double from a 64-bit int. */
#define INSERT_WORD64(d,ix)					\
do {								\
  ieee_double_shape_type iw_u;					\
  iw_u.xparts.w = (ix);						\
  (d) = iw_u.value;						\
} while (0)

/* Set the more significant 32 bits of a double from an int.  */

#define SET_HIGH_WORD(d,v)					\
do {								\
  ieee_double_shape_type sh_u;					\
  sh_u.value = (d);						\
  sh_u.parts.msw = (v);						\
  (d) = sh_u.value;						\
} while (0)

/* Set the less significant 32 bits of a double from an int.  */

#define SET_LOW_WORD(d,v)					\
do {								\
  ieee_double_shape_type sl_u;					\
  sl_u.value = (d);						\
  sl_u.parts.lsw = (v);						\
  (d) = sl_u.value;						\
} while (0)

/*
 * A union which permits us to convert between a float and a 32 bit
 * int.
 */

typedef union
{
  float value;
  /* FIXME: Assumes 32 bit int.  */
  unsigned int word;
} ieee_float_shape_type;

/* Get a 32 bit int from a float.  */

#define GET_FLOAT_WORD(i,d)					\
do {								\
  ieee_float_shape_type gf_u;					\
  gf_u.value = (d);						\
  (i) = gf_u.word;						\
} while (0)

/* Set a float from a 32 bit int.  */

#define SET_FLOAT_WORD(d,i)					\
do {								\
  ieee_float_shape_type sf_u;					\
  sf_u.word = (i);						\
  (d) = sf_u.value;						\
} while (0)

/*
 * Get expsign and mantissa as 16 bit and 64 bit ints from an 80 bit long
 * double.
 */

#define	EXTRACT_LDBL80_WORDS(ix0,ix1,d)				\
do {								\
  union IEEEl2bits ew_u;					\
  ew_u.e = (d);							\
  (ix0) = ew_u.xbits.expsign;					\
  (ix1) = ew_u.xbits.man;					\
} while (0)

/*
 * Get expsign and mantissa as one 16 bit and two 64 bit ints from a 128 bit
 * long double.
 */

#define	EXTRACT_LDBL128_WORDS(ix0,ix1,ix2,d)			\
do {								\
  union IEEEl2bits ew_u;					\
  ew_u.e = (d);							\
  (ix0) = ew_u.xbits.expsign;					\
  (ix1) = ew_u.xbits.manh;					\
  (ix2) = ew_u.xbits.manl;					\
} while (0)

/* Get expsign as a 16 bit int from a long double.  */

#define	GET_LDBL_EXPSIGN(i,d)					\
do {								\
  union IEEEl2bits ge_u;					\
  ge_u.e = (d);							\
  (i) = ge_u.xbits.expsign;					\
} while (0)

/*
 * Set an 80 bit long double from a 16 bit int expsign and a 64 bit int
 * mantissa.
 */

#define	INSERT_LDBL80_WORDS(d,ix0,ix1)				\
do {								\
  union IEEEl2bits iw_u;					\
  iw_u.xbits.expsign = (ix0);					\
  iw_u.xbits.man = (ix1);					\
  (d) = iw_u.e;							\
} while (0)

/*
 * Set a 128 bit long double from a 16 bit int expsign and two 64 bit ints
 * comprising the mantissa.
 */

#define	INSERT_LDBL128_WORDS(d,ix0,ix1,ix2)			\
do {								\
  union IEEEl2bits iw_u;					\
  iw_u.xbits.expsign = (ix0);					\
  iw_u.xbits.manh = (ix1);					\
  iw_u.xbits.manl = (ix2);					\
  (d) = iw_u.e;							\
} while (0)

/* Set expsign of a long double from a 16 bit int.  */

#define	SET_LDBL_EXPSIGN(d,v)					\
do {								\
  union IEEEl2bits se_u;					\
  se_u.e = (d);							\
  se_u.xbits.expsign = (v);					\
  (d) = se_u.e;							\
} while (0)

#ifdef __i386__
/* Long double constants are broken on i386. */
#define	LD80C(m, ex, v) {						\
	.xbits.man = __CONCAT(m, ULL),					\
	.xbits.expsign = (0x3fff + (ex)) | ((v) < 0 ? 0x8000 : 0),	\
}
#else
/* The above works on non-i386 too, but we use this to check v. */
#define	LD80C(m, ex, v)	{ .e = (v), }
#endif

#ifdef FLT_EVAL_METHOD
/*
 * Attempt to get strict C99 semantics for assignment with non-C99 compilers.
 */
#if FLT_EVAL_METHOD == 0 || __GNUC__ == 0
#define	STRICT_ASSIGN(type, lval, rval)	((lval) = (rval))
#else
#define	STRICT_ASSIGN(type, lval, rval) do {	\
	volatile type __lval;			\
						\
	if (sizeof(type) >= sizeof(long double))	\
		(lval) = (rval);		\
	else {					\
		__lval = (rval);		\
		(lval) = __lval;		\
	}					\
} while (0)
#endif
#endif /* FLT_EVAL_METHOD */

/* Support switching the mode to FP_PE if necessary. */
#if defined(__i386__) && !defined(NO_FPSETPREC)
#define	ENTERI() ENTERIT(long double)
#define	ENTERIT(returntype)			\
	returntype __retval;			\
	fp_prec_t __oprec;			\
						\
	if ((__oprec = fpgetprec()) != FP_PE)	\
		fpsetprec(FP_PE)
#define	RETURNI(x) do {				\
	__retval = (x);				\
	if (__oprec != FP_PE)			\
		fpsetprec(__oprec);		\
	RETURNF(__retval);			\
} while (0)
#define	ENTERV()				\
	fp_prec_t __oprec;			\
						\
	if ((__oprec = fpgetprec()) != FP_PE)	\
		fpsetprec(FP_PE)
#define	RETURNV() do {				\
	if (__oprec != FP_PE)			\
		fpsetprec(__oprec);		\
	return;			\
} while (0)
#else
#define	ENTERI()
#define	ENTERIT(x)
#define	RETURNI(x)	RETURNF(x)
#define	ENTERV()
#define	RETURNV()	return
#endif

/* Default return statement if hack*_t() is not used. */
#define      RETURNF(v)      return (v)

/*
 * 2sum gives the same result as 2sumF without requiring |a| >= |b| or
 * a == 0, but is slower.
 */
#define	_2sum(a, b) do {	\
	__typeof(a) __s, __w;	\
				\
	__w = (a) + (b);	\
	__s = __w - (a);	\
	(b) = ((a) - (__w - __s)) + ((b) - __s); \
	(a) = __w;		\
} while (0)

/*
 * 2sumF algorithm.
 *
 * "Normalize" the terms in the infinite-precision expression a + b for
 * the sum of 2 floating point values so that b is as small as possible
 * relative to 'a'.  (The resulting 'a' is the value of the expression in
 * the same precision as 'a' and the resulting b is the rounding error.)
 * |a| must be >= |b| or 0, b's type must be no larger than 'a's type, and
 * exponent overflow or underflow must not occur.  This uses a Theorem of
 * Dekker (1971).  See Knuth (1981) 4.2.2 Theorem C.  The name "TwoSum"
 * is apparently due to Skewchuk (1997).
 *
 * For this to always work, assignment of a + b to 'a' must not retain any
 * extra precision in a + b.  This is required by C standards but broken
 * in many compilers.  The brokenness cannot be worked around using
 * STRICT_ASSIGN() like we do elsewhere, since the efficiency of this
 * algorithm would be destroyed by non-null strict assignments.  (The
 * compilers are correct to be broken -- the efficiency of all floating
 * point code calculations would be destroyed similarly if they forced the
 * conversions.)
 *
 * Fortunately, a case that works well can usually be arranged by building
 * any extra precision into the type of 'a' -- 'a' should have type float_t,
 * double_t or long double.  b's type should be no larger than 'a's type.
 * Callers should use these types with scopes as large as possible, to
 * reduce their own extra-precision and efficiency problems.  In
 * particular, they shouldn't convert back and forth just to call here.
 */
#ifdef DEBUG
#define	_2sumF(a, b) do {				\
	__typeof(a) __w;				\
	volatile __typeof(a) __ia, __ib, __r, __vw;	\
							\
	__ia = (a);					\
	__ib = (b);					\
	assert(__ia == 0 || fabsl(__ia) >= fabsl(__ib));	\
							\
	__w = (a) + (b);				\
	(b) = ((a) - __w) + (b);			\
	(a) = __w;					\
							\
	/* The next 2 assertions are weak if (a) is already long double. */ \
	assert((long double)__ia + __ib == (long double)(a) + (b));	\
	__vw = __ia + __ib;				\
	__r = __ia - __vw;				\
	__r += __ib;					\
	assert(__vw == (a) && __r == (b));		\
} while (0)
#else /* !DEBUG */
#define	_2sumF(a, b) do {	\
	__typeof(a) __w;	\
				\
	__w = (a) + (b);	\
	(b) = ((a) - __w) + (b); \
	(a) = __w;		\
} while (0)
#endif /* DEBUG */

/*
 * Set x += c, where x is represented in extra precision as a + b.
 * x must be sufficiently normalized and sufficiently larger than c,
 * and the result is then sufficiently normalized.
 *
 * The details of ordering are that |a| must be >= |c| (so that (a, c)
 * can be normalized without extra work to swap 'a' with c).  The details of
 * the normalization are that b must be small relative to the normalized 'a'.
 * Normalization of (a, c) makes the normalized c tiny relative to the
 * normalized a, so b remains small relative to 'a' in the result.  However,
 * b need not ever be tiny relative to 'a'.  For example, b might be about
 * 2**20 times smaller than 'a' to give about 20 extra bits of precision.
 * That is usually enough, and adding c (which by normalization is about
 * 2**53 times smaller than a) cannot change b significantly.  However,
 * cancellation of 'a' with c in normalization of (a, c) may reduce 'a'
 * significantly relative to b.  The caller must ensure that significant
 * cancellation doesn't occur, either by having c of the same sign as 'a',
 * or by having |c| a few percent smaller than |a|.  Pre-normalization of
 * (a, b) may help.
 *
 * This is a variant of an algorithm of Kahan (see Knuth (1981) 4.2.2
 * exercise 19).  We gain considerable efficiency by requiring the terms to
 * be sufficiently normalized and sufficiently increasing.
 */
#define	_3sumF(a, b, c) do {	\
	__typeof(a) __tmp;	\
				\
	__tmp = (c);		\
	_2sumF(__tmp, (a));	\
	(b) += (a);		\
	(a) = __tmp;		\
} while (0)

/*
 * Common routine to process the arguments to nan(), nanf(), and nanl().
 */
void _scan_nan(uint32_t *__words, int __num_words, const char *__s);

/*
 * Mix 0, 1 or 2 NaNs.  First add 0 to each arg.  This normally just turns
 * signaling NaNs into quiet NaNs by setting a quiet bit.  We do this
 * because we want to never return a signaling NaN, and also because we
 * don't want the quiet bit to affect the result.  Then mix the converted
 * args using the specified operation.
 *
 * When one arg is NaN, the result is typically that arg quieted.  When both
 * args are NaNs, the result is typically the quietening of the arg whose
 * mantissa is largest after quietening.  When neither arg is NaN, the
 * result may be NaN because it is indeterminate, or finite for subsequent
 * construction of a NaN as the indeterminate 0.0L/0.0L.
 *
 * Technical complications: the result in bits after rounding to the final
 * precision might depend on the runtime precision and/or on compiler
 * optimizations, especially when different register sets are used for
 * different precisions.  Try to make the result not depend on at least the
 * runtime precision by always doing the main mixing step in long double
 * precision.  Try to reduce dependencies on optimizations by adding the
 * the 0's in different precisions (unless everything is in long double
 * precision).
 */
#define	nan_mix(x, y)		(nan_mix_op((x), (y), +))
#define	nan_mix_op(x, y, op)	(((x) + 0.0L) op ((y) + 0))

#ifdef _COMPLEX_H

/*
 * C99 specifies that complex numbers have the same representation as
 * an array of two elements, where the first element is the real part
 * and the second element is the imaginary part.
 */
typedef union {
	float complex f;
	float a[2];
} float_complex;
typedef union {
	double complex f;
	double a[2];
} double_complex;
typedef union {
	long double complex f;
	long double a[2];
} long_double_complex;
#define	REALPART(z)	((z).a[0])
#define	IMAGPART(z)	((z).a[1])

/*
 * Inline functions that can be used to construct complex values.
 *
 * The C99 standard intends x+I*y to be used for this, but x+I*y is
 * currently unusable in general since gcc introduces many overflow,
 * underflow, sign and efficiency bugs by rewriting I*y as
 * (0.0+I)*(y+0.0*I) and laboriously computing the full complex product.
 * In particular, I*Inf is corrupted to NaN+I*Inf, and I*-0 is corrupted
 * to -0.0+I*0.0.
 *
 * The C11 standard introduced the macros CMPLX(), CMPLXF() and CMPLXL()
 * to construct complex values.  Compilers that conform to the C99
 * standard require the following functions to avoid the above issues.
 */

#ifndef CMPLXF
static __inline float complex
CMPLXF(float x, float y)
{
	float_complex z;

	REALPART(z) = x;
	IMAGPART(z) = y;
	return (z.f);
}
#endif

#ifndef CMPLX
static __inline double complex
CMPLX(double x, double y)
{
	double_complex z;

	REALPART(z) = x;
	IMAGPART(z) = y;
	return (z.f);
}
#endif

#ifndef CMPLXL
static __inline long double complex
CMPLXL(long double x, long double y)
{
	long_double_complex z;

	REALPART(z) = x;
	IMAGPART(z) = y;
	return (z.f);
}
#endif

#endif /* _COMPLEX_H */
 
/*
 * The rnint() family rounds to the nearest integer for a restricted range
 * range of args (up to about 2**MANT_DIG).  We assume that the current
 * rounding mode is FE_TONEAREST so that this can be done efficiently.
 * Extra precision causes more problems in practice, and we only centralize
 * this here to reduce those problems, and have not solved the efficiency
 * problems.  The exp2() family uses a more delicate version of this that
 * requires extracting bits from the intermediate value, so it is not
 * centralized here and should copy any solution of the efficiency problems.
 */

static inline double
rnint(__double_t x)
{
	/*
	 * This casts to double to kill any extra precision.  This depends
	 * on the cast being applied to a double_t to avoid compiler bugs
	 * (this is a cleaner version of STRICT_ASSIGN()).  This is
	 * inefficient if there actually is extra precision, but is hard
	 * to improve on.  We use double_t in the API to minimise conversions
	 * for just calling here.  Note that we cannot easily change the
	 * magic number to the one that works directly with double_t, since
	 * the rounding precision is variable at runtime on x86 so the
	 * magic number would need to be variable.  Assuming that the
	 * rounding precision is always the default is too fragile.  This
	 * and many other complications will move when the default is
	 * changed to FP_PE.
	 */
	return ((double)(x + 0x1.8p52) - 0x1.8p52);
}

static inline float
rnintf(__float_t x)
{
	/*
	 * As for rnint(), except we could just call that to handle the
	 * extra precision case, usually without losing efficiency.
	 */
	return ((float)(x + 0x1.8p23F) - 0x1.8p23F);
}

#ifdef LDBL_MANT_DIG
/*
 * The complications for extra precision are smaller for rnintl() since it
 * can safely assume that the rounding precision has been increased from
 * its default to FP_PE on x86.  We don't exploit that here to get small
 * optimizations from limiting the range to double.  We just need it for
 * the magic number to work with long doubles.  ld128 callers should use
 * rnint() instead of this if possible.  ld80 callers should prefer
 * rnintl() since for amd64 this avoids swapping the register set, while
 * for i386 it makes no difference (assuming FP_PE), and for other arches
 * it makes little difference.
 */
static inline long double
rnintl(long double x)
{
	return (x + __CONCAT(0x1.8p, LDBL_MANT_DIG) / 2 -
	    __CONCAT(0x1.8p, LDBL_MANT_DIG) / 2);
}
#endif /* LDBL_MANT_DIG */

/*
 * irint() and i64rint() give the same result as casting to their integer
 * return type provided their arg is a floating point integer.  They can
 * sometimes be more efficient because no rounding is required.
 */
#if defined(amd64) || defined(__i386__)
#define	irint(x)						\
    (sizeof(x) == sizeof(float) &&				\
    sizeof(__float_t) == sizeof(long double) ? irintf(x) :	\
    sizeof(x) == sizeof(double) &&				\
    sizeof(__double_t) == sizeof(long double) ? irintd(x) :	\
    sizeof(x) == sizeof(long double) ? irintl(x) : (int)(x))
#else
#define	irint(x)	((int)(x))
#endif

#define	i64rint(x)	((int64_t)(x))	/* only needed for ld128 so not opt. */

#if defined(__i386__)
static __inline int
irintf(float x)
{
	int n;

	__asm("fistl %0" : "=m" (n) : "t" (x));
	return (n);
}

static __inline int
irintd(double x)
{
	int n;

	__asm("fistl %0" : "=m" (n) : "t" (x));
	return (n);
}
#endif

#if defined(__amd64__) || defined(__i386__)
static __inline int
irintl(long double x)
{
	int n;

	__asm("fistl %0" : "=m" (n) : "t" (x));
	return (n);
}
#endif

/*
 * The following are fast floor macros for 0 <= |x| < 0x1p(N-1), where
 * N is the precision of the type of x. These macros are used in the
 * half-cycle trignometric functions (e.g., sinpi(x)).
 */
#define	FFLOORF(x, j0, ix) do {			\
	(j0) = (((ix) >> 23) & 0xff) - 0x7f;	\
	(ix) &= ~(0x007fffff >> (j0));		\
	SET_FLOAT_WORD((x), (ix));		\
} while (0)

#define	FFLOOR(x, j0, ix, lx) do {				\
	(j0) = (((ix) >> 20) & 0x7ff) - 0x3ff;			\
	if ((j0) < 20) {					\
		(ix) &= ~(0x000fffff >> (j0));			\
		(lx) = 0;					\
	} else {						\
		(lx) &= ~((uint32_t)0xffffffff >> ((j0) - 20));	\
	}							\
	INSERT_WORDS((x), (ix), (lx));				\
} while (0)

#define	FFLOORL80(x, j0, ix, lx) do {			\
	j0 = ix - 0x3fff + 1;				\
	if ((j0) < 32) {				\
		(lx) = ((lx) >> 32) << 32;		\
		(lx) &= ~((((lx) << 32)-1) >> (j0));	\
	} else {					\
		uint64_t _m;				\
		_m = (uint64_t)-1 >> (j0);		\
		if ((lx) & _m) (lx) &= ~_m;		\
	}						\
	INSERT_LDBL80_WORDS((x), (ix), (lx));		\
} while (0)

#define FFLOORL128(x, ai, ar) do {			\
	union IEEEl2bits u;				\
	uint64_t m;					\
	int e;						\
	u.e = (x);					\
	e = u.bits.exp - 16383;				\
	if (e < 48) {					\
		m = ((1llu << 49) - 1) >> (e + 1);	\
		u.bits.manh &= ~m;			\
		u.bits.manl = 0;			\
	} else {					\
		m = (uint64_t)-1 >> (e - 48);		\
		u.bits.manl &= ~m;			\
	}						\
	(ai) = u.e;					\
	(ar) = (x) - (ai);				\
} while (0)

#ifdef DEBUG
#if defined(__amd64__) || defined(__i386__)
#define	breakpoint()	asm("int $3")
#else
#include <signal.h>

#define	breakpoint()	raise(SIGTRAP)
#endif
#endif

#ifdef STRUCT_RETURN
#define	RETURNSP(rp) do {		\
	if (!(rp)->lo_set)		\
		RETURNF((rp)->hi);	\
	RETURNF((rp)->hi + (rp)->lo);	\
} while (0)
#define	RETURNSPI(rp) do {		\
	if (!(rp)->lo_set)		\
		RETURNI((rp)->hi);	\
	RETURNI((rp)->hi + (rp)->lo);	\
} while (0)
#endif

#define	SUM2P(x, y) ({			\
	const __typeof (x) __x = (x);	\
	const __typeof (y) __y = (y);	\
	__x + __y;			\
})

/* fdlibm kernel function */
int	__kernel_rem_pio2(double*,double*,int,int,int);

/* double precision kernel functions */
#ifndef INLINE_REM_PIO2
int	__ieee754_rem_pio2(double,double*);
#endif
double	__kernel_sin(double,double,int);
double	__kernel_cos(double,double);
double	__kernel_tan(double,double,int);
double	__ldexp_exp(double,int);
#ifdef _COMPLEX_H
double complex __ldexp_cexp(double complex,int);
#endif

/* float precision kernel functions */
#ifndef INLINE_REM_PIO2F
int	__ieee754_rem_pio2f(float,double*);
#endif
#ifndef INLINE_KERNEL_SINDF
float	__kernel_sindf(double);
#endif
#ifndef INLINE_KERNEL_COSDF
float	__kernel_cosdf(double);
#endif
#ifndef INLINE_KERNEL_TANDF
float	__kernel_tandf(double,int);
#endif
float	__ldexp_expf(float,int);
#ifdef _COMPLEX_H
float complex __ldexp_cexpf(float complex,int);
#endif

/* long double precision kernel functions */
long double __kernel_sinl(long double, long double, int);
long double __kernel_cosl(long double, long double);
long double __kernel_tanl(long double, long double, int);

#endif /* !_MATH_PRIVATE_H_ */

"""

```