Response:
Let's break down the thought process for analyzing the `dtoa.c` file.

1. **Understanding the Goal:** The primary goal is to understand the functionality of this C file, particularly its role in converting double-precision floating-point numbers to strings. We need to identify its features, how it interacts with Android, explain the libc functions it uses, discuss dynamic linking if applicable, address potential user errors, and illustrate how Android framework/NDK reaches this code.

2. **Initial Code Scan and Identification of Core Functionality:**  Reading the header comments immediately reveals the core purpose: converting a `double` to an ASCII string. The author is identified, and the inspiration from the Steele & White paper is mentioned. The `dtoa` function signature and its parameters (double, mode, ndigits, decpt, sign, rve) are key. The various `mode` values suggest different formatting options.

3. **High-Level Feature Extraction:** Based on the comments and initial scan, we can list the major functionalities:
    * Conversion of `double` to string.
    * Handling different formatting modes (shortest representation, fixed precision, etc.).
    * Handling special cases like infinity and NaN.
    * Potentially using multiple-precision arithmetic for accuracy.
    * Optimization for small integers.
    * Considerations for rounding modes (though this part relies on other system settings).

4. **Android Relevance (Initial Thoughts):** Since this is in `bionic/libc`, it's a fundamental part of Android's C library. Any Android application that needs to display or serialize floating-point numbers will likely indirectly use this code. Examples include UI elements showing sensor data, network communication protocols, and mathematical calculations.

5. **Detailed Code Examination (Iterative Process):**  Now, we go through the code section by section, focusing on key aspects:
    * **Sign Handling:** The beginning of the `dtoa` function clearly handles the sign of the input `double`.
    * **Special Cases (Infinity/NaN):** The code checks for and handles these cases, setting `*decpt` to 9999 and returning appropriate strings.
    * **Zero Handling:**  A specific check for zero is present.
    * **Core Conversion Logic:** The call to `d2b` (double to bigint) is a critical step. This suggests the use of arbitrary-precision arithmetic. We need to understand what `d2b` likely does (converts the double to a big integer representation).
    * **Logarithm Approximation:** The code uses an approximation for `log10(d)` to estimate the exponent. This is an optimization to avoid costly iterations.
    * **Quick Path for Small Integers:** The code checks if the number is a "small" integer and uses simpler floating-point arithmetic in that case. This is a performance optimization.
    * **Multiple-Precision Arithmetic:**  The code uses `Bigint` data structures and functions like `i2b`, `pow5mult`, `mult`, `lshift`, `quorem`, `diff`, and `multadd`. This confirms the use of arbitrary-precision arithmetic for accurate conversion. We need to infer the purpose of these functions based on their names.
    * **Rounding Logic:**  The code includes logic for rounding the last digit based on the chosen mode and potential rounding modes.
    * **Memory Management:** The use of `rv_alloc` and `Bfree` indicates memory allocation and deallocation within the function.

6. **libc Function Analysis:** As we identify libc functions like `freedtoa`, `fegetround`, and potentially others called by the helper functions (like memory allocation), we need to explain their standard C library purpose. For instance, `fegetround` is used to get the current floating-point rounding mode. `freedtoa` suggests some internal caching or management of results.

7. **Dynamic Linking:**  Since this is a `.c` file within `bionic/libc`, it will be compiled into a shared library (likely `libc.so`). We need to create a sample `libc.so` layout (simplified) and explain the linking process. The dynamic linker (`ld-android.so`) will resolve symbols at runtime. We need to show how a call to a standard C function from an app gets directed to the implementation within `libc.so`.

8. **User Errors:** Consider common mistakes programmers might make when dealing with number-to-string conversions. Examples include assuming a fixed number of decimal places, not handling potential buffer overflows (though `dtoa` manages its own memory), and misunderstandings about different formatting modes.

9. **Android Framework/NDK Path:** Trace how a request to format a floating-point number might originate. Start from a high-level framework component (e.g., `TextView`), move down to the NDK (if native code is involved), and eventually to the `libc` functions. A Frida hook example can demonstrate how to intercept the `dtoa` call.

10. **Logical Inference and Assumptions:**  When explaining functions like `d2b`, `pow5mult`, etc., we make reasonable inferences based on their names and the context of the code. We assume they perform the expected arithmetic operations on the `Bigint` data structure.

11. **Structuring the Answer:** Finally, organize the information logically with clear headings and examples. Use formatting (like code blocks) to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial assumption about direct usage:** While apps might not directly call `dtoa`, they will use functions that *internally* rely on it (like `sprintf`, `std::to_string` in C++, etc.). Adjust the explanation accordingly.
* **Deep dive into `d2b`:**  Realize that fully explaining `d2b`'s implementation is beyond the scope of analyzing `dtoa.c`. Focus on its purpose and input/output.
* **Frida hook details:** Provide a concrete Frida script that demonstrates how to hook the function and log arguments/return values.
* **Clarifying `mode` values:**  Ensure each `mode` is explained clearly with its effect on the output format.
* **Emphasizing optimizations:** Highlight the sections of code that are clearly performance optimizations (small integer handling, logarithm approximation).

By following this structured approach, combining code analysis, domain knowledge (floating-point representation, C library functions, Android architecture), and logical reasoning, we can generate a comprehensive and accurate explanation of the `dtoa.c` file.
好的，我们来详细分析 `bionic/libc/upstream-openbsd/lib/libc/gdtoa/dtoa.c` 这个文件的功能及其在 Android Bionic 中的作用。

**功能概述**

`dtoa.c` 文件的核心功能是将一个 `double` 类型的浮点数转换为 ASCII 字符串表示。它提供了多种转换模式，可以生成不同格式的字符串，类似于 `ecvt` 和 `fcvt` 等函数的功能，但做了优化和改进。

**详细功能分解**

1. **浮点数到字符串的转换:**  这是最主要的功能。`dtoa` 函数接收一个 `double` 类型的浮点数 `d0`，并根据指定的模式将其转换为字符串。

2. **多种转换模式 (mode):**  `dtoa` 函数通过 `mode` 参数支持多种转换模式，以满足不同的格式需求：
   - **模式 0:** 生成最短的字符串，该字符串读回并四舍五入后能得到原始的 `double` 值。
   - **模式 1:** 类似于模式 0，但使用 Steele & White 的停止规则。在 IEEE 754 算术中，模式 0 可能会生成 "1e23"，而模式 1 可能会生成 "9.999999999999999e22"。
   - **模式 2:** 生成 `max(1, ndigits)` 个有效数字的字符串，类似于 `ecvt` 的结果，但会省略尾部的零。
   - **模式 3:** 生成小数点后 `ndigits` 位的字符串，类似于 `fcvt` 的结果，但会省略尾部的零，并且 `ndigits` 可以为负数。
   - **模式 4, 5:** 分别类似于模式 2 和 3，但在四舍五入模式下，会使用模式 0 的测试，以便可能返回一个更短且能四舍五入到 `d` 的字符串。在启用 `-DHonor_FLT_ROUNDS` 并使用 IEEE 算术进行编译时，如果 `FLT_ROUNDS != 1`，模式 4 和 5 的行为与模式 2 和 3 相同。
   - **模式 6-9:** 用于调试，类似于模式 2-5，但不尝试快速浮点数估算。

3. **处理特殊值 (Infinity 和 NaN):**  `dtoa` 函数能正确处理正负无穷大 (Infinity) 和非数字 (NaN) 的情况。当输入是这些特殊值时，`*decpt` 会被设置为 9999，并返回相应的字符串 "Infinity" 或 "NaN"。

4. **处理零:**  当输入为零时，`*decpt` 会被设置为 1，并返回字符串 "0"。

5. **精度控制 (ndigits):**  `ndigits` 参数允许用户指定所需的精度。其含义取决于所选的 `mode`。

6. **指数位置 (decpt):**  `*decpt` 指针用于返回小数点的位置。对于普通数字，它表示第一个数字前的位数（正数表示小数点在数字之后，负数表示小数点前有零）。对于 Infinity 和 NaN，它被设置为 9999。

7. **符号 (sign):**  `*sign` 指针用于返回数字的符号，0 表示正数，1 表示负数。

8. **字符串尾部指针 (rve):**  如果 `rve` 不为空，则它会被设置为指向返回字符串的末尾。

9. **内部优化:**
   - **数值估计:**  使用数值高估来确定 `k = floor(log10(d))`，并使用 `O(log2(k))` 次乘法来缩放相关量，而不是 `O(k)` 次乘法，提高了效率。
   - **延迟生成数字:**  对于某些模式（如 `ecvt` 和 `fcvt`），并不严格从左到右生成数字，而是在位数较少的情况下进行计算，并在需要时进行进位。
   - **处理 1e23 的情况:**  针对舍入到最近的规则进行了优化，例如，模式 0 可以将 1e23 渲染为 "1e23"，而不是 "9.999999999999999e22"。
   - **去除 2 的幂的公因子:**  从相关量中去除 2 的幂的公因子，简化计算。
   - **处理小整数:**  对于小于 1e16 的浮点整数，使用浮点运算而不是多精度整数运算。
   - **快速路径处理:**  当请求的位数较少时（少于 15 位），首先尝试使用浮点运算，只有在无法保证浮点计算结果正确舍入时才使用多精度整数运算。

**与 Android 功能的关系**

`dtoa.c` 是 Android Bionic C 库的一部分，因此它对 Android 系统的许多功能至关重要。任何需要在 Android 上将 `double` 类型转换为字符串的操作都可能间接使用到 `dtoa`。

**举例说明:**

- **Java `Double.toString()`:**  当 Java 代码调用 `Double.toString()` 方法时，Android Runtime (ART) 或 Dalvik 会调用底层的 native 方法，最终可能会调用到 `dtoa` 来完成转换。
- **`printf` 系列函数:**  C/C++ 代码中使用 `printf`、`sprintf` 等函数格式化输出 `double` 类型时，`libc.so` 中的实现会使用 `dtoa` 来将浮点数转换为字符串。
- **NDK 开发:**  通过 Android NDK 开发的 native 代码，在进行浮点数到字符串的转换时，也会用到 `dtoa`。例如，使用 `std::to_string` 或 C 风格的格式化输出。
- **图形界面显示:**  Android 应用中需要在 UI 上显示浮点数，例如传感器数据、计算结果等，底层的转换过程很可能涉及到 `dtoa`。

**libc 函数的功能实现**

`dtoa.c` 自身也使用了一些其他的 libc 函数（或其内部实现）：

- **`freedtoa(dtoa_result)`:**  这个函数可能是用于释放之前 `dtoa` 调用分配的内存。在 `dtoa` 函数的开头，会检查 `dtoa_result` 是否存在，如果存在则释放它，这表明可能存在某种缓存机制或线程局部存储。
- **`nrv_alloc(const char *s, char **rve, size_t len)`:**  这是一个用于分配内存并复制字符串的函数。它可能是在 `gdtoa` 库内部定义的，用于为转换后的字符串分配空间。
- **`d2b(double d, int *eptr, int *bits)`:**  这是一个关键的辅助函数，用于将 `double` 类型的浮点数 `d` 转换为一个高精度整数表示（Bigint）。`*eptr` 返回指数，`*bits` 返回有效位数。其实现细节通常在 `gdtoa` 库的其他文件中（例如 `d2b.c`）。
- **`i2b(Long i)`:**  将一个 `Long` 类型的整数转换为 `Bigint` 表示。
- **`pow5mult(Bigint *b, int k)`:**  将 `Bigint` `b` 乘以 5 的 `k` 次幂。
- **`mult(Bigint *a, Bigint *b)`:**  将两个 `Bigint` 相乘。
- **`multadd(Bigint *b, int m, int carry)`:**  将 `Bigint` `b` 乘以整数 `m` 并加上进位 `carry`。
- **`lshift(Bigint *b, int k)`:**  将 `Bigint` `b` 左移 `k` 位（相当于乘以 2 的 `k` 次幂）。
- **`quorem(Bigint *a, Bigint *b)`:**  计算两个 `Bigint` 的商，并修改 `a` 为余数。
- **`diff(Bigint *a, Bigint *b)`:**  计算两个 `Bigint` 的差。
- **`Balloc(int k)`:**  为 `Bigint` 结构分配内存。
- **`Bfree(Bigint *v)`:**  释放 `Bigint` 结构占用的内存。
- **`Bcopy(Bigint *to, Bigint *from)`:**  复制 `Bigint` 结构。
- **浮点数相关的宏和类型:**  例如 `U` 联合体用于访问 `double` 的位表示，`word0`, `word1` 用于访问 `double` 的两个字，`Sign_bit`, `Exp_mask`, `Frac_mask1` 等用于位操作。
- **`fegetround()`:** (在定义了 `Honor_FLT_ROUNDS` 的情况下) 用于获取当前的浮点数舍入模式。
- **`clear_inexact()` 和 与 `get_inexact()` 相关的操作:** (在定义了 `SET_INEXACT` 的情况下) 用于处理浮点数运算的精度标志。

**dynamic linker 的功能**

`dtoa.c` 本身的代码不直接涉及 dynamic linker 的操作。但是，作为 `libc.so` 的一部分，它的代码在运行时会被 dynamic linker 加载和链接。

**so 布局样本:**

```
libc.so:
    ...
    .text:
        dtoa:  # dtoa 函数的代码
            ...
        nrv_alloc: # nrv_alloc 函数的代码
            ...
        d2b:     # d2b 函数的代码
            ...
        # 其他 libc 函数的代码
    .data:
        # 全局变量和数据
    .dynamic:
        # 动态链接信息，例如依赖库、符号表等
    .symtab:
        # 符号表，包含 dtoa 等函数的符号
    .strtab:
        # 字符串表，包含符号名称等字符串
    ...
```

**链接的处理过程:**

1. **编译链接时:** 当编译一个使用 `dtoa` 的程序时，编译器会生成对 `dtoa` 函数的未定义引用。链接器会将这些未定义引用标记为需要在运行时解析。
2. **程序加载时:** 当程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被内核调用。
3. **加载依赖库:** Dynamic linker 会加载程序依赖的共享库，包括 `libc.so`。
4. **符号解析:** Dynamic linker 会遍历加载的共享库的符号表 (`.symtab`)，查找程序中未定义的符号，例如 `dtoa`。
5. **重定位:** 一旦找到 `dtoa` 的符号定义，dynamic linker 会更新程序代码中的引用地址，使其指向 `libc.so` 中 `dtoa` 函数的实际地址。这个过程称为重定位。
6. **执行:** 完成链接后，程序就可以正确地调用 `dtoa` 函数了。

**逻辑推理、假设输入与输出**

假设我们调用 `dtoa` 函数，并指定不同的模式：

**假设输入:**

```c
double d = 123.456789;
int decpt, sign;
char *rve;
char buffer[100];
```

**示例调用与输出:**

- **`dtoa(d, 0, 0, &decpt, &sign, &rve)`:**  (最短表示)
  - 输出 (假设)：`"123.456789"` (实际输出可能因浮点数精度而略有不同)
  - `decpt`: 3
  - `sign`: 0

- **`dtoa(d, 2, 5, &decpt, &sign, &rve)`:** (5 个有效数字)
  - 输出：`"123.46"`
  - `decpt`: 3
  - `sign`: 0

- **`dtoa(d, 3, 2, &decpt, &sign, &rve)`:** (小数点后 2 位)
  - 输出：`"123.46"`
  - `decpt`: 3
  - `sign`: 0

- **`dtoa(1000.0, 0, 0, &decpt, &sign, &rve)`:**
  - 输出：`"1000"`
  - `decpt`: 4
  - `sign`: 0

- **`dtoa(0.00123, 0, 0, &decpt, &sign, &rve)`:**
  - 输出：`"0.00123"`
  - `decpt`: -2
  - `sign`: 0

**用户或编程常见的使用错误**

1. **缓冲区溢出 (虽然 `dtoa` 自身会分配内存，但如果用户自行处理输出):** 如果用户假设 `dtoa` 返回的字符串长度有一个固定的上限，并使用固定大小的缓冲区来存储结果，可能会导致缓冲区溢出。但实际上 `dtoa` 内部会分配足够的内存。
2. **误解 `ndigits` 的含义:**  `ndigits` 的含义取决于 `mode`，用户可能会混淆不同模式下 `ndigits` 的作用。例如，在模式 2 中表示有效数字，而在模式 3 中表示小数点后的位数。
3. **忽略 `decpt` 和 `sign`:**  用户可能只关注返回的字符串，而忽略了 `decpt` 和 `sign` 的值，这在某些需要精确格式化输出的场景下可能会导致问题。
4. **不理解浮点数的精度限制:**  用户可能期望 `dtoa` 能返回完全精确的十进制表示，但由于浮点数的二进制表示存在精度限制，某些十进制数无法精确表示，`dtoa` 只能返回尽可能接近的表示。
5. **在多线程环境中使用未同步的版本:**  如果 `dtoa` 的实现不是线程安全的（虽然 Bionic 的实现通常是），在多线程环境中同时调用可能会导致数据竞争。

**Android framework 或 NDK 如何到达这里**

以下是一个简化的调用链，说明 Android framework 或 NDK 如何最终调用到 `dtoa`：

**Android Framework 示例 (Java):**

1. **`TextView.setText(double value)`:**  一个 `TextView` 需要显示一个 `double` 值。
2. **`String.valueOf(double d)`:** `TextView` 内部会调用 `String.valueOf()` 将 `double` 转换为字符串。
3. **`Double.toString(double d)`:** `String.valueOf()` 最终会调用 `Double.toString()`。
4. **`native public static String FloatingDecimal.toJavaFormat(double d)`:** `Double.toString()` 是一个 native 方法，会调用 ART 或 Dalvik 中的实现。
5. **ART/Dalvik `FloatingDecimal::toJavaFormat`:**  这个 native 函数会负责将 `double` 转换为符合 Java 格式的字符串，其内部可能会使用底层的 C 库函数。
6. **`libc.so` 中的 `dtoa` 或相关函数:**  `FloatingDecimal::toJavaFormat` 的实现最终会调用到 `libc.so` 中的 `dtoa` 或类似的函数来完成转换。

**Android NDK 示例 (C++):**

1. **NDK 代码中使用 `sprintf` 或 `std::to_string`:** Native 代码需要将一个 `double` 转换为字符串。
2. **`sprintf` 的 `libc.so` 实现:**  如果使用 `sprintf`，`libc.so` 中 `sprintf` 的实现会调用底层的浮点数转换函数。
3. **`std::to_string` 的 `libstdc++.so` 实现 (或 LLVM libc++):**  如果使用 `std::to_string`，`libstdc++.so` 或 `libc++.so` 中的实现最终也会调用底层的 C 库函数来进行转换。
4. **`libc.so` 中的 `dtoa`:**  无论是 `sprintf` 还是 `std::to_string`，最终都会间接地调用到 `libc.so` 中的 `dtoa` 来执行核心的浮点数到字符串的转换。

**Frida Hook 示例调试步骤**

我们可以使用 Frida 来 hook `dtoa` 函数，观察其参数和返回值。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
    const dtoaPtr = Module.findExportByName("libc.so", "dtoa");

    if (dtoaPtr) {
        Interceptor.attach(dtoaPtr, {
            onEnter: function (args) {
                const d0 = args[0].readDouble();
                const mode = args[1].toInt32();
                const ndigits = args[2].toInt32();
                const decptPtr = args[3];
                const signPtr = args[4];
                const rvePtrPtr = args[5];

                console.log("Called dtoa:");
                console.log("  d0:", d0);
                console.log("  mode:", mode);
                console.log("  ndigits:", ndigits);
                console.log("  decptPtr:", decptPtr);
                console.log("  signPtr:", signPtr);
                console.log("  rvePtrPtr:", rvePtrPtr);
            },
            onLeave: function (retval) {
                const result = retval.readCString();
                console.log("Return value:", result);
                // 可以读取和打印 decpt 和 sign 的值
                // const decpt = this.context.r2.readInt(); // 假设 r2 存储 decpt
                // const sign = this.context.r3.readInt();  // 假设 r3 存储 sign
                // console.log("  decpt:", decpt);
                // console.log("  sign:", sign);
            }
        });
        console.log("Successfully hooked dtoa");
    } else {
        console.error("Failed to find dtoa in libc.so");
    }
} else {
    console.log("Frida hook example is for arm64/x64 architectures.");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 和 frida-server。
2. **运行 Frida Server:** 在 Android 设备上启动 frida-server。
3. **运行目标应用:** 启动你想要调试的 Android 应用。
4. **执行 Frida 脚本:** 在你的 PC 上，使用 Frida 命令将上述 JavaScript 脚本注入到目标应用进程中。例如：
   ```bash
   frida -U -f <your_app_package_name> -l your_script.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <your_app_package_name> -l your_script.js
   ```
5. **触发 `dtoa` 调用:** 在你的 Android 应用中执行一些操作，这些操作会导致浮点数转换为字符串，例如显示一个包含浮点数的数据。
6. **查看 Frida 输出:**  Frida 会在你的终端上输出 `dtoa` 函数被调用时的参数值和返回值。你可以观察不同的 `mode` 和输入值对输出的影响。

**注意:**  在 `onLeave` 中读取 `decpt` 和 `sign` 的值需要了解目标架构的 ABI 约定，确定这些值是通过寄存器还是内存传递的。上面的注释提供了一种可能的假设，你需要根据实际情况调整。

通过以上分析，我们可以更深入地理解 `bionic/libc/upstream-openbsd/lib/libc/gdtoa/dtoa.c` 文件的功能及其在 Android 系统中的重要作用。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/dtoa.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/****************************************************************

The author of this software is David M. Gay.

Copyright (C) 1998, 1999 by Lucent Technologies
All Rights Reserved

Permission to use, copy, modify, and distribute this software and
its documentation for any purpose and without fee is hereby
granted, provided that the above copyright notice appear in all
copies and that both that the copyright notice and this
permission notice and warranty disclaimer appear in supporting
documentation, and that the name of Lucent or any of its entities
not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

LUCENT DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
IN NO EVENT SHALL LUCENT OR ANY OF ITS ENTITIES BE LIABLE FOR ANY
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.

****************************************************************/

/* Please send bug reports to David M. Gay (dmg at acm dot org,
 * with " at " changed at "@" and " dot " changed to ".").	*/

#include "gdtoaimp.h"

/* dtoa for IEEE arithmetic (dmg): convert double to ASCII string.
 *
 * Inspired by "How to Print Floating-Point Numbers Accurately" by
 * Guy L. Steele, Jr. and Jon L. White [Proc. ACM SIGPLAN '90, pp. 112-126].
 *
 * Modifications:
 *	1. Rather than iterating, we use a simple numeric overestimate
 *	   to determine k = floor(log10(d)).  We scale relevant
 *	   quantities using O(log2(k)) rather than O(k) multiplications.
 *	2. For some modes > 2 (corresponding to ecvt and fcvt), we don't
 *	   try to generate digits strictly left to right.  Instead, we
 *	   compute with fewer bits and propagate the carry if necessary
 *	   when rounding the final digit up.  This is often faster.
 *	3. Under the assumption that input will be rounded nearest,
 *	   mode 0 renders 1e23 as 1e23 rather than 9.999999999999999e22.
 *	   That is, we allow equality in stopping tests when the
 *	   round-nearest rule will give the same floating-point value
 *	   as would satisfaction of the stopping test with strict
 *	   inequality.
 *	4. We remove common factors of powers of 2 from relevant
 *	   quantities.
 *	5. When converting floating-point integers less than 1e16,
 *	   we use floating-point arithmetic rather than resorting
 *	   to multiple-precision integers.
 *	6. When asked to produce fewer than 15 digits, we first try
 *	   to get by with floating-point arithmetic; we resort to
 *	   multiple-precision integer arithmetic only if we cannot
 *	   guarantee that the floating-point calculation has given
 *	   the correctly rounded result.  For k requested digits and
 *	   "uniformly" distributed input, the probability is
 *	   something like 10^(k-15) that we must resort to the Long
 *	   calculation.
 */

#ifdef Honor_FLT_ROUNDS
#undef Check_FLT_ROUNDS
#define Check_FLT_ROUNDS
#else
#define Rounding Flt_Rounds
#endif

 char *
dtoa
#ifdef KR_headers
	(d0, mode, ndigits, decpt, sign, rve)
	double d0; int mode, ndigits, *decpt, *sign; char **rve;
#else
	(double d0, int mode, int ndigits, int *decpt, int *sign, char **rve)
#endif
{
 /*	Arguments ndigits, decpt, sign are similar to those
	of ecvt and fcvt; trailing zeros are suppressed from
	the returned string.  If not null, *rve is set to point
	to the end of the return value.  If d is +-Infinity or NaN,
	then *decpt is set to 9999.

	mode:
		0 ==> shortest string that yields d when read in
			and rounded to nearest.
		1 ==> like 0, but with Steele & White stopping rule;
			e.g. with IEEE P754 arithmetic , mode 0 gives
			1e23 whereas mode 1 gives 9.999999999999999e22.
		2 ==> max(1,ndigits) significant digits.  This gives a
			return value similar to that of ecvt, except
			that trailing zeros are suppressed.
		3 ==> through ndigits past the decimal point.  This
			gives a return value similar to that from fcvt,
			except that trailing zeros are suppressed, and
			ndigits can be negative.
		4,5 ==> similar to 2 and 3, respectively, but (in
			round-nearest mode) with the tests of mode 0 to
			possibly return a shorter string that rounds to d.
			With IEEE arithmetic and compilation with
			-DHonor_FLT_ROUNDS, modes 4 and 5 behave the same
			as modes 2 and 3 when FLT_ROUNDS != 1.
		6-9 ==> Debugging modes similar to mode - 4:  don't try
			fast floating-point estimate (if applicable).

		Values of mode other than 0-9 are treated as mode 0.

		Sufficient space is allocated to the return value
		to hold the suppressed trailing zeros.
	*/

	int bbits, b2, b5, be, dig, i, ieps, ilim, ilim0, ilim1,
		j, j1, k, k0, k_check, leftright, m2, m5, s2, s5,
		spec_case, try_quick;
	Long L;
#ifndef Sudden_Underflow
	int denorm;
	ULong x;
#endif
	Bigint *b, *b1, *delta, *mlo, *mhi, *S;
	U d, d2, eps;
	double ds;
	char *s, *s0;
#ifdef SET_INEXACT
	int inexact, oldinexact;
#endif
#ifdef Honor_FLT_ROUNDS /*{*/
	int Rounding;
#ifdef Trust_FLT_ROUNDS /*{{ only define this if FLT_ROUNDS really works! */
	Rounding = Flt_Rounds;
#else /*}{*/
	Rounding = 1;
	switch(fegetround()) {
	  case FE_TOWARDZERO:	Rounding = 0; break;
	  case FE_UPWARD:	Rounding = 2; break;
	  case FE_DOWNWARD:	Rounding = 3;
	  }
#endif /*}}*/
#endif /*}*/

#ifndef MULTIPLE_THREADS
	if (dtoa_result) {
		freedtoa(dtoa_result);
		dtoa_result = 0;
		}
#endif
	d.d = d0;
	if (word0(&d) & Sign_bit) {
		/* set sign for everything, including 0's and NaNs */
		*sign = 1;
		word0(&d) &= ~Sign_bit;	/* clear sign bit */
		}
	else
		*sign = 0;

#if defined(IEEE_Arith) + defined(VAX)
#ifdef IEEE_Arith
	if ((word0(&d) & Exp_mask) == Exp_mask)
#else
	if (word0(&d)  == 0x8000)
#endif
		{
		/* Infinity or NaN */
		*decpt = 9999;
#ifdef IEEE_Arith
		if (!word1(&d) && !(word0(&d) & 0xfffff))
			return nrv_alloc("Infinity", rve, 8);
#endif
		return nrv_alloc("NaN", rve, 3);
		}
#endif
#ifdef IBM
	dval(&d) += 0; /* normalize */
#endif
	if (!dval(&d)) {
		*decpt = 1;
		return nrv_alloc("0", rve, 1);
		}

#ifdef SET_INEXACT
	try_quick = oldinexact = get_inexact();
	inexact = 1;
#endif
#ifdef Honor_FLT_ROUNDS
	if (Rounding >= 2) {
		if (*sign)
			Rounding = Rounding == 2 ? 0 : 2;
		else
			if (Rounding != 2)
				Rounding = 0;
		}
#endif

	b = d2b(dval(&d), &be, &bbits);
	if (b == NULL)
		return (NULL);
#ifdef Sudden_Underflow
	i = (int)(word0(&d) >> Exp_shift1 & (Exp_mask>>Exp_shift1));
#else
	if (( i = (int)(word0(&d) >> Exp_shift1 & (Exp_mask>>Exp_shift1)) )!=0) {
#endif
		dval(&d2) = dval(&d);
		word0(&d2) &= Frac_mask1;
		word0(&d2) |= Exp_11;
#ifdef IBM
		if (( j = 11 - hi0bits(word0(&d2) & Frac_mask) )!=0)
			dval(&d2) /= 1 << j;
#endif

		/* log(x)	~=~ log(1.5) + (x-1.5)/1.5
		 * log10(x)	 =  log(x) / log(10)
		 *		~=~ log(1.5)/log(10) + (x-1.5)/(1.5*log(10))
		 * log10(&d) = (i-Bias)*log(2)/log(10) + log10(&d2)
		 *
		 * This suggests computing an approximation k to log10(&d) by
		 *
		 * k = (i - Bias)*0.301029995663981
		 *	+ ( (d2-1.5)*0.289529654602168 + 0.176091259055681 );
		 *
		 * We want k to be too large rather than too small.
		 * The error in the first-order Taylor series approximation
		 * is in our favor, so we just round up the constant enough
		 * to compensate for any error in the multiplication of
		 * (i - Bias) by 0.301029995663981; since |i - Bias| <= 1077,
		 * and 1077 * 0.30103 * 2^-52 ~=~ 7.2e-14,
		 * adding 1e-13 to the constant term more than suffices.
		 * Hence we adjust the constant term to 0.1760912590558.
		 * (We could get a more accurate k by invoking log10,
		 *  but this is probably not worthwhile.)
		 */

		i -= Bias;
#ifdef IBM
		i <<= 2;
		i += j;
#endif
#ifndef Sudden_Underflow
		denorm = 0;
		}
	else {
		/* d is denormalized */

		i = bbits + be + (Bias + (P-1) - 1);
		x = i > 32  ? word0(&d) << (64 - i) | word1(&d) >> (i - 32)
			    : word1(&d) << (32 - i);
		dval(&d2) = x;
		word0(&d2) -= 31*Exp_msk1; /* adjust exponent */
		i -= (Bias + (P-1) - 1) + 1;
		denorm = 1;
		}
#endif
	ds = (dval(&d2)-1.5)*0.289529654602168 + 0.1760912590558 + i*0.301029995663981;
	k = (int)ds;
	if (ds < 0. && ds != k)
		k--;	/* want k = floor(ds) */
	k_check = 1;
	if (k >= 0 && k <= Ten_pmax) {
		if (dval(&d) < tens[k])
			k--;
		k_check = 0;
		}
	j = bbits - i - 1;
	if (j >= 0) {
		b2 = 0;
		s2 = j;
		}
	else {
		b2 = -j;
		s2 = 0;
		}
	if (k >= 0) {
		b5 = 0;
		s5 = k;
		s2 += k;
		}
	else {
		b2 -= k;
		b5 = -k;
		s5 = 0;
		}
	if (mode < 0 || mode > 9)
		mode = 0;

#ifndef SET_INEXACT
#ifdef Check_FLT_ROUNDS
	try_quick = Rounding == 1;
#else
	try_quick = 1;
#endif
#endif /*SET_INEXACT*/

	if (mode > 5) {
		mode -= 4;
		try_quick = 0;
		}
	leftright = 1;
	ilim = ilim1 = -1;	/* Values for cases 0 and 1; done here to */
				/* silence erroneous "gcc -Wall" warning. */
	switch(mode) {
		case 0:
		case 1:
			i = 18;
			ndigits = 0;
			break;
		case 2:
			leftright = 0;
			/* no break */
		case 4:
			if (ndigits <= 0)
				ndigits = 1;
			ilim = ilim1 = i = ndigits;
			break;
		case 3:
			leftright = 0;
			/* no break */
		case 5:
			i = ndigits + k + 1;
			ilim = i;
			ilim1 = i - 1;
			if (i <= 0)
				i = 1;
		}
	s = s0 = rv_alloc(i);
	if (s == NULL)
		return (NULL);

#ifdef Honor_FLT_ROUNDS
	if (mode > 1 && Rounding != 1)
		leftright = 0;
#endif

	if (ilim >= 0 && ilim <= Quick_max && try_quick) {

		/* Try to get by with floating-point arithmetic. */

		i = 0;
		dval(&d2) = dval(&d);
		k0 = k;
		ilim0 = ilim;
		ieps = 2; /* conservative */
		if (k > 0) {
			ds = tens[k&0xf];
			j = k >> 4;
			if (j & Bletch) {
				/* prevent overflows */
				j &= Bletch - 1;
				dval(&d) /= bigtens[n_bigtens-1];
				ieps++;
				}
			for(; j; j >>= 1, i++)
				if (j & 1) {
					ieps++;
					ds *= bigtens[i];
					}
			dval(&d) /= ds;
			}
		else if (( j1 = -k )!=0) {
			dval(&d) *= tens[j1 & 0xf];
			for(j = j1 >> 4; j; j >>= 1, i++)
				if (j & 1) {
					ieps++;
					dval(&d) *= bigtens[i];
					}
			}
		if (k_check && dval(&d) < 1. && ilim > 0) {
			if (ilim1 <= 0)
				goto fast_failed;
			ilim = ilim1;
			k--;
			dval(&d) *= 10.;
			ieps++;
			}
		dval(&eps) = ieps*dval(&d) + 7.;
		word0(&eps) -= (P-1)*Exp_msk1;
		if (ilim == 0) {
			S = mhi = 0;
			dval(&d) -= 5.;
			if (dval(&d) > dval(&eps))
				goto one_digit;
			if (dval(&d) < -dval(&eps))
				goto no_digits;
			goto fast_failed;
			}
#ifndef No_leftright
		if (leftright) {
			/* Use Steele & White method of only
			 * generating digits needed.
			 */
			dval(&eps) = 0.5/tens[ilim-1] - dval(&eps);
			for(i = 0;;) {
				L = dval(&d);
				dval(&d) -= L;
				*s++ = '0' + (int)L;
				if (dval(&d) < dval(&eps))
					goto ret1;
				if (1. - dval(&d) < dval(&eps))
					goto bump_up;
				if (++i >= ilim)
					break;
				dval(&eps) *= 10.;
				dval(&d) *= 10.;
				}
			}
		else {
#endif
			/* Generate ilim digits, then fix them up. */
			dval(&eps) *= tens[ilim-1];
			for(i = 1;; i++, dval(&d) *= 10.) {
				L = (Long)(dval(&d));
				if (!(dval(&d) -= L))
					ilim = i;
				*s++ = '0' + (int)L;
				if (i == ilim) {
					if (dval(&d) > 0.5 + dval(&eps))
						goto bump_up;
					else if (dval(&d) < 0.5 - dval(&eps)) {
						while(*--s == '0');
						s++;
						goto ret1;
						}
					break;
					}
				}
#ifndef No_leftright
			}
#endif
 fast_failed:
		s = s0;
		dval(&d) = dval(&d2);
		k = k0;
		ilim = ilim0;
		}

	/* Do we have a "small" integer? */

	if (be >= 0 && k <= Int_max) {
		/* Yes. */
		ds = tens[k];
		if (ndigits < 0 && ilim <= 0) {
			S = mhi = 0;
			if (ilim < 0 || dval(&d) <= 5*ds)
				goto no_digits;
			goto one_digit;
			}
		for(i = 1;; i++, dval(&d) *= 10.) {
			L = (Long)(dval(&d) / ds);
			dval(&d) -= L*ds;
#ifdef Check_FLT_ROUNDS
			/* If FLT_ROUNDS == 2, L will usually be high by 1 */
			if (dval(&d) < 0) {
				L--;
				dval(&d) += ds;
				}
#endif
			*s++ = '0' + (int)L;
			if (!dval(&d)) {
#ifdef SET_INEXACT
				inexact = 0;
#endif
				break;
				}
			if (i == ilim) {
#ifdef Honor_FLT_ROUNDS
				if (mode > 1)
				switch(Rounding) {
				  case 0: goto ret1;
				  case 2: goto bump_up;
				  }
#endif
				dval(&d) += dval(&d);
#ifdef ROUND_BIASED
				if (dval(&d) >= ds)
#else
				if (dval(&d) > ds || (dval(&d) == ds && L & 1))
#endif
					{
 bump_up:
					while(*--s == '9')
						if (s == s0) {
							k++;
							*s = '0';
							break;
							}
					++*s++;
					}
				break;
				}
			}
		goto ret1;
		}

	m2 = b2;
	m5 = b5;
	mhi = mlo = 0;
	if (leftright) {
		i =
#ifndef Sudden_Underflow
			denorm ? be + (Bias + (P-1) - 1 + 1) :
#endif
#ifdef IBM
			1 + 4*P - 3 - bbits + ((bbits + be - 1) & 3);
#else
			1 + P - bbits;
#endif
		b2 += i;
		s2 += i;
		mhi = i2b(1);
		if (mhi == NULL)
			return (NULL);
		}
	if (m2 > 0 && s2 > 0) {
		i = m2 < s2 ? m2 : s2;
		b2 -= i;
		m2 -= i;
		s2 -= i;
		}
	if (b5 > 0) {
		if (leftright) {
			if (m5 > 0) {
				mhi = pow5mult(mhi, m5);
				if (mhi == NULL)
					return (NULL);
				b1 = mult(mhi, b);
				if (b1 == NULL)
					return (NULL);
				Bfree(b);
				b = b1;
				}
			if (( j = b5 - m5 )!=0) {
				b = pow5mult(b, j);
				if (b == NULL)
					return (NULL);
				}
			}
		else {
			b = pow5mult(b, b5);
			if (b == NULL)
				return (NULL);
			}
		}
	S = i2b(1);
	if (S == NULL)
		return (NULL);
	if (s5 > 0) {
		S = pow5mult(S, s5);
		if (S == NULL)
			return (NULL);
		}

	/* Check for special case that d is a normalized power of 2. */

	spec_case = 0;
	if ((mode < 2 || leftright)
#ifdef Honor_FLT_ROUNDS
			&& Rounding == 1
#endif
				) {
		if (!word1(&d) && !(word0(&d) & Bndry_mask)
#ifndef Sudden_Underflow
		 && word0(&d) & (Exp_mask & ~Exp_msk1)
#endif
				) {
			/* The special case */
			b2 += Log2P;
			s2 += Log2P;
			spec_case = 1;
			}
		}

	/* Arrange for convenient computation of quotients:
	 * shift left if necessary so divisor has 4 leading 0 bits.
	 *
	 * Perhaps we should just compute leading 28 bits of S once
	 * and for all and pass them and a shift to quorem, so it
	 * can do shifts and ors to compute the numerator for q.
	 */
#ifdef Pack_32
	if (( i = ((s5 ? 32 - hi0bits(S->x[S->wds-1]) : 1) + s2) & 0x1f )!=0)
		i = 32 - i;
#else
	if (( i = ((s5 ? 32 - hi0bits(S->x[S->wds-1]) : 1) + s2) & 0xf )!=0)
		i = 16 - i;
#endif
	if (i > 4) {
		i -= 4;
		b2 += i;
		m2 += i;
		s2 += i;
		}
	else if (i < 4) {
		i += 28;
		b2 += i;
		m2 += i;
		s2 += i;
		}
	if (b2 > 0) {
		b = lshift(b, b2);
		if (b == NULL)
			return (NULL);
		}
	if (s2 > 0) {
		S = lshift(S, s2);
		if (S == NULL)
			return (NULL);
		}
	if (k_check) {
		if (cmp(b,S) < 0) {
			k--;
			b = multadd(b, 10, 0);	/* we botched the k estimate */
			if (b == NULL)
				return (NULL);
			if (leftright) {
				mhi = multadd(mhi, 10, 0);
				if (mhi == NULL)
					return (NULL);
				}
			ilim = ilim1;
			}
		}
	if (ilim <= 0 && (mode == 3 || mode == 5)) {
		S = multadd(S,5,0);
		if (S == NULL)
			return (NULL);
		if (ilim < 0 || cmp(b,S) <= 0) {
			/* no digits, fcvt style */
 no_digits:
			k = -1 - ndigits;
			goto ret;
			}
 one_digit:
		*s++ = '1';
		k++;
		goto ret;
		}
	if (leftright) {
		if (m2 > 0) {
			mhi = lshift(mhi, m2);
			if (mhi == NULL)
				return (NULL);
			}

		/* Compute mlo -- check for special case
		 * that d is a normalized power of 2.
		 */

		mlo = mhi;
		if (spec_case) {
			mhi = Balloc(mhi->k);
			if (mhi == NULL)
				return (NULL);
			Bcopy(mhi, mlo);
			mhi = lshift(mhi, Log2P);
			if (mhi == NULL)
				return (NULL);
			}

		for(i = 1;;i++) {
			dig = quorem(b,S) + '0';
			/* Do we yet have the shortest decimal string
			 * that will round to d?
			 */
			j = cmp(b, mlo);
			delta = diff(S, mhi);
			if (delta == NULL)
				return (NULL);
			j1 = delta->sign ? 1 : cmp(b, delta);
			Bfree(delta);
#ifndef ROUND_BIASED
			if (j1 == 0 && mode != 1 && !(word1(&d) & 1)
#ifdef Honor_FLT_ROUNDS
				&& Rounding >= 1
#endif
								   ) {
				if (dig == '9')
					goto round_9_up;
				if (j > 0)
					dig++;
#ifdef SET_INEXACT
				else if (!b->x[0] && b->wds <= 1)
					inexact = 0;
#endif
				*s++ = dig;
				goto ret;
				}
#endif
			if (j < 0 || (j == 0 && mode != 1
#ifndef ROUND_BIASED
							&& !(word1(&d) & 1)
#endif
					)) {
				if (!b->x[0] && b->wds <= 1) {
#ifdef SET_INEXACT
					inexact = 0;
#endif
					goto accept_dig;
					}
#ifdef Honor_FLT_ROUNDS
				if (mode > 1)
				 switch(Rounding) {
				  case 0: goto accept_dig;
				  case 2: goto keep_dig;
				  }
#endif /*Honor_FLT_ROUNDS*/
				if (j1 > 0) {
					b = lshift(b, 1);
					if (b == NULL)
						return (NULL);
					j1 = cmp(b, S);
#ifdef ROUND_BIASED
					if (j1 >= 0 /*)*/
#else
					if ((j1 > 0 || (j1 == 0 && dig & 1))
#endif
					&& dig++ == '9')
						goto round_9_up;
					}
 accept_dig:
				*s++ = dig;
				goto ret;
				}
			if (j1 > 0) {
#ifdef Honor_FLT_ROUNDS
				if (!Rounding)
					goto accept_dig;
#endif
				if (dig == '9') { /* possible if i == 1 */
 round_9_up:
					*s++ = '9';
					goto roundoff;
					}
				*s++ = dig + 1;
				goto ret;
				}
#ifdef Honor_FLT_ROUNDS
 keep_dig:
#endif
			*s++ = dig;
			if (i == ilim)
				break;
			b = multadd(b, 10, 0);
			if (b == NULL)
				return (NULL);
			if (mlo == mhi) {
				mlo = mhi = multadd(mhi, 10, 0);
				if (mlo == NULL)
					return (NULL);
				}
			else {
				mlo = multadd(mlo, 10, 0);
				if (mlo == NULL)
					return (NULL);
				mhi = multadd(mhi, 10, 0);
				if (mhi == NULL)
					return (NULL);
				}
			}
		}
	else
		for(i = 1;; i++) {
			*s++ = dig = quorem(b,S) + '0';
			if (!b->x[0] && b->wds <= 1) {
#ifdef SET_INEXACT
				inexact = 0;
#endif
				goto ret;
				}
			if (i >= ilim)
				break;
			b = multadd(b, 10, 0);
			if (b == NULL)
				return (NULL);
			}

	/* Round off last digit */

#ifdef Honor_FLT_ROUNDS
	switch(Rounding) {
	  case 0: goto trimzeros;
	  case 2: goto roundoff;
	  }
#endif
	b = lshift(b, 1);
	if (b == NULL)
		return (NULL);
	j = cmp(b, S);
#ifdef ROUND_BIASED
	if (j >= 0)
#else
	if (j > 0 || (j == 0 && dig & 1))
#endif
		{
 roundoff:
		while(*--s == '9')
			if (s == s0) {
				k++;
				*s++ = '1';
				goto ret;
				}
		++*s++;
		}
	else {
#ifdef Honor_FLT_ROUNDS
 trimzeros:
#endif
		while(*--s == '0');
		s++;
		}
 ret:
	Bfree(S);
	if (mhi) {
		if (mlo && mlo != mhi)
			Bfree(mlo);
		Bfree(mhi);
		}
 ret1:
#ifdef SET_INEXACT
	if (inexact) {
		if (!oldinexact) {
			word0(&d) = Exp_1 + (70 << Exp_shift);
			word1(&d) = 0;
			dval(&d) += 1.;
			}
		}
	else if (!oldinexact)
		clear_inexact();
#endif
	Bfree(b);
	*s = 0;
	*decpt = k + 1;
	if (rve)
		*rve = s;
	return s0;
	}
DEF_STRONG(dtoa);

"""

```