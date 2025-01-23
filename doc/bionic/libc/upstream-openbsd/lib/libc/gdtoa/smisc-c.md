Response:
Let's break down the thought process for analyzing this C code snippet.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of the `smisc.c` file within Android's `bionic` library, particularly its relation to Android, libc functions, dynamic linking, common usage errors, and how to debug it. The decomposed instructions emphasize detail and examples.

**2. High-Level Overview of the Code:**

A quick skim of the code reveals several functions operating on a custom `Bigint` data structure. The function names (`s2b`, `ratio`, `match`, `copybits`, `any_on`) hint at their purposes:

*   `s2b`: String to Bigint conversion.
*   `ratio`: Calculates the ratio of two Bigints as doubles.
*   `match`: String matching (likely for parsing).
*   `copybits`: Copies bits from a Bigint to a ULong array.
*   `any_on`: Checks if any of the lower `k` bits in a Bigint are set.

The `#include "gdtoaimp.h"` suggests this code is part of a larger library related to converting between strings and floating-point numbers (gdtoa likely stands for "general decimal to ASCII"). The copyright notice confirms it's originally from David M. Gay, used in OpenBSD, and integrated into Android.

**3. Detailed Analysis of Each Function:**

This is the core of the analysis. For each function, the thought process would be:

*   **Purpose:** What does this function *do*? (Based on the name, parameters, and internal logic).
*   **Implementation Details:** How does it achieve its purpose?  Walk through the code step by step. Consider:
    *   Data structures used (`Bigint`). Note any specific fields (e.g., `x`, `wds`).
    *   Algorithms employed (e.g., multiplication and addition in `s2b`).
    *   Bitwise operations (shifting, masking).
    *   Conditional logic and loops.
*   **Relationship to Android/libc:** Is this function directly exposed in the Android NDK or part of the standard C library? If not directly exposed, where might it be used internally?  The `gdtoa` context is key here - it's used for `strtod`, `atof`, etc.
*   **Dynamic Linking (if applicable):**  Does this function itself involve dynamic linking? In this particular file, the core logic is within the functions. However, *the library this file belongs to* (`libc`) is a shared object, so it *is* subject to dynamic linking. The functions within it are resolved at runtime.
*   **Assumptions/Input-Output:**  What are typical inputs? What output can be expected for given inputs?  Think of simple test cases.
*   **Common Errors:**  What could go wrong when using this function (or the functions that depend on it)?  Consider things like:
    *   Invalid input formats (for `s2b`).
    *   Memory allocation failures.
    *   Precision issues (in `ratio`).
*   **Android Framework/NDK Path:** How does the Android system *reach* this code?  Start from a user-level action (e.g., parsing a string) and trace down through the layers (Android Framework, NDK, libc).
*   **Frida Hooking:**  How can we observe the execution of this function using Frida?  What are the key parameters to log?

**Example of Detailed Analysis for `s2b`:**

1. **Purpose:** Convert a string representation of a number to a `Bigint`.
2. **Implementation:**
    *   Allocate a `Bigint` based on the number of digits.
    *   Initialize it with the first few digits.
    *   Iterate through the remaining digits, multiplying the current `Bigint` by 10 and adding the new digit.
3. **Android/libc:** Used internally by functions like `strtod` to handle large numbers or numbers with high precision. Not directly exposed in the NDK.
4. **Dynamic Linking:** The `s2b` function itself is part of `libc.so`. When a program calls `strtod`, the dynamic linker resolves the call to the `strtod` implementation in `libc.so`, which may in turn call `s2b`.
5. **Assumptions/Input-Output:**
    *   Input: String `s`, start and end digit indices, initial value `y9`.
    *   Output: Pointer to a `Bigint`.
    *   Example: `s = "12345"`, `nd0 = 0`, `nd = 5`, `y9 = 12`. Output: `Bigint` representing 12345.
6. **Common Errors:**
    *   Invalid characters in the input string.
    *   Memory allocation failure (returning `NULL`).
7. **Android Framework/NDK Path:**
    *   Java code calls `Double.parseDouble("12345")`.
    *   This calls the native method `parseDouble` in `libjavacrypto.so` (as an example where `strtod` might be used internally).
    *   `libjavacrypto.so` calls `strtod` from `libc.so`.
    *   `strtod` (within `libc.so`) might use `s2b` to handle the conversion.
8. **Frida Hooking:** Hook `s2b`, log the input string `s`, and the output `Bigint` pointer.

**4. Dynamic Linking Explanation:**

This requires understanding how shared libraries work in Android. Key points:

*   `libc.so` is a central shared library.
*   When an executable or shared library needs a function from `libc.so`, the dynamic linker resolves the symbol at load time or runtime.
*   The SO layout involves sections like `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), and the symbol table.
*   The linking process involves looking up symbols in the dependency libraries.

**5. Frida Hooking Examples:**

This involves knowing the basics of Frida: attaching to a process, finding function addresses, and replacing/intercepting function calls. The examples should focus on logging input arguments and return values.

**6. Structuring the Output:**

The final output should be organized and easy to understand. Using headings, bullet points, and clear explanations is crucial. The examples should be concise and illustrative. Pay attention to the decomposed instructions and ensure each point is addressed.

**Self-Correction/Refinement during the process:**

*   **Initial Focus:**  Might initially focus too much on the `Bigint` structure without fully realizing the context of `gdtoa`. Need to adjust to understand the broader purpose.
*   **Dynamic Linking Depth:** Could get bogged down in the intricacies of the dynamic linker. Need to strike a balance between explanation and conciseness. Focus on the essential aspects relevant to this code.
*   **Android Framework Path:**  Finding the *exact* path can be tricky. Provide a plausible example rather than trying to be exhaustively precise, as internal implementation details can change. Focus on illustrating the general flow.
*   **Frida Syntax:**  Need to ensure the Frida examples are syntactically correct and demonstrate the intended hooking action.

By following this structured thought process, and constantly refining the analysis, it's possible to generate a comprehensive and accurate response to the given request.
好的，让我们详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/gdtoa/smisc.c` 这个文件。

**文件功能概述：**

`smisc.c` 文件是 Android Bionic C 库中 `gdtoa` (general decimal to ASCII) 组件的一部分。`gdtoa` 库主要负责将十进制浮点数转换为字符串表示形式，以及将字符串表示形式转换为浮点数。`smisc.c`  包含了 `gdtoa` 库中使用的一些辅助函数（miscellaneous functions）。

**具体功能分解：**

1. **`Bigint *s2b(CONST char *s, int nd0, int nd, ULong y9, int dplen)`:**
    *   **功能：** 将字符串 `s` 的一部分转换为一个 `Bigint` (大整数) 结构。`Bigint` 结构用于存储任意精度的整数，这对于处理非常大或非常小的浮点数的指数部分和有效数字至关重要。
    *   **实现：**
        *   首先根据数字的位数 `nd` 和机器字长 (`Pack_32` 或 `Pack_16`) 分配 `Bigint` 结构体的内存。
        *   将初始的 `y9` 值放入 `Bigint` 的低位。
        *   然后，遍历字符串 `s` 中从 `nd0` 到 `nd` 的数字字符，依次将每个数字字符转换为整数，并通过 `multadd` 函数将该数字添加到 `Bigint` 中。`multadd` 函数执行 `Bigint = Bigint * 10 + digit` 的操作。
    *   **与 Android 的关系：** `strtod`, `atof` 等将字符串转换为 `double` 或 `float` 的标准 C 库函数内部会使用 `gdtoa` 库。当需要处理的数字位数超出标准浮点类型的精度时，`gdtoa` 会使用 `Bigint` 来进行高精度计算。
    *   **举例说明：** 假设你要将字符串 "12345678901234567890" 转换为 `double` 类型。由于这个数字非常大，标准 `double` 类型可能无法精确表示。`strtod` 内部可能会调用 `gdtoa`，而 `gdtoa` 会使用 `s2b` 将字符串转换为 `Bigint` 进行处理。
    *   **假设输入与输出：**
        *   输入： `s = "12345"`, `nd0 = 0`, `nd = 5`, `y9 = 0`, `dplen = 0`
        *   输出： 指向一个 `Bigint` 结构的指针，该结构表示整数 12345。
    *   **常见使用错误：**  程序员通常不会直接调用 `s2b`，它是 `gdtoa` 内部使用的。但如果错误地将非数字字符传递给 `s`，则会导致逻辑错误，因为代码会尝试将字符转换为数字。

2. **`double ratio(Bigint *a, Bigint *b)`:**
    *   **功能：** 计算两个 `Bigint` `a` 和 `b` 的比值，结果以 `double` 类型返回。
    *   **实现：**
        *   使用 `b2d` 函数将 `Bigint` `a` 和 `b` 转换为 `double` 类型，并获取相应的指数 `ka` 和 `kb`。`b2d` 函数负责将 `Bigint` 转换为最接近的 `double` 值。
        *   计算两个 `double` 值的比值 `dval(&da) / dval(&db)`。
        *   根据 `Bigint` 的位数差异调整结果的指数，以尽量保证精度。`ULbits*(a->wds - b->wds)` 计算了两个 `Bigint` 位数的差异对指数的影响。
        *   针对不同的平台（例如 IBM），指数调整的方式可能略有不同。
    *   **与 Android 的关系：** 在 `gdtoa` 内部，可能需要计算两个 `Bigint` 的比例，例如在将一个高精度的小数转换为字符串时，可能需要比较有效数字和指数。
    *   **举例说明：** 假设你有一个 `Bigint` 表示 100，另一个 `Bigint` 表示 10。`ratio` 函数会返回 10.0。
    *   **假设输入与输出：**
        *   输入： `a` 指向表示 100 的 `Bigint`， `b` 指向表示 10 的 `Bigint`。
        *   输出： `10.0`
    *   **常见使用错误：** 精度损失是使用 `double` 表示 `Bigint` 比值时可能遇到的问题。由于 `double` 的精度有限，某些 `Bigint` 的比值可能无法精确表示。

3. **`int match(CONST char **sp, char *t)` (仅在 `INFNAN_CHECK` 定义时存在):**
    *   **功能：**  在字符串 `*sp` 中从当前位置开始，匹配字符串 `t`（忽略大小写）。如果匹配成功，则更新 `*sp` 指向匹配部分之后的位置。
    *   **实现：**
        *   遍历字符串 `t`，逐个字符与 `*sp` 指向的字符串进行比较。
        *   在比较时，将 `*sp` 中的字符转换为小写，以实现大小写不敏感匹配。
        *   如果所有字符都匹配，则返回 1，并将 `*sp` 指向匹配部分的下一个字符。否则返回 0。
    *   **与 Android 的关系：**  这个函数可能用于解析表示特殊浮点数值（如 NaN 或 Infinity）的字符串。
    *   **举例说明：** 假设 `*sp` 指向字符串 "InfinityTest"，`t` 是 "infinity"。调用 `match(&sp, "infinity")` 将会匹配成功，`sp` 将指向 "Test" 的 'T'。
    *   **假设输入与输出：**
        *   输入： `*sp` 指向 "nan(stuff)more"， `t` 为 "nan"。
        *   输出： 返回 1， `*sp` 指向 "(stuff)more" 的 '('。
    *   **常见使用错误：**  如果 `*sp` 指向的字符串过短，会导致读取越界。

4. **`void copybits(ULong *c, int n, Bigint *b)`:**
    *   **功能：** 将 `Bigint` `b` 的位复制到 `ULong` 数组 `c` 中，复制 `n` 位。
    *   **实现：**
        *   计算 `ULong` 数组 `c` 的大小。
        *   遍历 `Bigint` `b` 的内部数组 `x`，将每个 `ULong` 值复制到 `c` 数组的相应位置。
        *   根据 `Pack_32` 或 `Pack_16` 的定义，处理 `Bigint` 中字的存储方式。
        *   如果 `c` 数组的剩余空间大于 `Bigint` 的实际位数，则将剩余的 `ULong` 元素设置为 0。
    *   **与 Android 的关系：** 在 `gdtoa` 内部，可能需要将 `Bigint` 的二进制表示形式提取出来，用于构建浮点数的内部表示。
    *   **举例说明：** 假设 `b` 表示整数 10 (二进制 1010)，`n` 为 32。`copybits` 会将 `b` 的二进制位复制到 `c` 数组的第一个元素中，`c[0]` 的低 4 位将是 `1010`。
    *   **假设输入与输出：**
        *   输入： `c` 指向一个足够大的 `ULong` 数组， `n = 64`, `b` 指向表示数字 0xFFFFFFFFFFFFFFFF 的 `Bigint`。
        *   输出： `c` 数组的前两个元素将被设置为 0xFFFFFFFF。
    *   **常见使用错误：** 如果 `c` 数组的大小不足以容纳 `n` 位，会导致写越界。

5. **`ULong any_on(Bigint *b, int k)`:**
    *   **功能：** 检查 `Bigint` `b` 的低 `k` 位中是否有任何位被设置为 1。
    *   **实现：**
        *   计算 `k` 位对应于 `Bigint` 内部数组 `x` 的哪些元素。
        *   如果 `k` 大于 `Bigint` 的实际位数，则只检查 `Bigint` 的所有有效位。
        *   如果 `k` 小于 `Bigint` 的总位数，则需要对最后一个可能包含有效位的字进行位移和掩码操作，以只检查低 `k` 位。
        *   遍历 `Bigint` 内部数组 `x` 中需要检查的元素，如果找到任何非零元素，则返回 1。否则返回 0。
    *   **与 Android 的关系：** 在 `gdtoa` 内部，可能需要检查 `Bigint` 的某些低位是否为零，以进行舍入或其他操作。
    *   **举例说明：** 假设 `b` 表示整数 6 (二进制 110)，`k` 为 3。`any_on` 会返回 1，因为低 3 位中有 1。如果 `k` 为 1，则返回 0。
    *   **假设输入与输出：**
        *   输入： `b` 指向表示 8 (二进制 1000) 的 `Bigint`, `k = 3`。
        *   输出： `0`
        *   输入： `b` 指向表示 8 (二进制 1000) 的 `Bigint`, `k = 4`。
        *   输出： `1`
    *   **常见使用错误：**  传递负数的 `k` 值会导致未定义的行为。

**与 Android 功能的关系和举例：**

正如上面每个函数的功能描述中所述，这些函数是 `gdtoa` 库内部使用的。`gdtoa` 库在 Android 中主要被以下标准 C 库函数间接使用：

*   **字符串到浮点数转换：** `strtod`, `strtof`, `strtold`, `atof` 等函数在将字符串转换为 `double`, `float`, `long double` 时，如果遇到需要高精度处理的数字，会使用 `gdtoa` 库。
*   **浮点数到字符串转换：** `sprintf`, `snprintf` 等函数中使用 `%f`, `%e`, `%g` 等格式化说明符打印浮点数时，如果需要将浮点数转换为字符串，也会使用 `gdtoa` 库。

**Android Framework 或 NDK 如何到达这里：**

1. **用户代码 (Java 或 C/C++)：**
    *   **Java:** 用户可能在 Java 代码中调用 `Double.parseDouble("1.23456789012345e+20")` 或 `String.format("%.10f", 3.1415926535)` 等方法。
    *   **C/C++ (NDK):** 用户可能在 NDK 代码中调用 `strtod("1.23456789012345e+20", NULL)` 或 `sprintf(buf, "%.10f", 3.1415926535)` 等函数。

2. **NDK 库 (对于 C/C++) 或 Android Framework (对于 Java)：**
    *   **NDK:**  `strtod` 和 `sprintf` 等函数是标准 C 库函数，它们的实现位于 `libc.so` 中。
    *   **Android Framework:** `Double.parseDouble` 等 Java 方法最终会调用底层的 native 方法，这些 native 方法通常位于 ART (Android Runtime) 或一些基础库中，它们会调用 `libc.so` 中的 C 库函数。

3. **Bionic libc (`libc.so`)：**
    *   当调用 `strtod` 或 `sprintf` 等函数时，`libc.so` 中相应的实现会被执行。
    *   对于需要高精度处理的浮点数转换，`libc.so` 会调用 `gdtoa` 库中的函数，例如 `s2b` 将字符串转换为 `Bigint`，然后进行进一步处理。

**Dynamic Linker 的功能和 SO 布局样本：**

*   **功能：** Android 的动态链接器 (通常是 `linker64` 或 `linker`) 负责在程序启动或运行时加载和链接共享库 (`.so` 文件)。它解析可执行文件和共享库的依赖关系，将符号引用解析到内存中的实际地址，并执行必要的重定位操作。
*   **SO 布局样本 (`libc.so`)：**

```
libc.so:
  .text         # 包含可执行代码
    ...
    strtod:      # strtod 函数的代码
      ...
      callq s2b  # strtod 内部调用 s2b
      ...
    sprintf:     # sprintf 函数的代码
      ...
      callq gdtoa_e  # sprintf 内部调用 gdtoa 的函数
      ...
  .rodata       # 包含只读数据（例如字符串常量）
    ...
  .data         # 包含已初始化的全局变量
    ...
  .bss          # 包含未初始化的全局变量
    ...
  .dynsym       # 动态符号表，包含导出的符号（例如 strtod, sprintf）
    ...
    s2b
    ratio
    ...
  .dynstr       # 动态字符串表，包含符号名
    ...
    s2b
    ratio
    ...
  .plt          # 程序链接表，用于延迟绑定
    ...
  .got          # 全局偏移表，用于存储外部符号的地址
    ...
```

*   **链接的处理过程：**
    1. 当一个程序（例如一个 APK 中的 native 库）调用 `strtod` 时，编译器会生成对 `strtod` 的符号引用。
    2. 在程序加载时，动态链接器会查找 `libc.so` 中导出的 `strtod` 符号。
    3. 动态链接器会将 `strtod` 的实际地址填入程序的 GOT (Global Offset Table) 中。
    4. 程序执行到调用 `strtod` 的地方时，会通过 GOT 跳转到 `libc.so` 中 `strtod` 的代码。
    5. 同样，当 `strtod` 内部需要调用 `s2b` 时，链接器会在 `libc.so` 内部解析 `s2b` 的地址。由于 `s2b` 是 `libc.so` 内部的函数，这个过程通常发生在 `libc.so` 加载时。

**Frida Hook 示例调试步骤：**

假设你想 hook `s2b` 函数，查看其输入参数：

```python
import frida
import sys

package_name = "your.target.app"  # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "s2b"), {
    onEnter: function(args) {
        console.log("[*] Called s2b");
        console.log("[*] s (string pointer): " + ptr(args[0]));
        console.log("[*] nd0 (int): " + args[1].toInt32());
        console.log("[*] nd (int): " + args[2].toInt32());
        console.log("[*] y9 (ULong): " + args[3]); // 注意 ULong 的处理
        console.log("[*] dplen (int): " + args[4].toInt32());
        try {
            console.log("[*] s string value: " + Memory.readUtf8String(args[0]));
        } catch (e) {
            console.log("[*] Error reading string: " + e);
        }
    },
    onLeave: function(retval) {
        console.log("[*] s2b returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释：**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 设备上的目标 Android 应用进程。
2. **`Module.findExportByName("libc.so", "s2b")`:** 在 `libc.so` 模块中查找 `s2b` 函数的地址。
3. **`Interceptor.attach(...)`:**  拦截 `s2b` 函数的调用。
4. **`onEnter: function(args)`:**  在 `s2b` 函数被调用之前执行。`args` 数组包含了传递给 `s2b` 的参数。
5. **`ptr(args[0])`:**  获取第一个参数（字符串指针）的值。
6. **`args[1].toInt32()`:** 获取第二个参数（整数）的值。
7. **`Memory.readUtf8String(args[0])`:** 尝试读取字符串指针指向的字符串内容。
8. **`onLeave: function(retval)`:** 在 `s2b` 函数返回之后执行，`retval` 是返回值。

**运行步骤：**

1. 确保你的 Android 设备已连接并通过 adb 可访问。
2. 安装 Frida： `pip install frida frida-tools`
3. 运行目标 Android 应用。
4. 将上面的 Python 代码保存为 `hook_s2b.py` (或其他名字)。
5. 将 `your.target.app` 替换为实际的应用包名。
6. 运行 Frida 脚本： `python hook_s2b.py`
7. 在你的 Android 应用中执行一些可能触发 `strtod` 或其他相关函数的操作（例如，解析一个包含大数字的字符串）。
8. Frida 会在终端输出 `s2b` 函数被调用时的参数值。

这个 Frida 示例可以帮助你观察 `s2b` 函数的调用情况，了解传递给它的参数，从而更好地理解其在程序执行过程中的作用。你可以根据需要修改脚本来 hook 其他函数或提取更多信息。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/smisc.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
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

 Bigint *
s2b
#ifdef KR_headers
	(s, nd0, nd, y9, dplen) CONST char *s; int dplen, nd0, nd; ULong y9;
#else
	(CONST char *s, int nd0, int nd, ULong y9, int dplen)
#endif
{
	Bigint *b;
	int i, k;
	Long x, y;

	x = (nd + 8) / 9;
	for(k = 0, y = 1; x > y; y <<= 1, k++) ;
#ifdef Pack_32
	b = Balloc(k);
	if (b == NULL)
		return (NULL);
	b->x[0] = y9;
	b->wds = 1;
#else
	b = Balloc(k+1);
	if (b == NULL)
		return (NULL);
	b->x[0] = y9 & 0xffff;
	b->wds = (b->x[1] = y9 >> 16) ? 2 : 1;
#endif

	i = 9;
	if (9 < nd0) {
		s += 9;
		do {
			b = multadd(b, 10, *s++ - '0');
			if (b == NULL)
				return (NULL);
			} while(++i < nd0);
		s += dplen;
		}
	else
		s += dplen + 9;
	for(; i < nd; i++) {
		b = multadd(b, 10, *s++ - '0');
		if (b == NULL)
			return (NULL);
		}
	return b;
	}

 double
ratio
#ifdef KR_headers
	(a, b) Bigint *a, *b;
#else
	(Bigint *a, Bigint *b)
#endif
{
	U da, db;
	int k, ka, kb;

	dval(&da) = b2d(a, &ka);
	dval(&db) = b2d(b, &kb);
	k = ka - kb + ULbits*(a->wds - b->wds);
#ifdef IBM
	if (k > 0) {
		word0(&da) += (k >> 2)*Exp_msk1;
		if (k &= 3)
			dval(&da) *= 1 << k;
		}
	else {
		k = -k;
		word0(&db) += (k >> 2)*Exp_msk1;
		if (k &= 3)
			dval(&db) *= 1 << k;
		}
#else
	if (k > 0)
		word0(&da) += k*Exp_msk1;
	else {
		k = -k;
		word0(&db) += k*Exp_msk1;
		}
#endif
	return dval(&da) / dval(&db);
	}

#ifdef INFNAN_CHECK

 int
match
#ifdef KR_headers
	(sp, t) char **sp, *t;
#else
	(CONST char **sp, char *t)
#endif
{
	int c, d;
	CONST char *s = *sp;

	while( (d = *t++) !=0) {
		if ((c = *++s) >= 'A' && c <= 'Z')
			c += 'a' - 'A';
		if (c != d)
			return 0;
		}
	*sp = s + 1;
	return 1;
	}
#endif /* INFNAN_CHECK */

 void
#ifdef KR_headers
copybits(c, n, b) ULong *c; int n; Bigint *b;
#else
copybits(ULong *c, int n, Bigint *b)
#endif
{
	ULong *ce, *x, *xe;
#ifdef Pack_16
	int nw, nw1;
#endif

	ce = c + ((n-1) >> kshift) + 1;
	x = b->x;
#ifdef Pack_32
	xe = x + b->wds;
	while(x < xe)
		*c++ = *x++;
#else
	nw = b->wds;
	nw1 = nw & 1;
	for(xe = x + (nw - nw1); x < xe; x += 2)
		Storeinc(c, x[1], x[0]);
	if (nw1)
		*c++ = *x;
#endif
	while(c < ce)
		*c++ = 0;
	}

 ULong
#ifdef KR_headers
any_on(b, k) Bigint *b; int k;
#else
any_on(Bigint *b, int k)
#endif
{
	int n, nwds;
	ULong *x, *x0, x1, x2;

	x = b->x;
	nwds = b->wds;
	n = k >> kshift;
	if (n > nwds)
		n = nwds;
	else if (n < nwds && (k &= kmask)) {
		x1 = x2 = x[n];
		x1 >>= k;
		x1 <<= k;
		if (x1 != x2)
			return 1;
		}
	x0 = x;
	x += n;
	while(x > x0)
		if (*--x)
			return 1;
	return 0;
	}
```