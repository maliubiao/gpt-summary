Response:
Let's break down the thought process for analyzing the `gethex.c` code and generating the comprehensive response.

**1. Understanding the Goal:**

The request asks for a detailed analysis of the `gethex.c` file, specifically its functionality, relation to Android, implementation details, dynamic linking aspects, error handling, usage scenarios, and how it's reached from Android. The target audience seems to be someone familiar with C and system-level programming, but potentially needing more specific knowledge about this particular function and its context within Android.

**2. Initial Code Scan and Keyword Identification:**

The first step is to read through the code and identify key elements:

* **Function Signature:** `gethex( CONST char **sp, FPI *fpi, Long *exp, Bigint **bp, int sign)` - This immediately tells us the function's input and output. It takes a string pointer (`sp`), a floating-point info structure (`fpi`), pointers for the exponent (`exp`) and a big integer (`bp`), and a sign flag. It returns an integer.
* **Includes:** `gdtoaimp.h`, `locale.h` - These headers suggest the function is related to floating-point number conversion and potentially locale-specific number formatting.
* **Data Structures:** `FPI`, `Bigint` -  Recognize these are custom structures for handling floating-point representation and large integers.
* **Key Variables:** `decpt`, `e`, `b`, `nbits`, `rounding` -  These variables hint at the core logic: decimal point handling, exponent calculation, big integer representation, precision, and rounding.
* **Magic Numbers/Constants:** `0x10`, `0x19`, `kshift`, `kmask`, `ALL_ON`, `ULbits` - These require further investigation to understand their meaning (likely related to bit manipulation and the `Bigint` structure).
* **Function Calls:** `localeconv()`, `strdup()`, `Balloc()`, `Bfree()`, `rshift()`, `lshift()`, `increment()`, `hi0bits()`, `any_on()` - These are helper functions, some standard C library functions, and some likely defined within the `gdtoa` library. Understanding their roles is crucial.
* **Return Values:** `STRTOG_Zero`, `STRTOG_Normal`, `STRTOG_Denormal`, `STRTOG_Infinite`, `STRTOG_Overflow`, `STRTOG_Underflow`, `STRTOG_NoMemory` - These enumerated values represent the outcome of the conversion process.
* **`USE_LOCALE` Preprocessor Directive:** This indicates conditional compilation based on locale support.

**3. Deconstructing the Functionality:**

Based on the keywords and code structure, we can start piecing together the function's purpose:

* **Input Parsing:** The function parses a hexadecimal floating-point number string. It handles optional `0x` prefix, digits, decimal point (or locale-specific equivalent), and an optional exponent part (`p` or `P` followed by a signed integer).
* **Big Integer Conversion:** The significant digits of the hexadecimal number are converted and stored in a `Bigint` structure to handle arbitrary precision.
* **Exponent Handling:** The function extracts and calculates the exponent, considering the decimal point's position and the explicit exponent part.
* **Normalization and Rounding:** The `Bigint` is normalized to fit within the target floating-point precision (`fpi->nbits`). Rounding is applied based on the `fpi->rounding` mode.
* **Overflow and Underflow Detection:** The function checks for exponent overflow and underflow conditions.
* **Special Cases:** It handles zero values and potential denormalized numbers.

**4. Relating to Android and libc:**

The file path `bionic/libc/upstream-openbsd/lib/libc/gdtoa/gethex.c` clearly shows this code is part of Bionic's libc, specifically a port from OpenBSD. This means it's a fundamental part of Android's C standard library.

* **Usage in `strtod`, `strtof`, `strtold`:**  The most likely scenario is that `gethex` is a helper function for the standard C library functions that convert strings to floating-point numbers (`strtod`, `strtof`, `strtold`). These functions need to handle hexadecimal floating-point input as well.

**5. Explaining libc Function Implementations:**

This requires understanding the purpose of each called function:

* **Standard C Library:**  `localeconv()`, `strdup()`, `errno`. Their standard behavior should be explained.
* **`gdtoa` Library:**  `__hexdig_init_D2A()`, `Balloc()`, `Bfree()`, `rshift()`, `lshift()`, `increment()`, `hi0bits()`, `any_on()`. These are internal helper functions for managing big integers and performing bitwise operations. Reasoning about their probable implementations (e.g., `Balloc` likely allocates a `Bigint`, `rshift` performs a right bit shift) is important even without the source code.

**6. Dynamic Linking Aspects:**

Since `gethex.c` is part of libc, it's linked dynamically.

* **SO Layout:** A basic layout of `libc.so` should be presented, showing the data section (potentially holding locale information) and the text section (containing the code for `gethex` and other libc functions).
* **Linking Process:** Describe how the dynamic linker resolves symbols (like `gethex`) when an application calls a function that uses it (e.g., `strtod`). Explain the role of the Global Offset Table (GOT) and Procedure Linkage Table (PLT).

**7. Logical Reasoning and Examples:**

Provide simple examples to illustrate the function's behavior:

* **Normal Cases:**  A simple hexadecimal number like `0x1.23p4`.
* **Edge Cases:**  Numbers with leading zeros, decimal points, exponents, and numbers that result in overflow or underflow.

**8. Common Usage Errors:**

Think about how programmers might misuse this function *indirectly* through the functions that call it (`strtod`, etc.):

* **Invalid Input Format:** Incorrect hexadecimal prefixes, invalid characters.
* **Overflow/Underflow:**  Providing numbers outside the representable range.
* **Locale Issues:**  Not being aware of locale-specific decimal separators.

**9. Android Framework/NDK Usage and Frida Hooking:**

* **Path from Framework/NDK:** Trace how a high-level framework call (e.g., parsing a floating-point value from user input) might eventually lead to a call to `strtod` in the NDK, which in turn might use `gethex`.
* **Frida Hooking:** Provide a concrete Frida example showing how to intercept the `gethex` function call, log its arguments, and potentially modify its behavior. This demonstrates how to observe the function in action.

**10. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use code blocks for code examples and diagrams where appropriate (like the SO layout). Use clear and concise language.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe `gethex` is directly used for parsing configuration files. **Correction:**  More likely it's a low-level helper for standard conversion functions.
* **Initial thought:**  Focus heavily on the bit manipulation details. **Correction:**  Balance the technical details with a higher-level understanding of the function's purpose and context.
* **Initial thought:**  Only provide one example. **Correction:**  Include multiple examples to illustrate different scenarios and edge cases.

By following these steps and iteratively refining the analysis, the comprehensive and informative response can be generated. The key is to combine code understanding with knowledge of the surrounding system (Android, libc, dynamic linking).
好的，我们来详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/gdtoa/gethex.c` 这个源代码文件。

**文件功能：**

`gethex.c` 文件的主要功能是从一个字符串中解析十六进制浮点数。它接受一个指向字符串的指针，并将解析出的浮点数的各个组成部分（尾数、指数等）存储到提供的结构体中。更具体地说，它执行以下操作：

1. **识别和跳过前导零：**  它会跳过十六进制数前面的任何零。
2. **解析尾数（mantissa）：** 它提取十六进制数字，直到遇到非十六进制字符或指数部分。
3. **处理小数点：** 它会检测并处理小数点（或者根据 `USE_LOCALE` 定义，可能是其他本地化的小数点分隔符），并相应地调整指数。
4. **解析指数部分：** 如果存在 'p' 或 'P'，则解析后续的指数值（可以带正负号）。
5. **将尾数转换为 `Bigint`：** 它使用 `Bigint` 结构体来存储任意精度的尾数。
6. **计算最终指数：** 结合小数点位置和显式指数部分计算最终的指数值。
7. **处理溢出和下溢：** 它会检查计算出的指数是否超出浮点数类型的表示范围，并设置相应的错误标志。
8. **执行舍入：** 根据 `FPI` 结构体中指定的舍入模式，对尾数进行舍入。
9. **处理非规范化数：** 如果结果是一个非常小的数，它会将其标记为非规范化数。

**与 Android 功能的关系举例：**

`gethex.c` 是 Android C 库 (Bionic libc) 的一部分。这意味着它被底层的 C/C++ 代码广泛使用，包括 Android Framework 和 NDK 开发。

**举例：**

* **`strtod`, `strtof`, `strtold` 函数：**  标准 C 库中用于将字符串转换为 `double`, `float`, `long double` 类型的函数，很可能在内部使用了 `gethex` 来处理十六进制浮点数输入。例如，如果你在 Java 代码中调用 `Double.parseDouble("0x1.ffffp10")`，Android Framework 会将其传递给底层的 C++ 代码，最终可能会调用 `strtod`，而 `strtod` 则会使用 `gethex` 来解析这个十六进制字符串。
* **NDK 开发中的浮点数解析：**  如果你在 NDK 开发中使用 C/C++ 代码，并且需要解析包含十六进制浮点数表示的字符串（例如，从配置文件或网络数据中），那么你可能会间接地使用到 `gethex`。

**libc 函数的实现细节：**

让我们详细解释一下 `gethex.c` 中使用的一些关键 libc 函数以及 `gdtoa` 库内部的函数：

1. **`localeconv()` (libc):**
   - **功能：**  获取当前 locale 的数字格式信息，例如小数点字符。
   - **实现：**  `localeconv()` 通常会访问一个内部的 locale 数据结构，该结构包含了根据当前设置的 locale 存储的格式化信息。这个数据结构可能由 `setlocale()` 函数进行更新。
   - **在 `gethex.c` 中的作用：**  用于确定当前 locale 使用的小数点字符，以便正确解析浮点数字符串。

2. **`strdup()` (libc):**
   - **功能：**  复制一个字符串到新分配的内存中。
   - **实现：**  `strdup()` 首先计算输入字符串的长度，然后使用 `malloc()` 分配足够大小的内存，并将输入字符串的内容复制到新分配的内存中，最后返回指向新字符串的指针。调用者负责使用 `free()` 释放分配的内存。
   - **在 `gethex.c` 中的作用：**  在 `USE_LOCALE` 定义且未定义 `NO_LOCALE_CACHE` 时，用于缓存 `localeconv()->decimal_point` 的值，避免每次都调用 `localeconv()`。

3. **`__hexdig_init_D2A()` (gdtoa 内部函数):**
   - **功能：**  初始化一个查找表，用于快速判断字符是否是十六进制数字，并将十六进制字符转换为其数值。
   - **实现：**  它通常会设置一个数组，索引对应 ASCII 码，数组的值表示该字符是否是十六进制数字及其数值。
   - **在 `gethex.c` 中的作用：**  在函数开始时调用，确保十六进制数字查找表已初始化。

4. **`Balloc(k)` (gdtoa 内部函数):**
   - **功能：**  分配并初始化一个 `Bigint` 结构体，用于存储大整数。`k` 参数可能与分配的字 (word) 的数量有关。
   - **实现：**  它会使用 `malloc()` 分配 `Bigint` 结构体所需的内存，并可能初始化结构体的成员，例如将所有字设置为零。
   - **在 `gethex.c` 中的作用：**  用于分配存储解析出的十六进制浮点数的尾数的 `Bigint` 结构体。

5. **`Bfree(b)` (gdtoa 内部函数):**
   - **功能：**  释放 `Bigint` 结构体 `b` 占用的内存。
   - **实现：**  它会使用 `free()` 函数释放之前通过 `Balloc()` 分配的内存。
   - **在 `gethex.c` 中的作用：**  在发生错误或不再需要 `Bigint` 结构体时释放内存，防止内存泄漏。

6. **`rshift(b, n)` (gdtoa 内部函数):**
   - **功能：**  将 `Bigint` 结构体 `b` 表示的大整数向右移动 `n` 位。
   - **实现：**  它会执行逐字的位移操作，并将溢出的位传递到下一个较低的字中。
   - **在 `gethex.c` 中的作用：**  用于对尾数进行规范化和舍入。

7. **`lshift(b, n)` (gdtoa 内部函数):**
   - **功能：**  将 `Bigint` 结构体 `b` 表示的大整数向左移动 `n` 位。
   - **实现：**  它会执行逐字的位移操作，并将溢出的位传递到下一个较高的字中。如果需要，可能会增加 `Bigint` 结构体的大小。
   - **在 `gethex.c` 中的作用：**  用于调整尾数，例如在处理非规范化数时。

8. **`increment(b)` (gdtoa 内部函数):**
   - **功能：**  将 `Bigint` 结构体 `b` 表示的大整数加 1。
   - **实现：**  它会从最低有效字开始执行加 1 操作，并处理进位。如果最高有效字发生进位，可能需要增加 `Bigint` 结构体的大小。
   - **在 `gethex.c` 中的作用：**  在舍入模式为向上舍入时使用。

9. **`hi0bits(L)` (gdtoa 内部函数):**
   - **功能：**  返回 `ULong` 类型变量 `L` 的最高有效零位的数量。
   - **实现：**  它通常会使用位操作指令或循环来查找最高位的 1，并计算其前面的零位数量。
   - **在 `gethex.c` 中的作用：**  用于确定 `Bigint` 中实际使用的位数。

10. **`any_on(b, k)` (gdtoa 内部函数):**
    - **功能：** 检查 `Bigint` 结构体 `b` 中，从最低位开始的 `k` 位中是否有任何位为 1。
    - **实现：** 它会检查 `Bigint` 结构体的相应字中的位。
    - **在 `gethex.c` 中的作用：** 用于确定在右移操作中是否有丢失的非零位，这对于正确的舍入至关重要。

**涉及 dynamic linker 的功能：**

`gethex.c` 编译后的代码会链接到 `libc.so` 动态库中。当应用程序调用诸如 `strtod` 这样的函数时，动态链接器会参与将函数调用路由到 `libc.so` 中 `gethex` 的实际代码。

**so 布局样本 (libc.so 的简化版本):**

```
libc.so:
  ...
  .text:  # 代码段
    ...
    gethex:  # gethex 函数的代码
      ...
    strtod:  # strtod 函数的代码 (可能会调用 gethex)
      ...
  .data:  # 数据段
    ...
    __hexdig_D2A: # 十六进制数字查找表 (可能由 __hexdig_init_D2A 初始化)
    decimal_point_cache: # 本地化小数点缓存
    ...
  .rodata: # 只读数据段
    ...
  .dynsym: # 动态符号表
    gethex
    strtod
    ...
  .dynstr: # 动态字符串表
    gethex
    strtod
    ...
  .plt:   # Procedure Linkage Table (过程链接表)
    gethex@plt:
      jmp *GOT[gethex]
    strtod@plt:
      jmp *GOT[strtod]
    ...
  .got:   # Global Offset Table (全局偏移表)
    GOT[gethex]: 0  # 初始时指向 plt 中的下一条指令
    GOT[strtod]: 指向 strtod 函数的实际地址 (加载时由 linker 填充)
    ...
```

**链接的处理过程：**

1. **编译时：** 编译器将 `gethex.c` 编译成机器码，并将其放入目标文件。对外部符号（如 `malloc`）的引用会生成重定位条目。
2. **链接时：** 链接器将目标文件与其他目标文件和库文件链接在一起，生成 `libc.so`。`gethex` 函数的符号会导出到动态符号表中。
3. **加载时：** 当 Android 系统加载一个使用 `libc.so` 的应用程序时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
   - **加载 `libc.so`：** 将 `libc.so` 加载到内存中的某个地址。
   - **解析符号：** 遍历应用程序和 `libc.so` 的动态符号表，解析函数和变量的地址。
   - **重定位：**  填充全局偏移表 (GOT)。例如，`GOT[gethex]` 最初可能指向 `gethex@plt` 中的下一条指令。当第一次调用 `gethex` 时，会跳转到 `gethex@plt`，然后 `gethex@plt` 会跳转回自身（或类似机制），动态链接器会介入，找到 `gethex` 在内存中的实际地址，并更新 `GOT[gethex]`。后续对 `gethex` 的调用将直接通过 GOT 跳转到其真实地址，避免了每次都进行符号查找的开销。

**假设输入与输出：**

**假设输入：** `sp` 指向字符串 "0x1.8p+4"

**逻辑推理：**

1. **前缀：** 识别 "0x"，表示是十六进制浮点数。
2. **尾数：** 解析 "1.8"。
3. **小数点：** 遇到 "."，记录小数点位置。
4. **指数：** 解析 "p+4"，指数值为 +4。
5. **尾数转换：** 将 "18" (十六进制) 转换为 `Bigint`，小数点后的位数影响指数。
6. **指数计算：** 初始指数基于小数点位置，加上解析到的指数值。

**预期输出：**

* `*bp`:  指向一个 `Bigint` 结构体，其值表示尾数 (二进制形式的 1.8<sub>16</sub>)。
* `*exp`: 指数为 4。
* 函数返回值：`STRTOG_Normal` (或其他表示成功解析的返回值)。

**假设输入：** `sp` 指向字符串 "0x0.0000000000000000000000000000001p-100" (一个非常小的数)

**逻辑推理：**

1. **前缀：** 识别 "0x"。
2. **尾数：** 解析 "0.00...01"。
3. **小数点：** 记录小数点位置。
4. **指数：** 解析 "p-100"。
5. **尾数转换：** 将 "1" 转换为 `Bigint`。
6. **指数计算：** 初始指数很小，加上 -100，最终指数可能非常小。
7. **下溢处理：** 计算出的指数可能小于浮点数类型的最小可表示指数。

**预期输出：**

* `*bp`: 指向一个 `Bigint` 结构体，其值表示尾数 1。
* `*exp`: 指数可能接近浮点数的最小指数。
* 函数返回值：`STRTOG_Denormal` 或 `STRTOG_Underflow` (表示结果是非规范化数或发生下溢)。

**用户或编程常见的使用错误：**

由于 `gethex` 通常不是直接被用户调用的，错误通常发生在调用它的上层函数（如 `strtod`）时。

1. **无效的十六进制格式：**
   - **错误示例：**  `strtod("0xG.p1", NULL)`  // 'G' 不是有效的十六进制数字。
   - **结果：** `strtod` 会报告错误，`errno` 可能会被设置为 `EINVAL`。

2. **指数格式错误：**
   - **错误示例：** `strtod("0x1.0pe", NULL)`  // 指数部分缺少数值。
   - **结果：** `strtod` 会报告错误。

3. **超出范围的指数：**
   - **错误示例：** `strtod("0x1.0p10000", NULL)` // 指数过大，导致溢出。
   - **结果：** `strtod` 会返回 `HUGE_VAL` (或相关的无穷大值)，`errno` 会被设置为 `ERANGE`。

4. **缺少尾数或指数：**
   - **错误示例：** `strtod("0xp1", NULL)` 或 `strtod("0x", NULL)`
   - **结果：** `strtod` 会报告错误或返回 0。

5. **Locale 问题 (如果 `USE_LOCALE` 生效):**
   - **错误示例：**  如果当前 locale 的小数点分隔符不是 "."，但程序中使用了 "."。
   - **结果：**  解析可能会失败或得到错误的结果。

**说明 Android Framework 或 NDK 是如何一步步到达这里的，给出 Frida hook 示例调试这些步骤。**

**Android Framework 到 `gethex` 的路径 (示例):**

1. **Java 代码:**  Android 应用的 Java 代码尝试将一个包含十六进制浮点数的字符串转换为 `double` 类型。
   ```java
   String hexString = "0x1.ffffp10";
   double value = Double.parseDouble(hexString);
   ```

2. **Framework 层:** `Double.parseDouble()` 最终会调用 Native 方法。

3. **NDK (C/C++) 层:**  在 Android 的 libcore 库中，会调用到 C/C++ 代码，最终可能调用到 Bionic libc 的 `strtod` 函数。

4. **Bionic libc:** `strtod` 函数会解析输入的字符串。当检测到 "0x" 前缀时，`strtod` 内部可能会调用 `gethex` 函数来处理十六进制浮点数的解析。

**Frida Hook 示例：**

假设你想在 Android 设备上 hook `gethex` 函数，观察其参数和返回值。

```javascript
// Frida 脚本

console.log("Script loaded");

if (Process.arch === "arm64" || Process.arch === "arm") {
    const gethexPtr = Module.findExportByName("libc.so", "gethex");

    if (gethexPtr) {
        Interceptor.attach(gethexPtr, {
            onEnter: function (args) {
                console.log("gethex called!");
                console.log("  sp:", ptr(args[0]).readCString()); // 读取字符串指针
                console.log("  fpi:", args[1]); // FPI 结构体指针
                console.log("  exp:", args[2]); // Long 指针
                console.log("  bp:", args[3]);  // Bigint 指针
                console.log("  sign:", args[4]);
            },
            onLeave: function (retval) {
                console.log("gethex returned:", retval);
            }
        });
    } else {
        console.error("Could not find gethex in libc.so");
    }
} else {
    console.log("Skipping hook, not an ARM/ARM64 architecture.");
}
```

**使用 Frida 调试步骤：**

1. **准备环境：** 确保你的 Android 设备已 root，并安装了 Frida 服务。
2. **编写 Frida 脚本：** 将上面的 JavaScript 代码保存到一个文件中，例如 `hook_gethex.js`。
3. **运行应用：** 运行你想要调试的 Android 应用。
4. **执行 Frida 命令：** 使用 Frida CLI 将脚本附加到目标进程。你需要找到应用的进程 ID。
   ```bash
   frida -U -f <your_app_package_name> -l hook_gethex.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <your_app_package_name> -l hook_gethex.js
   ```
5. **触发 `gethex` 调用：** 在你的 Android 应用中执行会导致解析十六进制浮点数的操作（例如，调用 `Double.parseDouble("0x...")`）。
6. **查看 Frida 输出：** Frida 会在控制台中打印出 `gethex` 函数被调用时的参数和返回值，帮助你理解调用过程。

这个 Frida 示例提供了在运行时动态地观察 `gethex` 函数行为的方式，可以帮助你理解 Android Framework 或 NDK 如何调用到这个低层函数。

希望以上详细的解释能够帮助你理解 `bionic/libc/upstream-openbsd/lib/libc/gdtoa/gethex.c` 文件的功能、与 Android 的关系以及相关的实现细节。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/gethex.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

Copyright (C) 1998 by Lucent Technologies
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

#ifdef USE_LOCALE
#include "locale.h"
#endif

 int
#ifdef KR_headers
gethex(sp, fpi, exp, bp, sign)
	CONST char **sp; FPI *fpi; Long *exp; Bigint **bp; int sign;
#else
gethex( CONST char **sp, FPI *fpi, Long *exp, Bigint **bp, int sign)
#endif
{
	Bigint *b;
	CONST unsigned char *decpt, *s0, *s, *s1;
	int big, esign, havedig, irv, j, k, n, n0, nbits, up, zret;
	ULong L, lostbits, *x;
	Long e, e1;
#ifdef USE_LOCALE
	int i;
#ifdef NO_LOCALE_CACHE
	const unsigned char *decimalpoint = (unsigned char*)localeconv()->decimal_point;
#else
	const unsigned char *decimalpoint;
	static unsigned char *decimalpoint_cache;
	if (!(s0 = decimalpoint_cache)) {
		s0 = (unsigned char*)localeconv()->decimal_point;
		decimalpoint_cache = strdup(s0);
	}
	decimalpoint = s0;
#endif
#endif

	if (!hexdig['0'])
		__hexdig_init_D2A();
	*bp = 0;
	havedig = 0;
	s0 = *(CONST unsigned char **)sp + 2;
	while(s0[havedig] == '0')
		havedig++;
	s0 += havedig;
	s = s0;
	decpt = 0;
	zret = 0;
	e = 0;
	if (hexdig[*s])
		havedig++;
	else {
		zret = 1;
#ifdef USE_LOCALE
		for(i = 0; decimalpoint[i]; ++i) {
			if (s[i] != decimalpoint[i])
				goto pcheck;
			}
		decpt = s += i;
#else
		if (*s != '.')
			goto pcheck;
		decpt = ++s;
#endif
		if (!hexdig[*s])
			goto pcheck;
		while(*s == '0')
			s++;
		if (hexdig[*s])
			zret = 0;
		havedig = 1;
		s0 = s;
		}
	while(hexdig[*s])
		s++;
#ifdef USE_LOCALE
	if (*s == *decimalpoint && !decpt) {
		for(i = 1; decimalpoint[i]; ++i) {
			if (s[i] != decimalpoint[i])
				goto pcheck;
			}
		decpt = s += i;
#else
	if (*s == '.' && !decpt) {
		decpt = ++s;
#endif
		while(hexdig[*s])
			s++;
		}/*}*/
	if (decpt)
		e = -(((Long)(s-decpt)) << 2);
 pcheck:
	s1 = s;
	big = esign = 0;
	switch(*s) {
	  case 'p':
	  case 'P':
		switch(*++s) {
		  case '-':
			esign = 1;
			/* no break */
		  case '+':
			s++;
		  }
		if ((n = hexdig[*s]) == 0 || n > 0x19) {
			s = s1;
			break;
			}
		e1 = n - 0x10;
		while((n = hexdig[*++s]) !=0 && n <= 0x19) {
			if (e1 & 0xf8000000)
				big = 1;
			e1 = 10*e1 + n - 0x10;
			}
		if (esign)
			e1 = -e1;
		e += e1;
	  }
	*sp = (char*)s;
	if (!havedig)
		*sp = (char*)s0 - 1;
	if (zret)
		return STRTOG_Zero;
	if (big) {
		if (esign) {
			switch(fpi->rounding) {
			  case FPI_Round_up:
				if (sign)
					break;
				goto ret_tiny;
			  case FPI_Round_down:
				if (!sign)
					break;
				goto ret_tiny;
			  }
			goto retz;
 ret_tiny:
			b = Balloc(0);
			if (b == NULL)
				return (STRTOG_NoMemory);
			b->wds = 1;
			b->x[0] = 1;
			goto dret;
			}
		switch(fpi->rounding) {
		  case FPI_Round_near:
			goto ovfl1;
		  case FPI_Round_up:
			if (!sign)
				goto ovfl1;
			goto ret_big;
		  case FPI_Round_down:
			if (sign)
				goto ovfl1;
			goto ret_big;
		  }
 ret_big:
		nbits = fpi->nbits;
		n0 = n = nbits >> kshift;
		if (nbits & kmask)
			++n;
		for(j = n, k = 0; j >>= 1; ++k);
		*bp = b = Balloc(k);
		if (*bp == NULL)
			return (STRTOG_NoMemory);
		b->wds = n;
		for(j = 0; j < n0; ++j)
			b->x[j] = ALL_ON;
		if (n > n0)
			b->x[j] = ULbits >> (ULbits - (nbits & kmask));
		*exp = fpi->emin;
		return STRTOG_Normal | STRTOG_Inexlo;
		}
	n = s1 - s0 - 1;
	for(k = 0; n > (1 << (kshift-2)) - 1; n >>= 1)
		k++;
	b = Balloc(k);
	if (b == NULL)
		return (STRTOG_NoMemory);
	x = b->x;
	n = 0;
	L = 0;
#ifdef USE_LOCALE
	for(i = 0; decimalpoint[i+1]; ++i);
#endif
	while(s1 > s0) {
#ifdef USE_LOCALE
		if (*--s1 == decimalpoint[i]) {
			s1 -= i;
			continue;
			}
#else
		if (*--s1 == '.')
			continue;
#endif
		if (n == ULbits) {
			*x++ = L;
			L = 0;
			n = 0;
			}
		L |= (hexdig[*s1] & 0x0f) << n;
		n += 4;
		}
	*x++ = L;
	b->wds = n = x - b->x;
	n = ULbits*n - hi0bits(L);
	nbits = fpi->nbits;
	lostbits = 0;
	x = b->x;
	if (n > nbits) {
		n -= nbits;
		if (any_on(b,n)) {
			lostbits = 1;
			k = n - 1;
			if (x[k>>kshift] & 1 << (k & kmask)) {
				lostbits = 2;
				if (k > 0 && any_on(b,k))
					lostbits = 3;
				}
			}
		rshift(b, n);
		e += n;
		}
	else if (n < nbits) {
		n = nbits - n;
		b = lshift(b, n);
		if (b == NULL)
			return (STRTOG_NoMemory);
		e -= n;
		x = b->x;
		}
	if (e > fpi->emax) {
 ovfl:
		Bfree(b);
 ovfl1:
#ifndef NO_ERRNO
		errno = ERANGE;
#endif
		return STRTOG_Infinite | STRTOG_Overflow | STRTOG_Inexhi;
		}
	irv = STRTOG_Normal;
	if (e < fpi->emin) {
		irv = STRTOG_Denormal;
		n = fpi->emin - e;
		if (n >= nbits) {
			switch (fpi->rounding) {
			  case FPI_Round_near:
				if (n == nbits && (n < 2 || any_on(b,n-1)))
					goto one_bit;
				break;
			  case FPI_Round_up:
				if (!sign)
					goto one_bit;
				break;
			  case FPI_Round_down:
				if (sign) {
 one_bit:
					x[0] = b->wds = 1;
 dret:
					*bp = b;
					*exp = fpi->emin;
#ifndef NO_ERRNO
					errno = ERANGE;
#endif
					return STRTOG_Denormal | STRTOG_Inexhi
						| STRTOG_Underflow;
					}
			  }
			Bfree(b);
 retz:
#ifndef NO_ERRNO
			errno = ERANGE;
#endif
			return STRTOG_Zero | STRTOG_Inexlo | STRTOG_Underflow;
			}
		k = n - 1;
		if (lostbits)
			lostbits = 1;
		else if (k > 0)
			lostbits = any_on(b,k);
		if (x[k>>kshift] & 1 << (k & kmask))
			lostbits |= 2;
		nbits -= n;
		rshift(b,n);
		e = fpi->emin;
		}
	if (lostbits) {
		up = 0;
		switch(fpi->rounding) {
		  case FPI_Round_zero:
			break;
		  case FPI_Round_near:
			if (lostbits & 2
			 && (lostbits | x[0]) & 1)
				up = 1;
			break;
		  case FPI_Round_up:
			up = 1 - sign;
			break;
		  case FPI_Round_down:
			up = sign;
		  }
		if (up) {
			k = b->wds;
			b = increment(b);
			if (b == NULL)
				return (STRTOG_NoMemory);
			x = b->x;
			if (irv == STRTOG_Denormal) {
				if (nbits == fpi->nbits - 1
				 && x[nbits >> kshift] & 1 << (nbits & kmask))
					irv =  STRTOG_Normal;
				}
			else if (b->wds > k
			 || ((n = nbits & kmask) !=0
			      && hi0bits(x[k-1]) < 32-n)) {
				rshift(b,1);
				if (++e > fpi->emax)
					goto ovfl;
				}
			irv |= STRTOG_Inexhi;
			}
		else
			irv |= STRTOG_Inexlo;
		}
	*bp = b;
	*exp = e;
	return irv;
	}
```