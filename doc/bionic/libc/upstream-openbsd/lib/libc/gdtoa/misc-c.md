Response:
Let's break down the thought process for analyzing this `misc.c` file.

**1. Initial Understanding of the Context:**

The first crucial step is recognizing the file path: `bionic/libc/upstream-openbsd/lib/libc/gdtoa/misc.c`. This tells us several things:

* **`bionic`**:  This is Android's C library. Anything in here is fundamental to how Android operates.
* **`libc`**:  This confirms it's part of the core C library.
* **`upstream-openbsd`**: This is a key indicator. It means Android is using code from the OpenBSD project for this specific functionality. This is a common practice for leveraging well-vetted and secure code. It *doesn't* mean Android *directly* links against OpenBSD's libc, but rather they've incorporated this specific part.
* **`gdtoa`**: This is the core hint to the file's purpose. It stands for "Gay's dtoa" or "general double to ASCII."  This immediately tells us the file is about converting floating-point numbers (doubles) to their string representations.
* **`misc.c`**: The "misc" often suggests utility functions that don't fit neatly into other, more specific modules.

**2. High-Level Functionality Identification:**

Based on the "gdtoa" and the function names, I started identifying the primary purposes:

* **Big Integer Arithmetic:** Functions like `Balloc`, `Bfree`, `mult`, `add`, `diff`, `lshift`, `pow5mult`, `i2b`, `cmp`. These clearly deal with manipulating numbers larger than standard integer types. This is necessary for accurate representation and conversion of floating-point numbers, which can have very large or very small magnitudes.
* **Bit Manipulation:** Functions like `lo0bits`, `hi0bits_D2A`. These are likely used for extracting exponent and mantissa information from floating-point representations, which are bit-level manipulations.
* **Conversion:**  The functions `b2d` (BigInt to double) and `d2b` (double to BigInt) are central to the `gdtoa` purpose. They handle the core conversion logic.
* **Predefined Constants:** `bigtens`, `tinytens`, `tens`. These are clearly powers of 10, used for efficient scaling and conversion.
* **String/Memory Utilities:**  The conditional inclusion of `strcp_D2A` and `memcpy_D2A` suggests that the code might have some basic string and memory manipulation routines, possibly for internal use or in environments without full standard libraries.
* **Threading (Conditional):** The presence of `MULTIPLE_THREADS` defines and `__dtoa_locks` indicates awareness and handling of multi-threading scenarios.

**3. Detailed Function Analysis (Iterative Process):**

I went through each function, looking at its code and comments. Here's a more granular thought process for a few key functions:

* **`Balloc` and `Bfree`:**  The comments and code reveal a custom memory management scheme. The `freelist` suggests a simple free-list allocator for smaller `Bigint` structures. The `PRIVATE_MEM` section hints at a potential optimization for using a pre-allocated memory pool for small allocations, likely to reduce the overhead of frequent `malloc`/`free` calls. The locking mechanism (`ACQUIRE_DTOA_LOCK`, `FREE_DTOA_LOCK`) points to thread-safety considerations.
* **`mult`:** The nested loops and bitwise operations clearly indicate a multiplication algorithm for large integers. The use of `ULLong` or `Pack_32` indicates platform-specific optimizations or handling of different word sizes.
* **`d2b` and `b2d`:** These are the core conversion routines. I looked for how they extract the exponent and mantissa from the double representation (`word0`, `word1`, `Frac_mask`, `Exp_shift`, `Bias`), and how they populate the `Bigint` structure. The `lo0bits` and `hi0bits` functions are used to normalize the representation. The handling of `Sudden_Underflow` and `IBM` (likely for IBM floating-point format) indicates platform-specific concerns.
* **`pow5mult`:** The name suggests optimization for multiplication by powers of 5, which is a common operation in decimal conversions. The caching of powers of 625 (`p5s`) is an optimization to avoid repeated calculations.

**4. Connecting to Android:**

Knowing this is part of Bionic, I considered how these functions would be used in Android:

* **String Formatting:**  The most obvious use is in functions like `sprintf`, `snprintf`, and the C++ `<iostream>` library when formatting floating-point numbers for output (e.g., logging, UI display, file writing).
* **String to Number Conversion:**  While `gdtoa` is primarily for number-to-string, the underlying big integer arithmetic could be used in reverse (string-to-number conversion) although not directly in this file.
* **NDK Usage:**  Applications built with the NDK that need to format floating-point numbers will indirectly use this code.

**5. Dynamic Linker Considerations:**

Because it's in `libc`, this code is part of the main C library, which is loaded by the dynamic linker (`linker64` or `linker`). I considered:

* **SO Layout:**  The code will be within the `libc.so` shared object. I envisioned a simplified layout showing the `.text` section containing the code.
* **Linking Process:**  During application startup, the dynamic linker maps `libc.so` into the process's address space. When a function like `sprintf` is called (which will eventually call into `gdtoa`), the linker resolves the symbol and jumps to the appropriate address within `libc.so`.

**6. Error Handling and Common Mistakes:**

I thought about common programming errors related to floating-point conversions:

* **Precision Loss:**  Converting very large or very small numbers can lead to loss of precision.
* **Locale Issues:**  The decimal separator (period or comma) can vary based on locale, though this file doesn't seem to handle locale directly (that's often higher-level).
* **Buffer Overflows (Potentially):**  While this code focuses on the *conversion* logic, incorrect usage of the *calling* functions (like `sprintf` with an undersized buffer) can lead to overflows.

**7. Frida Hooking:**

To demonstrate debugging, I considered how to hook into these functions using Frida:

* **Identifying the Target:**  The key is to hook the specific functions within the `libc.so` library.
* **Frida Script:** I envisioned a basic Frida script using `Interceptor.attach` to log arguments and return values.

**8. Structuring the Answer:**

Finally, I organized the information into the requested categories: functionality, Android relevance, function implementation details, dynamic linker aspects, logical reasoning, common errors, and Frida hooking. I used clear headings and bullet points to improve readability. I aimed for a balance between technical detail and clarity, recognizing the target audience might have varying levels of expertise.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the `PRIVATE_MEM` is for thread-local storage. **Correction:**  Looking at the locking, it seems more like a per-process optimization, not strictly thread-local.
* **Initial thought:** Focus heavily on the string conversion aspects. **Correction:** Realized the core of this file is the *big integer arithmetic* that *supports* the string conversion.
* **Initially missed:** The connection between `d2b`/`b2d` and the bit-level representation of floating-point numbers. **Correction:**  Added more detail about how these functions extract and manipulate the exponent and mantissa.

By following this structured approach, combining code analysis with contextual understanding, and iteratively refining my understanding, I could generate a comprehensive and accurate answer to the prompt.
这个C源代码文件 `misc.c` 来自 OpenBSD 的 `lib/libc/gdtoa` 目录，并被 Android Bionic C 库所使用。`gdtoa` 代表 "Gay's dtoa"，指的是 David M. Gay 开发的用于将浮点数（通常是双精度 `double`）转换为字符串表示的库。`misc.c` 文件通常包含 `gdtoa` 库的一些辅助和通用的函数。

**`misc.c` 的功能:**

这个文件主要包含以下功能：

1. **大整数 (Bigint) 的管理:**
   - **`Balloc(int k)`:**  分配一个可以存储 2<sup>k</sup> 个 `ULong` (无符号长整型) 的 `Bigint` 结构体。`Bigint` 用于表示任意精度的整数，这是进行精确浮点数到字符串转换所必需的。
   - **`Bfree(Bigint *v)`:** 释放之前分配的 `Bigint` 结构体。它使用一个自由链表 `freelist` 来缓存小型的 `Bigint` 结构，以提高性能，避免频繁的内存分配和释放。
   - **`mult(Bigint *a, Bigint *b)`:** 将两个 `Bigint` 相乘，返回一个新的 `Bigint` 结果。
   - **`multadd(Bigint *b, int m, int a)`:** 将 `Bigint` `b` 乘以整数 `m`，再加上整数 `a`，结果存储回 `b`。
   - **`lshift(Bigint *b, int k)`:** 将 `Bigint` `b` 左移 `k` 位。
   - **`pow5mult(Bigint *b, int k)`:** 将 `Bigint` `b` 乘以 5 的 `k` 次方。它使用缓存的 5 的幂来优化计算。
   - **`i2b(int i)`:** 将一个普通的 `int` 转换为 `Bigint` 结构体。
   - **`cmp(Bigint *a, Bigint *b)`:** 比较两个 `Bigint` 的大小，返回 -1, 0 或 1。
   - **`diff(Bigint *a, Bigint *b)`:** 计算两个 `Bigint` 的差值 `a - b` 或 `b - a`，返回一个新的 `Bigint` 结果。

2. **位操作辅助函数:**
   - **`lo0bits(ULong *y)`:** 计算一个 `ULong` 类型的值 `y` 最低位的连续 0 的个数，并将 `y` 右移直到最低位为 1。
   - **`hi0bits_D2A(ULong x)`:** 计算一个 `ULong` 类型的值 `x` 最高位的连续 0 的个数 (用于 `double` 到 ASCII 转换)。

3. **`double` 和 `Bigint` 之间的转换:**
   - **`b2d(Bigint *a, int *e)`:** 将一个 `Bigint` `a` 转换为 `double` 类型，并返回其二进制指数 `e`。
   - **`d2b(double dd, int *e, int *bits)`:** 将一个 `double` 类型的值 `dd` 转换为 `Bigint` 结构体，并返回其二进制指数 `e` 和有效位数 `bits`。

4. **预定义的常量:**
   - `bigtens[]`:  存储一些大的 10 的正数幂，用于优化浮点数转换。
   - `tinytens[]`: 存储一些小的 10 的负数幂。
   - `tens[]`: 存储一些小的 10 的正数幂。

5. **可选的内存管理:**
   - 如果未定义 `Omit_Private_Memory`，则使用一个静态的私有内存池 `private_mem` 来分配小型的 `Bigint` 结构，以减少 `malloc` 和 `free` 的开销。

6. **线程安全 (可选):**
   - 如果定义了 `MULTIPLE_THREADS`，则使用锁 `__dtoa_locks` 来保护对 `Bigint` 自由链表的访问，以确保线程安全。

7. **字符串和内存操作辅助函数 (可选):**
   - 如果定义了 `NO_STRING_H`，则提供简单的 `strcp_D2A` (字符串拷贝) 和 `memcpy_D2A` (内存拷贝) 函数，这表明 `gdtoa` 可能在某些受限的环境中使用。

**与 Android 功能的关系及举例:**

这个文件是 Android Bionic C 库的一部分，因此它直接支持 Android 系统中各种需要将浮点数转换为字符串表示的功能。

**举例说明:**

* **`printf` 和相关函数:**  当你在 Android 应用中使用 `printf`, `sprintf`, `snprintf` 等函数格式化输出浮点数时，Bionic 的 `libc` 会调用 `gdtoa` 库（包括 `misc.c` 中的函数）来进行转换。例如：
   ```c
   #include <stdio.h>
   #include <stdlib.h>

   int main() {
       double value = 123.456789;
       char buffer[100];
       snprintf(buffer, sizeof(buffer), "The value is: %f", value);
       printf("%s\n", buffer);
       return 0;
   }
   ```
   在这个例子中，`snprintf` 函数内部会调用 `gdtoa` 相关的函数来将 `double` 类型的 `value` 转换为字符串 `"123.456789"`。`misc.c` 中的 `Balloc`、`mult`、`d2b` 等函数会参与到这个转换过程中。

* **Java 的 `String.valueOf(double)` 和相关方法:** Android 的 Java Framework 底层很多操作会调用 Native 代码。当 Java 代码需要将 `double` 转换为 `String` 时，例如调用 `String.valueOf(double)`，Android Framework 最终会调用到 Bionic 的 `libc` 中的相关函数，而 `gdtoa` 库就是其中一部分。

* **NDK 开发:** 使用 Android NDK 进行 Native 开发时，如果你在 C/C++ 代码中使用了标准库的浮点数格式化输出函数，那么就会间接地使用到 `misc.c` 中的代码。

**详细解释每一个 libc 函数的功能是如何实现的:**

由于 `misc.c` 中的函数主要是 `gdtoa` 库的内部实现，我们重点解释几个核心函数：

* **`Balloc(int k)`:**
   - 如果 `k` 小于等于 `Kmax`（一个预定义的最大值），则尝试从自由链表 `freelist[k]` 中获取一个空闲的 `Bigint` 结构。这是一种简单的内存池技术，可以提高小对象分配的效率。
   - 如果自由链表中没有可用的对象，或者 `k` 大于 `Kmax`，则分配新的内存。
   - 如果定义了 `Omit_Private_Memory`，则直接使用 `MALLOC` 分配内存。
   - 否则，尝试从私有内存池 `private_mem` 中分配，如果私有内存池不足，则使用 `MALLOC`。
   - 初始化 `Bigint` 结构的 `k` (指数)、`maxwds` (最大字数)，并将 `sign` 和 `wds` 初始化为 0。

* **`mult(Bigint *a, Bigint *b)`:**
   - 分配一个新的 `Bigint` 结构 `c` 来存储乘积结果。其大小足够容纳 `a` 和 `b` 的乘积。
   - 使用一个嵌套循环来实现长乘法。它遍历 `b` 的每一个字，然后与 `a` 的所有字相乘，并将结果累加到 `c` 中。
   - 处理进位 (carry) 以确保结果的正确性。
   - 最后，调整 `c` 的 `wds` (有效字数)，去除高位的零。

* **`d2b(double dd, int *e, int *bits)`:**
   - 将 `double` 类型的 `dd` 的位模式解释为整数。
   - 提取 `dd` 的符号、指数和尾数。
   - 根据 `dd` 的指数部分判断其类型（正常数、次正常数、零、无穷大、NaN）。
   - 对于正常数和次正常数，将尾数部分转换为 `Bigint` 结构。这涉及到将 52 位或 63 位的尾数（加上隐含的 1）放入 `Bigint` 的字数组中。
   - 计算二进制指数 `e` 和有效位数 `bits`。

* **`b2d(Bigint *a, int *e)`:**
   - 找到 `Bigint` `a` 的最高有效位。
   - 将 `Bigint` 的高位部分填充到 `double` 的尾数部分。
   - 根据 `Bigint` 的大小和位置计算 `double` 的二进制指数。
   - 组合符号、指数和尾数，形成最终的 `double` 值。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`misc.c` 中的代码最终会被编译链接到 `libc.so` (或在 32 位系统上可能是 `libc.so`) 这个共享对象文件中。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text:
        _start:             // 程序入口点 (不是 misc.c 的一部分)
        printf:             // printf 函数
        sprintf:            // sprintf 函数
        ...
        Balloc:             // misc.c 中的 Balloc 函数
        Bfree:              // misc.c 中的 Bfree 函数
        mult:               // misc.c 中的 mult 函数
        d2b:                // misc.c 中的 d2b 函数
        b2d:                // misc.c 中的 b2d 函数
        lo0bits:            // misc.c 中的 lo0bits 函数
        hi0bits_D2A:        // misc.c 中的 hi0bits_D2A 函数
        ...
    .rodata:
        bigtens:            // misc.c 中的 bigtens 数组
        tinytens:           // misc.c 中的 tinytens 数组
        tens:               // misc.c 中的 tens 数组
        ...
    .data:
        freelist:           // misc.c 中的 freelist 数组 (如果未优化掉)
        pmem_next:          // misc.c 中的 pmem_next 指针 (如果使用私有内存)
        __dtoa_locks:       // misc.c 中的 __dtoa_locks 数组 (如果启用多线程)
        ...
```

**链接的处理过程:**

1. **编译:**  `misc.c` 会被编译成目标文件 `misc.o`。
2. **链接:**  链接器 (如 `ld`) 将 `misc.o` 和其他 `libc` 相关的目标文件链接在一起，生成 `libc.so`。在这个过程中，会解析符号引用，例如 `Balloc` 函数的实现会被链接到任何调用 `Balloc` 的代码。
3. **动态链接:** 当一个 Android 应用启动时，`dalvikvm` (或 `art`) 会加载应用的 `apk` 文件，并启动应用进程。
4. **加载 `libc.so`:**  动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载应用依赖的共享库，包括 `libc.so`。
5. **符号解析:** 当应用代码调用 `printf` 或其他需要浮点数转换的函数时，如果该函数的实现需要调用 `misc.c` 中的函数（例如 `d2b`），动态链接器会解析这些符号，确保函数调用能够跳转到 `libc.so` 中正确的地址。例如，如果 `sprintf` 的实现中调用了 `d2a` (double to ASCII) 相关的函数，而 `d2a` 内部使用了 `Balloc`，那么在 `sprintf` 被调用时，`Balloc` 的地址会被正确解析。

**如果做了逻辑推理，请给出假设输入与输出:**

* **`Balloc(3)`:**
   - **假设输入:** `k = 3`
   - **逻辑推理:**  分配一个可以存储 2<sup>3</sup> = 8 个 `ULong` 的 `Bigint` 结构。如果自由链表 `freelist[3]` 为空，则会分配新的内存。
   - **假设输出:** 返回一个指向新分配的 `Bigint` 结构体的指针。

* **`mult(a, b)`:**
   - **假设输入:**
     - `a`: `Bigint` 表示整数 10 (二进制: ...00001010, `wds` 可能为 1 或更多)
     - `b`: `Bigint` 表示整数 5  (二进制: ...00000101, `wds` 可能为 1 或更多)
   - **逻辑推理:** 执行长乘法 10 * 5。
   - **假设输出:** 返回一个新的 `Bigint` 结构体，表示整数 50 (二进制: ...00110010)。

* **`d2b(1.5, e, bits)`:**
   - **假设输入:** `dd = 1.5`
   - **逻辑推理:**
     - 1.5 的二进制表示是 `1.1 * 2^0`。
     - 提取尾数 (包括隐含的 1) 和指数。
     - 将尾数存储到 `Bigint` 中。
     - 计算二进制指数和有效位数。
   - **假设输出:**
     - 返回一个 `Bigint` 结构体，其内部表示 3 (二进制 `11`)。
     - `*e` 的值为 0 (原始指数)。
     - `*bits` 的值为 2 (有效位数)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **内存泄漏:** 如果 `Balloc` 分配了内存，但 `Bfree` 没有被正确调用，就会导致内存泄漏。这在复杂的浮点数转换逻辑中可能发生，特别是在异常处理路径上。
   ```c
   Bigint *my_bigint = Balloc(5);
   // ... 使用 my_bigint ...
   // 忘记调用 Bfree(my_bigint); // 内存泄漏
   ```

* **`Bigint` 结构体操作错误:**  直接访问和修改 `Bigint` 结构体的内部成员 (如 `x`, `wds`) 而不使用提供的函数可能会导致数据结构不一致和程序崩溃。

* **在多线程环境下不加锁地访问 `Bigint` 自由链表:** 如果定义了 `MULTIPLE_THREADS`，但不使用 `ACQUIRE_DTOA_LOCK` 和 `FREE_DTOA_LOCK` 来保护对 `freelist` 的访问，可能会导致竞争条件和数据损坏。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `misc.c` 的路径 (以 `String.valueOf(double)` 为例):**

1. **Java 代码:** Android 应用或 Framework 的 Java 代码调用 `String.valueOf(double)`.
2. **`Double.toString(double)`:** `String.valueOf(double)` 内部会调用 `Double.toString(double)`.
3. **Native 方法:** `Double.toString(double)` 的实现最终会调用一个 Native 方法 (在 `libjavacrypto.so` 或其他相关库中)。
4. **Bionic `libm.so` 或 `libc.so`:** Native 方法会调用 Bionic 的 C 库函数，例如 `snprintf` 或其他内部的浮点数格式化函数。
5. **`gdtoa` 函数:**  Bionic 的浮点数格式化函数会调用 `gdtoa` 库中的函数，包括 `misc.c` 中定义的 `d2b`、`b2d` 等。

**NDK 到 `misc.c` 的路径 (以 `sprintf` 为例):**

1. **NDK C/C++ 代码:** 使用 NDK 开发的应用直接调用 C 标准库函数 `sprintf` 或 `snprintf`。
   ```c++
   #include <cstdio>
   #include <string>

   std::string formatDouble(double value) {
       char buffer[100];
       snprintf(buffer, sizeof(buffer), "%f", value);
       return buffer;
   }
   ```
2. **Bionic `libc.so`:** `sprintf` 和 `snprintf` 的实现位于 Bionic 的 `libc.so` 中。
3. **`gdtoa` 函数:**  `sprintf` 或 `snprintf` 的内部实现会调用 `gdtoa` 库的函数来完成浮点数到字符串的转换。

**Frida Hook 示例:**

以下是一个使用 Frida hook `Balloc` 函数的示例：

```javascript
if (Java.available) {
    Java.perform(function() {
        var libc = Process.getModuleByName("libc.so");
        var BallocPtr = libc.findExportByName("Balloc");

        if (BallocPtr) {
            Interceptor.attach(BallocPtr, {
                onEnter: function(args) {
                    var k = args[0].toInt32();
                    console.log("[Balloc] Called with k =", k);
                },
                onLeave: function(retval) {
                    console.log("[Balloc] Returned:", retval);
                }
            });
            console.log("Hooked Balloc in libc.so");
        } else {
            console.log("Could not find Balloc in libc.so");
        }
    });
} else {
    console.log("Java is not available (not an Android process).");
}
```

**解释 Frida Hook 示例:**

1. **`if (Java.available)`:** 检查当前进程是否是 Android 进程。
2. **`Java.perform(function() { ... });`:**  确保 Frida 代码在 Java VM 上下文中执行。
3. **`Process.getModuleByName("libc.so")`:** 获取 `libc.so` 模块的句柄。
4. **`libc.findExportByName("Balloc")`:** 查找 `Balloc` 函数的导出地址。
5. **`Interceptor.attach(BallocPtr, { ... });`:**  拦截 `Balloc` 函数的调用。
   - **`onEnter: function(args)`:** 在 `Balloc` 函数执行之前调用。`args` 数组包含传递给 `Balloc` 的参数。这里我们打印了参数 `k` 的值。
   - **`onLeave: function(retval)`:** 在 `Balloc` 函数执行之后调用。`retval` 包含了 `Balloc` 函数的返回值（指向 `Bigint` 结构的指针）。
6. **`console.log(...)`:**  输出调试信息到 Frida 的控制台。

通过类似的 Frida hook，你可以监控其他 `misc.c` 中的函数，例如 `d2b`、`mult` 等，来观察浮点数转换的详细过程，查看输入参数和返回值，从而调试和理解这些函数的行为。你可以 hook 诸如 `snprintf` 这样的上层函数，然后在 `snprintf` 的调用链中观察 `Balloc` 等底层函数的调用情况。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/misc.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

 static Bigint *freelist[Kmax+1];
#ifndef Omit_Private_Memory
#ifndef PRIVATE_MEM
#define PRIVATE_MEM 2304
#endif
#define PRIVATE_mem ((PRIVATE_MEM+sizeof(double)-1)/sizeof(double))
static double private_mem[PRIVATE_mem], *pmem_next = private_mem;
#endif

#ifdef MULTIPLE_THREADS
static void *__dtoa_locks[] = { NULL, NULL };
#endif

 Bigint *
Balloc
#ifdef KR_headers
	(k) int k;
#else
	(int k)
#endif
{
	int x;
	Bigint *rv;
#ifndef Omit_Private_Memory
	unsigned int len;
#endif

	ACQUIRE_DTOA_LOCK(0);
	/* The k > Kmax case does not need ACQUIRE_DTOA_LOCK(0), */
	/* but this case seems very unlikely. */
	if (k <= Kmax && (rv = freelist[k]) !=0) {
		freelist[k] = rv->next;
		}
	else {
		x = 1 << k;
#ifdef Omit_Private_Memory
		rv = (Bigint *)MALLOC(sizeof(Bigint) + (x-1)*sizeof(ULong));
		if (rv == NULL)
			return (NULL);
#else
		len = (sizeof(Bigint) + (x-1)*sizeof(ULong) + sizeof(double) - 1)
			/sizeof(double);
		if (k <= Kmax && pmem_next - private_mem + len <= PRIVATE_mem) {
			rv = (Bigint*)pmem_next;
			pmem_next += len;
			}
		else {
			rv = (Bigint*)MALLOC(len*sizeof(double));
			if (rv == NULL)
				return (NULL);
		}
#endif
		rv->k = k;
		rv->maxwds = x;
		}
	FREE_DTOA_LOCK(0);
	rv->sign = rv->wds = 0;
	return rv;
	}

 void
Bfree
#ifdef KR_headers
	(v) Bigint *v;
#else
	(Bigint *v)
#endif
{
	if (v) {
		if (v->k > Kmax)
#ifdef FREE
			FREE(v);
#else
			free(v);
#endif
		else {
			ACQUIRE_DTOA_LOCK(0);
			v->next = freelist[v->k];
			freelist[v->k] = v;
			FREE_DTOA_LOCK(0);
			}
		}
	}

 int
lo0bits
#ifdef KR_headers
	(y) ULong *y;
#else
	(ULong *y)
#endif
{
	int k;
	ULong x = *y;

	if (x & 7) {
		if (x & 1)
			return 0;
		if (x & 2) {
			*y = x >> 1;
			return 1;
			}
		*y = x >> 2;
		return 2;
		}
	k = 0;
	if (!(x & 0xffff)) {
		k = 16;
		x >>= 16;
		}
	if (!(x & 0xff)) {
		k += 8;
		x >>= 8;
		}
	if (!(x & 0xf)) {
		k += 4;
		x >>= 4;
		}
	if (!(x & 0x3)) {
		k += 2;
		x >>= 2;
		}
	if (!(x & 1)) {
		k++;
		x >>= 1;
		if (!x)
			return 32;
		}
	*y = x;
	return k;
	}

 Bigint *
multadd
#ifdef KR_headers
	(b, m, a) Bigint *b; int m, a;
#else
	(Bigint *b, int m, int a)	/* multiply by m and add a */
#endif
{
	int i, wds;
#ifdef ULLong
	ULong *x;
	ULLong carry, y;
#else
	ULong carry, *x, y;
#ifdef Pack_32
	ULong xi, z;
#endif
#endif
	Bigint *b1;

	wds = b->wds;
	x = b->x;
	i = 0;
	carry = a;
	do {
#ifdef ULLong
		y = *x * (ULLong)m + carry;
		carry = y >> 32;
		*x++ = y & 0xffffffffUL;
#else
#ifdef Pack_32
		xi = *x;
		y = (xi & 0xffff) * m + carry;
		z = (xi >> 16) * m + (y >> 16);
		carry = z >> 16;
		*x++ = (z << 16) + (y & 0xffff);
#else
		y = *x * m + carry;
		carry = y >> 16;
		*x++ = y & 0xffff;
#endif
#endif
		}
		while(++i < wds);
	if (carry) {
		if (wds >= b->maxwds) {
			b1 = Balloc(b->k+1);
			if (b1 == NULL)
				return (NULL);
			Bcopy(b1, b);
			Bfree(b);
			b = b1;
			}
		b->x[wds++] = carry;
		b->wds = wds;
		}
	return b;
	}

 int
hi0bits_D2A
#ifdef KR_headers
	(x) ULong x;
#else
	(ULong x)
#endif
{
	int k = 0;

	if (!(x & 0xffff0000)) {
		k = 16;
		x <<= 16;
		}
	if (!(x & 0xff000000)) {
		k += 8;
		x <<= 8;
		}
	if (!(x & 0xf0000000)) {
		k += 4;
		x <<= 4;
		}
	if (!(x & 0xc0000000)) {
		k += 2;
		x <<= 2;
		}
	if (!(x & 0x80000000)) {
		k++;
		if (!(x & 0x40000000))
			return 32;
		}
	return k;
	}

 Bigint *
i2b
#ifdef KR_headers
	(i) int i;
#else
	(int i)
#endif
{
	Bigint *b;

	b = Balloc(1);
	if (b == NULL)
		return (NULL);
	b->x[0] = i;
	b->wds = 1;
	return b;
	}

 Bigint *
mult
#ifdef KR_headers
	(a, b) Bigint *a, *b;
#else
	(Bigint *a, Bigint *b)
#endif
{
	Bigint *c;
	int k, wa, wb, wc;
	ULong *x, *xa, *xae, *xb, *xbe, *xc, *xc0;
	ULong y;
#ifdef ULLong
	ULLong carry, z;
#else
	ULong carry, z;
#ifdef Pack_32
	ULong z2;
#endif
#endif

	if (a->wds < b->wds) {
		c = a;
		a = b;
		b = c;
		}
	k = a->k;
	wa = a->wds;
	wb = b->wds;
	wc = wa + wb;
	if (wc > a->maxwds)
		k++;
	c = Balloc(k);
	if (c == NULL)
		return (NULL);
	for(x = c->x, xa = x + wc; x < xa; x++)
		*x = 0;
	xa = a->x;
	xae = xa + wa;
	xb = b->x;
	xbe = xb + wb;
	xc0 = c->x;
#ifdef ULLong
	for(; xb < xbe; xc0++) {
		if ( (y = *xb++) !=0) {
			x = xa;
			xc = xc0;
			carry = 0;
			do {
				z = *x++ * (ULLong)y + *xc + carry;
				carry = z >> 32;
				*xc++ = z & 0xffffffffUL;
				}
				while(x < xae);
			*xc = carry;
			}
		}
#else
#ifdef Pack_32
	for(; xb < xbe; xb++, xc0++) {
		if ( (y = *xb & 0xffff) !=0) {
			x = xa;
			xc = xc0;
			carry = 0;
			do {
				z = (*x & 0xffff) * y + (*xc & 0xffff) + carry;
				carry = z >> 16;
				z2 = (*x++ >> 16) * y + (*xc >> 16) + carry;
				carry = z2 >> 16;
				Storeinc(xc, z2, z);
				}
				while(x < xae);
			*xc = carry;
			}
		if ( (y = *xb >> 16) !=0) {
			x = xa;
			xc = xc0;
			carry = 0;
			z2 = *xc;
			do {
				z = (*x & 0xffff) * y + (*xc >> 16) + carry;
				carry = z >> 16;
				Storeinc(xc, z, z2);
				z2 = (*x++ >> 16) * y + (*xc & 0xffff) + carry;
				carry = z2 >> 16;
				}
				while(x < xae);
			*xc = z2;
			}
		}
#else
	for(; xb < xbe; xc0++) {
		if ( (y = *xb++) !=0) {
			x = xa;
			xc = xc0;
			carry = 0;
			do {
				z = *x++ * y + *xc + carry;
				carry = z >> 16;
				*xc++ = z & 0xffff;
				}
				while(x < xae);
			*xc = carry;
			}
		}
#endif
#endif
	for(xc0 = c->x, xc = xc0 + wc; wc > 0 && !*--xc; --wc) ;
	c->wds = wc;
	return c;
	}

 static Bigint *p5s;

 Bigint *
pow5mult
#ifdef KR_headers
	(b, k) Bigint *b; int k;
#else
	(Bigint *b, int k)
#endif
{
	Bigint *b1, *p5, *p51;
	int i;
	static int p05[3] = { 5, 25, 125 };

	if ( (i = k & 3) !=0) {
		b = multadd(b, p05[i-1], 0);
		if (b == NULL)
			return (NULL);
		}

	if (!(k >>= 2))
		return b;
	if ((p5 = p5s) == 0) {
		/* first time */
#ifdef MULTIPLE_THREADS
		ACQUIRE_DTOA_LOCK(1);
		if (!(p5 = p5s)) {
			p5 = p5s = i2b(625);
			if (p5 == NULL)
				return (NULL);
			p5->next = 0;
			}
		FREE_DTOA_LOCK(1);
#else
		p5 = p5s = i2b(625);
		if (p5 == NULL)
			return (NULL);
		p5->next = 0;
#endif
		}
	for(;;) {
		if (k & 1) {
			b1 = mult(b, p5);
			if (b1 == NULL)
				return (NULL);
			Bfree(b);
			b = b1;
			}
		if (!(k >>= 1))
			break;
		if ((p51 = p5->next) == 0) {
#ifdef MULTIPLE_THREADS
			ACQUIRE_DTOA_LOCK(1);
			if (!(p51 = p5->next)) {
				p51 = p5->next = mult(p5,p5);
				if (p51 == NULL)
					return (NULL);
				p51->next = 0;
				}
			FREE_DTOA_LOCK(1);
#else
			p51 = p5->next = mult(p5,p5);
			if (p51 == NULL)
				return (NULL);
			p51->next = 0;
#endif
			}
		p5 = p51;
		}
	return b;
	}

 Bigint *
lshift
#ifdef KR_headers
	(b, k) Bigint *b; int k;
#else
	(Bigint *b, int k)
#endif
{
	int i, k1, n, n1;
	Bigint *b1;
	ULong *x, *x1, *xe, z;

	n = k >> kshift;
	k1 = b->k;
	n1 = n + b->wds + 1;
	for(i = b->maxwds; n1 > i; i <<= 1)
		k1++;
	b1 = Balloc(k1);
	if (b1 == NULL)
		return (NULL);
	x1 = b1->x;
	for(i = 0; i < n; i++)
		*x1++ = 0;
	x = b->x;
	xe = x + b->wds;
	if (k &= kmask) {
#ifdef Pack_32
		k1 = 32 - k;
		z = 0;
		do {
			*x1++ = *x << k | z;
			z = *x++ >> k1;
			}
			while(x < xe);
		if ((*x1 = z) !=0)
			++n1;
#else
		k1 = 16 - k;
		z = 0;
		do {
			*x1++ = *x << k  & 0xffff | z;
			z = *x++ >> k1;
			}
			while(x < xe);
		if (*x1 = z)
			++n1;
#endif
		}
	else do
		*x1++ = *x++;
		while(x < xe);
	b1->wds = n1 - 1;
	Bfree(b);
	return b1;
	}

 int
cmp
#ifdef KR_headers
	(a, b) Bigint *a, *b;
#else
	(Bigint *a, Bigint *b)
#endif
{
	ULong *xa, *xa0, *xb, *xb0;
	int i, j;

	i = a->wds;
	j = b->wds;
#ifdef DEBUG
	if (i > 1 && !a->x[i-1])
		Bug("cmp called with a->x[a->wds-1] == 0");
	if (j > 1 && !b->x[j-1])
		Bug("cmp called with b->x[b->wds-1] == 0");
#endif
	if (i -= j)
		return i;
	xa0 = a->x;
	xa = xa0 + j;
	xb0 = b->x;
	xb = xb0 + j;
	for(;;) {
		if (*--xa != *--xb)
			return *xa < *xb ? -1 : 1;
		if (xa <= xa0)
			break;
		}
	return 0;
	}

 Bigint *
diff
#ifdef KR_headers
	(a, b) Bigint *a, *b;
#else
	(Bigint *a, Bigint *b)
#endif
{
	Bigint *c;
	int i, wa, wb;
	ULong *xa, *xae, *xb, *xbe, *xc;
#ifdef ULLong
	ULLong borrow, y;
#else
	ULong borrow, y;
#ifdef Pack_32
	ULong z;
#endif
#endif

	i = cmp(a,b);
	if (!i) {
		c = Balloc(0);
		if (c == NULL)
			return (NULL);
		c->wds = 1;
		c->x[0] = 0;
		return c;
		}
	if (i < 0) {
		c = a;
		a = b;
		b = c;
		i = 1;
		}
	else
		i = 0;
	c = Balloc(a->k);
	if (c == NULL)
		return (NULL);
	c->sign = i;
	wa = a->wds;
	xa = a->x;
	xae = xa + wa;
	wb = b->wds;
	xb = b->x;
	xbe = xb + wb;
	xc = c->x;
	borrow = 0;
#ifdef ULLong
	do {
		y = (ULLong)*xa++ - *xb++ - borrow;
		borrow = y >> 32 & 1UL;
		*xc++ = y & 0xffffffffUL;
		}
		while(xb < xbe);
	while(xa < xae) {
		y = *xa++ - borrow;
		borrow = y >> 32 & 1UL;
		*xc++ = y & 0xffffffffUL;
		}
#else
#ifdef Pack_32
	do {
		y = (*xa & 0xffff) - (*xb & 0xffff) - borrow;
		borrow = (y & 0x10000) >> 16;
		z = (*xa++ >> 16) - (*xb++ >> 16) - borrow;
		borrow = (z & 0x10000) >> 16;
		Storeinc(xc, z, y);
		}
		while(xb < xbe);
	while(xa < xae) {
		y = (*xa & 0xffff) - borrow;
		borrow = (y & 0x10000) >> 16;
		z = (*xa++ >> 16) - borrow;
		borrow = (z & 0x10000) >> 16;
		Storeinc(xc, z, y);
		}
#else
	do {
		y = *xa++ - *xb++ - borrow;
		borrow = (y & 0x10000) >> 16;
		*xc++ = y & 0xffff;
		}
		while(xb < xbe);
	while(xa < xae) {
		y = *xa++ - borrow;
		borrow = (y & 0x10000) >> 16;
		*xc++ = y & 0xffff;
		}
#endif
#endif
	while(!*--xc)
		wa--;
	c->wds = wa;
	return c;
	}

 double
b2d
#ifdef KR_headers
	(a, e) Bigint *a; int *e;
#else
	(Bigint *a, int *e)
#endif
{
	ULong *xa, *xa0, w, y, z;
	int k;
	U d;
#ifdef VAX
	ULong d0, d1;
#else
#define d0 word0(&d)
#define d1 word1(&d)
#endif

	xa0 = a->x;
	xa = xa0 + a->wds;
	y = *--xa;
#ifdef DEBUG
	if (!y) Bug("zero y in b2d");
#endif
	k = hi0bits(y);
	*e = 32 - k;
#ifdef Pack_32
	if (k < Ebits) {
		d0 = Exp_1 | y >> (Ebits - k);
		w = xa > xa0 ? *--xa : 0;
		d1 = y << ((32-Ebits) + k) | w >> (Ebits - k);
		goto ret_d;
		}
	z = xa > xa0 ? *--xa : 0;
	if (k -= Ebits) {
		d0 = Exp_1 | y << k | z >> (32 - k);
		y = xa > xa0 ? *--xa : 0;
		d1 = z << k | y >> (32 - k);
		}
	else {
		d0 = Exp_1 | y;
		d1 = z;
		}
#else
	if (k < Ebits + 16) {
		z = xa > xa0 ? *--xa : 0;
		d0 = Exp_1 | y << k - Ebits | z >> Ebits + 16 - k;
		w = xa > xa0 ? *--xa : 0;
		y = xa > xa0 ? *--xa : 0;
		d1 = z << k + 16 - Ebits | w << k - Ebits | y >> 16 + Ebits - k;
		goto ret_d;
		}
	z = xa > xa0 ? *--xa : 0;
	w = xa > xa0 ? *--xa : 0;
	k -= Ebits + 16;
	d0 = Exp_1 | y << k + 16 | z << k | w >> 16 - k;
	y = xa > xa0 ? *--xa : 0;
	d1 = w << k + 16 | y << k;
#endif
 ret_d:
#ifdef VAX
	word0(&d) = d0 >> 16 | d0 << 16;
	word1(&d) = d1 >> 16 | d1 << 16;
#endif
	return dval(&d);
	}
#undef d0
#undef d1

 Bigint *
d2b
#ifdef KR_headers
	(dd, e, bits) double dd; int *e, *bits;
#else
	(double dd, int *e, int *bits)
#endif
{
	Bigint *b;
	U d;
#ifndef Sudden_Underflow
	int i;
#endif
	int de, k;
	ULong *x, y, z;
#ifdef VAX
	ULong d0, d1;
#else
#define d0 word0(&d)
#define d1 word1(&d)
#endif
	d.d = dd;
#ifdef VAX
	d0 = word0(&d) >> 16 | word0(&d) << 16;
	d1 = word1(&d) >> 16 | word1(&d) << 16;
#endif

#ifdef Pack_32
	b = Balloc(1);
#else
	b = Balloc(2);
#endif
	if (b == NULL)
		return (NULL);
	x = b->x;

	z = d0 & Frac_mask;
	d0 &= 0x7fffffff;	/* clear sign bit, which we ignore */
#ifdef Sudden_Underflow
	de = (int)(d0 >> Exp_shift);
#ifndef IBM
	z |= Exp_msk11;
#endif
#else
	if ( (de = (int)(d0 >> Exp_shift)) !=0)
		z |= Exp_msk1;
#endif
#ifdef Pack_32
	if ( (y = d1) !=0) {
		if ( (k = lo0bits(&y)) !=0) {
			x[0] = y | z << (32 - k);
			z >>= k;
			}
		else
			x[0] = y;
#ifndef Sudden_Underflow
		i =
#endif
		     b->wds = (x[1] = z) !=0 ? 2 : 1;
		}
	else {
		k = lo0bits(&z);
		x[0] = z;
#ifndef Sudden_Underflow
		i =
#endif
		    b->wds = 1;
		k += 32;
		}
#else
	if ( (y = d1) !=0) {
		if ( (k = lo0bits(&y)) !=0)
			if (k >= 16) {
				x[0] = y | z << 32 - k & 0xffff;
				x[1] = z >> k - 16 & 0xffff;
				x[2] = z >> k;
				i = 2;
				}
			else {
				x[0] = y & 0xffff;
				x[1] = y >> 16 | z << 16 - k & 0xffff;
				x[2] = z >> k & 0xffff;
				x[3] = z >> k+16;
				i = 3;
				}
		else {
			x[0] = y & 0xffff;
			x[1] = y >> 16;
			x[2] = z & 0xffff;
			x[3] = z >> 16;
			i = 3;
			}
		}
	else {
#ifdef DEBUG
		if (!z)
			Bug("Zero passed to d2b");
#endif
		k = lo0bits(&z);
		if (k >= 16) {
			x[0] = z;
			i = 0;
			}
		else {
			x[0] = z & 0xffff;
			x[1] = z >> 16;
			i = 1;
			}
		k += 32;
		}
	while(!x[i])
		--i;
	b->wds = i + 1;
#endif
#ifndef Sudden_Underflow
	if (de) {
#endif
#ifdef IBM
		*e = (de - Bias - (P-1) << 2) + k;
		*bits = 4*P + 8 - k - hi0bits(word0(&d) & Frac_mask);
#else
		*e = de - Bias - (P-1) + k;
		*bits = P - k;
#endif
#ifndef Sudden_Underflow
		}
	else {
		*e = de - Bias - (P-1) + 1 + k;
#ifdef Pack_32
		*bits = 32*i - hi0bits(x[i-1]);
#else
		*bits = (i+2)*16 - hi0bits(x[i]);
#endif
		}
#endif
	return b;
	}
#undef d0
#undef d1

 CONST double
#ifdef IEEE_Arith
bigtens[] = { 1e16, 1e32, 1e64, 1e128, 1e256 };
CONST double tinytens[] = { 1e-16, 1e-32, 1e-64, 1e-128, 1e-256
		};
#else
#ifdef IBM
bigtens[] = { 1e16, 1e32, 1e64 };
CONST double tinytens[] = { 1e-16, 1e-32, 1e-64 };
#else
bigtens[] = { 1e16, 1e32 };
CONST double tinytens[] = { 1e-16, 1e-32 };
#endif
#endif

 CONST double
tens[] = {
		1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9,
		1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19,
		1e20, 1e21, 1e22
#ifdef VAX
		, 1e23, 1e24
#endif
		};

#ifdef NO_STRING_H

 char *
#ifdef KR_headers
strcp_D2A(a, b) char *a; char *b;
#else
strcp_D2A(char *a, CONST char *b)
#endif
{
	while((*a = *b++))
		a++;
	return a;
	}

 Char *
#ifdef KR_headers
memcpy_D2A(a, b, len) Char *a; Char *b; size_t len;
#else
memcpy_D2A(void *a1, void *b1, size_t len)
#endif
{
	char *a = (char*)a1, *ae = a + len;
	char *b = (char*)b1, *a0 = a;
	while(a < ae)
		*a++ = *b++;
	return a0;
	}

#endif /* NO_STRING_H */

"""

```