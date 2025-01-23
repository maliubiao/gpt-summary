Response:
Let's break down the thought process for analyzing this `gdtoa.c` file. The initial request is quite broad, so we need a structured approach.

**1. Understanding the Core Task:**

The very first step is to recognize the file's purpose. The initial comment block clearly states: "dtoa for IEEE arithmetic (dmg): convert double to ASCII string."  This is the fundamental function. It takes a floating-point number (represented by `FPI`, `be`, and `bits`) and converts it into a human-readable string.

**2. Deconstructing the Functionality (High-Level):**

Next, I scanned the code for major sections and keywords to understand the overall flow. I noticed:

* **Handling Special Cases:**  The code starts by checking for zero, infinity, and NaN. This is a standard practice in floating-point conversion.
* **Big Integer Arithmetic:**  The inclusion of `Bigint` and functions like `bitstob`, `rshift`, `pow5mult`, `mult`, `lshift`, `multadd`, `cmp`, `diff`, and `quorem` strongly suggests the use of arbitrary-precision arithmetic. This is crucial for accurate conversion, especially for long decimal expansions.
* **Floating-Point Optimizations:**  The code mentions "fast floating-point estimate" and has sections using `double` variables (`d`, `ds`, `eps`). This indicates attempts to optimize the conversion for certain cases by leveraging the speed of native floating-point operations.
* **Rounding Modes:** The `mode` parameter and the handling of `rdir` (rounding direction) are prominent, highlighting the importance of correctly implementing different rounding behaviors.
* **Steele & White Algorithm:** The comment referring to "How to Print Floating-Point Numbers Accurately" and the mention of a `mode 1` employing a different stopping rule points to a specific, well-known algorithm for accurate floating-point to string conversion.

**3. Detailed Analysis of Key Functions:**

Now, I'd delve into the details of specific functions:

* **`bitstob`:**  The name suggests "bits to bigint." The code confirms this by converting the raw bit representation of the floating-point number into a `Bigint` structure. This is the foundation for arbitrary-precision calculations.
* **`gdtoa`:**  This is the main function. I'd analyze its parameters (especially `mode` and `ndigits`) and the different code paths based on these parameters. I'd pay close attention to how it switches between fast floating-point paths and the more accurate `Bigint` based calculations.
* **`quorem`:**  The name hints at quotient and remainder. The code uses it for digit extraction during the conversion process.

**4. Connecting to Android Bionic:**

The prompt specifically asks about the relationship to Android. Since this file is part of `bionic/libc`, it's a core part of Android's standard C library. This means any Android application using standard C library functions for converting floating-point numbers to strings (like `sprintf`, `printf` with `%f`, `%e`, `%g`, `ecvt`, `fcvt`) will likely rely on this code, directly or indirectly.

**5. Dynamic Linking Considerations:**

Since `gdtoa` is part of `libc.so`, it's loaded by the dynamic linker. I'd think about:

* **`libc.so` Layout:**  A typical `.so` file has sections like `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), and the dynamic linking information.
* **Linking Process:** When an app uses `gdtoa`, the dynamic linker resolves the symbol `gdtoa` to its address in `libc.so`.

**6. Identifying Common Usage Errors:**

Based on the function's purpose and complexity, I'd consider common mistakes:

* **Incorrect `mode`:**  Misunderstanding the different modes (shortest representation, fixed precision, etc.) can lead to unexpected output.
* **Insufficient Buffer Size:** If a user were to implement their own string conversion, they might underestimate the required buffer size. (Though `gdtoa` handles allocation internally).
* **Locale Issues:**  While not directly apparent in *this* code, locale settings can affect number formatting (e.g., decimal separators).

**7. Frida Hooking:**

To demonstrate usage, a Frida hook is a great way to intercept calls to `gdtoa`. I'd focus on hooking the function entry, examining the input parameters (`fpi`, `be`, `bits`, `mode`, `ndigits`), and the output string.

**8. Structuring the Answer:**

Finally, I would organize the information into the requested sections:

* **Functionality:** A concise summary of what `gdtoa` does.
* **Relationship to Android:** Explaining how Android apps use this code.
* **Libc Function Details:**  In-depth explanation of `gdtoa` and other related functions within the file.
* **Dynamic Linker:**  Describing the `libc.so` layout and the linking process.
* **Logical Reasoning (with examples):** Providing input and expected output scenarios for different `mode` values.
* **Common Usage Errors:**  Illustrating potential mistakes users might make.
* **Android Framework/NDK and Frida Hook:** Showing how the function is reached from Android and providing a practical Frida example.

**Self-Correction/Refinement During the Process:**

* **Initial Broadness:**  The request is very broad. It's important to prioritize the most critical aspects and avoid getting bogged down in every detail of the code.
* **Focus on the Core Function:**  While dynamic linking is relevant, the primary focus should be on the floating-point conversion logic.
* **Balance Technical Depth with Clarity:**  The explanation should be technically accurate but also understandable to someone who might not be an expert in floating-point arithmetic or low-level C. Using clear language and examples is key.
* **Iterative Understanding:** My understanding of the code might evolve as I analyze it. I might initially focus on one aspect and then realize its connection to another part later. This iterative process is normal.

By following these steps, I can methodically analyze the `gdtoa.c` file and provide a comprehensive and well-structured answer to the request.
好的，我们来详细分析 `bionic/libc/upstream-openbsd/lib/libc/gdtoa/gdtoa.c` 这个文件。

**文件功能概述:**

`gdtoa.c` 文件实现了将 IEEE 浮点数（`double` 类型）转换为 ASCII 字符串的功能。这个转换过程需要考虑精度、舍入规则以及不同的格式化需求。 `gdtoa` 是 "generalized dtoa" 的缩写，意味着它是一个通用的浮点数到字符串的转换函数。

**与 Android 功能的关系及举例:**

这个文件是 Android Bionic C 库的一部分，这意味着 Android 系统中的许多核心组件和应用程序都会间接地或直接地使用到它。任何需要将浮点数转换为字符串的操作，例如：

* **`printf` 和 `sprintf` 等格式化输出函数:**  当你使用 `%f`, `%e`, `%g` 等格式化说明符打印浮点数时，`libc` 内部会调用 `gdtoa` (或其他类似的函数) 来完成转换。
    ```c
    #include <stdio.h>

    int main() {
        double pi = 3.14159265359;
        printf("Pi is approximately: %f\n", pi); // 内部会调用 gdtoa
        return 0;
    }
    ```

* **`std::cout` 等 C++ 流输出:**  C++ 的 iostream 库在输出浮点数时，底层也依赖于 C 库的浮点数转换功能。

* **Java Native Interface (JNI) 调用:**  当 Java 代码调用 native 方法，而 native 代码需要将浮点数转换为字符串返回给 Java 层时，也会用到 `gdtoa`。

* **Android Framework 服务:**  某些系统服务可能会记录包含浮点数的数据，并将这些数据转换为字符串形式存储或传输。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个文件中定义了几个静态辅助函数以及主要的 `gdtoa` 函数。

1. **`bitstob(ULong *bits, int nbits, int *bbits)`:**
   - **功能:** 将浮点数的位表示（存储在 `ULong` 数组 `bits` 中）转换为一个 `Bigint` 结构。`Bigint` 结构用于表示任意精度的整数，这对于精确转换浮点数至关重要。
   - **实现:**
     - 计算存储 `nbits` 所需的 `ULong` 字数。
     - 分配一个 `Bigint` 结构。
     - 将 `bits` 中的位数据拷贝到 `Bigint` 的内部表示中。
     - 计算并设置 `Bigint` 的有效字数 (`wds`) 和有效位数 (`bbits`)。
   - **逻辑推理 (假设输入与输出):**
     - **输入:** `bits` 指向一个包含浮点数位表示的 `ULong` 数组，`nbits` 是位数。
     - **输出:** 返回一个 `Bigint` 指针，该 `Bigint` 代表了 `bits` 中的整数值。例如，如果 `bits` 代表 `1.5 * 2^0`，则 `Bigint` 会表示整数 3。

2. **`gdtoa(FPI *fpi, int be, ULong *bits, int *kindp, int mode, int ndigits, int *decpt, char **rve)`:**
   - **功能:**  这是主要函数，将浮点数转换为字符串。
   - **参数:**
     - `fpi`: 指向 `FPI` 结构的指针，包含浮点数的参数信息 (如尾数位数)。
     - `be`: 指数部分的值。
     - `bits`: 指向存储浮点数尾数的 `ULong` 数组。
     - `kindp`: 指向整数的指针，指示浮点数的类型 (Normal, Zero, Infinite, NaN)。
     - `mode`:  指定转换模式，影响生成的字符串格式 (例如，最短表示、固定位数)。
     - `ndigits`:  指定所需的小数位数或有效位数，取决于 `mode`。
     - `decpt`:  指向整数的指针，用于返回小数点的位置。
     - `rve`: 指向字符指针的指针，用于返回结果字符串的末尾。
   - **实现:**
     - **处理特殊情况:** 首先检查输入是否为零、无穷大或 NaN，并返回相应的字符串。
     - **将位转换为 Bigint:** 调用 `bitstob` 将尾数转换为 `Bigint`。
     - **处理尾部的零:**  移除 `Bigint` 表示中尾部的零，并相应调整指数 `be`。
     - **快速路径优化:**  尝试使用浮点运算进行快速转换，特别是当请求的精度较低时。这部分代码利用了 `double` 类型的运算速度。
     - **使用 Bigint 进行精确计算:** 如果需要更高的精度或快速路径不可行，则使用 `Bigint` 进行任意精度的乘法、除法和比较运算。
     - **处理不同的 `mode`:** 根据 `mode` 的值，采用不同的策略生成数字：
       - **Mode 0 和 1 (最短表示):**  生成能够精确表示原始浮点数的尽可能短的字符串。Mode 1 使用 Steele & White 的停止规则。
       - **Mode 2 和 4 (指定有效位数):** 生成指定数量的有效数字。
       - **Mode 3 和 5 (指定小数点后位数):** 生成小数点后指定位数的字符串。
     - **舍入:**  根据浮点数的舍入模式 (`fpi->rounding`) 进行舍入操作。
     - **返回结果:**  将生成的数字字符存储到分配的缓冲区中，设置小数点位置 (`decpt`)，并返回指向字符串的指针。
   - **逻辑推理 (涉及 Bigint 运算):**
     - 为了将浮点数 `m * 2^e` 转换为十进制，核心在于计算 `m * 2^e` 接近哪个十进制数。
     - **乘除以 5 的幂:** 为了将二进制指数转换为十进制指数，代码会进行乘以或除以 5 的幂的操作。例如，乘以 `5^k` 可以将 `2^k` 转换为 `10^k / 5^k * 2^k = 10^k / (5/2)^k`。
     - **Bigint 的加减乘除:**  为了保证精度，所有涉及大数的运算 (例如，乘以 10, 除以 10 的幂) 都是通过 `Bigint` 库的函数实现的。
     - **比较:**  使用 `cmp` 函数比较 `Bigint` 的大小，以确定生成的数字是否需要进位或舍去。
   - **用户或编程常见的使用错误:**
     - **`ndigits` 的误用:**  不理解 `mode` 和 `ndigits` 的组合含义，导致生成的字符串不符合预期。例如，在 `mode = 3` 时，`ndigits` 是小数点后的位数，如果设置为负数可能会导致意外结果。
     - **缓冲区溢出 (理论上，因为 `gdtoa` 内部会分配内存):**  虽然 `gdtoa` 会自动分配内存，但在早期的实现或用户自行实现类似功能时，可能会因为分配的缓冲区不足而导致溢出。
     - **假设了特定的浮点数表示:**  `gdtoa` 是为 IEEE 浮点数设计的，如果用于其他浮点数表示，结果可能不正确。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`gdtoa` 函数位于 `libc.so` (或 Android 上的 `/system/lib[64]/libc.so`) 中。这是一个动态链接库，在程序运行时被加载。

**`libc.so` 布局样本 (简化):**

```
libc.so:
  .text         # 包含 gdtoa 等函数的机器码
  .data         # 包含已初始化的全局变量
  .rodata       # 包含只读数据，例如字符串常量
  .bss          # 包含未初始化的全局变量
  .dynamic      # 包含动态链接信息
  .dynsym       # 动态符号表，包含 gdtoa 等符号的信息
  .dynstr       # 动态字符串表，包含符号名称的字符串
  ...
```

**链接的处理过程:**

1. **编译时:** 当你编译一个使用 `printf` 或其他间接调用 `gdtoa` 的程序时，编译器会生成对 `gdtoa` 的未解析引用。这个信息会记录在生成的可执行文件或动态库的动态链接信息中。

2. **加载时 (Dynamic Linker 的工作):**
   - 当 Android 系统启动或一个应用程序启动时，动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 负责加载程序依赖的动态库，例如 `libc.so`。
   - 动态链接器会解析可执行文件或动态库中的动态链接信息，找到所有未解析的符号，如 `gdtoa`。
   - 它会在已加载的动态库的符号表 (`.dynsym`) 中查找 `gdtoa` 的地址。
   - 一旦找到 `gdtoa` 的地址，动态链接器会将程序中所有对 `gdtoa` 的未解析引用替换为 `libc.so` 中 `gdtoa` 函数的实际地址。这个过程称为**符号解析**或**链接重定位**。

3. **运行时:** 当程序执行到调用 `printf` 并需要打印浮点数时，`printf` 内部会调用 `gdtoa`。由于链接器已经完成了符号解析，程序会跳转到 `libc.so` 中 `gdtoa` 函数的正确地址执行。

**so 布局样本 (更详细的视角):**

使用 `readelf -S /system/lib64/libc.so` 可以查看 `libc.so` 的段信息。以下是一些相关的段：

```
Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        00000074c8e002a8 0002a8 00001c 00   A  0   0  1
  [ 2] .note.android.ident NOTE            00000074c8e002c4 0002c4 000034 00   A  0   0  4
  [ 3] .note.gnu.build-id NOTE            00000074c8e002f8 0002f8 000024 00   A  0   0  4
  [ 4] .text             PROGBITS        00000074c8e00320 000320 0170374 00  AX  0   0 16  // 代码段
  [ 5] .rodata           PROGBITS        00000074c9f04000 1104000 0043418 00   A  0   0 32  // 只读数据
  [ 6] .data.rel.ro      PROGBITS        00000074c9f48180 1148180 00017a0 00   A  0   0  8
  [ 7] .data.rel.ro.local PROGBITS        00000074c9f49920 1149920 0000028 00   A  0   0  8
  [ 8] .symtab           SYMTAB          00000074ca37e000 157e000 0036810 18   0 16003  8  // 符号表
  [ 9] .strtab           STRTAB          00000074ca6e6100 18e6100 002a5c8 00   0   0  1
  [10] .shstrtab         STRTAB          00000074caa8bf18 1ca8bf18 00001e2 00   0   0  1
  [11] .ARM.attributes   ARM_ATTRIBUTE   00000074caa8c100 1ca8c100 0000048 00      0   0  1
  [12] .rela.dyn         RELA            00000074caa8c148 1ca8c148 00066f0 18  AI  8   1  8  // 动态重定位表
  [13] .rela.plt         RELA            00000074caa92838 1ca92838 0000000 18  AI  8  30  8
  [14] .init             PROGBITS        00000074c8e0e000 00e000 00001c 00  AX  0   0  4
  [15] .plt              PROGBITS        00000074c8e0e020 00e020 0000000 10  AX  0   0 16
  [16] .fini             PROGBITS        00000074c8e0e020 00e020 000014 00  AX  0   0  4
  [17] .dynamic          DYNAMIC         00000074caaa0000 1ca94000 00002f0 10   D  8   0  8  // 动态链接信息
  [18] .got              PROGBITS        00000074caaa02f0 1ca942f0 0000008 08  AW  0   0  8
  [19] .data             PROGBITS        00000074caaa02f8 1ca942f8 0008240 00  W A  0   0 32  // 数据段
  [20] .bss              NOBITS          00000074cab226f8 1cb166f8 0003e58 00  WA  0   0 32  // BSS段
  [21] .ARM.exidx        ARM_EXIDX       00000074cab26550 1cb1a550 0000098 00  AL  4   0  4
  [22] .ARM.extab        PROGBITS        00000074cab265e8 1cb1a5e8 0000104 00   A  0   0  4
  [23] .plt.got          PROGBITS        00000074cab266ec 1cb1a6ec 0000000 08  AW  0   0  8
  [24] .gnu.hash         GNU_HASH        00000074cab266f0 1cb1a6f0 0003c04 00   A  8   0  4
  [25] .dynsym           SYMTAB          00000074cab2a2f0 1cb1e2f0 000d9a8 18   9  2834  8  // 动态符号表
  [26] .dynstr           STRTAB          00000074cab37ca0 1cb2bca0 000823b 00   0   0  1  // 动态字符串表
```

可以看到 `.text` 段包含了代码，`.dynsym` 和 `.dynstr` 包含了动态链接所需的符号信息。

**Frida Hook 示例调试步骤:**

假设你想在 Android 应用中使用 Frida Hook 跟踪 `gdtoa` 函数的调用和参数。

1. **准备环境:**
   - 确保你的 Android 设备已 root。
   - 安装 Frida 和 frida-tools (`pip install frida-tools`).
   - 将 Frida server 推送到 Android 设备 (`adb push frida-server /data/local/tmp/`).
   - 在设备上运行 Frida server (`adb shell "/data/local/tmp/frida-server &"`).
   - 找到你想要 hook 的应用进程名或 PID。

2. **Frida Hook 脚本 (JavaScript):**

   ```javascript
   if (Process.arch === 'arm64') {
       var moduleName = "libc.so";
   } else {
       var moduleName = "libc.so"; // 或者 "libc.so" 如果是 32 位
   }

   var gdtoaAddress = Module.findExportByName(moduleName, "gdtoa");

   if (gdtoaAddress) {
       Interceptor.attach(gdtoaAddress, {
           onEnter: function (args) {
               console.log("[+] gdtoa called!");
               console.log("    FPI:", args[0]); // 可以进一步解析 FPI 结构
               console.log("    be:", args[1].toInt32());
               console.log("    bits:", args[2]); // 可以遍历 ULong 数组
               console.log("    kindp:", args[3]);
               console.log("    mode:", args[4].toInt32());
               console.log("    ndigits:", args[5].toInt32());
               console.log("    decpt:", args[6]);
               console.log("    rve:", args[7]);
           },
           onLeave: function (retval) {
               console.log("[+] gdtoa returned:");
               console.log("    Return value:", retval.readUtf8String()); // 假设返回的是字符串
               // 可以检查 decpt 的值
           }
       });
   } else {
       console.error("[-] gdtoa not found!");
   }
   ```

3. **运行 Frida Hook:**

   ```bash
   frida -U -f <你的应用包名> -l hook_gdtoa.js
   # 或者使用 PID
   frida -U <进程PID> -l hook_gdtoa.js
   ```

   当你运行目标应用并执行涉及浮点数到字符串转换的操作时，Frida 控制台会输出 `gdtoa` 函数的调用信息和返回值。

**说明 Android Framework or NDK 是如何一步步的到达这里:**

1. **Android Framework/NDK 调用格式化输出函数:**
   - **Java Framework:** 当 Android Framework 中的 Java 代码需要将浮点数转换为字符串时，例如在 `Log.d()` 中打印浮点数，或者在 UI 元素中显示浮点数，通常会使用 `String.format()` 或类似的方法。
   - **NDK:** 在使用 NDK 开发的应用中，C/C++ 代码可以直接调用 `printf`, `sprintf`, `std::cout` 等函数。

2. **C 库的格式化输出函数:**  无论是 Java 的 `String.format()` 还是 NDK 的 C/C++ 输出函数，最终都会调用到 Bionic C 库提供的格式化输出函数，例如 `vfprintf`。

3. **`vfprintf` 的处理:** `vfprintf` 函数负责解析格式化字符串，并根据格式说明符调用相应的转换函数。当遇到浮点数格式说明符 (`%f`, `%e`, `%g` 等) 时，`vfprintf` 会调用浮点数转换函数。

4. **调用 `gdtoa` (或其他类似函数):**  Bionic C 库中可能有多个浮点数到字符串的转换函数，例如 `ecvt_r`, `fcvt_r`, `dtoa_r` 等。 `gdtoa` 是一个更通用的版本。具体调用哪个函数取决于所需的格式和精度。  现代的 Bionic C 库很可能会使用 `gdtoa` 作为其核心实现。

5. **`gdtoa` 执行转换:**  `gdtoa` 函数接收浮点数的内部表示和格式化参数，执行复杂的转换逻辑，生成最终的字符串。

**总结:**

`gdtoa.c` 文件在 Android 系统中扮演着关键的角色，负责将浮点数转换为人类可读的字符串。它是 Bionic C 库的基础组件，被广泛用于各种场景，从简单的打印输出到复杂的系统服务。理解其功能和实现细节有助于深入理解 Android 系统的底层工作原理。 通过 Frida Hook 这样的工具，我们可以动态地观察和调试这个函数的行为，从而更好地理解和排查问题。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/gdtoa.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

 static Bigint *
#ifdef KR_headers
bitstob(bits, nbits, bbits) ULong *bits; int nbits; int *bbits;
#else
bitstob(ULong *bits, int nbits, int *bbits)
#endif
{
	int i, k;
	Bigint *b;
	ULong *be, *x, *x0;

	i = ULbits;
	k = 0;
	while(i < nbits) {
		i <<= 1;
		k++;
		}
#ifndef Pack_32
	if (!k)
		k = 1;
#endif
	b = Balloc(k);
	if (b == NULL)
		return (NULL);
	be = bits + ((nbits - 1) >> kshift);
	x = x0 = b->x;
	do {
		*x++ = *bits & ALL_ON;
#ifdef Pack_16
		*x++ = (*bits >> 16) & ALL_ON;
#endif
		} while(++bits <= be);
	i = x - x0;
	while(!x0[--i])
		if (!i) {
			b->wds = 0;
			*bbits = 0;
			goto ret;
			}
	b->wds = i + 1;
	*bbits = i*ULbits + 32 - hi0bits(b->x[i]);
 ret:
	return b;
	}

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

 char *
gdtoa
#ifdef KR_headers
	(fpi, be, bits, kindp, mode, ndigits, decpt, rve)
	FPI *fpi; int be; ULong *bits;
	int *kindp, mode, ndigits, *decpt; char **rve;
#else
	(FPI *fpi, int be, ULong *bits, int *kindp, int mode, int ndigits, int *decpt, char **rve)
#endif
{
 /*	Arguments ndigits and decpt are similar to the second and third
	arguments of ecvt and fcvt; trailing zeros are suppressed from
	the returned string.  If not null, *rve is set to point
	to the end of the return value.  If d is +-Infinity or NaN,
	then *decpt is set to 9999.
	be = exponent: value = (integer represented by bits) * (2 to the power of be).

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
		4-9 should give the same return values as 2-3, i.e.,
			4 <= mode <= 9 ==> same return as mode
			2 + (mode & 1).  These modes are mainly for
			debugging; often they run slower but sometimes
			faster than modes 2-3.
		4,5,8,9 ==> left-to-right digit generation.
		6-9 ==> don't try fast floating-point estimate
			(if applicable).

		Values of mode other than 0-9 are treated as mode 0.

		Sufficient space is allocated to the return value
		to hold the suppressed trailing zeros.
	*/

	int bbits, b2, b5, be0, dig, i, ieps, ilim, ilim0, ilim1, inex;
	int j, j1, k, k0, k_check, kind, leftright, m2, m5, nbits;
	int rdir, s2, s5, spec_case, try_quick;
	Long L;
	Bigint *b, *b1, *delta, *mlo, *mhi, *mhi1, *S;
	double d2, ds;
	char *s, *s0;
	U d, eps;

#ifndef MULTIPLE_THREADS
	if (dtoa_result) {
		freedtoa(dtoa_result);
		dtoa_result = 0;
		}
#endif
	inex = 0;
	kind = *kindp &= ~STRTOG_Inexact;
	switch(kind & STRTOG_Retmask) {
	  case STRTOG_Zero:
		goto ret_zero;
	  case STRTOG_Normal:
	  case STRTOG_Denormal:
		break;
	  case STRTOG_Infinite:
		*decpt = -32768;
		return nrv_alloc("Infinity", rve, 8);
	  case STRTOG_NaN:
		*decpt = -32768;
		return nrv_alloc("NaN", rve, 3);
	  default:
		return 0;
	  }
	b = bitstob(bits, nbits = fpi->nbits, &bbits);
	if (b == NULL)
		return (NULL);
	be0 = be;
	if ( (i = trailz(b)) !=0) {
		rshift(b, i);
		be += i;
		bbits -= i;
		}
	if (!b->wds) {
		Bfree(b);
 ret_zero:
		*decpt = 1;
		return nrv_alloc("0", rve, 1);
		}

	dval(&d) = b2d(b, &i);
	i = be + bbits - 1;
	word0(&d) &= Frac_mask1;
	word0(&d) |= Exp_11;
#ifdef IBM
	if ( (j = 11 - hi0bits(word0(&d) & Frac_mask)) !=0)
		dval(&d) /= 1 << j;
#endif

	/* log(x)	~=~ log(1.5) + (x-1.5)/1.5
	 * log10(x)	 =  log(x) / log(10)
	 *		~=~ log(1.5)/log(10) + (x-1.5)/(1.5*log(10))
	 * log10(&d) = (i-Bias)*log(2)/log(10) + log10(d2)
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
#ifdef IBM
	i <<= 2;
	i += j;
#endif
	ds = (dval(&d)-1.5)*0.289529654602168 + 0.1760912590558 + i*0.301029995663981;

	/* correct assumption about exponent range */
	if ((j = i) < 0)
		j = -j;
	if ((j -= 1077) > 0)
		ds += j * 7e-17;

	k = (int)ds;
	if (ds < 0. && ds != k)
		k--;	/* want k = floor(ds) */
	k_check = 1;
#ifdef IBM
	j = be + bbits - 1;
	if ( (j1 = j & 3) !=0)
		dval(&d) *= 1 << j1;
	word0(&d) += j << Exp_shift - 2 & Exp_mask;
#else
	word0(&d) += (be + bbits - 1) << Exp_shift;
#endif
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
	try_quick = 1;
	if (mode > 5) {
		mode -= 4;
		try_quick = 0;
		}
	else if (i >= -4 - Emin || i < Emin)
		try_quick = 0;
	leftright = 1;
	ilim = ilim1 = -1;	/* Values for cases 0 and 1; done here to */
				/* silence erroneous "gcc -Wall" warning. */
	switch(mode) {
		case 0:
		case 1:
			i = (int)(nbits * .30103) + 3;
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

	if ( (rdir = fpi->rounding - 1) !=0) {
		if (rdir < 0)
			rdir = 2;
		if (kind & STRTOG_Neg)
			rdir = 3 - rdir;
		}

	/* Now rdir = 0 ==> round near, 1 ==> round up, 2 ==> round down. */

	if (ilim >= 0 && ilim <= Quick_max && try_quick && !rdir
#ifndef IMPRECISE_INEXACT
		&& k == 0
#endif
								) {

		/* Try to get by with floating-point arithmetic. */

		i = 0;
		d2 = dval(&d);
#ifdef IBM
		if ( (j = 11 - hi0bits(word0(&d) & Frac_mask)) !=0)
			dval(&d) /= 1 << j;
#endif
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
			}
		else  {
			ds = 1.;
			if ( (j1 = -k) !=0) {
				dval(&d) *= tens[j1 & 0xf];
				for(j = j1 >> 4; j; j >>= 1, i++)
					if (j & 1) {
						ieps++;
						dval(&d) *= bigtens[i];
						}
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
			dval(&eps) = ds*0.5/tens[ilim-1] - dval(&eps);
			for(i = 0;;) {
				L = (Long)(dval(&d)/ds);
				dval(&d) -= L*ds;
				*s++ = '0' + (int)L;
				if (dval(&d) < dval(&eps)) {
					if (dval(&d))
						inex = STRTOG_Inexlo;
					goto ret1;
					}
				if (ds - dval(&d) < dval(&eps))
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
				if ( (L = (Long)(dval(&d)/ds)) !=0)
					dval(&d) -= L*ds;
				*s++ = '0' + (int)L;
				if (i == ilim) {
					ds *= 0.5;
					if (dval(&d) > ds + dval(&eps))
						goto bump_up;
					else if (dval(&d) < ds - dval(&eps)) {
						if (dval(&d))
							inex = STRTOG_Inexlo;
						goto clear_trailing0;
						}
					break;
					}
				}
#ifndef No_leftright
			}
#endif
 fast_failed:
		s = s0;
		dval(&d) = d2;
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
			L = dval(&d) / ds;
			dval(&d) -= L*ds;
#ifdef Check_FLT_ROUNDS
			/* If FLT_ROUNDS == 2, L will usually be high by 1 */
			if (dval(&d) < 0) {
				L--;
				dval(&d) += ds;
				}
#endif
			*s++ = '0' + (int)L;
			if (dval(&d) == 0.)
				break;
			if (i == ilim) {
				if (rdir) {
					if (rdir == 1)
						goto bump_up;
					inex = STRTOG_Inexlo;
					goto ret1;
					}
				dval(&d) += dval(&d);
#ifdef ROUND_BIASED
				if (dval(&d) >= ds)
#else
				if (dval(&d) > ds || (dval(&d) == ds && L & 1))
#endif
					{
 bump_up:
					inex = STRTOG_Inexhi;
					while(*--s == '9')
						if (s == s0) {
							k++;
							*s = '0';
							break;
							}
					++*s++;
					}
				else {
					inex = STRTOG_Inexlo;
 clear_trailing0:
					while(*--s == '0'){}
					++s;
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
		i = nbits - bbits;
		if (be - i++ < fpi->emin && mode != 3 && mode != 5) {
			/* denormal */
			i = be - fpi->emin + 1;
			if (mode >= 2 && ilim > 0 && ilim < i)
				goto small_ilim;
			}
		else if (mode >= 2) {
 small_ilim:
			j = ilim - 1;
			if (m5 >= j)
				m5 -= j;
			else {
				s5 += j -= m5;
				b5 += j;
				m5 = 0;
				}
			if ((i = ilim) < 0) {
				m2 -= i;
				i = 0;
				}
			}
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
			if ( (j = b5 - m5) !=0) {
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
	if (mode < 2) {
		if (bbits == 1 && be0 > fpi->emin + 1) {
			/* The special case */
			b2++;
			s2++;
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
	i = ((s5 ? hi0bits(S->x[S->wds-1]) : ULbits - 1) - s2 - 4) & kmask;
	m2 += i;
	if ((b2 += i) > 0) {
		b = lshift(b, b2);
		if (b == NULL)
			return (NULL);
		}
	if ((s2 += i) > 0) {
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
	if (ilim <= 0 && mode > 2) {
		S = multadd(S,5,0);
		if (S == NULL)
			return (NULL);
		if (ilim < 0 || cmp(b,S) <= 0) {
			/* no digits, fcvt style */
 no_digits:
			k = -1 - ndigits;
			inex = STRTOG_Inexlo;
			goto ret;
			}
 one_digit:
		inex = STRTOG_Inexhi;
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
			mhi = lshift(mhi, 1);
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
			if (j1 == 0 && !mode && !(bits[0] & 1) && !rdir) {
				if (dig == '9')
					goto round_9_up;
				if (j <= 0) {
					if (b->wds > 1 || b->x[0])
						inex = STRTOG_Inexlo;
					}
				else {
					dig++;
					inex = STRTOG_Inexhi;
					}
				*s++ = dig;
				goto ret;
				}
#endif
			if (j < 0 || (j == 0 && !mode
#ifndef ROUND_BIASED
							&& !(bits[0] & 1)
#endif
					)) {
				if (rdir && (b->wds > 1 || b->x[0])) {
					if (rdir == 2) {
						inex = STRTOG_Inexlo;
						goto accept;
						}
					while (cmp(S,mhi) > 0) {
						*s++ = dig;
						mhi1 = multadd(mhi, 10, 0);
						if (mhi1 == NULL)
							return (NULL);
						if (mlo == mhi)
							mlo = mhi1;
						mhi = mhi1;
						b = multadd(b, 10, 0);
						if (b == NULL)
							return (NULL);
						dig = quorem(b,S) + '0';
						}
					if (dig++ == '9')
						goto round_9_up;
					inex = STRTOG_Inexhi;
					goto accept;
					}
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
					inex = STRTOG_Inexhi;
					}
				if (b->wds > 1 || b->x[0])
					inex = STRTOG_Inexlo;
 accept:
				*s++ = dig;
				goto ret;
				}
			if (j1 > 0 && rdir != 2) {
				if (dig == '9') { /* possible if i == 1 */
 round_9_up:
					*s++ = '9';
					inex = STRTOG_Inexhi;
					goto roundoff;
					}
				inex = STRTOG_Inexhi;
				*s++ = dig + 1;
				goto ret;
				}
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
			if (i >= ilim)
				break;
			b = multadd(b, 10, 0);
			if (b == NULL)
				return (NULL);
			}

	/* Round off last digit */

	if (rdir) {
		if (rdir == 2 || (b->wds <= 1 && !b->x[0]))
			goto chopzeros;
		goto roundoff;
		}
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
		inex = STRTOG_Inexhi;
		while(*--s == '9')
			if (s == s0) {
				k++;
				*s++ = '1';
				goto ret;
				}
		++*s++;
		}
	else {
 chopzeros:
		if (b->wds > 1 || b->x[0])
			inex = STRTOG_Inexlo;
		while(*--s == '0'){}
		++s;
		}
 ret:
	Bfree(S);
	if (mhi) {
		if (mlo && mlo != mhi)
			Bfree(mlo);
		Bfree(mhi);
		}
 ret1:
	Bfree(b);
	*s = 0;
	*decpt = k + 1;
	if (rve)
		*rve = s;
	*kindp |= inex;
	return s0;
	}
DEF_STRONG(gdtoa);
```