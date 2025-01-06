Response:
Let's break down the thought process for analyzing the `ldtoa.c` code.

1. **Understand the Context:** The first step is recognizing where this code comes from: OpenBSD's `libc`, used as an upstream source for Android's Bionic library. This immediately tells us it's dealing with low-level, core functionality related to number representation and conversion. The file name `ldtoa.c` strongly suggests it's about converting `long double` numbers to ASCII strings.

2. **Identify the Core Function:** The primary function is `__ldtoa`. Note the double underscore, which often signifies an internal, non-public function in `libc`. The arguments provide clues about its purpose:
    * `long double *ld`: The input number (passed by reference).
    * `int mode`: Likely controls the formatting (e.g., fixed-point, scientific).
    * `int ndigits`: Precision or number of digits desired.
    * `int *decpt`: Output for the decimal point position.
    * `int *sign`: Output for the sign of the number.
    * `char **rve`: Output for a pointer to the end of the generated string (potentially for error handling or further processing).

3. **Handle Conditional Compilation:**  The `#if (LDBL_MANT_DIG > DBL_MANT_DIG)` is crucial. It tells us the code handles two different scenarios based on the precision of `long double` compared to `double`. This immediately splits the analysis into two branches.

4. **Analyze the `long double` > `double` Case:**
    * **Delegation to `gdtoa`:** The code calls `gdtoa`. This is a significant piece of information. It suggests `ldtoa` is a wrapper around a more general conversion function. We need to understand what `gdtoa` does. The comments provide some context: it's a more generalized function.
    * **FPI Structure:** The `FPI` structure is initialized with parameters related to the `long double` format (mantissa bits, min/max exponents, rounding mode). This confirms the function's connection to IEEE floating-point representation.
    * **Sign Handling:** The code explicitly extracts the sign bit and adjusts the rounding mode. This highlights a detail in how `gdtoa` operates (it doesn't handle the sign directly).
    * **Exponent Handling:** The calculation of `be` (biased exponent) and the use of `EXT_TO_ARRAY32` indicate the manipulation of the raw bits of the `long double`.
    * **Special Floating-Point Numbers:** The `switch` statement based on `fpclassify` handles normal numbers, zero, subnormals, infinity, and NaN. This shows the robustness of the conversion process. The `STRTOG_*` constants suggest these are internal flags used by `gdtoa`.
    * **`decpt` Adjustment:** The adjustment of `*decpt` from `-32768` to `INT_MAX` when calling `gdtoa` signals a mapping between `gdtoa`'s error/special value representation and `ldtoa`'s.

5. **Analyze the `long double` == `double` Case:**
    * **Direct Call to `dtoa`:**  Here, `ldtoa` simply casts the `long double` to `double` and calls `dtoa`. This makes sense: if they have the same precision, we can reuse the `double` conversion logic.
    * **`decpt` Adjustment:**  Similar to the other case, `*decpt` is adjusted, but this time from `9999` to `INT_MAX`. This indicates a slightly different convention for `dtoa` regarding special values.

6. **Address the Specific Questions:** Now that the core functionality is understood, address each part of the prompt:

    * **Functionality:** Summarize the purpose: converting `long double` to a string.
    * **Android Relevance:** Explain its role in number formatting for various APIs and applications. Give examples like `String.valueOf()` or `printf`.
    * **`libc` Function Implementation:** For each function called (`gdtoa`, `dtoa`, `fpclassify`), describe its likely internal operation. Since we don't have the source for those, make informed guesses based on their purpose (e.g., bit manipulation, lookup tables for special values).
    * **Dynamic Linker:** Recognize that `ldtoa` itself is *part* of `libc`, which is a shared library. Explain how the dynamic linker loads and resolves symbols. Provide a basic `.so` layout. For the linking process, describe symbol lookup and relocation.
    * **Logical Reasoning (Input/Output):**  Provide examples of how different inputs (normal numbers, zero, infinity, NaN) would be converted to strings.
    * **Common Usage Errors:**  Focus on the consequences of incorrect formatting specifiers or buffer overflows (though this function returns a dynamically allocated string, it's good to mention).
    * **Android Framework/NDK Path:** Trace a hypothetical call from Java/Kotlin in the Android framework, through the NDK, and finally to `ldtoa`. Include relevant API calls (`String.format`, JNI).
    * **Frida Hook:** Provide a concrete Frida script example that hooks `__ldtoa`, intercepts calls, and logs arguments and results.

7. **Refine and Organize:**  Organize the information logically, using clear headings and bullet points. Ensure the language is precise and avoids jargon where possible, while still being technically accurate. Double-check for any inconsistencies or missing pieces. For instance, initially, I might forget to explicitly mention `DEF_STRONG(__ldtoa)` which is related to symbol visibility. Reviewing the code helps catch such details. Also, ensure the examples provided are relevant and easy to understand. For example, for the Frida hook, include clear instructions on how to use it and interpret the output.
这个`ldtoa.c`文件是Android Bionic库中用于将`long double`类型的浮点数转换为字符串表示的源代码文件。它实际上是对更通用的`gdtoa`函数的封装。让我们详细分析其功能：

**功能列举：**

1. **`long double` 到字符串转换:**  核心功能是将`long double`类型的浮点数转换成可读的字符串形式。
2. **处理不同的浮点数类型:** 能够处理正常的浮点数、零、次正规数（subnormal numbers）、无穷大（infinity）和NaN（Not a Number）。
3. **可配置的格式:** 接受 `mode` 和 `ndigits` 参数，允许控制输出字符串的格式和精度。例如，可以指定定点表示或科学计数法，以及需要显示的有效数字位数。
4. **返回指数和符号信息:** 除了返回表示浮点数的字符串外，还通过 `decpt` 参数返回十进制小数点的位置，通过 `sign` 参数返回数的符号（0表示正数，非零表示负数）。
5. **处理 `gdtoa` 的特殊返回值:**  由于 `gdtoa` 在处理 NaN 或无穷大时会将 `expt` 设置为 9999，而 `long double` 本身可能具有有效的指数 9999，`ldtoa` 将 `decpt` 设置为 `INT_MAX` 以区分这些情况。
6. **针对不同 `long double` 精度提供优化:**  根据 `LDBL_MANT_DIG` (long double 的尾数位数) 是否大于 `DBL_MANT_DIG` (double 的尾数位数)，采用了不同的实现策略，以优化性能。

**与 Android 功能的关系及举例：**

这个函数在 Android 系统中扮演着重要的角色，因为它涉及到将数值数据转换为用户可读的字符串，这在许多场景下都是必需的。

* **Java `String.valueOf(double)` 或 `String.format()` 的底层实现:** 当你在 Java 代码中使用 `String.valueOf()` 将一个 `double` 或 `long double` 转换为字符串，或者使用 `String.format()` 进行格式化输出时，最终会调用到 Native 层的函数来完成实际的转换工作。`ldtoa` 就是处理 `long double` 类型转换的关键部分。
    * **例子:** 在 Java 中执行 `String.valueOf(3.14159265358979323846264338327950288419716939937510582097494459)`，底层就可能通过 JNI 调用到 Bionic 的浮点数转换函数，其中对于 `long double` 类型会涉及到 `ldtoa`。
* **`printf` 系列函数的支持:**  C/C++ 代码中常用的 `printf`, `sprintf` 等函数在格式化输出浮点数时，也需要调用底层的转换函数。如果你在 NDK 开发中使用 `printf` 打印 `long double` 类型的变量，那么 `ldtoa` 就会被调用。
    * **例子:** 在 NDK 代码中执行 `printf("The value is: %Lg\n", my_long_double_variable);`，`ldtoa` 会将 `my_long_double_variable` 转换为字符串以便 `printf` 输出。
* **数学库函数的辅助:**  一些数学库函数可能会返回 `long double` 类型的结果。当需要将这些结果显示给用户或者进行持久化存储时，就需要用到像 `ldtoa` 这样的函数进行转换。

**`libc` 函数功能实现详解：**

1. **`__ldtoa(long double *ld, int mode, int ndigits, int *decpt, int *sign, char **rve)`:**
   * **参数解析:** 接收指向 `long double` 变量的指针 `ld`，转换模式 `mode`，所需有效数字位数 `ndigits`，以及用于返回小数点位置 `decpt`、符号 `sign` 和尾部指针 `rve` 的指针。
   * **条件编译:**  根据 `LDBL_MANT_DIG` 是否大于 `DBL_MANT_DIG`，采用不同的实现方式。
   * **`LDBL_MANT_DIG > DBL_MANT_DIG` 的情况 (更精确的 `long double`):**
     * **`FPI` 结构体初始化:**  创建一个 `FPI` (Floating Point Information) 结构体，用于描述 `long double` 的精度、指数范围和舍入模式。这些信息对于 `gdtoa` 函数至关重要。
     * **符号处理:**  提取 `long double` 的符号位，并根据符号调整 `FPI` 结构体中的舍入模式。这是因为 `gdtoa` 本身不直接处理符号。
     * **指数计算:** 计算 `long double` 的偏置指数 `be`。
     * **提取尾数:** 使用 `EXT_TO_ARRAY32` 宏将 `long double` 的尾数部分提取到一个 32 位整数数组 `bits` 中。这涉及到对底层 IEEE 754 浮点数表示的理解。
     * **浮点数分类:** 使用 `fpclassify(*ld)` 判断浮点数的类型（正常、零、次正规、无穷大、NaN）。
     * **类型处理:** 根据浮点数类型设置 `kind` 变量，并进行一些特定类型的处理，例如，对于次正规数，需要调整指数。如果启用了 `EXT_IMPLICIT_NBIT` (表示尾数最高位是隐含的 1)，则需要显式设置该位。
     * **调用 `gdtoa`:**  调用核心转换函数 `gdtoa`，将浮点数的内部表示转换为字符串。
     * **处理 `gdtoa` 的特殊返回值:** 如果 `gdtoa` 返回的 `*decpt` 为 -32768 (通常表示 NaN 或无穷大)，则将其设置为 `INT_MAX`。
   * **`LDBL_MANT_DIG == DBL_MANT_DIG` 的情况 (与 `double` 精度相同):**
     * **直接调用 `dtoa`:**  将 `long double` 强制转换为 `double`，并直接调用 `dtoa` 函数进行转换。这是一种优化，避免了重复实现相同精度的转换逻辑。
     * **处理 `dtoa` 的特殊返回值:** 如果 `dtoa` 返回的 `*decpt` 为 9999 (通常表示 NaN 或无穷大)，则将其设置为 `INT_MAX`。

2. **`gdtoa(const FPI *fpi, int exp, CONST void *bits, int *type, int mode, int ndigits, int *decpt, char **rve)`:** (虽然 `ldtoa.c` 中没有实现 `gdtoa`，但它是核心，需要解释)
   * **参数解析:** 接收 `FPI` 结构体指针 `fpi`，浮点数的指数 `exp`，尾数位 `bits` 的指针，浮点数类型 `type` 的指针，转换模式 `mode`，所需有效数字位数 `ndigits`，以及用于返回小数点位置 `decpt` 和尾部指针 `rve` 的指针。
   * **内部实现复杂:** `gdtoa` 的具体实现非常复杂，涉及到大量的数值计算和字符串处理。其主要步骤包括：
     * **处理特殊值:**  首先检查输入是否为零、无穷大或 NaN，并返回相应的字符串（"0"、"Inf"、"NaN"）。
     * **尾数和指数调整:**  根据浮点数的表示形式，调整尾数和指数，使其处于规范化的形式。
     * **大数乘法和除法:**  使用高精度算术进行尾数与 10 的幂的乘法或除法，以生成所需的十进制表示。这通常涉及到自定义的大数运算数据结构和算法。
     * **舍入:**  根据指定的舍入模式（`fpi->rounding`）对结果进行舍入。
     * **格式化:**  根据 `mode` 和 `ndigits` 参数，将结果格式化为定点数或科学计数法字符串。
     * **设置 `decpt`:** 计算并设置十进制小数点的位置。
     * **分配内存:**  动态分配内存来存储生成的字符串。

3. **`dtoa(double d, int mode, int ndigits, int *decpt, int *sign, char **rve)`:** (在 `LDBL_MANT_DIG == DBL_MANT_DIG` 的情况下被调用)
   * **功能类似 `ldtoa`:**  类似于 `ldtoa`，但专门用于将 `double` 类型的浮点数转换为字符串。
   * **内部实现:**  其内部实现也类似于 `gdtoa`，但针对 `double` 的精度进行了优化。

4. **`fpclassify(long double x)`:**
   * **功能:**  判断浮点数 `x` 的类型。
   * **实现:**  通常通过检查浮点数的符号位、指数位和尾数位来确定类型。例如，指数全为 0 且尾数非零表示次正规数，指数全为 1 且尾数全为 0 表示无穷大，指数全为 1 且尾数非零表示 NaN。

**涉及 dynamic linker 的功能，so 布局样本，以及链接的处理过程：**

`ldtoa.c` 本身的代码不直接涉及 dynamic linker 的功能。然而，作为 `libc` 的一部分，它会被编译成一个共享库 (shared object, `.so`)，并在程序运行时被 dynamic linker 加载和链接。

**SO 布局样本 (libm.so 或 libc.so 中的一部分):**

```
.so 文件头 (ELF header)
...
.text  (代码段)
    __ldtoa:
        ; ldtoa 的指令
        ...
    gdtoa:
        ; gdtoa 的指令
        ...
    dtoa:
        ; dtoa 的指令
        ...
    fpclassify:
        ; fpclassify 的指令
        ...
.rodata (只读数据段)
    ; 可能包含浮点数常量、字符串常量等
.data   (已初始化数据段)
    ; 可能包含全局变量
.bss    (未初始化数据段)
    ; 可能包含未初始化的全局变量
.dynsym (动态符号表)
    __ldtoa  (指向 __ldtoa 代码的地址)
    gdtoa    (指向 gdtoa 代码的地址)
    dtoa     (指向 dtoa 代码的地址)
    fpclassify (指向 fpclassify 代码的地址)
    ... 其他符号
.dynstr (动态字符串表)
    __ldtoa
    gdtoa
    dtoa
    fpclassify
    ... 其他字符串
.plt    (过程链接表)
    ; 用于延迟绑定
.got    (全局偏移表)
    ; 用于存储外部符号的地址
...
```

**链接的处理过程：**

1. **编译和链接:** 当包含对 `ldtoa` 或其他相关函数的调用的代码被编译时，编译器会生成对这些符号的未解析引用。在链接阶段，静态链接器会将这些引用记录在生成的可执行文件或共享库的动态符号表中。
2. **加载时链接 (Dynamic Linking):** 当程序启动时，dynamic linker (在 Android 上通常是 `linker64` 或 `linker`) 负责加载程序依赖的共享库 (例如 `libc.so` 或 `libm.so`)。
3. **符号解析:** dynamic linker 会扫描加载的共享库的动态符号表，查找程序中未解析的符号。例如，当程序调用 `ldtoa` 时，dynamic linker 会在 `libc.so` 的 `.dynsym` 中找到 `__ldtoa` 符号，并获取其地址。
4. **重定位:**  由于共享库被加载到内存的哪个地址是不确定的，dynamic linker 需要进行重定位，即修改代码和数据段中对外部符号的引用，使其指向共享库在内存中的实际地址。这通常通过全局偏移表 (GOT) 和过程链接表 (PLT) 来实现。
5. **延迟绑定 (Lazy Binding):** 为了提高启动速度，dynamic linker 通常采用延迟绑定策略。这意味着在第一次调用一个外部函数时才进行符号解析和重定位。PLT 中的代码会负责在首次调用时跳转到 dynamic linker 进行解析，并将解析后的地址更新到 GOT 中。后续的调用将直接通过 GOT 跳转到目标函数。

**逻辑推理，假设输入与输出：**

* **假设输入:** `ld = 3.14159L`, `mode = 3` (表示尽可能短但能精确表示的格式), `ndigits = 0`
* **预期输出:** `*decpt` 指向的值可能为 1，`*sign` 指向的值为 0，返回的字符串可能为 `"3.14159"`。

* **假设输入:** `ld = 0.0L`, `mode = 2` (定点格式), `ndigits = 5`
* **预期输出:** `*decpt` 指向的值可能为 1，`*sign` 指向的值为 0，返回的字符串可能为 `"0.00000"`。

* **假设输入:** `ld = -12345.6789L`, `mode = 0` (提供 `ndigits` 位有效数字), `ndigits = 8`
* **预期输出:** `*decpt` 指向的值可能为 5，`*sign` 指向的值可能非零，返回的字符串可能为 `"-1.2345679e+4"` (具体格式取决于 `gdtoa` 的实现细节)。

* **假设输入:** `ld = infinity`, `mode = 0`, `ndigits = 0`
* **预期输出:** `*decpt` 指向的值为 `INT_MAX`，`*sign` 指向的值为 0，返回的字符串可能为 `"Inf"`。

* **假设输入:** `ld = NaN`, `mode = 0`, `ndigits = 0`
* **预期输出:** `*decpt` 指向的值为 `INT_MAX`，`*sign` 指向的值为 0，返回的字符串可能为 `"NaN"`。

**用户或编程常见的使用错误：**

1. **缓冲区溢出 (如果直接使用返回值):** 虽然 `ldtoa` 内部会动态分配内存，但如果用户没有正确处理返回的字符串，例如复制到一个固定大小的缓冲区中，可能会发生缓冲区溢出。
   ```c
   char buffer[10];
   long double ld = 123456789.0L;
   int decpt, sign;
   char *rve;
   char *str = __ldtoa(&ld, 3, 0, &decpt, &sign, &rve);
   strcpy(buffer, str); // 潜在的缓冲区溢出
   free(str);
   ```
2. **内存泄漏:**  `__ldtoa` 返回的字符串是通过 `malloc` 分配的，使用后必须通过 `free` 释放，否则会导致内存泄漏。
   ```c
   long double ld = 3.14L;
   int decpt, sign;
   char *rve;
   char *str = __ldtoa(&ld, 3, 0, &decpt, &sign, &rve);
   // 忘记 free(str);
   ```
3. **误解 `mode` 和 `ndigits` 的含义:**  不清楚 `mode` 和 `ndigits` 参数的具体作用，导致输出格式不符合预期。需要查阅相关文档以正确使用这些参数。
4. **未检查 `decpt` 的特殊值:**  没有检查 `decpt` 是否为 `INT_MAX`，导致无法正确处理 NaN 或无穷大的情况。

**Android framework or ndk 如何一步步的到达这里，给出 frida hook 示例调试这些步骤：**

**Android Framework 到 `ldtoa` 的路径示例:**

1. **Java 代码调用 `String.valueOf(long double)`:**
   ```java
   double myLongDouble = 3.14159265358979323846264338327950288419716939937510582097494459;
   String str = String.valueOf(myLongDouble);
   ```
2. **`Double.toString(double)` (或者类似方法) 调用:** `String.valueOf(double)` 内部会调用 `Double.toString(double)`。
3. **Native 方法调用:** `Double.toString()` 最终会调用一个 native 方法，该方法位于 Android Runtime (ART) 的本地库中。
4. **JNI 调用:** ART 的 native 方法会通过 Java Native Interface (JNI) 调用到 Bionic 库中的相关函数。对于 `double` 类型，可能会涉及到 `dtoa` 的调用，而对于 `long double` 类型（如果 Java 支持 `long double` 并且 JNI 接口正确传递了该类型），则会调用到 `ldtoa`。
5. **Bionic 库中的 `ldtoa`:**  最终，执行权会到达 `bionic/libc/upstream-openbsd/lib/libc/gdtoa/ldtoa.c` 中的 `__ldtoa` 函数。

**NDK 到 `ldtoa` 的路径示例:**

1. **C/C++ 代码调用 `printf` 或其他格式化输出函数:**
   ```c++
   #include <cstdio>
   #include <cfloat> // for LDBL_DIG
   int main() {
       long double myLongDouble = 3.14159L;
       printf("%.*Lg\n", LDBL_DIG, myLongDouble);
       return 0;
   }
   ```
2. **`printf` 函数调用:**  C/C++ 标准库中的 `printf` 函数会被调用。
3. **Bionic 库中的 `printf` 实现:** Android NDK 提供的 `printf` 函数的实现位于 Bionic 库中。
4. **浮点数格式化:** `printf` 函数内部会解析格式化字符串 `%.*Lg`，识别出需要格式化一个 `long double` 类型的浮点数。
5. **调用 `ldtoa`:** `printf` 的实现会调用底层的浮点数转换函数，对于 `long double` 类型，会调用 `__ldtoa`。

**Frida Hook 示例:**

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__ldtoa"), {
    onEnter: function(args) {
        this.ld = ptr(args[0]).readDouble(); // 假设 long double 在内存中布局与 double 类似，可能需要调整
        this.mode = args[1].toInt32();
        this.ndigits = args[2].toInt32();
        this.decpt_ptr = ptr(args[3]);
        this.sign_ptr = ptr(args[4]);
        this.rve_ptr = ptr(args[5]);
        console.log("[+] __ldtoa called with:");
        console.log("    ld: " + this.ld);
        console.log("    mode: " + this.mode);
        console.log("    ndigits: " + this.ndigits);
    },
    onLeave: function(retval) {
        var decpt = this.decpt_ptr.readS32();
        var sign = this.sign_ptr.readS32();
        var result = ptr(retval).readCString();
        console.log("[+] __ldtoa returned:");
        console.log("    result: " + result);
        console.log("    decpt: " + decpt);
        console.log("    sign: " + sign);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida:** 确保你的系统上安装了 Frida 和 Frida Server。
2. **启动目标应用:** 运行你要调试的 Android 应用。
3. **运行 Frida 脚本:** 将上面的 Python 代码保存为 `.py` 文件，并将 `your.app.package.name` 替换为你的应用包名。通过命令行运行该脚本：`python your_script_name.py`。
4. **触发 `ldtoa` 调用:** 在你的应用中执行会触发 `long double` 到字符串转换的操作，例如调用 `String.valueOf()` 或 `printf` 输出 `long double` 类型的变量。
5. **查看 Frida 输出:** Frida 会拦截对 `__ldtoa` 函数的调用，并打印出传入的参数和返回的结果，包括 `ld` 的值、`mode`、`ndigits` 以及返回的字符串、小数点位置和符号。

**注意:**

* 上面的 Frida 脚本假设 `long double` 在内存中的布局与 `double` 类似，但这可能不总是正确的，具体取决于架构和编译器。你可能需要根据实际情况调整 `readDouble()` 的调用方式来读取 `long double` 的值。
* Hook 系统库函数需要 root 权限或者在可调试的应用上进行。

通过 Frida Hook，你可以动态地观察 `ldtoa` 函数的调用情况，这对于理解其工作原理和调试相关问题非常有帮助。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/ldtoa.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: ldtoa.c,v 1.4 2016/03/09 16:28:47 deraadt Exp $	*/
/*-
 * Copyright (c) 2003 David Schultz <das@FreeBSD.ORG>
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

#include <sys/types.h>
#include <machine/ieee.h>
#include <float.h>
#include <stdint.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include "gdtoaimp.h"

#if (LDBL_MANT_DIG > DBL_MANT_DIG)

/*
 * ldtoa() is a wrapper for gdtoa() that makes it smell like dtoa(),
 * except that the floating point argument is passed by reference.
 * When dtoa() is passed a NaN or infinity, it sets expt to 9999.
 * However, a long double could have a valid exponent of 9999, so we
 * use INT_MAX in ldtoa() instead.
 */
char *
__ldtoa(long double *ld, int mode, int ndigits, int *decpt, int *sign,
    char **rve)
{
	FPI fpi = {
		LDBL_MANT_DIG,			/* nbits */
		LDBL_MIN_EXP - LDBL_MANT_DIG,	/* emin */
		LDBL_MAX_EXP - LDBL_MANT_DIG,	/* emax */
		FLT_ROUNDS,	       		/* rounding */
#ifdef Sudden_Underflow	/* unused, but correct anyway */
		1
#else
		0
#endif
	};
	int be, kind;
	char *ret;
	struct ieee_ext *p = (struct ieee_ext *)ld;
	uint32_t bits[(LDBL_MANT_DIG + 31) / 32];
	void *vbits = bits;

	/*
	 * gdtoa doesn't know anything about the sign of the number, so
	 * if the number is negative, we need to swap rounding modes of
	 * 2 (upwards) and 3 (downwards).
	 */
	*sign = p->ext_sign;
	fpi.rounding ^= (fpi.rounding >> 1) & p->ext_sign;

	be = p->ext_exp - (LDBL_MAX_EXP - 1) - (LDBL_MANT_DIG - 1);
	EXT_TO_ARRAY32(p, bits);

	switch (fpclassify(*ld)) {
	case FP_NORMAL:
		kind = STRTOG_Normal;
#ifdef EXT_IMPLICIT_NBIT
		bits[LDBL_MANT_DIG / 32] |= 1 << ((LDBL_MANT_DIG - 1) % 32);
#endif /* EXT_IMPLICIT_NBIT */
		break;
	case FP_ZERO:
		kind = STRTOG_Zero;
		break;
	case FP_SUBNORMAL:
		kind = STRTOG_Denormal;
		be++;
		break;
	case FP_INFINITE:
		kind = STRTOG_Infinite;
		break;
	case FP_NAN:
		kind = STRTOG_NaN;
		break;
	default:
		abort();
	}

	ret = gdtoa(&fpi, be, vbits, &kind, mode, ndigits, decpt, rve);
	if (*decpt == -32768)
		*decpt = INT_MAX;
	return ret;
}
DEF_STRONG(__ldtoa);

#else   /* (LDBL_MANT_DIG == DBL_MANT_DIG) */

char *
__ldtoa(long double *ld, int mode, int ndigits, int *decpt, int *sign,
    char **rve)
{
	char *ret;

	ret = dtoa((double)*ld, mode, ndigits, decpt, sign, rve);
	if (*decpt == 9999)
		*decpt = INT_MAX;
	return ret;
}
DEF_STRONG(__ldtoa);

#endif  /* (LDBL_MANT_DIG == DBL_MANT_DIG) */

"""

```