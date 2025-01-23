Response:
我的思考过程如下：

1. **理解文件和目标：** 首先，我明确这个文件 `vfprintf.cpp` 是 Android Bionic libc 的一部分，专门处理格式化输出。我的目标是详细解释它的功能，以及它在 Android 系统中的作用。

2. **概括核心功能：**  快速浏览代码，我注意到它实现了 `__vfprintf` 函数。这个函数的核心任务是根据格式字符串 `fmt0` 和可变参数列表 `ap`，将格式化后的输出写入到文件流 `fp` 中。这让我联想到 `printf`, `fprintf`, `sprintf` 等标准 C 库函数，它们最终都会调用类似的底层实现。

3. **功能拆解与细节分析：** 接下来，我开始细致地分析代码的各个部分，并尝试理解其作用：
    * **宏定义:**  `CHAR_TYPE`, `FUNCTION_NAME`, `PRINT`, `FLUSH` 等宏定义了字符类型、函数名以及输出操作的简化方式。这表明代码可能被用于实现宽字符和窄字符版本的格式化输出。`PRINT` 和 `FLUSH` 涉及缓冲区的管理。
    * **变量声明:** 大量的局部变量负责存储格式化过程中的各种信息，例如标志位 `flags`、宽度 `width`、精度 `prec`、符号 `sign` 等。这暗示了格式字符串的复杂性。
    * **格式字符串解析循环:**  主循环遍历格式字符串，查找 `%` 字符，并根据其后的格式说明符执行相应的转换和输出操作。
    * **标志位处理 (rflag/reswitch):**  `switch` 语句处理各种格式标志（如 `+`, `-`, `#`, `0`, 空格等）和长度修饰符（如 `h`, `l`, `L` 等）。
    * **参数获取 (GETARG/UARG/SARG):**  宏 `GETARG` 用于从 `va_list` 中获取参数。`UARG` 和 `SARG` 分别用于获取无符号和有符号整数参数。
    * **不同类型格式符的处理:** 代码针对不同的格式说明符（`c`, `s`, `d`, `i`, `o`, `u`, `x`, `X`, `f`, `e`, `g`, `a`, `p`, `n`, `m`）有不同的处理逻辑。
    * **浮点数处理:**  浮点数的处理比较复杂，涉及到 `dtoa` 函数（double to ASCII）将浮点数转换为字符串，并处理指数、精度等。
    * **字符串处理:**  字符串的处理涉及到 `strlen`, `strnlen`, 以及宽字符和多字节字符的转换 (`wcrtomb`, `wcsconv`, `mbsconv`)。
    * **整数处理:**  整数的处理涉及到不同进制的转换。
    * **输出缓冲:** `uio` 结构和 `iov` 数组用于管理输出缓冲区，提高效率。`helpers::sprint` 负责将缓冲区内容写入文件。
    * **错误处理:** 代码中包含 `goto error` 语句，用于处理各种错误情况。
    * **内存管理:**  使用了 `free` 和 `munmap` 来释放动态分配的内存。

4. **关联 Android 功能：**  我思考 `vfprintf` 在 Android 中的应用场景。 任何需要在 Android 系统中输出格式化信息的地方，例如日志记录（`ALOG`），C++ 的流输出（`std::cout`），以及各种系统服务和应用程序的内部调试信息，最终都会调用到 `vfprintf` 或类似的函数。

5. **libc 函数实现细节：**  我详细解释了代码中关键 libc 函数的功能和实现思路，例如 `strlen`, `strnlen`, `wcrtomb`, `strerror_r` 以及 `dtoa` 系列函数。  对于 `dtoa`，我意识到这是一个非常底层的操作，需要处理各种浮点数的表示和精度问题。

6. **动态链接器关联：**  我分析了代码中可能与动态链接器相关的地方。 虽然 `vfprintf.cpp` 本身不直接调用动态链接器的 API，但它属于 libc，而 libc 是所有动态链接的程序的基础。  因此，我构造了一个简单的 SO 布局示例，并解释了链接器如何处理符号解析和重定位。

7. **逻辑推理和示例：**  我针对一些格式说明符给出了假设的输入和输出，以帮助理解其行为。

8. **常见错误：** 我列举了使用 `printf` 系列函数时常见的错误，例如格式字符串和参数类型不匹配，缓冲区溢出等。

9. **Android Framework/NDK 调用链：**  我尝试构建从 Android Framework 或 NDK 到 `vfprintf` 的调用链，从 Java 的 `Log` 类到 Native 层的 `__android_log_print`，最终到 `vfprintf`。  同时，给出了 Frida Hook 的示例，展示如何拦截和调试这些调用。

10. **组织和完善答案：**  最后，我将所有分析结果组织成清晰易懂的中文回复，并对答案进行完善和校对，确保逻辑正确，表达清晰。  我特别注意用代码块高亮显示代码片段和 Frida Hook 示例，增强可读性。

通过以上步骤，我能够比较全面和深入地理解 `vfprintf.cpp` 的功能，以及它在 Android 系统中的作用和实现细节。 我的重点是结合代码本身、相关的 C 标准库知识、以及 Android 系统的特定环境来进行分析。

这是一个关于 Android Bionic C 库中 `vfprintf.cpp` 源代码文件的分析。`vfprintf` 是一个核心的 C 标准库函数，用于将格式化的输出写入到指定的文件流。

**功能列举：**

1. **格式化输出:**  `vfprintf` 的主要功能是根据提供的格式字符串 (`fmt0`) 和可变参数列表 (`ap`)，将数据格式化为字符串并输出到文件流 (`fp`)。它支持各种格式说明符，用于处理不同类型的数据（整数、浮点数、字符串、字符等）。
2. **处理各种数据类型:**  代码中可以看到对 `int`, `long`, `long long`, `unsigned int`, `unsigned long`, `unsigned long long`, `double`, `long double`, `char`, `wchar_t`, 指针等多种数据类型的处理。
3. **支持格式标志:**  `vfprintf` 解析格式字符串中的标志（flags），例如：
    * `+`:  显示正数的符号。
    * `-`:  左对齐输出。
    * ` `:  正数前填充空格。
    * `#`:  使用替代格式（例如，在十六进制数前加上 `0x`）。
    * `0`:  用零填充。
    * `'`:  用于数字分组（未实现）。
4. **支持宽度和精度:**  可以指定输出字段的最小宽度和浮点数的精度。
5. **支持长度修饰符:**  可以指定参数的长度，例如 `h` (short), `l` (long), `ll` (long long), `L` (long double)。
6. **支持位置参数:**  允许使用 `$`` 符号指定要格式化的参数的位置。
7. **错误处理:**  代码中包含错误处理机制，例如检查写入错误 (`__sferror(fp)`) 和内存分配错误。
8. **缓冲区管理:**  使用 `__suio` 和 `__siov` 结构体来管理输出缓冲区，提高输出效率。
9. **支持宽字符:**  通过 `wchar_t` 和相关的转换函数 (`wcrtomb`, `wcsconv`)，支持宽字符的格式化输出。
10. **处理特殊值:**  可以正确处理浮点数的特殊值，如 `INF` (无穷大) 和 `NAN` (非数字)。
11. **`%n` 安全性:**  明确禁止使用 `%n` 格式说明符，因为它存在安全风险。
12. **`%m` 支持:**  支持 `%m` 格式说明符，用于输出 `errno` 对应的错误消息。

**与 Android 功能的关系及举例：**

`vfprintf` 是 Android 系统中许多核心功能的基石。任何需要在 native 层进行格式化输出的地方，最终都会间接地或直接地调用到 `vfprintf` 或其相关的函数（如 `fprintf`, `printf`, `sprintf`, `snprintf` 等）。

* **日志系统 (ALOG):** Android 的日志系统 `ALOG` 在 native 层使用 `vfprintf` 将格式化的日志消息写入到 logcat。

   ```c++
   // bionic/libc/bionic/android_log.cpp
   int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list ap) {
       // ...
       vfprintf(stderr, fmt, ap); // 或者写入到 log 文件描述符
       // ...
   }
   ```
   **举例：** 当一个 Android 应用调用 `Log.d("MyApp", "Value: %d", myValue);` 时，最终会调用到 native 层的 `__android_log_print`，后者会使用 `vfprintf` 将 "Value: [myValue]" 写入日志。

* **C++ 标准库 iostream:**  C++ 的 `iostream` 库在底层也依赖于 C 标准库的格式化输出功能。例如，`std::cout << "Count: " << count << std::endl;`  在 native 层最终会通过 `streambuf` 调用到类似 `vfprintf` 的函数。

* **NDK 开发:**  使用 NDK 进行 Android 开发时，你可以直接使用 `printf` 或 `fprintf` 等函数进行调试输出或文件写入。这些函数最终会调用 `vfprintf`。

   ```c
   // NDK 代码示例
   #include <stdio.h>
   #include <android/log.h>

   void myNativeFunction(int value) {
       printf("Native value: %d\n", value); // 最终会调用 vfprintf
       __android_log_print(ANDROID_LOG_DEBUG, "MyTag", "NDK value: %d", value); // 最终会调用 vfprintf
   }
   ```

* **系统服务:**  Android 的各种系统服务（例如 SurfaceFlinger, AudioFlinger 等）在进行调试或错误报告时，也会使用格式化输出。

**libc 函数的功能实现细节：**

以下是一些在 `vfprintf.cpp` 中使用或涉及到的 libc 函数的实现细节：

1. **`strlen(cp)` / `strnlen(cp, prec)`:** 用于计算字符串的长度。`strlen` 计算以 null 结尾的字符串的长度，而 `strnlen` 计算字符串的长度，但不超过指定的 `prec` 值。
   * **实现：**  通常是通过循环遍历字符串，直到遇到 null 终止符 (`\0`) 或达到指定的长度限制。

2. **`wcrtomb(buf, (wchar_t)GETARG(wint_t), &mbs)`:** 将一个宽字符转换为多字节字符序列，并存储到 `buf` 中。`mbs` 是一个 `mbstate_t` 结构体，用于记录转换状态。
   * **实现：**  依赖于当前的 locale 设置。根据字符的编码方式（例如 UTF-8），将宽字符转换为对应的字节序列。

3. **`wcsconv(wcp, prec)`:** (这是一个在 bionic 中实现的辅助函数，不是标准 libc 函数)  很可能用于将宽字符串转换为多字节字符串。`prec` 可能限制转换的字符数。
   * **实现：**  内部会循环调用类似 `wcrtomb` 的函数，将宽字符串中的每个字符转换为多字节字符，直到遇到 null 终止符或达到长度限制。

4. **`mbsconv(dtoaresult, -1)`:** (这也是 bionic 中实现的辅助函数) 很可能用于将一个以 null 结尾的多字节字符串复制到一个新分配的缓冲区中。参数 `-1` 可能表示复制整个字符串。
   * **实现：**  先计算输入字符串的长度，然后分配足够大小的内存，并将字符串内容复制到新分配的内存中。

5. **`strerror_r(caller_errno, buf, sizeof(buf))`:** 获取与给定的错误码 `caller_errno` 相关的错误消息，并将结果存储到 `buf` 中，`sizeof(buf)` 是缓冲区的大小。这是一个线程安全的版本。
   * **实现：**  根据 `errno` 的值，返回对应的错误字符串。在多线程环境下，它需要确保线程安全，可能通过使用线程局部存储或其他同步机制。

6. **`__hdtoa`, `__hldtoa`, `__dtoa`, `__ldtoa`:** (这些是 bionic 中实现的辅助函数，用于浮点数到 ASCII 的转换 - double to ASCII)。它们将浮点数 (`double` 或 `long double`) 转换为字符串表示形式。这些函数处理不同的精度和格式要求。
   * **实现：**  这是一个复杂的算法，涉及到将浮点数的二进制表示转换为十进制表示，并处理舍入、精度、指数等。不同的函数可能针对不同的格式（例如，科学计数法或普通小数形式）。

7. **`exponent(expstr, expt - 1, expchar)`:** (也是 bionic 中的辅助函数) 用于生成浮点数的指数部分字符串，例如 "e+03"。
   * **实现：**  将指数值格式化为字符串，并根据 `expchar`（'e' 或 'E'）添加指数符号。

**涉及 dynamic linker 的功能：**

`vfprintf.cpp` 本身不直接涉及 dynamic linker 的功能。但是，作为 `libc.so` 的一部分，它的代码会被动态链接器加载到进程的地址空间。

**SO 布局样本：**

假设一个简单的 Android 应用，它链接了 `libc.so`。`libc.so` 会被加载到进程的某个地址空间。

```
[进程地址空间布局]
0x...000 - 0x...FFF  可执行文件 (app_process 或 zygote)
0x...000 - 0x...FFF  libdl.so (动态链接器)
0x...000 - 0x...FFF  libc.so
    ...
    [vfprintf 函数代码位于 libc.so 的 .text 段]
    ...
0x...000 - 0x...FFF  libm.so (math library)
0x...000 - 0x...FFF  lib的其他依赖库
...
```

**链接的处理过程：**

1. **编译时：** 当你编译包含 `printf` 或其他 `vfprintf` 相关调用的代码时，编译器会生成对 `vfprintf` 函数的未定义引用。
2. **链接时：** 链接器（在 Android 上通常是 `lld`）会查找 `vfprintf` 函数的定义。由于 `vfprintf` 位于 `libc.so` 中，链接器会将你的可执行文件或共享库与 `libc.so` 链接起来。这涉及到在你的可执行文件或共享库的 `.dynamic` 段中添加 `libc.so` 的依赖信息。
3. **运行时：** 当你的应用程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
    * 加载可执行文件到内存。
    * 解析可执行文件的 `.dynamic` 段，找到依赖的共享库 (`libc.so`)。
    * 加载 `libc.so` 到进程的地址空间。
    * **符号解析和重定位：**  动态链接器会解析可执行文件中对 `vfprintf` 的未定义引用，并在 `libc.so` 中找到 `vfprintf` 的符号定义。然后，它会更新可执行文件中的调用地址，使其指向 `libc.so` 中 `vfprintf` 函数的实际地址。这个过程称为重定位。

**逻辑推理和假设输入输出：**

假设格式字符串为 `"%d + %d = %d"`，参数列表为 `5, 3, 8`。

* **输入:** `fp` 指向标准输出，`fmt0` 为 `"%d + %d = %d"`, `ap` 包含整数 `5`, `3`, `8`。
* **处理过程:**
    * 解析 `%d`，从 `ap` 中获取第一个参数 `5`，并将其转换为字符串 "5"。
    * 输出 "5"。
    * 输出 " + "。
    * 解析 `%d`，从 `ap` 中获取第二个参数 `3`，并将其转换为字符串 "3"。
    * 输出 "3"。
    * 输出 " = "。
    * 解析 `%d`，从 `ap` 中获取第三个参数 `8`，并将其转换为字符串 "8"。
    * 输出 "8"。
* **输出:**  在标准输出上打印 "5 + 3 = 8"。

**用户或编程常见的使用错误：**

1. **格式字符串与参数类型不匹配：**
   ```c
   int num = 10;
   printf("Number: %s\n", num); // 错误：期望字符串，但提供了整数
   ```
   **后果：**  可能导致程序崩溃、输出乱码或安全漏洞。

2. **参数数量不足：**
   ```c
   printf("Value 1: %d, Value 2: %d\n", 10); // 错误：缺少第二个参数
   ```
   **后果：**  读取栈上未初始化的数据，导致不可预测的结果。

3. **缓冲区溢出 (使用 `sprintf` 等时)：**
   ```c
   char buffer[10];
   sprintf(buffer, "This is a very long string: %s", "AAAAAAAAAAAAAAAAAAAA"); // 错误：字符串太长，超出缓冲区大小
   ```
   **后果：**  覆盖栈上的数据，可能导致程序崩溃或安全漏洞。应该使用 `snprintf` 来限制输出长度。

4. **使用 `%n` 格式说明符：**
   ```c
   int count;
   printf("Hello%n\n", &count); // 错误：存在安全风险
   ```
   **后果：**  允许格式字符串写入内存，可能被恶意利用。Android 的 `vfprintf` 明确禁用了 `%n`。

5. **忘记处理返回值：**  `printf` 和 `fprintf` 返回写入的字符数，如果发生错误则返回负数。忽略返回值可能导致无法检测到写入错误。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤：**

**Android Framework 到 `vfprintf` 的路径 (以 `Log.d` 为例):**

1. **Java 层:**  应用程序调用 `android.util.Log.d(String tag, String msg, Object... args)`。
2. **Native 层桥接:**  `Log.d` 方法最终会调用到 native 层的 `android_util_Log_println_native` 函数 (位于 `libandroid_runtime.so`)。
3. **`__android_log_print`:**  `android_util_Log_println_native` 会调用 Bionic 库提供的 `__android_log_print` 函数 (位于 `libc.so`)。
4. **`vfprintf`:**  `__android_log_print` 内部会调用 `vfprintf` 或类似的函数将格式化的日志消息写入到 logcat。

**NDK 到 `vfprintf` 的路径 (以 `printf` 为例):**

1. **NDK C/C++ 代码:**  NDK 开发者直接调用 `printf`, `fprintf` 等 C 标准库函数。
2. **`printf` 实现:**  `printf` 函数 (位于 `libc.so`) 内部会调用 `vfprintf` 将格式化输出发送到标准输出。

**Frida Hook 示例：**

可以使用 Frida hook 这些函数来观察参数和执行流程。

```python
import frida
import sys

package_name = "your.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Payload: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "vfprintf"), {
    onEnter: function(args) {
        var fp = new NativePointer(args[0]);
        var fmt = Memory.readUtf8String(args[1]);
        var ap = args[2];

        // 打印文件指针（可能需要进一步解析）
        console.log("[vfprintf] fp: " + fp);
        console.log("[vfprintf] format: " + fmt);

        // 尝试读取部分参数 (需要根据格式字符串来解析)
        if (fmt.includes("%d")) {
            console.log("[vfprintf] arg1 (int): " + Memory.readInt(ap));
            // 注意：va_list 的处理比较复杂，这里只是一个简单的示例
        }
        if (fmt.includes("%s")) {
            console.log("[vfprintf] arg1 (string): " + Memory.readUtf8String(Memory.readPointer(ap)));
        }
    },
    onLeave: function(retval) {
        console.log("[vfprintf] return: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "__android_log_print"), {
    onEnter: function(args) {
        var prio = args[0];
        var tag = Memory.readUtf8String(args[1]);
        var fmt = Memory.readUtf8String(args[2]);
        // va_list 处理类似 vfprintf

        console.log("[__android_log_print] prio: " + prio);
        console.log("[__android_log_print] tag: " + tag);
        console.log("[__android_log_print] format: " + fmt);
    }
});

// Hook printf (可选)
Interceptor.attach(Module.findExportByName("libc.so", "printf"), {
    onEnter: function(args) {
        var fmt = Memory.readUtf8String(args[0]);
        console.log("[printf] format: " + fmt);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. 将上面的 Python 代码保存为 `hook_vfprintf.py`。
2. 将 `your.package.name` 替换为你想要调试的 Android 应用的包名。
3. 确保你的 Android 设备已连接并通过 USB 调试授权。
4. 运行 Frida 服务 (`frida-server`) 在你的 Android 设备上。
5. 运行 Python 脚本：`python hook_vfprintf.py`
6. 在你的 Android 应用中执行会产生日志输出的操作。
7. Frida 会拦截对 `vfprintf` 和 `__android_log_print` 的调用，并打印出相关信息，例如文件指针、格式字符串和部分参数。

这个 Frida 脚本提供了一个基本的调试框架，你可以根据需要扩展它来解析更复杂的格式字符串和参数。记住 `va_list` 的处理在不同的架构和编译器中可能有所不同，需要仔细处理才能正确读取参数。

### 提示词
```
这是目录为bionic/libc/stdio/vfprintf.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*	$OpenBSD: vfprintf.c,v 1.71 2016/01/04 15:47:47 schwarze Exp $	*/
/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define CHAR_TYPE char
#define FUNCTION_NAME __vfprintf
#define CHAR_TYPE_STRLEN strlen
#define CHAR_TYPE_STRNLEN strnlen
#define CHAR_TYPE_INF "INF"
#define CHAR_TYPE_inf "inf"
#define CHAR_TYPE_NAN "NAN"
#define CHAR_TYPE_nan "nan"
#define CHAR_TYPE_ORIENTATION ORIENT_BYTES

#define PRINT(ptr, len)                          \
  do {                                           \
    iovp->iov_base = (void*)(ptr);               \
    iovp->iov_len = (len);                       \
    uio.uio_resid += (len);                      \
    iovp++;                                      \
    if (++uio.uio_iovcnt >= NIOV) {              \
      if (helpers::sprint(fp, &uio)) goto error; \
      iovp = iov;                                \
    }                                            \
  } while (0)

#define FLUSH()                                                 \
  do {                                                          \
    if (uio.uio_resid && helpers::sprint(fp, &uio)) goto error; \
    uio.uio_iovcnt = 0;                                         \
    iovp = iov;                                                 \
  } while (0)

#include "printf_common.h"

int FUNCTION_NAME(FILE* fp, const CHAR_TYPE* fmt0, va_list ap) {
  int caller_errno = errno;
  int n, n2;
  CHAR_TYPE* cp;            /* handy char pointer (short term usage) */
  CHAR_TYPE sign;           /* sign prefix (' ', '+', '-', or \0) */
  int flags;           /* flags as above */
  int ret;             /* return value accumulator */
  int width;           /* width from format (%8d), or 0 */
  int prec;            /* precision from format; <0 for N/A */
  /*
   * We can decompose the printed representation of floating
   * point numbers into several parts, some of which may be empty:
   *
   * [+|-| ] [0x|0X] MMM . NNN [e|E|p|P] [+|-] ZZ
   *    A       B     ---C---      D       E   F
   *
   * A:	'sign' holds this value if present; '\0' otherwise
   * B:	ox[1] holds the 'x' or 'X'; '\0' if not hexadecimal
   * C:	cp points to the string MMMNNN.  Leading and trailing
   *	zeros are not in the string and must be added.
   * D:	expchar holds this character; '\0' if no exponent, e.g. %f
   * F:	at least two digits for decimal, at least one digit for hex
   */
  char* decimal_point = nullptr;
  int signflag; /* true if float is negative */
  union {       /* floating point arguments %[aAeEfFgG] */
    double dbl;
    long double ldbl;
  } fparg;
  int expt;                   /* integer value of exponent */
  char expchar;               /* exponent character: [eEpP\0] */
  char* dtoaend;              /* pointer to end of converted digits */
  int expsize;                /* character count for expstr */
  int lead;                   /* sig figs before decimal or group sep */
  int ndig;                   /* actual number of digits returned by dtoa */
  CHAR_TYPE expstr[MAXEXPDIG + 2]; /* buffer for exponent string: e+ZZZ */
  char* dtoaresult = nullptr;

  uintmax_t _umax;             /* integer arguments %[diouxX] */
  enum { BIN, OCT, DEC, HEX } base; /* base for %[bBdiouxX] conversion */
  int dprec;                   /* a copy of prec if %[bBdiouxX], 0 otherwise */
  int realsz;                  /* field size expanded by dprec */
  int size;                    /* size of converted field or string */
  const char* xdigs;           /* digits for %[xX] conversion */
#define NIOV 8
  struct __suio uio;       /* output information: summary */
  struct __siov iov[NIOV]; /* ... and individual io vectors */
  struct __siov* iovp; /* for PRINT macro */
  CHAR_TYPE buf[BUF];           /* buffer with space for digits of uintmax_t */
  CHAR_TYPE ox[2];              /* space for 0x; ox[1] is either x, X, or \0 */
  union arg* argtable;     /* args, built due to positional arg */
  union arg statargtable[STATIC_ARG_TBL_SIZE];
  size_t argtablesiz;
  int nextarg;   /* 1-based argument index */
  va_list orgap; /* original argument pointer */
  CHAR_TYPE* convbuf; /* buffer for wide/multibyte conversion */

  /*
   * Choose PADSIZE to trade efficiency vs. size.  If larger printf
   * fields occur frequently, increase PADSIZE and make the initialisers
   * below longer.
   */
#define PADSIZE 16 /* pad chunk size */
  static const CHAR_TYPE blanks[PADSIZE] = {
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '
  };
  static const CHAR_TYPE zeroes[PADSIZE] = {
    '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
  };

  static const char xdigs_lower[] = "0123456789abcdef";
  static const char xdigs_upper[] = "0123456789ABCDEF";

  _SET_ORIENTATION(fp, CHAR_TYPE_ORIENTATION);

  // Writing "" to a read only file returns EOF, not 0.
  if (cantwrite(fp)) {
    errno = EBADF;
    return EOF;
  }

  // Optimize writes to stderr and other unbuffered files).
  if ((fp->_flags & (__SNBF | __SWR | __SRW)) == (__SNBF | __SWR) && fp->_file >= 0) {
    return (__sbprintf(fp, fmt0, ap));
  }

  CHAR_TYPE* fmt = const_cast<CHAR_TYPE*>(fmt0);
  argtable = nullptr;
  nextarg = 1;
  va_copy(orgap, ap);
  uio.uio_iov = iovp = iov;
  uio.uio_resid = 0;
  uio.uio_iovcnt = 0;
  ret = 0;
  convbuf = nullptr;

  /*
   * Scan the format for conversions (`%' character).
   */
  for (;;) {
    int ch;
    for (cp = fmt; (ch = *fmt) != '\0' && ch != '%'; fmt++) continue;
    if (fmt != cp) {
      ptrdiff_t m = fmt - cp;
      if (m < 0 || m > INT_MAX - ret) goto overflow;
      PRINT(cp, m);
      ret += m;
    }
    if (ch == '\0') goto done;
    fmt++; /* skip over '%' */

    flags = 0;
    dprec = 0;
    width = 0;
    prec = -1;
    sign = '\0';
    ox[1] = '\0';

  rflag:
    ch = *fmt++;
  reswitch:
    switch (ch) {
      case ' ':
        /*
         * ``If the space and + flags both appear, the space
         * flag will be ignored.''
         *	-- ANSI X3J11
         */
        if (!sign) sign = ' ';
        goto rflag;
      case '#':
        flags |= ALT;
        goto rflag;
      case '\'':
        /* grouping not implemented */
        goto rflag;
      case '*':
        /*
         * ``A negative field width argument is taken as a
         * - flag followed by a positive field width.''
         *	-- ANSI X3J11
         * They don't exclude field widths read from args.
         */
        GETASTER(width);
        if (width >= 0) goto rflag;
        if (width == INT_MIN) goto overflow;
        width = -width;
        __BIONIC_FALLTHROUGH;
      case '-':
        flags |= LADJUST;
        goto rflag;
      case '+':
        sign = '+';
        goto rflag;
      case '.':
        if ((ch = *fmt++) == '*') {
          GETASTER(n);
          prec = n < 0 ? -1 : n;
          goto rflag;
        }
        n = 0;
        while (is_digit(ch)) {
          APPEND_DIGIT(n, ch);
          ch = *fmt++;
        }
        if (ch == '$') {
          nextarg = n;
          if (argtable == nullptr) {
            argtable = statargtable;
            if (__find_arguments(fmt0, orgap, &argtable, &argtablesiz) == -1) {
              ret = -1;
              goto error;
            }
          }
          goto rflag;
        }
        prec = n;
        goto reswitch;
      case '0':
        /*
         * ``Note that 0 is taken as a flag, not as the
         * beginning of a field width.''
         *	-- ANSI X3J11
         */
        flags |= ZEROPAD;
        goto rflag;
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        n = 0;
        do {
          APPEND_DIGIT(n, ch);
          ch = *fmt++;
        } while (is_digit(ch));
        if (ch == '$') {
          nextarg = n;
          if (argtable == nullptr) {
            argtable = statargtable;
            if (__find_arguments(fmt0, orgap, &argtable, &argtablesiz) == -1) {
              ret = -1;
              goto error;
            }
          }
          goto rflag;
        }
        width = n;
        goto reswitch;
      case 'L':
        flags |= LONGDBL;
        goto rflag;
      case 'h':
        if (*fmt == 'h') {
          fmt++;
          flags |= CHARINT;
        } else {
          flags |= SHORTINT;
        }
        goto rflag;
      case 'j':
        flags |= MAXINT;
        goto rflag;
      case 'l':
        if (*fmt == 'l') {
          fmt++;
          flags |= LLONGINT;
        } else {
          flags |= LONGINT;
        }
        goto rflag;
      case 'q':
        flags |= LLONGINT;
        goto rflag;
      case 't':
        flags |= PTRINT;
        goto rflag;
      case 'z':
        flags |= SIZEINT;
        goto rflag;
      case 'B':
      case 'b':
        _umax = UARG();
        base = BIN;
        if (flags & ALT && _umax != 0) ox[1] = ch;
        goto nosign;
      case 'C':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'c':
        if (flags & LONGINT) {
          mbstate_t mbs;
          size_t mbseqlen;

          memset(&mbs, 0, sizeof(mbs));
          mbseqlen = wcrtomb(buf, (wchar_t)GETARG(wint_t), &mbs);
          if (mbseqlen == (size_t)-1) {
            ret = -1;
            goto error;
          }
          cp = buf;
          size = (int)mbseqlen;
        } else {
          *(cp = buf) = GETARG(int);
          size = 1;
        }
        sign = '\0';
        break;
      case 'D':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'd':
      case 'i':
        _umax = SARG();
signed_decimal:
        if ((intmax_t)_umax < 0) {
          _umax = -_umax;
          sign = '-';
        }
        base = DEC;
        goto number;
      case 'a':
      case 'A':
        if (ch == 'a') {
          ox[1] = 'x';
          xdigs = xdigs_lower;
          expchar = 'p';
        } else {
          ox[1] = 'X';
          xdigs = xdigs_upper;
          expchar = 'P';
        }
        if (prec >= 0) prec++;
        if (dtoaresult) __freedtoa(dtoaresult);
        if (flags & LONGDBL) {
          fparg.ldbl = GETARG(long double);
          dtoaresult = __hldtoa(fparg.ldbl, xdigs, prec, &expt, &signflag, &dtoaend);
          if (dtoaresult == nullptr) {
            errno = ENOMEM;
            goto error;
          }
        } else {
          fparg.dbl = GETARG(double);
          dtoaresult = __hdtoa(fparg.dbl, xdigs, prec, &expt, &signflag, &dtoaend);
          if (dtoaresult == nullptr) {
            errno = ENOMEM;
            goto error;
          }
        }
        if (prec < 0) prec = dtoaend - dtoaresult;
        if (expt == INT_MAX) ox[1] = '\0';
        goto fp_common;
      case 'e':
      case 'E':
        expchar = ch;
        if (prec < 0) /* account for digit before decpt */
          prec = DEFPREC + 1;
        else
          prec++;
        goto fp_begin;
      case 'f':
      case 'F':
        expchar = '\0';
        goto fp_begin;
      case 'g':
      case 'G':
        expchar = ch - ('g' - 'e');
        if (prec == 0) prec = 1;
      fp_begin:
        if (prec < 0) prec = DEFPREC;
        if (dtoaresult) __freedtoa(dtoaresult);
        if (flags & LONGDBL) {
          fparg.ldbl = GETARG(long double);
          dtoaresult = __ldtoa(&fparg.ldbl, expchar ? 2 : 3, prec, &expt, &signflag, &dtoaend);
          if (dtoaresult == nullptr) {
            errno = ENOMEM;
            goto error;
          }
        } else {
          fparg.dbl = GETARG(double);
          dtoaresult = __dtoa(fparg.dbl, expchar ? 2 : 3, prec, &expt, &signflag, &dtoaend);
          if (dtoaresult == nullptr) {
            errno = ENOMEM;
            goto error;
          }
          if (expt == 9999) expt = INT_MAX;
        }
      fp_common:
#if CHAR_TYPE_ORIENTATION == ORIENT_BYTES
        cp = dtoaresult;
#else
        free(convbuf);
        cp = convbuf = helpers::mbsconv(dtoaresult, -1);
        if (cp == nullptr) goto error;
#endif
        if (signflag) sign = '-';
        if (expt == INT_MAX) { /* inf or nan */
          if (*cp == 'N') {
            cp = const_cast<CHAR_TYPE*>((ch >= 'a') ? CHAR_TYPE_nan : CHAR_TYPE_NAN);
          } else {
            cp = const_cast<CHAR_TYPE*>((ch >= 'a') ? CHAR_TYPE_inf : CHAR_TYPE_INF);
          }
          size = 3;
          flags &= ~ZEROPAD;
          break;
        }
        flags |= FPT;
        ndig = dtoaend - dtoaresult;
        if (ch == 'g' || ch == 'G') {
          if (expt > -4 && expt <= prec) {
            /* Make %[gG] smell like %[fF] */
            expchar = '\0';
            if (flags & ALT)
              prec -= expt;
            else
              prec = ndig - expt;
            if (prec < 0) prec = 0;
          } else {
            /*
             * Make %[gG] smell like %[eE], but
             * trim trailing zeroes if no # flag.
             */
            if (!(flags & ALT)) prec = ndig;
          }
        }
        if (expchar) {
          expsize = exponent(expstr, expt - 1, expchar);
          size = expsize + prec;
          if (prec > 1 || flags & ALT) ++size;
        } else {
          /* space for digits before decimal point */
          if (expt > 0)
            size = expt;
          else /* "0" */
            size = 1;
          /* space for decimal pt and following digits */
          if (prec || flags & ALT) size += prec + 1;
          lead = expt;
        }
        break;
      case 'n':
        __fortify_fatal("%%n not allowed on Android");
      case 'm':
        if (flags & ALT) {
          cp = const_cast<char*>(strerrorname_np(caller_errno));
          if (cp == nullptr) {
            _umax = caller_errno;
            goto signed_decimal;
          }
        } else {
          cp = strerror_r(caller_errno, buf, sizeof(buf));
        }
        goto string;
      case 'O':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'o':
        _umax = UARG();
        base = OCT;
        goto nosign;
      case 'p':
        /*
         * ``The argument shall be a pointer to void.  The
         * value of the pointer is converted to a sequence
         * of printable characters, in an implementation-
         * defined manner.''
         *	-- ANSI X3J11
         */
        _umax = (u_long)GETARG(void*);
        base = HEX;
        xdigs = xdigs_lower;
        ox[1] = 'x';
        goto nosign;
      case 'S':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 's':
        if (flags & LONGINT) {
          wchar_t* wcp;

          free(convbuf);
          convbuf = nullptr;
          if ((wcp = GETARG(wchar_t*)) == nullptr) {
            cp = const_cast<char*>("(null)");
          } else {
            convbuf = helpers::wcsconv(wcp, prec);
            if (convbuf == nullptr) {
              ret = -1;
              goto error;
            }
            cp = convbuf;
          }
        } else if ((cp = GETARG(char*)) == nullptr) {
          cp = const_cast<char*>("(null)");
        }
  string:
        if (prec >= 0) {
          size = CHAR_TYPE_STRNLEN(cp, prec);
        } else {
          size_t len;

          if ((len = CHAR_TYPE_STRLEN(cp)) > INT_MAX) goto overflow;
          size = (int)len;
        }
        sign = '\0';
        break;
      case 'U':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'u':
        _umax = UARG();
        base = DEC;
        goto nosign;
      case 'w': {
        n = 0;
        bool fast = false;
        ch = *fmt++;
        if (ch == 'f') {
          fast = true;
          ch = *fmt++;
        }
        while (is_digit(ch)) {
          APPEND_DIGIT(n, ch);
          ch = *fmt++;
        }
        flags |= helpers::w_to_flag(n, fast);
        goto reswitch;
      }
      case 'X':
        xdigs = xdigs_upper;
        goto hex;
      case 'x':
        xdigs = xdigs_lower;
      hex:
        _umax = UARG();
        base = HEX;
        /* leading 0x/X only if non-zero */
        if (flags & ALT && _umax != 0) ox[1] = ch;

        /* unsigned conversions */
      nosign:
        sign = '\0';
        /*
         * ``... diouXx conversions ... if a precision is
         * specified, the 0 flag will be ignored.''
         *	-- ANSI X3J11
         */
      number:
        if ((dprec = prec) >= 0) flags &= ~ZEROPAD;

        /*
         * ``The result of converting a zero value with an
         * explicit precision of zero is no characters.''
         *	-- ANSI X3J11
         */
        cp = buf + BUF;
        if (_umax != 0 || prec != 0) {
          /*
           * Unsigned mod is hard, and unsigned mod
           * by a constant is easier than that by
           * a variable; hence this switch.
           */
          switch (base) {
            case BIN:
              do {
                *--cp = to_char(_umax & 1);
                _umax >>= 1;
              } while (_umax);
              break;

            case OCT:
              do {
                *--cp = to_char(_umax & 7);
                _umax >>= 3;
              } while (_umax);
              /* handle octal leading 0 */
              if (flags & ALT && *cp != '0') *--cp = '0';
              break;

            case DEC:
              /* many numbers are 1 digit */
              while (_umax >= 10) {
                *--cp = to_char(_umax % 10);
                _umax /= 10;
              }
              *--cp = to_char(_umax);
              break;

            case HEX:
              do {
                *--cp = xdigs[_umax & 15];
                _umax >>= 4;
              } while (_umax);
              break;

            default:
              abort();
          }
        }
        size = buf + BUF - cp;
        if (size > BUF) abort(); /* should never happen */
        break;
      default: /* "%?" prints ?, unless ? is NUL */
        if (ch == '\0') goto done;
        /* pretend it was %c with argument ch */
        cp = buf;
        *cp = ch;
        size = 1;
        sign = '\0';
        break;
    }

    /*
     * All reasonable formats wind up here.  At this point, `cp'
     * points to a string which (if not flags&LADJUST) should be
     * padded out to `width' places.  If flags&ZEROPAD, it should
     * first be prefixed by any sign or other prefix; otherwise,
     * it should be blank padded before the prefix is emitted.
     * After any left-hand padding and prefixing, emit zeroes
     * required by a decimal %[bBdiouxX] precision, then print the
     * string proper, then emit zeroes required by any leftover
     * floating precision; finally, if LADJUST, pad with blanks.
     *
     * Compute actual size, so we know how much to pad.
     * size excludes decimal prec; realsz includes it.
     */
    realsz = dprec > size ? dprec : size;
    if (sign) realsz++;
    if (ox[1]) realsz += 2;

    /* right-adjusting blank padding */
    if ((flags & (LADJUST | ZEROPAD)) == 0) PAD(width - realsz, blanks);

    /* prefix */
    if (sign) PRINT(&sign, 1);
    if (ox[1]) { /* ox[1] is either x, X, or \0 */
      ox[0] = '0';
      PRINT(ox, 2);
    }

    /* right-adjusting zero padding */
    if ((flags & (LADJUST | ZEROPAD)) == ZEROPAD) PAD(width - realsz, zeroes);

    /* leading zeroes from decimal precision */
    PAD(dprec - size, zeroes);

    /* the string or number proper */
    if ((flags & FPT) == 0) {
      PRINT(cp, size);
    } else { /* glue together f_p fragments */
      if (decimal_point == nullptr) decimal_point = nl_langinfo(RADIXCHAR);
      if (!expchar) { /* %[fF] or sufficiently short %[gG] */
        CHAR_TYPE* end = cp + ndig;
        if (expt <= 0) {
          PRINT(zeroes, 1);
          if (prec || flags & ALT) PRINT(decimal_point, 1);
          PAD(-expt, zeroes);
          /* already handled initial 0's */
          prec += expt;
        } else {
          PRINTANDPAD(cp, end, lead, zeroes);
          cp += lead;
          if (prec || flags & ALT) PRINT(decimal_point, 1);
        }
        PRINTANDPAD(cp, end, prec, zeroes);
      } else { /* %[eE] or sufficiently long %[gG] */
        if (prec > 1 || flags & ALT) {
          buf[0] = *cp++;
          buf[1] = *decimal_point;
          PRINT(buf, 2);
          PRINT(cp, ndig - 1);
          PAD(prec - ndig, zeroes);
        } else { /* XeYYY */
          PRINT(cp, 1);
        }
        PRINT(expstr, expsize);
      }
    }
    /* left-adjusting padding (always blank) */
    if (flags & LADJUST) PAD(width - realsz, blanks);

    /* finally, adjust ret */
    if (width < realsz) width = realsz;
    if (width > INT_MAX - ret) goto overflow;
    ret += width;

    FLUSH(); /* copy out the I/O vectors */
  }
done:
  FLUSH();
error:
  va_end(orgap);
  if (__sferror(fp)) ret = -1;
  goto finish;

overflow:
  errno = ENOMEM;
  ret = -1;

finish:
  free(convbuf);
  if (dtoaresult) __freedtoa(dtoaresult);
  if (argtable != nullptr && argtable != statargtable) {
    munmap(argtable, argtablesiz);
    argtable = nullptr;
  }
  return (ret);
}
```