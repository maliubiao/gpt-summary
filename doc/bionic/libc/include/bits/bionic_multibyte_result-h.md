Response:
Let's break down the thought process to answer the request about `bionic_multibyte_result.h`.

1. **Understanding the Core Request:** The primary goal is to understand the purpose of the `bionic_multibyte_result.h` header file and its connection to Android's Bionic libc. The request also asks for details about function implementation, dynamic linking, error handling, usage within Android, and debugging techniques.

2. **Initial Analysis of the Header File:** The first step is to read the provided header file carefully. Key observations:
    * It defines an `enum` called anonymously that inherits from `size_t`.
    * The enum defines three named constants: `BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE`, `BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE`, and `BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED`.
    * These constants are assigned negative values represented as unsigned long integers (`-1UL`, `-2UL`, `-3UL`).
    * The comments within the header clearly link these values to multibyte conversion APIs as defined by the C standard (C23 7.30.1).

3. **Identifying the Functionality:** Based on the header's comments and the names of the constants, the core functionality is related to *multibyte character conversion*. This immediately brings to mind functions like `mbrtoc16`, `mbrtoc32`, `mbtowc`, `wctomb`, etc., which handle the conversion between different character encodings (like UTF-8) and wide character representations (like UTF-16 or UTF-32).

4. **Connecting to Android:** Since this file is part of Bionic, Android's C library, it directly influences how Android handles text and character encodings. Android applications and the Android framework often need to process text in various encodings.

5. **Explaining Each Constant's Purpose:**  The comments within the header are already quite descriptive. I'd rephrase them slightly for clarity and add context:
    * `ILLEGAL_SEQUENCE`:  Indicates an invalid sequence of bytes that cannot form a valid character.
    * `INCOMPLETE_SEQUENCE`: Means a partial, but potentially valid, character sequence was encountered. More bytes are needed.
    * `NO_BYTES_CONSUMED`: Signals that a previous successful decoding occurred, and the function didn't process new input bytes. The example of `mbrtoc16` returning a low surrogate is a crucial illustration.

6. **Addressing libc Function Implementation:** The header file *itself* doesn't implement any libc functions. It *defines constants* used by those functions. Therefore, the explanation should focus on *how* these constants are used within functions like `mbrtoc16`. I would describe the general flow of such functions: they take a multibyte string, try to decode a character, and then return the number of bytes consumed or one of these error codes.

7. **Dynamic Linker and SO Layout:** This header file is unlikely to directly involve dynamic linking in a significant way. It defines constants, not code that needs relocation. However, since it's part of libc, it *is* present in the libc.so library. A simple SO layout example should suffice, showing libc.so and how application code links against it. The linking process involves resolving symbols, but these constants are likely used inline or as part of the function's return value. No complex dynamic linking scenario is directly triggered by *this* header.

8. **Logic Reasoning (Hypothetical Input/Output):**  This is best illustrated by an example using a hypothetical `mbrtoc16` call. I would choose examples that demonstrate each of the result constants:
    * Valid UTF-8 sequence -> positive return value (bytes consumed).
    * Invalid UTF-8 -> `BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE`.
    * Incomplete UTF-8 -> `BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE`.
    * Call after a low surrogate -> `BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED`.

9. **Common Usage Errors:**  Focus on mistakes programmers might make when using the multibyte conversion functions. Not checking return values is a major one. Incorrect buffer sizes and not handling incomplete sequences are also common errors.

10. **Android Framework/NDK and Frida Hooking:** This requires tracing how these low-level libc functions are ultimately called.
    * **Framework:**  Android framework components (like `TextView` rendering) often deal with text and may indirectly use these functions. The path is usually high-level Java code -> JNI calls -> native code in frameworks or libraries -> libc functions.
    * **NDK:** NDK developers directly use libc functions.
    * **Frida:**  Provide concrete Frida examples of hooking functions like `mbrtoc16` and observing the return values, demonstrating how these constants are used in practice. Highlighting how to inspect arguments and return values is key.

11. **Structure and Language:**  Organize the answer logically, using clear headings. Use Chinese as requested. Explain concepts clearly and avoid overly technical jargon where possible. Provide code examples to illustrate points.

**Self-Correction/Refinement during the Process:**

* **Initial Thought:**  Maybe this header file is more complex than it looks.
* **Correction:**  Realized it primarily defines constants. The complexity lies in the *usage* of these constants by other functions.

* **Initial Thought:**  Need a detailed explanation of dynamic linking.
* **Correction:**  The direct involvement with dynamic linking is minimal. Focus on the presence in `libc.so` and the basic linking concept.

* **Initial Thought:** Focus heavily on the bitwise representation of the negative numbers.
* **Correction:** While technically accurate, the *meaning* of the constants is more important for understanding. Briefly mention the `-1UL` representation but don't dwell on the bitwise details unless explicitly asked.

By following these steps and iteratively refining the explanations, the comprehensive answer provided previously can be constructed. The key is to understand the core purpose of the header file and then branch out to its implications within the broader Android ecosystem.
这个目录下的 `bionic_multibyte_result.handroid.h` 文件定义了一组用于表示多字节字符转换 API 返回值的魔术数字常量。它属于 Android 的 Bionic C 库，主要用于处理字符编码转换过程中可能出现的错误或特殊情况。

**功能:**

该文件定义了一个匿名枚举类型，其中包含了以下常量：

* **`BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE` (-1UL):** 表示遇到了非法的多字节字符序列。这说明读取到的字节无法构成一个有效的 Unicode 字符，也不是一个部分有效的字符。
* **`BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE` (-2UL):** 表示读取到的字节可能可以构成一个有效的 Unicode 字符，但当前的序列不完整。后续的调用可能会完成该字符的解码。
* **`BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED` (-3UL):** 表示当前调用的输出是之前成功解码的结果，没有消耗新的字节。这种情况常见于 `mbrtoc16` 函数返回代理对中的低位代理项时。

**与 Android 功能的关系及举例说明:**

这个头文件直接服务于 Android 系统处理文本和字符编码转换的需求。Android 应用和系统组件经常需要处理不同编码的文本数据，例如 UTF-8, UTF-16 等。Bionic libc 提供的多字节转换 API（如 `mbrtoc16`, `mbrtoc32`, `c16rtomb`, `c32rtomb` 等）会使用这些返回值来告知调用者转换的结果。

**举例说明:**

假设一个 Android 应用需要将 UTF-8 编码的字符串转换为 UTF-16 编码。它可能会使用 `mbrtoc16` 函数。

```c
#include <wchar.h>
#include <locale.h>
#include <stdio.h>
#include <stdint.h>
#include <bits/bionic_multibyte_result.h> // 包含头文件

int main() {
  setlocale(LC_ALL, "en_US.UTF-8"); // 设置本地化信息，支持 UTF-8

  const char* utf8_str = "你好"; // UTF-8 编码的字符串
  char16_t utf16_buf[3]; // 存储 UTF-16 字符的缓冲区
  mbstate_t ps;
  size_t result;
  const char* ptr = utf8_str;

  memset(&ps, 0, sizeof(ps)); // 初始化转换状态

  // 转换第一个字符 "你"
  result = mbrtoc16(utf16_buf, ptr, 3, &ps);
  if (result == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
    printf("遇到非法字符序列\n");
  } else if (result == BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE) {
    printf("字符序列不完整\n");
  } else if (result > 0) {
    printf("成功转换 %zu 字节，UTF-16 值为 0x%X\n", result, utf16_buf[0]);
    ptr += result; // 移动指针到下一个字符
  }

  // 转换第二个字符 "好"
  result = mbrtoc16(utf16_buf + 1, ptr, 3, &ps);
  if (result == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
    printf("遇到非法字符序列\n");
  } else if (result == BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE) {
    printf("字符序列不完整\n");
  } else if (result > 0) {
    printf("成功转换 %zu 字节，UTF-16 值为 0x%X\n", result, utf16_buf[1]);
  }

  return 0;
}
```

在这个例子中，如果 `mbrtoc16` 函数返回了 `BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE`，则说明输入的 UTF-8 序列中存在无效的字节组合。如果返回了 `BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE`，则说明当前的字节还不足以构成一个完整的 UTF-8 字符。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并没有实现任何 libc 函数，它只是定义了常量。真正实现多字节转换功能的是诸如 `mbrtoc16`, `mbrtoc32`, `c16rtomb`, `c32rtomb`, `mbtowc`, `wctomb` 等函数。这些函数的具体实现比较复杂，通常涉及以下步骤：

1. **状态管理:**  多字节转换通常是状态相关的，例如处理 UTF-8 的 continuation bytes 或 UTF-16 的代理对。这些函数会维护一个 `mbstate_t` 结构来记录当前的转换状态。
2. **字节解析:**  函数会根据当前的编码规则（例如 UTF-8 的编码规则）逐个读取输入字节，并判断是否构成一个有效的字符序列。
3. **查表或计算:**  根据不同的编码，可能需要查表（例如字符到码点的映射表）或进行位运算来将多字节序列转换为对应的宽字符表示。
4. **错误处理:**  如果遇到非法的字节序列，函数会返回 `BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE`。如果输入的字节不足以构成一个完整的字符，函数会返回 `BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE`。
5. **输出写入:**  成功转换后，函数会将转换后的宽字符写入到输出缓冲区。

由于篇幅限制，无法详细解释每个函数的具体实现细节。Bionic libc 的源代码可以在 Android Open Source Project (AOSP) 中找到，可以查阅相关函数的实现代码来了解更多细节。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件定义的是常量，本身不涉及动态链接。但是，定义这些常量的 `libc.so` 库会被 Android 应用程序动态链接。

**SO 布局样本 (libc.so):**

```
libc.so:
    .text          # 存放代码段
        ... (mbrtoc16, mbrtoc32 等函数的实现代码) ...
    .rodata        # 存放只读数据
        ... (可能包含字符编码相关的查找表) ...
        _BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE: -1  # 这些常量会被定义在只读数据段
        _BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE: -2
        _BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED: -3
    .data          # 存放可读写数据
        ... (全局变量，例如本地化信息) ...
    .bss           # 存放未初始化的全局变量
        ...
    .dynsym        # 动态符号表
        mbrtoc16
        mbrtoc32
        ...
        _BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE
        _BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE
        _BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED
    .dynstr        # 动态字符串表
        "mbrtoc16"
        "mbrtoc32"
        ...
        "_BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE"
        "_BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE"
        "_BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED"
    .plt           # Procedure Linkage Table (过程链接表)
        ... (用于延迟绑定) ...
    .got           # Global Offset Table (全局偏移表)
        ... (存储全局变量的地址) ...
```

**链接的处理过程:**

1. **编译时:** 当应用程序的代码中包含了 `<bits/bionic_multibyte_result.h>` 并使用了相关的多字节转换函数时，编译器会生成对 `libc.so` 中相关符号的未解析引用。
2. **链接时:** 链接器会将应用程序的目标文件与必要的库（包括 `libc.so`）链接在一起。链接器会查找 `libc.so` 的动态符号表 (`.dynsym`)，找到 `mbrtoc16` 等函数的定义，并将应用程序中对这些函数的未解析引用指向 `libc.so` 中对应的代码地址。对于常量 `BIONIC_MULTIBYTE_RESULT_*`，它们通常会被内联使用，或者链接器会将应用程序中对这些常量的引用指向 `libc.so` 的 `.rodata` 段中存储的常量值。
3. **运行时:** 当应用程序启动时，Android 的动态链接器 (`linker`/`linker64`) 会加载 `libc.so` 到内存中。动态链接器会解析应用程序中对 `libc.so` 中函数的调用，并更新过程链接表 (`.plt`) 和全局偏移表 (`.got`)，确保函数调用能够跳转到正确的地址。

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们使用 `mbrtoc16` 函数将 UTF-8 编码的字符串转换为 UTF-16。

**假设输入:**

* `ptr`: 指向 UTF-8 编码的字符串 "你好" 的第一个字节。
* `n`:  输入缓冲区的剩余大小，假设足够大。
* `ps`: 指向一个初始化过的 `mbstate_t` 结构。
* `out`: 指向一个 `char16_t` 类型的输出缓冲区。

**预期输出 (多次调用):**

1. **第一次调用 (`ptr` 指向 "你" 的起始字节):**
   * 返回值: 大于 0 的值，表示成功转换的字节数（通常是 3）。
   * `out[0]`:  存储 "你" 的 UTF-16 编码值。
   * `ps`:  更新后的转换状态。

2. **第二次调用 (`ptr` 指向 "好" 的起始字节):**
   * 返回值: 大于 0 的值，表示成功转换的字节数（通常是 3）。
   * `out[1]`:  存储 "好" 的 UTF-16 编码值。
   * `ps`:  更新后的转换状态。

**假设输入错误:**

* `ptr`: 指向一个包含非法 UTF-8 序列的字符串，例如 `"\xC0\x80"` (这是一个 overlong UTF-8 序列)。
* `n`:  输入缓冲区的剩余大小。
* `ps`: 指向一个初始化过的 `mbstate_t` 结构。
* `out`: 指向一个 `char16_t` 类型的输出缓冲区。

**预期输出:**

* 返回值: `BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE` (-1UL)。
* `ps`:  可能会被更新，指示遇到了错误。
* `out`:  内容未定义。

**假设输入不完整:**

* `ptr`: 指向一个 UTF-8 字符的起始字节，但缓冲区末尾截断了该字符，例如，只想转换 "你" 的前两个字节。
* `n`:  输入缓冲区的剩余大小，不足以包含完整的 UTF-8 字符。
* `ps`: 指向一个初始化过的 `mbstate_t` 结构。
* `out`: 指向一个 `char16_t` 类型的输出缓冲区。

**预期输出:**

* 返回值: `BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE` (-2UL)。
* `ps`:  可能会被更新，指示需要更多字节。
* `out`:  内容未定义。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **未检查返回值:**  程序员可能会忘记检查 `mbrtoc16` 等函数的返回值，导致没有正确处理错误情况（如非法序列或不完整序列），从而可能导致程序崩溃或产生不可预测的结果。

   ```c
   // 错误示例：未检查返回值
   mbrtoc16(buf, ptr, n, &ps);
   // 假设 ptr 指向非法 UTF-8 序列，buf 的内容将是不确定的
   ```

2. **缓冲区溢出:**  输出缓冲区 `out` 的大小不足以容纳转换后的字符。

   ```c
   char16_t buf[1]; // 缓冲区太小
   const char* utf8_str = "你好";
   mbrtoc16(buf, utf8_str, 10, &ps); // "你" 占用一个 char16_t，但 "好" 无法写入
   ```

3. **未正确初始化 `mbstate_t`:**  对于需要维护转换状态的函数，必须正确初始化 `mbstate_t` 结构。如果未初始化，可能会导致转换结果错误。

   ```c
   mbstate_t ps; // 未初始化
   mbrtoc16(buf, ptr, n, &ps); // 可能产生错误结果
   ```

4. **错误地处理不完整序列:**  当 `mbrtoc16` 返回 `BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE` 时，程序员需要保存当前的转换状态，并在接收到更多输入后再次调用该函数。如果错误地跳过或重复处理，可能会导致数据丢失或错误解码。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 Bionic libc 的路径:**

1. **Java Framework:** Android Framework 的许多部分，例如处理文本显示、输入法等，最终会涉及到字符编码转换。这些操作通常在 Java 代码中发起。
2. **JNI 调用:** Java 代码会通过 Java Native Interface (JNI) 调用 Native 代码（通常是 C/C++ 代码）。
3. **Native Framework/Libraries:** 这些 Native 代码可能存在于 Android Framework 的 Native 组件中，或者是一些系统库。
4. **Bionic libc 函数调用:**  Native 代码最终会调用 Bionic libc 提供的多字节转换函数，例如 `mbrtoc16`, `mbtowc` 等。这些函数会使用 `bits/bionic_multibyte_result.h` 中定义的常量来返回结果。

**NDK 到 Bionic libc 的路径:**

1. **NDK 开发:** 使用 Android NDK 开发的应用程序可以直接调用 Bionic libc 提供的函数。
2. **C/C++ 代码:** NDK 代码中会包含 `<wchar.h>` 等头文件，并直接调用 `mbrtoc16` 等函数。

**Frida Hook 示例:**

可以使用 Frida 来 hook `mbrtoc16` 函数，观察其参数和返回值，从而理解 Android Framework 或 NDK 如何使用它。

```python
import frida
import sys

# 要 hook 的目标进程
package_name = "com.example.myapp" # 替换为你的应用包名

# Frida 脚本
hook_script = """
Interceptor.attach(Module.findExportByName("libc.so", "mbrtoc16"), {
    onEnter: function(args) {
        console.log("mbrtoc16 called!");
        console.log("  dest: " + args[0]);
        console.log("  src:  " + args[1]);
        console.log("  n:    " + args[2]);
        console.log("  ps:   " + args[3]);

        // 尝试读取部分输入字符串
        try {
            var srcPtr = ptr(args[1]);
            var len = parseInt(args[2]);
            if (len > 0) {
                console.log("  src string: " + srcPtr.readUtf8String(Math.min(len, 32))); // 读取最多 32 字节
            }
        } catch (e) {
            console.log("  Error reading src string: " + e);
        }
    },
    onLeave: function(retval) {
        console.log("mbrtoc16 returned: " + retval);
        if (retval == -1) {
            console.log("  Error: BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE");
        } else if (retval == -2) {
            console.log("  Error: BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE");
        } else if (retval == -3) {
            console.log("  Result: BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED");
        } else if (retval > 0) {
            console.log("  Bytes consumed: " + retval);
        }
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(hook_script)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, press Ctrl+C to exit.")
    sys.stdin.read()
except frida.common.RPCException as e:
    print(f"[-] RPCException: {e}")
except KeyboardInterrupt:
    print("[*] Detaching...")
    session.detach()
```

**使用步骤:**

1. **安装 Frida:** 确保你的电脑上安装了 Frida 和 Frida tools (`pip install frida-tools`).
2. **连接 Android 设备:**  确保你的 Android 设备通过 USB 连接到电脑，并且 adb 可用。设备需要 root 权限。
3. **启动目标应用:** 运行你想要调试的 Android 应用程序。
4. **运行 Frida 脚本:** 将上面的 Python 代码保存为 `hook_mbrtoc16.py`，然后在终端中运行 `python hook_mbrtoc16.py`，将 `com.example.myapp` 替换为你目标应用的包名。
5. **操作应用:**  在你的 Android 应用中执行一些会触发字符编码转换的操作，例如输入文本、显示包含特殊字符的内容等。
6. **观察输出:** Frida 会拦截对 `mbrtoc16` 函数的调用，并打印出函数的参数和返回值，包括返回的错误代码。

通过 Frida Hook，你可以观察到 `mbrtoc16` 函数何时被调用，传入了哪些参数（包括要转换的字符串和缓冲区大小），以及返回了什么值，从而理解 Android 系统或 NDK 应用是如何使用这些底层的多字节转换 API 的，以及如何处理不同的转换结果。

Prompt: 
```
这是目录为bionic/libc/include/bits/bionic_multibyte_result.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2023 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

/**
 * @file bits/bionic_multibyte_result.h
 * @brief Named values for the magic number return values of multibyte
 * conversion APIs defined by C.
 */

#include <sys/cdefs.h>

#include <stddef.h>

__BEGIN_DECLS

/**
 * @brief The error values defined by C for multibyte conversion APIs.
 *
 * Refer to C23 7.30.1 Restartable multibyte/wide character conversion functions
 * for more details.
 */
enum : size_t {
  /// @brief An encoding error occurred. The bytes read are not a valid unicode
  /// character, nor are they a partially valid character.
  BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE = -1UL,
#define BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE

  /// @brief The bytes read may produce a valid unicode character, but the
  /// sequence is incomplete. Future calls may complete the character.
  BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE = -2UL,
#define BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE

  /// @brief The output of the call was the result of a previous successful
  /// decoding. No new bytes were consumed.
  ///
  /// The common case for this return value is when mbrtoc16 returns the low
  /// surrogate of a pair.
  BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED = -3UL,
#define BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED
};

__END_DECLS

"""

```