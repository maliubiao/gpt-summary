Response:
Let's break down the thought process for analyzing the `mbrtoc16.cpp` file.

**1. Understanding the Goal:**

The primary request is to understand the functionality of `mbrtoc16.cpp`, focusing on its purpose, implementation details (especially libc functions), interactions with the dynamic linker (though this file doesn't directly interact with it), handling of surrogates, error handling, and how Android frameworks might use it. The request also asks for usage examples, debugging tips with Frida, and a detailed explanation in Chinese.

**2. Initial Analysis of the Code:**

* **Copyright and Licensing:**  Immediately note the Apache 2.0 license and the copyright belonging to Google/Android. This provides context about the code's origin and intended usage.
* **Includes:** Identify the included header files:
    * `<assert.h>`:  Likely used for internal debugging assertions.
    * `<errno.h>`:  Essential for reporting errors using `errno`.
    * `<uchar.h>`:  Defines `char16_t` and other related types.
    * `<wchar.h>`:  While present, its direct use isn't immediately obvious. It's worth noting for later.
    * `"private/bionic_mbstate.h"`: This is crucial. It suggests the code manages some internal state related to multi-byte character conversions. This hints at dealing with potentially incomplete character sequences.
* **Function Signatures:**  The core function is `mbrtoc16`. Analyze its parameters and return type:
    * `char16_t* pc16`:  Pointer to the output buffer where the converted `char16_t` will be stored.
    * `const char* s`:  Pointer to the input multi-byte character sequence.
    * `size_t n`:  Maximum number of bytes to examine from the input.
    * `mbstate_t* ps`:  Pointer to a conversion state object.
    * `size_t`:  Return value indicating the number of bytes consumed, an error, or a special value.
* **Helper Functions:** Identify the helper functions:
    * `mbspartialc16`: Checks if the current state indicates a partial character.
    * `begin_surrogate`: Handles the initial part of converting a 32-bit character to a UTF-16 surrogate pair.
    * `finish_surrogate`: Handles the second part of the surrogate pair conversion.

**3. Deeper Dive into Function Implementations:**

* **`mbspartialc16`:** Simple check based on a byte within the `mbstate_t`. This confirms the state management aspect.
* **`begin_surrogate`:**  This function is central to handling characters outside the Basic Multilingual Plane (BMP). Notice the bit manipulations to split the 32-bit code point into the high and low surrogates. The comments about the C23 standard and the return values are very important for understanding the function's precise behavior, especially the `-3` return code.
* **`finish_surrogate`:** Retrieves the stored trailing surrogate from the `mbstate_t` and returns `-3`. This clearly complements `begin_surrogate`.
* **`mbrtoc16`:** This is the main logic. Follow the execution flow:
    * **State Management:** Handles the case where no `mbstate_t` is provided by using a private static state. Checks for a partial character using `mbspartialc16`.
    * **Delegation to `mbrtoc32`:**  Crucially, it calls `mbrtoc32`. This implies that `mbrtoc16` relies on `mbrtoc32` for the initial decoding of the multi-byte sequence into a `char32_t`.
    * **Error Handling from `mbrtoc32`:** Checks for errors returned by `mbrtoc32`.
    * **Handling BMP Characters:** If the decoded `char32_t` is within the BMP (less than `0x10000`), it's directly cast to `char16_t`.
    * **Handling Characters Outside BMP (Surrogates):** If the `char32_t` is outside the BMP but within the valid range for UTF-16 surrogates, it calls `begin_surrogate`.
    * **Handling Invalid Code Points:** Detects code points outside the valid Unicode range and returns an error.
    * **Resetting State:**  Uses `mbstate_reset_and_return` in some cases, reinforcing the importance of state management.

**4. Connecting to Android Functionality:**

* **Character Encoding:**  Recognize that Android, like most modern systems, uses UTF-8 as its primary encoding. `mbrtoc16` is essential for converting UTF-8 input (represented as `const char*`) into UTF-16, which is often used internally within Java-based Android components.
* **NDK Usage:**  Developers using the NDK to write native code might need to perform character conversions. `mbrtoc16` would be the standard C library function for this.
* **Framework Usage (Indirect):** While the framework might not call `mbrtoc16` directly, higher-level APIs dealing with text processing would eventually rely on lower-level functions like this. Think about Java's `String` class and its internal UTF-16 representation. When data comes from native sources (e.g., file I/O, network), conversions might be necessary.

**5. Dynamic Linker and SO Layout (Relatively Less Relevant Here):**

Since `mbrtoc16.cpp` is part of `libc`, it's statically linked into most processes or provided as a shared library. The core logic doesn't inherently involve dynamic linking. However, understanding the general SO layout and linking process is still important background knowledge:

* **SO Layout:**  Imagine `libc.so` with sections for code (`.text`), read-only data (`.rodata`), writable data (`.data`, `.bss`), etc. `mbrtoc16`'s compiled code would reside in the `.text` section.
* **Linking:** When an app uses `mbrtoc16`, the dynamic linker resolves the symbol `mbrtoc16` to its address within `libc.so`.

**6. Error Handling and Common Mistakes:**

* **Buffer Overflows:** The `n` parameter is crucial for preventing reads beyond the input buffer.
* **Incorrect State Management:** Failing to properly initialize or pass the `mbstate_t` can lead to incorrect conversions, especially with multi-byte sequences or surrogate pairs.
* **Ignoring Return Values:** Not checking the return value of `mbrtoc16` can lead to missed errors or misinterpretations of the conversion status.

**7. Frida Hooking:**

Think about where to place hooks to observe the behavior:

* **Entry and Exit of `mbrtoc16`:**  See the input parameters and the return value.
* **Calls to `mbrtoc32`:**  Understand what `mbrtoc32` is doing.
* **Inside `begin_surrogate` and `finish_surrogate`:** Observe how surrogate pairs are being constructed.
* **Accesses to the `mbstate_t`:** See how the state is being updated.

**8. Structuring the Response (Chinese):**

Organize the information logically:

* **功能:** Start with a concise summary of the function's purpose.
* **与 Android 的关系:** Explain how it fits into the Android ecosystem, focusing on character encoding and NDK usage.
* **libc 函数实现:**  Detail the implementation of `mbrtoc16` and its helper functions, explaining the logic behind surrogate pair handling and error conditions.
* **Dynamic Linker (Acknowledge Limited Relevance):** Briefly explain the role of `libc.so` and how the dynamic linker would resolve the function, even if this specific file doesn't heavily involve it.
* **逻辑推理 (Example with Input/Output):** Create a simple example to illustrate the conversion process, including surrogate pairs.
* **用户或编程常见的使用错误:** List common pitfalls.
* **Android Framework/NDK 调用路径:**  Describe the likely path from the Android framework or NDK down to `mbrtoc16`.
* **Frida Hook 示例:** Provide concrete Frida code examples to demonstrate how to intercept calls to the function.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe `wchar.h` is directly used for wide characters. **Correction:** Upon closer inspection, the primary focus is `char16_t` and `char32_t`. `wchar.h` might be included for compatibility or other related definitions within the broader `libc`.
* **Initial thought:**  Focus heavily on dynamic linking for this specific file. **Correction:**  Recognize that while `mbrtoc16` resides in a shared library, the core logic doesn't actively *use* dynamic linking features. Shift focus to the function's core purpose.
* **Ensure Clarity and Accuracy:** Double-check the explanation of surrogate pair encoding and the return values of the functions, especially the `-3` case.

By following this structured thought process, combining code analysis with knowledge of Android's architecture and common programming practices, you can generate a comprehensive and accurate explanation of the `mbrtoc16.cpp` file.好的，让我们详细分析一下 `bionic/libc/bionic/mbrtoc16.cpp` 这个文件。

**文件功能概览:**

`mbrtoc16.cpp` 文件实现了 C 标准库函数 `mbrtoc16`。这个函数的主要功能是将一个多字节字符序列（通常是 UTF-8 编码）转换为一个 16 位的字符（`char16_t`），用于表示 Unicode 字符。

**详细功能分解:**

1. **多字节到 char16_t 的转换:** `mbrtoc16` 的核心任务是将以字节序列形式表示的字符转换为 `char16_t` 类型。这对于处理不同字符编码之间的转换至关重要。

2. **处理 UTF-16 编码单元:**  Unicode 字符可以由一个或两个 `char16_t` 编码单元表示。对于基本多文种平面 (BMP) 内的字符，只需要一个 `char16_t`。对于 BMP 之外的字符，则需要一对被称为代理对 (surrogate pair) 的 `char16_t` 单元。`mbrtoc16` 需要能够处理这两种情况。

3. **状态管理 (`mbstate_t`)**:  多字节字符可能是由多个字节组成的，`mbrtoc16` 需要跟踪转换的状态，以便在多次调用中正确处理不完整的字符序列。`mbstate_t` 结构体用于存储这个状态信息。

4. **错误处理:**  如果输入的字节序列不是有效的多字节字符，`mbrtoc16` 需要能够检测到错误并返回相应的错误代码。

**与 Android 功能的关系及举例说明:**

在 Android 系统中，`mbrtoc16` 函数在处理文本数据时扮演着重要的角色，尤其是在 native 代码层。

* **NDK 开发:**  当 Android 开发者使用 NDK (Native Development Kit) 编写 C/C++ 代码时，如果需要处理从 Java 层传递下来的字符串（通常是 UTF-16 编码），或者需要将 native 代码中的字符串转换为 UTF-16 以便传递给 Java 层，就会涉及到多字节字符的转换。`mbrtoc16` 可以将其他多字节编码（如 UTF-8）转换为 UTF-16 编码单元。

   **例子:** 假设一个 NDK 应用从网络接收到 UTF-8 编码的文本数据，需要将其显示在 Android 的 `TextView` 组件上。在 native 代码中，可以使用 `mbrtoc16` 将 UTF-8 字节流转换为 `char16_t` 数组，然后再传递给 Java 层进行显示。

* **Bionic Libc 内部使用:** Android 的 Bionic Libc 自身也可能在内部使用 `mbrtoc16` 来处理字符编码转换相关的操作。

**libc 函数的实现细节:**

现在我们详细解释一下 `mbrtoc16.cpp` 中涉及的 libc 函数的实现：

1. **`mbstate_t` 相关的函数 (定义在 `private/bionic_mbstate.h`)**:
   - `mbstate_get_byte(state, index)`:  从 `mbstate_t` 结构体中获取指定索引位置的字节。在这个文件中，它被用来检查和存储代理对的低位部分。
   - `mbstate_set_byte(state, index, value)`: 设置 `mbstate_t` 结构体中指定索引位置的字节值。这里用于存储代理对的低位部分。
   - `mbstate_reset(state)`: 将 `mbstate_t` 的状态重置为初始状态。
   - `mbstate_reset_and_return(value, state)`:  重置状态并返回指定的值。
   - `mbstate_reset_and_return_illegal(error_code, state)`: 重置状态并返回一个表示非法序列的错误代码。

2. **`mbrtoc32` 函数调用:**
   - `mbrtoc16` 的实现依赖于另一个函数 `mbrtoc32`，它的功能是将多字节字符序列转换为一个 32 位的字符 (`char32_t`)，即 Unicode 代码点。
   - `mbrtoc16` 首先调用 `mbrtoc32` 将输入的字节序列解码为 `char32_t`。
   - **实现原理 (假设):** `mbrtoc32` 内部会根据 UTF-8 的编码规则（或其他多字节编码）来识别字符的边界，并将其组合成一个 Unicode 代码点。它会处理不同长度的 UTF-8 序列。

3. **代理对的处理逻辑:**
   - **`mbspartialc16(const mbstate_t* state)`:**  检查 `mbstate_t` 中是否存储了部分代理对的信息。如果之前调用 `mbrtoc16` 处理了一个需要代理对的字符，但只输出了高位代理，这个函数会返回 `true`。
   - **`begin_surrogate(char32_t c32, char16_t* pc16, size_t nconv, mbstate_t* state)`:** 当 `mbrtoc32` 返回一个大于 `0xffff` 的代码点时，表示需要使用代理对。这个函数将 32 位的代码点拆分成高位和低位代理，并将高位代理写入 `*pc16`，同时将低位代理的相关信息存储在 `state` 中，以便下次调用 `mbrtoc16` 时输出。
   - **`finish_surrogate(char16_t* pc16, mbstate_t* state)`:**  当 `mbspartialc16` 返回 `true` 时，说明需要输出之前存储的低位代理。这个函数从 `state` 中取出低位代理，并将其写入 `*pc16`，然后重置状态。

**涉及 dynamic linker 的功能:**

`mbrtoc16.cpp` 本身是 `libc` 的一部分，编译后会包含在 `libc.so` 这个共享库中。当应用程序需要使用 `mbrtoc16` 函数时，动态链接器会负责将应用程序的代码与 `libc.so` 中 `mbrtoc16` 的实现链接起来。

**SO 布局样本:**

假设 `libc.so` 的部分布局如下（简化）：

```
libc.so:
    .text          # 代码段
        ...
        mbrtoc16:   # mbrtoc16 函数的代码
        ...
    .rodata        # 只读数据段
        ...
    .data          # 可写数据段
        ...
    .symtab        # 符号表
        ...
        mbrtoc16   # mbrtoc16 的符号
        ...
    .dynsym        # 动态符号表
        ...
        mbrtoc16   # mbrtoc16 的动态符号
        ...
```

**链接的处理过程:**

1. **编译时:** 编译器在编译使用 `mbrtoc16` 的代码时，会生成对 `mbrtoc16` 的未解析符号引用。
2. **加载时:** 当 Android 系统加载应用程序时，动态链接器（如 `linker64` 或 `linker`) 会解析这些未解析的符号。
3. **符号查找:** 动态链接器会在应用程序依赖的共享库（包括 `libc.so`）的动态符号表 (`.dynsym`) 中查找 `mbrtoc16` 的符号。
4. **地址绑定:** 找到 `mbrtoc16` 的符号后，动态链接器会将应用程序中对 `mbrtoc16` 的引用绑定到 `libc.so` 中 `mbrtoc16` 函数的实际地址。
5. **执行:** 当应用程序执行到调用 `mbrtoc16` 的代码时，程序会跳转到 `libc.so` 中 `mbrtoc16` 的代码执行。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `s`: 指向一个 UTF-8 编码的字符串 "你好" 的指针。
* `n`: 输入缓冲区的大小，足够容纳 "你好" 的 UTF-8 编码（通常是 6 个字节）。
* `ps`: 一个指向已初始化 `mbstate_t` 结构的指针。

**预期输出:**

第一次调用 `mbrtoc16`:
* `pc16`: 指向的内存将存储 '你' 的 UTF-16 编码单元。
* 返回值: 3 (因为 '你' 的 UTF-8 编码占 3 个字节)。

第二次调用 `mbrtoc16`:
* `pc16`: 指向的内存将存储 '好' 的 UTF-16 编码单元。
* 返回值: 3 (因为 '好' 的 UTF-8 编码占 3 个字节)。

**假设输入 (需要代理对的字符):**

* `s`: 指向一个 UTF-8 编码的 BMP 之外的字符（例如，U+1D306，一个 Byzantine Musical Symbol）。
* `n`: 足够容纳该字符的 UTF-8 编码（通常是 4 个字节）。
* `ps`: 一个指向已初始化 `mbstate_t` 结构的指针。

**预期输出:**

第一次调用 `mbrtoc16`:
* `pc16`: 指向的内存将存储高位代理单元。
* 返回值: 4 (UTF-8 编码占 4 个字节)。

第二次调用 `mbrtoc16`:
* `pc16`: 指向的内存将存储低位代理单元。
* 返回值: -3 (表示这是之前字符的延续)。

**用户或编程常见的使用错误:**

1. **缓冲区溢出:**  如果 `n` 的值小于实际多字节字符所需的字节数，`mbrtoc16` 可能会读取超出输入缓冲区的范围。
2. **未初始化 `mbstate_t`:**  如果不初始化 `mbstate_t` 结构，或者在多次调用之间错误地使用 `mbstate_t`，可能会导致转换错误。
3. **忽略返回值:**  `mbrtoc16` 的返回值指示了转换的状态（成功、部分字符、错误等）。忽略返回值可能导致程序逻辑错误。
4. **假设字符大小:**  不应该假设一个输入字节对应一个输出 `char16_t`。有些字符需要代理对，会输出两个 `char16_t`。
5. **处理不完整的字符:**  在处理流式输入时，可能会遇到不完整的多字节字符序列。需要正确使用 `mbstate_t` 来处理这种情况。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework (Java 层):**
   - 当 Java 代码需要处理字符数据时，例如从文件读取文本、接收网络数据、用户输入等，Java 的 `String` 类内部使用 UTF-16 编码。
   - 如果需要将其他编码（如 UTF-8）的数据转换为 Java `String`，Java VM 内部会调用 native 方法。
   - 这些 native 方法最终可能会调用 Bionic Libc 提供的字符转换函数。

2. **NDK (Native 层):**
   - NDK 开发者可以直接调用 Bionic Libc 提供的标准 C 库函数，包括 `mbrtoc16`。
   - 例如，一个使用 NDK 开发的音视频解码器，如果需要处理字幕文件（通常是 UTF-8 编码），就会使用 `mbrtoc16` 将 UTF-8 转换为 UTF-16。

**步骤示例 (Framework -> Native):**

假设一个 Java 应用从网络接收到 UTF-8 编码的数据，并将其显示在 `TextView` 上：

1. **Java 代码:**
   ```java
   String utf8Data = receiveDataFromNetwork(); // 假设接收到 UTF-8 数据
   String unicodeString = new String(utf8Data, StandardCharsets.UTF_8); // Java 内部会进行编码转换
   textView.setText(unicodeString);
   ```
2. **Java VM 内部:** `String` 的构造函数会调用 native 方法来进行 UTF-8 到 UTF-16 的转换。
3. **Native 方法 (libcore/luni/src/main/native/java_lang_String.cpp 或相关代码):** 这些 native 方法会使用 ICU (International Components for Unicode) 库或者 Bionic Libc 提供的函数来进行转换。在某些情况下，可能会间接使用到 `mbrtoc16` 或其相关的函数。

**步骤示例 (NDK):**

1. **NDK 代码:**
   ```c++
   #include <uchar.h>
   #include <string>
   #include <locale.h>

   std::u16string utf8ToUtf16(const char* utf8Str) {
       std::u16string utf16Str;
       mbstate_t state;
       memset(&state, 0, sizeof(state));
       const char* p = utf8Str;
       size_t result;
       char16_t c16;

       while (*p != '\0') {
           result = mbrtoc16(&c16, p, strlen(p), &state);
           if (result == (size_t)-1 || result == (size_t)-2) {
               // 错误处理
               break;
           }
           if (result > 0) {
               utf16Str += c16;
               p += result;
           }
       }
       return utf16Str;
   }
   ```

**Frida Hook 示例调试步骤:**

以下是一个使用 Frida Hook `mbrtoc16` 函数的示例，可以观察其输入和输出：

```python
import frida
import sys

# 要 hook 的目标应用包名
package_name = "your.target.app"

# Frida 脚本
hook_script = """
Interceptor.attach(Module.findExportByName("libc.so", "mbrtoc16"), {
  onEnter: function(args) {
    console.log("mbrtoc16 called!");
    console.log("  pc16: " + args[0]);
    console.log("  s: " + args[1]);
    console.log("  n: " + args[2]);
    console.log("  ps: " + args[3]);

    // 可以尝试读取输入字符串
    if (args[1] != 0) {
      try {
        var n = parseInt(args[2]);
        var str = Memory.readUtf8String(ptr(args[1]), n);
        console.log("  Input string (max " + n + " bytes): " + str);
      } catch (e) {
        console.log("  Error reading input string: " + e);
      }
    }
  },
  onLeave: function(retval) {
    console.log("mbrtoc16 returned: " + retval);
    // 可以尝试读取输出的 char16_t 值
    if (ptr(this.context.r0) != 0 && retval > 0) { // 假设返回值大于 0 表示成功转换
      try {
        var c16 = Memory.readU16(ptr(this.context.r0));
        console.log("  Output char16_t: " + c16.toString(16));
      } catch (e) {
        console.log("  Error reading output char16_t: " + e);
      }
    }
  }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(hook_script)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, press Ctrl+C to quit")
    sys.stdin.read()
except frida.common.RPCException as e:
    print(f"[-] RPCException: {e}")
except KeyboardInterrupt:
    print("[*] Detaching from process...")
    session.detach()

```

**使用步骤:**

1. **安装 Frida:** 确保你的系统上安装了 Frida 和 Frida tools。
2. **找到目标应用进程:** 确定你要调试的 Android 应用的包名或进程 ID。
3. **运行 Frida 脚本:** 将上面的 Python 脚本保存为 `.py` 文件，并将 `package_name` 替换为你目标应用的包名。运行该脚本。
4. **操作目标应用:** 在你的 Android 设备上操作目标应用，触发可能调用 `mbrtoc16` 的场景，例如显示包含多语言字符的文本。
5. **查看 Frida 输出:** Frida 会打印出 `mbrtoc16` 函数被调用时的参数和返回值，你可以观察输入的 UTF-8 字节和输出的 UTF-16 编码单元。

这个分析应该涵盖了 `bionic/libc/bionic/mbrtoc16.cpp` 文件的主要功能、与 Android 的关系、实现细节、动态链接、使用示例、常见错误以及如何使用 Frida 进行调试。希望对你有所帮助！

### 提示词
```
这是目录为bionic/libc/bionic/mbrtoc16.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <assert.h>
#include <errno.h>
#include <uchar.h>
#include <wchar.h>

#include "private/bionic_mbstate.h"

static inline bool mbspartialc16(const mbstate_t* state) {
  return mbstate_get_byte(state, 3) != 0;
}

static size_t begin_surrogate(char32_t c32, char16_t* pc16,
                              size_t nconv, mbstate_t* state) {
  c32 -= 0x10000;
  char16_t trail = (c32 & 0x3ff) | 0xdc00;

  mbstate_set_byte(state, 0, trail & 0x00ff);
  mbstate_set_byte(state, 1, (trail & 0xff00) >> 8);
  mbstate_set_byte(state, 3, nconv & 0xff);

  *pc16 = ((c32 & 0xffc00) >> 10) | 0xd800;
  // https://issuetracker.google.com/289419882
  //
  // We misread the spec when implementing this. The first call should return
  // the length of the decoded character, and the second call should return -3
  // to indicate that the output is a continuation of the character decoded by
  // the first call.
  //
  // C23 7.30.1.3.4:
  //
  //     between 1 and n inclusive if the next n or fewer bytes complete a valid
  //     multibyte character (which is the value stored); the value returned is
  //     the number of bytes that complete the multibyte character.
  //
  //     (size_t)(-3) if the next character resulting from a previous call has
  //     been stored (no bytes from the input have been consumed by this call).
  //
  // The first call returns the number of bytes consumed, and the second call
  // returns -3.
  //
  // All UTF-8 sequences that encode a surrogate pair are 4 bytes, but we may
  // not have seen the full sequence yet.
  return nconv;
}

static size_t finish_surrogate(char16_t* pc16, mbstate_t* state) {
  char16_t trail = mbstate_get_byte(state, 1) << 8 |
                   mbstate_get_byte(state, 0);
  *pc16 = trail;
  mbstate_reset(state);
  return static_cast<size_t>(-3);
}

size_t mbrtoc16(char16_t* pc16, const char* s, size_t n, mbstate_t* ps) {
  static mbstate_t __private_state;
  mbstate_t* state = (ps == nullptr) ? &__private_state : ps;

  char16_t __private_pc16;
  if (pc16 == nullptr) {
    pc16 = &__private_pc16;
  }

  if (mbspartialc16(state)) {
    return finish_surrogate(pc16, state);
  }

  char32_t c32;
  size_t nconv = mbrtoc32(&c32, s, n, state);
  if (__MB_IS_ERR(nconv)) {
    return nconv;
  } else if (nconv == 0) {
    return mbstate_reset_and_return(nconv, state);
  } else if (c32 < 0x10000) {
    *pc16 = static_cast<char16_t>(c32);
    return mbstate_reset_and_return(nconv, state);
  } else if (c32 > 0x10ffff) {
    // This case is currently handled by mbrtoc32() returning an error, but
    // if that function is extended to cover 5-byte sequences (which are
    // illegal at the moment), we'd need to explicitly handle the case of
    // codepoints that can't be represented as a surrogate pair here.
    return mbstate_reset_and_return_illegal(EILSEQ, state);
  } else {
    return begin_surrogate(c32, pc16, nconv, state);
  }
}
```