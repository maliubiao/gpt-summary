Response:
Let's break down the thought process to answer the user's request about `bionic/libc/bionic/fortify.cpp`.

**1. Understanding the Core Purpose:**

The immediate giveaway from the filename and the initial comments is "fortify." This immediately suggests security hardening and buffer overflow protection. The comments explicitly mention `FORTIFY` and link to relevant documentation.

**2. Identifying Key Functionality:**

Scanning the code, the pattern `__<function_name>_chk` is very prominent. This clearly indicates wrapper functions around standard C library functions. The `_chk` suffix strongly suggests these wrappers perform additional *checks*.

**3. Analyzing the Checks:**

Looking inside the `__<function_name>_chk` functions, the calls to `__check_buffer_access` and `__check_count` are central. These functions are likely the core of the fortification mechanism. They take size arguments and compare them, hinting at preventing out-of-bounds access.

**4. Connecting to Android and Security:**

The initial description mentions Bionic is Android's C library. This, combined with the "fortify" aspect, immediately links this file to Android's security efforts. The provided blog post about "Fortify in Android" confirms this connection.

**5. Dissecting Individual `_chk` Functions:**

The next step is to examine a few representative `_chk` functions to understand how they work:

* **`__fgets_chk`:** Checks if the `supplied_size` is within the bounds of `dst_len_from_compiler`.
* **`__fread_chk` and `__fwrite_chk`:** Calculate the `total` size and check against the buffer size. They also handle potential overflow during the multiplication of `size` and `count`.
* **`__memcpy_chk` (and similar):**  Directly checks `count` against `dst_len`. The separate `__memcpy_chk_fail` function suggests a way to handle failures, potentially from optimized assembly implementations.
* **`__strlen_chk`:**  Performs the standard `strlen` and then checks if the result is within the provided buffer length. This is important because `strlen` itself doesn't inherently have bounds checking.
* **`__sprintf_chk` and `__vsnprintf_chk`:**  Check if the `supplied_size` is valid for the destination buffer.

**6. Generalizing the Functionality:**

From analyzing individual functions, a general pattern emerges:

* **Compiler Assistance:** The `dst_len_from_compiler` argument is crucial. This information is likely provided by the compiler based on the declared size of the buffer.
* **Runtime Checks:** The `_chk` functions perform runtime checks using this compiler-provided information.
* **Error Handling:** If a violation is detected, `__fortify_fatal` is called, likely leading to program termination.

**7. Addressing Specific User Questions:**

Now, let's address each part of the user's request systematically:

* **功能 (Functionality):**  Summarize the purpose of `fortify.cpp` as providing runtime buffer overflow protection. List the key techniques: size checking, compiler hints, and fatal error on detection.
* **与 Android 功能的关系 (Relationship to Android):** Explain that this is a core security component of Bionic, protecting against common vulnerabilities. Give examples like preventing buffer overflows in system services or apps.
* **libc 函数的实现 (Implementation of libc functions):** Choose a few representative functions (like `memcpy`, `strcpy`, `printf`) and explain how their `_chk` versions add the size checks. Highlight the use of `__check_buffer_access`. Mention the optimization for performance-critical functions using assembly.
* **dynamic linker 功能 (Dynamic linker functionality):**  This file *doesn't directly implement* dynamic linking. It *uses* functions that might be involved in dynamic linking (like `read`, `write`, and memory allocation), but its focus is on security checks. Explain this distinction and provide a general example of how SOs are laid out and linked.
* **逻辑推理 (Logical reasoning):** Provide examples of how the checks work. Create a simple scenario with a buffer and a copy operation that would trigger the fortify mechanism. Show the expected input (sizes) and the output (the error/termination).
* **用户或编程常见的使用错误 (Common user errors):** Give examples of buffer overflows and how the fortify mechanism would detect them. Illustrate with code snippets.
* **Android framework or NDK 如何到达这里 (How Android framework/NDK reaches here):** Explain that when code is compiled with `-D_FORTIFY_SOURCE=2` (or similar), the compiler replaces standard libc calls with the `_chk` versions. Show the flow from a Java call, through JNI, to native code, and how the fortify checks are applied in the native code.
* **Frida hook 示例 (Frida hook example):**  Provide a concrete Frida script that intercepts a `_chk` function (e.g., `__strcpy_chk`) and logs the arguments. This demonstrates how to observe the fortify mechanism in action.

**8. Refining and Structuring the Answer:**

Organize the answer clearly, using headings and bullet points for readability. Ensure the language is precise and avoids jargon where possible. Provide code examples to illustrate concepts.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe this file does something with memory allocation related to dynamic linking."  **Correction:** Upon closer inspection, the file focuses on *checking* existing memory operations, not managing the dynamic linker itself. The interaction with the dynamic linker is indirect, through the libc functions it wraps.
* **Consideration:** "Should I explain every single `_chk` function?" **Refinement:**  No, that would be too verbose. Focus on the common patterns and provide detailed explanations for a few representative examples.
* **Clarity:**  Ensure the explanation of how the compiler integrates the fortify checks is clear and accurate. Emphasize the role of compiler flags.
* **Practicality:** The Frida example should be simple and directly demonstrate the interception of a fortify function.

By following this thought process, breaking down the code, understanding the core purpose, and addressing each part of the user's request systematically, a comprehensive and accurate answer can be constructed.
好的，让我们详细分析 `bionic/libc/bionic/fortify.cpp` 这个文件。

**功能概述**

`fortify.cpp` 文件实现了 Bionic libc 提供的 **运行时安全检查机制 (Runtime Safety Checks)**，也被称为 **Fortification**。它的主要功能是：

1. **检测缓冲区溢出 (Buffer Overflows):**  在程序运行时，通过额外的检查来发现可能发生的缓冲区溢出错误，从而提高程序的安全性。
2. **利用编译器的信息:** 它利用编译器在编译时收集到的关于对象大小的信息，以便在运行时进行更精确的边界检查。
3. **提供与标准 C 库函数对应的安全版本:**  它定义了一系列与标准 C 库函数同名的函数，但带有 `_chk` 后缀，例如 `__memcpy_chk`，`__strcpy_chk` 等。这些函数内部会调用原始的 C 库函数，并在调用前后或调用过程中加入安全检查。
4. **在检测到错误时终止程序:**  如果检查发现潜在的缓冲区溢出，这些安全函数通常会调用 `__fortify_fatal` 函数，导致程序终止，防止进一步的破坏。

**与 Android 功能的关系及举例说明**

`fortify.cpp` 是 Bionic libc 的一部分，而 Bionic libc 是 Android 操作系统的核心 C 库。因此，`fortify.cpp` 的功能直接关系到 Android 系统的安全性和稳定性。

**举例说明:**

* **防止恶意代码利用缓冲区溢出:**  在 Android 系统中，很多系统服务和应用程序都是用 C/C++ 编写的。如果这些代码中存在缓冲区溢出漏洞，恶意代码可能会利用这些漏洞来执行任意代码，获取系统权限或者导致系统崩溃。`fortify.cpp` 提供的运行时检查可以在一定程度上阻止这种攻击。例如，当一个应用尝试将过多的数据写入一个缓冲区时，`__memcpy_chk` 函数会检测到这个错误并终止应用，防止缓冲区溢出扩散。
* **提高系统服务的安全性:** Android 的许多核心服务，如 `surfaceflinger`，`mediaserver` 等，都依赖于 Bionic libc。`fortify.cpp` 的安全检查可以帮助提高这些服务的安全性，防止它们被恶意攻击或者因为编程错误而崩溃。
* **NDK 开发的安全性:** 使用 Android NDK 进行原生开发的应用程序也会链接到 Bionic libc。通过 `-D_FORTIFY_SOURCE=2` 等编译选项，开发者可以使用 `fortify.cpp` 提供的安全函数，提高其应用的安全性。

**详细解释 libc 函数的实现**

`fortify.cpp` 中定义的函数并不是完全重新实现了 libc 函数的功能，而是对标准 libc 函数进行了包装，添加了安全检查。下面以几个典型的函数为例进行解释：

1. **`__memcpy_chk(void* dst, const void* src, size_t count, size_t dst_len)`:**
   - **功能:** 安全版本的 `memcpy` 函数，用于将 `src` 指向的内存块复制到 `dst` 指向的内存块，复制 `count` 个字节。
   - **实现:**
     - `__check_count("memcpy", "count", count);`:  检查 `count` 是否为非负数。
     - `__check_buffer_access("memcpy", "write into", count, dst_len);`: 这是核心的安全检查，它会比较要复制的字节数 `count` 和目标缓冲区 `dst` 的实际大小 `dst_len`。如果 `count` 大于 `dst_len`，则说明可能发生缓冲区溢出，函数会调用 `__fortify_fatal` 终止程序。
     - `return memcpy(dst, src, count);`: 如果安全检查通过，则调用标准的 `memcpy` 函数执行实际的内存复制操作。
   - **假设输入与输出:**
     - **假设输入:** `dst` 指向一个大小为 10 字节的缓冲区，`src` 指向一个包含 "Hello" 的字符串，`count` 为 5，`dst_len` 为 10。
     - **输出:**  `memcpy` 成功将 "Hello" 复制到 `dst`，函数返回 `dst` 的地址。
     - **假设输入 (错误情况):** `dst` 指向一个大小为 5 字节的缓冲区，`src` 指向一个包含 "HelloWorld" 的字符串，`count` 为 10，`dst_len` 为 5。
     - **输出:** `__check_buffer_access` 检测到 `count > dst_len`，调用 `__fortify_fatal` 终止程序。

2. **`__strcpy_chk(char* dst, const char* src, size_t dst_len)`:**
   - **功能:** 安全版本的 `strcpy` 函数，用于将 `src` 指向的以 null 结尾的字符串复制到 `dst` 指向的缓冲区。
   - **实现:**
     - `size_t src_len = strlen(src) + 1;`:  计算源字符串的长度（包括 null 终止符）。
     - `__check_buffer_access("strcpy", "write into", src_len, dst_len);`: 检查源字符串的长度是否超过目标缓冲区的实际大小。
     - `return strcpy(dst, src);`: 如果检查通过，则调用标准的 `strcpy` 函数。
   - **假设输入与输出:**
     - **假设输入:** `dst` 指向一个大小为 10 字节的缓冲区，`src` 指向 "Test"。 `dst_len` 为 10。
     - **输出:** `strcpy` 成功将 "Test" 复制到 `dst`，函数返回 `dst` 的地址。
     - **假设输入 (错误情况):** `dst` 指向一个大小为 3 字节的缓冲区，`src` 指向 "LongString"。 `dst_len` 为 3。
     - **输出:** `__check_buffer_access` 检测到源字符串长度超过目标缓冲区大小，调用 `__fortify_fatal` 终止程序。

3. **`__sprintf_chk(char* dst, int flags, size_t dst_len_from_compiler, const char* format, ...)`:**
   - **功能:** 安全版本的 `sprintf` 函数，用于根据格式化字符串 `format` 将结果写入到 `dst` 指向的缓冲区。
   - **实现:**
     - 它内部调用了 `__vsprintf_chk`。
     - `__vsprintf_chk` 内部最终会调用 `vsnprintf`，并将目标缓冲区的大小限制为 `dst_len_from_compiler` (编译器提供的目标缓冲区大小)。
     - 之后，还会通过 `__check_buffer_access` 再次检查实际写入的长度是否超过了目标缓冲区的大小。
   - **假设输入与输出:**
     - **假设输入:** `dst` 指向一个大小为 20 字节的缓冲区，`format` 为 "%s %d"，后面的参数分别为 "Value", 10。 `dst_len_from_compiler` 为 20。
     - **输出:** `sprintf` 成功将 "Value 10" 写入 `dst`，函数返回写入的字符数。
     - **假设输入 (错误情况):** `dst` 指向一个大小为 5 字节的缓冲区，`format` 为 "%s %s %s %s"，后面的参数是多个长字符串。 `dst_len_from_compiler` 为 5。
     - **输出:**  `vsnprintf` 会尝试写入，但会受到缓冲区大小的限制。 `__check_buffer_access` 可能会检测到写入超出范围，或者 `vsnprintf` 返回的长度超出范围，最终调用 `__fortify_fatal`。

**涉及 dynamic linker 的功能**

`fortify.cpp` 本身 **并不直接实现 dynamic linker 的功能**。它的主要作用是在程序运行时对 libc 函数进行安全检查。

然而，`fortify.cpp` 中使用的某些机制和检查与 dynamic linker 的工作方式有关联：

* **编译器提供的缓冲区大小信息 (`dst_len_from_compiler`):**  这个信息是由编译器在编译时静态确定的。当程序被加载时，dynamic linker 会根据程序头信息和共享库的依赖关系来加载和链接各个共享库，并将这些库加载到内存中的不同地址空间。`fortify.cpp` 依赖于编译器能够正确地将这些缓冲区的大小信息传递到运行时。

**SO 布局样本:**

假设我们有一个简单的应用程序 `app`，它链接到一个共享库 `libfoo.so`。

```
Memory Layout:

[Stack]          (应用程序的栈空间)
...
[Heap]           (应用程序的堆空间)
...
[libfoo.so]      (共享库 libfoo.so 的代码和数据段)
    .text        (代码段)
    .data        (已初始化的数据段)
    .bss         (未初始化的数据段)
    .plt         (过程链接表)
    .got         (全局偏移表)
...
[libc.so (Bionic)] (Bionic libc 共享库的代码和数据段，包括 fortify.cpp 的代码)
    ...
[app]            (应用程序的代码和数据段)
    .text
    .data
    ...
```

**链接的处理过程:**

1. **编译时:** 编译器在编译 `app` 和 `libfoo.so` 时，如果启用了 fortification，编译器会将对标准 libc 函数的调用替换为对 `_chk` 函数的调用，并传递缓冲区大小等信息。
2. **加载时:** 当 Android 系统启动 `app` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
   - 加载 `app` 的可执行文件到内存。
   - 解析 `app` 的依赖关系，发现它依赖于 `libfoo.so` 和 `libc.so`。
   - 加载 `libfoo.so` 和 `libc.so` 到内存中的不同地址空间。
   - **重定位:**  修改 `app` 和 `libfoo.so` 中的符号引用，使其指向正确的内存地址。这包括将 `app` 中对 `__memcpy_chk` 的调用指向 `libc.so` 中 `__memcpy_chk` 的实现。
   - **延迟绑定 (Lazy Binding):**  通常情况下，共享库中的函数只有在第一次被调用时才会被解析和绑定。过程链接表 (`.plt`) 和全局偏移表 (`.got`) 用于实现延迟绑定。

**假设输入与输出 (与 dynamic linker 相关):**

* **假设输入:**  `app` 调用了 `strcpy(buffer, "verylongstring")`，其中 `buffer` 是一个局部变量，编译器已知其大小为 10 字节。启用了 fortification。
* **链接处理:** 编译器将 `strcpy` 替换为 `__strcpy_chk(buffer, "verylongstring", 10)`。
* **运行时:**  当程序执行到 `__strcpy_chk` 时，它会计算源字符串的长度，并与 `dst_len` (10) 进行比较。如果源字符串长度超过 10，`__strcpy_chk` 会调用 `__fortify_fatal`。

**用户或编程常见的使用错误**

1. **缓冲区溢出:** 这是 fortification 最主要的目标。例如，使用 `strcpy` 将一个长字符串复制到一个较小的缓冲区中，或者使用 `memcpy` 复制过多的数据。
   ```c
   char buffer[10];
   const char* long_string = "This is a very long string";
   strcpy(buffer, long_string); // 可能会导致缓冲区溢出
   ```
   在启用 fortification 的情况下，`__strcpy_chk` 会检测到这个问题。

2. **格式化字符串漏洞:** 虽然 `fortify.cpp` 可以帮助检测某些格式化字符串相关的溢出，但它并不能完全防止所有此类漏洞。
   ```c
   char buffer[100];
   char user_input[50];
   scanf("%49s", user_input); // 从用户获取输入
   sprintf(buffer, user_input); // 如果 user_input 包含格式化字符串，可能导致问题
   ```
   `__sprintf_chk` 会检查输出缓冲区的大小，但如果 `user_input` 中包含恶意的格式化字符串，仍然可能导致问题。

3. **不正确的缓冲区大小传递:** 如果编译器无法准确推断缓冲区的大小，或者开发者错误地使用了指针和大小，fortification 可能无法发挥作用。

**Android framework 或 NDK 如何一步步的到达这里**

1. **Android Framework/NDK 代码调用 libc 函数:**  无论是 Java 代码通过 JNI 调用原生代码，还是 NDK 开发的纯原生应用，最终都会调用 Bionic libc 提供的函数，例如 `strcpy`, `memcpy`, `sprintf` 等。

2. **编译器标志 `-D_FORTIFY_SOURCE`:**  在编译 Android 系统组件、应用或者 NDK 代码时，通常会使用 `-D_FORTIFY_SOURCE` 编译标志来启用 fortification。
   - `-D_FORTIFY_SOURCE=1`: 提供一些基本的安全检查。
   - `-D_FORTIFY_SOURCE=2`: 提供更严格的安全检查，会替换更多的 libc 函数为 `_chk` 版本，并利用编译器提供的缓冲区大小信息。

3. **编译器替换 libc 函数调用:** 当启用了 `-D_FORTIFY_SOURCE` 后，编译器在编译代码时，会将对标准 libc 函数的调用替换为对 `fortify.cpp` 中定义的 `_chk` 函数的调用。例如，`strcpy(buf, src)` 会被替换为 `__strcpy_chk(buf, src, __builtin_object_size(buf, 0))`。 `__builtin_object_size` 是 GCC 提供的一个内建函数，用于获取对象的大小。

4. **运行时执行 `_chk` 函数:**  当程序运行时，执行到这些 `_chk` 函数时，它们会执行额外的安全检查。

5. **检测到错误并终止:** 如果 `_chk` 函数检测到潜在的缓冲区溢出或其他安全问题，它会调用 `__fortify_fatal` 函数，最终导致 `abort()` 系统调用，终止程序的执行。

**Frida Hook 示例调试这些步骤**

可以使用 Frida 来 hook `fortify.cpp` 中定义的 `_chk` 函数，观察其调用过程和参数。

```python
import frida
import sys

package_name = "你的应用包名"  # 例如 "com.example.myapp"

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__strcpy_chk"), {
    onEnter: function(args) {
        console.log("[*] __strcpy_chk called");
        console.log("    Destination:", args[0]);
        console.log("    Source:", args[1].readUtf8String());
        console.log("    Destination Size:", args[2]);
    },
    onLeave: function(retval) {
        console.log("[*] __strcpy_chk finished");
        console.log("    Return Value:", retval);
    }
});

// 可以添加更多你想 hook 的 _chk 函数
Interceptor.attach(Module.findExportByName("libc.so", "__memcpy_chk"), {
    onEnter: function(args) {
        console.log("[*] __memcpy_chk called");
        console.log("    Destination:", args[0]);
        console.log("    Source:", args[1]);
        console.log("    Count:", args[2]);
        console.log("    Destination Size:", args[3]);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将上面的 Python 代码保存为 `hook_fortify.py`。
2. 将你的 Android 设备连接到电脑并确保 adb 连接正常。
3. 替换 `package_name` 为你要调试的应用的包名。
4. 运行 Frida 服务：确保你的 Android 设备上运行着 frida-server。
5. 运行脚本：`python hook_fortify.py`
6. 启动或操作你的 Android 应用，Frida 将会 hook `libc.so` 中的 `__strcpy_chk` 和 `__memcpy_chk` 函数，并在控制台打印相关的参数信息。

通过这个 Frida hook 示例，你可以观察到当应用调用这些受 fortification 保护的函数时，传递的参数（包括缓冲区大小），从而理解 fortification 的工作原理。

总结来说，`bionic/libc/bionic/fortify.cpp` 是 Bionic libc 中非常重要的一个安全组件，它通过在运行时进行额外的安全检查，有效地提高了 Android 系统的安全性和稳定性，防止了许多常见的内存安全漏洞。理解它的工作原理对于 Android 开发者来说至关重要。

Prompt: 
```
这是目录为bionic/libc/bionic/fortify.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2012 The Android Open Source Project
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

/*
 * Copyright (c) 1988 Regents of the University of California.
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

#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "private/bionic_fortify.h"

//
// For more about FORTIFY see:
//
//   https://android-developers.googleblog.com/2017/04/fortify-in-android.html
//
//   http://gcc.gnu.org/onlinedocs/gcc/Object-Size-Checking.html
//   http://gcc.gnu.org/ml/gcc-patches/2004-09/msg02055.html
//

int __FD_ISSET_chk(int fd, const fd_set* set, size_t set_size) {
  __check_fd_set("FD_ISSET", fd, set_size);
  return __FD_ISSET(fd, set);
}

void __FD_CLR_chk(int fd, fd_set* set, size_t set_size) {
  __check_fd_set("FD_CLR", fd, set_size);
  __FD_CLR(fd, set);
}

void __FD_SET_chk(int fd, fd_set* set, size_t set_size) {
  __check_fd_set("FD_SET", fd, set_size);
  __FD_SET(fd, set);
}

char* __fgets_chk(char* dst, int supplied_size, FILE* stream, size_t dst_len_from_compiler) {
  __check_buffer_access("fgets", "write into", supplied_size, dst_len_from_compiler);
  return fgets(dst, supplied_size, stream);
}

size_t __fread_chk(void* buf, size_t size, size_t count, FILE* stream, size_t buf_size) {
  unsigned long total;
  if (__predict_false(__builtin_umull_overflow(size, count, &total))) {
    // overflow: trigger the error path in fread
    return fread(buf, size, count, stream);
  }
  __check_buffer_access("fread", "write into", total, buf_size);
  return fread(buf, size, count, stream);
}

size_t __fwrite_chk(const void* buf, size_t size, size_t count, FILE* stream, size_t buf_size) {
  unsigned long total;
  if (__predict_false(__builtin_umull_overflow(size, count, &total))) {
    // overflow: trigger the error path in fwrite
    return fwrite(buf, size, count, stream);
  }
  __check_buffer_access("fwrite", "read from", total, buf_size);
  return fwrite(buf, size, count, stream);
}

extern char* __getcwd_chk(char* buf, size_t len, size_t actual_size) {
  __check_buffer_access("getcwd", "write into", len, actual_size);
  return getcwd(buf, len);
}

void* __memchr_chk(const void* s, int c, size_t n, size_t actual_size) {
  __check_buffer_access("memchr", "read from", n, actual_size);
  return const_cast<void*>(memchr(s, c, n));
}

// Runtime implementation of __builtin____memmove_chk (used directly by compiler, not in headers).
extern "C" void* __memmove_chk(void* dst, const void* src, size_t len, size_t dst_len) {
  __check_buffer_access("memmove", "write into", len, dst_len);
  return memmove(dst, src, len);
}

// memcpy is performance-critical enough that we have assembler __memcpy_chk implementations.
// This function is used to give better diagnostics than we can easily do from assembler.
extern "C" void* __memcpy_chk_fail(void* /*dst*/, const void* /*src*/, size_t count, size_t dst_len) {
  __check_count("memcpy", "count", count);
  __check_buffer_access("memcpy", "write into", count, dst_len);
  abort(); // One of the above is supposed to have failed, otherwise we shouldn't have been called.
}

void* __memrchr_chk(const void* s, int c, size_t n, size_t actual_size) {
  __check_buffer_access("memrchr", "read from", n, actual_size);
  return memrchr(const_cast<void *>(s), c, n);
}

// memset is performance-critical enough that we have assembler __memset_chk implementations.
// This function is used to give better diagnostics than we can easily do from assembler.
extern "C" void* __memset_chk_fail(void* /*dst*/, int /*byte*/, size_t count, size_t dst_len) {
  __check_count("memset", "count", count);
  __check_buffer_access("memset", "write into", count, dst_len);
  abort(); // One of the above is supposed to have failed, otherwise we shouldn't have been called.
}

int __poll_chk(pollfd* fds, nfds_t fd_count, int timeout, size_t fds_size) {
  __check_pollfd_array("poll", fds_size, fd_count);
  return poll(fds, fd_count, timeout);
}

int __ppoll_chk(pollfd* fds, nfds_t fd_count, const timespec* timeout,
                const sigset_t* mask, size_t fds_size) {
  __check_pollfd_array("ppoll", fds_size, fd_count);
  return ppoll(fds, fd_count, timeout, mask);
}

int __ppoll64_chk(pollfd* fds, nfds_t fd_count, const timespec* timeout,
                  const sigset64_t* mask, size_t fds_size) {
  __check_pollfd_array("ppoll64", fds_size, fd_count);
  return ppoll64(fds, fd_count, timeout, mask);
}

ssize_t __pread64_chk(int fd, void* buf, size_t count, off64_t offset, size_t buf_size) {
  __check_count("pread64", "count", count);
  __check_buffer_access("pread64", "write into", count, buf_size);
  return pread64(fd, buf, count, offset);
}

ssize_t __pread_chk(int fd, void* buf, size_t count, off_t offset, size_t buf_size) {
  __check_count("pread", "count", count);
  __check_buffer_access("pread", "write into", count, buf_size);
  return pread(fd, buf, count, offset);
}

ssize_t __pwrite64_chk(int fd, const void* buf, size_t count, off64_t offset,
                                  size_t buf_size) {
  __check_count("pwrite64", "count", count);
  __check_buffer_access("pwrite64", "read from", count, buf_size);
  return pwrite64(fd, buf, count, offset);
}

ssize_t __pwrite_chk(int fd, const void* buf, size_t count, off_t offset,
                                size_t buf_size) {
  __check_count("pwrite", "count", count);
  __check_buffer_access("pwrite", "read from", count, buf_size);
  return pwrite(fd, buf, count, offset);
}

ssize_t __read_chk(int fd, void* buf, size_t count, size_t buf_size) {
  __check_count("read", "count", count);
  __check_buffer_access("read", "write into", count, buf_size);
  return read(fd, buf, count);
}

ssize_t __readlinkat_chk(int dirfd, const char* path, char* buf, size_t size, size_t buf_size) {
  __check_count("readlinkat", "size", size);
  __check_buffer_access("readlinkat", "write into", size, buf_size);
  return readlinkat(dirfd, path, buf, size);
}

ssize_t __readlink_chk(const char* path, char* buf, size_t size, size_t buf_size) {
  __check_count("readlink", "size", size);
  __check_buffer_access("readlink", "write into", size, buf_size);
  return readlink(path, buf, size);
}

ssize_t __recvfrom_chk(int socket, void* buf, size_t len, size_t buf_size,
                       int flags, sockaddr* src_addr, socklen_t* addrlen) {
  __check_buffer_access("recvfrom", "write into", len, buf_size);
  return recvfrom(socket, buf, len, flags, src_addr, addrlen);
}

ssize_t __sendto_chk(int socket, const void* buf, size_t len, size_t buflen,
                     int flags, const struct sockaddr* dest_addr,
                     socklen_t addrlen) {
  __check_buffer_access("sendto", "read from", len, buflen);
  return sendto(socket, buf, len, flags, dest_addr, addrlen);
}

// Runtime implementation of __builtin____stpcpy_chk (used directly by compiler, not in headers)..
extern "C" char* __stpcpy_chk(char* dst, const char* src, size_t dst_len) {
  // TODO: optimize so we don't scan src twice.
  size_t src_len = strlen(src) + 1;
  __check_buffer_access("stpcpy", "write into", src_len, dst_len);
  return stpcpy(dst, src);
}

// Runtime implementation of __builtin____stpncpy_chk (used directly by compiler, not in headers).
extern "C" char* __stpncpy_chk(char* dst, const char* src, size_t len, size_t dst_len) {
  __check_buffer_access("stpncpy", "write into", len, dst_len);
  return stpncpy(dst, src, len);
}

// This is a variant of __stpncpy_chk, but it also checks to make
// sure we don't read beyond the end of "src". The code for this is
// based on the original version of stpncpy, but modified to check
// how much we read from "src" during the copy operation.
char* __stpncpy_chk2(char* dst, const char* src, size_t n, size_t dst_len, size_t src_len) {
  __check_buffer_access("stpncpy", "write into", n, dst_len);
  if (n != 0) {
    char* d = dst;
    const char* s = src;

    do {
      size_t s_copy_len = static_cast<size_t>(s - src);
      if (__predict_false(s_copy_len >= src_len)) {
        __fortify_fatal("stpncpy: detected read past end of %zu-byte buffer", src_len);
      }

      if ((*d++ = *s++) == 0) {
        // NUL pad the remaining n-1 bytes.
        while (--n != 0) {
          *d++ = 0;
        }
        break;
      }
    } while (--n != 0);
  }

  return dst;
}

// strcat is performance-critical enough that we have assembler __strcat_chk implementations.
// This function is used to give better diagnostics than we can easily do from assembler.
extern "C" void __strcat_chk_fail(size_t dst_buf_size) {
  __fortify_fatal("strcat: prevented write past end of %zu-byte buffer", dst_buf_size);
}

char* __strchr_chk(const char* p, int ch, size_t s_len) {
  for (;; ++p, s_len--) {
    if (__predict_false(s_len == 0)) {
      __fortify_fatal("strchr: prevented read past end of buffer");
    }
    if (*p == static_cast<char>(ch)) {
      return const_cast<char*>(p);
    }
    if (*p == '\0') {
      return nullptr;
    }
  }
}

// strcpy is performance-critical enough that we have assembler __strcpy_chk implementations.
// This function is used to give better diagnostics than we can easily do from assembler.
extern "C" void __strcpy_chk_fail(size_t dst_buf_size) {
  __fortify_fatal("strcpy: prevented write past end of %zu-byte buffer", dst_buf_size);
}

size_t __strlcat_chk(char* dst, const char* src,
                     size_t supplied_size, size_t dst_len_from_compiler) {
  __check_buffer_access("strlcat", "write into", supplied_size, dst_len_from_compiler);
  return strlcat(dst, src, supplied_size);
}

size_t __strlcpy_chk(char* dst, const char* src,
                     size_t supplied_size, size_t dst_len_from_compiler) {
  __check_buffer_access("strlcpy", "write into", supplied_size, dst_len_from_compiler);
  return strlcpy(dst, src, supplied_size);
}

size_t __strlen_chk(const char* s, size_t s_len) {
  // TODO: "prevented" here would be a lie because this strlen can run off the end.
  // strlen is too important to be expensive, so we wanted to be able to call the optimized
  // implementation, but I think we need to implement optimized assembler __strlen_chk routines.
  size_t ret = strlen(s);
  if (__predict_false(ret >= s_len)) {
    __fortify_fatal("strlen: detected read past end of buffer");
  }
  return ret;
}

// Runtime implementation of __builtin____strncat_chk (used directly by compiler, not in headers).
extern "C" char* __strncat_chk(char* dst, const char* src, size_t len, size_t dst_buf_size) {
  if (len == 0) {
    return dst;
  }

  size_t dst_len = __strlen_chk(dst, dst_buf_size);
  char* d = dst + dst_len;
  dst_buf_size -= dst_len;

  while (*src != '\0') {
    *d++ = *src++;
    len--; dst_buf_size--;

    if (__predict_false(dst_buf_size == 0)) {
      __fortify_fatal("strncat: prevented write past end of buffer");
    }

    if (len == 0) {
      break;
    }
  }

  *d = '\0';
  return dst;
}

// Runtime implementation of __builtin____strncpy_chk (used directly by compiler, not in headers).
extern "C" char* __strncpy_chk(char* dst, const char* src, size_t len, size_t dst_len) {
  __check_buffer_access("strncpy", "write into", len, dst_len);
  return strncpy(dst, src, len);
}

// This is a variant of __strncpy_chk, but it also checks to make
// sure we don't read beyond the end of "src". The code for this is
// based on the original version of strncpy, but modified to check
// how much we read from "src" during the copy operation.
char* __strncpy_chk2(char* dst, const char* src, size_t n, size_t dst_len, size_t src_len) {
  __check_buffer_access("strncpy", "write into", n, dst_len);
  if (n != 0) {
    char* d = dst;
    const char* s = src;

    do {
      size_t s_copy_len = static_cast<size_t>(s - src);
      if (__predict_false(s_copy_len >= src_len)) {
        __fortify_fatal("strncpy: detected read past end of %zu-byte buffer", src_len);
      }

      if ((*d++ = *s++) == 0) {
        // NUL pad the remaining n-1 bytes.
        while (--n != 0) {
          *d++ = 0;
        }
        break;
      }
    } while (--n != 0);
  }

  return dst;
}

char* __strrchr_chk(const char* p, int ch, size_t s_len) {
  for (const char* save = nullptr;; ++p, s_len--) {
    if (s_len == 0) {
      __fortify_fatal("strrchr: prevented read past end of buffer");
    }
    if (*p == static_cast<char>(ch)) {
      save = p;
    }
    if (!*p) {
      return const_cast<char*>(save);
    }
  }
}

mode_t __umask_chk(mode_t mode) {
  if (__predict_false((mode & 0777) != mode)) {
    __fortify_fatal("umask: called with invalid mask %o", mode);
  }

  return umask(mode);
}

// Runtime implementation of __builtin____vsnprintf_chk (used directly by compiler, not in headers).
extern "C" int __vsnprintf_chk(char* dst, size_t supplied_size, int /*flags*/,
                               size_t dst_len_from_compiler, const char* format, va_list va) {
  __check_buffer_access("vsnprintf", "write into", supplied_size, dst_len_from_compiler);
  return vsnprintf(dst, supplied_size, format, va);
}

// Runtime implementation of __builtin____snprintf_chk (used directly by compiler, not in headers).
extern "C" int __snprintf_chk(char* dst, size_t supplied_size, int flags,
                              size_t dst_len_from_compiler, const char* format, ...) {
  va_list va;
  va_start(va, format);
  int result = __vsnprintf_chk(dst, supplied_size, flags, dst_len_from_compiler, format, va);
  va_end(va);
  return result;
}

// Runtime implementation of __builtin____vsprintf_chk (used directly by compiler, not in headers).
extern "C" int __vsprintf_chk(char* dst, int /*flags*/,
                              size_t dst_len_from_compiler, const char* format, va_list va) {
  // The compiler uses SIZE_MAX to mean "no idea", but our vsnprintf rejects sizes that large.
  int result = vsnprintf(dst,
                         dst_len_from_compiler == SIZE_MAX ? SSIZE_MAX : dst_len_from_compiler,
                         format, va);

  // Try to catch failures after the fact...
  __check_buffer_access("vsprintf", "write into", result + 1, dst_len_from_compiler);
  return result;
}

// Runtime implementation of __builtin____sprintf_chk (used directly by compiler, not in headers).
extern "C" int __sprintf_chk(char* dst, int flags, size_t dst_len_from_compiler,
                             const char* format, ...) {
  va_list va;
  va_start(va, format);
  int result = __vsprintf_chk(dst, flags, dst_len_from_compiler, format, va);
  va_end(va);
  return result;
}

ssize_t __write_chk(int fd, const void* buf, size_t count, size_t buf_size) {
  __check_count("write", "count", count);
  __check_buffer_access("write", "read from", count, buf_size);
  return write(fd, buf, count);
}

#if defined(RENAME___STRCAT_CHK)
#define __STRCAT_CHK __strcat_chk_generic
#else
#define __STRCAT_CHK __strcat_chk
#endif // RENAME___STRCAT_CHK

// Runtime implementation of __builtin____strcat_chk (used directly by compiler, not in headers).
extern "C" char* __STRCAT_CHK(char* dst, const char* src, size_t dst_buf_size) {
  char* save = dst;
  size_t dst_len = __strlen_chk(dst, dst_buf_size);

  dst += dst_len;
  dst_buf_size -= dst_len;

  while ((*dst++ = *src++) != '\0') {
    dst_buf_size--;
    if (__predict_false(dst_buf_size == 0)) {
      __fortify_fatal("strcat: prevented write past end of %zu-byte buffer", dst_buf_size);
    }
  }

  return save;
}

#if defined(RENAME___STRCPY_CHK)
#define __STRCPY_CHK __strcpy_chk_generic
#else
#define __STRCPY_CHK __strcpy_chk
#endif // RENAME___STRCPY_CHK

// Runtime implementation of __builtin____strcpy_chk (used directly by compiler, not in headers).
extern "C" char* __STRCPY_CHK(char* dst, const char* src, size_t dst_len) {
  // TODO: optimize so we don't scan src twice.
  size_t src_len = strlen(src) + 1;
  __check_buffer_access("strcpy", "write into", src_len, dst_len);
  return strcpy(dst, src);
}

#if !defined(__arm__) && !defined(__aarch64__) && !defined(__riscv)
// Runtime implementation of __memcpy_chk (used directly by compiler, not in headers).
// arm32,arm64,riscv have assembler implementations, and don't need this C fallback.
extern "C" void* __memcpy_chk(void* dst, const void* src, size_t count, size_t dst_len) {
  __check_count("memcpy", "count", count);
  __check_buffer_access("memcpy", "write into", count, dst_len);
  return memcpy(dst, src, count);
}
#endif

// Runtime implementation of __mempcpy_chk (used directly by compiler, not in headers).
extern "C" void* __mempcpy_chk(void* dst, const void* src, size_t count, size_t dst_len) {
  __check_count("mempcpy", "count", count);
  __check_buffer_access("mempcpy", "write into", count, dst_len);
  return mempcpy(dst, src, count);
}

"""

```