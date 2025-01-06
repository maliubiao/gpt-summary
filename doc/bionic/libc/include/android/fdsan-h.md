Response:
Let's break down the thought process for analyzing the `fdsan.h` header file.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of this header file, its relationship to Android, implementation details (specifically of `libc` functions), and how it's used and debugged. The target audience is likely someone working with Android development or debugging.

**2. Initial Scan and Keyword Recognition:**

I first quickly scanned the code for keywords and structural elements:

* **Copyright notice:** Indicates it's an official Android component.
* `#pragma once`: Standard header guard.
* `#include <sys/cdefs.h>`, `#include <stdbool.h>`, `#include <stdint.h>`: Standard C/C++ includes, suggesting core system functionality.
* `__BEGIN_DECLS`, `__END_DECLS`:  Common markers for C-style header files, especially in platform headers.
* **Comments:**  These are crucial. The initial comments about `close(2)` and file descriptor ownership are the most important clue to the file's purpose.
* **Function declarations:**  Names like `android_fdsan_create_owner_tag`, `android_fdsan_exchange_owner_tag`, `android_fdsan_close_with_tag`, etc., clearly indicate the file's functions. The `fdsan` part strongly suggests "file descriptor sanitization."
* **Enums:** `android_fdsan_owner_type` and `android_fdsan_error_level` define sets of related constants. The owner types give concrete examples of how fdsan is used.
* `__INTRODUCED_IN(29)` and `__attribute__((__weak__))`: These indicate API versioning and potential for weak linking.

**3. Core Functionality Identification (Based on Comments and Function Names):**

The comments about the `print` and `bug` functions immediately highlight the problem of double-closes or closing the wrong file descriptor. The introduction of "tags" and associating them with file descriptors becomes the central mechanism. The function names reinforce this:

* `create_owner_tag`: Create a tag to identify the "owner" of a file descriptor.
* `exchange_owner_tag`: Modify a file descriptor's associated tag.
* `close_with_tag`: Close a file descriptor, ensuring the correct tag is present.
* `get_owner_tag`: Retrieve the current tag of a file descriptor.
* `get_tag_type`, `get_tag_value`: Decompose a tag.
* `get_error_level`, `set_error_level`, `set_error_level_from_property`: Manage the severity of fdsan violations.

**4. Relating to Android:**

The `android_` prefix in function and enum names clearly links it to the Android platform. The `bionic/libc` path confirms it's part of Android's standard C library. The `android_fdsan_owner_type` enum provides explicit examples of Android framework components (like `ParcelFileDescriptor`, `FileInputStream`, `FileOutputStream`, ART, etc.) that utilize this mechanism.

**5. Implementation Details (libc Functions):**

The header file *declares* the functions but doesn't *implement* them. The request asks how they are implemented. My thought process here is:

* **Likely in `libc` source:** Given the file path, the implementation is within the bionic `libc` source code. I would mentally search for a `fdsan.c` or similar file.
* **System calls:**  File descriptor management ultimately relies on system calls. The `close_with_tag` function probably wraps the standard `close()` system call, but adds the tag validation logic. Other functions likely interact with internal kernel data structures to track tags.
* **Weak linking:** The `__attribute__((__weak__))` is important. This means these functions might not be present on all Android versions (prior to API level 29). The actual implementation might be in a separate library that's only linked in when needed.

**6. Dynamic Linker Aspects:**

The prompt asks about the dynamic linker. Here's the reasoning:

* **`libc` is a shared library:** `libc.so` is a fundamental shared library in Android.
* **fdsan needs to be available to all processes:** The fdsan mechanism should be consistent across the system.
* **Linkage and symbols:** The dynamic linker is responsible for resolving symbols (like the `android_fdsan_*` functions) at runtime.
* **SO layout:** I would envision `libc.so` having a section containing these functions.

**7. Error Scenarios and Usage Mistakes:**

The initial comments provide the primary example: closing a file descriptor that's still in use by another part of the program (the `print` and `bug` example). The tagging mechanism aims to prevent this.

**8. Android Framework and NDK Interaction:**

This is where connecting the dots is crucial:

* **Framework uses standard libraries:** Android framework components (written in Java/Kotlin) often interact with native code through JNI. These native components use `libc`.
* **NDK provides access to `libc`:** NDK developers can directly use the `android_fdsan_*` functions.
* **Example scenarios:**  `FileInputStream` internally uses file descriptors. `ParcelFileDescriptor` is a mechanism for passing file descriptors between processes.

**9. Frida Hooking:**

To debug, Frida is a natural choice for dynamic analysis:

* **Hooking functions:** The key is to intercept the `android_fdsan_*` functions.
* **Logging arguments:**  Logging the file descriptor and tag values is essential.
* **Tracing execution:**  Hooking related functions like `open`, `close`, `fopen`, `fclose` can provide context.

**10. Structuring the Answer:**

Finally, organizing the information into clear sections with headings is important for readability. I followed the prompt's structure as much as possible. Using bullet points, code examples, and clear explanations helps to convey the information effectively.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe fdsan directly modifies the kernel."  **Correction:**  More likely it uses existing system calls and internal `libc` structures to track tags.
* **Initial thought:** "Detailed implementation of every libc function." **Correction:** The header file doesn't contain the implementation. Focus on the *likely* implementation strategy and the purpose of each function.
* **Ensuring examples are concrete:** The examples in `android_fdsan_owner_type` are very helpful and should be highlighted.

By following these steps, combining code analysis, comment interpretation, and logical reasoning about system functionality, I arrived at the detailed explanation provided in the initial good answer.
这是一个位于 `bionic/libc/include/android/fdsan.h` 的头文件，属于 Android 的 C 库 bionic。它的主要功能是提供 **文件描述符安全（File Descriptor Sanitization，简称 fdsan）机制**。

**功能列举:**

该头文件定义了一组用于检测和防止文件描述符误用的接口，其核心功能包括：

1. **文件描述符所有权跟踪（File Descriptor Ownership Tracking）：**
   - 允许将文件描述符与一个“所有者标签”（owner tag）关联起来。
   - 这个标签可以用来标识哪个实体（例如，`FILE*` 指针的地址、`unique_fd` 对象的地址等）负责关闭这个文件描述符。

2. **强制所有者关闭（Enforce Owner Closure）：**
   - 提供 `android_fdsan_close_with_tag` 函数，要求在关闭文件描述符时，提供的标签必须与之前设置的标签匹配。
   - 如果标签不匹配，则会记录错误并根据配置的错误级别采取相应的行动（警告或中止）。

3. **所有者类型定义（Owner Type Definition）：**
   - 定义了 `android_fdsan_owner_type` 枚举，用于指示文件描述符所有者的类型，例如 `FILE*`、`DIR*`、`unique_fd`、Java 的各种 IO 类等。
   - 这有助于更清晰地识别错误来源。

4. **错误级别配置（Error Level Configuration）：**
   - 提供了设置和获取 fdsan 错误级别的函数 (`android_fdsan_get_error_level`, `android_fdsan_set_error_level`, `android_fdsan_set_error_level_from_property`)。
   - 可以配置 fdsan 在检测到错误时是发出警告、警告一次然后禁用、一直警告还是直接中止程序。

5. **获取和操作标签（Get and Manipulate Tags）：**
   - 提供了函数来创建、交换和获取文件描述符的标签 (`android_fdsan_create_owner_tag`, `android_fdsan_exchange_owner_tag`, `android_fdsan_get_owner_tag`)。
   - 也提供了函数来获取标签的类型和值 (`android_fdsan_get_tag_type`, `android_fdsan_get_tag_value`)。

**与 Android 功能的关系及举例说明:**

fdsan 是 Android 系统为了提高稳定性和可调试性而引入的一项重要功能。文件描述符管理不当是常见的 bug 来源，尤其是在多线程环境下。

**举例说明：**

* **`FILE*` 所有权:**  当使用 `fopen` 打开文件时，返回一个 `FILE*` 指针。fdsan 可以将该文件描述符与 `FILE*` 指针的地址作为标签关联起来。如果程序员错误地调用 `close(fileno(f))`，然后又调用 `fclose(f)`，`fclose` 内部也会尝试关闭同一个文件描述符，这时 fdsan 就会检测到标签不匹配并发出警告或中止。
* **`unique_fd` 所有权:**  C++ 中常用的智能指针 `unique_fd` 用于自动管理文件描述符的生命周期。fdsan 可以确保只有 `unique_fd` 析构时才能关闭其持有的文件描述符。
* **Java IO 类:**  Java 的 `FileInputStream`、`FileOutputStream` 等类底层也使用了文件描述符。fdsan 可以跟踪这些 Java 对象的生命周期，确保文件描述符在 Java 对象被垃圾回收或显式关闭时才会被关闭。
* **跨进程文件描述符传递:**  Android 的 Binder 机制允许在进程间传递文件描述符。fdsan 可以帮助确保传递的文件描述符在接收进程中被正确管理和关闭。

**libc 函数功能实现详解:**

这个头文件本身只声明了 fdsan 相关的函数接口，具体的实现代码位于 bionic 的其他源文件中（通常是 `bionic/libc/bionic/fdsan.c` 或类似的文件）。

**`android_fdsan_create_owner_tag(enum android_fdsan_owner_type type, uint64_t tag)`:**
   - **功能:** 创建一个所有者标签。将传入的 `type` 编码到标签的高位字节中，并将 `tag` 的低 56 位作为标签的值。
   - **实现:** 通常会使用位运算将类型信息存储到 64 位标签的高位字节，例如 `(static_cast<uint64_t>(type) << 56) | (tag & 0xffffffffffffff)`。
   - **假设输入:** `type = ANDROID_FDSAN_OWNER_TYPE_FILE`, `tag = 0x12345678`
   - **输出:**  一个 `uint64_t` 类型的标签，高位字节为 `0x01`，低 56 位为 `0x00000012345678` (假设小端序)。

**`android_fdsan_exchange_owner_tag(int fd, uint64_t expected_tag, uint64_t new_tag)`:**
   - **功能:** 交换指定文件描述符的标签。如果当前标签与 `expected_tag` 不匹配，则会记录错误并采取相应的行动。
   - **实现:**  需要访问系统维护的文件描述符信息，查找与 `fd` 关联的标签。比较当前标签与 `expected_tag`，如果匹配则更新为 `new_tag`。
   - **假设输入:** `fd = 3`, `expected_tag = 0x0100000012345678`, `new_tag = 0x03000000abcdef00`
   - **输出:** 无返回值。如果 `fd` 的当前标签不是 `expected_tag`，则会记录错误。

**`android_fdsan_close_with_tag(int fd, uint64_t tag)`:**
   - **功能:** 关闭文件描述符，并检查提供的标签是否与当前标签匹配。
   - **实现:**  首先访问系统维护的文件描述符信息，获取 `fd` 的当前标签。比较当前标签与传入的 `tag`，如果不匹配，则记录错误并采取相应的行动。如果匹配，则调用底层的 `close(fd)` 系统调用来关闭文件描述符，并将该文件描述符的标签重置为 0。
   - **假设输入:** `fd = 3`, `tag = 0x0100000012345678`
   - **输出:**  与 `close(2)` 系统调用相同，成功返回 0，失败返回 -1 并设置 `errno`。

**`android_fdsan_get_owner_tag(int fd)`:**
   - **功能:** 获取指定文件描述符的当前所有者标签。
   - **实现:**  访问系统维护的文件描述符信息，查找与 `fd` 关联的标签并返回。如果 `fd` 无效或未被标记，则返回 0。
   - **假设输入:** `fd = 3`
   - **输出:**  文件描述符 3 的当前标签，例如 `0x0100000012345678`。

**`android_fdsan_get_tag_type(uint64_t tag)`:**
   - **功能:** 获取所有者标签的类型字符串表示。
   - **实现:**  提取 `tag` 的高位字节，根据 `android_fdsan_owner_type` 枚举将其映射到对应的字符串描述，例如 "FILE*"、"unique_fd" 等。
   - **假设输入:** `tag = 0x0100000012345678`
   - **输出:**  字符串 "FILE*"。

**`android_fdsan_get_tag_value(uint64_t tag)`:**
   - **功能:** 获取所有者标签的值部分（去除类型信息）。
   - **实现:**  通过位运算屏蔽掉 `tag` 的高位字节，只保留低 56 位。
   - **假设输入:** `tag = 0x0100000012345678`
   - **输出:** `0x00000012345678`。

**`android_fdsan_get_error_level()`:**
   - **功能:** 获取当前的 fdsan 错误级别。
   - **实现:**  访问存储 fdsan 错误级别的全局变量并返回。

**`android_fdsan_set_error_level(enum android_fdsan_error_level new_level)`:**
   - **功能:** 设置 fdsan 的错误级别，并返回之前的级别。
   - **实现:**  更新存储 fdsan 错误级别的全局变量，并返回之前的值。需要注意的是，该函数不是线程安全的，通常在单线程环境下调用（例如 `fork` 之后）。

**`android_fdsan_set_error_level_from_property(enum android_fdsan_error_level default_level)`:**
   - **功能:** 从系统属性中读取 fdsan 的错误级别，如果属性不存在则使用默认值。
   - **实现:**  读取名为 `ro.debug.fdsan.error_level` 或类似的系统属性。根据属性值设置 fdsan 的错误级别。如果属性不存在或无效，则使用 `default_level`。

**涉及 dynamic linker 的功能和处理过程:**

这里涉及的函数都是定义在 `libc.so` 中的。当程序启动时，dynamic linker（`linker64` 或 `linker`）会将 `libc.so` 加载到进程的地址空间中，并解析这些符号。

**so 布局样本 (简化):**

```
libc.so:
    .text:
        android_fdsan_create_owner_tag:  <代码地址>
        android_fdsan_exchange_owner_tag: <代码地址>
        android_fdsan_close_with_tag:    <代码地址>
        ...
    .data:
        g_fdsan_error_level: <错误级别变量地址>
    .dynsym:
        android_fdsan_create_owner_tag
        android_fdsan_exchange_owner_tag
        android_fdsan_close_with_tag
        ...
```

**链接的处理过程:**

1. **程序加载:** 当一个程序（例如 Java 虚拟机进程 `zygote` 或一个 NDK 应用）启动时，dynamic linker 会被内核调用。
2. **依赖库加载:** Dynamic linker 会读取程序的可执行文件头，找到其依赖的共享库，例如 `libc.so`。
3. **库加载到内存:** Dynamic linker 将 `libc.so` 加载到进程的内存空间中。
4. **符号解析:** Dynamic linker 遍历程序的重定位表（Relocation Table），找到需要解析的外部符号，例如 `android_fdsan_create_owner_tag`。
5. **查找符号地址:** Dynamic linker 在 `libc.so` 的 `.dynsym` 段中查找这些符号，找到对应的地址。
6. **重定位:** Dynamic linker 将找到的地址写入到程序代码中需要调用这些函数的地方，完成链接过程。

**逻辑推理和假设输入/输出:**

假设有以下代码片段：

```c
#include <stdio.h>
#include <unistd.h>
#include <android/fdsan.h>

int main() {
    FILE *fp = fopen("test.txt", "r");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    int fd = fileno(fp);
    uint64_t owner_tag = android_fdsan_create_owner_tag(ANDROID_FDSAN_OWNER_TYPE_FILE, (uint64_t)fp);
    android_fdsan_exchange_owner_tag(fd, 0, owner_tag);

    // 错误使用：直接 close fd，而不是使用 fclose
    close(fd);

    // 尝试使用已经关闭的文件指针
    char buf[100];
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        printf("Read: %s\n", buf);
    }

    // 正确关闭方式：fclose(fp);

    return 0;
}
```

**假设输入:**  程序启动，文件 "test.txt" 存在。

**输出:**  由于 `close(fd)` 直接关闭了文件描述符，而 fdsan 已经将该文件描述符与 `fp` 的地址关联。当 `close(fd)` 执行时，如果 fdsan 的错误级别设置为 `ANDROID_FDSAN_ERROR_LEVEL_WARN_ALWAYS` 或 `ANDROID_FDSAN_ERROR_LEVEL_FATAL`，则会产生日志输出，指示文件描述符被错误关闭，因为它的所有者标签不匹配。如果错误级别是 `FATAL`，程序会中止。

**用户或编程常见的使用错误举例:**

1. **忘记使用 `fclose` 或 `close_with_tag`:** 直接使用 `close(fd)` 关闭通过 `fopen` 或其他方式获取的文件描述符，导致所有权混乱。
2. **多次关闭同一个文件描述符:**  例如，在 `fclose` 之后再次调用 `close(fileno(fp))`。
3. **在错误的时间关闭文件描述符:** 例如，在一个函数中关闭了传递进来的文件描述符，而调用者仍然需要使用它。
4. **多线程环境下文件描述符共享不当:**  多个线程可能同时操作同一个文件描述符，导致竞争条件和错误关闭。
5. **不理解所有权概念:**  没有正确理解文件描述符的所有权，导致在不应该关闭的地方关闭了文件描述符。

**Android framework 或 NDK 如何到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 的路径:**

1. **Java 代码调用:**  例如，Java 的 `FileInputStream` 的 `close()` 方法最终会调用 native 方法。
2. **JNI 调用:**  `FileInputStream` 的 native 方法会调用 bionic 库中的相关函数，这些函数内部会调用 `close` 或 `android_fdsan_close_with_tag`。例如，`java.io.FileInputStream.close0()` 可能会调用 `close()` 系统调用，而 bionic 的 fdsan 机制会在 `close()` 系统调用的实现中进行拦截和检查。

**NDK 的路径:**

1. **NDK 代码直接调用:**  NDK 开发者可以直接使用 bionic 提供的 fdsan 相关函数，例如 `android_fdsan_create_owner_tag` 和 `android_fdsan_close_with_tag`。
2. **NDK 代码间接调用:**  NDK 代码可能会调用标准 C 库的函数，例如 `fopen` 和 `fclose`。bionic 的 `fclose` 实现会利用 fdsan 机制来跟踪文件描述符的所有权。

**Frida Hook 示例:**

假设我们要 hook `android_fdsan_close_with_tag` 函数：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.example.myapp"])  # 替换为你的应用包名
    process = device.attach(pid)
except frida.TimedOutError:
    print("[-] Could not find USB device. Ensure device is connected and adb is running.")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print(f"[-] Could not find process for package 'com.example.myapp'. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "android_fdsan_close_with_tag"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var tag = args[1].toUInt64();
        console.log("[FDSAN Hook] android_fdsan_close_with_tag(fd=" + fd + ", tag=" + tag + ")");

        // 打印调用栈
        // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));
    },
    onLeave: function(retval) {
        console.log("[FDSAN Hook] android_fdsan_close_with_tag returns: " + retval);
    }
});
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()

device.resume(pid)

print("[*] Script loaded. Press Ctrl+C to exit.")
sys.stdin.read()
```

**解释:**

1. **连接设备和进程:** 代码首先尝试连接到 USB 设备并附加到目标应用程序的进程。
2. **查找函数地址:** `Module.findExportByName("libc.so", "android_fdsan_close_with_tag")` 用于查找 `libc.so` 中 `android_fdsan_close_with_tag` 函数的地址。
3. **Hook 函数:** `Interceptor.attach` 用于在函数入口和出口处插入代码。
4. **`onEnter`:** 在函数被调用时执行，可以访问函数的参数（`args`）。这里我们打印了文件描述符和标签的值。可以取消注释打印调用栈的代码以查看调用路径。
5. **`onLeave`:** 在函数返回时执行，可以访问函数的返回值。
6. **加载和运行:**  将脚本加载到目标进程并恢复进程执行。

通过运行这个 Frida 脚本，你可以在应用程序调用 `android_fdsan_close_with_tag` 时看到相应的日志输出，从而调试 fdsan 的工作流程和文件描述符的管理过程。你可以修改脚本来 hook 其他 fdsan 函数或相关的 `open`、`close` 等系统调用，以更深入地了解 Android 的文件描述符管理机制。

Prompt: 
```
这是目录为bionic/libc/include/android/fdsan.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2018 The Android Open Source Project
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

#include <sys/cdefs.h>

#include <stdbool.h>
#include <stdint.h>

__BEGIN_DECLS

/*
 * Error checking for close(2).
 *
 * Mishandling of file descriptor ownership is a common source of errors that
 * can be extremely difficult to diagnose. Mistakes like the following can
 * result in seemingly 'impossible' failures showing up on other threads that
 * happened to try to open a file descriptor between the buggy code's close and
 * fclose:
 *
 *     int print(int fd) {
 *         int rc;
 *         char buf[128];
 *         while ((rc = read(fd, buf, sizeof(buf))) > 0) {
 *             printf("%.*s", rc);
 *         }
 *         close(fd);
 *     }
 *
 *     int bug() {
 *         FILE* f = fopen("foo", "r");
 *         print(fileno(f));
 *         fclose(f);
 *     }
 *
 * To make it easier to find this class of bugs, bionic provides a method to
 * require that file descriptors are closed by their owners. File descriptors
 * can be associated with tags with which they must be closed. This allows
 * objects that conceptually own an fd (FILE*, unique_fd, etc.) to use their
 * own address at the tag, to enforce that closure of the fd must come as a
 * result of their own destruction (fclose, ~unique_fd, etc.)
 *
 * By default, a file descriptor's tag is 0, and close(fd) is equivalent to
 * closing fd with the tag 0.
 */

/*
 * For improved diagnostics, the type of a file descriptors owner can be
 * encoded in the most significant byte of the owner tag. Values of 0 and 0xff
 * are ignored, which allows for raw pointers to be used as owner tags without
 * modification.
 */
enum android_fdsan_owner_type {
  /*
   * Generic Java or native owners.
   *
   * Generic Java objects always use 255 as their type, using identityHashCode
   * as the value of the tag, leaving bits 33-56 unset. Native pointers are sign
   * extended from 48-bits of virtual address space, and so can have the MSB
   * set to 255 as well. Use the value of bits 49-56 to distinguish between
   * these cases.
   */
  ANDROID_FDSAN_OWNER_TYPE_GENERIC_00 = 0,
  ANDROID_FDSAN_OWNER_TYPE_GENERIC_FF = 255,

  /* FILE* */
  ANDROID_FDSAN_OWNER_TYPE_FILE = 1,

  /* DIR* */
  ANDROID_FDSAN_OWNER_TYPE_DIR = 2,

  /* android::base::unique_fd */
  ANDROID_FDSAN_OWNER_TYPE_UNIQUE_FD = 3,

  /* sqlite-owned file descriptors */
  ANDROID_FDSAN_OWNER_TYPE_SQLITE = 4,

  /* java.io.FileInputStream */
  ANDROID_FDSAN_OWNER_TYPE_FILEINPUTSTREAM = 5,

  /* java.io.FileOutputStream */
  ANDROID_FDSAN_OWNER_TYPE_FILEOUTPUTSTREAM = 6,

  /* java.io.RandomAccessFile */
  ANDROID_FDSAN_OWNER_TYPE_RANDOMACCESSFILE = 7,

  /* android.os.ParcelFileDescriptor */
  ANDROID_FDSAN_OWNER_TYPE_PARCELFILEDESCRIPTOR = 8,

  /* ART FdFile */
  ANDROID_FDSAN_OWNER_TYPE_ART_FDFILE = 9,

  /* java.net.DatagramSocketImpl */
  ANDROID_FDSAN_OWNER_TYPE_DATAGRAMSOCKETIMPL = 10,

  /* java.net.SocketImpl */
  ANDROID_FDSAN_OWNER_TYPE_SOCKETIMPL = 11,

  /* libziparchive's ZipArchive */
  ANDROID_FDSAN_OWNER_TYPE_ZIPARCHIVE = 12,

  /* native_handle_t */
  ANDROID_FDSAN_OWNER_TYPE_NATIVE_HANDLE = 13,

  /* android::Parcel */
  ANDROID_FDSAN_OWNER_TYPE_PARCEL = 14,
};

/*
 * Create an owner tag with the specified type and least significant 56 bits of tag.
 */

#if __BIONIC_AVAILABILITY_GUARD(29)
uint64_t android_fdsan_create_owner_tag(enum android_fdsan_owner_type type, uint64_t tag) __INTRODUCED_IN(29) __attribute__((__weak__));

/*
 * Exchange a file descriptor's tag.
 *
 * Logs and aborts if the fd's tag does not match expected_tag.
 */
void android_fdsan_exchange_owner_tag(int fd, uint64_t expected_tag, uint64_t new_tag) __INTRODUCED_IN(29) __attribute__((__weak__));

/*
 * Close a file descriptor with a tag, and resets the tag to 0.
 *
 * Logs and aborts if the tag is incorrect.
 */
int android_fdsan_close_with_tag(int fd, uint64_t tag) __INTRODUCED_IN(29) __attribute__((__weak__));

/*
 * Get a file descriptor's current owner tag.
 *
 * Returns 0 for untagged and invalid file descriptors.
 */
uint64_t android_fdsan_get_owner_tag(int fd) __INTRODUCED_IN(29);

/*
 * Get an owner tag's string representation.
 *
 * The return value points to memory with static lifetime, do not attempt to modify it.
 */
const char* _Nonnull android_fdsan_get_tag_type(uint64_t tag) __INTRODUCED_IN(29);

/*
 * Get an owner tag's value, with the type masked off.
 */
uint64_t android_fdsan_get_tag_value(uint64_t tag) __INTRODUCED_IN(29);
#endif /* __BIONIC_AVAILABILITY_GUARD(29) */


enum android_fdsan_error_level {
  // No errors.
  ANDROID_FDSAN_ERROR_LEVEL_DISABLED,

  // Warn once(ish) on error, and then downgrade to ANDROID_FDSAN_ERROR_LEVEL_DISABLED.
  ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE,

  // Warn always on error.
  ANDROID_FDSAN_ERROR_LEVEL_WARN_ALWAYS,

  // Abort on error.
  ANDROID_FDSAN_ERROR_LEVEL_FATAL,
};

/*
 * Get the error level.
 */

#if __BIONIC_AVAILABILITY_GUARD(29)
enum android_fdsan_error_level android_fdsan_get_error_level() __INTRODUCED_IN(29) __attribute__((__weak__));

/*
 * Set the error level and return the previous state.
 *
 * Error checking is automatically disabled in the child of a fork, to maintain
 * compatibility with code that forks, closes all file descriptors, and then
 * execs.
 *
 * In cases such as the zygote, where the child has no intention of calling
 * exec, call this function to reenable fdsan checks.
 *
 * This function is not thread-safe and does not synchronize with checks of the
 * value, and so should probably only be called in single-threaded contexts
 * (e.g. postfork).
 */
enum android_fdsan_error_level android_fdsan_set_error_level(enum android_fdsan_error_level new_level) __INTRODUCED_IN(29) __attribute__((__weak__));
#endif /* __BIONIC_AVAILABILITY_GUARD(29) */


/*
 * Set the error level to the global setting if available, or a default value.
 */

#if __BIONIC_AVAILABILITY_GUARD(30)
enum android_fdsan_error_level android_fdsan_set_error_level_from_property(enum android_fdsan_error_level default_level) __INTRODUCED_IN(30) __attribute__((__weak__));
#endif /* __BIONIC_AVAILABILITY_GUARD(30) */

__END_DECLS

"""

```