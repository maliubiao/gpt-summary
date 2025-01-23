Response:
Let's break down the thought process for generating the response.

1. **Understand the Core Request:** The user wants a comprehensive explanation of the provided C++ code snippet (`bionic/libc/bionic/fdtrack.cpp`). The request emphasizes functionality, relation to Android, internal implementation details (especially libc and dynamic linker), usage errors, and how to interact with it (Frida).

2. **Initial Code Analysis (High-Level):**  The code defines functions related to enabling/disabling and setting hooks for file descriptor tracking (`fdtrack`). It seems to use atomic operations for thread safety. The `__libc_init_fdtrack` function suggests initialization during libc startup.

3. **Categorize the Required Information:**  Based on the request, the necessary information can be grouped as follows:
    * **Functionality:** What does this code *do*?
    * **Android Relevance:** How does it relate to the Android ecosystem?
    * **Libc Function Implementation:**  Detailed explanation of the libc functions involved.
    * **Dynamic Linker Involvement:**  How, if at all, does this interact with the dynamic linker?
    * **Logic/Assumptions:** Any inherent logic or assumptions in the code?
    * **Usage Errors:** Common mistakes developers might make.
    * **Android Framework/NDK Path:** How does code execution reach this module?
    * **Frida Hooking:** Examples of how to intercept and observe the behavior.

4. **Detailed Code Analysis (Function by Function):**

    * **`__android_fdtrack_hook`:** This is an atomic global variable, likely holding a function pointer. This immediately suggests a mechanism for registering a callback to be notified about file descriptor events.

    * **`__android_fdtrack_globally_disabled`:** Another global boolean. Clearly controls the global on/off state of fd tracking.

    * **`android_fdtrack_set_globally_enabled()`:** A simple setter for the global disable flag.

    * **`android_fdtrack_get_enabled()`:**  Checks both the thread-local (`__get_bionic_tls().fdtrack_disabled`) and global disable flags. This implies that tracking can be disabled globally or on a per-thread basis. The `__get_bionic_tls()` points to Thread Local Storage, which is a crucial detail.

    * **`android_fdtrack_set_enabled()`:** Modifies the thread-local disable flag. It also returns the *previous* state, which is good practice for such settings.

    * **`android_fdtrack_compare_exchange_hook()`:** Uses `atomic_compare_exchange_strong`. This is a standard atomic operation for safely updating the function hook pointer. It ensures that the update only happens if the current value matches the expected value, preventing race conditions.

    * **`__libc_init_fdtrack()`:** This function registers a signal handler for `BIONIC_SIGNAL_FDTRACK`. The handler is a no-op (does nothing). This raises the question: why register a signal handler that does nothing?  The answer is likely to reserve the signal number and potentially allow other parts of the system to *send* this signal, which the fdtrack mechanism might internally listen for (though this specific code doesn't show that). The comment "Register a no-op signal handler" is a strong hint.

5. **Connecting to Android Functionality:**

    * The name "fdtrack" strongly suggests it's for tracking file descriptor usage. This is a valuable debugging and monitoring tool, especially for resource leaks.
    * The thread-local and global enabling/disabling mechanisms indicate flexibility in how the tracking is used.
    * The hook mechanism allows external code to be notified of file descriptor events, making it extensible.

6. **Libc Function Details:**

    * **`atomic_compare_exchange_strong`:** Explain its purpose in atomic operations and thread safety.
    * **`signal`:** Explain how signal handlers work in Unix-like systems and why a no-op handler might be used.
    * **`__get_bionic_tls()`:** Explain the concept of Thread Local Storage and its purpose.

7. **Dynamic Linker Aspect:**  While the provided code itself doesn't *directly* call dynamic linker functions, its *presence* in `bionic` (Android's C library) means it's linked into almost every Android process. The dynamic linker is responsible for loading and linking this code at runtime. The hook mechanism itself could be used by dynamically loaded libraries. Therefore, provide a basic explanation of SO layout and linking.

8. **Logic and Assumptions:**

    * The code assumes that file descriptor operations will trigger some event (not shown in this snippet) that can then trigger the registered hook.
    * It assumes that the caller of the hook will handle the file descriptor information appropriately.

9. **Usage Errors:**

    * Not understanding the global vs. thread-local enabling.
    * Race conditions when setting the hook if not using `atomic_compare_exchange_hook`.
    * Expecting the hook to be called for *every* file descriptor operation if tracking isn't enabled.

10. **Android Framework/NDK Path:**  Think about how high-level Android code (Java in the framework, C++ in NDK) might indirectly lead to this code being executed. Consider system calls related to file I/O, and how the C library (bionic) intercepts and handles them. The initialization in `__libc_init_fdtrack` is key here – it happens during process startup.

11. **Frida Hooking:**  Provide practical examples of how to use Frida to intercept the relevant functions (`android_fdtrack_set_enabled`, `android_fdtrack_compare_exchange_hook`) and observe the global variable. Emphasize the use of `Interceptor.attach`.

12. **Structure and Language:**  Organize the information logically using clear headings. Use precise technical terms but explain them where necessary. Maintain a helpful and informative tone. Use Chinese as requested.

13. **Review and Refine:**  Read through the entire response to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have focused too much on the signal handler without fully explaining *why* a no-op handler is useful in this context. The refinement process would involve adding that crucial detail. Also, ensuring the Frida examples are correct and practical is important.
好的，让我们详细分析一下 `bionic/libc/bionic/fdtrack.cpp` 这个文件的功能和实现。

**功能概述**

`fdtrack.cpp` 文件的主要功能是提供一个用于跟踪文件描述符 (file descriptor) 使用情况的机制。它允许在全局或线程级别启用/禁用跟踪，并提供了一个可以设置钩子 (hook) 函数的接口，以便在文件描述符相关的操作发生时得到通知。这对于调试、性能分析以及检测资源泄漏等场景非常有用。

**与 Android 功能的关系及举例说明**

文件描述符是操作系统用于访问文件、网络连接和其他 I/O 资源的抽象句柄。在 Android 系统中，文件描述符被广泛使用，例如：

* **打开文件:** 当应用程序打开一个文件时，会获得一个文件描述符。
* **创建 socket 连接:** 网络通信需要创建 socket，每个 socket 也对应一个文件描述符。
* **管道 (pipe):** 进程间通信可以使用管道，管道的两端也分别对应文件描述符。
* **binder 通信:** Android 的进程间通信机制 binder 底层也涉及文件描述符的传递。

`fdtrack` 机制可以帮助开发者监控这些文件描述符的创建、使用和关闭，从而发现潜在的问题。

**举例说明:**

假设一个应用在进行网络通信时，由于某些逻辑错误，打开了很多 socket 连接却没有及时关闭，导致文件描述符泄漏。通过启用 `fdtrack` 并设置相应的钩子函数，开发者可以记录下每次打开 socket 的操作，并在程序结束时检查是否有未关闭的 socket，从而定位问题。

**详细解释每一个 libc 函数的功能是如何实现的**

1. **`_Atomic(android_fdtrack_hook_t) __android_fdtrack_hook;`**

   * **功能:** 定义一个原子变量 `__android_fdtrack_hook`，用于存储用户设置的钩子函数。`android_fdtrack_hook_t`  很可能是一个函数指针类型。
   * **实现:** 使用 C++11 的原子类型 `_Atomic` 保证了对该变量的并发访问是线程安全的。这意味着即使多个线程同时尝试设置或读取这个钩子函数，也不会出现数据竞争的问题。原子操作通常由编译器或底层硬件指令实现，确保操作的完整性和不可分割性。

2. **`bool __android_fdtrack_globally_disabled = false;`**

   * **功能:** 定义一个全局布尔变量 `__android_fdtrack_globally_disabled`，用于全局性地禁用文件描述符跟踪。
   * **实现:**  这是一个简单的布尔变量，初始化为 `false`，表示默认情况下全局跟踪是启用的。

3. **`void android_fdtrack_set_globally_enabled(bool new_value)`**

   * **功能:**  设置全局的文件描述符跟踪启用状态。
   * **实现:**  直接修改全局变量 `__android_fdtrack_globally_disabled` 的值。如果 `new_value` 为 `true`，则 `__android_fdtrack_globally_disabled` 被设置为 `false`（因为禁用状态用 `true` 表示）。

4. **`bool android_fdtrack_get_enabled()`**

   * **功能:** 获取当前线程的文件描述符跟踪启用状态。
   * **实现:**  它首先通过 `__get_bionic_tls()` 获取当前线程的线程局部存储 (Thread Local Storage, TLS) 的引用。TLS 允许每个线程拥有自己独立的变量副本。然后，它检查 TLS 中的 `fdtrack_disabled` 标志以及全局禁用标志 `__android_fdtrack_globally_disabled`。只有当线程局部跟踪没有被禁用 **并且** 全局跟踪也没有被禁用时，该函数才返回 `true`。

5. **`bool android_fdtrack_set_enabled(bool new_value)`**

   * **功能:** 设置当前线程的文件描述符跟踪启用状态。
   * **实现:**  首先获取当前线程的 TLS 引用，然后保存当前的 `fdtrack_disabled` 状态到 `prev` 变量中。接着，根据 `new_value` 设置 TLS 中的 `fdtrack_disabled` 标志。最后返回之前的状态 `prev`。

6. **`bool android_fdtrack_compare_exchange_hook(android_fdtrack_hook_t* expected, android_fdtrack_hook_t value)`**

   * **功能:** 原子地比较并交换全局钩子函数。
   * **实现:**  使用 `atomic_compare_exchange_strong` 函数来实现。这是一个标准的原子操作，它比较 `__android_fdtrack_hook` 的当前值是否等于 `expected` 指向的值。如果相等，则将 `__android_fdtrack_hook` 的值设置为 `value` 并返回 `true`；否则，将 `expected` 指向的值更新为 `__android_fdtrack_hook` 的当前值，并返回 `false`。这个操作保证了在多线程环境下设置钩子函数的安全性，避免了多个线程同时设置导致数据不一致的问题。

7. **`void __libc_init_fdtrack()`**

   * **功能:** 初始化文件描述符跟踪机制。
   * **实现:**  它调用 `signal(BIONIC_SIGNAL_FDTRACK, [](int) {});` 来注册一个信号处理函数。`BIONIC_SIGNAL_FDTRACK` 是一个预定义的信号量。这里注册了一个 lambda 表达式作为信号处理函数，该函数接受一个 `int` 参数（信号编号），但实际上什么也不做 (no-op)。
   * **为什么注册一个空操作的信号处理函数？**  这通常是为了在系统层面保留这个信号量，防止其他地方使用。即使当前不执行任何操作，将来也可能通过发送这个信号来触发文件描述符跟踪相关的逻辑。这是一种预留机制。

**涉及 dynamic linker 的功能**

从这段代码本身来看，它并没有直接调用 dynamic linker 的 API。但是，作为 bionic libc 的一部分，它会被动态链接到所有的 Android 进程中。

**so 布局样本:**

```
应用程序进程内存布局：

0x......000  text segment (代码段，包含 fdtrack.cpp 编译后的机器码)
    ... 一些其他的 libc 代码 ...
    ... fdtrack.cpp 的代码 ...
0x......000  rodata segment (只读数据段，可能包含字符串常量等)
0x......000  data segment (已初始化数据段，包含 __android_fdtrack_globally_disabled 等全局变量)
    __android_fdtrack_hook 的地址
    __android_fdtrack_globally_disabled 的地址
0x......000  bss segment (未初始化数据段)
0x......000  heap (堆)
0x......000  stack (栈，每个线程都有自己的栈)
    ... 当前线程的 TLS 区域 ...
        tls.fdtrack_disabled 的地址
    ...
```

**链接的处理过程:**

1. **编译时链接:** 当应用程序或共享库依赖于 libc 时，链接器会将对 `android_fdtrack_set_enabled` 等符号的引用记录在可执行文件或共享库的动态符号表中。
2. **运行时链接:** 当 Android 系统启动一个进程或者加载一个共享库时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
   * 加载所有依赖的共享库到内存中，包括 `libc.so`。
   * 解析可执行文件和共享库的动态符号表。
   * 重定位符号：将代码中对外部符号的引用（例如 `android_fdtrack_set_enabled`）指向 `libc.so` 中对应的函数地址。这涉及到修改指令中的地址。
   * 处理 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table)：GOT 存储全局变量的地址，PLT 用于延迟绑定函数调用。

在 `fdtrack.cpp` 的上下文中，这意味着当应用程序调用 `android_fdtrack_set_enabled` 时，实际上会跳转到 `libc.so` 中该函数的实现地址。

**逻辑推理，给出假设输入与输出**

假设我们有以下代码片段：

```c++
#include <bionic/fdtrack.h>
#include <stdio.h>

int main() {
  printf("Initial fdtrack enabled: %d\n", android_fdtrack_get_enabled()); // 假设全局默认启用

  android_fdtrack_set_enabled(false);
  printf("Thread-local fdtrack enabled after set to false: %d\n", android_fdtrack_get_enabled());

  android_fdtrack_set_enabled(true);
  printf("Thread-local fdtrack enabled after set to true: %d\n", android_fdtrack_get_enabled());

  android_fdtrack_set_globally_enabled(false);
  printf("Global fdtrack enabled after set to false: %d\n", android_fdtrack_get_enabled()); // 此时全局禁用生效

  android_fdtrack_set_enabled(true); // 尝试在全局禁用时启用线程局部跟踪
  printf("Thread-local fdtrack enabled after set to true (global disabled): %d\n", android_fdtrack_get_enabled());

  return 0;
}
```

**预期输出:**

```
Initial fdtrack enabled: 1
Thread-local fdtrack enabled after set to false: 0
Thread-local fdtrack enabled after set to true: 1
Global fdtrack enabled after set to false: 0
Thread-local fdtrack enabled after set to true (global disabled): 0
```

**解释:**

* 初始状态下，假设全局跟踪是启用的 (`1`)。
* 调用 `android_fdtrack_set_enabled(false)` 后，当前线程的跟踪被禁用 (`0`)。
* 调用 `android_fdtrack_set_enabled(true)` 后，当前线程的跟踪被重新启用 (`1`)。
* 调用 `android_fdtrack_set_globally_enabled(false)` 后，全局跟踪被禁用。即使线程局部跟踪被设置为启用，由于全局禁用生效，`android_fdtrack_get_enabled()` 也会返回 `0`。
* 最后一次调用 `android_fdtrack_set_enabled(true)` 尝试启用线程局部跟踪，但由于全局禁用仍然有效，结果仍然是禁用 (`0`)。

**涉及用户或者编程常见的使用错误，请举例说明**

1. **误解全局和线程局部启用状态:** 开发者可能会认为只要调用了 `android_fdtrack_set_enabled(true)` 就能启用跟踪，而忽略了全局禁用状态。

   ```c++
   android_fdtrack_set_globally_enabled(false); // 全局禁用
   android_fdtrack_set_enabled(true); // 尝试启用线程局部跟踪，但无效
   if (android_fdtrack_get_enabled()) {
       // 这段代码不会执行，因为全局禁用了
       printf("fdtrack is enabled\n");
   }
   ```

2. **在多线程环境下设置钩子函数时出现竞争条件:** 如果多个线程同时尝试设置钩子函数，可能会导致只有一个线程的设置生效，或者出现未定义的行为。应该使用 `android_fdtrack_compare_exchange_hook` 来原子地设置钩子函数。

   ```c++
   android_fdtrack_hook_t my_hook = [](int fd) { /* 处理文件描述符 */ };
   // 错误的做法，可能存在竞争
   __android_fdtrack_hook = my_hook;

   // 正确的做法，使用原子操作
   android_fdtrack_hook_t expected = nullptr; // 假设初始钩子为 nullptr
   android_fdtrack_compare_exchange_hook(&expected, my_hook);
   ```

3. **忘记处理钩子函数中的异常:** 如果钩子函数执行过程中抛出异常，可能会导致程序崩溃或行为异常。应该在钩子函数中进行适当的异常处理。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

`fdtrack` 机制主要在 native 层工作，因此通常是通过 NDK 开发的应用或 Android Framework 的 native 组件来接触到。

**Android Framework 到达 `fdtrack` 的路径示例:**

1. **Java Framework 请求:** 例如，一个 Java Framework 组件需要打开一个文件。它会调用 Java 的文件 I/O API，例如 `FileOutputStream`。
2. **JNI 调用:** `FileOutputStream` 的底层实现会通过 JNI (Java Native Interface) 调用到 Android Runtime (ART) 的 native 代码。
3. **系统调用:** ART 的 native 代码会调用底层的系统调用，例如 `open()`。
4. **Bionic Libc:** `open()` 系统调用的实现位于 bionic libc 中。
5. **`fdtrack` 介入 (假设已启用):**  在 bionic libc 的文件 I/O 相关函数（如 `open`, `close`, `dup` 等）的实现中，可能会有代码检查 `fdtrack` 是否启用。如果启用，则会调用已注册的钩子函数，并传递当前操作的文件描述符信息。

**NDK 应用到达 `fdtrack` 的路径示例:**

1. **NDK 应用调用:** NDK 开发的 C/C++ 应用直接调用 bionic libc 的函数，例如 `open()`, `socket()` 等。
2. **Bionic Libc:** 这些调用直接进入 bionic libc 的实现。
3. **`fdtrack` 介入 (假设已启用):** 类似于 Framework 的情况，如果 `fdtrack` 启用，钩子函数会被调用。

**Frida Hook 示例调试:**

我们可以使用 Frida 来 hook `fdtrack` 相关的函数，观察其行为。以下是一些示例：

**1. Hook `android_fdtrack_set_enabled` 函数:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['msg']))
    else:
        print(message)

def main():
    package_name = "your.target.package"  # 替换为你的目标应用包名
    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Process with package name '{package_name}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "android_fdtrack_set_enabled"), {
        onEnter: function(args) {
            var enabled = !!args[0].toInt32();
            send({tag: "fdtrack", msg: "android_fdtrack_set_enabled called with: " + enabled});
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to detach.")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

这个脚本会 hook `android_fdtrack_set_enabled` 函数，并在每次调用时打印出传递的参数（是否启用）。

**2. Hook `android_fdtrack_compare_exchange_hook` 函数:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['msg']))
    else:
        print(message)

def main():
    package_name = "your.target.package"  # 替换为你的目标应用包名
    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Process with package name '{package_name}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "android_fdtrack_compare_exchange_hook"), {
        onEnter: function(args) {
            var expectedPtr = ptr(args[0]);
            var valuePtr = ptr(args[1]);

            // 读取 expected 指针指向的值（旧的钩子函数地址）
            var expectedValue = expectedPtr.readPointer();
            // 读取 value 指针的值（新的钩子函数地址）
            var newValue = valuePtr;

            send({tag: "fdtrack", msg: "android_fdtrack_compare_exchange_hook called. Expected: " + expectedValue + ", New Value: " + newValue});
        },
        onLeave: function(retval) {
            send({tag: "fdtrack", msg: "android_fdtrack_compare_exchange_hook returned: " + retval});
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to detach.")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

这个脚本会 hook `android_fdtrack_compare_exchange_hook` 函数，并在调用时打印出期望的旧钩子函数地址和新的钩子函数地址，以及函数的返回值（是否交换成功）。

**3. 观察全局禁用标志的变化:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['msg']))
    else:
        print(message)

def main():
    package_name = "your.target.package"  # 替换为你的目标应用包名
    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Process with package name '{package_name}' not found.")
        sys.exit(1)

    script_code = """
    var globalDisabledPtr = Module.findExportByName("libc.so", "__android_fdtrack_globally_disabled");
    if (globalDisabledPtr) {
        send({tag: "fdtrack", msg: "__android_fdtrack_globally_disabled address: " + globalDisabledPtr});
        // 每秒读取一次全局禁用标志的值
        setInterval(function() {
            var isDisabled = Memory.readU8(globalDisabledPtr);
            send({tag: "fdtrack", msg: "__android_fdtrack_globally_disabled value: " + isDisabled});
        }, 1000);
    } else {
        send({tag: "error", msg: "Could not find __android_fdtrack_globally_disabled"});
    }
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to detach.")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

这个脚本会找到全局禁用标志 `__android_fdtrack_globally_disabled` 的地址，并每秒读取其值，从而观察其变化。

通过这些 Frida hook 示例，你可以更深入地理解 `fdtrack` 机制的工作原理，并观察 Android Framework 或 NDK 应用如何与其交互。记住替换 `your.target.package` 为你想要调试的应用程序的包名。

### 提示词
```
这是目录为bionic/libc/bionic/fdtrack.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stdatomic.h>

#include <platform/bionic/fdtrack.h>
#include <platform/bionic/reserved_signals.h>

#include "private/bionic_fdtrack.h"
#include "private/bionic_tls.h"
#include "private/bionic_globals.h"

_Atomic(android_fdtrack_hook_t) __android_fdtrack_hook;

bool __android_fdtrack_globally_disabled = false;

void android_fdtrack_set_globally_enabled(bool new_value) {
  __android_fdtrack_globally_disabled = !new_value;
}

bool android_fdtrack_get_enabled() {
  return !__get_bionic_tls().fdtrack_disabled && !__android_fdtrack_globally_disabled;
}

bool android_fdtrack_set_enabled(bool new_value) {
  auto& tls = __get_bionic_tls();
  bool prev = !tls.fdtrack_disabled;
  tls.fdtrack_disabled = !new_value;
  return prev;
}

bool android_fdtrack_compare_exchange_hook(android_fdtrack_hook_t* expected,
                                           android_fdtrack_hook_t value) {
  return atomic_compare_exchange_strong(&__android_fdtrack_hook, expected, value);
}

void __libc_init_fdtrack() {
  // Register a no-op signal handler.
  signal(BIONIC_SIGNAL_FDTRACK, [](int) {});
}
```