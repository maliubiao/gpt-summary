Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding (Skimming and Context):**

* **File Name:** `testbinary_is_stack_mte_after_dlopen.cpp`. This immediately suggests the test is related to Memory Tagging Extension (MTE) on the stack after using `dlopen`.
* **Path:** `bionic/tests/libs`. This tells us it's part of Android's Bionic library tests, specifically for library-related functionality.
* **Copyright:**  Standard Android Open Source Project copyright. Confirms the source.
* **Includes:**  A mix of standard C/C++ headers (`stdint.h`, `stdio.h`, `stdlib.h`), threading primitives (`condition_variable`, `thread`), dynamic linking (`dlfcn.h`), and internal Bionic headers (`mte_utils.h`, `CHECK.h`). This reinforces the dynamic linking and MTE focus.
* **`#if defined(__BIONIC__) && defined(__aarch64__)`:**  The core logic is only compiled for Android (Bionic) on ARM64 architectures. This is a crucial piece of information.

**2. High-Level Functionality Identification:**

* The core purpose is to verify if stack MTE is enabled after a dynamic library is loaded using `dlopen`.
* It involves creating threads, specifically before and after the `dlopen` call.
* It checks the state of MTE in these threads using `is_stack_mte_on()` and retrieves the MTE TLS pointer using `mte_tls()`.
* It touches a newly allocated stack page after `dlopen`.

**3. Detailed Code Analysis - Key Sections:**

* **`find_main_stack_limits`:**
    * Opens `/proc/self/maps`. Immediately, the connection to the Linux process information system is evident.
    * Reads memory map entries to locate the stack segment of the main thread.
    * Parses the start and end addresses of the stack region.
    * **Key Idea:**  This is how the test determines the boundaries of the main thread's stack.
* **`fault_new_stack_page`:**
    *  A recursive function that allocates a small buffer on the stack.
    *  The purpose is to force the stack to grow and potentially trigger any necessary remapping or MTE setup.
    * **Key Idea:** Verifying MTE is enabled on *newly allocated* stack pages after `dlopen`.
* **`main` function:**
    * **Argument Handling:** Checks for a command-line argument (the path to the dynamic library).
    * **Initial Checks:** Verifies the existence of the dynamic library and that MTE is initially *off*.
    * **Thread Creation (Early):** Creates a thread *before* `dlopen`. Checks MTE state within this thread.
    * **`dlopen`:** The central point of the test. Loads the dynamic library.
    * **Thread Creation (Late):** Creates a thread *after* `dlopen`. Checks MTE state.
    * **MTE State Assertions:** Uses `CHECK` macros to verify that MTE is enabled in the main thread and the new threads after `dlopen`. Also checks that the MTE TLS pointers are not null.
    * **Stack Growth Check:** Calls `fault_new_stack_page` to test MTE on a newly allocated stack page.

**4. Connecting to Android and Bionic:**

* **Bionic:** The test is *within* the Bionic source tree, so it's inherently related. Bionic's dynamic linker (`linker64` or `linker`) is responsible for `dlopen` and handling MTE setup during library loading.
* **MTE:** A security feature supported by ARMv8.5-A and later. Android leverages this for memory safety. Bionic's dynamic linker plays a role in ensuring MTE is correctly enabled/propagated when loading libraries.
* **`/proc/self/maps`:**  A standard Linux feature, but Bionic provides the underlying implementation for accessing process information.
* **`dlopen`:** A standard POSIX function, but Bionic provides its specific implementation, which includes MTE awareness.
* **`is_stack_mte_on()` and `mte_tls()`:** These are likely Bionic-specific utility functions (defined in `mte_utils.h`) to check and retrieve MTE-related information.

**5. Dynamic Linker Specifics:**

* **SO Layout (Hypothetical):**  Imagine a simple library:
    ```
    my_library.so:
        .text:  // Code segment
        .data:  // Initialized data
        .bss:   // Uninitialized data
    ```
* **Linking Process:**
    1. `dlopen("my_library.so", RTLD_NOW)` is called.
    2. Bionic's dynamic linker finds and loads `my_library.so` into memory.
    3. The linker maps the segments of `my_library.so` into the process's address space.
    4. **Crucially for MTE:** The linker ensures that the newly loaded library's stack (if it creates threads) is also configured with MTE if the main process has it enabled after `dlopen`. This test verifies this behavior.
    5. `RTLD_NOW` means all symbols are resolved immediately during `dlopen`.

**6. Error Scenarios:**

* **Forgetting to check return value of `dlopen`:**  If `dlopen` fails, it returns `NULL`. Not checking this can lead to crashes when trying to use the returned handle.
* **Incorrect library path:** Providing an invalid path to `dlopen` will cause it to fail.

**7. Android Framework/NDK Path:**

* **App Development:** An app developer uses the NDK to write native code.
* **NDK `dlopen`:** The NDK provides the `dlfcn.h` header, which allows using `dlopen` in native code.
* **Framework Service:** An Android framework service (written in Java or C++) might dynamically load native libraries using `System.loadLibrary()` (Java) or `dlopen` (C++). The Java call eventually translates to a native `dlopen` call in Bionic.

**8. Frida Hooking (Conceptual):**

* **Hook `dlopen`:** Intercept calls to `dlopen` to observe the library path.
* **Hook `is_stack_mte_on`:** See when and where this function is called and its return value.
* **Hook `mte_tls`:** Inspect the returned MTE TLS pointer.

**Self-Correction/Refinement During Analysis:**

* Initially, I might just see the threading and think it's purely about concurrency. However, the filename and the includes point strongly to the `dlopen` and MTE aspects.
* I need to pay close attention to *when* the threads are created relative to the `dlopen` call, as this is key to the test's logic.
* Understanding the purpose of `find_main_stack_limits` is crucial – it's not just a random utility function. It's about getting the baseline stack boundaries *before* the dynamic loading.
* The `fault_new_stack_page` function might initially seem complex, but the core idea is simply to force stack growth after `dlopen`.

By following this kind of structured breakdown, I can systematically understand the purpose and functionality of the given code and its relation to the broader Android ecosystem.
这个C++源代码文件 `testbinary_is_stack_mte_after_dlopen.cpp` 是 Android Bionic 库的一个测试，专门用来验证在使用 `dlopen` 加载动态库之后，新分配的栈内存是否启用了内存标记扩展 (Memory Tagging Extension, MTE)。

下面将详细列举其功能、与 Android 的关系、涉及的 libc 函数、dynamic linker 功能、逻辑推理、常见错误、以及如何在 Android Framework/NDK 中触发并进行调试。

**1. 文件功能:**

* **测试 MTE 在 `dlopen` 后的栈上是否启用:**  核心目的是验证当使用 `dlopen` 加载一个动态库后，主线程以及新创建的线程的栈内存是否正确地启用了 MTE。
* **检查主线程栈的 MTE 状态:** 在 `dlopen` 调用前后检查主线程栈的 MTE 状态。
* **检查新创建线程栈的 MTE 状态:**  在 `dlopen` 调用前后分别创建线程，并检查这些线程的栈是否启用了 MTE。
* **验证新分配的栈页是否启用 MTE:** 通过触发栈增长，检查在 `dlopen` 后新分配的栈内存页是否也启用了 MTE。
* **使用 `mte_tls()` 检查线程本地存储:** 验证与 MTE 相关的线程本地存储 (TLS) 指针是否被正确设置。

**2. 与 Android 功能的关系及举例说明:**

* **内存安全 (Memory Safety):** MTE 是 Android 为了提高内存安全而引入的一项硬件特性。这个测试直接验证了 Android 的动态链接器 (`linker64` 或 `linker`) 在加载动态库时是否正确地处理了 MTE 的配置。
* **动态库加载:**  `dlopen` 是 Android 中加载动态库的关键 API。Android 系统和应用程序广泛使用动态库来组织代码和实现模块化。这个测试确保了在动态加载场景下，MTE 能够正常工作。
* **线程管理:** Android 应用程序经常使用多线程来实现并发。这个测试覆盖了在 `dlopen` 发生时，不同时间点创建的线程栈的 MTE 状态。

**举例说明:**

假设一个 Android 应用的 native 代码需要使用一个第三方库。该应用可能会使用 `dlopen` 来加载这个第三方库。这个测试保证了当这个第三方库被加载到应用进程中后，应用的主线程以及任何它创建的新线程的栈内存都受到了 MTE 的保护，从而减少了内存安全漏洞的风险。

**3. 详细解释每一个 libc 函数的功能是如何实现的:**

* **`access(path, F_OK)`:**
    * **功能:** 检查文件是否存在以及是否可访问。`F_OK` 表示检查文件是否存在。
    * **实现:**  系统调用 `access(const char *pathname, int mode)`。内核会检查调用进程的权限以及文件的存在性。
* **`dlopen(path, RTLD_NOW)`:**
    * **功能:** 打开一个由 `path` 指定的动态链接库，并将其加载到调用进程的地址空间。`RTLD_NOW` 标志表示在 `dlopen` 返回之前解析所有未定义的符号。
    * **实现:** 这是一个复杂的过程，由 Android 的动态链接器 (`linker64` 或 `linker`) 实现。主要步骤包括：
        1. **查找库文件:** 根据 `path` 在预定义的路径（如 `/system/lib64`, `/vendor/lib64` 等）中查找库文件。
        2. **解析 ELF 文件头:** 读取库文件的 ELF 头，获取加载所需的各种信息，例如程序头表、节区头表等。
        3. **加载节区:** 将库文件的各个节区（如 `.text` 代码段, `.data` 初始化数据段, `.bss` 未初始化数据段等）映射到进程的地址空间。
        4. **符号解析和重定位:** 根据库文件的重定位表，修改代码和数据段中的地址引用，使其指向正确的内存地址。`RTLD_NOW` 会强制在此时完成所有符号的解析和重定位。
        5. **执行初始化函数:** 如果库文件有初始化函数 (`.init` 节或 `DT_INIT` 项指定)，则会执行这些函数。
        6. **MTE 处理:**  在加载过程中，链接器会考虑 MTE 的状态。如果系统支持 MTE 且调用进程的栈启用了 MTE，链接器需要确保新加载的库也能正确处理 MTE（例如，如果库创建新的线程，这些线程的栈也应该启用 MTE）。
* **`fclose(fp)`:**
    * **功能:** 关闭与文件指针 `fp` 关联的文件。
    * **实现:** 系统调用 `close(int fd)`，其中 `fd` 是文件描述符。内核会释放与该文件描述符相关的资源。
* **`fopen(path, "re")`:**
    * **功能:** 以只读二进制模式打开由 `path` 指定的文件。如果文件不存在或无法打开，则返回 `NULL`。
    * **实现:** 系统调用 `open(const char *pathname, int flags, mode_t mode)`，其中 `flags` 包括 `O_RDONLY` 和 `O_BINARY`。内核会为该文件分配一个文件描述符，并返回一个指向 `FILE` 结构的指针。
* **`fgets(line, sizeof(line), fp)`:**
    * **功能:** 从文件流 `fp` 中读取最多 `sizeof(line) - 1` 个字符到 `line` 指向的字符数组中，直到遇到换行符或文件结束符。
    * **实现:**  底层通常使用系统调用 `read(int fd, void *buf, size_t count)` 从文件描述符读取数据。
* **`sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &lo, &hi)`:**
    * **功能:** 从字符串 `line` 中按照指定的格式读取数据。`%" SCNxPTR` 用于读取十六进制的指针值。
    * **实现:**  `sscanf` 函数会解析字符串，并根据格式字符串将提取出的值存储到相应的变量中。
* **`abort()`:**
    * **功能:** 立即终止程序执行，通常用于表示发生了无法恢复的错误。
    * **实现:**  发送 `SIGABRT` 信号给当前进程，默认情况下会导致进程异常终止并产生 core dump 文件。
* **`printf("RAN\n")`:**
    * **功能:** 将格式化的字符串 `"RAN\n"` 输出到标准输出流。
    * **实现:**  底层通常使用系统调用 `write(int fd, const void *buf, size_t count)` 将数据写入到文件描述符 `1`（标准输出）。

**4. 对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**so 布局样本 (简化):**

```
my_library.so:
    .text:  // 代码段
        <函数代码>
    .rodata: // 只读数据段
        <常量数据>
    .data:  // 初始化数据段
        <全局变量>
    .bss:   // 未初始化数据段
        <未初始化的全局变量>
    .dynamic: // 动态链接信息
        DT_SONAME: my_library.so
        DT_NEEDED: libc.so
        DT_INIT: <初始化函数地址>
        // ... 其他动态链接信息
    .symtab: // 符号表
        <导出的符号信息>
    .strtab: // 字符串表
        <符号名称字符串>
    .rel.dyn: // 动态重定位表
        // ... 重定位条目
    .rel.plt: // PLT 重定位表
        // ... 重定位条目
```

**链接的处理过程 (针对 `dlopen`):**

1. **查找库文件:** 当 `dlopen("my_library.so", RTLD_NOW)` 被调用时，动态链接器会根据配置的搜索路径查找 `my_library.so` 文件。
2. **加载到内存:** 链接器会将 `my_library.so` 的各个段映射到进程的地址空间中。这涉及到创建虚拟内存映射。
3. **符号解析:** 由于使用了 `RTLD_NOW`，链接器会在 `dlopen` 返回之前解析所有未定义的符号。这包括：
    * **查找依赖库:** 解析 `.dynamic` 段中的 `DT_NEEDED` 条目，找到 `my_library.so` 依赖的其他库（例如 `libc.so`），并确保这些依赖库也被加载。
    * **符号查找:** 对于 `my_library.so` 中引用的外部符号，链接器会在已加载的库中查找其定义。
4. **重定位:**  链接器会修改代码和数据段中的地址引用，使其指向正确的内存地址。这通过读取 `.rel.dyn` 和 `.rel.plt` 等重定位表完成。例如，如果 `my_library.so` 调用了 `libc.so` 中的 `printf` 函数，链接器会将对 `printf` 的调用指令中的地址修改为 `printf` 在 `libc.so` 中的实际地址。
5. **MTE 配置:**
    * 链接器会检查系统的 MTE 支持以及调用进程的 MTE 配置。
    * 如果主进程的栈启用了 MTE，链接器需要确保为 `my_library.so` 创建的任何新线程的栈也启用 MTE。
    * 链接器可能会设置与 MTE 相关的线程本地存储 (TLS)。
6. **执行初始化代码:**  如果 `my_library.so` 定义了初始化函数（通过 `.init` 段或 `DT_INIT` 指定），链接器会在完成重定位后执行这些函数。

**5. 如果做了逻辑推理，请给出假设输入与输出:**

**假设输入:**

* 编译后的测试二进制文件 `testbinary_is_stack_mte_after_dlopen`
* 一个简单的动态库 `libtest.so`，该库不做任何特殊操作，只是一个空库即可。

**预期输出:**

如果测试成功，程序应该打印 "RAN\n" 并返回 0。如果任何一个 `CHECK` 宏失败，程序将会调用 `abort()` 终止。

在这个测试中，关键的逻辑推理在于：

* **`dlopen` 应该触发 MTE 的启用 (如果系统支持且之前未启用):**  测试假设在 `dlopen` 调用之后，主线程的栈会启用 MTE。
* **新创建的线程应该继承或启用 MTE:**  测试假设在 `dlopen` 调用前后创建的线程，它们的栈都应该启用 MTE。
* **新分配的栈内存页应该启用 MTE:** 测试假设在 `dlopen` 后，由于栈增长而新分配的内存页也应该启用 MTE。

**6. 如果涉及用户或者编程常见的使用错误，请举例说明:**

* **未检查 `dlopen` 的返回值:** 如果 `dlopen` 失败（例如，找不到指定的库文件），它会返回 `NULL`。如果程序没有检查返回值就尝试使用返回的句柄，会导致程序崩溃。

   ```c++
   void* handle = dlopen("non_existent_library.so", RTLD_NOW);
   // 错误：未检查 handle 是否为 NULL
   void (*func)();
   *(void **)(&func) = dlsym(handle, "some_function"); // 如果 handle 为 NULL，这里会崩溃
   ```

* **使用错误的库路径:**  `dlopen` 需要提供正确的库文件路径。如果路径错误，`dlopen` 会失败。

   ```c++
   // 假设库文件在 /data/local/tmp/mylib.so
   void* handle = dlopen("mylib.so", RTLD_NOW); // 错误：可能找不到库
   void* handle = dlopen("/data/local/tmp/mylib.so", RTLD_NOW); // 正确
   ```

* **忘记处理 `dlclose`:** 虽然在这个测试中没有使用 `dlclose`，但在实际编程中，当不再需要动态库时，应该使用 `dlclose` 来卸载库并释放资源。忘记 `dlclose` 可能导致资源泄漏。

* **假设 `dlopen` 总能成功:**  网络问题、文件权限问题、库文件损坏等都可能导致 `dlopen` 失败。编写健壮的代码需要处理 `dlopen` 可能失败的情况。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤:**

1. **Java 代码请求加载 native 库:** 在 Android Framework 的 Java 代码中，可能会调用 `System.loadLibrary("test")` 来加载一个名为 `libtest.so` 的 native 库。
2. **`System.loadLibrary` 的 native 实现:**  `System.loadLibrary` 方法最终会调用到 Android Runtime (ART) 的 native 代码。
3. **ART 调用 `dlopen`:** ART 会使用 `dlopen` 函数来加载指定的 native 库。ART 会根据库名称查找对应的 `.so` 文件，并调用 `dlopen`。

**NDK 到达这里的步骤:**

1. **NDK 代码调用 `dlopen`:** 使用 NDK 开发的 native 代码可以直接调用 `dlopen` 函数来加载动态库。

   ```c++
   #include <dlfcn.h>

   void loadMyLibrary() {
       void* handle = dlopen("/path/to/my/library.so", RTLD_NOW);
       if (handle == nullptr) {
           // 处理错误
       }
       // ... 使用库中的函数
       // dlclose(handle);
   }
   ```

**Frida Hook 示例调试步骤:**

可以使用 Frida 来 hook 相关的函数调用，以观察参数和返回值，从而调试动态库加载过程和 MTE 的状态。

**Hook `dlopen`:**

```python
import frida
import sys

package_name = "your.android.app.package"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        var flags = args[1].toInt();
        console.log(`[*] dlopen called with path: ${path}, flags: ${flags}`);
    },
    onLeave: function(retval) {
        console.log(`[*] dlopen returned: ${retval}`);
    }
});

Interceptor.attach(Module.findExportByName(null, "is_stack_mte_on"), {
    onEnter: function(args) {
        console.log("[*] is_stack_mte_on called");
    },
    onLeave: function(retval) {
        console.log("[*] is_stack_mte_on returned: " + retval);
    }
});

Interceptor.attach(Module.findExportByName(null, "mte_tls"), {
    onEnter: function(args) {
        console.log("[*] mte_tls called");
    },
    onLeave: function(retval) {
        console.log("[*] mte_tls returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将上述 Python 代码保存为 `hook.py`。
2. 确保你的 Android 设备已连接并启用了 USB 调试。
3. 安装 Frida 和 frida-tools (`pip install frida frida-tools`)。
4. 替换 `package_name` 为你要调试的应用程序的包名。
5. 运行应用程序。
6. 在终端中运行 `python hook.py`。

Frida 脚本会 hook `dlopen`、`is_stack_mte_on` 和 `mte_tls` 函数，并在这些函数被调用时打印相关信息，包括 `dlopen` 的路径和标志，以及 `is_stack_mte_on` 和 `mte_tls` 的返回值，从而帮助你观察动态库加载过程和 MTE 的状态变化。

通过以上分析，可以全面理解 `testbinary_is_stack_mte_after_dlopen.cpp` 文件的功能、与 Android 的关系、涉及的技术细节以及如何进行调试。

### 提示词
```
这是目录为bionic/tests/libs/testbinary_is_stack_mte_after_dlopen.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2024 The Android Open Source Project
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <condition_variable>
#include <thread>

#include <dlfcn.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include "../mte_utils.h"
#include "CHECK.h"

#if defined(__BIONIC__) && defined(__aarch64__)

enum State { kInit, kThreadStarted, kStackRemapped };

// We can't use pthread_getattr_np because that uses the rlimit rather than the actual mapping
// bounds.
static void find_main_stack_limits(uintptr_t* low, uintptr_t* high) {
  uintptr_t startstack = reinterpret_cast<uintptr_t>(__builtin_frame_address(0));

  // Hunt for the region that contains that address.
  FILE* fp = fopen("/proc/self/maps", "re");
  if (fp == nullptr) {
    abort();
  }
  char line[BUFSIZ];
  while (fgets(line, sizeof(line), fp) != nullptr) {
    uintptr_t lo, hi;
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &lo, &hi) == 2) {
      if (lo <= startstack && startstack <= hi) {
        *low = lo;
        *high = hi;
        fclose(fp);
        return;
      }
    }
  }
  abort();
}

template <typename Fn>
unsigned int fault_new_stack_page(uintptr_t low, Fn f) {
  uintptr_t new_low;
  uintptr_t new_high;
  volatile char buf[4096];
  buf[4095] = 1;
  find_main_stack_limits(&new_low, &new_high);
  if (new_low < low) {
    f();
    return new_high;
  }
  // Useless, but should defeat TCO.
  return new_low + fault_new_stack_page(low, f);
}
extern "C" int main(int argc, char** argv) {
  if (argc < 2) {
    return 1;
  }
  const char* path = argv[1];
  CHECK(access(path, F_OK) == 0);  // Verify test setup.
  CHECK(!is_stack_mte_on());
  std::mutex m;
  std::condition_variable cv;
  State state = kInit;

  bool is_early_thread_mte_on = false;
  void* early_thread_mte_tls = nullptr;
  std::thread early_th([&] {
    {
      std::lock_guard lk(m);
      state = kThreadStarted;
    }
    cv.notify_one();
    {
      std::unique_lock lk(m);
      cv.wait(lk, [&] { return state == kStackRemapped; });
    }
    is_early_thread_mte_on = is_stack_mte_on();
    early_thread_mte_tls = mte_tls();
    *reinterpret_cast<uintptr_t*>(early_thread_mte_tls) = 1;
  });
  {
    std::unique_lock lk(m);
    cv.wait(lk, [&] { return state == kThreadStarted; });
  }
  void* handle = dlopen(path, RTLD_NOW);
  {
    std::lock_guard lk(m);
    state = kStackRemapped;
  }
  cv.notify_one();
  CHECK(handle != nullptr);
  CHECK(is_stack_mte_on());
  CHECK(mte_tls() != nullptr);

  bool new_stack_page_mte_on = false;
  uintptr_t low;
  uintptr_t high;
  find_main_stack_limits(&low, &high);
  fault_new_stack_page(low, [&] { new_stack_page_mte_on = is_stack_mte_on(); });
  CHECK(new_stack_page_mte_on);

  bool is_late_thread_mte_on = false;
  void* late_thread_mte_tls = nullptr;
  std::thread late_th([&] {
    is_late_thread_mte_on = is_stack_mte_on();
    late_thread_mte_tls = mte_tls();
    *reinterpret_cast<uintptr_t*>(late_thread_mte_tls) = 1;
  });
  late_th.join();
  early_th.join();
  CHECK(is_late_thread_mte_on);
  CHECK(is_early_thread_mte_on);
  CHECK(late_thread_mte_tls != nullptr);
  CHECK(early_thread_mte_tls != nullptr);
  printf("RAN\n");
  return 0;
}

#else
extern "C" int main(int, char**) {
  return 1;
}
#endif
```