Response:
Let's break down the thought process for analyzing this C++ header file (`utils.h`) within the context of Android's Bionic library tests.

**1. Understanding the Context:**

The initial prompt clearly states the file's location (`bionic/tests/utils.handroid bionic`) and the purpose of Bionic. This immediately tells me this file is *not* part of the core Bionic library itself, but rather a *testing utility* for Bionic. This distinction is crucial. It means the functions here are designed to help write tests for things like `libc`, `libm`, and the dynamic linker.

**2. High-Level Overview (Skimming and Identifying Major Sections):**

I start by quickly scanning the code, looking for major structural elements and keywords. I notice:

* **Includes:** A variety of standard C/C++ headers (`dirent.h`, `dlfcn.h`, `fcntl.h`, etc.) as well as some Android-specific ones (`sys/system_properties.h`, `android-base/...`). This suggests a mix of general utility functions and Android-specific testing aids.
* **Macros:** Several `#define` directives, some conditional on `__BIONIC__`, `__LP64__`, `__GLIBC__`. This indicates platform-specific handling and Bionic-specific logic.
* **Function-like Macros:** `SKIP_WITH_NATIVE_BRIDGE`, `KNOWN_FAILURE_ON_BIONIC`. These clearly relate to test execution control.
* **Functions:**  A collection of `static inline` functions (likely for performance in tests), and a few regular classes.
* **Classes:** `Maps`, `ExecTestHelper`, `FdLeakChecker`, `Errno`. These represent more structured utility functionalities.
* **Conditional Compilation:**  `#if defined(__linux__)` blocks suggest OS-specific code.
* **Global Variables:**  `get_executable_path`, `get_argc`, `get_argv`, `get_envp`. These are likely helpers for understanding the test environment.

**3. Detailed Analysis (Function by Function, Class by Class):**

Now, I go through each section more carefully, trying to understand the purpose of each element.

* **Includes:**  I recognize the standard library headers and their general purpose. The Android-specific headers hint at interaction with Android system properties.
* **Macros:**
    * `untag_address`:  Relates to memory tagging (likely MTE). The conditional nature is important.
    * `PATH_TO_SYSTEM_LIB`, `BIN_DIR`:  Define standard locations on Android, useful for finding libraries and executables in tests.
    * `KNOWN_FAILURE_ON_BIONIC`:  A way to mark tests that are known to fail specifically on Bionic.
    * `have_dl()`: Checks if dynamic linking is working, which is relevant for Bionic tests.
    * `running_with_native_bridge()`: Detects if the test is running under a native bridge (like when running 32-bit apps on 64-bit systems), which can affect behavior.
    * `SKIP_WITH_NATIVE_BRIDGE`:  Allows skipping tests under native bridge.
* **`Maps` Class:** This is clearly about parsing `/proc/self/maps`, a standard Linux mechanism for inspecting memory mappings. The structure `map_record` represents a single entry in the maps file.
* **`gettid()` (extern "C"):** A standard Linux/POSIX function to get the thread ID.
* **`WaitUntilThreadSleep()`:**  A synchronization primitive for tests involving threads. It waits for a thread to enter a sleeping state. The logic involving reading `/proc/<pid>/stat` and checking the state is specific to Linux process monitoring.
* **`AssertChildExited()`:** A crucial helper for testing processes. It forks a child, runs code in the child, and then waits for the child to exit, asserting the exit status or signal.
* **`CloseOnExec()`:** Checks the `FD_CLOEXEC` flag on a file descriptor, indicating whether the FD should be closed when `execve()` is called. This is important for security and resource management.
* **`get_executable_path()`, `get_argc()`, `get_argv()`, `get_envp()`:**  These provide access to the execution environment of the test program itself. This is very useful for setting up test scenarios.
* **`ExecTestHelper` Class:** This is a powerful helper for running external commands or snippets of code in a separate process and capturing their output. It simplifies setting arguments, environment variables, and verifying output.
* **`FdLeakChecker` Class:**  A vital tool for ensuring tests don't leak file descriptors. The constructor records the initial number of open FDs, and the destructor checks if the count has changed.
* **`running_with_mte()`:** Checks if Memory Tagging Extension (MTE) is active on ARM64.
* **`NanoTime()`:** Likely a high-resolution timer.
* **`Errno` Class and related macros:** A wrapper around `errno` to facilitate easier assertions on error codes in tests.

**4. Connecting to Android and Dynamic Linking:**

Throughout the analysis, I look for specific connections to Android and the dynamic linker:

* **`__BIONIC__` macro:**  Indicates code specific to the Bionic C library.
* **`sys/system_properties.h`:**  Accessing Android system properties is a key Android-specific feature. The `running_with_native_bridge()` function directly uses this.
* **`dlfcn.h`:**  This header is fundamental to dynamic linking. The `have_dl()` function checks if dynamic linking is functional.
* **`PATH_TO_SYSTEM_LIB`:**  Points to the standard location of shared libraries on Android.
* **`ExecTestHelper`:** This can be used to launch executables that rely on the dynamic linker, making it essential for testing dynamic linking scenarios. I can envision using it to run small programs that load specific `.so` files.

**5. Addressing Specific Requirements of the Prompt:**

* **功能列表:**  As I analyze each element, I mentally list its function.
* **与 Android 功能的关系和举例:** I actively look for these connections and provide concrete examples like `running_with_native_bridge()` and the use of `PATH_TO_SYSTEM_LIB`.
* **libc 函数实现:**  Since this is a *test utility*, it doesn't directly implement `libc` functions. However, the *tests* that use these utilities *will* test `libc` functions. Therefore, I focus on how these utilities *facilitate* testing `libc`.
* **Dynamic Linker 功能:** The `ExecTestHelper`, the use of `dlfcn.h`, and the ability to run external programs make this utility relevant to testing the dynamic linker. I can then construct an example of an `so` layout and the linking process.
* **逻辑推理、假设输入输出:**  For functions like `WaitUntilThreadSleep` and `AssertChildExited`, I can create simple test case scenarios with hypothetical inputs and expected outputs.
* **用户或编程常见错误:** I consider how developers might misuse these utilities in tests, such as forgetting to check for FD leaks or incorrectly asserting exit codes.
* **Android Framework/NDK 到达这里的步骤和 Frida Hook:**  This requires understanding the Android build system and how tests are typically executed. I trace the path from building a test using the NDK to running it on a device, and how Frida could be used to intercept execution at various points.

**6. Structuring the Output:**

Finally, I organize my findings into a clear and structured response, addressing each point in the prompt with relevant details and examples. I use headings and bullet points to improve readability.

This systematic approach allows me to thoroughly understand the provided code and address all aspects of the prompt, even for a file that isn't core Bionic code but rather a helper for *testing* Bionic.
这是一个位于 `bionic/tests/utils.handroid bionic` 目录下的 C++ 头文件 `utils.h`。从文件名和路径来看，它属于 Android Bionic 库的测试工具集，并且很可能包含了一些用于编写和运行 Bionic 相关测试的辅助函数和类。

让我们逐一分析它的功能：

**主要功能列表:**

* **提供断言和辅助宏:**  集成了 `gtest/gtest.h`，提供了测试框架的基础设施，例如 `ASSERT_TRUE`, `ASSERT_EQ` 等宏，并定义了一些特定于 Bionic 测试的宏，如 `KNOWN_FAILURE_ON_BIONIC` 和 `SKIP_WITH_NATIVE_BRIDGE`。
* **进程和线程管理辅助:** 提供了创建和管理子进程、等待子进程结束、获取线程 ID 等功能，例如 `AssertChildExited`, `WaitUntilThreadSleep`, `gettid`。
* **文件描述符管理辅助:** 提供了检查文件描述符是否设置了 `close-on-exec` 标志的功能 (`CloseOnExec`)，以及一个用于检测文件描述符泄漏的类 `FdLeakChecker`。
* **内存映射信息获取:** 提供了读取和解析 `/proc/self/maps` 文件内容的 `Maps` 类，用于获取进程的内存映射信息。
* **执行测试程序辅助:** 提供了 `ExecTestHelper` 类，用于在子进程中执行程序，并可以捕获其标准输出和标准错误，方便测试需要启动外部程序的情况。
* **路径和环境信息获取:** 提供了获取当前可执行文件路径 (`get_executable_path`)、命令行参数 (`get_argc`, `get_argv`) 和环境变量 (`get_envp`) 的函数。
* **Android 特性检测:** 提供了检测是否运行在 Native Bridge 下 (`running_with_native_bridge`) 以及检测是否启用内存标记扩展 (MTE, Memory Tagging Extension) (`running_with_mte`) 的功能。
* **时间辅助:** 提供了获取高精度时间戳的函数 `NanoTime`。
* **错误码处理辅助:** 提供了 `Errno` 类和相关的宏 (`ASSERT_ERRNO`, `EXPECT_ERRNO`)，方便在测试中断言 `errno` 的值。
* **动态链接辅助:** 提供了检查动态链接是否可用的函数 `have_dl`。

**与 Android 功能的关系及举例说明:**

* **Native Bridge 检测 (`running_with_native_bridge`)**:  Android 可以在 64 位系统上运行 32 位应用，这时会使用 Native Bridge 进行指令翻译。这个函数用于判断当前测试是否运行在 Native Bridge 环境下。某些 Bionic 的行为可能在 Native Bridge 下有所不同，因此测试需要考虑这种情况。
    * **举例:**  如果一个测试用例涉及到特定的系统调用行为，而 Native Bridge 对该系统调用的实现可能与原生 64 位 Bionic 不同，则可以使用 `SKIP_WITH_NATIVE_BRIDGE` 宏跳过在 Native Bridge 环境下的测试。
* **系统属性访问 (`__system_property_find`)**: `running_with_native_bridge` 函数内部使用了 `__system_property_find` 来查询 `ro.dalvik.vm.isa.<abi>` 属性，这是 Android 系统属性机制的一部分。
    * **举例:**  测试 Bionic 中与 Native Bridge 兼容性相关的功能时，可能需要检查特定的系统属性。
* **标准库路径 (`PATH_TO_SYSTEM_LIB`, `BIN_DIR`)**:  定义了 Android 系统库和可执行文件的标准路径。这些路径在测试中可能需要用来加载特定的共享库或执行系统命令。
    * **举例:**  测试 `dlopen` 函数时，可能需要使用 `PATH_TO_SYSTEM_LIB` 拼接出 `/system/lib/libc.so` 的路径进行加载。
* **内存标记扩展 (MTE) 检测 (`running_with_mte`)**:  MTE 是 ARMv8.5-A 引入的一项安全特性，用于检测内存错误。Bionic 可能会针对 MTE 提供特定的支持。
    * **举例:**  某些内存相关的测试可能需要根据是否启用了 MTE 来采取不同的测试策略。

**libc 函数的功能实现:**

这个 `utils.h` 文件本身 **并没有实现 libc 函数的功能**。它是一个测试辅助文件，用于帮助测试 libc 函数以及 Bionic 的其他部分。

例如，`AssertChildExited` 函数可以用于测试 `fork`, `execve`, `waitpid` 等 libc 函数的行为。你可以创建一个子进程，在子进程中调用你想测试的 libc 函数，然后父进程使用 `AssertChildExited` 来验证子进程的退出状态。

**dynamic linker 的功能及 SO 布局样本和链接处理过程:**

`utils.h` 文件提供了一些辅助功能，可以用于测试 dynamic linker (通常指 `linker64` 或 `linker`)。

* **`have_dl()`**:  可以用来检查 `dlopen`, `dlsym`, `dlclose` 等 dynamic linker 相关的函数是否能够正常工作。

**SO 布局样本:**

假设我们有一个简单的共享库 `libtest.so`：

```c
// libtest.c
#include <stdio.h>

void hello_from_lib() {
    printf("Hello from libtest.so\n");
}
```

编译成共享库：

```bash
clang -shared -o libtest.so libtest.c
```

和一个依赖于 `libtest.so` 的可执行文件 `main_app`：

```c
// main.c
#include <stdio.h>
#include <dlfcn.h>

int main() {
    void *handle = dlopen("./libtest.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }
    typedef void (*hello_func_t)();
    hello_func_t hello = (hello_func_t) dlsym(handle, "hello_from_lib");
    if (hello) {
        hello();
    } else {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }
    dlclose(handle);
    return 0;
}
```

编译可执行文件：

```bash
clang main.c -o main_app -ldl
```

**链接处理过程:**

1. **加载:** 当 `main_app` 运行时，操作系统会加载 `main_app` 的代码段和数据段到内存中。
2. **动态链接器介入:** 由于 `main_app` 链接了动态库 (`libdl.so` 和间接依赖的 `libtest.so`)，dynamic linker 会被操作系统加载到进程的地址空间。
3. **依赖项解析:** dynamic linker 会解析 `main_app` 的依赖项，发现它依赖于 `./libtest.so`。
4. **加载依赖库:** dynamic linker 会尝试在指定的路径（或者通过 LD_LIBRARY_PATH 等环境变量指定的路径）找到 `libtest.so`，并将其加载到内存中。
5. **符号解析 (Relocation):** dynamic linker 会解析 `main_app` 中对 `libtest.so` 中符号的引用（例如 `dlsym` 查找的 `hello_from_lib`），并将这些引用重定位到 `libtest.so` 中相应的地址。这涉及到修改 `main_app` 代码段中的某些指令。
6. **`dlopen` 处理:** 当 `main_app` 调用 `dlopen("./libtest.so", RTLD_LAZY)` 时，如果 `libtest.so` 尚未加载，dynamic linker 会执行加载和链接的过程。`RTLD_LAZY` 表示符号解析会延迟到实际使用时。
7. **`dlsym` 处理:** 当 `main_app` 调用 `dlsym(handle, "hello_from_lib")` 时，dynamic linker 会在已加载的共享库 `libtest.so` 的符号表中查找名为 `hello_from_lib` 的符号，并返回其地址。
8. **`dlclose` 处理:**  当 `main_app` 调用 `dlclose(handle)` 时，如果 `libtest.so` 没有被其他模块引用，dynamic linker 可能会将其从内存中卸载。

**`utils.h` 在测试 Dynamic Linker 的应用:**

可以使用 `ExecTestHelper` 运行 `main_app`，并检查其输出，以验证 dynamic linker 的行为是否符合预期。例如，你可以验证 `dlopen` 是否成功加载了 `libtest.so`，`dlsym` 是否成功找到了 `hello_from_lib` 函数。

**逻辑推理、假设输入与输出:**

以 `WaitUntilThreadSleep` 函数为例：

**假设输入:**

* 一个原子变量 `tid`，初始值为 0。
* 另一个线程，其线程 ID 最终会被写入 `tid`。

**逻辑推理:**

该函数会不断循环，直到 `tid` 的值不为 0。当 `tid` 不为 0 时，它会尝试读取 `/proc/<tid_value>/stat` 文件，并使用正则表达式搜索表示线程状态为 "Sleeping" (通常是 'S') 的模式。如果找到，则函数返回。

**假设输出:**

* 函数最终会返回，前提是另一个线程成功运行并进入睡眠状态。

**涉及用户或者编程常见的使用错误:**

* **文件描述符泄漏:**  用户在编写测试时，可能打开了文件或 socket，但忘记关闭，导致资源泄漏。`FdLeakChecker` 可以帮助检测这种错误。
    ```c++
    TEST(MyTest, FileDescriptorLeak) {
        FdLeakChecker leak_checker; // 在作用域结束时检查泄漏
        int fd = open("/tmp/test_file", O_RDONLY);
        // 忘记 close(fd);
    }
    ```
* **子进程未正确等待:**  使用 `fork` 创建子进程后，父进程必须使用 `waitpid` 等函数等待子进程结束。如果忘记等待，可能会产生僵尸进程。`AssertChildExited` 强制进行等待，避免这种错误。
    ```c++
    TEST(MyTest, ForkWithoutWait) {
        pid_t pid = fork();
        ASSERT_NE(pid, -1);
        if (pid == 0) {
            exit(0);
        }
        // 错误：忘记 waitpid(pid, ...);
    }
    ```
* **`ExecTestHelper` 使用不当:**  例如，提供的参数不正确，导致子进程执行失败，或者期望的输出正则表达式写错，导致测试误判。
* **在 Native Bridge 环境下假设了错误的 Bionic 行为:**  没有使用 `SKIP_WITH_NATIVE_BRIDGE` 导致测试在 Native Bridge 下失败，但实际上代码本身没有问题。

**Android Framework or NDK 如何一步步的到达这里，给出 Frida hook 示例调试这些步骤。**

1. **Android Framework/NDK 编写代码:**  开发者使用 Android SDK (包括 NDK) 编写 C/C++ 代码，这些代码可能会调用 Bionic 提供的 libc, libm 或 dynamic linker 的功能。

2. **NDK 编译:** 使用 NDK 的构建工具 (如 `ndk-build` 或 CMake) 编译 C/C++ 代码，生成共享库 (`.so`) 或可执行文件。这个过程中会链接到 Bionic 提供的库。

3. **运行在 Android 设备上:** 编译后的应用或可执行文件部署到 Android 设备上运行。

4. **Bionic 库加载和使用:** 当应用运行时，Android 系统（通过 `zygote` 进程）会加载必要的 Bionic 库。应用代码通过系统调用或动态链接的方式调用 Bionic 库提供的函数。

5. **测试 Bionic:** 为了确保 Bionic 的正确性，Android 开发者会编写针对 Bionic 的测试用例，这些测试用例就可能使用到 `bionic/tests/utils.handroid bionic/utils.h` 中的工具函数。

**Frida Hook 示例调试步骤:**

假设我们要调试 `AssertChildExited` 函数是如何工作的。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['msg']))
    else:
        print(message)

# 目标进程，可以是正在运行的测试进程的进程名或 PID
process_name = "bionic_test_process"  # 替换为实际的测试进程名

try:
    session = frida.attach(process_name)
except frida.ProcessNotFoundError:
    print(f"Process '{process_name}' not found. Please run the test first.")
    sys.exit(1)

script_code = """
console.log("Script loaded");

const utils_lib = Process.getModuleByName("libutils.so"); // 假设 utils.h 中的函数编译到了 libutils.so 中
const assertChildExited = utils_lib.getExportByName("AssertChildExited"); // 需要知道 AssertChildExited 的符号名

if (assertChildExited) {
    Interceptor.attach(assertChildExited, {
        onEnter: function(args) {
            console.log("[*] AssertChildExited called");
            console.log("[*] PID:", args[0]);
            console.log("[*] Expected Exit Status:", args[1]);
        },
        onLeave: function(retval) {
            console.log("[*] AssertChildExited returned:", retval);
        }
    });
} else {
    console.error("AssertChildExited not found!");
}
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

print("[*] Waiting for messages...")
sys.stdin.read()
session.detach()
```

**解释 Frida Hook:**

1. **`frida.attach(process_name)`:**  连接到目标测试进程。
2. **`Process.getModuleByName("libutils.so")`:** 获取包含 `AssertChildExited` 函数的共享库的模块对象。你需要知道 `utils.h` 中的函数最终被编译到了哪个 `.so` 文件中。
3. **`utils_lib.getExportByName("AssertChildExited")`:** 获取 `AssertChildExited` 函数的地址。
4. **`Interceptor.attach(assertChildExited, ...)`:**  Hook `AssertChildExited` 函数，在函数进入和退出时执行自定义的 JavaScript 代码。
5. **`onEnter`:**  在 `AssertChildExited` 函数被调用时执行，打印传入的参数，例如子进程的 PID 和期望的退出状态。
6. **`onLeave`:** 在 `AssertChildExited` 函数返回时执行，打印返回值。

**调试步骤:**

1. 编译并运行包含使用 `AssertChildExited` 的 Bionic 测试用例。
2. 找到测试进程的进程名或 PID。
3. 运行 Frida 脚本，将进程名替换为实际的进程名。
4. 当测试用例执行到 `AssertChildExited` 时，Frida 脚本会拦截并打印相关信息，帮助你理解该函数的工作流程。

请注意，上述 Frida Hook 示例需要根据实际情况进行调整，例如替换正确的进程名和共享库名。 此外，Bionic 的测试通常在受限的环境下运行，可能需要 root 权限才能进行 Frida Hook。

Prompt: 
```
这是目录为bionic/tests/utils.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__BIONIC__)
#include <sys/system_properties.h>
#endif

#if defined(__BIONIC__)
#include <bionic/macros.h>
#else
#define untag_address(p) p
#endif

#include <atomic>
#include <iomanip>
#include <string>
#include <regex>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>

#if defined(__LP64__)
#define PATH_TO_SYSTEM_LIB "/system/lib64/"
#else
#define PATH_TO_SYSTEM_LIB "/system/lib/"
#endif

#if defined(__GLIBC__)
#define BIN_DIR "/bin/"
#else
#define BIN_DIR "/system/bin/"
#endif

#if defined(__BIONIC__)
#define KNOWN_FAILURE_ON_BIONIC(x) xfail_ ## x
#else
#define KNOWN_FAILURE_ON_BIONIC(x) x
#endif

// bionic's dlsym doesn't work in static binaries, so we can't access icu,
// so any unicode test case will fail.
static inline bool have_dl() {
  return (dlopen("libc.so", 0) != nullptr);
}

static inline bool running_with_native_bridge() {
#if defined(__BIONIC__)
  static const prop_info* pi = __system_property_find("ro.dalvik.vm.isa." ABI_STRING);
  return pi != nullptr;
#endif
  return false;
}

#define SKIP_WITH_NATIVE_BRIDGE if (running_with_native_bridge()) GTEST_SKIP()

#if defined(__linux__)

#include <sys/sysmacros.h>

struct map_record {
  uintptr_t addr_start;
  uintptr_t addr_end;

  int perms;

  size_t offset;

  dev_t device;
  ino_t inode;

  std::string pathname;
};

class Maps {
 public:
  static bool parse_maps(std::vector<map_record>* maps) {
    maps->clear();

    std::unique_ptr<FILE, decltype(&fclose)> fp(fopen("/proc/self/maps", "re"), fclose);
    if (!fp) return false;

    char line[BUFSIZ];
    while (fgets(line, sizeof(line), fp.get()) != nullptr) {
      map_record record;
      uint32_t dev_major, dev_minor;
      int path_offset;
      char prot[5]; // sizeof("rwxp")
      if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNxPTR " %x:%x %lu %n",
            &record.addr_start, &record.addr_end, prot, &record.offset,
            &dev_major, &dev_minor, &record.inode, &path_offset) == 7) {
        record.perms = 0;
        if (prot[0] == 'r') {
          record.perms |= PROT_READ;
        }
        if (prot[1] == 'w') {
          record.perms |= PROT_WRITE;
        }
        if (prot[2] == 'x') {
          record.perms |= PROT_EXEC;
        }

        // TODO: parse shared/private?

        record.device = makedev(dev_major, dev_minor);
        record.pathname = line + path_offset;
        if (!record.pathname.empty() && record.pathname.back() == '\n') {
          record.pathname.pop_back();
        }
        maps->push_back(record);
      }
    }

    return true;
  }
};

extern "C" pid_t gettid();

#endif

static inline void WaitUntilThreadSleep(std::atomic<pid_t>& tid) {
  while (tid == 0) {
    usleep(1000);
  }
  std::string filename = android::base::StringPrintf("/proc/%d/stat", tid.load());
  std::regex regex {R"(\s+S\s+)"};

  while (true) {
    std::string content;
    ASSERT_TRUE(android::base::ReadFileToString(filename, &content));
    if (std::regex_search(content, regex)) {
      break;
    }
    usleep(1000);
  }
}

static inline void AssertChildExited(int pid, int expected_exit_status,
                                     const std::string* error_msg = nullptr) {
  int status;
  std::string error;
  if (error_msg == nullptr) {
    error_msg = &error;
  }
  ASSERT_EQ(pid, TEMP_FAILURE_RETRY(waitpid(pid, &status, 0))) << *error_msg;
  if (expected_exit_status >= 0) {
    ASSERT_TRUE(WIFEXITED(status)) << *error_msg;
    ASSERT_EQ(expected_exit_status, WEXITSTATUS(status)) << *error_msg;
  } else {
    ASSERT_TRUE(WIFSIGNALED(status)) << *error_msg;
    ASSERT_EQ(-expected_exit_status, WTERMSIG(status)) << *error_msg;
  }
}

static inline bool CloseOnExec(int fd) {
  int flags = fcntl(fd, F_GETFD);
  // This isn't ideal, but the alternatives are worse:
  // * If we return void and use ASSERT_NE here, we get failures at utils.h:191
  //   rather than in the relevant test.
  // * If we ignore failures of fcntl(), well, that's obviously a bad idea.
  if (flags == -1) abort();
  return flags & FD_CLOEXEC;
}

// The absolute path to the executable
const std::string& get_executable_path();

// Access to argc/argv/envp
int get_argc();
char** get_argv();
char** get_envp();

// ExecTestHelper is only used in bionic and glibc tests.
#ifndef __APPLE__
class ExecTestHelper {
 public:
  char** GetArgs() {
    return const_cast<char**>(args_.data());
  }
  const char* GetArg0() {
    return args_[0];
  }
  char** GetEnv() {
    return const_cast<char**>(env_.data());
  }
  const std::string& GetOutput() {
    return output_;
  }

  void SetArgs(const std::vector<const char*>& args) {
    args_ = args;
  }
  void SetEnv(const std::vector<const char*>& env) {
    env_ = env;
  }

  void Run(const std::function<void()>& child_fn, int expected_exit_status,
           const char* expected_output_regex) {
    int fds[2];
    ASSERT_NE(pipe(fds), -1);

    pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0) {
      // Child.
      close(fds[0]);
      dup2(fds[1], STDOUT_FILENO);
      dup2(fds[1], STDERR_FILENO);
      if (fds[1] != STDOUT_FILENO && fds[1] != STDERR_FILENO) close(fds[1]);
      child_fn();
      FAIL();
    }

    // Parent.
    close(fds[1]);
    output_.clear();
    char buf[BUFSIZ];
    ssize_t bytes_read;
    while ((bytes_read = TEMP_FAILURE_RETRY(read(fds[0], buf, sizeof(buf)))) > 0) {
      output_.append(buf, bytes_read);
    }
    close(fds[0]);

    std::string error_msg("Test output:\n" + output_);
    AssertChildExited(pid, expected_exit_status, &error_msg);
    if (expected_output_regex != nullptr) {
      if (!std::regex_search(output_, std::regex(expected_output_regex))) {
        FAIL() << "regex " << std::quoted(expected_output_regex) << " didn't match " << std::quoted(output_);
      }
    }
  }

 private:
  std::vector<const char*> args_;
  std::vector<const char*> env_;
  std::string output_;
};

void RunGwpAsanTest(const char* test_name);
void RunSubtestNoEnv(const char* test_name);
#endif

class FdLeakChecker {
 public:
  FdLeakChecker() {
  }

  ~FdLeakChecker() {
    size_t end_count = CountOpenFds();
    EXPECT_EQ(start_count_, end_count);
  }

 private:
  static size_t CountOpenFds() {
    auto fd_dir = std::unique_ptr<DIR, decltype(&closedir)>{ opendir("/proc/self/fd"), closedir };
    size_t count = 0;
    dirent* de = nullptr;
    while ((de = readdir(fd_dir.get())) != nullptr) {
      if (de->d_type == DT_LNK) {
        ++count;
      }
    }
    return count;
  }

  size_t start_count_ = CountOpenFds();
};

static inline bool running_with_mte() {
#ifdef __aarch64__
  int level = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
  return level >= 0 && (level & PR_TAGGED_ADDR_ENABLE) &&
         (level & PR_MTE_TCF_MASK) != PR_MTE_TCF_NONE;
#else
  return false;
#endif
}

bool IsLowRamDevice();

int64_t NanoTime();

class Errno {
 public:
  Errno(int e) : errno_(e) {}
  int errno_;
};
void PrintTo(const Errno& e, std::ostream* os);
bool operator==(const Errno& lhs, const Errno& rhs);
#define ASSERT_ERRNO(expected_errno) ASSERT_EQ(Errno(expected_errno), Errno(errno))
#define EXPECT_ERRNO(expected_errno) EXPECT_EQ(Errno(expected_errno), Errno(errno))

"""

```