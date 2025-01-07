Response:
Let's break down the thought process for analyzing the given C++ test file.

**1. Understanding the Context:**

The first step is to recognize the file's location and purpose: `bionic/tests/memtag_stack_dlopen_test.cpp`. The path immediately tells us this is a test file within the `bionic` project, specifically targeting `memtag_stack` and `dlopen`. The comment at the beginning reinforces this, stating bionic's role as Android's C library, math library, and dynamic linker. This sets the expectation that the tests will focus on how dynamic linking interacts with memory tagging, particularly on the stack.

**2. Initial Code Scan for Key Features:**

Next, I'd quickly scan the code for important keywords and structures:

* **`#include` directives:** These tell us what libraries and headers are being used. `dlfcn.h` (for `dlopen`), `stdlib.h` (general utilities), `gtest/gtest.h` (Google Test framework), and the Android-specific headers (`android-base/...`, `mte_utils.h`, `utils.h`). This immediately highlights the core functionalities being tested: dynamic linking and memory tagging.
* **`TEST(...)` macros:**  These are the test cases themselves. I'd quickly identify the names of the tests: `DependentBinaryGetsMemtagStack`, `DependentBinaryGetsMemtagStack2`, `DlopenRemapsStack`, and `DlopenRemapsStack2`. The names give a high-level idea of what each test aims to verify.
* **Conditional compilation (`#if defined(...)`)**: The presence of `__BIONIC__` and `__aarch64__` indicates that these tests are specifically designed for the Android bionic library on ARM64 architecture. The `running_with_mte()` and `is_stack_mte_on()` checks further narrow down the requirements to systems with Memory Tagging Extension (MTE) enabled, but *not* with stack MTE fully enabled (likely because these tests are checking how stack MTE *becomes* active).
* **`ExecTestHelper`:** This class appears to be a utility for running external executables in a controlled environment. It's likely responsible for setting up arguments, environment variables, and running the process.
* **`execve()`:** This is a crucial system call for executing a new program. Its presence in the `Run` lambda of `ExecTestHelper` confirms that these tests involve launching separate processes.
* **File paths:**  The code constructs paths to test binaries (e.g., `testbinary_depends_on_simple_memtag_stack`). This suggests the tests verify the behavior of these external binaries.
* **`LD_LIBRARY_PATH`:** This environment variable is used to specify where the dynamic linker should search for shared libraries. Its use here indicates testing dynamic linking scenarios.

**3. Analyzing Individual Test Cases:**

With the overall structure in mind, I'd analyze each test case individually:

* **`DependentBinaryGetsMemtagStack` and `DependentBinaryGetsMemtagStack2`:** These tests seem to verify that when an executable depends on a shared library that requires memory tagging on the stack, the executable also gets memory tagging enabled on its stack. The difference between the two is likely the depth of the dependency chain (one library versus a library that depends on another).
* **`DlopenRemapsStack` and `DlopenRemapsStack2`:** These tests focus on the behavior of `dlopen`. The names suggest they are checking if calling `dlopen` causes the stack to be remapped, presumably to enable memory tagging if the loaded library requires it. The difference likely lies in the dependencies of the dynamically loaded library.

**4. Inferring Functionality and Android Integration:**

Based on the test names and the libraries used, I could infer the following functionalities:

* **Dynamic Linking with MTE:** The core function is verifying that the dynamic linker correctly handles memory tagging requirements when loading shared libraries.
* **Stack Memory Tagging:**  The tests specifically target the stack, confirming that memory tagging is correctly applied to the stack when needed.
* **`dlopen` Interaction:** The tests assess how `dlopen` affects stack memory tagging.

The connection to Android is clear because this code resides within the Android bionic library. Memory tagging is a security feature in Android, and these tests ensure its correct operation during dynamic linking.

**5. Explaining `libc` Functions:**

The primary `libc` function involved is `execve`. I would explain its purpose (executing a new program) and key parameters (path, arguments, environment). For a deeper explanation of `execve`'s implementation, I'd need to access the bionic source code for `execve` itself, which would involve discussing process creation, loading the executable, setting up the address space, and handling arguments and environment.

**6. Dynamic Linker Details (Hypothetical SO Layout and Linking):**

Since the tests involve dynamic linking, I would create a hypothetical scenario:

* **Executable (`testbinary`)**:  Links against `libc.so` and potentially other standard libraries.
* **Shared Library (`libtest_simple_memtag_stack.so`)**:  Compiled with flags that request memory tagging on the stack.
* **Dependency (for `DependentBinaryGetsMemtagStack2`):**  Another shared library (`libintermediate.so`) that `testbinary` depends on, which in turn depends on `libtest_simple_memtag_stack.so`.

The linking process would involve:

1. **Loading the executable:** The kernel loads `testbinary` into memory.
2. **Resolving dependencies:** The dynamic linker (`linker64` on ARM64) parses the ELF header of `testbinary` to find its dependencies.
3. **Loading shared libraries:** The linker loads the required shared libraries (e.g., `libtest_simple_memtag_stack.so`). The `LD_LIBRARY_PATH` environment variable guides the search for these libraries.
4. **Relocation:** The linker adjusts addresses within the loaded libraries and the executable so they can function correctly in the current process's memory space. Crucially, the linker would check the memory tagging requirements of the shared libraries.
5. **Stack Remapping (for `dlopen` tests):** When `dlopen` is called, if the loaded library requires stack MTE and the current stack doesn't have it, the linker would remap the stack to allocate a new region with MTE enabled.

**7. Logic, Assumptions, and Input/Output:**

For tests like `DependentBinaryGetsMemtagStack`, the assumption is that if the dependent library requires MTE on the stack, the parent process will also have it. The input is the execution of `testbinary_depends_on_simple_memtag_stack`. The expected output is that the test binary runs successfully (indicated by the "RAN" marker in `ExecTestHelper`). Internally, the test binary likely checks if stack MTE is enabled.

**8. Common Usage Errors:**

Common errors related to dynamic linking and MTE include:

* **Incorrect `LD_LIBRARY_PATH`:**  If the dynamic linker can't find the required shared libraries, the program will fail to start.
* **ABI compatibility issues:** If the executable and shared libraries are compiled with incompatible ABIs, linking errors can occur.
* **Memory tagging mismatches:**  While these tests specifically check for correct handling, in other scenarios, incorrectly assuming MTE is enabled or disabled could lead to crashes.

**9. Android Framework/NDK Path and Frida Hooking:**

Tracing the path from the Android Framework or NDK to these tests involves understanding the build process. The NDK provides the tools and headers to compile native code, which would then be packaged into an APK. When the Android runtime loads the APK, the dynamic linker (`linker64`) is responsible for loading the native libraries.

A Frida hook example could target the `dlopen` function to observe its behavior and the state of memory tagging before and after the call. For example:

```javascript
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
  onEnter: function (args) {
    console.log("dlopen called with:", args[0].readUtf8String(), args[1]);
    // Check memory tagging status here (requires more advanced techniques)
  },
  onLeave: function (retval) {
    console.log("dlopen returned:", retval);
    // Check memory tagging status here after dlopen
  }
});
```

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus too much on the `gtest` framework.
* **Correction:** Recognize that `gtest` is just the testing *mechanism*. The core focus is the dynamic linking and memory tagging aspects.
* **Initial thought:** Explain every single line of code.
* **Correction:**  Focus on the overall functionality and the key components involved in the tests. Details of the `ExecTestHelper` implementation are less important than its purpose.
* **Initial thought:** Assume deep knowledge of MTE internals.
* **Correction:** Provide a general overview of MTE and its purpose in the context of these tests, rather than delving into low-level hardware details.

By following these steps, breaking down the problem into smaller parts, and iteratively refining the understanding, a comprehensive analysis of the given C++ test file can be achieved.
这是一个位于 Android Bionic 库中的测试文件，专门用于测试在动态链接库加载（通过 `dlopen`）时，内存标签（Memtag，也常称为 MTE - Memory Tagging Extension）在栈上的行为。

**文件功能总结：**

这个测试文件的主要功能是验证在 Android 系统中，当使用 `dlopen` 加载共享库时，栈内存的内存标签是否能正确地被设置和管理。具体来说，它关注以下几个方面：

1. **依赖库的栈内存标签继承：** 当一个可执行文件依赖于一个需要栈内存标签的共享库时，该可执行文件是否也能获得栈内存标签。
2. **`dlopen` 触发栈重映射：**  当使用 `dlopen` 加载一个需要栈内存标签的共享库时，当前进程的栈内存是否会被重新映射以启用内存标签。

**与 Android 功能的关系及举例说明：**

这个测试文件直接关系到 Android 的安全性和内存管理。内存标签是一种硬件支持的内存安全机制，可以帮助检测和防止某些类型的内存错误，例如堆溢出和栈溢出。

* **安全性：** 通过确保动态加载的库也能获得栈内存标签，Android 可以提高应用程序的安全性，防止恶意代码通过动态加载的库进行攻击。例如，如果一个应用动态加载了一个包含漏洞的库，而该漏洞可能导致栈溢出，内存标签可以帮助及时检测到这种攻击。
* **内存管理：**  动态链接是 Android 系统中非常重要的机制，它允许应用程序在运行时加载和卸载代码。正确地管理动态加载库的内存，包括栈内存的内存标签，对于系统的稳定性和效率至关重要。

**libc 函数功能解释：**

这个测试文件中直接使用到的 libc 函数主要是 `execve` 和间接使用的 `dlopen`。

* **`execve(const char *pathname, char *const argv[], char *const envp[])`:**
    * **功能：** `execve` 系统调用用于执行由 `pathname` 指定的可执行文件。它会将当前进程替换为新的进程。
    * **实现原理：**
        1. **查找可执行文件：** 内核根据 `pathname` 查找要执行的文件。
        2. **加载可执行文件：** 内核将可执行文件的代码和数据加载到内存中。这包括读取 ELF 文件头，分配内存段（如代码段、数据段、BSS 段），并将文件内容映射到这些段。
        3. **设置执行环境：** 内核设置新进程的执行环境，包括命令行参数 (`argv`) 和环境变量 (`envp`)。
        4. **启动执行：**  内核跳转到可执行文件的入口点开始执行。原进程的上下文（如栈、堆、打开的文件描述符等）会被替换为新进程的上下文。
    * **在这个测试中的作用：**  测试用例使用 `execve` 启动一个新的进程来模拟应用程序加载动态链接库的场景。

* **`dlopen(const char *filename, int flags)`:** （虽然代码中没有直接调用，但测试场景基于 `dlopen` 的行为）
    * **功能：** `dlopen` 函数用于加载一个动态链接库（共享对象）。
    * **实现原理：**
        1. **查找共享库：**  动态链接器（在 Android 上通常是 `linker64` 或 `linker`）根据 `filename` 在预定义的路径（如 `LD_LIBRARY_PATH`）中查找共享库文件。
        2. **加载共享库：** 如果找到共享库，动态链接器会将其加载到进程的地址空间中。这包括分配内存空间，解析 ELF 文件头，加载代码和数据段。
        3. **符号解析和重定位：** 动态链接器会解析共享库中的未定义符号，并将其链接到已经加载的其他库或主程序中的符号。这需要修改代码和数据段中的地址，这个过程称为重定位。
        4. **执行初始化代码：**  如果共享库有初始化函数（例如，使用 `__attribute__((constructor))` 标记的函数），动态链接器会在加载完成后执行这些函数。
        5. **返回句柄：** `dlopen` 成功后返回一个表示已加载共享库的句柄，失败则返回 `NULL`。
    * **在这个测试中的作用：**  测试用例依赖于 `dlopen` 的行为来触发栈内存的重新映射，以验证内存标签是否能正确应用。

**Dynamic Linker 的功能及 SO 布局样本和链接处理过程：**

动态链接器负责在程序运行时加载和链接共享库。

**SO 布局样本：**

假设我们有以下两个共享库：

* **`libtest_simple_memtag_stack.so`：**  这是一个简单的共享库，它可能包含一些被标记为需要栈内存标签的函数。
* **`testbinary_depends_on_simple_memtag_stack`：** 这是一个可执行文件，它链接了 `libtest_simple_memtag_stack.so`。

**`libtest_simple_memtag_stack.so` 的布局 (简化)：**

```
ELF Header
Program Headers:
  LOAD: 可读可执行段
  LOAD: 可读可写段
Dynamic Section:
  SONAME: libtest_simple_memtag_stack.so
  ...其他动态链接信息...
Symbol Table:
  ...导出的函数符号...
Relocation Table:
  ...需要重定位的信息...
```

**链接处理过程：**

1. **编译时链接：** 当 `testbinary_depends_on_simple_memtag_stack` 被编译时，链接器会记录它依赖于 `libtest_simple_memtag_stack.so`。
2. **运行时加载：** 当 `testbinary_depends_on_simple_memtag_stack` 启动时，操作系统会加载它。
3. **动态链接器启动：**  操作系统的加载器会启动动态链接器 (`linker64`)。
4. **加载依赖库：** 动态链接器会读取 `testbinary_depends_on_simple_memtag_stack` 的 ELF 文件头，找到其依赖的共享库 `libtest_simple_memtag_stack.so`。动态链接器会根据配置的路径（如 `LD_LIBRARY_PATH`）查找并加载 `libtest_simple_memtag_stack.so` 到进程的地址空间。
5. **符号解析和重定位：** 动态链接器会解析 `testbinary_depends_on_simple_memtag_stack` 中对 `libtest_simple_memtag_stack.so` 中函数的调用，并将这些调用重定向到 `libtest_simple_memtag_stack.so` 中相应的函数地址。
6. **内存标签处理：**  在这个测试场景中，关键在于动态链接器如何处理内存标签。如果 `libtest_simple_memtag_stack.so` 被标记为需要栈内存标签，动态链接器需要确保调用它的代码（包括 `testbinary_depends_on_simple_memtag_stack` 的栈）也启用了栈内存标签。这可能涉及重新映射栈内存。

**逻辑推理、假设输入与输出：**

**测试用例：`DependentBinaryGetsMemtagStack`**

* **假设输入：**
    * 运行一个名为 `testbinary_depends_on_simple_memtag_stack` 的可执行文件。
    * 该可执行文件依赖于 `libtest_simple_memtag_stack.so`。
    * `libtest_simple_memtag_stack.so` 在编译时被标记为需要栈内存标签。
    * 当前系统运行在支持 MTE 的 ARM64 架构上，但初始状态栈 MTE 是关闭的。
* **逻辑推理：**
    * 当 `testbinary_depends_on_simple_memtag_stack` 启动时，动态链接器会加载 `libtest_simple_memtag_stack.so`。
    * 动态链接器会检测到 `libtest_simple_memtag_stack.so` 需要栈内存标签。
    * 为了满足这个要求，动态链接器可能会重新映射 `testbinary_depends_on_simple_memtag_stack` 的栈，使其启用内存标签。
    * `testbinary_depends_on_simple_memtag_stack` 内部会检查其栈是否启用了内存标签。
* **预期输出：** 测试通过，因为 `testbinary_depends_on_simple_memtag_stack` 的栈在加载依赖库后成功启用了内存标签。

**测试用例：`DlopenRemapsStack`**

* **假设输入：**
    * 运行一个名为 `testbinary_is_stack_mte_after_dlopen` 的可执行文件。
    * 该可执行文件在运行时通过 `dlopen` 加载 `libtest_simple_memtag_stack.so`。
    * `libtest_simple_memtag_stack.so` 在编译时被标记为需要栈内存标签。
    * 当前系统运行在支持 MTE 的 ARM64 架构上，但初始状态栈 MTE 是关闭的。
* **逻辑推理：**
    * 当 `testbinary_is_stack_mte_after_dlopen` 调用 `dlopen` 加载 `libtest_simple_memtag_stack.so` 时，动态链接器会检测到被加载的库需要栈内存标签。
    * 由于当前进程的栈可能没有启用内存标签，动态链接器会重新映射栈内存，创建一个新的带有内存标签的栈。
    * `testbinary_is_stack_mte_after_dlopen` 内部会检查在 `dlopen` 调用后其栈是否启用了内存标签。
* **预期输出：** 测试通过，因为在 `dlopen` 调用后，`testbinary_is_stack_mte_after_dlopen` 的栈成功启用了内存标签。

**用户或编程常见的使用错误：**

* **忘记设置 `LD_LIBRARY_PATH`：** 如果要加载的共享库不在系统默认路径中，或者没有通过 `LD_LIBRARY_PATH` 指定路径，`dlopen` 会失败。
    ```c++
    // 假设 libmylib.so 在 /opt/mylibs 目录下
    void* handle = dlopen("libmylib.so", RTLD_LAZY); // 如果没有设置 LD_LIBRARY_PATH，这里可能会失败
    if (!handle) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
    }
    ```
    **解决方法：** 在运行程序前设置 `LD_LIBRARY_PATH` 环境变量：
    ```bash
    export LD_LIBRARY_PATH=/opt/mylibs:$LD_LIBRARY_PATH
    ./myprogram
    ```
* **加载的库与程序架构不匹配：** 尝试加载与程序架构（例如，32 位程序加载 64 位库）不匹配的库会导致 `dlopen` 失败。
* **符号冲突：** 如果加载的多个库中定义了相同的符号，可能会导致符号冲突，从而影响程序的行为。
* **内存标签不一致的假设：**  在没有正确理解内存标签机制的情况下，如果开发者假设某个库或一段代码的栈一定有或没有内存标签，可能会导致难以调试的错误。例如，一个库在有内存标签的情况下分配内存并传递给另一个没有内存标签的库使用，可能会导致内存标签错误。
* **错误地使用 `dlclose`：**  过早地调用 `dlclose` 卸载一个仍在被使用的库会导致程序崩溃。

**Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例：**

1. **NDK 编译：** 当开发者使用 NDK 构建包含动态链接库的 Android 应用时，NDK 工具链会生成共享库 (`.so` 文件)。这些库可能包含需要栈内存标签的代码，具体的标签需求由编译选项和代码中的注解决定。
2. **APK 打包：**  编译生成的共享库会被打包到 APK 文件中。
3. **应用加载：** 当 Android 系统加载应用程序时，Zygote 进程会 fork 出新的应用进程。
4. **动态链接器启动：**  在应用进程启动时，系统会启动动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`)。
5. **加载应用依赖库：** 动态链接器会根据应用的清单文件和链接信息，加载应用依赖的系统库和应用私有的共享库。这个过程中会涉及到内存标签的处理。
6. **`dlopen` 调用：**  应用程序代码可能会显式地调用 `dlopen` 来加载额外的动态链接库。

**Frida Hook 示例调试步骤：**

假设我们要观察当 `testbinary_is_stack_mte_after_dlopen` 调用 `dlopen` 加载 `libtest_simple_memtag_stack.so` 时，栈内存标签的变化。

```python
import frida
import sys

package_name = "your.package.name" # 替换为包含测试二进制文件的应用的包名
process = frida.get_usb_device().attach(package_name)

script_code = """
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        console.log("[dlopen] filename:", args[0].readCString());
        console.log("[dlopen] flags:", args[1]);
        // 在 dlopen 调用前检查栈内存标签状态 (需要更底层的 Frida API 或自定义实现)
        // 例如，读取当前栈指针附近的内存标签
    },
    onLeave: function(retval) {
        console.log("[dlopen] returned handle:", retval);
        if (retval != 0) {
            // 在 dlopen 调用后检查栈内存标签状态
        }
    }
});
"""

script = process.create_script(script_code)
script.on('message', lambda message, data: print(message))
script.load()
sys.stdin.read()
```

**步骤说明：**

1. **安装 Frida：** 确保你的开发机器上安装了 Frida 和 Python 的 Frida 绑定。
2. **找到目标进程：**  你需要知道运行测试二进制文件的应用的包名。
3. **编写 Frida 脚本：**  上面的 Python 代码创建了一个 Frida 脚本，用于 hook `dlopen` 函数。
    * `Interceptor.attach` 用于拦截对 `dlopen` 函数的调用。
    * `onEnter` 函数在 `dlopen` 被调用前执行，可以打印传入的参数（文件名和标志）。
    * `onLeave` 函数在 `dlopen` 调用返回后执行，可以打印返回值（库的句柄）。
    * **检查栈内存标签状态是一个更复杂的问题，可能需要访问内存标签寄存器或使用更底层的 Frida API 来读取内存标签。**
4. **运行 Frida 脚本：**  运行 Frida 脚本后，当目标应用调用 `dlopen` 时，你将在控制台上看到相关的日志信息。

**更深入的 Frida 栈内存标签调试可能需要：**

* **了解 ARM MTE 的硬件细节：**  理解如何读取和解释内存标签。
* **使用 Frida 的 Memory API：**  可能需要使用 `Memory.read*` 系列函数来读取栈内存附近的标签。这需要你对栈的布局和内存标签的存储方式有深入的了解。
* **自定义 Frida Gadget 或 Agent：**  对于更复杂的调试场景，可能需要编写自定义的 Frida Gadget 或 Agent 来实现更精细的控制和信息收集。

这个测试文件是 Android Bionic 中内存安全特性的一个重要组成部分，它确保了动态链接库加载过程中内存标签的正确应用，从而增强了系统的安全性。

Prompt: 
```
这是目录为bionic/tests/memtag_stack_dlopen_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <thread>

#include <dlfcn.h>
#include <stdlib.h>

#include <gtest/gtest.h>

#include <android-base/silent_death_test.h>
#include <android-base/test_utils.h>
#include "mte_utils.h"
#include "utils.h"

TEST(MemtagStackDlopenTest, DependentBinaryGetsMemtagStack) {
#if defined(__BIONIC__) && defined(__aarch64__)
  if (!running_with_mte()) GTEST_SKIP() << "Test requires MTE.";
  if (is_stack_mte_on())
    GTEST_SKIP() << "Stack MTE needs to be off for this test. Are you running fullmte?";

  std::string path =
      android::base::GetExecutableDirectory() + "/testbinary_depends_on_simple_memtag_stack";
  ExecTestHelper eth;
  std::string ld_library_path = "LD_LIBRARY_PATH=" + android::base::GetExecutableDirectory();
  eth.SetArgs({path.c_str(), nullptr});
  eth.SetEnv({ld_library_path.c_str(), nullptr});
  eth.Run([&]() { execve(path.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, "RAN");
#else
  GTEST_SKIP() << "requires bionic arm64";
#endif
}

TEST(MemtagStackDlopenTest, DependentBinaryGetsMemtagStack2) {
#if defined(__BIONIC__) && defined(__aarch64__)
  if (!running_with_mte()) GTEST_SKIP() << "Test requires MTE.";
  if (is_stack_mte_on())
    GTEST_SKIP() << "Stack MTE needs to be off for this test. Are you running fullmte?";

  std::string path = android::base::GetExecutableDirectory() +
                     "/testbinary_depends_on_depends_on_simple_memtag_stack";
  ExecTestHelper eth;
  std::string ld_library_path = "LD_LIBRARY_PATH=" + android::base::GetExecutableDirectory();
  eth.SetArgs({path.c_str(), nullptr});
  eth.SetEnv({ld_library_path.c_str(), nullptr});
  eth.Run([&]() { execve(path.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, "RAN");
#else
  GTEST_SKIP() << "requires bionic arm64";
#endif
}

TEST(MemtagStackDlopenTest, DlopenRemapsStack) {
#if defined(__BIONIC__) && defined(__aarch64__)
  // If this test is failing, look at crash logcat for why the test binary died.
  if (!running_with_mte()) GTEST_SKIP() << "Test requires MTE.";
  if (is_stack_mte_on())
    GTEST_SKIP() << "Stack MTE needs to be off for this test. Are you running fullmte?";

  std::string path =
      android::base::GetExecutableDirectory() + "/testbinary_is_stack_mte_after_dlopen";
  std::string lib_path =
      android::base::GetExecutableDirectory() + "/libtest_simple_memtag_stack.so";
  ExecTestHelper eth;
  std::string ld_library_path = "LD_LIBRARY_PATH=" + android::base::GetExecutableDirectory();
  eth.SetArgs({path.c_str(), lib_path.c_str(), nullptr});
  eth.SetEnv({ld_library_path.c_str(), nullptr});
  eth.Run([&]() { execve(path.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, "RAN");
#else
  GTEST_SKIP() << "requires bionic arm64";
#endif
}

TEST(MemtagStackDlopenTest, DlopenRemapsStack2) {
#if defined(__BIONIC__) && defined(__aarch64__)
  // If this test is failing, look at crash logcat for why the test binary died.
  if (!running_with_mte()) GTEST_SKIP() << "Test requires MTE.";
  if (is_stack_mte_on())
    GTEST_SKIP() << "Stack MTE needs to be off for this test. Are you running fullmte?";

  std::string path =
      android::base::GetExecutableDirectory() + "/testbinary_is_stack_mte_after_dlopen";
  std::string lib_path =
      android::base::GetExecutableDirectory() + "/libtest_depends_on_simple_memtag_stack.so";
  ExecTestHelper eth;
  std::string ld_library_path = "LD_LIBRARY_PATH=" + android::base::GetExecutableDirectory();
  eth.SetArgs({path.c_str(), lib_path.c_str(), nullptr});
  eth.SetEnv({ld_library_path.c_str(), nullptr});
  eth.Run([&]() { execve(path.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, "RAN");
#else
  GTEST_SKIP() << "requires bionic arm64";
#endif
}

"""

```