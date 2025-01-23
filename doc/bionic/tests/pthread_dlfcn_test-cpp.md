Response:
Let's break down the thought process for analyzing the provided C++ test code.

**1. Understanding the Core Objective:**

The first step is to read the initial description and the filename: `pthread_dlfcn_test.cpp`. This immediately suggests the code is testing the interaction between pthreads (specifically `pthread_atfork`) and dynamic linking (`dlfcn`). The comment within the file reinforces this idea, noting it's a test for `pthread_atfork` with `dlclose`.

**2. Initial Scan for Key Functions:**

Next, quickly scan the code for important function calls. We see:

* `pthread_atfork`: This is the central function being tested. We should understand what it does.
* `dlopen`, `dlsym`, `dlclose`: These are dynamic linking functions. Their interaction with `pthread_atfork` is the focus.
* `fork`: This system call creates a child process, crucial for testing `pthread_atfork`'s behavior in different processes.
* `ASSERT_EQ`, `ASSERT_TRUE`, `EXPECT_EQ`: These are from the `gtest` framework, indicating this is a unit test. They help verify expected outcomes.
* `_exit`: Used for immediate termination in the child process.
* `strerror`, `errno`: For error reporting related to `fork`.
* `AssertChildExited`:  A custom helper function (defined in `utils.h`, though not provided) likely used to wait for and check the exit status of the child process.

**3. Deciphering the Test Logic (Iterative Process):**

Now, examine each test case (`TEST` macro) individually.

* **`pthread_atfork_with_dlclose`:**
    * Multiple calls to `pthread_atfork` are made, registering prepare, parent, and child handlers.
    * `dlopen` is called to load "libtest_pthread_atfork.so".
    * `dlsym` is used to get a function pointer (`proxy_pthread_atfork`) from the loaded library. This implies "libtest_pthread_atfork.so" likely registers its own `pthread_atfork` handlers.
    * Another set of `pthread_atfork` calls are made via the `proxy_pthread_atfork` function.
    * `fork` is called to create a child process.
    * Assertions check the values of global variables (`g_atfork_*_calls`) in both parent and child processes. This is the core of the test – verifying the correct execution of the `atfork` handlers.
    * `dlclose` is called in the parent process after the first fork.
    * A second `fork` occurs, and similar assertions are performed.

* **`pthread_atfork_child_with_dlclose`:**
    * `dlopen` is called *before* any `pthread_atfork` calls. The handle is stored in a global variable.
    * A single `pthread_atfork` call is made.
    * `fork` is called.
    * `dlclose` is called in the *parent* process *after* the fork.

**4. Identifying Key Concepts and Relationships:**

Based on the code and the function names, the key concepts are:

* **`pthread_atfork`:** Understand its role in registering handlers that are called before and after a `fork`. Specifically, the prepare handler runs in the parent *before* forking, the parent handler runs in the parent *after* forking, and the child handler runs in the child process.
* **Dynamic Linking:** How `dlopen`, `dlsym`, and `dlclose` load and unload shared libraries and resolve symbols at runtime.
* **Process Forking:** The creation of a new process, and the implications for memory and resource sharing (or lack thereof).
* **Shared Libraries and Constructors:** The comment about the library registering additional handlers in its constructor is important. It suggests `libtest_pthread_atfork.so` has code that runs automatically when loaded.

**5. Answering the Specific Questions (Applying the Understanding):**

Now, address each of the prompt's questions systematically:

* **功能 (Functionality):**  Summarize the test's purpose based on the analysis.
* **与 Android 的关系 (Relationship with Android):** Explain why these tests are relevant to Android (Bionic being the core C library).
* **libc 函数解释 (Explanation of libc functions):** Detail how `pthread_atfork`, `dlopen`, `dlsym`, `dlclose`, and `fork` work. Focus on the aspects relevant to the test.
* **动态链接器功能 (Dynamic Linker Functionality):** Explain the role of the dynamic linker in loading and managing shared libraries. Create a hypothetical `.so` layout and describe the linking process (though the provided code doesn't directly show the linker's internals, it demonstrates its usage).
* **逻辑推理 (Logical Deduction):**  Explain the logic behind the assertions in the tests, showing how the values of the global variables are expected to change based on the sequence of `pthread_atfork` calls and the forking. Provide example inputs and outputs for the global variables.
* **常见错误 (Common Usage Errors):**  Think about typical mistakes developers make when using these functions (e.g., race conditions, incorrect flag usage with `dlopen`, dangling pointers after `dlclose`).
* **Android Framework/NDK 到达路径 (Path from Android Framework/NDK):** Explain how these low-level functions are used by higher-level components.
* **Frida Hook 示例 (Frida Hook Example):** Provide concrete Frida code to intercept the relevant function calls and observe their behavior.

**6. Refinement and Clarity:**

After drafting the initial answers, review and refine them for clarity, accuracy, and completeness. Ensure the language is precise and easy to understand. For example, when explaining the linking process, break it down into steps. When providing Frida examples, make sure the syntax is correct and the explanation is clear.

This iterative process of scanning, understanding, analyzing, and refining allows for a comprehensive and accurate response to the prompt. It involves not just reading the code but also understanding the underlying concepts and the purpose of the test.
好的，让我们来详细分析一下 `bionic/tests/pthread_dlfcn_test.cpp` 这个文件。

**文件功能：**

该文件是一个 C++ 单元测试文件，用于测试 Android Bionic 库中 `pthread_atfork` 函数与 `dlfcn` 库（动态链接相关函数）的交互行为，特别是当在 `fork` 之后的子进程中调用 `dlclose` 时，`pthread_atfork` 注册的回调函数是否能够正确执行。

**与 Android 功能的关系及举例：**

这个测试文件直接关系到 Android 的核心功能，因为它测试了 Bionic 库的关键组件：

* **`pthread`:**  线程库，`pthread_atfork` 是其中的一个重要函数，用于在 `fork` 系统调用前后注册需要在父子进程中执行的回调函数。这对于确保多线程程序在 `fork` 后的状态一致性至关重要。
* **`dlfcn`:** 动态链接库，提供了在运行时加载、查找符号和卸载共享库的功能。`dlopen`、`dlsym` 和 `dlclose` 是其核心函数。Android 系统大量使用动态链接来组织代码和管理依赖关系。

**举例说明:**

在 Android 系统中，很多服务和应用都是通过动态链接加载的。假设一个服务使用了某个共享库，并且该服务创建了子进程（例如，通过 `fork` 来处理新的连接请求）。如果该共享库在父进程中注册了 `pthread_atfork` 处理函数来清理资源或维护状态，那么这些处理函数需要在 `fork` 前后以及在子进程中正确执行。

例如，一个网络服务可能在加载某个网络库后，通过 `pthread_atfork` 注册一个回调函数，在 `fork` 前锁定某个全局的网络状态变量，在父进程 `fork` 后释放锁，在子进程 `fork` 后重新初始化网络连接。如果 `pthread_atfork` 与 `dlclose` 的交互存在问题，可能导致子进程在 `dlclose` 卸载库后，仍然尝试访问已释放的资源，从而引发崩溃或其他错误。

**libc 函数的功能实现：**

让我们详细解释一下代码中涉及的 libc 函数：

1. **`pthread_atfork(prepare, parent, child)`:**
   - **功能:**  在 `fork()` 系统调用前后注册需要执行的处理函数。
   - **实现:**  Bionic 中的 `pthread_atfork` 维护一个由 `fork` 处理函数组成的链表。
     - `prepare` 函数会在 `fork()` **之前**在父进程中被调用，用于在父进程中进行一些准备工作，例如加锁以避免数据竞争。
     - `parent` 函数会在 `fork()` **之后**在父进程中被调用，用于在父进程中进行清理工作，例如释放 `prepare` 中加的锁。
     - `child` 函数会在 `fork()` **之后**在子进程中被调用，用于在子进程中进行必要的初始化或清理工作。
   - **代码中的使用:** 代码中多次调用 `pthread_atfork` 来注册不同的回调函数 (`AtForkPrepare1` 到 `AtForkPrepare4` 等)。这些函数简单地修改全局变量的值，用于验证调用顺序和次数。

2. **`dlopen(filename, flags)`:**
   - **功能:**  加载指定的动态链接库（共享对象 `.so` 文件）。
   - **实现:**  动态链接器（linker，在 Android 中是 `linker64` 或 `linker`）会找到指定的 `.so` 文件，将其加载到内存中，并解析其符号表和依赖关系。
     - `filename` 是要加载的库的文件名（例如 "libtest_pthread_atfork.so"）。
     - `flags` 控制加载的行为，例如 `RTLD_NOW` 表示立即解析所有符号，`RTLD_LOCAL` 表示加载的符号仅对当前加载器可见。
   - **代码中的使用:**  代码中使用 `dlopen` 加载了 "libtest_pthread_atfork.so"。

3. **`dlsym(handle, symbol)`:**
   - **功能:**  在已加载的动态链接库中查找指定的符号（通常是函数或全局变量）。
   - **实现:**  动态链接器会在指定 `handle` 的共享库的符号表中查找与 `symbol` 匹配的符号，并返回其地址。
   - **代码中的使用:**  代码中使用 `dlsym` 从 "libtest_pthread_atfork.so" 中查找名为 "proxy_pthread_atfork" 的函数。

4. **`dlclose(handle)`:**
   - **功能:**  卸载之前通过 `dlopen` 加载的动态链接库。
   - **实现:**  动态链接器会解除对该共享库的引用计数，如果引用计数降为零，则卸载该库，释放其占用的内存，并执行其析构函数（如果有）。
   - **代码中的使用:**  代码中在父进程和子进程中都调用了 `dlclose`。

5. **`fork()`:**
   - **功能:**  创建一个新的进程，称为子进程。
   - **实现:**  操作系统会创建一个与父进程几乎完全相同的副本，包括代码、数据、打开的文件描述符等。父进程和子进程拥有各自独立的内存空间（写时复制）。
   - **代码中的使用:**  代码中多次调用 `fork()` 来创建子进程，用于测试 `pthread_atfork` 在父子进程中的行为。

**涉及 dynamic linker 的功能，对应的 so 布局样本和链接处理过程：**

为了理解 dynamic linker 的工作方式，我们假设 `libtest_pthread_atfork.so` 的布局如下：

```
libtest_pthread_atfork.so:
  .text      # 代码段
    proxy_pthread_atfork:  # 该库提供的函数，用于代理调用 pthread_atfork
      ...
    # 其他函数

  .data      # 数据段
    # 全局变量

  .rodata    # 只读数据段

  .dynamic   # 动态链接信息
    SONAME: libtest_pthread_atfork.so
    NEEDED: libc.so  # 依赖于 libc.so
    SYMTAB: ...      # 符号表
    STRTAB: ...      # 字符串表
    REL?: ...       # 重定位表 (REL/RELA)
    INIT_ARRAY: ... # 初始化函数数组 (可能包含注册 atfork handler 的代码)
```

**链接处理过程：**

1. **加载时链接 (`dlopen`):**
   - 当 `dlopen("libtest_pthread_atfork.so", ...)` 被调用时，dynamic linker 会查找该 `.so` 文件。
   - Linker 会检查 `.dynamic` 段的信息，确定其依赖关系 (例如 `NEEDED: libc.so`)。
   - 如果依赖的库尚未加载，linker 会先加载这些依赖库。
   - Linker 会解析 `libtest_pthread_atfork.so` 的符号表 (`SYMTAB`) 和字符串表 (`STRTAB`)。
   - Linker 会处理重定位信息 (`REL?`)，将库中对外部符号的引用绑定到这些符号在已加载库中的实际地址。
   - Linker 会执行 `INIT_ARRAY` 中指定的初始化函数。这很重要，因为 **`libtest_pthread_atfork.so` 可能在其构造函数或 `INIT_ARRAY` 中的函数中调用 `pthread_atfork` 来注册自己的处理函数**，这解释了代码中 "the library registers 2 additional atfork handlers in a constructor" 的注释。

2. **符号查找 (`dlsym`):**
   - 当 `dlsym(handle, "proxy_pthread_atfork")` 被调用时，linker 会在 `handle` 对应的 `libtest_pthread_atfork.so` 的符号表中查找 "proxy_pthread_atfork" 符号，并返回其地址。

3. **卸载时处理 (`dlclose`):**
   - 当 `dlclose(handle)` 被调用时，linker 会减少 `libtest_pthread_atfork.so` 的引用计数。
   - 如果引用计数降为零，linker 会执行 `FINI_ARRAY` 中指定的析构函数（如果有），并从内存中卸载该库。

**逻辑推理，假设输入与输出：**

让我们分析 `pthread_atfork_with_dlclose` 测试用例中的逻辑：

**假设输入：**

- 初始状态：全局变量 `g_atfork_prepare_calls`, `g_atfork_parent_calls`, `g_atfork_child_calls` 均为 0。

**执行流程和预期输出 (第一次 fork 之前):**

1. `pthread_atfork(AtForkPrepare1, AtForkParent1, AtForkChild1)`: 注册第一组回调。
2. `dlopen("libtest_pthread_atfork.so", ...)`: 加载库，假设库的构造函数注册了两个额外的 atfork 处理函数。
3. `dlsym(handle, "proxy_pthread_atfork")`: 获取代理函数。
4. `fn(AtForkPrepare2, AtForkParent2, AtForkChild2)`: 通过代理注册第二组回调。
5. `fn(AtForkPrepare3, AtForkParent3, AtForkChild3)`: 通过代理注册第三组回调。
6. `pthread_atfork(AtForkPrepare4, AtForkParent4, AtForkChild4)`: 注册第四组回调。

**第一次 `fork()` 之后:**

- **父进程:**
  - `prepare` 函数按注册顺序执行：`AtForkPrepare1`, 库注册的两个函数, `AtForkPrepare4`。 假设库注册的 prepare 函数分别增加 10 和 100。
  - `g_atfork_prepare_calls` 的预期值： `0 * 10 + 1 = 1` -> `1 * 10 + (假设库注册的是 1)` -> `...`  最终预期是 4321 (1, 库1, 库2, 4)。
  - `parent` 函数按注册顺序执行：`AtForkParent1`, 库注册的两个函数, `AtForkParent4`。假设库注册的 parent 函数分别增加 1 和 10。
  - `g_atfork_parent_calls` 的预期值： `0 * 10 + 1 = 1` -> `...` 最终预期是 1234 (1, 库1, 库2, 4)。
- **子进程:**
  - `child` 函数按注册顺序执行：`AtForkChild1`, 库注册的两个函数, `AtForkChild4`。假设库注册的 child 函数分别增加 1 和 10。
  - `g_atfork_child_calls` 的预期值： `0 * 10 + 1 = 1` -> `...` 最终预期是 1234 (1, 库1, 库2, 4)。
  - 在子进程中，`dlclose(g_atfork_test_handle)` 被调用。

**第一次 `dlclose(handle)` 之后 (父进程):**

- 卸载 `libtest_pthread_atfork.so`。

**第二次 `fork()` 之后:**

- 此时，只有 `pthread_atfork` 直接注册的 handler (AtForkPrepare1 和 AtForkPrepare4 等) 会被调用，因为之前通过 `libtest_pthread_atfork.so` 注册的 handler 随着库的卸载而失效。
- **父进程:**
  - `g_atfork_prepare_calls` 的预期值： `0 * 10 + 1 = 1` -> `1 * 10 + 4 = 14`。
  - `g_atfork_parent_calls` 的预期值： `0 * 10 + 1 = 1` -> `1 * 10 + 4 = 14`。
- **子进程:**
  - `g_atfork_child_calls` 的预期值： `0 * 10 + 1 = 1` -> `1 * 10 + 4 = 14`。

**用户或编程常见的使用错误：**

1. **忘记在 `prepare` handler 中加锁，导致数据竞争:** 如果在 `fork` 前有多个线程访问共享数据，并且没有在 `prepare` handler 中加锁，子进程可能会看到不一致的数据状态。
   ```c++
   // 错误示例
   int global_counter = 0;

   void prepare_handler() {
       // 忘记加锁
   }

   void parent_handler() {
       global_counter++;
   }

   void child_handler() {
       printf("Child counter: %d\n", global_counter); // 可能与父进程不同步
   }
   ```

2. **在 `child` handler 中访问父进程的资源 (例如，文件句柄):** 虽然文件描述符在 `fork` 后会复制，但父子进程共享相同的文件偏移量。不小心操作可能导致父子进程互相干扰。

3. **在 `child` handler 中执行与父进程不兼容的操作:** 例如，尝试关闭父进程正在使用的网络连接。

4. **不理解 `dlclose` 对 `pthread_atfork` 的影响:**  如果在子进程 `fork` 后 `dlclose` 一个注册了 `pthread_atfork` handler 的库，这些 handler 将不再有效，可能导致资源泄漏或错误的行为。

5. **在 `pthread_atfork` handler 中使用可能导致死锁的函数:** 尤其是 `prepare` handler，应该避免调用可能阻塞或加锁的函数，因为这可能会导致死锁。

**Android Framework 或 NDK 如何一步步到达这里：**

1. **应用程序或 Framework 组件调用 `fork()`:**  例如，`Zygote` 进程会 `fork` 出新的应用进程；系统服务也可能 `fork` 出子进程来处理特定任务。
2. **`fork()` 系统调用:** 当 `fork()` 被调用时，内核会创建子进程。
3. **Bionic 的 `fork()` 实现:** Bionic 提供的 `fork()` 函数在内核执行实际的进程复制前后，会调用通过 `pthread_atfork` 注册的处理函数。
4. **`pthread_atfork` 的使用:** Android Framework 和 NDK 中的库（例如，用于图形、媒体、网络等的库）可能会使用 `pthread_atfork` 来确保在 `fork` 操作前后资源状态的正确性。例如，`SurfaceFlinger` 可能在 `fork` 前锁定图形缓冲区，在 `fork` 后进行相应的处理。
5. **动态链接库的加载和卸载:**  Framework 或应用使用的共享库可能在其初始化阶段（例如，构造函数或 `__attribute__((constructor))` 函数）中调用 `pthread_atfork`。在运行时，这些库可能会被动态加载和卸载。

**Frida Hook 示例调试步骤：**

假设我们要 hook `pthread_atfork` 函数，查看其参数：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['data']))
    else:
        print(message)

def main():
    package_name = "你的应用包名"  # 替换为你要调试的应用程序包名

    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
        return

    script_source = """
    Interceptor.attach(Module.findExportByName(null, "pthread_atfork"), {
        onEnter: function(args) {
            console.log("[pthread_atfork] prepare: " + args[0]);
            console.log("[pthread_atfork] parent: " + args[1]);
            console.log("[pthread_atfork] child: " + args[2]);

            // 你可以进一步解析函数指针，查看函数名
            var prepare_ptr = ptr(args[0]);
            var parent_ptr = ptr(args[1]);
            var child_ptr = ptr(args[2]);

            // 尝试解析符号名 (可能需要符号信息)
            try {
                console.log("[pthread_atfork] prepare symbol: " + DebugSymbol.fromAddress(prepare_ptr).name);
                console.log("[pthread_atfork] parent symbol: " + DebugSymbol.fromAddress(parent_ptr).name);
                console.log("[pthread_atfork] child symbol: " + DebugSymbol.fromAddress(child_ptr).name);
            } catch (e) {
                console.log("[pthread_atfork] Could not resolve symbols.");
            }
        },
        onLeave: function(retval) {
            console.log("[pthread_atfork] returned: " + retval);
        }
    });
    """

    script = session.create_script(script_source)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**调试步骤：**

1. **安装 Frida 和 USB 驱动。**
2. **启动要调试的 Android 应用。**
3. **将上述 Python 代码保存为 `hook_pthread_atfork.py`，并将 `你的应用包名` 替换为实际的包名。**
4. **通过 USB 连接 Android 设备，并确保 adb 可用。**
5. **在 PC 上运行 `python hook_pthread_atfork.py`。**
6. **在 Android 应用中触发会调用 `fork()` 的操作。**
7. **Frida 会在终端输出 `pthread_atfork` 被调用时的参数信息，包括 `prepare`、`parent` 和 `child` 函数的地址和可能的符号名。**

这个 Frida 脚本可以帮助你观察哪些库或组件注册了 `pthread_atfork` 处理函数，以及这些处理函数是什么。你可以根据需要修改脚本来 hook 其他函数或查看更详细的信息。

希望这个详细的分析能够帮助你理解 `bionic/tests/pthread_dlfcn_test.cpp` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/pthread_dlfcn_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
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
#include <gtest/gtest.h>

#include <dlfcn.h>

#include "utils.h"

static int g_atfork_prepare_calls = 0;
static void AtForkPrepare1() { g_atfork_prepare_calls = (g_atfork_prepare_calls * 10) + 1; }
static void AtForkPrepare2() { g_atfork_prepare_calls = (g_atfork_prepare_calls * 10) + 2; }
static void AtForkPrepare3() { g_atfork_prepare_calls = (g_atfork_prepare_calls * 10) + 3; }
static void AtForkPrepare4() { g_atfork_prepare_calls = (g_atfork_prepare_calls * 10) + 4; }

static int g_atfork_parent_calls = 0;
static void AtForkParent1() { g_atfork_parent_calls = (g_atfork_parent_calls * 10) + 1; }
static void AtForkParent2() { g_atfork_parent_calls = (g_atfork_parent_calls * 10) + 2; }
static void AtForkParent3() { g_atfork_parent_calls = (g_atfork_parent_calls * 10) + 3; }
static void AtForkParent4() { g_atfork_parent_calls = (g_atfork_parent_calls * 10) + 4; }

static int g_atfork_child_calls = 0;
static void AtForkChild1() { g_atfork_child_calls = (g_atfork_child_calls * 10) + 1; }
static void AtForkChild2() { g_atfork_child_calls = (g_atfork_child_calls * 10) + 2; }
static void AtForkChild3() { g_atfork_child_calls = (g_atfork_child_calls * 10) + 3; }
static void AtForkChild4() { g_atfork_child_calls = (g_atfork_child_calls * 10) + 4; }

static void* g_atfork_test_handle = nullptr;
static void AtForkPrepare() {}
static void AtForkParent() {}
static void AtForkChild() { dlclose(g_atfork_test_handle); g_atfork_test_handle = dlopen("libtest_pthread_atfork.so", RTLD_NOW | RTLD_LOCAL); }

TEST(pthread, pthread_atfork_with_dlclose) {
  ASSERT_EQ(0, pthread_atfork(AtForkPrepare1, AtForkParent1, AtForkChild1));

  void* handle = dlopen("libtest_pthread_atfork.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  typedef int (*fn_t)(void (*)(void), void (*)(void), void (*)(void));
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "proxy_pthread_atfork"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  // the library registers 2 additional atfork handlers in a constructor
  ASSERT_EQ(0, fn(AtForkPrepare2, AtForkParent2, AtForkChild2));
  ASSERT_EQ(0, fn(AtForkPrepare3, AtForkParent3, AtForkChild3));

  ASSERT_EQ(0, pthread_atfork(AtForkPrepare4, AtForkParent4, AtForkChild4));

  pid_t pid = fork();

  ASSERT_NE(-1, pid) << strerror(errno);

  if (pid == 0) {
    ASSERT_EQ(1234, g_atfork_child_calls);
    _exit(0);
  }

  ASSERT_EQ(1234, g_atfork_parent_calls);
  ASSERT_EQ(4321, g_atfork_prepare_calls);

  EXPECT_EQ(0, dlclose(handle));
  g_atfork_prepare_calls = g_atfork_parent_calls = g_atfork_child_calls = 0;

  AssertChildExited(pid, 0);

  pid = fork();

  ASSERT_NE(-1, pid) << strerror(errno);

  if (pid == 0) {
    ASSERT_EQ(14, g_atfork_child_calls);
    _exit(0);
  }

  ASSERT_EQ(14, g_atfork_parent_calls);
  ASSERT_EQ(41, g_atfork_prepare_calls);

  AssertChildExited(pid, 0);
}

TEST(pthread, pthread_atfork_child_with_dlclose) {

  g_atfork_test_handle = dlopen("libtest_pthread_atfork.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(g_atfork_test_handle != nullptr) << dlerror();
  typedef int (*fn_t)(void (*)(void), void (*)(void), void (*)(void));
  fn_t fn = reinterpret_cast<fn_t>(dlsym(g_atfork_test_handle, "proxy_pthread_atfork"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  // the library registers 2 additional atfork handlers in a constructor

  ASSERT_EQ(0, pthread_atfork(AtForkPrepare, AtForkParent, AtForkChild));

  pid_t pid = fork();

  ASSERT_NE(-1, pid) << strerror(errno);

  if (pid == 0) {
    _exit(0);
  }

  AssertChildExited(pid, 0);

  EXPECT_EQ(0, dlclose(g_atfork_test_handle));
  g_atfork_test_handle = nullptr;
}
```