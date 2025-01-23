Response:
Let's break down the thought process for answering the request about `sys_thread_properties_test.cpp`.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the provided C++ test file within the context of Android's Bionic library. Key areas of focus are:

* **Functionality:** What does this test file do?
* **Android Relevance:** How does it relate to Android's core functionalities?
* **libc Function Details:** Deep dive into the implementation of any libc functions used.
* **Dynamic Linker Involvement:** Explain if and how the dynamic linker is involved, including sample SO layouts and the linking process.
* **Logic and I/O:**  Analyze the test logic, including potential inputs and outputs.
* **Common Errors:** Identify potential user/programmer errors.
* **Android Framework/NDK Path:** Trace how execution reaches this code.
* **Frida Hooking:** Provide examples of using Frida for debugging.

**2. Initial Code Analysis (Skimming and Identifying Key Elements):**

First, I scanned the code quickly to identify the main components:

* **Includes:** `gtest/gtest.h`, `gtest_globals.h`, `utils.h`. This tells me it's a unit test using Google Test.
* **Test Cases:**  `iterate_dts` and `thread_exit_cb`. These are the main functionalities being tested.
* **Conditional Compilation:** `#if defined(__BIONIC__)`. Indicates the tests are specific to the Bionic environment.
* **`ExecTestHelper`:**  This custom helper suggests the tests involve executing external processes.
* **`execve`:** This is a crucial libc function for executing new programs.
* **Helper Executables:**  The tests execute `tls_properties_helper` and `thread_exit_cb_helper`. This implies the test focuses on the interaction *between* processes.
* **Expected Output:** Each test has `expected_out`, which suggests the tests verify the output of the helper executables.

**3. Deeper Dive into Each Test Case:**

* **`iterate_dts`:**
    *  "dts" likely refers to "Dynamic Thread Storage" or "Dynamic TLS".
    *  The expected output string includes "test_static_tls_bounds", "iterate_cb", and "done_iterate_dynamic_tls". This strongly suggests it's testing the iteration of thread-local storage.
    *  The helper likely sets up some static and dynamic TLS and then iterates over the dynamic ones, printing these messages.

* **`thread_exit_cb`:**
    * "exit_cb" clearly indicates callbacks executed when a thread exits.
    * The expected output shows the sequence of callbacks being executed. The helper likely registers multiple exit callbacks.

**4. Connecting to Android Functionality:**

Knowing the test names and their general purpose, I started connecting them to Android features:

* **TLS (Thread Local Storage):**  Crucial for thread-safe programming. Android, like other operating systems, needs a mechanism for each thread to have its own set of variables. This test likely verifies Bionic's implementation of TLS.
* **Thread Exit Callbacks:** Allows for cleanup actions when a thread finishes. This is a common OS feature that Android leverages.

**5. libc Function Analysis (`execve`):**

The key libc function here is `execve`. I focused on explaining its role in:

* Replacing the current process image with a new one.
* Taking arguments, environment variables, and the executable path.
* Its significance in process creation and execution.

**6. Dynamic Linker Analysis:**

Since the tests execute external executables, the dynamic linker is inevitably involved. I considered:

* **SO Layout:**  Created a simplified example of how the main test process and the helper executables might be laid out in memory, highlighting the code, data, and GOT/PLT sections.
* **Linking Process:** Explained the steps: finding dependencies, resolving symbols using the GOT/PLT, and relocation. The focus was on how `execve` triggers this process for the helper executable.

**7. Logic and I/O Analysis:**

For each test, I outlined the assumed input (the helper executable) and the expected output (the strings being compared). I explained how the `ExecTestHelper` facilitates this execution and output verification.

**8. Common Errors:**

I brainstormed common programming errors related to the tested features:

* **Incorrect TLS Access:**  Accessing TLS variables without proper initialization or from the wrong thread.
* **Missing Exit Callbacks:**  Forgetting to unregister exit callbacks leading to resource leaks or unexpected behavior.
* **`execve` Errors:**  Providing incorrect paths, arguments, or environment variables, leading to execution failures.

**9. Android Framework/NDK Path:**

This requires thinking about the layers of Android:

* **Framework (Java):**  High-level APIs like `java.lang.Thread`.
* **NDK (Native Development Kit):**  Provides C/C++ APIs that map to lower-level system calls.
* **Bionic:** The underlying C library that implements these system calls.

I traced a hypothetical path from a Java thread creation to the Bionic code responsible for managing thread properties and exit callbacks.

**10. Frida Hooking:**

I considered which functions would be relevant to hook for debugging:

* **`execve`:**  To understand when and with what parameters new processes are launched.
* **Functions within the helper executables:**  To observe the internal logic of TLS iteration or exit callback registration/execution.
* **Potentially Bionic internals related to TLS or thread management:**  Although more complex, this could provide deeper insights.

I provided basic Frida script examples for hooking `execve` and a hypothetical function within the helper.

**11. Structuring the Answer:**

Finally, I organized the information into logical sections, addressing each part of the original request clearly and concisely. I used headings and bullet points to improve readability. I ensured the language was clear and avoided overly technical jargon where possible.

**Self-Correction/Refinement:**

During the process, I might have initially focused too much on the specific details of the helper executables. I realized that the core request was about understanding the *test file's* functionality and its relation to Bionic. Therefore, I adjusted the focus to explaining what the tests *verify* rather than delving too deeply into the implementation of the helper executables themselves (since their source code wasn't provided). I also ensured I explicitly linked the tested features back to their purpose in a multithreaded environment like Android.
好的，让我们详细分析一下 `bionic/tests/sys_thread_properties_test.cpp` 这个文件。

**文件功能：**

`sys_thread_properties_test.cpp` 是 Android Bionic 库中的一个测试文件，其主要功能是测试与线程属性相关的 Bionic 功能。具体而言，这个文件包含了两个独立的测试用例：

1. **`iterate_dts`**:  这个测试用例旨在验证 Bionic 库遍历和处理动态线程局部存储 (Dynamic Thread Storage, DTS) 的能力。它会启动一个辅助进程 (`tls_properties_helper`)，该辅助进程会设置一些静态和动态 TLS 变量，然后通过 Bionic 提供的机制遍历这些动态 TLS 变量，并打印相关信息。测试用例会检查辅助进程的输出是否符合预期。

2. **`thread_exit_cb`**:  这个测试用例旨在验证 Bionic 库提供的线程退出回调 (thread exit callback) 功能。它会启动另一个辅助进程 (`thread_exit_cb_helper`)，该辅助进程会注册多个线程退出回调函数。当辅助进程的主线程退出时，这些回调函数应该按照注册的顺序被调用。测试用例会检查辅助进程的输出，验证回调函数是否按预期顺序执行。

**与 Android 功能的关系和举例说明：**

这两个测试用例都直接关系到 Android 的核心功能，尤其是其对多线程的支持。

* **动态线程局部存储 (DTS)：**  在多线程环境中，有时需要让每个线程拥有自己独立的变量副本，而无需显式地传递数据。TLS 提供了一种机制来实现这一点。动态 TLS 允许在运行时分配和管理这些线程独立的存储空间。Android 系统和应用程序广泛使用 TLS 来存储线程特定的数据，例如：
    * **errno 变量：**  每个线程都有自己的 `errno` 变量，用于记录最近一次系统调用发生的错误。
    * **Locale 信息：**  不同线程可能需要使用不同的语言区域设置。
    * **OpenGL 上下文：**  在图形渲染中，每个线程可能需要维护自己的 OpenGL 上下文。
    * **Binder 事务信息：**  处理跨进程通信 (IPC) 时，每个线程可能需要维护当前的 Binder 事务状态。

* **线程退出回调：**  在多线程应用程序中，需要在线程退出时执行一些清理操作，例如释放资源、记录日志或通知其他线程。线程退出回调提供了一种标准化的机制来执行这些操作。Android 系统自身也使用了线程退出回调来执行一些清理工作，例如：
    * **释放线程本地资源。**
    * **取消注册与线程相关的事件监听器。**
    * **执行一些统计或监控操作。

**详细解释每一个 libc 函数的功能是如何实现的：**

在这个测试文件中，最关键的 libc 函数是 `execve`。

* **`execve(const char *pathname, char *const argv[], char *const envp[])`**:
    * **功能：** `execve` 系统调用用于执行由 `pathname` 指定的可执行文件。它会替换当前进程的映像，用新的程序代码、数据、堆栈等替换当前进程的内容。
    * **参数：**
        * `pathname`: 指向要执行的可执行文件的路径名的指针。
        * `argv`: 指向以空指针结尾的字符指针数组的指针，这些字符指针表示传递给新程序的命令行参数。`argv[0]` 通常是程序自身的名称。
        * `envp`: 指向以空指针结尾的字符指针数组的指针，这些字符指针表示传递给新程序的环境变量。
    * **实现原理：**
        1. **查找可执行文件：** 内核会根据 `pathname` 查找对应的可执行文件。
        2. **加载程序：** 如果找到可执行文件，内核会将其加载到内存中。这包括读取程序的代码段、数据段等。
        3. **设置执行环境：** 内核会根据 `argv` 和 `envp` 设置新进程的命令行参数和环境变量。
        4. **替换进程映像：**  内核会清除当前进程的内存空间，并用新程序的代码和数据填充。
        5. **开始执行：**  内核会将 CPU 的指令指针设置为新程序的入口点，开始执行新程序。
    * **重要性：** `execve` 是创建新进程的核心机制之一（通常与 `fork` 系统调用配合使用）。在 Android 中，无论是启动新的应用程序、运行系统服务，还是执行 shell 命令，都离不开 `execve`。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

当 `execve` 被调用执行辅助进程时，Android 的动态链接器 (linker，通常是 `linker64` 或 `linker`) 会发挥关键作用。

**SO 布局样本：**

假设 `tls_properties_helper` 和 `thread_exit_cb_helper` 都是动态链接的可执行文件。它们的内存布局可能如下所示（简化版）：

```
        +----------------------+
        |      ELF Header      |
        +----------------------+
        |  Program Headers     |
        +----------------------+
        | Section Headers      |
        +----------------------+
        |       .text (代码段)     |  <-- 程序指令
        +----------------------+
        |       .rodata (只读数据) |
        +----------------------+
        |       .data (已初始化数据) |
        +----------------------+
        |       .bss (未初始化数据)  |
        +----------------------+
        |       .dynamic (动态链接信息) |
        +----------------------+
        |       .dynsym (动态符号表) |
        +----------------------+
        |       .dynstr (动态字符串表) |
        +----------------------+
        |       .plt (过程链接表)   |
        +----------------------+
        |       .got (全局偏移表)   |
        +----------------------+
        |         ...          |
        +----------------------+
```

* **`.text`**:  包含可执行的代码指令。
* **`.rodata`**: 包含只读数据，例如字符串常量。
* **`.data`**: 包含已初始化的全局变量和静态变量。
* **`.bss`**: 包含未初始化的全局变量和静态变量。
* **`.dynamic`**: 包含动态链接器需要的信息，例如依赖的共享库列表、符号表位置等。
* **`.dynsym`**: 包含动态符号表，列出了程序导出的和导入的符号。
* **`.dynstr`**: 包含动态符号表中使用的字符串。
* **`.plt` (Procedure Linkage Table)**:  用于延迟绑定（lazy binding）导入的函数。
* **`.got` (Global Offset Table)**:  用于存储全局变量和导入函数的最终地址。

**链接的处理过程：**

1. **`execve` 调用：** 当 `execve` 启动辅助进程时，内核会将控制权交给动态链接器。
2. **加载依赖库：** 动态链接器会读取辅助进程 ELF 文件的 `.dynamic` 段，找到所有依赖的共享库（通常是 `libc.so` 等）。
3. **查找共享库：** 动态链接器会在预定义的路径中查找这些共享库。
4. **加载共享库：** 找到共享库后，动态链接器会将它们加载到进程的地址空间中。
5. **符号解析（Symbol Resolution）：**
   * **重定位（Relocation）：** 动态链接器会遍历辅助进程和其依赖库的重定位表，根据 `.dynsym` 和 `.dynstr` 中的信息，将代码和数据中对外部符号的引用绑定到这些符号的实际地址。
   * **GOT 和 PLT 的使用：** 对于导入的函数，动态链接器会使用 GOT 和 PLT 实现延迟绑定。最初，PLT 中的条目会跳转到链接器代码。当第一次调用该函数时，链接器会解析该符号的地址并更新 GOT 中的条目，后续调用将直接跳转到目标地址，避免重复解析。
6. **执行程序：** 链接完成后，动态链接器会将控制权交给辅助进程的入口点，开始执行程序代码。

**假设输入与输出 (对于 `iterate_dts` 测试)：**

**假设输入 (`tls_properties_helper` 内部行为):**

```c++
// tls_properties_helper.cpp (简化示例)
#include <pthread.h>
#include <stdio.h>
#include <bionic/tls.h>

__thread int static_tls_var = 123;

int main() {
  printf("got test_static_tls_bounds\n");

  // 设置一些动态 TLS
  pthread_key_t key1, key2;
  pthread_key_create(&key1, nullptr);
  pthread_key_create(&key2, nullptr);
  pthread_setspecific(key1, (void*)456);
  pthread_setspecific(key2, (void*)789);

  // 遍历动态 TLS
  __bionic_iterate_dynamic_tls([](void* value) {
    printf("iterate_cb i = %p\n", value); // 假设这里打印了 value
    return true;
  });

  printf("done_iterate_dynamic_tls\n");
  return 0;
}
```

**预期输出 (与测试用例中的 `expected_out` 匹配):**

```
got test_static_tls_bounds
iterate_cb i = 0x1c8
iterate_cb i = 0x309
done_iterate_dynamic_tls
```

**解释：**

* `got test_static_tls_bounds`:  辅助进程打印的初始消息。
* `iterate_cb i = ...`: `__bionic_iterate_dynamic_tls` 遍历动态 TLS 变量时，回调函数被调用，并打印了每个动态 TLS 变量的值（示例中假设直接打印了 `void*` 指针的值，实际实现可能更复杂）。注意，实际输出的地址值会因运行时内存布局而异。
* `done_iterate_dynamic_tls`: 辅助进程完成遍历后打印的消息。

**假设输入与输出 (对于 `thread_exit_cb` 测试)：**

**假设输入 (`thread_exit_cb_helper` 内部行为):**

```c++
// thread_exit_cb_helper.cpp (简化示例)
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void exit_cb_1(void* arg) { printf("exit_cb_1 called "); }
void exit_cb_2(void* arg) { printf("exit_cb_2 called "); }
void exit_cb_3(void* arg) { printf("exit_cb_3 called"); }

int main() {
  pthread_key_t key;
  pthread_key_create(&key, exit_cb_1);
  pthread_setspecific(key, (void*)1);

  pthread_key_t key2;
  pthread_key_create(&key2, exit_cb_2);
  pthread_setspecific(key2, (void*)2);

  atexit(exit_cb_3); // 使用 atexit 注册一个回调

  return 0; // 主线程退出
}
```

**预期输出 (与测试用例中的 `expected_out` 匹配):**

```
exit_cb_1 called exit_cb_2 called exit_cb_3 called
```

**解释：**

* `exit_cb_1 called`: 当线程退出时，与 `key` 关联的退出回调 `exit_cb_1` 被调用。
* `exit_cb_2 called`: 当线程退出时，与 `key2` 关联的退出回调 `exit_cb_2` 被调用。
* `exit_cb_3 called`: 当进程正常退出时，通过 `atexit` 注册的 `exit_cb_3` 被调用。

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **TLS 使用错误：**
   * **忘记初始化 TLS 变量：** 如果没有为 TLS 变量赋予初始值，可能会导致未定义的行为。
   * **在错误的线程访问 TLS 变量：** TLS 变量是线程局部的，尝试在其他线程访问会导致错误。
   * **内存泄漏：** 如果动态分配了 TLS 变量，需要在线程退出回调中释放内存，否则可能导致内存泄漏。
   * **竞争条件：**  虽然 TLS 本身是为了避免竞争条件，但在某些复杂的场景下，不当的 TLS 使用仍然可能引入竞争。

   **示例：**

   ```c++
   __thread int my_tls_var; // 未初始化

   void* thread_func(void* arg) {
       printf("TLS value: %d\n", my_tls_var); // 可能输出随机值
       return nullptr;
   }
   ```

2. **线程退出回调使用错误：**
   * **回调函数中访问无效内存：**  如果在回调函数中尝试访问已经释放的资源，会导致程序崩溃。
   * **回调函数中执行耗时操作：**  线程退出回调应该快速执行，避免阻塞进程退出。
   * **回调函数中抛出异常 (C++)：** 在某些平台上，线程退出回调中抛出的异常可能不会被正确处理。
   * **注册顺序依赖：** 如果回调函数的执行顺序很重要，需要仔细考虑注册顺序，但最好设计为顺序无关。
   * **忘记取消注册回调：**  某些回调机制可能需要显式取消注册，否则可能在不期望的时候被调用。

   **示例：**

   ```c++
   pthread_key_t key;
   int* data_to_free;

   void exit_callback(void* arg) {
       free(data_to_free); // 如果 data_to_free 在其他地方被提前释放，这里会出错
   }

   void* thread_func(void* arg) {
       data_to_free = (int*)malloc(sizeof(int));
       pthread_key_create(&key, exit_callback);
       pthread_setspecific(key, nullptr);
       // ...
       return nullptr;
   }
   ```

3. **`execve` 使用错误：**
   * **路径错误：**  提供的可执行文件路径不存在或不可访问。
   * **参数错误：**  传递给新程序的参数不正确。
   * **环境变量错误：**  设置了不正确的环境变量。
   * **权限问题：**  当前用户没有执行目标文件的权限。
   * **文件格式错误：**  目标文件不是有效的可执行文件。

   **示例：**

   ```c++
   execve("/path/to/nonexistent_program", nullptr, nullptr); // 路径错误
   ```

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework (Java):**
   * Android 应用通常从 Java 代码开始。如果应用需要执行一些原生代码，可以使用 NDK。
   * 例如，一个 Java 线程可以使用 `java.lang.Thread` 类创建。

2. **NDK (Native Development Kit):**
   * Java 代码可以通过 JNI (Java Native Interface) 调用 NDK 编写的 C/C++ 代码。
   * 在 NDK 代码中，可以使用 POSIX 线程 API (`pthread_create`) 创建新的线程。

3. **Bionic (C Library):**
   * `pthread_create` 等 NDK 提供的线程相关 API 最终会调用 Bionic 库中的实现。
   * Bionic 负责底层的线程创建、管理和同步。这包括 TLS 的分配和管理，以及线程退出回调的注册和执行。

4. **`sys_thread_properties_test.cpp` 的触发：**
   * 这个测试文件不是应用运行时会直接执行的代码。它是 Android 系统编译和测试过程的一部分。
   * 当 Android 工程师或自动化测试系统构建和测试 Bionic 库时，会编译并运行 `sys_thread_properties_test.cpp` 中的测试用例，以确保 Bionic 的线程相关功能正常工作。

**Frida Hook 示例：**

可以使用 Frida hook 这些步骤中的关键函数，以观察参数和行为。

**示例 1：Hook `execve` 系统调用：**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach("com.example.myapp") # 替换为你的应用进程名
except frida.ProcessNotFoundError:
    print("目标进程未找到，请确保应用正在运行")
    sys.exit()

script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, "execve"), {
    onEnter: function(args) {
        console.log("execve called");
        console.log("  pathname: " + Memory.readUtf8String(args[0]));
        console.log("  argv: " + JSON.stringify(this.argvToStringArray(args[1])));
        console.log("  envp: (omitted for brevity)"); // 环境变量可能很多
    },
    argvToStringArray: function(argv) {
        var result = [];
        for (var i = 0; ; i++) {
            var arg = Memory.readPointer(argv.add(i * Process.pointerSize));
            if (arg.isNull())
                break;
            result.push(Memory.readUtf8String(arg));
        }
        return result;
    }
});
""")
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**示例 2：Hook `pthread_create` 函数：**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach("com.example.myapp") # 替换为你的应用进程名
except frida.ProcessNotFoundError:
    print("目标进程未找到，请确保应用正在运行")
    sys.exit()

script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
    onEnter: function(args) {
        console.log("pthread_create called");
        console.log("  thread: " + args[0]);
        console.log("  attr: " + args[1]);
        console.log("  start_routine: " + args[2]);
        console.log("  arg: " + args[3]);
    }
});
""")
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**示例 3：Hook `__bionic_iterate_dynamic_tls` 函数 (可能需要 root 权限或在模拟器上操作):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach("com.example.myapp") # 替换为你的应用进程名
except frida.ProcessNotFoundError:
    print("目标进程未找到，请确保应用正在运行")
    sys.exit()

script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "__bionic_iterate_dynamic_tls"), {
    onEnter: function(args) {
        console.log("__bionic_iterate_dynamic_tls called");
        console.log("  callback: " + args[0]);
    },
    onLeave: function(retval) {
        console.log("__bionic_iterate_dynamic_tls returned: " + retval);
    }
});
""")
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤：**

1. **准备环境：** 安装 Frida 和 Python，连接 Android 设备或模拟器。
2. **找到目标进程：** 确定要调试的应用程序的进程名或 PID。
3. **编写 Frida 脚本：** 根据需要 hook 的函数编写相应的 Frida 脚本。
4. **运行 Frida 脚本：** 使用 `frida -U -f com.example.myapp script.py` (或 `frida -U <进程名或 PID> script.py`) 运行脚本。
5. **触发目标代码：** 在应用程序中执行操作，触发调用被 hook 的函数。
6. **观察输出：** Frida 会打印出 hook 函数的参数和返回值等信息，帮助你理解代码的执行流程。

通过 Frida hook，可以深入了解 Android Framework 和 NDK 如何一步步调用到 Bionic 的底层实现，以及 Bionic 如何处理线程属性和相关操作。记住，hook 系统级别的函数可能需要 root 权限或在模拟器上进行。

### 提示词
```
这是目录为bionic/tests/sys_thread_properties_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2020 The Android Open Source Project
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

#include "gtest_globals.h"
#include "utils.h"

TEST(thread_properties_test, iterate_dts) {
#if defined(__BIONIC__)
  const char expected_out[] =
      "got test_static_tls_bounds\niterate_cb i = 0\ndone_iterate_dynamic_tls\n";
  std::string helper = GetTestLibRoot() + "tls_properties_helper/tls_properties_helper";
  ExecTestHelper eth;
  eth.SetArgs({helper.c_str(), nullptr});
  eth.Run([&]() { execve(helper.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, expected_out);
#endif
}

TEST(thread_properties_test, thread_exit_cb) {
#if defined(__BIONIC__)
  // tests/libs/thread_exit_cb_helper.cpp
  const char expected_out[] = "exit_cb_1 called exit_cb_2 called exit_cb_3 called";
  std::string helper = GetTestLibRoot() + "thread_exit_cb_helper/thread_exit_cb_helper";
  ExecTestHelper eth;
  eth.SetArgs({helper.c_str(), nullptr});
  eth.Run([&]() { execve(helper.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, expected_out);
#endif
}
```