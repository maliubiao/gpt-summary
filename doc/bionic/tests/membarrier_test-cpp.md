Response:
Let's break down the thought process for generating the comprehensive answer about `membarrier_test.cpp`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C++ code and explain its functionality within the Android Bionic context. This involves more than just a simple code summary. It requires understanding the purpose of the code, its relation to the OS kernel, potential usage scenarios, and how it fits within the broader Android ecosystem.

**2. Initial Code Scan and Identification of Key Elements:**

The first step is to read through the code and identify the main components:

* **Includes:** `gtest/gtest.h`, `linux/membarrier.h`, `sys/syscall.h`, `utils.h`. This immediately tells us it's a testing file using Google Test, interacts with the Linux kernel's `membarrier` feature, and likely makes direct system calls. The `utils.h` might contain helper functions, but its content isn't provided, so we can only speculate generally.
* **Conditional Compilation:** `#if defined(__BIONIC__)` is crucial. It signifies that this code is specific to Bionic builds.
* **`ScopedErrnoCleaner`:**  This is a simple RAII class for resetting `errno`. This suggests the tests are concerned with checking the success/failure of system calls.
* **`HasMembarrier` function:**  This function checks if a specific `membarrier` command is supported by the kernel. It uses the `MEMBARRIER_CMD_QUERY` command.
* **`TEST` macros:** These clearly define individual test cases.
* **`membarrier` test suite:**  The tests are grouped under this suite.
* **System calls:** The core functionality revolves around `syscall(__NR_membarrier, ...)`. This is the direct way to interact with the `membarrier` system call in the kernel.
* **`MembarrierCommandToName` function:** A utility function to convert `membarrier` command constants to human-readable strings for better test output.
* **`TestRegisterAndBarrierCommands` function:** A helper function to test registration and subsequent barrier execution for different `membarrier` commands.

**3. Deciphering the Functionality - Connecting the Dots:**

After identifying the key elements, the next step is to understand *what* the code is doing:

* **Testing the `membarrier` system call:** The core purpose is clearly to test the functionality of the `membarrier` system call.
* **Checking for kernel support:** The `HasMembarrier` function and the conditional skips in the tests demonstrate a focus on verifying if the kernel supports the `membarrier` feature and specific commands.
* **Testing different `membarrier` commands:** The individual tests for `global_barrier`, `global_expedited`, `private_expedited`, and `private_expedited_sync_core` show that the code aims to test various types of memory barriers.
* **Testing registration:** The `TestRegisterAndBarrierCommands` function specifically targets the registration mechanism for certain expedited memory barriers. It verifies that you need to register before using the private expedited barriers.

**4. Relating to Android:**

Now, we need to connect the code to the broader Android context:

* **Bionic's role:**  Recognizing that Bionic is Android's C library is key. This means these tests are part of ensuring the correctness of Bionic's implementation of the `membarrier` functionality.
* **Kernel dependency:** Understanding that `membarrier` is a Linux kernel feature is essential. The tests implicitly acknowledge that the availability and behavior of `membarrier` depend on the underlying kernel.
* **Implications for multithreading/multiprocessing:** The very nature of memory barriers points to their importance in concurrent programming. Explaining how they help ensure memory consistency is crucial.

**5. Explaining Libc Functions:**

The primary libc function involved is `syscall`. The explanation should cover:

* **Purpose:**  The general mechanism for making system calls.
* **Mechanism:**  How it transitions to kernel space.
* **Parameters:**  The role of `__NR_membarrier` and the command arguments.
* **Return value and `errno`:** How errors are reported.

**6. Addressing Dynamic Linking (Though Limited in This Code):**

While this specific test file doesn't heavily involve dynamic linking, it's important to touch upon it because Bionic includes the dynamic linker. The explanation should:

* **Acknowledge the limited scope:**  Point out that this file primarily tests system calls.
* **General concepts:** Briefly explain the role of the dynamic linker in resolving symbols and loading shared libraries.
* **Hypothetical example:**  Create a simple scenario where another library might use `membarrier` and how the dynamic linker would be involved in resolving the `syscall` function.

**7. User/Programming Errors:**

This requires thinking about how developers might misuse `membarrier`:

* **Incorrect usage without registration:**  The tests themselves highlight this potential error.
* **Misunderstanding the scope of barriers:**  Not understanding the difference between global and private barriers.
* **Performance implications:** Using barriers unnecessarily can impact performance.

**8. Android Framework/NDK and Frida Hooking:**

This is where we trace the path from the higher levels of Android down to this code:

* **Framework/NDK usage:**  Explain how the framework or NDK libraries might eventually rely on the underlying `membarrier` system call (even indirectly). A concrete example involving concurrency would be beneficial.
* **Frida example:**  Provide a practical Frida script to intercept the `syscall` related to `membarrier`. This demonstrates how to observe the system call in action.

**9. Structure and Language:**

Finally, the answer needs to be structured logically and written in clear, concise Chinese. Using headings, bullet points, and code examples enhances readability. The language should be technically accurate but also understandable to a broader audience.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:** Focus solely on the code.
* **Correction:**  Realize the need to connect it to the bigger picture of Android and the kernel.
* **Initial thought:**  Provide a very technical explanation of `syscall`.
* **Correction:**  Balance technical details with a more accessible explanation.
* **Initial thought:**  Overlook dynamic linking because it's not explicit in the code.
* **Correction:**  Include a brief explanation of its potential involvement and provide a hypothetical scenario.
* **Initial thought:**  Focus only on the successful test cases.
* **Correction:**  Also consider potential error scenarios and how developers might misuse the functionality.

By following this structured thought process, considering the different facets of the request, and incorporating self-correction, we can arrive at a comprehensive and informative answer like the example provided.这个`bionic/tests/membarrier_test.cpp` 文件是 Android Bionic 库中的一个测试文件，专门用于测试 `membarrier` 系统调用的功能。`membarrier` 是 Linux 内核提供的一个内存屏障机制，用于在多线程或多进程环境下确保内存操作的顺序性和可见性。

**它的功能:**

1. **测试 `membarrier` 系统调用的存在性:**  测试当前运行的内核是否支持 `membarrier` 系统调用。如果不支持，则跳过后续的测试。
2. **测试 `MEMBARRIER_CMD_QUERY` 命令:**  通过 `MEMBARRIER_CMD_QUERY` 命令查询内核支持的 `membarrier` 命令。
3. **测试 `MEMBARRIER_CMD_GLOBAL` 命令:** 测试全局内存屏障功能，确保所有 CPU 上的所有线程都执行完之前的内存操作。
4. **测试 `MEMBARRIER_CMD_GLOBAL_EXPEDITED` 命令:** 测试全局加速内存屏障功能，这是一种更轻量级的全局屏障，但可能只保证部分内存操作的顺序性。
5. **测试 `MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED` 命令:** 测试注册使用全局加速内存屏障的功能。
6. **测试 `MEMBARRIER_CMD_PRIVATE_EXPEDITED` 命令:** 测试进程私有的加速内存屏障功能。这种屏障只影响调用进程内的线程。
7. **测试 `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED` 命令:** 测试注册使用进程私有的加速内存屏障的功能。
8. **测试 `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` 命令:** 测试进程私有的加速内存屏障，并同步调用线程所在 CPU 核心的功能。
9. **测试 `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` 命令:** 测试注册使用进程私有的加速内存屏障并同步核心的功能。
10. **处理 `errno`:**  使用 `ScopedErrnoCleaner` 类在测试前后重置 `errno`，以确保每个测试的 `errno` 状态是独立的。

**与 Android 功能的关系及举例说明:**

`membarrier` 对于 Android 系统的稳定性和正确性至关重要，尤其是在多线程和多进程的场景下。Android Framework 和 NDK 中许多并发相关的机制都依赖于内存屏障来保证数据的一致性。

* **Zygote 进程 fork:** 当 Zygote 进程 fork 出新的应用进程时，`membarrier` 可以确保父进程（Zygote）的内存状态在子进程中得到正确的反映，避免出现数据竞争和意外行为。例如，Zygote 可能会预加载一些共享库，`membarrier` 可以确保这些库的初始化操作在子进程 fork 之后对子进程可见。
* **Binder 机制:** Android 的 Binder 机制用于进程间通信。在 Binder 驱动程序和用户空间库中，可能会使用内存屏障来确保跨进程传递的数据的可见性和顺序性。例如，当一个进程通过 Binder 调用另一个进程的服务时，`membarrier` 可以确保调用的参数在服务进程中被正确读取。
* **ART (Android Runtime) 的垃圾回收 (GC):** ART 的 GC 是并发执行的，需要保证 GC 线程和其他应用线程之间内存操作的正确同步。`membarrier` 可以用于确保 GC 线程对堆内存的修改对应用线程是可见的，反之亦然。
* **NDK 中的多线程编程:** 使用 NDK 进行 native 开发的开发者可能会使用 pthreads 等库创建多线程应用。在这些应用中，如果多个线程访问共享内存，就需要使用内存屏障（如 `std::atomic` 内部可能使用 `membarrier` 或类似的机制）来避免数据竞争。

**详细解释每一个 libc 函数的功能是如何实现的:**

在这个测试文件中，主要使用的 libc 函数是 `syscall`。

* **`syscall` 函数:**
    * **功能:** `syscall` 是一个通用的系统调用接口。它允许用户空间程序直接调用 Linux 内核提供的系统服务。
    * **实现:**
        1. **系统调用号:**  `syscall` 的第一个参数是一个整数，表示要调用的系统调用的编号。`__NR_membarrier` 是 `membarrier` 系统调用的宏定义编号。这个编号在不同的架构下可能会有所不同。
        2. **参数传递:**  `syscall` 的后续参数是要传递给系统调用的参数。对于 `membarrier`，第二个参数是 `membarrier_cmd`，表示要执行的具体 `membarrier` 命令，第三个参数通常是标志位，在这个测试中通常为 0。
        3. **陷入内核:** `syscall` 函数内部会使用汇编指令（例如，x86-64 架构上的 `syscall` 指令，ARM64 上的 `svc` 指令）触发一个异常，使得 CPU 从用户态切换到内核态。
        4. **内核处理:**  内核接收到系统调用请求后，会根据系统调用号找到对应的内核函数 (`sys_membarrier`) 并执行。
        5. **返回值和错误处理:**  系统调用执行完毕后，内核会将结果返回给用户空间。如果系统调用成功，通常返回 0。如果发生错误，通常返回 -1，并且内核会将错误码设置到全局变量 `errno` 中。
        6. **`errno`:**  `errno` 是一个全局变量，用于存储最近一次系统调用或某些库函数调用失败时的错误码。`ScopedErrnoCleaner` 类在构造时和析构时都将 `errno` 设置为 0，确保测试的独立性，方便检查特定的系统调用是否设置了预期的错误码。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

在这个特定的测试文件中，并没有直接涉及动态链接器的功能。这个文件直接使用 `syscall` 调用内核的 `membarrier` 系统调用，而不需要通过动态链接加载共享库。

但是，如果其他库（比如 Android Framework 中的某个库）使用了 `membarrier` 功能，那么动态链接器就会参与到链接的过程中。

**so 布局样本 (假设一个名为 `libmembarrier_user.so` 的共享库使用了 `membarrier`):**

```
libmembarrier_user.so:
    .text         # 代码段
        ... 使用 membarrier 的函数 ...
    .data         # 数据段
        ...
    .bss          # 未初始化数据段
        ...
    .dynamic      # 动态链接信息
        NEEDED      libc.so  # 依赖 libc.so
        ...
    .dynsym       # 动态符号表
        ... syscall 的符号 ...
        ... 其他符号 ...
    .rel.plt      # PLT 重定位表
        ... syscall 的重定位信息 ...
    .plt          # 过程链接表 (PLT)
        ... syscall 的 PLT 条目 ...
```

**链接的处理过程:**

1. **加载 `libmembarrier_user.so`:** 当一个应用或进程需要使用 `libmembarrier_user.so` 时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载这个共享库到进程的地址空间。
2. **解析依赖:** 动态链接器会读取 `libmembarrier_user.so` 的 `.dynamic` 段，找到其依赖的共享库，例如 `libc.so`。
3. **加载依赖库:** 动态链接器会继续加载 `libc.so`（如果尚未加载）。
4. **符号解析:** 动态链接器会解析 `libmembarrier_user.so` 中对外部符号的引用，例如 `syscall`。它会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `syscall` 的地址。
5. **重定位:**
    * **PLT (Procedure Linkage Table):** 对于像 `syscall` 这样的外部函数，通常会使用 PLT 进行延迟绑定。在第一次调用 `syscall` 时，会通过 PLT 中的一段代码跳转回动态链接器。
    * **动态链接器介入:** 动态链接器会解析 `syscall` 的真实地址，并更新 PLT 表中的条目，以便后续的调用可以直接跳转到 `syscall` 的实现。
    * **GOT (Global Offset Table):** PLT 通常会使用 GOT 来存储解析后的地址。

**假设输入与输出 (逻辑推理):**

* **假设输入:**
    * 运行测试的 Android 设备内核支持 `membarrier` 系统调用。
    * 内核支持 `MEMBARRIER_CMD_GLOBAL` 命令。
* **预期输出:** `TEST(membarrier, global_barrier)` 测试会成功，`ASSERT_EQ(0, syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0))` 返回 0，表示系统调用成功。

* **假设输入:**
    * 运行测试的 Android 设备内核 **不** 支持 `membarrier` 系统调用。
* **预期输出:** `TEST(membarrier, query)` 测试中，`syscall(__NR_membarrier, MEMBARRIER_CMD_QUERY, 0)` 会返回 -1，并且 `errno` 会被设置为 `ENOSYS` (Function not implemented)，然后测试会因为 `GTEST_SKIP()` 而跳过。

* **假设输入:**
    * 运行测试的 Android 设备内核支持 `membarrier`，但不支持 `MEMBARRIER_CMD_PRIVATE_EXPEDITED` 命令。
* **预期输出:** `TEST(membarrier, private_expedited)` 测试会因为 `!HasMembarrier(membarrier_cmd_register)` 的判断而跳过。

**用户或者编程常见的使用错误，请举例说明:**

1. **在不支持 `membarrier` 的内核上使用:** 如果应用程序尝试在旧版本的 Android 或 Linux 内核上使用 `membarrier`，系统调用会失败，`errno` 会被设置为 `ENOSYS`。开发者需要进行内核版本检查或者使用条件编译。

   ```c++
   #include <sys/syscall.h>
   #include <unistd.h>
   #include <errno.h>
   #include <stdio.h>
   #include <linux/membarrier.h>

   int main() {
       int result = syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0);
       if (result == -1) {
           perror("membarrier failed");
           if (errno == ENOSYS) {
               printf("membarrier is not supported on this kernel.\n");
           }
           return 1;
       }
       printf("membarrier succeeded.\n");
       return 0;
   }
   ```

2. **在需要注册的情况下直接使用 barrier 命令:**  对于某些类型的 `membarrier` 命令（如 `MEMBARRIER_CMD_PRIVATE_EXPEDITED`），需要先进行注册。如果直接使用 barrier 命令而没有先注册，系统调用会失败，`errno` 会被设置为 `EPERM` (Operation not permitted)。

   ```c++
   #include <sys/syscall.h>
   #include <unistd.h>
   #include <errno.h>
   #include <stdio.h>
   #include <linux/membarrier.h>

   int main() {
       int result = syscall(__NR_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0);
       if (result == -1) {
           perror("private expedited membarrier failed");
           if (errno == EPERM) {
               printf("Must register before using private expedited membarrier.\n");
           }
           return 1;
       }
       printf("private expedited membarrier succeeded.\n");
       return 0;
   }
   ```

3. **错误地理解不同 barrier 命令的作用域:**  开发者需要清楚不同 `membarrier` 命令（如 global vs. private）的影响范围，错误地使用可能无法达到预期的同步效果，或者造成不必要的性能开销。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

虽然这个测试文件本身是在 Bionic 库的测试套件中，但 Android Framework 或 NDK 的代码最终可能会调用到 `membarrier` 系统调用。以下是一个简化的说明和 Frida Hook 示例：

**可能的路径 (示例，实际情况可能更复杂):**

1. **Android Framework (Java 代码):**  某些涉及到并发控制或者跨进程通信的 Framework 组件（例如，`ActivityManagerService`，`WindowManagerService`）的 Java 代码可能会调用到 Native 代码。
2. **JNI 调用:** Framework 的 Java 代码通过 JNI (Java Native Interface) 调用到相关的 Native (C/C++) 代码。
3. **NDK 库或 Framework Native 库:** 这些 Native 库可能会使用 pthreads 或其他并发原语，在这些原语的实现中，为了保证内存一致性，可能会间接地调用到 `membarrier` 或者使用其他类似的内存屏障机制。例如，`std::atomic` 的某些操作在底层可能会使用 `membarrier`。
4. **Bionic libc:**  最终，这些 Native 代码如果需要显式地调用 `membarrier`，会通过 `syscall(__NR_membarrier, ...)` 来实现，这正是这个测试文件所测试的。

**Frida Hook 示例:**

假设我们想 hook 任何进程中对 `membarrier` 系统调用的调用，并打印出调用的命令：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <process name or PID>".format(sys.argv[0]))
        sys.exit(1)

    try:
        process = frida.attach(sys.argv[1])
    except frida.ProcessNotFoundError:
        print("Process not found: {}".format(sys.argv[1]))
        sys.exit(1)

    script_code = """
    'use strict';

    const MembarrierCommandToName = (cmd) => {
        switch (cmd) {
            case 0: return "MEMBARRIER_CMD_QUERY";
            case 1: return "MEMBARRIER_CMD_GLOBAL";
            case 2: return "MEMBARRIER_CMD_GLOBAL_EXPEDITED";
            case 3: return "MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED";
            case 4: return "MEMBARRIER_CMD_PRIVATE_EXPEDITED";
            case 5: return "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED";
            case 6: return "MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE";
            case 7: return "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE";
            default: return "MEMBARRIER_UNKNOWN";
        }
    };

    Interceptor.attach(Module.findExportByName(null, "syscall"), {
        onEnter: function(args) {
            const syscallNumber = args[0].toInt32();
            const membarrierSyscallNumber = 333; // 替换为当前架构的 __NR_membarrier 值

            if (syscallNumber === membarrierSyscallNumber) {
                const cmd = args[1].toInt32();
                const cmdName = MembarrierCommandToName(cmd);
                console.log("[Membarrier Hook] Calling membarrier with command: " + cmdName);
                // 可以打印更多参数信息
            }
        },
        onLeave: function(retval) {
            // console.log("Return value: " + retval);
        }
    });
    """

    script = process.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, press Ctrl+C to exit")
    sys.stdin.read()
    process.detach()

if __name__ == '__main__':
    main()
```

**使用步骤:**

1. **找到 `__NR_membarrier` 的值:**  需要在目标 Android 设备的架构下找到 `__NR_membarrier` 的值。这通常可以在 `/usr/include/asm/unistd_64.h` (对于 64 位系统) 或类似的头文件中找到。
2. **替换脚本中的值:** 将脚本中的 `membarrierSyscallNumber` 替换为找到的实际值。
3. **运行 Frida 脚本:**  使用 `python your_script.py <目标进程名或 PID>` 运行脚本。例如，`python your_script.py system_server` 或 `python your_script.py 1234`。
4. **观察输出:** 当目标进程调用 `membarrier` 系统调用时，Frida 脚本会拦截调用并打印出相应的命令。

这个 Frida 示例提供了一种动态调试和观察 Android 系统中 `membarrier` 使用情况的方法。通过这种方式，可以更深入地了解 Framework 或 NDK 中哪些组件在何时使用了内存屏障。

Prompt: 
```
这是目录为bionic/tests/membarrier_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

// membarrier(2) is only supported for bionic builds (b/111199492).
#if defined(__BIONIC__)

#include <linux/membarrier.h>
#include <sys/syscall.h>

#include "utils.h"

class ScopedErrnoCleaner {
 public:
  ScopedErrnoCleaner() { errno = 0; }
  ~ScopedErrnoCleaner() { errno = 0; }
};

static bool HasMembarrier(int membarrier_cmd) {
  ScopedErrnoCleaner errno_cleaner;
  int supported_cmds = syscall(__NR_membarrier, MEMBARRIER_CMD_QUERY, 0);
  return (supported_cmds > 0) && ((supported_cmds & membarrier_cmd) != 0);
}

TEST(membarrier, query) {
  ScopedErrnoCleaner errno_cleaner;
  int supported = syscall(__NR_membarrier, MEMBARRIER_CMD_QUERY, 0);
  if (supported == -1 && errno == ENOSYS) GTEST_SKIP() << "no membarrier() in this kernel";
  ASSERT_GE(supported, 0);
}

TEST(membarrier, global_barrier) {
  if (!HasMembarrier(MEMBARRIER_CMD_GLOBAL)) {
    GTEST_SKIP() << "MEMBARRIER_CMD_GLOBAL not supported";
  }
  ASSERT_EQ(0, syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0));
}

static const char* MembarrierCommandToName(int membarrier_cmd) {
  switch (membarrier_cmd) {
  case MEMBARRIER_CMD_QUERY:
    return "MEMBARRIER_CMD_QUERY";
  case MEMBARRIER_CMD_GLOBAL:
    return "MEMBARRIER_CMD_GLOBAL";
  case MEMBARRIER_CMD_GLOBAL_EXPEDITED:
    return "MEMBARRIER_CMD_GLOBAL_EXPEDITED";
  case MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED:
    return "MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED";
  case MEMBARRIER_CMD_PRIVATE_EXPEDITED:
    return "MEMBARRIER_CMD_PRIVATE_EXPEDITED";
  case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED:
    return "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED";
  case MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE:
    return "MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE";
  case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE:
    return "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE";
  default:
    return "MEMBARRIER_UNKNOWN";
  }
}

static void TestRegisterAndBarrierCommands(int membarrier_cmd_register,
                                           int membarrier_cmd_barrier) {
  if (!HasMembarrier(membarrier_cmd_register)) {
    GTEST_SKIP() << MembarrierCommandToName(membarrier_cmd_register) << " not supported";
  }
  if (!HasMembarrier(membarrier_cmd_barrier)) {
    GTEST_SKIP() << MembarrierCommandToName(membarrier_cmd_barrier) << " not supported";
  }

  ScopedErrnoCleaner errno_cleaner;

  // Check barrier use without prior registration.
  if (membarrier_cmd_register == MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED) {
    // Global barrier use is always okay.
    ASSERT_EQ(0, syscall(__NR_membarrier, membarrier_cmd_barrier, 0));
  } else {
    // Private barrier should fail.
    ASSERT_EQ(-1, syscall(__NR_membarrier, membarrier_cmd_barrier, 0));
    ASSERT_ERRNO(EPERM);
    errno = 0;
  }

  // Check registration for barrier succeeds.
  ASSERT_EQ(0, syscall(__NR_membarrier, membarrier_cmd_register, 0));

  // Check barrier use after registration succeeds.
  ASSERT_EQ(0, syscall(__NR_membarrier, membarrier_cmd_barrier, 0));
}

TEST(membarrier, global_expedited) {
  TestRegisterAndBarrierCommands(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
                                 MEMBARRIER_CMD_GLOBAL_EXPEDITED);
}

TEST(membarrier, private_expedited) {
  TestRegisterAndBarrierCommands(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,
                                 MEMBARRIER_CMD_PRIVATE_EXPEDITED);
}

TEST(membarrier, private_expedited_sync_core) {
  TestRegisterAndBarrierCommands(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
                                 MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE);
}

#endif  // __BIONIC__

"""

```