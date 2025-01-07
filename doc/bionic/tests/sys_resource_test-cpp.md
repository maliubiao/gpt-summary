Response:
Let's break down the thought process for analyzing this C++ test file and generating the comprehensive response.

**1. Understanding the Goal:**

The request asks for a detailed analysis of the `sys_resource_test.cpp` file within the Android Bionic library. The core requests are: functionality, relationship to Android, libc function explanation, dynamic linker involvement (if any), logic reasoning, common errors, and how Android frameworks reach this code (with Frida examples).

**2. Initial Code Scan and Keyword Identification:**

First, I quickly scanned the code looking for key elements:

* **Includes:** `<sys/resource.h>`, `<gtest/gtest.h>`. This immediately tells me it's a test file focusing on resource limits. `gtest` confirms it's a Google Test framework test.
* **Test Fixtures:** `TEST(sys_resource, ...)` and `class SysResourceTest : public ::testing::Test`. This structure confirms it's organized testing specific functionalities related to resource limits.
* **Core Functions:** `getrlimit`, `getrlimit64`, `setrlimit`, `setrlimit64`, `prlimit`, `prlimit64`. These are the central functions being tested.
* **Data Structures:** `rlimit`, `rlimit64`. These are the structures used to interact with the resource limit functions.
* **Resource Limit Constant:** `RLIMIT_CORE`. This indicates the tests are primarily concerned with the core dump size limit.
* **Assertions:** `ASSERT_EQ`, `ASSERT_NE`, `ASSERT_TRUE`. These are standard Google Test assertions used to verify expected behavior.

**3. Deconstructing the Tests:**

I then went through each `TEST` case individually to understand its purpose:

* **`rlimit_struct_size`:**  This test checks the sizes of `rlimit`, `rlimit64`, and `rlim_t`. The `#if defined(__LP64__) || defined(__GLIBC__)` conditional indicates it's verifying size differences between 32-bit and 64-bit architectures (and potentially GLIBC).
* **`SysResourceTest` fixture's `SetUp`:**  This initializes the test environment by fetching the current core dump limits using both the standard `getrlimit`/`getrlimit64` and the process-specific `prlimit`/`prlimit64` functions.
* **`SysResourceTest::CheckResourceLimits`:** This utility function verifies that the limits obtained by `getrlimit` and `prlimit` (and their 64-bit counterparts) are consistent. It also handles the `RLIM_INFINITY` case.
* **`RLIMIT_CORE_rlim_max_not_zero`:**  This test ensures the maximum core dump size is not zero, which is important for subsequent tests. It also highlights a potential setup issue.
* **`get_resource_limit_equal`:** Simply calls `CheckResourceLimits` to verify initial consistency.
* **`setrlimit`:**  Tests setting a new current limit using `setrlimit` and then verifying the change.
* **`setrlimit64_smoke`:**  Similar to `setrlimit` but uses `setrlimit64`. The "smoke" indicates a basic functionality test.
* **`prlimit`:** Tests setting the current limit using `prlimit` for the current process.
* **`prlimit64_smoke`:** Similar to `prlimit` but uses `prlimit64`.

**4. Addressing Specific Request Points:**

Now, with a clear understanding of the code's purpose, I addressed each part of the original request:

* **Functionality:** Summarize what the tests do – verify the correct behavior of functions related to getting and setting resource limits, particularly for core dumps.
* **Android Relationship:** Explain how resource limits are crucial for managing system resources, preventing crashes from consuming excessive memory, and aiding in debugging via core dumps. Provide concrete examples like setting `RLIMIT_NOFILE` for open files.
* **libc Function Explanation:** For each function (`getrlimit`, `setrlimit`, `prlimit`, etc.), explain its purpose, parameters, return value, and its underlying implementation (system calls like `getrlimit` and `prlimit`). Emphasize the differences between the standard and process-specific versions.
* **Dynamic Linker:** Recognizing that this test file *doesn't directly involve dynamic linking*, I explicitly stated that and explained *why* it doesn't. This is important – not everything in Bionic touches the dynamic linker.
* **Logic Reasoning:** For tests like `rlimit_struct_size`, explain the assumptions and the reasoning behind the assertions (e.g., 64-bit systems use larger `rlim_t`). For other tests, briefly mention the expected outcome.
* **Common Errors:**  Consider what could go wrong when using these functions: permission issues, setting invalid limits, and the limitations of `setrlimit` requiring root privileges for increasing hard limits.
* **Android Framework/NDK Flow:**  Trace the path from a higher-level Android component (like `ActivityManager`) down to the system call level, explaining how resource limits are managed.
* **Frida Hook Example:** Provide concrete Frida code to demonstrate how to intercept and inspect the `getrlimit` call. This requires understanding Frida's syntax for hooking function calls.

**5. Structuring and Refining the Response:**

Finally, I organized the information logically, using clear headings and bullet points. I ensured the language was precise and easy to understand. I paid attention to the detail requested, providing specifics about system calls, data structures, and potential errors. The goal was to create a comprehensive and informative answer.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the dynamic linker is involved because it's in Bionic. **Correction:**  After closer inspection, the tests directly use system call wrappers, not dynamic linking features. It's important to be precise.
* **Considering the audience:**  The request doesn't specify the reader's background. I aimed for a balance between technical detail and clear explanations, suitable for someone with some C/C++ and operating system knowledge.
* **Emphasis on practical examples:** Instead of just listing function signatures, I focused on explaining the *use cases* and implications of these functions within Android.

By following these steps, I could generate a detailed and accurate analysis that addresses all aspects of the original request.好的，让我们来详细分析一下 `bionic/tests/sys_resource_test.cpp` 这个文件。

**功能概要**

`sys_resource_test.cpp` 是 Android Bionic 库中的一个测试文件，其主要功能是测试与系统资源限制相关的 C 标准库函数，特别是 `<sys/resource.h>` 中定义的函数和数据结构。这些函数允许进程查询和设置其自身的资源限制，例如允许使用的最大 CPU 时间、最大内存使用量、可以打开的最大文件数等。

这个测试文件使用 Google Test 框架（gtest）来编写，它包含了多个测试用例（以 `TEST` 或 `TEST_F` 开头），用于验证以下方面的功能：

1. **数据结构 `rlimit` 和 `rlimit64` 的大小:**  `rlimit_struct_size` 测试用例检查了 `rlimit` 和 `rlimit64` 结构体的大小，以及它们成员 `rlim_t` 和 `rlim64_t` 的大小。这对于确保在不同架构（32 位和 64 位）上数据结构的布局是正确的非常重要。

2. **获取资源限制:** `get_resource_limit_equal` 测试用例，以及 `SysResourceTest` fixture 的 `SetUp` 方法，验证了 `getrlimit` 和 `getrlimit64` 函数以及 `prlimit` 和 `prlimit64` 函数获取到的资源限制信息是否一致。

3. **设置资源限制:** `setrlimit` 和 `setrlimit64_smoke` 测试用例测试了设置资源限制的功能。它们尝试设置 `RLIMIT_CORE`（核心转储文件的大小限制）的当前值，并验证设置是否生效。`prlimit` 和 `prlimit64_smoke` 也是做类似的事情，但是针对特定进程（这里是当前进程 0）。

4. **资源限制的一致性:**  `SysResourceTest::CheckResourceLimits` 辅助函数被多个测试用例调用，用于确保通过不同方式（`getrlimit`/`getrlimit64` 和 `prlimit`/`prlimit64`）获取到的资源限制是相同的。它还处理了 `RLIM_INFINITY` 的情况。

5. **确保 `rlim_max` 不为零:** `RLIMIT_CORE_rlim_max_not_zero` 测试用例确保了 `RLIMIT_CORE` 的硬限制（`rlim_max`）不是零或一个很小的值。这可能是为了保证后续的测试能够正常运行，因为如果硬限制太小，设置新的当前限制可能会失败。

**与 Android 功能的关系及举例说明**

资源限制在 Android 系统中扮演着至关重要的角色，用于管理和控制进程对系统资源的使用，防止恶意或错误的应用程序消耗过多资源，从而影响系统稳定性。以下是一些具体的例子：

* **`RLIMIT_CPU` (CPU 时间限制):**  限制进程可以使用的 CPU 时间。如果一个进程超过了这个限制，系统会发送一个 `SIGXCPU` 信号给该进程。这可以防止某些死循环或计算密集型进程无限期地占用 CPU 资源。Android Framework 可以使用此限制来防止应用无响应（ANR）。

* **`RLIMIT_FSIZE` (文件大小限制):** 限制进程可以创建的文件的最大大小。这可以防止日志文件或临时文件无限增长，耗尽存储空间。例如，Android 的日志系统 (logcat) 在内部可能受到此限制的约束。

* **`RLIMIT_DATA` (数据段大小限制):** 限制进程的堆大小。这可以防止应用程序分配过多的内存，导致系统内存不足。Dalvik/ART 虚拟机在启动时会根据设备的内存配置设置此限制。

* **`RLIMIT_STACK` (栈大小限制):** 限制进程的栈大小。这可以防止栈溢出错误。每个线程都有自己的栈，Android 系统会为每个线程设置一个合理的栈大小限制。

* **`RLIMIT_NOFILE` (打开文件数限制):** 限制进程可以同时打开的最大文件描述符数量。这可以防止某些应用程序打开过多的文件句柄，耗尽系统资源。例如，一个网络服务器应用如果没有正确关闭连接，可能会超出这个限制。

* **`RLIMIT_CORE` (核心转储文件大小限制):** 限制进程崩溃时可以生成的核心转储文件的大小。核心转储文件用于调试崩溃问题。Android 系统通常会禁用核心转储，或者将其大小限制为一个较小的值，以节省存储空间。

**libc 函数的功能实现**

这里涉及到的主要 libc 函数是：

1. **`getrlimit(int resource, struct rlimit *rlim)` 和 `getrlimit64(int resource, struct rlimit64 *rlim)`:**
   - **功能:** 获取指定资源 (`resource`) 的当前软限制和硬限制。
   - **实现:**  这两个函数是系统调用的封装。在 Linux 内核中，它们最终会调用 `do_prlimit` 系统调用。内核会根据进程的凭据和资源限制表查找相应的限制值，并将其填充到 `rlim` 或 `rlim64` 结构体中。
   - **`rlimit` 结构体:** 通常包含两个成员 `rlim_cur` (当前/软限制) 和 `rlim_max` (最大/硬限制)。
   - **`rlimit64` 结构体:** 与 `rlimit` 类似，但其成员 `rlim_cur` 和 `rlim_max` 的类型是 `rlim64_t`，可以表示更大的值。
   - **返回值:** 成功时返回 0，失败时返回 -1 并设置 `errno`。

2. **`setrlimit(int resource, const struct rlimit *rlim)` 和 `setrlimit64(int resource, const struct rlimit64 *rlim)`:**
   - **功能:** 设置指定资源 (`resource`) 的软限制和/或硬限制。
   - **实现:** 这也是系统调用的封装，最终会调用内核的 `do_prlimit` 系统调用。
   - **限制:**
     - 只能将软限制设置为小于或等于硬限制的值。
     - 只有具有足够权限的进程（通常是 root 用户或具有 `CAP_SYS_RESOURCE` 能力的进程）才能提高硬限制。普通进程只能降低硬限制。
     - 尝试设置超过系统最大值的限制也会失败。
   - **返回值:** 成功时返回 0，失败时返回 -1 并设置 `errno`。

3. **`prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit)` 和 `prlimit64(pid_t pid, int resource, const struct rlimit64 *new_limit, struct rlimit64 *old_limit)`:**
   - **功能:**  获取或设置指定进程 (`pid`) 的资源限制。
   - **实现:**  这两个函数直接对应于 Linux 的 `prlimit` 系统调用。
   - **`pid` 参数:** 指定要操作的进程 ID。如果 `pid` 为 0，则表示当前进程。
   - **`new_limit` 参数:** 如果不为 `NULL`，则指向包含要设置的新限制的 `rlimit` 或 `rlimit64` 结构体。
   - **`old_limit` 参数:** 如果不为 `NULL`，则指向用于存储旧限制的 `rlimit` 或 `rlimit64` 结构体。
   - **权限:** 设置其他进程的资源限制需要相应的权限。
   - **返回值:** 成功时返回 0，失败时返回 -1 并设置 `errno`。

**涉及 dynamic linker 的功能**

这个测试文件 **没有直接涉及** dynamic linker 的功能。它主要关注的是与操作系统内核交互的资源限制相关的系统调用。dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的主要职责是加载动态链接库 (`.so` 文件)，解析符号，并重定位代码。

**但是，资源限制本身可能会影响 dynamic linker 的行为。** 例如，`RLIMIT_DATA` 可能会限制 dynamic linker 加载共享库时可以分配的内存。如果内存不足，加载过程可能会失败。

**如果这个测试文件要测试与 dynamic linker 相关的功能，它可能会包含以下内容：**

1. **加载和卸载共享库的测试:** 使用 `dlopen` 和 `dlclose` 函数来加载和卸载 `.so` 文件，并检查资源限制是否会影响这些操作。
2. **符号解析的测试:**  测试在加载共享库后，符号解析是否正常工作，并考虑资源限制可能带来的影响。

**so 布局样本和链接的处理过程 (假设测试 dynamic linker 功能)**

如果测试涉及到 dynamic linker，我们可能会创建一个简单的共享库，其布局可能如下：

```
# mylib.c
int my_function(int x) {
  return x * 2;
}
```

编译成共享库：

```bash
clang -shared -o libmylib.so mylib.c
```

这个 `libmylib.so` 文件在内存中的布局大致如下：

```
[ELF header]
[Program headers] (描述内存段，如 .text, .data, .dynamic)
...
[ .text section ] (代码段，包含 my_function 的指令)
...
[ .data section ] (已初始化数据)
...
[ .bss section ] (未初始化数据)
...
[ .dynamic section ] (动态链接信息，如依赖的库、符号表等)
...
[Symbol table] (包含导出的符号，如 my_function)
[String table] (用于存储符号名等字符串)
...
```

**链接的处理过程:**

1. **`dlopen("libmylib.so", RTLD_LAZY | RTLD_GLOBAL)`:** 当应用程序调用 `dlopen` 时，dynamic linker 会找到 `libmylib.so` 文件。
2. **加载到内存:** Dynamic linker 根据 ELF header 和 Program headers 将 `.so` 文件的各个段加载到内存中的合适位置。这涉及到分配内存（可能受 `RLIMIT_DATA` 影响）。
3. **解析依赖:** 如果 `libmylib.so` 依赖其他共享库，dynamic linker 会递归地加载这些依赖库。
4. **符号解析:** Dynamic linker 会解析 `libmylib.so` 中的符号引用。如果应用程序需要调用 `libmylib.so` 中的 `my_function`，dynamic linker 会在 `libmylib.so` 的符号表中查找 `my_function` 的地址。
5. **重定位:**  由于共享库被加载到内存中的地址可能不是编译时确定的地址，dynamic linker 需要修改代码中的某些指令，将符号引用更新为实际的内存地址。
6. **返回句柄:** `dlopen` 成功后返回一个指向已加载共享库的句柄。

**逻辑推理，假设输入与输出 (以 `setrlimit` 测试为例)**

**假设输入:**

* 当前进程的 `RLIMIT_CORE` 的软限制 (`l32_.rlim_cur`) 为某个值 (例如，0)。
* 我们想要将 `RLIMIT_CORE` 的软限制设置为 123U。

**逻辑推理:**

1. `setrlimit(RLIMIT_CORE, &l32_)` 被调用，其中 `l32_.rlim_cur` 被设置为 123U。
2. 系统调用会被执行，尝试更新当前进程的 `RLIMIT_CORE` 软限制。
3. 假设设置成功（通常需要满足软限制 <= 硬限制的条件）。
4. 随后调用 `CheckResourceLimits()` 来验证新的限制是否生效。
5. `getrlimit(RLIMIT_CORE, &l32_)` 应该返回更新后的软限制值 123U。
6. 断言 `ASSERT_EQ(123U, l32_.rlim_cur)` 应该通过。

**预期输出:**

测试用例执行成功，没有断言失败。

**用户或编程常见的使用错误**

1. **权限不足:** 尝试使用 `setrlimit` 提高硬限制，但当前进程没有足够的权限（例如，不是 root 用户或没有 `CAP_SYS_RESOURCE` 能力）。这会导致 `setrlimit` 调用失败，并返回 -1，`errno` 设置为 `EPERM`。

   ```c++
   #include <sys/resource.h>
   #include <stdio.h>
   #include <errno.h>

   int main() {
       struct rlimit limit;
       getrlimit(RLIMIT_NOFILE, &limit);
       limit.rlim_max = 65535; // 尝试提高硬限制
       if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
           perror("setrlimit"); // 如果权限不足，会打印 "setrlimit: Operation not permitted"
       }
       return 0;
   }
   ```

2. **设置无效的限制值:** 尝试将软限制设置为大于硬限制的值。这也会导致 `setrlimit` 调用失败，并返回 -1，`errno` 设置为 `EINVAL`。

   ```c++
   #include <sys/resource.h>
   #include <stdio.h>
   #include <errno.h>

   int main() {
       struct rlimit limit;
       getrlimit(RLIMIT_NOFILE, &limit);
       limit.rlim_cur = limit.rlim_max + 1; // 软限制大于硬限制
       if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
           perror("setrlimit"); // 打印 "setrlimit: Invalid argument"
       }
       return 0;
   }
   ```

3. **错误地理解软限制和硬限制:** 混淆软限制和硬限制的概念。软限制是内核尝试强制执行的限制，但进程可能会在短时间内超过它，而硬限制是内核强制执行的最终限制，无法超过。

4. **忽略 `setrlimit` 的返回值:** 没有检查 `setrlimit` 的返回值，导致即使设置失败也没有意识到。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework:**
   - Android Framework 中的某些系统服务 (如 `ActivityManagerService`) 可能需要设置或查询进程的资源限制。例如，`ActivityManagerService` 可能会设置新启动的应用程序的某些资源限制。
   - Framework 可以通过 JNI 调用到 Android Runtime (ART)，然后 ART 可以调用 Bionic 提供的 C 标准库函数。

   **路径示例:**
   - `ActivityManagerService.java` (Java 代码) -> JNI 调用 -> ART 的本地方法 -> Bionic 的 `setrlimit` 或 `prlimit`。

2. **NDK (Native Development Kit):**
   - 使用 NDK 开发的应用程序可以直接调用 Bionic 提供的 C 标准库函数，包括资源限制相关的函数。

   **路径示例:**
   - NDK 应用程序的 C/C++ 代码 -> 直接调用 `<sys/resource.h>` 中声明的函数 (`getrlimit`, `setrlimit`, `prlimit` 等)。

**Frida Hook 示例调试步骤**

假设我们想 hook `getrlimit` 函数来查看应用程序获取的 `RLIMIT_NOFILE` 的值。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const getrlimitPtr = Module.findExportByName("libc.so", "getrlimit");

  if (getrlimitPtr) {
    Interceptor.attach(getrlimitPtr, {
      onEnter: function (args) {
        const resource = args[0].toInt();
        const rlimitPtr = ptr(args[1]);

        if (resource === Process.constants.RLIMIT_NOFILE) {
          console.log("getrlimit called for RLIMIT_NOFILE");
        }
      },
      onLeave: function (retval) {
        if (this.lastResource === Process.constants.RLIMIT_NOFILE && retval.toInt() === 0) {
          const rlimit = Memory.readPtr(this.rlimitPtr);
          const rlim_cur = Memory.readU64(rlimit);
          const rlim_max = Memory.readU64(rlimit.add(Process.pointerSize));
          console.log(`  rlim_cur: ${rlim_cur}`);
          console.log(`  rlim_max: ${rlim_max}`);
        }
      }
    });
  } else {
    console.log("Could not find getrlimit in libc.so");
  }
} else {
  console.log("This script is designed for Android.");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 和 Frida Server。
2. **运行目标应用:** 启动你想要调试的 Android 应用程序。
3. **运行 Frida 脚本:** 使用 Frida 连接到目标应用程序并运行 hook 脚本。

   ```bash
   frida -U -f <your_package_name> -l your_script.js --no-pause
   ```

   将 `<your_package_name>` 替换为你的应用程序的包名，`your_script.js` 替换为上面的 Frida 脚本文件名。

4. **观察输出:** 当目标应用程序调用 `getrlimit` 获取 `RLIMIT_NOFILE` 时，Frida 脚本会在控制台上打印相关信息，包括当前的软限制和硬限制。

**注意:** 上面的 Frida 脚本是一个基本示例。根据你需要调试的具体场景，可能需要进行更复杂的 hook 和数据解析。你需要了解 `rlimit` 结构体在目标设备上的布局（32 位或 64 位），以便正确读取其成员。可以使用 `Process.pointerSize` 来处理 32 位和 64 位架构的区别。

希望以上详细的分析能够帮助你理解 `bionic/tests/sys_resource_test.cpp` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/sys_resource_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <sys/resource.h>

#include <gtest/gtest.h>

TEST(sys_resource, rlimit_struct_size) {
#if defined(__LP64__) || defined(__GLIBC__)
  ASSERT_EQ(sizeof(rlimit), sizeof(rlimit64));
  ASSERT_EQ(8U, sizeof(rlim_t));
#else
  ASSERT_NE(sizeof(rlimit), sizeof(rlimit64));
  ASSERT_EQ(4U, sizeof(rlim_t));
#endif
  ASSERT_EQ(8U, sizeof(rlim64_t));
}

class SysResourceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(0, getrlimit(RLIMIT_CORE, &l32_));
    ASSERT_EQ(0, getrlimit64(RLIMIT_CORE, &l64_));
    ASSERT_EQ(0, prlimit(0, RLIMIT_CORE, nullptr, &pr_l32_));
    ASSERT_EQ(0, prlimit64(0, RLIMIT_CORE, nullptr, &pr_l64_));
  }

  void CheckResourceLimits();

 protected:
  rlimit l32_;
  rlimit64 l64_;
  rlimit pr_l32_;
  rlimit64 pr_l64_;
};

void SysResourceTest::CheckResourceLimits() {
  ASSERT_EQ(0, getrlimit(RLIMIT_CORE, &l32_));
  ASSERT_EQ(0, getrlimit64(RLIMIT_CORE, &l64_));
  ASSERT_EQ(0, prlimit(0, RLIMIT_CORE, nullptr, &pr_l32_));
  ASSERT_EQ(0, prlimit64(0, RLIMIT_CORE, nullptr, &pr_l64_));

  ASSERT_EQ(l32_.rlim_cur, pr_l32_.rlim_cur);
  ASSERT_EQ(l64_.rlim_cur, pr_l64_.rlim_cur);

  if (l64_.rlim_cur == RLIM64_INFINITY) {
    ASSERT_EQ(RLIM_INFINITY, l32_.rlim_cur);
  } else {
    ASSERT_EQ(l64_.rlim_cur, l32_.rlim_cur);
  }

  ASSERT_EQ(l32_.rlim_max, pr_l32_.rlim_max);
  ASSERT_EQ(l64_.rlim_max, pr_l64_.rlim_max);

  if (l64_.rlim_max == RLIM64_INFINITY) {
    ASSERT_EQ(RLIM_INFINITY, l32_.rlim_max);
  } else {
    ASSERT_EQ(l64_.rlim_max, l32_.rlim_max);
  }
}

// Force rlim_max to be bigger than a constant so we can continue following test.
// Change resource limit setting with "ulimit -Hc" in the shell if this test fails.
TEST_F(SysResourceTest, RLIMIT_CORE_rlim_max_not_zero) {
  ASSERT_TRUE(l32_.rlim_max == RLIM_INFINITY || l32_.rlim_max >= 456U) <<
    "RLIMIT_CORE rlim_max = " << l32_.rlim_max;
}

TEST_F(SysResourceTest, get_resource_limit_equal) {
  CheckResourceLimits();
}

TEST_F(SysResourceTest, setrlimit) {
  l32_.rlim_cur = 123U;
  ASSERT_EQ(0, setrlimit(RLIMIT_CORE, &l32_));
  CheckResourceLimits();
  ASSERT_EQ(123U, l32_.rlim_cur);
}

TEST_F(SysResourceTest, setrlimit64_smoke) {
  l64_.rlim_cur = 456U;
  ASSERT_EQ(0, setrlimit64(RLIMIT_CORE, &l64_));
  CheckResourceLimits();
  ASSERT_EQ(456U, l64_.rlim_cur);
}

TEST_F(SysResourceTest, prlimit) {
  pr_l32_.rlim_cur = pr_l32_.rlim_max;
  ASSERT_EQ(0, prlimit(0, RLIMIT_CORE, &pr_l32_, nullptr));
  CheckResourceLimits();
  ASSERT_EQ(pr_l32_.rlim_max, pr_l32_.rlim_cur);
}

TEST_F(SysResourceTest, prlimit64_smoke) {
  pr_l64_.rlim_cur = pr_l64_.rlim_max;
  ASSERT_EQ(0, prlimit64(0, RLIMIT_CORE, &pr_l64_, nullptr));
  CheckResourceLimits();
  ASSERT_EQ(pr_l64_.rlim_max, pr_l64_.rlim_cur);
}

"""

```