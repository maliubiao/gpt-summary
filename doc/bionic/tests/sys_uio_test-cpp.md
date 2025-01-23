Response:
Let's break down the thought process for answering the request about `bionic/tests/sys_uio_test.cpp`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of a C++ test file within Android's Bionic library. Key elements to address are:

* **Functionality:** What does the code *do*?
* **Android Relevance:** How does it relate to the broader Android system?
* **Libc Function Implementation:** How are the standard C library functions being tested implemented (at a high level)?
* **Dynamic Linker:** Are any dynamic linking aspects relevant?
* **Logic and I/O:** Can we deduce input/output behavior?
* **Common Errors:** What mistakes might developers make using these functions?
* **Android Framework/NDK Integration:** How does code execution reach this point?
* **Frida Hooking:** How can we inspect this code in action?

**2. Initial Code Scan and Identification of Key Functions:**

The first step is to quickly scan the code and identify the core functions being tested. The test names and the included headers (`<sys/uio.h>`) immediately point to the focus:

* `readv` and `writev`: Vectorized I/O on file descriptors.
* `preadv`, `pwritev`, `preadv64`, `pwritev64`:  Vectorized I/O with explicit file offsets.
* `preadv2`, `pwritev2`, `preadv64v2`, `pwritev64v2`:  Vectorized I/O with explicit file offsets and flags.
* `process_vm_readv`, `process_vm_writev`:  Inter-process memory access.

**3. Analyzing Each Test Case:**

For each `TEST` block, we need to understand its purpose:

* **`readv_writev`:**  Tests basic reading and writing of multiple buffers to a file. It verifies that data is written contiguously and read back correctly.
* **`TestPreadVPwriteV` (and its specializations):** Focuses on the "p" versions of the functions, demonstrating that they operate at a specific offset *without* changing the file's current position (unlike `lseek` followed by `read` or `write`).
* **`TestPreadV2PwriteV2` (and its specializations):**  Highlights the extended versions (`v2`) that likely introduce additional flags for control. The `#if defined(__BIONIC__)` suggests these are Bionic-specific or newer features.
* **`process_vm_readv` and `process_vm_writev`:** Demonstrates reading and writing memory *between* processes, a more advanced capability. The tests include error handling scenarios (reading from/writing to invalid memory).

**4. Connecting to Android:**

Think about where these functions might be used in Android. Consider:

* **File I/O:**  Apps need to read and write files. Vectorized I/O can be more efficient for handling multiple data chunks.
* **Inter-Process Communication (IPC):** Android relies heavily on IPC (e.g., between apps and system services). `process_vm_readv`/`process_vm_writev` are clearly related to this.
* **System Services:**  Lower-level system services within Android might directly use these functions.

**5. Explaining Libc Function Implementation (High Level):**

We don't have the *actual* Bionic source code for these functions within this test file. The explanation needs to be at a conceptual level:

* **System Calls:** Emphasize that these libc functions are wrappers around system calls (kernel-level operations).
* **Kernel Interaction:**  Describe how the kernel manages file descriptors, memory, and inter-process communication.
* **`iovec` Structure:** Explain the purpose of this structure in defining memory regions for I/O.

**6. Considering the Dynamic Linker:**

While this specific test file doesn't *directly* test the dynamic linker, the functions it uses *are* part of Bionic, which includes the dynamic linker. Therefore:

* **Shared Libraries:**  Explain that libc (and thus these functions) are in shared libraries (`.so` files).
* **Linking Process:** Briefly describe how the dynamic linker resolves symbols and loads libraries when a program starts. A simple `.so` layout example is helpful.

**7. Deducing Logic and I/O:**

For each test case, outline the expected input (data in the buffers, file content) and the anticipated output (return values, modified buffer contents, file content). This demonstrates an understanding of the test's purpose.

**8. Identifying Common Errors:**

Think about common mistakes developers might make when using these functions:

* **Incorrect Buffer Sizes:** Passing wrong sizes in `iovec`.
* **Invalid File Descriptors:** Using closed or incorrect FDs.
* **Incorrect Offsets:**  For `p...` functions, providing wrong offsets.
* **Memory Access Errors:** For `process_vm...`, trying to access unmapped memory.
* **Permissions:**  Not having the necessary permissions for inter-process memory access.

**9. Tracing Android Framework/NDK to the Test:**

This requires a general understanding of the Android software stack:

* **Application Layer:**  NDK usage in apps.
* **Framework Layer:** How the framework might use these functions indirectly (though less likely directly).
* **Native Layer (Bionic):**  Where these functions reside.
* **System Calls:** The ultimate entry point into the kernel.

**10. Providing Frida Hook Examples:**

Demonstrate how to use Frida to intercept and inspect these function calls. This involves:

* **Identifying the Function:** Knowing the function name.
* **Basic Hook Structure:**  Using `Interceptor.attach`.
* **Accessing Arguments:** Showing how to get the values of parameters.
* **Modifying Behavior (Optional):** Briefly mentioning the possibility of changing return values or arguments.

**11. Structuring the Response:**

Organize the information logically, using headings and bullet points for clarity. Start with a general overview, then delve into specifics for each function and concept.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Focus too much on the *internal* implementation of the libc functions.
* **Correction:** Shift focus to the *interface* and the *system call* level, as the test file doesn't reveal the internal implementation.
* **Initial thought:** Overlook the dynamic linker aspect.
* **Correction:** Include a brief explanation of how these functions exist within shared libraries and the linker's role.
* **Initial thought:**  Not provide concrete Frida examples.
* **Correction:**  Add specific Frida code snippets to make the explanation more practical.

By following this structured approach, considering the different facets of the request, and refining the thinking process, a comprehensive and accurate answer can be generated.
好的，我们来详细分析一下 `bionic/tests/sys_uio_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/sys_uio_test.cpp` 是 Android Bionic 库中用于测试与 `sys/uio.h` 头文件中定义的系统调用相关的测试文件。这些系统调用主要用于执行 **分散/聚集 I/O (Scatter/Gather I/O)** 操作，允许在单个系统调用中读写多个不连续的内存缓冲区。

具体来说，这个测试文件主要测试了以下功能：

* **`readv` 和 `writev`:**  从/向文件描述符读取/写入多个缓冲区。
* **`preadv` 和 `pwritev`:** 在指定偏移量处从/向文件描述符读取/写入多个缓冲区，但不改变文件偏移量。
* **`preadv64` 和 `pwritev64`:**  与 `preadv` 和 `pwritev` 功能相同，但使用 64 位的文件偏移量，允许操作更大的文件。
* **`preadv2` 和 `pwritev2`:**  扩展的 `preadv` 和 `pwritev`，允许传递附加标志 (flags) 来控制 I/O 操作。
* **`preadv64v2` 和 `pwritev64v2`:** 扩展的 `preadv64` 和 `pwritev64`，同样允许传递附加标志。
* **`process_vm_readv`:** 从指定进程的内存空间读取数据到当前进程的多个缓冲区。
* **`process_vm_writev`:** 将当前进程的多个缓冲区中的数据写入到指定进程的内存空间。

**与 Android 功能的关系及举例说明**

这些系统调用在 Android 系统中扮演着重要的角色，特别是在需要高效处理多个数据块的场景中。

* **文件 I/O 优化:**  Android 应用和系统服务经常需要读写文件。使用 `readv` 和 `writev` 可以减少系统调用的次数，从而提高 I/O 效率。例如，在处理网络数据包时，可能需要将包头和包体分别存储在不同的缓冲区中，然后一次性写入文件。

* **IPC (进程间通信):**  `process_vm_readv` 和 `process_vm_writev` 提供了进程间直接读写内存的能力。这对于一些高性能的 IPC 场景非常有用，例如调试器（如 `gdb`）读取目标进程的内存，或者一些共享内存的实现。

* **Binder 机制 (间接关系):** 虽然 Binder 通信不直接使用这些 uio 函数，但 Binder 底层的数据传输可能涉及到类似的分散/聚集操作的概念，以高效地处理不同大小和位置的数据块。

**libc 函数的功能实现**

这些函数都是 C 标准库 (libc) 提供的接口，它们是对底层操作系统系统调用的封装。

* **`readv(int fd, const struct iovec *iov, int iovcnt)`:**
    * **功能:** 从文件描述符 `fd` 读取数据到 `iov` 指向的 `iovcnt` 个缓冲区中。`iov` 是一个 `iovec` 结构体数组，每个结构体包含一个缓冲区的起始地址和长度。数据会按照缓冲区在 `iov` 数组中的顺序依次填充。
    * **实现:**  `readv` 函数最终会调用底层的 `readv` 系统调用。内核接收到这个系统调用后，会根据 `iov` 数组中的描述，从文件描述符指向的文件或管道中读取相应数量的数据，并将其复制到各个指定的缓冲区中。系统调用返回实际读取的字节数，如果发生错误则返回 -1 并设置 `errno`。

* **`writev(int fd, const struct iovec *iov, int iovcnt)`:**
    * **功能:** 将 `iov` 指向的 `iovcnt` 个缓冲区中的数据写入到文件描述符 `fd` 中。数据会按照缓冲区在 `iov` 数组中的顺序依次写入。
    * **实现:** `writev` 函数最终会调用底层的 `writev` 系统调用。内核接收到这个系统调用后，会根据 `iov` 数组中的描述，将各个指定缓冲区中的数据依次写入到文件描述符指向的文件或管道中。系统调用返回实际写入的字节数，如果发生错误则返回 -1 并设置 `errno`。

* **`preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)` 和 `pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)`:**
    * **功能:**  与 `readv` 和 `writev` 类似，但增加了 `offset` 参数，用于指定读取或写入操作的文件偏移量。重要的是，这些函数在操作完成后，不会改变文件描述符当前的偏移量。
    * **实现:**  这两个函数最终会调用底层的 `preadv` 和 `pwritev` 系统调用。内核在执行读写操作时，会使用指定的 `offset`，但不会更新文件描述符内部的偏移量计数器。

* **`preadv64`, `pwritev64`, `preadv2`, `pwritev2`, `preadv64v2`, `pwritev64v2`:**
    * **功能:** 这些是 `preadv` 和 `pwritev` 的扩展版本。`preadv64` 和 `pwritev64` 使用 `off64_t` 类型的 64 位偏移量。 `preadv2` 和 `pwritev2` 以及它们的 64 位版本，还引入了一个 `flags` 参数，允许传递一些控制 I/O 行为的标志，例如 `RWF_HIPRI` (高优先级 I/O)。
    * **实现:** 它们会调用相应的底层系统调用，例如 `preadv64`, `pwritev64`, `preadv2`, `pwritev2` 等。

* **`process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)`:**
    * **功能:** 从进程 ID 为 `pid` 的进程的内存空间中，读取 `riovcnt` 个由 `remote_iov` 描述的缓冲区的数据，并将其写入到当前进程的 `liovcnt` 个由 `local_iov` 描述的缓冲区中。`flags` 参数用于指定一些操作标志。
    * **实现:**  这个函数会调用底层的 `process_vm_readv` 系统调用。内核需要进行权限检查，确保当前进程有权限读取目标进程的内存。然后，内核会根据 `remote_iov` 和 `local_iov` 的描述，在两个进程的地址空间之间复制数据。

* **`process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)`:**
    * **功能:** 将当前进程的 `liovcnt` 个由 `local_iov` 描述的缓冲区的数据，写入到进程 ID 为 `pid` 的进程的内存空间中，写入的目标缓冲区由 `remote_iov` 描述。
    * **实现:** 这个函数会调用底层的 `process_vm_writev` 系统调用。同样需要权限检查。内核会根据 `local_iov` 和 `remote_iov` 的描述，将数据从当前进程复制到目标进程的地址空间。

**涉及 dynamic linker 的功能**

`sys_uio_test.cpp` 本身并不直接测试 dynamic linker 的功能。但是，它使用的 libc 函数（如 `readv`, `writev` 等）是由 dynamic linker 在程序启动时加载到进程地址空间的共享库提供的。

**so 布局样本:**

假设一个简单的 Android 应用使用了这些 uio 函数，其进程的内存布局可能包含以下部分：

```
[进程地址空间]
---------------------
|     ...           |
|  可执行文件段     |  (例如 app_process)
|     ...           |
---------------------
|  libc.so 段       |  (包含 readv, writev 等函数的实现)
|     .text         |  (代码段)
|     .data         |  (已初始化数据段)
|     .bss          |  (未初始化数据段)
|     ...           |
---------------------
|  其他 .so 文件段  |  (例如 libandroid.so, libm.so 等)
|     ...           |
---------------------
|      栈            |
---------------------
|      堆            |
---------------------
|  mmap 区域       |
---------------------
```

**链接的处理过程:**

1. **编译时链接:** 当你编译包含这些 uio 函数调用的代码时，编译器会生成对这些函数的未解析符号引用。

2. **打包成 APK:**  编译后的代码会被打包到 APK 文件中。

3. **加载时链接 (Dynamic Linking):** 当 Android 系统启动应用进程时，`app_process` 进程（或者其变体）会负责加载应用的 native 代码。dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会被调用来执行以下操作：
   * **加载依赖库:**  dynamic linker 会读取可执行文件的头部信息，找到其依赖的共享库列表（例如 `libc.so`）。
   * **加载 libc.so:** dynamic linker 会将 `libc.so` 加载到进程的地址空间中，并将其各个段（代码段、数据段等）映射到内存中。
   * **符号解析:** dynamic linker 会遍历可执行文件中的未解析符号引用，并在已加载的共享库中查找对应的符号定义（例如 `readv` 函数的实现）。
   * **重定位:**  dynamic linker 会修改可执行文件和共享库中的代码和数据，以确保函数调用和数据访问指向正确的内存地址。例如，将对 `readv` 的调用指令修改为指向 `libc.so` 中 `readv` 函数的实际地址。

**逻辑推理、假设输入与输出**

以 `TEST(sys_uio, readv_writev)` 为例：

* **假设输入:**
    * 创建一个临时文件 `tf`。
    * 定义两个字符串缓冲区 `buf1 = "hello"` 和 `buf2 = "world"`。
    * 创建一个 `iovec` 数组 `ios`，包含指向 `buf1` 和 `buf2` 的指针和长度。
* **执行过程:**
    * `writev(tf.fd, ios, 2)` 将 "hello" 和 "world" 写入到临时文件中。预计写入 10 个字节。
    * `lseek(tf.fd, 0, SEEK_SET)` 将文件偏移量设置回文件开头。
    * `readv(tf.fd, ios, 2)` 从临时文件中读取数据到 `buf1` 和 `buf2` 中。预计读取 10 个字节。
* **预期输出:**
    * `writev` 返回 10。
    * `readv` 返回 10。
    * `buf1` 的内容变为 "hello"。
    * `buf2` 的内容变为 "world"。

**用户或编程常见的使用错误**

* **`iovec` 结构体配置错误:**
    * `iov_base` 指针指向无效的内存地址。
    * `iov_len` 设置的长度超过了缓冲区实际的大小，导致越界读写。
    * `iovcnt` 与 `iovec` 数组的实际大小不符。
* **文件描述符无效:**  使用已关闭或未打开的文件描述符。
* **偏移量错误 (对于 `preadv`/`pwritev`):**  指定的偏移量超出文件大小，或者为负数。
* **权限问题 (对于 `process_vm_readv`/`process_vm_writev`):**  尝试读写没有权限访问的进程的内存，会导致 `EPERM` 错误。
* **内存映射问题 (对于 `process_vm_readv`/`process_vm_writev`):**  尝试读写目标进程未映射的内存地址，会导致 `EFAULT` 错误。

**示例:**

```c++
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int main() {
    char buf1[10];
    char buf2[10];
    iovec iov[2];
    int fd;

    // 错误示例 1: iov_len 设置过大
    iov[0].iov_base = buf1;
    iov[0].iov_len = sizeof(buf1) * 2; // 错误！

    // 错误示例 2: 使用无效的文件描述符
    ssize_t nread = readv(-1, iov, 1);
    if (nread == -1) {
        perror("readv"); // 输出 "readv: Bad file descriptor"
    }

    // 错误示例 3: process_vm_readv 权限不足
    char remote_buf[10];
    char local_buf[10];
    iovec local_iov = {local_buf, sizeof(local_buf)};
    iovec remote_iov = {remote_buf, sizeof(remote_buf)};
    pid_t other_pid = 1; // 假设尝试读取 init 进程的内存
    ssize_t result = process_vm_readv(other_pid, &local_iov, 1, &remote_iov, 1, 0);
    if (result == -1) {
        perror("process_vm_readv"); // 很可能输出 "process_vm_readv: Operation not permitted"
    }

    return 0;
}
```

**Android Framework or NDK 如何到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK 开发:** 开发者使用 NDK (Native Development Kit) 编写 C/C++ 代码。

2. **调用 uio 函数:**  NDK 代码中直接调用了 `readv`, `writev`, `process_vm_readv` 等函数。

3. **编译链接:** NDK 构建系统会将 C/C++ 代码编译成共享库 (`.so`) 文件，这些调用会链接到 Bionic 提供的 libc.so。

4. **Framework 调用 (间接):** Android Framework 层的 Java 代码，在某些情况下可能会通过 JNI (Java Native Interface) 调用 NDK 编写的 native 代码，从而间接触发对这些 uio 函数的调用. 例如，Framework 层处理文件 I/O 或进程间通信时，底层的 native 代码可能会使用这些函数。

5. **系统服务:**  一些 Android 系统服务，例如 `SurfaceFlinger` (负责屏幕合成) 或者网络相关的服务，可能会直接使用这些 uio 函数进行高效的数据处理。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `writev` 函数的简单示例：

```javascript
// hook_writev.js
if (Process.platform === 'linux') {
  const writevPtr = Module.findExportByName("libc.so", "writev");

  if (writevPtr) {
    Interceptor.attach(writevPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const iov = ptr(args[1]);
        const iovcnt = args[2].toInt32();

        console.log("writev called!");
        console.log("  File Descriptor:", fd);
        console.log("  iovec count:", iovcnt);

        for (let i = 0; i < iovcnt; i++) {
          const current_iov = iov.add(i * Process.pointerSize * 2); // 假设 pointerSize 是指针大小
          const base = current_iov.readPointer();
          const len = current_iov.add(Process.pointerSize).readInt();
          console.log(`  Buffer ${i + 1}:`);
          console.log(`    Base: ${base}`);
          console.log(`    Length: ${len}`);
          if (len > 0) {
            try {
              console.log(`    Content: ${base.readUtf8String(len)}`);
            } catch (e) {
              console.log(`    Content: <Unable to read>`);
            }
          }
        }
      },
      onLeave: function (retval) {
        console.log("writev returned:", retval.toInt32());
      }
    });
    console.log("writev hooked!");
  } else {
    console.error("writev function not found in libc.so");
  }
} else {
  console.log("This script is designed for Linux (Android) platforms.");
}
```

**使用方法:**

1. 将上述代码保存为 `hook_writev.js`。
2. 找到你想要 hook 的 Android 进程的进程 ID (PID)。
3. 使用 Frida 命令运行 hook 脚本：
   ```bash
   frida -U -f <package_name> -l hook_writev.js
   # 或者如果进程已经在运行
   frida -U <package_name> -l hook_writev.js
   # 或者指定 PID
   frida -U -p <PID> -l hook_writev.js
   ```

当目标进程调用 `writev` 函数时，Frida 会拦截调用，并打印出文件描述符、`iovec` 数组的信息（包括缓冲区地址、长度和内容）以及函数的返回值。

你可以类似地 hook 其他的 uio 函数，例如 `readv` 或 `process_vm_readv`，来观察它们的行为和参数。对于 `process_vm_readv` 和 `process_vm_writev`，你需要注意权限问题，通常需要在 root 权限下运行 Frida 才能成功 hook 系统进程。

希望以上详细的解释能够帮助你理解 `bionic/tests/sys_uio_test.cpp` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/sys_uio_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <android-base/file.h>

#include "utils.h"

TEST(sys_uio, readv_writev) {
  TemporaryFile tf;

  char buf1[] = "hello";
  char buf2[] = "world";
  iovec ios[] = { { buf1, 5 }, { buf2, 5 } };

  ASSERT_EQ(10, writev(tf.fd, ios, 2));

  ASSERT_EQ(0, lseek(tf.fd, 0, SEEK_SET));

  memset(buf1, '1', sizeof(buf1));
  memset(buf2, '2', sizeof(buf2));

  ASSERT_EQ(10, readv(tf.fd, ios, 2));
  buf1[5] = buf2[5] = '\0';
  ASSERT_STREQ("hello", buf1);
  ASSERT_STREQ("world", buf2);
}

template <typename ReadFn, typename WriteFn>
void TestPreadVPwriteV(ReadFn read_fn, WriteFn write_fn) {
  TemporaryFile tf;

  char buf[] = "world";
  iovec ios[] = { { buf, 5 } };

  ASSERT_EQ(5, write_fn(tf.fd, ios, 1, 5));
  ASSERT_EQ(0, lseek(tf.fd, 0, SEEK_CUR));

  strcpy(buf, "hello");
  ASSERT_EQ(5, write_fn(tf.fd, ios, 1, 0));
  ASSERT_EQ(0, lseek(tf.fd, 0, SEEK_CUR));

  ASSERT_EQ(5, read_fn(tf.fd, ios, 1, 5));
  ASSERT_STREQ("world", buf);
  ASSERT_EQ(5, read_fn(tf.fd, ios, 1, 0));
  ASSERT_STREQ("hello", buf);
}

TEST(sys_uio, preadv_pwritev) {
  TestPreadVPwriteV(preadv, pwritev);
}

TEST(sys_uio, preadv64_pwritev64) {
  TestPreadVPwriteV(preadv64, pwritev64);
}

template <typename ReadFn, typename WriteFn>
void TestPreadV2PwriteV2(ReadFn read_fn, WriteFn write_fn) {
  TemporaryFile tf;

  char buf[] = "world";
  iovec ios[] = {{buf, 5}};

  ASSERT_EQ(5, write_fn(tf.fd, ios, 1, 5, 0)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, 0, SEEK_CUR));

  strcpy(buf, "hello");
  ASSERT_EQ(5, write_fn(tf.fd, ios, 1, 0, 0)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, 0, SEEK_CUR));

  ASSERT_EQ(5, read_fn(tf.fd, ios, 1, 5, 0)) << strerror(errno);
  ASSERT_STREQ("world", buf);
  ASSERT_EQ(5, read_fn(tf.fd, ios, 1, 0, 0)) << strerror(errno);
  ASSERT_STREQ("hello", buf);
}

TEST(sys_uio, preadv2_pwritev2) {
#if defined(__BIONIC__)
  TestPreadV2PwriteV2(preadv2, pwritev2);
#else
  GTEST_SKIP() << "preadv2/pwritev2 not available";
#endif
}

TEST(sys_uio, preadv64v2_pwritev64v2) {
#if defined(__BIONIC__)
  TestPreadV2PwriteV2(preadv64v2, pwritev64v2);
#else
  GTEST_SKIP() << "preadv2/pwritev2 not available";
#endif
}

TEST(sys_uio, process_vm_readv) {
  ASSERT_EQ(0, process_vm_readv(0, nullptr, 0, nullptr, 0, 0));

  // Test that we can read memory from our own process
  char src[1024] = "This is the source buffer containing some data";
  char dst[1024] = "";
  iovec remote = { src, sizeof src };
  iovec local = { dst, sizeof dst };
  ASSERT_EQ(ssize_t(sizeof src), process_vm_readv(getpid(), &local, 1, &remote, 1, 0));
  // Check whether data was copied (in the correct direction)
  ASSERT_EQ('T', dst[0]);
  ASSERT_EQ(0, memcmp(src, dst, sizeof src));

  // Reading from non-allocated memory should return an error
  remote = { nullptr, sizeof dst };
  errno = 0;
  ASSERT_EQ(-1, process_vm_readv(getpid(), &local, 1, &remote, 1, 0));
  ASSERT_ERRNO(EFAULT);
}

TEST(sys_uio, process_vm_writev) {
  ASSERT_EQ(0, process_vm_writev(0, nullptr, 0, nullptr, 0, 0));

  // Test that we can read memory from our own process
  char src[1024] = "This is the source buffer containing some data";
  char dst[1024] = "";
  iovec remote = { dst, sizeof dst };
  iovec local = { src, sizeof src };
  ASSERT_EQ(ssize_t(sizeof src), process_vm_writev(getpid(), &local, 1, &remote, 1, 0));
  // Check whether data was copied (in the correct direction)
  ASSERT_EQ('T', dst[0]);
  ASSERT_EQ(0, memcmp(src, dst, sizeof src));

  // Writing to non-allocated memory should return an error
  remote = { nullptr, sizeof dst };
  errno = 0;
  ASSERT_EQ(-1, process_vm_writev(getpid(), &local, 1, &remote, 1, 0));
  ASSERT_ERRNO(EFAULT);
}
```