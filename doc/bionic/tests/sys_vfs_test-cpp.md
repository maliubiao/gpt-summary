Response:
Let's break down the thought process for answering the prompt about `bionic/tests/sys_vfs_test.cpp`.

**1. Understanding the Core Task:**

The primary goal is to analyze a C++ test file within the Android bionic library and explain its purpose, related functions, potential issues, and how it fits into the Android ecosystem. The prompt explicitly asks for explanations of libc functions, dynamic linking aspects, usage errors, and debugging techniques.

**2. Initial Examination of the Code:**

The first step is to quickly read through the code. Key observations:

* **Includes:**  `<gtest/gtest.h>`, `<sys/vfs.h>`, `<sys/types.h>`, `<sys/stat.h>`, `<fcntl.h>`, `<string>`, `"utils.h"`. This tells us it's a unit test using Google Test, and it's testing functionalities related to filesystem information (`sys/vfs.h`).
* **Test Structure:**  The code uses `TEST()` macros, indicating Google Test unit tests. The tests are named `statfs`, `statfs_failure`, `statfs64_smoke`, `statfs64_failure`, `fstatfs`, `fstatfs_failure`, `fstatfs64_smoke`, `fstatfs64_failure`. This suggests it's testing both `statfs` and `statfs64` system calls, and also testing both success and failure scenarios. The "smoke" suffix often implies a basic functionality check.
* **Core Logic:** The `Check()` template function is central. It performs assertions on the values within the `statfs` or `statfs64` structures. This is where the actual verification of the system call's behavior happens.
* **System Calls:** The tests directly call `statfs`, `statfs64`, and `fstatfs`, `fstatfs64`. These are the core libc functions being tested.
* **File Descriptors:** The `fstatfs` tests use `open()` and `close()`, indicating they're testing the file descriptor-based versions of the `statfs` calls.
* **Error Handling:** The `_failure` tests check for specific `errno` values (like `ENOENT` and `EBADF`).

**3. Answering the Prompt -  Section by Section:**

Now, address each point of the prompt systematically:

* **功能列举:**  This is straightforward. List the tested functionalities based on the test names and the system calls involved.
* **与 Android 功能的关系:** Connect the tested system calls (`statfs`, `fstatfs`) to their broader purpose in Android – providing filesystem information, crucial for apps, system services, package management, etc. Provide concrete examples like disk space checks or application installation.
* **libc 函数的实现:** This requires knowledge of how `statfs` and `fstatfs` work. Explain the high-level steps: transitioning to the kernel, the kernel retrieving filesystem metadata, and passing it back to the user space. Emphasize the role of the VFS layer in the kernel. Mention the difference between `statfs` (path-based) and `fstatfs` (file descriptor-based).
* **dynamic linker 功能:** Although the test file *itself* doesn't directly exercise dynamic linking, the *libc functions* it calls are part of the dynamically linked libc. Therefore, it's relevant to explain:
    * **SO 布局:**  Describe the structure of a shared object (`.so`) file, including `.text`, `.data`, `.bss`, `.plt`, `.got`.
    * **链接过程:** Explain symbol resolution (local and global), the role of the GOT and PLT, and lazy binding.
* **逻辑推理 (假设输入与输出):** Focus on the `Check()` function. Assume a successful call to `statfs("/proc", &sb)`. Explain what values are expected in `sb` based on the assertions in `Check()`, specifically `f_bsize`, `f_bfree`, `f_ffree`, `f_namelen`, and `f_fsid`. Also, explain the x86_64 specific logic.
* **用户或编程常见的使用错误:**  Think about common mistakes when using `statfs` and `fstatfs`:
    * Incorrect pathnames or file descriptors.
    * Not checking the return value.
    * Assuming specific values in the `statfs` structure without understanding their meaning.
* **Android Framework/NDK 到达这里:** Trace the path:
    * An app or framework component makes a high-level request (e.g., checking disk space).
    * This often translates to a system call.
    * The NDK provides wrappers for these system calls.
    * The libc implementation of `statfs` is invoked.
    * This makes the actual kernel system call.
* **Frida Hook 示例:**  Provide concrete Frida code to intercept `statfs` and log arguments and the return value. This demonstrates a debugging technique.

**4. Refining and Structuring the Answer:**

Organize the answer clearly, using headings and bullet points. Ensure the language is precise and easy to understand. Provide sufficient detail for each point, but avoid unnecessary jargon. Double-check that all aspects of the prompt have been addressed.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus only on what the test file directly does.
* **Correction:** Realize that the test file is testing *libc functions*, so explaining those functions' implementation and their broader context within Android is crucial.
* **Initial thought:**  Dynamic linking is not directly *in* the test file.
* **Correction:**  The *functions being tested* are part of the dynamically linked libc. Therefore, explaining the dynamic linking process for those functions is important.
* **Initial thought:** Just describe the Frida code.
* **Correction:** Explain *why* Frida is useful in this context and how it helps in understanding the system call flow.

By following this structured approach, including initial examination, systematic answering, and refinement, a comprehensive and accurate response to the prompt can be generated.
好的，让我们来详细分析一下 `bionic/tests/sys_vfs_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/sys_vfs_test.cpp` 是 Android Bionic 库中的一个单元测试文件。它的主要功能是测试与虚拟文件系统 (Virtual File System, VFS) 相关的系统调用，特别是 `statfs` 和 `fstatfs` 及其 64 位版本 `statfs64` 和 `fstatfs64`。

简单来说，这个测试文件验证了 Bionic 库中对这些 VFS 相关系统调用的封装是否正确，以及它们在不同情况下的行为是否符合预期，例如成功执行和失败时的错误处理。

**与 Android 功能的关系及举例说明**

VFS 相关的系统调用在 Android 系统中扮演着至关重要的角色，它们被用于获取文件系统的各种信息，例如：

* **磁盘空间管理:**  `statfs` 可以用来查询文件系统的总空间、可用空间、剩余空间等信息，这对于系统监控磁盘使用情况、应用判断是否有足够的空间存储数据非常重要。例如，Android 的设置应用会使用这些信息来显示存储空间的使用情况。
* **应用安装和卸载:** 当安装或卸载应用时，系统需要知道文件系统的状态来分配或回收空间。`statfs` 可以帮助确定是否有足够的空间进行安装。
* **文件系统类型识别:**  虽然测试代码中没有直接体现，但 `statfs` 返回的结构体中包含文件系统 ID 等信息，可以用于识别文件系统的类型。
* **权限管理:**  虽然主要由 `stat` 系列函数负责，但 `statfs` 提供的某些信息也可能间接地用于权限相关的判断。

**举例说明：**

假设一个 Android 应用需要下载一个 100MB 的文件。在下载之前，它可以使用 `statfs` 来检查 `/sdcard` 分区是否有足够的可用空间：

```c++
#include <sys/vfs.h>
#include <stdio.h>
#include <errno.h>

int main() {
  struct statfs sb;
  if (statfs("/sdcard", &sb) == 0) {
    long long available_space = (long long)sb.f_bavail * sb.f_frsize;
    printf("可用空间: %lld 字节\n", available_space);
    if (available_space >= 100 * 1024 * 1024) {
      printf("有足够的空间下载文件。\n");
      // 进行下载操作
    } else {
      printf("空间不足，无法下载文件。\n");
    }
  } else {
    perror("statfs 失败");
    return 1;
  }
  return 0;
}
```

这个例子展示了 `statfs` 如何被用于实际的 Android 功能中，帮助应用做出决策。

**libc 函数的实现**

让我们详细解释一下 `statfs` 和 `fstatfs` 的实现原理：

1. **`statfs(const char *path, struct statfs *buf)`:**
   - **系统调用入口:** `statfs` 是一个库函数，它的实现最终会调用内核提供的系统调用。在 Linux 内核中，对应的系统调用通常是 `sys_statfs`。
   - **路径解析:**  内核首先会根据传入的 `path` 参数解析出对应的 inode (索引节点)。Inode 是文件系统内部用于标识文件或目录的唯一标识符。
   - **权限检查:** 内核会检查当前进程是否有权限访问指定的路径。
   - **VFS 操作:** 内核的 VFS 层会根据 inode 找到对应的文件系统驱动。
   - **文件系统驱动调用:**  VFS 层会调用具体文件系统驱动提供的操作来获取文件系统的统计信息。不同的文件系统 (如 ext4, FAT32 等) 获取这些信息的方式可能不同。
   - **数据填充:** 文件系统驱动将获取到的信息填充到 `struct statfs` 结构体中，包括：
     - `f_type`: 文件系统类型 ID。
     - `f_bsize`: 文件系统块大小。
     - `f_frsize`: 分片大小 (可能小于块大小)。
     - `f_blocks`: 文件系统中块的总数。
     - `f_bfree`: 文件系统中空闲块的数量。
     - `f_bavail`: 可供非特权用户使用的空闲块数量。
     - `f_files`: 文件节点 (inode) 的总数。
     - `f_ffree`: 空闲文件节点 (inode) 的数量。
     - `f_fsid`: 文件系统 ID。
     - `f_namelen`: 文件名的最大长度。
     - `f_flags`: 文件系统的挂载标志。
     - `f_spare`:  保留字段。
   - **数据返回:** 内核将填充好的 `struct statfs` 结构体数据复制到用户空间的 `buf` 指向的内存。
   - **返回值:** 成功时返回 0，失败时返回 -1 并设置 `errno`。

2. **`fstatfs(int fd, struct statfs *buf)`:**
   - **系统调用入口:**  类似于 `statfs`，`fstatfs` 也会调用内核的系统调用，通常是 `sys_fstatfs`。
   - **文件描述符验证:** 内核首先会验证传入的文件描述符 `fd` 的有效性，确保它指向一个打开的文件或目录。
   - **获取 inode:**  内核通过文件描述符 `fd` 找到对应的 inode。
   - **后续步骤:**  后续的权限检查、VFS 操作、文件系统驱动调用和数据填充过程与 `statfs` 基本一致。
   - **返回值:** 成功时返回 0，失败时返回 -1 并设置 `errno`。

**`statfs64` 和 `fstatfs64`:**  这两个函数是 `statfs` 和 `fstatfs` 的 64 位版本。它们的主要区别在于 `struct statfs64` 结构体中的某些字段使用了 64 位整数，以支持更大的文件系统和更大的文件大小。其实现原理与 32 位版本类似，只是在数据类型处理上有所不同。

**涉及 dynamic linker 的功能**

虽然 `sys_vfs_test.cpp` 这个测试文件本身没有直接涉及动态链接器的功能，但它测试的 `statfs` 和 `fstatfs` 函数是 Bionic libc 库的一部分，而 libc 本身就是一个共享库，需要通过动态链接器加载到进程的地址空间中。

**SO 布局样本：**

假设 `libc.so` 是 Bionic 的 C 库文件，它的布局大致如下：

```
LOAD           0x...7f00000000  0x...7f00000000  r-x ...
LOAD           0x...7f00001000  0x...7f00001000  r-- ...
LOAD           0x...7f00002000  0x...7f00002000  rw- ...

.text          0x...7f00000000  # 存放代码段，包括 statfs 和 fstatfs 的实现
.rodata        0x...7f00001000  # 存放只读数据
.data          0x...7f00002000  # 存放已初始化全局变量和静态变量
.bss           0x...7f00003000  # 存放未初始化全局变量和静态变量
.plt           0x...7f00004000  # Procedure Linkage Table，用于延迟绑定
.got.plt       0x...7f00005000  # Global Offset Table (for PLT entries)
.got           0x...7f00006000  # Global Offset Table (for direct GOT entries)

... 其他段 ...
```

**链接的处理过程：**

1. **编译时链接：** 当编译 `sys_vfs_test.cpp` 时，编译器会知道需要调用 `statfs` 和 `fstatfs` 函数。但是，这些函数的具体地址在编译时是未知的，因为它们位于 `libc.so` 中。编译器会在目标文件中生成对这些函数的符号引用。
2. **动态链接：** 当运行测试程序时，Android 的动态链接器 (linker, 通常是 `linker64` 或 `linker`) 负责加载程序所需的共享库，包括 `libc.so`。
3. **符号解析：** 动态链接器会解析程序中对 `statfs` 和 `fstatfs` 的符号引用，找到 `libc.so` 中这些符号对应的地址。
4. **重定位 (Relocation)：**  由于共享库加载到内存的地址可能每次都不同，动态链接器需要修改程序中的某些指令和数据，使其能够正确访问 `libc.so` 中的函数和数据。这通常通过 Global Offset Table (GOT) 和 Procedure Linkage Table (PLT) 来实现。
   - **GOT：**  GOT 中存储着全局变量和外部函数的地址。动态链接器在加载时会填充 GOT 的条目。
   - **PLT：** PLT 中的每一项都对应一个外部函数。当程序第一次调用一个外部函数时，会跳转到 PLT 中对应的条目。PLT 中的代码会调用动态链接器来解析函数的地址，并将地址填入 GOT 中。后续对该函数的调用将直接通过 GOT 跳转，避免了重复的解析过程 (这被称为延迟绑定或惰性绑定)。

**`sys_vfs_test.cpp` 中涉及的链接过程：**

当 `sys_vfs_test` 程序调用 `statfs("/proc", &sb)` 时：

1. 程序会跳转到 `statfs` 在 PLT 中的条目。
2. PLT 条目中的代码会调用动态链接器。
3. 动态链接器查找 `libc.so` 中 `statfs` 的地址，并将该地址写入 `statfs` 对应的 GOT 条目。
4. PLT 条目中的代码会跳转到 GOT 中 `statfs` 的地址，从而执行 `libc.so` 中的 `statfs` 函数。

**逻辑推理 (假设输入与输出)**

假设我们运行 `TEST(sys_vfs, statfs)` 这个测试用例，并且 `/proc` 文件系统存在且可访问。

**假设输入：**

* 调用 `statfs("/proc", &sb)`。
* `/proc` 文件系统正常工作。

**预期输出 (基于 `Check` 函数的断言)：**

* `sb.f_bsize` (文件系统块大小) 应该等于 `getpagesize()` 的返回值 (通常是 4096 字节，但在 x86_64 上可能模拟为 16384，实际底层文件系统块大小仍然是 4096)。
* `sb.f_bfree` (空闲块数量) 应该等于 0。这在 `/proc` 文件系统上是预期的，因为它是一个虚拟文件系统。
* `sb.f_ffree` (空闲 inode 数量) 应该等于 0。同样，在 `/proc` 上预期为 0。
* `sb.f_namelen` (文件名的最大长度) 应该等于 255。
* `sb.f_fsid.__val[0]` (文件系统 ID 的第一个值) 应该等于 `/proc` 文件系统对应的设备号 (通过 `stat("/proc", &proc_sb)` 获取)。
* `sb.f_fsid.__val[1]` (文件系统 ID 的第二个值) 应该等于 0。
* `(sb.f_flags & 0x0020)` 应该等于 0，因为 `ST_VALID` 位不应该暴露给用户空间。

**用户或者编程常见的使用错误**

1. **忘记检查返回值：** `statfs` 和 `fstatfs` 在失败时会返回 -1 并设置 `errno`。如果程序员不检查返回值，就无法判断调用是否成功，可能会导致程序逻辑错误。

   ```c++
   struct statfs sb;
   statfs("/invalid/path", &sb); // 忘记检查返回值
   // 错误地使用了 sb 中的值
   ```

2. **传入无效的路径或文件描述符：** 如果 `statfs` 传入一个不存在的路径，或者 `fstatfs` 传入一个无效的文件描述符，调用将会失败，`errno` 会被设置为 `ENOENT` 或 `EBADF`。

   ```c++
   struct statfs sb;
   if (statfs("/does-not-exist", &sb) == -1) {
       perror("statfs failed"); // 正确处理错误
   }
   ```

3. **错误地解释 `statfs` 结构体中的字段：**  例如，混淆 `f_bfree` 和 `f_bavail`，或者不理解块大小 `f_bsize` 的含义。

4. **假设所有文件系统的行为都一致：** 不同的文件系统可能有不同的特性和限制。例如，某些虚拟文件系统的空闲空间可能始终为 0。

5. **在多线程环境中使用 `errno` 而不加保护：** `errno` 是一个线程局部变量，但在某些情况下，如果使用不当，仍然可能导致问题。

**Android Framework 或 NDK 如何一步步的到达这里**

1. **Android Framework 层 (Java 代码):**
   - 例如，`StorageManager` 类提供了获取存储设备信息的方法，如 `getFreeBytes()` 和 `getTotalBytes()`。
   - 这些方法最终会通过 JNI (Java Native Interface) 调用到 Native 代码。

2. **NDK (Native Development Kit) 或 Android Runtime (ART):**
   - 在 Native 代码中，可能会使用 POSIX 标准 C 库函数，例如 `statvfs` (它是 `statfs` 的 POSIX 版本，在 Android 上通常映射到 `statfs`) 或直接使用 `statfs`。

3. **Bionic libc:**
   - NDK 提供的 C 库实现位于 Bionic 中。当调用 `statfs` 时，会调用 Bionic libc 中对应的函数实现。

4. **系统调用:**
   - Bionic libc 中的 `statfs` 函数最终会通过系统调用 (syscall) 进入 Linux 内核。

5. **Linux 内核:**
   - 内核接收到系统调用请求后，会调用 VFS 层来处理。
   - VFS 层会根据路径找到对应的文件系统驱动。
   - 文件系统驱动执行实际的操作，获取文件系统信息。
   - 内核将结果返回给 Bionic libc。

6. **返回路径:**
   - Bionic libc 将内核返回的结果传递回 Native 代码。
   - Native 代码通过 JNI 将结果返回给 Java Framework 层。

**Frida Hook 示例调试步骤**

假设我们要 hook `statfs` 函数，查看它被调用时的路径参数和返回结果。

**Frida Hook 代码 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const statfs = Module.findExportByName('libc.so', 'statfs');
  if (statfs) {
    Interceptor.attach(statfs, {
      onEnter: function (args) {
        const path = Memory.readUtf8String(args[0]);
        console.log('[+] statfs called with path:', path);
      },
      onLeave: function (retval) {
        console.log('[+] statfs returned:', retval);
        if (retval === 0) {
          const statfsBuf = this.context.sp.add(Process.pointerSize); // Assuming x86/x64, adjust for ARM
          const f_bsize = Memory.readU64(statfsBuf);
          const f_bfree = Memory.readU64(statfsBuf.add(8));
          console.log('    f_bsize:', f_bsize);
          console.log('    f_bfree:', f_bfree);
          // 读取其他 statfs 结构体成员
        } else {
          const errno_value = System.errno();
          console.log('    errno:', errno_value);
        }
      }
    });
  } else {
    console.log('[-] statfs not found in libc.so');
  }
} else {
  console.log('[-] This script is for Android only.');
}
```

**调试步骤：**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务 (`frida-server`)。
2. **启动目标应用:** 运行你想要监控的应用。
3. **运行 Frida Hook 脚本:** 使用 Frida CLI 或通过 USB 连接到设备，运行上面的 JavaScript 代码。例如：
   ```bash
   frida -U -f <your_package_name> -l your_script.js --no-pause
   ```
   将 `<your_package_name>` 替换为你要监控的 Android 应用的包名，`your_script.js` 是保存 Frida Hook 代码的文件名。
4. **观察输出:** 当目标应用调用 `statfs` 函数时，Frida Hook 脚本会在终端输出 `statfs` 被调用的路径参数以及返回值和 `errno` (如果调用失败)。如果调用成功，还会输出 `statfs` 结构体中的部分字段值。

**注意:** 上面的 Frida Hook 示例假设了 x86/x64 架构，并且简化了对 `statfs` 结构体的读取。在 ARM 架构上，你需要根据具体的架构调整堆栈指针的计算方式，并根据 `statfs` 结构体的定义正确读取各个字段。你需要查阅 `<sys/vfs.h>` 头文件来了解 `statfs` 结构体的布局。

希望以上详细的解释能够帮助你理解 `bionic/tests/sys_vfs_test.cpp` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/sys_vfs_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <gtest/gtest.h>

#include <sys/vfs.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string>

#include "utils.h"

template <typename StatFsT> void Check(StatFsT& sb) {
#if defined(__x86_64__)
  // On x86_64 based 16kb page size targets, the page size in userspace is simulated to 16kb but
  // the underlying filesystem block size would remain unchanged, i.e., 4kb.
  // For more info:
  // https://source.android.com/docs/core/architecture/16kb-page-size/getting-started-cf-x86-64-pgagnostic
  EXPECT_EQ(4096, static_cast<int>(sb.f_bsize));
#else
  EXPECT_EQ(getpagesize(), static_cast<int>(sb.f_bsize));
#endif
  EXPECT_EQ(0U, sb.f_bfree);
  EXPECT_EQ(0U, sb.f_ffree);
  EXPECT_EQ(255, static_cast<int>(sb.f_namelen));

  // Linux 6.7 requires that all filesystems have a non-zero fsid.
  if (sb.f_fsid.__val[0] != 0U) {
    // fs/libfs.c reuses the filesystem's device number.
    struct stat proc_sb;
    ASSERT_EQ(0, stat("/proc", &proc_sb));
    EXPECT_EQ(static_cast<int>(proc_sb.st_dev), sb.f_fsid.__val[0]);
    EXPECT_EQ(0, sb.f_fsid.__val[1]);
  } else {
    // Prior to that, the fsid for /proc was just 0.
    EXPECT_EQ(0, sb.f_fsid.__val[0]);
    EXPECT_EQ(0, sb.f_fsid.__val[1]);
  }

  // The kernel sets a private bit to indicate that f_flags is valid.
  // This flag is not supposed to be exposed to libc clients.
  static const uint32_t ST_VALID = 0x0020;
  EXPECT_TRUE((sb.f_flags & ST_VALID) == 0) << sb.f_flags;
}

TEST(sys_vfs, statfs) {
  struct statfs sb;
  ASSERT_EQ(0, statfs("/proc", &sb));
  Check(sb);
}

TEST(sys_vfs, statfs_failure) {
  struct statfs sb;
  errno = 0;
  ASSERT_EQ(-1, statfs("/does-not-exist", &sb));
  ASSERT_ERRNO(ENOENT);
}

TEST(sys_vfs, statfs64_smoke) {
  struct statfs64 sb;
  ASSERT_EQ(0, statfs64("/proc", &sb));
  Check(sb);
}

TEST(sys_vfs, statfs64_failure) {
  struct statfs64 sb;
  errno = 0;
  ASSERT_EQ(-1, statfs64("/does-not-exist", &sb));
  ASSERT_ERRNO(ENOENT);
}

TEST(sys_vfs, fstatfs) {
  struct statfs sb;
  int fd = open("/proc", O_RDONLY);
  ASSERT_EQ(0, fstatfs(fd, &sb));
  close(fd);
  Check(sb);
}

TEST(sys_vfs, fstatfs_failure) {
  struct statfs sb;
  errno = 0;
  ASSERT_EQ(-1, fstatfs(-1, &sb));
  ASSERT_ERRNO(EBADF);
}

TEST(sys_vfs, fstatfs64_smoke) {
  struct statfs64 sb;
  int fd = open("/proc", O_RDONLY);
  ASSERT_EQ(0, fstatfs64(fd, &sb));
  close(fd);
  Check(sb);
}

TEST(sys_vfs, fstatfs64_failure) {
  struct statfs sb;
  errno = 0;
  ASSERT_EQ(-1, fstatfs(-1, &sb));
  ASSERT_ERRNO(EBADF);
}

"""

```