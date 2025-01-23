Response:
Let's break down the thought process for answering this complex request about `mman-common.h`.

**1. Understanding the Core Request:**

The central ask is to analyze the `mman-common.h` header file within the Android Bionic library. The request specifically asks for:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does it tie into Android's features?
* **libc Function Details:** Explanation of each constant's purpose.
* **Dynamic Linker Connection:** If applicable, details on its role and relevant samples.
* **Logic and Assumptions:**  If any reasoning is used, explain the inputs and outputs.
* **Common Errors:**  How can programmers misuse these definitions?
* **Android Framework/NDK Path:** How does the system get to this header?
* **Frida Hooking:**  Demonstrate how to intercept these definitions.

**2. Initial Assessment of the File:**

The file itself contains a series of `#define` preprocessor directives. This immediately suggests that it's a header file defining *constants*. These constants are related to memory management, as the filename "mman" indicates. The "common" part suggests these are general definitions shared across different architectures. The `uapi` path signifies that these definitions form part of the user-kernel interface.

**3. Deconstructing the Content (Categorization):**

To address the "functionality" and "libc function details" requests, it's crucial to categorize the defined constants:

* **Memory Protection (PROT_*)**:  Clearly related to access permissions for memory regions.
* **Mapping Flags (MAP_*)**: Options for how memory regions are mapped into the address space.
* **Memory Locking (MLOCK_*)**:  Options for locking memory in RAM.
* **Synchronization Flags (MS_*)**:  Flags for `msync` system call related to writing back changes.
* **Memory Advice (MADV_*)**: Hints to the kernel about how to handle memory regions.
* **File Mapping (MAP_FILE)**:  A specific mapping type.
* **Protection Keys (PKEY_*)**:  More advanced memory protection mechanisms.

**4. Connecting to Android Functionality:**

Now, consider how these categories relate to Android:

* **Memory Protection:**  Fundamental for security, process isolation, and preventing crashes. Android's permission system and application sandboxing rely on memory protection.
* **Mapping:** Essential for loading executables, libraries, and managing shared memory. Android's Dalvik/ART virtual machines heavily use memory mapping.
* **Memory Locking:**  Used in performance-critical applications or those requiring low latency, ensuring data stays in RAM. Android's media frameworks or real-time applications might use this.
* **Memory Advice:**  Allows applications to optimize memory usage. Android apps could use this to guide the kernel.

**5. Explaining Each Constant (Detailing):**

Go through each category and explain the purpose of individual constants. For example:

* `PROT_READ`: Allows reading from the memory region.
* `MAP_ANONYMOUS`: Creates a mapping not backed by a file (used for heap allocation).
* `MADV_DONTNEED`: Informs the kernel that a region is no longer needed.

**6. Dynamic Linker Relevance:**

The `MAP_` constants are directly relevant to the dynamic linker (`linker64` or `linker`). When loading shared libraries (`.so` files), the linker uses `mmap` (which takes `MAP_*` flags) to map the library segments into the process's address space.

* **SO Layout Example:**  Illustrate the different segments (.text, .data, .bss) and how they are mapped with different permissions (e.g., `.text` with `PROT_READ | PROT_EXEC`).
* **Linking Process:** Briefly describe how the linker reads the ELF headers and uses `mmap` to create these mappings.

**7. Logic and Assumptions:**

This file primarily defines constants. The "logic" comes in when *using* these constants in system calls like `mmap`, `mprotect`, etc. Provide examples of how these constants would be combined (e.g., `mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)`).

**8. Common User Errors:**

Think about common mistakes developers make when working with memory management:

* Incorrect `PROT_*` flags leading to crashes (e.g., trying to write to a read-only region).
* Misunderstanding `MAP_FIXED` and causing memory overlaps.
* Not understanding the implications of `MAP_SHARED` vs. `MAP_PRIVATE`.

**9. Android Framework/NDK Path:**

Trace the execution flow:

* **NDK:** An NDK application uses standard C/C++ library functions (like those wrapping `mmap`).
* **libc (Bionic):**  The NDK functions call into Bionic's implementations.
* **System Calls:** Bionic functions make system calls to the Linux kernel (e.g., `syscall(__NR_mmap)`).
* **Kernel:** The kernel interprets the system call arguments, including the flags defined in `mman-common.h`.

**10. Frida Hooking:**

Demonstrate how to use Frida to intercept system calls related to memory management (like `mmap`). Show how to read the arguments, including the flag values.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus solely on `mmap`.
* **Correction:** Realize the file also covers `mprotect`, `msync`, `madvise`, and related concepts. Expand the explanation accordingly.
* **Initial thought:**  Provide a very technical, low-level explanation of the dynamic linker.
* **Correction:** Simplify the dynamic linker explanation to focus on the core concept of mapping library segments and providing a basic SO layout example.
* **Initial thought:** Just list potential errors.
* **Correction:** Provide concrete code examples of incorrect usage to make it clearer.

By following these steps and iterating on the initial understanding, a comprehensive and accurate answer can be constructed. The key is to break down the complex request into smaller, manageable parts and systematically address each one.
这是一个名为 `mman-common.h` 的头文件，属于 Android Bionic 库的一部分，位于内核用户空间 API 目录下。它定义了一系列用于内存管理相关的常量（宏定义）。这些常量主要被用于和内存管理相关的系统调用，例如 `mmap`, `mprotect`, `msync`, `madvise` 等。由于它位于 `uapi` 目录下，意味着这些定义是用户空间程序可以直接使用的，并且与内核中使用的定义保持一致，确保用户空间和内核空间对于内存管理操作的理解是一致的。

**它的功能：**

这个文件的主要功能是定义了以下几类常量：

1. **内存保护标志 (PROT_*)**:  用于指定内存区域的访问权限。
2. **内存映射标志 (MAP_*)**:  用于指定内存映射的行为和特性。
3. **内存锁定标志 (MLOCK_*)**: 用于控制内存锁定行为。
4. **内存同步标志 (MS_*)**:  用于 `msync` 系统调用，控制内存与存储之间的同步方式。
5. **内存建议标志 (MADV_*)**: 用于向内核提供关于内存区域使用模式的建议，以帮助内核优化内存管理。
6. **保护密钥标志 (PKEY_*)**: 用于更细粒度的内存访问控制（较新的特性）。

**与 Android 功能的关系及举例说明：**

这些常量是 Android 操作系统进行内存管理的基础。Android 依赖这些常量来实现进程隔离、内存保护、高效的内存使用等核心功能。

* **进程隔离和内存保护:** `PROT_READ`, `PROT_WRITE`, `PROT_EXEC`, `PROT_NONE` 等标志用于控制不同进程对内存区域的访问权限。例如，Android 系统可以将一个应用的代码段映射为只读和可执行 (`PROT_READ | PROT_EXEC`)，防止应用修改自身代码，提高安全性。数据段通常映射为可读写 (`PROT_READ | PROT_WRITE`)。
* **匿名内存分配:** `MAP_ANONYMOUS` 常量用于创建不与任何文件关联的内存映射，这通常用于实现动态内存分配（例如 `malloc` 底层可能使用 `mmap` 与 `MAP_ANONYMOUS`）。Android 应用的堆内存分配就依赖于此。
* **共享内存:**  可以通过 `mmap` 结合 `MAP_SHARED` 标志在不同进程之间创建共享内存区域。Android 中的 Binder 机制底层就可能使用共享内存来传递大数据。
* **加载可执行文件和共享库:**  当 Android 加载一个应用或者共享库时，会使用 `mmap` 将其代码段和数据段映射到进程的地址空间。`PROT_READ`, `PROT_WRITE`, `PROT_EXEC` 等标志会被用来设置相应的内存保护属性。
* **内存优化:**  `MADV_*` 系列常量允许应用向内核提供关于内存使用模式的提示。例如，一个应用如果知道某个内存区域即将被频繁访问，可以使用 `MADV_WILLNEED` 提示内核提前加载该区域到内存中。反之，如果某个区域不再需要，可以使用 `MADV_DONTNEED` 告诉内核可以回收这部分内存。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身不包含任何 libc 函数的实现，它只是定义了一些常量。这些常量会被 libc 库中的内存管理相关的系统调用包装函数使用。例如：

* **`mmap`**:  `mmap` 系统调用用于在进程的地址空间中创建一个新的内存映射。它的原型通常是 `void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);`。
    * `prot` 参数使用 `PROT_*` 常量来指定内存区域的保护属性（读、写、执行）。
    * `flags` 参数使用 `MAP_*` 常量来指定映射的类型（例如，是否是匿名映射、是否共享、是否固定地址）。
    * 当 Android 应用调用 `malloc` 时，如果分配的内存块较大，libc 可能会使用 `mmap` 系统调用配合 `MAP_ANONYMOUS` 来分配内存。
    * 当加载一个共享库时，linker (动态链接器) 会使用 `mmap` 将库文件的各个段（如代码段、数据段）映射到进程的地址空间，并使用 `PROT_READ | PROT_EXEC` 或 `PROT_READ | PROT_WRITE` 设置相应的权限。

* **`mprotect`**:  `mprotect` 系统调用用于修改一个已存在的内存区域的保护属性。它的原型是 `int mprotect(void *addr, size_t len, int prot);`。
    * `prot` 参数使用 `PROT_*` 常量来指定新的保护属性。
    * Android 系统可能会使用 `mprotect` 来实现写时复制 (copy-on-write) 机制，或者在需要时修改内存区域的权限。

* **`msync`**: `msync` 系统调用用于将内存映射区域的数据同步回 backing storage (如果存在)。它的原型是 `int msync(void *addr, size_t length, int flags);`。
    * `flags` 参数使用 `MS_*` 常量来指定同步的方式（例如，异步、同步、是否使缓存失效）。
    * 在 Android 中，如果使用了 `MAP_SHARED` 创建了共享内存，一个进程修改了共享内存的内容后，可以使用 `msync` 将修改写回，以便其他映射到同一区域的进程可以看到修改。

* **`madvise`**: `madvise` 系统调用用于向内核提供关于内存区域使用模式的建议。它的原型是 `int madvise(void *addr, size_t length, int advice);`。
    * `advice` 参数使用 `MADV_*` 常量来提供不同的建议。
    * 例如，一个视频播放器可能使用 `MADV_SEQUENTIAL` 提示内核，它将顺序访问一段内存，内核可以提前预读数据。

* **`mlock` 和 `munlock`**: 虽然 `MLOCK_ONFAULT` 在此文件中定义，但 `mlock` 和 `munlock` 系统调用用于将内存页锁定在 RAM 中，防止被交换到磁盘。`MLOCK_ONFAULT` 是 `mlock2` 系统调用中的一个标志，表示只有在访问页时才锁定。在 Android 中，一些对性能有严格要求的服务可能会使用内存锁定。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

当 Android 启动一个应用或者加载一个共享库时，dynamic linker (如 `linker64` 或 `linker`) 负责将共享库加载到进程的地址空间中。这个过程中会用到 `mmap` 以及这里定义的常量。

**SO 布局样本：**

一个典型的共享库 (`.so`) 文件（ELF 格式）包含多个段（segment），这些段在加载时会被映射到内存的不同区域，并设置不同的保护属性。以下是一个简化的示例：

```
LOAD           0x0000000000000000  0x0000000000000000  0x0000000000000000  0x0000000000001000 R E   0x1000
LOAD           0x0000000000002000  0x0000000000002000  0x0000000000002000  0x0000000000000100 RW    0x1000
```

* **第一个 LOAD 段 (R E):**
    * 虚拟地址 (Vaddr): `0x0000000000000000`
    * 文件偏移 (Offset): `0x0000000000000000`
    * 大小: `0x1000` 字节
    * 权限: **R**ead (读), **E**xecute (执行)
    * 这个段通常包含代码（`.text` 段），使用 `mmap` 映射时会指定 `PROT_READ | PROT_EXEC`。

* **第二个 LOAD 段 (RW):**
    * 虚拟地址 (Vaddr): `0x0000000000002000`
    * 文件偏移 (Offset): `0x0000000000002000`
    * 大小: `0x1000` 字节
    * 权限: **R**ead (读), **W**rite (写)
    * 这个段通常包含已初始化的全局变量（`.data` 段）和未初始化的全局变量（`.bss` 段），使用 `mmap` 映射时会指定 `PROT_READ | PROT_WRITE`。`.bss` 段在映射后会被清零。

**链接的处理过程：**

1. **读取 ELF 头:** Dynamic linker 首先会读取共享库的 ELF 头，获取程序的入口点、段表信息等。
2. **映射共享库的段:**  对于每个需要加载的段，dynamic linker 会调用 `mmap` 系统调用，并将对应的文件内容映射到进程的地址空间。
    * 代码段（通常只读和可执行）：`mmap(..., PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, offset)`
    * 数据段（可读写）：`mmap(..., PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, offset)`
    * `MAP_PRIVATE` 表示这是一个私有映射，对该内存区域的修改不会反映到原始文件，也不会被其他进程看到（除非使用了 `MAP_SHARED`）。
    * `MAP_FIXED` 表示映射的地址是固定的（通常由 ELF 文件指定）。
3. **重定位:**  共享库中的代码可能依赖于其他库中的符号。Dynamic linker 会解析共享库的重定位表，并修改代码和数据段中的地址，使其指向正确的符号地址。
4. **绑定符号:** Dynamic linker 会解析共享库的导入表，找到它依赖的符号，并将其绑定到相应的库中的地址。
5. **执行初始化代码:**  如果共享库有初始化函数（例如，使用 `__attribute__((constructor))` 定义的函数），dynamic linker 会在完成加载和链接后执行这些初始化代码。

**如果做了逻辑推理，请给出假设输入与输出：**

这个头文件定义的是常量，本身不涉及复杂的逻辑推理。逻辑推理主要发生在内核处理内存管理系统调用时。

**假设输入（对于 `mmap` 系统调用）：**

* `addr`: `NULL` (让内核选择地址)
* `length`: `4096` (分配 4KB 内存)
* `prot`: `PROT_READ | PROT_WRITE` (可读写)
* `flags`: `MAP_ANONYMOUS | MAP_PRIVATE` (匿名私有映射)
* `fd`: `-1` (对于匿名映射，文件描述符设为 -1)
* `offset`: `0`

**假设输出：**

内核会找到一块未使用的 4KB 内存区域，并将其映射到调用进程的地址空间。`mmap` 系统调用成功返回新映射的起始地址，失败则返回 `MAP_FAILED` 并设置 `errno`。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **权限不足导致段错误 (Segmentation Fault):**
   ```c
   #include <sys/mman.h>
   #include <stdio.h>
   #include <stdlib.h>
   #include <errno.h>
   #include <string.h>

   int main() {
       size_t size = 4096;
       void *addr = mmap(NULL, size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
       if (addr == MAP_FAILED) {
           perror("mmap");
           return 1;
       }

       // 尝试写入只读内存
       strcpy(addr, "Hello"); // 错误！会触发 SIGSEGV

       if (munmap(addr, size) == -1) {
           perror("munmap");
           return 1;
       }
       return 0;
   }
   ```
   在这个例子中，使用 `PROT_READ` 创建了一个只读的内存映射，然后尝试向该区域写入数据，会导致程序崩溃。

2. **错误使用 `MAP_FIXED` 导致覆盖现有映射:**
   ```c
   #include <sys/mman.h>
   #include <stdio.h>
   #include <stdlib.h>
   #include <errno.h>

   int main() {
       size_t size = 4096;
       void *addr1 = mmap((void*)0x10000000, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
       if (addr1 == MAP_FAILED) {
           perror("mmap addr1");
           return 1;
       }
       printf("addr1: %p\n", addr1);

       void *addr2 = mmap((void*)0x10000000, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
       if (addr2 == MAP_FAILED) {
           perror("mmap addr2");
           return 1;
       }
       printf("addr2: %p\n", addr2);

       // addr2 会覆盖 addr1 的映射，可能导致不可预测的行为

       if (munmap(addr1, size) == -1) { // 此时 addr1 的映射可能已被覆盖
           perror("munmap addr1");
       }
       if (munmap(addr2, size) == -1) {
           perror("munmap addr2");
       }
       return 0;
   }
   ```
   使用 `MAP_FIXED` 会尝试在指定的地址创建映射。如果该地址已被占用，新的映射会覆盖旧的映射，可能导致程序崩溃或数据损坏。通常应避免在不确定地址是否空闲的情况下使用 `MAP_FIXED`。

3. **忘记 `munmap` 导致内存泄漏:**
   如果使用 `mmap` 分配了内存，但忘记使用 `munmap` 释放，会导致内存泄漏。虽然进程结束时操作系统会回收所有内存，但在长时间运行的程序中，不释放不再使用的映射会导致内存资源耗尽。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤：**

**Android Framework 到达这里的步骤：**

1. **Java 代码请求内存：** Android Framework 中的 Java 代码，例如 `Bitmap.allocateBuffer()` 或其他需要分配 Native 内存的操作，最终会调用到 Native 代码。
2. **JNI 调用到 Native 代码：**  Java 代码通过 JNI (Java Native Interface) 调用到 Android Runtime (ART) 或 Dalvik 虚拟机的 Native 方法。
3. **Native 代码中的内存分配：** Native 代码中可能会使用 `malloc`, `mmap` 等函数进行内存分配。
4. **libc 函数调用：** `malloc` 底层可能会调用 `mmap` 系统调用（特别是对于大块内存分配）。`mmap` 函数会使用 `mman-common.h` 中定义的常量作为参数。

**NDK 到达这里的步骤：**

1. **NDK 应用调用 libc 函数：** NDK 应用直接使用 C/C++ 标准库函数，例如 `mmap`, `mprotect` 等。
2. **libc 函数实现：**  NDK 应用调用的 libc 函数是 Bionic 库提供的实现。
3. **系统调用：** Bionic 库中的内存管理函数会调用相应的 Linux 内核系统调用，例如 `syscall(__NR_mmap, ...)`。系统调用的参数就包含了 `mman-common.h` 中定义的常量。

**Frida Hook 示例：**

可以使用 Frida Hook `mmap` 系统调用来观察这些常量的使用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

package_name = "your.target.package" # 替换为你的目标应用包名

try:
    device = frida.get_usb_device(timeout=10)
    session = device.attach(package_name)
except frida.TimedOutError:
    print("[-] Device not found or USB not configured correctly.")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "syscall"), {
    onEnter: function(args) {
        var syscall_number = this.context.rax.toInt(); // For x86_64, adjust for other architectures
        if (syscall_number == 9) { // __NR_mmap
            var addr = args[0];
            var length = args[1];
            var prot = args[2].toInt();
            var flags = args[3].toInt();
            var fd = args[4].toInt();
            var offset = args[5];

            var prot_str = "";
            if (prot & 0x1) prot_str += "PROT_READ | ";
            if (prot & 0x2) prot_str += "PROT_WRITE | ";
            if (prot & 0x4) prot_str += "PROT_EXEC | ";

            var flags_str = "";
            if (flags & 0x10) flags_str += "MAP_FIXED | ";
            if (flags & 0x20) flags_str += "MAP_ANONYMOUS | ";

            send({
                type: "mmap",
                addr: addr,
                length: length.toString(),
                prot: prot_str.slice(0, -3),
                flags: flags_str.slice(0, -3),
                fd: fd,
                offset: offset.toString()
            });
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. 将 `your.target.package` 替换为你想要监控的 Android 应用的包名。
2. 确保你的 Android 设备已连接并通过 USB 调试。
3. 运行这个 Frida 脚本。
4. 在你的 Android 设备上操作目标应用，触发内存分配等操作。

**输出示例：**

当你操作应用时，Frida 脚本会拦截 `mmap` 系统调用，并打印出调用的参数，包括 `prot` 和 `flags` 的值，你可以看到 `PROT_*` 和 `MAP_*` 常量是如何被使用的。例如：

```
[*] {"type": "mmap", "addr": "0x0", "length": "4096", "prot": "PROT_READ | PROT_WRITE", "flags": "MAP_ANONYMOUS", "fd": -1, "offset": "0"}
[*] {"type": "mmap", "addr": "0x7b88000000", "length": "131072", "prot": "PROT_READ | PROT_EXEC", "flags": "MAP_PRIVATE | MAP_FIXED", "fd": 32, "offset": "0"}
```

这个示例展示了 `mmap` 系统调用被调用，并使用了 `PROT_READ | PROT_WRITE` 和 `MAP_ANONYMOUS`，以及 `PROT_READ | PROT_EXEC` 和 `MAP_PRIVATE | MAP_FIXED` 等常量，这对应了匿名内存分配和共享库加载的场景。

通过 Frida Hook，你可以深入了解 Android Framework 或 NDK 应用在底层是如何使用这些内存管理相关的常量和系统调用的。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-generic/mman-common.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```c
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef __ASM_GENERIC_MMAN_COMMON_H
#define __ASM_GENERIC_MMAN_COMMON_H
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define PROT_SEM 0x8
#define PROT_NONE 0x0
#define PROT_GROWSDOWN 0x01000000
#define PROT_GROWSUP 0x02000000
#define MAP_TYPE 0x0f
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_POPULATE 0x008000
#define MAP_NONBLOCK 0x010000
#define MAP_STACK 0x020000
#define MAP_HUGETLB 0x040000
#define MAP_SYNC 0x080000
#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_UNINITIALIZED 0x4000000
#define MLOCK_ONFAULT 0x01
#define MS_ASYNC 1
#define MS_INVALIDATE 2
#define MS_SYNC 4
#define MADV_NORMAL 0
#define MADV_RANDOM 1
#define MADV_SEQUENTIAL 2
#define MADV_WILLNEED 3
#define MADV_DONTNEED 4
#define MADV_FREE 8
#define MADV_REMOVE 9
#define MADV_DONTFORK 10
#define MADV_DOFORK 11
#define MADV_HWPOISON 100
#define MADV_SOFT_OFFLINE 101
#define MADV_MERGEABLE 12
#define MADV_UNMERGEABLE 13
#define MADV_HUGEPAGE 14
#define MADV_NOHUGEPAGE 15
#define MADV_DONTDUMP 16
#define MADV_DODUMP 17
#define MADV_WIPEONFORK 18
#define MADV_KEEPONFORK 19
#define MADV_COLD 20
#define MADV_PAGEOUT 21
#define MADV_POPULATE_READ 22
#define MADV_POPULATE_WRITE 23
#define MADV_DONTNEED_LOCKED 24
#define MADV_COLLAPSE 25
#define MAP_FILE 0
#define PKEY_DISABLE_ACCESS 0x1
#define PKEY_DISABLE_WRITE 0x2
#define PKEY_ACCESS_MASK (PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE)
#endif
```