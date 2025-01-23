Response:
Let's break down the thought process for generating the comprehensive answer about `bionic/libc/bionic/sys_shm.cpp`.

**1. Understanding the Core Request:**

The primary request is to analyze the provided C++ source code file, `sys_shm.cpp`, within the context of Android's Bionic library. The key areas to address are:

* **Functionality:** What do the functions in this file do?
* **Android Relevance:** How do these functions relate to the overall Android system?
* **Implementation Details:** How are these functions implemented in terms of system calls?
* **Dynamic Linking (Potentially):** Although this specific file doesn't *directly* involve dynamic linking, the request asks about it in the broader context of bionic. I need to address this conceptually and explain why it's not prominent here.
* **Error Handling:**  What are common mistakes users might make?
* **Tracing/Debugging:** How can these functions be traced and debugged using tools like Frida?
* **Step-by-step Call Stack:** How does a request from the Android framework or NDK reach these functions?

**2. Initial Code Analysis:**

The code is straightforward. It defines four functions: `shmat`, `shmctl`, `shmdt`, and `shmget`. Each function simply wraps a corresponding Linux system call using the `syscall()` mechanism.

**3. Identifying the Core Concept: Shared Memory:**

The names of the functions (`shm` for shared memory) immediately point to the core functionality: inter-process communication (IPC) using shared memory segments.

**4. Detailing Functionality (Per Function):**

* **`shmget`:**  This function *creates* or *accesses* a shared memory segment. The key information here is the `key` (a way to identify the shared memory), the `size`, and the `flags` (permissions, creation flags).
* **`shmat`:** This function *attaches* a shared memory segment to the address space of the calling process. The `id` refers to the shared memory segment obtained from `shmget`. `address` is a hint for where to map it, and `flags` control the attachment behavior (read-only, etc.).
* **`shmdt`:** This function *detaches* a shared memory segment from the process's address space.
* **`shmctl`:** This function provides *control operations* for a shared memory segment. This includes getting status (`IPC_STAT`), setting status (`IPC_SET`), and removing the segment (`IPC_RMID`). The special handling for 32-bit architectures (`IPC_64`) is a noteworthy implementation detail.

**5. Connecting to Android:**

* **IPC:** Emphasize that shared memory is a fundamental IPC mechanism in Android, allowing different processes (apps, system services) to efficiently share data.
* **Examples:**  Brainstorm concrete Android scenarios where shared memory is used. SurfaceFlinger (framebuffer sharing), Binder (less directly, but related to shared memory concepts for data transfer), and media subsystems are good examples.

**6. Explaining Implementation (System Calls):**

Clearly explain that these functions are thin wrappers around Linux system calls. Name the corresponding system calls (`SYS_shmget`, `SYS_shmat`, etc.). This clarifies the low-level interaction with the kernel.

**7. Addressing Dynamic Linking:**

Recognize that while this specific file doesn't showcase dynamic linking, it's a crucial part of Bionic. Explain the general purpose of the dynamic linker (loading shared libraries). Provide a simplified `.so` layout example, including sections like `.text`, `.data`, `.bss`, and the dynamic symbol table. Describe the linking process (symbol resolution, relocation). Explain *why* dynamic linking isn't prominent here (these are base libc functions directly invoking system calls).

**8. Identifying Potential Errors:**

Think about common mistakes developers might make when using shared memory:

* **Permissions:** Incorrect flags in `shmget` or `shmat`.
* **Key Management:** Conflicts if keys aren't managed properly.
* **Synchronization:** The lack of built-in synchronization and the need for mechanisms like mutexes or semaphores.
* **Resource Leaks:** Forgetting to detach or remove shared memory segments.

**9. Demonstrating Frida Hooking:**

Provide a practical Frida script to intercept and log calls to these functions. This gives a concrete way to observe their behavior. The script should include:

* Selecting the target process (e.g., by name).
* Attaching to the process.
* Intercepting the functions (`Interceptor.attach`).
* Logging the arguments of the functions.

**10. Illustrating the Call Stack (Android Framework/NDK to Bionic):**

Describe a typical path:

* **High-level API:** An application or framework component uses a high-level API (e.g., NDK's ASharedMemory).
* **NDK Layer:** The NDK provides C/C++ wrappers.
* **Bionic:** The NDK wrappers eventually call the Bionic libc functions (`shmget`, `shmat`, etc.).
* **System Calls:** Bionic makes system calls to the kernel.

**11. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Use formatting (bolding, bullet points) to improve readability. Start with a summary of the file's purpose and then delve into the details.

**12. Language and Clarity:**

Use clear and concise language. Explain technical terms where necessary. Maintain a professional and informative tone.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Should I go deep into the kernel implementation of shared memory? **Correction:** No, the request focuses on the `sys_shm.cpp` file and its role in Bionic. Mentioning system calls is sufficient.
* **Initial thought:**  Focus only on the direct usage of these functions. **Correction:**  The request asks about Android context, so providing broader examples within Android is important.
* **Considering dynamic linking:** Although not directly used here, it's part of Bionic, so a conceptual explanation is necessary. Focus on the *why* it's not prominent here.
* **Frida Example:**  Make the Frida script practical and easy to understand. Include the necessary steps for setting it up.

By following these steps, including analysis, connection to the broader context, and practical examples, the detailed and informative answer can be generated. The self-correction aspect ensures that the answer remains focused and relevant to the original request.
好的，我们来详细分析 `bionic/libc/bionic/sys_shm.cpp` 这个文件。

**功能概述**

`sys_shm.cpp` 文件在 Android 的 Bionic 库中实现了与共享内存相关的系统调用封装函数。它提供了一组 C 标准库函数，允许进程创建、访问和控制共享内存段。这些函数是进程间通信（IPC）的一种重要机制。

具体来说，这个文件实现了以下四个函数：

1. **`shmat` (Shared Memory Attach):**  将一个共享内存段连接到调用进程的地址空间。
2. **`shmctl` (Shared Memory Control):**  对共享内存段执行各种控制操作，例如获取状态、设置状态或删除共享内存段。
3. **`shmdt` (Shared Memory Detach):**  将共享内存段从调用进程的地址空间分离。
4. **`shmget` (Shared Memory Get):**  创建一个新的共享内存段，或者返回一个已存在的共享内存段的标识符。

**与 Android 功能的关系及举例说明**

共享内存是 Android 系统中实现进程间通信的一种关键方式。许多 Android 组件和服务依赖于共享内存来实现高效的数据共享和通信。

**举例说明：**

* **SurfaceFlinger:**  Android 的 SurfaceFlinger 服务负责屏幕合成和显示。它使用共享内存缓冲区来接收来自不同应用程序的图形数据（例如，窗口内容）。应用程序将渲染好的图形数据写入共享内存，然后 SurfaceFlinger 读取这些数据进行合成和显示。这避免了昂贵的数据复制操作。
* **Binder:**  虽然 Binder 的主要通信机制是基于代理对象的，但在数据量较大的情况下，Binder 也可以利用共享内存来传递数据。这提高了大数据传输的效率。
* **匿名共享内存 (ashmem/memfd_create):**  虽然 `sys_shm.cpp` 主要关注 System V 风格的共享内存，但 Android 还提供了一种更现代的匿名共享内存机制，通常通过 `ashmem` (Android Shared Memory) 或更底层的 `memfd_create` 系统调用实现。这些机制在内部也可能与内核的共享内存实现相关联。例如，`ASharedMemory_create` (NDK API) 就使用了 `memfd_create`。
* **媒体框架 (Media Framework):**  在 Android 的媒体框架中，例如用于视频解码和编码，共享内存经常被用来传递原始的视频帧数据，以提高性能。

**libc 函数的实现细节**

`sys_shm.cpp` 中实现的 libc 函数实际上是对 Linux 内核提供的相应系统调用的简单封装。

1. **`shmat(int id, const void* address, int flags)`:**
   - **功能:** 将由 `id` 指定的共享内存段连接到调用进程的地址空间。`address` 是一个可选的建议连接地址，可以为 `nullptr`，由内核选择地址。`flags` 控制连接的属性，例如 `SHM_RDONLY` 表示只读连接。
   - **实现:**  该函数通过 `syscall(SYS_shmat, id, address, flags)` 直接调用 Linux 内核的 `shmat` 系统调用。
   - **系统调用:** `SYS_shmat`。
   - **内核操作:**  内核会查找指定的共享内存段，并在进程的虚拟地址空间中创建一个映射。返回实际映射到的地址。

2. **`shmctl(int id, int cmd, struct shmid_ds* buf)`:**
   - **功能:**  对由 `id` 指定的共享内存段执行控制操作。`cmd` 指定要执行的操作，例如 `IPC_STAT`（获取共享内存段的状态信息）、`IPC_SET`（设置共享内存段的状态信息，需要 root 权限）、`IPC_RMID`（删除共享内存段）。`buf` 是一个指向 `shmid_ds` 结构的指针，用于传递或接收状态信息。
   - **实现:**
     - 在 32 位系统上（`!defined(__LP64__)`），代码添加了 `IPC_64` 标志。这是因为在早期的 Linux 内核中，32 位系统和 64 位系统对于 `shmctl` 系统调用的参数处理略有不同，需要 `IPC_64` 标志来指示使用 64 位兼容的数据结构。但在现代内核中，这个标志通常不再需要，尤其是在 64 位系统上反而会引起错误。Bionic 这里可能保留了兼容旧版本的考虑。
     - 函数通过 `syscall(SYS_shmctl, id, cmd, buf)` 调用 Linux 内核的 `shmctl` 系统调用。
   - **系统调用:** `SYS_shmctl`.
   - **内核操作:** 内核根据 `cmd` 的值执行相应的操作，例如读取或修改共享内存段的元数据。

3. **`shmdt(const void* address)`:**
   - **功能:**  将先前通过 `shmat` 连接到进程地址空间的共享内存段分离。`address` 是通过 `shmat` 返回的连接地址。
   - **实现:**  函数通过 `syscall(SYS_shmdt, address)` 调用 Linux 内核的 `shmdt` 系统调用。
   - **系统调用:** `SYS_shmdt`.
   - **内核操作:**  内核会移除进程虚拟地址空间中与该共享内存段的映射。

4. **`shmget(key_t key, size_t size, int flags)`:**
   - **功能:**  根据给定的 `key` 创建一个新的共享内存段，或者获取一个已存在的共享内存段的标识符。`key` 是一个用于标识共享内存段的键值。`size` 是要创建的共享内存段的大小（以字节为单位）。`flags` 控制创建的行为和权限，例如 `IPC_CREAT`（如果不存在则创建）、`IPC_EXCL`（与 `IPC_CREAT` 一起使用，如果已存在则失败）、权限位（如 `0666`）。
   - **实现:**  函数通过 `syscall(SYS_shmget, key, size, flags)` 调用 Linux 内核的 `shmget` 系统调用。
   - **系统调用:** `SYS_shmget`.
   - **内核操作:**
     - 如果指定了 `IPC_CREAT` 且 `key` 对应的共享内存段不存在，内核会分配一块新的内存区域，并创建一个与 `key` 关联的共享内存段结构。
     - 如果 `key` 对应的共享内存段已存在，则返回其标识符。
     - 返回新创建或已存在的共享内存段的标识符（一个整数）。如果创建或获取失败，返回 -1 并设置 `errno`。

**涉及 dynamic linker 的功能**

这个 `sys_shm.cpp` 文件本身并不直接涉及 dynamic linker 的功能。它主要关注的是系统调用的封装。dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 到进程的地址空间，并解析和重定位符号。

然而，理解 dynamic linker 如何处理共享内存是重要的。当一个 `.so` 文件被加载到多个进程中时，它的 `.text`（代码段）通常会在进程间共享以节省内存。这正是 dynamic linker 的一个核心优化。

**so 布局样本和链接的处理过程 (概念性说明)**

一个典型的 `.so` 文件的布局可能包含以下几个部分：

* **`.text` (代码段):**  包含可执行的机器代码。这部分通常是只读的，并且可以被多个进程共享。
* **`.data` (已初始化数据段):**  包含已初始化的全局变量和静态变量。每个进程拥有自己的 `.data` 段的副本。
* **`.bss` (未初始化数据段):**  包含未初始化的全局变量和静态变量。每个进程拥有自己的 `.bss` 段的副本。
* **`.rodata` (只读数据段):**  包含只读的常量数据。可以被多个进程共享。
* **`.dynamic` (动态链接信息):**  包含 dynamic linker 需要的信息，例如导入和导出的符号表、重定位表等。
* **`.got` (全局偏移量表):**  用于访问全局数据。
* **`.plt` (过程链接表):**  用于调用外部函数。

**链接的处理过程 (简化描述):**

1. **加载：** 当一个进程需要加载一个 `.so` 文件时，`linker` 会读取 ELF 文件头，确定需要加载的段，并将其映射到进程的地址空间。对于可以共享的段（如 `.text` 和 `.rodata`），如果其他进程已经加载了相同的 `.so`，`linker` 可能会重用已有的内存映射，从而实现共享。
2. **符号解析：**  `.so` 文件可能依赖于其他共享库提供的函数和变量。`linker` 会遍历 `.dynamic` 段中的信息，找到需要的符号，并在其他已加载的共享库中查找这些符号的定义。
3. **重定位：**  由于共享库被加载到不同的内存地址，代码中访问全局变量和调用外部函数的地址需要在运行时进行调整。`linker` 会根据 `.rel.dyn` 和 `.rel.plt` 段中的信息，修改 `.got` 和 `.plt` 中的地址。

**注意：**  `sys_shm.cpp` 中处理的共享内存是通过独立的系统调用创建和管理的，与 dynamic linker 加载共享库的共享内存机制是不同的概念。前者是显式地创建和连接内存段，后者是 dynamic linker 管理的代码和只读数据的共享。

**逻辑推理、假设输入与输出**

假设我们有一个简单的程序使用 `shmget` 和 `shmat`：

**假设输入:**

```c++
#include <iostream>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <cstring>

int main() {
    key_t key = 1234;
    size_t shm_size = 1024;
    int shmid;
    void* shared_memory;

    // 创建共享内存段
    shmid = shmget(key, shm_size, IPC_CREAT | 0666);
    if (shmid == -1) {
        perror("shmget");
        return 1;
    }

    // 连接共享内存段
    shared_memory = shmat(shmid, nullptr, 0);
    if (shared_memory == (void*) -1) {
        perror("shmat");
        return 1;
    }

    // 向共享内存写入数据
    const char* message = "Hello from process 1!";
    std::strcpy(static_cast<char*>(shared_memory), message);
    std::cout << "Process 1 wrote: " << message << std::endl;

    // 等待另一个进程读取数据（简化，实际需要同步机制）
    sleep(5);

    // 分离共享内存段
    if (shmdt(shared_memory) == -1) {
        perror("shmdt");
        return 1;
    }

    // 注意：这里没有删除共享内存段，以便其他进程可以访问

    return 0;
}
```

**预期输出 (Process 1):**

```
Process 1 wrote: Hello from process 1!
```

**假设另一个进程 (Process 2) 也使用了相同的 `key` 来访问共享内存:**

**预期输出 (Process 2):**

```
Process 2 read: Hello from process 1!
```

**逻辑推理:**

1. Process 1 调用 `shmget` 创建了一个大小为 1024 字节的共享内存段，键值为 1234。
2. Process 1 调用 `shmat` 将该共享内存段连接到自己的地址空间。
3. Process 1 将字符串 "Hello from process 1!" 写入到共享内存中。
4. 如果另一个进程 (Process 2) 使用相同的键值调用 `shmget`，它将获得相同的共享内存段的标识符。
5. Process 2 调用 `shmat` 后，也可以访问到 Process 1 写入的数据。

**涉及用户或编程常见的使用错误**

1. **忘记处理错误返回值:**  `shmget`, `shmat`, `shmdt`, `shmctl` 在失败时都会返回 -1，并设置 `errno`。程序员需要检查返回值并处理错误情况。
   ```c++
   int shmid = shmget(key, size, flags);
   if (shmid == -1) {
       perror("shmget failed"); // 正确处理错误
       // ... 采取相应的错误处理措施
   }
   ```

2. **权限问题:**  创建共享内存时指定的权限 (`flags` 中的权限位) 决定了哪些用户和进程可以访问它。如果权限设置不当，其他进程可能无法连接到共享内存。

3. **键值冲突:**  如果多个不相关的程序使用相同的键值调用 `shmget`，可能会意外地访问到同一个共享内存段，导致数据混乱。建议使用 `ftok` 函数基于文件路径生成键值，以减少冲突的可能性，或者使用 `IPC_PRIVATE` 创建私有共享内存段。

4. **同步问题:**  共享内存允许多个进程同时访问同一块内存区域。如果没有适当的同步机制（如互斥锁、信号量），可能会出现数据竞争和不一致的问题。
   ```c++
   // 错误示例：多个进程同时写入共享内存，没有同步
   // ... 连接到共享内存 ...
   for (int i = 0; i < 1000; ++i) {
       // 多个进程同时执行，可能导致数据覆盖
       shared_memory[i] = some_value;
   }

   // 正确示例：使用互斥锁进行同步
   pthread_mutex_t* mutex = ...; // 假设互斥锁已初始化并位于共享内存中
   pthread_mutex_lock(mutex);
   for (int i = 0; i < 1000; ++i) {
       shared_memory[i] = some_value;
   }
   pthread_mutex_unlock(mutex);
   ```

5. **资源泄漏:**  创建的共享内存段在不使用后需要显式地删除 (`shmctl` 与 `IPC_RMID`)。如果进程异常退出或忘记删除，共享内存段会一直存在于系统中，占用资源。

6. **连接和分离不匹配:**  每个 `shmat` 调用都应该有对应的 `shmdt` 调用。如果忘记分离，进程退出时操作系统会自动清理，但在进程运行期间会占用进程的地址空间。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

一个典型的调用路径可能是这样的：

1. **Android Framework 或 NDK 组件请求共享内存:**
   - **Framework:**  例如，SurfaceFlinger 服务在分配图形缓冲区时可能会使用共享内存。
   - **NDK:**  应用程序通过 NDK 的 API (例如 `ASharedMemory_create`) 请求创建共享内存。`ASharedMemory_create` 内部会调用底层的 `memfd_create` 或类似的机制。

2. **NDK 层的封装 (如果使用 NDK):**
   - 对于 `ASharedMemory_create`，NDK 提供了 C API 来创建和管理匿名共享内存。虽然 `sys_shm.cpp` 主要处理 System V 风格的共享内存，但匿名共享内存在内核层面也涉及到共享内存的管理。

3. **Bionic libc 函数调用:**
   - 如果代码直接使用 System V 风格的共享内存，会直接调用 `shmget`, `shmat` 等函数。
   - 即使使用 `ASharedMemory_create`，其底层实现最终也会与内核的共享内存管理机制交互。

4. **系统调用:**
   - Bionic libc 的 `sys_shm.cpp` 中的函数会将调用转发给 Linux 内核的相应系统调用 (`SYS_shmget`, `SYS_shmat`, 等)。

5. **内核处理:**
   - Linux 内核接收到系统调用后，会执行相应的操作，例如分配内存、创建共享内存段的元数据、建立地址映射等。

**Frida Hook 示例调试步骤:**

假设我们要 hook `shmget` 函数，查看其参数：

**Frida 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const shmgetPtr = libc.getExportByName("shmget");

  if (shmgetPtr) {
    Interceptor.attach(shmgetPtr, {
      onEnter: function (args) {
        console.log("shmget called");
        console.log("  key:", args[0].toInt());
        console.log("  size:", args[1].toInt());
        console.log("  flags:", args[2].toInt());
      },
      onLeave: function (retval) {
        console.log("shmget returned:", retval.toInt());
      }
    });
  } else {
    console.error("shmget not found in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**使用 Frida 进行调试的步骤：**

1. **确保设备或模拟器已 root，并且安装了 `frida-server`。**
2. **确定要 hook 的目标进程的包名或进程 ID。**
3. **将上面的 Frida 脚本保存为 `hook_shmget.js`。**
4. **使用 Frida 命令运行脚本：**

   ```bash
   frida -U -f <目标应用包名> -l hook_shmget.js
   # 或者，如果已知进程 ID
   frida -p <进程 ID> -l hook_shmget.js
   ```

   将 `<目标应用包名>` 替换为你要监控的应用的包名，例如 `com.example.myapp`。

5. **运行目标应用，当应用调用 `shmget` 时，Frida 将会拦截调用并打印出参数和返回值。**

**Frida Hook 的输出示例：**

```
shmget called
  key: 1234
  size: 1024
  flags: 33
shmget returned: 5
```

这个输出表明 `shmget` 函数被调用了，键值为 1234，大小为 1024 字节，标志位为 33（十进制，对应 `IPC_CREAT | 0666`）。返回值 5 是新创建的共享内存段的标识符。

通过类似的 Frida hook，你可以监控 `shmat`, `shmdt`, `shmctl` 等函数的调用，从而理解 Android framework 或 NDK 是如何在底层使用共享内存的。

总结来说，`bionic/libc/bionic/sys_shm.cpp` 文件在 Android 系统中扮演着重要的角色，它提供了访问共享内存这一核心 IPC 机制的接口。理解其功能和实现细节对于深入理解 Android 系统的工作原理至关重要。

### 提示词
```
这是目录为bionic/libc/bionic/sys_shm.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

#include <sys/shm.h>

#include <sys/syscall.h>
#include <unistd.h>

void* shmat(int id, const void* address, int flags) {
  return reinterpret_cast<void*>(syscall(SYS_shmat, id, address, flags));
}

int shmctl(int id, int cmd, struct shmid_ds* buf) {
#if !defined(__LP64__)
  // Annoyingly, the kernel requires this for 32-bit but rejects it for 64-bit.
  cmd |= IPC_64;
#endif
  return syscall(SYS_shmctl, id, cmd, buf);
}

int shmdt(const void* address) {
  return syscall(SYS_shmdt, address);
}

int shmget(key_t key, size_t size, int flags) {
  return syscall(SYS_shmget, key, size, flags);
}
```