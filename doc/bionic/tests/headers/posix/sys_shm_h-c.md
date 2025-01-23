Response:
Let's break down the thought process for answering the request. The core request is to analyze a header file test in Android's Bionic library. This means understanding what the code does and how it relates to the larger Android system.

**1. Deconstructing the Request:**

I identified the key components of the request:

* **Functionality:** What does this specific C file do?
* **Android Relevance:** How does it fit into Android's overall functionality?
* **libc Function Details:** Explanation of the `shm*` functions.
* **Dynamic Linker:**  How does this interact with the dynamic linker? (This required careful consideration as the test file itself *doesn't* directly involve dynamic linking, but the underlying `shm*` functions *do*).
* **Logic/Assumptions:** Any inferred behaviors or dependencies.
* **Common Errors:** Potential pitfalls for developers.
* **Android Framework/NDK Path:** How a call might originate.
* **Frida Hook:**  A practical debugging example.

**2. Analyzing the Code:**

I carefully examined the provided C code. I noticed it's a test file (`bionic/tests/headers/...`). The core logic revolves around:

* **Header Inclusion:** `#include <sys/shm.h>` - This tells us it's testing the `sys/shm.h` header file.
* **Conditional Compilation:** `#if defined(__BIONIC__)` -  Confirms it's specific to the Bionic library.
* **`header_checks.h`:**  Implies the existence of macros like `MACRO`, `TYPE`, and `STRUCT_MEMBER`, and `FUNCTION` which are used for testing the presence and structure of elements defined in `sys/shm.h`.
* **Macros:** `MACRO(SHM_RDONLY)`, `MACRO(SHM_RND)`, `MACRO(SHMLBA)` - These check if these constants are defined in the header.
* **Types:** `TYPE(shmatt_t)`, `TYPE(struct shmid_ds)`, `TYPE(pid_t)`, `TYPE(size_t)`, `TYPE(time_t)` - These check if these types are defined.
* **Structure Members:** `STRUCT_MEMBER(...)` - These check for the existence and type of members within the `struct shmid_ds`. The `#if defined(__LP64__)` block is important, indicating architecture-specific definitions.
* **Functions:** `FUNCTION(shmat, ...)` etc. - These check if these functions are declared in the header with the correct signature.

**3. Connecting to Android Functionality:**

The core functionality being tested is shared memory. I knew shared memory is a fundamental inter-process communication (IPC) mechanism. I brainstormed where this might be used in Android:

* **SurfaceFlinger:** Manages display buffers (a likely use case for shared memory).
* **Zygote:**  Process forking relies on efficient memory sharing.
* **Native Daemons:**  Might use shared memory for data exchange.
* **AIDL:** While not directly using `shm*`, it represents a higher-level IPC mechanism that *could* potentially be implemented using shared memory at a lower level.

**4. Explaining libc Functions:**

For each `shm*` function, I recalled their purpose and tried to explain the core implementation steps (at a high level, without going into kernel details):

* **`shmget`:** Creating or accessing a shared memory segment. Involves checking for existing segments, allocating memory, and creating a kernel object.
* **`shmat`:** Attaching the shared memory segment to a process's address space. This involves mapping the kernel object into the process's virtual memory.
* **`shmdt`:** Detaching the shared memory segment. Removes the mapping from the process's address space.
* **`shmctl`:** Performing control operations. This is a broad function involving various actions like getting status, setting permissions, or destroying the segment.

**5. Addressing the Dynamic Linker:**

This was the trickiest part. The *test file itself* doesn't link against anything. However, the *`shm*` functions themselves* are part of libc, which is dynamically linked. My thought process was:

* **Recognize the Indirection:** The test checks the *header*, not the implementation. The implementation resides in `libc.so`.
* **Create a Sample SO Layout:**  Imagine `libc.so` with `shmget`, `shmat`, etc., exported. Another SO, `libMySharedMem.so`, might *use* these functions.
* **Describe the Linking Process:**  The dynamic linker finds the definitions in `libc.so` and resolves the symbols during loading.

**6. Logic/Assumptions, Common Errors:**

These were relatively straightforward. I considered typical usage scenarios and common mistakes related to shared memory:

* **Permissions:**  Incorrect permissions leading to access issues.
* **Key Collisions:**  Multiple processes accidentally using the same key.
* **Forgetting to Detach:**  Leading to resource leaks.
* **Size Mismatches:**  Incorrectly calculating or handling the shared memory size.

**7. Android Framework/NDK Path:**

I traced a hypothetical path:

* **Framework:** A higher-level service might need IPC.
* **AIDL:**  A common way to define inter-process interfaces.
* **Binder:**  The underlying IPC mechanism for AIDL, which *could* potentially use shared memory for large data transfers (though it doesn't directly expose `shm*`).
* **NDK:**  Direct access to POSIX shared memory functions.

**8. Frida Hook:**

I devised a simple Frida hook targeting `shmget` to demonstrate how to intercept and inspect calls to these functions.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe the test directly links against something. **Correction:** Realized it's just a header test, so linking is indirect via `libc.so`.
* **Overly complex linking example:** Initially thought of more involved linking scenarios. **Correction:** Simplified to a basic dependency on `libc.so`.
* **Focus on the Test:**  Kept reminding myself that the primary focus is *testing the header*, even though understanding the underlying functionality is crucial for a complete answer.

By following this systematic approach, combining code analysis with knowledge of the Android ecosystem and common programming practices, I could generate a comprehensive and accurate response to the detailed request.
这个文件 `bionic/tests/headers/posix/sys_shm_h.c` 是 Android Bionic 库中的一个测试文件，它的主要功能是**验证 `sys/shm.h` 头文件是否按照 POSIX 标准正确定义了相关的宏、类型和函数声明**。  换句话说，它不是一个实际执行共享内存操作的代码，而是用来确保 Android 的 C 标准库正确提供了共享内存的接口。

**功能列举:**

1. **检查宏定义:**  验证 `SHM_RDONLY`, `SHM_RND`, `SHMLBA` 等宏是否在 `sys/shm.h` 中被定义。
2. **检查类型定义:** 验证 `shmatt_t`, `struct shmid_ds`, `pid_t`, `size_t`, `time_t` 等类型是否在 `sys/shm.h` 中被定义。
3. **检查结构体成员:** 验证 `struct shmid_ds` 结构体是否包含预期的成员，例如 `shm_perm`, `shm_segsz`, `shm_lpid` 等，并检查它们的类型是否正确。特别注意对于 32 位和 64 位架构，`shm_atime`, `shm_dtime`, `shm_ctime` 的类型定义可能不同。
4. **检查函数声明:** 验证 `shmat`, `shmctl`, `shmdt`, `shmget` 等共享内存相关的函数是否在 `sys/shm.h` 中被声明，并检查它们的函数签名（参数和返回值类型）是否正确。

**与 Android 功能的关系及举例说明:**

共享内存是一种重要的进程间通信 (IPC) 机制。Android 系统和应用程序在很多场景下会使用共享内存来实现高效的数据共享。

* **SurfaceFlinger:** Android 的 SurfaceFlinger 服务负责管理屏幕上的所有图形缓冲区。  它很可能使用共享内存来与应用程序共享图形数据，这样应用程序可以直接将渲染好的帧写入共享内存，而 SurfaceFlinger 可以直接读取并显示，避免了昂贵的内存拷贝。
* **Zygote 进程:**  Android 的 Zygote 进程是所有应用程序进程的父进程。当 Zygote fork 新的应用程序进程时，会使用写时复制 (copy-on-write) 技术来共享内存页，这在某种程度上可以看作是共享内存的优化应用。虽然不直接使用 `shm*` 函数，但其原理与共享内存相关。
* **Native 守护进程:**  一些 Android 的原生守护进程 (native daemons) 可能使用共享内存来进行数据交换，例如音频服务器、媒体服务器等。
* **AIDL (Android Interface Definition Language):** 虽然 AIDL 主要使用 Binder 进行进程间通信，但在某些情况下，对于大数据量的传输，底层的 Binder 驱动可能会利用共享内存来提高效率。

**详细解释每一个 libc 函数的功能是如何实现的:**

这些函数的具体实现位于 Android Bionic 库 (libc.so) 的源代码中，并最终由 Linux 内核提供支持。以下是简要的解释：

1. **`shmget(key_t key, size_t size, int shmflg)`:**
   * **功能:**  获取一个共享内存段标识符 (shmid)。如果指定的 `key` 对应的共享内存段不存在，且 `shmflg` 中设置了 `IPC_CREAT` 标志，则创建一个新的共享内存段。
   * **实现:**
      * **参数校验:** 检查 `size` 是否有效（通常大于 0）。
      * **键值查找:**  使用提供的 `key` 在内核维护的共享内存段列表中查找是否已存在对应的段。
      * **创建新段 (如果需要):** 如果未找到且指定创建，则内核会分配一块大小为 `size` 的内存区域，并创建一个表示该共享内存段的内核对象，将 `key` 与该对象关联。`shmflg` 中可以指定权限等属性。
      * **返回 shmid:** 返回新创建或已存在的共享内存段的唯一标识符 (shmid)。如果出错，返回 -1 并设置 `errno`。

2. **`shmat(int shmid, const void *shmaddr, int shmflg)`:**
   * **功能:** 将 `shmid` 指定的共享内存段连接到调用进程的地址空间。
   * **实现:**
      * **参数校验:** 检查 `shmid` 是否有效。
      * **查找共享内存段:** 根据 `shmid` 查找对应的内核共享内存段对象。
      * **内存映射:**  在调用进程的虚拟地址空间中找到一块合适的空闲区域（或者使用 `shmaddr` 指定的地址，如果可行），将共享内存段的物理页映射到该虚拟地址区域。`shmflg` 可以指定连接的权限，例如 `SHM_RDONLY` 表示只读连接。
      * **返回地址:** 返回共享内存段在调用进程地址空间中的起始地址。如果出错，返回 `(void *) -1` 并设置 `errno`。

3. **`shmdt(const void *shmaddr)`:**
   * **功能:**  将先前用 `shmat` 连接的共享内存段从调用进程的地址空间分离。
   * **实现:**
      * **参数校验:** 检查 `shmaddr` 是否是先前通过 `shmat` 返回的有效地址。
      * **取消映射:**  从调用进程的页表中移除与共享内存段相关的映射关系。这并不意味着销毁共享内存段，只是当前进程不再访问它。
      * **更新引用计数:**  内核会维护共享内存段的连接计数，当一个进程分离时，计数会减 1。
      * **返回值:** 成功返回 0，出错返回 -1 并设置 `errno`。

4. **`shmctl(int shmid, int cmd, struct shmid_ds *buf)`:**
   * **功能:** 对 `shmid` 指定的共享内存段执行各种控制操作。
   * **实现:**  根据 `cmd` 参数执行不同的操作，常见的包括：
      * **`IPC_STAT`:** 获取共享内存段的状态信息，并将信息填充到 `buf` 指向的 `struct shmid_ds` 结构体中，例如权限、大小、连接进程数等。
      * **`IPC_SET`:** 设置共享内存段的某些属性，例如权限（需要有足够的权限）。
      * **`IPC_RMID`:** 标记删除共享内存段。只有当所有连接到该段的进程都分离后，内核才会真正释放该段占用的内存。
      * **参数校验:** 检查 `shmid` 和 `cmd` 是否有效，以及调用进程是否有执行指定操作的权限。
      * **内核操作:**  根据 `cmd` 调用相应的内核函数来修改或查询共享内存段的状态。
      * **返回值:** 成功返回 0，出错返回 -1 并设置 `errno`。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

尽管 `sys_shm_h.c` 本身是一个测试头文件的代码，不涉及动态链接，但实际使用共享内存的程序会链接到 `libc.so`，其中包含了 `shm*` 函数的实现。

**so 布局样本 (简化):**

假设我们有一个名为 `libMySharedMem.so` 的动态库，它使用了共享内存：

```
# libMySharedMem.so

.text        # 代码段
    my_shm_function:
        ; 调用 shmget, shmat 等函数
        call    shmget@plt
        call    shmat@plt
        ; ...

.plt         # 过程链接表 (Procedure Linkage Table)
    shmget@plt:
        ; 跳转到 .got.plt 中 shmget 的地址
        jmp     *[.got.plt + shmget_offset]

    shmat@plt:
        ; 跳转到 .got.plt 中 shmat 的地址
        jmp     *[.got.plt + shmat_offset]

.got.plt     # 全局偏移表 (Global Offset Table) - PLT 部分
    shmget_addr:  0x0  ; 初始值为 0，由 linker 填充
    shmat_addr:   0x0  ; 初始值为 0，由 linker 填充

.dynsym      # 动态符号表
    shmget (FUNC):  # 标记需要从其他库链接的符号
    shmat  (FUNC):

.dynamic     # 动态链接信息
    NEEDED libc.so  # 声明依赖于 libc.so
    ; ...
```

**链接的处理过程:**

1. **编译时链接 (Static Linking):** 编译器在编译 `libMySharedMem.so` 时，看到对 `shmget` 和 `shmat` 的调用，由于这些函数在 `libc.so` 中定义，编译器会在 `.dynsym` 中记录这些需要动态链接的符号，并在 `.plt` 和 `.got.plt` 中生成相应的条目。`.got.plt` 中的初始地址为 0。
2. **加载时链接 (Dynamic Linking):** 当 Android 系统加载 `libMySharedMem.so` 时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下步骤：
   * **加载依赖库:**  根据 `libMySharedMem.so` 的 `.dynamic` 段中的 `NEEDED` 条目，加载 `libc.so` 到内存中。
   * **符号解析:** 遍历 `libMySharedMem.so` 的 `.dynsym` 段，找到需要解析的外部符号（例如 `shmget`, `shmat`）。
   * **查找符号定义:** 在已加载的共享库（包括 `libc.so`）的符号表中查找这些符号的定义。动态链接器会在 `libc.so` 的符号表中找到 `shmget` 和 `shmat` 的地址。
   * **重定位 (Relocation):** 将找到的 `shmget` 和 `shmat` 的实际地址填充到 `libMySharedMem.so` 的 `.got.plt` 中对应的条目。
   * **PLT 的作用:** 当程序第一次调用 `shmget` 时，会跳转到 `shmget@plt`。`shmget@plt` 中的指令会跳转到 `.got.plt` 中 `shmget_addr` 的位置。由于动态链接器已经填充了正确的地址，所以程序会跳转到 `libc.so` 中 `shmget` 函数的实际地址并执行。后续的调用会直接跳转到 `.got.plt` 中的地址，避免了重复的符号解析。

**如果做了逻辑推理，请给出假设输入与输出:**

由于 `sys_shm_h.c` 是一个测试文件，它的“输入”是 `sys/shm.h` 头文件的内容，“输出”是测试结果（通过或失败）。

**假设输入:**  `sys/shm.h` 文件内容如下（部分）：

```c
#ifndef _SYS_SHM_H
#define _SYS_SHM_H

#include <sys/types.h>
#include <bits/ipc.h>
#include <time.h>

#define SHM_RDONLY 010000
#define SHM_RND    020000
#define SHMLBA     04000000

typedef unsigned long shmatt_t;

struct shmid_ds {
  struct ipc_perm shm_perm;
  size_t          shm_segsz;
  pid_t           shm_lpid;
  pid_t           shm_cpid;
  shmatt_t        shm_nattch;
  time_t          shm_atime;
  time_t          shm_dtime;
  time_t          shm_ctime;
};

extern void *shmat(int __shmid, const void *__shmaddr, int __shmflg);
extern int shmctl(int __shmid, int __cmd, struct shmid_ds *__buf);
extern int shmdt(const void *__shmaddr);
extern int shmget(key_t __key, size_t __size, int __shmflg);

#endif
```

**预期输出:**  `sys_shm_h.c` 中的测试应该全部通过，因为它验证了上述头文件中定义的宏、类型、结构体成员和函数声明与预期一致。  如果头文件缺少某些定义或类型不匹配，测试将会失败。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **权限问题:**  尝试访问或操作一个没有足够权限的共享内存段。例如，尝试连接一个只读的共享内存段进行写入操作，或者尝试删除一个不属于当前用户的共享内存段。

   ```c
   // 假设 shmid 是一个只读共享内存段的 ID
   void *addr = shmat(shmid, NULL, 0); // 连接成功
   if (addr != (void*)-1) {
       strcpy((char*)addr, "写入数据"); // 错误：尝试写入只读内存
   }
   ```

2. **忘记分离:**  在进程退出前没有调用 `shmdt` 分离共享内存段。虽然操作系统最终会清理这些资源，但这可能导致资源泄漏，特别是在频繁创建和销毁共享内存段的场景下。

   ```c
   int shmid = shmget(IPC_PRIVATE, 1024, IPC_CREAT | 0666);
   void *addr = shmat(shmid, NULL, 0);
   // ... 使用共享内存 ...
   // 忘记调用 shmdt(addr);  <-- 潜在的资源泄漏
   // 进程退出
   ```

3. **键值冲突:**  多个不相关的进程使用了相同的 `key` 来创建共享内存段，导致意外的数据共享或相互干扰。应该使用 `IPC_PRIVATE` 来创建只能被父子进程共享的共享内存段，或者使用更复杂的命名约定来避免键值冲突。

   ```c
   // 进程 A
   key_t key = 1234;
   int shmid_a = shmget(key, 1024, IPC_CREAT | 0666);
   // 进程 B (可能由不同的开发者编写)
   key_t key = 1234; // 相同的 key
   int shmid_b = shmget(key, 2048, IPC_CREAT | 0666); // 可能会访问到进程 A 创建的共享内存
   ```

4. **大小不匹配:**  在不同的进程中使用不同的大小来访问同一个共享内存段，可能导致越界访问或其他未定义的行为。

   ```c
   // 进程 1 创建了一个 1024 字节的共享内存
   int shmid = shmget(IPC_PRIVATE, 1024, IPC_CREAT | 0666);
   void *addr1 = shmat(shmid, NULL, 0);
   // 进程 2 连接到同一个共享内存，但假设它的大小是 2048 字节
   void *addr2 = shmat(shmid, NULL, 0);
   // 进程 2 可能会写入超出实际分配大小的内存
   memset(addr2, 0, 2048); // 错误：可能导致内存越界
   ```

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 使用 (间接):**
   * Android Framework 的某些服务，例如 SurfaceFlinger，在底层可能使用共享内存来管理图形缓冲区。这些服务通常是用 Java 编写的，并通过 JNI (Java Native Interface) 调用到底层的 C/C++ 代码。
   * 例如，一个 Java 层的 `Surface` 对象最终会关联到一个 Native 层的 `ANativeWindow`，而 `ANativeWindow` 的实现可能会涉及到使用共享内存来存储图形缓冲区。

2. **NDK 使用 (直接):**
   * 通过 Android NDK (Native Development Kit)，开发者可以直接在 C/C++ 代码中使用 POSIX 共享内存 API (`shmget`, `shmat`, `shmdt`, `shmctl`).
   * 一个典型的 NDK 应用流程可能是这样的：
      * Java 代码通过 JNI 调用 Native 方法。
      * Native 方法中使用 `shmget` 创建或获取一个共享内存段。
      * 使用 `shmat` 将共享内存段连接到进程的地址空间。
      * 在多个 Native 进程之间共享数据。
      * 使用 `shmdt` 分离共享内存段。
      * 使用 `shmctl` 删除共享内存段。

**Frida Hook 示例:**

以下是一个使用 Frida hook 拦截 `shmget` 函数调用的示例：

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const shmgetPtr = libc.getExportByName("shmget");

  if (shmgetPtr) {
    Interceptor.attach(shmgetPtr, {
      onEnter: function (args) {
        console.log("[shmget] Called");
        console.log("  key:", args[0]);
        console.log("  size:", args[1]);
        console.log("  shmflg:", args[2]);
      },
      onLeave: function (retval) {
        console.log("  Return value:", retval);
        if (retval.toInt32() === -1) {
          console.log("  Error:", Process.getModuleByName("libc.so").getExportByName("__errno_location").readPointer().readS32());
        }
      }
    });
  } else {
    console.log("shmget not found in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**使用步骤：**

1. **保存脚本:** 将上述 JavaScript 代码保存为例如 `shmget_hook.js`。
2. **运行 Frida Server:** 在 Android 设备上运行 Frida Server。
3. **运行目标应用:** 运行你想要调试的 Android 应用或进程。
4. **执行 Frida 命令:** 在你的电脑上使用 Frida 命令来附加到目标进程并执行 hook 脚本：

   ```bash
   frida -U -f <your_package_name> -l shmget_hook.js --no-pause
   # 或者，如果进程已经在运行：
   frida -U <process_name_or_pid> -l shmget_hook.js
   ```

   将 `<your_package_name>` 替换为你的应用的包名，或者 `<process_name_or_pid>` 替换为进程名称或 PID。

**Frida Hook 输出示例:**

当目标应用调用 `shmget` 函数时，Frida 会拦截调用并打印相关信息：

```
[Pixel 6::com.example.myapp]-> [shmget] Called
[Pixel 6::com.example.myapp]->   key: 0
[Pixel 6::com.example.myapp]->   size: 1024
[Pixel 6::com.example.myapp]->   shmflg: 384 (IPC_CREAT | 0600)
[Pixel 6::com.example.myapp]->   Return value: 123456789
```

如果 `shmget` 调用失败，你还会看到错误码：

```
[Pixel 6::com.example.myapp]-> [shmget] Called
[Pixel 6::com.example.myapp]->   key: 1234
[Pixel 6::com.example.myapp]->   size: 1024
[Pixel 6::com.example.myapp]->   shmflg: 0
[Pixel 6::com.example.myapp]->   Return value: -1
[Pixel 6::com.example.myapp]->   Error: 2 (ENOENT)
```

通过类似的 Frida hook 技术，你可以拦截和分析 `shmat`, `shmdt`, `shmctl` 等函数的调用，从而理解 Android Framework 或 NDK 应用是如何使用共享内存的。 你可以通过修改 `onEnter` 和 `onLeave` 中的代码来检查参数值、返回值以及其他相关上下文信息。

### 提示词
```
这是目录为bionic/tests/headers/posix/sys_shm_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
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

#if defined(__BIONIC__)

#include <sys/shm.h>

#include "header_checks.h"

static void sys_shm_h() {
  MACRO(SHM_RDONLY);
  MACRO(SHM_RND);
  MACRO(SHMLBA);

  TYPE(shmatt_t);

  TYPE(struct shmid_ds);
  STRUCT_MEMBER(struct shmid_ds, struct ipc_perm, shm_perm);
  STRUCT_MEMBER(struct shmid_ds, size_t, shm_segsz);
  STRUCT_MEMBER(struct shmid_ds, pid_t, shm_lpid);
  STRUCT_MEMBER(struct shmid_ds, pid_t, shm_cpid);
  STRUCT_MEMBER(struct shmid_ds, shmatt_t, shm_nattch);
#if defined(__LP64__)
  STRUCT_MEMBER(struct shmid_ds, time_t, shm_atime);
  STRUCT_MEMBER(struct shmid_ds, time_t, shm_dtime);
  STRUCT_MEMBER(struct shmid_ds, time_t, shm_ctime);
#else
  // Starting at kernel v4.19, 32 bit changed these to unsigned values.
  STRUCT_MEMBER(struct shmid_ds, unsigned long, shm_atime);
  STRUCT_MEMBER(struct shmid_ds, unsigned long, shm_dtime);
  STRUCT_MEMBER(struct shmid_ds, unsigned long, shm_ctime);
#endif

  TYPE(pid_t);
  TYPE(size_t);
  TYPE(time_t);

  FUNCTION(shmat, void* (*f)(int, const void*, int));
  FUNCTION(shmctl, int (*f)(int, int, struct shmid_ds*));
  FUNCTION(shmdt, int (*f)(const void*));
  FUNCTION(shmget, int (*f)(key_t, size_t, int));
}
#endif
```