Response:
Let's break down the thought process for answering the request.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided `io_uring.h` header file within the Android bionic context. Key aspects to address are: functionality, relation to Android, libc function implementation details (even though this is a header, the concept applies to the underlying syscalls), dynamic linker aspects (again, more conceptual given it's a header), error handling, and how Android frameworks/NDK reach this code.

**2. Initial Analysis of the Header File:**

The first thing to recognize is that this isn't a *source code* file containing function implementations. It's a *header file*. Header files define data structures, constants, and function prototypes. Therefore, the "implementation details" request will focus on the *purpose* of these definitions, which relate to the underlying system calls.

The file name `io_uring.h` immediately points to the Linux `io_uring` asynchronous I/O framework. The presence of `bionic` in the path signifies its integration into the Android environment.

**3. Deconstructing the Header Content:**

I mentally scan the header, identifying key sections:

* **`struct io_uring_sqe`:** This is the core structure for submitting I/O requests (Submission Queue Entry). I note the various fields and unions, understanding they represent different parameters for different I/O operations.
* **`enum io_uring_sqe_flags_bit` and `#define IOSQE_*`:** These define flags that modify the behavior of individual I/O requests.
* **`#define IORING_SETUP_*`:**  These constants are used when setting up the `io_uring` instance itself.
* **`enum io_uring_op` and `#define IORING_OP_*`:**  This crucial part lists all the supported I/O operations that can be submitted via `io_uring`.
* **`struct io_uring_cqe`:**  This defines the structure for the completion queue entry, which the kernel uses to report the status of completed I/O operations.
* **Offset Definitions (`IORING_OFF_*`):** These are important for memory mapping the shared submission and completion queues.
* **Ring Offset Structures (`io_sqring_offsets`, `io_cqring_offsets`):**  These describe the layout of the shared memory regions.
* **`struct io_uring_params`:** Parameters used during the `io_uring_setup` system call.
* **Feature Flags (`IORING_FEAT_*`):** Capabilities supported by the kernel's `io_uring` implementation.
* **Register Operations (`enum io_uring_register_op`):**  System calls for registering resources (buffers, files, etc.) with the `io_uring` instance.
* **Various other structs:**  These define specific data structures used with certain `io_uring` operations (e.g., `io_uring_files_update`, `io_uring_probe`, etc.).

**4. Addressing Specific Request Points:**

* **Functionality:** I list the core purpose: enabling asynchronous I/O, reducing context switching, and improving performance. I then detail the main components: submission queue, completion queue, and the submission queue entry (`io_uring_sqe`). I also mention the various I/O operations supported.
* **Relationship to Android:** I emphasize that while defined in bionic, it's fundamentally a Linux kernel feature. Its integration in Android allows for more efficient I/O, benefiting apps and the system. I provide concrete examples like file access, network operations, and potentially database interactions.
* **Libc Function Implementation:** Since it's a header, I explain that this *defines* the structures and constants used by libc functions that *wrap* the `io_uring` system calls. I'd mention functions like `syscall(__NR_io_uring_setup, ...)` and similar wrappers (though these aren't explicitly in the header). I then broadly describe how these functions would prepare the structures and invoke the syscalls.
* **Dynamic Linker:**  I explain that this header itself doesn't directly involve the dynamic linker. However, if an application or library *uses* `io_uring`, the corresponding system call wrappers in `libc.so` would be linked. I create a simple `libc.so` layout example, highlighting the `io_uring_setup` symbol. The linking process involves the dynamic linker resolving this symbol at runtime.
* **Logical Reasoning (Assumptions and Outputs):**  I provide an example scenario of submitting a read request, detailing the steps involved, and the expected outcome (completion queue entry).
* **User/Programming Errors:** I list common pitfalls like incorrect setup parameters, invalid file descriptors, and improper handling of completion events.
* **Android Framework/NDK Path:** I illustrate the likely path from Java/Kotlin framework code down to the native layer, involving system calls. I point out the NDK as the bridge for direct usage in native code.
* **Frida Hook Example:** I provide a practical Frida script to intercept the `io_uring_setup` syscall, demonstrating how to inspect arguments and potentially modify behavior.

**5. Structuring the Answer:**

I organize the response using the request's prompts as section headings, ensuring clarity and addressing each point systematically. I use clear, concise language and provide code examples where appropriate (like the Frida script). I emphasize that the header file itself *defines* the interface, and the actual *implementation* resides in the kernel and the corresponding libc wrappers.

**Self-Correction/Refinement During Thought Process:**

* Initially, I might focus too much on the *structure* of the header. I need to shift focus to the *purpose* and *implications* of these definitions in the context of the `io_uring` framework and its use within Android.
* I need to be careful not to confuse header file definitions with actual function implementations. The request asks about implementation, so I need to explain the *conceptual* implementation of the underlying system calls.
* When discussing the dynamic linker, it's important to clarify that the *header itself* isn't linked, but the code *using* these definitions will link against `libc.so`.
* For the Frida example, I ensure it's a practical and illustrative case, focusing on a key `io_uring` function like `io_uring_setup`.

By following this structured approach, breaking down the request, and focusing on the core concepts, I can generate a comprehensive and accurate answer to the complex question.
这是一个名为 `io_uring.h` 的头文件，位于 Android Bionic 库中的内核用户空间 API 目录 `bionic/libc/kernel/uapi/linux/io_uring.handroid bionic` 下。`io_uring` 是 Linux 内核提供的一种新的异步 I/O 框架。此头文件定义了用户空间程序与内核 `io_uring` 子系统交互所需的各种数据结构、常量和宏。

**它的功能:**

这个头文件定义了与 Linux `io_uring` 框架交互的接口。`io_uring` 允许应用程序发起异步 I/O 操作，而无需为每个操作创建独立的线程或使用 `select`/`poll`/`epoll` 等机制。它旨在提高 I/O 密集型应用程序的性能。

主要功能可以概括为：

1. **定义提交队列入口 (Submission Queue Entry, SQE):** `struct io_uring_sqe` 结构体定义了用于向内核提交 I/O 请求的入口。它包含了执行特定 I/O 操作所需的所有信息，例如操作类型、文件描述符、缓冲区地址、长度等。
2. **定义完成队列入口 (Completion Queue Entry, CQE):** `struct io_uring_cqe` 结构体定义了内核向用户空间报告 I/O 操作完成状态的入口。它包含了操作的结果、用户数据等信息。
3. **定义 `io_uring` 的设置参数:** `struct io_uring_params` 结构体定义了用于配置 `io_uring` 实例的参数，例如提交队列和完成队列的大小、标志位等。
4. **定义各种 I/O 操作的类型:** `enum io_uring_op` 枚举定义了 `io_uring` 支持的各种 I/O 操作，例如读、写、同步、文件范围操作、网络操作等。
5. **定义各种标志位和常量:**  例如 `IOSQE_FIXED_FILE`、`IORING_SETUP_SQPOLL`、`IORING_FSYNC_DATASYNC` 等，用于控制 `io_uring` 的行为和特定操作的属性。
6. **定义用于注册资源的结构体:**  例如 `struct io_uring_buf_reg` 用于注册缓冲区，`struct io_uring_files_update` 用于更新已注册的文件描述符。
7. **定义用于探测 `io_uring` 功能的结构体:** `struct io_uring_probe` 用于查询内核 `io_uring` 实现支持的操作。
8. **定义用于设置限制的结构体:** `struct io_uring_restriction` 用于限制可以提交的操作类型或标志位。

**与 Android 功能的关系及举例说明:**

`io_uring` 是 Linux 内核的一个功能，Android 作为基于 Linux 内核的操作系统，自然可以利用这个功能。使用 `io_uring` 可以显著提升 Android 上 I/O 密集型应用程序的性能。

**举例说明：**

* **文件系统操作：** Android 应用程序经常需要读取或写入文件。使用 `io_uring` 可以异步地执行这些操作，避免阻塞主线程，提高应用的响应速度。例如，一个图片加载库可以使用 `IORING_OP_READ` 异步读取图片数据。
* **网络操作：**  网络请求是 Android 应用的常见操作。`io_uring` 提供了 `IORING_OP_SENDMSG` 和 `IORING_OP_RECVMSG` 等操作，可以高效地处理大量的并发网络连接。例如，一个下载管理器可以使用 `io_uring` 并发下载多个文件块。
* **数据库操作：**  一些高性能的数据库可能会利用 `io_uring` 来加速磁盘 I/O 操作。
* **媒体处理：** 音视频的解码和编码过程涉及大量的数据读写，`io_uring` 可以帮助提高效率。

**详细解释每一个 libc 函数的功能是如何实现的:**

**需要注意的是，这个 `io_uring.h` 文件本身** **不是** **libc 函数的实现代码，而是定义了与 `io_uring` 系统调用交互所需的数据结构。**  实际的 libc 函数（例如，封装 `io_uring` 相关系统调用的函数）的实现位于 Bionic 库的其他源文件中。

不过，我们可以解释一下用户空间如何使用这些定义以及对应的系统调用是如何工作的：

1. **`io_uring_setup(unsigned entries, struct io_uring_params *p)`:**
   - **功能：** 创建一个 `io_uring` 实例。
   - **实现：**  这是一个系统调用，最终会陷入内核。内核会分配用于提交队列和完成队列的内存，并将其映射到用户空间。`entries` 参数指定了队列的大小，`p` 参数用于传递额外的配置信息。
2. **`io_uring_enter(unsigned fd, unsigned to_submit, unsigned min_complete, unsigned flags, sigset_t *sig)`:**
   - **功能：**  提交一个或多个 SQE 到内核，并等待至少指定数量的 CQE 完成。
   - **实现：**  这是一个系统调用。用户空间将填充好的 `io_uring_sqe` 结构体放入提交队列中，然后调用此系统调用通知内核。内核会处理提交队列中的请求，并将完成状态写入完成队列。
3. **`io_uring_register(unsigned fd, unsigned opcode, void *arg, unsigned nr_args)`:**
   - **功能：**  注册各种资源到 `io_uring` 实例，例如固定缓冲区、文件等，以优化后续 I/O 操作。
   - **实现：**  这是一个系统调用。内核会根据 `opcode` 和 `arg` 参数注册相应的资源，例如将用户提供的缓冲区地址固定在内存中，或者记录一组文件描述符。
4. **`io_uring_unregister(unsigned fd, unsigned opcode, void *arg)`:**
   - **功能：**  取消注册之前注册的资源。
   - **实现：**  这是一个系统调用，内核会释放之前注册的资源。

**用户空间使用 `io_uring` 的一般流程：**

1. **调用 `io_uring_setup` 创建 `io_uring` 实例。**
2. **在提交队列 (Submission Queue, SQ) 中填充 `io_uring_sqe` 结构体，描述要执行的 I/O 操作。**  这涉及到设置 `opcode`、`fd`、地址、长度等参数。
3. **调用 `io_uring_enter` 系统调用将 SQE 提交到内核。**
4. **内核异步地执行提交的 I/O 操作。**
5. **当 I/O 操作完成时，内核将结果写入完成队列 (Completion Queue, CQ) 的 `io_uring_cqe` 结构体中。**
6. **用户空间可以轮询或等待完成队列，以获取已完成操作的结果。**

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个 `io_uring.h` 头文件本身不直接涉及动态链接。动态链接发生在应用程序或库使用 `io_uring` 相关功能的 libc 函数时。

**so 布局样本 (假设一个使用了 `io_uring` 的库 `libmyuring.so`):**

```
libmyuring.so:
    .text:
        my_async_read_function:  // 自定义的异步读取函数
            ; ... 调用 libc 的 io_uring 相关函数 ...
    .dynsym:
        io_uring_setup  @ LIBC
        io_uring_enter  @ LIBC
        ; ... 其他可能用到的 libc 函数 ...
    .dynamic:
        NEEDED libc.so  // 依赖 libc.so
```

**链接的处理过程：**

1. **编译时链接：**  在编译 `libmyuring.so` 时，编译器会看到代码中使用了 `io_uring_setup` 和 `io_uring_enter` 等函数。由于这些函数通常是 libc 提供的，链接器会将这些符号标记为需要外部提供的符号。
2. **运行时链接：** 当 Android 系统加载 `libmyuring.so` 时，动态链接器 (linker) 会负责解析这些外部符号。
3. **依赖查找：** 动态链接器会检查 `libmyuring.so` 的 `.dynamic` 段，找到其依赖的库 `libc.so`。
4. **符号查找：** 动态链接器会在 `libc.so` 的符号表 (`.dynsym`) 中查找 `io_uring_setup` 和 `io_uring_enter` 等符号的地址。
5. **地址重定位：** 找到符号地址后，动态链接器会将 `libmyuring.so` 中调用这些函数的地方的地址替换为 `libc.so` 中对应函数的实际地址。

**假设输入与输出 (逻辑推理):**

假设我们有一个程序想要异步读取一个文件的前 1024 个字节。

**假设输入：**

* 文件描述符 `fd` 指向要读取的文件。
* 缓冲区 `buf` 的地址和大小（至少 1024 字节）。
* `io_uring` 实例已经通过 `io_uring_setup` 创建。

**输出（执行过程）：**

1. **填充 `io_uring_sqe`：**
   - `opcode` 设置为 `IORING_OP_READ`。
   - `fd` 设置为要读取的文件描述符。
   - `addr` 设置为 `buf` 的地址。
   - `len` 设置为 1024。
   - `user_data` 设置为用户自定义的值，用于在完成时识别此次操作。
2. **调用 `io_uring_enter`：**  将填充好的 SQE 提交给内核。
3. **内核执行读取操作。**
4. **读取完成后，内核创建一个 `io_uring_cqe`：**
   - `user_data` 与提交时 SQE 中的 `user_data` 相同。
   - `res` 设置为读取的字节数（成功）或错误码（失败）。
   - `flags` 包含其他状态信息。
5. **程序从完成队列中获取 CQE，并检查 `res` 的值。** 如果 `res` 大于 0，则表示读取成功，读取的数据在 `buf` 中。

**用户或者编程常见的使用错误，请举例说明:**

1. **未正确初始化 `io_uring` 实例：**  忘记调用 `io_uring_setup` 就尝试提交请求会导致错误。
2. **SQE 参数设置错误：** 例如，传递了无效的文件描述符、缓冲区地址或长度。这会导致 I/O 操作失败。
3. **缓冲区生命周期管理不当：** 提交读取请求后，如果过早地释放了缓冲区，内核在执行读取操作时会访问无效内存。
4. **没有检查 CQE 的结果：**  忽略 CQE 中的 `res` 字段，无法判断 I/O 操作是否成功，可能导致数据错误。
5. **竞争条件：** 在多线程环境中使用 `io_uring` 时，如果没有适当的同步机制，可能会出现竞争条件，导致数据损坏或程序崩溃。
6. **错误地使用固定缓冲区或文件：** 如果注册了固定缓冲区或文件，但在提交请求时没有设置相应的标志位 (`IOSQE_FIXED_FILE`)，会导致错误。
7. **完成队列溢出：** 如果提交了大量的请求，但没有及时处理完成队列，可能会导致完成队列溢出，新的完成事件会被丢弃。

**Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `io_uring` 的路径 (可能的方式，取决于具体实现):**

1. **Java/Kotlin Framework 层:** Android Framework 中的某些组件（例如，负责文件访问、网络操作的组件）可能需要在底层执行高效的 I/O 操作。
2. **JNI 调用:** Framework 层通常会通过 JNI (Java Native Interface) 调用 Native 代码（C/C++）。
3. **NDK 库或自定义 Native 模块:**  NDK 库（例如，一些高性能的网络库或文件操作库）或者应用程序自定义的 Native 模块可能会直接使用 `io_uring` 相关的系统调用。
4. **Bionic libc:**  这些 Native 代码会调用 Bionic libc 提供的系统调用封装函数（例如，`syscall(__NR_io_uring_setup, ...)` 或更高层的封装函数，如果存在）。
5. **`io_uring.h`:**  在编写 Native 代码时，开发者会包含 `io_uring.h` 头文件，以使用其中定义的结构体和常量。
6. **Linux Kernel:**  最终，libc 的系统调用封装函数会触发 Linux 内核的 `io_uring` 子系统执行相应的操作。

**NDK 直接使用 `io_uring` 的路径:**

1. **NDK 应用代码:** 使用 NDK 开发的 Android 应用可以直接在 C/C++ 代码中使用 `io_uring` 相关的系统调用。
2. **包含 `io_uring.h`:** 应用代码会包含此头文件。
3. **系统调用:**  应用代码可以直接使用 `syscall` 函数调用 `io_uring` 相关的系统调用，或者使用一些封装好的库。

**Frida Hook 示例:**

以下是一个使用 Frida hook `io_uring_setup` 系统调用的示例：

```javascript
if (Process.platform === 'linux') {
  const SYSCALL_NUMBER_IO_URING_SETUP = 425; // 不同架构可能不同，需要查阅 syscall 号码
  const io_uring_setup = new NativeFunction(
    Module.findExportByName(null, 'syscall'),
    'int',
    ['int', 'uint', 'pointer']
  );

  Interceptor.attach(io_uring_setup, {
    onEnter: function (args) {
      const syscallNumber = args[0].toInt32();
      if (syscallNumber === SYSCALL_NUMBER_IO_URING_SETUP) {
        console.log('[Frida] io_uring_setup called');
        console.log('[Frida]   entries:', args[1].toInt32());
        console.log('[Frida]   params:', args[2]);

        // 可以进一步解析 io_uring_params 结构体的内容
        const params = ptr(args[2]);
        const sq_entries = params.readU32();
        const cq_entries = params.add(4).readU32();
        console.log('[Frida]     sq_entries:', sq_entries);
        console.log('[Frida]     cq_entries:', cq_entries);
      }
    },
    onLeave: function (retval) {
      if (this.syscallNumber === SYSCALL_NUMBER_IO_URING_SETUP) {
        console.log('[Frida] io_uring_setup returned:', retval.toInt32());
      }
    }
  });
}
```

**解释 Frida Hook 代码：**

1. **检查平台:** 确保代码在 Linux 平台上运行。
2. **定义系统调用号:** `SYSCALL_NUMBER_IO_URING_SETUP` 需要根据目标 Android 设备的架构查找对应的系统调用号。
3. **获取 `syscall` 函数:** 使用 `Module.findExportByName` 获取 `syscall` 函数的地址。
4. **创建 `NativeFunction`:** 将 `syscall` 函数包装成 `NativeFunction`，指定其参数和返回类型。
5. **拦截 `io_uring_setup`:** 使用 `Interceptor.attach` 拦截 `syscall` 函数的调用。
6. **`onEnter` 回调：** 在 `syscall` 函数调用之前执行。
   - 检查系统调用号是否为 `io_uring_setup`。
   - 打印 `io_uring_setup` 的参数，例如队列大小和 `io_uring_params` 结构体的地址。
   - 可以进一步读取 `io_uring_params` 结构体的字段。
7. **`onLeave` 回调：** 在 `syscall` 函数调用之后执行。
   - 打印 `io_uring_setup` 的返回值。

**使用 Frida 进行调试：**

1. 将上述 Frida 脚本保存为 `.js` 文件 (例如 `hook_io_uring.js`)。
2. 找到你想要调试的 Android 进程的进程 ID。
3. 使用 Frida 连接到目标进程并执行脚本：
   ```bash
   frida -U -f <包名> -l hook_io_uring.js --no-pause
   # 或者连接到已经运行的进程
   frida -U <进程ID> -l hook_io_uring.js
   ```

当目标应用程序调用 `io_uring_setup` 时，Frida 会拦截该调用并打印出相关信息，帮助你理解应用程序如何使用 `io_uring`。你可以根据需要修改脚本来 hook 其他 `io_uring` 相关的系统调用或函数，并检查更详细的参数和返回值。

请注意，`io_uring` 是一个相对较新的 Linux 特性，在旧版本的 Android 上可能不可用。同时，直接使用系统调用可能绕过了一些 Android Framework 提供的安全和抽象层，需要谨慎使用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/io_uring.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef LINUX_IO_URING_H
#define LINUX_IO_URING_H
#include <linux/fs.h>
#include <linux/types.h>
#ifndef UAPI_LINUX_IO_URING_H_SKIP_LINUX_TIME_TYPES_H
#include <linux/time_types.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif
struct io_uring_sqe {
  __u8 opcode;
  __u8 flags;
  __u16 ioprio;
  __s32 fd;
  union {
    __u64 off;
    __u64 addr2;
    struct {
      __u32 cmd_op;
      __u32 __pad1;
    };
  };
  union {
    __u64 addr;
    __u64 splice_off_in;
    struct {
      __u32 level;
      __u32 optname;
    };
  };
  __u32 len;
  union {
    __kernel_rwf_t rw_flags;
    __u32 fsync_flags;
    __u16 poll_events;
    __u32 poll32_events;
    __u32 sync_range_flags;
    __u32 msg_flags;
    __u32 timeout_flags;
    __u32 accept_flags;
    __u32 cancel_flags;
    __u32 open_flags;
    __u32 statx_flags;
    __u32 fadvise_advice;
    __u32 splice_flags;
    __u32 rename_flags;
    __u32 unlink_flags;
    __u32 hardlink_flags;
    __u32 xattr_flags;
    __u32 msg_ring_flags;
    __u32 uring_cmd_flags;
    __u32 waitid_flags;
    __u32 futex_flags;
    __u32 install_fd_flags;
    __u32 nop_flags;
  };
  __u64 user_data;
  union {
    __u16 buf_index;
    __u16 buf_group;
  } __attribute__((packed));
  __u16 personality;
  union {
    __s32 splice_fd_in;
    __u32 file_index;
    __u32 optlen;
    struct {
      __u16 addr_len;
      __u16 __pad3[1];
    };
  };
  union {
    struct {
      __u64 addr3;
      __u64 __pad2[1];
    };
    __u64 optval;
    __u8 cmd[0];
  };
};
#define IORING_FILE_INDEX_ALLOC (~0U)
enum io_uring_sqe_flags_bit {
  IOSQE_FIXED_FILE_BIT,
  IOSQE_IO_DRAIN_BIT,
  IOSQE_IO_LINK_BIT,
  IOSQE_IO_HARDLINK_BIT,
  IOSQE_ASYNC_BIT,
  IOSQE_BUFFER_SELECT_BIT,
  IOSQE_CQE_SKIP_SUCCESS_BIT,
};
#define IOSQE_FIXED_FILE (1U << IOSQE_FIXED_FILE_BIT)
#define IOSQE_IO_DRAIN (1U << IOSQE_IO_DRAIN_BIT)
#define IOSQE_IO_LINK (1U << IOSQE_IO_LINK_BIT)
#define IOSQE_IO_HARDLINK (1U << IOSQE_IO_HARDLINK_BIT)
#define IOSQE_ASYNC (1U << IOSQE_ASYNC_BIT)
#define IOSQE_BUFFER_SELECT (1U << IOSQE_BUFFER_SELECT_BIT)
#define IOSQE_CQE_SKIP_SUCCESS (1U << IOSQE_CQE_SKIP_SUCCESS_BIT)
#define IORING_SETUP_IOPOLL (1U << 0)
#define IORING_SETUP_SQPOLL (1U << 1)
#define IORING_SETUP_SQ_AFF (1U << 2)
#define IORING_SETUP_CQSIZE (1U << 3)
#define IORING_SETUP_CLAMP (1U << 4)
#define IORING_SETUP_ATTACH_WQ (1U << 5)
#define IORING_SETUP_R_DISABLED (1U << 6)
#define IORING_SETUP_SUBMIT_ALL (1U << 7)
#define IORING_SETUP_COOP_TASKRUN (1U << 8)
#define IORING_SETUP_TASKRUN_FLAG (1U << 9)
#define IORING_SETUP_SQE128 (1U << 10)
#define IORING_SETUP_CQE32 (1U << 11)
#define IORING_SETUP_SINGLE_ISSUER (1U << 12)
#define IORING_SETUP_DEFER_TASKRUN (1U << 13)
#define IORING_SETUP_NO_MMAP (1U << 14)
#define IORING_SETUP_REGISTERED_FD_ONLY (1U << 15)
#define IORING_SETUP_NO_SQARRAY (1U << 16)
enum io_uring_op {
  IORING_OP_NOP,
  IORING_OP_READV,
  IORING_OP_WRITEV,
  IORING_OP_FSYNC,
  IORING_OP_READ_FIXED,
  IORING_OP_WRITE_FIXED,
  IORING_OP_POLL_ADD,
  IORING_OP_POLL_REMOVE,
  IORING_OP_SYNC_FILE_RANGE,
  IORING_OP_SENDMSG,
  IORING_OP_RECVMSG,
  IORING_OP_TIMEOUT,
  IORING_OP_TIMEOUT_REMOVE,
  IORING_OP_ACCEPT,
  IORING_OP_ASYNC_CANCEL,
  IORING_OP_LINK_TIMEOUT,
  IORING_OP_CONNECT,
  IORING_OP_FALLOCATE,
  IORING_OP_OPENAT,
  IORING_OP_CLOSE,
  IORING_OP_FILES_UPDATE,
  IORING_OP_STATX,
  IORING_OP_READ,
  IORING_OP_WRITE,
  IORING_OP_FADVISE,
  IORING_OP_MADVISE,
  IORING_OP_SEND,
  IORING_OP_RECV,
  IORING_OP_OPENAT2,
  IORING_OP_EPOLL_CTL,
  IORING_OP_SPLICE,
  IORING_OP_PROVIDE_BUFFERS,
  IORING_OP_REMOVE_BUFFERS,
  IORING_OP_TEE,
  IORING_OP_SHUTDOWN,
  IORING_OP_RENAMEAT,
  IORING_OP_UNLINKAT,
  IORING_OP_MKDIRAT,
  IORING_OP_SYMLINKAT,
  IORING_OP_LINKAT,
  IORING_OP_MSG_RING,
  IORING_OP_FSETXATTR,
  IORING_OP_SETXATTR,
  IORING_OP_FGETXATTR,
  IORING_OP_GETXATTR,
  IORING_OP_SOCKET,
  IORING_OP_URING_CMD,
  IORING_OP_SEND_ZC,
  IORING_OP_SENDMSG_ZC,
  IORING_OP_READ_MULTISHOT,
  IORING_OP_WAITID,
  IORING_OP_FUTEX_WAIT,
  IORING_OP_FUTEX_WAKE,
  IORING_OP_FUTEX_WAITV,
  IORING_OP_FIXED_FD_INSTALL,
  IORING_OP_FTRUNCATE,
  IORING_OP_BIND,
  IORING_OP_LISTEN,
  IORING_OP_LAST,
};
#define IORING_URING_CMD_FIXED (1U << 0)
#define IORING_URING_CMD_MASK IORING_URING_CMD_FIXED
#define IORING_FSYNC_DATASYNC (1U << 0)
#define IORING_TIMEOUT_ABS (1U << 0)
#define IORING_TIMEOUT_UPDATE (1U << 1)
#define IORING_TIMEOUT_BOOTTIME (1U << 2)
#define IORING_TIMEOUT_REALTIME (1U << 3)
#define IORING_LINK_TIMEOUT_UPDATE (1U << 4)
#define IORING_TIMEOUT_ETIME_SUCCESS (1U << 5)
#define IORING_TIMEOUT_MULTISHOT (1U << 6)
#define IORING_TIMEOUT_CLOCK_MASK (IORING_TIMEOUT_BOOTTIME | IORING_TIMEOUT_REALTIME)
#define IORING_TIMEOUT_UPDATE_MASK (IORING_TIMEOUT_UPDATE | IORING_LINK_TIMEOUT_UPDATE)
#define SPLICE_F_FD_IN_FIXED (1U << 31)
#define IORING_POLL_ADD_MULTI (1U << 0)
#define IORING_POLL_UPDATE_EVENTS (1U << 1)
#define IORING_POLL_UPDATE_USER_DATA (1U << 2)
#define IORING_POLL_ADD_LEVEL (1U << 3)
#define IORING_ASYNC_CANCEL_ALL (1U << 0)
#define IORING_ASYNC_CANCEL_FD (1U << 1)
#define IORING_ASYNC_CANCEL_ANY (1U << 2)
#define IORING_ASYNC_CANCEL_FD_FIXED (1U << 3)
#define IORING_ASYNC_CANCEL_USERDATA (1U << 4)
#define IORING_ASYNC_CANCEL_OP (1U << 5)
#define IORING_RECVSEND_POLL_FIRST (1U << 0)
#define IORING_RECV_MULTISHOT (1U << 1)
#define IORING_RECVSEND_FIXED_BUF (1U << 2)
#define IORING_SEND_ZC_REPORT_USAGE (1U << 3)
#define IORING_RECVSEND_BUNDLE (1U << 4)
#define IORING_NOTIF_USAGE_ZC_COPIED (1U << 31)
#define IORING_ACCEPT_MULTISHOT (1U << 0)
#define IORING_ACCEPT_DONTWAIT (1U << 1)
#define IORING_ACCEPT_POLL_FIRST (1U << 2)
enum io_uring_msg_ring_flags {
  IORING_MSG_DATA,
  IORING_MSG_SEND_FD,
};
#define IORING_MSG_RING_CQE_SKIP (1U << 0)
#define IORING_MSG_RING_FLAGS_PASS (1U << 1)
#define IORING_FIXED_FD_NO_CLOEXEC (1U << 0)
#define IORING_NOP_INJECT_RESULT (1U << 0)
struct io_uring_cqe {
  __u64 user_data;
  __s32 res;
  __u32 flags;
  __u64 big_cqe[];
};
#define IORING_CQE_F_BUFFER (1U << 0)
#define IORING_CQE_F_MORE (1U << 1)
#define IORING_CQE_F_SOCK_NONEMPTY (1U << 2)
#define IORING_CQE_F_NOTIF (1U << 3)
#define IORING_CQE_F_BUF_MORE (1U << 4)
#define IORING_CQE_BUFFER_SHIFT 16
#define IORING_OFF_SQ_RING 0ULL
#define IORING_OFF_CQ_RING 0x8000000ULL
#define IORING_OFF_SQES 0x10000000ULL
#define IORING_OFF_PBUF_RING 0x80000000ULL
#define IORING_OFF_PBUF_SHIFT 16
#define IORING_OFF_MMAP_MASK 0xf8000000ULL
struct io_sqring_offsets {
  __u32 head;
  __u32 tail;
  __u32 ring_mask;
  __u32 ring_entries;
  __u32 flags;
  __u32 dropped;
  __u32 array;
  __u32 resv1;
  __u64 user_addr;
};
#define IORING_SQ_NEED_WAKEUP (1U << 0)
#define IORING_SQ_CQ_OVERFLOW (1U << 1)
#define IORING_SQ_TASKRUN (1U << 2)
struct io_cqring_offsets {
  __u32 head;
  __u32 tail;
  __u32 ring_mask;
  __u32 ring_entries;
  __u32 overflow;
  __u32 cqes;
  __u32 flags;
  __u32 resv1;
  __u64 user_addr;
};
#define IORING_CQ_EVENTFD_DISABLED (1U << 0)
#define IORING_ENTER_GETEVENTS (1U << 0)
#define IORING_ENTER_SQ_WAKEUP (1U << 1)
#define IORING_ENTER_SQ_WAIT (1U << 2)
#define IORING_ENTER_EXT_ARG (1U << 3)
#define IORING_ENTER_REGISTERED_RING (1U << 4)
#define IORING_ENTER_ABS_TIMER (1U << 5)
struct io_uring_params {
  __u32 sq_entries;
  __u32 cq_entries;
  __u32 flags;
  __u32 sq_thread_cpu;
  __u32 sq_thread_idle;
  __u32 features;
  __u32 wq_fd;
  __u32 resv[3];
  struct io_sqring_offsets sq_off;
  struct io_cqring_offsets cq_off;
};
#define IORING_FEAT_SINGLE_MMAP (1U << 0)
#define IORING_FEAT_NODROP (1U << 1)
#define IORING_FEAT_SUBMIT_STABLE (1U << 2)
#define IORING_FEAT_RW_CUR_POS (1U << 3)
#define IORING_FEAT_CUR_PERSONALITY (1U << 4)
#define IORING_FEAT_FAST_POLL (1U << 5)
#define IORING_FEAT_POLL_32BITS (1U << 6)
#define IORING_FEAT_SQPOLL_NONFIXED (1U << 7)
#define IORING_FEAT_EXT_ARG (1U << 8)
#define IORING_FEAT_NATIVE_WORKERS (1U << 9)
#define IORING_FEAT_RSRC_TAGS (1U << 10)
#define IORING_FEAT_CQE_SKIP (1U << 11)
#define IORING_FEAT_LINKED_FILE (1U << 12)
#define IORING_FEAT_REG_REG_RING (1U << 13)
#define IORING_FEAT_RECVSEND_BUNDLE (1U << 14)
#define IORING_FEAT_MIN_TIMEOUT (1U << 15)
enum io_uring_register_op {
  IORING_REGISTER_BUFFERS = 0,
  IORING_UNREGISTER_BUFFERS = 1,
  IORING_REGISTER_FILES = 2,
  IORING_UNREGISTER_FILES = 3,
  IORING_REGISTER_EVENTFD = 4,
  IORING_UNREGISTER_EVENTFD = 5,
  IORING_REGISTER_FILES_UPDATE = 6,
  IORING_REGISTER_EVENTFD_ASYNC = 7,
  IORING_REGISTER_PROBE = 8,
  IORING_REGISTER_PERSONALITY = 9,
  IORING_UNREGISTER_PERSONALITY = 10,
  IORING_REGISTER_RESTRICTIONS = 11,
  IORING_REGISTER_ENABLE_RINGS = 12,
  IORING_REGISTER_FILES2 = 13,
  IORING_REGISTER_FILES_UPDATE2 = 14,
  IORING_REGISTER_BUFFERS2 = 15,
  IORING_REGISTER_BUFFERS_UPDATE = 16,
  IORING_REGISTER_IOWQ_AFF = 17,
  IORING_UNREGISTER_IOWQ_AFF = 18,
  IORING_REGISTER_IOWQ_MAX_WORKERS = 19,
  IORING_REGISTER_RING_FDS = 20,
  IORING_UNREGISTER_RING_FDS = 21,
  IORING_REGISTER_PBUF_RING = 22,
  IORING_UNREGISTER_PBUF_RING = 23,
  IORING_REGISTER_SYNC_CANCEL = 24,
  IORING_REGISTER_FILE_ALLOC_RANGE = 25,
  IORING_REGISTER_PBUF_STATUS = 26,
  IORING_REGISTER_NAPI = 27,
  IORING_UNREGISTER_NAPI = 28,
  IORING_REGISTER_CLOCK = 29,
  IORING_REGISTER_CLONE_BUFFERS = 30,
  IORING_REGISTER_LAST,
  IORING_REGISTER_USE_REGISTERED_RING = 1U << 31
};
enum io_wq_type {
  IO_WQ_BOUND,
  IO_WQ_UNBOUND,
};
struct io_uring_files_update {
  __u32 offset;
  __u32 resv;
  __aligned_u64 fds;
};
#define IORING_RSRC_REGISTER_SPARSE (1U << 0)
struct io_uring_rsrc_register {
  __u32 nr;
  __u32 flags;
  __u64 resv2;
  __aligned_u64 data;
  __aligned_u64 tags;
};
struct io_uring_rsrc_update {
  __u32 offset;
  __u32 resv;
  __aligned_u64 data;
};
struct io_uring_rsrc_update2 {
  __u32 offset;
  __u32 resv;
  __aligned_u64 data;
  __aligned_u64 tags;
  __u32 nr;
  __u32 resv2;
};
#define IORING_REGISTER_FILES_SKIP (- 2)
#define IO_URING_OP_SUPPORTED (1U << 0)
struct io_uring_probe_op {
  __u8 op;
  __u8 resv;
  __u16 flags;
  __u32 resv2;
};
struct io_uring_probe {
  __u8 last_op;
  __u8 ops_len;
  __u16 resv;
  __u32 resv2[3];
  struct io_uring_probe_op ops[];
};
struct io_uring_restriction {
  __u16 opcode;
  union {
    __u8 register_op;
    __u8 sqe_op;
    __u8 sqe_flags;
  };
  __u8 resv;
  __u32 resv2[3];
};
struct io_uring_clock_register {
  __u32 clockid;
  __u32 __resv[3];
};
enum {
  IORING_REGISTER_SRC_REGISTERED = 1,
};
struct io_uring_clone_buffers {
  __u32 src_fd;
  __u32 flags;
  __u32 pad[6];
};
struct io_uring_buf {
  __u64 addr;
  __u32 len;
  __u16 bid;
  __u16 resv;
};
struct io_uring_buf_ring {
  union {
    struct {
      __u64 resv1;
      __u32 resv2;
      __u16 resv3;
      __u16 tail;
    };
    __DECLARE_FLEX_ARRAY(struct io_uring_buf, bufs);
  };
};
enum io_uring_register_pbuf_ring_flags {
  IOU_PBUF_RING_MMAP = 1,
  IOU_PBUF_RING_INC = 2,
};
struct io_uring_buf_reg {
  __u64 ring_addr;
  __u32 ring_entries;
  __u16 bgid;
  __u16 flags;
  __u64 resv[3];
};
struct io_uring_buf_status {
  __u32 buf_group;
  __u32 head;
  __u32 resv[8];
};
struct io_uring_napi {
  __u32 busy_poll_to;
  __u8 prefer_busy_poll;
  __u8 pad[3];
  __u64 resv;
};
enum io_uring_register_restriction_op {
  IORING_RESTRICTION_REGISTER_OP = 0,
  IORING_RESTRICTION_SQE_OP = 1,
  IORING_RESTRICTION_SQE_FLAGS_ALLOWED = 2,
  IORING_RESTRICTION_SQE_FLAGS_REQUIRED = 3,
  IORING_RESTRICTION_LAST
};
struct io_uring_getevents_arg {
  __u64 sigmask;
  __u32 sigmask_sz;
  __u32 min_wait_usec;
  __u64 ts;
};
struct io_uring_sync_cancel_reg {
  __u64 addr;
  __s32 fd;
  __u32 flags;
  struct __kernel_timespec timeout;
  __u8 opcode;
  __u8 pad[7];
  __u64 pad2[3];
};
struct io_uring_file_index_range {
  __u32 off;
  __u32 len;
  __u64 resv;
};
struct io_uring_recvmsg_out {
  __u32 namelen;
  __u32 controllen;
  __u32 payloadlen;
  __u32 flags;
};
enum io_uring_socket_op {
  SOCKET_URING_OP_SIOCINQ = 0,
  SOCKET_URING_OP_SIOCOUTQ,
  SOCKET_URING_OP_GETSOCKOPT,
  SOCKET_URING_OP_SETSOCKOPT,
};
#ifdef __cplusplus
}
#endif
#endif
```