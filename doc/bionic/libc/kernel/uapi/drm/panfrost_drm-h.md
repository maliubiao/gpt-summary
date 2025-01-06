Response:
Let's break down the thought process for analyzing the provided header file and generating the comprehensive response.

**1. Understanding the Context:**

The first and most crucial step is understanding *what* this file is and *where* it comes from. The initial description provides this: "bionic/libc/kernel/uapi/drm/panfrost_drm.handroid bionic is Android's C library, math library, and dynamic linker." This immediately tells us:

* **Bionic:**  This is Android's core C library. Anything here is low-level and related to system calls or kernel interfaces.
* **`libc/kernel/uapi`:** This path signifies that the file defines *userspace Application Programming Interfaces (APIs)* for interacting with the *kernel*. Specifically, it's under `drm`, which points to the Direct Rendering Manager, a Linux kernel subsystem for managing graphics hardware.
* **`panfrost_drm.h`:** This clearly indicates it's the DRM interface for a specific GPU driver named "Panfrost." This driver is likely for Mali GPUs, as Panfrost is an open-source reverse-engineered driver for them.
* **`.handroid`:** This suffix is a strong hint that the file is specific to Android and may have Android-specific adaptations.

**2. Identifying the Core Functionality:**

The next step is to scan the file for key elements that reveal its purpose. The most prominent features are:

* **`#define` constants starting with `DRM_PANFROST_`:** These are the core commands (IOCTLs) that userspace programs can send to the Panfrost DRM driver in the kernel. Each defines a specific operation.
* **`struct drm_panfrost_*`:** These are data structures that are passed as arguments to the IOCTLs. They define the input and output data for each command.
* **`enum drm_panfrost_param`:** This enumeration defines parameters that can be queried from the driver.
* **`#define` constants starting with `PANFROST_`:** These are flags and other related constants used with the IOCTLs and data structures.
* **Structures related to `panfrost_dump`:** This suggests functionality related to debugging and crash dumping.

**3. Categorizing and Detailing Functionality:**

Based on the identified elements, we can categorize the functionality:

* **Buffer Object (BO) Management:** `CREATE_BO`, `MMAP_BO`, `GET_BO_OFFSET`, `WAIT_BO`, `MADVISE`. These are fundamental for allocating, mapping, and synchronizing GPU memory.
* **Command Submission:** `SUBMIT`. This is how userspace programs tell the GPU what to do.
* **Parameter Querying:** `GET_PARAM`. Allows retrieving information about the GPU's capabilities.
* **Performance Counters:** `PERFCNT_ENABLE`, `PERFCNT_DUMP`. For performance monitoring and debugging.
* **Crash Dumping:** Structures and constants related to `panfrost_dump`.

For each category, I would elaborate on the purpose of the individual constants and structures. For example, for `DRM_PANFROST_CREATE_BO`, I'd explain that it's for allocating GPU memory and the associated `drm_panfrost_create_bo` structure defines the size and flags.

**4. Connecting to Android:**

Since the file is part of Bionic, it's crucial to explain how these low-level DRM calls relate to higher-level Android functionality. Key connections include:

* **SurfaceFlinger:**  The Android system service responsible for compositing and displaying UI. It heavily uses GPU buffers.
* **Gralloc:** The Graphics Allocator HAL, which manages the allocation of graphics buffers.
* **Vulkan/OpenGL ES:** Graphics APIs that rely on the underlying DRM driver to interact with the GPU.
* **NDK:** Developers can directly access some of these low-level functionalities through the NDK, although it's less common.

For examples, I'd explain how SurfaceFlinger would use `CREATE_BO` to allocate buffers for UI elements and `SUBMIT` to send rendering commands.

**5. Addressing Libc and Dynamic Linker:**

The prompt specifically asks about `libc` and the dynamic linker.

* **Libc Functions:**  The core `libc` function involved is `ioctl()`. I need to explain what `ioctl()` does (system call for device-specific operations) and how the `DRM_IOCTL_*` macros are used to construct the appropriate `ioctl()` request codes. Crucially, I need to emphasize that the *implementation* of the Panfrost DRM commands resides in the *kernel driver*, not in `libc` itself.
* **Dynamic Linker:** While this header file itself doesn't directly involve the dynamic linker, I need to explain *where* the relevant code resides. This would be the Panfrost DRM kernel module. I would provide a hypothetical `.so` layout for a userspace graphics library that might interact with this driver and describe how the linking process would connect the library to the kernel.

**6. Handling Logic and Error Scenarios:**

* **Logical Reasoning:** For the `SUBMIT` command, I can give a simple example of how the parameters are used to submit a job to the GPU. This involves assuming input values and describing the expected outcome.
* **User Errors:**  Common errors with DRM interactions include using incorrect handles, incorrect flags, or failing to synchronize access to shared buffers. Providing concrete examples of these helps illustrate potential pitfalls.

**7. Tracing the Call Path and Frida Hooking:**

This part requires explaining how a high-level Android framework call eventually reaches the Panfrost DRM driver. This involves tracing the path from something like `Canvas.draw()` in the framework, through the graphics APIs (OpenGL ES/Vulkan), down to the HAL implementations, and finally to the `ioctl()` system call with the Panfrost-specific commands. Providing a Frida hook example demonstrates how to intercept and examine these low-level calls. The example should focus on hooking the `ioctl` system call and filtering for the relevant Panfrost IOCTL numbers.

**8. Structure and Language:**

Finally, presenting the information clearly and concisely in Chinese is important. Using headings, bullet points, and code formatting enhances readability. Explaining technical terms and providing context is crucial for understanding.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the C preprocessor directives. **Correction:** While important, the core functionality lies in the IOCTLs and data structures.
* **Initial thought:** Explain the internal workings of the Panfrost driver. **Correction:** The prompt asks about the *interface*. Focus on the user-facing aspects defined in the header file. The driver implementation is a separate topic.
* **Initial thought:** Provide overly complex Frida hook examples. **Correction:** Keep the Frida example simple and focused on demonstrating the `ioctl` interception.
* **Initial thought:** Get bogged down in the details of dynamic linking. **Correction:**  Focus on the relevant aspects – how a userspace library *might* interact with the kernel driver.

By following this structured thought process, breaking down the problem into smaller, manageable parts, and constantly refining the approach, I can generate a comprehensive and accurate response to the prompt.
这个文件 `bionic/libc/kernel/uapi/drm/panfrost_drm.h` 是 Android Bionic C 库中用于定义与 Panfrost DRM (Direct Rendering Manager) 驱动程序进行交互的接口头文件。Panfrost 是针对 ARM Mali GPU 的一个开源 DRM 驱动程序。这个头文件定义了用户空间应用程序与内核中的 Panfrost 驱动程序通信所需的常量、数据结构和 ioctl 命令。

**功能列举:**

该头文件主要定义了以下功能：

1. **定义了与 Panfrost DRM 驱动交互的 ioctl 命令码:**  例如 `DRM_IOCTL_PANFROST_SUBMIT`, `DRM_IOCTL_PANFROST_CREATE_BO` 等，这些命令码用于指示内核执行特定的 GPU 操作。
2. **定义了与这些 ioctl 命令相关的数据结构:**  例如 `struct drm_panfrost_submit`, `struct drm_panfrost_create_bo` 等，这些结构体用于传递命令的参数和接收结果。
3. **定义了用于控制和查询 GPU 状态的常量:**  例如 `PANFROST_JD_REQ_FS`, `PANFROST_BO_NOEXEC`, 以及 `enum drm_panfrost_param` 中的各种参数。
4. **定义了用于性能计数器和调试信息的结构体:** 例如 `struct drm_panfrost_perfcnt_enable` 和 `struct panfrost_dump_object_header`。

**与 Android 功能的关系及举例说明:**

这个头文件直接关联着 Android 的图形系统。Android 的图形渲染流程涉及到与 GPU 驱动程序的交互，而 Panfrost DRM 驱动正是某些 Android 设备上 Mali GPU 的驱动。

* **SurfaceFlinger:** Android 的 SurfaceFlinger 服务负责合成屏幕上的所有图层并将最终的帧发送到显示器。SurfaceFlinger 会使用类似 `DRM_IOCTL_PANFROST_SUBMIT` 来将渲染命令提交给 GPU 执行。它会使用 Buffer Object (BO) 来管理图形数据，而 `DRM_IOCTL_PANFROST_CREATE_BO` 和 `DRM_IOCTL_PANFROST_MMAP_BO` 就用于创建和映射这些 BO。
* **Gralloc (Graphics Allocation):** Android 的 Gralloc HAL (硬件抽象层) 负责分配图形缓冲区。当应用程序请求分配一块用于渲染的内存时，Gralloc 的实现可能会调用底层的 DRM 驱动接口，例如使用 `DRM_IOCTL_PANFROST_CREATE_BO` 来在 GPU 内存中分配缓冲区。
* **Vulkan/OpenGL ES:**  Android 应用程序可以使用 Vulkan 或 OpenGL ES 进行图形渲染。这些图形 API 的驱动程序实现最终会通过 DRM 接口与 GPU 硬件进行交互。例如，当应用程序调用一个绘制命令时，底层的 Vulkan 或 OpenGL ES 驱动会将这些命令转化为一系列对 DRM 驱动的 ioctl 调用，例如 `DRM_IOCTL_PANFROST_SUBMIT`。

**详细解释 libc 函数的功能实现:**

这个头文件本身并没有定义任何 libc 函数的实现。它定义的是与内核交互的接口。真正执行与这些定义相关的操作的是 libc 中的 `ioctl` 函数。

`ioctl` (input/output control) 是一个系统调用，允许用户空间程序向设备驱动程序发送设备特定的命令并进行数据交换。它的原型通常如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* `fd`:  文件描述符，通常是打开的 DRM 设备的文件描述符 (例如 `/dev/dri/card0`)。
* `request`:  一个设备特定的请求码，用于指定要执行的操作。在 Panfrost DRM 的情况下，这些请求码就是头文件中定义的 `DRM_IOCTL_PANFROST_*` 宏的值。
* `...`:  可选的参数，指向与请求码相关的数据结构。这些数据结构就是头文件中定义的 `struct drm_panfrost_*` 结构体。

**`ioctl` 的实现过程 (简化):**

1. **用户空间调用 `ioctl`:**  应用程序调用 `ioctl` 函数，并传入 DRM 设备的文件描述符、一个 `DRM_IOCTL_PANFROST_*` 命令码以及指向相应数据结构的指针。
2. **系统调用陷入内核:**  `ioctl` 是一个系统调用，因此会触发从用户空间到内核空间的切换。
3. **内核处理 `ioctl`:**  内核接收到 `ioctl` 系统调用，根据传入的文件描述符找到对应的设备驱动程序 (Panfrost DRM 驱动)。
4. **驱动程序处理请求:**  Panfrost DRM 驱动程序会根据传入的 `request` 码 (例如 `DRM_IOCTL_PANFROST_SUBMIT`) 执行相应的操作。这通常涉及到访问 GPU 硬件、操作 GPU 内存、或者与 GPU 的命令队列进行交互。
5. **数据交换:**  如果 ioctl 命令涉及到数据的传递，内核会根据传入的数据结构指针读取用户空间的数据，或者将结果数据写入用户空间提供的缓冲区。
6. **返回结果:**  ioctl 系统调用返回执行结果，通常是一个整数值，表示成功或失败。

**涉及 dynamic linker 的功能和 SO 布局样本及链接处理过程:**

这个头文件本身并不直接涉及动态链接器。动态链接器负责在程序运行时加载和链接共享库。然而，使用这个头文件中定义的接口的库（例如图形驱动的用户空间部分）会被动态链接到应用程序中。

**SO 布局样本 (假设一个与 Panfrost 交互的图形库 `libpanfrost_client.so`):**

```
libpanfrost_client.so:
    .text         # 代码段，包含调用 ioctl 的函数
    .rodata       # 只读数据段，可能包含一些常量
    .data         # 可读写数据段，可能包含一些全局变量
    .dynsym       # 动态符号表
    .dynstr       # 动态字符串表
    .rel.dyn      # 动态重定位表
    ...

```

**链接的处理过程:**

1. **编译时链接:**  应用程序在编译时，编译器会找到需要使用的共享库 (`libpanfrost_client.so`)，并在可执行文件的头部记录下对该库的依赖。
2. **程序启动:**  当程序启动时，操作系统会加载程序到内存。
3. **动态链接器介入:**  动态链接器 (例如 Android 上的 `linker64` 或 `linker`) 会被启动，负责解析程序的依赖关系。
4. **加载共享库:**  动态链接器会找到并加载 `libpanfrost_client.so` 到内存中。
5. **符号解析与重定位:**  动态链接器会解析 `libpanfrost_client.so` 中的符号 (例如函数地址) 以及应用程序中对这些符号的引用。它会修改内存中的指令和数据，将这些引用指向正确的地址。这个过程称为重定位。
6. **完成链接:**  一旦所有依赖的共享库都被加载和链接，应用程序就可以开始执行。

**在 `libpanfrost_client.so` 中，可能会有如下代码片段 (伪代码):**

```c
// 假设 libpanfrost_client.so 中有一个函数用于创建 Buffer Object
int panfrost_create_bo(int fd, size_t size) {
    struct drm_panfrost_create_bo create_bo;
    create_bo.size = size;
    create_bo.flags = 0; // 示例，可以有其他标志

    if (ioctl(fd, DRM_IOCTL_PANFROST_CREATE_BO, &create_bo) == -1) {
        // 处理错误
        perror("ioctl(DRM_IOCTL_PANFROST_CREATE_BO) failed");
        return -1;
    }
    return create_bo.handle;
}
```

在这个例子中，`libpanfrost_client.so` 中的 `panfrost_create_bo` 函数会调用 `ioctl`，并使用在 `panfrost_drm.h` 中定义的 `DRM_IOCTL_PANFROST_CREATE_BO` 宏。

**假设输入与输出 (针对 `DRM_IOCTL_PANFROST_CREATE_BO`):**

**假设输入:**

* `fd`:  打开的 DRM 设备文件描述符，例如 3。
* `size`:  要分配的 Buffer Object 的大小，例如 4096 字节。
* `flags`:  分配标志，例如 0 (默认)。

**预期输出:**

* 如果成功，`ioctl` 返回 0，并且 `create_bo.handle` 字段会被内核填充为新创建的 Buffer Object 的句柄 (一个整数值，例如 123)。
* 如果失败，`ioctl` 返回 -1，并设置 `errno` 指示错误原因。

**用户或编程常见的使用错误举例说明:**

1. **文件描述符无效:**  在调用 `ioctl` 之前，忘记打开 DRM 设备或者使用了错误的文件描述符。这会导致 `ioctl` 调用失败，并返回 `EBADF` 错误。

   ```c
   int fd = open("/dev/dri/card0", O_RDWR);
   // 假设 open 失败，fd 为 -1
   struct drm_panfrost_create_bo create_bo;
   // ... 初始化 create_bo ...
   if (ioctl(fd, DRM_IOCTL_PANFROST_CREATE_BO, &create_bo) == -1) {
       perror("ioctl failed"); // 输出类似 "ioctl failed: Bad file descriptor"
   }
   ```

2. **传递了错误的数据结构或数据结构内容错误:**  例如，传递了一个大小不正确的结构体，或者结构体中的某些字段值不符合预期。内核可能会拒绝处理该 ioctl，或者导致未定义的行为。

   ```c
   int fd = open("/dev/dri/card0", O_RDWR);
   struct drm_panfrost_create_bo create_bo;
   create_bo.size = 0; // 尝试分配大小为 0 的 BO，这可能是不允许的
   // ...
   if (ioctl(fd, DRM_IOCTL_PANFROST_CREATE_BO, &create_bo) == -1) {
       perror("ioctl failed"); // 可能输出其他错误，例如 "Invalid argument"
   }
   ```

3. **权限不足:**  调用 `ioctl` 的进程没有足够的权限访问 DRM 设备。这会导致 `ioctl` 调用失败，并返回 `EACCES` 或 `EPERM` 错误。

4. **竞争条件和同步问题:**  多个线程或进程同时访问和操作同一个 Buffer Object 而没有进行适当的同步，可能导致数据损坏或程序崩溃。例如，一个线程正在写入 BO，而另一个线程同时尝试读取。

5. **忘记处理错误返回值:**  `ioctl` 调用可能会失败，但程序员没有检查返回值并采取相应的错误处理措施。

**Android framework 或 NDK 如何一步步到达这里:**

以一个简单的 OpenGL ES 绘制调用为例，说明 Android framework 如何最终到达 Panfrost DRM 驱动：

1. **应用程序调用 OpenGL ES API:**  例如，在 Java 代码中调用 `android.opengl.GLES20.glDrawArrays(...)`。
2. **Framework 层处理:**  Android Framework 的 OpenGL ES 实现 (通常在 `libGLESv2.so` 中) 接收到调用。
3. **EGL (Embedded-System Graphics Library):**  OpenGL ES 的实现依赖于 EGL 来与底层的窗口系统和图形驱动程序进行交互。Framework 会调用 EGL 相关的函数 (通常在 `libEGL.so` 中)。
4. **Gralloc HAL:**  当需要分配图形缓冲区 (例如用于渲染目标) 时，EGL 会通过 Gralloc HAL (硬件抽象层) 进行分配。Gralloc HAL 的实现可能位于特定于硬件的 SO 库中 (例如 `android.hardware.graphics.allocator@4.0-service`).
5. **DRM 驱动交互:**  Gralloc HAL 的实现最终会打开 DRM 设备文件描述符 (`/dev/dri/card0`)，并使用 `ioctl` 系统调用，传入在 `panfrost_drm.h` 中定义的 `DRM_IOCTL_PANFROST_*` 命令码，与 Panfrost DRM 驱动进行交互，分配 GPU 内存。
6. **提交渲染命令:**  当应用程序调用绘制命令时，OpenGL ES 驱动程序会将这些命令转换为 GPU 能够理解的指令，并将这些指令和相关的数据 (例如顶点数据、纹理) 提交给 GPU 执行。这通常涉及到使用 `DRM_IOCTL_PANFROST_SUBMIT` ioctl 命令。

**NDK 的情况类似:**  如果使用 NDK 直接调用 OpenGL ES 或 Vulkan API，流程基本一致，只是跳过了 Java Framework 的部分。

**Frida hook 示例调试步骤:**

可以使用 Frida hook `ioctl` 系统调用，并过滤出与 Panfrost DRM 相关的调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    device = frida.get_usb_device()
    pid = device.spawn(['com.example.myapp']) # 替换为你的应用包名
    session = device.attach(pid)
    device.resume(pid)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            // 过滤 DRM 相关的 ioctl 命令 (基于 DRM_COMMAND_BASE)
            const DRM_COMMAND_BASE = 0x40006400; // 需要根据实际情况调整

            if ((request & ~0xff) === DRM_COMMAND_BASE) {
                const command = request & 0xff;
                console.log("[IOCTL] fd:", fd, "request:", request, "command:", command);

                // 可以进一步解析参数，例如根据 command 的值读取 argp 指针指向的数据结构
                if (command === 0x00) { // DRM_PANFROST_SUBMIT
                    const submit_ptr = ptr(args[2]);
                    if (submit_ptr) {
                        const jc = submit_ptr.readU64();
                        console.log("  [DRM_PANFROST_SUBMIT] jc:", jc.toString(16));
                    }
                }
                // 添加其他命令的解析
            }
        },
        onLeave: function(retval) {
            // console.log("ioctl returned:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**Frida hook 示例解释:**

1. **导入 frida 库。**
2. **定义 `on_message` 函数处理 Frida 脚本发送的消息。**
3. **在 `main` 函数中:**
   - 获取 USB 设备并启动目标 Android 应用。
   - 连接到目标应用的进程。
   - 定义 Frida 脚本代码。
4. **Frida 脚本代码:**
   - 使用 `Interceptor.attach` hook 了 `ioctl` 函数。
   - 在 `onEnter` 中，获取 `ioctl` 的文件描述符 (`fd`) 和请求码 (`request`).
   - 定义了 `DRM_COMMAND_BASE`，你需要根据实际系统的定义调整这个值。这个值通常用于区分不同的 DRM 驱动的 ioctl 命令。
   - 检查 `request` 码是否属于 DRM 驱动的命令。
   - 如果是，则打印出文件描述符、请求码和命令编号。
   - 添加了针对 `DRM_PANFROST_SUBMIT` 命令的参数解析示例，读取了 `jc` 字段的值。你可以根据需要添加其他命令的解析。
5. **加载并运行 Frida 脚本。**
6. **当目标应用调用 `ioctl` 时，Frida 脚本会拦截调用并打印相关信息。**

这个 Frida 脚本可以帮助你观察应用程序如何与 Panfrost DRM 驱动进行交互，查看传递的命令和参数，从而进行调试和逆向分析。你需要根据具体的调试需求扩展脚本，解析更多的数据结构和命令。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/drm/panfrost_drm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _PANFROST_DRM_H_
#define _PANFROST_DRM_H_
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#define DRM_PANFROST_SUBMIT 0x00
#define DRM_PANFROST_WAIT_BO 0x01
#define DRM_PANFROST_CREATE_BO 0x02
#define DRM_PANFROST_MMAP_BO 0x03
#define DRM_PANFROST_GET_PARAM 0x04
#define DRM_PANFROST_GET_BO_OFFSET 0x05
#define DRM_PANFROST_PERFCNT_ENABLE 0x06
#define DRM_PANFROST_PERFCNT_DUMP 0x07
#define DRM_PANFROST_MADVISE 0x08
#define DRM_IOCTL_PANFROST_SUBMIT DRM_IOW(DRM_COMMAND_BASE + DRM_PANFROST_SUBMIT, struct drm_panfrost_submit)
#define DRM_IOCTL_PANFROST_WAIT_BO DRM_IOW(DRM_COMMAND_BASE + DRM_PANFROST_WAIT_BO, struct drm_panfrost_wait_bo)
#define DRM_IOCTL_PANFROST_CREATE_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_PANFROST_CREATE_BO, struct drm_panfrost_create_bo)
#define DRM_IOCTL_PANFROST_MMAP_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_PANFROST_MMAP_BO, struct drm_panfrost_mmap_bo)
#define DRM_IOCTL_PANFROST_GET_PARAM DRM_IOWR(DRM_COMMAND_BASE + DRM_PANFROST_GET_PARAM, struct drm_panfrost_get_param)
#define DRM_IOCTL_PANFROST_GET_BO_OFFSET DRM_IOWR(DRM_COMMAND_BASE + DRM_PANFROST_GET_BO_OFFSET, struct drm_panfrost_get_bo_offset)
#define DRM_IOCTL_PANFROST_MADVISE DRM_IOWR(DRM_COMMAND_BASE + DRM_PANFROST_MADVISE, struct drm_panfrost_madvise)
#define DRM_IOCTL_PANFROST_PERFCNT_ENABLE DRM_IOW(DRM_COMMAND_BASE + DRM_PANFROST_PERFCNT_ENABLE, struct drm_panfrost_perfcnt_enable)
#define DRM_IOCTL_PANFROST_PERFCNT_DUMP DRM_IOW(DRM_COMMAND_BASE + DRM_PANFROST_PERFCNT_DUMP, struct drm_panfrost_perfcnt_dump)
#define PANFROST_JD_REQ_FS (1 << 0)
struct drm_panfrost_submit {
  __u64 jc;
  __u64 in_syncs;
  __u32 in_sync_count;
  __u32 out_sync;
  __u64 bo_handles;
  __u32 bo_handle_count;
  __u32 requirements;
};
struct drm_panfrost_wait_bo {
  __u32 handle;
  __u32 pad;
  __s64 timeout_ns;
};
#define PANFROST_BO_NOEXEC 1
#define PANFROST_BO_HEAP 2
struct drm_panfrost_create_bo {
  __u32 size;
  __u32 flags;
  __u32 handle;
  __u32 pad;
  __u64 offset;
};
struct drm_panfrost_mmap_bo {
  __u32 handle;
  __u32 flags;
  __u64 offset;
};
enum drm_panfrost_param {
  DRM_PANFROST_PARAM_GPU_PROD_ID,
  DRM_PANFROST_PARAM_GPU_REVISION,
  DRM_PANFROST_PARAM_SHADER_PRESENT,
  DRM_PANFROST_PARAM_TILER_PRESENT,
  DRM_PANFROST_PARAM_L2_PRESENT,
  DRM_PANFROST_PARAM_STACK_PRESENT,
  DRM_PANFROST_PARAM_AS_PRESENT,
  DRM_PANFROST_PARAM_JS_PRESENT,
  DRM_PANFROST_PARAM_L2_FEATURES,
  DRM_PANFROST_PARAM_CORE_FEATURES,
  DRM_PANFROST_PARAM_TILER_FEATURES,
  DRM_PANFROST_PARAM_MEM_FEATURES,
  DRM_PANFROST_PARAM_MMU_FEATURES,
  DRM_PANFROST_PARAM_THREAD_FEATURES,
  DRM_PANFROST_PARAM_MAX_THREADS,
  DRM_PANFROST_PARAM_THREAD_MAX_WORKGROUP_SZ,
  DRM_PANFROST_PARAM_THREAD_MAX_BARRIER_SZ,
  DRM_PANFROST_PARAM_COHERENCY_FEATURES,
  DRM_PANFROST_PARAM_TEXTURE_FEATURES0,
  DRM_PANFROST_PARAM_TEXTURE_FEATURES1,
  DRM_PANFROST_PARAM_TEXTURE_FEATURES2,
  DRM_PANFROST_PARAM_TEXTURE_FEATURES3,
  DRM_PANFROST_PARAM_JS_FEATURES0,
  DRM_PANFROST_PARAM_JS_FEATURES1,
  DRM_PANFROST_PARAM_JS_FEATURES2,
  DRM_PANFROST_PARAM_JS_FEATURES3,
  DRM_PANFROST_PARAM_JS_FEATURES4,
  DRM_PANFROST_PARAM_JS_FEATURES5,
  DRM_PANFROST_PARAM_JS_FEATURES6,
  DRM_PANFROST_PARAM_JS_FEATURES7,
  DRM_PANFROST_PARAM_JS_FEATURES8,
  DRM_PANFROST_PARAM_JS_FEATURES9,
  DRM_PANFROST_PARAM_JS_FEATURES10,
  DRM_PANFROST_PARAM_JS_FEATURES11,
  DRM_PANFROST_PARAM_JS_FEATURES12,
  DRM_PANFROST_PARAM_JS_FEATURES13,
  DRM_PANFROST_PARAM_JS_FEATURES14,
  DRM_PANFROST_PARAM_JS_FEATURES15,
  DRM_PANFROST_PARAM_NR_CORE_GROUPS,
  DRM_PANFROST_PARAM_THREAD_TLS_ALLOC,
  DRM_PANFROST_PARAM_AFBC_FEATURES,
};
struct drm_panfrost_get_param {
  __u32 param;
  __u32 pad;
  __u64 value;
};
struct drm_panfrost_get_bo_offset {
  __u32 handle;
  __u32 pad;
  __u64 offset;
};
struct drm_panfrost_perfcnt_enable {
  __u32 enable;
  __u32 counterset;
};
struct drm_panfrost_perfcnt_dump {
  __u64 buf_ptr;
};
#define PANFROST_MADV_WILLNEED 0
#define PANFROST_MADV_DONTNEED 1
struct drm_panfrost_madvise {
  __u32 handle;
  __u32 madv;
  __u32 retained;
};
#define PANFROSTDUMP_MAJOR 1
#define PANFROSTDUMP_MINOR 0
#define PANFROSTDUMP_MAGIC 0x464E4150
#define PANFROSTDUMP_BUF_REG 0
#define PANFROSTDUMP_BUF_BOMAP (PANFROSTDUMP_BUF_REG + 1)
#define PANFROSTDUMP_BUF_BO (PANFROSTDUMP_BUF_BOMAP + 1)
#define PANFROSTDUMP_BUF_TRAILER (PANFROSTDUMP_BUF_BO + 1)
struct panfrost_dump_object_header {
  __u32 magic;
  __u32 type;
  __u32 file_size;
  __u32 file_offset;
  union {
    struct {
      __u64 jc;
      __u32 gpu_id;
      __u32 major;
      __u32 minor;
      __u64 nbos;
    } reghdr;
    struct {
      __u32 valid;
      __u64 iova;
      __u32 data[2];
    } bomap;
    __u32 sizer[496];
  };
};
struct panfrost_dump_registers {
  __u32 reg;
  __u32 value;
};
#ifdef __cplusplus
}
#endif
#endif

"""

```