Response:
Let's break down the thought process for answering this comprehensive request about the `qaic_accel.handroid` DRM header file.

**1. Understanding the Core Request:**

The fundamental goal is to analyze the provided C header file and explain its purpose, how it interacts with Android, and how it's used within the Android ecosystem. The request emphasizes connecting the file to various levels of the Android stack, including the C library, dynamic linker, framework, and NDK. It also asks for practical examples and debugging techniques.

**2. Initial Scans and Keyword Recognition:**

My first pass through the code involves looking for keywords and patterns that give immediate clues about its functionality. I see:

* **`QAIC`:** This is the most prominent identifier, suggesting a specific subsystem or component. The filename `qaic_accel.handroid` reinforces this, indicating acceleration capabilities.
* **`DRM`:**  The inclusion of `drm.h` and the `DRM_IOCTL_QAIC_*` macros immediately tell me this is related to the Direct Rendering Manager, a Linux kernel subsystem for managing graphics hardware. The "handroid" likely signifies a hardware-accelerated component specific to Android devices.
* **`IOCTL`:** The `DRM_IOCTL_*` macros indicate this file defines interfaces for communicating with a kernel driver through ioctl system calls.
* **`struct` definitions:** These structures clearly define data layouts for exchanging information with the kernel driver. The names of the structures (e.g., `qaic_manage_trans_*`, `qaic_create_bo`, `qaic_attach_slice`) suggest different operations or data types handled by the QAIC accelerator.
* **`#define` constants:** These define symbolic names for various parameters and commands, making the code more readable and maintainable. Constants like `QAIC_TRANS_*` (transaction types) and `QAIC_SEM_*` (semaphore operations) are particularly informative.
* **`__u32`, `__u64`, `__u8`:** These are standard Linux kernel type definitions for unsigned integers of different sizes, confirming this is kernel-level code or designed to interface with it directly.
* **`SZ_4K`:** This indicates a buffer size, often used in memory management or communication protocols.
* **`eventfd`:** This suggests a mechanism for signaling events between processes or between user-space and the kernel.

**3. Deducting Functionality based on Keywords and Structures:**

Based on the initial scan, I start to form hypotheses about the file's purpose:

* **Hardware Acceleration:** The name and the presence of DRM suggest this is about offloading computation or data processing to specialized hardware.
* **Inter-Process Communication:** The ioctl interface and the presence of message structures (`qaic_manage_msg`) imply a communication channel between user-space applications and the kernel driver.
* **Memory Management:** Structures like `qaic_create_bo` (buffer object), `qaic_mmap_bo`, and the DMA transfer types strongly indicate the management of shared memory between the user-space and the device.
* **Command Queuing:** The `qaic_execute_*` structures and the mention of `queue_size` in `qaic_manage_trans_activate_to_dev` point towards a command queue mechanism for the accelerator.
* **Synchronization:** The `qaic_sem` structure suggests the use of semaphores for synchronizing operations.
* **State Management:** Structures like `qaic_manage_trans_activate_*` and `qaic_manage_trans_deactivate` suggest managing the lifecycle of the accelerator.

**4. Connecting to Android Functionality:**

Now, I start to connect these deduced functionalities to Android concepts:

* **DRM and Graphics/Compute:**  DRM is a core part of Android's graphics stack. This QAIC accelerator likely provides hardware acceleration for specific graphics or compute tasks.
* **Buffer Objects (BOs):** BOs are a fundamental concept in DRM for managing GPU memory. The `qaic_create_bo` and related structures are clearly related to this. This ties into Android's SurfaceFlinger and graphics rendering pipeline.
* **IOCTL and System Calls:**  Android applications and frameworks interact with kernel drivers via system calls like `ioctl`. This file defines the data structures used in those calls.
* **NDK and Hardware Access:** The NDK allows developers to write native code that can potentially interact with hardware-specific features like this QAIC accelerator.

**5. Detailed Explanation of Structures and Constants:**

I then go through each structure and constant, explaining its likely purpose based on its name and the types of its members. For example:

* **`qaic_manage_trans_*`:** Clearly defines different types of transactions for a "manage" operation.
* **`qaic_create_bo`:**  Obvious purpose of creating a buffer object of a certain size and receiving a handle.
* **`QAIC_SEM_*`:**  Defines different semaphore operations, which are standard synchronization primitives.
* **`QAIC_TRANS_*`:** Enumerates the various types of transactions supported.

**6. Addressing Specific Request Points:**

* **libc Functions:** Since this is a header file, it doesn't *implement* libc functions. It *uses* standard C types. The explanation focuses on the role of libc in system calls.
* **Dynamic Linker:**  This header file itself isn't directly involved in dynamic linking. However, the *driver* that uses these definitions might be dynamically loaded. I would explain the general principles of dynamic linking and provide a basic `so` layout example.
* **Logic Inference:** I choose a simple scenario, like creating a buffer and transferring data, to illustrate the interaction between the user-space and the driver.
* **Common Errors:** I think about common mistakes developers make when interacting with low-level APIs, such as incorrect sizes, memory management issues, and race conditions.
* **Android Framework/NDK Path:** This is a crucial part. I need to trace how a high-level Android operation might eventually lead to the use of these ioctls. I start with the high-level (e.g., media processing, ML inference) and work my way down through the Android framework layers to the native level and finally the kernel driver.
* **Frida Hooking:**  Provide practical examples of how to intercept these ioctl calls using Frida, focusing on the key aspects of hooking system calls and inspecting the data structures.

**7. Structuring the Answer:**

Finally, I organize the information logically, addressing each part of the original request. I use clear headings and bullet points to make the information easier to read and understand. The goal is to provide a comprehensive yet accessible explanation for someone familiar with Android development concepts.

**Self-Correction/Refinement during the Process:**

* **Initial Overemphasis on Implementation:** I might initially think about how the *driver* implements these functions. I need to refocus on the *header file's* role, which is to *define the interface*.
* **Clarity on libc and Dynamic Linking:**  I need to be precise about the relationship between the header file, libc, and the dynamic linker. The header defines types used in system calls, which are mediated by libc. The driver itself might be a dynamically linked library.
* **Practical Examples:**  Ensuring the examples are concrete and relatable is important. Instead of just saying "data transfer," I specify "transferring input data to the accelerator."
* **Frida Specifics:** Providing concrete Frida code snippets makes the debugging section much more useful.

By following this systematic process of analyzing the code, connecting it to Android concepts, and addressing each aspect of the request, I can generate a comprehensive and informative answer.
好的，让我们深入分析一下 `bionic/libc/kernel/uapi/drm/qaic_accel.handroid` 这个头文件。

**功能概述**

这个头文件定义了用户空间程序与 QAIC (Qualcomm Artificial Intelligence Core) 加速器 Linux DRM 驱动程序进行交互的接口。它主要包含以下几个方面的功能：

1. **定义了与 QAIC 加速器通信的数据结构：**  这些结构体用于封装用户空间向内核驱动发送的命令以及驱动返回的数据。
2. **定义了控制 QAIC 加速器的 IOCTL 命令：** 这些宏定义了不同的操作，例如管理消息、创建/映射缓冲区对象、连接/执行/等待切片、获取性能统计等。
3. **定义了与 QAIC 加速器交互相关的常量：**  例如消息最大长度、信号量类型、事务类型等。

**与 Android 功能的关系及举例说明**

QAIC 加速器是高通平台上的一个专门用于加速人工智能计算的硬件单元。这个头文件定义了与该加速器交互的底层接口，因此它与 Android 的以下功能息息相关：

* **机器学习 (Machine Learning/ML)：**  Android 设备上很多 ML 相关的任务，例如图像识别、自然语言处理等，可以利用 QAIC 加速器来提高执行效率和降低功耗。例如，TensorFlow Lite 或其他 ML 推理框架可能会通过底层的 HAL (Hardware Abstraction Layer) 调用到这个 DRM 驱动，最终使用这里定义的 IOCTL 命令与 QAIC 加速器进行通信。
* **计算机视觉 (Computer Vision/CV)：**  一些图像处理、视频分析相关的应用也可能利用 QAIC 加速器进行加速。例如，某些相机应用的实时图像增强功能或者视频编辑应用的特效处理。
* **Android Neural Networks API (NNAPI)：**  NNAPI 是 Android 提供的一个用于加速神经网络计算的 API。底层实现可能会使用硬件加速器，例如这里的 QAIC。通过 NNAPI 提交的 ML 模型推理任务，最终可能会通过这个 DRM 驱动与 QAIC 加速器交互。

**举例说明：**

假设一个 Android 应用需要进行图像分类。它可以使用 NNAPI 来加载一个预训练的图像分类模型。当应用请求对一张图片进行分类时，NNAPI 可能会将这个推理任务委托给 QAIC 加速器来执行。这个过程涉及到：

1. **NNAPI Framework:**  应用通过 NNAPI 的接口提交推理请求。
2. **NNAPI HAL:**  NNAPI 的硬件抽象层将请求转换为特定硬件加速器的指令。
3. **QAIC DRM Driver:**  NNAPI HAL 可能会调用到 QAIC 的 DRM 驱动，使用这里定义的 `DRM_IOCTL_QAIC_EXECUTE_BO` 等 IOCTL 命令，将需要执行的模型和数据发送给 QAIC 加速器。
4. **QAIC Accelerator:**  QAIC 加速器执行模型推理计算。
5. **结果返回:**  计算结果通过 DRM 驱动返回给 NNAPI HAL，最终传递回应用。

**详细解释每一个 libc 函数的功能是如何实现的**

这个头文件本身并没有实现任何 libc 函数。它主要定义了数据结构和宏。但是，**用户空间程序** 需要使用 libc 提供的系统调用接口（例如 `ioctl`）来与 QAIC DRM 驱动进行交互。

* **`ioctl()` 函数：** 这是与设备驱动程序进行通信的主要系统调用。用户空间程序使用 `ioctl()` 函数，并传入特定的设备文件描述符、IOCTL 命令以及指向数据结构的指针，来向驱动程序发送控制指令或接收数据。

**`ioctl()` 的基本工作原理：**

1. 用户空间程序调用 `ioctl()`，提供文件描述符（指向 `/dev/dri/cardX` 这样的 DRM 设备节点）、请求码（例如 `DRM_IOCTL_QAIC_EXECUTE_BO`）和一个指向数据结构的指针。
2. 系统调用陷入内核。
3. 内核根据文件描述符找到对应的设备驱动程序（QAIC DRM 驱动）。
4. 内核根据 IOCTL 请求码，调用驱动程序中相应的处理函数。
5. 驱动程序处理用户空间传递过来的数据，执行相应的操作（例如，将数据发送到 QAIC 加速器，分配内存等）。
6. 驱动程序将结果数据写入用户空间提供的缓冲区。
7. 系统调用返回用户空间。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

这个头文件自身不直接涉及动态链接。但是，与 QAIC 加速器交互的 **DRM 驱动程序** 可能是一个内核模块，或者用户空间使用的库 (例如 NNAPI HAL 的实现) 可能是动态链接的 `.so` 文件。

**假设 NNAPI HAL 库 (例如 `libneuralnetworks.so`) 使用了 QAIC 加速器:**

**`libneuralnetworks.so` 布局样本：**

```
libneuralnetworks.so:
    .text          # 代码段，包含 NNAPI HAL 的实现逻辑
    .rodata        # 只读数据段，包含常量等
    .data          # 可读写数据段，包含全局变量等
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表，列出本 so 提供的符号
    .dynstr        # 动态字符串表，存储符号名等字符串
    .rel.dyn       # 动态重定位表，用于链接时修正地址
    .plt           # 程序链接表，用于延迟绑定
    .got.plt       # 全局偏移量表，用于存储外部符号的地址
    ...
```

**链接的处理过程：**

1. **编译时链接：** 当编译使用 NNAPI 的应用或者 NNAPI HAL 本身时，链接器会记录下需要的外部符号，例如与 DRM 交互的系统调用 (`ioctl`) 以及可能的其他库的符号。
2. **加载时链接：** 当应用启动或者首次加载 `libneuralnetworks.so` 时，Android 的动态链接器 (`linker64` 或 `linker`) 会执行以下操作：
   * **加载依赖库：**  如果 `libneuralnetworks.so` 依赖其他共享库 (例如 libc.so)，链接器会先加载这些依赖库。
   * **符号查找和重定位：** 链接器会遍历所有加载的共享库的动态符号表，查找 `libneuralnetworks.so` 中引用的外部符号的地址。
   * **填充 GOT 和 PLT：** 找到符号地址后，链接器会将这些地址填充到 `libneuralnetworks.so` 的全局偏移量表 (`.got.plt`) 中。对于通过过程链接表 (`.plt`) 调用的函数，会设置一个跳转到链接器的桩代码，在首次调用时再解析实际地址（延迟绑定）。
   * **执行初始化函数：** 如果共享库有初始化函数 (通过 `__attribute__((constructor))` 定义)，链接器会在完成重定位后执行这些函数。

**与 QAIC DRM 相关的链接：**

虽然 `qaic_accel.handroid` 是一个头文件，但实际与 QAIC 硬件交互的代码在内核驱动中。用户空间的 `libneuralnetworks.so` 或者其他相关库需要使用 libc 提供的 `ioctl` 系统调用来与该驱动通信。`ioctl` 函数的地址由 libc.so 提供，动态链接器负责在加载 `libneuralnetworks.so` 时找到 `ioctl` 函数的地址并将其填入 `libneuralnetworks.so` 的 GOT 表。

**如果做了逻辑推理，请给出假设输入与输出**

假设用户空间程序想要让 QAIC 加速器执行一个推理任务。

**假设输入：**

* **文件描述符：**  一个打开的 QAIC DRM 设备文件描述符，例如 `fd = open("/dev/dri/card0", O_RDWR);`
* **IOCTL 命令：** `DRM_IOCTL_QAIC_EXECUTE_BO`
* **`struct qaic_execute` 数据结构：**
  ```c
  struct qaic_execute execute_cmd;
  execute_cmd.hdr.count = 1; // 执行一个 BO
  execute_cmd.hdr.dbc_id = 123; // 设备的上下文 ID
  // execute_cmd.data 指向一个 qaic_execute_entry 数组的内存地址
  struct qaic_execute_entry entry;
  entry.handle = 456; // 要执行的 Buffer Object 的句柄
  entry.dir = 0;     // 执行方向
  // 将 entry 的地址赋值给 execute_cmd.data
  execute_cmd.data = (uintptr_t)&entry;
  ```
* **假设已经创建了 handle 为 456 的 Buffer Object，并加载了模型数据。**

**假设输出：**

* **`ioctl()` 返回值：**  成功时返回 0，失败时返回 -1 并设置 `errno`。
* **QAIC 加速器执行推理任务。**
* **推理结果可能被写入到另一个事先分配好的 Buffer Object 中，用户空间程序需要通过其他 IOCTL 命令 (例如 `DRM_IOCTL_QAIC_MMAP_BO` 映射该 BO) 来读取结果。** 或者，某些类型的执行可以直接将结果返回到用户空间。

**如果涉及用户或者编程常见的使用错误，请举例说明**

1. **错误的 IOCTL 命令或参数：** 使用了错误的 `ioctl` 命令或者传递了不符合预期的参数值，例如传递了无效的 Buffer Object 句柄，或者 `count` 与实际提供的 entry 数量不符。这会导致驱动程序返回错误。

   ```c
   // 错误示例：使用了错误的 IOCTL 命令
   ioctl(fd, DRM_IOCTL_QAIC_CREATE_BO, &create_bo);

   // 错误示例：传递了无效的句柄
   execute_cmd.data = (uintptr_t)NULL;
   ioctl(fd, DRM_IOCTL_QAIC_EXECUTE_BO, &execute_cmd);
   ```

2. **内存管理错误：**  Buffer Object 的生命周期管理不当，例如在 BO 被释放后尝试访问，或者分配的 BO 大小不足以存储数据。

3. **同步问题：**  与 QAIC 加速器的交互可能需要进行同步操作，例如等待加速器完成任务。如果同步处理不当，可能会导致程序逻辑错误或死锁。例如，没有正确使用 `DRM_IOCTL_QAIC_WAIT_BO` 等待执行完成。

4. **竞争条件：**  在多线程或多进程环境下，如果没有适当的锁机制保护共享资源 (例如 Buffer Object)，可能会发生竞争条件，导致数据损坏或程序崩溃。

5. **权限问题：**  访问 `/dev/dri/cardX` 设备文件需要相应的权限。如果用户程序没有足够的权限，`open()` 调用会失败。

6. **未处理错误返回值：**  没有检查 `ioctl()` 等系统调用的返回值，导致错误被忽略，程序行为异常。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 QAIC DRM 驱动的路径 (以 NNAPI 为例)：**

1. **Application (Java/Kotlin):**  Android 应用使用 NNAPI 的 Java API (例如 `android.media.nn.NeuralNetworks`) 来构建和执行机器学习模型。
2. **NNAPI Framework (Java):**  Java 层的 NNAPI Framework 接收到应用的请求，进行参数校验和管理。
3. **NNAPI Native (C++):**  Java Framework 通过 JNI 调用到 NNAPI 的 Native 层 (C++ 代码，通常在 `libneuralnetworks.so` 中)。
4. **NNAPI HAL (Hardware Abstraction Layer):** Native 层的 NNAPI 代码会与硬件抽象层 (HAL) 进行交互。Android 定义了 NNAPI HAL 接口，不同的硬件供应商需要实现这个接口来支持其硬件加速器。对于高通平台，可能会有一个实现了 NNAPI HAL 接口的库，例如 `vendor.qti.neuralnetworks@x.x.so`。
5. **QAIC User-space Library (可能存在):**  某些高通平台可能提供一个用户空间的库来简化与 QAIC DRM 驱动的交互，这个库会封装 `ioctl` 调用。
6. **DRM Subsystem:**  NNAPI HAL 或者上述的用户空间库会打开 DRM 设备文件 (`/dev/dri/cardX`)，并使用 `ioctl()` 系统调用，传入 `qaic_accel.handroid` 中定义的 IOCTL 命令和数据结构，与 QAIC DRM 驱动进行通信.
7. **QAIC DRM Driver (Kernel):**  内核中的 QAIC DRM 驱动程序接收到 `ioctl` 调用，解析命令和数据，与 QAIC 硬件加速器进行交互，并将结果返回给用户空间。

**NDK 直接使用 QAIC DRM 驱动：**

NDK 开发者可以直接使用 C/C++ 代码，通过 libc 提供的系统调用接口 (`open`, `ioctl`) 与 QAIC DRM 驱动进行交互。他们需要了解 `qaic_accel.handroid` 中定义的结构体和 IOCTL 命令。

**Frida Hook 示例调试步骤：**

假设我们要 hook `DRM_IOCTL_QAIC_EXECUTE_BO` 这个 IOCTL 命令，查看发送给驱动的数据。

**Frida Hook 脚本 (JavaScript):**

```javascript
// 获取 ioctl 函数的地址
const ioctlPtr = Module.findExportByName("libc.so", "ioctl");

if (ioctlPtr) {
  Interceptor.attach(ioctlPtr, {
    onEnter: function (args) {
      const fd = args[0].toInt32();
      const request = args[1].toInt32();
      const argp = args[2];

      // 检查是否是 DRM_IOCTL_QAIC_EXECUTE_BO 命令
      const DRM_COMMAND_BASE = 0xC0; // 通常的 DRM 命令基址
      const DRM_QAIC_EXECUTE_BO = 0x04;
      const DRM_IOCTL_QAIC_EXECUTE_BO_VALUE = (DRM_COMMAND_BASE + DRM_QAIC_EXECUTE_BO) | (0 << 8) | (0x48 << 16) | (0x80000000); //  DRM_IOW 的值，需要根据架构和定义计算

      if (request === DRM_IOCTL_QAIC_EXECUTE_BO_VALUE) {
        console.log("Detected DRM_IOCTL_QAIC_EXECUTE_BO call!");
        console.log("File Descriptor:", fd);
        console.log("Request Code:", request);

        // 读取 struct qaic_execute 的数据
        const qaic_execute_ptr = argp;
        const hdr_ptr = qaic_execute_ptr;
        const count = Memory.readU32(hdr_ptr);
        const dbc_id = Memory.readU32(hdr_ptr.add(4));
        const data_ptr = ptr(Memory.readU64(qaic_execute_ptr.add(8)));

        console.log("qaic_execute.hdr.count:", count);
        console.log("qaic_execute.hdr.dbc_id:", dbc_id);
        console.log("qaic_execute.data Pointer:", data_ptr);

        if (data_ptr.isNull() === false) {
          // 假设 count 为 1，读取一个 qaic_execute_entry
          const handle = Memory.readU32(data_ptr);
          const dir = Memory.readU32(data_ptr.add(4));
          console.log("qaic_execute_entry.handle:", handle);
          console.log("qaic_execute_entry.dir:", dir);
        }
      }
    },
  });
} else {
  console.error("Failed to find ioctl in libc.so");
}
```

**使用 Frida 调试步骤：**

1. **找到目标进程：**  确定你要调试的应用进程的 PID。
2. **运行 Frida 脚本：** 使用 Frida 将上述脚本注入到目标进程中。例如：
   ```bash
   frida -U -f <package_name> -l hook_qaic_execute.js --no-pause
   # 或者，如果进程已经在运行
   frida -U <process_name_or_pid> -l hook_qaic_execute.js
   ```
3. **触发目标代码：**  在 Android 设备上运行目标应用，并执行触发 QAIC 加速器调用的操作（例如，运行一个使用 NNAPI 的 ML 模型）。
4. **查看 Frida 输出：** Frida 会在控制台输出 hook 到的 `ioctl` 调用信息，包括文件描述符、IOCTL 命令码以及解析出的 `qaic_execute` 结构体的数据。

**注意：**

* 上述 Frida 脚本是一个基本示例，可能需要根据实际情况进行调整，例如调整 `DRM_COMMAND_BASE` 和 `DRM_IOCTL_QAIC_EXECUTE_BO_VALUE` 的计算方式。
* 你可能需要根据具体的 Android 版本和设备厂商的实现来确定 NNAPI HAL 库的名称和路径。
* Hook 内核态的驱动程序通常比较复杂，需要更底层的调试技术，Frida 主要用于 hook 用户空间的函数。

希望以上详细的分析能够帮助你理解 `qaic_accel.handroid` 头文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/drm/qaic_accel.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef QAIC_ACCEL_H_
#define QAIC_ACCEL_H_
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QAIC_MANAGE_MAX_MSG_LENGTH SZ_4K
#define QAIC_SEM_INSYNCFENCE 2
#define QAIC_SEM_OUTSYNCFENCE 1
#define QAIC_SEM_NOP 0
#define QAIC_SEM_INIT 1
#define QAIC_SEM_INC 2
#define QAIC_SEM_DEC 3
#define QAIC_SEM_WAIT_EQUAL 4
#define QAIC_SEM_WAIT_GT_EQ 5
#define QAIC_SEM_WAIT_GT_0 6
#define QAIC_TRANS_UNDEFINED 0
#define QAIC_TRANS_PASSTHROUGH_FROM_USR 1
#define QAIC_TRANS_PASSTHROUGH_TO_USR 2
#define QAIC_TRANS_PASSTHROUGH_FROM_DEV 3
#define QAIC_TRANS_PASSTHROUGH_TO_DEV 4
#define QAIC_TRANS_DMA_XFER_FROM_USR 5
#define QAIC_TRANS_DMA_XFER_TO_DEV 6
#define QAIC_TRANS_ACTIVATE_FROM_USR 7
#define QAIC_TRANS_ACTIVATE_FROM_DEV 8
#define QAIC_TRANS_ACTIVATE_TO_DEV 9
#define QAIC_TRANS_DEACTIVATE_FROM_USR 10
#define QAIC_TRANS_DEACTIVATE_FROM_DEV 11
#define QAIC_TRANS_STATUS_FROM_USR 12
#define QAIC_TRANS_STATUS_TO_USR 13
#define QAIC_TRANS_STATUS_FROM_DEV 14
#define QAIC_TRANS_STATUS_TO_DEV 15
#define QAIC_TRANS_TERMINATE_FROM_DEV 16
#define QAIC_TRANS_TERMINATE_TO_DEV 17
#define QAIC_TRANS_DMA_XFER_CONT 18
#define QAIC_TRANS_VALIDATE_PARTITION_FROM_DEV 19
#define QAIC_TRANS_VALIDATE_PARTITION_TO_DEV 20
struct qaic_manage_trans_hdr {
  __u32 type;
  __u32 len;
};
struct qaic_manage_trans_passthrough {
  struct qaic_manage_trans_hdr hdr;
  __u8 data[];
};
struct qaic_manage_trans_dma_xfer {
  struct qaic_manage_trans_hdr hdr;
  __u32 tag;
  __u32 pad;
  __u64 addr;
  __u64 size;
};
struct qaic_manage_trans_activate_to_dev {
  struct qaic_manage_trans_hdr hdr;
  __u32 queue_size;
  __u32 eventfd;
  __u32 options;
  __u32 pad;
};
struct qaic_manage_trans_activate_from_dev {
  struct qaic_manage_trans_hdr hdr;
  __u32 status;
  __u32 dbc_id;
  __u64 options;
};
struct qaic_manage_trans_deactivate {
  struct qaic_manage_trans_hdr hdr;
  __u32 dbc_id;
  __u32 pad;
};
struct qaic_manage_trans_status_to_dev {
  struct qaic_manage_trans_hdr hdr;
};
struct qaic_manage_trans_status_from_dev {
  struct qaic_manage_trans_hdr hdr;
  __u16 major;
  __u16 minor;
  __u32 status;
  __u64 status_flags;
};
struct qaic_manage_msg {
  __u32 len;
  __u32 count;
  __u64 data;
};
struct qaic_create_bo {
  __u64 size;
  __u32 handle;
  __u32 pad;
};
struct qaic_mmap_bo {
  __u32 handle;
  __u32 pad;
  __u64 offset;
};
struct qaic_sem {
  __u16 val;
  __u8 index;
  __u8 presync;
  __u8 cmd;
  __u8 flags;
  __u16 pad;
};
struct qaic_attach_slice_entry {
  __u64 size;
  struct qaic_sem sem0;
  struct qaic_sem sem1;
  struct qaic_sem sem2;
  struct qaic_sem sem3;
  __u64 dev_addr;
  __u64 db_addr;
  __u32 db_data;
  __u32 db_len;
  __u64 offset;
};
struct qaic_attach_slice_hdr {
  __u32 count;
  __u32 dbc_id;
  __u32 handle;
  __u32 dir;
  __u64 size;
};
struct qaic_attach_slice {
  struct qaic_attach_slice_hdr hdr;
  __u64 data;
};
struct qaic_execute_entry {
  __u32 handle;
  __u32 dir;
};
struct qaic_partial_execute_entry {
  __u32 handle;
  __u32 dir;
  __u64 resize;
};
struct qaic_execute_hdr {
  __u32 count;
  __u32 dbc_id;
};
struct qaic_execute {
  struct qaic_execute_hdr hdr;
  __u64 data;
};
struct qaic_wait {
  __u32 handle;
  __u32 timeout;
  __u32 dbc_id;
  __u32 pad;
};
struct qaic_perf_stats_hdr {
  __u16 count;
  __u16 pad;
  __u32 dbc_id;
};
struct qaic_perf_stats {
  struct qaic_perf_stats_hdr hdr;
  __u64 data;
};
struct qaic_perf_stats_entry {
  __u32 handle;
  __u32 queue_level_before;
  __u32 num_queue_element;
  __u32 submit_latency_us;
  __u32 device_latency_us;
  __u32 pad;
};
struct qaic_detach_slice {
  __u32 handle;
  __u32 pad;
};
#define DRM_QAIC_MANAGE 0x00
#define DRM_QAIC_CREATE_BO 0x01
#define DRM_QAIC_MMAP_BO 0x02
#define DRM_QAIC_ATTACH_SLICE_BO 0x03
#define DRM_QAIC_EXECUTE_BO 0x04
#define DRM_QAIC_PARTIAL_EXECUTE_BO 0x05
#define DRM_QAIC_WAIT_BO 0x06
#define DRM_QAIC_PERF_STATS_BO 0x07
#define DRM_QAIC_DETACH_SLICE_BO 0x08
#define DRM_IOCTL_QAIC_MANAGE DRM_IOWR(DRM_COMMAND_BASE + DRM_QAIC_MANAGE, struct qaic_manage_msg)
#define DRM_IOCTL_QAIC_CREATE_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_QAIC_CREATE_BO, struct qaic_create_bo)
#define DRM_IOCTL_QAIC_MMAP_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_QAIC_MMAP_BO, struct qaic_mmap_bo)
#define DRM_IOCTL_QAIC_ATTACH_SLICE_BO DRM_IOW(DRM_COMMAND_BASE + DRM_QAIC_ATTACH_SLICE_BO, struct qaic_attach_slice)
#define DRM_IOCTL_QAIC_EXECUTE_BO DRM_IOW(DRM_COMMAND_BASE + DRM_QAIC_EXECUTE_BO, struct qaic_execute)
#define DRM_IOCTL_QAIC_PARTIAL_EXECUTE_BO DRM_IOW(DRM_COMMAND_BASE + DRM_QAIC_PARTIAL_EXECUTE_BO, struct qaic_execute)
#define DRM_IOCTL_QAIC_WAIT_BO DRM_IOW(DRM_COMMAND_BASE + DRM_QAIC_WAIT_BO, struct qaic_wait)
#define DRM_IOCTL_QAIC_PERF_STATS_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_QAIC_PERF_STATS_BO, struct qaic_perf_stats)
#define DRM_IOCTL_QAIC_DETACH_SLICE_BO DRM_IOW(DRM_COMMAND_BASE + DRM_QAIC_DETACH_SLICE_BO, struct qaic_detach_slice)
#ifdef __cplusplus
}
#endif
#endif

"""

```