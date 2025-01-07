Response:
Let's break down the thought process for analyzing the provided C header file and generating the comprehensive answer.

**1. Understanding the Context:**

The prompt clearly states that this is a header file (`.h`) located within the Android Bionic library, specifically related to the DRM (Direct Rendering Manager) subsystem and an "ivpu" (likely an internal video processing unit). This immediately tells us that the code is dealing with low-level hardware interaction, likely related to graphics or video acceleration.

**2. Initial Pass - Identifying Key Elements:**

I'd first scan the file for obvious keywords and patterns:

* **`#ifndef`, `#define`, `#include`:** Standard C header file guards. Not directly functional, but essential for avoiding multiple inclusions.
* **`extern "C"`:**  Indicates this header is designed to be compatible with C++ code.
* **`DRM_IVPU_DRIVER_MAJOR`, `DRM_IVPU_DRIVER_MINOR`:**  Version information for the driver.
* **`DRM_IVPU_GET_PARAM`, `DRM_IVPU_SET_PARAM`, etc.:**  These are macro definitions, and the names strongly suggest Input/Output Control (IOCTL) commands. The `GET` and `SET` patterns for `PARAM` are common. The `BO` prefix likely refers to "buffer object," a standard DRM concept. `SUBMIT` points to submitting work to the IVPU. `METRIC_STREAMER` suggests performance monitoring.
* **`DRM_IOCTL_IVPU_...`:**  These clearly define the specific IOCTL numbers associated with the previously defined commands. The `DRM_IOWR` and `DRM_IOW` macros hint at the direction of data transfer (read/write).
* **`DRM_IVPU_PARAM_...`:**  Enums or constants defining specific parameters that can be queried or set.
* **`DRM_IVPU_PLATFORM_TYPE_...`, `DRM_IVPU_CONTEXT_PRIORITY_...`, `DRM_IVPU_JOB_PRIORITY_...`, `DRM_IVPU_CAP_...`:**  More enums/constants defining specific values or capabilities.
* **`struct drm_ivpu_...`:**  Structures defining the data exchanged with the kernel via IOCTLs.

**3. Deeper Analysis - Grouping and Inferring Functionality:**

Now, I'd group related items and infer their purpose:

* **Parameter Handling (`DRM_IVPU_GET_PARAM`, `DRM_IVPU_SET_PARAM`, `DRM_IVPU_PARAM_*`, `struct drm_ivpu_param`):** This is clearly for querying and configuring the IVPU's operational parameters. Think of it like getting device information or setting its clock speed.
* **Buffer Management (`DRM_IVPU_BO_CREATE`, `DRM_IVPU_BO_INFO`, `DRM_IVPU_BO_WAIT`, `DRM_IVPU_BO_*`, `struct drm_ivpu_bo_create`, `struct drm_ivpu_bo_info`, `struct drm_ivpu_bo_wait`):** This section deals with allocating, querying, and waiting for buffer objects used by the IVPU. Buffer objects are fundamental for transferring data to and from hardware accelerators.
* **Job Submission (`DRM_IVPU_SUBMIT`, `DRM_IVPU_ENGINE_*`, `DRM_IVPU_JOB_PRIORITY_*`, `struct drm_ivpu_submit`, `struct drm_ivpu_bo_wait`):** This handles submitting tasks or "jobs" to the IVPU for processing. The `ENGINE` and `PRIORITY` hints at different processing units and scheduling. The reuse of `drm_ivpu_bo_wait` suggests waiting for job completion.
* **Performance Monitoring (`DRM_IVPU_METRIC_STREAMER_START`, `DRM_IVPU_METRIC_STREAMER_STOP`, `DRM_IVPU_METRIC_STREAMER_GET_DATA`, `DRM_IVPU_METRIC_STREAMER_GET_INFO`, `DRM_IVPU_CAP_METRIC_STREAMER`, `struct drm_ivpu_metric_streamer_*`):** This set of definitions relates to collecting performance metrics from the IVPU.

**4. Connecting to Android:**

The file's location within Bionic and the "drm" prefix are strong indicators of its connection to Android's graphics stack. I would then consider:

* **SurfaceFlinger:** The Android system service responsible for compositing and displaying surfaces. It likely interacts with DRM drivers.
* **Hardware Abstraction Layer (HAL):**  Android uses HALs to abstract hardware specifics. There's likely an IVPU HAL that uses these DRM interfaces.
* **NDK (Native Development Kit):**  Developers using the NDK can directly interact with low-level graphics APIs, potentially indirectly using these interfaces.

**5. Addressing Specific Requirements of the Prompt:**

* **Libc Functions:**  This header file *defines* interfaces but doesn't *implement* libc functions directly. The interaction happens through the `ioctl()` system call, which is a libc function. I'd explain how `ioctl()` is used in conjunction with the defined IOCTL numbers.
* **Dynamic Linker:**  This header file doesn't directly involve the dynamic linker. The *implementation* of the IVPU driver (likely a kernel module) and user-space libraries using it would be dynamically linked. I'd provide a conceptual example of how such libraries might be structured.
* **Logic Inference and Assumptions:** When discussing IOCTLs, I'd make the logical connection that writing (`_IOW`) means sending data to the kernel, while read/write (`_IOWR`) means sending and receiving data. Assumptions would be based on standard DRM practices.
* **Common Errors:**  I'd think about typical mistakes when dealing with hardware interfaces, such as incorrect IOCTL numbers, invalid data structures, or failure to handle errors returned by `ioctl()`.
* **Android Framework/NDK Flow:** I would trace the path from a high-level Android API (like `Surface`) down to the eventual `ioctl()` call using the definitions from this header.
* **Frida Hooking:**  Since it's a system call interface, Frida would be a natural fit for intercepting `ioctl()` calls. I would illustrate how to hook `ioctl()` and filter for the relevant IVPU commands.

**6. Structuring the Answer:**

Finally, I'd organize the information logically, using clear headings and explanations. The goal is to be comprehensive yet understandable. I'd start with the core functionalities, then move to Android specifics, and then address the more technical aspects like libc, dynamic linking, and debugging. Using bullet points, code examples (even if conceptual), and clear language would enhance readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on the *declarations* and not enough on the *usage*.
* **Correction:**  Shift focus to how these declarations are used in conjunction with system calls and higher-level Android components.
* **Initial thought:** Get bogged down in the low-level bitwise operations of the flags.
* **Correction:** Briefly explain the meaning of the flags without going into excessive detail, focusing on the higher-level concepts like caching and memory location.
* **Initial thought:**  Overcomplicate the dynamic linker section.
* **Correction:** Keep the dynamic linker explanation conceptual, showing the basic structure and linking process without getting into the intricacies of relocation.

By following these steps and iterating through the analysis, I can generate a detailed and accurate answer that addresses all aspects of the prompt.
好的，我们来详细分析一下 `bionic/libc/kernel/uapi/drm/ivpu_accel.handroid` 这个头文件。这个文件定义了与 Android 系统中 IVPU（Integrated Video Processing Unit，集成视频处理单元）硬件加速相关的用户空间 API。它使用了 Linux DRM（Direct Rendering Manager，直接渲染管理器）框架。

**1. 功能列举:**

这个头文件定义了与 IVPU 硬件加速交互所需的常量、宏和数据结构。主要功能包括：

* **驱动程序信息:** 定义了 IVPU 驱动的主次版本号 (`DRM_IVPU_DRIVER_MAJOR`, `DRM_IVPU_DRIVER_MINOR`)。
* **IOCTL 命令:** 定义了用户空间程序与 IVPU 驱动通信的 IOCTL (Input/Output Control) 命令，用于执行各种操作，例如：
    * 获取/设置 IVPU 参数 (`DRM_IVPU_GET_PARAM`, `DRM_IVPU_SET_PARAM`)
    * 创建/查询 Buffer Object (BO) 信息 (`DRM_IVPU_BO_CREATE`, `DRM_IVPU_BO_INFO`)
    * 提交任务给 IVPU (`DRM_IVPU_SUBMIT`)
    * 等待 BO 完成 (`DRM_IVPU_BO_WAIT`)
    * 启动/停止/获取 IVPU 性能指标流 (`DRM_IVPU_METRIC_STREAMER_START`, `DRM_IVPU_METRIC_STREAMER_STOP`, `DRM_IVPU_METRIC_STREAMER_GET_DATA`, `DRM_IVPU_METRIC_STREAMER_GET_INFO`)
* **参数定义:** 定义了可以通过 `DRM_IVPU_GET_PARAM` 和 `DRM_IVPU_SET_PARAM` 获取或设置的 IVPU 参数，例如设备 ID、修订版本、平台类型、时钟频率、上下文数量、固件 API 版本等。
* **常量定义:** 定义了与 IVPU 操作相关的常量，例如平台类型、上下文优先级、任务优先级、BO 标志位、引擎类型、任务状态和性能指标能力等。
* **数据结构:** 定义了用于与 IVPU 驱动交互的数据结构，例如：
    * `drm_ivpu_param`: 用于获取和设置 IVPU 参数。
    * `drm_ivpu_bo_create`: 用于创建 BO。
    * `drm_ivpu_bo_info`: 用于获取 BO 信息。
    * `drm_ivpu_submit`: 用于提交任务给 IVPU。
    * `drm_ivpu_bo_wait`: 用于等待 BO 完成。
    * `drm_ivpu_metric_streamer_*`: 用于控制和获取 IVPU 性能指标流。

**2. 与 Android 功能的关系及举例:**

这个头文件直接关系到 Android 系统中利用 IVPU 进行硬件加速的功能。IVPU 通常用于处理视频编解码、图像处理、机器学习等计算密集型任务，以提高性能并降低功耗。

**举例说明:**

* **多媒体编解码:** Android 的 MediaCodec API 可以利用 IVPU 进行视频的硬件编码和解码。例如，当播放高清视频时，解码器可以使用 IVPU 来加速解码过程，从而流畅播放视频。
* **Camera 图像处理:** Android 的 Camera API 可以使用 IVPU 进行实时的图像处理，例如降噪、锐化、色彩校正等。这可以提高相机应用的性能和图像质量。
* **机器学习加速:** Android 的 Neural Networks API (NNAPI) 可以将机器学习模型的推理任务卸载到 IVPU 上进行加速，例如图像识别、物体检测等。

**3. libc 函数的功能及实现:**

这个头文件本身并不包含 libc 函数的实现，它只是定义了常量、宏和数据结构。用户空间程序需要使用 libc 提供的系统调用接口（例如 `ioctl`）来与内核中的 IVPU 驱动进行交互。

**`ioctl` 函数:**

`ioctl` 是一个通用的设备控制系统调用，允许用户空间程序向设备驱动程序发送控制命令并传递数据。在这个上下文中，用户空间程序会使用 `ioctl` 系统调用，并将定义在 `drm_ivpu_accel.handroid` 中的 `DRM_IOCTL_IVPU_*` 宏作为请求参数传递给内核驱动。

**实现原理:**

1. 用户空间程序调用 `ioctl` 函数，提供文件描述符（指向 IVPU 设备节点，例如 `/dev/dri/renderDxxx`）、IOCTL 命令（例如 `DRM_IOCTL_IVPU_GET_PARAM`）以及指向数据结构的指针。
2. 内核接收到 `ioctl` 系统调用后，会根据文件描述符找到对应的 IVPU 驱动程序。
3. IVPU 驱动程序会解析 IOCTL 命令，并根据命令执行相应的操作。例如，如果是 `DRM_IOCTL_IVPU_GET_PARAM`，驱动程序会读取相应的硬件寄存器或内部状态，并将结果填充到用户空间传递的数据结构中。
4. `ioctl` 系统调用返回，用户空间程序可以访问驱动程序返回的数据。

**4. 涉及 dynamic linker 的功能，so 布局样本和链接过程:**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker 主要负责在程序启动时加载和链接共享库（.so 文件）。

但是，使用 IVPU 加速功能的 Android 组件通常会链接到与硬件抽象层 (HAL) 相关的共享库。这些 HAL 库会使用这个头文件中定义的常量和数据结构来与 IVPU 驱动进行交互。

**so 布局样本:**

假设一个使用 IVPU 加速的 Camera HAL 库 `vendor.foo.hardware.camera@device.so`：

```
vendor.foo.hardware.camera@device.so:
    NEEDED libbinder.so
    NEEDED libcutils.so
    ... 其他依赖库
    # 可能会有直接或间接依赖于 libdrm.so (DRM 库)，而 libdrm.so 会使用这里的定义
    # 或者直接包含一些辅助函数来调用 ioctl 并使用这里的定义
```

**链接处理过程:**

1. 当 Android 系统启动或某个进程需要使用 Camera HAL 时，dynamic linker 会根据配置文件（例如 `ld.config.txt`）找到 `vendor.foo.hardware.camera@device.so`。
2. Dynamic linker 会加载 `vendor.foo.hardware.camera@device.so` 到进程的地址空间。
3. Dynamic linker 会解析 `vendor.foo.hardware.camera@device.so` 的依赖关系，并加载其依赖的共享库，例如 `libbinder.so`、`libcutils.so` 和可能的 `libdrm.so`。
4. 如果 `vendor.foo.hardware.camera@device.so` 直接使用了 `ioctl` 系统调用并使用了 `drm_ivpu_accel.handroid` 中定义的常量和结构体，那么这些定义会在编译时被包含到 HAL 库中。如果使用了 `libdrm.so`，那么 `libdrm.so` 内部会处理与 DRM 驱动的交互。

**5. 逻辑推理、假设输入与输出:**

**示例：获取 IVPU 设备 ID**

**假设输入:**

* 用户空间程序打开了 IVPU 设备节点的文件描述符 `fd`。
* 用户空间程序创建了一个 `drm_ivpu_param` 结构体，并将 `param` 设置为 `DRM_IVPU_PARAM_DEVICE_ID`。

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/drm.h>
#include "ivpu_accel.handroid" // 假设头文件在当前目录

int main() {
    int fd = open("/dev/dri/renderDxxx", O_RDWR); // 替换为实际的设备节点
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct drm_ivpu_param param;
    param.param = DRM_IVPU_PARAM_DEVICE_ID;
    param.index = 0; // 通常为 0
    param.value = 0;

    if (ioctl(fd, DRM_IOCTL_IVPU_GET_PARAM, &param) == -1) {
        perror("ioctl");
        close(fd);
        return 1;
    }

    printf("IVPU Device ID: %lu\n", param.value);

    close(fd);
    return 0;
}
```

**逻辑推理:**

程序调用 `ioctl` 函数，将 `DRM_IOCTL_IVPU_GET_PARAM` 命令和指向 `param` 结构体的指针传递给 IVPU 驱动。驱动程序会读取 IVPU 硬件的设备 ID，并将结果写入 `param.value`。

**假设输出:**

```
IVPU Device ID: 1234  // 实际值取决于硬件
```

**6. 用户或编程常见的使用错误:**

* **错误的 IOCTL 命令:** 使用了错误的 `DRM_IOCTL_IVPU_*` 宏，导致驱动程序无法识别请求。
* **错误的数据结构:** 传递给 `ioctl` 的数据结构内容不正确，例如字段顺序错误、大小错误或值超出范围。
* **权限不足:** 用户空间程序没有足够的权限访问 IVPU 设备节点。
* **设备节点不存在:** 尝试打开不存在的 IVPU 设备节点（例如 `/dev/dri/renderDxxx`）。
* **忘记检查返回值:** `ioctl` 调用可能会失败，返回 -1，但程序没有检查返回值并处理错误。
* **竞态条件:** 在多线程或多进程环境中，对 IVPU 资源的访问可能存在竞态条件，需要适当的同步机制。
* **内存管理错误:**  例如，传递给 `DRM_IOCTL_IVPU_SUBMIT` 的 buffer 指针无效或已释放。

**示例：忘记检查 ioctl 返回值**

```c
    // ... 打开设备节点并设置 param ...

    ioctl(fd, DRM_IOCTL_IVPU_GET_PARAM, &param); // 忘记检查返回值
    printf("IVPU Device ID: %lu\n", param.value); // 如果 ioctl 失败，param.value 的值可能未定义

    // ...
```

**7. Android Framework 或 NDK 如何到达这里，给出 Frida Hook 示例:**

**流程说明:**

1. **Android Framework (Java 层):**  例如，一个使用 MediaCodec API 进行硬件解码的应用。
2. **MediaCodec Service (C++ 层):** Framework 通过 Binder IPC 调用 MediaCodec Service。
3. **Codec 接口实现 (C++ 层):** MediaCodec Service 会加载相应的 Codec 插件，这些插件通常会使用 Android 的 Media Framework (libmedia).
4. **Hardware Abstraction Layer (HAL) (C++ 层):**  Codec 插件会调用与 IVPU 相关的 HAL 接口，例如 Video 解码器 HAL。
5. **DRM 库 (libdrm.so) 或直接调用:**  HAL 库可能会使用 `libdrm.so` 来与 DRM 子系统交互，或者直接调用 `ioctl` 系统调用，并使用 `drm_ivpu_accel.handroid` 中定义的常量和结构体。
6. **Kernel Driver (内核层):**  最终，`ioctl` 系统调用会将请求传递给 IVPU 的内核驱动程序。

**Frida Hook 示例:**

可以使用 Frida hook `ioctl` 系统调用，并过滤出与 IVPU 相关的 IOCTL 命令。

```javascript
if (Process.platform === 'linux') {
  const ioctlPtr = Module.getExportByName(null, 'ioctl');
  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        // 检查文件描述符是否可能与 DRM 设备相关
        const pathBuf = Memory.allocUtf8String(256);
        const ret = syscall(Process.constants.syscall.SYS_readlink, fd, pathBuf, 255);
        if (ret.toInt32() > 0) {
          const path = pathBuf.readUtf8String();
          if (path && path.startsWith("/dev/dri/")) {
            // 检查是否是 IVPU 相关的 IOCTL 命令
            const ivpu_cmds = [
              0x40106400, // DRM_IOCTL_IVPU_GET_PARAM
              0x80106401, // DRM_IOCTL_IVPU_SET_PARAM
              0xc0186402, // DRM_IOCTL_IVPU_BO_CREATE
              0xc0186403, // DRM_IOCTL_IVPU_BO_INFO
              0x80106405, // DRM_IOCTL_IVPU_SUBMIT
              0xc0186406, // DRM_IOCTL_IVPU_BO_WAIT
              0xc0206407, // DRM_IOCTL_IVPU_METRIC_STREAMER_START
              0x80086408, // DRM_IOCTL_IVPU_METRIC_STREAMER_STOP
              0xc0206409, // DRM_IOCTL_IVPU_METRIC_STREAMER_GET_DATA
              0xc020640a  // DRM_IOCTL_IVPU_METRIC_STREAMER_GET_INFO
            ];
            if (ivpu_cmds.includes(request)) {
              console.log("ioctl called with IVPU command:", request.toString(16), "fd:", fd, "path:", path);
              // 可以进一步解析参数 args[2] 指向的数据结构
            }
          }
        }
      },
      onLeave: function (retval) {
        // console.log("ioctl returned:", retval);
      }
    });
  } else {
    console.error("Could not find ioctl function");
  }
} else {
  console.log("This script is for Linux only.");
}
```

**解释:**

1. **获取 `ioctl` 地址:** 使用 `Module.getExportByName(null, 'ioctl')` 获取 `ioctl` 函数在内存中的地址。
2. **附加 Interceptor:** 使用 `Interceptor.attach` 拦截 `ioctl` 函数的调用。
3. **`onEnter` 函数:** 在 `ioctl` 函数被调用前执行。
4. **获取参数:** 从 `args` 数组中获取文件描述符 `fd` 和请求码 `request`。
5. **检查文件路径:** 使用 `readlink` 系统调用尝试获取文件描述符对应的路径，判断是否是 `/dev/dri/` 下的设备。
6. **过滤 IVPU 命令:** 检查 `request` 是否是 `drm_ivpu_accel.handroid` 中定义的 IVPU 相关的 IOCTL 命令。
7. **打印信息:** 如果是 IVPU 命令，则打印相关信息，包括命令码、文件描述符和设备路径。
8. **解析参数 (可选):** 可以进一步解析 `args[2]` 指针指向的数据结构，以获取更详细的调用信息。

通过这个 Frida Hook 示例，可以监控 Android 系统中哪些进程在调用与 IVPU 相关的 IOCTL 命令，从而了解 IVPU 的使用情况。

希望以上分析能够帮助你理解 `bionic/libc/kernel/uapi/drm/ivpu_accel.handroid` 文件的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/drm/ivpu_accel.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __UAPI_IVPU_DRM_H__
#define __UAPI_IVPU_DRM_H__
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#define DRM_IVPU_DRIVER_MAJOR 1
#define DRM_IVPU_DRIVER_MINOR 0
#define DRM_IVPU_GET_PARAM 0x00
#define DRM_IVPU_SET_PARAM 0x01
#define DRM_IVPU_BO_CREATE 0x02
#define DRM_IVPU_BO_INFO 0x03
#define DRM_IVPU_SUBMIT 0x05
#define DRM_IVPU_BO_WAIT 0x06
#define DRM_IVPU_METRIC_STREAMER_START 0x07
#define DRM_IVPU_METRIC_STREAMER_STOP 0x08
#define DRM_IVPU_METRIC_STREAMER_GET_DATA 0x09
#define DRM_IVPU_METRIC_STREAMER_GET_INFO 0x0a
#define DRM_IOCTL_IVPU_GET_PARAM DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_GET_PARAM, struct drm_ivpu_param)
#define DRM_IOCTL_IVPU_SET_PARAM DRM_IOW(DRM_COMMAND_BASE + DRM_IVPU_SET_PARAM, struct drm_ivpu_param)
#define DRM_IOCTL_IVPU_BO_CREATE DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_BO_CREATE, struct drm_ivpu_bo_create)
#define DRM_IOCTL_IVPU_BO_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_BO_INFO, struct drm_ivpu_bo_info)
#define DRM_IOCTL_IVPU_SUBMIT DRM_IOW(DRM_COMMAND_BASE + DRM_IVPU_SUBMIT, struct drm_ivpu_submit)
#define DRM_IOCTL_IVPU_BO_WAIT DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_BO_WAIT, struct drm_ivpu_bo_wait)
#define DRM_IOCTL_IVPU_METRIC_STREAMER_START DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_START, struct drm_ivpu_metric_streamer_start)
#define DRM_IOCTL_IVPU_METRIC_STREAMER_STOP DRM_IOW(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_STOP, struct drm_ivpu_metric_streamer_stop)
#define DRM_IOCTL_IVPU_METRIC_STREAMER_GET_DATA DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_GET_DATA, struct drm_ivpu_metric_streamer_get_data)
#define DRM_IOCTL_IVPU_METRIC_STREAMER_GET_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_GET_INFO, struct drm_ivpu_metric_streamer_get_data)
#define DRM_IVPU_PARAM_DEVICE_ID 0
#define DRM_IVPU_PARAM_DEVICE_REVISION 1
#define DRM_IVPU_PARAM_PLATFORM_TYPE 2
#define DRM_IVPU_PARAM_CORE_CLOCK_RATE 3
#define DRM_IVPU_PARAM_NUM_CONTEXTS 4
#define DRM_IVPU_PARAM_CONTEXT_BASE_ADDRESS 5
#define DRM_IVPU_PARAM_CONTEXT_PRIORITY 6
#define DRM_IVPU_PARAM_CONTEXT_ID 7
#define DRM_IVPU_PARAM_FW_API_VERSION 8
#define DRM_IVPU_PARAM_ENGINE_HEARTBEAT 9
#define DRM_IVPU_PARAM_UNIQUE_INFERENCE_ID 10
#define DRM_IVPU_PARAM_TILE_CONFIG 11
#define DRM_IVPU_PARAM_SKU 12
#define DRM_IVPU_PARAM_CAPABILITIES 13
#define DRM_IVPU_PLATFORM_TYPE_SILICON 0
#define DRM_IVPU_CONTEXT_PRIORITY_IDLE 0
#define DRM_IVPU_CONTEXT_PRIORITY_NORMAL 1
#define DRM_IVPU_CONTEXT_PRIORITY_FOCUS 2
#define DRM_IVPU_CONTEXT_PRIORITY_REALTIME 3
#define DRM_IVPU_JOB_PRIORITY_DEFAULT 0
#define DRM_IVPU_JOB_PRIORITY_IDLE 1
#define DRM_IVPU_JOB_PRIORITY_NORMAL 2
#define DRM_IVPU_JOB_PRIORITY_FOCUS 3
#define DRM_IVPU_JOB_PRIORITY_REALTIME 4
#define DRM_IVPU_CAP_METRIC_STREAMER 1
#define DRM_IVPU_CAP_DMA_MEMORY_RANGE 2
struct drm_ivpu_param {
  __u32 param;
  __u32 index;
  __u64 value;
};
#define DRM_IVPU_BO_SHAVE_MEM 0x00000001
#define DRM_IVPU_BO_HIGH_MEM DRM_IVPU_BO_SHAVE_MEM
#define DRM_IVPU_BO_MAPPABLE 0x00000002
#define DRM_IVPU_BO_DMA_MEM 0x00000004
#define DRM_IVPU_BO_CACHED 0x00000000
#define DRM_IVPU_BO_UNCACHED 0x00010000
#define DRM_IVPU_BO_WC 0x00020000
#define DRM_IVPU_BO_CACHE_MASK 0x00030000
#define DRM_IVPU_BO_FLAGS (DRM_IVPU_BO_HIGH_MEM | DRM_IVPU_BO_MAPPABLE | DRM_IVPU_BO_DMA_MEM | DRM_IVPU_BO_CACHE_MASK)
struct drm_ivpu_bo_create {
  __u64 size;
  __u32 flags;
  __u32 handle;
  __u64 vpu_addr;
};
struct drm_ivpu_bo_info {
  __u32 handle;
  __u32 flags;
  __u64 vpu_addr;
  __u64 mmap_offset;
  __u64 size;
};
#define DRM_IVPU_ENGINE_COMPUTE 0
#define DRM_IVPU_ENGINE_COPY 1
struct drm_ivpu_submit {
  __u64 buffers_ptr;
  __u32 buffer_count;
  __u32 engine;
  __u32 flags;
  __u32 commands_offset;
  __u32 priority;
};
#define DRM_IVPU_JOB_STATUS_SUCCESS 0
#define DRM_IVPU_JOB_STATUS_ABORTED 256
struct drm_ivpu_bo_wait {
  __u32 handle;
  __u32 flags;
  __s64 timeout_ns;
  __u32 job_status;
  __u32 pad;
};
struct drm_ivpu_metric_streamer_start {
  __u64 metric_group_mask;
  __u64 sampling_period_ns;
  __u32 read_period_samples;
  __u32 sample_size;
  __u32 max_data_size;
};
struct drm_ivpu_metric_streamer_get_data {
  __u64 metric_group_mask;
  __u64 buffer_ptr;
  __u64 buffer_size;
  __u64 data_size;
};
struct drm_ivpu_metric_streamer_stop {
  __u64 metric_group_mask;
};
#ifdef __cplusplus
}
#endif
#endif

"""

```