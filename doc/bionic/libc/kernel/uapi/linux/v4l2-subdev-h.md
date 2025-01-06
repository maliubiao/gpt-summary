Response:
Let's break down the thought process for analyzing this header file.

**1. Understanding the Context:**

The prompt clearly states the file path and that `bionic` is Android's C library. This immediately tells us:

* **Kernel Interface:** This file defines structures and constants for interacting with a Linux kernel subsystem. Specifically, it's under `uapi`, indicating it's the *user-space* API for a kernel module.
* **V4L2:** The filename `v4l2-subdev.h` is a strong indicator. V4L2 stands for Video for Linux version 2, a core Linux framework for video capture and processing. The "subdev" part suggests it deals with individual components within a larger video pipeline (like sensors, encoders, etc.).
* **Android Relevance:** Since it's part of Bionic, it's a *crucial* component for Android's multimedia framework. Android devices heavily rely on cameras and video processing.

**2. Initial Scan for Keywords and Patterns:**

A quick skim reveals recurring patterns:

* **`struct v4l2_subdev_*`:**  This confirms the focus on data structures related to V4L2 subdevices.
* **`__u32`, `__u64`:**  These are standard Linux kernel types for unsigned 32-bit and 64-bit integers.
* **`#define V4L2_SUBDEV_*`:** These are preprocessor definitions, mostly constants and bitmasks.
* **`#define VIDIOC_SUBDEV_*`:**  These look like ioctl (input/output control) commands. The `_IOR`, `_IOWR`, `_IOW` macros are telltale signs of ioctl definitions. The 'V' likely signifies it's related to video.

**3. Grouping and Categorizing Functionality:**

Based on the identified patterns, we can start grouping the elements:

* **Data Structures (`struct v4l2_subdev_*`):**  These represent different aspects of a subdevice's configuration and state (format, crop, frame interval, routing, capabilities, etc.).
* **Enums (`enum v4l2_subdev_format_whence`):** These define sets of related named constants.
* **Constants (`#define V4L2_SUBDEV_*`):** These provide symbolic names for numerical values, often used as flags or identifiers.
* **IOCTLs (`#define VIDIOC_SUBDEV_*`):** These are the actual commands used to interact with the kernel driver. The naming convention (G for Get, S for Set, ENUM for Enumerate, QUERY for Query) is helpful.

**4. Analyzing Individual Structures and IOCTLs:**

Now, let's delve into the specifics of some key elements:

* **`v4l2_subdev_format`:**  This structure clearly deals with the video format (resolution, pixel format, etc.) of a subdevice. The `which` field suggests the ability to get/set the current format or a proposed/trial format.
* **`v4l2_subdev_crop`:** Deals with defining a region of interest (ROI) within the video stream.
* **`v4l2_subdev_capability`:**  Describes the supported features of the subdevice.
* **`v4l2_subdev_routing`:**  Handles how different subdevices are connected in a video pipeline.
* **`VIDIOC_SUBDEV_G_FMT`, `VIDIOC_SUBDEV_S_FMT`:**  These ioctls are the most direct way to get and set the video format, using the `v4l2_subdev_format` structure.

**5. Connecting to Android Functionality:**

This is where the Android context becomes crucial:

* **Camera HAL (Hardware Abstraction Layer):** The Camera HAL is the interface between the Android framework and the specific camera hardware on a device. This header file *directly* impacts the implementation of Camera HAL modules. HAL implementations use these ioctls to configure the camera sensor, image signal processor (ISP), and other video-related components.
* **Media Framework:**  Higher-level Android APIs (like `android.hardware.camera2`) abstract away the low-level details, but under the hood, they rely on the Camera HAL, which in turn interacts with the kernel using these V4L2 structures and ioctls.
* **NDK:** Developers can use the NDK to write native code that directly interacts with V4L2, although this is less common for standard application development and more prevalent for hardware-specific libraries or specialized applications.

**6. Addressing Specific Prompt Points:**

* **libc Functions:**  This header file *defines* structures and constants. It doesn't contain libc function *implementations*. The libc functions used would be those related to interacting with device drivers, primarily `ioctl()`. We can explain how `ioctl()` works in general.
* **Dynamic Linker:** This header file is a static definition. It doesn't involve dynamic linking in the same way that a shared library does. However, the Camera HAL modules that *use* these definitions are shared libraries, so we can discuss the linking process of a typical `.so` and how it might interact with the kernel.
* **User Errors:**  Common mistakes involve using incorrect ioctl numbers, passing invalid data in the structures, or trying to set parameters that are not supported by the specific hardware.
* **Frida Hooking:** We can devise examples of how Frida could be used to intercept ioctl calls related to V4L2 subdevices.

**7. Structuring the Answer:**

Finally, organize the information logically, following the points raised in the prompt:

* Start with a general overview of the file's purpose.
* Explain the key data structures and their roles.
* Discuss the ioctl commands and how they are used.
* Detail the connections to Android's camera system.
* Explain the relevant libc functions (specifically `ioctl`).
* Address the dynamic linker aspect (focusing on the `.so` that *uses* these definitions).
* Provide examples of user errors.
* Illustrate how the Android framework reaches this level and how Frida can be used for debugging.

This systematic approach allows for a comprehensive and well-structured answer that addresses all aspects of the prompt. The key is to understand the context, identify the core elements, and then connect those elements to the broader Android ecosystem.
这个头文件 `bionic/libc/kernel/uapi/linux/v4l2-subdev.handroid` 是 Android 系统中 Bionic C 库的一部分，它定义了用户空间程序与 Linux 内核中 V4L2 (Video for Linux version 2) 子设备驱动进行交互所需的常量、数据结构和 ioctl 命令。V4L2 是 Linux 系统中处理视频输入、输出和编解码的标准框架。

**功能列举:**

这个头文件主要定义了以下功能：

1. **数据结构定义:** 定义了用于描述 V4L2 子设备状态和配置的各种数据结构，例如：
    * `v4l2_subdev_format`: 描述子设备的视频格式 (例如，分辨率、像素格式)。
    * `v4l2_subdev_crop`: 描述子设备的裁剪区域。
    * `v4l2_subdev_mbus_code_enum`: 用于枚举子设备支持的媒体总线代码 (用于描述像素格式)。
    * `v4l2_subdev_frame_size_enum`: 用于枚举子设备支持的帧大小范围。
    * `v4l2_subdev_frame_interval`: 描述子设备的帧间隔。
    * `v4l2_subdev_frame_interval_enum`: 用于枚举子设备支持的帧间隔。
    * `v4l2_subdev_selection`: 描述子设备的选择区域（例如，对焦窗口）。
    * `v4l2_subdev_capability`: 描述子设备的功能。
    * `v4l2_subdev_route`: 描述子设备之间的连接路由。
    * `v4l2_subdev_routing`: 包含多个子设备路由信息的结构。
    * `v4l2_subdev_client_capability`: 描述客户端（用户空间程序）支持的功能。

2. **枚举类型定义:** 定义了枚举类型 `v4l2_subdev_format_whence`，用于指定获取或设置格式时是尝试性的还是激活的。

3. **常量定义:** 定义了一些宏常量，例如：
    * `V4L2_SUBDEV_MBUS_CODE_CSC_*`:  与色彩空间转换相关的媒体总线代码。
    * `V4L2_SUBDEV_CAP_*`:  子设备的功能标志。
    * `V4L2_SUBDEV_ROUTE_FL_ACTIVE`:  路由处于激活状态的标志。
    * `V4L2_SUBDEV_CLIENT_CAP_*`: 客户端功能标志。

4. **ioctl 命令定义:** 定义了用于与 V4L2 子设备驱动进行通信的 ioctl 命令，例如：
    * `VIDIOC_SUBDEV_QUERYCAP`: 查询子设备功能。
    * `VIDIOC_SUBDEV_G_FMT`: 获取子设备格式。
    * `VIDIOC_SUBDEV_S_FMT`: 设置子设备格式。
    * `VIDIOC_SUBDEV_G_FRAME_INTERVAL`: 获取子设备帧间隔。
    * `VIDIOC_SUBDEV_S_FRAME_INTERVAL`: 设置子设备帧间隔。
    * `VIDIOC_SUBDEV_ENUM_MBUS_CODE`: 枚举子设备支持的媒体总线代码。
    * `VIDIOC_SUBDEV_ENUM_FRAME_SIZE`: 枚举子设备支持的帧大小。
    * `VIDIOC_SUBDEV_ENUM_FRAME_INTERVAL`: 枚举子设备支持的帧间隔。
    * `VIDIOC_SUBDEV_G_CROP`: 获取子设备裁剪区域。
    * `VIDIOC_SUBDEV_S_CROP`: 设置子设备裁剪区域。
    * `VIDIOC_SUBDEV_G_SELECTION`: 获取子设备选择区域。
    * `VIDIOC_SUBDEV_S_SELECTION`: 设置子设备选择区域。
    * `VIDIOC_SUBDEV_G_ROUTING`: 获取子设备路由信息。
    * `VIDIOC_SUBDEV_S_ROUTING`: 设置子设备路由信息。
    * `VIDIOC_SUBDEV_G_CLIENT_CAP`: 获取客户端功能。
    * `VIDIOC_SUBDEV_S_CLIENT_CAP`: 设置客户端功能。
    * 以及其他与标准、EDID、DV 时序相关的 ioctl 命令。

**与 Android 功能的关系及举例说明:**

这个头文件对于 Android 的 **多媒体框架**，特别是 **相机子系统 (Camera Subsystem)** 至关重要。Android 设备上的摄像头通常由多个独立的硬件模块组成，例如图像传感器、图像信号处理器 (ISP)、编解码器等。这些模块在 V4L2 框架中被抽象为 "子设备"。

以下是一些具体的例子：

* **配置摄像头传感器:** Android 的 Camera HAL (Hardware Abstraction Layer) 实现会使用这个头文件中定义的结构体和 ioctl 命令来配置摄像头传感器的各种参数，例如：
    * 使用 `VIDIOC_SUBDEV_S_FMT` 设置传感器的输出格式 (分辨率、像素格式，例如 RAW, YUV)。
    * 使用 `VIDIOC_SUBDEV_S_CROP` 设置传感器的感兴趣区域 (ROI)。
    * 使用 `VIDIOC_SUBDEV_S_FRAME_INTERVAL` 设置传感器的帧率。
* **控制 ISP:** ISP 是处理传感器原始数据的关键组件。Camera HAL 可以使用这个头文件中的定义来控制 ISP 的各种功能，例如：
    * 使用 `VIDIOC_SUBDEV_G_SELECTION` 和 `VIDIOC_SUBDEV_S_SELECTION` 控制自动对焦 (AF) 窗口的位置和大小。
    * 通过特定的 ioctl (可能不是这个头文件中直接定义的，但概念类似) 配置白平衡、曝光等参数。
* **管理视频管道:** Android 的多媒体框架可以使用 `VIDIOC_SUBDEV_G_ROUTING` 和 `VIDIOC_SUBDEV_S_ROUTING` 来查询和配置不同视频子设备之间的连接关系，构建完整的视频处理管道。例如，将摄像头传感器的输出连接到 ISP 的输入，再将 ISP 的输出连接到编码器的输入。

**libc 函数的实现:**

这个头文件本身 **不包含任何 libc 函数的实现**。它只是定义了一些数据结构和常量。用户空间程序（例如 Camera HAL）会使用标准的 libc 函数来与内核驱动进行交互，其中最关键的是 `ioctl()` 函数。

`ioctl()` 函数是一个通用的设备输入/输出控制系统调用。它的原型如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* `fd`: 是一个打开的文件描述符，通常是 V4L2 子设备对应的设备节点文件 (例如 `/dev/v4l-subdev0`).
* `request`: 是一个与设备相关的请求码，通常由宏定义 (例如 `VIDIOC_SUBDEV_S_FMT`) 提供。这个宏会编码操作类型、设备类型和命令编号。
* `...`: 可变参数，用于传递与特定 ioctl 命令相关的数据，通常是指向一个结构体的指针 (例如 `struct v4l2_subdev_format *`).

**`ioctl()` 函数的实现原理** 涉及到内核的设备驱动模型。当用户空间程序调用 `ioctl()` 时，系统调用会陷入内核。内核会根据文件描述符找到对应的设备驱动程序，并调用该驱动程序中与 `request` 对应的处理函数。驱动程序会解析传入的数据，执行相应的硬件操作，并将结果返回给用户空间程序。

**dynamic linker 的功能和 so 布局样本及链接处理过程:**

这个头文件本身与 dynamic linker **没有直接关系**。它是一个静态的头文件，用于编译期。然而，使用这个头文件的代码通常位于共享库 (`.so`) 中，例如 Camera HAL 的实现。

**so 布局样本:**

一个典型的 Camera HAL `.so` 文件的布局可能如下：

```
.so 文件名: vendor.camera.provider@2.6-service_vendor.so

Sections:
  .text         # 包含可执行代码
  .rodata       # 包含只读数据 (例如字符串常量)
  .data         # 包含已初始化的全局变量
  .bss          # 包含未初始化的全局变量
  .dynamic      # 包含动态链接信息
  .dynsym       # 包含动态符号表
  .dynstr       # 包含动态字符串表
  .plt          # Procedure Linkage Table (过程链接表)
  .got.plt      # Global Offset Table (全局偏移表)
  ... 其他段 ...
```

**链接的处理过程:**

1. **编译期:**  当编译 Camera HAL 的源代码时，编译器会包含 `v4l2-subdev.h` 头文件，并使用其中定义的结构体和常量。这些信息会被编码到生成的 `.o` 目标文件中。
2. **链接期:**  链接器会将多个 `.o` 文件链接成一个共享库 `.so` 文件。链接器会处理符号引用，例如，如果在代码中使用了 `VIDIOC_SUBDEV_S_FMT`，链接器会确保该符号被正确解析。由于 `VIDIOC_SUBDEV_S_FMT` 是一个宏定义，它在编译时就已经被替换为具体的数值，所以这里主要关联的是使用的结构体类型（例如 `v4l2_subdev_format`）。
3. **运行时:**  当 Android 系统加载 Camera HAL `.so` 文件时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
    * **加载共享库:** 将 `.so` 文件加载到内存中。
    * **符号解析:**  解析共享库中未定义的符号引用。对于 Camera HAL 来说，它需要与内核交互，但内核符号通常不通过标准的动态链接机制暴露。相反，Camera HAL 会使用 `ioctl()` 系统调用，这是一个 libc 提供的函数。libc 本身会被链接到 HAL 库中。
    * **重定位:**  调整代码和数据中的地址，以便它们在内存中的实际位置正确。
    * **执行初始化代码:**  运行共享库中的初始化函数。

**假设输入与输出 (涉及逻辑推理):**

假设一个 Camera HAL 实现想要设置摄像头传感器的输出格式为 1920x1080 的 YUYV 格式。

**假设输入:**

* 打开的 V4L2 子设备的文件描述符 `fd`.
* 一个 `struct v4l2_subdev_format` 结构体，其成员被设置为：
    * `which = V4L2_SUBDEV_FORMAT_ACTIVE;`
    * `pad = 0;` // 假设是第一个 pad
    * `format.width = 1920;`
    * `format.height = 1080;`
    * `format.code = MEDIA_BUS_FMT_YUYV8_2X8;` // YUYV 格式的媒体总线代码
    * `stream = 0;`

**预期输出:**

* 调用 `ioctl(fd, VIDIOC_SUBDEV_S_FMT, &format)` 成功返回 0。
* 内核驱动成功将摄像头的输出格式设置为 1920x1080 的 YUYV 格式。
* 后续的视频捕获操作将会按照这个新的格式进行。

**用户或编程常见的使用错误举例说明:**

1. **使用错误的 ioctl 命令码:**  例如，尝试使用 `VIDIOC_SUBDEV_G_FMT` 去设置格式，或者使用与子设备类型不匹配的 ioctl 命令。
2. **传递无效的结构体数据:** 例如，将 `v4l2_subdev_format.format.code` 设置为一个子设备不支持的媒体总线代码。
3. **忘记初始化结构体成员:**  `ioctl` 传递的结构体中未初始化的成员可能导致不可预测的行为或错误。
4. **在错误的设备节点上调用 ioctl:**  例如，尝试在一个音频子设备的文件描述符上调用视频相关的 ioctl 命令。
5. **权限不足:**  用户空间程序可能没有足够的权限访问 `/dev/v4l-subdevX` 设备节点。
6. **竞争条件:**  在多线程环境下，多个线程可能同时尝试修改同一个子设备的配置，导致冲突。

**Android framework 或 ndk 如何一步步的到达这里:**

1. **Android Framework (Java 层):**
   * 应用程序通过 `android.hardware.camera2` 等高级 API 请求访问摄像头。
   * CameraService (系统服务) 接收到请求。
   * CameraService 与 Camera HAL 交互。

2. **Camera HAL (Native 层, 通常是 C++):**
   * Camera HAL 的实现 (通常是 `.so` 库) 会加载，并通过 `open()` 系统调用打开对应的 V4L2 子设备节点 (例如 `/dev/v4l-subdev0`)。
   * Camera HAL 使用这个头文件中定义的结构体 (例如 `v4l2_subdev_format`) 填充参数，并调用 `ioctl()` 系统调用，指定相应的 `VIDIOC_SUBDEV_*` 命令码。

3. **Kernel Driver (C 语言):**
   * `ioctl()` 系统调用陷入内核。
   * 内核根据文件描述符找到对应的 V4L2 子设备驱动程序。
   * 驱动程序的 `ioctl` 处理函数被调用，该函数会解析 `request` 和传递的数据。
   * 驱动程序与底层的硬件进行交互，执行相应的操作 (例如配置传感器寄存器)。
   * 驱动程序将结果返回给用户空间。

4. **NDK:**
   * 使用 NDK 开发的应用程序可以直接使用标准的 Linux API (包括 `ioctl`) 与 V4L2 子设备进行交互。开发者需要在 NDK 代码中包含 `<linux/v4l2-subdev.h>` 头文件，并使用相应的结构体和 ioctl 命令。

**Frida hook 示例调试这些步骤:**

以下是一个使用 Frida hook `ioctl` 系统调用的示例，用于观察与 V4L2 子设备相关的操作：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.android.camera2"]) # 替换为目标应用的包名
    session = device.attach(pid)
    device.resume(pid)
except frida.TimedOutError:
    print("Error: Could not find or connect to USB device.")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print("Error: Could not find the specified process.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const pathname = "/dev/v4l-subdev";
        if (fd > 0) {
            try {
                const path = Kernel.readLink("/proc/self/fd/" + fd);
                if (path.startsWith(pathname)) {
                    this.ioctl_name = "";
                    if (request === 0xc0145605) this.ioctl_name = "VIDIOC_SUBDEV_S_FMT";
                    if (request === 0xc0145604) this.ioctl_name = "VIDIOC_SUBDEV_G_FMT";
                    if (request === 0xc0045600) this.ioctl_name = "VIDIOC_SUBDEV_QUERYCAP";
                    // ... 添加其他你感兴趣的 ioctl 命令

                    if (this.ioctl_name !== "") {
                        send({
                            type: "ioctl",
                            fd: fd,
                            request: request,
                            ioctl_name: this.ioctl_name,
                            path: path
                        });
                        // 你可以在这里进一步解析参数，例如读取结构体的内容
                    }
                }
            } catch (e) {
                // 忽略读取链接失败的情况
            }
        }
    },
    onLeave: function(retval) {
        if (this.ioctl_name !== "") {
            send({
                type: "ioctl_return",
                ioctl_name: this.ioctl_name,
                retval: retval.toInt32()
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

**代码解释:**

* 这个 Frida 脚本 hook 了 `libc.so` 中的 `ioctl` 函数。
* 在 `onEnter` 中，它获取了文件描述符 `fd` 和 ioctl 请求码 `request`。
* 它尝试读取文件描述符对应的路径，如果路径以 `/dev/v4l-subdev` 开头，则认为是与 V4L2 子设备相关的调用。
* 它根据 `request` 的值判断是哪个 V4L2 ioctl 命令，并将信息发送到 Frida 客户端。
* 你可以扩展这个脚本，根据不同的 `ioctl_name` 来解析 `args` 中的参数，例如读取 `v4l2_subdev_format` 结构体的内容。
* 在 `onLeave` 中，它记录了 `ioctl` 函数的返回值。

通过运行这个 Frida 脚本，你可以在 Android 设备上监控目标应用程序 (例如相机应用) 对 V4L2 子设备的 `ioctl` 调用，从而了解 Android framework 或 NDK 如何与内核中的 V4L2 子设备驱动进行交互。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/v4l2-subdev.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_V4L2_SUBDEV_H
#define __LINUX_V4L2_SUBDEV_H
#include <linux/const.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/v4l2-common.h>
#include <linux/v4l2-mediabus.h>
enum v4l2_subdev_format_whence {
  V4L2_SUBDEV_FORMAT_TRY = 0,
  V4L2_SUBDEV_FORMAT_ACTIVE = 1,
};
struct v4l2_subdev_format {
  __u32 which;
  __u32 pad;
  struct v4l2_mbus_framefmt format;
  __u32 stream;
  __u32 reserved[7];
};
struct v4l2_subdev_crop {
  __u32 which;
  __u32 pad;
  struct v4l2_rect rect;
  __u32 stream;
  __u32 reserved[7];
};
#define V4L2_SUBDEV_MBUS_CODE_CSC_COLORSPACE 0x00000001
#define V4L2_SUBDEV_MBUS_CODE_CSC_XFER_FUNC 0x00000002
#define V4L2_SUBDEV_MBUS_CODE_CSC_YCBCR_ENC 0x00000004
#define V4L2_SUBDEV_MBUS_CODE_CSC_HSV_ENC V4L2_SUBDEV_MBUS_CODE_CSC_YCBCR_ENC
#define V4L2_SUBDEV_MBUS_CODE_CSC_QUANTIZATION 0x00000008
struct v4l2_subdev_mbus_code_enum {
  __u32 pad;
  __u32 index;
  __u32 code;
  __u32 which;
  __u32 flags;
  __u32 stream;
  __u32 reserved[6];
};
struct v4l2_subdev_frame_size_enum {
  __u32 index;
  __u32 pad;
  __u32 code;
  __u32 min_width;
  __u32 max_width;
  __u32 min_height;
  __u32 max_height;
  __u32 which;
  __u32 stream;
  __u32 reserved[7];
};
struct v4l2_subdev_frame_interval {
  __u32 pad;
  struct v4l2_fract interval;
  __u32 stream;
  __u32 which;
  __u32 reserved[7];
};
struct v4l2_subdev_frame_interval_enum {
  __u32 index;
  __u32 pad;
  __u32 code;
  __u32 width;
  __u32 height;
  struct v4l2_fract interval;
  __u32 which;
  __u32 stream;
  __u32 reserved[7];
};
struct v4l2_subdev_selection {
  __u32 which;
  __u32 pad;
  __u32 target;
  __u32 flags;
  struct v4l2_rect r;
  __u32 stream;
  __u32 reserved[7];
};
struct v4l2_subdev_capability {
  __u32 version;
  __u32 capabilities;
  __u32 reserved[14];
};
#define V4L2_SUBDEV_CAP_RO_SUBDEV 0x00000001
#define V4L2_SUBDEV_CAP_STREAMS 0x00000002
#define V4L2_SUBDEV_ROUTE_FL_ACTIVE (1U << 0)
struct v4l2_subdev_route {
  __u32 sink_pad;
  __u32 sink_stream;
  __u32 source_pad;
  __u32 source_stream;
  __u32 flags;
  __u32 reserved[5];
};
struct v4l2_subdev_routing {
  __u32 which;
  __u32 len_routes;
  __u64 routes;
  __u32 num_routes;
  __u32 reserved[11];
};
#define V4L2_SUBDEV_CLIENT_CAP_STREAMS (1ULL << 0)
#define V4L2_SUBDEV_CLIENT_CAP_INTERVAL_USES_WHICH (1ULL << 1)
struct v4l2_subdev_client_capability {
  __u64 capabilities;
};
#define v4l2_subdev_edid v4l2_edid
#define VIDIOC_SUBDEV_QUERYCAP _IOR('V', 0, struct v4l2_subdev_capability)
#define VIDIOC_SUBDEV_G_FMT _IOWR('V', 4, struct v4l2_subdev_format)
#define VIDIOC_SUBDEV_S_FMT _IOWR('V', 5, struct v4l2_subdev_format)
#define VIDIOC_SUBDEV_G_FRAME_INTERVAL _IOWR('V', 21, struct v4l2_subdev_frame_interval)
#define VIDIOC_SUBDEV_S_FRAME_INTERVAL _IOWR('V', 22, struct v4l2_subdev_frame_interval)
#define VIDIOC_SUBDEV_ENUM_MBUS_CODE _IOWR('V', 2, struct v4l2_subdev_mbus_code_enum)
#define VIDIOC_SUBDEV_ENUM_FRAME_SIZE _IOWR('V', 74, struct v4l2_subdev_frame_size_enum)
#define VIDIOC_SUBDEV_ENUM_FRAME_INTERVAL _IOWR('V', 75, struct v4l2_subdev_frame_interval_enum)
#define VIDIOC_SUBDEV_G_CROP _IOWR('V', 59, struct v4l2_subdev_crop)
#define VIDIOC_SUBDEV_S_CROP _IOWR('V', 60, struct v4l2_subdev_crop)
#define VIDIOC_SUBDEV_G_SELECTION _IOWR('V', 61, struct v4l2_subdev_selection)
#define VIDIOC_SUBDEV_S_SELECTION _IOWR('V', 62, struct v4l2_subdev_selection)
#define VIDIOC_SUBDEV_G_ROUTING _IOWR('V', 38, struct v4l2_subdev_routing)
#define VIDIOC_SUBDEV_S_ROUTING _IOWR('V', 39, struct v4l2_subdev_routing)
#define VIDIOC_SUBDEV_G_CLIENT_CAP _IOR('V', 101, struct v4l2_subdev_client_capability)
#define VIDIOC_SUBDEV_S_CLIENT_CAP _IOWR('V', 102, struct v4l2_subdev_client_capability)
#define VIDIOC_SUBDEV_G_STD _IOR('V', 23, v4l2_std_id)
#define VIDIOC_SUBDEV_S_STD _IOW('V', 24, v4l2_std_id)
#define VIDIOC_SUBDEV_ENUMSTD _IOWR('V', 25, struct v4l2_standard)
#define VIDIOC_SUBDEV_G_EDID _IOWR('V', 40, struct v4l2_edid)
#define VIDIOC_SUBDEV_S_EDID _IOWR('V', 41, struct v4l2_edid)
#define VIDIOC_SUBDEV_QUERYSTD _IOR('V', 63, v4l2_std_id)
#define VIDIOC_SUBDEV_S_DV_TIMINGS _IOWR('V', 87, struct v4l2_dv_timings)
#define VIDIOC_SUBDEV_G_DV_TIMINGS _IOWR('V', 88, struct v4l2_dv_timings)
#define VIDIOC_SUBDEV_ENUM_DV_TIMINGS _IOWR('V', 98, struct v4l2_enum_dv_timings)
#define VIDIOC_SUBDEV_QUERY_DV_TIMINGS _IOR('V', 99, struct v4l2_dv_timings)
#define VIDIOC_SUBDEV_DV_TIMINGS_CAP _IOWR('V', 100, struct v4l2_dv_timings_cap)
#endif

"""

```