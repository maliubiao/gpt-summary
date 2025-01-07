Response:
Let's break down the thought process for answering this complex request about the `pisp_be_config.h` header file.

**1. Understanding the Core Request:**

The central goal is to analyze the provided C header file (`pisp_be_config.h`), explain its purpose within the Android ecosystem (specifically bionic), and connect it to various aspects of Android development. The request is quite detailed, asking for:

* **Functionality:** What does this header do?
* **Android Relevance:** How does it relate to Android features?
* **libc Functions:** Explain their implementation (this part was a bit of a misdirection in the original request, as it's a header file, not a source file with function implementations).
* **Dynamic Linker:**  Explain the role of the dynamic linker (again, slightly misdirected, but the concept of shared libraries and their configuration is relevant).
* **Logic Reasoning:**  Illustrate with input/output examples.
* **Common Errors:**  Point out potential mistakes.
* **Android Framework/NDK Path:** Trace how this gets used.
* **Frida Hook Example:** Demonstrate debugging.

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPI_PISP_BE_CONFIG_H_`:**  Standard header guard, indicating it's meant to be included in C/C++ code.
* **`#include <linux/types.h>`:**  Uses standard Linux types (`__u32`, `__u8`, etc.), suggesting a kernel-level or hardware abstraction layer.
* **`#include "pisp_common.h"`:**  Depends on another header file, likely defining common structures or enums related to PISP.
* **`#define` constants:**  Defines various constants related to alignment, tile dimensions, and the number of outputs. These suggest low-level hardware or driver configurations.
* **`enum` declarations:**  Defines enumerations like `pisp_be_bayer_enable` and `pisp_be_rgb_enable`. The names strongly hint at image processing pipeline stages (Bayer, RGB, etc.). The bitmask values (0x000001, 0x000002, etc.) are typical for enabling/disabling features.
* **`struct` declarations:**  Defines numerous structures like `pisp_be_global_config`, `pisp_be_input_buffer_config`, etc. These structures contain configuration parameters for different image processing blocks. The `__attribute__((packed))` directive is crucial; it ensures no padding is added by the compiler, which is common when interacting with hardware registers or memory-mapped I/O.

**3. Identifying the Core Purpose:**

Based on the names of the enums and structs, the most likely function of this header file is to define the configuration interface for a **Raspberry Pi Image Signal Processor (PISP) Back-End (BE)**. It allows software to control the various stages of image processing within this hardware component.

**4. Connecting to Android:**

The header resides in `bionic/libc/kernel/uapi/linux/media/raspberrypi/`. This location is significant:

* **`bionic`:**  Android's core C library, used by both the Android framework and native code.
* **`kernel/uapi`:**  Indicates this is a userspace API for interacting with kernel-level drivers.
* **`linux/media`:**  Specifically relates to Linux media device drivers (V4L2 is likely involved).
* **`raspberrypi`:** Confirms the target platform.

Therefore, this header is used by Android (or more precisely, code running on Android on a Raspberry Pi) to configure the Raspberry Pi's camera processing hardware.

**5. Addressing Specific Request Points:**

* **Functionality:**  Summarize the key purpose (configuring the PISP BE). List the main categories of configurations (input, Bayer processing, RGB processing, output, etc.).
* **Android Relevance:** Explain that Android's camera framework or lower-level HAL (Hardware Abstraction Layer) would use these structures. Give concrete examples like adjusting brightness, contrast, or enabling HDR.
* **libc Functions:** Correct the misunderstanding. Explain that this is a *header file*, defining data structures, not implementing functions. Mention that the *kernel driver* (not libc) implements the logic.
* **Dynamic Linker:** Explain that while this header itself doesn't directly involve the dynamic linker, the *code* that uses these structures would be part of shared libraries (.so files). Provide a basic .so layout and explain the linking process.
* **Logic Reasoning:**  Create a simple scenario, like enabling Bayer processing and setting input buffer addresses. Illustrate how the bitmask values are used.
* **Common Errors:**  Focus on incorrect structure packing, incorrect bitmask usage, and passing invalid addresses.
* **Android Framework/NDK Path:**  Outline the chain: Camera App -> Camera Service -> HAL (NDK) -> Kernel Driver.
* **Frida Hook:** Provide a practical example of hooking a function that likely interacts with these structures (e.g., an `ioctl` call).

**6. Refining and Structuring the Answer:**

Organize the answer clearly, using headings and bullet points for readability. Explain technical terms. Use precise language. Emphasize the distinction between header files, source code, and kernel drivers.

**Self-Correction/Refinement During the Process:**

* **Initial thought about libc functions:**  Realized the request was about a header, not implementation. Corrected the focus to the data structures defined.
* **Dynamic linker relevance:**  Acknowledged the indirect connection through shared libraries, even though the header itself doesn't contain dynamic linking code.
* **Complexity of tracing the exact path:**  Recognized that pinpointing the *exact* function calls in the Android framework is difficult without access to the source code. Focused on providing a high-level overview.
* **Frida Hook example:** Chose a generic but relevant target (`ioctl`) since the specific function interacting with this header is unknown without further context.

By following this structured thought process, starting with understanding the core request and progressively analyzing the provided information, a comprehensive and accurate answer can be constructed. The key is to connect the technical details of the header file to the broader context of Android development.
好的，我们来详细分析一下 `bionic/libc/kernel/uapi/linux/media/raspberrypi/pisp_be_config.handroid` 这个头文件。

**功能列举:**

这个头文件定义了用于配置 Raspberry Pi Image Signal Processor (PISP) 后端 (Back-End, BE) 的各种数据结构和常量。PISP 是 Raspberry Pi 上用于处理摄像头图像的硬件模块。这些配置用于控制图像处理流水线的各个阶段，包括：

* **输入配置 (`pisp_be_input_buffer_config`)**: 定义输入图像缓冲区的地址。
* **Bayer 处理配置 (`pisp_be_bayer_enable`, 以及 `pisp_be_*_config` 中与 Bayer 相关的结构体)**: 配置 Bayer 图像处理的各个步骤，例如去马赛克 (demosaic)、坏点校正 (DPC)、镜头阴影校正 (LSC) 等。
* **RGB 处理配置 (`pisp_be_rgb_enable`, 以及 `pisp_be_*_config` 中与 RGB 相关的结构体)**: 配置 RGB 图像处理的各个步骤，例如色彩校正矩阵 (CCM)、饱和度控制、锐化等。
* **输出配置 (`pisp_be_output_buffer_config`, `pisp_be_output_format_config`)**: 定义输出图像缓冲区的地址和格式。
* **降噪 (`pisp_be_tdn_config`, `pisp_be_sdn_config`, `pisp_be_cdn_config`)**: 配置时域降噪 (TDN)、空域降噪 (SDN) 和色度降噪 (CDN)。
* **拼接 (`pisp_be_stitch_config`)**: 配置图像拼接功能。
* **直方图均衡化 (`pisp_be_tonemap_config`)**: 配置色调映射。
* **裁剪 (`pisp_be_crop_config`)**: 配置图像裁剪区域。
* **缩放 (`pisp_be_downscale_config`, `pisp_be_resample_config`)**: 配置图像的降采样和重采样。
* **HOG (方向梯度直方图) 特征提取 (`pisp_be_hog_config`, `pisp_be_hog_buffer_config`)**: 配置 HOG 特征的计算和存储。
* **AXI 总线配置 (`pisp_be_axi_config`)**: 配置 PISP 后端与 AXI 总线的接口参数。
* **分块处理 (`pisp_be_tiles_config`, `pisp_tile`)**:  定义了将图像分成小块进行处理的配置，可以提高并行处理效率。
* **全局配置 (`pisp_be_global_config`)**: 包含 Bayer 和 RGB 处理的总开关以及 Bayer 格式顺序。
* **脏标记 (`dirty_flags_bayer`, `dirty_flags_rgb`, `dirty_flags_extra`)**:  指示哪些配置需要更新。

**与 Android 功能的关系及举例说明:**

这个头文件直接关系到 Android 设备上使用 Raspberry Pi 摄像头的功能。Android 的 Camera HAL (Hardware Abstraction Layer) 会使用这些结构体来配置底层的 PISP 硬件。

**举例说明:**

1. **调整摄像头亮度/对比度:** Android 的 Camera2 API 允许应用程序调整图像的亮度、对比度等参数。这些操作最终可能通过修改 `pisp_be_tonemap_config` 结构体中的参数 (例如 `strength`, LUT 表) 来实现，从而影响 PISP 的色调映射处理。
2. **启用 HDR (高动态范围) 模式:** HDR 模式通常涉及多帧图像的融合。PISP 的配置可能需要调整 `pisp_be_stitch_config` 来启用图像拼接功能，或者调整曝光参数并使用不同的处理流程。
3. **设置图像格式:** 当应用程序请求特定的图像格式 (例如 YUV420, JPEG) 时，Camera HAL 会配置 `pisp_be_output_format_config` 中的 `image` 字段，以告知 PISP 后端输出所需格式的数据。
4. **夜景模式:** 夜景模式通常需要更长的曝光时间和更高的 ISO 感光度。这可能涉及到调整 PISP 的增益设置，并可能影响降噪模块的配置 (`pisp_be_tdn_config`, `pisp_be_sdn_config`) 来减少噪点。
5. **人脸检测:**  一些人脸检测算法可能会利用 HOG 特征。Android 的人脸检测 API 可能驱动 Camera HAL 配置 `pisp_be_hog_config` 和 `pisp_be_hog_buffer_config` 来提取图像的 HOG 特征，供算法使用。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个头文件本身并没有定义或实现任何 libc 函数。** 它是一个定义数据结构的头文件，用于与硬件或内核驱动程序交互。这些数据结构会被传递给内核驱动程序，驱动程序负责将这些配置写入 PISP 硬件的寄存器。

实际的图像处理逻辑和配置应用是在 Raspberry Pi 的内核驱动程序中实现的，而不是在 `bionic` 的 libc 库中。`bionic` 提供的只是用户空间访问内核功能的接口，例如通过 `ioctl` 系统调用来传递这些配置信息。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及 dynamic linker。但是，使用这个头文件的代码通常会存在于 Android 的共享库 (`.so` 文件) 中，例如 Camera HAL 的实现。

**so 布局样本 (简化):**

```
.so 文件名: libRPiCamera.so

.text  (代码段):
    - 实现 Camera HAL 接口的函数
    - 调用内核驱动程序 (例如通过 ioctl) 的代码

.rodata (只读数据段):
    - 可能包含一些常量数据

.data   (可读写数据段):
    - 全局变量

.bss    (未初始化数据段):
    - 未初始化的全局变量

.dynamic (动态链接信息):
    - 依赖的其他 so 库的信息 (例如 libc.so, libbinder.so)
    - 导出和导入的符号表

.symtab  (符号表):
    - 包含库中定义的函数和变量的符号信息

.strtab  (字符串表):
    - 包含符号表中使用的字符串
```

**链接的处理过程:**

1. **编译时链接:** 当编译 `libRPiCamera.so` 时，编译器会处理头文件 `pisp_be_config.h`，了解 PISP 配置结构体的定义。如果代码中使用了例如 `ioctl` 这样的 libc 函数，则会生成对这些函数的未解析引用。
2. **动态链接时加载:** 当 Android 系统加载使用 `libRPiCamera.so` 的进程时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所有依赖的共享库。
3. **符号解析:** dynamic linker 会解析 `libRPiCamera.so` 中对 libc 函数 (如 `ioctl`) 的未解析引用。它会在 `libc.so` 的符号表中查找对应的符号，并将引用地址绑定到 `libc.so` 中函数的实际地址。
4. **重定位:** dynamic linker 还会根据库加载的基地址调整库中的一些地址引用，确保代码能够正确执行。

**假设输入与输出 (逻辑推理):**

假设有一个 Camera HAL 函数需要配置 PISP 的曝光时间。

**假设输入:**

*  一个表示目标曝光时间的数值 (例如，以微秒为单位)。

**逻辑推理过程:**

1. Camera HAL 函数会将目标曝光时间转换为 PISP 硬件能够理解的寄存器值。这可能涉及到查表或者应用特定的公式。
2. HAL 函数可能会填充 `pisp_be_config` 结构体中的相关字段，例如与曝光控制相关的结构体 (具体结构体可能未在提供的代码片段中)。
3. HAL 函数会使用 `ioctl` 系统调用，将填充好的 `pisp_be_config` 结构体传递给 PISP 的内核驱动程序。

**假设输出:**

*  `ioctl` 系统调用成功返回 (表示配置已发送到内核驱动程序)。
*  PISP 硬件根据接收到的配置调整其曝光时间。

**用户或者编程常见的使用错误:**

1. **结构体内存布局错误:** 由于使用了 `__attribute__((packed))`, 必须严格按照结构体定义填充数据，任何字节对齐的假设都可能导致错误。
2. **位域操作错误:** 在设置 `enum` 类型的标志位时，使用错误的掩码或逻辑运算可能导致意外的功能启用或禁用。例如，错误地使用 `|` 代替 `&` 来清除标志位。
3. **传递无效地址:**  在配置缓冲区地址时，传递无效的物理地址或用户空间地址会导致内核访问错误。
4. **配置顺序错误:**  PISP 的配置可能存在依赖关系，不正确的配置顺序可能导致硬件工作异常。
5. **权限问题:**  用户空间程序可能没有足够的权限直接访问或配置 PISP 硬件，需要通过内核驱动程序进行操作。
6. **并发访问冲突:** 如果多个进程或线程同时尝试配置 PISP，可能会导致数据竞争和配置错误。
7. **未初始化结构体:**  在使用 `pisp_be_config` 结构体之前，忘记初始化某些字段可能导致 PISP 使用默认的或随机的配置值。

**Android Framework or NDK 是如何一步步的到达这里:**

1. **Camera Application (Java/Kotlin):** 用户通过 Android 应用程序 (例如系统相机 App) 发起拍照或录像请求，并设置各种参数 (例如分辨率、曝光、白平衡等)。
2. **Camera Service (Java):**  应用程序的请求会被传递到 Camera Service，它是 Android Framework 的一部分，负责管理系统上的摄像头设备。
3. **Camera HAL (NDK/C++):** Camera Service 通过 Camera HAL 接口与底层的硬件驱动程序进行交互。Camera HAL 是一个由硬件供应商提供的共享库 (`.so` 文件)，使用 NDK (Native Development Kit) 开发。
4. **HAL Implementation (`libRPiCamera.so` 示例):**  在 Raspberry Pi 上，Camera HAL 的实现 (例如 `libRPiCamera.so`) 会包含与 PISP 硬件交互的代码。
5. **ioctl 系统调用:** HAL 实现会填充 `pisp_be_config` 结构体，并使用 `ioctl` 系统调用将配置信息传递给 PISP 的内核驱动程序。
6. **Kernel Driver (C):**  PISP 的内核驱动程序接收到 `ioctl` 命令后，会将 `pisp_be_config` 中的数据写入 PISP 硬件的寄存器，从而配置图像处理流水线。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook `ioctl` 系统调用，并检查传递给内核驱动程序的参数，以了解 Android Framework 或 NDK 如何配置 PISP。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = device.spawn(["com.android.camera2"]) # 替换为你的相机应用包名
    process = device.attach(pid)
except frida.ServerNotStartedError:
    print("Frida server is not running. Please start it on the device.")
    sys.exit()

script_source = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();
        var argp = args[2];

        // 可以根据 fd 判断是否是与摄像头相关的设备文件
        // 常见的摄像头设备文件路径可能包含 "video" 或 "v4l"

        // 可以根据 request 的值判断是哪个控制命令
        // PISP 相关的 ioctl 命令通常会有特定的定义

        // 这里简单地打印 ioctl 的参数
        send({
            "ioctl": "called",
            "fd": fd,
            "request": request,
            "argp": argp
        });

        // 如果已知 PISP 配置结构体的地址，可以读取其内容
        // 例如:
        // if (request == PISP_CONFIG_IOCTL_CODE) { // 假设存在这样的定义
        //     var pisp_config = ptr(argp);
        //     // 读取 pisp_config 中的字段并打印
        // }
    },
    onLeave: function(retval) {
        send({"ioctl": "returned", "retval": retval.toInt32()});
    }
});
"""

script = process.create_script(script_source)
script.on('message', on_message)
script.load()

device.resume(pid)
sys.stdin.read()
```

**使用说明:**

1. 确保你的 Android 设备上安装了 Frida server，并且你的电脑上安装了 Python 和 Frida 库。
2. 将 `com.android.camera2` 替换为你想要监控的相机应用程序的包名。
3. 运行这个 Python 脚本。
4. 在你的 Android 设备上打开相机应用程序并执行一些操作 (例如拍照、录像、切换模式)。
5. Frida 会 hook `ioctl` 系统调用，并打印出调用的参数。你需要根据 `fd` (文件描述符) 和 `request` (ioctl 命令) 的值来判断是否是与 PISP 相关的操作。
6. 如果你已知 PISP 相关的 `ioctl` 命令码和配置结构体的地址，可以在 Frida 脚本中读取结构体的内容进行更详细的分析。

请注意，以上 Frida 脚本只是一个基本的示例。实际调试可能需要更深入的了解 PISP 驱动程序的实现和相关的 `ioctl` 命令码。你可能需要参考 Raspberry Pi 的内核源代码或者相关的文档来获取更详细的信息。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/media/raspberrypi/pisp_be_config.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_PISP_BE_CONFIG_H_
#define _UAPI_PISP_BE_CONFIG_H_
#include <linux/types.h>
#include "pisp_common.h"
#define PISP_BACK_END_INPUT_ALIGN 4u
#define PISP_BACK_END_COMPRESSED_ALIGN 8u
#define PISP_BACK_END_OUTPUT_MIN_ALIGN 16u
#define PISP_BACK_END_OUTPUT_MAX_ALIGN 64u
#define PISP_BACK_END_MIN_TILE_WIDTH 16u
#define PISP_BACK_END_MIN_TILE_HEIGHT 16u
#define PISP_BACK_END_NUM_OUTPUTS 2
#define PISP_BACK_END_HOG_OUTPUT 1
#define PISP_BACK_END_NUM_TILES 64
enum pisp_be_bayer_enable {
  PISP_BE_BAYER_ENABLE_INPUT = 0x000001,
  PISP_BE_BAYER_ENABLE_DECOMPRESS = 0x000002,
  PISP_BE_BAYER_ENABLE_DPC = 0x000004,
  PISP_BE_BAYER_ENABLE_GEQ = 0x000008,
  PISP_BE_BAYER_ENABLE_TDN_INPUT = 0x000010,
  PISP_BE_BAYER_ENABLE_TDN_DECOMPRESS = 0x000020,
  PISP_BE_BAYER_ENABLE_TDN = 0x000040,
  PISP_BE_BAYER_ENABLE_TDN_COMPRESS = 0x000080,
  PISP_BE_BAYER_ENABLE_TDN_OUTPUT = 0x000100,
  PISP_BE_BAYER_ENABLE_SDN = 0x000200,
  PISP_BE_BAYER_ENABLE_BLC = 0x000400,
  PISP_BE_BAYER_ENABLE_STITCH_INPUT = 0x000800,
  PISP_BE_BAYER_ENABLE_STITCH_DECOMPRESS = 0x001000,
  PISP_BE_BAYER_ENABLE_STITCH = 0x002000,
  PISP_BE_BAYER_ENABLE_STITCH_COMPRESS = 0x004000,
  PISP_BE_BAYER_ENABLE_STITCH_OUTPUT = 0x008000,
  PISP_BE_BAYER_ENABLE_WBG = 0x010000,
  PISP_BE_BAYER_ENABLE_CDN = 0x020000,
  PISP_BE_BAYER_ENABLE_LSC = 0x040000,
  PISP_BE_BAYER_ENABLE_TONEMAP = 0x080000,
  PISP_BE_BAYER_ENABLE_CAC = 0x100000,
  PISP_BE_BAYER_ENABLE_DEBIN = 0x200000,
  PISP_BE_BAYER_ENABLE_DEMOSAIC = 0x400000,
};
enum pisp_be_rgb_enable {
  PISP_BE_RGB_ENABLE_INPUT = 0x000001,
  PISP_BE_RGB_ENABLE_CCM = 0x000002,
  PISP_BE_RGB_ENABLE_SAT_CONTROL = 0x000004,
  PISP_BE_RGB_ENABLE_YCBCR = 0x000008,
  PISP_BE_RGB_ENABLE_FALSE_COLOUR = 0x000010,
  PISP_BE_RGB_ENABLE_SHARPEN = 0x000020,
  PISP_BE_RGB_ENABLE_YCBCR_INVERSE = 0x000080,
  PISP_BE_RGB_ENABLE_GAMMA = 0x000100,
  PISP_BE_RGB_ENABLE_CSC0 = 0x000200,
  PISP_BE_RGB_ENABLE_CSC1 = 0x000400,
  PISP_BE_RGB_ENABLE_DOWNSCALE0 = 0x001000,
  PISP_BE_RGB_ENABLE_DOWNSCALE1 = 0x002000,
  PISP_BE_RGB_ENABLE_RESAMPLE0 = 0x008000,
  PISP_BE_RGB_ENABLE_RESAMPLE1 = 0x010000,
  PISP_BE_RGB_ENABLE_OUTPUT0 = 0x040000,
  PISP_BE_RGB_ENABLE_OUTPUT1 = 0x080000,
  PISP_BE_RGB_ENABLE_HOG = 0x200000
};
#define PISP_BE_RGB_ENABLE_CSC(i) (PISP_BE_RGB_ENABLE_CSC0 << (i))
#define PISP_BE_RGB_ENABLE_DOWNSCALE(i) (PISP_BE_RGB_ENABLE_DOWNSCALE0 << (i))
#define PISP_BE_RGB_ENABLE_RESAMPLE(i) (PISP_BE_RGB_ENABLE_RESAMPLE0 << (i))
#define PISP_BE_RGB_ENABLE_OUTPUT(i) (PISP_BE_RGB_ENABLE_OUTPUT0 << (i))
enum pisp_be_dirty {
  PISP_BE_DIRTY_GLOBAL = 0x0001,
  PISP_BE_DIRTY_SH_FC_COMBINE = 0x0002,
  PISP_BE_DIRTY_CROP = 0x0004
};
struct pisp_be_global_config {
  __u32 bayer_enables;
  __u32 rgb_enables;
  __u8 bayer_order;
  __u8 pad[3];
} __attribute__((packed));
struct pisp_be_input_buffer_config {
  __u32 addr[3][2];
} __attribute__((packed));
struct pisp_be_dpc_config {
  __u8 coeff_level;
  __u8 coeff_range;
  __u8 pad;
#define PISP_BE_DPC_FLAG_FOLDBACK 1
  __u8 flags;
} __attribute__((packed));
struct pisp_be_geq_config {
  __u16 offset;
#define PISP_BE_GEQ_SHARPER (1U << 15)
#define PISP_BE_GEQ_SLOPE ((1 << 10) - 1)
  __u16 slope_sharper;
  __u16 min;
  __u16 max;
} __attribute__((packed));
struct pisp_be_tdn_input_buffer_config {
  __u32 addr[2];
} __attribute__((packed));
struct pisp_be_tdn_config {
  __u16 black_level;
  __u16 ratio;
  __u16 noise_constant;
  __u16 noise_slope;
  __u16 threshold;
  __u8 reset;
  __u8 pad;
} __attribute__((packed));
struct pisp_be_tdn_output_buffer_config {
  __u32 addr[2];
} __attribute__((packed));
struct pisp_be_sdn_config {
  __u16 black_level;
  __u8 leakage;
  __u8 pad;
  __u16 noise_constant;
  __u16 noise_slope;
  __u16 noise_constant2;
  __u16 noise_slope2;
} __attribute__((packed));
struct pisp_be_stitch_input_buffer_config {
  __u32 addr[2];
} __attribute__((packed));
#define PISP_BE_STITCH_STREAMING_LONG 0x8000
#define PISP_BE_STITCH_EXPOSURE_RATIO_MASK 0x7fff
struct pisp_be_stitch_config {
  __u16 threshold_lo;
  __u8 threshold_diff_power;
  __u8 pad;
  __u16 exposure_ratio;
  __u8 motion_threshold_256;
  __u8 motion_threshold_recip;
} __attribute__((packed));
struct pisp_be_stitch_output_buffer_config {
  __u32 addr[2];
} __attribute__((packed));
struct pisp_be_cdn_config {
  __u16 thresh;
  __u8 iir_strength;
  __u8 g_adjust;
} __attribute__((packed));
#define PISP_BE_LSC_LOG_GRID_SIZE 5
#define PISP_BE_LSC_GRID_SIZE (1 << PISP_BE_LSC_LOG_GRID_SIZE)
#define PISP_BE_LSC_STEP_PRECISION 18
struct pisp_be_lsc_config {
  __u16 grid_step_x;
  __u16 grid_step_y;
#define PISP_BE_LSC_LUT_SIZE (PISP_BE_LSC_GRID_SIZE + 1)
  __u32 lut_packed[PISP_BE_LSC_LUT_SIZE][PISP_BE_LSC_LUT_SIZE];
} __attribute__((packed));
struct pisp_be_lsc_extra {
  __u16 offset_x;
  __u16 offset_y;
} __attribute__((packed));
#define PISP_BE_CAC_LOG_GRID_SIZE 3
#define PISP_BE_CAC_GRID_SIZE (1 << PISP_BE_CAC_LOG_GRID_SIZE)
#define PISP_BE_CAC_STEP_PRECISION 20
struct pisp_be_cac_config {
  __u16 grid_step_x;
  __u16 grid_step_y;
#define PISP_BE_CAC_LUT_SIZE (PISP_BE_CAC_GRID_SIZE + 1)
  __s8 lut[PISP_BE_CAC_LUT_SIZE][PISP_BE_CAC_LUT_SIZE][2][2];
} __attribute__((packed));
struct pisp_be_cac_extra {
  __u16 offset_x;
  __u16 offset_y;
} __attribute__((packed));
#define PISP_BE_DEBIN_NUM_COEFFS 4
struct pisp_be_debin_config {
  __s8 coeffs[PISP_BE_DEBIN_NUM_COEFFS];
  __s8 h_enable;
  __s8 v_enable;
  __s8 pad[2];
} __attribute__((packed));
#define PISP_BE_TONEMAP_LUT_SIZE 64
struct pisp_be_tonemap_config {
  __u16 detail_constant;
  __u16 detail_slope;
  __u16 iir_strength;
  __u16 strength;
  __u32 lut[PISP_BE_TONEMAP_LUT_SIZE];
} __attribute__((packed));
struct pisp_be_demosaic_config {
  __u8 sharper;
  __u8 fc_mode;
  __u8 pad[2];
} __attribute__((packed));
struct pisp_be_ccm_config {
  __s16 coeffs[9];
  __u8 pad[2];
  __s32 offsets[3];
} __attribute__((packed));
struct pisp_be_sat_control_config {
  __u8 shift_r;
  __u8 shift_g;
  __u8 shift_b;
  __u8 pad;
} __attribute__((packed));
struct pisp_be_false_colour_config {
  __u8 distance;
  __u8 pad[3];
} __attribute__((packed));
#define PISP_BE_SHARPEN_SIZE 5
#define PISP_BE_SHARPEN_FUNC_NUM_POINTS 9
struct pisp_be_sharpen_config {
  __s8 kernel0[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
  __s8 pad0[3];
  __s8 kernel1[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
  __s8 pad1[3];
  __s8 kernel2[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
  __s8 pad2[3];
  __s8 kernel3[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
  __s8 pad3[3];
  __s8 kernel4[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
  __s8 pad4[3];
  __u16 threshold_offset0;
  __u16 threshold_slope0;
  __u16 scale0;
  __u16 pad5;
  __u16 threshold_offset1;
  __u16 threshold_slope1;
  __u16 scale1;
  __u16 pad6;
  __u16 threshold_offset2;
  __u16 threshold_slope2;
  __u16 scale2;
  __u16 pad7;
  __u16 threshold_offset3;
  __u16 threshold_slope3;
  __u16 scale3;
  __u16 pad8;
  __u16 threshold_offset4;
  __u16 threshold_slope4;
  __u16 scale4;
  __u16 pad9;
  __u16 positive_strength;
  __u16 positive_pre_limit;
  __u16 positive_func[PISP_BE_SHARPEN_FUNC_NUM_POINTS];
  __u16 positive_limit;
  __u16 negative_strength;
  __u16 negative_pre_limit;
  __u16 negative_func[PISP_BE_SHARPEN_FUNC_NUM_POINTS];
  __u16 negative_limit;
  __u8 enables;
  __u8 white;
  __u8 black;
  __u8 grey;
} __attribute__((packed));
struct pisp_be_sh_fc_combine_config {
  __u8 y_factor;
  __u8 c1_factor;
  __u8 c2_factor;
  __u8 pad;
} __attribute__((packed));
#define PISP_BE_GAMMA_LUT_SIZE 64
struct pisp_be_gamma_config {
  __u32 lut[PISP_BE_GAMMA_LUT_SIZE];
} __attribute__((packed));
struct pisp_be_crop_config {
  __u16 offset_x, offset_y;
  __u16 width, height;
} __attribute__((packed));
#define PISP_BE_RESAMPLE_FILTER_SIZE 96
struct pisp_be_resample_config {
  __u16 scale_factor_h, scale_factor_v;
  __s16 coef[PISP_BE_RESAMPLE_FILTER_SIZE];
} __attribute__((packed));
struct pisp_be_resample_extra {
  __u16 scaled_width;
  __u16 scaled_height;
  __s16 initial_phase_h[3];
  __s16 initial_phase_v[3];
} __attribute__((packed));
struct pisp_be_downscale_config {
  __u16 scale_factor_h;
  __u16 scale_factor_v;
  __u16 scale_recip_h;
  __u16 scale_recip_v;
} __attribute__((packed));
struct pisp_be_downscale_extra {
  __u16 scaled_width;
  __u16 scaled_height;
} __attribute__((packed));
struct pisp_be_hog_config {
  __u8 compute_signed;
  __u8 channel_mix[3];
  __u32 stride;
} __attribute__((packed));
struct pisp_be_axi_config {
  __u8 r_qos;
  __u8 r_cache_prot;
  __u8 w_qos;
  __u8 w_cache_prot;
} __attribute__((packed));
enum pisp_be_transform {
  PISP_BE_TRANSFORM_NONE = 0x0,
  PISP_BE_TRANSFORM_HFLIP = 0x1,
  PISP_BE_TRANSFORM_VFLIP = 0x2,
  PISP_BE_TRANSFORM_ROT180 = (PISP_BE_TRANSFORM_HFLIP | PISP_BE_TRANSFORM_VFLIP)
};
struct pisp_be_output_format_config {
  struct pisp_image_format_config image;
  __u8 transform;
  __u8 pad[3];
  __u16 lo;
  __u16 hi;
  __u16 lo2;
  __u16 hi2;
} __attribute__((packed));
struct pisp_be_output_buffer_config {
  __u32 addr[3][2];
} __attribute__((packed));
struct pisp_be_hog_buffer_config {
  __u32 addr[2];
} __attribute__((packed));
struct pisp_be_config {
  struct pisp_be_input_buffer_config input_buffer;
  struct pisp_be_tdn_input_buffer_config tdn_input_buffer;
  struct pisp_be_stitch_input_buffer_config stitch_input_buffer;
  struct pisp_be_tdn_output_buffer_config tdn_output_buffer;
  struct pisp_be_stitch_output_buffer_config stitch_output_buffer;
  struct pisp_be_output_buffer_config output_buffer[PISP_BACK_END_NUM_OUTPUTS];
  struct pisp_be_hog_buffer_config hog_buffer;
  struct pisp_be_global_config global;
  struct pisp_image_format_config input_format;
  struct pisp_decompress_config decompress;
  struct pisp_be_dpc_config dpc;
  struct pisp_be_geq_config geq;
  struct pisp_image_format_config tdn_input_format;
  struct pisp_decompress_config tdn_decompress;
  struct pisp_be_tdn_config tdn;
  struct pisp_compress_config tdn_compress;
  struct pisp_image_format_config tdn_output_format;
  struct pisp_be_sdn_config sdn;
  struct pisp_bla_config blc;
  struct pisp_compress_config stitch_compress;
  struct pisp_image_format_config stitch_output_format;
  struct pisp_image_format_config stitch_input_format;
  struct pisp_decompress_config stitch_decompress;
  struct pisp_be_stitch_config stitch;
  struct pisp_be_lsc_config lsc;
  struct pisp_wbg_config wbg;
  struct pisp_be_cdn_config cdn;
  struct pisp_be_cac_config cac;
  struct pisp_be_debin_config debin;
  struct pisp_be_tonemap_config tonemap;
  struct pisp_be_demosaic_config demosaic;
  struct pisp_be_ccm_config ccm;
  struct pisp_be_sat_control_config sat_control;
  struct pisp_be_ccm_config ycbcr;
  struct pisp_be_sharpen_config sharpen;
  struct pisp_be_false_colour_config false_colour;
  struct pisp_be_sh_fc_combine_config sh_fc_combine;
  struct pisp_be_ccm_config ycbcr_inverse;
  struct pisp_be_gamma_config gamma;
  struct pisp_be_ccm_config csc[PISP_BACK_END_NUM_OUTPUTS];
  struct pisp_be_downscale_config downscale[PISP_BACK_END_NUM_OUTPUTS];
  struct pisp_be_resample_config resample[PISP_BACK_END_NUM_OUTPUTS];
  struct pisp_be_output_format_config output_format[PISP_BACK_END_NUM_OUTPUTS];
  struct pisp_be_hog_config hog;
  struct pisp_be_axi_config axi;
  struct pisp_be_lsc_extra lsc_extra;
  struct pisp_be_cac_extra cac_extra;
  struct pisp_be_downscale_extra downscale_extra[PISP_BACK_END_NUM_OUTPUTS];
  struct pisp_be_resample_extra resample_extra[PISP_BACK_END_NUM_OUTPUTS];
  struct pisp_be_crop_config crop;
  struct pisp_image_format_config hog_format;
  __u32 dirty_flags_bayer;
  __u32 dirty_flags_rgb;
  __u32 dirty_flags_extra;
} __attribute__((packed));
enum pisp_tile_edge {
  PISP_LEFT_EDGE = (1 << 0),
  PISP_RIGHT_EDGE = (1 << 1),
  PISP_TOP_EDGE = (1 << 2),
  PISP_BOTTOM_EDGE = (1 << 3)
};
struct pisp_tile {
  __u8 edge;
  __u8 pad0[3];
  __u32 input_addr_offset;
  __u32 input_addr_offset2;
  __u16 input_offset_x;
  __u16 input_offset_y;
  __u16 input_width;
  __u16 input_height;
  __u32 tdn_input_addr_offset;
  __u32 tdn_output_addr_offset;
  __u32 stitch_input_addr_offset;
  __u32 stitch_output_addr_offset;
  __u32 lsc_grid_offset_x;
  __u32 lsc_grid_offset_y;
  __u32 cac_grid_offset_x;
  __u32 cac_grid_offset_y;
  __u16 crop_x_start[PISP_BACK_END_NUM_OUTPUTS];
  __u16 crop_x_end[PISP_BACK_END_NUM_OUTPUTS];
  __u16 crop_y_start[PISP_BACK_END_NUM_OUTPUTS];
  __u16 crop_y_end[PISP_BACK_END_NUM_OUTPUTS];
  __u16 downscale_phase_x[3 * PISP_BACK_END_NUM_OUTPUTS];
  __u16 downscale_phase_y[3 * PISP_BACK_END_NUM_OUTPUTS];
  __u16 resample_in_width[PISP_BACK_END_NUM_OUTPUTS];
  __u16 resample_in_height[PISP_BACK_END_NUM_OUTPUTS];
  __u16 resample_phase_x[3 * PISP_BACK_END_NUM_OUTPUTS];
  __u16 resample_phase_y[3 * PISP_BACK_END_NUM_OUTPUTS];
  __u16 output_offset_x[PISP_BACK_END_NUM_OUTPUTS];
  __u16 output_offset_y[PISP_BACK_END_NUM_OUTPUTS];
  __u16 output_width[PISP_BACK_END_NUM_OUTPUTS];
  __u16 output_height[PISP_BACK_END_NUM_OUTPUTS];
  __u32 output_addr_offset[PISP_BACK_END_NUM_OUTPUTS];
  __u32 output_addr_offset2[PISP_BACK_END_NUM_OUTPUTS];
  __u32 output_hog_addr_offset;
} __attribute__((packed));
struct pisp_be_tiles_config {
  struct pisp_be_config config;
  struct pisp_tile tiles[PISP_BACK_END_NUM_TILES];
  __u32 num_tiles;
} __attribute__((packed));
#endif

"""

```