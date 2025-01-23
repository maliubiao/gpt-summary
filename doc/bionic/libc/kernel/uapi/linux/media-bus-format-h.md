Response:
Let's break down the thought process to answer this complex request.

**1. Understanding the Core Request:**

The fundamental request is to analyze a C header file (`media-bus-format.h`) located within the Android bionic library and explain its purpose, relationships to Android, implementation details (though it's a header), dynamic linking aspects (minimal here), common errors, and how Android frameworks access it, culminating in a Frida hook example.

**2. Initial Analysis of the Header File:**

The first thing to notice is that the file is auto-generated and defines a series of preprocessor macros (`#define`). These macros all start with `MEDIA_BUS_FMT_` and are followed by a descriptive name and a hexadecimal value. This strongly suggests that the file defines constants representing different media bus formats.

**3. Identifying the Purpose:**

Given the naming convention and the context of "media-bus," the core purpose is clearly to define standard formats for transferring media data (likely images and video) between hardware components within an Android device. The hexadecimal values likely act as unique identifiers for these formats. The presence of RGB, YUV, and Bayer pattern formats reinforces this.

**4. Connecting to Android Functionality:**

The key connection to Android is through the camera and media subsystems. The formats defined here would be used by:

* **Camera HAL (Hardware Abstraction Layer):**  The low-level software that directly interacts with the camera sensor. It needs to communicate the captured image format.
* **Media Framework (MediaCodec, MediaRecorder, etc.):** These frameworks process and encode/decode media. They need to understand the format of the input and output data.
* **Display Subsystem:** When displaying images or video, the display driver needs to know the pixel format.

**5. Addressing Implementation Details (for a Header File):**

Since it's a header file, there's no actual code implementation within this file. The "implementation" is handled by the components that *use* these definitions. The header simply provides the agreed-upon vocabulary (the constants). It's crucial to point this out.

**6. Dynamic Linking Aspects:**

This header file itself doesn't directly involve dynamic linking. However, the *components* that use these definitions (like the Camera HAL or Media Framework libraries) *do* use dynamic linking.

* **SO Layout Sample:**  Illustrate a typical arrangement where a system process loads a HAL library. Highlight the dependencies.
* **Linking Process:**  Briefly describe the linker's role in resolving symbols and loading shared objects. Emphasize that the header facilitates agreement on data structures but the linking happens with the libraries using those structures.

**7. Logical Reasoning and Input/Output (Limited for a Header):**

There isn't much logical reasoning within the header itself. The definitions are fixed. However, one could *hypothesize* a scenario where a camera driver reports a specific `MEDIA_BUS_FMT_*` value, and the media framework uses that value to determine how to interpret the incoming data.

* **Hypothetical Input:** Camera HAL reports `MEDIA_BUS_FMT_RGB888_1X24`.
* **Hypothetical Output:** MediaCodec configures itself to expect 24 bits per pixel in RGB format.

**8. Common Usage Errors:**

The main errors related to this file are about misinterpreting or mismatching format definitions:

* **Incorrect Format Assumption:**  Assuming the data is in one format when the sensor is providing another.
* **Missing Format Support:** The application or framework might not support a specific format reported by the hardware.
* **Endianness Issues:** Some formats have BE (Big Endian) and LE (Little Endian) variants, and incorrect handling can lead to garbled images.

**9. Android Framework/NDK Access Path:**

This is a multi-step process, starting from the high-level Android APIs down to the kernel level:

1. **Application (Java/Kotlin):**  Uses Camera2 API or Media APIs.
2. **Framework (Java/Native):**  `android.hardware.camera2.*`, `android.media.*`.
3. **HAL Interface (AIDL/HIDL):**  Defines communication between the framework and the hardware-specific HAL.
4. **Camera HAL Implementation (Native):**  The vendor-provided library that interacts with the sensor.
5. **Kernel Drivers:**  Low-level drivers that directly control the camera hardware.
6. **`media-bus-format.h`:** Used as a common vocabulary throughout these layers, especially within the HAL and kernel drivers.

**10. Frida Hook Example:**

A Frida hook is crucial to demonstrate how to inspect these values at runtime. Focus on hooking a function within the Camera HAL that likely deals with format negotiation or processing. The hook should read the value of a variable representing the media bus format.

**11. Structuring the Answer:**

Organize the information logically with clear headings. Use bullet points and examples to make it easy to understand. Clearly distinguish between the header file itself and the components that use it.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe the header file contains structs or function prototypes.
* **Correction:**  No, it's just `#define` macros, indicating it's purely for defining constants. This simplifies the explanation.

* **Initial Thought:**  Focus heavily on dynamic linking within the *header*.
* **Correction:**  The header itself doesn't *do* dynamic linking. Shift the focus to how the *libraries that use these definitions* are linked.

* **Initial Thought:**  Provide extremely low-level kernel details.
* **Correction:** Keep the explanation at a high enough level to be understandable while still being accurate. Focus on the flow of information and the roles of different components.

By following these steps and continuously refining the understanding, a comprehensive and accurate answer can be constructed.
这是一个定义了一系列用于描述多媒体数据格式的常量的头文件。它主要用于 Linux 内核的媒体子系统，在 Android 中，这些定义通过 Bionic C 库暴露给用户空间。

**功能列举:**

该文件定义了一系列宏，这些宏代表了各种不同的媒体数据格式，包括：

* **RGB 格式:** 例如 `MEDIA_BUS_FMT_RGB888_1X24` 代表 24 位的 RGB 格式，每个像素由 8 位的红色、绿色和蓝色分量组成。
* **YUV 格式:** 例如 `MEDIA_BUS_FMT_YUYV8_2X8` 代表一种 YUV 格式，其中 Y、U 和 V 分量以特定的顺序排列。YUV 格式常用于视频编码和处理。
* **Bayer 格式:** 例如 `MEDIA_BUS_FMT_SBGGR8_1X8` 代表 Bayer 模式的图像数据，通常用于相机传感器输出的原始数据。
* **其他格式:**  还包括 JPEG、AHSV 和元数据格式。

这些宏定义了不同格式的特性，例如：

* **颜色空间:** RGB, YUV, Bayer 等。
* **位深度:** 每个颜色分量或像素占用的位数，例如 8 位、10 位、12 位等。
* **像素排列方式:**  例如，在 YUV 格式中，Y、U 和 V 分量的排列顺序不同，例如 YUYV、VYUY 等。
* **打包方式:**  例如，某些格式将多个像素打包在一起。
* **字节序:** 大端 (BE) 或小端 (LE)。

**与 Android 功能的关系及举例:**

这个头文件定义的格式常量在 Android 的多媒体框架中扮演着至关重要的角色，特别是在以下方面：

* **相机子系统:**
    * **Camera HAL (Hardware Abstraction Layer):**  相机硬件抽象层使用这些常量来描述相机传感器输出的图像格式。例如，相机传感器可能输出 `MEDIA_BUS_FMT_RAW16` 格式的原始数据。Camera HAL 会将这些原始数据转换为 Android Framework 可以理解的格式，例如 `ImageFormat.RAW_SENSOR` 或 `ImageFormat.JPEG`。
    * **示例:** 当一个 Android 应用使用 Camera2 API 请求一个原始格式的图像时，底层的 Camera HAL 会使用这些 `MEDIA_BUS_FMT_*` 常量来配置相机传感器的数据输出格式。

* **视频编解码:**
    * **MediaCodec:** Android 的媒体编解码器使用这些常量来识别输入和输出的视频帧格式。例如，一个视频解码器可能需要知道输入的 H.264 比特流解码后的像素格式是 `MEDIA_BUS_FMT_YUV420P`。
    * **示例:**  当一个应用使用 `MediaCodec` 解码一段视频时，它需要指定期望的输出格式。这个输出格式可能对应于这里定义的一个 `MEDIA_BUS_FMT_*` 常量。

* **显示子系统:**
    * **SurfaceFlinger:** Android 的显示合成器可能需要了解不同图层的像素格式，这些格式可能与这里定义的某些常量相关。
    * **示例:**  当将一个视频帧渲染到屏幕上时，SurfaceFlinger 需要知道该帧的像素格式，这可能间接地与这些常量相关。

**libc 函数的功能及实现:**

这个文件中定义的都是宏常量，并不包含任何 libc 函数。libc 函数是 C 标准库提供的函数，例如 `printf`、`malloc` 等。这个头文件的作用是定义常量，而不是实现函数。

**dynamic linker 的功能、so 布局样本及链接处理过程:**

这个头文件本身并不直接涉及动态链接器的功能。动态链接器（在 Android 中是 `linker64` 或 `linker`）负责在程序运行时加载和链接共享库（.so 文件）。

尽管如此，这些常量被定义在 bionic 库中，而 bionic 库本身就是一个共享库。使用这些常量的其他共享库或可执行文件需要链接到 bionic 库。

**SO 布局样本:**

假设有一个名为 `libcamera_hal.so` 的 Camera HAL 库，它使用了 `media-bus-format.h` 中定义的常量。

```
libcamera_hal.so:
    ... 代码 ...
    引用的符号:
        MEDIA_BUS_FMT_RGB888_1X24 (来自 bionic)
        MEDIA_BUS_FMT_YUV420P (来自 bionic)
    ... 其他符号 ...

bionic:
    ... 代码 ...
    导出的符号:
        MEDIA_BUS_FMT_RGB888_1X24 = 0x100a
        MEDIA_BUS_FMT_YUV420P  //  这里实际会展开成对应的数值
    ... 其他符号 ...
```

**链接的处理过程:**

1. **编译时:** 当 `libcamera_hal.so` 被编译时，编译器会记录它引用了 `MEDIA_BUS_FMT_RGB888_1X24` 等符号。这些符号在编译时是未解析的。
2. **链接时:** 链接器会将 `libcamera_hal.so` 与它依赖的库（包括 bionic）链接在一起。链接器会找到 bionic 库中导出的这些符号的定义（即具体的数值）。
3. **运行时:** 当 Android 系统加载 `libcamera_hal.so` 时，动态链接器会确保 bionic 库也被加载，并将 `libcamera_hal.so` 中对 `MEDIA_BUS_FMT_RGB888_1X24` 等符号的引用指向 bionic 库中对应的数值。

**逻辑推理、假设输入与输出:**

由于这个文件只定义了常量，没有逻辑运算，因此不涉及逻辑推理。

**用户或编程常见的使用错误:**

* **硬编码数值:**  直接在代码中使用 `0x100a` 而不是 `MEDIA_BUS_FMT_RGB888_1X24`，这会使代码难以理解和维护。如果格式的定义发生变化，硬编码的值也会失效。
* **格式不匹配:**  在不同的组件之间传递数据时，假设了错误的格式。例如，一个相机驱动输出了 `MEDIA_BUS_FMT_YUV420P`，但上层应用却按照 `MEDIA_BUS_FMT_NV21` 来解析，会导致图像显示错误或崩溃。
* **字节序错误:** 对于有大端和小端变体的格式，如果没有正确处理字节序，会导致颜色分量错乱。

**Android Framework 或 NDK 如何到达这里:**

1. **应用层 (Java/Kotlin):** 开发者使用 Android Framework 提供的 Camera2 API 或 Media APIs (例如 `MediaCodec`)。
2. **Framework 层 (Java/Native):**
   * **Camera Service:** 处理相机相关的请求，并与 Camera HAL 通信。
   * **Media Framework:** 提供媒体编解码、录制等功能。
3. **HAL Interface Definition Language (HIDL) 或 Android Interface Definition Language (AIDL):** 定义了 Framework 层和 HAL 层之间的接口。这些接口会传递描述图像格式的参数。
4. **Camera HAL Implementation (Native C++):** 厂商提供的 HAL 库实现了与具体相机硬件交互的逻辑。在这里，`media-bus-format.h` 中定义的常量会被使用来描述硬件支持的格式以及与内核驱动交互时使用的格式。
5. **Kernel Drivers (Linux Kernel):**  相机驱动程序会使用这些常量来配置硬件并处理图像数据。`media-bus-format.h` 来自 Linux 内核，因此驱动程序可以直接使用。

**Frida Hook 示例调试步骤:**

假设我们想在 Camera HAL 中查看当前使用的图像格式。我们可以 hook 一个与图像数据处理相关的函数，例如获取图像缓冲区的函数。

```python
import frida
import sys

package_name = "your.camera.app" # 替换成你的相机应用包名
process = frida.get_usb_device().attach(package_name)

# 假设 libcamera_hal.so 中有一个函数叫 get_buffer_format，它返回一个格式 ID
script_code = """
Interceptor.attach(Module.findExportByName("libcamera_hal.so", "get_buffer_format"), {
  onEnter: function(args) {
    console.log("get_buffer_format called");
  },
  onLeave: function(retval) {
    console.log("get_buffer_format returned: " + retval);
    // 可以根据 retval 的值查找对应的格式名称
    if (retval.toInt() === 0x100a) {
      console.log("Format is MEDIA_BUS_FMT_RGB888_1X24");
    } else if (retval.toInt() === 0x2008) {
      console.log("Format is MEDIA_BUS_FMT_YUYV8_2X8");
    }
    // ... 添加更多格式判断 ...
  }
});
"""

script = process.create_script(script_code)
script.on('message', lambda message, data: print(message))
script.load()
sys.stdin.read()
```

**解释:**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 设备上的指定应用进程。
2. **`Module.findExportByName("libcamera_hal.so", "get_buffer_format")`:**  在 `libcamera_hal.so` 模块中查找名为 `get_buffer_format` 的导出函数。你需要根据实际情况替换函数名。
3. **`Interceptor.attach(...)`:**  拦截目标函数。
4. **`onEnter`:** 在函数调用前执行，这里打印一条日志。
5. **`onLeave`:** 在函数返回后执行，这里打印返回值，并根据返回值判断图像格式。
6. **`retval.toInt()`:** 将返回值转换为整数。
7. **`script.on('message', ...)`:** 处理脚本中的 `console.log` 输出。

**使用步骤:**

1. 确保你的 Android 设备已 root，并安装了 Frida 服务。
2. 安装 Frida Python 库：`pip install frida-tools`。
3. 将 `your.camera.app` 替换为你要调试的相机应用的包名。
4. 替换 `get_buffer_format` 为 `libcamera_hal.so` 中实际存在的与图像格式相关的函数名。你可以使用 `frida-ps -U` 查看进程列表，然后使用 `frida -U -n <进程名> -l list_exports.js` (需要自己编写 `list_exports.js` 来列出导出函数) 来查找可能的函数。
5. 运行 Python 脚本。
6. 启动或使用你的相机应用。
7. Frida 会打印出 `get_buffer_format` 函数的返回值，你可以根据返回值判断当前使用的图像格式。

这个 Frida 示例提供了一个基本的框架，你可以根据需要修改它来 hook 不同的函数和检查不同的参数，从而更深入地了解 Android 多媒体框架如何使用这些格式定义。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/media-bus-format.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_MEDIA_BUS_FORMAT_H
#define __LINUX_MEDIA_BUS_FORMAT_H
#define MEDIA_BUS_FMT_FIXED 0x0001
#define MEDIA_BUS_FMT_RGB444_1X12 0x1016
#define MEDIA_BUS_FMT_RGB444_2X8_PADHI_BE 0x1001
#define MEDIA_BUS_FMT_RGB444_2X8_PADHI_LE 0x1002
#define MEDIA_BUS_FMT_RGB555_2X8_PADHI_BE 0x1003
#define MEDIA_BUS_FMT_RGB555_2X8_PADHI_LE 0x1004
#define MEDIA_BUS_FMT_RGB565_1X16 0x1017
#define MEDIA_BUS_FMT_BGR565_2X8_BE 0x1005
#define MEDIA_BUS_FMT_BGR565_2X8_LE 0x1006
#define MEDIA_BUS_FMT_RGB565_2X8_BE 0x1007
#define MEDIA_BUS_FMT_RGB565_2X8_LE 0x1008
#define MEDIA_BUS_FMT_RGB666_1X18 0x1009
#define MEDIA_BUS_FMT_RGB666_2X9_BE 0x1025
#define MEDIA_BUS_FMT_BGR666_1X18 0x1023
#define MEDIA_BUS_FMT_RBG888_1X24 0x100e
#define MEDIA_BUS_FMT_RGB666_1X24_CPADHI 0x1015
#define MEDIA_BUS_FMT_BGR666_1X24_CPADHI 0x1024
#define MEDIA_BUS_FMT_RGB565_1X24_CPADHI 0x1022
#define MEDIA_BUS_FMT_RGB666_1X7X3_SPWG 0x1010
#define MEDIA_BUS_FMT_BGR888_1X24 0x1013
#define MEDIA_BUS_FMT_BGR888_3X8 0x101b
#define MEDIA_BUS_FMT_GBR888_1X24 0x1014
#define MEDIA_BUS_FMT_RGB888_1X24 0x100a
#define MEDIA_BUS_FMT_RGB888_2X12_BE 0x100b
#define MEDIA_BUS_FMT_RGB888_2X12_LE 0x100c
#define MEDIA_BUS_FMT_RGB888_3X8 0x101c
#define MEDIA_BUS_FMT_RGB888_3X8_DELTA 0x101d
#define MEDIA_BUS_FMT_RGB888_1X7X4_SPWG 0x1011
#define MEDIA_BUS_FMT_RGB888_1X7X4_JEIDA 0x1012
#define MEDIA_BUS_FMT_RGB666_1X30_CPADLO 0x101e
#define MEDIA_BUS_FMT_RGB888_1X30_CPADLO 0x101f
#define MEDIA_BUS_FMT_ARGB8888_1X32 0x100d
#define MEDIA_BUS_FMT_RGB888_1X32_PADHI 0x100f
#define MEDIA_BUS_FMT_RGB101010_1X30 0x1018
#define MEDIA_BUS_FMT_RGB666_1X36_CPADLO 0x1020
#define MEDIA_BUS_FMT_RGB888_1X36_CPADLO 0x1021
#define MEDIA_BUS_FMT_RGB121212_1X36 0x1019
#define MEDIA_BUS_FMT_RGB161616_1X48 0x101a
#define MEDIA_BUS_FMT_Y8_1X8 0x2001
#define MEDIA_BUS_FMT_UV8_1X8 0x2015
#define MEDIA_BUS_FMT_UYVY8_1_5X8 0x2002
#define MEDIA_BUS_FMT_VYUY8_1_5X8 0x2003
#define MEDIA_BUS_FMT_YUYV8_1_5X8 0x2004
#define MEDIA_BUS_FMT_YVYU8_1_5X8 0x2005
#define MEDIA_BUS_FMT_UYVY8_2X8 0x2006
#define MEDIA_BUS_FMT_VYUY8_2X8 0x2007
#define MEDIA_BUS_FMT_YUYV8_2X8 0x2008
#define MEDIA_BUS_FMT_YVYU8_2X8 0x2009
#define MEDIA_BUS_FMT_Y10_1X10 0x200a
#define MEDIA_BUS_FMT_Y10_2X8_PADHI_LE 0x202c
#define MEDIA_BUS_FMT_UYVY10_2X10 0x2018
#define MEDIA_BUS_FMT_VYUY10_2X10 0x2019
#define MEDIA_BUS_FMT_YUYV10_2X10 0x200b
#define MEDIA_BUS_FMT_YVYU10_2X10 0x200c
#define MEDIA_BUS_FMT_Y12_1X12 0x2013
#define MEDIA_BUS_FMT_UYVY12_2X12 0x201c
#define MEDIA_BUS_FMT_VYUY12_2X12 0x201d
#define MEDIA_BUS_FMT_YUYV12_2X12 0x201e
#define MEDIA_BUS_FMT_YVYU12_2X12 0x201f
#define MEDIA_BUS_FMT_Y14_1X14 0x202d
#define MEDIA_BUS_FMT_Y16_1X16 0x202e
#define MEDIA_BUS_FMT_UYVY8_1X16 0x200f
#define MEDIA_BUS_FMT_VYUY8_1X16 0x2010
#define MEDIA_BUS_FMT_YUYV8_1X16 0x2011
#define MEDIA_BUS_FMT_YVYU8_1X16 0x2012
#define MEDIA_BUS_FMT_YDYUYDYV8_1X16 0x2014
#define MEDIA_BUS_FMT_UYVY10_1X20 0x201a
#define MEDIA_BUS_FMT_VYUY10_1X20 0x201b
#define MEDIA_BUS_FMT_YUYV10_1X20 0x200d
#define MEDIA_BUS_FMT_YVYU10_1X20 0x200e
#define MEDIA_BUS_FMT_VUY8_1X24 0x2024
#define MEDIA_BUS_FMT_YUV8_1X24 0x2025
#define MEDIA_BUS_FMT_UYYVYY8_0_5X24 0x2026
#define MEDIA_BUS_FMT_UYVY12_1X24 0x2020
#define MEDIA_BUS_FMT_VYUY12_1X24 0x2021
#define MEDIA_BUS_FMT_YUYV12_1X24 0x2022
#define MEDIA_BUS_FMT_YVYU12_1X24 0x2023
#define MEDIA_BUS_FMT_YUV10_1X30 0x2016
#define MEDIA_BUS_FMT_UYYVYY10_0_5X30 0x2027
#define MEDIA_BUS_FMT_AYUV8_1X32 0x2017
#define MEDIA_BUS_FMT_UYYVYY12_0_5X36 0x2028
#define MEDIA_BUS_FMT_YUV12_1X36 0x2029
#define MEDIA_BUS_FMT_YUV16_1X48 0x202a
#define MEDIA_BUS_FMT_UYYVYY16_0_5X48 0x202b
#define MEDIA_BUS_FMT_SBGGR8_1X8 0x3001
#define MEDIA_BUS_FMT_SGBRG8_1X8 0x3013
#define MEDIA_BUS_FMT_SGRBG8_1X8 0x3002
#define MEDIA_BUS_FMT_SRGGB8_1X8 0x3014
#define MEDIA_BUS_FMT_SBGGR10_ALAW8_1X8 0x3015
#define MEDIA_BUS_FMT_SGBRG10_ALAW8_1X8 0x3016
#define MEDIA_BUS_FMT_SGRBG10_ALAW8_1X8 0x3017
#define MEDIA_BUS_FMT_SRGGB10_ALAW8_1X8 0x3018
#define MEDIA_BUS_FMT_SBGGR10_DPCM8_1X8 0x300b
#define MEDIA_BUS_FMT_SGBRG10_DPCM8_1X8 0x300c
#define MEDIA_BUS_FMT_SGRBG10_DPCM8_1X8 0x3009
#define MEDIA_BUS_FMT_SRGGB10_DPCM8_1X8 0x300d
#define MEDIA_BUS_FMT_SBGGR10_2X8_PADHI_BE 0x3003
#define MEDIA_BUS_FMT_SBGGR10_2X8_PADHI_LE 0x3004
#define MEDIA_BUS_FMT_SBGGR10_2X8_PADLO_BE 0x3005
#define MEDIA_BUS_FMT_SBGGR10_2X8_PADLO_LE 0x3006
#define MEDIA_BUS_FMT_SBGGR10_1X10 0x3007
#define MEDIA_BUS_FMT_SGBRG10_1X10 0x300e
#define MEDIA_BUS_FMT_SGRBG10_1X10 0x300a
#define MEDIA_BUS_FMT_SRGGB10_1X10 0x300f
#define MEDIA_BUS_FMT_SBGGR12_1X12 0x3008
#define MEDIA_BUS_FMT_SGBRG12_1X12 0x3010
#define MEDIA_BUS_FMT_SGRBG12_1X12 0x3011
#define MEDIA_BUS_FMT_SRGGB12_1X12 0x3012
#define MEDIA_BUS_FMT_SBGGR14_1X14 0x3019
#define MEDIA_BUS_FMT_SGBRG14_1X14 0x301a
#define MEDIA_BUS_FMT_SGRBG14_1X14 0x301b
#define MEDIA_BUS_FMT_SRGGB14_1X14 0x301c
#define MEDIA_BUS_FMT_SBGGR16_1X16 0x301d
#define MEDIA_BUS_FMT_SGBRG16_1X16 0x301e
#define MEDIA_BUS_FMT_SGRBG16_1X16 0x301f
#define MEDIA_BUS_FMT_SRGGB16_1X16 0x3020
#define MEDIA_BUS_FMT_JPEG_1X8 0x4001
#define MEDIA_BUS_FMT_S5C_UYVY_JPEG_1X8 0x5001
#define MEDIA_BUS_FMT_AHSV8888_1X32 0x6001
#define MEDIA_BUS_FMT_METADATA_FIXED 0x7001
#define MEDIA_BUS_FMT_META_8 0x8001
#define MEDIA_BUS_FMT_META_10 0x8002
#define MEDIA_BUS_FMT_META_12 0x8003
#define MEDIA_BUS_FMT_META_14 0x8004
#define MEDIA_BUS_FMT_META_16 0x8005
#define MEDIA_BUS_FMT_META_20 0x8006
#define MEDIA_BUS_FMT_META_24 0x8007
#endif
```