Response:
Let's break down the thought process for answering the request about `v4l2-mediabus.h`.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of the provided C header file (`v4l2-mediabus.h`) within the context of Android (bionic). The request explicitly asks for:

* Functionality listing.
* Relation to Android with examples.
* Detailed explanation of libc functions (though none are directly in this file).
* Dynamic linker aspects (relevant due to bionic location).
* Logical reasoning (if any).
* Common usage errors.
* How Android framework/NDK reaches this point.
* Frida hook examples.

**2. Initial Analysis of the Header File:**

* **`#ifndef __LINUX_V4L2_MEDIABUS_H`... `#endif`:** Standard header guard, preventing multiple inclusions.
* **`/* ... auto-generated ... */`:**  Indicates this file is likely generated from some other source, and manual edits are discouraged. This is important context.
* **`#include <linux/media-bus-format.h>` and `#include <linux/types.h>` and `#include <linux/videodev2.h>`:**  Crucial dependencies. This file *relies* on definitions from these other Linux kernel headers. The functionality is built *upon* these.
* **`#define V4L2_MBUS_FRAMEFMT_SET_CSC 0x0001`:** A simple macro definition. It's a flag.
* **`struct v4l2_mbus_framefmt { ... };`:**  A key data structure. This describes the format of a video frame transmitted over the media bus. The members clearly relate to image properties (width, height, pixel format, color information).
* **`#define V4L2_MBUS_FROM_MEDIA_BUS_FMT(name) V4L2_MBUS_FMT_ ##name = MEDIA_BUS_FMT_ ##name`:** A preprocessor macro used to define enumerations. This is a code generation pattern.
* **`enum v4l2_mbus_pixelcode { ... };`:**  A long list of enumerated pixel format codes. The names (e.g., `RGB888_1X24`, `YUYV8_2X8`) strongly suggest various RGB, YUV, and Bayer formats.

**3. Identifying Key Functionality (Based on Analysis):**

From the structure and contents, the primary function is clear: **Defining data structures and enumerations for describing video frame formats used in the Video4Linux2 (V4L2) media bus subsystem.**

**4. Connecting to Android:**

* **Camera Subsystem:** The most obvious connection. Android's camera framework needs to interact with hardware cameras. These cameras often communicate using standard protocols, including those defined by V4L2.
* **Media Framework:**  Android's media framework (for video decoding, encoding, and playback) needs to understand and handle various video formats. These formats are described, in part, by the definitions in this file.
* **Hardware Abstraction Layer (HAL):**  Camera HAL implementations directly interact with the kernel drivers that use these structures.

**5. Addressing Specific Request Points:**

* **libc Functions:**  This file *doesn't* define libc functions. It defines data structures and enums. Therefore, the detailed explanation of libc function implementation isn't applicable here. This is a crucial point to state explicitly.
* **Dynamic Linker:** While the file is *located* within bionic, it's a header file. Header files themselves aren't directly linked. However, the *code* that uses these definitions *will* be linked. The linker's role is to resolve symbols. In this case, the code using these structures would be part of a shared library (like a camera HAL or media codec). A sample `so` layout and linking process can be described generally for such a library.
* **Logical Reasoning:** The primary logic is the mapping between the generic `MEDIA_BUS_FMT_` definitions and the `V4L2_MBUS_FMT_` specific definitions using the macro. This ensures consistency.
* **Common Errors:** Misunderstanding or incorrectly configuring the pixel format is a common issue. Examples can be given.
* **Android Framework/NDK Path:**  Trace the path from the high-level Android APIs down to the kernel level, highlighting where these structures would be used.
* **Frida Hooks:**  Focus on hooking functions within the camera HAL or media framework that would likely use the `v4l2_mbus_framefmt` structure or the `v4l2_mbus_pixelcode` enum.

**6. Structuring the Answer:**

Organize the answer according to the points in the request. Use clear headings and bullet points. Provide code examples where relevant (especially for Frida).

**7. Refinement and Language:**

Use precise language. Explain technical terms. Since the request is in Chinese, the response should also be in fluent Chinese.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file defines some low-level C functions related to video.
* **Correction:**  Closer examination reveals it's primarily data structure and enum definitions. The *functionality* comes from the kernel drivers and higher-level libraries that *use* these definitions.
* **Initial thought:**  Focus heavily on the bionic aspect.
* **Correction:** While located in bionic, the core function is about V4L2 and kernel interaction. The bionic context is important (it's how Android interacts with the kernel), but the focus should be on the V4L2 aspects.
* **Realization:** The request asks for *libc function* explanations. This file has none. Explicitly state this and pivot to where these definitions are *used*.

By following this structured thought process, considering the context, and refining the analysis, a comprehensive and accurate answer can be constructed.
这个 `bionic/libc/kernel/uapi/linux/v4l2-mediabus.h` 文件是 Android Bionic C 库的一部分，它直接来源于 Linux 内核的头文件。这个文件的主要作用是 **定义了与 Video4Linux2 (V4L2) 媒体总线相关的结构体、宏和枚举类型**。V4L2 是 Linux 系统中用于访问视频设备的 API。媒体总线则是一种用于连接视频设备内部各个组件（例如传感器、ISP、编码器）的硬件接口。

**功能列举:**

1. **定义 `v4l2_mbus_framefmt` 结构体:**  这个结构体用于描述通过媒体总线传输的视频帧的格式。它包含了以下信息：
    * `width`: 图像宽度
    * `height`: 图像高度
    * `code`: 像素格式代码，用于标识具体的像素排列方式和色彩空间。
    * `field`: 隔行扫描模式。
    * `colorspace`: 色彩空间。
    * `ycbcr_enc`, `hsv_enc`:  用于指定 YCbCr 和 HSV 编码的参数。
    * `quantization`: 量化范围。
    * `xfer_func`: 传递函数（例如 Gamma 校正）。
    * `flags`: 标志位，例如 `V4L2_MBUS_FRAMEFMT_SET_CSC` 表示需要进行色彩空间转换。
    * `reserved`: 保留字段。

2. **定义 `V4L2_MBUS_FRAMEFMT_SET_CSC` 宏:**  这是一个标志位，用于指示是否需要设置色彩空间转换。

3. **定义 `v4l2_mbus_pixelcode` 枚举类型:** 这个枚举类型列出了各种支持的像素格式代码。这些代码与 `linux/media-bus-format.h` 中定义的 `MEDIA_BUS_FMT_` 宏对应。例如，`V4L2_MBUS_RGB888_1X24` 表示 24 位的 RGB 格式。这个枚举类型是通过 `V4L2_MBUS_FROM_MEDIA_BUS_FMT` 宏来生成的，该宏将 `MEDIA_BUS_FMT_` 开头的宏转换为 `V4L2_MBUS_FMT_` 开头的枚举值。

**与 Android 功能的关系及举例:**

这个文件直接关系到 **Android 的相机 (Camera) 子系统**。当 Android 设备上的相机传感器捕获图像数据时，这些数据通常会通过媒体总线传输到图像信号处理器 (ISP) 或其他处理单元。

**举例说明:**

* **相机 HAL (Hardware Abstraction Layer):** Android 的 Camera HAL 接口的实现需要与底层的相机驱动程序交互。这些驱动程序会使用 `v4l2` 的 API 来配置和控制相机硬件。`v4l2_mbus_framefmt` 结构体会被用来协商相机传感器输出的图像格式，例如分辨率、像素格式等。
* **图像采集和处理:** 当一个 Android 应用（例如相机应用）请求捕获图像时，底层的 Camera 服务会使用 V4L2 API 与相机驱动进行交互。驱动程序会使用 `v4l2_mbus_framefmt` 来告诉内核期望的图像格式。
* **视频编解码:**  在 Android 的媒体框架中，当处理视频流时，需要知道视频帧的格式。如果视频源是通过 V4L2 设备获取的，那么 `v4l2_mbus_framefmt` 中定义的像素格式信息就至关重要，以便正确地解码或编码视频数据。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个文件中并没有定义任何 libc 函数。** 它只定义了数据结构、宏和枚举类型。这些定义会被其他的 C/C++ 代码引用，而这些代码可能会调用 libc 函数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然这个头文件本身不涉及 dynamic linker，但使用它的代码（例如 Camera HAL 的实现）会被编译成共享库 (`.so` 文件）。

**so 布局样本 (简略):**

```
.text         # 代码段
   ... (Camera HAL 的函数实现，可能会使用 v4l2_mbus_framefmt 结构体) ...
.rodata       # 只读数据段
   ... (可能包含一些静态的 v4l2_mbus_framefmt 常量) ...
.data         # 可读写数据段
   ... (可能包含一些全局的 v4l2_mbus_framefmt 变量) ...
.bss          # 未初始化数据段
.dynsym       # 动态符号表
   ... (可能包含 Camera HAL 中需要外部链接的符号) ...
.dynstr       # 动态字符串表
.plt          # 程序链接表 (用于延迟绑定)
.got.plt      # 全局偏移表 (用于动态链接)
...
```

**链接的处理过程:**

1. **编译时:**  Camera HAL 的源代码会被编译成目标文件 (`.o`)。编译器会识别出代码中使用的 `v4l2_mbus_framefmt` 结构体，但由于这是在头文件中定义的，编译器只需要知道其布局。
2. **链接时:**  链接器会将不同的目标文件链接成一个共享库 (`.so`)。如果 Camera HAL 的代码中使用了 V4L2 相关的符号（例如，如果它直接调用了 V4L2 的 ioctl 系统调用），链接器会查找这些符号的定义。对于内核提供的 V4L2 接口，这些符号通常不会直接链接到用户空间的 `.so` 文件中。
3. **运行时 (Dynamic Linking):** 当 Android 系统加载 Camera HAL 共享库时，dynamic linker (在 Android 中是 `linker64` 或 `linker`) 会负责解析库的依赖关系，并将库加载到内存中。
    * 对于像 `v4l2_mbus_framefmt` 这样的结构体定义，dynamic linker 的作用主要是确保使用这个定义的各个共享库使用相同的定义。这通常是通过包含相同的头文件来保证的。
    * 如果 Camera HAL 调用了 V4L2 的系统调用（例如通过 `ioctl`），这些调用会通过系统调用接口陷入内核。内核会处理这些调用，而 `v4l2-mediabus.h` 中定义的结构体会被用于在用户空间和内核空间之间传递数据。

**如果做了逻辑推理，请给出假设输入与输出:**

由于这个文件主要是定义数据结构，直接的逻辑推理较少。主要的“逻辑”在于宏 `V4L2_MBUS_FROM_MEDIA_BUS_FMT` 的使用，它确保了 `v4l2_mbus_pixelcode` 枚举中的值与 `linux/media-bus-format.h` 中定义的 `MEDIA_BUS_FMT_` 宏一致。

**假设输入:**  `linux/media-bus-format.h` 中定义了新的像素格式 `MEDIA_BUS_FMT_NEW_FORMAT = 0xXXXX`.

**输出:**  重新编译 `bionic` 后，`v4l2-mediabus.h` 文件将会包含新的枚举值 `V4L2_MBUS_FMT_NEW_FORMAT = 0xXXXX`.

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **像素格式不匹配:**  一个常见的错误是在配置相机或视频设备时，用户空间程序请求的像素格式与设备实际支持的格式不匹配。例如，程序可能尝试配置相机输出 `V4L2_MBUS_RGB888_1X24` 格式，但相机传感器只支持 `V4L2_MBUS_YUYV8_2X8` 格式。这会导致 `ioctl` 调用失败，或者捕获到错误的图像数据。

   **Frida Hook 示例 (用于调试像素格式协商):**

   ```python
   import frida
   import sys

   def on_message(message, data):
       if message['type'] == 'send':
           print("[*] {}".format(message['payload']))
       else:
           print(message)

   device = frida.get_usb_device()
   pid = device.spawn(["com.android.camera2"])  # 替换为目标应用包名
   session = device.attach(pid)
   script = session.create_script("""
       Interceptor.attach(Module.findExportByName(null, "ioctl"), {
           onEnter: function(args) {
               var req = args[1].toInt32();
               if (req == 0xc0345614) { // VIDIOC_S_FMT 的值
                   console.log("[*] ioctl called with VIDIOC_S_FMT");
                   var fmt = ptr(args[2]);
                   var type = fmt.readU32();
                   if (type == 1) { // V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
                       var width = fmt.add(8).readU32();
                       var height = fmt.add(12).readU32();
                       var pixelformat = fmt.add(20).readU32();
                       console.log("[*]   Requested format: width=" + width + ", height=" + height + ", pixelformat=" + pixelformat.toString(16));
                   }
               }
           }
       });
   """)
   script.on('message', on_message)
   script.load()
   device.resume(pid)
   sys.stdin.read()
   ```

2. **错误地设置色彩空间参数:** `v4l2_mbus_framefmt` 结构体中的 `colorspace`, `ycbcr_enc`, `quantization`, `xfer_func` 等字段用于描述色彩空间信息。如果这些参数设置不正确，会导致图像颜色失真。

3. **忽略保留字段:** 虽然 `reserved` 字段应该被忽略，但在某些情况下，错误地写入这些字段可能会导致不可预测的行为。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework (Java 层):**
   * 用户在 Android 设备上打开相机应用或使用需要访问摄像头的 API。
   * `android.hardware.camera2` 包中的类 (例如 `CameraManager`, `CameraDevice`, `CaptureRequest`) 被用来配置和控制相机。

2. **Camera Service (System Server):**
   * Framework 层的 API 调用会传递到 Camera Service。
   * Camera Service 负责管理设备的相机资源，并与底层的 Camera HAL 交互。

3. **Camera HAL (Native 层 - C/C++):**
   * Camera Service 通过 HIDL (Hardware Interface Definition Language) 或 AIDL (Android Interface Definition Language) 与 Camera HAL 交互。
   * Camera HAL 的实现通常位于 `/vendor/` 或 `/hardware/` 目录下。
   * **关键点:** Camera HAL 的实现会使用 V4L2 API 来控制相机硬件。这涉及到打开 V4L2 设备节点 (`/dev/videoX`)，并使用 `ioctl` 系统调用来配置设备参数，包括图像格式。

4. **V4L2 Driver (Kernel 空间):**
   * Camera HAL 通过 `ioctl` 系统调用与 V4L2 驱动程序通信。
   * **关键点:**  在配置图像格式时，Camera HAL 会填充 `v4l2_format` 结构体，其中包含一个 `v4l2_pix_format_mplane` 成员（用于多平面格式）或者 `v4l2_pix_format` 成员（用于单平面格式）。这两个结构体中都有一个 `pixelformat` 字段，用于指定像素格式，其值通常对应于 `v4l2-mediabus.h` 中定义的 `V4L2_MBUS_` 开头的宏。
   * 内核的 V4L2 驱动程序会解析这些结构体，并根据硬件能力配置相机传感器。

**Frida Hook 示例 (调试 Camera HAL 中使用 V4L2 的过程):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device()
# 找到 Camera HAL 进程，可能需要根据设备进行调整
pid = device.spawn(["/system/bin/cameraserver"])
session = device.attach(pid)

script = session.create_script("""
    // 假设 Camera HAL 库名为 libCameraService.so，需要根据实际情况修改
    var cameraService = Process.getModuleByName("libCameraService.so");

    // Hook open 系统调用，查看是否打开了 V4L2 设备节点
    Interceptor.attach(Module.findExportByName(null, "open"), {
        onEnter: function(args) {
            var pathname = Memory.readUtf8String(args[0]);
            if (pathname.startsWith("/dev/video")) {
                console.log("[*] open(\"" + pathname + "\", ...)");
            }
        }
    });

    // Hook ioctl 系统调用，查看与 V4L2 相关的操作
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            var req = args[1].toInt32();
            if (req == 0xc0345614) { // VIDIOC_S_FMT
                console.log("[*] ioctl(fd, VIDIOC_S_FMT, ...)");
                // 可以进一步解析 v4l2_format 结构体
            } else if (req == 0xc0185604) { // VIDIOC_G_FMT
                console.log("[*] ioctl(fd, VIDIOC_G_FMT, ...)");
                // 可以进一步解析 v4l2_format 结构体
            }
        }
    });
""")

script.on('message', on_message)
script.load()
device.resume(pid)
sys.stdin.read()
```

**总结:**

`bionic/libc/kernel/uapi/linux/v4l2-mediabus.h` 文件在 Android 的相机子系统中扮演着关键的角色，它定义了用于描述媒体总线视频帧格式的数据结构和枚举。虽然它本身不是可执行代码，但它的定义被 Camera HAL 和内核驱动程序广泛使用，以实现相机硬件的配置和图像数据的传输。理解这个文件的内容有助于理解 Android 相机系统的底层工作原理。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/v4l2-mediabus.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_V4L2_MEDIABUS_H
#define __LINUX_V4L2_MEDIABUS_H
#include <linux/media-bus-format.h>
#include <linux/types.h>
#include <linux/videodev2.h>
#define V4L2_MBUS_FRAMEFMT_SET_CSC 0x0001
struct v4l2_mbus_framefmt {
  __u32 width;
  __u32 height;
  __u32 code;
  __u32 field;
  __u32 colorspace;
  union {
    __u16 ycbcr_enc;
    __u16 hsv_enc;
  };
  __u16 quantization;
  __u16 xfer_func;
  __u16 flags;
  __u16 reserved[10];
};
#define V4L2_MBUS_FROM_MEDIA_BUS_FMT(name) V4L2_MBUS_FMT_ ##name = MEDIA_BUS_FMT_ ##name
enum v4l2_mbus_pixelcode {
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(FIXED),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(RGB444_2X8_PADHI_BE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(RGB444_2X8_PADHI_LE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(RGB555_2X8_PADHI_BE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(RGB555_2X8_PADHI_LE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(BGR565_2X8_BE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(BGR565_2X8_LE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(RGB565_2X8_BE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(RGB565_2X8_LE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(RGB666_1X18),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(RGB888_1X24),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(RGB888_2X12_BE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(RGB888_2X12_LE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(ARGB8888_1X32),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(Y8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(UV8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(UYVY8_1_5X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(VYUY8_1_5X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YUYV8_1_5X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YVYU8_1_5X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(UYVY8_2X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(VYUY8_2X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YUYV8_2X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YVYU8_2X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(Y10_1X10),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(UYVY10_2X10),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(VYUY10_2X10),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YUYV10_2X10),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YVYU10_2X10),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(Y12_1X12),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(UYVY8_1X16),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(VYUY8_1X16),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YUYV8_1X16),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YVYU8_1X16),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YDYUYDYV8_1X16),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(UYVY10_1X20),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(VYUY10_1X20),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YUYV10_1X20),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YVYU10_1X20),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YUV10_1X30),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(AYUV8_1X32),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(UYVY12_2X12),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(VYUY12_2X12),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YUYV12_2X12),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YVYU12_2X12),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(UYVY12_1X24),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(VYUY12_1X24),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YUYV12_1X24),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(YVYU12_1X24),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SBGGR8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SGBRG8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SGRBG8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SRGGB8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SBGGR10_ALAW8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SGBRG10_ALAW8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SGRBG10_ALAW8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SRGGB10_ALAW8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SBGGR10_DPCM8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SGBRG10_DPCM8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SGRBG10_DPCM8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SRGGB10_DPCM8_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SBGGR10_2X8_PADHI_BE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SBGGR10_2X8_PADHI_LE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SBGGR10_2X8_PADLO_BE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SBGGR10_2X8_PADLO_LE),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SBGGR10_1X10),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SGBRG10_1X10),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SGRBG10_1X10),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SRGGB10_1X10),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SBGGR12_1X12),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SGBRG12_1X12),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SGRBG12_1X12),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(SRGGB12_1X12),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(JPEG_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(S5C_UYVY_JPEG_1X8),
  V4L2_MBUS_FROM_MEDIA_BUS_FMT(AHSV8888_1X32),
};
#endif
```