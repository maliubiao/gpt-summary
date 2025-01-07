Response:
Let's break down the thought process for answering the user's request about the `pisp_common.h` file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of a specific header file within Android's Bionic library. The key is to interpret the C code and relate it to broader concepts, especially within the Android context. The request is multi-faceted, asking for:

* Functionality listing.
* Relationship to Android.
* Detailed explanation of libc functions (which is a bit of a misinterpretation, as this file *defines* structures and enums, not libc functions directly).
* Dynamic linker aspects (also a misinterpretation).
* Logical reasoning with input/output examples.
* Common usage errors.
* How the file is accessed from Android Framework/NDK.
* Frida hooking examples.

**2. Initial Analysis of the Header File:**

The first step is to carefully examine the contents of `pisp_common.h`. Key observations:

* **`#ifndef _UAPI_PISP_COMMON_H_` and `#define _UAPI_PISP_COMMON_H_`:** This is a standard include guard to prevent multiple inclusions.
* **Comment about auto-generation:** This suggests the file is likely generated from some other source, possibly hardware or kernel-level definitions. Changes shouldn't be made directly.
* **`#include <linux/types.h>`:** This is a standard Linux kernel header providing basic data types like `__u16`, `__u32`, `__s32`, `__u8`. This immediately signals that the file deals with low-level, kernel-related functionality.
* **`struct pisp_image_format_config`:** This structure defines the configuration for image formats, including width, height, format, and strides. The `__attribute__((packed))` indicates that the compiler should minimize padding, ensuring the structure's memory layout is predictable.
* **`enum pisp_bayer_order`:** Defines different orderings of Bayer patterns, common in image sensors.
* **`enum pisp_image_format`:** This is the most complex part. It defines various flags and bitmasks to specify image formats (bits per sample, planarity, sampling, compression, etc.). The naming convention (e.g., `PISP_IMAGE_FORMAT_BPS_8`, `PISP_IMAGE_FORMAT_PLANARITY_INTERLEAVED`) is quite descriptive.
* **Macros for checking flags:**  A series of `#define` macros like `PISP_IMAGE_FORMAT_BPS_8(fmt)` provide convenient ways to check if specific format properties are set.
* **Other structs:** `pisp_bla_config`, `pisp_wbg_config`, `pisp_compress_config`, `pisp_decompress_config`, `pisp_axi_config` seem to represent configurations for black level adjustment, white balance gain, compression/decompression, and AXI bus settings, respectively.
* **`enum pisp_axi_flags`:** Defines flags related to the AXI bus.
* **Location:** The file path (`bionic/libc/kernel/uapi/linux/media/raspberrypi/pisp_common.h`) is crucial. The `uapi` directory signifies "user-space API," meaning these definitions are intended for use by user-space programs. The "raspberrypi" part indicates it's specific to Raspberry Pi hardware.

**3. Addressing the User's Specific Questions:**

* **Functionality:** Based on the structures and enums, the core functionality revolves around defining and configuring image processing pipelines, specifically related to the Raspberry Pi's camera system (implied by "pisp").

* **Relationship to Android:**  Since it's within Bionic, it's part of Android's system libraries. It directly relates to the hardware abstraction layer (HAL) for camera functionality on Raspberry Pi devices running Android. Android's CameraService and related components would interact with kernel drivers that use these definitions.

* **libc functions:** The user's understanding is slightly off. This file *defines* types and constants, not implements libc functions. Therefore, explaining the *implementation* of libc functions isn't directly applicable. However, these definitions would be *used* by libc functions that interact with the kernel for camera operations (like `ioctl`).

* **Dynamic Linker:** Again, the file doesn't directly involve the dynamic linker. It's a header file. The dynamic linker comes into play when libraries containing code that *uses* these definitions are loaded. The SO layout would depend on the specific library. The linking process would resolve symbols related to the data types defined here.

* **Logical Reasoning:**  We can create examples showing how these definitions could be used to construct image format configurations.

* **Common Usage Errors:**  Misinterpreting the bitmasks, using incorrect values, or not understanding the implications of the different format options are potential errors.

* **Android Framework/NDK Access:**  The Android framework (CameraService) would interact with the camera HAL. The HAL implementation for Raspberry Pi would likely use these definitions. NDK developers working with low-level camera access might also use them. This involves binder calls, JNI, and the HAL.

* **Frida Hooking:**  Frida can be used to intercept calls to system functions or HAL interfaces where these definitions are used, allowing for inspection of the data being passed.

**4. Structuring the Answer:**

Organize the answer logically, addressing each part of the user's request. Use clear headings and examples.

* Start with a summary of the file's purpose.
* Explain the functionality of each structure and enum.
* Clearly articulate the connection to Android, providing concrete examples (Camera HAL).
* Address the misinterpretations about libc functions and the dynamic linker. Explain *how* they might indirectly relate.
* Provide clear logical reasoning examples with input and output.
* List common usage errors.
* Describe the path from the Android Framework/NDK to these definitions.
* Offer practical Frida hooking examples.

**5. Refinement and Language:**

Use clear and concise language. Since the user requested a Chinese response, ensure accurate translation of technical terms. Double-check the technical details and ensure they are accurate. The "auto-generated" comment is important to highlight.

By following this thought process, we can construct a comprehensive and accurate answer that addresses all aspects of the user's request, even when there are slight misunderstandings in the initial question. The key is to interpret the provided code within its context and connect it to the broader Android ecosystem.
这个头文件 `pisp_common.h` 定义了与 Raspberry Pi 图像信号处理 (PISP) 相关的常用数据结构、枚举和宏定义。由于它位于 `bionic/libc/kernel/uapi/linux/media/raspberrypi/` 路径下，属于 Android 的 Bionic 库，并且标记为 `uapi` (用户空间 API)，这意味着这些定义旨在被用户空间的程序使用，以便与 Linux 内核中 Raspberry Pi 的媒体子系统进行交互。

**它的功能：**

该头文件主要定义了用于配置和描述 Raspberry Pi 图像处理管道中使用的图像格式和相关参数的数据结构和枚举。具体来说，它涵盖了以下方面：

1. **图像格式配置 (`struct pisp_image_format_config`)：**
   - 定义了图像的宽度 (`width`)、高度 (`height`)、像素格式 (`format`)、行步长 (`stride`) 和第二行步长 (`stride2`)。这些参数对于描述图像缓冲区在内存中的布局至关重要。

2. **Bayer 顺序枚举 (`enum pisp_bayer_order`)：**
   - 定义了 Bayer 模式的各种排列方式，例如 RGGB、GBRG、BGGR 和 GRBG。这是相机传感器中常用的彩色滤镜阵列模式。还包括灰度 (`PISP_BAYER_ORDER_GREYSCALE`)。

3. **图像格式枚举 (`enum pisp_image_format`)：**
   - 定义了各种图像格式的标志位，可以通过位运算组合使用。这些标志位包括：
     - **位深度 (Bits Per Sample, BPS)：** 8位、10位、12位、16位 (`PISP_IMAGE_FORMAT_BPS_*`)。
     - **平面性 (Planarity)：** 交错 (Interleaved)、半平面 (Semi-Planar)、平面 (Planar) (`PISP_IMAGE_FORMAT_PLANARITY_*`)。
     - **采样 (Sampling)：** 4:4:4, 4:2:2, 4:2:0 (`PISP_IMAGE_FORMAT_SAMPLING_*`)。
     - **字节序 (Order)：** 正常 (Normal)、交换 (Swapped) (`PISP_IMAGE_FORMAT_ORDER_*`)。
     - **位移 (Shift)：** 用于指定某些位域的起始位置 (`PISP_IMAGE_FORMAT_SHIFT_*`)。
     - **每像素位数 (Bits Per Pixel, BPP)：** 32位 (`PISP_IMAGE_FORMAT_BPP_32`)。
     - **压缩 (Compression)：** 未压缩 (`PISP_IMAGE_FORMAT_UNCOMPRESSED`) 和不同的压缩模式 (`PISP_IMAGE_FORMAT_COMPRESSION_MODE_*`)。
     - **其他特性：**  HOG 描述符的符号性 (`PISP_IMAGE_FORMAT_HOG_*`)、积分图 (`PISP_IMAGE_FORMAT_INTEGRAL_IMAGE`)、壁纸滚动 (`PISP_IMAGE_FORMAT_WALLPAPER_ROLL`)、三通道 (`PISP_IMAGE_FORMAT_THREE_CHANNEL`)。
   - 还定义了一些组合的格式，例如单通道 16 位 (`PISP_IMAGE_FORMAT_SINGLE_16`) 和三通道 16 位 (`PISP_IMAGE_FORMAT_THREE_16`)。

4. **图像格式检查宏：**
   - 提供了一系列宏，用于方便地检查给定的图像格式是否具有特定的属性，例如位深度、通道数、压缩状态、采样方式、平面性等。

5. **黑电平配置 (`struct pisp_bla_config`)：**
   - 定义了红、绿(Gr, Gb)、蓝通道的黑电平值，以及输出黑电平值。黑电平是传感器读取到的最小信号值，需要进行校正。

6. **白平衡增益配置 (`struct pisp_wbg_config`)：**
   - 定义了红、绿、蓝通道的增益值，用于进行白平衡调整，使图像颜色更自然。

7. **压缩/解压缩配置 (`struct pisp_compress_config`, `struct pisp_decompress_config`)：**
   - 定义了压缩和解压缩相关的配置参数，例如偏移量和模式。

8. **AXI 总线配置 (`struct pisp_axi_config`) 和标志位 (`enum pisp_axi_flags`)：**
   - 定义了与 AXI (Advanced eXtensible Interface) 总线相关的配置，例如最大长度标志、缓存协议和 QoS (服务质量)。这些参数影响数据在硬件模块之间的传输。

**与 Android 功能的关系举例：**

该头文件直接关系到 Android 在 Raspberry Pi 设备上的摄像头功能。

* **Camera HAL (Hardware Abstraction Layer)：** Android 的 Camera HAL 是连接 Android 框架和底层硬件的桥梁。Raspberry Pi 的 Camera HAL 实现会使用这些定义来配置和控制 PISP 硬件。例如，当 Android 应用请求捕获特定格式的图像时，Camera HAL 会使用 `pisp_image_format_config` 结构体来设置 PISP 模块的输入和输出图像格式。
* **Media Framework：** Android 的 Media Framework (包括 `MediaCodec`, `MediaRecorder` 等) 处理音视频的编码、解码和录制。当使用 Raspberry Pi 的摄像头作为输入源时，Media Framework 会与 Camera HAL 交互，而 Camera HAL 又会使用这里的定义来控制图像数据的处理流程。
* **NDK (Native Development Kit)：** 使用 NDK 进行原生开发的开发者，如果需要直接访问 Raspberry Pi 的摄像头硬件，可能会通过底层的 Linux API (例如 `ioctl`) 与 PISP 驱动交互，这时就需要使用这些头文件中定义的结构体和枚举。

**libc 函数的功能实现：**

这个头文件本身并没有实现任何 libc 函数。它只是定义了一些数据结构和常量，这些定义会被其他的 C/C++ 代码使用，包括 libc 库中的一些与设备驱动交互的函数，例如：

* **`ioctl()`：**  `ioctl` 是一个通用的设备控制系统调用。Android 的 Camera HAL 或其他与 PISP 交互的库可能会使用 `ioctl` 系统调用，并将指向这些结构体的指针传递给内核驱动，以配置 PISP 硬件或获取其状态。例如，可以使用 `ioctl` 命令和一个指向 `pisp_image_format_config` 结构体的指针来设置 PISP 模块的图像格式。

**dynamic linker 的功能：**

这个头文件本身不涉及 dynamic linker 的功能。Dynamic linker 主要负责在程序启动时加载和链接动态链接库 (SO 文件)。

如果某个使用了这些定义的库 (例如 Raspberry Pi 的 Camera HAL 实现) 是一个动态链接库，那么 dynamic linker 会负责加载它。

**SO 布局样本：**

假设一个名为 `camera.rpi.so` 的动态链接库实现了 Raspberry Pi 的 Camera HAL，它可能会使用 `pisp_common.h` 中定义的结构体。其布局可能如下：

```
camera.rpi.so:
  .text         # 代码段
    - HAL 函数实现 (例如 openCamera, configureStreams, capture)
    - 调用内核驱动的 ioctl 代码
  .rodata       # 只读数据段
    - 字符串常量
    - 预定义的 PISP 配置信息
  .data         # 可读写数据段
    - 全局变量
    - 缓存的 PISP 配置
  .bss          # 未初始化数据段
    - 未初始化的全局变量
  .symtab       # 符号表
    - 导出和导入的符号 (例如 HAL 接口函数)
    - 内部使用的函数和变量
  .dynsym       # 动态符号表
    - 导出的动态符号
  .rel.dyn      # 动态重定位表
    - 需要在加载时进行重定位的符号引用
  .rel.plt      # PLT 重定位表
    - 用于延迟绑定的函数调用重定位
  ...           # 其他段
```

**链接的处理过程：**

1. 当 Android 系统启动或应用程序需要使用摄像头时，可能会加载 `camera.rpi.so` 库。
2. Dynamic linker (例如 `linker64` 或 `linker`) 会读取 `camera.rpi.so` 的头部信息，包括 `.dynamic` 段，其中包含了加载和链接所需的信息。
3. Dynamic linker 会将 `camera.rpi.so` 加载到内存中的合适地址空间。
4. Dynamic linker 会根据 `.rel.dyn` 和 `.rel.plt` 段中的信息，解析库中对其他共享库或系统函数的引用，并进行重定位，即将这些引用指向正确的内存地址。
5. 如果 `camera.rpi.so` 依赖于其他共享库 (例如 libc 或其他 HAL 库)，dynamic linker 也会加载这些依赖库并进行链接。

在这个过程中，`pisp_common.h` 中定义的结构体和枚举本身不会直接参与链接过程。但是，`camera.rpi.so` 中的代码会使用这些定义来声明变量和函数参数，编译器会将这些信息编码到符号表中。当其他代码需要与 `camera.rpi.so` 交互时，它们需要知道这些数据结构的布局，而 `pisp_common.h` 就提供了这些信息。

**逻辑推理和假设输入输出：**

假设我们想要配置 PISP 以捕获 1920x1080 的 RGGB Bayer 格式图像，每个像素 8 位。

**假设输入：**

```c
struct pisp_image_format_config config;
config.width = 1920;
config.height = 1080;
config.format = PISP_IMAGE_FORMAT_BPS_8 | PISP_IMAGE_FORMAT_PLANARITY_INTERLEAVED;
// 假设 stride 可以通过其他方式计算或已知
config.stride = 1920;
config.stride2 = 0; // 对于交错格式，stride2 通常为 0
```

**逻辑推理：**

我们可以使用宏来检查配置是否正确：

```c
bool is_bps_8 = PISP_IMAGE_FORMAT_BPS_8(config.format); // true
bool is_interleaved = PISP_IMAGE_FORMAT_INTERLEAVED(config.format); // true
```

**假设输出 (传递给内核驱动的 `ioctl` 调用)：**

内核驱动会接收到指向 `config` 结构体的指针，并从中读取宽度、高度和格式信息，然后配置 PISP 硬件以捕获指定格式的图像。

**用户或编程常见的使用错误：**

1. **位运算错误：**  在组合 `pisp_image_format` 的标志位时，使用错误的位运算符或混淆不同的标志位。例如，错误地使用 `&` 代替 `|` 来组合标志位。

   ```c
   // 错误示例：应该使用 | 来组合标志位
   uint32_t wrong_format = PISP_IMAGE_FORMAT_BPS_8 & PISP_IMAGE_FORMAT_PLANARITY_INTERLEAVED;
   ```

2. **结构体成员赋值错误：**  错误地设置 `pisp_image_format_config` 结构体的成员，例如宽度、高度或步长不匹配实际的图像尺寸或内存布局。

   ```c
   struct pisp_image_format_config config;
   config.width = 1080; // 错误：宽度和高度反了
   config.height = 1920;
   // ...
   ```

3. **不理解不同图像格式的含义：**  不理解交错、半平面和平面格式的区别，或者 4:4:4、4:2:2 和 4:2:0 采样的含义，导致配置的格式与预期不符。

4. **忘记考虑字节序：**  在某些情况下，图像数据的字节序可能需要考虑，如果配置了错误的字节序 (`PISP_IMAGE_FORMAT_ORDER_SWAPPED`)，会导致图像显示异常。

5. **与硬件能力不符的配置：**  配置了 PISP 硬件不支持的图像格式或参数，导致驱动程序返回错误或硬件工作异常。

**Android Framework 或 NDK 如何到达这里：**

1. **Android 应用 (Java/Kotlin)：** 应用程序使用 Android 的 `Camera2` API 或旧的 `Camera` API 来请求捕获图像。

2. **Camera Service (System Server)：**  Android Framework 中的 `CameraService` 接收到应用程序的请求。

3. **Camera HAL (C++)：** `CameraService` 通过 Binder IPC 调用相应的 Camera HAL 模块的接口函数 (例如 `configureStreams`, `processCaptureRequest`)。Raspberry Pi 的 Camera HAL 实现会处理这些调用。

4. **HAL 实现 (可能使用 `libcamera` 或自定义驱动接口)：**  HAL 实现可能会使用 `libcamera` 库，或者直接与底层的 PISP 驱动交互。如果直接交互，它会使用 `pisp_common.h` 中定义的结构体来配置驱动。

5. **内核驱动 (Linux Kernel)：**  HAL 实现最终会通过系统调用 (通常是 `ioctl`) 将配置信息传递给 Raspberry Pi 的 PISP 驱动。驱动程序会解析这些结构体，并配置硬件。

**Frida Hook 示例调试步骤：**

假设我们想 hook Camera HAL 中配置图像流的函数，以查看传递给 PISP 驱动的 `pisp_image_format_config` 结构体的内容。

```python
import frida
import sys

# 目标进程，例如 CameraService
process_name = "system_server"

# 要 hook 的函数，假设 Camera HAL 库名为 camera.rpi.so
# 需要找到 configureStreams 或类似的函数，并确定其参数中包含图像格式配置
hook_config_stream_address = 0xXXXXXXXX # 替换为实际函数地址

session = frida.attach(process_name)

script = session.create_script("""
Interceptor.attach(ptr("%s"), {
    onEnter: function(args) {
        console.log("configureStreams called!");
        // 假设图像格式配置结构体是第三个参数 (需要根据实际情况调整)
        var configPtr = ptr(args[2]);
        console.log("pisp_image_format_config address:", configPtr);

        // 读取结构体成员 (需要根据结构体定义调整偏移)
        var width = configPtr.readU16();
        var height = configPtr.add(2).readU16();
        var format = configPtr.add(4).readU32();
        console.log("width:", width);
        console.log("height:", height);
        console.log("format:", format.toString(16));
        // 可以进一步解析 format 的各个标志位
    },
    onLeave: function(retval) {
        console.log("configureStreams returned:", retval);
    }
});
""" % hook_config_stream_address)

script.load()
sys.stdin.read()
```

**步骤说明：**

1. **找到目标进程：** 确定运行 Camera HAL 的进程名称，通常是 `system_server`。
2. **定位要 hook 的函数：**  需要找到 Camera HAL 库 (`camera.rpi.so`) 中负责配置图像流的函数，并确定其内存地址。可以使用 `adb shell` 和 `grep` 命令来查找库文件路径，然后使用 `readelf -s` 或 `nm` 工具查看符号表。
3. **编写 Frida 脚本：**
   - 使用 `frida.attach()` 连接到目标进程。
   - 使用 `Interceptor.attach()` hook 目标函数。
   - 在 `onEnter` 回调函数中：
     - 打印函数被调用的信息。
     - 获取包含 `pisp_image_format_config` 结构体的参数指针 (需要根据函数签名确定参数位置)。
     - 使用 `readU16()`, `readU32()` 等方法读取结构体成员的值。
     - 打印读取到的配置信息。
   - 在 `onLeave` 回调函数中打印返回值。
4. **运行 Frida 脚本：**  执行 Python 脚本，然后触发 Android 设备上的摄像头操作，Frida 就会拦截到目标函数调用并输出相关信息。

这个 Frida 示例需要根据实际的 Camera HAL 实现和函数签名进行调整，找到正确的函数地址和参数位置是关键。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/media/raspberrypi/pisp_common.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_PISP_COMMON_H_
#define _UAPI_PISP_COMMON_H_
#include <linux/types.h>
struct pisp_image_format_config {
  __u16 width;
  __u16 height;
  __u32 format;
  __s32 stride;
  __s32 stride2;
} __attribute__((packed));
enum pisp_bayer_order {
  PISP_BAYER_ORDER_RGGB = 0,
  PISP_BAYER_ORDER_GBRG = 1,
  PISP_BAYER_ORDER_BGGR = 2,
  PISP_BAYER_ORDER_GRBG = 3,
  PISP_BAYER_ORDER_GREYSCALE = 128
};
enum pisp_image_format {
  PISP_IMAGE_FORMAT_BPS_8 = 0x00000000,
  PISP_IMAGE_FORMAT_BPS_10 = 0x00000001,
  PISP_IMAGE_FORMAT_BPS_12 = 0x00000002,
  PISP_IMAGE_FORMAT_BPS_16 = 0x00000003,
  PISP_IMAGE_FORMAT_BPS_MASK = 0x00000003,
  PISP_IMAGE_FORMAT_PLANARITY_INTERLEAVED = 0x00000000,
  PISP_IMAGE_FORMAT_PLANARITY_SEMI_PLANAR = 0x00000010,
  PISP_IMAGE_FORMAT_PLANARITY_PLANAR = 0x00000020,
  PISP_IMAGE_FORMAT_PLANARITY_MASK = 0x00000030,
  PISP_IMAGE_FORMAT_SAMPLING_444 = 0x00000000,
  PISP_IMAGE_FORMAT_SAMPLING_422 = 0x00000100,
  PISP_IMAGE_FORMAT_SAMPLING_420 = 0x00000200,
  PISP_IMAGE_FORMAT_SAMPLING_MASK = 0x00000300,
  PISP_IMAGE_FORMAT_ORDER_NORMAL = 0x00000000,
  PISP_IMAGE_FORMAT_ORDER_SWAPPED = 0x00001000,
  PISP_IMAGE_FORMAT_SHIFT_0 = 0x00000000,
  PISP_IMAGE_FORMAT_SHIFT_1 = 0x00010000,
  PISP_IMAGE_FORMAT_SHIFT_2 = 0x00020000,
  PISP_IMAGE_FORMAT_SHIFT_3 = 0x00030000,
  PISP_IMAGE_FORMAT_SHIFT_4 = 0x00040000,
  PISP_IMAGE_FORMAT_SHIFT_5 = 0x00050000,
  PISP_IMAGE_FORMAT_SHIFT_6 = 0x00060000,
  PISP_IMAGE_FORMAT_SHIFT_7 = 0x00070000,
  PISP_IMAGE_FORMAT_SHIFT_8 = 0x00080000,
  PISP_IMAGE_FORMAT_SHIFT_MASK = 0x000f0000,
  PISP_IMAGE_FORMAT_BPP_32 = 0x00100000,
  PISP_IMAGE_FORMAT_UNCOMPRESSED = 0x00000000,
  PISP_IMAGE_FORMAT_COMPRESSION_MODE_1 = 0x01000000,
  PISP_IMAGE_FORMAT_COMPRESSION_MODE_2 = 0x02000000,
  PISP_IMAGE_FORMAT_COMPRESSION_MODE_3 = 0x03000000,
  PISP_IMAGE_FORMAT_COMPRESSION_MASK = 0x03000000,
  PISP_IMAGE_FORMAT_HOG_SIGNED = 0x04000000,
  PISP_IMAGE_FORMAT_HOG_UNSIGNED = 0x08000000,
  PISP_IMAGE_FORMAT_INTEGRAL_IMAGE = 0x10000000,
  PISP_IMAGE_FORMAT_WALLPAPER_ROLL = 0x20000000,
  PISP_IMAGE_FORMAT_THREE_CHANNEL = 0x40000000,
  PISP_IMAGE_FORMAT_SINGLE_16 = PISP_IMAGE_FORMAT_BPS_16,
  PISP_IMAGE_FORMAT_THREE_16 = PISP_IMAGE_FORMAT_BPS_16 | PISP_IMAGE_FORMAT_THREE_CHANNEL
};
#define PISP_IMAGE_FORMAT_BPS_8(fmt) (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_8)
#define PISP_IMAGE_FORMAT_BPS_10(fmt) (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_10)
#define PISP_IMAGE_FORMAT_BPS_12(fmt) (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_12)
#define PISP_IMAGE_FORMAT_BPS_16(fmt) (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_16)
#define PISP_IMAGE_FORMAT_BPS(fmt) (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) ? 8 + (2 << (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) - 1)) : 8)
#define PISP_IMAGE_FORMAT_SHIFT(fmt) (((fmt) & PISP_IMAGE_FORMAT_SHIFT_MASK) / PISP_IMAGE_FORMAT_SHIFT_1)
#define PISP_IMAGE_FORMAT_THREE_CHANNEL(fmt) ((fmt) & PISP_IMAGE_FORMAT_THREE_CHANNEL)
#define PISP_IMAGE_FORMAT_SINGLE_CHANNEL(fmt) (! ((fmt) & PISP_IMAGE_FORMAT_THREE_CHANNEL))
#define PISP_IMAGE_FORMAT_COMPRESSED(fmt) (((fmt) & PISP_IMAGE_FORMAT_COMPRESSION_MASK) != PISP_IMAGE_FORMAT_UNCOMPRESSED)
#define PISP_IMAGE_FORMAT_SAMPLING_444(fmt) (((fmt) & PISP_IMAGE_FORMAT_SAMPLING_MASK) == PISP_IMAGE_FORMAT_SAMPLING_444)
#define PISP_IMAGE_FORMAT_SAMPLING_422(fmt) (((fmt) & PISP_IMAGE_FORMAT_SAMPLING_MASK) == PISP_IMAGE_FORMAT_SAMPLING_422)
#define PISP_IMAGE_FORMAT_SAMPLING_420(fmt) (((fmt) & PISP_IMAGE_FORMAT_SAMPLING_MASK) == PISP_IMAGE_FORMAT_SAMPLING_420)
#define PISP_IMAGE_FORMAT_ORDER_NORMAL(fmt) (! ((fmt) & PISP_IMAGE_FORMAT_ORDER_SWAPPED))
#define PISP_IMAGE_FORMAT_ORDER_SWAPPED(fmt) ((fmt) & PISP_IMAGE_FORMAT_ORDER_SWAPPED)
#define PISP_IMAGE_FORMAT_INTERLEAVED(fmt) (((fmt) & PISP_IMAGE_FORMAT_PLANARITY_MASK) == PISP_IMAGE_FORMAT_PLANARITY_INTERLEAVED)
#define PISP_IMAGE_FORMAT_SEMIPLANAR(fmt) (((fmt) & PISP_IMAGE_FORMAT_PLANARITY_MASK) == PISP_IMAGE_FORMAT_PLANARITY_SEMI_PLANAR)
#define PISP_IMAGE_FORMAT_PLANAR(fmt) (((fmt) & PISP_IMAGE_FORMAT_PLANARITY_MASK) == PISP_IMAGE_FORMAT_PLANARITY_PLANAR)
#define PISP_IMAGE_FORMAT_WALLPAPER(fmt) ((fmt) & PISP_IMAGE_FORMAT_WALLPAPER_ROLL)
#define PISP_IMAGE_FORMAT_BPP_32(fmt) ((fmt) & PISP_IMAGE_FORMAT_BPP_32)
#define PISP_IMAGE_FORMAT_HOG(fmt) ((fmt) & (PISP_IMAGE_FORMAT_HOG_SIGNED | PISP_IMAGE_FORMAT_HOG_UNSIGNED))
#define PISP_WALLPAPER_WIDTH 128
struct pisp_bla_config {
  __u16 black_level_r;
  __u16 black_level_gr;
  __u16 black_level_gb;
  __u16 black_level_b;
  __u16 output_black_level;
  __u8 pad[2];
} __attribute__((packed));
struct pisp_wbg_config {
  __u16 gain_r;
  __u16 gain_g;
  __u16 gain_b;
  __u8 pad[2];
} __attribute__((packed));
struct pisp_compress_config {
  __u16 offset;
  __u8 pad;
  __u8 mode;
} __attribute__((packed));
struct pisp_decompress_config {
  __u16 offset;
  __u8 pad;
  __u8 mode;
} __attribute__((packed));
enum pisp_axi_flags {
  PISP_AXI_FLAG_ALIGN = 128,
  PISP_AXI_FLAG_PAD = 64,
  PISP_AXI_FLAG_PANIC = 32,
};
struct pisp_axi_config {
  __u8 maxlen_flags;
  __u8 cache_prot;
  __u16 qos;
} __attribute__((packed));
#endif

"""

```