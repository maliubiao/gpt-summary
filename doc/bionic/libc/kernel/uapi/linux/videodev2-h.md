Response:
The user wants to understand the functionality of the `videodev2.h` header file within the Android Bionic library. The request is broken down into several parts, and this is part 1, focusing on summarization.

Here's a breakdown of the thought process to achieve the summary:

1. **Identify the core purpose of the file:** The filename `videodev2.h` and the inclusion of `<linux/videodev2.h>` strongly suggest this file defines the user-space API for interacting with video devices in Linux. The "uapi" in the path further confirms this, indicating it's the userspace facing part of the kernel API.

2. **Recognize the "auto-generated" note:** This is a crucial piece of information. It means the file's content is derived from the kernel headers and likely adapted for the Android environment. Therefore, the core functionality is inherited from the Linux V4L2 API.

3. **Scan for key elements:** Quickly go through the file, looking for recurring patterns and significant definitions. Keywords like `enum`, `struct`, `#define`, and function-like macros are important.

4. **Categorize the definitions:**  Group the identified elements into logical categories. The most prominent categories are:
    * **Basic Types and Definitions:**  Things like `VIDEO_MAX_FRAME`, `VIDEO_MAX_PLANES`, and the `v4l2_fourcc` macro.
    * **Enumerated Types (`enum v4l2_*`):** These define the possible values for various settings and states related to video devices (e.g., field order, buffer types, colorspaces).
    * **Structures (`struct v4l2_*`):** These define data structures used to exchange information with the kernel driver (e.g., image formats, buffer descriptions, capabilities).
    * **Capability Flags (`V4L2_CAP_*`):** These represent the features supported by a specific video device.
    * **Pixel Format Codes (`V4L2_PIX_FMT_*`):**  These define standard codes for different image and video encoding formats.
    * **IO Control Macros (`_IOR`, `_IOW`, `_IOWR` - although not explicitly present in *this* part, the includes hint at their use later):**  These are used to define the interface for interacting with the device driver via `ioctl` system calls.

5. **Infer the overall functionality from the categories:** Based on the categories, it becomes clear that this header file provides the necessary definitions for applications to:
    * **Discover video devices and their capabilities.**
    * **Configure video capture and output parameters** (resolution, pixel format, frame rates, etc.).
    * **Manage buffers for video data.**
    * **Control various aspects of video processing** (color space, transfer functions, etc.).
    * **Handle different video standards and formats.**

6. **Connect to Android:**  Since this is part of Android's Bionic library, its purpose is to enable Android applications (both framework and NDK) to interact with the underlying video hardware. This is essential for camera functionality, video playback, and other multimedia tasks.

7. **Formulate the summary:** Combine the identified purpose, key elements, and their categories into a concise summary. Emphasize that this is a user-space API for controlling video devices and that it's largely based on the Linux V4L2 standard.

8. **Review and refine:** Ensure the summary accurately reflects the content of the provided code snippet and addresses the prompt.

By following these steps, we arrive at the summary provided in the example answer, highlighting the key aspects of the `videodev2.h` file's functionality within the Android context.
好的，这是对提供的 `bionic/libc/kernel/uapi/linux/videodev2.handroid bionic` 源代码文件（第一部分）的功能归纳：

**功能归纳:**

这个头文件 `videodev2.h` 是 Android Bionic 库的一部分，它定义了用户空间程序与 Linux 视频设备进行交互的接口。更具体地说，它定义了 V4L2 (Video for Linux version 2) API 的数据结构、枚举类型和宏定义，这些是用户空间应用程序用来控制和访问视频设备（如摄像头）的关键要素。

主要功能可以概括为以下几点：

1. **定义了与视频设备交互的数据结构:**  例如 `v4l2_rect` (矩形区域), `v4l2_fract` (分数), `v4l2_pix_format` (像素格式), `v4l2_buffer` (视频缓冲区) 等。这些结构体用于描述视频的属性、缓冲区信息以及设备的状态。

2. **定义了枚举类型，用于表示视频设备的各种属性和状态:** 例如 `v4l2_field` (场序), `v4l2_buf_type` (缓冲区类型，如捕获或输出), `v4l2_memory` (内存类型), `v4l2_colorspace` (色彩空间) 等。这些枚举为开发者提供了预定义的常量，用于设置和查询视频设备的各种参数。

3. **定义了宏，方便进行常用操作和检查:** 例如 `v4l2_fourcc` 用于生成像素格式的四字符码,  `V4L2_FIELD_HAS_TOP` 等宏用于检查场序的属性。

4. **定义了视频设备能力相关的常量:** 例如 `V4L2_CAP_VIDEO_CAPTURE`, `V4L2_CAP_VIDEO_OUTPUT` 等，用于表示设备支持的功能，例如视频捕获、视频输出等。

5. **定义了大量的像素格式常量:** 例如 `V4L2_PIX_FMT_RGB332`, `V4L2_PIX_FMT_YUYV` 等，涵盖了各种常见的 RGB 和 YUV 像素格式。

**与 Android 功能的关系:**

这个头文件是 Android 框架和 NDK 中访问摄像头、视频编解码器等硬件组件的基础。

* **摄像头 (Camera):** Android 的 CameraService 和 Camera HAL (Hardware Abstraction Layer)  会使用这些定义来配置摄像头参数，例如捕获分辨率、像素格式、帧率等。
* **视频编解码 (Video Codec):**  Android 的 MediaCodec API  底层可能也会涉及到这些定义，用于配置视频编码和解码器的输入输出格式。
* **图形显示 (Graphics Display):** 某些视频输出可能也会用到这里的定义来描述帧缓冲区的格式。

**总结来说，`videodev2.h` 在 Android 中扮演着桥梁的角色，连接了用户空间的应用程序（包括 framework 和 NDK 应用）和底层的 Linux 视频驱动，使得上层能够以标准化的方式控制和使用视频硬件。**

接下来在第二部分，我们会更深入地探讨每个 libc 函数的实现，动态链接器的处理，以及如何在 Android 中使用这些定义。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/videodev2.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI__LINUX_VIDEODEV2_H
#define _UAPI__LINUX_VIDEODEV2_H
#include <sys/time.h>
#include <linux/compiler.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/v4l2-common.h>
#include <linux/v4l2-controls.h>
#define VIDEO_MAX_FRAME 64
#define VIDEO_MAX_PLANES 8
#define v4l2_fourcc(a,b,c,d) ((__u32) (a) | ((__u32) (b) << 8) | ((__u32) (c) << 16) | ((__u32) (d) << 24))
#define v4l2_fourcc_be(a,b,c,d) (v4l2_fourcc(a, b, c, d) | (1U << 31))
enum v4l2_field {
  V4L2_FIELD_ANY = 0,
  V4L2_FIELD_NONE = 1,
  V4L2_FIELD_TOP = 2,
  V4L2_FIELD_BOTTOM = 3,
  V4L2_FIELD_INTERLACED = 4,
  V4L2_FIELD_SEQ_TB = 5,
  V4L2_FIELD_SEQ_BT = 6,
  V4L2_FIELD_ALTERNATE = 7,
  V4L2_FIELD_INTERLACED_TB = 8,
  V4L2_FIELD_INTERLACED_BT = 9,
};
#define V4L2_FIELD_HAS_TOP(field) ((field) == V4L2_FIELD_TOP || (field) == V4L2_FIELD_INTERLACED || (field) == V4L2_FIELD_INTERLACED_TB || (field) == V4L2_FIELD_INTERLACED_BT || (field) == V4L2_FIELD_SEQ_TB || (field) == V4L2_FIELD_SEQ_BT)
#define V4L2_FIELD_HAS_BOTTOM(field) ((field) == V4L2_FIELD_BOTTOM || (field) == V4L2_FIELD_INTERLACED || (field) == V4L2_FIELD_INTERLACED_TB || (field) == V4L2_FIELD_INTERLACED_BT || (field) == V4L2_FIELD_SEQ_TB || (field) == V4L2_FIELD_SEQ_BT)
#define V4L2_FIELD_HAS_BOTH(field) ((field) == V4L2_FIELD_INTERLACED || (field) == V4L2_FIELD_INTERLACED_TB || (field) == V4L2_FIELD_INTERLACED_BT || (field) == V4L2_FIELD_SEQ_TB || (field) == V4L2_FIELD_SEQ_BT)
#define V4L2_FIELD_HAS_T_OR_B(field) ((field) == V4L2_FIELD_BOTTOM || (field) == V4L2_FIELD_TOP || (field) == V4L2_FIELD_ALTERNATE)
#define V4L2_FIELD_IS_INTERLACED(field) ((field) == V4L2_FIELD_INTERLACED || (field) == V4L2_FIELD_INTERLACED_TB || (field) == V4L2_FIELD_INTERLACED_BT)
#define V4L2_FIELD_IS_SEQUENTIAL(field) ((field) == V4L2_FIELD_SEQ_TB || (field) == V4L2_FIELD_SEQ_BT)
enum v4l2_buf_type {
  V4L2_BUF_TYPE_VIDEO_CAPTURE = 1,
  V4L2_BUF_TYPE_VIDEO_OUTPUT = 2,
  V4L2_BUF_TYPE_VIDEO_OVERLAY = 3,
  V4L2_BUF_TYPE_VBI_CAPTURE = 4,
  V4L2_BUF_TYPE_VBI_OUTPUT = 5,
  V4L2_BUF_TYPE_SLICED_VBI_CAPTURE = 6,
  V4L2_BUF_TYPE_SLICED_VBI_OUTPUT = 7,
  V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY = 8,
  V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE = 9,
  V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE = 10,
  V4L2_BUF_TYPE_SDR_CAPTURE = 11,
  V4L2_BUF_TYPE_SDR_OUTPUT = 12,
  V4L2_BUF_TYPE_META_CAPTURE = 13,
  V4L2_BUF_TYPE_META_OUTPUT = 14,
  V4L2_BUF_TYPE_PRIVATE = 0x80,
};
#define V4L2_TYPE_IS_MULTIPLANAR(type) ((type) == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE || (type) == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE)
#define V4L2_TYPE_IS_OUTPUT(type) ((type) == V4L2_BUF_TYPE_VIDEO_OUTPUT || (type) == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE || (type) == V4L2_BUF_TYPE_VIDEO_OVERLAY || (type) == V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY || (type) == V4L2_BUF_TYPE_VBI_OUTPUT || (type) == V4L2_BUF_TYPE_SLICED_VBI_OUTPUT || (type) == V4L2_BUF_TYPE_SDR_OUTPUT || (type) == V4L2_BUF_TYPE_META_OUTPUT)
#define V4L2_TYPE_IS_CAPTURE(type) (! V4L2_TYPE_IS_OUTPUT(type))
enum v4l2_tuner_type {
  V4L2_TUNER_RADIO = 1,
  V4L2_TUNER_ANALOG_TV = 2,
  V4L2_TUNER_DIGITAL_TV = 3,
  V4L2_TUNER_SDR = 4,
  V4L2_TUNER_RF = 5,
};
#define V4L2_TUNER_ADC V4L2_TUNER_SDR
enum v4l2_memory {
  V4L2_MEMORY_MMAP = 1,
  V4L2_MEMORY_USERPTR = 2,
  V4L2_MEMORY_OVERLAY = 3,
  V4L2_MEMORY_DMABUF = 4,
};
enum v4l2_colorspace {
  V4L2_COLORSPACE_DEFAULT = 0,
  V4L2_COLORSPACE_SMPTE170M = 1,
  V4L2_COLORSPACE_SMPTE240M = 2,
  V4L2_COLORSPACE_REC709 = 3,
  V4L2_COLORSPACE_BT878 = 4,
  V4L2_COLORSPACE_470_SYSTEM_M = 5,
  V4L2_COLORSPACE_470_SYSTEM_BG = 6,
  V4L2_COLORSPACE_JPEG = 7,
  V4L2_COLORSPACE_SRGB = 8,
  V4L2_COLORSPACE_OPRGB = 9,
  V4L2_COLORSPACE_BT2020 = 10,
  V4L2_COLORSPACE_RAW = 11,
  V4L2_COLORSPACE_DCI_P3 = 12,
};
#define V4L2_MAP_COLORSPACE_DEFAULT(is_sdtv,is_hdtv) ((is_sdtv) ? V4L2_COLORSPACE_SMPTE170M : ((is_hdtv) ? V4L2_COLORSPACE_REC709 : V4L2_COLORSPACE_SRGB))
enum v4l2_xfer_func {
  V4L2_XFER_FUNC_DEFAULT = 0,
  V4L2_XFER_FUNC_709 = 1,
  V4L2_XFER_FUNC_SRGB = 2,
  V4L2_XFER_FUNC_OPRGB = 3,
  V4L2_XFER_FUNC_SMPTE240M = 4,
  V4L2_XFER_FUNC_NONE = 5,
  V4L2_XFER_FUNC_DCI_P3 = 6,
  V4L2_XFER_FUNC_SMPTE2084 = 7,
};
#define V4L2_MAP_XFER_FUNC_DEFAULT(colsp) ((colsp) == V4L2_COLORSPACE_OPRGB ? V4L2_XFER_FUNC_OPRGB : ((colsp) == V4L2_COLORSPACE_SMPTE240M ? V4L2_XFER_FUNC_SMPTE240M : ((colsp) == V4L2_COLORSPACE_DCI_P3 ? V4L2_XFER_FUNC_DCI_P3 : ((colsp) == V4L2_COLORSPACE_RAW ? V4L2_XFER_FUNC_NONE : ((colsp) == V4L2_COLORSPACE_SRGB || (colsp) == V4L2_COLORSPACE_JPEG ? V4L2_XFER_FUNC_SRGB : V4L2_XFER_FUNC_709)))))
enum v4l2_ycbcr_encoding {
  V4L2_YCBCR_ENC_DEFAULT = 0,
  V4L2_YCBCR_ENC_601 = 1,
  V4L2_YCBCR_ENC_709 = 2,
  V4L2_YCBCR_ENC_XV601 = 3,
  V4L2_YCBCR_ENC_XV709 = 4,
  V4L2_YCBCR_ENC_SYCC = 5,
  V4L2_YCBCR_ENC_BT2020 = 6,
  V4L2_YCBCR_ENC_BT2020_CONST_LUM = 7,
  V4L2_YCBCR_ENC_SMPTE240M = 8,
};
enum v4l2_hsv_encoding {
  V4L2_HSV_ENC_180 = 128,
  V4L2_HSV_ENC_256 = 129,
};
#define V4L2_MAP_YCBCR_ENC_DEFAULT(colsp) (((colsp) == V4L2_COLORSPACE_REC709 || (colsp) == V4L2_COLORSPACE_DCI_P3) ? V4L2_YCBCR_ENC_709 : ((colsp) == V4L2_COLORSPACE_BT2020 ? V4L2_YCBCR_ENC_BT2020 : ((colsp) == V4L2_COLORSPACE_SMPTE240M ? V4L2_YCBCR_ENC_SMPTE240M : V4L2_YCBCR_ENC_601)))
enum v4l2_quantization {
  V4L2_QUANTIZATION_DEFAULT = 0,
  V4L2_QUANTIZATION_FULL_RANGE = 1,
  V4L2_QUANTIZATION_LIM_RANGE = 2,
};
#define V4L2_MAP_QUANTIZATION_DEFAULT(is_rgb_or_hsv,colsp,ycbcr_enc) (((is_rgb_or_hsv) || (colsp) == V4L2_COLORSPACE_JPEG) ? V4L2_QUANTIZATION_FULL_RANGE : V4L2_QUANTIZATION_LIM_RANGE)
#define V4L2_COLORSPACE_ADOBERGB V4L2_COLORSPACE_OPRGB
#define V4L2_XFER_FUNC_ADOBERGB V4L2_XFER_FUNC_OPRGB
enum v4l2_priority {
  V4L2_PRIORITY_UNSET = 0,
  V4L2_PRIORITY_BACKGROUND = 1,
  V4L2_PRIORITY_INTERACTIVE = 2,
  V4L2_PRIORITY_RECORD = 3,
  V4L2_PRIORITY_DEFAULT = V4L2_PRIORITY_INTERACTIVE,
};
struct v4l2_rect {
  __s32 left;
  __s32 top;
  __u32 width;
  __u32 height;
};
struct v4l2_fract {
  __u32 numerator;
  __u32 denominator;
};
struct v4l2_area {
  __u32 width;
  __u32 height;
};
struct v4l2_capability {
  __u8 driver[16];
  __u8 card[32];
  __u8 bus_info[32];
  __u32 version;
  __u32 capabilities;
  __u32 device_caps;
  __u32 reserved[3];
};
#define V4L2_CAP_VIDEO_CAPTURE 0x00000001
#define V4L2_CAP_VIDEO_OUTPUT 0x00000002
#define V4L2_CAP_VIDEO_OVERLAY 0x00000004
#define V4L2_CAP_VBI_CAPTURE 0x00000010
#define V4L2_CAP_VBI_OUTPUT 0x00000020
#define V4L2_CAP_SLICED_VBI_CAPTURE 0x00000040
#define V4L2_CAP_SLICED_VBI_OUTPUT 0x00000080
#define V4L2_CAP_RDS_CAPTURE 0x00000100
#define V4L2_CAP_VIDEO_OUTPUT_OVERLAY 0x00000200
#define V4L2_CAP_HW_FREQ_SEEK 0x00000400
#define V4L2_CAP_RDS_OUTPUT 0x00000800
#define V4L2_CAP_VIDEO_CAPTURE_MPLANE 0x00001000
#define V4L2_CAP_VIDEO_OUTPUT_MPLANE 0x00002000
#define V4L2_CAP_VIDEO_M2M_MPLANE 0x00004000
#define V4L2_CAP_VIDEO_M2M 0x00008000
#define V4L2_CAP_TUNER 0x00010000
#define V4L2_CAP_AUDIO 0x00020000
#define V4L2_CAP_RADIO 0x00040000
#define V4L2_CAP_MODULATOR 0x00080000
#define V4L2_CAP_SDR_CAPTURE 0x00100000
#define V4L2_CAP_EXT_PIX_FORMAT 0x00200000
#define V4L2_CAP_SDR_OUTPUT 0x00400000
#define V4L2_CAP_META_CAPTURE 0x00800000
#define V4L2_CAP_READWRITE 0x01000000
#define V4L2_CAP_EDID 0x02000000
#define V4L2_CAP_STREAMING 0x04000000
#define V4L2_CAP_META_OUTPUT 0x08000000
#define V4L2_CAP_TOUCH 0x10000000
#define V4L2_CAP_IO_MC 0x20000000
#define V4L2_CAP_DEVICE_CAPS 0x80000000
struct v4l2_pix_format {
  __u32 width;
  __u32 height;
  __u32 pixelformat;
  __u32 field;
  __u32 bytesperline;
  __u32 sizeimage;
  __u32 colorspace;
  __u32 priv;
  __u32 flags;
  union {
    __u32 ycbcr_enc;
    __u32 hsv_enc;
  };
  __u32 quantization;
  __u32 xfer_func;
};
#define V4L2_PIX_FMT_RGB332 v4l2_fourcc('R', 'G', 'B', '1')
#define V4L2_PIX_FMT_RGB444 v4l2_fourcc('R', '4', '4', '4')
#define V4L2_PIX_FMT_ARGB444 v4l2_fourcc('A', 'R', '1', '2')
#define V4L2_PIX_FMT_XRGB444 v4l2_fourcc('X', 'R', '1', '2')
#define V4L2_PIX_FMT_RGBA444 v4l2_fourcc('R', 'A', '1', '2')
#define V4L2_PIX_FMT_RGBX444 v4l2_fourcc('R', 'X', '1', '2')
#define V4L2_PIX_FMT_ABGR444 v4l2_fourcc('A', 'B', '1', '2')
#define V4L2_PIX_FMT_XBGR444 v4l2_fourcc('X', 'B', '1', '2')
#define V4L2_PIX_FMT_BGRA444 v4l2_fourcc('G', 'A', '1', '2')
#define V4L2_PIX_FMT_BGRX444 v4l2_fourcc('B', 'X', '1', '2')
#define V4L2_PIX_FMT_RGB555 v4l2_fourcc('R', 'G', 'B', 'O')
#define V4L2_PIX_FMT_ARGB555 v4l2_fourcc('A', 'R', '1', '5')
#define V4L2_PIX_FMT_XRGB555 v4l2_fourcc('X', 'R', '1', '5')
#define V4L2_PIX_FMT_RGBA555 v4l2_fourcc('R', 'A', '1', '5')
#define V4L2_PIX_FMT_RGBX555 v4l2_fourcc('R', 'X', '1', '5')
#define V4L2_PIX_FMT_ABGR555 v4l2_fourcc('A', 'B', '1', '5')
#define V4L2_PIX_FMT_XBGR555 v4l2_fourcc('X', 'B', '1', '5')
#define V4L2_PIX_FMT_BGRA555 v4l2_fourcc('B', 'A', '1', '5')
#define V4L2_PIX_FMT_BGRX555 v4l2_fourcc('B', 'X', '1', '5')
#define V4L2_PIX_FMT_RGB565 v4l2_fourcc('R', 'G', 'B', 'P')
#define V4L2_PIX_FMT_RGB555X v4l2_fourcc('R', 'G', 'B', 'Q')
#define V4L2_PIX_FMT_ARGB555X v4l2_fourcc_be('A', 'R', '1', '5')
#define V4L2_PIX_FMT_XRGB555X v4l2_fourcc_be('X', 'R', '1', '5')
#define V4L2_PIX_FMT_RGB565X v4l2_fourcc('R', 'G', 'B', 'R')
#define V4L2_PIX_FMT_BGR666 v4l2_fourcc('B', 'G', 'R', 'H')
#define V4L2_PIX_FMT_BGR24 v4l2_fourcc('B', 'G', 'R', '3')
#define V4L2_PIX_FMT_RGB24 v4l2_fourcc('R', 'G', 'B', '3')
#define V4L2_PIX_FMT_BGR32 v4l2_fourcc('B', 'G', 'R', '4')
#define V4L2_PIX_FMT_ABGR32 v4l2_fourcc('A', 'R', '2', '4')
#define V4L2_PIX_FMT_XBGR32 v4l2_fourcc('X', 'R', '2', '4')
#define V4L2_PIX_FMT_BGRA32 v4l2_fourcc('R', 'A', '2', '4')
#define V4L2_PIX_FMT_BGRX32 v4l2_fourcc('R', 'X', '2', '4')
#define V4L2_PIX_FMT_RGB32 v4l2_fourcc('R', 'G', 'B', '4')
#define V4L2_PIX_FMT_RGBA32 v4l2_fourcc('A', 'B', '2', '4')
#define V4L2_PIX_FMT_RGBX32 v4l2_fourcc('X', 'B', '2', '4')
#define V4L2_PIX_FMT_ARGB32 v4l2_fourcc('B', 'A', '2', '4')
#define V4L2_PIX_FMT_XRGB32 v4l2_fourcc('B', 'X', '2', '4')
#define V4L2_PIX_FMT_RGBX1010102 v4l2_fourcc('R', 'X', '3', '0')
#define V4L2_PIX_FMT_RGBA1010102 v4l2_fourcc('R', 'A', '3', '0')
#define V4L2_PIX_FMT_ARGB2101010 v4l2_fourcc('A', 'R', '3', '0')
#define V4L2_PIX_FMT_BGR48_12 v4l2_fourcc('B', '3', '1', '2')
#define V4L2_PIX_FMT_BGR48 v4l2_fourcc('B', 'G', 'R', '6')
#define V4L2_PIX_FMT_RGB48 v4l2_fourcc('R', 'G', 'B', '6')
#define V4L2_PIX_FMT_ABGR64_12 v4l2_fourcc('B', '4', '1', '2')
#define V4L2_PIX_FMT_GREY v4l2_fourcc('G', 'R', 'E', 'Y')
#define V4L2_PIX_FMT_Y4 v4l2_fourcc('Y', '0', '4', ' ')
#define V4L2_PIX_FMT_Y6 v4l2_fourcc('Y', '0', '6', ' ')
#define V4L2_PIX_FMT_Y10 v4l2_fourcc('Y', '1', '0', ' ')
#define V4L2_PIX_FMT_Y12 v4l2_fourcc('Y', '1', '2', ' ')
#define V4L2_PIX_FMT_Y012 v4l2_fourcc('Y', '0', '1', '2')
#define V4L2_PIX_FMT_Y14 v4l2_fourcc('Y', '1', '4', ' ')
#define V4L2_PIX_FMT_Y16 v4l2_fourcc('Y', '1', '6', ' ')
#define V4L2_PIX_FMT_Y16_BE v4l2_fourcc_be('Y', '1', '6', ' ')
#define V4L2_PIX_FMT_Y10BPACK v4l2_fourcc('Y', '1', '0', 'B')
#define V4L2_PIX_FMT_Y10P v4l2_fourcc('Y', '1', '0', 'P')
#define V4L2_PIX_FMT_IPU3_Y10 v4l2_fourcc('i', 'p', '3', 'y')
#define V4L2_PIX_FMT_Y12P v4l2_fourcc('Y', '1', '2', 'P')
#define V4L2_PIX_FMT_Y14P v4l2_fourcc('Y', '1', '4', 'P')
#define V4L2_PIX_FMT_PAL8 v4l2_fourcc('P', 'A', 'L', '8')
#define V4L2_PIX_FMT_UV8 v4l2_fourcc('U', 'V', '8', ' ')
#define V4L2_PIX_FMT_YUYV v4l2_fourcc('Y', 'U', 'Y', 'V')
#define V4L2_PIX_FMT_YYUV v4l2_fourcc('Y', 'Y', 'U', 'V')
#define V4L2_PIX_FMT_YVYU v4l2_fourcc('Y', 'V', 'Y', 'U')
#define V4L2_PIX_FMT_UYVY v4l2_fourcc('U', 'Y', 'V', 'Y')
#define V4L2_PIX_FMT_VYUY v4l2_fourcc('V', 'Y', 'U', 'Y')
#define V4L2_PIX_FMT_Y41P v4l2_fourcc('Y', '4', '1', 'P')
#define V4L2_PIX_FMT_YUV444 v4l2_fourcc('Y', '4', '4', '4')
#define V4L2_PIX_FMT_YUV555 v4l2_fourcc('Y', 'U', 'V', 'O')
#define V4L2_PIX_FMT_YUV565 v4l2_fourcc('Y', 'U', 'V', 'P')
#define V4L2_PIX_FMT_YUV24 v4l2_fourcc('Y', 'U', 'V', '3')
#define V4L2_PIX_FMT_YUV32 v4l2_fourcc('Y', 'U', 'V', '4')
#define V4L2_PIX_FMT_AYUV32 v4l2_fourcc('A', 'Y', 'U', 'V')
#define V4L2_PIX_FMT_XYUV32 v4l2_fourcc('X', 'Y', 'U', 'V')
#define V4L2_PIX_FMT_VUYA32 v4l2_fourcc('V', 'U', 'Y', 'A')
#define V4L2_PIX_FMT_VUYX32 v4l2_fourcc('V', 'U', 'Y', 'X')
#define V4L2_PIX_FMT_YUVA32 v4l2_fourcc('Y', 'U', 'V', 'A')
#define V4L2_PIX_FMT_YUVX32 v4l2_fourcc('Y', 'U', 'V', 'X')
#define V4L2_PIX_FMT_M420 v4l2_fourcc('M', '4', '2', '0')
#define V4L2_PIX_FMT_YUV48_12 v4l2_fourcc('Y', '3', '1', '2')
#define V4L2_PIX_FMT_Y210 v4l2_fourcc('Y', '2', '1', '0')
#define V4L2_PIX_FMT_Y212 v4l2_fourcc('Y', '2', '1', '2')
#define V4L2_PIX_FMT_Y216 v4l2_fourcc('Y', '2', '1', '6')
#define V4L2_PIX_FMT_NV12 v4l2_fourcc('N', 'V', '1', '2')
#define V4L2_PIX_FMT_NV21 v4l2_fourcc('N', 'V', '2', '1')
#define V4L2_PIX_FMT_NV16 v4l2_fourcc('N', 'V', '1', '6')
#define V4L2_PIX_FMT_NV61 v4l2_fourcc('N', 'V', '6', '1')
#define V4L2_PIX_FMT_NV24 v4l2_fourcc('N', 'V', '2', '4')
#define V4L2_PIX_FMT_NV42 v4l2_fourcc('N', 'V', '4', '2')
#define V4L2_PIX_FMT_P010 v4l2_fourcc('P', '0', '1', '0')
#define V4L2_PIX_FMT_P012 v4l2_fourcc('P', '0', '1', '2')
#define V4L2_PIX_FMT_NV12M v4l2_fourcc('N', 'M', '1', '2')
#define V4L2_PIX_FMT_NV21M v4l2_fourcc('N', 'M', '2', '1')
#define V4L2_PIX_FMT_NV16M v4l2_fourcc('N', 'M', '1', '6')
#define V4L2_PIX_FMT_NV61M v4l2_fourcc('N', 'M', '6', '1')
#define V4L2_PIX_FMT_P012M v4l2_fourcc('P', 'M', '1', '2')
#define V4L2_PIX_FMT_YUV410 v4l2_fourcc('Y', 'U', 'V', '9')
#define V4L2_PIX_FMT_YVU410 v4l2_fourcc('Y', 'V', 'U', '9')
#define V4L2_PIX_FMT_YUV411P v4l2_fourcc('4', '1', '1', 'P')
#define V4L2_PIX_FMT_YUV420 v4l2_fourcc('Y', 'U', '1', '2')
#define V4L2_PIX_FMT_YVU420 v4l2_fourcc('Y', 'V', '1', '2')
#define V4L2_PIX_FMT_YUV422P v4l2_fourcc('4', '2', '2', 'P')
#define V4L2_PIX_FMT_YUV420M v4l2_fourcc('Y', 'M', '1', '2')
#define V4L2_PIX_FMT_YVU420M v4l2_fourcc('Y', 'M', '2', '1')
#define V4L2_PIX_FMT_YUV422M v4l2_fourcc('Y', 'M', '1', '6')
#define V4L2_PIX_FMT_YVU422M v4l2_fourcc('Y', 'M', '6', '1')
#define V4L2_PIX_FMT_YUV444M v4l2_fourcc('Y', 'M', '2', '4')
#define V4L2_PIX_FMT_YVU444M v4l2_fourcc('Y', 'M', '4', '2')
#define V4L2_PIX_FMT_NV12_4L4 v4l2_fourcc('V', 'T', '1', '2')
#define V4L2_PIX_FMT_NV12_16L16 v4l2_fourcc('H', 'M', '1', '2')
#define V4L2_PIX_FMT_NV12_32L32 v4l2_fourcc('S', 'T', '1', '2')
#define V4L2_PIX_FMT_NV15_4L4 v4l2_fourcc('V', 'T', '1', '5')
#define V4L2_PIX_FMT_P010_4L4 v4l2_fourcc('T', '0', '1', '0')
#define V4L2_PIX_FMT_NV12_8L128 v4l2_fourcc('A', 'T', '1', '2')
#define V4L2_PIX_FMT_NV12_10BE_8L128 v4l2_fourcc_be('A', 'X', '1', '2')
#define V4L2_PIX_FMT_NV12MT v4l2_fourcc('T', 'M', '1', '2')
#define V4L2_PIX_FMT_NV12MT_16X16 v4l2_fourcc('V', 'M', '1', '2')
#define V4L2_PIX_FMT_NV12M_8L128 v4l2_fourcc('N', 'A', '1', '2')
#define V4L2_PIX_FMT_NV12M_10BE_8L128 v4l2_fourcc_be('N', 'T', '1', '2')
#define V4L2_PIX_FMT_SBGGR8 v4l2_fourcc('B', 'A', '8', '1')
#define V4L2_PIX_FMT_SGBRG8 v4l2_fourcc('G', 'B', 'R', 'G')
#define V4L2_PIX_FMT_SGRBG8 v4l2_fourcc('G', 'R', 'B', 'G')
#define V4L2_PIX_FMT_SRGGB8 v4l2_fourcc('R', 'G', 'G', 'B')
#define V4L2_PIX_FMT_SBGGR10 v4l2_fourcc('B', 'G', '1', '0')
#define V4L2_PIX_FMT_SGBRG10 v4l2_fourcc('G', 'B', '1', '0')
#define V4L2_PIX_FMT_SGRBG10 v4l2_fourcc('B', 'A', '1', '0')
#define V4L2_PIX_FMT_SRGGB10 v4l2_fourcc('R', 'G', '1', '0')
#define V4L2_PIX_FMT_SBGGR10P v4l2_fourcc('p', 'B', 'A', 'A')
#define V4L2_PIX_FMT_SGBRG10P v4l2_fourcc('p', 'G', 'A', 'A')
#define V4L2_PIX_FMT_SGRBG10P v4l2_fourcc('p', 'g', 'A', 'A')
#define V4L2_PIX_FMT_SRGGB10P v4l2_fourcc('p', 'R', 'A', 'A')
#define V4L2_PIX_FMT_SBGGR10ALAW8 v4l2_fourcc('a', 'B', 'A', '8')
#define V4L2_PIX_FMT_SGBRG10ALAW8 v4l2_fourcc('a', 'G', 'A', '8')
#define V4L2_PIX_FMT_SGRBG10ALAW8 v4l2_fourcc('a', 'g', 'A', '8')
#define V4L2_PIX_FMT_SRGGB10ALAW8 v4l2_fourcc('a', 'R', 'A', '8')
#define V4L2_PIX_FMT_SBGGR10DPCM8 v4l2_fourcc('b', 'B', 'A', '8')
#define V4L2_PIX_FMT_SGBRG10DPCM8 v4l2_fourcc('b', 'G', 'A', '8')
#define V4L2_PIX_FMT_SGRBG10DPCM8 v4l2_fourcc('B', 'D', '1', '0')
#define V4L2_PIX_FMT_SRGGB10DPCM8 v4l2_fourcc('b', 'R', 'A', '8')
#define V4L2_PIX_FMT_SBGGR12 v4l2_fourcc('B', 'G', '1', '2')
#define V4L2_PIX_FMT_SGBRG12 v4l2_fourcc('G', 'B', '1', '2')
#define V4L2_PIX_FMT_SGRBG12 v4l2_fourcc('B', 'A', '1', '2')
#define V4L2_PIX_FMT_SRGGB12 v4l2_fourcc('R', 'G', '1', '2')
#define V4L2_PIX_FMT_SBGGR12P v4l2_fourcc('p', 'B', 'C', 'C')
#define V4L2_PIX_FMT_SGBRG12P v4l2_fourcc('p', 'G', 'C', 'C')
#define V4L2_PIX_FMT_SGRBG12P v4l2_fourcc('p', 'g', 'C', 'C')
#define V4L2_PIX_FMT_SRGGB12P v4l2_fourcc('p', 'R', 'C', 'C')
#define V4L2_PIX_FMT_SBGGR14 v4l2_fourcc('B', 'G', '1', '4')
#define V4L2_PIX_FMT_SGBRG14 v4l2_fourcc('G', 'B', '1', '4')
#define V4L2_PIX_FMT_SGRBG14 v4l2_fourcc('G', 'R', '1', '4')
#define V4L2_PIX_FMT_SRGGB14 v4l2_fourcc('R', 'G', '1', '4')
#define V4L2_PIX_FMT_SBGGR14P v4l2_fourcc('p', 'B', 'E', 'E')
#define V4L2_PIX_FMT_SGBRG14P v4l2_fourcc('p', 'G', 'E', 'E')
#define V4L2_PIX_FMT_SGRBG14P v4l2_fourcc('p', 'g', 'E', 'E')
#define V4L2_PIX_FMT_SRGGB14P v4l2_fourcc('p', 'R', 'E', 'E')
#define V4L2_PIX_FMT_SBGGR16 v4l2_fourcc('B', 'Y', 'R', '2')
#define V4L2_PIX_FMT_SGBRG16 v4l2_fourcc('G', 'B', '1', '6')
#define V4L2_PIX_FMT_SGRBG16 v4l2_fourcc('G', 'R', '1', '6')
#define V4L2_PIX_FMT_SRGGB16 v4l2_fourcc('R', 'G', '1', '6')
#define V4L2_PIX_FMT_HSV24 v4l2_fourcc('H', 'S', 'V', '3')
#define V4L2_PIX_FMT_HSV32 v4l2_fourcc('H', 'S', 'V', '4')
#define V4L2_PIX_FMT_MJPEG v4l2_fourcc('M', 'J', 'P', 'G')
#define V4L2_PIX_FMT_JPEG v4l2_fourcc('J', 'P', 'E', 'G')
#define V4L2_PIX_FMT_DV v4l2_fourcc('d', 'v', 's', 'd')
#define V4L2_PIX_FMT_MPEG v4l2_fourcc('M', 'P', 'E', 'G')
#define V4L2_PIX_FMT_H264 v4l2_fourcc('H', '2', '6', '4')
#define V4L2_PIX_FMT_H264_NO_SC v4l2_fourcc('A', 'V', 'C', '1')
#define V4L2_PIX_FMT_H264_MVC v4l2_fourcc('M', '2', '6', '4')
#define V4L2_PIX_FMT_H263 v4l2_fourcc('H', '2', '6', '3')
#define V4L2_PIX_FMT_MPEG1 v4l2_fourcc('M', 'P', 'G', '1')
#define V4L2_PIX_FMT_MPEG2 v4l2_fourcc('M', 'P', 'G', '2')
#define V4L2_PIX_FMT_MPEG2_SLICE v4l2_fourcc('M', 'G', '2', 'S')
#define V4L2_PIX_FMT_MPEG4 v4l2_fourcc('M', 'P', 'G', '4')
#define V4L2_PIX_FMT_XVID v4l2_fourcc('X', 'V', 'I', 'D')
#define V4L2_PIX_FMT_VC1_ANNEX_G v4l2_fourcc('V', 'C', '1', 'G')
#define V4L2_PIX_FMT_VC1_ANNEX_L v4l2_fourcc('V', 'C', '1', 'L')
#define V4L2_PIX_FMT_VP8 v4l2_fourcc('V', 'P', '8', '0')
#define V4L2_PIX_FMT_VP8_FRAME v4l2_fourcc('V', 'P', '8', 'F')
#define V4L2_PIX_FMT_VP9 v4l2_fourcc('V', 'P', '9', '0')
#define V4L2_PIX_FMT_VP9_FRAME v4l2_fourcc('V', 'P', '9', 'F')
#define V4L2_PIX_FMT_HEVC v4l2_fourcc('H', 'E', 'V', 'C')
#define V4L2_PIX_FMT_FWHT v4l2_fourcc('F', 'W', 'H', 'T')
#define V4L2_PIX_FMT_FWHT_STATELESS v4l2_fourcc('S', 'F', 'W', 'H')
#define V4L2_PIX_FMT_H264_SLICE v4l2_fourcc('S', '2', '6', '4')
#define V4L2_PIX_FMT_HEVC_SLICE v4l2_fourcc('S', '2', '6', '5')
#define V4L2_PIX_FMT_AV1_FRAME v4l2_fourcc('A', 'V', '1', 'F')
#define V4L2_PIX_FMT_SPK v4l2_fourcc('S', 'P', 'K', '0')
#define V4L2_PIX_FMT_RV30 v4l2_fourcc('R', 'V', '3', '0')
#define V4L2_PIX_FMT_RV40 v4l2_fourcc('R', 'V', '4', '0')
#define V4L2_PIX_FMT_CPIA1 v4l2_fourcc('C', 'P', 'I', 'A')
#define V4L2_PIX_FMT_WNVA v4l2_fourcc('W', 'N', 'V', 'A')
#define V4L2_PIX_FMT_SN9C10X v4l2_fourcc('S', '9', '1', '0')
#define V4L2_PIX_FMT_SN9C20X_I420 v4l2_fourcc('S', '9', '2', '0')
#define V4L2_PIX_FMT_PWC1 v4l2_fourcc('P', 'W', 'C', '1')
#define V4L2_PIX_FMT_PWC2 v4l2_fourcc('P', 'W', 'C', '2')
#define V4L2_PIX_FMT_ET61X251 v4l2_fourcc('E', '6', '2', '5')
#define V4L2_PIX_FMT_SPCA501 v4l2_fourcc('S', '5', '0', '1')
#define V4L2_PIX_FMT_SPCA505 v4l2_fourcc('S', '5', '0', '5')
#define V4L2_PIX_FMT_SPCA508 v4l2_fourcc('S', '5', '0', '8')
#define V4L2_PIX_FMT_SPCA561 v4l2_fourcc('S', '5', '6', '1')
#define V4L2_PIX_FMT_PAC207 v4l2_fourcc('P', '2', '0', '7')
#define V4L2_PIX_FMT_MR97310A v4l2_fourcc('M', '3', '1', '0')
#define V4L2_PIX_FMT_JL2005BCD v4l2_fourcc('J', 'L', '2', '0')
#define V4L2_PIX_FMT_SN9C2028 v4l2_fourcc('S', 'O', 'N', 'X')
#define V4L2_PIX_FMT_SQ905C v4l2_fourcc('9', '0', '5', 'C')
#define V4L2_PIX_FMT_PJPG v4l2_fourcc('P', 'J', 'P', 'G')
#define V4L2_PIX_FMT_OV511 v4l2_fourcc('O', '5', '1', '1')
#define V4L2_PIX_FMT_OV518 v4l2_fourcc('O', '5', '1', '8')
#define V4L2_PIX_FMT_STV0680 v4l2_fourcc('S', '6', '8', '0')
#define V4L2_PIX_FMT_TM6000 v4l2_fourcc('T', 'M', '6', '0')
#define V4L2_PIX_FMT_CIT_YYVYUY v4l2_fourcc('C', 'I', 'T', 'V')
#define V4L2_PIX_FMT_KONICA420 v4l2_fourcc('K', 'O', 'N', 'I')
#define V4L2_PIX_FMT_JPGL v4l2_fourcc('J', 'P', 'G', 'L')
#define V4L2_PIX_FMT_SE401 v4l2_fourcc('S', '4', '0', '1')
#define V4L2_PIX_FMT_S5C_UYVY_JPG v4l2_fourcc('S', '5', 'C', 'I')
#define V4L2_PIX_FMT_Y8I v4l2_fourcc('Y', '8', 'I', ' ')
#define V4L2_PIX_FMT_Y12I v4l2_fourcc('Y', '1', '2', 'I')
#define V4L2_PIX_FMT_Z16 v4l2_fourcc('Z', '1', '6', ' ')
#define V4L2_PIX_FMT_MT21C v4l2_fourcc('M', 'T', '2', '1')
#define V4L2_PIX_FMT_MM21 v4l2_fourcc('M', 'M', '2', '1')
#define V4L2_PIX_FMT_MT2110T v4l2_fourcc('M', 'T', '2', 'T')
#define V4L2_PIX_FMT_MT2110R v4l2_fourcc('M', 'T', '2', 'R')
#define V4L2_PIX_FMT_INZI v4l2_fourcc('I', 'N', 'Z', 'I')
#define V4L2_PIX_FMT_CNF4 v4l2_fourcc('C', 'N', 'F', '4')
#define V4L2_PIX_FMT_HI240 v4l2_fourcc('H', 'I', '2', '4')
#define V4L2_PIX_FMT_QC08C v4l2_fourcc('Q', '0', '8', 'C')
#define V4L2_PIX_FMT_QC10C v4l2_fourcc('Q', '1', '0', 'C')
#define V4L2_PIX_FMT_AJPG v4l2_fourcc('A', 'J', 'P', 'G')
#define V4L2_PIX_FMT_HEXTILE v4l2_fourcc('H', 'X', 'T', 'L')
#define V4L2_PIX_FMT_IPU3_SBGGR10 v4l2_fourcc('i', 'p', '3', 'b')
#define V4L2_PIX_FMT_IPU3_SGBRG10 v4l2_fourcc('i', 'p', '3', 'g')
#define V4L2_PIX_FMT_IPU3_SGRBG10 v4l2_fourcc('i', 'p', '3', 'G')
#define V4L2_PIX_FMT_IPU3_SRGGB10 v4l2_fourcc('i', 'p', '3', 'r')
#define V4L2_PIX_FMT_PISP_COMP1_RGGB v4l2_fourcc('P', 'C', '1', 'R')
#define V4L2_PIX_FMT_PISP_COMP1_GRBG v4l2_fourcc('P', 'C', '1', 'G')
#define V4L2_PIX_FMT_PISP_COMP1_GBRG v4l2_fourcc('P', 'C', '1', 'g')
#define V4L2_PIX_FMT_PISP_COMP1_BGGR v4l2_fourcc('P', 'C', '1', 'B')
#define V4L2_PIX_FMT_PISP_COMP1_MONO v4l2_fourcc('P', 'C', '1', 'M')
#define V4L2_PIX_FMT_PISP_COMP2_RGGB v4l2_fourcc('P', 'C', '2', 'R')
#define V4L2_PIX_FMT_PISP_COMP2_GRBG v4l2_fourcc('P', 'C', '2', 'G')
#define V4L2_PIX_FMT_PISP_COMP2_GBRG v4l2_fourcc('P', 'C', '2', 'g')
#define V4L2_PIX_FMT_PISP_COMP2_BGGR v4l2_fourcc('P', 'C', '2', 'B')
#define V4L2_PIX_FMT_PISP_COMP2_MONO v4l2_fourcc('P', 'C', '2', 'M')
#define V4L2_SDR_FMT_CU8 v4l2_fourcc('C', 'U', '0', '8')
#define V4L2_SDR_FMT_CU16LE v4l2_fourcc('C', 'U', '1', '6')
#define V4L2_SDR_FMT_CS8 v4l2_fourcc('C', 'S', '0', '8')
#define V4L2_SDR_FMT_CS14LE v4l2_fourcc('C', 'S', '1', '4')
#define V4L2_SDR_FMT_RU12LE v4l2_fourcc('R', 'U', '1', '2')
#define V4L2_SDR_FMT_PCU16BE v4l2_fourcc('P', 'C', '1', '6')
#define V4L2_SDR_FMT_PCU18BE v4l2_fourcc('P', 'C', '1', '8')
#define V4L2_SDR_FMT_PCU20BE v4l2_fourcc('P', 'C', '2', '0')
#define V4L2_TCH_FMT_DELTA_TD16 v4l2_fourcc('T', 'D', '1', '6')
#define V4L2_TCH_FMT_DELTA_TD08 v4l2_fourcc('T', 'D', '0', '8')
#define V4L2_TCH_FMT_TU16 v4l2_fourcc('T', 'U', '1', '6')
#define V4L2_TCH_FMT_TU08 v4l2_fourcc('T', 'U', '0', '8')
#define V4L2_META_FMT_VSP1_HGO v4l2_fourcc('V', 'S', 'P', 'H')
#define V4L2_META_FMT_VSP1_HGT v4l2_fourcc('V', 'S', 'P', 'T')
#define V4L2_META_FMT_UVC v4l2_fourcc('U', 'V', 'C', 'H')
#define V4L2_META_FMT_D4XX v4l2_fourcc('D', '4', 'X', 'X')
#define V4L2_META_FMT_VIVID v4l2_fourcc('V', 'I', 'V', 'D')
#define V4L2_META_FMT_RK_ISP1_PARAMS v4l2_fourcc('R', 'K', '1', 'P')
#define V4L2_META_FMT_RK_ISP1_STAT_3A v4l2_fourcc('R', 'K', '1', 'S')
#define V4L2_META_FMT_RK_ISP1_EXT_PARAMS v4l2_fourcc('R', 'K', '1', 'E')
#define V4L2_META_FMT_RPI_BE_CFG v4l2_fourcc('R', 'P', 'B', 'C')
#define V4L2_PIX_FMT_PRIV_MAGIC 0xfeedcafe
#define V4L2_PIX_FMT_FLAG_PREMUL_ALPHA 0x00000001
#define V4L2_PIX_FMT_FLAG_SET_CSC 0x00000002
struct v4l2_fmtdesc {
  __u32 index;
  __u32 type;
  __u32 flags;
  __u8 description[32];
  __u32 pixelformat;
  __u32 mbus_code;
  __u32 reserved[3];
};
#define V4L2_FMT_FLAG_COMPRESSED 0x0001
#define V4L2_FMT_FLAG_EMULATED 0x0002
#define V4L2_FMT_FLAG_CONTINUOUS_BYTESTREAM 0x0004
#define V4L2_FMT_FLAG_DYN_RESOLUTION 0x0008
#define V4L2_FMT_FLAG_ENC_CAP_FRAME_INTERVAL 0x0010
#define V4L2_FMT_FLAG_CSC_COLORSPACE 0x0020
#define V4L2_FMT_FLAG_CSC_XFER_FUNC 0x0040
#define V4L2_FMT_FLAG_CSC_YCBCR_ENC 0x0080
#define V4L2_FMT_FLAG_CSC_HSV_ENC V4L2_FMT_FLAG_CSC_YCBCR_ENC
#define V4L2_FMT_FLAG_CSC_QUANTIZATION 0x0100
#define V4L2_FMT_FLAG_META_LINE_BASED 0x0200
enum v4l2_frmsizetypes {
  V4L2_FRMSIZE_TYPE_DISCRETE = 1,
  V4L2_FRMSIZE_TYPE_CONTINUOUS = 2,
  V4L2_FRMSIZE_TYPE_STEPWISE = 3,
};
struct v4l2_frmsize_discrete {
  __u32 width;
  __u32 height;
};
struct v4l2_frmsize_stepwise {
  __u32 min_width;
  __u32 max_width;
  __u32 step_width;
  __u32 min_height;
  __u32 max_height;
  __u32 step_height;
};
struct v4l2_frmsizeenum {
  __u32 index;
  __u32 pixel_format;
  __u32 type;
  union {
    struct v4l2_frmsize_discrete discrete;
    struct v4l2_frmsize_stepwise stepwise;
  };
  __u32 reserved[2];
};
enum v4l2_frmivaltypes {
  V4L2_FRMIVAL_TYPE_DISCRETE = 1,
  V4L2_FRMIVAL_TYPE_CONTINUOUS = 2,
  V4L2_FRMIVAL_TYPE_STEPWISE = 3,
};
struct v4l2_frmival_stepwise {
  struct v4l2_fract min;
  struct v4l2_fract max;
  struct v4l2_fract step;
};
struct v4l2_frmivalenum {
  __u32 index;
  __u32 pixel_format;
  __u32 width;
  __u32 height;
  __u32 type;
  union {
    struct v4l2_fract discrete;
    struct v4l2_frmival_stepwise stepwise;
  };
  __u32 reserved[2];
};
struct v4l2_timecode {
  __u32 type;
  __u32 flags;
  __u8 frames;
  __u8 seconds;
  __u8 minutes;
  __u8 hours;
  __u8 userbits[4];
};
#define V4L2_TC_TYPE_24FPS 1
#define V4L2_TC_TYPE_25FPS 2
#define V4L2_TC_TYPE_30FPS 3
#define V4L2_TC_TYPE_50FPS 4
#define V4L2_TC_TYPE_60FPS 5
#define V4L2_TC_FLAG_DROPFRAME 0x0001
#define V4L2_TC_FLAG_COLORFRAME 0x0002
#define V4L2_TC_USERBITS_field 0x000C
#define V4L2_TC_USERBITS_USERDEFINED 0x0000
#define V4L2_TC_USERBITS_8BITCHARS 0x0008
struct v4l2_jpegcompression {
  int quality;
  int APPn;
  int APP_len;
  char APP_data[60];
  int COM_len;
  char COM_data[60];
  __u32 jpeg_markers;
#define V4L2_JPEG_MARKER_DHT (1 << 3)
#define V4L2_JPEG_MARKER_DQT (1 << 4)
#define V4L2_JPEG_MARKER_DRI (1 << 5)
#define V4L2_JPEG_MARKER_COM (1 << 6)
#define V4L2_JPEG_MARKER_APP (1 << 7)
};
struct v4l2_requestbuffers {
  __u32 count;
  __u32 type;
  __u32 memory;
  __u32 capabilities;
  __u8 flags;
  __u8 reserved[3];
};
#define V4L2_MEMORY_FLAG_NON_COHERENT (1 << 0)
#define V4L2_BUF_CAP_SUPPORTS_MMAP (1 << 0)
#define V4L2_BUF_CAP_SUPPORTS_USERPTR (1 << 1)
#define V4L2_BUF_CAP_SUPPORTS_DMABUF (1 << 2)
#define V4L2_BUF_CAP_SUPPORTS_REQUESTS (1 << 3)
#define V4L2_BUF_CAP_SUPPORTS_ORPHANED_BUFS (1 << 4)
#define V4L2_BUF_CAP_SUPPORTS_M2M_HOLD_CAPTURE_BUF (1 << 5)
#define V4L2_BUF_CAP_SUPPORTS_MMAP_CACHE_HINTS (1 << 6)
#define V4L2_BUF_CAP_SUPPORTS_MAX_NUM_BUFFERS (1 << 7)
#define V4L2_BUF_CAP_SUPPORTS_REMOVE_BUFS (1 << 8)
struct v4l2_plane {
  __u32 bytesused;
  __u32 length;
  union {
    __u32 mem_offset;
    unsigned long userptr;
    __s32 fd;
  } m;
  __u32 data_offset;
  __u32 reserved[11];
};
struct v4l2_buffer {
  __u32 index;
  __u32 type;
  __u32 bytesused;
  __u32 flags;
  __u32 field;
  struct timeval timestamp;
  struct v4l2_timecode timecode;
  __u32 sequence;
  __u32 memory;
  union {
    __u32 offset;
    unsigned long userptr;
    struct v4l2_plane * planes;
    __s32 fd;
  } m;
  __u32 length;
  __u32 reserved2;
  union {
    __s32 request_fd;
    __u32 reserved;
  };
};
#define V4L2_BUF_FLAG_MAPPED 0x00000001
#define V4L2_BUF_FLAG_QUEUED 0x00000002
#define V4L2_BUF_FLAG_DONE 0x00000004
#define V4L2_BUF_FLAG_KEYFRAME 0x00000008
#define V4L2_BUF_FLAG_PFRAME 0x00000010
#define V4L2_BUF_FLAG_BFRAME 0x00000020
#define V4L2_BUF_FLAG_ERROR 0x00000040
#define V4L2_BUF_FLAG_IN_REQUEST 0x00000080
#define V4L2_BUF_FLAG_TIMECODE 0x00000100
#define V4L2_BUF_FLAG_M2M_HOLD_CAPTURE_BUF 0x00000200
#define V4L2_BUF_FLAG_PREPARED 0x00000400
#define V4L2_BUF_FLAG_NO_CACHE_INVALIDATE 0x00000800
#define V4L2_BUF_FLAG_NO_CACHE_CLEAN 0x00001000
#define V4L2_BUF_FLAG_TIMESTAMP_MASK 0x0000e000
#define V4L2_BUF_FLAG_TIMESTAMP_UNKNOWN 0x00000000
#define V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC 0x00002000
#define V4L2_BUF_FLAG_TIMESTAMP_COPY 0x00004000
#define V4L2_BUF_FLAG_TSTAMP_SRC_MASK 0x00070000
#define V4L2_BUF_FLAG_TSTAMP_SRC_EOF 0x00000000
#define V4L2_BUF_FLAG_TSTAMP_SRC_SOE 0x00010000
#define V4L2_BUF_FLAG_LAST 0x00100000
#define V4L2_BUF_FLAG_REQUEST_FD 0x00800000
struct v4l2_exportbuffer {
  __u32 type;
  __u32 index;
  __u32 plane;
  __u32 flags;
  __s32 fd;
  __u32 reserved[11];
};
struct v4l2_framebuffer {
  __u32 capability;
  __u32 flags;
  void * base;
  struct {
    __u32 width;
    __u32 height;
    __u32 pixelformat;
    __u32 field;
    __u32 bytesperline;
    __u32 sizeimage;
    __u32 colorspace;
    __u32 priv;
  } fmt;
};
#define V4L2_FBUF_CAP_EXTERNOVERLAY 0x0001
#define V4L2_FBUF_CAP_CHROMAKEY 0x0002
#define V4L2_FBUF_CAP_LIST_CLIPPING 0x0004
#define V4L2_FBUF_CAP_BITMAP_CLIPPING 0x0008
#define V4L2_FBUF_CAP_LOCAL_ALPHA 0x0010
#define V4L2_FBUF_CAP_GLOBAL_ALPHA 0x0020
#define V4L2_FBUF_CAP_LOCAL_INV_ALPHA 0x0040
#define V4L2_FBUF_CAP_SRC_CHROMAKEY 0x0080
#define V4L2_FBUF_FLAG_PRIMARY 0x0001
#define V4L2_FBUF_FLAG_OVERLAY 0x0002
#define V4L2_FBUF_FLAG_CHROMAKEY 0x0004
#define V4L2_FBUF_FLAG_LOCAL_ALPHA 0x0008
#define V4L2_FBUF_FLAG_GLOBAL_ALPHA 0x0010
#define V4L2_FBUF_FLAG_LOCAL_INV_ALPHA 0x0020
#define V4L2_FBUF_FLAG_SRC_CHROMAKEY 0x0040
struct v4l2_clip {
  struct v4l2_rect c;
  struct v4l2_clip  * next;
};
struct v4l2_window {
  struct v4l2_rect w;
  __u32 field;
  __u32 chromakey;
  struct v4l2_clip * clips;
  __u32 clipcount;
  void  * bitmap;
  __u8 global_alpha;
};
struct v4l2_captureparm {
  __u32 capability;
  __u32 capturemode;
  struct v4l2_fract timeperframe;
  __u32 extendedmode;
  __u32 readbuffers;
  __u32 reserved[4];
};
#define V4L2_MODE_HIGHQUALITY 0x0001
#define V4L2_CAP_TIMEPERFRAME 0x1000
struct v4l2_outputparm {
  __u32 capability;
  __u32 outputmode;
  struct v4l2_fract timeperframe;
  __u32 extendedmode;
  __u32 writebuffers;
  __u32 reserved[4];
};
struct v4l2_cropcap {
  __u32 type;
  struct v4l2_rect bounds;
  struct v4l2_rect defrect;
  struct v4l2_fract pixelaspect;
};
struct v4l2_crop {
  __u32 type;
  struct v4l2_rect c;
};
struct v4l2_selection {
  __u32 type;
  __u32 target;
  __u32 flags;
  struct v4l2_rect r;
  __u32 reserved[9];
};
typedef __u64 v4l2_std_id;
#define V4L2_STD_PAL_B ((v4l2_std_id) 0x00000001)
#define V4L2_STD_PAL_B1 ((v4l2_std_id) 0x00000002)
#define V4L2_STD_PAL_G ((v4l2_std_id) 0x00000004)
#define V4L2_STD_PAL_H ((v4l2_std_id) 0x00000008)
#define V4L2_STD_PAL_I ((v4l2_std_id) 0x00000010)
#define V4L2_STD_PAL_D ((v4l2_std_id) 0x00000020)
#define V4L2_STD_PAL_D1 ((v4l2_std_id) 0x00000040)
#define V4L2_STD_PAL_K ((v4l2_std_id) 0x00000080)
#define V4L2_STD_PAL_M ((v4l2_std_id) 0x00000100)
#define V4L2_STD_PAL_N ((v4l2_std_id) 0x00000200)
#define V4L2_STD_PAL_Nc ((v4l2_std_id) 0x00000400)
#define V4L2_STD_PAL_60 ((v4l2_std_id) 0x00000800)
#define V4L2_STD_NTSC_M ((v4l2_std_id) 0x00001000)
#define V4L2_STD_NTSC_M_JP ((v4l2_std_id) 0x00002000)
#define V4L2_STD_NTSC_443 ((v4l2_std_id) 0x00004000)
#define V4L2_STD_NTSC_M_KR ((v4l2_std_id) 0x00008000)
#define V4L2_STD_SECAM_B ((v4l2_std_id) 0x00010000)
#define V4L2_STD_SECAM_D ((v4l2_std_id) 0x00020000)
#define V4L2_STD_SECAM_G ((v4l2_std_id) 0x00040000)
#define V4L2_STD_SECAM_H ((v4l2_std_id) 0x00080000)
#define V4L2_STD_SECAM_K ((v4l2_std_id) 0x00100000)
#define V4L2_STD_SECAM_K1 ((v4l2_std_id) 0x00200000)
#define V4L2_STD_SECAM_L ((v4l2_std_id) 0x00400000)
#define V4L2_STD_SECAM_LC ((v4l2_std_id) 0x00800000)
#define V4L2_STD_ATSC_8_VSB ((v4l2_std_id) 0x01000000)
#define V4L2_STD_ATSC_16_VSB ((v4l2_std_id) 0x02000000)
#define V4L2_STD_NTSC (V4L2_STD_NTSC_M | V4L2_STD_NTSC_M_JP | V4L2_STD_NTSC_M_KR)
#define V4L2_STD_SECAM_DK (V4L2_STD_SECAM_D | V4L2_STD_SECAM_K | V4L2_STD_SECAM_K1)
#define V4L2_STD_SECAM (V4L2_STD_SECAM_B | V4L2_STD_SECAM_G | V4L2_STD_SECAM_H | V4L2_STD_SECAM_DK | V4L2_STD_SECAM_L | V4L2_STD_SECAM_LC)
#define V4L2_STD_PAL_BG (V4L2_STD_PAL_B | V4L2_STD_PAL_B1 | V4L2_STD_PAL_G)
#define V4L2_STD_PAL_DK (V4L2_STD_PAL_D | V4L2_STD_PAL_D1 | V4L2_STD_PAL_K)
#define V4L2_STD_PAL (V4L2_STD_PAL_BG | V4L2_STD_PAL_DK | V4L2_STD_PAL_H | V4L2_STD_PAL_I)
#define V4L2_STD_B (V4L2_STD_PAL_B | V4L2_STD_PAL_B1 | V4L2_STD_SECAM_B)
#define V4L2_STD_G (V4L2_STD_PAL_G | V4L2_STD_SECAM_G)
#define V4L2
```