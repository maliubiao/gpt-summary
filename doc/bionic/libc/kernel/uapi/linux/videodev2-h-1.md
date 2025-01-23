Response:
The user is asking for a summary of the provided C header file, which defines structures and constants related to the Video4Linux version 2 (V4L2) API. The file resides within the Android Bionic library, indicating its relevance to Android's multimedia framework.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Functionality:** The file name `videodev2.handroid` and the content strongly suggest that this file defines the interface for interacting with video devices on Android systems. The "uapi" in the path implies it's a user-space API header.

2. **Categorize the Content:** Scan the file for major types of definitions. Immediately noticeable are:
    * `#define` macros: These define constants, likely representing flags, IDs, and standard values.
    * `struct` definitions: These define data structures used to pass information to and from the kernel driver.
    * `VIDIOC_*` macros: These are ioctl command codes for interacting with the V4L2 driver.

3. **Group Structures by Purpose:**  Examine the `struct` members and names to understand their roles. Key categories emerge:
    * **Video Standards and Timings:** Structures like `v4l2_standard`, `v4l2_bt_timings`, `v4l2_dv_timings`, and related enums deal with defining and querying video signal properties.
    * **Inputs and Outputs:** `v4l2_input` and `v4l2_output` describe video sources and sinks.
    * **Controls:** `v4l2_control`, `v4l2_ext_control`, `v4l2_queryctrl`, and related structures handle device-specific settings.
    * **Tuning and Frequency:**  `v4l2_tuner`, `v4l2_modulator`, `v4l2_frequency`, and related structures are for controlling radio/TV tuners.
    * **Encoding and Decoding:** `v4l2_enc_idx`, `v4l2_encoder_cmd`, `v4l2_decoder_cmd` relate to video encoding and decoding functionalities.
    * **VBI (Vertical Blanking Interval):**  `v4l2_vbi_format`, `v4l2_sliced_vbi_format`, and related structures handle data embedded in the vertical blanking interval.
    * **Pixel Formats:** `v4l2_pix_format`, `v4l2_pix_format_mplane`, `v4l2_sdr_format`, and `v4l2_meta_format` define how pixel data is structured.
    * **Streaming:** `v4l2_format`, `v4l2_streamparm`, `v4l2_requestbuffers`, `v4l2_buffer` are crucial for setting up and managing video data streams.
    * **Events:** `v4l2_event` and `v4l2_event_subscription` are for asynchronous notifications from the driver.
    * **Debugging:** `v4l2_dbg_match`, `v4l2_dbg_register`, and `v4l2_dbg_chip_info` facilitate debugging the driver.
    * **Buffer Management:** `v4l2_create_buffers` and `v4l2_remove_buffers` are used for creating and destroying buffers.

4. **Explain the `VIDIOC_*` Macros:**  These are the primary way user-space applications interact with the V4L2 driver. Explain that they represent ioctl calls and list a few examples to illustrate their purpose (e.g., setting format, querying capabilities).

5. **Relate to Android:**  Highlight that this header is part of Bionic and essential for Android's multimedia stack. Mention camera and video playback as key areas of usage.

6. **Address the "No libc functions" aspect:**  Explicitly state that this header primarily defines data structures and constants, not libc function implementations. Therefore, there's no libc function implementation to explain. Similarly, the header itself doesn't contain dynamic linker logic, though the V4L2 driver interacts with the kernel.

7. **Explain the Absence of Specific Examples:** Since this is a *header* file, it lacks executable code. Therefore, input/output examples, common errors within the header itself, and Frida hook examples directly within the header are not applicable. These would be relevant when *using* the definitions in actual code.

8. **Structure the Summary:** Organize the information logically, starting with the high-level purpose and then delving into the categorized components. Use clear headings and concise language.

9. **Review and Refine:** Read through the generated summary to ensure accuracy, completeness, and clarity. Make any necessary adjustments to improve readability and flow. Specifically, ensure the negative constraints (no libc functions, no direct dynamic linker interaction) are clearly addressed.
这是目录为`bionic/libc/kernel/uapi/linux/videodev2.handroid` 的源代码文件的第二部分，是对 V4L2 (Video for Linux version 2) API 的定义。这个头文件主要定义了用于与Linux视频设备驱动程序进行交互的数据结构和ioctl命令。

**功能归纳:**

总的来说，这个文件的主要功能是**定义了用户空间程序与Linux内核中的V4L2视频设备驱动程序通信的接口**。它包含了描述各种视频设备特性、控制、数据格式、以及进行操作所需的结构体、联合体、枚举类型和宏定义。

更具体地说，这个文件定义了以下方面的接口：

* **视频标准和时序:**  定义了各种模拟和数字视频标准（例如 PAL, NTSC, SECAM, ATSC）及其相关的时序参数，如帧率、行数、同步信号等。这部分允许应用程序查询和设置设备支持的视频标准。
* **输入和输出:** 描述了视频设备的输入和输出接口，包括类型（调谐器、摄像头等）、音频设置、以及相关的能力。
* **控制:** 定义了用于控制视频设备各种属性的结构，例如亮度、对比度、色调、饱和度等。扩展控制结构允许更复杂的参数传递。
* **调谐器和频率:** 针对带有调谐器的设备，定义了用于控制调频、频道扫描等功能的结构。
* **编码和解码:**  定义了与视频编码和解码相关的结构，例如编码索引、编码器和解码器命令，用于控制编码和解码过程。
* **垂直消隐间隔 (VBI):**  定义了用于处理垂直消隐间隔数据的结构，例如图文电视、字幕等。
* **像素格式:**  定义了各种视频像素数据的存储格式，包括单平面和多平面格式，以及不同的颜色空间和采样方式。
* **帧缓冲:**  定义了与帧缓冲相关的结构，用于内存映射和管理视频数据缓冲区。
* **流参数:**  定义了用于设置视频流参数的结构，例如捕获和输出参数。
* **事件:**  定义了用于异步通知的事件结构，例如垂直同步、帧结束、控制变化等。
* **调试:**  定义了用于调试视频设备驱动程序的结构，例如读写寄存器信息。
* **ioctl 命令:**  定义了用于向视频设备驱动程序发送命令的ioctl宏，涵盖了查询能力、设置格式、请求缓冲区、控制设备等各种操作。

**与 Android 功能的关系举例:**

这个头文件定义的接口是 Android Multimedia Framework 的基础。Android 系统中的摄像头服务 (Camera Service)、媒体编解码器 (MediaCodec)、以及显示相关的服务 (SurfaceFlinger) 等都需要通过 V4L2 接口与底层的摄像头硬件、视频编码器和解码器等进行交互。

**举例说明:**

* **摄像头预览:**  当 Android 应用请求摄像头预览时，Camera Service 会使用 V4L2 接口与摄像头驱动进行通信，例如：
    * 使用 `VIDIOC_QUERYCAP` 查询摄像头设备的能力。
    * 使用 `VIDIOC_ENUM_FMT` 枚举摄像头支持的像素格式和分辨率。
    * 使用 `VIDIOC_S_FMT` 设置所需的像素格式和分辨率。
    * 使用 `VIDIOC_REQBUFS` 请求用于存储预览帧的缓冲区。
    * 使用 `VIDIOC_QBUF` 将缓冲区放入队列。
    * 使用 `VIDIOC_STREAMON` 启动视频流。
    * 使用 `VIDIOC_DQBUF` 从队列中取出填充了数据的缓冲区。
* **视频解码:**  当 Android 播放视频文件时，MediaCodec 会使用 V4L2 接口与硬件解码器进行交互，例如：
    * 使用 `VIDIOC_DECODER_CMD` 发送解码命令。
    * 使用 `VIDIOC_QBUF` 将编码后的视频数据放入解码器输入缓冲区。
    * 使用 `VIDIOC_DQBUF` 获取解码后的视频数据。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个文件中定义的是数据结构和宏定义，**本身不包含任何 libc 函数的实现代码**。它是一个头文件，用于在用户空间程序中声明这些结构和宏，以便程序可以与内核驱动进行正确的交互。实际的系统调用（例如 `ioctl`）以及内核驱动的实现才是执行具体操作的地方。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个头文件本身不直接涉及 dynamic linker 的功能。** Dynamic linker 主要负责加载和链接共享库。这个头文件是被编译到需要使用 V4L2 功能的程序中。

不过，可以考虑以下情况：

* Android 的 Camera Service 或 MediaCodec 等组件通常会以共享库 (`.so`) 的形式存在。
* 这些共享库在实现与 V4L2 设备交互的功能时，会包含此头文件中定义的结构体和宏定义。
* Dynamic linker 在加载这些共享库时，会解析其依赖关系，并将其链接到相应的库和内核接口。

**SO 布局样本 (以 Camera Service 为例):**

```
/system/bin/cameraserver  (可执行文件)
/system/lib64/android.hardware.camera.provider@2.6-service.so (Camera Service 的实现)
/system/lib64/libbase.so
/system/lib64/libcutils.so
/system/lib64/libbinder.so
/system/lib64/libhardware.so  (可能包含加载 V4L2 驱动的逻辑)
/system/lib64/libv4l2.so     (用户空间的 V4L2 库，可能存在)
...其他依赖库...
```

**链接处理过程:**

1. 当 `cameraserver` 启动时，dynamic linker (`/linker64` 或 `/system/bin/linker`) 会被调用。
2. Dynamic linker 读取 `cameraserver` 的 ELF 头信息，找到其依赖的共享库列表。
3. Dynamic linker 遍历依赖列表，依次加载所需的共享库（例如 `android.hardware.camera.provider@2.6-service.so`）。
4. 对于每个加载的共享库，dynamic linker 会解析其符号表，找到其依赖的其他库。
5. 如果 `android.hardware.camera.provider@2.6-service.so` 中使用了 V4L2 相关的函数或结构体，并且这些函数位于一个单独的共享库（例如 `libv4l2.so`，虽然 Android 中不一定以这种形式存在，V4L2 功能可能直接在 `libhardware.so` 中实现），那么 dynamic linker 会找到并加载 `libv4l2.so`。
6. Dynamic linker 会进行符号解析，将共享库中对其他库中符号的引用（例如 V4L2 相关的系统调用封装函数）链接到正确的地址。
7. 最终，`cameraserver` 及其依赖的共享库被加载到内存中，并且它们之间的函数调用可以正常进行。

**逻辑推理，假设输入与输出:**

由于这是一个头文件，不存在直接的输入和输出。其作用是定义数据结构，为后续的程序开发提供类型信息。

**涉及用户或者编程常见的使用错误，请举例说明:**

虽然头文件本身不会导致运行时错误，但在使用其定义的结构体和宏时，常见的错误包括：

* **结构体成员访问错误:**  访问了不存在或错误的成员，或者使用了错误的类型。
* **ioctl 命令使用错误:**  使用了错误的 ioctl 命令码，或者传递了不正确的数据结构。
* **缓冲区管理错误:**  没有正确分配或释放缓冲区，导致内存泄漏或访问越界。
* **像素格式设置错误:**  设置了设备不支持的像素格式，导致图像显示异常。
* **时序参数设置错误:**  设置了无效的时序参数，可能导致设备无法正常工作。
* **忘记检查返回值:**  系统调用 (如 `ioctl`) 可能会返回错误码，没有检查返回值会导致程序在发生错误时继续执行，从而产生不可预测的行为。

**Android Framework 或 NDK 是如何一步步的到达这里:**

1. **Android Framework (Java层):**
   * 应用程序通过 Android Framework 的 Camera2 API 或旧的 Camera API 发起摄像头相关的请求（例如打开摄像头，开始预览，拍照）。
   * Framework 层的 Camera Service 负责处理这些请求。

2. **Camera Service (Native层 C++):**
   * Camera Service 会调用底层的 HAL (Hardware Abstraction Layer) 接口，通常是 Camera HAL。
   * Camera HAL 是连接 Android Framework 和硬件驱动程序的桥梁。

3. **Camera HAL (Native层 C++):**
   * Camera HAL 的实现会打开对应的摄像头设备文件 (例如 `/dev/video0`)。
   * Camera HAL 会使用标准 C 库的 `open()`, `ioctl()`, `mmap()` 等函数与内核中的 V4L2 驱动进行交互。
   * **在这里，Camera HAL 的代码会包含并使用 `videodev2.h` 头文件中定义的结构体和宏，例如 `v4l2_capability`, `v4l2_format`, `VIDIOC_QUERYCAP`, `VIDIOC_S_FMT` 等。**

4. **V4L2 驱动 (Kernel层 C):**
   * 内核中的 V4L2 驱动程序接收来自用户空间的 `ioctl` 调用。
   * 驱动程序根据 `ioctl` 命令码和传递的数据结构执行相应的操作，例如配置摄像头硬件、分配缓冲区、传输数据等。

5. **NDK 的使用:**
   * NDK 允许开发者使用 C/C++ 代码直接访问 Android 的 Native API。
   * 如果开发者使用 NDK 开发直接操作摄像头的应用程序，他们可以直接包含 `<linux/videodev2.h>` 头文件，并使用 V4L2 接口与摄像头驱动进行交互，绕过 Framework 层。

**Frida Hook 示例调试这些步骤:**

可以使用 Frida hook `ioctl` 系统调用来观察 Android Framework 或 NDK 应用如何与 V4L2 驱动交互。

**示例 (Hook `ioctl` 并过滤 V4L2 相关命令):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['timestamp'], message['payload']['data']))
    else:
        print(message)

def main():
    package_name = "com.android.camera2"  # 或者你的 NDK 应用的包名
    device = frida.get_usb_device()

    try:
        session = device.attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
        sys.exit(1)

    script_code = """
    var ioctlPtr = Module.getExportByName(null, "ioctl");

    Interceptor.attach(ioctlPtr, {
        onEnter: function(args) {
            var fd = args[0].toInt32();
            var request = args[1].toInt32();
            var timestamp = new Date().toLocaleTimeString();

            // 检查文件描述符是否可能与视频设备相关 (可以根据实际情况添加更精确的判断)
            if (fd > 0) {
                var requestName = "";
                // 根据 VIDIOC_* 的宏定义，将 request 转换为可读的名称
                if (request === 0x80085600) requestName = "VIDIOC_QUERYCAP";
                else if (request === 0xc0485602) requestName = "VIDIOC_ENUM_FMT";
                else if (request === 0xc0c85604) requestName = "VIDIOC_G_FMT";
                else if (request === 0xc0c85605) requestName = "VIDIOC_S_FMT";
                else if (request === 0xc0205608) requestName = "VIDIOC_REQBUFS";
                else if (request === 0xc0585609) requestName = "VIDIOC_QUERYBUF";
                else if (request === 0xc058560f) requestName = "VIDIOC_QBUF";
                else if (request === 0xc0585611) requestName = "VIDIOC_DQBUF";
                else if (request === 0x40045612) requestName = "VIDIOC_STREAMON";
                else if (request === 0x40045613) requestName = "VIDIOC_STREAMOFF";
                // ... 添加其他你关心的 VIDIOC_* 命令 ...
                else if ((request & 0xff) == 0x00 && ((request >> 8) & 0xff) == 0x56) {
                    requestName = "VIDIOC_UNKNOWN (" + request.toString(16) + ")";
                }

                if (requestName.startsWith("VIDIOC")) {
                    this.data = {
                        timestamp: timestamp,
                        data: "ioctl(fd=" + fd + ", request=" + requestName + ")"
                    };
                    send(this.data);
                }
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] 正在 Hook ioctl...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 确保你的 Android 设备已连接并开启 USB 调试。
2. 手机上运行目标应用（例如相机应用）。
3. 运行上述 Frida 脚本。
4. 观察 Frida 输出，它会打印出 `ioctl` 调用，并尝试识别 V4L2 相关的命令。

这个脚本只是一个基础示例，你可以根据需要扩展它，例如：

* 解析 `ioctl` 调用的参数，显示传递给驱动的数据结构的内容。
* 过滤特定的文件描述符，只关注与视频设备相关的调用。
* Hook 其他与 V4L2 交互相关的函数。

总结来说，`videodev2.handroid` 头文件是 Android 系统与底层视频设备驱动交互的关键接口定义，为 Android 的多媒体功能提供了基础。虽然它本身不包含代码实现，但其定义的结构体和宏被广泛用于 Android Framework 和 NDK 应用中，以控制和管理视频设备。

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
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
_STD_H (V4L2_STD_PAL_H | V4L2_STD_SECAM_H)
#define V4L2_STD_L (V4L2_STD_SECAM_L | V4L2_STD_SECAM_LC)
#define V4L2_STD_GH (V4L2_STD_G | V4L2_STD_H)
#define V4L2_STD_DK (V4L2_STD_PAL_DK | V4L2_STD_SECAM_DK)
#define V4L2_STD_BG (V4L2_STD_B | V4L2_STD_G)
#define V4L2_STD_MN (V4L2_STD_PAL_M | V4L2_STD_PAL_N | V4L2_STD_PAL_Nc | V4L2_STD_NTSC)
#define V4L2_STD_MTS (V4L2_STD_NTSC_M | V4L2_STD_PAL_M | V4L2_STD_PAL_N | V4L2_STD_PAL_Nc)
#define V4L2_STD_525_60 (V4L2_STD_PAL_M | V4L2_STD_PAL_60 | V4L2_STD_NTSC | V4L2_STD_NTSC_443)
#define V4L2_STD_625_50 (V4L2_STD_PAL | V4L2_STD_PAL_N | V4L2_STD_PAL_Nc | V4L2_STD_SECAM)
#define V4L2_STD_ATSC (V4L2_STD_ATSC_8_VSB | V4L2_STD_ATSC_16_VSB)
#define V4L2_STD_UNKNOWN 0
#define V4L2_STD_ALL (V4L2_STD_525_60 | V4L2_STD_625_50)
struct v4l2_standard {
  __u32 index;
  v4l2_std_id id;
  __u8 name[24];
  struct v4l2_fract frameperiod;
  __u32 framelines;
  __u32 reserved[4];
};
struct v4l2_bt_timings {
  __u32 width;
  __u32 height;
  __u32 interlaced;
  __u32 polarities;
  __u64 pixelclock;
  __u32 hfrontporch;
  __u32 hsync;
  __u32 hbackporch;
  __u32 vfrontporch;
  __u32 vsync;
  __u32 vbackporch;
  __u32 il_vfrontporch;
  __u32 il_vsync;
  __u32 il_vbackporch;
  __u32 standards;
  __u32 flags;
  struct v4l2_fract picture_aspect;
  __u8 cea861_vic;
  __u8 hdmi_vic;
  __u8 reserved[46];
} __attribute__((packed));
#define V4L2_DV_PROGRESSIVE 0
#define V4L2_DV_INTERLACED 1
#define V4L2_DV_VSYNC_POS_POL 0x00000001
#define V4L2_DV_HSYNC_POS_POL 0x00000002
#define V4L2_DV_BT_STD_CEA861 (1 << 0)
#define V4L2_DV_BT_STD_DMT (1 << 1)
#define V4L2_DV_BT_STD_CVT (1 << 2)
#define V4L2_DV_BT_STD_GTF (1 << 3)
#define V4L2_DV_BT_STD_SDI (1 << 4)
#define V4L2_DV_FL_REDUCED_BLANKING (1 << 0)
#define V4L2_DV_FL_CAN_REDUCE_FPS (1 << 1)
#define V4L2_DV_FL_REDUCED_FPS (1 << 2)
#define V4L2_DV_FL_HALF_LINE (1 << 3)
#define V4L2_DV_FL_IS_CE_VIDEO (1 << 4)
#define V4L2_DV_FL_FIRST_FIELD_EXTRA_LINE (1 << 5)
#define V4L2_DV_FL_HAS_PICTURE_ASPECT (1 << 6)
#define V4L2_DV_FL_HAS_CEA861_VIC (1 << 7)
#define V4L2_DV_FL_HAS_HDMI_VIC (1 << 8)
#define V4L2_DV_FL_CAN_DETECT_REDUCED_FPS (1 << 9)
#define V4L2_DV_BT_BLANKING_WIDTH(bt) ((bt)->hfrontporch + (bt)->hsync + (bt)->hbackporch)
#define V4L2_DV_BT_FRAME_WIDTH(bt) ((bt)->width + V4L2_DV_BT_BLANKING_WIDTH(bt))
#define V4L2_DV_BT_BLANKING_HEIGHT(bt) ((bt)->vfrontporch + (bt)->vsync + (bt)->vbackporch + ((bt)->interlaced ? ((bt)->il_vfrontporch + (bt)->il_vsync + (bt)->il_vbackporch) : 0))
#define V4L2_DV_BT_FRAME_HEIGHT(bt) ((bt)->height + V4L2_DV_BT_BLANKING_HEIGHT(bt))
struct v4l2_dv_timings {
  __u32 type;
  union {
    struct v4l2_bt_timings bt;
    __u32 reserved[32];
  };
} __attribute__((packed));
#define V4L2_DV_BT_656_1120 0
struct v4l2_enum_dv_timings {
  __u32 index;
  __u32 pad;
  __u32 reserved[2];
  struct v4l2_dv_timings timings;
};
struct v4l2_bt_timings_cap {
  __u32 min_width;
  __u32 max_width;
  __u32 min_height;
  __u32 max_height;
  __u64 min_pixelclock;
  __u64 max_pixelclock;
  __u32 standards;
  __u32 capabilities;
  __u32 reserved[16];
} __attribute__((packed));
#define V4L2_DV_BT_CAP_INTERLACED (1 << 0)
#define V4L2_DV_BT_CAP_PROGRESSIVE (1 << 1)
#define V4L2_DV_BT_CAP_REDUCED_BLANKING (1 << 2)
#define V4L2_DV_BT_CAP_CUSTOM (1 << 3)
struct v4l2_dv_timings_cap {
  __u32 type;
  __u32 pad;
  __u32 reserved[2];
  union {
    struct v4l2_bt_timings_cap bt;
    __u32 raw_data[32];
  };
};
struct v4l2_input {
  __u32 index;
  __u8 name[32];
  __u32 type;
  __u32 audioset;
  __u32 tuner;
  v4l2_std_id std;
  __u32 status;
  __u32 capabilities;
  __u32 reserved[3];
};
#define V4L2_INPUT_TYPE_TUNER 1
#define V4L2_INPUT_TYPE_CAMERA 2
#define V4L2_INPUT_TYPE_TOUCH 3
#define V4L2_IN_ST_NO_POWER 0x00000001
#define V4L2_IN_ST_NO_SIGNAL 0x00000002
#define V4L2_IN_ST_NO_COLOR 0x00000004
#define V4L2_IN_ST_HFLIP 0x00000010
#define V4L2_IN_ST_VFLIP 0x00000020
#define V4L2_IN_ST_NO_H_LOCK 0x00000100
#define V4L2_IN_ST_COLOR_KILL 0x00000200
#define V4L2_IN_ST_NO_V_LOCK 0x00000400
#define V4L2_IN_ST_NO_STD_LOCK 0x00000800
#define V4L2_IN_ST_NO_SYNC 0x00010000
#define V4L2_IN_ST_NO_EQU 0x00020000
#define V4L2_IN_ST_NO_CARRIER 0x00040000
#define V4L2_IN_ST_MACROVISION 0x01000000
#define V4L2_IN_ST_NO_ACCESS 0x02000000
#define V4L2_IN_ST_VTR 0x04000000
#define V4L2_IN_CAP_DV_TIMINGS 0x00000002
#define V4L2_IN_CAP_CUSTOM_TIMINGS V4L2_IN_CAP_DV_TIMINGS
#define V4L2_IN_CAP_STD 0x00000004
#define V4L2_IN_CAP_NATIVE_SIZE 0x00000008
struct v4l2_output {
  __u32 index;
  __u8 name[32];
  __u32 type;
  __u32 audioset;
  __u32 modulator;
  v4l2_std_id std;
  __u32 capabilities;
  __u32 reserved[3];
};
#define V4L2_OUTPUT_TYPE_MODULATOR 1
#define V4L2_OUTPUT_TYPE_ANALOG 2
#define V4L2_OUTPUT_TYPE_ANALOGVGAOVERLAY 3
#define V4L2_OUT_CAP_DV_TIMINGS 0x00000002
#define V4L2_OUT_CAP_CUSTOM_TIMINGS V4L2_OUT_CAP_DV_TIMINGS
#define V4L2_OUT_CAP_STD 0x00000004
#define V4L2_OUT_CAP_NATIVE_SIZE 0x00000008
struct v4l2_control {
  __u32 id;
  __s32 value;
};
struct v4l2_ext_control {
  __u32 id;
  __u32 size;
  __u32 reserved2[1];
  union {
    __s32 value;
    __s64 value64;
    char  * string;
    __u8  * p_u8;
    __u16  * p_u16;
    __u32  * p_u32;
    __s32  * p_s32;
    __s64  * p_s64;
    struct v4l2_area  * p_area;
    struct v4l2_ctrl_h264_sps  * p_h264_sps;
    struct v4l2_ctrl_h264_pps  * p_h264_pps;
    struct v4l2_ctrl_h264_scaling_matrix  * p_h264_scaling_matrix;
    struct v4l2_ctrl_h264_pred_weights  * p_h264_pred_weights;
    struct v4l2_ctrl_h264_slice_params  * p_h264_slice_params;
    struct v4l2_ctrl_h264_decode_params  * p_h264_decode_params;
    struct v4l2_ctrl_fwht_params  * p_fwht_params;
    struct v4l2_ctrl_vp8_frame  * p_vp8_frame;
    struct v4l2_ctrl_mpeg2_sequence  * p_mpeg2_sequence;
    struct v4l2_ctrl_mpeg2_picture  * p_mpeg2_picture;
    struct v4l2_ctrl_mpeg2_quantisation  * p_mpeg2_quantisation;
    struct v4l2_ctrl_vp9_compressed_hdr  * p_vp9_compressed_hdr_probs;
    struct v4l2_ctrl_vp9_frame  * p_vp9_frame;
    struct v4l2_ctrl_hevc_sps  * p_hevc_sps;
    struct v4l2_ctrl_hevc_pps  * p_hevc_pps;
    struct v4l2_ctrl_hevc_slice_params  * p_hevc_slice_params;
    struct v4l2_ctrl_hevc_scaling_matrix  * p_hevc_scaling_matrix;
    struct v4l2_ctrl_hevc_decode_params  * p_hevc_decode_params;
    struct v4l2_ctrl_av1_sequence  * p_av1_sequence;
    struct v4l2_ctrl_av1_tile_group_entry  * p_av1_tile_group_entry;
    struct v4l2_ctrl_av1_frame  * p_av1_frame;
    struct v4l2_ctrl_av1_film_grain  * p_av1_film_grain;
    struct v4l2_ctrl_hdr10_cll_info  * p_hdr10_cll_info;
    struct v4l2_ctrl_hdr10_mastering_display  * p_hdr10_mastering_display;
    void  * ptr;
  } __attribute__((packed));
} __attribute__((packed));
struct v4l2_ext_controls {
  union {
    __u32 ctrl_class;
    __u32 which;
  };
  __u32 count;
  __u32 error_idx;
  __s32 request_fd;
  __u32 reserved[1];
  struct v4l2_ext_control * controls;
};
#define V4L2_CTRL_ID_MASK (0x0fffffff)
#define V4L2_CTRL_ID2CLASS(id) ((id) & 0x0fff0000UL)
#define V4L2_CTRL_ID2WHICH(id) ((id) & 0x0fff0000UL)
#define V4L2_CTRL_DRIVER_PRIV(id) (((id) & 0xffff) >= 0x1000)
#define V4L2_CTRL_MAX_DIMS (4)
#define V4L2_CTRL_WHICH_CUR_VAL 0
#define V4L2_CTRL_WHICH_DEF_VAL 0x0f000000
#define V4L2_CTRL_WHICH_REQUEST_VAL 0x0f010000
enum v4l2_ctrl_type {
  V4L2_CTRL_TYPE_INTEGER = 1,
  V4L2_CTRL_TYPE_BOOLEAN = 2,
  V4L2_CTRL_TYPE_MENU = 3,
  V4L2_CTRL_TYPE_BUTTON = 4,
  V4L2_CTRL_TYPE_INTEGER64 = 5,
  V4L2_CTRL_TYPE_CTRL_CLASS = 6,
  V4L2_CTRL_TYPE_STRING = 7,
  V4L2_CTRL_TYPE_BITMASK = 8,
  V4L2_CTRL_TYPE_INTEGER_MENU = 9,
  V4L2_CTRL_COMPOUND_TYPES = 0x0100,
  V4L2_CTRL_TYPE_U8 = 0x0100,
  V4L2_CTRL_TYPE_U16 = 0x0101,
  V4L2_CTRL_TYPE_U32 = 0x0102,
  V4L2_CTRL_TYPE_AREA = 0x0106,
  V4L2_CTRL_TYPE_HDR10_CLL_INFO = 0x0110,
  V4L2_CTRL_TYPE_HDR10_MASTERING_DISPLAY = 0x0111,
  V4L2_CTRL_TYPE_H264_SPS = 0x0200,
  V4L2_CTRL_TYPE_H264_PPS = 0x0201,
  V4L2_CTRL_TYPE_H264_SCALING_MATRIX = 0x0202,
  V4L2_CTRL_TYPE_H264_SLICE_PARAMS = 0x0203,
  V4L2_CTRL_TYPE_H264_DECODE_PARAMS = 0x0204,
  V4L2_CTRL_TYPE_H264_PRED_WEIGHTS = 0x0205,
  V4L2_CTRL_TYPE_FWHT_PARAMS = 0x0220,
  V4L2_CTRL_TYPE_VP8_FRAME = 0x0240,
  V4L2_CTRL_TYPE_MPEG2_QUANTISATION = 0x0250,
  V4L2_CTRL_TYPE_MPEG2_SEQUENCE = 0x0251,
  V4L2_CTRL_TYPE_MPEG2_PICTURE = 0x0252,
  V4L2_CTRL_TYPE_VP9_COMPRESSED_HDR = 0x0260,
  V4L2_CTRL_TYPE_VP9_FRAME = 0x0261,
  V4L2_CTRL_TYPE_HEVC_SPS = 0x0270,
  V4L2_CTRL_TYPE_HEVC_PPS = 0x0271,
  V4L2_CTRL_TYPE_HEVC_SLICE_PARAMS = 0x0272,
  V4L2_CTRL_TYPE_HEVC_SCALING_MATRIX = 0x0273,
  V4L2_CTRL_TYPE_HEVC_DECODE_PARAMS = 0x0274,
  V4L2_CTRL_TYPE_AV1_SEQUENCE = 0x280,
  V4L2_CTRL_TYPE_AV1_TILE_GROUP_ENTRY = 0x281,
  V4L2_CTRL_TYPE_AV1_FRAME = 0x282,
  V4L2_CTRL_TYPE_AV1_FILM_GRAIN = 0x283,
};
struct v4l2_queryctrl {
  __u32 id;
  __u32 type;
  __u8 name[32];
  __s32 minimum;
  __s32 maximum;
  __s32 step;
  __s32 default_value;
  __u32 flags;
  __u32 reserved[2];
};
struct v4l2_query_ext_ctrl {
  __u32 id;
  __u32 type;
  char name[32];
  __s64 minimum;
  __s64 maximum;
  __u64 step;
  __s64 default_value;
  __u32 flags;
  __u32 elem_size;
  __u32 elems;
  __u32 nr_of_dims;
  __u32 dims[V4L2_CTRL_MAX_DIMS];
  __u32 reserved[32];
};
struct v4l2_querymenu {
  __u32 id;
  __u32 index;
  union {
    __u8 name[32];
    __s64 value;
  };
  __u32 reserved;
} __attribute__((packed));
#define V4L2_CTRL_FLAG_DISABLED 0x0001
#define V4L2_CTRL_FLAG_GRABBED 0x0002
#define V4L2_CTRL_FLAG_READ_ONLY 0x0004
#define V4L2_CTRL_FLAG_UPDATE 0x0008
#define V4L2_CTRL_FLAG_INACTIVE 0x0010
#define V4L2_CTRL_FLAG_SLIDER 0x0020
#define V4L2_CTRL_FLAG_WRITE_ONLY 0x0040
#define V4L2_CTRL_FLAG_VOLATILE 0x0080
#define V4L2_CTRL_FLAG_HAS_PAYLOAD 0x0100
#define V4L2_CTRL_FLAG_EXECUTE_ON_WRITE 0x0200
#define V4L2_CTRL_FLAG_MODIFY_LAYOUT 0x0400
#define V4L2_CTRL_FLAG_DYNAMIC_ARRAY 0x0800
#define V4L2_CTRL_FLAG_NEXT_CTRL 0x80000000
#define V4L2_CTRL_FLAG_NEXT_COMPOUND 0x40000000
#define V4L2_CID_MAX_CTRLS 1024
#define V4L2_CID_PRIVATE_BASE 0x08000000
struct v4l2_tuner {
  __u32 index;
  __u8 name[32];
  __u32 type;
  __u32 capability;
  __u32 rangelow;
  __u32 rangehigh;
  __u32 rxsubchans;
  __u32 audmode;
  __s32 signal;
  __s32 afc;
  __u32 reserved[4];
};
struct v4l2_modulator {
  __u32 index;
  __u8 name[32];
  __u32 capability;
  __u32 rangelow;
  __u32 rangehigh;
  __u32 txsubchans;
  __u32 type;
  __u32 reserved[3];
};
#define V4L2_TUNER_CAP_LOW 0x0001
#define V4L2_TUNER_CAP_NORM 0x0002
#define V4L2_TUNER_CAP_HWSEEK_BOUNDED 0x0004
#define V4L2_TUNER_CAP_HWSEEK_WRAP 0x0008
#define V4L2_TUNER_CAP_STEREO 0x0010
#define V4L2_TUNER_CAP_LANG2 0x0020
#define V4L2_TUNER_CAP_SAP 0x0020
#define V4L2_TUNER_CAP_LANG1 0x0040
#define V4L2_TUNER_CAP_RDS 0x0080
#define V4L2_TUNER_CAP_RDS_BLOCK_IO 0x0100
#define V4L2_TUNER_CAP_RDS_CONTROLS 0x0200
#define V4L2_TUNER_CAP_FREQ_BANDS 0x0400
#define V4L2_TUNER_CAP_HWSEEK_PROG_LIM 0x0800
#define V4L2_TUNER_CAP_1HZ 0x1000
#define V4L2_TUNER_SUB_MONO 0x0001
#define V4L2_TUNER_SUB_STEREO 0x0002
#define V4L2_TUNER_SUB_LANG2 0x0004
#define V4L2_TUNER_SUB_SAP 0x0004
#define V4L2_TUNER_SUB_LANG1 0x0008
#define V4L2_TUNER_SUB_RDS 0x0010
#define V4L2_TUNER_MODE_MONO 0x0000
#define V4L2_TUNER_MODE_STEREO 0x0001
#define V4L2_TUNER_MODE_LANG2 0x0002
#define V4L2_TUNER_MODE_SAP 0x0002
#define V4L2_TUNER_MODE_LANG1 0x0003
#define V4L2_TUNER_MODE_LANG1_LANG2 0x0004
struct v4l2_frequency {
  __u32 tuner;
  __u32 type;
  __u32 frequency;
  __u32 reserved[8];
};
#define V4L2_BAND_MODULATION_VSB (1 << 1)
#define V4L2_BAND_MODULATION_FM (1 << 2)
#define V4L2_BAND_MODULATION_AM (1 << 3)
struct v4l2_frequency_band {
  __u32 tuner;
  __u32 type;
  __u32 index;
  __u32 capability;
  __u32 rangelow;
  __u32 rangehigh;
  __u32 modulation;
  __u32 reserved[9];
};
struct v4l2_hw_freq_seek {
  __u32 tuner;
  __u32 type;
  __u32 seek_upward;
  __u32 wrap_around;
  __u32 spacing;
  __u32 rangelow;
  __u32 rangehigh;
  __u32 reserved[5];
};
struct v4l2_rds_data {
  __u8 lsb;
  __u8 msb;
  __u8 block;
} __attribute__((packed));
#define V4L2_RDS_BLOCK_MSK 0x7
#define V4L2_RDS_BLOCK_A 0
#define V4L2_RDS_BLOCK_B 1
#define V4L2_RDS_BLOCK_C 2
#define V4L2_RDS_BLOCK_D 3
#define V4L2_RDS_BLOCK_C_ALT 4
#define V4L2_RDS_BLOCK_INVALID 7
#define V4L2_RDS_BLOCK_CORRECTED 0x40
#define V4L2_RDS_BLOCK_ERROR 0x80
struct v4l2_audio {
  __u32 index;
  __u8 name[32];
  __u32 capability;
  __u32 mode;
  __u32 reserved[2];
};
#define V4L2_AUDCAP_STEREO 0x00001
#define V4L2_AUDCAP_AVL 0x00002
#define V4L2_AUDMODE_AVL 0x00001
struct v4l2_audioout {
  __u32 index;
  __u8 name[32];
  __u32 capability;
  __u32 mode;
  __u32 reserved[2];
};
#define V4L2_ENC_IDX_FRAME_I (0)
#define V4L2_ENC_IDX_FRAME_P (1)
#define V4L2_ENC_IDX_FRAME_B (2)
#define V4L2_ENC_IDX_FRAME_MASK (0xf)
struct v4l2_enc_idx_entry {
  __u64 offset;
  __u64 pts;
  __u32 length;
  __u32 flags;
  __u32 reserved[2];
};
#define V4L2_ENC_IDX_ENTRIES (64)
struct v4l2_enc_idx {
  __u32 entries;
  __u32 entries_cap;
  __u32 reserved[4];
  struct v4l2_enc_idx_entry entry[V4L2_ENC_IDX_ENTRIES];
};
#define V4L2_ENC_CMD_START (0)
#define V4L2_ENC_CMD_STOP (1)
#define V4L2_ENC_CMD_PAUSE (2)
#define V4L2_ENC_CMD_RESUME (3)
#define V4L2_ENC_CMD_STOP_AT_GOP_END (1 << 0)
struct v4l2_encoder_cmd {
  __u32 cmd;
  __u32 flags;
  union {
    struct {
      __u32 data[8];
    } raw;
  };
};
#define V4L2_DEC_CMD_START (0)
#define V4L2_DEC_CMD_STOP (1)
#define V4L2_DEC_CMD_PAUSE (2)
#define V4L2_DEC_CMD_RESUME (3)
#define V4L2_DEC_CMD_FLUSH (4)
#define V4L2_DEC_CMD_START_MUTE_AUDIO (1 << 0)
#define V4L2_DEC_CMD_PAUSE_TO_BLACK (1 << 0)
#define V4L2_DEC_CMD_STOP_TO_BLACK (1 << 0)
#define V4L2_DEC_CMD_STOP_IMMEDIATELY (1 << 1)
#define V4L2_DEC_START_FMT_NONE (0)
#define V4L2_DEC_START_FMT_GOP (1)
struct v4l2_decoder_cmd {
  __u32 cmd;
  __u32 flags;
  union {
    struct {
      __u64 pts;
    } stop;
    struct {
      __s32 speed;
      __u32 format;
    } start;
    struct {
      __u32 data[16];
    } raw;
  };
};
struct v4l2_vbi_format {
  __u32 sampling_rate;
  __u32 offset;
  __u32 samples_per_line;
  __u32 sample_format;
  __s32 start[2];
  __u32 count[2];
  __u32 flags;
  __u32 reserved[2];
};
#define V4L2_VBI_UNSYNC (1 << 0)
#define V4L2_VBI_INTERLACED (1 << 1)
#define V4L2_VBI_ITU_525_F1_START (1)
#define V4L2_VBI_ITU_525_F2_START (264)
#define V4L2_VBI_ITU_625_F1_START (1)
#define V4L2_VBI_ITU_625_F2_START (314)
struct v4l2_sliced_vbi_format {
  __u16 service_set;
  __u16 service_lines[2][24];
  __u32 io_size;
  __u32 reserved[2];
};
#define V4L2_SLICED_TELETEXT_B (0x0001)
#define V4L2_SLICED_VPS (0x0400)
#define V4L2_SLICED_CAPTION_525 (0x1000)
#define V4L2_SLICED_WSS_625 (0x4000)
#define V4L2_SLICED_VBI_525 (V4L2_SLICED_CAPTION_525)
#define V4L2_SLICED_VBI_625 (V4L2_SLICED_TELETEXT_B | V4L2_SLICED_VPS | V4L2_SLICED_WSS_625)
struct v4l2_sliced_vbi_cap {
  __u16 service_set;
  __u16 service_lines[2][24];
  __u32 type;
  __u32 reserved[3];
};
struct v4l2_sliced_vbi_data {
  __u32 id;
  __u32 field;
  __u32 line;
  __u32 reserved;
  __u8 data[48];
};
#define V4L2_MPEG_VBI_IVTV_TELETEXT_B (1)
#define V4L2_MPEG_VBI_IVTV_CAPTION_525 (4)
#define V4L2_MPEG_VBI_IVTV_WSS_625 (5)
#define V4L2_MPEG_VBI_IVTV_VPS (7)
struct v4l2_mpeg_vbi_itv0_line {
  __u8 id;
  __u8 data[42];
} __attribute__((packed));
struct v4l2_mpeg_vbi_itv0 {
  __le32 linemask[2];
  struct v4l2_mpeg_vbi_itv0_line line[35];
} __attribute__((packed));
struct v4l2_mpeg_vbi_ITV0 {
  struct v4l2_mpeg_vbi_itv0_line line[36];
} __attribute__((packed));
#define V4L2_MPEG_VBI_IVTV_MAGIC0 "itv0"
#define V4L2_MPEG_VBI_IVTV_MAGIC1 "ITV0"
struct v4l2_mpeg_vbi_fmt_ivtv {
  __u8 magic[4];
  union {
    struct v4l2_mpeg_vbi_itv0 itv0;
    struct v4l2_mpeg_vbi_ITV0 ITV0;
  };
} __attribute__((packed));
struct v4l2_plane_pix_format {
  __u32 sizeimage;
  __u32 bytesperline;
  __u16 reserved[6];
} __attribute__((packed));
struct v4l2_pix_format_mplane {
  __u32 width;
  __u32 height;
  __u32 pixelformat;
  __u32 field;
  __u32 colorspace;
  struct v4l2_plane_pix_format plane_fmt[VIDEO_MAX_PLANES];
  __u8 num_planes;
  __u8 flags;
  union {
    __u8 ycbcr_enc;
    __u8 hsv_enc;
  };
  __u8 quantization;
  __u8 xfer_func;
  __u8 reserved[7];
} __attribute__((packed));
struct v4l2_sdr_format {
  __u32 pixelformat;
  __u32 buffersize;
  __u8 reserved[24];
} __attribute__((packed));
struct v4l2_meta_format {
  __u32 dataformat;
  __u32 buffersize;
  __u32 width;
  __u32 height;
  __u32 bytesperline;
} __attribute__((packed));
struct v4l2_format {
  __u32 type;
  union {
    struct v4l2_pix_format pix;
    struct v4l2_pix_format_mplane pix_mp;
    struct v4l2_window win;
    struct v4l2_vbi_format vbi;
    struct v4l2_sliced_vbi_format sliced;
    struct v4l2_sdr_format sdr;
    struct v4l2_meta_format meta;
    __u8 raw_data[200];
  } fmt;
};
struct v4l2_streamparm {
  __u32 type;
  union {
    struct v4l2_captureparm capture;
    struct v4l2_outputparm output;
    __u8 raw_data[200];
  } parm;
};
#define V4L2_EVENT_ALL 0
#define V4L2_EVENT_VSYNC 1
#define V4L2_EVENT_EOS 2
#define V4L2_EVENT_CTRL 3
#define V4L2_EVENT_FRAME_SYNC 4
#define V4L2_EVENT_SOURCE_CHANGE 5
#define V4L2_EVENT_MOTION_DET 6
#define V4L2_EVENT_PRIVATE_START 0x08000000
struct v4l2_event_vsync {
  __u8 field;
} __attribute__((packed));
#define V4L2_EVENT_CTRL_CH_VALUE (1 << 0)
#define V4L2_EVENT_CTRL_CH_FLAGS (1 << 1)
#define V4L2_EVENT_CTRL_CH_RANGE (1 << 2)
#define V4L2_EVENT_CTRL_CH_DIMENSIONS (1 << 3)
struct v4l2_event_ctrl {
  __u32 changes;
  __u32 type;
  union {
    __s32 value;
    __s64 value64;
  };
  __u32 flags;
  __s32 minimum;
  __s32 maximum;
  __s32 step;
  __s32 default_value;
};
struct v4l2_event_frame_sync {
  __u32 frame_sequence;
};
#define V4L2_EVENT_SRC_CH_RESOLUTION (1 << 0)
struct v4l2_event_src_change {
  __u32 changes;
};
#define V4L2_EVENT_MD_FL_HAVE_FRAME_SEQ (1 << 0)
struct v4l2_event_motion_det {
  __u32 flags;
  __u32 frame_sequence;
  __u32 region_mask;
};
struct v4l2_event {
  __u32 type;
  union {
    struct v4l2_event_vsync vsync;
    struct v4l2_event_ctrl ctrl;
    struct v4l2_event_frame_sync frame_sync;
    struct v4l2_event_src_change src_change;
    struct v4l2_event_motion_det motion_det;
    __u8 data[64];
  } u;
  __u32 pending;
  __u32 sequence;
  struct timespec timestamp;
  __u32 id;
  __u32 reserved[8];
};
#define V4L2_EVENT_SUB_FL_SEND_INITIAL (1 << 0)
#define V4L2_EVENT_SUB_FL_ALLOW_FEEDBACK (1 << 1)
struct v4l2_event_subscription {
  __u32 type;
  __u32 id;
  __u32 flags;
  __u32 reserved[5];
};
#define V4L2_CHIP_MATCH_BRIDGE 0
#define V4L2_CHIP_MATCH_SUBDEV 4
#define V4L2_CHIP_MATCH_HOST V4L2_CHIP_MATCH_BRIDGE
#define V4L2_CHIP_MATCH_I2C_DRIVER 1
#define V4L2_CHIP_MATCH_I2C_ADDR 2
#define V4L2_CHIP_MATCH_AC97 3
struct v4l2_dbg_match {
  __u32 type;
  union {
    __u32 addr;
    char name[32];
  };
} __attribute__((packed));
struct v4l2_dbg_register {
  struct v4l2_dbg_match match;
  __u32 size;
  __u64 reg;
  __u64 val;
} __attribute__((packed));
#define V4L2_CHIP_FL_READABLE (1 << 0)
#define V4L2_CHIP_FL_WRITABLE (1 << 1)
struct v4l2_dbg_chip_info {
  struct v4l2_dbg_match match;
  char name[32];
  __u32 flags;
  __u32 reserved[32];
} __attribute__((packed));
struct v4l2_create_buffers {
  __u32 index;
  __u32 count;
  __u32 memory;
  struct v4l2_format format;
  __u32 capabilities;
  __u32 flags;
  __u32 max_num_buffers;
  __u32 reserved[5];
};
struct v4l2_remove_buffers {
  __u32 index;
  __u32 count;
  __u32 type;
  __u32 reserved[13];
};
#define VIDIOC_QUERYCAP _IOR('V', 0, struct v4l2_capability)
#define VIDIOC_ENUM_FMT _IOWR('V', 2, struct v4l2_fmtdesc)
#define VIDIOC_G_FMT _IOWR('V', 4, struct v4l2_format)
#define VIDIOC_S_FMT _IOWR('V', 5, struct v4l2_format)
#define VIDIOC_REQBUFS _IOWR('V', 8, struct v4l2_requestbuffers)
#define VIDIOC_QUERYBUF _IOWR('V', 9, struct v4l2_buffer)
#define VIDIOC_G_FBUF _IOR('V', 10, struct v4l2_framebuffer)
#define VIDIOC_S_FBUF _IOW('V', 11, struct v4l2_framebuffer)
#define VIDIOC_OVERLAY _IOW('V', 14, int)
#define VIDIOC_QBUF _IOWR('V', 15, struct v4l2_buffer)
#define VIDIOC_EXPBUF _IOWR('V', 16, struct v4l2_exportbuffer)
#define VIDIOC_DQBUF _IOWR('V', 17, struct v4l2_buffer)
#define VIDIOC_STREAMON _IOW('V', 18, int)
#define VIDIOC_STREAMOFF _IOW('V', 19, int)
#define VIDIOC_G_PARM _IOWR('V', 21, struct v4l2_streamparm)
#define VIDIOC_S_PARM _IOWR('V', 22, struct v4l2_streamparm)
#define VIDIOC_G_STD _IOR('V', 23, v4l2_std_id)
#define VIDIOC_S_STD _IOW('V', 24, v4l2_std_id)
#define VIDIOC_ENUMSTD _IOWR('V', 25, struct v4l2_standard)
#define VIDIOC_ENUMINPUT _IOWR('V', 26, struct v4l2_input)
#define VIDIOC_G_CTRL _IOWR('V', 27, struct v4l2_control)
#define VIDIOC_S_CTRL _IOWR('V', 28, struct v4l2_control)
#define VIDIOC_G_TUNER _IOWR('V', 29, struct v4l2_tuner)
#define VIDIOC_S_TUNER _IOW('V', 30, struct v4l2_tuner)
#define VIDIOC_G_AUDIO _IOR('V', 33, struct v4l2_audio)
#define VIDIOC_S_AUDIO _IOW('V', 34, struct v4l2_audio)
#define VIDIOC_QUERYCTRL _IOWR('V', 36, struct v4l2_queryctrl)
#define VIDIOC_QUERYMENU _IOWR('V', 37, struct v4l2_querymenu)
#define VIDIOC_G_INPUT _IOR('V', 38, int)
#define VIDIOC_S_INPUT _IOWR('V', 39, int)
#define VIDIOC_G_EDID _IOWR('V', 40, struct v4l2_edid)
#define VIDIOC_S_EDID _IOWR('V', 41, struct v4l2_edid)
#define VIDIOC_G_OUTPUT _IOR('V', 46, int)
#define VIDIOC_S_OUTPUT _IOWR('V', 47, int)
#define VIDIOC_ENUMOUTPUT _IOWR('V', 48, struct v4l2_output)
#define VIDIOC_G_AUDOUT _IOR('V', 49, struct v4l2_audioout)
#define VIDIOC_S_AUDOUT _IOW('V', 50, struct v4l2_audioout)
#define VIDIOC_G_MODULATOR _IOWR('V', 54, struct v4l2_modulator)
#define VIDIOC_S_MODULATOR _IOW('V', 55, struct v4l2_modulator)
#define VIDIOC_G_FREQUENCY _IOWR('V', 56, struct v4l2_frequency)
#define VIDIOC_S_FREQUENCY _IOW('V', 57, struct v4l2_frequency)
#define VIDIOC_CROPCAP _IOWR('V', 58, struct v4l2_cropcap)
#define VIDIOC_G_CROP _IOWR('V', 59, struct v4l2_crop)
#define VIDIOC_S_CROP _IOW('V', 60, struct v4l2_crop)
#define VIDIOC_G_JPEGCOMP _IOR('V', 61, struct v4l2_jpegcompression)
#define VIDIOC_S_JPEGCOMP _IOW('V', 62, struct v4l2_jpegcompression)
#define VIDIOC_QUERYSTD _IOR('V', 63, v4l2_std_id)
#define VIDIOC_TRY_FMT _IOWR('V', 64, struct v4l2_format)
#define VIDIOC_ENUMAUDIO _IOWR('V', 65, struct v4l2_audio)
#define VIDIOC_ENUMAUDOUT _IOWR('V', 66, struct v4l2_audioout)
#define VIDIOC_G_PRIORITY _IOR('V', 67, __u32)
#define VIDIOC_S_PRIORITY _IOW('V', 68, __u32)
#define VIDIOC_G_SLICED_VBI_CAP _IOWR('V', 69, struct v4l2_sliced_vbi_cap)
#define VIDIOC_LOG_STATUS _IO('V', 70)
#define VIDIOC_G_EXT_CTRLS _IOWR('V', 71, struct v4l2_ext_controls)
#define VIDIOC_S_EXT_CTRLS _IOWR('V', 72, struct v4l2_ext_controls)
#define VIDIOC_TRY_EXT_CTRLS _IOWR('V', 73, struct v4l2_ext_controls)
#define VIDIOC_ENUM_FRAMESIZES _IOWR('V', 74, struct v4l2_frmsizeenum)
#define VIDIOC_ENUM_FRAMEINTERVALS _IOWR('V', 75, struct v4l2_frmivalenum)
#define VIDIOC_G_ENC_INDEX _IOR('V', 76, struct v4l2_enc_idx)
#define VIDIOC_ENCODER_CMD _IOWR('V', 77, struct v4l2_encoder_cmd)
#define VIDIOC_TRY_ENCODER_CMD _IOWR('V', 78, struct v4l2_encoder_cmd)
#define VIDIOC_DBG_S_REGISTER _IOW('V', 79, struct v4l2_dbg_register)
#define VIDIOC_DBG_G_REGISTER _IOWR('V', 80, struct v4l2_dbg_register)
#define VIDIOC_S_HW_FREQ_SEEK _IOW('V', 82, struct v4l2_hw_freq_seek)
#define VIDIOC_S_DV_TIMINGS _IOWR('V', 87, struct v4l2_dv_timings)
#define VIDIOC_G_DV_TIMINGS _IOWR('V', 88, struct v4l2_dv_timings)
#define VIDIOC_DQEVENT _IOR('V', 89, struct v4l2_event)
#define VIDIOC_SUBSCRIBE_EVENT _IOW('V', 90, struct v4l2_event_subscription)
#define VIDIOC_UNSUBSCRIBE_EVENT _IOW('V', 91, struct v4l2_event_subscription)
#define VIDIOC_CREATE_BUFS _IOWR('V', 92, struct v4l2_create_buffers)
#define VIDIOC_PREPARE_BUF _IOWR('V', 93, struct v4l2_buffer)
#define VIDIOC_G_SELECTION _IOWR('V', 94, struct v4l2_selection)
#define VIDIOC_S_SELECTION _IOWR('V', 95, struct v4l2_selection)
#define VIDIOC_DECODER_CMD _IOWR('V', 96, struct v4l2_decoder_cmd)
#define VIDIOC_TRY_DECODER_CMD _IOWR('V', 97, struct v4l2_decoder_cmd)
#define VIDIOC_ENUM_DV_TIMINGS _IOWR('V', 98, struct v4l2_enum_dv_timings)
#define VIDIOC_QUERY_DV_TIMINGS _IOR('V', 99, struct v4l2_dv_timings)
#define VIDIOC_DV_TIMINGS_CAP _IOWR('V', 100, struct v4l2_dv_timings_cap)
#define VIDIOC_ENUM_FREQ_BANDS _IOWR('V', 101, struct v4l2_frequency_band)
#define VIDIOC_DBG_G_CHIP_INFO _IOWR('V', 102, struct v4l2_dbg_chip_info)
#define VIDIOC_QUERY_EXT_CTRL _IOWR('V', 103, struct v4l2_query_ext_ctrl)
#define VIDIOC_REMOVE_BUFS _IOWR('V', 104, struct v4l2_remove_buffers)
#define BASE_VIDIOC_PRIVATE 192
#define V4L2_PIX_FMT_HM12 V4L2_PIX_FMT_NV12_16L16
#define V4L2_PIX_FMT_SUNXI_TILED_NV12 V4L2_PIX_FMT_NV12_32L32
#define V4L2_CAP_ASYNCIO 0x02000000
#endif
```