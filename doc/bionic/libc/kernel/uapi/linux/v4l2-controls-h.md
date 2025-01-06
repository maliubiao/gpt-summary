Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Request:**

The fundamental goal is to analyze a C header file (`v4l2-controls.h`) within the Android Bionic library and explain its purpose and relevance to Android. The prompt emphasizes detailing functionality, Android integration, low-level details (libc, dynamic linker), debugging, and common errors. It's a deep dive request.

**2. Initial Analysis of the Header File:**

The first step is to recognize the core purpose of the file. The `#define` macros and `enum` definitions strongly suggest that this file defines constants and types related to the Video4Linux2 (V4L2) API. Keywords like `V4L2_CTRL_CLASS_`, `V4L2_CID_`, and the names of controls (brightness, contrast, various codec parameters) confirm this. The comment at the beginning explicitly states it's auto-generated and part of the Bionic library's kernel headers.

**3. Identifying Key Functional Areas:**

Based on the content, the file's functions can be grouped:

* **Control Class Definitions:**  Macros like `V4L2_CTRL_CLASS_USER`, `V4L2_CTRL_CLASS_CODEC`, etc., categorize different types of V4L2 controls.
* **Control ID Definitions:** Macros starting with `V4L2_CID_` define specific control IDs, often grouped by class. Examples include basic user controls (brightness, contrast), audio controls, and a large section dedicated to MPEG video encoding parameters.
* **Enumerated Types:**  `enum` definitions provide sets of possible values for certain controls (e.g., power line frequency, color effects, audio encoding).

**4. Connecting to Android Functionality:**

The next crucial step is to link these V4L2 controls to Android's multimedia framework. This requires some domain knowledge about how Android handles cameras and video.

* **Cameras:** The most obvious connection is to the Android camera subsystem. Controls like brightness, contrast, focus, white balance, and color effects directly map to settings that users can adjust in camera apps.
* **Video Encoding/Decoding:** The extensive set of MPEG-related controls points to Android's media codecs. Android uses hardware and software codecs to encode and decode video for recording, playback, and streaming.
* **Media Framework (Camera Service, MediaCodec):**  These Android framework components are the primary users of V4L2. The Camera Service interacts with the kernel driver for camera access, and `MediaCodec` utilizes codecs, which in turn might configure underlying V4L2 devices.

**5. Addressing Specific Prompt Requirements:**

* **Function Listing:** This is straightforward. Summarize the identified key functional areas.
* **Android Relationship and Examples:**  Provide concrete examples of how each functional area relates to Android features (camera settings, video recording formats, etc.).
* **libc Function Details:** This is where the prompt becomes tricky. This header file *doesn't define libc functions*. It defines *constants* used by programs that *call* libc functions (like `ioctl`). It's important to clarify this distinction. The *use* of these constants within `ioctl` needs to be explained.
* **Dynamic Linker:** Similarly, this header file itself doesn't directly involve the dynamic linker. However, the libraries that *use* these constants (like camera HALs or media codecs) *are* dynamically linked. Therefore, providing a typical `.so` layout and explaining the linking process (using `dlopen`, `dlsym`, etc.) is relevant, even though the header itself isn't directly linked.
* **Logical Inference (Assumptions):**  This mainly applies to how these constants are *used*. For example, assuming an application sets a brightness value and how that translates to an `ioctl` call with a specific `V4L2_CID_BRIGHTNESS` value.
* **Common Usage Errors:**  Focus on errors related to using these constants incorrectly, such as passing invalid values to `ioctl` or misinterpreting the meaning of specific control IDs.
* **Android Framework/NDK Path:**  Illustrate the chain of calls from the high-level Android framework down to the kernel level where these constants are used. Camera apps -> Camera Service -> HAL -> Kernel Driver (using V4L2).
* **Frida Hook Example:** Provide a practical example of how to use Frida to intercept `ioctl` calls and inspect the control IDs and values being passed, demonstrating how these constants are used at runtime.

**6. Structuring the Answer:**

Organize the response logically, addressing each part of the prompt. Use headings and bullet points for clarity. Start with a summary, then delve into details.

**7. Refining the Language:**

Use precise and clear language. Explain technical terms. Acknowledge limitations (e.g., not defining libc functions).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on the *definition* of the constants might miss the bigger picture of their *usage*.
* **Correction:** Shift focus to how these constants are used within the V4L2 API calls, particularly `ioctl`.
* **Initial thought:** Directly linking this header file to the dynamic linker is inaccurate.
* **Correction:** Explain the role of the dynamic linker in loading the libraries that *use* this header file.
* **Initial thought:**  Providing a generic `ioctl` example might not be specific enough.
* **Correction:**  Tailor the `ioctl` example to setting a V4L2 control, making it more relevant to the header file.

By following these steps, the comprehensive and informative answer provided earlier can be constructed. The key is to understand the core purpose of the file, connect it to the broader Android ecosystem, and address each aspect of the prompt with relevant technical details and examples.
好的，这是对提供的C头文件 `bionic/libc/kernel/uapi/linux/v4l2-controls.h` 第一部分的分析和功能归纳。

**功能归纳（针对第一部分）：**

这个头文件定义了大量的常量（宏定义）和枚举类型，这些常量和类型用于标识和操作Linux V4L2（Video for Linux version 2）控制接口中的各种控制项。  简单来说，它为用户空间程序提供了访问和配置视频设备（如摄像头）各种属性的“词汇表”。

**更具体地，第一部分主要定义了以下内容：**

1. **V4L2 控制类 (Control Classes):**
   - 定义了各种控制项所属的类别，例如：用户自定义控制、编解码器控制、摄像头控制、闪光灯控制等等。
   - 这些类别用 `V4L2_CTRL_CLASS_` 前缀的宏表示，例如 `V4L2_CTRL_CLASS_USER`，`V4L2_CTRL_CLASS_CAMERA`。
   - 这种分类有助于组织和管理大量的控制项。

2. **基本的 V4L2 控制 ID (Control IDs):**
   - 定义了具体的控制项的唯一标识符，例如亮度、对比度、饱和度、音量、白平衡等等。
   - 这些 ID 用 `V4L2_CID_` 前缀的宏表示，例如 `V4L2_CID_BRIGHTNESS`，`V4L2_CID_AUDIO_VOLUME`。
   - `V4L2_CID_BASE` 是一个基地址，许多控制 ID 基于这个基地址进行偏移。
   - 还有一些用户自定义的控制 ID 基地址，例如 `V4L2_CID_USER_MEYE_BASE` 等，允许硬件或驱动程序添加特定的控制项。

3. **枚举类型 (Enumerated Types):**
   - 为一些具有有限取值的控制项定义了枚举类型，例如电源线频率、色彩特效。
   - 这些枚举类型用 `enum v4l2_` 开头，例如 `enum v4l2_power_line_frequency`， `enum v4l2_colorfx`。
   - 枚举类型中的每个成员都代表该控制项的一个可能值，例如 `V4L2_CID_POWER_LINE_FREQUENCY_50HZ`。

**与 Android 功能的关系及举例说明：**

这个头文件对于 Android 的多媒体功能至关重要，特别是涉及到摄像头和视频编解码的部分。

* **摄像头控制:**
    - Android 的 Camera API 允许应用程序控制摄像头的各种参数。 底层实现中，Android Framework 会通过 HAL (Hardware Abstraction Layer) 与摄像头驱动进行交互。
    - 这个头文件中定义的 `V4L2_CID_BRIGHTNESS`、`V4L2_CID_CONTRAST`、`V4L2_CID_SATURATION` 等控制 ID，直接对应了用户在相机应用中可以调节的亮度、对比度、饱和度等参数。
    - **例如：** 当一个 Android 相机应用的用户调整亮度滑块时，Framework 会调用相应的 HAL 接口，HAL 接口最终可能会使用 `ioctl` 系统调用，并带上 `V4L2_CID_BRIGHTNESS` 这个控制 ID 和新的亮度值，来设置底层的摄像头硬件。

* **视频编解码控制:**
    - Android 的 MediaCodec API 提供了访问硬件和软件编解码器的接口。
    - 这个头文件中 `V4L2_CTRL_CLASS_CODEC` 以及 `V4L2_CID_MPEG_*` 开头的控制 ID，用于配置视频编解码器的各种参数，例如码率、帧率、GOP 大小、编码标准（H.264, H.265, MPEG-4 等）的 Profile 和 Level 等。
    - **例如：** 当一个 Android 应用使用 MediaCodec 进行 H.264 视频编码时，可能会使用 `V4L2_CID_MPEG_VIDEO_BITRATE` 设置编码码率，使用 `V4L2_CID_MPEG_VIDEO_GOP_SIZE` 设置 GOP 大小。

**详细解释每一个 libc 函数的功能是如何实现的:**

**重要提示：**  这个头文件本身 **没有定义任何 libc 函数**。它定义的是 **常量** 和 **枚举类型**。这些常量被用户空间程序使用，作为参数传递给 Linux 系统调用，例如 `ioctl`。

`ioctl` 函数才是 libc 提供的函数，它的功能是向设备驱动程序发送控制命令。

**`ioctl` 函数的功能和实现（简述）：**

`ioctl` 函数的声明通常如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* **`fd` (File Descriptor):**  要控制的设备的文件描述符，通常通过 `open()` 系统调用获得。对于视频设备，这个 `fd` 通常指向 `/dev/videoX` 这样的设备文件。
* **`request` (请求):**  一个与设备相关的请求码，用于告诉驱动程序要执行的具体操作。  在这个上下文中，`request` 通常会包含 V4L2 定义的宏，例如用于设置或获取控制项的 `VIDIOC_S_CTRL` 或 `VIDIOC_G_CTRL`。
* **`...` (可变参数):**  可选的参数，具体取决于 `request` 的值。对于设置或获取控制项，这个参数通常是一个指向 `struct v4l2_control` 或 `struct v4l2_ext_control` 结构的指针。

**实现原理：**

1. 当用户空间程序调用 `ioctl` 时，内核会接收到这个系统调用。
2. 内核会根据 `fd` 找到对应的设备驱动程序。
3. 内核会将 `request` 和可变参数传递给设备驱动程序的 `ioctl` 处理函数。
4. 设备驱动程序会解析 `request`，并根据请求执行相应的操作。 例如，如果 `request` 是 `VIDIOC_S_CTRL` 并且控制 ID 是 `V4L2_CID_BRIGHTNESS`，驱动程序会修改底层摄像头硬件的亮度寄存器。
5. 驱动程序完成操作后，会返回结果给内核，内核再将结果返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及 dynamic linker。 然而，使用这些 V4L2 常量的库（例如 Camera HAL 模块、MediaCodec 库）通常是动态链接库 (.so)。

**so 布局样本 (以 Camera HAL 模块为例):**

```
lib камера.so:
    .text          # 代码段
        ...         # HAL 接口实现代码，例如 openCameraDevice(), setCameraParameters()
                    # 这些函数内部会使用 ioctl 并带上 v4l2-controls.h 中定义的常量
    .rodata        # 只读数据段
        ...
    .data          # 可读写数据段
        ...
    .bss           # 未初始化数据段
        ...
    .dynsym        # 动态符号表
        ioctl       # 声明使用了 ioctl 函数
        ...         # 其他导入的符号
    .dynstr        # 动态字符串表
        libc.so     # 依赖的库
        ...
    .plt           # 过程链接表 (Procedure Linkage Table) 用于延迟绑定
        ioctl@LIBC  # ioctl 函数的 PLT 条目
    .got           # 全局偏移表 (Global Offset Table) 用于存储外部符号的地址
        ioctl@LIBC  # ioctl 函数的 GOT 条目
        ...
```

**链接的处理过程：**

1. **编译时链接：** 当编译 `lib камера.so` 时，编译器会识别出代码中使用了 `ioctl` 函数。由于 `ioctl` 是 libc 的一部分，编译器会在 `.dynsym` 中记录对 `ioctl` 的引用，并在 `.plt` 和 `.got` 中创建相应的条目。
2. **加载时链接（Dynamic Linker 的工作）：**
   - 当 Android 系统需要加载 `lib камера.so` 时，例如当 Camera Service 请求打开摄像头时，dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 会被调用。
   - dynamic linker 会解析 `lib камера.so` 的头部信息，包括 `.dynsym` 和 `.dynstr` 等。
   - 它会检查 `lib камера.so` 依赖的库，例如 `libc.so`。
   - dynamic linker 会加载 `libc.so` 到内存中（如果尚未加载）。
   - **符号解析和重定位：** dynamic linker 会遍历 `lib камера.so` 的 `.rel.plt` 段（重定位表），找到对外部符号（例如 `ioctl`）的引用。
   - 它会在已加载的库（`libc.so`）的符号表中查找 `ioctl` 的地址。
   - 找到 `ioctl` 的地址后，dynamic linker 会更新 `lib камера.so` 的 `.got` 段中 `ioctl@LIBC` 条目的值为 `ioctl` 函数在 `libc.so` 中的实际内存地址。
   - **延迟绑定（Lazy Binding，通常情况下）：**  在首次调用 `ioctl` 时，程序会跳转到 `.plt` 中的 `ioctl@LIBC` 条目。 `.plt` 条目中的代码会调用 dynamic linker 的某个函数来解析符号并更新 `.got` 表。之后对 `ioctl` 的调用会直接通过 `.got` 表跳转到 `ioctl` 的实际地址，避免重复解析。

**如果做了逻辑推理，请给出假设输入与输出:**

假设一个 Camera HAL 模块需要设置摄像头的亮度。

**假设输入：**

* 控制 ID：`V4L2_CID_BRIGHTNESS`
* 目标亮度值：150
* 视频设备文件描述符：`fd` (假设已经通过 `open("/dev/video0", ...)` 获取)

**逻辑推理过程：**

1. HAL 模块会创建一个 `struct v4l2_control` 结构体。
2. 将 `id` 成员设置为 `V4L2_CID_BRIGHTNESS`。
3. 将 `value` 成员设置为 150。
4. 调用 `ioctl(fd, VIDIOC_S_CTRL, &ctrl)`，其中 `ctrl` 是指向上面创建的 `v4l2_control` 结构体的指针。

**预期输出：**

* 如果 `ioctl` 调用成功，返回值通常是 0。
* 底层摄像头硬件的亮度会被设置为 150。
* 如果 `ioctl` 调用失败（例如，设备不支持亮度控制或值超出范围），返回值通常是 -1，并且 `errno` 会被设置为相应的错误码。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用错误的控制 ID：**
   - 错误示例：`ioctl(fd, VIDIOC_S_CTRL, &(struct v4l2_control){ .id = 0x12345678, .value = 100 });`  // 使用了一个不存在或不正确的控制 ID。
   - 结果：`ioctl` 调用可能会失败，并返回 `EINVAL` 错误（Invalid argument）。

2. **设置超出范围的值：**
   - 错误示例： 假设 `V4L2_CID_BRIGHTNESS` 的有效范围是 0-255，但尝试设置 300：
     `ioctl(fd, VIDIOC_S_CTRL, &(struct v4l2_control){ .id = V4L2_CID_BRIGHTNESS, .value = 300 });`
   - 结果：`ioctl` 调用可能会失败，并返回 `ERANGE` 错误（Result too large）。

3. **在不支持的设备上设置控制项：**
   - 错误示例：尝试在一个不支持亮度控制的视频设备上设置亮度。
   - 结果：`ioctl` 调用可能会失败，并返回 `EINVAL` 或其他相关的错误码。

4. **忘记包含必要的头文件：**
   - 错误示例：代码中没有包含 `<linux/videodev2.h>` 或 `<linux/v4l2-controls.h>`，导致 `V4L2_CID_BRIGHTNESS` 等宏未定义。
   - 结果：编译时会报错。

5. **类型不匹配：**
   - 错误示例：某些控制项的值可能需要特定的数据类型。如果传递了错误的类型，可能会导致意外的行为或错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**从 Android Framework 到达 V4L2 控制的过程 (以设置摄像头亮度为例)：**

1. **Android Camera App (Java/Kotlin):** 用户在相机应用中调整亮度滑块。
2. **Camera API (Java):** 相机应用调用 Android Framework 提供的 Camera API，例如 `Camera.Parameters.setBrightness()` 或 `Camera2 API` 中相应的接口。
3. **Camera Service (Java/Native):** Framework 将请求传递给 Camera Service，这是一个系统服务，负责管理摄像头硬件的访问。
4. **Camera HAL (Hardware Abstraction Layer) (Native C/C++):** Camera Service 通过 HAL 接口与特定于硬件的摄像头驱动程序进行交互。 HAL 实现通常位于 `.so` 文件中，例如上面提到的 `lib камера.so`。
5. **V4L2 驱动程序 (Kernel):** HAL 模块会调用底层的 V4L2 驱动程序，通常通过 `ioctl` 系统调用，并使用 `v4l2-controls.h` 中定义的控制 ID（例如 `V4L2_CID_BRIGHTNESS`）和目标值。

**Frida Hook 示例：**

可以使用 Frida Hook `ioctl` 系统调用来观察 Camera HAL 如何使用 V4L2 控制项。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = device.spawn(["com.android.camera"]) # 替换成你的相机应用包名
    process = device.attach(pid)
    device.resume(pid)
except frida.ServerNotStartedError:
    print("请确保 Frida Server 正在 Android 设备上运行")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = ptr(args[1]).toInt32();
        const argp = ptr(args[2]);

        // 检查是否是 V4L2 相关的 ioctl 命令 (这里可以根据 VIDIOC_* 宏进行更精确的判断)
        if ((request & 0xFF00) == 0x5600) { // V4L2 魔数 'V' = 0x56
            this.is_v4l2 = true;
            this.request_str = "Unknown V4L2 Command";

            if (request == 0xc0045601) this.request_str = "VIDIOC_QUERYCAP";
            else if (request == 0xc090560f) this.request_str = "VIDIOC_ENUM_FMT";
            else if (request == 0xc0ac5610) this.request_str = "VIDIOC_S_FMT";
            else if (request == 0xc0ac5604) this.request_str = "VIDIOC_G_FMT";
            else if (request == 0xc00c5618) this.request_str = "VIDIOC_REQBUFS";
            else if (request == 0xc0105615) this.request_str = "VIDIOC_QBUF";
            else if (request == 0xc0105617) this.request_str = "VIDIOC_DQBUF";
            else if (request == 0xc0045632) this.request_str = "VIDIOC_STREAMON";
            else if (request == 0xc0045633) this.request_str = "VIDIOC_STREAMOFF";
            else if (request == 0xc00c560c) this.request_str = "VIDIOC_G_CTRL";
            else if (request == 0xc00c560d) this.request_str = "VIDIOC_S_CTRL";

            send({ type: "v4l2_ioctl", fd: fd, request: this.request_str });

            if (request == 0xc00c560d) { // VIDIOC_S_CTRL
                const ctrl = argp.readByteArray(12); // struct v4l2_control 的大小
                const id = ptr(ctrl).readU32();
                const value = ptr(ctrl).add(4).readS32();

                let control_name = "Unknown Control";
                if (id === 0x00980900) control_name = "V4L2_CID_BRIGHTNESS";
                else if (id === 0x00980901) control_name = "V4L2_CID_CONTRAST";
                // ... 添加其他你感兴趣的控制 ID

                send({ type: "v4l2_control", control_id: id, control_name: control_name, value: value });
            }
        }
    }
});
""";

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 代码解释：**

1. **附加到目标进程：**  代码首先尝试附加到 Android 相机应用的进程。
2. **Hook `ioctl` 函数：** 使用 `Interceptor.attach` 钩住 `libc.so` 中的 `ioctl` 函数。
3. **`onEnter` 处理函数：**  在每次调用 `ioctl` 之前执行。
4. **判断是否是 V4L2 命令：** 通过检查 `request` 参数的魔数来判断是否是 V4L2 相关的 `ioctl` 调用 (V4L2 的命令通常以 `0x56` 开头)。
5. **解析 `VIDIOC_S_CTRL`：** 如果是 `VIDIOC_S_CTRL` 命令，则读取 `argp` 指向的 `struct v4l2_control` 结构体，并解析出 `id` 和 `value` 成员。
6. **匹配控制 ID：** 将解析出的 `id` 与 `v4l2-controls.h` 中定义的宏进行比较，以确定正在设置哪个控制项。
7. **发送消息：** 使用 `send()` 函数将捕获到的信息发送回 Frida 主机，你可以在主机上看到这些信息。

**使用步骤：**

1. 确保你的 Android 设备已 root，并且 Frida Server 正在运行。
2. 将上面的 Python 代码保存为 `hook_camera.py`。
3. 替换代码中的 `"com.android.camera"` 为你实际使用的相机应用包名。
4. 运行 `python3 hook_camera.py`。
5. 在你的 Android 设备上打开相机应用并调整亮度等设置。
6. 你将在运行 Frida 的终端中看到捕获到的 `ioctl` 调用和相关的 V4L2 控制信息。

这个 Frida 示例可以帮助你实时地观察 Android Framework 如何通过 Camera HAL 与底层的 V4L2 驱动进行交互，并验证 `v4l2-controls.h` 中定义的常量是如何被使用的。

希望以上分析能够帮助你理解 `bionic/libc/kernel/uapi/linux/v4l2-controls.handroid bionic` 这个头文件的功能以及它在 Android 系统中的作用。接下来的部分，我会继续分析文件中剩余的内容。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/v4l2-controls.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef __LINUX_V4L2_CONTROLS_H
#define __LINUX_V4L2_CONTROLS_H
#include <linux/const.h>
#include <linux/types.h>
#define V4L2_CTRL_CLASS_USER 0x00980000
#define V4L2_CTRL_CLASS_CODEC 0x00990000
#define V4L2_CTRL_CLASS_CAMERA 0x009a0000
#define V4L2_CTRL_CLASS_FM_TX 0x009b0000
#define V4L2_CTRL_CLASS_FLASH 0x009c0000
#define V4L2_CTRL_CLASS_JPEG 0x009d0000
#define V4L2_CTRL_CLASS_IMAGE_SOURCE 0x009e0000
#define V4L2_CTRL_CLASS_IMAGE_PROC 0x009f0000
#define V4L2_CTRL_CLASS_DV 0x00a00000
#define V4L2_CTRL_CLASS_FM_RX 0x00a10000
#define V4L2_CTRL_CLASS_RF_TUNER 0x00a20000
#define V4L2_CTRL_CLASS_DETECT 0x00a30000
#define V4L2_CTRL_CLASS_CODEC_STATELESS 0x00a40000
#define V4L2_CTRL_CLASS_COLORIMETRY 0x00a50000
#define V4L2_CID_BASE (V4L2_CTRL_CLASS_USER | 0x900)
#define V4L2_CID_USER_BASE V4L2_CID_BASE
#define V4L2_CID_USER_CLASS (V4L2_CTRL_CLASS_USER | 1)
#define V4L2_CID_BRIGHTNESS (V4L2_CID_BASE + 0)
#define V4L2_CID_CONTRAST (V4L2_CID_BASE + 1)
#define V4L2_CID_SATURATION (V4L2_CID_BASE + 2)
#define V4L2_CID_HUE (V4L2_CID_BASE + 3)
#define V4L2_CID_AUDIO_VOLUME (V4L2_CID_BASE + 5)
#define V4L2_CID_AUDIO_BALANCE (V4L2_CID_BASE + 6)
#define V4L2_CID_AUDIO_BASS (V4L2_CID_BASE + 7)
#define V4L2_CID_AUDIO_TREBLE (V4L2_CID_BASE + 8)
#define V4L2_CID_AUDIO_MUTE (V4L2_CID_BASE + 9)
#define V4L2_CID_AUDIO_LOUDNESS (V4L2_CID_BASE + 10)
#define V4L2_CID_BLACK_LEVEL (V4L2_CID_BASE + 11)
#define V4L2_CID_AUTO_WHITE_BALANCE (V4L2_CID_BASE + 12)
#define V4L2_CID_DO_WHITE_BALANCE (V4L2_CID_BASE + 13)
#define V4L2_CID_RED_BALANCE (V4L2_CID_BASE + 14)
#define V4L2_CID_BLUE_BALANCE (V4L2_CID_BASE + 15)
#define V4L2_CID_GAMMA (V4L2_CID_BASE + 16)
#define V4L2_CID_WHITENESS (V4L2_CID_GAMMA)
#define V4L2_CID_EXPOSURE (V4L2_CID_BASE + 17)
#define V4L2_CID_AUTOGAIN (V4L2_CID_BASE + 18)
#define V4L2_CID_GAIN (V4L2_CID_BASE + 19)
#define V4L2_CID_HFLIP (V4L2_CID_BASE + 20)
#define V4L2_CID_VFLIP (V4L2_CID_BASE + 21)
#define V4L2_CID_POWER_LINE_FREQUENCY (V4L2_CID_BASE + 24)
enum v4l2_power_line_frequency {
  V4L2_CID_POWER_LINE_FREQUENCY_DISABLED = 0,
  V4L2_CID_POWER_LINE_FREQUENCY_50HZ = 1,
  V4L2_CID_POWER_LINE_FREQUENCY_60HZ = 2,
  V4L2_CID_POWER_LINE_FREQUENCY_AUTO = 3,
};
#define V4L2_CID_HUE_AUTO (V4L2_CID_BASE + 25)
#define V4L2_CID_WHITE_BALANCE_TEMPERATURE (V4L2_CID_BASE + 26)
#define V4L2_CID_SHARPNESS (V4L2_CID_BASE + 27)
#define V4L2_CID_BACKLIGHT_COMPENSATION (V4L2_CID_BASE + 28)
#define V4L2_CID_CHROMA_AGC (V4L2_CID_BASE + 29)
#define V4L2_CID_COLOR_KILLER (V4L2_CID_BASE + 30)
#define V4L2_CID_COLORFX (V4L2_CID_BASE + 31)
enum v4l2_colorfx {
  V4L2_COLORFX_NONE = 0,
  V4L2_COLORFX_BW = 1,
  V4L2_COLORFX_SEPIA = 2,
  V4L2_COLORFX_NEGATIVE = 3,
  V4L2_COLORFX_EMBOSS = 4,
  V4L2_COLORFX_SKETCH = 5,
  V4L2_COLORFX_SKY_BLUE = 6,
  V4L2_COLORFX_GRASS_GREEN = 7,
  V4L2_COLORFX_SKIN_WHITEN = 8,
  V4L2_COLORFX_VIVID = 9,
  V4L2_COLORFX_AQUA = 10,
  V4L2_COLORFX_ART_FREEZE = 11,
  V4L2_COLORFX_SILHOUETTE = 12,
  V4L2_COLORFX_SOLARIZATION = 13,
  V4L2_COLORFX_ANTIQUE = 14,
  V4L2_COLORFX_SET_CBCR = 15,
  V4L2_COLORFX_SET_RGB = 16,
};
#define V4L2_CID_AUTOBRIGHTNESS (V4L2_CID_BASE + 32)
#define V4L2_CID_BAND_STOP_FILTER (V4L2_CID_BASE + 33)
#define V4L2_CID_ROTATE (V4L2_CID_BASE + 34)
#define V4L2_CID_BG_COLOR (V4L2_CID_BASE + 35)
#define V4L2_CID_CHROMA_GAIN (V4L2_CID_BASE + 36)
#define V4L2_CID_ILLUMINATORS_1 (V4L2_CID_BASE + 37)
#define V4L2_CID_ILLUMINATORS_2 (V4L2_CID_BASE + 38)
#define V4L2_CID_MIN_BUFFERS_FOR_CAPTURE (V4L2_CID_BASE + 39)
#define V4L2_CID_MIN_BUFFERS_FOR_OUTPUT (V4L2_CID_BASE + 40)
#define V4L2_CID_ALPHA_COMPONENT (V4L2_CID_BASE + 41)
#define V4L2_CID_COLORFX_CBCR (V4L2_CID_BASE + 42)
#define V4L2_CID_COLORFX_RGB (V4L2_CID_BASE + 43)
#define V4L2_CID_LASTP1 (V4L2_CID_BASE + 44)
#define V4L2_CID_USER_MEYE_BASE (V4L2_CID_USER_BASE + 0x1000)
#define V4L2_CID_USER_BTTV_BASE (V4L2_CID_USER_BASE + 0x1010)
#define V4L2_CID_USER_S2255_BASE (V4L2_CID_USER_BASE + 0x1030)
#define V4L2_CID_USER_SI476X_BASE (V4L2_CID_USER_BASE + 0x1040)
#define V4L2_CID_USER_TI_VPE_BASE (V4L2_CID_USER_BASE + 0x1050)
#define V4L2_CID_USER_SAA7134_BASE (V4L2_CID_USER_BASE + 0x1060)
#define V4L2_CID_USER_ADV7180_BASE (V4L2_CID_USER_BASE + 0x1070)
#define V4L2_CID_USER_TC358743_BASE (V4L2_CID_USER_BASE + 0x1080)
#define V4L2_CID_USER_MAX217X_BASE (V4L2_CID_USER_BASE + 0x1090)
#define V4L2_CID_USER_IMX_BASE (V4L2_CID_USER_BASE + 0x10b0)
#define V4L2_CID_USER_ATMEL_ISC_BASE (V4L2_CID_USER_BASE + 0x10c0)
#define V4L2_CID_USER_CODA_BASE (V4L2_CID_USER_BASE + 0x10e0)
#define V4L2_CID_USER_CCS_BASE (V4L2_CID_USER_BASE + 0x10f0)
#define V4L2_CID_USER_ALLEGRO_BASE (V4L2_CID_USER_BASE + 0x1170)
#define V4L2_CID_USER_ISL7998X_BASE (V4L2_CID_USER_BASE + 0x1180)
#define V4L2_CID_USER_DW100_BASE (V4L2_CID_USER_BASE + 0x1190)
#define V4L2_CID_USER_ASPEED_BASE (V4L2_CID_USER_BASE + 0x11a0)
#define V4L2_CID_USER_NPCM_BASE (V4L2_CID_USER_BASE + 0x11b0)
#define V4L2_CID_USER_THP7312_BASE (V4L2_CID_USER_BASE + 0x11c0)
#define V4L2_CID_CODEC_BASE (V4L2_CTRL_CLASS_CODEC | 0x900)
#define V4L2_CID_CODEC_CLASS (V4L2_CTRL_CLASS_CODEC | 1)
#define V4L2_CID_MPEG_STREAM_TYPE (V4L2_CID_CODEC_BASE + 0)
enum v4l2_mpeg_stream_type {
  V4L2_MPEG_STREAM_TYPE_MPEG2_PS = 0,
  V4L2_MPEG_STREAM_TYPE_MPEG2_TS = 1,
  V4L2_MPEG_STREAM_TYPE_MPEG1_SS = 2,
  V4L2_MPEG_STREAM_TYPE_MPEG2_DVD = 3,
  V4L2_MPEG_STREAM_TYPE_MPEG1_VCD = 4,
  V4L2_MPEG_STREAM_TYPE_MPEG2_SVCD = 5,
};
#define V4L2_CID_MPEG_STREAM_PID_PMT (V4L2_CID_CODEC_BASE + 1)
#define V4L2_CID_MPEG_STREAM_PID_AUDIO (V4L2_CID_CODEC_BASE + 2)
#define V4L2_CID_MPEG_STREAM_PID_VIDEO (V4L2_CID_CODEC_BASE + 3)
#define V4L2_CID_MPEG_STREAM_PID_PCR (V4L2_CID_CODEC_BASE + 4)
#define V4L2_CID_MPEG_STREAM_PES_ID_AUDIO (V4L2_CID_CODEC_BASE + 5)
#define V4L2_CID_MPEG_STREAM_PES_ID_VIDEO (V4L2_CID_CODEC_BASE + 6)
#define V4L2_CID_MPEG_STREAM_VBI_FMT (V4L2_CID_CODEC_BASE + 7)
enum v4l2_mpeg_stream_vbi_fmt {
  V4L2_MPEG_STREAM_VBI_FMT_NONE = 0,
  V4L2_MPEG_STREAM_VBI_FMT_IVTV = 1,
};
#define V4L2_CID_MPEG_AUDIO_SAMPLING_FREQ (V4L2_CID_CODEC_BASE + 100)
enum v4l2_mpeg_audio_sampling_freq {
  V4L2_MPEG_AUDIO_SAMPLING_FREQ_44100 = 0,
  V4L2_MPEG_AUDIO_SAMPLING_FREQ_48000 = 1,
  V4L2_MPEG_AUDIO_SAMPLING_FREQ_32000 = 2,
};
#define V4L2_CID_MPEG_AUDIO_ENCODING (V4L2_CID_CODEC_BASE + 101)
enum v4l2_mpeg_audio_encoding {
  V4L2_MPEG_AUDIO_ENCODING_LAYER_1 = 0,
  V4L2_MPEG_AUDIO_ENCODING_LAYER_2 = 1,
  V4L2_MPEG_AUDIO_ENCODING_LAYER_3 = 2,
  V4L2_MPEG_AUDIO_ENCODING_AAC = 3,
  V4L2_MPEG_AUDIO_ENCODING_AC3 = 4,
};
#define V4L2_CID_MPEG_AUDIO_L1_BITRATE (V4L2_CID_CODEC_BASE + 102)
enum v4l2_mpeg_audio_l1_bitrate {
  V4L2_MPEG_AUDIO_L1_BITRATE_32K = 0,
  V4L2_MPEG_AUDIO_L1_BITRATE_64K = 1,
  V4L2_MPEG_AUDIO_L1_BITRATE_96K = 2,
  V4L2_MPEG_AUDIO_L1_BITRATE_128K = 3,
  V4L2_MPEG_AUDIO_L1_BITRATE_160K = 4,
  V4L2_MPEG_AUDIO_L1_BITRATE_192K = 5,
  V4L2_MPEG_AUDIO_L1_BITRATE_224K = 6,
  V4L2_MPEG_AUDIO_L1_BITRATE_256K = 7,
  V4L2_MPEG_AUDIO_L1_BITRATE_288K = 8,
  V4L2_MPEG_AUDIO_L1_BITRATE_320K = 9,
  V4L2_MPEG_AUDIO_L1_BITRATE_352K = 10,
  V4L2_MPEG_AUDIO_L1_BITRATE_384K = 11,
  V4L2_MPEG_AUDIO_L1_BITRATE_416K = 12,
  V4L2_MPEG_AUDIO_L1_BITRATE_448K = 13,
};
#define V4L2_CID_MPEG_AUDIO_L2_BITRATE (V4L2_CID_CODEC_BASE + 103)
enum v4l2_mpeg_audio_l2_bitrate {
  V4L2_MPEG_AUDIO_L2_BITRATE_32K = 0,
  V4L2_MPEG_AUDIO_L2_BITRATE_48K = 1,
  V4L2_MPEG_AUDIO_L2_BITRATE_56K = 2,
  V4L2_MPEG_AUDIO_L2_BITRATE_64K = 3,
  V4L2_MPEG_AUDIO_L2_BITRATE_80K = 4,
  V4L2_MPEG_AUDIO_L2_BITRATE_96K = 5,
  V4L2_MPEG_AUDIO_L2_BITRATE_112K = 6,
  V4L2_MPEG_AUDIO_L2_BITRATE_128K = 7,
  V4L2_MPEG_AUDIO_L2_BITRATE_160K = 8,
  V4L2_MPEG_AUDIO_L2_BITRATE_192K = 9,
  V4L2_MPEG_AUDIO_L2_BITRATE_224K = 10,
  V4L2_MPEG_AUDIO_L2_BITRATE_256K = 11,
  V4L2_MPEG_AUDIO_L2_BITRATE_320K = 12,
  V4L2_MPEG_AUDIO_L2_BITRATE_384K = 13,
};
#define V4L2_CID_MPEG_AUDIO_L3_BITRATE (V4L2_CID_CODEC_BASE + 104)
enum v4l2_mpeg_audio_l3_bitrate {
  V4L2_MPEG_AUDIO_L3_BITRATE_32K = 0,
  V4L2_MPEG_AUDIO_L3_BITRATE_40K = 1,
  V4L2_MPEG_AUDIO_L3_BITRATE_48K = 2,
  V4L2_MPEG_AUDIO_L3_BITRATE_56K = 3,
  V4L2_MPEG_AUDIO_L3_BITRATE_64K = 4,
  V4L2_MPEG_AUDIO_L3_BITRATE_80K = 5,
  V4L2_MPEG_AUDIO_L3_BITRATE_96K = 6,
  V4L2_MPEG_AUDIO_L3_BITRATE_112K = 7,
  V4L2_MPEG_AUDIO_L3_BITRATE_128K = 8,
  V4L2_MPEG_AUDIO_L3_BITRATE_160K = 9,
  V4L2_MPEG_AUDIO_L3_BITRATE_192K = 10,
  V4L2_MPEG_AUDIO_L3_BITRATE_224K = 11,
  V4L2_MPEG_AUDIO_L3_BITRATE_256K = 12,
  V4L2_MPEG_AUDIO_L3_BITRATE_320K = 13,
};
#define V4L2_CID_MPEG_AUDIO_MODE (V4L2_CID_CODEC_BASE + 105)
enum v4l2_mpeg_audio_mode {
  V4L2_MPEG_AUDIO_MODE_STEREO = 0,
  V4L2_MPEG_AUDIO_MODE_JOINT_STEREO = 1,
  V4L2_MPEG_AUDIO_MODE_DUAL = 2,
  V4L2_MPEG_AUDIO_MODE_MONO = 3,
};
#define V4L2_CID_MPEG_AUDIO_MODE_EXTENSION (V4L2_CID_CODEC_BASE + 106)
enum v4l2_mpeg_audio_mode_extension {
  V4L2_MPEG_AUDIO_MODE_EXTENSION_BOUND_4 = 0,
  V4L2_MPEG_AUDIO_MODE_EXTENSION_BOUND_8 = 1,
  V4L2_MPEG_AUDIO_MODE_EXTENSION_BOUND_12 = 2,
  V4L2_MPEG_AUDIO_MODE_EXTENSION_BOUND_16 = 3,
};
#define V4L2_CID_MPEG_AUDIO_EMPHASIS (V4L2_CID_CODEC_BASE + 107)
enum v4l2_mpeg_audio_emphasis {
  V4L2_MPEG_AUDIO_EMPHASIS_NONE = 0,
  V4L2_MPEG_AUDIO_EMPHASIS_50_DIV_15_uS = 1,
  V4L2_MPEG_AUDIO_EMPHASIS_CCITT_J17 = 2,
};
#define V4L2_CID_MPEG_AUDIO_CRC (V4L2_CID_CODEC_BASE + 108)
enum v4l2_mpeg_audio_crc {
  V4L2_MPEG_AUDIO_CRC_NONE = 0,
  V4L2_MPEG_AUDIO_CRC_CRC16 = 1,
};
#define V4L2_CID_MPEG_AUDIO_MUTE (V4L2_CID_CODEC_BASE + 109)
#define V4L2_CID_MPEG_AUDIO_AAC_BITRATE (V4L2_CID_CODEC_BASE + 110)
#define V4L2_CID_MPEG_AUDIO_AC3_BITRATE (V4L2_CID_CODEC_BASE + 111)
enum v4l2_mpeg_audio_ac3_bitrate {
  V4L2_MPEG_AUDIO_AC3_BITRATE_32K = 0,
  V4L2_MPEG_AUDIO_AC3_BITRATE_40K = 1,
  V4L2_MPEG_AUDIO_AC3_BITRATE_48K = 2,
  V4L2_MPEG_AUDIO_AC3_BITRATE_56K = 3,
  V4L2_MPEG_AUDIO_AC3_BITRATE_64K = 4,
  V4L2_MPEG_AUDIO_AC3_BITRATE_80K = 5,
  V4L2_MPEG_AUDIO_AC3_BITRATE_96K = 6,
  V4L2_MPEG_AUDIO_AC3_BITRATE_112K = 7,
  V4L2_MPEG_AUDIO_AC3_BITRATE_128K = 8,
  V4L2_MPEG_AUDIO_AC3_BITRATE_160K = 9,
  V4L2_MPEG_AUDIO_AC3_BITRATE_192K = 10,
  V4L2_MPEG_AUDIO_AC3_BITRATE_224K = 11,
  V4L2_MPEG_AUDIO_AC3_BITRATE_256K = 12,
  V4L2_MPEG_AUDIO_AC3_BITRATE_320K = 13,
  V4L2_MPEG_AUDIO_AC3_BITRATE_384K = 14,
  V4L2_MPEG_AUDIO_AC3_BITRATE_448K = 15,
  V4L2_MPEG_AUDIO_AC3_BITRATE_512K = 16,
  V4L2_MPEG_AUDIO_AC3_BITRATE_576K = 17,
  V4L2_MPEG_AUDIO_AC3_BITRATE_640K = 18,
};
#define V4L2_CID_MPEG_AUDIO_DEC_PLAYBACK (V4L2_CID_CODEC_BASE + 112)
enum v4l2_mpeg_audio_dec_playback {
  V4L2_MPEG_AUDIO_DEC_PLAYBACK_AUTO = 0,
  V4L2_MPEG_AUDIO_DEC_PLAYBACK_STEREO = 1,
  V4L2_MPEG_AUDIO_DEC_PLAYBACK_LEFT = 2,
  V4L2_MPEG_AUDIO_DEC_PLAYBACK_RIGHT = 3,
  V4L2_MPEG_AUDIO_DEC_PLAYBACK_MONO = 4,
  V4L2_MPEG_AUDIO_DEC_PLAYBACK_SWAPPED_STEREO = 5,
};
#define V4L2_CID_MPEG_AUDIO_DEC_MULTILINGUAL_PLAYBACK (V4L2_CID_CODEC_BASE + 113)
#define V4L2_CID_MPEG_VIDEO_ENCODING (V4L2_CID_CODEC_BASE + 200)
enum v4l2_mpeg_video_encoding {
  V4L2_MPEG_VIDEO_ENCODING_MPEG_1 = 0,
  V4L2_MPEG_VIDEO_ENCODING_MPEG_2 = 1,
  V4L2_MPEG_VIDEO_ENCODING_MPEG_4_AVC = 2,
};
#define V4L2_CID_MPEG_VIDEO_ASPECT (V4L2_CID_CODEC_BASE + 201)
enum v4l2_mpeg_video_aspect {
  V4L2_MPEG_VIDEO_ASPECT_1x1 = 0,
  V4L2_MPEG_VIDEO_ASPECT_4x3 = 1,
  V4L2_MPEG_VIDEO_ASPECT_16x9 = 2,
  V4L2_MPEG_VIDEO_ASPECT_221x100 = 3,
};
#define V4L2_CID_MPEG_VIDEO_B_FRAMES (V4L2_CID_CODEC_BASE + 202)
#define V4L2_CID_MPEG_VIDEO_GOP_SIZE (V4L2_CID_CODEC_BASE + 203)
#define V4L2_CID_MPEG_VIDEO_GOP_CLOSURE (V4L2_CID_CODEC_BASE + 204)
#define V4L2_CID_MPEG_VIDEO_PULLDOWN (V4L2_CID_CODEC_BASE + 205)
#define V4L2_CID_MPEG_VIDEO_BITRATE_MODE (V4L2_CID_CODEC_BASE + 206)
enum v4l2_mpeg_video_bitrate_mode {
  V4L2_MPEG_VIDEO_BITRATE_MODE_VBR = 0,
  V4L2_MPEG_VIDEO_BITRATE_MODE_CBR = 1,
  V4L2_MPEG_VIDEO_BITRATE_MODE_CQ = 2,
};
#define V4L2_CID_MPEG_VIDEO_BITRATE (V4L2_CID_CODEC_BASE + 207)
#define V4L2_CID_MPEG_VIDEO_BITRATE_PEAK (V4L2_CID_CODEC_BASE + 208)
#define V4L2_CID_MPEG_VIDEO_TEMPORAL_DECIMATION (V4L2_CID_CODEC_BASE + 209)
#define V4L2_CID_MPEG_VIDEO_MUTE (V4L2_CID_CODEC_BASE + 210)
#define V4L2_CID_MPEG_VIDEO_MUTE_YUV (V4L2_CID_CODEC_BASE + 211)
#define V4L2_CID_MPEG_VIDEO_DECODER_SLICE_INTERFACE (V4L2_CID_CODEC_BASE + 212)
#define V4L2_CID_MPEG_VIDEO_DECODER_MPEG4_DEBLOCK_FILTER (V4L2_CID_CODEC_BASE + 213)
#define V4L2_CID_MPEG_VIDEO_CYCLIC_INTRA_REFRESH_MB (V4L2_CID_CODEC_BASE + 214)
#define V4L2_CID_MPEG_VIDEO_FRAME_RC_ENABLE (V4L2_CID_CODEC_BASE + 215)
#define V4L2_CID_MPEG_VIDEO_HEADER_MODE (V4L2_CID_CODEC_BASE + 216)
enum v4l2_mpeg_video_header_mode {
  V4L2_MPEG_VIDEO_HEADER_MODE_SEPARATE = 0,
  V4L2_MPEG_VIDEO_HEADER_MODE_JOINED_WITH_1ST_FRAME = 1,
};
#define V4L2_CID_MPEG_VIDEO_MAX_REF_PIC (V4L2_CID_CODEC_BASE + 217)
#define V4L2_CID_MPEG_VIDEO_MB_RC_ENABLE (V4L2_CID_CODEC_BASE + 218)
#define V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MAX_BYTES (V4L2_CID_CODEC_BASE + 219)
#define V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MAX_MB (V4L2_CID_CODEC_BASE + 220)
#define V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MODE (V4L2_CID_CODEC_BASE + 221)
enum v4l2_mpeg_video_multi_slice_mode {
  V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_SINGLE = 0,
  V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_MB = 1,
  V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_BYTES = 2,
  V4L2_MPEG_VIDEO_MULTI_SICE_MODE_MAX_MB = 1,
  V4L2_MPEG_VIDEO_MULTI_SICE_MODE_MAX_BYTES = 2,
};
#define V4L2_CID_MPEG_VIDEO_VBV_SIZE (V4L2_CID_CODEC_BASE + 222)
#define V4L2_CID_MPEG_VIDEO_DEC_PTS (V4L2_CID_CODEC_BASE + 223)
#define V4L2_CID_MPEG_VIDEO_DEC_FRAME (V4L2_CID_CODEC_BASE + 224)
#define V4L2_CID_MPEG_VIDEO_VBV_DELAY (V4L2_CID_CODEC_BASE + 225)
#define V4L2_CID_MPEG_VIDEO_REPEAT_SEQ_HEADER (V4L2_CID_CODEC_BASE + 226)
#define V4L2_CID_MPEG_VIDEO_MV_H_SEARCH_RANGE (V4L2_CID_CODEC_BASE + 227)
#define V4L2_CID_MPEG_VIDEO_MV_V_SEARCH_RANGE (V4L2_CID_CODEC_BASE + 228)
#define V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME (V4L2_CID_CODEC_BASE + 229)
#define V4L2_CID_MPEG_VIDEO_BASELAYER_PRIORITY_ID (V4L2_CID_CODEC_BASE + 230)
#define V4L2_CID_MPEG_VIDEO_AU_DELIMITER (V4L2_CID_CODEC_BASE + 231)
#define V4L2_CID_MPEG_VIDEO_LTR_COUNT (V4L2_CID_CODEC_BASE + 232)
#define V4L2_CID_MPEG_VIDEO_FRAME_LTR_INDEX (V4L2_CID_CODEC_BASE + 233)
#define V4L2_CID_MPEG_VIDEO_USE_LTR_FRAMES (V4L2_CID_CODEC_BASE + 234)
#define V4L2_CID_MPEG_VIDEO_DEC_CONCEAL_COLOR (V4L2_CID_CODEC_BASE + 235)
#define V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD (V4L2_CID_CODEC_BASE + 236)
#define V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD_TYPE (V4L2_CID_CODEC_BASE + 237)
enum v4l2_mpeg_video_intra_refresh_period_type {
  V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD_TYPE_RANDOM = 0,
  V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD_TYPE_CYCLIC = 1,
};
#define V4L2_CID_MPEG_VIDEO_MPEG2_LEVEL (V4L2_CID_CODEC_BASE + 270)
enum v4l2_mpeg_video_mpeg2_level {
  V4L2_MPEG_VIDEO_MPEG2_LEVEL_LOW = 0,
  V4L2_MPEG_VIDEO_MPEG2_LEVEL_MAIN = 1,
  V4L2_MPEG_VIDEO_MPEG2_LEVEL_HIGH_1440 = 2,
  V4L2_MPEG_VIDEO_MPEG2_LEVEL_HIGH = 3,
};
#define V4L2_CID_MPEG_VIDEO_MPEG2_PROFILE (V4L2_CID_CODEC_BASE + 271)
enum v4l2_mpeg_video_mpeg2_profile {
  V4L2_MPEG_VIDEO_MPEG2_PROFILE_SIMPLE = 0,
  V4L2_MPEG_VIDEO_MPEG2_PROFILE_MAIN = 1,
  V4L2_MPEG_VIDEO_MPEG2_PROFILE_SNR_SCALABLE = 2,
  V4L2_MPEG_VIDEO_MPEG2_PROFILE_SPATIALLY_SCALABLE = 3,
  V4L2_MPEG_VIDEO_MPEG2_PROFILE_HIGH = 4,
  V4L2_MPEG_VIDEO_MPEG2_PROFILE_MULTIVIEW = 5,
};
#define V4L2_CID_FWHT_I_FRAME_QP (V4L2_CID_CODEC_BASE + 290)
#define V4L2_CID_FWHT_P_FRAME_QP (V4L2_CID_CODEC_BASE + 291)
#define V4L2_CID_MPEG_VIDEO_H263_I_FRAME_QP (V4L2_CID_CODEC_BASE + 300)
#define V4L2_CID_MPEG_VIDEO_H263_P_FRAME_QP (V4L2_CID_CODEC_BASE + 301)
#define V4L2_CID_MPEG_VIDEO_H263_B_FRAME_QP (V4L2_CID_CODEC_BASE + 302)
#define V4L2_CID_MPEG_VIDEO_H263_MIN_QP (V4L2_CID_CODEC_BASE + 303)
#define V4L2_CID_MPEG_VIDEO_H263_MAX_QP (V4L2_CID_CODEC_BASE + 304)
#define V4L2_CID_MPEG_VIDEO_H264_I_FRAME_QP (V4L2_CID_CODEC_BASE + 350)
#define V4L2_CID_MPEG_VIDEO_H264_P_FRAME_QP (V4L2_CID_CODEC_BASE + 351)
#define V4L2_CID_MPEG_VIDEO_H264_B_FRAME_QP (V4L2_CID_CODEC_BASE + 352)
#define V4L2_CID_MPEG_VIDEO_H264_MIN_QP (V4L2_CID_CODEC_BASE + 353)
#define V4L2_CID_MPEG_VIDEO_H264_MAX_QP (V4L2_CID_CODEC_BASE + 354)
#define V4L2_CID_MPEG_VIDEO_H264_8X8_TRANSFORM (V4L2_CID_CODEC_BASE + 355)
#define V4L2_CID_MPEG_VIDEO_H264_CPB_SIZE (V4L2_CID_CODEC_BASE + 356)
#define V4L2_CID_MPEG_VIDEO_H264_ENTROPY_MODE (V4L2_CID_CODEC_BASE + 357)
enum v4l2_mpeg_video_h264_entropy_mode {
  V4L2_MPEG_VIDEO_H264_ENTROPY_MODE_CAVLC = 0,
  V4L2_MPEG_VIDEO_H264_ENTROPY_MODE_CABAC = 1,
};
#define V4L2_CID_MPEG_VIDEO_H264_I_PERIOD (V4L2_CID_CODEC_BASE + 358)
#define V4L2_CID_MPEG_VIDEO_H264_LEVEL (V4L2_CID_CODEC_BASE + 359)
enum v4l2_mpeg_video_h264_level {
  V4L2_MPEG_VIDEO_H264_LEVEL_1_0 = 0,
  V4L2_MPEG_VIDEO_H264_LEVEL_1B = 1,
  V4L2_MPEG_VIDEO_H264_LEVEL_1_1 = 2,
  V4L2_MPEG_VIDEO_H264_LEVEL_1_2 = 3,
  V4L2_MPEG_VIDEO_H264_LEVEL_1_3 = 4,
  V4L2_MPEG_VIDEO_H264_LEVEL_2_0 = 5,
  V4L2_MPEG_VIDEO_H264_LEVEL_2_1 = 6,
  V4L2_MPEG_VIDEO_H264_LEVEL_2_2 = 7,
  V4L2_MPEG_VIDEO_H264_LEVEL_3_0 = 8,
  V4L2_MPEG_VIDEO_H264_LEVEL_3_1 = 9,
  V4L2_MPEG_VIDEO_H264_LEVEL_3_2 = 10,
  V4L2_MPEG_VIDEO_H264_LEVEL_4_0 = 11,
  V4L2_MPEG_VIDEO_H264_LEVEL_4_1 = 12,
  V4L2_MPEG_VIDEO_H264_LEVEL_4_2 = 13,
  V4L2_MPEG_VIDEO_H264_LEVEL_5_0 = 14,
  V4L2_MPEG_VIDEO_H264_LEVEL_5_1 = 15,
  V4L2_MPEG_VIDEO_H264_LEVEL_5_2 = 16,
  V4L2_MPEG_VIDEO_H264_LEVEL_6_0 = 17,
  V4L2_MPEG_VIDEO_H264_LEVEL_6_1 = 18,
  V4L2_MPEG_VIDEO_H264_LEVEL_6_2 = 19,
};
#define V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_ALPHA (V4L2_CID_CODEC_BASE + 360)
#define V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_BETA (V4L2_CID_CODEC_BASE + 361)
#define V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_MODE (V4L2_CID_CODEC_BASE + 362)
enum v4l2_mpeg_video_h264_loop_filter_mode {
  V4L2_MPEG_VIDEO_H264_LOOP_FILTER_MODE_ENABLED = 0,
  V4L2_MPEG_VIDEO_H264_LOOP_FILTER_MODE_DISABLED = 1,
  V4L2_MPEG_VIDEO_H264_LOOP_FILTER_MODE_DISABLED_AT_SLICE_BOUNDARY = 2,
};
#define V4L2_CID_MPEG_VIDEO_H264_PROFILE (V4L2_CID_CODEC_BASE + 363)
enum v4l2_mpeg_video_h264_profile {
  V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE = 0,
  V4L2_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_BASELINE = 1,
  V4L2_MPEG_VIDEO_H264_PROFILE_MAIN = 2,
  V4L2_MPEG_VIDEO_H264_PROFILE_EXTENDED = 3,
  V4L2_MPEG_VIDEO_H264_PROFILE_HIGH = 4,
  V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10 = 5,
  V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_422 = 6,
  V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_444_PREDICTIVE = 7,
  V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10_INTRA = 8,
  V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_422_INTRA = 9,
  V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_444_INTRA = 10,
  V4L2_MPEG_VIDEO_H264_PROFILE_CAVLC_444_INTRA = 11,
  V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_BASELINE = 12,
  V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH = 13,
  V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH_INTRA = 14,
  V4L2_MPEG_VIDEO_H264_PROFILE_STEREO_HIGH = 15,
  V4L2_MPEG_VIDEO_H264_PROFILE_MULTIVIEW_HIGH = 16,
  V4L2_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_HIGH = 17,
};
#define V4L2_CID_MPEG_VIDEO_H264_VUI_EXT_SAR_HEIGHT (V4L2_CID_CODEC_BASE + 364)
#define V4L2_CID_MPEG_VIDEO_H264_VUI_EXT_SAR_WIDTH (V4L2_CID_CODEC_BASE + 365)
#define V4L2_CID_MPEG_VIDEO_H264_VUI_SAR_ENABLE (V4L2_CID_CODEC_BASE + 366)
#define V4L2_CID_MPEG_VIDEO_H264_VUI_SAR_IDC (V4L2_CID_CODEC_BASE + 367)
enum v4l2_mpeg_video_h264_vui_sar_idc {
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_UNSPECIFIED = 0,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_1x1 = 1,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_12x11 = 2,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_10x11 = 3,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_16x11 = 4,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_40x33 = 5,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_24x11 = 6,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_20x11 = 7,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_32x11 = 8,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_80x33 = 9,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_18x11 = 10,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_15x11 = 11,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_64x33 = 12,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_160x99 = 13,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_4x3 = 14,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_3x2 = 15,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_2x1 = 16,
  V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_EXTENDED = 17,
};
#define V4L2_CID_MPEG_VIDEO_H264_SEI_FRAME_PACKING (V4L2_CID_CODEC_BASE + 368)
#define V4L2_CID_MPEG_VIDEO_H264_SEI_FP_CURRENT_FRAME_0 (V4L2_CID_CODEC_BASE + 369)
#define V4L2_CID_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE (V4L2_CID_CODEC_BASE + 370)
enum v4l2_mpeg_video_h264_sei_fp_arrangement_type {
  V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_CHECKERBOARD = 0,
  V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_COLUMN = 1,
  V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_ROW = 2,
  V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_SIDE_BY_SIDE = 3,
  V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_TOP_BOTTOM = 4,
  V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_TEMPORAL = 5,
};
#define V4L2_CID_MPEG_VIDEO_H264_FMO (V4L2_CID_CODEC_BASE + 371)
#define V4L2_CID_MPEG_VIDEO_H264_FMO_MAP_TYPE (V4L2_CID_CODEC_BASE + 372)
enum v4l2_mpeg_video_h264_fmo_map_type {
  V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_INTERLEAVED_SLICES = 0,
  V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_SCATTERED_SLICES = 1,
  V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_FOREGROUND_WITH_LEFT_OVER = 2,
  V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_BOX_OUT = 3,
  V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_RASTER_SCAN = 4,
  V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_WIPE_SCAN = 5,
  V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_EXPLICIT = 6,
};
#define V4L2_CID_MPEG_VIDEO_H264_FMO_SLICE_GROUP (V4L2_CID_CODEC_BASE + 373)
#define V4L2_CID_MPEG_VIDEO_H264_FMO_CHANGE_DIRECTION (V4L2_CID_CODEC_BASE + 374)
enum v4l2_mpeg_video_h264_fmo_change_dir {
  V4L2_MPEG_VIDEO_H264_FMO_CHANGE_DIR_RIGHT = 0,
  V4L2_MPEG_VIDEO_H264_FMO_CHANGE_DIR_LEFT = 1,
};
#define V4L2_CID_MPEG_VIDEO_H264_FMO_CHANGE_RATE (V4L2_CID_CODEC_BASE + 375)
#define V4L2_CID_MPEG_VIDEO_H264_FMO_RUN_LENGTH (V4L2_CID_CODEC_BASE + 376)
#define V4L2_CID_MPEG_VIDEO_H264_ASO (V4L2_CID_CODEC_BASE + 377)
#define V4L2_CID_MPEG_VIDEO_H264_ASO_SLICE_ORDER (V4L2_CID_CODEC_BASE + 378)
#define V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING (V4L2_CID_CODEC_BASE + 379)
#define V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_TYPE (V4L2_CID_CODEC_BASE + 380)
enum v4l2_mpeg_video_h264_hierarchical_coding_type {
  V4L2_MPEG_VIDEO_H264_HIERARCHICAL_CODING_B = 0,
  V4L2_MPEG_VIDEO_H264_HIERARCHICAL_CODING_P = 1,
};
#define V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_LAYER (V4L2_CID_CODEC_BASE + 381)
#define V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_LAYER_QP (V4L2_CID_CODEC_BASE + 382)
#define V4L2_CID_MPEG_VIDEO_H264_CONSTRAINED_INTRA_PREDICTION (V4L2_CID_CODEC_BASE + 383)
#define V4L2_CID_MPEG_VIDEO_H264_CHROMA_QP_INDEX_OFFSET (V4L2_CID_CODEC_BASE + 384)
#define V4L2_CID_MPEG_VIDEO_H264_I_FRAME_MIN_QP (V4L2_CID_CODEC_BASE + 385)
#define V4L2_CID_MPEG_VIDEO_H264_I_FRAME_MAX_QP (V4L2_CID_CODEC_BASE + 386)
#define V4L2_CID_MPEG_VIDEO_H264_P_FRAME_MIN_QP (V4L2_CID_CODEC_BASE + 387)
#define V4L2_CID_MPEG_VIDEO_H264_P_FRAME_MAX_QP (V4L2_CID_CODEC_BASE + 388)
#define V4L2_CID_MPEG_VIDEO_H264_B_FRAME_MIN_QP (V4L2_CID_CODEC_BASE + 389)
#define V4L2_CID_MPEG_VIDEO_H264_B_FRAME_MAX_QP (V4L2_CID_CODEC_BASE + 390)
#define V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L0_BR (V4L2_CID_CODEC_BASE + 391)
#define V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L1_BR (V4L2_CID_CODEC_BASE + 392)
#define V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L2_BR (V4L2_CID_CODEC_BASE + 393)
#define V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L3_BR (V4L2_CID_CODEC_BASE + 394)
#define V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L4_BR (V4L2_CID_CODEC_BASE + 395)
#define V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L5_BR (V4L2_CID_CODEC_BASE + 396)
#define V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L6_BR (V4L2_CID_CODEC_BASE + 397)
#define V4L2_CID_MPEG_VIDEO_MPEG4_I_FRAME_QP (V4L2_CID_CODEC_BASE + 400)
#define V4L2_CID_MPEG_VIDEO_MPEG4_P_FRAME_QP (V4L2_CID_CODEC_BASE + 401)
#define V4L2_CID_MPEG_VIDEO_MPEG4_B_FRAME_QP (V4L2_CID_CODEC_BASE + 402)
#define V4L2_CID_MPEG_VIDEO_MPEG4_MIN_QP (V4L2_CID_CODEC_BASE + 403)
#define V4L2_CID_MPEG_VIDEO_MPEG4_MAX_QP (V4L2_CID_CODEC_BASE + 404)
#define V4L2_CID_MPEG_VIDEO_MPEG4_LEVEL (V4L2_CID_CODEC_BASE + 405)
enum v4l2_mpeg_video_mpeg4_level {
  V4L2_MPEG_VIDEO_MPEG4_LEVEL_0 = 0,
  V4L2_MPEG_VIDEO_MPEG4_LEVEL_0B = 1,
  V4L2_MPEG_VIDEO_MPEG4_LEVEL_1 = 2,
  V4L2_MPEG_VIDEO_MPEG4_LEVEL_2 = 3,
  V4L2_MPEG_VIDEO_MPEG4_LEVEL_3 = 4,
  V4L2_MPEG_VIDEO_MPEG4_LEVEL_3B = 5,
  V4L2_MPEG_VIDEO_MPEG4_LEVEL_4 = 6,
  V4L2_MPEG_VIDEO_MPEG4_LEVEL_5 = 7,
};
#define V4L2_CID_MPEG_VIDEO_MPEG4_PROFILE (V4L2_CID_CODEC_BASE + 406)
enum v4l2_mpeg_video_mpeg4_profile {
  V4L2_MPEG_VIDEO_MPEG4_PROFILE_SIMPLE = 0,
  V4L2_MPEG_VIDEO_MPEG4_PROFILE_ADVANCED_SIMPLE = 1,
  V4L2_MPEG_VIDEO_MPEG4_PROFILE_CORE = 2,
  V4L2_MPEG_VIDEO_MPEG4_PROFILE_SIMPLE_SCALABLE = 3,
  V4L2_MPEG_VIDEO_MPEG4_PROFILE_ADVANCED_CODING_EFFICIENCY = 4,
};
#define V4L2_CID_MPEG_VIDEO_MPEG4_QPEL (V4L2_CID_CODEC_BASE + 407)
#define V4L2_CID_MPEG_VIDEO_VPX_NUM_PARTITIONS (V4L2_CID_CODEC_BASE + 500)
enum v4l2_vp8_num_partitions {
  V4L2_CID_MPEG_VIDEO_VPX_1_PARTITION = 0,
  V4L2_CID_MPEG_VIDEO_VPX_2_PARTITIONS = 1,
  V4L2_CID_MPEG_VIDEO_VPX_4_PARTITIONS = 2,
  V4L2_CID_MPEG_VIDEO_VPX_8_PARTITIONS = 3,
};
#define V4L2_CID_MPEG_VIDEO_VPX_IMD_DISABLE_4X4 (V4L2_CID_CODEC_BASE + 501)
#define V4L2_CID_MPEG_VIDEO_VPX_NUM_REF_FRAMES (V4L2_CID_CODEC_BASE + 502)
enum v4l2_vp8_num_ref_frames {
  V4L2_CID_MPEG_VIDEO_VPX_1_REF_FRAME = 0,
  V4L2_CID_MPEG_VIDEO_VPX_2_REF_FRAME = 1,
  V4L2_CID_MPEG_VIDEO_VPX_3_REF_FRAME = 2,
};
#define V4L2_CID_MPEG_VIDEO_VPX_FILTER_LEVEL (V4L2_CID_CODEC_BASE + 503)
#define V4L2_CID_MPEG_VIDEO_VPX_FILTER_SHARPNESS (V4L2_CID_CODEC_BASE + 504)
#define V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_REF_PERIOD (V4L2_CID_CODEC_BASE + 505)
#define V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_SEL (V4L2_CID_CODEC_BASE + 506)
enum v4l2_vp8_golden_frame_sel {
  V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_USE_PREV = 0,
  V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_USE_REF_PERIOD = 1,
};
#define V4L2_CID_MPEG_VIDEO_VPX_MIN_QP (V4L2_CID_CODEC_BASE + 507)
#define V4L2_CID_MPEG_VIDEO_VPX_MAX_QP (V4L2_CID_CODEC_BASE + 508)
#define V4L2_CID_MPEG_VIDEO_VPX_I_FRAME_QP (V4L2_CID_CODEC_BASE + 509)
#define V4L2_CID_MPEG_VIDEO_VPX_P_FRAME_QP (V4L2_CID_CODEC_BASE + 510)
#define V4L2_CID_MPEG_VIDEO_VP8_PROFILE (V4L2_CID_CODEC_BASE + 511)
enum v4l2_mpeg_video_vp8_profile {
  V4L2_MPEG_VIDEO_VP8_PROFILE_0 = 0,
  V4L2_MPEG_VIDEO_VP8_PROFILE_1 = 1,
  V4L2_MPEG_VIDEO_VP8_PROFILE_2 = 2,
  V4L2_MPEG_VIDEO_VP8_PROFILE_3 = 3,
};
#define V4L2_CID_MPEG_VIDEO_VPX_PROFILE V4L2_CID_MPEG_VIDEO_VP8_PROFILE
#define V4L2_CID_MPEG_VIDEO_VP9_PROFILE (V4L2_CID_CODEC_BASE + 512)
enum v4l2_mpeg_video_vp9_profile {
  V4L2_MPEG_VIDEO_VP9_PROFILE_0 = 0,
  V4L2_MPEG_VIDEO_VP9_PROFILE_1 = 1,
  V4L2_MPEG_VIDEO_VP9_PROFILE_2 = 2,
  V4L2_MPEG_VIDEO_VP9_PROFILE_3 = 3,
};
#define V4L2_CID_MPEG_VIDEO_VP9_LEVEL (V4L2_CID_CODEC_BASE + 513)
enum v4l2_mpeg_video_vp9_level {
  V4L2_MPEG_VIDEO_VP9_LEVEL_1_0 = 0,
  V4L2_MPEG_VIDEO_VP9_LEVEL_1_1 = 1,
  V4L2_MPEG_VIDEO_VP9_LEVEL_2_0 = 2,
  V4L2_MPEG_VIDEO_VP9_LEVEL_2_1 = 3,
  V4L2_MPEG_VIDEO_VP9_LEVEL_3_0 = 4,
  V4L2_MPEG_VIDEO_VP9_LEVEL_3_1 = 5,
  V4L2_MPEG_VIDEO_VP9_LEVEL_4_0 = 6,
  V4L2_MPEG_VIDEO_VP9_LEVEL_4_1 = 7,
  V4L2_MPEG_VIDEO_VP9_LEVEL_5_0 = 8,
  V4L2_MPEG_VIDEO_VP9_LEVEL_5_1 = 9,
  V4L2_MPEG_VIDEO_VP9_LEVEL_5_2 = 10,
  V4L2_MPEG_VIDEO_VP9_LEVEL_6_0 = 11,
  V4L2_MPEG_VIDEO_VP9_LEVEL_6_1 = 12,
  V4L2_MPEG_VIDEO_VP9_LEVEL_6_2 = 13,
};
#define V4L2_CID_MPEG_VIDEO_HEVC_MIN_QP (V4L2_CID_CODEC_BASE + 600)
#define V4L2_CID_MPEG_VIDEO_HEVC_MAX_QP (V4L2_CID_CODEC_BASE + 601)
#define V4L2_CID_MPEG_VIDEO_HEVC_I_FRAME_QP (V4L2_CID_CODEC_BASE + 602)
#define V4L2_CID_MPEG_VIDEO_HEVC_P_FRAME_QP (V4L2_CID_CODEC_BASE + 603)
#define V4L2_CID_MPEG_VIDEO_HEVC_B_FRAME_QP (V4L2_CID_CODEC_BASE + 604)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_QP (V4L2_CID_CODEC_BASE + 605)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_TYPE (V4L2_CID_CODEC_BASE + 606)
enum v4l2_mpeg_video_hevc_hier_coding_type {
  V4L2_MPEG_VIDEO_HEVC_HIERARCHICAL_CODING_B = 0,
  V4L2_MPEG_VIDEO_HEVC_HIERARCHICAL_CODING_P = 1,
};
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_LAYER (V4L2_CID_CODEC_BASE + 607)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L0_QP (V4L2_CID_CODEC_BASE + 608)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L1_QP (V4L2_CID_CODEC_BASE + 609)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L2_QP (V4L2_CID_CODEC_BASE + 610)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L3_QP (V4L2_CID_CODEC_BASE + 611)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L4_QP (V4L2_CID_CODEC_BASE + 612)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L5_QP (V4L2_CID_CODEC_BASE + 613)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L6_QP (V4L2_CID_CODEC_BASE + 614)
#define V4L2_CID_MPEG_VIDEO_HEVC_PROFILE (V4L2_CID_CODEC_BASE + 615)
enum v4l2_mpeg_video_hevc_profile {
  V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN = 0,
  V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_STILL_PICTURE = 1,
  V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_10 = 2,
};
#define V4L2_CID_MPEG_VIDEO_HEVC_LEVEL (V4L2_CID_CODEC_BASE + 616)
enum v4l2_mpeg_video_hevc_level {
  V4L2_MPEG_VIDEO_HEVC_LEVEL_1 = 0,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_2 = 1,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_2_1 = 2,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_3 = 3,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_3_1 = 4,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_4 = 5,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_4_1 = 6,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_5 = 7,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_5_1 = 8,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_5_2 = 9,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_6 = 10,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_6_1 = 11,
  V4L2_MPEG_VIDEO_HEVC_LEVEL_6_2 = 12,
};
#define V4L2_CID_MPEG_VIDEO_HEVC_FRAME_RATE_RESOLUTION (V4L2_CID_CODEC_BASE + 617)
#define V4L2_CID_MPEG_VIDEO_HEVC_TIER (V4L2_CID_CODEC_BASE + 618)
enum v4l2_mpeg_video_hevc_tier {
  V4L2_MPEG_VIDEO_HEVC_TIER_MAIN = 0,
  V4L2_MPEG_VIDEO_HEVC_TIER_HIGH = 1,
};
#define V4L2_CID_MPEG_VIDEO_HEVC_MAX_PARTITION_DEPTH (V4L2_CID_CODEC_BASE + 619)
#define V4L2_CID_MPEG_VIDEO_HEVC_LOOP_FILTER_MODE (V4L2_CID_CODEC_BASE + 620)
enum v4l2_cid_mpeg_video_hevc_loop_filter_mode {
  V4L2_MPEG_VIDEO_HEVC_LOOP_FILTER_MODE_DISABLED = 0,
  V4L2_MPEG_VIDEO_HEVC_LOOP_FILTER_MODE_ENABLED = 1,
  V4L2_MPEG_VIDEO_HEVC_LOOP_FILTER_MODE_DISABLED_AT_SLICE_BOUNDARY = 2,
};
#define V4L2_CID_MPEG_VIDEO_HEVC_LF_BETA_OFFSET_DIV2 (V4L2_CID_CODEC_BASE + 621)
#define V4L2_CID_MPEG_VIDEO_HEVC_LF_TC_OFFSET_DIV2 (V4L2_CID_CODEC_BASE + 622)
#define V4L2_CID_MPEG_VIDEO_HEVC_REFRESH_TYPE (V4L2_CID_CODEC_BASE + 623)
enum v4l2_cid_mpeg_video_hevc_refresh_type {
  V4L2_MPEG_VIDEO_HEVC_REFRESH_NONE = 0,
  V4L2_MPEG_VIDEO_HEVC_REFRESH_CRA = 1,
  V4L2_MPEG_VIDEO_HEVC_REFRESH_IDR = 2,
};
#define V4L2_CID_MPEG_VIDEO_HEVC_REFRESH_PERIOD (V4L2_CID_CODEC_BASE + 624)
#define V4L2_CID_MPEG_VIDEO_HEVC_LOSSLESS_CU (V4L2_CID_CODEC_BASE + 625)
#define V4L2_CID_MPEG_VIDEO_HEVC_CONST_INTRA_PRED (V4L2_CID_CODEC_BASE + 626)
#define V4L2_CID_MPEG_VIDEO_HEVC_WAVEFRONT (V4L2_CID_CODEC_BASE + 627)
#define V4L2_CID_MPEG_VIDEO_HEVC_GENERAL_PB (V4L2_CID_CODEC_BASE + 628)
#define V4L2_CID_MPEG_VIDEO_HEVC_TEMPORAL_ID (V4L2_CID_CODEC_BASE + 629)
#define V4L2_CID_MPEG_VIDEO_HEVC_STRONG_SMOOTHING (V4L2_CID_CODEC_BASE + 630)
#define V4L2_CID_MPEG_VIDEO_HEVC_MAX_NUM_MERGE_MV_MINUS1 (V4L2_CID_CODEC_BASE + 631)
#define V4L2_CID_MPEG_VIDEO_HEVC_INTRA_PU_SPLIT (V4L2_CID_CODEC_BASE + 632)
#define V4L2_CID_MPEG_VIDEO_HEVC_TMV_PREDICTION (V4L2_CID_CODEC_BASE + 633)
#define V4L2_CID_MPEG_VIDEO_HEVC_WITHOUT_STARTCODE (V4L2_CID_CODEC_BASE + 634)
#define V4L2_CID_MPEG_VIDEO_HEVC_SIZE_OF_LENGTH_FIELD (V4L2_CID_CODEC_BASE + 635)
enum v4l2_cid_mpeg_video_hevc_size_of_length_field {
  V4L2_MPEG_VIDEO_HEVC_SIZE_0 = 0,
  V4L2_MPEG_VIDEO_HEVC_SIZE_1 = 1,
  V4L2_MPEG_VIDEO_HEVC_SIZE_2 = 2,
  V4L2_MPEG_VIDEO_HEVC_SIZE_4 = 3,
};
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L0_BR (V4L2_CID_CODEC_BASE + 636)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L1_BR (V4L2_CID_CODEC_BASE + 637)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L2_BR (V4L2_CID_CODEC_BASE + 638)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L3_BR (V4L2_CID_CODEC_BASE + 639)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L4_BR (V4L2_CID_CODEC_BASE + 640)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L5_BR (V4L2_CID_CODEC_BASE + 641)
#define V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L6_BR (V4L2_CID_CODEC_BASE + 642)
#define V4L2_CID_MPEG_VIDEO_REF_NUMBER_FOR_PFRAMES (V4L2_CID_CODEC_BASE + 643)
#define V4L2_CID_MPEG_VIDEO_PREPEND_SPSPPS_TO_IDR (V4L2_CID_CODEC_BASE + 644)
#define V4L2_CID_MPEG_VIDEO_CONSTANT_QUALITY (V4L2_CID_CODEC_BASE + 645)
#define V4L2_CID_MPEG_VIDEO_FRAME_SKIP_MODE (V4L2_CID_CODEC_BASE + 646)
enum v4l2_mpeg_video_frame_skip_mode {
  V4L2_MPEG_VIDEO_FRAME_SKIP_MODE_DISABLED = 0,
  V4L2_MPEG_VIDEO_FRAME_SKIP_MODE_LEVEL_LIMIT = 1,
  V4L2_MPEG_VIDEO_FRAME_SKIP_MODE_BUF_LIMIT = 2,
};
#
"""


```