Response:
Let's break down the thought process to answer the request about `v4l2-dv-timings.h`.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of the provided C header file. Key areas of interest are:

* **Functionality:** What does this file do?
* **Android Relevance:** How is it connected to Android?
* **libc Functions:** Detailed explanation of any libc functions used.
* **Dynamic Linker:** Explanation of dynamic linking aspects, including SO layout and linking process.
* **Logic & Assumptions:**  If any reasoning is involved, explain the inputs and outputs.
* **Common Errors:** What mistakes might developers make when using this file?
* **Framework/NDK Usage:** How does the Android system get to this file?
* **Frida Hooking:**  Provide examples of how to use Frida to inspect this file's behavior.

**2. Initial Analysis of the Code:**

The first thing that stands out is the `#ifndef`, `#define`, and `#endif` block. This is a standard include guard, preventing multiple inclusions of the header file. The comment at the top also indicates that the file is auto-generated and modifications will be lost. This suggests it's likely derived from a more authoritative source.

Next, I see a conditional macro definition for `V4L2_INIT_BT_TIMINGS`. This seems to handle different GCC versions, but the core functionality appears the same.

The bulk of the file consists of `#define` statements that define constants like `V4L2_DV_BT_CEA_640X480P59_94`. These constants appear to represent video timings, with names indicating resolution and refresh rate (e.g., 640x480 progressive at 59.94 Hz). The values within these definitions look like parameters for describing video signals.

**3. Identifying Key Concepts:**

Based on the `#define` names and values, the core concept is **video display timings**. The prefixes "V4L2_DV_BT_" strongly suggest a connection to the Video4Linux2 (V4L2) API, which is a standard Linux API for video input and output. The suffixes like "CEA" and "DMT" indicate adherence to specific video standards.

**4. Connecting to Android:**

Given the file's location within `bionic/libc/kernel/uapi/linux`, it's clearly part of Android's low-level system libraries. Android devices often have cameras and display capabilities, so V4L2 is a natural fit for managing these hardware components. The "handroid" subdirectory reinforces this Android connection.

**5. Addressing Specific Request Points:**

* **Functionality:** The file provides a set of pre-defined constants representing standard video display timings, likely used by drivers or middleware to configure video output.

* **Android Relevance:** Android's camera HAL (Hardware Abstraction Layer) and display drivers likely use these timings to communicate with video hardware. For example, a camera might report its supported output resolutions using these constants, or the display driver might use them to set the refresh rate and signal parameters of the screen.

* **libc Functions:**  A closer look reveals **no direct calls to libc functions**. The code primarily uses preprocessor macros. However, the *types* used within the implied structures (like `struct v4l2_dv_timings` - though the structure definition isn't in this snippet) would likely involve standard C data types provided by libc.

* **Dynamic Linker:** Since there are no function calls, there's **no direct involvement of the dynamic linker** in this header file itself. However, the *code that uses* these definitions would reside in shared libraries (`.so` files) and would be subject to dynamic linking. I need to provide a plausible SO layout example.

* **Logic and Assumptions:** The logic is primarily *declarative* – defining constants. However, the *selection* of which constant to use would involve logical decisions in the calling code. I can create a hypothetical input/output scenario.

* **Common Errors:**  Incorrectly using or interpreting these timing values could lead to display issues like flickering, out-of-sync signals, or unsupported resolutions.

* **Framework/NDK Usage:**  I need to trace the path from high-level Android APIs down to where these constants might be used. This would involve the media framework, camera service, HALs, and kernel drivers.

* **Frida Hooking:** I can provide examples of using Frida to inspect values related to these timings in running Android processes, even though the header itself doesn't contain executable code.

**6. Structuring the Answer:**

I'll organize the answer according to the user's request, providing clear headings for each point. I'll use examples and analogies to make the technical concepts more accessible. For the dynamic linker section, I'll create a simplified SO layout and explain the linking steps conceptually. For Frida, I'll provide concrete code snippets.

**7. Refinement and Detail:**

As I write, I'll add details to each section. For instance, when explaining the video timing parameters, I'll briefly mention what `width`, `height`, `pixelclock`, etc., represent. For the framework/NDK section, I'll provide a more concrete example, like an app using the Camera2 API.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe there are some hidden function-like macros that call libc.
* **Correction:**  Upon closer inspection, the macros primarily deal with structure initialization. The libc dependency is on the underlying data types.

* **Initial thought:** Focus solely on direct usage within a `.c` file.
* **Refinement:**  Expand to explain how these constants influence higher-level Android components.

* **Initial thought:** Only provide a generic Frida hook.
* **Refinement:** Provide more targeted examples that demonstrate how to inspect variables related to video timings.

By following this structured approach, I can systematically address all aspects of the user's request and provide a comprehensive and informative answer.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/v4l2-dv-timings.h` 这个头文件。

**功能列举:**

这个头文件的主要功能是定义了一系列**预定义的数字电视（Digital Video, DV）时序（Timings）参数**，用于 Video4Linux2 (V4L2) 框架。这些时序参数描述了各种标准视频分辨率、帧率以及相关的同步信号特性。

具体来说，它定义了：

1. **宏定义 `V4L2_INIT_BT_TIMINGS`**:  这是一个辅助宏，用于简化初始化 `v4l2_bt_timings` 结构体的过程。它根据不同的 GCC 版本使用了不同的语法。

2. **大量的预定义宏常量**: 这些常量以 `V4L2_DV_BT_` 开头，描述了各种标准的视频时序，包括：
   - **CEA (Consumer Electronics Association) 标准时序**: 例如 `V4L2_DV_BT_CEA_640X480P59_94`、`V4L2_DV_BT_CEA_1920X1080P60` 等，涵盖了常见的消费电子设备使用的分辨率和帧率。
   - **DMT (Display Monitor Timings) 标准时序**: 例如 `V4L2_DV_BT_DMT_640X350P85`、`V4L2_DV_BT_DMT_1920X1200P60` 等，这些通常用于计算机显示器。
   - **SDI (Serial Digital Interface) 标准时序**: 例如 `V4L2_DV_BT_SDI_720X487I60`，用于广播电视等专业视频领域。

   每个宏常量都代表一个特定的视频时序，并包含了该时序的详细参数，例如：
   - `type`:  时序类型 (CEA, DMT, SDI 等)。
   - `width`: 图像宽度（像素）。
   - `height`: 图像高度（像素）。
   - `interlaced`: 是否隔行扫描 (0: 逐行，1: 隔行)。
   - `flags`: 一些标志位，例如同步极性等。
   - `pixelclock`: 像素时钟频率（Hz）。
   - `hfrontporch`, `hsync`, `hbackporch`: 水平同步前肩、同步脉冲宽度、后肩。
   - `vfrontporch`, `vsync`, `vbackporch`: 垂直同步前肩、同步脉冲宽度、后肩。
   - `il_vfrontporch`, `il_vsync`, `il_vbackporch`: 隔行扫描的垂直同步参数。
   - `standards`: 支持的标准。
   - `fl` : 一些标志位。
   - `picture_aspect`: 图像宽高比。
   - `vic`: 视频识别码 (Video Identification Code)。

**与 Android 功能的关系及举例说明:**

这个头文件在 Android 系统中扮演着重要的角色，因为它直接关联到 **摄像头和显示** 功能。

* **摄像头 (Camera):** Android 设备上的摄像头驱动程序可能使用这些预定义的时序来配置摄像头的输出格式。例如，当一个应用请求摄像头以 1920x1080 分辨率和 30fps 帧率进行拍摄时，底层的驱动程序可能会使用 `V4L2_DV_BT_CEA_1920X1080P30` 中定义的参数来配置硬件。

* **显示 (Display):** Android 设备的显示驱动程序也会使用这些时序来配置输出到屏幕的视频信号。例如，连接到 Android 设备的 HDMI 显示器可能支持多种分辨率和刷新率，Android 系统需要根据显示器的 EDID (Extended Display Identification Data) 信息和用户的设置来选择合适的时序。

**举例说明:**

假设一个 Android 应用想要使用设备的后置摄像头录制 1080p 60fps 的视频。

1. **应用层 (Java/Kotlin):** 应用通过 Android 的 Camera2 API 请求以 1920x1080 分辨率和 60fps 帧率录制视频。

2. **框架层 (Framework):** Camera Service 接收到请求，并根据设备的硬件能力和应用的要求，选择一个合适的视频配置。

3. **硬件抽象层 (HAL):** Camera HAL (hardware/interfaces/camera/…)  会调用底层的摄像头驱动程序。

4. **内核驱动层 (Kernel Driver):** 摄像头驱动程序会使用 `v4l2` 相关的 ioctl 命令与摄像头硬件进行交互。在配置视频输出格式时，驱动程序可能会使用 `V4L2_DV_BT_CEA_1920X1080P60` 中定义的参数来设置摄像头的输出时序。这包括设置像素时钟频率、水平和垂直同步信号的参数等。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个头文件本身并没有直接调用任何 libc 函数。** 它主要定义的是宏常量和一些预处理指令。libc 函数是在 `.c` 或 `.cpp` 源文件中被调用的，这些源文件可能会包含这个头文件。

然而，这个头文件中定义的宏会用于初始化结构体，而这些结构体在内核或驱动程序中会被使用，并最终传递给内核提供的系统调用，这些系统调用的实现部分位于内核空间，不属于 libc 的范畴。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个头文件本身与 dynamic linker 没有直接关系。**  Dynamic linker 主要负责在程序运行时加载和链接共享库 (`.so` 文件)。

然而，如果一个共享库（例如，一个摄像头相关的 HAL 库）的代码中包含了这个头文件，那么这个共享库在加载时会涉及到 dynamic linker。

**SO 布局样本 (假设一个名为 `android.hardware.camera.provider@2.4-service.so` 的 HAL 库使用了这个头文件):**

```
android.hardware.camera.provider@2.4-service.so:
    Offset          VirtAddr          FileSiz MemSiz  Flags  Align ReqLink OffRel Type    ObjectName
    ......          ......          ...... ...... ..... ..... ...... ...... -------- ----------
    0x0000000000000438  0xXXXXXXXXXXXX0438     0x28    0x28  R  A     8      0 REL      v4l2_dv_timings.h
    ......          ......          ...... ...... ..... ..... ...... ...... -------- ----------
    (代码段)
    ......
    (数据段，可能包含使用这些宏初始化的结构体变量)
    ......
```

**链接的处理过程:**

1. **编译时:** 当编译 `android.hardware.camera.provider@2.4-service.so` 的源代码时，如果代码中包含了 `v4l2-dv-timings.h`，预处理器会将这些宏定义展开。编译器会根据这些展开后的值生成目标代码。

2. **链接时:** 静态链接器会将编译生成的目标文件链接成共享库。在这个阶段，`v4l2-dv-timings.h` 中的宏定义已经完成了它的使命，它不会作为单独的链接单元存在。

3. **运行时:** 当 Android 系统需要加载 `android.hardware.camera.provider@2.4-service.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下步骤：
   - **加载共享库:** 将 `.so` 文件加载到内存中。
   - **符号解析 (Symbol Resolution):** 如果共享库中定义了需要被其他库调用的符号，或者它需要调用其他库的符号，dynamic linker 会进行符号解析，找到这些符号的地址。但由于 `v4l2-dv-timings.h` 中只定义了宏，并没有导出符号，因此这里不涉及对该头文件符号的解析。
   - **重定位 (Relocation):**  调整代码和数据段中的地址，使其在当前内存地址空间中有效。

**如果做了逻辑推理，请给出假设输入与输出:**

虽然这个头文件本身没有复杂的逻辑，但可以假设一个使用它的场景：

**假设输入:**  Android 系统需要配置 HDMI 输出到一台支持 1920x1080@60Hz 的显示器。

**逻辑推理过程:**

1. **系统读取 EDID:** Android 系统会读取连接的 HDMI 显示器的 EDID 信息，从中获取显示器支持的分辨率和刷新率列表。

2. **匹配最佳时序:** 系统会将 EDID 中报告的信息与 `v4l2-dv-timings.h` 中定义的标准时序进行匹配。如果找到了完全匹配的条目（例如 `V4L2_DV_BT_CEA_1920X1080P60`），则使用该时序。

3. **配置显示驱动:**  显示驱动程序会使用匹配到的时序参数来配置硬件，包括设置像素时钟、同步信号等。

**假设输出:**  显示器成功显示 1920x1080@60Hz 的画面。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **直接修改自动生成的文件:**  这个头文件顶部的注释已经明确指出 "Modifications will be lost"。用户或开发者不应该直接修改这个文件，因为任何更改都可能在下次代码生成时被覆盖。如果需要自定义时序，应该在其他地方定义。

2. **错误地假设所有设备都支持所有时序:**  并非所有 Android 设备或显示设备都支持 `v4l2-dv-timings.h` 中定义的所有时序。开发者在选择时序时，应该根据实际硬件能力和 EDID 信息进行判断。如果尝试使用不支持的时序，可能会导致显示错误或驱动程序崩溃。

3. **手动解析时序参数的含义:**  虽然这些宏的名字和参数看起来比较直观，但直接手动解析每个参数的含义并用于硬件配置是容易出错的。应该使用 V4L2 提供的结构体和 API 来处理这些时序信息。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**从 Android Framework 到内核驱动的路径（以摄像头为例）：**

1. **应用层 (Java/Kotlin):** 应用使用 `android.hardware.camera2` 包中的类 (如 `CameraManager`, `CameraDevice`, `CaptureRequest`) 来访问摄像头。

2. **Framework 层 (Java):**
   - `CameraService` 接收到应用的请求。
   - `CameraService` 通过 Binder IPC 与 Camera HAL 进程通信。

3. **HAL 层 (C++):**
   - Camera HAL 接口 (hardware/interfaces/camera/…) 的实现接收到来自 `CameraService` 的调用。
   - HAL 实现通常会加载特定于硬件的库。

4. **Native 驱动适配层 (C/C++):**
   - 硬件相关的库会调用内核提供的 V4L2 API。这通常涉及到打开设备文件 (`/dev/videoX`) 并使用 `ioctl` 系统调用。

5. **内核驱动层 (Kernel Driver):**
   - 内核中的摄像头驱动程序 (例如，MediaTek 或 Qualcomm 提供的驱动) 接收到 `ioctl` 调用。
   - 当需要配置视频格式时，驱动程序可能会使用 `v4l2-dv-timings.h` 中定义的宏来填充 `struct v4l2_dv_timings` 结构体，然后通过 `VIDIOC_S_DV_TIMINGS` 或类似的 `ioctl` 命令将其传递给摄像头硬件。

**Frida Hook 示例 (以 hook 摄像头 HAL 获取或设置时序为例):**

假设你想在摄像头 HAL 库中查看何时使用了某个特定的时序配置。

首先，你需要找到负责设置视频时序的 HAL 函数。这通常涉及到查看 Camera HAL 接口的定义 (`hardware/interfaces/camera/…/ICameraDevice.hal`) 和具体的 HAL 实现代码。

假设你找到了一个名为 `setStreamConfiguration` 的 HAL 函数，它接收一个包含视频流配置的参数，其中可能包含时序信息。

**Frida Hook 脚本示例:**

```javascript
function hookCameraHAL() {
  const cameraHalLib = Process.getModuleByName("android.hardware.camera.provider@2.4-service.so"); // 替换为实际的 HAL 库名

  if (cameraHalLib) {
    const symbols = cameraHalLib.enumerateSymbols();
    for (let i = 0; i < symbols.length; i++) {
      const symbol = symbols[i];
      if (symbol.name.includes("setStreamConfiguration")) { // 根据实际函数名调整
        Interceptor.attach(ptr(symbol.address), {
          onEnter: function (args) {
            console.log("[+] Hooked setStreamConfiguration");
            // 假设时序信息在第二个参数中
            const streamConfig = args[1];
            // 需要根据 streamConfig 的结构来解析时序信息
            // 这可能涉及到读取内存中的结构体字段
            console.log("Stream Configuration:", streamConfig);

            // 尝试读取可能的时序参数 (需要根据实际结构体定义调整)
            // 例如，假设 width 在偏移 8，height 在偏移 12
            const width = streamConfig.readU32();
            const height = streamConfig.add(4).readU32();
            console.log("Width:", width, "Height:", height);
          },
          onLeave: function (retval) {
            console.log("[+] setStreamConfiguration returned:", retval);
          },
        });
      }
    }
  } else {
    console.log("[-] Camera HAL library not found.");
  }
}

setImmediate(hookCameraHAL);
```

**使用 Frida 调试步骤:**

1. **找到目标进程:**  确定运行 Camera HAL 的进程的 ID。

2. **运行 Frida 脚本:** 使用 Frida 命令将上述脚本注入到目标进程：
   ```bash
   frida -U -f <目标进程包名或进程名> -l your_frida_script.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <目标进程包名或进程名> -l your_frida_script.js
   ```

3. **操作应用:** 运行使用摄像头的 Android 应用，触发 HAL 函数的调用。

4. **查看 Frida 输出:** Frida 会在控制台输出 hook 到的函数调用信息，包括参数值，你可以从中观察到是否使用了 `v4l2-dv-timings.h` 中定义的时序参数。

**更精细的 Hook:**

如果想更精确地观察 `v4l2-dv-timings.h` 中定义的常量如何被使用，可以尝试 hook 内核驱动中的 V4L2 相关 `ioctl` 调用，例如 `VIDIOC_S_DV_TIMINGS`。但这通常需要 root 权限和对内核符号的了解。

希望这个详细的分析能够帮助你理解 `v4l2-dv-timings.h` 的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/v4l2-dv-timings.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _V4L2_DV_TIMINGS_H
#define _V4L2_DV_TIMINGS_H
#if __GNUC__ < 4 || __GNUC__ == 4 && __GNUC_MINOR__ < 6
#define V4L2_INIT_BT_TIMINGS(_width,args...) {.bt = { _width, ##args } }
#else
#define V4L2_INIT_BT_TIMINGS(_width,args...) . bt = { _width, ##args }
#endif
#define V4L2_DV_BT_CEA_640X480P59_94 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(640, 480, 0, 0, 25175000, 16, 96, 48, 10, 2, 33, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 1) \
}
#define V4L2_DV_BT_CEA_720X480I59_94 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(720, 480, 1, 0, 13500000, 19, 62, 57, 4, 3, 15, 4, 3, 16, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_HALF_LINE | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_PICTURE_ASPECT | V4L2_DV_FL_HAS_CEA861_VIC, { 4, 3 }, 6) \
}
#define V4L2_DV_BT_CEA_720X480P59_94 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(720, 480, 0, 0, 27000000, 16, 62, 60, 9, 6, 30, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_PICTURE_ASPECT | V4L2_DV_FL_HAS_CEA861_VIC, { 4, 3 }, 2) \
}
#define V4L2_DV_BT_CEA_720X576I50 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(720, 576, 1, 0, 13500000, 12, 63, 69, 2, 3, 19, 2, 3, 20, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_HALF_LINE | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_PICTURE_ASPECT | V4L2_DV_FL_HAS_CEA861_VIC, { 4, 3 }, 21) \
}
#define V4L2_DV_BT_CEA_720X576P50 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(720, 576, 0, 0, 27000000, 12, 64, 68, 5, 5, 39, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_PICTURE_ASPECT | V4L2_DV_FL_HAS_CEA861_VIC, { 4, 3 }, 17) \
}
#define V4L2_DV_BT_CEA_1280X720P24 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 720, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 59400000, 1760, 40, 220, 5, 5, 20, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 60) \
}
#define V4L2_DV_BT_CEA_1280X720P25 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 720, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 74250000, 2420, 40, 220, 5, 5, 20, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 61) \
}
#define V4L2_DV_BT_CEA_1280X720P30 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 720, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 74250000, 1760, 40, 220, 5, 5, 20, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 62) \
}
#define V4L2_DV_BT_CEA_1280X720P50 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 720, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 74250000, 440, 40, 220, 5, 5, 20, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 19) \
}
#define V4L2_DV_BT_CEA_1280X720P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 720, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 74250000, 110, 40, 220, 5, 5, 20, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 4) \
}
#define V4L2_DV_BT_CEA_1920X1080P24 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1080, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 74250000, 638, 44, 148, 4, 5, 36, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 32) \
}
#define V4L2_DV_BT_CEA_1920X1080P25 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1080, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 74250000, 528, 44, 148, 4, 5, 36, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 33) \
}
#define V4L2_DV_BT_CEA_1920X1080P30 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1080, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 74250000, 88, 44, 148, 4, 5, 36, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 34) \
}
#define V4L2_DV_BT_CEA_1920X1080I50 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1080, 1, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 74250000, 528, 44, 148, 2, 5, 15, 2, 5, 16, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_HALF_LINE | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 20) \
}
#define V4L2_DV_BT_CEA_1920X1080P50 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1080, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 148500000, 528, 44, 148, 4, 5, 36, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 31) \
}
#define V4L2_DV_BT_CEA_1920X1080I60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1080, 1, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 74250000, 88, 44, 148, 2, 5, 15, 2, 5, 16, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_HALF_LINE | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 5) \
}
#define V4L2_DV_BT_CEA_1920X1080P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1080, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 148500000, 88, 44, 148, 4, 5, 36, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 16) \
}
#define V4L2_DV_BT_CEA_3840X2160P24 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(3840, 2160, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 297000000, 1276, 88, 296, 8, 10, 72, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC | V4L2_DV_FL_HAS_HDMI_VIC, { 0, 0 }, 93, 3) \
}
#define V4L2_DV_BT_CEA_3840X2160P25 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(3840, 2160, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 297000000, 1056, 88, 296, 8, 10, 72, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC | V4L2_DV_FL_HAS_HDMI_VIC, { 0, 0 }, 94, 2) \
}
#define V4L2_DV_BT_CEA_3840X2160P30 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(3840, 2160, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 297000000, 176, 88, 296, 8, 10, 72, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC | V4L2_DV_FL_HAS_HDMI_VIC, { 0, 0 }, 95, 1) \
}
#define V4L2_DV_BT_CEA_3840X2160P50 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(3840, 2160, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 594000000, 1056, 88, 296, 8, 10, 72, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 96) \
}
#define V4L2_DV_BT_CEA_3840X2160P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(3840, 2160, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 594000000, 176, 88, 296, 8, 10, 72, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 97) \
}
#define V4L2_DV_BT_CEA_4096X2160P24 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(4096, 2160, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 297000000, 1020, 88, 296, 8, 10, 72, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC | V4L2_DV_FL_HAS_HDMI_VIC, { 0, 0 }, 98, 4) \
}
#define V4L2_DV_BT_CEA_4096X2160P25 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(4096, 2160, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 297000000, 968, 88, 128, 8, 10, 72, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 99) \
}
#define V4L2_DV_BT_CEA_4096X2160P30 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(4096, 2160, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 297000000, 88, 88, 128, 8, 10, 72, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 100) \
}
#define V4L2_DV_BT_CEA_4096X2160P50 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(4096, 2160, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 594000000, 968, 88, 128, 8, 10, 72, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 101) \
}
#define V4L2_DV_BT_CEA_4096X2160P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(4096, 2160, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 594000000, 88, 88, 128, 8, 10, 72, 0, 0, 0, V4L2_DV_BT_STD_CEA861, V4L2_DV_FL_CAN_REDUCE_FPS | V4L2_DV_FL_IS_CE_VIDEO | V4L2_DV_FL_HAS_CEA861_VIC, { 0, 0 }, 102) \
}
#define V4L2_DV_BT_DMT_640X350P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(640, 350, 0, V4L2_DV_HSYNC_POS_POL, 31500000, 32, 64, 96, 32, 3, 60, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_640X400P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(640, 400, 0, V4L2_DV_VSYNC_POS_POL, 31500000, 32, 64, 96, 1, 3, 41, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_720X400P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(720, 400, 0, V4L2_DV_VSYNC_POS_POL, 35500000, 36, 72, 108, 1, 3, 42, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_640X480P60 V4L2_DV_BT_CEA_640X480P59_94
#define V4L2_DV_BT_DMT_640X480P72 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(640, 480, 0, 0, 31500000, 24, 40, 128, 9, 3, 28, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_640X480P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(640, 480, 0, 0, 31500000, 16, 64, 120, 1, 3, 16, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_640X480P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(640, 480, 0, 0, 36000000, 56, 56, 80, 1, 3, 25, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_800X600P56 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(800, 600, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 36000000, 24, 72, 128, 1, 2, 22, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_800X600P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(800, 600, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 40000000, 40, 128, 88, 1, 4, 23, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_800X600P72 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(800, 600, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 50000000, 56, 120, 64, 37, 6, 23, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_800X600P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(800, 600, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 49500000, 16, 80, 160, 1, 3, 21, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_800X600P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(800, 600, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 56250000, 32, 64, 152, 1, 3, 27, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_800X600P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(800, 600, 0, V4L2_DV_HSYNC_POS_POL, 73250000, 48, 32, 80, 3, 4, 29, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_848X480P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(848, 480, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 33750000, 16, 112, 112, 6, 8, 23, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1024X768I43 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1024, 768, 1, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 44900000, 8, 176, 56, 0, 4, 20, 0, 4, 21, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1024X768P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1024, 768, 0, 0, 65000000, 24, 136, 160, 3, 6, 29, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1024X768P70 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1024, 768, 0, 0, 75000000, 24, 136, 144, 3, 6, 29, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1024X768P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1024, 768, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 78750000, 16, 96, 176, 1, 3, 28, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1024X768P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1024, 768, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 94500000, 48, 96, 208, 1, 3, 36, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1024X768P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1024, 768, 0, V4L2_DV_HSYNC_POS_POL, 115500000, 48, 32, 80, 3, 4, 38, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1152X864P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1152, 864, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 108000000, 64, 128, 256, 1, 3, 32, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1280X720P60 V4L2_DV_BT_CEA_1280X720P60
#define V4L2_DV_BT_DMT_1280X768P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 768, 0, V4L2_DV_HSYNC_POS_POL, 68250000, 48, 32, 80, 3, 7, 12, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1280X768P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 768, 0, V4L2_DV_VSYNC_POS_POL, 79500000, 64, 128, 192, 3, 7, 20, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1280X768P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 768, 0, V4L2_DV_VSYNC_POS_POL, 102250000, 80, 128, 208, 3, 7, 27, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1280X768P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 768, 0, V4L2_DV_VSYNC_POS_POL, 117500000, 80, 136, 216, 3, 7, 31, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1280X768P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 768, 0, V4L2_DV_HSYNC_POS_POL, 140250000, 48, 32, 80, 3, 7, 35, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1280X800P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 800, 0, V4L2_DV_HSYNC_POS_POL, 71000000, 48, 32, 80, 3, 6, 14, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1280X800P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 800, 0, V4L2_DV_VSYNC_POS_POL, 83500000, 72, 128, 200, 3, 6, 22, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1280X800P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 800, 0, V4L2_DV_VSYNC_POS_POL, 106500000, 80, 128, 208, 3, 6, 29, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1280X800P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 800, 0, V4L2_DV_VSYNC_POS_POL, 122500000, 80, 136, 216, 3, 6, 34, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1280X800P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 800, 0, V4L2_DV_HSYNC_POS_POL, 146250000, 48, 32, 80, 3, 6, 38, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1280X960P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 960, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 108000000, 96, 112, 312, 1, 3, 36, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1280X960P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 960, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 148500000, 64, 160, 224, 1, 3, 47, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1280X960P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 960, 0, V4L2_DV_HSYNC_POS_POL, 175500000, 48, 32, 80, 3, 4, 50, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1280X1024P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 1024, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 108000000, 48, 112, 248, 1, 3, 38, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1280X1024P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 1024, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 135000000, 16, 144, 248, 1, 3, 38, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1280X1024P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 1024, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 157500000, 64, 160, 224, 1, 3, 44, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1280X1024P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1280, 1024, 0, V4L2_DV_HSYNC_POS_POL, 187250000, 48, 32, 80, 3, 7, 50, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1360X768P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1360, 768, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 85500000, 64, 112, 256, 3, 6, 18, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1360X768P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1360, 768, 0, V4L2_DV_HSYNC_POS_POL, 148250000, 48, 32, 80, 3, 5, 37, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1366X768P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1366, 768, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 85500000, 70, 143, 213, 3, 3, 24, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1366X768P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1366, 768, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 72000000, 14, 56, 64, 1, 3, 28, 0, 0, 0, V4L2_DV_BT_STD_DMT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1400X1050P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1400, 1050, 0, V4L2_DV_HSYNC_POS_POL, 101000000, 48, 32, 80, 3, 4, 23, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1400X1050P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1400, 1050, 0, V4L2_DV_VSYNC_POS_POL, 121750000, 88, 144, 232, 3, 4, 32, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1400X1050P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1400, 1050, 0, V4L2_DV_VSYNC_POS_POL, 156000000, 104, 144, 248, 3, 4, 42, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1400X1050P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1400, 1050, 0, V4L2_DV_VSYNC_POS_POL, 179500000, 104, 152, 256, 3, 4, 48, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1400X1050P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1400, 1050, 0, V4L2_DV_HSYNC_POS_POL, 208000000, 48, 32, 80, 3, 4, 55, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1440X900P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1440, 900, 0, V4L2_DV_HSYNC_POS_POL, 88750000, 48, 32, 80, 3, 6, 17, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1440X900P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1440, 900, 0, V4L2_DV_VSYNC_POS_POL, 106500000, 80, 152, 232, 3, 6, 25, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1440X900P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1440, 900, 0, V4L2_DV_VSYNC_POS_POL, 136750000, 96, 152, 248, 3, 6, 33, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1440X900P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1440, 900, 0, V4L2_DV_VSYNC_POS_POL, 157000000, 104, 152, 256, 3, 6, 39, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1440X900P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1440, 900, 0, V4L2_DV_HSYNC_POS_POL, 182750000, 48, 32, 80, 3, 6, 44, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1600X900P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1600, 900, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 108000000, 24, 80, 96, 1, 3, 96, 0, 0, 0, V4L2_DV_BT_STD_DMT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1600X1200P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1600, 1200, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 162000000, 64, 192, 304, 1, 3, 46, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1600X1200P65 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1600, 1200, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 175500000, 64, 192, 304, 1, 3, 46, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1600X1200P70 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1600, 1200, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 189000000, 64, 192, 304, 1, 3, 46, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1600X1200P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1600, 1200, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 202500000, 64, 192, 304, 1, 3, 46, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1600X1200P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1600, 1200, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 229500000, 64, 192, 304, 1, 3, 46, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1600X1200P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1600, 1200, 0, V4L2_DV_HSYNC_POS_POL, 268250000, 48, 32, 80, 3, 4, 64, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1680X1050P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1680, 1050, 0, V4L2_DV_HSYNC_POS_POL, 119000000, 48, 32, 80, 3, 6, 21, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1680X1050P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1680, 1050, 0, V4L2_DV_VSYNC_POS_POL, 146250000, 104, 176, 280, 3, 6, 30, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1680X1050P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1680, 1050, 0, V4L2_DV_VSYNC_POS_POL, 187000000, 120, 176, 296, 3, 6, 40, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1680X1050P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1680, 1050, 0, V4L2_DV_VSYNC_POS_POL, 214750000, 128, 176, 304, 3, 6, 46, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1680X1050P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1680, 1050, 0, V4L2_DV_HSYNC_POS_POL, 245500000, 48, 32, 80, 3, 6, 53, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1792X1344P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1792, 1344, 0, V4L2_DV_VSYNC_POS_POL, 204750000, 128, 200, 328, 1, 3, 46, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1792X1344P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1792, 1344, 0, V4L2_DV_VSYNC_POS_POL, 261000000, 96, 216, 352, 1, 3, 69, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1792X1344P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1792, 1344, 0, V4L2_DV_HSYNC_POS_POL, 333250000, 48, 32, 80, 3, 4, 72, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1856X1392P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1856, 1392, 0, V4L2_DV_VSYNC_POS_POL, 218250000, 96, 224, 352, 1, 3, 43, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1856X1392P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1856, 1392, 0, V4L2_DV_VSYNC_POS_POL, 288000000, 128, 224, 352, 1, 3, 104, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1856X1392P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1856, 1392, 0, V4L2_DV_HSYNC_POS_POL, 356500000, 48, 32, 80, 3, 4, 75, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1920X1080P60 V4L2_DV_BT_CEA_1920X1080P60
#define V4L2_DV_BT_DMT_1920X1200P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1200, 0, V4L2_DV_HSYNC_POS_POL, 154000000, 48, 32, 80, 3, 6, 26, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1920X1200P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1200, 0, V4L2_DV_VSYNC_POS_POL, 193250000, 136, 200, 336, 3, 6, 36, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1920X1200P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1200, 0, V4L2_DV_VSYNC_POS_POL, 245250000, 136, 208, 344, 3, 6, 46, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1920X1200P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1200, 0, V4L2_DV_VSYNC_POS_POL, 281250000, 144, 208, 352, 3, 6, 53, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_1920X1200P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1200, 0, V4L2_DV_HSYNC_POS_POL, 317000000, 48, 32, 80, 3, 6, 62, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_1920X1440P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1440, 0, V4L2_DV_VSYNC_POS_POL, 234000000, 128, 208, 344, 1, 3, 56, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1920X1440P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1440, 0, V4L2_DV_VSYNC_POS_POL, 297000000, 144, 224, 352, 1, 3, 56, 0, 0, 0, V4L2_DV_BT_STD_DMT, 0) \
}
#define V4L2_DV_BT_DMT_1920X1440P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(1920, 1440, 0, V4L2_DV_HSYNC_POS_POL, 380500000, 48, 32, 80, 3, 4, 78, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_2048X1152P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(2048, 1152, 0, V4L2_DV_HSYNC_POS_POL | V4L2_DV_VSYNC_POS_POL, 162000000, 26, 80, 96, 1, 3, 44, 0, 0, 0, V4L2_DV_BT_STD_DMT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_2560X1600P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(2560, 1600, 0, V4L2_DV_HSYNC_POS_POL, 268500000, 48, 32, 80, 3, 6, 37, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_2560X1600P60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(2560, 1600, 0, V4L2_DV_VSYNC_POS_POL, 348500000, 192, 280, 472, 3, 6, 49, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_2560X1600P75 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(2560, 1600, 0, V4L2_DV_VSYNC_POS_POL, 443250000, 208, 280, 488, 3, 6, 63, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_2560X1600P85 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(2560, 1600, 0, V4L2_DV_VSYNC_POS_POL, 505250000, 208, 280, 488, 3, 6, 73, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, 0) \
}
#define V4L2_DV_BT_DMT_2560X1600P120_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(2560, 1600, 0, V4L2_DV_HSYNC_POS_POL, 552750000, 48, 32, 80, 3, 6, 85, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_4096X2160P60_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(4096, 2160, 0, V4L2_DV_HSYNC_POS_POL, 556744000, 8, 32, 40, 48, 8, 6, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_DMT_4096X2160P59_94_RB {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(4096, 2160, 0, V4L2_DV_HSYNC_POS_POL, 556188000, 8, 32, 40, 48, 8, 6, 0, 0, 0, V4L2_DV_BT_STD_DMT | V4L2_DV_BT_STD_CVT, V4L2_DV_FL_REDUCED_BLANKING) \
}
#define V4L2_DV_BT_SDI_720X487I60 {.type = V4L2_DV_BT_656_1120, V4L2_INIT_BT_TIMINGS(720, 487, 1, V4L2_DV_HSYNC_POS_POL, 13500000, 16, 121, 0, 0, 19, 0, 0, 19, 0, V4L2_DV_BT_STD_SDI, V4L2_DV_FL_FIRST_FIELD_EXTRA_LINE) \
}
#endif

"""

```