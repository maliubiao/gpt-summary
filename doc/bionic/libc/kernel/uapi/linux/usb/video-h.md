Response:
Let's break down the thought process for answering the request about the `video.h` file.

**1. Understanding the Core Request:**

The central ask is to analyze a C header file related to USB Video Class (UVC) and explain its function, its relationship to Android, and how Android uses it. The request also has specific sub-questions related to libc functions, dynamic linking, error handling, and debugging.

**2. Initial Assessment of the File:**

* **Header Guard:** The `#ifndef __LINUX_USB_VIDEO_H` and `#define __LINUX_USB_VIDEO_H` indicate this is a standard C header file, preventing multiple inclusions.
* **Include:** `#include <linux/types.h>` tells us it relies on basic Linux data types.
* **Constants:** The majority of the file consists of `#define` statements defining constants. These appear to be related to the UVC specification.
* **Enums:**  `enum uvc_color_primaries_values`, `enum uvc_transfer_characteristics_values`, `enum uvc_matrix_coefficients` define sets of related named constants.
* **Structs:**  A series of `struct` definitions like `uvc_descriptor_header`, `uvc_header_descriptor`, etc., suggest this file describes the structure of UVC descriptors used in communication between the host (Android device) and a UVC device (like a webcam).
* **Macros for Structs:**  Macros like `UVC_DT_HEADER_SIZE(n)` and `DECLARE_UVC_HEADER_DESCRIPTOR(n)` are used to define struct sizes and declare structs with variable-length arrays.

**3. Deciphering the Functionality:**

Based on the naming conventions and the UVC abbreviation, the primary function is clearly related to the USB Video Class. The constants represent various parts of the UVC protocol:

* **Interface and Endpoint Types:** `UVC_SC_*`, `UVC_PC_*`, `UVC_EP_*`
* **Descriptor Types:** `UVC_VC_*`, `UVC_VS_*`  These are the core building blocks of UVC communication.
* **Control Commands:** `UVC_SET_CUR`, `UVC_GET_CUR`, `UVC_CT_*`, `UVC_PU_*`, `UVC_VS_*`  These represent ways to control the video device's features.
* **Terminal Types:** `UVC_TT_*`, `UVC_ITT_*`, `UVC_OTT_*`  Define the different types of input and output points in the video pipeline.
* **Status and Stream Information:** `UVC_STATUS_TYPE_*`, `UVC_STREAM_*`
* **Color Information:** `uvc_color_primaries_values`, etc.

The structs directly map to the data structures defined in the UVC specification, used for sending and receiving configuration and data.

**4. Relating to Android:**

The file is located within the Android Bionic library (`bionic/libc/kernel/uapi/linux/usb/video.h`). This strongly suggests its role in how Android interacts with USB video devices.

* **Camera API:** The most obvious connection is to Android's Camera APIs. When an Android app uses the camera, the framework needs to communicate with the underlying hardware, which might be a UVC device.
* **HAL (Hardware Abstraction Layer):** The Camera HAL is a key component that interacts directly with hardware drivers. This header file provides the necessary definitions for this interaction.
* **USB Stack:** Android's USB stack utilizes these definitions to parse and create USB control and data transfers for video.

**5. Addressing Specific Questions:**

* **Libc Functions:** The header file *itself* doesn't contain any libc function implementations. It primarily defines constants and data structures. The *usage* of these definitions within Android will involve libc functions for memory management, system calls, etc., but the header file is just providing the blueprint.
* **Dynamic Linker:** Similar to libc, the header file doesn't directly involve the dynamic linker. However, libraries that *use* this header (like camera HAL implementations) will be linked dynamically. The example SO layout and linking process will illustrate this.
* **Logical Reasoning:**  The logical reasoning involves understanding how the constants and structs relate to the UVC specification. For example, knowing that `UVC_CT_EXPOSURE_TIME_ABSOLUTE_CONTROL` corresponds to a specific control command helps understand its purpose.
* **User/Programming Errors:**  Common errors would involve using incorrect constants, misinterpreting the meaning of the structs, or not properly handling the communication with the USB device based on these definitions.
* **Android Framework/NDK Path:**  Tracing the path involves understanding the layers of Android's architecture, starting from the app, going through the framework, down to the HAL, and eventually reaching the kernel driver and this header file.
* **Frida Hook:**  A Frida hook example can demonstrate how to intercept and examine the data being exchanged based on these definitions.

**6. Structuring the Answer:**

A logical structure for the answer would be:

* **Introduction:** Briefly state what the file is and its purpose.
* **Functionality Breakdown:** List the main types of definitions (constants, enums, structs) and explain what each category represents in the context of UVC.
* **Android Relationship:**  Explain how this file is used in the Android ecosystem, specifically mentioning the Camera API and HAL. Provide a concrete example.
* **Libc Functions:**  Clarify that the header doesn't *implement* libc functions but is used in code that does.
* **Dynamic Linker:** Explain the role of the dynamic linker in loading libraries that use this header. Provide an example SO layout and the linking process.
* **Logical Reasoning Example:** Show how the definitions translate to real-world UVC concepts.
* **Common Errors:**  Give practical examples of programming mistakes.
* **Android Framework/NDK Path:** Detail the sequence of calls and components involved.
* **Frida Hook Example:**  Provide a concrete Frida script to demonstrate debugging.

**7. Refinement and Language:**

Finally, ensure the language is clear, concise, and in Chinese as requested. Use appropriate technical terms while also providing explanations for those less familiar with the details. The use of bullet points and clear headings makes the information easier to digest.

By following these steps, the detailed and comprehensive answer provided earlier can be generated. The key is to understand the purpose of the file, its connection to the broader system (Android), and then address each specific aspect of the request methodically.
这个文件 `bionic/libc/kernel/uapi/linux/usb/video.h` 是 Android 系统中用于定义 Linux 内核中 USB 视频类 (UVC, USB Video Class) 相关的常量、枚举和结构体的头文件。它属于 Bionic 库的一部分，Bionic 是 Android 系统的 C 库，因此它直接服务于 Android 系统底层的硬件交互。

**功能列举:**

1. **定义 UVC 协议常量:**  文件中包含了大量的 `#define` 预处理指令，定义了 UVC 协议中各种描述符类型、子类型、控制命令、终端类型、端点类型等常量。这些常量用于在 Android 系统和 USB 视频设备之间进行通信，识别和控制视频设备的各种功能。

   * 例如：`UVC_SC_VIDEOCONTROL` 和 `UVC_SC_VIDEOSTREAMING` 定义了视频控制接口和视频流接口的子类代码。
   * 例如：`UVC_CT_EXPOSURE_TIME_ABSOLUTE_CONTROL` 定义了曝光时间绝对控制的控制命令。
   * 例如：`UVC_VS_FORMAT_MJPEG` 定义了 MJPEG 视频格式。

2. **定义 UVC 协议枚举类型:** 文件中定义了一些 `enum` 类型，用于表示颜色基色、传输特性和矩阵系数等视频相关的属性。

   * 例如：`enum uvc_color_primaries_values` 定义了不同的颜色基色标准，如 `UVC_COLOR_PRIMARIES_BT_709_SRGB`。

3. **定义 UVC 协议数据结构:** 文件中定义了各种 `struct` 结构体，这些结构体对应着 UVC 协议中定义的各种描述符，用于在主机（Android 设备）和设备（如摄像头）之间交换配置信息和控制信息。

   * 例如：`struct uvc_header_descriptor` 定义了视频控制接口头描述符的结构。
   * 例如：`struct uvc_input_terminal_descriptor` 定义了输入终端描述符的结构。
   * 例如：`struct uvc_streaming_control` 定义了视频流控制请求的结构。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android 系统与 USB 视频设备交互的基础。当 Android 设备连接一个 USB 摄像头时，系统需要理解摄像头的能力并进行控制。这个头文件中定义的常量和结构体就被用于这个过程。

**举例说明:**

* **Camera API 使用:**  Android 应用通过 Camera API 请求访问摄像头。底层的 CameraService 和 HAL (Hardware Abstraction Layer) 会使用这里定义的常量来构造和解析与摄像头通信的 USB 控制请求。例如，当应用设置曝光时间时，HAL 可能会使用 `UVC_CT_EXPOSURE_TIME_ABSOLUTE_CONTROL` 常量来构造一个 USB 控制传输，并将期望的曝光时间值发送给摄像头。
* **视频录制和播放:** 当 Android 设备录制视频时，底层的驱动程序会使用这里定义的格式常量（如 `UVC_VS_FORMAT_MJPEG`) 来识别摄像头输出的视频流格式，并进行相应的解码和处理。
* **摄像头参数控制:**  Android 允许用户调整摄像头的亮度、对比度、焦距等参数。这些操作最终会映射到对 UVC 定义的控制单元的访问，例如使用 `UVC_PU_BRIGHTNESS_CONTROL` 来设置亮度。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **不包含任何 libc 函数的实现**。它只是定义了常量、枚举和结构体。  libc 函数是在 Bionic 库的其他源文件中实现的。这个头文件是被 libc 库中的其他代码所包含和使用的。

例如，当 Android 系统需要发送一个 USB 控制请求时，它可能会使用 libc 提供的 `ioctl` 系统调用与 USB 驱动程序进行交互。`ioctl` 的具体实现位于 Bionic 库的 `sys/ioctl.c` 等文件中。  这里定义的 UVC 常量会被传递给 `ioctl` 的参数，用于指定要执行的具体 USB 控制操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身 **不直接涉及 dynamic linker 的功能**。Dynamic linker (如 `linker64` 或 `linker`) 负责在程序运行时加载和链接动态共享对象 (`.so` 文件)。

然而，使用这个头文件的代码通常会编译成动态共享对象，例如 Camera HAL 的实现。

**SO 布局样本:**

假设一个 Camera HAL 的动态库名为 `android.hardware.camera.provider@2.4-impl.so`：

```
android.hardware.camera.provider@2.4-impl.so:
    DEBUG
    .gnu.hash
    .dynstr
    .dynsym
    .rel.dyn
    .rel.plt
    .init
    .plt
    .plt.got
    .text  <-- 包含使用 video.h 中定义的常量和结构体的代码
    .fini
    .rodata
    .data
    .bss
    __symbol_stub
```

* **`.text` 段:** 包含可执行的代码，这些代码可能会使用 `video.h` 中定义的常量和结构体来与 USB 摄像头驱动进行交互。
* **`.rodata` 段:** 包含只读数据，可能包含一些与 UVC 相关的字符串或其他常量。
* **`.dynstr` 和 `.dynsym` 段:** 包含动态链接所需的字符串表和符号表，记录了该 SO 导出的和依赖的符号。如果该 SO 中使用了与 UVC 相关的函数或数据结构（即使这些结构体本身是在内核头文件中定义的），相关的符号信息也会在这里。
* **`.rel.dyn` 和 `.rel.plt` 段:** 包含重定位信息，用于在加载时调整代码和数据中的地址，以确保正确链接到依赖的库。

**链接的处理过程:**

1. **编译时:**  当编译 `android.hardware.camera.provider@2.4-impl.so` 时，编译器会找到代码中包含的 `video.h` 头文件，并使用其中定义的常量和结构体。  如果代码中调用了需要链接到其他库的函数（例如，与 USB 子系统交互的函数），编译器会在生成的对象文件中记录这些依赖关系。
2. **链接时:** 链接器会将编译生成的对象文件链接成最终的 SO 文件。它会解析符号引用，并将代码和数据段组合在一起。
3. **运行时:** 当 Android 系统需要加载 Camera HAL 库时，dynamic linker 会执行以下步骤：
    * **加载 SO 文件:** 将 `android.hardware.camera.provider@2.4-impl.so` 加载到内存中。
    * **解析依赖:** 检查 SO 文件的动态链接信息，确定它依赖的其他共享库（例如，一些与 USB 或内核交互的库）。
    * **加载依赖库:**  加载所有依赖的共享库到内存中。
    * **重定位:** 根据 `.rel.dyn` 和 `.rel.plt` 段中的信息，调整 SO 文件及其依赖库中的地址，将符号引用解析到正确的内存地址。这包括解析对内核提供的符号的引用（尽管这些符号可能不是标准的共享库符号）。
    * **执行初始化代码:** 执行 SO 文件中的 `.init` 段中的代码，进行一些初始化操作。

**如果做了逻辑推理，请给出假设输入与输出:**

假设 Android 的 CameraService 需要获取连接的 USB 摄像头的曝光时间范围。

**假设输入:**

* 一个已连接的 USB 摄像头，其视频控制接口的地址已知。
* 需要获取曝光时间范围的控制单元 ID。

**逻辑推理过程:**

1. **查找控制单元信息:**  根据 UVC 规范，曝光时间控制属于 Camera Terminal 或 Processing Unit。需要根据设备的描述符信息确定具体的控制单元 ID。
2. **构造 USB 控制请求:**  使用 `video.h` 中定义的常量，构造一个 GET_MIN 请求，用于获取曝光时间的最小值。例如，使用 `UVC_GET_MIN` 常量作为请求类型，并指定 `UVC_CT_EXPOSURE_TIME_ABSOLUTE_CONTROL` 作为控制选择器。
3. **发送 USB 控制请求:**  通过 USB 驱动程序发送构造的控制请求到摄像头。
4. **接收 USB 控制响应:**  摄像头会返回一个包含曝光时间最小值的响应。响应数据的格式由 UVC 规范定义，可能是一个 `__le32` 类型的值。
5. **构造 USB 控制请求 (GET_MAX):** 类似地，构造一个 GET_MAX 请求，用于获取曝光时间的最大值。
6. **发送 USB 控制请求 (GET_MAX):** 发送该请求。
7. **接收 USB 控制响应 (GET_MAX):** 摄像头返回包含曝光时间最大值的响应。
8. **解析响应数据:**  将接收到的最小值和最大值从网络字节序转换为主机字节序。

**假设输出:**

假设摄像头支持的曝光时间范围是 1ms 到 100ms。接收到的响应数据可能包含以下字节（小端序）：

* **GET_MIN 响应:** `0x01 0x00 0x00 0x00` (对应 1ms)
* **GET_MAX 响应:** `0x64 0x00 0x00 0x00` (对应 100ms)

经过解析后，输出的曝光时间范围将是：最小值 1，最大值 100。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用错误的常量值:**  开发者可能错误地使用了 `video.h` 中定义的常量，导致发送了错误的 USB 控制请求。例如，将 `UVC_GET_CUR` 误用为 `UVC_SET_CUR`，或者使用了错误的控制选择器。
2. **结构体字段大小和字节序错误:**  在构造或解析 UVC 描述符时，开发者可能没有正确处理结构体字段的大小和字节序（小端序）。例如，直接将从 USB 设备读取的字节流强制转换为结构体，而没有考虑字节序转换。
3. **忽略描述符长度:**  UVC 描述符通常包含一个 `bLength` 字段，指示描述符的长度。开发者可能忽略这个字段，导致解析描述符时越界读取或处理不完整。
4. **没有正确处理控制请求的返回值:**  USB 控制请求可能会返回错误代码。开发者可能没有检查这些错误代码，导致程序在发生错误时继续执行，从而产生不可预测的行为。
5. **不理解 UVC 协议状态机:**  某些 UVC 操作需要按照特定的顺序进行。开发者可能不理解 UVC 协议的状态机，导致操作失败。例如，在没有发送 Probe 请求的情况下直接发送 Commit 请求。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `video.h` 的路径:**

1. **应用层 (Java/Kotlin):** Android 应用通过 `android.hardware.camera2` 等 Camera API 发起摄像头操作请求（如拍照、录像、设置参数）。
2. **Camera Service (Java/C++):** Framework 层的 `CameraService` 接收到应用请求，并负责协调底层的硬件访问。
3. **Camera HAL (C++):** `CameraService` 通过 HIDL (Hardware Interface Definition Language) 或 AIDL 与 Camera HAL 模块进行通信。Camera HAL 是一个动态库 (`.so` 文件)，负责与具体的摄像头硬件驱动进行交互。
4. **内核驱动 (C):** Camera HAL 调用底层的内核驱动程序来控制摄像头。对于 USB 摄像头，这通常是 UVC 驱动程序 (`uvcvideo`).
5. **USB 子系统 (内核):** UVC 驱动程序通过 Linux 内核的 USB 子系统与 USB 设备进行通信。
6. **`video.h`:**  在 Camera HAL 的实现中，以及在内核 UVC 驱动程序的实现中，都会包含 `bionic/libc/kernel/uapi/linux/usb/video.h` 头文件，以使用其中定义的常量和结构体来构造和解析 USB 控制请求和响应，以及处理视频数据流。

**NDK 到达 `video.h` 的路径:**

使用 NDK 开发的 Native 应用可以直接调用 Android 提供的 Native Camera API（如 ACamera2）。其路径与 Framework 类似，只是绕过了 Java Framework 的部分。

1. **应用层 (C/C++):** NDK 应用使用 ACamera2 API 发起摄像头操作。
2. **Camera Service (Java/C++):** 类似于 Framework 的路径，Native API 的调用最终也会到达 `CameraService`.
3. **Camera HAL (C++):**  后续路径与 Framework 相同。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 Camera HAL 中可能使用 `video.h` 中定义的常量进行 USB 控制传输的示例。  我们假设 Camera HAL 中有一个函数负责发送 USB 控制请求，其函数名可能包含 "control" 或 "transfer"。

```javascript
// 假设目标进程是 com.example.cameraapp
const targetProcess = "com.example.cameraapp";

// 连接到目标进程
Frida.attach(targetProcess, function(session) {
  console.log("[*] Attached, searching for camera HAL library...");

  // 搜索 Camera HAL 库的模块名，可能需要根据实际情况调整
  const cameraHalModule = Process.getModuleByName("android.hardware.camera.provider@2.4-impl.so");

  if (cameraHalModule) {
    console.log("[*] Found camera HAL module:", cameraHalModule.name);

    // 搜索可能发送 USB 控制请求的函数，这里使用模糊匹配，需要根据实际情况分析
    const sendControlFunctions = cameraHalModule.enumerateSymbols().filter(sym =>
      sym.name.toLowerCase().includes("control") && sym.name.toLowerCase().includes("transfer")
    );

    sendControlFunctions.forEach(function(func) {
      console.log("[*] Hooking function:", func.name, "at address:", func.address);

      Interceptor.attach(func.address, {
        onEnter: function(args) {
          console.log("\n[*] Called", func.name);
          console.log("[*] Arguments:", args);

          // 尝试解析可能包含 UVC 常量的参数
          // 这部分需要根据实际的函数签名来调整
          if (args.length > 0) {
            try {
              const controlType = args[0].toInt32(); // 假设第一个参数是控制类型
              console.log("[*] Potential Control Type:", controlType.toString(16));

              // 检查是否是 video.h 中定义的 UVC 常量
              // 这里可以添加更详细的检查
              if (controlType >= 0 && controlType <= 0xFFFF) {
                console.log("[*] Looks like a UVC control constant!");
              }
            } catch (e) {
              console.log("[*] Error parsing argument:", e);
            }
          }
        },
        onLeave: function(retval) {
          console.log("[*] Return value:", retval);
        }
      });
    });
  } else {
    console.log("[!] Camera HAL module not found.");
  }
});
```

**Frida Hook 说明:**

1. **连接到目标进程:**  使用 `Frida.attach()` 连接到运行 Camera 应用的进程。
2. **搜索 Camera HAL 模块:**  使用 `Process.getModuleByName()` 找到 Camera HAL 的动态库。你需要根据 Android 版本和设备型号调整模块名称。
3. **枚举符号并 Hook 函数:**  使用 `enumerateSymbols()` 遍历模块中的所有符号，并筛选出可能发送 USB 控制请求的函数。这里使用了模糊匹配，实际操作中可能需要更精确的函数名。
4. **拦截函数调用:**  使用 `Interceptor.attach()` 拦截目标函数的调用。
5. **打印参数和返回值:**  在 `onEnter` 和 `onLeave` 回调中，打印函数的参数和返回值，以便分析 USB 控制请求的内容。
6. **尝试解析 UVC 常量:**  在 `onEnter` 中，尝试将函数的参数解析为整数，并检查其是否落在 `video.h` 中定义的 UVC 常量的范围内。这需要根据目标函数的实际参数来调整解析方式。

**调试步骤:**

1. **找到 Camera HAL 库的路径和名称:**  可以通过 `adb shell` 和 `dumpsys media.camera` 等命令来获取 Camera HAL 库的信息。
2. **分析 Camera HAL 的代码 (如果可能):** 如果可以获取 Camera HAL 的源代码或反汇编代码，可以更准确地找到发送 USB 控制请求的函数和参数。
3. **调整 Frida Hook 脚本:**  根据实际情况调整 Frida Hook 脚本中的模块名、函数名和参数解析方式。
4. **运行 Frida 脚本:**  使用 Frida 命令行工具或图形界面运行 Hook 脚本。
5. **触发摄像头操作:**  在 Android 设备上运行目标 Camera 应用，并触发一些会发送 USB 控制请求的操作（例如，调整曝光、聚焦）。
6. **查看 Frida 输出:**  观察 Frida 的输出，查看拦截到的函数调用和参数，分析是否使用了 `video.h` 中定义的常量。

这个过程可能需要多次尝试和调整，因为不同的 Android 版本和设备可能使用不同的 Camera HAL 实现。 通过 Frida Hook，你可以动态地观察 Camera HAL 的行为，深入理解 Android Framework 如何一步步地与底层的 USB 视频设备进行交互。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/usb/video.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_USB_VIDEO_H
#define __LINUX_USB_VIDEO_H
#include <linux/types.h>
#define UVC_SC_UNDEFINED 0x00
#define UVC_SC_VIDEOCONTROL 0x01
#define UVC_SC_VIDEOSTREAMING 0x02
#define UVC_SC_VIDEO_INTERFACE_COLLECTION 0x03
#define UVC_PC_PROTOCOL_UNDEFINED 0x00
#define UVC_PC_PROTOCOL_15 0x01
#define UVC_VC_DESCRIPTOR_UNDEFINED 0x00
#define UVC_VC_HEADER 0x01
#define UVC_VC_INPUT_TERMINAL 0x02
#define UVC_VC_OUTPUT_TERMINAL 0x03
#define UVC_VC_SELECTOR_UNIT 0x04
#define UVC_VC_PROCESSING_UNIT 0x05
#define UVC_VC_EXTENSION_UNIT 0x06
#define UVC_VS_UNDEFINED 0x00
#define UVC_VS_INPUT_HEADER 0x01
#define UVC_VS_OUTPUT_HEADER 0x02
#define UVC_VS_STILL_IMAGE_FRAME 0x03
#define UVC_VS_FORMAT_UNCOMPRESSED 0x04
#define UVC_VS_FRAME_UNCOMPRESSED 0x05
#define UVC_VS_FORMAT_MJPEG 0x06
#define UVC_VS_FRAME_MJPEG 0x07
#define UVC_VS_FORMAT_MPEG2TS 0x0a
#define UVC_VS_FORMAT_DV 0x0c
#define UVC_VS_COLORFORMAT 0x0d
#define UVC_VS_FORMAT_FRAME_BASED 0x10
#define UVC_VS_FRAME_FRAME_BASED 0x11
#define UVC_VS_FORMAT_STREAM_BASED 0x12
#define UVC_EP_UNDEFINED 0x00
#define UVC_EP_GENERAL 0x01
#define UVC_EP_ENDPOINT 0x02
#define UVC_EP_INTERRUPT 0x03
#define UVC_RC_UNDEFINED 0x00
#define UVC_SET_CUR 0x01
#define UVC_GET_CUR 0x81
#define UVC_GET_MIN 0x82
#define UVC_GET_MAX 0x83
#define UVC_GET_RES 0x84
#define UVC_GET_LEN 0x85
#define UVC_GET_INFO 0x86
#define UVC_GET_DEF 0x87
#define UVC_VC_CONTROL_UNDEFINED 0x00
#define UVC_VC_VIDEO_POWER_MODE_CONTROL 0x01
#define UVC_VC_REQUEST_ERROR_CODE_CONTROL 0x02
#define UVC_TE_CONTROL_UNDEFINED 0x00
#define UVC_SU_CONTROL_UNDEFINED 0x00
#define UVC_SU_INPUT_SELECT_CONTROL 0x01
#define UVC_CT_CONTROL_UNDEFINED 0x00
#define UVC_CT_SCANNING_MODE_CONTROL 0x01
#define UVC_CT_AE_MODE_CONTROL 0x02
#define UVC_CT_AE_PRIORITY_CONTROL 0x03
#define UVC_CT_EXPOSURE_TIME_ABSOLUTE_CONTROL 0x04
#define UVC_CT_EXPOSURE_TIME_RELATIVE_CONTROL 0x05
#define UVC_CT_FOCUS_ABSOLUTE_CONTROL 0x06
#define UVC_CT_FOCUS_RELATIVE_CONTROL 0x07
#define UVC_CT_FOCUS_AUTO_CONTROL 0x08
#define UVC_CT_IRIS_ABSOLUTE_CONTROL 0x09
#define UVC_CT_IRIS_RELATIVE_CONTROL 0x0a
#define UVC_CT_ZOOM_ABSOLUTE_CONTROL 0x0b
#define UVC_CT_ZOOM_RELATIVE_CONTROL 0x0c
#define UVC_CT_PANTILT_ABSOLUTE_CONTROL 0x0d
#define UVC_CT_PANTILT_RELATIVE_CONTROL 0x0e
#define UVC_CT_ROLL_ABSOLUTE_CONTROL 0x0f
#define UVC_CT_ROLL_RELATIVE_CONTROL 0x10
#define UVC_CT_PRIVACY_CONTROL 0x11
#define UVC_PU_CONTROL_UNDEFINED 0x00
#define UVC_PU_BACKLIGHT_COMPENSATION_CONTROL 0x01
#define UVC_PU_BRIGHTNESS_CONTROL 0x02
#define UVC_PU_CONTRAST_CONTROL 0x03
#define UVC_PU_GAIN_CONTROL 0x04
#define UVC_PU_POWER_LINE_FREQUENCY_CONTROL 0x05
#define UVC_PU_HUE_CONTROL 0x06
#define UVC_PU_SATURATION_CONTROL 0x07
#define UVC_PU_SHARPNESS_CONTROL 0x08
#define UVC_PU_GAMMA_CONTROL 0x09
#define UVC_PU_WHITE_BALANCE_TEMPERATURE_CONTROL 0x0a
#define UVC_PU_WHITE_BALANCE_TEMPERATURE_AUTO_CONTROL 0x0b
#define UVC_PU_WHITE_BALANCE_COMPONENT_CONTROL 0x0c
#define UVC_PU_WHITE_BALANCE_COMPONENT_AUTO_CONTROL 0x0d
#define UVC_PU_DIGITAL_MULTIPLIER_CONTROL 0x0e
#define UVC_PU_DIGITAL_MULTIPLIER_LIMIT_CONTROL 0x0f
#define UVC_PU_HUE_AUTO_CONTROL 0x10
#define UVC_PU_ANALOG_VIDEO_STANDARD_CONTROL 0x11
#define UVC_PU_ANALOG_LOCK_STATUS_CONTROL 0x12
#define UVC_VS_CONTROL_UNDEFINED 0x00
#define UVC_VS_PROBE_CONTROL 0x01
#define UVC_VS_COMMIT_CONTROL 0x02
#define UVC_VS_STILL_PROBE_CONTROL 0x03
#define UVC_VS_STILL_COMMIT_CONTROL 0x04
#define UVC_VS_STILL_IMAGE_TRIGGER_CONTROL 0x05
#define UVC_VS_STREAM_ERROR_CODE_CONTROL 0x06
#define UVC_VS_GENERATE_KEY_FRAME_CONTROL 0x07
#define UVC_VS_UPDATE_FRAME_SEGMENT_CONTROL 0x08
#define UVC_VS_SYNC_DELAY_CONTROL 0x09
#define UVC_TT_VENDOR_SPECIFIC 0x0100
#define UVC_TT_STREAMING 0x0101
#define UVC_ITT_VENDOR_SPECIFIC 0x0200
#define UVC_ITT_CAMERA 0x0201
#define UVC_ITT_MEDIA_TRANSPORT_INPUT 0x0202
#define UVC_OTT_VENDOR_SPECIFIC 0x0300
#define UVC_OTT_DISPLAY 0x0301
#define UVC_OTT_MEDIA_TRANSPORT_OUTPUT 0x0302
#define UVC_EXTERNAL_VENDOR_SPECIFIC 0x0400
#define UVC_COMPOSITE_CONNECTOR 0x0401
#define UVC_SVIDEO_CONNECTOR 0x0402
#define UVC_COMPONENT_CONNECTOR 0x0403
#define UVC_STATUS_TYPE_CONTROL 1
#define UVC_STATUS_TYPE_STREAMING 2
#define UVC_STREAM_EOH (1 << 7)
#define UVC_STREAM_ERR (1 << 6)
#define UVC_STREAM_STI (1 << 5)
#define UVC_STREAM_RES (1 << 4)
#define UVC_STREAM_SCR (1 << 3)
#define UVC_STREAM_PTS (1 << 2)
#define UVC_STREAM_EOF (1 << 1)
#define UVC_STREAM_FID (1 << 0)
#define UVC_CONTROL_CAP_GET (1 << 0)
#define UVC_CONTROL_CAP_SET (1 << 1)
#define UVC_CONTROL_CAP_DISABLED (1 << 2)
#define UVC_CONTROL_CAP_AUTOUPDATE (1 << 3)
#define UVC_CONTROL_CAP_ASYNCHRONOUS (1 << 4)
enum uvc_color_primaries_values {
  UVC_COLOR_PRIMARIES_UNSPECIFIED,
  UVC_COLOR_PRIMARIES_BT_709_SRGB,
  UVC_COLOR_PRIMARIES_BT_470_2_M,
  UVC_COLOR_PRIMARIES_BT_470_2_B_G,
  UVC_COLOR_PRIMARIES_SMPTE_170M,
  UVC_COLOR_PRIMARIES_SMPTE_240M,
};
enum uvc_transfer_characteristics_values {
  UVC_TRANSFER_CHARACTERISTICS_UNSPECIFIED,
  UVC_TRANSFER_CHARACTERISTICS_BT_709,
  UVC_TRANSFER_CHARACTERISTICS_BT_470_2_M,
  UVC_TRANSFER_CHARACTERISTICS_BT_470_2_B_G,
  UVC_TRANSFER_CHARACTERISTICS_SMPTE_170M,
  UVC_TRANSFER_CHARACTERISTICS_SMPTE_240M,
  UVC_TRANSFER_CHARACTERISTICS_LINEAR,
  UVC_TRANSFER_CHARACTERISTICS_SRGB,
};
enum uvc_matrix_coefficients {
  UVC_MATRIX_COEFFICIENTS_UNSPECIFIED,
  UVC_MATRIX_COEFFICIENTS_BT_709,
  UVC_MATRIX_COEFFICIENTS_FCC,
  UVC_MATRIX_COEFFICIENTS_BT_470_2_B_G,
  UVC_MATRIX_COEFFICIENTS_SMPTE_170M,
  UVC_MATRIX_COEFFICIENTS_SMPTE_240M,
};
struct uvc_descriptor_header {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
} __attribute__((packed));
struct uvc_header_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __le16 bcdUVC;
  __le16 wTotalLength;
  __le32 dwClockFrequency;
  __u8 bInCollection;
  __u8 baInterfaceNr[];
} __attribute__((__packed__));
#define UVC_DT_HEADER_SIZE(n) (12 + (n))
#define UVC_HEADER_DESCRIPTOR(n) uvc_header_descriptor_ ##n
#define DECLARE_UVC_HEADER_DESCRIPTOR(n) struct UVC_HEADER_DESCRIPTOR(n) { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubType; __le16 bcdUVC; __le16 wTotalLength; __le32 dwClockFrequency; __u8 bInCollection; __u8 baInterfaceNr[n]; \
} __attribute__((packed))
struct uvc_input_terminal_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bTerminalID;
  __le16 wTerminalType;
  __u8 bAssocTerminal;
  __u8 iTerminal;
} __attribute__((__packed__));
#define UVC_DT_INPUT_TERMINAL_SIZE 8
struct uvc_output_terminal_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bTerminalID;
  __le16 wTerminalType;
  __u8 bAssocTerminal;
  __u8 bSourceID;
  __u8 iTerminal;
} __attribute__((__packed__));
#define UVC_DT_OUTPUT_TERMINAL_SIZE 9
struct uvc_camera_terminal_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bTerminalID;
  __le16 wTerminalType;
  __u8 bAssocTerminal;
  __u8 iTerminal;
  __le16 wObjectiveFocalLengthMin;
  __le16 wObjectiveFocalLengthMax;
  __le16 wOcularFocalLength;
  __u8 bControlSize;
  __u8 bmControls[3];
} __attribute__((__packed__));
#define UVC_DT_CAMERA_TERMINAL_SIZE(n) (15 + (n))
struct uvc_selector_unit_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bUnitID;
  __u8 bNrInPins;
  __u8 baSourceID[0];
  __u8 iSelector;
} __attribute__((__packed__));
#define UVC_DT_SELECTOR_UNIT_SIZE(n) (6 + (n))
#define UVC_SELECTOR_UNIT_DESCRIPTOR(n) uvc_selector_unit_descriptor_ ##n
#define DECLARE_UVC_SELECTOR_UNIT_DESCRIPTOR(n) struct UVC_SELECTOR_UNIT_DESCRIPTOR(n) { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubType; __u8 bUnitID; __u8 bNrInPins; __u8 baSourceID[n]; __u8 iSelector; \
} __attribute__((packed))
struct uvc_processing_unit_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bUnitID;
  __u8 bSourceID;
  __le16 wMaxMultiplier;
  __u8 bControlSize;
  __u8 bmControls[2];
  __u8 iProcessing;
  __u8 bmVideoStandards;
} __attribute__((__packed__));
#define UVC_DT_PROCESSING_UNIT_SIZE(n) (10 + (n))
struct uvc_extension_unit_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bUnitID;
  __u8 guidExtensionCode[16];
  __u8 bNumControls;
  __u8 bNrInPins;
  __u8 baSourceID[0];
  __u8 bControlSize;
  __u8 bmControls[0];
  __u8 iExtension;
} __attribute__((__packed__));
#define UVC_DT_EXTENSION_UNIT_SIZE(p,n) (24 + (p) + (n))
#define UVC_EXTENSION_UNIT_DESCRIPTOR(p,n) uvc_extension_unit_descriptor_ ##p_ ##n
#define DECLARE_UVC_EXTENSION_UNIT_DESCRIPTOR(p,n) struct UVC_EXTENSION_UNIT_DESCRIPTOR(p, n) { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubType; __u8 bUnitID; __u8 guidExtensionCode[16]; __u8 bNumControls; __u8 bNrInPins; __u8 baSourceID[p]; __u8 bControlSize; __u8 bmControls[n]; __u8 iExtension; \
} __attribute__((packed))
struct uvc_control_endpoint_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __le16 wMaxTransferSize;
} __attribute__((__packed__));
#define UVC_DT_CONTROL_ENDPOINT_SIZE 5
struct uvc_input_header_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bNumFormats;
  __le16 wTotalLength;
  __u8 bEndpointAddress;
  __u8 bmInfo;
  __u8 bTerminalLink;
  __u8 bStillCaptureMethod;
  __u8 bTriggerSupport;
  __u8 bTriggerUsage;
  __u8 bControlSize;
  __u8 bmaControls[];
} __attribute__((__packed__));
#define UVC_DT_INPUT_HEADER_SIZE(n,p) (13 + (n * p))
#define UVC_INPUT_HEADER_DESCRIPTOR(n,p) uvc_input_header_descriptor_ ##n_ ##p
#define DECLARE_UVC_INPUT_HEADER_DESCRIPTOR(n,p) struct UVC_INPUT_HEADER_DESCRIPTOR(n, p) { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubType; __u8 bNumFormats; __le16 wTotalLength; __u8 bEndpointAddress; __u8 bmInfo; __u8 bTerminalLink; __u8 bStillCaptureMethod; __u8 bTriggerSupport; __u8 bTriggerUsage; __u8 bControlSize; __u8 bmaControls[p][n]; \
} __attribute__((packed))
struct uvc_output_header_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bNumFormats;
  __le16 wTotalLength;
  __u8 bEndpointAddress;
  __u8 bTerminalLink;
  __u8 bControlSize;
  __u8 bmaControls[];
} __attribute__((__packed__));
#define UVC_DT_OUTPUT_HEADER_SIZE(n,p) (9 + (n * p))
#define UVC_OUTPUT_HEADER_DESCRIPTOR(n,p) uvc_output_header_descriptor_ ##n_ ##p
#define DECLARE_UVC_OUTPUT_HEADER_DESCRIPTOR(n,p) struct UVC_OUTPUT_HEADER_DESCRIPTOR(n, p) { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubType; __u8 bNumFormats; __le16 wTotalLength; __u8 bEndpointAddress; __u8 bTerminalLink; __u8 bControlSize; __u8 bmaControls[p][n]; \
} __attribute__((packed))
struct uvc_color_matching_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bColorPrimaries;
  __u8 bTransferCharacteristics;
  __u8 bMatrixCoefficients;
} __attribute__((__packed__));
#define UVC_DT_COLOR_MATCHING_SIZE 6
struct uvc_streaming_control {
  __u16 bmHint;
  __u8 bFormatIndex;
  __u8 bFrameIndex;
  __u32 dwFrameInterval;
  __u16 wKeyFrameRate;
  __u16 wPFrameRate;
  __u16 wCompQuality;
  __u16 wCompWindowSize;
  __u16 wDelay;
  __u32 dwMaxVideoFrameSize;
  __u32 dwMaxPayloadTransferSize;
  __u32 dwClockFrequency;
  __u8 bmFramingInfo;
  __u8 bPreferedVersion;
  __u8 bMinVersion;
  __u8 bMaxVersion;
} __attribute__((__packed__));
struct uvc_format_uncompressed {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bFormatIndex;
  __u8 bNumFrameDescriptors;
  __u8 guidFormat[16];
  __u8 bBitsPerPixel;
  __u8 bDefaultFrameIndex;
  __u8 bAspectRatioX;
  __u8 bAspectRatioY;
  __u8 bmInterlaceFlags;
  __u8 bCopyProtect;
} __attribute__((__packed__));
#define UVC_DT_FORMAT_UNCOMPRESSED_SIZE 27
struct uvc_frame_uncompressed {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bFrameIndex;
  __u8 bmCapabilities;
  __le16 wWidth;
  __le16 wHeight;
  __le32 dwMinBitRate;
  __le32 dwMaxBitRate;
  __le32 dwMaxVideoFrameBufferSize;
  __le32 dwDefaultFrameInterval;
  __u8 bFrameIntervalType;
  __le32 dwFrameInterval[];
} __attribute__((__packed__));
#define UVC_DT_FRAME_UNCOMPRESSED_SIZE(n) (26 + 4 * (n))
#define UVC_FRAME_UNCOMPRESSED(n) uvc_frame_uncompressed_ ##n
#define DECLARE_UVC_FRAME_UNCOMPRESSED(n) struct UVC_FRAME_UNCOMPRESSED(n) { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubType; __u8 bFrameIndex; __u8 bmCapabilities; __le16 wWidth; __le16 wHeight; __le32 dwMinBitRate; __le32 dwMaxBitRate; __le32 dwMaxVideoFrameBufferSize; __le32 dwDefaultFrameInterval; __u8 bFrameIntervalType; __le32 dwFrameInterval[n]; \
} __attribute__((packed))
struct uvc_format_mjpeg {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bFormatIndex;
  __u8 bNumFrameDescriptors;
  __u8 bmFlags;
  __u8 bDefaultFrameIndex;
  __u8 bAspectRatioX;
  __u8 bAspectRatioY;
  __u8 bmInterlaceFlags;
  __u8 bCopyProtect;
} __attribute__((__packed__));
#define UVC_DT_FORMAT_MJPEG_SIZE 11
struct uvc_frame_mjpeg {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubType;
  __u8 bFrameIndex;
  __u8 bmCapabilities;
  __le16 wWidth;
  __le16 wHeight;
  __le32 dwMinBitRate;
  __le32 dwMaxBitRate;
  __le32 dwMaxVideoFrameBufferSize;
  __le32 dwDefaultFrameInterval;
  __u8 bFrameIntervalType;
  __le32 dwFrameInterval[];
} __attribute__((__packed__));
#define UVC_DT_FRAME_MJPEG_SIZE(n) (26 + 4 * (n))
#define UVC_FRAME_MJPEG(n) uvc_frame_mjpeg_ ##n
#define DECLARE_UVC_FRAME_MJPEG(n) struct UVC_FRAME_MJPEG(n) { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubType; __u8 bFrameIndex; __u8 bmCapabilities; __le16 wWidth; __le16 wHeight; __le32 dwMinBitRate; __le32 dwMaxBitRate; __le32 dwMaxVideoFrameBufferSize; __le32 dwDefaultFrameInterval; __u8 bFrameIntervalType; __le32 dwFrameInterval[n]; \
} __attribute__((packed))
#endif
```