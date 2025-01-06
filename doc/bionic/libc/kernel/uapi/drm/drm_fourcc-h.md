Response:
Let's break down the thought process for analyzing the `drm_fourcc.handroid` file.

1. **Understanding the Context:** The first step is to understand the provided information:
    * **File Location:** `bionic/libc/kernel/uapi/drm/drm_fourcc.handroid`. This tells us it's part of Android's C library (`bionic`), specifically the kernel user-space API (`uapi`) related to Direct Rendering Manager (`drm`). The `.handroid` suffix is a bionic-specific way of marking headers copied from the kernel.
    * **Purpose:** The comment at the top clearly states it's auto-generated and defines DRM pixel formats (FourCC codes).
    * **Dependencies:** It includes `drm.h`, indicating a relationship with other DRM structures and definitions.

2. **Identifying Core Functionality:**  The core functionality revolves around defining constants related to pixel formats. The key elements to focus on are:
    * **`fourcc_code` macro:** This is the fundamental building block for creating FourCC codes.
    * **`DRM_FORMAT_*` macros:** These define specific pixel formats using the `fourcc_code` macro.
    * **`DRM_FORMAT_MOD_*` macros:** These define format modifiers for things like tiling and compression.
    * **Vendor-specific modifiers:** Sections dedicated to Intel, Samsung, Qualcomm, etc., showing how different hardware vendors have their own extensions.

3. **Relating to Android Functionality:**  The next step is to connect these definitions to how they are used in Android. Key areas to consider:
    * **Graphics Subsystem:**  DRM is the core of the Android graphics stack. SurfaceFlinger, the compositor, uses DRM. Media codecs, camera HALs, and display drivers also interact with DRM.
    * **Hardware Abstraction Layer (HAL):**  The HAL is the bridge between the Android framework and hardware-specific implementations.
    * **NDK:**  Developers can directly access some lower-level graphics functionalities using the NDK.

4. **Analyzing `libc` Functions:** The file itself *doesn't define any `libc` functions*. It defines *macros*. This is a crucial distinction. The `fourcc_code` macro is a simple bitwise operation and doesn't involve complex `libc` functions.

5. **Addressing Dynamic Linker:**  Similarly, this file itself *doesn't directly involve the dynamic linker*. It's a header file containing macro definitions. However, the *usage* of these definitions within Android's graphics libraries (which are dynamically linked) *does* involve the linker. This is where the explanation about libraries like `libsurfaceflinger.so` comes in.

6. **Logical Deduction and Examples:**  To illustrate the concepts, provide simple examples:
    * **Input/Output for `fourcc_code`:**  Show how the macro takes character inputs and produces a 32-bit integer.
    * **Common Usage Errors:** Explain mistakes developers might make, like using an incorrect FourCC code or misunderstanding format modifiers.

7. **Tracing the Path from Framework/NDK:** This is a multi-step process. Start from the high-level framework components and work downwards:
    * **Framework:**  `Surface`, `SurfaceView`, MediaCodec, Camera API.
    * **Binder calls:** The communication mechanism between framework and native layers.
    * **Native Services:** `SurfaceFlinger`, media services, camera services.
    * **HAL:**  Implementation-specific libraries that interact with the kernel DRM drivers.
    * **Kernel DRM:** Where these `drm_fourcc.h` definitions are ultimately used.

8. **Frida Hook Example:**  Demonstrate how to use Frida to intercept calls and examine the FourCC values being used. The key is to hook functions in the native graphics stack (e.g., within `libsurfaceflinger.so`) that deal with buffer allocation or format negotiation.

9. **Structuring the Response:** Organize the information logically with clear headings and subheadings. Use bullet points and code blocks for readability.

10. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Are there any ambiguities?  Can anything be explained more simply?  For example, initially, I might have incorrectly focused on `libc` functions *within* the file. The key is to realize it's a header, so the focus shifts to how those definitions are used *by* `libc` and other Android components.

**Self-Correction Example during the process:**

* **Initial Thought:** "This file defines `libc` functions for handling DRM formats."
* **Correction:** "Wait, this is a header file (`.h`). It defines *macros* and constants. The `libc` functions will *use* these definitions, but they aren't defined here."
* **Refinement:** "I need to focus on how these macros are used in the context of Android's graphics system and how the dynamic linker plays a role in loading the libraries that use them."

By following these steps and engaging in self-correction, a comprehensive and accurate analysis of the `drm_fourcc.handroid` file can be produced.
好的，我们来详细分析一下 `bionic/libc/kernel/uapi/drm/drm_fourcc.handroid` 这个文件。

**功能列举:**

这个头文件 (`drm_fourcc.h`) 的主要功能是定义了 **DRM (Direct Rendering Manager) 中使用的像素格式代码 (FourCC codes)** 和 **格式修饰符 (Format Modifiers)**。

* **定义 FourCC 代码:** 它使用 `fourcc_code` 宏定义了大量的常量，每个常量代表一种特定的像素数据排列方式。例如，`DRM_FORMAT_RGB888` 代表 24 位的 RGB 格式，每个颜色分量占用 8 位。
* **定义格式修饰符:** 除了基本的像素格式，它还定义了格式修饰符，用于描述像素数据的内存布局，例如是否是平铺的 (tiled)、压缩的 (compressed) 等。这些修饰符允许驱动程序和用户空间应用程序更精细地控制内存分配和访问。
* **定义供应商特定的修饰符:**  该文件还包含特定硬件供应商 (如 Intel, AMD, NVIDIA, Qualcomm 等) 的格式修饰符，允许他们为自己的硬件定义优化的内存布局。

**与 Android 功能的关系及举例:**

这个文件在 Android 的图形显示系统中扮演着至关重要的角色。Android 的 SurfaceFlinger (负责屏幕合成) 和 Gralloc (图形内存分配器) 等组件都依赖于这些 FourCC 代码和格式修饰符。

**举例说明:**

1. **SurfaceFlinger 和 BufferQueue:** 当一个应用程序想要在屏幕上显示内容时，它会将图像数据放入一个 BufferQueue 中。SurfaceFlinger 从 BufferQueue 中取出这些数据进行合成。在分配图像缓冲区时，会使用这里定义的 FourCC 代码来指定缓冲区的像素格式。例如，如果一个应用程序使用 `AHardwareBuffer` 并指定了 `AHARDWAREBUFFER_FORMAT_R8G8B8X8_UNORM`，那么底层 Gralloc 实现可能会使用 `DRM_FORMAT_XRGB8888` 这个 FourCC 代码来分配 DMA-BUF。

2. **MediaCodec 和视频解码:** 视频解码器在输出解码后的帧时，也需要告知系统帧的像素格式。例如，一个 H.264 解码器可能会输出 NV12 格式的帧，这对应于 `DRM_FORMAT_NV12`。

3. **Camera HAL 和图像捕获:**  相机硬件抽象层 (HAL) 在捕获图像数据时，需要指定输出图像的格式。例如，一个相机传感器可能输出 RAW16 格式的数据，或者经过 ISP 处理后输出 NV21 格式的数据，这些都对应着这里定义的 FourCC 代码。

**详细解释 `libc` 函数的功能是如何实现的:**

这个头文件本身 **没有定义任何 `libc` 函数**。它定义的是宏常量。`libc` 中的函数，例如与内存分配相关的函数 (如 `malloc`, `free`)，以及与文件操作相关的函数 (如 `open`, `close`, `ioctl`) 等，可能会在图形显示系统的实现中使用，但这些函数的功能实现位于 `libc` 的其他源文件中。

`fourcc_code` 宏本身是一个简单的内联操作，它将四个字符组合成一个 32 位的整数，代表 FourCC 代码。它的实现非常直接：

```c
#define fourcc_code(a,b,c,d) ((__u32) (a) | ((__u32) (b) << 8) | ((__u32) (c) << 16) | ((__u32) (d) << 24))
```

它通过位移操作将四个 8 位的字符放置到 32 位整数的不同字节位置。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker 的功能。然而，使用这些 FourCC 代码和格式修饰符的图形库，例如 `libsurfaceflinger.so`、`libhwui.so`、以及各个硬件厂商提供的 Gralloc HAL 实现 `.so` 文件，都是动态链接库。

**so 布局样本 (以 `libsurfaceflinger.so` 为例):**

```
libsurfaceflinger.so:
    .text          # 代码段，包含 SurfaceFlinger 的逻辑
    .rodata        # 只读数据段，可能包含字符串常量等
    .data          # 可读写数据段，包含全局变量等
    .bss           # 未初始化数据段
    .dynamic       # 动态链接信息，包括依赖的库、符号表等
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .plt           # 程序链接表 (Procedure Linkage Table)
    .got           # 全局偏移表 (Global Offset Table)
    ...           # 其他段
```

**链接的处理过程:**

1. **编译时链接:** 当编译 `libsurfaceflinger.so` 的源代码时，编译器会记录下它所引用的外部符号 (例如，来自 `libbinder.so` 或其他库的函数)。这些符号在编译时可能还未解析。

2. **加载时链接 (Dynamic Linking):** 当 Android 系统启动或需要使用 `libsurfaceflinger.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责将该库加载到内存中，并解析它所依赖的外部符号。

3. **符号查找:** Dynamic linker 会查找 `libsurfaceflinger.so` 的 `.dynamic` 段中的信息，找到它所依赖的其他 `.so` 文件。

4. **加载依赖库:**  Dynamic linker 会依次加载 `libsurfaceflinger.so` 依赖的库，例如 `libbinder.so`。

5. **重定位:**  Dynamic linker 会修改 `libsurfaceflinger.so` 的 `.got` (Global Offset Table) 和 `.plt` (Procedure Linkage Table)，将外部符号的地址指向它们在内存中的实际位置。例如，如果 `libsurfaceflinger.so` 调用了 `libbinder.so` 中的 `binder_open` 函数，dynamic linker 会将 `binder_open` 的地址填入 `libsurfaceflinger.so` 的 GOT 表项中。

6. **执行:** 一旦所有依赖关系都被解析，`libsurfaceflinger.so` 就可以被安全地执行了。

在这个过程中，`drm_fourcc.h` 定义的宏常量被编译到使用它们的库的 `.rodata` 或 `.text` 段中。Dynamic linker 本身不直接处理这些常量，但它确保了使用这些常量的库能够正确加载和执行。

**如果做了逻辑推理，请给出假设输入与输出:**

`fourcc_code` 宏的逻辑推理非常简单。

**假设输入:**

* `a` = 'R' (ASCII 0x52)
* `b` = 'G' (ASCII 0x47)
* `c` = 'B' (ASCII 0x42)
* `d` = 'A' (ASCII 0x41)

**输出:**

`fourcc_code('R', 'G', 'B', 'A')` 将会计算为:

```
0x52 | (0x47 << 8) | (0x42 << 16) | (0x41 << 24)
= 0x52 | 0x4700 | 0x420000 | 0x41000000
= 0x41424752
```

因此，`DRM_FORMAT_RGBA8888` 的值就是 `0x41424752`。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用错误的 FourCC 代码:**  开发者可能会错误地使用一个 FourCC 代码，导致应用程序请求的缓冲区格式与硬件或驱动程序支持的格式不匹配。这可能导致程序崩溃、显示错误或性能下降。例如，在需要 RGB 格式时错误地使用了 BGR 格式。

2. **不理解格式修饰符:**  对于高级用例，开发者可能需要理解和使用格式修饰符。如果错误地使用了格式修饰符，例如在非平铺的缓冲区上使用了平铺的访问方式，会导致内存访问错误。

3. **假设平台的默认格式:**  开发者不应该假设所有 Android 设备都支持相同的默认像素格式。不同的设备可能支持不同的格式集。应该根据实际需求和设备能力来选择合适的 FourCC 代码。

4. **在不支持的 API 版本中使用新的 FourCC 代码:**  一些较新的 FourCC 代码可能只在较新的 Android 版本或特定的硬件平台上支持。在旧版本或不支持的平台上使用这些代码可能会导致错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `drm_fourcc.h` 的步骤:**

1. **应用程序请求显示:** 一个 Android 应用程序 (使用 Java/Kotlin) 通过 `SurfaceView` 或 `TextureView` 请求在屏幕上显示内容。

2. **Surface 创建:** Framework 创建一个 `Surface` 对象，该对象通过 Binder IPC 与 SurfaceFlinger 通信。

3. **BufferQueue 分配:**  应用程序通过 `Surface` 的 API (例如 `lockCanvas`, `dequeueBuffer`) 请求一个图形缓冲区。在 native 层，这涉及到 `ANativeWindow` 和 `BufferQueue` 的操作。

4. **Gralloc HAL 调用:** `BufferQueue` 会调用 Gralloc HAL (通常是硬件厂商提供的 `.so` 库) 来分配实际的图形缓冲区。Gralloc HAL 需要决定缓冲区的格式和内存布局。

5. **DRM 交互:** Gralloc HAL 可能会使用 DRM API (通过 `libdrm.so`) 与内核 DRM 驱动程序交互。在分配 DMA-BUF 时，Gralloc HAL 会使用 `drm_fourcc.h` 中定义的 FourCC 代码来指定缓冲区的像素格式。

6. **内核 DRM 驱动:** 内核 DRM 驱动程序根据 Gralloc HAL 提供的 FourCC 代码和格式修饰符，分配物理内存并设置相关的硬件参数。

**NDK 到达 `drm_fourcc.h` 的步骤:**

1. **NDK 应用程序使用 AHardwareBuffer:**  一个使用 NDK 开发的应用程序可以直接使用 `AHardwareBuffer` API 来分配图形缓冲区。

2. **指定 BufferFormat:**  应用程序在创建 `AHardwareBuffer` 时，需要指定缓冲区的格式，例如 `AHARDWAREBUFFER_FORMAT_R8G8B8X8_UNORM`。

3. **AHardwareBuffer_allocate 调用:**  NDK 调用 `AHardwareBuffer_allocate` 函数。

4. **底层 Gralloc 实现:**  `AHardwareBuffer_allocate` 的实现最终会调用 Gralloc HAL 来分配缓冲区。

5. **DRM 交互:** 类似于 Framework 的情况，Gralloc HAL 可能会使用 `drm_fourcc.h` 中定义的 FourCC 代码与内核 DRM 驱动交互。

**Frida Hook 示例:**

我们可以使用 Frida Hook Gralloc HAL 中分配缓冲区的函数，来查看实际使用的 FourCC 代码。以下是一个示例，假设我们要 Hook 的函数是 `alloc`，它接受一个描述缓冲区属性的结构体作为参数：

```python
import frida
import sys

package_name = "your.target.app"  # 替换为你的应用程序包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Please launch the app.")
    sys.exit(1)

script_source = """
Interceptor.attach(Module.findExportByName("libgralloc.so", "_ZN7androidw08Gralloc4devElockElockEjPKNS0_13native_handle_tEPv"), {
    onEnter: function(args) {
        console.log("[*] Gralloc::alloc called");
        // 假设缓冲区的属性结构体是 args[0]
        // 你需要根据实际的结构体定义来解析 FourCC 代码
        // 这里只是一个示例，假设 format 字段在偏移 0x4 处
        var format = Memory.readU32(args[0].add(0x4));
        console.log("[*] Requested Format (FourCC): 0x" + format.toString(16));

        // 你可以尝试解析 FourCC 代码中的字符
        var a = String.fromCharCode(format & 0xFF);
        var b = String.fromCharCode((format >> 8) & 0xFF);
        var c = String.fromCharCode((format >> 16) & 0xFF);
        var d = String.fromCharCode((format >> 24) & 0xFF);
        console.log("[*] FourCC Chars: '" + a + b + c + d + "'");
    }
});
"""

script = session.create_script(script_source)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用说明:**

1. **替换 `package_name`:** 将 `your.target.app` 替换为你要调试的应用程序的包名。
2. **查找 Gralloc 库:** 不同的 Android 版本和设备可能使用不同的 Gralloc HAL 库。你可能需要根据你的目标设备修改 `Module.findExportByName` 中的库名 (例如 `android.hardware.graphics.allocator@4.0-service.so` 等)。
3. **确定 Hook 的函数:**  `_ZN7androidw08Gralloc4devElockElockEjPKNS0_13native_handle_tEPv`  只是一个示例函数签名，你需要根据你的 Gralloc HAL 实现找到实际负责分配缓冲区的函数。可以使用 `adb shell dumpsys SurfaceFlinger` 或查看 Gralloc HAL 的源代码来确定。
4. **解析缓冲区属性结构体:**  示例代码假设缓冲区属性结构体的 `format` 字段位于偏移 `0x4` 处。你需要根据实际的结构体定义来解析 FourCC 代码。可以使用 IDA Pro 或 Ghidra 等工具来分析 Gralloc HAL 库的结构体定义。

通过这个 Frida 脚本，当目标应用程序分配图形缓冲区时，你可以在控制台上看到 Gralloc HAL 中 `alloc` 函数被调用，并打印出请求的像素格式 (FourCC 代码)。这将帮助你理解 Android Framework 或 NDK 如何一步步地使用到 `drm_fourcc.h` 中定义的常量。

总结来说，`drm_fourcc.handroid` 定义了 DRM 中使用的像素格式代码和格式修饰符，是 Android 图形显示系统的基础。理解这个文件对于深入了解 Android 图形栈的工作原理至关重要。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/drm/drm_fourcc.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef DRM_FOURCC_H
#define DRM_FOURCC_H
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#define fourcc_code(a,b,c,d) ((__u32) (a) | ((__u32) (b) << 8) | ((__u32) (c) << 16) | ((__u32) (d) << 24))
#define DRM_FORMAT_BIG_ENDIAN (1U << 31)
#define DRM_FORMAT_INVALID 0
#define DRM_FORMAT_C1 fourcc_code('C', '1', ' ', ' ')
#define DRM_FORMAT_C2 fourcc_code('C', '2', ' ', ' ')
#define DRM_FORMAT_C4 fourcc_code('C', '4', ' ', ' ')
#define DRM_FORMAT_C8 fourcc_code('C', '8', ' ', ' ')
#define DRM_FORMAT_D1 fourcc_code('D', '1', ' ', ' ')
#define DRM_FORMAT_D2 fourcc_code('D', '2', ' ', ' ')
#define DRM_FORMAT_D4 fourcc_code('D', '4', ' ', ' ')
#define DRM_FORMAT_D8 fourcc_code('D', '8', ' ', ' ')
#define DRM_FORMAT_R1 fourcc_code('R', '1', ' ', ' ')
#define DRM_FORMAT_R2 fourcc_code('R', '2', ' ', ' ')
#define DRM_FORMAT_R4 fourcc_code('R', '4', ' ', ' ')
#define DRM_FORMAT_R8 fourcc_code('R', '8', ' ', ' ')
#define DRM_FORMAT_R10 fourcc_code('R', '1', '0', ' ')
#define DRM_FORMAT_R12 fourcc_code('R', '1', '2', ' ')
#define DRM_FORMAT_R16 fourcc_code('R', '1', '6', ' ')
#define DRM_FORMAT_RG88 fourcc_code('R', 'G', '8', '8')
#define DRM_FORMAT_GR88 fourcc_code('G', 'R', '8', '8')
#define DRM_FORMAT_RG1616 fourcc_code('R', 'G', '3', '2')
#define DRM_FORMAT_GR1616 fourcc_code('G', 'R', '3', '2')
#define DRM_FORMAT_RGB332 fourcc_code('R', 'G', 'B', '8')
#define DRM_FORMAT_BGR233 fourcc_code('B', 'G', 'R', '8')
#define DRM_FORMAT_XRGB4444 fourcc_code('X', 'R', '1', '2')
#define DRM_FORMAT_XBGR4444 fourcc_code('X', 'B', '1', '2')
#define DRM_FORMAT_RGBX4444 fourcc_code('R', 'X', '1', '2')
#define DRM_FORMAT_BGRX4444 fourcc_code('B', 'X', '1', '2')
#define DRM_FORMAT_ARGB4444 fourcc_code('A', 'R', '1', '2')
#define DRM_FORMAT_ABGR4444 fourcc_code('A', 'B', '1', '2')
#define DRM_FORMAT_RGBA4444 fourcc_code('R', 'A', '1', '2')
#define DRM_FORMAT_BGRA4444 fourcc_code('B', 'A', '1', '2')
#define DRM_FORMAT_XRGB1555 fourcc_code('X', 'R', '1', '5')
#define DRM_FORMAT_XBGR1555 fourcc_code('X', 'B', '1', '5')
#define DRM_FORMAT_RGBX5551 fourcc_code('R', 'X', '1', '5')
#define DRM_FORMAT_BGRX5551 fourcc_code('B', 'X', '1', '5')
#define DRM_FORMAT_ARGB1555 fourcc_code('A', 'R', '1', '5')
#define DRM_FORMAT_ABGR1555 fourcc_code('A', 'B', '1', '5')
#define DRM_FORMAT_RGBA5551 fourcc_code('R', 'A', '1', '5')
#define DRM_FORMAT_BGRA5551 fourcc_code('B', 'A', '1', '5')
#define DRM_FORMAT_RGB565 fourcc_code('R', 'G', '1', '6')
#define DRM_FORMAT_BGR565 fourcc_code('B', 'G', '1', '6')
#define DRM_FORMAT_RGB888 fourcc_code('R', 'G', '2', '4')
#define DRM_FORMAT_BGR888 fourcc_code('B', 'G', '2', '4')
#define DRM_FORMAT_XRGB8888 fourcc_code('X', 'R', '2', '4')
#define DRM_FORMAT_XBGR8888 fourcc_code('X', 'B', '2', '4')
#define DRM_FORMAT_RGBX8888 fourcc_code('R', 'X', '2', '4')
#define DRM_FORMAT_BGRX8888 fourcc_code('B', 'X', '2', '4')
#define DRM_FORMAT_ARGB8888 fourcc_code('A', 'R', '2', '4')
#define DRM_FORMAT_ABGR8888 fourcc_code('A', 'B', '2', '4')
#define DRM_FORMAT_RGBA8888 fourcc_code('R', 'A', '2', '4')
#define DRM_FORMAT_BGRA8888 fourcc_code('B', 'A', '2', '4')
#define DRM_FORMAT_XRGB2101010 fourcc_code('X', 'R', '3', '0')
#define DRM_FORMAT_XBGR2101010 fourcc_code('X', 'B', '3', '0')
#define DRM_FORMAT_RGBX1010102 fourcc_code('R', 'X', '3', '0')
#define DRM_FORMAT_BGRX1010102 fourcc_code('B', 'X', '3', '0')
#define DRM_FORMAT_ARGB2101010 fourcc_code('A', 'R', '3', '0')
#define DRM_FORMAT_ABGR2101010 fourcc_code('A', 'B', '3', '0')
#define DRM_FORMAT_RGBA1010102 fourcc_code('R', 'A', '3', '0')
#define DRM_FORMAT_BGRA1010102 fourcc_code('B', 'A', '3', '0')
#define DRM_FORMAT_XRGB16161616 fourcc_code('X', 'R', '4', '8')
#define DRM_FORMAT_XBGR16161616 fourcc_code('X', 'B', '4', '8')
#define DRM_FORMAT_ARGB16161616 fourcc_code('A', 'R', '4', '8')
#define DRM_FORMAT_ABGR16161616 fourcc_code('A', 'B', '4', '8')
#define DRM_FORMAT_XRGB16161616F fourcc_code('X', 'R', '4', 'H')
#define DRM_FORMAT_XBGR16161616F fourcc_code('X', 'B', '4', 'H')
#define DRM_FORMAT_ARGB16161616F fourcc_code('A', 'R', '4', 'H')
#define DRM_FORMAT_ABGR16161616F fourcc_code('A', 'B', '4', 'H')
#define DRM_FORMAT_AXBXGXRX106106106106 fourcc_code('A', 'B', '1', '0')
#define DRM_FORMAT_YUYV fourcc_code('Y', 'U', 'Y', 'V')
#define DRM_FORMAT_YVYU fourcc_code('Y', 'V', 'Y', 'U')
#define DRM_FORMAT_UYVY fourcc_code('U', 'Y', 'V', 'Y')
#define DRM_FORMAT_VYUY fourcc_code('V', 'Y', 'U', 'Y')
#define DRM_FORMAT_AYUV fourcc_code('A', 'Y', 'U', 'V')
#define DRM_FORMAT_AVUY8888 fourcc_code('A', 'V', 'U', 'Y')
#define DRM_FORMAT_XYUV8888 fourcc_code('X', 'Y', 'U', 'V')
#define DRM_FORMAT_XVUY8888 fourcc_code('X', 'V', 'U', 'Y')
#define DRM_FORMAT_VUY888 fourcc_code('V', 'U', '2', '4')
#define DRM_FORMAT_VUY101010 fourcc_code('V', 'U', '3', '0')
#define DRM_FORMAT_Y210 fourcc_code('Y', '2', '1', '0')
#define DRM_FORMAT_Y212 fourcc_code('Y', '2', '1', '2')
#define DRM_FORMAT_Y216 fourcc_code('Y', '2', '1', '6')
#define DRM_FORMAT_Y410 fourcc_code('Y', '4', '1', '0')
#define DRM_FORMAT_Y412 fourcc_code('Y', '4', '1', '2')
#define DRM_FORMAT_Y416 fourcc_code('Y', '4', '1', '6')
#define DRM_FORMAT_XVYU2101010 fourcc_code('X', 'V', '3', '0')
#define DRM_FORMAT_XVYU12_16161616 fourcc_code('X', 'V', '3', '6')
#define DRM_FORMAT_XVYU16161616 fourcc_code('X', 'V', '4', '8')
#define DRM_FORMAT_Y0L0 fourcc_code('Y', '0', 'L', '0')
#define DRM_FORMAT_X0L0 fourcc_code('X', '0', 'L', '0')
#define DRM_FORMAT_Y0L2 fourcc_code('Y', '0', 'L', '2')
#define DRM_FORMAT_X0L2 fourcc_code('X', '0', 'L', '2')
#define DRM_FORMAT_YUV420_8BIT fourcc_code('Y', 'U', '0', '8')
#define DRM_FORMAT_YUV420_10BIT fourcc_code('Y', 'U', '1', '0')
#define DRM_FORMAT_XRGB8888_A8 fourcc_code('X', 'R', 'A', '8')
#define DRM_FORMAT_XBGR8888_A8 fourcc_code('X', 'B', 'A', '8')
#define DRM_FORMAT_RGBX8888_A8 fourcc_code('R', 'X', 'A', '8')
#define DRM_FORMAT_BGRX8888_A8 fourcc_code('B', 'X', 'A', '8')
#define DRM_FORMAT_RGB888_A8 fourcc_code('R', '8', 'A', '8')
#define DRM_FORMAT_BGR888_A8 fourcc_code('B', '8', 'A', '8')
#define DRM_FORMAT_RGB565_A8 fourcc_code('R', '5', 'A', '8')
#define DRM_FORMAT_BGR565_A8 fourcc_code('B', '5', 'A', '8')
#define DRM_FORMAT_NV12 fourcc_code('N', 'V', '1', '2')
#define DRM_FORMAT_NV21 fourcc_code('N', 'V', '2', '1')
#define DRM_FORMAT_NV16 fourcc_code('N', 'V', '1', '6')
#define DRM_FORMAT_NV61 fourcc_code('N', 'V', '6', '1')
#define DRM_FORMAT_NV24 fourcc_code('N', 'V', '2', '4')
#define DRM_FORMAT_NV42 fourcc_code('N', 'V', '4', '2')
#define DRM_FORMAT_NV15 fourcc_code('N', 'V', '1', '5')
#define DRM_FORMAT_NV20 fourcc_code('N', 'V', '2', '0')
#define DRM_FORMAT_NV30 fourcc_code('N', 'V', '3', '0')
#define DRM_FORMAT_P210 fourcc_code('P', '2', '1', '0')
#define DRM_FORMAT_P010 fourcc_code('P', '0', '1', '0')
#define DRM_FORMAT_P012 fourcc_code('P', '0', '1', '2')
#define DRM_FORMAT_P016 fourcc_code('P', '0', '1', '6')
#define DRM_FORMAT_P030 fourcc_code('P', '0', '3', '0')
#define DRM_FORMAT_Q410 fourcc_code('Q', '4', '1', '0')
#define DRM_FORMAT_Q401 fourcc_code('Q', '4', '0', '1')
#define DRM_FORMAT_YUV410 fourcc_code('Y', 'U', 'V', '9')
#define DRM_FORMAT_YVU410 fourcc_code('Y', 'V', 'U', '9')
#define DRM_FORMAT_YUV411 fourcc_code('Y', 'U', '1', '1')
#define DRM_FORMAT_YVU411 fourcc_code('Y', 'V', '1', '1')
#define DRM_FORMAT_YUV420 fourcc_code('Y', 'U', '1', '2')
#define DRM_FORMAT_YVU420 fourcc_code('Y', 'V', '1', '2')
#define DRM_FORMAT_YUV422 fourcc_code('Y', 'U', '1', '6')
#define DRM_FORMAT_YVU422 fourcc_code('Y', 'V', '1', '6')
#define DRM_FORMAT_YUV444 fourcc_code('Y', 'U', '2', '4')
#define DRM_FORMAT_YVU444 fourcc_code('Y', 'V', '2', '4')
#define DRM_FORMAT_MOD_VENDOR_NONE 0
#define DRM_FORMAT_MOD_VENDOR_INTEL 0x01
#define DRM_FORMAT_MOD_VENDOR_AMD 0x02
#define DRM_FORMAT_MOD_VENDOR_NVIDIA 0x03
#define DRM_FORMAT_MOD_VENDOR_SAMSUNG 0x04
#define DRM_FORMAT_MOD_VENDOR_QCOM 0x05
#define DRM_FORMAT_MOD_VENDOR_VIVANTE 0x06
#define DRM_FORMAT_MOD_VENDOR_BROADCOM 0x07
#define DRM_FORMAT_MOD_VENDOR_ARM 0x08
#define DRM_FORMAT_MOD_VENDOR_ALLWINNER 0x09
#define DRM_FORMAT_MOD_VENDOR_AMLOGIC 0x0a
#define DRM_FORMAT_RESERVED ((1ULL << 56) - 1)
#define fourcc_mod_get_vendor(modifier) (((modifier) >> 56) & 0xff)
#define fourcc_mod_is_vendor(modifier,vendor) (fourcc_mod_get_vendor(modifier) == DRM_FORMAT_MOD_VENDOR_ ##vendor)
#define fourcc_mod_code(vendor,val) ((((__u64) DRM_FORMAT_MOD_VENDOR_ ##vendor) << 56) | ((val) & 0x00ffffffffffffffULL))
#define DRM_FORMAT_MOD_GENERIC_16_16_TILE DRM_FORMAT_MOD_SAMSUNG_16_16_TILE
#define DRM_FORMAT_MOD_INVALID fourcc_mod_code(NONE, DRM_FORMAT_RESERVED)
#define DRM_FORMAT_MOD_LINEAR fourcc_mod_code(NONE, 0)
#define DRM_FORMAT_MOD_NONE 0
#define I915_FORMAT_MOD_X_TILED fourcc_mod_code(INTEL, 1)
#define I915_FORMAT_MOD_Y_TILED fourcc_mod_code(INTEL, 2)
#define I915_FORMAT_MOD_Yf_TILED fourcc_mod_code(INTEL, 3)
#define I915_FORMAT_MOD_Y_TILED_CCS fourcc_mod_code(INTEL, 4)
#define I915_FORMAT_MOD_Yf_TILED_CCS fourcc_mod_code(INTEL, 5)
#define I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS fourcc_mod_code(INTEL, 6)
#define I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS fourcc_mod_code(INTEL, 7)
#define I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS_CC fourcc_mod_code(INTEL, 8)
#define I915_FORMAT_MOD_4_TILED fourcc_mod_code(INTEL, 9)
#define I915_FORMAT_MOD_4_TILED_DG2_RC_CCS fourcc_mod_code(INTEL, 10)
#define I915_FORMAT_MOD_4_TILED_DG2_MC_CCS fourcc_mod_code(INTEL, 11)
#define I915_FORMAT_MOD_4_TILED_DG2_RC_CCS_CC fourcc_mod_code(INTEL, 12)
#define I915_FORMAT_MOD_4_TILED_MTL_RC_CCS fourcc_mod_code(INTEL, 13)
#define I915_FORMAT_MOD_4_TILED_MTL_MC_CCS fourcc_mod_code(INTEL, 14)
#define I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC fourcc_mod_code(INTEL, 15)
#define I915_FORMAT_MOD_4_TILED_LNL_CCS fourcc_mod_code(INTEL, 16)
#define I915_FORMAT_MOD_4_TILED_BMG_CCS fourcc_mod_code(INTEL, 17)
#define DRM_FORMAT_MOD_SAMSUNG_64_32_TILE fourcc_mod_code(SAMSUNG, 1)
#define DRM_FORMAT_MOD_SAMSUNG_16_16_TILE fourcc_mod_code(SAMSUNG, 2)
#define DRM_FORMAT_MOD_QCOM_COMPRESSED fourcc_mod_code(QCOM, 1)
#define DRM_FORMAT_MOD_QCOM_TILED3 fourcc_mod_code(QCOM, 3)
#define DRM_FORMAT_MOD_QCOM_TILED2 fourcc_mod_code(QCOM, 2)
#define DRM_FORMAT_MOD_VIVANTE_TILED fourcc_mod_code(VIVANTE, 1)
#define DRM_FORMAT_MOD_VIVANTE_SUPER_TILED fourcc_mod_code(VIVANTE, 2)
#define DRM_FORMAT_MOD_VIVANTE_SPLIT_TILED fourcc_mod_code(VIVANTE, 3)
#define DRM_FORMAT_MOD_VIVANTE_SPLIT_SUPER_TILED fourcc_mod_code(VIVANTE, 4)
#define VIVANTE_MOD_TS_64_4 (1ULL << 48)
#define VIVANTE_MOD_TS_64_2 (2ULL << 48)
#define VIVANTE_MOD_TS_128_4 (3ULL << 48)
#define VIVANTE_MOD_TS_256_4 (4ULL << 48)
#define VIVANTE_MOD_TS_MASK (0xfULL << 48)
#define VIVANTE_MOD_COMP_DEC400 (1ULL << 52)
#define VIVANTE_MOD_COMP_MASK (0xfULL << 52)
#define VIVANTE_MOD_EXT_MASK (VIVANTE_MOD_TS_MASK | VIVANTE_MOD_COMP_MASK)
#define DRM_FORMAT_MOD_NVIDIA_TEGRA_TILED fourcc_mod_code(NVIDIA, 1)
#define DRM_FORMAT_MOD_NVIDIA_BLOCK_LINEAR_2D(c,s,g,k,h) fourcc_mod_code(NVIDIA, (0x10 | ((h) & 0xf) | (((k) & 0xff) << 12) | (((g) & 0x3) << 20) | (((s) & 0x1) << 22) | (((c) & 0x7) << 23)))
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(v) DRM_FORMAT_MOD_NVIDIA_BLOCK_LINEAR_2D(0, 0, 0, 0, (v))
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_ONE_GOB DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(0)
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_TWO_GOB DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(1)
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_FOUR_GOB DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(2)
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_EIGHT_GOB DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(3)
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_SIXTEEN_GOB DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(4)
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_THIRTYTWO_GOB DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(5)
#define __fourcc_mod_broadcom_param_shift 8
#define __fourcc_mod_broadcom_param_bits 48
#define fourcc_mod_broadcom_code(val,params) fourcc_mod_code(BROADCOM, ((((__u64) params) << __fourcc_mod_broadcom_param_shift) | val))
#define fourcc_mod_broadcom_param(m) ((int) (((m) >> __fourcc_mod_broadcom_param_shift) & ((1ULL << __fourcc_mod_broadcom_param_bits) - 1)))
#define fourcc_mod_broadcom_mod(m) ((m) & ~(((1ULL << __fourcc_mod_broadcom_param_bits) - 1) << __fourcc_mod_broadcom_param_shift))
#define DRM_FORMAT_MOD_BROADCOM_VC4_T_TILED fourcc_mod_code(BROADCOM, 1)
#define DRM_FORMAT_MOD_BROADCOM_SAND32_COL_HEIGHT(v) fourcc_mod_broadcom_code(2, v)
#define DRM_FORMAT_MOD_BROADCOM_SAND64_COL_HEIGHT(v) fourcc_mod_broadcom_code(3, v)
#define DRM_FORMAT_MOD_BROADCOM_SAND128_COL_HEIGHT(v) fourcc_mod_broadcom_code(4, v)
#define DRM_FORMAT_MOD_BROADCOM_SAND256_COL_HEIGHT(v) fourcc_mod_broadcom_code(5, v)
#define DRM_FORMAT_MOD_BROADCOM_SAND32 DRM_FORMAT_MOD_BROADCOM_SAND32_COL_HEIGHT(0)
#define DRM_FORMAT_MOD_BROADCOM_SAND64 DRM_FORMAT_MOD_BROADCOM_SAND64_COL_HEIGHT(0)
#define DRM_FORMAT_MOD_BROADCOM_SAND128 DRM_FORMAT_MOD_BROADCOM_SAND128_COL_HEIGHT(0)
#define DRM_FORMAT_MOD_BROADCOM_SAND256 DRM_FORMAT_MOD_BROADCOM_SAND256_COL_HEIGHT(0)
#define DRM_FORMAT_MOD_BROADCOM_UIF fourcc_mod_code(BROADCOM, 6)
#define DRM_FORMAT_MOD_ARM_CODE(__type,__val) fourcc_mod_code(ARM, ((__u64) (__type) << 52) | ((__val) & 0x000fffffffffffffULL))
#define DRM_FORMAT_MOD_ARM_TYPE_AFBC 0x00
#define DRM_FORMAT_MOD_ARM_TYPE_MISC 0x01
#define DRM_FORMAT_MOD_ARM_AFBC(__afbc_mode) DRM_FORMAT_MOD_ARM_CODE(DRM_FORMAT_MOD_ARM_TYPE_AFBC, __afbc_mode)
#define AFBC_FORMAT_MOD_BLOCK_SIZE_MASK 0xf
#define AFBC_FORMAT_MOD_BLOCK_SIZE_16x16 (1ULL)
#define AFBC_FORMAT_MOD_BLOCK_SIZE_32x8 (2ULL)
#define AFBC_FORMAT_MOD_BLOCK_SIZE_64x4 (3ULL)
#define AFBC_FORMAT_MOD_BLOCK_SIZE_32x8_64x4 (4ULL)
#define AFBC_FORMAT_MOD_YTR (1ULL << 4)
#define AFBC_FORMAT_MOD_SPLIT (1ULL << 5)
#define AFBC_FORMAT_MOD_SPARSE (1ULL << 6)
#define AFBC_FORMAT_MOD_CBR (1ULL << 7)
#define AFBC_FORMAT_MOD_TILED (1ULL << 8)
#define AFBC_FORMAT_MOD_SC (1ULL << 9)
#define AFBC_FORMAT_MOD_DB (1ULL << 10)
#define AFBC_FORMAT_MOD_BCH (1ULL << 11)
#define AFBC_FORMAT_MOD_USM (1ULL << 12)
#define DRM_FORMAT_MOD_ARM_TYPE_AFRC 0x02
#define DRM_FORMAT_MOD_ARM_AFRC(__afrc_mode) DRM_FORMAT_MOD_ARM_CODE(DRM_FORMAT_MOD_ARM_TYPE_AFRC, __afrc_mode)
#define AFRC_FORMAT_MOD_CU_SIZE_MASK 0xf
#define AFRC_FORMAT_MOD_CU_SIZE_16 (1ULL)
#define AFRC_FORMAT_MOD_CU_SIZE_24 (2ULL)
#define AFRC_FORMAT_MOD_CU_SIZE_32 (3ULL)
#define AFRC_FORMAT_MOD_CU_SIZE_P0(__afrc_cu_size) (__afrc_cu_size)
#define AFRC_FORMAT_MOD_CU_SIZE_P12(__afrc_cu_size) ((__afrc_cu_size) << 4)
#define AFRC_FORMAT_MOD_LAYOUT_SCAN (1ULL << 8)
#define DRM_FORMAT_MOD_ARM_16X16_BLOCK_U_INTERLEAVED DRM_FORMAT_MOD_ARM_CODE(DRM_FORMAT_MOD_ARM_TYPE_MISC, 1ULL)
#define DRM_FORMAT_MOD_ALLWINNER_TILED fourcc_mod_code(ALLWINNER, 1)
#define __fourcc_mod_amlogic_layout_mask 0xff
#define __fourcc_mod_amlogic_options_shift 8
#define __fourcc_mod_amlogic_options_mask 0xff
#define DRM_FORMAT_MOD_AMLOGIC_FBC(__layout,__options) fourcc_mod_code(AMLOGIC, ((__layout) & __fourcc_mod_amlogic_layout_mask) | (((__options) & __fourcc_mod_amlogic_options_mask) << __fourcc_mod_amlogic_options_shift))
#define AMLOGIC_FBC_LAYOUT_BASIC (1ULL)
#define AMLOGIC_FBC_LAYOUT_SCATTER (2ULL)
#define AMLOGIC_FBC_OPTION_MEM_SAVING (1ULL << 0)
#define AMD_FMT_MOD fourcc_mod_code(AMD, 0)
#define IS_AMD_FMT_MOD(val) (((val) >> 56) == DRM_FORMAT_MOD_VENDOR_AMD)
#define AMD_FMT_MOD_TILE_VER_GFX9 1
#define AMD_FMT_MOD_TILE_VER_GFX10 2
#define AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS 3
#define AMD_FMT_MOD_TILE_VER_GFX11 4
#define AMD_FMT_MOD_TILE_VER_GFX12 5
#define AMD_FMT_MOD_TILE_GFX9_64K_S 9
#define AMD_FMT_MOD_TILE_GFX9_64K_D 10
#define AMD_FMT_MOD_TILE_GFX9_64K_S_X 25
#define AMD_FMT_MOD_TILE_GFX9_64K_D_X 26
#define AMD_FMT_MOD_TILE_GFX9_64K_R_X 27
#define AMD_FMT_MOD_TILE_GFX11_256K_R_X 31
#define AMD_FMT_MOD_TILE_GFX12_256B_2D 1
#define AMD_FMT_MOD_TILE_GFX12_4K_2D 2
#define AMD_FMT_MOD_TILE_GFX12_64K_2D 3
#define AMD_FMT_MOD_TILE_GFX12_256K_2D 4
#define AMD_FMT_MOD_DCC_BLOCK_64B 0
#define AMD_FMT_MOD_DCC_BLOCK_128B 1
#define AMD_FMT_MOD_DCC_BLOCK_256B 2
#define AMD_FMT_MOD_TILE_VERSION_SHIFT 0
#define AMD_FMT_MOD_TILE_VERSION_MASK 0xFF
#define AMD_FMT_MOD_TILE_SHIFT 8
#define AMD_FMT_MOD_TILE_MASK 0x1F
#define AMD_FMT_MOD_DCC_SHIFT 13
#define AMD_FMT_MOD_DCC_MASK 0x1
#define AMD_FMT_MOD_DCC_RETILE_SHIFT 14
#define AMD_FMT_MOD_DCC_RETILE_MASK 0x1
#define AMD_FMT_MOD_DCC_PIPE_ALIGN_SHIFT 15
#define AMD_FMT_MOD_DCC_PIPE_ALIGN_MASK 0x1
#define AMD_FMT_MOD_DCC_INDEPENDENT_64B_SHIFT 16
#define AMD_FMT_MOD_DCC_INDEPENDENT_64B_MASK 0x1
#define AMD_FMT_MOD_DCC_INDEPENDENT_128B_SHIFT 17
#define AMD_FMT_MOD_DCC_INDEPENDENT_128B_MASK 0x1
#define AMD_FMT_MOD_DCC_MAX_COMPRESSED_BLOCK_SHIFT 18
#define AMD_FMT_MOD_DCC_MAX_COMPRESSED_BLOCK_MASK 0x3
#define AMD_FMT_MOD_DCC_CONSTANT_ENCODE_SHIFT 20
#define AMD_FMT_MOD_DCC_CONSTANT_ENCODE_MASK 0x1
#define AMD_FMT_MOD_PIPE_XOR_BITS_SHIFT 21
#define AMD_FMT_MOD_PIPE_XOR_BITS_MASK 0x7
#define AMD_FMT_MOD_BANK_XOR_BITS_SHIFT 24
#define AMD_FMT_MOD_BANK_XOR_BITS_MASK 0x7
#define AMD_FMT_MOD_PACKERS_SHIFT 27
#define AMD_FMT_MOD_PACKERS_MASK 0x7
#define AMD_FMT_MOD_RB_SHIFT 30
#define AMD_FMT_MOD_RB_MASK 0x7
#define AMD_FMT_MOD_PIPE_SHIFT 33
#define AMD_FMT_MOD_PIPE_MASK 0x7
#define AMD_FMT_MOD_SET(field,value) ((__u64) (value) << AMD_FMT_MOD_ ##field ##_SHIFT)
#define AMD_FMT_MOD_GET(field,value) (((value) >> AMD_FMT_MOD_ ##field ##_SHIFT) & AMD_FMT_MOD_ ##field ##_MASK)
#define AMD_FMT_MOD_CLEAR(field) (~((__u64) AMD_FMT_MOD_ ##field ##_MASK << AMD_FMT_MOD_ ##field ##_SHIFT))
#ifdef __cplusplus
}
#endif
#endif

"""

```