Response:
Let's break down the thought process for answering the request.

**1. Understanding the Core Request:**

The central piece is the provided C header file (`audio.handroid`). The request asks for a comprehensive analysis, including:

* **Functionality:** What does this file define?
* **Android Relevance:** How does it relate to Android's audio system?
* **`libc` Functions:** Detailed explanation of any `libc` functions used.
* **Dynamic Linker:**  Analysis of dynamic linking aspects, if any.
* **Logic & I/O:**  Hypothetical inputs and outputs.
* **Common Errors:**  Potential user/programmer mistakes.
* **Android Framework/NDK Path:** How does the code get involved from a high level?
* **Frida Hooking:**  Examples of using Frida for debugging.

**2. Initial Code Analysis (Skimming and Keyword Identification):**

The first step is to quickly read through the header file, looking for keywords and patterns:

* **`#ifndef`, `#define`, `#include`:** Standard C header file guards and inclusion. `linux/types.h` is a notable include.
* **`UAC_...`:**  A very strong indicator of "USB Audio Class." This immediately suggests the file defines constants and structures related to USB audio devices.
* **`USB_SUBCLASS_...`:** Reinforces the USB aspect, specifically related to audio and MIDI.
* **`UAC_HEADER`, `UAC_INPUT_TERMINAL`, `UAC_OUTPUT_TERMINAL`, etc.:**  These look like definitions for various components and configurations within a USB audio device.
* **`UAC__CUR`, `UAC__MIN`, `UAC__MAX`, etc.:** These resemble constants for setting or getting properties of audio devices (current, minimum, maximum values).
* **`struct uac1_ac_header_descriptor`, `struct uac_input_terminal_descriptor`, etc.:** These are clearly data structures describing different aspects of a USB audio device's configuration.
* **`__u8`, `__le16`:**  These are type definitions, likely related to platform-specific sizes and endianness (little-endian in this case). The `__attribute__((packed))` is important – it means the compiler shouldn't add padding to these structures.

**3. Categorizing the Functionality:**

Based on the initial scan, it's clear the file primarily defines:

* **Constants (Macros):** Representing USB Audio Class specifications, device types, control types, and data formats.
* **Data Structures (Structs):**  Representing the layout of descriptors used in USB audio communication. These descriptors are used to inform the host (e.g., an Android device) about the audio device's capabilities.

**4. Connecting to Android:**

The "handroid" in the path `bionic/libc/kernel/uapi/linux/usb/audio.handroid` is a strong hint. This signifies that these definitions are part of Android's adaptation of the Linux kernel's UAPI (User-space API). Android needs to understand how to communicate with USB audio devices, and this file provides the vocabulary for that communication.

**5. `libc` Function Analysis:**

A closer examination of the code reveals the *absence* of explicit `libc` function calls. This file primarily defines data structures and constants. It doesn't contain executable code. Therefore, the explanation focuses on *why* `libc` functions aren't directly present and where they *might* be used (e.g., when interacting with these structures in userspace or the kernel).

**6. Dynamic Linker Analysis:**

Similarly, because this is a header file defining data structures, it doesn't directly involve dynamic linking. The explanation clarifies that header files are used during compilation, and the *resulting compiled code* might be part of a shared library (SO) that is dynamically linked. The example SO layout is a generic representation of how shared libraries are structured in memory, rather than specific to this header file itself. The linking process description is also general.

**7. Logic, Input/Output, and Errors:**

Since the file defines data structures, "logic" is more about the *interpretation* of these structures. The hypothetical input/output demonstrates how Android might receive and interpret descriptor data from a USB audio device. The common errors focus on incorrect usage *of the defined constants and structures* when writing code that interacts with USB audio devices.

**8. Android Framework/NDK Path:**

This requires tracing the flow from a high level:

* **User Action:**  A user plugs in a USB audio device.
* **Android Framework:** The system detects the new device.
* **Hardware Abstraction Layer (HAL):**  Android interacts with hardware through HALs. An audio HAL would handle communication with the USB audio device.
* **Kernel Drivers:** The HAL interacts with the Linux kernel's USB audio driver.
* **UAPI:** The driver uses the definitions in `audio.handroid` to understand the device's capabilities.
* **NDK:** NDK developers can use related APIs (likely wrapping these low-level concepts) to interact with audio devices.

**9. Frida Hooking:**

The Frida examples target potential points of interaction:

* **System Calls:**  Functions that might be used to interact with the USB subsystem.
* **HAL Functions:**  Targeting the Audio HAL to see how it processes USB audio information.

**10. Structuring the Answer:**

Finally, the information is organized into clear sections with headings to address each part of the request. Using bullet points, code blocks, and explanations makes the answer easier to understand. The language is kept technical but also attempts to explain concepts clearly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Are there any functions in this file?"  *Correction:* Realized it's a header file, primarily defining data structures, not implementing functions.
* **Initial thought:** "How does dynamic linking directly apply here?" *Correction:*  Understood that the header file itself isn't dynamically linked, but the code using it might be part of a dynamically linked library. The example SO layout and linking description should be generalized.
* **Focus on Clarity:**  Ensuring the explanation of each section is understandable, even to someone who might not be deeply familiar with USB audio or kernel internals. Using analogies or simple examples where possible.

By following this structured approach, breaking down the request into smaller parts, and constantly refining the understanding of the code and its context, a comprehensive and accurate answer can be generated.
好的，让我们来详细分析一下 `bionic/libc/kernel/uapi/linux/usb/audio.handroid` 这个头文件。

**文件功能概览**

这个头文件 `audio.handroid` 定义了用于与 USB 音频设备进行通信的常量、宏和数据结构。它本质上是 Linux 内核中 USB 音频类（USB Audio Class，UAC）规范的用户空间接口（UAPI）的一部分。这些定义允许用户空间的程序（例如 Android 的音频服务）理解和控制连接的 USB 音频设备的功能。

**与 Android 功能的关系和举例说明**

这个头文件对于 Android 的音频系统至关重要，因为它定义了 Android 如何与 USB 音频设备（例如 USB 耳机、麦克风、音频接口等）进行交互。

* **音频输入/输出:**  头文件中定义的常量，如 `UAC_INPUT_TERMINAL_MICROPHONE` 和 `UAC_OUTPUT_TERMINAL_SPEAKER`，帮助 Android 系统识别连接的 USB 设备是音频输入设备、输出设备还是两者兼有。
* **音频控制:** 定义了各种控制单元和功能单元，例如 `UAC_FEATURE_UNIT`、`UAC_FU_VOLUME`、`UAC_FU_MUTE` 等。Android 可以使用这些定义来控制 USB 音频设备的音量、静音等功能。
* **音频格式:**  定义了不同的音频数据格式，例如 `UAC_FORMAT_TYPE_I_PCM`，这使得 Android 能够识别和处理 USB 音频设备支持的音频格式。
* **USB 设备描述符:**  头文件中定义的结构体，例如 `struct uac1_ac_header_descriptor` 和 `struct uac_input_terminal_descriptor`，对应于 USB 音频设备的描述符。Android 系统会读取这些描述符来了解设备的功能和配置。

**举例说明:**

当用户将 USB 耳机插入 Android 设备时，Android 系统会检测到这个 USB 设备。操作系统会读取该设备的描述符，这些描述符的格式和内容与 `audio.handroid` 中定义的结构体相对应。例如，如果耳机支持音量控制，其描述符中会包含一个特征单元（Feature Unit），Android 系统可以通过发送 USB 控制请求，使用 `UAC_FU_VOLUME` 常量来调节耳机的音量。

**libc 函数的功能实现**

这个头文件本身并没有包含任何 `libc` 函数的实现。它只是定义了一些常量、宏和数据结构。这些定义会被其他 C/C++ 代码使用，而这些代码可能会调用 `libc` 中的函数。

例如，当 Android 系统需要与 USB 设备进行通信时，可能会使用 `libc` 中的 `ioctl` 函数来发送 USB 控制请求。`ioctl` 函数是一个通用的设备控制接口，允许用户空间的程序向设备驱动程序发送特定的命令和数据。

**涉及 dynamic linker 的功能**

这个头文件本身不直接涉及 dynamic linker 的功能。它是在编译时被包含到其他源文件中的。然而，使用这个头文件的代码最终可能会被编译成共享库（.so 文件），而这些共享库会被 Android 的 dynamic linker 加载和链接。

**so 布局样本:**

假设有一个名为 `libusbaudio.so` 的共享库，它使用了 `audio.handroid` 中定义的结构体和常量来处理 USB 音频设备。它的布局可能如下：

```
libusbaudio.so:
  .text         # 包含可执行代码
    - 函数 A (例如：初始化 USB 音频设备)
    - 函数 B (例如：发送音量控制命令)
    - ...
  .rodata       # 包含只读数据
    - audio.handroid 中定义的常量 (可能被编译器内联)
    - 其他只读数据
  .data         # 包含可读写数据
    - 全局变量 (例如：USB 设备句柄)
  .bss          # 包含未初始化的静态变量
  .dynsym       # 动态符号表
    - 函数 A 的符号
    - 函数 B 的符号
    - ...
  .dynstr       # 动态字符串表
    - 函数 A 的名称 "init_usb_audio"
    - 函数 B 的名称 "set_volume"
    - ...
  .plt          # 程序链接表 (用于延迟绑定)
  .got.plt      # 全局偏移量表 (用于延迟绑定)
```

**链接的处理过程:**

1. **编译:** 使用 `audio.handroid` 的源文件被编译成目标文件 (.o)。
2. **链接:** 链接器将这些目标文件以及需要的库文件（包括 `libc.so` 等）链接成共享库 `libusbaudio.so`。链接器会解析符号引用，并生成动态符号表、动态字符串表、程序链接表和全局偏移量表等。
3. **加载:** 当 Android 系统需要使用 `libusbaudio.so` 时，dynamic linker（通常是 `/system/bin/linker64` 或 `/system/bin/linker`）会将该共享库加载到内存中。
4. **重定位:** dynamic linker 会根据加载地址调整共享库中的地址引用。
5. **符号解析:**  当程序调用 `libusbaudio.so` 中的函数时，如果使用了延迟绑定，dynamic linker 会在第一次调用时解析函数地址，并更新程序链接表和全局偏移量表。

**逻辑推理、假设输入与输出**

虽然这个头文件本身不包含逻辑，但我们可以假设一个使用它的场景：Android 音频服务尝试获取连接的 USB 音频设备的输入终端数量。

**假设输入:**

* 一个连接到 Android 设备的 USB 音频设备。
* Android 音频服务通过 USB 子系统读取了该设备的配置描述符。
* 配置描述符中包含了音频控制接口描述符，其中包含一个或多个输入终端描述符。

**逻辑推理:**

Android 音频服务会解析 USB 设备的配置描述符，查找音频控制接口描述符。在音频控制接口描述符中，会存在一个或多个输入终端描述符，其结构体定义在 `audio.handroid` 中（例如 `struct uac_input_terminal_descriptor`）。服务会遍历这些描述符，并根据 `bDescriptorSubtype` 字段判断是否为输入终端描述符，并统计其数量。

**假设输出:**

假设 USB 音频设备有两个输入终端（例如，左右声道麦克风），则 Android 音频服务会输出：`输入终端数量: 2`。

**用户或编程常见的使用错误**

* **字节序错误:**  USB 规范通常使用小端字节序（Little-Endian），而某些平台的 CPU 可能使用大端字节序（Big-Endian）。如果在解析描述符时没有注意字节序转换（例如，使用 `le16_to_cpu()` 宏），可能会导致读取的数值错误。
* **结构体大小和对齐问题:**  `__attribute__((packed))` 指示编译器不要在结构体成员之间填充字节。如果用户代码在解析这些结构体时假设了错误的结构体大小或对齐方式，可能会导致数据读取错误。
* **常量值错误:**  错误地使用了头文件中定义的常量值，例如，使用了一个不存在的终端类型 ID，会导致系统无法正确识别设备的功能。
* **未检查返回值:**  在与 USB 设备进行交互时，例如发送控制请求，应该检查操作系统的返回值，以确保操作成功。忽略错误返回值可能导致程序行为异常。

**Android Framework 或 NDK 如何到达这里**

1. **硬件连接:** 用户将 USB 音频设备连接到 Android 设备。
2. **内核驱动:** Linux 内核中的 USB 子系统检测到新设备，并加载相应的 USB 音频类驱动程序 (`snd-usb-audio`)。
3. **UAPI 交互:**  USB 音频类驱动程序使用 `audio.handroid` 中定义的结构体来解析 USB 音频设备的描述符，了解设备的功能和配置。
4. **Audio HAL (Hardware Abstraction Layer):** Android 的音频硬件抽象层（Audio HAL）是连接 Android Framework 和底层音频驱动程序的桥梁。Audio HAL 的实现会与内核驱动程序进行交互，获取 USB 音频设备的信息并进行控制。
5. **AudioFlinger (System Service):**  `AudioFlinger` 是 Android 系统中负责音频管理的系统服务。它使用 Audio HAL 提供的接口来管理音频输入和输出设备，包括 USB 音频设备。
6. **Media Framework (Application Layer):**  应用程序通过 Android 的 Media Framework 与音频系统进行交互。Media Framework 会调用 `AudioFlinger` 的接口来播放或录制音频。
7. **NDK (Native Development Kit):**  NDK 允许开发者使用 C/C++ 代码来访问 Android 的底层 API。开发者可以使用 NDK 提供的音频相关的 API（例如 AAudio）来与 USB 音频设备进行交互。这些 NDK API 最终也会调用到 Audio HAL 或更底层的内核驱动程序。

**Frida Hook 示例调试步骤**

我们可以使用 Frida hook 一些关键的函数调用，来观察 Android 系统如何与 USB 音频设备交互。以下是一些示例：

**1. Hook `ioctl` 系统调用，查看发送给 USB 设备的控制请求:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")

def main():
    device = frida.get_usb_device()
    pid = device.spawn(['com.android.systemui']) # 替换为你想要 hook 的进程
    session = device.attach(pid)
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
            onEnter: function(args) {
                const fd = args[0].toInt37();
                const request = args[1].toInt37();
                // 检查是否是与 USB 设备相关的 ioctl 请求
                if (request >= 0xc0005500 && request <= 0xc00055ff) { // 假设 USB 音频相关的 ioctl 范围
                    console.log("[*] ioctl called with fd:", fd, "request:", request);
                    // 可以尝试读取 argp 中的数据，但这可能很复杂
                }
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()

if __name__ == '__main__':
    main()
```

**2. Hook Audio HAL 中的函数，查看对 USB 音频设备的操作:**

你需要找到 Audio HAL 库的路径和相关的函数名。例如，可以尝试 hook `AudioFlinger` 加载 Audio HAL 库的函数，然后 hook Audio HAL 中与 USB 设备相关的函数，例如打开设备、设置参数等。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")

def main():
    device = frida.get_usb_device()
    session = device.attach('com.android.systemui') # 替换为你想要 hook 的进程
    script = session.create_script("""
        // 假设已知 Audio HAL 库的名称
        const audioHalModule = Process.getModuleByName("android.hardware.audio.service.so");
        if (audioHalModule) {
            // 假设已知 Audio HAL 中打开 USB 音频设备的函数名
            const openUsbAudioDevice = audioHalModule.findExportByName("_ZN7android3Hal17UsbAudioHwDevice5openEDPv"); // 示例函数名，需要根据实际情况修改
            if (openUsbAudioDevice) {
                Interceptor.attach(openUsbAudioDevice, {
                    onEnter: function(args) {
                        console.log("[*] openUsbAudioDevice called with args:", args);
                    }
                });
            } else {
                console.log("[-] openUsbAudioDevice function not found.");
            }
        } else {
            console.log("[-] Audio HAL module not found.");
        }
    """)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()

if __name__ == '__main__':
    main()
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。
2. **连接设备:** 使用 `frida-ls-devices` 确认 Frida 可以连接到你的设备。
3. **编写 Frida 脚本:** 根据你想要调试的内容编写 Frida hook 脚本。
4. **运行脚本:** 使用 `frida -U -f <package_name> -l <script_name>.py` 或 `frida -U <process_name> -l <script_name>.py` 运行脚本。
5. **触发事件:** 在 Android 设备上执行操作，例如插入 USB 音频设备，播放音频等，以触发你 hook 的函数调用。
6. **查看输出:** Frida 会在控制台上输出 hook 到的函数调用信息和参数。

**总结**

`bionic/libc/kernel/uapi/linux/usb/audio.handroid` 是 Android 系统与 USB 音频设备交互的基础。它定义了通信所需的常量、宏和数据结构。理解这个头文件的内容对于分析和调试 Android 音频系统的 USB 音频相关问题至关重要。通过 Frida 等工具，我们可以 hook 相关的系统调用和库函数，深入了解 Android 系统如何一步步地与 USB 音频设备进行交互。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/usb/audio.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__LINUX_USB_AUDIO_H
#define _UAPI__LINUX_USB_AUDIO_H
#include <linux/types.h>
#define UAC_VERSION_1 0x00
#define UAC_VERSION_2 0x20
#define UAC_VERSION_3 0x30
#define USB_SUBCLASS_AUDIOCONTROL 0x01
#define USB_SUBCLASS_AUDIOSTREAMING 0x02
#define USB_SUBCLASS_MIDISTREAMING 0x03
#define UAC_HEADER 0x01
#define UAC_INPUT_TERMINAL 0x02
#define UAC_OUTPUT_TERMINAL 0x03
#define UAC_MIXER_UNIT 0x04
#define UAC_SELECTOR_UNIT 0x05
#define UAC_FEATURE_UNIT 0x06
#define UAC1_PROCESSING_UNIT 0x07
#define UAC1_EXTENSION_UNIT 0x08
#define UAC_AS_GENERAL 0x01
#define UAC_FORMAT_TYPE 0x02
#define UAC_FORMAT_SPECIFIC 0x03
#define UAC_PROCESS_UNDEFINED 0x00
#define UAC_PROCESS_UP_DOWNMIX 0x01
#define UAC_PROCESS_DOLBY_PROLOGIC 0x02
#define UAC_PROCESS_STEREO_EXTENDER 0x03
#define UAC_PROCESS_REVERB 0x04
#define UAC_PROCESS_CHORUS 0x05
#define UAC_PROCESS_DYN_RANGE_COMP 0x06
#define UAC_EP_GENERAL 0x01
#define UAC_SET_ 0x00
#define UAC_GET_ 0x80
#define UAC__CUR 0x1
#define UAC__MIN 0x2
#define UAC__MAX 0x3
#define UAC__RES 0x4
#define UAC__MEM 0x5
#define UAC_SET_CUR (UAC_SET_ | UAC__CUR)
#define UAC_GET_CUR (UAC_GET_ | UAC__CUR)
#define UAC_SET_MIN (UAC_SET_ | UAC__MIN)
#define UAC_GET_MIN (UAC_GET_ | UAC__MIN)
#define UAC_SET_MAX (UAC_SET_ | UAC__MAX)
#define UAC_GET_MAX (UAC_GET_ | UAC__MAX)
#define UAC_SET_RES (UAC_SET_ | UAC__RES)
#define UAC_GET_RES (UAC_GET_ | UAC__RES)
#define UAC_SET_MEM (UAC_SET_ | UAC__MEM)
#define UAC_GET_MEM (UAC_GET_ | UAC__MEM)
#define UAC_GET_STAT 0xff
#define UAC_TERM_COPY_PROTECT 0x01
#define UAC_FU_MUTE 0x01
#define UAC_FU_VOLUME 0x02
#define UAC_FU_BASS 0x03
#define UAC_FU_MID 0x04
#define UAC_FU_TREBLE 0x05
#define UAC_FU_GRAPHIC_EQUALIZER 0x06
#define UAC_FU_AUTOMATIC_GAIN 0x07
#define UAC_FU_DELAY 0x08
#define UAC_FU_BASS_BOOST 0x09
#define UAC_FU_LOUDNESS 0x0a
#define UAC_CONTROL_BIT(CS) (1 << ((CS) - 1))
#define UAC_UD_ENABLE 0x01
#define UAC_UD_MODE_SELECT 0x02
#define UAC_DP_ENABLE 0x01
#define UAC_DP_MODE_SELECT 0x02
#define UAC_3D_ENABLE 0x01
#define UAC_3D_SPACE 0x02
#define UAC_REVERB_ENABLE 0x01
#define UAC_REVERB_LEVEL 0x02
#define UAC_REVERB_TIME 0x03
#define UAC_REVERB_FEEDBACK 0x04
#define UAC_CHORUS_ENABLE 0x01
#define UAC_CHORUS_LEVEL 0x02
#define UAC_CHORUS_RATE 0x03
#define UAC_CHORUS_DEPTH 0x04
#define UAC_DCR_ENABLE 0x01
#define UAC_DCR_RATE 0x02
#define UAC_DCR_MAXAMPL 0x03
#define UAC_DCR_THRESHOLD 0x04
#define UAC_DCR_ATTACK_TIME 0x05
#define UAC_DCR_RELEASE_TIME 0x06
#define UAC_XU_ENABLE 0x01
#define UAC_MS_HEADER 0x01
#define UAC_MIDI_IN_JACK 0x02
#define UAC_MIDI_OUT_JACK 0x03
#define UAC_MS_GENERAL 0x01
#define UAC_TERMINAL_UNDEFINED 0x100
#define UAC_TERMINAL_STREAMING 0x101
#define UAC_TERMINAL_VENDOR_SPEC 0x1FF
struct uac1_ac_header_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __le16 bcdADC;
  __le16 wTotalLength;
  __u8 bInCollection;
  __u8 baInterfaceNr[];
} __attribute__((packed));
#define UAC_DT_AC_HEADER_SIZE(n) (8 + (n))
#define DECLARE_UAC_AC_HEADER_DESCRIPTOR(n) struct uac1_ac_header_descriptor_ ##n { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubtype; __le16 bcdADC; __le16 wTotalLength; __u8 bInCollection; __u8 baInterfaceNr[n]; \
} __attribute__((packed))
struct uac_input_terminal_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bTerminalID;
  __le16 wTerminalType;
  __u8 bAssocTerminal;
  __u8 bNrChannels;
  __le16 wChannelConfig;
  __u8 iChannelNames;
  __u8 iTerminal;
} __attribute__((packed));
#define UAC_DT_INPUT_TERMINAL_SIZE 12
#define UAC_INPUT_TERMINAL_UNDEFINED 0x200
#define UAC_INPUT_TERMINAL_MICROPHONE 0x201
#define UAC_INPUT_TERMINAL_DESKTOP_MICROPHONE 0x202
#define UAC_INPUT_TERMINAL_PERSONAL_MICROPHONE 0x203
#define UAC_INPUT_TERMINAL_OMNI_DIR_MICROPHONE 0x204
#define UAC_INPUT_TERMINAL_MICROPHONE_ARRAY 0x205
#define UAC_INPUT_TERMINAL_PROC_MICROPHONE_ARRAY 0x206
#define UAC_TERMINAL_CS_COPY_PROTECT_CONTROL 0x01
struct uac1_output_terminal_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bTerminalID;
  __le16 wTerminalType;
  __u8 bAssocTerminal;
  __u8 bSourceID;
  __u8 iTerminal;
} __attribute__((packed));
#define UAC_DT_OUTPUT_TERMINAL_SIZE 9
#define UAC_OUTPUT_TERMINAL_UNDEFINED 0x300
#define UAC_OUTPUT_TERMINAL_SPEAKER 0x301
#define UAC_OUTPUT_TERMINAL_HEADPHONES 0x302
#define UAC_OUTPUT_TERMINAL_HEAD_MOUNTED_DISPLAY_AUDIO 0x303
#define UAC_OUTPUT_TERMINAL_DESKTOP_SPEAKER 0x304
#define UAC_OUTPUT_TERMINAL_ROOM_SPEAKER 0x305
#define UAC_OUTPUT_TERMINAL_COMMUNICATION_SPEAKER 0x306
#define UAC_OUTPUT_TERMINAL_LOW_FREQ_EFFECTS_SPEAKER 0x307
#define UAC_BIDIR_TERMINAL_UNDEFINED 0x400
#define UAC_BIDIR_TERMINAL_HANDSET 0x401
#define UAC_BIDIR_TERMINAL_HEADSET 0x402
#define UAC_BIDIR_TERMINAL_SPEAKER_PHONE 0x403
#define UAC_BIDIR_TERMINAL_ECHO_SUPPRESSING 0x404
#define UAC_BIDIR_TERMINAL_ECHO_CANCELING 0x405
#define UAC_DT_FEATURE_UNIT_SIZE(ch) (7 + ((ch) + 1) * 2)
#define DECLARE_UAC_FEATURE_UNIT_DESCRIPTOR(ch) struct uac_feature_unit_descriptor_ ##ch { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubtype; __u8 bUnitID; __u8 bSourceID; __u8 bControlSize; __le16 bmaControls[ch + 1]; __u8 iFeature; \
} __attribute__((packed))
struct uac_mixer_unit_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bUnitID;
  __u8 bNrInPins;
  __u8 baSourceID[];
} __attribute__((packed));
struct uac_selector_unit_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bUintID;
  __u8 bNrInPins;
  __u8 baSourceID[];
} __attribute__((packed));
struct uac_feature_unit_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bUnitID;
  __u8 bSourceID;
  __u8 bControlSize;
  __u8 bmaControls[];
} __attribute__((packed));
struct uac_processing_unit_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bUnitID;
  __le16 wProcessType;
  __u8 bNrInPins;
  __u8 baSourceID[];
} __attribute__((packed));
struct uac1_as_header_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bTerminalLink;
  __u8 bDelay;
  __le16 wFormatTag;
} __attribute__((packed));
#define UAC_DT_AS_HEADER_SIZE 7
#define UAC_FORMAT_TYPE_I_UNDEFINED 0x0
#define UAC_FORMAT_TYPE_I_PCM 0x1
#define UAC_FORMAT_TYPE_I_PCM8 0x2
#define UAC_FORMAT_TYPE_I_IEEE_FLOAT 0x3
#define UAC_FORMAT_TYPE_I_ALAW 0x4
#define UAC_FORMAT_TYPE_I_MULAW 0x5
struct uac_format_type_i_continuous_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bFormatType;
  __u8 bNrChannels;
  __u8 bSubframeSize;
  __u8 bBitResolution;
  __u8 bSamFreqType;
  __u8 tLowerSamFreq[3];
  __u8 tUpperSamFreq[3];
} __attribute__((packed));
#define UAC_FORMAT_TYPE_I_CONTINUOUS_DESC_SIZE 14
struct uac_format_type_i_discrete_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bFormatType;
  __u8 bNrChannels;
  __u8 bSubframeSize;
  __u8 bBitResolution;
  __u8 bSamFreqType;
  __u8 tSamFreq[][3];
} __attribute__((packed));
#define DECLARE_UAC_FORMAT_TYPE_I_DISCRETE_DESC(n) struct uac_format_type_i_discrete_descriptor_ ##n { __u8 bLength; __u8 bDescriptorType; __u8 bDescriptorSubtype; __u8 bFormatType; __u8 bNrChannels; __u8 bSubframeSize; __u8 bBitResolution; __u8 bSamFreqType; __u8 tSamFreq[n][3]; \
} __attribute__((packed))
#define UAC_FORMAT_TYPE_I_DISCRETE_DESC_SIZE(n) (8 + (n * 3))
struct uac_format_type_i_ext_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bFormatType;
  __u8 bSubslotSize;
  __u8 bBitResolution;
  __u8 bHeaderLength;
  __u8 bControlSize;
  __u8 bSideBandProtocol;
} __attribute__((packed));
#define UAC_FORMAT_TYPE_II_MPEG 0x1001
#define UAC_FORMAT_TYPE_II_AC3 0x1002
struct uac_format_type_ii_discrete_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bFormatType;
  __le16 wMaxBitRate;
  __le16 wSamplesPerFrame;
  __u8 bSamFreqType;
  __u8 tSamFreq[][3];
} __attribute__((packed));
struct uac_format_type_ii_ext_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bFormatType;
  __le16 wMaxBitRate;
  __le16 wSamplesPerFrame;
  __u8 bHeaderLength;
  __u8 bSideBandProtocol;
} __attribute__((packed));
#define UAC_FORMAT_TYPE_III_IEC1937_AC3 0x2001
#define UAC_FORMAT_TYPE_III_IEC1937_MPEG1_LAYER1 0x2002
#define UAC_FORMAT_TYPE_III_IEC1937_MPEG2_NOEXT 0x2003
#define UAC_FORMAT_TYPE_III_IEC1937_MPEG2_EXT 0x2004
#define UAC_FORMAT_TYPE_III_IEC1937_MPEG2_LAYER1_LS 0x2005
#define UAC_FORMAT_TYPE_III_IEC1937_MPEG2_LAYER23_LS 0x2006
#define UAC_FORMAT_TYPE_UNDEFINED 0x0
#define UAC_FORMAT_TYPE_I 0x1
#define UAC_FORMAT_TYPE_II 0x2
#define UAC_FORMAT_TYPE_III 0x3
#define UAC_EXT_FORMAT_TYPE_I 0x81
#define UAC_EXT_FORMAT_TYPE_II 0x82
#define UAC_EXT_FORMAT_TYPE_III 0x83
struct uac_iso_endpoint_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDescriptorSubtype;
  __u8 bmAttributes;
  __u8 bLockDelayUnits;
  __le16 wLockDelay;
} __attribute__((packed));
#define UAC_ISO_ENDPOINT_DESC_SIZE 7
#define UAC_EP_CS_ATTR_SAMPLE_RATE 0x01
#define UAC_EP_CS_ATTR_PITCH_CONTROL 0x02
#define UAC_EP_CS_ATTR_FILL_MAX 0x80
#define UAC1_STATUS_TYPE_ORIG_MASK 0x0f
#define UAC1_STATUS_TYPE_ORIG_AUDIO_CONTROL_IF 0x0
#define UAC1_STATUS_TYPE_ORIG_AUDIO_STREAM_IF 0x1
#define UAC1_STATUS_TYPE_ORIG_AUDIO_STREAM_EP 0x2
#define UAC1_STATUS_TYPE_IRQ_PENDING (1 << 7)
#define UAC1_STATUS_TYPE_MEM_CHANGED (1 << 6)
struct uac1_status_word {
  __u8 bStatusType;
  __u8 bOriginator;
} __attribute__((packed));
#endif
```