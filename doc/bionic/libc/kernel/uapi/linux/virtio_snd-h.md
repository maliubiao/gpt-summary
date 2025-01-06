Response:
Let's break down the thought process for analyzing the provided C header file `virtio_snd.handroid`.

**1. Understanding the Context:**

The prompt explicitly states: "这是目录为bionic/libc/kernel/uapi/linux/virtio_snd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker."  This is crucial. It immediately tells us:

* **Location:** This file defines kernel-level interfaces (`uapi`) related to sound (`snd`) using the virtio framework.
* **Purpose:** It's part of the Android Bionic library, implying it's used for communication between the Android userspace and the kernel regarding audio.
* **Technology:** The "virtio" part signals that this is about virtualized hardware. This is common in Android emulators and virtual machines.

**2. Initial Scan and Identification of Key Components:**

A quick read-through reveals several recurring patterns and keywords:

* **`struct` definitions:**  These define data structures for exchanging information. We can see structures related to configuration (`virtio_snd_config`), events (`virtio_snd_event`), queries (`virtio_snd_query_info`), and specific audio concepts like jacks, PCM, and controls.
* **`enum` definitions:** These define sets of named constants, often representing flags, states, or types. Examples include queue types (`VIRTIO_SND_VQ_*`), directions (`VIRTIO_SND_D_*`), requests (`VIRTIO_SND_R_*`), events (`VIRTIO_SND_EVT_*`), PCM formats (`VIRTIO_SND_PCM_FMT_*`), rates (`VIRTIO_SND_PCM_RATE_*`), channel maps (`VIRTIO_SND_CHMAP_*`), and control types (`VIRTIO_SND_CTL_TYPE_*`).
* **`#ifndef`, `#define`, `#include`:** Standard C preprocessor directives for header file inclusion and preventing multiple inclusions. The inclusion of `<linux/virtio_types.h>` confirms the virtio connection.
* **`__le32`, `__le64`, `__u8`:**  Data type definitions likely ensuring correct endianness for communication between different systems. The `__le` likely signifies "little-endian."

**3. Deduce High-Level Functionality:**

Based on the identified components, we can infer the overall purpose: This file defines the interface for a virtualized sound card driver. It allows the guest operating system (like Android running in an emulator) to interact with the host's audio hardware.

**4. Categorize Functionality:**

To structure the explanation, it's helpful to group related definitions:

* **Configuration:** `virtio_snd_config` - basic properties of the virtual sound device.
* **Virtual Queues:** `VIRTIO_SND_VQ_*` - different channels for communication (control, event, transmit, receive).
* **Requests/Commands:** `VIRTIO_SND_R_*` - actions the guest can request from the host (get info, set parameters, start/stop playback, control volume, etc.).
* **Events:** `VIRTIO_SND_EVT_*` - notifications from the host to the guest (jack status changes, playback progress, errors).
* **Data Structures (payloads for requests/events):** `virtio_snd_hdr`, `virtio_snd_event`, `virtio_snd_query_info`, etc. These contain the specific data associated with each request or event.
* **Audio Concepts:**  Structures and enums related to audio streams (PCM), jacks (physical connectors), channel mapping, and controls (volume, mute).

**5. Explain Android Relevance (and give examples):**

The connection to Android is clear because this is part of Bionic. The key is *how* it's used:

* **Emulation/Virtualization:**  The primary use case is Android running in a virtualized environment (emulator, virtual machine). The virtual sound card allows audio to be played and recorded.
* **Hardware Abstraction:**  Virtio provides a standardized interface, making the guest OS independent of the specific host audio hardware.
* **Framework Interaction (High-Level):**  The Android framework's audio subsystems (like `AudioFlinger`) will ultimately use these low-level interfaces to interact with the virtualized audio device.

**Examples:**

* When a user plays music in an Android emulator, the audio data will eventually be transmitted via the `VIRTIO_SND_VQ_TX` queue.
* When the user plugs in headphones (in the emulated environment), the host will send a `VIRTIO_SND_EVT_JACK_CONNECTED` event to the Android guest.
* Adjusting the volume slider in the Android settings might translate into a `VIRTIO_SND_R_CTL_WRITE` request to modify a control.

**6. Address Specific Prompt Requirements:**

* **libc Function Implementation:**  This file *defines interfaces*, not implements libc functions. It's a header file. The *implementation* would be in the kernel driver and potentially in userspace libraries that interact with the driver (though not directly part of *libc*). Therefore, the answer should clarify this distinction.
* **Dynamic Linker:** This file doesn't directly involve the dynamic linker. It's a kernel-level interface. The dynamic linker is concerned with loading and linking shared libraries in userspace. The answer should state this clearly. No SO layout or linking process is relevant here.
* **Logic Inference:**  The logic is primarily about defining data structures and enums. No complex logical deduction with specific inputs/outputs is present within *this header file itself*. The *use* of these structures would involve logic in the driver and userspace code.
* **User/Programming Errors:**  Common errors would involve:
    * Incorrectly formatting the data sent in requests.
    * Using invalid enum values.
    * Not handling events properly.
    * Issues with buffer sizes or data alignment when interacting with the virtual queues.
* **Android Framework/NDK Path and Frida Hook:** This is about tracing the execution flow. The explanation needs to connect the high-level framework components to the low-level kernel interface. A Frida hook example should target a system call or a function within a relevant Android service that interacts with the audio subsystem. The key is to illustrate how the framework *eventually* touches these virtio structures.

**7. Structure and Refine:**

Organize the information logically using headings and bullet points. Use clear and concise language. Ensure all aspects of the prompt are addressed. Review for accuracy and completeness. Emphasize the core purpose: defining the interface for a virtualized sound card.

This detailed breakdown reflects the thinking process required to thoroughly analyze the header file and address all parts of the prompt. It involves understanding the context, identifying key elements, inferring functionality, and connecting it to the broader Android ecosystem.## 对 bionic/libc/kernel/uapi/linux/virtio_snd.handroid 的分析

这个头文件 `virtio_snd.handroid` 定义了 Linux 内核中 virtio 框架下的音频子系统接口。它用于在虚拟机或容器环境中，Guest 操作系统（例如运行 Android 的虚拟机）与 Host 操作系统之间的音频设备通信。 由于它位于 `bionic/libc/kernel/uapi/` 目录下，这意味着它被 Android 的 Bionic C 库用来定义用户空间程序与内核交互的接口。

**功能列举:**

这个头文件定义了用于 virtio 声卡的各种数据结构和枚举类型，主要功能包括：

1. **配置虚拟声卡:** 定义了 `virtio_snd_config` 结构体，描述了虚拟声卡的基本配置信息，例如支持的 Jack (音频接口) 数量，Stream (音频流) 数量，Chmap (声道映射) 数量和 Control (控制) 数量。
2. **定义虚拟队列 (Virtual Queue):**  枚举类型 `VIRTIO_SND_VQ_*` 定义了用于不同目的的虚拟队列，例如控制命令队列、事件通知队列以及发送和接收音频数据的队列。
3. **定义请求 (Request) 类型:** 枚举类型 `VIRTIO_SND_R_*` 定义了 Guest 操作系统可以向 Host 操作系统发送的各种请求，例如获取 Jack 信息、PCM 流信息、设置 PCM 参数、控制音频流的开始和停止等。
4. **定义事件 (Event) 类型:** 枚举类型 `VIRTIO_SND_EVT_*` 定义了 Host 操作系统可以向 Guest 操作系统发送的各种事件通知，例如 Jack 连接/断开事件、PCM 流周期结束事件、音频数据欠载/过载事件以及控制状态改变事件。
5. **定义数据传输结构:**  定义了各种结构体用于在 Guest 和 Host 之间传递数据，例如 `virtio_snd_hdr` (通用头部)、`virtio_snd_event` (事件数据)、`virtio_snd_pcm_info` (PCM 流信息)、`virtio_snd_ctl_value` (控制值) 等。
6. **定义音频相关的参数和枚举:**  包括音频流的方向 (`VIRTIO_SND_D_OUTPUT`, `VIRTIO_SND_D_INPUT`)、PCM 格式 (`VIRTIO_SND_PCM_FMT_*`)、采样率 (`VIRTIO_SND_PCM_RATE_*`)、声道映射 (`VIRTIO_SND_CHMAP_*`) 以及控制相关的角色 (`VIRTIO_SND_CTL_ROLE_*`)、类型 (`VIRTIO_SND_CTL_TYPE_*`) 和访问权限 (`VIRTIO_SND_CTL_ACCESS_*`)。
7. **定义控制接口:**  定义了与音频设备控制相关的结构体和枚举，允许 Guest 操作系统读取和写入音频设备的各种控制参数，例如音量、静音等。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android 音频框架底层实现的关键部分，特别是在 Android 运行于虚拟机或模拟器中的场景下。

* **Android 虚拟机/模拟器音频支持:** 当 Android 在虚拟机 (例如使用 QEMU 或 VirtualBox) 或模拟器 (例如 Android Studio 的模拟器) 中运行时，底层的音频设备通常是通过 virtio 框架虚拟出来的。这个头文件中定义的结构体和枚举类型就是 Android 系统与虚拟音频设备驱动进行通信的接口。
    * **举例:** 当 Android 应用播放音频时，Android AudioFlinger 服务会通过 HAL (Hardware Abstraction Layer) 与内核驱动交互。如果使用的是 virtio 音频设备，那么 HAL 会使用这里定义的结构体，例如 `virtio_snd_pcm_set_params` 来设置音频流的参数 (采样率、格式等)，并使用 `VIRTIO_SND_VQ_TX` 队列来发送音频数据。当耳机插入或拔出模拟器时，Host 操作系统会发送 `VIRTIO_SND_EVT_JACK_CONNECTED` 或 `VIRTIO_SND_EVT_JACK_DISCONNECTED` 事件，Android 系统接收到这些事件后会更新音频路由。
* **硬件抽象层 (HAL):** Android 的 HAL 层是连接硬件和软件的桥梁。 对于 virtio 音频设备，会有一个对应的 HAL 模块，该模块会解析和使用这个头文件中定义的数据结构，以便与内核中的 virtio 音频驱动进行交互。
* **音频策略管理:** Android 的音频策略服务 (AudioPolicyService) 负责管理音频路由和设备选择。 当系统检测到新的音频设备 (例如通过 virtio 模拟的耳机) 时，它会依赖于底层驱动提供的事件信息，而这些事件信息正是通过这个头文件中定义的结构体传递的。

**libc 函数的功能实现解释:**

这个头文件本身**并不包含 libc 函数的实现**。它只是一个定义了数据结构和枚举类型的头文件，用于描述内核接口。libc 函数的实现位于 Bionic 库的其他源文件中。

然而，这个头文件中定义的接口会被 Bionic 库中与音频相关的系统调用或封装函数所使用。例如，当 Android 应用调用 `open()` 打开一个音频设备节点 (例如 `/dev/snd/pcmC0D0`) 时，或者调用 `ioctl()` 来控制音频设备时，Bionic 库会将这些调用转换为与内核 virtio 音频驱动交互的命令，而这些命令的数据结构就是在这个头文件中定义的。

**涉及 dynamic linker 的功能，对应的 so 布局样本和链接处理过程:**

这个头文件本身**不直接涉及 dynamic linker 的功能**。dynamic linker (在 Android 上是 `linker64` 或 `linker`) 负责在程序启动时加载共享库 (SO 文件) 并解析符号引用。

虽然这个头文件定义了内核接口，但用户空间程序（包括 Bionic 库本身）会通过系统调用与内核交互。  **与 virtio 音频相关的 SO 文件** 可能是那些实现了音频 HAL 模块的库，这些库会被 Android 的音频服务加载。

**SO 布局样本 (假设一个与 virtio 音频相关的 HAL 模块 `audio.r_submix.default.so`):**

```
audio.r_submix.default.so:
    ... (ELF header 等)
    .text:  # 代码段
        ... (HAL 接口函数的实现，例如 openOutputStream, closeOutputStream 等)
    .data:  # 数据段
        ... (全局变量)
    .rodata: # 只读数据段
        ... (字符串常量等)
    .bss:   # 未初始化数据段
        ...
    .symtab: # 符号表
        ... (导出的符号，例如 HAL 接口函数)
    .dynsym: # 动态符号表
        ... (动态链接需要的符号)
    .rel.dyn: # 动态重定位表
        ...
    .rel.plt: # PLT 重定位表
        ...
    .init_array: # 初始化函数指针数组
        ...
    .fini_array: # 析构函数指针数组
        ...
    ...
```

**链接处理过程:**

1. **加载 SO 文件:** 当 Android 音频服务启动或需要加载特定的 HAL 模块时，dynamic linker 会找到对应的 SO 文件 (`audio.r_submix.default.so`) 并将其加载到内存中。
2. **解析依赖:**  Dynamic linker 会检查 SO 文件的依赖关系，并加载其依赖的其他共享库。
3. **符号解析和重定位:** Dynamic linker 会解析 SO 文件中的符号引用 (例如对其他库中函数的调用)，并根据符号表中的信息进行重定位，将这些引用指向正确的内存地址。  对于 HAL 模块，它可能需要解析对 Bionic 库中系统调用封装函数的引用。
4. **执行初始化代码:**  Dynamic linker 会执行 SO 文件中的 `.init_array` 段中指定的初始化函数。

**逻辑推理、假设输入与输出:**

由于这个头文件主要定义数据结构，逻辑推理更多发生在内核驱动和使用这些结构的 Bionic 库代码中。

**假设输入 (以设置 PCM 参数为例):**

假设一个 Android 应用尝试以 44100Hz 采样率、16 位采样格式播放音频。

**对应的数据结构填充 (在 Bionic 库或 HAL 中):**

```c
struct virtio_snd_pcm_set_params params;
params.hdr.code = htole32(VIRTIO_SND_R_PCM_SET_PARAMS); // 设置请求类型
params.hdr.stream_id = htole32(0); // 假设 stream_id 为 0
params.buffer_bytes = htole32(8192); // 假设缓冲区大小
params.period_bytes = htole32(1024); // 假设周期大小
params.features = htole32(0);
params.channels = 2; // 双声道
params.format = VIRTIO_SND_PCM_FMT_S16; // 16 位有符号整数
params.rate = VIRTIO_SND_PCM_RATE_44100; // 44100 Hz
params.padding = 0;
```

**输出 (内核驱动的可能响应):**

内核驱动会解析接收到的 `virtio_snd_pcm_set_params` 结构体，并根据其内容配置虚拟音频设备。如果配置成功，可能会返回一个成功状态码。如果配置失败 (例如不支持该采样率)，可能会返回一个错误状态码 (例如 `VIRTIO_SND_S_NOT_SUPP`)。

**用户或编程常见的使用错误举例:**

1. **字节序错误:**  直接使用主机字节序的数据填充结构体，而没有使用 `htole32()` 或 `htole64()` 等函数转换为小端字节序，可能导致内核驱动解析错误。
    * **错误示例:** `params.hdr.code = VIRTIO_SND_R_PCM_SET_PARAMS;` (应该使用 `htole32()`)
2. **使用不支持的枚举值:**  为 `format` 或 `rate` 字段设置了虚拟音频设备不支持的值，导致内核驱动返回错误。
    * **错误示例:**  设置 `params.rate = 999;` (假设 999 不是有效的 `VIRTIO_SND_PCM_RATE_*` 值)
3. **缓冲区/周期大小设置不合理:**  设置的 `buffer_bytes` 或 `period_bytes` 过小或过大，可能导致音频播放出现问题 (例如卡顿或延迟)。
4. **未正确处理事件通知:**  应用程序没有正确监听和处理来自内核的事件通知 (例如 `VIRTIO_SND_EVT_PCM_XRUN`)，可能导致程序状态与实际音频设备状态不一致。

**Android framework 或 ndk 如何一步步到达这里:**

1. **NDK 应用调用音频 API:**  使用 NDK 开发的 Android 应用可能会使用 OpenSL ES 或 AAudio 等音频 API 来进行音频播放或录制。
2. **Framework 音频服务处理:**  这些 API 的调用最终会传递到 Android Framework 的音频服务 (例如 AudioFlinger)。
3. **HAL 层接口调用:** AudioFlinger 会根据配置选择相应的音频 HAL 模块，并调用 HAL 模块提供的接口函数 (例如 `openOutputStream`, `write`)。
4. **HAL 实现与内核交互:** 对于 virtio 音频设备，对应的 HAL 模块会使用 Bionic 库提供的系统调用封装函数 (例如 `ioctl`)，并将数据组织成这个头文件中定义的结构体格式，发送给内核中的 virtio 音频驱动。
5. **内核 virtio 驱动处理:** 内核中的 virtio 音频驱动接收到来自 Guest 操作系统的请求后，会解析这些结构体，并执行相应的操作 (例如配置音频流、发送/接收音频数据)。

**Frida hook 示例调试步骤:**

可以使用 Frida hook 技术来观察 Android Framework 与内核 virtio 音频驱动之间的交互过程。

**Frida Hook 示例 (Hook `ioctl` 系统调用，监控与 virtio 音频相关的命令):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device()
pid = device.spawn(['com.example.myapp']) # 替换为你的应用包名
process = device.attach(pid)
device.resume(pid)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        // 假设 virtio 音频设备的文件描述符范围或特定值
        if (fd > 100 && request >= 0x40000000 && request <= 0x4000FFFF) {
            console.log("[IOCTL] fd:", fd, "request:", request.toString(16));

            // 可以进一步解析 args[2] 指向的数据，根据 request 类型解析出具体的 virtio_snd 结构体
            // 例如，如果 request 是 VIRTIO_SND_R_PCM_SET_PARAMS，可以读取并打印 virtio_snd_pcm_set_params 结构体的内容
            if (request == 0x4004af01) { // 假设这是 VIRTIO_SND_R_PCM_SET_PARAMS 对应的 ioctl 请求码
                const paramsPtr = ptr(args[2]);
                const code = paramsPtr.readU32();
                const streamId = paramsPtr.add(4).readU32();
                const bufferBytes = paramsPtr.add(8).readU32();
                const periodBytes = paramsPtr.add(12).readU32();
                console.log("  [PCM_SET_PARAMS] code:", code.toString(16), "streamId:", streamId, "bufferBytes:", bufferBytes, "periodBytes:", periodBytes);
            }
        }
    },
    onLeave: function(retval) {
        // console.log("Return value:", retval);
    }
});
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **准备环境:** 安装 Frida 和 Python，确保 USB 调试已启用。
2. **查找目标进程:** 确定你要调试的 Android 应用的进程 ID 或包名。
3. **编写 Frida 脚本:**  如上面的示例，hook `ioctl` 系统调用，并根据文件描述符和 `request` 值判断是否是与 virtio 音频相关的调用。
4. **运行 Frida 脚本:** 使用 `frida -U -f com.example.myapp your_script.py` 运行脚本。
5. **执行音频操作:** 在 Android 应用中执行音频播放或录制等操作。
6. **查看 Frida 输出:**  Frida 会打印出 `ioctl` 调用的相关信息，包括文件描述符、请求码以及传递的数据 (需要根据请求码解析数据结构)。

通过这种方式，可以观察到 Android Framework 或 NDK 如何一步步构建和发送符合 `virtio_snd.handroid` 中定义的数据结构，从而与内核中的 virtio 音频驱动进行交互。

总而言之，`bionic/libc/kernel/uapi/linux/virtio_snd.handroid` 是 Android 系统在虚拟化环境下处理音频的关键接口定义，它架起了用户空间音频服务与内核虚拟音频驱动之间的桥梁。 理解这个文件的内容对于深入了解 Android 音频系统的底层实现至关重要。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/virtio_snd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef VIRTIO_SND_IF_H
#define VIRTIO_SND_IF_H
#include <linux/virtio_types.h>
enum {
  VIRTIO_SND_F_CTLS = 0
};
struct virtio_snd_config {
  __le32 jacks;
  __le32 streams;
  __le32 chmaps;
  __le32 controls;
};
enum {
  VIRTIO_SND_VQ_CONTROL = 0,
  VIRTIO_SND_VQ_EVENT,
  VIRTIO_SND_VQ_TX,
  VIRTIO_SND_VQ_RX,
  VIRTIO_SND_VQ_MAX
};
enum {
  VIRTIO_SND_D_OUTPUT = 0,
  VIRTIO_SND_D_INPUT
};
enum {
  VIRTIO_SND_R_JACK_INFO = 1,
  VIRTIO_SND_R_JACK_REMAP,
  VIRTIO_SND_R_PCM_INFO = 0x0100,
  VIRTIO_SND_R_PCM_SET_PARAMS,
  VIRTIO_SND_R_PCM_PREPARE,
  VIRTIO_SND_R_PCM_RELEASE,
  VIRTIO_SND_R_PCM_START,
  VIRTIO_SND_R_PCM_STOP,
  VIRTIO_SND_R_CHMAP_INFO = 0x0200,
  VIRTIO_SND_R_CTL_INFO = 0x0300,
  VIRTIO_SND_R_CTL_ENUM_ITEMS,
  VIRTIO_SND_R_CTL_READ,
  VIRTIO_SND_R_CTL_WRITE,
  VIRTIO_SND_R_CTL_TLV_READ,
  VIRTIO_SND_R_CTL_TLV_WRITE,
  VIRTIO_SND_R_CTL_TLV_COMMAND,
  VIRTIO_SND_EVT_JACK_CONNECTED = 0x1000,
  VIRTIO_SND_EVT_JACK_DISCONNECTED,
  VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED = 0x1100,
  VIRTIO_SND_EVT_PCM_XRUN,
  VIRTIO_SND_EVT_CTL_NOTIFY = 0x1200,
  VIRTIO_SND_S_OK = 0x8000,
  VIRTIO_SND_S_BAD_MSG,
  VIRTIO_SND_S_NOT_SUPP,
  VIRTIO_SND_S_IO_ERR
};
struct virtio_snd_hdr {
  __le32 code;
};
struct virtio_snd_event {
  struct virtio_snd_hdr hdr;
  __le32 data;
};
struct virtio_snd_query_info {
  struct virtio_snd_hdr hdr;
  __le32 start_id;
  __le32 count;
  __le32 size;
};
struct virtio_snd_info {
  __le32 hda_fn_nid;
};
struct virtio_snd_jack_hdr {
  struct virtio_snd_hdr hdr;
  __le32 jack_id;
};
enum {
  VIRTIO_SND_JACK_F_REMAP = 0
};
struct virtio_snd_jack_info {
  struct virtio_snd_info hdr;
  __le32 features;
  __le32 hda_reg_defconf;
  __le32 hda_reg_caps;
  __u8 connected;
  __u8 padding[7];
};
struct virtio_snd_jack_remap {
  struct virtio_snd_jack_hdr hdr;
  __le32 association;
  __le32 sequence;
};
struct virtio_snd_pcm_hdr {
  struct virtio_snd_hdr hdr;
  __le32 stream_id;
};
enum {
  VIRTIO_SND_PCM_F_SHMEM_HOST = 0,
  VIRTIO_SND_PCM_F_SHMEM_GUEST,
  VIRTIO_SND_PCM_F_MSG_POLLING,
  VIRTIO_SND_PCM_F_EVT_SHMEM_PERIODS,
  VIRTIO_SND_PCM_F_EVT_XRUNS
};
enum {
  VIRTIO_SND_PCM_FMT_IMA_ADPCM = 0,
  VIRTIO_SND_PCM_FMT_MU_LAW,
  VIRTIO_SND_PCM_FMT_A_LAW,
  VIRTIO_SND_PCM_FMT_S8,
  VIRTIO_SND_PCM_FMT_U8,
  VIRTIO_SND_PCM_FMT_S16,
  VIRTIO_SND_PCM_FMT_U16,
  VIRTIO_SND_PCM_FMT_S18_3,
  VIRTIO_SND_PCM_FMT_U18_3,
  VIRTIO_SND_PCM_FMT_S20_3,
  VIRTIO_SND_PCM_FMT_U20_3,
  VIRTIO_SND_PCM_FMT_S24_3,
  VIRTIO_SND_PCM_FMT_U24_3,
  VIRTIO_SND_PCM_FMT_S20,
  VIRTIO_SND_PCM_FMT_U20,
  VIRTIO_SND_PCM_FMT_S24,
  VIRTIO_SND_PCM_FMT_U24,
  VIRTIO_SND_PCM_FMT_S32,
  VIRTIO_SND_PCM_FMT_U32,
  VIRTIO_SND_PCM_FMT_FLOAT,
  VIRTIO_SND_PCM_FMT_FLOAT64,
  VIRTIO_SND_PCM_FMT_DSD_U8,
  VIRTIO_SND_PCM_FMT_DSD_U16,
  VIRTIO_SND_PCM_FMT_DSD_U32,
  VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME
};
enum {
  VIRTIO_SND_PCM_RATE_5512 = 0,
  VIRTIO_SND_PCM_RATE_8000,
  VIRTIO_SND_PCM_RATE_11025,
  VIRTIO_SND_PCM_RATE_16000,
  VIRTIO_SND_PCM_RATE_22050,
  VIRTIO_SND_PCM_RATE_32000,
  VIRTIO_SND_PCM_RATE_44100,
  VIRTIO_SND_PCM_RATE_48000,
  VIRTIO_SND_PCM_RATE_64000,
  VIRTIO_SND_PCM_RATE_88200,
  VIRTIO_SND_PCM_RATE_96000,
  VIRTIO_SND_PCM_RATE_176400,
  VIRTIO_SND_PCM_RATE_192000,
  VIRTIO_SND_PCM_RATE_384000
};
struct virtio_snd_pcm_info {
  struct virtio_snd_info hdr;
  __le32 features;
  __le64 formats;
  __le64 rates;
  __u8 direction;
  __u8 channels_min;
  __u8 channels_max;
  __u8 padding[5];
};
struct virtio_snd_pcm_set_params {
  struct virtio_snd_pcm_hdr hdr;
  __le32 buffer_bytes;
  __le32 period_bytes;
  __le32 features;
  __u8 channels;
  __u8 format;
  __u8 rate;
  __u8 padding;
};
struct virtio_snd_pcm_xfer {
  __le32 stream_id;
};
struct virtio_snd_pcm_status {
  __le32 status;
  __le32 latency_bytes;
};
struct virtio_snd_chmap_hdr {
  struct virtio_snd_hdr hdr;
  __le32 chmap_id;
};
enum {
  VIRTIO_SND_CHMAP_NONE = 0,
  VIRTIO_SND_CHMAP_NA,
  VIRTIO_SND_CHMAP_MONO,
  VIRTIO_SND_CHMAP_FL,
  VIRTIO_SND_CHMAP_FR,
  VIRTIO_SND_CHMAP_RL,
  VIRTIO_SND_CHMAP_RR,
  VIRTIO_SND_CHMAP_FC,
  VIRTIO_SND_CHMAP_LFE,
  VIRTIO_SND_CHMAP_SL,
  VIRTIO_SND_CHMAP_SR,
  VIRTIO_SND_CHMAP_RC,
  VIRTIO_SND_CHMAP_FLC,
  VIRTIO_SND_CHMAP_FRC,
  VIRTIO_SND_CHMAP_RLC,
  VIRTIO_SND_CHMAP_RRC,
  VIRTIO_SND_CHMAP_FLW,
  VIRTIO_SND_CHMAP_FRW,
  VIRTIO_SND_CHMAP_FLH,
  VIRTIO_SND_CHMAP_FCH,
  VIRTIO_SND_CHMAP_FRH,
  VIRTIO_SND_CHMAP_TC,
  VIRTIO_SND_CHMAP_TFL,
  VIRTIO_SND_CHMAP_TFR,
  VIRTIO_SND_CHMAP_TFC,
  VIRTIO_SND_CHMAP_TRL,
  VIRTIO_SND_CHMAP_TRR,
  VIRTIO_SND_CHMAP_TRC,
  VIRTIO_SND_CHMAP_TFLC,
  VIRTIO_SND_CHMAP_TFRC,
  VIRTIO_SND_CHMAP_TSL,
  VIRTIO_SND_CHMAP_TSR,
  VIRTIO_SND_CHMAP_LLFE,
  VIRTIO_SND_CHMAP_RLFE,
  VIRTIO_SND_CHMAP_BC,
  VIRTIO_SND_CHMAP_BLC,
  VIRTIO_SND_CHMAP_BRC
};
#define VIRTIO_SND_CHMAP_MAX_SIZE 18
struct virtio_snd_chmap_info {
  struct virtio_snd_info hdr;
  __u8 direction;
  __u8 channels;
  __u8 positions[VIRTIO_SND_CHMAP_MAX_SIZE];
};
struct virtio_snd_ctl_hdr {
  struct virtio_snd_hdr hdr;
  __le32 control_id;
};
enum {
  VIRTIO_SND_CTL_ROLE_UNDEFINED = 0,
  VIRTIO_SND_CTL_ROLE_VOLUME,
  VIRTIO_SND_CTL_ROLE_MUTE,
  VIRTIO_SND_CTL_ROLE_GAIN
};
enum {
  VIRTIO_SND_CTL_TYPE_BOOLEAN = 0,
  VIRTIO_SND_CTL_TYPE_INTEGER,
  VIRTIO_SND_CTL_TYPE_INTEGER64,
  VIRTIO_SND_CTL_TYPE_ENUMERATED,
  VIRTIO_SND_CTL_TYPE_BYTES,
  VIRTIO_SND_CTL_TYPE_IEC958
};
enum {
  VIRTIO_SND_CTL_ACCESS_READ = 0,
  VIRTIO_SND_CTL_ACCESS_WRITE,
  VIRTIO_SND_CTL_ACCESS_VOLATILE,
  VIRTIO_SND_CTL_ACCESS_INACTIVE,
  VIRTIO_SND_CTL_ACCESS_TLV_READ,
  VIRTIO_SND_CTL_ACCESS_TLV_WRITE,
  VIRTIO_SND_CTL_ACCESS_TLV_COMMAND
};
struct virtio_snd_ctl_info {
  struct virtio_snd_info hdr;
  __le32 role;
  __le32 type;
  __le32 access;
  __le32 count;
  __le32 index;
  __u8 name[44];
  union {
    struct {
      __le32 min;
      __le32 max;
      __le32 step;
    } integer;
    struct {
      __le64 min;
      __le64 max;
      __le64 step;
    } integer64;
    struct {
      __le32 items;
    } enumerated;
  } value;
};
struct virtio_snd_ctl_enum_item {
  __u8 item[64];
};
struct virtio_snd_ctl_iec958 {
  __u8 status[24];
  __u8 subcode[147];
  __u8 pad;
  __u8 dig_subframe[4];
};
struct virtio_snd_ctl_value {
  union {
    __le32 integer[128];
    __le64 integer64[64];
    __le32 enumerated[128];
    __u8 bytes[512];
    struct virtio_snd_ctl_iec958 iec958;
  } value;
};
enum {
  VIRTIO_SND_CTL_EVT_MASK_VALUE = 0,
  VIRTIO_SND_CTL_EVT_MASK_INFO,
  VIRTIO_SND_CTL_EVT_MASK_TLV
};
struct virtio_snd_ctl_event {
  struct virtio_snd_hdr hdr;
  __le16 control_id;
  __le16 mask;
};
#endif

"""

```