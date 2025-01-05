Response:
Let's break down the thought process for analyzing this header file.

**1. Understanding the Context:**

The first and most crucial step is recognizing the context. The prompt clearly states: "This is the source code file for bionic/libc/kernel/uapi/sound/snd_ar_tokens.handroid bionic is Android's C library, math library, and dynamic linker." This immediately tells us:

* **Location:** This file resides within the Android Bionic library, specifically in the kernel's UAPI (User API) for sound. This means it's defining interfaces that user-space applications can use to interact with the kernel's sound subsystem.
* **Purpose:** The filename `snd_ar_tokens.handroid` suggests it deals with "tokens" related to the "Android Routing" (AR) aspect of sound. The `.handroid` likely signifies Android-specific extensions or configurations.

**2. Initial Scan for Structure and Content:**

Next, quickly scan the file for its structural elements:

* **Header Guards:** The `#ifndef __SND_AR_TOKENS_H__` and `#define __SND_AR_TOKENS_H__` are standard header guards, preventing multiple inclusions. This is a common practice in C/C++ and a good sign.
* **Macros (#define):** The majority of the content consists of `#define` macros. This indicates that the file is defining constants, likely for use in data structures or function arguments.
* **Enums:** There's a single `enum ar_event_types`. Enums define a set of named integer constants, useful for representing a limited set of options.
* **Comments:** The initial comment block is important, explaining the file is auto-generated and points to the source repository. This suggests that manual modification is discouraged.

**3. Grouping and Categorizing the Macros:**

Now, start grouping the macros based on their prefixes and apparent purpose. This is where pattern recognition comes in:

* **`APM_...`:**  Many macros start with `APM_`. This likely stands for "Audio Policy Manager" or something similar, a core component of Android's audio system. Sub-prefixes like `APM_SUB_GRAPH_`, `APM_CONTAINER_CAP_ID_`, `APM_CONT_GRAPH_POS_`, and `APM_PROC_DOMAIN_ID_` further refine the categories.
* **`PCM_...`:** These are standard PCM (Pulse-Code Modulation) format definitions, common in audio.
* **`AR_I2S_...`:**  Likely related to I2S (Inter-IC Sound), a common digital audio interface.
* **`AR_EVENT_...`:**  Clearly defines event types related to the "AR" system.
* **`SND_SOC_AR_TPLG_...`:**  The `SND_SOC` prefix often indicates the "Sound Open Firmware (SOF)" or a similar sound subsystem. `TPLG` likely stands for "Topology."
* **`AR_TKN_...`:**  The core of the file. These macros define "tokens," likely used to identify specific parameters or properties in the AR system. The sub-prefixes like `AR_TKN_DAI_INDEX`, `AR_TKN_U32_...` give hints about their data type and purpose.

**4. Inferring Functionality Based on Names:**

With the categories established, start making educated guesses about the meaning of each macro:

* **`APM_SUB_GRAPH_PERF_MODE_LOW_POWER`**:  Suggests different power consumption modes for audio sub-graphs.
* **`APM_SUB_GRAPH_DIRECTION_TX`**: Indicates the direction of audio flow (Transmit).
* **`APM_CONTAINER_CAP_ID_PP`**:  Likely identifies a "Post-Processing" capability of an audio container.
* **`APM_PROC_DOMAIN_ID_MDSP`**:  Indicates processing on a "Multimedia Digital Signal Processor."
* **`AR_TKN_U32_SUB_GRAPH_INSTANCE_ID`**: A unique identifier for a sub-graph instance.
* **`AR_TKN_U32_MODULE_FMT_SAMPLE_RATE`**:  Specifies the sample rate of an audio module.

**5. Connecting to Android Functionality:**

Now, think about how these tokens relate to Android's audio system:

* **Audio Routing:** The "AR" in the filename is a strong clue. This file likely defines the building blocks for configuring how audio streams are routed between different hardware and software components in Android.
* **Audio Policy Manager:** The `APM_` prefixes strongly suggest interaction with the Audio Policy Manager, which is responsible for making routing decisions.
* **Hardware Abstraction Layer (HAL):** These tokens are likely used in the audio HAL implementations to communicate with the underlying audio hardware.
* **NDK:**  While this is a kernel UAPI header, the constants defined here are likely used by the NDK's audio APIs (e.g., AAudio) to configure audio streams and devices.

**6. Considering Dynamic Linking (Even if Not Directly Present):**

The prompt specifically asks about the dynamic linker. While this header file *itself* doesn't involve dynamic linking, the *usage* of the constants defined here often does. Think about how these constants might be used in shared libraries:

* **Shared Library Usage:** The audio HAL implementations are typically shared libraries (`.so` files). These libraries would include this header file and use these constants to interact with the kernel.
* **Linking Process:** When an application using the NDK audio APIs loads, the dynamic linker loads the necessary audio HAL libraries. These libraries would have been compiled with the definitions from this header.

**7. Addressing Specific Requests (libc, Examples, Frida):**

* **libc Functions:** This file *defines constants*, not libc functions. So, the detailed explanation of libc function implementation isn't directly applicable *to this file*. However, acknowledge that these constants are *used by* libc functions related to audio.
* **Examples:** Construct simple examples showing how these constants might be used (e.g., setting a performance mode, specifying a data format).
* **Frida Hooking:**  Think about *where* these constants are used in user-space. The audio HAL libraries are a prime target. Show a basic Frida example of hooking a function in an audio HAL library that likely uses these constants.

**8. Iterative Refinement and Clarity:**

Review the analysis, ensuring it's clear, well-organized, and addresses all parts of the prompt. Use precise terminology and avoid jargon where possible. Structure the answer logically with headings and bullet points.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have focused too much on the literal contents of the file and missed the broader context of how these constants are *used*. The prompt about the dynamic linker forced me to think beyond just the `#define` statements and consider the role of shared libraries and the linking process in making these constants available to user-space code. Similarly, while the file isn't about libc *functions*, it's essential to connect these constants to the *overall* audio functionality provided by libc.

这是一个定义了音频路由（Audio Routing, AR）相关令牌（tokens）的C头文件，主要用于 Android 音频子系统。它定义了一系列宏常量和枚举，用于在不同的音频组件之间传递和识别配置信息。

**功能列举：**

1. **定义音频拓扑结构元素：**  文件定义了描述音频处理流程中各种组件的常量，例如子图（Sub-Graph）、容器（Container）、模块（Module）等。
2. **定义音频组件的属性：**  例如性能模式（Performance Mode）、数据流方向（Direction）、功能ID（Capability ID）、位置（Graph Position）、处理域（Process Domain）等。
3. **定义音频数据格式：**  例如交织（Interleaved）、非交织打包（Deinterleaved Packed）、非交织解包（Deinterleaved Unpacked）。
4. **定义音频事件类型：**  目前只定义了一个 `AR_PGA_DAPM_EVENT`，可能用于表示与可编程增益放大器（PGA）和动态音频电源管理（DAPM）相关的事件。
5. **定义用于标识特定参数的令牌（Tokens）：** 以 `AR_TKN_` 开头的宏定义，用于指示后续数据的含义，例如子图实例ID、性能模式、方向、容器能力ID、模块ID、端口ID、数据格式、采样率等。

**与 Android 功能的关系及举例说明：**

这个文件是 Android 音频框架底层基础设施的一部分，直接参与了音频策略管理（Audio Policy Management）和音频路由的配置。

**举例说明：**

* **音频策略管理 (Audio Policy Management, APM):**
    * `APM_SUB_GRAPH_PERF_MODE_LOW_POWER` 和 `APM_SUB_GRAPH_PERF_MODE_LOW_LATENCY`:  APM 可以使用这些常量来配置音频处理子图的性能模式，以平衡功耗和延迟。例如，在播放背景音乐时可能选择低功耗模式，而在玩游戏或进行语音通话时可能选择低延迟模式。
    * `APM_SUB_GRAPH_DIRECTION_TX` 和 `APM_SUB_GRAPH_DIRECTION_RX`: APM 使用这些常量来指定音频子图处理的是发送（TX，例如录音）还是接收（RX，例如播放）的音频流。
    * `APM_SUB_GRAPH_SID_AUDIO_PLAYBACK`, `APM_SUB_GRAPH_SID_AUDIO_RECORD`, `APM_SUB_GRAPH_SID_VOICE_CALL`: 这些常量标识了音频子图所属的场景，APM 可以根据不同的场景应用不同的路由策略。

* **音频路由 (Audio Routing):**
    * `AR_TKN_U32_MODULE_SRC_OP_PORT_ID` 和 `AR_TKN_U32_MODULE_DST_IN_PORT_ID`:  这些令牌用于描述音频模块之间的连接，指定源模块的输出端口和目标模块的输入端口。Android 音频框架使用这些信息来构建音频处理管道，将音频数据从一个模块路由到另一个模块。
    * `AR_TKN_U32_MODULE_FMT_SAMPLE_RATE`, `AR_TKN_U32_MODULE_FMT_BIT_DEPTH`, `AR_TKN_U32_MODULE_FMT_INTERLEAVE`: 这些令牌用于指定音频模块处理的数据的格式，包括采样率、位深度和交织方式。这确保了不同音频处理模块之间的数据兼容性。

**详细解释每一个 libc 函数的功能是如何实现的:**

**需要明确的是，这个头文件本身 *并没有定义任何 libc 函数*。** 它定义的是宏常量和枚举类型，这些常量会被 Android 音频相关的 libc 函数、内核驱动程序和 HAL (Hardware Abstraction Layer) 使用。

例如，`open()`, `ioctl()`, `read()`, `write()` 等 libc 函数可能会在 Android 音频系统的实现中使用，但这个头文件定义的常量会作为 `ioctl()` 的参数，或者用于构建传递给这些函数的结构体。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及 dynamic linker 的功能。然而，其中定义的常量会被编译到不同的共享库 (`.so` 文件) 中，这些共享库会在运行时被 dynamic linker 加载和链接。

**so 布局样本：**

假设有一个名为 `libaudiohal.so` 的音频 HAL 库，它使用了这个头文件中定义的常量。

```
libaudiohal.so:
    .text          # 代码段
        ... // 实现音频 HAL 功能的代码，可能会用到 AR_TKN_... 等常量
    .rodata        # 只读数据段
        ... // 可能会包含一些硬编码的常量值
    .data          # 可读写数据段
        ...
    .bss           # 未初始化数据段
        ...
    .symtab        # 符号表
        ... // 包含导出的符号，例如音频 HAL 的接口函数
    .strtab        # 字符串表
        ...
    .dynsym        # 动态符号表
        ... // 包含动态链接需要的符号信息
    .dynstr        # 动态字符串表
        ...
    .dynamic       # 动态链接信息
        ... // 包含依赖的其他共享库信息
```

**链接的处理过程：**

1. **编译时：**  当编译 `libaudiohal.so` 的源代码时，编译器会读取 `snd_ar_tokens.handroid` 头文件，将其中定义的宏常量的值替换到代码中。
2. **链接时：** 静态链接器会将编译后的目标文件链接成共享库。此时，头文件中定义的常量已经作为数值硬编码在代码或数据段中。
3. **运行时：**
    * 当一个进程（例如 Android 的 MediaServer 或应用程序进程）需要使用音频 HAL 时，它会尝试加载 `libaudiohal.so`。
    * Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责查找和加载 `libaudiohal.so` 及其依赖的其他共享库。
    * Dynamic linker 会解析 `libaudiohal.so` 的 `.dynamic` 段，找到所需的动态符号和依赖的库。
    * 如果 `libaudiohal.so` 依赖于其他共享库（例如 libc），dynamic linker 也会加载这些依赖库。
    * Dynamic linker 会进行符号重定位，将 `libaudiohal.so` 中引用的外部符号（例如 libc 中的函数）地址解析为实际的内存地址。
    * 加载完成后，进程就可以调用 `libaudiohal.so` 中导出的函数，这些函数内部可能使用了在编译时嵌入的 `snd_ar_tokens.handroid` 中定义的常量。

**逻辑推理，假设输入与输出:**

这个头文件主要定义常量，没有直接的逻辑推理过程。但是，在使用这些常量的音频处理流程中，会涉及逻辑推理。

**假设输入：**  APM 接收到用户请求播放音乐的事件。

**逻辑推理过程：**

1. APM 根据当前系统状态（例如是否有其他音频流正在播放）和用户配置，决定音频流的路由策略。
2. APM 可能会使用 `APM_SUB_GRAPH_SID_AUDIO_PLAYBACK` 来标识当前是音频播放场景。
3. APM 会根据设备的音频拓扑配置，选择合适的音频处理子图。
4. APM 会使用 `AR_TKN_U32_MODULE_SRC_OP_PORT_ID` 和 `AR_TKN_U32_MODULE_DST_IN_PORT_ID` 等令牌，配置音频模块之间的连接，构建音频处理管道。
5. APM 可能会根据设备的性能需求，选择合适的性能模式，例如使用 `APM_SUB_GRAPH_PERF_MODE_LOW_POWER` 来节省电量。
6. APM 将配置信息传递给音频 HAL。

**输出：** 音频数据按照配置好的路径进行处理，最终输出到扬声器或耳机。

**涉及用户或者编程常见的使用错误，请举例说明:**

由于这个文件是内核 UAPI 的一部分，普通用户或应用开发者通常不会直接操作这些常量。这些常量主要在 Android 系统框架和 HAL 层使用。

**编程常见的使用错误（主要发生在 HAL 或系统框架开发中）：**

1. **使用了错误的令牌值：**  如果在配置音频路由或模块属性时使用了错误的 `AR_TKN_` 值，会导致配置信息无法正确解析，从而导致音频功能异常。例如，将表示采样率的令牌用于表示位深度。
2. **传递了超出范围的数值：** 虽然头文件定义了令牌，但并没有定义这些令牌对应值的有效范围。如果传递了超出硬件或软件能力范围的值，可能会导致错误。例如，设置一个硬件不支持的采样率。
3. **不一致的配置：**  如果在配置音频处理管道时，各个模块的格式参数（采样率、位深度、交织方式）不一致，会导致数据处理错误或崩溃。
4. **忽略了令牌的上下文：**  一些令牌可能只有在特定的上下文下才有意义。例如，某些模块特定的配置令牌只能在配置该模块时使用。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `snd_ar_tokens.handroid` 的步骤：**

1. **应用请求音频播放：**  一个 Android 应用通过 MediaSession 或 AudioManager 等 API 请求播放音频。
2. **AudioService 处理请求：** Android Framework 的 AudioService 接收到请求，并开始处理音频策略。
3. **AudioPolicyService 进行策略决策：** AudioService 将请求转发给 AudioPolicyService，后者根据当前系统状态、设备配置和应用请求，做出音频路由决策。
4. **AudioPolicyManager 交互：** AudioPolicyService 与 AudioPolicyManager (APM) 交互，APM 负责维护音频设备的拓扑结构和配置信息。在进行路由决策时，APM 可能会参考与 `snd_ar_tokens.handroid` 中定义的常量相关的配置信息。
5. **HAL 调用：** APM 将路由决策传递给相应的音频 HAL 实现。HAL 是连接 Android Framework 和底层音频驱动的桥梁。
6. **Kernel 驱动交互：** 音频 HAL 通过 ioctl 等系统调用与内核音频驱动进行交互，配置音频硬件。在与内核驱动交互时，HAL 可能会使用 `snd_ar_tokens.handroid` 中定义的常量来构建传递给内核的控制命令或数据结构。

**NDK 到达 `snd_ar_tokens.handroid` 的步骤：**

1. **NDK 应用使用 AAudio 或 OpenSL ES API：** NDK 应用可以使用 AAudio 或 OpenSL ES 等 API 进行音频输入/输出。
2. **AAudio 或 OpenSL ES 实现：** 这些 API 的底层实现最终会调用到 Android Framework 的 AudioService 或直接与 HAL 层交互。
3. **后续步骤与 Framework 类似：**  从这里开始，后续的步骤与 Android Framework 到达该文件的步骤类似，涉及到 AudioPolicyService、APM 和 HAL 的交互，最终可能会使用到 `snd_ar_tokens.handroid` 中定义的常量。

**Frida Hook 示例调试步骤：**

假设我们要 hook 音频 HAL 中一个设置音频模块参数的函数，该函数可能会用到 `AR_TKN_U32_MODULE_FMT_SAMPLE_RATE` 常量。

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except Exception as e:
    print(f"Error attaching to process: {e}")
    sys.exit(1)

script_code = """
console.log("Script loaded");

// 假设 libaudiohal.so 中有一个名为 setModuleParameter 的函数
// 并且它的参数中使用了 AR_TKN_U32_MODULE_FMT_SAMPLE_RATE

const AR_TKN_U32_MODULE_FMT_SAMPLE_RATE = 254; // 从头文件中获取

// 找到 libaudiohal.so 的基地址
const audioHalModule = Process.getModuleByName("libaudiohal.so");
if (audioHalModule) {
    console.log("Found libaudiohal.so at:", audioHalModule.base);

    // 假设 setModuleParameter 函数的签名是 void setModuleParameter(int token, int value)
    // 需要根据实际情况修改函数名和参数类型
    const setModuleParameterAddress = audioHalModule.base.add(0xXXXX); // 替换为 setModuleParameter 函数的实际偏移地址

    if (setModuleParameterAddress) {
        Interceptor.attach(setModuleParameterAddress, {
            onEnter: function(args) {
                const token = args[0].toInt();
                const value = args[1].toInt();
                console.log("setModuleParameter called");
                if (token === AR_TKN_U32_MODULE_FMT_SAMPLE_RATE) {
                    console.log("  Token: AR_TKN_U32_MODULE_FMT_SAMPLE_RATE, Value:", value);
                } else {
                    console.log("  Token:", token, ", Value:", value);
                }
            }
        });
        console.log("Hooked setModuleParameter");
    } else {
        console.log("setModuleParameter address not found");
    }
} else {
    console.log("libaudiohal.so not found");
}
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例说明：**

1. **导入 Frida 库。**
2. **指定要 hook 的应用包名。**
3. **定义 `on_message` 回调函数，用于处理 Frida 脚本发送的消息。**
4. **连接到 USB 设备上的目标应用进程。**
5. **构造 Frida 脚本：**
    * 在脚本中，首先定义了 `AR_TKN_U32_MODULE_FMT_SAMPLE_RATE` 常量的值，确保与头文件中的定义一致。
    * 使用 `Process.getModuleByName()` 获取 `libaudiohal.so` 的基地址。
    * **需要找到 `setModuleParameter` 函数在 `libaudiohal.so` 中的实际偏移地址。** 这可以通过反汇编 `libaudiohal.so` 或使用其他工具来完成。
    * 使用 `Interceptor.attach()` hook `setModuleParameter` 函数。
    * 在 `onEnter` 回调函数中，获取函数的参数值，并判断第一个参数是否等于 `AR_TKN_U32_MODULE_FMT_SAMPLE_RATE`。
    * 打印函数的调用信息和参数值。
6. **创建并加载 Frida 脚本。**
7. **保持脚本运行，直到手动停止。**

**调试步骤：**

1. 运行包含音频播放功能的 Android 应用。
2. 运行 Frida hook 脚本。
3. 当应用进行音频播放时，Frida 脚本会拦截对 `setModuleParameter` 函数的调用，并打印出相关的参数信息，包括是否使用了 `AR_TKN_U32_MODULE_FMT_SAMPLE_RATE` 常量以及设置的采样率值。

**注意：**

* 上述 Frida 脚本示例中的 `setModuleParameterAddress` 需要替换为实际的函数地址。
* 音频 HAL 的实现和函数名可能因设备和 Android 版本而异，需要根据实际情况进行调整。
* Hook 系统级别的库需要 root 权限。

通过 Frida hook，你可以动态地观察 Android 系统在处理音频请求时，是否以及如何使用了 `snd_ar_tokens.handroid` 中定义的常量，从而深入理解 Android 音频系统的运行机制。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/sound/snd_ar_tokens.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __SND_AR_TOKENS_H__
#define __SND_AR_TOKENS_H__
#define APM_SUB_GRAPH_PERF_MODE_LOW_POWER 0x1
#define APM_SUB_GRAPH_PERF_MODE_LOW_LATENCY 0x2
#define APM_SUB_GRAPH_DIRECTION_TX 0x1
#define APM_SUB_GRAPH_DIRECTION_RX 0x2
#define APM_SUB_GRAPH_SID_AUDIO_PLAYBACK 0x1
#define APM_SUB_GRAPH_SID_AUDIO_RECORD 0x2
#define APM_SUB_GRAPH_SID_VOICE_CALL 0x3
#define APM_CONTAINER_CAP_ID_PP 0x1
#define APM_CONTAINER_CAP_ID_CD 0x2
#define APM_CONTAINER_CAP_ID_EP 0x3
#define APM_CONTAINER_CAP_ID_OLC 0x4
#define APM_CONT_GRAPH_POS_STREAM 0x1
#define APM_CONT_GRAPH_POS_PER_STR_PER_DEV 0x2
#define APM_CONT_GRAPH_POS_STR_DEV 0x3
#define APM_CONT_GRAPH_POS_GLOBAL_DEV 0x4
#define APM_PROC_DOMAIN_ID_MDSP 0x1
#define APM_PROC_DOMAIN_ID_ADSP 0x2
#define APM_PROC_DOMAIN_ID_SDSP 0x4
#define APM_PROC_DOMAIN_ID_CDSP 0x5
#define PCM_INTERLEAVED 1
#define PCM_DEINTERLEAVED_PACKED 2
#define PCM_DEINTERLEAVED_UNPACKED 3
#define AR_I2S_WS_SRC_EXTERNAL 0
#define AR_I2S_WS_SRC_INTERNAL 1
enum ar_event_types {
  AR_EVENT_NONE = 0,
  AR_PGA_DAPM_EVENT
};
#define SND_SOC_AR_TPLG_FE_BE_GRAPH_CTL_MIX 256
#define SND_SOC_AR_TPLG_VOL_CTL 257
#define AR_TKN_DAI_INDEX 1
#define AR_TKN_U32_SUB_GRAPH_INSTANCE_ID 2
#define AR_TKN_U32_SUB_GRAPH_PERF_MODE 3
#define AR_TKN_U32_SUB_GRAPH_DIRECTION 4
#define AR_TKN_U32_SUB_GRAPH_SCENARIO_ID 5
#define AR_TKN_U32_CONTAINER_INSTANCE_ID 100
#define AR_TKN_U32_CONTAINER_CAPABILITY_ID 101
#define AR_TKN_U32_CONTAINER_STACK_SIZE 102
#define AR_TKN_U32_CONTAINER_GRAPH_POS 103
#define AR_TKN_U32_CONTAINER_PROC_DOMAIN 104
#define AR_TKN_U32_MODULE_ID 200
#define AR_TKN_U32_MODULE_INSTANCE_ID 201
#define AR_TKN_U32_MODULE_MAX_IP_PORTS 202
#define AR_TKN_U32_MODULE_MAX_OP_PORTS 203
#define AR_TKN_U32_MODULE_IN_PORTS 204
#define AR_TKN_U32_MODULE_OUT_PORTS 205
#define AR_TKN_U32_MODULE_SRC_OP_PORT_ID 206
#define AR_TKN_U32_MODULE_DST_IN_PORT_ID 207
#define AR_TKN_U32_MODULE_SRC_INSTANCE_ID 208
#define AR_TKN_U32_MODULE_DST_INSTANCE_ID 209
#define AR_TKN_U32_MODULE_SRC_OP_PORT_ID1 210
#define AR_TKN_U32_MODULE_DST_IN_PORT_ID1 211
#define AR_TKN_U32_MODULE_DST_INSTANCE_ID1 212
#define AR_TKN_U32_MODULE_SRC_OP_PORT_ID2 213
#define AR_TKN_U32_MODULE_DST_IN_PORT_ID2 214
#define AR_TKN_U32_MODULE_DST_INSTANCE_ID2 215
#define AR_TKN_U32_MODULE_SRC_OP_PORT_ID3 216
#define AR_TKN_U32_MODULE_DST_IN_PORT_ID3 217
#define AR_TKN_U32_MODULE_DST_INSTANCE_ID3 218
#define AR_TKN_U32_MODULE_SRC_OP_PORT_ID4 219
#define AR_TKN_U32_MODULE_DST_IN_PORT_ID4 220
#define AR_TKN_U32_MODULE_DST_INSTANCE_ID4 221
#define AR_TKN_U32_MODULE_SRC_OP_PORT_ID5 222
#define AR_TKN_U32_MODULE_DST_IN_PORT_ID5 223
#define AR_TKN_U32_MODULE_DST_INSTANCE_ID5 224
#define AR_TKN_U32_MODULE_SRC_OP_PORT_ID6 225
#define AR_TKN_U32_MODULE_DST_IN_PORT_ID6 226
#define AR_TKN_U32_MODULE_DST_INSTANCE_ID6 227
#define AR_TKN_U32_MODULE_SRC_OP_PORT_ID7 228
#define AR_TKN_U32_MODULE_DST_IN_PORT_ID7 229
#define AR_TKN_U32_MODULE_DST_INSTANCE_ID7 230
#define AR_TKN_U32_MODULE_HW_IF_IDX 250
#define AR_TKN_U32_MODULE_HW_IF_TYPE 251
#define AR_TKN_U32_MODULE_FMT_INTERLEAVE 252
#define AR_TKN_U32_MODULE_FMT_DATA 253
#define AR_TKN_U32_MODULE_FMT_SAMPLE_RATE 254
#define AR_TKN_U32_MODULE_FMT_BIT_DEPTH 255
#define AR_TKN_U32_MODULE_SD_LINE_IDX 256
#define AR_TKN_U32_MODULE_WS_SRC 257
#define AR_TKN_U32_MODULE_FRAME_SZ_FACTOR 258
#define AR_TKN_U32_MODULE_LOG_CODE 259
#define AR_TKN_U32_MODULE_LOG_TAP_POINT_ID 260
#define AR_TKN_U32_MODULE_LOG_MODE 261
#endif

"""

```