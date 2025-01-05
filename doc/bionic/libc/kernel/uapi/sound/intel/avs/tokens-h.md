Response:
Let's break down the thought process for answering the request about the `tokens.handroid` file.

**1. Understanding the Context:**

The first step is recognizing the context. The prompt explicitly states:

* **File Location:** `bionic/libc/kernel/uapi/sound/intel/avs/tokens.handroid`
* **Purpose:**  Configuration tokens for Intel AVS (Audio Virtualization System) in the Android kernel's UAPI (User-space API).
* **Bionic:**  Android's C library, math library, and dynamic linker.

This immediately tells us that the file isn't directly involved in general-purpose C library functions or dynamic linking, but rather a specific kernel interface related to audio hardware. However, being part of Bionic's `uapi` means it defines constants used by user-space programs.

**2. Initial Analysis of the File Contents:**

Scanning the file, the most obvious thing is the `enum avs_tplg_token`. This is a C enumeration defining a set of symbolic constants. The names of the constants (`AVS_TKN_*`) strongly suggest they represent different types of configuration parameters or attributes related to audio processing.

* **Keywords:**  "MANIFEST", "LIBRARY", "AFMT" (Audio Format), "MODCFG" (Module Configuration), "PPLCFG" (Pipeline Configuration), "BINDING", "PATH", "PIN", "KCONTROL", "INIT_CONFIG" are prominent. These give clues about the structure and components of the AVS system being configured.
* **Data Types:**  The suffixes like `_STRING`, `_U32`, `_U8`, `_S32` indicate the data type associated with each token. This is important for understanding how these tokens are used in data structures or function arguments.

**3. Inferring Functionality:**

Based on the token names, we can start inferring the functionality:

* **Manifest:**  Information about the audio processing topology itself (name, version, number of libraries, etc.).
* **Library:**  Reusable components or modules.
* **Audio Format (AFMT):**  Describes the properties of audio streams (sample rate, bit depth, number of channels, etc.).
* **Module Configuration (MODCFG):**  Settings for individual audio processing modules (input/output buffer sizes, specific module types, etc.).
* **Pipeline Configuration (PPLCFG):**  Defines the overall audio processing pipelines (priority, size, triggering conditions).
* **Binding:**  Connections between different components (modules, pipelines).
* **Path:**  Routes for audio data flow.
* **Pin:**  Input/output points of modules.
* **KControl:**  Kernel controls (likely related to ALSA's kcontrol framework for managing hardware).
* **Initialization Configuration (INIT_CONFIG):**  Parameters to set up modules during initialization.

**4. Relating to Android:**

The "handroid" suffix and the file's location within the Android Bionic tree strongly suggest it's specifically for Android. The AVS system is likely used for advanced audio processing features on Android devices, potentially involving:

* **Sound Effects:** Implementing various audio effects.
* **Voice Processing:** Noise cancellation, echo cancellation, voice recognition.
* **Multi-Channel Audio:** Handling surround sound or spatial audio.
* **Low-Power Audio:** Optimizations for battery life.

**5. Addressing Specific Questions in the Prompt:**

* **List Functionality:** This directly maps to the inferred functionalities based on the token names.
* **Relationship to Android:** The explanation about advanced audio features addresses this.
* **libc Function Implementation:**  This file *doesn't* define libc functions. It defines *constants*. It's important to clarify this. The *use* of these constants might involve libc functions (e.g., `open`, `ioctl`), but the file itself doesn't implement them.
* **Dynamic Linker:**  This file is a header file defining constants. It's not directly involved in dynamic linking. However, user-space libraries using these constants would be linked dynamically. Therefore, a basic explanation of dynamic linking and a simple `dlopen`/`dlsym` example is relevant to show *how* user-space code might interact with components related to this configuration.
* **Logical Reasoning/Input-Output:**  Since it's a header file defining constants, direct input/output examples aren't applicable. However, explaining how these tokens would be used *within* a configuration structure is a good way to illustrate their purpose.
* **User/Programming Errors:**  Focus on common mistakes when using these constants: typos, incorrect values, inconsistent configurations.
* **Android Framework/NDK Path:**  Tracing the flow from high-level Android audio APIs down to the kernel driver level is crucial. Mentioning the AudioFlinger, HAL, and kernel drivers provides the necessary context.
* **Frida Hook:**  Provide an example of how to hook functions that might use these constants, focusing on the `ioctl` system call which is likely how user-space interacts with the kernel driver.

**6. Structuring the Answer:**

Organize the information logically, addressing each point in the prompt. Use clear headings and examples. Emphasize the distinction between the header file defining constants and the actual code that uses them.

**7. Refinement and Language:**

Use clear and concise language. Avoid jargon where possible, or explain it when necessary. Ensure the response is in Chinese as requested. Review and refine the answer for accuracy and completeness. For instance, initially, I might have thought the file *directly* uses libc functions, but upon closer inspection, it becomes clear it only *defines constants* that other code might use in conjunction with libc functions. This kind of self-correction is important.
这个文件 `bionic/libc/kernel/uapi/sound/intel/avs/tokens.handroid` 是 Android 系统中 Bionic C 库的一部分，它定义了一组用于 Intel AVS (Audio Virtualization System) 的令牌（tokens）。这些令牌是枚举类型 `avs_tplg_token` 的成员，用于在用户空间和内核空间之间传递关于音频拓扑结构配置的信息。由于它位于 `uapi` 目录下，表明它是用户空间可访问的 API，用于与内核中的 AVS 驱动进行交互。

**它的功能：**

这个文件的主要功能是定义了一系列常量，这些常量代表了 Intel AVS 音频处理拓扑配置中的各种元素和属性。这些令牌可以被用来：

1. **标识音频拓扑结构的各个部分：** 例如，`AVS_TKN_MANIFEST_NAME_STRING` 代表拓扑清单的名称，`AVS_TKN_LIBRARY_ID_U32` 代表一个库的 ID。
2. **描述音频流的格式：** 例如，`AVS_TKN_AFMT_SAMPLE_RATE_U32` 代表采样率，`AVS_TKN_AFMT_BIT_DEPTH_U32` 代表位深。
3. **配置音频处理模块：** 例如，`AVS_TKN_MODCFG_BASE_ID_U32` 代表基本模块配置的 ID，`AVS_TKN_MODCFG_EXT_TYPE_UUID` 代表扩展模块配置的类型 UUID。
4. **定义音频处理管道：** 例如，`AVS_TKN_PPLCFG_ID_U32` 代表管道配置的 ID，`AVS_TKN_PPLCFG_PRIORITY_U8` 代表管道的优先级。
5. **指定组件之间的连接：** 例如，`AVS_TKN_BINDING_MOD_ID_U32` 和 `AVS_TKN_BINDING_MOD_PIN_U8` 代表连接的模块 ID 和引脚号。
6. **配置初始化参数：** 例如，`AVS_TKN_INIT_CONFIG_ID_U32` 代表初始化配置的 ID，`AVS_TKN_INIT_CONFIG_PARAM_U8` 代表初始化参数。

**与 Android 功能的关系及举例说明：**

这个文件直接关系到 Android 设备上的音频功能，特别是那些使用 Intel AVS 硬件加速的设备。AVS 负责处理音频数据的路由、格式转换、效果处理等。

**举例说明：**

假设一个 Android 应用需要播放一段音频。Android 音频框架（AudioFlinger）可能会通过 HAL (Hardware Abstraction Layer) 与底层的音频驱动交互。如果设备使用了 Intel AVS，那么 HAL 可能会使用这里定义的令牌来配置 AVS 的音频处理流程。

例如，当应用请求以特定的采样率播放音频时，HAL 可能会构造一个包含 `AVS_TKN_AFMT_SAMPLE_RATE_U32` 令牌的消息，并将其传递给内核中的 AVS 驱动，指示驱动将音频流配置为指定的采样率。

另一个例子是，当使用特定的音频效果（例如均衡器或混响器）时，Android framework 可能会通过 HAL 配置 AVS 中的相应音频处理模块。这可能涉及到使用 `AVS_TKN_MODCFG_EXT_TYPE_UUID` 来指定模块的类型，并使用其他的 `AVS_TKN_MODCFG_*` 令牌来设置模块的参数。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个文件中定义的是常量（枚举类型），而不是 libc 函数。因此，没有 libc 函数的实现细节可以解释。这个文件是定义数据结构的组成部分，而不是实现具体的操作。用户空间的程序会使用这些常量来构造数据结构，然后通过系统调用（例如 `ioctl`）传递给内核驱动。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个文件本身并不直接涉及 dynamic linker 的功能。它是一个头文件，定义了内核接口的常量。然而，用户空间的库或服务如果需要与使用 Intel AVS 的内核驱动交互，可能会包含这个头文件，并且自身会被动态链接。

**so 布局样本：**

假设有一个名为 `libavs_client.so` 的动态链接库，它使用了 `tokens.handroid` 中定义的常量来与 AVS 驱动交互。其布局可能如下：

```
libavs_client.so:
    .text           # 代码段
        - 函数1
        - 函数2
        ...
    .rodata         # 只读数据段
        - 字符串常量
        - 使用 tokens.handroid 中定义的常量
    .data           # 可读写数据段
        - 全局变量
    .bss            # 未初始化数据段
        - 未初始化全局变量
    .dynamic        # 动态链接信息
        - 依赖的库 (例如 libc.so)
        - 符号表
        - 重定位表
    ...
```

**链接的处理过程：**

1. **编译时：** 当编译 `libavs_client.c` 等源文件时，编译器会读取 `tokens.handroid` 头文件，将枚举常量的值内联到代码中。
2. **链接时：** 静态链接器会将 `libavs_client.o` 等目标文件链接成 `libavs_client.so`。它会处理符号引用，并生成动态链接所需的元数据。
3. **运行时：** 当 Android 系统启动或者应用启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载 `libavs_client.so` 及其依赖的库（如 `libc.so`）。
4. **重定位：** dynamic linker 会根据 `.dynamic` 段中的信息，调整 `libavs_client.so` 中需要重定位的符号的地址，使其指向正确的内存位置。
5. **符号解析：** 如果 `libavs_client.so` 依赖于其他动态库提供的符号，dynamic linker 会在加载时解析这些符号。

在这个特定的例子中，由于 `tokens.handroid` 定义的是常量，不太可能直接引起复杂的动态链接过程。关键在于使用这些常量的代码所在的库是如何被动态链接的。

**如果做了逻辑推理，请给出假设输入与输出：**

这个文件定义的是常量，没有直接的逻辑推理过程。逻辑会发生在使用了这些常量的代码中。

**假设输入与输出的例子（在使用了这些常量的代码中）：**

假设一个用户空间的程序需要配置一个音频处理模块的输入音频格式。

**输入：**

* `module_id = 123` (要配置的模块 ID)
* `sample_rate = 48000` (目标采样率)
* `bit_depth = 16` (目标位深)

**处理逻辑（在用户空间库或服务中）：**

1. 构建一个数据结构或消息，其中包含以下信息：
   * 令牌 `AVS_TKN_MOD_ID_U32`，值为 `123`。
   * 令牌 `AVS_TKN_MOD_IN_AFMT_ID_U32`，指向一个音频格式结构的 ID。
   * 在音频格式结构中，包含：
     * 令牌 `AVS_TKN_AFMT_SAMPLE_RATE_U32`，值为 `48000`。
     * 令牌 `AVS_TKN_AFMT_BIT_DEPTH_U32`，值为 `16`。
2. 使用系统调用（例如 `ioctl`）将这个数据结构传递给内核 AVS 驱动。

**输出（内核 AVS 驱动的响应）：**

* 成功：驱动成功配置了模块的输入音频格式，返回成功状态。
* 失败：如果配置失败（例如，不支持该采样率），驱动返回错误代码。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **拼写错误或使用错误的令牌值：** 例如，错误地使用了 `AVS_TKN_AFMT_SAMPL_RATE_U32`（拼写错误）而不是 `AVS_TKN_AFMT_SAMPLE_RATE_U32`。这会导致内核驱动无法识别该配置项。
2. **提供无效的参数值：** 例如，将 `AVS_TKN_AFMT_SAMPLE_RATE_U32` 设置为一个不支持的采样率值。内核驱动可能会拒绝该配置。
3. **以错误的顺序或组合使用令牌：** 有些配置可能需要特定的令牌顺序或依赖关系。例如，在配置模块之前可能需要先定义模块的基本信息。
4. **类型不匹配：** 虽然令牌本身是枚举，但它们代表的数据类型是不同的（U32, String 等）。如果将错误类型的数据与令牌关联，会导致数据解析错误。
5. **忽略必要的令牌：** 有些配置可能需要提供一组完整的令牌信息。缺少某些必要的令牌会导致配置不完整或失败。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**从 Android Framework 到达这里的大致步骤：**

1. **应用层 (Java/Kotlin):** 应用使用 Android SDK 提供的音频相关的 API (例如 `MediaPlayer`, `AudioTrack`, `MediaRecorder`)。
2. **Framework 层 (Java):** 这些 API 调用会传递到 Android framework 的 `android.media` 包中的类，例如 `AudioManager`, `AudioService`, `AudioSystem` 等。
3. **Native 层 (C++):** Framework 层会通过 JNI (Java Native Interface) 调用到 native 代码，通常在 `frameworks/av/media/libaudioclient/` 和 `frameworks/av/services/audioflinger/` 等目录中。
4. **HAL 层 (C++):** Native 代码会调用 Audio HAL (Hardware Abstraction Layer) 的接口，这些接口定义在 `hardware/libhardware/include/hardware/audio.h` 等文件中。具体的 HAL 实现由设备制造商提供，并位于 `/vendor/` 或 `/system/hw/` 等目录。
5. **Kernel 驱动层 (C):** Audio HAL 的实现会与底层的音频驱动交互。对于使用 Intel AVS 的设备，HAL 会构造包含 `tokens.handroid` 中定义的令牌的消息，并通过 `ioctl` 系统调用发送给内核中的 Intel AVS 驱动。

**Frida Hook 示例调试步骤：**

假设我们想观察用户空间程序如何使用 `AVS_TKN_AFMT_SAMPLE_RATE_U32` 这个令牌。我们可以 hook HAL 层中可能发送包含此令牌的消息的函数。

**假设我们知道 Audio HAL 中某个函数 `send_avs_config` 负责发送 AVS 配置到内核。**

**Frida 脚本示例：**

```python
import frida
import sys

package_name = "your.app.package.name" # 替换为你的应用包名
function_name = "send_avs_config" # 假设的 HAL 函数名
library_path = "/vendor/lib64/hw/audio.primary.so" # 假设的 HAL 库路径

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[*] Error: {message['stack']}")

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 {package_name} 未找到，请先启动应用。")
    sys.exit(1)

script_code = """
Interceptor.attach(ptr("%s").add(Module.findExportByName("%s", "%s").offset), {
    onEnter: function(args) {
        console.log("[*] Hooking %s");
        // 假设第一个参数是指向配置数据的指针
        var configPtr = ptr(args[0]);
        // 这里需要根据实际的数据结构来解析配置数据，查找 AVS_TKN_AFMT_SAMPLE_RATE_U32 令牌
        // 这只是一个示例，实际解析过程会更复杂
        console.log("[*] Configuration data: " + configPtr.readByteArray(128));
    },
    onLeave: function(retval) {
        console.log("[*] %s returned: " + retval);
    }
});
""" % (library_path, "audio.primary.so", function_name, function_name, function_name)

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释：**

1. **导入 frida 库。**
2. **指定要 hook 的应用包名、HAL 函数名和库路径。** 这些需要根据实际情况进行替换。
3. **定义 `on_message` 函数来处理 Frida 发送的消息。**
4. **连接到目标 Android 设备上的应用进程。**
5. **构造 Frida 脚本代码：**
   - 使用 `Interceptor.attach` hook 目标 HAL 函数的入口和出口。
   - 在 `onEnter` 中，打印日志并尝试读取配置数据。**注意：这里读取配置数据的部分只是一个示例，实际的解析需要了解 HAL 函数接收的配置数据的具体结构。你需要根据实际情况来解析包含 `AVS_TKN_AFMT_SAMPLE_RATE_U32` 令牌的部分。**
   - 在 `onLeave` 中，打印函数的返回值。
6. **创建并加载 Frida 脚本。**
7. **保持脚本运行，直到用户按下 Ctrl+C。**

**使用步骤：**

1. 确保你的开发机上安装了 Frida 和相关的工具。
2. 将你的 Android 设备通过 USB 连接到开发机，并确保 adb 可用。
3. 运行目标 Android 应用。
4. 运行上述 Frida 脚本。
5. 在应用中执行触发音频配置的操作（例如，播放音频）。
6. 观察 Frida 的输出，你应该能看到 hook 到的 HAL 函数被调用，并打印出相关的配置数据。你需要分析打印出的数据，查找 `AVS_TKN_AFMT_SAMPLE_RATE_U32` 令牌以及其对应的值。

**请注意：**

* 上述 Frida 脚本只是一个框架，实际的 hook 代码需要根据具体的 HAL 实现和数据结构进行调整。你需要分析 Audio HAL 的源代码或者使用反编译工具来确定目标函数和数据结构。
* HAL 的实现可能因设备制造商而异，因此库路径和函数名可能会有所不同。
* 解析配置数据可能需要了解 AVS 配置数据的具体格式，这可能涉及到阅读相关的内核驱动源代码或文档。

通过 Frida hook，你可以动态地观察 Android framework 和 HAL 是如何一步步地使用这些令牌来配置底层的音频硬件的。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/sound/intel/avs/tokens.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __UAPI_SOUND_INTEL_AVS_TOKENS_H
#define __UAPI_SOUND_INTEL_AVS_TOKENS_H
enum avs_tplg_token {
  AVS_TKN_MANIFEST_NAME_STRING = 1,
  AVS_TKN_MANIFEST_VERSION_U32 = 2,
  AVS_TKN_MANIFEST_NUM_LIBRARIES_U32 = 3,
  AVS_TKN_MANIFEST_NUM_AFMTS_U32 = 4,
  AVS_TKN_MANIFEST_NUM_MODCFGS_BASE_U32 = 5,
  AVS_TKN_MANIFEST_NUM_MODCFGS_EXT_U32 = 6,
  AVS_TKN_MANIFEST_NUM_PPLCFGS_U32 = 7,
  AVS_TKN_MANIFEST_NUM_BINDINGS_U32 = 8,
  AVS_TKN_MANIFEST_NUM_CONDPATH_TMPLS_U32 = 9,
  AVS_TKN_MANIFEST_NUM_INIT_CONFIGS_U32 = 10,
  AVS_TKN_LIBRARY_ID_U32 = 101,
  AVS_TKN_LIBRARY_NAME_STRING = 102,
  AVS_TKN_AFMT_ID_U32 = 201,
  AVS_TKN_AFMT_SAMPLE_RATE_U32 = 202,
  AVS_TKN_AFMT_BIT_DEPTH_U32 = 203,
  AVS_TKN_AFMT_CHANNEL_MAP_U32 = 204,
  AVS_TKN_AFMT_CHANNEL_CFG_U32 = 205,
  AVS_TKN_AFMT_INTERLEAVING_U32 = 206,
  AVS_TKN_AFMT_NUM_CHANNELS_U32 = 207,
  AVS_TKN_AFMT_VALID_BIT_DEPTH_U32 = 208,
  AVS_TKN_AFMT_SAMPLE_TYPE_U32 = 209,
  AVS_TKN_MODCFG_BASE_ID_U32 = 301,
  AVS_TKN_MODCFG_BASE_CPC_U32 = 302,
  AVS_TKN_MODCFG_BASE_IBS_U32 = 303,
  AVS_TKN_MODCFG_BASE_OBS_U32 = 304,
  AVS_TKN_MODCFG_BASE_PAGES_U32 = 305,
  AVS_TKN_MODCFG_EXT_ID_U32 = 401,
  AVS_TKN_MODCFG_EXT_TYPE_UUID = 402,
  AVS_TKN_MODCFG_CPR_OUT_AFMT_ID_U32 = 403,
  AVS_TKN_MODCFG_CPR_FEATURE_MASK_U32 = 404,
  AVS_TKN_MODCFG_CPR_DMA_TYPE_U32 = 405,
  AVS_TKN_MODCFG_CPR_DMABUFF_SIZE_U32 = 406,
  AVS_TKN_MODCFG_CPR_VINDEX_U8 = 407,
  AVS_TKN_MODCFG_CPR_BLOB_FMT_ID_U32 = 408,
  AVS_TKN_MODCFG_MICSEL_OUT_AFMT_ID_U32 = 409,
  AVS_TKN_MODCFG_INTELWOV_CPC_LP_MODE_U32 = 410,
  AVS_TKN_MODCFG_SRC_OUT_FREQ_U32 = 411,
  AVS_TKN_MODCFG_MUX_REF_AFMT_ID_U32 = 412,
  AVS_TKN_MODCFG_MUX_OUT_AFMT_ID_U32 = 413,
  AVS_TKN_MODCFG_AEC_REF_AFMT_ID_U32 = 414,
  AVS_TKN_MODCFG_AEC_OUT_AFMT_ID_U32 = 415,
  AVS_TKN_MODCFG_AEC_CPC_LP_MODE_U32 = 416,
  AVS_TKN_MODCFG_ASRC_OUT_FREQ_U32 = 417,
  AVS_TKN_MODCFG_ASRC_MODE_U8 = 418,
  AVS_TKN_MODCFG_ASRC_DISABLE_JITTER_U8 = 419,
  AVS_TKN_MODCFG_UPDOWN_MIX_OUT_CHAN_CFG_U32 = 420,
  AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_SELECT_U32 = 421,
  AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_0_S32 = 422,
  AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_1_S32 = 423,
  AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_2_S32 = 424,
  AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_3_S32 = 425,
  AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_4_S32 = 426,
  AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_5_S32 = 427,
  AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_6_S32 = 428,
  AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_7_S32 = 429,
  AVS_TKN_MODCFG_UPDOWN_MIX_CHAN_MAP_U32 = 430,
  AVS_TKN_MODCFG_EXT_NUM_INPUT_PINS_U16 = 431,
  AVS_TKN_MODCFG_EXT_NUM_OUTPUT_PINS_U16 = 432,
  AVS_TKN_PPLCFG_ID_U32 = 1401,
  AVS_TKN_PPLCFG_REQ_SIZE_U16 = 1402,
  AVS_TKN_PPLCFG_PRIORITY_U8 = 1403,
  AVS_TKN_PPLCFG_LOW_POWER_BOOL = 1404,
  AVS_TKN_PPLCFG_ATTRIBUTES_U16 = 1405,
  AVS_TKN_PPLCFG_TRIGGER_U32 = 1406,
  AVS_TKN_BINDING_ID_U32 = 1501,
  AVS_TKN_BINDING_TARGET_TPLG_NAME_STRING = 1502,
  AVS_TKN_BINDING_TARGET_PATH_TMPL_ID_U32 = 1503,
  AVS_TKN_BINDING_TARGET_PPL_ID_U32 = 1504,
  AVS_TKN_BINDING_TARGET_MOD_ID_U32 = 1505,
  AVS_TKN_BINDING_TARGET_MOD_PIN_U8 = 1506,
  AVS_TKN_BINDING_MOD_ID_U32 = 1507,
  AVS_TKN_BINDING_MOD_PIN_U8 = 1508,
  AVS_TKN_BINDING_IS_SINK_U8 = 1509,
  AVS_TKN_PPL_ID_U32 = 1601,
  AVS_TKN_PPL_PPLCFG_ID_U32 = 1602,
  AVS_TKN_PPL_NUM_BINDING_IDS_U32 = 1603,
  AVS_TKN_PPL_BINDING_ID_U32 = 1604,
  AVS_TKN_MOD_ID_U32 = 1701,
  AVS_TKN_MOD_MODCFG_BASE_ID_U32 = 1702,
  AVS_TKN_MOD_IN_AFMT_ID_U32 = 1703,
  AVS_TKN_MOD_CORE_ID_U8 = 1704,
  AVS_TKN_MOD_PROC_DOMAIN_U8 = 1705,
  AVS_TKN_MOD_MODCFG_EXT_ID_U32 = 1706,
  AVS_TKN_MOD_KCONTROL_ID_U32 = 1707,
  AVS_TKN_MOD_INIT_CONFIG_NUM_IDS_U32 = 1708,
  AVS_TKN_MOD_INIT_CONFIG_ID_U32 = 1709,
  AVS_TKN_PATH_TMPL_ID_U32 = 1801,
  AVS_TKN_PATH_ID_U32 = 1901,
  AVS_TKN_PATH_FE_FMT_ID_U32 = 1902,
  AVS_TKN_PATH_BE_FMT_ID_U32 = 1903,
  AVS_TKN_PIN_FMT_INDEX_U32 = 2201,
  AVS_TKN_PIN_FMT_IOBS_U32 = 2202,
  AVS_TKN_PIN_FMT_AFMT_ID_U32 = 2203,
  AVS_TKN_KCONTROL_ID_U32 = 2301,
  AVS_TKN_INIT_CONFIG_ID_U32 = 2401,
  AVS_TKN_INIT_CONFIG_PARAM_U8 = 2402,
  AVS_TKN_INIT_CONFIG_LENGTH_U32 = 2403,
};
#endif

"""

```