Response:
Let's break down the thought process for answering the request about the `tokens.handroid` header file.

1. **Understand the Core Request:** The main goal is to analyze the provided C header file (`tokens.handroid`) and explain its purpose within the Android ecosystem, particularly focusing on its relationship to bionic (libc, math, linker) and providing practical examples.

2. **Initial Analysis of the File:**
   - **File Path:**  `bionic/libc/kernel/uapi/sound/sof/tokens.handroid`. This path immediately suggests:
     - `bionic`: Part of Android's core libraries.
     - `libc`:  Likely interacts with the C standard library.
     - `kernel`: Interface with the Linux kernel.
     - `uapi`: User-space API definitions.
     - `sound/sof`: Related to sound processing and the Sound Open Firmware (SOF) project.
     - `tokens.handroid`:  The file itself seems to define symbolic constants or "tokens."
   - **Content:** The file is primarily a series of `#define` statements, assigning integer values to macro names like `SOF_TPLG_KCTL_VOL_ID`, `SOF_TKN_BUF_SIZE`, etc.
   - **Comment:** The comment at the beginning is crucial: "This file is auto-generated. Modifications will be lost." This implies it's likely generated from some other source of truth (e.g., a configuration file or a script) and manual changes are discouraged.

3. **Infer the Purpose of the Tokens:**  The names of the defined macros give strong hints about their purpose:
   - `SOF_TPLG_KCTL_*`:  Likely related to "SOF Topology Kernel Control." These probably define IDs for different types of kernel controls used to manage the audio pipeline. Examples: `VOL_ID` (volume), `ENUM_ID` (enumeration), `SWITCH_ID` (switch).
   - `SOF_TKN_*`: Likely related to "SOF Token." These appear to represent identifiers for various parameters or properties within the SOF framework. Examples: `BUF_SIZE` (buffer size), `DAI_TYPE` (DAI type - likely Digital Audio Interface), `SCHED_PRIORITY` (scheduling priority), `SRC_RATE_IN` (source sample rate).

4. **Connect to Android Functionality:**  Given the file path and the nature of the tokens, the most obvious connection is to Android's audio subsystem.
   - **Audio HAL (Hardware Abstraction Layer):**  Android's audio HAL interacts with the kernel's audio drivers. This header file likely provides constants used in communication between the HAL and the SOF driver in the kernel.
   - **AudioFlinger:**  The core Android audio server manages audio routing, mixing, and playback. It might indirectly use these constants when configuring audio devices.
   - **NDK:**  Applications using the NDK's audio APIs (e.g., AAudio, OpenSL ES) could potentially interact with these underlying kernel mechanisms, although likely indirectly through higher-level abstractions.

5. **Address Specific Request Points:**

   - **List Functions:** The file *doesn't* define functions; it defines constants. It's important to clarify this misunderstanding.
   - **Relationship to Android:** Explain the connection to the audio subsystem (HAL, AudioFlinger, NDK). Give examples like controlling volume via a `KCTL_VOL_ID`.
   - **libc Function Implementation:** The file doesn't contain libc functions. Explain the distinction between this header file and the implementation of libc functions.
   - **Dynamic Linker:** While the file is *part* of bionic, it doesn't directly involve the dynamic linker's functionality (linking shared libraries). It's crucial to state this clearly. If there were structures or function declarations related to loading/unloading modules, then the linker aspect would be relevant. Since it's just `#define`s, it's about *using* the linked library, not the linking process itself. *Initially, I might have thought there could be a connection if these tokens were used in shared libraries, but the `#define` nature makes it a compile-time concept, not directly runtime linking.*
   - **Logical Reasoning (Assumptions):** Provide examples of how these tokens might be used. For instance, setting the buffer size using `SOF_TKN_BUF_SIZE`.
   - **User/Programming Errors:**  Common errors would be using incorrect token values (if manually setting them), leading to unexpected audio behavior or failures.
   - **Android Framework/NDK to This File:** Trace the path from an Android app playing audio down to the kernel driver, mentioning the involved layers (framework, media server, HAL, kernel driver).
   - **Frida Hook Example:** Provide a conceptual Frida example showing how to intercept calls using these constants, likely at the HAL level.

6. **Structure and Language:** Organize the answer logically with clear headings. Use precise language and avoid making assumptions. Translate the technical terms accurately into Chinese.

7. **Review and Refine:** Read through the answer to ensure clarity, accuracy, and completeness. Check for any misunderstandings of the prompt or technical details. For example, double-check that the explanation about the dynamic linker is accurate and doesn't overstate the connection. Ensure the Frida example is illustrative and not misleadingly specific without further context.
这个文件 `bionic/libc/kernel/uapi/sound/sof/tokens.handroid` 是 Android 系统中 Bionic C 库的一部分，它定义了一系列用于与 Sound Open Firmware (SOF) 交互的常量（宏定义）。SOF 是一个开源音频 DSP 固件项目，旨在为嵌入式系统提供灵活且强大的音频处理能力。

**功能列举:**

这个文件的主要功能是定义了一系列预定义的整数常量，这些常量作为“令牌”（tokens）用于标识不同的音频参数、控制标识符和配置选项。这些令牌在用户空间应用程序、Android 音频框架以及底层的 SOF 固件之间进行通信时使用。

具体来说，这些常量涵盖了以下几个方面：

* **控制标识符 (KCTL):**  以 `SOF_TPLG_KCTL_` 开头的常量，用于标识不同的内核控制 (kernel control)，例如音量控制 (`VOL_ID`)、枚举控制 (`ENUM_ID`)、字节数组控制 (`BYTES_ID`)、开关控制 (`SWITCH_ID`) 等。这些控制允许用户空间程序调整音频设备的各种属性。
* **缓冲区属性 (Buffer):** 以 `SOF_TKN_BUF_` 开头的常量，例如缓冲区大小 (`BUF_SIZE`)、缓冲区能力 (`BUF_CAPS`)、缓冲区标志 (`BUF_FLAGS`)。
* **数字音频接口 (DAI):** 以 `SOF_TKN_DAI_` 开头的常量，用于标识 DAI 的类型 (`DAI_TYPE`)、索引 (`DAI_INDEX`) 和方向 (`DAI_DIRECTION`)。
* **调度参数 (Scheduling):** 以 `SOF_TKN_SCHED_` 开头的常量，用于配置 SOF DSP 的任务调度，例如周期 (`SCHED_PERIOD`)、优先级 (`SCHED_PRIORITY`)、MIPS 需求 (`SCHED_MIPS`)、核心分配 (`SCHED_CORE`) 等。
* **音量和增益控制 (Volume/Gain):** 以 `SOF_TKN_VOLUME_` 和 `SOF_TKN_GAIN_` 开头的常量，用于控制音量渐变 (`VOLUME_RAMP_STEP_TYPE`) 和增益调整 (`GAIN_RAMP_TYPE`, `GAIN_VAL`)。
* **采样率 (Sample Rate):** 以 `SOF_TKN_SRC_RATE_` 和 `SOF_TKN_ASRC_RATE_` 开头的常量，用于指定音频流的输入和输出采样率。
* **组件属性 (Component):** 以 `SOF_TKN_COMP_` 开头的常量，用于描述音频处理组件的属性，例如周期计数 (`COMP_PERIOD_SINK_COUNT`, `COMP_PERIOD_SOURCE_COUNT`)、格式 (`COMP_FORMAT`)、核心 ID (`COMP_CORE_ID`)、UUID (`COMP_UUID`)、引脚绑定 (`COMP_INPUT_PIN_BINDING_WNAME`, `COMP_OUTPUT_PIN_BINDING_WNAME`) 等。
* **特定硬件平台相关的参数:** 例如针对 Intel SSP (`SOF_TKN_INTEL_SSP_`)、Intel DMIC (`SOF_TKN_INTEL_DMIC_`)、IMX SAI/ESAI (`SOF_TKN_IMX_SAI_`, `SOF_TKN_IMX_ESAI_`)、AMD ACP (`SOF_TKN_AMD_ACPDMIC_`, `SOF_TKN_AMD_ACPI2S_`, `SOF_TKN_AMD_ACP_SDW_`)、联发科 AFE (`SOF_TKN_MEDIATEK_AFE_`) 等硬件平台的特定配置。
* **其他参数:** 包括混音器类型 (`SOF_TKN_MIXER_TYPE`)、静音 LED 控制 (`SOF_TKN_MUTE_LED_`)、音频格式 (`SOF_TKN_CAVS_AUDIO_FORMAT_`) 等。

**与 Android 功能的关系及举例说明:**

这个文件与 Android 的音频功能紧密相关。SOF 固件在许多 Android 设备上被用作音频 DSP，负责处理音频的采集、处理和播放。`tokens.handroid` 中定义的常量作为用户空间程序（例如音频播放器、录音应用）与 SOF 固件交互的桥梁。

**举例说明:**

1. **音量控制:**  当用户在 Android 设备上调整音量时，Android 的音频框架会通过 Audio HAL (Hardware Abstraction Layer) 向底层的音频驱动发送控制命令。这个命令可能包含 `SOF_TPLG_KCTL_VOL_ID` 常量，用于标识这是一个音量控制操作。驱动程序接收到这个常量后，会知道需要修改与音量相关的参数。

2. **音频格式配置:**  当应用程序请求以特定的采样率或格式播放音频时，Audio HAL 会使用 `SOF_TKN_SRC_RATE_IN`、`SOF_TKN_COMP_FORMAT` 等常量来配置 SOF 固件的输入和组件参数，确保音频数据按照期望的方式进行处理。

3. **麦克风配置:**  对于集成了 SOF DSP 的设备，配置麦克风可能涉及到使用 `SOF_TKN_INTEL_DMIC_SAMPLE_RATE`、`SOF_TKN_INTEL_DMIC_PDM_CTRL_ID` 等常量来设置 DMIC (Digital Microphone) 的采样率、PDM 控制等参数。

**libc 函数的功能实现:**

这个头文件本身**不包含任何 libc 函数的实现**。它只是定义了一些宏常量。libc 函数的实现位于 Bionic 库的其他源文件中，例如 `stdio.c` (用于输入输出), `stdlib.c` (用于内存管理), `string.c` (用于字符串操作) 等。

**对于涉及 dynamic linker 的功能:**

这个头文件**直接不涉及 dynamic linker 的功能**。dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是在程序运行时加载和链接共享库 (.so 文件)。这个头文件定义的是用于与内核驱动交互的常量，在编译时被应用程序和库使用。

**so 布局样本和链接的处理过程 (与此文件无关):**

为了说明 dynamic linker 的工作，我们假设一个简单的场景：

**so 布局样本:**

假设我们有两个共享库：`liba.so` 和 `libb.so`，以及一个可执行文件 `app_executable`。

* **liba.so:**
  ```c
  // liba.c
  int add(int a, int b) {
      return a + b;
  }
  ```

* **libb.so:**
  ```c
  // libb.c
  #include <stdio.h>
  extern int add(int a, int b); // 声明来自 liba.so 的函数

  void print_sum(int x, int y) {
      printf("Sum is: %d\n", add(x, y));
  }
  ```

* **app_executable:**
  ```c
  // main.c
  #include <stdio.h>
  extern void print_sum(int x, int y); // 声明来自 libb.so 的函数

  int main() {
      print_sum(5, 3);
      return 0;
  }
  ```

**链接的处理过程:**

1. **编译时链接 (Static Linking):**  在编译 `liba.so` 和 `libb.so` 时，编译器会将源代码编译成目标文件 (.o)。链接器会将这些目标文件以及所需的库文件组合起来，生成最终的共享库。`libb.so` 在编译时需要知道 `add` 函数的存在，但不需要 `liba.so` 的具体地址。

2. **运行时链接 (Dynamic Linking):** 当 `app_executable` 运行时，操作系统会加载它。dynamic linker 会检查 `app_executable` 依赖的共享库 (`libb.so`)。

3. **加载依赖库:** dynamic linker 会加载 `libb.so` 到内存中。由于 `libb.so` 依赖于 `liba.so`，dynamic linker 也会加载 `liba.so`。

4. **符号解析 (Symbol Resolution):** dynamic linker 会解析 `libb.so` 中对 `add` 函数的引用。它会在已经加载的共享库中查找名为 `add` 的符号，并在 `liba.so` 中找到它。

5. **重定位 (Relocation):** dynamic linker 会修改 `libb.so` 中的代码，将对 `add` 函数的调用地址更新为 `liba.so` 中 `add` 函数的实际内存地址。

6. **执行:**  完成链接后，`app_executable` 就可以调用 `libb.so` 中的 `print_sum` 函数，而 `print_sum` 函数内部可以正确地调用 `liba.so` 中的 `add` 函数。

**假设输入与输出 (与此文件无关):**

如果一个使用 SOF 的音频应用程序尝试设置一个无效的采样率令牌值，例如：

**假设输入:**  应用程序尝试将 `SOF_TKN_SRC_RATE_IN` 设置为一个超出硬件支持范围的值，例如 192001 Hz。

**输出:**  底层的 SOF 驱动程序可能会返回一个错误码，指示不支持该采样率。Android 音频框架可能会捕获这个错误并通知应用程序，或者尝试回退到一个支持的采样率。用户可能会听到音频播放失败或出现失真。

**用户或编程常见的使用错误:**

1. **使用错误的令牌 ID:**  开发者可能会错误地使用了一个与预期功能不符的令牌 ID，导致设置了错误的参数或控制了错误的组件。
2. **提供无效的令牌值:**  例如，为音量控制令牌提供超出允许范围的值，或者为枚举令牌提供未定义的枚举值。
3. **在错误的时间设置令牌:**  某些令牌可能只能在特定的音频流状态下设置，如果在错误的时间设置可能会导致失败。
4. **忽略返回值:**  在与 SOF 交互时，驱动程序可能会返回错误码。开发者忽略这些返回值可能导致问题难以排查。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **用户应用程序 (Java/Kotlin):**  用户通过 Android 应用程序（例如音乐播放器）发起音频播放或录制请求。

2. **Android Framework (Java):**
   - `AudioManager`: 应用程序通过 `AudioManager` 服务与音频系统交互。
   - `MediaSession`: 用于控制媒体播放会话。
   - `AudioTrack`/`AudioRecord`: 用于播放和录制音频数据。

3. **Media Server (C++):**
   - `AudioFlinger`:  Android 的音频服务器，负责音频策略、路由和管理。它会处理来自 Framework 的请求。

4. **Audio HAL (C++):**
   - Audio Hardware Abstraction Layer，定义了与特定音频硬件交互的接口。`AudioFlinger` 通过 HAL 与底层的音频驱动进行通信。

5. **Kernel Driver (C):**
   - 特定于设备的音频驱动程序，例如与 SOF 固件交互的驱动。这个驱动程序会理解 `tokens.handroid` 中定义的常量，并使用它们来配置 SOF 固件。

6. **SOF Firmware:**  在音频 DSP 上运行的固件，负责实际的音频信号处理。

**Frida Hook 示例调试步骤:**

假设我们想监控 Audio HAL 中与设置 SOF 音量控制相关的操作。

```python
import frida
import sys

package_name = "com.example.audioplayer"  # 替换为你的应用程序包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libaudiohal.so", "_ZN7androidAHAL16setControlValueEPKcRKNS_13ControlValuesE"), {
    onEnter: function(args) {
        var controlName = Memory.readUtf8String(args[1]);
        var values = JSON.parse(Memory.readUtf8String(args[2])); // 假设 ControlValues 可以转换为 JSON

        if (controlName.includes("volume") || controlName.includes("Volume")) {
            send({
                type: "volume_control",
                control_name: controlName,
                values: values
            });
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释:**

1. **`frida.get_usb_device().attach(package_name)`:**  连接到运行在 USB 设备上的目标应用程序进程。
2. **`Module.findExportByName("libaudiohal.so", "_ZN7androidAHAL16setControlValueEPKcRKNS_13ControlValuesE")`:**  在 `libaudiohal.so` 库中查找 `setControlValue` 函数的符号。这个函数很可能是 Audio HAL 中用于设置控制值的关键函数。**注意：函数签名可能会因 Android 版本而异，需要根据实际情况调整。**
3. **`Interceptor.attach(...)`:**  拦截对 `setControlValue` 函数的调用。
4. **`onEnter: function(args)`:**  在函数被调用时执行的代码。
5. **`Memory.readUtf8String(args[1])`:** 读取控制名称（通常包含类似 "volume" 的字符串）。
6. **`Memory.readUtf8String(args[2])`:** 读取控制值。这里假设 `ControlValues` 可以转换为 JSON 字符串。实际情况可能需要更复杂的解析。
7. **`if (controlName.includes("volume"))`:**  过滤出与音量控制相关的调用。
8. **`send(...)`:**  将拦截到的信息发送回 Frida 客户端。

**调试步骤:**

1. 确保你的 Android 设备已连接并通过 adb 可访问。
2. 安装 Frida 和 frida-tools。
3. 运行你的目标音频应用程序。
4. 运行上面的 Frida 脚本。
5. 在应用程序中执行音量调整操作。
6. 查看 Frida 客户端输出，你应该能看到包含音量控制名称和值的消息。

通过这种方式，你可以监控 Audio HAL 如何使用 `tokens.handroid` 中隐含的控制 ID 与底层的 SOF 驱动进行交互。虽然 Frida 脚本直接操作的是 HAL 层的函数，但这些函数内部会使用相关的令牌常量来构建与驱动通信的消息。要直接 hook 使用这些常量的地方，可能需要深入到内核驱动或者 SOF 固件层面，这通常需要更底层的调试工具。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/sound/sof/tokens.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __INCLUDE_UAPI_SOF_TOPOLOGY_H__
#define __INCLUDE_UAPI_SOF_TOPOLOGY_H__
#define SOF_TPLG_KCTL_VOL_ID 256
#define SOF_TPLG_KCTL_ENUM_ID 257
#define SOF_TPLG_KCTL_BYTES_ID 258
#define SOF_TPLG_KCTL_SWITCH_ID 259
#define SOF_TPLG_KCTL_BYTES_VOLATILE_RO 260
#define SOF_TPLG_KCTL_BYTES_VOLATILE_RW 261
#define SOF_TPLG_KCTL_BYTES_WO_ID 262
#define SOF_TKN_BUF_SIZE 100
#define SOF_TKN_BUF_CAPS 101
#define SOF_TKN_BUF_FLAGS 102
#define SOF_TKN_DAI_TYPE 154
#define SOF_TKN_DAI_INDEX 155
#define SOF_TKN_DAI_DIRECTION 156
#define SOF_TKN_SCHED_PERIOD 200
#define SOF_TKN_SCHED_PRIORITY 201
#define SOF_TKN_SCHED_MIPS 202
#define SOF_TKN_SCHED_CORE 203
#define SOF_TKN_SCHED_FRAMES 204
#define SOF_TKN_SCHED_TIME_DOMAIN 205
#define SOF_TKN_SCHED_DYNAMIC_PIPELINE 206
#define SOF_TKN_SCHED_LP_MODE 207
#define SOF_TKN_SCHED_MEM_USAGE 208
#define SOF_TKN_SCHED_USE_CHAIN_DMA 209
#define SOF_TKN_VOLUME_RAMP_STEP_TYPE 250
#define SOF_TKN_VOLUME_RAMP_STEP_MS 251
#define SOF_TKN_GAIN_RAMP_TYPE 260
#define SOF_TKN_GAIN_RAMP_DURATION 261
#define SOF_TKN_GAIN_VAL 262
#define SOF_TKN_SRC_RATE_IN 300
#define SOF_TKN_SRC_RATE_OUT 301
#define SOF_TKN_ASRC_RATE_IN 320
#define SOF_TKN_ASRC_RATE_OUT 321
#define SOF_TKN_ASRC_ASYNCHRONOUS_MODE 322
#define SOF_TKN_ASRC_OPERATION_MODE 323
#define SOF_TKN_PCM_DMAC_CONFIG 353
#define SOF_TKN_COMP_PERIOD_SINK_COUNT 400
#define SOF_TKN_COMP_PERIOD_SOURCE_COUNT 401
#define SOF_TKN_COMP_FORMAT 402
#define SOF_TKN_COMP_CORE_ID 404
#define SOF_TKN_COMP_UUID 405
#define SOF_TKN_COMP_CPC 406
#define SOF_TKN_COMP_IS_PAGES 409
#define SOF_TKN_COMP_NUM_AUDIO_FORMATS 410
#define SOF_TKN_COMP_NUM_INPUT_PINS 411
#define SOF_TKN_COMP_NUM_OUTPUT_PINS 412
#define SOF_TKN_COMP_INPUT_PIN_BINDING_WNAME 413
#define SOF_TKN_COMP_OUTPUT_PIN_BINDING_WNAME 414
#define SOF_TKN_COMP_NUM_INPUT_AUDIO_FORMATS 415
#define SOF_TKN_COMP_NUM_OUTPUT_AUDIO_FORMATS 416
#define SOF_TKN_COMP_NO_WNAME_IN_KCONTROL_NAME 417
#define SOF_TKN_INTEL_SSP_CLKS_CONTROL 500
#define SOF_TKN_INTEL_SSP_MCLK_ID 501
#define SOF_TKN_INTEL_SSP_SAMPLE_BITS 502
#define SOF_TKN_INTEL_SSP_FRAME_PULSE_WIDTH 503
#define SOF_TKN_INTEL_SSP_QUIRKS 504
#define SOF_TKN_INTEL_SSP_TDM_PADDING_PER_SLOT 505
#define SOF_TKN_INTEL_SSP_BCLK_DELAY 506
#define SOF_TKN_INTEL_DMIC_DRIVER_VERSION 600
#define SOF_TKN_INTEL_DMIC_CLK_MIN 601
#define SOF_TKN_INTEL_DMIC_CLK_MAX 602
#define SOF_TKN_INTEL_DMIC_DUTY_MIN 603
#define SOF_TKN_INTEL_DMIC_DUTY_MAX 604
#define SOF_TKN_INTEL_DMIC_NUM_PDM_ACTIVE 605
#define SOF_TKN_INTEL_DMIC_SAMPLE_RATE 608
#define SOF_TKN_INTEL_DMIC_FIFO_WORD_LENGTH 609
#define SOF_TKN_INTEL_DMIC_UNMUTE_RAMP_TIME_MS 610
#define SOF_TKN_INTEL_DMIC_PDM_CTRL_ID 700
#define SOF_TKN_INTEL_DMIC_PDM_MIC_A_Enable 701
#define SOF_TKN_INTEL_DMIC_PDM_MIC_B_Enable 702
#define SOF_TKN_INTEL_DMIC_PDM_POLARITY_A 703
#define SOF_TKN_INTEL_DMIC_PDM_POLARITY_B 704
#define SOF_TKN_INTEL_DMIC_PDM_CLK_EDGE 705
#define SOF_TKN_INTEL_DMIC_PDM_SKEW 706
#define SOF_TKN_TONE_SAMPLE_RATE 800
#define SOF_TKN_PROCESS_TYPE 900
#define SOF_TKN_EFFECT_TYPE SOF_TKN_PROCESS_TYPE
#define SOF_TKN_IMX_SAI_MCLK_ID 1000
#define SOF_TKN_IMX_ESAI_MCLK_ID 1100
#define SOF_TKN_STREAM_PLAYBACK_COMPATIBLE_D0I3 1200
#define SOF_TKN_STREAM_CAPTURE_COMPATIBLE_D0I3 1201
#define SOF_TKN_MUTE_LED_USE 1300
#define SOF_TKN_MUTE_LED_DIRECTION 1301
#define SOF_TKN_INTEL_ALH_RATE 1400
#define SOF_TKN_INTEL_ALH_CH 1401
#define SOF_TKN_INTEL_HDA_RATE 1500
#define SOF_TKN_INTEL_HDA_CH 1501
#define SOF_TKN_MEDIATEK_AFE_RATE 1600
#define SOF_TKN_MEDIATEK_AFE_CH 1601
#define SOF_TKN_MEDIATEK_AFE_FORMAT 1602
#define SOF_TKN_MIXER_TYPE 1700
#define SOF_TKN_AMD_ACPDMIC_RATE 1800
#define SOF_TKN_AMD_ACPDMIC_CH 1801
#define SOF_TKN_CAVS_AUDIO_FORMAT_IN_RATE 1900
#define SOF_TKN_CAVS_AUDIO_FORMAT_IN_BIT_DEPTH 1901
#define SOF_TKN_CAVS_AUDIO_FORMAT_IN_VALID_BIT_DEPTH 1902
#define SOF_TKN_CAVS_AUDIO_FORMAT_IN_CHANNELS 1903
#define SOF_TKN_CAVS_AUDIO_FORMAT_IN_CH_MAP 1904
#define SOF_TKN_CAVS_AUDIO_FORMAT_IN_CH_CFG 1905
#define SOF_TKN_CAVS_AUDIO_FORMAT_IN_INTERLEAVING_STYLE 1906
#define SOF_TKN_CAVS_AUDIO_FORMAT_IN_FMT_CFG 1907
#define SOF_TKN_CAVS_AUDIO_FORMAT_IN_SAMPLE_TYPE 1908
#define SOF_TKN_CAVS_AUDIO_FORMAT_INPUT_PIN_INDEX 1909
#define SOF_TKN_CAVS_AUDIO_FORMAT_OUT_RATE 1930
#define SOF_TKN_CAVS_AUDIO_FORMAT_OUT_BIT_DEPTH 1931
#define SOF_TKN_CAVS_AUDIO_FORMAT_OUT_VALID_BIT_DEPTH 1932
#define SOF_TKN_CAVS_AUDIO_FORMAT_OUT_CHANNELS 1933
#define SOF_TKN_CAVS_AUDIO_FORMAT_OUT_CH_MAP 1934
#define SOF_TKN_CAVS_AUDIO_FORMAT_OUT_CH_CFG 1935
#define SOF_TKN_CAVS_AUDIO_FORMAT_OUT_INTERLEAVING_STYLE 1936
#define SOF_TKN_CAVS_AUDIO_FORMAT_OUT_FMT_CFG 1937
#define SOF_TKN_CAVS_AUDIO_FORMAT_OUT_SAMPLE_TYPE 1938
#define SOF_TKN_CAVS_AUDIO_FORMAT_OUTPUT_PIN_INDEX 1939
#define SOF_TKN_CAVS_AUDIO_FORMAT_IBS 1970
#define SOF_TKN_CAVS_AUDIO_FORMAT_OBS 1971
#define SOF_TKN_CAVS_AUDIO_FORMAT_DMA_BUFFER_SIZE 1972
#define SOF_TKN_INTEL_COPIER_NODE_TYPE 1980
#define SOF_TKN_INTEL_COPIER_DEEP_BUFFER_DMA_MS 1981
#define SOF_TKN_AMD_ACPI2S_RATE 1700
#define SOF_TKN_AMD_ACPI2S_CH 1701
#define SOF_TKN_AMD_ACPI2S_TDM_MODE 1702
#define SOF_TKN_IMX_MICFIL_RATE 2000
#define SOF_TKN_IMX_MICFIL_CH 2001
#define SOF_TKN_AMD_ACP_SDW_RATE 2100
#define SOF_TKN_AMD_ACP_SDW_CH 2101
#endif
```