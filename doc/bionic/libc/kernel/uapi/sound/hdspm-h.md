Response:
Let's break down the thought process for analyzing this C header file.

**1. Initial Understanding of the Context:**

The prompt clearly states: "这是目录为bionic/libc/kernel/uapi/sound/hdspm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker."  This immediately tells us:

* **Location:**  It's part of Android's core C library (bionic), specifically within the kernel's user-space API (uapi) related to sound.
* **Purpose:** It's defining an interface for interacting with a specific sound device or driver, likely named "hdspm". The ".handroid" suffix likely indicates Android-specific additions or adaptations.
* **Language:** It's a C header file (`.h`), meaning it defines structures, enums, and macros.

**2. Deconstructing the Header File (Iterative Process):**

I'll go through the header file section by section and reason about each part:

* **Header Guards:** `#ifndef __SOUND_HDSPM_H`, `#define __SOUND_HDSPM_H`, `#endif` -  Standard practice to prevent multiple inclusions and compilation errors. No specific functionality here, but crucial for proper C/C++ projects.

* **Linux Include:** `#ifdef __linux__`, `#include <linux/types.h>`, `#endif` - This is important. It indicates that while part of Android, this header file directly interacts with Linux kernel structures. `linux/types.h` provides basic type definitions like `__u32`, `__u8`, etc. This strongly suggests the "hdspm" device driver exists within the Linux kernel.

* **`HDSPM_MAX_CHANNELS 64`:**  A simple constant defining the maximum number of audio channels the "hdspm" device supports.

* **`enum hdspm_io_type`:**  An enumeration defining the different input/output types the device can handle (MADI, MADIface, AIO, AES32, RayDAT). These are likely standard professional audio interfaces.

* **`enum hdspm_speed`:** Defines the sampling rate speeds (ss - single speed, ds - double speed, qs - quad speed).

* **`struct hdspm_peak_rms`:** This is the first complex structure. It clearly relates to audio metering. `input_peaks`, `playback_peaks`, `output_peaks` and their corresponding `rms` values are for measuring audio signal levels. `speed` and `status2` likely provide additional context.

* **`#define SNDRV_HDSPM_IOCTL_GET_PEAK_RMS _IOR('H', 0x42, struct hdspm_peak_rms)`:**  This is a *key* piece. It defines an ioctl command. `_IOR` is a macro used in Linux kernel drivers for read operations from the kernel to user space. The 'H' likely represents a "magic number" for the hdspm driver, and `0x42` is the specific command code for retrieving peak/RMS data. The `struct hdspm_peak_rms` specifies the data structure to be transferred. This immediately connects the header file to the underlying kernel driver interaction.

* **`struct hdspm_config`:** This structure defines various configuration parameters for the device, such as sync references, sample rates, clock sources, and output settings.

* **`#define SNDRV_HDSPM_IOCTL_GET_CONFIG _IOR('H', 0x41, struct hdspm_config)`:** Another ioctl command, this time to *get* the device configuration.

* **`enum hdspm_ltc_format`, `enum hdspm_ltc_frame`, `enum hdspm_ltc_input_format`, `struct hdspm_ltc`:** This section deals with Linear Timecode (LTC), a standard for synchronizing audio and video. The enums define the format, frame type, and input format of the LTC signal. The `hdspm_ltc` structure holds the LTC value and the associated format information.

* **`#define SNDRV_HDSPM_IOCTL_GET_LTC _IOR('H', 0x46, struct hdspm_ltc)`:** Ioctl to retrieve LTC information.

* **`enum hdspm_sync`, `enum hdspm_madi_input`, `enum hdspm_madi_channel_format`, `enum hdspm_madi_frame_format`, `enum hdspm_syncsource`, `struct hdspm_status`:**  This section focuses on the synchronization and status of the "hdspm" device. It covers different synchronization sources (word clock, MADI, etc.), MADI-specific settings, and general device status information like card type and clock.

* **`#define SNDRV_HDSPM_IOCTL_GET_STATUS _IOR('H', 0x47, struct hdspm_status)`:** Ioctl to get the device status.

* **`#define HDSPM_ADDON_TCO 1`:** A simple definition for a TCO (Time Code Option) addon.

* **`struct hdspm_version`:** Contains information about the device's version, including card type, name, serial number, firmware revision, and addon flags.

* **`#define SNDRV_HDSPM_IOCTL_GET_VERSION _IOR('H', 0x48, struct hdspm_version)`:** Ioctl to get the device version.

* **`#define HDSPM_MIXER_CHANNELS HDSPM_MAX_CHANNELS`, `struct hdspm_channelfader`, `struct hdspm_mixer`, `struct hdspm_mixer_ioctl`:** This part deals with a digital mixer built into the "hdspm" device. The structures define fader levels for input and playback channels and a structure to hold the entire mixer state. The `hdspm_mixer_ioctl` is a wrapper for the mixer structure, likely used in an ioctl call.

* **`#define SNDRV_HDSPM_IOCTL_GET_MIXER _IOR('H', 0x44, struct hdspm_mixer_ioctl)`:** Ioctl to get the mixer state.

**3. Connecting to Android Functionality:**

The presence of ioctl commands is the key link to Android. Android's audio system (AudioFlinger and related components) interacts with hardware through HAL (Hardware Abstraction Layer) implementations. The HAL often uses ioctl calls to communicate with the underlying kernel drivers.

**4. Dynamic Linker and SO Layout:**

This header file itself *doesn't* directly involve the dynamic linker. It's a definition of a kernel interface. However, if user-space libraries were to interact with the "hdspm" driver (e.g., a library providing a higher-level API for controlling the device), those libraries would be `.so` files linked by the dynamic linker.

**5. Common Usage Errors:**

Understanding the purpose of each structure and ioctl allows me to infer potential errors. For example, using an incorrect ioctl command, passing an incorrectly sized buffer, or trying to access the device without proper permissions.

**6. Tracing the Call Path (Android Framework/NDK):**

I would mentally trace the likely path:

* **NDK:** An audio application using the NDK might use low-level system calls like `open()` to access the device file (e.g., `/dev/snd/controlC0` – this is a guess, the actual path depends on the specific sound card). Then, it would use `ioctl()` with the defined `SNDRV_HDSPM_IOCTL_*` constants and corresponding structures to communicate with the driver.
* **Android Framework:**  The Android audio framework (AudioFlinger) would likely interact with the "hdspm" device through a HAL implementation. The HAL would then make the same kind of `ioctl()` calls.

**7. Frida Hooking:**

Knowing the key `ioctl` calls allows me to formulate Frida hook examples, targeting the `ioctl` function and filtering for the specific `SNDRV_HDSPM_IOCTL_*` constants.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "Is this purely a user-space library?"  Correction: The `#include <linux/types.h>` and the ioctl definitions clearly indicate kernel interaction.
* **Initial thought:** "How does the dynamic linker fit in?" Correction:  The header itself doesn't, but libraries *using* this interface would be linked dynamically.
* **Focusing on the "big picture":** Continuously reminding myself that this is an *interface* definition and how that interface is used in the broader Android audio ecosystem.

By following this step-by-step analysis, combining the information in the header file with general knowledge of Android and Linux driver interaction, I can generate a comprehensive and accurate explanation.
这个C头文件 `bionic/libc/kernel/uapi/sound/hdspm.handroid` 定义了用户空间程序与Linux内核中 `hdspm` 声卡驱动进行交互的接口。它定义了一些常量、枚举和结构体，用于获取和设置 `hdspm` 声卡的各种参数和状态。

**功能列举：**

1. **定义常量:** `HDSPM_MAX_CHANNELS` 定义了 `hdspm` 声卡支持的最大通道数 (64)。

2. **定义枚举类型:**
   - `hdspm_io_type`:  定义了 `hdspm` 声卡支持的输入/输出接口类型，例如 MADI, MADIface, AIO, AES32, RayDAT。
   - `hdspm_speed`: 定义了采样率速度，例如单倍速 (ss), 双倍速 (ds), 四倍速 (qs)。
   - `hdspm_ltc_format`: 定义了 LTC (Linear Timecode) 的格式，用于音频和视频同步。
   - `hdspm_ltc_frame`: 定义了 LTC 的帧类型。
   - `hdspm_ltc_input_format`: 定义了 LTC 的输入视频格式。
   - `hdspm_sync`: 定义了同步状态。
   - `hdspm_madi_input`: 定义了 MADI 输入类型 (光纤或同轴)。
   - `hdspm_madi_channel_format`: 定义了 MADI 通道格式 (64通道或56通道)。
   - `hdspm_madi_frame_format`: 定义了 MADI 帧格式 (48k或96k)。
   - `hdspm_syncsource`: 定义了同步源。

3. **定义数据结构:**
   - `hdspm_peak_rms`:  用于获取 `hdspm` 声卡的峰值和 RMS (均方根) 电平。包含输入、回放和输出通道的峰值和 RMS 值，以及当前速度和状态信息。
   - `hdspm_config`: 用于获取 `hdspm` 声卡的配置信息，例如首选同步参考、字时钟和 MADI 同步检查、系统和自动同步采样率、时钟模式、时钟源、自动同步参考、线路输出和直通/模拟输出设置。
   - `hdspm_ltc`: 用于获取 `hdspm` 声卡的 LTC 信息，包括 LTC 值、格式、帧类型和输入格式。
   - `hdspm_status`: 用于获取 `hdspm` 声卡的状态信息，包括卡类型、自动同步源、卡时钟、主周期以及特定于卡的 MADI 相关状态。
   - `hdspm_version`: 用于获取 `hdspm` 声卡的版本信息，包括卡类型、卡名、序列号、固件版本和附加组件。
   - `hdspm_channelfader`: 用于表示通道的推子电平，包含输入和回放的推子值。
   - `hdspm_mixer`: 用于表示 `hdspm` 声卡的混音器状态，包含所有通道的推子信息。
   - `hdspm_mixer_ioctl`:  用于在使用 `ioctl` 系统调用时传递混音器数据的结构体。

4. **定义 ioctl 命令:**
   - `SNDRV_HDSPM_IOCTL_GET_PEAK_RMS`: 用于通过 `ioctl` 系统调用获取 `hdspm_peak_rms` 结构体的数据。
   - `SNDRV_HDSPM_IOCTL_GET_CONFIG`: 用于通过 `ioctl` 系统调用获取 `hdspm_config` 结构体的数据。
   - `SNDRV_HDSPM_IOCTL_GET_LTC`: 用于通过 `ioctl` 系统调用获取 `hdspm_ltc` 结构体的数据。
   - `SNDRV_HDSPM_IOCTL_GET_STATUS`: 用于通过 `ioctl` 系统调用获取 `hdspm_status` 结构体的数据。
   - `SNDRV_HDSPM_IOCTL_GET_VERSION`: 用于通过 `ioctl` 系统调用获取 `hdspm_version` 结构体的数据。
   - `SNDRV_HDSPM_IOCTL_GET_MIXER`: 用于通过 `ioctl` 系统调用获取 `hdspm_mixer_ioctl` 结构体的数据。

**与 Android 功能的关系及举例说明：**

这个头文件定义了与特定硬件 (RME HDSPe MADI 系列声卡) 交互的接口。在 Android 系统中，如果安装了这类声卡并且有相应的驱动程序，Android 的音频系统 (例如 AudioFlinger) 或者通过 NDK 开发的音频应用可能需要使用这些定义来控制和读取声卡的状态。

**举例说明：**

一个 Android 音频应用可能需要获取 `hdspm` 声卡的输入信号电平来显示 VU 表。这时，应用会：

1. 打开声卡对应的设备文件 (通常在 `/dev/snd/` 目录下，例如 `controlC0`)。
2. 使用 `ioctl` 系统调用，并传入 `SNDRV_HDSPM_IOCTL_GET_PEAK_RMS` 命令。
3. 提供一个 `hdspm_peak_rms` 结构体的指针，内核驱动会将当前的峰值和 RMS 电平数据填充到这个结构体中。
4. 应用读取结构体中的 `input_peaks` 和 `input_rms` 字段来获取电平信息。

**详细解释 libc 函数的功能实现：**

这个头文件本身**不包含** libc 函数的实现。它只是一个头文件，用于声明数据结构和常量。libc 函数的实现位于 bionic 库的其他源文件中。

这里涉及的关键是 `ioctl` 系统调用。`ioctl` 是一个通用的设备控制操作，它允许用户空间程序向设备驱动程序发送命令和传递数据。

`ioctl` 函数在 libc 中的实现通常会调用内核提供的系统调用接口。其基本流程是：

1. **参数准备:** 用户空间程序将要传递给驱动程序的数据打包到结构体中 (例如 `hdspm_peak_rms`)。
2. **系统调用:** 调用 libc 提供的 `ioctl` 函数，传入设备文件描述符、ioctl 命令码 (例如 `SNDRV_HDSPM_IOCTL_GET_PEAK_RMS`) 和指向数据结构体的指针。
3. **内核处理:** Linux 内核接收到 `ioctl` 系统调用后，会根据文件描述符找到对应的设备驱动程序 (在这里是 `hdspm` 驱动)。
4. **驱动程序处理:** `hdspm` 驱动程序会根据传入的 ioctl 命令码执行相应的操作。对于 `SNDRV_HDSPM_IOCTL_GET_PEAK_RMS`，驱动程序会读取声卡的硬件寄存器来获取峰值和 RMS 电平，并将这些数据填充到用户空间传递的 `hdspm_peak_rms` 结构体中。
5. **返回结果:** `ioctl` 系统调用返回，用户空间程序可以访问填充后的数据结构体。

**涉及 dynamic linker 的功能及 so 布局样本和链接处理过程：**

这个头文件本身并不直接涉及 dynamic linker。但是，如果用户空间程序使用这个头文件来与 `hdspm` 声卡交互，那么该程序可能会链接到一些共享库 (.so 文件)，例如：

- **libc.so:**  提供 `ioctl` 等系统调用函数的标准 C 库。
- **libaudioclient.so 或其他音频相关的 HAL 库:** 如果是通过 Android 的音频框架进行交互，可能会涉及到这些库。

**so 布局样本：**

假设一个名为 `my_audio_app` 的应用使用了这个头文件：

```
/system/bin/my_audio_app  (可执行文件)
/system/lib64/libc.so
/system/lib64/libaudioclient.so
/vendor/lib64/hw/audio.r_submix.default.so  (可能的音频 HAL 实现)
```

**链接处理过程：**

1. **编译时链接:** 编译器会将 `my_audio_app` 中对 `ioctl` 等函数的调用链接到 libc.so 中对应的符号。
2. **运行时链接:** 当 `my_audio_app` 启动时，Android 的 dynamic linker (linker64) 会负责加载所需的共享库 (libc.so, libaudioclient.so 等) 到进程的地址空间，并解析符号引用，将 `my_audio_app` 中对 `ioctl` 的调用指向 libc.so 中 `ioctl` 函数的实际地址。

**假设输入与输出 (针对 `SNDRV_HDSPM_IOCTL_GET_PEAK_RMS`)：**

**假设输入：**

- 打开了 `hdspm` 声卡对应的设备文件描述符 `fd`。
- 创建了一个 `hdspm_peak_rms` 结构体变量 `peak_rms`。

**假设输出：**

- 调用 `ioctl(fd, SNDRV_HDSPM_IOCTL_GET_PEAK_RMS, &peak_rms)` 后，如果成功，`ioctl` 返回 0。
- `peak_rms` 结构体中的 `input_peaks`, `playback_peaks`, `output_peaks`, `input_rms`, `playback_rms`, `output_rms`, `speed`, `status2` 字段会被 `hdspm` 驱动程序填充上当前声卡的电平、速度和状态信息。

**涉及用户或编程常见的使用错误：**

1. **忘记包含头文件:** 如果没有包含 `sound/hdspm.h`，编译器会报错，因为无法识别定义的常量、枚举和结构体。
2. **使用错误的 ioctl 命令码:**  如果使用了错误的 ioctl 命令码，`hdspm` 驱动程序可能无法识别，导致 `ioctl` 调用失败并返回错误码。
3. **传递了错误大小的结构体:** `ioctl` 依赖于传递正确大小的数据结构。如果传递的结构体大小不匹配，可能导致数据错乱或程序崩溃。
4. **没有正确初始化结构体:** 有些 ioctl 命令可能需要先初始化结构体的某些字段。如果初始化不正确，可能导致驱动程序行为异常。
5. **权限问题:**  访问声卡设备文件通常需要特定的权限。如果用户没有足够的权限，`open` 或 `ioctl` 调用可能会失败。
6. **设备文件不存在或驱动未加载:** 如果 `hdspm` 声卡驱动没有正确加载，或者对应的设备文件不存在，尝试打开设备文件会失败。

**Android framework 或 NDK 如何一步步到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 路径：**

1. **用户应用 (Java/Kotlin):**  用户应用可能通过 `MediaRecorder`, `MediaPlayer`, `AudioTrack`, `AudioRecord` 等 Android Framework API 进行音频操作。
2. **AudioFlinger 服务:**  Framework API 的底层实现会调用到 `AudioFlinger` 服务，它是 Android 音频系统的核心组件。
3. **Audio HAL (Hardware Abstraction Layer):** `AudioFlinger` 通过 Audio HAL 与硬件进行交互。对于 `hdspm` 声卡，可能存在一个实现了 Audio HAL 接口的 `.so` 库。
4. **HAL 实现:** HAL 实现的代码 (通常是 C/C++) 会打开声卡对应的设备文件 (`/dev/snd/controlC0` 或类似的)，并使用 `ioctl` 系统调用，并使用 `sound/hdspm.h` 中定义的常量和结构体与 `hdspm` 驱动程序进行通信。
5. **内核驱动:**  `ioctl` 调用最终会到达 Linux 内核中的 `hdspm` 驱动程序。

**NDK 路径：**

1. **用户应用 (C/C++):**  NDK 应用可以直接使用 POSIX 系统调用，例如 `open` 和 `ioctl`。
2. **直接调用:** NDK 应用可以包含 `sound/hdspm.h` 头文件，并直接调用 `open` 打开声卡设备文件，然后使用 `ioctl` 和定义的 ioctl 命令与驱动程序交互。

**Frida Hook 示例：**

假设我们想 hook 获取 `hdspm` 声卡峰值和 RMS 电平的 ioctl 调用。

```python
import frida
import sys

package_name = "your.audio.app" # 替换为你的应用包名
ioctl_cmd = 0x40084842 # SNDRV_HDSPM_IOCTL_GET_PEAK_RMS 的值，可以通过查看头文件计算得到 (_IOR('H', 0x42, struct hdspm_peak_rms))

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")

session = frida.attach(package_name)

script = session.create_script(f"""
    const ioctlPtr = Module.getExportByName(null, "ioctl");
    Interceptor.attach(ioctlPtr, {
        onEnter: function (args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();
            if (request === {ioctl_cmd}) {
                console.log("[*] ioctl called with SNDRV_HDSPM_IOCTL_GET_PEAK_RMS");
                this.peakRmsPtr = args[2];
            }
        },
        onLeave: function (retval) {
            if (this.peakRmsPtr) {
                const peakRms = new NativePointer(this.peakRmsPtr);
                // 假设 __u32 是 4 字节，__u64 是 8 字节，__u8 是 1 字节
                let inputPeaks = [];
                for (let i = 0; i < 64; i++) {
                    inputPeaks.push(peakRms.add(i * 4).readU32());
                }
                console.log("[*] Input Peaks:", inputPeaks);

                let inputRms = [];
                for (let i = 0; i < 64; i++) {
                    inputRms.push(peakRms.add(64 * 4 + i * 8).readU64());
                }
                console.log("[*] Input RMS:", inputRms);
            }
        }
    });
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**代码解释：**

1. **导入 frida 库。**
2. **指定要 hook 的应用包名和 ioctl 命令码。**
3. **定义 `on_message` 函数来处理 Frida 发送的消息。**
4. **附加到目标进程。**
5. **创建 Frida script：**
   - 获取 `ioctl` 函数的地址。
   - 使用 `Interceptor.attach` hook `ioctl` 函数。
   - 在 `onEnter` 中，检查 `ioctl` 的命令码是否为 `SNDRV_HDSPM_IOCTL_GET_PEAK_RMS`。如果是，则记录指向 `hdspm_peak_rms` 结构体的指针。
   - 在 `onLeave` 中，如果之前记录了结构体指针，则读取结构体中的 `input_peaks` 和 `input_rms` 数据并打印出来。
6. **设置消息回调并加载 script。**
7. **保持脚本运行，直到用户输入。**

运行这个 Frida 脚本后，当目标应用调用 `ioctl` 并使用 `SNDRV_HDSPM_IOCTL_GET_PEAK_RMS` 命令时，你将在控制台中看到 hook 到的调用信息以及读取到的峰值和 RMS 电平数据。

请注意，你需要根据实际情况调整代码中的结构体偏移量和数据类型大小。你可能还需要根据应用的具体实现来调整 hook 的位置和方式。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/sound/hdspm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __SOUND_HDSPM_H
#define __SOUND_HDSPM_H
#ifdef __linux__
#include <linux/types.h>
#endif
#define HDSPM_MAX_CHANNELS 64
enum hdspm_io_type {
  MADI,
  MADIface,
  AIO,
  AES32,
  RayDAT
};
enum hdspm_speed {
  ss,
  ds,
  qs
};
struct hdspm_peak_rms {
  __u32 input_peaks[64];
  __u32 playback_peaks[64];
  __u32 output_peaks[64];
  __u64 input_rms[64];
  __u64 playback_rms[64];
  __u64 output_rms[64];
  __u8 speed;
  int status2;
};
#define SNDRV_HDSPM_IOCTL_GET_PEAK_RMS _IOR('H', 0x42, struct hdspm_peak_rms)
struct hdspm_config {
  unsigned char pref_sync_ref;
  unsigned char wordclock_sync_check;
  unsigned char madi_sync_check;
  unsigned int system_sample_rate;
  unsigned int autosync_sample_rate;
  unsigned char system_clock_mode;
  unsigned char clock_source;
  unsigned char autosync_ref;
  unsigned char line_out;
  unsigned int passthru;
  unsigned int analog_out;
};
#define SNDRV_HDSPM_IOCTL_GET_CONFIG _IOR('H', 0x41, struct hdspm_config)
enum hdspm_ltc_format {
  format_invalid,
  fps_24,
  fps_25,
  fps_2997,
  fps_30
};
enum hdspm_ltc_frame {
  frame_invalid,
  drop_frame,
  full_frame
};
enum hdspm_ltc_input_format {
  ntsc,
  pal,
  no_video
};
struct hdspm_ltc {
  unsigned int ltc;
  enum hdspm_ltc_format format;
  enum hdspm_ltc_frame frame;
  enum hdspm_ltc_input_format input_format;
};
#define SNDRV_HDSPM_IOCTL_GET_LTC _IOR('H', 0x46, struct hdspm_ltc)
enum hdspm_sync {
  hdspm_sync_no_lock = 0,
  hdspm_sync_lock = 1,
  hdspm_sync_sync = 2
};
enum hdspm_madi_input {
  hdspm_input_optical = 0,
  hdspm_input_coax = 1
};
enum hdspm_madi_channel_format {
  hdspm_format_ch_64 = 0,
  hdspm_format_ch_56 = 1
};
enum hdspm_madi_frame_format {
  hdspm_frame_48 = 0,
  hdspm_frame_96 = 1
};
enum hdspm_syncsource {
  syncsource_wc = 0,
  syncsource_madi = 1,
  syncsource_tco = 2,
  syncsource_sync = 3,
  syncsource_none = 4
};
struct hdspm_status {
  __u8 card_type;
  enum hdspm_syncsource autosync_source;
  __u64 card_clock;
  __u32 master_period;
  union {
    struct {
      __u8 sync_wc;
      __u8 sync_madi;
      __u8 sync_tco;
      __u8 sync_in;
      __u8 madi_input;
      __u8 channel_format;
      __u8 frame_format;
    } madi;
  } card_specific;
};
#define SNDRV_HDSPM_IOCTL_GET_STATUS _IOR('H', 0x47, struct hdspm_status)
#define HDSPM_ADDON_TCO 1
struct hdspm_version {
  __u8 card_type;
  char cardname[20];
  unsigned int serial;
  unsigned short firmware_rev;
  int addons;
};
#define SNDRV_HDSPM_IOCTL_GET_VERSION _IOR('H', 0x48, struct hdspm_version)
#define HDSPM_MIXER_CHANNELS HDSPM_MAX_CHANNELS
struct hdspm_channelfader {
  unsigned int in[HDSPM_MIXER_CHANNELS];
  unsigned int pb[HDSPM_MIXER_CHANNELS];
};
struct hdspm_mixer {
  struct hdspm_channelfader ch[HDSPM_MIXER_CHANNELS];
};
struct hdspm_mixer_ioctl {
  struct hdspm_mixer * mixer;
};
#define SNDRV_HDSPM_IOCTL_GET_MIXER _IOR('H', 0x44, struct hdspm_mixer_ioctl)
#endif
```