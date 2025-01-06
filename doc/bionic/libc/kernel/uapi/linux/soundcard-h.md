Response:
Thinking Process:

1. **Understand the Request:** The core request is to analyze the provided C header file (`soundcard.handroid`) and explain its functionality, especially its relationship to Android, implementation details of libc functions, dynamic linker aspects, potential errors, and how Android frameworks interact with it.

2. **Initial Overview:**  The file is a C header file defining constants and structures related to the Linux soundcard API (OSS - Open Sound System). The `uapi` in the path suggests it's a user-space API header meant to be used by applications interacting with the kernel.

3. **Functionality Breakdown:** I'll go through the header and categorize the defined entities:
    * **Version and Includes:** `SOUND_VERSION`, `OPEN_SOUND_SYSTEM`, `linux/ioctl.h`, `endian.h`. These set the API version and include necessary headers for IO control and endianness handling.
    * **Soundcard Types:**  `SNDCARD_ADLIB`, `SNDCARD_SB`, etc. These are enumerations representing different sound card models.
    * **IO Control Macros:** `SIOCPARM_MASK`, `SIOC_VOID`, `SIOC_OUT`, etc., along with `_SIO`, `_SIOR`, `_SIOW`, `_SIOWR`. These macros are used to define ioctl commands. The code provides fallback definitions for systems where `_IOWR` might not be defined as expected.
    * **Sequencer IOCTLs:** `SNDCTL_SEQ_RESET`, `SNDCTL_SEQ_SYNC`, etc. These constants define specific ioctl commands for controlling the sound sequencer. They often take structures as arguments (e.g., `synth_info`, `midi_info`).
    * **Timer IOCTLs:** `SNDCTL_TMR_TIMEBASE`, `SNDCTL_TMR_START`, etc. These control the sound timer.
    * **Patch Information:** `struct patch_info`. This structure describes sound patches or samples.
    * **Sysex Information:** `struct sysex_info`. This relates to System Exclusive MIDI messages.
    * **Sequencer Events:** `SEQ_NOTEOFF`, `SEQ_NOTEON`, `SEQ_PGMCHANGE`, etc. These are constants representing different sequencer events.
    * **MIDI Controllers:** `CTL_BANK_SELECT`, `CTL_MODWHEEL`, etc. Standard MIDI controller numbers.
    * **Instrument Definition:** `struct sbi_instrument`. Used for defining instruments, especially for FM synthesis.
    * **Synthesizer Information:** `struct synth_info`. Describes the capabilities of a synthesizer.
    * **Timer Information:** `struct sound_timer_info`. Information about the sound timer.
    * **MIDI Information:** `struct midi_info`. Information about MIDI devices.
    * **MPU-401 Commands:** `struct mpu_command_rec`, `SNDCTL_MIDI_PRETIME`, etc. Specific to the MPU-401 MIDI interface.
    * **DSP IOCTLs:** `SNDCTL_DSP_RESET`, `SNDCTL_DSP_SPEED`, etc. IO controls for the Digital Signal Processor (audio playback and recording). Includes definitions for audio formats (`AFMT_*`).
    * **Audio Buffer Information:** `struct audio_buf_info`. Describes the status of audio buffers.
    * **DSP Capabilities:** `DSP_CAP_REVISION`, `DSP_CAP_DUPLEX`, etc. Flags indicating DSP features.
    * **Data Transfer Information:** `struct count_info`. Information about data transfer progress.
    * **Memory Mapping:** `struct buffmem_desc`, `SNDCTL_DSP_MAPINBUF`, `SNDCTL_DSP_MAPOUTBUF`. Allows mapping audio buffers into user space.
    * **Channel Binding:** `SNDCTL_DSP_GETCHANNELMASK`, `SNDCTL_DSP_BIND_CHANNEL`. For managing audio channels.
    * **S/PDIF Control:** `SNDCTL_DSP_SETSPDIF`, `SNDCTL_DSP_GETSPDIF`. Controls the S/PDIF digital audio interface.
    * **Simplified PCM Defines:** `SOUND_PCM_READ_RATE`, `SOUND_PCM_WRITE_RATE`, etc. More user-friendly aliases for some DSP ioctls.
    * **Coprocessor Control:** `struct copr_buffer`, `struct copr_debug_buf`, `struct copr_msg`, `SNDCTL_COPR_RESET`, etc. For controlling an audio coprocessor.
    * **Mixer Definitions:** `SOUND_MIXER_NRDEVICES`, `SOUND_MIXER_VOLUME`, etc., along with `MIXER_READ` and `MIXER_WRITE` macros. Defines mixer controls and provides macros for accessing them.
    * **Mixer Information Structures:** `struct mixer_info`, `struct _old_mixer_info`. Information about the mixer device.
    * **Mixer Volume Tables:** `struct mixer_vol_table`. For getting and setting mixer levels in a table format.
    * **OSS Version:** `OSS_GETVERSION`. An ioctl to get the OSS version.
    * **Sequencer Event Values:** `EV_SEQ_LOCAL`, `EV_TIMING`, `EV_CHN_COMMON`, etc. Raw event codes for the sequencer.
    * **MIDI Event Values:** `MIDI_NOTEOFF`, `MIDI_NOTEON`, etc. Standard MIDI event codes.
    * **Timer Event Values:** `TMR_WAIT_REL`, `TMR_WAIT_ABS`, etc. Timer-related event codes.
    * **Local Events:** `LOCL_STARTAUDIO`. Local sequencer event.
    * **Sequencer Buffer Macros:** `SEQ_DECLAREBUF`, `SEQ_DEFINEBUF`, `_SEQ_NEEDBUF`, etc. Macros for managing a sequencer buffer in user space.
    * **Sequencer Event Generation Macros:** `SEQ_VOLUME_MODE`, `_CHN_VOICE`, `SEQ_START_NOTE`, `SEQ_STOP_NOTE`, etc. Higher-level macros for generating sequencer events and writing them to the buffer.

4. **Android Relevance:** This header is part of Android's Bionic library, indicating it's used for audio functionality. Examples include:
    * **Audio Playback/Recording:**  NDK applications using low-level audio APIs likely interact with these ioctls to control audio devices.
    * **MIDI Support:** Android's MIDI implementation may use parts of this API for interacting with MIDI hardware or software synthesizers.
    * **Mixer Control:**  System settings and audio applications might use the mixer ioctls to adjust volume levels for different audio sources.

5. **libc Function Implementation:** The header file *defines constants and structures*, it doesn't implement libc functions. The actual implementation would be in the kernel driver for the soundcard. However, the macros like `_SIO`, `_SIOR`, `_SIOW`, `_SIOWR` are wrappers around the `ioctl()` system call, a fundamental libc function for device control. The implementation of `ioctl()` involves transitioning to kernel space, finding the appropriate device driver, and executing the requested command.

6. **Dynamic Linker:** This header file itself doesn't directly involve the dynamic linker. However, if an application uses functions or structures defined here, the Bionic library (which contains the `ioctl()` implementation and other related functions) will be dynamically linked.

7. **Assumptions and Logic:** The ioctl macros use bit manipulation to encode the command, direction, and data size. The different `SNDCTL_*` and `SOUND_MIXER_*` constants are essentially unique identifiers for different operations.

8. **Common Errors:**
    * **Incorrect ioctl Number:** Using the wrong `SNDCTL_*` constant will result in `EINVAL` error.
    * **Incorrect Data Structure:** Passing the wrong structure or an incorrectly sized structure to an ioctl will lead to errors.
    * **Permissions:**  Lack of permissions to access the sound device file (`/dev/sound/...`).
    * **Device Not Found:** The sound device might not be present or properly initialized.

9. **Android Framework and NDK Interaction:**
    * **Framework:** Android's Java framework (e.g., `android.media.AudioTrack`, `android.media.MediaRecorder`, `android.media.AudioManager`) provides high-level APIs for audio. Internally, these often delegate to native code.
    * **NDK:** NDK developers can use `<sys/ioctl.h>` and open the sound device files directly (e.g., `/dev/dsp`, `/dev/mixer`, `/dev/sequencer`) to interact with the soundcard using the ioctls defined in this header.
    * **Path:** Java Framework -> Native Audio Code (e.g., in frameworks/av/media/...) -> Opens device files and uses `ioctl()` with constants from `soundcard.handroid`.

10. **Frida Hooking:** I can provide examples of hooking `open()` and `ioctl()` to observe interactions with the soundcard.

By following these steps, I can address all parts of the request in a structured and detailed manner. The emphasis is on explaining the *purpose* and *structure* of the header file, its connection to lower-level kernel interfaces, and how it's used within the Android ecosystem.


## bionic/libc/kernel/uapi/linux/soundcard.h 功能列举

这个头文件 `soundcard.h` 定义了 Linux 操作系统中用于与声卡硬件进行交互的用户空间 API。它属于传统的 **Open Sound System (OSS)** 架构，尽管现在 Linux 主要使用 ALSA (Advanced Linux Sound Architecture)，但为了兼容性，OSS API 仍然被保留。

其主要功能可以概括为：

**1. 定义了声卡设备的常量:**

*   **`SOUND_VERSION`**:  定义了 OSS API 的版本号。
*   **`OPEN_SOUND_SYSTEM`**:  一个标识符，表明使用了 OSS。
*   **`SNDCARD_ADLIB`, `SNDCARD_SB`, ..., `SNDCARD_UART401`**:  定义了各种早期声卡型号的枚举值，用于识别不同的硬件。

**2. 定义了用于 ioctl 系统调用的宏和常量:**

*   **`SIOCPARM_MASK`, `SIOC_VOID`, `SIOC_OUT`, `SIOC_IN`, `SIOC_INOUT`, `_SIO`, `_SIOR`, `_SIOW`, `_SIOWR`**: 这些宏定义了构建 `ioctl` 命令所需的位掩码和标志。`ioctl` 是 Linux 中用户空间程序与设备驱动程序通信的主要方式。它们允许用户空间程序向内核发送控制命令和传递数据。

**3. 定义了控制音频序列器 (Sequencer) 的 ioctl 命令:**

*   **`SNDCTL_SEQ_RESET`, `SNDCTL_SEQ_SYNC`, `SNDCTL_SYNTH_INFO`, `SNDCTL_SEQ_CTRLRATE`, ... , `SNDCTL_SEQ_GETTIME`**:  这些常量定义了用于控制音频序列器的 `ioctl` 命令。序列器用于合成和播放 MIDI 音频。这些命令允许应用程序：
    *   重置序列器。
    *   同步序列器。
    *   获取合成器信息。
    *   设置控制速率。
    *   获取输入/输出计数。
    *   加载乐器。
    *   测试 MIDI 设备等。
*   **`struct synth_control`, `struct remove_sample`, `struct seq_event_rec`**:  定义了与序列器 ioctl 命令配合使用的数据结构，用于传递参数。

**4. 定义了控制音频定时器 (Timer) 的 ioctl 命令:**

*   **`SNDCTL_TMR_TIMEBASE`, `SNDCTL_TMR_START`, `SNDCTL_TMR_STOP`, `SNDCTL_TMR_CONTINUE`, `SNDCTL_TMR_TEMPO`, `SNDCTL_TMR_SOURCE`, `SNDCTL_TMR_METRONOME`, `SNDCTL_TMR_SELECT`**:  这些常量定义了用于控制音频定时器的 `ioctl` 命令。定时器用于控制音频事件发生的时间。
*   **`TMR_INTERNAL`, `TMR_EXTERNAL`, `TMR_MODE_MIDI`, `TMR_MODE_FSK`, `TMR_MODE_CLS`, `TMR_MODE_SMPTE`**: 定义了定时器相关的常量，如时钟源和模式。

**5. 定义了音频补丁 (Patch) 和系统专属消息 (Sysex) 的数据结构:**

*   **`struct patch_info`**:  描述了音频采样或乐器的信息，包括采样率、位深度、循环信息等。
*   **`struct sysex_info`**:  用于传递 MIDI 系统专属消息。

**6. 定义了序列器事件的常量:**

*   **`SEQ_NOTEOFF`, `SEQ_NOTEON`, `SEQ_PGMCHANGE`, `SEQ_CONTROLLER`, ...**:  定义了各种 MIDI 和序列器事件类型，例如音符开启/关闭、程序切换、控制器变化等。
*   **`CTL_BANK_SELECT`, `CTL_MODWHEEL`, ...**:  定义了 MIDI 控制器编号。

**7. 定义了合成器 (Synthesizer) 和 MIDI 设备的信息结构:**

*   **`struct sbi_instrument`**:  用于定义 FM 合成器的乐器参数。
*   **`struct synth_info`**:  包含了合成器的名称、类型、支持的特性等信息。
*   **`struct sound_timer_info`**:  包含了音频定时器的信息。
*   **`struct midi_info`**:  包含了 MIDI 设备的名称、类型和能力信息.

**8. 定义了与音频数字信号处理器 (DSP) 交互的 ioctl 命令:**

*   **`SNDCTL_DSP_RESET`, `SNDCTL_DSP_SYNC`, `SNDCTL_DSP_SPEED`, `SNDCTL_DSP_STEREO`, `SNDCTL_DSP_SETFMT`, ...**:  这些常量定义了用于控制 DSP 的 `ioctl` 命令。DSP 负责实际的音频输入和输出。这些命令允许应用程序：
    *   重置 DSP。
    *   同步 DSP。
    *   设置采样率。
    *   设置立体声/单声道模式。
    *   设置采样格式（例如，8位、16位，有符号/无符号）。
    *   获取/设置缓冲区大小。
    *   启动/停止音频输入/输出。
    *   执行内存映射等。
*   **`AFMT_QUERY`, `AFMT_MU_LAW`, `AFMT_A_LAW`, `AFMT_U8`, `AFMT_S16_LE`, ...**: 定义了各种音频格式。
*   **`struct audio_buf_info`**:  描述了音频缓冲区的信息。
*   **`DSP_CAP_REVISION`, `DSP_CAP_DUPLEX`, ...**:  定义了 DSP 设备的能力标志。
*   **`struct count_info`**:  用于获取 DSP 输入/输出的指针信息。
*   **`struct buffmem_desc`**:  用于描述内存映射的缓冲区。

**9. 定义了控制音频协处理器 (Coprocessor) 的 ioctl 命令:**

*   **`SNDCTL_COPR_RESET`, `SNDCTL_COPR_LOAD`, `SNDCTL_COPR_RDATA`, ...**:  用于控制一些声卡上集成的音频协处理器。

**10. 定义了音频混音器 (Mixer) 的常量和 ioctl 命令:**

*   **`SOUND_MIXER_NRDEVICES`, `SOUND_MIXER_VOLUME`, `SOUND_MIXER_BASS`, ..., `SOUND_MIXER_MONITOR`**:  定义了各种混音器控制项，例如主音量、低音、高音、各种音频输入/输出源的音量等。
*   **`MIXER_READ(dev)`, `MIXER_WRITE(dev)`**:  定义了用于读取和写入混音器控制项的宏。
*   **`SOUND_MIXER_READ_VOLUME`, `SOUND_MIXER_WRITE_VOLUME`, ...**:  使用 `MIXER_READ` 和 `MIXER_WRITE` 宏定义的具体混音器控制项的读取和写入常量。
*   **`struct mixer_info`, `struct _old_mixer_info`**:  包含了混音器的信息，例如 ID 和名称.
*   **`struct mixer_vol_table`**:  用于批量获取和设置混音器级别。

**11. 定义了其他常量:**

*   **`OSS_GETVERSION`**:  用于获取 OSS API 版本的 ioctl 命令。
*   **`EV_SEQ_LOCAL`, `EV_TIMING`, `EV_CHN_COMMON`, `EV_CHN_VOICE`, `EV_SYSEX`**: 定义了序列器事件的原始类型。
*   **`MIDI_NOTEOFF`, `MIDI_NOTEON`, ...**: 定义了标准的 MIDI 消息类型。
*   **`TMR_WAIT_REL`, `TMR_WAIT_ABS`, ...**: 定义了定时器事件类型。
*   **`LOCL_STARTAUDIO`**: 定义了一个本地序列器事件。

**12. 定义了用于操作序列器缓冲区的宏:**

*   **`SEQ_DECLAREBUF()`, `SEQ_DEFINEBUF(len)`, `_SEQ_NEEDBUF(len)`, `_SEQ_ADVBUF(len)`, `SEQ_DUMPBUF`**:  这些宏提供了一种在用户空间管理序列器事件缓冲区的便捷方式。

**13. 定义了用于生成序列器事件的宏:**

*   **`SEQ_VOLUME_MODE`, `_CHN_VOICE`, `SEQ_START_NOTE`, `SEQ_STOP_NOTE`, `SEQ_PGM_CHANGE`, `SEQ_CONTROL`, `SEQ_BENDER`, `SEQ_START_TIMER`, `SEQ_STOP_TIMER`, `SEQ_WAIT_TIME`, `SEQ_MIDIOUT` 等**: 这些宏简化了构建序列器事件的过程，并将其添加到缓冲区中。

## 与 Android 功能的关系及举例说明

由于该头文件位于 `bionic` 库中，这意味着 Android 系统的底层音频功能（特别是与旧的硬件或兼容层相关的功能）可能会涉及到这些定义。虽然 Android 主要使用 ALSA 作为其主要的音频子系统，但在某些情况下，为了兼容旧的应用程序或硬件，可能会使用或模拟 OSS API。

**举例说明:**

*   **音频播放和录制 (DSP 部分):**  Android 的 NDK (Native Development Kit) 开发者可以使用底层的 POSIX 文件操作（如 `open()`, `ioctl()`, `read()`, `write()`）来直接与音频设备交互。例如，一个 NDK 应用可能打开 `/dev/dsp` 设备文件，并使用 `SNDCTL_DSP_SPEED` 来设置采样率，使用 `SNDCTL_DSP_SETFMT` 来设置音频格式，然后通过 `write()` 系统调用向设备写入音频数据进行播放，或使用 `read()` 读取音频数据进行录制。

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <linux/soundcard.h>

    int main() {
        int audio_fd = open("/dev/dsp", O_RDWR);
        if (audio_fd < 0) {
            perror("打开 /dev/dsp 失败");
            return 1;
        }

        int sample_rate = 44100;
        if (ioctl(audio_fd, SNDCTL_DSP_SPEED, &sample_rate) == -1) {
            perror("设置采样率失败");
            close(audio_fd);
            return 1;
        }

        int format = AFMT_S16_LE;
        if (ioctl(audio_fd, SNDCTL_DSP_SETFMT, &format) == -1) {
            perror("设置音频格式失败");
            close(audio_fd);
            return 1;
        }

        // ... 进行音频数据的读取或写入 ...

        close(audio_fd);
        return 0;
    }
    ```

*   **MIDI 功能 (Sequencer 部分):**  虽然 Android 现在有自己的 MIDI API，但早期的 MIDI 支持或者某些兼容层可能会使用 OSS 的序列器接口。一个应用程序可能会打开 `/dev/sequencer` 设备文件，并使用 `SNDCTL_SYNTH_INFO` 获取合成器信息，或者使用 `SEQ_PGM_CHANGE` 宏来发送 MIDI 程序切换消息。

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <linux/soundcard.h>

    int main() {
        int seq_fd = open("/dev/sequencer", O_RDWR);
        if (seq_fd < 0) {
            perror("打开 /dev/sequencer 失败");
            return 1;
        }

        struct synth_info sinfo;
        if (ioctl(seq_fd, SNDCTL_SYNTH_INFO, &sinfo) == -1) {
            perror("获取合成器信息失败");
            close(seq_fd);
            return 1;
        }
        printf("合成器名称: %s\n", sinfo.name);

        // ... 发送 MIDI 消息 ...
        unsigned char buffer[8];
        buffer[0] = EV_CHN_COMMON;
        buffer[1] = 0; // 设备号
        buffer[2] = MIDI_PGM_CHANGE;
        buffer[3] = 0; // 通道号
        buffer[4] = 10; // 乐器编号
        buffer[5] = 0;
        buffer[6] = 0;
        buffer[7] = 0;
        write(seq_fd, buffer, 8);

        close(seq_fd);
        return 0;
    }
    ```

*   **混音器控制 (Mixer 部分):**  Android 系统或某些音频应用可能使用混音器接口来调整音量。例如，系统设置中的音量滑块最终可能会调用底层的 `ioctl` 命令，使用 `SOUND_MIXER_WRITE_PCM` 来设置 PCM 音频的音量。

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <linux/soundcard.h>

    int main() {
        int mixer_fd = open("/dev/mixer", O_RDWR);
        if (mixer_fd < 0) {
            perror("打开 /dev/mixer 失败");
            return 1;
        }

        int volume = (75 << 8) | 75; // 设置左右声道音量为 75% (假设范围是 0-100)
        if (ioctl(mixer_fd, SOUND_MIXER_WRITE_PCM, &volume) == -1) {
            perror("设置 PCM 音量失败");
            close(mixer_fd);
            return 1;
        }

        close(mixer_fd);
        return 0;
    }
    ```

**需要注意的是，现代 Android 应用通常会使用更高层次的 Android SDK 提供的音频 API (如 `android.media.AudioTrack`, `android.media.MediaRecorder`, `android.media.AudioManager`)，而不是直接操作这些底层的 OSS 接口。**  这些高层 API 在底层可能会使用 ALSA 或其他更现代的音频架构，并提供更抽象和易于使用的接口。  `soundcard.h` 的存在更多是为了兼容性和某些特定的低级别操作。

## libc 函数的功能实现

这个头文件本身 **没有实现任何 libc 函数**。它只是定义了常量、宏和数据结构。

真正与硬件交互的是 **设备驱动程序** 和 **内核**。  用户空间程序通过 `ioctl` 系统调用与设备驱动程序通信。

**`ioctl` 函数的简要功能实现：**

1. 用户空间程序调用 `ioctl(fd, request, argp)`。
2. 系统调用陷入内核。
3. 内核根据文件描述符 `fd` 找到对应的设备驱动程序。
4. 内核根据 `request` (一个整数，通常由 `_IO`, `_IOR`, `_IOW`, `_IOWR` 等宏生成) 确定要执行的操作。
5. 内核将 `argp` 指向的数据传递给设备驱动程序，或者从设备驱动程序接收数据。
6. 设备驱动程序执行相应的硬件操作。
7. 内核将结果返回给用户空间程序。

在这个 `soundcard.h` 文件中，`_SIO`, `_SIOR`, `_SIOW`, `_SIOWR` 宏是用来辅助生成 `ioctl` 系统调用的 `request` 参数的。  它们并不直接实现任何功能，而是方便程序员构建正确的 `ioctl` 命令。

例如，`_SIOWR('Q', 2, struct synth_info)` 宏展开后会生成一个整数值，这个整数编码了以下信息：

*   操作方向：读写 (`_IOWR`)
*   幻数： `'Q'`
*   命令编号： `2`
*   数据大小： `sizeof(struct synth_info)`

当用户空间程序调用 `ioctl(fd, SNDCTL_SYNTH_INFO, &my_synth_info)` 时，`SNDCTL_SYNTH_INFO` 实际上就是由 `_SIOWR` 宏生成的那个整数。内核会解析这个整数，并调用声卡驱动程序中处理幻数 `'Q'` 和命令编号 `2` 的函数，并将 `my_synth_info` 结构体的地址传递给驱动程序。

## 涉及 dynamic linker 的功能

这个头文件本身 **不直接涉及 dynamic linker 的功能**。  它定义的是与内核交互的接口。

但是，如果一个应用程序使用了这个头文件中定义的常量和结构体，那么在编译和链接时，它会链接到包含 `ioctl` 函数以及其他相关支持函数的 C 库 (`libc.so` 在 Android 上是 `bionic`)。

**so 布局样本 (以 bionic 的 libc.so 为例):**

```
libc.so (bionic):
    .interp        # 指示动态链接器路径
    .note.android.ident
    .gnu.hash
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .rel.dyn       # 动态重定位表
    .rel.plt       # PLT 重定位表
    .plt           # 过程链接表 (PLT)
    .text          # 代码段 (包含 ioctl 等函数的实现)
    .rodata        # 只读数据段
    .data          # 数据段
    .bss           # 未初始化数据段
    .dynamic       # 动态链接信息

    # ... 其他段 ...

    # 导出符号 (部分):
    ioctl
    open
    read
    write
    # ... 其他 libc 函数 ...
```

**链接的处理过程:**

1. **编译时:** 编译器看到代码中使用了 `ioctl` 函数和 `linux/soundcard.h` 中定义的常量，它会将其标记为需要链接的符号。
2. **链接时:** 链接器 (在 Android 上通常是 `lld`) 会查找提供这些符号的共享库。在这种情况下，`ioctl` 函数来自 `libc.so`。
3. **生成可执行文件:** 链接器会将对 `ioctl` 的调用放入可执行文件的 `.plt` (Procedure Linkage Table) 段，并将重定位信息放入 `.rel.plt` 段。
4. **运行时:**
    *   当加载器加载可执行文件时，它会读取 `.interp` 段，找到动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`)。
    *   动态链接器加载所有需要的共享库 (包括 `libc.so`) 到内存中。
    *   动态链接器会处理 `.rel.plt` 中的重定位信息。对于 `ioctl` 函数的调用，动态链接器会在 `libc.so` 的 `.dynsym` (动态符号表) 中查找 `ioctl` 的地址，并更新 `.plt` 中的条目，使其指向 `libc.so` 中 `ioctl` 函数的实际地址。
    *   当程序执行到调用 `ioctl` 的地方时，它会跳转到 `.plt` 中已更新的地址，从而执行 `libc.so` 中的 `ioctl` 函数。

## 逻辑推理的假设输入与输出

由于这个文件主要是定义常量和结构体，不包含可执行的逻辑，因此直接进行逻辑推理的假设输入和输出不太适用。

**可以针对特定的 `ioctl` 调用进行逻辑推理的示例：**

**假设输入:**

*   打开了 `/dev/mixer` 设备文件，文件描述符为 `mixer_fd`。
*   要设置 PCM 音量的目标值为 75% (假设编码为左右声道各 75，即 `(75 << 8) | 75`)，存储在变量 `volume` 中。

**执行的 `ioctl` 调用:**

```c
ioctl(mixer_fd, SOUND_MIXER_WRITE_PCM, &volume);
```

**逻辑推理和可能的输出:**

1. `ioctl` 系统调用被触发。
2. 内核找到 `/dev/mixer` 对应的混音器驱动程序。
3. 内核将 `SOUND_MIXER_WRITE_PCM` 命令和 `volume` 变量的值传递给混音器驱动程序。
4. 混音器驱动程序根据 `volume` 的值，设置硬件混音器的 PCM 音量寄存器。
5. **如果成功:** `ioctl` 返回 0。
6. **如果失败 (例如，设备不支持音量控制，权限不足等):** `ioctl` 返回 -1，并设置 `errno` 变量指示错误类型 (例如 `ENODEV`, `EACCES`, `EINVAL`)。  应用程序可以通过 `perror` 或检查 `errno` 来获取错误信息。

**示例代码和可能的输出:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/soundcard.h>
#include <errno.h>

int main() {
    int mixer_fd = open("/dev/mixer", O_RDWR);
    if (mixer_fd < 0) {
        perror("打开 /dev/mixer 失败");
        return 1;
    }

    int volume = (75 << 8) | 75;
    if (ioctl(mixer_fd, SOUND_MIXER_WRITE_PCM, &volume) == -1) {
        perror("设置 PCM 音量失败");
        printf("错误码: %d\n", errno);
        close(mixer_fd);
        return 1;
    }

    printf("成功设置 PCM 音量为 75%%\n");
    close(mixer_fd);
    return 0;
}
```

**可能的输出:**

*   **成功:**
    ```
    成功设置 PCM 音量为 75%
    ```
*   **失败 (例如，设备不支持):**
    ```
    打开 /dev/mixer 失败: No such device or address
    ```
    或
    ```
    设置 PCM 音量失败: Invalid argument
    错误码: 22
    ```

## 用户或编程常见的使用错误

1. **使用了错误的 ioctl 命令:**  例如，将用于 DSP 的 ioctl 命令用于 Mixer 设备文件，或者使用了拼写错误的常量名。这会导致 `ioctl` 返回 -1，`errno` 通常设置为 `EINVAL`。

    ```c
    int dsp_fd = open("/dev/dsp", O_RDWR);
    int volume = (50 << 8) | 50;
    if (ioctl(dsp_fd, SOUND_MIXER_WRITE_PCM, &volume) == -1) { // 错误：混音器命令用于 DSP
        perror("错误：尝试在 DSP 设备上设置混音器音量");
    }
    close(dsp_fd);
    ```

2. **传递了错误的数据结构或数据大小:**  某些 `ioctl` 命令需要传递指向特定数据结构的指针。如果传递了错误类型的指针或结构体大小不匹配，会导致 `ioctl` 返回错误。

    ```c
    struct synth_info wrong_struct;
    if (ioctl(seq_fd, SNDCTL_MIDI_INFO, &wrong_struct) == -1) { // 错误：使用了错误的结构体
        perror("错误：传递了错误的结构体给 ioctl");
    }
    ```

3. **没有正确处理 `ioctl` 的返回值和 `errno`:**  `ioctl` 返回 -1 表示出错，但程序员需要检查 `errno` 来确定具体的错误原因，并进行相应的处理。忽略错误返回值可能导致程序行为异常。

    ```c
    int fd = open("/dev/dsp", O_RDWR);
    int rate = 44100;
    ioctl(fd, SNDCTL_DSP_SPEED, &rate); // 潜在错误：没有检查 ioctl 的返回值
    // ... 假设设置成功继续操作 ...
    ```

4. **权限问题:**  访问音频设备文件通常需要特定的权限。如果用户运行的程序没有足够的权限，`open()` 或 `ioctl()` 调用可能会失败，`errno` 设置为 `EACCES` 或 `EPERM`。

5. **设备文件不存在或驱动未加载:**  如果尝试打开 `/dev/dsp`, `/dev/mixer`, `/dev/sequencer` 等设备文件时，文件不存在，或者相关的声卡驱动程序没有加载，`open()` 调用会失败，`errno` 设置为 `ENOENT` 或 `ENODEV`。

6. **多线程竞争:**  在多线程应用程序中，如果多个线程同时访问同一个音频设备文件，可能会导致冲突和错误。需要使用互斥锁等同步机制来保护对设备文件的访问。

7. **不正确的音频格式或参数:**  在设置 DSP 参数时，例如采样率、采样格式、声道数等，如果设置的值与硬件不支持的值不匹配，`ioctl` 调用可能会失败。

## Android framework 或 ndk 是如何一步步的到达这里

以音频播放为例，从 Android framework 到达 `soundcard.h` 定义的 ioctl 的步骤大致如下：

1. **Java Framework 层:**  应用程序使用 `android.media.AudioTrack` 类来播放音频。

    ```java
    AudioTrack audioTrack = new AudioTrack.Builder()
            .setAudioAttributes(new AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                    .build())
            .setAudioFormat(new AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(44100)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_STEREO)
                    .build())
            .setBufferSizeInBytes(bufferSize)
            .setTransferMode(AudioTrack.MODE_STREAM)
            .build();
    audioTrack.play();
    audioTrack.write(audioData, 0, audioData.length);
    ```

2. **Native 代码层 (frameworks/av/media/):** `AudioTrack` 类的方法调用会通过 JNI (Java Native Interface) 调用到 C++ 代码，例如 `frameworks/av/media/libaudioclient/AudioTrack.cpp`。

3. **AudioFlinger 服务:**  `AudioTrack` 的 native 代码会与 `AudioFlinger` 服务进行交互。`AudioFlinger` 是 Android 音
Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/soundcard.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPISOUNDCARD_H
#define _UAPISOUNDCARD_H
#define SOUND_VERSION 0x030802
#define OPEN_SOUND_SYSTEM
#include <linux/ioctl.h>
#include <endian.h>
#define SNDCARD_ADLIB 1
#define SNDCARD_SB 2
#define SNDCARD_PAS 3
#define SNDCARD_GUS 4
#define SNDCARD_MPU401 5
#define SNDCARD_SB16 6
#define SNDCARD_SB16MIDI 7
#define SNDCARD_UART6850 8
#define SNDCARD_GUS16 9
#define SNDCARD_MSS 10
#define SNDCARD_PSS 11
#define SNDCARD_SSCAPE 12
#define SNDCARD_PSS_MPU 13
#define SNDCARD_PSS_MSS 14
#define SNDCARD_SSCAPE_MSS 15
#define SNDCARD_TRXPRO 16
#define SNDCARD_TRXPRO_SB 17
#define SNDCARD_TRXPRO_MPU 18
#define SNDCARD_MAD16 19
#define SNDCARD_MAD16_MPU 20
#define SNDCARD_CS4232 21
#define SNDCARD_CS4232_MPU 22
#define SNDCARD_MAUI 23
#define SNDCARD_PSEUDO_MSS 24
#define SNDCARD_GUSPNP 25
#define SNDCARD_UART401 26
#ifndef _SIOWR
#if defined(_IOWR) && (defined(_AIX) || !defined(sun) && !defined(sparc) && !defined(__sparc__) && !defined(__INCioctlh) && !defined(__Lynx__))
#define SIOCPARM_MASK IOCPARM_MASK
#define SIOC_VOID IOC_VOID
#define SIOC_OUT IOC_OUT
#define SIOC_IN IOC_IN
#define SIOC_INOUT IOC_INOUT
#define _SIOC_SIZE _IOC_SIZE
#define _SIOC_DIR _IOC_DIR
#define _SIOC_NONE _IOC_NONE
#define _SIOC_READ _IOC_READ
#define _SIOC_WRITE _IOC_WRITE
#define _SIO _IO
#define _SIOR _IOR
#define _SIOW _IOW
#define _SIOWR _IOWR
#else
#define SIOCPARM_MASK 0x1fff
#define SIOC_VOID 0x00000000
#define SIOC_OUT 0x20000000
#define SIOC_IN 0x40000000
#define SIOC_INOUT (SIOC_IN | SIOC_OUT)
#define _SIO(x,y) ((int) (SIOC_VOID | (x << 8) | y))
#define _SIOR(x,y,t) ((int) (SIOC_OUT | ((sizeof(t) & SIOCPARM_MASK) << 16) | (x << 8) | y))
#define _SIOW(x,y,t) ((int) (SIOC_IN | ((sizeof(t) & SIOCPARM_MASK) << 16) | (x << 8) | y))
#define _SIOWR(x,y,t) ((int) (SIOC_INOUT | ((sizeof(t) & SIOCPARM_MASK) << 16) | (x << 8) | y))
#define _SIOC_SIZE(x) ((x >> 16) & SIOCPARM_MASK)
#define _SIOC_DIR(x) (x & 0xf0000000)
#define _SIOC_NONE SIOC_VOID
#define _SIOC_READ SIOC_OUT
#define _SIOC_WRITE SIOC_IN
#endif
#endif
#define SNDCTL_SEQ_RESET _SIO('Q', 0)
#define SNDCTL_SEQ_SYNC _SIO('Q', 1)
#define SNDCTL_SYNTH_INFO _SIOWR('Q', 2, struct synth_info)
#define SNDCTL_SEQ_CTRLRATE _SIOWR('Q', 3, int)
#define SNDCTL_SEQ_GETOUTCOUNT _SIOR('Q', 4, int)
#define SNDCTL_SEQ_GETINCOUNT _SIOR('Q', 5, int)
#define SNDCTL_SEQ_PERCMODE _SIOW('Q', 6, int)
#define SNDCTL_FM_LOAD_INSTR _SIOW('Q', 7, struct sbi_instrument)
#define SNDCTL_SEQ_TESTMIDI _SIOW('Q', 8, int)
#define SNDCTL_SEQ_RESETSAMPLES _SIOW('Q', 9, int)
#define SNDCTL_SEQ_NRSYNTHS _SIOR('Q', 10, int)
#define SNDCTL_SEQ_NRMIDIS _SIOR('Q', 11, int)
#define SNDCTL_MIDI_INFO _SIOWR('Q', 12, struct midi_info)
#define SNDCTL_SEQ_THRESHOLD _SIOW('Q', 13, int)
#define SNDCTL_SYNTH_MEMAVL _SIOWR('Q', 14, int)
#define SNDCTL_FM_4OP_ENABLE _SIOW('Q', 15, int)
#define SNDCTL_SEQ_PANIC _SIO('Q', 17)
#define SNDCTL_SEQ_OUTOFBAND _SIOW('Q', 18, struct seq_event_rec)
#define SNDCTL_SEQ_GETTIME _SIOR('Q', 19, int)
#define SNDCTL_SYNTH_ID _SIOWR('Q', 20, struct synth_info)
#define SNDCTL_SYNTH_CONTROL _SIOWR('Q', 21, struct synth_control)
#define SNDCTL_SYNTH_REMOVESAMPLE _SIOWR('Q', 22, struct remove_sample)
typedef struct synth_control {
  int devno;
  char data[4000];
} synth_control;
typedef struct remove_sample {
  int devno;
  int bankno;
  int instrno;
} remove_sample;
typedef struct seq_event_rec {
  unsigned char arr[8];
} seq_event_rec;
#define SNDCTL_TMR_TIMEBASE _SIOWR('T', 1, int)
#define SNDCTL_TMR_START _SIO('T', 2)
#define SNDCTL_TMR_STOP _SIO('T', 3)
#define SNDCTL_TMR_CONTINUE _SIO('T', 4)
#define SNDCTL_TMR_TEMPO _SIOWR('T', 5, int)
#define SNDCTL_TMR_SOURCE _SIOWR('T', 6, int)
#define TMR_INTERNAL 0x00000001
#define TMR_EXTERNAL 0x00000002
#define TMR_MODE_MIDI 0x00000010
#define TMR_MODE_FSK 0x00000020
#define TMR_MODE_CLS 0x00000040
#define TMR_MODE_SMPTE 0x00000080
#define SNDCTL_TMR_METRONOME _SIOW('T', 7, int)
#define SNDCTL_TMR_SELECT _SIOW('T', 8, int)
#define _LINUX_PATCHKEY_H_INDIRECT
#include <linux/patchkey.h>
#undef _LINUX_PATCHKEY_H_INDIRECT
#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
#define AFMT_S16_NE AFMT_S16_BE
#elif __BYTE_ORDER==__LITTLE_ENDIAN
#define AFMT_S16_NE AFMT_S16_LE
#else
#error "could not determine byte order"
#endif
#endif
struct patch_info {
  unsigned short key;
#define WAVE_PATCH _PATCHKEY(0x04)
#define GUS_PATCH WAVE_PATCH
#define WAVEFRONT_PATCH _PATCHKEY(0x06)
  short device_no;
  short instr_no;
  unsigned int mode;
#define WAVE_16_BITS 0x01
#define WAVE_UNSIGNED 0x02
#define WAVE_LOOPING 0x04
#define WAVE_BIDIR_LOOP 0x08
#define WAVE_LOOP_BACK 0x10
#define WAVE_SUSTAIN_ON 0x20
#define WAVE_ENVELOPES 0x40
#define WAVE_FAST_RELEASE 0x80
#define WAVE_VIBRATO 0x00010000
#define WAVE_TREMOLO 0x00020000
#define WAVE_SCALE 0x00040000
#define WAVE_FRACTIONS 0x00080000
#define WAVE_ROM 0x40000000
#define WAVE_MULAW 0x20000000
  int len;
  int loop_start, loop_end;
  unsigned int base_freq;
  unsigned int base_note;
  unsigned int high_note;
  unsigned int low_note;
  int panning;
  int detuning;
  unsigned char env_rate[6];
  unsigned char env_offset[6];
  unsigned char tremolo_sweep;
  unsigned char tremolo_rate;
  unsigned char tremolo_depth;
  unsigned char vibrato_sweep;
  unsigned char vibrato_rate;
  unsigned char vibrato_depth;
  int scale_frequency;
  unsigned int scale_factor;
  int volume;
  int fractions;
  int reserved1;
  int spare[2];
  char data[1];
};
struct sysex_info {
  short key;
#define SYSEX_PATCH _PATCHKEY(0x05)
#define MAUI_PATCH _PATCHKEY(0x06)
  short device_no;
  int len;
  unsigned char data[1];
};
#define SEQ_NOTEOFF 0
#define SEQ_FMNOTEOFF SEQ_NOTEOFF
#define SEQ_NOTEON 1
#define SEQ_FMNOTEON SEQ_NOTEON
#define SEQ_WAIT TMR_WAIT_ABS
#define SEQ_PGMCHANGE 3
#define SEQ_FMPGMCHANGE SEQ_PGMCHANGE
#define SEQ_SYNCTIMER TMR_START
#define SEQ_MIDIPUTC 5
#define SEQ_DRUMON 6
#define SEQ_DRUMOFF 7
#define SEQ_ECHO TMR_ECHO
#define SEQ_AFTERTOUCH 9
#define SEQ_CONTROLLER 10
#define CTL_BANK_SELECT 0x00
#define CTL_MODWHEEL 0x01
#define CTL_BREATH 0x02
#define CTL_FOOT 0x04
#define CTL_PORTAMENTO_TIME 0x05
#define CTL_DATA_ENTRY 0x06
#define CTL_MAIN_VOLUME 0x07
#define CTL_BALANCE 0x08
#define CTL_PAN 0x0a
#define CTL_EXPRESSION 0x0b
#define CTL_GENERAL_PURPOSE1 0x10
#define CTL_GENERAL_PURPOSE2 0x11
#define CTL_GENERAL_PURPOSE3 0x12
#define CTL_GENERAL_PURPOSE4 0x13
#define CTL_DAMPER_PEDAL 0x40
#define CTL_SUSTAIN 0x40
#define CTL_HOLD 0x40
#define CTL_PORTAMENTO 0x41
#define CTL_SOSTENUTO 0x42
#define CTL_SOFT_PEDAL 0x43
#define CTL_HOLD2 0x45
#define CTL_GENERAL_PURPOSE5 0x50
#define CTL_GENERAL_PURPOSE6 0x51
#define CTL_GENERAL_PURPOSE7 0x52
#define CTL_GENERAL_PURPOSE8 0x53
#define CTL_EXT_EFF_DEPTH 0x5b
#define CTL_TREMOLO_DEPTH 0x5c
#define CTL_CHORUS_DEPTH 0x5d
#define CTL_DETUNE_DEPTH 0x5e
#define CTL_CELESTE_DEPTH 0x5e
#define CTL_PHASER_DEPTH 0x5f
#define CTL_DATA_INCREMENT 0x60
#define CTL_DATA_DECREMENT 0x61
#define CTL_NONREG_PARM_NUM_LSB 0x62
#define CTL_NONREG_PARM_NUM_MSB 0x63
#define CTL_REGIST_PARM_NUM_LSB 0x64
#define CTL_REGIST_PARM_NUM_MSB 0x65
#define CTRL_PITCH_BENDER 255
#define CTRL_PITCH_BENDER_RANGE 254
#define CTRL_EXPRESSION 253
#define CTRL_MAIN_VOLUME 252
#define SEQ_BALANCE 11
#define SEQ_VOLMODE 12
#define VOL_METHOD_ADAGIO 1
#define VOL_METHOD_LINEAR 2
#define SEQ_FULLSIZE 0xfd
#define SEQ_PRIVATE 0xfe
#define SEQ_EXTENDED 0xff
typedef unsigned char sbi_instr_data[32];
struct sbi_instrument {
  unsigned short key;
#define FM_PATCH _PATCHKEY(0x01)
#define OPL3_PATCH _PATCHKEY(0x03)
  short device;
  int channel;
  sbi_instr_data operators;
};
struct synth_info {
  char name[30];
  int device;
  int synth_type;
#define SYNTH_TYPE_FM 0
#define SYNTH_TYPE_SAMPLE 1
#define SYNTH_TYPE_MIDI 2
  int synth_subtype;
#define FM_TYPE_ADLIB 0x00
#define FM_TYPE_OPL3 0x01
#define MIDI_TYPE_MPU401 0x401
#define SAMPLE_TYPE_BASIC 0x10
#define SAMPLE_TYPE_GUS SAMPLE_TYPE_BASIC
#define SAMPLE_TYPE_WAVEFRONT 0x11
  int perc_mode;
  int nr_voices;
  int nr_drums;
  int instr_bank_size;
  unsigned int capabilities;
#define SYNTH_CAP_PERCMODE 0x00000001
#define SYNTH_CAP_OPL3 0x00000002
#define SYNTH_CAP_INPUT 0x00000004
  int dummies[19];
};
struct sound_timer_info {
  char name[32];
  int caps;
};
#define MIDI_CAP_MPU401 1
struct midi_info {
  char name[30];
  int device;
  unsigned int capabilities;
  int dev_type;
  int dummies[18];
};
typedef struct {
  unsigned char cmd;
  char nr_args, nr_returns;
  unsigned char data[30];
} mpu_command_rec;
#define SNDCTL_MIDI_PRETIME _SIOWR('m', 0, int)
#define SNDCTL_MIDI_MPUMODE _SIOWR('m', 1, int)
#define SNDCTL_MIDI_MPUCMD _SIOWR('m', 2, mpu_command_rec)
#define SNDCTL_DSP_RESET _SIO('P', 0)
#define SNDCTL_DSP_SYNC _SIO('P', 1)
#define SNDCTL_DSP_SPEED _SIOWR('P', 2, int)
#define SNDCTL_DSP_STEREO _SIOWR('P', 3, int)
#define SNDCTL_DSP_GETBLKSIZE _SIOWR('P', 4, int)
#define SNDCTL_DSP_SAMPLESIZE SNDCTL_DSP_SETFMT
#define SNDCTL_DSP_CHANNELS _SIOWR('P', 6, int)
#define SOUND_PCM_WRITE_CHANNELS SNDCTL_DSP_CHANNELS
#define SOUND_PCM_WRITE_FILTER _SIOWR('P', 7, int)
#define SNDCTL_DSP_POST _SIO('P', 8)
#define SNDCTL_DSP_SUBDIVIDE _SIOWR('P', 9, int)
#define SNDCTL_DSP_SETFRAGMENT _SIOWR('P', 10, int)
#define SNDCTL_DSP_GETFMTS _SIOR('P', 11, int)
#define SNDCTL_DSP_SETFMT _SIOWR('P', 5, int)
#define AFMT_QUERY 0x00000000
#define AFMT_MU_LAW 0x00000001
#define AFMT_A_LAW 0x00000002
#define AFMT_IMA_ADPCM 0x00000004
#define AFMT_U8 0x00000008
#define AFMT_S16_LE 0x00000010
#define AFMT_S16_BE 0x00000020
#define AFMT_S8 0x00000040
#define AFMT_U16_LE 0x00000080
#define AFMT_U16_BE 0x00000100
#define AFMT_MPEG 0x00000200
#define AFMT_AC3 0x00000400
typedef struct audio_buf_info {
  int fragments;
  int fragstotal;
  int fragsize;
  int bytes;
} audio_buf_info;
#define SNDCTL_DSP_GETOSPACE _SIOR('P', 12, audio_buf_info)
#define SNDCTL_DSP_GETISPACE _SIOR('P', 13, audio_buf_info)
#define SNDCTL_DSP_NONBLOCK _SIO('P', 14)
#define SNDCTL_DSP_GETCAPS _SIOR('P', 15, int)
#define DSP_CAP_REVISION 0x000000ff
#define DSP_CAP_DUPLEX 0x00000100
#define DSP_CAP_REALTIME 0x00000200
#define DSP_CAP_BATCH 0x00000400
#define DSP_CAP_COPROC 0x00000800
#define DSP_CAP_TRIGGER 0x00001000
#define DSP_CAP_MMAP 0x00002000
#define DSP_CAP_MULTI 0x00004000
#define DSP_CAP_BIND 0x00008000
#define SNDCTL_DSP_GETTRIGGER _SIOR('P', 16, int)
#define SNDCTL_DSP_SETTRIGGER _SIOW('P', 16, int)
#define PCM_ENABLE_INPUT 0x00000001
#define PCM_ENABLE_OUTPUT 0x00000002
typedef struct count_info {
  int bytes;
  int blocks;
  int ptr;
} count_info;
#define SNDCTL_DSP_GETIPTR _SIOR('P', 17, count_info)
#define SNDCTL_DSP_GETOPTR _SIOR('P', 18, count_info)
typedef struct buffmem_desc {
  unsigned * buffer;
  int size;
} buffmem_desc;
#define SNDCTL_DSP_MAPINBUF _SIOR('P', 19, buffmem_desc)
#define SNDCTL_DSP_MAPOUTBUF _SIOR('P', 20, buffmem_desc)
#define SNDCTL_DSP_SETSYNCRO _SIO('P', 21)
#define SNDCTL_DSP_SETDUPLEX _SIO('P', 22)
#define SNDCTL_DSP_GETODELAY _SIOR('P', 23, int)
#define SNDCTL_DSP_GETCHANNELMASK _SIOWR('P', 64, int)
#define SNDCTL_DSP_BIND_CHANNEL _SIOWR('P', 65, int)
#define DSP_BIND_QUERY 0x00000000
#define DSP_BIND_FRONT 0x00000001
#define DSP_BIND_SURR 0x00000002
#define DSP_BIND_CENTER_LFE 0x00000004
#define DSP_BIND_HANDSET 0x00000008
#define DSP_BIND_MIC 0x00000010
#define DSP_BIND_MODEM1 0x00000020
#define DSP_BIND_MODEM2 0x00000040
#define DSP_BIND_I2S 0x00000080
#define DSP_BIND_SPDIF 0x00000100
#define SNDCTL_DSP_SETSPDIF _SIOW('P', 66, int)
#define SNDCTL_DSP_GETSPDIF _SIOR('P', 67, int)
#define SPDIF_PRO 0x0001
#define SPDIF_N_AUD 0x0002
#define SPDIF_COPY 0x0004
#define SPDIF_PRE 0x0008
#define SPDIF_CC 0x07f0
#define SPDIF_L 0x0800
#define SPDIF_DRS 0x4000
#define SPDIF_V 0x8000
#define SNDCTL_DSP_PROFILE _SIOW('P', 23, int)
#define APF_NORMAL 0
#define APF_NETWORK 1
#define APF_CPUINTENS 2
#define SOUND_PCM_READ_RATE _SIOR('P', 2, int)
#define SOUND_PCM_READ_CHANNELS _SIOR('P', 6, int)
#define SOUND_PCM_READ_BITS _SIOR('P', 5, int)
#define SOUND_PCM_READ_FILTER _SIOR('P', 7, int)
#define SOUND_PCM_WRITE_BITS SNDCTL_DSP_SETFMT
#define SOUND_PCM_WRITE_RATE SNDCTL_DSP_SPEED
#define SOUND_PCM_POST SNDCTL_DSP_POST
#define SOUND_PCM_RESET SNDCTL_DSP_RESET
#define SOUND_PCM_SYNC SNDCTL_DSP_SYNC
#define SOUND_PCM_SUBDIVIDE SNDCTL_DSP_SUBDIVIDE
#define SOUND_PCM_SETFRAGMENT SNDCTL_DSP_SETFRAGMENT
#define SOUND_PCM_GETFMTS SNDCTL_DSP_GETFMTS
#define SOUND_PCM_SETFMT SNDCTL_DSP_SETFMT
#define SOUND_PCM_GETOSPACE SNDCTL_DSP_GETOSPACE
#define SOUND_PCM_GETISPACE SNDCTL_DSP_GETISPACE
#define SOUND_PCM_NONBLOCK SNDCTL_DSP_NONBLOCK
#define SOUND_PCM_GETCAPS SNDCTL_DSP_GETCAPS
#define SOUND_PCM_GETTRIGGER SNDCTL_DSP_GETTRIGGER
#define SOUND_PCM_SETTRIGGER SNDCTL_DSP_SETTRIGGER
#define SOUND_PCM_SETSYNCRO SNDCTL_DSP_SETSYNCRO
#define SOUND_PCM_GETIPTR SNDCTL_DSP_GETIPTR
#define SOUND_PCM_GETOPTR SNDCTL_DSP_GETOPTR
#define SOUND_PCM_MAPINBUF SNDCTL_DSP_MAPINBUF
#define SOUND_PCM_MAPOUTBUF SNDCTL_DSP_MAPOUTBUF
typedef struct copr_buffer {
  int command;
  int flags;
#define CPF_NONE 0x0000
#define CPF_FIRST 0x0001
#define CPF_LAST 0x0002
  int len;
  int offs;
  unsigned char data[4000];
} copr_buffer;
typedef struct copr_debug_buf {
  int command;
  int parm1;
  int parm2;
  int flags;
  int len;
} copr_debug_buf;
typedef struct copr_msg {
  int len;
  unsigned char data[4000];
} copr_msg;
#define SNDCTL_COPR_RESET _SIO('C', 0)
#define SNDCTL_COPR_LOAD _SIOWR('C', 1, copr_buffer)
#define SNDCTL_COPR_RDATA _SIOWR('C', 2, copr_debug_buf)
#define SNDCTL_COPR_RCODE _SIOWR('C', 3, copr_debug_buf)
#define SNDCTL_COPR_WDATA _SIOW('C', 4, copr_debug_buf)
#define SNDCTL_COPR_WCODE _SIOW('C', 5, copr_debug_buf)
#define SNDCTL_COPR_RUN _SIOWR('C', 6, copr_debug_buf)
#define SNDCTL_COPR_HALT _SIOWR('C', 7, copr_debug_buf)
#define SNDCTL_COPR_SENDMSG _SIOWR('C', 8, copr_msg)
#define SNDCTL_COPR_RCVMSG _SIOR('C', 9, copr_msg)
#define SOUND_MIXER_NRDEVICES 25
#define SOUND_MIXER_VOLUME 0
#define SOUND_MIXER_BASS 1
#define SOUND_MIXER_TREBLE 2
#define SOUND_MIXER_SYNTH 3
#define SOUND_MIXER_PCM 4
#define SOUND_MIXER_SPEAKER 5
#define SOUND_MIXER_LINE 6
#define SOUND_MIXER_MIC 7
#define SOUND_MIXER_CD 8
#define SOUND_MIXER_IMIX 9
#define SOUND_MIXER_ALTPCM 10
#define SOUND_MIXER_RECLEV 11
#define SOUND_MIXER_IGAIN 12
#define SOUND_MIXER_OGAIN 13
#define SOUND_MIXER_LINE1 14
#define SOUND_MIXER_LINE2 15
#define SOUND_MIXER_LINE3 16
#define SOUND_MIXER_DIGITAL1 17
#define SOUND_MIXER_DIGITAL2 18
#define SOUND_MIXER_DIGITAL3 19
#define SOUND_MIXER_PHONEIN 20
#define SOUND_MIXER_PHONEOUT 21
#define SOUND_MIXER_VIDEO 22
#define SOUND_MIXER_RADIO 23
#define SOUND_MIXER_MONITOR 24
#define SOUND_ONOFF_MIN 28
#define SOUND_ONOFF_MAX 30
#define SOUND_MIXER_NONE 31
#define SOUND_MIXER_ENHANCE SOUND_MIXER_NONE
#define SOUND_MIXER_MUTE SOUND_MIXER_NONE
#define SOUND_MIXER_LOUD SOUND_MIXER_NONE
#define SOUND_DEVICE_LABELS { "Vol  ", "Bass ", "Trebl", "Synth", "Pcm  ", "Spkr ", "Line ", "Mic  ", "CD   ", "Mix  ", "Pcm2 ", "Rec  ", "IGain", "OGain", "Line1", "Line2", "Line3", "Digital1", "Digital2", "Digital3", "PhoneIn", "PhoneOut", "Video", "Radio", "Monitor" }
#define SOUND_DEVICE_NAMES { "vol", "bass", "treble", "synth", "pcm", "speaker", "line", "mic", "cd", "mix", "pcm2", "rec", "igain", "ogain", "line1", "line2", "line3", "dig1", "dig2", "dig3", "phin", "phout", "video", "radio", "monitor" }
#define SOUND_MIXER_RECSRC 0xff
#define SOUND_MIXER_DEVMASK 0xfe
#define SOUND_MIXER_RECMASK 0xfd
#define SOUND_MIXER_CAPS 0xfc
#define SOUND_CAP_EXCL_INPUT 0x00000001
#define SOUND_MIXER_STEREODEVS 0xfb
#define SOUND_MIXER_OUTSRC 0xfa
#define SOUND_MIXER_OUTMASK 0xf9
#define SOUND_MASK_VOLUME (1 << SOUND_MIXER_VOLUME)
#define SOUND_MASK_BASS (1 << SOUND_MIXER_BASS)
#define SOUND_MASK_TREBLE (1 << SOUND_MIXER_TREBLE)
#define SOUND_MASK_SYNTH (1 << SOUND_MIXER_SYNTH)
#define SOUND_MASK_PCM (1 << SOUND_MIXER_PCM)
#define SOUND_MASK_SPEAKER (1 << SOUND_MIXER_SPEAKER)
#define SOUND_MASK_LINE (1 << SOUND_MIXER_LINE)
#define SOUND_MASK_MIC (1 << SOUND_MIXER_MIC)
#define SOUND_MASK_CD (1 << SOUND_MIXER_CD)
#define SOUND_MASK_IMIX (1 << SOUND_MIXER_IMIX)
#define SOUND_MASK_ALTPCM (1 << SOUND_MIXER_ALTPCM)
#define SOUND_MASK_RECLEV (1 << SOUND_MIXER_RECLEV)
#define SOUND_MASK_IGAIN (1 << SOUND_MIXER_IGAIN)
#define SOUND_MASK_OGAIN (1 << SOUND_MIXER_OGAIN)
#define SOUND_MASK_LINE1 (1 << SOUND_MIXER_LINE1)
#define SOUND_MASK_LINE2 (1 << SOUND_MIXER_LINE2)
#define SOUND_MASK_LINE3 (1 << SOUND_MIXER_LINE3)
#define SOUND_MASK_DIGITAL1 (1 << SOUND_MIXER_DIGITAL1)
#define SOUND_MASK_DIGITAL2 (1 << SOUND_MIXER_DIGITAL2)
#define SOUND_MASK_DIGITAL3 (1 << SOUND_MIXER_DIGITAL3)
#define SOUND_MASK_PHONEIN (1 << SOUND_MIXER_PHONEIN)
#define SOUND_MASK_PHONEOUT (1 << SOUND_MIXER_PHONEOUT)
#define SOUND_MASK_RADIO (1 << SOUND_MIXER_RADIO)
#define SOUND_MASK_VIDEO (1 << SOUND_MIXER_VIDEO)
#define SOUND_MASK_MONITOR (1 << SOUND_MIXER_MONITOR)
#define SOUND_MASK_MUTE (1 << SOUND_MIXER_MUTE)
#define SOUND_MASK_ENHANCE (1 << SOUND_MIXER_ENHANCE)
#define SOUND_MASK_LOUD (1 << SOUND_MIXER_LOUD)
#define MIXER_READ(dev) _SIOR('M', dev, int)
#define SOUND_MIXER_READ_VOLUME MIXER_READ(SOUND_MIXER_VOLUME)
#define SOUND_MIXER_READ_BASS MIXER_READ(SOUND_MIXER_BASS)
#define SOUND_MIXER_READ_TREBLE MIXER_READ(SOUND_MIXER_TREBLE)
#define SOUND_MIXER_READ_SYNTH MIXER_READ(SOUND_MIXER_SYNTH)
#define SOUND_MIXER_READ_PCM MIXER_READ(SOUND_MIXER_PCM)
#define SOUND_MIXER_READ_SPEAKER MIXER_READ(SOUND_MIXER_SPEAKER)
#define SOUND_MIXER_READ_LINE MIXER_READ(SOUND_MIXER_LINE)
#define SOUND_MIXER_READ_MIC MIXER_READ(SOUND_MIXER_MIC)
#define SOUND_MIXER_READ_CD MIXER_READ(SOUND_MIXER_CD)
#define SOUND_MIXER_READ_IMIX MIXER_READ(SOUND_MIXER_IMIX)
#define SOUND_MIXER_READ_ALTPCM MIXER_READ(SOUND_MIXER_ALTPCM)
#define SOUND_MIXER_READ_RECLEV MIXER_READ(SOUND_MIXER_RECLEV)
#define SOUND_MIXER_READ_IGAIN MIXER_READ(SOUND_MIXER_IGAIN)
#define SOUND_MIXER_READ_OGAIN MIXER_READ(SOUND_MIXER_OGAIN)
#define SOUND_MIXER_READ_LINE1 MIXER_READ(SOUND_MIXER_LINE1)
#define SOUND_MIXER_READ_LINE2 MIXER_READ(SOUND_MIXER_LINE2)
#define SOUND_MIXER_READ_LINE3 MIXER_READ(SOUND_MIXER_LINE3)
#define SOUND_MIXER_READ_MUTE MIXER_READ(SOUND_MIXER_MUTE)
#define SOUND_MIXER_READ_ENHANCE MIXER_READ(SOUND_MIXER_ENHANCE)
#define SOUND_MIXER_READ_LOUD MIXER_READ(SOUND_MIXER_LOUD)
#define SOUND_MIXER_READ_RECSRC MIXER_READ(SOUND_MIXER_RECSRC)
#define SOUND_MIXER_READ_DEVMASK MIXER_READ(SOUND_MIXER_DEVMASK)
#define SOUND_MIXER_READ_RECMASK MIXER_READ(SOUND_MIXER_RECMASK)
#define SOUND_MIXER_READ_STEREODEVS MIXER_READ(SOUND_MIXER_STEREODEVS)
#define SOUND_MIXER_READ_CAPS MIXER_READ(SOUND_MIXER_CAPS)
#define MIXER_WRITE(dev) _SIOWR('M', dev, int)
#define SOUND_MIXER_WRITE_VOLUME MIXER_WRITE(SOUND_MIXER_VOLUME)
#define SOUND_MIXER_WRITE_BASS MIXER_WRITE(SOUND_MIXER_BASS)
#define SOUND_MIXER_WRITE_TREBLE MIXER_WRITE(SOUND_MIXER_TREBLE)
#define SOUND_MIXER_WRITE_SYNTH MIXER_WRITE(SOUND_MIXER_SYNTH)
#define SOUND_MIXER_WRITE_PCM MIXER_WRITE(SOUND_MIXER_PCM)
#define SOUND_MIXER_WRITE_SPEAKER MIXER_WRITE(SOUND_MIXER_SPEAKER)
#define SOUND_MIXER_WRITE_LINE MIXER_WRITE(SOUND_MIXER_LINE)
#define SOUND_MIXER_WRITE_MIC MIXER_WRITE(SOUND_MIXER_MIC)
#define SOUND_MIXER_WRITE_CD MIXER_WRITE(SOUND_MIXER_CD)
#define SOUND_MIXER_WRITE_IMIX MIXER_WRITE(SOUND_MIXER_IMIX)
#define SOUND_MIXER_WRITE_ALTPCM MIXER_WRITE(SOUND_MIXER_ALTPCM)
#define SOUND_MIXER_WRITE_RECLEV MIXER_WRITE(SOUND_MIXER_RECLEV)
#define SOUND_MIXER_WRITE_IGAIN MIXER_WRITE(SOUND_MIXER_IGAIN)
#define SOUND_MIXER_WRITE_OGAIN MIXER_WRITE(SOUND_MIXER_OGAIN)
#define SOUND_MIXER_WRITE_LINE1 MIXER_WRITE(SOUND_MIXER_LINE1)
#define SOUND_MIXER_WRITE_LINE2 MIXER_WRITE(SOUND_MIXER_LINE2)
#define SOUND_MIXER_WRITE_LINE3 MIXER_WRITE(SOUND_MIXER_LINE3)
#define SOUND_MIXER_WRITE_MUTE MIXER_WRITE(SOUND_MIXER_MUTE)
#define SOUND_MIXER_WRITE_ENHANCE MIXER_WRITE(SOUND_MIXER_ENHANCE)
#define SOUND_MIXER_WRITE_LOUD MIXER_WRITE(SOUND_MIXER_LOUD)
#define SOUND_MIXER_WRITE_RECSRC MIXER_WRITE(SOUND_MIXER_RECSRC)
typedef struct mixer_info {
  char id[16];
  char name[32];
  int modify_counter;
  int fillers[10];
} mixer_info;
typedef struct _old_mixer_info {
  char id[16];
  char name[32];
} _old_mixer_info;
#define SOUND_MIXER_INFO _SIOR('M', 101, mixer_info)
#define SOUND_OLD_MIXER_INFO _SIOR('M', 101, _old_mixer_info)
typedef unsigned char mixer_record[128];
#define SOUND_MIXER_ACCESS _SIOWR('M', 102, mixer_record)
#define SOUND_MIXER_AGC _SIOWR('M', 103, int)
#define SOUND_MIXER_3DSE _SIOWR('M', 104, int)
#define SOUND_MIXER_PRIVATE1 _SIOWR('M', 111, int)
#define SOUND_MIXER_PRIVATE2 _SIOWR('M', 112, int)
#define SOUND_MIXER_PRIVATE3 _SIOWR('M', 113, int)
#define SOUND_MIXER_PRIVATE4 _SIOWR('M', 114, int)
#define SOUND_MIXER_PRIVATE5 _SIOWR('M', 115, int)
typedef struct mixer_vol_table {
  int num;
  char name[32];
  int levels[32];
} mixer_vol_table;
#define SOUND_MIXER_GETLEVELS _SIOWR('M', 116, mixer_vol_table)
#define SOUND_MIXER_SETLEVELS _SIOWR('M', 117, mixer_vol_table)
#define OSS_GETVERSION _SIOR('M', 118, int)
#define EV_SEQ_LOCAL 0x80
#define EV_TIMING 0x81
#define EV_CHN_COMMON 0x92
#define EV_CHN_VOICE 0x93
#define EV_SYSEX 0x94
#define MIDI_NOTEOFF 0x80
#define MIDI_NOTEON 0x90
#define MIDI_KEY_PRESSURE 0xA0
#define MIDI_CTL_CHANGE 0xB0
#define MIDI_PGM_CHANGE 0xC0
#define MIDI_CHN_PRESSURE 0xD0
#define MIDI_PITCH_BEND 0xE0
#define MIDI_SYSTEM_PREFIX 0xF0
#define TMR_WAIT_REL 1
#define TMR_WAIT_ABS 2
#define TMR_STOP 3
#define TMR_START 4
#define TMR_CONTINUE 5
#define TMR_TEMPO 6
#define TMR_ECHO 8
#define TMR_CLOCK 9
#define TMR_SPP 10
#define TMR_TIMESIG 11
#define LOCL_STARTAUDIO 1
#define SEQ_DECLAREBUF() SEQ_USE_EXTBUF()
#define SEQ_PM_DEFINES int __foo_bar___
#define SEQ_LOAD_GMINSTR(dev,instr)
#define SEQ_LOAD_GMDRUM(dev,drum)
#define _SEQ_EXTERN extern
#define SEQ_USE_EXTBUF() _SEQ_EXTERN unsigned char _seqbuf[]; _SEQ_EXTERN int _seqbuflen; _SEQ_EXTERN int _seqbufptr
#ifndef USE_SIMPLE_MACROS
#define SEQ_DEFINEBUF(len) unsigned char _seqbuf[len]; int _seqbuflen = len; int _seqbufptr = 0
#define _SEQ_NEEDBUF(len) if((_seqbufptr + (len)) > _seqbuflen) seqbuf_dump()
#define _SEQ_ADVBUF(len) _seqbufptr += len
#define SEQ_DUMPBUF seqbuf_dump
#else
#define _SEQ_NEEDBUF(len)
#endif
#define SEQ_VOLUME_MODE(dev,mode) { _SEQ_NEEDBUF(8); _seqbuf[_seqbufptr] = SEQ_EXTENDED; _seqbuf[_seqbufptr + 1] = SEQ_VOLMODE; _seqbuf[_seqbufptr + 2] = (dev); _seqbuf[_seqbufptr + 3] = (mode); _seqbuf[_seqbufptr + 4] = 0; _seqbuf[_seqbufptr + 5] = 0; _seqbuf[_seqbufptr + 6] = 0; _seqbuf[_seqbufptr + 7] = 0; _SEQ_ADVBUF(8); }
#define _CHN_VOICE(dev,event,chn,note,parm) { _SEQ_NEEDBUF(8); _seqbuf[_seqbufptr] = EV_CHN_VOICE; _seqbuf[_seqbufptr + 1] = (dev); _seqbuf[_seqbufptr + 2] = (event); _seqbuf[_seqbufptr + 3] = (chn); _seqbuf[_seqbufptr + 4] = (note); _seqbuf[_seqbufptr + 5] = (parm); _seqbuf[_seqbufptr + 6] = (0); _seqbuf[_seqbufptr + 7] = 0; _SEQ_ADVBUF(8); }
#define SEQ_START_NOTE(dev,chn,note,vol) _CHN_VOICE(dev, MIDI_NOTEON, chn, note, vol)
#define SEQ_STOP_NOTE(dev,chn,note,vol) _CHN_VOICE(dev, MIDI_NOTEOFF, chn, note, vol)
#define SEQ_KEY_PRESSURE(dev,chn,note,pressure) _CHN_VOICE(dev, MIDI_KEY_PRESSURE, chn, note, pressure)
#define _CHN_COMMON(dev,event,chn,p1,p2,w14) { _SEQ_NEEDBUF(8); _seqbuf[_seqbufptr] = EV_CHN_COMMON; _seqbuf[_seqbufptr + 1] = (dev); _seqbuf[_seqbufptr + 2] = (event); _seqbuf[_seqbufptr + 3] = (chn); _seqbuf[_seqbufptr + 4] = (p1); _seqbuf[_seqbufptr + 5] = (p2); * (short *) & _seqbuf[_seqbufptr + 6] = (w14); _SEQ_ADVBUF(8); }
#define SEQ_SYSEX(dev,buf,len) { int ii, ll = (len); unsigned char * bufp = buf; if(ll > 6) ll = 6; _SEQ_NEEDBUF(8); _seqbuf[_seqbufptr] = EV_SYSEX; _seqbuf[_seqbufptr + 1] = (dev); for(ii = 0; ii < ll; ii ++) _seqbuf[_seqbufptr + ii + 2] = bufp[ii]; for(ii = ll; ii < 6; ii ++) _seqbuf[_seqbufptr + ii + 2] = 0xff; _SEQ_ADVBUF(8); }
#define SEQ_CHN_PRESSURE(dev,chn,pressure) _CHN_COMMON(dev, MIDI_CHN_PRESSURE, chn, pressure, 0, 0)
#define SEQ_SET_PATCH SEQ_PGM_CHANGE
#define SEQ_PGM_CHANGE(dev,chn,patch) _CHN_COMMON(dev, MIDI_PGM_CHANGE, chn, patch, 0, 0)
#define SEQ_CONTROL(dev,chn,controller,value) _CHN_COMMON(dev, MIDI_CTL_CHANGE, chn, controller, 0, value)
#define SEQ_BENDER(dev,chn,value) _CHN_COMMON(dev, MIDI_PITCH_BEND, chn, 0, 0, value)
#define SEQ_V2_X_CONTROL(dev,voice,controller,value) { _SEQ_NEEDBUF(8); _seqbuf[_seqbufptr] = SEQ_EXTENDED; _seqbuf[_seqbufptr + 1] = SEQ_CONTROLLER; _seqbuf[_seqbufptr + 2] = (dev); _seqbuf[_seqbufptr + 3] = (voice); _seqbuf[_seqbufptr + 4] = (controller); _seqbuf[_seqbufptr + 5] = ((value) & 0xff); _seqbuf[_seqbufptr + 6] = ((value >> 8) & 0xff); _seqbuf[_seqbufptr + 7] = 0; _SEQ_ADVBUF(8); }
#define SEQ_PITCHBEND(dev,voice,value) SEQ_V2_X_CONTROL(dev, voice, CTRL_PITCH_BENDER, value)
#define SEQ_BENDER_RANGE(dev,voice,value) SEQ_V2_X_CONTROL(dev, voice, CTRL_PITCH_BENDER_RANGE, value)
#define SEQ_EXPRESSION(dev,voice,value) SEQ_CONTROL(dev, voice, CTL_EXPRESSION, value * 128)
#define SEQ_MAIN_VOLUME(dev,voice,value) SEQ_CONTROL(dev, voice, CTL_MAIN_VOLUME, (value * 16383) / 100)
#define SEQ_PANNING(dev,voice,pos) SEQ_CONTROL(dev, voice, CTL_PAN, (pos + 128) / 2)
#define _TIMER_EVENT(ev,parm) { _SEQ_NEEDBUF(8); _seqbuf[_seqbufptr + 0] = EV_TIMING; _seqbuf[_seqbufptr + 1] = (ev); _seqbuf[_seqbufptr + 2] = 0; _seqbuf[_seqbufptr + 3] = 0; * (unsigned int *) & _seqbuf[_seqbufptr + 4] = (parm); _SEQ_ADVBUF(8); }
#define SEQ_START_TIMER() _TIMER_EVENT(TMR_START, 0)
#define SEQ_STOP_TIMER() _TIMER_EVENT(TMR_STOP, 0)
#define SEQ_CONTINUE_TIMER() _TIMER_EVENT(TMR_CONTINUE, 0)
#define SEQ_WAIT_TIME(ticks) _TIMER_EVENT(TMR_WAIT_ABS, ticks)
#define SEQ_DELTA_TIME(ticks) _TIMER_EVENT(TMR_WAIT_REL, ticks)
#define SEQ_ECHO_BACK(key) _TIMER_EVENT(TMR_ECHO, key)
#define SEQ_SET_TEMPO(value) _TIMER_EVENT(TMR_TEMPO, value)
#define SEQ_SONGPOS(pos) _TIMER_EVENT(TMR_SPP, pos)
#define SEQ_TIME_SIGNATURE(sig) _TIMER_EVENT(TMR_TIMESIG, sig)
#define _LOCAL_EVENT(ev,parm) { _SEQ_NEEDBUF(8); _seqbuf[_seqbufptr + 0] = EV_SEQ_LOCAL; _seqbuf[_seqbufptr + 1] = (ev); _seqbuf[_seqbufptr + 2] = 0; _seqbuf[_seqbufptr + 3] = 0; * (unsigned int *) & _seqbuf[_seqbufptr + 4] = (parm); _SEQ_ADVBUF(8); }
#define SEQ_PLAYAUDIO(devmask) _LOCAL_EVENT(LOCL_STARTAUDIO, devmask)
#define SEQ_MIDIOUT(device,byte) { _SEQ_NEEDBUF(4); _seqbuf[_seqbufptr] = SEQ_MIDIPUTC; _seqbuf[_seqbufptr + 1] = (byte); _seqbuf[_seqbufptr + 2] = (device); _seqbuf[_seqbufptr + 3] = 0; _SEQ_ADVBUF(4); }
#define SEQ_WRPATCH(patchx,len) { if(_seqbufptr) SEQ_DUMPBUF(); if(write(seqfd, (char *) (patchx), len) == - 1) perror("Write patch: /dev/sequencer"); }
#define SEQ_WRPATCH2(patchx,len) (SEQ_DUMPBUF(), write(seqfd, (char *) (patchx), len))
#endif

"""

```