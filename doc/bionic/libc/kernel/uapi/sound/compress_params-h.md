Response:
The user wants to understand the functionality of the provided C header file `compress_params.h`. This file is part of the Android Bionic library and defines structures and constants related to audio compression parameters. I need to address the following:

1. **功能列举:** List the functionalities defined in the header file.
2. **与 Android 的关系:** Explain how these definitions relate to Android's audio capabilities, providing examples.
3. **libc 函数解释:** This header file primarily defines structures and macros, not libc functions. I need to clarify this and explain the role of the defined structures in interacting with kernel modules (which might involve system calls handled by libc).
4. **dynamic linker 功能:**  This header file doesn't directly involve dynamic linking. I need to explain this and clarify that it defines data structures used by components that *might* be dynamically linked. I should provide a hypothetical scenario where these structures are used in a dynamically linked library.
5. **逻辑推理 (假设输入/输出):**  Since it's a header file, there's no direct execution. However, I can provide examples of how these structures would be populated and used when configuring audio compression.
6. **常见使用错误:**  Give examples of common errors when using these definitions in Android audio development.
7. **Android Framework/NDK 到达路径 & Frida Hook:** Describe how the Android audio framework and NDK interact with these definitions and provide a Frida hook example to inspect the values.

**Plan:**

*   Analyze the header file and identify the key data structures and constants.
*   Explain the purpose of each structure and constant.
*   Illustrate how these structures are used in the Android audio stack.
*   Explain the relationship with the kernel and potential system calls.
*   Address the dynamic linking aspect by describing a hypothetical scenario.
*   Provide examples of populating the structures and potential errors.
*   Outline the path from Android framework/NDK to the kernel.
*   Craft a Frida hook example to demonstrate inspection of these parameters.
好的，我们来详细分析一下 `bionic/libc/kernel/uapi/sound/compress_params.h` 这个头文件。

**功能列举:**

这个头文件定义了用于配置和描述音频压缩参数的结构体、联合体和常量。其主要功能是：

1. **定义音频编解码器 (Codec) 的 ID:**  例如 `SND_AUDIOCODEC_PCM`, `SND_AUDIOCODEC_MP3`, `SND_AUDIOCODEC_AAC` 等，用于标识不同的音频编码格式。
2. **定义音频 Profile:** 例如 `SND_AUDIOPROFILE_PCM`, `SND_AUDIOPROFILE_AMR`，表示特定编解码器的配置或变种。
3. **定义音频通道模式:** 例如 `SND_AUDIOCHANMODE_MP3_MONO`, `SND_AUDIOCHANMODE_MP3_STEREO`，用于描述音频的通道布局。
4. **定义音频流格式:** 例如 `SND_AUDIOSTREAMFORMAT_UNDEFINED`, `SND_AUDIOSTREAMFORMAT_MP4ADTS`，用于描述音频数据在传输或存储时的格式。
5. **定义特定编解码器的模式 (Mode):**  例如 AMR 的 `SND_AUDIOMODE_AMR_DTX_OFF`, AAC 的 `SND_AUDIOMODE_AAC_LC`，WMA 的 `SND_AUDIOMODE_WMA_LEVEL1` 等，用于更精细地控制编解码器的行为。
6. **定义码率控制模式:** 例如 `SND_RATECONTROLMODE_CONSTANTBITRATE` (CBR), `SND_RATECONTROLMODE_VARIABLEBITRATE` (VBR)。
7. **定义特定编解码器的配置结构体:** 例如 `struct snd_enc_wma`, `struct snd_enc_vorbis`, `struct snd_dec_flac` 等，包含特定编解码器需要的详细参数。
8. **定义通用的编解码器配置结构体:** `struct snd_codec`，它包含了编解码器的 ID、通道数、采样率、比特率、Profile、Level、模式、格式以及一个用于存储特定编解码器配置的联合体 `union snd_codec_options`。
9. **定义编解码器描述结构体:** `struct snd_codec_desc`，用于描述编解码器的能力，例如支持的最大通道数、支持的采样率和比特率范围等。
10. **定义最大值常量:** 例如 `MAX_NUM_CODECS`, `MAX_NUM_BITRATES`，用于限制数组大小。

**与 Android 的关系及举例说明:**

这个头文件是 Android 音频框架与底层 Linux 内核音频驱动交互的重要桥梁。它定义了应用程序和音频驱动之间传递音频压缩参数的标准格式。

**举例说明:**

*   **音频录制/播放:** 当 Android 应用需要录制或播放压缩音频 (例如 MP3, AAC)，它会通过 Android Framework (例如 `MediaRecorder`, `MediaPlayer`) 或 NDK 的相关 API (例如 `AAudio`, `OpenSL ES`)  与底层的音频系统服务进行交互。这些服务最终会调用底层的音频驱动。在配置音频流的过程中，就需要指定音频的编码格式，例如选择 AAC 编码。这时，`SND_AUDIOCODEC_AAC` 这个常量就会被使用。

*   **编解码器配置:**  假设一个应用需要录制 AMR 格式的音频，并且需要关闭 DTX (Discontinuous Transmission) 功能。那么在配置录音参数时，会使用到 `SND_AUDIOCODEC_AMR` 和 `SND_AUDIOMODE_AMR_DTX_OFF` 这些常量。

*   **查询编解码器能力:**  Android 系统可能需要查询某个音频编解码器所支持的采样率、比特率等信息。这些信息会通过 `struct snd_codec_desc` 结构体传递。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并没有定义任何 libc 函数。它定义的是数据结构和宏常量，用于在不同的组件之间传递数据。这些数据结构最终会被传递给 Linux 内核的音频驱动，驱动程序会根据这些参数来配置硬件编解码器。

与这个头文件相关的 libc 函数主要是用于进行系统调用的函数，例如 `ioctl`。应用程序通过 `ioctl` 系统调用，并将包含这些结构体的指针传递给内核，从而配置音频压缩相关的参数。`ioctl` 的具体实现非常复杂，涉及到内核态的上下文切换、参数校验、驱动程序的调用等。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接参与 dynamic linker 的功能。它定义的是数据结构，这些数据结构可以被不同的共享库 (shared object, `.so`) 使用。

**so 布局样本:**

假设我们有一个名为 `libaudio_codec.so` 的共享库，它负责音频编解码的功能。这个库可能会使用到 `compress_params.h` 中定义的结构体。

```
libaudio_codec.so:
    .text        # 代码段
        ...
        codec_init:  # 初始化编解码器的函数
            # 使用 compress_params.h 中定义的结构体来配置编解码器
            ...
    .data        # 数据段
        ...
    .rodata      # 只读数据段
        ...
    .bss         # 未初始化数据段
        ...
    .dynamic     # 动态链接信息
        SONAME        libaudio_codec.so
        NEEDED        libc.so
        ...
    .symtab      # 符号表
        codec_init
        ...
    .strtab      # 字符串表
        ...
```

**链接的处理过程:**

1. **编译时链接:** 当编译使用 `libaudio_codec.so` 的应用程序或其他共享库时，编译器会记录下对 `libaudio_codec.so` 中符号 (例如 `codec_init`) 的引用。

2. **运行时加载:** 当应用程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载应用程序及其依赖的共享库。

3. **符号解析:** dynamic linker 会遍历所有加载的共享库的符号表，找到 `codec_init` 等符号的定义，并将应用程序中对这些符号的引用绑定到实际的地址。在这个过程中，`compress_params.h` 中定义的结构体类型信息会被用于确保数据传递的正确性，但 dynamic linker 本身并不直接处理这些结构体的具体内容。

**逻辑推理，假设输入与输出:**

虽然这个是头文件，没有直接的输入输出，但我们可以假设在配置音频编解码器时，如何使用这些结构体：

**假设输入:**

*   需要配置一个用于录制 MP3 音频的编解码器。
*   目标采样率为 44100 Hz，比特率为 128 kbps，立体声模式。

**使用结构体进行配置:**

```c
#include <sound/compress_params.h>
#include <stdio.h>

int main() {
    struct snd_codec codec_config;

    codec_config.id = SND_AUDIOCODEC_MP3;
    codec_config.ch_in = 1; // 假设录音是单声道输入
    codec_config.ch_out = 2; // 输出为立体声
    codec_config.sample_rate = 44100;
    codec_config.bit_rate = 128000;
    codec_config.ch_mode = SND_AUDIOCHANMODE_MP3_STEREO;
    // ... 其他参数的配置

    printf("Codec ID: %u\n", codec_config.id);
    printf("Sample Rate: %u\n", codec_config.sample_rate);
    printf("Bit Rate: %u\n", codec_config.bit_rate);
    printf("Channel Mode: %u\n", codec_config.ch_mode);

    // 将 codec_config 传递给底层的音频驱动 (通常通过 ioctl 系统调用)

    return 0;
}
```

**假设输出:**

当把 `codec_config` 传递给音频驱动后，驱动会根据这些参数配置硬件或软件编解码器，最终录制出的音频流将是 MP3 格式，采样率为 44100 Hz，比特率为 128 kbps 的立体声。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用未定义的常量:** 错误地使用了头文件中未定义的常量，导致编译错误或运行时错误。例如，手写了一个不存在的 `SND_AUDIOCODEC_XYZ`。

2. **参数取值超出范围:**  为某些参数设置了超出其允许范围的值。例如，设置了不支持的采样率或比特率。

3. **结构体成员赋值错误:**  错误地赋值结构体成员，例如将通道数设置为负数。

4. **类型不匹配:** 在传递参数时，使用了错误的类型，例如将一个 `int` 类型的值赋值给一个 `__u32` 类型的成员。

5. **忘记初始化结构体:**  直接使用未初始化的结构体，导致传递给驱动的是随机值。

6. **编译时头文件路径错误:**  如果没有正确包含头文件，编译器将无法找到这些定义，导致编译错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到达路径:**

1. **应用层 (Java/Kotlin):**  Android 应用通过 `MediaRecorder` 或 `MediaPlayer` 等类来录制或播放音频。例如，使用 `MediaRecorder` 设置音频编码器：

    ```java
    MediaRecorder recorder = new MediaRecorder();
    recorder.setAudioSource(MediaRecorder.AudioSource.MIC);
    recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4);
    recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
    recorder.setOutputFile(outputFile.getAbsolutePath());
    recorder.prepare();
    recorder.start();
    ```

2. **Android Framework (Java层):**  `MediaRecorder` 的 Java 层实现会调用 Framework 层的 Media 服务 (mediaserver)。

3. **Media 服务 (C++):**  mediaserver 进程中的 `AudioFlinger` 组件负责处理音频相关的操作。`AudioFlinger` 会与硬件抽象层 (HAL) 进行交互。

4. **Audio HAL (C++):**  Audio HAL 定义了 Android 音频系统的硬件接口。在录制音频时，HAL 实现会将应用程序的请求转换为底层的硬件操作。在配置压缩编码器时，HAL 实现可能会使用到 `compress_params.h` 中定义的结构体来设置内核驱动的参数。

5. **Kernel Driver (C):**  最终，Audio HAL 会通过 `ioctl` 系统调用将包含 `snd_codec` 结构体的参数传递给 Linux 内核的音频驱动程序。驱动程序会解析这些参数，并配置底层的音频编解码器硬件。

**NDK 路径:**

使用 NDK 进行音频操作时，例如使用 AAudio 或 OpenSL ES，路径类似：

1. **应用层 (C/C++):**  NDK 应用使用 AAudio 或 OpenSL ES 的 API 来创建音频流，并设置音频格式和编码器。

    ```c++
    // AAudio 示例
    AAudioStreamBuilder_setFormat(builder, AAUDIO_FORMAT_PCM_I16);
    AAudioStreamBuilder_setSampleRate(builder, 44100);
    AAudioStreamBuilder_setChannelCount(builder, 2);
    // ... 设置编码器相关的参数 (可能间接使用到 compress_params.h 中的定义)
    ```

2. **NDK Libraries (C++):**  AAudio 和 OpenSL ES 的 NDK 库会调用底层的 Android Framework 服务。

3. **后续步骤与 Framework 路径类似，最终到达 Kernel Driver。**

**Frida Hook 示例:**

我们可以使用 Frida Hook `ioctl` 系统调用，并检查传递的参数，来观察 `compress_params.h` 中定义的结构体是如何被使用的。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    process = frida.get_usb_device().attach('com.example.yourapp') # 替换为你的应用包名
except frida.ServerNotStartedError:
    print("Frida server not started. Please start the Frida server on the device.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        var request = args[1].toInt32();
        // 假设音频压缩相关的 ioctl 命令字是某个特定的值，需要根据实际情况替换
        var SNDRV_COMPRESS_PARAMS = 0xC0004100; // 这是一个假设的值，需要根据实际情况确定
        if (request == SNDRV_COMPRESS_PARAMS) {
            send("[*] ioctl called with SNDRV_COMPRESS_PARAMS");
            var argp = ptr(args[2]);
            // 根据实际的 ioctl 命令字和参数结构体类型，读取参数
            // 这里假设传递的是 snd_codec 结构体
            var codec_ptr = argp.readPointer();
            if (codec_ptr) {
                send("[*] snd_codec structure address: " + codec_ptr);
                var id = codec_ptr.readU32();
                var sample_rate = codec_ptr.add(8).readU32(); // 假设 sample_rate 偏移为 8
                var bit_rate = codec_ptr.add(12).readU32(); // 假设 bit_rate 偏移为 12
                send("[*] Codec ID: " + id);
                send("[*] Sample Rate: " + sample_rate);
                send("[*] Bit Rate: " + bit_rate);
            }
        }
    },
    onLeave: function(retval) {
        //console.log("ioctl returned: " + retval);
    }
});
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
"""

**使用方法:**

1. 将上述 Python 代码保存为 `.py` 文件 (例如 `hook_audio.py`)。
2. 确保你的 Android 设备已连接并通过 USB 调试授权，并且 Frida 服务已在设备上运行。
3. 将 `com.example.yourapp` 替换为你要调试的 Android 应用的包名。
4. **重要:**  你需要找到与音频压缩相关的 `ioctl` 命令字 (例如 `SNDRV_COMPRESS_PARAMS`)，这通常需要在内核驱动的源代码中查找。
5. 运行 Python 脚本：`python hook_audio.py`。
6. 在你的 Android 设备上运行目标应用，并执行触发音频录制或播放的操作。
7. Frida 会拦截 `ioctl` 调用，并打印出相关的参数信息，包括 `snd_codec` 结构体中的 Codec ID、采样率和比特率等。

**请注意:**  上述 Frida Hook 代码只是一个示例，实际的 `ioctl` 命令字和参数结构体布局可能有所不同，需要根据具体的 Android 版本和硬件平台进行调整。你需要研究相关的内核驱动源代码才能确定正确的偏移量和命令字。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/sound/compress_params.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __SND_COMPRESS_PARAMS_H
#define __SND_COMPRESS_PARAMS_H
#include <linux/types.h>
#define MAX_NUM_CODECS 32
#define MAX_NUM_CODEC_DESCRIPTORS 32
#define MAX_NUM_BITRATES 32
#define MAX_NUM_SAMPLE_RATES 32
#define SND_AUDIOCODEC_PCM ((__u32) 0x00000001)
#define SND_AUDIOCODEC_MP3 ((__u32) 0x00000002)
#define SND_AUDIOCODEC_AMR ((__u32) 0x00000003)
#define SND_AUDIOCODEC_AMRWB ((__u32) 0x00000004)
#define SND_AUDIOCODEC_AMRWBPLUS ((__u32) 0x00000005)
#define SND_AUDIOCODEC_AAC ((__u32) 0x00000006)
#define SND_AUDIOCODEC_WMA ((__u32) 0x00000007)
#define SND_AUDIOCODEC_REAL ((__u32) 0x00000008)
#define SND_AUDIOCODEC_VORBIS ((__u32) 0x00000009)
#define SND_AUDIOCODEC_FLAC ((__u32) 0x0000000A)
#define SND_AUDIOCODEC_IEC61937 ((__u32) 0x0000000B)
#define SND_AUDIOCODEC_G723_1 ((__u32) 0x0000000C)
#define SND_AUDIOCODEC_G729 ((__u32) 0x0000000D)
#define SND_AUDIOCODEC_BESPOKE ((__u32) 0x0000000E)
#define SND_AUDIOCODEC_ALAC ((__u32) 0x0000000F)
#define SND_AUDIOCODEC_APE ((__u32) 0x00000010)
#define SND_AUDIOCODEC_MAX SND_AUDIOCODEC_APE
#define SND_AUDIOPROFILE_PCM ((__u32) 0x00000001)
#define SND_AUDIOCHANMODE_MP3_MONO ((__u32) 0x00000001)
#define SND_AUDIOCHANMODE_MP3_STEREO ((__u32) 0x00000002)
#define SND_AUDIOCHANMODE_MP3_JOINTSTEREO ((__u32) 0x00000004)
#define SND_AUDIOCHANMODE_MP3_DUAL ((__u32) 0x00000008)
#define SND_AUDIOPROFILE_AMR ((__u32) 0x00000001)
#define SND_AUDIOMODE_AMR_DTX_OFF ((__u32) 0x00000001)
#define SND_AUDIOMODE_AMR_VAD1 ((__u32) 0x00000002)
#define SND_AUDIOMODE_AMR_VAD2 ((__u32) 0x00000004)
#define SND_AUDIOSTREAMFORMAT_UNDEFINED ((__u32) 0x00000000)
#define SND_AUDIOSTREAMFORMAT_CONFORMANCE ((__u32) 0x00000001)
#define SND_AUDIOSTREAMFORMAT_IF1 ((__u32) 0x00000002)
#define SND_AUDIOSTREAMFORMAT_IF2 ((__u32) 0x00000004)
#define SND_AUDIOSTREAMFORMAT_FSF ((__u32) 0x00000008)
#define SND_AUDIOSTREAMFORMAT_RTPPAYLOAD ((__u32) 0x00000010)
#define SND_AUDIOSTREAMFORMAT_ITU ((__u32) 0x00000020)
#define SND_AUDIOPROFILE_AMRWB ((__u32) 0x00000001)
#define SND_AUDIOMODE_AMRWB_DTX_OFF ((__u32) 0x00000001)
#define SND_AUDIOMODE_AMRWB_VAD1 ((__u32) 0x00000002)
#define SND_AUDIOMODE_AMRWB_VAD2 ((__u32) 0x00000004)
#define SND_AUDIOPROFILE_AMRWBPLUS ((__u32) 0x00000001)
#define SND_AUDIOPROFILE_AAC ((__u32) 0x00000001)
#define SND_AUDIOMODE_AAC_MAIN ((__u32) 0x00000001)
#define SND_AUDIOMODE_AAC_LC ((__u32) 0x00000002)
#define SND_AUDIOMODE_AAC_SSR ((__u32) 0x00000004)
#define SND_AUDIOMODE_AAC_LTP ((__u32) 0x00000008)
#define SND_AUDIOMODE_AAC_HE ((__u32) 0x00000010)
#define SND_AUDIOMODE_AAC_SCALABLE ((__u32) 0x00000020)
#define SND_AUDIOMODE_AAC_ERLC ((__u32) 0x00000040)
#define SND_AUDIOMODE_AAC_LD ((__u32) 0x00000080)
#define SND_AUDIOMODE_AAC_HE_PS ((__u32) 0x00000100)
#define SND_AUDIOMODE_AAC_HE_MPS ((__u32) 0x00000200)
#define SND_AUDIOSTREAMFORMAT_MP2ADTS ((__u32) 0x00000001)
#define SND_AUDIOSTREAMFORMAT_MP4ADTS ((__u32) 0x00000002)
#define SND_AUDIOSTREAMFORMAT_MP4LOAS ((__u32) 0x00000004)
#define SND_AUDIOSTREAMFORMAT_MP4LATM ((__u32) 0x00000008)
#define SND_AUDIOSTREAMFORMAT_ADIF ((__u32) 0x00000010)
#define SND_AUDIOSTREAMFORMAT_MP4FF ((__u32) 0x00000020)
#define SND_AUDIOSTREAMFORMAT_RAW ((__u32) 0x00000040)
#define SND_AUDIOPROFILE_WMA7 ((__u32) 0x00000001)
#define SND_AUDIOPROFILE_WMA8 ((__u32) 0x00000002)
#define SND_AUDIOPROFILE_WMA9 ((__u32) 0x00000004)
#define SND_AUDIOPROFILE_WMA10 ((__u32) 0x00000008)
#define SND_AUDIOPROFILE_WMA9_PRO ((__u32) 0x00000010)
#define SND_AUDIOPROFILE_WMA9_LOSSLESS ((__u32) 0x00000020)
#define SND_AUDIOPROFILE_WMA10_LOSSLESS ((__u32) 0x00000040)
#define SND_AUDIOMODE_WMA_LEVEL1 ((__u32) 0x00000001)
#define SND_AUDIOMODE_WMA_LEVEL2 ((__u32) 0x00000002)
#define SND_AUDIOMODE_WMA_LEVEL3 ((__u32) 0x00000004)
#define SND_AUDIOMODE_WMA_LEVEL4 ((__u32) 0x00000008)
#define SND_AUDIOMODE_WMAPRO_LEVELM0 ((__u32) 0x00000010)
#define SND_AUDIOMODE_WMAPRO_LEVELM1 ((__u32) 0x00000020)
#define SND_AUDIOMODE_WMAPRO_LEVELM2 ((__u32) 0x00000040)
#define SND_AUDIOMODE_WMAPRO_LEVELM3 ((__u32) 0x00000080)
#define SND_AUDIOSTREAMFORMAT_WMA_ASF ((__u32) 0x00000001)
#define SND_AUDIOSTREAMFORMAT_WMA_NOASF_HDR ((__u32) 0x00000002)
#define SND_AUDIOPROFILE_REALAUDIO ((__u32) 0x00000001)
#define SND_AUDIOMODE_REALAUDIO_G2 ((__u32) 0x00000001)
#define SND_AUDIOMODE_REALAUDIO_8 ((__u32) 0x00000002)
#define SND_AUDIOMODE_REALAUDIO_10 ((__u32) 0x00000004)
#define SND_AUDIOMODE_REALAUDIO_SURROUND ((__u32) 0x00000008)
#define SND_AUDIOPROFILE_VORBIS ((__u32) 0x00000001)
#define SND_AUDIOMODE_VORBIS ((__u32) 0x00000001)
#define SND_AUDIOPROFILE_FLAC ((__u32) 0x00000001)
#define SND_AUDIOMODE_FLAC_LEVEL0 ((__u32) 0x00000001)
#define SND_AUDIOMODE_FLAC_LEVEL1 ((__u32) 0x00000002)
#define SND_AUDIOMODE_FLAC_LEVEL2 ((__u32) 0x00000004)
#define SND_AUDIOMODE_FLAC_LEVEL3 ((__u32) 0x00000008)
#define SND_AUDIOMODE_FLAC_LEVEL4 ((__u32) 0x00000010)
#define SND_AUDIOMODE_FLAC_LEVEL5 ((__u32) 0x00000020)
#define SND_AUDIOMODE_FLAC_LEVEL6 ((__u32) 0x00000040)
#define SND_AUDIOMODE_FLAC_LEVEL7 ((__u32) 0x00000080)
#define SND_AUDIOMODE_FLAC_LEVEL8 ((__u32) 0x00000100)
#define SND_AUDIOSTREAMFORMAT_FLAC ((__u32) 0x00000001)
#define SND_AUDIOSTREAMFORMAT_FLAC_OGG ((__u32) 0x00000002)
#define SND_AUDIOPROFILE_IEC61937 ((__u32) 0x00000001)
#define SND_AUDIOPROFILE_IEC61937_SPDIF ((__u32) 0x00000002)
#define SND_AUDIOMODE_IEC_REF_STREAM_HEADER ((__u32) 0x00000000)
#define SND_AUDIOMODE_IEC_LPCM ((__u32) 0x00000001)
#define SND_AUDIOMODE_IEC_AC3 ((__u32) 0x00000002)
#define SND_AUDIOMODE_IEC_MPEG1 ((__u32) 0x00000004)
#define SND_AUDIOMODE_IEC_MP3 ((__u32) 0x00000008)
#define SND_AUDIOMODE_IEC_MPEG2 ((__u32) 0x00000010)
#define SND_AUDIOMODE_IEC_AACLC ((__u32) 0x00000020)
#define SND_AUDIOMODE_IEC_DTS ((__u32) 0x00000040)
#define SND_AUDIOMODE_IEC_ATRAC ((__u32) 0x00000080)
#define SND_AUDIOMODE_IEC_SACD ((__u32) 0x00000100)
#define SND_AUDIOMODE_IEC_EAC3 ((__u32) 0x00000200)
#define SND_AUDIOMODE_IEC_DTS_HD ((__u32) 0x00000400)
#define SND_AUDIOMODE_IEC_MLP ((__u32) 0x00000800)
#define SND_AUDIOMODE_IEC_DST ((__u32) 0x00001000)
#define SND_AUDIOMODE_IEC_WMAPRO ((__u32) 0x00002000)
#define SND_AUDIOMODE_IEC_REF_CXT ((__u32) 0x00004000)
#define SND_AUDIOMODE_IEC_HE_AAC ((__u32) 0x00008000)
#define SND_AUDIOMODE_IEC_HE_AAC2 ((__u32) 0x00010000)
#define SND_AUDIOMODE_IEC_MPEG_SURROUND ((__u32) 0x00020000)
#define SND_AUDIOPROFILE_G723_1 ((__u32) 0x00000001)
#define SND_AUDIOMODE_G723_1_ANNEX_A ((__u32) 0x00000001)
#define SND_AUDIOMODE_G723_1_ANNEX_B ((__u32) 0x00000002)
#define SND_AUDIOMODE_G723_1_ANNEX_C ((__u32) 0x00000004)
#define SND_AUDIOPROFILE_G729 ((__u32) 0x00000001)
#define SND_AUDIOMODE_G729_ANNEX_A ((__u32) 0x00000001)
#define SND_AUDIOMODE_G729_ANNEX_B ((__u32) 0x00000002)
#define SND_RATECONTROLMODE_CONSTANTBITRATE ((__u32) 0x00000001)
#define SND_RATECONTROLMODE_VARIABLEBITRATE ((__u32) 0x00000002)
struct snd_enc_wma {
  __u32 super_block_align;
};
struct snd_enc_vorbis {
  __s32 quality;
  __u32 managed;
  __u32 max_bit_rate;
  __u32 min_bit_rate;
  __u32 downmix;
} __attribute__((packed, aligned(4)));
struct snd_enc_real {
  __u32 quant_bits;
  __u32 start_region;
  __u32 num_regions;
} __attribute__((packed, aligned(4)));
struct snd_enc_flac {
  __u32 num;
  __u32 gain;
} __attribute__((packed, aligned(4)));
struct snd_enc_generic {
  __u32 bw;
  __s32 reserved[15];
} __attribute__((packed, aligned(4)));
struct snd_dec_flac {
  __u16 sample_size;
  __u16 min_blk_size;
  __u16 max_blk_size;
  __u16 min_frame_size;
  __u16 max_frame_size;
  __u16 reserved;
} __attribute__((packed, aligned(4)));
struct snd_dec_wma {
  __u32 encoder_option;
  __u32 adv_encoder_option;
  __u32 adv_encoder_option2;
  __u32 reserved;
} __attribute__((packed, aligned(4)));
struct snd_dec_alac {
  __u32 frame_length;
  __u8 compatible_version;
  __u8 pb;
  __u8 mb;
  __u8 kb;
  __u32 max_run;
  __u32 max_frame_bytes;
} __attribute__((packed, aligned(4)));
struct snd_dec_ape {
  __u16 compatible_version;
  __u16 compression_level;
  __u32 format_flags;
  __u32 blocks_per_frame;
  __u32 final_frame_blocks;
  __u32 total_frames;
  __u32 seek_table_present;
} __attribute__((packed, aligned(4)));
union snd_codec_options {
  struct snd_enc_wma wma;
  struct snd_enc_vorbis vorbis;
  struct snd_enc_real real;
  struct snd_enc_flac flac;
  struct snd_enc_generic generic;
  struct snd_dec_flac flac_d;
  struct snd_dec_wma wma_d;
  struct snd_dec_alac alac_d;
  struct snd_dec_ape ape_d;
} __attribute__((packed, aligned(4)));
struct snd_codec_desc {
  __u32 max_ch;
  __u32 sample_rates[MAX_NUM_SAMPLE_RATES];
  __u32 num_sample_rates;
  __u32 bit_rate[MAX_NUM_BITRATES];
  __u32 num_bitrates;
  __u32 rate_control;
  __u32 profiles;
  __u32 modes;
  __u32 formats;
  __u32 min_buffer;
  __u32 reserved[15];
} __attribute__((packed, aligned(4)));
struct snd_codec {
  __u32 id;
  __u32 ch_in;
  __u32 ch_out;
  __u32 sample_rate;
  __u32 bit_rate;
  __u32 rate_control;
  __u32 profile;
  __u32 level;
  __u32 ch_mode;
  __u32 format;
  __u32 align;
  union snd_codec_options options;
  __u32 reserved[3];
} __attribute__((packed, aligned(4)));
#endif

"""

```