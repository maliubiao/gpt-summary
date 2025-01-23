Response:
Let's break down the thought process for analyzing this C header file.

**1. Initial Understanding & Context:**

The first step is to understand the context provided: "bionic/libc/kernel/uapi/sound/sfnt_info.handroid". This tells us a lot:

* **bionic:** This is the Android C library. This means the definitions are likely used in system-level audio processing within Android.
* **libc/kernel/uapi:**  This path suggests that the header file defines the *user-space API* (uapi) for interacting with the kernel. Specifically, it's about the kernel's sound subsystem.
* **sound/sfnt_info.h:** This clearly indicates that the file deals with "SoundFont" information. SoundFonts are files containing sampled instrument sounds.
* **.handroid:** This suffix often indicates an Android-specific or modified version of a standard kernel header.

Therefore, the core purpose is likely to define data structures and ioctl commands for user-space applications to interact with the kernel's SoundFont handling mechanisms.

**2. Analyzing the Header File Structure:**

Next, I scan through the file to identify key elements:

* **Header Guards:** `#ifndef __SOUND_SFNT_INFO_H` and `#define __SOUND_SFNT_INFO_H` are standard header guards to prevent multiple inclusions. This is a basic but important observation.
* **Includes:** `#include <sound/asound.h>` indicates a dependency on another sound-related header, likely containing fundamental audio definitions.
* **Endianness:** The `#ifdef SNDRV_BIG_ENDIAN` block hints at platform-specific byte ordering, which is crucial for data interpretation. The `SNDRV_OSS_PATCHKEY` macro shows how patch keys are defined based on endianness.
* **Structures:** The core of the file consists of several `struct` definitions: `soundfont_patch_info`, `soundfont_open_parm`, `soundfont_voice_parm`, `soundfont_voice_info`, `soundfont_voice_rec_hdr`, `soundfont_sample_info`, `soundfont_voice_map`, and `snd_emux_misc_mode`. Each structure likely represents a distinct aspect of SoundFont handling.
* **Macros:**  Various `#define` directives are used for:
    * **Constants:**  Like `SNDRV_OSS_SOUNDFONT_PATCH`, `SNDRV_SFNT_LOAD_INFO`, `SNDRV_SFNT_PAT_TYPE_MISC`,  `SNDRV_SFNT_MODE_ROMSOUND`, etc. These provide symbolic names for magic numbers and flags.
    * **String Literals:**  Like `SNDRV_EMUX_HWDEP_NAME`.
    * **Version Numbers:** Like `SNDRV_EMUX_VERSION`.
    * **IOCTL Codes:**  Like `SNDRV_EMUX_IOCTL_VERSION`, `SNDRV_EMUX_IOCTL_LOAD_PATCH`, etc. The `_IOR`, `_IOWR`, `_IO` macros strongly suggest these are used for ioctl calls.

**3. Deducing Functionality from Structures and Macros:**

Now, I start to connect the dots and infer the purpose of each structure and macro:

* **`soundfont_patch_info`:** This structure likely holds information about a SoundFont patch (an instrument). The `key`, `device_no`, `sf_id`, `type`, and `len` fields suggest identification, location, and type of operation. The nested `#define`s within this structure further specify the different types of patch operations (load info, load data, open, close, etc.).
* **`soundfont_open_parm`:**  This seems to define parameters for opening a SoundFont patch, including its type (`MISC`, `GUS`, `MAP`) and flags (`LOCKED`, `SHARED`). The `name` field likely holds the patch's name.
* **`soundfont_voice_parm`:** This structure appears to contain parameters for controlling individual voices (notes) within a SoundFont instrument, including modulation, volume, and filter settings.
* **`soundfont_voice_info`:** This structure probably describes a specific voice or sample within a SoundFont, including its ID, sample number, start/end points, looping information, and pitch/velocity ranges.
* **`soundfont_voice_rec_hdr`:** This likely acts as a header for a record of voice information, possibly used when loading or managing voices.
* **`soundfont_sample_info`:** This structure describes the properties of a raw audio sample within a SoundFont, such as its size, format (8-bit, unsigned, stereo), and looping characteristics.
* **`soundfont_voice_map`:** This structure probably defines mappings between different banks, instruments, and keys, allowing for complex sound organization.
* **`snd_emux_misc_mode`:** This seems to be a more generic structure for setting miscellaneous modes for an "Emux WaveTable" device.
* **IOCTL Macros:** The `SNDRV_EMUX_IOCTL_*` macros clearly define the ioctl commands that can be sent to the kernel driver. For instance, `SNDRV_EMUX_IOCTL_LOAD_PATCH` suggests a way to load SoundFont patch data.

**4. Connecting to Android Functionality:**

Given that this is within the Android bionic library, I consider how this might be used:

* **Audio Playback:**  Android's media framework likely uses these structures and ioctls to load and play back audio using SoundFonts. This is relevant for MIDI playback, software synthesizers, and potentially some system sounds.
* **Hardware Abstraction:** This header file probably provides an abstraction layer for interacting with hardware or software synthesizers that support the SoundFont format. The "Emux WaveTable" name suggests a possible hardware or software synthesizer component.

**5. Considering Dynamic Linking (although the header itself doesn't directly show it):**

While the header file *defines* the interface, the actual *implementation* of the ioctl calls and the kernel driver would reside in kernel modules and potentially linked libraries. User-space applications would link against the bionic library, which provides wrappers around the system calls.

**6. Thinking about Common Errors and Usage:**

Based on the structure definitions, potential errors could involve:

* **Incorrect IOCTL Codes:** Using the wrong ioctl number.
* **Invalid Data Structures:**  Populating the structures with incorrect values.
* **Memory Management:**  Not allocating enough memory for data buffers.
* **Endianness Issues:** If not handled correctly, data interpretation can be wrong.

**7. Planning Frida Hook Examples (Mental Outline):**

To debug, I'd consider hooking:

* **The ioctl system call:** To intercept the calls made using the `SNDRV_EMUX_IOCTL_*` macros. This would reveal the specific commands and data being sent to the kernel.
* **Functions within the Android media framework:** To see how these structures are used at a higher level. Specifically, I'd look for functions related to MIDI playback or SoundFont loading.

**8. Structuring the Output:**

Finally, I would organize the information into logical sections, as shown in the example answer, covering functionality, Android relevance, function implementation (as much as possible from the header), dynamic linking (conceptually), potential errors, and Frida hooking.

This iterative process of examining the code, understanding the context, inferring purpose, and considering practical usage leads to a comprehensive analysis of the header file.
这是位于 `bionic/libc/kernel/uapi/sound/sfnt_info.h` 的源代码文件，它定义了用于与内核声音子系统交互，特别是关于 SoundFont (SFNT) 信息的结构体和宏定义。SoundFont 是一种包含乐器采样数据的常见格式。由于它位于 `uapi` (用户空间 API) 目录下，这意味着这些定义是用户空间程序用来与内核驱动程序通信的接口。

以下是该文件的功能列表和详细解释：

**主要功能:**

1. **定义与 SoundFont 相关的内核接口:**  该文件定义了一系列 C 结构体，用于在用户空间程序和内核驱动程序之间传递关于 SoundFont 数据的信息。这允许用户空间的音频应用程序（如音乐播放器、合成器等）与内核中的 SoundFont 处理模块进行交互。

2. **定义用于操作 SoundFont 数据的 IO 控制命令 (ioctl):** 文件中定义了多个以 `SNDRV_EMUX_IOCTL_` 开头的宏，这些宏代表了可以发送给内核驱动程序的 IO 控制命令。这些命令用于加载、卸载、管理 SoundFont 数据和控制相关的硬件/软件设备。

**与 Android 功能的关系和举例说明:**

该文件定义的接口直接关系到 Android 的音频功能，特别是涉及到以下方面：

* **MIDI 回放:**  Android 系统或应用可以使用 SoundFont 来渲染 MIDI 文件。MIDI 文件本身只包含音符、乐器等信息，而 SoundFont 提供了实际的乐器声音样本。当 Android 播放 MIDI 时，它可能会使用内核提供的 SoundFont 功能来合成音频。
* **软件合成器 (Software Synthesizers):**  某些 Android 应用或音频中间件可能会使用 SoundFont 作为其声音库，通过与内核交互来加载和管理这些声音资源。
* **硬件合成器抽象:** 尽管文件名包含 "Emux WaveTable"，这可能指的是一种特定的硬件或软件合成器，但这里的结构体和 ioctl 命令的设计目标是提供一个相对通用的接口来操作 SoundFont 数据，而不仅仅局限于特定的硬件。

**举例说明:**

假设一个 Android 音乐播放器应用需要播放一个 MIDI 文件。它可能会执行以下步骤，间接或直接地使用到这里定义的接口：

1. **加载 SoundFont 文件:** 应用可能通过某种方式（例如，从存储中读取）获取一个 SoundFont 文件 (`.sf2` 文件)。
2. **与内核交互 (通过 AudioFlinger 或其他音频服务):**  应用（或者更可能是 Android 的音频服务 AudioFlinger）会使用系统调用（例如 `ioctl`）向内核发送命令，以加载 SoundFont 文件中的数据。 这时，`SNDRV_EMUX_IOCTL_LOAD_PATCH` 这样的 ioctl 命令以及 `soundfont_patch_info` 结构体就可能被使用。
3. **指定乐器和音符:** 当 MIDI 文件指示播放某个音符时，音频服务会使用加载的 SoundFont 数据来合成相应的声音。内核驱动程序会根据 MIDI 事件和 SoundFont 中的信息，生成音频数据。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **不包含任何 libc 函数的实现**。它仅仅定义了数据结构和宏。实际的 libc 函数（如 `ioctl` 系统调用的封装函数）的实现位于 bionic 库的其他部分。

* **`ioctl` 系统调用:**  `ioctl` 是一个通用的 Unix 系统调用，用于对设备驱动程序执行设备特定的控制操作。它的基本原型是 `int ioctl(int fd, unsigned long request, ...)`。
    * **`fd`:**  文件描述符，通常是打开的设备文件的文件描述符。
    * **`request`:**  一个设备特定的请求码，通常由宏定义，例如 `SNDRV_EMUX_IOCTL_LOAD_PATCH`。
    * **`...`:**  可选的参数，其类型和含义取决于 `request`。在这个场景下，通常是指向结构体的指针，例如 `soundfont_patch_info`。

当用户空间程序调用 `ioctl` 时，内核会根据文件描述符找到对应的设备驱动程序，并将 `request` 和参数传递给驱动程序的 `ioctl` 处理函数。驱动程序会根据 `request` 执行相应的操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身 **不直接涉及 dynamic linker 的功能**。它定义的是内核接口。然而，用户空间程序需要链接到 bionic 库才能使用 `ioctl` 等系统调用。

**SO 布局样本 (bionic 库相关部分):**

```
/system/lib64/libc.so  (或 /system/lib/libc.so)
├── ... (其他符号)
├── ioctl  <--- ioctl 系统调用的封装函数
├── ...
```

**链接的处理过程:**

1. **编译时链接:** 当用户空间的应用程序使用 `ioctl` 函数时，编译器会将该函数标记为需要链接的符号。
2. **运行时链接:** 当应用程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载应用程序依赖的共享库，包括 `libc.so`。
3. **符号解析:** dynamic linker 会解析应用程序中对 `ioctl` 函数的引用，将其绑定到 `libc.so` 中 `ioctl` 函数的实际地址。
4. **系统调用:** 当应用程序调用 `ioctl` 时，实际上会执行 `libc.so` 中 `ioctl` 的封装函数。这个封装函数会将参数传递给内核，触发内核中对应设备驱动程序的处理逻辑。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要加载一个 SoundFont 补丁：

**假设输入:**

* **`fd`:**  代表音频设备的打开文件描述符 (例如，`/dev/snd/hwC0D0`).
* **`request`:**  `SNDRV_EMUX_IOCTL_LOAD_PATCH`.
* **`argp` (指向 `soundfont_patch_info` 结构体的指针):**

```c
struct soundfont_patch_info patch_info;
patch_info.key = SNDRV_OSS_SOUNDFONT_PATCH; // 0xfd07 (假设小端)
patch_info.device_no = 0;
patch_info.sf_id = 1;
patch_info.optarg = 0;
patch_info.len = 1024; // 假设要加载的数据长度
patch_info.type = SNDRV_SFNT_LOAD_DATA;
patch_info.reserved = 0;
```

**可能的输出:**

* **成功:** `ioctl` 函数返回 0。内核驱动程序已成功接收并开始处理加载 SoundFont 数据的请求。之后，可能还需要发送更多数据（实际的 SoundFont 数据）。
* **失败:** `ioctl` 函数返回 -1，并设置 `errno` 以指示错误原因 (例如，设备忙、无效参数等)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的 ioctl 命令:** 使用了错误的 `request` 值，导致内核驱动程序无法识别请求。
   ```c
   ioctl(fd, SNDRV_EMUX_IOCTL_RESET_SAMPLES + 1, &patch_info); // 错误的命令
   ```

2. **未正确初始化结构体:**  `soundfont_patch_info` 结构体中的某些字段未正确设置，例如 `len` 与实际要发送的数据长度不符。
   ```c
   struct soundfont_patch_info patch_info;
   patch_info.key = SNDRV_OSS_SOUNDFONT_PATCH;
   // ... 其他字段未初始化
   ioctl(fd, SNDRV_EMUX_IOCTL_LOAD_PATCH, &patch_info); // 可能导致内核错误
   ```

3. **传递无效的指针:**  传递给 `ioctl` 的指针指向无效的内存地址。
   ```c
   struct soundfont_patch_info *patch_info_ptr = NULL;
   ioctl(fd, SNDRV_EMUX_IOCTL_LOAD_PATCH, patch_info_ptr); // 导致段错误
   ```

4. **权限问题:**  用户空间程序可能没有足够的权限来访问 `/dev/snd/hwC0D0` 等设备文件。

5. **设备未打开:** 在调用 `ioctl` 之前，没有成功打开对应的音频设备文件。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，用户空间的应用程序不会直接调用 `ioctl` 来操作 SoundFont。Android Framework 提供更高级别的抽象。其调用链可能如下：

1. **NDK (Native Development Kit) 或 Java 代码:**  应用程序可以使用 NDK 调用 C/C++ 代码，或者使用 Java API (如 `android.media.midi`)。
2. **`android.media.midi` (Java Framework):**  如果涉及 MIDI，Java Framework 提供了 `MidiManager`, `MidiDevice`, `MidiOutputPort` 等类来处理 MIDI 通信。
3. **`android_media_midi_*` (JNI Bridge):** Java Framework 调用 Native 代码，这些 Native 代码通常位于 `frameworks/base/core/jni/android_media_midi.cpp`。
4. **AudioFlinger (System Service):**  Android 的音频服务 `AudioFlinger` 负责音频的路由、处理和输出。当播放 MIDI 或使用软件合成器时，相关的请求可能会传递给 `AudioFlinger`。
5. **Kernel Driver (ALSA/OSS):** `AudioFlinger` 或底层的音频库会通过系统调用（包括 `ioctl`) 与内核的音频驱动程序（例如，基于 ALSA 或 OSS）交互。
6. **`sfnt_info.h` 定义的结构体和 ioctl:**  在 `AudioFlinger` 或更底层的驱动程序中，会使用 `sfnt_info.h` 中定义的结构体和 ioctl 命令来加载和管理 SoundFont 数据。

**Frida Hook 示例:**

可以使用 Frida hook `ioctl` 系统调用，并过滤出与音频设备和 SoundFont 相关的调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['name'], message['payload']['args']))
    else:
        print(message)

session = frida.attach("com.example.myapp") # 替换为你的应用进程名

script = session.create_script("""
    const ioctlPtr = Module.getExportByName(null, "ioctl");

    Interceptor.attach(ioctlPtr, {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();
            const argp = args[2];

            // 过滤与音频设备相关的 ioctl 调用 (假设你的音频设备文件描述符范围)
            if (fd > 0 && fd < 100) {
                let requestName = "UNKNOWN";
                // 根据 sfnt_info.h 中的定义，尝试解析 request
                if (request === 0xc8814848) { // SNDRV_EMUX_IOCTL_LOAD_PATCH 的值 (可能需要根据架构调整)
                    requestName = "SNDRV_EMUX_IOCTL_LOAD_PATCH";
                    // 可以进一步解析 argp 指向的结构体
                    let patchInfo = {};
                    patchInfo.key = Memory.readU16(argp);
                    patchInfo.device_no = Memory.readS16(argp.add(2));
                    patchInfo.sf_id = Memory.readU16(argp.add(4));
                    // ... 解析其他字段
                    send({ name: "ioctl", args: [fd, requestName, patchInfo] });
                } else if (request === 0xc8824848) {
                    requestName = "SNDRV_EMUX_IOCTL_RESET_SAMPLES";
                    send({ name: "ioctl", args: [fd, requestName] });
                } else {
                    send({ name: "ioctl", args: [fd, request] });
                }
            }
        }
    });
""");

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码:**

1. **`frida.attach("com.example.myapp")`:** 连接到目标 Android 应用程序的进程。
2. **`Module.getExportByName(null, "ioctl")`:** 获取 `ioctl` 函数的地址。
3. **`Interceptor.attach(ioctlPtr, { ... })`:**  拦截对 `ioctl` 函数的调用。
4. **`onEnter: function(args)`:**  在 `ioctl` 函数执行之前被调用，`args` 包含了传递给 `ioctl` 的参数。
5. **过滤设备描述符:**  `if (fd > 0 && fd < 100)`  这是一个简单的过滤条件，你需要根据实际情况调整以捕获与音频设备相关的调用。
6. **解析 `request`:**  根据 `sfnt_info.h` 中的宏定义，检查 `request` 的值，并尝试将其解析为可读的名称。**注意：ioctl 的值可能会因架构而异，你需要根据你的目标环境获取实际值。可以使用 `adb shell getprop ro.hardware` 和查看内核源代码来确定。**
7. **解析结构体:** 如果 `request` 是 `SNDRV_EMUX_IOCTL_LOAD_PATCH`，则尝试读取 `argp` 指向的 `soundfont_patch_info` 结构体的字段。
8. **`send({ name: "ioctl", args: [...] })`:**  将捕获到的信息发送回 Frida 客户端。

通过运行这个 Frida 脚本，你可以在目标应用程序运行时，观察其对 `ioctl` 的调用，特别是与 SoundFont 加载相关的操作，从而理解 Android Framework 或 NDK 是如何一步步地与内核中的 SoundFont 功能交互的。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/sound/sfnt_info.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __SOUND_SFNT_INFO_H
#define __SOUND_SFNT_INFO_H
#include <sound/asound.h>
#ifdef SNDRV_BIG_ENDIAN
#define SNDRV_OSS_PATCHKEY(id) (0xfd00 | id)
#else
#define SNDRV_OSS_PATCHKEY(id) ((id << 8) | 0xfd)
#endif
struct soundfont_patch_info {
  unsigned short key;
#define SNDRV_OSS_SOUNDFONT_PATCH SNDRV_OSS_PATCHKEY(0x07)
  short device_no;
  unsigned short sf_id;
  short optarg;
  int len;
  short type;
#define SNDRV_SFNT_LOAD_INFO 0
#define SNDRV_SFNT_LOAD_DATA 1
#define SNDRV_SFNT_OPEN_PATCH 2
#define SNDRV_SFNT_CLOSE_PATCH 3
#define SNDRV_SFNT_REPLACE_DATA 5
#define SNDRV_SFNT_MAP_PRESET 6
#define SNDRV_SFNT_PROBE_DATA 8
#define SNDRV_SFNT_REMOVE_INFO 9
  short reserved;
};
#define SNDRV_SFNT_PATCH_NAME_LEN 32
struct soundfont_open_parm {
  unsigned short type;
#define SNDRV_SFNT_PAT_TYPE_MISC 0
#define SNDRV_SFNT_PAT_TYPE_GUS 6
#define SNDRV_SFNT_PAT_TYPE_MAP 7
#define SNDRV_SFNT_PAT_LOCKED 0x100
#define SNDRV_SFNT_PAT_SHARED 0x200
  short reserved;
  char name[SNDRV_SFNT_PATCH_NAME_LEN];
};
struct soundfont_voice_parm {
  unsigned short moddelay;
  unsigned short modatkhld;
  unsigned short moddcysus;
  unsigned short modrelease;
  short modkeyhold, modkeydecay;
  unsigned short voldelay;
  unsigned short volatkhld;
  unsigned short voldcysus;
  unsigned short volrelease;
  short volkeyhold, volkeydecay;
  unsigned short lfo1delay;
  unsigned short lfo2delay;
  unsigned short pefe;
  unsigned short fmmod;
  unsigned short tremfrq;
  unsigned short fm2frq2;
  unsigned char cutoff;
  unsigned char filterQ;
  unsigned char chorus;
  unsigned char reverb;
  unsigned short reserved[4];
};
struct soundfont_voice_info {
  unsigned short sf_id;
  unsigned short sample;
  int start, end;
  int loopstart, loopend;
  short rate_offset;
  unsigned short mode;
#define SNDRV_SFNT_MODE_ROMSOUND 0x8000
#define SNDRV_SFNT_MODE_STEREO 1
#define SNDRV_SFNT_MODE_LOOPING 2
#define SNDRV_SFNT_MODE_NORELEASE 4
#define SNDRV_SFNT_MODE_INIT_PARM 8
  short root;
  short tune;
  unsigned char low, high;
  unsigned char vellow, velhigh;
  signed char fixkey, fixvel;
  signed char pan, fixpan;
  short exclusiveClass;
  unsigned char amplitude;
  unsigned char attenuation;
  short scaleTuning;
  struct soundfont_voice_parm parm;
  unsigned short sample_mode;
};
struct soundfont_voice_rec_hdr {
  unsigned char bank;
  unsigned char instr;
  char nvoices;
  char write_mode;
#define SNDRV_SFNT_WR_APPEND 0
#define SNDRV_SFNT_WR_EXCLUSIVE 1
#define SNDRV_SFNT_WR_REPLACE 2
};
struct soundfont_sample_info {
  unsigned short sf_id;
  unsigned short sample;
  int start, end;
  int loopstart, loopend;
  int size;
  short dummy;
  unsigned short mode_flags;
#define SNDRV_SFNT_SAMPLE_8BITS 1
#define SNDRV_SFNT_SAMPLE_UNSIGNED 2
#define SNDRV_SFNT_SAMPLE_NO_BLANK 4
#define SNDRV_SFNT_SAMPLE_SINGLESHOT 8
#define SNDRV_SFNT_SAMPLE_BIDIR_LOOP 16
#define SNDRV_SFNT_SAMPLE_STEREO_LEFT 32
#define SNDRV_SFNT_SAMPLE_STEREO_RIGHT 64
#define SNDRV_SFNT_SAMPLE_REVERSE_LOOP 128
  unsigned int truesize;
};
struct soundfont_voice_map {
  int map_bank, map_instr, map_key;
  int src_bank, src_instr, src_key;
};
#define SNDRV_EMUX_HWDEP_NAME "Emux WaveTable"
#define SNDRV_EMUX_VERSION ((1 << 16) | (0 << 8) | 0)
struct snd_emux_misc_mode {
  int port;
  int mode;
  int value;
  int value2;
};
#define SNDRV_EMUX_IOCTL_VERSION _IOR('H', 0x80, unsigned int)
#define SNDRV_EMUX_IOCTL_LOAD_PATCH _IOWR('H', 0x81, struct soundfont_patch_info)
#define SNDRV_EMUX_IOCTL_RESET_SAMPLES _IO('H', 0x82)
#define SNDRV_EMUX_IOCTL_REMOVE_LAST_SAMPLES _IO('H', 0x83)
#define SNDRV_EMUX_IOCTL_MEM_AVAIL _IOW('H', 0x84, int)
#define SNDRV_EMUX_IOCTL_MISC_MODE _IOWR('H', 0x84, struct snd_emux_misc_mode)
#endif
```