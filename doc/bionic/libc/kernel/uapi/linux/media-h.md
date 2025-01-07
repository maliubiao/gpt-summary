Response:
Let's break down the thought process to answer the user's request about the `media.h` header file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the provided `media.h` file within the context of Android's Bionic library. They are asking for a breakdown of its capabilities, connections to Android features, explanations of libc functions (even though this file *doesn't* define libc functions, a key point to address), dynamic linker aspects (also not directly present, but related through its use in the Android system), debugging information, and common usage errors.

**2. Initial Analysis of the File:**

* **Header File:** The `#ifndef __LINUX_MEDIA_H` and `#define __LINUX_MEDIA_H` clearly indicate this is a header file designed to prevent multiple inclusions.
* **Kernel UAPI:** The path `bionic/libc/kernel/uapi/linux/media.handroid` tells us this is a user-space API (UAPI) header file, copied from the Linux kernel for use in Android's user-space libraries. This means it defines structures and constants for interacting with the kernel's media subsystem.
* **Includes:**  `#include <linux/ioctl.h>` and `#include <linux/types.h>` are crucial. This immediately suggests that the primary mechanism for interaction will be `ioctl` system calls.
* **Data Structures:** The file primarily defines `struct` types: `media_device_info`, `media_entity_desc`, `media_pad_desc`, `media_link_desc`, `media_links_enum`, `media_v2_entity`, `media_v2_intf_devnode`, `media_v2_interface`, `media_v2_pad`, `media_v2_link`, and `media_v2_topology`. These structures likely represent the building blocks of the media framework in the kernel.
* **Constants and Macros:**  A significant portion of the file defines macros and constants (starting with `MEDIA_ENT_F_`, `MEDIA_ENT_FL_`, `MEDIA_PAD_FL_`, `MEDIA_LNK_FL_`, `MEDIA_INTF_T_`, `MEDIA_IOC_`, etc.). These define flags, types, and `ioctl` command codes.

**3. Addressing Each Part of the User's Request:**

* **Functionality:** Based on the structures and constants, the primary function is to provide a way for user-space applications to:
    * **Discover media devices:** (`media_device_info`)
    * **Enumerate media entities:** (`media_entity_desc`) - representing components like sensors, decoders, etc.
    * **Describe connections (links) between entities:** (`media_link_desc`)
    * **Describe input/output points (pads) of entities:** (`media_pad_desc`)
    * **Get the overall topology:** (`media_v2_topology`)
    * **Configure links:** (`MEDIA_IOC_SETUP_LINK`)
    * **Allocate and manage requests (less detailed):** (`MEDIA_IOC_REQUEST_ALLOC`, `MEDIA_REQUEST_IOC_QUEUE`, `MEDIA_REQUEST_IOC_REINIT`)

* **Relationship to Android:**  The media framework is fundamental to Android's camera, video playback, and audio subsystems. Examples include:
    * **Camera:** The camera HAL interacts with sensor devices using these structures.
    * **Video Playback:** Video decoders and display pipelines use this framework.
    * **Audio:** Audio capture and playback devices are also represented.

* **libc Function Explanations:**  This is a crucial point of clarification. The file *doesn't* define libc functions. It defines data structures and macros. The *usage* of these structures involves libc functions like `open`, `ioctl`, and `close`. The explanation should focus on how `ioctl` works in conjunction with these structures.

* **Dynamic Linker:** This file doesn't directly deal with the dynamic linker. However, the libraries that *use* this header (like the camera HAL) *are* dynamically linked. The explanation should provide a general overview of dynamic linking in Android and how shared libraries are loaded. A sample `so` layout and linking process should be described conceptually.

* **Logical Inference (Assumptions and Outputs):**  An example of how a camera application might use these structures to find a sensor and a processing unit can illustrate the logical flow.

* **Common Usage Errors:** Errors typically involve:
    * Incorrect `ioctl` commands.
    * Passing incorrect data structures to `ioctl`.
    * Not handling errors from `ioctl`.
    * Trying to perform operations on non-existent entities or links.

* **Android Framework/NDK Path and Frida Hooking:** This requires tracing the path from high-level Android APIs down to the kernel.
    * **Framework:** Camera2 APIs -> Camera Service -> Camera HAL (Hardware Abstraction Layer).
    * **NDK:** MediaCodec, Camera2 NDK APIs.
    * **Frida:**  Hooking the `ioctl` system call with appropriate filters (file descriptor pointing to a media device) would be a powerful way to observe the interaction.

**4. Structuring the Response:**

The response should be organized logically, addressing each part of the user's request in turn. Using clear headings and examples makes the information easier to understand. It's important to explicitly state what the file *does* and *does not* do (e.g., it defines structures, not implements libc functions).

**5. Refining and Reviewing:**

After drafting the initial response, review it to ensure accuracy, clarity, and completeness. Double-check the explanations and examples. Ensure that the response directly addresses all parts of the user's request. For example, explicitly addressing the misunderstanding about libc functions is important. Also, providing a concrete Frida example enhances the practical value of the answer.

By following this thought process, which involves understanding the core request, analyzing the provided file, addressing each point systematically, and structuring the response clearly, a comprehensive and helpful answer can be generated.
这个 `bionic/libc/kernel/uapi/linux/media.h` 文件是 Android Bionic C 库的一部分，它定义了 Linux 内核中媒体设备子系统的用户空间 API。 简单来说，它提供了应用程序与内核中的媒体设备（如摄像头、视频解码器、音频设备等）进行交互的接口。由于它位于 `uapi` 目录下，这意味着它定义的是用户空间程序可以直接使用的结构体、宏和常量，用于和内核驱动进行通信。

**它的功能：**

1. **定义媒体设备信息结构体 (`media_device_info`):**  这个结构体用于描述一个媒体设备的基本信息，例如驱动名称、型号、序列号、总线信息以及驱动版本等。应用程序可以使用这个结构体来查询系统中存在的媒体设备的信息。

   ```c
   struct media_device_info {
     char driver[16];
     char model[32];
     char serial[40];
     char bus_info[32];
     __u32 media_version;
     __u32 hw_revision;
     __u32 driver_version;
     __u32 reserved[31];
   };
   ```

2. **定义媒体实体描述结构体 (`media_entity_desc`):**  媒体设备通常由多个实体组成，例如一个摄像头模组可能包含传感器、ISP（图像信号处理器）等多个实体。这个结构体描述了一个媒体实体的属性，包括 ID、名称、类型、修订版本、标志、分组 ID、连接的 pad 数量和 link 数量等。  它还包含一个 union，可以用来获取特定类型的设备节点信息（如 V4L2 设备的主次设备号，ALSA 设备的 card/device/subdevice 信息等）。

   ```c
   struct media_entity_desc {
     __u32 id;
     char name[32];
     __u32 type;
     __u32 revision;
     __u32 flags;
     __u32 group_id;
     __u16 pads;
     __u16 links;
     __u32 reserved[4];
     union {
       struct {
         __u32 major;
         __u32 minor;
       } dev;
       struct {
         __u32 card;
         __u32 device;
         __u32 subdevice;
       } alsa;
       struct {
         __u32 major;
         __u32 minor;
       } v4l;
       struct {
         __u32 major;
         __u32 minor;
       } fb;
       int dvb;
       __u8 raw[184];
     };
   };
   ```

3. **定义 Pad 和 Link 相关的结构体 (`media_pad_desc`, `media_link_desc`, `media_links_enum`):** 媒体实体之间通过 Pad (逻辑上的输入/输出端口) 连接。 `media_pad_desc` 描述了一个 Pad 的信息，例如所属的实体 ID、索引和标志（SOURCE/SINK）。 `media_link_desc` 描述了两个 Pad 之间的连接关系。 `media_links_enum` 用于枚举一个实体上的所有 Pad 和 Link。

4. **定义枚举和常量:**  文件中定义了大量的宏和常量，用于表示不同的媒体实体类型 (`MEDIA_ENT_F_*`),  Pad 的标志 (`MEDIA_PAD_FL_*`), Link 的标志 (`MEDIA_LNK_FL_*`), 以及接口类型 (`MEDIA_INTF_T_*`) 等。 这些常量帮助应用程序理解和操作媒体设备的各个组件。

5. **定义 ioctl 命令 (`MEDIA_IOC_*`):**  最重要的是，这个头文件定义了一系列 `ioctl` 命令，用户空间的应用程序可以使用这些命令与内核中的媒体设备驱动程序进行交互。 例如：
   - `MEDIA_IOC_DEVICE_INFO`: 获取媒体设备信息。
   - `MEDIA_IOC_ENUM_ENTITIES`: 枚举媒体设备上的实体。
   - `MEDIA_IOC_ENUM_LINKS`: 枚举实体之间的连接。
   - `MEDIA_IOC_SETUP_LINK`: 设置实体之间的连接。
   - `MEDIA_IOC_G_TOPOLOGY`: 获取媒体设备的拓扑结构。

**与 Android 功能的关系及举例说明：**

`media.h` 中定义的接口是 Android 多媒体框架的基础。Android 的 CameraService、MediaCodec 等核心组件都依赖于这些底层的内核接口。

**举例：摄像头子系统**

1. **设备发现:**  当 Android 系统启动或者有新的摄像头连接时，CameraService 会通过 `open()` 系统调用打开 `/dev/media0` (或其他 media 设备节点)，然后使用 `ioctl(fd, MEDIA_IOC_DEVICE_INFO, &dev_info)` 来获取摄像头的基本信息，例如驱动名称和型号。

2. **枚举实体:** 接下来，CameraService 会使用 `ioctl(fd, MEDIA_IOC_ENUM_ENTITIES, &entity)` 循环调用来枚举摄像头模组上的各个实体，例如传感器 ( `MEDIA_ENT_T_V4L2_SUBDEV_SENSOR` ) 和 ISP (可能属于 `MEDIA_ENT_T_PROC_VIDEO_ISP` 或其他处理单元)。  通过 `entity.name` 可以获取实体的名称，通过 `entity.type` 可以判断实体的类型。

3. **枚举连接:**  CameraService 会使用 `ioctl(fd, MEDIA_IOC_ENUM_LINKS, &links_enum)` 来获取实体之间的连接关系。例如，传感器的输出 Pad 连接到 ISP 的输入 Pad。

4. **配置连接:**  根据硬件配置，CameraService 可能会使用 `ioctl(fd, MEDIA_IOC_SETUP_LINK, &link_desc)` 来启用或禁用某些连接。

**详细解释 libc 函数的功能是如何实现的:**

需要明确的是，`media.h` **本身并不实现任何 libc 函数**。 它只是一个头文件，定义了数据结构和常量。 用户空间的程序（包括 Android framework 和 NDK 应用）会使用标准的 libc 函数，例如：

* **`open()`:** 用于打开媒体设备的设备节点，例如 `/dev/media0`。这是与内核媒体驱动交互的第一步。
* **`close()`:** 用于关闭打开的媒体设备文件描述符。
* **`ioctl()`:** 这是与内核媒体驱动进行通信的核心函数。应用程序将 `media.h` 中定义的 `MEDIA_IOC_*` 命令以及相应的结构体指针传递给 `ioctl()`，从而向内核发送控制命令或请求数据。

**`ioctl()` 的工作原理：**

1. **系统调用:** 用户空间的应用程序调用 `ioctl()` 函数，这会触发一个系统调用，将控制权转移到内核。
2. **文件描述符查找:** 内核根据传入的文件描述符找到对应的设备驱动程序。
3. **命令分发:** 内核根据 `ioctl()` 调用中指定的命令码 (`MEDIA_IOC_*`)，将请求分发到设备驱动程序中相应的处理函数。
4. **驱动处理:** 设备驱动程序根据命令码执行相应的操作，例如读取设备信息、枚举实体、配置连接等。驱动程序会填充传入的结构体指针指向的内存区域，将结果返回给用户空间。
5. **返回用户空间:** 内核将执行结果返回给用户空间的 `ioctl()` 调用，应用程序可以读取返回的数据或判断操作是否成功。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`media.h` 本身不直接涉及 dynamic linker 的功能。但是，使用 `media.h` 中定义的接口的库（例如 Camera HAL 相关的库）通常是动态链接库 (`.so` 文件)。

**`so` 布局样本：**

一个典型的 Android 动态链接库 (`.so`) 的布局可能如下：

```
.so 文件结构：
|--- .text        (代码段)
|--- .rodata      (只读数据段，例如字符串常量)
|--- .data        (已初始化数据段)
|--- .bss         (未初始化数据段)
|--- .plt         (Procedure Linkage Table，用于延迟绑定)
|--- .got.plt     (Global Offset Table for PLT)
|--- .dynsym      (动态符号表)
|--- .dynstr      (动态字符串表)
|--- .rel.dyn     (动态重定位表)
|--- .rel.plt     (PLT 的重定位表)
|--- ...          (其他段)
```

**链接的处理过程：**

1. **加载时链接器 (`linker64` 或 `linker`):** 当 Android 系统启动或者应用程序需要加载一个动态链接库时，加载时链接器负责将 `.so` 文件加载到内存中。
2. **解析 ELF 头:** 链接器解析 `.so` 文件的 ELF 头，获取加载地址、段信息、动态链接信息等。
3. **加载段:** 链接器根据段信息将 `.text`, `.rodata`, `.data`, `.bss` 等段加载到内存中的合适位置。
4. **处理依赖关系:** 链接器读取 `.dynamic` 段中的信息，找到该 `.so` 文件依赖的其他共享库。然后递归地加载这些依赖库。
5. **符号解析和重定位:**
   - **动态符号表 (`.dynsym`):**  包含了该 `.so` 文件导出的符号以及它引用的外部符号。
   - **动态字符串表 (`.dynstr`):**  包含了符号表中符号的名字。
   - **全局偏移表 (`.got.plt`):**  在加载时创建，用于存储外部符号的最终地址。
   - **过程链接表 (`.plt`):**  包含了对外部函数的调用桩。
   - **重定位表 (`.rel.dyn`, `.rel.plt`):**  包含了需要在加载时修改的地址信息。

   链接器会遍历重定位表，根据符号名在已加载的共享库中查找对应的符号地址，并将地址填入 `.got.plt` 中。  对于函数调用，初始时 `.plt` 中的代码会跳转到链接器，链接器解析符号并更新 `.got.plt`，后续的调用将直接通过 `.got.plt` 跳转到目标函数，这就是延迟绑定的过程。

**假设输入与输出 (逻辑推理):**

假设有一个用户空间的应用程序想要获取系统中第一个 V4L2 视频设备的信息。

**假设输入:**

* 打开 `/dev/media0` 设备节点成功，返回文件描述符 `fd`。
* 初始化 `media_entity_desc` 结构体 `entity`，并将 `entity.id` 初始化为 0，表示从第一个实体开始枚举。

**逻辑推理过程:**

1. 应用程序调用 `ioctl(fd, MEDIA_IOC_ENUM_ENTITIES, &entity)`。
2. 内核媒体驱动程序遍历其管理的实体列表。
3. 如果找到一个类型为 `MEDIA_ENT_T_V4L2_VIDEO` 的实体，驱动程序会将该实体的信息填充到 `entity` 结构体中。
4. `ioctl` 调用返回 0 (成功)。
5. 应用程序可以读取 `entity.name` 获取设备名称，读取 `entity.union.v4l.major` 和 `entity.union.v4l.minor` 获取 V4L2 设备的主次设备号。

**假设输出 (如果找到 V4L2 视频设备):**

* `ioctl` 返回值: 0
* `entity.name`:  例如 "imx6-mipi-csi2 a00c004.csi"
* `entity.type`:  `MEDIA_ENT_T_V4L2_VIDEO` 对应的数值
* `entity.union.v4l.major`:  例如 81
* `entity.union.v4l.minor`:  例如 0

**如果找不到 V4L2 视频设备:**

* `ioctl` 返回值: 0 (因为枚举到了最后一个实体)
* `entity.id` 会被设置为 0，表示枚举结束。
* 需要应用程序检查返回值和 `entity.id` 来判断是否找到了目标设备。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记检查 `ioctl` 的返回值:** `ioctl` 调用失败时会返回 -1，并设置 `errno`。如果应用程序不检查返回值，可能会在操作失败的情况下继续执行，导致程序崩溃或行为异常。

   ```c
   struct media_device_info dev_info;
   int fd = open("/dev/media0", O_RDWR);
   if (fd < 0) {
       perror("open /dev/media0 failed");
       return -1;
   }
   if (ioctl(fd, MEDIA_IOC_DEVICE_INFO, &dev_info) < 0) {
       perror("ioctl MEDIA_IOC_DEVICE_INFO failed"); // 应该检查返回值并处理错误
       // ... 错误处理逻辑 ...
   }
   close(fd);
   ```

2. **传递错误的 `ioctl` 命令或结构体:**  如果传递的 `ioctl` 命令与提供的结构体类型不匹配，或者结构体中的数据不正确，内核驱动程序可能会返回错误，甚至导致系统崩溃。

3. **没有正确初始化结构体:** 在调用 `ioctl` 之前，需要确保传递给 `ioctl` 的结构体已经被正确初始化。例如，在使用 `MEDIA_IOC_ENUM_ENTITIES` 循环枚举实体时，需要将 `entity.id` 初始化为 0 开始。

4. **权限问题:**  访问 `/dev/media*` 设备节点可能需要特定的权限。如果应用程序没有足够的权限，`open()` 调用会失败。

5. **并发访问问题:**  多个进程或线程同时访问同一个媒体设备可能会导致冲突。需要使用适当的同步机制来保护共享资源。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `media.h` 的路径 (以 Camera 为例):**

1. **Android 应用 (Java/Kotlin):**  应用程序使用 Android SDK 提供的 `android.hardware.camera2` 包中的 API 来访问摄像头。
2. **Camera Service (Java/Kotlin):**  应用程序的请求会被传递到系统服务 `CameraService`。
3. **Camera HAL (C/C++):**  `CameraService` 通过 HIDL (Hardware Interface Definition Language) 或 AIDL (Android Interface Definition Language) 与 Camera HAL (Hardware Abstraction Layer) 交互。Camera HAL 是一个动态链接库 (`.so`)，由设备制造商提供，用于与底层的摄像头硬件驱动程序进行通信。
4. **Kernel Media Driver (C):**  Camera HAL 使用标准的文件操作 (`open`, `close`, `ioctl`) 与内核中的媒体设备驱动程序进行交互。 在这个阶段，就会使用到 `media.h` 中定义的结构体和 `ioctl` 命令。

**NDK 到达 `media.h` 的路径:**

1. **NDK 应用 (C/C++):**  使用 NDK 开发的应用程序可以直接调用 Android 的底层 API，例如可以使用 `libmedia` 库中的函数。
2. **`libmedia` (C++):**  `libmedia` 是 Android 提供的一个 C++ 库，封装了与媒体相关的底层操作。
3. **Kernel Media Driver (C):**  `libmedia` 最终也会通过 `open`, `close`, `ioctl` 等系统调用与内核媒体驱动进行交互，同样会使用 `media.h` 中定义的接口。

**Frida Hook 示例:**

可以使用 Frida hook `ioctl` 系统调用，并过滤与媒体设备相关的操作，以观察 Android Framework 或 NDK 如何使用 `media.h` 中定义的接口。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.attach('com.android.camera2') # 替换为目标进程

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt31();
            const request = args[1].toInt31();

            // 检查文件描述符是否可能与 media 设备相关
            // 实际判断可能需要更精细的逻辑，例如检查文件路径
            if (fd > 0) {
                const cmd_str = {
                    0xc0187c00: "MEDIA_IOC_DEVICE_INFO",
                    0xc0107c01: "MEDIA_IOC_ENUM_ENTITIES",
                    0xc0187c02: "MEDIA_IOC_ENUM_LINKS",
                    0xc0107c03: "MEDIA_IOC_SETUP_LINK",
                    0xc0287c04: "MEDIA_IOC_G_TOPOLOGY",
                    // ... 其他 MEDIA_IOC_* 命令
                }[request];

                if (cmd_str) {
                    console.log(`[ioctl] fd: ${fd}, request: 0x${request.toString(16)} (${cmd_str})`);
                    // 可以进一步解析 args[2] 指向的结构体内容
                    // 例如，如果 request 是 MEDIA_IOC_ENUM_ENTITIES，可以读取 media_entity_desc 结构体
                }
            }
        },
        onLeave: function(retval) {
            // console.log('[ioctl] Returned:', retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print('[*] Script loaded, press Ctrl+C to exit')
    sys.stdin.read()

except frida.ProcessNotFoundError:
    print("Process not found. Please specify the process ID or name.")
except KeyboardInterrupt:
    print("Exiting...")

```

**使用方法:**

1. 将上述 Python 代码保存为 `hook_media_ioctl.py`。
2. 找到目标 Android 应用程序的进程 ID (PID) 或进程名，例如 "com.android.camera2"。
3. 运行 Frida 脚本： `frida -U -f <进程名> -l hook_media_ioctl.py` 或 `frida -U <PID> -l hook_media_ioctl.py`

**预期输出:**

Frida 脚本会 hook `ioctl` 系统调用，并在控制台上打印出与媒体设备相关的 `ioctl` 调用信息，包括文件描述符、`ioctl` 命令码以及对应的宏名称。通过观察这些信息，你可以了解 Android Framework 或 NDK 如何使用 `media.h` 中定义的接口与内核进行交互。

**总结:**

`bionic/libc/kernel/uapi/linux/media.h` 是 Android 访问底层媒体设备功能的重要接口，它定义了与内核媒体驱动交互的数据结构和 `ioctl` 命令。Android Framework 和 NDK 都通过调用标准的 libc 函数（如 `open` 和 `ioctl`）并使用这个头文件中定义的接口来实现对摄像头、视频解码器等媒体设备的操作。使用 Frida 可以方便地观察和调试这些底层的交互过程。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/media.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_MEDIA_H
#define __LINUX_MEDIA_H
#include <linux/ioctl.h>
#include <linux/types.h>
struct media_device_info {
  char driver[16];
  char model[32];
  char serial[40];
  char bus_info[32];
  __u32 media_version;
  __u32 hw_revision;
  __u32 driver_version;
  __u32 reserved[31];
};
#define MEDIA_ENT_F_BASE 0x00000000
#define MEDIA_ENT_F_OLD_BASE 0x00010000
#define MEDIA_ENT_F_OLD_SUBDEV_BASE 0x00020000
#define MEDIA_ENT_F_UNKNOWN MEDIA_ENT_F_BASE
#define MEDIA_ENT_F_V4L2_SUBDEV_UNKNOWN MEDIA_ENT_F_OLD_SUBDEV_BASE
#define MEDIA_ENT_F_DTV_DEMOD (MEDIA_ENT_F_BASE + 0x00001)
#define MEDIA_ENT_F_TS_DEMUX (MEDIA_ENT_F_BASE + 0x00002)
#define MEDIA_ENT_F_DTV_CA (MEDIA_ENT_F_BASE + 0x00003)
#define MEDIA_ENT_F_DTV_NET_DECAP (MEDIA_ENT_F_BASE + 0x00004)
#define MEDIA_ENT_F_IO_V4L (MEDIA_ENT_F_OLD_BASE + 1)
#define MEDIA_ENT_F_IO_DTV (MEDIA_ENT_F_BASE + 0x01001)
#define MEDIA_ENT_F_IO_VBI (MEDIA_ENT_F_BASE + 0x01002)
#define MEDIA_ENT_F_IO_SWRADIO (MEDIA_ENT_F_BASE + 0x01003)
#define MEDIA_ENT_F_CAM_SENSOR (MEDIA_ENT_F_OLD_SUBDEV_BASE + 1)
#define MEDIA_ENT_F_FLASH (MEDIA_ENT_F_OLD_SUBDEV_BASE + 2)
#define MEDIA_ENT_F_LENS (MEDIA_ENT_F_OLD_SUBDEV_BASE + 3)
#define MEDIA_ENT_F_TUNER (MEDIA_ENT_F_OLD_SUBDEV_BASE + 5)
#define MEDIA_ENT_F_IF_VID_DECODER (MEDIA_ENT_F_BASE + 0x02001)
#define MEDIA_ENT_F_IF_AUD_DECODER (MEDIA_ENT_F_BASE + 0x02002)
#define MEDIA_ENT_F_AUDIO_CAPTURE (MEDIA_ENT_F_BASE + 0x03001)
#define MEDIA_ENT_F_AUDIO_PLAYBACK (MEDIA_ENT_F_BASE + 0x03002)
#define MEDIA_ENT_F_AUDIO_MIXER (MEDIA_ENT_F_BASE + 0x03003)
#define MEDIA_ENT_F_PROC_VIDEO_COMPOSER (MEDIA_ENT_F_BASE + 0x4001)
#define MEDIA_ENT_F_PROC_VIDEO_PIXEL_FORMATTER (MEDIA_ENT_F_BASE + 0x4002)
#define MEDIA_ENT_F_PROC_VIDEO_PIXEL_ENC_CONV (MEDIA_ENT_F_BASE + 0x4003)
#define MEDIA_ENT_F_PROC_VIDEO_LUT (MEDIA_ENT_F_BASE + 0x4004)
#define MEDIA_ENT_F_PROC_VIDEO_SCALER (MEDIA_ENT_F_BASE + 0x4005)
#define MEDIA_ENT_F_PROC_VIDEO_STATISTICS (MEDIA_ENT_F_BASE + 0x4006)
#define MEDIA_ENT_F_PROC_VIDEO_ENCODER (MEDIA_ENT_F_BASE + 0x4007)
#define MEDIA_ENT_F_PROC_VIDEO_DECODER (MEDIA_ENT_F_BASE + 0x4008)
#define MEDIA_ENT_F_PROC_VIDEO_ISP (MEDIA_ENT_F_BASE + 0x4009)
#define MEDIA_ENT_F_VID_MUX (MEDIA_ENT_F_BASE + 0x5001)
#define MEDIA_ENT_F_VID_IF_BRIDGE (MEDIA_ENT_F_BASE + 0x5002)
#define MEDIA_ENT_F_ATV_DECODER (MEDIA_ENT_F_OLD_SUBDEV_BASE + 4)
#define MEDIA_ENT_F_DV_DECODER (MEDIA_ENT_F_BASE + 0x6001)
#define MEDIA_ENT_F_DV_ENCODER (MEDIA_ENT_F_BASE + 0x6002)
#define MEDIA_ENT_FL_DEFAULT (1U << 0)
#define MEDIA_ENT_FL_CONNECTOR (1U << 1)
#define MEDIA_ENT_ID_FLAG_NEXT (1U << 31)
struct media_entity_desc {
  __u32 id;
  char name[32];
  __u32 type;
  __u32 revision;
  __u32 flags;
  __u32 group_id;
  __u16 pads;
  __u16 links;
  __u32 reserved[4];
  union {
    struct {
      __u32 major;
      __u32 minor;
    } dev;
    struct {
      __u32 card;
      __u32 device;
      __u32 subdevice;
    } alsa;
    struct {
      __u32 major;
      __u32 minor;
    } v4l;
    struct {
      __u32 major;
      __u32 minor;
    } fb;
    int dvb;
    __u8 raw[184];
  };
};
#define MEDIA_PAD_FL_SINK (1U << 0)
#define MEDIA_PAD_FL_SOURCE (1U << 1)
#define MEDIA_PAD_FL_MUST_CONNECT (1U << 2)
struct media_pad_desc {
  __u32 entity;
  __u16 index;
  __u32 flags;
  __u32 reserved[2];
};
#define MEDIA_LNK_FL_ENABLED (1U << 0)
#define MEDIA_LNK_FL_IMMUTABLE (1U << 1)
#define MEDIA_LNK_FL_DYNAMIC (1U << 2)
#define MEDIA_LNK_FL_LINK_TYPE (0xf << 28)
#define MEDIA_LNK_FL_DATA_LINK (0U << 28)
#define MEDIA_LNK_FL_INTERFACE_LINK (1U << 28)
#define MEDIA_LNK_FL_ANCILLARY_LINK (2U << 28)
struct media_link_desc {
  struct media_pad_desc source;
  struct media_pad_desc sink;
  __u32 flags;
  __u32 reserved[2];
};
struct media_links_enum {
  __u32 entity;
  struct media_pad_desc  * pads;
  struct media_link_desc  * links;
  __u32 reserved[4];
};
#define MEDIA_INTF_T_DVB_BASE 0x00000100
#define MEDIA_INTF_T_V4L_BASE 0x00000200
#define MEDIA_INTF_T_DVB_FE (MEDIA_INTF_T_DVB_BASE)
#define MEDIA_INTF_T_DVB_DEMUX (MEDIA_INTF_T_DVB_BASE + 1)
#define MEDIA_INTF_T_DVB_DVR (MEDIA_INTF_T_DVB_BASE + 2)
#define MEDIA_INTF_T_DVB_CA (MEDIA_INTF_T_DVB_BASE + 3)
#define MEDIA_INTF_T_DVB_NET (MEDIA_INTF_T_DVB_BASE + 4)
#define MEDIA_INTF_T_V4L_VIDEO (MEDIA_INTF_T_V4L_BASE)
#define MEDIA_INTF_T_V4L_VBI (MEDIA_INTF_T_V4L_BASE + 1)
#define MEDIA_INTF_T_V4L_RADIO (MEDIA_INTF_T_V4L_BASE + 2)
#define MEDIA_INTF_T_V4L_SUBDEV (MEDIA_INTF_T_V4L_BASE + 3)
#define MEDIA_INTF_T_V4L_SWRADIO (MEDIA_INTF_T_V4L_BASE + 4)
#define MEDIA_INTF_T_V4L_TOUCH (MEDIA_INTF_T_V4L_BASE + 5)
#define MEDIA_INTF_T_ALSA_BASE 0x00000300
#define MEDIA_INTF_T_ALSA_PCM_CAPTURE (MEDIA_INTF_T_ALSA_BASE)
#define MEDIA_INTF_T_ALSA_PCM_PLAYBACK (MEDIA_INTF_T_ALSA_BASE + 1)
#define MEDIA_INTF_T_ALSA_CONTROL (MEDIA_INTF_T_ALSA_BASE + 2)
#define MEDIA_V2_ENTITY_HAS_FLAGS(media_version) ((media_version) >= ((4U << 16) | (19U << 8) | 0U))
struct media_v2_entity {
  __u32 id;
  char name[64];
  __u32 function;
  __u32 flags;
  __u32 reserved[5];
} __attribute__((packed));
struct media_v2_intf_devnode {
  __u32 major;
  __u32 minor;
} __attribute__((packed));
struct media_v2_interface {
  __u32 id;
  __u32 intf_type;
  __u32 flags;
  __u32 reserved[9];
  union {
    struct media_v2_intf_devnode devnode;
    __u32 raw[16];
  };
} __attribute__((packed));
#define MEDIA_V2_PAD_HAS_INDEX(media_version) ((media_version) >= ((4U << 16) | (19U << 8) | 0U))
struct media_v2_pad {
  __u32 id;
  __u32 entity_id;
  __u32 flags;
  __u32 index;
  __u32 reserved[4];
} __attribute__((packed));
struct media_v2_link {
  __u32 id;
  __u32 source_id;
  __u32 sink_id;
  __u32 flags;
  __u32 reserved[6];
} __attribute__((packed));
struct media_v2_topology {
  __u64 topology_version;
  __u32 num_entities;
  __u32 reserved1;
  __u64 ptr_entities;
  __u32 num_interfaces;
  __u32 reserved2;
  __u64 ptr_interfaces;
  __u32 num_pads;
  __u32 reserved3;
  __u64 ptr_pads;
  __u32 num_links;
  __u32 reserved4;
  __u64 ptr_links;
} __attribute__((packed));
#define MEDIA_IOC_DEVICE_INFO _IOWR('|', 0x00, struct media_device_info)
#define MEDIA_IOC_ENUM_ENTITIES _IOWR('|', 0x01, struct media_entity_desc)
#define MEDIA_IOC_ENUM_LINKS _IOWR('|', 0x02, struct media_links_enum)
#define MEDIA_IOC_SETUP_LINK _IOWR('|', 0x03, struct media_link_desc)
#define MEDIA_IOC_G_TOPOLOGY _IOWR('|', 0x04, struct media_v2_topology)
#define MEDIA_IOC_REQUEST_ALLOC _IOR('|', 0x05, int)
#define MEDIA_REQUEST_IOC_QUEUE _IO('|', 0x80)
#define MEDIA_REQUEST_IOC_REINIT _IO('|', 0x81)
#define MEDIA_ENT_TYPE_SHIFT 16
#define MEDIA_ENT_TYPE_MASK 0x00ff0000
#define MEDIA_ENT_SUBTYPE_MASK 0x0000ffff
#define MEDIA_ENT_T_DEVNODE_UNKNOWN (MEDIA_ENT_F_OLD_BASE | MEDIA_ENT_SUBTYPE_MASK)
#define MEDIA_ENT_T_DEVNODE MEDIA_ENT_F_OLD_BASE
#define MEDIA_ENT_T_DEVNODE_V4L MEDIA_ENT_F_IO_V4L
#define MEDIA_ENT_T_DEVNODE_FB (MEDIA_ENT_F_OLD_BASE + 2)
#define MEDIA_ENT_T_DEVNODE_ALSA (MEDIA_ENT_F_OLD_BASE + 3)
#define MEDIA_ENT_T_DEVNODE_DVB (MEDIA_ENT_F_OLD_BASE + 4)
#define MEDIA_ENT_T_UNKNOWN MEDIA_ENT_F_UNKNOWN
#define MEDIA_ENT_T_V4L2_VIDEO MEDIA_ENT_F_IO_V4L
#define MEDIA_ENT_T_V4L2_SUBDEV MEDIA_ENT_F_V4L2_SUBDEV_UNKNOWN
#define MEDIA_ENT_T_V4L2_SUBDEV_SENSOR MEDIA_ENT_F_CAM_SENSOR
#define MEDIA_ENT_T_V4L2_SUBDEV_FLASH MEDIA_ENT_F_FLASH
#define MEDIA_ENT_T_V4L2_SUBDEV_LENS MEDIA_ENT_F_LENS
#define MEDIA_ENT_T_V4L2_SUBDEV_DECODER MEDIA_ENT_F_ATV_DECODER
#define MEDIA_ENT_T_V4L2_SUBDEV_TUNER MEDIA_ENT_F_TUNER
#define MEDIA_ENT_F_DTV_DECODER MEDIA_ENT_F_DV_DECODER
#define MEDIA_INTF_T_ALSA_COMPRESS (MEDIA_INTF_T_ALSA_BASE + 3)
#define MEDIA_INTF_T_ALSA_RAWMIDI (MEDIA_INTF_T_ALSA_BASE + 4)
#define MEDIA_INTF_T_ALSA_HWDEP (MEDIA_INTF_T_ALSA_BASE + 5)
#define MEDIA_INTF_T_ALSA_SEQUENCER (MEDIA_INTF_T_ALSA_BASE + 6)
#define MEDIA_INTF_T_ALSA_TIMER (MEDIA_INTF_T_ALSA_BASE + 7)
#define MEDIA_API_VERSION ((0U << 16) | (1U << 8) | 0U)
#endif

"""

```