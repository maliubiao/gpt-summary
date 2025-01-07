Response:
Let's break down the thought process for generating the detailed response about the `dmx.handroid` header file.

**1. Understanding the Core Request:**

The initial request asks for an analysis of the provided C header file, specifically `bionic/libc/kernel/uapi/linux/dvb/dmx.handroid`. The key aspects to address are:

* **Functionality:** What does this file define?
* **Android Relevance:** How does it connect to Android's capabilities?
* **libc Function Details:** Explanation of individual libc functions (though the file primarily *defines* structures and enums for kernel interactions, not libc functions themselves).
* **Dynamic Linker:** How does it relate to dynamic linking (again, more about kernel interaction than direct dynamic linking).
* **Logic and Examples:**  Provide illustrative scenarios.
* **Usage Errors:** Common mistakes developers might make.
* **Android Framework/NDK Path:**  How is this used in Android development?
* **Frida Hooking:**  Demonstrate debugging.

**2. Initial Analysis of the Header File:**

The first step is to recognize the nature of the file:

* **`uapi` Directory:**  This immediately signals a "user-space API" definition that mirrors kernel structures. User-space programs (like Android apps or system services) use these definitions to interact with kernel drivers.
* **`linux/dvb/dmx.h`:**  This strongly indicates involvement with Digital Video Broadcasting (DVB) and demultiplexing (DMX).
* **`#ifndef _UAPI_DVBDMX_H_ ... #endif`:** Standard header guard to prevent multiple inclusions.
* **`#include <linux/types.h>` and `#include <time.h>`:**  Dependencies on basic Linux types and time-related structures.
* **`enum` definitions:**  Clearly defines sets of related constants for input, output, and PES (Packetized Elementary Stream) types.
* **`struct` definitions:** Defines the structure of data exchanged with the DVB demux driver in the kernel (filters, buffer parameters, etc.).
* **`#define` macros:**  Defines constants (like `DMX_FILTER_SIZE`) and, importantly, *ioctl* commands (`DMX_START`, `DMX_STOP`, etc.). These are crucial for interacting with the kernel driver.
* **`typedef` definitions:** Creates aliases for the `enum` and `struct` types for easier use.

**3. Connecting to Android Functionality:**

Knowing it's related to DVB, the next step is to consider how Android uses DVB:

* **Live TV Apps:**  The most direct connection. Android devices with DVB tuners use these APIs to receive and process broadcast television signals.
* **Background Services:**  System services might use these interfaces for tasks like channel scanning or recording.

**4. Addressing the "libc Functions" Misdirection:**

The request asks about libc function implementations. It's important to clarify that this header file *doesn't define libc functions*. It defines *data structures and constants* that are used *with* libc functions like `open()`, `close()`, and especially `ioctl()`. The focus should shift to how these definitions are used in the context of interacting with the kernel driver *through* libc.

**5. Dynamic Linker Relevance:**

Similarly, this header file itself doesn't directly involve the dynamic linker. However, the *user-space libraries* that *use* these definitions will be dynamically linked. The explanation needs to emphasize this indirect connection. A library like a DVB HAL (Hardware Abstraction Layer) would be dynamically linked.

**6. Developing Examples and Scenarios:**

To illustrate the concepts, it's crucial to provide concrete examples:

* **Filter Setup:**  Demonstrate how the `dmx_filter` and `dmx_sct_filter_params` structures are used to filter specific data streams.
* **Buffer Management:** Explain the purpose of `dmx_requestbuffers`, `dmx_qbuf`, and `dmx_dqbuf` in receiving data from the driver.

**7. Identifying Potential Usage Errors:**

Think about common mistakes developers might make when working with low-level APIs:

* **Incorrect `ioctl` Usage:**  Providing the wrong arguments or sizes.
* **Buffer Overflows:** Not allocating enough buffer space.
* **Race Conditions:** If multiple threads are interacting with the demuxer.
* **Permission Issues:**  Not having the necessary permissions to access the DVB device.

**8. Tracing the Android Framework/NDK Path:**

This requires outlining the layers involved:

* **Android Application:**  Starts the process.
* **Android Framework (Java):** Uses APIs like `android.media.tv.TvInputService`.
* **Native Code (C/C++):**  The framework often delegates to native code for hardware interaction. This might involve a HAL.
* **Hardware Abstraction Layer (HAL):**  Provides a standardized interface to the hardware. A DVB HAL would use the definitions in `dmx.handroid`.
* **Kernel Driver:** The ultimate recipient of the `ioctl` calls.

**9. Crafting the Frida Hooking Example:**

The Frida example should target a relevant `ioctl` call, such as `DMX_SET_FILTER`. The code needs to:

* **Attach to the target process.**
* **Find the address of the `ioctl` function.**
* **Hook the function.**
* **Extract the arguments, particularly the `dmx_sct_filter_params` structure.**
* **Log the relevant data.**

**10. Structuring the Response:**

Finally, organize the information logically, using clear headings and bullet points for readability. Ensure all aspects of the original request are addressed thoroughly. Use precise language and avoid jargon where possible, or explain it when necessary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on libc function implementations. **Correction:** Realize the focus should be on how the header is used *with* libc, particularly `ioctl`.
* **Initial thought:**  Overemphasize dynamic linking details of this specific header. **Correction:**  Shift to the dynamic linking of *libraries that use* this header.
* **Consider adding more specific examples:** Initially, the examples might be too abstract. **Refinement:** Add concrete values for PID, filter masks, etc. to make them more understandable.
* **Ensure the Frida example is practical:** Focus on hooking a meaningful function and extracting relevant data.

By following this structured approach and being willing to refine the analysis along the way, it's possible to generate a comprehensive and accurate response to the complex request.
好的，我们来详细分析一下 `bionic/libc/kernel/uapi/linux/dvb/dmx.handroid` 这个头文件。

**功能列举**

这个头文件定义了用于与Linux DVB（Digital Video Broadcasting，数字视频广播） demultiplexer (DMX，解复用器) 子系统进行用户空间交互的常量、枚举和结构体。 它的主要功能是为用户空间程序提供一个接口，以控制和配置 DVB 设备的解复用功能。具体来说，它定义了：

1. **数据结构:**
   - `dmx_filter`: 用于定义数据包过滤规则。
   - `dmx_sct_filter_params`: 用于设置基于 Section 的过滤参数。
   - `dmx_pes_filter_params`: 用于设置基于 PES (Packetized Elementary Stream) 的过滤参数。
   - `dmx_stc`: 用于获取或设置系统时间时钟 (STC)。
   - `dmx_buffer`: 用于描述解复用器缓存的状态。
   - `dmx_requestbuffers`: 用于请求分配解复用器缓存。
   - `dmx_exportbuffer`: 用于导出解复用器缓存的文件描述符。

2. **枚举类型:**
   - `dmx_output`: 定义解复用器输出的目标 (例如，解码器、TAP 接口)。
   - `dmx_input`: 定义解复用器的输入源 (例如，前端、DVR)。
   - `dmx_ts_pes`: 定义传输流 (TS) 中 PES 包的类型 (例如，音频、视频、字幕)。
   - `dmx_buffer_flags`: 定义解复用器缓存的标志位，用于指示数据包的状态或错误。

3. **宏定义:**
   - `DMX_FILTER_SIZE`: 定义了过滤器的大小。
   - `DMX_PES_AUDIO`, `DMX_PES_VIDEO` 等：定义了一些常用的 PES 类型宏。
   - `DMX_CHECK_CRC`, `DMX_ONESHOT`, `DMX_IMMEDIATE_START`:  `dmx_sct_filter_params` 结构体中使用的标志位。
   - `DMX_START`, `DMX_STOP` 等：定义了用于与 DVB 解复用器设备驱动进行 ioctl 系统调用的命令码。

4. **类型别名:**
   - `dmx_output_t`, `dmx_input_t`, `dmx_pes_type_t`, `dmx_filter_t`: 为枚举和结构体定义了更简洁的类型名称。

**与 Android 功能的关系和举例**

这个头文件与 Android 设备中的数字电视功能直接相关。Android 设备如果配备了 DVB 硬件（例如，用于接收地面数字电视广播的调谐器），就需要使用这些接口来控制和访问 DVB 数据流。

**举例说明:**

假设一个 Android 应用想要接收特定的电视频道。其背后的流程可能涉及以下步骤，而 `dmx.handroid` 中定义的结构体和宏会在其中发挥作用：

1. **打开 DVB 设备文件:**  应用会使用 `open()` 系统调用打开一个表示 DVB 解复用器的设备文件，例如 `/dev/dvb0.demux0`。
2. **设置 PID 过滤器:** 应用可能需要过滤特定的 PID (Packet Identifier)，以便只接收目标频道的音视频数据。这会涉及到填充 `dmx_sct_filter_params` 或 `dmx_pes_filter_params` 结构体，设置 `pid` 字段以及定义过滤规则的 `filter` 和 `mask`。
3. **配置输出目标:** 使用 `dmx_pes_filter_params` 结构体中的 `output` 字段，应用可以指定将解复用后的数据发送到哪里，例如解码器 (`DMX_OUT_DECODER`)。
4. **启动解复用:**  应用会使用 `ioctl()` 系统调用，并传入 `DMX_START` 命令码来启动解复用过程。
5. **读取解复用数据:** 应用可以使用诸如 `read()` 的系统调用从解复用器读取过滤后的数据。为了更高效地处理数据，可能会使用 `DMX_REQBUFS`, `DMX_QBUF`, `DMX_DQBUF` 等命令来管理内核缓冲区。

**libc 函数的功能实现 (主要涉及 ioctl)**

这个头文件本身并没有定义 libc 函数的实现，它定义的是用于与内核交互的数据结构和命令。真正进行操作的是 libc 提供的系统调用接口，特别是 `ioctl()` 函数。

`ioctl()` (input/output control) 是一个通用的设备控制接口，允许用户空间程序向设备驱动程序发送控制命令和传递数据。

在这个 DVB 解复用的场景中，`ioctl()` 的使用方式如下：

```c
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/dvb/dmx.h> // 包含 dmx.handroid 定义

int fd = open("/dev/dvb0.demux0", O_RDWR);
if (fd < 0) {
  perror("open");
  return -1;
}

struct dmx_sct_filter_params sfp;
// ... 初始化 sfp 的成员 ...

if (ioctl(fd, DMX_SET_FILTER, &sfp) == -1) {
  perror("ioctl DMX_SET_FILTER");
  close(fd);
  return -1;
}

if (ioctl(fd, DMX_START) == -1) {
  perror("ioctl DMX_START");
  close(fd);
  return -1;
}

// ... 读取数据 ...

if (ioctl(fd, DMX_STOP) == -1) {
  perror("ioctl DMX_STOP");
  close(fd);
  return -1;
}

close(fd);
```

**`ioctl()` 的处理过程:**

1. **系统调用:** 用户空间程序调用 `ioctl()`，提供文件描述符、命令码 (`DMX_SET_FILTER`, `DMX_START` 等) 以及可选的参数指针。
2. **内核处理:**  内核接收到 `ioctl()` 系统调用后，会根据文件描述符找到对应的设备驱动程序。
3. **驱动程序处理:** DVB 解复用器驱动程序会根据接收到的命令码执行相应的操作。例如：
   - 对于 `DMX_SET_FILTER`，驱动程序会解析 `dmx_sct_filter_params` 结构体，并配置硬件过滤器。
   - 对于 `DMX_START`，驱动程序会启动数据流的解复用过程。
   - 对于 `DMX_STOP`，驱动程序会停止解复用。
4. **返回结果:** 驱动程序执行完操作后，会将结果返回给内核，内核再将结果返回给用户空间程序。

**涉及 dynamic linker 的功能 (间接关联)**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的作用是在程序启动时加载和链接动态链接库 (.so 文件)。

然而，使用这个头文件的应用程序或库通常会链接到一些共享库，例如 libc 本身。当应用程序启动时，dynamic linker 会负责加载这些共享库，并将应用程序代码中对共享库函数的调用链接到库中的实际实现。

**so 布局样本和链接的处理过程 (假设一个使用了 DVB 功能的 Android 应用):**

假设我们有一个名为 `tv_app` 的 Android 应用，它使用了 DVB 功能。它可能会依赖于一个提供 DVB 相关接口的共享库，例如 `libdvb.so`。

**so 布局样本:**

```
/system/bin/tv_app  (可执行文件)
/system/lib64/libdvb.so (共享库，可能由硬件供应商提供)
/apex/com.android.runtime/lib64/bionic/libc.so (Android 的 C 库)
/apex/com.android.runtime/lib64/bionic/libm.so (Android 的数学库)
/apex/com.android.runtime/lib64/bionic/libdl.so (Android 的动态链接器接口库)
... 其他系统库 ...
```

**链接的处理过程:**

1. **应用启动:** 当 Android 系统启动 `tv_app` 时，它会调用 dynamic linker。
2. **加载依赖:** Dynamic linker 会读取 `tv_app` 的 ELF 头，找到它依赖的共享库（例如 `libdvb.so`，以及 libc 等）。
3. **查找共享库:** Dynamic linker 会在预定义的路径（例如 `/system/lib64`, `/vendor/lib64` 等）中查找这些共享库。
4. **加载和映射:** Dynamic linker 将找到的共享库加载到内存中，并将其映射到进程的地址空间。
5. **符号解析和重定位:** Dynamic linker 会解析应用程序和共享库中的符号引用，并将它们链接到实际的函数地址。例如，如果 `tv_app` 调用了 `libdvb.so` 中定义的某个函数来设置 DVB 过滤器，dynamic linker 会将这个调用指向 `libdvb.so` 中该函数的具体地址。
6. **启动应用程序:**  链接完成后，dynamic linker 将控制权交给应用程序的入口点。

在 `libdvb.so` 的实现中，可能会使用 `open()`, `ioctl()` 等 libc 函数以及 `dmx.handroid` 中定义的结构体和宏来与 DVB 驱动进行交互。

**逻辑推理、假设输入与输出 (以设置过滤器为例)**

**假设输入:**

- DVB 设备文件描述符 `fd`: 指向 `/dev/dvb0.demux0`。
- 目标 PID: `0x1011` (代表某个频道的视频流)。
- 过滤器配置:  我们想要接收 PID 为 `0x1011` 的所有数据包。

**代码示例:**

```c
struct dmx_sct_filter_params sfp;
sfp.pid = 0x1011;
memset(sfp.filter.filter, 0, DMX_FILTER_SIZE); // 接收所有匹配 PID 的数据
memset(sfp.filter.mask, 0xff, DMX_FILTER_SIZE);
memset(sfp.filter.mode, 0xff, DMX_FILTER_SIZE);
sfp.timeout = 0;
sfp.flags = 0;

if (ioctl(fd, DMX_SET_FILTER, &sfp) == 0) {
  // 设置过滤器成功
  printf("成功设置 PID 过滤器为 0x%x\n", sfp.pid);
} else {
  perror("设置过滤器失败");
}
```

**预期输出:**

如果 `ioctl()` 调用成功，预期输出是 "成功设置 PID 过滤器为 0x1011"。并且，在启动解复用后，从设备文件读取的数据将只包含 PID 为 `0x1011` 的数据包。

**用户或编程常见的使用错误**

1. **未正确打开设备文件:** 忘记使用 `open()` 打开 DVB 解复用器设备文件，或者打开的文件路径不正确。
2. **`ioctl()` 命令码错误:** 使用了错误的 `ioctl` 命令码，或者命令码与传递的结构体类型不匹配。
3. **结构体初始化错误:**  未正确初始化 `dmx_filter` 或其他结构体的成员，例如 `pid`、`filter`、`mask` 等。
4. **缓冲区溢出:** 在使用缓冲区相关的 `ioctl` 命令（例如 `DMX_QBUF`）时，提供的缓冲区大小不足以容纳数据。
5. **权限问题:**  用户没有足够的权限访问 DVB 设备文件。
6. **资源泄漏:**  打开设备文件后忘记使用 `close()` 关闭。
7. **竞态条件:** 在多线程环境下，多个线程同时访问同一个 DVB 设备，可能导致状态不一致。
8. **不支持的 DVB 硬件或驱动:**  设备不支持相关的 DVB 功能，或者驱动程序存在 bug。

**Android Framework 或 NDK 如何一步步到达这里**

1. **Android Application (Java/Kotlin):**  一个需要使用 DVB 功能的 Android 应用会调用 Android Framework 提供的相关 API，例如 `android.media.tv.TvInputService` 和相关的类。
2. **Android Framework (Java):** Framework 层处理应用的请求，并将其转换为底层的操作。对于 DVB 功能，Framework 会通过 JNI (Java Native Interface) 调用 Native 代码。
3. **Native Code (C/C++):**  在 Android Framework 的 Native 层，或者在硬件抽象层 (HAL) 中，会使用 C/C++ 代码来实现 DVB 的控制和数据处理。
4. **Hardware Abstraction Layer (HAL):** Android 的 HAL 提供了一组标准的接口，供 Framework 与硬件设备进行交互。对于 DVB 设备，可能会有一个 DVB HAL 模块。
5. **HAL Implementation:** HAL 的具体实现通常由硬件供应商提供。在这个实现中，会使用底层的 Linux 系统调用来与 DVB 驱动程序进行交互，包括 `open()` 和 `ioctl()`。
6. **Kernel Driver:**  HAL 的实现会打开 `/dev/dvb0.demux0` 等设备文件，并使用 `ioctl()` 系统调用，传递 `dmx.handroid` 中定义的命令码和结构体，来配置和控制 DVB 解复用器。

**Frida Hook 示例调试步骤**

假设我们想 hook `ioctl` 函数，看看应用程序是如何设置 DVB 过滤器的。

```python
import frida
import sys

# 要 hook 的进程名称
process_name = "com.example.tvapp"

# Frida 脚本
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
  onEnter: function(args) {
    const fd = args[0].toInt39();
    const request = args[1].toInt39();
    const argp = args[2];

    if (request === 0xc01827) { // DMX_SET_FILTER 的值 (0xc01800 | 43)
      console.log("ioctl called with DMX_SET_FILTER");
      console.log("File Descriptor:", fd);

      // 读取 dmx_sct_filter_params 结构体
      const dmx_sct_filter_params_ptr = argp;
      const pid = dmx_sct_filter_params_ptr.readU16();
      console.log("PID:", pid);

      const filter_ptr = dmx_sct_filter_params_ptr.add(2); // pid 占 2 字节
      const filter = filter_ptr.readByteArray(16);
      console.log("Filter:", hexdump(filter));

      const mask_ptr = filter_ptr.add(16);
      const mask = mask_ptr.readByteArray(16);
      console.log("Mask:", hexdump(mask));

      // ... 可以继续读取其他字段 ...
    } else if (request === 0x80040029) { // DMX_START 的值 (0xbf00 | 41)
      console.log("ioctl called with DMX_START");
      console.log("File Descriptor:", fd);
    }
  },
  onLeave: function(retval) {
    // console.log("ioctl returned:", retval);
  }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach(process_name)
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print(f"Process '{process_name}' not found.")
except Exception as e:
    print(e)
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **找到目标进程:** 确定你要调试的应用程序的进程名称（例如，使用 `adb shell ps | grep tvapp`）。
3. **编写 Frida 脚本:**  如上面的示例代码所示，使用 `Interceptor.attach` hook `ioctl` 函数。你需要知道 `DMX_SET_FILTER` 和 `DMX_START` 等宏对应的数值。这些值可以通过查看内核头文件或者反汇编相关的库来获取。
4. **运行 Frida 脚本:** 将脚本保存为 `.py` 文件，并在 PC 上运行 `frida -U -f com.example.tvapp your_script.py` (替换为你应用的包名和脚本文件名)。或者，如果应用已经在运行，可以使用 `frida -U com.example.tvapp your_script.py`。
5. **观察输出:** 当应用程序调用 `ioctl` 设置 DVB 过滤器或启动解复用时，Frida 脚本会在控制台上打印出相关的信息，例如文件描述符、PID、过滤器配置等。

通过这种方式，你可以监控应用程序与 DVB 驱动的交互，了解其如何配置和使用 DVB 功能。

希望这个详细的解释能够帮助你理解 `dmx.handroid` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/dvb/dmx.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_DVBDMX_H_
#define _UAPI_DVBDMX_H_
#include <linux/types.h>
#include <time.h>
#define DMX_FILTER_SIZE 16
enum dmx_output {
  DMX_OUT_DECODER,
  DMX_OUT_TAP,
  DMX_OUT_TS_TAP,
  DMX_OUT_TSDEMUX_TAP
};
enum dmx_input {
  DMX_IN_FRONTEND,
  DMX_IN_DVR
};
enum dmx_ts_pes {
  DMX_PES_AUDIO0,
  DMX_PES_VIDEO0,
  DMX_PES_TELETEXT0,
  DMX_PES_SUBTITLE0,
  DMX_PES_PCR0,
  DMX_PES_AUDIO1,
  DMX_PES_VIDEO1,
  DMX_PES_TELETEXT1,
  DMX_PES_SUBTITLE1,
  DMX_PES_PCR1,
  DMX_PES_AUDIO2,
  DMX_PES_VIDEO2,
  DMX_PES_TELETEXT2,
  DMX_PES_SUBTITLE2,
  DMX_PES_PCR2,
  DMX_PES_AUDIO3,
  DMX_PES_VIDEO3,
  DMX_PES_TELETEXT3,
  DMX_PES_SUBTITLE3,
  DMX_PES_PCR3,
  DMX_PES_OTHER
};
#define DMX_PES_AUDIO DMX_PES_AUDIO0
#define DMX_PES_VIDEO DMX_PES_VIDEO0
#define DMX_PES_TELETEXT DMX_PES_TELETEXT0
#define DMX_PES_SUBTITLE DMX_PES_SUBTITLE0
#define DMX_PES_PCR DMX_PES_PCR0
struct dmx_filter {
  __u8 filter[DMX_FILTER_SIZE];
  __u8 mask[DMX_FILTER_SIZE];
  __u8 mode[DMX_FILTER_SIZE];
};
struct dmx_sct_filter_params {
  __u16 pid;
  struct dmx_filter filter;
  __u32 timeout;
  __u32 flags;
#define DMX_CHECK_CRC 1
#define DMX_ONESHOT 2
#define DMX_IMMEDIATE_START 4
};
struct dmx_pes_filter_params {
  __u16 pid;
  enum dmx_input input;
  enum dmx_output output;
  enum dmx_ts_pes pes_type;
  __u32 flags;
};
struct dmx_stc {
  unsigned int num;
  unsigned int base;
  __u64 stc;
};
enum dmx_buffer_flags {
  DMX_BUFFER_FLAG_HAD_CRC32_DISCARD = 1 << 0,
  DMX_BUFFER_FLAG_TEI = 1 << 1,
  DMX_BUFFER_PKT_COUNTER_MISMATCH = 1 << 2,
  DMX_BUFFER_FLAG_DISCONTINUITY_DETECTED = 1 << 3,
  DMX_BUFFER_FLAG_DISCONTINUITY_INDICATOR = 1 << 4,
};
struct dmx_buffer {
  __u32 index;
  __u32 bytesused;
  __u32 offset;
  __u32 length;
  __u32 flags;
  __u32 count;
};
struct dmx_requestbuffers {
  __u32 count;
  __u32 size;
};
struct dmx_exportbuffer {
  __u32 index;
  __u32 flags;
  __s32 fd;
};
#define DMX_START _IO('o', 41)
#define DMX_STOP _IO('o', 42)
#define DMX_SET_FILTER _IOW('o', 43, struct dmx_sct_filter_params)
#define DMX_SET_PES_FILTER _IOW('o', 44, struct dmx_pes_filter_params)
#define DMX_SET_BUFFER_SIZE _IO('o', 45)
#define DMX_GET_PES_PIDS _IOR('o', 47, __u16[5])
#define DMX_GET_STC _IOWR('o', 50, struct dmx_stc)
#define DMX_ADD_PID _IOW('o', 51, __u16)
#define DMX_REMOVE_PID _IOW('o', 52, __u16)
typedef enum dmx_output dmx_output_t;
typedef enum dmx_input dmx_input_t;
typedef enum dmx_ts_pes dmx_pes_type_t;
typedef struct dmx_filter dmx_filter_t;
#define DMX_REQBUFS _IOWR('o', 60, struct dmx_requestbuffers)
#define DMX_QUERYBUF _IOWR('o', 61, struct dmx_buffer)
#define DMX_EXPBUF _IOWR('o', 62, struct dmx_exportbuffer)
#define DMX_QBUF _IOWR('o', 63, struct dmx_buffer)
#define DMX_DQBUF _IOWR('o', 64, struct dmx_buffer)
#endif

"""

```