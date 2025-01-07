Response:
Let's break down the thought process for answering the request about `virtio_gpu.h`.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of the provided C header file (`virtio_gpu.h`). Key aspects they're interested in are:

* **Functionality:** What does this file *do*?  What are its purpose and the concepts it defines?
* **Android Relevance:** How does this relate to the Android operating system?  Specific examples are needed.
* **Implementation Details (libc):**  While this file *defines* structures and constants, the user asks about `libc` functions. This signals a slight misunderstanding. The file *doesn't implement* `libc` functions; it defines the *interface* for communication, likely used by `libc` functions. This needs to be clarified.
* **Dynamic Linker:** How does this interact with the dynamic linker?  Again, this file doesn't directly interact with the dynamic linker in the sense of being a shared library. It defines structures for data passed *between* processes, potentially across library boundaries. The connection is more indirect. We need to address this nuance.
* **Logic and Assumptions:** Are there any underlying assumptions or logical relationships within the definitions?
* **Common Errors:** What are typical mistakes developers might make when using these definitions?
* **Android Framework and NDK:** How does a request from the Android framework or NDK eventually lead to the use of these definitions? This requires tracing the execution path.
* **Frida Hooking:** How can we use Frida to observe the usage of these structures?

**2. Initial Analysis of the Header File:**

* **`#ifndef VIRTIO_GPU_HW_H` ... `#endif`:** This is a standard header guard to prevent multiple inclusions.
* **Includes `<linux/types.h>`:**  Indicates this header is meant for kernel-level or low-level interactions, relying on fundamental Linux types.
* **`#define VIRTIO_GPU_F_*`:** These are feature flags, suggesting capabilities that the virtual GPU might support (virgl, EDID, UUIDs, etc.).
* **`enum virtio_gpu_ctrl_type`:**  This is the heart of the file. It defines the different *commands* and *responses* for controlling the virtual GPU. These commands cover resource management (create, unref, flush), scanout (display) control, context management, data transfers, cursor manipulation, and capabilities negotiation. The `0x0100`, `0x0200`, `0x0300`, `0x1100`, `0x1200` groupings likely represent different categories of commands/responses.
* **`enum virtio_gpu_shm_id`:** Defines IDs for shared memory regions.
* **`#define VIRTIO_GPU_FLAG_*`:**  Defines general flags for the control structures.
* **`struct virtio_gpu_*`:**  The core of the file. These structures represent the data payloads for the commands and responses defined in the `enum virtio_gpu_ctrl_type`. They contain fields like resource IDs, dimensions, offsets, memory addresses, etc. The naming conventions are quite descriptive.
* **`#define VIRTIO_GPU_MAX_SCANOUTS 16`:** A constant defining the maximum number of display outputs.
* **`enum virtio_gpu_formats`:** Defines pixel formats supported by the virtual GPU.
* **`struct virtio_gpu_config`:**  Defines the configuration structure for the virtio GPU device.
* **Comments:** The auto-generated comment at the top provides context about its origin.

**3. Addressing the User's Points (and Refining the Interpretation):**

* **Functionality:** The file defines the *interface* for communicating with a virtual GPU. It's not the implementation itself. It specifies the commands and data structures used for this communication.
* **Android Relevance:** This is crucial for Android's virtualization strategy. Android emulators (like the one used in Android Studio) and potentially some virtualized Android environments rely on this type of virtual GPU. The commands relate directly to graphics operations within Android.
* **libc Functions:**  The key is to explain that *this file doesn't contain libc functions*. Instead, `libc` (or libraries built on top of it) would *use* these definitions to interact with the virtual GPU driver. The actual system calls (like `ioctl`) would be involved, but those are not defined here.
* **Dynamic Linker:**  Again, this file itself isn't a dynamically linked library. However, the *drivers* or *libraries* that *use* these definitions would be dynamically linked. We can provide a generic example of a shared library layout and the linking process, emphasizing that these structures would be part of the data passed between the application and the driver.
* **Logic and Assumptions:** The command/response structure implies a request-response pattern. The flags and enums define the capabilities and states of the virtual GPU. There's an implicit assumption that the underlying virtio transport mechanism is functioning correctly.
* **Common Errors:** Focus on incorrect usage of the structures (e.g., wrong sizes, incorrect command codes, invalid resource IDs).
* **Android Framework and NDK:** Trace the path from a high-level Android graphics API (like `Surface`) down to the native layer, involving libraries like `libui` and eventually potentially interacting with a kernel driver via `ioctl` using these structures.
* **Frida Hooking:** Show how to hook functions that would likely interact with these structures, such as `ioctl`.

**4. Structuring the Answer:**

Organize the answer logically, addressing each of the user's points in a clear and structured manner. Use headings and bullet points to improve readability.

**5. Providing Examples:**

Concrete examples are essential for understanding. For instance, for Android relevance, linking `VIRTIO_GPU_CMD_SET_SCANOUT` to setting the display resolution makes it tangible. For Frida, a simple `ioctl` hook is a good starting point.

**6. Refining and Clarifying:**

Review the answer to ensure clarity and accuracy. Address any potential misunderstandings, such as the distinction between defining an interface and implementing it. Use precise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus on individual struct members.
* **Correction:** Shift focus to the *purpose* of the structs within the command/response framework.
* **Initial thought:** Explain `libc` implementation details.
* **Correction:** Clarify that this file *uses* `libc` types but doesn't *implement* `libc` functions. Explain how `libc` functions would utilize these definitions.
* **Initial thought:** Provide a highly specific dynamic linker layout.
* **Correction:** Provide a more generic example that demonstrates the principle of data being passed across library boundaries.
* **Initial thought:**  Provide complex Frida examples.
* **Correction:** Start with a simple, illustrative `ioctl` hook.

By following this thought process, iteratively refining the understanding and structuring the information effectively, we arrive at a comprehensive and helpful answer to the user's request.
这个头文件 `virtio_gpu.h` 定义了与 VirtIO GPU 设备交互的接口。VirtIO 是一种标准化的设备虚拟化框架，允许虚拟机高效地访问主机资源。这个特定的头文件定义了用于控制和与虚拟 GPU 设备通信的数据结构和常量。

让我们逐个解答你的问题：

**1. 功能列举:**

这个头文件主要定义了以下功能：

* **设备特性协商:** 定义了用于协商 VirtIO GPU 设备支持的特性的标志（例如 `VIRTIO_GPU_F_VIRGL`）。
* **控制命令类型:** 定义了一系列用于向 VirtIO GPU 设备发送命令的枚举值 (`enum virtio_gpu_ctrl_type`)，涵盖了诸如创建/销毁资源、设置扫描输出、数据传输、上下文管理、光标控制、能力查询等操作。
* **共享内存标识:** 定义了共享内存区域的标识符 (`enum virtio_gpu_shm_id`)。
* **控制命令头:** 定义了所有控制命令结构体共有的头部信息 (`struct virtio_gpu_ctrl_hdr`)，包括命令类型、标志、fence ID、上下文 ID 等。
* **具体命令和响应结构体:** 定义了各种控制命令和对应响应的数据结构，例如：
    * `struct virtio_gpu_resource_create_2d`: 创建 2D 资源。
    * `struct virtio_gpu_set_scanout`: 设置扫描输出。
    * `struct virtio_gpu_transfer_to_host_2d`: 将数据传输到主机。
    * `struct virtio_gpu_resp_display_info`: 获取显示信息。
    * ...以及许多其他用于管理 GPU 资源、上下文、数据传输和光标控制的结构体。
* **设备配置信息:** 定义了设备配置信息的结构体 (`struct virtio_gpu_config`)，例如支持的扫描输出数量和能力集数量。
* **像素格式:** 定义了 VirtIO GPU 支持的像素格式 (`enum virtio_gpu_formats`)。
* **Blob 资源支持:** 定义了用于创建和管理 Blob 资源的结构体，Blob 资源是用于存储 GPU 数据的另一种方式。

**2. 与 Android 功能的关系及举例:**

这个头文件与 Android 的图形显示功能密切相关，尤其是在以下场景中：

* **Android 虚拟机 (Emulator):** Android 模拟器通常使用 VirtIO GPU 来模拟 GPU 硬件，以便在宿主机上渲染图形。  当 Android 虚拟机内的应用程序进行图形绘制时，相关的命令和数据会通过 VirtIO 接口发送到宿主机的 VirtIO GPU 驱动程序。
    * **举例:** 当 Android 应用调用 OpenGL ES API 进行绘制时，例如创建一个纹理，模拟器内部的图形栈会将这个操作转换为 `VIRTIO_GPU_CMD_RESOURCE_CREATE_2D` 命令，并使用相应的 `struct virtio_gpu_resource_create_2d` 结构体填充资源 ID、格式、宽度和高度等信息，然后发送给宿主机。
    * **举例:** 当需要将帧缓冲区的内容显示到屏幕上时，会使用 `VIRTIO_GPU_CMD_SET_SCANOUT` 命令，指定要显示的资源 ID 和屏幕区域。

* **Containerized Android 环境:** 在一些容器化的 Android 环境中，也可能使用 VirtIO GPU 来提供图形加速。

**3. libc 函数的功能实现:**

这个头文件本身 **不包含任何 libc 函数的实现**。它只是定义了数据结构和常量。  `libc` (Bionic) 中的代码会使用这些定义来构建与 VirtIO GPU 设备通信的消息。

具体来说，与 VirtIO GPU 交互通常涉及到以下步骤，其中可能会使用到 `libc` 函数：

* **打开设备节点:** 使用 `open()` 系统调用打开 VirtIO GPU 的设备节点 (例如 `/dev/dri/renderDxxx`)。
* **内存映射 (mmap):**  可能使用 `mmap()` 将设备内存或共享内存映射到进程地址空间，以便高效地进行数据传输。
* **ioctl 系统调用:** 这是与设备驱动程序通信的主要方式。 `ioctl()` 函数会将命令和数据发送给 VirtIO GPU 驱动程序。
    * **功能:** `ioctl()` 允许用户空间程序向设备驱动程序发送控制命令和接收响应。
    * **实现:**  `ioctl()` 是一个系统调用，其实现位于 Linux 内核中。当用户空间程序调用 `ioctl()` 时，内核会根据传入的文件描述符和命令号，找到对应的设备驱动程序，并将数据传递给驱动程序的 `ioctl` 处理函数。驱动程序执行相应的操作，并将结果返回给用户空间。

**4. Dynamic Linker 功能及 SO 布局样本和链接处理:**

这个头文件本身 **不涉及 dynamic linker 的功能**。它不是一个可动态链接的共享库。

然而，使用这个头文件的代码 (例如 Android 的图形驱动程序或模拟器) 可能会被编译成共享库 (`.so` 文件)。

**SO 布局样本:**

```
.so 文件名: libvirtio_gpu_driver.so

Sections:
  .text         # 代码段
  .rodata       # 只读数据段 (可能包含与 VirtIO GPU 相关的常量)
  .data         # 可读写数据段
  .bss          # 未初始化数据段
  .dynsym       # 动态符号表
  .dynstr       # 动态字符串表
  .rel.dyn      # 动态重定位表
  .init         # 初始化函数
  .fini         # 析构函数

Symbols (部分):
  virtio_gpu_init  (函数)
  virtio_gpu_submit_command (函数)
  # ... 其他与 VirtIO GPU 驱动相关的函数 ...

Dependencies:
  libc.so        # 依赖 libc
  # ... 其他依赖库 ...
```

**链接处理过程:**

1. **编译时链接:** 当编译依赖 `libvirtio_gpu_driver.so` 的程序时，链接器会将程序中对 `libvirtio_gpu_driver.so` 中符号的引用记录下来。
2. **运行时加载:** 当程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库。
3. **符号解析:** dynamic linker 会解析程序中对共享库符号的引用，找到 `libvirtio_gpu_driver.so` 中对应的符号地址，并将程序的调用指向正确的地址。
4. **重定位:** dynamic linker 会根据重定位表中的信息，修改程序和共享库中的地址，以确保它们在内存中的正确位置。

**5. 逻辑推理、假设输入与输出:**

以 `VIRTIO_GPU_CMD_RESOURCE_CREATE_2D` 命令为例：

* **假设输入:**
    * `hdr.type`: `VIRTIO_GPU_CMD_RESOURCE_CREATE_2D`
    * `resource_id`:  1234 (假设分配的资源 ID)
    * `format`: `VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM`
    * `width`: 1920
    * `height`: 1080
* **逻辑推理:** VirtIO GPU 驱动程序收到此命令后，会尝试在 GPU 内存中分配一块 1920x1080 的内存区域，用于存储 `B8G8R8A8_UNORM` 格式的图像数据，并将资源 ID 1234 与这块内存关联起来。
* **输出 (响应):**
    * 如果成功，会发送 `VIRTIO_GPU_RESP_OK_NODATA` 响应。
    * 如果失败 (例如，内存不足)，会发送相应的错误响应，例如 `VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY`。

**6. 用户或编程常见的使用错误:**

* **错误的命令类型:**  发送了不支持的命令或使用了错误的命令枚举值。
* **结构体字段填充错误:**  例如，`resource_id` 未初始化或使用了无效的值。
* **数据大小不匹配:**  例如，在 `VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D` 中，传输的大小超过了资源的大小。
* **违反状态机:**  例如，在资源未创建的情况下就尝试刷新它。
* **内存泄漏:**  创建了资源但没有及时 `unref` (使用 `VIRTIO_GPU_CMD_RESOURCE_UNREF`)。
* **并发问题:**  在多线程环境下，如果没有适当的同步机制，可能会导致数据竞争或状态不一致。
* **不支持的特性:** 尝试使用设备不支持的特性，例如在不支持 virgl 的情况下发送 virgl 相关的命令。

**7. Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例:**

**路径:**

1. **Android Framework (Java/Kotlin):**  应用程序通过 Android Framework 的图形 API (例如 `Surface`, `Canvas`, OpenGL ES, Vulkan) 发起图形操作。
2. **Android Graphics Stack (Native):** Framework 的调用会传递到 Native 层的图形库，例如 `libgui.so`, `libhwui.so`, `libvulkan.so`。
3. **Hardware Abstraction Layer (HAL):** 这些库会与硬件抽象层 (HAL) 进行交互，特别是 GPU HAL (`android.hardware.graphics.composer`).
4. **Kernel Driver (VirtIO GPU):** GPU HAL 会调用相应的驱动程序接口，最终会通过系统调用 (通常是 `ioctl`) 与内核中的 VirtIO GPU 驱动程序通信。
5. **VirtIO Transport:**  VirtIO GPU 驱动程序会使用 VirtIO 传输机制 (例如，基于 virtqueues) 与虚拟机监控程序或宿主机上的 VirtIO backend 通信。

**Frida Hook 示例:**

以下是一个使用 Frida hook `ioctl` 系统调用的示例，用于观察与 VirtIO GPU 相关的交互：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

def main():
    try:
        device = frida.get_usb_device()
        pid = device.spawn(["com.example.myapp"]) # 替换为你的应用包名
        session = device.attach(pid)
    except frida.ServerNotRunningError:
        print("Frida server is not running. Please start the Frida server on the device.")
        sys.exit(1)
    except frida.ProcessNotFoundError:
        print("Process not found. Make sure the application is running.")
        sys.exit(1)

    script_source = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function (args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();
            const ptr = args[2];

            // 这里可以添加逻辑来判断是否是 VirtIO GPU 的设备节点
            // 例如，检查文件路径或 request 的值

            if (request >= 0x0100 && request <= 0x03ff) { // 假设 VirtIO GPU 命令范围
                console.log("[*] ioctl called with fd:", fd, "request:", request);

                // 可以进一步解析 ptr 指向的数据，根据 request 的值判断结构体类型
                // 例如，如果 request 是 VIRTIO_GPU_CMD_RESOURCE_CREATE_2D，可以读取相应的结构体
                // ...
            }
        },
        onLeave: function (retval) {
            // console.log("[*] ioctl returned:", retval);
        }
    });
    """

    script = session.create_script(script_source)
    script.on('message', on_message)
    script.load()

    device.resume(pid)
    input() # 等待用户输入以保持脚本运行

    session.detach()

if __name__ == "__main__":
    main()
```

**说明:**

* 这个 Frida 脚本 hook 了 `ioctl` 系统调用。
* 在 `onEnter` 函数中，我们获取了文件描述符 `fd` 和请求码 `request`。
* 可以添加逻辑来判断 `fd` 是否指向 VirtIO GPU 的设备节点。
* 如果 `request` 的值在 VirtIO GPU 命令的范围内，我们打印出相关信息。
* 可以进一步解析 `ptr` 指向的数据，以查看发送给 VirtIO GPU 驱动程序的具体命令和参数。

通过这种方式，你可以观察 Android Framework 或 NDK 代码最终如何通过 `ioctl` 与 VirtIO GPU 驱动程序进行交互，并查看传递的具体数据结构内容。

希望这个详细的解答能够帮助你理解 `virtio_gpu.h` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/virtio_gpu.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef VIRTIO_GPU_HW_H
#define VIRTIO_GPU_HW_H
#include <linux/types.h>
#define VIRTIO_GPU_F_VIRGL 0
#define VIRTIO_GPU_F_EDID 1
#define VIRTIO_GPU_F_RESOURCE_UUID 2
#define VIRTIO_GPU_F_RESOURCE_BLOB 3
#define VIRTIO_GPU_F_CONTEXT_INIT 4
enum virtio_gpu_ctrl_type {
  VIRTIO_GPU_UNDEFINED = 0,
  VIRTIO_GPU_CMD_GET_DISPLAY_INFO = 0x0100,
  VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
  VIRTIO_GPU_CMD_RESOURCE_UNREF,
  VIRTIO_GPU_CMD_SET_SCANOUT,
  VIRTIO_GPU_CMD_RESOURCE_FLUSH,
  VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
  VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
  VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
  VIRTIO_GPU_CMD_GET_CAPSET_INFO,
  VIRTIO_GPU_CMD_GET_CAPSET,
  VIRTIO_GPU_CMD_GET_EDID,
  VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID,
  VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB,
  VIRTIO_GPU_CMD_SET_SCANOUT_BLOB,
  VIRTIO_GPU_CMD_CTX_CREATE = 0x0200,
  VIRTIO_GPU_CMD_CTX_DESTROY,
  VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE,
  VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE,
  VIRTIO_GPU_CMD_RESOURCE_CREATE_3D,
  VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D,
  VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D,
  VIRTIO_GPU_CMD_SUBMIT_3D,
  VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB,
  VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB,
  VIRTIO_GPU_CMD_UPDATE_CURSOR = 0x0300,
  VIRTIO_GPU_CMD_MOVE_CURSOR,
  VIRTIO_GPU_RESP_OK_NODATA = 0x1100,
  VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
  VIRTIO_GPU_RESP_OK_CAPSET_INFO,
  VIRTIO_GPU_RESP_OK_CAPSET,
  VIRTIO_GPU_RESP_OK_EDID,
  VIRTIO_GPU_RESP_OK_RESOURCE_UUID,
  VIRTIO_GPU_RESP_OK_MAP_INFO,
  VIRTIO_GPU_RESP_ERR_UNSPEC = 0x1200,
  VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
  VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
  VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
  VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID,
  VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
};
enum virtio_gpu_shm_id {
  VIRTIO_GPU_SHM_ID_UNDEFINED = 0,
  VIRTIO_GPU_SHM_ID_HOST_VISIBLE = 1
};
#define VIRTIO_GPU_FLAG_FENCE (1 << 0)
#define VIRTIO_GPU_FLAG_INFO_RING_IDX (1 << 1)
struct virtio_gpu_ctrl_hdr {
  __le32 type;
  __le32 flags;
  __le64 fence_id;
  __le32 ctx_id;
  __u8 ring_idx;
  __u8 padding[3];
};
struct virtio_gpu_cursor_pos {
  __le32 scanout_id;
  __le32 x;
  __le32 y;
  __le32 padding;
};
struct virtio_gpu_update_cursor {
  struct virtio_gpu_ctrl_hdr hdr;
  struct virtio_gpu_cursor_pos pos;
  __le32 resource_id;
  __le32 hot_x;
  __le32 hot_y;
  __le32 padding;
};
struct virtio_gpu_rect {
  __le32 x;
  __le32 y;
  __le32 width;
  __le32 height;
};
struct virtio_gpu_resource_unref {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 resource_id;
  __le32 padding;
};
struct virtio_gpu_resource_create_2d {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 resource_id;
  __le32 format;
  __le32 width;
  __le32 height;
};
struct virtio_gpu_set_scanout {
  struct virtio_gpu_ctrl_hdr hdr;
  struct virtio_gpu_rect r;
  __le32 scanout_id;
  __le32 resource_id;
};
struct virtio_gpu_resource_flush {
  struct virtio_gpu_ctrl_hdr hdr;
  struct virtio_gpu_rect r;
  __le32 resource_id;
  __le32 padding;
};
struct virtio_gpu_transfer_to_host_2d {
  struct virtio_gpu_ctrl_hdr hdr;
  struct virtio_gpu_rect r;
  __le64 offset;
  __le32 resource_id;
  __le32 padding;
};
struct virtio_gpu_mem_entry {
  __le64 addr;
  __le32 length;
  __le32 padding;
};
struct virtio_gpu_resource_attach_backing {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 resource_id;
  __le32 nr_entries;
};
struct virtio_gpu_resource_detach_backing {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 resource_id;
  __le32 padding;
};
#define VIRTIO_GPU_MAX_SCANOUTS 16
struct virtio_gpu_resp_display_info {
  struct virtio_gpu_ctrl_hdr hdr;
  struct virtio_gpu_display_one {
    struct virtio_gpu_rect r;
    __le32 enabled;
    __le32 flags;
  } pmodes[VIRTIO_GPU_MAX_SCANOUTS];
};
struct virtio_gpu_box {
  __le32 x, y, z;
  __le32 w, h, d;
};
struct virtio_gpu_transfer_host_3d {
  struct virtio_gpu_ctrl_hdr hdr;
  struct virtio_gpu_box box;
  __le64 offset;
  __le32 resource_id;
  __le32 level;
  __le32 stride;
  __le32 layer_stride;
};
#define VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP (1 << 0)
struct virtio_gpu_resource_create_3d {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 resource_id;
  __le32 target;
  __le32 format;
  __le32 bind;
  __le32 width;
  __le32 height;
  __le32 depth;
  __le32 array_size;
  __le32 last_level;
  __le32 nr_samples;
  __le32 flags;
  __le32 padding;
};
#define VIRTIO_GPU_CONTEXT_INIT_CAPSET_ID_MASK 0x000000ff
struct virtio_gpu_ctx_create {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 nlen;
  __le32 context_init;
  char debug_name[64];
};
struct virtio_gpu_ctx_destroy {
  struct virtio_gpu_ctrl_hdr hdr;
};
struct virtio_gpu_ctx_resource {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 resource_id;
  __le32 padding;
};
struct virtio_gpu_cmd_submit {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 size;
  __le32 padding;
};
#define VIRTIO_GPU_CAPSET_VIRGL 1
#define VIRTIO_GPU_CAPSET_VIRGL2 2
#define VIRTIO_GPU_CAPSET_VENUS 4
#define VIRTIO_GPU_CAPSET_DRM 6
struct virtio_gpu_get_capset_info {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 capset_index;
  __le32 padding;
};
struct virtio_gpu_resp_capset_info {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 capset_id;
  __le32 capset_max_version;
  __le32 capset_max_size;
  __le32 padding;
};
struct virtio_gpu_get_capset {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 capset_id;
  __le32 capset_version;
};
struct virtio_gpu_resp_capset {
  struct virtio_gpu_ctrl_hdr hdr;
  __u8 capset_data[];
};
struct virtio_gpu_cmd_get_edid {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 scanout;
  __le32 padding;
};
struct virtio_gpu_resp_edid {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 size;
  __le32 padding;
  __u8 edid[1024];
};
#define VIRTIO_GPU_EVENT_DISPLAY (1 << 0)
struct virtio_gpu_config {
  __le32 events_read;
  __le32 events_clear;
  __le32 num_scanouts;
  __le32 num_capsets;
};
enum virtio_gpu_formats {
  VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM = 1,
  VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM = 2,
  VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM = 3,
  VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM = 4,
  VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM = 67,
  VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM = 68,
  VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM = 121,
  VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM = 134,
};
struct virtio_gpu_resource_assign_uuid {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 resource_id;
  __le32 padding;
};
struct virtio_gpu_resp_resource_uuid {
  struct virtio_gpu_ctrl_hdr hdr;
  __u8 uuid[16];
};
struct virtio_gpu_resource_create_blob {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 resource_id;
#define VIRTIO_GPU_BLOB_MEM_GUEST 0x0001
#define VIRTIO_GPU_BLOB_MEM_HOST3D 0x0002
#define VIRTIO_GPU_BLOB_MEM_HOST3D_GUEST 0x0003
#define VIRTIO_GPU_BLOB_FLAG_USE_MAPPABLE 0x0001
#define VIRTIO_GPU_BLOB_FLAG_USE_SHAREABLE 0x0002
#define VIRTIO_GPU_BLOB_FLAG_USE_CROSS_DEVICE 0x0004
  __le32 blob_mem;
  __le32 blob_flags;
  __le32 nr_entries;
  __le64 blob_id;
  __le64 size;
};
struct virtio_gpu_set_scanout_blob {
  struct virtio_gpu_ctrl_hdr hdr;
  struct virtio_gpu_rect r;
  __le32 scanout_id;
  __le32 resource_id;
  __le32 width;
  __le32 height;
  __le32 format;
  __le32 padding;
  __le32 strides[4];
  __le32 offsets[4];
};
struct virtio_gpu_resource_map_blob {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 resource_id;
  __le32 padding;
  __le64 offset;
};
#define VIRTIO_GPU_MAP_CACHE_MASK 0x0f
#define VIRTIO_GPU_MAP_CACHE_NONE 0x00
#define VIRTIO_GPU_MAP_CACHE_CACHED 0x01
#define VIRTIO_GPU_MAP_CACHE_UNCACHED 0x02
#define VIRTIO_GPU_MAP_CACHE_WC 0x03
struct virtio_gpu_resp_map_info {
  struct virtio_gpu_ctrl_hdr hdr;
  __u32 map_info;
  __u32 padding;
};
struct virtio_gpu_resource_unmap_blob {
  struct virtio_gpu_ctrl_hdr hdr;
  __le32 resource_id;
  __le32 padding;
};
#endif

"""

```